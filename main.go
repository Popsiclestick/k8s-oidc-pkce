package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"math/rand"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"os/user"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	k8s_client "k8s.io/client-go/tools/clientcmd"
	k8s_api "k8s.io/client-go/tools/clientcmd/api"

	"github.com/coreos/go-oidc"
	"github.com/spf13/cobra"
	"golang.org/x/oauth2"
)

const (
	exampleAppState = "login"
)

type app struct {
	clientID     string
	redirectURI  string
	kubeconfig   string
	debug        bool
	codeVerifier string
	context      string

	verifier *oidc.IDTokenVerifier
	provider *oidc.Provider

	client       *http.Client
	shutdownChan chan bool
}

type claim struct {
	Iss           string `json:"iss"`
	Sub           string `json:"sub"`
	Aud           string `json:"aud"`
	Exp           int    `json:"exp"`
	Iat           int    `json:"iat"`
	AtHash        string `json:"at_hash"`
	Username      string `json:"username"` // This will change based on your provider
	Email         string `json:"email"`
	EmailVerified bool   `json:"email_verified"`
	Name          string `json:"name"`
}

type debugTransport struct {
	t http.RoundTripper
}

func (d debugTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	reqDump, err := httputil.DumpRequest(req, true)
	if err != nil {
		return nil, err
	}
	log.Printf("%s", reqDump)

	resp, err := d.t.RoundTrip(req)
	if err != nil {
		return nil, err
	}

	respDump, err := httputil.DumpResponse(resp, true)
	if err != nil {
		resp.Body.Close()
		return nil, err
	}
	log.Printf("%s", respDump)
	return resp, nil
}

func cmd() *cobra.Command {
	var (
		a         app
		issuerURL string
		listen    string
	)
	c := cobra.Command{
		Use:   "k8s-auth",
		Short: "Authenticates users against OIDC and writes the required kubeconfig.",
		Long:  "",
		RunE: func(cmd *cobra.Command, args []string) error {
			u, err := url.Parse(a.redirectURI)
			if err != nil {
				return fmt.Errorf("parse redirect-uri: %v", err)
			}
			listenURL, err := url.Parse(listen)
			if err != nil {
				return fmt.Errorf("parse listen address: %v", err)
			}

			if a.debug {
				if a.client == nil {
					a.client = &http.Client{
						Transport: debugTransport{http.DefaultTransport},
					}
				} else {
					a.client.Transport = debugTransport{a.client.Transport}
				}
			}

			if a.client == nil {
				a.client = http.DefaultClient
			}

			ctx := oidc.ClientContext(context.Background(), a.client)
			provider, err := oidc.NewProvider(ctx, issuerURL)
			if err != nil {
				return fmt.Errorf("Failed to query provider %q: %v", issuerURL, err)
			}

			a.provider = provider
			a.verifier = provider.Verifier(&oidc.Config{ClientID: a.clientID})
			a.shutdownChan = make(chan bool)

			rand.Seed(time.Now().UnixNano())
			a.codeVerifier = fmt.Sprint(rand.Int31())

			http.HandleFunc("/", a.handleLogin)
			http.HandleFunc(u.Path, a.handleCallback)
			http.HandleFunc("/favicon.ico", a.fuckFavicon)

			switch listenURL.Scheme {
			case "http":
				log.Printf("listening on %s", listen)
				go open(listen)
				go a.waitShutdown()
				return http.ListenAndServe(listenURL.Host, nil)
			default:
				return fmt.Errorf("listen address %q is not using http or https", listen)
			}
		},
	}

	// Configurable variables
	c.Flags().StringVar(&a.clientID, "client-id", "$(DEFUALT_CLIENT_ID_HERE)", "OAuth2 client ID of this application.")
	c.Flags().StringVar(&a.redirectURI, "redirect-uri", "http://127.0.0.1:8080/callback", "Callback URL for OAuth2 responses.")
	c.Flags().StringVar(&issuerURL, "issuer", "$(DEFAULT_ISSUER_URL_HERE)", "URL of the OpenID Connect issuer.")
	c.Flags().StringVar(&listen, "listen", "http://127.0.0.1:8080", "HTTP(S) address to listen at.")
	c.Flags().BoolVar(&a.debug, "debug", false, "Print all request and responses from the OpenID Connect issuer.")
	c.Flags().StringVar(&a.kubeconfig, "kubeconfig", "", "Kubeconfig file to configure")
	c.Flags().StringVar(&a.context, "cluster-context", "", "Cluster name for new context")

	return &c
}

func main() {
	if err := cmd().Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(2)
	}
}

func (a *app) oauth2Config(scopes []string) *oauth2.Config {
	// Setting AuthStyle=1 changes the auth to the post body, and not a basic header
	endpoint := a.provider.Endpoint()
	endpoint.AuthStyle = 1

	return &oauth2.Config{
		ClientID:    a.clientID,
		Endpoint:    endpoint,
		Scopes:      scopes,
		RedirectURL: a.redirectURI,
	}
}

// Stop the shitty browser from making multiple requests
func (a *app) fuckFavicon(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(404)
}

// Make the first request to IdP setting up PKCE as our authentication method.
func (a *app) handleLogin(w http.ResponseWriter, r *http.Request) {
	var scopes []string

	codeChallengeSha := sha256.Sum256([]byte(a.codeVerifier))
	codeChallengeEncode := base64.RawURLEncoding.EncodeToString(codeChallengeSha[:])

	codeChallengeOption := oauth2.SetAuthURLParam("code_challenge", codeChallengeEncode)
	codeChallengeMethod := oauth2.SetAuthURLParam("code_challenge_method", "S256")

	// var authCodeURL string
	scopes = append(scopes, "groups", "openid")
	authCodeURL := a.oauth2Config(scopes).AuthCodeURL(exampleAppState, codeChallengeOption, codeChallengeMethod)

	http.Redirect(w, r, authCodeURL, http.StatusSeeOther)
}

// Handles the redirect callback
func (a *app) handleCallback(w http.ResponseWriter, r *http.Request) {
	var (
		err   error
		token *oauth2.Token
	)

	ctx := oidc.ClientContext(r.Context(), a.client)
	oauth2Config := a.oauth2Config(nil)
	switch r.Method {
	case "GET":
		// Authorization redirect callback from OAuth2 auth flow.
		if errMsg := r.FormValue("error"); errMsg != "" {
			http.Error(w, errMsg+": "+r.FormValue("error_description"), http.StatusBadRequest)
			return
		}
		code := r.FormValue("code")
		if code == "" {
			http.Error(w, fmt.Sprintf("no code in request: %q", r.Form), http.StatusBadRequest)
			return
		}
		if state := r.FormValue("state"); state != exampleAppState {
			http.Error(w, fmt.Sprintf("expected state %q got %q", exampleAppState, state), http.StatusBadRequest)
			return
		}

		plainTextCodeVerifier := oauth2.SetAuthURLParam("code_verifier", a.codeVerifier)
		token, err = oauth2Config.Exchange(ctx, code, plainTextCodeVerifier)
	default:
		http.Error(w, fmt.Sprintf("method not implemented: %s", r.Method), http.StatusBadRequest)
		return
	}

	if err != nil {
		http.Error(w, fmt.Sprintf("failed to get token: %v", err), http.StatusInternalServerError)
		return
	}

	// Get the raw token so we can verify it below, and check our output.
	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok {
		http.Error(w, "no id_token in token response", http.StatusInternalServerError)
		return
	}

	idToken, err := a.verifier.Verify(r.Context(), rawIDToken)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to verify ID token: %v", err), http.StatusInternalServerError)
		return
	}
	var claims json.RawMessage
	idToken.Claims(&claims)

	buff := new(bytes.Buffer)
	json.Indent(buff, []byte(claims), "", "  ")
	var m claim
	err = json.Unmarshal(claims, &m)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to read claims: %v", err), http.StatusInternalServerError)
		go func() {
			a.shutdownChan <- true
		}()
		return
	}

	err = updateKubeConfig(rawIDToken, m, a)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to update kubeconfig: %v", err), http.StatusInternalServerError)
		go func() {
			a.shutdownChan <- true
		}()
		return
	}

	renderToken(w, a.redirectURI, rawIDToken, token.RefreshToken, buff.Bytes(), a.debug)
	fmt.Printf("Login Succeeded as %s\n", m.Username)
	if a.debug {
		fmt.Printf("ID Token: %s\n", rawIDToken)
		fmt.Printf("Refresh Token: %s\n", token.RefreshToken)
		fmt.Printf("Claims: %s\n", string(claims))
	}

	go func() {
		a.shutdownChan <- true
	}()
}

func (a *app) waitShutdown() {
	irqSig := make(chan os.Signal, 1)
	signal.Notify(irqSig, syscall.SIGINT, syscall.SIGTERM)

	//Wait interrupt or shutdown request through /shutdown
	select {
	case sig := <-irqSig:
		log.Printf("Shutdown request (signal: %v)", sig)
		os.Exit(0)
	case <-a.shutdownChan:
		os.Exit(0)
	}
}

// Update the specified kube config with the authentication and context info
// Precedence: Explicit command line path => KUBECONFIG env => Default ~/.kube/config
func updateKubeConfig(IDToken string, claims claim, a *app) error {
	var config *k8s_api.Config
	var outputFilename string
	var err error

	clientConfigLoadingRules := k8s_client.NewDefaultClientConfigLoadingRules()

	if a.kubeconfig != "" {
		if _, err = os.Stat(a.kubeconfig); os.IsNotExist(err) {
			config = k8s_api.NewConfig()
			err = nil
		} else {
			clientConfigLoadingRules.ExplicitPath = a.kubeconfig
			config, err = clientConfigLoadingRules.Load()
		}
		outputFilename = a.kubeconfig
	} else {
		outputFilename = clientConfigLoadingRules.Precedence[0]
		outputFilename = expandTilde(outputFilename)

		if _, err = os.Stat(outputFilename); os.IsNotExist(err) {
			config = k8s_api.NewConfig()
			err = nil
		} else {
			clientConfigLoadingRules.ExplicitPath = outputFilename
			config, err = clientConfigLoadingRules.Load()
		}
	}
	if err != nil {
		return err
	}

	authInfo := k8s_api.NewAuthInfo()
	if conf, ok := config.AuthInfos[claims.Username]; ok {
		authInfo = conf
	}

	authInfo.AuthProvider = &k8s_api.AuthProviderConfig{
		Name: "oidc",
		Config: map[string]string{
			"client-id":      a.clientID,
			"id-token":       IDToken,
			"idp-issuer-url": claims.Iss,
		},
	}

	config.AuthInfos[claims.Username] = authInfo

	if a.context != "" {
		contextInfo := &k8s_api.Context{
			Cluster:  a.context,
			AuthInfo: claims.Username,
		}
		contextName := fmt.Sprintf("%s-%s", claims.Username, a.context)
		config.Contexts[contextName] = contextInfo
	}

	fmt.Printf("Writing config to %s\n", outputFilename)
	err = k8s_client.WriteToFile(*config, outputFilename)
	if err != nil {
		return err
	}
	return nil
}

// ~/ doesn't expand inside our environment variable, so we need to do it
func expandTilde(path string) string {
	if strings.HasPrefix(path, "~/") {
		usr, _ := user.Current()
		dir := usr.HomeDir
		path = filepath.Join(dir, path[2:])
	}
	return path
}

// Open the browser to our webserver url
func open(url string) error {

	var cmd string
	var args []string

	switch runtime.GOOS {
	case "windows":
		cmd = "cmd"
		args = []string{"/c", "start"}
	case "darwin":
		cmd = "open"
	default: // "linux", "freebsd", "openbsd", "netbsd"
		cmd = "xdg-open"
	}
	args = append(args, url)
	return exec.Command(cmd, args...).Start()
}
