# k8s-oidc-pkce

## Why does this exist
I took the example code provided by [Pusher](https://github.com/pusher/k8s-auth-example) and made several changes:
1. This code is configured to use PKCE as the authentication method
2. Provide example for testing on Minikube
3. Properly respect `KUBECONFIG` environment variable
4. Allow writing new contexts from the command line

I decided not to write the client secret and refresh token into the kube config. Because we're using PKCE, we no longer require the client secret for authentication. I omit writing the refresh token, because unless your provider allows you to limit the number of refreshes on a token. You could eventually have a token that last forever. I wanted to avoid this, thus forcing people to reauthenticate at whatever interval the maintainer deems appropriate.

## Installerino
```
git clone git@github.com:Popsiclestick/k8s-oidc-pkce.git
go get
go build
```

## Run
```
:; k8s-oidc
```

## Test
Stand up minikube with the additional API options
```
:; minikube start --extra-config=apiserver.oidc-client-id=$(PUT_YOUR_CLIENT_ID_HERE_FROM_YOUR_IDP) --extra-config=apiserver.oidc-username-claim=$(PUT_WHATEVER_KEY_CONTAINS_YOUR_USER_NAME) --extra-config=apiserver.oidc-issuer-url=$(PUT_YOUR_ISSUER_URL_HERE) --extra-config=apiserver.oidc-username-prefix=oidc: --extra-config=apiserver.oidc-group-prefix=oidc: --extra-config=apiserver.oidc-groups-claim=groups
```
Apply our example roles
```
kubectl apply -f oidc-rbac
```

### Kubernetes config
This code writes the user authentication information to your configuration file. You're going to need to tell your config context which user to use for authentication.

#### Example of my minikube config
The key pieces here are the `user: Popsiclestick` in the context and the user existing in `users:`
```
apiVersion: v1
clusters:
- cluster:
    certificate-authority: ca.crt
    server: https://192.168.99.105:8443
  name: minikube
contexts:
- context:
    cluster: minikube
    user: Popsiclestick <-------------- Important piece
  name: minikube
current-context: minikube
kind: Config
preferences: {}
users:
- name: minikube
  user:
    client-certificate: client.crt
    client-key: client.key
- name: Popsiclestick
  user:
    auth-provider:
      config:
        client-id: $(WRITTEN_BY_TOOL)
        id-token: $(WRITTEN_BY_TOOL)
        idp-issuer-url: $(WRITTEN_BY_TOOL)
      name: oidc
```


