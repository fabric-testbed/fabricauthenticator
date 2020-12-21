[![Requirements Status](https://requires.io/github/fabric-testbed/fabricauthenticator/requirements.svg?branch=vouch)](https://requires.io/github/fabric-testbed/fabricauthenticator/requirements/?branch=master)

# Fabric Authenticator for Jupyterhub

The authenticator for Fabric Testbed Jupyterhub
Based on CILogon authentication, in addition it checks if user belongs to Fabric JUPYTERHUB COU group

## Usage
### If using dockerspawner:

In jupyter_config.py:

```
   import fabricauthenticator
   c.JupyterHub.authenticator_class = 'fabricauthenticator.FabricAuthenticator'
   c.Authenticator.enable_auth_state = True

   # set the OIDC client info in following CILogon configuration
   c.CILogonOAuthenticator.client_id = ""
   c.CILogonOAuthenticator.client_secret = ""
   c.CILogonOAuthenticator.oauth_callback_url = "<host>/hub/oauth_callback"
```

### if using KubeSpawner

in config.yaml:

```
hub:
  extraConfig:
    authconfig: |
      c.Authenticator.enable_auth_state = True
      c.CILogonOAuthenticator.client_id = ""
      c.CILogonOAuthenticator.client_secret = ""
      c.CILogonOAuthenticator.oauth_callback_url = "<host>/hub/oauth_callback"
auth:
  type: custom
  custom:
      className: fabricauthenticator.FabricAuthenticator
```
