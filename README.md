# Fabric Authenticator for Jupyterhub

The authenticator for Fabric Testbed Jupyterhub
Based on CILogon authentication, in addition checks if user belongs to Fabric JUPYTERHUB COU group

## Usage
In jupyter_config.py:

```
   import fabricauthenticator
   c.JupyterHub.authenticator_class = 'fabricauthenticator.FabricAuthenticator'
```