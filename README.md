# OpenID Connect auth plugin for PeerTube

Add OpenID Connect support to login form in PeerTube.

## Configuration

The callback URL to configure on the OIDC provider side is: <your-instance-url>/plugins/oidc-cnr/router/code-cb
If you don't specifie a role attribute new users will have a 'User' role by default.
If you use this attribute it should hold a paroperty that contains `tube.roles` Array with this values: 

- `Administrator#tube` (Administrator)
- `Moderator#tube` (Moderator)
- `User#tube` (User)

If you want to deny access use this boolean attribute `access-property` or you can use `group-property` and `allowed-group` you can allow only a subset of users to login.
