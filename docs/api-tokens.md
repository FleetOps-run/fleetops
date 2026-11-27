# API tokens

Enterprise. An API token lets CI jobs, scripts and other tools call the FleetOps API without a browser. A token acts as the user who created it, with that user's role and environment access, and every action it takes is written to the audit log under the token's name.

## Creating a token

On the **Account** page, under **API tokens**, choose **Create token** and give it:

- **Name**: what uses it, such as `ci-deploy`. Names are unique per user.
- **Expires**: 30 days, 90 days (the default), 1 year, or never.
- **Read-only**: the token may only read (GET). Anything that changes something is refused.

The token (`fo_` and 64 hex characters) is shown **once**. Copy it into your CI secret store; FleetOps keeps only a hash of it. Each user may have up to 50 tokens.

## Using a token

Send it in the `Authorization` header. No CSRF token is needed:

```sh
curl -H "Authorization: Bearer $FLEETOPS_TOKEN" https://fleetops.example.com/api/v1/envs

curl -X POST -H "Authorization: Bearer $FLEETOPS_TOKEN" \
  https://fleetops.example.com/api/v1/envs/prod/containers/web/restart
```

The full API is described at `/api/v1/openapi.json` on your server.

A request with an `Authorization` header is checked against the token only; a cookie sent with it is ignored. An unknown, expired or revoked token gets `401`.

## What a token cannot do

Some things need a person signed in with a browser:

- open the real-time websocket, so no container or pod terminals and no live log streams;
- sign out or change a password;
- create users, or set any user's password or role (an admin's token included), so a leaked token cannot turn itself into an account that outlives revoking it;
- create, list or revoke tokens (a token cannot make more tokens).

These answer `403` with `this needs a signed-in browser session`. A read-only token also gets `403` (`this token is read-only`) for anything other than GET.

## Revoking

Revoke a token on the **Account** page; it stops working at once. Admins see every user's tokens in **Admin → API tokens** and can revoke any of them. Disabling or deleting a user stops their tokens too.

## Audit

Every audit row written by a token request shows **via token *name*** next to the user. Creating and revoking tokens are audited as `token.create` and `token.revoke`. The audit export (CSV and NDJSON) has a `token_name` column.

## Without a license

When the license expires or is removed, requests with a token get `403` with code `license_required`. The tokens are kept, and work again as soon as a license is installed.
