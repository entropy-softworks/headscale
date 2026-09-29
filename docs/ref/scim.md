# SCIM provisioning

Headscale can act as a SCIM 2.0 service provider ([RFC 7643](https://www.rfc-editor.org/rfc/rfc7643),
[RFC 7644](https://www.rfc-editor.org/rfc/rfc7644)). An identity provider such as Microsoft Entra ID, Okta or Authentik
then pushes users and groups to Headscale as they change in the directory:

- Users are created ahead of their first login and updated when their profile changes.
- Deactivating a user at the identity provider [suspends](#suspension) them in Headscale at once: their nodes lose all
  peers until the user is reactivated.
- Deleting a user at the identity provider deletes them in Headscale, together with their nodes.
- Groups and their memberships are pushed as well, and the policy can reference them as `group:<name>@<domain>`.

Users still log in with [OpenID Connect](oidc.md). SCIM only manages who exists and which groups they are in; it does
not authenticate anyone. At a user's first login, Headscale [links](#link-provisioned-users-to-logins) the login to the
provisioned user.

!!! info "SCIM or OIDC group sync?"

    [OIDC group sync](oidc.md#use-identity-provider-groups-in-the-policy) reads the groups claim at login. It needs
    nothing but OIDC, but changes at the identity provider only reach Headscale at the user's next login: a user
    removed from a group, or disabled entirely, keeps their access until then.

    SCIM applies changes as soon as the identity provider sends them, whether the user logs in or not: Okta and
    Authentik push changes as they happen, Entra ID in provisioning cycles of about 40 minutes. Use SCIM when
    revoking access must not wait for a login, when users must exist before they first log in, or when leaving the
    company must also remove the user's nodes. Both can be enabled together, see [Groups managed by
    SCIM](#groups-managed-by-scim).

## Requirements

- [OpenID Connect](oidc.md) must be configured (`oidc.issuer`): it is the only way a provisioned user can log in.
  Headscale refuses to start with `scim.enabled` but no OIDC issuer.
- A domain for SCIM groups: `scim.groups_domain`, or `oidc.groups.domain` which it defaults to.
- An identity provider with a SCIM 2.0 client that can send a bearer token.
- `server_url` must be the URL the identity provider reaches Headscale at: resources returned to it carry absolute
  `meta.location` URLs built from it.

The SCIM endpoint is served at `/scim/v2` on the main listener, e.g. `https://headscale.example.com/scim/v2`, and only
while `scim.enabled` is set; otherwise every SCIM path is a 404.

## Configuration

The `scim` section of the [configuration](configuration.md) holds all settings. They are validated at startup, and an
invalid combination stops Headscale.

| Key                         | Default              | Effect                                              |
| --------------------------- | -------------------- | --------------------------------------------------- |
| `scim.enabled`              | `false`              | Serve `/scim/v2`. Requires `oidc.issuer`.           |
| `scim.groups_domain`        | `oidc.groups.domain` | Domain of SCIM groups: `group:<name>@<domain>`.     |
| `scim.link_by`              | `email`              | How logins find their user: `email`, `external_id`. |
| `scim.link_claim`           | `sub`                | OIDC claim matched against the SCIM `externalId`.   |
| `scim.adopt_existing_users` | `false`              | SCIM may take over existing OIDC users.             |
| `scim.require_provisioning` | `false`              | Refuse logins of users not provisioned.             |

- `scim.groups_domain` is required when `oidc.groups.domain` is not set. It must not contain `@`; ASCII letters are
  lowercased.
- `scim.link_by` accepts only `email` and `external_id`. With `external_id`, `scim.link_claim` must not be empty. See
  [Link provisioned users to logins](#link-provisioned-users-to-logins).
- `scim.adopt_existing_users` is described in [Bring an existing tailnet under
  SCIM](#bring-an-existing-tailnet-under-scim).
- `scim.require_provisioning` is described in [Keep deprovisioned users out](#keep-deprovisioned-users-out). It
  governs OIDC logins only: registrations with a pre-auth key are not affected.

```yaml
scim:
  enabled: true
  groups_domain: "example.com"
  link_by: "external_id"
  link_claim: "oid"
  adopt_existing_users: false
  require_provisioning: true
```

## Quick start

1. Configure [OpenID Connect](oidc.md) and check that users can log in.

1. Enable SCIM and pick how logins are linked to provisioned users. For Microsoft Entra ID:

    ```yaml
    scim:
      enabled: true
      groups_domain: "example.com"
      link_by: "external_id"
      link_claim: "oid"
    ```

    Restart Headscale.

1. Create a SCIM token for the identity provider. It is shown once:

    ```console
    headscale scim tokens create --description "Entra ID" --expiration 1y
    ```

    The token starts with `hskey-scim-`. Without `--expiration`, it expires after 90 days; `--expiration never` creates
    a token that does not expire.

1. In the identity provider, create a SCIM provisioning connection with:

    - SCIM base URL (also called tenant URL or connector base URL): `https://headscale.example.com/scim/v2`
    - Authentication: HTTP bearer token, the SCIM token from the previous step (`Authorization: Bearer hskey-scim-…`)

    See [Identity provider specific configuration](#identity-provider-specific-configuration) for the exact fields.

1. Assign users and groups to the application at the identity provider and start provisioning.

1. Check what arrived:

    ```console
    headscale scim users list
    headscale scim groups list
    ```

1. Reference the provisioned groups in the [policy](#reference-scim-groups-in-the-policy).

## Identity provider specific configuration

!!! warning "Third-party software and services"

    This section of the documentation is specific for third-party software and services. The names of settings change
    over time; please also consult the identity provider's documentation on SCIM provisioning.

Headscale handles the SCIM dialects of the identity providers below, including their different PATCH formats, without
any provider-specific setting. Any other SCIM 2.0 client with bearer-token authentication should work too.

| Identity provider  | `link_by` / `link_claim` | Deactivating a user | Deleting a user       |
| ------------------ | ------------------------ | ------------------- | --------------------- |
| Microsoft Entra ID | `external_id` / `oid`    | Suspends            | Deletes (hard delete) |
| Okta               | `external_id` / `sub`    | Suspends            | Not sent              |
| Authentik          | `external_id` / `sub`    | Suspends            | Deletes               |
| Access             | `external_id` / `sub`    | Suspends            | Deletes               |

### Microsoft Entra ID

Entra ID provisions through an enterprise application. If Headscale's OIDC login already uses an app registration, the
provisioning is configured on its enterprise application (Entra ID → Enterprise applications → the Headscale
application); otherwise create a non-gallery application: Enterprise applications → New application → Create your own
application → "Integrate any other application you don't find in the gallery (Non-gallery)".

In the application, open Provisioning, set the provisioning mode to Automatic and enter the admin credentials:

- Tenant URL: `https://headscale.example.com/scim/v2`

    The `?aadOptscim062020` feature flag is not needed. Headscale accepts both Entra ID's default PATCH format and the
    RFC-compliant one the flag enables, so the Tenant URL works with or without it.

- Secret Token: a SCIM token from `headscale scim tokens create`.

    Entra ID can also authenticate with the OAuth 2.0 client-credentials grant instead of a long-lived token, where
    offered for non-gallery applications. Create an OAuth client with the `scim` scope,
    `headscale oauth-clients create --scope scim`, and use `https://headscale.example.com/api/v2/oauth/token` as token
    endpoint, with the client's id and secret.

Select "Test Connection": it looks up a random user with the token.

Under Mappings, review the attribute mappings for users:

| SCIM attribute                 | Entra ID attribute                     | Notes                              |
| ------------------------------ | -------------------------------------- | ---------------------------------- |
| `userName`                     | `userPrincipalName` (default)          | Or `mail`; the matching attribute  |
| `externalId`                   | `objectId`                             | Default: `mailNickname`, see below |
| `active`                       | `Switch([IsSoftDeleted], …)` (default) | `false` [suspends](#suspension)    |
| `emails[type eq "work"].value` | `mail` (default)                       | One email per user                 |
| `displayName`, `name.*`        | defaults                               | Informational                      |

Map `objectId` to `externalId` and configure Headscale with `link_by: external_id` and `link_claim: oid`. The object ID
is the `oid` claim of Entra ID's ID token: it is immutable and never reassigned, unlike the UPN or mail, and Entra ID
does not normally send the `email_verified` claim that [linking by email](#link-by-email) requires. Other mapped
attributes, such as the enterprise extension or `title`, are accepted and ignored.

For groups, the default mappings (`displayName`, `objectId` → `externalId`, `members`) are what Headscale expects. The
object ID becomes the group's [policy alias](#reference-scim-groups-in-the-policy), which survives renames. Disable
group provisioning ("Provision Microsoft Entra ID Groups") if you only want users.

Under Settings, set the scope to "Sync only assigned users and groups" and assign the users and groups that should
exist in Headscale under Users and groups. Groups assigned this way provision their direct members. Turn provisioning
on. Entra ID provisions every 40 minutes; use "Provision on demand" to push a single user right away while testing.

Entra ID disables a user (`active: false`), and so [suspends](#suspension) them in Headscale, when the user is
unassigned from the application, falls out of the provisioning scope, is blocked from sign-in or is soft deleted. It
sends the deletion, which [deletes](#deletion) the user and their nodes, once the user is permanently deleted in the
directory.

### Okta

Create an app integration with SCIM provisioning. For an OIDC web app used for Headscale's login, enable "SCIM" as the
provisioning option on its General tab; alternatively add the "SCIM 2.0 Test App (Header Auth)" from the Okta
Integration Network. Then, on the Provisioning tab, under Integration:

- SCIM connector base URL: `https://headscale.example.com/scim/v2`
- Unique identifier field for users: `userName`
- Supported provisioning actions: "Push New Users", "Push Profile Updates" and "Push Groups". "Import New Users and
  Profile Updates" works too.
- Authentication Mode: HTTP Header, with the SCIM token as the bearer token in the Authorization header.

Select "Test Connector Configuration", save, and under Provisioning → To App enable "Create Users", "Update User
Attributes" and "Deactivate Users". Make sure the app's username format sends the user's email as `userName`, which is
Okta's default.

Okta sends the Okta user ID (`00u…`) as `externalId`, which is also the `sub` claim of its OIDC tokens: configure
Headscale with `link_by: external_id` and `link_claim: sub`. Okta also sends `email_verified`, so `link_by: email` works
as well.

Assign users on the Assignments tab. Push groups on the Push Groups tab; Okta does not send an `externalId` for pushed
groups, so they are referenced by their name only.

Okta deactivates users (`active: false`) when they are unassigned or deactivated in Okta, which [suspends](#suspension)
them in Headscale. Okta never deletes users through SCIM, so deprovisioned Okta users stay suspended in Headscale. To
remove such a user and their nodes, delete them in Headscale while SCIM is [disabled](#disable-scim).

### Authentik

Create a SCIM provider under Applications → Providers → Create → SCIM Provider:

- URL: `https://headscale.example.com/scim/v2`
- Token: a SCIM token from `headscale scim tokens create`

Select which users and groups to sync in the provider's filters, then open the Headscale application and add the SCIM
provider as a backchannel provider. Authentik syncs changes as they happen and all objects periodically.

Authentik's default mappings send the username as `userName` and the user's `uid` as `externalId`. With the OIDC
provider's default subject mode ("Based on the User's hashed ID") that is the `sub` claim, so `link_by: external_id`
with `link_claim: sub` links reliably. If you changed the subject mode, adjust `scim.link_claim` or the SCIM property
mapping so both carry the same value, or link by email: since the `userName` is not an email, Headscale then matches the
login's verified email against the SCIM email.

Deactivating a user in Authentik [suspends](#suspension) them in Headscale, and deleting them [deletes](#deletion) them.

### Access

Access provisions through its outbound SCIM connector, which is an ordinary SCIM 2.0 client:

- `base_url`: `https://headscale.example.com/scim/v2`
- `token`: a SCIM token from `headscale scim tokens create`
- Include `groups` in the connector's scope to push groups along with users.

Configure Headscale with `link_by: external_id` and `link_claim: sub`: the connector sends the user's subject identifier
as `externalId`.

### Other identity providers

JumpCloud, OneLogin and other identity providers with a generic SCIM 2.0 connector are configured the same way: use
`https://headscale.example.com/scim/v2` as the base URL and a SCIM token as the bearer token. Make sure the connector
sends a `userName`, and either:

- sends the same immutable user ID as `externalId` that the OIDC login carries in a claim, and configure
  `link_by: external_id` with that claim as `link_claim`; or
- sends the user's email as `userName` or primary email, keeps `link_by: email`, and the OIDC login asserts
  `email_verified: true`.

## Link provisioned users to logins

A provisioned user exists in Headscale before they ever log in. Until then, they are named after their lowercased
`userName`, their email is the SCIM email (or the `userName` if it looks like one), and they can already be referenced
in the policy. At the user's first OIDC login, Headscale looks for an unlinked provisioned user matching the login and
links the two. From then on the login owns the user's name, email and display name, as for any OIDC user, while the
SCIM attributes are kept alongside and shown by `headscale scim users list`.

A login that matches no provisioned user is handled as without SCIM: it creates a new user, unless
[`require_provisioning`](#keep-deprovisioned-users-out) is set. A provisioned user is linked only once: afterwards it no
longer matches other logins, and a different login that raced to link the same user is refused with a 403.

### Link by email

With `link_by: email` (the default), the login's email must equal the SCIM `userName`, or failing that the SCIM email
of exactly one unlinked user. The second rule covers identity providers that provision a `userName` which is not the
login's email, such as a UPN or a username.

- Headscale only uses an email that the identity provider asserts as verified, with `email_verified: true` from the same
  ID token or UserInfo response as the email. This holds even with `oidc.email_verified_required: false`, which only
  controls whether unverified emails are stored; Headscale logs a warning at startup for that combination. An identity
  provider that does not send `email_verified` never links by email.
- Emails are compared ignoring the case of ASCII letters only. Lookalike characters, such as the Kelvin sign (U+212A)
  for `k`, never match their ASCII counterparts, so an address spelled with them cannot claim another user.
- If several unlinked provisioned users share the login's email, none is linked.

### Link by external ID

With `link_by: external_id`, the string value of the OIDC claim named by `scim.link_claim` must equal the SCIM
`externalId` exactly (case-sensitive). The claim is read from the ID token, then from the UserInfo response; a claim
whose name contains a dot is looked up by its literal name first, then as a path into nested claims.

This is the recommended mode whenever the identity provider sends a suitable ID. The claim must be an identifier that
the identity provider never reassigns and users cannot change, never a name or an email, and the identity provider's
SCIM client must send the same value as `externalId`:

| Identity provider  | `scim.link_claim` | SCIM `externalId`                              |
| ------------------ | ----------------- | ---------------------------------------------- |
| Microsoft Entra ID | `oid`             | `objectId` (change the default `mailNickname`) |
| Okta               | `sub`             | The Okta user ID, sent by default              |
| Authentik          | `sub`             | The user's `uid`, sent by default              |
| Access             | `sub`             | The subject identifier, sent by default        |

A login without the claim is not linked.

### Bring an existing tailnet under SCIM

Users who logged in before SCIM was enabled already exist as OIDC users. By default, provisioning such a user is
refused with a 409 conflict, since its `userName` or email is already taken: Headscale never hands an existing account,
with its nodes, to the directory on its own.

To bring an existing tailnet under SCIM without duplicating users, enable adoption for the initial sync:

```yaml
scim:
  adopt_existing_users: true
```

A SCIM create then takes over an existing user instead of failing, but only if exactly one existing user has the
provisioned `userName` or email as their name or email, and that user:

- logged in with OIDC and is not yet managed by SCIM, and
- has the `userName` as their stored email. Matching a name is never enough, since names come from
  `preferred_username`, which users can often choose.

The adopted user keeps their login, nodes and group memberships from other sources, and SCIM manages them from then on.
Each adoption is logged at warn level. Any other overlap, with a local user, a user matching only by name, several
users, or a user already managed by SCIM, stays a 409.

!!! warning "Adoption hands existing accounts to the directory"

    Whoever controls the identity provider's directory can take over the account, and its nodes, of any OIDC user
    whose email they provision as a `userName`. Only enable adoption while bringing an existing tailnet under SCIM, and
    disable it again once the initial sync has completed.

    Stored emails are only verified if `oidc.email_verified_required` is `true` (the default). With `false`, adoption
    trusts unverified emails; keep adoption disabled in that case. Also keep it disabled if users from a previous OIDC
    provider remain in the database, see [Switching OIDC providers](oidc.md#switching-oidc-providers).

## Deprovisioning

### Suspension

Setting `active` to `false`, which identity providers do when a user is deactivated or unassigned, suspends the user.
Suspension takes effect immediately and follows Tailscale's semantics:

- The user's untagged nodes stay connected to Headscale but have no peers and are no one's peer. They receive an empty
  packet filter and SSH policy, so they accept no traffic.
- Subnet routes and exit nodes they advertise are no longer served; another node advertising the same route takes over.
- The user can no longer log in (403), register nodes, not even with their pre-auth keys or for a node restarting, or
  approve SSH check-mode sessions. Earlier SSH check approvals are forgotten.
- Tagged nodes are not affected, including those the user registered.
- Nodes, keys and group memberships are kept. Setting `active` back to `true` restores everything at once, without a
  new login.

A `PUT` that omits `active` keeps the user's current state instead of reactivating them, and a `PATCH` only changes
`active` when it sets it. A user created with `active: false` starts suspended.

### Deletion

Deleting a user through SCIM deprovisions them for good: they are suspended at once, then their nodes are deleted, then
the user with their pre-auth keys and group memberships. Tagged nodes are owned by their tags, not by a user, and are
kept.

### Keep deprovisioned users out

A deleted user no longer exists in Headscale, so their next OIDC login would create a new, unprovisioned user, and
suspension does not apply to them. Deprovisioning therefore only sticks if either:

- the identity provider itself refuses the user's sign-in to Headscale's OIDC client, as it does for users that are
  unassigned from the application when assignment is required, or disabled; or

- Headscale refuses logins from users that are not provisioned:

    ```yaml
    scim:
      require_provisioning: true
    ```

With `require_provisioning`, an OIDC login that matches no provisioned user is refused with a 403 and creates no user,
and users created by OIDC logins before, and not since adopted by SCIM, can no longer log in. Their existing nodes are
not affected. Registrations with a pre-auth key are not affected either. Enable it once the identity provider has
provisioned everyone who should have access.

### Suspend and restore users manually

Any user can also be suspended by an administrator, with the same effect as above:

```console
headscale users suspend --identifier <ID>
headscale users restore --identifier <ID>
```

The same is available in the v2 API as `POST /api/v2/users/{id}/suspend` and `POST /api/v2/users/{id}/restore`, with the
`users` scope. `headscale users list` shows each user's status and whether SCIM manages them, and the v1 API returns
them as the `suspended` and `scimManaged` fields.

For users managed by SCIM, the identity provider owns the suspension while SCIM is enabled:

- A manual suspension is a stopgap: it lasts until the identity provider next sends the user's `active` state, which
  may lift it.
- Restoring is refused with a 409: reactivate the user at the identity provider instead.
- `headscale users rename` and `headscale users destroy` are refused as well: change or delete the user at the identity
  provider.

## Groups

Groups pushed by the identity provider are stored with their members. Only provisioned users can be members; a
membership change reaches connected nodes immediately.

### Reference SCIM groups in the policy

A SCIM group is referenced as `group:<displayName>@<groups_domain>`, with the ASCII letters of the display name
lowercased, the same syntax as for [OIDC group sync](oidc.md#use-identity-provider-groups-in-the-policy). A group with
an `externalId` can also be referenced by the alias `group:<externalId>@<groups_domain>`, lowercased the same way.
Both can be used wherever a group can: grants, ACLs, SSH rules, tag owners and auto approvers.

For a group `Engineering` with the Entra ID object ID `3f2a8c1e-5b7d-4e9f-a1c2-6d8e0b4f7a93` and the groups domain
`example.com`:

```json
{
  "grants": [
    {
      "src": ["group:engineering@example.com"],
      "dst": ["tag:prod"],
      "ip": ["*"]
    },
    {
      "src": ["group:3f2a8c1e-5b7d-4e9f-a1c2-6d8e0b4f7a93@example.com"],
      "dst": ["tag:ci"],
      "ip": ["*"]
    }
  ]
}
```

`headscale scim groups list` shows each group's policy reference and alias.

- A display name that already ends with `@<groups_domain>` is used as is; any other display name containing `@` is
  refused. An `externalId` containing `@` is stored and matched as an ID, but gives the group no policy alias.
- Display names and aliases of SCIM groups share one namespace: a group whose name or alias would equal another SCIM
  group's name or alias is refused with a 409.
- A group reference nobody is a member of is valid and grants nothing, as for OIDC group sync.

!!! warning "Renaming a group breaks references to its name"

    A policy referencing a group by its display name stops matching when the group is renamed at the identity provider:
    it then grants nothing (fails closed) until the policy is updated. The alias of an immutable `externalId`, such as
    Entra ID's object ID, survives renames. Reference Entra ID groups by their alias, or keep group names stable.

Renaming a SCIM group to the name of a group created by OIDC logins absorbs that group: it is deleted with its OIDC
memberships.

### Groups managed by SCIM

SCIM is authoritative for the groups it manages: only SCIM memberships grant them. When [OIDC group
sync](oidc.md#use-identity-provider-groups-in-the-policy) is also enabled with the same domain:

- Memberships of a SCIM group that a user's groups claim asserts are ignored. When SCIM starts managing a group that
  OIDC logins created, the group is adopted with its ID and name, and its OIDC memberships are removed at once: its
  members lose the group until the identity provider pushes its members.
- The same holds for OIDC groups named like a SCIM group's alias. This covers Entra ID, whose groups claim carries the
  object IDs that are also the SCIM `externalId`s: `group:<objectId>@<domain>` is granted by SCIM only.
- Groups not provisioned through SCIM keep working through the groups claim, refreshed at each login.
- Non-SCIM memberships of SCIM groups are also removed at startup.

Deleting a group through SCIM removes it with all its memberships.

### Release a group

SCIM keeps ownership of its groups even if SCIM is disabled. To hand a group back to OIDC group sync after
turning SCIM off, release it:

```console
headscale scim groups release <ID>
```

The group keeps its ID, name and display name, so references to `group:<name>@<domain>` keep working; its SCIM
memberships and its `externalId`, and so its alias, are removed at once. Users whose groups claim asserts the group are
granted it again at their next login. Release is refused while `scim.enabled` is true, since the identity provider would
provision the group again; disable SCIM first.

## Disable SCIM

Remove `scim.enabled` (or set it to `false`) and restart. The SCIM endpoint is no longer served. Users provisioned
through SCIM remain, keep their links to their logins, and can be renamed, deleted and restored locally again. SCIM
groups remain managed by SCIM until [released](#release-a-group).

## Security

- **SCIM credentials:** The SCIM endpoint accepts only a SCIM token (`hskey-scim-…`) or an OAuth access token whose
  scopes include `scim`. Admin API keys are rejected, so the secret stored at the identity provider can neither
  administer the tailnet nor be revoked only by breaking the operator's CLI access. SCIM tokens are only accepted by the
  SCIM endpoint, never by the admin API.

- **The `scim` scope is explicit-only:** neither `all` nor `all:read` grants it, so an existing all-scope OAuth client
  does not gain the power to rewrite the user directory. A client needs `headscale oauth-clients create --scope scim`.
  There is no `scim:read`.

- **Treat a SCIM credential like an admin credential for users:** whoever holds it can create, suspend and delete users
  and their nodes, and change group memberships the policy relies on. Give each identity provider its own token with a
  description, and prefer an expiring token.

- **Rotation:** create a new token, update the identity provider, check that provisioning still succeeds, then revoke
  the old one. `headscale scim tokens list` shows when each token was last used.

    ```console
    headscale scim tokens create --description "Okta" --expiration 1y
    headscale scim tokens list
    headscale scim tokens revoke <ID>
    headscale scim tokens delete <ID>
    ```

    A revoked token stops authenticating at once but stays listed for audit; `delete` removes it.

- **Adoption and linking:** keep `adopt_existing_users` disabled except during an initial migration, and prefer
  `link_by: external_id` with an immutable claim. See [Link provisioned users to
  logins](#link-provisioned-users-to-logins).

- **Group memberships** pushed by the identity provider grant whatever the policy grants those groups: only provision
  groups whose membership is managed by administrators.

- Authentication failures are logged at warn level with the client address and cause, never with the token.

## Supported protocol

Headscale implements the parts of SCIM 2.0 that identity providers use for provisioning. Every request, discovery
included, requires the bearer token.

| Method   | Path                                    | Notes                                           |
| -------- | --------------------------------------- | ----------------------------------------------- |
| `GET`    | `/ServiceProviderConfig`                | PATCH and filter supported; no bulk, sort, ETag |
| `GET`    | `/ResourceTypes`, `/ResourceTypes/{id}` |                                                 |
| `GET`    | `/Schemas`, `/Schemas/{id}`             |                                                 |
| `GET`    | `/Users`, `/Groups`                     | `filter`, `startIndex`, `count`                 |
| `POST`   | `/Users`, `/Groups`                     | 201 with `Location`                             |
| `GET`    | `/Users/{id}`, `/Groups/{id}`           |                                                 |
| `PUT`    | `/Users/{id}`, `/Groups/{id}`           | 200                                             |
| `PATCH`  | `/Users/{id}`                           | 200 with the resource                           |
| `PATCH`  | `/Groups/{id}`                          | 204; 200 with the resource if projected         |
| `DELETE` | `/Users/{id}`, `/Groups/{id}`           | 204                                             |

- **Resources:** users support `id`, `externalId`, `userName`, `name` (`givenName`, `familyName`), `displayName`,
  `active`, `emails` and the read-only `groups`; groups support `id`, `externalId`, `displayName` and `members`.
  Headscale stores one email per user, the primary one, returned with type `work`. Unknown attributes, extension
  schemas, `roles` and `password` are accepted and ignored; passwords are never stored. IDs are Headscale's numeric user
  and group IDs.
- **Uniqueness:** `userName` is unique case-insensitively, `externalId` exactly; a group's `displayName` is unique
  ignoring the case of ASCII letters.
- **Filters:** the full RFC 7644 filter grammar: `eq`, `ne`, `co`, `sw`, `ew`, `gt`, `ge`, `lt`, `le`, `pr`, `and`,
  `or`, `not`, grouping and value paths such as `emails[type eq "work"]`, plus Entra ID's `.value` suffix after a value
  path. `userName`, `displayName` and `emails.value` compare case-insensitively, `id` and `externalId` exactly. A filter
  may be at most 4096 bytes and nest 32 levels deep.
- **PATCH:** `add`, `replace` and `remove`, case-insensitive, with or without a path, in the formats of Entra ID (with
  and without `aadOptscim062020`), Okta and Authentik. Booleans may be sent as `"True"`/`"False"` strings. Paths to
  attributes Headscale does not store are accepted and ignored. Removing a group member who is not one is a no-op;
  adding a member who is not a provisioned user is a 400 `invalidValue`.
- **Pagination:** `startIndex` is 1-based and `count` is at most 1000, the default when omitted. Results are ordered
  by ID, so pages are stable.
- **Media types:** request bodies may be `application/scim+json` or `application/json`; responses are
  `application/scim+json` with RFC 7644 error bodies.

Limits per request:

| Limit                                              | Value      | Beyond it          |
| -------------------------------------------------- | ---------- | ------------------ |
| Request body                                       | 1 MiB      | 413                |
| PATCH operations                                   | 1000       | 413                |
| Group member references (`POST`, `PUT` or `PATCH`) | 10000      | 413                |
| Emails per user                                    | 32         | 400 `invalidValue` |
| PATCH path length                                  | 1024 bytes | 400                |
| Results per page                                   | 1000       | Clamped            |

Not supported: bulk operations (`/Bulk`), sorting, ETags and versioned requests, password changes, `/Me` and `POST`
searches (`/.search`).

## Troubleshooting

Headscale logs every SCIM write at info level ("scim user provisioned", "scim user patched", "scim user deprovisioned",
…) and failed requests at debug level with their status, SCIM error type and detail ("scim request failed"). Set
`log.level: debug` to see why an identity provider's request was refused.

**401 Unauthorized:** the bearer token is missing, unknown, revoked or expired, or it is an admin API key
(`hskey-api-…`), which the SCIM endpoint never accepts. Look for "scim request unauthenticated" in the logs, check the
token with `headscale scim tokens list`, and create a new one if needed. Check that the identity provider sends
`Authorization: Bearer <token>`.

**403 Forbidden from the SCIM endpoint:** an OAuth access token without the `scim` scope. `all` does not include it;
create a client with `--scope scim`.

**403 at login:** the log line "user msg: …" names the cause.

- "your account is suspended": the user is [suspended](#suspension). Reactivate them at the identity provider.
- "user is not provisioned through SCIM", shown to the user as "Your account has not been provisioned for this
  tailnet": [`require_provisioning`](#keep-deprovisioned-users-out) is set and the login matches no provisioned user.
  Check that the user is assigned at the identity provider and listed by `headscale scim users list`, and that the
  login [links](#link-provisioned-users-to-logins): with `link_by: email` the login needs a verified email equal to the
  `userName` or SCIM email; with `link_by: external_id` the `link_claim` claim must equal the `externalId`. "OIDC login
  carries no string link claim" at debug level means the claim is missing.
- "provisioned user was linked to another login": a different login linked the provisioned user at the same time.

**409 Conflict when creating a user:** the `userName`, `externalId` or email is already held by another user. Usually
this is a user who logged in before SCIM was enabled; see [Bring an existing tailnet under
SCIM](#bring-an-existing-tailnet-under-scim). A local user with the same name has to be renamed or deleted first. The
log entry names the conflicting user.

**409 Conflict for a group:** another group already has the display name or `externalId`, or a SCIM group's alias
equals the name of another SCIM group.

**400 `invalidValue` for a group:** a member is not a user provisioned through SCIM (provision the user first, or
assign them to the application), or the display name contains `@`.

**A user shows up twice:** the user logged in before being provisioned and linking did not match, so the login created
its own user. Check the [linking](#link-provisioned-users-to-logins) settings, delete the duplicate OIDC user, or use
[adoption](#bring-an-existing-tailnet-under-scim).

**A group grants nothing:** compare the policy reference with the "Policy reference" and "Alias" columns of
`headscale scim groups list`; the group may have been renamed. `headscale users list` shows the groups each user holds.

**Useful commands:**

```console
headscale scim users list    # userName, externalId, email, linked, status
headscale scim groups list   # policy reference, alias, members, source
headscale users list         # groups, SCIM-managed, status of every user
```
