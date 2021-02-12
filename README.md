# token

A simple tool to decode or generate OpenStack Fernet tokens.

# Quick Start

Use the [config.yaml](config.yaml.example) example to configure the tool.

## Verify

Set an `OS_AUTH_TOKEN` environment variable to decode and verify the token.

## Generate

When an `OS_AUTH_TOKEN` environment variable is not set, the tool will try to generate a project scoped token using the `-user-id` (`OS_USER_ID` env variable) and `-project-id` (`OS_PROJECT_ID` env variable) flags. When `-project-id` flag is empty or invalid, the tool will generate an unscoped token (details below).

When `-user-id` is unknown, the `-user-name` (`OS_USER_NAME` env variable) and `-user-domain-id` (`OS_USER_DOMAIN_ID` env variable) will be used to generate the user ID (works only with users, which come from AD/LDAP).

To generate a domain scoped token, specify a `-domain-id` (`OS_DOMAIN_ID` env variable) argument.

To generate and print a random Fernet key use `-generate-key` CLI argument.

# Example

## Verify

```sh
$ OS_AUTH_TOKEN=gAAAAABgHrIyjxg1uhHRszMPJ5c_dbs06ijQsiRc2aKbquUZeSsQgm7NtYZ8J3kqyofilwPx0Y5wDq4GS7inZeDP6Xj1mcYl_dd9GkXYoRfAk9Adv6qUfPQzajoVJgqnwcIF8jntnd2G2eSJU8uCqf60mF79pT9j5jKF4l-GmOHK5GxzvicdkEVTdNLOkPLS_BnCyXJ2gvdR token
Type: ProjectScoped
UserID: 28f6d90bb6d948ac9105b90bcc1e3a84
AuthMethods: 1 ["password"]
ProjectID: 5b7d00a6d7a94f8fb57de9c6ef858ea8
ExpiresAt: 3000-03-12 12:12:12 +0000 UTC
ExpiresIn: 2562047h47m16.854775807s
AuditIDs: ["XLKFCG23T66BbaJ-uC7uWg" "sGEDVFDgTDO4rumtnbui5g"]
```

## Generate

```sh
$ token -project-id 5b7d00a6d7a94f8fb57de9c6ef858ea8 -user-id 28f6d90bb6d948ac9105b90bcc1e3a84
Type: ProjectScoped
UserID: 28f6d90bb6d948ac9105b90bcc1e3a84
AuthMethods: 1 ["password"]
ProjectID: 5b7d00a6d7a94f8fb57de9c6ef858ea8
ExpiresAt: 2021-02-08 22:08:29 +0000 UTC
ExpiresIn: 3h59m59.142362161s
AuditIDs: ["5XhC5EnaYDty7vmZ-n1nQA"]
Generated token: gAAAAABgIX4dX7dpqI7epLIIk4m370dRbNA3f4bzEudSdcsKkBiFdruHFyVaPM9UeOM8pwIVe95PoS99xUByNtnvoiH-FzVQsZ6R6oYnqXSAR2InTGk2EyOLVKAiM94v9pv3q-2RiSeB2oOInNqcod5rNWC6NJ7CysXbUx7rkGCi-Xh4yQDcjweSsVXAdD-_w6WGczHyHuew
```
