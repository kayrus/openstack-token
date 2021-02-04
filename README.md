# token

A simple tool to decode or generate OpenStack Fernet tokens.

# Quick Start

Use the [config.yaml](config.yaml.example) example to configure the tool.

## Verify

Set an `OS_AUTH_TOKEN` environment variable to decode and verify the token.

## Generate

When an `OS_AUTH_TOKEN` environment variable is not set, the tool will try to generate a project scoped token using the `--user-id` (`OS_USER_ID` env variable) and `--project-id` (`OS_PROJECT_ID` env variable) flags. When `--project-id` flag is empty or invalid, the tool will generate an unscoped token (details below).

When `--user-id` is unknown, the `--user-name` (`OS_USER_NAME` env variable) and `--user-domain-id` (`OS_USER_DOMAIN_ID` env variable) will be used to generate the user ID (works only with users, which come from AD/LDAP).

To generate and print a random Fernet key use `--generate-key` CLI argument.
