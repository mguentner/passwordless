# passwordless

authenticates without a password using e-mail and issues
short-lived JWT access tokens.

Thought as a library to cover the authentication domain of independent
services. Check `main.go` for a sample application.

The sample application serves all public keys under `/api/keys`, other services
can retrieve these and validate the JWT tokens.

# Usage

Create a set of keys using `create_signing_keys.sh`.

Example:

```
$ ./create_signing_keys.sh testKeys
```

Copy `config.sample.yaml` to `config.yaml` and adjust for your needs.
The key directory is set using the `keyPath` option.
Check `config/config.go` for comments on other options.

Run the application using `./passwordless --configPath config.yaml`

# Copyright and License

AGPLv3 (see LICENSE)

2021 Maximilian Güntner <code@mguentner.de>
