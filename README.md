# authwall

Pluggable login page.

## TODO

* CLI.
* Ensure the login page supports multiple providers.
* Ensure the login page looks decent in mobile.
* Add expiration to provider sessions.
* Cleanup.
* Add screenshot.
* Sign forwarded HTTP headers.

### CLI (TODO)

```sh
authwall \
	--listen 'localhost:3333' \
	--login '/login' \
	--ssh 'example.com:22' \
	--forward 'http://localhost:8000'
```

## Supported authentication methods

* LDAP
* SSH

## License

Apache 2.0
