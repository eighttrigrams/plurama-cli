# plurama-cli

A curl-like command line client for the [plurama](https://plurama.eighttrigrams.net)
apps. It exists so that a shell — or an agent driving a shell — can talk to a
running plurama app in one line, without juggling logins and bearer tokens:

```bash
plurama-cli treina /api/describe
plurama-cli treina '/api/trainings/?limit=10'
plurama-cli treina /api/trainings/ -X POST --body '{"name":"Squat"}'
```

The first argument names the app, the second is the request path (query string
included). Everything else mirrors curl.

| flag | meaning |
|------|---------|
| `-X, --method METHOD` | HTTP method. Defaults to `GET`, or `POST` when a body is given. |
| `-d, --body BODY` | Request body. `@file` reads it from a file. Sets `Content-Type: application/json`. |
| `-H, --header "K: V"` | Extra header. Repeatable. |
| `-i, --include` | Print the status line and response headers. |
| `--raw` | Do not pretty-print JSON responses. |

`plurama-cli apps` lists the configured apps. The exit code is `0` for a 2xx
response, `1` for any other HTTP status, and `2` for a local error.

## Authentication

Each app is a JWT-authenticated web app. The CLI logs in via
`POST /api/auth/login` on first use, caches the token under
`~/.cache/plurama-cli/<app>.token` (mode `600`), and re-authenticates
automatically when the server answers `401`.

Credentials come from one of two places:

1. **Baked in at install time.** The `baked-credentials` var holds the marker
   `__BAKED_CREDENTIALS__` in this repo. An installer may replace it with
   base64-encoded EDN, so the installed script carries its own credentials and
   nothing has to be configured on the machine.
2. **`~/.config/plurama-cli/credentials.edn`**, used when the marker is still in
   place.

Either way the shape is the same:

```clojure
{:treina {:base-url "https://treina.eighttrigrams.net"
          :username "admin"
          :password "…"}}
```

Keep that file at mode `600`; it is a plaintext password store.

## Install

Requires [babashka](https://babashka.org) and
[bbin](https://github.com/babashka/bbin).

```bash
bbin install https://raw.githubusercontent.com/eighttrigrams/plurama-cli/main/plurama_cli.clj --as plurama-cli
```

Or run it straight from a checkout: `bb plurama_cli.clj treina /api/describe`.
