# plurama-cli

A curl-like command line client for the [plurama](https://plurama.eighttrigrams.net)
apps. It exists so that a shell — or an agent driving a shell — can talk to a
running plurama app in one line, without juggling logins and bearer tokens:

```bash
plurama-cli treina /describe
plurama-cli treina '/trainings/?search=squat'
plurama-cli treina /trainings/ -X POST --body '{"name":"Squat"}'
plurama-cli tracker /today-board
plurama-cli rhizome '/contexts?q=Books'
```

The first argument names the app, the second is the request path (query string
included). Everything else mirrors curl. Paths are relative to `/api`, the
one root every plurama app serves its API under — so the same `/describe`
works everywhere. A path that already starts with `/api` is passed through
unchanged, so the older absolute form keeps working.

| flag | meaning |
|------|---------|
| `-X, --method METHOD` | HTTP method. Defaults to `GET`, or `POST` when a body is given. |
| `-d, --body BODY` | Request body. `@file` reads it from a file. Sets `Content-Type: application/json`. |
| `-H, --header "K: V"` | Extra header. Repeatable. |
| `-i, --include` | Print the status line and response headers. |
| `--raw` | Do not pretty-print JSON responses. |

`plurama-cli apps` lists the configured apps. The exit code is `0` for a 2xx
response, `1` for any other HTTP status, and `2` for a local error.

## The configured apps

| app | endpoint | identity |
|-----|----------|----------|
| `treina` | `https://treina.eighttrigrams.net` | `admin` |
| `tracker` | `https://tracker.eighttrigrams.net` | `daniel-machine`, the machine user bound to `daniel` |
| `tracker-just-msg` | `https://tracker.eighttrigrams.net` | `plurama-development`, a **mail-only** machine user bound to `daniel` |
| `rhizome` | `http://127.0.0.1:3007` | none — local, unauthenticated |
| `blog` | `https://eighttrigrams.net` | `notes-user` — may `POST /api/notes` to deliver a Note, and nothing else |
| `cookbook` | `https://cookbook.eighttrigrams.net` | `machine-user` — writes **unsupervised**; the one thing it cannot do is cross the publish latch |

Blog's `notes-user` is the narrowest identity here: it authorises exactly one write.
Every read stays public, and a notes token presented to a read is **ignored** rather
than rejected — `GET /api/articles` answers 200 with or without it — so the credential
never changes what the API returns.

```bash
plurama-cli blog /notes --body '{"title":"Read this","description":"…"}'
```

Two things follow from tracker being a *machine* user: reads are unrestricted,
but writes pass the recording-mode gate, so a `POST` returns
`{"dropped":true}` while recording is off. Rhizome has the same gate, plus it
rejects any mutation whose body lacks a `reason` field.

**Cookbook is the deliberate exception, and it matters because the gate fails
quietly.** Do not carry the rule above over to it: cookbook has **no**
recording-mode gate at all, by design. It is an agentic memory store, so a
credentialled client writes freely and unsupervised — there is no toggle, and
`{"dropped":true}` is not a thing that can come back from it. A reader who
assumes the house rule would conclude their writes were being dropped when they
are landing.

Its one boundary is the **publish latch**. Recipes are private by default;
publishing makes one public *and* freezes it against machine mutation, in a
single irreversible step — so publishing is an act of taking ownership rather
than just of visibility, and there is no unpublish. Concretely, `machine-user`
may read everything, create Recipes, and edit or delete **unpublished** ones
without ceremony; editing, deleting or publishing a **published** Recipe is a
`403` that no switch lifts.

```bash
plurama-cli cookbook /recipes                     # title + useful-when only
plurama-cli cookbook '/recipes/7?detail=full'     # …and the body
```

The listing is lean on purpose rather than as an optimisation: the reader here is
an agent, so it scans title and useful-when to decide what is relevant and then
fetches exactly one body.

`tracker-just-msg` points at the same tracker, but its user carries
`mail-only`, which means the recording gate drops **every** mutating request
except the gate-exempt ones. In practice that leaves exactly one useful write:

```bash
plurama-cli tracker-just-msg /messages \
  --body '{"sender":"Plurama Development Coordinator","title":"Need your input on X"}'
```

Post as **`Plurama Development Coordinator`** — that is the sender this target
is meant to appear under in the inbox.

Use it when something needs to reach the inbox and nothing else should be
writable — it cannot create tasks, edit anything, or delete. Reads still work,
so it is also the safest target for a quick look at the inbox.

## Authentication

Most apps are JWT-authenticated. The CLI logs in via
`POST /api/auth/login` on first use, caches the token under
`~/.cache/plurama-cli/<app>.token` (mode `600`), and re-authenticates
automatically when the server answers `401`. An app configured without a
`:username` is treated as unauthenticated: no login, no `Authorization`
header.

Credentials come from one of two places:

1. **Baked in at install time.** The `baked-credentials` var holds the marker
   `__BAKED_CREDENTIALS__` in this repo. An installer may replace it with
   base64-encoded EDN, so the installed script carries its own credentials and
   nothing has to be configured on the machine.
2. **`~/.config/plurama-cli/credentials.edn`**, used when the marker is still in
   place.

Either way the shape is the same:

```clojure
{:treina  {:base-url "https://treina.eighttrigrams.net"
           :username "admin"
           :password "…"}
 :rhizome {:base-url "http://127.0.0.1:3007"}}
```

Keep that file at mode `600`; it is a plaintext password store.

## Install

Requires [babashka](https://babashka.org) and
[bbin](https://github.com/babashka/bbin).

```bash
bbin install https://raw.githubusercontent.com/eighttrigrams/plurama-cli/main/plurama_cli.clj --as plurama-cli
```

Or run it straight from a checkout: `bb plurama_cli.clj treina /describe`.

## `cookbook-tui` — a second binary in this repo

`cookbook_tui.clj` is a line-based browser and editor for cookbook, installed as
its own command **alongside** `plurama-cli`. One run of the private
`deploy-plurama-cli-cookbook-tui-and-us-vs-them-cli.sh` puts both on `PATH`,
from the same credential blob.

```bash
cookbook-tui
```

It lists Recipes as **title + useful-when only** — the lean projection is the
point, so it does not fetch bodies it is not showing — then `<n>` opens one in
full, `n` writes a new one, `/text` searches, `e` edits, `v` shows the version
history, `q` quits. The two short fields are prompted inline, and leaving a
prompt blank keeps the current value.

Bodies are edited **in the tool**, not in `$EDITOR` — it is a TUI and it stays
one. A new body is typed straight in and ended with a lone `.`; an existing one is
shown numbered and edited a line at a time (`a` append, `i N` insert before,
`r N` replace, `d N` delete, `c` clear, `w` done), because retyping a whole Recipe
to change one word is not editing.

Markdown is printed **raw**. It is a text format and reads fine as text; a
terminal renderer with Clojure highlighting would be a project of its own.

It authenticates as `machine-user`, so it inherits exactly that identity's one
limit: **it cannot edit or delete a published Recipe, and it cannot publish.**
Those come back as explanations rather than as a bare `403`. The `p` command
exists and asks for confirmation — publishing is irreversible — but publishing is
the owner's act, done from the web UI, so from here it is expected to be refused.

Run it from a checkout without installing: `bb cookbook_tui.clj`. Unbaked, it
reads `~/.config/plurama-cli/credentials.edn`, so a `:cookbook` entry pointing at
`http://127.0.0.1:3170` is enough to drive a local cookbook. It shares
`~/.cache/plurama-cli/cookbook.token` with `plurama-cli`, so signing in through
either serves both.

It reads **only** its own `:cookbook` entry. The baked blob is a map of every
configured app — the same map already inside the `plurama-cli` binary at mode
`700`, so not new exposure — and nothing here prints it or any other app's row.
