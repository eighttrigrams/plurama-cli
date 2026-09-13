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

**Since the cookbook seal landed, that one-file install is no longer enough** —
and `make dist` is the answer to it. `plurama_cli.clj` and `cookbook_tui.clj`
both `require` `cookbook_seal.clj`, so whatever installs them has to carry that
file too, and a URL is one file. From a checkout `bb.edn` puts the seal on the
classpath and nothing has to be done; installed as a lone file, babashka refuses
to start. Nothing about this fails quietly:

```
Could not locate cookbook_seal.bb, cookbook_seal.clj or cookbook_seal.cljc on classpath.
```

So there is a `Makefile` now, the same one `us-vs-them` has and for the same
reason. `bb uberscript` collects the required namespaces into one self-contained
script — the concatenation the seal's own docstring asks for — and

```bash
make dist                    # target/plurama-cli, target/cookbook-tui, target/cookbook-seal-migrate
make install                 # the two commands, flattened, on your PATH
make dist DIST=/tmp/stage    # build somewhere else; what a deploy does
```

`make install` installs them **unbaked**: they carry the credential marker
rather than credentials, so they read `~/.config/plurama-cli/credentials.edn`
as above. The owner's install is the private
`deploy-plurama-cli-cookbook-tui-and-us-vs-them-cli.sh`, which builds these same
artifacts with `make dist` and then substitutes the credential blob into them.

`make dist` also builds `cookbook-seal-migrate`, which is not installed — see
its section below. The `Makefile` says why it is built anyway.

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

## Cookbook's prose is encrypted, and this is one of the two clients

Cookbook seals the **prose** in its clients — a Recipe's description, its
useful-when line, the `reason` and `context` an agent writes about its own
change, and a Scope's description. Thirteen columns. Everything you *find* things
by stays in the clear: titles, tags, Scopes and Scope tags, which is the same
line cookbook's search already drew.

It is done in the clients because cookbook runs on fly and **the key never goes
there**. So there are exactly two surfaces that decrypt: the web UI, which holds
a non-extractable key in the browser, and this program, which is how agents read
and write. Both implement one envelope — `enc:v1:<base64(nonce ‖ ciphertext ‖
tag)>`, AES-256-GCM, a fresh nonce per value — and a shared test-vector file in
the cookbook checkout is what keeps the two from drifting.

**Two credentials, and they answer different questions.** The machine token says
who may *write*; the key says who may *read prose*. An agent with a token and no
key can fill the shelf and cannot read a word of what is on it. That is not a
misconfiguration to fix — it is a real and sometimes wanted arrangement.

### Where the key comes from

Three places, in order. The first one that answers wins:

| | |
|---|---|
| `COOKBOOK_SEAL_KEY` | the key, base64. What a `sops exec-env` wrapper hands over. |
| `COOKBOOK_SEAL_KEY_FILE` | a path to read it from. |
| `~/.config/plurama-cli/cookbook-seal.key` | the default file, mode `600`. |

**No key means sealing is off** — reads and writes pass through untouched, which
is cookbook before any of this existed and is what a half-migrated shelf needs.
A key that is present but malformed throws instead: writing plaintext into a
sealed shelf while believing otherwise is the one failure worth being loud about.

**A sandboxed agent gets none of the three.** In a devbox the key stays host-side
in the credential proxy, exactly as the passwords do — see *The proxy holds the
key, so the box does not* below.

`plurama-cli apps` says which of the two it is, and names the source without ever
printing the key.

### What that changes about using it

Nothing, mostly. Bodies come back as text and go out as text; the sealing happens
in between.

Three things are worth knowing:

- **A `--raw` cookbook response is re-serialised**, so its key order may differ
  from the server's. `--raw` means *do not pretty-print*; it has never meant *do
  not decrypt*.
- **A `PUT` to `/recipes/:id` or `/scopes/:id` makes one extra read first.** A
  value you did not change has to be written back as the very ciphertext already
  stored, or the server compares values, sees a change that is not one, and piles
  up a version and a history row for it. For a Recipe that read is `/versions`
  and deliberately not `?detail=full`: a full read counts as a consumption and
  ranks the shelf, and seal bookkeeping must not quietly reorder anybody's
  Cookbook.
- **Blank is never sealed.** An empty `reason` stays empty, and `null` stays
  `null` — cookbook needs *not recorded* and *recorded, and nothing* to go on
  meaning different things, and the server's own check that a machine write says
  why still has a blank to see.
- **An unchanged value is written back byte for byte, whichever encoding it is
  in** — the stored ciphertext on a sealed row, the stored plaintext on one
  nobody has migrated yet, and the unopenable envelope on a row this key does not
  open. A no-op stays a no-op in all three, which is what keeps the server from
  writing a version for it. If you are writing the migration pass, note the
  corollary: **it must pass no `stored` at all**, or it will be told that nothing
  has changed and will seal nothing.

### `caution` on a sealed Recipe: dropped, not passed on

`caution` — the per-line provenance split on `?detail=full` — is computed on the
server from the version history, and the server cannot read a sealed history. On
a sealed Recipe what comes back is **wrong, not incomplete**: base64 carries no
newlines, so the whole ladder reads as one line, and the single range you are
handed carries the *last writer's* label over line 1 of the plaintext. A Recipe
the owner wrote and an agent later edited at line 5 reads as if he had written
none of it.

**So this client takes the key off the response.** A sealed Recipe read here
carries no `caution` at all — the same shape a visitor gets, and the same thing
the web UI does at the same boundary. It happens **whether or not a key is
configured**, because a client that cannot read the prose is exactly the one that
cannot tell the split is a lie. Nothing else about the body changes; a response
neither the drop nor the unseal touched goes over the wire byte for byte.

The earlier wording here said *do not act on `caution` from a sealed Recipe*. It
is no longer possible to, which is better than being told not to.

**What is still missing is the number itself.** The browser does not merely drop
the split, it recomputes one, over the version ladder it can unseal — see
cookbook's README, *Which lines are his, when they are sealed*. This client could
do the same: `us-vs-them` runs under babashka by design and `GET
/recipes/:id/versions` is already fetched here on a write. What stops it is
packaging rather than design — `et.uvt.core` and `et.uvt.caution` would have to
go on `bb.edn`'s `:paths` **and** be baked into both binaries by the private
deploy script, which already has one outstanding change against it (see *Install*
above, on `cookbook_seal.clj`). Until that is done, an agent reading a sealed
Recipe here is told nothing about which lines are the owner's, where the browser
is told everything. That is a real gap and it is named rather than papered over.

### Publishing a sealed Recipe: the owner's browser, and only it

Publishing **unseals**. The publisher reads what the Recipe's trail still holds
in ciphertext (`GET /api/recipes/:id/sealed`), opens all of it with the key it
has, and hands the plaintext back with the publish; the server writes it in
place and sets the latch in one transaction, refusing the lot if an envelope
would remain. There is no unpublish, so it happens once and it is permanent.

**Neither binary here can do that, and neither should.** Both sign in as
`machine-user`, and cookbook refuses a machine publish with a 403 whatever it
carries — publishing is an act of taking ownership, which is the boundary
described above and not a seal question. So both keep a refusal in front of the
call, now saying where to go rather than that the feature is missing: publish it
from the web UI. It is defence in depth on an irreversible act, one round trip
earlier than the server's own refusal.

## `cookbook-seal-migrate` — the pass that seals a database

`cookbook_seal_migrate.clj` walks the thirteen prose columns of a cookbook
SQLite file and seals every value that is not sealed already. It is what closes
the gap between *everything written since the seal landed is sealed* and
*everything written before it is not*.

```bash
bb cookbook_seal_migrate.clj --verify  data/cookbook.db   # read-only, exits 1 if broken
bb cookbook_seal_migrate.clj --dry-run data/cookbook.db   # decide everything, write nothing
bb cookbook_seal_migrate.clj          data/cookbook.db    # seal
bb cookbook_seal_migrate.clj --unseal data/cookbook.db    # the escape hatch
```

It runs from a checkout — it is not one of the installed binaries, because it is
not a thing anybody runs twice. `make dist` builds it anyway, next to the two
that are: it requires the seal like they do, so it has the same lone-file
problem, and it runs wherever the *database file* is. Needing a checkout at that
moment buys nothing, and one script you can copy next to the backup you are
about to seal is the better shape. Its `--help` still names the checkout
invocation above, which is the one the deploy script and this README document.
It needs `sqlite3` on `PATH` and a key, and
**unlike every other client here it refuses to run without one**: no key means
sealing off everywhere else, and here that would be a pass that walks the whole
shelf, writes nothing and reports success.

**Direct SQL, never the HTTP API.** That path compares prose values to decide
version bumps, writes a history row for each one, flips `has_human_edit` and
files proposals — so a pass driven through `PUT /api/recipes/:id` would rewrite
the version ladder in the act of protecting it. The ladder is what `caution`
reads to say which lines are the owner's.

**It never touches a published Recipe** — not its row, not its history, not its
proposals. Publishing is a one-way unseal and there is no unpublish, so a
published Recipe's prose is deliberately in the clear. Scopes are walked whatever
their Recipes are: a Scope's description is served to no visitor at any `?detail`,
so it stays the owner's. Thirteen columns here, twelve in the server's publish
guard.

It prints its counts — sealed, already sealed, blank, published, and anything it
could not open — because a pass whose output is *done* is a pass nobody can
check. The header prints the key's **fingerprint**, which is the eight characters
the web UI's ⚙ panel shows: sealing a database with a key the browser cannot open
is the one mistake here with no recovery, and comparing eight characters is the
whole of how to not make it.

A second run changes nothing and says so. One row is one statement is one
transaction, so a pass killed halfway leaves a legal half-sealed database — mixed
state is legal permanently, everywhere — and the next run picks up where it
stopped. Each write carries the values it read in its `WHERE`, **and that the
Recipe is still unpublished**, so neither a value that moved underneath the pass
nor a Recipe published underneath it is written over.

**It exits non-zero for anything it cannot call finished** — not only for a
`--verify` violation. A value it could not open, a nested envelope, a prose
column holding a BLOB, an envelope inside a published Recipe's trail, a row that
moved, or a journal beside the database: each prints a paragraph saying what it
is and what to do, and none of them lets the summary line claim the database is
where it should be.

### Running it against production

The key is never on fly, so the pass cannot run there. It runs on the owner's
laptop against a pulled copy, and the sealed file goes back up — a downtime
cutover, once:

1. **Back the database up — with any `-journal` or `-wal` beside it — and open
   the backup.** This is the irreversible step.
2. Stop writes; pull `/app/data/cookbook.db`.
3. `--dry-run`, and read the counts. **Check the fingerprint in the header against
   the ⚙ panel**; and if `PUBLISHED-SEALED` is anything but 0, stop.
4. Seal. Then `--verify`, **which must exit 0**. This is not advisory: the pass
   and the verify catch different things, and the verify is what catches a Recipe
   published while the pass ran.
5. Push it back; start.

**If the pass was interrupted — a closed terminal, a sleeping laptop, an
impatient `Ctrl-C` — do not copy the file. Run the pass again first.** In
`journal_mode=delete`, which is what cookbook uses, an interrupted write leaves a
`-journal` holding the pre-images while the database file is already modified, so
the `.db` on its own is either torn or silently different from what was
committed. Opening the database is the repair — SQLite rolls the journal back —
which is why re-running fixes it, and why the walker names any journal it finds
and then exits non-zero even though it has just repaired it: the run that did the
repairing is not the run whose exit code you should push on. Never copy a `.db`
while a `-journal` or `-wal` sits beside it.

Deploy the unseal-capable clients **first** and confirm them live: prefix-driven
unseal makes the mixed window legal, and the failure mode is a cached old browser
bundle meeting `enc:v1:…`. Afterwards the backups in `backups/` stop being
plaintext copies of the shelf — the old tarballs still are, and restoring one
lands back in plaintext.

## `tracker-seal-migrate` — the pass that seals one user's prose

`tracker_seal_migrate.clj` is the same pass asked a different question. Cookbook
has one owner, so its walker seals a database; tracker has several users and
exactly one of them holds a key, so this one seals **a user**:

```bash
bb tracker_seal_migrate.clj --user daniel --verify  data/tracker.db   # read-only, exits 1 if broken
bb tracker_seal_migrate.clj --user daniel --dry-run data/tracker.db   # decide everything, write nothing
bb tracker_seal_migrate.clj --user daniel           data/tracker.db   # seal
bb tracker_seal_migrate.clj --user daniel --arm     data/tracker.db   # flip the gate, last
bb tracker_seal_migrate.clj --user daniel --unseal  data/tracker.db   # the escape hatch
```

It runs from a checkout, needs `sqlite3` on `PATH`, and **refuses to run without
a key** — for the reason cookbook's does: no key means passthrough everywhere
else in this program, and here that would be a pass that walks the whole database,
writes nothing, and reports success.

**`--user` is required, and a default would be the one mistake with no cheap
undo.** Guessing wrong seals rows nobody asked to seal, and getting back out of
that needs the key *and* a second downtime. Named rows and their machine users
are walked; every other user's rows are not read and not written, in any mode.

**Nine description columns and the audit log.** `messages` and `mottos` stay
clear permanently and are only counted — messages because three writers that hold
no key produce them (the IMAP poller, the blog, tracker's own crawler), mottos
because a motto body is a second name rather than prose. The log is sealed for the
opposite reason: it is the one place where a deleted thing's prose outlives the
thing, so leaving it would leave a plaintext copy of everything the pass had just
sealed. Prose *inside* each payload is sealed; the titles beside it stay clear,
because the server builds those payloads and holds no key.

**Direct SQL, never the HTTP API** — and here that is not a preference. Writing
through `PUT /api/tasks/:id` records an audit event per write, so a pass driven
that way would fill the log it is in the middle of sealing, and would never
converge.

### `--arm` is a separate act, and it goes last

`users.seal_prose` is the server's half: with it up, a write that introduces new
plaintext prose into a sealed column is refused. The flag is not the seal and the
seal is not the flag, so they are two flags on the command line:

- **`--arm` refuses while anything of his is still unsealed.** A gate raised over
  an unfinished pass turns every remaining plaintext row into a row that can be
  read and not saved.
- **`--disarm` is the first act of getting back out**, and `--unseal` is refused
  while the gate is up — the same unusable state, reached from the other side.

So: seal, verify, *then* arm. Getting back: disarm, unseal, verify.

### What it prints, and when it exits non-zero

The header names the key's source and its **fingerprint** — the same eight
characters tracker's ⚙ panel shows. Sealing a database with a key the browser
cannot open is the mistake here with no recovery, and comparing eight characters
is the whole of how not to make it.

`--verify` asserts the invariant in both directions: everything of his that must
be sealed is, nothing of anybody else's is, and nothing at all in the tables that
stay clear. With `--unseal` it asserts the inverse — no envelope anywhere.

It **exits non-zero for anything it cannot call finished**, not only for a
`--verify` violation: a value that carries the prefix and will not open with this
key (`unopenable`), a value that carries the prefix and is not an envelope at all
(`NOT-ENVELOPE`), an envelope inside an envelope (`NESTED`), a row that moved
underneath the pass, or a `-wal`/`-journal` beside the database. Each prints a
paragraph saying what it is and what to do. A summary line saying *done* over any
of those would be the failure this project keeps catching in review.

A second run changes nothing and says so. One row is one statement is one
transaction, so an interrupted pass leaves a legal half-sealed database — mixed
state is legal permanently, everywhere — and the next run picks up where it
stopped. Each write carries the values it read in its `WHERE`, so a value that
moved underneath the pass is reported rather than written over.

**If the pass was interrupted, do not copy the database file. Run the pass again
first** — the same rule, and the same reason, as cookbook's: opening the database
is what repairs it, and the run that did the repairing is not the run whose exit
code you should push on.

The full production sequence — pulling the file off fly, the order the clients
have to be deployed in, and what to check afterwards — is in
`handoffs/tracker-seal-deploy-playbook.md`, because it is a downtime cutover and
belongs in one place rather than two.

## The proxy holds the key, so the box does not

`plurama_cli_proxy.clj` is the credential sidecar the devboxes talk to: the box
gets a build of `plurama-cli` whose baked blob holds base-urls and no passwords,
and this process attaches the credential on the way past. Since the seal it does
the same thing with the key — **for cookbook and for tracker, with a different
key each**.

- **Responses are unsealed** on the way back, so an agent in the box reads prose.
- **Request prose is sealed** on the way out, so an agent writes prose.
- Neither the key nor anything derived from it is ever in the box.

The alternative was a key file mounted into the box, beside the credentials this
whole program exists to keep out of it. It is the same trade the baked passwords
were — except that a leaked password can be rotated and **a leaked key cannot**.
It opens every Recipe the owner has ever written — and, with the second key,
every description in his tracker — and there is no re-encrypting them against a
copy somebody took. That is also why there are two keys rather than one for both
apps: a leak that cannot be rotated out of the data should not cost two stores.

The mounts go beside the credentials one, and the box gets none of them:

```yaml
environment:
  BABASHKA_CLASSPATH: /app
volumes:
  - ${HOME}/.local/share/plurama-cli/proxy-credentials.edn:/credentials.edn:ro
  - ${HOME}/.config/plurama-cli/cookbook-seal.key:/cookbook-seal.key:ro
  - ${HOME}/.config/plurama-cli/tracker-seal.key:/tracker-seal.key:ro
  - ../plurama-cli/seal_envelope.clj:/app/seal_envelope.clj:ro
  - ../plurama-cli/cookbook_seal.clj:/app/cookbook_seal.clj:ro
  - ../plurama-cli/tracker_seal.clj:/app/tracker_seal.clj:ro
  - ../tracker/src/cljc/et/tr/seal_rules.cljc:/app/et/tr/seal_rules.cljc:ro
```

The four source mounts are not decoration. The proxy `require`s them rather than
carrying a second copy of the envelope, and **babashka puts neither the script's
directory nor the working directory on the classpath by itself** — so they have to
be mounted and `BABASHKA_CLASSPATH` has to name where. If one is forgotten the
proxy refuses to start, which is the loud half of the failure; the quiet half
would have been two spellings of one envelope, which is the thing this project's
reviews have caught twice.

Four files and not one, because the shape says what is shared and what is not:
one envelope (`seal_envelope.clj`) both apps use, one inventory per app saying
which columns hold prose, and tracker's pure rules — which live in *tracker's*
checkout, not here, because its server and its browser read that same file. Three
implementations, one list.

A bind mount whose source is missing does not fail: docker creates an empty
**directory** at that path. So the key guard asks `.isFile`, not `.exists` — a
directory is *no key*, which is passthrough, rather than a malformed key, which
stops the process. That distinction was learned by crash-looping this sidecar.

`PLURAMA_PROXY_SEAL_KEY` overrides cookbook's path and
`PLURAMA_PROXY_TRACKER_SEAL_KEY` tracker's; the cookbook one keeps its
app-less name because that is what the deployed boxes already set.
**No key configured is passthrough**,
byte for byte, which is this proxy before any of this existed and is right for a
shelf nobody has sealed yet. A key that is there and malformed stops the process
at `docker compose up`, before the line that says *listening*.

The startup lines — one per app — name the source and print the key's
**fingerprint**, the same eight characters each web UI's ⚙ panel shows, so that
*the proxy holds the key my browser holds* is a comparison anyone can make in five
seconds:

```
 cookbook prose: sealed here, key /cookbook-seal.key fingerprint d53515b0
 tracker prose: passthrough -- no key at /tracker-seal.key
```

(`d53515b0` is the test key in `seal-vectors.edn`, so that the one example line
in this file names a key that is in the repo on purpose rather than one somebody
is actually using.)

### The key belongs on one side of this hop, never both

If the box holds a key too, it seals before the proxy does, and the proxy sealing
again would write `enc(enc(…))` — which the browser opens once and displays as an
envelope, with nothing anywhere reporting an error. If the box's key were a
*different* key, the result would open for nobody, ever.

So the rule is enforced rather than believed: **a write whose prose arrives
already sealed is refused**, 400, naming the columns.

```json
{"error":"this proxy seals cookbook prose, and description arrived already
          sealed. The key belongs on one side of the proxy or the other, never
          both — unset it in the box.",
 "reason":"already-sealed","columns":["description"]}
```

The one envelope that is *not* a foreign one is the value the row already holds:
a client echoing back a value the proxy could not open is not sealing, and
comparing against what is stored is what tells the two apart.

### What else it does, and what it never says

- **A value it cannot open comes back as it is** — `enc:v1:…`, visibly — rather
  than throwing. One unreadable column beside everything that reads beats a
  response dropped with nothing to say why. That is rule 3 in every client here.
- **A `caution` computed over ciphertext is taken off the body**, and this is the
  proxy's job now rather than the box's: the in-box client asks the same question,
  but by the time it sees a body the proxy has opened it, so it would pass on a
  provenance split the server computed over base64 — a lie about which lines are
  the owner's, told to the one reader written to act on it.
- **One extra upstream read** in front of a write that carries prose, for the echo
  rule: `/versions`, never `?detail=full`, because a full read counts as a
  consumption and ranks the shelf. A write with no prose in it asks nothing and
  goes over the wire byte-identical.
- **The audit line carries a count and never a value**, and never the key:

      ALLOW :put /cookbook/api/recipes/7 -> 200 sealed:2 opened   a real edit
      ALLOW :put /cookbook/api/recipes/7 -> 200 echoed:2 opened   the same body again
      DENY :put /cookbook/api/recipes/7 - prose already sealed: description

  `sealed:n` is columns newly sealed and `echoed:n` is columns handed back as the
  ciphertext the row already held, counted apart so that *the echo rule fired* is
  something the log can be read for — one number could not tell a real edit from
  an idempotent resend.

The in-box client needs no change for any of this. It holds no key, so its own
sealing is off by its own first rule — the build mounted in the boxes today
predates the seal entirely, and it goes on working.
