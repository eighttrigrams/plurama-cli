(ns tracker-seal
  "Tracker's inventory, and the binding its ciphertexts carry.

  The envelope itself is `seal_envelope.clj` — shared with cookbook, because two
  spellings of one cryptographic control is how they drift. What is here is
  everything that is *about tracker*: which ten columns are sealed, what a value
  is bound to, which user's rows this applies to at all, and where prose hides
  inside the audit log.

  ## The line

  **Every `description` body, for one user, at every scope.** Titles, names, tags
  and badge titles stay clear: they are what the search runs on and what he chose
  to find things by, and prose was never that. Nine of tracker's eleven
  body-carrying entities already search `[:title :tags]` and read a body never, so
  sealing costs the search nothing — the same happy finding cookbook had, for the
  same reason, arrived at independently by whoever wrote those queries.

  ## One user, and this is what tracker has that cookbook did not

  Cookbook had one owner. Tracker has three humans in one SQLite file, and only
  one of them is sealing. So there is a second gate beside *does this client hold
  a key*: `users.seal_prose`, which the server reads and enforces and which this
  file does not consult at all.

  That split is deliberate. A client seals what it is told to seal; deciding
  *whose* rows those are is the server's job, because the server is the only
  party that knows who is asking. A CLI that tried to decide would be guessing
  from a username, and a guess that seals antonio's rows is not recoverable.

  ## The binding: nine tables, one name

  `item/description`, for all of them. That is not laziness, it is the schema
  being told the truth — the same argument cookbook's `bound-as` makes, arriving
  at a flatter answer because tracker's copying is flatter:

  - `db/issue.clj` `convert-issue-to-task` copies an issue's body into a task's,
    verbatim, server-side, with no key.
  - `db/task.clj` `convert-message-to-task` and `db/resource.clj`
    `convert-message-to-resource` do the same from a message.
  - A category's Group is mutable and **the row keeps its id**
    (`PUT /api/categories/:id/group`), so a value bound to `person/description`
    would stop opening the moment that category became a project.

  Bind per table and the first conversion seals a value shut in the column it
  lands in, with nothing anywhere to say why. Cookbook learned that from a live
  run that sealed a whole version ladder; there is no reason to learn it twice.

  The two-level shape is kept even though the first level is constant, because it
  is what refuses a value moved into some future *second* sealed column, and
  because `events/body` is already a second binding.

  ## `messages` is not in the inventory, and that is not a deferral

  Message bodies are written by three producers that hold no key and cannot be
  given one: the IMAP poller and blog's forwarding, both on fly, and tracker's own
  in-process feed worker. A fourth reason sits beside them — `messages` is one of
  only two list searches that reads a body, and the server *parses* message bodies
  to recover titles for YouTube and Atom items. Sealing them would need all of
  that plaintext. They stay clear, permanently.

  ## Sealing is off when there is no key

  As everywhere: `nil` key means values pass through untouched. That is what lets
  this ship inert, long before a key exists. The one client that must refuse to
  run without a key is the migration walker, because there *no key* would mean
  walking the whole database, writing nothing, and reporting success."
  (:require [et.tr.seal-rules :as rules]
            [seal-envelope :as env]))

;; ---------------------------------------------------------------------------
;; The envelope, re-exported so that no call site reaches past this namespace.

(def envelope-prefix env/envelope-prefix)
(def random-bytes env/random-bytes)
(def generate-key-base64 env/generate-key-base64)
(def fingerprint env/fingerprint)
(def sealed? env/sealed?)
(def envelope-shaped? env/envelope-shaped?)
(def blank-value? env/blank-value?)
(def seal-text-with-nonce env/seal-text-with-nonce)
(def seal-text env/seal-text)
(def unseal-text env/unseal-text)

(defn key-from-base64
  "A 32-byte key, given as base64, with tracker's name in the message — a laptop
  holds cookbook's key too, and which one is malformed is the whole of what the
  reader needs."
  [s]
  (env/key-from-base64 "tracker" s))

;; ---------------------------------------------------------------------------
;; The rules that are not the cipher, re-exported from where all three
;; implementations read them.
;;
;; `et.tr.seal-rules` is a `.cljc` file in the tracker checkout beside this one:
;; the prefix, what counts as blank, what a value is bound to, which ten columns
;; are sealed, and where prose hides inside an audit payload. Tracker's server
;; and tracker's browser read that same file. Nothing here restates any of it —
;; a second spelling of the inventory is how a new sealed column ends up walked
;; by two of three clients.

(def bound-as rules/bound-as)
(def aad rules/aad)
(def item-description-aad rules/item-description-aad)
(def event-body-aad rules/event-body-aad)
(def sealed-columns rules/sealed-columns)
(def clear-tables rules/clear-tables)
(def sealed-in rules/sealed-in)
(def prose-paths rules/prose-paths)
(def body-prose-paths rules/body-prose-paths)
(def entity-type->table rules/entity-type->table)
(def clear-entity-type? rules/clear-entity-type?)
(def api-segment->table rules/api-segment->table)
(def endpoint-table rules/endpoint-table)
(def endpoint-id rules/endpoint-id)
(def stored-entries rules/stored-entries)

;; ---------------------------------------------------------------------------
;; The three rules, bound to tracker's columns.

(defn unseal
  "Read one value out of one column. Prefix-driven, never throws, and a no-op
  when there is no key — see `seal-envelope/unseal-at`."
  [k table column v]
  (env/unseal-at k (aad table column) v))

(defn seal
  "Write one value into one column, under all three rules — see
  `seal-envelope/seal-at`, where they are argued at length.

  `stored` is what that column holds right now, and an unchanged value comes back
  as exactly those bytes. **A migration pass must pass `nil` as `stored`**, or it
  will be told, correctly, that nothing has changed and will seal nothing at all.

  In tracker the echo rule is not needed for correctness the way it is in
  cookbook — optimistic concurrency here keys on `modified_at` and not on content,
  so a re-nonced body would not cost a version. It is needed because
  `events/record-update!` diffs before against after: without it every no-op save
  writes an audit event holding two different envelopes of one unchanged
  sentence, forever."
  ([k table column v] (seal k table column v nil))
  ([k table column v stored]
   (env/seal-at k (aad table column) v stored)))

;; ---------------------------------------------------------------------------
;; Where the key comes from.

(def key-file
  "The default place tracker's key file is looked for. Mode 600, like the
  credentials beside it."
  (env/default-key-file "tracker"))

(def ^:private key-spec
  "Three places, in order: `TRACKER_SEAL_KEY` (base64, the shape a `sops
  exec-env` wrapper hands it over in), `TRACKER_SEAL_KEY_FILE` (a path), and the
  default file — the shape the proxy sidecar gets it in, a mounted file.

  **A different secret from cookbook's**, in a different file. One envelope, two
  apps, two keys: a leaked key cannot be rotated out of the data it already
  sealed, so there is no reason to make one leak cost two shelves."
  {:app "tracker"
   :env-var "TRACKER_SEAL_KEY"
   :file-var "TRACKER_SEAL_KEY_FILE"
   :default-file key-file})

(defn- key-location [] (env/key-location key-spec))

(defn load-key
  "The key, or `nil` — and `nil` means **sealing is off**, which is tracker's
  behaviour before any of this existed. A key that is present but malformed
  throws. See `seal-envelope/load-key`."
  []
  (env/load-key key-spec))

(defn key-source
  "Where `load-key` would find a **usable** key, in words, for the places this is
  reported. Never the key itself."
  []
  (env/key-source key-spec))

;; ---------------------------------------------------------------------------
;; Rows.

(defn unseal-row
  "Unseal every sealed column of one row of `table`, leaving every other key
  alone. A key the row does not carry stays absent — tracker's machine listings
  are lean on purpose (`middleware/machine_lean.clj` strips `:description`) and an
  unseal must not invent an empty body on a listing that deliberately has none."
  [k table row]
  (if (or (nil? k) (nil? row))
    row
    (reduce (fn [r column]
              (if (contains? r column)
                (assoc r column (unseal k table column (get r column)))
                r))
            row
            (get sealed-columns table))))

(defn seal-row
  "Seal every sealed column present in `row`, echoing `stored`'s value for
  anything that has not changed. `stored` is the row as this client last read it
  — see `seal`."
  ([k table row] (seal-row k table row nil))
  ([k table row stored]
   (if (or (nil? k) (nil? row))
     row
     (reduce (fn [r column]
               (if (contains? r column)
                 (assoc r column (seal k table column (get r column) (get stored column)))
                 r))
             row
             (get sealed-columns table)))))

;; ---------------------------------------------------------------------------
;; Prose inside the audit log.
;;
;; `et.tr.seal-rules/prose-paths` knows the five shapes; this knows how to walk
;; them synchronously. The browser knows how to walk the same paths with
;; promises. Splitting it that way is what stops the shape knowledge — the part
;; that would actually drift — being written twice.
;;
;; Going forward none of this needs doing: the server copies values that arrived
;; sealed, so a sealed body produces a sealed payload for free. What these are
;; for is the browser's audit view, which must open what it renders, and the
;; migration walker, which has thousands of historical payloads to seal.

(defn unseal-payload
  "Open every sealed value inside one already-parsed event payload. Prefix-driven
  and never throwing, like everything else: a payload from before the cutover
  passes through untouched, and a value this key cannot open comes back visibly."
  [k payload]
  (if (nil? k)
    payload
    (reduce (fn [p [path aad-str]]
              (update-in p path #(env/unseal-at k aad-str %)))
            payload
            (prose-paths payload))))

(defn seal-payload
  "Seal every prose value inside one already-parsed event payload.

  **There is no `stored` arity, and that is deliberate.** The only thing that ever
  seals a payload is the migration walker, and a walker must pass nothing to echo
  — hand it the value it just read and the echo rule will tell it, correctly, that
  nothing changed. Nothing else seals one: the server writes payloads by copying
  values that arrived sealed, and it could not echo anyway, having no key. An
  arity nobody may correctly call is a trap with a docstring, so there isn't one.

  The blank rule applies inside a payload exactly as it does in a column: an
  `old-value` of `\"\"` means *this body was empty before the edit*, and that is
  not a thing to encrypt."
  [k payload]
  (if (nil? k)
    payload
    (reduce (fn [p [path aad-str]]
              (update-in p path #(env/seal-at k aad-str % nil)))
            payload
            (prose-paths payload))))

(defn payload-sealed?
  "Whether a payload still holds anything in ciphertext — what a verify pass asks
  of the audit log, and what it can ask without a key."
  [payload]
  (boolean (some (fn [[path _]] (rules/sealed? (get-in payload path)))
                 (prose-paths payload))))

(defn- associable
  "The same JSON tree with every sequential node a vector.

  **cheshire answers a top-level JSON array with a `LazySeq`**, and a `LazySeq` is
  not associative, so `update-in` through an integer index into one throws
  `ClassCastException`. That is the whole of a live bug: `GET /api/tasks` — a
  listing, an array at the top — could not be opened at all, while
  `GET /api/tasks/1229` opened fine, its path being `[:description]` and never
  touching an index. It shipped because a listing is the one shape no test built:
  a fixture written in Clojure gives you a vector, and only the wire gives you
  this.

  Measured, and written down because the obvious guess is wrong: **it is only the
  top level**. Every array cheshire parses *inside* an object is already a
  `PersistentVector`, so `{:tasks [...]}` was never broken and `[...]` always
  was.

  The coercion is nonetheless written over the whole tree rather than the root
  alone. That fact is one parser's internals, and this function's contract is
  with *an already-parsed body* — `parse-stream`, another JSON library, or a
  later cheshire is free to differ, and none of them should be able to put the
  ciphertext back. Walking the tree costs a rebuild only when something is
  actually sealed, which is the same condition that already costs crypto.

  The browser needs none of this: `js->clj` yields vectors, so `seal.cljs` walks
  these very paths with `assoc-in` and always could."
  [x]
  (cond
    (map? x)        (reduce-kv (fn [m k v] (assoc m k (associable v))) x x)
    (sequential? x) (mapv associable x)
    :else           x))

(defn unseal-response-body
  "Open every sealed value anywhere in one already-parsed response body — the CLI
  and proxy's read path, and the same walk the browser uses.

  `et.tr.seal-rules/body-prose-paths` is where the argument for a tree walk over a
  shape dispatch lives. The short version: tracker binds all nine body-carrying
  tables under one name, so nothing has to be classified before it can be opened,
  and a new endpoint cannot silently go unsealed.

  **Whatever the body was parsed by, it is made associative first** — see
  `associable`, which exists because a listing parsed by cheshire is a `LazySeq`
  and this function could not open one. The coercion is gated behind the path
  count, so a body with nothing sealed in it is still handed straight back, the
  very same object: one walk, no crypto, no rebuild, which is every response
  before the cutover and every response for a user who is not sealing."
  [k body]
  (let [paths (when k (body-prose-paths body))]
    (if (empty? paths)
      body
      (reduce (fn [b [path aad-str]]
                (update-in b path #(env/unseal-at k aad-str %)))
              (associable body)
              paths))))

;; ---------------------------------------------------------------------------
;; The write path, for a process that sees one request.

(def write-target rules/write-target)
(def prose-in rules/prose-in)
(def state-path rules/state-path)

(defn stored-of
  "The sealed columns of a row as one map, out of the body of a `state-path`
  read. What the echo rule needs, and nothing else."
  [{:keys [table]} body]
  (when (map? body)
    (select-keys body (get sealed-columns table))))

(defn state-of
  "What the seal needs to know about the row a write is aimed at, out of the body
  of a `state-path` read — `{:stored …}`.

  A map with one key rather than the map itself, deliberately: it is the same
  shape `cookbook-seal/state-of` answers, so the proxy sidecar can hold one
  adapter per app and not one code path per app. Cookbook's carries a
  `:published?` beside it; tracker has nothing to publish, and the shape absorbs
  that difference instead of the caller doing it."
  [target body]
  {:stored (stored-of target body)})

(defn seal-write
  "Seal the prose of one write, or answer `nil` when there is nothing to do.

  `nil` — rather than the body re-serialised — is what lets a caller send exactly
  the bytes it was given. A write with no prose in it goes over the wire
  byte-identical to what the user typed, as it did before any of this existed.

  `state` is what `state-of` answered for that row, or `nil` for a create. Every
  rule the seal has applies per column: blank passes through, an unchanged value
  echoes whatever encoding it is already in, and only genuinely new text spends a
  fresh nonce."
  [k {:keys [table]} parsed state]
  (when (and k table (prose-in table parsed))
    (seal-row k table parsed (:stored state))))
