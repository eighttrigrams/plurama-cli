(ns cookbook-seal
  "The Cookbook envelope, and the inventory of what goes inside it.

  Cookbook's security model draws one line: **prose is sealed, names and curated
  words are not.** Description, useful-when, and the `reason`/`context` pair an
  agent writes about its own change are the prose; title, tags, Scopes and Scope
  tags are how you find things, and they stay clear. The line is not a
  compromise — it is exactly the line the search already draws, so sealing costs
  the search nothing.

  Cookbook is served from fly and the key never goes there, so there is no
  trusted middle process: the seal lives in the clients, and there are two of
  them. The browser holds a non-extractable `CryptoKey` and uses WebCrypto; this
  file is the other one, and it is what `plurama-cli` and `cookbook-tui` — that
  is, every agent — read and write cookbook through.

  **Two implementations of one envelope is the drift this suite spends its
  docstrings warning about, and the answer is not discipline, it is a fixture.**
  `cookbook/test/fixtures/seal-vectors.edn` holds a known key, known nonces,
  known plaintexts and the exact ciphertext each must produce, plus a tamper case
  that must fail. Both this namespace's suite and cookbook's ClojureScript suite
  read that one file. A divergence is a red test rather than a Recipe nobody can
  open six months from now.

  ## The envelope

      enc:v1:<base64(nonce ‖ ciphertext ‖ tag)>

  AES-256-GCM, a fresh random 96-bit nonce per value, a 128-bit tag, standard
  base64 with padding. The value is stored as text in the column it came from, so
  the seal needs no schema migration, and the `enc:v1:` prefix is what lets a
  half-migrated database work: `unseal` of a value without it hands the value
  back unchanged. Mixed state is legal everywhere, permanently.

  **The AAD binds a value to what its column means** — `recipe/description`,
  `recipe/reason`, `scope/description` — so a ciphertext cannot be lifted from one
  column and dropped into another by anyone holding the database file.

  It binds the *meaning* rather than the table, and `bound-as` says why at length:
  the server copies these values between `recipes`, `recipe_history` and
  `recipe_proposals` verbatim and without a key, so a per-table binding seals a
  Recipe's history shut on its own first save.

  It does not bind the row either: the id is assigned by `AUTOINCREMENT` on
  insert, so at the moment of sealing there is nothing to bind to. That gap is
  deliberate and worth knowing.

  ## Three rules, and they live here rather than at the call sites

  1. **Never seal a blank value.** `nil` stays `nil`, `\"\"` stays `\"\"`, and so does
     any string that is only whitespace. Ciphertext is never NULL and never
     empty, so without this rule every historical row grows a *\"not recorded\"*
     that reads as *\"recorded, and empty\"* — and `reason`/`context` are nullable
     precisely because those two mean different things. It is also what keeps the
     server's mandatory-`reason` check working: blank arrives unsealed, so the
     server can still refuse it. That check validates the non-blankness of what
     the writer chose to send; it never could and now visibly cannot validate
     content.

  2. **Never re-seal an unchanged value.** A fresh nonce per value means sealing
     the same sentence twice gives two different ciphertexts — which is the point,
     it is what stops equality leaking — but cookbook's server compares prose
     *values* to decide no-op versus version bump versus history row, and for a
     machine PUT direct-write versus proposal. Seal naively and an agent resending
     text it did not change piles up versions, history rows, inbox entries and
     proposals, corrupting the very ladder this is meant to protect. So `seal`
     takes the value currently stored in that column and, when the new plaintext
     is the same, hands that stored ciphertext straight back, byte for byte. The
     server's equality then keeps working verbatim, with no server change at all.

  3. **`unseal` is prefix-driven.** A value without `enc:v1:` passes through
     untouched. That is what makes rule 1 safe, what makes a partial migration
     resumable, and what makes an unsealed cookbook and a sealed one the same code
     path.

  ## Sealing is off when there is no key

  Every function here takes the key as its first argument and treats `nil` as
  *sealing off*: values pass through unchanged, which is cookbook's behaviour
  before any of this existed. That keeps the whole thing reversible until the
  migration runs, and it lets both worlds be exercised.

  ## Shipping note

  This file is a namespace of its own rather than ~150 lines copied into
  `plurama_cli.clj` and again into `cookbook_tui.clj`. The credential block *is*
  copied between those two, and says so — thirty lines of convention where copying
  beats factoring. A cryptographic envelope is the opposite case: two copies of it
  is the drift the fixture exists to prevent, and a fixture cannot police a copy
  that is inlined into a `-main` script.

  `bb.edn` puts this on the classpath for a checkout. For the installed binaries,
  the deploy script must concatenate this file **before** each script that
  requires it — which is exactly what it already does for `us-vs-them`, whose
  installed single file is `core.clj`, `caution.clj` and `cli.clj` one after the
  other. Nothing fails silently if that is forgotten: babashka refuses to start."
  (:require [clojure.string :as str]
            [seal-envelope :as env]))

;; ---------------------------------------------------------------------------
;; The envelope, which is not cookbook's any more.
;;
;; It moved to `seal_envelope.clj` when tracker became the second app to seal
;; prose. What is generic — the `enc:v1:` shape, AES-256-GCM, the three rules,
;; how a key is found — is one file now, because two spellings of one
;; cryptographic control is how they drift, and a fixture cannot police a copy.
;;
;; What stayed is everything below that is *about cookbook*: what a value is
;; bound to, which thirteen columns are sealed, what a visitor may see, which
;; HTTP paths carry prose, and the shapes its responses come back in.
;;
;; These names are re-exported rather than left to callers to reach through, so
;; that every existing call site — `plurama_cli.clj`, `cookbook_tui.clj`, the
;; proxy, the walker, the suite — keeps reading exactly as it did.

(def envelope-prefix env/envelope-prefix)
(def random-bytes env/random-bytes)
(def generate-key-base64 env/generate-key-base64)
(def fingerprint env/fingerprint)
(def sealed? env/sealed?)
(def blank-value? env/blank-value?)
(def seal-text-with-nonce env/seal-text-with-nonce)
(def seal-text env/seal-text)
(def unseal-text env/unseal-text)

(defn key-from-base64
  "A 32-byte key, given as base64. `seal-envelope/key-from-base64` with
  cookbook's name in the message, because a laptop holds more than one key and
  which one is malformed is the whole of what the reader needs."
  [s]
  (env/key-from-base64 "cookbook" s))

(def bound-as
  "Which name a table's values are bound under — the AAD's first half.

  **Three tables share one binding, and that is not sloppiness, it is the schema
  being told the truth.** `recipes`, `recipe_history` and `recipe_proposals` are
  three places one per-version field lives, and the server *moves values between
  them, verbatim, without a key*:

  - `db.recipe/archive!` copies the outgoing row's four columns straight into
    `recipe_history` on every save.
  - `db.recipe/approve-proposal!` copies a proposal's straight into `recipes`.
  - `db.recipe/merge-content` fills a partial proposal from the current row, so a
    `recipes` value lands in `recipe_proposals`.

  Bind a ciphertext to `recipes/description` and the first save archives it into
  a column it can no longer be read from. That is not a hypothetical: it is what
  the first end-to-end run did, and the whole version ladder came back sealed with
  no error anywhere to say why. The server cannot re-seal on the way past — it has
  no key, which is the entire point — so the binding has to be one the server's own
  copying respects.

  **What it refuses is cross-*column* moves, and nothing else**: a description
  read as a useful-when, a reason read as a context, a Scope's prose read as a
  Recipe's. All three fail the tag check, and they are in the fixture. It permits
  every cross-table move — that is the point of the grouping — and every
  cross-*row* move too, since ids are assigned on insert and there is nothing to
  bind to at the moment of sealing.

  That is a smaller guarantee than it first sounds, and it is worth saying why it
  is enough. Every column that carries provenance — `source`, `version`,
  `has_human_edit` — is clear and unauthenticated, so somebody holding the
  database file can forge a version's authorship outright by editing the label
  beside the text. The AAD was never what protected provenance from that reader.
  What it protects is the one thing that reader could otherwise do *without*
  touching a label: silently make a Recipe's body read as its useful-when."
  {:recipes :recipe
   :recipe_history :recipe
   :recipe_proposals :recipe
   :scopes :scope})

(defn aad
  "What a ciphertext is bound to: the *meaning* of the column it belongs in, as
  `binding/column` — `recipe/description`, `scope/description`. See `bound-as`
  for why this is not the table name."
  [table column]
  (str (name (or (bound-as table)
                 (throw (ex-info (str "no seal binding for table " table) {:table table}))))
       "/" (name column)))

;; ---------------------------------------------------------------------------
;; The three rules, bound to cookbook's columns.
;;
;; The rules themselves are `seal-envelope/unseal-at` and `seal-envelope/seal-at`,
;; and their docstrings are where they are argued. These two are the arity every
;; cookbook call site wants — a table and a column rather than a resolved AAD —
;; so that no caller is ever in a position to spell a binding itself.

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
  will be told, correctly, that nothing has changed and will seal nothing at all."
  ([k table column v] (seal k table column v nil))
  ([k table column v stored]
   (env/seal-at k (aad table column) v stored)))

;; ---------------------------------------------------------------------------
;; Where the key comes from.

(def key-file
  "The default place cookbook's key file is looked for. Mode 600, like the
  credentials beside it."
  (env/default-key-file "cookbook"))

(def ^:private key-spec
  "Cookbook's three places, in order: `COOKBOOK_SEAL_KEY` (base64, the shape a
  `sops exec-env` wrapper hands it over in), `COOKBOOK_SEAL_KEY_FILE` (a path),
  and the default file — which is the shape a devbox gets it in, a mounted file,
  the same pattern as `docker/cookbook_creds`.

  Tracker's key is a different secret in a different file. One envelope, two
  keys: a leaked key cannot be rotated out of the data it already sealed, and
  there is no reason to make one leak cost two shelves."
  {:app "cookbook"
   :env-var "COOKBOOK_SEAL_KEY"
   :file-var "COOKBOOK_SEAL_KEY_FILE"
   :default-file key-file})

(defn- key-location [] (env/key-location key-spec))

(defn load-key
  "The key, or `nil` — and `nil` means **sealing is off**, which is cookbook's
  behaviour before any of this existed. A key that is present but malformed
  throws. See `seal-envelope/load-key`."
  []
  (env/load-key key-spec))

(defn key-source
  "Where `load-key` would find a **usable** key, in words, for the places this is
  reported. Never the key itself. See `seal-envelope/key-source`."
  []
  (env/key-source key-spec))

;; ---------------------------------------------------------------------------
;; The inventory.
;;
;; Thirteen columns, in one place. Both clients carry this list and nothing else
;; decides what is sealed; a rule written down twice is a rule that will drift.

(def sealed-columns
  "Table → the columns of it that hold prose.

  `recipes` is the current version, `recipe_history` the superseded ones, and
  `recipe_proposals` the machine writes that have not become versions yet — a
  per-version field has to be on all three or it vanishes on the next save.
  `scopes.description` is here on the model's own logic: it is prose, it is never
  searched, and a Scope's *title* and *tags* — which are the search surface — stay
  clear beside it.

  `recipe_scopes`, `users` and `recipe_events` hold no prose at all.
  `recipe_events.recipe_title` is a denormalised title, and titles are clear."
  {:recipes          [:description :useful_when :reason :context]
   :recipe_history   [:description :useful_when :reason :context]
   :recipe_proposals [:description :useful_when :reason :context]
   :scopes           [:description]})

(def published-surface
  "The columns a visitor is served, and therefore the ones whose being sealed
  makes publishing wrong.

  **In the fixture, and asserted by both suites against it**, because the publish
  interlock is implemented three times — the browser, `cookbook-tui`,
  `plurama-cli` — and a client that widened its idea of the published surface
  while another did not would leave a sealed column reachable through the narrower
  one. That is the shape round 1's finding 4 had: a name promising a guarantee
  nothing enforced.

  Not `reason`/`context` and not the history: a visitor is served none of them at
  any `?detail`, so their being sealed is not what makes publishing wrong."
  [:description :useful_when])

(defn published-surface-sealed?
  "Whether the two columns a visitor would be served arrived sealed, given the row
  as the database actually holds it."
  [stored]
  (boolean (some #(sealed? (get stored %)) published-surface)))

(defn unseal-row
  "Unseal every sealed column of one row of `table`, leaving every other key
  alone. A key the row does not carry stays absent — cookbook's projections are
  lean on purpose and an unseal must not invent an empty description on a listing
  that deliberately has none."
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
  "Seal every sealed column present in `row`, echoing `stored`'s ciphertext for
  any value that has not changed. `stored` is the row as this client last read
  it — see `seal`."
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
;; The shapes cookbook's API actually hands back.
;;
;; A row is not always one table's. A version list interleaves the current
;; `recipes` row with `recipe_history`; an inbox entry carries a proposal *and*
;; the recipe's current text beside it; Scopes ride along on nearly everything.
;; Since the AAD names the column a value came out of, unsealing has to know which
;; table each of those came from — so the mapping is written down here, once, next
;; to the inventory it uses.

(defn- unseal-scopes [k row]
  (if (sequential? (:scopes row))
    (update row :scopes #(mapv (partial unseal-row k :scopes) %))
    row))

(defn unseal-recipe
  "One `recipes` row, with the Scopes attached to it."
  [k row]
  (->> row (unseal-row k :recipes) (unseal-scopes k)))

(defn unseal-versions
  "`GET /api/recipes/:id/versions`. The newest entry is the `recipes` row itself
  and is flagged `:current`; everything below it is a `recipe_history` row.

  Both open, because the two tables share a binding — see `bound-as`, and note
  that this list is exactly where a per-table binding was found to be wrong: the
  history is made *by copying the current row*, so a ladder sealed per table is a
  ladder that cannot be climbed. The table is still passed rather than assumed,
  because it is the truth about where the row came from."
  [k body]
  (if (sequential? (:versions body))
    (update body :versions
            #(mapv (fn [v] (unseal-row k (if (:current v) :recipes :recipe_history) v)) %))
    body))

(def ^:private current-aliases
  "The inbox entry's second copy of the text: the Recipe as it reads *now*, joined
  in under `current_` names. They are `recipes` columns wearing an alias, and the
  alias is what has to be undone: the *column* is what a value is bound to, so a
  `current_description` is a `description` and reading it as a `useful_when` fails
  the tag check."
  {:current_useful_when :useful_when
   :current_description :description})

(defn unseal-proposal
  "A proposal as the inbox and the 409/202 bodies render it: the agent's own text
  out of `recipe_proposals`, **and** the Recipe's current text beside it, where a
  shape carries it under a `current_` alias.

  Both halves are here rather than one of them a level up, because this function
  and its ClojureScript twin have the same name and must mean the same thing. They
  did not: one undid the aliases and the other left that to its caller. They agreed
  on every body cookbook sends today — `pending-body` carries no aliases, so only
  the inbox has them — and would have disagreed the moment a 409 grew one, with the
  browser reading it and the CLI printing ciphertext, out of two functions a reader
  would take for the same function."
  [k p]
  (reduce (fn [p [alias column]]
            (if (contains? p alias)
              (assoc p alias (unseal k :recipes column (get p alias)))
              p))
          (unseal-row k :recipe_proposals p)
          current-aliases))

(defn unseal-inbox-entry
  "One queue entry. `recipe_title` and `kind` are clear; a `proposed` entry
  carries a `proposal`, which holds both texts."
  [k entry]
  (cond-> (unseal-scopes k entry)
    (map? (:proposal entry)) (update :proposal #(unseal-proposal k %))))

(defn unseal-body
  "Everything cookbook can answer with, unsealed by shape. One function, so a
  caller does not have to know which endpoint returns which of them — and so that
  adding an endpoint means adding a clause here rather than remembering an unseal
  at a new call site.

  Dispatch is on the shape rather than on the path: the same recipe row comes
  back from a create, a save, a publish, a read and the `:current` of a 409, and a
  shape test recognises all five without a path table that has to be kept in step
  with the routes."
  [k body]
  (cond
    (nil? k) body

    (sequential? body)
    ;; A listing: recipes, deleted recipes, scopes, or the inbox. Every one of
    ;; them is a vector of maps, and the maps differ.
    (mapv (fn [row]
            (cond
              (contains? row :kind)     (unseal-inbox-entry k row)
              ;; A Scope has no `title`-plus-`version` pair; a Recipe row always
              ;; carries a version, on every projection cookbook serves.
              (contains? row :version)  (unseal-recipe k row)
              :else                     (unseal-row k :scopes row)))
          body)

    (not (map? body)) body

    ;; GET /api/recipes/:id/versions
    (contains? body :versions) (unseal-versions k body)

    ;; The 202 from a machine PUT, and the 409 that says a proposal is pending.
    ;;
    ;; **`map?`, not `contains?`.** A Recipe row carries a `pending` of its own —
    ;; 0 or 1, whether an agent has a rewrite waiting — so the key alone does not
    ;; say which shape this is, and reading a flag as a proposal is how every
    ;; ordinary save came back still sealed. It is worth the sentence: the two
    ;; meanings of `pending` are both cookbook's and both correct, and only the
    ;; type tells them apart.
    (map? (:pending body))
    (cond-> (update body :pending #(unseal-proposal k %))
      (map? (:recipe body)) (update :recipe #(unseal-recipe k %)))

    ;; The 409 that says the Recipe moved under us.
    (map? (:current body)) (update body :current #(unseal-recipe k %))

    ;; A single Recipe: created, saved, read, published.
    (contains? body :version) (unseal-recipe k body)

    ;; A single Scope, from a create or a save.
    (and (contains? body :title) (contains? body :description)) (unseal-row k :scopes body)

    :else body))

;; ---------------------------------------------------------------------------
;; Writes.

(defn seal-recipe-write
  "The body of a `POST /api/recipes` or a `PUT /api/recipes/:id`. `stored` is the
  Recipe as this client last read it, or `nil` for a create — see `seal` for what
  it buys and why a write path that skips it corrupts the version ladder.

  `title`, `tags`, `scope_ids` and `modified_at` are not prose and are not
  touched."
  ([k body] (seal-recipe-write k body nil))
  ([k body stored] (seal-row k :recipes body stored)))

(defn seal-scope-write
  "The body of a `POST /api/scopes` or a `PUT /api/scopes/:id`."
  ([k body] (seal-scope-write k body nil))
  ([k body stored] (seal-row k :scopes body stored)))

;; ---------------------------------------------------------------------------
;; What a client can tell about a response it is holding.

(defn caution-over-ciphertext?
  "Whether the `caution` a cookbook response is carrying was computed over text
  the server could not read.

  The server assesses `recipe_history` on every `?detail=full` of one Recipe and
  on every PUT that made a version, and it holds no key. On a sealed Recipe what
  it produces is **wrong rather than incomplete**: base64 carries no newlines, so
  the whole ladder reads as one line, and the single range that comes back
  carries the *last writer's* label onto line 1 of the plaintext. A Recipe the
  owner wrote and an agent later edited at line 5 reads as if he had written none
  of it — and `caution` is the one number in cookbook's API written for an agent
  to act on.

  So it is dropped, and the reader is told nothing rather than told a lie. The
  browser drops it too, at the same boundary and by the same test
  (`et.cb.seal/caution-over-ciphertext?` in the cookbook checkout) — but there it
  is the first half of a fix, since the browser goes on to compute the split
  itself over the unsealed ladder. Here it is the whole of it: computing it would
  mean `et.uvt.caution` on this classpath and baked into two more binaries, which
  is a wiring job nobody has done. plurama-cli's README says so in as many words.

  **Asked of the body as it arrived**, before any unsealing, and **whether or not
  there is a key** — a wrong split is wrong to whoever reads it, and a client with
  no key is exactly the one that cannot tell.

  Not in the shared fixture, unlike `published-surface`, and the difference is
  worth a line: that one is a *list* two clients could widen differently, this is
  one column already named in `et.cb.caution/ranges` and pinned by
  `caution-test/the-text-is-the-description`. A fourth place saying `description`
  would be a fourth place to keep in step. Both suites assert the behaviour on the
  same shapes instead."
  [body]
  (boolean (and (map? body)
                (contains? body :caution)
                (sealed? (:description body)))))

;; ---------------------------------------------------------------------------
;; What a write path has to know, and why it is here rather than in one of them.
;;
;; **Three clients seal a cookbook write now, and they differ only in how they
;; make an HTTP request.** `plurama_cli.clj` and `cookbook_tui.clj` do it from the
;; owner's laptop, or from a box that was handed a key; `plurama_cli_proxy.clj`
;; does it from outside a sandbox, on behalf of a box that holds nothing at all.
;; What none of them may differ about is *which* paths carry prose, *which* read
;; says what the row holds now, and what that read means — because getting any of
;; those wrong is invisible from the outside. Too narrow and prose goes out in the
;; clear; too wide and a filing PUT drags down a version ladder it discards; a
;; misread `published` puts an envelope back onto a public page.
;;
;; So they live here, pure, beside the inventory they are made of. The transport
;; stays with each caller, because that is the part that genuinely differs.

(def write-paths
  "Table → the API path segment a client writes it under. Two of them, and the
  reason this is data rather than two `cond` branches is the guard below it."
  {:recipes "recipes"
   :scopes  "scopes"})

(def server-derived
  "The tables in the inventory that **no client ever names in a path**, because
  the server fills them by copying prose it cannot read: `archive!` writes the
  outgoing row into the history on every save, `approve-proposal!` writes a
  proposal into the row, `merge-content` fills a partial proposal from the row.
  That copying is why one binding covers all three — see `bound-as`."
  #{:recipe_history :recipe_proposals})

(when-not (= (set (keys sealed-columns))
             (into server-derived (keys write-paths)))
  ;; **A fourteenth table in the inventory has to be classified here or nothing
  ;; starts.** Found in review as the one gap a new *table* left, where a new
  ;; column is safe by construction: columns are read out of `sealed-columns` at
  ;; call time and flow through the SELECT, the UPDATE, the AAD, `prose-in`,
  ;; `state-of` and `seal-write` untouched by hand, but a table nothing could name
  ;; a path for would have had its prose forwarded **in the clear, with no error**
  ;; — the proxy answering `nil` from `write-target` and sealing nothing.
  ;;
  ;; So: written directly, or written by the server. There is no third kind, and
  ;; the refusal is at load, in the file every clj client requires.
  (throw (ex-info (str "cookbook-seal: a sealed table is neither written directly nor "
                       "derived by the server: "
                       (pr-str (sort (map name (remove (into server-derived (keys write-paths))
                                                       (keys sealed-columns)))))
                       " — classify it in `write-paths` (and give it a path) or in "
                       "`server-derived`")
                  {:sealed-columns (sort (map name (keys sealed-columns)))})))

(defn write-target
  "Which table a cookbook write is aimed at, and at which row — `nil` for
  everything else, which is most of the API. `/recipes/7/publish` is deliberately
  not matched: what it can carry is an *unseal*, plaintext going back over
  ciphertext, which is the opposite of what this is for.

  Built from `write-paths` rather than spelled out, so that a table added to the
  inventory cannot be written through here without a path having been chosen for
  it — see the guard above."
  [path]
  (let [p (-> path (str/split #"\?") first (str/replace #"/$" ""))]
    (first (for [[table segment] write-paths
                 :let [base (str "/api/" segment)]
                 :when (or (= p base) (re-matches (re-pattern (str base "/\\d+")) p))]
             (cond-> {:table table}
               (not= p base) (assoc :id (parse-long (last (str/split p #"/")))))))))

(defn publish-target
  "The Recipe id a cookbook publish names, or `nil`. A separate matcher from
  `write-target` on purpose: a publish carries no body worth sealing — what it
  carries, on a sealed Recipe, is something to refuse."
  [path]
  (when-let [[_ id] (re-matches #"/api/recipes/(\d+)/publish/?"
                                (-> path (str/split #"\?") first))]
    (parse-long id)))

(defn prose-in
  "The sealed columns a parsed write body actually carries, or `nil`. It decides
  whether a write pays for the echo rule's extra read, and it is a named function
  rather than an `if` because getting it wrong in either direction says nothing:
  too wide and `-d '{\"tags\":\"x\"}'` fetches a whole version ladder to look up
  columns it is not sending, too narrow and a prose write goes out unsealed."
  [table parsed]
  (when (map? parsed)
    (seq (filter #(contains? parsed %) (get sealed-columns table)))))

(defn state-path
  "The read a write has to make first, or `nil` when there is no row yet.

  **A Recipe's is `/versions` and deliberately not `?detail=full`**: a full read
  counts as a consumption and ranks the shelf, so seal bookkeeping would quietly
  reorder the owner's Cookbook. `/versions` carries all four columns of the
  current row, says whether the Recipe is published, and counts nothing.

  A Scope has no read of one alone, so it is the listing."
  [{:keys [table id]}]
  (when id
    (case table
      :recipes (str "/api/recipes/" id "/versions")
      :scopes "/api/scopes")))

(defn state-of
  "What that read says: `:stored` and `:published?`, out of one round trip.

  `:stored` is what the row's sealed columns hold **right now**, so that a value
  the caller did not change can be written back as the very ciphertext already
  there. Without it a fresh nonce makes every resend look like a change to the
  server, and an agent that PUTs the same text twice piles up versions, history
  rows and inbox entries — corrupting the ladder the seal exists to protect.

  `:published?` is the other rule, and it arrived with publish-as-unseal:
  publishing opens every envelope in a Recipe, one way, because a visitor has no
  key and there is no unpublish — so a write to a published Recipe must go out in
  the clear or it puts `enc:v1:…` back on a public page. Cookbook refuses such a
  write with a 400, so this is the honest path rather than the guarantee.

  A Scope has no latch — the projection that hides a Scope's prose from a visitor
  is not the publish latch — so `:published?` is always false there."
  [{:keys [table id]} parsed]
  (case table
    :recipes {:stored (some-> (->> parsed :versions (filter :current) first)
                              (select-keys (get sealed-columns :recipes)))
              :published? (= 1 (:published parsed))}
    :scopes {:stored (some-> (->> parsed (filter #(= id (:id %))) first)
                             (select-keys (get sealed-columns :scopes)))
             :published? false}))

(defn seal-write
  "The write body with its prose sealed — or **`nil`, meaning send what you were
  given, untouched**.

  That second answer is not the same as an unchanged map handed back. A client
  that re-serialises a body it did not change alters its key order for no reason,
  and both callers promise that a write they had no business touching goes over
  the wire byte for byte as it was typed. `nil` is how that is said.

  It is the answer for a published Recipe and for nothing else — a body with no
  prose in it never gets this far, because asking would have cost a round trip
  the caller already decided not to spend."
  [k target parsed {:keys [stored published?]}]
  (when-not published?
    (seal-row k (:table target) parsed stored)))

(defn unseal-response-body
  "The two things that happen to a cookbook response, and **the order is the whole
  of it**: the caution question is asked of the body *as it arrived*, before a
  word of it is opened.

  `caution-over-ciphertext?` reads `(sealed? (:description body))`, so a client
  that unsealed first would find a plaintext description there and conclude the
  split had been computed over readable text. It had not. That is not
  hypothetical, it is the trap the proxy sidecar sits in: the box's own client
  asks this question too, and by the time it sees a body the proxy has already
  opened it. Whoever unseals is therefore the one that must drop the caution."
  [k body]
  (-> (cond-> body (caution-over-ciphertext? body) (dissoc :caution))
      (->> (unseal-body k))))
