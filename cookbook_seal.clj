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
  (:require [clojure.string :as str]))

;; ---------------------------------------------------------------------------
;; The envelope.

(def envelope-prefix
  "Self-describing and versioned. A reader — a person looking at the database, a
  half-migrated row, another implementation — can tell a sealed value from a
  plain one without being told which columns are sealed."
  "enc:v1:")

(def ^:private nonce-length 12)   ; 96 bits, the GCM standard
(def ^:private tag-bits 128)
(def ^:private key-length 32)     ; AES-256

(defn- b64-encode ^String [^bytes bs]
  (.encodeToString (java.util.Base64/getEncoder) bs))

(defn- b64-decode ^bytes [^String s]
  (.decode (java.util.Base64/getDecoder) s))

(defn- utf8 ^bytes [^String s] (.getBytes s "UTF-8"))

(def ^:private secure-random (delay (java.security.SecureRandom.)))

(defn random-bytes ^bytes [n]
  (let [bs (byte-array n)]
    (.nextBytes ^java.security.SecureRandom @secure-random bs)
    bs))

(defn key-from-base64
  "A 32-byte key, given as base64. Throws on anything else rather than padding or
  truncating: a key of the wrong length is a configuration mistake, and the only
  useful moment to hear about it is the first one."
  [s]
  (when-not (string? s)
    (throw (ex-info "cookbook seal key must be base64 text" {})))
  (let [bs (try (b64-decode (str/trim s))
                (catch Exception _
                  (throw (ex-info "cookbook seal key is not valid base64" {}))))]
    (when-not (= key-length (count bs))
      (throw (ex-info (str "cookbook seal key must be " key-length " bytes, got "
                           (count bs))
                      {:length (count bs)})))
    (javax.crypto.spec.SecretKeySpec. bs "AES")))

(defn generate-key-base64
  "A fresh key, base64, for tests and for the one time a real one is minted. This
  program never writes it anywhere — where a key is kept is `secrets.yaml` and a
  sheet of paper, and neither is a thing a CLI should be doing on its own."
  []
  (b64-encode (random-bytes key-length)))

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

  What it still refuses is every move the server does *not* make: a description
  into a useful-when, a reason into a context, and a Scope's prose into a
  Recipe's. Those are the moves an attacker with the database file would want, and
  they all fail the tag check."
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

(defn sealed?
  "Whether a value read out of a sealed column is actually sealed. Only ever a
  question about the prefix — see rule 3."
  [v]
  (boolean (and (string? v) (str/starts-with? v envelope-prefix))))

(defn- blank-value?
  "The values rule 1 refuses to seal. `nil`, `\"\"`, and whitespace-only — the last
  of those because cookbook's server refuses a blank `reason` with `str/blank?`,
  and a client that sealed `\" \"` would be defeating that check on the server's
  behalf. Non-strings are left alone too; a number in a prose column is not this
  function's problem to solve."
  [v]
  (or (nil? v) (not (string? v)) (str/blank? v)))

(defn- cipher ^javax.crypto.Cipher [mode ^javax.crypto.spec.SecretKeySpec k ^bytes nonce ^String aad-str]
  (doto (javax.crypto.Cipher/getInstance "AES/GCM/NoPadding")
    (.init (int mode) k (javax.crypto.spec.GCMParameterSpec. tag-bits nonce))
    (.updateAAD (utf8 aad-str))))

(defn seal-text-with-nonce
  "**The fixture's arity, and nothing else's** — which is why it has a name you
  have to type rather than an overload you can fall into.

  A nonce supplied by a caller is a nonce that can be supplied twice, and in GCM
  two values sealed under one key and one nonce is not a weakening, it is a total
  break: the keystream cancels between them and the authentication key itself
  falls out. Nothing in this application has any reason to choose one. The test
  vectors do, because pinning an exact ciphertext is the whole point of them.

  Every other caller wants `seal-text`, which takes one from the CSPRNG."
  [k aad-str ^String plaintext ^bytes nonce]
  (let [c (cipher javax.crypto.Cipher/ENCRYPT_MODE k nonce aad-str)
        body (.doFinal c (utf8 plaintext))
        out (byte-array (+ (alength nonce) (alength ^bytes body)))]
    (System/arraycopy nonce 0 out 0 (alength nonce))
    (System/arraycopy body 0 out (alength nonce) (alength ^bytes body))
    (str envelope-prefix (b64-encode out))))

(defn seal-text
  "The envelope itself: plaintext in, `enc:v1:…` out. No rules, no inventory, no
  opinion about blanks — `seal` below is what call sites use.

  A fresh 96-bit nonce per value, from the CSPRNG, every time."
  [k aad-str plaintext]
  (seal-text-with-nonce k aad-str plaintext (random-bytes nonce-length)))

(defn unseal-text
  "The inverse, for a value known to carry the prefix. Throws when the tag does
  not check out — a tampered ciphertext, a ciphertext moved to another column, or
  the wrong key. `unseal` below is what call sites use."
  [k aad-str ^String value]
  (let [raw (b64-decode (subs value (count envelope-prefix)))
        nonce (java.util.Arrays/copyOfRange raw 0 nonce-length)
        body (java.util.Arrays/copyOfRange raw (int nonce-length) (alength raw))
        c (cipher javax.crypto.Cipher/DECRYPT_MODE k nonce aad-str)]
    (String. (.doFinal c body) "UTF-8")))

;; ---------------------------------------------------------------------------
;; The three rules.

(defn unseal
  "Read one value out of one column. Prefix-driven: anything without `enc:v1:`
  comes back exactly as it went in, and so does everything when there is no key.

  **A value that will not open comes back as it is**, ciphertext and all, rather
  than throwing. That is the honest answer — this client cannot read this, and
  inventing text or a blank would be worse — and it is the diagnosable one: one
  unreadable value shows as `enc:v1:…` beside everything that reads, instead of a
  single failure somewhere in a listing taking the whole response down with it.
  The first end-to-end run of this code lost a whole version ladder that way and
  said nothing about why.

  The browser half does the same, deliberately, for the same reason."
  [k table column v]
  (if (and k (sealed? v))
    (try (unseal-text k (aad table column) v)
         (catch Exception _ v))
    v))

(defn seal
  "Write one value into one column, under all three rules.

  `stored` is what that column holds right now — the ciphertext this client read
  a moment ago, or a plaintext on a shelf not yet migrated, or `nil` for a row
  that does not exist yet. When the new plaintext is what `stored` already says,
  `stored` is handed back byte for byte, so the server's value comparison still
  sees 'unchanged'. Anything genuinely new gets a fresh nonce, so two Recipes
  saying the same sentence still seal differently.

  A `stored` that cannot be opened — wrong key, tampered — is treated as *not
  matching* rather than as an error. Refusing the write would leave a client
  holding the only copy of the new text with nowhere to put it."
  ([k table column v] (seal k table column v nil))
  ([k table column v stored]
   (cond
     (nil? k) v
     (blank-value? v) v
     (and (sealed? stored)
          (= v (try (unseal-text k (aad table column) stored)
                    (catch Exception _ ::unreadable))))
     stored
     :else (seal-text k (aad table column) v))))

;; ---------------------------------------------------------------------------
;; Where the key comes from.

(def key-file
  "The default place a key file is looked for. Mode 600, like the credentials
  beside it."
  (java.io.File. (System/getProperty "user.home") ".config/plurama-cli/cookbook-seal.key"))

(defn- key-location
  "Where the key would come from — `[:env NAME]`, `[:file PATH]`, or `nil` for
  none. Resolved in **one** place, because `load-key` and `key-source` must not
  be able to disagree about whether sealing is on, and once they did: a
  `COOKBOOK_SEAL_KEY_FILE` naming a file that was not there left `load-key`
  answering `nil` while `apps` reported *sealing: on*. That is precisely the
  shape of lie the `apps` line exists to prevent.

  Three places, in order:

  - `COOKBOOK_SEAL_KEY` — base64. The shape a `sops exec-env` wrapper hands it
    over in on the owner's laptop, where the key lives in `secrets.yaml`.
  - `COOKBOOK_SEAL_KEY_FILE` — a path to read it from.
  - `~/.config/plurama-cli/cookbook-seal.key` — the default file, which is the
    shape a devbox gets it in: a mounted file, the same pattern as
    `docker/cookbook_creds`.

  **A file somebody named and did not put there throws.** It is a mistake, not a
  request for plaintext — the same judgement a malformed key gets. The *default*
  file's absence is not: nothing named it, so nothing is missing, and sealing is
  simply off."
  []
  (let [from-env (System/getenv "COOKBOOK_SEAL_KEY")
        named (System/getenv "COOKBOOK_SEAL_KEY_FILE")]
    (cond
      (not (str/blank? from-env)) [:env "COOKBOOK_SEAL_KEY"]

      (not (str/blank? named))
      (if (.exists (java.io.File. ^String named))
        [:file named]
        (throw (ex-info (str "COOKBOOK_SEAL_KEY_FILE names " named
                             ", which is not there — cookbook prose would be "
                             "written in the clear")
                        {:path named})))

      (.exists key-file) [:file (str key-file)])))

(defn load-key
  "The key, or `nil` — and `nil` means **sealing is off**, which is cookbook's
  behaviour before any of this existed and is what every function above already
  understands. That is deliberate: it keeps the whole thing reversible until the
  data is migrated, and it lets both worlds be exercised.

  A key that is present but malformed **throws**. Falling back to 'sealing off'
  there would be the worst of both: an agent writing plaintext into a sealed
  shelf, and nothing saying so."
  []
  (when-let [[kind where] (key-location)]
    (key-from-base64 (case kind
                       :env (System/getenv where)
                       :file (slurp where)))))

(defn key-source
  "Where `load-key` would find a **usable** key, in words, for the places this is
  reported. Never the key itself.

  It loads the key rather than only locating it, because *on* is read as a
  promise that prose will be sealed, and a five-byte string in
  `COOKBOOK_SEAL_KEY` locates perfectly and opens nothing. A malformed key
  throws out of here, which is the answer the caller wants: it is the same
  refusal every other cookbook call is about to give."
  []
  (when (load-key) (second (key-location))))

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

(defn unseal-proposal
  "A proposal as `pending-body` renders it: the agent's own text, out of
  `recipe_proposals`."
  [k p]
  (unseal-row k :recipe_proposals p))

(def ^:private current-aliases
  "The inbox entry's second copy of the text: the Recipe as it reads *now*, joined
  in under `current_` names. They are `recipes` columns wearing an alias, and the
  alias is what has to be undone: the *column* is what a value is bound to, so a
  `current_description` is a `description` and reading it as a `useful_when` fails
  the tag check."
  {:current_useful_when :useful_when
   :current_description :description})

(defn- unseal-current-aliases [k p]
  (reduce (fn [p [alias column]]
            (if (contains? p alias)
              (assoc p alias (unseal k :recipes column (get p alias)))
              p))
          p
          current-aliases))

(defn unseal-inbox-entry
  "One queue entry. `recipe_title` and `kind` are clear; a `proposed` entry
  carries a `proposal`, which holds both texts."
  [k entry]
  (cond-> (unseal-scopes k entry)
    (map? (:proposal entry))
    (update :proposal #(->> % (unseal-proposal k) (unseal-current-aliases k)))))

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
