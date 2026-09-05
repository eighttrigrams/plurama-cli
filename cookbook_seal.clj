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

  **The AAD binds a value to its column** — `recipes/description`,
  `recipe_history/reason` — so a ciphertext cannot be lifted from one column and
  dropped into another by anyone holding the database file. It does not bind the
  row: the id is assigned by `AUTOINCREMENT` on insert, so there is nothing to
  bind to at the moment of sealing. That gap is deliberate and worth knowing.

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

(defn aad
  "What a ciphertext is bound to: the column it belongs in, as `table/column`."
  [table column]
  (str (name table) "/" (name column)))

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

(defn seal-text
  "The envelope itself: plaintext in, `enc:v1:…` out. No rules, no inventory, no
  opinion about blanks — `seal` below is what call sites use. Separate so the
  fixture can pin an exact ciphertext by handing in the nonce it wants."
  ([k aad-str plaintext] (seal-text k aad-str plaintext (random-bytes nonce-length)))
  ([k aad-str ^String plaintext ^bytes nonce]
   (let [c (cipher javax.crypto.Cipher/ENCRYPT_MODE k nonce aad-str)
         body (.doFinal c (utf8 plaintext))
         out (byte-array (+ (alength nonce) (alength ^bytes body)))]
     (System/arraycopy nonce 0 out 0 (alength nonce))
     (System/arraycopy body 0 out (alength nonce) (alength ^bytes body))
     (str envelope-prefix (b64-encode out)))))

(defn unseal-text
  "The inverse, for a value known to carry the prefix. Throws when the tag does
  not check out — a tampered ciphertext, a ciphertext moved to another column, or
  the wrong key. `unseal` below is what call sites use."
  [k aad-str ^String value]
  (let [raw (b64-decode (subs value (count envelope-prefix)))
        nonce (java.util.Arrays/copyOfRange raw 0 nonce-length)
        body (java.util.Arrays/copyOfRange raw (int nonce-length) (int (alength raw)))
        c (cipher javax.crypto.Cipher/DECRYPT_MODE k nonce aad-str)]
    (String. (.doFinal c body) "UTF-8")))

;; ---------------------------------------------------------------------------
;; The three rules.

(defn unseal
  "Read one value out of one column. Prefix-driven: anything without `enc:v1:`
  comes back exactly as it went in, and so does everything when there is no key —
  which is what a client without the key sees of a sealed shelf, ciphertext and
  all. That is the honest answer: it cannot read this, and pretending otherwise
  would mean inventing text."
  [k table column v]
  (if (and k (sealed? v))
    (unseal-text k (aad table column) v)
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
  and is flagged `:current`; everything below it is a `recipe_history` row. Two
  tables, two AADs, in one list — which is precisely the case a per-column AAD
  makes you think about, and the reason this mapping is not left to a call site."
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
  in under `current_` names. They are `recipes` columns wearing an alias, so they
  unseal against `recipes`, not against the proposal they sit beside. Getting this
  backwards would not be a silent bug — the tag check fails — which is the AAD
  earning its place."
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
    (contains? body :pending)
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
