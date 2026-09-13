(ns seal-envelope
  "The envelope, once, for every plurama app that seals prose.

  Cookbook was the first, and for a while it was the only one, so the whole of
  the seal lived in `cookbook_seal.clj`. Tracker is the second. That makes this
  file the answer to a question this codebase's reviews have already caught twice
  in smaller forms: **two spellings of one cryptographic control is how they
  drift**, and a fixture cannot police a copy.

  So what is *generic* is here — the envelope, the three rules, the key — and what
  is *an app's own* stays in that app's namespace: which tables and columns are
  sealed, what a ciphertext is bound to, which HTTP paths carry prose, and what
  shape a response comes back in. Those differ per app and should; the cipher
  must not.

  ## The envelope

      enc:v1:<base64(nonce ‖ ciphertext ‖ tag)>

  AES-256-GCM, a fresh random 96-bit nonce per value, a 128-bit tag, standard
  base64 with padding. The value is stored as text in the column it came from, so
  the seal needs no schema migration, and the `enc:v1:` prefix is what lets a
  half-migrated database work: unsealing a value without it hands the value back
  unchanged. **Mixed state is legal everywhere, permanently** — not for a rollout
  window, but as a property.

  One envelope across apps does not mean one key across apps. Cookbook's key and
  tracker's key are different 32-byte secrets in different places, because a
  leaked key cannot be rotated out of the data it already sealed and there is no
  reason to make one leak cost two shelves.

  ## The AAD is the app's business, not this file's

  Every function here takes the binding already resolved, as a string. What a
  ciphertext is bound to is a statement about a schema — cookbook binds
  `recipe/description` across three tables because its server copies prose
  between them without a key; tracker binds `item/description` across ten for the
  same reason, one level flatter. Neither of those is knowledge this namespace
  should hold, and an `aad` function here would be a place for them to be wrong
  in.

  ## Three rules, and they live here rather than at the call sites

  1. **Never seal a blank value.** `nil` stays `nil`, `\"\"` stays `\"\"`, and so
     does any string that is only whitespace. Ciphertext is never NULL and never
     empty, so without this rule every historical row grows a *\"not recorded\"*
     that reads as *\"recorded, and empty\"* — and the two mean different things in
     both apps. It is also what keeps a server's own blank checks working: blank
     arrives unsealed, so the server can still see it is blank.

  2. **Never re-seal an unchanged value — echo the stored value, whichever
     encoding it has.** A fresh nonce per value means sealing one sentence twice
     gives two ciphertexts, which is the point: it is what stops equality leaking.
     But a server that compares prose *values* to decide anything — a version
     bump, a no-op, an audit diff — sees every resend as a change. So `seal-at`
     takes what the column holds right now and hands it straight back when the
     value has not changed. See its docstring: the comparison is made on the bytes
     **before** anything is opened, and that order was a live bug.

  3. **Unsealing is prefix-driven and never throws.** A value without `enc:v1:`
     passes through untouched; a value carrying the prefix that will not open is
     handed back visibly, as it is. That is what makes rule 1 safe, what makes a
     partial migration resumable, and what stops one unreadable column taking a
     whole response down with it.

  ## Sealing is off when there is no key

  Every rule function takes the key first and treats `nil` as *sealing off*:
  values pass through unchanged, which is how these apps behaved before any of
  this existed. That is what lets the code ship inert, long before a key exists,
  and it is what makes the whole feature reversible up until a migration pass
  runs.

  The one client that must **refuse** to run without a key is a migration walker,
  because there *no key* would mean walking a whole database, writing nothing,
  and reporting success.

  ## Shipping note

  `bb.edn` puts this on the classpath for a checkout. For the installed binaries
  there is no classpath, so `make dist` concatenates this file **before** the app
  seal namespace, which goes before the script that requires it. Nothing fails
  silently if that is forgotten: babashka refuses to start."
  (:require [clojure.string :as str]))

;; ---------------------------------------------------------------------------
;; The envelope.

(def envelope-prefix
  "Self-describing and versioned. A reader — a person looking at the database, a
  half-migrated row, another implementation — can tell a sealed value from a plain
  one without being told which columns are sealed."
  "enc:v1:")

(def ^:private nonce-length 12)   ; 96 bits, the GCM standard
(def ^:private tag-bits 128)
(def key-length 32)               ; AES-256

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
  useful moment to hear about it is the first one.

  `app` names the app in the message — \"cookbook\", \"tracker\" — because a
  laptop holds more than one key and *which* one is malformed is the whole of what
  the reader needs."
  [app s]
  (when-not (string? s)
    (throw (ex-info (str app " seal key must be base64 text") {:app app})))
  (let [bs (try (b64-decode (str/trim s))
                (catch Exception _
                  (throw (ex-info (str app " seal key is not valid base64") {:app app}))))]
    (when-not (= key-length (count bs))
      (throw (ex-info (str app " seal key must be " key-length " bytes, got "
                           (count bs))
                      {:app app :length (count bs)})))
    (javax.crypto.spec.SecretKeySpec. bs "AES")))

(defn generate-key-base64
  "A fresh key, base64, for tests and for the one time a real one is minted. This
  program never writes it anywhere — where a key is kept is `secrets.yaml` and a
  sheet of paper, and neither is a thing a CLI should be doing on its own."
  []
  (b64-encode (random-bytes key-length)))

(defn fingerprint
  "Eight hex characters of SHA-256 over the raw key, the same eight a browser's
  ⚙ panel shows.

  **Not part of the envelope**: nothing is bound to it and no ciphertext carries
  it. What it is for is telling two things that hold a key that they hold the
  *same* key, without either of them being able to say what it is — the job an ssh
  key fingerprint does. Half a truncated hash of 256 bits of entropy identifies a
  key and helps nobody find one, so it is safe on a settings panel, in a proxy's
  startup line, and in the header of a migration pass.

  That last one is why it exists at all. Sealing a database with a key the owner's
  browser cannot open is the one mistake in this whole design with no recovery,
  and comparing eight characters against the ⚙ panel is the only cheap check that
  it is not about to happen. A check like that is worthless if the two sides
  compute it differently, so each app's fixture pins the answer for its own test
  key and every suite asserts it."
  [^javax.crypto.spec.SecretKeySpec k]
  (->> (.digest (java.security.MessageDigest/getInstance "SHA-256") (.getEncoded k))
       (take 4)
       (map #(format "%02x" (bit-and % 0xff)))
       (str/join)))

(defn sealed?
  "Whether a value read out of a sealed column is actually sealed. Only ever a
  question about the prefix — see rule 3.

  Matched strictly: `enc:v0:`, `encv1:`, `ENC:V1:` and a leading space are all
  plaintext, and each app's fixture carries them as `:passthrough` cases so that
  three implementations cannot quietly disagree about a near-miss."
  [v]
  (boolean (and (string? v) (str/starts-with? v envelope-prefix))))

(defn envelope-shaped?
  "Whether a value carrying the prefix could be an envelope **at all**: the rest
  of it is base64, and it decodes to at least a nonce and a tag.

  ## A diagnostic, and deliberately not a rule

  Nothing decides what to write by this. `sealed?` above is still the only
  question the three rules ask and it is still only about the prefix, in all four
  implementations, which is what keeps them from disagreeing about a near miss.
  This answers a question only a *report* has: of the values that carry the prefix
  and do not open, which ones are ciphertext at all?

  The case is not invented. A body that merely begins with `enc:v1:` reads as
  sealed to `sealed?`, is left in the clear by a migration pass, and used to be
  reported by tracker's walker as *sealed under another key, or damaged* — two
  causes, neither of them true, with no way past it but hand-editing a row in SQL.
  Somebody who has spent a week writing prose *about* this envelope is one paste
  away from having one.

  It says nothing about whether a genuinely-shaped ciphertext opens; that needs
  the key, and `unseal-at` is what asks. And it **leans towards *this is an
  envelope*** on every doubtful case — a length that is merely plausible, base64
  that merely parses — because telling somebody that a damaged ciphertext is only
  prose is the worse of the two mistakes to make about their data."
  [v]
  (and (sealed? v)
       (try
         (>= (alength ^bytes (b64-decode (subs v (count envelope-prefix))))
             (+ nonce-length (quot tag-bits 8)))
         (catch Exception _ false))))

(defn blank-value?
  "The values rule 1 refuses to seal. `nil`, `\"\"`, and whitespace-only — the last
  of those because a server that refuses a blank field with `str/blank?` would be
  defeated by a client that sealed `\" \"` on its behalf. Non-strings are left
  alone too; a number in a prose column is not this function's problem to solve.

  Public because the migration walkers count by it. A walker with its own idea of
  blank would file a value under *sealed* that the seal had handed straight back —
  an audit line disagreeing with what is in the database."
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
  falls out. Nothing in these applications has any reason to choose one. The test
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
  opinion about blanks — `seal-at` below is what call sites use.

  A fresh 96-bit nonce per value, from the CSPRNG, every time."
  [k aad-str plaintext]
  (seal-text-with-nonce k aad-str plaintext (random-bytes nonce-length)))

(defn unseal-text
  "The inverse, for a value known to carry the prefix. Throws when the tag does
  not check out — a tampered ciphertext, a ciphertext moved to another column, or
  the wrong key. `unseal-at` below is what call sites use."
  [k aad-str ^String value]
  (let [raw (b64-decode (subs value (count envelope-prefix)))
        nonce (java.util.Arrays/copyOfRange raw 0 nonce-length)
        body (java.util.Arrays/copyOfRange raw (int nonce-length) (alength raw))
        c (cipher javax.crypto.Cipher/DECRYPT_MODE k nonce aad-str)]
    (String. (.doFinal c body) "UTF-8")))

;; ---------------------------------------------------------------------------
;; The three rules. An app wraps these with its own `aad`.

(defn unseal-at
  "Read one value, given what it is bound to. Prefix-driven: anything without
  `enc:v1:` comes back exactly as it went in, and so does everything when there is
  no key.

  **A value that will not open comes back as it is**, ciphertext and all, rather
  than throwing. That is the honest answer — this client cannot read this, and
  inventing text or a blank would be worse — and it is the diagnosable one: one
  unreadable value shows as `enc:v1:…` beside everything that reads, instead of a
  single failure somewhere in a listing taking the whole response down with it.
  The first end-to-end run of cookbook's seal lost a whole version ladder that way
  and said nothing about why.

  The browser halves do the same, deliberately, for the same reason."
  [k aad-str v]
  (if (and k (sealed? v))
    (try (unseal-text k aad-str v)
         (catch Exception _ v))
    v))

(defn seal-at
  "Write one value, given what it is bound to, under all three rules.

  `stored` is what that column holds right now — the ciphertext this client read a
  moment ago, a plaintext on a row not yet migrated, or `nil` for a row that does
  not exist yet.

  **When the value has not changed, `stored` comes back byte for byte, whichever
  of those it is.** That is the whole echo rule: *does this column already say
  what I am about to write?* It is asked twice, and both halves are load-bearing.

  **First, of the bytes.** If `v` is already exactly what is stored, nothing has
  changed and nothing is written, whatever `v` happens to be. That covers the case
  the second half gets wrong: an **envelope handed back unchanged by a client that
  could open it**. Unsealing that `stored` answers the *plaintext*, `v` is the
  *ciphertext*, they differ — and sealing would then write `enc(enc(…))`, which
  opens once into an envelope and reads as an envelope, with nothing anywhere
  reporting an error. That is not hypothetical: the proxy sidecar deliberately
  lets an echoed envelope through on the strength of this rule, and until the byte
  test was here it was corrupted by it once per write, forever. Found in review,
  reproduced live, one line.

  **Then, of the plaintext.** `unseal-at` answers for all three shapes at once — it
  opens a ciphertext, hands a plaintext straight back, and hands back an envelope
  it cannot open as well. So an unchanged value is a no-op on a sealed row, on an
  unmigrated row, and on a row this client cannot read.

  The unmigrated case is not an optimisation, it is the window the rollout
  mandates: clients are deployed first and the data is sealed later, so for a
  while every row is unmigrated. Sealing an unchanged plaintext there would turn an
  idempotent re-`PUT` into a write — a version bump and a history row in cookbook,
  a spurious audit event in tracker. The row seals on its next real edit.

  The unreadable case is the one a wrong or rotated key produces. Sealing there
  would write `enc_new(enc_old(…))`, and the *next* no-op would nest it again,
  once per cycle without bound, on a row nobody can read to notice. A no-op stays
  a no-op, which is what the rule is for.

  **A migration pass must therefore pass `nil` as `stored`**, and this is one of
  the two places that trap is written down: a walker that handed in the plaintext
  it just read as `stored` would be told, correctly, that nothing changed, and
  would seal nothing at all.

  ## And an envelope is never sealed, whatever is stored

  Both halves of the echo rule need a `stored` to compare against, and there is a
  case where there is none: `stored` is `nil` — a create, a client that never read
  the row, a stale index — and `v` already carries the prefix. Neither comparison
  can answer, so before this branch existed the value fell through to `seal-text`
  and was sealed a second time.

  There is no reading of that case in which sealing is right. **A client only ever
  holds an envelope because it read one**, so handing it back is what *has* not
  changed, and what comes back out of a second seal is `enc(enc(…))`: it opens
  once into an envelope, reads as an envelope, and nothing anywhere reports an
  error. If the envelope is one this key cannot open, sealing it makes it
  unopenable under two keys rather than one.

  This does not soften the proxy, which is the one place a *foreign* envelope is a
  real possibility. `plurama-cli-proxy/foreign-envelopes` refuses those before
  anything gets here, by comparing against `stored` exactly as this does, and it
  must keep doing so: the question there is not *should this be sealed again* but
  *whose key sealed it*, and that is not a question this function can be asked."
  ([k aad-str v] (seal-at k aad-str v nil))
  ([k aad-str v stored]
   (cond
     (nil? k) v
     (blank-value? v) v
     ;; An envelope, before anything is compared: nothing here has any business
     ;; sealing one, and the two rules below cannot answer when `stored` is nil.
     (sealed? v) v
     ;; The bytes, before anything is opened. See the docstring: this is the
     ;; branch an echoed openable envelope needs, and the one below cannot answer.
     (= v stored) stored
     (= v (unseal-at k aad-str stored)) stored
     :else (seal-text k aad-str v))))

;; ---------------------------------------------------------------------------
;; Where the key comes from.
;;
;; One shape, two apps. A `key-spec` is:
;;
;;   {:app "tracker"
;;    :env-var "TRACKER_SEAL_KEY"           ; base64, the shape `sops exec-env` gives
;;    :file-var "TRACKER_SEAL_KEY_FILE"     ; a path to read it from
;;    :default-file <java.io.File>}         ; ~/.config/plurama-cli/<app>-seal.key

(defn default-key-file
  "Where an app's key file lives when nothing names another. Mode 600, like the
  credentials beside it."
  [app]
  (java.io.File. (System/getProperty "user.home")
                 (str ".config/plurama-cli/" app "-seal.key")))

(defn key-location
  "Where the key would come from — `[:env NAME]`, `[:file PATH]`, or `nil` for
  none. Resolved in **one** place, because `load-key` and `key-source` must not be
  able to disagree about whether sealing is on, and once they did: a
  `COOKBOOK_SEAL_KEY_FILE` naming a file that was not there left `load-key`
  answering `nil` while the `apps` line reported *sealing: on*. That is precisely
  the shape of lie that line exists to prevent.

  Three places, in order: the env var, the named file, the default file.

  **A file somebody named and did not put there throws.** It is a mistake, not a
  request for plaintext — the same judgement a malformed key gets. The *default*
  file's absence is not: nothing named it, so nothing is missing, and sealing is
  simply off."
  [{:keys [app env-var file-var default-file]}]
  (let [from-env (System/getenv env-var)
        named (System/getenv file-var)]
    (cond
      (not (str/blank? from-env)) [:env env-var]

      (not (str/blank? named))
      (if (.isFile (java.io.File. ^String named))
        [:file named]
        (throw (ex-info (str file-var " names " named
                             ", which is not a readable file — " app " prose "
                             "would be written in the clear")
                        {:path named :app app})))

      ;; `.isFile`, not `.exists`. A docker bind mount whose source is missing
      ;; creates an empty **directory** at the destination rather than failing,
      ;; so `.exists` is true for a key nobody has minted yet — and the process
      ;; then dies on "Is a directory" reported as a malformed key. Live failure:
      ;; the devbox proxy crash-looped the moment a second key was mounted before
      ;; its ceremony had happened. A directory here means the same thing as
      ;; absence, which is: nothing named it, so sealing is simply off.
      (.isFile ^java.io.File default-file) [:file (str default-file)])))

(defn load-key
  "The key, or `nil` — and `nil` means **sealing is off**, which is how these apps
  behaved before any of this existed and is what every rule function already
  understands. That is deliberate: it keeps the whole thing reversible until the
  data is migrated, and it lets both worlds be exercised.

  A key that is present but malformed **throws**. Falling back to 'sealing off'
  there would be the worst of both: an agent writing plaintext into a sealed
  shelf, and nothing saying so."
  [{:keys [app] :as spec}]
  (when-let [[kind where] (key-location spec)]
    (key-from-base64 app (case kind
                           :env (System/getenv where)
                           :file (slurp where)))))

(defn key-source
  "Where `load-key` would find a **usable** key, in words, for the places this is
  reported. Never the key itself.

  It loads the key rather than only locating it, because *on* is read as a promise
  that prose will be sealed, and a five-byte string in the env var locates
  perfectly and opens nothing. A malformed key throws out of here, which is the
  answer the caller wants: it is the same refusal every other call is about to
  give."
  [spec]
  (when (load-key spec) (second (key-location spec))))
