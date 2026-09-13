#!/usr/bin/env bb

(ns tracker-seal-migrate
  "The migration pass: seal **one user's** prose in a tracker database, or open it
  again.

  Tracker's prose is end-to-end encrypted in the clients, so everything written
  since the seal landed is sealed and everything written before it is not. This
  is what closes that gap — one walk over the nine prose columns and over the
  audit log's payloads, sealing every value that is not sealed already.

  `handoffs/tracker-seal-plan.md` is the design and
  `handoffs/tracker-seal-playbook.md` is the day this runs on. Cookbook paid for
  most of what is here: `cookbook_seal_migrate.clj` is the precedent, and Cookbook
  recipe 159 is the distilled version of writing it. What follows is what is
  *different* about tracker.

  ## One user, and nobody else. This is the whole difference.

  Cookbook had one owner and one database. **Tracker has three humans in one
  SQLite file** — `daniel`, `antonio` and `saiyuri` — and only the first one's
  prose is being sealed. So every read and every write here is scoped to one
  user's rows:

  - the nine entity tables by `user_id`,
  - `events` by `effective_user_id`, which the server has already collapsed onto
    the human a machine user acts for (`server/common.clj claims->identity`).

  The scope is **a set of ids**, not one: a human plus every machine user whose
  `for_user_id` is his. No row of his carries a machine user's id today, because
  the collapse happens before a write — but a walk that assumed that would be
  assuming it about somebody else's data, and the cost of the `IN` is nothing.

  Which user is **a required argument**. There is no default and there must not
  be: a default that guessed wrong would seal rows nobody asked to seal, and
  sealing is not reversible without the key and a second downtime. `--user` is
  refused loudly instead, with the database's usernames printed, which is a
  five-second fix at any point before the irreversible one.

  The `IN` clause rides along **in the WHERE of every UPDATE too**, beside the
  compare-and-set on the value. That is the same move cookbook makes with
  `published`: the scope is read once for a whole table and acted on row by row,
  so a row that changed hands underneath the pass must fail its own write rather
  than be taken on trust.

  ## `events.payload` is walked, and it is JSON rather than a column

  3,919 of the audit log's 6,387 rows hold a description. They are not a column:
  the payload is a JSON document, and prose hides in five shapes inside it
  because five functions in `server/events.clj` build them. Those shapes are
  spelled **once**, in `et.tr.seal-rules/prose-paths`, which tracker's server,
  tracker's browser and this file all read. A sixth spelling here is exactly the
  drift the `.cljc` exists to prevent, so there is none: this file knows how to
  *walk* a payload synchronously, and knows nothing about what the shapes are.

  Going forward the log seals itself — `record-update!` copies what the client
  sent, and a sealed body makes a sealed payload for free. This is only the
  history.

  **A payload is rewritten by re-serialising it.** Key order inside a JSON object
  is not meaning, and `db/event.clj` parses the payload back into a map on read,
  so what matters is that the document says the same thing. It does. What changes
  beyond the prose is the order of keys and the odd redundant escape, in the rows
  this pass writes and in no others.

  ## What it will not touch

  **Every other user's rows**, which is the invariant above and is asserted
  rather than assumed: `--verify` counts, without a key and without reading one
  value, how many rows outside the scope carry the envelope prefix. It must be
  zero in both directions. That is the *other way* the invariant is reported, and
  it is the half cookbook never needed.

  **Blanks.** `nil` stays `nil`, `\"\"` stays `\"\"`, whitespace-only stays as it
  is — `seal-envelope/blank-value?` is the one place that rule is spelled and this
  counts by it. It is load-bearing in tracker for one specific reason:
  `db/journal_entry.clj prune-empty-entries` deletes stale journal entries whose
  description is empty, in SQL, server-side, with no key. Seal a blank and
  entries nobody wrote accumulate forever with nothing to say why.

  **`messages` and `mottos`**, which are not in the inventory at all. Message
  bodies are written by three producers that hold no key; a motto's description
  is a second name and not prose. `et.tr.seal-rules/clear-tables` argues both.

  **That one is asked rather than assumed, too**, and for a while it was not.
  `--verify` reported *nothing of anybody else's is sealed*, which is a different
  sentence from *nothing that must stay clear is sealed* — and since nothing here
  walks `messages` or `mottos`, nothing here was looking at them. A sealed motto
  and a sealed message body sat on a database that called the invariant held. So
  the clear tables get the same GLOB the foreign audit gets, over every column
  they have, for every user, in both directions, without reading a value.

  **Everything that is not prose.** No title, tag, badge title, scope, date, flag,
  ordering or id is read into an UPDATE, let alone written.

  ## The trap

  **The seal is called with no `stored`.** Its echo rule answers *does this column
  already say what I am about to write?* and hands back the stored value when it
  does — which is what stops a no-op save writing an audit event holding two
  envelopes of one unchanged sentence. A walker that passed the plaintext it just
  read in as `stored` would be told, correctly, that nothing had changed, and
  would seal nothing at all over the whole database while reporting a clean pass.
  Both the suite next door and `seal-envelope/seal-at`'s docstring say so, and
  `decide-value-test` would go red.

  ## Idempotent, resumable, reversible

  A value that already carries the prefix is left alone and counted as such, so a
  second run writes nothing and says so. **One row is one statement is one
  transaction**, so a kill mid-pass leaves some rows sealed and some not — which
  is a state every client already handles, since `unseal` is prefix-driven and
  mixed state is legal permanently — and the next run picks up where this one
  stopped. The suite proves that with `timeout -s KILL`.

  `--unseal` is the exact inverse, with the same scope. It is written and tested
  now rather than when it is needed, because an escape hatch nobody has opened is
  not one.

  ## `--arm`, which is the last act of the cutover

  `users.seal_prose` is what makes the server refuse a write that would introduce
  new plaintext prose into this user's rows. **It is armed after `--verify` is
  green and not before**: a flag armed over an unfinished pass turns every
  remaining plaintext row into a row that cannot be saved. So `--arm` runs the
  verify walk itself and refuses if anything of that user's is still unsealed.

  It arms the human and not his machine users, because the server resolves the
  flag through an identity that has already collapsed a machine user onto him.

  **And the mirror of that refusal, which is the first act of getting back.**
  `--unseal` over an armed database is refused too. It reaches the same state from
  the other side — the flag set over a database of plaintext — and it used to
  reach it in silence: every body readable and none of them saveable, which is a
  400 per the plan's guard table and another downtime to undo. The playbook's
  *Getting back* is `--disarm` and then `--unseal` for exactly this reason; the
  program is now what makes the order true rather than the operator's memory.
  `--dry-run --unseal` is left alone deliberately: it writes nothing, and a
  rehearsal that shows the flag still up is the cheapest moment to find that out.

  ## Why it refuses to run without a key

  Every other client in this system treats *no key* as *sealing off*, which is
  tracker before any of this existed. Here that would mean a pass that walks the
  whole database, writes nothing, and reports success — the one failure nobody
  would notice until somebody read a body that should have been sealed and was
  not. So this refuses, in every mode, and a malformed key throws where it is
  loaded. The fingerprint in the header is the other half of that: sealing a
  database with a key the owner's browser cannot open is the one mistake in this
  design with no recovery, and comparing eight characters against the ⚙ panel is
  the whole of how not to make it.

  ## sqlite3, and hex

  babashka has no JDBC, so the file is reached through the `sqlite3` binary.
  Values cross that boundary as **hex**, in both directions: prose is multi-line,
  holds quotes and holds emoji, and the one way to be certain no value is mangled
  by quoting is never to quote one. `typeof()` rides along, because `hex(NULL)`
  and `hex('')` are the same empty string and those two mean different things
  here."
  (:require [babashka.cli :as cli]
            [babashka.process :as p]
            [cheshire.core :as json]
            [clojure.string :as str]
            [seal-envelope :as env]
            [tracker-seal :as seal]))

;; ---------------------------------------------------------------------------
;; The inventory, and the little this file adds to it.
;;
;; `seal/sealed-columns`, `seal/bound-as` and `seal/prose-paths` are
;; `et.tr.seal-rules`, re-exported — the same vars tracker's server and tracker's
;; browser read. Nothing here restates any of them. A second spelling of the
;; inventory is how a new sealed column ends up walked by two clients of three.

(def ^:private tables
  "The nine tables that carry a sealed column, in a fixed order so that two runs
  read alike and a resumed pass is easy to follow.

  Which *columns* of them are sealed is not here and must not be: that is
  `seal/sealed-columns`, read at call time, so a new column flows into the
  SELECT, the UPDATE and the AAD with no hand-edit. Only the tables need naming,
  and `check-inventory!` is what stops that list going stale."
  [:tasks :issues :meets :meeting_series :recurring_tasks :journals
   :journal_entries :resources :categories])

(def ^:private events-table
  "The audit log, walked beside the nine because its payloads hold their prose.

  It is not one of them: `payload` is not a sealed column, it is a JSON document
  with sealed values inside it, which is why `seal/sealed-columns` does not name
  it and why everything below has to ask whether it is looking at this table."
  :events)

(def ^:private walked (conj tables events-table))

(defn- check-inventory!
  "A table added to the inventory and forgotten here would be walked by nobody and
  reported by nothing. So it is a refusal — raised at the start of `-main` and
  caught there, so it reads as one line and not a stack trace out of namespace
  load.

  Both halves of the inventory are checked. `sealed-columns` is what the walk
  reads columns out of, and `bound-as` is what an AAD is built from: a table can
  be added to either one alone, and each of those is a different quiet failure —
  a column nobody walks, or a binding nobody uses."
  []
  (when-not (= (set tables) (set (keys seal/sealed-columns)))
    (throw (ex-info (str "the walk and the inventory disagree about which tables hold prose: "
                         (pr-str (sort (map name tables))) " vs "
                         (pr-str (sort (map name (keys seal/sealed-columns))))) {})))
  (when-not (= (set walked) (set (keys seal/bound-as)))
    (throw (ex-info (str "the walk and the bindings disagree about which tables are sealed: "
                         (pr-str (sort (map name walked))) " vs "
                         (pr-str (sort (map name (keys seal/bound-as))))) {}))))

(defn- owner-column
  "Which column says whose row this is.

  Two answers, and the second one is the reason there is a function rather than a
  map: `events.effective_user_id` is already the *human* a write was for — the
  server collapses a machine user onto his parent before it records anything
  (`server/common.clj claims->identity`) — while an entity's `user_id` is the
  owner directly. They are different columns with the same meaning, and that is
  the whole of it."
  [table]
  (if (= events-table table) :effective_user_id :user_id))

(defn- value-columns
  "The columns of one table this pass reads. The inventory's, except for the audit
  log, whose one column is a JSON document rather than a value."
  [table]
  (if (= events-table table) [:payload] (get seal/sealed-columns table)))

;; ---------------------------------------------------------------------------
;; sqlite3.

(def ^:private preamble
  "Every invocation says how it wants its output before it asks for any. The
  shell reads `~/.sqliterc` on the machine this runs on, and a person who has
  ever typed `.mode box` into it would otherwise get a pass that reads a drawing
  of a table as a table.

  **`.timeout` is what makes the compare-and-set reachable as documented.**
  Without it a concurrent writer does not lose the race, it aborts the pass:
  `SQLITE_BUSY` fires before the `WHERE` is ever evaluated. The abort is safe —
  it leaves the legal, resumable half-sealed state everything here is built
  around — but *reported as `moved`* is the better answer and is what the report
  claims. A cutover should have stopped writes anyway.

  It is the dot command and not `PRAGMA busy_timeout = 5000`, which **prints its
  new value**: one extra line at the head of every result, which a parser reading
  by position takes for a row. Everything in this preamble has to be output-free."
  ".mode list\n.separator |\n.headers off\n.timeout 5000\n")

(defn- sqlite!
  "One `sqlite3` invocation, SQL on stdin. On stdin rather than in argv because a
  body — or a whole event payload, doubled by hex — is arbitrarily long, and
  `ARG_MAX` is a limit somebody else's operating system chooses."
  [db sql]
  (let [{:keys [out err exit]} (p/shell {:in (str preamble sql) :out :string :err :string
                                         :continue true}
                                        "sqlite3" "-batch" db)]
    (when-not (zero? exit)
      (throw (ex-info (str "sqlite3 refused: " (str/trim (str err))) {:exit exit})))
    out))

(defn- rows [db sql]
  (->> (sqlite! db sql) str/split-lines (remove str/blank?)))

(defn- one [db sql] (first (rows db sql)))

(defn- unhex ^String [^String h]
  (let [n (quot (count h) 2)
        bs (byte-array n)]
    (dotimes [i n]
      (aset-byte bs i (unchecked-byte (Integer/parseInt (subs h (* 2 i) (+ 2 (* 2 i))) 16))))
    (String. bs "UTF-8")))

(defn- hexed ^String [^String s]
  (str/join (map #(format "%02x" (bit-and % 0xff)) (.getBytes s "UTF-8"))))

(defn- literal
  "A text value as SQL that cannot be misread. `CAST(X'…' AS TEXT)` says the same
  thing as a quoted string and says it without a quote in it, which is the only
  way to be sure a body full of apostrophes and newlines arrives as it left."
  [s]
  (str "CAST(X'" (hexed s) "' AS TEXT)"))

(defn- cell
  "One `typeof(c) || ':' || hex(c)` field, back into a value.

  `hex(NULL)` and `hex('')` are both the empty string, and NULL and empty are the
  distinction this whole pass is careful about — so the type comes along and is
  what decides."
  [field]
  (let [[t h] (str/split field #":" 2)]
    (case t
      "null" {:type :null}
      "text" {:type :text :value (unhex h)}
      {:type (keyword t)})))

(defn- id-list
  "A set of user ids as a SQL list. Integers, straight out of `users.id`, and
  they are the one kind of value this file is willing to interpolate: they came
  from `parse-long` and anything that did not parse is not here."
  [ids]
  (str/join "," (sort ids)))

;; ---------------------------------------------------------------------------
;; Whose rows. The argument this pass refuses to guess.

(defn- resolve-user!
  "The scope of the walk: `{:username … :id … :machine-ids [...] :ids #{…}}`.

  A human, plus every machine user acting for him. The machine ids are in the
  scope for completeness rather than because anything uses them today — every
  write goes through an identity that has already collapsed a machine user onto
  his parent, so his rows carry his own id. A pass that left them out would be
  betting on that, and the bet is free to decline.

  Refusals, and each of them is a mistake worth making loudly at the start rather
  than quietly forever:

  - **no name at all** — see the namespace docstring. There is no default.
  - **a name that is not in this database** — usually the wrong file or a typo,
    and the usernames are printed so the answer is on screen.
  - **a machine user's name** — it is half a scope. The human is named instead."
  [db username]
  (when (str/blank? username)
    (throw (ex-info (str "--user is required: name the user whose prose is to be sealed."
                         " There is no default, deliberately — a wrong guess seals rows"
                         " nobody asked to seal. This database holds: "
                         (str/join ", " (rows db (str "SELECT username || ' (id ' || id || ')' "
                                                      "FROM users WHERE is_machine_user IS NOT 1 "
                                                      "ORDER BY id;"))))
                    {})))
  (let [line (one db (str "SELECT id || '|' || COALESCE(is_machine_user, 0) || '|' "
                          "|| COALESCE(for_user_id, '') FROM users WHERE username IS "
                          (literal username) ";"))]
    (when-not line
      (throw (ex-info (str "no user " (pr-str username) " in this database. It holds: "
                           (str/join ", " (rows db "SELECT username FROM users ORDER BY id;")))
                      {})))
    (let [[id machine? for-user] (str/split line #"\|" -1)]
      (when (= "1" machine?)
        (throw (ex-info (str (pr-str username) " is a machine user"
                             (when-not (str/blank? for-user)
                               (str " acting for user " for-user))
                             ". Name the human whose prose is sealed: his rows and his"
                             " machines' are one scope, and half of it is not a scope.")
                        {})))
      (let [id (parse-long id)
            machine-ids (keep parse-long
                              (rows db (str "SELECT id FROM users WHERE for_user_id = " id
                                            " ORDER BY id;")))]
        {:username username
         :id id
         :machine-ids (vec machine-ids)
         :ids (into #{id} machine-ids)}))))

;; ---------------------------------------------------------------------------
;; Reading. Scoped, always.

(defn- select-sql [table ids]
  (str "SELECT t.id, "
       (str/join ", " (for [c (value-columns table)]
                        (str "typeof(t." (name c) ") || ':' || hex(t." (name c) ")")))
       " FROM " (name table) " t"
       " WHERE t." (name (owner-column table)) " IN (" (id-list ids) ")"
       " ORDER BY t.id;"))

(defn- read-table
  "Every in-scope row of one table, as `{:id n :cells {column → cell}}`.

  Read in one go and written row by row. The gap between the two is what the
  compare-and-set write is for.

  **Rows of other users never leave the database**, and rows with no owner at all
  — `user_id` is nullable on six of the nine tables — are not this user's either,
  so `IN` excludes them and says so by saying nothing. `foreign-audit` below is
  what accounts for all of them, in counts rather than in values."
  [db table ids]
  (let [columns (value-columns table)]
    (for [line (rows db (select-sql table ids))
          :let [fields (str/split line #"\|" -1)
                [id & cells] fields]]
      {:id (parse-long id)
       :cells (zipmap columns (map cell cells))})))

;; ---------------------------------------------------------------------------
;; The decision, one value at a time. Pure, and the only part of this worth a
;; test that needs no database.
;;
;; Everything below takes the binding as a **string** rather than a table and a
;; column, because half the values here are not in a column: a payload's prose
;; comes with its own binding from `seal/prose-paths`, and `item/description` is
;; the same string whichever of the nine tables it came out of. `seal/aad` is
;; what turns a table and a column into one, and it is the only place that
;; happens. `env/seal-at` and `env/unseal-at` are the arities that take it —
;; reaching past `tracker-seal` for exactly that reason, and for no other:
;; `tracker-seal/seal-payload` reaches the same way for the same reason.

(defn- inside
  "What one envelope actually holds: `:unopenable`, `:nested`, or `:prose`.

  `unseal-at` hands back a value it cannot read exactly as it is — rule 3, so that
  one unreadable column shows as `enc:v1:…` beside everything that reads instead
  of taking a response down — so *unchanged* is how *it did not open* is said.

  `:nested` is the third answer: a value that opens into another envelope is
  `enc(enc(prose))`, a reader meets `enc:v1:…` where the body should be, and
  opening it once succeeds, so every check short of this one is blind to it. No
  correct client writes one; a client that sealed a ciphertext it had echoed did,
  which is the bug `seal-at`'s bytes-first comparison exists to prevent."
  [k aad v]
  (let [opened (env/unseal-at k aad v)]
    (cond
      (= opened v) :unopenable
      (seal/sealed? opened) :nested
      :else :prose)))

(defn- json-cell
  "A value read out of a parsed payload, in the shape a value read out of a column
  arrives in — so that one `decide` and one `verdict` serve both.

  JSON has one more shape than a column does: a path that leads to a number, a
  boolean or a map where prose was expected. That is `:odd`, the same answer a
  BLOB in a prose column gets, and for the same reason — deciding it is text would
  be a judgement about somebody else's data that a counting pass has no business
  making."
  [v]
  (cond
    (nil? v) {:type :null}
    (string? v) {:type :text :value v}
    :else {:type :other}))

(defn decide
  "What this pass must do with one value: `[bucket new-value]`, where `new-value`
  is `nil` for everything it is leaving alone.

  The buckets are the audit. Every value lands in exactly one of them and the
  counts are printed, so a pass that did less than it should have shows up as a
  number rather than as a body somebody reads six months later.

  `:blank` and `:already` are the two ways of doing nothing on purpose;
  `:unopenable` is a value carrying the prefix that this key does not open, which
  is the one thing here nobody can fix in passing — it is reported and left
  exactly as it is. `:nested` is an envelope inside an envelope, which this pass
  will not try to unwrap in the seal direction. `:odd` is a prose value that is
  not text at all."
  [direction k aad {:keys [type value]}]
  (cond
    (= :null type) [:blank nil]
    (and (= :text type) (seal/blank-value? value)) [:blank nil]
    (not= :text type) [:odd nil]

    (= :seal direction)
    (if (seal/sealed? value)
      [(case (inside k aad value)
         :unopenable :unopenable
         :nested :nested
         :prose :already)
       nil]
      ;; **No `stored`.** The trap in the namespace docstring, and in
      ;; `seal-envelope/seal-at`'s: hand it the plaintext just read and the echo
      ;; rule answers, correctly, that nothing changed.
      [:changed (env/seal-at k aad value nil)])

    :else
    (if-not (seal/sealed? value)
      [:already nil]
      ;; **One layer, deliberately** — and counted as `:nested` when a layer is
      ;; all it was. Unwrapping recursively would be a pass inventing how deep
      ;; somebody else's mistake goes; writing the inner envelope and saying so
      ;; makes progress, exits non-zero, and finishes on the next run.
      (let [plain (env/unseal-at k aad value)]
        (cond
          (= plain value) [:unopenable nil]
          (seal/sealed? plain) [:nested plain]
          :else [:changed plain])))))

(defn verdict
  "The same walk, deciding nothing and asserting instead. `[bucket violation?]`.

  In the seal direction every non-blank prose value in scope must be an envelope
  this key opens; in the unseal direction none of them may be an envelope at all.
  The *other* half of the invariant — that nothing outside the scope is sealed —
  is `foreign-audit`, which asks it of the database rather than of a value, and
  needs no key to do it.

  ## A value this pass cannot account for is a violation in **both** directions

  `:odd` used to be one only in the seal direction, while `unfinished` counted it
  in both — so `--verify --inverse` printed *The invariant holds, in both
  directions.* and exited 1 over the same database, and the playbook's *Getting
  back* ends on exactly that command, calling it *how you prove the hatch
  actually opened rather than reported that it had*. A headline and an exit code
  that answer different questions are worse than either answer alone.

  They are reconciled towards the stricter reading, because it is the truer one.
  A BLOB holding readable prose, and a payload shape nothing walks, are
  **readable prose this pass went past** — and neither becomes less so by the
  direction of travel. Nothing here will convert one, in either direction, so
  neither direction can call a database holding one finished."
  [direction k aad {:keys [type value]}]
  (cond
    (= :null type) [:null false]
    (and (= :text type) (seal/blank-value? value)) [:blank false]

    ;; **A violation whichever way this is going**, and that is the point of the
    ;; bucket. A BLOB holding readable prose is prose in the clear; `decide` will
    ;; not convert it in either direction, so a verify that called it merely odd
    ;; would report a holding invariant over a line anybody with the file can read.
    (not= :text type) [:odd true]

    (= :unseal direction)
    (if (seal/sealed? value) [:sealed true] [:plain false])

    (not (seal/sealed? value)) [:plain true]

    :else (case (inside k aad value)
            :prose [:sealed false]
            :nested [:nested true]
            :unopenable [:unopenable true])))

(defn- judge
  "One value, judged in whichever way this run is judging: the decision and its
  new value, or the verdict and its flag.

  They are kept in **named keys of one map** rather than in a pair, because the
  two answers have the same shape and different meanings, and cookbook's walker
  put a `verdict`'s boolean into an UPDATE for exactly as long as it took its
  suite to say so."
  [{:keys [mode direction k]} aad cell]
  (if (= :verify mode)
    (let [[bucket flag] (verdict direction k aad cell)]
      {:bucket bucket :violation? flag})
    (let [[bucket v] (decide direction k aad cell)]
      {:bucket bucket :value v})))

;; ---------------------------------------------------------------------------
;; The audit log, whose values are inside a document.

(def ^:private unparseable ::unparseable)

(defn- parse-payload [^String s]
  (try (json/parse-string s true) (catch Exception _ unparseable)))

(def ^:private loose-description
  "A `description` holding something, in raw payload text.

  This is not a sixth spelling of the shapes — it does not know where prose lives
  and cannot seal anything. It is the smoke alarm for the one failure the shapes
  cannot report about themselves: a payload that holds a description somewhere
  `prose-paths` does not look, which would be walked by nobody, counted as clean,
  and left in the clear. Compared against the number of paths actually found, so
  the shapes that hold *no* literal `\"description\":\"…\"` — an update's
  `{:field \"description\" …}`, a multi-field `{:changes {:description {…}}}`, a
  dropped write's escaped body — cannot make it fire, and neither can a
  description whose value is empty."
  #"\"description\"\s*:\s*\"[^\"]")

(defn- judge-payload
  "One event payload, judged. `{:entries [{:bucket … :violation? …} …] :value …}`,
  where `:value` is the re-serialised payload when anything inside it changed.

  Every prose value inside gets its own entry and its own bucket, because that is
  what the counts are for; the row is written once, with all of them.

  A payload that is not JSON at all is `:odd` and a violation in **both**
  directions, for the reason a BLOB in a prose column is: unreadable to this pass
  is not the same as holding nothing, and the operator should look. So is a
  payload holding a description in a shape `prose-paths` does not know — prose
  this pass went past, which it went past going either way."
  [ctx {:keys [type value]}]
  (let [direction (:direction ctx)]
    (cond
      (= :null type) {:entries [{:bucket :blank}]}
      (not= :text type) {:entries [{:bucket :odd :violation? true}]}
      :else
      (let [payload (parse-payload value)]
        (if (= unparseable payload)
          {:entries [{:bucket :odd :violation? true}]}
          (let [paths (seal/prose-paths payload)
                judged (for [[path aad] paths]
                         (assoc (judge ctx aad (json-cell (get-in payload path))) :path path))
                sealed (reduce (fn [p {:keys [path value]}]
                                 (if (some? value) (assoc-in p path value) p))
                               payload judged)
                unwalked? (> (count (re-seq loose-description value)) (count paths))]
            {:entries (cond-> (vec judged)
                        (empty? judged) (conj {:bucket :no-prose})
                        unwalked? (conj {:bucket :unwalked :violation? true}))
             :value (when (some :value judged) (json/generate-string sealed))}))))))

(defn- judge-row
  "One row of any walked table: `{:entries […] :changed {column → new value}}`.

  The nine tables answer one entry per sealed column. The audit log answers one
  entry per prose value inside its payload and one changed column, since the
  document is written back whole."
  [ctx table {:keys [cells]}]
  (if (= events-table table)
    (let [{:keys [entries value]} (judge-payload ctx (get cells :payload))]
      {:entries (map #(assoc % :column :payload) entries)
       :changed (when (some? value) {:payload value})})
    (let [entries (for [c (value-columns table)]
                    (assoc (judge ctx (seal/aad table c) (get cells c)) :column c))]
      {:entries entries
       :changed (into {} (for [{:keys [column value]} entries :when (some? value)]
                           [column value]))})))

;; ---------------------------------------------------------------------------
;; Writing.

(defn- update-sql
  "One row, one statement, one transaction — which is the whole of the
  resumability story.

  **The `WHERE` re-asks everything the decision rested on**: the id, the values
  this pass read, and *that the row still belongs to the user being sealed*. A row
  that moved underneath the pass is then not written over, and `changes()` is how
  that is noticed.

  The scope conjunct is the tracker half of what cookbook spells as
  `still-unpublished`. Ownership is read once for a whole table and acted on row
  by row, and a row changing hands changes no prose value, so the compare-and-set
  on the value alone would have matched — and the pass would have sealed a row
  that had become antonio's in between. There is nothing to seal outside the
  scope, ever, so a `WHERE` that says so costs nothing and closes the window."
  [table {:keys [id cells]} changed ids]
  (str "UPDATE " (name table) " SET "
       (str/join ", " (for [[c v] changed] (str (name c) " = " (literal v))))
       " WHERE id = " id
       " AND " (str/join " AND " (for [[c _] changed]
                                   (str (name c) " IS " (literal (:value (get cells c))))))
       " AND " (name (owner-column table)) " IN (" (id-list ids) ")"
       "; SELECT changes();"))

;; ---------------------------------------------------------------------------
;; The pass.

(defn- tally [m bucket] (update m bucket (fnil inc 0)))

(defn- walk-table
  [{:keys [db mode ids verbose?] :as ctx} table]
  (reduce
   (fn [acc row]
     (let [{:keys [entries changed]} (judge-row ctx table row)
           acc (reduce (fn [a {:keys [bucket violation? column]}]
                         (cond-> (tally a bucket)
                           violation?
                           (update :violations (fnil conj [])
                                   {:table table :id (:id row) :column column :why bucket})))
                       acc entries)]
       (if (empty? changed)
         acc
         (do
           ;; **A dry run names them too**, which is the one occasion on which
           ;; being able to read the list changes a decision: it is the run whose
           ;; output the operator is deciding whether to proceed on. The table, the
           ;; id and the column names — never a value, in any mode.
           (when verbose?
             (println (format "  %-16s %-10s %s" (name table) (str "id " (:id row))
                              (str/join " " (map name (keys changed))))))
           (if (= :dry-run mode)
             (update acc :rows (fnil inc 0))
             (let [n (parse-long (str/trim (or (one db (update-sql table row changed ids)) "0")))]
               (if (= 1 n)
                 (update acc :rows (fnil inc 0))
                 ;; The compare-and-set found something else there — a value that
                 ;; moved, or a row that changed hands. Counted, named and left: a
                 ;; re-run picks up whatever the new state is. The buckets those
                 ;; values were tallied into are given back one by one rather than
                 ;; assumed to be `:changed`, since the unseal direction can put a
                 ;; write in `:nested`.
                 (-> (reduce (fn [a {:keys [bucket value]}]
                               (cond-> a (some? value) (update bucket dec)))
                             acc entries)
                     (update :moved (fnil conj []) {:table table :id (:id row)})
                     (tally :skipped-moved)))))))))
   {}
   (read-table db table ids)))

;; ---------------------------------------------------------------------------
;; The other half of the invariant: nobody else's prose.
;;
;; This is the check cookbook never needed, and it is the one this pass exists to
;; be able to make. It asks the database rather than the values: no key, no
;; decryption, and **not one of another user's bodies crosses the sqlite3
;; boundary** — only counts and ids do. Asking it any other way would mean
;; reading the rows this pass is promising not to read.

(defn- sealed-glob
  "The GLOB that matches exactly what `sealed?` matches — the prefix, anchored,
  read out of the shared rules rather than spelled here. GLOB and not LIKE:
  LIKE is case-insensitive over ASCII in SQLite, so it would call `ENC:V1:…`
  sealed, and the fixture carries that exact string as plaintext."
  []
  (literal (str seal/envelope-prefix "*")))

(defn- payload-sealed-glob
  "The same question of a JSON document. A sealed value inside a payload is a JSON
  string, so the prefix is always preceded by a quote — which is what keeps a body
  that merely *writes about* `enc:v1:` from being reported as one."
  []
  (literal (str "*\"" seal/envelope-prefix "*")))

(defn- foreign-audit
  "For every walked table: how many rows are **not** this user's, and how many of
  those carry the envelope prefix. One invocation for all ten.

  The first number is the reassurance the playbook asks for — *the pass touches no
  other user* — as a number rather than as a claim. The second is a violation in
  both directions: a keyed client sealing antonio's prose is what the server's
  guard refuses in its other direction, and if one ever got through, the row would
  be unreadable to the only person entitled to read it."
  [db ids]
  (let [scope (fn [table] (str (name (owner-column table)) " IS NULL OR "
                               (name (owner-column table)) " NOT IN (" (id-list ids) ")"))
        glob (fn [table] (if (= events-table table)
                           (str "payload GLOB " (payload-sealed-glob))
                           (str/join " OR " (for [c (value-columns table)]
                                              (str (name c) " GLOB " (sealed-glob))))))]
    (for [line (rows db (str/join "\nUNION ALL\n"
                                  (for [t walked]
                                    (str "SELECT " (literal (name t)) " || '|' || count(*) || '|' "
                                         "|| COALESCE(SUM(CASE WHEN " (glob t) " THEN 1 ELSE 0 END), 0)"
                                         " FROM " (name t) " WHERE " (scope t)))))
          :let [[table rows-out sealed] (str/split line #"\|" -1)]]
      {:table (keyword table) :rows (parse-long rows-out) :sealed (parse-long sealed)})))

(defn- foreign-sealed-ids
  "The ids of the offending rows, asked only when there are any. Ids, and nothing
  else: naming a row is what the operator needs, and its body is not."
  [db ids table]
  (let [glob (if (= events-table table)
               (str "payload GLOB " (payload-sealed-glob))
               (str/join " OR " (for [c (value-columns table)]
                                  (str (name c) " GLOB " (sealed-glob)))))]
    (keep parse-long
          (rows db (str "SELECT id FROM " (name table)
                        " WHERE (" (name (owner-column table)) " IS NULL OR "
                        (name (owner-column table)) " NOT IN (" (id-list ids) "))"
                        " AND (" glob ") ORDER BY id LIMIT 40;")))))

;; ---------------------------------------------------------------------------
;; The third direction: the tables that must stay clear.
;;
;; `foreign-audit` above asks *is anything of somebody else's sealed*. That is a
;; different question from *is anything that must stay clear sealed*, and for a
;; while this program only asked the first — so a sealed `mottos` description and
;; a sealed `messages` body sat on a database whose `--verify` said, in those
;; words, that the invariant held in both directions.
;;
;; `messages` and `mottos` are in neither `walked` nor `foreign-audit`, because
;; nothing here touches them; that is exactly why nothing here was asking about
;; them. Recipe 159 names the shape: **an invariant that holds only for the
;; columns somebody happens to look at is not one.**
;;
;; Like `foreign-audit`, this asks the database rather than the values — a GLOB
;; against the prefix, no key, no decryption, and not one message body crosses
;; the sqlite3 boundary. And unlike everything else here it is **not scoped to a
;; user**: `clear-tables` is permanent and applies to all three humans, so
;; antonio's sealed message is the same violation as daniel's.

(defn- quoted-identifier
  "A column name as SQL. Double quotes, doubled inside, because these names come
  out of `pragma_table_info` rather than out of this file — every one of
  tracker's is a bare word today, and a walk that assumed that about a schema it
  reads at run time would be assuming it about somebody else's database."
  [s]
  (str \" (str/replace s "\"" "\"\"") \"))

(defn- any-column-sealed
  "`c1 GLOB 'enc:v1:*' OR c2 GLOB …` over a whole row.

  **Every column, and not the one called `description`.** A clear table is clear
  in all of it: a subject line, a sender or a motto's scope carrying an envelope
  is the same accident with the same cause, and picking one column to ask about
  would rebuild the blind spot this check exists to close — one column lower
  down."
  [columns]
  (str/join " OR " (for [c columns] (str (quoted-identifier c) " GLOB " (sealed-glob)))))

(defn- clear-columns
  "The clear tables this database actually has, and every column of each:
  `{table [column …]}`, in one invocation.

  The intersection matters in both directions. `clear-tables` names eighteen
  tables and a given tracker holds some of them — `items` is not a tracker table
  at all and the seven `*_categories` join tables came in one at a time — so a
  walk over the list as written would refuse a database for not having a table it
  was never supposed to have. Asking `sqlite_master` costs one query and makes
  the answer about this file.

  `pragma_table_info` as a joinable table-valued function is SQLite ≥ 3.16, which
  this program already depends on elsewhere (`seal-prose-column?`)."
  [db]
  (let [wanted (str/join ", " (map #(literal (name %)) (sort (map name seal/clear-tables))))]
    (reduce (fn [m line]
              (let [[table column] (str/split line #"\|" -1)]
                (update m (keyword table) (fnil conj []) column)))
            {}
            (rows db (str "SELECT m.name || '|' || p.name"
                          " FROM sqlite_master m JOIN pragma_table_info(m.name) p"
                          " WHERE m.type = 'table' AND m.name IN (" wanted ")"
                          " ORDER BY m.name, p.cid;")))))

(defn- clear-audit
  "For every clear table present: how many rows it has, and how many of them carry
  the envelope prefix anywhere. One invocation for all of them.

  The first number is what turns *and these stay clear* from a claim into
  something on the screen; the second is a violation in both directions."
  [db]
  (let [columns (clear-columns db)]
    (when (seq columns)
      (vec (for [line (rows db (str/join "\nUNION ALL\n"
                                         (for [[t cs] (sort-by key columns)]
                                           (str "SELECT " (literal (name t)) " || '|' || count(*) || '|' "
                                                "|| COALESCE(SUM(CASE WHEN " (any-column-sealed cs)
                                                " THEN 1 ELSE 0 END), 0) FROM " (name t)))))
                 :let [[table rows-out sealed] (str/split line #"\|" -1)]]
             {:table (keyword table) :columns (get columns (keyword table))
              :rows (parse-long rows-out) :sealed (parse-long sealed)})))))

(defn- clear-sealed-rows
  "The offending rows, asked only of the tables that answered. The row and the
  column it is in, and nothing else — the operator needs to know which motto, not
  what it says.

  **`rowid` rather than `id`**, because `working_on` has no `id`: its primary key
  is `user_id`. Every one of these is an ordinary rowid table, where `rowid` is
  the `id` when there is one and an answer when there is not."
  [db {:keys [table columns]}]
  (for [line (rows db (str "SELECT rowid || '|' || CASE "
                           (str/join " " (for [c columns]
                                           (str "WHEN " (quoted-identifier c) " GLOB " (sealed-glob)
                                                " THEN " (literal c))))
                           " END FROM " (name table)
                           " WHERE (" (any-column-sealed columns) ") ORDER BY rowid LIMIT 40;"))
        :let [[id column] (str/split line #"\|" -1)]]
    {:table table :id (parse-long id) :column (keyword column) :why :clear-sealed}))

;; ---------------------------------------------------------------------------
;; What it prints. The counts are the point: a pass whose output is "done" is a
;; pass nobody can check.

(def ^:private headings
  "Which buckets each mode prints, in order, and what to call them. A bucket with
  no column here would be counted and never seen, so every one `decide`,
  `verdict` and `judge-payload` can answer appears in exactly one of these lists."
  {[:pass :seal]     [[:changed "sealed"] [:already "already"] [:blank "blank"]
                      [:no-prose "no-prose"] [:unopenable "unopenable"] [:nested "NESTED"]
                      [:odd "odd"] [:unwalked "UNWALKED"] [:skipped-moved "moved"]]
   [:pass :unseal]   [[:changed "unsealed"] [:already "plain"] [:blank "blank"]
                      [:no-prose "no-prose"] [:unopenable "unopenable"] [:nested "NESTED"]
                      [:odd "odd"] [:unwalked "UNWALKED"] [:skipped-moved "moved"]]
   [:verify :seal]   [[:sealed "sealed"] [:plain "PLAINTEXT"] [:blank "blank"] [:null "null"]
                      [:no-prose "no-prose"] [:unopenable "UNOPENABLE"] [:nested "NESTED"]
                      [:odd "odd"] [:unwalked "UNWALKED"]]
   [:verify :unseal] [[:plain "plain"] [:sealed "SEALED"] [:blank "blank"] [:null "null"]
                      [:no-prose "no-prose"] [:odd "odd"] [:unwalked "UNWALKED"]]})

(defn- print-counts [mode direction by-table]
  (let [cols (get headings [(if (= :verify mode) :verify :pass) direction])
        total (apply merge-with + (vals by-table))
        used (filter (fn [[b _]] (pos? (get total b 0))) cols)
        ;; Only the buckets that answered. A row of zeroes across nine columns
        ;; hides the two numbers that matter.
        used (if (seq used) used (take 2 cols))
        w (fn [[_ label]] (max 8 (count label)))]
    (println)
    (println (apply str (format "  %-18s" "table") (map #(format (str "%" (w %) "s  ") (second %)) used)))
    (doseq [table walked
            :let [counts (get by-table table)]]
      (println (apply str (format "  %-18s" (name table))
                      (map (fn [[b :as c]] (format (str "%" (w c) "s  ")
                                                   (str (get counts b 0)))) used))))
    (println (apply str "  " (apply str (repeat 16 "-")) "  "
                    (map #(str (apply str (repeat (w %) "-")) "  ") used)))
    (println (apply str (format "  %-18s" "total")
                    (map (fn [[b :as c]] (format (str "%" (w c) "s  ") (str (get total b 0)))) used)))))

(defn- print-alarms
  "The numbers the playbook's own checklist asks the operator to confirm are zero
  — printed whether or not they are.

  The table above prints only the buckets that answered, because a row of zeroes
  across nine columns hides the two numbers that matter. But *\"unopenable,
  nested, odd and moved all 0 — any of them is a stop\"* is answered badly by a
  column that is not there: absent and zero look the same only to somebody who
  already knows the rule. One line, always, and it is the line to read before
  deciding to go on."
  [total elsewhere in-the-clear-tables]
  (println)
  (println (str "  alarms             "
                (str/join " · " (for [[k label] [[:unopenable "unopenable"] [:nested "nested"]
                                                 [:odd "odd"] [:unwalked "unwalked"]
                                                 [:skipped-moved "moved"]]]
                                  (str label " " (get total k 0))))))
  ;; The two halves of the invariant this pass cannot see from inside its own
  ;; walk, on their own line because the first one is already as long as a line
  ;; should be. Both are counts of rows nothing here read.
  (println (str "                     sealed rows of other users " (count elsewhere)
                " · sealed rows in clear tables " (count in-the-clear-tables))))

(defn- plural [n word] (str n " " word (when (not= 1 n) "s")))

(def ^:private reasons
  {:plain "in the clear, where this user's prose must be sealed"
   :sealed "an envelope, where none may remain"
   :unopenable "carries the prefix and does not open with this key"
   :nested "an envelope inside an envelope — a reader meets enc:v1: for prose"
   :odd "not text: a BLOB, or a payload that is not JSON"
   :unwalked "holds a description in a payload shape prose-paths does not know"
   :foreign-sealed "another user's row, and it carries the envelope prefix"
   :clear-sealed "a table that stays clear, and it carries the envelope prefix"})

(defn- print-violations [violations]
  (when (seq violations)
    (println)
    (println (str "  " (plural (count violations) "violation") ":"))
    (doseq [{:keys [table id column why]} (take 40 violations)]
      (println (format "    %-18s %-10s %-10s %s" (name table) (str "id " id) (name column)
                       (get reasons why (name why)))))
    (when (> (count violations) 40)
      (println (str "    … and " (- (count violations) 40) " more")))))

;; ---------------------------------------------------------------------------
;; Everything that has to be true before a value is read.

(defn- check-database!
  "Said one at a time, because each of these is a different wrong file.

  `sqlite3` **creates** a database it is pointed at, so a typo in the path would
  otherwise produce an empty file, a clean pass over nothing, and a report saying
  so."
  [db]
  (when-not (.exists (java.io.File. ^String db))
    (throw (ex-info (str "no database at " db
                         " — sqlite3 would have made an empty one and this would have"
                         " reported a clean pass over it") {})))
  (let [encoding (str/trim (str (one db "PRAGMA encoding;")))]
    (when-not (= "UTF-8" encoding)
      (throw (ex-info (str "this database is " encoding
                           "; every value here crosses as UTF-8 bytes") {}))))
  (let [present (set (rows db "SELECT name FROM sqlite_master WHERE type = 'table';"))
        missing (remove present (conj (map name walked) "users"))]
    (when (seq missing)
      (throw (ex-info (str "not a tracker database: no " (str/join ", " missing)) {})))))

(defn- sidecars
  "The files beside a database that **hold state the `.db` alone does not**, named
  by their suffix.

  ## The distinction is the bytes, not the filename

  It is tempting to write this as *is there a file called `-journal` or `-wal`
  next to it*, and that is wrong in a way that only shows up on somebody else's
  machine. The two suffixes mean opposite things:

  - a **`-journal`** beside a `journal_mode=delete` database is an interrupted
    write. It holds the pre-images, the `.db` is already modified, and the file
    alone is either torn or silently different from what was committed. Refusing
    is the whole point.
  - a **`-wal`** beside a `journal_mode=wal` database is the ordinary resting
    state. `PRAGMA wal_checkpoint(TRUNCATE)` folds its pages into the `.db` and
    **truncates it to zero bytes without removing it** — and whether the empty
    file then survives the connection closing is the platform's business. This
    box's sqlite3 deletes it; a build with `SQLITE_FCNTL_PERSIST_WAL` keeps it.
    Both are healthy, and a pass that called one of them a stray would exit 1 on
    one machine and 0 on the other over the same database.

  So the question is *does this file hold anything the database file does not*,
  and the answer is its length. A zero-length sidecar holds nothing — which is
  also true of the `-journal` that `journal_mode=truncate` leaves at rest, and of
  the one a process can leave behind by dying after creating the file and before
  writing a header, which SQLite itself does not consider hot.

  `-shm` is deliberately not here: it is a shared-memory index rebuilt from the
  `-wal`, it never holds anything that is not elsewhere, and a read is enough to
  create one.

  **`vec` and not a lazy seq, and that is not style.** The answer has to be
  *taken* before the first `sqlite3` invocation, not merely asked for: a lazy seq
  realised one line later is realised after the database has been opened, the
  journal rolled back and the file deleted — and then the note never prints."
  [db]
  (vec (for [suffix ["-journal" "-wal"]
             :let [f (java.io.File. (str db suffix))]
             :when (and (.isFile f) (pos? (.length f)))]
         suffix)))

(defn- checkpoint!
  "A WAL database keeps the newest pages in a sidecar file. Copying the `.db`
  alone after a pass would leave the sealing behind — so the pass folds it in
  before it says it is done, and says which mode it found. Tracker is in
  `delete` mode today, which is exactly the kind of thing that changes once.

  `TRUNCATE` empties the `-wal` rather than removing it, and that zero-length
  file is the healthy resting state — see `sidecars`, which is why this runs
  *before* the sidecars are counted for the last time and not after. A `-wal`
  that still has bytes in it once this has run is a real answer and not a
  filename: something else is holding the WAL open, and a TRUNCATE checkpoint
  cannot complete while a reader has a snapshot in it."
  [db]
  (when (= "wal" (str/lower-case (str/trim (str (one db "PRAGMA journal_mode;")))))
    (sqlite! db "PRAGMA wal_checkpoint(TRUNCATE);")
    true))

;; ---------------------------------------------------------------------------
;; The flag. The last act of the cutover, and the first act of getting back.

(defn- seal-prose-column? [db]
  (boolean (some #{"seal_prose"} (rows db "SELECT name FROM pragma_table_info('users');"))))

(defn- require-flag-column! [db]
  (when-not (seal-prose-column? db)
    (throw (ex-info (str "this database has no users.seal_prose column: migration"
                         " 074-add-seal-prose has not run against it. The flag is the"
                         " server's half of the seal, and arming one the server does not"
                         " understand would change nothing while reporting that it had.")
                    {}))))

(defn- flag-state
  "`users.seal_prose` for one user: `:armed`, `:clear`, or `:absent` when the
  column is not there at all.

  **Read in every mode**, because the flag is half of what the state of a cutover
  is, and finding out which half should not cost a second command at the hour
  this is run. `--arm` and `--disarm` are the two that cannot proceed without the
  column, and they refuse for themselves in `require-flag-column!`; everything
  else says what it found in the header and carries on."
  [db user-id]
  (if-not (seal-prose-column? db)
    :absent
    (if (= "1" (str/trim (str (one db (str "SELECT seal_prose FROM users WHERE id = "
                                           user-id ";")))))
      :armed
      :clear)))

(defn- refuse-unseal-while-armed!
  "The mirror of `--arm`'s refusal, and it was missing.

  `--arm` will not arm over an unfinished pass, because a flag set over plaintext
  rows turns every one of them into a row that cannot be saved. **The same state
  is reachable from the other side**, and was reachable in silence: unseal an
  armed database and the flag is still 1 over a database in which every one of
  his bodies is now plaintext. Per the plan's own guard table, *plaintext
  differing from stored* is a 400 — he can read everything and save no body, and
  recovery is another downtime.

  So the program insists on the order the procedure already keeps. The playbook's
  *Getting back* is `--disarm` and then `--unseal`, two commands in that order for
  exactly this reason; what was missing was anything that made the order true
  rather than remembered.

  Only the write is refused. `--dry-run --unseal` is left alone deliberately: it
  writes nothing, and a rehearsal that shows the flag still up is the cheapest
  possible moment to find that out."
  [username]
  (throw (ex-info (str "users.seal_prose is 1 for " username ", and unsealing while it is"
                       " would leave the flag set over a database of plaintext — which is"
                       " the state --arm refuses to create, arrived at from the other side."
                       " The server would then refuse every body he saved, with a 400, while"
                       " letting him read all of them; getting back out of that is another"
                       " downtime. Run --disarm first and --unseal second: the playbook's"
                       " *Getting back* is two commands in that order for this reason.")
                  {})))

(defn- set-flag!
  "`users.seal_prose`, for one user and nobody else. Answers whether it moved.

  A compare-and-set like every other write here, so that *already armed* and
  *armed just now* are different answers rather than the same number."
  [db user-id on?]
  (let [v (if on? 1 0)]
    (= 1 (parse-long (str/trim (str (one db (str "UPDATE users SET seal_prose = " v
                                                 " WHERE id = " user-id
                                                 " AND seal_prose IS NOT " v
                                                 "; SELECT changes();"))))))))

(defn- print-flags
  "Every user's flag, after the write. It is two lines and it is what turns *and
  nobody else* from a claim into something the operator can see."
  [db]
  (println)
  (println "  users.seal_prose")
  (doseq [line (rows db (str "SELECT '    ' || username || CASE WHEN is_machine_user = 1"
                             " THEN ' (machine)' ELSE '' END || ' — ' || seal_prose"
                             " FROM users ORDER BY id;"))]
    (println line)))

;; ---------------------------------------------------------------------------

(def ^:private cli-spec
  {:user {:desc "Whose prose. Required, and there is no default." :coerce :string}
   :unseal {:desc "Open the prose again, with the same scope. The escape hatch." :coerce :boolean}
   :inverse {:desc "A synonym of --unseal. The playbook spells `--verify --inverse`." :coerce :boolean}
   :verify {:desc "Read-only. Report the invariant and exit non-zero if it is broken." :coerce :boolean}
   :dry-run {:desc "Decide everything, write nothing." :coerce :boolean}
   :arm {:desc "users.seal_prose = 1. The last act of the cutover." :coerce :boolean}
   :disarm {:desc "users.seal_prose = 0. The first act of getting back." :coerce :boolean}
   :verbose {:desc "Name every row written, and the columns. Never a value." :coerce :boolean}
   :help {:coerce :boolean}})

(defn- usage []
  (println "Usage: bb tracker_seal_migrate.clj --user NAME [--unseal] [--verify] [--dry-run]")
  (println "                                   [--arm] [--disarm] [--verbose] DATABASE")
  (println)
  (println "Seal one user's prose in a tracker database — nine description columns and")
  (println "the prose inside the audit log's payloads — or open it again. Direct SQL,")
  (println "never the HTTP API: that path writes audit events of its own, so migrating")
  (println "through it would fill the log it is sealing.")
  (println)
  (println "  --user NAME the user whose rows are sealed, with his machine users.")
  (println "              Required: a default that guessed wrong would seal rows")
  (println "              nobody asked to seal, and that is not reversible without")
  (println "              the key and a second downtime.")
  (println "  --unseal    the inverse pass. Same scope, same counts.")
  (println "  --verify    read-only; reports the invariant both ways and exits 1 if it")
  (println "              is broken — everything of his that must be sealed is,")
  (println "              nothing of anybody else's is, and nothing at all in the")
  (println "              tables that stay clear. With --unseal (or --inverse),")
  (println "              asserts the inverse: no envelope anywhere.")
  (println "  --dry-run   decide everything and write nothing.")
  (println "  --arm       set users.seal_prose = 1 for him and nobody else. Refuses")
  (println "              while anything of his is still unsealed: a flag armed over")
  (println "              an unfinished pass turns every remaining plaintext row into")
  (println "              a row that cannot be saved. Run it last.")
  (println "  --disarm    set it back to 0, which is the first act of getting back.")
  (println "              --unseal is refused while the flag is up, for the reason")
  (println "              --arm is refused over an unfinished pass: it is the same")
  (println "              unusable state reached from the other side.")
  (println "  --verbose   one line per row written — table, id, columns. Never a value.")
  (println)
  (println "No other user's rows are read or written, in any mode, and neither is")
  (println "anything in messages or mottos — they stay clear permanently, and are only")
  (println "counted. Blank values are never touched. Nothing but prose is written.")
  (println)
  (println "The key comes from TRACKER_SEAL_KEY, TRACKER_SEAL_KEY_FILE, or")
  (println (str "  " seal/key-file " — and unlike every other client here,"))
  (println "this refuses to run without one rather than passing everything through.")
  (println)
  (println "Back the database up first, and open the backup. This rewrites in place."))

(defn- print-header
  [{:keys [mode direction db source k user journal strays foreign clear flag]}]
  (println)
  (println (str "tracker seal walk — "
                (case mode
                  :verify (str "verify, " (name direction) " direction")
                  :dry-run (str "dry run, " (name direction))
                  :arm "arm, once the verify is green"
                  :disarm "disarm"
                  (name direction))))
  (println (format "  %-10s %s" "database" (.getAbsolutePath (java.io.File. ^String db))))
  (println (format "  %-10s %s   fingerprint %s" "key" source (seal/fingerprint k)))
  (println (format "  %-10s %s (id %s)%s" "user" (:username user) (:id user)
                   (if (seq (:machine-ids user))
                     (str ", with " (plural (count (:machine-ids user)) "machine user")
                          " acting for him (" (str/join ", " (:machine-ids user)) ")")
                     "")))
  (println (format "  %-10s %s" "flag"
                   (case flag
                     :armed (str "users.seal_prose is 1 for " (:username user) " — armed")
                     :clear (str "users.seal_prose is 0 for " (:username user) " — not armed")
                     :absent (str "no users.seal_prose column here; migration"
                                  " 074-add-seal-prose has not run against this file"))))
  (println (format "  %-10s %s" "journal" journal))
  (when foreign
    (println (format "  %-10s %s belonging to other users, and not read" "elsewhere"
                     (plural (reduce + (map :rows foreign)) "row"))))
  ;; Its own line beside `elsewhere`, and phrased the same way, because it is the
  ;; same kind of answer: a count of rows nothing here read, standing for the half
  ;; of the invariant the walk cannot see from inside itself.
  (when (seq clear)
    (println (format "  %-10s %s in %s that must hold no envelope, and not read" "clear"
                     (plural (reduce + (map :rows clear)) "row")
                     (plural (count clear) "table"))))
  ;; **A sidecar with bytes in it is state the `.db` alone does not hold** — see
  ;; `sidecars` for why the length and not the filename is the question. By the
  ;; time this prints, a journal is already gone: `check-database!` opened the
  ;; file, which rolls it back, and that is the repair. What is left to do is say
  ;; so, because the procedure's next step is to copy the file somewhere, and the
  ;; operator has to know that the run which repaired it is not the run whose
  ;; output they should trust.
  (when (seq strays)
    (println (format "  %-10s %s" "NOTE"
                     (str "a " (str/join " and a " strays)
                          " sat beside this database with bytes in it:")))
    (when (some #{"-journal"} strays)
      (println "             a -journal holds the pre-images of a write that did not finish, so")
      (println "             the database file alone is either torn or not what was committed.")
      (println "             Opening it has now rolled that back, which is the repair."))
    (when (some #{"-wal"} strays)
      (println "             a -wal holds pages this database has and the .db file alone does")
      (println "             not. A pass folds them in before it finishes; a read-only mode")
      (println "             leaves them exactly where they are."))
    (println "             Never copy the .db anywhere while one of those is there. This run")
    (println "             therefore exits non-zero: run it again, and copy nothing until it")
    (println "             answers 0 with no note here.")))

(defn- run-walk
  "Every walked table, in order, with the totals merged. Numbers add; the lists —
  violations, moved — concatenate."
  [ctx]
  (let [by-table (into {} (for [t walked] [t (walk-table ctx t)]))]
    {:by-table by-table
     :total (apply merge-with (fn [a b] (if (number? a) (+ a b) (into a b))) (vals by-table))}))

(defn- foreign-violations [db ids foreign]
  (vec (for [{:keys [table sealed]} foreign
             :when (pos? sealed)
             id (foreign-sealed-ids db ids table)]
         {:table table :id id :column (first (value-columns table)) :why :foreign-sealed})))

(defn- clear-violations [db clear]
  (vec (for [{:keys [sealed] :as t} clear
             :when (pos? sealed)
             row (clear-sealed-rows db t)]
         row)))

(defn- parse!
  "The command line, refused rather than interpreted. `{:opts … :db …}`.

  ## Why this is a function and not a call to `parse-args`

  `babashka.cli` is permissive by default: an option it does not recognise is
  parsed into the map under its own misspelled key and nothing anywhere says so.
  Every **mode** here is an option, so an unrecognised one selects no mode — and
  the mode that nothing selects is the bare pass, which is the one thing in this
  program that cannot be undone without the key and a second downtime.

  That inverted the whole character of the program. A missing `--user` is
  refused, a machine user's name is refused, a missing key is refused, two modes
  at once is refused, `--arm --unseal` is refused: **every deliberate mistake was
  caught, and only a typo got through — into the irreversible one.** `--dryrun`,
  `--dry_run`, `-n` and `--verfiy` each sealed a whole database at the step whose
  entire purpose is to decide everything and write nothing.

  So: three refusals, and each of them is the same rule said about a different
  way of being unrecognised.

  1. **An option this program does not have.** `:restrict` is `babashka.cli`'s
     own word for that, and it resolves aliases first, so `-h` still means
     `--help`.
  2. **A mode given a value that reads as false.** `:restrict` does not catch
     this one, and it is the same fall-through by another spelling: `--verify
     false`, `--verify=false` and `--no-verify` all parse cleanly, all leave the
     mode unselected, and all run the pass. Every flag here is a switch — it is
     given or it is not — so a `false` in one is a typing that did not mean what
     it said, and guessing which half of it was meant is not this program's
     business.
  3. **A second database.** One was operated on and the rest dropped in silence,
     which looks exactly like a run that did all of them.

  Nothing here loads a key or opens a file, and that is deliberate: an argument
  is wrong before either of those is anybody's business."
  [argv]
  (let [{:keys [opts args]}
        (try (cli/parse-args argv {:spec cli-spec :aliases {:h :help} :restrict true})
             (catch Exception e
               (if-not (= :restrict (:cause (ex-data e)))
                 (throw e)
                 (throw (ex-info (str (ex-message e) ". The flags this program has are "
                                      (str/join ", " (map #(str "--" (name %)) (keys cli-spec)))
                                      ". One it does not know selects no mode, and the mode"
                                      " nothing selects is the pass — which writes, and is not"
                                      " reversible without the key and a second downtime.")
                                 {})))))
        negated (sort (keep (fn [[k v]] (when (false? v) (name k))) opts))]
    (when (seq negated)
      (throw (ex-info (str (str/join " and " (map #(str "--" %) negated))
                           " read as false. Every flag here is a switch: it is given or it is"
                           " not, and there is no third answer to act on. One that parses to"
                           " false selects no mode, and the mode nothing selects is the pass"
                           " — which writes.")
                      {})))
    (when (next args)
      (throw (ex-info (str "one database at a time, and this names " (count args) ": "
                           (str/join ", " args) ". Only the first would have been walked and"
                           " the rest dropped in silence, which reads exactly like a run that"
                           " had done all of them.")
                      {})))
    {:opts opts :db (first args)}))

(defn -main [& args]
  (try
    (let [{:keys [opts db]} (parse! args)
          direction (if (or (:unseal opts) (:inverse opts)) :unseal :seal)
          chosen (filterv some? [(when (:arm opts) :arm) (when (:disarm opts) :disarm)
                                 (when (:verify opts) :verify) (when (:dry-run opts) :dry-run)])
          mode (or (first chosen) :pass)]
      (when (or (:help opts) (nil? db))
        (usage)
        (System/exit (if (:help opts) 0 2)))
      (when (next chosen)
        (throw (ex-info (str "these are different jobs and only one of them can be this run: "
                             (str/join ", " (map name chosen))) {})))
      (when (and (#{:arm :disarm} mode) (or (:unseal opts) (:inverse opts)))
        (throw (ex-info (str "--" (name mode) " sets a flag and walks nothing, so it has no"
                             " direction. Disarm first, then --unseal; the playbook's"
                             " *Getting back* is two commands for that reason.") {})))
      (check-inventory!)
      ;; **Before the first `sqlite3` invocation of any kind**, because opening the
      ;; database is what rolls a journal back and deletes it — the repair, and the
      ;; reason the answer is gone by the time the header prints. Even `--verify`,
      ;; which is otherwise read-only to the byte, performs that one write.
      (let [strays-before (sidecars db)]
        (check-database! db)
        ;; Asked here rather than at the moment of the write, so that a database
        ;; the server's half of the seal has not reached yet is refused before a
        ;; walk over it rather than after one.
        (when (#{:arm :disarm} mode) (require-flag-column! db))
        (let [k (or (seal/load-key)
                    (throw (ex-info (str "no key, and this is the one client that will not run"
                                         " without one: a pass with no key walks the whole"
                                         " database, writes nothing, and reports success") {})))
              source (seal/key-source)
              user (resolve-user! db (:user opts))
              ids (:ids user)
              flag (flag-state db (:id user))
              journal (str/trim (str (one db "PRAGMA journal_mode;")))
              walking? (not= :disarm mode)
              foreign (when walking? (vec (foreign-audit db ids)))
              clear (when walking? (clear-audit db))]
          ;; **Before the header and before the walk**, like every other refusal here:
          ;; a run that should not happen should not start by printing as though it
          ;; were happening.
          (when (and (= :pass mode) (= :unseal direction) (= :armed flag))
            (refuse-unseal-while-armed! (:username user)))
          (print-header {:mode mode :direction direction :db db :source source :k k :user user
                         :journal journal :strays strays-before :foreign foreign :clear clear
                         :flag flag})
          (when (= :disarm mode)
            (let [moved? (set-flag! db (:id user) false)]
              (println)
              (println (str "  " (if moved?
                                   (str "users.seal_prose is now 0 for " (:username user) ".")
                                   (str (:username user) " was not armed; nothing to do."))))
              (println "  The server no longer requires his writes to be sealed — and, in the")
              (println "  other direction, now refuses one that carries an envelope. Unseal next.")
              (print-flags db)
              (when (checkpoint! db)
                (println)
                (println "  WAL checkpointed into the database file."))
              (println)
              ;; Its own exit, and the same rule as the walking modes': a sidecar
              ;; with bytes in it before or after means the file is not one to
              ;; copy, whatever this run did to the flag.
              (System/exit (if (seq (concat strays-before (sidecars db))) 1 0))))
          (when (:verbose opts) (println))
          (let [{:keys [by-table total]} (run-walk {:db db :direction direction
                                                    :mode (if (= :arm mode) :verify mode)
                                                    :k k :ids ids :verbose? (:verbose opts)})
                elsewhere (foreign-violations db ids foreign)
                in-the-clear (clear-violations db clear)
                violations (-> (vec (:violations total)) (into elsewhere) (into in-the-clear))
                moved (:moved total)
                unopenable (get total :unopenable 0)
                odd (get total :odd 0)
                nested (get total :nested 0)
                unwalked (get total :unwalked 0)
                ;; What stops the pass from claiming to be finished. Every one of
                ;; them is a value that should have ended sealed, or ended in the
                ;; clear, and did not — which is exactly what nobody would notice.
                ;; A sidecar with bytes in it is unfinished in the most literal
                ;; sense, and the one state whose danger is in what the operator
                ;; does next. It counts whether or not this run repaired it: the
                ;; operator must be made to run again rather than proceed to
                ;; *push* on the strength of the run that did the repairing.
                ;;
                ;; **The state this run *leaves* is asked for after the
                ;; checkpoint, not here.** A pass over a WAL database has its own
                ;; freshly written pages in the `-wal` at this moment, and asking
                ;; now would have every WAL pass report the work it had just done
                ;; as something left behind — and exit 1 over it.
                unfinished (+ unopenable odd nested unwalked (count moved) (count elsewhere)
                              (count in-the-clear) (count strays-before))]
            (print-counts (if (= :arm mode) :verify mode) direction
                          (into {} (for [[t c] by-table]
                                     [t (dissoc c :violations :moved :rows)])))
            (print-alarms total elsewhere in-the-clear)
            (print-violations violations)
            (when (seq moved)
              (println)
              (println (str "  " (plural (count moved) "row") " changed underneath this pass"
                            " and were left alone:"))
              (doseq [{:keys [table id]} (take 20 moved)]
                (println (format "    %-18s id %s" (name table) id)))
              (println "    Nothing should be writing during a cutover, and a row that changed")
              (println "    hands is not this user's to seal. Re-run when writes have stopped."))
            (println)
            (case mode
              :verify (println (str "  " (if (seq violations)
                                           (str (plural (count violations) "violation")
                                                " — the invariant does not hold.")
                                           "The invariant holds, in both directions.")))
              :dry-run (println (str "  Dry run: " (get total :changed 0) " values in "
                                     (get total :rows 0) " rows would be "
                                     (if (= :seal direction) "sealed" "unsealed") ". Nothing written."))
              :arm (if (or (seq violations) (seq strays-before))
                     (do (println (str "  Refusing to arm: "
                                       (if (seq violations)
                                         (str (plural (count violations) "violation")
                                              " against the seal invariant.")
                                         "an unfinished write sat beside this database.")))
                         (println "  A flag armed over an unfinished pass turns every remaining plaintext")
                         (println "  row into a row that cannot be saved. Seal, verify, then arm."))
                     (let [moved? (set-flag! db (:id user) true)]
                       (println (str "  " (if moved?
                                            (str "users.seal_prose is now 1 for " (:username user)
                                                 " (id " (:id user) ") and nobody else.")
                                            (str (:username user) " was armed already; nothing to do."))))
                       (println "  The server now refuses any write that would introduce new plaintext")
                       (println "  prose into his rows — and refuses a keyed client sealing anybody")
                       (println "  else's.")
                       (print-flags db)))
              (println (str "  " (get total :changed 0) " values in " (get total :rows 0) " rows "
                            (if (= :seal direction) "sealed" "unsealed") "."
                            ;; **Only when there is genuinely nothing left.**
                            (when (and (zero? (get total :changed 0)) (zero? unfinished))
                              " Nothing to do — this database is already where it should be."))))
            ;; **Every mode that writes a row folds its own WAL back in.** A WAL
            ;; database keeps the newest pages in a sidecar, and the procedure's
            ;; next step is to copy the `.db` — so a pass, and the one-row write
            ;; `--arm` makes, would otherwise be left behind in a file nobody
            ;; copies. `--dry-run` and `--verify` are excluded because they write
            ;; nothing, and that is the whole of what they promise.
            (when (and (#{:pass :arm} mode) (checkpoint! db))
              (println "  WAL checkpointed into the database file."))
            (when (pos? unopenable)
              (println)
              (println (str "  " (plural unopenable "value") " carry the prefix and do not open with this key."))
              (println "  They were left exactly as they are. Either they were sealed under another")
              (println "  key, or they are damaged — and neither is a thing a pass can fix as it goes.")
              (println "  Check the fingerprint above against the one in the browser's ⚙ panel."))
            (when (pos? odd)
              (println)
              (println (str "  " (plural odd "value") " are not text: a BLOB in a prose column,"))
              (println "  or an event payload that is not JSON. They were left alone — sealing one")
              (println "  would mean deciding it is text, which is a judgement about somebody")
              (println "  else's data that a counting pass has no business making. Look at them."))
            (when (pos? nested)
              (println)
              (println (str "  " (plural nested "value") " are an envelope inside an envelope."))
              (println "  No correct client writes one; one that sealed a ciphertext it had echoed")
              (println "  did. A reader meets `enc:v1:…` where the prose should be.")
              (println (if (= :unseal direction)
                         "  One layer came off each of them here; run this again until it is 0."
                         "  `--unseal` takes one layer off per run, and `--verify --inverse` says when
  none is left.")))
            (when (pos? unwalked)
              (println)
              (println (str "  " (plural unwalked "event payload") " hold a description somewhere"))
              (println "  `et.tr.seal-rules/prose-paths` does not look — a sixth shape, which means")
              (println "  prose in the clear that this pass walked past. Do not seal by hand: add")
              (println "  the shape there, where the server, the browser and this pass all read it,")
              (println "  and run again.")) 
            (when (seq elsewhere)
              (println)
              (println (str "  " (plural (count elsewhere) "row") " belonging to another user carry"))
              (println "  the envelope prefix. Nothing here sealed them and nothing here will touch")
              (println "  them: they are outside the scope in both directions. A keyed client wrote")
              (println "  them, which the server's guard refuses for an unarmed user — so find out")
              (println "  which client, and unseal them with the key that sealed them."))
            (when (seq in-the-clear)
              (println)
              (println (str "  " (plural (count in-the-clear) "row")
                            " in a table that stays clear carry the"))
              (println "  envelope prefix. `messages` and `mottos` are not in the inventory and that")
              (println "  is a decision, not a deferral: message bodies are written by three")
              (println "  producers that hold no key, and a motto's description is a second name")
              (println "  rather than prose. Sealed, a motto stops answering the one search in")
              (println "  tracker that reads a body, and a message body stops opening for anybody")
              (println "  at all. Nothing here sealed them and nothing here will touch them — find")
              (println "  the client that did, and unseal them with the key that sealed them."))
            ;; **After the pass, and after the checkpoint.** Nearly unreachable:
            ;; every mode opens the database, which rolls back and deletes a
            ;; journal, and a pass folds a WAL in and truncates it. What could
            ;; still leave bytes here is something *else* writing while this ran —
            ;; and, for a `-wal`, a reader holding the WAL open, which is what
            ;; stops a TRUNCATE checkpoint completing. Either way the answer is the
            ;; same: the file is not safe to copy.
            (let [strays-after (sidecars db)]
              (when (seq strays-after)
                (println)
                (println (str "  A " (str/join " and a " strays-after)
                              " is still beside this database, with bytes in it."))
                (println "  Do not copy or push the .db while that is true: the file alone is")
                (println "  either torn or missing pages this database has. Re-run this pass in")
                (println "  place — opening the database rolls a journal back and a pass folds a")
                (println "  WAL in — and copy it only once this line is gone. A -wal that survives")
                (println "  a checkpoint means something else is holding it open."))
              (println)
              ;; **Non-zero for anything left in a state the pass cannot call
              ;; finished** — `unfinished`, above, which is where the list lives
              ;; rather than spelled twice, plus whatever this run has left beside
              ;; the file.
              (System/exit (if (or (seq violations) (pos? (+ unfinished (count strays-after))))
                             1 0)))))))
    (catch Exception e
      (binding [*out* *err*] (println "tracker-seal-migrate:" (ex-message e)))
      (System/exit 2))))

(when (= *file* (System/getProperty "babashka.file"))
  (apply -main *command-line-args*))
