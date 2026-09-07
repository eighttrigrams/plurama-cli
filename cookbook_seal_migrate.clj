#!/usr/bin/env bb

(ns cookbook-seal-migrate
  "The migration pass: seal a cookbook database in place, or open one again.

  Cookbook's prose is end-to-end encrypted in the clients, so everything written
  since the seal landed is sealed and everything written before it is not. This
  is what closes that gap — one walk over the thirteen prose columns, sealing
  every value that is not sealed already.

  ## Where it runs, and why it cannot run anywhere else

  The key is never on fly. That is the whole design, and its consequence is that
  **the sealing pass cannot run on the server**: it runs on the owner's laptop
  against a pulled copy of `/app/data/cookbook.db`, and the sealed file goes back
  up. A downtime cutover, once — stop writes, pull, seal, verify, push, start.

  ## Direct SQL, never the HTTP API. This is law.

  Cookbook's write path is not a place to put encoding changes through. It
  compares prose values to decide no-op versus version bump, writes a
  `recipe_history` row for every version it makes, flips `has_human_edit`, files
  a proposal for a machine write and drops an entry in the owner's inbox. A pass
  driven through `PUT /api/recipes/:id` would therefore rewrite the version
  ladder in the act of protecting it, and `caution` — which lines are the owner's
  — reads that ladder. So this speaks to the file.

  ## What it will not touch

  **A published Recipe's whole trail**: its `recipes` row, every
  `recipe_history` row behind it, every `recipe_proposals` row against it.
  Publishing is a one-way unseal — a visitor has no key, must never have one, and
  there is no unpublish — so a published Recipe's prose is deliberately in the
  clear and sealing it again would put `enc:v1:…` on a public page. Since step 6
  the server enforces that in both directions, which is what makes skipping them
  consistent rather than a special case: a published Recipe cannot be holding a
  sealed value for this to have missed.

  **Scopes are always walked, including the Scopes a published Recipe is filed
  under.** A Scope's description is never served to a visitor at any `?detail`,
  so it stays the owner's however its Recipes are published. Thirteen columns
  here, twelve in the server's publish guard, and the difference is deliberate.

  **Blanks.** `nil` stays `nil`, `\"\"` stays `\"\"`, whitespace-only stays as it is —
  `cookbook-seal/blank-value?` is the one place that rule is spelled, and this
  counts by it so the audit cannot disagree with what was written. Ciphertext is
  never NULL and never empty, so sealing a blank would turn every historical
  *\"not recorded\"* into *\"recorded, and empty\"*, and nothing could tell them apart
  afterwards.

  **Everything that is not prose.** No timestamp, version, flag, id or title is
  read into an UPDATE, let alone written.

  ## The trap

  **`seal` is called with no `stored`.** Its echo rule answers *does this column
  already say what I am about to write?* and hands back the stored value when it
  does — which is what keeps an agent's idempotent re-`PUT` from costing a
  version. A walker that passed the plaintext it just read in as `stored` would be
  told, correctly, that nothing had changed, and would seal nothing at all while
  reporting a clean pass. The four-argument arity is the migration arity; both
  suites assert that it seals.

  ## Idempotent, resumable, reversible

  A value that already carries the prefix is left alone and counted as such, so a
  second run writes nothing and says so. **One row is one statement is one
  transaction**, so a kill mid-pass leaves some rows sealed and some not, which is
  a state every client already handles — `unseal` is prefix-driven, mixed state is
  legal permanently — and the next run picks up where this one stopped.

  Each write is a compare-and-set: the `WHERE` clause carries the values this pass
  read, so a row that changed underneath it is skipped and reported rather than
  clobbered. Nothing should be writing during a cutover; this is what says so
  instead of hoping.

  `--unseal` is the exact inverse, with the same skips. It is written and tested
  now rather than when it is needed, because an escape hatch nobody has opened is
  not one.

  ## Why it refuses to run without a key

  Every other client in this system treats *no key* as *sealing off*, which is
  cookbook before any of this existed. Here that would mean a pass that walks the
  whole shelf, writes nothing, and reports success — the one failure that would
  be discovered by someone reading a Recipe that should have been sealed and was
  not. So this refuses, and a malformed key throws where it is loaded.

  ## sqlite3, and hex

  babashka has no JDBC, so the file is reached through the `sqlite3` binary, which
  is on every machine that could plausibly be holding a cookbook database. Values
  cross that boundary as **hex**, in both directions: prose is multi-line, holds
  quotes and holds unicode, and the one way to be certain no value is mangled by
  quoting is never to quote one. `typeof()` rides along, because `hex(NULL)` and
  `hex('')` are the same empty string and those two mean different things here."
  (:require [babashka.cli :as cli]
            [babashka.process :as p]
            [clojure.string :as str]
            [cookbook-seal :as seal]))

;; ---------------------------------------------------------------------------
;; The inventory, and the little this file adds to it.

(def ^:private row-shape
  "How to reach a row of each of the inventory's tables — **not which columns hold
  prose**, which is `cookbook-seal/sealed-columns` and is a cross-client contract
  pinned to `seal-vectors.edn`. A fourteenth copy of that list is exactly what
  three suites exist to prevent.

  What is here is the three things the inventory cannot say: which columns name
  a row, how to ask whether it belongs to a published Recipe, and how to ask that
  same question again *inside the write*.

  `recipe_history` has no id of its own — its key is `(recipe_id, version)`, the
  same pair `GET /api/recipes/:id/sealed` uses to name one. The published question
  is a correlated subquery for the two tables that hang off a Recipe, and it
  answers -1 rather than NULL for a row whose Recipe is gone — a definite string
  in the output rather than one whose rendering `.nullvalue` can change under it.

  **`:still-unpublished` is the same question as a `WHERE` conjunct, and it is
  there because `published` is read once for a whole table and then acted on row
  by row.** Publishing a Recipe whose prose is still plaintext — which is every
  Recipe before the migration — changes no prose value, so the compare-and-set on
  the values matched and the pass sealed a Recipe that had gone public underneath
  it. Found in review, staged deterministically. `IS NOT 1` rather than `= 0`, so
  an orphan's NULL still passes and orphans go on being walked."
  {:recipes          {:pk [:id]
                      :published "t.published"
                      :still-unpublished "published IS NOT 1"
                      :label (fn [{:keys [id]}] (str "recipe " id))}
   :recipe_history   {:pk [:recipe_id :version]
                      :published "COALESCE((SELECT published FROM recipes r WHERE r.id = t.recipe_id), -1)"
                      :still-unpublished (str "(SELECT published FROM recipes r "
                                              "WHERE r.id = recipe_history.recipe_id) IS NOT 1")
                      :label (fn [{:keys [recipe_id version]}]
                               (str "recipe " recipe_id " v" version))}
   :recipe_proposals {:pk [:id]
                      :extra [:recipe_id]
                      :published "COALESCE((SELECT published FROM recipes r WHERE r.id = t.recipe_id), -1)"
                      :still-unpublished (str "(SELECT published FROM recipes r "
                                              "WHERE r.id = recipe_proposals.recipe_id) IS NOT 1")
                      :label (fn [{:keys [id recipe_id]}]
                               (str "proposal " id " of recipe " recipe_id))}
   ;; A Scope has no latch to race: the projection that keeps a Scope's prose from
   ;; a visitor is not the publish latch, and a Scope is walked whatever its
   ;; Recipes are.
   :scopes           {:pk [:id]
                      :published "0"
                      :label (fn [{:keys [id]}] (str "scope " id))}})

(def ^:private tables
  "In a fixed order, so two runs read alike and a resumed pass is easy to follow."
  [:recipes :recipe_history :recipe_proposals :scopes])

(defn- check-inventory!
  "A table added to the inventory and forgotten here would be walked by nobody and
  reported by nothing. So it is a refusal — and, since review, a refusal in the
  same shape as every other one this file makes: exit 2 and one line, from
  `-main`'s catch, rather than a stack trace out of namespace load.

  What is *not* here is columns, and does not need to be: they are read out of
  `seal/sealed-columns` at call time, so a new one flows into the SELECT, the
  UPDATE and the AAD untouched by hand. Only a table needs classifying."
  []
  (when-not (= (set tables) (set (keys seal/sealed-columns)) (set (keys row-shape)))
    (throw (ex-info (str "the walk and the inventory disagree about which tables hold prose: "
                         (pr-str (sort (map name tables))) " vs "
                         (pr-str (sort (map name (keys seal/sealed-columns))))) {}))))

;; ---------------------------------------------------------------------------
;; sqlite3.

(def ^:private preamble
  "Every invocation says how it wants its output before it asks for any. The
  shell reads `~/.sqliterc` on the machine this runs on, and a person who has
  ever typed `.mode box` into it would otherwise get a pass that reads a drawing
  of a table as a table.

  **`.timeout` is what makes the compare-and-set reachable as documented.**
  Without it a concurrent writer does not lose the race, it aborts the pass:
  `SQLITE_BUSY` fires before the `WHERE` is ever evaluated, and six of eight
  attempts died that way in review. The abort is safe — it leaves the legal,
  resumable half-sealed state everything here is built around — but *reported as
  `moved`* is the better answer and is what the report claims, and five seconds
  of patience is the difference. A cutover should have stopped writes anyway.

  It is the dot command and not `PRAGMA busy_timeout = 5000`, which **prints its
  new value** — one extra line at the head of every result, which a parser reading
  by position takes for a row. The suite caught it inside a minute and it is worth
  the sentence: everything in this preamble has to be output-free."
  ".mode list\n.separator |\n.headers off\n.timeout 5000\n")

(defn- sqlite!
  "One `sqlite3` invocation, SQL on stdin. On stdin rather than in argv because a
  Recipe's body is arbitrarily long and hex doubles it, and `ARG_MAX` is a limit
  somebody else's operating system chooses."
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

;; ---------------------------------------------------------------------------
;; Reading.

(defn- select-sql [table]
  (let [{:keys [pk extra published]} (row-shape table)
        columns (get seal/sealed-columns table)]
    (str "SELECT "
         (str/join ", " (concat (map name (concat pk extra))
                                [published]
                                (for [c columns]
                                  (str "typeof(t." (name c) ") || ':' || hex(t." (name c) ")"))))
         " FROM " (name table) " t ORDER BY " (str/join ", " (map name pk)) ";")))

(defn- read-table
  "Every row of one table, as `{:key {…} :published? bool :cells {column → cell}}`.

  Read in one go and written row by row. The gap between the two is what the
  compare-and-set write is for."
  [db table]
  (let [{:keys [pk extra]} (row-shape table)
        ids (concat pk extra)
        columns (get seal/sealed-columns table)]
    (for [line (rows db (select-sql table))
          :let [fields (str/split line #"\|" -1)
                [id-fields [published & cells]] (split-at (count ids) fields)]]
      {:key (zipmap ids (map parse-long id-fields))
       ;; **`-1` is neither 0 nor 1: it is a row whose Recipe is not in the
       ;; database at all.** The dev shelf holds three — proposals against
       ;; Recipes hard-deleted before tombstones existed — and SQLite does not
       ;; enforce the foreign key that would have stopped them.
       ;;
       ;; They are walked as unpublished, and that is the safe reading in both
       ;; directions: ids come from AUTOINCREMENT and are never reused, so an
       ;; orphan cannot rejoin a live Recipe and be published by accident, while
       ;; leaving it alone would leave prose of the owner's sitting in the file in
       ;; the clear — which is the one thing this pass exists to end. Counted
       ;; separately all the same, because *walked as unpublished* is a judgement
       ;; and a judgement should be visible.
       :published? (= "1" published)
       :orphan? (= "-1" published)
       :cells (zipmap columns (map cell cells))})))

;; ---------------------------------------------------------------------------
;; The decision, one value at a time. Pure, and the only thing here worth a test
;; that does not need a database.

(defn- inside
  "What one envelope actually holds: `:unopenable`, `:nested`, or `:prose`.

  `unseal` hands back a value it cannot read exactly as it is — rule 3, so that one
  unreadable column shows as `enc:v1:…` beside everything that reads instead of
  taking a response down — so *unchanged* is how *it did not open* is said.

  **`:nested` is the third answer and it was missing.** A value that opens into
  another envelope is `enc(enc(prose))`: a reader sees `enc:v1:…` where the body
  should be, and every check in this system was blind to it, because opening it
  once succeeds. It is what a client that sealed an echoed ciphertext produced —
  fixed in `cookbook-seal/seal` this round, and detectable here now, because a
  corruption nobody can see is one nobody can be told about."
  [k table column v]
  (let [opened (seal/unseal k table column v)]
    (cond
      (= opened v) :unopenable
      (seal/sealed? opened) :nested
      :else :prose)))

(defn decide
  "What this pass must do with one value: `[bucket new-value]`, where `new-value`
  is `nil` for everything it is leaving alone.

  The buckets are the audit. Every value of every prose column lands in exactly
  one of them and the counts are printed, so a pass that did less than it should
  have shows up as a number rather than as a Recipe somebody reads six months
  later.

  `:blank`, `:published` and `:already` are the three ways of doing nothing on
  purpose; `:unopenable` is a value carrying the prefix that this key does not
  open, which is the one thing here nobody can fix in passing — it is reported and
  left exactly as it is. `:nested` is an envelope inside an envelope, which no
  correct client can produce and which this pass will not try to unwrap. `:odd` is
  a prose column holding something that is not text at all."
  [direction k table column {:keys [published?]} {:keys [type value]}]
  (cond
    ;; Blank first, in both senses of blank: a NULL `reason` inside a published
    ;; Recipe is a blank, not a published value, and the counts are read.
    (= :null type) [:blank nil]
    (and (= :text type) (seal/blank-value? value)) [:blank nil]

    ;; Then: a published Recipe is not this pass's business in either direction. A
    ;; sealed value inside one is a violation of an invariant the server enforces,
    ;; so it is worth a line of its own rather than a silent skip — but it is still
    ;; not touched here.
    published? [(if (seal/sealed? value) :published-sealed :published) nil]

    ;; A prose column holding something that is not text. It exists: one
    ;; `recipe_history` row on the dev shelf holds a BLOB of perfectly good UTF-8,
    ;; left by a repair made with SQL rather than through the app. Sealing it would
    ;; mean deciding it is text, which is a judgement about somebody else's data
    ;; that a pass counting values has no business making. Reported instead.
    (not= :text type) [:odd nil]

    (= :seal direction)
    (if (seal/sealed? value)
      [(case (inside k table column value)
         :unopenable :unopenable
         :nested :nested
         :prose :already)
       nil]
      ;; No `stored`. The trap in the ns docstring, and in `seal`'s.
      [:changed (seal/seal k table column value)])

    :else
    (if-not (seal/sealed? value)
      [:already nil]
      ;; **One layer, deliberately** — and counted as `:nested` when a layer is
      ;; all it was. Unwrapping recursively would be a pass inventing how deep
      ;; somebody else's mistake goes; writing the inner envelope and saying so
      ;; makes progress, exits non-zero, and finishes on the next run.
      (let [plain (seal/unseal k table column value)]
        (cond
          (= plain value) [:unopenable nil]
          (seal/sealed? plain) [:nested plain]
          :else [:changed plain])))))

(defn verdict
  "The same walk, deciding nothing and asserting instead. `[bucket violation?]`.

  Both directions of the invariant, which is what makes it worth running twice:
  in the seal direction every non-blank prose value of every unpublished Recipe
  must be an envelope this key opens, and no envelope may be anywhere in a
  published Recipe's trail; in the unseal direction no envelope may be anywhere at
  all."
  [direction k table column {:keys [published?]} {:keys [type value]}]
  (cond
    (= :null type) [:null false]
    (and (= :text type) (seal/blank-value? value)) [:blank false]

    published? (if (seal/sealed? value) [:published-sealed true] [:published false])

    ;; **A violation in the seal direction, and that is the point of the bucket.**
    ;; A BLOB holding readable prose is prose in the clear; `decide` will not seal
    ;; it, so a verify that called it merely odd would report a holding invariant
    ;; over a line anybody with the file can read.
    (not= :text type) [:odd (= :seal direction)]

    (= :unseal direction)
    (if (seal/sealed? value) [:sealed true] [:plain false])

    (not (seal/sealed? value)) [:plain true]

    ;; **The three things an envelope can turn out to be.** Only one of them is
    ;; the invariant holding. `:nested` is here because it was the gap: a value
    ;; that opens was called sealed and asked nothing further, so a database
    ;; corrupted by a double seal verified clean and printed *The invariant
    ;; holds.* — over prose a reader would meet as `enc:v1:…`.
    :else (case (inside k table column value)
            :prose [:sealed false]
            :nested [:nested true]
            :unopenable [:unopenable true])))

;; ---------------------------------------------------------------------------
;; Writing.

(defn- update-sql
  "One row, one statement, one transaction — which is the whole of the
  resumability story.

  **The `WHERE` re-asks everything the decision rested on**: the key, the values
  this pass read, and — for the three tables that hang off a Recipe — that the
  Recipe is *still* unpublished. A row that moved underneath the pass is then not
  written over, and `changes()` is how that is noticed.

  The published conjunct is the one that was missing. `published` is read once for
  a whole table and acted on row by row, and publishing a plaintext Recipe changes
  no prose value, so the value comparison alone matched and the pass sealed a
  Recipe that had gone public in between. There is nothing to seal in a published
  trail, ever, so a `WHERE` that says so costs nothing and closes the window."
  [table {:keys [key cells]} changed]
  (let [{:keys [pk still-unpublished]} (row-shape table)]
    (str "UPDATE " (name table) " SET "
         (str/join ", " (for [[c v] changed] (str (name c) " = " (literal v))))
         " WHERE " (str/join " AND " (for [p pk] (str (name p) " = " (get key p))))
         " AND " (str/join " AND " (for [[c _] changed]
                                     (str (name c) " IS " (literal (:value (get cells c))))))
         (when still-unpublished (str " AND " still-unpublished))
         "; SELECT changes();")))

;; ---------------------------------------------------------------------------
;; The pass.

(defn- tally [m bucket] (update m bucket (fnil inc 0)))

(defn- walk-table
  [{:keys [db direction mode k verbose?]} table]
  (let [verify? (= :verify mode)
        label (:label (row-shape table))]
    (reduce
     (fn [acc row]
       (let [;; **Asked once per value.** `verdict` used to be called a second time
             ;; inside the tally, to read the violation flag off it — two
             ;; decryptions of every value in the database, and two answers that
             ;; could in principle differ.
             results (for [c (get seal/sealed-columns table)]
                       [c ((if verify? verdict decide)
                           direction k table c row (get (:cells row) c))])
             acc (reduce (fn [a [c [bucket flag]]]
                           (cond-> (tally a bucket)
                             (and verify? flag)
                             (update :violations (fnil conj [])
                                     {:table table :row (label (:key row))
                                      :column c :why bucket})))
                         acc results)
             acc (cond-> acc (:orphan? row) (update :orphans (fnil conj #{}) (label (:key row))))
             ;; **Only a pass writes**, and in a pass any bucket that produced a
             ;; value is a write: `:changed` almost always, and `:nested` in the
             ;; unseal direction, where one layer came off a value that is still an
             ;; envelope underneath. `verdict`'s second element is a *flag* and not
             ;; a value, and reading it as one put a boolean into an UPDATE for
             ;; exactly as long as it took the suite to say so.
             changed (when-not verify?
                       (into {} (for [[c [_ v]] results :when (some? v)] [c v])))]
         (cond
           (empty? changed) acc
           (= :dry-run mode) (update acc :rows (fnil inc 0))
           :else
           (let [n (parse-long (str/trim (or (one db (update-sql table row changed)) "0")))]
             (when verbose?
               (println (format "  %-16s %-24s %s" (name table) (label (:key row))
                                (str/join " " (map name (keys changed))))))
             (if (= 1 n)
               (update acc :rows (fnil inc 0))
               ;; The compare-and-set found something else there — a value that
               ;; moved, or a Recipe published in between. Counted, named and left:
               ;; a re-run picks up whatever the new state is. The buckets those
               ;; columns were tallied into are given back one by one rather than
               ;; assumed to be `:changed`, since the unseal direction can put a
               ;; write in `:nested`.
               (-> (reduce (fn [a [_ [bucket _]]] (update a bucket dec))
                           acc
                           (filter (fn [[c _]] (contains? changed c)) results))
                   (update :moved (fnil conj [])
                           {:table table :row (label (:key row))})
                   (tally :skipped-moved)))))))
     {}
     (read-table db table))))

;; ---------------------------------------------------------------------------
;; What it prints. The counts are the point: a pass whose output is "done" is a
;; pass nobody can check.

(def ^:private headings
  "Which buckets each mode prints, in order, and what to call them. A bucket with
  no column here would be counted and never seen, so every one `decide` and
  `verdict` can answer appears in exactly one of these lists."
  {[:pass :seal]     [[:changed "sealed"] [:already "already"] [:blank "blank"]
                      [:published "published"] [:published-sealed "PUBLISHED-SEALED"]
                      [:unopenable "unopenable"] [:nested "NESTED"] [:odd "odd"]
                      [:skipped-moved "moved"]]
   [:pass :unseal]   [[:changed "unsealed"] [:already "plain"] [:blank "blank"]
                      [:published "published"] [:published-sealed "PUBLISHED-SEALED"]
                      [:unopenable "unopenable"] [:nested "NESTED"] [:odd "odd"]
                      [:skipped-moved "moved"]]
   [:verify :seal]   [[:sealed "sealed"] [:plain "PLAINTEXT"] [:blank "blank"] [:null "null"]
                      [:published "published"] [:published-sealed "PUBLISHED-SEALED"]
                      [:unopenable "UNOPENABLE"] [:nested "NESTED"] [:odd "odd"]]
   [:verify :unseal] [[:plain "plain"] [:sealed "SEALED"] [:blank "blank"] [:null "null"]
                      [:published "published"] [:published-sealed "PUBLISHED-SEALED"]
                      [:odd "odd"]]})

(defn- print-counts [mode direction by-table]
  (let [cols (get headings [(if (= :verify mode) :verify :pass) direction])
        total (apply merge-with + (vals by-table))
        used (filter (fn [[b _]] (pos? (get total b 0))) cols)
        ;; Only the buckets that answered. A row of zeroes across eight columns
        ;; hides the two numbers that matter.
        used (if (seq used) used (take 2 cols))
        w (fn [[_ label]] (max 8 (count label)))]
    (println)
    (println (apply str (format "  %-18s" "table") (map #(format (str "%" (w %) "s  ") (second %)) used)))
    (doseq [table tables
            :let [counts (get by-table table)]]
      (println (apply str (format "  %-18s" (name table))
                      (map (fn [[b :as c]] (format (str "%" (w c) "s  ")
                                                   (str (get counts b 0)))) used))))
    (println (apply str "  " (apply str (repeat 16 "-")) "  "
                    (map #(str (apply str (repeat (w %) "-")) "  ") used)))
    (println (apply str (format "  %-18s" "total")
                    (map (fn [[b :as c]] (format (str "%" (w c) "s  ") (str (get total b 0)))) used)))))

(defn- print-violations [violations]
  (when (seq violations)
    (println)
    (println (str "  " (count violations) " violation"
                  (when (not= 1 (count violations)) "s") ":"))
    (doseq [{:keys [table row column why]} (take 40 violations)]
      (println (format "    %-16s %-24s %-12s %s" (name table) row (name column)
                       (case why
                         :plain "in the clear on an unpublished Recipe"
                         :sealed "an envelope, where none may remain"
                         :published-sealed "an envelope inside a published Recipe's trail"
                         :unopenable "carries the prefix and does not open with this key"
                         :nested "an envelope inside an envelope — a reader meets enc:v1: for prose"
                         (name why)))))
    (when (> (count violations) 40)
      (println (str "    … and " (- (count violations) 40) " more")))))

;; ---------------------------------------------------------------------------

(defn- check-database!
  "Everything that has to be true before a single value is read, said one at a
  time. `sqlite3` **creates** a database it is pointed at, so a typo in the path
  would otherwise produce an empty file, a clean pass over nothing, and a report
  saying so."
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
        missing (remove present (map name tables))]
    (when (seq missing)
      (throw (ex-info (str "not a cookbook database: no " (str/join ", " missing)) {})))))

(defn- sidecars
  "The journal files sitting beside a database, if any.

  **This is the one way an interrupted pass can become a damaged production
  file**, and it is not the pass's doing — it is what happens next. In
  `journal_mode=delete`, which is what cookbook uses, an interrupted write leaves
  a `-journal` holding the pre-images while the database file itself is already
  modified. The file alone is then either torn or silently different from what the
  pass committed, and the procedure's next step is *push it back*.

  Opening the database repairs it: sqlite3 rolls the journal back and deletes it,
  which is why re-running the pass in place is the recovery. What must never
  happen is a copy taken while the journal is there. So: named on the way in, and
  refused on the way out.

  **`filterv` and not `filter`, and that is not style.** The answer has to be
  *taken* before the first `sqlite3` invocation, not merely asked for: a lazy seq
  realised one line later is realised after the database has been opened, the
  journal rolled back and the file deleted — which is exactly what happened, and
  the note never printed."
  [db]
  (filterv #(.exists (java.io.File. (str db %))) ["-journal" "-wal"]))

(defn- checkpoint!
  "A WAL database keeps the newest pages in a sidecar file. Copying the `.db`
  alone after a pass would leave the sealing behind — so the pass folds it in
  before it says it is done, and says which mode it found."
  [db]
  (when (= "wal" (str/lower-case (str/trim (str (one db "PRAGMA journal_mode;")))))
    (sqlite! db "PRAGMA wal_checkpoint(TRUNCATE);")
    true))

(def ^:private cli-spec
  {:unseal {:desc "Open the prose again, with the same skips. The escape hatch." :coerce :boolean}
   :verify {:desc "Read-only. Report the invariant and exit non-zero if it is broken." :coerce :boolean}
   :dry-run {:desc "Decide everything, write nothing." :coerce :boolean}
   :verbose {:desc "Name every row written, and the columns. Never a value." :coerce :boolean}
   :help {:coerce :boolean}})

(defn- usage []
  (println "Usage: bb cookbook_seal_migrate.clj [--unseal] [--verify] [--dry-run] [--verbose] DATABASE")
  (println)
  (println "Seal cookbook's thirteen prose columns in a database file, or open them again.")
  (println "Direct SQL, never the HTTP API: that path bumps versions and writes history")
  (println "rows, so migrating through it would corrupt the ladder the seal protects.")
  (println)
  (println "  --unseal    the inverse pass. Same skips, same counts.")
  (println "  --verify    read-only; reports the invariant and exits 1 if it is broken.")
  (println "              With --unseal, asserts the inverse: no envelope anywhere.")
  (println "  --dry-run   decide everything and write nothing.")
  (println "  --verbose   one line per row written — table, row, columns. Never a value.")
  (println)
  (println "A published Recipe's whole trail is never touched, in either direction.")
  (println "Blank values are never touched. Nothing but prose columns is read or written.")
  (println)
  (println "The key comes from COOKBOOK_SEAL_KEY, COOKBOOK_SEAL_KEY_FILE, or")
  (println (str "  " seal/key-file " — and unlike every other client here,"))
  (println "this refuses to run without one rather than passing everything through.")
  (println)
  (println "Back the database up first, and open the backup. This rewrites in place."))

(defn -main [& args]
  (let [{:keys [opts args]} (cli/parse-args args {:spec cli-spec :aliases {:h :help}})
        db (first args)
        direction (if (:unseal opts) :unseal :seal)
        mode (cond (:verify opts) :verify (:dry-run opts) :dry-run :else :pass)]
    (when (or (:help opts) (nil? db))
      (usage)
      (System/exit (if (:help opts) 0 2)))
    (try
      (check-inventory!)
      ;; **Before the first `sqlite3` invocation of any kind**, because opening the
      ;; database is what rolls a journal back and deletes it — the repair, and the
      ;; reason the answer is gone by the time the header prints. Even `--verify`,
      ;; which is otherwise read-only to the byte, performs that one write.
      (let [strays-before (sidecars db)]
      (check-database! db)
      (let [k (or (seal/load-key)
                  (throw (ex-info (str "no key, and this is the one client that will not run without"
                                       " one: a pass with no key walks the whole shelf, writes"
                                       " nothing, and reports success") {})))
            source (seal/key-source)]
        (println)
        (println (str "cookbook seal walk — "
                      (case mode :verify "verify" :dry-run "dry run, " "")
                      (when (not= :verify mode) (name direction))
                      (when (= :verify mode) (str ", " (name direction) " direction"))))
        (println (format "  %-10s %s" "database" (.getAbsolutePath (java.io.File. ^String db))))
        (println (format "  %-10s %s   fingerprint %s" "key" source (seal/fingerprint k)))
        (println (format "  %-10s %s" "journal" (str/trim (str (one db "PRAGMA journal_mode;")))))
        ;; **A journal beside the file is a database that has not finished a
        ;; write**, almost always this pass being interrupted. By now it is gone:
        ;; `check-database!` opened the file, which rolls it back — the repair. What
        ;; is left to do is say so, because the procedure's next step is to copy the
        ;; file somewhere, and the operator has to know that the run which repaired
        ;; it is not the run whose output they should trust.
        (when-let [strays (seq strays-before)]
          (println (format "  %-10s %s" "NOTE"
                           (str "a " (str/join " and a " strays) " sat beside this database:")))
          (println "             an unfinished write, whose pre-images the database file alone does")
          (println "             not hold. Opening it has now rolled that back, which is the repair —")
          (println "             but never copy the .db anywhere while one is there. This run")
          (println "             therefore exits non-zero: run it again, and copy nothing until it")
          (println "             answers 0 with no note here."))
        (when (:verbose opts) (println))
        (let [by-table (into {} (for [table tables]
                                  [table (walk-table {:db db :direction direction :mode mode
                                                      :k k :verbose? (:verbose opts)}
                                                     table)]))
              total (apply merge-with (fn [a b] (if (number? a) (+ a b) (into a b))) (vals by-table))
              violations (:violations total)
              moved (:moved total)
              unopenable (get total :unopenable 0)
            odd (get total :odd 0)
            nested (get total :nested 0)
            ;; **An envelope inside a published Recipe's trail.** `--verify` has
            ;; always called this a violation and the server enforces against it in
            ;; both directions; a *pass* printed it in the table and exited 0
            ;; anyway, under a summary line saying the database was where it should
            ;; be. Found in review, against this file's own decision C7: a pass
            ;; that left a value in a state it cannot call finished must not
            ;; answer 0. It is also the state a publish racing the pass produces.
            published-sealed (get total :published-sealed 0)
            ;; What stops the pass from claiming to be finished. Every one of them
            ;; is a value that should have ended sealed, or ended in the clear, and
            ;; did not — which is exactly what nobody would notice.
            unfinished (+ unopenable odd nested published-sealed (count moved)
                          ;; A journal is unfinished in the most literal sense,
                          ;; and the one state whose danger is in what the operator
                          ;; does next. Counted whether it was there when this run
                          ;; started — in which case this run repaired it, and the
                          ;; operator must be made to run again rather than proceed
                          ;; to *push* on the strength of the run that did the
                          ;; repairing — or is there still.
                          (count strays-before)
                          (count (sidecars db)))]
          (print-counts mode direction (into {} (for [[t c] by-table]
                                                  [t (dissoc c :violations :moved :rows :orphans)])))
          (print-violations violations)
          (when-let [orphans (seq (:orphans total))]
            (println)
            (println (str "  " (count orphans) " row(s) belong to a Recipe that is not in this database"))
            (println "  and were walked as unpublished — see `read-table` for why:")
            (doseq [o (sort (take 10 orphans))] (println (str "    " o))))
          (when (seq moved)
            (println)
            (println (str "  " (count moved) " row(s) changed underneath this pass and were left alone:"))
            (doseq [{:keys [table row]} (take 20 moved)]
              (println (format "    %-16s %s" (name table) row)))
            (println "    Nothing should be writing during a cutover. Re-run when it has stopped."))
          (println)
          (case mode
            :verify (println (str "  " (if (seq violations)
                                         (str (count violations) " violations — the invariant does not hold.")
                                         "The invariant holds.")))
            :dry-run (println (str "  Dry run: " (get total :changed 0) " values in "
                                   (get total :rows 0) " rows would be "
                                   (if (= :seal direction) "sealed" "unsealed") ". Nothing written."))
            (do (println (str "  " (get total :changed 0) " values in " (get total :rows 0) " rows "
                              (if (= :seal direction) "sealed" "unsealed") "."
                              ;; **Only when there is genuinely nothing left.** This
                              ;; line used to say the database was where it should be
                              ;; while `PUBLISHED-SEALED 2` stood in the table above
                              ;; it.
                              (when (and (zero? (get total :changed 0)) (zero? unfinished))
                                " Nothing to do — this database is already where it should be.")))
                (when (checkpoint! db)
                  (println "  WAL checkpointed into the database file."))))
          (when (pos? unopenable)
            (println)
            (println (str "  " unopenable " value(s) carry the prefix and do not open with this key."))
            (println "  They were left exactly as they are. Either they were sealed under another")
            (println "  key, or they are damaged — and neither is a thing a pass can fix as it goes."))
          (when (pos? odd)
            (println)
            ;; A number written to one of these columns is converted by TEXT
            ;; affinity, so a BLOB is what actually reaches this bucket — which is
            ;; the shape the dev shelf's one case has, from a repair made in SQL.
            (println (str "  " odd " prose value(s) are not text — a BLOB — outside a published"))
            (println "  Recipe. They were left alone: sealing one would mean deciding it is text.")
            (println "  Look at them, and write them back through the app or as TEXT. Note that")
            (println "  cookbook itself cannot save a Recipe whose history holds one."))
          (when (pos? nested)
            (println)
            (println (str "  " nested " value(s) are an envelope inside an envelope."))
            (println "  No correct client writes one; one that sealed a ciphertext it had echoed")
            (println "  did, and until this round nothing could see the result. A reader meets")
            (println "  `enc:v1:…` where the prose should be.")
            (println (if (= :unseal direction)
                       "  One layer came off each of them here; run this again until it is 0."
                       "  `--unseal` takes one layer off per run, and `--verify --unseal` says
  when none is left.")))
          ;; **After the pass.** Nearly unreachable, and kept anyway: every mode
          ;; opens the database and so rolls back and deletes any journal that was
          ;; there, which is why the note above is worded in the past tense. What
          ;; could still leave one here is something *else* writing while this ran
          ;; and dying, and the answer to that is the same as to the other case —
          ;; the file is not safe to copy, which is the only way this pass can end
          ;; in a damaged production database.
          (when-let [strays (seq (sidecars db))]
            (println)
            (println (str "  A " (str/join " and a " strays) " is still beside this database."))
            (println "  Do not copy or push the .db while one is there: the file alone is either")
            (println "  torn or silently different from what was committed. Re-run this pass in")
            (println "  place — opening the database rolls the journal back — and copy it only")
            (println "  once no journal remains beside it."))
          (when (pos? published-sealed)
            (println)
            (println (str "  " published-sealed " value(s) inside a published Recipe's trail are sealed."))
            (println "  A published Recipe's prose is public and must be in the clear — the server")
            (println "  refuses both a publish that would leave an envelope and a write that would")
            (println "  put one back. This pass will not touch a published trail, so it cannot fix")
            (println "  this: unseal those values with the key and write them back, or the Recipe")
            (println "  serves base64 to strangers. If a publish raced this pass, that is how."))
          (println)
          ;; **Non-zero for anything left in a state the pass cannot call
          ;; finished** — `unfinished`, above, which is where the list lives now
          ;; rather than spelled twice.
          (System/exit (if (or (seq violations) (pos? unfinished)) 1 0)))))
      (catch Exception e
        (binding [*out* *err*] (println "cookbook-seal-migrate:" (ex-message e)))
        (System/exit 2)))))

(when (= *file* (System/getProperty "babashka.file"))
  (apply -main *command-line-args*))
