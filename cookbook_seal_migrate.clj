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

  What is here is the two things the inventory cannot say: which columns name a
  row, and how to ask whether it belongs to a published Recipe.

  `recipe_history` has no id of its own — its key is `(recipe_id, version)`, the
  same pair `GET /api/recipes/:id/sealed` uses to name one. The published question
  is a correlated subquery for the two tables that hang off a Recipe, and it
  answers -1 rather than NULL for a row whose Recipe is gone — a definite string
  in the output rather than one whose rendering `.nullvalue` can change under it."
  {:recipes          {:pk [:id]
                      :published "t.published"
                      :label (fn [{:keys [id]}] (str "recipe " id))}
   :recipe_history   {:pk [:recipe_id :version]
                      :published "COALESCE((SELECT published FROM recipes r WHERE r.id = t.recipe_id), -1)"
                      :label (fn [{:keys [recipe_id version]}]
                               (str "recipe " recipe_id " v" version))}
   :recipe_proposals {:pk [:id]
                      :extra [:recipe_id]
                      :published "COALESCE((SELECT published FROM recipes r WHERE r.id = t.recipe_id), -1)"
                      :label (fn [{:keys [id recipe_id]}]
                               (str "proposal " id " of recipe " recipe_id))}
   :scopes           {:pk [:id]
                      :published "0"
                      :label (fn [{:keys [id]}] (str "scope " id))}})

(def ^:private tables
  "In a fixed order, so two runs read alike and a resumed pass is easy to follow."
  [:recipes :recipe_history :recipe_proposals :scopes])

(when-not (= (set tables) (set (keys seal/sealed-columns)) (set (keys row-shape)))
  ;; A table added to the inventory and forgotten here would be walked by nobody
  ;; and reported by nothing. Loud, at load, rather than a quiet gap in a pass
  ;; whose whole output is counts.
  (throw (ex-info (str "the walk and the inventory disagree about which tables hold prose: "
                       (pr-str (sort (map name tables))) " vs "
                       (pr-str (sort (map name (keys seal/sealed-columns))))) {})))

;; ---------------------------------------------------------------------------
;; sqlite3.

(def ^:private preamble
  "Every invocation says how it wants its output before it asks for any. The
  shell reads `~/.sqliterc` on the machine this runs on, and a person who has
  ever typed `.mode box` into it would otherwise get a pass that reads a drawing
  of a table as a table."
  ".mode list\n.separator |\n.headers off\n")

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

(defn- opens?
  "Whether an envelope opens with the key in hand. `unseal` hands back a value it
  cannot read exactly as it is — rule 3, so that one unreadable column shows as
  `enc:v1:…` beside everything that reads instead of taking a response down — so
  *unchanged* is the answer to this question."
  [k table column v]
  (not= v (seal/unseal k table column v)))

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
  left exactly as it is. `:odd` is a prose column holding something that is not
  text at all."
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
      [(if (opens? k table column value) :already :unopenable) nil]
      ;; No `stored`. The trap in the ns docstring, and in `seal`'s.
      [:changed (seal/seal k table column value)])

    :else
    (if-not (seal/sealed? value)
      [:already nil]
      (let [plain (seal/unseal k table column value)]
        (if (= plain value) [:unopenable nil] [:changed plain])))))

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

    (opens? k table column value) [:sealed false]
    :else [:unopenable true]))

;; ---------------------------------------------------------------------------
;; Writing.

(defn- update-sql
  "One row, one statement, one transaction — which is the whole of the
  resumability story. The `WHERE` carries the values this pass read as well as the
  key, so a row somebody else moved in the meantime is not written over; the
  `changes()` after it is how that is noticed."
  [table {:keys [key cells]} changed]
  (let [{:keys [pk]} (row-shape table)]
    (str "UPDATE " (name table) " SET "
         (str/join ", " (for [[c v] changed] (str (name c) " = " (literal v))))
         " WHERE " (str/join " AND " (for [p pk] (str (name p) " = " (get key p))))
         " AND " (str/join " AND " (for [[c _] changed]
                                     (str (name c) " IS " (literal (:value (get cells c))))))
         "; SELECT changes();")))

;; ---------------------------------------------------------------------------
;; The pass.

(defn- tally [m bucket] (update m bucket (fnil inc 0)))

(defn- walk-table
  [{:keys [db direction mode k verbose?]} table]
  (reduce
   (fn [acc row]
     (let [columns (get seal/sealed-columns table)
           results (for [c columns]
                     [c (if (= :verify mode)
                          (verdict direction k table c row (get (:cells row) c))
                          (decide direction k table c row (get (:cells row) c)))])
           acc (reduce (fn [a [c [bucket _]]]
                         (cond-> (tally a bucket)
                           (and (= :verify mode) (second (verdict direction k table c row
                                                                  (get (:cells row) c))))
                           (update :violations (fnil conj [])
                                   {:table table :row ((:label (row-shape table)) (:key row))
                                    :column c :why bucket})))
                       acc results)
           acc (cond-> acc (:orphan? row) (update :orphans (fnil conj #{})
                                                        ((:label (row-shape table)) (:key row))))
           changed (into {} (for [[c [bucket v]] results :when (= :changed bucket)] [c v]))]
       (cond
         (empty? changed) acc
         (= :dry-run mode) (update acc :rows (fnil inc 0))
         :else
         (let [n (parse-long (str/trim (or (one db (update-sql table row changed)) "0")))]
           (when verbose?
             (println (format "  %-16s %-24s %s" (name table)
                              ((:label (row-shape table)) (:key row))
                              (str/join " " (map name (keys changed))))))
           (if (= 1 n)
             (update acc :rows (fnil inc 0))
             ;; The compare-and-set found something else there. Counted, named,
             ;; and left: a re-run picks up whatever the new value is.
             (-> acc
                 (update :moved (fnil conj [])
                         {:table table :row ((:label (row-shape table)) (:key row))})
                 (update :changed - (count changed))
                 (tally :skipped-moved)))))))
   {}
   (read-table db table)))

;; ---------------------------------------------------------------------------
;; What it prints. The counts are the point: a pass whose output is "done" is a
;; pass nobody can check.

(def ^:private headings
  "Which buckets each mode prints, in order, and what to call them. A bucket with
  no column here would be counted and never seen, so every one `decide` and
  `verdict` can answer appears in exactly one of these lists."
  {[:pass :seal]     [[:changed "sealed"] [:already "already"] [:blank "blank"]
                      [:published "published"] [:published-sealed "PUBLISHED-SEALED"]
                      [:unopenable "unopenable"] [:odd "odd"] [:skipped-moved "moved"]]
   [:pass :unseal]   [[:changed "unsealed"] [:already "plain"] [:blank "blank"]
                      [:published "published"] [:published-sealed "PUBLISHED-SEALED"]
                      [:unopenable "unopenable"] [:odd "odd"] [:skipped-moved "moved"]]
   [:verify :seal]   [[:sealed "sealed"] [:plain "PLAINTEXT"] [:blank "blank"] [:null "null"]
                      [:published "published"] [:published-sealed "PUBLISHED-SEALED"]
                      [:unopenable "UNOPENABLE"] [:odd "odd"]]
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
        (when (:verbose opts) (println))
        (let [by-table (into {} (for [table tables]
                                  [table (walk-table {:db db :direction direction :mode mode
                                                      :k k :verbose? (:verbose opts)}
                                                     table)]))
              total (apply merge-with (fn [a b] (if (number? a) (+ a b) (into a b))) (vals by-table))
              violations (:violations total)
              moved (:moved total)
              unopenable (get total :unopenable 0)
            odd (get total :odd 0)]
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
                              (when (zero? (get total :changed 0))
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
            (println (str "  " odd " prose value(s) are not text — a BLOB, a number — outside a"))
            (println "  published Recipe. They were left alone: sealing one would mean deciding it")
            (println "  is text. Look at them, and write them back through the app or as TEXT."))
          (println)
          ;; **Non-zero for anything left in a state the pass cannot call finished.**
          ;; The three of them have one thing in common: a value that should have
          ;; ended sealed and did not, which is precisely what nobody would notice.
          (System/exit (cond (seq violations) 1
                             (pos? unopenable) 1
                             (pos? odd) 1
                             (seq moved) 1
                             :else 0))))
      (catch Exception e
        (binding [*out* *err*] (println "cookbook-seal-migrate:" (ex-message e)))
        (System/exit 2)))))

(when (= *file* (System/getProperty "babashka.file"))
  (apply -main *command-line-args*))
