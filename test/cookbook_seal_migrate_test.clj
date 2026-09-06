(ns cookbook-seal-migrate-test
  "The migration walker, against a database.

  Everything here runs against a real SQLite file built for each test, because
  what the walker is is a set of decisions *about rows* — published or not, blank
  or not, sealed already or not — and the interesting ones are the rows nobody
  writes on purpose: a NULL `reason`, a whitespace-only body, a proposal against a
  Recipe that is no longer there, a value sealed under a key this pass does not
  hold. None of those can be exercised by calling a pure function on a map, and
  all of them are on the dev shelf.

  **The schema here is deliberately minimal and is not a copy of cookbook's.**
  What the walker names is the thirteen prose columns (out of
  `cookbook-seal/sealed-columns`, which is the cross-client contract), the keys
  that identify a row, and `recipes.published`. A test that pasted cookbook's
  whole schema in would be a fourteenth copy of it going stale in a second repo,
  and would still not catch a rename — nothing in this repo can.

  `sqlite3` is required, and its absence is a failure rather than a skip. The
  walker cannot run without it either, so a suite that went green on a machine
  where the tool does not work would be reporting agreement it never checked —
  the same judgement `seal-vectors.edn` gets next door."
  (:require [babashka.process :as p]
            [clojure.string :as str]
            [clojure.test :refer [deftest is testing use-fixtures]]
            [cookbook-seal :as seal]
            [cookbook-seal-migrate :as walk]))

(def ^:private sqlite! @#'walk/sqlite!)
(def ^:private rows @#'walk/rows)
(def ^:private walk-table @#'walk/walk-table)
(def ^:private update-sql @#'walk/update-sql)
(def ^:private read-table @#'walk/read-table)
(def ^:private tables @#'walk/tables)

(def ^:private repo-root
  "The suite runs from the repo root — `bb test` says so — and the one test that
  drives the script as a program needs to find it. Named and asserted rather than
  assumed, because the failure would otherwise read as the script being broken."
  (System/getProperty "user.dir"))

(use-fixtures :once
  (fn [f]
    (let [{:keys [exit]} (p/shell {:out :string :err :string :continue true} "sqlite3" "--version")]
      (when-not (zero? exit)
        (throw (ex-info "no working sqlite3, which is also all the walker has" {}))))
    (when-not (.exists (java.io.File. repo-root "cookbook_seal_migrate.clj"))
      (throw (ex-info (str "run this from the repo root; " repo-root " holds no walker") {})))
    (f)))

;; ---------------------------------------------------------------------------

(def ^:private test-key
  ;; Generated, not the fixture's: nothing here pins a ciphertext — that is the
  ;; envelope suite's job next door — and what these need of a key is that there
  ;; is one, and that a second one is different.
  (delay (seal/key-from-base64 (seal/generate-key-base64))))

(def ^:private other-key
  (delay (seal/key-from-base64 (seal/generate-key-base64))))

(def ^:private schema
  "The columns the walker touches, the keys it identifies rows by, and the latch
  it reads. Nothing else, on purpose — see the namespace docstring."
  "CREATE TABLE recipes (id INTEGER PRIMARY KEY AUTOINCREMENT, title TEXT NOT NULL,
     useful_when TEXT NOT NULL DEFAULT '', description TEXT NOT NULL DEFAULT '',
     version INTEGER NOT NULL DEFAULT 1, published INTEGER NOT NULL DEFAULT 0,
     modified_at DATETIME DEFAULT '2026-01-01 00:00:00', reason TEXT, context TEXT);
   CREATE TABLE recipe_history (recipe_id INTEGER NOT NULL, version INTEGER NOT NULL,
     title TEXT, useful_when TEXT, description TEXT, reason TEXT, context TEXT,
     PRIMARY KEY (recipe_id, version));
   CREATE TABLE recipe_proposals (id INTEGER PRIMARY KEY AUTOINCREMENT,
     recipe_id INTEGER NOT NULL, base_version INTEGER NOT NULL DEFAULT 1,
     title TEXT NOT NULL DEFAULT '', useful_when TEXT NOT NULL DEFAULT '',
     description TEXT NOT NULL DEFAULT '', reason TEXT, context TEXT);
   CREATE TABLE scopes (id INTEGER PRIMARY KEY AUTOINCREMENT, title TEXT NOT NULL,
     description TEXT NOT NULL DEFAULT '', tags TEXT NOT NULL DEFAULT '');")

(defn- sql-value [v]
  (cond
    (nil? v) "NULL"
    (number? v) (str v)
    (and (vector? v) (= :blob (first v)))
    ;; A BLOB holding readable text. Not invented: one `recipe_history` row on the
    ;; dev shelf is one, left by a repair made in SQL rather than through the app.
    (str "X'" (str/join (map #(format "%02x" (bit-and % 0xff)) (.getBytes ^String (second v) "UTF-8"))) "'")
    :else (str "CAST(X'"
               (str/join (map #(format "%02x" (bit-and % 0xff)) (.getBytes ^String v "UTF-8")))
               "' AS TEXT)")))

(defn- insert! [db table row]
  (sqlite! db (str "INSERT INTO " (name table) " (" (str/join ", " (map name (keys row))) ") VALUES ("
                   (str/join ", " (map sql-value (vals row))) ");")))

(defn- sealed [k table column text] (seal/seal k table column text))

(defn- fresh-db
  "A database with one row of every shape the walker has an opinion about."
  []
  (let [dir (java.nio.file.Files/createTempDirectory
             "seal-walk" (into-array java.nio.file.attribute.FileAttribute []))
        db (str (.resolve dir "cookbook.db"))
        k @test-key]
    (sqlite! db schema)
    ;; 1 — the ordinary unsealed Recipe, and the three shapes of blank beside it.
    (insert! db :recipes {:id 1 :title "plain" :description "A body.\nWith a second line, an apostrophe's worth of quoting, and 🦫."
                          :useful_when "" :reason nil :context "   "})
    ;; 2 — already sealed. A second pass must leave it byte for byte.
    (insert! db :recipes {:id 2 :title "sealed" :description (sealed k :recipes :description "already sealed")
                          :useful_when "still plain" :reason nil :context nil})
    ;; 3 — an envelope this key does not open. Nothing can be done with it and
    ;; nothing is: it is counted and left.
    (insert! db :recipes {:id 3 :title "foreign" :description (sealed @other-key :recipes :description "another key")
                          :useful_when "plain beside it" :reason nil :context nil})
    ;; 4 — published, in the clear, and its whole trail is out of bounds.
    (insert! db :recipes {:id 4 :title "published" :published 1 :description "public prose"
                          :useful_when "a visitor reads this" :reason "why" :context "context"})
    ;; 5 — published and holding an envelope, which is a violation of an invariant
    ;; the server enforces. Reported; still not touched.
    (insert! db :recipes {:id 5 :title "published, sealed" :published 1
                          :description (sealed k :recipes :description "should not be here")
                          :useful_when "plain" :reason nil :context nil})
    ;; 6 — a prose column holding something that is not text at all.
    (insert! db :recipes {:id 6 :title "blob" :description [:blob "text, in a blob"]
                          :useful_when "plain" :reason nil :context nil})
    ;; A value that looks like an envelope and is not, from the fixture's
    ;; passthrough class: it must be sealed like any other prose.
    (insert! db :recipes {:id 7 :title "near miss" :description "enc:v0:d2hhdGV2ZXI="
                          :useful_when "ENC:V1:not this either" :reason nil :context nil})

    (insert! db :recipe_history {:recipe_id 1 :version 1 :description "v1 body" :useful_when nil
                                 :reason nil :context nil})
    (insert! db :recipe_history {:recipe_id 1 :version 2 :description "v2 body" :useful_when ""
                                 :reason "why v2" :context "context v2"})
    (insert! db :recipe_history {:recipe_id 4 :version 1 :description "public v1" :useful_when "public"
                                 :reason nil :context nil})

    (insert! db :recipe_proposals {:id 1 :recipe_id 1 :description "a proposal" :useful_when ""
                                   :reason "the agent's reason" :context "the agent's context"})
    (insert! db :recipe_proposals {:id 2 :recipe_id 4 :description "against a published Recipe"
                                   :useful_when "" :reason nil :context nil})
    ;; An orphan: no Recipe 99. SQLite does not enforce the foreign key, and the
    ;; dev shelf holds three of these.
    (insert! db :recipe_proposals {:id 3 :recipe_id 99 :description "orphaned prose"
                                   :useful_when "" :reason nil :context nil})

    (insert! db :scopes {:id 1 :title "A Scope" :description "Scope prose, which is sealed."})
    ;; Filed under the published Recipe, and still the owner's: Scopes are not part
    ;; of a publish and are walked whatever their Recipes are.
    (insert! db :scopes {:id 2 :title "Public Recipe's Scope" :description "still the owner's"})
    (insert! db :scopes {:id 3 :title "No prose" :description ""})
    db))

(defn- pass
  "One whole run, as `-main` makes it, without the exit and the printing."
  [db mode direction]
  (let [by-table (into {} (for [t tables]
                            [t (walk-table {:db db :direction direction :mode mode :k @test-key} t)]))]
    (apply merge-with (fn [a b] (if (number? a) (+ a b) (into a b))) (vals by-table))))

(defn- content
  "Every value of every column of every table, as SQL text. What a byte-comparison
  of two databases comes down to once the page layout is out of the way."
  [db]
  (str/join "\n" (rows db ".dump")))

(defn- skeleton
  "The database with every prose value blanked, dumped. Two of these being equal
  is the proof that a pass touched nothing but the thirteen columns — no
  timestamp, no version, no flag, no id, no title."
  [db]
  (let [copy (str db ".skeleton")]
    (java.nio.file.Files/copy (.toPath (java.io.File. ^String db))
                              (.toPath (java.io.File. ^String copy))
                              (into-array java.nio.file.CopyOption
                                          [java.nio.file.StandardCopyOption/REPLACE_EXISTING]))
    (sqlite! copy (str/join (for [[table columns] seal/sealed-columns]
                              (str "UPDATE " (name table) " SET "
                                   (str/join ", " (for [c columns] (str (name c) " = ''")))
                                   ";"))))
    (content copy)))

(defn- raw
  "One column of one row as `typeof:hex`, which is the only way to read a blank
  without a helper eating it: `rows` drops empty lines, and empty is a value here."
  [db table column where]
  (first (rows db (str "SELECT typeof(" (name column) ") || ':' || hex(" (name column) ")"
                       " FROM " (name table) " WHERE " where ";"))))

;; ---------------------------------------------------------------------------

(deftest a-seal-pass-seals-the-prose-of-unpublished-recipes-and-nothing-else
  (let [db (fresh-db)
        before-skeleton (skeleton db)
        counts (pass db :pass :seal)]
    (testing "the counts are the audit, and every value lands in exactly one bucket"
      (is (= 16 (get counts :changed)) "recipes, history, proposals and scopes together")
      (is (= 1 (get counts :already)) "recipe 2's description, sealed already")
      (is (= 1 (get counts :unopenable)) "recipe 3's, sealed under another key")
      (is (= 1 (get counts :odd)) "recipe 6's blob")
      (is (= 8 (get counts :published)) "recipe 4 and 5's trail, in the clear")
      (is (= 1 (get counts :published-sealed)) "recipe 5's description")
      (is (= #{"proposal 3 of recipe 99"} (:orphans counts))))

    (testing "everything that should be sealed is"
      (is (every? seal/sealed?
                  (rows db "SELECT description FROM recipes WHERE id IN (1,7);")))
      (is (every? seal/sealed? (rows db "SELECT description FROM scopes WHERE id IN (1,2);"))))

    (testing "and nothing but the thirteen columns moved — not a timestamp, a
      version, a flag or an id"
      (is (= before-skeleton (skeleton db))))

    (testing "blank stays blank, and NULL stays NULL — the distinction the whole
      rule exists for"
      (is (= "null:" (raw db :recipes :reason "id=1")) "NULL is still NULL")
      (is (= "text:" (raw db :recipes :useful_when "id=1")) "and empty is still empty")
      (is (= "null:" (raw db :recipe_history :useful_when "recipe_id=1 AND version=1")))
      (is (= "text:202020" (raw db :recipes :context "id=1"))
          "whitespace-only is blank by `seal/blank-value?`, and this counts by it"))

    (testing "a published Recipe's prose is exactly what it was, all four columns,
      across all three tables"
      (is (= ["public prose" "a visitor reads this" "why" "context"]
             (rows db "SELECT description FROM recipes WHERE id=4
                       UNION ALL SELECT useful_when FROM recipes WHERE id=4
                       UNION ALL SELECT reason FROM recipes WHERE id=4
                       UNION ALL SELECT context FROM recipes WHERE id=4;")))
      (is (= ["public v1"] (rows db "SELECT description FROM recipe_history WHERE recipe_id=4;")))
      (is (= ["against a published Recipe"]
             (rows db "SELECT description FROM recipe_proposals WHERE recipe_id=4;"))))

    (testing "a Scope filed under a published Recipe is still sealed: Scopes are
      not part of a publish"
      (is (seal/sealed? (first (rows db "SELECT description FROM scopes WHERE id=2;")))))

    (testing "the value that only looks like an envelope was sealed like the prose
      it is"
      (let [v (first (rows db "SELECT description FROM recipes WHERE id=7;"))]
        (is (seal/sealed? v))
        (is (= "enc:v0:d2hhdGV2ZXI=" (seal/unseal @test-key :recipes :description v)))))))

(deftest a-second-pass-changes-nothing-and-says-so
  (let [db (fresh-db)
        _ (pass db :pass :seal)
        after-one (content db)
        counts (pass db :pass :seal)]
    (is (zero? (get counts :changed 0)) "nothing sealed twice")
    (is (= after-one (content db)) "and not one byte written")))

(deftest the-round-trip-is-the-identity
  (let [db (fresh-db)
        opened (do (pass db :pass :unseal) (content db))]
    (testing "opening first gives the baseline: everything this key can read, in
      the clear. Then a seal and an unseal must land back on it exactly — which is
      the whole claim, and the reason the escape hatch is written now rather than
      when it is needed."
      (pass db :pass :seal)
      (is (not= opened (content db)) "sanity: the seal did something")
      (pass db :pass :unseal)
      (is (= opened (content db))))))

(deftest verify-reports-the-invariant-both-ways
  (let [db (fresh-db)]
    (testing "before the pass: every plaintext value of an unpublished Recipe is a
      violation, and so is the envelope inside a published one"
      (let [{:keys [violations]} (pass db :verify :seal)
            why (frequencies (map :why violations))]
        (is (= 16 (get why :plain)))
        (is (= 1 (get why :published-sealed)))
        (is (= 1 (get why :unopenable)))
        (is (= 1 (get why :odd)) "a blob of prose is prose in the clear")))

    (testing "after it: only the three that cannot be fixed by a pass"
      (pass db :pass :seal)
      (let [{:keys [violations]} (pass db :verify :seal)]
        (is (= #{:published-sealed :unopenable :odd} (set (map :why violations))))
        (is (= 3 (count violations)))))

    (testing "and the inverse direction, which is what `--unseal` is checked with:
      no envelope anywhere at all, published or not"
      (is (pos? (count (:violations (pass db :verify :unseal)))))
      (pass db :pass :unseal)
      (let [{:keys [violations]} (pass db :verify :unseal)]
        (is (= #{:sealed :published-sealed} (set (map :why violations)))
            "the one this key cannot open, and the one inside a published Recipe —
             which this pass will not touch in either direction")
        (is (= 2 (count violations)))))))

(deftest a-row-that-moved-underneath-the-pass-is-not-written-over
  (testing "each write carries the values this pass read in its WHERE clause. A
    cutover should have nothing else writing; this is what says so instead of
    hoping, and it is what makes an interrupted pass safe to re-run."
    (let [db (fresh-db)
          row (first (filter #(= 1 (:id (:key %))) (read-table db :recipes)))]
      (sqlite! db "UPDATE recipes SET description = CAST(X'6d6f766564' AS TEXT) WHERE id = 1;")
      (let [out (str/trim (first (rows db (update-sql :recipes row {:description "new"}))))]
        (is (= "0" out) "changes() — the row was not written"))
      (is (= ["moved"] (rows db "SELECT description FROM recipes WHERE id=1;"))))))

(deftest the-walk-and-the-inventory-name-the-same-tables
  (testing "the guard that runs at load: a table added to `sealed-columns` and
    forgotten in the walk would be walked by nobody and reported by nothing"
    (is (= (set tables) (set (keys seal/sealed-columns))))))

(deftest decide-passes-a-migration-arity-seal-and-therefore-no-stored-value
  (testing "the trap the whole pass turns on. `seal` hands back `stored` when the
    value has not changed, so a walker that handed it the plaintext it just read
    would be told, correctly, that nothing had changed — and would seal nothing
    while reporting a clean pass."
    (let [[bucket v] (walk/decide :seal @test-key :recipes :description {}
                                  {:type :text :value "a body"})]
      (is (= :changed bucket))
      (is (seal/sealed? v))
      (is (= "a body" (seal/unseal @test-key :recipes :description v))))
    (testing "and the same value handed in as `stored` is what would have gone wrong"
      (is (= "a body" (seal/seal @test-key :recipes :description "a body" "a body"))))))

(deftest the-exit-code-is-the-contract
  (testing "a migration script is run by a person watching a shell, and by
    whatever they wrap it in. `--verify` answering 1 is the whole of how a pass is
    known to have finished."
    (let [db (fresh-db)
          run (fn [& args]
                (:exit (apply p/shell {:out :string :err :string :continue true
                                       :dir repo-root
                                       :extra-env {"COOKBOOK_SEAL_KEY" (seal/generate-key-base64)}}
                              "bb" "cookbook_seal_migrate.clj" (concat args [db]))))]
      ;; A key that opens nothing at all: every sealed value is unopenable, which
      ;; is itself a refusal to report success.
      (is (= 1 (run "--verify")) "an unsealed database does not satisfy the seal invariant")
      (is (= 2 (run "--verify" "/tmp/there-is-no-database-here.db")) "and a missing file is a local error"))))
