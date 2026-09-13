(ns tracker-seal-migrate-test
  "The tracker migration walker, against a database.

  Everything here runs against a real SQLite file built for each test, because
  what the walker is is a set of decisions *about rows* — whose they are, blank or
  not, sealed already or not, prose in a column or prose inside a JSON document —
  and the interesting ones are the rows nobody writes on purpose: a NULL body, a
  whitespace-only one, a row belonging to a user who is not sealing, a value
  sealed under a key this pass does not hold. None of those can be exercised by
  calling a pure function on a map, and all of them are in the live file.

  **The schema here is deliberately minimal and is not a copy of tracker's.** The
  nine entity tables are one shape written nine times, generated from
  `tracker-seal/sealed-columns` — which is the cross-client contract — plus the
  two columns that are not prose and must be seen not to move, and the `user_id`
  that decides whose row it is. A test that pasted tracker's whole schema in would
  be a second copy of it going stale in a second repo, and would still not catch a
  rename; nothing in this repo can.

  `users` and `events` are written out, because their columns are not derivable
  from anything: `is_machine_user` and `for_user_id` are what a scope is resolved
  through, `seal_prose` is what `--arm` writes, and `effective_user_id` is the
  audit log's answer to *whose row is this*.

  `sqlite3` is required, and its absence is a failure rather than a skip. The
  walker cannot run without it either, so a suite that went green on a machine
  where the tool does not work would be reporting agreement it never checked —
  the same judgement `seal-vectors.edn` gets next door."
  (:require [babashka.process :as p]
            [cheshire.core :as json]
            [clojure.string :as str]
            [clojure.test :refer [deftest is testing use-fixtures]]
            [tracker-seal :as seal]
            [tracker-seal-migrate :as walk]))

(def ^:private sqlite! @#'walk/sqlite!)
(def ^:private rows @#'walk/rows)
(def ^:private walk-table @#'walk/walk-table)
(def ^:private update-sql @#'walk/update-sql)
(def ^:private read-table @#'walk/read-table)
(def ^:private resolve-user! @#'walk/resolve-user!)
(def ^:private foreign-audit @#'walk/foreign-audit)
(def ^:private tables @#'walk/tables)
(def ^:private walked @#'walk/walked)
(def ^:private sidecars @#'walk/sidecars)

(def ^:private repo-root
  "The suite runs from the repo root — `bb test` says so — and the tests that
  drive the script as a program need to find it. Named and asserted rather than
  assumed, because the failure would otherwise read as the script being broken."
  (System/getProperty "user.dir"))

(use-fixtures :once
  (fn [f]
    (let [{:keys [exit]} (p/shell {:out :string :err :string :continue true} "sqlite3" "--version")]
      (when-not (zero? exit)
        (throw (ex-info "no working sqlite3, which is also all the walker has" {}))))
    (when-not (.exists (java.io.File. repo-root "tracker_seal_migrate.clj"))
      (throw (ex-info (str "run this from the repo root; " repo-root " holds no walker") {})))
    (f)))

;; ---------------------------------------------------------------------------

(def ^:private test-key-base64
  ;; Generated, not the fixture's: nothing here pins a ciphertext — that is the
  ;; envelope suite's job next door — and what these need of a key is that there
  ;; is one, and that a second one is different.
  ;;
  ;; **Kept as the base64 rather than only as the key**, so that the tests which
  ;; drive the script as a *program* can hand it the same key through
  ;; `TRACKER_SEAL_KEY`. A subprocess holding a different key sees every sealed
  ;; value as unopenable, which makes every exit code 1 for the wrong reason —
  ;; and an exit-code test that cannot distinguish its reasons is not one.
  (delay (seal/generate-key-base64)))

(def ^:private test-key (delay (seal/key-from-base64 @test-key-base64)))
(def ^:private other-key (delay (seal/key-from-base64 (seal/generate-key-base64))))

(def ^:private daniel 4)
(def ^:private machine 5)
(def ^:private antonio 2)
(def ^:private scope #{4 5})

(def ^:private schema
  (str
   ;; Three humans and a machine acting for one of them, which is the whole of
   ;; what makes tracker's walk different from cookbook's.
   "CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT NOT NULL UNIQUE,
      is_machine_user INTEGER NOT NULL DEFAULT 0, for_user_id INTEGER,
      seal_prose INTEGER NOT NULL DEFAULT 0);\n"
   ;; One shape, nine times, out of the inventory. `title` and `tags` are here to
   ;; be seen not to move; `user_id` is nullable because it is nullable on six of
   ;; the nine in the live schema, and a row with no owner is nobody's to seal.
   (str/join "\n" (for [[table columns] seal/sealed-columns]
                    (str "CREATE TABLE " (name table)
                         " (id INTEGER PRIMARY KEY, title TEXT NOT NULL DEFAULT '',"
                         " tags TEXT NOT NULL DEFAULT '', user_id INTEGER, "
                         (str/join ", " (for [c columns] (str (name c) " TEXT DEFAULT ''")))
                         ");")))
   "\nCREATE TABLE events (id INTEGER PRIMARY KEY, ts TEXT NOT NULL DEFAULT '2026-01-01 00:00:00',
      action TEXT NOT NULL DEFAULT 'update', entity_type TEXT, entity_id INTEGER,
      effective_user_id INTEGER, payload TEXT NOT NULL);"))

(defn- sql-value [v]
  (cond
    (nil? v) "NULL"
    (number? v) (str v)
    (and (vector? v) (= :blob (first v)))
    ;; A prose column holding a BLOB. Not invented: cookbook's dev shelf holds
    ;; one, left by a repair made in SQL rather than through the app, and nothing
    ;; about tracker's columns makes it less possible.
    (str "X'" (str/join (map #(format "%02x" (bit-and % 0xff))
                             (.getBytes ^String (second v) "UTF-8"))) "'")
    :else (str "CAST(X'"
               (str/join (map #(format "%02x" (bit-and % 0xff)) (.getBytes ^String v "UTF-8")))
               "' AS TEXT)")))

(defn- insert! [db table row]
  (sqlite! db (str "INSERT INTO " (name table) " (" (str/join ", " (map name (keys row))) ")"
                   " VALUES (" (str/join ", " (map sql-value (vals row))) ");")))

(defn- sealed
  "A body, sealed the way a client seals one. `:tasks :description` for anything
  bound as an item — which is all nine tables and every prose value inside a
  payload, since they share one binding."
  ([text] (sealed @test-key text))
  ([k text] (seal/seal k :tasks :description text)))

(defn- nested
  "`enc(enc(prose))`, built at the envelope level on purpose.

  It is what a client that sealed a ciphertext it had echoed used to produce, and
  **no correct client can produce one any more**: `seal-envelope/seal-at` hands an
  envelope straight back, whatever is stored. So a fixture that needs one has to
  reach past the rules and make it by hand — which is the right shape for a
  fixture of a corruption. The walker still has to see it, because the databases
  that already hold one are the reason the bucket exists."
  [text]
  (seal/seal-text @test-key seal/item-description-aad (sealed text)))

(defn- payload [m] (json/generate-string m))

(defn- tmp-db [prefix]
  (let [dir (java.nio.file.Files/createTempDirectory
             prefix (into-array java.nio.file.attribute.FileAttribute []))]
    (str (.resolve dir "tracker.db"))))

(defn- with-users! [db]
  (sqlite! db schema)
  (insert! db :users {:id antonio :username "antonio"})
  (insert! db :users {:id 3 :username "saiyuri"})
  (insert! db :users {:id daniel :username "daniel"})
  (insert! db :users {:id machine :username "daniel-machine" :is_machine_user 1 :for_user_id daniel})
  db)

(defn- fresh-db
  "A database with one row of every shape the walker has an opinion about, and —
  the part cookbook's fixture had no need of — rows belonging to somebody else
  beside every one of them."
  []
  (let [db (with-users! (tmp-db "tracker-seal-walk"))]
    ;; 1 — the ordinary unsealed body, with everything that makes quoting a
    ;; question: a second line, an apostrophe, and a beaver.
    (insert! db :tasks {:id 1 :user_id daniel :title "plain" :tags "a,b"
                        :description "A body.\nWith an apostrophe's worth of quoting, and 🦫."})
    ;; 2 — already sealed. A second pass must leave it byte for byte.
    (insert! db :tasks {:id 2 :user_id daniel :title "sealed" :description (sealed "already sealed")})
    ;; 3 — an envelope this key does not open. Nothing can be done with it and
    ;; nothing is: it is counted and left.
    (insert! db :tasks {:id 3 :user_id daniel :title "foreign key"
                        :description (sealed @other-key "sealed under another key")})
    ;; 4 — a prose column holding something that is not text at all.
    (insert! db :tasks {:id 4 :user_id daniel :title "blob" :description [:blob "text, in a blob"]})
    ;; 5 — a value that only looks like an envelope, from the fixture's
    ;; passthrough class. It is prose and must be sealed like any other.
    (insert! db :tasks {:id 5 :user_id daniel :title "near miss" :description "enc:v0:d2hhdGV2ZXI="})
    ;; 6, 7, 8 — the three shapes of blank. NULL and empty mean different things
    ;; and both must still mean them afterwards.
    (insert! db :tasks {:id 6 :user_id daniel :title "null body" :description nil})
    (insert! db :tasks {:id 7 :user_id daniel :title "empty body" :description ""})
    (insert! db :tasks {:id 8 :user_id daniel :title "spaces" :description "   "})
    ;; 9, 10 — not his. One belongs to antonio and one to nobody at all, and the
    ;; walk must not read, count or touch either.
    (insert! db :tasks {:id 9 :user_id antonio :title "antonio's" :description "antonio's body"})
    (insert! db :tasks {:id 10 :user_id nil :title "ownerless" :description "a body with no owner"})
    ;; 11 — a machine user's row. In scope: a machine acting for him is him.
    (insert! db :tasks {:id 11 :user_id machine :title "the machine's" :description "written by a machine"})

    ;; One body each in the other eight tables, and antonio beside every one.
    (doseq [table (remove #{:tasks} tables)]
      (insert! db table {:id 1 :user_id daniel :title (name table)
                         :description (str "prose in " (name table))})
      (insert! db table {:id 2 :user_id antonio :title "antonio's"
                         :description (str "antonio's " (name table))}))

    ;; The five payload shapes `et.tr.seal-rules/prose-paths` knows, one row each.
    (insert! db :events {:id 1 :effective_user_id daniel :action "create" :entity_type "task"
                         :payload (payload {:row {:title "t" :description "a created body"}})})
    (insert! db :events {:id 2 :effective_user_id daniel :action "delete" :entity_type "task"
                         :payload (payload {:snapshot {:title "t" :description "a deleted body"}})})
    (insert! db :events {:id 3 :effective_user_id daniel :action "update" :entity_type "task"
                         :payload (payload {:field "description" :old-value "what it was"
                                            :new-value "what it is"})})
    (insert! db :events {:id 4 :effective_user_id daniel :action "update" :entity_type "task"
                         :payload (payload {:changes {:description {:old "before" :new "after"}
                                                      :title {:old "x" :new "y"}}})})
    (insert! db :events {:id 5 :effective_user_id daniel :action "dropped-write" :entity_type "dropped"
                         :payload (payload {:method "PUT" :uri "/api/tasks/1"
                                            :body "{\"description\":\"a body inside a raw request\"}"})})
    ;; 6 — a shape with no prose in it at all. Walked, counted, untouched.
    (insert! db :events {:id 6 :effective_user_id daniel :action "link" :entity_type "task"
                         :payload (payload {:category "Work" :entity-title "t"})})
    ;; 7 — a create whose body was empty. The blank rule, inside a document.
    (insert! db :events {:id 7 :effective_user_id daniel :action "create" :entity_type "task"
                         :payload (payload {:row {:title "t" :description ""}})})
    ;; 8 — a create for a row that never had a body. The key must not appear.
    (insert! db :events {:id 8 :effective_user_id daniel :action "create" :entity_type "motto"
                         :payload (payload {:row {:title "just a title"}})})
    ;; 9 — antonio's, and it holds prose in the shape most likely to be sealed by
    ;; accident.
    (insert! db :events {:id 9 :effective_user_id antonio :action "create" :entity_type "task"
                         :payload (payload {:row {:title "t" :description "antonio's event prose"}})})
    ;; 10 — an update from nothing to something: one blank and one body, in one row.
    (insert! db :events {:id 10 :effective_user_id daniel :action "update" :entity_type "task"
                         :payload (payload {:field "description" :old-value nil
                                            :new-value "the first body"})})
    db))

(defn- clean-db
  "A database with nothing wrong in it: two bodies of his, one of antonio's, one
  event payload. What a pass over it does is seal three values and exit 0, which
  is the control every exit-code assertion below is measured against."
  []
  (let [db (with-users! (tmp-db "tracker-seal-walk-clean"))]
    (insert! db :tasks {:id 1 :user_id daniel :title "one" :description "a body"})
    (insert! db :tasks {:id 2 :user_id daniel :title "two" :description "another body"})
    (insert! db :tasks {:id 3 :user_id antonio :title "antonio's" :description "not his to seal"})
    (insert! db :events {:id 1 :effective_user_id daniel :action "create" :entity_type "task"
                         :payload (payload {:row {:title "t" :description "a created body"}})})
    db))

(defn- pass
  "One whole run, as `-main` makes it, without the exit and the printing."
  ([db mode direction] (pass db mode direction scope))
  ([db mode direction ids]
   (let [by-table (into {} (for [t walked]
                             [t (walk-table {:db db :direction direction :mode mode
                                             :k @test-key :ids ids} t)]))]
     (apply merge-with (fn [a b] (if (number? a) (+ a b) (into a b))) (vals by-table)))))

(defn- content
  "Every value of every column of every table, as SQL text. What a byte-comparison
  of two databases comes down to once the page layout is out of the way."
  [db]
  (str/join "\n" (rows db ".dump")))

(defn- skeleton
  "The database with every prose value blanked, dumped. Two of these being equal
  is the proof that a pass touched nothing but the prose — no title, no tag, no
  id, no owner, and none of the audit log's own columns."
  [db]
  (let [copy (str db ".skeleton")]
    (java.nio.file.Files/copy (.toPath (java.io.File. ^String db))
                              (.toPath (java.io.File. ^String copy))
                              (into-array java.nio.file.CopyOption
                                          [java.nio.file.StandardCopyOption/REPLACE_EXISTING]))
    (sqlite! copy (str (str/join (for [[table columns] seal/sealed-columns]
                                   (str "UPDATE " (name table) " SET "
                                        (str/join ", " (for [c columns] (str (name c) " = ''")))
                                        ";")))
                       "UPDATE events SET payload = '';"))
    (content copy)))

(defn- raw
  "One column of one row as `typeof:hex`, which is the only way to read a blank
  without a helper eating it: `rows` drops empty lines, and empty is a value here."
  [db table column where]
  (first (rows db (str "SELECT typeof(" (name column) ") || ':' || hex(" (name column) ")"
                       " FROM " (name table) " WHERE " where ";"))))

(defn- value [db table column where]
  (first (rows db (str "SELECT " (name column) " FROM " (name table) " WHERE " where ";"))))

(defn- event-payload [db id]
  (json/parse-string (value db :events :payload (str "id=" id)) true))

;; ---------------------------------------------------------------------------

(deftest a-seal-pass-seals-one-users-prose-and-nothing-else
  (let [db (fresh-db)
        before-skeleton (skeleton db)
        antonio-before (content db)
        counts (pass db :pass :seal)]
    (testing "the counts are the audit, and every value lands in exactly one bucket"
      (is (= 19 (get counts :changed))
          "3 in tasks (a body, a near-miss, and the machine's), 8 in the other eight
           tables, 8 inside the audit log's payloads")
      (is (= 1 (get counts :already)) "task 2, sealed already")
      (is (= 1 (get counts :unopenable)) "task 3, sealed under another key")
      (is (= 1 (get counts :odd)) "task 4's blob")
      (is (= 5 (get counts :blank)) "three shapes of blank in tasks, two inside payloads")
      (is (= 2 (get counts :no-prose)) "the link event, and the create with no body")
      (is (= 17 (get counts :rows)) "3 + 8 entity rows and 6 event rows written")
      (is (nil? (get counts :skipped-moved))))

    (testing "everything of his that should be sealed is"
      (is (every? seal/sealed? (rows db "SELECT description FROM tasks WHERE id IN (1,5,11);")))
      (doseq [table (remove #{:tasks} tables)]
        (is (seal/sealed? (value db table :description "id=1")) (name table))))

    (testing "**and not one row of anybody else's.** The half cookbook never had:
      antonio's rows, and a row with no owner at all, are byte for byte what they
      were — in every table, and in the audit log."
      (is (= "antonio's body" (value db :tasks :description "id=9")))
      (is (= "a body with no owner" (value db :tasks :description "id=10")))
      (doseq [table (remove #{:tasks} tables)]
        (is (= (str "antonio's " (name table)) (value db table :description "id=2")) (name table)))
      (is (= "antonio's event prose" (get-in (event-payload db 9) [:row :description]))))

    (testing "nothing but the prose moved — not a title, a tag, an id, an owner,
      or any of the audit log's own columns"
      (is (= before-skeleton (skeleton db))))

    (testing "blank stays blank, and NULL stays NULL — the distinction the whole
      rule exists for, and the one `prune-empty-entries` reads in SQL with no key"
      (is (= "null:" (raw db :tasks :description "id=6")) "NULL is still NULL")
      (is (= "text:" (raw db :tasks :description "id=7")) "and empty is still empty")
      (is (= "text:202020" (raw db :tasks :description "id=8"))
          "whitespace-only is blank by `blank-value?`, and this counts by it"))

    (testing "the value that only looks like an envelope was sealed like the prose it is"
      (let [v (value db :tasks :description "id=5")]
        (is (seal/sealed? v))
        (is (= "enc:v0:d2hhdGV2ZXI=" (seal/unseal @test-key :tasks :description v)))))

    (testing "the one sealed under another key was left exactly as it was"
      (is (= (seal/sealed? (value db :tasks :description "id=3")) true))
      (is (str/includes? antonio-before (value db :tasks :description "id=3"))))))

(deftest the-audit-log-is-walked-through-the-shapes-seal-rules-spells
  (testing "five shapes, because five functions in `server/events.clj` build them.
    This file knows how to walk a payload and knows nothing about where prose is
    in one — `et.tr.seal-rules/prose-paths` is the only place that is written, and
    tracker's server and browser read the same var."
    (let [db (fresh-db)]
      (pass db :pass :seal)
      (testing "a create's row"
        (let [p (event-payload db 1)]
          (is (seal/sealed? (get-in p [:row :description])))
          (is (= "a created body" (seal/unseal @test-key :tasks :description
                                               (get-in p [:row :description]))))
          (is (= "t" (get-in p [:row :title])) "and the title beside it is clear")))
      (testing "a delete's snapshot"
        (is (= "a deleted body" (seal/unseal @test-key :tasks :description
                                             (get-in (event-payload db 2) [:snapshot :description])))))
      (testing "a single-field update, both sides of it"
        (let [p (event-payload db 3)]
          (is (= "what it was" (seal/unseal @test-key :tasks :description (:old-value p))))
          (is (= "what it is" (seal/unseal @test-key :tasks :description (:new-value p))))
          (is (= "description" (:field p)) "the field name is not prose")))
      (testing "a multi-field update, the description entry only"
        (let [p (event-payload db 4)]
          (is (= "before" (seal/unseal @test-key :tasks :description
                                       (get-in p [:changes :description :old]))))
          (is (= "after" (seal/unseal @test-key :tasks :description
                                      (get-in p [:changes :description :new]))))
          (is (= {:old "x" :new "y"} (get-in p [:changes :title]))
              "and the title's change is clear, in the log as everywhere else")))
      (testing "a dropped machine write's captured body, bound as a document and
        not as a description — `event/body`, which is what stops somebody holding
        the file lifting it into a real column"
        (let [p (event-payload db 5)]
          (is (seal/sealed? (:body p)))
          (is (= "{\"description\":\"a body inside a raw request\"}"
                 (seal/unseal @test-key :events :body (:body p))))
          (is (= "/api/tasks/1" (:uri p)) "and the request line is clear")))

      (testing "**a create for a row that never had a body does not grow one.** A
        walk that used `update-in` would call its function with `nil` on a missing
        key and then put the key there — a payload asserting something untrue
        about the row, written by the pass that was re-encoding it for safekeeping."
        (is (= {:row {:title "just a title"}} (event-payload db 8))))

      (testing "an empty body inside a payload stays empty"
        (is (= "" (get-in (event-payload db 7) [:row :description]))))

      (testing "a payload with no prose in it is untouched, to the byte"
        (is (= {:category "Work" :entity-title "t"} (event-payload db 6))))

      (testing "a blank old-value and a real new-value, in one row and one write"
        (let [p (event-payload db 10)]
          (is (nil? (:old-value p)) "null stays null: there was no body before")
          (is (= "the first body" (seal/unseal @test-key :tasks :description (:new-value p)))))))))

(deftest a-second-pass-changes-nothing-and-says-so
  (let [db (fresh-db)
        _ (pass db :pass :seal)
        after-one (content db)
        counts (pass db :pass :seal)]
    (is (zero? (get counts :changed 0)) "nothing sealed twice")
    (is (= after-one (content db)) "and not one byte written")))

(deftest the-round-trip-is-the-identity
  (let [db (fresh-db)
        ;; Opening first gives the baseline: everything this key can read, in the
        ;; clear. A real database is already mixed, so *seal then unseal equals
        ;; the original* is not the claim that can be made — this one is, and it
        ;; is the stronger half of recipe 159's three comparisons. It also
        ;; normalises the payloads, which is the one thing a pass changes about a
        ;; document beyond its prose.
        opened (do (pass db :pass :unseal) (content db))]
    (pass db :pass :seal)
    (is (not= opened (content db)) "sanity: the seal did something")
    (pass db :pass :unseal)
    (is (= opened (content db)))))

(deftest verify-reports-the-invariant-both-ways
  (let [db (fresh-db)]
    (testing "before the pass: every plaintext value of his is a violation"
      (let [{:keys [violations]} (pass db :verify :seal)
            why (frequencies (map :why violations))]
        (is (= 19 (get why :plain)))
        (is (= 1 (get why :unopenable)))
        (is (= 1 (get why :odd)) "a blob of prose is prose in the clear")
        (is (nil? (get why :foreign-sealed)))))

    (testing "after it: only the two that cannot be fixed by a pass"
      (pass db :pass :seal)
      (let [{:keys [violations]} (pass db :verify :seal)]
        (is (= #{:unopenable :odd} (set (map :why violations))))
        (is (= 2 (count violations)))))

    (testing "and the inverse direction, which is what `--unseal` is checked with:
      no envelope anywhere at all"
      (is (pos? (count (:violations (pass db :verify :unseal)))))
      (pass db :pass :unseal)
      (let [{:keys [violations]} (pass db :verify :unseal)]
        (is (= #{:sealed} (set (map :why violations))))
        (is (= 1 (count violations)) "the one this key cannot open, and nothing else")))))

(deftest the-scope-is-resolved-from-a-name-and-refused-rather-than-guessed
  (let [db (fresh-db)]
    (testing "a human, plus every machine user acting for him"
      (is (= {:username "daniel" :id 4 :machine-ids [5] :ids #{4 5}} (resolve-user! db "daniel"))))
    (testing "a human with no machines is just himself"
      (is (= #{2} (:ids (resolve-user! db "antonio")))))
    (testing "no name is a refusal, and it names the candidates rather than picking one"
      (let [e (is (thrown? clojure.lang.ExceptionInfo (resolve-user! db nil)))]
        (is (str/includes? (ex-message e) "--user is required"))
        (is (str/includes? (ex-message e) "daniel (id 4)"))
        (is (not (str/includes? (ex-message e) "daniel-machine")) "machine users are not candidates")))
    (testing "a name that is not there is a refusal, not an empty walk"
      (is (thrown-with-msg? clojure.lang.ExceptionInfo #"no user \"nobody\""
                            (resolve-user! db "nobody"))))
    (testing "a machine user's name is half a scope, and half a scope is refused"
      (is (thrown-with-msg? clojure.lang.ExceptionInfo #"is a machine user"
                            (resolve-user! db "daniel-machine"))))))

(deftest a-row-that-moved-underneath-the-pass-is-not-written-over
  (testing "each write carries the values this pass read in its WHERE clause. A
    cutover should have nothing else writing; this is what says so instead of
    hoping, and it is what makes an interrupted pass safe to re-run."
    (let [db (fresh-db)
          row (first (filter #(= 1 (:id %)) (read-table db :tasks scope)))]
      (sqlite! db "UPDATE tasks SET description = CAST(X'6d6f766564' AS TEXT) WHERE id = 1;")
      (is (= "0" (str/trim (first (rows db (update-sql :tasks row {:description "new"} scope)))))
          "changes() — the row was not written")
      (is (= "moved" (value db :tasks :description "id=1"))))))

(deftest a-row-that-changed-hands-underneath-the-pass-is-not-written
  (testing "**the tracker half of what cookbook spells as `still-unpublished`.**
    Ownership is read once for a whole table and acted on row by row, and a row
    changing hands changes no prose value — so the compare-and-set on the value
    alone would have matched, and the pass would have sealed a row that had become
    antonio's in between. Staged the way a reviewer would stage it: read the row,
    hand it over, then run the write the pass would have run."
    (let [db (fresh-db)
          row (first (filter #(= 1 (:id %)) (read-table db :tasks scope)))
          before (raw db :tasks :description "id=1")]
      (sqlite! db (str "UPDATE tasks SET user_id = " antonio " WHERE id = 1;"))
      (is (= "0" (str/trim (first (rows db (update-sql :tasks row {:description "sealed"} scope)))))
          "changes() — the write did not land")
      (is (= before (raw db :tasks :description "id=1"))
          "and the prose is byte for byte the plaintext it was, not an envelope"))

    (testing "an event whose effective user changed is refused by the same conjunct"
      (let [db (fresh-db)
            row (first (filter #(= 1 (:id %)) (read-table db :events scope)))]
        (sqlite! db (str "UPDATE events SET effective_user_id = " antonio " WHERE id = 1;"))
        (is (= "0" (str/trim (first (rows db (update-sql :events row {:payload "{}"} scope))))))))))

(deftest another-users-sealed-row-is-a-violation-in-both-directions
  (testing "the *other* way the invariant is reported, and the one this pass
    exists to be able to make. It is asked of the database rather than of the
    values: no key, no decryption, and not one of another user's bodies crosses
    the sqlite3 boundary — only counts and ids do."
    (let [db (fresh-db)]
      (testing "a clean database has nobody else's prose sealed"
        (let [audit (into {} (for [{:keys [table rows sealed]} (foreign-audit db scope)]
                               [table [rows sealed]]))]
          (is (= [2 0] (get audit :tasks)) "antonio's row and the ownerless one")
          (is (= [1 0] (get audit :events)))
          (is (zero? (reduce + (map :sealed (foreign-audit db scope)))))))

      (testing "and one that has is named, in a pass and in a verify, whichever
        direction the pass is going"
        (sqlite! db (str "UPDATE tasks SET description = " (@#'walk/literal (sealed "antonio's, sealed"))
                         " WHERE id = 9;"))
        (is (= 1 (reduce + (map :sealed (foreign-audit db scope)))))
        (testing "and it is still not touched by anything here"
          (pass db :pass :unseal)
          (is (seal/sealed? (value db :tasks :description "id=9"))))))))

(deftest a-payload-holding-a-description-in-an-unknown-shape-is-reported
  (testing "the smoke alarm for the one failure the shapes cannot report about
    themselves: a payload holding a description somewhere `prose-paths` does not
    look would be walked by nobody, counted as clean, and left in the clear.
    It cannot seal anything and does not try — it says *look here*."
    (let [db (clean-db)]
      (insert! db :events {:id 2 :effective_user_id daniel :action "invented" :entity_type "task"
                           :payload (payload {:sixth-shape {:description "prose nobody walks"}})})
      (let [counts (pass db :pass :seal)]
        (is (= 1 (get counts :unwalked)))
        (is (= "prose nobody walks" (get-in (event-payload db 2) [:sixth-shape :description]))
            "reported and not guessed at: sealing it would be inventing a sixth shape here"))
      (let [{:keys [violations]} (pass db :verify :seal)]
        (is (= 1 (count (filter #(= :unwalked (:why %)) violations)))))))

  (testing "and the shapes that hold no literal description cannot make it fire"
    (let [db (clean-db)]
      (insert! db :events {:id 2 :effective_user_id daniel :action "update"
                           :payload (payload {:field "description" :old-value "a" :new-value "b"})})
      (insert! db :events {:id 3 :effective_user_id daniel :action "update"
                           :payload (payload {:changes {:description {:old "a" :new "b"}}})})
      (insert! db :events {:id 4 :effective_user_id daniel :action "create"
                           :payload (payload {:row {:description ""}})})
      (is (nil? (get (pass db :pass :seal) :unwalked)))
      (is (nil? (get (pass db :verify :seal) :unwalked))))))

(deftest the-walk-and-the-inventory-name-the-same-tables
  (testing "the guard that runs before anything else: a table added to
    `sealed-columns` and forgotten in the walk would be walked by nobody and
    reported by nothing, and a table added to `bound-as` alone would have a
    binding nobody uses"
    (is (= (set tables) (set (keys seal/sealed-columns))))
    (is (= (set walked) (set (keys seal/bound-as))))
    (is (= #{:events} (set (remove (set tables) walked)))
        "the audit log is walked and is not one of the nine: `payload` is a
         document with sealed values inside it, not a sealed column")))

(deftest decide-passes-a-migration-arity-seal-and-therefore-no-stored-value
  (testing "the trap the whole pass turns on. `seal` hands back `stored` when the
    value has not changed, so a walker that handed it the plaintext it just read
    would be told, correctly, that nothing had changed — and would seal nothing
    over the whole database while reporting a clean pass."
    (let [[bucket v] (walk/decide :seal @test-key seal/item-description-aad
                                  {:type :text :value "a body"})]
      (is (= :changed bucket))
      (is (seal/sealed? v))
      (is (= "a body" (seal/unseal @test-key :tasks :description v))))
    (testing "and the same value handed in as `stored` is what would have gone wrong"
      (is (= "a body" (seal/seal @test-key :tasks :description "a body" "a body")))))

  (testing "the same trap inside a payload, where there is no `stored` arity at all"
    (let [db (clean-db)]
      (pass db :pass :seal)
      (is (seal/sealed? (get-in (event-payload db 1) [:row :description]))))))

;; ---------------------------------------------------------------------------
;; The walker as a program. A migration script is run by a person watching a
;; shell, and by whatever they wrap it in, so the exit code is the whole of how a
;; pass is known to have finished — and the playbook's seal → verify → arm ladder
;; is mandatory on the strength of it.

(defn- run-env
  [env & args]
  (let [{:keys [exit out err]} (apply p/shell {:out :string :err :string :continue true
                                               :dir repo-root :extra-env env}
                                      "bb" "tracker_seal_migrate.clj" args)]
    {:exit exit :out out :err err}))

(defn- run-script [& args]
  (apply run-env {"TRACKER_SEAL_KEY" @test-key-base64} args))

(defn- flag [db username]
  (first (rows db (str "SELECT seal_prose FROM users WHERE username = '" username "';"))))

(deftest the-exit-code-is-the-contract
  (testing "an unmigrated database does not satisfy the seal invariant, and a
    missing file is a local error rather than a broken invariant"
    (let [db (fresh-db)]
      (is (= 1 (:exit (run-script "--verify" "--user" "daniel" db))))
      (is (= 2 (:exit (run-script "--verify" "--user" "daniel" "/tmp/there-is-no-tracker-here.db"))))))

  (testing "**a clean pass exits 0** — the negative control, without which none of
    the numbers here mean anything. Every rung of the playbook's ladder, in order."
    (let [db (clean-db)]
      (testing "the header carries the key's fingerprint: the same eight characters
        the browser's ⚙ panel shows, and the whole of how not to seal a database
        with a key the owner cannot open — which is the one mistake here with no
        recovery. The playbook's first instruction at the dry run is to compare it."
        (let [{:keys [out]} (run-script "--dry-run" "--user" "daniel" db)]
          (is (= 8 (count (seal/fingerprint @test-key))))
          (is (str/includes? out (str "fingerprint " (seal/fingerprint @test-key))))))
      (testing "and --verbose names the rows a dry run would write — table, id and
        column, and never a value"
        (let [{:keys [out]} (run-script "--dry-run" "--verbose" "--user" "daniel" db)]
          (is (str/includes? out "tasks            id 1       description"))
          (is (str/includes? out "events           id 1       payload"))
          (is (not (str/includes? out "a body")) "never a value")
          (is (not (str/includes? out "a created body")))))
      (testing "and the alarms the playbook's checklist names are printed whether
        or not they are zero — the table above them prints only the buckets that
        answered, and *these must all be 0* is answered badly by a column that is
        not there"
        (let [{:keys [out]} (run-script "--dry-run" "--user" "daniel" db)]
          (is (str/includes? out "unopenable 0 · nested 0 · odd 0 · unwalked 0 · moved 0"))
          (is (str/includes? out "sealed rows of other users 0"))))
      (is (= 0 (:exit (run-script "--dry-run" "--user" "daniel" db))))
      (is (= "a body" (value db :tasks :description "id=1")) "a dry run writes nothing")
      (is (= 0 (:exit (run-script "--user" "daniel" db))))
      (is (= 0 (:exit (run-script "--verify" "--user" "daniel" db))))
      (is (= 0 (:exit (run-script "--user" "daniel" db))) "and again, idempotently")
      (is (= 0 (:exit (run-script "--unseal" "--user" "daniel" db))))
      (is (= 0 (:exit (run-script "--verify" "--unseal" "--user" "daniel" db))))
      (testing "`--verify --inverse`, which is how the playbook's *Getting back*
        spells the same thing. Both are accepted, because a flag the procedure
        names and the program does not is a five-second failure at the worst
        possible moment."
        (is (= 0 (:exit (run-script "--verify" "--inverse" "--user" "daniel" db)))))))

  (testing "**--user is required and is never guessed.** The refusal names the
    candidates, so the answer is on the screen."
    (let [db (clean-db)
          {:keys [exit err]} (run-script db)]
      (is (= 2 exit))
      (is (str/includes? err "--user is required"))
      (is (str/includes? err "daniel (id 4)"))
      (is (= 2 (:exit (run-script "--user" "nobody" db))))
      (is (= 2 (:exit (run-script "--user" "daniel-machine" db))))
      (is (= "a body" (value db :tasks :description "id=1")) "and nothing was written")))

  (testing "**it refuses to run without a usable key**, unlike every other client
    here, because *no key* would mean a pass that walks the whole database, writes
    nothing, and reports success.

    The literal no-key case can only be exercised on a machine that holds no
    tracker key of its own: babashka takes `user.home` from the passwd database
    and not from `$HOME`, so a subprocess cannot be pointed at a home without one.
    The malformed case runs everywhere and is the same judgement — anything short
    of a usable key is a refusal, never a quiet pass-through."
    (let [db (clean-db)]
      (let [{:keys [exit err]} (run-env {"TRACKER_SEAL_KEY" "not base64 at all"}
                                        "--user" "daniel" db)]
        (is (= 2 exit))
        (is (str/includes? err "tracker seal key")))
      (when-not (.isFile ^java.io.File seal/key-file)
        (let [{:keys [exit err]} (run-env {"TRACKER_SEAL_KEY" ""} "--user" "daniel" db)]
          (is (= 2 exit))
          (is (str/includes? err "no key"))))
      (is (= "a body" (value db :tasks :description "id=1")) "and nothing was written")))

  (testing "**a nested envelope is a violation, in a pass and in a verify.** No
    correct client writes one; one that sealed a ciphertext it had echoed did, and
    a reader meets `enc:v1:…` where the prose should be."
    (let [db (clean-db)]
      (insert! db :tasks {:id 90 :user_id daniel :title "nested"
                          :description (nested "the prose under two layers")})
      (let [{:keys [exit out]} (run-script "--verify" "--user" "daniel" db)]
        (is (= 1 exit))
        (is (str/includes? out "NESTED")))
      (is (= 1 (:exit (run-script "--user" "daniel" db)))
          "and a pass over it does not report success either")
      (testing "`--unseal` opens one layer per run, and says the second is needed"
        (is (= 1 (:exit (run-script "--unseal" "--user" "daniel" db))))
        (is (= 0 (:exit (run-script "--unseal" "--user" "daniel" db))) "the second run finishes it")
        (is (= 0 (:exit (run-script "--verify" "--inverse" "--user" "daniel" db)))))))

  (testing "**another user's sealed row stops the pass**, in either direction, and
    is named without its value being read"
    (let [db (clean-db)]
      (sqlite! db (str "UPDATE tasks SET description = " (@#'walk/literal (sealed "antonio's, sealed"))
                       " WHERE id = 3;"))
      (let [{:keys [exit out]} (run-script "--user" "daniel" db)]
        (is (= 1 exit))
        (is (str/includes? out "belonging to another user"))
        (is (str/includes? out "tasks"))
        (is (not (str/includes? out "antonio's, sealed")) "the value is never printed"))))

  (testing "**M3: a journal beside the database is named on the way in and refused
    on the way out.** It is the one way an interrupted pass becomes a damaged
    production file, and it turns on what the operator does next — the
    procedure's next step being to copy the file somewhere."
    (let [db (clean-db)]
      (spit (str db "-journal") "not a real journal, but a file by that name")
      (let [{:keys [exit out]} (run-script "--user" "daniel" db)]
        (is (= 1 exit) "a run over a database with an unfinished write is not a clean answer")
        (is (str/includes? out "sat beside this database"))
        (is (str/includes? out "Never copy the .db anywhere")))
      (is (empty? (sidecars db)) "opening the database was the repair")
      (is (= 0 (:exit (run-script "--user" "daniel" db)))
          "and the next run, over the repaired file, is the one to trust"))))

(deftest a-flag-this-does-not-know-is-a-refusal-and-never-a-pass
  (testing "**Every deliberate mistake here is already caught and only a typo got
    through — into the one mode that cannot be undone.** A missing `--user`, a
    machine user's name, a missing key, two modes at once and `--arm --unseal` are
    all refusals. But an option this program does not know was parsed, kept under
    its misspelled key, and selected no mode at all — so the run fell through to
    the bare pass, which writes. `--dryrun` sealed the database it was asked to
    leave alone.

    So an unknown option is a refusal, before the key is loaded and before the
    database is opened."
    (doseq [flag ["--dryrun" "--dry_run" "-n" "--verfiy" "--unsel" "--am" "--Verify"]]
      (let [db (clean-db)
            {:keys [exit err]} (run-script flag "--user" "daniel" db)]
        (is (= 2 exit) (str flag " is not a flag this program has"))
        (is (str/includes? err flag) (str "and the refusal names " flag))
        (is (= "a body" (value db :tasks :description "id=1"))
            (str flag " wrote nothing")))))

  (testing "**a mode given a value that reads as false selects no mode**, which is
    the same fall-through by another spelling: `--verify false` and `--no-verify`
    both parse, both leave `chosen` empty, and both would run the pass. Every mode
    here is a switch — it is given or it is not."
    (doseq [args [["--verify" "false"] ["--verify=false"] ["--no-verify"]
                  ["--dry-run" "false"] ["--no-dry-run"] ["--no-unseal"]]]
      (let [db (clean-db)
            {:keys [exit err]} (apply run-script (concat args ["--user" "daniel" db]))]
        (is (= 2 exit) (str (pr-str args) " is a mode that was not asked for"))
        (is (str/includes? err "switch") (str "and says why: " (pr-str args)))
        (is (= "a body" (value db :tasks :description "id=1"))
            (str (pr-str args) " wrote nothing")))))

  (testing "**a second database on the command line is a refusal too.** It was
    dropped in silence, so `--user daniel A.db B.db` sealed `A.db`, said nothing
    about `B.db`, and looked exactly like a run that had done both."
    (let [a (clean-db)
          b (clean-db)
          {:keys [exit err]} (run-script "--user" "daniel" a b)]
      (is (= 2 exit))
      (is (str/includes? err b) "the refusal names the one it would have ignored")
      (is (= "a body" (value a :tasks :description "id=1")) "and neither was written")
      (is (= "a body" (value b :tasks :description "id=1")))))

  (testing "and the flags it does have still work, which is what makes the above a
    fix rather than a wall"
    (let [db (clean-db)]
      (is (= 0 (:exit (run-script "--dry-run" "--user" "daniel" db))))
      (is (= 0 (:exit (run-script "-h"))) "including the alias")
      (is (= "a body" (value db :tasks :description "id=1"))))))

(deftest arming-is-the-last-act-and-refuses-to-be-anything-else
  (testing "`users.seal_prose` is what makes the server refuse a write that would
    introduce new plaintext prose into this user's rows. **Armed over an
    unfinished pass it turns every remaining plaintext row into a row that cannot
    be saved** — so it is armed after `--verify` is green, and the program is what
    enforces that rather than the operator's memory."
    (let [db (fresh-db)]
      (let [{:keys [exit out]} (run-script "--arm" "--user" "daniel" db)]
        (is (= 1 exit))
        (is (str/includes? out "Refusing to arm")))
      (is (= "0" (flag db "daniel")) "and the flag did not move")

      (run-script "--user" "daniel" db)
      (testing "the fresh database still holds two values a pass cannot finish —
        one sealed under another key and one BLOB — so arming is still refused"
        (is (= 1 (:exit (run-script "--arm" "--user" "daniel" db))))
        (is (= "0" (flag db "daniel"))))))

  (testing "over a database whose verify is green it arms him, and nobody else"
    (let [db (clean-db)]
      (is (= 0 (:exit (run-script "--user" "daniel" db))))
      (let [{:keys [exit out]} (run-script "--arm" "--user" "daniel" db)]
        (is (= 0 exit))
        (is (str/includes? out "and nobody else")))
      (is (= "1" (flag db "daniel")))
      (is (= "0" (flag db "antonio")))
      (is (= "0" (flag db "saiyuri")))
      (testing "his machine user's row stays 0, and that is not an oversight: the
        server resolves the flag through an identity that has already collapsed a
        machine user onto the human he acts for"
        (is (= "0" (flag db "daniel-machine"))))
      (testing "arming twice is not an error and does not claim to have done
        anything"
        (let [{:keys [exit out]} (run-script "--arm" "--user" "daniel" db)]
          (is (= 0 exit))
          (is (str/includes? out "was armed already"))))
      (testing "and `--disarm` is the first act of getting back"
        (is (= 0 (:exit (run-script "--disarm" "--user" "daniel" db))))
        (is (= "0" (flag db "daniel")))
        (is (= 0 (:exit (run-script "--unseal" "--user" "daniel" db))))
        (is (= 0 (:exit (run-script "--verify" "--inverse" "--user" "daniel" db)))))))

  (testing "a database the server's half has not reached yet is refused before any
    walk over it: arming a flag the server does not understand would change
    nothing while reporting that it had"
    (let [db (clean-db)]
      (sqlite! db "ALTER TABLE users DROP COLUMN seal_prose;")
      (let [{:keys [exit err]} (run-script "--arm" "--user" "daniel" db)]
        (is (= 2 exit))
        (is (str/includes? err "074-add-seal-prose")))
      (is (= 2 (:exit (run-script "--disarm" "--user" "daniel" db))))))

  (testing "the flag is one job and the walk is another"
    (let [db (clean-db)]
      (is (= 2 (:exit (run-script "--arm" "--verify" "--user" "daniel" db))))
      (is (= 2 (:exit (run-script "--arm" "--unseal" "--user" "daniel" db))))
      (is (= "0" (flag db "daniel"))))))

;; ---------------------------------------------------------------------------

(defn- big-db
  "Enough rows that a pass over it takes seconds, so that a kill can land in the
  middle of one."
  []
  (let [db (with-users! (tmp-db "tracker-seal-walk-big"))]
    (sqlite! db (str "BEGIN;"
                     (str/join (for [i (range 1 401)]
                                 (str "INSERT INTO tasks (id, user_id, title, description) VALUES ("
                                      i ", " daniel ", 't', "
                                      (sql-value (str "body number " i ", which is prose.")) ");")))
                     (str/join (for [i (range 1 21)]
                                 (str "INSERT INTO events (id, effective_user_id, action, payload)"
                                      " VALUES (" i ", " daniel ", 'create', "
                                      (sql-value (payload {:row {:title "t"
                                                                 :description (str "event body " i)}}))
                                      ");")))
                     "COMMIT;"))
    db))

(defn- opened
  "A database's content with everything opened — the only way to compare two
  sealed databases, since a fresh nonce per value means two correct passes over
  the same rows produce different bytes. That is the point of the nonce, and it is
  why recipe 159 states the comparison as `unseal(a) == unseal(b)`."
  [db]
  (let [copy (str db ".opened")]
    (java.nio.file.Files/copy (.toPath (java.io.File. ^String db))
                              (.toPath (java.io.File. ^String copy))
                              (into-array java.nio.file.CopyOption
                                          [java.nio.file.StandardCopyOption/REPLACE_EXISTING]))
    (run-script "--unseal" "--user" "daniel" copy)
    (content copy)))

(deftest a-killed-pass-is-resumable-and-lands-where-an-uninterrupted-one-does
  (testing "**one row is one statement is one transaction**, so a kill mid-pass
    leaves a *legal* half-sealed database — mixed state is legal permanently,
    because unsealing is prefix-driven — and the next run picks up where this one
    stopped. Proved rather than reasoned about: killed with SIGKILL, verified,
    resumed, and compared against a database sealed in one go."
    (let [control (big-db)
          victim (big-db)
          total (parse-long (first (rows control "SELECT count(*) FROM tasks;")))
          sealed-in (fn [db] (parse-long (first (rows db "SELECT count(*) FROM tasks
                                                          WHERE description GLOB 'enc:v1:*';"))))
          started (System/currentTimeMillis)
          _ (is (= 0 (:exit (run-script "--user" "daniel" control))))
          ;; Half of however long the uninterrupted run took **on this machine**.
          ;; A fixed number of seconds would be a race on a slow one, and the
          ;; measurement is free: the control had to run anyway.
          half (format "%.2f" (/ (- (System/currentTimeMillis) started) 2000.0))
          {:keys [exit]} (p/shell {:out :string :err :string :continue true :dir repo-root
                                   :extra-env {"TRACKER_SEAL_KEY" @test-key-base64}}
                                  "timeout" "-s" "KILL" half "bb" "tracker_seal_migrate.clj"
                                  "--user" "daniel" victim)]
      (is (= 137 exit) "SIGKILL, which is the one signal nothing can clean up after")
      (let [part (sealed-in victim)]
        (is (pos? part) "the kill landed after some rows were written")
        (is (< part total) "and before the last one"))
      (let [{:keys [exit out]} (run-script "--verify" "--user" "daniel" victim)]
        (is (= 1 exit) "a half-sealed database does not satisfy the invariant")
        (is (str/includes? out "PLAINTEXT") "and says which values are the reason"))

      ;; **A killed pass leaves a `-journal` beside the file, in one of two
      ;; shapes**, and this is what an interrupted cutover actually looks like: the
      ;; kill lands on `bb`, the `sqlite3` it had started dies with it, and what it
      ;; leaves depends on how far into its one write it had got.
      ;;
      ;;   *hot* — bytes and a valid header. The database file is already modified
      ;;   and the pre-images are in the journal, so the **first connection to open
      ;;   the database at all, reader or writer, rolls it back and deletes it**.
      ;;   The count above is such a connection, so this often repairs itself.
      ;;
      ;;   *not hot* — created and not yet written, so zero length. SQLite ignores
      ;;   it, a read leaves it exactly there, and `sidecars` does not call it a
      ;;   stray, because it holds nothing the `.db` does not.
      ;;
      ;; Which of the two is there is a matter of microseconds, so the state is
      ;; **taken immediately before the run it describes** and with no `sqlite3`
      ;; call in between — the same discipline the walker keeps, and for the same
      ;; reason. A run that does meet one exits non-zero having done its work,
      ;; because the procedure's next step is *copy the file* and the run that
      ;; repaired a journal is not the run whose output to trust. The run after it
      ;; is. That is the playbook's rule, arrived at by killing something rather
      ;; than by writing a file called `-journal`.
      (let [strays (sidecars victim)
            {:keys [exit]} (run-script "--user" "daniel" victim)]
        (if (seq strays)
          (do (is (= 1 exit) "the run that repairs a journal does not report a clean pass")
              (is (empty? (sidecars victim)) "and opening it for writing was the repair"))
          (is (= 0 exit)
              "nothing was left holding state the .db does not, so there is nothing to repair")))

      (is (= 0 (:exit (run-script "--user" "daniel" victim))) "the resumed pass is clean")
      (is (= total (sealed-in victim)))
      (is (= 0 (:exit (run-script "--verify" "--user" "daniel" victim))))
      (is (not= (content control) (content victim))
          "sanity: the sealed bytes differ, which is what a fresh nonce per value is for")
      (is (= (opened control) (opened victim))
          "and what the resumed pass left is what an uninterrupted one would have —
           compared opened, because two correct passes cannot be compared sealed"))))

(deftest a-sidecar-is-judged-by-its-bytes-and-not-by-its-name
  (testing "**the bug this replaced.** `sidecars` asked whether a file called
    `-journal` or `-wal` existed, and the two mean opposite things: an interrupted
    write, and the ordinary resting state of a WAL database. `wal_checkpoint`
    truncates a `-wal` to zero bytes *without removing it*, and whether the empty
    file then survives the connection closing is the platform's business — this
    box's sqlite3 deletes it, a build with `SQLITE_FCNTL_PERSIST_WAL` keeps it. So
    the pass answered 0 on one machine and 1 on the other over the same database,
    and this suite was green here and red where it was read.

    The question is whether the file holds anything the `.db` does not, and the
    answer is its length."
    (let [db (str (tmp-db "tracker-seal-walk-sidecars"))]
      (sqlite! db schema)
      (is (= [] (sidecars db)) "nothing beside it")
      (spit (str db "-wal") "")
      (is (= [] (sidecars db)) "a zero-length -wal is what a checkpoint leaves: healthy")
      (spit (str db "-journal") "")
      (is (= [] (sidecars db))
          "and a zero-length -journal holds no pre-images — SQLite does not call
           one hot either, and journal_mode=truncate rests exactly there")
      (spit (str db "-wal") "pages this database has and the .db does not")
      (is (= ["-wal"] (sidecars db)))
      (spit (str db "-journal") "the pre-images of a write that did not finish")
      (is (= ["-journal" "-wal"] (sidecars db)) "named in a fixed order")
      (spit (str db "-wal") "")
      (is (= ["-journal"] (sidecars db)))))

  (testing "and a -shm is never one: it is an index rebuilt from the -wal, it
    holds nothing that is not elsewhere, and a read is enough to make one"
    (let [db (str (tmp-db "tracker-seal-walk-shm"))]
      (sqlite! db schema)
      (spit (str db "-shm") "32768 bytes of shared-memory index, in spirit")
      (is (= [] (sidecars db))))))

(deftest a-wal-database-has-its-pages-folded-back-in-before-the-pass-says-it-is-done
  (testing "tracker is in `delete` mode today, which is exactly the kind of thing
    that changes once. A WAL database keeps the newest pages in a sidecar file, and
    the procedure's next step is to copy the `.db` — so every mode that writes a
    row checkpoints, and `--arm`'s one-row write is a mode that writes a row."
    (let [db (clean-db)]
      (sqlite! db "PRAGMA journal_mode=WAL;")
      (is (= "wal" (first (rows db "PRAGMA journal_mode;"))))
      (let [{:keys [exit out]} (run-script "--user" "daniel" db)]
        (is (= 0 exit))
        (is (str/includes? out "WAL checkpointed")))
      (is (empty? (sidecars db)) "and nothing is left beside the file to be forgotten")
      (is (= 0 (:exit (run-script "--verify" "--user" "daniel" db))))
      (let [{:keys [exit out]} (run-script "--arm" "--user" "daniel" db)]
        (is (= 0 exit))
        (is (str/includes? out "WAL checkpointed")))
      (is (= "1" (flag db "daniel")))
      (is (empty? (sidecars db)))

      (testing "**and a zero-length -wal left beside it stops nothing.** This is
        the platform difference written down as a test: where sqlite3 keeps the
        truncated file, every one of the assertions above used to fail — the pass
        exited 1 over its own healthy checkpoint, which made `--verify` exit 1 and
        `--arm` refuse, so the flag stayed 0 and the cutover could not finish."
        (spit (str db "-wal") "")
        (is (= 0 (:exit (run-script "--verify" "--user" "daniel" db))))
        (spit (str db "-wal") "")
        (is (= 0 (:exit (run-script "--user" "daniel" db))))
        (spit (str db "-wal") "")
        (is (= 0 (:exit (run-script "--arm" "--user" "daniel" db)))))

      (testing "**a -wal with bytes in it is the dangerous case and still stops
        everything.** Pages the `.db` alone does not hold, whether they arrived
        from a copy taken live or from a checkpoint that could not complete
        because something else is holding the WAL open."
        (spit (str db "-wal") "bytes that are not in the .db")
        (let [{:keys [exit out]} (run-script "--verify" "--user" "daniel" db)]
          (is (= 1 exit))
          (is (str/includes? out "sat beside this database with bytes in it"))
          (is (str/includes? out "pages this database has and the .db file alone does")))
        (spit (str db "-wal") "bytes that are not in the .db")
        (is (= 1 (:exit (run-script "--user" "daniel" db)))
            "a pass over it is not a clean answer either, and the run after it is")
        (is (= 0 (:exit (run-script "--user" "daniel" db))))))))
