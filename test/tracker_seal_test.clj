(ns tracker-seal-test
  "The Clojure half of tracker's drift control.

  Everything textual in here comes out of
  `tracker/test/fixtures/seal-vectors.edn`, which tracker's ClojureScript suite
  and its server-side envelope test read as well. Nothing in this file invents a
  ciphertext: if the implementations ever disagree about the envelope, one of them
  goes red here.

  The shared half of the envelope is `seal-envelope`, and cookbook's suite pins
  the same code against cookbook's fixture. Between them, an edit to the cipher
  that satisfies one app and not the other cannot pass."
  (:require [clojure.test :refer [deftest is testing]]
            [cheshire.core :as json]
            [clojure.edn :as edn]
            [clojure.java.io :as io]
            [clojure.set]
            [clojure.string :as str]
            [et.tr.seal-rules :as rules]
            [seal-envelope :as env]
            [tracker-seal :as seal]))

(def ^:private vectors-path
  "The fixture lives in tracker, because the columns it names are tracker's. This
  repo reaches it as a sibling checkout — the idiom the cookbook suite beside this
  one already uses — or wherever TRACKER_SEAL_VECTORS says.

  **Missing is a failure, not a skip.** A fixture whose absence turns the suite
  green would be worse than no fixture: it would report agreement it never
  checked."
  (or (System/getenv "TRACKER_SEAL_VECTORS")
      "../tracker/test/fixtures/seal-vectors.edn"))

(def ^:private fixture
  (delay
    (let [f (io/file vectors-path)]
      (when-not (.exists f)
        (throw (ex-info (str "no seal vectors at " (.getAbsolutePath f)
                             " — check out tracker beside this repo, or set "
                             "TRACKER_SEAL_VECTORS")
                        {:path (.getAbsolutePath f)})))
      (edn/read-string (slurp f)))))

(defn- test-key [] (seal/key-from-base64 (:key-base64 @fixture)))
(defn- b64-decode [s] (.decode (java.util.Base64/getDecoder) ^String s))

;; ---------------------------------------------------------------------------
;; The contract the fixture states.

(deftest the-fixture-describes-the-envelope-this-file-implements
  (let [{:keys [prefix nonce-bytes tag-bits key-bytes]} (:envelope @fixture)]
    (is (= prefix seal/envelope-prefix))
    (is (= 12 nonce-bytes) "96 bits, the GCM standard")
    (is (= 128 tag-bits))
    (is (= 32 key-bytes) "AES-256")))

(deftest the-binding-is-the-one-the-fixture-names
  (is (= (into {} (for [[t b] (:binding @fixture)] [t (keyword b)]))
         seal/bound-as)
      "nine tables under one binding, plus events under its own — see bound-as"))

(deftest the-inventory-is-the-one-the-fixture-names
  (is (= (into {} (for [[t cs] (:sealed-columns @fixture)] [t (mapv keyword cs)]))
         seal/sealed-columns)))

(deftest the-inventory-is-nine-tables-of-one-column
  (is (= 9 (count seal/sealed-columns)))
  (is (every? #(= [:description] %) (vals seal/sealed-columns))
      "one column name everywhere, which is what makes one binding honest"))

(deftest the-clear-tables-do-not-overlap-the-sealed-ones
  (is (empty? (clojure.set/intersection
               (set (keys seal/sealed-columns))
               seal/clear-tables)))
  (is (contains? seal/clear-tables :messages)
      "messages are written by three keyless producers and their search reads the body")
  (is (contains? seal/clear-tables :mottos)
      "a motto's description is a second name, not prose — and its search reads it"))

(deftest the-fingerprint-is-the-one-the-fixture-names
  (is (= (:key-fingerprint @fixture) (seal/fingerprint (test-key)))
      "the eight characters the ⚙ panel, the proxy and the walker all show")
  (is (not= (:key-fingerprint @fixture)
            (seal/fingerprint (seal/key-from-base64 (:other-key-base64 @fixture))))))

;; ---------------------------------------------------------------------------
;; The two shared files, which each define the keyless half and must not drift.
;;
;; `seal_envelope.clj` carries its own `sealed?` and `blank-value?` because it is
;; shared with cookbook, which has no `.cljc` rules file to read them from. So
;; the predicates genuinely exist twice, and the answer to that is the answer it
;; always is here: not discipline, a test.

(deftest the-envelope-and-the-rules-agree-about-the-prefix
  (is (= env/envelope-prefix rules/envelope-prefix))
  (is (= seal/envelope-prefix rules/envelope-prefix)))

(deftest the-envelope-and-the-rules-agree-about-what-is-sealed
  (doseq [v (concat (:passthrough @fixture)
                    (:unopenable @fixture)
                    (:blank @fixture)
                    (map :sealed (:vectors @fixture))
                    [nil 7 :a-keyword])]
    (is (= (env/sealed? v) (rules/sealed? v))
        (str "the two spellings disagree about " (pr-str v)))))

(deftest the-envelope-and-the-rules-agree-about-what-is-blank
  (doseq [v (concat (:blank @fixture)
                    (:round-trip @fixture)
                    (:passthrough @fixture)
                    [nil 7 :a-keyword "  x  "])]
    (is (= (env/blank-value? v) (rules/blank-value? v))
        (str "the two spellings disagree about " (pr-str v)))))

(deftest the-rules-are-the-ones-the-seal-namespace-re-exports
  (is (= rules/bound-as seal/bound-as))
  (is (= rules/sealed-columns seal/sealed-columns))
  (is (identical? rules/prose-paths seal/prose-paths))
  (is (= rules/item-description-aad seal/item-description-aad)))

;; ---------------------------------------------------------------------------
;; The vectors.

(deftest every-vector-seals-to-exactly-the-recorded-ciphertext
  (let [k (test-key)]
    (doseq [{:keys [name aad nonce plaintext sealed]} (:vectors @fixture)]
      (testing name
        (is (= sealed (seal/seal-text-with-nonce k aad plaintext (b64-decode nonce))))))))

(deftest every-vector-unseals-back-to-its-plaintext
  (let [k (test-key)]
    (doseq [{:keys [name aad plaintext sealed]} (:vectors @fixture)]
      (testing name
        (is (= plaintext (seal/unseal-text k aad sealed)))))))

(deftest a-vector-resolves-the-aad-its-table-and-column-do
  (doseq [{:keys [name table column aad]} (:vectors @fixture)]
    (testing name
      (is (= aad (seal/aad table column))
          "what the fixture records and what a client would compute"))))

(deftest a-tampered-envelope-fails-to-open
  (doseq [{:keys [name aad key-base64 sealed]} (:tamper @fixture)]
    (testing name
      (is (thrown? Exception
                   (seal/unseal-text (seal/key-from-base64 key-base64) aad sealed))))))

(deftest a-tampered-envelope-is-handed-back-by-unseal-rather-than-thrown
  ;; Each case with **its own** key. The wrong-key case in the fixture is an
  ;; untampered ciphertext paired with a different key, so opening it with the
  ;; test key would succeed — which is the point of that case and not a failure.
  ;; The browser suite asserts the same thing, in the same way.
  (doseq [{:keys [name key-base64 sealed]} (:tamper @fixture)]
    (testing name
      (let [k (seal/key-from-base64 key-base64)]
        (is (= sealed (seal/unseal k :tasks :description sealed))
            "handed back, not thrown")))))

(deftest a-cookbook-ciphertext-does-not-open-as-a-tracker-item
  (let [t (first (filter #(str/includes? (:name %) "cookbook") (:tamper @fixture)))]
    (is (some? t) "the cross-app tamper case must be in the fixture")
    (is (= (:sealed t) (seal/unseal (test-key) :tasks :description (:sealed t)))
        "handed back, not opened and not thrown — one laptop holds both keys")))

(deftest a-round-trip-holds-for-a-fresh-nonce
  (let [k (test-key)]
    (doseq [p (:round-trip @fixture)]
      (is (= p (seal/unseal k :tasks :description
                            (seal/seal k :tasks :description p nil)))))))

(deftest the-same-sentence-seals-differently-every-time
  (let [k (test-key)
        p "the same body, twice"]
    (is (not= (seal/seal k :tasks :description p nil)
              (seal/seal k :tasks :description p nil))
        "a fresh nonce per value is what stops equality leaking")))

(deftest a-value-travels-between-all-nine-tables
  (let [k (test-key)
        sealed (seal/seal k :issues :description "an issue that becomes a task" nil)]
    (doseq [t (keys seal/sealed-columns)]
      (testing (str "read as " t)
        (is (= "an issue that becomes a task" (seal/unseal k t :description sealed))
            "one binding, because the server copies bodies between these without a key")))))

;; ---------------------------------------------------------------------------
;; The three rules.

(deftest blank-is-never-sealed
  (let [k (test-key)]
    (doseq [b (conj (:blank @fixture) nil)]
      (is (= b (seal/seal k :tasks :description b nil))))
    (is (= 7 (seal/seal k :tasks :description 7 nil))
        "a number in a prose column is not this function's problem to solve")))

(deftest unseal-passes-through-anything-without-the-prefix
  (let [k (test-key)]
    (doseq [p (:passthrough @fixture)]
      (is (= p (seal/unseal k :tasks :description p))))))

(deftest the-prefix-is-not-matched-loosely
  (doseq [p (:passthrough @fixture)]
    (is (false? (seal/sealed? p)) (str p " must read as plaintext"))))

(deftest a-prefixed-value-that-will-not-open-is-handed-back-not-thrown
  (let [k (test-key)]
    (doseq [u (:unopenable @fixture)]
      (is (= u (seal/unseal k :tasks :description u))
          "one unreadable value beside everything that reads beats a dropped response"))))

(deftest no-key-means-no-sealing
  (is (= "plain" (seal/seal nil :tasks :description "plain" nil)))
  (is (= "enc:v1:whatever" (seal/unseal nil :tasks :description "enc:v1:whatever"))))

(deftest an-unchanged-value-is-not-re-sealed
  (let [k (test-key)
        stored (seal/seal k :tasks :description "a body" nil)]
    (is (= stored (seal/seal k :tasks :description "a body" stored))
        "the plaintext half of the echo rule")))

(deftest an-echoed-envelope-this-key-can-open-is-a-no-op-and-not-a-second-envelope
  (let [k (test-key)
        stored (seal/seal k :tasks :description "a body" nil)
        out (seal/seal k :tasks :description stored stored)]
    (is (= stored out) "the bytes are compared before anything is opened")
    (is (= "a body" (seal/unseal k :tasks :description out))
        "and so it is not enc(enc(…)), which would open once into an envelope")))

(deftest an-envelope-with-nothing-to-compare-it-against-is-still-not-sealed-again
  (let [k (test-key)
        stored (seal/seal k :tasks :description "a body" nil)]
    (testing "nothing stored at all — a create, or a client that never read the row"
      (let [out (seal/seal k :tasks :description stored nil)]
        (is (= stored out)
            "a client only ever holds an envelope because it read one")
        (is (= "a body" (seal/unseal k :tasks :description out))
            "one open and the body — not a second envelope")))
    (testing "a stored value that is stale, or some other row's"
      (let [other (seal/seal k :tasks :description "something else" nil)
            out (seal/seal k :tasks :description stored other)]
        (is (= stored out))
        (is (= "a body" (seal/unseal k :tasks :description out)))))
    (testing "an envelope this key cannot open, with nothing stored"
      (let [foreign (seal/seal (seal/key-from-base64 (:other-key-base64 @fixture))
                               :tasks :description "someone else's key" nil)
            out (seal/seal k :tasks :description foreign nil)]
        (is (= foreign out)
            "sealing it would make it unopenable under two keys instead of one")))))

(deftest an-unchanged-value-on-an-unmigrated-row-stays-plaintext
  (let [k (test-key)]
    (is (= "not migrated yet" (seal/seal k :tasks :description "not migrated yet" "not migrated yet"))
        "a no-op stays a no-op in every state of the migration")))

(deftest an-unchanged-value-on-a-row-this-client-cannot-read-stays-put
  (let [k (test-key)
        foreign (seal/seal (seal/key-from-base64 (:other-key-base64 @fixture))
                           :tasks :description "someone else's key" nil)]
    (is (= foreign (seal/seal k :tasks :description foreign foreign))
        "otherwise every no-op nests one more envelope, on a row nobody can read")))

(deftest a-changed-value-is-sealed-afresh
  (let [k (test-key)
        stored (seal/seal k :tasks :description "before" nil)
        out (seal/seal k :tasks :description "after" stored)]
    (is (seal/sealed? out))
    (is (not= stored out))
    (is (= "after" (seal/unseal k :tasks :description out)))))

;; ---------------------------------------------------------------------------
;; Rows.

(deftest a-lean-row-gains-no-keys
  (let [k (test-key)
        lean {:id 1 :title "a task" :tags "x"}]
    (is (= lean (seal/seal-row k :tasks lean)))
    (is (= lean (seal/unseal-row k :tasks lean))
        "machine listings are lean on purpose; an unseal must not invent a body")))

(deftest a-row-seals-and-opens-its-body-and-nothing-else
  (let [k (test-key)
        row {:id 1 :title "a task" :tags "x" :description "the body"}
        sealed (seal/seal-row k :tasks row)]
    (is (= (dissoc row :description) (dissoc sealed :description)))
    (is (seal/sealed? (:description sealed)))
    (is (= row (seal/unseal-row k :tasks sealed)))))

(deftest a-row-echoes-what-has-not-changed
  (let [k (test-key)
        stored (seal/seal-row k :tasks {:id 1 :description "the body"})
        again (seal/seal-row k :tasks {:id 1 :description "the body"} stored)]
    (is (= stored again))))

(deftest sealed-in-answers-without-a-key
  (let [k (test-key)
        sealed (seal/seal-row k :tasks {:id 1 :description "the body"})]
    (is (= [:description] (seal/sealed-in :tasks sealed)))
    (is (= [] (seal/sealed-in :tasks {:id 1 :description "plain"})))
    (is (= [] (seal/sealed-in :tasks {:id 1})))))

;; ---------------------------------------------------------------------------
;; Prose inside the audit log.

(deftest every-event-shape-the-fixture-names-is-handled
  (let [k (test-key)
        shapes (:shapes (:event-prose @fixture))]
    (is (= 5 (count shapes)) "five builders in server/events.clj, five shapes")
    (is (= #{"create" "delete" "update-one" "update-many" "dropped-write"}
           (set (map :shape shapes))))))

(deftest a-create-payload-seals-its-body
  (let [k (test-key)
        out (seal/seal-payload k {:row {:title "a task" :description "the body"}})]
    (is (seal/sealed? (get-in out [:row :description])))
    (is (= "a task" (get-in out [:row :title])) "the title in the log stays clear")))

(deftest a-payload-for-a-row-with-no-body-gains-no-body
  (let [k (test-key)
        payload {:row {:title "a task"}}]
    (is (= payload (seal/seal-payload k payload))
        "update-in would have invented a :description nil and asserted something false")))

(deftest a-delete-snapshot-seals-its-body
  (let [k (test-key)]
    (is (seal/sealed? (get-in (seal/seal-payload k {:snapshot {:description "gone"}})
                              [:snapshot :description])))))

(deftest a-single-field-update-seals-both-sides
  (let [k (test-key)
        out (seal/seal-payload k {:field "description" :old-value "was" :new-value "is"})]
    (is (seal/sealed? (:old-value out)))
    (is (seal/sealed? (:new-value out)))
    (is (= "description" (:field out)))))

(deftest a-blank-old-value-stays-blank-inside-a-payload
  (let [k (test-key)
        out (seal/seal-payload k {:field "description" :old-value "" :new-value "is"})]
    (is (= "" (:old-value out))
        "an empty old-value means the body was empty before the edit, and that is not a thing to encrypt")))

(deftest an-update-to-some-other-field-is-untouched
  (let [k (test-key)
        payload {:field "title" :old-value "a" :new-value "b"}]
    (is (= payload (seal/seal-payload k payload)))))

(deftest a-many-field-update-seals-only-the-description
  (let [k (test-key)
        out (seal/seal-payload k {:changes {:description {:old "o" :new "n"}
                                            :title {:old "x" :new "y"}}})]
    (is (seal/sealed? (get-in out [:changes :description :old])))
    (is (seal/sealed? (get-in out [:changes :description :new])))
    (is (= {:old "x" :new "y"} (get-in out [:changes :title])))))

(deftest a-dropped-write-seals-its-captured-body-under-its-own-binding
  (let [k (test-key)
        raw "{\"description\":\"what the machine tried to write\"}"
        out (seal/seal-payload k {:method "put" :uri "/api/tasks/1" :body raw :reason "recording-off"})]
    (is (seal/sealed? (:body out)))
    (is (= "/api/tasks/1" (:uri out)))
    (is (= raw (:body (seal/unseal-payload k out))))
    (is (= raw (seal/unseal k :events :body (:body out)))
        "it opens under the binding it was sealed with")
    (is (= (:body out) (seal/unseal k :tasks :description (:body out)))
        "and not as a description: a captured request body is a JSON document that
         may contain one, so binding it as one would let it be lifted into a column")))

(deftest a-link-payload-carries-no-prose-and-is-left-alone
  (let [k (test-key)
        payload {:category-type "person" :category-id 3 :category-title "Andrew"}]
    (is (= payload (seal/seal-payload k payload)))))

(deftest a-payload-round-trips
  (let [k (test-key)]
    (doseq [payload [{:row {:title "t" :description "b"}}
                     {:snapshot {:description "gone"}}
                     {:field "description" :old-value "was" :new-value "is"}
                     {:changes {:description {:old "o" :new "n"} :title {:old "x" :new "y"}}}
                     {:method "put" :uri "/u" :body "{}" :reason "r"}]]
      (is (= payload (seal/unseal-payload k (seal/seal-payload k payload)))))))

(deftest payload-sealed-asks-without-a-key
  (let [k (test-key)]
    (is (true? (seal/payload-sealed? (seal/seal-payload k {:row {:description "b"}}))))
    (is (false? (seal/payload-sealed? {:row {:description "b"}})))
    (is (false? (seal/payload-sealed? {:category-type "person"})))))

(deftest no-key-leaves-a-payload-alone
  (let [payload {:row {:title "t" :description "b"}}]
    (is (= payload (seal/seal-payload nil payload)))
    (is (= payload (seal/unseal-payload nil payload)))))

;; ---------------------------------------------------------------------------
;; The read path and the write path's knowledge, which both clients share.
;;
;; These are the same questions `et.tr.ui.seal-test` asks of the browser. The
;; answers come out of `et.tr.seal-rules`, so a disagreement here means one host
;; is reading a different file than it thinks it is.

(deftest an-endpoint-names-the-table-its-own-rows-belong-to
  (is (= :tasks (seal/endpoint-table "/api/tasks/123")))
  (is (= :tasks (seal/endpoint-table "/api/tasks")))
  (is (= :categories (seal/endpoint-table "/api/people/7"))
      "six Groups, one table, since 073-unify-category-tables")
  (is (= :journal_entries (seal/endpoint-table "/api/journal-entries/9?detail=full")))
  (is (nil? (seal/endpoint-table "/api/today-board"))
      "its rows are not its own; the path into the body is what says whose they are")
  (is (nil? (seal/endpoint-table "/api/messages/3"))
      "and this is what keeps message bodies in the clear on the write path")
  (is (nil? (seal/endpoint-table "/api/mottos/2"))
      "same, and for the reason clear-tables gives"))

(deftest a-message-conversion-names-the-table-it-writes-into-and-not-its-own
  (testing "the two that delete their own original"
    (is (= :tasks (rules/convert-target "/api/messages/7/convert-to-task")))
    (is (= :resources (rules/convert-target "/api/messages/7/convert-to-resource"))))
  (testing "**an issue conversion is not one of them.** It copies ciphertext to
    ciphertext under the single binding, server-side, and is genuinely fine —
    catching it here would demand a sealed body the browser has no reason to send."
    (is (nil? (rules/convert-target "/api/issues/7/convert-to-task"))))
  (testing "and nothing else is either"
    (doseq [p ["/api/messages/7" "/api/messages" "/api/tasks/7"
               "/api/messages/7/convert-to-nothing" "/api/today-board" nil]]
      (is (nil? (rules/convert-target p)) (str p))))
  (testing "`endpoint-table` still answers nil for the same path, and must:
    a message body is never sealed, and its own id is the one in this URL"
    (is (nil? (seal/endpoint-table "/api/messages/7/convert-to-task")))
    (is (= 7 (seal/endpoint-id "/api/messages/7/convert-to-task"))
        "which is the *message's* id — echoing [:tasks 7 :description] against it
         would seal some unrelated task's ciphertext into the new row, so a
         convert is treated as the create it is and echoes nothing")))

(deftest a-message-conversion-is-a-write-target-and-says-where-its-prose-is
  ;; `write-target` is what a process that sees one request asks instead of
  ;; keeping an index — `plurama-cli` and the proxy sidecar both. Built on
  ;; `endpoint-table` alone it answers `nil` for every path under `messages`,
  ;; which is right for `PUT /api/messages/3` and wrong for the one write under
  ;; `messages` that lands in a sealed column. Without this the box agent's
  ;; convert is refused by the server forever, for an armed user, with no client
  ;; anywhere able to satisfy it.
  (let [t (seal/write-target "/api/messages/7/convert-to-task")]
    (is (= :tasks (:table t))
        "the table it writes into, and not the one its path names")
    (is (nil? (:id t))
        "a convert is a create: no row yet, and therefore nothing to echo")
    (is (nil? (seal/state-path t))
        "so there is no state read either — and the 7 is the *message's*, so a
         read of /api/tasks/7 would answer for a row nobody mentioned")
    (is (= "/api/messages/7" (:body-from t))
        "the prose it has to carry is over there, in the row it is about to
         delete, and this is the only thing that can say so"))
  (testing "to a resource, the same shape"
    (let [t (seal/write-target "/api/messages/7/convert-to-resource")]
      (is (= :resources (:table t)))
      (is (nil? (:id t)))
      (is (= "/api/messages/7" (:body-from t)))))
  (testing "and every other path answers exactly what it answered before"
    (is (nil? (seal/write-target "/api/messages/7"))
        "an ordinary message write carries no sealed prose and must not gain any")
    (is (nil? (seal/write-target "/api/messages")))
    (is (= {:table :tasks :segment "tasks" :id 7} (seal/write-target "/api/tasks/7")))
    (is (= {:table :categories :segment "people" :id 7} (seal/write-target "/api/people/7"))
        "the segment is carried because six of them map to :categories")
    (is (nil? (:body-from (seal/write-target "/api/issues/7/convert-to-task")))
        "an issue conversion moves ciphertext to ciphertext server-side and has
         no original to lose — it is not one of the two")))

(deftest an-endpoint-names-the-row-when-it-has-one
  (is (= 123 (seal/endpoint-id "/api/tasks/123")))
  (is (= 9 (seal/endpoint-id "/api/journal-entries/9?detail=full")))
  (is (nil? (seal/endpoint-id "/api/tasks")) "a create has no row to echo")
  (is (nil? (seal/endpoint-id "/api/tasks/today-board"))))

(deftest a-response-is-indexed-by-row-and-never-by-text
  (let [k (test-key)
        ct (seal/seal k :tasks :description "a body" nil)]
    (is (= [[:tasks 7 :description ct]]
           (seal/stored-entries "/api/tasks/7" {:id 7 :description ct})))
    (testing "an aggregate gets its table from the path, not the endpoint"
      (is (= [[:tasks 1 :description ct]
              [:categories 9 :description ct]
              [:meets 2 :description ct]
              [:journal_entries 3 :description ct]]
             (seal/stored-entries "/api/today-board"
                                  {:tasks [{:id 1 :description ct
                                            :categories [{:id 9 :description ct}]}]
                                   :meets [{:id 2 :description ct}]
                                   :journal-entries [{:id 3 :description ct}]}))))
    (testing "reports spells journal entries the other way, and both must index"
      (is (= [[:journal_entries 4 :description ct]]
             (seal/stored-entries "/api/reports" {:journal_entries [{:id 4 :description ct}]}))))
    (testing "uncertainty degrades to not indexing, never to guessing"
      (is (= [] (seal/stored-entries "/api/tasks" [{:description ct}])) "no id")
      (is (= [] (seal/stored-entries "/api/whatever" {:blah {:description ct}})) "no table")
      (is (= [] (seal/stored-entries "/api/messages/3" {:id 3 :description ct})) "not a sealed table"))))

(deftest a-response-body-opens-wherever-the-prose-is
  (let [k (test-key)
        ct #(seal/seal k :tasks :description % nil)
        body {:tasks [{:id 1 :title "t" :description (ct "a body")
                       :categories [{:id 9 :name "Andrew" :description (ct "a person")}]}]
              :messages [{:id 5 :description "a plaintext inbox body"}]
              :events [{:id 7 :payload {:row {:title "x" :description (ct "created")}}}]}
        out (seal/unseal-response-body k body)]
    (is (= "a body" (get-in out [:tasks 0 :description])))
    (is (= "a person" (get-in out [:tasks 0 :categories 0 :description]))
        "a category nested in a task is found without anyone remembering it is there")
    (is (= "created" (get-in out [:events 0 :payload :row :description])))
    (is (= "a plaintext inbox body" (get-in out [:messages 0 :description]))
        "never sealed, so never collected — the read path needs no opinion about tables")))

(deftest a-listing-arrives-parsed-and-not-written-by-hand
  ;; What this covers that every test above it cannot.
  ;;
  ;; Every other body in this file is a Clojure literal, and a literal `[...]` is
  ;; a **vector** — associative, so `update-in` walks into it by index without
  ;; complaint. Production bodies are not written by hand: they come off the wire
  ;; through `json/parse-string`, and cheshire hands a **top-level JSON array
  ;; back as a `LazySeq`**, which is not associative. `update-in` through an
  ;; integer index into one throws `ClassCastException`, and
  ;; `tracker-unseal-response` caught that and returned the response untouched —
  ;; so `GET /api/tasks` served every body as `enc:v1:…` with a 200 and no error
  ;; anywhere.
  ;;
  ;; The shape under test had therefore never been the shape in production, and
  ;; no number of literal-built fixtures would have found it. So this one builds
  ;; its body the way the CLI does: serialise, then parse. That is the whole
  ;; point of it, and it is why the `generate-string` here is not ceremony for a
  ;; later reader to optimise away.
  ;;
  ;; The detail read is asserted beside it deliberately. `/api/tasks/1229` kept
  ;; working right through the outage, because its path is `[:description]` at
  ;; top level and never touches an index — which is exactly what made the bug
  ;; look like a key problem rather than a shape problem.
  (let [k (test-key)
        ct #(seal/seal k :tasks :description % nil)
        parsed #(json/parse-string (json/generate-string %) true)
        listing (parsed [{:id 1229 :title "t" :description (ct "abc 9")}
                         {:id 1230 :title "u" :description (ct "abc 10")}])
        detail (parsed {:id 1229 :title "t" :description (ct "abc 9")})]
    (testing "the premise: a shape no literal in this file can produce"
      (is (seq? listing) "cheshire parses a top-level JSON array to a LazySeq")
      (is (not (associative? listing)) "…which update-in cannot walk into"))
    (testing "a listing opens"
      (let [out (seal/unseal-response-body k listing)]
        (is (= ["abc 9" "abc 10"] (mapv :description out)))
        (is (associative? out)
            "and comes back associative, so a caller may get-in by index")))
    (testing "a detail opens — it always did, which is what hid the listing"
      (is (= "abc 9" (:description (seal/unseal-response-body k detail)))))
    (testing "an array nested under a key opens too"
      (is (= "nested"
             (get-in (seal/unseal-response-body
                      k (parsed {:tasks [{:id 1 :description (ct "nested")}]}))
                     [:tasks 0 :description]))))))

(deftest a-parsed-listing-with-nothing-sealed-still-passes-through
  ;; The cheap path has to survive the coercion. `tracker-unseal-response` sends
  ;; the original bytes on when `(= body out)`, and that is what keeps an
  ;; unsealed database's responses byte-identical. This pins the stronger claim —
  ;; the *same object* back — because a coercion applied before the paths were
  ;; counted would rebuild every response in the estate, and nothing else here
  ;; would have said so.
  (let [body (json/parse-string
              (json/generate-string [{:id 1 :description "not migrated yet"}])
              true)
        out (seal/unseal-response-body (test-key) body)]
    (is (identical? body out)
        "one walk, no crypto, no rebuild — every response before the cutover")))

(deftest a-body-with-nothing-sealed-comes-back-identical
  (let [k (test-key)
        body {:tasks [{:id 1 :description "not migrated yet"}]}]
    (is (identical? body (seal/unseal-response-body k body))
        "one walk and no crypto — every response before the cutover")))

;; ---------------------------------------------------------------------------
;; A live failure, pinned.

(deftest a-directory-at-the-key-path-means-no-key-and-not-a-crash
  ;; A docker bind mount whose source is missing creates an empty **directory**
  ;; at the destination rather than failing. The compose file mounts a key per
  ;; sealing app whether or not that app's ceremony has happened yet — so on the
  ;; day tracker's mount was added and its key did not exist, every client that
  ;; tested `.exists` read a directory as a malformed key. The proxy sidecar took
  ;; that as "stop the process", which is right for a malformed key and wrong for
  ;; this, and crash-looped the whole devbox.
  ;;
  ;; A directory here means the same thing as absence: nothing named a key, so
  ;; sealing is off.
  (let [dir (java.io.File. (System/getProperty "java.io.tmpdir")
                           (str "tracker-seal-key-dir-" (System/currentTimeMillis)))
        spec {:app "tracker"
              ;; Names no real env var, so resolution falls through to the
              ;; default file -- which is the directory.
              :env-var "TRACKER_SEAL_KEY_ABSENT_IN_TEST"
              :file-var "TRACKER_SEAL_KEY_FILE_ABSENT_IN_TEST"
              :default-file dir}]
    (try
      (.mkdirs dir)
      (is (nil? (env/key-location spec)) "a directory is not a key location")
      (is (nil? (env/load-key spec)) "and so sealing is simply off, as it is for any absent key")
      (is (nil? (env/key-source spec)) "and nothing reports sealing as on")
      (finally (.delete dir)))))
