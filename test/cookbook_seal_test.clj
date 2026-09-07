(ns cookbook-seal-test
  "The Clojure half of the drift control.

  Everything textual in here comes out of
  `cookbook/test/fixtures/seal-vectors.edn`, which cookbook's ClojureScript suite
  reads as well. Nothing in this file invents a ciphertext: if the two suites
  ever disagree about the envelope, one of them goes red here."
  (:require [clojure.test :refer [deftest is testing]]
            [clojure.edn :as edn]
            [clojure.java.io :as io]
            [cookbook-seal :as seal]))

(def ^:private vectors-path
  "The fixture lives in cookbook, because the columns it names are cookbook's.
  This repo reaches it as a sibling checkout — the idiom cookbook's own deps.edn
  already uses for us-vs-them — or wherever COOKBOOK_SEAL_VECTORS says.

  **Missing is a failure, not a skip.** A fixture whose absence turns the suite
  green would be worse than no fixture: it would report agreement it never
  checked."
  (or (System/getenv "COOKBOOK_SEAL_VECTORS")
      "../cookbook/test/fixtures/seal-vectors.edn"))

(def ^:private fixture
  (delay
    (let [f (io/file vectors-path)]
      (when-not (.exists f)
        (throw (ex-info (str "no seal vectors at " (.getAbsolutePath f)
                             " — check out cookbook beside this repo, or set "
                             "COOKBOOK_SEAL_VECTORS")
                        {:path (.getAbsolutePath f)})))
      (edn/read-string (slurp f)))))

(defn- test-key [] (seal/key-from-base64 (:key-base64 @fixture)))

(defn- b64-decode [s] (.decode (java.util.Base64/getDecoder) ^String s))

(deftest the-fixture-describes-the-envelope-this-file-implements
  (let [{:keys [prefix nonce-bytes tag-bits key-bytes]} (:envelope @fixture)]
    (is (= prefix seal/envelope-prefix))
    (is (= 12 nonce-bytes))
    (is (= 128 tag-bits))
    (is (= 32 key-bytes))
    (is (= 32 (count (b64-decode (:key-base64 @fixture)))))))

(deftest the-binding-is-the-one-the-fixture-names
  (testing "three tables under one name, because the server copies between them"
    (is (= (:binding @fixture)
           (into {} (for [[table binding] seal/bound-as] [table (name binding)]))))
    (is (= (set (keys seal/sealed-columns)) (set (keys seal/bound-as)))
        "every sealed table has a binding, and nothing else does")))

(deftest the-published-surface-is-the-one-the-fixture-names
  (testing "three clients implement the publish interlock; one of them widening
    while another did not is how a sealed column stays reachable through the
    narrower one. So the pair is in the fixture, like the binding and the
    inventory, and each client asserts its own list against it."
    (is (= (:published-surface @fixture) (mapv name seal/published-surface)))
    (testing "and it is a subset of what is actually sealed"
      (is (every? (set (:recipes seal/sealed-columns)) seal/published-surface)))
    (testing "the reason/context pair is not in it — a visitor is served neither"
      (is (not-any? #{:reason :context} seal/published-surface)))))

(deftest published-surface-sealed?-is-what-the-two-binaries-ask
  (let [k (test-key)
        sealed (seal/seal k :recipes :description "a sealed body")
        sealed-line (seal/seal k :recipes :useful_when "a sealed line")]
    (is (true? (seal/published-surface-sealed? {:description sealed :useful_when "clear"})))
    (is (true? (seal/published-surface-sealed? {:description "clear" :useful_when sealed-line}))
        "a sealed useful-when alone is still a published surface")
    (is (false? (seal/published-surface-sealed? {:description "clear" :useful_when "clear"})))
    (is (false? (seal/published-surface-sealed? {}))
        "fail-open on a row nothing was read for, as the callers document")
    (testing "and a sealed reason does not make publishing wrong"
      (is (false? (seal/published-surface-sealed?
                   {:description "clear" :useful_when "clear"
                    :reason (seal/seal k :recipes :reason "why")}))))))

(deftest the-fingerprint-is-the-one-the-fixture-names
  (testing "the eight characters the ⚙ panel shows and the migration walker prints
    before it seals a database. They are compared by eye, across two
    implementations, ahead of the one act here that cannot be undone — so the
    answer for the fixture key is written down once and both suites assert it.
    Nothing binds a ciphertext to it; it names a key, it is not part of the
    envelope."
    (is (= (:key-fingerprint @fixture) (seal/fingerprint (test-key))))
    (is (= 8 (count (seal/fingerprint (test-key)))) "four bytes, hex")
    (is (not= (:key-fingerprint @fixture)
              (seal/fingerprint (seal/key-from-base64 (:other-key-base64 @fixture))))
        "and a different key is a different name")))

(deftest a-value-travels-between-the-three-recipe-tables
  (testing "archive! and approve-proposal! copy verbatim and hold no key"
    (let [k (test-key)
          sealed (seal/seal k :recipes :description "the body, as saved")]
      (doseq [table [:recipes :recipe_history :recipe_proposals]]
        (testing (name table)
          (is (= "the body, as saved" (seal/unseal k table :description sealed))
              "a save archives this value into recipe_history untouched")))
      (testing "and still refuses the moves the server never makes"
        (is (thrown? Exception (seal/unseal-text k (seal/aad :recipes :useful_when) sealed)))
        (is (thrown? Exception (seal/unseal-text k (seal/aad :scopes :description) sealed)))))))

(deftest every-vector-seals-to-exactly-the-recorded-ciphertext
  (let [k (test-key)]
    (doseq [{:keys [name aad nonce plaintext sealed]} (:vectors @fixture)]
      (testing name
        (is (= sealed (seal/seal-text-with-nonce k aad plaintext (b64-decode nonce)))
            "same key, same nonce, same AAD must give the same envelope")))))

(deftest every-vector-unseals-back-to-its-plaintext
  (let [k (test-key)]
    (doseq [{:keys [name aad plaintext sealed]} (:vectors @fixture)]
      (testing name
        (is (= plaintext (seal/unseal-text k aad sealed)))))))

(deftest the-column-api-agrees-with-the-raw-one
  (let [k (test-key)]
    (doseq [{:keys [name table column plaintext sealed]} (:vectors @fixture)]
      (testing name
        (is (= plaintext (seal/unseal k table column sealed))
            "unseal derives the AAD from the column it was handed")))))

(deftest blank-is-never-sealed
  (let [k (test-key)]
    (testing "nil stays nil — 'not recorded' is not 'recorded, and nothing'"
      (is (nil? (seal/seal k :recipes :reason nil))))
    (doseq [blank (:blank @fixture)]
      (testing (pr-str blank)
        (is (= blank (seal/seal k :recipes :description blank))
            "byte-identical, not normalised")))))

(deftest unseal-passes-through-anything-without-the-prefix
  (let [k (test-key)]
    (testing "nil"
      (is (nil? (seal/unseal k :recipes :description nil))))
    (doseq [v (:passthrough @fixture)]
      (testing (pr-str v)
        (is (= v (seal/unseal k :recipes :description v)))
        (is (false? (seal/sealed? v)))))))

(deftest a-prefixed-value-that-will-not-open-is-handed-back-not-thrown
  (testing "rule 3 is about the prefix, and the prefix is not a promise that it opens"
    (let [k (test-key)]
      (doseq [v (:unopenable @fixture)]
        (testing (pr-str v)
          (is (= v (seal/unseal k :recipes :description v))
              "handed back, not thrown: one bad value must not cost a whole response")
          (testing "and it does not fail a write either"
            (let [out (seal/seal k :recipes :description "the new text" v)]
              (is (seal/sealed? out))
              (is (= "the new text" (seal/unseal k :recipes :description out)))))
          (testing "and writing it back unchanged is a no-op, not a second envelope"
            ;; The shape the two clients diverged on: `v` and `stored` both the
            ;; unopenable value. A wrong or rotated key hands a client
            ;; `enc:v1:…` where prose should be; a save of "keep everything"
            ;; writes exactly that back. Sealing it would store
            ;; enc_new(enc_old(…)), and the next no-op would nest it again,
            ;; once per cycle without bound, on a Recipe nobody can read to
            ;; notice.
            (is (= v (seal/seal k :recipes :description v v)))))))))

(deftest a-tampered-envelope-fails-to-open
  (doseq [{:keys [name aad sealed key-base64]} (:tamper @fixture)]
    (testing name
      (is (thrown? Exception
                   (seal/unseal-text (seal/key-from-base64 key-base64) aad sealed))))))

(deftest unseal-of-a-value-that-will-not-open-hands-it-back
  (testing "a wrong key must not take a whole response down; it must be visibly unreadable"
    (let [k (seal/key-from-base64 (:other-key-base64 @fixture))
          {:keys [sealed table column]} (first (:vectors @fixture))]
      (is (= sealed (seal/unseal k table column sealed)))
      (testing "and a whole body is unsealed as far as it can be, not abandoned"
        (let [readable (seal/seal k :recipes :useful_when "this one opens")
              out (seal/unseal-body k {:id 1 :version 2 :description sealed
                                       :useful_when readable})]
          (is (= sealed (:description out)))
          (is (= "this one opens" (:useful_when out))))))))

(deftest a-round-trip-holds-for-a-fresh-nonce
  (let [k (test-key)]
    (doseq [plaintext (:round-trip @fixture)]
      (testing (pr-str plaintext)
        (let [sealed (seal/seal-text k (seal/aad :recipes :description) plaintext)]
          (is (seal/sealed? sealed))
          (is (= plaintext (seal/unseal-text k (seal/aad :recipes :description) sealed))))))))

(deftest the-same-sentence-seals-differently-every-time
  (let [k (test-key)
        text "Two Recipes may legitimately say the same thing."]
    (is (not= (seal/seal k :recipes :description text)
              (seal/seal k :recipes :description text))
        "a fresh nonce per value is what stops equality leaking")))

(deftest an-unchanged-value-is-not-re-sealed
  (testing "the rule that keeps content-would-change? working, server-side and untouched"
    (let [k (test-key)
          stored (seal/seal k :recipes :description "The text as it stands.")]
      (is (= stored (seal/seal k :recipes :description "The text as it stands." stored))
          "byte-identical echo, so the server's equality still sees a no-op")
      (is (not= stored (seal/seal k :recipes :description "Something else." stored))
          "a genuine change gets a fresh nonce")
      (is (= "The text as it stands."
             (seal/unseal k :recipes :description
                          (seal/seal k :recipes :description "The text as it stands." stored)))))))

(deftest an-echoed-envelope-this-key-can-open-is-a-no-op-and-not-a-second-envelope
  (testing "**the shape the rule was wrong about**, found in review. `v` and
    `stored` both the stored ciphertext, and this key opens it: `unseal` answers
    the *plaintext*, `v` is the *ciphertext*, they differ — so the rule as written
    sealed the ciphertext and stored enc(enc(…)), which opens once into an
    envelope and reads as one, with nothing anywhere reporting an error.

    It is not a shape nobody sends. The proxy sidecar permits exactly this value
    through its double-seal refusal, on the grounds that an echo is a no-op; the
    grounds were false. Every write of it nested one more layer."
    (let [k (test-key)
          stored (seal/seal k :recipes :description "The text as it stands.")]
      (is (= stored (seal/seal k :recipes :description stored stored))
          "byte-identical, and no second envelope")
      (is (= "The text as it stands." (seal/unseal k :recipes :description
                                                   (seal/seal k :recipes :description stored stored)))
          "one unseal reaches the prose, which is what nesting would have broken")
      (testing "and the same for every column and table the fixture names, since a
        nested value is unreadable in whichever of them it lands"
        (doseq [{:keys [table column sealed]} (:vectors @fixture)]
          (is (= sealed (seal/seal (test-key) table column sealed sealed)))))))

  (testing "a *different* envelope over an openable stored one is still a write:
    the byte test must not swallow a real change"
    (let [k (test-key)
          stored (seal/seal k :recipes :description "the old text")
          other (seal/seal k :recipes :description "a value from somewhere else")
          out (seal/seal k :recipes :description other stored)]
      (is (not= stored out))
      (is (seal/sealed? (seal/unseal k :recipes :description out))
          "and it nests, because that is what writing an envelope as prose means —
           this is nit 9 and is still deliberately not guarded here; what guards it
           is the proxy's refusal and, since this round, `--verify`"))))

(deftest an-unopenable-stored-value-does-not-block-the-write
  (let [k (test-key)
        other (seal/key-from-base64 (:other-key-base64 @fixture))
        stored (seal/seal other :recipes :description "Sealed under a key we do not hold.")
        out (seal/seal k :recipes :description "The new text." stored)]
    (is (not= stored out))
    (is (= "The new text." (seal/unseal k :recipes :description out)))))

(deftest an-unchanged-value-on-an-unmigrated-row-stays-plaintext
  (testing "the mixed-state window: clients deployed first, data sealed later"
    (let [k (test-key)
          text "unchanged since before the migration"]
      (is (= text (seal/seal k :recipes :description text text))
          "a no-op stays a no-op — the server sees the same value and writes no version")
      (is (not (seal/sealed? (seal/seal k :recipes :description text text)))
          "and the row is left as it was, to seal on its next real edit")
      (testing "a real edit on the same row does seal"
        (let [out (seal/seal k :recipes :description "edited at last" text)]
          (is (seal/sealed? out))
          (is (= "edited at last" (seal/unseal k :recipes :description out)))))
      (testing "and a migration pass, which passes no stored, seals it"
        (is (seal/sealed? (seal/seal k :recipes :description text)))))))

(deftest no-key-means-no-sealing
  (testing "cookbook's behaviour before any of this existed, reachable by config"
    (is (= "plain" (seal/seal nil :recipes :description "plain")))
    (is (= "enc:v1:whatever" (seal/unseal nil :recipes :description "enc:v1:whatever")))
    (is (= {:description "plain"} (seal/seal-row nil :recipes {:description "plain"})))
    (is (= [{:version 1 :description "plain"}]
           (seal/unseal-body nil [{:version 1 :description "plain"}])))))

;; ---------------------------------------------------------------------------
;; The inventory and the shapes.

(deftest the-inventory-is-thirteen-columns
  (is (= 13 (reduce + (map count (vals seal/sealed-columns)))))
  (is (= {:recipes [:description :useful_when :reason :context]
          :recipe_history [:description :useful_when :reason :context]
          :recipe_proposals [:description :useful_when :reason :context]
          :scopes [:description]}
         seal/sealed-columns))
  (testing "title and tags are the search surface and are never in it"
    (doseq [[_ columns] seal/sealed-columns]
      (is (not-any? #{:title :tags} columns)))))

(deftest the-inventory-is-the-one-the-fixture-names
  (testing "the list above is spelled out because it is the thing being asserted;
    what makes the *clients* agree about it is the fixture, the way it already
    does for the binding and the published surface. Since publishing became a
    one-way unseal there is a third reader: cookbook's server walks the twelve
    Recipe columns of this inventory — with no key, on the prefix alone — before
    it will let a publish latch, and a server whose list was narrower than this
    one would let a sealed value ride out onto a public page through the column
    it did not know to look at."
    (is (= (:sealed-columns @fixture)
           (into {} (for [[table columns] seal/sealed-columns]
                      [table (mapv name columns)]))))))

(deftest a-lean-row-gains-no-keys
  (testing "cookbook's listing carries no description at all, and must not grow one"
    (let [k (test-key)
          lean {:id 1 :version 2 :title "T" :useful_when "U"}]
      (is (= lean (dissoc (seal/unseal-recipe k (assoc lean :useful_when
                                                       (seal/seal k :recipes :useful_when "U")))
                          :nothing)))
      (is (not (contains? (seal/unseal-recipe k lean) :description))))))

(deftest a-version-list-unseals-against-two-tables
  (let [k (test-key)
        body {:total 2
              :versions [{:version 2 :current true
                          :description (seal/seal k :recipes :description "now")
                          :reason (seal/seal k :recipes :reason "because")}
                         {:version 1
                          :description (seal/seal k :recipe_history :description "before")
                          :reason nil}]}
        out (seal/unseal-versions k body)]
    (is (= "now" (get-in out [:versions 0 :description])))
    (is (= "because" (get-in out [:versions 0 :reason])))
    (is (= "before" (get-in out [:versions 1 :description])))
    (is (nil? (get-in out [:versions 1 :reason])))
    (testing "and the ladder holds because the two tables share a binding"
      ;; The history *is* the current row, copied by the server on the next save.
      ;; A per-table binding sealed exactly this list shut, which is how the
      ;; grouping came to be written down.
      (is (= "now" (seal/unseal k :recipe_history :description
                                (get-in body [:versions 0 :description])))))))

(deftest an-inbox-entry-carries-both-texts-and-they-come-from-different-tables
  (let [k (test-key)
        entry {:id 9 :kind "proposed" :recipe_title "A title, in the clear"
               :scopes [{:id 3 :title "sandboxing"
                         :description (seal/seal k :scopes :description "safe agentic coding")}]
               :proposal {:title "A title, in the clear"
                          :description (seal/seal k :recipe_proposals :description "what the agent wants")
                          :reason (seal/seal k :recipe_proposals :reason "the example went stale")
                          :current_description (seal/seal k :recipes :description "what it says now")
                          :current_useful_when (seal/seal k :recipes :useful_when "when you need it")}}
        out (seal/unseal-inbox-entry k entry)]
    (is (= "what the agent wants" (get-in out [:proposal :description])))
    (is (= "the example went stale" (get-in out [:proposal :reason])))
    (is (= "what it says now" (get-in out [:proposal :current_description])))
    (is (= "when you need it" (get-in out [:proposal :current_useful_when])))
    (is (= "safe agentic coding" (get-in out [:scopes 0 :description])))
    (is (= "A title, in the clear" (:recipe_title out)))))

(deftest unseal-proposal-means-the-same-thing-in-both-clients
  (testing "the agent's own text and, where a shape carries them, the current_ aliases"
    (let [k (test-key)
          p (seal/unseal-proposal
             k {:base_version 2
                :description (seal/seal k :recipe_proposals :description "proposed")
                :reason (seal/seal k :recipe_proposals :reason "why")
                :current_description (seal/seal k :recipes :description "as it reads now")
                :current_useful_when (seal/seal k :recipes :useful_when "when you need it")})]
      (is (= "proposed" (:description p)))
      (is (= "why" (:reason p)))
      (is (= "as it reads now" (:current_description p)))
      (is (= "when you need it" (:current_useful_when p))))
    (testing "and a shape without them is untouched by that half"
      (let [k (test-key)
            p (seal/unseal-proposal k {:base_version 2
                                       :description (seal/seal k :recipe_proposals :description "proposed")})]
        (is (= "proposed" (:description p)))
        (is (not (contains? p :current_description)))))))

(deftest unseal-body-recognises-the-shapes-the-api-answers-with
  (let [k (test-key)
        d #(seal/seal k :recipes :description %)]
    (testing "a single Recipe, from a read, a create, a save or a publish"
      (is (= "body" (:description (seal/unseal-body k {:id 1 :version 3 :description (d "body")})))))
    (testing "a listing"
      (is (= ["a" "b"] (mapv :description
                             (seal/unseal-body k [{:id 1 :version 1 :description (d "a")}
                                                  {:id 2 :version 1 :description (d "b")}])))))
    (testing "the Scopes listing, which carries no version"
      (is (= ["coding with AI"]
             (mapv :description
                   (seal/unseal-body k [{:id 1 :title "agentic engineering"
                                         :description (seal/seal k :scopes :description "coding with AI")}])))))
    (testing "the 409 that says the Recipe moved"
      (is (= "current text"
             (get-in (seal/unseal-body k {:error "Recipe was modified elsewhere"
                                          :reason "modified-elsewhere"
                                          :current {:id 1 :version 4 :description (d "current text")}})
                     [:current :description]))))
    (testing "the 409 that says a proposal is pending"
      (is (= "queued text"
             (get-in (seal/unseal-body k {:error "..." :reason "proposal-pending"
                                          :pending {:base_version 2
                                                    :description (seal/seal k :recipe_proposals :description "queued text")}})
                     [:pending :description]))))
    (testing "the 202 that says one was just filed"
      (let [out (seal/unseal-body k {:pending {:description (seal/seal k :recipe_proposals :description "filed")}
                                     :recipe {:id 1 :version 2 :description (d "unchanged")}})]
        (is (= "filed" (get-in out [:pending :description])))
        (is (= "unchanged" (get-in out [:recipe :description])))))
    (testing "a Recipe row carrying its own pending flag is still a Recipe"
      ;; `pending` means two things in this API — 0/1 on a row, and a proposal
      ;; body on a 409 or a 202 — and reading the flag as the proposal left
      ;; every ordinary save sealed. Found end to end, pinned here.
      (is (= "body" (:description (seal/unseal-body k {:id 1 :version 3 :pending 0
                                                      :description (d "body")})))))
    (testing "a body with no prose in it at all is handed back as it came"
      (is (= {:success true} (seal/unseal-body k {:success true})))
      (is (= {:error "Recipe not found"} (seal/unseal-body k {:error "Recipe not found"}))))))

(deftest a-recipe-write-seals-the-prose-and-nothing-else
  (let [k (test-key)
        stored {:description (seal/seal k :recipes :description "the body as stored")
                :useful_when (seal/seal k :recipes :useful_when "unchanged")}
        body {:title "A title"
              :tags "one two three"
              :scope_ids [1 2]
              :modified_at "2026-09-05 10:00:00"
              :useful_when "unchanged"
              :description "the body, edited"
              :reason "because it was wrong"
              :context "steps 1-4"}
        out (seal/seal-recipe-write k body stored)]
    (is (= "A title" (:title out)) "the title is the search surface")
    (is (= "one two three" (:tags out)))
    (is (= [1 2] (:scope_ids out)))
    (is (= "2026-09-05 10:00:00" (:modified_at out)))
    (is (= (:useful_when stored) (:useful_when out))
        "unchanged, so the stored ciphertext is echoed and the server sees a no-op")
    (is (seal/sealed? (:description out)))
    (is (not= (:description stored) (:description out)))
    (is (= "the body, edited" (seal/unseal k :recipes :description (:description out))))
    (is (= "because it was wrong" (seal/unseal k :recipes :reason (:reason out))))
    (is (= "steps 1-4" (seal/unseal k :recipes :context (:context out))))))

(deftest a-partial-write-seals-only-what-it-carries
  (testing "an omitted field keeps its value, server-side; the seal must not send one"
    (let [k (test-key)
          out (seal/seal-recipe-write k {:scope_ids [3] :modified_at "…"})]
      (is (= {:scope_ids [3] :modified_at "…"} out)))))

(deftest a-caution-computed-over-ciphertext-is-not-passed-on
  ;; The mirror of `et.cb.seal-test/what-a-client-can-tell-about-a-ladder` in the
  ;; cookbook checkout. Written out in both suites rather than driven from
  ;; `seal-vectors.edn`, on purpose: `published-surface` is in the fixture because
  ;; it is a *list* three clients could widen differently, and this is one column
  ;; already named in `et.cb.caution/ranges` and pinned by
  ;; `caution-test/the-text-is-the-description`. A fourth statement of
  ;; `description` would be a fourth thing to keep in step.
  (let [k (test-key)
        sealed (seal/seal k :recipes :description "a sealed body")
        split {:legend "1.00 saved here by hand, 0.00 written by an agent"
               :ranges [{:from 1 :to 1 :caution 1.0}]}]
    (testing "a sealed body means the server assessed base64, so the split goes"
      (is (true? (seal/caution-over-ciphertext?
                  {:id 7 :version 3 :description sealed :caution split}))))
    (testing "prose in the clear keeps the server's answer — unmigrated or published"
      (is (false? (seal/caution-over-ciphertext?
                   {:id 7 :version 3 :description "plain" :caution split}))))
    (testing "a body with no split acquires no opinion about one"
      ;; A lean read, a visitor's read, a filing PUT, a publish, a 202.
      (is (false? (seal/caution-over-ciphertext? {:id 7 :version 3 :description sealed})))
      (is (false? (seal/caution-over-ciphertext? {:id 7 :version 3}))))
    (testing "and neither does a listing, a nil, or anything that is not a map"
      (is (false? (seal/caution-over-ciphertext? nil)))
      (is (false? (seal/caution-over-ciphertext? [{:caution split :description sealed}])))
      (is (false? (seal/caution-over-ciphertext? "enc:v1:not-a-body"))))
    (testing "it is answered of the body as it arrived, so no key is needed to answer it"
      ;; The client that cannot read the prose is exactly the one that cannot tell
      ;; the split is a lie, which is why this asks nothing of the key.
      (is (true? (seal/caution-over-ciphertext?
                  {:id 7 :version 3 :description sealed :caution split}))))))

;; ---------------------------------------------------------------------------
;; What a write path has to know.
;;
;; These moved here from `plurama_cli_test.clj` when the proxy sidecar became a
;; third client that seals a write. They were never about `plurama_cli.clj`; they
;; are about which cookbook paths carry prose and what the read in front of a
;; write means, and two clients answering that differently is the shape of thing
;; this file exists to make impossible.

(deftest prose-in-agrees-with-the-inventory-and-nothing-else
  (testing "a Recipe write"
    (is (= [:description] (seal/prose-in :recipes {:description "x" :tags "y"})))
    (is (= [:description :useful_when :reason :context]
           (seal/prose-in :recipes {:description "d" :useful_when "u" :reason "r" :context "c"})))
    (is (nil? (seal/prose-in :recipes {:tags "x"})) "filing is not prose")
    (is (nil? (seal/prose-in :recipes {:title "x" :scope_ids [1] :modified_at "…"}))
        "and neither is anything else the search or the guards are made of"))
  (testing "a Scope write"
    (is (= [:description] (seal/prose-in :scopes {:title "x" :description "d"})))
    (is (nil? (seal/prose-in :scopes {:title "x" :tags "y"}))))
  (testing "and it is the inventory that decides, not a second list"
    (doseq [[table columns] seal/sealed-columns]
      (is (= columns (seal/prose-in table (zipmap columns (repeat "v"))))
          (str "every sealed column of " table " has to be seen"))))
  (testing "junk is not prose"
    (is (nil? (seal/prose-in :recipes nil)))
    (is (nil? (seal/prose-in :recipes "not a map")))))

(deftest write-target-names-the-two-tables-a-client-writes
  (is (= {:table :recipes} (seal/write-target "/api/recipes")))
  (is (= {:table :scopes} (seal/write-target "/api/scopes")))
  (is (= {:table :recipes :id 7} (seal/write-target "/api/recipes/7")))
  (is (= {:table :scopes :id 3} (seal/write-target "/api/scopes/3?overwrite=true")))
  (testing "and nothing else"
    (is (nil? (seal/write-target "/api/recipes/7/publish")))
    (is (nil? (seal/write-target "/api/recipes/7/versions")))
    (is (nil? (seal/write-target "/api/recipes/7/sealed")))
    (is (nil? (seal/write-target "/api/inbox/9/approve")))
    (is (nil? (seal/write-target "/api/machine-user/password")))))

(deftest publish-target-is-its-own-matcher
  (is (= 7 (seal/publish-target "/api/recipes/7/publish")))
  (is (nil? (seal/publish-target "/api/recipes/7")))
  (is (nil? (seal/publish-target "/api/recipes")))
  (is (nil? (seal/publish-target "/api/inbox/7/approve"))))

(deftest the-read-in-front-of-a-write-is-versions-and-not-a-full-read
  (testing "a full read counts as a consumption and ranks the shelf, so seal
    bookkeeping would quietly reorder the owner's Cookbook. Named here because
    three clients make this read and only one of them was ever reviewed for it."
    (is (= "/api/recipes/7/versions" (seal/state-path {:table :recipes :id 7})))
    (is (= "/api/scopes" (seal/state-path {:table :scopes :id 3})))
    (testing "and a create has no row to read"
      (is (nil? (seal/state-path {:table :recipes})))
      (is (nil? (seal/state-path {:table :scopes}))))))

(deftest state-of-reads-both-rules-out-of-one-round-trip
  (testing "a Recipe: the current row's four columns, and the latch"
    (let [body {:published 0
                :versions [{:version 3 :current true :description "d" :useful_when "u"
                            :reason "r" :context "c" :title "not prose"}
                           {:version 2 :description "old"}]}]
      (is (= {:stored {:description "d" :useful_when "u" :reason "r" :context "c"}
              :published? false}
             (seal/state-of {:table :recipes :id 7} body))
          "the title comes along on that read and is not the seal's business")
      (is (true? (:published? (seal/state-of {:table :recipes :id 7}
                                             (assoc body :published 1)))))))
  (testing "a Scope: its row out of the listing, and never a latch"
    (let [listing [{:id 1 :title "a" :description "one"} {:id 3 :title "b" :description "three"}]]
      (is (= {:stored {:description "three"} :published? false}
             (seal/state-of {:table :scopes :id 3} listing)))
      (is (= {:stored nil :published? false} (seal/state-of {:table :scopes :id 9} listing))
          "a Scope the listing does not carry is nothing to echo, not an error")))
  (testing "and every column it picks up is one the inventory named"
    (is (= (set (:recipes seal/sealed-columns))
           (set (keys (:stored (seal/state-of {:table :recipes :id 7}
                                              {:versions [{:current true :description "d"
                                                           :useful_when "u" :reason "r"
                                                           :context "c"}]}))))))))

(deftest seal-write-answers-nil-for-a-published-recipe
  (testing "and `nil` is not an unchanged map: it is how a client is told to send
    the body it was given, byte for byte, rather than a re-serialisation of it
    with a different key order"
    (let [k (test-key)
          body {:description "a line meant for strangers" :title "t"}]
      (is (nil? (seal/seal-write k {:table :recipes} body {:published? true})))
      (let [out (seal/seal-write k {:table :recipes} body {:published? false})]
        (is (seal/sealed? (:description out)))
        (is (= "t" (:title out)) "and nothing that is not prose was touched")
        (is (= "a line meant for strangers"
               (seal/unseal k :recipes :description (:description out)))))
      (testing "with the stored value in hand, an unchanged one echoes"
        (let [stored (seal/seal k :recipes :description "a line meant for strangers")]
          (is (= stored (:description (seal/seal-write k {:table :recipes} body
                                                       {:stored {:description stored}})))))))))

(deftest the-caution-question-is-asked-before-a-word-is-opened
  (testing "**the order is the whole of it.** `caution-over-ciphertext?` reads the
    description, so a client that unsealed first would find plaintext there and
    conclude the server's split had been computed over readable text. It is why
    whoever unseals is the one that must drop the caution — which is not an
    abstraction: the proxy sidecar unseals on behalf of a box whose own client
    asks this question a moment later, of a body already opened."
    (let [k (test-key)
          body {:id 7 :version 3
                :description (seal/seal k :recipes :description "line one\nline two")
                :caution {:legend "…" :ranges [{:from 1 :to 1 :caution 1.0}]}}
          out (seal/unseal-response-body k body)]
      (is (= "line one\nline two" (:description out)) "opened")
      (is (not (contains? out :caution)) "and the split that was computed over base64 is gone"))
    (testing "a plaintext Recipe keeps its split — unmigrated, or published"
      (let [body {:id 7 :version 3 :description "plain" :caution {:ranges []}}]
        (is (= body (seal/unseal-response-body (test-key) body)))))
    (testing "and with no key the drop still happens, because a client that cannot
      read the prose is exactly the one that cannot tell the split is a lie"
      (let [sealed (seal/seal (test-key) :recipes :description "line one\nline two")
            body {:id 7 :version 3 :description sealed :caution {:ranges []}}]
        (is (= {:id 7 :version 3 :description sealed}
               (seal/unseal-response-body nil body)))))))
