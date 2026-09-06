(ns plurama-cli-test
  "The parts of `plurama_cli.clj` that decide something about the seal and can be
  held still without a network.

  Deliberately narrow. This program is a one-shot client — parse argv, do one
  request, print, exit — and most of it is only true against a running cookbook.
  What is *not* is the pair of pure decisions the seal added to it: which write
  carries prose, and which path names a publish. Both were checked by hand and by
  eye when they landed, and both are the kind of thing that goes wrong invisibly:
  a prose column dropped from the inventory here would send prose out in the clear
  and nothing would say so."
  (:require [clojure.test :refer [deftest is testing]]
            [cheshire.core :as json]
            [cookbook-seal :as seal]
            [plurama-cli]))

(def ^:private prose-in @#'plurama-cli/prose-in)
(def ^:private write-target @#'plurama-cli/write-target)
(def ^:private publish-target @#'plurama-cli/publish-target)
(def ^:private seal-request-body @#'plurama-cli/seal-request-body)

(deftest prose-in-agrees-with-the-inventory-and-nothing-else
  (testing "a Recipe write"
    (is (= [:description] (prose-in :recipes {:description "x" :tags "y"})))
    (is (= [:description :useful_when :reason :context]
           (prose-in :recipes {:description "d" :useful_when "u" :reason "r" :context "c"})))
    (is (nil? (prose-in :recipes {:tags "x"})) "filing is not prose")
    (is (nil? (prose-in :recipes {:title "x" :scope_ids [1] :modified_at "…"}))
        "and neither is anything else the search or the guards are made of"))
  (testing "a Scope write"
    (is (= [:description] (prose-in :scopes {:title "x" :description "d"})))
    (is (nil? (prose-in :scopes {:title "x" :tags "y"}))))
  (testing "and it is the inventory that decides, not a second list"
    (doseq [[table columns] seal/sealed-columns]
      (is (= columns (prose-in table (zipmap columns (repeat "v"))))
          (str "every sealed column of " table " has to be seen"))))
  (testing "junk is not prose"
    (is (nil? (prose-in :recipes nil)))
    (is (nil? (prose-in :recipes "not a map")))))

(def ^:private test-key
  ;; Generated here rather than taken from `seal-vectors.edn`: these are tests
  ;; about which writes the seal *touches*, not about the envelope, and the one
  ;; thing they need of a key is that there is one. The fixture is the envelope's
  ;; drift control and belongs to the suite next door.
  ;;
  ;; **Bound explicitly by every test below that needs sealing to be on**, and
  ;; that is not tidiness. `seal-request-body` returns its body untouched when
  ;; `@seal-key` is nil, so a suite that let the ambient key decide would pass for
  ;; the right reason on a box that has one and for no reason at all on a box that
  ;; does not — and `~/.config/plurama-cli/cookbook-seal.key` has failed to survive
  ;; the gap between sessions three rounds running. A test that is a coin toss
  ;; about whether it tested anything is the shape `seal-vectors.edn`'s own header
  ;; warns about.
  (delay (seal/key-from-base64 (seal/generate-key-base64))))

(deftest a-prose-less-write-is-returned-byte-identical-and-asks-nothing
  (testing "the guard that keeps a filing PUT from paying for the echo rule.

    **The read is counted, and that is what makes the second half of the name an
    assertion.** It used to rest on `cfg` and `token` being nil — *if the guard
    let this through it would try to reach a server with them and throw* — which
    was never true: `current-state` catches everything and answers nil, and the
    bodies below re-serialise to themselves, so removing the guard entirely left
    this test green. Counting the call is the only thing that can tell whether the
    round trip happened."
    (let [asked (atom 0)]
      (with-redefs [plurama-cli/seal-key test-key
                    plurama-cli/current-state (fn [& _] (swap! asked inc) nil)]
        (doseq [[path body] [["/recipes/7" "{\"tags\":\"x\"}"]
                             ["/recipes/7" "{\"scope_ids\":[1,2],\"modified_at\":\"…\"}"]
                             ["/scopes/3" "{\"title\":\"x\"}"]]]
          (testing (str path " " body)
            (is (= body (seal-request-body nil nil :put path body))
                "the body itself, not a re-serialisation of it")))
        (testing "and so is a path the seal has no opinion about"
          (is (= "{\"description\":\"x\"}"
                 (seal-request-body nil nil :post "/recipes/7/publish" "{\"description\":\"x\"}")))
          (is (= "{\"seen\":true}"
                 (seal-request-body nil nil :post "/inbox/9/seen" "{\"seen\":true}"))))
        (is (zero? @asked)
            "and not one of them asked the server anything"))))

  (testing "and with no key configured at all — sealing off, which is cookbook as
    it was before any of this — every one of them is still the body it was given,
    by the other road"
    (with-redefs [plurama-cli/seal-key (delay nil)]
      (is (= "{\"tags\":\"x\"}" (seal-request-body nil nil :put "/recipes/7" "{\"tags\":\"x\"}")))
      (is (= "{\"description\":\"x\"}"
             (seal-request-body nil nil :put "/recipes/7" "{\"description\":\"x\"}"))
          "including one that carries prose, which is what 'sealing off' means"))))

(deftest the-publish-interlock-asks-the-shared-question
  (testing "not a pair spelled out inline. `refuse-sealed-publish!` and
    cookbook-tui's `sealed-recipe?` both go through
    `seal/published-surface-sealed?`, which is asserted against the fixture in
    the suite next door — so widening the surface in one client cannot leave
    this one narrower without something going red."
    (is (= [:description :useful_when] seal/published-surface))
    (is (true? (seal/published-surface-sealed? {:description "enc:v1:AAAA"})))
    (is (true? (seal/published-surface-sealed? {:useful_when "enc:v1:AAAA"})))
    (is (false? (seal/published-surface-sealed? {:description "clear" :useful_when "clear"})))
    (is (false? (seal/published-surface-sealed? {:reason "enc:v1:AAAA"}))
        "a sealed reason is not a published surface — a visitor is served none")))

(deftest write-target-names-the-two-tables-a-client-writes
  (is (= {:table :recipes} (write-target "/api/recipes")))
  (is (= {:table :scopes} (write-target "/api/scopes")))
  (is (= {:table :recipes :id 7} (write-target "/api/recipes/7")))
  (is (= {:table :scopes :id 3} (write-target "/api/scopes/3?overwrite=true")))
  (testing "and nothing else"
    (is (nil? (write-target "/api/recipes/7/publish")))
    (is (nil? (write-target "/api/recipes/7/versions")))
    (is (nil? (write-target "/api/inbox/9/approve")))
    (is (nil? (write-target "/api/machine-user/password")))))

(deftest publish-target-is-its-own-matcher
  (is (= 7 (publish-target "/api/recipes/7/publish")))
  (is (nil? (publish-target "/api/recipes/7")))
  (is (nil? (publish-target "/api/recipes")))
  (is (nil? (publish-target "/api/inbox/7/approve"))))

;; ---------------------------------------------------------------------------
;; The published rule
;;
;; Publishing a Recipe unseals it, one way — a visitor has no key and there is no
;; unpublish — so a write to a published Recipe has to go out in the clear or it
;; puts `enc:v1:…` back on a public page. Cookbook refuses such a write with a
;; 400; this is what keeps an honest agent from meeting that refusal.
(deftest a-write-to-a-published-recipe-is-not-sealed
  (let [body "{\"description\":\"a line meant for strangers\"}"]
    (testing "published: the body goes over the wire byte-identical, exactly as a
      prose-less one does — no envelope, no re-serialisation"
      (with-redefs [plurama-cli/seal-key test-key
                    plurama-cli/current-state (fn [_ _ _] {:stored nil :published? true})]
        (is (= body (seal-request-body nil nil :put "/recipes/7" body)))))

    (testing "and unpublished it is sealed, which is the whole point of the shelf"
      (with-redefs [plurama-cli/seal-key test-key
                    plurama-cli/current-state (fn [_ _ _] {:stored nil :published? false})]
        (let [out (json/parse-string (seal-request-body nil nil :put "/recipes/7" body) true)]
          (is (seal/sealed? (:description out)))
          (is (= "a line meant for strangers"
                 (seal/unseal @test-key :recipes :description (:description out)))))))

    (testing "a read that failed answers neither, and the write seals: that is the
      safe direction for the echo rule and the unsafe one for this rule, on
      purpose — a client that cannot read the Recipe cannot know, and the server
      refuses what this would get wrong"
      (with-redefs [plurama-cli/seal-key test-key
                    plurama-cli/current-state (fn [_ _ _] nil)]
        (let [out (json/parse-string (seal-request-body nil nil :put "/recipes/7" body) true)]
          (is (seal/sealed? (:description out))))))))
