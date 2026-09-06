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

(deftest a-prose-less-write-is-returned-byte-identical-and-asks-nothing
  (testing "the guard that keeps a filing PUT from paying for the echo rule.
    `cfg` and `token` are nil on purpose: if the guard let this through it would
    try to reach a server with them and throw, so a body coming back unchanged is
    also the proof that nothing was fetched."
    (doseq [[path body] [["/recipes/7" "{\"tags\":\"x\"}"]
                         ["/recipes/7" "{\"scope_ids\":[1,2],\"modified_at\":\"…\"}"]
                         ["/scopes/3" "{\"title\":\"x\"}"]]]
      (testing (str path " " body)
        (is (= body (seal-request-body nil nil :put path body))
            "the body itself, not a re-serialisation of it"))))
  (testing "and so is a path the seal has no opinion about"
    (is (= "{\"description\":\"x\"}"
           (seal-request-body nil nil :post "/recipes/7/publish" "{\"description\":\"x\"}")))
    (is (= "{\"seen\":true}" (seal-request-body nil nil :post "/inbox/9/seen" "{\"seen\":true}")))))

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
