(ns plurama-cli-test
  "The parts of `plurama_cli.clj` that decide something about the seal and can be
  held still without a network.

  Deliberately narrow. This program is a one-shot client — parse argv, do one
  request, print, exit — and most of it is only true against a running cookbook.
  What is *not* is what `seal-request-body` decides: whether a write pays for the
  echo rule's extra read at all, and whether the answer to that read means the
  body goes out sealed or exactly as it was typed.

  **The questions themselves moved next door** when the proxy sidecar became a
  third client that seals a write — `write-target`, `prose-in`, `state-path`,
  `state-of` and `seal-write` are in `cookbook-seal` now, with the suite that
  reads the fixture. What is left here is this program wiring them together, which
  is the part only this program has."
  (:require [clojure.test :refer [deftest is testing]]
            [cheshire.core :as json]
            [cookbook-seal :as seal]
            [cookbook-tui]
            [plurama-cli]))

(def ^:private seal-request-body @#'plurama-cli/seal-request-body)

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

(deftest cookbook-tui-is-loaded-by-a-suite-at-all
  (testing "**it was not, and that was the gap.** `bb test` required four
    namespaces and none of them was the TUI, so its copy of the prose columns —
    written out by hand, the fifth statement of them in this system and the only
    unpinned one — could have gone stale with every suite green. A fifth column
    would then have been missing from the `stored` map it builds, the echo rule
    would never have fired for that column, and every save from the TUI would have
    looked like a change to the server: the ladder corruption the echo rule exists
    to prevent.

    The copy is gone — it reads `seal/sealed-columns` now — and the file is loaded
    here so that it cannot stop compiling unnoticed either. What the TUI *does*
    with what it reads is still checked by hand: it is a terminal program, and
    most of it is only true against a running cookbook."
    (is (some? (resolve 'cookbook-tui/-main))
        "the namespace loads, which is the whole of what a suite can say about it")))

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
