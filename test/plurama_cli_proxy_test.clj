(ns plurama-cli-proxy-test
  "The proxy sidecar, driven end to end against a cookbook that is not there.

  `handle` is a ring handler and `forward` is one HTTP call, so the whole path a
  request takes through this process — allowlist, token, seal the prose, forward,
  unseal the answer — can be exercised in-process against a fake upstream that
  records what it was handed. That is as far as babashka reaches, and it reaches
  further than it looks: what is *not* covered here is the compose mount, and only
  the compose mount.

  Every test binds its own key rather than letting the ambient one decide.
  `~/.config/plurama-cli/cookbook-seal.key` has failed to survive the gap between
  sessions three rounds running, and a suite that passes for the right reason on a
  box that has a key and for no reason at all on a box that does not is the shape
  the fixture's own header warns about."
  (:require [cheshire.core :as json]
            [clojure.string :as str]
            [clojure.test :refer [deftest is testing]]
            [cookbook-seal :as seal]
            [tracker-seal]
            [org.httpkit.server :as srv]
            [plurama-cli-proxy]))

(def ^:private handle @#'plurama-cli-proxy/handle)

(def ^:private test-key (delay (seal/key-from-base64 (seal/generate-key-base64))))
(def ^:private other-key (delay (seal/key-from-base64 (seal/generate-key-base64))))

(defn- with-upstream
  "A cookbook that answers `routes` — a map of path to body — and remembers every
  request it was handed. `f` is called with `{:seen atom, :port n}`."
  [routes f]
  (let [seen (atom [])
        handler (fn [{:keys [request-method uri body]}]
                  (swap! seen conj {:method request-method :uri uri
                                    :body (when body (slurp body))})
                  (if-let [answer (get routes uri)]
                    {:status (:status answer 200)
                     :headers {"Content-Type" "application/json"}
                     :body (json/generate-string (:body answer))}
                    {:status 404 :headers {"Content-Type" "application/json"}
                     :body (json/generate-string {:error (str "no route " uri)})}))
        stop (srv/run-server handler {:port 0 :ip "127.0.0.1"})
        port (:local-port (meta stop))]
    (try (f {:seen seen :port port})
         (finally (stop)))))

(defn- request
  "One box-side request through the proxy, with the keys it is to hold.

  `k` is cookbook's, for the tests that predate tracker sealing. A map instead
  names both, which is what a tracker test needs — and what proves the two keys
  are genuinely separate rather than one key the proxy happens to use twice."
  [{:keys [port]} k {:keys [method uri body]}]
  (let [{ck :cookbook tk :tracker} (if (map? k) k {:cookbook k})]
   (with-redefs [plurama-cli-proxy/credentials
                (delay {:cookbook {:base-url (str "http://127.0.0.1:" port)}
                        :tracker {:base-url (str "http://127.0.0.1:" port)}
                        :tracker-just-msg {:base-url (str "http://127.0.0.1:" port)}})
                plurama-cli-proxy/cookbook-seal-key (delay ck)
                plurama-cli-proxy/tracker-seal-key (delay tk)]
    (handle {:request-method method
             :uri uri
             :body (when body (java.io.StringReader. body))
             :headers {"content-type" "application/json"}}))))

(defn- body-of [resp] (json/parse-string (:body resp) true))

(defn- writes [seen] (remove #(= :get (:method %)) @seen))

;; ---------------------------------------------------------------------------

(deftest a-response-is-opened-on-the-way-back
  (testing "which is the whole point: an agent in the box reads prose, and the key
    it would have needed to is one hop away, where it cannot be copied out"
    (let [k @test-key
          sealed (seal/seal k :recipes :description "the body an agent came for")]
      (with-upstream {"/api/recipes/7" {:body {:id 7 :version 2 :title "clear"
                                               :description sealed
                                               :useful_when (seal/seal k :recipes :useful_when "when")}}}
        (fn [up]
          (let [out (body-of (request up k {:method :get :uri "/cookbook/api/recipes/7"}))]
            (is (= "the body an agent came for" (:description out)))
            (is (= "when" (:useful_when out)))
            (is (= "clear" (:title out)) "and the title was never sealed to begin with")))))))

(deftest a-caution-computed-over-ciphertext-is-taken-off-here
  (testing "**and it has to be here, not in the box.** The in-box client asks the
    same question — `caution-over-ciphertext?`, of the description — but by the
    time it sees the body this proxy has opened it, so it would find prose there
    and pass on a provenance split the server computed over base64: a lie about
    which lines are the owner's, told to the one reader written to act on it."
    (let [k @test-key
          split {:legend "1.00 by hand" :ranges [{:from 1 :to 1 :caution 1.0}]}]
      (with-upstream {"/api/recipes/7" {:body {:id 7 :version 3 :caution split
                                               :description (seal/seal k :recipes :description
                                                                       "line one\nline two")}}}
        (fn [up]
          (let [out (body-of (request up k {:method :get :uri "/cookbook/api/recipes/7?detail=full"}))]
            (is (= "line one\nline two" (:description out)))
            (is (not (contains? out :caution))))))
      (testing "a Recipe whose prose was already in the clear keeps its split"
        (with-upstream {"/api/recipes/8" {:body {:id 8 :version 3 :caution split
                                                 :description "plain all along"}}}
          (fn [up]
            (let [out (body-of (request up k {:method :get :uri "/cookbook/api/recipes/8?detail=full"}))]
              (is (= split (:caution out))))))))))

(deftest a-write-is-sealed-on-the-way-out
  (let [k @test-key]
    (with-upstream {"/api/recipes" {:body {:id 9 :version 1}}}
      (fn [up]
        (request up k {:method :post :uri "/cookbook/api/recipes"
                       :body (json/generate-string {:title "a title" :tags "one two"
                                                    :description "prose the server must not read"
                                                    :useful_when "" :reason "because"})})
        (let [sent (json/parse-string (:body (first (writes (:seen up)))) true)]
          (is (seal/sealed? (:description sent)))
          (is (seal/sealed? (:reason sent)))
          (is (= "prose the server must not read"
                 (seal/unseal k :recipes :description (:description sent))))
          (testing "the search surface is untouched, which is the line the model draws"
            (is (= "a title" (:title sent)))
            (is (= "one two" (:tags sent))))
          (testing "and blank is never sealed"
            (is (= "" (:useful_when sent)))))))))

(deftest an-unchanged-value-goes-back-as-the-very-ciphertext-already-stored
  (testing "the echo rule, and the reason this proxy makes a read before a write:
    a fresh nonce would make every resend look like a change to the server, and an
    agent that PUTs the same text twice would pile up versions, history rows and
    inbox entries — corrupting the ladder the seal exists to protect."
    (let [k @test-key
          stored (seal/seal k :recipes :description "unchanged")]
      (with-upstream {"/api/recipes/7/versions" {:body {:published 0
                                                        :versions [{:version 2 :current true
                                                                    :description stored}]}}
                      "/api/recipes/7" {:body {:id 7 :version 2}}}
        (fn [up]
          (request up k {:method :put :uri "/cookbook/api/recipes/7"
                         :body (json/generate-string {:description "unchanged"})})
          (let [sent (json/parse-string (:body (first (writes (:seen up)))) true)]
            (is (= stored (:description sent)) "byte for byte"))))
      (testing "the audit line says which it was, and that is L4: one count could
        not tell a real edit from an idempotent resend, since a no-op write also
        turns four plaintext fields into four ciphertexts on the wire"
        (with-upstream {"/api/recipes/7/versions" {:body {:published 0
                                                          :versions [{:version 2 :current true
                                                                      :description stored}]}}
                        "/api/recipes/7" {:body {:id 7 :version 2}}}
          (fn [up]
            (let [logged (java.io.StringWriter.)]
              (binding [*out* logged]
                (request up k {:method :put :uri "/cookbook/api/recipes/7"
                               :body (json/generate-string {:description "unchanged"})}))
              (is (str/includes? (str logged) "echoed:1"))
              (is (not (str/includes? (str logged) "sealed:"))
                  "nothing new was sealed, and the log no longer says it was")))))
      (testing "and a value that did change is sealed afresh"
        (with-upstream {"/api/recipes/7/versions" {:body {:published 0
                                                          :versions [{:version 2 :current true
                                                                      :description stored}]}}
                        "/api/recipes/7" {:body {:id 7 :version 3}}}
          (fn [up]
            (request up k {:method :put :uri "/cookbook/api/recipes/7"
                           :body (json/generate-string {:description "changed"})})
            (let [sent (json/parse-string (:body (first (writes (:seen up)))) true)]
              (is (not= stored (:description sent)))
              (is (= "changed" (seal/unseal k :recipes :description (:description sent)))))))))))

(deftest a-prose-less-write-asks-the-server-nothing-and-arrives-byte-identical
  (testing "without the guard a filing PUT pays for an echo rule it has no use
    for: `{\"tags\":\"x\"}` would drag down a whole version ladder to look up
    columns it is not sending. The read is counted, because that is the only
    thing that can tell whether the round trip happened."
    (let [k @test-key
          body (json/generate-string {:tags "x" :scope_ids [1 2]})]
      (with-upstream {"/api/recipes/7" {:body {:id 7}}}
        (fn [up]
          (request up k {:method :put :uri "/cookbook/api/recipes/7" :body body})
          (is (= 1 (count @(:seen up))) "one request upstream, not two")
          (is (= body (:body (first @(:seen up)))) "and the body the caller typed"))))))

(deftest a-write-to-a-published-recipe-goes-out-in-the-clear
  (testing "publishing opens every envelope in a Recipe, one way, because a
    visitor has no key and there is no unpublish. Sealing it again would put
    `enc:v1:…` back on a public page; cookbook refuses such a write with a 400,
    and this is what keeps an honest agent from meeting that refusal."
    (let [k @test-key
          body (json/generate-string {:description "a line meant for strangers"})]
      (with-upstream {"/api/recipes/7/versions" {:body {:published 1
                                                        :versions [{:version 2 :current true
                                                                    :description "public"}]}}
                      "/api/recipes/7" {:body {:id 7}}}
        (fn [up]
          (request up k {:method :put :uri "/cookbook/api/recipes/7" :body body})
          (is (= body (:body (first (writes (:seen up)))))
              "byte-identical, not a re-serialisation of an unchanged map"))))))

;; ---------------------------------------------------------------------------
;; The double-seal rule

(deftest prose-that-arrived-already-sealed-is-refused-and-not-forwarded
  (testing "**the key belongs on one side of this proxy or the other, never
    both.** If the box seals too, sealing again writes enc(enc(…)) — the browser
    opens it once and shows an envelope, and nothing reports an error. If the
    box's key is a different key, the result opens for nobody, ever. So the rule
    is enforced here rather than believed."
    (let [k @test-key
          body (json/generate-string {:description (seal/seal @other-key :recipes :description "sealed in the box")})]
      (with-upstream {"/api/recipes" {:body {:id 9}}}
        (fn [up]
          (let [resp (request up k {:method :post :uri "/cookbook/api/recipes" :body body})]
            (is (= 400 (:status resp)))
            (is (= "already-sealed" (:reason (body-of resp))))
            (is (= ["description"] (:columns (body-of resp))))
            (is (empty? (writes (:seen up))) "and nothing reached the server")))))))

(deftest an-echoed-envelope-the-proxy-can-open-is-forwarded-unchanged
  (testing "**the hole the double-seal refusal left open**, found in review and
    reproduced live before it was fixed. `foreign-envelopes` permits the value the
    row already holds, on the grounds that `seal`'s rule 2 makes it a no-op — and
    that was true only while the proxy *could not* open it. When it can, `unseal`
    answered the plaintext, the arriving ciphertext differed from it, and the
    ciphertext was sealed: enc(enc(…)) on the shelf, `sealed:2 opened` in the
    audit line, a version bump and a history row, and `--verify` reporting a
    holding invariant over it.

    The fix is a byte test in front of the unseal, in `cookbook-seal/seal`. This
    is the shape asserted at the door it came in by."
    (let [k @test-key
          stored (seal/seal k :recipes :description "line one of new prose")]
      (with-upstream {"/api/recipes/7/versions" {:body {:published 0
                                                        :versions [{:version 1 :current true
                                                                    :description stored}]}}
                      "/api/recipes/7" {:body {:id 7}}}
        (fn [up]
          (let [resp (request up k {:method :put :uri "/cookbook/api/recipes/7"
                                    :body (json/generate-string {:description stored})})]
            (is (not= 400 (:status resp)) "an echo is not a foreign envelope")
            (let [sent (json/parse-string (:body (first (writes (:seen up)))) true)]
              (is (= stored (:description sent)) "byte-identical — no second envelope")
              (is (= "line one of new prose"
                     (seal/unseal k :recipes :description (:description sent)))
                  "and one unseal still reaches the prose"))))))))

(deftest an-envelope-that-is-the-value-already-stored-is-an-echo-and-not-a-refusal
  (testing "a client that read a value this proxy could not open, and sent it back
    unchanged, is echoing rather than sealing — `seal`'s rule 2 answers that case,
    and comparing against `stored` is what tells the two apart."
    (let [k @test-key
          unopenable (seal/seal @other-key :recipes :description "sealed under a key nobody here has")]
      (with-upstream {"/api/recipes/7/versions" {:body {:published 0
                                                        :versions [{:version 2 :current true
                                                                    :description unopenable}]}}
                      "/api/recipes/7" {:body {:id 7}}}
        (fn [up]
          (let [resp (request up k {:method :put :uri "/cookbook/api/recipes/7"
                                    :body (json/generate-string {:description unopenable})})]
            (is (not= 400 (:status resp)))
            (let [sent (json/parse-string (:body (first (writes (:seen up)))) true)]
              (is (= unopenable (:description sent))
                  "handed back exactly as it is, which is rule 3 in every client"))))))))

;; ---------------------------------------------------------------------------

(deftest with-no-key-configured-nothing-happens-at-all
  (testing "passthrough, byte for byte, which is this proxy before any of this
    existed and is right for a shelf nobody has sealed"
    (let [k @test-key
          sealed (seal/seal k :recipes :description "not this proxy's business")
          body (json/generate-string {:description "plain from the box"})]
      (with-upstream {"/api/recipes/7" {:body {:id 7 :version 2 :description sealed}}}
        (fn [up]
          (let [out (body-of (request up nil {:method :get :uri "/cookbook/api/recipes/7"}))]
            (is (= sealed (:description out)) "an envelope reaches the box unopened"))
          (request up nil {:method :put :uri "/cookbook/api/recipes/7" :body body})
          (is (= body (:body (last @(:seen up)))) "and a write goes out as it came in")
          (is (= 2 (count @(:seen up))) "with no read in front of it"))))))

(deftest an-app-that-is-not-cookbook-is-not-touched
  (testing "the seal is cookbook's, and a `description` on another app's write is
    another app's word"
    (let [k @test-key
          body (json/generate-string {:sender "Plurama Development Coordinator"
                                      :title "done" :description "prose, and not cookbook's"})]
      (with-upstream {"/api/messages" {:body {:id 1}}}
        (fn [up]
          (request up k {:method :post :uri "/tracker-just-msg/api/messages" :body body})
          (is (= body (:body (first (writes (:seen up)))))))))))

(deftest the-audit-line-carries-no-prose-and-no-key
  (testing "every decision is logged where `docker compose logs plurama-proxy`
    finds it, and the point of the log is that it can be read by whoever is
    worried about what an agent did in the owner's name. It must therefore be
    readable *without* being a second copy of the thing being protected: a count,
    a status, a path — never a value, never the key."
    (let [k @test-key
          key-b64 (.encodeToString (java.util.Base64/getEncoder) (.getEncoded k))
          secret "a sentence nobody but the owner should ever read"
          out (java.io.StringWriter.)]
      (with-upstream {"/api/recipes/7/versions" {:body {:published 0
                                                        :versions [{:version 1 :current true
                                                                    :description (seal/seal k :recipes :description secret)}]}}
                      "/api/recipes/7" {:body {:id 7 :description (seal/seal k :recipes :description secret)}}}
        (fn [up]
          (binding [*out* out]
            (request up k {:method :put :uri "/cookbook/api/recipes/7"
                           :body (json/generate-string {:description "a new sentence, also private"})}))
          (let [logged (str out)]
            (is (str/includes? logged "ALLOW"))
            (is (str/includes? logged "sealed:1") "the count is the useful part")
            (is (not (str/includes? logged "echoed:"))
                "and this one was a real edit, not an echo")
            (is (not (str/includes? logged secret)))
            (is (not (str/includes? logged "a new sentence, also private")))
            (is (not (str/includes? logged key-b64)))
            (is (not (str/includes? logged "enc:v1:")))))))))

;; ---------------------------------------------------------------------------
;; Tracker, the second app to seal — and the reason this proxy stopped being
;; cookbook-shaped.
;;
;; The whole of what is new here is that there are now two keys and they are
;; different secrets. A test that used one key for both would pass while proving
;; the opposite of what matters.

(def ^:private tracker-test-key
  (delay (tracker-seal/key-from-base64 (tracker-seal/generate-key-base64))))

(defn- tracker-keys []
  {:cookbook @test-key :tracker @tracker-test-key})

(deftest a-tracker-write-is-sealed-on-the-way-past
  (with-upstream {"/api/tasks/7" {:body {:id 7 :title "a task" :description ""}}}
    (fn [up]
      (let [resp (request up (tracker-keys)
                          {:method :put :uri "/tracker/api/tasks/7"
                           :body (json/generate-string {:title "a task"
                                                        :description "what the agent wrote"})})
            forwarded (->> @(:seen up)
                           (filter #(= :put (:method %)))
                           first
                           :body
                           (#(json/parse-string % true)))]
        (is (= 200 (:status resp)))
        (is (tracker-seal/sealed? (:description forwarded))
            "the upstream is handed an envelope, never the prose")
        (is (= "a task" (:title forwarded)) "and the title goes as it was typed")
        (is (= "what the agent wrote"
               (tracker-seal/unseal @tracker-test-key :tasks :description (:description forwarded))))))))

(deftest the-two-keys-are-not-one-key
  (with-upstream {"/api/tasks/7" {:body {:id 7 :description ""}}}
    (fn [up]
      (request up (tracker-keys)
               {:method :put :uri "/tracker/api/tasks/7"
                :body (json/generate-string {:description "a body"})})
      (let [forwarded (-> (->> @(:seen up) (filter #(= :put (:method %))) first :body)
                          (json/parse-string true))]
        (is (= (:description forwarded)
               (seal/unseal @test-key :recipes :description (:description forwarded)))
            "cookbook's key does not open a tracker body — handed back, not opened")
        (is (= "a body" (tracker-seal/unseal @tracker-test-key :tasks :description
                                             (:description forwarded))))))))

(deftest a-tracker-response-is-opened-on-the-way-back
  (let [ct (tracker-seal/seal @tracker-test-key :tasks :description "a sealed body" nil)]
    (with-upstream {"/api/tasks/7" {:body {:id 7 :title "a task" :description ct}}}
      (fn [up]
        (let [resp (request up (tracker-keys) {:method :get :uri "/tracker/api/tasks/7"})]
          (is (= "a sealed body" (:description (body-of resp)))
              "an agent in the box reads prose, and the box holds no key"))))))

(deftest a-tracker-response-opens-wherever-the-prose-is
  (let [ct #(tracker-seal/seal @tracker-test-key :tasks :description % nil)]
    (with-upstream {"/api/today-board"
                    {:body {:tasks [{:id 1 :description (ct "a task body")
                                     :categories [{:id 9 :description (ct "a person")}]}]
                            :meets [{:id 2 :description (ct "a meeting note")}]}}}
      (fn [up]
        (let [b (body-of (request up (tracker-keys) {:method :get :uri "/tracker/api/today-board"}))]
          (is (= "a task body" (get-in b [:tasks 0 :description])))
          (is (= "a person" (get-in b [:tasks 0 :categories 0 :description]))
              "a category nested in a task, found without anyone remembering it is there")
          (is (= "a meeting note" (get-in b [:meets 0 :description]))))))))

(deftest an-unchanged-tracker-body-echoes-rather-than-re-sealing
  (let [ct (tracker-seal/seal @tracker-test-key :tasks :description "unchanged" nil)]
    (with-upstream {"/api/tasks/7" {:body {:id 7 :description ct}}}
      (fn [up]
        (request up (tracker-keys)
                 {:method :put :uri "/tracker/api/tasks/7"
                  :body (json/generate-string {:description "unchanged"})})
        (let [forwarded (-> (->> @(:seen up) (filter #(= :put (:method %))) first :body)
                            (json/parse-string true))]
          (is (= ct (:description forwarded))
              "the very bytes already stored, so the audit log records no edit"))))))

(deftest a-tracker-write-arriving-already-sealed-is-refused
  (let [foreign (tracker-seal/seal @tracker-test-key :tasks :description "sealed in the box" nil)]
    (with-upstream {"/api/tasks/7" {:body {:id 7 :description ""}}}
      (fn [up]
        (let [resp (request up (tracker-keys)
                            {:method :put :uri "/tracker/api/tasks/7"
                             :body (json/generate-string {:description foreign})})]
          (is (= 400 (:status resp)))
          (is (= "already-sealed" (:reason (body-of resp))))
          (is (= ["description"] (:columns (body-of resp))))
          (is (empty? (filter #(= :put (:method %)) @(:seen up)))
              "and nothing was forwarded: the key belongs on one side of this hop")
          (is (not (str/includes? (:body resp) "sealed in the box"))
              "the refusal names the column and never the value"))))))

(deftest a-message-body-goes-through-the-proxy-untouched
  (with-upstream {"/api/messages" {:body {:id 5}}}
    (fn [up]
      (request up (tracker-keys)
               {:method :post :uri "/tracker-just-msg/api/messages"
                :body (json/generate-string {:sender "blog" :title "m"
                                             :description "an inbox body"})})
      (let [forwarded (-> (->> @(:seen up) (filter #(= :post (:method %))) first :body)
                          (json/parse-string true))]
        (is (= "an inbox body" (:description forwarded))
            "three keyless producers write these; sealing them would break the inbox")))))

(deftest tracker-just-msg-still-opens-what-it-reads
  ;; Mail-only restricts what that identity may **write**, not what it may read.
  (let [ct (tracker-seal/seal @tracker-test-key :tasks :description "a body" nil)]
    (with-upstream {"/api/tasks/7" {:body {:id 7 :description ct}}}
      (fn [up]
        (is (= "a body"
               (:description (body-of (request up (tracker-keys)
                                               {:method :get :uri "/tracker-just-msg/api/tasks/7"})))))))))

(deftest with-no-tracker-key-everything-passes-through
  (let [ct (tracker-seal/seal @tracker-test-key :tasks :description "still sealed" nil)]
    (with-upstream {"/api/tasks/7" {:body {:id 7 :description ct}}}
      (fn [up]
        (let [resp (request up {:cookbook @test-key :tracker nil}
                            {:method :get :uri "/tracker/api/tasks/7"})]
          (is (= ct (:description (body-of resp)))
              "passthrough, byte for byte — the proxy before any of this existed"))))))

(deftest a-tracker-write-with-no-prose-asks-the-upstream-nothing
  (with-upstream {"/api/tasks/7" {:body {:id 7}}}
    (fn [up]
      (request up (tracker-keys)
               {:method :put :uri "/tracker/api/tasks/7"
                :body (json/generate-string {:tags "x"})})
      (is (= 1 (count @(:seen up)))
          "one PUT and no read: the echo rule is only paid for when there is prose"))))

;; ---------------------------------------------------------------------------
;; The two message conversions, which are the one write in tracker that deletes
;; its own original.
;;
;; A box agent sends `POST /api/messages/7/convert-to-task` with no body at all
;; — that is what the endpoint has always taken, and the server read the message
;; and copied its body across. For an armed user the server now refuses that,
;; because the copy would be readable prose in a sealed column and the message it
;; came from is gone in the same transaction. The browser answers by sending the
;; body it is already holding. This process is not holding it, so it has to go
;; and get it: one read of the row that is about to be destroyed.

(deftest a-message-conversion-carries-the-body-it-is-about-to-destroy
  (with-upstream {"/api/messages/7" {:body {:id 7 :sender "the poller" :title "an article"
                                            :description "a paragraph of his own notes"}}
                  "/api/messages/7/convert-to-task" {:body {:id 88 :title "an article"}}}
    (fn [up]
      (let [resp (request up (tracker-keys)
                          {:method :post :uri "/tracker/api/messages/7/convert-to-task"})
            forwarded (-> (->> @(:seen up) (filter #(= :post (:method %))) first :body
                               (#(json/parse-string % true))))]
        (is (= 200 (:status resp)))
        (is (tracker-seal/sealed? (:description forwarded))
            "a convert with no body at all now carries one, sealed")
        (is (= "a paragraph of his own notes"
               (tracker-seal/unseal @tracker-test-key :tasks :description
                                    (:description forwarded)))
            "and it is the message's own prose, bound as an item body — which is
             what the new task's column expects, since all nine tables share it")))))

(deftest a-conversion-to-a-resource-keeps-what-the-agent-sent-and-adds-the-body
  (with-upstream {"/api/messages/7" {:body {:id 7 :description "a resource note body"}}
                  "/api/messages/7/convert-to-resource" {:body {:id 99}}}
    (fn [up]
      (request up (tracker-keys)
               {:method :post :uri "/tracker/api/messages/7/convert-to-resource"
                :body (json/generate-string {:link "https://example.com/x"})})
      (let [forwarded (-> (->> @(:seen up) (filter #(= :post (:method %))) first :body)
                          (json/parse-string true))]
        (is (= "https://example.com/x" (:link forwarded))
            "the link the agent chose is still the link")
        (is (= "a resource note body"
               (tracker-seal/unseal @tracker-test-key :resources :description
                                    (:description forwarded))))))))

(deftest a-conversion-of-a-blank-message-still-forwards-a-blank-body
  ;; Blank is never sealed, so nothing here is an encoding change — and the
  ;; request still has to change, because the server tells `""` from *no body was
  ;; sent* on purpose and refuses the second. A link-only message from the feed
  ;; worker is the commonest convert in the app.
  (with-upstream {"/api/messages/7" {:body {:id 7 :title "a link somebody posted"
                                            :description nil}}
                  "/api/messages/7/convert-to-task" {:body {:id 88}}}
    (fn [up]
      (request up (tracker-keys)
               {:method :post :uri "/tracker/api/messages/7/convert-to-task"})
      (let [forwarded (-> (->> @(:seen up) (filter #(= :post (:method %))) first :body)
                          (json/parse-string true))]
        (is (= {:description ""} forwarded)
            "a blank, explicitly — not a null, and not nothing")))))

(deftest a-conversion-whose-message-cannot-be-read-forwards-nothing-of-its-own
  ;; The direction this fallback points is the whole of its value. Filling in a
  ;; blank here would convert cleanly and lose the body permanently, with nothing
  ;; anywhere to say it happened; forwarding what arrived earns the server's
  ;; refusal, which says exactly that and leaves the message in the inbox.
  (with-upstream {"/api/messages/7/convert-to-task" {:body {:id 88}}}
    (fn [up]
      (request up (tracker-keys)
               {:method :post :uri "/tracker/api/messages/7/convert-to-task"
                :body (json/generate-string {})})
      (let [forwarded (-> (->> @(:seen up) (filter #(= :post (:method %))) first :body)
                          (json/parse-string true))]
        (is (= {} forwarded)
            "the upstream 404'd on the message, so nothing was invented for it")))))

(deftest a-conversion-that-arrives-already-sealed-is-refused-like-any-other-write
  (let [foreign (tracker-seal/seal @tracker-test-key :tasks :description "sealed in the box" nil)]
    (with-upstream {"/api/messages/7" {:body {:id 7 :description "the mail body"}}
                    "/api/messages/7/convert-to-task" {:body {:id 88}}}
      (fn [up]
        (let [resp (request up (tracker-keys)
                            {:method :post :uri "/tracker/api/messages/7/convert-to-task"
                             :body (json/generate-string {:description foreign})})]
          (is (= 400 (:status resp)))
          (is (= "already-sealed" (:reason (body-of resp))))
          (is (empty? (filter #(= :post (:method %)) @(:seen up)))
              "the key belongs on one side of this hop, converts included"))))))

(deftest an-ordinary-message-write-is-still-not-a-conversion
  (with-upstream {"/api/messages/7" {:body {:id 7}}}
    (fn [up]
      (request up (tracker-keys)
               {:method :put :uri "/tracker/api/messages/7"
                :body (json/generate-string {:description "an inbox body"})})
      (is (= 1 (count @(:seen up)))
          "one PUT and no read: a message body is never sealed and nothing is looked up")
      (let [forwarded (-> (->> @(:seen up) (filter #(= :put (:method %))) first :body)
                          (json/parse-string true))]
        (is (= "an inbox body" (:description forwarded)))))))
