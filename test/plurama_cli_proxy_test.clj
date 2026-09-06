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
  "One box-side request through the proxy, with the key it is to hold."
  [{:keys [port]} k {:keys [method uri body]}]
  (with-redefs [plurama-cli-proxy/credentials
                (delay {:cookbook {:base-url (str "http://127.0.0.1:" port)}
                        :tracker-just-msg {:base-url (str "http://127.0.0.1:" port)}})
                plurama-cli-proxy/seal-key (delay k)]
    (handle {:request-method method
             :uri uri
             :body (when body (java.io.StringReader. body))
             :headers {"content-type" "application/json"}})))

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
            (is (not (str/includes? logged secret)))
            (is (not (str/includes? logged "a new sentence, also private")))
            (is (not (str/includes? logged key-b64)))
            (is (not (str/includes? logged "enc:v1:")))))))))
