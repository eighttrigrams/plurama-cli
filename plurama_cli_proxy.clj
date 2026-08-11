#!/usr/bin/env bb

;; The credential proxy for the sandboxes.
;;
;; `plurama-cli` bakes its credentials in, and the devboxes bind-mount the
;; restricted build of it. That build reaches less than the full one, but the
;; secrets are still *in* the box: `baked-credentials` is base64, not
;; ciphertext, so a three-line decode recovers two live passwords. They can be
;; copied out, and they keep working long after the container is gone.
;;
;; This moves them one hop away. The box gets a build whose baked blob holds
;; URLs and no passwords at all -- they point here, and this process does the
;; login and adds the Authorization header on the way past. Nothing in the box
;; can name a credential, because there is no longer one to name.
;;
;; What that does and does not buy:
;;
;;   - It stops exfiltration and persistence. A password can no longer end up in
;;     a transcript, a screenshot, a committed file, or somebody's clipboard
;;     three months from now.
;;   - It does NOT, by itself, narrow what the box can *do* while it runs.
;;     Anything that can reach this port gets whatever this port allows. That is
;;     what `allowlist` below is for, and why it is deliberately tighter than
;;     the credentials themselves.
;;
;; There is no auth between the box and here. The boundary is the network: in
;; locked mode the box sits on an internal compose network with no gateway, and
;; only the sidecars on it can be reached at all. A shared secret would have to
;; live in the box's environment to be usable, which puts us back where we
;; started, one indirection along.

(ns plurama-cli-proxy
  (:require [babashka.http-client :as http]
            [cheshire.core :as json]
            [clojure.edn :as edn]
            [clojure.java.io :as io]
            [clojure.string :as str]
            [org.httpkit.server :as srv]))

(def ^:private port
  (Integer/parseInt (or (System/getenv "PLURAMA_PROXY_PORT") "8899")))

(def ^:private credentials-path
  "Mounted read-only into this container and nowhere else. Deliberately not an
  env var holding the secrets themselves: env leaks through `docker inspect`,
  crash dumps and any child process, and the compose file that would have to
  set it is synced to a git remote."
  (or (System/getenv "PLURAMA_PROXY_CREDENTIALS") "/credentials.edn"))

(def ^:private credentials
  (delay
    (let [f (io/file credentials-path)]
      (when-not (.exists f)
        (binding [*out* *err*]
          (println "plurama-cli-proxy: no credentials at" credentials-path))
        (System/exit 1))
      (edn/read-string (slurp f)))))

(def ^:private allowlist
  "What the box may ask for, per app -- method plus a pattern the *upstream*
  path must match in full. Everything not matched is refused here, before any
  credential is attached.

  This is narrower than the credentials on purpose. `cookbook`'s machine user
  can write unsupervised and `tracker-just-msg` is only mail-only because
  tracker's own recording gate says so; neither restriction is visible from in
  here, and neither is ours. These rules are, and they sit outside the box where
  nothing in it can edit them.

  The starting set mirrors what docker/CLAUDE.md actually tells an in-box agent
  to do -- consult and add to the memory store, and post one inbox message per
  finished task -- so it should not break a workflow that was already sanctioned.
  Widen it here, deliberately, rather than reaching for the full binary."
  {:cookbook         [[:get  #"/api(/.*)?"]
                      [:post #"/api/recipes"]]
   :tracker-just-msg [[:post #"/api/messages"]]})

(defn- allowed? [app method path]
  (boolean
   (some (fn [[m pattern]]
           (and (= m method) (re-matches pattern path)))
         (get allowlist app))))

;; ---------------------------------------------------------------------------
;; Upstream tokens. Same login dance plurama_cli.clj does, kept in memory
;; rather than on disk: this process is the only thing that needs them, and a
;; token file would be one more artifact to reason about.

(def ^:private tokens (atom {}))

(defn- login! [app {:keys [base-url username password]}]
  (let [resp (http/post (str base-url "/api/auth/login")
                        {:headers {"Content-Type" "application/json"}
                         :body (json/generate-string {:username username
                                                      :password password})
                         :throw false})]
    (if (= 200 (:status resp))
      (let [token (-> resp :body (json/parse-string true) :token)]
        (swap! tokens assoc app token)
        token)
      (throw (ex-info (str "login to " base-url " failed: HTTP " (:status resp))
                      {:app app})))))

(defn- token-for [app cfg]
  (or (get @tokens app) (login! app cfg)))

(defn- forward
  "One upstream attempt. Separate from the retry in `handle` so a 401 can be
  retried against a freshly minted token without re-deciding anything else."
  [cfg token {:keys [method path query body content-type]}]
  (http/request
   {:method method
    :uri (str (:base-url cfg) path (when (seq query) (str "?" query)))
    :headers (cond-> {}
               token        (assoc "Authorization" (str "Bearer " token))
               content-type (assoc "Content-Type" content-type))
    :body body
    :throw false}))

;; ---------------------------------------------------------------------------

(defn- split-target
  "`/cookbook/api/recipes` -> [:cookbook \"/api/recipes\"]. The first segment
  names the app because that is what the box's baked base-url ends in; the rest
  is the upstream path verbatim."
  [uri]
  (let [[_ app rest] (re-matches #"/([^/]+)(/.*)?" (or uri "/"))]
    (when app
      [(keyword app) (or rest "/")])))

(defn- log! [& parts]
  ;; Every decision, on stdout, where `docker compose logs plurama-proxy` finds
  ;; it. The audit trail is a feature and not a side effect: the baked-in
  ;; arrangement could not produce one, so nothing recorded what an agent did
  ;; in the owner's name.
  (println (str/join " " (map str parts)))
  (flush))

(defn- json-response [status m]
  {:status status
   :headers {"Content-Type" "application/json"}
   :body (json/generate-string m)})

(defn- handle [{:keys [request-method uri query-string body headers]}]
  (let [[app path] (or (split-target uri) [nil nil])
        cfg (get @credentials app)]
    (cond
      (nil? app)
      (json-response 400 {:error "expected /<app>/<path>"})

      (nil? cfg)
      (do (log! "DENY" request-method uri "- unknown app")
          (json-response 404 {:error (str "unknown app: " (name app))
                              :configured (sort (map name (keys @credentials)))}))

      (not (allowed? app request-method path))
      (do (log! "DENY" request-method uri "- not in allowlist")
          (json-response 403 {:error "refused by proxy allowlist"
                              :app (name app)
                              :method (name request-method)
                              :path path}))

      :else
      (let [req {:method request-method
                 :path path
                 :query query-string
                 ;; Read the stream now: the retry below would otherwise get an
                 ;; already-consumed body and silently POST nothing.
                 :body (when body (slurp body))
                 :content-type (get headers "content-type")}
            auth? (some? (:username cfg))]
        (try
          (let [token (when auth? (token-for app cfg))
                resp (let [r (forward cfg token req)]
                       (if (and auth? (= 401 (:status r)))
                         ;; Cached token went stale (restarted app, rotated
                         ;; password). Mint once and retry; a second 401 is the
                         ;; caller's answer.
                         (forward cfg (login! app cfg) req)
                         r))]
            (log! "ALLOW" request-method uri "->" (:status resp))
            {:status (:status resp)
             :headers (select-keys (:headers resp) ["content-type"])
             :body (:body resp)})
          (catch Exception e
            (log! "ERROR" request-method uri "-" (ex-message e))
            ;; The message can name the upstream URL but never a credential --
            ;; login! only ever reports a status code.
            (json-response 502 {:error (ex-message e)})))))))

(defn -main [& _]
  (let [apps (sort (map name (keys @credentials)))]
    (log! "plurama-cli-proxy listening on" port)
    (log! "targets:" (str/join ", " apps))
    (doseq [app apps
            :let [rules (get allowlist (keyword app))]]
      (log! " " app (if (seq rules)
                      (str/join "; " (for [[m p] rules]
                                       (str (str/upper-case (name m)) " " p)))
                      "(nothing allowed -- no rules)")))
    (srv/run-server handle {:port port :ip "0.0.0.0"})
    @(promise)))

(when (= *file* (System/getProperty "babashka.file"))
  (apply -main *command-line-args*))
