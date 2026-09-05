#!/usr/bin/env bb

(ns plurama-cli
  (:require [babashka.cli :as cli]
            [babashka.http-client :as http]
            [cheshire.core :as json]
            [clojure.edn :as edn]
            [clojure.java.io :as io]
            [clojure.string :as str]
            [cookbook-seal :as seal]))

(def ^:private baked-credentials
  "Base64-encoded EDN, substituted at install time by the private
  `deploy-plurama-cli-cookbook-tui-and-us-vs-them-cli.sh` script. Left as the
  literal marker in the public repo."
  "__BAKED_CREDENTIALS__")

(def ^:private tool-name
  "What to call this program in its own help — **read off the invocation, not
  baked in**.

  One source yields more than one binary: a full `plurama-cli`, and a
  `plurama-cli-restricted` carrying only cookbook and the mail-only tracker
  target, which is what the devboxes mount. So the help has to name itself, or a
  restricted build would tell a sandboxed agent to run a binary it does not have.

  This was first done by substituting the name at install time, next to the
  credentials. That version lied the moment the file was called anything else —
  copy the binary, rename it, mount it elsewhere, and it still announced the name
  it was built under. `babashka.file` is the path babashka was actually handed,
  so this cannot disagree with reality however the file is named or mounted.

  Falls back for the checkout: run straight from source the path ends in `.clj`,
  and `plurama_cli.clj` is a filename rather than a command anyone types."
  (let [invoked (some-> (System/getProperty "babashka.file")
                        java.io.File. .getName)]
    (if (or (str/blank? invoked) (str/ends-with? invoked ".clj"))
      "plurama-cli"
      invoked)))

(defn- apply-proxy-env!
  "Point the JDK at the proxy named by HTTP(S)_PROXY.

  A locked devbox has no gateway, so its egress proxy is the only way out, and
  it is announced through that env var. curl reads it; babashka.http-client
  sits on java.net.http.HttpClient, which reads only the system properties
  below — so without this the CLI has no route out of a box at all."
  []
  (doseq [scheme ["http" "https"]
          :let [url (System/getenv (str/upper-case (str scheme "_proxy")))]
          :when (not (str/blank? url))]
    (let [uri (java.net.URI. url)
          port (.getPort uri)]
      (System/setProperty (str scheme ".proxyHost") (.getHost uri))
      (System/setProperty (str scheme ".proxyPort") (str (if (pos? port) port 80)))))
  ;; NO_PROXY, in the form the JDK wants. Setting proxyHost alone routes
  ;; *everything* through the egress proxy, including sidecars on the box's own
  ;; compose network -- which tinyproxy then refuses, since its filter names
  ;; public hosts and nothing internal. That is how the credential proxy gets
  ;; locked out of a locked box: it lives at http://plurama-proxy:8899, on the
  ;; internal network, and every call to it dies in the egress filter.
  ;;
  ;; curl honours NO_PROXY natively; the JDK does not read the env var at all,
  ;; only `nonProxyHosts`, pipe-separated with `*` wildcards. `.foo` is the
  ;; env-var idiom for a domain suffix and becomes `*.foo`.
  ;;
  ;; Both keys are set because HTTPS is the ambiguous one: the JDK's default
  ;; ProxySelector is documented to fold https onto `http.nonProxyHosts`, and
  ;; writing the https key too costs nothing if it is indeed never read.
  (when-let [no-proxy (System/getenv "NO_PROXY")]
    (let [hosts (->> (str/split no-proxy #",")
                     (map str/trim)
                     (remove str/blank?)
                     (map #(if (str/starts-with? % ".") (str "*" %) %)))]
      (when (seq hosts)
        (let [spec (str/join "|" hosts)]
          (System/setProperty "http.nonProxyHosts" spec)
          (System/setProperty "https.nonProxyHosts" spec))))))

(def ^:private credentials-file
  (io/file (System/getProperty "user.home") ".config" "plurama-cli" "credentials.edn"))

(defn- decode-baked []
  (when-not (str/starts-with? baked-credentials "__")
    (-> (java.util.Base64/getDecoder)
        (.decode ^String baked-credentials)
        (String. "UTF-8")
        edn/read-string)))

(defn- read-credentials-file []
  (when (.exists credentials-file)
    (edn/read-string (slurp credentials-file))))

(def ^:private credentials
  (delay (or (decode-baked) (read-credentials-file) {})))

(defn- app-config [app]
  (or (get @credentials (keyword app))
      (throw (ex-info (str "unknown app: " app
                           " (configured: "
                           (str/join ", " (sort (map name (keys @credentials))))
                           ")")
                      {:app app}))))

(def ^:private token-dir
  (io/file (System/getProperty "user.home") ".cache" "plurama-cli"))

(defn- token-file [app]
  (io/file token-dir (str (name app) ".token")))

(defn- cached-token [app]
  (let [f (token-file app)]
    (when (.exists f)
      (str/trim (slurp f)))))

(defn- cache-token! [app token]
  (.mkdirs token-dir)
  (let [f (token-file app)]
    (spit f token)
    (java.nio.file.Files/setPosixFilePermissions
     (.toPath f)
     (java.nio.file.attribute.PosixFilePermissions/fromString "rw-------"))))

(defn- resolve-path
  "Request paths are relative to `/api`, the one root every plurama app serves
  its API under. A path that already starts with `/api` is taken as given, so
  the older absolute form keeps working."
  [path]
  (let [path (if (str/starts-with? path "/") path (str "/" path))]
    (if (or (= path "/api") (str/starts-with? path "/api/"))
      path
      (str "/api" path))))

(defn- login! [app {:keys [base-url username password]}]
  (let [resp (http/post (str base-url "/api/auth/login")
                        {:headers {"Content-Type" "application/json"}
                         :body (json/generate-string {:username username :password password})
                         :throw false})]
    (if (= 200 (:status resp))
      (let [token (-> resp :body (json/parse-string true) :token)]
        (cache-token! app token)
        token)
      (throw (ex-info (str "login to " base-url " failed: HTTP " (:status resp)) {})))))

(defn- parse-headers [headers]
  (into {} (for [h headers
                 :let [[k v] (str/split h #":" 2)]
                 :when v]
             [(str/trim k) (str/trim v)])))

(defn- read-body [body]
  (when body
    (if (str/starts-with? body "@")
      (slurp (subs body 1))
      body)))

(defn- send-request [{:keys [base-url]} token {:keys [method path body headers]}]
  (http/request
   {:method method
    :uri (str base-url (resolve-path path))
    :headers (cond-> headers
               token (assoc "Authorization" (str "Bearer " token))
               body (assoc "Content-Type" "application/json"))
    :body body
    :throw false}))

(defn- json-response? [resp]
  (some-> (get-in resp [:headers "content-type"]) (str/includes? "json")))

(defn- print-response [resp {:keys [include raw]}]
  (when include
    (println (str "HTTP " (:status resp)))
    (doseq [[k v] (sort-by key (:headers resp))]
      (println (str k ": " v)))
    (println))
  (let [body (:body resp)]
    (if (and (json-response? resp) (not raw) (seq body))
      (println (json/generate-string (json/parse-string body) {:pretty true}))
      (when (seq body) (println body)))))

;; ---------------------------------------------------------------------------
;; Cookbook's prose is sealed in the clients.
;;
;; Cookbook is served from fly and the key is never sent there, so there is no
;; trusted middle process to seal in: the browser does it on WebCrypto and this
;; does it on javax.crypto. Both use the one envelope in `cookbook_seal.clj`, and
;; a fixture in the cookbook repo pins it so the two cannot drift.
;;
;; That makes this program the reading and writing surface for **agents**. Note
;; the two credentials are different things: the machine token says who may
;; *write*, and the key says who may *read prose*. An agent with a token and no
;; key can fill the shelf and cannot read a word of what is on it.
;;
;; With no key configured nothing here does anything at all — see
;; `cookbook-seal/load-key`.

(def ^:private seal-key
  "Read once, and lazily: a run that never touches cookbook has no business
  failing on a malformed key file, and a run that does has every business
  failing on it."
  (delay (seal/load-key)))

(defn- cookbook? [app] (= "cookbook" app))

(defn- write-target
  "Which table a cookbook write is aimed at, and at which row — `nil` for
  everything else, which is most of the API. `/recipes/7/publish` is deliberately
  not matched: it carries no body, and after step 6 it is an unseal rather than a
  seal."
  [path]
  (let [p (-> path (str/split #"\?") first (str/replace #"/$" ""))
        id #(parse-long (last (str/split % #"/")))]
    (cond
      (= p "/api/recipes") {:table :recipes}
      (= p "/api/scopes")  {:table :scopes}
      (re-matches #"/api/recipes/\d+" p) {:table :recipes :id (id p)}
      (re-matches #"/api/scopes/\d+" p)  {:table :scopes  :id (id p)})))

(defn- stored-columns
  "What that row's sealed columns hold **right now**, so a value the caller did
  not change can be written back as the very ciphertext already stored. Without
  it, a fresh nonce makes every resend look like a change to the server, and an
  agent that PUTs the same text twice piles up versions, history rows and inbox
  entries — corrupting the ladder the seal exists to protect.

  A Recipe's is read from `/versions` and **not** from `?detail=full`, which is
  the whole reason this is reachable at all: a full read counts as a consumption
  and ranks the shelf, so seal bookkeeping would quietly reorder the owner's
  Cookbook. `/versions` carries all four columns of the current row and counts
  nothing.

  Anything that goes wrong here — a 404, a 401, a body that will not parse —
  yields `nil`, which means *nothing to echo* and a fresh seal. That is the safe
  direction: a redundant version is a wart, and a refused write is a lost one."
  [cfg token {:keys [table id]}]
  (when id
    (try
      (let [path (case table
                   :recipes (str "/api/recipes/" id "/versions")
                   :scopes "/api/scopes")
            resp (send-request cfg token {:method :get :path path :headers {}})]
        (when (= 200 (:status resp))
          (let [parsed (json/parse-string (:body resp) true)]
            (case table
              :recipes (some-> (->> parsed :versions (filter :current) first)
                               (select-keys [:description :useful_when :reason :context]))
              :scopes (some-> (->> parsed (filter #(= id (:id %))) first)
                              (select-keys [:description]))))))
      (catch Exception _ nil))))

(defn- seal-request-body
  "Seal the prose of a cookbook write. Everything else — the title, the tags, the
  Scope ids, `modified_at` — goes as it was given, because it is what the search
  and the guards are made of."
  [cfg token method path body]
  (let [k @seal-key
        target (when (#{:post :put} method) (write-target (resolve-path path)))]
    (if-not (and k target body)
      body
      (let [parsed (try (json/parse-string body true) (catch Exception _ nil))]
        (if-not (map? parsed)
          body
          (let [stored (stored-columns cfg token target)]
            (json/generate-string
             (case (:table target)
               :recipes (seal/seal-recipe-write k parsed stored)
               :scopes (seal/seal-scope-write k parsed stored)))))))))

(defn- unseal-response
  "Every cookbook response, including the ones that are refusals: the 409 naming
  the Recipe that moved and the 409 naming a pending proposal both carry prose,
  and an agent reading `Refused:` with `enc:v1:…` under it has been told nothing.

  The body is re-serialised rather than passed through, so `--raw` prints the
  same JSON with possibly a different key order. `--raw` means *do not
  pretty-print*; it has never meant *do not decrypt*."
  [resp]
  (let [k @seal-key]
    (if-not (and k (json-response? resp) (seq (:body resp)))
      resp
      (try (update resp :body #(json/generate-string (seal/unseal-body k (json/parse-string % true))))
           (catch Exception _ resp)))))

(def ^:private cli-spec
  {:method {:desc "HTTP method (default GET, or POST when --body is given)"}
   :body {:desc "Request body, or @file to read from a file"}
   :header {:desc "Extra header \"Key: Value\" (repeatable)" :coerce []}
   :include {:desc "Print status line and response headers" :coerce :boolean}
   :raw {:desc "Do not pretty-print JSON responses" :coerce :boolean}
   :help {:coerce :boolean}})

(def ^:private cli-aliases
  {:X :method :d :body :H :header :i :include :h :help})

(def ^:private examples-by-app
  "Example invocations, filed under the app each one needs, minus the program
  name. Printed only for apps this build actually carries.

  Hardcoded examples are how the help came to advertise a treina `?limit` that
  treina has never implemented — a filter somebody then reported as broken. A
  restricted build listing `rhizome` and `tracker` would fail the same way and
  more often, since those targets are absent rather than merely unhelpful.

  The order here is the order they print in; apps not baked in simply drop out."
  [["treina"           ["treina /describe"]]
   ["treina"           ["treina '/trainings/?search=squat'"]]
   ["treina"           ["treina /trainings/ -X POST --body '{\"name\":\"Squat\"}'"]]
   ["tracker"          ["tracker /today-board"]]
   ["rhizome"          ["rhizome '/contexts?q=Books'"]]
   ["cookbook"         ["cookbook '/recipes?search=docker'"]]
   ;; /me is the cheapest proof the baked machine token is still the live one:
   ;; 200 names the machine user, 401 means it was rotated out from under us.
   ["personalist"      ["personalist /me"]]
   ["tracker-just-msg" ["tracker-just-msg /messages \\"
                        "    --body '{\"sender\":\"Plurama Development Coordinator\",\"title\":\"...\"}'"]]])

(defn- print-examples [configured]
  (let [shown (for [[app lines] examples-by-app
                    :when (contains? configured app)]
                lines)]
    (when (seq shown)
      (println "Examples:")
      (doseq [[head & tail] shown]
        (println (str "  " tool-name " " head))
        (doseq [line tail] (println line)))
      (println))))

(defn- usage []
  (println (str "Usage: " tool-name " <app> <path> [options]"))
  (println (str "       " tool-name " apps"))
  (println)
  (println "Curl-like client for the plurama apps. Credentials are baked in at install time.")
  (println)
  (println "Options:")
  (println "  -X, --method METHOD   HTTP method (default GET, or POST when --body is given)")
  (println "  -d, --body BODY       Request body, or @file")
  (println "  -H, --header H        Extra header \"Key: Value\" (repeatable)")
  (println "  -i, --include         Print status line and response headers")
  (println "      --raw             Do not pretty-print JSON responses")
  (println)
  ;; Listed from the baked credentials rather than hardcoded, so a target added
  ;; by the deploy script shows up here without this text going stale.
  (println "Configured apps:")
  (let [apps (sort (map name (keys @credentials)))]
    (if (seq apps)
      (println "  " (str/join ", " apps))
      (println "   (none — no baked credentials and no credentials.edn)"))
    (println (str "  Run '" tool-name " apps' for each one's endpoint and identity."))
    (println)
    (print-examples (set apps)))
  (println "Paths are relative to /api, where every plurama app serves its API;")
  (println "a path that already starts with /api is passed through unchanged.")
  (println)
  (println "Single-quote anything with a query string or a JSON body: in zsh an")
  (println "unquoted ? is a glob and fails outright, and & would background the")
  (println "command. Plain paths need no quotes."))

(defn- list-apps []
  (doseq [[app cfg] (sort-by key @credentials)]
    (println (format "%-18s %-40s %s" (name app) (str (:base-url cfg) "/api")
                     ;; The identity column names the auth kind as well as the
                     ;; identity, because "(no auth)" here is load-bearing: it is
                     ;; how the proxy build is checked to carry no credentials,
                     ;; and a machine token silently reading like a login would
                     ;; blunt that.
                     (cond
                       (:token cfg)    (str (or (:username cfg) "machine") " (token)")
                       (:username cfg) (:username cfg)
                       :else           "(no auth)"))))
  ;; **Whether cookbook's prose is sealed, said out loud**, because the failure
  ;; is silent in the direction that matters: an agent with no key writes
  ;; plaintext into a sealed shelf and is told nothing. It names the source and
  ;; never the key. Off is a legitimate state — it is cookbook before any of
  ;; this — so this is a fact and not a warning.
  (when (:cookbook @credentials)
    (println)
    (if-let [source (seal/key-source)]
      (println (str "cookbook prose sealing: on, key from " source))
      (println (str "cookbook prose sealing: off — no key. Set COOKBOOK_SEAL_KEY, or put one at "
                    seal/key-file)))))

(defn- run [app path opts]
  (let [cfg (app-config app)
        body (read-body (:body opts))
        method (keyword (str/lower-case (or (:method opts) (if body "post" "get"))))
        req {:method method
             :path path
             :body body
             :headers (parse-headers (:header opts))}
        ;; Two credential kinds reach the same Authorization: Bearer header.
        ;;
        ;; `:token` is an opaque machine token baked in whole -- personalist's
        ;; `pmu_...`, minted once in its UI and only ever stored as a SHA-256
        ;; hash, so there is nothing to log in with and nothing to cache. It is
        ;; used verbatim.
        ;;
        ;; `:username`/`:password` is the older path: POST /api/auth/login for a
        ;; short-lived JWT, cached on disk, re-minted on a 401.
        ;;
        ;; A static token gets no 401 retry, deliberately. There is no second
        ;; thing to try -- rotation is revocation for these, so a 401 means the
        ;; token was replaced and the baked one is dead. Retrying would just ask
        ;; twice and report the same failure a beat later.
        static-token (:token cfg)
        login-auth? (and (nil? static-token) (some? (:username cfg)))
        token (or static-token
                  (when login-auth? (or (cached-token app) (login! app cfg))))
        ;; Cookbook only, and only on a write that carries prose. Sealing needs
        ;; the token, so it happens here rather than beside `read-body` above.
        req (cond-> req
              (cookbook? app) (update :body #(seal-request-body cfg token method path %)))
        resp (let [r (send-request cfg token req)]
               (if (and login-auth? (= 401 (:status r)))
                 (send-request cfg (login! app cfg) req)
                 r))
        resp (cond-> resp (cookbook? app) unseal-response)]
    (print-response resp opts)
    (if (<= 200 (:status resp) 299) 0 1)))

(defn -main [& args]
  (apply-proxy-env!)
  (let [{:keys [opts args]} (cli/parse-args args {:spec cli-spec :aliases cli-aliases})
        [app path] args]
    (cond
      (or (:help opts) (nil? app)) (do (usage) (System/exit 0))
      (= "apps" app) (do (list-apps) (System/exit 0))
      (nil? path) (do (usage) (System/exit 2))
      :else
      (try
        (System/exit (run app path opts))
        (catch Exception e
          ;; `tool-name`, not a literal: this line is what a sandboxed agent
          ;; sees when it names an app its build does not carry, and telling it
          ;; `plurama-cli:` would name a binary it has not got.
          (binding [*out* *err*] (println (str tool-name ":") (ex-message e)))
          (System/exit 2))))))

(when (= *file* (System/getProperty "babashka.file"))
  (apply -main *command-line-args*))
