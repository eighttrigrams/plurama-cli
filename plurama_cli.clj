#!/usr/bin/env bb

(ns plurama-cli
  (:require [babashka.cli :as cli]
            [babashka.http-client :as http]
            [cheshire.core :as json]
            [clojure.edn :as edn]
            [clojure.java.io :as io]
            [clojure.string :as str]))

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
      (System/setProperty (str scheme ".proxyPort") (str (if (pos? port) port 80))))))

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
                     (or (:username cfg) "(no auth)")))))

(defn- run [app path opts]
  (let [cfg (app-config app)
        body (read-body (:body opts))
        method (keyword (str/lower-case (or (:method opts) (if body "post" "get"))))
        req {:method method
             :path path
             :body body
             :headers (parse-headers (:header opts))}
        auth? (some? (:username cfg))
        token (when auth? (or (cached-token app) (login! app cfg)))
        resp (let [r (send-request cfg token req)]
               (if (and auth? (= 401 (:status r)))
                 (send-request cfg (login! app cfg) req)
                 r))]
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
