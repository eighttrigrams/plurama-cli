#!/usr/bin/env bb

(ns plurama-cli
  (:require [babashka.cli :as cli]
            [babashka.http-client :as http]
            [cheshire.core :as json]
            [clojure.edn :as edn]
            [clojure.java.io :as io]
            [clojure.string :as str]
            [cookbook-seal :as seal]
            [tracker-seal]))

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

(def ^:private tracker-seal-key
  "Tracker's key, which is **a different secret from cookbook's** and lives in a
  different file. One envelope, two apps, two keys: a leaked key cannot be
  rotated out of the data it already sealed, so there is no reason to make one
  leak cost two shelves. Lazily, for the same reason as above."
  (delay (tracker-seal/load-key)))

(defn- cookbook? [app] (= "cookbook" app))

(defn- tracker? [app]
  "Both configured identities that reach tracker's API.

  `tracker-just-msg` is the mail-only machine user, and it is in here for a
  reason that is easy to miss: **mail-only restricts what it may write, not what
  it may read.** An agent reading a task through that identity would meet
  `enc:v1:…` with nothing to say why if this named only `tracker`."
  (contains? #{"tracker" "tracker-just-msg"} app))

(defn- current-state
  "What the seal needs to know about the row a write is aimed at, out of **one**
  read — `:stored` and `:published?`, both parsed by `seal/state-of`, which is
  where the meaning of that read is written down for every client that makes it.

  What is here is the round trip and nothing else.

  Anything that goes wrong — a 404, a 401, a body that will not parse — yields
  `nil` for both, which means *nothing to echo* and a fresh seal. That is the safe
  direction for the echo rule: a redundant version is a wart, and a refused write
  is a lost one. It is the *unsafe* direction for the published rule, and
  deliberately: a client that cannot read the Recipe cannot know, and the server
  refuses what this would get wrong."
  [cfg token target]
  (when-let [path (seal/state-path target)]
    (try
      (let [resp (send-request cfg token {:method :get :path path :headers {}})]
        (when (= 200 (:status resp))
          (seal/state-of target (json/parse-string (:body resp) true))))
      (catch Exception _ nil))))

(defn- seal-request-body
  "Seal the prose of a cookbook write. Everything else — the title, the tags, the
  Scope ids, `modified_at` — goes as it was given, because it is what the search
  and the guards are made of.

  **A body carrying no prose at all is returned untouched, and never asks the
  server anything.** That is the guard worth naming, because without it a filing
  PUT paid for the echo rule it had no use for: `-d '{\"tags\":\"x\"}'` fetched a
  Recipe's whole version ladder to look up ciphertexts for columns it was not
  sending, and `PUT /scopes/3 -d '{\"title\":\"x\"}'` pulled the entire Scope
  listing for the same nothing. The extra read is unavoidable when there is
  something to echo; it is only unavoidable then.

  Returning the body itself rather than a re-serialisation is the second half of
  that, and it is what `seal/seal-write` answering `nil` means: a write with no
  prose in it, and a write to a published Recipe, both go over the wire
  byte-identical to what the caller typed, exactly as they did before any of this
  existed."
  [cfg token method path body]
  (let [k @seal-key
        target (when (#{:post :put} method) (seal/write-target (resolve-path path)))]
    (if-not (and k target body)
      body
      (let [parsed (try (json/parse-string body true) (catch Exception _ nil))]
        (if-not (seal/prose-in (:table target) parsed)
          body
          (if-let [sealed (seal/seal-write k target parsed (current-state cfg token target))]
            (json/generate-string sealed)
            body))))))

(defn- tracker-current-state
  "What the row a tracker write is aimed at holds right now, out of one plain
  single-row GET — `{:stored …}`, the shape `tracker-seal/state-of` defines and
  the proxy sidecar shares. The echo rule's input, and nothing else.

  Anything that goes wrong — a 404, a 401, a body that will not parse — yields
  `nil`, which means *nothing to echo* and a fresh seal. That is the safe
  direction: a redundant audit entry is a wart, a refused write is a lost one."
  [cfg token target]
  (when-let [path (tracker-seal/state-path target)]
    (try
      (let [resp (send-request cfg token {:method :get :path path :headers {}})]
        (when (= 200 (:status resp))
          (tracker-seal/state-of target (json/parse-string (:body resp) true))))
      (catch Exception _ nil))))

(defn- tracker-seal-request-body
  "Seal the prose of a tracker write. Titles, names, tags, scopes and every flag
  go as they were given, because they are what the search and the filters are
  made of.

  A body carrying no prose is returned untouched and asks the server nothing —
  the guard `tracker-seal/prose-in` exists for, and the one cookbook paid to
  learn: without it a `-d '{\"tags\":\"x\"}'` would fetch a whole row to look up
  a ciphertext for a column it is not sending."
  [cfg token method path body]
  (let [k @tracker-seal-key
        target (when (#{:post :put} method) (tracker-seal/write-target (resolve-path path)))]
    (if-not (and k target body)
      body
      (let [parsed (try (json/parse-string body true) (catch Exception _ nil))]
        (if-not (tracker-seal/prose-in (:table target) parsed)
          body
          (if-let [sealed (tracker-seal/seal-write k target parsed
                                                   (tracker-current-state cfg token target))]
            (json/generate-string sealed)
            body))))))

(defn- opened-or-warn
  "Parse, unseal, re-serialise — **keeping the two failures apart**, because they
  are not the same failure and conflating them hid a live bug for a whole
  cutover.

  A body that will not *parse* is expected and stays silent. An endpoint that
  answers HTML behind a JSON content-type, a proxy error page, a 204 with a
  content-type it did not mean: there is nothing to open and nothing to say.

  A body that parses and then will not *open* is a defect in this program, and it
  has to be audible. Rule 3 — unsealing never throws — is about a value that will
  not decrypt, and `seal-envelope/unseal-at` already honours it one level down by
  handing such a value back untouched, which is why one unreadable column shows
  as `enc:v1:…` beside everything that reads. Rule 3 was never about a
  *structural* failure. When `unseal-response-body` threw `ClassCastException` on
  every listing cheshire handed it, a single `try` around both steps dressed that
  up as rule 3 and returned ciphertext with a 200 — no error, no log line,
  nothing to search for. Both callers' docstrings already said a swallowed
  failure here 'would return the whole response still sealed and say nothing
  about why'. They were right. The `try` was drawn around one step too many.

  It still degrades rather than dying: one bad body should not cost an agent a
  whole listing, and that is the right shape for a read path. It simply stops
  being quiet about it. **stderr**, so the JSON on stdout stays exactly as
  pipeable as it was — an agent's `| jq` must not start eating a warning."
  [resp unseal]
  (let [body (try (json/parse-string (:body resp) true)
                  (catch Exception _ ::unparseable))]
    (if (= ::unparseable body)
      resp
      (try (let [out (unseal body)]
             (if (= body out) resp (assoc resp :body (json/generate-string out))))
           (catch Exception e
             (binding [*out* *err*]
               (println "plurama-cli: response left sealed —" (ex-message e)))
             resp)))))

(defn- tracker-unseal-response
  "Every tracker response, including refusals — a 400 from the seal guard names a
  column and carries no prose, but a 409 from the optimistic-concurrency guard
  carries the row that moved, and an agent reading `enc:v1:…` there has been told
  nothing.

  A response nothing was opened in goes through **byte-identical**: the walk
  collects only values that actually carry the prefix, so an unsealed database
  and a keyless run both cost one traversal and no re-serialisation.

  The catch is for a body that says it is JSON and is not. It is **not** what
  handles a value that will not open — `tracker-seal/unseal` hands those back as
  they are, so one unreadable body shows beside everything that reads rather than
  taking the response down with it."
  [resp]
  (let [k @tracker-seal-key]
    (if-not (and k (json-response? resp) (seq (:body resp)))
      resp
      (opened-or-warn resp #(tracker-seal/unseal-response-body k %)))))

(defn- refuse-sealed-publish!
  "Publishing hands the prose to somebody who has no key and must never have one,
  and there is **no unpublish** — recovery would mean writing the text back out in
  the clear by hand. So a sealed Recipe is refused here, before the call.

  Which columns are asked about is `seal/published-surface` — the two a visitor
  is served, so the two that would appear on a public page as `enc:v1:…`. It is
  named there rather than listed here because this interlock exists in three
  clients, and one of them widening while another did not is how a sealed column
  would stay reachable through the narrower one. The reason/context pair and the
  history are the owner's and are not published at any `?detail`.

  **It fails open** if the Recipe cannot be read — a 404, a 401, an unparseable
  body. That is the honest direction here rather than the safe-looking one: this
  check reads `/versions`, and a caller who cannot read that is a caller whose
  publish is about to be refused by the server anyway.

  **Defence in depth, and it is now the third refusal on the same act.**
  Publishing a sealed Recipe *does* unseal it since step 6 — the owner's browser
  reads GET /api/recipes/:id/sealed, opens every envelope in the Recipe's trail
  and hands the plaintext back with the publish, in one transaction. But that is
  the browser's alone: this tool signs in as `machine-user`, and cookbook refuses
  a machine publish with a 403 whatever it carries, sealed or not
  (`wrap-machine-recipe-rules`). The server also refuses any publish that would
  leave an envelope behind, whoever asks. So this check cannot be the only thing
  standing between a sealed Recipe and a public page, and it is not written as
  though it were — what it buys is a clearer sentence one round trip earlier."
  [cfg token id]
  (when-let [k @seal-key]
    (let [{:keys [stored]} (current-state cfg token {:table :recipes :id id})]
      (when (seal/published-surface-sealed? stored)
        (throw (ex-info (str "Recipe " id "'s text is encrypted, and publishing is one way. "
                             "Publishing unseals a Recipe, and only the owner's browser "
                             "holds a key to unseal it with — cookbook refuses a machine "
                             "publish outright. Publish it from the web UI.")
                        {:recipe-id id :seal :sealed-publish})))
      ;; `k` is bound so this reads as what it is: with no key configured there is
      ;; nothing sealed to protect anybody from.
      k)))

(defn- unseal-response
  "Every cookbook response, including the ones that are refusals: the 409 naming
  the Recipe that moved and the 409 naming a pending proposal both carry prose,
  and an agent reading `Refused:` with `enc:v1:…` under it has been told nothing.

  **Two things happen here and only one of them is unsealing.** The other is that
  a `caution` computed over ciphertext is taken off the body — see
  `seal/caution-over-ciphertext?` for why a wrong provenance split is worse than
  none. That one runs **whether or not there is a key**, which is why the key test
  moved off the guard and into the `let`: a client with no key is precisely the
  one that cannot tell the split is a lie.

  The body is re-serialised when either of them changed something, so `--raw`
  prints the same JSON with possibly a different key order. `--raw` means *do not
  pretty-print*; it has never meant *do not decrypt*. A response neither of them
  touched now goes through **byte-identical**, which it did not before: with no
  key every cookbook response was re-serialised for nothing.

  The catch is for a body that says it is JSON and is not. It is **not** what
  handles a value that will not open: `seal/unseal` hands those back as they
  are, so one unreadable column shows as `enc:v1:…` beside everything that
  reads. A catch that swallowed decryption failures here would return the whole
  response still sealed and say nothing about why — which is precisely what it
  did during development, and it cost an afternoon."
  [resp]
  (let [k @seal-key]
    (if-not (and (json-response? resp) (seq (:body resp)))
      resp
      ;; Both steps, in the order `seal/unseal-response-body` explains — and
      ;; `unseal-body` is a no-op with no key by its own first clause, so they
      ;; compose without a second test for one.
      (opened-or-warn resp #(seal/unseal-response-body k %)))))

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
  (let [lines (cond-> []
                (:cookbook @credentials)
                (conj ["cookbook" #(seal/key-source) "COOKBOOK_SEAL_KEY" seal/key-file])

                (some @credentials [:tracker :tracker-just-msg])
                (conj ["tracker" #(tracker-seal/key-source) "TRACKER_SEAL_KEY"
                       tracker-seal/key-file]))]
    (when (seq lines)
      (println))
    (doseq [[app source-fn env-var default-file] lines]
      ;; The try is so a misconfigured key file does not cost the reader the app
      ;; table above it. It still says what is wrong, on the line whose whole job
      ;; is to say what is true about sealing.
      (try
        (if-let [source (source-fn)]
          (println (str app " prose sealing: on, key from " source))
          (println (str app " prose sealing: off — no key. Set " env-var ", or put one at "
                        default-file)))
        (catch Exception e
          (println (str app " prose sealing: misconfigured — " (ex-message e))))))))

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
        _ (when-let [id (and (cookbook? app) (= :post method)
                             (seal/publish-target (resolve-path path)))]
            (refuse-sealed-publish! cfg token id))
        req (cond-> req
              (cookbook? app) (update :body #(seal-request-body cfg token method path %))
              (tracker? app) (update :body #(tracker-seal-request-body cfg token method path %)))
        resp (let [r (send-request cfg token req)]
               (if (and login-auth? (= 401 (:status r)))
                 (send-request cfg (login! app cfg) req)
                 r))
        resp (cond-> resp
               (cookbook? app) unseal-response
               (tracker? app) tracker-unseal-response)]
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
