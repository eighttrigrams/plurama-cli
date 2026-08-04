#!/usr/bin/env bb

(ns cookbook-tui
  "A line-based browser and editor for cookbook, the agentic memory store.

  Written as its own program rather than derived from `plurama_cli.clj`. That one
  is a one-shot curl-like client: parse argv, do one request, print, exit. This
  holds state, renders a view and loops on input, so deriving one from the other
  would leave argv-parsing and single-request assumptions embedded in something
  whose job is neither.

  **Line-based on purpose.** babashka has no curses binding, and the alternative
  is raw mode — `stty -echo raw`, ANSI cursor control, arrow keys — which is much
  nicer to use, considerably more to get right, and easy to leave a terminal
  broken by on an exception. This works over ssh and inside cmux, and it is what
  the rest of plurama-cli already feels like. Rendering is kept separate from the
  input loop below so a full-screen version could reuse it.

  **Markdown is printed raw.** A Recipe body is markdown and reads fine as text;
  a terminal renderer with Clojure highlighting is a project of its own.

  **The lean projection is the point, not an optimisation.** The listing asks for
  no `?detail=full`, so it never carries a description — cookbook's reader is an
  agent that scans title and useful-when to decide what is relevant and then
  fetches exactly one body. This tool reads the same way."
  (:require [babashka.http-client :as http]
            [cheshire.core :as json]
            [clojure.edn :as edn]
            [clojure.java.io :as io]
            [clojure.string :as str]))

;; ---------------------------------------------------------------------------
;; Credentials and tokens.
;;
;; Deliberately duplicated from plurama_cli.clj rather than shared. bbin installs
;; single files, so a `require` between the two would have to resolve both from a
;; checkout *and* from an installed standalone script. These ~30 lines are the one
;; place here where copying beats factoring; the conventions must stay identical.

(def ^:private baked-credentials
  "Base64-encoded EDN, substituted at install time by the private
  `deploy-plurama-cli` script. Left as the literal marker in the public repo."
  "__BAKED_CREDENTIALS__")

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

(def ^:private config
  "Only cookbook's entry, never the whole blob. The baked map holds every
  configured app's credential — the same map already inside the plurama-cli
  binary at mode 700, so this is not new exposure — but nothing here has any
  business reading another app's row, let alone printing one."
  (delay
    (or (:cookbook (or (decode-baked) (read-credentials-file) {}))
        (throw (ex-info (str "no cookbook credential. Either install with "
                             "deploy-plurama-cli.sh, or add a :cookbook entry to "
                             credentials-file)
                        {})))))

(def ^:private token-dir
  (io/file (System/getProperty "user.home") ".cache" "plurama-cli"))

(defn- token-file [] (io/file token-dir "cookbook.token"))

(defn- cached-token []
  (let [f (token-file)]
    (when (.exists f) (str/trim (slurp f)))))

(defn- cache-token!
  "Same directory and filename as plurama-cli uses, so a token minted by either
  tool serves the other."
  [token]
  (.mkdirs token-dir)
  (let [f (token-file)]
    (spit f token)
    (java.nio.file.Files/setPosixFilePermissions
     (.toPath f)
     (java.nio.file.attribute.PosixFilePermissions/fromString "rw-------"))))

(defn- login! []
  (let [{:keys [base-url username password]} @config
        resp (http/post (str base-url "/api/auth/login")
                        {:headers {"Content-Type" "application/json"}
                         :body (json/generate-string {:username username :password password})
                         :throw false})]
    (if (= 200 (:status resp))
      (doto (-> resp :body (json/parse-string true) :token) cache-token!)
      (throw (ex-info (str "login to " base-url " failed: HTTP " (:status resp)
                           ". Cookbook must be deployed and its machine user must "
                           "have a password set, from the web UI's settings panel.")
                      {})))))

(defn- api
  "One request, retried once after a fresh login on a 401 — a cached token
  outlives a password rotation otherwise.

  A config with **no `:username`** is treated as unauthenticated: no login, no
  `Authorization` header, no retry. That is the same rule `plurama_cli.clj`
  applies, and it is what makes a local dev cookbook drivable — dev runs with
  `:dangerously-skip-logins?`, so there is no machine user to log in as, and
  logging in unconditionally would 401 against the one target where no credential
  is needed."
  ([method path] (api method path nil))
  ([method path body]
   (let [{:keys [base-url username]} @config
         auth? (some? username)
         send (fn [token]
                (http/request
                 (cond-> {:method method
                          :uri (str base-url path)
                          :headers {}
                          :throw false}
                   token (update :headers assoc "Authorization" (str "Bearer " token))
                   body (assoc :body (json/generate-string body))
                   body (update :headers assoc "Content-Type" "application/json"))))
         resp (send (when auth? (or (cached-token) (login!))))
         resp (if (and auth? (= 401 (:status resp))) (send (login!)) resp)]
     {:status (:status resp)
      :body (when (seq (:body resp))
              (try (json/parse-string (:body resp) true)
                   (catch Exception _ (:body resp))))})))

;; ---------------------------------------------------------------------------
;; Rendering. Pure: state in, strings out, no input and no requests. Kept apart
;; from the loop so a full-screen version could reuse all of it.

(defn- refusal
  "The two things this tool cannot do, in words rather than as a bare 403.
  Cookbook has **no** recording-mode gate — a machine credential writes
  unsupervised — so a 403 here is always the publish latch and nothing else."
  [status body action]
  (cond
    (= 403 status)
    (str "Refused: " (or (:error body) "forbidden") "\n"
         (case action
           :publish "  Publishing is the owner's — it is irreversible, so only he does it, from the web UI."
           "  A published Recipe is the owner's. Edit it in the web UI, or work on an unpublished one here."))

    (= 404 status) "No such Recipe (or it is not yours)."
    (= 409 status) "Someone else saved this Recipe while you had it open. Reopen it and redo the edit."
    (= 400 status) (str "Rejected: " (or (:error body) "bad request"))
    :else (str "HTTP " status (when body (str " — " (pr-str body))))))

(defn- render-list [recipes]
  (if (empty? recipes)
    ["(no Recipes yet — n to write the first one)"]
    (into ["  #  ver  pub  title / useful-when"
           "  -  ---  ---  ---------------------------------------------------"]
          (map-indexed
           (fn [i {:keys [id version published title useful_when]}]
             (format "%3d  %3s  %3s  %s\n              %s"
                     id version (if (= 1 published) " ✔ " "   ")
                     title
                     (if (str/blank? useful_when) "(no useful-when)" useful_when)))
           recipes))))

(defn- render-recipe [{:keys [id title useful_when description version published published_at modified_at]}]
  (concat [(str "── Recipe " id "  ·  v" version
                (if (= 1 published) (str "  ·  published " published_at) "  ·  private"))
           ""
           (str "title:       " title)
           (str "useful-when: " (if (str/blank? useful_when) "(none)" useful_when))
           ""]
          (if (str/blank? description)
            ["(no description)"]
            (str/split-lines description))
          ["" (str "last saved " modified_at)]))

;; ---------------------------------------------------------------------------
;; Input.

(defn- prompt [label]
  (print label) (flush) (read-line))

(defn- prompt-keep
  "Blank keeps the current value, so an edit meant for one field cannot silently
  clear another — the same rule the API applies to an omitted field."
  [label current]
  (let [v (prompt (str label " [" (or current "") "]: "))]
    (if (str/blank? v) current v)))

(defn- read-lines
  "Lines until a lone `.` — the convention mail clients used for the same job."
  []
  (loop [lines []]
    (let [l (read-line)]
      (if (or (nil? l) (= "." l))
        lines
        (recur (conj lines l))))))

(defn- show-body [lines]
  (if (empty? lines)
    (println "  (empty)")
    (doseq [[i l] (map-indexed vector lines)]
      (println (format "  %2d  %s" (inc i) l)))))

(defn- edit-body
  "Bodies are edited **here**, not in `$EDITOR`. This is a TUI and it stays one:
  shelling out makes the tool unusable wherever no editor is configured, and it
  hands the terminal to a process whose exit conditions this loop does not
  control.

  A new body is typed straight in and ended with a lone `.`. An existing one is
  shown numbered and edited a line at a time, because retyping a whole Recipe to
  change one word is not editing."
  [current]
  (let [lines (if (str/blank? (or current "")) [] (vec (str/split-lines current)))]
    (if (empty? lines)
      (do (println "Body — type it, and end with a single '.' on its own line.")
          (str/join "\n" (read-lines)))
      (loop [lines lines]
        (println)
        (show-body lines)
        (println "  a append · i N insert before · r N replace · d N delete · c clear · w done")
        (let [in (str/trim (or (prompt "body> ") "w"))
              [cmd arg] (str/split in #"\s+" 2)
              n (some-> arg str/trim parse-long)
              idx (when (and n (<= 1 n (count lines))) (dec n))
              need-n (fn [] (println "  that needs a line number in range") lines)]
          (case cmd
            ("w" "") (str/join "\n" lines)
            "c" (recur [])
            "a" (do (println "  appending — end with '.'")
                    (recur (into lines (read-lines))))
            "i" (if idx
                  (do (println (str "  inserting before line " n " — end with '.'"))
                      (recur (vec (concat (subvec lines 0 idx) (read-lines) (subvec lines idx)))))
                  (recur (need-n)))
            "r" (if idx
                  (recur (assoc lines idx (or (prompt (str "  " n "> ")) "")))
                  (recur (need-n)))
            "d" (if idx
                  (recur (vec (concat (subvec lines 0 idx) (subvec lines (inc idx)))))
                  (recur (need-n)))
            (do (println "  ?") (recur lines))))))))

;; ---------------------------------------------------------------------------
;; Actions.

(defn- fetch-list [search]
  (let [{:keys [status body]} (api :get (cond-> "/api/recipes"
                                         (seq search) (str "?search=" (java.net.URLEncoder/encode search "UTF-8"))))]
    (if (= 200 status) body (do (println (refusal status body :read)) nil))))

(defn- fetch-recipe [id]
  (let [{:keys [status body]} (api :get (str "/api/recipes/" id "?detail=full"))]
    (if (= 200 status) body (do (println (refusal status body :read)) nil))))

(defn- create! []
  (let [title (prompt "title: ")]
    (if (str/blank? title)
      (println "Cancelled — a title is required.")
      (let [useful (prompt "useful-when: ")
            body (edit-body "")
            {:keys [status body]} (api :post "/api/recipes"
                                       {:title title :useful_when useful :description body})]
        (if (= 201 status)
          (println (str "Created Recipe " (:id body) " (v1, private)."))
          (println (refusal status body :write)))))))

(defn- save! [recipe]
  (let [title (prompt-keep "title" (:title recipe))
        useful (prompt-keep "useful-when" (:useful_when recipe))
        body (edit-body (:description recipe))
        {:keys [status body]} (api :put (str "/api/recipes/" (:id recipe))
                                   {:title title :useful_when useful :description body
                                    :modified_at (:modified_at recipe)})]
    (if (= 200 status)
      (println (if (= (:version body) (:version recipe))
                 "Nothing changed — same version, no new history entry."
                 (str "Saved as v" (:version body) ".")))
      (println (refusal status body :write)))))

(defn- publish!
  "Owner-only, and this tool authenticates as `machine-user`, so a refusal is the
  expected outcome rather than a fault. It is offered anyway: attempting it and
  being told why is more use than a missing command, and it is the owner's call
  whether machines may ever publish. The confirmation is here because the latch
  is one-way — there is no unpublish, on the server or anywhere else."
  [recipe]
  (println (str "Publishing Recipe " (:id recipe) " — \"" (:title recipe) "\""))
  (println "  It becomes readable by anyone who opens Cookbook, and you have put")
  (println "  your name to it. There is no unpublish.")
  (println "  Note: publishing is the owner's; this tool signs in as machine-user")
  (println "  and expects to be refused.")
  (if-not (= "publish" (prompt "Type 'publish' to confirm: "))
    (println "Cancelled — nothing was written.")
    (let [{:keys [status body]} (api :post (str "/api/recipes/" (:id recipe) "/publish"))]
      (if (= 200 status)
        (println (str "Published at " (:published_at body) "."))
        (println (refusal status body :publish))))))

(defn- versions [id]
  (let [{:keys [status body]} (api :get (str "/api/recipes/" id "/versions"))]
    (if (= 200 status)
      (doseq [v (:versions body)]
        (println (format "  v%-3s %s  %s" (:version v) (:created_at v)
                         (str (:title v) (when (:current v) "   (current)")))))
      (println (refusal status body :read)))))

;; ---------------------------------------------------------------------------
;; The loop.

(def ^:private list-help
  "  <n> open   n new   / search   a all   r refresh   q quit")

(def ^:private recipe-help
  "  e edit   v versions   p publish (owner only)   b back   q quit")

(defn- recipe-loop [id]
  (loop [recipe (fetch-recipe id)]
    (when recipe
      (println)
      (doseq [l (render-recipe recipe)] (println l))
      (println)
      (println recipe-help)
      (case (str/trim (or (prompt "> ") "q"))
        "e" (do (save! recipe) (recur (fetch-recipe id)))
        "v" (do (versions id) (recur recipe))
        "p" (do (publish! recipe) (recur (fetch-recipe id)))
        "b" :back
        "q" :quit
        (do (println "?") (recur recipe))))))

(defn- main-loop []
  (loop [search nil]
    (when-let [recipes (fetch-list search)]
      (println)
      (println (str "cookbook  ·  " (:base-url @config)
                    "  ·  " (count recipes) " Recipe(s)"
                    (when (seq search) (str "  ·  search \"" search \"))))
      (doseq [l (render-list recipes)] (println l))
      (println)
      (println list-help)
      (let [in (str/trim (or (prompt "> ") "q"))]
        (cond
          (= "q" in) :quit
          (= "n" in) (do (create!) (recur search))
          (= "a" in) (recur nil)
          (= "r" in) (recur search)
          (str/starts-with? in "/") (recur (str/trim (subs in 1)))
          (re-matches #"\d+" in)
          (if (= :quit (recipe-loop (parse-long in))) :quit (recur search))
          :else (do (println "?") (recur search)))))))

(defn -main [& _]
  (try
    (main-loop)
    (println "bye")
    (catch Exception e
      (binding [*out* *err*] (println "cookbook-tui:" (ex-message e)))
      (System/exit 2))))

(when (= *file* (System/getProperty "babashka.file")) (apply -main *command-line-args*))
