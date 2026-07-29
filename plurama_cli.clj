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
    :uri (str base-url (if (str/starts-with? path "/") path (str "/" path)))
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

(defn- usage []
  (println "Usage: plurama-cli <app> <path> [options]")
  (println "       plurama-cli apps")
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
  (println "Examples:")
  (println "  plurama-cli treina /api/describe")
  (println "  plurama-cli treina '/api/trainings/?limit=10'")
  (println "  plurama-cli treina /api/trainings/ -X POST --body '{\"name\":\"Squat\"}'")
  (println "  plurama-cli tracker /api/today-board")
  (println "  plurama-cli rhizome '/rest/contexts?q=Books'"))

(defn- list-apps []
  (doseq [[app cfg] (sort-by key @credentials)]
    (println (format "%-14s %-40s %s" (name app) (:base-url cfg)
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
          (binding [*out* *err*] (println "plurama-cli:" (ex-message e)))
          (System/exit 2))))))

(when (= *file* (System/getProperty "babashka.file"))
  (apply -main *command-line-args*))
