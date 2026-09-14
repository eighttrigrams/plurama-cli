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
            [cookbook-seal :as seal]
            [tracker-seal]
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
  {})

(def ^:private default-policy
  "What an app with no rule of its own gets, and today that is everything.

  This proxy exists to keep credentials out of the sandbox, not to narrow what
  the sandbox may do. Those are separable, and only the first one is being asked
  for: an agent in the box gets whatever the credential itself gets, with the
  apps' own gates — tracker's recording gate, cookbook's publish latch — doing
  the deciding, exactly as they did when the passwords were baked in. What
  changed is that a password can no longer be read, copied out, or used after the
  container is gone.

  **And the decisive reason is maintenance, not philosophy.** A per-path rule set
  here is a second copy of each app's route list, kept in a different repo from
  the routes themselves. It cannot be kept in step: an app adds an endpoint and
  this file does not fail, it quietly refuses the new one — the same failure mode
  prober's README describes for enumerating the shapes of secrets.yaml. A list
  that goes stale silently is worse than no list, because it reads like policy
  while behaving like rot.

  Set to `:all` deliberately rather than by leaving the map empty and calling it
  a default, so that adding a target to `proxy-credentials.edn` does not silently
  refuse every call to it. `allowlist` above stays in place because tightening one
  app later is then a single entry — e.g. `{:tracker-just-msg [[:post
  #\"/api/messages\"]]}` — and that is worth having for a target that genuinely
  deserves a local limit, where a short, stable rule beats mirroring a whole API."
  :all)

(defn- allowed? [app method path]
  (let [rules (get allowlist app default-policy)]
    (if (= :all rules)
      true
      (boolean
       (some (fn [[m pattern]]
               (and (= m method) (re-matches pattern path)))
             rules)))))

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
;; Cookbook's prose, sealed here rather than in the box.
;;
;; Cookbook is end-to-end encrypted: description, useful-when and the
;; reason/context an agent writes about its own change are sealed in the
;; clients, because the key never goes to fly. Titles, tags and Scopes stay
;; clear — that is the line cookbook's search already drew.
;;
;; Which leaves the question of what an *agent* holds. The security model's
;; first answer was a key file mounted into the box, beside the credentials the
;; whole of this program exists to keep out of it. That is the same trade the
;; baked credentials were: it works, and it puts a secret somewhere it can be
;; read, copied out, and used long after the container is gone — except that a
;; leaked password can be rotated and a leaked key cannot. The shelf it opens is
;; every Recipe the owner has ever written, and there is no re-encrypting them
;; against a copy somebody took.
;;
;; So the key stops one hop short, here, exactly as the passwords do:
;;
;;   - Responses are **unsealed** on the way past, so an agent reads prose.
;;   - Request prose is **sealed** on the way past, so an agent writes prose.
;;   - Neither the key nor anything derived from it is ever in the box, in its
;;     environment, in a mounted file, or in a response body.
;;
;; The in-box client needs no change at all for this — it holds no key, so its
;; own sealing is off by its own first rule, and the build that is mounted today
;; predates the seal entirely. It goes on working.
;;
;; **No key configured means passthrough**, byte for byte, which is this proxy
;; before any of this existed and is right for an unsealed shelf.
;;
;; The mount, beside the credentials one:
;;
;;   volumes:
;;     - ${HOME}/.local/share/plurama-cli/proxy-credentials.edn:/credentials.edn:ro
;;     - ${HOME}/.config/plurama-cli/cookbook-seal.key:/cookbook-seal.key:ro
;;   environment:
;;     BABASHKA_CLASSPATH: /app
;;
;; and the box gets neither. `BABASHKA_CLASSPATH` is not decoration: this file
;; now requires `cookbook_seal.clj`, babashka puts neither the script's directory
;; nor the working directory on the classpath on its own, and so the sidecar's
;; compose entry has to mount that file too and say where it is. If it is
;; forgotten babashka refuses to start, which is the loud half of the failure;
;; the quiet half would have been a second copy of the envelope living in here,
;; and that is the one thing this project's reviews have caught twice.

(defn- key-path
  "Mounted read-only into this container and nowhere else, like the credentials.
  Deliberately a file rather than an env var holding the key itself: env leaks
  through `docker inspect`, crash dumps and every child process, and the compose
  file that would have to set it is synced to a git remote.

  `PLURAMA_PROXY_SEAL_KEY` keeps its cookbook-only name because that is what the
  compose file and the README already say, and renaming a mount point to make a
  second app fit is how a working sandbox stops starting."
  [app]
  (case app
    :cookbook (or (System/getenv "PLURAMA_PROXY_SEAL_KEY") "/cookbook-seal.key")
    :tracker  (or (System/getenv "PLURAMA_PROXY_TRACKER_SEAL_KEY") "/tracker-seal.key")))

(defn- load-key
  "The key, or `nil` — and `nil` means sealing off for that app, which is what
  every function in the seal namespaces already understands and what this proxy
  did before any of this existed.

  **A key that is there and malformed stops the process** rather than falling
  back to passthrough. The fallback would be the worst of both: agents writing
  plaintext into a sealed store, and nothing anywhere saying so. `-main` forces
  these before the server starts, so that failure happens at `docker compose up`
  and not on the first write."
  [app from-base64]
  (let [f (io/file (key-path app))]
    ;; `.isFile`, not `.exists`. A bind mount whose source is missing creates an
    ;; empty **directory** here rather than failing, and the compose file mounts
    ;; a key per sealing app whether or not that app's ceremony has happened
    ;; yet. Read as a malformed key, that directory stops the sidecar at
    ;; `docker compose up` — which is what it did, crash-looping the whole box,
    ;; the first time tracker's mount was added. A directory means no key, and
    ;; no key means passthrough.
    (when (.isFile f)
      (from-base64 (slurp f)))))

(def ^:private cookbook-seal-key (delay (load-key :cookbook seal/key-from-base64)))
(def ^:private tracker-seal-key (delay (load-key :tracker tracker-seal/key-from-base64)))

(def ^:private sealers
  "One adapter per app that seals prose. Two apps now, and the shape is what
  keeps the handler from growing a branch per app: everything below takes a
  `sealer` and asks it, rather than asking which app this is.

  The key is a function of no arguments rather than the delay itself, so that
  the delay stays a top-level var: the suite drives this whole path by redefining
  those two, and a key reachable only through a map inside a `let` is a key no
  test can supply.

  The two differ in exactly three ways and the adapter is where all three live —
  which inventory, which key, and that cookbook has a published-Recipe rule with
  nothing to correspond to it in tracker. The envelope underneath is one file,
  shared, and the fixtures are what say so.

  `:tracker-just-msg` is the same tracker, reached with the mail-only identity,
  and it is here for a reason that is easy to miss: **mail-only restricts what
  that machine user may write, not what it may read.** An agent reading a task
  through it would meet `enc:v1:…` with nothing to say why if this named only
  `:tracker`."
  (let [cookbook {:app :cookbook
                  :key #(deref cookbook-seal-key)
                  :key-path (key-path :cookbook)
                  :sealed-columns seal/sealed-columns
                  :write-target seal/write-target
                  :prose-in seal/prose-in
                  :state-path seal/state-path
                  :state-of seal/state-of
                  :seal-write seal/seal-write
                  :unseal-response-body seal/unseal-response-body}
        tracker {:app :tracker
                 :key #(deref tracker-seal-key)
                 :key-path (key-path :tracker)
                 :sealed-columns tracker-seal/sealed-columns
                 :write-target tracker-seal/write-target
                 :prose-in tracker-seal/prose-in
                 :state-path tracker-seal/state-path
                 :state-of tracker-seal/state-of
                 :seal-write tracker-seal/seal-write
                 :unseal-response-body tracker-seal/unseal-response-body}]
    {:cookbook cookbook
     :tracker tracker
     :tracker-just-msg tracker}))

(defn- sealer-for [app] (get sealers app))

(defn- json-body? [resp]
  (some-> (get-in resp [:headers "content-type"]) (str/includes? "json")))

(defn- current-state
  "What the row a write is aimed at holds right now, and whether it is published.
  One upstream read, whose path and meaning are `cookbook-seal`'s — see
  `seal/state-path` for why a Recipe's is `/versions` and never `?detail=full`.

  **It is not logged.** The audit line records what an agent did in the owner's
  name, and this is the proxy's own bookkeeping rather than anything the box
  asked for. It was chosen so that it costs nothing to ask: a full read would
  count as a consumption and rank the shelf, so sealing would quietly reorder
  somebody's Cookbook.

  Anything that goes wrong answers `nil` for both, which means *nothing to echo*
  and a fresh seal — the safe direction for the echo rule, and the direction the
  server refuses if the published rule needed it."
  [sealer cfg token target]
  (when-let [path ((:state-path sealer) target)]
    (try
      (let [resp (forward cfg token {:method :get :path path})]
        (when (= 200 (:status resp))
          ((:state-of sealer) target (json/parse-string (:body resp) true))))
      (catch Exception _ nil))))

(defn- borrowed-prose
  "The prose a write has to carry and did not — read out of the row it names, or
  `nil` when there is no such row or it could not be read.

  Only one kind of write answers a `:body-from` at all: a tracker message
  conversion, which is the single write in either app that **deletes its own
  original**. It historically carried no body, because the server read the
  message and copied it across; a server holds no key, so for an armed user that
  copy is readable prose in a sealed column with the original gone in the same
  transaction. The browser answers by sending the body it is already holding.
  This process is holding nothing, so it goes and gets it.

  **A read that fails fills nothing in.** That is the whole value of the
  direction: inventing a blank here would convert cleanly and lose the body
  permanently with nothing anywhere to say so, where forwarding what arrived
  earns the server's refusal, which says exactly that and leaves the message in
  the inbox. A blank that the *message itself* carries is different and is filled
  in as `\"\"`, because the server tells `\"\"` from *no body was sent* on
  purpose and the link-only message from the feed worker is the commonest
  convert in the app.

  Like `current-state` it is not logged: it is this process's own bookkeeping,
  not something the box asked for."
  [sealer cfg token {:keys [table body-from]}]
  (when body-from
    (when-let [row (try
                     (let [resp (forward cfg token {:method :get :path body-from})]
                       (when (= 200 (:status resp))
                         (json/parse-string (:body resp) true)))
                     (catch Exception _ nil))]
      (into {} (for [column (get (:sealed-columns sealer) table)]
                 [column (or (get row column) "")])))))

(defn- foreign-envelopes
  "The prose columns of this write that arrived **already sealed by somebody
  else** — sealed, and not simply the value the row already holds.

  This is the double-seal question, and it has exactly one right answer. If the
  box also holds a key, it seals before this does, and sealing again writes
  `enc(enc(…))`: the browser opens it once and shows an envelope, the CLI opens
  it once and prints one, and nothing anywhere reports an error. Worse, if the
  box's key is a *different* key, the result is a value nobody can ever open, on
  a Recipe nobody will look at until they need it.

  So: **the key belongs on one side of this proxy or the other, never both**, and
  that rule is enforced here rather than written in a comment somewhere and
  believed. A write whose prose is already an envelope is refused, loudly, naming
  the columns — because the alternative readings are worse. Passing it through
  would be right only when the box's key is this key, which cannot be checked;
  sealing it again is the corruption above.

  The one envelope that is *not* foreign is the value the row already holds: a
  client that read a value this proxy could not open, and sent it back
  unchanged, is echoing rather than sealing, and `seal`'s own rule 2 answers that
  case correctly. Comparing against `stored` is what tells the two apart."
  [sealer table parsed stored]
  (seq (for [column (get (:sealed-columns sealer) table)
             :let [v (get parsed column)]
             :when (and (seal/sealed? v) (not= v (get stored column)))]
         column)))

(defn- seal-outgoing
  "A cookbook write, sealed on the way past. Answers

    `nil`                          — nothing to do; forward what arrived, byte for byte
    `{:body … :sealed n :echoed m}` — forward this instead
    `{:refused [columns]}`         — do not forward at all

  **`:sealed` and `:echoed` are counted apart**, and that is the audit trail
  earning its name. Both are columns that left sealed and did not arrive sealed,
  which is one number — and one number cannot tell a real edit from an idempotent
  resend, since a no-op write also leaves four plaintext fields as four
  ciphertexts. `:echoed` is the ones handed back byte-identical to what the row
  already held, so *the echo rule fired* becomes something the log can be read
  for rather than something only a version number can prove. Found in review.

  A body with no prose in it is the first of those and **asks the server
  nothing**: without that guard a filing PUT of `{\"tags\":\"x\"}` would drag down
  a whole version ladder to look up columns it is not sending."
  [sealer k cfg token {:keys [method path body]}]
  (let [target (when (#{:post :put} method) ((:write-target sealer) path))]
    (when (and k target (or (:body-from target) (seq body)))
      (let [parsed (or (try (json/parse-string body true) (catch Exception _ nil))
                       (when (:body-from target) {}))
            ;; What actually goes out, once a write that carries no body of its
            ;; own has been handed the one it is about to destroy. Anything the
            ;; caller *did* send wins — `some?` and not `contains?`, which is the
            ;; same question tracker's own guard asks, because a JSON null is a
            ;; key with no body behind it and the server reads it as *nothing was
            ;; sent*. Identical to `parsed` for every write that is not a convert.
            filled (reduce (fn [m [column v]]
                             (if (some? (get m column)) m (assoc m column v)))
                           parsed
                           (borrowed-prose sealer cfg token target))]
        (when ((:prose-in sealer) (:table target) filled)
          (let [{:keys [stored] :as state} (current-state sealer cfg token target)]
            (if-let [foreign (foreign-envelopes sealer (:table target) filled stored)]
              {:refused foreign}
              (let [sealed (or ((:seal-write sealer) k target filled state) filled)]
                ;; Compared against what **arrived**, so that filling a body in
                ;; is enough to make the request worth rewriting even when
                ;; nothing was sealed — a blank message converts to a blank body,
                ;; and `""` is not the same request as no body at all.
                (when-not (= sealed parsed)
                  ;; The counts are compared against `filled`, though: a column
                  ;; this process fetched and did not re-encode was not sealed by
                  ;; it and must not be reported as if it were. `:sealed` and
                  ;; `:echoed` are the audit line's claim about the *key*.
                  (let [moved (remove (fn [[c v]] (= v (get filled c))) sealed)]
                    {:body (json/generate-string sealed)
                     :sealed (count (remove (fn [[c v]] (= v (get stored c))) moved))
                     :echoed (count (filter (fn [[c v]] (= v (get stored c))) moved))}))))))))))

;; `log!` is defined below, with the rest of the sidecar's plumbing. It is
;; reached from here because a response that would not open is exactly the kind
;; of decision that log is for — see `unseal-incoming`.
(declare log!)

(defn- unseal-incoming
  "A cookbook response, opened on the way back. `{:body …}` when anything changed,
  `nil` when nothing did — including every response on a box with no key
  configured, which then goes back byte for byte. The audit line reports *that* it
  was opened and not how much of it, because a count of opened fields is a
  description of the response's shape and the shape is the caller's business, not
  the log's.

  Error bodies are opened too, and deliberately: the 409 naming the Recipe that
  moved and the 409 naming a pending proposal both carry prose, and an agent
  reading `Refused:` over `enc:v1:…` has been told nothing.

  What it does *besides* unsealing is take a `caution` computed over ciphertext
  off the body — see `seal/unseal-response-body`, which is where the order is
  argued. **That step is this process's job now and cannot be left to the box.**
  The in-box client asks the same question, but by then this has already opened
  the description, so it would find prose there and pass on a provenance split
  the server computed over base64 — a lie about which lines are the owner's, to
  the one reader written to act on it.

  A value that will not open comes back exactly as it is, which is
  `cookbook-seal`'s rule 3 and every other client's behaviour: one unreadable
  column beside everything that reads, rather than a response dropped with
  nothing to say why."
  [sealer k resp]
  (when (and k (json-body? resp) (seq (:body resp)))
    (let [parsed (try (json/parse-string (:body resp) true)
                      (catch Exception _ ::unparseable))]
      (when-not (= ::unparseable parsed)
        (try
          (let [out ((:unseal-response-body sealer) k parsed)]
            (when-not (= parsed out)
              {:body (json/generate-string out)}))
          (catch Exception e
            ;; **Not the same failure as a body that would not parse, and the
            ;; difference is why this is two `try`s and not one.** A body that
            ;; will not parse is expected and silent. A body that parses and then
            ;; will not open is a defect in this sidecar, and one `try` around
            ;; both of them turned `ClassCastException` on every tracker listing
            ;; into a forwarded 200 full of `enc:v1:…` — every agent in the box
            ;; reading ciphertext, and this log, which records every other
            ;; decision the proxy makes, saying nothing at all.
            ;;
            ;; It still forwards rather than failing the request: rule 3's shape
            ;; is right for a read path, one bad body beside everything that
            ;; reads. It just says so now.
            (log! "LEFT-SEALED" (ex-message e))
            nil))))))

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
            ;; Two upstream credential kinds, the same two plurama_cli.clj
            ;; carries. `:token` is an opaque machine token (personalist's
            ;; `pmu_…`) used verbatim — there is no login route to call and
            ;; nothing to mint. `:username`/`:password` is the login path.
            ;;
            ;; The token is checked FIRST and its presence suppresses the login
            ;; entirely, because a machine user has both keys: personalist's
            ;; entry carries `:username "daniel-machine"` for the listing as well
            ;; as its `:token`. Keying off the username alone would post a login
            ;; with a nil password and fail with the working credential sitting
            ;; unused in the same map.
            ;;
            ;; No 401 retry for a token, deliberately — rotation is revocation
            ;; for these, so there is no second thing to try.
            static-token (:token cfg)
            login-auth? (and (nil? static-token) (some? (:username cfg)))]
        (try
          (let [token (or static-token (when login-auth? (token-for app cfg)))
                ;; Only for an app that seals, and only after the token exists:
                ;; sealing a write needs one read of the row it is aimed at, and
                ;; that read is authenticated like any other.
                sealer (sealer-for app)
                k (when sealer ((:key sealer)))
                out (when k (seal-outgoing sealer k cfg token req))]
            (if-let [refused (:refused out)]
              ;; **The one refusal this proxy makes that is not about reach.** See
              ;; `foreign-envelopes`: the key belongs on one side of this hop or
              ;; the other, and a write arriving already sealed says it is on both.
              ;; Neither the columns nor the message carry a value, and no line
              ;; anywhere here carries the key.
              (do (log! "DENY" request-method uri "- prose already sealed:"
                        (str/join "," (map name refused)))
                  (json-response 400
                                 {:error (str "this proxy seals " (name app) " prose, and "
                                              (str/join ", " (map name refused))
                                              " arrived already sealed. The key belongs on one "
                                              "side of the proxy or the other, never both — "
                                              "unset it in the box.")
                                  :reason "already-sealed"
                                  :columns (mapv name refused)
                                  :app (name app)}))
              (let [req (cond-> req (:body out) (assoc :body (:body out)))
                    resp (let [r (forward cfg token req)]
                           (if (and login-auth? (= 401 (:status r)))
                             ;; Cached token went stale (restarted app, rotated
                             ;; password). Mint once and retry; a second 401 is the
                             ;; caller's answer.
                             (forward cfg (login! app cfg) req)
                             r))
                    opened (when k (unseal-incoming sealer k resp))]
                ;; The audit line says whether prose crossed sealed, and whether
                ;; anything was echoed rather than freshly sealed, because "did the
                ;; key work" and "did the echo rule fire" are otherwise questions
                ;; only a Recipe and a version number can answer. Counts and never
                ;; a value, and never the key.
                (apply log! "ALLOW" request-method uri "->" (:status resp)
                       (concat (when (pos? (:sealed out 0)) [(str "sealed:" (:sealed out))])
                               (when (pos? (:echoed out 0)) [(str "echoed:" (:echoed out))])
                               (when opened ["opened"])))
                {:status (:status resp)
                 :headers (select-keys (:headers resp) ["content-type"])
                 :body (or (:body opened) (:body resp))})))
          (catch Exception e
            (log! "ERROR" request-method uri "-" (ex-message e))
            ;; The message can name the upstream URL but never a credential --
            ;; login! only ever reports a status code.
            (json-response 502 {:error (ex-message e)})))))))

(defn -main [& _]
  (let [apps (sort (map name (keys @credentials)))
        ;; **Forced before anything is announced.** A key that is there and
        ;; malformed has to stop the process at `docker compose up`, where
        ;; somebody is watching, rather than on the first write months later —
        ;; and it must stop it before a line saying *listening* scrolls past.
        ;; "Sealing on" means the key opens things, not that a file exists.
        ;;
        ;; Both apps, and only the ones this proxy is actually configured to
        ;; reach: a box given cookbook and not tracker has no business failing
        ;; to start over a tracker key it will never use.
        configured (->> sealers
                        (keep (fn [[app sealer]] (when (get @credentials app) sealer)))
                        (distinct)
                        (vec))
        keys-by-app (into {}
                          (for [sealer configured]
                            [(:app sealer)
                             (try ((:key sealer))
                                  (catch Exception e
                                    (binding [*out* *err*]
                                      (println "plurama-cli-proxy:" (name (:app sealer))
                                               "seal key at" (:key-path sealer)
                                               "is unusable --" (ex-message e)))
                                    (System/exit 1)))]))]
    (log! "plurama-cli-proxy listening on" port)
    (log! "targets:" (str/join ", " apps))
    (doseq [app apps
            :let [rules (get allowlist (keyword app) default-policy)]]
      (log! " " app (if (= :all rules)
                      "any method, any path -- the app's own gates decide"
                      (str/join "; " (for [[m p] rules]
                                       (str (str/upper-case (name m)) " " p))))))
    ;; The fingerprint is the eight characters the web UI's ⚙ panel shows, so
    ;; that *this holds the same key the owner's browser does* is a comparison
    ;; anyone can make in five seconds. It is a name for a key and no help in
    ;; finding one; the key itself is never printed, logged or answered with.
    (doseq [sealer configured
            :let [k (get keys-by-app (:app sealer))]]
      (if k
        (log! " " (str (name (:app sealer)) " prose:") "sealed here, key" (:key-path sealer)
              "fingerprint" (seal/fingerprint k))
        (log! " " (str (name (:app sealer)) " prose:") "passthrough -- no key at"
              (:key-path sealer))))
    (srv/run-server handle {:port port :ip "0.0.0.0"})
    @(promise)))

(when (= *file* (System/getProperty "babashka.file"))
  (apply -main *command-line-args*))
