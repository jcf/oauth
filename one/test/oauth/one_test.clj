(ns oauth.one-test
  (:require [clojure.test :refer :all]
            [oauth.one :refer :all]
            [schema.test :refer [validate-schemas]]
            [clojure.string :as str]
            [schema.core :as s]
            [ring.util.codec :as codec]))

(use-fixtures :once validate-schemas)

;; -----------------------------------------------------------------------------
;; Schema

(def ^:private urlencoded
  "application/x-www-form-urlencoded")

(def ^:private SignedRequest
  {:headers {(s/required-key "Authorization") s/Str
             (s/required-key "Content-Type") (s/eq urlencoded)
             s/Str s/Str}
   :request-method (s/eq :post)
   :url s/Str})

;; -----------------------------------------------------------------------------
;; Utils

(def ^:private consumer-config
  {:access-uri "http://example.com/access"
   :authorize-uri "http://example.com/authorize"
   :callback-uri "http://localhost/oauth/callback"
   :key "key"
   :request-uri "http://example.com/token"
   :secret "secret"
   :signature-algo :hmac-sha1})

(defn- parse-auth-header
  [s]
  (reduce
   #(let [[_ k v] (re-find #"(.*?)=\"(.*?)\"" %2)]
      (assoc %1 k v))
   {}
   (str/split (str/replace s #"^OAuth\s+" "") #",\s+")))

(defn- parse-uri
  [^String url]
  (let [uri (java.net.URI. url)]
    {:authority (.getAuthority uri)
     :host (.getHost uri)
     :path (.getPath uri)
     :query (.getQuery uri)
     :scheme (.getScheme uri)}))

(defn- split-url
  [^String url]
  (let [{:keys [scheme host path query]} (parse-uri url)]
    [(str scheme "://" host path) (codec/form-decode query)]))

;; -----------------------------------------------------------------------------
;; Consumer

(deftest t-make-consumer
  (is (make-consumer consumer-config)))

;; -----------------------------------------------------------------------------
;; Auth headers

(deftest t-auth-headers->str
  (are [m s] (= (auth-headers->str m) s)
    {} ""

    {"oauth_callback" "http://example.com/callback"}
    "oauth_callback=\"http%3A%2F%2Fexample.com%2Fcallback\""

    {"oauth_callback" "http://example.com/callback"
     "oauth_nonce" "abc123"}
    (str "oauth_callback=\"http%3A%2F%2Fexample.com%2Fcallback\", "
         "oauth_nonce=\"abc123\"")))

;; -----------------------------------------------------------------------------
;; Request tokens

(deftest t-request-token-request
  (let [consumer (make-consumer consumer-config)
        request (request-token-request consumer)
        auth (-> request
                 (get-in [:headers "Authorization"])
                 parse-auth-header)]
    (is (nil? (s/check SignedRequest request)))
    (is (= "http://example.com/token" (:url request)))
    (is (nil? (s/check SignedOAuthAuthorization auth)))
    (are [k v] (= (get auth k ::missing) v)
      "oauth_callback" (codec/url-encode "http://localhost/oauth/callback")
      "oauth_consumer_key" "key"
      "oauth_signature_method" "HMAC-SHA1")))

(deftest t-request-token-request-with-callback-override
  (let [consumer (make-consumer consumer-config)
        request (request-token-request consumer {"oauth_callback" "http://localhost/override"})
        auth (-> request
                 (get-in [:headers "Authorization"])
                 parse-auth-header)]
    (is (nil? (s/check SignedRequest request)))
    (is (= "http://example.com/token" (:url request)))
    (is (nil? (s/check SignedOAuthAuthorization auth)))
    (are [k v] (= (get auth k ::missing) v)
      "oauth_callback" (codec/url-encode "http://localhost/override")
      "oauth_consumer_key" "key"
      "oauth_signature_method" "HMAC-SHA1")))

;; -----------------------------------------------------------------------------
;; Authorisation URL

(deftest t-authorization-url
  (let [consumer (make-consumer consumer-config)]
    (is (= ["http://example.com/authorize"
            {"oauth_callback" "http://localhost/oauth/callback"}]
           (split-url (authorization-url consumer))))
    (is (= ["http://example.com/authorize"
            {"a" "1" "b" "2"
             "oauth_callback" "http://localhost/oauth/callback"
             "oauth_token" "token"}]
           (split-url (authorization-url
                       consumer {"oauth_token" "token" :a 1 :b 2}))))
    (is (= ["http://example.com/authorize"
            {"a" "1" "b" "2"
             "oauth_callback" "http://localhost/override"
             "oauth_token" "token"}]
           (-> consumer
               (authorization-url {"oauth_token" "token"
                                   "oauth_callback" "http://localhost/override"
                                   :a 1
                                   :b 2})
               split-url)))))

;; -----------------------------------------------------------------------------
;; Access token request

(deftest t-access-token-request
  (let [consumer (make-consumer consumer-config)
        request (access-token-request consumer {"oauth_token" "token"
                                                "oauth_verifier" "verifier"})
        auth (-> request
                 (get-in [:headers "Authorization"])
                 parse-auth-header)]
    (is (nil? (s/check SignedRequest request)))
    (is (= "http://example.com/access" (:url request)))
    (is (nil? (s/check SignedOAuthAuthorization auth)))
    (are [k v] (= (get auth k ::missing) v)
      "oauth_consumer_key" "key"
      "oauth_signature_method" "HMAC-SHA1"
      "oauth_token" "token"
      "oauth_verifier" "verifier")))

;; -----------------------------------------------------------------------------
;; Signature generation

(def ^:private test-requests
  {"yEzHR87PoGcUSua%2FF+48V%2FNzd3M%3D"
   {:oauth-params {"oauth_consumer_key" "abc123"
                   "oauth_nonce" "nonce"
                   "oauth_signature_method" "HMAC-SHA1"
                   "oauth_timestamp" "1000"
                   "oauth_version" "1.0"}
    :request-method :post
    :url "https://example.com/"}

   "8ZoF1R8s%2F7JRKivUJkPs%2F1yhaZU%3D"
   {:form-params {"status" "testing things!"}
    :oauth-params {"oauth_consumer_key" "abc123"
                   "oauth_nonce" "nonce"
                   "oauth_signature_method" "HMAC-SHA1"
                   "oauth_timestamp" "1000"
                   "oauth_version" "1.0"}
    :request-method :post
    :url "https://example.com/"}})

(deftest t-signed-request
  (let [consumer (make-consumer consumer-config)]
    (doseq [[signature oauth-request] test-requests]
      (let [request (signed-request consumer oauth-request)
            auth (-> request
                     (get-in [:headers "Authorization"])
                     parse-auth-header)]
        (is (nil? (s/check SignedOAuthAuthorization auth)))
        (is (= signature (get auth "oauth_signature" ::missing)))))))
