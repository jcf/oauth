(ns oauth.one-test
  (:require [clojure.test :refer :all]
            [oauth.one :refer :all]
            [schema.test :refer [validate-schemas]]
            [clojure.string :as str]
            [schema.core :as s]))

(use-fixtures :once validate-schemas)

;; -----------------------------------------------------------------------------
;; Schema

(def ^:private urlencoded
  "application/x-www-form-urlencoded")

(def ^:private SignatureMethod
  (s/enum "HMAC-SHA1" "PLAINTEXT" "RSA-SHA1"))

(def ^:private OAuthAuthorization
  {(s/optional-key "oauth_version") (s/eq "1.0")
   (s/required-key "oauth_consumer_key") s/Str
   (s/required-key "oauth_nonce") s/Str
   (s/required-key "oauth_signature") s/Str
   (s/required-key "oauth_signature_method") SignatureMethod
   (s/required-key "oauth_timestamp") s/Str})

(def ^:private RequestTokenRequest
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
    (is (nil? (s/check RequestTokenRequest request)))
    (is (= "http://example.com/token" (:url request)))
    (is (nil? (s/check OAuthAuthorization auth)))
    (are [k v] (= (get auth k ::missing) v)
      "oauth_consumer_key" "key"
      "oauth_signature_method" "HMAC-SHA1")))
