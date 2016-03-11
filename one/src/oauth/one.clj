(ns oauth.one
  (:require [clojure.string :as str]
            [crypto.random :as random]
            [pandect.core :as pandect]
            [ring.util.codec :as codec]
            [schema.core :as s]))

;; -----------------------------------------------------------------------------
;; Schema

(def ^:private signature-algos
  {:hmac-sha1 "HMAC-SHA1"
   :plaintext "PLAINTEXT"
   :rsa-sha1 "RSA-SHA1"})

(def ^:private SignatureAlgo
  (apply s/enum (keys signature-algos)))

(def ^:private ConsumerConfig
  {:access-uri s/Str
   :authorize-uri s/Str
   :callback-uri s/Str
   :key s/Str
   :request-uri s/Str
   :secret s/Str
   :signature-algo SignatureAlgo})

(defrecord Consumer
    [access-uri authorize-uri callback-uri key secret signature-algo])

(s/defn make-consumer :- Consumer
  [config :- ConsumerConfig]
  (map->Consumer config))

;; -----------------------------------------------------------------------------
;; Request signing

(s/defn auth-headers->str :- s/Str
  "The OAuth Protocol Parameters are sent in the Authorization header the
   following way:

   1. Parameter names and values are encoded per Parameter Encoding.
   2. For each parameter, the name is immediately followed by an ‘=’ character
      (ASCII code 61), a ‘”’ character (ASCII code 34), the parameter value (MAY
      be empty), and another ‘”’ character (ASCII code 34).
   3. Parameters are separated by a comma character (ASCII code 44) and OPTIONAL
      linear whitespace per [RFC2617](http://oauth.net/core/1.0/#RFC2617).
   4. The OPTIONAL realm parameter is added and interpreted per
      [RFC2617](http://oauth.net/core/1.0/#RFC2617), section 1.2.

   http://oauth.net/core/1.0/#auth_header"
  [m :- {s/Str s/Any}]
  (->> m
       (map #(format "%s=\"%s\""
                     (key %)
                     (-> % val codec/url-encode)))
       (str/join ", ")))

(s/defn ->seconds :- s/Int
  [millis :- s/Int]
  (quot millis 1000))

(s/defn sign :- s/Str
  ([consumer :- Consumer data :- s/Str]
   (sign consumer "" data))
  ([consumer :- Consumer token-secret :- s/Str data :- s/Str]
   (let [{:keys [secret signature-algo]} consumer]
     (case signature-algo
       :hmac-sha1
       (codec/base64-encode
        (pandect/sha1-hmac-bytes
         data
         (format "%s&%s"
                 (codec/url-encode secret)
                 (codec/url-encode token-secret))))))))

(s/defn ^:always-validate request-token-request
  [consumer :- Consumer]
  (let [;; http://oauth.net/core/1.0/#auth_step1
        ;;
        ;; The Consumer obtains an unauthorized Request Token by asking the
        ;; Service Provider to issue a Token. The Request Token’s sole purpose
        ;; is to receive User approval and can only be used to obtain an Access
        ;; Token.
        ;;
        ;; To obtain a Request Token, the Consumer sends an HTTP request to the
        ;; Service Provider’s Request Token URL. The Service Provider
        ;; documentation specifies the HTTP method for this request, and HTTP
        ;; POST is RECOMMENDED.
        auth-params
        (sorted-map
         "oauth_consumer_key" (:key consumer)
         "oauth_nonce" (random/url-part 32)
         "oauth_signature_method" (-> consumer :signature-algo signature-algos)
         "oauth_timestamp" (->seconds (System/currentTimeMillis))
         "oauth_version" "1.0")

        ;; http://oauth.net/core/1.0/#anchor14
        ;;
        ;; The Signature Base String is a consistent reproducible concatenation
        ;; of the request elements into a single string. The string is used as
        ;; an input in hashing or signing algorithms. The HMAC-SHA1 signature
        ;; method provides both a standard and an example of using the Signature
        ;; Base String with a signing algorithm to generate signatures. All the
        ;; request parameters MUST be encoded as described in Parameter Encoding
        ;; prior to constructing the Signature Base String.
        ;;
        ;; The following items MUST be concatenated in order into a single
        ;; string. Each item is encoded and separated by an ‘&’ character (ASCII
        ;; code 38), even if empty.
        ;;
        ;; 1. The HTTP request method used to send the request. Value MUST be
        ;;    uppercase, for example: `HEAD`, `GET`, `POST`, etc.
        ;; 2. The request URL from Section 9.1.2.
        ;; 3. The normalized request parameters string from Section 9.1.1.
        base-string
        (format "POST&%s&%s"
                (codec/url-encode (:request-uri consumer))
                (codec/url-encode (codec/form-encode auth-params)))

        ;; http://oauth.net/core/1.0/#signing_process
        ;;
        ;; All Token requests and Protected Resources requests MUST be signed by
        ;; the Consumer and verified by the Service Provider. The purpose of
        ;; signing requests is to prevent unauthorized parties from using the
        ;; Consumer Key and Tokens when making Token requests or Protected
        ;; Resources requests. The signature process encodes the Consumer Secret
        ;; and Token Secret into a verifiable value which is included with the
        ;; request.
        ;;
        ;; OAuth does not mandate a particular signature method, as each
        ;; implementation can have its own unique requirements. The protocol
        ;; defines three signature methods: HMAC-SHA1, RSA-SHA1, and PLAINTEXT,
        ;; but Service Providers are free to implement and document their own
        ;; methods. Recommending any particular method is beyond the scope of
        ;; this specification.
        ;;
        ;; The Consumer declares a signature method in the
        ;; `oauth_signature_method` parameter, generates a signature, and stores
        ;; it in the `oauth_signature` parameter. The Service Provider verifies
        ;; the signature as specified in each method. When verifying a Consumer
        ;; signature, the Service Provider SHOULD check the request nonce to
        ;; ensure it has not been used in a previous Consumer request.
        ;;
        ;; The signature process MUST NOT change the request parameter names or
        ;; values, with the exception of the `oauth_signature` parameter.
        signed-auth-params (assoc auth-params "oauth_signature"
                                  (sign consumer base-string))
        authorization (auth-headers->str signed-auth-params)]
    {:headers {"Authorization" (str "OAuth " authorization)
               "Accept" "application/json"
               "Content-Type" "application/x-www-form-urlencoded"}
     :request-method :post
     :url (:request-uri consumer)}))
