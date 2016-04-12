(ns oauth.one
  "Provides functions for generating requests, and parsing responses necessary
  for integrating with three-legged OAuth 1.0 providers like Twitter.

  All Token requests and Protected Resources requests MUST be signed by the
  Consumer and verified by the Service Provider. The purpose of signing requests
  is to prevent unauthorized parties from using the Consumer Key and Tokens when
  making Token requests or Protected Resources requests. The signature process
  encodes the Consumer Secret and Token Secret into a verifiable value which is
  included with the request.

  OAuth does not mandate a particular signature method, as each implementation
  can have its own unique requirements. The protocol defines three signature
  methods: HMAC-SHA1, RSA-SHA1, and PLAINTEXT, but Service Providers are free to
  implement and document their own methods. Recommending any particular method
  is beyond the scope of this specification.

  The Consumer declares a signature method in the `oauth_signature_method`
  parameter, generates a signature, and stores it in the `oauth_signature`
  parameter. The Service Provider verifies the signature as specified in each
  method. When verifying a Consumer signature, the Service Provider SHOULD check
  the request nonce to ensure it has not been used in a previous Consumer
  request.

  The signature process MUST NOT change the request parameter names or values,
  with the exception of the `oauth_signature` parameter.

  For more information refer to the OAuth 1.0 specification at
  http://oauth.net/core/1.0/#signing_process."
  (:require [clojure.string :as str]
            [crypto.random :as random]
            [pandect.core :as pandect]
            [ring.util.codec :as codec]
            [schema.core :as s]))

;; -----------------------------------------------------------------------------
;; Schema

(def ^:private signature-algos
  "Mapping from keyword algorithm used in a consumer to the string version used
  in the OAuth Authorization header."
  {:hmac-sha1 "HMAC-SHA1"
   :plaintext "PLAINTEXT"
   :rsa-sha1 "RSA-SHA1"})

(def SignatureAlgo
  (apply s/enum (keys signature-algos)))

(def SignatureMethod
  (apply s/enum (vals signature-algos)))

(def ConsumerConfig
  {:access-uri s/Str
   :authorize-uri s/Str
   :callback-uri s/Str
   :key s/Str
   :request-uri s/Str
   :secret s/Str
   :signature-algo SignatureAlgo})

(def ^:private Map
  "Hash-map of keyword or string to any value"
  {(s/either s/Keyword s/Str) s/Any})

(def OAuthAuthorization
  "Valid attributes and corresponding values allowed in the unsigned OAuth
  Authorization header."
  {(s/optional-key "oauth_callback") s/Str
   (s/optional-key "oauth_token") s/Str
   (s/optional-key "oauth_verifier") s/Str
   (s/optional-key "oauth_version") (s/eq "1.0")
   (s/required-key "oauth_consumer_key") s/Str
   (s/required-key "oauth_nonce") s/Str
   (s/required-key "oauth_signature_method") SignatureMethod
   (s/required-key "oauth_timestamp") (s/either s/Str s/Int)})

(def SignedOAuthAuthorization
  "Signed version of the valid attributes and corresponding values allowed in
  the OAuth Authorization header. See `OAuthAuthorization`."
  (assoc OAuthAuthorization (s/required-key "oauth_signature") s/Str))

(def ^:private RequestTokenParams
  {(s/optional-key "oauth_callback") s/Str})

(def ^:private AuthorizationParams
  (assoc Map (s/optional-key :callback-uri) s/Str
         (s/optional-key "oauth_token") s/Str))

(def ^:private RequestMethod
  "Valid HTTP request methods"
  (s/enum :delete :get :head :patch :post :put :trace))

(def ^:private Request
  "A clj-http compatible request map that is also OAuth 1.0 compatible."
  {(s/optional-key :form-params) Map
   (s/optional-key :headers) {s/Str s/Str}
   :request-method RequestMethod
   :url s/Str})

(def ^:private OAuthRequest
  "clj-http compatible request map with required `:oauth-params` that will be
  used to generate a signature."
  (assoc Request :oauth-params OAuthAuthorization))

(def ^:private SignedRequest
  "Signed OAuth request with an Authorization header."
  (assoc Request
         (s/optional-key :headers)
         {(s/required-key "Authorization") s/Str
          s/Str s/Str}))

;; -----------------------------------------------------------------------------
;; Utils

(defn- filter-vals
  [m]
  (into {} (filter val m)))

;; -----------------------------------------------------------------------------
;; Consumer

(defrecord Consumer
    [access-uri authorize-uri callback-uri key secret signature-algo])

(s/defn make-consumer :- Consumer
  "Create a new consumer instance with necessary URIs, key and secret."
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

(s/defn ^:private base-string :- s/Str
  "http://oauth.net/core/1.0/#anchor14

  The Signature Base String is a consistent reproducible concatenation of the
  request elements into a single string. The string is used as an input in
  hashing or signing algorithms. The HMAC-SHA1 signature method provides both a
  standard and an example of using the Signature Base String with a signing
  algorithm to generate signatures. All the request parameters MUST be encoded
  as described in Parameter Encoding prior to constructing the Signature Base
  String.

  The following items MUST be concatenated in order into a single string. Each
  item is encoded and separated by an ‘&’ character (ASCII code 38), even if
  empty.

  1. The HTTP request method used to send the request. Value MUST be uppercase,
     for example: `HEAD`, `GET`, `POST`, etc.
  2. The request URL from Section 9.1.2.
  3. The normalized request parameters string from Section 9.1.1."
  [method :- (s/either s/Keyword s/Str)
   uri :- s/Str
   params :- Map]
  base-string
  {:pre [(sorted? params)]}
  (format "%s&%s&%s"
          (-> method name str/upper-case)
          (codec/url-encode uri)
          (codec/url-encode (codec/form-encode (filter-vals params)))))

(s/defn signed-request :- SignedRequest
  [consumer :- Consumer oauth-request :- OAuthRequest]
  (let [{:keys [form-params request-method oauth-params url]} oauth-request
        base-string (base-string request-method
                                 url
                                 (merge oauth-params form-params))
        signed-params (assoc oauth-params "oauth_signature"
                             (sign consumer base-string))]
    (-> oauth-request
        (dissoc :oauth-params)
        (assoc-in [:headers "Content-Type"]
                  "application/x-www-form-urlencoded")
        (assoc-in [:headers "Authorization"]
                  (str "OAuth " (auth-headers->str signed-params))))))

;; -----------------------------------------------------------------------------
;; Request token

(s/defn request-token-request
  "Generate a clj-http compatible request map that will request a token from the
  provider associated with `consumer`.

  http://oauth.net/core/1.0/#auth_step1

  The Consumer obtains an unauthorized Request Token by asking the Service
  Provider to issue a Token. The Request Token’s sole purpose is to receive
  User approval and can only be used to obtain an Access Token.

  To obtain a Request Token, the Consumer sends an HTTP request to the Service
  Provider’s Request Token URL. The Service Provider documentation specifies
  the HTTP method for this request, and HTTP POST is RECOMMENDED.

  Note, if you override the \"oauth_callback\" via `params`, you need to pass
  the same callback URI to `authorization-url`."
  ([consumer :- Consumer] (request-token-request consumer {}))
  ([consumer :- Consumer params :- RequestTokenParams]
   (signed-request
    consumer
    {:oauth-params
     (sorted-map
      "oauth_callback" (or (get params "oauth_callback") (:callback-uri consumer))
      "oauth_consumer_key" (:key consumer)
      "oauth_nonce" (random/url-part 32)
      "oauth_signature_method" (-> consumer :signature-algo signature-algos)
      "oauth_timestamp" (->seconds (System/currentTimeMillis))
      "oauth_version" "1.0")
     :request-method :post
     :url (:request-uri consumer)})))

;; -----------------------------------------------------------------------------
;; User authorisation

(s/defn authorization-url
  "Generate a provider-specific authorisation URL that you send the user's agent
  (aka. browser) to typically via an HTTP redirect.

  Optional `params` can be passed to append to the authorisation URL via a query
  string.

  `params` may contain an \"oauth_callback\" to override any callback URI in the
  consumer. This can be useful when you need to pass some state for CSRF
  protection to the OAuth provider.

  Note, if you override the \"oauth_callback\" via `params`, you need to pass
  the same callback URI to `request-token-request`."
  ([consumer :- Consumer] (authorization-url consumer {}))
  ([consumer :- Consumer params :- AuthorizationParams]
   (format
    "%s?%s"
    (:authorize-uri consumer)
    (-> {"oauth_callback" (:callback-uri consumer)}
        (merge params)
        filter-vals
        codec/form-encode))))

;; -----------------------------------------------------------------------------
;; Access token request

(s/defn ^:always-validate access-token-request
  "Generate a signed request that will ask the OAuth provider for an access
  token.

  This request must contain the token and verifier provided by the OAuth
  provider when they redirect back to your application after you send someone to
  the authorisation URL generated by `authorization-url`."
  [consumer :- Consumer
   creds :- {(s/optional-key "oauth_token") s/Str
             (s/optional-key "oauth_verifier") s/Str}]
  (signed-request
   consumer
   {:oauth-params
    (merge
     (sorted-map
      "oauth_consumer_key" (:key consumer)
      "oauth_nonce" (random/url-part 32)
      "oauth_signature_method" (-> consumer :signature-algo signature-algos)
      "oauth_timestamp" (->seconds (System/currentTimeMillis))
      "oauth_version" "1.0")
     (when-let [token (get creds "oauth_token")]
       {"oauth_token" token})
     (when-let [verifier (get creds "oauth_verifier")]
       {"oauth_verifier" verifier}))
    :request-method :post
    :url (:access-uri consumer)}))
