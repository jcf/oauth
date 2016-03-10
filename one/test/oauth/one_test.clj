(ns oauth.one-test
  (:require [clojure.test :refer :all]
            [oauth.one :refer :all]
            [schema.test :refer [validate-schemas]]))

(use-fixtures :once validate-schemas)

(deftest t-auth-headers->str
  (are [m s] (= (auth-headers->str m) s)
    {} ""

    {:oauth_callback "http://example.com/callback"}
    "oauth_callback=\"http%3A%2F%2Fexample.com%2Fcallback\""

    {:oauth_callback "http://example.com/callback"
     :oauth_nonce "abc123"}
    (str "oauth_callback=\"http%3A%2F%2Fexample.com%2Fcallback\", "
         "oauth_nonce=\"abc123\"")))

(deftest t-sign-request
  (is (= (sign-request {}) {:headers {"Authorization" "OAuth coming soon!"}})))
