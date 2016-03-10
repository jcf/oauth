(ns oauth.one
  (:require [clojure.string :as str]
            [ring.util.codec :as codec]
            [schema.core :as s]))

(s/defn auth-headers->str :- s/Str
  [m :- {s/Keyword s/Any}]
  (->> m
       (map #(format "%s=\"%s\"" (-> % key name) (-> % val codec/url-encode)))
       (str/join ", ")))

(defn auth-headers
  []
  )

(defn sign-request
  [{:keys [form-params]}]
  (merge {:headers {"Authorization" "OAuth coming soon!"}}
         (when form-params {:form-params form-params})))
