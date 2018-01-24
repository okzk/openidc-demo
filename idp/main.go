package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"github.com/go-chi/chi"
	"github.com/go-chi/chi/middleware"
	"github.com/google/uuid"
	"github.com/patrickmn/go-cache"
	"log"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"time"
)

var tmpCache = cache.New(10*time.Minute, 10*time.Minute)

var issuer = fmt.Sprintf("http://%s:3000", os.Getenv("FQDN"))

type ClientConfig struct {
	ID          string
	Secret      string
	RedirectURI string
}

type TokenContent struct {
	User     string
	ClientID string
	Nonce    string
}

type Claim struct {
	jwt.StandardClaims

	Nonce string `json:"nonce,omitempty"`
}

func getClientConfig(clientID string) (*ClientConfig, error) {
	// 本来はDB等から引いてくるが、ココでは固定で返す
	if clientID != "my_client_id" {
		return nil, errors.New("not found")
	}

	return &ClientConfig{
		ID:          "my_client_id",
		Secret:      "this_is_client_secret",
		RedirectURI: fmt.Sprintf("http://%s/protected/openidc_callback", os.Getenv("FQDN")),
	}, nil
}

func main() {
	r := chi.NewRouter()
	r.Use(middleware.Logger)

	r.Get("/.well-known/openid-configuration", metadata)
	r.Get("/as/authorization.oauth2", authorization)
	r.Post("/as/token.oauth2", token)

	http.ListenAndServe(":3000", r)
}

func metadata(w http.ResponseWriter, _ *http.Request) {
	// ココでは仕様でREQUIREDとなっているモノのうち、ごく一部だけをmetadataとして返す。
	// http://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata
	//
	// なお、mod_auth_openidcの設定でOIDCProviderMetadataURLの代わりに以下を直接設定すれば
	// metadataの実装自体が不要となる。
	//
	//  - OIDCProviderIssuer
	//  - OIDCProviderAuthorizationEndpoint
	//  - OIDCProviderTokenEndpoint
	//
	// 直接指定する場合はhttpsでないとダメなので、デモではmetadataのサブセット実装としている

	b, _ := json.Marshal(map[string]interface{}{
		"issuer":                 issuer,
		"authorization_endpoint": issuer + "/as/authorization.oauth2",
		"token_endpoint":         issuer + "/as/token.oauth2",
	})

	log.Println("metadata response: ", string(b))

	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Length", strconv.Itoa(len(b)))
	w.Write(b)
}

func authorization(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()

	// 固定値
	if query.Get("response_type") != "code" {
		http.Error(w, "invalid response_type", http.StatusBadRequest)
		return
	}

	// 固定値
	if query.Get("scope") != "openid" {
		http.Error(w, "invalid scope", http.StatusBadRequest)
		return
	}

	clientID := query.Get("client_id")
	config, err := getClientConfig(clientID)
	if err != nil {
		// 登録されていたclientではなかった
		http.Error(w, "forbidden", http.StatusForbidden)
	}

	// redirect_uriが登録されたものかチェック
	if query.Get("redirect_uri") != config.RedirectURI {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}

	// ログインしていないようだったら、ログイン画面に遷移してログイン後に、以下のリダイレクト処理を行う。
	// ココでは"Alice"としてログインしているモノとする。

	// 後で使う情報を、codeをキーに一時的に保存
	// 実際にはmemcached等を使う
	code := uuid.New().String()
	nonce := query.Get("nonce")
	tmpCache.Set(code, &TokenContent{User: "Alice", ClientID: clientID, Nonce: nonce}, cache.DefaultExpiration)

	// redirectURIにcodeと、リクエストにstateが存在していたらソレをそのままクエリパラメータに付けてリダイレクト
	v := url.Values{}
	v.Add("code", code)
	state := query.Get("state")
	if state != "" {
		v.Add("state", state)
	}
	http.Redirect(w, r, config.RedirectURI+"?"+v.Encode(), http.StatusFound)
}

func token(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()

	clientID, secret, ok := r.BasicAuth()
	if !ok {
		// Basic認証が不正
		http.Error(w, "forbidden", http.StatusForbidden)
	}
	config, err := getClientConfig(clientID)
	if err != nil {
		// 登録されていたclientではなかった
		http.Error(w, "forbidden", http.StatusForbidden)
	}
	if secret != config.Secret {
		// シークレットが違う
		http.Error(w, "forbidden", http.StatusForbidden)
	}
	// redirect_uriが登録されたものかチェック
	if r.Form.Get("redirect_uri") != config.RedirectURI {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}

	// 固定値
	if r.Form.Get("grant_type") != "authorization_code" {
		http.Error(w, "invalid grant_type", http.StatusBadRequest)
		return
	}

	data, ok := tmpCache.Get(r.Form.Get("code"))
	if !ok {
		// authorizationで発行したコードじゃない
		http.Error(w, "forbidden", http.StatusForbidden)
	}
	// リプレイ攻撃を緩和するために使ったcodeは削除する
	tmpCache.Delete(r.Form.Get("code"))

	content := data.(*TokenContent)
	if content.ClientID != clientID {
		// 違うClientID用に発行したcodeだった
		http.Error(w, "forbidden", http.StatusForbidden)
	}

	token := jwt.NewWithClaims(jwt.GetSigningMethod("HS256"), Claim{
		StandardClaims: jwt.StandardClaims{
			// ユーザ名
			Subject: content.User,
			// IdPのURL
			Issuer: issuer,
			// どのサービスに対して発行したか
			Audience:  clientID,
			IssuedAt:  time.Now().Unix(),
			ExpiresAt: time.Now().Unix() + 3600,
		},
		Nonce: content.Nonce,
	})

	tokenStr, err := token.SignedString([]byte(config.Secret))
	b, err := json.Marshal(map[string]string{
		"access_token": uuid.New().String(),
		"token_type":   "Bearer",
		"id_token":     tokenStr,
	})
	if err != nil {
		panic(err)
	}

	log.Println("token response: ", string(b))

	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Length", strconv.Itoa(len(b)))
	w.Write(b)
}
