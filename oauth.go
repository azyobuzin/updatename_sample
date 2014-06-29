package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	HmacSha1     = "HMAC-SHA1"
	PlainText    = "PLAINTEXT"
	allowedChars = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz-._~"
)

func sortedKeys(m map[string][]string) []string {
	keys := make([]string, len(m))
	i := 0
	for k, _ := range m {
		keys[i] = k
		i++
	}
	sort.Strings(keys)
	return keys
}

func addAllParams(target url.Values, p map[string][]string) {
	for k, values := range p {
		for _, v := range values {
			target.Add(k, v)
		}
	}
}

func forEachSorted(m map[string][]string, action func(string, string)) {
	keys := sortedKeys(m)
	for _, k := range keys {
		x := m[k]
		y := make([]string, len(x))
		copy(y, x)
		sort.Strings(y)
		for _, v := range y {
			action(k, v)
		}
	}
}

func percentEncode(text string) string {
	writer := new(bytes.Buffer)
	reader := strings.NewReader(text)
	for {
		c, err := reader.ReadByte()
		if err == io.EOF {
			return writer.String()
		}

		if strings.ContainsRune(allowedChars, rune(c)) {
			writer.WriteByte(c)
		} else {
			writer.WriteRune('%')
			if c < 16 {
				writer.WriteRune('0')
			}
			writer.WriteString(fmt.Sprintf("%X", c))
		}
	}
}

func normalizeUrl(u *url.URL) string {
	host := strings.ToLower(u.Host)
	if u.Scheme == "http" {
		host = strings.Replace(host, ":80", "", 1)
	} else if u.Scheme == "https" {
		host = strings.Replace(host, ":443", "", 1)
	}
	return fmt.Sprintf("%v://%v%v", u.Scheme, u.Host, u.Path)
}

func normalizeParameters(params map[string][]string) string {
	writer := new(bytes.Buffer)
	forEachSorted(params, func(k, v string) {
		writer.WriteString(percentEncode(k))
		writer.WriteRune('=')
		writer.WriteString(percentEncode(v))
		writer.WriteRune('&')
	})
	return writer.String()[:writer.Len()-1]
}

func timestamp() string {
	return fmt.Sprint(time.Now().Unix())
}

func nonce() string {
	const (
		s     = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
		count = 42
	)
	a := make([]string, count)
	for i := 0; i < count; i++ {
		a[i] = string(s[rand.Intn(count)])
	}
	return strings.Join(a, "")
}

func signParametersBase(realm, consumerKey, token, signatureMethod, timestamp, nonce, callback, verifier string) map[string][]string {
	dic := map[string][]string{"oauth_version": []string{"1.0"}}
	if realm != "" {
		dic["realm"] = []string{realm}
	}
	if consumerKey != "" {
		dic["oauth_consumer_key"] = []string{consumerKey}
	}
	if token != "" {
		dic["oauth_token"] = []string{token}
	}
	if signatureMethod != "" {
		dic["oauth_signature_method"] = []string{signatureMethod}
	}
	if timestamp != "" {
		dic["oauth_timestamp"] = []string{timestamp}
	}
	if nonce != "" {
		dic["oauth_nonce"] = []string{nonce}
	}
	if callback != "" {
		dic["oauth_callback"] = []string{callback}
	}
	if verifier != "" {
		dic["oauth_verifier"] = []string{verifier}
	}
	return dic
}

func signatureBase(httpMethod string, u *url.URL, signParams, params map[string][]string) string {
	baseParams := url.Values{}
	addAllParams(baseParams, signParams)
	addAllParams(baseParams, params)
	addAllParams(baseParams, u.Query())

	return strings.Join([]string{
		strings.ToUpper(httpMethod),
		percentEncode(normalizeUrl(u)),
		percentEncode(normalizeParameters(baseParams)),
	}, "&")
}

func signatureKey(consumerSecret, tokenSecret string) string {
	return percentEncode(consumerSecret) + "&" + percentEncode(tokenSecret)
}

func signature(baseString, key, signatureMethod string) string {
	if signatureMethod == HmacSha1 {
		mac := hmac.New(sha1.New, []byte(key))
		mac.Write([]byte(baseString))
		return base64.StdEncoding.EncodeToString(mac.Sum(nil))
	} else {
		return key
	}
}

func signParameters(httpMethod string, u *url.URL, realm, consumerKey, consumerSecret, token, tokenSecret, signatureMethod, callback, verifier string, params map[string][]string) map[string][]string {
	t := ""
	n := ""
	if signatureMethod != PlainText {
		t = timestamp()
		n = nonce()
	}
	signParams := signParametersBase(realm, consumerKey, token, signatureMethod, t, n, callback, verifier)
	signParams["oauth_signature"] = []string{signature(
		signatureBase(httpMethod, u, signParams, params),
		signatureKey(consumerSecret, tokenSecret), signatureMethod)}
	return signParams
}

func CreateAuthorizationHeader(httpMethod, uri, realm, consumerKey, consumerSecret, token, tokenSecret, signatureMethod, callback, verifier string, params map[string][]string) (string, error) {
	u, e := url.Parse(uri)
	if e != nil {
		return "", e
	}
	if !u.IsAbs() {
		return "", errors.New("The uri is not absolute.")
	}
	if !(signatureMethod == HmacSha1 || signatureMethod == PlainText) {
		return "", errors.New("The signatureMethod is not supported.")
	}

	signParams := signParameters(httpMethod, u, realm, consumerKey, consumerSecret, token, tokenSecret, signatureMethod, callback, verifier, params)
	writer := bytes.NewBufferString("OAuth ")
	forEachSorted(signParams, func(k, v string) {
		writer.WriteString(percentEncode(k))
		writer.WriteString(`="`)
		writer.WriteString(percentEncode(v))
		writer.WriteString(`",`)
	})
	return writer.String()[:writer.Len()-1], nil
}

type OAuthClient struct {
	ConsumerKey, ConsumerSecret, OAuthToken, OAuthTokenSecret, ScreenName string
	UserId                                                                uint64
}

func NewOAuthClient(consumerKey, consumerSecret string) *OAuthClient {
	return &OAuthClient{ConsumerKey: consumerKey, ConsumerSecret: consumerSecret}
}

func NewOAuthClientWithToken(consumerKey, consumerSecret, oauthToken, oauthTokenSecret string) *OAuthClient {
	return &OAuthClient{
		ConsumerKey: consumerKey, ConsumerSecret: consumerSecret,
		OAuthToken: oauthToken, OAuthTokenSecret: oauthTokenSecret,
	}
}

func (self *OAuthClient) MakeGetRequest(urlStr string, params map[string][]string) (*http.Request, error) {
	u, e := url.Parse(urlStr)
	if e != nil {
		return nil, e
	}
	p := url.Values{}
	addAllParams(p, u.Query())
	addAllParams(p, params)
	u.RawQuery = p.Encode()
	urlStr = u.String()
	header, e := CreateAuthorizationHeader("GET", urlStr, "", self.ConsumerKey, self.ConsumerSecret,
		self.OAuthToken, self.OAuthTokenSecret, HmacSha1, "", "", map[string][]string{})
	if e != nil {
		return nil, e
	}
	req, e := http.NewRequest("GET", urlStr, &bytes.Reader{})
	if e != nil {
		return nil, e
	}
	req.Header.Set("Authorization", header)
	return req, nil
}

func (self *OAuthClient) MakePostRequest(urlStr string, params map[string][]string) (*http.Request, error) {
	u, e := url.Parse(urlStr)
	if e != nil {
		return nil, e
	}
	p := url.Values{}
	addAllParams(p, u.Query())
	addAllParams(p, params)
	u.RawQuery = ""
	urlStr = u.String()
	header, e := CreateAuthorizationHeader("POST", urlStr, "", self.ConsumerKey, self.ConsumerSecret,
		self.OAuthToken, self.OAuthTokenSecret, HmacSha1, "", "", p)
	if e != nil {
		return nil, e
	}
	body := p.Encode()
	req, e := http.NewRequest("POST", urlStr, strings.NewReader(body))
	if e != nil {
		return nil, e
	}
	req.Header.Set("Authorization", header)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Content-Length", strconv.Itoa(len([]byte(body))))
	return req, nil
}
