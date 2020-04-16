package oauth

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/fmarinCeiba/bookstore_utils-go/rest_errors"
	"github.com/mercadolibre/golang-restclient/rest"
)

const (
	headerXPublic   = "X-Public"
	headerXClientID = "X-Client-Id"
	headerXCallerID = "X-Caller-Id"

	paramAccessToken = "access_token"
)

var (
	oauthRestClient = rest.RequestBuilder{
		BaseURL: "http://localhost:8080",
		Timeout: 200 * time.Millisecond,
	}
)

type accessToken struct {
	ID       string `json:"id"`
	UserID   int64  `json:"user_id"`
	ClientID int64  `json:"client_id"`
}

type oauthClient struct{}

type oauthInterface interface{}

func IsPublic(req *http.Request) bool {
	if req == nil {
		return true
	}
	return req.Header.Get(headerXPublic) == "true"
}

func GetCallerID(req *http.Request) int64 {
	if req == nil {
		return 0
	}
	callerID, err := strconv.ParseInt(req.Header.Get(headerXCallerID), 10, 64)
	if err != nil {
		return 0
	}
	return callerID
}

func GetClientID(req *http.Request) int64 {
	if req == nil {
		return 0
	}
	clientID, err := strconv.ParseInt(req.Header.Get(headerXClientID), 10, 64)
	if err != nil {
		return 0
	}
	return clientID
}

func AuthenticateRequest(req *http.Request) rest_errors.RestErr {
	if req == nil {
		return nil
	}
	cleanRequest(req)
	accessTokenID := strings.TrimSpace(req.URL.Query().Get(paramAccessToken))
	if accessTokenID == "" {
		return nil
	}
	at, err := getAccessToken(accessTokenID)
	if err != nil {
		if err.Status() == http.StatusNotFound {
			return nil
		}
		return err
	}

	req.Header.Add(headerXCallerID, fmt.Sprintf("%v", at.UserID))
	req.Header.Add(headerXClientID, fmt.Sprintf("%v", at.ClientID))
	return nil
}

func cleanRequest(req *http.Request) {
	if req == nil {
		return
	}
	req.Header.Del(headerXClientID)
	req.Header.Del(headerXCallerID)
}

func getAccessToken(accessTokenID string) (*accessToken, rest_errors.RestErr) {
	res := oauthRestClient.Get(fmt.Sprintf("/oauth/access_token/%s", accessTokenID))
	if res == nil || res.Response == nil {
		return nil, rest_errors.NewInternalServerError("invalid resclient response when trying to get access token", errors.New("network timeout"))
	}
	if res.StatusCode > 299 {
		rErr, err := rest_errors.NewRestErrorFromBytes(res.Bytes())
		if err != nil {
			return nil, rest_errors.NewInternalServerError("invalid error interface when trying to get access token", err)
		}
		return nil, rErr
	}
	var at accessToken
	if err := json.Unmarshal(res.Bytes(), &at); err != nil {
		return nil, rest_errors.NewInternalServerError("error when trying to unmarshal access token response", errors.New("rest error"))
	}
	return &at, nil
}
