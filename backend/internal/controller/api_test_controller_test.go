package controller

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
	"vulnark/pkg/outbound"
)

func TestAPITesterRejectsRedirectsAndBoundsBodies(t *testing.T) {
	gin.SetMode(gin.TestMode)
	var targetCalls atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { targetCalls.Add(1) }))
	defer target.Close()
	source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/large" {
			_, _ = w.Write([]byte(strings.Repeat("x", (4<<20)+1)))
			return
		}
		http.Redirect(w, r, target.URL, http.StatusFound)
	}))
	defer source.Close()
	policy := outbound.Policy{PrivateOrigins: []string{source.URL}}
	client := outbound.NewClient(time.Second, policy)
	defer client.CloseIdleConnections()
	ctrl := &APITestController{client: client, policy: policy}
	router := gin.New()
	router.POST("/test", ctrl.TestAPI)
	request := func(url string) *httptest.ResponseRecorder {
		encoded, err := json.Marshal(APITestRequest{Method: "GET", URL: url})
		require.NoError(t, err)
		req := httptest.NewRequest("POST", "/test", strings.NewReader(string(encoded)))
		req.Header.Set("Content-Type", "application/json")
		response := httptest.NewRecorder()
		router.ServeHTTP(response, req)
		return response
	}
	denied := request(target.URL)
	require.Equal(t, 400, denied.Code)
	require.Zero(t, targetCalls.Load())
	redirect := request(source.URL)
	require.Equal(t, 200, redirect.Code)
	require.Contains(t, redirect.Body.String(), "目标未获授权")
	require.Zero(t, targetCalls.Load())
	large := request(source.URL + "/large")
	require.Equal(t, 200, large.Code)
	require.Contains(t, large.Body.String(), "大小限制")
	require.Less(t, large.Body.Len(), 2000)
	oversized := httptest.NewRequest("POST", "/test", strings.NewReader(`{"method":"GET","url":"https://httpbin.org","headers":{"X-Large":"`+strings.Repeat("x", 1<<20)+`"}}`))
	oversized.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	router.ServeHTTP(response, oversized)
	require.Equal(t, 400, response.Code)
}
