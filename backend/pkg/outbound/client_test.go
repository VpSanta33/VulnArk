package outbound

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestDestinationPolicy(t *testing.T) {
	p := Policy{}
	for _, raw := range []string{"file:///etc/passwd", "http://user:secret@example.com", "http://localhost", "http://127.0.0.1", "http://[::ffff:127.0.0.1]", "http://10.1.2.3", "http://169.254.169.254", "http://[100::1]", "http://[2001:2::1]", "http://[3fff::1]", "http://[4000::1]", "http://192.88.99.1", "http://[64:ff9b:1::a00:1]", "http://[2002:7f00:1::]", "http://[fc00::1]", "http://192.0.2.1", "http://224.0.0.1", "http://example.com:0"} {
		t.Run(raw, func(t *testing.T) { require.Error(t, p.ValidateURL(raw)) })
	}
	for _, raw := range []string{"https://example.com/path", "https://8.8.8.8", "https://[2606:4700:4700::1111]"} {
		require.NoError(t, p.ValidateURL(raw))
	}
	p = Policy{AllowedHosts: []string{"example.com"}, PrivateOrigins: []string{"http://127.0.0.1:11434"}}
	require.NoError(t, p.ValidateURL("https://example.com"))
	require.Error(t, p.ValidateURL("https://sub.example.com"))
	require.Error(t, p.ValidateURL("https://example.com.evil.test"))
	require.NoError(t, p.ValidateURL("http://127.0.0.1:11434/v1/chat"))
	require.Error(t, p.ValidateURL("http://127.0.0.1:11435"))
	require.Error(t, p.ValidateURL("https://127.0.0.1:11434"))
	require.NoError(t, ValidatePrivateOrigins(p.PrivateOrigins))
	for _, origin := range []string{"http://*.example.com", "http://localhost/path", "http://localhost?x=1", "http://user@localhost", "ftp://localhost"} {
		require.Error(t, ValidatePrivateOrigins([]string{origin}))
	}
}

func TestDNSCheckedAtDialAndPinned(t *testing.T) {
	dialed := ""
	lookup := func(context.Context, string, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("8.8.8.8"), netip.MustParseAddr("127.0.0.1")}, nil
	}
	dial := func(_ context.Context, _, addr string) (net.Conn, error) {
		dialed = addr
		return nil, errors.New("dial sentinel")
	}
	_, err := checkedDial(lookup, dial)(context.Background(), "tcp", "public.example:443")
	require.ErrorIs(t, err, ErrDestinationDenied)
	require.Empty(t, dialed, "a mixed public/private DNS answer must never be dialed")
	lookup = func(context.Context, string, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("8.8.8.8")}, nil
	}
	_, err = checkedDial(lookup, dial)(context.Background(), "tcp", "public.example:443")
	require.EqualError(t, err, "dial sentinel")
	require.Equal(t, "8.8.8.8:443", dialed, "dial the validated numeric address, never resolve the hostname twice")
}

func TestPrivateOriginAndRedirectBoundary(t *testing.T) {
	var reached atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached.Add(1)
		require.Empty(t, r.Header.Get("X-API-Key"))
		require.Empty(t, r.Header.Get("Authorization"))
		_, _ = io.WriteString(w, "ok")
	}))
	defer target.Close()
	source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, target.URL, http.StatusFound) }))
	defer source.Close()
	client := NewClient(time.Second, Policy{})
	_, err := client.Get(source.URL)
	require.ErrorIs(t, err, ErrDestinationDenied)
	client = NewClient(time.Second, Policy{PrivateOrigins: []string{source.URL}})
	defer client.CloseIdleConnections()
	_, err = client.Get(source.URL)
	require.ErrorIs(t, err, ErrDestinationDenied)
	require.Zero(t, reached.Load(), "redirect must not reach an unapproved private origin")
	client = NewClient(time.Second, Policy{PrivateOrigins: []string{source.URL, target.URL}})
	defer client.CloseIdleConnections()
	request, err := http.NewRequest("GET", source.URL, nil)
	require.NoError(t, err)
	request.Header.Set("Authorization", "Bearer secret")
	request.Header.Set("X-API-Key", "custom-secret")
	response, err := client.Do(request)
	require.NoError(t, err)
	defer response.Body.Close()
	require.EqualValues(t, 1, reached.Load())
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	request, err = http.NewRequestWithContext(ctx, "GET", source.URL, nil)
	require.NoError(t, err)
	_, err = client.Do(request)
	require.ErrorIs(t, err, context.Canceled)
}

func TestReadBodyLimit(t *testing.T) {
	body, err := ReadBody(strings.NewReader("1234"), 4)
	require.NoError(t, err)
	require.Equal(t, "1234", string(body))
	_, err = ReadBody(strings.NewReader("12345"), 4)
	require.Error(t, err)
}
