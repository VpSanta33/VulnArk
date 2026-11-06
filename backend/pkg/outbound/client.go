// Package outbound bounds HTTP responses and checks destinations at connection
// time, so redirects and DNS changes cannot bypass the network boundary.
package outbound

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"
)

var ErrDestinationDenied = errors.New("出站请求目标未获授权")

type Policy struct {
	// An empty list permits public hosts. Entries are exact DNS names/IPs.
	AllowedHosts []string
	// Only the deployment administrator can authorize a private scheme/host/port.
	PrivateOrigins []string
}

func origin(u *url.URL) string {
	port := u.Port()
	if port == "" {
		port = "80"
		if u.Scheme == "https" {
			port = "443"
		}
	}
	return u.Scheme + "://" + net.JoinHostPort(strings.ToLower(strings.TrimSuffix(u.Hostname(), ".")), port)
}

func ValidatePrivateOrigins(origins []string) error {
	for _, raw := range origins {
		u, err := parseURL(raw)
		if err != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" {
			return errors.New("security.outbound_private_origins must contain exact HTTP origins without paths, credentials, queries, or wildcards")
		}
	}
	return nil
}

func parseURL(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil || u == nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" || u.User != nil || u.Opaque != "" || strings.ContainsAny(u.Hostname(), "*%") {
		return nil, ErrDestinationDenied
	}
	if port := u.Port(); port != "" {
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65535 {
			return nil, ErrDestinationDenied
		}
	}
	return u, nil
}

func (p Policy) privateAllowed(u *url.URL) bool {
	for _, raw := range p.PrivateOrigins {
		allowed, err := parseURL(raw)
		if err == nil && allowed.Path == "" && allowed.RawQuery == "" && allowed.Fragment == "" && origin(allowed) == origin(u) {
			return true
		}
	}
	return false
}

func (p Policy) ValidateURL(raw string) error {
	u, err := parseURL(raw)
	if err != nil {
		return err
	}
	if p.privateAllowed(u) {
		return nil
	}
	host := strings.ToLower(strings.TrimSuffix(u.Hostname(), "."))
	if len(p.AllowedHosts) > 0 {
		allowed := false
		for _, candidate := range p.AllowedHosts {
			allowed = allowed || host == strings.ToLower(candidate)
		}
		if !allowed {
			return ErrDestinationDenied
		}
	}
	if ip, err := netip.ParseAddr(host); err == nil && !publicIP(ip) {
		return ErrDestinationDenied
	}
	if host == "localhost" || strings.HasSuffix(host, ".localhost") {
		return ErrDestinationDenied
	}
	return nil
}

var reservedNetworks = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"), netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("192.0.0.0/24"), netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("192.88.99.0/24"),
	netip.MustParsePrefix("198.18.0.0/15"), netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"), netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("2001:db8::/32"), netip.MustParsePrefix("2001::/23"),
	netip.MustParsePrefix("3fff::/20"),
	netip.MustParsePrefix("2002::/16"), netip.MustParsePrefix("64:ff9b::/96"),
	netip.MustParsePrefix("64:ff9b:1::/48"), netip.MustParsePrefix("100::/64"),
	netip.MustParsePrefix("2001:10::/28"), netip.MustParsePrefix("2001:20::/28"),
}

func publicIP(ip netip.Addr) bool {
	ip = ip.Unmap()
	if !ip.IsValid() || ip.Zone() != "" || !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
		return false
	}
	// Only the currently assigned global IPv6 unicast space is public; other
	// ranges include translation, discard, local-use and unallocated addresses.
	if ip.Is6() && !netip.MustParsePrefix("2000::/3").Contains(ip) {
		return false
	}
	for _, prefix := range reservedNetworks {
		if prefix.Contains(ip) {
			return false
		}
	}
	return true
}

type privateOriginKey struct{}

type checkedTransport struct {
	policy Policy
	base   *http.Transport
}

func (t *checkedTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if err := t.policy.ValidateURL(req.URL.String()); err != nil {
		return nil, err
	}
	ctx := context.WithValue(req.Context(), privateOriginKey{}, t.policy.privateAllowed(req.URL))
	return t.base.RoundTrip(req.Clone(ctx))
}

func (t *checkedTransport) CloseIdleConnections() { t.base.CloseIdleConnections() }

// NewClient checks resolved addresses and dials those exact IPs. Environment
// proxies are deliberately disabled: an unchecked proxy would bypass the policy.
func NewClient(timeout time.Duration, policy Policy) *http.Client {
	policy.AllowedHosts = append([]string(nil), policy.AllowedHosts...)
	policy.PrivateOrigins = append([]string(nil), policy.PrivateOrigins...)
	transport := &http.Transport{
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: time.Second,
	}
	transport.MaxResponseHeaderBytes = 32 << 10
	transport.MaxConnsPerHost = 10
	dialer := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
	transport.DialContext = checkedDial(net.DefaultResolver.LookupNetIP, dialer.DialContext)
	return &http.Client{
		Timeout:   timeout,
		Transport: &checkedTransport{policy: policy, base: transport},
		CheckRedirect: func(req *http.Request, previous []*http.Request) error {
			if len(previous) >= 10 {
				return errors.New("出站请求重定向次数超过限制")
			}
			if err := policy.ValidateURL(req.URL.String()); err != nil {
				return err
			}
			if len(previous) > 0 && origin(req.URL) != origin(previous[0].URL) {
				// Custom API headers may contain credentials as well as Authorization.
				req.Header = make(http.Header)
			}
			return nil
		},
	}
}

func checkedDial(lookup func(context.Context, string, string) ([]netip.Addr, error), dial func(context.Context, string, string) (net.Conn, error)) func(context.Context, string, string) (net.Conn, error) {
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(address)
		if err != nil {
			return nil, ErrDestinationDenied
		}
		ips, err := lookup(ctx, "ip", host)
		if err != nil || len(ips) == 0 {
			return nil, errors.New("出站请求目标解析失败")
		}
		allowPrivate, _ := ctx.Value(privateOriginKey{}).(bool)
		for _, ip := range ips {
			if !allowPrivate && !publicIP(ip) {
				return nil, ErrDestinationDenied
			}
		}
		var lastErr error
		for _, ip := range ips {
			conn, err := dial(ctx, network, net.JoinHostPort(ip.String(), port))
			if err == nil {
				return conn, nil
			}
			lastErr = err
		}
		return nil, lastErr
	}
}

func ReadBody(body io.Reader, limit int64) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(body, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("上游响应超过大小限制 (%d bytes)", limit)
	}
	return data, nil
}
