package fortinet

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"testing"
)

func TestNetworkConfigUsesSessionAndDualStackEndpoint(t *testing.T) {
	var paths []string
	transport := roundTripFunc(func(r *http.Request) (*http.Response, error) {
		paths = append(paths, r.URL.RequestURI())
		if r.Header.Get("Accept-Encoding") != "identity" || r.Header.Get("Content-Length") == "" {
			t.Fatalf("missing FortiGate compatibility headers: %#v", r.Header)
		}
		if r.Host != "example.test:443" {
			t.Fatalf("Host = %q, want explicit HTTPS port", r.Host)
		}
		header := make(http.Header)
		if r.URL.Path == "/remote/saml/auth_id" {
			if r.URL.Query().Get("id") != "callback-id" {
				t.Fatalf("unexpected SAML ID")
			}
			header.Add("Set-Cookie", "SVPNTMPCOOKIE=temporary; Path=/remote/hostcheck_install; Secure; HttpOnly")
			return &http.Response{StatusCode: http.StatusOK, Status: "200 OK", Header: header, Body: io.NopCloser(strings.NewReader("ret=1,redir=/remote/hostcheck_install?auth_type=16")), Request: r}, nil
		} else if r.URL.Path == "/remote/hostcheck_install" {
			if _, err := r.Cookie("SVPNTMPCOOKIE"); err != nil {
				t.Fatalf("host-check request missing temporary cookie: %v", err)
			}
			header.Add("Set-Cookie", "SVPNCOOKIE=test-session; Path=/remote; Secure; HttpOnly")
		} else if _, err := r.Cookie("SVPNCOOKIE"); err != nil {
			t.Fatalf("network request missing session cookie: %v", err)
		}
		body := ""
		if r.URL.Path == "/remote/fortisslvpn_xml" {
			body = `<sslvpn><assigned-addr ipv6="2001:db8::1/128"/></sslvpn>`
		}
		return &http.Response{StatusCode: http.StatusOK, Status: "200 OK", Header: header, Body: io.NopCloser(strings.NewReader(body)), Request: r}, nil
	})

	client, err := NewClient(ClientOptions{Gateway: "example.test"})
	if err != nil {
		t.Fatal(err)
	}
	client.http.Transport = transport

	ctx := context.Background()
	if err := client.AuthenticateSAML(ctx, "callback-id"); err != nil {
		t.Fatal(err)
	}
	config, err := client.NetworkConfig(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if config.IPv6 == nil {
		t.Fatal("IPv6 assignment was not parsed")
	}
	want := []string{
		"/remote/saml/auth_id?id=callback-id",
		"/remote/hostcheck_install?auth_type=16",
		"/remote/index",
		"/remote/fortisslvpn",
		"/remote/fortisslvpn_xml?dual_stack=1",
	}
	if !reflect.DeepEqual(paths, want) {
		t.Fatalf("paths = %#v, want %#v", paths, want)
	}
}

func TestPasswordLoginSendsFormAndRetainsCookie(t *testing.T) {
	var gotForm url.Values
	transport := roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.URL.Path != "/remote/logincheck" || r.Method != http.MethodPost {
			t.Fatalf("unexpected request: %s %s", r.Method, r.URL)
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatal(err)
		}
		gotForm, err = url.ParseQuery(string(body))
		if err != nil {
			t.Fatal(err)
		}
		header := make(http.Header)
		header.Add("Set-Cookie", "SVPNCOOKIE=test-session; Path=/remote; Secure; HttpOnly")
		return &http.Response{StatusCode: http.StatusOK, Status: "200 OK", Header: header, Body: io.NopCloser(strings.NewReader("ret=1")), Request: r}, nil
	})
	client, err := NewClient(ClientOptions{Gateway: "example.test"})
	if err != nil {
		t.Fatal(err)
	}
	client.http.Transport = transport
	if err := client.AuthenticatePassword(context.Background(), "alice", "not-logged", "employees"); err != nil {
		t.Fatal(err)
	}
	want := url.Values{"username": {"alice"}, "credential": {"not-logged"}, "realm": {"employees"}, "ajax": {"1"}}
	if !reflect.DeepEqual(gotForm, want) {
		t.Fatalf("form = %#v, want %#v", gotForm, want)
	}
}

func TestPasswordLoginReportsInvalidPasswordAndTracesCookieDiagnostic(t *testing.T) {
	transport := roundTripFunc(func(r *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Status: "200 OK", Header: make(http.Header), Body: io.NopCloser(strings.NewReader("ret=0")), Request: r}, nil
	})
	client, err := NewClient(ClientOptions{Gateway: "example.test"})
	if err != nil {
		t.Fatal(err)
	}
	client.http.Transport = transport
	var trace bytes.Buffer
	client.SetDebugWriter(&trace)
	err = client.AuthenticatePassword(context.Background(), "alice", "wrong", "")
	if !errors.Is(err, ErrInvalidPassword) || err.Error() != "Password errata" {
		t.Fatalf("AuthenticatePassword() error = %v", err)
	}
	if !strings.Contains(trace.String(), "gateway did not issue an SVPNCOOKIE") {
		t.Fatalf("debug trace = %q, missing cookie diagnostic", trace.String())
	}
}

func TestPasswordLoginMapsUnauthorizedToInvalidPassword(t *testing.T) {
	transport := roundTripFunc(func(r *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusUnauthorized, Status: "401 Unauthorized", Header: make(http.Header), Body: io.NopCloser(strings.NewReader("denied")), Request: r}, nil
	})
	client, err := NewClient(ClientOptions{Gateway: "example.test"})
	if err != nil {
		t.Fatal(err)
	}
	client.http.Transport = transport
	if err := client.AuthenticatePassword(context.Background(), "alice", "wrong", ""); !errors.Is(err, ErrInvalidPassword) {
		t.Fatalf("AuthenticatePassword() error = %v, want ErrInvalidPassword", err)
	}
}

func TestRequestErrorRedactsCookieValues(t *testing.T) {
	transport := roundTripFunc(func(r *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusForbidden, Status: "403 Forbidden", Header: make(http.Header), Body: io.NopCloser(strings.NewReader("denied")), Request: r}, nil
	})
	client, err := NewClient(ClientOptions{Gateway: "example.test"})
	if err != nil {
		t.Fatal(err)
	}
	client.http.Transport = transport
	client.http.Jar.SetCookies(client.baseURL, []*http.Cookie{{Name: "SVPNCOOKIE", Value: "must-not-appear", Path: "/"}})
	_, err = client.get(context.Background(), "/remote/index")
	if err == nil || !strings.Contains(err.Error(), "SVPNCOOKIE") || strings.Contains(err.Error(), "must-not-appear") {
		t.Fatalf("error did not safely describe sent cookies: %v", err)
	}
}

func TestNetworkConfigFallsBackWhenWebModeIndexIsForbidden(t *testing.T) {
	transport := roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.URL.Path == "/remote/index" {
			return &http.Response{StatusCode: http.StatusForbidden, Status: "403 Forbidden", Header: make(http.Header), Body: io.NopCloser(strings.NewReader("web mode disabled")), Request: r}, nil
		}
		body := ""
		if r.URL.Path == "/remote/fortisslvpn_xml" {
			body = `<sslvpn><assigned-addr ipv6="2001:db8::1/128"/></sslvpn>`
		}
		return &http.Response{StatusCode: http.StatusOK, Status: "200 OK", Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body)), Request: r}, nil
	})
	client, err := NewClient(ClientOptions{Gateway: "example.test"})
	if err != nil {
		t.Fatal(err)
	}
	client.http.Transport = transport
	config, err := client.NetworkConfig(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if config.IPv6 == nil {
		t.Fatal("IPv6 allocation was not parsed")
	}
}

func TestDebugTraceDoesNotExposeCookieValuesOrQueries(t *testing.T) {
	var trace bytes.Buffer
	client, err := NewClient(ClientOptions{Gateway: "example.test"})
	if err != nil {
		t.Fatal(err)
	}
	client.SetDebugWriter(&trace)
	client.tracef("GET %s; cookies: %s", redactPath("/remote/saml/auth_id?id=secret"), responseCookieMetadata([]*http.Cookie{{Name: "SVPNCOOKIE", Value: "must-not-appear", Path: "/remote"}}))
	if strings.Contains(trace.String(), "secret") || strings.Contains(trace.String(), "must-not-appear") {
		t.Fatalf("debug trace exposes a secret: %q", trace.String())
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
