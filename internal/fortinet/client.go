// Package fortinet implements the FortiGate SSL-VPN HTTPS control plane.
package fortinet

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/filippoferrazini/fortivpn-go/internal/network"
)

const userAgent = "fortivpn-go/0.1"

// ErrInvalidPassword is returned only by the traditional username/password
// authentication flow when FortiGate rejects the supplied credentials.
var ErrInvalidPassword = errors.New("Password errata")

var errSessionCookieMissing = errors.New("gateway did not issue an SVPNCOOKIE; authentication was rejected or requires an unsupported challenge")

type ClientOptions struct {
	Gateway  string
	Port     int
	Insecure bool
}

type Client struct {
	baseURL *url.URL
	http    *http.Client
	tls     *tls.Config
	debug   io.Writer
}

type HTTPStatusError struct {
	Method      string
	Path        string
	Status      string
	StatusCode  int
	CookieNames []string
}

func (e *HTTPStatusError) Error() string {
	if len(e.CookieNames) == 0 {
		return fmt.Sprintf("%s %s: gateway returned %s (no session cookie was sent)", e.Method, e.Path, e.Status)
	}
	return fmt.Sprintf("%s %s: gateway returned %s (sent cookie names: %s)", e.Method, e.Path, e.Status, strings.Join(e.CookieNames, ", "))
}

func NewClient(options ClientOptions) (*Client, error) {
	if options.Port < 0 || options.Port > 65535 {
		return nil, fmt.Errorf("invalid gateway port %d", options.Port)
	}
	rawGateway := strings.TrimSpace(options.Gateway)
	if rawGateway == "" {
		return nil, errors.New("gateway is required")
	}
	if !strings.Contains(rawGateway, "://") {
		rawGateway = "https://" + rawGateway
	}
	endpoint, err := url.Parse(rawGateway)
	if err != nil || endpoint.Scheme != "https" || endpoint.Hostname() == "" || endpoint.Path != "" && endpoint.Path != "/" {
		return nil, errors.New("gateway must be a hostname or an https URL without a path")
	}
	endpoint.Path = ""
	endpoint.RawQuery = ""
	endpoint.Fragment = ""
	if options.Port != 0 {
		endpoint.Host = endpoint.Hostname()
		endpoint.Host += ":" + strconv.Itoa(options.Port)
	}
	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, fmt.Errorf("create cookie jar: %w", err)
	}
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: options.Insecure} // #nosec G402 -- enabled only by explicit CLI option
	return &Client{
		baseURL: endpoint,
		tls:     tlsConfig,
		http: &http.Client{
			Jar: jar,
			Transport: &http.Transport{
				TLSClientConfig:    tlsConfig,
				DisableCompression: true,
				ForceAttemptHTTP2:  false,
				TLSNextProto:       make(map[string]func(string, *tls.Conn) http.RoundTripper),
			},
			Timeout: 30 * time.Second,
		},
	}, nil
}

func (c *Client) Gateway() string { return c.baseURL.Host }

// SetDebugWriter enables redacted control-plane diagnostics. It never writes
// credential, cookie, token, or query-string values.
func (c *Client) SetDebugWriter(writer io.Writer) { c.debug = writer }

func (c *Client) url(path string) string {
	endpoint := *c.baseURL
	requestURL, _ := url.Parse(path)
	endpoint.Path = requestURL.Path
	endpoint.RawQuery = requestURL.RawQuery
	return endpoint.String()
}

func (c *Client) get(ctx context.Context, path string) ([]byte, error) {
	return c.request(ctx, http.MethodGet, path, nil)
}

func (c *Client) postForm(ctx context.Context, path string, form url.Values) ([]byte, error) {
	return c.request(ctx, http.MethodPost, path, strings.NewReader(form.Encode()))
}

func (c *Client) request(ctx context.Context, method, path string, requestBody io.Reader) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, method, c.url(path), requestBody)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", userAgent)
	// Fortinet-compatible clients include the explicit HTTPS port in Host, even
	// for 443. Some multi-portal FortiGate deployments use this while selecting
	// the SSL-VPN handler.
	req.Host = c.gatewayHostHeader()
	// FortiGate's SSL-VPN handler is stricter than a general web server. These
	// headers match the HTTP/1.1 profile used by Fortinet-compatible clients.
	req.Header.Set("Accept", "*/*")
	req.Header.Set("Accept-Encoding", "identity")
	req.Header.Set("Pragma", "no-cache")
	req.Header.Set("Cache-Control", "no-store, no-cache, must-revalidate")
	req.Header.Set("If-Modified-Since", "Sat, 1 Jan 2000 00:00:00 GMT")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	// The FortiGate control-plane implementation expects an explicit zero-length
	// body for GET requests as well as POST requests.
	req.Header.Set("Content-Length", strconv.FormatInt(req.ContentLength, 10))
	cookieNames := requestCookieNames(c.http.Jar.Cookies(req.URL))
	c.tracef("%s %s; sent cookies: %s", method, redactPath(path), displayCookieNames(cookieNames))
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%s %s: %w", method, path, err)
	}
	defer resp.Body.Close()
	c.tracef("%s %s -> %s; received cookies: %s", method, redactPath(path), resp.Status, responseCookieMetadata(resp.Cookies()))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		return nil, &HTTPStatusError{Method: method, Path: path, Status: resp.Status, StatusCode: resp.StatusCode, CookieNames: cookieNames}
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	return body, nil
}

func (c *Client) gatewayHostHeader() string {
	port := c.baseURL.Port()
	if port == "" {
		port = "443"
	}
	return net.JoinHostPort(c.baseURL.Hostname(), port)
}

func (c *Client) tracef(format string, args ...any) {
	if c.debug != nil {
		fmt.Fprintf(c.debug, "debug: "+format+"\n", args...)
	}
}

func (c *Client) traceRouteElements(data []byte) {
	if c.debug == nil {
		return
	}
	decoder := xml.NewDecoder(bytes.NewReader(data))
	for {
		token, err := decoder.Token()
		if err == io.EOF {
			return
		}
		if err != nil {
			c.tracef("cannot decode route metadata: %v", err)
			return
		}
		element, ok := token.(xml.StartElement)
		if !ok {
			continue
		}
		name := strings.ToLower(element.Name.Local)
		if name != "addr" && !strings.Contains(name, "route") && !strings.Contains(name, "tunnel") {
			continue
		}
		attributes := make([]string, 0, len(element.Attr))
		for _, attr := range element.Attr {
			key := strings.ToLower(attr.Name.Local)
			switch key {
			case "ip", "ipv4", "ipv6", "ip6", "dest", "destination", "mask", "netmask", "prefix", "prefix-len", "prefixlen", "gateway", "gw", "negate":
				attributes = append(attributes, key+"="+attr.Value)
			}
		}
		sort.Strings(attributes)
		c.tracef("network XML <%s %s>", name, strings.Join(attributes, " "))
	}
}

func redactPath(path string) string {
	endpoint, err := url.Parse(path)
	if err != nil || endpoint.Path == "" {
		return "<invalid path>"
	}
	return endpoint.EscapedPath()
}

func displayCookieNames(names []string) string {
	if len(names) == 0 {
		return "none"
	}
	return strings.Join(names, ", ")
}

func responseCookieMetadata(cookies []*http.Cookie) string {
	if len(cookies) == 0 {
		return "none"
	}
	metadata := make([]string, 0, len(cookies))
	for _, cookie := range cookies {
		path := cookie.Path
		if path == "" {
			path = "<default>"
		}
		metadata = append(metadata, cookie.Name+"(path="+path+")")
	}
	sort.Strings(metadata)
	return strings.Join(metadata, ", ")
}

func requestCookieNames(cookies []*http.Cookie) []string {
	unique := make(map[string]struct{}, len(cookies))
	for _, cookie := range cookies {
		unique[cookie.Name] = struct{}{}
	}
	names := make([]string, 0, len(unique))
	for name := range unique {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func (c *Client) hasSessionCookie() bool {
	// CookieJar applies RFC path matching. FortiGate commonly scopes its
	// session cookies to /remote, while baseURL points to /. Query the same
	// control-plane path where the cookie will actually be sent.
	remoteURL, err := url.Parse(c.url("/remote/"))
	if err != nil {
		return false
	}
	for _, cookie := range c.http.Jar.Cookies(remoteURL) {
		if cookie.Name == "SVPNCOOKIE" && cookie.Value != "" {
			return true
		}
	}
	return false
}

// AuthenticateSAML exchanges the browser callback ID for an authenticated
// FortiGate session. The cookie is retained by this Client's in-memory jar.
func (c *Client) AuthenticateSAML(ctx context.Context, sessionID string) error {
	if strings.TrimSpace(sessionID) == "" {
		return errors.New("empty SAML session ID")
	}
	response, err := c.get(ctx, "/remote/saml/auth_id?id="+url.QueryEscape(sessionID))
	if err != nil {
		return err
	}
	return c.completeAuthentication(ctx, response)
}

// AuthenticatePassword performs the traditional FortiGate form login. Neither
// credentials nor the returned session cookie are written to logs or disk.
func (c *Client) AuthenticatePassword(ctx context.Context, username, password, realm string) error {
	if strings.TrimSpace(username) == "" || password == "" {
		return errors.New("username and password are required")
	}
	form := url.Values{
		"username":   {username},
		"credential": {password},
		"realm":      {realm},
		"ajax":       {"1"},
	}
	response, err := c.postForm(ctx, "/remote/logincheck", form)
	if err != nil {
		var statusErr *HTTPStatusError
		if errors.As(err, &statusErr) && (statusErr.StatusCode == http.StatusUnauthorized || statusErr.StatusCode == http.StatusForbidden) {
			c.tracef("password authentication failed: %v", err)
			return ErrInvalidPassword
		}
		return err
	}
	if err := c.completeAuthentication(ctx, response); err != nil {
		if errors.Is(err, errSessionCookieMissing) {
			return ErrInvalidPassword
		}
		return err
	}
	return nil
}

// completeAuthentication follows the application-level host-check redirect
// returned by newer FortiGate releases. http.Client only follows HTTP 3xx
// redirects; this response is a `redir=` value in a successful response body.
func (c *Client) completeAuthentication(ctx context.Context, response []byte) error {
	for range 4 {
		if c.hasSessionCookie() {
			return nil
		}
		nextPath, ok := authRedirectPath(response)
		if !ok {
			break
		}
		var err error
		response, err = c.get(ctx, nextPath)
		if err != nil {
			return err
		}
	}
	if c.hasSessionCookie() {
		return nil
	}
	c.tracef("%v", errSessionCookieMissing)
	return errSessionCookieMissing
}

func authRedirectPath(response []byte) (string, bool) {
	const key = "redir="
	body := string(response)
	start := strings.Index(body, key)
	if start < 0 {
		return "", false
	}
	value := body[start+len(key):]
	if end := strings.IndexAny(value, "\r\n\t <\""); end >= 0 {
		value = value[:end]
	}
	value = strings.TrimRight(value, ",;")
	decoded, err := url.QueryUnescape(value)
	if err != nil {
		return "", false
	}
	endpoint, err := url.Parse(decoded)
	if err != nil || endpoint.IsAbs() || endpoint.Host != "" || !strings.HasPrefix(endpoint.Path, "/remote/") {
		return "", false
	}
	return endpoint.RequestURI(), true
}

// NetworkConfig requests a VPN allocation then obtains the best available XML
// configuration. No TUN interface, routes, or DNS are changed by this method.
func (c *Client) NetworkConfig(ctx context.Context) (*network.Config, error) {
	return c.NetworkConfigForIPMode(ctx, network.IPModeAuto)
}

// NetworkConfigForIPMode requests a VPN allocation and restricts the result to
// one IP family when requested. Auto tries the dual-stack endpoint first and
// falls back to the legacy single-stack endpoint for older FortiGates.
func (c *Client) NetworkConfigForIPMode(ctx context.Context, mode network.IPMode) (*network.Config, error) {
	if _, err := c.get(ctx, "/remote/index"); err != nil {
		var statusErr *HTTPStatusError
		if !errors.As(err, &statusErr) || statusErr.StatusCode != http.StatusForbidden {
			return nil, err
		}
		// Tunnel-only portals can deny the web-mode index endpoint while still
		// permitting the native FortiGate tunnel allocation endpoint.
		c.tracef("GET /remote/index is forbidden; trying tunnel allocation directly")
	}
	if _, err := c.get(ctx, "/remote/fortisslvpn"); err != nil {
		return nil, err
	}
	path := "/remote/fortisslvpn_xml?dual_stack=1"
	if mode == network.IPModeIPv4 {
		path = "/remote/fortisslvpn_xml"
	}
	xmlConfig, err := c.get(ctx, path)
	if err != nil && mode != network.IPModeDualStack && path != "/remote/fortisslvpn_xml" {
		c.tracef("GET /remote/fortisslvpn_xml?dual_stack=1 failed; trying legacy allocation")
		xmlConfig, err = c.get(ctx, "/remote/fortisslvpn_xml")
	}
	if err != nil {
		return nil, err
	}
	c.traceRouteElements(xmlConfig)
	config, err := ParseNetworkConfig(xmlConfig)
	if err != nil {
		return nil, fmt.Errorf("parse FortiGate network configuration: %w", err)
	}
	selected, err := config.ForIPMode(mode)
	if err != nil {
		return nil, fmt.Errorf("select FortiGate IP mode: %w", err)
	}
	return selected, nil
}
