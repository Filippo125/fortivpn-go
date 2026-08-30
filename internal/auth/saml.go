package auth

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/Filippo125/fortivpn-go/internal/fortinet"
)

type SAMLAuthenticator struct {
	Realm              string
	OpenURL            func(string) error
	OnCallbackListener func(string)
}

// FortiGate installations commonly redirect SAML callbacks to this fixed
// loopback port even when a different local_port is supplied in the start URL.
const samlCallbackAddress = "127.0.0.1:8020"

func (a *SAMLAuthenticator) Authenticate(ctx context.Context, client *fortinet.Client) (*AuthResult, error) {
	listener, err := net.Listen("tcp4", samlCallbackAddress)
	if err != nil {
		return nil, fmt.Errorf("start SAML callback listener on %s: %w", samlCallbackAddress, err)
	}
	defer listener.Close()

	result := make(chan string, 1)
	server := &http.Server{
		ReadHeaderTimeout: 5 * time.Second,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodGet || r.URL.Path != "/" {
				http.NotFound(w, r)
				return
			}
			id := strings.TrimSpace(r.URL.Query().Get("id"))
			if id == "" || len(id) > 4096 {
				http.Error(w, "Invalid SAML callback.", http.StatusBadRequest)
				return
			}
			select {
			case result <- id:
				w.Header().Set("Content-Type", "text/html; charset=utf-8")
				fmt.Fprint(w, "<!doctype html><title>FortiVPN</title><p>Authentication complete. You can close this tab.</p>")
			default:
				http.Error(w, "SAML callback already received.", http.StatusConflict)
			}
		}),
	}
	serveResult := make(chan error, 1)
	serveDone := make(chan struct{})
	go func() {
		serveResult <- server.Serve(listener)
		close(serveDone)
	}()
	defer func() {
		_ = server.Shutdown(context.Background())
		<-serveDone
	}()
	callbackURL := "http://" + listener.Addr().String() + "/"
	if a.OnCallbackListener != nil {
		a.OnCallbackListener(callbackURL)
	}

	loginURL := url.URL{Scheme: "https", Host: client.Gateway(), Path: "/remote/saml/start"}
	query := loginURL.Query()
	query.Set("redirect", "1")
	if a.Realm != "" {
		query.Set("realm", a.Realm)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	query.Set("local_port", strconv.Itoa(port))
	loginURL.RawQuery = query.Encode()
	open := a.OpenURL
	if open == nil {
		open = OpenBrowser
	}
	if err := open(loginURL.String()); err != nil {
		return nil, fmt.Errorf("open SAML browser: %w", err)
	}

	select {
	case sessionID := <-result:
		if err := client.AuthenticateSAML(ctx, sessionID); err != nil {
			return nil, fmt.Errorf("complete SAML authentication: %w", err)
		}
		return &AuthResult{SessionID: Secret(sessionID)}, nil
	case err := <-serveResult:
		if err == nil || errors.Is(err, http.ErrServerClosed) {
			return nil, errors.New("SAML callback listener stopped before authentication completed")
		}
		return nil, fmt.Errorf("SAML callback listener stopped: %w", err)
	case <-ctx.Done():
		return nil, fmt.Errorf("wait for SAML callback: %w", ctx.Err())
	}
}

// OpenBrowser uses the operating system's standard URL handler.
func OpenBrowser(rawURL string) error {
	return OpenBrowserWith(rawURL, "default")
}

// OpenBrowserWith opens rawURL in the requested browser. On macOS, browser
// names are application names accepted by `open -a`; "chrome" is a convenient
// alias for Google Chrome. "default" uses the configured system browser.
func OpenBrowserWith(rawURL, browser string) error {
	if _, err := url.ParseRequestURI(rawURL); err != nil {
		return err
	}
	browser = strings.TrimSpace(browser)
	var command string
	var args []string
	switch runtime.GOOS {
	case "darwin":
		if strings.EqualFold(browser, "chrome") {
			browser = "Google Chrome"
		}
		if browser != "" && !strings.EqualFold(browser, "default") {
			command, args = "open", []string{"-a", browser, rawURL}
			if err := exec.Command(command, args...).Run(); err != nil {
				return fmt.Errorf("open %s: %w", browser, err)
			}
			return nil
		}
		command, args = "open", []string{rawURL}
	case "windows":
		command, args = "rundll32", []string{"url.dll,FileProtocolHandler", rawURL}
	default:
		command, args = "xdg-open", []string{rawURL}
	}
	return exec.Command(command, args...).Start()
}
