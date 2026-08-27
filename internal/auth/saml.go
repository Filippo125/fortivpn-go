package auth

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/filippoferrazini/fortivpn-go/internal/fortinet"
)

type SAMLAuthenticator struct {
	Realm   string
	OpenURL func(string) error
}

func (a *SAMLAuthenticator) Authenticate(ctx context.Context, client *fortinet.Client) (*AuthResult, error) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("start SAML callback listener: %w", err)
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
	serveDone := make(chan struct{})
	go func() { _ = server.Serve(listener); close(serveDone) }()
	defer func() {
		_ = server.Shutdown(context.Background())
		<-serveDone
	}()

	loginURL := url.URL{Scheme: "https", Host: client.Gateway(), Path: "/remote/saml/start"}
	query := loginURL.Query()
	query.Set("redirect", "1")
	if a.Realm != "" {
		query.Set("realm", a.Realm)
	}
	query.Set("local_port", strings.Split(listener.Addr().String(), ":")[1])
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
	case <-ctx.Done():
		return nil, fmt.Errorf("wait for SAML callback: %w", ctx.Err())
	}
}

// OpenBrowser uses the operating system's standard URL handler.
func OpenBrowser(rawURL string) error {
	if _, err := url.ParseRequestURI(rawURL); err != nil {
		return err
	}
	var command string
	var args []string
	switch runtime.GOOS {
	case "darwin":
		command, args = "open", []string{rawURL}
	case "windows":
		command, args = "rundll32", []string{"url.dll,FileProtocolHandler", rawURL}
	default:
		command, args = "xdg-open", []string{rawURL}
	}
	return exec.Command(command, args...).Start()
}
