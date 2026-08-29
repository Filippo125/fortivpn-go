# fortivpn-go

Native Go client for FortiGate SSL-VPN. It authenticates with SAML or with a
username and password, reads the FortiGate allocation, and on macOS can create
a native `utun` interface to forward the allocated IPv4 and/or IPv6 traffic.

## Requirements

- Go 1.25 or later to build from source.
- macOS for `tunnel connect` and `tun create`.
- Administrator privileges for commands that create `utun` or install routes.

## Authentication

### Username and password

For interactive use, pass only the username. The client asks for the password
without echoing it and prints one `*` for each typed character:

```sh
go run ./cmd/fortivpn inspect vpn.example.com --username alice
```

The prompt is:

```text
Insert VPN Password: ********
```

`--password` is available for automation but exposes the secret to shell
history and process inspection. For scripts, use `--password-stdin` instead:

```sh
printf '%s\n' "$VPN_PASSWORD" | go run ./cmd/fortivpn inspect vpn.example.com \
  --username alice --password-stdin
```

If FortiGate rejects a username/password login, the normal error is
`Password errata`. The protocol-level reason is available only with `--debug`;
cookie and credential values are never printed.

### SAML

```sh
go run ./cmd/fortivpn inspect vpn.example.com \
  --saml --realm employees --timeout 10m
```

On macOS, SAML opens Google Chrome by default. Select another browser with:

```sh
--browser default       # macOS default browser
--browser "Firefox"     # installed macOS application name
```

FortiGate redirects the completed SAML login to the fixed local callback URL
`http://127.0.0.1:8020/`. Keep the client process running until the callback.
Before Chrome opens, it prints:

```text
Waiting for SAML callback on http://127.0.0.1:8020/
```

If the browser reports `ERR_CONNECTION_REFUSED`, verify that this message is
still visible in the terminal and that no other process occupies port 8020:

```sh
lsof -nP -iTCP:8020 -sTCP:LISTEN
```

Do not use a short `--timeout` for SAML; the default is five minutes.

## Inspect the FortiGate allocation

`inspect` authenticates and prints the assigned addresses, DNS entries,
split-tunnel routes, MTU, and supported tunnel methods. It does not create an
interface or change the system network configuration.

```sh
go run ./cmd/fortivpn inspect vpn.example.com --username alice
```

## Connect the VPN

`tunnel probe` validates the authenticated FortiClient 7+
`/remote/sslvpn-tunnel2` endpoint without changing the local machine:

```sh
go run ./cmd/fortivpn tunnel probe vpn.example.com --username alice
```

`tunnel connect` creates a temporary native `utunN`, configures the allocated
addresses and MTU, installs the allocated split-tunnel routes, and forwards
packets until `Ctrl-C`:

```sh
sudo go run ./cmd/fortivpn tunnel connect vpn.example.com \
  --username alice --ip-mode auto
```

On shutdown, the client removes the routes it installed and closes the `utun`
interface. DNS servers and search domains returned by FortiGate are displayed
but deliberately not applied globally.

### IP mode

Use `--ip-mode` with `inspect`, `tunnel probe`, or `tunnel connect`.

| Mode | Behaviour |
| --- | --- |
| `auto` | Default. Keeps the allocation returned by FortiGate; falls back to the legacy XML endpoint when dual-stack is unsupported. |
| `ipv4` | Uses only the IPv4 address, DNS servers, and routes. |
| `ipv6` | Uses only the IPv6 address, DNS servers, and routes. |
| `dual` | Requires FortiGate to assign both IPv4 and IPv6. |

Examples:

```sh
sudo go run ./cmd/fortivpn tunnel connect vpn.example.com --username alice --ip-mode ipv4
sudo go run ./cmd/fortivpn tunnel connect vpn.example.com --username alice --ip-mode ipv6
```

## Native `utun` smoke test

Create an independent interface without contacting a gateway or installing
routes/DNS:

```sh
sudo go run ./cmd/fortivpn tun create \
  --ipv4 10.20.4.12/32 --ipv4-gateway 10.20.4.1 \
  --ipv6 2001:db8:1234::12/128 --mtu 1400
```

The interface remains active until `Ctrl-C`.

## Diagnostics and TLS

`--debug` prints redacted control-plane diagnostics, including endpoint paths,
HTTP status, and cookie names. It never prints passwords, cookie values,
tokens, or query-string values.

TLS certificate validation is enabled by default. `--insecure` disables it and
is intended only for controlled diagnostics.
