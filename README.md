# fortivpn-go

Native Go client for FortiGate SSL-VPN. It authenticates with SAML or with a
username and password, reads the FortiGate allocation, and on macOS or Linux
can create a native TUN interface to forward the allocated IPv4 and/or IPv6 traffic.

## Requirements

- Go 1.25 or later to build from source.
- macOS or Linux (Ubuntu 22.04+) for `tunnel connect` and `tun create`.
- On Ubuntu, the `iproute2` package and the `/dev/net/tun` device must be
  available (both are normally present on a standard installation).
- Administrator privileges for commands that create a TUN interface or install routes.

## Configuration file

Use a YAML or JSON file with `--config`. Settings are resolved in this order:
global values, group values, instance values, and finally command-line options.
Select an instance with `--instance gruppo\istanza`. If the file contains
exactly one instance, it is selected automatically; an instance without a
group uses its name alone.

```yaml
# ~/.config/fortivpn/config.yaml
globals:
  insecure: false
  ip_mode: auto
  timeout: 5m
  browser: default
  username: alice
  # password: your-password

groups:
  company:
    username: alice@company.example
    saml: true

instances:
  - name: production
    group: company
    gateway: vpn.example.com
    port: 443
    realm: employees

  - name: lab
    group: company
    gateway: vpn-lab.example.com
    insecure: true
    saml: false
    username: lab-user
```

For example:

```sh
go run ./cmd/fortivpn tunnel connect \
  --config ~/.config/fortivpn/config.yaml --instance 'company\production'
```

`globals` supports `insecure`, `ip_mode`, `timeout`, `browser`, `username`, and
`password`. Each entry in the `groups` dictionary supports the same values plus
`saml`. An instance supports all of those values plus `name`, `group`, `gateway`,
`port`, and `realm`. Field names and unknown values are checked strictly.

JSON uses the same structure and field names. Other formats, including INI,
are rejected.

A file containing a password at any level must be `0600` (for example,
`chmod 600 config.yaml`), or the program refuses to use it. An instance can
clear an inherited password with `password: ""`. `--password-stdin` overrides a
configured password; use `--saml=false` to override inherited SAML authentication.

### Adding an instance

Add an instance without editing the file manually:

```sh
fortivpn config add-instance \
  --config ~/.config/fortivpn/config.yaml \
  --instance 'company\disaster-recovery' \
  --gateway vpn-dr.example.com \
  --realm employees \
  --saml \
  --ip-mode dual
```

The group must already exist. The command rejects duplicate selectors and
invalid values, then replaces the JSON or YAML file atomically. It preserves
the file permissions; when `--password` is used it restricts them to `0600`.
All instance fields shown in the configuration example have corresponding
flags; boolean overrides also accept forms such as `--saml=false`.

### Shell completion

The generated completion reads `--config` and completes `--instance` with the
available `group\instance` selectors. Enable it for the current shell with one
of these commands:

```sh
# zsh
source <(fortivpn completion zsh)

# bash
source <(fortivpn completion bash)

# fish
fortivpn completion fish | source
```

For example, after typing `--instance comp<Tab>`, completion inserts the
shell-escaped form of `company\production`.

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

`tunnel connect` creates a temporary native TUN interface (`utunN` on macOS,
`tunN` on Linux), configures the allocated addresses and MTU, installs the
allocated split-tunnel routes, and forwards
packets until `Ctrl-C`:

```sh
sudo go run ./cmd/fortivpn tunnel connect vpn.example.com \
  --username alice --ip-mode auto
```

On shutdown, the client removes the routes it installed and closes the TUN
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

## Native TUN smoke test

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

## IPsec roadmap

IKEv2/IPsec is planned as the next protocol, with SSL-VPN retained for existing
deployments. IPsec is not implemented yet. See the [migration plan](docs/ipsec-migration.md)
for architecture, delivery stages, interoperability checks, and gateway migration
requirements. WebSocket transport is deferred in favor of this work.

## License

Copyright © 2026 Filippo Ferrazini. This project is licensed under the GNU
General Public License v3.0. See [LICENSE](LICENSE).

## IPsec sperimentale

È disponibile `fortivpn ipsec connect`, basato su un daemon strongSwan dedicato
controllato tramite VICI. Il prototipo Linux supporta il profilo di laboratorio
IKEv2 PSK + EAP-MSCHAPv2 su UDP/NAT-T con split routing IPv4/IPv6.
Il supporto macOS nativo e le funzionalità TCP/SAML restano da verificare.

Vedi [backend e istruzioni di test](docs/ipsec-backend.md) e
[configurazione del laboratorio](docs/ipsec-lab-reference.md).
Il comando è separato dalla configurazione SSL-VPN esistente.

Il trasporto IPsec TCP sperimentale e la build macOS nativa sono descritti nella
[reference macOS/TCP](docs/ipsec-macos-tcp.md). Il tunnel nativo deve ancora
superare il collaudo amministrativo sul Mac.
