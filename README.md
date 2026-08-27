# fortivpn-go

Native Go client for the Fortinet SSL-VPN control plane. Milestone 1 implements
SAML browser authentication and reads the network settings allocated by the
gateway; it does not yet create a TUN device or change routes/DNS.

```sh
go run ./cmd/fortivpn inspect vpn.example.com --saml --realm employees
```

For gateways using the legacy form login instead of SAML:

```sh
go run ./cmd/fortivpn inspect vpn.example.com --username alice --password '…' --realm employees
```

`--password` is accepted for automation but can be visible in shell history and
process inspection. A non-argument secret input will be added before `connect`.

The command starts a temporary listener bound only to `127.0.0.1` on an
available port, opens the system browser, and waits up to five minutes for the
SAML callback. The session cookie is held only in the process cookie jar and is
never printed. TLS verification is enabled by default. `--insecure` exists only
for explicit diagnostic use.
