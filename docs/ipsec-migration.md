> Update 2026-09-08: Go TCP framing adapter and a native macOS userspace-ESP
> runtime build are implemented. Seven TCP gateway scenarios pass in Linux
> with external UDP blocked. Native macOS tunnel/routing validation is pending
> administrative execution. See [macOS/TCP](ipsec-macos-tcp.md).

# IPsec migration plan

Status: session separation implemented; an experimental strongSwan/VICI
IPsec backend is implemented and tested against the lab gateway on Linux.
Native macOS interoperability remains pending. WebSocket transport is deferred.

## Implementation progress (2026-09-06)

The backend-independent work in delivery step 2 is implemented ahead of the
step 1 gateway prototype:

- `internal/session` defines setup, negotiated session information, runtime,
  and idempotent teardown without requiring a raw-packet interface.
- `internal/sslvpn` owns authentication, allocation, transport discovery, TUN
  setup, and route cleanup. The CLI delegates inspect, probe, and connect to it;
  configuration precedence, password input, and displayed diagnostics remain
  in the CLI.
- Connection setup now observes Ctrl-C/SIGTERM as well as its timeout. Its
  timeout is released after setup and does not limit the active session.
- Lifecycle tests cover setup failures, cancellation, peer disconnect, engine
  startup errors, concurrent close, and routes-before-interface cleanup.
  Existing SSL-VPN tests and the race detector pass on the macOS development
  host. Linux/amd64 packages and test binaries cross-compile; Linux runtime
  and real-gateway tests remain pending.

Step 1 has Linux prototype evidence from an authorized FortiOS 7.4.x lab,
PSK + EAP-MSCHAPv2, IPv4/IPv6 allocation and protected ICMP/TCP traffic over
NAT-T. The experimental `fortivpn ipsec connect` command uses a dedicated
strongSwan daemon via VICI. Native macOS tests remain pending, so the backend
decision is provisional for the cross-platform release. See the
[backend notes and reproducible tests](ipsec-backend.md).

The stable `--protocol`/INI integration in step 3 is still deferred. Existing
SSL-VPN options are unchanged; the experimental command uses separate
credential and identity inputs. TCP, SAML, certificates and operational soak
tests remain pending.

## Motivation and scope

Fortinet replaced SSL-VPN tunnel mode with IPsec in FortiOS 7.6.3. Existing
deployments must migrate their gateway configuration before upgrading; adding
client support alone cannot perform that migration. See the official
[migration guide](https://docs.fortinet.com/document/fortigate/7.6.0/new-features/155142/migration-from-ssl-vpn-tunnel-mode-to-ipsec-vpn-7-6-3).

Target IKEv2 on macOS and Linux, keeping SSL-VPN available for existing profiles.
First establish interoperability over UDP with NAT traversal. Then validate
IPsec over TCP, including TCP/443, and Fortinet SAML authentication. TCP/443
here carries IKE and encapsulated ESP, not HTTPS or WebSocket.

## Architecture

Introduce a protocol-level session boundary above authentication, allocation,
and packet forwarding. A session owns connection setup, negotiated network
configuration, lifetime, and cleanup. Keep protocol-specific credentials and
authentication results within their backend.

The current `internal/auth.Authenticator` accepts `*fortinet.Client` and returns
an SSL-VPN session cookie; it must not be reused as an IPsec authentication
contract. Browser-launch helpers may be shared, but the SSL-VPN callback,
SVPNCOOKIE, and realm semantics must not be assumed to apply to IPsec.

Reuse `internal/network.Config` for normalized addresses, routes, DNS, and MTU
where applicable. IPsec obtains configuration through its negotiation/backend,
not FortiGate SSL-VPN XML. Keep SSL-VPN tunnel-method discovery protocol-local.

Retain `internal/tunnel.Tunnel` and `PacketEngine` for transports that expose raw
IP packets. A kernel or OS-managed IPsec backend may own its data plane and
interface, so do not force it through the existing TUN packet-copy loop. Define
one owner for routes, interface state, and teardown for each backend.

Prefer an established IKEv2/IPsec implementation over writing a new IKE and ESP
stack. Select the backend only after a bounded interoperability prototype.
Evaluate Linux daemon integration and macOS system or packaged-daemon options
for authentication support, TCP encapsulation, privileges, distribution,
licensing, and reliable cleanup. A native Go implementation remains an option
only if a suitable maintained implementation satisfies those requirements.

## Delivery sequence

1. **Gateway inventory and backend prototype.** Record actual FortiOS versions,
   IKE identities, authentication method, trust roots, proposals, traffic
   selectors, assigned address families, UDP/TCP ports, and any Fortinet network
   ID. Obtain a test profile and prove an IKEv2 connection and protected traffic
   on each target OS. Deliver a backend decision and compatibility matrix.
2. **Session separation.** Move SSL-VPN orchestration from the CLI behind the
   session boundary without changing its behavior. Preserve INI/CLI precedence,
   password handling, diagnostics, cancellation, and route cleanup.
3. **Explicit protocol selection and UDP MVP.** Add `protocol = sslvpn|ipsec`
   and `--protocol` when the IPsec backend works. Keep `sslvpn` as the default
   for existing configurations. Introduce protocol-specific port and identity
   settings; do not reinterpret today's SSL-VPN `port`, `realm`, or `insecure`
   options as IPsec settings. Support one verified authentication profile,
   IPv4 allocation, split routes, NAT traversal, and deterministic disconnect.
4. **Authentication and TCP compatibility.** Validate the required EAP or
   certificate profiles, MFA, Fortinet SAML, and TCP/443 with the selected
   backend and gateway versions. Treat SAML and TCP as separate capabilities;
   FortiClient support does not establish third-party backend compatibility.
5. **Operational completeness.** Verify rekeying, dead-peer detection,
   reconnect, sleep/wake, network changes, IPv6/dual-stack, and negotiated
   traffic selectors. Keep DNS display-only until a separate reversible DNS
   integration is implemented. Report unsupported requested capabilities
   explicitly rather than silently dropping them.
6. **Migration release.** Publish tested OS/backend/FortiOS/authentication
   combinations, installation prerequisites, and working profile examples.
   Switch a deployment to IPsec only after its gateway and client checks pass.

Do not automatically retry SSL-VPN after IPsec authentication, certificate, or
negotiation failures. Any UDP-to-TCP fallback stays within IPsec, is explicitly
configured, and requires proven backend support. No new configuration keys in
this plan are accepted by the current release.

## Acceptance checks

- Existing SSL-VPN tests pass after the session refactor; legacy profiles keep
  their behavior.
- Integration tests demonstrate negotiated addresses and actual protected
  traffic on macOS and Linux, including NAT traversal and split routing.
- Invalid server identity, untrusted certificates, wrong credentials, and
  unsupported proposals fail clearly without exposing secrets in diagnostics.
- Cancellation, partial setup failure, peer loss, and normal disconnect remove
  only session-owned state; gateway reachability survives route installation.
- Rekey tests run across an SA lifetime without losing the working connection.
- TCP, SAML/MFA, and IPv6 are advertised only after gateway-backed tests; unit
  tests alone are insufficient evidence of Fortinet interoperability.

## Deployment and rollback

Create and test an IKEv2 gateway profile while SSL-VPN is still available, where
the installed firmware permits it. Match users/groups, trust, pools, routes,
DNS, and firewall policies, then pilot a separate IPsec client profile. Keep
the previous SSL-VPN profile during this coexistence period.

After upgrading to firmware that removes SSL-VPN tunnel mode, restoring the old
client profile is not a rollback path. Before upgrading, the administrator must
have a tested IPsec access path and a gateway recovery procedure. This plan
does not change the gateway or schedule an upgrade.

## Protocol references

- [Fortinet migration guide](https://docs.fortinet.com/document/fortigate/7.6.0/new-features/155142/migration-from-ssl-vpn-tunnel-mode-to-ipsec-vpn-7-6-3)
- [FortiClient IPsec transport and network ID settings](https://docs.fortinet.com/document/forticlient/7.4.3/ems-administration-guide/952355)
- [FortiClient IKE and SAML settings](https://docs.fortinet.com/document/forticlient/7.4.3/xml-reference-guide/96295/ike-settings)

References reviewed on 2026-09-05. These describe Fortinet behavior; backend
compatibility remains to be tested against the actual deployment.
