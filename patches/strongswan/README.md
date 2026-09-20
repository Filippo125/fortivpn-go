# strongSwan patch provenance

These patches are applied to the strongSwan 5.9.14 source archive by
`scripts/patch-ipsec-macos.sh`.

## Upstream backports

- `0001-tun-ipv6.patch`: strongSwan commit
  [`fccc76449dc5f135147c6167739916408753f66b`](https://github.com/strongswan/strongswan/commit/fccc76449dc5f135147c6167739916408753f66b).
- `0002-close-ipv6-socket.patch`: strongSwan commit
  [`e1091327b5d7f6cc8ca58931c8dd9b48fc53d42e`](https://github.com/strongswan/strongswan/commit/e1091327b5d7f6cc8ca58931c8dd9b48fc53d42e).
- `0003-linux-ipv6.patch`: strongSwan commit
  [`ea569867d24376eb4059fcf1df93269cc37d6ff3`](https://github.com/strongswan/strongswan/commit/ea569867d24376eb4059fcf1df93269cc37d6ff3).
- `0004-pfroute-interface-gateway.patch`: strongSwan commit
  [`bf165afb780b7ba4edd2092b3348038c0a14b7ae`](https://github.com/strongswan/strongswan/commit/bf165afb780b7ba4edd2092b3348038c0a14b7ae).

The patch files retain the original commit authorship and messages.

## Local patch

- `0005-utun-ipv6-packet-protocol.patch` is maintained by fortivpn-go and has no
  upstream strongSwan commit. It selects the macOS utun packet header protocol
  from the IP version nibble so both IPv4 and IPv6 packets can be delivered.
