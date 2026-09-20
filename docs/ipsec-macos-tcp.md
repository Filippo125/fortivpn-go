# IPsec TCP e runtime macOS nativo

Runtime, CLI e credenziali devono risiedere in una cartella privata esclusa da
Git. Password e PSK del profilo di laboratorio vanno salvate in
`credentials.json` con permessi 0600. Lo script richiede esplicitamente runtime,
client, credenziali, identità remota e route, senza valori ambientali predefiniti:

```sh
sudo /path/to/fortivpn-go/scripts/run-ipsec-macos.sh \
  /private/runtime /private/fortivpn /private/credentials.json \
  vpn.example.test 198.51.100.0/24 2001:db8:100::/64
```

I percorsi riportati sotto sono placeholder e devono essere sostituiti con
directory private locali.

Stato del 2026-09-08: adattatore Go implementato; runtime strongSwan compilato
nativamente su macOS arm64. Test Go con race detector superati
sul Mac. Il collaudo del tunnel macOS con privilegi amministrativi è ancora
pendente: la compilazione e i test del trasporto non provano utun e routing.

## Architettura

```text
applicazioni → utun → strongSwan kernel-libipsec (ESP cifrato)
                            ↕ UDP solo su 127.0.0.1
                      adattatore Go RFC 9329
                            ↕ TCP/4500
                          FortiGate
```

Go aggiunge framing TCP ai datagrammi IKE/ESP già prodotti da strongSwan.
Il daemon continua a gestire autenticazione PSK + EAP-MSCHAPv2, chiavi, SA,
anti-replay, rekey e policy. Sul Mac `kernel-pfroute` gestisce la rete e
`kernel-libipsec` usa interfacce utun per IPv4/IPv6.

Il socket UDP locale è connesso a `127.0.0.1:4500`: accetta soltanto quel peer.
Il backend configura esplicitamente entrambi gli endpoint IKE sul loopback;
l'identità autenticata rimane quella del gateway reale. Non esiste fallback
esterno UDP. Un daemon dedicato è obbligatorio, senza altre sessioni o client.

Il framing usa il prefisso `IKETCP`, lunghezze a 16 bit comprensive dell'header,
letture complete e gestione dei record vuoti. La chiusura TCP provoca la
terminazione della sessione e il cleanup; non viene effettuata una riconnessione
trasparente. È un adattatore sperimentale per questo profilo, non una completa
implementazione di tutte le estensioni RFC 9329 (MOBIKE/redirect/TLS esclusi).

## Build macOS

Prerequisiti: Go, Command Line Tools Apple, un'installazione OpenSSL esistente.
Lo script non usa Homebrew per installare pacchetti e non installa servizi.
Richiede i sorgenti strongSwan **5.9.14**, già estratti, e una destinazione privata.
Il runtime è una build locale, non un bundle autonomo firmato/notarizzato.

Archivio upstream: `https://download.strongswan.org/strongswan-5.9.14.tar.bz2`.
SHA-256 verificato per la build:
`728027ddda4cb34c67c4cec97d3ddb8c274edfbabdaeecf7e74693b54fc33678`.

```sh
./scripts/build-ipsec-macos.sh /percorso/strongswan-5.9.14 /percorso/runtime
# Su Intel o con OpenSSL altrove, impostare OPENSSL_PREFIX al percorso corretto.
go build -o /percorso/fortivpn ./cmd/fortivpn
```

La build abilita ESP userspace, kernel-pfroute, VICI, socket-default, KDF,
OpenSSL ed EAP. Disabilita tutti i plugin predefiniti non esplicitamente scelti.
La configurazione generata usa il socket VICI `/percorso/runtime/run/charon.vici`.
L'intero percorso runtime deve essere privo di spazi o metacaratteri.

## Prova nativa nel laboratorio

Generare credenziali dedicate e salvarle fuori dal repository con permessi
`0600`. Usare percorsi privati scelti localmente; nessuna credenziale o
posizione reale deve essere inclusa nel repository.

La prova richiede sudo per creare interfacce e modificare le route; inserire
la password del Mac soltanto nel proprio Terminale. Nel workspace attuale:

```sh
sudo ./scripts/run-ipsec-macos.sh \
 /percorso/privato/runtime \
 /percorso/privato/fortivpn \
 /percorso/privato/credentials.json \
 vpn.example.test \
 198.51.100.0/24 \
 2001:db8:100::/64
```

Lo script avvia il daemon dedicato, limita il socket VICI al proprietario,
collega IPv4/IPv6 per 60 secondi e chiude i processi alla fine. Prima delle
prove di traffico controllare che le rotte verso gli host di test usino le
nuove utun, non un'eventuale SSL-VPN già collegata alle stesse reti.

Per l'uso manuale con daemon già avviato:

```sh
sudo /percorso/fortivpn ipsec connect \
 --socket /percorso/runtime/run/charon.vici \
 --credentials /percorso/privato/credentials.json \
 --remote-id 192.0.2.10 \
 --transport tcp --tcp-port 4500 --ip-mode dual \
 --route 198.51.100.0/24 --route 2001:db8:100::/64
```

## Risultati sul gateway

Nel container di collaudo il medesimo adattatore ha superato sette scenari:
IPv4, dual-stack, password errata, PSK errata, identità errata,
cancellazione e perdita sessione. Verificati ICMP/TCP verso gli host LAN,
route sul dispositivo ESP userspace, sostituzione delle SA IKE/ESP dopo rekey
e cleanup. Il test Linux non certifica il funzionamento delle utun macOS.

La prova riproducibile con UDP esterno bloccato nel solo container ha poi
superato gli stessi sette scenari:

```sh
./tests/integration/ipsec-tcp/run.sh \
  /percorso/privato/credentials.json \
  198.51.100.0/24 198.51.100.2 \
  2001:db8:100::/64 2001:db8:100::2
```

Il firewall usa TCP/4500 con il servizio `ipsec-lab-tcp` aggiunto alla policy
di ingresso, mantenendone le sorgenti ristrette. Il profilo `ipsec-lab` usa
`udp-fallback-tcp`, così rimane disponibile anche il backend UDP esistente.
La SSL-VPN continua a occupare TCP/443. Non è stato modificato il suo endpoint.

Restano aperti: verifica nativa del tunnel, collaudo macOS Intel, prestazioni,
soak test, sleep/wake, packaging e gestione del servizio privilegiato. DNS,
SAML/MFA, autenticazione a certificati e TCP con TLS non sono implementati.

## Fonti

- [RFC 9329, framing IKE/ESP su TCP](https://www.rfc-editor.org/rfc/rfc9329.html).
- [strongSwan kernel-libipsec e macOS](https://docs.strongswan.org/docs/latest/plugins/kernel-libipsec.html).
