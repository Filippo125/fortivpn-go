# Esempio di laboratorio IPsec IKEv2 su FortiGate

Data: 2026-09-06. Collegato al [piano di migrazione](ipsec-migration.md).

> Tutti gli indirizzi appartengono ai blocchi di documentazione RFC 5737 e
> RFC 3849. Nomi di host, VDOM, interfacce, utenti, gruppi e policy sono
> esempi sintetici e non identificano alcun ambiente reale.

Aggiornamento TCP del 2026-09-08: credenziali di laboratorio rigenerate,
Phase 1 `udp-fallback-tcp` e servizio TCP/4500 `ipsec-lab-tcp` aggiunto alla
policy di ingresso. I blocchi sotto descrivono il profilo UDP iniziale; applicare anche questo
delta per riprodurre lo stato corrente. Vedere [reference macOS/TCP](ipsec-macos-tcp.md).

## Stato e obiettivo

Il modello rappresenta un FortiGate di laboratorio con FortiOS 7.4.x e VDOM
`lab-vdom`. Oggetti, Phase 1/2, policy e route sono esempi riproducibili; non
sono un'esportazione della configurazione di un firewall. Il backend Go
strongSwan/VICI ha superato i test di interoperabilità su Linux in Docker:
vedere [risultati e limiti](ipsec-test-results.md).

Il tunnel risulta `down`, con `child_num=0`, `rxp=0` e `txp=0`: nessun client
IPsec era collegato al termine della configurazione. Questo documento descrive
lo stato applicato, con password e PSK sostituite da placeholder.
Obiettivo: VPN dial-up IKEv2 su UDP con PSK, utente locale via EAP,
assegnazione IPv4/IPv6 e accesso split alle reti di laboratorio. Il gateway
esterno resta IPv4 anche quando il tunnel trasporta IPv6.

Il client `fortivpn-go` espone il comando sperimentale `fortivpn ipsec connect`.
Prerequisiti, credenziali e comandi sono descritti nella
[reference del backend](ipsec-backend.md).
TCP, SAML e MFA saranno oggetto di prove successive.

## Dati dell’installazione

Dallo screenshot del firewall:

- Interfaccia: `ipsec-loopback`.
- Tipo: loopback.
- IPv4: `192.0.2.10/32`.
- La SSL-VPN è già associata a questa interfaccia, secondo quanto indicato
  dall'utente.

| Impostazione | Valore applicato                                                       |
|---|------------------------------------------------------------------------|
| Firewall / VDOM | `lab-fgt-1` / `lab-vdom`                                              |
| Versione | FortiOS 7.4.x                                               |
| Endpoint | `192.0.2.10`, loopback `ipsec-loopback`                                   |
| Ingresso Internet | `wan`                                                                  |
| LAN IPv4 | `lab-lan4`, `198.51.100.0/24`                                             |
| LAN IPv6 | `lab-lan6`, `2001:db8:100::/64`                                    |
| Pool VPN IPv4 | `203.0.113.10`–`203.0.113.20`, assegnazione `/32`                    |
| Pool VPN IPv6 | `2001:db8:200::10`–`2001:db8:200::20`, assegnazione `/128` |
| Utente / gruppo | `vpn-test-user` / `vpn-test-users`                                   |
| Segreti nei comandi | `<PASSWORD_UTENTE>` e `<PSK_CASUALE>` sono placeholder                 |

Le subnet dei pool devono essere libere e distinte dalle LAN, dalle altre VPN
e dalle reti locali dei client. Sostituire coerentemente ogni occorrenza se
si scelgono indirizzi diversi. Le subnet LAN indicate devono esistere realmente:
il modello non assegna indirizzi alla LAN né agli host.

I blocchi CLI seguenti sono un modello da adattare, non uno script da eseguire
integralmente. In particolare, non applicare i placeholder dei segreti e
verificare sempre gli identificativi assegnati dal proprio FortiGate.

Password e PSK devono essere generate per il proprio laboratorio, conservate
fuori dal repository in un file con permessi `0600` e ruotate al termine dei
test. Non usare nei comandi valori provenienti da ambienti reali.

L'esempio assume che eventuali pool SSL-VPN siano distinti dai nuovi pool
IPsec e che la configurazione SSL-VPN non venga modificata.

L'ingresso IPsec conserva un insieme di sorgenti già autorizzate:
`trusted-source-1`, `trusted-source-2`, `trusted-source-3`, `allowed-geo-1`,
`allowed-geo-2`, `allowed-geo-3`. La policy IKE/ESP deve precedere eventuali
regole confliggenti senza ampliare la lista delle sorgenti ammesse.

## 1. Utente e oggetti di rete

```text
config user local
    edit "vpn-test-user"
        set type password
        set passwd "LAB_USER_PASSWORD"
    next
end

config user group
    edit "vpn-test-users"
        set member "vpn-test-user"
    next
end

config firewall address
    edit "ipsec-lab-public"
        set subnet 192.0.2.10 255.255.255.255
    next
    edit "ipsec-lab-pool4"
        set type iprange
        set start-ip 203.0.113.10
        set end-ip 203.0.113.20
    next
    edit "ipsec-lab-lan4"
        set subnet 198.51.100.0 255.255.255.0
    next
end

config firewall address6
    edit "ipsec-lab-pool6"
        set ip6 2001:db8:200::/64
    next
    edit "ipsec-lab-lan6"
        set ip6 2001:db8:100::/64
    next
end

config firewall service custom
    edit "ipsec-lab-udp"
        set udp-portrange 500 4500
    next
end
```

## 2. Phase 1: autenticazione e allocazione dual-stack

```text
config vpn ipsec phase1-interface
    edit "ipsec-lab"
        set type dynamic
        set interface "ipsec-loopback"
        set local-gw 192.0.2.10
        set ike-version 2
        set peertype any
        set net-device disable

        set authmethod psk
        set psksecret "<PSK_CASUALE>"
        set eap enable
        set eap-identity send-request
        set authusrgrp "vpn-test-users"

        set proposal aes256-sha256
        set dhgrp 14
        set keylife 28800

        set transport udp
        set nattraversal enable
        set dpd on-idle
        set dpd-retryinterval 10
        set dpd-retrycount 3

        set mode-cfg enable
        set assign-ip-from range
        set ipv4-start-ip 203.0.113.10
        set ipv4-end-ip 203.0.113.20
        set ipv4-netmask 255.255.255.255
        set ipv4-split-include "ipsec-lab-lan4"

        set ipv6-start-ip 2001:db8:200::10
        set ipv6-end-ip 2001:db8:200::20
        set ipv6-prefix 128
        set ipv6-split-include "ipsec-lab-lan6"

        set dns-mode auto
        set add-route disable
    next
end
```

`dns-mode auto` comunica i DNS di sistema del FortiGate. Per le prime prove
usare direttamente gli indirizzi degli host. Nel piano del client, i DNS
rimangono display-only fino a un'integrazione reversibile dedicata.

La PSK autentica il gateway nel profilo iniziale; EAP autentica l'utente.
Questo profilo non permette di verificare CA, certificato e identità certificata
del server: servirà un successivo profilo con autenticazione a certificato.

## 3. Phase 2: IPv4 e IPv6

I selettori ampi permettono la negoziazione con il client. L'accesso effettivo
è limitato dalle policy e dalle reti split. L'aggiunta automatica delle route
è disabilitata; le route per i pool sono definite nel blocco 5.

```text
config vpn ipsec phase2-interface
    edit "ipsec-lab-v4"
        set phase1name "ipsec-lab"
        set proposal aes256-sha256
        set pfs enable
        set dhgrp 14
        set keylifeseconds 3600
        set src-subnet 0.0.0.0 0.0.0.0
        set dst-subnet 0.0.0.0 0.0.0.0
        set add-route disable
    next
    edit "ipsec-lab-v6"
        set phase1name "ipsec-lab"
        set proposal aes256-sha256
        set pfs enable
        set dhgrp 14
        set keylifeseconds 3600
        set src-addr-type subnet6
        set dst-addr-type subnet6
        set src-subnet6 ::/0
        set dst-subnet6 ::/0
        set add-route disable
    next
end
```

## 4. Policy Internet → loopback e tunnel → LAN

La terminazione su loopback richiede una policy dall'interfaccia Internet alla
loopback. UDP 500/4500 copre IKE e NAT-T; ESP permette il traffico senza NAT-T.
Anche il percorso a monte deve consentire questi protocolli fino al FortiGate.

```text
config firewall policy
    edit 0
        set name "ipsec-lab-ingress"
        set srcintf "wan"
        set dstintf "ipsec-loopback"
        set srcaddr "trusted-source-1" "trusted-source-2" "trusted-source-3" "allowed-geo-1" "allowed-geo-2" "allowed-geo-3"
        set dstaddr "ipsec-lab-public"
        set action accept
        set schedule "always"
        set service "ipsec-lab-udp" "ESP"
        set nat disable
        set logtraffic all
    next

    edit 0
        set name "ipsec-lab-to-lan4"
        set srcintf "ipsec-lab"
        set dstintf "lab-lan4"
        set srcaddr "ipsec-lab-pool4"
        set dstaddr "ipsec-lab-lan4"
        set action accept
        set schedule "always"
        set service "ALL"
        set nat disable
        set logtraffic all
    next

    edit 0
        set name "ipsec-lab-to-lan6"
        set srcintf "ipsec-lab"
        set dstintf "lab-lan6"
        set srcaddr6 "ipsec-lab-pool6"
        set dstaddr6 "ipsec-lab-lan6"
        set action accept
        set schedule "always"
        set service "ALL"
        set nat disable
        set logtraffic all
    next
end
```

`ALL` è limitato alle subnet di laboratorio indicate. Le risposte alle
connessioni iniziate dal client passano nelle stesse sessioni firewall.
Posizionare la policy di ingresso prima di eventuali regole confliggenti e le
policy verso le LAN prima del deny implicito. Il modello non aggiunge policy
per connessioni iniziate dalla LAN verso i client.

## 5. Route verso i pool VPN

```text
config router static
    edit 0
        set dst 203.0.113.0 255.255.255.0
        set device "ipsec-lab"
        set comment "IPsec lab client pool IPv4"
    next
end

config router static6
    edit 0
        set dst 2001:db8:200::/64
        set device "ipsec-lab"
        set comment "IPsec lab client pool IPv6"
    next
end
```

Se gli host LAN usano un altro router come gateway, anche quel router deve
instradare i pool VPN verso questo FortiGate. Queste route sono configurazione
persistente del laboratorio sul firewall; sono distinte dalle route temporanee
che il backend installerà e rimuoverà sul client.

## 6. Parametri da replicare nel prototipo client

| Parametro | Valore |
|---|---|
| Endpoint | `192.0.2.10` |
| Protocollo | IKEv2 |
| Trasporto | UDP 500, NAT-T UDP 4500 |
| Autenticazione | PSK + EAP con utente locale |
| Utente | `vpn-test-user` |
| Proposta IKE | AES256 / SHA256 / DH14 |
| Lifetime IKE | 28800 secondi |
| Proposta ESP | AES256 / SHA256 / PFS DH14 |
| Lifetime Phase 2 | 3600 secondi |
| Allocazione | IPv4 e IPv6 via Mode Config |
| Reti split | Le subnet LAN scelte nel modello |

Il metodo EAP effettivamente negoziato, le identità IKE e i selettori accettati
vanno registrati durante il prototipo. Non assumere che le sole opzioni del
FortiClient dimostrino compatibilità con il backend di terze parti.

## 7. Verifica

Se FortiOS rifiuta un comando, annotare versione ed errore e adattare il modello
prima di applicare i blocchi successivi. Un errore CLI può lasciare applicata
solo una parte della configurazione.

Durante il tentativo di connessione:

```text
diagnose vpn ike gateway list
diagnose vpn tunnel list name ipsec-lab
```

Per vedere l'arrivo di IKE e NAT-T; interrompere con Ctrl-C:

```text
diagnose sniffer packet any 'host 192.0.2.10 and (udp port 500 or udp port 4500)' 4 0 l
```

La cattura dimostra l'arrivo dei pacchetti, non l'avvenuta autenticazione o
il corretto inoltro del traffico protetto.

Sequenza delle prove:

1. Collegare un client da una rete esterna, inizialmente con IPv4.
2. Verificare l'indirizzo assegnato e la negoziazione IKE/ESP.
3. Raggiungere un host LAN con ping e una connessione TCP effettiva.
4. Verificare che Internet continui a usare il percorso precedente al tunnel.
5. Ripetere con allocazione dual-stack e traffico IPv6 verso un host LAN.
6. Provare da una rete con NAT e verificare l'uso di UDP 4500.
7. Disconnettere e verificare il cleanup delle risorse sul client.
8. Provare password e PSK errate, cancellazione del setup e perdita del peer.
9. Mantenere traffico durante un rekey Phase 2 e, successivamente, un rekey IKE.

## 8. Registro del laboratorio

Compilare senza includere password, PSK o chiavi private.

| Dato | Valore / risultato |
|---|---|
| Modello FortiGate | Appliance di laboratorio |
| Versione FortiOS e build | 7.4.x; annotare la build usata |
| VDOM | lab-vdom |
| Interfaccia/zona Internet | wan; default IPv4 via 192.0.2.1 |
| Interfaccia/zona LAN | IPv4: lab-lan4; IPv6: lab-lan6 |
| Presenza di NAT a monte / lato client | Client Docker/OrbStack; NAT-T verificato |
| Host di test IPv4 e IPv6 | 198.51.100.2; 2001:db8:100::2 (ICMP e TCP 22) |
| Sistema operativo client e versione | Linux in container; annotare architettura e versione |
| Backend client e versione | Go VICI; strongSwan 5.9.x; govici v0.8.2 |
| Identità IKE client e server | vpn-test-user; 192.0.2.10 |
| Metodo EAP negoziato | EAP-MSCHAPv2, peer autenticato con PSK |
| Indirizzi assegnati | 203.0.113.10/32; 2001:db8:200::10/128 |
| Selettori verificati | VIP locale; reti remote 198.51.100.0/24 e 2001:db8:100::/64 |
| Traffico IPv4 / IPv6 / NAT-T | Superato |
| Cleanup / perdita peer / rekey | Superato; rekey IKE/ESP esplicito, soak test pendente |
| ID delle tre policy create | Assegnati dal FortiGate del laboratorio |
| ID delle route IPv4 e IPv6 create | Assegnati dal FortiGate del laboratorio |

## Fonti

Riferimenti consultati nella preparazione del modello il 2026-09-06. Descrivono
il comportamento Fortinet; non costituiscono una verifica del nostro backend.

- [IKEv2 con utenti locali ed EAP](https://community.fortinet.com/t5/FortiClient/Technical-Tip-How-to-configure-IPsec-VPN-Tunnel-using-IKE-v2/ta-p/196140).
- [IPsec su loopback e policy d'ingresso](https://community.fortinet.com/fortigate-3/technical-tip-ipsec-between-2-fortigates-using-a-loopback-interface-183454).
- [Assegnazione dual-stack e Phase 2 IPv6](https://docs.fortinet.com/document/fortigate/7.6.3/administration-guide/4729).
- [CLI Phase 1 e parametri IPv6](https://docs.fortinet.com/document/fortigate/7.6.5/cli-reference/305883427/config-vpn-ipsec-phase1-interface).
- [Policy IPv6 e trasporto su IPv4](https://docs.fortinet.com/document/fortigate/7.6.3/administration-guide/906628/site-to-site-ipv6-over-ipv4-vpn-example).
