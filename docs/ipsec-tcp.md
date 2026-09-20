# Passaggio a IPsec su TCP

Verifica iniziale del 2026-09-07. **Aggiornamento 2026-09-08:** implementato
un adattatore Go TCP con strongSwan ESP userspace; test sul FortiGate superati
in Linux e runtime macOS compilato. La verifica nativa del tunnel resta pendente.
Vedere [implementazione e prova macOS](ipsec-macos-tcp.md). Le sezioni seguenti
conservano la valutazione iniziale, precedente alle modifiche del laboratorio.
I precedenti test TCP/22 erano traffico interno al tunnel IPsec su UDP: non
dimostravano il supporto di TCP come trasporto di IKE ed ESP.

## Stato verificato sul FortiGate

Lettura via SSH sul laboratorio, FortiOS 7.4.11:

| Impostazione | Valore |
|---|---|
| `system settings: ike-tcp-port` | 4500 |
| `vpn ssl settings: port` | 443 |
| `vpn ssl settings: port-precedence` | enable |
| `ipsec-lab: transport` | udp |

Non sono state apportate modifiche al firewall in questa verifica.
La porta 443 sull'indirizzo pubblico è già usata dalla SSL-VPN. Per il primo
test TCP scegliere 4500, oppure progettare un endpoint separato se è richiesta
specificamente la 443. La porta TCP IKE è un'impostazione del VDOM, non del
solo profilo: cambiarla può influire su altri tunnel.

## Vincolo del backend

Il daemon strongSwan 5.9.14 usato dal laboratorio non implementa
l'incapsulamento IKE/ESP su TCP. Il controllo VICI via TCP, ove configurato,
è un canale di gestione e non risolve questo requisito.

Libreswan implementa RFC 8229, ma la documentazione delle funzionalità EAP
non offre il client EAP-MSCHAPv2 richiesto dal profilo attuale. Non basta
sostituire l'eseguibile: occorrono un nuovo adapter, una scelta compatibile
dell'autenticazione e nuove prove. Non disabilitare EAP per aggirare il limite.

Per mantenere PSK + EAP-MSCHAPv2 serve un backend che supporti entrambi,
oppure un'estensione del trasporto strongSwan. Una prova Libreswan con
certificati sarebbe un profilo di autenticazione diverso, da progettare
separatamente. Il supporto TCP Fortinet, incluso `fortinet-esp`, richiede
verifica di interoperabilità: la sola presenza di RFC 8229 nel client non la
dimostra.

## Sequenza di implementazione e collaudo

1. Validare il backend TCP con l'autenticazione scelta su un profilo isolato.
2. Usare inizialmente TCP/4500 e conservare il profilo UDP come riferimento.
   Sulla policy d'ingresso autorizzare il servizio TCP della porta scelta con
   le stesse sorgenti ristrette del laboratorio. Verificare il framing
   standard/proprietario prima di scegliere `fortinet-esp`.
3. Implementare l'adapter dietro `session.Backend`, con scelta esplicita del
   trasporto, porta validata e nessun fallback silenzioso a UDP o SSL-VPN.
4. Ripetere autenticazione, IPv4/IPv6, traffico, rekey, perdita del peer e
   cleanup. Bloccare UDP nel solo container di test e osservare il flusso
   TCP esterno, per provare che anche IKE ed ESP usano TCP.
5. Migrare il profilo esistente soltanto dopo queste prove. TCP/443 non è
   necessariamente TLS/HTTPS e non garantisce il passaggio attraverso proxy
   o filtri che richiedono HTTPS.

Le opzioni FortiOS pertinenti sono `set transport tcp` in Phase 1 e
`set ike-tcp-port 4500` in `config system settings`. Non costituiscono una
configurazione completa e non sono state applicate: il client attuale
cesserebbe di collegarsi al profilo convertito.

## Fonti primarie

- [FortiOS 7.4.11: porta IKE TCP](https://docs.fortinet.com/document/fortigate/7.4.11/cli-reference/130421147/config-system-settings).
- [Fortinet: trasporto TCP e conflitti di porta](https://docs.fortinet.com/document/fortigate/7.4.2/administration-guide/351073/encapsulate-esp-packets-within-tcp-headers-new).
- [strongSwan: richiesta supporto RFC 8229](https://github.com/strongswan/strongswan/discussions/1566).
- [Libreswan: supporto TCP](https://github.com/libreswan/libreswan/wiki/RFC_8229_-_TCP_support_for_IKEv2_and_ESP).
- [Libreswan: standard EAP implementati](https://github.com/libreswan/libreswan/wiki/FAQ%3A-Implemented-Standards).
