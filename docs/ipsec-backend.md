# Backend IPsec sperimentale: strongSwan / VICI

## Stato

Il primo backend Go è implementato in `internal/ipsec`. Il comando utente
`fortivpn connect <istanza>` seleziona il backend tramite `protocol: ipsec`;
`fortivpn ipsec connect` resta disponibile come interfaccia avanzata. Le
istanze senza `protocol` continuano a usare SSL-VPN.

Il prototipo Linux ha superato autenticazione PSK + EAP-MSCHAPv2, allocazione
IPv4/IPv6, NAT-T e traffico verso il FortiGate di laboratorio. macOS nativo
rimane da provare: l'installazione di strongSwan e l'esecuzione tramite sudo
sul Mac non sono state autorizzate; i test sono avvenuti nel container Linux
su OrbStack. La compilazione per macOS non prova l'interoperabilità nativa.

## Scelta del backend

Per IPsec su TCP è disponibile l'[adattatore Go con runtime macOS](ipsec-macos-tcp.md),
che richiede strongSwan ESP userspace. Il daemon standard non implementa TCP
nativamente; TCP/443 è già occupato dalla SSL-VPN sul laboratorio.

strongSwan è il candidato adottato per il prototipo Linux dopo la prova con il
gateway. Il client Go usa `github.com/strongswan/govici v0.8.2` per controllare
un daemon `charon` dedicato tramite socket Unix. Non implementa IKE o ESP.

- Charon gestisce autenticazione, SA, indirizzi virtuali, policy IPsec e route.
- Il backend Go carica credenziali e connessioni con nomi casuali per sessione,
  avvia le CHILD_SA e ricava la configurazione dalle SA effettivamente installate.
- Ogni sessione rimuove esclusivamente le proprie SA, connessioni e credenziali.
  Il cleanup usa un contesto separato da quello cancellato del chiamante.
- Il backend richiede un daemon senza connessioni o credenziali VICI già caricate.
  Usare una sola sessione per daemon. Non collegarlo a un servizio strongSwan
  condiviso con altre VPN o gestito da altri processi.
- I plugin `resolve`, `osx-attr` e `updown` devono essere disabilitati: il
  preflight li controlla e rifiuta il daemon se presenti. Non viene integrato
  il DNS nel sistema e non vengono eseguiti script up/down.
- Il profilo richiede gateway IPv4, identità remota esplicita, EAP-MSCHAPv2,
  NAT-T e traffic selector restituiti dal gateway. TCP richiede
  `--transport tcp` e il runtime userspace dedicato; nessun fallback SSL-VPN.
- SAML/MFA, certificati, IPv6 come trasporto esterno e riconnessione
  automatica non sono implementati da questo backend.

strongSwan è distribuito sotto GPL-2.0-or-later; govici usa MIT. Il laboratorio
installa strongSwan dai pacchetti Alpine e comunica con il processo separato.
Distribuzione e gestione privilegi su macOS restano da definire prima di un
rilascio multipiattaforma.

## Uso

Serve un daemon dedicato con VICI, `eap-identity`, `eap-mschapv2` e il backend
kernel adatto alla piattaforma. Il socket Unix deve essere accessibile solo
agli utenti autorizzati a controllare la VPN. Per il laboratorio è disponibile
[la configurazione del daemon](../tests/integration/ipsec/strongswan.conf).

Usare la stessa configurazione JSON/YAML della SSL-VPN, con permessi `0600` e
fuori dal repository quando contiene `password` o `psk`:

```yaml
instances:
  - name: ipsec-lab
    gateway: 192.0.2.10
    protocol: ipsec
    remote_id: 192.0.2.10
    username: vpn-test-user
    password: PASSWORD_DI_LABORATORIO
    psk: PSK_DI_LABORATORIO
    saml: false
    ip_mode: dual
    transport: udp
```

```sh
fortivpn connect ipsec-lab --config /percorso/privato/fortivpn.yaml
```

`--socket` sceglie il socket VICI (default `/var/run/charon.vici`). `--timeout`
limita il setup (default 30s). `--duration 30s` disconnette automaticamente
30 secondi dopo il setup; altrimenti la sessione dura fino a Ctrl-C/SIGTERM.

La PSK e la password lette dalla configurazione non compaiono negli argomenti
del processo. Il precedente file JSON è ancora accettato tramite
`--credentials` per compatibilità. Le opzioni SSL-VPN `--realm`, `--port` e
`--insecure` non si applicano a questo comando; una configurazione che risolve
`saml: true` viene rifiutata esplicitamente. Il client propone selector ampi e
ricava le rotte dai `remote-ts` delle CHILD_SA installate, fino a un massimo di
32. Un selector `/0` è accettato come full tunnel. Le rotte non-default che
contengono il gateway e, con TCP, quelle che contengono il relay loopback
vengono rifiutate. In modalità dual il gateway deve installare una CHILD_SA per
entrambe le famiglie; un'allocazione o una CHILD_SA mancante causa il cleanup.

Il monitor verifica periodicamente che IKE e CHILD_SA siano presenti. Tre
rilevazioni consecutive incomplete producono un errore e la disconnessione;
questo margine consente le transizioni durante un rekey. Non è un meccanismo di
reconnect. SIGKILL, crash del daemon o perdita del socket durante il cleanup
richiedono la verifica manuale dello stato: usare il container dedicato per
le prove e distruggerlo al termine.

## Test riproducibili

Il [registro dei risultati](ipsec-test-results.md) distingue le prove eseguite
dalle verifiche ancora aperte.

Il gateway deve essere configurato secondo [la reference](ipsec-lab-reference.md).
I test contattano esclusivamente l'endpoint del file credenziali e gli host
LAN del laboratorio `198.51.100.2:22` e `[2001:db8:100::2]:22`, oltre a ICMP.
Se il laboratorio cambia, adattare le destinazioni nel test prima di eseguirlo.

```sh
# Test locali: non contattano il gateway senza la variabile opt-in.
go test -race ./...

# Test reali: Go + Docker; rete IPv6 e container dedicati temporanei.
./tests/integration/ipsec/run.sh \
  /percorso/privato/credentials.json \
  198.51.100.0/24 198.51.100.2 \
  2001:db8:100::/64 2001:db8:100::2
```

Lo script compila i test per l'architettura Docker, crea una rete dual-stack,
avvia charon con `NET_ADMIN` nel namespace del container e rimuove container
e rete all'uscita. Non usa `--privileged` né `--network host`.
La rete dual-stack è necessaria: sulla bridge Docker predefinita IPv6 può
rimanere disabilitato su `eth0`, impedendo l'installazione dell'indirizzo VPN.

Il Dockerfile usa Alpine; durante la validazione il pacchetto era strongSwan
5.9.x su Linux/arm64. I dettagli identificativi dell'host non sono registrati.

Le prove includono autenticazione valida ed errata, peer identity errata,
cancellazione del setup, IPv4/dual-stack, ICMP/TCP, rekey espliciti e perdita
della sessione. Verificano inoltre che SA, configurazioni VICI, credenziali,
indirizzi virtuali e route split siano rimossi. Un rekey esplicito non equivale
a un test attraverso l'intera lifetime: i soak test restano da eseguire.

## Riferimenti

- [strongSwan su macOS](https://docs.strongswan.org/docs/latest/os/macos.html).
- [Configurazione swanctl](https://docs.strongswan.org/docs/latest/swanctl/swanctlConf.html).
- [Protocollo VICI 5.9.14](https://github.com/strongswan/strongswan/blob/5.9.14/src/libcharon/plugins/vici/README.md).
- [Libreria Go ufficiale govici](https://github.com/strongswan/govici).
