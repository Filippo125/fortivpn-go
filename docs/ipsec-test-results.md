# Risultati IPsec — 2026-09-06/07

Backend sperimentale Go/strongSwan VICI verificato contro un FortiGate di
laboratorio con FortiOS 7.4.x. Nomi e indirizzi sono stati sostituiti con
placeholder e blocchi RFC di documentazione. Client Linux in container con
strongSwan 5.9.x.

## Verifiche eseguite

`go test -race ./...` superato sul Mac. Compilazione dei test Linux amd64
superata; questi ultimi non sono stati eseguiti su amd64.

Lo [script di integrazione](../tests/integration/ipsec/run.sh) ha completato
sette scenari su un gateway di laboratorio autorizzato, tutti superati:

| Scenario | Evidenza |
|---|---|
| IPv4 | PSK + EAP-MSCHAPv2, VIP 203.0.113.10/32, ICMP e TCP/22 verso 198.51.100.2 |
| Dual-stack | Anche VIP 2001:db8:200::10/128, ICMP e TCP/22 verso 2001:db8:100::2 |
| Password errata | Connessione rifiutata e cleanup |
| PSK errata | Connessione rifiutata e cleanup |
| Identità remota errata | Connessione rifiutata e cleanup |
| Cancellazione setup | Deadline durante la negoziazione e cleanup |
| Perdita sessione | Terminazione SA simulata, errore rilevato dal monitor e cleanup |

Nei casi IPv4 e dual-stack è stata verificata la sostituzione effettiva delle
SA dopo rekey espliciti IKE e di ciascuna CHILD_SA, con traffico funzionante
dopo ogni sostituzione. È stato verificato ESP incapsulato NAT-T.

Prima e dopo ogni scenario sono controllati SA, connessioni e credenziali
VICI, indirizzi del pool e route split nella tabella 220. Il test richiede
che le risorse del tunnel siano assenti dopo il cleanup.

Verificata anche la CLI compilata con `ipsec connect --ip-mode dual` e
disconnessione automatica con `--duration 3s`: indirizzi e rotte IPv4/IPv6
correttamente riportati.

La verifica CLI ha rilevato e permesso di correggere una race tra timeout del
socket e notifica della deadline Go. Dopo la correzione, il test di regressione
e `go test -race ./internal/ipsec ./cmd/fortivpn` passano; la CLI dual-stack
termina con codice 0 alla scadenza e la lista SA è vuota. Container e rete
temporanei sono stati rimossi.

## Limiti della validazione

Questi risultati validano il prototipo Linux su questo laboratorio. Restano
da verificare macOS nativo, sessioni prolungate attraverso le lifetime,
sleep/wake e cambi di rete. Il test di perdita sessione termina una SA:
non simula un'interruzione fisica della rete o verifica i tempi DPD.

TCP come trasporto IPsec, SAML/MFA, certificati, DNS di sistema e riconnessione
automatica non sono implementati. Non è ancora un rilascio multipiattaforma.

Per ripetere le prove usare la [reference del backend](ipsec-backend.md)
e la [configurazione FortiGate](ipsec-lab-reference.md). Le credenziali
rimangono in un file privato esterno al repository.

## Aggiornamento TCP — 2026-09-08

Sette scenari TCP superati tramite lo script dedicato, con
UDP esterno bloccato nel container. Inclusi IPv4/IPv6, traffico ICMP/TCP, rekey
IKE/ESP, errori di autenticazione, cancellazione e perdita sessione. Le route
sono state verificate sul dispositivo ESP userspace; il cleanup ora controlla
tutte le tabelle, anche quando la tabella 220 non è ancora stata creata.

Runtime nativo macOS arm64 compilato; CLI compilata per arm64 e amd64. Test
Go con race detector superati sul Mac. Il tunnel nativo resta da collaudare
con privilegi amministrativi: [istruzioni](ipsec-macos-tcp.md).
