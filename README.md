# CVE Daily Alert Script

Uno script Python per monitorare nuove CVE critiche correlate a tecnologie di tuo interesse.

---

## Descrizione

Questo tool:

* Clona/aggiorna la repo [`CVEProject/cvelistV5`](https://github.com/CVEProject/cvelistV5.git)
* Individua i file JSON aggiunti nelle ultime 24 ore (tramite `git log --diff-filter=A`)
* Filtra solo le CVE con punteggio CVSS ≥ 9.0 e "affetcted"
* Ricerca nei campi principali la presenza di tecnologie elencate in `tech_list.txt`
* Restituisce un output in stile Nagios con codice di uscita:

  * `0` OK (nessuna CVE critica)
  * `1` WARNING (CVSS ≥ 7.0 e < 9.0)
  * `2` CRITICAL (CVSS ≥ 9.0)
  * `3` UNKNOWN (errori o configurazione mancante)

---

## Prerequisiti

* Python 3.6+
* Git installato e accessibile da CLI
* Ambiente POSIX (Linux/macOS)

---

## Installazione

1. Clona questo repository:

   ```bash
   git clone https://github.com/LucaMarastoni/cve_detector.git
   cd cve_detector
   ```
2. (Opzionale) Crea un virtualenv e attivalo:

   ```bash
   python3 -m venv venv
   source venv/bin/activate
   ```
3. Rendi eseguibile lo script:

   ```bash
   chmod +x cve_monitor.py
   ```

---

## Configurazione

1. **`tech_list.txt`**: file di testo in cartella principale, una tecnologia per riga (case-insensitive).

   ```text
   nginx
   apache
   log4j
   ```
2. (Facoltativo) Modifica le soglie CVSS direttamente nel codice:

   * `WARNING`: CVSS ≥ 7.0 e < 9.0
   * `CRITICAL`: CVSS ≥ 9.0

---

## Uso

Esempio di esecuzione manuale:

```bash
./cve_monitor.py
```

### Output esempio

* **OK** (nessuna CVE grave):

  ```text
  OK - nessuna CVE critica trovata
  ```
* **WARNING** (ad es. CVSS 7.2):

  ```text
  WARNING - 2 CVE critiche trovate: NGINX[7.2] CVE-2025-6001.json; APACHE[7.5] CVE-2025-6010.json
  ```
* **CRITICAL** (almeno CVSS ≥ 9.0):

  ```text
  CRITICAL - 1 CVE critiche trovate: LOG4J[9.8] CVE-2025-6020.json
  ```

L’ultimo campo elenca `TECNOLOGIA[score] filename`

---

## Pianificazione con cron

Per eseguire lo script ogni giorno alle 00:10 e salvare i log:

```cron
10 0 * * * /usr/bin/env python3 /path/to/cve_monitor.py >> /var/log/cve_monitor.log 2>&1
```

Assicurati che il percorso sia corretto e che l’utente abbia permessi di lettura/scrittura sui log.

---

## Codici di uscita

| Codice | Significato                                    |
| -----: | ---------------------------------------------- |
|      0 | OK: nessuna CVE critica                        |
|      1 | WARNING: CVSS ≥ 7.0 e < 9.0                    |
|      2 | CRITICAL: CVSS ≥ 9.0                           |
|      3 | UNKNOWN: errori (es. `tech_list.txt` mancante) |

---

## Log & Debug

* Verifica la repo `cvelistV5` in locale: `% ls cvelistV5`
* Esegui manualmente `git -C cvelistV5 log --since="24 hours ago" --diff-filter=A`
* Aggiungi flag `-v` al print per debug esteso.
