# BSO N02 – LAN Security Scanner Agent

Etap II projektu BSO 26L: praktyczna implementacja systemu skanowania lokalnej sieci komputerowej z wykrywaniem potencjalnych zagrożeń oraz raportowaniem e-mail dla urządzeń sieciowych typu router.

Implementacja została przygotowana zgodnie z założeniami z etapu I: lekki agent w Go uruchamiany w kontenerze, Nmap/NSE jako silnik skanowania, profile `baseline`, `deep`, `pentest`, zapis XML/JSON/HTML/TXT oraz wysyłka raportu przez zewnętrzny serwer SMTP.

## 1. Struktura repozytorium

Aktualna struktura repozytorium na GitHubie jest płaska na poziomie katalogu głównego: dokumentacja z etapu I znajduje się bezpośrednio w repozytorium, a nie w osobnym katalogu `docs/`.

```text
BSO_projektN02/
├── cmd/
│   └── scanner/
│       └── main.go                 # punkt wejścia aplikacji
├── configs/
│   ├── config.yaml                 # domyślna konfiguracja uruchomieniowa
│   └── config.example.yaml         # przykładowa konfiguracja
├── container/
│   ├── Dockerfile                  # definicja obrazu kontenera
│   └── entrypoint.sh               # skrypt startowy kontenera
├── internal/
│   ├── config/                     # config.yaml + zmienne środowiskowe + profile
│   ├── discovery/                  # lekki skan hostów aktywnych
│   ├── scanner/                    # orkiestracja procesów Nmap/NSE
│   ├── parser/                     # parser XML Nmap i normalizacja danych
│   ├── scoring/                    # punktowa klasyfikacja ryzyka i rekomendacje
│   ├── reporting/                  # raport HTML, TXT, JSON
│   ├── mailer/                     # SMTP/SMTPS
│   └── models/                     # wspólny model danych
├── profiles/
│   ├── baseline.yaml               # profil diagnostyczny
│   ├── deep.yaml                   # profil pogłębiony
│   └── pentest.yaml                # profil pentestowy
├── routeros/
│   └── install.rsc                 # skrypt bootstrapu dla RouterOS
├── templates/
│   └── report.html                 # szablon raportu HTML
├── .gitignore
├── BSO26L_PRO_etapI_MS_MZ.pdf      # sprawozdanie z etapu I
├── BSO26L_PRO_etapI_MS_MZ.zip      # archiwum etapu I
├── README.md
└── go.mod
```

Katalogi robocze `data/scans/`, `data/reports/` i `data/state/` nie muszą być widoczne w repozytorium. Aplikacja tworzy je podczas pracy, jeżeli są potrzebne. Plik binarny `scanner` również nie jest wymagany do zbudowania projektu ze źródeł; powstaje po wykonaniu komendy `go build`.

## 2. Profile skanowania

### `baseline`
Profil diagnostyczny do cyklicznego monitoringu. Jest niskoinwazyjny i dostosowany do pracy na urządzeniu brzegowym: wykonuje discovery, lekki skan TCP connect, ograniczone rozpoznanie wersji usług oraz jawnie wybrane, bezpieczne skrypty NSE (`banner`, `http-title`, `http-server-header`, `ssl-cert`). Nie używa szerokich kategorii `broadcast`, `external`, `brute`, `dos`, `exploit` ani `intrusive`, ponieważ profil diagnostyczny ma nadawać się do automatycznego wykonywania.

### `deep`
Profil pogłębiony. Rozszerza analizę o dokładniejsze rozpoznanie usług, HTTP, TLS, SSH, DNS, NTP, SMB oraz wybrane testy podatności przez wyrażenie `vuln and not intrusive and not brute and not dos and not exploit`. Jest przeznaczony do uruchamiania na żądanie lub rzadziej niż profil diagnostyczny.

### `pentest`
Profil pentestowy. Może uruchamiać bardziej agresywne kategorie NSE, w tym `intrusive`, `exploit`, `dos` i `brute`. Powinien być używany wyłącznie świadomie, w autoryzowanym oknie serwisowym, zgodnie z ograniczeniami bezpieczeństwa opisanymi w etapie I.

## 3. Konfiguracja

Podstawowa konfiguracja znajduje się w `configs/config.example.yaml`. Wszystkie kluczowe pola można nadpisać zmiennymi środowiskowymi:

| Zmienna | Znaczenie | Przykład |
|---|---|---|
| `BSO_SUBNETS` | lista podsieci/adresów po przecinku | `192.168.88.0/24,192.168.1.0/24` |
| `BSO_PROFILE` | profil skanowania | `baseline` |
| `BSO_BASE_TIMEOUT_SECONDS` | limit czasu dla procesu Nmap | `300` |
| `BSO_SMTP_HOST` | serwer SMTP | `smtp.gmail.com` |
| `BSO_SMTP_PORT` | port SMTP | `587` albo `465` |
| `BSO_SMTP_SENDER` | nadawca | `operator@example.com` |
| `BSO_SMTP_PASSWORD` | hasło/aplikacyjne hasło SMTP | `...` |
| `BSO_SMTP_RECIPIENT` | odbiorca raportu | `admin@example.com` |
| `BSO_DRY_RUN` | tryb demonstracyjny bez Nmap | `true` |
| `BSO_NO_EMAIL` | pominięcie wysyłki e-mail | `true` |
| `BSO_RUN_MODE` | `once` albo `daemon` | `once` |

## 4. Uruchomienie lokalne bez kontenera

Wymagania: Go i Nmap z pakietem skryptów NSE.

```bash
go build -o scanner ./cmd/scanner
./scanner -config configs/config.yaml -profile baseline -no-email
```

Szybki test demonstracyjny bez Nmap:

```bash
./scanner -config configs/config.yaml -profile deep -dry-run -no-email
```

Wyniki pojawią się w:

```text
data/scans/      # surowe XML z Nmap
data/reports/    # JSON, HTML i TXT
data/state/      # katalog na przyszłą obsługę stanu między skanami
```

## 5. Budowa kontenera

```bash
docker build -f container/Dockerfile -t bso-projektn02:latest .
```

W razie braku obrazu `golang:1.26.1-alpine` można zbudować obraz ze starszym builderem:

```bash
docker build --build-arg GO_VERSION=1.23 -f container/Dockerfile -t bso-projektn02:latest .
```

## 6. Uruchomienie kontenera na zwykłym Dockerze

Tryb demonstracyjny:

```bash
docker run --rm \
  -e BSO_DRY_RUN=true \
  -e BSO_NO_EMAIL=true \
  -e BSO_PROFILE=deep \
  -v "$(pwd)/data:/app/data" \
  bso-projektn02:latest
```

Skan realnej podsieci, bez wysyłki e-mail:

```bash
docker run --rm --network host \
  -e BSO_SUBNETS=192.168.88.0/24 \
  -e BSO_PROFILE=baseline \
  -e BSO_NO_EMAIL=true \
  -v "$(pwd)/data:/app/data" \
  bso-projektn02:latest
```

Skan z wysyłką e-mail:

```bash
docker run --rm --network host \
  -e BSO_SUBNETS=192.168.88.0/24 \
  -e BSO_PROFILE=baseline \
  -e BSO_SMTP_HOST=smtp.gmail.com \
  -e BSO_SMTP_PORT=587 \
  -e BSO_SMTP_SENDER=operator@example.com \
  -e BSO_SMTP_PASSWORD='APP_PASSWORD' \
  -e BSO_SMTP_RECIPIENT=admin@example.com \
  -v "$(pwd)/data:/app/data" \
  bso-projektn02:latest
```

## 7. Instalacja na MikroTik RouterOS

### Warunek wstępny

Obsługa kontenerów w RouterOS jest domyślnie wyłączona. Trzeba ją jednorazowo włączyć lokalnie/fizycznie na urządzeniu zgodnie z dokumentacją MikroTik:

```routeros
/system/device-mode/update container=yes
```

Po restarcie i fizycznym potwierdzeniu dalsza instalacja może być wykonana zdalnie.

### Jedna komenda przez SSH

Po opublikowaniu repozytorium na GitHubie i obrazu w GHCR:

```bash
ssh admin@ROUTER_IP "/tool/fetch url=https://raw.githubusercontent.com/Montjoje/BSO_projektN02/main/routeros/install.rsc dst-path=install.rsc; /import file-name=install.rsc"
```

Skrypt `routeros/install.rsc`:

1. konfiguruje rejestr kontenerów,
2. tworzy interfejs `veth-bso-n02`,
3. dodaje zmienne środowiskowe kontenera,
4. pobiera obraz `ghcr.io/montjoje/bso_projektn02:latest`,
5. ustawia `start-on-boot=yes`,
6. dodaje harmonogram `bso-n02-daily-scan`,
7. uruchamia pierwszy skan.

Przed wdrożeniem produkcyjnym należy podmienić w `install.rsc` wartości SMTP i podsieć LAN.

## 8. Logika raportu i rekomendacji

Raport nie ogranicza się do ogólnego komunikatu typu „NSE zwrócił ostrzeżenie”. Parser zbiera konkretne porty, nazwy usług, wersje, produkty i wyjścia skryptów NSE. Silnik punktowy przypisuje ustalenia do kategorii, np.:

- panel HTTP bez TLS,
- Telnet/FTP lub inny protokół nieszyfrowany,
- usługa zdalnego zarządzania w LAN,
- kamera/IoT z typowymi usługami RTSP/GoAhead/BusyBox,
- stara wersja usługi,
- konkretny wynik NSE zawierający CVE lub `VULNERABLE`,
- słaba konfiguracja typu `anonymous`, `default credentials`, `weak`, `expired`, `self-signed`.

Dla każdego ustalenia raport zawiera:

- poziom ważności,
- liczbę punktów,
- dowód z portem/usługą/skryptem,
- praktyczną rekomendację naprawczą.

Progi ryzyka są zgodne z etapem I:

- `0–19 pkt` – niskie,
- `20–39 pkt` – średnie,
- `40+ pkt` – wysokie.

## 9. Uwagi bezpieczeństwa

- Skanować wolno wyłącznie sieci własne lub takie, dla których uzyskano zgodę.
- Profil `pentest` nie powinien działać cyklicznie.
- Hasła SMTP nie powinny być trzymane w repozytorium; w praktyce należy przekazywać je jako zmienne środowiskowe albo uzupełniać w RouterOS dopiero na urządzeniu testowym.
- Rozwiązanie nie wprowadza automatycznych zmian na urządzeniach końcowych; raport ma charakter diagnostyczny.
- Skan bazowy i rozszerzony wykonywany jest per host, a nie jednym dużym wywołaniem Nmapa dla całej podsieci. Dzięki temu problem z jednym urządzeniem nie unieważnia wyników pozostałych hostów.
- Jeśli skan konkretnego hosta przekroczy limit czasu, aplikacja nie oznacza go myląco jako `LOW`. Host otrzymuje status `UNKNOWN`, `assessment_status=scan_failed` oraz informacyjne ustalenie z zaleceniem powtórzenia skanu. Raport pozostaje częściowy, ale jasno odróżnia hosty ocenione od nieocenionych.

## 10. Zachowanie przy niepełnych skanach

Wyniki discovery i wyniki skanu usług są rozdzielone. Host wykryty w discovery nie jest automatycznie traktowany jako bezpieczny. Jeżeli nie uda się wykonać skanu portów/usług dla danego adresu, raport pokazuje:

- `assessment_status=scan_failed`, `parse_failed` albo `discovery_only`,
- `risk_level=UNKNOWN`,
- komunikat operacyjny w sekcji ostrzeżeń,
- rekomendację powtórzenia skanu lub zwiększenia limitu czasu.

Dopiero host z `assessment_status=assessed` może otrzymać zwykły poziom ryzyka `LOW`, `MEDIUM` albo `HIGH`.
