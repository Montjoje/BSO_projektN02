# BSO_projektN02 – etap II

Prototyp systemu skanowania lokalnej sieci komputerowej uruchamianego w kontenerze na routerze MikroTik.

Implementacja odpowiada założeniom z etapu I:

* aplikacja sterująca napisana w Go,
* skanowanie realizowane przez Nmap z obsługą NSE,
* profile skanowania: `baseline`, `deep`, `pentest`,
* raport HTML i tekstowy,
* wysyłka raportu e-mail bezpośrednio z kontenera przez SMTP,
* konteneryzacja przez Docker,
* szkic wdrożenia dla RouterOS w pliku `routeros/install.rsc`.

Dockerfile buduje obraz w oparciu o `golang:1.26.1-alpine`. Plik `go.mod` pozostaje ustawiony na `go 1.23`, ponieważ kod nie korzysta z funkcji zależnych od nowszej składni języka i dzięki temu łatwiej uruchomić go lokalnie w środowiskach testowych.

---

## Zawartość repozytorium

```text
BSO_projektN02/
|-- cmd/
|   `-- scanner/
|       `-- main.go
|-- internal/
|   |-- config/
|   |-- discovery/
|   |-- scanner/
|   |-- parser/
|   |-- scoring/
|   |-- reporting/
|   |-- mailer/
|   `-- models/
|-- configs/
|   `-- config.example.yaml
|-- profiles/
|   |-- baseline.yaml
|   |-- deep.yaml
|   `-- pentest.yaml
|-- templates/
|   `-- report.html
|-- container/
|   |-- Dockerfile
|   `-- entrypoint.sh
|-- routeros/
|   `-- install.rsc
|-- docs/
|   `-- etap1/
|-- go.mod
|-- README.md
`-- .gitignore
```

---

## Wymagania lokalne

Do uruchomienia testowego na Windowsie potrzebne są:

* Docker Desktop,
* Git,
* repozytorium projektu pobrane lokalnie,
* poprawnie przygotowany plik konfiguracyjny,
* konto SMTP do wysyłki raportów, np. Gmail z hasłem aplikacji.

Sprawdzenie Dockera:

```powershell
docker --version
docker run hello-world
```

---

## Przygotowanie konfiguracji

Nie edytujemy bezpośrednio przykładowego pliku, tylko tworzymy własny plik konfiguracyjny:

```powershell
copy .\configs\config.example.yaml .\configs\config.yaml
```

Następnie edytujemy:

```powershell
notepad .\configs\config.yaml
```

albo w VS Code:

```powershell
code .\configs\config.yaml
```

Przykład konfiguracji:

```yaml
subnets:
  - 192.168.1.0/24

profile: baseline
work_dir: /app/data

base_timeout_seconds: 600
extended_timeout_seconds: 1200

smtp_host: smtp.gmail.com
smtp_port: 587
smtp_user: twojmail@gmail.com
smtp_password: HASLO_APLIKACJI
smtp_from: twojmail@gmail.com
smtp_to: twojmail@gmail.com
subject_prefix: "[BSO N02]"
```

### Znaczenie pól

`subnets` określa zakres sieci do skanowania.
Przykład:

```yaml
subnets:
  - 192.168.1.0/24
```

`profile` określa profil skanowania:

```yaml
profile: baseline
```

Dostępne profile:

* `baseline` – podstawowy, najmniej obciążający skan,
* `deep` – dokładniejszy skan z dodatkowymi skryptami NSE,
* `pentest` – profil testów penetracyjnych, uruchamiany świadomie i tylko w autoryzowanym środowisku.

`work_dir` określa katalog roboczy wewnątrz kontenera:

```yaml
work_dir: /app/data
```

`base_timeout_seconds` to maksymalny czas dla discovery hostów oraz skanu bazowego.

`extended_timeout_seconds` to maksymalny czas dla skanu rozszerzonego, używanego przy profilach `deep` i `pentest`.

Timeout nie oznacza, ile skan ma trwać. Jest to limit bezpieczeństwa. Po jego przekroczeniu proces Nmap zostanie przerwany.

Rekomendowane wartości testowe:

```yaml
base_timeout_seconds: 600
extended_timeout_seconds: 1200
```

Dla małej sieci lub pojedynczego hosta można użyć mniejszych wartości, np.:

```yaml
base_timeout_seconds: 300
extended_timeout_seconds: 900
```

### Konfiguracja Gmail SMTP

Dla Gmaila poprawne ustawienia to:

```yaml
smtp_host: smtp.gmail.com
smtp_port: 587
smtp_user: twojmail@gmail.com
smtp_password: HASLO_APLIKACJI
smtp_from: twojmail@gmail.com
smtp_to: twojmail@gmail.com
```

Adres w polach `smtp_user`, `smtp_from` i `smtp_to` może być ten sam.
Do pola `smtp_password` nie należy wpisywać zwykłego hasła do Gmaila. Należy użyć hasła aplikacji Google.

Nie należy commitować prawdziwego hasła SMTP do repozytorium.

---

## Budowanie obrazu kontenera

W katalogu głównym projektu:

```powershell
docker build --no-cache -f container/Dockerfile -t bso-n02 .
```

Po zakończeniu można sprawdzić obraz:

```powershell
docker images
```

Na liście powinien pojawić się obraz:

```text
bso-n02
```

---

## Uruchomienie testowe na Windowsie

Podstawowe uruchomienie:

```powershell
docker run --rm `
  -v ${PWD}/configs:/app/configs `
  -v ${PWD}/data:/app/data `
  bso-n02
```

Jeżeli chcesz jawnie wskazać plik `config.yaml`:

```powershell
docker run --rm `
  -e CONFIG_PATH=/app/configs/config.yaml `
  -v ${PWD}/configs:/app/configs `
  -v ${PWD}/data:/app/data `
  bso-n02
```

---

## Uruchomienie z nadpisaniem profilu

Profil można zmienić bez edycji pliku YAML:

```powershell
docker run --rm `
  -e CONFIG_PATH=/app/configs/config.yaml `
  -e BSO_PROFILE=deep `
  -v ${PWD}/configs:/app/configs `
  -v ${PWD}/data:/app/data `
  bso-n02
```

---

## Uruchomienie skanu pojedynczego hosta

Przykład dla jednego hosta:

```powershell
docker run --rm `
  -e CONFIG_PATH=/app/configs/config.yaml `
  -e BSO_SUBNETS=192.168.1.100/32 `
  -e BSO_PROFILE=deep `
  -v ${PWD}/configs:/app/configs `
  -v ${PWD}/data:/app/data `
  bso-n02
```

Adres `192.168.1.100` należy zastąpić adresem IP testowanego urządzenia.

---

## Logi i progress skanowania

Podczas działania aplikacja wypisuje informacje o aktualnym etapie:

```text
[STEP 1/8] Wczytywanie konfiguracji
[STEP 2/8] Wczytywanie profilu skanowania
[STEP 3/8] Discovery hostów
[STEP 4/8] Skan bazowy
[STEP 5/8] Parsowanie wyników bazowych
[STEP 6/8] Skan rozszerzony
[STEP 7/8] Ocena ryzyka
[STEP 8/8] Budowanie, zapis i wysyłka raportu
```

Dodatkowo logi Nmapa są wypisywane z prefiksami:

```text
[NMAP:base]
[NMAP:extended]
```

Program cyklicznie pokazuje też, że skan nadal trwa, np.:

```text
[INFO] Skan base nadal trwa, czas od startu: 30s
```

---

## Gdzie są wyniki

Raporty HTML i TXT:

```powershell
dir .\data\reports
```

Surowe wyniki Nmap XML:

```powershell
dir .\data\scans
```

Dane pomocnicze:

```powershell
dir .\data\state
```

---

## Sprawdzenie kontenerów i logów

Lista kontenerów:

```powershell
docker ps -a
```

Logi konkretnego kontenera:

```powershell
docker logs ID_KONTENERA
```

Lista obrazów:

```powershell
docker images
```

Usunięcie zatrzymanych kontenerów:

```powershell
docker container prune
```

---

## Publikacja obrazu do GitHub Container Registry

Budowanie obrazu z nazwą docelową:

```powershell
docker build -f container/Dockerfile -t ghcr.io/montjoje/bso_projektn02:latest .
```

Logowanie do GHCR:

```powershell
echo TOKEN_GHCR | docker login ghcr.io -u Montjoje --password-stdin
```

Publikacja obrazu:

```powershell
docker push ghcr.io/montjoje/bso_projektn02:latest
```

`TOKEN_GHCR` należy zastąpić tokenem GitHub z uprawnieniami do publikowania paczek.

---

## Jednolinijkowy bootstrap dla RouterOS

Po opublikowaniu obrazu kontenera możliwe jest uruchomienie instalacji z poziomu SSH:

```bash
ssh admin@ROUTER_IP '/tool fetch url=https://raw.githubusercontent.com/Montjoje/BSO_projektN02/main/routeros/install.rsc dst-path=install.rsc; /import file-name=install.rsc'
```

Przed użyciem na realnym routerze należy dopasować plik:

```text
routeros/install.rsc
```

w szczególności:

* nazwę obrazu kontenera,
* `root-dir`,
* `tmpdir`,
* nazwę bridge,
* subnet do skanowania,
* dane SMTP,
* profil skanowania.

---

## Ważne założenia wdrożeniowe

`install.rsc` jest szkicem wdrożeniowym i wymaga dopasowania do konkretnego modelu MikroTik.

Na urządzeniu MikroTik trzeba wcześniej aktywować obsługę kontenerów.

Dla routerów z małą pamięcią wewnętrzną zalecane jest użycie zewnętrznego nośnika dla `root-dir` oraz `tmpdir`.

Ustawienia SMTP, subnety i profil można nadpisać przez zmienne środowiskowe RouterOS z prefiksem `BSO_*`.

---

## Przykładowa procedura testowa

1. Przygotować plik `configs/config.yaml`.
2. Ustawić profil `baseline`.
3. Zbudować obraz:

```powershell
docker build --no-cache -f container/Dockerfile -t bso-n02 .
```

4. Uruchomić kontener:

```powershell
docker run --rm `
  -e CONFIG_PATH=/app/configs/config.yaml `
  -v ${PWD}/configs:/app/configs `
  -v ${PWD}/data:/app/data `
  bso-n02
```

5. Sprawdzić katalogi:

```powershell
dir .\data\reports
dir .\data\scans
```

6. Sprawdzić, czy raport e-mail dotarł na wskazany adres.

7. Wykonać test profilu `deep` na pojedynczym hoście:

```powershell
docker run --rm `
  -e CONFIG_PATH=/app/configs/config.yaml `
  -e BSO_SUBNETS=192.168.1.100/32 `
  -e BSO_PROFILE=deep `
  -v ${PWD}/configs:/app/configs `
  -v ${PWD}/data:/app/data `
  bso-n02
```

---

## Typowe problemy

### `exec /app/entrypoint.sh: no such file or directory`

Najczęściej oznacza to problem z końcami linii Windows CRLF w pliku `entrypoint.sh`.

Naprawa:

```powershell
(Get-Content .\container\entrypoint.sh) -join "`n" | Set-Content -NoNewline .\container\entrypoint.sh
docker build --no-cache -f container/Dockerfile -t bso-n02 .
```

### `Username and Password not accepted`

Dla Gmaila oznacza to zwykle, że wpisano zwykłe hasło do konta zamiast hasła aplikacji.

### Skan kończy się timeoutem

Zwiększyć wartości:

```yaml
base_timeout_seconds: 600
extended_timeout_seconds: 1200
```

### Brak raportu w katalogu `data`

Sprawdzić, czy kontener został uruchomiony z volume:

```powershell
-v ${PWD}/data:/app/data
```

oraz czy w konfiguracji ustawiono:

```yaml
work_dir: /app/data
```
