# BSO_projektN02 – etap II

Prototyp systemu skanowania lokalnej sieci uruchamianego w kontenerze na routerze MikroTik.
Implementacja odpowiada założeniom z etapu I: Go + Nmap/NSE, profile `baseline`, `deep`, `pentest`, raport e-mail wysyłany bezpośrednio z kontenera przez SMTP oraz szkic wdrożenia RouterOS. Dockerfile buduje obraz w oparciu o `golang:1.26.1-alpine`, natomiast plik `go.mod` pozostaje konserwatywnie ustawiony na `go 1.23`, ponieważ sam kod nie wykorzystuje funkcji zależnych od nowszej składni i dzięki temu łatwiej uruchomić go lokalnie w środowiskach testowych.

## Zawartość repozytorium
- implementacja prototypu w Go,
- profile skanowania (`baseline`, `deep`, `pentest`),
- konfiguracja przykładowa,
- szablon raportu HTML,
- `Dockerfile` i `entrypoint.sh`,
- szkic `routeros/install.rsc`,
- dokumentacja z etapu I w `docs/etap1/`.

## Szybkie uruchomienie lokalne
```bash
go run ./cmd/scanner -config ./configs/config.example.yaml
```

## Budowanie binarki
```bash
go build -o bin/scanner ./cmd/scanner
```

## Budowanie obrazu kontenera
```bash
docker build -f container/Dockerfile -t ghcr.io/montjoje/bso_projektn02:latest .
```

## Publikacja obrazu do GHCR
```bash
echo <TOKEN_GHCR> | docker login ghcr.io -u Montjoje --password-stdin
docker push ghcr.io/montjoje/bso_projektn02:latest
```

## Jednolinijkowy bootstrap dla RouterOS
```bash
ssh admin@ROUTER_IP '/tool fetch url=https://raw.githubusercontent.com/Montjoje/BSO_projektN02/main/routeros/install.rsc dst-path=install.rsc; /import file-name=install.rsc'
```

## Ważne założenia wdrożeniowe
- `install.rsc` jest szkicem i wymaga dopasowania do konkretnego modelu MikroTik,
- na urządzeniu trzeba wcześniej aktywować obsługę kontenerów,
- dla małych modeli warto użyć zewnętrznego nośnika dla `root-dir` i `tmpdir`,
- ustawienia SMTP, subnety i profil można nadpisać przez ENV w RouterOS (`BSO_*`).
