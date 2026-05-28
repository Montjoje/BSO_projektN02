# BSO N02 - skrypt bootstrapujący dla RouterOS 7 z obsługą kontenerów.
# UWAGA: /system/device-mode/update container=yes wymaga jednorazowego fizycznego potwierdzenia na routerze.
# Po tej czynności dalsza instalacja może zostać wykonana zdalnie przez SSH.

:local image "ghcr.io/montjoje/bso_projektn02:latest"
:local workdir "usb1/bso-n02"
:local tmpdir "usb1/container-tmp"
:local subnet "192.168.88.0/24"
:local profile "baseline"
:local smtpHost "smtp.gmail.com"
:local smtpPort "587"
:local smtpSender "operator@example.com"
:local smtpPassword "CHANGE_ME_APP_PASSWORD"
:local smtpRecipient "admin@example.com"

/log info "BSO N02: rozpoczynam instalacje kontenera skanera"
/container/config set registry-url=https://ghcr.io tmpdir=$tmpdir

# Interfejs veth kontenera. W typowej konfiguracji bridge=bridge zapewnia dostęp do LAN.
:if ([:len [/interface/veth/find name="veth-bso-n02"]] = 0) do={
  /interface/veth/add name=veth-bso-n02 address=172.19.26.2/24 gateway=172.19.26.1
}
:if ([:len [/ip/address/find address="172.19.26.1/24"]] = 0) do={
  /ip/address/add address=172.19.26.1/24 interface=veth-bso-n02
}
:if ([:len [/interface/bridge/find name="bridge"]] > 0) do={
  :if ([:len [/interface/bridge/port/find interface="veth-bso-n02"]] = 0) do={
    /interface/bridge/port/add bridge=bridge interface=veth-bso-n02
  }
}

# Lista zmiennych środowiskowych. Hasło SMTP należy podmienić przed wdrożeniem produkcyjnym.
:foreach item in=[/container/envs/find name="bso-n02-envs"] do={ /container/envs/remove $item }
/container/envs/add name=bso-n02-envs key=BSO_SUBNETS value=$subnet
/container/envs/add name=bso-n02-envs key=BSO_PROFILE value=$profile
/container/envs/add name=bso-n02-envs key=BSO_RUN_MODE value="once"
/container/envs/add name=bso-n02-envs key=BSO_BASE_TIMEOUT_SECONDS value="300"
/container/envs/add name=bso-n02-envs key=BSO_SMTP_HOST value=$smtpHost
/container/envs/add name=bso-n02-envs key=BSO_SMTP_PORT value=$smtpPort
/container/envs/add name=bso-n02-envs key=BSO_SMTP_SENDER value=$smtpSender
/container/envs/add name=bso-n02-envs key=BSO_SMTP_PASSWORD value=$smtpPassword
/container/envs/add name=bso-n02-envs key=BSO_SMTP_RECIPIENT value=$smtpRecipient

:if ([:len [/container/find name="bso-lan-security-scanner"]] = 0) do={
  /container/add name=bso-lan-security-scanner remote-image=$image interface=veth-bso-n02 root-dir=$workdir envlist=bso-n02-envs start-on-boot=yes logging=yes
} else={
  /container/set [find name="bso-lan-security-scanner"] remote-image=$image interface=veth-bso-n02 root-dir=$workdir envlist=bso-n02-envs start-on-boot=yes logging=yes
}

# Harmonogram zgodny z dokumentacją etapu I: RouterOS uruchamia kontener cyklicznie.
:if ([:len [/system/scheduler/find name="bso-n02-daily-scan"]] = 0) do={
  /system/scheduler/add name=bso-n02-daily-scan interval=1d start-time=03:30:00 on-event="/container/start [find name=bso-lan-security-scanner]"
} else={
  /system/scheduler/set [find name="bso-n02-daily-scan"] interval=1d start-time=03:30:00 on-event="/container/start [find name=bso-lan-security-scanner]"
}

/log info "BSO N02: instalacja zakonczona; pierwszy skan zostanie uruchomiony teraz"
/container/start [find name=bso-lan-security-scanner]
