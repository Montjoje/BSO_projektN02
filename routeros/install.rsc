# BSO N02 - szkic wdrożenia na RouterOS v7
# Zakłada publikację obrazu w GHCR oraz użycie ENV do nadpisania konfiguracji.
# Jednorazowy bootstrap po SSH może mieć postać:
# /tool fetch url=https://raw.githubusercontent.com/Montjoje/BSO_projektN02/main/routeros/install.rsc dst-path=install.rsc; /import file-name=install.rsc

:local containerName "bso-n02"
:local vethName "veth-bso"
:local bridgeName "bridge"
:local rootDir "disk1/bso-n02/root"
:local tmpDir "disk1/bso-n02/tmp"
:local image "ghcr.io/montjoje/bso_projektn02:latest"

/container/config/set registry-url=https://ghcr.io tmpdir=$tmpDir

:if ([:len [/interface/veth/find where name=$vethName]] = 0) do={
    /interface/veth/add name=$vethName address=172.18.0.2/24 gateway=172.18.0.1
}

:if ([:len [/interface/bridge/port/find where interface=$vethName]] = 0) do={
    /interface/bridge/port/add bridge=$bridgeName interface=$vethName
}

:if ([:len [/ip/address/find where address="172.18.0.1/24"]] = 0) do={
    /ip/address/add address=172.18.0.1/24 interface=$bridgeName
}

:if ([:len [/ip/firewall/nat/find where comment="BSO N02 NAT"]] = 0) do={
    /ip/firewall/nat/add chain=srcnat action=masquerade src-address=172.18.0.0/24 comment="BSO N02 NAT"
}

:if ([:len [/container/envs/find where list="ENV_BSO"]] = 0) do={
    /container/envs/add list=ENV_BSO key=CONFIG_PATH value="/app/configs/config.example.yaml"
    /container/envs/add list=ENV_BSO key=BSO_PROFILE value="baseline"
    /container/envs/add list=ENV_BSO key=BSO_SUBNETS value="192.168.88.0/24"
    /container/envs/add list=ENV_BSO key=BSO_WORK_DIR value="/tmp/bso-data"
    /container/envs/add list=ENV_BSO key=BSO_SMTP_HOST value="smtp.example.com"
    /container/envs/add list=ENV_BSO key=BSO_SMTP_PORT value="587"
    /container/envs/add list=ENV_BSO key=BSO_SMTP_USER value="scanner@example.com"
    /container/envs/add list=ENV_BSO key=BSO_SMTP_PASSWORD value="change-me"
    /container/envs/add list=ENV_BSO key=BSO_SMTP_FROM value="scanner@example.com"
    /container/envs/add list=ENV_BSO key=BSO_SMTP_TO value="admin@example.com"
    /container/envs/add list=ENV_BSO key=BSO_SUBJECT_PREFIX value="[BSO N02]"
}

:if ([:len [/container/find where name=$containerName]] = 0) do={
    /container/add remote-image=$image interface=$vethName root-dir=$rootDir envlist=ENV_BSO start-on-boot=yes logging=yes name=$containerName
}

:if ([:len [/system/scheduler/find where name="bso-n02-runner"]] = 0) do={
    /system/scheduler/add name="bso-n02-runner" interval=1d start-time=03:00:00 on-event="/container/start bso-n02" comment="Uruchamianie skanera BSO N02"
}
