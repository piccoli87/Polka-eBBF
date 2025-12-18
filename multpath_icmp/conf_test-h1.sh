#!/bin/bash
set -euo pipefail

############################
# CONFIGURAÇÃO
############################
DEV="h1-eth0"

BPF_FS="/sys/fs/bpf"
PIN_BASE="$BPF_FS/decap"

DECAP_OBJ="decap_h1.o"
ENCAP_OBJ="encap_map_h1.o"

XDP_PROG_PIN="$PIN_BASE/decap_prog"

MAP_FWD_REV="tag_fwd_to_rev_map_h1"
MAP_IP_REV="ip_to_revtag_map_h1"

############################
# FUNÇÕES AUXILIARES
############################
fail() {
    echo "❌ ERRO: $1"
    exit 1
}

info() {
    echo "▶ $1"
}

check_file() {
    [ -f "$1" ] || fail "Arquivo não encontrado: $1"
}

check_root() {
    [ "$(id -u)" -eq 0 ] || fail "Execute como root"
}

############################
# INÍCIO
############################
check_root

info "Verificando objetos eBPF"
check_file "$DECAP_OBJ"
check_file "$ENCAP_OBJ"

info "Preparando bpffs"
mkdir -p "$BPF_FS"
mountpoint -q "$BPF_FS" || mount -t bpf bpf "$BPF_FS"

mkdir -p "$PIN_BASE"

############################
# LIMPEZA CONTROLADA
############################
info "Removendo XDP e TC anteriores (se existirem)"
ip link set dev "$DEV" xdp off 2>/dev/null || true
tc qdisc del dev "$DEV" clsact 2>/dev/null || true

info "Limpando pins antigos"
rm -f "$PIN_BASE/$MAP_FWD_REV" \
      "$PIN_BASE/$MAP_IP_REV" \
      "$XDP_PROG_PIN"

############################
# ETAPA 1 — CARREGAR XDP (CRIADOR)
############################
info "Carregando XDP (decap) e criando maps pinned"

bpftool prog load "$DECAP_OBJ" "$XDP_PROG_PIN" \
    map name "$MAP_FWD_REV" pinned "$PIN_BASE/$MAP_FWD_REV" \
    map name "$MAP_IP_REV" pinned "$PIN_BASE/$MAP_IP_REV" \
|| fail "Falha ao carregar programa XDP ou criar maps"

############################
# CHECAGENS DOS MAPS
############################
info "Verificando maps pinned"

[ -e "$PIN_BASE/$MAP_FWD_REV" ] || fail "Map $MAP_FWD_REV não foi criado"
[ -e "$PIN_BASE/$MAP_IP_REV" ]  || fail "Map $MAP_IP_REV não foi criado"

info "Maps criados com sucesso:"
ls -l "$PIN_BASE"

############################
# ETAPA 2 — ANCORAR XDP
############################
info "Ancorando XDP na interface $DEV"
ip link set dev "$DEV" xdp pinned "$XDP_PROG_PIN" \
|| fail "Falha ao ancorar XDP"

############################
# ETAPA 3 — CARREGAR TC (CONSUMIDOR)
############################
info "Criando clsact"
tc qdisc add dev "$DEV" clsact \
|| fail "Falha ao criar clsact"

info "Carregando TC (encap), reutilizando map pinned"
tc filter add dev "$DEV" egress bpf da \
    obj "$ENCAP_OBJ" sec tc \
|| fail "Falha ao carregar filtro TC"

############################
# VERIFICAÇÕES FINAIS
############################
info "Verificando estado final"

echo "--- XDP ---"
ip -details link show dev "$DEV" | grep -A6 xdp || fail "XDP não ativo"

echo "--- TC ---"
tc filter show dev "$DEV" egress || fail "Filtro TC não ativo"

echo "--- MAPS ---"
bpftool map show pinned "$PIN_BASE/$MAP_IP_REV" \
|| fail "Map compartilhado não acessível"

############################
# ALERTA DE ESTADO INDESEJADO
############################
if [ -d /sys/fs/bpf/tc/globals ] && \
   [ "$(ls -A /sys/fs/bpf/tc/globals 2>/dev/null)" ]; then
    echo "⚠️  AVISO: existem maps em /sys/fs/bpf/tc/globals:"
    ls /sys/fs/bpf/tc/globals
    echo "⚠️  Isso normalmente indica carregamento fora de ordem."
fi

info "Configuração eBPF concluída com sucesso ✅"
