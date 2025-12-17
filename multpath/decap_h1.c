#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <linux/ip.h>

/* ======= Endian helpers ======= */
#ifndef __BPF_ENDIAN__
#define __BPF_ENDIAN__
#define bpf_htons(x) ((__u16)__builtin_bswap16(x))
#define bpf_ntohs(x) ((__u16)__builtin_bswap16(x))
#define bpf_htonl(x) ((__u32)__builtin_bswap32(x))
#define bpf_ntohl(x) ((__u32)__builtin_bswap32(x))
#endif
/* ============================== */

/* ======= Estrutura da tag (20 bytes) ======= */
struct tag160 {
    __u8 bytes[20];
};

/* ============================================================
 * MAP 1 (estático)
 * tag de ida  -> tag de retorno
 * preenchido em user space na inicialização da topologia
 * ============================================================ */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 64);
    __type(key, struct tag160);
    __type(value, struct tag160);
} tag_fr_h1 SEC(".maps");

/* ============================================================
 * MAP 2 (dinâmico, compartilhado)
 * IP de origem -> tag de retorno
 * lido por outro filtro eBPF (encap.c)
 * ============================================================ */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);
    __type(value, struct tag160);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} ip_to_rtag_h1 SEC(".maps");

/* ============================================================
 * XDP decapsulation + aprendizado do caminho reverso
 * ============================================================ */
SEC("xdp")
int xdp_decap(struct xdp_md *ctx)
{
    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    const __u32 tun_hdr_len = 20;

    /* --- valida Ethernet --- */
    if (data + sizeof(*eth) > data_end)
        return XDP_PASS;

    /* --- verifica Ethertype customizado --- */
    if (bpf_ntohs(eth->h_proto) != 0x1234)
        return XDP_PASS;

    /* --- garante acesso à tag --- */
    if (data + sizeof(*eth) + tun_hdr_len > data_end)
        return XDP_DROP;

    /* =====================================================
     * 1. Ler tag primária (ida)
     * ===================================================== */
    struct tag160 tag_fwd;
    __builtin_memcpy(&tag_fwd,
                     data + sizeof(struct ethhdr),
                     sizeof(tag_fwd));

    /* =====================================================
     * 2. Lookup da tag reversa
     * ===================================================== */
    struct tag160 *tag_rev;
    tag_rev = bpf_map_lookup_elem(&tag_fr_h1, &tag_fwd);
    if (!tag_rev) {
        /* tag desconhecida → política conservadora */
        return XDP_DROP;
    }

    /* =====================================================
     * 3. Acessar cabeçalho IP original
     * ===================================================== */
    struct iphdr *iph = data + sizeof(struct ethhdr) + tun_hdr_len;
    if ((void *)(iph + 1) > data_end)
        return XDP_DROP;

    __u32 src_ip = iph->saddr;

    /* =====================================================
     * 4. Aprender IP → tag reversa
     * ===================================================== */
    bpf_map_update_elem(&ip_to_rtag_h1,
                        &src_ip,
                        tag_rev,
                        BPF_ANY);

    /* =====================================================
     * 5. DECAP — lógica original preservada
     * ===================================================== */

    /* salva Ethernet original */
    struct ethhdr eth_backup;
    __builtin_memcpy(&eth_backup, eth, sizeof(struct ethhdr));

    /* remove Ethernet + tag */
    if (bpf_xdp_adjust_head(ctx,
            sizeof(struct ethhdr) + tun_hdr_len))
        return XDP_ABORTED;

    /* recria espaço para Ethernet */
    if (bpf_xdp_adjust_head(ctx, -14))
    return XDP_ABORTED;

    /* recria espaço para Ethernet */
    // if (bpf_xdp_adjust_head(ctx, -sizeof(struct ethhdr)))
    //     return XDP_ABORTED;

    /* recarrega ponteiros */
    data     = (void *)(long)ctx->data;
    data_end = (void *)(long)ctx->data_end;

    if (data + sizeof(struct ethhdr) > data_end)
        return XDP_ABORTED;

    /* restaura Ethernet */
    eth = data;
    __builtin_memcpy(eth, &eth_backup, sizeof(struct ethhdr));
    eth->h_proto = bpf_htons(ETH_P_IP);

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
