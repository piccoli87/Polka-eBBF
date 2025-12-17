// encap.c — encapsulamento usando map compartilhado (ip_to_revtag_map)

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/pkt_cls.h>
#include <linux/if_ether.h>
#include <linux/ip.h>

/* ===== Estrutura da tag (20 bytes) ===== */
struct tag160 {
    __u8 bytes[20];
};

/* ============================================================
 * MAP COMPARTILHADO (PINNED)
 * IP destino -> tag reversa (20 bytes)
 * Criado e preenchido dinamicamente pelo decap.c
 * ============================================================ */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);              // IP destino (network byte order)
    __type(value, struct tag160);    // tag reversa
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} ip_to_rtag_h2 SEC(".maps");

/* ============================================================
 * TC egress — encapsulamento
 * ============================================================ */
SEC("tc")
int encap_func(struct __sk_buff *skb)
{
    void *data     = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return TC_ACT_SHOT;

    /* processa apenas IPv4 "normal" */
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return TC_ACT_OK;

    struct iphdr *iph = (struct iphdr *)(eth + 1);
    if ((void *)(iph + 1) > data_end)
        return TC_ACT_SHOT;

    /* =====================================================
     * 1. Lookup da tag reversa usando IP destino
     * ===================================================== */
    __u32 dst_ip = iph->daddr;   // network byte order

    struct tag160 *tag;
    tag = bpf_map_lookup_elem(&ip_to_rtag_h2, &dst_ip);
    if (!tag) {
        /* não há caminho reverso aprendido */
        return TC_ACT_OK;
    }

    /* =====================================================
     * 2. Abrir espaço para o header de 20 bytes
     * ===================================================== */
    if (bpf_skb_adjust_room(skb,
                            sizeof(struct tag160),
                            BPF_ADJ_ROOM_MAC,
                            0))
        return TC_ACT_SHOT;

    /* =====================================================
     * 3. Recarregar ponteiros após adjust_room
     * ===================================================== */
    data     = (void *)(long)skb->data;
    data_end = (void *)(long)skb->data_end;

    eth = data;
    if ((void *)(eth + 1) > data_end)
        return TC_ACT_SHOT;

    iph = (struct iphdr *)(eth + 1);
    if ((void *)(iph + 1) > data_end)
        return TC_ACT_SHOT;

    /* =====================================================
     * 4. Atualizar Ethertype para protocolo customizado
     * ===================================================== */
    eth->h_proto = bpf_htons(0x1234);

    /* =====================================================
     * 5. Inserir a tag de 20 bytes após o Ethernet
     * ===================================================== */
    if (bpf_skb_store_bytes(skb,
                            sizeof(struct ethhdr),
                            tag->bytes,
                            sizeof(tag->bytes),
                            0))
        return TC_ACT_SHOT;

    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
