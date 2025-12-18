// encap.c — encapsulamento TC/ICMP com maps separados

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include <linux/pkt_cls.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/icmp.h>
#include <linux/in.h>   /* IPPROTO_TCP, IPPROTO_ICMP */


/* ============================================================
 * Estrutura da tag (20 bytes)
 * ============================================================ */
struct tag160 {
    __u8 bytes[20];
};

/* ============================================================
 * MAP TCP (PINNED)
 * IP destino -> tag reversa TCP
 * ============================================================ */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);              // IPv4 destino (network order)
    __type(value, struct tag160);    // tag TCP
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} ip_to_rtag_h2 SEC(".maps");

/* ============================================================
 * MAP ICMP (PINNED)
 * IP destino -> tag reversa ICMP
 * ============================================================ */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);              // IPv4 destino (network order)
    __type(value, struct tag160);    // tag ICMP
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} ip_tag_icmp_h2 SEC(".maps");

/* ============================================================
 * TC egress — encapsulamento
 * ============================================================ */
SEC("tc")
int encap_func(struct __sk_buff *skb)
{
    void *data     = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    /* ---------------- Ethernet ---------------- */
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return TC_ACT_SHOT;

    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return TC_ACT_OK;

    /* ---------------- IPv4 ---------------- */
    struct iphdr *iph = (struct iphdr *)(eth + 1);
    if ((void *)(iph + 1) > data_end)
        return TC_ACT_SHOT;

    __u32 dst_ip = iph->daddr;   // network byte order

    /* ---------------- Seleção do map ---------------- */
    struct tag160 *tag = NULL;

    if (iph->protocol == IPPROTO_TCP) {

        tag = bpf_map_lookup_elem(&ip_to_rtag_h2, &dst_ip);

    } else if (iph->protocol == IPPROTO_ICMP) {

        tag = bpf_map_lookup_elem(&ip_tag_icmp_h2, &dst_ip);

    } else {
        /* outros protocolos L4 não são encapsulados */
        return TC_ACT_OK;
    }

    if (!tag) {
        /* caminho reverso ainda não aprendido */
        return TC_ACT_OK;
    }

    /* =====================================================
     * Abrir espaço para a tag de 20 bytes
     * ===================================================== */
    if (bpf_skb_adjust_room(skb,
                            sizeof(struct tag160),
                            BPF_ADJ_ROOM_MAC,
                            0))
        return TC_ACT_SHOT;

    /* =====================================================
     * Recarregar ponteiros após adjust_room
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
     * Atualizar EtherType para protocolo customizado
     * ===================================================== */
    eth->h_proto = bpf_htons(0x1234);

    /* =====================================================
     * Inserir a tag de 20 bytes após o Ethernet
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
