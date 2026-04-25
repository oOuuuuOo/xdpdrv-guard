#define KBUILD_MODNAME "xdp_syn_guard"
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include <linux/udp.h>

/* IPv6 extension header protocol numbers — not always exposed by <linux/in.h>. */
#ifndef IPPROTO_HOPOPTS
#define IPPROTO_HOPOPTS  0
#endif
#ifndef IPPROTO_ROUTING
#define IPPROTO_ROUTING  43
#endif
#ifndef IPPROTO_FRAGMENT
#define IPPROTO_FRAGMENT 44
#endif
#ifndef IPPROTO_DSTOPTS
#define IPPROTO_DSTOPTS  60
#endif

/* 802.1Q / 802.1ad ethertypes — DOUBLE_TAG often missing on older headers. */
#ifndef ETH_P_8021Q
#define ETH_P_8021Q  0x8100
#endif
#ifndef ETH_P_8021AD
#define ETH_P_8021AD 0x88A8
#endif

struct vlan_hdr_local {
    __be16 h_vlan_TCI;
    __be16 h_vlan_encapsulated_proto;
};

#define SEC(NAME) __attribute__((section(NAME), used))

struct port_range { __u16 start; __u16 end; };

static __always_inline int is_allowed_tcp_port(__u16 dport_host) {
static const struct port_range allowed_tcp_ranges[] = { { .start = 34443, .end = 34443 }, };
static const __u32 allowed_tcp_ranges_len = 1;
  if (allowed_tcp_ranges_len == 0) {
        return 0;
    }
  for (__u32 i = 0; i < allowed_tcp_ranges_len; i++) {
    if (dport_host >= allowed_tcp_ranges[i].start && dport_host <= allowed_tcp_ranges[i].end) {
            return 1;
        }
    }
    return 0;
}

static __always_inline int is_allowed_udp_port(__u16 dport_host) {
static const struct port_range allowed_udp_ranges[] = { { .start = 0, .end = 0 } };
static const __u32 allowed_udp_ranges_len = 0;
  if (allowed_udp_ranges_len == 0) {
        return 1;
    }
  for (__u32 i = 0; i < allowed_udp_ranges_len; i++) {
    if (dport_host >= allowed_udp_ranges[i].start && dport_host <= allowed_udp_ranges[i].end) {
            return 1;
        }
    }
    return 0;
}

static __always_inline int parse_l4_guard(void *data, void *data_end, __u16 h_proto, __u64 nh_off) {
    if (h_proto == __builtin_bswap16(ETH_P_IP)) {
        struct iphdr *iph = data + nh_off;
        if ((void *)(iph + 1) > data_end) return XDP_PASS;

        /*
         * Later-fragment IPv4 packets carry no L4 header; we can't read
         * dport, so we have nothing to filter on — pass to kernel.
         */
        __u16 frag_off_h = __builtin_bswap16(iph->frag_off);
        if ((frag_off_h & 0x1FFF) != 0) {
            return XDP_PASS;
        }

        if (iph->protocol == IPPROTO_TCP) {
            __u64 ihl_len = (__u64)iph->ihl * 4;
            struct tcphdr *tcph = (void *)iph + ihl_len;
            if ((void *)(tcph + 1) > data_end) return XDP_PASS;

            if (tcph->syn && !tcph->ack) {
                __u16 dport = __builtin_bswap16(tcph->dest);
                if (!is_allowed_tcp_port(dport)) {
                    return XDP_DROP;
                }
            }
            return XDP_PASS;
        }

        if (iph->protocol == IPPROTO_UDP) {
            __u64 ihl_len = (__u64)iph->ihl * 4;
            struct udphdr *udph = (void *)iph + ihl_len;
            if ((void *)(udph + 1) > data_end) return XDP_PASS;

            __u16 dport = __builtin_bswap16(udph->dest);
            if (!is_allowed_udp_port(dport)) {
                return XDP_DROP;
            }
            return XDP_PASS;
        }

        return XDP_PASS;
    }

    if (h_proto == __builtin_bswap16(ETH_P_IPV6)) {
        struct ipv6hdr *ip6h = data + nh_off;
        if ((void *)(ip6h + 1) > data_end) return XDP_PASS;

        /*
         * Walk IPv6 extension header chain (HBH/DESTOPT/ROUTING) before
         * touching L4. Fragment header => no full L4 in this packet, PASS.
         * Bounded by 6 iterations so the verifier accepts the loop.
         */
        __u8 nexthdr = ip6h->nexthdr;
        unsigned char *cur = (unsigned char *)(ip6h + 1);

        #pragma unroll
        for (int __i = 0; __i < 6; __i++) {
            if (nexthdr == IPPROTO_TCP || nexthdr == IPPROTO_UDP) break;
            if (nexthdr == IPPROTO_HOPOPTS ||
                nexthdr == IPPROTO_DSTOPTS ||
                nexthdr == IPPROTO_ROUTING) {
                struct ipv6_opt_hdr *opt = (struct ipv6_opt_hdr *)cur;
                if ((void *)(opt + 1) > data_end) return XDP_PASS;
                __u32 hdr_len = ((__u32)opt->hdrlen + 1) * 8;
                if ((void *)(cur + hdr_len) > data_end) return XDP_PASS;
                nexthdr = opt->nexthdr;
                cur += hdr_len;
                continue;
            }
            if (nexthdr == IPPROTO_FRAGMENT) {
                /* Fragmented v6 packet — no usable L4 header here. */
                return XDP_PASS;
            }
            /* AH, ESP, MH, NONE, unknown — let kernel handle. */
            return XDP_PASS;
        }

        if (nexthdr == IPPROTO_TCP) {
            struct tcphdr *tcph = (struct tcphdr *)cur;
            if ((void *)(tcph + 1) > data_end) return XDP_PASS;

            if (tcph->syn && !tcph->ack) {
                __u16 dport = __builtin_bswap16(tcph->dest);
                if (!is_allowed_tcp_port(dport)) {
                    return XDP_DROP;
                }
            }
            return XDP_PASS;
        }

        if (nexthdr == IPPROTO_UDP) {
            struct udphdr *udph = (struct udphdr *)cur;
            if ((void *)(udph + 1) > data_end) return XDP_PASS;

            __u16 dport = __builtin_bswap16(udph->dest);
            if (!is_allowed_udp_port(dport)) {
                return XDP_DROP;
            }
            return XDP_PASS;
        }

        return XDP_PASS;
    }

    return XDP_PASS;
}

SEC("xdp")
int xdp_syn_guard(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) {
        return XDP_PASS;
    }

    __u16 h_proto = eth->h_proto;
    __u64 nh_off = sizeof(*eth);

    /*
     * Unwrap up to two VLAN tags (covers single-tagged 802.1Q and
     * Q-in-Q / 802.1ad). Without this, VLAN-trunked traffic on the host
     * NIC bypasses the SYN guard entirely.
     */
    #pragma unroll
    for (int __vi = 0; __vi < 2; __vi++) {
        if (h_proto != __builtin_bswap16(ETH_P_8021Q) &&
            h_proto != __builtin_bswap16(ETH_P_8021AD)) break;
        struct vlan_hdr_local *vh = (struct vlan_hdr_local *)((unsigned char *)data + nh_off);
        if ((void *)(vh + 1) > data_end) return XDP_PASS;
        h_proto = vh->h_vlan_encapsulated_proto;
        nh_off += sizeof(*vh);
    }

    return parse_l4_guard(data, data_end, h_proto, nh_off);
}

char _license[] SEC("license") = "GPL";
