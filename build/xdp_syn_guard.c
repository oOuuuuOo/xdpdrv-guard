#define KBUILD_MODNAME "xdp_syn_guard"
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include <linux/udp.h>

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
        if (ip6h->nexthdr == IPPROTO_TCP) {
            struct tcphdr *tcph = (void *)(ip6h + 1);
            if ((void *)(tcph + 1) > data_end) return XDP_PASS;

            if (tcph->syn && !tcph->ack) {
                __u16 dport = __builtin_bswap16(tcph->dest);
                if (!is_allowed_tcp_port(dport)) {
                    return XDP_DROP;
                }
            }
            return XDP_PASS;
        }

        if (ip6h->nexthdr == IPPROTO_UDP) {
            struct udphdr *udph = (void *)(ip6h + 1);
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

    return parse_l4_guard(data, data_end, h_proto, nh_off);
}

char _license[] SEC("license") = "GPL";
