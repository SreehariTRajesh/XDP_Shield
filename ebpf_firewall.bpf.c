#include <uapi/linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>

BPF_HASH(allowed_ips, u32);

int xdp_firewall(struct xdp_md *ctx) {
    void * data = (void *) (long) ctx->data;
    void * data_end = (void *) (long) ctx->data_end;

    struct ethhdr *eth = data;

    if(data + sizeof(struct ethhdr) > data_end) 
    {
        return XDP_PASS;
    }

    if(eth->h_proto != __constant_htons(ETH_P_IP)) 
    {
        return XDP_PASS;
    }

    struct iphdr *ip = data + sizeof(struct ethhdr);

    if(data + sizeof(struct ethhdr) + sizeof(struct iphdr) > data_end) 
    {
        return XDP_PASS;
    }

    if(ip->protocol != IPPROTO_TCP) 
    {
        return XDP_PASS;
    }

    struct tcphdr *tcp = data + sizeof(struct ethhdr) + sizeof(struct iphdr);

    if(data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct tcphdr) > data_end)
    {
        return XDP_PASS;
    }

    if(tcp->dest != __constant_htons(3333)) 
    {
        return XDP_PASS;
    }

    __u32 key = ip->saddr;
    __u32 * value  = allowed_ips.lookup(&key);

    if(value) {
        bpf_trace_printk("Authorized TCP packet to ssh !\n");
        return XDP_PASS;
    }

    bpf_trace_printk("Unauthorized TCP Packet To SSH\n");

    return XDP_DROP;
}