#include "xdp_lb_kern.h"

#define IP_ADDRESS(x) (unsigned int)(172 + (17 << 8) + (0 << 16) + (x << 24))

#define CLIENT_IP (unsigned int)(172 + 31 + 10 + 0)
#define PROXY_IP (unsigned int)(172 + 31 + 11 + 0)
#define RECP_IP1 (unsigned int)(172 + 31 + 12 + 0)
#define RECP_IP2 (unsigned int)(172 + 31 + 12 + 1)

#define CLIENT_MAC (unsigned int)(02:a1:16:74:c7:37)

#define BACKEND_A 2
#define BACKEND_B 3
#define CLIENT 4
#define LB 5

SEC("xdp_lb")
int xdp_load_balancer(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if (data + sizeof(struct ethhdr) > data_end)
        return XDP_ABORTED;

    if (bpf_ntohs(eth->h_proto) != ETH_P_IP)
        return XDP_PASS;

    struct iphdr *iph = data + sizeof(struct ethhdr);
    if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) > data_end)
        return XDP_ABORTED;

    if (iph->protocol != IPPROTO_UDP)
        return XDP_PASS;

    bpf_printk("Got UDP packet from %x \n", iph->saddr);

    unsigned char client_mac[] = {0x02, 0xa1, 0x16, 0x74, 0xc7, 0x37};
    unsigned char proxy_mac[] = {0x02, 0x95, 0x89, 0x6d, 0x91, 0xe3};
    unsigned char recp_mac1[] = {0x02, 0xf0, 0xc8, 0xe5, 0xd6, 0x67};
    unsigned char recp_mac2[] = {0x02, 0x9d, 0x0f, 0x11, 0xba, 0x09};

    if (iph->saddr == CLIENT_IP)
    {
        // char be = BACKEND_A;
        // if (bpf_ktime_get_ns() % 2)
        //     be = BACKEND_B;
        bpf_printk("Hit if branch\n");
        iph->daddr = RECP_IP1;
        
        eth->h_dest[0] = recp_mac1[0];
        eth->h_dest[1] = recp_mac1[1];
        eth->h_dest[2] = recp_mac1[2];
        eth->h_dest[3] = recp_mac1[3];
        eth->h_dest[4] = recp_mac1[4];
        eth->h_dest[5] = recp_mac1[5];
    }
    else
    {
        bpf_printk("Hit else branch\n");
        iph->daddr = RECP_IP1;
        
        eth->h_dest[0] = recp_mac1[0];
        eth->h_dest[1] = recp_mac1[1];
        eth->h_dest[2] = recp_mac1[2];
        eth->h_dest[3] = recp_mac1[3];
        eth->h_dest[4] = recp_mac1[4];
        eth->h_dest[5] = recp_mac1[5];
        
        // iph->daddr = CLIENT_IP;
        // eth->h_dest[0] = client_mac[0];
        // eth->h_dest[1] = client_mac[1];
        // eth->h_dest[2] = client_mac[2];
        // eth->h_dest[3] = client_mac[3];
        // eth->h_dest[4] = client_mac[4];
        // eth->h_dest[5] = client_mac[5];
    }
    iph->saddr = PROXY_IP;
    eth->h_source[0] = proxy_mac[0];
    eth->h_source[1] = proxy_mac[1];
    eth->h_source[2] = proxy_mac[2];
    eth->h_source[3] = proxy_mac[3];
    eth->h_source[4] = proxy_mac[4];
    eth->h_source[5] = proxy_mac[5];

    iph->check = iph_csum(iph);

    return XDP_TX;
}

char _license[] SEC("license") = "GPL";
