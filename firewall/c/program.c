#define KBUILD_MODNAME "program"
#include <linux/bpf.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>

struct peer_rule_key {
  __u32 src_ip;
  __u32 dst_ip;
  __u16 port;
  __u8  proto;
  __u8  pad;
};

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 1024);
  __type(key, struct peer_rule_key);
  __type(value, __u32);
} peer_rules SEC(".maps");

volatile const __u32 filter_net  = 0;
volatile const __u32 filter_mask = 0;

SEC("xdp")
int filter(struct xdp_md *ctx) {
  void *data     = (void *)(long)ctx->data;
  void *data_end = (void *)(long)ctx->data_end;

  // WireGuard is L3 - packet starts at IP header
  struct iphdr *ip = data;
  if ((void *)(ip + 1) > data_end)
    return XDP_DROP;

  // Read ihl once into a local - the verifier tracks range per register,
  // so re-reading ip->ihl would produce an unconstrained scalar.
  __u32 ihl = ip->ihl;
  if (ihl < 5 || ihl > 15)
    return XDP_DROP;

  // Skip traffic outside the configured subnet
  if (filter_mask != 0 && (ip->saddr & filter_mask) != filter_net)
    return XDP_PASS;

  // Only filter TCP/UDP - pass everything else (ICMP, etc.)
  __u8 proto = ip->protocol;
  if (proto != IPPROTO_TCP && proto != IPPROTO_UDP)
    return XDP_PASS;

  // TCP and UDP dest port are at the same offset - use udphdr (smaller)
  // for the bounds check. Single pointer computation to satisfy verifier.
  __u32 ip_hdr_len = ihl * 4;
  struct udphdr *l4 = (struct udphdr *)(data + ip_hdr_len);
  if ((void *)(l4 + 1) > data_end)
    return XDP_DROP;

  struct peer_rule_key key = {
      .src_ip = ip->saddr,
      .dst_ip = ip->daddr,
      .port   = bpf_ntohs(l4->dest),
      .proto  = proto,
      .pad    = 0,
  };

  __u32 *action = bpf_map_lookup_elem(&peer_rules, &key);
  if (action && *action == 1)
    return XDP_PASS;

  return XDP_DROP;
}

char _license[] SEC("license") = "GPL";
