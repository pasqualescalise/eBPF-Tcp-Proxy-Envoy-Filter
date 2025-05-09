#include <linux/bpf.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/pkt_cls.h>

#include "ebpf/ebpf_tcp_proxy_log.h"

#define MIDDLEWARE_PORT 4444
#define MAX_TCP_SIZE 1480 // XXX: huge approximation but it works
#define MAX_ENTRIES_MAP 65536

// Get the interface index to redirect packets to
// XXX: can be replaced with a HASH to support multiple interfaces
struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __type(key, __u32);
  __type(value, int);
  __uint(max_entries, 1);
} interface_index_map SEC(".maps");

// Map each connection to its parameters
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __type(key, struct connection_fingerprint);
  __type(value, struct connection_parameters);
  __uint(max_entries, MAX_ENTRIES_MAP);
} connection_fingerprint_to_connection_parameters_map SEC(".maps");

// Map each connection to its respective one (Client <-> Server)
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __type(key, struct connection_fingerprint);
  __type(value, struct connection_fingerprint);
  __uint(max_entries, MAX_ENTRIES_MAP);
} connection_fingerprint_to_connection_fingerprint_map SEC(".maps");

struct connection_fingerprint {
  unsigned int ip;
  unsigned int port;
};

struct tcp_timestamps_option {
  unsigned int tsval;
  unsigned int tsecr;
};

// Parameters to remember and update each time a packet arrives
struct connection_parameters {
  // Ethernet
  unsigned char source_mac[ETH_ALEN];
  unsigned char destination_mac[ETH_ALEN];

  // IP
  unsigned int source_address;
  unsigned int destination_address;

  // TCP
  unsigned int source_port;
  unsigned int destination_port;
  unsigned int base_sequence_number;
  unsigned int base_ack_number;
  struct tcp_timestamps_option timestamps;

  int seen_fin;
  int tc_ack_counter;

  // counter
  int packet_counter;
};

// How much to increment the TCP numbers
struct tcp_sequence_ack_numbers_increment {
  unsigned int sequence_increment;
  unsigned int ack_increment;
};

/* Parse headers */

static __always_inline int parse_ethhdr(void* data, void* data_end, __u16* nh_off,
                                        struct ethhdr** ethhdr) {
  struct ethhdr* eth = (struct ethhdr*)data;
  int hdr_size = sizeof(*eth);

  /* Byte-count bounds check; check if current pointer + size of header
   * is after data_end.
   */
  if ((void*)eth + hdr_size > data_end)
    return -1;

  *nh_off += hdr_size;
  *ethhdr = eth;

  return eth->h_proto; /* network-byte-order */
}

static __always_inline int parse_iphdr(void* data, void* data_end, __u16* nh_off,
                                       struct iphdr** iphdr) {
  struct iphdr* ip = data + *nh_off;
  int hdr_size = sizeof(struct iphdr);

  // bounds checking
  if ((void*)ip + hdr_size > data_end) {
    return -1;
  }

  hdr_size = ip->ihl * 4;

  // bounds checking now with the actual header size
  if ((void*)ip + hdr_size > data_end) {
    return -1;
  }

  *nh_off += hdr_size;
  *iphdr = ip;

  return hdr_size;
}

static __always_inline int parse_tcphdr(void* data, void* data_end, __u16* nh_off,
                                        struct tcphdr** tcphdr) {
  struct tcphdr* tcp = data + *nh_off;
  int hdr_size = sizeof(struct tcphdr);

  // bounds checking
  if ((void*)tcp + hdr_size > data_end) {
    return -1;
  }

  hdr_size = tcp->doff * 4;

  // bounds checking now with the actual header size
  if (data + *nh_off + hdr_size > data_end) {
    return -1;
  }

  *nh_off += hdr_size;
  *tcphdr = tcp;

  return hdr_size;
}

/**
 * Parse the Ethernet, IP and TCP headers: if a packet does not have these
 * three headers, return -1; otherwise, return 0
 */
static __always_inline int parse_headers(void* data, void* data_end, struct ethhdr** eth,
                                         struct iphdr** ip, struct tcphdr** tcp, __u16* tcp_start,
                                         int* tcp_hdr_size) {
  int err;

  // keep track of layers, each time peeling off a header
  __u16 nf_off = 0;
  int hdr_size;

  /* LAYER 2: ETHERNET */

  __u16 eth_type = parse_ethhdr(data, data_end, &nf_off, eth);

  if (data + sizeof(struct ethhdr) > data_end) {
    bpf_log_err("Packet is not a valid Ethernet packet, dropping it");
    return -1;
  }

  /* LAYER 3: IP */

  if (eth_type != bpf_ntohs(ETH_P_IP)) {
    bpf_log_warning("Packet is not IPv4, passing it");
    return -1;
  }

  hdr_size = parse_iphdr(data, data_end, &nf_off, ip);
  if (hdr_size < 0) {
    bpf_log_warning("Packet is not a valid IPv4 packet, dropping it");
    return -1;
  }

  /* LAYER 4: TCP */

  if ((*ip)->protocol != IPPROTO_TCP) {
    bpf_log_warning("Packet is not TCP, passing it");
    return -1;
  }

  *tcp_start = nf_off;

  hdr_size = parse_tcphdr(data, data_end, &nf_off, tcp);
  if (hdr_size < 0) {
    bpf_log_warning("Packet is not a valid TCP packet, dropping it");
    return -1;
  }

  *tcp_hdr_size = hdr_size;

  return 0;
}

/* TCP Timestamps */
static __always_inline void calculate_timestamps(unsigned int* tsval, unsigned int* tsecr,
                                                 struct tcp_timestamps_option* this_timestamps,
                                                 struct tcp_timestamps_option* other_timestamps,
                                                 int swap_timestamps, int active_connection) {
  // bpf_printk("Swap timestamps: %d Active connection: %d Other timestamps: %p", swap_timestamps,
  // active_connection, other_timestamps);

  // extract the timestamps
  unsigned int extracted_tsval = *tsval;
  unsigned int extracted_tsecr = *tsecr;
  // bpf_printk("Extracted TSval: %u Extracted TSecr: %u", bpf_htonl(extracted_tsval),
  // bpf_htonl(extracted_tsecr));

  // swap the timestamps in the fake FINs
  if (swap_timestamps) {
    *tsval = extracted_tsecr;
    *tsecr = extracted_tsval;
    // bpf_printk("This packet new TSval: %u This packet new TSecr: %u", bpf_htonl(*tsval),
    // bpf_htonl(*tsecr));
    return;
  }

  // update the timestamps the other connection using the ones of this connection
  if (other_timestamps != NULL) {
    // bpf_printk("This old TSval: %u This old TSecr: %u", bpf_htonl(this_timestamps->tsval),
    // bpf_htonl(this_timestamps->tsecr));

    // how much has the timestamp increased
    unsigned int increase = 0;
    if (active_connection) {
      increase = bpf_htonl(extracted_tsval) - bpf_htonl(this_timestamps->tsecr);
    } else {
      increase = bpf_htonl(extracted_tsval) - bpf_htonl(this_timestamps->tsval);
    }
    // bpf_printk("Increase: %u", increase);

    // save the timestamps of this connection
    // TODO: check this

    // save the new timestamps
    // bpf_printk("Other old TSval: %u Other old TSecr: %u", bpf_htonl(other_timestamps->tsval),
    // bpf_htonl(other_timestamps->tsecr));
    if (active_connection) {
      this_timestamps->tsecr = extracted_tsval;
      other_timestamps->tsval = bpf_htonl(bpf_htonl(other_timestamps->tsval) + increase);
    } else {
      this_timestamps->tsval = extracted_tsval;
      other_timestamps->tsecr = bpf_htonl(bpf_htonl(other_timestamps->tsecr) + increase);
    }
    // bpf_printk("Other new TSval: %u Other new TSecr: %u", bpf_htonl(other_timestamps->tsval),
    // bpf_htonl(other_timestamps->tsecr));

    // set the packet timestamps
    if (active_connection) {
      *tsval = other_timestamps->tsecr;
      *tsecr = other_timestamps->tsval;
    } else {
      *tsval = other_timestamps->tsval;
      *tsecr = other_timestamps->tsecr;
    }
    // bpf_printk("This packet new TSval: %u This packet new TSecr: %u", bpf_htonl(*tsval),
    // bpf_htonl(*tsecr));
    return;
  }

  // save the timestamps without actually swapping them
  if (active_connection) {
    this_timestamps->tsval = extracted_tsecr;
    this_timestamps->tsecr = extracted_tsval;
    // bpf_printk("Active Saving TSval: %u Saving TSecr: %u", bpf_htonl(this_timestamps->tsval),
    // bpf_htonl(this_timestamps->tsecr));
  } else {
    this_timestamps->tsval = extracted_tsval;
    this_timestamps->tsecr = extracted_tsecr;
    // bpf_printk("Passive Saving TSval: %u Saving TSecr: %u", bpf_htonl(this_timestamps->tsval),
    // bpf_htonl(this_timestamps->tsecr));
  }
}

struct tcp_timestamps_ctx {
  void* data;
  void* data_end;

  __u16 tcp_options_start_offset;

  // how many cycles to skip
  int skip;

  struct tcp_timestamps_option* this_timestamps;
  struct tcp_timestamps_option* other_timestamps;

  // 1 if we only need to increment the current timestamps
  int swap_timestamps;

  int active_connection;
};

/**
 * Function meant to be called in bpf_loop
 *
 * Loop until the TCP Timestamps option is reached, then extract the timestamps
 * and update them with the one passed in the context
 *
 * To just extract the timestamps, just put ctx->new_timestamps = NULL
 */
static long extract_and_update_tcp_timestamps_loop(unsigned int index, void* _ctx) {
  struct tcp_timestamps_ctx* ctx = (struct tcp_timestamps_ctx*)_ctx;

  __u8* data = (__u8*)(long)ctx->data;
  __u8* data_end = (__u8*)(long)ctx->data_end;

  bpf_log_debug("Skip: %d", ctx->skip);
  if (ctx->skip > 0) {
    ctx->skip--;
    return 0;
  }

  // XXX: make sure that the verifier knows index is 2 bytes long max
  index = (index + ctx->tcp_options_start_offset) & 0x7FFF;

  // Type
  unsigned char* option_type = data + index;

  if (option_type + 1 > data_end) {
    return 1;
  }

  bpf_log_debug("Type: %d", *option_type);

  // No-Operation option
  if (*option_type == 0x01) {
    return 0;
  }

  // another option
  if (*option_type != 0x08) {
    unsigned char* option_len = data + index + 1;

    if (option_len + 1 > data_end) {
      return 1;
    }

    bpf_log_debug("Len: %d", *option_len);
    // loop until the option is finished
    ctx->skip = *option_len - 1;
    return 0;
  }

  // Timestamps option
  unsigned int* tsval = (unsigned int*)(data + index + 2);

  if ((void*)tsval + 4 > (void*)data_end) {
    return 1;
  }

  unsigned int* tsecr = (unsigned int*)(data + index + 6);

  if ((void*)tsecr + 4 > (void*)data_end) {
    return 1;
  }

  calculate_timestamps(tsval, tsecr, ctx->this_timestamps, ctx->other_timestamps,
                       ctx->swap_timestamps, ctx->active_connection);

  return 1;
}

/**
 * Try to parse the TCP options faster by assuming that the options are NOOP-NOOP-TIMESTAMPS;
 * this avoids using the slower bpf_loop
 *
 * Inspired by the Linux kernel
 */
static int fast_extract_and_update_tcp_timestamps_option(
    void* data, void* data_end, __u16 tcp_start, int tcp_hdr_size,
    struct tcp_timestamps_option* this_timestamps, struct tcp_timestamps_option* other_timestamps,
    int swap_timestamps, int active_connection) {
  __u16 tcp_options_start_offset = (tcp_start + sizeof(struct tcphdr)) & 0x7FFF;

  unsigned char* noop1 = data + tcp_options_start_offset;
  unsigned char* noop2 = data + (tcp_options_start_offset + 1);
  unsigned char* type = data + (tcp_options_start_offset + 2);

  if ((void*)noop1 + 1 > data_end || (void*)noop2 + 1 > data_end || (void*)type + 1 > data_end) {
    return -1;
  }

  if (*noop1 != 0x01 && *noop2 != 0x01 && *type != 0x08) {
    return -1;
  }

  bpf_log_info("Fast path for TCP options");

  unsigned int* tsval = (unsigned int*)(data + tcp_options_start_offset + 4);

  if ((void*)tsval + 4 > (void*)data_end) {
    return -1;
  }

  unsigned int* tsecr = (unsigned int*)(data + tcp_options_start_offset + 8);

  if ((void*)tsecr + 4 > (void*)data_end) {
    return -1;
  }

  calculate_timestamps(tsval, tsecr, this_timestamps, other_timestamps, swap_timestamps,
                       active_connection);

  return 0;
}

/**
 * Extract the TCP timestamps and put them in extracted_timestamps; if new_timestamps is not NULL,
 * also update them
 */
static __always_inline int extract_and_update_tcp_timestamps_option(
    void* data, void* data_end, __u16 tcp_start, int tcp_hdr_size,
    struct tcp_timestamps_option* this_timestamps, struct tcp_timestamps_option* other_timestamps,
    int swap_timestamps, int active_connection) {

  // FIXME: return 0;
  int err = 0;

  // try doing it without the bpf_loop
  err = fast_extract_and_update_tcp_timestamps_option(data, data_end, tcp_start, tcp_hdr_size,
                                                      this_timestamps, other_timestamps,
                                                      swap_timestamps, active_connection);
  if (err == 0) {
    return 0;
  }

  bpf_log_info("Slow path for TCP options - expected for SYN packets");

  struct tcp_timestamps_ctx loop_ctx = {.data = data,
                                        .data_end = data_end,

                                        .tcp_options_start_offset =
                                            tcp_start + sizeof(struct tcphdr),

                                        .skip = 0,

                                        .this_timestamps = this_timestamps,
                                        .other_timestamps = other_timestamps,

                                        .swap_timestamps = swap_timestamps,

                                        .active_connection = active_connection};

  int nr = bpf_loop(tcp_hdr_size, (void*)extract_and_update_tcp_timestamps_loop, &loop_ctx, 0);
  if (nr < 0) {
    bpf_log_err("Error in extract_and_update_tcp_timestamps_loop");
    return nr;
  }

  return 0;
}

/* Checksum */
// All checksum functions have been provided by <https://github.com/fshahinfar1/kashk> and
// <https://github.com/Whi1el/xdp-tutorial> with a few changes
__attribute__((__always_inline__)) static inline __u16 csum_fold_helper(__u64 csum) {
  int i;
#pragma unroll
  for (i = 0; i < 4; i++) {
    if (csum >> 16)
      csum = (csum & 0xffff) + (csum >> 16);
  }

  return ~csum;
}

static inline void ipv4_csum_inline(void* iph, unsigned long long* csum) {
  unsigned int i;
  unsigned short* next_iph_u16 = (unsigned short*)iph;
#pragma clang loop unroll(full)
  for (i = 0; i < sizeof(struct iphdr) >> 1; i++) {
    *csum += bpf_ntohs(*next_iph_u16);
    next_iph_u16++;
  }
  *csum = csum_fold_helper(*csum);
}

__attribute__((__always_inline__)) static inline void
ipv4_l4_csum(void* data_start, int data_size, __u64* csum, struct iphdr* iph, void* data_end) {
  __u32 tmp = 0;
  *csum = bpf_csum_diff(0, 0, &iph->saddr, sizeof(__be32), *csum);
  *csum = bpf_csum_diff(0, 0, &iph->daddr, sizeof(__be32), *csum);

  tmp = bpf_htonl((__u32)(iph->protocol));
  *csum = bpf_csum_diff(0, 0, &tmp, sizeof(__u32), *csum);
  tmp = bpf_htonl((__u32)(data_size));
  *csum = bpf_csum_diff(0, 0, &tmp, sizeof(__u32), *csum);

  // Compute checksum from scratch by a bounded loop
  __u16* buf = data_start;
  for (int i = 0; i < MAX_TCP_SIZE; i += 2) {
    if ((void*)(buf + 1) > data_end) {
      break;
    }
    *csum += *buf;
    buf++;
  }

  if ((void*)(buf) < data_end) {
    *csum += *(__u8*)buf;
  }

  *csum = csum_fold_helper(*csum);
}

static void update_ip_checksum(struct iphdr* ip) {
  ip->check = 0;
  __u64 csum = 0;
  ipv4_csum_inline(ip, &csum);
  ip->check = bpf_htons(csum);
}

static void update_tcp_checksum(void* data, void* data_end, struct iphdr* ip, struct tcphdr* tcp) {
  tcp->check = 0;
  __u64 csum = 0;
  int tcplen = bpf_ntohs(ip->tot_len) - ip->ihl * 4;
  ipv4_l4_csum((void*)tcp, tcplen, &csum, ip, data_end);
  tcp->check = csum;
}

/* Redirecting */

/**
 * Redirect packets using the interface_index_map
 *
 * Works for both XDP and TC
 *
 * XXX: I had problems with DEVMAPs and TC, this is a good medium that can be used by both programs
 */
static long bpf_redirect_array(__u64 flags) {
  int zero = 0;
  int* interface_index = (int*)bpf_map_lookup_elem(&interface_index_map, &zero);
  if (interface_index == NULL) {
    return -1;
  }

  return bpf_redirect(*interface_index, flags);
}

/* XDP - REDIRECT PACKET */

/* New Connection */
/**
 * Get all the parameters of the new connection and put them in the
 * connection_fingerprint_to_connection_parameters_map
 */
static __always_inline int add_new_connection(void* data, void* data_end, struct ethhdr* eth,
                                              struct iphdr* ip, struct tcphdr* tcp, __u16 tcp_start,
                                              int tcp_hdr_size,
                                              struct connection_fingerprint* new_connection) {
  int err;

  struct connection_parameters params;

  // XXX: needed for the verifier <https://github.com/iovisor/bcc/issues/2623>
  __builtin_memset(&params, 0, sizeof(params));

  // Ethernet
  __builtin_memcpy(params.source_mac, eth->h_source, ETH_ALEN);
  __builtin_memcpy(params.destination_mac, eth->h_dest, ETH_ALEN);

  // IP
  params.source_address = ip->saddr;
  params.destination_address = ip->daddr;

  // TCP
  params.source_port = tcp->source;
  params.destination_port = tcp->dest;

  params.base_sequence_number = tcp->seq;
  params.base_ack_number = 0;

  // for Clients we have SYNs and for Servers SYN/ACKs,
  // in the Client case we get the ack number later
  if (tcp->syn && tcp->ack) {
    params.base_ack_number = bpf_ntohl(bpf_ntohl(tcp->ack_seq) - 1);
  }

  // extract the timestamps
  if (tcp->syn && tcp->ack) {
    err = extract_and_update_tcp_timestamps_option(data, data_end, tcp_start, tcp_hdr_size,
                                                   &(params.timestamps), NULL, 0, 1);
  } else {
    err = extract_and_update_tcp_timestamps_option(data, data_end, tcp_start, tcp_hdr_size,
                                                   &(params.timestamps), NULL, 0, 0);
  }

  if (err < 0) {
    return err;
  }

  // counter
  params.packet_counter = 1;

  err = bpf_map_update_elem(&connection_fingerprint_to_connection_parameters_map, new_connection,
                            &params, BPF_ANY);
  if (err < 0) {
    return err;
  }

  return 0;
}

/**
 * If the packet is a TCP SYN, add the connection parameters to the
 * connection_fingerprint_to_connection_parameters_map
 */
static __always_inline int handle_new_connection(void* data, void* data_end, struct ethhdr* eth,
                                                 struct iphdr* ip, struct tcphdr* tcp,
                                                 __u16 tcp_start, int tcp_hdr_size,
                                                 struct connection_fingerprint* new_connection) {
  int err;

  if (tcp->syn != 1) {
    bpf_log_err("Unexpected packet");
    return -1;
  }

  bpf_log_notice("New connection");

  err = add_new_connection(data, data_end, eth, ip, tcp, tcp_start, tcp_hdr_size, new_connection);
  if (err < 0) {
    bpf_log_err("Error while adding new connection");
    return err;
  }

  return 0;
}

/* Existing Connection */
/**
 * Update all the Ethernet, IP and TCP fields of the packet to match the ones
 * of the other connection
 *
 * As a side effect, also extract the Timestamps option of the packet; this is
 * done here to avoid scanning the packet twice
 */
static __always_inline int update_packet(void* data, void* data_end, struct ethhdr* eth,
                                         struct iphdr* ip, struct tcphdr* tcp, __u16 tcp_start,
                                         int tcp_hdr_size, struct connection_parameters* params,
                                         struct tcp_timestamps_option* extracted_timestamps,
                                         struct tcp_sequence_ack_numbers_increment increment,
                                         int active_connection) {
  int err;

  // Ethernet
  __builtin_memcpy(eth->h_source, params->destination_mac, ETH_ALEN);
  __builtin_memcpy(eth->h_dest, params->source_mac, ETH_ALEN);

  // IP
  ip->saddr = params->destination_address;
  ip->daddr = params->source_address;

  update_ip_checksum(ip);

  // TCP
  tcp->source = params->destination_port;
  tcp->dest = params->source_port;

  // sequence numbers
  tcp->seq = bpf_htonl(bpf_htonl(params->base_ack_number) + increment.sequence_increment);
  tcp->ack_seq = bpf_htonl(bpf_htonl(params->base_sequence_number) + increment.ack_increment);

  bpf_log_debug("New sequence number: %u New ACK number: %u", bpf_ntohl(tcp->seq),
                bpf_ntohl(tcp->ack_seq));

  // timestamps
  err = extract_and_update_tcp_timestamps_option(data, data_end, tcp_start, tcp_hdr_size,
                                                 extracted_timestamps, &params->timestamps, 0,
                                                 active_connection);
  if (err < 0) {
    bpf_log_err("Error while updating the TCP Timestamps option");
    return err;
  }

  // checksum
  update_tcp_checksum(data, data_end, ip, tcp);

  return 0;
}

/**
 * Update the connection parameters and change the packet fields for redirection
 *
 * Returns 0 on success, 1 if the packet needs to be passed or a negative number on error
 */
static __always_inline int
handle_existing_connection(void* data, void* data_end, struct ethhdr* eth, struct iphdr* ip,
                           struct tcphdr* tcp, __u16 tcp_start, int tcp_hdr_size,
                           struct connection_fingerprint connection,
                           struct connection_parameters* params, int active_connection) {
  int err = 0;

  // this should never happen
  // TODO: check if we should do something to parameters if this happens
  if (tcp->syn) {
    bpf_log_err("Received SYN while handling existing connection");
    return -1;
  }

  params->packet_counter++;

  // on both connections, the second ACK packet is important:
  // + for the Client, it's the ACK of the handshake (get the base ack number
  //   we missed in add_new_connection), so it must be passed
  // + for the Server, it's the ACK of the first Client packet; its connection has already been
  //   closed, so this ACK must be dropped
  if (tcp->ack && !tcp->psh && params->packet_counter == 2) {
    if (params->base_ack_number == 0) {
      params->base_ack_number = bpf_ntohl(bpf_ntohl(tcp->ack_seq) - 1);
      extract_and_update_tcp_timestamps_option(data, data_end, tcp_start, tcp_hdr_size,
                                               &params->timestamps, NULL, 0, 0);
      bpf_log_notice("Passing this ACK");
      return XDP_PASS;
    } else {
      extract_and_update_tcp_timestamps_option(data, data_end, tcp_start, tcp_hdr_size,
                                               &params->timestamps, NULL, 0, 1);
      bpf_log_notice("Dropping this ACK");
      return XDP_DROP;
    }
  }

  // get the increment of the sequence numbers
  struct tcp_sequence_ack_numbers_increment increment = {
      .sequence_increment = bpf_ntohl(tcp->seq) - bpf_ntohl(params->base_sequence_number),
      .ack_increment = bpf_ntohl(tcp->ack_seq) - bpf_ntohl(params->base_ack_number)};

  // get the other connection
  struct connection_fingerprint* other_conn = (struct connection_fingerprint*)bpf_map_lookup_elem(
      &connection_fingerprint_to_connection_fingerprint_map, &connection);
  if (other_conn == NULL) {
    bpf_log_warning("No mapping (expected for the first PUSH/ACK)");
    return -1;
  }

  bpf_log_info("OtherIP: %u, OtherPort: %u", other_conn->ip, other_conn->port);

  // get the parameters of the other connection
  struct connection_parameters* other_params = (struct connection_parameters*)bpf_map_lookup_elem(
      &connection_fingerprint_to_connection_parameters_map, other_conn);
  if (other_params == NULL) {
    bpf_log_warning("No reverse");
    return -1;
  }

  // prepare the packet headers to redirect it
  err = update_packet(data, data_end, eth, ip, tcp, tcp_start, tcp_hdr_size, other_params,
                      &params->timestamps, increment, active_connection);
  if (err < 0) {
    bpf_log_err("Error while updating the packet");
    return err;
  }

  if (tcp->fin) {
    bpf_log_info("Seen FIN packet");
    params->seen_fin = 1;
  }

  // if we have seen both FINs, this is the last ACK, delete the map entries
  if (!tcp->fin && tcp->ack && params->seen_fin && other_params->seen_fin || tcp->rst) {
    bpf_log_info("Finished communication, deleting map entries");
    err = bpf_map_delete_elem(&connection_fingerprint_to_connection_fingerprint_map, &connection);
    if (err < 0) {
      bpf_log_err("Error while deleting the connection");
    }
    err = bpf_map_delete_elem(&connection_fingerprint_to_connection_parameters_map, &connection);
    if (err < 0) {
      bpf_log_err("Error while deleting the parameters");
    }
    err = bpf_map_delete_elem(&connection_fingerprint_to_connection_fingerprint_map, other_conn);
    if (err < 0) {
      bpf_log_err("Error while deleting the other connection");
    }
    err = bpf_map_delete_elem(&connection_fingerprint_to_connection_parameters_map, other_conn);
    if (err < 0) {
      bpf_log_err("Error while deleting the other parameters");
    }
  }

  return 0;
}

/**
 * Redirect the Client packets on the Server connection and viceversa
 */
SEC("xdp/redirect_packet")
int redirect_packet_main(struct xdp_md* ctx) {
  int err;

  void* data = (void*)(long)ctx->data;
  void* data_end = (void*)(long)ctx->data_end;

  struct ethhdr* eth;
  struct iphdr* ip;
  struct tcphdr* tcp;

  __u16 tcp_start;
  int tcp_hdr_size;

  // get the Ethernet, IP and TCP headers
  err = parse_headers(data, data_end, &eth, &ip, &tcp, &tcp_start, &tcp_hdr_size);
  if (err < 0) {
    bpf_log_err("Failed to parse headers for XDP");
    goto pass;
  }

  // get connection type
  struct connection_fingerprint connection;
  int active_connection = 0;

  if (bpf_ntohs(tcp->dest) == MIDDLEWARE_PORT) {
    bpf_log_notice("Message from Client SYN: %d ACK: %d FIN: %d PSH: %d RST: %d", tcp->syn,
                   tcp->ack, tcp->fin, tcp->psh, tcp->rst);
    connection.ip = ip->saddr;
    connection.port = bpf_htons(tcp->source);
    active_connection = 0;
  } else {
    bpf_log_notice("Message from Server SYN: %d ACK: %d FIN: %d PSH: %d RST: %d", tcp->syn,
                   tcp->ack, tcp->fin, tcp->psh, tcp->rst);
    connection.ip = ip->saddr;
    connection.port = bpf_ntohs(tcp->dest);
    active_connection = 1;
  }

  unsigned int tcp_len = data_end - (void*)tcp - tcp_hdr_size;
  bpf_log_debug("Sequence number: %u ACK number: %u TCP Len: %u", bpf_ntohl(tcp->seq),
                bpf_ntohl(tcp->ack_seq), tcp_len);

  bpf_log_info("IP: %u, Port: %u", connection.ip, connection.port);

  struct connection_parameters* params = (struct connection_parameters*)bpf_map_lookup_elem(
      &connection_fingerprint_to_connection_parameters_map, &connection);

  // new connection
  if (params == NULL) {
    err = handle_new_connection(data, data_end, eth, ip, tcp, tcp_start, tcp_hdr_size, &connection);
    if (err < 0) {
      bpf_log_err("Error while handling new connection");
    }

    goto pass;
  }

  // existing connection
  err = handle_existing_connection(data, data_end, eth, ip, tcp, tcp_start, tcp_hdr_size,
                                   connection, params, active_connection);
  if (err < 0) {
    bpf_log_err("Error while handling existing connection");
    goto pass;
  } else if (err == XDP_PASS) {
    goto pass;
  } else if (err == XDP_DROP) {
    goto drop;
  }

  // redirect the packet
  long red = bpf_redirect_array(0);
  if (red != XDP_REDIRECT) {
    bpf_log_err("Failed to redirect XDP, passing");
    goto pass;
  }

  bpf_log_notice("Redirecting XDP\n");
  return XDP_REDIRECT;

pass:
  bpf_log_notice("Passing XDP\n");
  return XDP_PASS;

drop:
  bpf_log_notice("Dropping XDP\n");
  return XDP_DROP;
}

/* TC - BLOCK FINS */

/**
 * Redirect the FIN to the interface by swapping MACs, IPs, ports, updating timestamps and checksums
 */
static __always_inline int reply_fin_back(void* data, void* data_end, struct ethhdr* eth,
                                          struct iphdr* ip, struct tcphdr* tcp, __u16 tcp_start,
                                          int tcp_hdr_size) {
  // swap MACs
  unsigned char temp_mac[ETH_ALEN];
  __builtin_memcpy(temp_mac, eth->h_source, ETH_ALEN);
  __builtin_memcpy(eth->h_source, eth->h_dest, ETH_ALEN);
  __builtin_memcpy(eth->h_dest, temp_mac, ETH_ALEN);

  // swap IPs
  unsigned int temp_ip;
  temp_ip = ip->saddr;
  ip->saddr = ip->daddr;
  ip->daddr = temp_ip;

  // swap ports
  unsigned int temp_port;
  temp_port = tcp->source;
  tcp->source = tcp->dest;
  tcp->dest = temp_port;

  // swap seq & ack, while incrementing
  unsigned int temp_seq;
  temp_seq = tcp->seq;

  tcp->seq = tcp->ack_seq;
  tcp->ack_seq = bpf_ntohl(bpf_ntohl(temp_seq) + 1);

  // make sure that the reply is a FIN/ACK
  tcp->ack = 1;

  // swap timestamps, while incrementing
  struct tcp_timestamps_option timestamps;
  extract_and_update_tcp_timestamps_option(data, data_end, tcp_start, tcp_hdr_size, &timestamps,
                                           NULL, 1, 1);

  // update checksum
  update_ip_checksum(ip);
  update_tcp_checksum(data, data_end, ip, tcp);

  long red = bpf_redirect_array(BPF_F_INGRESS);
  if (red != TC_ACT_REDIRECT) {
    bpf_log_err("Failed to redirect TC, passing\n");
    return TC_ACT_OK;
  }

  bpf_log_notice("Redirected TC\n");
  return TC_ACT_REDIRECT;
}

/**
 * Drop the last ACK, using the connection parameters set by XDP
 */
static __always_inline int block_last_ack(void* data, void* data_end, struct iphdr* ip,
                                          struct tcphdr* tcp, __u16 tcp_start, int tcp_hdr_size) {
  // get connection type
  struct connection_fingerprint connection;

  int active_connection = 0;
  if (bpf_ntohs(tcp->source) == MIDDLEWARE_PORT) {
    connection.ip = ip->daddr;
    connection.port = bpf_htons(tcp->dest);
    active_connection = 1;
  } else {
    connection.ip = ip->daddr;
    connection.port = bpf_ntohs(tcp->source);
    active_connection = 0;
  }

  bpf_log_info("IP: %u, Port: %u", connection.ip, connection.port);

  // get the parameters of the connection
  struct connection_parameters* params = (struct connection_parameters*)bpf_map_lookup_elem(
      &connection_fingerprint_to_connection_parameters_map, &connection);

  if (params == NULL) {
    bpf_log_err("Error while looking up parameters");
    return -1;
  }

  params->tc_ack_counter += 1;
  if (params->tc_ack_counter == 1) {
    extract_and_update_tcp_timestamps_option(data, data_end, tcp_start, tcp_hdr_size,
                                             &params->timestamps, NULL, 0, active_connection);

    return -1;
  }

  return 0;
}

/**
 * Block all FINs on egress from exiting; instead, reply to them with fake FINs and drop the last
 * ACK
 */
SEC("cls/block_fins")
int block_fins_main(struct __sk_buff* skb) {
  int err;

  void* data = (void*)(unsigned long long)skb->data;
  void* data_end = (void*)(unsigned long long)skb->data_end;

  struct ethhdr* eth;
  struct iphdr* ip;
  struct tcphdr* tcp;

  __u16 tcp_start;
  int tcp_hdr_size;

  // get the Ethernet, IP and TCP headers
  err = parse_headers(data, data_end, &eth, &ip, &tcp, &tcp_start, &tcp_hdr_size);
  if (err < 0) {
    bpf_log_err("Failed to parse headers for TC");
    goto pass;
  }

  if (bpf_ntohs(tcp->source) == MIDDLEWARE_PORT) {
    bpf_log_notice("Message to Client SYN: %d ACK: %d FIN: %d PSH: %d RST: %d", tcp->syn, tcp->ack,
                   tcp->fin, tcp->psh, tcp->rst);
  } else {
    bpf_log_notice("Message to Server SYN: %d ACK: %d FIN: %d PSH: %d RST: %d", tcp->syn, tcp->ack,
                   tcp->fin, tcp->psh, tcp->rst);
  }
  bpf_log_debug("Sequence number: %u ACK number: %u", bpf_ntohl(tcp->seq), bpf_ntohl(tcp->ack_seq));

  // reply with a fake FIN
  if (tcp->fin) {
    return reply_fin_back(data, data_end, eth, ip, tcp, tcp_start, tcp_hdr_size);
  }

  // we need to block the last single ACK
  if (tcp->ack && !tcp->syn && !tcp->psh) {
    err = block_last_ack(data, data_end, ip, tcp, tcp_start, tcp_hdr_size);
    if (err < 0) {
      goto pass;
    }

    bpf_log_notice("Dropping last ACK\n");
    return TC_ACT_SHOT;
  }

pass:
  bpf_log_notice("Passing TC\n");
  return TC_ACT_OK;
}

char LICENSE[] SEC("license") = "GPL";
