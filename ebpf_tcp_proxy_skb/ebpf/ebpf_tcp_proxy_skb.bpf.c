#include <linux/bpf.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#define MIDDLEWARE_PORT 4444
#define MAX_ENTRIES_SOCKHASH 65536

struct connection_fingerprint {
  unsigned int ip;
  unsigned int port;
};

// Map to save sockets file descriptors
struct {
  __uint(type, BPF_MAP_TYPE_SOCKHASH);
  __type(key, struct connection_fingerprint);
  __type(value, int);
  __uint(max_entries, MAX_ENTRIES_SOCKHASH);
} sockhash SEC(".maps");

// Map each connection to its respective one (Client <-> Server)
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __type(key, struct connection_fingerprint);
  __type(value, struct connection_fingerprint);
  __uint(max_entries, MAX_ENTRIES_SOCKHASH);
} connection_fingerprint_to_connection_fingerprint_map SEC(".maps");

/* SOCKOPS - ADD TO SOCKHASH */

/**
 * Add the new connections to the sockhash
 */
SEC("sockops/add_to_sockhash")
int add_to_sockhash_main(struct bpf_sock_ops* ops) {
  int err;

  // TODO: find a way to get rid of this
  if (ops->local_port == 22) {
    // bpf_printk("SSH");
    return 0;
  }

  struct connection_fingerprint connection;

  switch (ops->op) {
  case BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB:
    bpf_printk("Passive = Client");
    connection.ip = ops->remote_ip4;
    connection.port = bpf_htonl(ops->remote_port);

    err = bpf_sock_hash_update(ops, &sockhash, &connection, BPF_ANY);
    if (err < 0) {
      // bpf_printk("Error while Client %d", err);
    }

	err = bpf_sock_ops_cb_flags_set(ops, BPF_SOCK_OPS_STATE_CB_FLAG);
    if (err < 0) {
      // bpf_printk("Error while setting Client BPF_SOCK_OPS_STATE_CB_FLAG %d", err);
    }

    break;
  case BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB:
    bpf_printk("Active = Server");
    connection.ip = ops->remote_ip4;
    connection.port = ops->local_port;

    err = bpf_sock_hash_update(ops, &sockhash, &connection, BPF_ANY);
    if (err < 0) {
      // bpf_printk("Error while Server %d", err);
    }
	err = bpf_sock_ops_cb_flags_set(ops, BPF_SOCK_OPS_STATE_CB_FLAG);
    if (err < 0) {
      // bpf_printk("Error while setting Server BPF_SOCK_OPS_STATE_CB_FLAG %d", err);
    }

    break;
  case BPF_SOCK_OPS_STATE_CB: // TODO: remove, this is here just for debugging
    if (ops->args[1] == BPF_TCP_CLOSE) {
      // bpf_printk("Closing");
	  connection.ip = ops->remote_ip4;
	  connection.port = 0;
    } else {
		// bpf_printk("Uncaptured state: %d", ops->args[1]);
	}
	break;
  default:
    bpf_printk("Uncaptured OP: %d", ops->op);
  }

  bpf_printk("IP: %d, Port: %d", connection.ip, connection.port);
  bpf_printk("");
  return 0;
}

/* SK_SKB VERDICT - REDIRECT SOCKET */

/**
 * Redirect the Client socket on the Server one and viceversa
 */
SEC("sk_skb_verdict/redirect_packet")
int redirect_packet_main(struct __sk_buff* skb) {
  int err;

  struct connection_fingerprint connection;

  if (skb->local_port == MIDDLEWARE_PORT) {
    // bpf_printk("Message from Client");
    connection.ip = skb->remote_ip4;
    connection.port = bpf_htonl(skb->remote_port);
    // bpf_printk("IP: %d, Port: %d", connection.ip, connection.port);
  } else {
    // bpf_printk("Message from Server");
    connection.ip = skb->remote_ip4;
    connection.port = skb->local_port;
    // bpf_printk("IP: %d, Port: %d", connection.ip, connection.port);
  }

  struct connection_fingerprint* other_connection =
      (struct connection_fingerprint*)bpf_map_lookup_elem(
          &connection_fingerprint_to_connection_fingerprint_map, &connection);
  if (other_connection == NULL) {
    bpf_printk("No match between sockets - expected for first Client message");
    goto pass;
  }

  // bpf_printk("Other IP: %d, Port: %d", other_connection->ip, other_connection->port);

  err = bpf_sk_redirect_hash(skb, &sockhash, other_connection, 0);
  if (err == SK_DROP) {
    // bpf_printk("Failed redirecting to socket");
    goto pass;
  }

  // bpf_printk("Redirecting socket to socket");

pass:
  // bpf_printk("");
  return SK_PASS;
}

char LICENSE[] SEC("license") = "GPL";
