#include "ebpf_loader_skb.h"

namespace Envoy {
namespace Extensions {
namespace NetworkFilters {
namespace TcpProxy {
namespace EbpfTcpProxy {
namespace EbpfTcpProxySKB {

bool EbpfLoader::ebpf_loaded = false;

/**
 * Load and attach the SKB eBPF programs
 */
void EbpfLoader::loadeBPFPrograms(int* sockhash_fd, int* connection_fingerprint_to_connection_fingerprint_map_fd) {
  if (ebpf_loaded) {
    return;
  }

  ebpf_loaded = true;

  struct bpf_object_skeleton* skel = NULL;

  // open eBPF application
  struct ebpf_tcp_proxy_skb_bpf* obj = ebpf_tcp_proxy_skb_bpf__open();
  if (!obj) {
    throw eBPFLoadException("Error while opening eBPF skeleton");
  }

  skel = obj->skeleton;

  // set program types
  for (int i = 0; i < skel->prog_cnt; i++) {
    bpf_program__set_type(*(skel->progs[i].prog), progs[i].type);
  }

  // load and verify eBPF programs
  if (ebpf_tcp_proxy_skb_bpf__load(obj)) {
    throw eBPFLoadException("Error while loading eBPF program");
  }

  // get the maps file descriptor from the eBPF object
  *sockhash_fd = bpf_map__fd(obj->maps.sockhash);
  *connection_fingerprint_to_connection_fingerprint_map_fd =
      bpf_map__fd(obj->maps.connection_fingerprint_to_connection_fingerprint_map);

  attachSOCKOPS(skel);
  attachSKSKB(skel, *sockhash_fd);

  ENVOY_LOG_MISC(trace, "Successfully attached!");
}

/**
 * Attach the "ADD TO SOCKHASH" SOCKOPS program to the root cgroup
 */
void EbpfLoader::attachSOCKOPS(struct bpf_object_skeleton* skel) {
  int err;

  int cg_fd = open("/sys/fs/cgroup/", __O_DIRECTORY, O_RDONLY);
  if (cg_fd < 0) {
    throw eBPFLoadException("Failed to open cgroup");
  }

  err = bpf_prog_attach(
      bpf_program__fd(*(skel->progs[PROG_SOCKOPS_ADD_TO_SOCKHASH].prog)), cg_fd,
      BPF_CGROUP_SOCK_OPS, 0);
  if (err < 0) {
    throw eBPFLoadException("Failed to attach SOCKOPS program to the root cgroup");
  }
}

/**
 * Attach the "REDIRECT SOCKET" SKB program to the sockhash map
 */
void EbpfLoader::attachSKSKB(struct bpf_object_skeleton* skel, int sockhash_fd) {
  int err;

  err = bpf_prog_attach(bpf_program__fd(*(skel->progs[PROG_SK_SKB_VERDICT_REDIRECT_SOCKET].prog)),
                        sockhash_fd, BPF_SK_SKB_STREAM_VERDICT, 0);
  if (err) {
    throw eBPFLoadException("Failed to attach the SK_SKB program to the sockhash");
  }
}

/**
 * Unload and detach the eBPF programs
 */
void EbpfLoader::unloadeBPFPrograms() {
  if (!ebpf_loaded) {
    return;
  }

  struct bpf_object_skeleton* skel = NULL;

  // open eBPF application
  struct ebpf_tcp_proxy_skb_bpf* obj = ebpf_tcp_proxy_skb_bpf__open();
  if (!obj) {
    throw eBPFLoadException("Error while opening eBPF skeleton");
  }

  skel = obj->skeleton;

  detachSOCKOPS(skel);
}

/**
 * Detach the SOCKOPS program from the root cgroup
 */
void EbpfLoader::detachSOCKOPS(struct bpf_object_skeleton* skel) {
  int err;

  int cg_fd = open("/sys/fs/cgroup/", __O_DIRECTORY, O_RDONLY);
  if (cg_fd < 0) {
    throw eBPFLoadException("Failed to open cgroup");
  }

  err = bpf_prog_detach2(
      bpf_program__fd(*(skel->progs[PROG_SOCKOPS_ADD_TO_SOCKHASH].prog)), cg_fd,
      BPF_CGROUP_SOCK_OPS);
  if (err < 0) {
    throw eBPFLoadException("Failed to detach SOCKOPS program");
  }
}

} // namespace EbpfTcpProxySKB
} // namespace EbpfTcpProxy
} // namespace TcpProxy
} // namespace NetworkFilters
} // namespace Extensions
} // namespace Envoy
