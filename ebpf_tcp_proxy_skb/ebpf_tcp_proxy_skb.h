#pragma once

#include <bpf/bpf.h>

#include "envoy/network/filter.h"

#include "source/common/common/logger.h"

#include "source/common/tcp_proxy/tcp_proxy.h"

namespace Envoy {
namespace TcpProxy {
namespace EbpfTcpProxy {
namespace EbpfTcpProxySKB {

/**
 * This filter extends the TcpProxy Filter, using SOCKOPS and SK_SKB eBPF programs to accelerate it
 */
class EbpfTcpProxySKB : public Filter {
public:
  EbpfTcpProxySKB(ConfigSharedPtr config, Upstream::ClusterManager& cluster_manager, int sockhash_fd_,
               int connection_fingerprint_to_connection_fingerprint_map_fd_)
      : Filter(config, cluster_manager), sockhash_fd(sockhash_fd_),
        connection_fingerprint_to_connection_fingerprint_map_fd(
            connection_fingerprint_to_connection_fingerprint_map_fd_){};

  Network::FilterStatus onData(Buffer::Instance& data, bool end_stream) override;

private:
  struct ConnectionFingerprint {
    unsigned int ip;
    unsigned int port;
  };

  ConnectionFingerprint client_fingerprint, server_fingerprint;
  int sockhash_fd;
  int connection_fingerprint_to_connection_fingerprint_map_fd;

  void bindClientAndServerConnections();
};

} // namespace EbpfTcpProxySKB
} // namespace EbpfTcpProxy
} // namespace TcpProxy
} // namespace Envoy
