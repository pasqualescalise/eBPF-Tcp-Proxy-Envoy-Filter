#pragma once

#include <bpf/bpf.h>

#include "envoy/network/filter.h"

#include "source/common/common/logger.h"

#include "source/common/tcp_proxy/tcp_proxy.h"

namespace Envoy {
namespace TcpProxy {
namespace EbpfTcpProxy {

/**
 * This filter extends the TcpProxy Filter, using eBPF to accelerate it
 */
class EbpfTcpProxy : public Filter {
public:
  EbpfTcpProxy(ConfigSharedPtr config, Upstream::ClusterManager& cluster_manager,
               int connection_fingerprint_to_connection_fingerprint_map_fd_)
      : Filter(config, cluster_manager),
        connection_fingerprint_to_connection_fingerprint_map_fd(
            connection_fingerprint_to_connection_fingerprint_map_fd_){};

  Network::FilterStatus onData(Buffer::Instance& data, bool end_stream) override;

private:
  struct ConnectionFingerprint {
    unsigned int ip;
    unsigned int port;
  };

  ConnectionFingerprint client_fingerprint, server_fingerprint;
  int connection_fingerprint_to_connection_fingerprint_map_fd;

  void bindClientAndServerConnections();
};

} // namespace EbpfTcpProxy
} // namespace TcpProxy
} // namespace Envoy
