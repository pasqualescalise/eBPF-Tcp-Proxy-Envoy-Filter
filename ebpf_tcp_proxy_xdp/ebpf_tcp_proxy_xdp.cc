#include "ebpf_tcp_proxy_xdp.h"

#include "envoy/buffer/buffer.h"
#include "envoy/network/connection.h"

#include "source/common/common/assert.h"

namespace Envoy {
namespace TcpProxy {
namespace EbpfTcpProxy {
namespace EbpfTcpProxyXDP {

Network::FilterStatus EbpfTcpProxyXDP::onData(Buffer::Instance& data, bool end_stream) {
  ENVOY_CONN_LOG(trace, "downstream connection received {} bytes, end_stream={}, has upstream {}",
                 read_callbacks_->connection(), data.length(), end_stream, upstream_ != nullptr);

  // copied from Envoy::TcpProxyFilter::onData
  getStreamInfo().getDownstreamBytesMeter()->addWireBytesReceived(data.length());
  if (upstream_) {
    getStreamInfo().getUpstreamBytesMeter()->addWireBytesSent(data.length());
    // send the TLS Client Hello and close the connection
    upstream_->encodeData(data, true);
  }

  ASSERT(0 == data.length());

  bindClientAndServerConnections();

  resetIdleTimer();
  return Network::FilterStatus::StopIteration;
}

/**
 * Get the Client and Server ConnectionFingerprints and put them in
 * connection_fingerprint_to_connection_fingerprint_map
 */
void EbpfTcpProxyXDP::bindClientAndServerConnections() {
  client_fingerprint.ip =
      getStreamInfo().downstreamAddressProvider().remoteAddress()->ip()->ipv4()->address();
  client_fingerprint.port =
      getStreamInfo().downstreamAddressProvider().remoteAddress()->ip()->port();
  ENVOY_CONN_LOG(trace, "Client ip: {}, Client port: {}", read_callbacks_->connection(),
                 client_fingerprint.ip, client_fingerprint.port);

  server_fingerprint.ip =
      getStreamInfo().upstreamInfo()->upstreamRemoteAddress()->ip()->ipv4()->address();
  server_fingerprint.port = getStreamInfo().upstreamInfo()->upstreamLocalAddress()->ip()->port();
  ENVOY_CONN_LOG(trace, "Server ip: {}, Server port: {}", read_callbacks_->connection(),
                 server_fingerprint.ip, server_fingerprint.port);

  int err = bpf_map_update_elem(connection_fingerprint_to_connection_fingerprint_map_fd,
                                &client_fingerprint, &server_fingerprint, BPF_NOEXIST);
  if (err < 0) {
    ENVOY_CONN_LOG(error, "Client fingerprint to Server fingerprint map update failed",
                   read_callbacks_->connection());
  }

  err = bpf_map_update_elem(connection_fingerprint_to_connection_fingerprint_map_fd,
                            &server_fingerprint, &client_fingerprint, BPF_NOEXIST);
  if (err < 0) {
    ENVOY_CONN_LOG(error, "Server fingerprint to Client fingerprint map update failed",
                   read_callbacks_->connection());
  }
}

} // namespace EbpfTcpProxyXDP
} // namespace EbpfTcpProxy
} // namespace TcpProxy
} // namespace Envoy
