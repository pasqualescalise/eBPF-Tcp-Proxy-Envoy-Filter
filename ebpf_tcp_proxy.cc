#include "ebpf_tcp_proxy.h"

#include "envoy/buffer/buffer.h"
#include "envoy/network/connection.h"

#include "source/common/common/assert.h"

namespace Envoy {
namespace TcpProxy {
namespace EbpfTcpProxy {

Network::FilterStatus EbpfTcpProxy::onData(Buffer::Instance& data, bool end_stream) {
  ENVOY_CONN_LOG(trace, "downstream connection received {} bytes, end_stream={}, has upstream {}",
                 read_callbacks_->connection(), data.length(), end_stream, upstream_ != nullptr);

  // copied from Envoy::TcpProxyFilter::onData
  getStreamInfo().getDownstreamBytesMeter()->addWireBytesReceived(data.length());
  if (upstream_) {
    getStreamInfo().getUpstreamBytesMeter()->addWireBytesSent(data.length());
    // send the TLS Client Hello
    upstream_->encodeData(data, end_stream);

    // after sending the TLS Client Hello, wait for the connection to end then close the sockets
    upstream_->addBytesSentCallback([&](uint64_t) -> bool {
      waitUntilClosedConnection();
      return false;
    });
  }

  ASSERT(0 == data.length());

  bindClientAndServerConnections();

  resetIdleTimer();
  return Network::FilterStatus::StopIteration;
}

/**
 * Wait until the connection have ended and destroy the threads
 *
 * XXX: this implementation can be improved greatly
 */
void EbpfTcpProxy::waitUntilClosedConnection() {
  ConnectionFingerprint client_fingerprint_lookup, server_fingerprint_lookup;

  while (1) {
    // look for the Client connection
    int err = bpf_map_lookup_elem(connection_fingerprint_to_connection_fingerprint_map_fd,
                                  &client_fingerprint, &server_fingerprint_lookup);
    if (err < 0) {
      ENVOY_CONN_LOG(trace, "Client connection ended", read_callbacks_->connection());
      break;
    }

    // look for the Server connection
    err = bpf_map_lookup_elem(connection_fingerprint_to_connection_fingerprint_map_fd,
                              &server_fingerprint, &client_fingerprint_lookup);
    if (err < 0) {
      ENVOY_CONN_LOG(trace, "Server connection ended", read_callbacks_->connection());
      break;
    }
  }

  read_callbacks_->connection().close(Network::ConnectionCloseType::Abort,
                                      "EbpfTcpProxyDownstream");
  ENVOY_CONN_LOG(trace, "Closing", read_callbacks_->connection());
}

/**
 * Get the Client and Server ConnectionFingerprints and put them in
 * connection_fingerprint_to_connection_fingerprint_map
 */
void EbpfTcpProxy::bindClientAndServerConnections() {
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

} // namespace EbpfTcpProxy
} // namespace TcpProxy
} // namespace Envoy
