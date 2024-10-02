#include "ebpf_tcp_proxy_skb_config.h"

namespace Envoy {
namespace Extensions {
namespace NetworkFilters {
namespace TcpProxy {
namespace EbpfTcpProxy {
namespace EbpfTcpProxySKB {

/**
 * Construct a EbpfTcpProxySKB using a TcpProxy configuration
 */
Network::FilterFactoryCb EbpfTcpProxySKBConfigFactory::createFilterFactoryFromProtoTyped(
    const envoy::extensions::filters::network::tcp_proxy::v3::TcpProxy& proto_config,
    Server::Configuration::FactoryContext& context) {
  ASSERT(!proto_config.stat_prefix().empty());

  Envoy::TcpProxy::ConfigSharedPtr filter_config(
      std::make_shared<Envoy::TcpProxy::Config>(proto_config, context));
  return [filter_config, &context, this](Network::FilterManager& filter_manager) -> void {
    filter_manager.addReadFilter(std::make_shared<Envoy::TcpProxy::EbpfTcpProxy::EbpfTcpProxySKB::EbpfTcpProxySKB>(
        filter_config, context.serverFactoryContext().clusterManager(), sockhash_fd,
        connection_fingerprint_to_connection_fingerprint_map_fd));
  };
}

/**
 * Load the eBPF programs, extract the TcpProxy configuration from the EbpfTcpProxySKB
 * one, then instantiate the filter
 */
Network::FilterFactoryCb EbpfTcpProxySKBConfigFactory::createFilterFactoryFromProtoTyped(
    const envoy::extensions::filters::network::tcp_proxy::v3::EbpfTcpProxySKB& proto_config,
    Server::Configuration::FactoryContext& context) {

  // load the eBPF programs and get the map descriptor
  try {
    EbpfLoader::loadeBPFPrograms(&sockhash_fd,
                                 &connection_fingerprint_to_connection_fingerprint_map_fd);
  } catch (eBPFLoadException& e) {
    ENVOY_LOG_MISC(error, e.what());
    throw std::runtime_error(e.what());
  }

  // construct the EbpfTcpProxySKB filter using a TcpProxy configuration
  return EbpfTcpProxySKBConfigFactory::createFilterFactoryFromProtoTyped(proto_config.tcp_proxy(),
                                                                      context);
}

} // namespace EbpfTcpProxySKB
} // namespace EbpfTcpProxy
} // namespace TcpProxy
} // namespace NetworkFilters
} // namespace Extensions
} // namespace Envoy
