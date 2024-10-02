#include "ebpf_tcp_proxy_xdp_config.h"

namespace Envoy {
namespace Extensions {
namespace NetworkFilters {
namespace TcpProxy {
namespace EbpfTcpProxy {
namespace EbpfTcpProxyXDP {

/**
 * Construct a EbpfTcpProxyXDP using a TcpProxy configuration
 */
Network::FilterFactoryCb EbpfTcpProxyXDPConfigFactory::createFilterFactoryFromProtoTyped(
    const envoy::extensions::filters::network::tcp_proxy::v3::TcpProxy& proto_config,
    Server::Configuration::FactoryContext& context) {
  ASSERT(!proto_config.stat_prefix().empty());

  Envoy::TcpProxy::ConfigSharedPtr filter_config(
      std::make_shared<Envoy::TcpProxy::Config>(proto_config, context));
  return [filter_config, &context, this](Network::FilterManager& filter_manager) -> void {
    filter_manager.addReadFilter(std::make_shared<Envoy::TcpProxy::EbpfTcpProxy::EbpfTcpProxyXDP::EbpfTcpProxyXDP>(
        filter_config, context.serverFactoryContext().clusterManager(),
        connection_fingerprint_to_connection_fingerprint_map_fd));
  };
}

/**
 * Load the eBPF programs, extract the TcpProxy configuration from the EbpfTcpProxyXDP
 * one, then instantiate the filter
 */
Network::FilterFactoryCb EbpfTcpProxyXDPConfigFactory::createFilterFactoryFromProtoTyped(
    const envoy::extensions::filters::network::tcp_proxy::v3::EbpfTcpProxyXDP& proto_config,
    Server::Configuration::FactoryContext& context) {
  interface_index = proto_config.interface_index();

  // load the eBPF programs and get the map descriptor
  try {
    EbpfLoader::loadeBPFPrograms(interface_index,
                                 &connection_fingerprint_to_connection_fingerprint_map_fd);
  } catch (eBPFLoadException& e) {
    ENVOY_LOG_MISC(error, e.what());
    throw std::runtime_error(e.what());
  }

  // construct the EbpfTcpProxyXDP filter using a TcpProxy configuration
  return EbpfTcpProxyXDPConfigFactory::createFilterFactoryFromProtoTyped(proto_config.tcp_proxy(),
                                                                      context);
}

} // namespace EbpfTcpProxyXDP
} // namespace EbpfTcpProxy
} // namespace TcpProxy
} // namespace NetworkFilters
} // namespace Extensions
} // namespace Envoy
