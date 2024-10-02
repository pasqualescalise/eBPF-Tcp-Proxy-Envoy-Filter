#include "ebpf_tcp_proxy_xdp.h"

#include "envoy/registry/registry.h"
#include "envoy/server/filter_config.h"

#include "source/extensions/filters/network/tcp_proxy/config.h"

#include "envoy/extensions/filters/network/tcp_proxy/v3/ebpf_tcp_proxy_xdp.pb.h"
#include "envoy/extensions/filters/network/tcp_proxy/v3/ebpf_tcp_proxy_xdp.pb.validate.h"

#include "ebpf_loader_xdp.h"

namespace Envoy {
namespace Extensions {
namespace NetworkFilters {
namespace TcpProxy {
namespace EbpfTcpProxy {
namespace EbpfTcpProxyXDP {

/**
 * Config registration for the EbpfTcpProxyXDP filter
 */
class EbpfTcpProxyXDPConfigFactory
    : public Common::FactoryBase<envoy::extensions::filters::network::tcp_proxy::v3::EbpfTcpProxyXDP> {
public:
  EbpfTcpProxyXDPConfigFactory() : FactoryBase("ebpf_tcp_proxy_xdp", true){};

  ~EbpfTcpProxyXDPConfigFactory() {
    try {
      EbpfLoader::unloadeBPFPrograms(interface_index);
    } catch (eBPFLoadException& e) {
      ENVOY_LOG_MISC(error, e.what());
    }
  }

  std::string name() const override { return "ebpf_tcp_proxy_xdp"; }

  std::set<std::string> configTypes() override {
    return {"envoy.extensions.filters.network.tcp_proxy.v3.EbpfTcpProxyXDP"};
  }

private:
  int interface_index;
  int connection_fingerprint_to_connection_fingerprint_map_fd;

  Network::FilterFactoryCb createFilterFactoryFromProtoTyped(
      const envoy::extensions::filters::network::tcp_proxy::v3::TcpProxy& proto_config,
      Server::Configuration::FactoryContext& context);

  Network::FilterFactoryCb createFilterFactoryFromProtoTyped(
      const envoy::extensions::filters::network::tcp_proxy::v3::EbpfTcpProxyXDP& proto_config,
      Server::Configuration::FactoryContext& context);
};

/**
 * Static registration for the EbpfTcpProxyXDP filter
 */
REGISTER_FACTORY(EbpfTcpProxyXDPConfigFactory, Server::Configuration::NamedNetworkFilterConfigFactory);

} // namespace EbpfTcpProxyXDP
} // namespace EbpfTcpProxy
} // namespace TcpProxy
} // namespace NetworkFilters
} // namespace Extensions
} // namespace Envoy
