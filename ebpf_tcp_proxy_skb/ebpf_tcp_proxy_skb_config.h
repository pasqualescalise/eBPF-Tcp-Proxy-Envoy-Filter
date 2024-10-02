#include "ebpf_tcp_proxy_skb.h"

#include "envoy/registry/registry.h"
#include "envoy/server/filter_config.h"

#include "source/extensions/filters/network/tcp_proxy/config.h"

#include "envoy/extensions/filters/network/tcp_proxy/v3/ebpf_tcp_proxy_skb.pb.h"
#include "envoy/extensions/filters/network/tcp_proxy/v3/ebpf_tcp_proxy_skb.pb.validate.h"

#include "ebpf_loader_skb.h"

namespace Envoy {
namespace Extensions {
namespace NetworkFilters {
namespace TcpProxy {
namespace EbpfTcpProxy {
namespace EbpfTcpProxySKB {

/**
 * Config registration for the EbpfTcpProxySKB filter
 */
class EbpfTcpProxySKBConfigFactory
    : public Common::FactoryBase<envoy::extensions::filters::network::tcp_proxy::v3::EbpfTcpProxySKB> {
public:
  EbpfTcpProxySKBConfigFactory() : FactoryBase("ebpf_tcp_proxy_skb", true){};

  ~EbpfTcpProxySKBConfigFactory() {
    try {
      EbpfLoader::unloadeBPFPrograms();
    } catch (eBPFLoadException& e) {
      ENVOY_LOG_MISC(error, e.what());
    }
  }

  std::string name() const override { return "ebpf_tcp_proxy_skb"; }

  std::set<std::string> configTypes() override {
    return {"envoy.extensions.filters.network.tcp_proxy.v3.EbpfTcpProxySKB"};
  }

private:
  int sockhash_fd;
  int connection_fingerprint_to_connection_fingerprint_map_fd;

  Network::FilterFactoryCb createFilterFactoryFromProtoTyped(
      const envoy::extensions::filters::network::tcp_proxy::v3::TcpProxy& proto_config,
      Server::Configuration::FactoryContext& context);

  Network::FilterFactoryCb createFilterFactoryFromProtoTyped(
      const envoy::extensions::filters::network::tcp_proxy::v3::EbpfTcpProxySKB& proto_config,
      Server::Configuration::FactoryContext& context);
};

/**
 * Static registration for the EbpfTcpProxySKB filter
 */
REGISTER_FACTORY(EbpfTcpProxySKBConfigFactory, Server::Configuration::NamedNetworkFilterConfigFactory);

} // namespace EbpfTcpProxySKB
} // namespace EbpfTcpProxy
} // namespace TcpProxy
} // namespace NetworkFilters
} // namespace Extensions
} // namespace Envoy
