#include "ebpf_tcp_proxy.h"

#include <linux/if_link.h>

#include "envoy/registry/registry.h"
#include "envoy/server/filter_config.h"

#include "source/extensions/filters/network/tcp_proxy/config.h"

#include "envoy/extensions/filters/network/tcp_proxy/v3/ebpf_tcp_proxy.pb.h"
#include "envoy/extensions/filters/network/tcp_proxy/v3/ebpf_tcp_proxy.pb.validate.h"

namespace Envoy {
namespace Extensions {
namespace NetworkFilters {
namespace TcpProxy {
namespace EbpfTcpProxy {

class EbpfLoader {
public:
  static int LoadeBPFPrograms(int interface_index) {
    struct bpf_object_skeleton* skel = NULL;
    int err;

    // description of all the programs
    ProgramDescription progs[] = {
        {"xdp/parse_headers", BPF_PROG_TYPE_XDP, PROG_XDP_PARSE_HEADERS, NULL},
        {"xdp/redirect_packet", BPF_PROG_TYPE_XDP, PROG_XDP_REDIRECT_PACKET, NULL},
    };

    // open eBPF application
    struct ebpf_tcp_proxy_bpf* obj = ebpf_tcp_proxy_bpf__open();
    if (!obj) {
      ENVOY_LOG_MISC(error, "Error while opening eBPF skeleton");
    }

    skel = obj->skeleton;
    struct bpf_prog_skeleton* skeleton_programs = skel->progs;

    // set program types
    for (int i = 0; i < skel->prog_cnt; i++) {
      bpf_program__set_type(*(skeleton_programs[i].prog), progs[i].type);
    }

    // load and verify eBPF programs
    if (ebpf_tcp_proxy_bpf__load(obj)) {
      ENVOY_LOG_MISC(error, "Error while loading eBPF program");
    }

    // put the XDP programs in the programs map
    int programs_map_fd = bpf_map__fd(obj->maps.programs_map);

    int xdp_index = 0;
    for (int i = 0; i < skel->prog_cnt; i++) {
      if (progs[i].type != BPF_PROG_TYPE_XDP) {
        continue;
      }

      int prog_fd = bpf_program__fd(*(skeleton_programs[i].prog));

      err = bpf_map_update_elem(programs_map_fd, &xdp_index, &prog_fd, BPF_ANY);
      if (err) {
        ENVOY_LOG_MISC(error, "Error while adding eBPF program to map");
      }

      xdp_index++;
    }

    // attach the first XDP program to the interface
    err = bpf_xdp_attach(interface_index,
                         bpf_program__fd(*(skeleton_programs[PROG_XDP_PARSE_HEADERS].prog)),
                         XDP_FLAGS_DRV_MODE, NULL);
    if (err) {
      ENVOY_LOG_MISC(error, "Error while attaching the XDP program to the interface");
    }

    // get the map file descriptor from the eBPF object
    int connection_fingerprint_to_connection_fingerprint_map_fd =
        bpf_map__fd(obj->maps.connection_fingerprint_to_connection_fingerprint_map);

    ENVOY_LOG_MISC(trace, "Successfully attached!");

    return connection_fingerprint_to_connection_fingerprint_map_fd;
  }

private:
  // Program indexes
  enum {
    PROG_XDP_PARSE_HEADERS = 0,
    PROG_XDP_REDIRECT_PACKET,

    MAX_NUM_OF_PROGRAMS
  };

  struct ProgramDescription {
    char name[256];
    enum bpf_prog_type type;
    int map_prog_idx;
    struct bpf_program* prog;
  };
};

/**
 * Config registration for the EbpfTcpProxy filter
 */
class EbpfTcpProxyConfigFactory
    : public Common::FactoryBase<envoy::extensions::filters::network::tcp_proxy::v3::EbpfTcpProxy> {
public:
  EbpfTcpProxyConfigFactory() : FactoryBase("ebpf_tcp_proxy", true){};

  std::string name() const override { return "ebpf_tcp_proxy"; }

  std::set<std::string> configTypes() override {
    return {"envoy.extensions.filters.network.tcp_proxy.v3.EbpfTcpProxy"};
  }

private:
  int connection_fingerprint_to_connection_fingerprint_map_fd;

  /**
   * Construct a EbpfTcpProxy using a TcpProxy configuration
   */
  Network::FilterFactoryCb createFilterFactoryFromProtoTyped(
      const envoy::extensions::filters::network::tcp_proxy::v3::TcpProxy& proto_config,
      Server::Configuration::FactoryContext& context) {
    ASSERT(!proto_config.stat_prefix().empty());

    Envoy::TcpProxy::ConfigSharedPtr filter_config(
        std::make_shared<Envoy::TcpProxy::Config>(proto_config, context));
    return [filter_config, &context, this](Network::FilterManager& filter_manager) -> void {
      filter_manager.addReadFilter(std::make_shared<Envoy::TcpProxy::EbpfTcpProxy::EbpfTcpProxy>(
          filter_config, context.serverFactoryContext().clusterManager(),
          connection_fingerprint_to_connection_fingerprint_map_fd));
    };
  }

  /**
   * Load the eBPF programs, extract the TcpProxy configuration from the EbpfTcpProxy
   * one, then instantiate the filter
   */
  Network::FilterFactoryCb createFilterFactoryFromProtoTyped(
      const envoy::extensions::filters::network::tcp_proxy::v3::EbpfTcpProxy& proto_config,
      Server::Configuration::FactoryContext& context) {
    // load the eBPF program and get the map descriptor
    connection_fingerprint_to_connection_fingerprint_map_fd =
        EbpfLoader::LoadeBPFPrograms(proto_config.interface_index());

    // construct the EbpfTcpProxy filter using a TcpProxy configuration
    return EbpfTcpProxyConfigFactory::createFilterFactoryFromProtoTyped(proto_config.tcp_proxy(),
                                                                        context);
  }
};

/**
 * Static registration for the EbpfTcpProxy filter
 */
REGISTER_FACTORY(EbpfTcpProxyConfigFactory, Server::Configuration::NamedNetworkFilterConfigFactory);

} // namespace EbpfTcpProxy
} // namespace TcpProxy
} // namespace NetworkFilters
} // namespace Extensions
} // namespace Envoy
