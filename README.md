# eBPF TCP Proxy - Envoy Filter

This envoy filter extends the [TCP Proxy](https://www.envoyproxy.io/docs/envoy/latest/configuration/listeners/network_filters/tcp_proxy_filter.html#tcp-proxy) filter using eBPF

This repo is based on the [Envoy filter example](https://github.com/envoyproxy/envoy-filter-example)

This was tested with [Envoy v1.30.4](https://github.com/envoyproxy/envoy/releases/tag/v1.30.4)

## Dependencies

+ Linux kernel >= 6.1
+ libbpf >= 1.1
+ bpftool >= 7.1
+ clang >= 14

## Building

To setup bazel, follow [the envoy guide](https://github.com/envoyproxy/envoy/tree/main/bazel/README.md)

To build the Envoy static binary:

1. `git submodule update --init`
2. `ln -s ebpf_tcp_proxy.proto envoy/api/envoy/extensions/filters/network/tcp_proxy/v3/`
3. `bazel build --linkopt="-lbpf" //:envoy`

Note that on the first time this may take a while because [it has to compile all of envoy](https://www.envoyproxy.io/docs/envoy/latest/faq/build/speed)

TODO: remove step 2

## Running

`sudo ./bazel-bin/envoy --config-path ebpf_tcp_proxy_configuration.yaml`

## Configuration

Since this filter is an extension of TCP Proxy, it takes its own configuration parameters plus a whole configuration of TCP Proxy:

```yaml
filters:
- name: ebpf_tcp_proxy
  typed_config:
    "@type": type.googleapis.com/envoy.extensions.filters.network.tcp_proxy.v3.EbpfTcpProxy
    interface_index: 5 # the interface index to attach the eBPF programs to
    tcp_proxy:
      # configuration of TCP proxy
      ...
```

## How it works

TODO
