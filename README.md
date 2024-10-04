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

Once it has compiled, run on a Middleware server Envoy using the configuration file that uses this filter:

`sudo ./bazel-bin/envoy --config-path ./conf/ebpf_tcp_proxy_config.yaml`

### Configuration

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

In the "conf" directory there are two example configuration files: they both use 3 envoy clusters (kafka1_cluster, kafka2_cluster, kafka3_cluster) and choose between these using the SNI "kafkax.server.test"

These two configuration files can be used to test the EBPF Tcp Proxy filter against the vanilla Tcp Proxy one, just use the "envoy_config.yaml" instead of the "ebpf_tcp_proxy_config.yaml"

## Benchmarking and testing

* [iperf-ssl](https://github.com/TrekkieCoder/iperf-ssl)

On the server, run `iperf --tls=v1.2 -s -p <server-port>`

On the client, run `iperf --tls=v1.2 -c <middleware-ip> -p <middleware-port> -A kafkax.server.test`

### HTTP benchmarking

Most of the performace benefit where seen while requesting big (>10MB) files

Setup a HTTP server (usually [nginx](https://nginx.org/)) and use the "/etc/hosts" to associate the kafkax.server.test to the Middleware

* [autocannon](https://github.com/mcollina/autocannon)

On the client, run `autocannon https://kafkax.server.test:<middleware-port>`

* [wrk](https://github.com/wg/wrk)

On the client, run `wrk https://kafkax.server.test:<middleware-port>`

* [bombardier](https://github.com/codesenberg/bombardier)

On the client, run `bombardier http://kafkax.server.test:<middleware-port>`

## How it works

TODO
