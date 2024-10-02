load(
    "@envoy//bazel:envoy_build_system.bzl",
    "envoy_cc_binary",
    "envoy_cc_library",
    "envoy_cc_test",
)

package(default_visibility = ["//visibility:public"])

envoy_cc_binary(
    name = "envoy",
    repository = "@envoy",
    deps = [
        "//ebpf_tcp_proxy_xdp:ebpf_tcp_proxy_xdp_config",
        "//ebpf_tcp_proxy_skb:ebpf_tcp_proxy_skb_config",
        "@envoy//source/exe:envoy_main_entry_lib",
    ],
)
