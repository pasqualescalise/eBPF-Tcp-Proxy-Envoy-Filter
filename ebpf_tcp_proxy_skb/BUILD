load(
    "@envoy//bazel:envoy_build_system.bzl",
    "envoy_cc_binary",
    "envoy_cc_library",
)

package(default_visibility = ["//visibility:public"])

load("//:bpf.bzl", "bpf_program")
load("//:bpf.bzl", "bpf_skeleton")

# The eBPF program.
bpf_program(
    name = "ebpf_skb_object",
    src = "ebpf/ebpf_tcp_proxy_skb.bpf.c",
    hdrs = [
        "//:vmlinux",
        "//:ebpf_log",
    ],
    defines = [
        "BPF_LOG_LEVEL=5",
    ],
    bpf_object = "ebpf/ebpf_tcp_proxy_skb.bpf.o",
)

# The skeleton header file generated from the eBPF program.
bpf_skeleton(
    name = "ebpf_skb_skeleton",
    bpf_object = ":ebpf_skb_object",
    skel_hdr = "ebpf/ebpf_tcp_proxy_skb.skel.h",
)

envoy_cc_library(
    name = "ebpf_tcp_proxy_skb_lib",
	srcs = ["ebpf_tcp_proxy_skb.cc"],
    hdrs = ["ebpf_tcp_proxy_skb.h"],
    repository = "@envoy",
    deps = [
        "@envoy//envoy/buffer:buffer_interface",
        "@envoy//envoy/network:connection_interface",
        "@envoy//envoy/network:filter_interface",
        "@envoy//source/common/common:assert_lib",
        "@envoy//source/common/common:logger_lib",
        "@envoy//source/common/tcp_proxy",
    ],
)

envoy_cc_library(
    name = "ebpf_tcp_proxy_skb_config",
    srcs = ["ebpf_tcp_proxy_skb_config.cc"],
    hdrs = ["ebpf_tcp_proxy_skb_config.h"],
    repository = "@envoy",
    deps = [
        ":ebpf_tcp_proxy_skb_lib",
        ":ebpf_tcp_proxy_skb_ebpf_loader",
        "@envoy//envoy/network:filter_interface",
        "@envoy//envoy/registry",
        "@envoy//envoy/server:filter_config_interface",
        "@envoy//source/extensions/filters/network/tcp_proxy:config",
        "@linux//:libbpf",
    ],
)

envoy_cc_library(
    name = "ebpf_tcp_proxy_skb_ebpf_loader",
    srcs = ["ebpf_loader_skb.cc"],
    hdrs = [
        "ebpf_loader_skb.h",
        "ebpf/ebpf_tcp_proxy_skb.skel.h",
    ],
    repository = "@envoy",
	deps = [
        ":ebpf_skb_skeleton",
        ":ebpf_tcp_proxy_skb_lib",
	]
)
