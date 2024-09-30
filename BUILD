package(default_visibility = ["//visibility:public"])

load(
    "@envoy//bazel:envoy_build_system.bzl",
    "envoy_cc_binary",
    "envoy_cc_library",
    "envoy_cc_test",
)

load("bpf.bzl", "bpf_program")
load("bpf.bzl", "bpf_skeleton")

# The eBPF program.
bpf_program(
    name = "ebpf_object",
    src = "ebpf/ebpf_tcp_proxy.bpf.c",
    hdrs = [
        "vmlinux/vmlinux.h",
    ],
    bpf_object = "ebpf/ebpf_tcp_proxy.bpf.o",
)

# The skeleton header file generated from the eBPF program.
bpf_skeleton(
    name = "ebpf_skeleton",
    bpf_object = ":ebpf_object",
    skel_hdr = "ebpf_tcp_proxy.skel.h",
)

envoy_cc_binary(
    name = "envoy",
    repository = "@envoy",
    deps = [
        ":ebpf_tcp_proxy_config",
        "@envoy//source/exe:envoy_main_entry_lib",
        "@linux//:libbpf",
    ],
    linkopts = [
        "-lelf", "-lz"
    ],
)

envoy_cc_library(
    name = "ebpf_tcp_proxy_lib",
    srcs = ["ebpf_tcp_proxy.cc"],
    hdrs = ["ebpf_tcp_proxy.h"],
    repository = "@envoy",
    deps = [
        "@envoy//envoy/buffer:buffer_interface",
        "@envoy//envoy/network:connection_interface",
        "@envoy//envoy/network:filter_interface",
        "@envoy//source/common/common:assert_lib",
        "@envoy//source/common/common:logger_lib",
        "@envoy//source/common/tcp_proxy:tcp_proxy",
        "@linux//:libbpf",
    ],
)

envoy_cc_library(
    name = "ebpf_tcp_proxy_config",
    srcs = ["ebpf_tcp_proxy_config.cc"],
    hdrs = ["ebpf_tcp_proxy.h", "ebpf_tcp_proxy_config.h", "ebpf_tcp_proxy.skel.h"],
    repository = "@envoy",
    deps = [
        ":ebpf_tcp_proxy_lib",
        "@envoy//envoy/network:filter_interface",
        "@envoy//envoy/registry:registry",
        "@envoy//envoy/server:filter_config_interface",
        "@envoy//source/extensions/filters/network/tcp_proxy:config",
        "@linux//:libbpf",
    ],
)
