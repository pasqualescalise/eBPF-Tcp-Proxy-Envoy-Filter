load(
    "@envoy//bazel:envoy_build_system.bzl",
    "envoy_cc_binary",
    "envoy_cc_library",
    "envoy_cc_test",
)

package(default_visibility = ["//visibility:public"])

# Compile the eBPF code
genrule(
    name = "ebpf_object_xdp",
    srcs = ["ebpf/ebpf_tcp_proxy_xdp.bpf.c"],
    outs = ["ebpf/ebpf_tcp_proxy_xdp.bpf.o"],
    cmd = """
	clang -g -O2 -target bpf -D__TARGET_ARCH_x86 -c $< -o $@
    """,
)

# Generate eBPF programs skeleton file
genrule(
	name = "ebpf_skeleton_xdp",
    srcs = ["ebpf/ebpf_tcp_proxy_xdp.bpf.o"],
	outs = ["ebpf/ebpf_tcp_proxy_xdp.skel.h"],

    # XXX: this sed hack is needed to change C casts to the C++ ones
    cmd = """
	bpftool gen skeleton $< | sed -e "s/\\(= \\)(\\([^)]*\\))\\(.*\\);/\\1static_cast<\\2>(\\3);/" -e "s/\\(return \\)(\\([^)]*\\))\\(.*\\);/\\1static_cast<\\2>(\\3);/" -e "s/static_cast<void \\*>/const_cast<void \\*>/" -e "s/static_cast<void \\*\\*>/reinterpret_cast<void **>/" | sed -z -e 's/";\\n\\n/\\";\\n\\n/' > $@
    """,
)

envoy_cc_library(
    name = "ebpf_tcp_proxy_xdp_lib",
	srcs = ["ebpf_tcp_proxy_xdp.cc"],
    hdrs = ["ebpf_tcp_proxy_xdp.h"],
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
    name = "ebpf_tcp_proxy_xdp_config",
    srcs = ["ebpf_tcp_proxy_xdp_config.cc"],
    hdrs = ["ebpf_tcp_proxy_xdp_config.h"],
    repository = "@envoy",
    deps = [
        ":ebpf_tcp_proxy_xdp_lib",
        ":ebpf_tcp_proxy_xdp_ebpf_loader",
        "@envoy//envoy/network:filter_interface",
        "@envoy//envoy/registry",
        "@envoy//envoy/server:filter_config_interface",
        "@envoy//source/extensions/filters/network/tcp_proxy:config",
    ],
)

envoy_cc_library(
    name = "ebpf_tcp_proxy_xdp_ebpf_loader",
    srcs = ["ebpf_loader_xdp.cc"],
    hdrs = [
        "ebpf/ebpf_tcp_proxy_xdp.skel.h",
        "ebpf_loader_xdp.h",
    ],
    repository = "@envoy",
	deps = [
        ":ebpf_skeleton_xdp",
        ":ebpf_tcp_proxy_xdp_lib",
	]
)
