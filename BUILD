package(default_visibility = ["//visibility:public"])

load(
    "@envoy//bazel:envoy_build_system.bzl",
    "envoy_cc_binary",
    "envoy_cc_library",
    "envoy_cc_test",
)

envoy_cc_binary(
    name = "envoy",
    repository = "@envoy",
    deps = [
        ":ebpf_tcp_proxy_config",
        "@envoy//source/exe:envoy_main_entry_lib",
    ],
)

# Compile the eBPF code
genrule(
	name = "ebpf_object",
	outs = ["ebpf/ebpf_tcp_proxy.bpf.o"],

	# $(location)
	srcs = ["ebpf/ebpf_tcp_proxy.bpf.c"],

    cmd = """
	clang -g -O2 -target bpf -D__TARGET_ARCH_x86 -c $< -o $@
    """,
)

# Generate eBPF programs skeleton file
genrule(
	name = "ebpf_skeleton",
	outs = ["ebpf_tcp_proxy.skel.h"],

	# TODO: use $(location)
	srcs = ["ebpf/ebpf_tcp_proxy.bpf.o"],

	# XXX: this sed hack is needed to change C casts to the C++ ones
    cmd = """
    bpftool gen skeleton $< | sed -e "s/\\(= \\)(\\([^)]*\\))\\(.*\\);/\\1static_cast<\\2>(\\3);/" -e "s/\\(return \\)(\\([^)]*\\))\\(.*\\)/\\1static_cast<\\2>(\\3/" -e "s/static_cast<void \\*>/const_cast<void \\*>/" | sed -z -e 's/";\\n}/\\");\\n}/' > $@
    """,
)

envoy_cc_library(
    name = "ebpf_tcp_proxy_lib",
    srcs = ["ebpf_tcp_proxy.cc"],
    hdrs = ["ebpf_tcp_proxy.h", "ebpf_tcp_proxy.skel.h"],
    repository = "@envoy",
    deps = [
        "@envoy//envoy/buffer:buffer_interface",
        "@envoy//envoy/network:connection_interface",
        "@envoy//envoy/network:filter_interface",
        "@envoy//source/common/common:assert_lib",
        "@envoy//source/common/common:logger_lib",
        "@envoy//source/common/tcp_proxy:tcp_proxy",
    ],
)

envoy_cc_library(
    name = "ebpf_tcp_proxy_config",
    srcs = ["ebpf_tcp_proxy_config.cc"],
    repository = "@envoy",
    deps = [
        ":ebpf_tcp_proxy_lib",
        "@envoy//envoy/network:filter_interface",
        "@envoy//envoy/registry:registry",
        "@envoy//envoy/server:filter_config_interface",
        "@envoy//source/extensions/filters/network/tcp_proxy:config",
    ],
)
