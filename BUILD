load(
    "@envoy//bazel:envoy_build_system.bzl",
    "envoy_cc_binary",
    "envoy_cc_library",
)

package(default_visibility = ["//visibility:public"])

load("@rules_oci//oci:defs.bzl", "oci_image", "oci_load")
load("@rules_pkg//pkg:tar.bzl", "pkg_tar")

filegroup(
    name = "bpf.bzl",
    srcs = ["bpf.bzl"],
    visibility = ["//visibility:public"],
)                      

filegroup(
    name = "vmlinux",
    srcs = ["vmlinux/vmlinux.h"],
    visibility = ["//visibility:public"],
)                      

filegroup(
    name = "ebpf_log",
    srcs = ["ebpf/ebpf_tcp_proxy_log.h"],
    visibility = ["//visibility:public"],
)                      

envoy_cc_binary(
    name = "envoy",
    repository = "@envoy",
    deps = [
        "//ebpf_tcp_proxy_xdp:ebpf_tcp_proxy_xdp_config",
        "//ebpf_tcp_proxy_skb:ebpf_tcp_proxy_skb_config",
        "@envoy//source/exe:envoy_main_entry_lib",
        "@linux//:libbpf",
    ],
    linkopts = [
        "-lelf", "-lz"
    ],
)

# Packaging the binary into tar, which is needed by oci_image rule
pkg_tar(
    name = "tar",
    srcs = [":envoy"],
)

oci_image(
    name = "ebpf_tcp_proxy_image",
    base = "@docker_lib_ubuntu",
    tars = [":tar"],
    entrypoint = ["/envoy"],
)

# Use with 'bazel run' to load the oci image into a container runtime.
# The image is designated using `repo_tags` attribute.
oci_load(
    name = "image_load",
    image = ":ebpf_tcp_proxy_image",
    repo_tags = ["ebpf_tcp_proxy_envoy:latest"],
)
