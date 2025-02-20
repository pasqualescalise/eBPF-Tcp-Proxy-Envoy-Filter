workspace(name = "ebpf_tcp_proxy")

local_repository(
    name = "envoy",
    path = "envoy",
)

load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")
load("@bazel_tools//tools/build_defs/repo:git.bzl", "new_git_repository")

http_archive(
    name = "rules_foreign_cc",
    url = "https://github.com/bazelbuild/rules_foreign_cc/archive/99ea7e75c2a48cc233ff5e7682c1a31516faa84b.tar.gz",
    sha256 = "06fb31803fe3d2552f988f3c2fee430b10d566bc77dd7688897eca5388107883",
    strip_prefix = "rules_foreign_cc-99ea7e75c2a48cc233ff5e7682c1a31516faa84b",
)
load("@rules_foreign_cc//foreign_cc:repositories.bzl", "rules_foreign_cc_dependencies")
rules_foreign_cc_dependencies()

# We clone Linux so that we can use libbpf and bpftool when compiling our eBPF
# programs.
new_git_repository(
    name = "linux",
    remote = "https://github.com/torvalds/linux",
    tag = "v6.11",
    build_file = "//:linux.BUILD",
)

http_archive(
    name = "rules_oci",
    sha256 = "d007e6c96eb62c88397b68f329e4ca56e0cfe31204a2c54b0cb17819f89f83c8",
    strip_prefix = "rules_oci-2.0.0",
    url = "https://github.com/bazel-contrib/rules_oci/releases/download/v2.0.0/rules_oci-v2.0.0.tar.gz",
)

load("@rules_oci//oci:dependencies.bzl", "rules_oci_dependencies")

rules_oci_dependencies()

load("@rules_oci//oci:repositories.bzl", "oci_register_toolchains")

oci_register_toolchains(name = "oci")

# You can pull your base images using oci_pull like this:
load("@rules_oci//oci:pull.bzl", "oci_pull")

oci_pull(
    name = "docker_lib_ubuntu",
    image = "gcr.io/bazel-public/bazel",
    platforms = [
        "linux/amd64",
    ],
    tag = "latest",
)

load("@envoy//bazel:api_binding.bzl", "envoy_api_binding")

envoy_api_binding()

load("@envoy//bazel:api_repositories.bzl", "envoy_api_dependencies")

envoy_api_dependencies()

load("@envoy//bazel:repositories.bzl", "envoy_dependencies")

envoy_dependencies()

load("@envoy//bazel:repositories_extra.bzl", "envoy_dependencies_extra")

envoy_dependencies_extra()

load("@envoy//bazel:python_dependencies.bzl", "envoy_python_dependencies")

envoy_python_dependencies()

load("@envoy//bazel:dependency_imports.bzl", "envoy_dependency_imports")

envoy_dependency_imports()
