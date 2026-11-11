# Sandbox workload image for the OpenShell driver: the OpenShell default workload base plus curl.
# UNTESTED (no Docker/OpenShell on the authoring machine).
#
# Why this exists: the driver runs `curl` inside the sandbox, and the default OpenShell workload
# image "does not include agent CLIs" (docs/about/support-matrix.mdx @ v0.1.8); the tutorials say
# "A user-owned workload image with `curl` installed" (docs/tutorials/first-network-policy.mdx).
# Build with the container engine the gateway uses, then pass the tag to `--from`
# (docs/how-it-works/sandboxes/overview.mdx, "Sandbox Images"):
#
#   docker build -t bench-curl:local bench/openshell/image
#
# The non-root `app` user mirrors examples/bring-your-own-container/Dockerfile: the Docker driver
# uses the image USER when the policy omits process identity.
ARG BASE=nvcr.io/nvidia/base/ubuntu:24.04
FROM ${BASE}
USER root
RUN apt-get update \
    && apt-get install -y --no-install-recommends curl ca-certificates \
    && rm -rf /var/lib/apt/lists/*
RUN groupadd --gid 1500 app \
    && useradd --uid 1500 --gid app --create-home app \
    && install -d -o app -g app /sandbox
WORKDIR /sandbox
USER app
