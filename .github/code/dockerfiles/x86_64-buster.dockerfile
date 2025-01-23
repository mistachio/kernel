# SPDX-License-Identifier: GPL-2.0-only
# Copyright (c) 2024 ByteDance.

FROM --platform=linux/amd64 debian:10

RUN mkdir /linux
RUN mkdir /linux/src
RUN mkdir /linux/output

RUN apt update
RUN apt install -y bc
RUN apt install -y bison
RUN apt install -y ccache
RUN apt install -y cpio
RUN apt install -y dpkg-dev
RUN apt install -y flex
RUN apt install -y gcc
RUN apt install -y git
RUN apt install -y kmod
RUN apt install -y libaudit-dev
RUN apt install -y libbfd-dev
RUN apt install -y libdw-dev
RUN apt install -y libelf-dev
RUN apt install -y libiberty-dev
RUN apt install -y liblzma-dev
RUN apt install -y libnuma-dev
RUN apt install -y libperl-dev
RUN apt install -y libslang2-dev
RUN apt install -y libssl-dev
RUN apt install -y libunwind-dev
RUN apt install -y libunwind8-dev
RUN apt install -y make
RUN apt install -y pkg-config
RUN apt install -y python
RUN apt install -y python3
RUN apt install -y python3-pip
RUN apt install -y python3-requests
RUN apt install -y rsync
RUN apt install -y lsb-release
RUN apt install -y python-dev
RUN apt install -y python3-dev
RUN apt install -y sshpass
RUN apt install -y debhelper
RUN apt install -y libpci-dev
RUN apt install -y libcap-dev
RUN apt install -y systemtap-sdt-dev
RUN apt install -y libzstd-dev
RUN apt install -y libbabeltrace-dev
RUN apt install -y libpfm4-dev
ENV NO_LIBTRACEEVENT=1

# WA for install pahole>=1.13
RUN echo "deb http://deb.debian.org/debian bullseye main" >> /etc/apt/sources.list
RUN apt update && apt install -y dwarves
