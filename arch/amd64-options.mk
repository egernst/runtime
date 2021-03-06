# Copyright (c) 2018-2019 Intel Corporation
#
# SPDX-License-Identifier: Apache-2.0
#

# Intel x86-64 settings

MACHINETYPE := pc
KERNELPARAMS :=
MACHINEACCELERATORS :=

QEMUCMD := qemu-system-x86_64

# Qemu experimental with virtiofs
QEMUVIRTIOFSCMD := qemu-virtiofs-system-x86_64

# Firecracker binary name
FCCMD := firecracker
# Firecracker's jailer binary name
FCJAILERCMD := jailer

# NEMU binary name
NEMUCMD := nemu-system-x86_64

#ACRN binary name
ACRNCMD := acrn-dm
ACRNCTLCMD := acrnctl
