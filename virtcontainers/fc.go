// Copyright (c) 2018 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

package virtcontainers

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/kata-containers/runtime/virtcontainers/pkg/uuid"
	opentracing "github.com/opentracing/opentracing-go"
	"github.com/sirupsen/logrus"

	"github.com/kata-containers/runtime/virtcontainers/device/config"
	"github.com/kata-containers/runtime/virtcontainers/utils"
)

// qemu is an Hypervisor interface implementation for the Linux qemu hypervisor.
type firecracker struct {
	id string

	storage resourceStorage

	config HypervisorConfig

	state fcState

	ctx context.Context
}

type operation int

// Logger returns a logrus logger appropriate for logging qemu messages
func (fc *firecracker) Logger() *logrus.Entry {
	return virtLog.WithField("subsystem", "qemu")
}

func (fc *firecracker) trace(name string) (opentracing.Span, context.Context) {
	if q.ctx == nil {
		q.Logger().WithField("type", "bug").Error("trace called before context set")
		q.ctx = context.Background()
	}

	span, ctx := opentracing.StartSpanFromContext(q.ctx, name)

	span.SetTag("subsystem", "hypervisor")
	span.SetTag("type", "qemu")

	return span, ctx
}

//
// init: initialize the firecracker hypervisor's structure. Doesn't
//  actually do anything with firecracker itself, rather it just parses
//  through and provides necessary details for its structs...
//
func (fc *firecracker) init(ctx context.Context, id string, hypervisorConfig *HypervisorConfig, storage resourceStorage) error {
	// save
	fc.ctx = ctx

	span, _ := fc.trace("init")
	defer span.Finish()

	//todo: check validity of the hypervisor config provided

	fc.id = id
	fc.storage = storage
	fc.config = *hypervisorConfig

	return nil
}

func (fc *firecracker) createSandbox() error {
	span, _ := fc.trace("createSandbox")
	defer span.Finish()

	kernelPath, err := fc.config.KernelAssetPath()
	if err != nil {
		return err
	}

	initrdPath, err := fc.config.InitrdAssetPath()
	if err != nil {
		return err
	}

	return nil
}

// startSandbox will start the hypervisor for the given sandbox.
// In the context of firecracker, this will start the hypervisor,
// for configuration, but not yet start the actual virtual machine
func (fc *firecracker) startSandbox() error {
	span, _ := q.trace("startSandbox")
	defer span.Finish()

	//
	// call script to start firecracker process with a unique name
	//  provided by fc.id ? I hope that is unique...

	//TODO

	return nil
}

// waitSandbox will wait for the Sandbox's VM to be up and running.
func (fc *firecracker) waitSandbox(timeout int) error {
	span, _ := q.trace("waitSandbox")
	defer span.Finish()

	if timeout < 0 {
		return fmt.Errorf("Invalid timeout %ds", timeout)
	}

	for {
		//
		// check to see if there's an instance of firecracker
		// to talk with
		//

		// TODO call script to check on the firecracker instance, calling
		// instance-info, using fc.id as a way to identify the socket?
		//

		if int(time.Now().Sub(timeStart).Seconds()) > timeout {
			return fmt.Errorf("Failed to connect to firecrackerinstance (timeout %ds): %v", timeout, err)
		}

		time.Sleep(time.Duration(50) * time.Millisecond)
	}
	return nil
}

// stopSandbox will stop the Sandbox's VM.
func (fc *firecracker) stopSandbox() error {
	span, _ := q.trace("stopSandbox")
	defer span.Finish()

	q.Logger().Info("Stopping Sandbox")

	return nil
}

func (fc *firecracker) pauseSandbox() error {
	return nil
}

func (fc *firecracker) saveSandbox() error {
	return nil
}

func (fc *firecracker) resumeSandbox() error {
	return nil
}

func (fc *firecracker) fcAddNetDevice(endpoint Endpoint) error {
	guest_mac := endpoint.HardwareAddr()
	iface_id := endpoint.Name()
	host_dev_name := iface_id

	//
	// call rest API: {iface_id, guest_mac (endpoint.HardwareAddr(), host_dev_name(?)
	//

	return nil
}

func (fc *firecracker) fcAddBlockDrive(drive config.BlockDrive) error {
	drive_id := config.BlockDrive.ID
	path_on_host := config.BlockDrive.File
	is_root_device := false
	is_read_only := false

	//
	// call rest API
	//

	return nil
}

// addDevice will add extra devices to firecracker.  Limited to configure before the
// virtual machine starts.  Devices include drivers and network interfaces only.
func (fc *firecracker) addDevice(devInfo interface{}, devType deviceType) error {
	span, _ := fc.trace("addDevice")
	defer span.Finish()

	switch v := devInfo.(type) {
	case Endpoint:
		fcAddNetDevice(v)
	case config.BlockDrive:
		fcAddBlockDrive(v)
	default:
		break
	}

	return nil
}

// hotplugAddDevice not supported in Firecracker VMM
func (fc *firecracker) hotplugAddDevice(devInfo interface{}, devType deviceType) (interface{}, error) {
	return nil, fmt.Errorf("firecracker does not support device hotplug")
}

// hotplugRemoveDevice not supported in Firecracker VMM
func (fc *firecracker) hotplugRemoveDevice(devInfo interface{}, devType deviceType) (interface{}, error) {
	return nil, fmt.Errorf("firecracker does not support device hotplug")
}

// getSandboxConsole builds the path of the console where we can read
// logs coming from the sandbox.
//
// we can get logs from firecracker itself; WIP on enabling.  Who needs
// logs when you're just hacking?
func (fc *firecracker) getSandboxConsole(id string) (string, error) {
	return nil, nil
}

func (fc *firecracker) disconnect() {
	// not sure if this is really necessary, at least in the first pass
	return
}

// Adds all capabilities supported by firecracker implementation of hypervisor interface
func (fc *firecracker) capabilities() capabilities {
	span, _ := fc.trace("capabilities")
	defer span.Finish()
	var caps capabilities
	caps.set9pUnsupported()

	return caps
}

func (fc *firecracker) hypervisorConfig() HypervisorConfig {
	return fc.config
}

// this is used to apply cgroup information on the host. not sure how necessary this
// is in the first pass.
//
// Need to see if there's an easy way to ask firecracker for thread ids associated with
// the vCPUs.  Issue opened to ask for per vCPU thread IDs:
//			https://github.com/firecracker-microvm/firecracker/issues/718
func (fc *firecracker) getThreadIDs() (*threadIDs, error) {
	//TODO: this may not be exactly supported in Firecracker. Closest is cpu-template as part
	// of get /machine-config
	return nil, nil
}
