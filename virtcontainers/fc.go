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

// agnostic list of kernel parameters
var defaultKernelParameters = []Param{
	{"panic", "1"},
}

type operation int

// Logger returns a logrus logger appropriate for logging qemu messages
func (fc *firecracker) Logger() *logrus.Entry {
	return virtLog.WithField("subsystem", "qemu")
}

func (fc *firecracker) hypervisorConfig() HypervisorConfig {
	return fc.config
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

func (fc *firecracker) hotplugBlockDevice(drive *config.BlockDrive, op operation) error {}

func (fc *firecracker) hotplugDevice(devInfo interface{}, devType deviceType, op operation) (interface{}, error) {
	switch devType {
	case blockDev:
		drive := devInfo.(*config.BlockDrive)
		return nil, q.hotplugBlockDevice(drive, op)
	case cpuDev:
		vcpus := devInfo.(uint32)
		return q.hotplugCPUs(vcpus, op)
	case memoryDev:
		memdev := devInfo.(*memoryDevice)
		return q.hotplugMemory(memdev, op)
	case netDev:
		device := devInfo.(Endpoint)
		return nil, q.hotplugNetDevice(device, op)
	default:
		return nil, fmt.Errorf("cannot hotplug device: unsupported device type '%v'", devType)
	}
}

func (fc *firecracker) hotplugAddDevice(devInfo interface{}, devType deviceType) (interface{}, error) {
	span, _ := q.trace("hotplugAddDevice")
	defer span.Finish()

	return nil, nil
}

func (fc *firecracker) hotplugRemoveDevice(devInfo interface{}, devType deviceType) (interface{}, error)

func (fc *firecracker) pauseSandbox() error {
	return nil
}

func (fc *firecracker) resumeSandbox() error {
	return nil
}

// addDevice will add extra devices to Qemu command line.
func (fc *firecracker) addDevice(devInfo interface{}, devType deviceType) error {
	return nil
}

// getSandboxConsole builds the path of the console where we can read
// logs coming from the sandbox.
func (fc *firecracker) getSandboxConsole(id string) (string, error) {
	return nil
}

func (fc *firecracker) saveSandbox() error {
	return nil
}

// Adds all capabilities supported by firecracker implementation of hypervisor interface
func (fc *firecracker) capabilities() capabilities {
	span, _ := fc.trace("capabilities")
	defer span.Finish()
	var caps capabilities
	caps.set9pUnsupported()
	return caps
}
