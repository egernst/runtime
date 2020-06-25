// Copyright (c) 2020 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

package cgroups

import (
	"bufio"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	"github.com/containerd/cgroups"
	cgroupsv2 "github.com/containerd/cgroups/v2"
	"github.com/kata-containers/runtime/virtcontainers/pkg/rootless"
	specs "github.com/opencontainers/runtime-spec/specs-go"
	"github.com/sirupsen/logrus"
)

type Config struct {
	Mode          int
	systemdCgroup *bool
}

type cgroupPather interface {
	cgroups.Subsystem
	Path(path string) string
}

type Manager struct {
	sync.Mutex
}

const (
	// file in the cgroup that contains the pids
	cgroupProcs = "cgroup.procs"
)

var (
	cgroupsLogger = logrus.WithField("source", "virtcontainers/pkg/cgroups")
)

// SetLogger sets up a logger for this pkg
func SetLogger(logger *logrus.Entry) {
	fields := cgroupsLogger.Data
	cgroupsLogger = logger.WithFields(fields)
}

func SystemdHostCgroupSubsystems() ([]cgroups.Subsystem, error) {
	root, err := cgroupV1MountPoint()
	if err != nil {
		return nil, err
	}
	s, err := cgroups.NewSystemd(root)
	if err != nil {
		return nil, err
	}
	subsystems, err := V1HostCgroupSubsystems()
	if err != nil {
		return nil, err
	}

	// Make sure the systemd controller is added first:
	return append([]cgroups.Subsystem{s}, subsystems...), nil

}

func V1HostCgroupSubsystems() ([]cgroups.Subsystem, error) {
	root, err := cgroupV1MountPoint()
	if err != nil {
		return nil, err
	}
	subsystems := []cgroups.Subsystem{
		cgroups.NewCputset(root),
	}

	return cgroupsSubsystems(subsystems)
}

func isSystemd() bool {
	return false
}

// New: create the cgroup.
func New() (*Manager, error) {

	var (
		cg  cgroups.Cgroup
		cg2 *cgroupsv2.Manager
	)

	path := ""

	// V2 or V1?
	if cgroups.Mode() == cgroups.Unified {
		// we are working with a v2 manager
		cg2, err := cgroupsv2.NewManager("/sys/fs/cgroup", path, &cgroupsv2.Resources{})
		if err != nil {
			return nil, err
		}
		defer cg2.Delete()
	} else {
		if isSystemd() {
			cg, _ = cgroups.New(SystemdHostCgroupSubsystems, cgroups.StaticPath(path), &specs.LinuxResources{})
		} else {
			cg, _ = cgroups.New(V1HostCgroupSubsystems, cgroups.StaticPath(path), &specs.LinuxResources{})
		}

		cg.Update(nil)
	}

	return nil, nil
}

// read all the pids in cgroupPath
func readPids(cgroupPath string) ([]int, error) {
	pids := []int{}
	f, err := os.Open(filepath.Join(cgroupPath, cgroupProcs))
	if err != nil {
		return nil, err
	}
	defer f.Close()
	buf := bufio.NewScanner(f)

	for buf.Scan() {
		if t := buf.Text(); t != "" {
			pid, err := strconv.Atoi(t)
			if err != nil {
				return nil, err
			}
			pids = append(pids, pid)
		}
	}
	return pids, nil
}

// write the pids into cgroup.procs
func writePids(pids []int, cgroupPath string) error {
	cgroupProcsPath := filepath.Join(cgroupPath, cgroupProcs)
	for _, pid := range pids {
		if err := ioutil.WriteFile(cgroupProcsPath,
			[]byte(strconv.Itoa(pid)),
			os.FileMode(0),
		); err != nil {
			return err
		}
	}
	return nil
}

func (m *Manager) logger() *logrus.Entry {
	return cgroupsLogger.WithField("source", "cgroup-manager")
}

// Add pid to cgroups
func (m *Manager) Add(pid int) error {
	if rootless.IsRootless() {
		m.logger().Debug("Unable to setup add pids to cgroup: running rootless")
		return nil
	}

	return nil
}

// Apply constraints
func (m *Manager) Apply() error {
	return nil
}

func (m *Manager) GetCgroups() (*cgroups.Cgroup, error) {
	return nil, nil
}

func (m *Manager) Destroy() error {
	return nil
}

// AddDevice adds a device to the device cgroup
func (m *Manager) AddDevice(device string) error {
	//ld, err := DeviceToCgroupDevice(device)
	return nil
}

// RemoveDevice removed a device from the device cgroup
func (m *Manager) RemoveDevice(device string) error {
	return nil
}

func (m *Manager) UpdateCpuSets(cpuset string) error {
	return nil
}

// v1MountPoint returns the mount point where the cgroup
// mountpoints are mounted in a single hiearchy
func cgroupV1MountPoint() (string, error) {
	f, err := os.Open("/proc/self/mountinfo")
	if err != nil {
		return "", err
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		if err := scanner.Err(); err != nil {
			return "", err
		}
		var (
			text   = scanner.Text()
			fields = strings.Split(text, " ")
			// safe as mountinfo encodes mountpoints with spaces as \040.
			index               = strings.Index(text, " - ")
			postSeparatorFields = strings.Fields(text[index+3:])
			numPostFields       = len(postSeparatorFields)
		)
		// this is an error as we can't detect if the mount is for "cgroup"
		if numPostFields == 0 {
			return "", fmt.Errorf("Found no fields post '-' in %q", text)
		}
		if postSeparatorFields[0] == "cgroup" {
			// check that the mount is properly formated.
			if numPostFields < 3 {
				return "", fmt.Errorf("Error found less than 3 fields post '-' in %q", text)
			}
			return filepath.Dir(fields[4]), nil
		}
	}
	return "", cgroups.ErrMountPointNotExist
}

func cgroupsSubsystems(subsystems []cgroups.Subsystem) ([]cgroups.Subsystem, error) {
	var enabled []cgroups.Subsystem
	for _, s := range cgroupPathers(subsystems) {
		// check and remove the default groups that do not exist
		if _, err := os.Lstat(s.Path("/")); err == nil {
			enabled = append(enabled, s)
		}
	}
	return enabled, nil
}

func cgroupPathers(subystems []cgroups.Subsystem) []cgroupPather {
	var out []cgroupPather
	for _, s := range subystems {
		if p, ok := s.(cgroupPather); ok {
			out = append(out, p)
		}
	}
	return out
}
