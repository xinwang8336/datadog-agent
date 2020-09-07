// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-2020 Datadog, Inc.

// +build linux

package probe

import (
	"bytes"
	"encoding/binary"
	"os"
	"syscall"

	"github.com/pkg/errors"

	"github.com/DataDog/datadog-agent/pkg/security/ebpf"
	"github.com/DataDog/datadog-agent/pkg/security/utils"
	"github.com/DataDog/datadog-agent/pkg/util/log"
	"github.com/DataDog/gopsutil/process"
)

// processSnapshotTables list of tables used to snapshot
var processSnapshotTables = []string{
	"inode_numlower",
}

// processSnapshotProbes list of hooks used to snapshot
var processSnapshotProbes = []*ebpf.KProbe{
	{
		Name:      "getattr",
		EntryFunc: "kprobe/vfs_getattr",
	},
}

// ProcCacheEntry this structure holds the container context that we keep in kernel for each process
type ProcCacheEntry struct {
	Inode    uint64
	Numlower uint32
	Padding  uint32
	ID       [utils.ContainerIDLen]byte
}

// Bytes returns the bytes representation of process cache entry
func (pc *ProcCacheEntry) Bytes() []byte {
	b := make([]byte, 16+utils.ContainerIDLen)
	byteOrder.PutUint64(b[0:8], pc.Inode)
	byteOrder.PutUint32(b[8:12], pc.Numlower)
	copy(b[16:16+utils.ContainerIDLen], pc.ID[:])
	return b
}

func (pc *ProcCacheEntry) UnmarshalBinary(data []byte) (int, error) {
	if len(data) < 16+utils.ContainerIDLen {
		return 0, ErrNotEnoughData
	}

	pc.Inode = byteOrder.Uint64(data[0:8])
	pc.Numlower = byteOrder.Uint32(data[8:12])

	if err := binary.Read(bytes.NewBuffer(data[16:utils.ContainerIDLen+16]), byteOrder, &pc.ID); err != nil {
		return 0, err
	}

	return 16 + utils.ContainerIDLen, nil
}

type ProcessResolverEntry struct {
	Filename string
}

// ProcessResolver resolved process context
type ProcessResolver struct {
	probe            *Probe
	inodeNumlowerMap *ebpf.Table
	procCacheMap     *ebpf.Table
	pidCookieMap     *ebpf.Table
	entryCache       map[uint32]*ProcessResolverEntry
}

func (p *ProcessResolver) AddEntry(pid uint32, entry *ProcessResolverEntry) {
	p.entryCache[pid] = entry
}

func (p *ProcessResolver) DelEntry(pid uint32) {
	delete(p.entryCache, pid)
}

func (p *ProcessResolver) Resolve(pid uint32) *ProcessResolverEntry {
	entry, ok := p.entryCache[pid]
	if ok {
		return entry
	}

	// fallback request the map directly, the perf event should be delayed
	pidb := make([]byte, 4)
	byteOrder.PutUint32(pidb, pid)

	cookieb, err := p.pidCookieMap.Get(pidb)
	if err != nil {
		return nil
	}

	entryb, err := p.procCacheMap.Get(cookieb)
	if err != nil {
		return nil
	}

	var procCacheEntry ProcCacheEntry
	if _, err := procCacheEntry.UnmarshalBinary(entryb); err != nil {
		return nil
	}

	return nil
}

func (p *ProcessResolver) Start() error {
	// Select the in-kernel process cache that will be populated by the snapshot
	p.procCacheMap = p.probe.Table("proc_cache")
	if p.procCacheMap == nil {
		return errors.New("proc_cache BPF_HASH table doesn't exist")
	}

	// Select the in-kernel pid <-> cookie cache
	p.pidCookieMap = p.probe.Table("pid_cookie")
	if p.pidCookieMap == nil {
		return errors.New("pid_cookie BPF_HASH table doesn't exist")
	}

	return nil
}

func (p *ProcessResolver) snapshot(containerResolver *ContainerResolver, mountResolver *MountResolver) error {
	processes, err := process.AllProcesses()
	if err != nil {
		return err
	}

	cacheModified := false

	for _, proc := range processes {
		// If Exe is not set, the process is a short lived process and its /proc entry has already expired, move on.
		if len(proc.Exe) == 0 {
			continue
		}

		// Notify that we modified the cache.
		if p.snapshotProcess(uint32(proc.Pid), containerResolver, mountResolver) {
			cacheModified = true
		}
	}

	// There is a possible race condition where a process could have started right after we did the call to
	// process.AllProcesses and before we inserted the cache entry of its parent. Call Snapshot again until we
	// do not modify the process cache anymore
	if cacheModified {
		return errors.New("cache modified")
	}

	return nil
}

// snapshotProcess snapshots /proc for the provided pid. This method returns true if it updated the kernel process cache.
func (p *ProcessResolver) snapshotProcess(pid uint32, containerResolver *ContainerResolver, mountResolver *MountResolver) bool {
	entry := ProcCacheEntry{}
	pidb := make([]byte, 4)
	cookieb := make([]byte, 4)
	inodeb := make([]byte, 8)

	// Check if there already is an entry in the pid <-> cookie cache
	byteOrder.PutUint32(pidb, pid)
	if _, err := p.pidCookieMap.Get(pidb); err == nil {
		// If there is a cookie, there is an entry in cache, we don't need to do anything else
		return false
	}

	// Populate the mount point cache for the process
	if err := mountResolver.SyncCache(pid); err != nil {
		if !os.IsNotExist(err) {
			log.Debug(errors.Wrapf(err, "snapshot failed for %d: couldn't sync mount points", pid))
			return false
		}
	}

	// Retrieve the container ID of the process
	containerID, err := containerResolver.GetContainerID(pid)
	if err != nil {
		log.Debug(errors.Wrapf(err, "snapshot failed for %d: couldn't parse container ID", pid))
		return false
	}
	entry.ID = containerID.Bytes()

	procExecPath := utils.ProcExePath(pid)

	// Get process filename and pre-fill the cache
	filename, err := os.Readlink(procExecPath)
	if err != nil {
		log.Debug(errors.Wrapf(err, "snapshot failed for %d: couldn't readlink binary", pid))
		return false
	}
	p.AddEntry(pid, &ProcessResolverEntry{
		Filename: filename,
	})

	// Get the inode of the process binary
	fi, err := os.Stat(procExecPath)
	if err != nil {
		log.Debug(errors.Wrapf(err, "snapshot failed for %d: couldn't stat binary", pid))
		return false
	}
	stat, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		log.Debug(errors.Wrapf(err, "snapshot failed for %d: couldn't stat binary", pid))
		return false
	}
	entry.Inode = stat.Ino

	// Fetch the numlower value of the inode
	byteOrder.PutUint64(inodeb, stat.Ino)
	numlowerb, err := p.inodeNumlowerMap.Get(inodeb)
	if err != nil {
		log.Debug(errors.Wrapf(err, "snapshot failed for %d: couldn't retrieve numlower value", pid))
		return false
	}
	entry.Numlower = byteOrder.Uint32(numlowerb)

	// Generate a new cookie for this pid
	byteOrder.PutUint32(cookieb, utils.NewCookie())

	// Insert the new cache entry and then the cookie
	if err := p.procCacheMap.SetP(cookieb, entry.Bytes()); err != nil {
		log.Debug(errors.Wrapf(err, "snapshot failed for %d: couldn't insert cache entry", pid))
		return false
	}
	if err := p.pidCookieMap.SetP(pidb, cookieb); err != nil {
		log.Debug(errors.Wrapf(err, "snapshot failed for %d: couldn't insert cookie", pid))
		return false
	}

	return true
}

func (p *ProcessResolver) Snapshot(containerResolver *ContainerResolver, mountResolver *MountResolver) error {
	// Register snapshot tables
	for _, t := range processSnapshotTables {
		if err := p.probe.RegisterTable(t); err != nil {
			return err
		}
	}

	// Select the inode numlower map to prepare for the snapshot
	p.inodeNumlowerMap = p.probe.Table("inode_numlower")
	if p.inodeNumlowerMap == nil {
		return errors.New("inode_numlower BPF_HASH table doesn't exist")
	}

	// Activate the probes required by the snapshot
	for _, kp := range processSnapshotProbes {
		if err := p.probe.Module.RegisterKprobe(kp); err != nil {
			return errors.Wrapf(err, "couldn't register kprobe %s", kp.Name)
		}
	}

	// Deregister probes
	defer func() {
		for _, kp := range processSnapshotProbes {
			if err := p.probe.Module.UnregisterKprobe(kp); err != nil {
				log.Debugf("couldn't unregister kprobe %s: %v", kp.Name, err)
			}
		}
	}()

	retry := 5

	for retry > 0 {
		if err := p.snapshot(containerResolver, mountResolver); err == nil {
			return nil
		}

		retry--
	}

	return errors.New("unable to snapshot processes")
}

// NewProcessResolver returns a new process resolver
func NewProcessResolver(probe *Probe) (*ProcessResolver, error) {
	return &ProcessResolver{
		probe:      probe,
		entryCache: make(map[uint32]*ProcessResolverEntry),
	}, nil
}
