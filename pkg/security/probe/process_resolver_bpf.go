// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-2020 Datadog, Inc.

// +build linux_bpf

package probe

import (
	"os"
	"syscall"
	"time"

	"github.com/pkg/errors"

	"github.com/DataDog/datadog-agent/pkg/security/ebpf"
	"github.com/DataDog/datadog-agent/pkg/security/utils"
	"github.com/DataDog/datadog-agent/pkg/util/log"
	"github.com/DataDog/gopsutil/process"
)

// processSnapshotTables list of tables used to snapshot
var processSnapshotTables = []string{
	"inode_info_cache",
}

// processSnapshotProbes list of hooks used to snapshot
var processSnapshotProbes = []*ebpf.KProbe{
	{
		Name:      "getattr",
		EntryFunc: "kprobe/vfs_getattr",
	},
}

// InodeInfo holds information related to inode from kernel
type InodeInfo struct {
	MountID         uint32
	OverlayNumLower int32
}

// ProcessResolver resolved process context
type ProcessResolver struct {
	probe        *Probe
	resolvers    *Resolvers
	inodeInfoMap *ebpf.Table
	procCacheMap *ebpf.Table
	pidCookieMap *ebpf.Table
	entryCache   map[uint32]*ProcessCacheEntry
}

// UnmarshalBinary unmarshals a binary representation of itself
func (i *InodeInfo) UnmarshalBinary(data []byte) (int, error) {
	if len(data) < 8 {
		return 0, ErrNotEnoughData
	}
	i.MountID = byteOrder.Uint32(data)
	i.OverlayNumLower = int32(byteOrder.Uint32(data[4:]))
	return 8, nil
}

// AddEntry add an entry to the local cache
func (p *ProcessResolver) AddEntry(pid uint32, entry *ProcessCacheEntry) {
	// resolve now, so that the dentry cache is up to date
	entry.FileEvent.ResolveInode(p.resolvers)
	entry.FileEvent.ResolveContainerPath(p.resolvers)
	entry.ContainerEvent.ResolveContainerID(p.resolvers)

	if entry.Timestamp.IsZero() {
		entry.Timestamp = p.resolvers.TimeResolver.ResolveMonotonicTimestamp(entry.TimestampRaw)
	}

	p.entryCache[pid] = entry
}

// DelEntry removes an entry from the cache
func (p *ProcessResolver) DelEntry(pid uint32) {
	delete(p.entryCache, pid)

	pidb := make([]byte, 4)
	byteOrder.PutUint32(pidb, pid)

	p.pidCookieMap.Delete(pidb)
}

func (p *ProcessResolver) resolve(pid uint32) *ProcessCacheEntry {
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

	var entry ProcessCacheEntry
	if _, err := entry.UnmarshalBinary(entryb); err != nil {
		return nil
	}

	p.AddEntry(pid, &entry)

	return &entry
}

// Resolve returns the cache entry for the given pid
func (p *ProcessResolver) Resolve(pid uint32) *ProcessCacheEntry {
	entry, ok := p.entryCache[pid]
	if ok {
		return entry
	}

	// fallback request the map directly, the perf event should be delayed
	return p.resolve(pid)
}

func (p *ProcessResolver) Get(pid uint32) *ProcessCacheEntry {
	return p.entryCache[pid]
}

// Start starts the resolver
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

func (p *ProcessResolver) snapshot() error {
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
		if p.snapshotProcess(proc) {
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

func (p *ProcessResolver) retrieveInodeInfo(inode uint64) (*InodeInfo, error) {
	inodeb := make([]byte, 8)

	byteOrder.PutUint64(inodeb, inode)
	data, err := p.inodeInfoMap.Get(inodeb)
	if err != nil {
		return nil, err
	}

	var info InodeInfo
	if _, err := info.UnmarshalBinary(data); err != nil {
		return nil, err
	}

	return &info, nil
}

// snapshotProcess snapshots /proc for the provided pid. This method returns true if it updated the kernel process cache.
func (p *ProcessResolver) snapshotProcess(proc *process.FilledProcess) bool {
	pid := uint32(proc.Pid)

	if _, exists := p.entryCache[pid]; exists {
		return false
	}

	// create time
	timestamp := time.Unix(0, proc.CreateTime*int64(time.Millisecond))

	// Populate the mount point cache for the process
	if err := p.resolvers.MountResolver.SyncCache(pid); err != nil {
		if !os.IsNotExist(err) {
			log.Debug(errors.Wrapf(err, "snapshot failed for %d: couldn't sync mount points", pid))
			return false
		}
	}

	// Retrieve the container ID of the process
	containerID, err := p.resolvers.ContainerResolver.GetContainerID(pid)
	if err != nil {
		log.Debug(errors.Wrapf(err, "snapshot failed for %d: couldn't parse container ID", pid))
		return false
	}

	procExecPath := utils.ProcExePath(pid)

	// Get process filename and pre-fill the cache
	pathnameStr, err := os.Readlink(procExecPath)
	if err != nil {
		log.Debug(errors.Wrapf(err, "snapshot failed for %d: couldn't readlink binary", pid))
		return false
	}

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
	inode := stat.Ino

	info, err := p.retrieveInodeInfo(inode)
	if err != nil {
		log.Debug(errors.Wrapf(err, "snapshot failed for %d: couldn't retrieve inode info", pid))
		return false
	}

	// preset and add the entry to the cache
	entry := &ProcessCacheEntry{
		FileEvent: FileEvent{
			Inode:           inode,
			OverlayNumLower: info.OverlayNumLower,
			MountID:         info.MountID,
			PathnameStr:     pathnameStr,
		},
		ContainerEvent: ContainerEvent{
			ID: string(containerID),
		},
		Timestamp: timestamp,
	}

	p.AddEntry(pid, entry)

	return true
}

// Snapshot retrieves the process informations
func (p *ProcessResolver) Snapshot() error {
	// Register snapshot tables
	for _, t := range processSnapshotTables {
		if err := p.probe.RegisterTable(t); err != nil {
			return err
		}
	}

	// Select the inode numlower map to prepare for the snapshot
	p.inodeInfoMap = p.probe.Table("inode_info_cache")
	if p.inodeInfoMap == nil {
		return errors.New("inode_info_cache BPF_HASH table doesn't exist")
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

	for retry := 0; retry < 5; retry++ {
		if err := p.snapshot(); err == nil {
			return nil
		}
	}

	return errors.New("unable to snapshot processes")
}

// NewProcessResolver returns a new process resolver
func NewProcessResolver(probe *Probe, resolvers *Resolvers) (*ProcessResolver, error) {
	return &ProcessResolver{
		probe:      probe,
		resolvers:  resolvers,
		entryCache: make(map[uint32]*ProcessCacheEntry),
	}, nil
}
