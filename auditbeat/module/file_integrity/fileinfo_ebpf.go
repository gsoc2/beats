// Licensed to Elasticsearch B.V. under one or more contributor
// license agreements. See the NOTICE file distributed with
// this work for additional information regarding copyright
// ownership. Elasticsearch B.V. licenses this file to you under
// the Apache License, Version 2.0 (the "License"); you may
// not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

//go:build linux

package file_integrity

import (
	"os"
	"os/user"
	"strconv"

	"github.com/elastic/ebpfevents"
)

func metadataFromFileCreate(evt *ebpfevents.FileCreate) Metadata {
	var md Metadata
	fillFileInfo(&md, evt.Finfo)
	fillExtendedAttributes(&md, evt.Path)
	return md
}

func metadataFromFileRename(evt *ebpfevents.FileRename) Metadata {
	var md Metadata
	fillFileInfo(&md, evt.Finfo)
	fillExtendedAttributes(&md, evt.NewPath)
	return md
}

func metadataFromFileDelete(evt *ebpfevents.FileDelete) Metadata {
	var md Metadata
	fillFileInfo(&md, evt.Finfo)
	fillExtendedAttributes(&md, evt.Path)
	return md
}

func fillFileInfo(md *Metadata, finfo ebpfevents.FileInfo) {
	var owner, group string

	u, err := user.LookupId(strconv.FormatUint(uint64(finfo.Uid), 10))
	if err != nil {
		owner = "n/a"
	} else {
		owner = u.Username
	}

	g, err := user.LookupGroupId(strconv.FormatUint(uint64(finfo.Gid), 10))
	if err != nil {
		group = "n/a"
	} else {
		group = g.Name
	}

	md.Inode = finfo.Inode
	md.UID = finfo.Uid
	md.GID = finfo.Gid
	md.Owner = owner
	md.Group = group
	md.Size = finfo.Size
	md.MTime = finfo.Mtime
	md.CTime = finfo.Ctime
	md.Type = typeFromEbpfType(finfo.Type)
	md.Mode = finfo.Mode
	md.SetUID = finfo.Mode&os.ModeSetuid != 0
	md.SetGID = finfo.Mode&os.ModeSetgid != 0
}

func typeFromEbpfType(typ ebpfevents.FileType) Type {
	switch typ {
	case ebpfevents.FileTypeFile:
		return FileType
	case ebpfevents.FileTypeDir:
		return DirType
	case ebpfevents.FileTypeSymlink:
		return SymlinkType
	case ebpfevents.FileTypeCharDevice:
		return CharDeviceType
	case ebpfevents.FileTypeBlockDevice:
		return BlockDeviceType
	case ebpfevents.FileTypeNamedPipe:
		return FIFOType
	case ebpfevents.FileTypeSocket:
		return SocketType
	default:
		return UnknownType
	}
}
