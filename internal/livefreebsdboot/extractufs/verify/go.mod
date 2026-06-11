module github.com/cloud-boot/tamago-uefi/internal/livefreebsdboot/extractufs/verify

go 1.25.0

require github.com/go-filesystems/ufs v0.0.0

require github.com/go-filesystems/interface v0.0.0 // indirect

// We point at a vendored snapshot of go-filesystems/ufs pinned at
// commit e1250c1 ("Initial pure-Go read-only UFS2 driver", sprint
// 2A). This fixture exercises only the read surface; pinning at the
// last read-only-only commit keeps the verify build immune to the
// concurrent write-side work agent 2C-A is landing on top.
// _ufs_at_head/ is a copy of {block,dirent,errors,fs,inode,path,
// superblock}.go + go.mod + LICENSE from that commit.
replace (
	github.com/go-filesystems/interface => ../../../../../../go-filesystems/interface
	github.com/go-filesystems/ufs => ./_ufs_at_head
)
