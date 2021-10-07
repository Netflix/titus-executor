//go:build linux
// +build linux

package xattr

import (
	"crypto/rand"
	"io/ioutil"
	"testing"

	"golang.org/x/sys/unix"
)

func TestFallocate(t *testing.T) {
	skipIfUnsupportedFilesystem(t)
	b := make([]byte, 1024*1024*16)
	_, err := rand.Read(b)
	if err != nil {
		t.Fatal("Couldn't generate random data:", err)
	}

	testfile, err := ioutil.TempFile(".", "fallocate-test")
	if err != nil {
		t.Fatal("Couldn't create temp file:", err)
	}

	defer mustRemove(testfile)

	_, err = testfile.Write(b)
	if err != nil {
		t.Fatal("Couldn't write to temp file:", err)
	}

	var stat1, stat2 unix.Stat_t

	err = unix.Fstat(int(testfile.Fd()), &stat1)
	if err != nil {
		t.Fatal("Couldn't stat temp file:", err)
	}

	// Start should get rounded up to 8192
	// Length should get turned into 8192 as well
	err = MakeHole(testfile, 4097, 11059)
	if err != nil {
		t.Fatal("Couldn't make hole in temp file:", err)
	}

	err = unix.Fstat(int(testfile.Fd()), &stat2)
	if err != nil {
		t.Fatal("Couldn't stat temp file:", err)
	}

	// Blocks is a little misleading. It's not accounted for in st_blksize (blocksize for file system I/O),
	// but instead it's accounted for as the number of 512B blocks allocated.
	// Unfortunately, the filesystem (logical block size) may also be different! Therefore we have to use the logical
	// block size, as it should be bigger or equal to the physical block size

	if stat1.Blocks*512 != int64(len(b)) {
		t.Fatal("Initial size unexpected: ", stat1.Blocks)
	}

	if 512*(stat1.Blocks-stat2.Blocks) != 8192 {
		t.Fatal("Incorrect number of blocks freed")
	}
}
