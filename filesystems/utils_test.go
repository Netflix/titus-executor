package filesystems

import "os"

func mustClose(file *os.File) {
	if err := file.Close(); err != nil {
		panic(err)
	}
}

func mustRemove(file *os.File) {
	if err := os.Remove(file.Name()); err != nil {
		panic(err)
	}
}

func max(x int, y int) int {
	if x > y {
		return x
	}
	return y
}

func min(x int, y int) int {
	if x > y {
		return y
	}
	return x
}
