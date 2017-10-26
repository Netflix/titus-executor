package main

import (
	"fmt"
	"os"
	"time"
)

func check(e error) {
	if e != nil {
		panic(e)

	}
}

func writeFile(fileName string) {
	f, err := os.Create(fileName)
	check(err)

	defer func() {
		if err1 := f.Close(); err1 != nil {
			fmt.Printf("Error closing file: %s\n", err1)
		}
	}()

	for i := 0; i < 3; i++ {
		d2 := []byte{115, 111, 109, 101, 10}
		n2, err := f.Write(d2)
		check(err)
		fmt.Printf("wrote %d bytes\n", n2)
	}
}

func main() {
	err := os.Mkdir("/logs/service", 0777)
	check(err)
	for i := 0; i < 3; i++ {
		writeFile(fmt.Sprintf("/logs/service/service-log-2016-%v.log", i))
		time.Sleep(20 * time.Second)
	}
}
