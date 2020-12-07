package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"os"

	"github.com/sirupsen/logrus"

	"github.com/wercker/journalhook"

	"github.com/opencontainers/runtime-spec/specs-go"
)

func doPrestart() error {
	journalhook.Enable()
	bundleDirPath, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("get working directory: %w", err)
	}

	logrus.Infof("Using bundle file: %s\n", bundleDirPath+"/config.json")
	jsonFile, err := os.OpenFile(bundleDirPath+"/config.json", os.O_RDWR, 0644)
	if err != nil {
		return fmt.Errorf("Couldn't open OCI spec file: %w", err)
	}
	defer jsonFile.Close()

	jsonContent, err := ioutil.ReadAll(jsonFile)
	if err != nil {
		return fmt.Errorf("Couldn't read OCI spec file: %w", err)
	}
	var spec specs.Spec
	err = json.Unmarshal(jsonContent, &spec)
	if err != nil {
		return fmt.Errorf("Couldn't unmarshal OCI spec file: %w", err)
	}

	// TODO: Add stuff

	jsonOutput, err := json.Marshal(spec)
	if err != nil {
		return fmt.Errorf("Couldn't marshal OCI spec file: %w", err)
	}
	_, err = jsonFile.WriteAt(jsonOutput, 0)
	if err != nil {
		return fmt.Errorf("Couldn't write OCI spec file: %w", err)
	}

	return nil
}

func usage() {
	fmt.Fprintf(os.Stderr, "Usage of %s:\n", os.Args[0])
	flag.PrintDefaults()
	fmt.Fprintf(os.Stderr, "\nCommands:\n")
	fmt.Fprintf(os.Stderr, "  prestart\n        run the prestart hook\n")
	fmt.Fprintf(os.Stderr, "  poststart\n       run the poststart hook\n")
	fmt.Fprintf(os.Stderr, "  poststop\n        run the poststop hook\n")
}

func main() {
	flag.Usage = usage
	flag.Parse()

	args := flag.Args()
	if len(args) == 0 {
		flag.Usage()
		os.Exit(2)
	}

	switch args[0] {
	case "prestart":
		err := doPrestart()
		if err != nil {
			logrus.Fatal(err)
		}
		os.Exit(0)
	case "poststart":
		os.Exit(0)
	case "poststop":
		os.Exit(0)
	default:
		flag.Usage()
		os.Exit(2)
	}
}
