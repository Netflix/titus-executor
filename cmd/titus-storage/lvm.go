package main

import (
	"encoding/json"
	"fmt"
	"math"
	"os"
	"os/exec"
	"strconv"
	"strings"
)

const (
	TitusEphemeralVolumeGroup = "ephemeral"
)

type vgsOutputStructure struct {
	Report []struct {
		Vg []vgStruct `json:"vg"`
	} `json:"report"`
}

type vgStruct struct {
	VgName    string `json:"vg_name"`
	PvCount   string `json:"pv_count"`
	LvCount   string `json:"lv_count"`
	SnapCount string `json:"snap_count"`
	VgAttr    string `json:"vg_attr"`
	VgSize    string `json:"vg_size"`
	VgFree    string `json:"vg_free"`
}

func LogicalVolumeCreate(vgName string, sizeGB int) error {
	size := fmt.Sprintf("%dG", sizeGB)
	cmd := exec.Command("/sbin/lvcreate", TitusEphemeralVolumeGroup, "--name", vgName, "--size", size)
	fmt.Printf("%+v\n", cmd)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func LogicalVolumeRemove(vgName string) error {
	cmd := exec.Command("/sbin/lvremove", TitusEphemeralVolumeGroup, vgName, "--yes", "--force")
	fmt.Printf("%+v\n", cmd)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func LogicalVolumeSizeGB(vgName string) (int, error) {
	cmd := exec.Command("/sbin/vgs", vgName, "--reportformat", "json", "--units", "G")
	fmt.Printf("%+v\n", cmd)
	// err := cmd.Run()
	// if err != nil {
	// 	return -1, fmt.Errorf("Error running vgs: %w", err)
	// }
	var vgsOputput vgsOutputStructure
	cmd.Stderr = os.Stderr
	stdout, err := cmd.Output()
	if err != nil {
		return -1, fmt.Errorf("Error running vgs: %w", err)
	}
	err = json.Unmarshal(stdout, &vgsOputput)
	if err != nil {
		return -1, fmt.Errorf("Error parsing vgs json output: %w - output '%s'", err, stdout)
	}
	sizeGB, err := getVGSize(vgsOputput, vgName)
	if err != nil {
		return -1, fmt.Errorf("Error parsing vgs output to get the size: %w - original output: '%s'", err, stdout)
	}
	return sizeGB, nil
}

func getVGSize(vgsOutput vgsOutputStructure, vgName string) (int, error) {
	report := vgsOutput.Report
	vgList := report[0].Vg
	vg := findVGByName(vgList, vgName)
	if vg.VgName == "" {
		return -1, fmt.Errorf("Couldn't find %s in the list of vgs: %+v", vgName, vgList)
	}
	size, err := convertAndRoundGString(vg.VgSize)
	if err != nil {
		return -1, fmt.Errorf("Couldn't interpret the GB of this string: '%s' - %w", vg.VgSize, err)
	}
	return size, nil
}

func findVGByName(vgList []vgStruct, vgName string) vgStruct {
	for _, vg := range vgList {
		if vg.VgName == vgName {
			return vg
		}
	}
	return vgStruct{}
}

func convertAndRoundGString(in string) (int, error) {
	cleaned := strings.ReplaceAll(in, "G", "")
	i, err := strconv.ParseFloat(cleaned, 32)
	return int(math.Round(i)), err
}
