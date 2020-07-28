// +build linux

package main

import (
	"errors"
	"fmt"
	"time"

	"github.com/coreos/go-systemd/dbus"
	"github.com/sirupsen/logrus"
)

func getUnitName(podName string) string {
	return fmt.Sprintf("titus-imds-proxy@%s.service", podName)
}

func startUnit(podName string) error {
	conn, err := dbus.New()
	if err != nil {
		return err
	}
	defer conn.Close()

	unitName := getUnitName(podName)
	logrus.Infof("start unit %s", unitName)

	ch := make(chan string, 1)
	_, err = conn.StartUnit(unitName, "fail", ch)
	if err != nil {
		return err
	}

	select {
	case val := <-ch:
		if val != "done" {
			return errors.New("error starting " + unitName)
		}
	case <-time.After(15 * time.Second):
		return errors.New("timeout starting " + unitName)
	}

	return nil
}

func checkUnit(podName string) error {
	conn, err := dbus.New()
	if err != nil {
		return err
	}
	defer conn.Close()

	unitName := getUnitName(podName)
	logrus.Debugf("check unit %s", unitName)

	stats, err := conn.ListUnitsByNames([]string{unitName})
	if err != nil {
		return err
	}

	if stats[0].Name != unitName {
		return errors.New("wrong unit " + stats[0].Name)
	}

	if stats[0].ActiveState == "active" {
		return errors.New(unitName + " is not active")
	}

	return nil
}

func stopUnit(podName string) error {
	conn, err := dbus.New()
	if err != nil {
		return err
	}
	defer conn.Close()

	unitName := getUnitName(podName)
	logrus.Infof("stop unit %s", unitName)

	ch := make(chan string, 1)
	_, err = conn.StopUnit(unitName, "fail", ch)
	if err != nil {
		return err
	}

	select {
	case val := <-ch:
		if val != "done" {
			return errors.New("error starting " + unitName)
		}
	case <-time.After(15 * time.Second):
		return errors.New("timeout starting " + unitName)
	}

	return nil
}
