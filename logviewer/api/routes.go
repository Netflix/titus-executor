package api

import (
	"errors"
	"fmt"
	"regexp"

	"github.com/Netflix/titus-executor/logviewer/conf"
)

var (
	logsExp             = regexp.MustCompile(`/logs/(.*)`)
	listLogsExp         = regexp.MustCompile(`/listlogs/(.*)`)
	logViewerExp        = regexp.MustCompile(`^/logviewer/([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})`)
	errUnknownContainer = errors.New("Unknown container")
)

func containerIDFromURL(url string, re *regexp.Regexp) (string, error) {
	matchResult := re.FindStringSubmatch(url)

	if len(matchResult) < 1 || matchResult[1] == "" {
		return "", fmt.Errorf("invalid URI: %s: %+v", url, matchResult)
	}

	containerID := matchResult[1]
	if containerID == "" {
		return "", errUnknownContainer
	}

	if conf.RunningInContainer && containerID != conf.ContainerID {
		return "", errUnknownContainer
	}

	return containerID, nil
}
