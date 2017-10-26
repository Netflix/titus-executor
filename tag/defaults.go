package tag

import (
	"os"
)

// Defaults to be added to all metrics
var Defaults = map[string]string{
	"stack": os.Getenv("NETFLIX_STACK"),
	"node":  os.Getenv("EC2_INSTANCE_ID"),
	"asg":   os.Getenv("NETFLIX_AUTO_SCALE_GROUP"),
}
