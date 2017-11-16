package core

// cleanUpEvent should be used when tearing a container down
type cleanUpEvent interface {
	CleanUpEvent
	done() <-chan struct{}
}

// launchEvent is used to synchronize launching containers
type launchEvent interface {
	LaunchEvent
	notifyLaunch()
}

// CleanUpEvent should be used when tearing a container down
type CleanUpEvent interface {
	Done()
}

// LaunchEvent is used to synchronize launching containers
type LaunchEvent interface {
	Launch() <-chan struct{}
}
