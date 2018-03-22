package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/Netflix/titus-executor/api/netflix/titus"
	log "github.com/sirupsen/logrus"
)

const (
	defaultConfigFile             = "/etc/titus-executor/config.json"
	defaultStatusCheckFrequency   = 10 * time.Second
	defaultLogUploadThreshold     = 6 * time.Hour
	defaultLogUploadCheckInterval = 15 * time.Minute
	defaultStdioLogCheckInterval  = 1 * time.Minute
	defaultLogsTmpDir             = "/var/lib/titus-container-logs"
)

// Synchronizes access and modification to config variables
var configLock sync.RWMutex

// WTF go!? why do I have to do this bullshit?
type duration time.Duration

func (d duration) MarshalJSON() ([]byte, error) {
	return []byte("\"" + time.Duration(d).String() + "\""), nil
}

func (d *duration) UnmarshalJSON(in []byte) error {
	if len(in) < 2 || in[0] != byte('"') || in[len(in)-1] != byte('"') {
		return errors.New("invalid duration")
	}
	dur, err := time.ParseDuration(string(in[1 : len(in)-1]))
	if err != nil {
		return err
	}
	*d = duration(dur)
	return nil
}

func (d duration) duration() time.Duration {
	return time.Duration(d)
}

type uploaders struct {
	Log  []map[string]string `json:"log"`
	Noop []map[string]string `json:"noop"`
}

type devWorkspace struct {
	DisableMetrics    bool `json:"disableMetrics"`
	MockMetatronCreds bool `json:"mockMetatronCreds"`
}

// This mirrors the logUploadJSON structure, but using standard types (i.e. time.Duration over duration)
type logUpload struct {
	KeepLocalFileAfterUpload bool
	LogUploadThresholdTime   time.Duration
	LogUploadCheckInterval   time.Duration
	StdioLogCheckInterval    time.Duration
}

// logUploadJSON is used for deserialization, the actual config variable is of type logUpload, using time.Duration -- We copy over the values
type logUploadJSON struct {
	LogUploadThresholdTime   duration `json:"logUploadThresholdTime"`
	LogUploadCheckInterval   duration `json:"logUploadCheckInterval"`
	KeepLocalFileAfterUpload bool     `json:"keepLocalFileAfterUpload"`
	StdioLogCheckInterval    duration `json:"stdioLogCheckInterval"`
}

type docker struct {
	Host     string `json:"host"`
	Registry string `json:"registry"`
}

type env struct {
	CopiedFromHost []string          `json:"copiedFromHost"`
	HardCoded      map[string]string `json:"hardCoded"`
}

var currentConfig struct {
	metatronEnabled             bool
	privilegedContainersEnabled bool
	useNewNetworkDriver         bool
	devWorkspace                devWorkspace
	logUpload                   logUpload
	statusCheckFrequency        time.Duration
	logsTmpDir                  string
	stack                       string
	docker                      docker
	env                         env
	uploaders                   uploaders
}

// Load loads the configuration from the given file
func Load(configFilePath string) {
	configLock.Lock()
	defer configLock.Unlock()
	if configFilePath == "" {
		configFilePath = defaultConfigFile
	}
	f, err := os.Open(configFilePath)
	if err != nil {
		log.Fatal("config : " + err.Error())
	}
	defer func() {
		if err := f.Close(); err != nil {
			log.Printf("Failed to close %s: %s", f.Name(), err)
		}
	}()

	var c struct {
		Stack                string        `json:"stack"`
		Zone                 string        `json:"zone"`
		Docker               docker        `json:"docker"`
		Uploaders            uploaders     `json:"uploaders"`
		Env                  env           `json:"env"`
		StatusCheckFrequency duration      `json:"statusCheckFrequency"`
		LogUpload            logUploadJSON `json:"logUpload"`
		DevWorkspace         devWorkspace  `json:"dev"`
		UseNewNetworkDriver  bool          `json:"useNewNetworkDriver"`
		UsePrivilegedTasks   bool          `json:"usePrivilegedTasks"`
		UseMetatron          bool          `json:"useMetatron"`
		LogsTmpDir           string        `json:"logsTmpDir"`
	}
	if err := json.NewDecoder(f).Decode(&c); err != nil {
		log.Fatal("config : " + err.Error())
	}

	currentConfig.stack = c.Stack
	currentConfig.docker = c.Docker
	currentConfig.uploaders = c.Uploaders
	currentConfig.env = c.Env
	currentConfig.devWorkspace = c.DevWorkspace
	currentConfig.useNewNetworkDriver = c.UseNewNetworkDriver
	currentConfig.privilegedContainersEnabled = c.UsePrivilegedTasks
	currentConfig.metatronEnabled = c.UseMetatron
	currentConfig.logsTmpDir = c.LogsTmpDir

	currentConfig.statusCheckFrequency = c.StatusCheckFrequency.duration()
	if currentConfig.statusCheckFrequency == 0 {
		currentConfig.statusCheckFrequency = defaultStatusCheckFrequency
	}

	currentConfig.logUpload.LogUploadCheckInterval = c.LogUpload.LogUploadCheckInterval.duration()
	currentConfig.logUpload.KeepLocalFileAfterUpload = c.LogUpload.KeepLocalFileAfterUpload
	currentConfig.logUpload.LogUploadThresholdTime = c.LogUpload.LogUploadThresholdTime.duration()
	currentConfig.logUpload.StdioLogCheckInterval = c.LogUpload.StdioLogCheckInterval.duration()

	if currentConfig.logUpload.LogUploadThresholdTime == 0 {
		log.Printf("Default LogUploadThresholdTime %v\n", defaultLogUploadThreshold)
		currentConfig.logUpload.LogUploadThresholdTime = defaultLogUploadThreshold
	}

	if currentConfig.logUpload.LogUploadCheckInterval == 0 {
		log.Printf("Default LogUploadCheckInterval %v\n", defaultLogUploadCheckInterval)
		currentConfig.logUpload.LogUploadCheckInterval = defaultLogUploadCheckInterval
	}

	if currentConfig.logUpload.StdioLogCheckInterval == 0 {
		log.Printf("Default StdioLogCheckInterval %v\n", defaultStdioLogCheckInterval)
		currentConfig.logUpload.StdioLogCheckInterval = defaultStdioLogCheckInterval
	}

	if currentConfig.logsTmpDir == "" {
		log.WithField("defaultLogsTmpDir", defaultLogsTmpDir).Debug("Setting default config value")
		currentConfig.logsTmpDir = defaultLogsTmpDir
	}

	log.Debugf("LOG Uploader Configuration %+v\n", currentConfig.logUpload)
}

func getEnv() env {
	configLock.RLock()
	defer configLock.RUnlock()
	return currentConfig.env
}

func GetNetflixEnvForTask(taskInfo *titus.ContainerInfo, mem, cpu, disk, networkBandwidth string) map[string]string { // nolint: golint
	env := getEnvHardcoded()
	env = appendMap(env, getEnvFromHost())
	env = appendMap(env, getEnvBasedOnTask(taskInfo, mem, cpu, disk, networkBandwidth))
	env = appendMap(env, getUserProvided(taskInfo))
	return env
}

func getEnvBasedOnTask(taskInfo *titus.ContainerInfo, mem, cpu, disk, networkBandwidth string) map[string]string {
	env1 := make(map[string]string)

	setClusterInfoBasedOnTask(taskInfo, env1)
	env1["TITUS_NUM_MEM"] = mem
	env1["TITUS_NUM_CPU"] = cpu
	env1["TITUS_NUM_DISK"] = disk
	env1["TITUS_NUM_NETWORK_BANDWIDTH"] = networkBandwidth

	return env1
}

// Sets cluster info based on provided task info.
func setClusterInfoBasedOnTask(taskInfo *titus.ContainerInfo, env map[string]string) {
	// TODO(Andrew L): Remove this check once appName is required
	appName := taskInfo.GetAppName()
	if appName == "" {
		// Use image name as app name if no app name is provided.
		appName = getAppName(taskInfo.GetImageName())
	}

	cluster := combineAppStackDetails(taskInfo, appName)
	env["NETFLIX_APP"] = appName
	env["NETFLIX_CLUSTER"] = cluster
	env["NETFLIX_STACK"] = taskInfo.GetJobGroupStack()
	env["NETFLIX_DETAIL"] = taskInfo.GetJobGroupDetail()

	var asgName string
	if seq := taskInfo.GetJobGroupSequence(); seq == "" {
		asgName = cluster + "-v000"
	} else {
		asgName = cluster + "-" + seq
	}
	env["NETFLIX_AUTO_SCALE_GROUP"] = asgName
}

func getEnvFromHost() map[string]string {
	fromHost := make(map[string]string)

	for _, hostKey := range getEnv().CopiedFromHost {
		if hostKey == "NETFLIX_STACK" {
			// Add agent's stack as TITUS_STACK so platform libraries can
			// determine agent stack, if needed
			addElementFromHost(fromHost, hostKey, "TITUS_STACK")
		} else {
			addElementFromHost(fromHost, hostKey, hostKey)
		}
	}
	return fromHost
}

func addElementFromHost(addTo map[string]string, hostEnvVarName string, containerEnvVarName string) {
	hostVal := os.Getenv(hostEnvVarName)
	if hostVal != "" {
		addTo[containerEnvVarName] = hostVal
	}
}

// Merge user and titus provided ENV vars
func getUserProvided(taskInfo *titus.ContainerInfo) map[string]string {
	var (
		userProvided  = taskInfo.GetUserProvidedEnv()
		titusProvided = taskInfo.GetTitusProvidedEnv()
	)
	if len(userProvided) == 0 && len(titusProvided) == 0 {
		return getUserProvidedDeprecated(taskInfo)
	}

	delete(userProvided, "") // in case users provided key=nil
	// titus provided can override user provided
	return appendMap(userProvided, titusProvided)
}

// ENV from the deprecated environmentVariable field that had both user and Titus provided values merged
func getUserProvidedDeprecated(taskInfo *titus.ContainerInfo) map[string]string {
	vars := make(map[string]string)
	for _, env := range taskInfo.GetEnvironmentVariable() {
		vars[env.GetName()] = env.GetValue()
	}
	return vars
}

// appendMap works like the builtin append function, but for maps. nil can be safely passed in.
func appendMap(m map[string]string, add map[string]string) map[string]string {
	all := make(map[string]string, len(m)+len(add))
	for k, v := range m {
		all[k] = v
	}
	for k, v := range add {
		all[k] = v
	}
	return all
}

// combineAppStackDetails is a port of the method with the same name from frigga.
// See: https://github.com/Netflix/frigga/blob/v0.17.0/src/main/java/com/netflix/frigga/NameBuilder.java
func combineAppStackDetails(taskInfo *titus.ContainerInfo, appName string) string {
	var (
		stack   = taskInfo.GetJobGroupStack()
		details = taskInfo.GetJobGroupDetail()
	)
	if details != "" {
		return fmt.Sprintf("%s-%s-%s", appName, stack, details)
	}
	if stack != "" {
		return fmt.Sprintf("%s-%s", appName, stack)
	}
	return appName
}

// TODO: This is deprecated and should be removed as soon as API is redesigned
func getAppName(imageName string) string {
	split := strings.Split(imageName, "/")
	lastWord := split[len(split)-1]
	appName := ""
	for _, runeVal := range lastWord {
		if unicode.IsLetter(runeVal) || unicode.IsDigit(runeVal) {
			appName += string(runeVal)
		} else {
			appName += "_"
		}
	}
	return appName
}

func getEnvHardcoded() map[string]string {
	env1 := make(map[string]string)

	for k, v := range getEnv().HardCoded {
		env1[k] = v
	}

	return env1
}
