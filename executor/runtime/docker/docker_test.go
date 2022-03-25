package docker

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/Netflix/metrics-client-go/metrics"
	"github.com/Netflix/titus-executor/config"
	runtimeTypes "github.com/Netflix/titus-executor/executor/runtime/types"
	"github.com/Netflix/titus-executor/properties"
	commonResource "github.com/Netflix/titus-kube-common/resource"
	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	docker "github.com/docker/docker/client"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestDockerPullRetries(t *testing.T) {
	t.Parallel()
	begin := time.Now()
	myErr := errors.New("Fake error")
	retries := 0
	fakePuller := func(context.Context, config.Config, metrics.Reporter, *docker.Client, string) error {
		retries = retries + 1
		return myErr
	}
	cfg := config.Config{}
	err := pullWithRetries(context.Background(), cfg, metrics.Discard, nil, "", fakePuller)
	if retries != 5 {
		t.Fatal("Not enough retries: ", retries)
	}
	if err != myErr {
		t.Fatal("Invalid error returned: ", err)
	}
	length := time.Since(begin)
	if length < 25*time.Second {
		t.Fatal("Backoff didn't last long enough: ", length)
	}
	if length > 60*time.Second {
		t.Fatal("Backoff lasted too long: ", length)
	}
}

func TestDockerCancel(t *testing.T) {
	t.Parallel()
	begin := time.Now()
	ctx, cancel := context.WithCancel(context.Background())
	cfg := config.Config{}

	fakePuller := func(context.Context, config.Config, metrics.Reporter, *docker.Client, string) error {
		return errors.New("Fake Error")
	}

	c := make(chan error)
	go func() {
		defer close(c)
		c <- pullWithRetries(ctx, cfg, metrics.Discard, nil, "", fakePuller)
	}()
	time.AfterFunc(time.Second*15, cancel)
	if err := <-c; err == nil {
		t.Fatal("No error observed during fetch")
	}
	length := time.Since(begin)
	if length < 15*time.Second {
		t.Fatal("Backoff didn't last long enough: ", length)
	}
	if length > 20*time.Second {
		t.Fatal("Backoff lasted too long: ", length)
	}

}

func TestWriteTitusEnvironment(t *testing.T) {
	buf := new(bytes.Buffer)
	assert.NoError(t, writeTitusEnvironmentFile(map[string]string{}, buf))
	assert.Equal(t, "", buf.String())
}

func TestWriteTitusEnvironmentGoodVariable(t *testing.T) {
	buf := new(bytes.Buffer)
	assert.NoError(t, writeTitusEnvironmentFile(map[string]string{"foo": "bar"}, buf))
	assert.Equal(t, "foo=\"bar\"\n", buf.String())
}

func TestWriteTitusEnvironmentBadVariable(t *testing.T) {
	buf := new(bytes.Buffer)
	assert.NoError(t, writeTitusEnvironmentFile(map[string]string{"foo\"": "bar"}, buf))
	assert.Equal(t, "", buf.String())

	assert.NoError(t, writeTitusEnvironmentFile(map[string]string{"foo\x00": "bar"}, buf))
	assert.Equal(t, "", buf.String())
}

func TestWriteTitusEnvironmentComplicatedVariable(t *testing.T) {
	buf := new(bytes.Buffer)
	assert.NoError(t, writeTitusEnvironmentFile(map[string]string{"ksrouter.filter.xpath.expression": `(XXXXX("XXXXXX") = "XXXXXXX" XXX XXX XXXXX("XXXX") XX ("XXXXXXXXXXXX", "XXXXXXXXXXXXXXXXXXX", "XXXXXXXXXXXXXXXXX", "XXXXXXXXXXXXXXXXXXXXX", "XXXXXXXXXXXXXXXXXX", "XXXXXXXXXXXXXXXXXXXXXXX", "XXXXXXXXXXXX", "XXXXXXXXXXXXXXXXXX", "XXXXXXXXXX", "XXXXXXXXXXXXX", "XXXXXXXXXXXXX", "XXXXXXXXXXXXXXX", "XXXXXXXXXXXXXX", "XXXXXXXXXXXXXXXXXXXX", "XXXXXXXXXXXXXX", "XXXXXXXXXXXXXXXXXX")) XX (XXXXX("XXXXXX") = "XXXXXXXX" XXX XXX XXXXX("XXXX") XX ("XXXXXXXXXXXXXXXXXXX", "XXXXXXXXXXXXXXXXXXX", "XXXXXXXXXXXXXXXXXX", "XXXX", "XXXXXXXXXXXX", "XXXXXXXXXXXXX", "XXXXXXXXXXXXXXXXXXXXXXXX", "XXXXXXXXXXXXXXXX", "XXXXXXXXXXX", "XXXXXXXXXXXXXXXX", "XXXXXXXXX", "XXXXXXXXXXXXXXXXX", "XXXXXXXXXXXXX", "XXXXXXXXXXXXX", "XXXXXXXXXXXXXXX", "XXXXXXXXXXXXXX", "XXXXXXXXXX", "XXXXXXXXXXXXXXXXXXXXXXXXX", "XXXXXXXXXXXXXXXXX", "XXXXXXXXXXXXXXXXXXXX", "XXXXXXXX", "XXXXXXXXXXXXXX", "XXXXXXXXXXXXXX", "XXXXXXXXXXX", "XXXXXXXXXXX", "XXXXXXXXXXXXXXXX", "XXXXXXXXXXXXXXXX", "XXXXXXXXXXXXXX", "XXXXXXX", "XXXX", "XXXXXXXXXXXXXXXXXX", "XXXXXXXXXXXXX", "XXXXXXXXXXXXXXX", "XXXXXXXXXXXXX", "XXXXXXXXXXXXX", "XXXXXXXXXXXX", "XXXXXXXXXXXXXXXXXX", "XXXXXXXXXX", "XXXXXXXXXXXXXXX", "XXXXXXXXXXX")) XX (XXXXX("XXXXXX") = "XXX" XXX XXX XXXXX("XXXX") XX ("XXXXXXXXXXXXXXXXX", "XXXXXXXXXXXXX", "XXXXXXXXXXXXXXXXXXXX", "XXXXXXXXXXXXX", "XXXXXXXXXXXXX", "XXXXXXXXXXXXXXXX", "XXXXXXXXXXXXXXXXXX", "XXXXXXXXXXXXXXXXXX", "XXXXXXXXXXX", "XXXXXXXXXXXXXXXX", "XXXXX", "XXX", "XXXXXXXXXXXXXXXXXXXXXXXXXX")) XX (XXXXX("XXXXXX") = "XXX" XXX XXXXX("XXXX") XX ("XXXXXXXXXXXXX", "XXXXXXXXXXXXXXX", "XXXXXXXXXXXX", "XXXXXXXXXXXXX", "XXXXXXXXXXXXXXX", "XXXXXXXXXXXXXXX", "XXXXXXXXXXXXXXXX", "XXXXX", "XXXXXXXXXXXXXXXXXX", "XXXXXXXXXXXXXXXXXX", "XXXXXXXXXXXXXXXXXXXXXXXXX", "XXXXXXXXXXXXXXXXXXXX", "XXXXXXXXXXX", "XXXXXXXXXXXXX", "XXXXXXXXXXXXXX", "XXXXXXXXXXXXXXXXXXXX", "XXXXXXXXXXXXXXXXXXXXX")) XX (XXXXX("XXXXXX") = "XXXX" XXX XXXXX("XXXX") XX ("XXXXXXXXXXXXX", "XXXXXXXXXXXXXXX", "XXXXXXXXXXXX", "XXXXXXXXX", "XXXXXXXXXXXXX", "XXXXXXXXXXXXXXX", "XXXXXXXXXXXXXXX", "XXXXXXXXXXXXXXXX", "XXXXX", "XXXXXXXXXXXXXXXXXX", "XXXXXXXXXXXXXXXXXX", "XXXXXXXXXXXXXXXXXXXXXXXXX", "XXXXXXXXXXXXXXXXXXXX", "XXXXXXXXXXX", "XXXXXXXXXXXXX", "XXXXXXXXXXXXXX", "XXXXXXXXXXXXXXXXXXXX"))`}, buf))
	assert.Equal(t, "", buf.String())
}

func testEnvFileTemplateContains(t *testing.T, envVars map[string]string, expected string) {
	var buf bytes.Buffer
	imageInspect := &types.ImageInspect{
		Config: &container.Config{
			Env: []string{},
		},
	}

	assert.NoError(t, executeEnvFileTemplate(envVars, imageInspect, &buf))
	assert.Contains(t, buf.String(), expected)
}

func TestEnvFileTemplate(t *testing.T) {
	env := map[string]string{"NORMAL": "normal"}
	testEnvFileTemplateContains(t, env, `export NORMAL=normal`)

	env = map[string]string{"JSON": `{"json": "value"}`}
	testEnvFileTemplateContains(t, env, `export JSON='{"json": "value"}'`)

	env = map[string]string{"NL": "new\nline"}
	testEnvFileTemplateContains(t, env, `
export NL='new
line'
`)

	env = map[string]string{}
	testEnvFileTemplateContains(t, env, `# This file was autogenerated by the titus executor

`)

	env = map[string]string{"SQ": "I'm an env var"}
	testEnvFileTemplateContains(t, env, `export SQ='I'"'"'m an env var'`)

	env = map[string]string{"A": "TEST1", "B": "TEST2"}
	testEnvFileTemplateContains(t, env, `
export A=TEST1
export B=TEST2
`)
	env = map[string]string{"A": "TEST1", "B.C": "TEST2"}
	testEnvFileTemplateContains(t, env, `
export A=TEST1

# Any extra invalid env variables will be commented out here:
# export B.C=TEST2
`)
}

func TestEnvFileDocker(t *testing.T) {
	var buf bytes.Buffer
	imageInspect := &types.ImageInspect{
		Config: &container.Config{
			Env: []string{
				"FOO=bar",
				"CAT=meow",
				// Env vars are unescaped in the Dockerfile
				"EVIL=I'm an env var",
				// Invalid things have weird chars
				"IN.VALID=foo",
			},
		},
	}

	assert.NoError(t, executeEnvFileTemplate(map[string]string{"A": "TEST1", "B": "TEST2", "FOO": "baz"}, imageInspect, &buf))

	assert.Equal(t, `# This file was autogenerated by the titus executor

# These environment variables are a combination of titus-set variables
# and user-defined variables for the job:
export A=TEST1
export B=TEST2
export FOO=baz

# These environment variables were in this docker image's ENV configuration:
export CAT=${CAT-meow}
export EVIL=${EVIL-'I'"'"'m an env var'}
export FOO=${FOO-bar}

# Any extra invalid env variables will be commented out here:
# export IN.VALID=foo
# This path setting makes it convenient for users to run
# tools that have been injected into the container from the
# Titus agent.
export PATH=$PATH:/titus/container-tools/bin
`, buf.String())

	t.Run("TestEnvFileDockerIntegration", func(t2 *testing.T) {
		testEnvFileDockerIntegration(t2, buf.String())
	})
}

func testEnvFileDockerIntegration(t *testing.T, data string) {
	// Let's see if we can put it to the test?
	binBash, err := exec.LookPath("/bin/bash")
	if err != nil {
		t.Skip("Could not find bash")
	}

	f, err := ioutil.TempFile("", "envvartest")
	require.NoError(t, err)
	defer f.Close()           // nolint: errcheck
	defer os.Remove(f.Name()) // nolint: errcheck
	_, err = f.Write([]byte(data))
	require.NoError(t, err)

	// Make sure foo set inside of the env file template takes precedence
	t.Run("CheckFoo", func(t2 *testing.T) {
		cmd := exec.Command(binBash, "-c", fmt.Sprintf(". %s && echo -n $FOO", f.Name()))
		output, err2 := cmd.CombinedOutput()
		assert.NoError(t2, err2)
		assert.Equal(t2, "baz", string(output))
	})

	t.Run("CheckCat", func(t2 *testing.T) {
		cmd := exec.Command(binBash, "-c", fmt.Sprintf(". %s && echo -n $CAT", f.Name()))
		output, err2 := cmd.CombinedOutput()
		assert.NoError(t2, err2)
		assert.Equal(t2, "meow", string(output))
	})

	t.Run("CheckEvil", func(t2 *testing.T) {
		cmd := exec.Command(binBash, "-c", fmt.Sprintf(". %s && echo -n $EVIL", f.Name()))
		output, err2 := cmd.CombinedOutput()
		assert.NoError(t2, err2)
		assert.Equal(t2, "I'm an env var", string(output))
	})
}

func TestValidEnvironmentKeys(t *testing.T) {
	assert.True(t, environmentVariableKeyRegexp.MatchString("HELLO"))
	assert.True(t, environmentVariableKeyRegexp.MatchString("HELLO1"))
	assert.True(t, environmentVariableKeyRegexp.MatchString("HELLO_"))
	assert.True(t, environmentVariableKeyRegexp.MatchString("HEL_LO"))
	assert.True(t, environmentVariableKeyRegexp.MatchString("HEL0LO"))
	assert.True(t, environmentVariableKeyRegexp.MatchString("hE10LLO_"))
	assert.True(t, environmentVariableKeyRegexp.MatchString("_hE10LLO_"))

	assert.False(t, environmentVariableKeyRegexp.MatchString("0ello"))
	assert.False(t, environmentVariableKeyRegexp.MatchString("ksrouter.foo.bar"))
	assert.False(t, environmentVariableKeyRegexp.MatchString("foo-bar"))
	assert.False(t, environmentVariableKeyRegexp.MatchString("0"))
}

func TestFlags(t *testing.T) {
	_, flags := NewConfig()
	properties.ConvertFlagsForAltSrc(flags)
}

func TestGenerateContainerStatusSpectatordMetrics(t *testing.T) {
	pod := &v1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Annotations: map[string]string{
				"pod.titus.netflix.com/image-tag-main":       "latest",
				"pod.titus.netflix.com/system-env-var-names": "",
			},
		},
		Spec: v1.PodSpec{
			Containers: []v1.Container{
				{
					Name:  runtimeTypes.MainContainerName,
					Image: "registry.us-east-1.streamingtest.titus.netflix.net:7002/titusops/echoservice@sha256:60d5cdeea0de265fe7b5fe40fe23a90e1001181312d226d0e688b0f75045109e",
					Resources: v1.ResourceRequirements{
						Limits: v1.ResourceList{
							commonResource.ResourceNameNetwork: resource.MustParse("128M"),
						},
					},
				},
				{
					Name: "fuse",
					Env: []v1.EnvVar{
						{
							Name:  "NETFLIX_PROCESS_NAME",
							Value: "foo",
						},
					},
				},
			},
		},
		Status: v1.PodStatus{
			ContainerStatuses: []v1.ContainerStatus{
				{
					Name:  runtimeTypes.MainContainerName,
					Image: "registry.us-east-1.streamingtest.titus.netflix.net:7002/titusops/echoservice@sha256:60d5cdeea0de265fe7b5fe40fe23a90e1001181312d226d0e688b0f75045109e",
					Ready: true,
					State: v1.ContainerState{
						Running: &v1.ContainerStateRunning{},
					},
				},
				{
					Name:  "fuse",
					Image: "registry.us-east-1.streamingtest.titus.netflix.net:7002/titusops/titus-test-fuse@sha256:f6ac1d3f204660792aef47b482fb43a34de23768727512868f428d18a90d4c48",
					Ready: true,
					State: v1.ContainerState{
						Running: &v1.ContainerStateRunning{},
					},
				},
			},
		},
	}
	container, err := runtimeTypes.NewPodContainer(pod, config.Config{})
	assert.NoError(t, err)
	runtime := &DockerRuntime{
		c: container,
	}
	actual := runtime.generateContainerStatusSpectatordMetrics()
	expected := []string{
		"g,2:titus.containers.status,nf.container=main,titus.image.name=titusops_echoservice_latest,titus.image.version=sha256_60d5cdeea0de265fe7b5fe40fe23a90e1001181312d226d0e688b0f75045109e,titus.state=healthy:1",
		"g,2:titus.containers.status,nf.container=fuse,nf.process=foo,titus.image.name=titusops_titus-test-fuse,titus.image.version=sha256_f6ac1d3f204660792aef47b482fb43a34de23768727512868f428d18a90d4c48,titus.state=healthy:1",
	}
	assert.Equal(t, expected, actual)
}
