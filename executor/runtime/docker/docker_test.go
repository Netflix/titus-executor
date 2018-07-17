package docker

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"github.com/Netflix/metrics-client-go/metrics"
	docker "github.com/docker/docker/client"
	"github.com/stretchr/testify/assert"
)

func TestDockerPullRetries(t *testing.T) {
	t.Parallel()
	begin := time.Now()
	myErr := errors.New("Fake error")
	retries := 0
	fakePuller := func(context.Context, metrics.Reporter, *docker.Client, string) error {
		retries = retries + 1
		return myErr
	}
	err := pullWithRetries(context.Background(), metrics.Discard, nil, nil, fakePuller)
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

	fakePuller := func(context.Context, metrics.Reporter, *docker.Client, string) error {
		return errors.New("Fake Error")
	}

	c := make(chan error)
	go func() {
		defer close(c)
		c <- pullWithRetries(ctx, metrics.Discard, nil, nil, fakePuller)
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
