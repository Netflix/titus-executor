package properties

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"gopkg.in/urfave/cli.v1"
	"gopkg.in/urfave/cli.v1/altsrc"
)

type properties struct {
	TestBool   bool
	TestBoolT  bool
	TestString string
}

var referenceProperties = properties{
	TestBool:   true,
	TestBoolT:  false,
	TestString: "test",
}

type propertiesHandler struct {
	t *testing.T
}

func (p *propertiesHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	assert.NoError(p.t, json.NewEncoder(w).Encode(referenceProperties))
}

func generateFlags() (*properties, []cli.Flag) {
	localProperties := &properties{}

	ret := []cli.Flag{
		cli.BoolFlag{
			Name:        "TestBool",
			Destination: &localProperties.TestBool,
		},
		cli.BoolTFlag{
			Name:        "TestBoolT",
			Destination: &localProperties.TestBoolT,
		},
		cli.StringFlag{
			Name:        "TestString",
			Destination: &localProperties.TestString,
		},
	}

	return localProperties, ConvertFlagsForAltSrc(ret)
}

func TestProperties(t *testing.T) {
	var (
		run   = false
		props *properties
	)
	server := httptest.NewServer(&propertiesHandler{
		t: t,
	})
	defer server.Close()

	propertiesURL := server.URL + "/properties"
	app := cli.NewApp()
	props, app.Flags = generateFlags()

	app.Action = func(c *cli.Context) error {
		run = true
		assert.Equal(t, referenceProperties.TestString, props.TestString)
		assert.Equal(t, referenceProperties.TestBoolT, props.TestBoolT)
		assert.Equal(t, referenceProperties.TestBool, props.TestBool)
		return nil
	}

	app.Before = altsrc.InitInputSourceWithContext(app.Flags, func(context *cli.Context) (altsrc.InputSourceContext, error) {
		qls, e := fetchQuiteLiteSource(propertiesURL)
		return qls, e
	})
	assert.NoError(t, app.Run([]string{"fooexec", "--TestString", "test"}))
	assert.True(t, run)

}

func TestPropertiesWithoutAltsrc(t *testing.T) {
	var (
		run   = false
		props *properties
	)

	app := cli.NewApp()
	props, app.Flags = generateFlags()

	app.Action = func(c *cli.Context) error {
		run = true
		assert.True(t, props.TestBoolT)
		return nil
	}

	assert.NoError(t, app.Run([]string{"fooexec"}))
	assert.True(t, run)

}
