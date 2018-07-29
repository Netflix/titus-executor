package properties

import (
	"encoding/json"
	"fmt"
	"net/http"
	"reflect"
	"time"

	"github.com/sirupsen/logrus"
	"gopkg.in/urfave/cli.v1"
	"gopkg.in/urfave/cli.v1/altsrc"
)

var (
	_ altsrc.InputSourceContext = (*QuiteliteInputSource)(nil)
)

const defaultURI = "http://localhost:3002/properties/serialize"

// NewQuiteliteSource instantiates a quitelite source. It will pull unless the disable flag is true.
func NewQuiteliteSource() func(context *cli.Context) (altsrc.InputSourceContext, error) {
	return func(context *cli.Context) (altsrc.InputSourceContext, error) {
		return fetchQuiteLiteSource(defaultURI)
	}
}

func fetchQuiteLiteSource(alternateURIFlag string) (altsrc.InputSourceContext, error) {
	client := http.Client{}
	client.Timeout = 10 * time.Second
	resp, err := client.Get(alternateURIFlag)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err2 := resp.Body.Close(); err2 != nil {
			logrus.Error("Error closing body: ", err)
		}

	}()
	ret := QuiteliteInputSource{}
	err = json.NewDecoder(resp.Body).Decode(&ret.valueMap)
	if err != nil {
		return nil, err
	}
	return &ret, nil
}

// QuiteliteInputSource is an altsrc backed by the quitelite serialize property
type QuiteliteInputSource struct {
	valueMap map[string]interface{}
}

func (qis *QuiteliteInputSource) getVal(name string) (interface{}, bool) {
	val, ok := qis.valueMap[name]
	return val, ok
}

// Int returns an int from the map if it exists otherwise returns 0
func (qis *QuiteliteInputSource) Int(name string) (int, error) {
	otherGenericValue, exists := qis.getVal(name)
	if exists {
		otherValue, isType := otherGenericValue.(int)
		if !isType {
			return 0, incorrectTypeForFlagError(name, "int", otherGenericValue)
		}
		return otherValue, nil
	}
	return 0, nil
}

// Duration returns a duration from the map if it exists otherwise returns 0
func (qis *QuiteliteInputSource) Duration(name string) (time.Duration, error) {
	otherGenericValue, exists := qis.getVal(name)
	if exists {
		otherValue, isType := otherGenericValue.(time.Duration)
		if !isType {
			return 0, incorrectTypeForFlagError(name, "duration", otherGenericValue)
		}
		return otherValue, nil
	}

	return 0, nil
}

// Float64 returns an float64 from the map if it exists otherwise returns 0
func (qis *QuiteliteInputSource) Float64(name string) (float64, error) {
	otherGenericValue, exists := qis.getVal(name)
	if exists {
		otherValue, isType := otherGenericValue.(float64)
		if !isType {
			return 0, incorrectTypeForFlagError(name, "float64", otherGenericValue)
		}
		return otherValue, nil
	}

	return 0, nil
}

// String returns a string from the map if it exists otherwise returns an empty string
func (qis *QuiteliteInputSource) String(name string) (string, error) {
	otherGenericValue, exists := qis.getVal(name)
	if exists {
		otherValue, isType := otherGenericValue.(string)
		if !isType {
			return "", incorrectTypeForFlagError(name, "string", otherGenericValue)
		}
		return otherValue, nil
	}

	return "", nil
}

// StringSlice returns an []string from the map if it exists otherwise returns nil
func (qis *QuiteliteInputSource) StringSlice(name string) ([]string, error) {
	otherGenericValue, exists := qis.getVal(name)

	if !exists {
		return nil, nil
	}

	otherValue, isType := otherGenericValue.([]interface{})
	if !isType {
		return nil, incorrectTypeForFlagError(name, "[]interface{}", otherGenericValue)
	}

	var stringSlice = make([]string, 0, len(otherValue))
	for i, v := range otherValue {
		stringValue, isType := v.(string)

		if !isType {
			return nil, incorrectTypeForFlagError(fmt.Sprintf("%s[%d]", name, i), "string", v)
		}

		stringSlice = append(stringSlice, stringValue)
	}

	return stringSlice, nil
}

// IntSlice returns an []int from the map if it exists otherwise returns nil
func (qis *QuiteliteInputSource) IntSlice(name string) ([]int, error) {
	otherGenericValue, exists := qis.getVal(name)

	if !exists {
		return nil, nil
	}

	otherValue, isType := otherGenericValue.([]interface{})
	if !isType {
		return nil, incorrectTypeForFlagError(name, "[]interface{}", otherGenericValue)
	}

	var intSlice = make([]int, 0, len(otherValue))
	for i, v := range otherValue {
		intValue, isType := v.(int)

		if !isType {
			return nil, incorrectTypeForFlagError(fmt.Sprintf("%s[%d]", name, i), "int", v)
		}

		intSlice = append(intSlice, intValue)
	}

	return intSlice, nil
}

// Generic returns an cli.Generic from the map if it exists otherwise returns nil
func (qis *QuiteliteInputSource) Generic(name string) (cli.Generic, error) {
	otherGenericValue, exists := qis.getVal(name)
	if exists {
		otherValue, isType := otherGenericValue.(cli.Generic)
		if !isType {
			return nil, incorrectTypeForFlagError(name, "cli.Generic", otherGenericValue)
		}
		return otherValue, nil
	}

	return nil, nil
}

// Bool returns an bool from the map otherwise returns false
func (qis *QuiteliteInputSource) Bool(name string) (bool, error) {
	otherGenericValue, exists := qis.getVal(name)
	if exists {
		otherValue, isType := otherGenericValue.(bool)
		if !isType {
			return false, incorrectTypeForFlagError(name, "bool", otherGenericValue)
		}
		return otherValue, nil
	}

	return false, nil
}

// BoolT returns an bool from the map otherwise returns true
func (qis *QuiteliteInputSource) BoolT(name string) (bool, error) {
	otherGenericValue, exists := qis.getVal(name)
	if exists {
		otherValue, isType := otherGenericValue.(bool)
		if !isType {
			return true, incorrectTypeForFlagError(name, "bool", otherGenericValue)
		}
		return otherValue, nil
	}

	return true, nil
}

func incorrectTypeForFlagError(name, expectedTypeName string, value interface{}) error {
	valueType := reflect.TypeOf(value)
	valueTypeName := ""
	if valueType != nil {
		valueTypeName = valueType.Name()
	}

	return fmt.Errorf("Mismatched type for flag '%s'. Expected '%s' but actual is '%s'", name, expectedTypeName, valueTypeName)
}

// ConvertFlagsForAltSrc enables a flag to be used by altsrc
func ConvertFlagsForAltSrc(flags []cli.Flag) []cli.Flag { // nolint: gocyclo
	ret := make([]cli.Flag, len(flags))
	for idx, untypedflag := range flags {
		switch f := untypedflag.(type) {
		case cli.IntFlag:
			ret[idx] = altsrc.NewIntFlag(f)
		case cli.DurationFlag:
			ret[idx] = altsrc.NewDurationFlag(f)
		case cli.Float64Flag:
			ret[idx] = altsrc.NewFloat64Flag(f)
		case cli.StringFlag:
			ret[idx] = altsrc.NewStringFlag(f)
		case cli.StringSliceFlag:
			ret[idx] = altsrc.NewStringSliceFlag(f)
		case cli.IntSliceFlag:
			ret[idx] = altsrc.NewIntSliceFlag(f)
		case cli.GenericFlag:
			ret[idx] = altsrc.NewGenericFlag(f)
		case cli.BoolFlag:
			ret[idx] = altsrc.NewBoolFlag(f)
		case cli.BoolTFlag:
			ret[idx] = altsrc.NewBoolTFlag(f)
		default:
			panic(fmt.Sprintf("Unknown type: %T", untypedflag))
		}
	}
	return ret
}
