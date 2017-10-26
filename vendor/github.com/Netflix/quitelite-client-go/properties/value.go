package properties

import (
	"fmt"
	"math"
	"reflect"
	"strconv"
	"time"
)

/*
To unmarshal JSON into an interface value, Unmarshal stores one of these in the interface value:

bool, for JSON booleans
float64, for JSON numbers
string, for JSON strings
[]interface{}, for JSON arrays
map[string]interface{}, for JSON objects
nil for JSON null
*/

// DynamicPropertyValue holds the representation of a dynamic property,
// not to be created by users
type DynamicPropertyValue struct {
	value interface{}
}

func newDynamicPropertyValue(value interface{}) *DynamicPropertyValue {
	return &DynamicPropertyValue{value: value}
}

// Raw gets the raw, underlying, non-coerced value
func (dpv DynamicPropertyValue) Raw() interface{} {
	return dpv.value
}

// Equal checks if the *value* of two DPVs are equal
func (dpv DynamicPropertyValue) Equal(other DynamicPropertyValue) bool {
	return reflect.DeepEqual(dpv.value, other.value)
}

// AsString tries to cast the DPV into a String
func (dpv DynamicPropertyValue) AsString() (string, error) {
	switch v := dpv.value.(type) {
	case string:
		return v, nil
	case bool:
		return strconv.FormatBool(v), nil
	case float64:
		return strconv.FormatFloat(v, 'f', -1, 64), nil
	default:
		return "", fmt.Errorf("Cannot cast %v to string", v)
	}
}

// MustString tries to cast the DPV into a String, or panics
func (dpv DynamicPropertyValue) MustString() string {
	val, err := dpv.AsString()
	if err != nil {
		panic(err)
	}
	return val
}

// AsBool tries to cast the DPV into a bool
func (dpv DynamicPropertyValue) AsBool() (bool, error) {
	switch v := dpv.value.(type) {
	case string:
		return strconv.ParseBool(v)
	case bool:
		return v, nil
	case float64:
		return v != 0, nil
	default:
		return false, fmt.Errorf("Cannot cast %v to bool", v)
	}
}

// MustBool tries to cast the DPV into a bool or panics
func (dpv DynamicPropertyValue) MustBool() bool {
	val, err := dpv.AsBool()
	if err != nil {
		panic(err)
	}
	return val
}

// AsDuration tries to cast the DPV into a duration
func (dpv DynamicPropertyValue) AsDuration() (time.Duration, error) {
	switch v := dpv.value.(type) {
	case string:
		return time.ParseDuration(v)
	case float64:
		return time.Duration(int64(math.Floor(v))) * time.Millisecond, nil
	default:
		return 0, fmt.Errorf("Cannot cast %v to duration", v)
	}
}

// MustDuration tries to cast the DPV into a duration or panics
func (dpv DynamicPropertyValue) MustDuration() time.Duration {
	val, err := dpv.AsDuration()
	if err != nil {
		panic(err)
	}
	return val
}

/*
 * This math.floor could mean that we accidentally cast a float into
 * an integer. Currently, we don't use floats in properties.
 */

// AsInteger tries to cast the DPV into a integer
func (dpv DynamicPropertyValue) AsInteger() (int, error) {
	switch v := dpv.value.(type) {
	case string:
		if intVal, err := strconv.ParseInt(v, 10, 64); err == nil {
			return int(intVal), nil
		}
		if floatVal, err := strconv.ParseFloat(v, 64); err == nil {
			return int(math.Floor(floatVal)), nil
		}
		return 0, fmt.Errorf("Cannot cast %s to integer", v)
	case float64:
		return int(math.Floor(v)), nil
	case bool:
		if v {
			return 1, nil
		}
		return 0, nil
	default:
		return 0, fmt.Errorf("Cannot cast %v to integer", v)
	}
}

// MustInteger tries to cast the DPV into a integer or panics
func (dpv DynamicPropertyValue) MustInteger() int {
	val, err := dpv.AsInteger()
	if err != nil {
		panic(err)
	}
	return val
}
