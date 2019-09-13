package spectator

import (
	"bytes"
	"fmt"
	"sort"
)

type Id struct {
	name string
	tags map[string]string
	key  string
}

// computes and saves a key to be used to address Ids in maps
func (id *Id) mapKey() string {
	if len(id.key) > 0 {
		return id.key
	}

	var buf bytes.Buffer
	_, err := buf.WriteString(id.name)
	const errKey = "ERR"
	if err != nil {
		return errKey
	}
	var keys []string
	for k := range id.tags {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	for _, k := range keys {
		v := id.tags[k]
		_, err = buf.WriteRune('|')
		if err != nil {
			return errKey
		}
		_, err = buf.WriteString(k)
		if err != nil {
			return errKey
		}
		_, err = buf.WriteRune('|')
		if err != nil {
			return errKey
		}
		_, err = buf.WriteString(v)
		if err != nil {
			return errKey
		}
	}
	id.key = buf.String()
	return id.key
}

func newId(name string, tags map[string]string) *Id {
	var myTags = make(map[string]string)
	for k, v := range tags {
		myTags[k] = v
	}
	return &Id{name, myTags, ""}
}

func (id *Id) WithTag(key string, value string) *Id {
	newTags := make(map[string]string)

	for k, v := range id.tags {
		newTags[k] = v
	}
	newTags[key] = value

	return newId(id.name, newTags)
}

func (id *Id) WithStat(stat string) *Id {
	return id.WithTag("statistic", stat)
}

func (id *Id) WithDefaultStat(stat string) *Id {
	s := id.tags["statistic"]
	if s == "" {
		return id.WithTag("statistic", stat)
	} else {
		return id
	}
}

func (id *Id) String() string {
	return fmt.Sprintf("Id{name=%s,tags=%v}", id.name, id.tags)
}

func (id *Id) Name() string {
	return id.name
}

func (id *Id) Tags() map[string]string {
	return id.tags
}

func (id *Id) WithTags(tags map[string]string) *Id {
	if len(tags) == 0 {
		return id
	}

	newTags := make(map[string]string)

	for k, v := range id.tags {
		newTags[k] = v
	}

	for k, v := range tags {
		newTags[k] = v
	}
	return newId(id.name, newTags)
}
