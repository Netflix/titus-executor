package ec2util

import "github.com/aws/aws-sdk-go/service/ec2"

// TagSetToMap converts ec2 tags to a map
func TagSetToMap(tagSet []*ec2.Tag) map[string]*string {
	ret := make(map[string]*string)
	// No tags
	if tagSet == nil {
		return ret
	}
	for _, tag := range tagSet {
		ret[*tag.Key] = tag.Value
	}
	return ret
}
