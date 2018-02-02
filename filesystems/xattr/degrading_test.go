package xattr

import (
	"bytes"
	"io/ioutil"
	"os"
	"reflect"
	"syscall"
	"testing"

	"github.com/leanovate/gopter/prop"

	"runtime"
	"strings"

	"github.com/leanovate/gopter"
	"github.com/leanovate/gopter/gen"
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

const exampleAttrName = "user.example"
const exampleAttrVal = "some exciting value"

func init() {
	log.SetLevel(log.DebugLevel)
}

func TestBasicFXattrs(t *testing.T) {
	skipIfUnsupportedFilesystem(t)
	testfile, err := ioutil.TempFile(".", "xattr-basic-test")
	if err != nil {
		t.Fatal("Could not create temporary file: ", err)
	}
	tempfileName := testfile.Name()
	defer func() {
		err = testfile.Close()
		if err != nil {
			t.Fatal("Could not close temporary file: ", err)
		}
		err = os.Remove(tempfileName)
		if err != nil {
			t.Fatal("Could not unlink temporary file: ", err)
		}
	}()

	fCheckListEmpty(testfile, t)
	fCheckGetMissing(testfile, t)
	fCheckDelMissing(testfile, t)

	fCheckSetGetListDelete(testfile, t)

	fCheckListEmpty(testfile, t)
	fCheckGetMissing(testfile, t)
	fCheckDelMissing(testfile, t)
}

func fCheckSetGetListDelete(testfile *os.File, t *testing.T) {

	// Set
	if err := FSetXattr(testfile, exampleAttrName, []byte(exampleAttrVal)); err != nil {
		t.Fatal("Unable to set x attr: ", err)
	}
	// Get
	if val, err := FGetXattr(testfile, exampleAttrName); err != nil {
		t.Fatal("Unable to get x attr: ", err)
	} else if string(val) != exampleAttrVal {
		t.Fatal("Unexpected value: ", string(val))
	}

	// List
	if attrs, err := FListXattrs(testfile); err != nil {
		t.Fatal("Could not list xattrs: ", err)
	} else if len(attrs) != 1 {
		t.Fatal("Unexpected number of attributes seen: ", attrs)
	} else if attrs[exampleAttrName] != struct{}{} {
		t.Fatal("Value unexpected: ", attrs)
	}

	if err := FDelXattr(testfile, exampleAttrName); err != nil {
		t.Fatal("Could not delete xattr: ", err)
	}

}

func fCheckListEmpty(testfile *os.File, t *testing.T) {
	attrs, err := FListXattrs(testfile)
	if err != nil {
		t.Fatal("Could not list xattrs: ", err)
	}
	if len(attrs) != 0 {
		t.Fatal("Attributes exist: ", attrs)
	}
}

func fCheckGetMissing(testfile *os.File, t *testing.T) {
	_, err := FGetXattr(testfile, exampleAttrName)
	if err != ENOATTR {
		t.Fatal("Get had unexpected result: ", err)
	}
}

func fCheckDelMissing(testfile *os.File, t *testing.T) {
	err := FDelXattr(testfile, exampleAttrName)
	if err != ENOATTR {
		t.Fatal("Delete had unexpected result: ", err)
	}
}

func testManyFXattrsWithFile(testfile *os.File, keyValues map[string][]byte) bool {
	expectedKeyValues := map[string][]byte{}
	expectedKeys := map[string]struct{}{}
	for key, value := range keyValues {
		if err := FSetXattr(testfile, key, value); err == ErrInvalidKey && len(key) == 0 {
			// continue, this is fine
			continue
		} else if err == syscall.ENAMETOOLONG && len(key) > XATTR_MAXNAMELEN {
			// continue, this is fine, proper error handling was done
			continue
		} else if err != nil {
			log.WithField("key", key).WithField("value", value).Warning("Unable to set xattr: ", err)
			return false
		}

		// Add it to the values we set on this file
		expectedKeyValues[key] = value
		expectedKeys[key] = struct{}{}

	}

	return verifyTestManyFXattrsWithFile(testfile, expectedKeys, expectedKeyValues)
}

func verifyTestManyFXattrsWithFile(testfile *os.File, expectedKeys map[string]struct{}, expectedKeyValues map[string][]byte) bool {

	// OS X with HFS+ takes a ridiculous amount of time to do the following
	// Perhaps we should think of sampling?
	if xattrlist, err := FListXattrs(testfile); err != nil {
		log.Warning("Unable to retrieve xattrs: ", err)
		return false
	} else if !reflect.DeepEqual(xattrlist, expectedKeys) {
		log.Warning("Not all xattrs returned in xattrlist")
		return false
	}

	for key, expectedValue := range expectedKeyValues {
		if value, err := FGetXattr(testfile, key); err != nil {
			log.Warning("Unable to retrieve xattr: ", err)
			return false
		} else if !bytes.Equal(value, expectedValue) {
			log.Warning("Retrieved value incorrect")
			return false
		}
	}

	return true
}

type KeyValuePair struct {
	Key   string
	Value []byte
}

func testManyFXattrs(keyValues []KeyValuePair) bool {
	testfile, err := ioutil.TempFile(".", "xattr-many-test")
	if err != nil {
		log.Error("Could not create temporary file: ", err)
		return false
	}
	tempfileName := testfile.Name()
	defer func() {
		err = testfile.Close()
		if err != nil {
			log.Fatal("Could not close temporary file: ", err)
		}
		err = os.Remove(tempfileName)
		if err != nil {
			log.Fatal("Could not unlink temporary file: ", err)
		}
	}()

	oldlistXattrsStartBufferSize := listXattrsStartBufferSize
	listXattrsStartBufferSize = 16 // Limit the start buffer to 16Bytes as a way of torturing the test
	defer func() {
		listXattrsStartBufferSize = oldlistXattrsStartBufferSize
	}()

	realKeyValues := map[string][]byte{}

	// Filter keys where names are too long, and rewrite names to be user.*
	totalSize := 0

	ext := isExt()
	for _, kv := range keyValues {
		key := kv.Key
		value := kv.Value

		userKey := "user." + key

		totalAttrSize := len(userKey) + len(value)
		if ext {
			// EXT overhead
			totalAttrSize = +28
		}
		if ext && (totalSize+totalAttrSize >= 512) {
			// Unfortunately, this is an ext4 limit
			break
		}
		totalSize += totalAttrSize
		realKeyValues[userKey] = value
	}

	log.Debug("Keys: ", len(realKeyValues))
	log.Debug("TotalSize: ", totalSize)

	return testManyFXattrsWithFile(testfile, realKeyValues)
}

func TestManyFXattrs(t *testing.T) {
	skipIfUnsupportedFilesystem(t)

	if testing.Short() {
		t.Skip("skipping test in short mode.")
	}
	properties := gopter.NewProperties(nil)

	isKey := func(key string) bool {
		return len(key) > 1 && len("user."+key) < 255
	}

	properties.Property("Xattr Torture Test", prop.ForAll(
		testManyFXattrs,
		gen.SliceOf(
			gen.Struct(
				reflect.TypeOf(KeyValuePair{}),
				map[string]gopter.Gen{
					"Key":   gen.Identifier().SuchThat(isKey),
					"Value": gen.SliceOf(gen.UInt8()),
				}))))
	properties.TestingRun(t)
}

func TestBasicXattrs(t *testing.T) {
	skipIfUnsupportedFilesystem(t)
	testfile, err := ioutil.TempFile(".", "xattr-basic-test")
	if err != nil {
		t.Fatal("Could not create temporary file: ", err)
	}
	tempfileName := testfile.Name()
	defer mustClose(testfile)
	defer mustRemove(testfile)

	checkListEmpty(tempfileName, t)
	checkGetMissing(tempfileName, t)
	checkDelMissing(tempfileName, t)

	checkSetGetListDelete(tempfileName, t)

	checkListEmpty(tempfileName, t)
	checkGetMissing(tempfileName, t)
	checkDelMissing(tempfileName, t)
}

func checkSetGetListDelete(path string, t *testing.T) {

	// Set
	if err := SetXattr(path, exampleAttrName, []byte(exampleAttrVal)); err != nil {
		t.Fatal("Unable to set x attr: ", err)
	}
	// Get
	if val, err := GetXattr(path, exampleAttrName); err != nil {
		t.Fatal("Unable to get x attr: ", err)
	} else if string(val) != exampleAttrVal {
		t.Fatal("Unexpected value: ", string(val))
	}

	// List
	if attrs, err := ListXattrs(path); err != nil {
		t.Fatal("Could not list xattrs: ", err)
	} else if len(attrs) != 1 {
		t.Fatal("Unexpected number of attributes seen: ", attrs)
	} else if attrs[exampleAttrName] != struct{}{} {
		t.Fatal("Value unexpected: ", attrs)
	}

	if err := delXattr(path, exampleAttrName); err != nil {
		t.Fatal("Could not delete xattr: ", err)
	}

}

func checkListEmpty(path string, t *testing.T) {
	attrs, err := ListXattrs(path)
	if err != nil {
		t.Fatalf("List had unexpected result %v with file %s", err, path)
	}
	if len(attrs) != 0 {
		t.Fatal("Attributes exist: ", attrs)
	}
}

func checkGetMissing(path string, t *testing.T) {
	_, err := GetXattr(path, exampleAttrName)
	if err != ENOATTR {
		t.Fatalf("Get had unexpected result %v with file %s", err, path)
	}
}

func checkDelMissing(path string, t *testing.T) {
	err := delXattr(path, exampleAttrName)
	if err != ENOATTR {
		t.Fatalf("Delete had unexpected result %v with file %s", err, path)
	}
}

func skipIfUnsupportedFilesystem(t *testing.T) {
	var statfs unix.Statfs_t
	err := unix.Statfs(".", &statfs)
	if err != nil {
		t.Fatal("Unable to statfs: ", err)
	}
	switch statfs.Type {
	case 0xef53: // EXT3_SUPER_MAGIC / EXT4_SUPER_MAGIC
	case 0x4244: // HFS_SUPER_MAGIC
	case 0x9123683e: // BTRFS_SUPER_MAGIC
	case 0x17: // HFS on OS X
	default:
		t.Skip("Unrecognized filesystem, with magic: ", statfs.Type)
	}
}

func isExt() bool {
	var statfs unix.Statfs_t
	err := unix.Statfs(".", &statfs)
	if err != nil {
		return false
	}
	switch statfs.Type {
	case 0xef53: // EXT3_SUPER_MAGIC / EXT4_SUPER_MAGIC
		return true
	default:
	}
	return false
}

func TestMimeTypes(t *testing.T) {
	testFunctions := []func(*testing.T, *os.File, string){
		testSimpleMimeParsing,
		testSimpleNoParsing,
		testSimpleBadMimeType1,
		testSimpleBadMimeType2,
	}

	skipIfUnsupportedFilesystem(t)
	for _, fun := range testFunctions {
		fullName := runtime.FuncForPC(reflect.ValueOf(fun).Pointer()).Name()
		splitName := strings.Split(fullName, ".")
		funName := splitName[len(splitName)-1]

		t.Run(strings.Title(funName), decorateTestFunction(fun))
	}
}

func decorateTestFunction(f func(*testing.T, *os.File, string)) func(*testing.T) {
	return func(t *testing.T) {
		t.Parallel()
		testfile, err := ioutil.TempFile("", "mime-test")
		require.NoError(t, err)
		tempfileName := testfile.Name()
		defer func() {
			require.NoError(t, testfile.Close())
			require.NoError(t, os.Remove(tempfileName))
		}()

		f(t, testfile, tempfileName)
	}
}

func testSimpleMimeParsing(t *testing.T, testfile *os.File, filename string) {
	require.NoError(t, FSetXattr(testfile, MimeTypeAttr, []byte("application/json")))
	assert.Equal(t, "application/json", GetMimeType(filename))
}

func testSimpleNoParsing(t *testing.T, testfile *os.File, filename string) {
	assert.Equal(t, "", GetMimeType(filename))
}

func testSimpleBadMimeType1(t *testing.T, testfile *os.File, filename string) {
	require.NoError(t, FSetXattr(testfile, MimeTypeAttr, []byte("")))
	assert.Equal(t, "", GetMimeType(filename))
}

func testSimpleBadMimeType2(t *testing.T, testfile *os.File, filename string) {
	require.NoError(t, FSetXattr(testfile, MimeTypeAttr, []byte("application/json;text/plain")))
	assert.Equal(t, "", GetMimeType(filename))
}

func mustRemove(file *os.File) {
	if err := os.Remove(file.Name()); err != nil {
		panic(err)
	}
}

func mustClose(file *os.File) {
	if err := file.Close(); err != nil {
		panic(err)
	}
}
