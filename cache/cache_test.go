package cache

import (
	"context"
	"io/ioutil"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	testKey   = "key"
	testValue = "value"
)

func TestAssertInterfaceNotPointer(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	c := cache{}
	var x int
	assert.Panics(t, func() { _ = c.Resolve(ctx, "", x) })
}

func wrapTest(t *testing.T, f func(t *testing.T, ctx context.Context, c *cache)) {
	t.Parallel()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	tmpdir, err := ioutil.TempDir("", t.Name())
	require.NoError(t, err)
	defer os.RemoveAll(tmpdir)

	c, err := NewCache(tmpdir, nil, nil)
	require.NoError(t, err)
	f(t, ctx, c.(*cache))
}

func TestCacheNoCache(tt *testing.T) {
	wrapTest(tt, func(t *testing.T, ctx context.Context, c *cache) {
		count := 0
		countPtr := &count

		c.resolver = func(ctx context.Context, key string, v interface{}) error {
			valPtr := v.(*string)
			*valPtr = testValue
			*countPtr = (*countPtr) + 1
			return nil
		}

		val := ""
		assert.NoError(t, c.Resolve(ctx, testKey, &val))
		assert.Equal(t, 1, count)
		assert.Equal(t, val, testValue)

		val = ""
		assert.NoError(t, c.Resolve(ctx, testKey, &val))
		assert.Equal(t, 1, count)
		assert.Equal(t, val, testValue)
	})
}

func TestCacheSecondCacheInvalidation(tt *testing.T) {
	wrapTest(tt, func(t *testing.T, ctx context.Context, c *cache) {
		count := 0
		countPtr := &count
		c.ttl = Duration(time.Second)
		c.resolver = func(ctx context.Context, key string, v interface{}) error {
			valPtr := v.(*string)
			*valPtr = testValue
			*countPtr = (*countPtr) + 1
			return nil
		}

		val := ""
		// First allocation will go through
		assert.NoError(t, c.Resolve(ctx, testKey, &val))
		assert.Equal(t, count, 1)

		// Sleep 3 seconds to wait for invalidation (Mac OS X has seconds time stamps)
		time.Sleep(3 * time.Second)

		val = ""
		// Check it's hit again
		assert.NoError(t, c.Resolve(ctx, testKey, &val))
		assert.Equal(t, 2, count)
		assert.Equal(t, val, testValue)
	})

}

func TestCache2SecondCacheValid(tt *testing.T) {
	wrapTest(tt, func(t *testing.T, ctx context.Context, c *cache) {
		count := 0
		countPtr := &count
		c.ttl = Duration(2 * time.Second)
		c.resolver = func(ctx context.Context, key string, v interface{}) error {
			valPtr := v.(*string)
			*valPtr = testValue
			*countPtr = (*countPtr) + 1
			return nil
		}
		val := ""
		assert.NoError(t, c.Resolve(ctx, testKey, &val))
		assert.Equal(t, count, 1)

		val = ""
		assert.NoError(t, c.Resolve(ctx, testKey, &val))
		assert.Equal(t, count, 1)
	})
}

func wrapTest2Cachers(t *testing.T, f func(t *testing.T, ctx context.Context, c1 *cache, c2 *cache)) {
	t.Parallel()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	tmpdir, err := ioutil.TempDir("", t.Name())
	require.NoError(t, err)
	//defer os.RemoveAll(tmpdir)

	c1, err := NewCache(tmpdir, nil, nil)
	require.NoError(t, err)

	c2, err := NewCache(tmpdir, nil, nil)
	require.NoError(t, err)

	f(t, ctx, c1.(*cache), c2.(*cache))
}

func noerror(resolverError ResolverError, err error) {
	if err != nil {
		panic(err)
	}
}

func TestTwoRacingCaches(tt *testing.T) {
	wrapTest2Cachers(tt, func(t *testing.T, ctx context.Context, c1 *cache, c2 *cache) {
		var counter uint32
		counterPtr := &counter

		c1.ttl = Duration(10 * time.Second)
		c2.ttl = Duration(10 * time.Second)
		wg := &sync.WaitGroup{}
		wg.Add(2)
		generate := func(testVal string) KeyResolver {
			return func(ctx context.Context, key string, v interface{}) error {
				if wg != nil {
					wg.Done()
					wg.Wait()
				}
				valPtr := v.(*string)
				*valPtr = testVal
				atomic.AddUint32(counterPtr, 1)
				return nil
			}
		}
		c1.resolver = generate("v1")
		c2.resolver = generate("v2")
		var val1, val2 string
		wg2 := &sync.WaitGroup{}
		wg2.Add(2)
		go func() {
			noerror(c1.ResolveSplitErrors(ctx, testKey, &val1))
			wg2.Done()
		}()
		go func() {
			noerror(c2.ResolveSplitErrors(ctx, testKey, &val2))
			wg2.Done()
		}()
		wg2.Wait()
		assert.Equal(t, 2, int(atomic.LoadUint32(&counter)))
		assert.NotEqual(t, val1, val2)

		wg = nil
		// Let's ensure that one of the values got cached
		wg2.Add(2)
		val1 = ""
		val2 = ""
		go func() {
			noerror(c1.ResolveSplitErrors(ctx, testKey, &val1))
			wg2.Done()
		}()
		go func() {
			noerror(c2.ResolveSplitErrors(ctx, testKey, &val2))
			wg2.Done()
		}()
		wg2.Wait()
		assert.Equal(t, 2, int(atomic.LoadUint32(&counter)))
		assert.Equal(t, val1, val2)
		assert.Contains(t, []string{"v1", "v2"}, val1)
		assert.Contains(t, []string{"v1", "v2"}, val2)
	})
}
