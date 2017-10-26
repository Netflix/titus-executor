A container that produces a titus-executor deb package.

The source code should be bind mounted into `/src`, and a deb package will be built into `/dist` inside the container.

## Usage

```
cd <titus-executor root>
mkdir -p build/distribution
docker build -t titus-executor-builder hack/builder
docker run $(pwd):/src $(pwd)/build/distibution:/dist titus-executor-builder
```

The example above generates a deb package in `<titus-executor root>/build/dist/titus-executor-VERSION.deb`.