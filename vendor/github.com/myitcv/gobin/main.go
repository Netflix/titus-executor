/*
 The gobin command installs/runs main packages.
*/
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"time"

	"github.com/rogpeppe/go-internal/module"
)

const (
	debug = false

	tempModule = "temporary.com/gobin"
)

var (
	exitCode = 0

	fMainMod  = flag.Bool("m", false, "resolve dependencies via the main module (as given by go env GOMOD)")
	fMod      = flag.String("mod", "", "provide additional control over updating and use of go.mod")
	fRun      = flag.Bool("run", false, "run the provided main package")
	fPrint    = flag.Bool("p", false, "print gobin install cache location for main packages")
	fVersion  = flag.Bool("v", false, "print the module path and version for main packages")
	fDownload = flag.Bool("d", false, "stop after installing main packages to the gobin install cache")
	fUpgrade  = flag.Bool("u", false, "check for the latest tagged version of main packages")
	fNoNet    = flag.Bool("nonet", false, "prevent network access")
	fDebug    = flag.Bool("debug", debug, "print debug information")
	fTags     = flag.String("tags", "", "build tags to apply; go help build for more information")

	// envGOFLAGS is the value of GOENV passed to gobin with -tags= values stripped out
	envGOFLAGS string
)

func main() {
	os.Exit(main1())
}

// TODO
//
// 1. Work out whether we want to support ... patterns
// 2. Make local step concurrent?

func main1() int {
	if err := mainerr(); err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			return ExitCode(ee.ProcessState)
		}
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	return 0
}

func mainerr() error {
	goenv, err := getGoEnv()
	if err != nil {
		return err
	}
	// Set the default value of the -tags value to be the last -tags= value in
	// GOFLAGS. Also, strip any -tags= values from GOFLAGS to ensure a "clean"
	// value that can then be used for any cmd/go calls.
	if goenv.GOFLAGS != "" {
		var goenvVals []string
		for _, v := range strings.Fields(goenv.GOFLAGS) {
			if strings.HasPrefix(v, "-tags=") {
				*fTags = strings.TrimPrefix(v, "-tags=")
				continue
			}
			goenvVals = append(goenvVals, v)
		}
		envGOFLAGS = strings.Join(goenvVals, " ")
	}

	flag.Usage = func() {
		mainUsage(os.Stderr)
	}
	flag.Parse()

	// check exclusivity of certain flags
	{
		comm := 0
		if *fRun {
			comm += 1
		}
		if *fPrint {
			comm += 1
		}
		if *fDownload {
			comm += 1
		}
		if *fVersion {
			comm += 1
		}
		if comm > 1 {
			return fmt.Errorf("the -run, -p, -v and -d flags are mutually exclusive")
		}
	}

	*fTags = strings.TrimSpace(*fTags)

	if *fMod != "" {
		switch *fMod {
		case "readonly", "vendor":
		default:
			return fmt.Errorf("-mod has invalid value %q", *fMod)
		}
		*fMainMod = true
	}

	if *fUpgrade && *fNoNet {
		return fmt.Errorf("the -n and -g flags are mutually exclusive")
	}

	var gopath string          // effective GOPATH
	var gobinCache string      // does what it says on the tin
	var localCacheProxy string // local filesystem-based module download cache

	cwd, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("failed to get working directory: %v", err)
	}

	// cache path discovery
	{
		gopath = goenv.GOPATH
		if gopath != "" {
			gopath = filepath.SplitList(gopath)[0]
		} else {
			uhd, err := userHomeDir()
			if err != nil {
				return fmt.Errorf("failed to determine user home directory: %v", err)
			}
			gopath = filepath.Join(uhd, "go")
		}
		// TODO I don't think the module cache path is advertised anywhere public...
		// intentionally but in case it is, replace what follows
		cachePath := path.Join(filepath.ToSlash(gopath), "pkg", "mod", "cache", "download")
		if goenv.ReleaseTags["go1.13"] && cachePath[0] != '/' {
			// in Go 1.13 the handling of file:// proxy URLs changed to require a /
			cachePath = "/" + cachePath
		}

		localCacheProxy = "GOPROXY=file://" + cachePath

		if *fMainMod {
			md := cwd
			for {
				if _, err := os.Stat(filepath.Join(md, "go.mod")); err == nil {
					break
				}
				if d := filepath.Dir(md); d != md {
					md = d
				} else {
					return fmt.Errorf("could not find main module")
				}
			}

			gobinCache = filepath.Join(md, ".gobincache")

		} else {
			ucd, err := os.UserCacheDir()
			if err != nil {
				return fmt.Errorf("failed to determine user cache dir: %v", err)
			}

			gobinCache = filepath.Join(ucd, "gobin")
		}
	}

	var allPkgs []*arg   // all of the non-run command line provided packages
	var runArgs []string // -r command line run args
	var netPkgs []*arg   // packages that need network resolution
	var nonMain []*arg   // non-main packages

	// prepare allPkgs
	{
		pkgPatts := flag.Args()
		if len(pkgPatts) == 0 {
			return fmt.Errorf("need to provide at least one main package")
		}
		if *fRun && len(pkgPatts) > 1 {
			pkgPatts, runArgs = pkgPatts[:1], pkgPatts[1:]
		}

		var tmpDirs []string
		defer func() {
			for _, td := range tmpDirs {
				os.RemoveAll(td)
			}
		}()

		for _, patt := range pkgPatts {
			parts := strings.SplitN(patt, "@", 2)

			a := &arg{
				patt:    patt,
				pkgPatt: parts[0],
			}

			if len(parts) == 2 {
				a.verPatt = parts[1]
			}

			if *fMainMod {
				a.wd = cwd
			} else {
				td, err := ioutil.TempDir("", "gobin")
				if err != nil {
					return fmt.Errorf("failed to create temp dir: %v", err)
				}
				tmpDirs = append(tmpDirs, td)
				if err := ioutil.WriteFile(filepath.Join(td, "go.mod"), []byte("module "+tempModule+"\n"), 0644); err != nil {
					return fmt.Errorf("failed to initialise temp Go module: %v", err)
				}
				a.wd = td
			}

			allPkgs = append(allPkgs, a)
		}
	}

	if !*fUpgrade {
		// local resolution step
		for _, pkg := range allPkgs {
			useModCurr := *fMainMod && pkg.verPatt == ""

			if !useModCurr {
				if err := pkg.get(localCacheProxy); err != nil {
					if *fNoNet {
						return err
					}

					netPkgs = append(netPkgs, pkg)
					continue
				}
			}

			// This is the point at which fMod == readonly
			// will fail. At the moment we return a rather gross
			// error... probably can't assume that any error
			// here is as a result of readonly... but we can
			// likely improve the error message (somehow).
			if err := pkg.list(localCacheProxy); err != nil {
				if !useModCurr {
					return err
				}

				netPkgs = append(netPkgs, pkg)
				continue
			}

			if pkg.resErr != nil {
				nonMain = append(nonMain, pkg)
			}
		}
	} else {
		netPkgs = allPkgs
	}

	if *fNoNet && len(netPkgs) > 0 {
		panic("invariant on netPkgs failed")
	}

	// network resolution step
	for _, pkg := range netPkgs {
		proxy := goenv.GOPROXY
		if proxy != "" {
			proxy = "GOPROXY=" + proxy
		}

		useModCurr := *fMainMod && pkg.verPatt == ""

		if !useModCurr {
			if err := pkg.get(proxy); err != nil {
				return err
			}
		}

		if err := pkg.list(proxy); err != nil {
			return err
		}

		if pkg.resErr != nil {
			nonMain = append(nonMain, pkg)
		}
	}

	if len(nonMain) > 0 {
		for _, pkg := range nonMain {
			fmt.Fprintf(os.Stderr, "%v@%v: %v\n", pkg.pkgPatt, pkg.verPatt, pkg.resErr)
		}
		s := ""
		if len(nonMain) > 1 {
			s = "s"
		}
		return fmt.Errorf("failed to resolve module-based main package%v", s)
	}

	for _, pkg := range allPkgs {
		// each mainPkg install must be done as a separate go command invocation because
		// we set a different GOBIN for each one.
		for _, mp := range pkg.mainPkgs {
			// calculate the relative install directory from main package import path
			// and the containing module's version
			var mainrel string
			{
				emp, err := module.EncodePath(mp.Module.Path)
				if err != nil {
					return fmt.Errorf("failed to encode module path %v: %v", mp.Module.Path, err)
				}

				md := filepath.FromSlash(emp)

				if mp.Module.Version != "" {
					emv, err := module.EncodeVersion(mp.Module.Version)
					if err != nil {
						return fmt.Errorf("failed to encode module version %v: %v", mp.Module.Version, err)
					}

					md = filepath.Join(md, "@v", emv)
				}

				if mp.Module.Path != mp.ImportPath {
					// We don't need to encode what remains in the pkg path because
					// we've already uniquely identified the module. If there are
					// case flips within a module then...  well, we'll see.
					pkgRem := strings.TrimPrefix(mp.ImportPath, mp.Module.Path+"/")
					mainrel = filepath.Join(md, filepath.FromSlash(pkgRem))
				} else {
					mainrel = md
				}
			}

			gobin := filepath.Join(gobinCache, mainrel)

			// If we have non-zero -tags then we need to hash the path
			if *fTags != "" {
				// TODO we could get smart about building a sorted, uniq list of build constraints
				// but for now let's just be stupid
				h := sha256.New()
				fmt.Fprintln(h, mainrel)
				fmt.Fprintln(h, *fTags)
				gobin = filepath.Join(gobinCache, fmt.Sprintf("%x", h.Sum(nil)))
			}

			// mp.Target already has .exe for Windows
			base := filepath.Base(mp.Target)
			target := filepath.Join(gobin, base)

			// Only install if the target (within the gobin cache) does not
			// exist. For now this cache is not read-only so this isn't as
			// safe as it could/should be, but people shouldn't be messing with
			// the cache anyway. The target in the cache is already hash by
			// build tags so we should never have "overlapping" gobin runs.
			//
			// Always install if we are in -m mode, because the main module is
			// responsible for resolving versions. We therefore utilise the
			// install step to effectively ensure the target binary is up to date.
			// This logic would change if were to adopt
			// https://github.com/myitcv/gobin/issues/81 because we would then
			// only install non-versioned module packages (i.e. non-main module,
			// non-directory replaced), or in the case a versioned target does not
			// exist in the gobin cache.
			var install bool
			if *fMainMod {
				install = true
			} else {
				if _, err := os.Stat(target); err != nil {
					if !os.IsNotExist(err) {
						return fmt.Errorf("failed to read %v: %v", target, err)
					}
					install = true
				}
			}
			if install {
				// optimistically remove our target in case we are installing over self
				// TODO work out what to do for Windows
				if mp.ImportPath == "github.com/myitcv/gobin" {
					_ = os.Remove(target)
				}
				installCmd := goCommand("install")
				if *fTags != "" {
					installCmd.Args = append(installCmd.Args, "-tags", *fTags)
				}
				installCmd.Args = append(installCmd.Args, mp.ImportPath)
				installCmd.Dir = pkg.wd
				proxy := ""
				if *fNoNet {
					proxy = localCacheProxy
				}
				installCmd.Env = append(buildEnv(proxy), "GOBIN="+gobin)
				if err := installCmd.run(); err != nil {
					return err
				}
			}

			switch {
			case *fDownload:
				// noop
			case *fPrint:
				fmt.Println(target)
			case *fVersion:
				fmt.Printf("%v %v\n", mp.Module.Path, mp.Module.Version)
			case *fRun:
				run := exec.Command(target, runArgs...)
				run.Args[0] = filepath.Base(mp.Target)
				run.Stdin = os.Stdin
				run.Stdout = os.Stdout
				run.Stderr = os.Stderr
				if err := run.Run(); err != nil {
					if _, ok := err.(*exec.ExitError); ok {
						return err
					}

					return fmt.Errorf("failed to run %v: %v", run.Path, err)
				}
			default:
				installBin := os.Getenv("GOBIN")
				if installBin == "" {
					installBin = filepath.Join(gopath, "bin")
				}
				if err := os.MkdirAll(installBin, 0755); err != nil {
					return fmt.Errorf("failed to mkdir %v: %v", installBin, err)
				}
				src, err := os.Open(target)
				if err != nil {
					return fmt.Errorf("failed to open %v: %v", target, err)
				}
				defer src.Close()

				bin := filepath.Join(installBin, filepath.Base(mp.Target))
				openMode := os.O_CREATE | os.O_WRONLY

				// optimistically remove our target in case we are installing over self
				// TODO work out what to do for Windows
				if mp.ImportPath == "github.com/myitcv/gobin" {
					_ = os.Remove(bin)
					openMode = openMode | os.O_EXCL
				}

				dest, err := os.OpenFile(bin, openMode, 0755)
				if err != nil {
					return fmt.Errorf("failed to open %v for writing: %v", bin, err)
				}
				defer dest.Close()
				if _, err := io.Copy(dest, src); err != nil {
					return fmt.Errorf("failed to copy %v to %v", target, bin)
				}
				fmt.Printf("Installed %v@%v to %v\n", mp.ImportPath, mp.Module.Version, bin)
			}
		}
	}

	return nil
}

// listPkg is a convenience type for unmarshaling the output from go list
type listPkg struct {
	ImportPath string
	Name       string
	Dir        string
	Target     string
	Module     struct {
		Path    string
		Dir     string
		Version string
		GoMod   string
	}
}

type modEditModule struct {
	Path    string
	Version string
}

type modEdit struct {
	Module  modEditModule
	Replace []struct {
		Old modEditModule
		New modEditModule
	}
}

// arg is a wrapper around a command line-provided package
type arg struct {
	patt     string     // the command line-provided pattern
	pkgPatt  string     // the package part of patt
	verPatt  string     // the version part of patt
	mainPkgs []*listPkg // main packages resolved from patt
	wd       string     // working directory for resolution
	resErr   error      // resolution error
	target   string     // the gobin cache target
}

var (
	errNonMain      = errors.New("not a main package")
	errMultiModules = errors.New("cannot (yet) install main packages from a pattern that spans multiple modules")
)

// resolve attempts to resolve a.patt to main packages, using the supplied
// proxy (if != "").  If there is an error resolving a.patt to a package and
// version this is returned. Otherwise the main packages matched by the
// packages are populated into a.mainPkgs
func (a *arg) get(proxy string) error {
	env := buildEnv(proxy)

	getCmd := goCommand("get", "-d", a.patt)
	getCmd.Dir = a.wd
	getCmd.Env = env

	if err := getCmd.run(); err != nil {
		return err
	}

	return nil
}

func (a *arg) list(proxy string) error {
	env := buildEnv(proxy)

	var stdout bytes.Buffer

	listCmd := goCommand("list", "-find", "-json", a.pkgPatt)
	listCmd.Dir = a.wd
	listCmd.Stdout = &stdout
	listCmd.Env = env

	if err := listCmd.run(); err != nil {
		return err
	}

	dec := json.NewDecoder(&stdout)

	// TODO if/when we support patterns including ... we will need to change the
	// semantics of a.resErr and the version resolution below

	// TODO for now we simply throw an error in case the package pattern
	// provided cross module boundaries. Because in global mode, we would need a
	// temp module per module for things to work cleanly (else we might have to
	// handle conflicting replace statements)
	seenMods := make(map[string]bool)

	for {
		pkg := new(listPkg)
		if err := dec.Decode(pkg); err != nil {
			if err == io.EOF {
				break
			}
			return err
		}

		a.verPatt = pkg.Module.Version

		if pkg.Name != "main" {
			a.resErr = errNonMain
			return nil
		}

		seen := seenMods[pkg.Module.Path]
		if !seen && len(seenMods) > 0 {
			a.resErr = errMultiModules
			return nil
		}

		seenMods[pkg.Module.Path] = true

		// If we are not in main-module mode (i.e. -m is not provided), then we
		// are working in a temporary module. Any replacements in
		// $(mp.Module.GoMod) need to be applied to $(pkg.wd)/go.mod. So the
		// simplest thing to do is copy the main package's module's go.mod over
		// the top of the temporary module's go.mod and then adjust the module
		// line and add the single requirement that we now have resolved.
		if !seen && !*fMainMod {
			srcPath := pkg.Module.GoMod
			src, err := os.Open(srcPath)
			if err != nil {
				return fmt.Errorf("failed to open src %v: %v", srcPath, err)
			}

			destPath := filepath.Join(a.wd, "go.mod")
			dest, err := os.Create(destPath)
			if err != nil {
				return fmt.Errorf("failed to create dest %v: %v", destPath, err)
			}

			_, err = io.Copy(dest, src)
			src.Close()
			if err != nil {
				return fmt.Errorf("failed to copy %v to %v: %v", srcPath, destPath, err)
			}
			if err := dest.Close(); err != nil {
				return fmt.Errorf("failed to close dest file %v: %v", destPath, err)
			}

			// work around https://github.com/golang/go/issues/28820 by reading the go.mod
			// and doing a string replace on the module line. Otherwise we could do this
			// in the go mod edit below.
			{
				modreg := regexp.MustCompile(`\A\s*module\s+"?` + regexp.QuoteMeta(pkg.Module.Path) + `"?.*\n`)
				fpath := filepath.Join(a.wd, "go.mod")
				fbyts, err := ioutil.ReadFile(fpath)
				if err != nil {
					return fmt.Errorf("failed to read %v: %v", fpath, err)
				}
				fstr := string(fbyts)
				fstr = modreg.ReplaceAllString(fstr, "module "+tempModule+"\n")
				if err := ioutil.WriteFile(fpath, []byte(fstr), 0644); err != nil {
					return fmt.Errorf("failed to write back to %v: %v", fpath, err)
				}
			}

			gmeCmd := goCommand("mod", "edit", "-require="+pkg.Module.Path+"@"+pkg.Module.Version)
			gmeCmd.Dir = a.wd
			gmeCmd.Env = buildEnv("")

			if err := gmeCmd.run(); err != nil {
				return err
			}

			// now we need to drop all the replacements for which the RHS value does
			// not include a version... because these are directory replacements
			{
				var out bytes.Buffer
				gmeCmd := goCommand("mod", "edit", "-json")
				gmeCmd.Dir = a.wd
				gmeCmd.Stdout = &out
				gmeCmd.Env = buildEnv("")
				if err := gmeCmd.run(); err != nil {
					return err
				}
				var mod modEdit
				if err := json.Unmarshal(out.Bytes(), &mod); err != nil {
					return fmt.Errorf("failed to process output of %v: %v\n%s", strings.Join(gmeCmd.Args, " "), err, out.Bytes())
				}
				var todrop []string
				for _, r := range mod.Replace {
					if r.New.Version != "" {
						continue
					}
					drop := r.Old.Path
					if r.Old.Version != "" {
						drop += "@" + r.Old.Version
					}
					todrop = append(todrop, "-dropreplace="+drop)
				}
				if len(todrop) > 0 {
					gmeCmd := goCommand("mod", "edit")
					gmeCmd.Args = append(gmeCmd.Args, todrop...)
					gmeCmd.Dir = a.wd
					gmeCmd.Env = buildEnv("")
					if err := gmeCmd.run(); err != nil {
						return err
					}
				}
			}

			// now that we effectively have a copy of everything relevant in the
			// target module (including replace directives), list to ensure they
			// have been resolved

			listCmd := goCommand("list", "-find", "-json", pkg.ImportPath)
			listCmd.Dir = a.wd
			listCmd.Env = buildEnv(proxy)

			if err := listCmd.run(); err != nil {
				return err
			}
		}

		a.mainPkgs = append(a.mainPkgs, pkg)
	}

	return nil
}

// buildEnv builds the correct environment for running go commands from gobin.
// proxy is expected to be empty or take the form "GOPROXY=X". If it is non
// empty it will be added to the environment.
func buildEnv(proxy string) []string {
	env := append(os.Environ(), "GO111MODULE=on")
	if proxy != "" {
		env = append(env, proxy)
	}
	goflags := envGOFLAGS
	if *fMainMod && *fMod != "" {
		goflags += " -mod=" + *fMod
	}
	return append(env, "GOFLAGS="+goflags)
}

type goCmd struct {
	*exec.Cmd
}

func goCommand(args ...string) *goCmd {
	return &goCmd{
		Cmd: exec.Command("go", args...),
	}
}

func (cmd *goCmd) run() error {
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	start := time.Now()

	if cmd.Env == nil {
		cmd.Env = os.Environ()
	}
	// in -run mode, it only makes sense to perform go commands in line with
	// runtime.GOOS and runtime.GOARCH. In the edge case scenario where this is
	// intended, use gobin -p with appropriate GOOS and GOARCH env vars set.
	if *fRun {
		cmd.Env = append(cmd.Env,
			"GOOS="+runtime.GOOS,
			"GOARCH="+runtime.GOARCH,
		)
	}

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to run %v: %v\n%s", strings.Join(cmd.Args, " "), err, stderr.String())
	}

	end := time.Now()

	if !*fDebug {
		return nil
	}

	var goenv []string
	for _, v := range cmd.Env {
		if strings.HasPrefix(v, "GO") {
			goenv = append(goenv, v)
		}
	}
	fmt.Fprintf(os.Stderr, "+ cd %v; %v %v # took %v\n%s", cmd.Dir, strings.Join(goenv, " "), strings.Join(cmd.Args, " "), end.Sub(start), stderr.String())

	return nil
}

type goEnv struct {
	ReleaseTags map[string]bool
	GOFLAGS     string
	GOPATH      string
	GOPROXY     string
	GOBIN       string
}

func getGoEnv() (goEnv, error) {
	var res goEnv
	{
		cmd := exec.Command("go", "env", "-json")
		out, err := cmd.CombinedOutput()
		if err != nil {
			return goEnv{}, fmt.Errorf("failed to get go env: %v\n%s", err, out)
		}
		if err := json.Unmarshal(out, &res); err != nil {
			return goEnv{}, fmt.Errorf("failed to unmarshal go env: %v (output was %q)", err, out)
		}
	}
	{
		// Create a temp dir that is not a module for the simple
		// results we need from a go list of runtime
		td, err := ioutil.TempDir("", "gobin-release-tags-")
		if err != nil {
			return goEnv{}, fmt.Errorf("failed to create temp dir for release tags derivation: %v", err)
		}
		defer os.RemoveAll(td)
		cmd := exec.Command("go", "list", `-f={{join context.ReleaseTags "\n"}}`, "runtime")
		cmd.Dir = td
		out, err := cmd.CombinedOutput()
		if err != nil {
			return goEnv{}, fmt.Errorf("failed to get release tags: %v\n%s", err, out)
		}
		res.ReleaseTags = make(map[string]bool)
		for _, t := range strings.Fields(string(out)) {
			res.ReleaseTags[t] = true
		}
	}
	return res, nil
}
