Response: Let's break down the thought process for analyzing this Go code snippet.

**1. Understanding the Core Goal:**

The initial comment is crucial: "Distpack creates the tgz and zip files for a Go distribution." This immediately tells us the program's primary purpose. The subsequent comments elaborate on the *types* of distributions it creates (binary, source, module) and *where* it places them (`GOROOT/pkg/distpack`). This sets the high-level context.

**2. Identifying Key Functionalities:**

* **Packaging:** The name "distpack" itself strongly suggests packaging. The comments about creating `tgz` and `zip` files confirm this.
* **Filtering/Selecting Files:** The description mentions different types of distributions requiring different sets of files. This points to a need for file filtering and selection logic.
* **Platform Awareness:** The comments discuss cross-compilation (`GOOS`, `GOARCH`) and generating platform-specific binary distributions. This indicates platform-aware logic.
* **Module Support:** The creation of module-related files (`.mod`, `.info`, `.zip`) highlights support for Go modules and the `GOTOOLCHAIN` feature.
* **Command-Line Invocation:** The mention of `-distpack` flag to `make.bash` suggests it's designed to be used as part of the Go build process, likely invoked via a command line.

**3. Examining the `main` Function (the Entry Point):**

* **Initialization:** The initial lines deal with logging, telemetry counters (likely for internal Go build tracking), and parsing command-line flags. The `flag.Parse()` and subsequent checks for `flag.NArg()` indicate the program expects no command-line arguments.
* **Context Loading:** The code retrieves `GOROOT`, `GOOS`, `GOARCH`, etc. This is essential for determining the target platform and the location of the Go source tree.
* **Version Handling:**  The `readVERSION` function is called, indicating that the version information is critical for naming the distribution files.
* **Archive Creation and Manipulation:** The core logic revolves around an `Archive` type (not shown in the snippet but clearly used). The code uses methods like `NewArchive`, `Clone`, `Remove`, `Filter`, `Add`, `AddPrefix`, `RenameGoMod`, and `Sort`. This suggests the `Archive` type likely represents a collection of files to be packaged.
* **Distribution-Specific Logic:** The code branches into creating `srcArch`, `binArch`, and `modArch`, each with specific filtering and modifications based on the intended distribution type.
* **Output File Writing:** The `writeTgz` and `writeZip` functions are called to create the actual archive files in the `pkg/distpack` directory. The naming of these files incorporates the version and target platform.
* **Module File Creation:**  The code explicitly creates `.mod` and `.info` files with specific content related to the Go module.

**4. Deeper Dive into Key Functions:**

* **`readVERSION`:** This function parses the `VERSION` file, extracting the version string and potentially a timestamp. The error handling (`log.Fatal`) suggests these values are critical.
* **`writeTgz` and `writeZip`:** These functions use the `archive/tar`, `compress/gzip`, and `archive/zip` packages to create the respective archive formats. The code handles setting file modes and timestamps within the archives.
* **`mode`:** This function determines the file permissions within the archive based on the file name. This is important for ensuring executables have the correct permissions.

**5. Inferring the `Archive` Type (Hypothetical):**

Based on its usage, we can infer that the `Archive` type likely has:

* A way to store a list of files (perhaps a slice of structs).
* Methods for adding, removing, and filtering files.
* Methods for setting timestamps and file modes.
* A method to add a common prefix to all file names.
* A method to rename the `go.mod` file specifically.

**6. Identifying Potential User Errors:**

The comments and the structure of the code itself point to potential errors:

* **Incorrect Environment Variables:**  The script relies on `GOOS` and `GOARCH` for cross-compilation. Setting these incorrectly will lead to the wrong target platform.
* **Interfering with Generated Files:** The code explicitly removes certain generated files. Manually adding or modifying these files might cause issues.
* **Testing Module Downloads:** The comments provide specific instructions for testing the module distribution using `GOPROXY` and `GOTOOLCHAIN`. Not following these steps might lead to incorrect assumptions about the module's usability.

**7. Constructing Examples:**

With the understanding of the code's functionality, we can create illustrative examples for:

* **Cross-compilation:** Showing how setting `GOOS` and `GOARCH` affects the output file names.
* **Module Usage:** Demonstrating how the generated module files can be used with `go get` and `GOPROXY`.

**Self-Correction/Refinement during the Process:**

* **Initial Assumption Check:**  Initially, I might have assumed the `Archive` type is a standard library type, but the custom methods (`AddPrefix`, `RenameGoMod`) indicate it's a custom type within the `distpack` package.
* **Focusing on the "Why":**  Instead of just describing *what* the code does, I focused on *why* it does it. For example, why are certain files removed for the source distribution?  The comment about `../dist/build.go` provides the answer.
* **Connecting to Go Concepts:** I explicitly linked the code to relevant Go features like modules, `GOPROXY`, and the build process.

By following these steps, combining code analysis with an understanding of the Go ecosystem and build process, we can arrive at a comprehensive explanation of the `distpack` code.
这段Go语言代码是 `cmd/distpack/pack.go` 的一部分，它的主要功能是**为 Go 语言发行版创建不同类型的归档文件（archive files）**。

以下是它的具体功能列表：

1. **创建当前 GOOS/GOARCH 的二进制发行版 (Binary Distribution):**
    *   根据当前的操作系统 (`GOOS`) 和架构 (`GOARCH`)，将编译好的 Go 二进制文件、工具链和其他必要文件打包成 `tgz` 或 `zip` 文件。
    *   Windows 系统会生成 `.zip` 文件，其他系统通常生成 `.tar.gz` 文件。
    *   此发行版包含运行 Go 所需的核心组件。

2. **创建与 GOOS/GOARCH 无关的源代码发行版 (Source Distribution):**
    *   打包 Go 的完整源代码，不包含编译生成的文件和平台特定的二进制文件。
    *   生成的 `.tar.gz` 文件包含了 `src` 目录下的所有源代码。
    *   用于构建其他平台或进行源代码研究。

3. **创建模块形式的发行版 (Module Distribution):**
    *   生成用于 Go 工具链支持的模块文件，包括 `.mod`、`.info` 和 `.zip` 文件。
    *   `.zip` 文件类似于二进制发行版，但经过裁剪，只包含运行时和工具链的核心部分，并加上了模块路径前缀。
    *   `.mod` 文件描述了该模块的信息（模块路径）。
    *   `.info` 文件包含了模块的版本和时间戳信息。
    *   这种形式的发行版主要用于 `go` 命令的 `GOTOOLCHAIN` 功能，允许用户下载和使用特定版本的 Go 工具链。

**它是什么 Go 语言功能的实现：**

这段代码是 Go 语言构建和发布过程中的一个关键步骤，它利用了 Go 的标准库来处理文件操作、压缩和归档：

*   **`archive/tar` 和 `compress/gzip`:** 用于创建 `.tar.gz` 格式的归档文件。
*   **`archive/zip`:** 用于创建 `.zip` 格式的归档文件。
*   **`io` 和 `os`:** 用于文件读写和文件系统操作。
*   **`path/filepath`:** 用于处理文件路径。
*   **`crypto/sha256`:** 用于计算文件的 SHA256 哈希值。
*   **`flag`:** 用于处理命令行参数（虽然这段代码中没有实际使用任何参数，但 `flag` 包被导入并初始化）。
*   **`runtime`:** 用于获取当前 Go 运行时的信息，如 `GOROOT`、`GOOS` 和 `GOARCH`。

**Go 代码举例说明：**

这段代码本身就是一个完整的 `main` 函数，用于执行打包操作。 它可以被编译成一个可执行文件 `distpack`。  以下是如何使用它（通常不是直接使用，而是通过 `make.bash` 脚本）：

**假设的输入与输出：**

假设我们正在 `linux` 操作系统和 `amd64` 架构上构建 Go 1.21 版本。 `GOROOT` 指向 Go 的源代码根目录。

**输入 (通过环境变量和 `make.bash` 脚本设置):**

*   `GOROOT`: `/path/to/go/source`
*   `GOOS`: `linux`
*   `GOARCH`: `amd64`
*   `VERSION` 文件内容 (在 `GOROOT` 下):
    ```
    go1.21
    time 2023-08-08T10:00:00Z
    ```

**执行命令 (通常由 `make.bash` 内部调用):**

```bash
go run go/src/cmd/distpack/pack.go
```

**输出 (在 `$GOROOT/pkg/distpack` 目录下):**

*   `go1.21.src.tar.gz`:  Go 1.21 的源代码归档文件。
*   `go1.21.linux-amd64.tar.gz`:  适用于 Linux amd64 的 Go 1.21 二进制发行版。
*   `v0.0.1-go1.21.linux-amd64.zip`:  Go 1.21 的模块发行版 (zip)。
*   `v0.0.1-go1.21.linux-amd64.mod`:  模块描述文件，内容为 `module golang.org/toolchain`。
*   `v0.0.1-go1.21.linux-amd64.info`: 模块信息文件，内容类似 `{"Version":"v0.0.1-go1.21.linux-amd64", "Time":"2023-08-08T10:00:00Z"}`。

**控制台输出 (显示计算出的哈希值):**

```
distpack: <hash> go1.21.src.tar.gz
distpack: <hash> go1.21.linux-amd64.tar.gz
distpack: <hash> v0.0.1-go1.21.linux-amd64.zip
distpack: <hash> v0.0.1-go1.21.linux-amd64.mod
distpack: <hash> v0.0.1-go1.21.linux-amd64.info
```

**命令行参数的具体处理：**

虽然代码中导入了 `flag` 包，但实际上 `main` 函数中并没有定义和处理任何命令行参数。代码检查了 `flag.NArg() != 0`，如果存在任何命令行参数，它会调用 `usage()` 函数并退出。

因此，**`distpack` 工具本身不接受任何命令行参数**。它的行为完全由环境变量 (`GOROOT`, `GOOS`, `GOARCH`) 和 `VERSION` 文件的内容驱动。

**使用者易犯错的点：**

虽然 `distpack` 通常不由最终用户直接调用，但参与 Go 语言构建过程的开发者可能会遇到以下问题：

1. **环境变量设置错误:**
    *   **错误设置 `GOOS` 和 `GOARCH` 进行交叉编译:**  如果 `GOOS` 和 `GOARCH` 设置与目标平台不符，则会生成错误的二进制发行版。
        ```bash
        # 期望构建 linux/amd64 版本，但错误地设置了 GOARCH
        GOOS=linux GOARCH=arm64 ./make.bash -distpack
        ```
        这将导致生成文件名包含 `arm64`，但内容可能是为 `amd64` 编译的，或者构建过程会出错。

2. **依赖 `make.bash` 脚本的上下文:**
    *   **直接运行 `go run pack.go` 可能失败或产生不完整的结果:** `distpack` 依赖于 `make.bash` 脚本设置正确的构建环境，例如，确保二进制文件已编译好。直接运行 `go run pack.go` 可能因为缺少必要的输入文件或环境而失败。

3. **修改或删除 `VERSION` 文件:**
    *   `distpack` 读取 `VERSION` 文件来获取版本号和时间戳。 错误地修改或删除此文件会导致程序崩溃或生成文件名不正确的发行版。

4. **测试模块下载时的配置错误:**
    *   **`GOPROXY` 和 `GOTOOLCHAIN` 设置不当:**  在测试模块下载功能时，如果 `GOPROXY` 指向的路径不正确，或者 `GOTOOLCHAIN` 没有设置为期望的版本，会导致测试失败。 例如，`ln -sf $(pwd)/../pkg/distpack /tmp/goproxy/golang.org/toolchain/@v` 这一步至关重要，如果链接创建错误，`go version` 命令将无法找到对应的工具链。

**总结:**

`go/src/cmd/distpack/pack.go` 是 Go 语言构建过程中的一个核心工具，负责生成各种类型的发行版文件。它不接受命令行参数，而是依赖于环境变量和 `VERSION` 文件的内容。使用者需要理解其与 `make.bash` 脚本的集成，并正确设置环境变量以避免错误。

### 提示词
```
这是路径为go/src/cmd/distpack/pack.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
```

### 源代码
```go
// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Distpack creates the tgz and zip files for a Go distribution.
// It writes into GOROOT/pkg/distpack:
//
//   - a binary distribution (tgz or zip) for the current GOOS and GOARCH
//   - a source distribution that is independent of GOOS/GOARCH
//   - the module mod, info, and zip files for a distribution in module form
//     (as used by GOTOOLCHAIN support in the go command).
//
// Distpack is typically invoked by the -distpack flag to make.bash.
// A cross-compiled distribution for goos/goarch can be built using:
//
//	GOOS=goos GOARCH=goarch ./make.bash -distpack
//
// To test that the module downloads are usable with the go command:
//
//	./make.bash -distpack
//	mkdir -p /tmp/goproxy/golang.org/toolchain/
//	ln -sf $(pwd)/../pkg/distpack /tmp/goproxy/golang.org/toolchain/@v
//	GOPROXY=file:///tmp/goproxy GOTOOLCHAIN=$(sed 1q ../VERSION) gotip version
//
// gotip can be replaced with an older released Go version once there is one.
// It just can't be the one make.bash built, because it knows it is already that
// version and will skip the download.
package main

import (
	"archive/tar"
	"archive/zip"
	"compress/flate"
	"compress/gzip"
	"crypto/sha256"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"log"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"cmd/internal/telemetry/counter"
)

func usage() {
	fmt.Fprintf(os.Stderr, "usage: distpack\n")
	os.Exit(2)
}

const (
	modPath          = "golang.org/toolchain"
	modVersionPrefix = "v0.0.1"
)

var (
	goroot     string
	gohostos   string
	gohostarch string
	goos       string
	goarch     string
)

func main() {
	log.SetPrefix("distpack: ")
	log.SetFlags(0)
	counter.Open()
	flag.Usage = usage
	flag.Parse()
	counter.Inc("distpack/invocations")
	counter.CountFlags("distpack/flag:", *flag.CommandLine)
	if flag.NArg() != 0 {
		usage()
	}

	// Load context.
	goroot = runtime.GOROOT()
	if goroot == "" {
		log.Fatalf("missing $GOROOT")
	}
	gohostos = runtime.GOOS
	gohostarch = runtime.GOARCH
	goos = os.Getenv("GOOS")
	if goos == "" {
		goos = gohostos
	}
	goarch = os.Getenv("GOARCH")
	if goarch == "" {
		goarch = gohostarch
	}
	goosUnderGoarch := goos + "_" + goarch
	goosDashGoarch := goos + "-" + goarch
	exe := ""
	if goos == "windows" {
		exe = ".exe"
	}
	version, versionTime := readVERSION(goroot)

	// Start with files from GOROOT, filtering out non-distribution files.
	base, err := NewArchive(goroot)
	if err != nil {
		log.Fatal(err)
	}
	base.SetTime(versionTime)
	base.SetMode(mode)
	base.Remove(
		".git/**",
		".gitattributes",
		".github/**",
		".gitignore",
		"VERSION.cache",
		"misc/cgo/*/_obj/**",
		"**/.DS_Store",
		"**/*.exe~", // go.dev/issue/23894
		// Generated during make.bat/make.bash.
		"src/cmd/dist/dist",
		"src/cmd/dist/dist.exe",
	)

	// The source distribution removes files generated during the release build.
	// See ../dist/build.go's deptab.
	srcArch := base.Clone()
	srcArch.Remove(
		"bin/**",
		"pkg/**",

		// Generated during cmd/dist. See ../dist/build.go:/gentab.
		"src/cmd/go/internal/cfg/zdefaultcc.go",
		"src/go/build/zcgo.go",
		"src/internal/runtime/sys/zversion.go",
		"src/time/tzdata/zzipdata.go",

		// Generated during cmd/dist by bootstrapBuildTools.
		"src/cmd/cgo/zdefaultcc.go",
		"src/cmd/internal/objabi/zbootstrap.go",
		"src/internal/buildcfg/zbootstrap.go",

		// Generated by earlier versions of cmd/dist .
		"src/cmd/go/internal/cfg/zosarch.go",
	)
	srcArch.AddPrefix("go")
	testSrc(srcArch)

	// The binary distribution includes only a subset of bin and pkg.
	binArch := base.Clone()
	binArch.Filter(func(name string) bool {
		// Discard bin/ for now, will add back later.
		if strings.HasPrefix(name, "bin/") {
			return false
		}
		// Discard most of pkg.
		if strings.HasPrefix(name, "pkg/") {
			// Keep pkg/include.
			if strings.HasPrefix(name, "pkg/include/") {
				return true
			}
			// Discard other pkg except pkg/tool.
			if !strings.HasPrefix(name, "pkg/tool/") {
				return false
			}
			// Inside pkg/tool, keep only $GOOS_$GOARCH.
			if !strings.HasPrefix(name, "pkg/tool/"+goosUnderGoarch+"/") {
				return false
			}
			// Inside pkg/tool/$GOOS_$GOARCH, discard helper tools.
			switch strings.TrimSuffix(path.Base(name), ".exe") {
			case "api", "dist", "distpack", "metadata":
				return false
			}
		}
		return true
	})

	// Add go and gofmt to bin, using cross-compiled binaries
	// if this is a cross-compiled distribution.
	binExes := []string{
		"go",
		"gofmt",
	}
	crossBin := "bin"
	if goos != gohostos || goarch != gohostarch {
		crossBin = "bin/" + goosUnderGoarch
	}
	for _, b := range binExes {
		name := "bin/" + b + exe
		src := filepath.Join(goroot, crossBin, b+exe)
		info, err := os.Stat(src)
		if err != nil {
			log.Fatal(err)
		}
		binArch.Add(name, src, info)
	}
	binArch.Sort()
	binArch.SetTime(versionTime) // fix added files
	binArch.SetMode(mode)        // fix added files

	zipArch := binArch.Clone()
	zipArch.AddPrefix("go")
	testZip(zipArch)

	// The module distribution is the binary distribution with unnecessary files removed
	// and file names using the necessary prefix for the module.
	modArch := binArch.Clone()
	modArch.Remove(
		"api/**",
		"doc/**",
		"misc/**",
		"test/**",
	)
	modVers := modVersionPrefix + "-" + version + "." + goosDashGoarch
	modArch.AddPrefix(modPath + "@" + modVers)
	modArch.RenameGoMod()
	modArch.Sort()
	testMod(modArch)

	// distpack returns the full path to name in the distpack directory.
	distpack := func(name string) string {
		return filepath.Join(goroot, "pkg/distpack", name)
	}
	if err := os.MkdirAll(filepath.Join(goroot, "pkg/distpack"), 0777); err != nil {
		log.Fatal(err)
	}

	writeTgz(distpack(version+".src.tar.gz"), srcArch)

	if goos == "windows" {
		writeZip(distpack(version+"."+goos+"-"+goarch+".zip"), zipArch)
	} else {
		writeTgz(distpack(version+"."+goos+"-"+goarch+".tar.gz"), zipArch)
	}

	writeZip(distpack(modVers+".zip"), modArch)
	writeFile(distpack(modVers+".mod"),
		[]byte(fmt.Sprintf("module %s\n", modPath)))
	writeFile(distpack(modVers+".info"),
		[]byte(fmt.Sprintf("{%q:%q, %q:%q}\n",
			"Version", modVers,
			"Time", versionTime.Format(time.RFC3339))))
}

// mode computes the mode for the given file name.
func mode(name string, _ fs.FileMode) fs.FileMode {
	if strings.HasPrefix(name, "bin/") ||
		strings.HasPrefix(name, "pkg/tool/") ||
		strings.HasSuffix(name, ".bash") ||
		strings.HasSuffix(name, ".sh") ||
		strings.HasSuffix(name, ".pl") ||
		strings.HasSuffix(name, ".rc") {
		return 0o755
	} else if ok, _ := amatch("**/go_?*_?*_exec", name); ok {
		return 0o755
	}
	return 0o644
}

// readVERSION reads the VERSION file.
// The first line of the file is the Go version.
// Additional lines are 'key value' pairs setting other data.
// The only valid key at the moment is 'time', which sets the modification time for file archives.
func readVERSION(goroot string) (version string, t time.Time) {
	data, err := os.ReadFile(filepath.Join(goroot, "VERSION"))
	if err != nil {
		log.Fatal(err)
	}
	version, rest, _ := strings.Cut(string(data), "\n")
	for _, line := range strings.Split(rest, "\n") {
		f := strings.Fields(line)
		if len(f) == 0 {
			continue
		}
		switch f[0] {
		default:
			log.Fatalf("VERSION: unexpected line: %s", line)
		case "time":
			if len(f) != 2 {
				log.Fatalf("VERSION: unexpected time line: %s", line)
			}
			t, err = time.ParseInLocation(time.RFC3339, f[1], time.UTC)
			if err != nil {
				log.Fatalf("VERSION: bad time: %s", err)
			}
		}
	}
	return version, t
}

// writeFile writes a file with the given name and data or fatals.
func writeFile(name string, data []byte) {
	if err := os.WriteFile(name, data, 0666); err != nil {
		log.Fatal(err)
	}
	reportHash(name)
}

// check panics if err is not nil. Otherwise it returns x.
// It is only meant to be used in a function that has deferred
// a function to recover appropriately from the panic.
func check[T any](x T, err error) T {
	check1(err)
	return x
}

// check1 panics if err is not nil.
// It is only meant to be used in a function that has deferred
// a function to recover appropriately from the panic.
func check1(err error) {
	if err != nil {
		panic(err)
	}
}

// writeTgz writes the archive in tgz form to the file named name.
func writeTgz(name string, a *Archive) {
	out, err := os.Create(name)
	if err != nil {
		log.Fatal(err)
	}

	var f File
	defer func() {
		if err := recover(); err != nil {
			extra := ""
			if f.Name != "" {
				extra = " " + f.Name
			}
			log.Fatalf("writing %s%s: %v", name, extra, err)
		}
	}()

	zw := check(gzip.NewWriterLevel(out, gzip.BestCompression))
	tw := tar.NewWriter(zw)

	// Find the mode and mtime to use for directory entries,
	// based on the mode and mtime of the first file we see.
	// We know that modes and mtimes are uniform across the archive.
	var dirMode fs.FileMode
	var mtime time.Time
	for _, f := range a.Files {
		dirMode = fs.ModeDir | f.Mode | (f.Mode&0444)>>2 // copy r bits down to x bits
		mtime = f.Time
		break
	}

	// mkdirAll ensures that the tar file contains directory
	// entries for dir and all its parents. Some programs reading
	// these tar files expect that. See go.dev/issue/61862.
	haveDir := map[string]bool{".": true}
	var mkdirAll func(string)
	mkdirAll = func(dir string) {
		if dir == "/" {
			panic("mkdirAll /")
		}
		if haveDir[dir] {
			return
		}
		haveDir[dir] = true
		mkdirAll(path.Dir(dir))
		df := &File{
			Name: dir + "/",
			Time: mtime,
			Mode: dirMode,
		}
		h := check(tar.FileInfoHeader(df.Info(), ""))
		h.Name = dir + "/"
		if err := tw.WriteHeader(h); err != nil {
			panic(err)
		}
	}

	for _, f = range a.Files {
		h := check(tar.FileInfoHeader(f.Info(), ""))
		mkdirAll(path.Dir(f.Name))
		h.Name = f.Name
		if err := tw.WriteHeader(h); err != nil {
			panic(err)
		}
		r := check(os.Open(f.Src))
		check(io.Copy(tw, r))
		check1(r.Close())
	}
	f.Name = ""
	check1(tw.Close())
	check1(zw.Close())
	check1(out.Close())
	reportHash(name)
}

// writeZip writes the archive in zip form to the file named name.
func writeZip(name string, a *Archive) {
	out, err := os.Create(name)
	if err != nil {
		log.Fatal(err)
	}

	var f File
	defer func() {
		if err := recover(); err != nil {
			extra := ""
			if f.Name != "" {
				extra = " " + f.Name
			}
			log.Fatalf("writing %s%s: %v", name, extra, err)
		}
	}()

	zw := zip.NewWriter(out)
	zw.RegisterCompressor(zip.Deflate, func(out io.Writer) (io.WriteCloser, error) {
		return flate.NewWriter(out, flate.BestCompression)
	})
	for _, f = range a.Files {
		h := check(zip.FileInfoHeader(f.Info()))
		h.Name = f.Name
		h.Method = zip.Deflate
		w := check(zw.CreateHeader(h))
		r := check(os.Open(f.Src))
		check(io.Copy(w, r))
		check1(r.Close())
	}
	f.Name = ""
	check1(zw.Close())
	check1(out.Close())
	reportHash(name)
}

func reportHash(name string) {
	f, err := os.Open(name)
	if err != nil {
		log.Fatal(err)
	}
	h := sha256.New()
	io.Copy(h, f)
	f.Close()
	fmt.Printf("distpack: %x %s\n", h.Sum(nil)[:8], filepath.Base(name))
}
```