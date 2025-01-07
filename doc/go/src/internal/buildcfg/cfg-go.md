Response:
Let's break down the thought process for analyzing the provided Go code snippet.

**1. Understanding the Core Purpose:**

The initial comment block is crucial. It explicitly states the package `buildcfg` is for accessing build configuration *during the build process* for tools like `cmd/go` and `cmd/compile`. It also emphasizes that this is *not* the configuration of the currently running binary. This distinction is vital for understanding its function.

**2. Identifying Key Data Structures and Variables:**

The code immediately defines several top-level variables like `GOROOT`, `GOARCH`, `GOOS`, etc. These are clearly environment variables related to Go's build system. The capitalization suggests they are intended to be exported and accessible. The comments next to them, like "cached for efficiency," provide hints about their usage. The `Error` variable and `Check()` function strongly suggest a mechanism for reporting and handling configuration errors.

**3. Analyzing Functions and Their Roles:**

* **`envOr(key, value string) string`:** This is a common pattern for retrieving environment variables with a default value. It's a utility function for the rest of the package.
* **`goamd64()`, `goarm()`, `goarm64()`, `gomips()`, `gomips64()`, `goppc64()`, `goriscv64()`, `gowasm()`:** These functions stand out because their names directly correspond to Go architecture and operating system environment variables. They likely handle the parsing and validation of these specific variables. The `switch` statements and error handling within them support this. Notice the consistent pattern of retrieving the environment variable using `envOr`, validating it, and potentially setting the global `Error`.
* **`gofips140()` and `isFIPSVersion()` and `skipNum()`:** This cluster of functions seems related to a specific security standard (FIPS 140). The logic involves checking for prefixes and numeric patterns in the environment variable value.
* **`ParseGoarm64(v string)`:** This function is explicitly for parsing the `GOARM64` string, suggesting a more complex structure for this variable. The handling of ",lse" and ",crypto" suffixes confirms this.
* **`Getgoextlinkenabled()`:**  A straightforward function to get the `GO_EXTLINK_ENABLED` environment variable.
* **`toolTags()` and `experimentTags()` and `gogoarchTags()`:** These functions return slices of strings. The names suggest they are generating build tags, likely used by the Go build system to conditionally compile code.
* **`GOGOARCH()`:**  This function returns a pair of strings, hinting at how the `GOARCH` variable is mapped to specific environment variables and their values.
* **Methods on `GoarmFeatures` and `Goarm64Features` and `gowasmFeatures`:** The `String()` methods suggest these structs are used to represent the parsed and structured values of the corresponding environment variables. The `Supports()` method on `Goarm64Features` indicates a way to check if a specific ARM64 feature set is supported by the current configuration.

**4. Inferring Functionality and Purpose:**

Based on the analysis above, the core functionality of `buildcfg` is to:

* **Read and Parse Go Build Environment Variables:** It retrieves values from environment variables that control the Go build process (target OS, architecture, specific CPU features, etc.).
* **Validate Environment Variable Values:** It checks if the provided values for these variables are valid according to Go's specifications.
* **Provide Structured Access to Configuration:** It parses the raw string values into more structured Go types (like the `GoarmFeatures` struct) for easier use by other build tools.
* **Collect and Report Errors:** It accumulates any validation errors in the global `Error` variable and provides a `Check()` function to halt the build process if errors exist.
* **Generate Build Tags:** It creates build tags based on the configured environment, allowing conditional compilation of code.
* **Set up `go/build` Context (as mentioned in the package comment):** This is an implied function. By providing access to these configuration variables, `buildcfg` likely facilitates the initialization of the `go/build` package's context, which is used for package discovery and compilation.

**5. Constructing Examples:**

With the understanding of the functionality, constructing examples becomes more straightforward. The examples should illustrate:

* **Reading environment variables:**  Demonstrate how the global variables like `GOARCH` and `GOOS` are populated.
* **Parsing specific variables:** Show how functions like `goarm()` parse the `GOARM` environment variable into the `GoarmFeatures` struct.
* **Error handling:**  Illustrate how invalid environment variable values lead to errors and how `Check()` can be used to detect them.
* **Generating build tags:**  Show how `toolTags()` produces build tags based on the environment.

**6. Identifying Potential Pitfalls:**

Focus on the validation logic within the parsing functions. Think about common mistakes users might make when setting environment variables:

* **Incorrect formatting:**  For example, providing an invalid value for `GOAMD64` or `GOARM`.
* **Typos:**  Misspelling environment variable names.
* **Not understanding the allowed values:**  For instance, not knowing the valid options for `GOMIPS`.

**7. Structuring the Answer:**

Organize the information logically using headings and bullet points for clarity. Start with the main functions, then provide code examples, explain command-line parameters (though not heavily used in *this* specific snippet), and finally, address potential errors.

**Self-Correction/Refinement during the Process:**

* Initially, I might have focused too much on the individual variable declarations. Realizing the parsing functions are where the core logic lies is important.
*  The package comment about setting up `go/build`'s `Default` context is a key insight that needs to be included in the overall functionality description.
* While the code doesn't directly process command-line arguments, recognizing that these environment variables are *often* set via command-line flags to `go build` or similar tools is a useful connection to make.

By following this structured analysis, I can effectively understand and explain the functionality of the `buildcfg` package.
这段代码是 Go 语言标准库中 `internal/buildcfg` 包的一部分，它主要负责**获取和解析当前 Go 构建环境的配置信息**。这些配置信息通常通过环境变量来设置，并被 `cmd/go` 和 `cmd/compile` 等构建工具使用，也用于设置 `go/build` 包的默认上下文。

下面我将详细列举其功能，并进行代码推理和举例说明：

**功能列举:**

1. **读取 Go 构建相关的环境变量:**  代码定义了一系列全局变量（如 `GOROOT`, `GOARCH`, `GOOS` 等）来存储从环境变量中读取的值。例如，`GOROOT = os.Getenv("GOROOT")` 直接读取了 `GOROOT` 环境变量。对于一些常用的环境变量，还使用了 `envOr` 函数，如果环境变量不存在则使用默认值。

2. **解析和验证特定的架构和操作系统相关的环境变量:**  代码中包含多个以 `go` 开头的函数（如 `goamd64`, `goarm`, `goarm64` 等），这些函数负责解析和验证特定架构或操作系统相关的环境变量，例如 `GOAMD64`、`GOARM`、`GOARM64` 等。这些函数会根据环境变量的值进行转换和检查，确保其符合预期的格式和取值范围。

3. **处理架构特性的环境变量:** 对于一些架构，如 `arm`、`arm64`、`wasm`，代码定义了相应的结构体（如 `GoarmFeatures`, `Goarm64Features`, `gowasmFeatures`）来更精细地表示架构的特性，并通过解析环境变量将其填充到这些结构体中。

4. **记录和检查配置错误:**  代码中使用全局变量 `Error` 来记录在解析过程中遇到的错误。`Check()` 函数用于检查 `Error` 是否为空，如果不为空则将错误信息打印到标准错误流并退出程序。

5. **生成构建标签 (Build Tags):**  `toolTags()` 函数会根据当前的构建配置生成一系列的构建标签。这些标签可以用于条件编译，允许根据不同的构建环境编译不同的代码。`gogoarchTags()` 函数专门负责生成与目标架构相关的构建标签。

6. **提供访问配置信息的接口:**  通过导出的全局变量（如 `GOARCH`, `GOOS`, `GOARM64` 等），以及 `GOGOARCH()` 函数，其他包可以方便地获取当前的构建配置信息。

**Go 语言功能实现推理与代码举例:**

这个包主要实现了对**环境变量的读取、解析和验证**，以及**根据环境变量生成构建标签**的功能。

**例 1: 读取和解析 `GOARCH` 和 `GOAMD64`**

```go
package main

import (
	"fmt"
	"internal/buildcfg"
	"os"
)

func main() {
	// 假设环境变量 GOARCH 设置为 "amd64"，GOAMD64 设置为 "v3"
	os.Setenv("GOARCH", "amd64")
	os.Setenv("GOAMD64", "v3")

	// 访问 buildcfg 包的全局变量
	arch := buildcfg.GOARCH
	amd64Level := buildcfg.GOAMD64

	fmt.Printf("GOARCH: %s\n", arch)        // 输出: GOARCH: amd64
	fmt.Printf("GOAMD64: %d\n", amd64Level) // 输出: GOAMD64: 3

	// 使用 GOGOARCH 函数
	name, value := buildcfg.GOGOARCH()
	fmt.Printf("GOGOARCH Name: %s, Value: %s\n", name, value) // 输出: GOGOARCH Name: GOAMD64, Value: v3

	// 清理环境变量 (可选)
	os.Unsetenv("GOARCH")
	os.Unsetenv("GOAMD64")
}
```

**假设输入:** 环境变量 `GOARCH="amd64"`，`GOAMD64="v3"`

**输出:**
```
GOARCH: amd64
GOAMD64: 3
GOGOARCH Name: GOAMD64, Value: v3
```

**代码推理:**

* `buildcfg.GOARCH` 直接读取了 `GOARCH` 环境变量的值。
* `buildcfg.goamd64()` 函数被调用来解析 `GOAMD64` 环境变量。该函数会根据 "v1", "v2", "v3", "v4" 将其转换为对应的整数。
* `buildcfg.GOGOARCH()` 函数根据 `GOARCH` 的值，返回对应的环境变量名和当前值。

**例 2: 解析 `GOARM` 环境变量**

```go
package main

import (
	"fmt"
	"internal/buildcfg"
	"os"
)

func main() {
	// 假设环境变量 GOARM 设置为 "7,softfloat"
	os.Setenv("GOARM", "7,softfloat")

	// 访问 buildcfg 包的全局变量
	armFeatures := buildcfg.GOARM

	fmt.Printf("GOARM Version: %d\n", armFeatures.Version)   // 输出: GOARM Version: 7
	fmt.Printf("GOARM SoftFloat: %t\n", armFeatures.SoftFloat) // 输出: GOARM SoftFloat: true

	fmt.Printf("GOARM String representation: %s\n", armFeatures.String()) // 输出: GOARM String representation: 7,softfloat

	// 清理环境变量 (可选)
	os.Unsetenv("GOARM")
}
```

**假设输入:** 环境变量 `GOARM="7,softfloat"`

**输出:**
```
GOARM Version: 7
GOARM SoftFloat: true
GOARM String representation: 7,softfloat
```

**代码推理:**

* `buildcfg.goarm()` 函数被调用来解析 `GOARM` 环境变量。该函数会处理 ",softfloat" 和 ",hardfloat" 后缀，并提取 ARM 的版本信息。
* `buildcfg.GOARM` 是一个 `GoarmFeatures` 类型的结构体，包含了解析后的版本号和是否使用软浮点的信息。

**例 3: 生成构建标签**

```go
package main

import (
	"fmt"
	"internal/buildcfg"
	"os"
)

func main() {
	// 假设 GOOS 是 "linux"，GOARCH 是 "amd64"，GOAMD64 是 "v2"
	os.Setenv("GOOS", "linux")
	os.Setenv("GOARCH", "amd64")
	os.Setenv("GOAMD64", "v2")

	tags := buildcfg.ToolTags

	fmt.Println("Build Tags:")
	for _, tag := range tags {
		fmt.Println(tag)
	}

	// 清理环境变量 (可选)
	os.Unsetenv("GOOS")
	os.Unsetenv("GOARCH")
	os.Unsetenv("GOAMD64")
}
```

**假设输入:** 环境变量 `GOOS="linux"`, `GOARCH="amd64"`, `GOAMD64="v2"`

**可能的输出 (输出会包含实验性标签，此处仅列出部分):**
```
Build Tags:
linux
amd64
amd64.v1
amd64.v2
```

**代码推理:**

* `buildcfg.toolTags()` 函数被调用。
* 该函数内部会调用 `buildcfg.gogoarchTags()` 来生成与架构相关的标签。
* 对于 `GOARCH=amd64` 和 `GOAMD64=v2`，`gogoarchTags()` 会生成 `amd64.v1` 和 `amd64.v2` 这样的标签。
* `toolTags()` 还会包含其他的标签，例如与操作系统相关的标签 "linux"。

**命令行参数的具体处理:**

这段代码本身并不直接处理命令行参数。这些环境变量通常是在运行 `go build`、`go run` 等命令时通过命令行选项或者直接在 shell 中设置的。

例如：

* 使用命令行选项设置：
  ```bash
  GOOS=linux GOARCH=arm go build myprogram.go
  ```
* 在 shell 中设置环境变量：
  ```bash
  export GOOS=linux
  export GOARCH=arm
  go build myprogram.go
  ```

`cmd/go` 工具在运行时会读取这些环境变量，并将其传递给 `internal/buildcfg` 包进行解析和处理。

**使用者易犯错的点:**

1. **环境变量名称拼写错误:**  如果环境变量名称拼写错误，`os.Getenv()` 将返回空字符串，或者 `envOr` 函数会使用默认值，这可能导致构建配置不符合预期。例如，将 `GOARCH` 误写成 `GARCH`。

   ```go
   // 假设错误地使用了 GARCH
   os.Setenv("GARCH", "arm")
   arch := buildcfg.GOARCH // arch 将会是默认值，而不是 "arm"
   ```

2. **环境变量值不符合预期格式:**  某些环境变量有特定的格式要求，例如 `GOAMD64` 只能是 "v1"、"v2"、"v3" 或 "v4"。如果设置了其他值，`goamd64()` 函数会返回错误。

   ```go
   os.Setenv("GOAMD64", "invalid")
   buildcfg.Check() // 会因为 GOAMD64 的值无效而导致程序退出
   ```

3. **混淆目标平台的配置和当前构建工具的配置:**  需要明确 `internal/buildcfg` 是用于配置**将要构建的程序**的目标平台，而不是当前运行 `go build` 命令的平台的配置。当前运行平台的配置可以使用 `runtime` 包中的 `runtime.GOOS` 和 `runtime.GOARCH` 等。

**总结:**

`go/src/internal/buildcfg/cfg.go` 是 Go 构建系统的核心组成部分，它负责从环境变量中读取和解析构建配置信息，并提供给其他构建工具使用。理解其功能和工作原理对于深入理解 Go 的构建过程至关重要。

Prompt: 
```
这是路径为go/src/internal/buildcfg/cfg.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。

"""
// Copyright 2021 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package buildcfg provides access to the build configuration
// described by the current environment. It is for use by build tools
// such as cmd/go or cmd/compile and for setting up go/build's Default context.
//
// Note that it does NOT provide access to the build configuration used to
// build the currently-running binary. For that, use runtime.GOOS etc
// as well as internal/goexperiment.
package buildcfg

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

var (
	GOROOT    = os.Getenv("GOROOT") // cached for efficiency
	GOARCH    = envOr("GOARCH", defaultGOARCH)
	GOOS      = envOr("GOOS", defaultGOOS)
	GO386     = envOr("GO386", DefaultGO386)
	GOAMD64   = goamd64()
	GOARM     = goarm()
	GOARM64   = goarm64()
	GOMIPS    = gomips()
	GOMIPS64  = gomips64()
	GOPPC64   = goppc64()
	GORISCV64 = goriscv64()
	GOWASM    = gowasm()
	ToolTags  = toolTags()
	GO_LDSO   = defaultGO_LDSO
	GOFIPS140 = gofips140()
	Version   = version
)

// Error is one of the errors found (if any) in the build configuration.
var Error error

// Check exits the program with a fatal error if Error is non-nil.
func Check() {
	if Error != nil {
		fmt.Fprintf(os.Stderr, "%s: %v\n", filepath.Base(os.Args[0]), Error)
		os.Exit(2)
	}
}

func envOr(key, value string) string {
	if x := os.Getenv(key); x != "" {
		return x
	}
	return value
}

func goamd64() int {
	switch v := envOr("GOAMD64", DefaultGOAMD64); v {
	case "v1":
		return 1
	case "v2":
		return 2
	case "v3":
		return 3
	case "v4":
		return 4
	}
	Error = fmt.Errorf("invalid GOAMD64: must be v1, v2, v3, v4")
	return int(DefaultGOAMD64[len("v")] - '0')
}

func gofips140() string {
	v := envOr("GOFIPS140", DefaultGOFIPS140)
	switch v {
	case "off", "latest", "inprocess", "certified":
		return v
	}
	if isFIPSVersion(v) {
		return v
	}
	Error = fmt.Errorf("invalid GOFIPS140: must be off, latest, inprocess, certified, or vX.Y.Z")
	return DefaultGOFIPS140
}

// isFIPSVersion reports whether v is a valid FIPS version,
// of the form vX.Y.Z.
func isFIPSVersion(v string) bool {
	if !strings.HasPrefix(v, "v") {
		return false
	}
	v, ok := skipNum(v[len("v"):])
	if !ok || !strings.HasPrefix(v, ".") {
		return false
	}
	v, ok = skipNum(v[len("."):])
	if !ok || !strings.HasPrefix(v, ".") {
		return false
	}
	v, ok = skipNum(v[len("."):])
	return ok && v == ""
}

// skipNum skips the leading text matching [0-9]+
// in s, returning the rest and whether such text was found.
func skipNum(s string) (rest string, ok bool) {
	i := 0
	for i < len(s) && '0' <= s[i] && s[i] <= '9' {
		i++
	}
	return s[i:], i > 0
}

type GoarmFeatures struct {
	Version   int
	SoftFloat bool
}

func (g GoarmFeatures) String() string {
	armStr := strconv.Itoa(g.Version)
	if g.SoftFloat {
		armStr += ",softfloat"
	} else {
		armStr += ",hardfloat"
	}
	return armStr
}

func goarm() (g GoarmFeatures) {
	const (
		softFloatOpt = ",softfloat"
		hardFloatOpt = ",hardfloat"
	)
	def := DefaultGOARM
	if GOOS == "android" && GOARCH == "arm" {
		// Android arm devices always support GOARM=7.
		def = "7"
	}
	v := envOr("GOARM", def)

	floatSpecified := false
	if strings.HasSuffix(v, softFloatOpt) {
		g.SoftFloat = true
		floatSpecified = true
		v = v[:len(v)-len(softFloatOpt)]
	}
	if strings.HasSuffix(v, hardFloatOpt) {
		floatSpecified = true
		v = v[:len(v)-len(hardFloatOpt)]
	}

	switch v {
	case "5":
		g.Version = 5
	case "6":
		g.Version = 6
	case "7":
		g.Version = 7
	default:
		Error = fmt.Errorf("invalid GOARM: must start with 5, 6, or 7, and may optionally end in either %q or %q", hardFloatOpt, softFloatOpt)
		g.Version = int(def[0] - '0')
	}

	// 5 defaults to softfloat. 6 and 7 default to hardfloat.
	if !floatSpecified && g.Version == 5 {
		g.SoftFloat = true
	}
	return
}

type Goarm64Features struct {
	Version string
	// Large Systems Extension
	LSE bool
	// ARM v8.0 Cryptographic Extension. It includes the following features:
	// * FEAT_AES, which includes the AESD and AESE instructions.
	// * FEAT_PMULL, which includes the PMULL, PMULL2 instructions.
	// * FEAT_SHA1, which includes the SHA1* instructions.
	// * FEAT_SHA256, which includes the SHA256* instructions.
	Crypto bool
}

func (g Goarm64Features) String() string {
	arm64Str := g.Version
	if g.LSE {
		arm64Str += ",lse"
	}
	if g.Crypto {
		arm64Str += ",crypto"
	}
	return arm64Str
}

func ParseGoarm64(v string) (g Goarm64Features, e error) {
	const (
		lseOpt    = ",lse"
		cryptoOpt = ",crypto"
	)

	g.LSE = false
	g.Crypto = false
	// We allow any combination of suffixes, in any order
	for {
		if strings.HasSuffix(v, lseOpt) {
			g.LSE = true
			v = v[:len(v)-len(lseOpt)]
			continue
		}

		if strings.HasSuffix(v, cryptoOpt) {
			g.Crypto = true
			v = v[:len(v)-len(cryptoOpt)]
			continue
		}

		break
	}

	switch v {
	case "v8.0":
		g.Version = v
	case "v8.1", "v8.2", "v8.3", "v8.4", "v8.5", "v8.6", "v8.7", "v8.8", "v8.9",
		"v9.0", "v9.1", "v9.2", "v9.3", "v9.4", "v9.5":
		g.Version = v
		// LSE extension is mandatory starting from 8.1
		g.LSE = true
	default:
		e = fmt.Errorf("invalid GOARM64: must start with v8.{0-9} or v9.{0-5} and may optionally end in %q and/or %q",
			lseOpt, cryptoOpt)
		g.Version = DefaultGOARM64
	}

	return
}

func goarm64() (g Goarm64Features) {
	g, Error = ParseGoarm64(envOr("GOARM64", DefaultGOARM64))
	return
}

// Returns true if g supports giving ARM64 ISA
// Note that this function doesn't accept / test suffixes (like ",lse" or ",crypto")
func (g Goarm64Features) Supports(s string) bool {
	// We only accept "v{8-9}.{0-9}. Everything else is malformed.
	if len(s) != 4 {
		return false
	}

	major := s[1]
	minor := s[3]

	// We only accept "v{8-9}.{0-9}. Everything else is malformed.
	if major < '8' || major > '9' ||
		minor < '0' || minor > '9' ||
		s[0] != 'v' || s[2] != '.' {
		return false
	}

	g_major := g.Version[1]
	g_minor := g.Version[3]

	if major == g_major {
		return minor <= g_minor
	} else if g_major == '9' {
		// v9.0 diverged from v8.5. This means we should compare with g_minor increased by five.
		return minor <= g_minor+5
	} else {
		return false
	}
}

func gomips() string {
	switch v := envOr("GOMIPS", DefaultGOMIPS); v {
	case "hardfloat", "softfloat":
		return v
	}
	Error = fmt.Errorf("invalid GOMIPS: must be hardfloat, softfloat")
	return DefaultGOMIPS
}

func gomips64() string {
	switch v := envOr("GOMIPS64", DefaultGOMIPS64); v {
	case "hardfloat", "softfloat":
		return v
	}
	Error = fmt.Errorf("invalid GOMIPS64: must be hardfloat, softfloat")
	return DefaultGOMIPS64
}

func goppc64() int {
	switch v := envOr("GOPPC64", DefaultGOPPC64); v {
	case "power8":
		return 8
	case "power9":
		return 9
	case "power10":
		return 10
	}
	Error = fmt.Errorf("invalid GOPPC64: must be power8, power9, power10")
	return int(DefaultGOPPC64[len("power")] - '0')
}

func goriscv64() int {
	switch v := envOr("GORISCV64", DefaultGORISCV64); v {
	case "rva20u64":
		return 20
	case "rva22u64":
		return 22
	}
	Error = fmt.Errorf("invalid GORISCV64: must be rva20u64, rva22u64")
	v := DefaultGORISCV64[len("rva"):]
	i := strings.IndexFunc(v, func(r rune) bool {
		return r < '0' || r > '9'
	})
	year, _ := strconv.Atoi(v[:i])
	return year
}

type gowasmFeatures struct {
	SatConv bool
	SignExt bool
}

func (f gowasmFeatures) String() string {
	var flags []string
	if f.SatConv {
		flags = append(flags, "satconv")
	}
	if f.SignExt {
		flags = append(flags, "signext")
	}
	return strings.Join(flags, ",")
}

func gowasm() (f gowasmFeatures) {
	for _, opt := range strings.Split(envOr("GOWASM", ""), ",") {
		switch opt {
		case "satconv":
			f.SatConv = true
		case "signext":
			f.SignExt = true
		case "":
			// ignore
		default:
			Error = fmt.Errorf("invalid GOWASM: no such feature %q", opt)
		}
	}
	return
}

func Getgoextlinkenabled() string {
	return envOr("GO_EXTLINK_ENABLED", defaultGO_EXTLINK_ENABLED)
}

func toolTags() []string {
	tags := experimentTags()
	tags = append(tags, gogoarchTags()...)
	return tags
}

func experimentTags() []string {
	var list []string
	// For each experiment that has been enabled in the toolchain, define a
	// build tag with the same name but prefixed by "goexperiment." which can be
	// used for compiling alternative files for the experiment. This allows
	// changes for the experiment, like extra struct fields in the runtime,
	// without affecting the base non-experiment code at all.
	for _, exp := range Experiment.Enabled() {
		list = append(list, "goexperiment."+exp)
	}
	return list
}

// GOGOARCH returns the name and value of the GO$GOARCH setting.
// For example, if GOARCH is "amd64" it might return "GOAMD64", "v2".
func GOGOARCH() (name, value string) {
	switch GOARCH {
	case "386":
		return "GO386", GO386
	case "amd64":
		return "GOAMD64", fmt.Sprintf("v%d", GOAMD64)
	case "arm":
		return "GOARM", GOARM.String()
	case "arm64":
		return "GOARM64", GOARM64.String()
	case "mips", "mipsle":
		return "GOMIPS", GOMIPS
	case "mips64", "mips64le":
		return "GOMIPS64", GOMIPS64
	case "ppc64", "ppc64le":
		return "GOPPC64", fmt.Sprintf("power%d", GOPPC64)
	case "wasm":
		return "GOWASM", GOWASM.String()
	}
	return "", ""
}

func gogoarchTags() []string {
	switch GOARCH {
	case "386":
		return []string{GOARCH + "." + GO386}
	case "amd64":
		var list []string
		for i := 1; i <= GOAMD64; i++ {
			list = append(list, fmt.Sprintf("%s.v%d", GOARCH, i))
		}
		return list
	case "arm":
		var list []string
		for i := 5; i <= GOARM.Version; i++ {
			list = append(list, fmt.Sprintf("%s.%d", GOARCH, i))
		}
		return list
	case "arm64":
		var list []string
		major := int(GOARM64.Version[1] - '0')
		minor := int(GOARM64.Version[3] - '0')
		for i := 0; i <= minor; i++ {
			list = append(list, fmt.Sprintf("%s.v%d.%d", GOARCH, major, i))
		}
		// ARM64 v9.x also includes support of v8.x+5 (i.e. v9.1 includes v8.(1+5) = v8.6).
		if major == 9 {
			for i := 0; i <= minor+5 && i <= 9; i++ {
				list = append(list, fmt.Sprintf("%s.v%d.%d", GOARCH, 8, i))
			}
		}
		return list
	case "mips", "mipsle":
		return []string{GOARCH + "." + GOMIPS}
	case "mips64", "mips64le":
		return []string{GOARCH + "." + GOMIPS64}
	case "ppc64", "ppc64le":
		var list []string
		for i := 8; i <= GOPPC64; i++ {
			list = append(list, fmt.Sprintf("%s.power%d", GOARCH, i))
		}
		return list
	case "riscv64":
		list := []string{GOARCH + "." + "rva20u64"}
		if GORISCV64 >= 22 {
			list = append(list, GOARCH+"."+"rva22u64")
		}
		return list
	case "wasm":
		var list []string
		if GOWASM.SatConv {
			list = append(list, GOARCH+".satconv")
		}
		if GOWASM.SignExt {
			list = append(list, GOARCH+".signext")
		}
		return list
	}
	return nil
}

"""



```