Response:
Let's break down the thought process for analyzing the provided Go code.

**1. Initial Understanding - The Big Picture:**

The first thing to notice is the comment at the very top: "This file exercises the import parser but also checks that some low-level packages do not have new dependencies added." This immediately tells us the primary purpose of this file: **dependency management and validation within the Go standard library.**  It's not about implementing a general-purpose feature, but about enforcing internal architectural rules.

**2. Examining Key Data Structures:**

* **`depsRules` (string):** This large multi-line string stands out. The comments within it are crucial: "defines the expected dependencies," "DO NOT CHANGE THIS DATA TO FIX BUILDS," and the explanation of the `<` operator. This clearly represents the **policy** of allowed dependencies. The all-caps names hint at abstract groups of packages.

* **`sawImport` (map[string]map[string]bool):**  This structure, initialized in `TestDependencies`, looks like it's designed to track actual import relationships. The nested maps suggest `sawImport[packageA][packageB]` will be true if `packageA` imports `packageB`.

* **`policy` (*dag.Graph):** The `depsPolicy` function uses `dag.Parse(depsRules)`. This strongly suggests that the `depsRules` string is being parsed into a directed acyclic graph (DAG) representation, suitable for checking dependency relationships. The `internal/dag` package import confirms this.

**3. Analyzing the Test Functions:**

* **`TestDependencies(t *testing.T)`:** This is the core test function. It iterates through all standard library packages (`listStdPkgs`), finds their actual imports (`findImports`), and then checks if those imports conform to the `policy`. The error message "unexpected dependency" confirms its purpose is to detect violations of the defined dependency rules.

* **`TestStdlibLowercase(t *testing.T)`:**  This test seems unrelated to dependency management. Its purpose, as the comment and logic show, is to ensure all standard library package names are lowercase. This is a style/convention check.

* **`TestFindImports(t *testing.T)`:**  This appears to be a utility test to verify that the `findImports` function itself works correctly. It checks if `findImports("go/build")` returns the expected imports.

**4. Deconstructing Helper Functions:**

* **`listStdPkgs(goroot string) ([]string, error)`:** The comment and its logic (walking the `src` directory) clearly indicate it's designed to list all standard library packages, mimicking the output of `go list std`.

* **`findImports(pkg string) ([]string, error)`:** This function's purpose is evident: find the import statements within the Go files of a given package. It handles vendor prefixes and ignores test files and `//go:build ignore` directives.

* **`depsPolicy(t *testing.T) *dag.Graph`:** As mentioned before, this parses the `depsRules` string into a `dag.Graph`.

**5. Reasoning about the "Why":**

Based on the code and comments, the underlying reason for this dependency checking mechanism seems to be:

* **Maintainability:**  Preventing unintended dependencies keeps the standard library's architecture clean and easier to understand and modify.
* **Reducing Coupling:**  Lower coupling between packages makes them more independent and reduces the risk of ripple effects when changes are made.
* **Controlling the "Foundation":** The explicit rules, particularly the "NONE < ..." section, aim to establish a very stable and dependency-free foundation of core packages.

**6. Addressing the Prompt's Specific Questions (Pre-computation/Analysis):**

* **Functionality:** Enforce dependency rules, verify lowercase package names, test the import finding function.
* **Go Feature:** Dependency management/architectural constraints.
* **Code Example:** Demonstrate how the `depsRules` string defines the allowed imports. This requires showing the rule and the corresponding allowed import.
* **Assumptions/Inputs/Outputs:** For `findImports`, show an example input package and the expected list of imported packages.
* **Command Line:** Not applicable, as this is a test file.
* **Common Mistakes:** Focus on the "DO NOT CHANGE THIS DATA TO FIX BUILDS" warning.

**7. Structuring the Answer:**

Finally, organize the findings in a clear and structured way, addressing each part of the prompt. Use headings and bullet points for readability. Provide code examples where requested, and explain the reasoning behind the code's behavior. Emphasize the key takeaways, such as the importance of the `depsRules` string and the purpose of the tests.

This iterative process of examining the code, understanding its components, and reasoning about its purpose allows for a comprehensive analysis and the generation of a detailed and accurate answer.
这是 `go/src/go/build/deps_test.go` 文件的一部分，它主要的功能是**测试 Go 语言标准库中包的依赖关系是否符合预定义的规则**。 它的目标是维护标准库的架构清晰和稳定，防止低层级的包引入不必要的依赖。

更具体地说，这个文件实现了以下功能：

1. **定义依赖规则:** 通过一个名为 `depsRules` 的多行字符串变量，硬编码了标准库中各个包之间允许的依赖关系。这个 `depsRules` 的语法由 `internal/dag` 包定义，使用类似 `a < b` 的形式表示包 `b` 可以导入包 `a`。  `NONE < package_name` 表示没有任何包可以导入 `package_name`。

2. **列出标准库包:** 使用 `listStdPkgs` 函数，通过遍历 `$GOROOT/src` 目录来获取所有标准库包的列表，类似于 `go list std` 命令。

3. **查找包的导入:**  使用 `findImports` 函数，解析指定 Go 包的源文件，提取其中 `import` 语句声明的依赖包。这个函数会忽略测试文件和带有 `//go:build ignore` 标记的文件。

4. **验证依赖关系:** 在 `TestDependencies` 测试函数中，遍历所有标准库包，获取它们的实际导入，然后对照 `depsPolicy` 函数解析 `depsRules` 生成的依赖图进行校验。如果发现实际导入的包不在预定义的允许依赖关系中，测试将会报错。

5. **测试标准库包名小写:** `TestStdlibLowercase` 函数检查所有标准库包的名称是否都是小写字母，这是一个风格约定。

6. **测试 `findImports` 函数:** `TestFindImports` 函数是一个单元测试，用于验证 `findImports` 函数本身的功能是否正常。

**它是什么 Go 语言功能的实现？**

这个文件主要实现了对 **Go 语言包依赖管理和架构约束** 的测试和维护。它不是一个直接给用户使用的 Go 语言特性，而是 Go 语言开发团队用来保证标准库质量和架构稳定性的内部工具。

**Go 代码举例说明:**

`depsRules` 变量定义了允许的依赖关系。例如，规则：

```go
internal/goarch < internal/abi;
```

意味着 `internal/abi` 包可以导入 `internal/goarch` 包。

`TestDependencies` 函数会验证实际的导入是否符合这个规则。 假设 `internal/abi` 的某个源文件导入了 `fmt` 包，而 `depsRules` 中没有定义 `fmt` 可以被 `internal/abi` 导入的规则，测试就会失败。

```go
// 假设这是 internal/abi/some_file.go 的内容
package abi

import "fmt" // 这会导致 TestDependencies 失败，因为 depsRules 中没有允许的依赖

func PrintSomething() {
	fmt.Println("Something")
}
```

**假设的输入与输出 (针对 `findImports` 函数):**

**假设输入:** 包名字符串 `"go/build"`

**预期输出:** 一个字符串切片，包含 `go/build` 包中所有非测试 Go 文件导入的包，例如 `["bytes", "os", "path/filepath", "strings"]` (基于提供的代码片段中的 `TestFindImports` 函数的 `want` 变量)。

**命令行参数的具体处理:**

这个文件本身是一个测试文件，不涉及命令行参数的处理。它通过 `go test` 命令执行。

**使用者易犯错的点:**

对于 *使用者* (指想要贡献代码到 Go 标准库的开发者) 而言，最容易犯的错误就是在添加新的依赖时，没有考虑到 `go/build/deps_test.go` 中定义的规则。

**举例说明:**

假设你想修改 `container/list` 包，并且在其中引入了对 `fmt` 包的依赖。当你运行 `go test std` 或相关的测试时，`TestDependencies` 函数会检测到 `container/list` 导入了 `fmt`，但 `depsRules` 中定义了 `NONE < container/list`，这意味着 `container/list` 不应该有任何依赖。 这会导致测试失败。

```
--- FAIL: TestDependencies (0.01s)
    deps_test.go:148: unexpected dependency: container/list imports fmt
```

为了修复这个错误，**你不能直接修改 `depsRules` 来允许这个新的依赖** (除非经过充分的讨论和论证，因为 `depsRules` 代表了重要的架构策略)。 正确的做法是重新考虑你的修改，看是否有其他方式实现功能，而不需要引入这个新的依赖。 如果确实有必要引入，你需要与 Go 核心团队讨论，并解释为什么这个依赖是必要的。

总而言之，`go/src/go/build/deps_test.go` 是 Go 语言标准库中一个非常重要的测试文件，它通过硬编码的依赖规则来维护标准库的架构完整性和稳定性。 它有效地防止了低层级的包意外地引入新的依赖，保证了标准库的长期可维护性和可理解性。

### 提示词
```
这是路径为go/src/go/build/deps_test.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
```

### 源代码
```go
// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// This file exercises the import parser but also checks that
// some low-level packages do not have new dependencies added.

package build

import (
	"bytes"
	"fmt"
	"go/token"
	"internal/dag"
	"internal/testenv"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// depsRules defines the expected dependencies between packages in
// the Go source tree. It is a statement of policy.
//
// DO NOT CHANGE THIS DATA TO FIX BUILDS.
// Existing packages should not have their constraints relaxed
// without prior discussion.
// Negative assertions should almost never be removed.
//
// "a < b" means package b can import package a.
//
// See `go doc internal/dag` for the full syntax.
//
// All-caps names are pseudo-names for specific points
// in the dependency lattice.
var depsRules = `
	# No dependencies allowed for any of these packages.
	NONE
	< unsafe
	< cmp,
	  container/list,
	  container/ring,
	  internal/byteorder,
	  internal/cfg,
	  internal/coverage,
	  internal/coverage/rtcov,
	  internal/coverage/uleb128,
	  internal/coverage/calloc,
	  internal/cpu,
	  internal/goarch,
	  internal/godebugs,
	  internal/goexperiment,
	  internal/goos,
	  internal/goversion,
	  internal/nettrace,
	  internal/platform,
	  internal/profilerecord,
	  internal/syslist,
	  internal/trace/traceviewer/format,
	  log/internal,
	  math/bits,
	  structs,
	  unicode,
	  unicode/utf8,
	  unicode/utf16;

	internal/goarch < internal/abi;
	internal/byteorder, internal/goarch < internal/chacha8rand;

	# RUNTIME is the core runtime group of packages, all of them very light-weight.
	internal/abi,
	internal/chacha8rand,
	internal/coverage/rtcov,
	internal/cpu,
	internal/goarch,
	internal/godebugs,
	internal/goexperiment,
	internal/goos,
	internal/profilerecord,
	math/bits,
	structs
	< internal/bytealg
	< internal/stringslite
	< internal/itoa
	< internal/unsafeheader
	< internal/race
	< internal/msan
	< internal/asan
	< internal/runtime/sys
	< internal/runtime/syscall
	< internal/runtime/atomic
	< internal/runtime/exithook
	< internal/runtime/math
	< internal/runtime/maps
	< runtime
	< sync/atomic
	< internal/sync
	< weak
	< sync
	< internal/bisect
	< internal/godebug
	< internal/reflectlite
	< errors
	< internal/oserror;

	cmp, runtime, math/bits
	< iter
	< maps, slices;

	internal/oserror, maps, slices
	< RUNTIME;

	RUNTIME
	< sort
	< container/heap
	< unique;

	RUNTIME
	< io;

	RUNTIME
	< arena;

	syscall !< io;
	reflect !< sort;

	RUNTIME, unicode/utf8
	< path;

	unicode !< path;

	RUNTIME
	< internal/synctest
	< testing/synctest;

	# SYSCALL is RUNTIME plus the packages necessary for basic system calls.
	RUNTIME, unicode/utf8, unicode/utf16, internal/synctest
	< internal/syscall/windows/sysdll, syscall/js
	< syscall
	< internal/syscall/unix, internal/syscall/windows, internal/syscall/windows/registry
	< internal/syscall/execenv
	< SYSCALL;

	# TIME is SYSCALL plus the core packages about time, including context.
	SYSCALL
	< time/tzdata
	< time
	< context
	< TIME;

	TIME, io, path, slices
	< io/fs;

	# MATH is RUNTIME plus the basic math packages.
	RUNTIME
	< math
	< MATH;

	unicode !< math;

	MATH
	< math/cmplx;

	MATH
	< math/rand, math/rand/v2;

	MATH
	< runtime/metrics;

	MATH, unicode/utf8
	< strconv;

	unicode !< strconv;

	# STR is basic string and buffer manipulation.
	RUNTIME, io, unicode/utf8, unicode/utf16, unicode
	< bytes, strings
	< bufio;

	bufio, path, strconv
	< STR;

	# OS is basic OS access, including helpers (path/filepath, os/exec, etc).
	# OS includes string routines, but those must be layered above package os.
	# OS does not include reflection.
	io/fs
	< internal/testlog
	< internal/poll
	< internal/filepathlite
	< os
	< os/signal;

	io/fs
	< embed;

	unicode, fmt !< net, os, os/signal;

	os/signal, internal/filepathlite, STR
	< path/filepath
	< io/ioutil;

	path/filepath, internal/godebug < os/exec;

	io/ioutil, os/exec, os/signal
	< OS;

	reflect !< OS;

	OS
	< golang.org/x/sys/cpu;

	# FMT is OS (which includes string routines) plus reflect and fmt.
	# It does not include package log, which should be avoided in core packages.
	arena, strconv, unicode
	< reflect;

	os, reflect
	< internal/fmtsort
	< fmt;

	OS, fmt
	< FMT;

	log !< FMT;

	# Misc packages needing only FMT.
	FMT
	< html,
	  internal/dag,
	  internal/goroot,
	  internal/types/errors,
	  mime/quotedprintable,
	  net/internal/socktest,
	  net/url,
	  runtime/trace,
	  text/scanner,
	  text/tabwriter;

	io, reflect
	< internal/saferio;

	# encodings
	# core ones do not use fmt.
	io, strconv, slices
	< encoding;

	encoding, reflect
	< encoding/binary
	< encoding/base32, encoding/base64;

	FMT, encoding < flag;

	fmt !< encoding/base32, encoding/base64;

	FMT, encoding/base32, encoding/base64, internal/saferio
	< encoding/ascii85, encoding/csv, encoding/gob, encoding/hex,
	  encoding/json, encoding/pem, encoding/xml, mime;

	# hashes
	io
	< hash
	< hash/adler32, hash/crc32, hash/crc64, hash/fnv;

	# math/big
	FMT, math/rand
	< math/big;

	# compression
	FMT, encoding/binary, hash/adler32, hash/crc32, sort
	< compress/bzip2, compress/flate, compress/lzw, internal/zstd
	< archive/zip, compress/gzip, compress/zlib;

	# templates
	FMT
	< text/template/parse;

	net/url, text/template/parse
	< text/template
	< internal/lazytemplate;

	# regexp
	FMT, sort
	< regexp/syntax
	< regexp
	< internal/lazyregexp;

	encoding/json, html, text/template, regexp
	< html/template;

	# suffix array
	encoding/binary, regexp
	< index/suffixarray;

	# executable parsing
	FMT, encoding/binary, compress/zlib, internal/saferio, internal/zstd, sort
	< runtime/debug
	< debug/dwarf
	< debug/elf, debug/gosym, debug/macho, debug/pe, debug/plan9obj, internal/xcoff
	< debug/buildinfo
	< DEBUG;

	# go parser and friends.
	FMT, sort
	< internal/gover
	< go/version
	< go/token
	< go/scanner
	< go/ast
	< go/internal/typeparams;

	FMT
	< go/build/constraint;

	FMT, sort
	< go/doc/comment;

	go/internal/typeparams, go/build/constraint
	< go/parser;

	go/doc/comment, go/parser, text/tabwriter
	< go/printer
	< go/format;

	math/big, go/token
	< go/constant;

	FMT, internal/goexperiment
	< internal/buildcfg;

	container/heap, go/constant, go/parser, internal/buildcfg, internal/goversion, internal/types/errors
	< go/types;

	# The vast majority of standard library packages should not be resorting to regexp.
	# go/types is a good chokepoint. It shouldn't use regexp, nor should anything
	# that is low-enough level to be used by go/types.
	regexp !< go/types;

	go/doc/comment, go/parser, internal/lazyregexp, text/template
	< go/doc;

	go/build/constraint, go/doc, go/parser, internal/buildcfg, internal/goroot, internal/goversion, internal/platform, internal/syslist
	< go/build;

	# databases
	FMT
	< database/sql/internal
	< database/sql/driver;

	database/sql/driver, math/rand/v2 < database/sql;

	# images
	FMT, compress/lzw, compress/zlib
	< image/color
	< image, image/color/palette
	< image/internal/imageutil
	< image/draw
	< image/gif, image/jpeg, image/png;

	# cgo, delayed as long as possible.
	# If you add a dependency on CGO, you must add the package
	# to cgoPackages in cmd/dist/test.go as well.
	RUNTIME
	< C
	< runtime/cgo
	< CGO
	< runtime/msan, runtime/asan;

	# runtime/race
	NONE < runtime/race/internal/amd64v1;
	NONE < runtime/race/internal/amd64v3;
	CGO, runtime/race/internal/amd64v1, runtime/race/internal/amd64v3 < runtime/race;

	# Bulk of the standard library must not use cgo.
	# The prohibition stops at net and os/user.
	C !< fmt, go/types, CRYPTO-MATH, log/slog;

	CGO, OS
	< plugin;

	CGO, FMT
	< os/user
	< archive/tar;

	sync
	< internal/singleflight;

	os
	< golang.org/x/net/dns/dnsmessage,
	  golang.org/x/net/lif,
	  golang.org/x/net/route;

	internal/bytealg, internal/itoa, math/bits, slices, strconv, unique
	< net/netip;

	# net is unavoidable when doing any networking,
	# so large dependencies must be kept out.
	# This is a long-looking list but most of these
	# are small with few dependencies.
	CGO,
	golang.org/x/net/dns/dnsmessage,
	golang.org/x/net/lif,
	golang.org/x/net/route,
	internal/godebug,
	internal/nettrace,
	internal/poll,
	internal/singleflight,
	net/netip,
	os,
	sort
	< net;

	fmt, unicode !< net;
	math/rand !< net; # net uses runtime instead

	# NET is net plus net-helper packages.
	FMT, net
	< net/textproto;

	mime, net/textproto, net/url
	< NET;

	# logging - most packages should not import; http and up is allowed
	FMT, log/internal
	< log;

	log, log/slog !< crypto/tls, database/sql, go/importer, testing;

	FMT, log, net
	< log/syslog;

	RUNTIME
	< log/slog/internal, log/slog/internal/buffer;

	FMT,
	encoding, encoding/json,
	log, log/internal,
	log/slog/internal, log/slog/internal/buffer,
	slices
	< log/slog
	< log/slog/internal/slogtest, log/slog/internal/benchmarks;

	NET, log
	< net/mail;

	# FIPS is the FIPS 140 module.
	# It must not depend on external crypto packages.
	# See also fips140deps.AllowedInternalPackages.

	io, math/rand/v2 < crypto/internal/randutil;

	STR < crypto/internal/impl;

	OS < crypto/internal/sysrand
	< crypto/internal/entropy;

	internal/byteorder < crypto/internal/fips140deps/byteorder;
	internal/cpu, internal/goarch < crypto/internal/fips140deps/cpu;
	internal/godebug < crypto/internal/fips140deps/godebug;

	STR, crypto/internal/impl,
	crypto/internal/entropy,
	crypto/internal/randutil,
	crypto/internal/fips140deps/byteorder,
	crypto/internal/fips140deps/cpu,
	crypto/internal/fips140deps/godebug
	< crypto/internal/fips140
	< crypto/internal/fips140/alias
	< crypto/internal/fips140/subtle
	< crypto/internal/fips140/sha256
	< crypto/internal/fips140/sha512
	< crypto/internal/fips140/sha3
	< crypto/internal/fips140/hmac
	< crypto/internal/fips140/check
	< crypto/internal/fips140/pbkdf2
	< crypto/internal/fips140/aes
	< crypto/internal/fips140/drbg
	< crypto/internal/fips140/aes/gcm
	< crypto/internal/fips140/hkdf
	< crypto/internal/fips140/mlkem
	< crypto/internal/fips140/ssh
	< crypto/internal/fips140/tls12
	< crypto/internal/fips140/tls13
	< crypto/internal/fips140/bigmod
	< crypto/internal/fips140/nistec/fiat
	< crypto/internal/fips140/nistec
	< crypto/internal/fips140/ecdh
	< crypto/internal/fips140/ecdsa
	< crypto/internal/fips140/edwards25519/field
	< crypto/internal/fips140/edwards25519
	< crypto/internal/fips140/ed25519
	< crypto/internal/fips140/rsa
	< FIPS;

	FIPS, internal/godebug < crypto/fips140;

	crypto, hash !< FIPS;

	# CRYPTO is core crypto algorithms - no cgo, fmt, net.
	# Mostly wrappers around the FIPS module.

	NONE < crypto/internal/boring/sig, crypto/internal/boring/syso;
	sync/atomic < crypto/internal/boring/bcache;

	FIPS, internal/godebug, hash, embed,
	crypto/internal/boring/sig,
	crypto/internal/boring/syso,
	crypto/internal/boring/bcache
	< crypto/internal/fips140only
	< crypto
	< crypto/subtle
	< crypto/cipher
	< crypto/internal/boring
	< crypto/boring
	< crypto/aes,
	  crypto/des,
	  crypto/rc4,
	  crypto/md5,
	  crypto/sha1,
	  crypto/sha256,
	  crypto/sha512,
	  crypto/sha3,
	  crypto/hmac,
	  crypto/hkdf,
	  crypto/pbkdf2,
	  crypto/ecdh,
	  crypto/mlkem
	< CRYPTO;

	CGO, fmt, net !< CRYPTO;

	# CRYPTO-MATH is crypto that exposes math/big APIs - no cgo, net; fmt now ok.

	CRYPTO, FMT, math/big
	< crypto/internal/boring/bbig
	< crypto/rand
	< crypto/ed25519 # depends on crypto/rand.Reader
	< encoding/asn1
	< golang.org/x/crypto/cryptobyte/asn1
	< golang.org/x/crypto/cryptobyte
	< crypto/dsa, crypto/elliptic, crypto/rsa
	< crypto/ecdsa
	< CRYPTO-MATH;

	CGO, net !< CRYPTO-MATH;

	# TLS, Prince of Dependencies.

	FIPS, sync/atomic < crypto/tls/internal/fips140tls;

	crypto/internal/boring/sig, crypto/tls/internal/fips140tls < crypto/tls/fipsonly;

	CRYPTO, golang.org/x/sys/cpu, encoding/binary, reflect
	< golang.org/x/crypto/internal/alias
	< golang.org/x/crypto/internal/subtle
	< golang.org/x/crypto/chacha20
	< golang.org/x/crypto/internal/poly1305
	< golang.org/x/crypto/chacha20poly1305;

	CRYPTO-MATH, NET, container/list, encoding/hex, encoding/pem,
	golang.org/x/crypto/chacha20poly1305, crypto/tls/internal/fips140tls
	< crypto/internal/hpke
	< crypto/x509/internal/macos
	< crypto/x509/pkix
	< crypto/x509
	< crypto/tls;

	# crypto-aware packages

	DEBUG, go/build, go/types, text/scanner, crypto/md5
	< internal/pkgbits, internal/exportdata
	< go/internal/gcimporter, go/internal/gccgoimporter, go/internal/srcimporter
	< go/importer;

	NET, crypto/rand, mime/quotedprintable
	< mime/multipart;

	crypto/tls
	< net/smtp;

	crypto/rand
	< hash/maphash; # for purego implementation

	# HTTP, King of Dependencies.

	FMT
	< golang.org/x/net/http2/hpack
	< net/http/internal, net/http/internal/ascii, net/http/internal/testcert;

	FMT, NET, container/list, encoding/binary, log
	< golang.org/x/text/transform
	< golang.org/x/text/unicode/norm
	< golang.org/x/text/unicode/bidi
	< golang.org/x/text/secure/bidirule
	< golang.org/x/net/idna
	< golang.org/x/net/http/httpguts, golang.org/x/net/http/httpproxy;

	NET, crypto/tls
	< net/http/httptrace;

	compress/gzip,
	golang.org/x/net/http/httpguts,
	golang.org/x/net/http/httpproxy,
	golang.org/x/net/http2/hpack,
	net/http/internal,
	net/http/internal/ascii,
	net/http/internal/testcert,
	net/http/httptrace,
	mime/multipart,
	log
	< net/http;

	# HTTP-aware packages

	encoding/json, net/http
	< expvar;

	net/http, net/http/internal/ascii
	< net/http/cookiejar, net/http/httputil;

	net/http, flag
	< net/http/httptest;

	net/http, regexp
	< net/http/cgi
	< net/http/fcgi;

	# Profiling
	FMT, compress/gzip, encoding/binary, sort, text/tabwriter
	< runtime/pprof;

	OS, compress/gzip, internal/lazyregexp
	< internal/profile;

	html, internal/profile, net/http, runtime/pprof, runtime/trace
	< net/http/pprof;

	# RPC
	encoding/gob, encoding/json, go/token, html/template, net/http
	< net/rpc
	< net/rpc/jsonrpc;

	# System Information
	bufio, bytes, internal/cpu, io, os, strings, sync
	< internal/sysinfo;

	# Test-only
	log
	< testing/iotest
	< testing/fstest;

	FMT, flag, math/rand
	< testing/quick;

	FMT, DEBUG, flag, runtime/trace, internal/sysinfo, math/rand
	< testing;

	log/slog, testing
	< testing/slogtest;

	FMT, crypto/sha256, encoding/json, go/ast, go/parser, go/token,
	internal/godebug, math/rand, encoding/hex
	< internal/fuzz;

	OS, flag, testing, internal/cfg, internal/platform, internal/goroot
	< internal/testenv;

	OS, encoding/base64
	< internal/obscuretestdata;

	CGO, OS, fmt
	< internal/testpty;

	NET, testing, math/rand
	< golang.org/x/net/nettest;

	syscall
	< os/exec/internal/fdtest;

	FMT, sort
	< internal/diff;

	FMT
	< internal/txtar;

	CRYPTO-MATH, testing, internal/testenv, encoding/json
	< crypto/internal/cryptotest;

	CGO, FMT
	< crypto/internal/sysrand/internal/seccomp;

	FIPS
	< crypto/internal/fips140/check/checktest;

	# v2 execution trace parser.
	FMT
	< internal/trace/event;

	internal/trace/event
	< internal/trace/event/go122;

	FMT, io, internal/trace/event/go122
	< internal/trace/version;

	FMT, encoding/binary, internal/trace/version
	< internal/trace/raw;

	FMT, internal/trace/event, internal/trace/version, io, sort, encoding/binary
	< internal/trace/internal/oldtrace;

	FMT, encoding/binary, internal/trace/version, internal/trace/internal/oldtrace, container/heap, math/rand
	< internal/trace;

	regexp, internal/trace, internal/trace/raw, internal/txtar
	< internal/trace/testtrace;

	regexp, internal/txtar, internal/trace, internal/trace/raw
	< internal/trace/internal/testgen/go122;

	# cmd/trace dependencies.
	FMT,
	embed,
	encoding/json,
	html/template,
	internal/profile,
	internal/trace,
	internal/trace/traceviewer/format,
	net/http
	< internal/trace/traceviewer;

	# Coverage.
	FMT, hash/fnv, encoding/binary, regexp, sort, text/tabwriter,
	internal/coverage, internal/coverage/uleb128
	< internal/coverage/cmerge,
	  internal/coverage/pods,
	  internal/coverage/slicereader,
	  internal/coverage/slicewriter;

	internal/coverage/slicereader, internal/coverage/slicewriter
	< internal/coverage/stringtab
	< internal/coverage/decodecounter, internal/coverage/decodemeta,
	  internal/coverage/encodecounter, internal/coverage/encodemeta;

	internal/coverage/cmerge
	< internal/coverage/cformat;

	internal/coverage, crypto/sha256, FMT
	< cmd/internal/cov/covcmd;

	encoding/json,
	runtime/debug,
	internal/coverage/calloc,
	internal/coverage/cformat,
	internal/coverage/decodecounter, internal/coverage/decodemeta,
	internal/coverage/encodecounter, internal/coverage/encodemeta,
	internal/coverage/pods
	< internal/coverage/cfile
	< runtime/coverage;

	internal/coverage/cfile, internal/fuzz, internal/testlog, runtime/pprof, regexp
	< testing/internal/testdeps;

	# Test-only packages can have anything they want
	CGO, internal/syscall/unix < net/internal/cgotest;


`

// listStdPkgs returns the same list of packages as "go list std".
func listStdPkgs(goroot string) ([]string, error) {
	// Based on cmd/go's matchPackages function.
	var pkgs []string

	src := filepath.Join(goroot, "src") + string(filepath.Separator)
	walkFn := func(path string, d fs.DirEntry, err error) error {
		if err != nil || !d.IsDir() || path == src {
			return nil
		}

		base := filepath.Base(path)
		if strings.HasPrefix(base, ".") || strings.HasPrefix(base, "_") || base == "testdata" {
			return filepath.SkipDir
		}

		name := filepath.ToSlash(path[len(src):])
		if name == "builtin" || name == "cmd" {
			return filepath.SkipDir
		}

		pkgs = append(pkgs, strings.TrimPrefix(name, "vendor/"))
		return nil
	}
	if err := filepath.WalkDir(src, walkFn); err != nil {
		return nil, err
	}
	return pkgs, nil
}

func TestDependencies(t *testing.T) {
	testenv.MustHaveSource(t)

	ctxt := Default
	all, err := listStdPkgs(ctxt.GOROOT)
	if err != nil {
		t.Fatal(err)
	}
	slices.Sort(all)

	sawImport := map[string]map[string]bool{} // from package => to package => true
	policy := depsPolicy(t)

	for _, pkg := range all {
		imports, err := findImports(pkg)
		if err != nil {
			t.Error(err)
			continue
		}
		if sawImport[pkg] == nil {
			sawImport[pkg] = map[string]bool{}
		}
		var bad []string
		for _, imp := range imports {
			sawImport[pkg][imp] = true
			if !policy.HasEdge(pkg, imp) {
				bad = append(bad, imp)
			}
		}
		if bad != nil {
			t.Errorf("unexpected dependency: %s imports %v", pkg, bad)
		}
	}
}

var buildIgnore = []byte("\n//go:build ignore")

func findImports(pkg string) ([]string, error) {
	vpkg := pkg
	if strings.HasPrefix(pkg, "golang.org") {
		vpkg = "vendor/" + pkg
	}
	dir := filepath.Join(Default.GOROOT, "src", vpkg)
	files, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var imports []string
	var haveImport = map[string]bool{}
	if pkg == "crypto/internal/boring" {
		haveImport["C"] = true // kludge: prevent C from appearing in crypto/internal/boring imports
	}
	fset := token.NewFileSet()
	for _, file := range files {
		name := file.Name()
		if name == "slice_go14.go" || name == "slice_go18.go" {
			// These files are for compiler bootstrap with older versions of Go and not built in the standard build.
			continue
		}
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		info := fileInfo{
			name: filepath.Join(dir, name),
			fset: fset,
		}
		f, err := os.Open(info.name)
		if err != nil {
			return nil, err
		}
		err = readGoInfo(f, &info)
		f.Close()
		if err != nil {
			return nil, fmt.Errorf("reading %v: %v", name, err)
		}
		if info.parsed.Name.Name == "main" {
			continue
		}
		if bytes.Contains(info.header, buildIgnore) {
			continue
		}
		for _, imp := range info.imports {
			path := imp.path
			if !haveImport[path] {
				haveImport[path] = true
				imports = append(imports, path)
			}
		}
	}
	slices.Sort(imports)
	return imports, nil
}

// depsPolicy returns a map m such that m[p][d] == true when p can import d.
func depsPolicy(t *testing.T) *dag.Graph {
	g, err := dag.Parse(depsRules)
	if err != nil {
		t.Fatal(err)
	}
	return g
}

// TestStdlibLowercase tests that all standard library package names are
// lowercase. See Issue 40065.
func TestStdlibLowercase(t *testing.T) {
	testenv.MustHaveSource(t)

	ctxt := Default
	all, err := listStdPkgs(ctxt.GOROOT)
	if err != nil {
		t.Fatal(err)
	}

	for _, pkgname := range all {
		if strings.ToLower(pkgname) != pkgname {
			t.Errorf("package %q should not use upper-case path", pkgname)
		}
	}
}

// TestFindImports tests that findImports works.  See #43249.
func TestFindImports(t *testing.T) {
	imports, err := findImports("go/build")
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("go/build imports %q", imports)
	want := []string{"bytes", "os", "path/filepath", "strings"}
wantLoop:
	for _, w := range want {
		for _, imp := range imports {
			if imp == w {
				continue wantLoop
			}
		}
		t.Errorf("expected to find %q in import list", w)
	}
}
```