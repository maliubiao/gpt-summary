Response: The user wants to understand the functionality of the Go code snippet provided, which is located in `go/src/cmd/internal/obj/fips140.go`.

Here's a breakdown of the thought process to answer the request:

1. **Understand the Purpose:** The initial comments clearly state the goal: FIPS-140 verification support. This immediately suggests that the code is related to ensuring the integrity of cryptographic code within the Go runtime.

2. **Identify Key Concepts:**  The comments mention "power-on self-test," "HMAC-SHA256," "code+data," and "build-time HMAC-SHA256." These are the core elements of the FIPS-140 verification mechanism being implemented. The code aims to detect corruption of cryptographic code at startup.

3. **Analyze Major Sections:** The comments are organized into sections with headings. This provides a good structure for understanding the code's functionality.

    * **FIPS Symbol Types:** This section explains how specific symbol types (`STEXTFIPS`, `SRODATAFIPS`, etc.) are used to mark code and data belonging to the FIPS-validated cryptographic module. The key function here is `setFIPSType`, which converts standard symbol types to these FIPS-specific types.

    * **Relocation Restrictions:** This part highlights the constraint that load-time relocations are problematic because they modify code/data after the build-time hash is calculated. The function `checkFIPSReloc` is responsible for enforcing this restriction.

    * **FIPS and Non-FIPS Symbols:** This clarifies the scope of the FIPS verification, explaining why certain symbols (wrappers, runtime support) are excluded.

    * **Debugging:**  This section introduces the `bisect` tool for debugging FIPS symbol issues, and the `SetFIPSDebugHash` function.

    * **Link-Time Hashing:** This acknowledges that the actual hash generation is handled elsewhere.

4. **Focus on Key Functions:**  The comments explicitly mention `setFIPSType` and `checkFIPSReloc`. These are the most crucial functions to understand for the core functionality.

5. **Explain Functionality of `setFIPSType`:**
    * This function is called whenever a symbol's type is set.
    * It checks if FIPS is enabled and if the symbol belongs to a FIPS package (based on the package path).
    * It has logic to exclude certain symbols even within FIPS packages (like runtime metadata, wrappers).
    * It converts the symbol's type to the corresponding FIPS type (e.g., `STEXT` to `STEXTFIPS`).
    * It integrates with the `bisect` tool for debugging.

6. **Illustrate `setFIPSType` with Go Code:**  A simple example can demonstrate how a symbol's type changes based on whether it's in a FIPS package. This requires making assumptions about the `Link` context and symbol name.

7. **Explain Functionality of `checkFIPSReloc`:**
    * This function is called for every relocation applied to a symbol.
    * It only performs checks when building with `-buildmode=pie` (shared libraries) because that's where load-time relocations become an issue.
    * It allows certain "pseudo-relocations."
    * It prohibits all relocations for FIPS data symbols.
    * For FIPS code symbols, it only allows PC-relative relocations.

8. **Illustrate `checkFIPSReloc` with Go Code:**  An example showing a valid PC-relative relocation and an invalid absolute relocation for a FIPS code symbol would be helpful. Again, assumptions about the `Link` context and relocation types are needed.

9. **Address Command-Line Parameters:**  The code mentions `-buildmode=pie` and `-d=fipshash=pattern`. Explain their role in the FIPS context.

10. **Identify Potential Pitfalls:**  The comments themselves point out a key pitfall: load-time relocations invalidating the hash. Explain this with a concrete example involving global variable initialization.

11. **Structure the Answer:** Organize the information logically, starting with a general overview, then detailing the functions, providing code examples, explaining command-line parameters, and concluding with potential pitfalls. Use clear headings and formatting for readability.

12. **Review and Refine:**  Read through the generated answer to ensure accuracy, clarity, and completeness. Make sure the code examples are easy to understand and the explanations are concise. For instance, initially, I might not have explicitly linked the prohibition of `R_ADDR` relocations to the global variable initialization problem. Reviewing the comments helps connect these pieces of information.
`go/src/cmd/internal/obj/fips140.go` 的主要功能是支持 Go 语言在构建过程中集成 FIPS-140 (Federal Information Processing Standard Publication 140) 的合规性检查。它主要关注于确保被标记为 FIPS 模块一部分的代码和数据在运行时没有被篡改。

以下是其功能的详细列表：

1. **标记 FIPS 代码和数据段：**
   - 它定义了特殊的符号类型，如 `STEXTFIPS`, `SRODATAFIPS`, `SNOPTRDATAFIPS`, `SDATAFIPS`。
   - 当链接器处理 `crypto/internal/fips140` 包及其子包中的符号时，`setFIPSType` 函数会将标准的符号类型（如 `STEXT`, `SRODATA` 等）转换为这些 FIPS 特定的类型。
   - 这样做的好处是，链接器会将这些 FIPS 相关的代码和数据段分组在一起，方便后续的哈希计算。

2. **实施重定位限制：**
   - 为了确保运行时计算的哈希值与构建时计算的哈希值一致，FIPS 模块的代码和数据不能包含在加载时会修改它们的重定位。
   - `checkFIPSReloc` 函数用于检查应用于 FIPS 符号的重定位类型。
   - 当以 `-buildmode=pie`（生成位置无关可执行文件）模式构建时，它会拒绝某些类型的重定位（主要是绝对地址重定位），因为这些重定位会在运行时被加载器修改，从而导致哈希校验失败。

3. **区分 FIPS 和非 FIPS 符号：**
   - 该文件中的逻辑用于区分哪些代码和数据属于 FIPS 模块，哪些不属于。
   - 通常，`crypto/internal/fips140` 包及其子包中的所有符号都被认为是 FIPS 模块的一部分。
   - 但也有例外，例如函数包装器（如 `foo·f`）、运行时支持数据（如类型描述符、字典、栈映射等）即使在 FIPS 包中也不被视为 FIPS 模块的一部分，因为它们可能包含不允许的重定位。

4. **支持 FIPS 相关的调试：**
   - 提供了 `SetFIPSDebugHash` 函数，允许通过 `bisect` 工具进行调试。
   - 通过设置 `-d=fipshash=pattern` 编译选项，可以根据符号名来控制哪些 FIPS 符号被特殊处理，从而帮助定位 FIPS 相关的问题。

5. **启用/禁用 FIPS 的控制：**
   - `EnableFIPS` 函数根据当前的 GOOS 和 GOARCH 配置来决定是否启用 FIPS 支持。
   - 例如，在 `wasm` 架构上，FIPS 默认是被禁用的。在某些 Windows 和 AIX 平台上也被禁用，因为其 `-buildmode=pie` 的实现方式与 FIPS 的要求不兼容。

**它是什么 go 语言功能的实现？**

这个文件是 Go 语言构建工具链中用于支持 FIPS-140 验证功能的一部分。具体来说，它与链接器（`cmd/link`）和对象文件格式（`cmd/obj`）相关联。它通过自定义符号类型和重定位检查，来确保在运行时对 FIPS 模块的代码和数据进行完整性验证。这种验证是在 `crypto/internal/fips140/check` 包的 `init` 函数中完成的，该函数会重新计算 FIPS 代码和数据的哈希值，并与构建时存储的哈希值进行比较。

**Go 代码举例说明：**

假设我们有以下简单的 Go 代码在 `crypto/internal/fips140/internal/dummyfips` 包中：

```go
package dummyfips

var FIPSData = []byte("fips data")

func FIPSFunction() int {
	return 42
}
```

当编译这个包时，`obj/fips140.go` 中的 `setFIPSType` 函数会被调用，并且：

- `FIPSData` 对应的符号类型可能会从 `objabi.SDATA` 变为 `objabi.SDATAFIPS`。
- `FIPSFunction` 对应的符号类型可能会从 `objabi.STEXT` 变为 `objabi.STEXTFIPS`。

以下代码展示了 `setFIPSType` 函数如何根据包路径和符号类型来修改符号的类型（这只是概念性的演示，实际调用发生在编译器的内部）：

```go
package main

import (
	"cmd/internal/obj"
	"cmd/internal/objabi"
	"strings"
	"fmt"
)

type MockLink struct {
	Pkgpath string
}

func (l *MockLink) IsFIPS() bool {
	return strings.HasPrefix(l.Pkgpath, "crypto/internal/fips140")
}

type MockLSym struct {
	Name      string
	Type      objabi.SymbolType
	Attribute SymbolAttribute // 假设有这个结构体
}

func (s *MockLSym) setFIPSType(ctxt *MockLink) {
	if !enableFIPS {
		return
	}
	if strings.HasSuffix(ctxt.Pkgpath, "_test") {
		return
	}
	if strings.HasPrefix(ctxt.Pkgpath, "crypto/internal/fips140") {
		switch s.Type {
		case objabi.STEXT:
			s.Type = objabi.STEXTFIPS
		case objabi.SDATA:
			s.Type = objabi.SDATAFIPS
		// ... 其他类型的转换
		}
	}
}

func main() {
	linkFIPS := &MockLink{Pkgpath: "crypto/internal/fips140/internal/dummyfips"}
	linkNonFIPS := &MockLink{Pkgpath: "mypackage"}

	symTextFIPS := &MockLSym{Name: "dummyfips.FIPSFunction", Type: objabi.STEXT}
	symDataFIPS := &MockLSym{Name: "dummyfips.FIPSData", Type: objabi.SDATA}
	symTextNonFIPS := &MockLSym{Name: "mypackage.MyFunction", Type: objabi.STEXT}

	symTextFIPS.setFIPSType(linkFIPS)
	symDataFIPS.setFIPSType(linkFIPS)
	symTextNonFIPS.setFIPSType(linkNonFIPS)

	fmt.Printf("FIPS Function Type: %v\n", symTextFIPS.Type)      // Output: obj.STEXTFIPS
	fmt.Printf("FIPS Data Type: %v\n", symDataFIPS.Type)          // Output: obj.SDATAFIPS
	fmt.Printf("Non-FIPS Function Type: %v\n", symTextNonFIPS.Type) // Output: obj.STEXT
}
```

**假设的输入与输出：**

在上面的例子中，假设输入是两个不同包的符号及其初始类型。输出是经过 `setFIPSType` 处理后的符号类型。

**命令行参数的具体处理：**

该文件本身不直接处理命令行参数，但它会受到构建过程中的一些标志的影响：

- **`-buildmode=pie`**:  当使用此标志构建位置无关可执行文件时，`checkFIPSReloc` 函数会更加严格地检查重定位。这是因为 PIE 二进制文件中的某些重定位是在加载时执行的，如果这些重定位修改了 FIPS 模块的代码或数据，就会导致哈希校验失败。
- **`-d=fipshash=pattern`**: 这是一个 `-d` 调试标志，用于控制 FIPS 相关的调试。`SetFIPSDebugHash` 函数会解析这个模式，并将其存储在 `bisectFIPS` 变量中。`bisect` 工具可以利用这个模式来缩小导致 FIPS 问题的特定符号的范围。例如，如果 `go test strings` 失败，可以使用 `bisect -compile=fips go test strings`，并通过 `-d=fipshash=特定符号名` 来逐步调试。

**使用者易犯错的点：**

使用者在开发涉及 FIPS 的 Go 代码时，可能会遇到以下容易犯错的点：

1. **在 FIPS 代码中使用不允许的全局变量初始化方式：**
   - **错误示例：**
     ```go
     package myfips

     import _ "crypto/internal/fips140/check"

     var globalArray = [...]int{1, 2, 3}
     var globalSlice = globalArray[:] // 错误：这会导致加载时重定位

     func F() int {
         return globalSlice[0]
     }
     ```
   - **原因：** 上述代码中 `globalSlice` 的初始化会产生一个需要在加载时填充 `&globalArray` 地址的重定位。由于 FIPS 模块需要在初始化时进行哈希校验，这种加载时修改会导致校验失败。
   - **解决方法：** 将初始化移动到 `init` 函数中，确保在 FIPS 哈希校验之后进行初始化。
     ```go
     package myfips

     import _ "crypto/internal/fips140/check"

     var globalArray = [...]int{1, 2, 3}
     var globalSlice []int

     func init() {
         globalSlice = globalArray[:]
     }

     func F() int {
         return globalSlice[0]
     }
     ```

2. **在 FIPS 代码中嵌入包含绝对地址的数据：**
   - **错误示例：** 使用 `//go:embed` 指令嵌入的文件包含绝对路径或在链接时会被修改的内容。
   - **原因：** `//go:embed` 可能会在数据段中产生包含文件内容的符号，如果嵌入的内容包含了绝对路径或其他需要在加载时重定位的信息，就会破坏 FIPS 校验。
   - **解决方法：** 避免在 FIPS 代码中嵌入此类内容，或者确保嵌入的内容是位置无关的。

3. **误解 FIPS 模块的边界：**
   - 使用者可能会错误地认为整个 `crypto` 包都在 FIPS 的范围内。实际上，只有 `crypto/internal/fips140` 及其子包才是被 FIPS 验证的模块。例如，`crypto/sha256` 包本身不在 FIPS 模块内。

理解 `go/src/cmd/internal/obj/fips140.go` 的功能对于开发需要满足 FIPS-140 合规性的 Go 应用程序至关重要。它确保了在运行时能够验证关键的加密代码和数据的完整性，从而增强了安全性。

Prompt: 
```
这是路径为go/src/cmd/internal/obj/fips140.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，

"""
// Copyright 2024 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

/*
FIPS-140 Verification Support

# Overview

For FIPS-140 crypto certification, one of the requirements is that the
“cryptographic module” perform a power-on self-test that includes
verification of its code+data at startup, ostensibly to guard against
corruption. (Like most of FIPS, the actual value here is as questionable
as it is non-negotiable.) Specifically, at startup we need to compute
an HMAC-SHA256 of the cryptographic code+data and compare it against a
build-time HMAC-SHA256 that has been stored in the binary as well.
This obviously guards against accidental corruption only, not attacks.

We could compute an HMAC-SHA256 of the entire binary, but that's more
startup latency than we'd like. (At 500 MB/s, a large 50MB binary
would incur a 100ms hit.) Also, as we'll see, there are some
limitations imposed on the code+data being hashed, and it's nice to
restrict those to the actual cryptographic packages.

# FIPS Symbol Types

Since we're not hashing the whole binary, we need to record the parts
of the binary that contain FIPS code, specifically the part of the
binary corresponding to the crypto/internal/fips140 package subtree.
To do that, we create special symbol types STEXTFIPS, SRODATAFIPS,
SNOPTRDATAFIPS, and SDATAFIPS, which those packages use instead of
STEXT, SRODATA, SNOPTRDATA, and SDATA. The linker groups symbols by
their type, so that naturally makes the FIPS parts contiguous within a
given type. The linker then writes out in a special symbol the start
and end of each of these FIPS-specific sections, alongside the
expected HMAC-SHA256 of them. At startup, the crypto/internal/fips140/check
package has an init function that recomputes the hash and checks it
against the recorded expectation.

The first important functionality in this file, then, is converting
from the standard symbol types to the FIPS symbol types, in the code
that needs them. Every time an LSym.Type is set, code must call
[LSym.setFIPSType] to update the Type to a FIPS type if appropriate.

# Relocation Restrictions

Of course, for the hashes to match, the FIPS code+data written by the
linker has to match the FIPS code+data in memory at init time.
This means that there cannot be an load-time relocations that modify
the FIPS code+data. In a standard -buildmode=exe build, that's vacuously
true, since those binaries have no load-time relocations at all.
For a -buildmode=pie build, there's more to be done.
Specifically, we have to make sure that all the relocations needed are
position-independent, so that they can be applied a link time with no
load-time component. For the code segment (the STEXTFIPS symbols),
that means only using PC-relative relocations. For the data segment,
that means basically having no relocations at all. In particular,
there cannot be R_ADDR relocations.

For example, consider the compilation of code like the global variables:

	var array = [...]int{10, 20, 30}
	var slice = array[:]

The standard implementation of these globals is to fill out the array
values in an SDATA symbol at link time, and then also to fill out the
slice header at link time as {nil, 3, 3}, along with a relocation to
fill in the first word of the slice header with the pointer &array at
load time, once the address of array is known.

A similar issue happens with:

	var slice = []int{10, 20, 30}

The compiler invents an anonymous array and then treats the code as in
the first example. In both cases, a load-time relocation applied
before the crypto/internal/fips140/check init function would invalidate
the hash. Instead, we disable the “link time initialization” optimizations
in the compiler (package staticinit) for the fips packages.
That way, the slice initialization is deferred to its own init function.
As long as the package in question imports crypto/internal/fips140/check,
the hash check will happen before the package's own init function
runs, and so the hash check will see the slice header written by the
linker, with a slice base pointer predictably nil instead of the
unpredictable &array address.

The details of disabling the static initialization appropriately are
left to the compiler (see ../../compile/internal/staticinit).
This file is only concerned with making sure that no hash-invalidating
relocations sneak into the object files. [LSym.checkFIPSReloc] is called
for every new relocation in a symbol in a FIPS package (as reported by
[Link.IsFIPS]) and rejects invalid relocations.

# FIPS and Non-FIPS Symbols

The cryptographic code+data must be included in the hash-verified
data. In general we accomplish that by putting all symbols from
crypto/internal/fips140/... packages into the hash-verified data.
But not all.

Note that wrapper code that layers a Go API atop the cryptographic
core is unverified. For example, crypto/internal/fips140/sha256 is part of
the FIPS module and verified but the crypto/sha256 package that wraps
it is outside the module and unverified. Also, runtime support like
the implementation of malloc and garbage collection is outside the
FIPS module. Again, only the core cryptographic code and data is in
scope for the verification.

By analogy with these cases, we treat function wrappers like foo·f
(the function pointer form of func foo) and runtime support data like
runtime type descriptors, generic dictionaries, stack maps, and
function argument data as being outside the FIPS module. That's
important because some of them need to be contiguous with other
non-FIPS data, and all of them include data relocations that would be
incompatible with the hash verification.

# Debugging

Bugs in the handling of FIPS symbols can be mysterious. It is very
helpful to narrow the bug down to a specific symbol that causes a
problem when treated as a FIPS symbol. Rather than work that out
manually, if “go test strings” is failing, then you can use

	go install golang.org/x/tools/cmd/bisect@latest
	bisect -compile=fips go test strings

to automatically bisect which symbol triggers the bug.

# Link-Time Hashing

The link-time hash preparation is out of scope for this file;
see ../../link/internal/ld/fips.go for those details.
*/

package obj

import (
	"cmd/internal/objabi"
	"fmt"
	"internal/bisect"
	"internal/buildcfg"
	"log"
	"os"
	"strings"
)

const enableFIPS = true

// IsFIPS reports whether we are compiling one of the crypto/internal/fips140/... packages.
func (ctxt *Link) IsFIPS() bool {
	if strings.HasSuffix(ctxt.Pkgpath, "_test") {
		// External test packages are outside the FIPS hash scope.
		// This allows them to use //go:embed, which would otherwise
		// emit absolute relocations in the global data.
		return false
	}
	return ctxt.Pkgpath == "crypto/internal/fips140" || strings.HasPrefix(ctxt.Pkgpath, "crypto/internal/fips140/")
}

// bisectFIPS controls bisect-based debugging of FIPS symbol assignment.
var bisectFIPS *bisect.Matcher

// SetFIPSDebugHash sets the bisect pattern for debugging FIPS changes.
// The compiler calls this with the pattern set by -d=fipshash=pattern,
// so that if FIPS symbol type conversions are causing problems,
// you can use 'bisect -compile fips go test strings' to identify exactly
// which symbol is not being handled correctly.
func SetFIPSDebugHash(pattern string) {
	m, err := bisect.New(pattern)
	if err != nil {
		log.Fatal(err)
	}
	bisectFIPS = m
}

// EnableFIPS reports whether FIPS should be enabled at all
// on the current buildcfg GOOS and GOARCH.
func EnableFIPS() bool {
	// WASM is out of scope; its binaries are too weird.
	// I'm not even sure it can read its own code.
	if buildcfg.GOARCH == "wasm" {
		return false
	}

	// CL 214397 added -buildmode=pie to windows-386
	// and made it the default, but the implementation is
	// not a true position-independent executable.
	// Instead, it writes tons of relocations into the executable
	// and leaves the loader to apply them to update the text
	// segment for the specific address where the code was loaded.
	// It should instead pass -shared to the compiler to get true
	// position-independent code, at which point FIPS verification
	// would work fine. FIPS verification does work fine on -buildmode=exe,
	// but -buildmode=pie is the default, so crypto/internal/fips140/check
	// would fail during all.bash if we enabled FIPS here.
	// Perhaps the default should be changed back to -buildmode=exe,
	// after which we could remove this case, but until then,
	// skip FIPS on windows-386.
	//
	// We don't know whether arm works, because it is too hard to get builder
	// time to test it. Disable since it's not important right now.
	if buildcfg.GOOS == "windows" {
		switch buildcfg.GOARCH {
		case "386", "arm":
			return false
		}
	}

	// AIX doesn't just work, and it's not worth fixing.
	if buildcfg.GOOS == "aix" {
		return false
	}

	return enableFIPS
}

// setFIPSType should be called every time s.Type is set or changed.
// It changes the type to one of the FIPS type (for example, STEXT -> STEXTFIPS) if appropriate.
func (s *LSym) setFIPSType(ctxt *Link) {
	if !EnableFIPS() {
		return
	}

	// External test packages are not in scope.
	if strings.HasSuffix(ctxt.Pkgpath, "_test") {
		return
	}

	if s.Attribute.Static() {
		// Static (file-scoped) symbol does not have name prefix,
		// but must be local to package; rely on whether package is FIPS.
		if !ctxt.IsFIPS() {
			return
		}
	} else {
		// Name must begin with crypto/internal/fips140, then dot or slash.
		// The quick check for 'c' before the string compare is probably overkill,
		// but this function is called a fair amount, and we don't want to
		// slow down all the non-FIPS compilations.
		const prefix = "crypto/internal/fips140"
		name := s.Name
		if len(name) <= len(prefix) || (name[len(prefix)] != '.' && name[len(prefix)] != '/') || name[0] != 'c' || name[:len(prefix)] != prefix {
			return
		}

		// Now we're at least handling a FIPS symbol.
		// It's okay to be slower now, since this code only runs when compiling a few packages.
		// Text symbols are always okay, since they can use PC-relative relocations,
		// but some data symbols are not.
		if s.Type != objabi.STEXT && s.Type != objabi.STEXTFIPS {
			// Even in the crypto/internal/fips140 packages,
			// we exclude various Go runtime metadata,
			// so that it can be allowed to contain data relocations.
			if strings.Contains(name, ".inittask") ||
				strings.Contains(name, ".dict") ||
				strings.Contains(name, ".typeAssert") ||
				strings.HasSuffix(name, ".arginfo0") ||
				strings.HasSuffix(name, ".arginfo1") ||
				strings.HasSuffix(name, ".argliveinfo") ||
				strings.HasSuffix(name, ".args_stackmap") ||
				strings.HasSuffix(name, ".opendefer") ||
				strings.HasSuffix(name, ".stkobj") ||
				strings.HasSuffix(name, "·f") {
				return
			}

			// This symbol is linknamed to go:fipsinfo,
			// so we shouldn't see it, but skip it just in case.
			if s.Name == "crypto/internal/fips140/check.linkinfo" {
				return
			}
		}
	}

	// This is a FIPS symbol! Convert its type to FIPS.

	// Allow hash-based bisect to override our decision.
	if bisectFIPS != nil {
		h := bisect.Hash(s.Name)
		if bisectFIPS.ShouldPrint(h) {
			fmt.Fprintf(os.Stderr, "%v %s (%v)\n", bisect.Marker(h), s.Name, s.Type)
		}
		if !bisectFIPS.ShouldEnable(h) {
			return
		}
	}

	switch s.Type {
	case objabi.STEXT:
		s.Type = objabi.STEXTFIPS
	case objabi.SDATA:
		s.Type = objabi.SDATAFIPS
	case objabi.SRODATA:
		s.Type = objabi.SRODATAFIPS
	case objabi.SNOPTRDATA:
		s.Type = objabi.SNOPTRDATAFIPS
	}
}

// checkFIPSReloc should be called for every relocation applied to s.
// It rejects absolute (non-PC-relative) address relocations when building
// with go build -buildmode=pie (which triggers the compiler's -shared flag),
// because those relocations will be applied before crypto/internal/fips140/check
// can hash-verify the FIPS code+data, which will make the verification fail.
func (s *LSym) checkFIPSReloc(ctxt *Link, rel Reloc) {
	if !ctxt.Flag_shared {
		// Writing a non-position-independent binary, so all the
		// relocations will be applied at link time, before we
		// calculate the expected hash. Anything goes.
		return
	}

	// Pseudo-relocations don't show up in code or data and are fine.
	switch rel.Type {
	case objabi.R_INITORDER,
		objabi.R_KEEP,
		objabi.R_USEIFACE,
		objabi.R_USEIFACEMETHOD,
		objabi.R_USENAMEDMETHOD:
		return
	}

	// Otherwise, any relocation we emit must be possible to handle
	// in the linker, meaning it has to be a PC-relative relocation
	// or a non-symbol relocation like a TLS relocation.

	// There are no PC-relative or TLS relocations in data. All data relocations are bad.
	if s.Type != objabi.STEXTFIPS {
		ctxt.Diag("%s: invalid relocation %v in fips data (%v)", s, rel.Type, s.Type)
		return
	}

	// In code, check that only PC-relative relocations are being used.
	// See ../objabi/reloctype.go comments for descriptions.
	switch rel.Type {
	case objabi.R_ADDRARM64, // used with ADRP+ADD, so PC-relative
		objabi.R_ADDRMIPS,  // used by adding to REGSB, so position-independent
		objabi.R_ADDRMIPSU, // used by adding to REGSB, so position-independent
		objabi.R_ADDRMIPSTLS,
		objabi.R_ADDROFF,
		objabi.R_ADDRPOWER_GOT,
		objabi.R_ADDRPOWER_GOT_PCREL34,
		objabi.R_ADDRPOWER_PCREL,
		objabi.R_ADDRPOWER_TOCREL,
		objabi.R_ADDRPOWER_TOCREL_DS,
		objabi.R_ADDRPOWER_PCREL34,
		objabi.R_ARM64_TLS_LE,
		objabi.R_ARM64_TLS_IE,
		objabi.R_ARM64_GOTPCREL,
		objabi.R_ARM64_GOT,
		objabi.R_ARM64_PCREL,
		objabi.R_ARM64_PCREL_LDST8,
		objabi.R_ARM64_PCREL_LDST16,
		objabi.R_ARM64_PCREL_LDST32,
		objabi.R_ARM64_PCREL_LDST64,
		objabi.R_CALL,
		objabi.R_CALLARM,
		objabi.R_CALLARM64,
		objabi.R_CALLIND,
		objabi.R_CALLLOONG64,
		objabi.R_CALLPOWER,
		objabi.R_GOTPCREL,
		objabi.R_LOONG64_ADDR_LO, // used with PC-relative load
		objabi.R_LOONG64_ADDR_HI, // used with PC-relative load
		objabi.R_LOONG64_TLS_LE_HI,
		objabi.R_LOONG64_TLS_LE_LO,
		objabi.R_LOONG64_TLS_IE_HI,
		objabi.R_LOONG64_TLS_IE_LO,
		objabi.R_LOONG64_GOT_HI,
		objabi.R_LOONG64_GOT_LO,
		objabi.R_JMP16LOONG64,
		objabi.R_JMP21LOONG64,
		objabi.R_JMPLOONG64,
		objabi.R_PCREL,
		objabi.R_PCRELDBL,
		objabi.R_POWER_TLS_LE,
		objabi.R_POWER_TLS_IE,
		objabi.R_POWER_TLS,
		objabi.R_POWER_TLS_IE_PCREL34,
		objabi.R_POWER_TLS_LE_TPREL34,
		objabi.R_RISCV_JAL,
		objabi.R_RISCV_PCREL_ITYPE,
		objabi.R_RISCV_PCREL_STYPE,
		objabi.R_RISCV_TLS_IE,
		objabi.R_RISCV_TLS_LE,
		objabi.R_RISCV_GOT_HI20,
		objabi.R_RISCV_PCREL_HI20,
		objabi.R_RISCV_PCREL_LO12_I,
		objabi.R_RISCV_PCREL_LO12_S,
		objabi.R_RISCV_BRANCH,
		objabi.R_RISCV_RVC_BRANCH,
		objabi.R_RISCV_RVC_JUMP,
		objabi.R_TLS_IE,
		objabi.R_TLS_LE,
		objabi.R_WEAKADDROFF:
		// ok
		return

	case objabi.R_ADDRPOWER,
		objabi.R_ADDRPOWER_DS,
		objabi.R_CALLMIPS,
		objabi.R_JMPMIPS:
		// NOT OK!
		//
		// These are all non-PC-relative but listed here to record that we
		// looked at them and decided explicitly that they aren't okay.
		// Don't add them to the list above.
	}
	ctxt.Diag("%s: invalid relocation %v in fips code", s, rel.Type)
}

"""



```