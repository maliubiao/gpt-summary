Response:
Let's break down the thought process for analyzing this Go code snippet for Rust symbol demangling.

1. **Understand the Goal:** The file path `go/src/cmd/vendor/github.com/ianlancetaylor/demangle/rust.go` and the function name `rustToString` immediately suggest that this code is responsible for taking a mangled Rust symbol name and converting it into a human-readable form (demangling). The `vendor` directory indicates this is likely an external dependency vendored into a Go project, probably related to debugging or analysis tools.

2. **Identify the Core Function:** The `rustToString` function is clearly the entry point. It takes a mangled Rust symbol `name` (a string) and some `options`.

3. **Error Handling:** The `defer func() { ... }()` block suggests a panic/recover mechanism for handling errors during demangling. The `demangleErr` type confirms this.

4. **Input Validation:** The `strings.HasPrefix(name, "_R")` check suggests that Rust mangled symbols this code handles start with "_R". The `ErrNotMangledName` error confirms this.

5. **Suffix Handling:** The code looks for a "." in the name and separates it into a `suffix`. This likely handles versioning or other metadata appended to the core symbol name.

6. **State Management:** The `rustState` struct is crucial. It holds the state of the demangling process:
    * `orig`: The original mangled name.
    * `str`: The remaining part of the string to be processed.
    * `off`: The current offset.
    * `buf`: The `strings.Builder` where the demangled string is built.
    * `skip`: A flag to stop writing to the buffer (for length limiting).
    * `lifetimes`:  Likely related to Rust's lifetime annotations.
    * `last`: The last character written to the buffer (potentially for formatting).
    * `noGenericArgs`: An option to suppress generic argument demangling.
    * `max`: The maximum output length.

7. **Option Processing:** The loop iterating over `options` hints at configurable demangling behavior. `NoTemplateParams` and the `isMaxLength`/`maxLength` functions suggest options to control generic parameter display and output length. The `LLVMStyle` option influences how the suffix is handled.

8. **Parsing Logic:** The code then calls `rst.symbolName()`, which seems to be the starting point of the recursive descent parsing. The comments in functions like `symbolName`, `path`, `identifier`, `demangleType`, etc., are essential for understanding the grammar of the mangled names. Notice the use of characters like 'C', 'M', 'N', 'I' as markers for different parts of the Rust path and type system.

9. **Core Demangling Actions:**  Functions like `writeByte`, `writeString`, and the format string in `fmt.Fprintf` within the `N` namespace handling show how the demangled output is constructed.

10. **Backreferences:** The 'B' case in various parsing functions (`path`, `demangleType`, `demangleConst`) and the `backref` function strongly indicate that the mangling scheme uses backreferences for compression or to avoid repeating complex type information.

11. **Error Handling within Parsing:** The `rst.fail()` method is used extensively within the parsing functions to signal errors when the input doesn't match the expected format.

12. **Punycode Decoding:** The `expandPunycode` function reveals that Rust mangled names can contain Punycode-encoded identifiers, likely for handling Unicode characters.

13. **Old Mangling Scheme:** The `oldRustToString` function suggests that there's a legacy mangling scheme that this code also supports, indicated by the "_ZN" prefix. This part of the code uses a different parsing approach based on length-prefixed identifiers and escape sequences.

14. **Putting it Together (Inferring Functionality):** Based on the structure and the code, we can infer:
    * **Rust Symbol Demangling:** The primary function is to take a mangled Rust symbol name and produce a human-readable version.
    * **Handling Different Mangling Schemes:** The presence of `rustToString` and `oldRustToString` indicates support for at least two different mangling schemes.
    * **Options for Customization:** The `options` parameter allows users to control aspects like generic parameter display and output length.
    * **Error Handling:** The code gracefully handles invalid mangled names.
    * **Support for Complex Type Systems:** The parsing logic for paths, types, generic arguments, lifetimes, and constants reflects the complexity of Rust's type system.

15. **Example Generation Strategy:** To create examples, I would focus on:
    * **Basic Symbols:**  Simple function names.
    * **Symbols with Generics:**  Demonstrate how generic parameters are handled.
    * **Symbols with Lifetimes:** Show the demangling of lifetime annotations.
    * **Symbols with Paths:** Illustrate how module paths are represented.
    * **Symbols with the `LLVMStyle` option:** Show how the suffix is included.
    * **Symbols with `NoTemplateParams` option:** Show how generic parameters are suppressed.
    * **Invalid Symbols:** Demonstrate the error handling.

16. **Identifying Potential Pitfalls:** Based on the option handling and the different mangling schemes, I'd consider:
    * **Forgetting `LLVMStyle`:** Users might expect the suffix to always be present.
    * **Assuming the Correct Mangling Scheme:**  Users might try to demangle old-style symbols with the new demangler (or vice-versa).
    * **Length Limits:** Users might not realize the output can be truncated.

This detailed breakdown demonstrates how to approach analyzing code like this: start with the big picture, identify key components, understand the flow of execution, and then delve into the details of the parsing logic. The comments in the code are invaluable for this process.
这段代码是 Go 语言实现的一部分，用于**将 Rust 语言的符号名称从其 mangled (编码) 形式转换回人类可读的形式**，这个过程被称为 **demangling**。

更具体地说，它实现了 Rust 语言新的符号 mangling 方案的 demangling。

以下是它的主要功能：

1. **`rustToString(name string, options []Option) (ret string, err error)`:**
   - 这是 demangling 的入口函数。
   - 它接收一个字符串 `name`，即被 mangled 的 Rust 符号名称。
   - 它接收一个 `options` 切片，用于配置 demangling 的行为（例如，是否显示泛型参数，最大输出长度等）。
   - 它首先检查 `name` 是否以 "_R" 开头，这是 Rust 新 mangling 方案的标志。如果不是，则返回 `ErrNotMangledName` 错误。
   - 它使用 `defer` 和 `recover` 来捕获 demangling 过程中可能发生的 `demangleErr` 类型的 panic，并将其转换为普通的 `error` 返回。
   - 它会处理符号名称中可能存在的后缀（例如，".llvm.7915142723881930117"），并根据 `LLVMStyle` 选项决定是否将其添加到 demangled 后的字符串中。
   - 它创建了一个 `rustState` 结构体来维护 demangling 的状态。
   - 它根据 `options` 设置 `rustState` 的 `noGenericArgs` 和 `max` 字段。
   - 它调用 `rst.symbolName()` 开始实际的 demangling 过程。
   - 最后，它返回 demangled 后的字符串 `s` 和可能发生的错误 `err`。

2. **`rustState` 结构体:**
   - 这是一个状态机，用于在 demangling 过程中跟踪当前的解析状态。
   - 它包含原始的 mangled 字符串 (`orig`)，当前待解析的字符串片段 (`str`)，当前偏移量 (`off`)，用于构建 demangled 字符串的 `strings.Builder` (`buf`)，一个用于跳过输出的标志 (`skip`)，绑定生命周期的数量 (`lifetimes`)，最后写入缓冲区的字节 (`last`)，以及控制泛型参数显示和最大输出长度的选项。

3. **解析函数 (例如 `symbolName`, `path`, `identifier`, `demangleType` 等):**
   - 这些函数根据 Rust 符号 mangling 的语法规则，递归地解析 mangled 字符串。
   - 它们使用 `rst.advance()` 来移动解析位置，`rst.checkChar()` 来检查下一个字符是否符合预期，`rst.writeByte()` 和 `rst.writeString()` 来构建 demangled 后的字符串。
   - 它们处理各种 Rust 语言构造的 mangled 形式，例如 crate 根，impl 块，trait 实现，命名空间，泛型参数，类型，生命周期，函数签名，动态 trait 对象等等。

4. **辅助函数 (例如 `base62Number`, `decimalNumber`, `expandPunycode`):**
   - 这些函数用于解析 mangled 字符串中使用的特定编码格式，例如 base62 编码的数字，十进制数字，以及 Punycode 编码的标识符。

5. **`oldRustToString(name string, options []Option) (string, bool)`:**
   - 这是一个处理 **旧版 Rust 符号 mangling 方案** 的 demangling 函数。
   - 它检查符号是否以 "_ZN" 开头，这是旧版 mangling 方案的标志。
   - 它使用一种不同的解析逻辑，基于长度前缀的标识符和转义序列。
   - 它返回 demangled 后的字符串和一个布尔值，指示是否是一个有效的旧版 Rust mangled 名称。

**可以推理出它是什么 Go 语言功能的实现：**

根据代码结构和功能，可以推断出这是 **Go 语言的 `go tool nm` 命令或者类似调试/分析工具** 中用于解析 Rust 符号名称的部分实现。这些工具需要能够理解不同语言编译产生的符号，以便进行符号解析、回溯跟踪等操作。

**Go 代码示例：**

假设我们有一个 mangled 的 Rust 符号名称 `_RNvNtNtCrateEmodEfunction.llvm.7915142723881930117`。我们可以使用 `rustToString` 函数对其进行 demangle：

```go
package main

import (
	"fmt"
	"github.com/ianlancetaylor/demangle"
)

func main() {
	mangledName := "_RNvNtNtCrateEmodEfunction.llvm.7915142723881930117"
	demangledName, err := demangle.RustToString(mangledName, nil)
	if err != nil {
		fmt.Println("Demangling error:", err)
		return
	}
	fmt.Println("Demangled name:", demangledName)

	// 使用带选项的 demangle
	mangledName2 := "_RINvNtCrateEmodEgeneric_functionINtcorememManuallyDrop_u32_E.llvm.12345"
	demangledNameWithOptions, err := demangle.RustToString(mangledName2, []demangle.Option{demangle.NoTemplateParams, demangle.LLVMStyle})
	if err != nil {
		fmt.Println("Demangling error with options:", err)
		return
	}
	fmt.Println("Demangled name with options:", demangledNameWithOptions)
}
```

**假设的输入与输出：**

* **输入:** `_RNvNtNtCrateEmodEfunction.llvm.7915142723881930117`
* **输出:** `Crate::mod::function`

* **输入:** `_RINvNtCrateEmodEgeneric_functionINtcorememManuallyDrop_u32_E.llvm.12345`
* **不带选项输出:** `Crate::mod::generic_function<core::mem::ManuallyDrop<u32>>`
* **带 `NoTemplateParams` 选项输出:** `Crate::mod::generic_function`
* **带 `LLVMStyle` 选项输出:** `Crate::mod::generic_function (llvm.12345)`
* **带 `NoTemplateParams` 和 `LLVMStyle` 选项输出:** `Crate::mod::generic_function (llvm.12345)`

**命令行参数的具体处理：**

这段代码本身并没有直接处理命令行参数。它是一个库，提供 demangling 功能。具体的命令行参数处理应该在调用此库的工具中实现。

例如，如果 `go tool nm` 使用了这个库，它可能会有类似 `--demangle` 或 `--rust-demangle` 这样的命令行参数来启用 Rust 符号的 demangling，并且可能还有其他参数来控制 demangling 的选项（例如，是否显示模板参数）。

**使用者易犯错的点：**

1. **混淆新旧 mangling 方案:**  使用者可能会尝试使用 `rustToString` 来 demangle 旧版的 Rust 符号（以 "_ZN" 开头），或者使用 `oldRustToString` 来 demangle 新版的符号，这会导致错误或者无法得到正确的 demangled 结果。

   **例子:**
   ```go
   package main

   import (
   	"fmt"
   	"github.com/ianlancetaylor/demangle"
   )

   func main() {
   	oldMangledName := "_ZN4core3fmt2_$LT$impl$u20$core..fmt..Debug$u20$for$u20$i32$GT$3fmt17h0e6c7657b656e9aE"
   	demangledNew, errNew := demangle.RustToString(oldMangledName, nil)
   	fmt.Printf("New demangler result: '%s', error: %v\n", demangledNew, errNew) // 可能会得到空字符串和 ErrNotMangledName

   	demangledOld, validOld := demangle.OldRustToString(oldMangledName, nil)
   	fmt.Printf("Old demangler result: '%s', valid: %v\n", demangledOld, validOld) // 应该能正确 demangle
   }
   ```

2. **忘记 `LLVMStyle` 选项:** 如果使用者期望 demangled 的符号包含 `.llvm.xxxxxxxxxxxxx` 这样的后缀，他们需要显式地传递 `demangle.LLVMStyle` 选项。否则，默认情况下后缀会被省略。

   **例子:**
   ```go
   package main

   import (
   	"fmt"
   	"github.com/ianlancetaylor/demangle"
   )

   func main() {
   	mangledName := "_RNvNtNtCrateEmodEfunction.llvm.7915142723881930117"
   	demangledWithoutStyle, _ := demangle.RustToString(mangledName, nil)
   	fmt.Println("Without LLVMStyle:", demangledWithoutStyle) // 输出: Crate::mod::function

   	demangledWithStyle, _ := demangle.RustToString(mangledName, []demangle.Option{demangle.LLVMStyle})
   	fmt.Println("With LLVMStyle:", demangledWithStyle)    // 输出: Crate::mod::function (llvm.7915142723881930117)
   }
   ```

3. **不理解 `NoTemplateParams` 选项的作用:**  使用者可能不清楚 `NoTemplateParams` 选项会省略泛型参数，导致他们误以为 demangling 失败或者结果不完整。

   **例子:**  (见上面的 Go 代码示例中的第二个 demangle 调用)

总而言之，这段代码的核心功能是实现了 Rust 语言符号名称的 demangling，支持新的和旧的 mangling 方案，并提供了一些选项来定制 demangling 的行为。使用者需要了解不同 mangling 方案的区别以及可用选项的作用，才能正确地使用这个库。

### 提示词
```
这是路径为go/src/cmd/vendor/github.com/ianlancetaylor/demangle/rust.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
```

### 源代码
```go
// Copyright 2021 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package demangle

import (
	"fmt"
	"math"
	"math/bits"
	"strings"
	"unicode/utf8"
)

// rustToString demangles a Rust symbol.
func rustToString(name string, options []Option) (ret string, err error) {
	if !strings.HasPrefix(name, "_R") {
		return "", ErrNotMangledName
	}

	// When the demangling routines encounter an error, they panic
	// with a value of type demangleErr.
	defer func() {
		if r := recover(); r != nil {
			if de, ok := r.(demangleErr); ok {
				ret = ""
				err = de
				return
			}
			panic(r)
		}
	}()

	suffix := ""
	dot := strings.Index(name, ".")
	if dot >= 0 {
		suffix = name[dot:]
		name = name[:dot]
	}

	name = name[2:]
	rst := &rustState{orig: name, str: name}

	for _, o := range options {
		if o == NoTemplateParams {
			rst.noGenericArgs = true
		} else if isMaxLength(o) {
			rst.max = maxLength(o)
		}
	}

	rst.symbolName()

	if len(rst.str) > 0 {
		rst.fail("unparsed characters at end of mangled name")
	}

	if suffix != "" {
		llvmStyle := false
		for _, o := range options {
			if o == LLVMStyle {
				llvmStyle = true
				break
			}
		}
		if llvmStyle {
			rst.skip = false
			rst.writeString(" (")
			rst.writeString(suffix)
			rst.writeByte(')')
		}
	}

	s := rst.buf.String()
	if rst.max > 0 && len(s) > rst.max {
		s = s[:rst.max]
	}
	return s, nil
}

// A rustState holds the current state of demangling a Rust string.
type rustState struct {
	orig          string          // the original string being demangled
	str           string          // remainder of string to demangle
	off           int             // offset of str within original string
	buf           strings.Builder // demangled string being built
	skip          bool            // don't print, just skip
	lifetimes     int64           // number of bound lifetimes
	last          byte            // last byte written to buffer
	noGenericArgs bool            // don't demangle generic arguments
	max           int             // maximum output length
}

// fail panics with demangleErr, to be caught in rustToString.
func (rst *rustState) fail(err string) {
	panic(demangleErr{err: err, off: rst.off})
}

// advance advances the current string offset.
func (rst *rustState) advance(add int) {
	if len(rst.str) < add {
		panic("internal error")
	}
	rst.str = rst.str[add:]
	rst.off += add
}

// checkChar requires that the next character in the string be c,
// and advances past it.
func (rst *rustState) checkChar(c byte) {
	if len(rst.str) == 0 || rst.str[0] != c {
		rst.fail("expected " + string(c))
	}
	rst.advance(1)
}

// writeByte writes a byte to the buffer.
func (rst *rustState) writeByte(c byte) {
	if rst.skip {
		return
	}
	if rst.max > 0 && rst.buf.Len() > rst.max {
		rst.skip = true
		return
	}
	rst.last = c
	rst.buf.WriteByte(c)
}

// writeString writes a string to the buffer.
func (rst *rustState) writeString(s string) {
	if rst.skip {
		return
	}
	if rst.max > 0 && rst.buf.Len() > rst.max {
		rst.skip = true
		return
	}
	if len(s) > 0 {
		rst.last = s[len(s)-1]
		rst.buf.WriteString(s)
	}
}

// symbolName parses:
//
//	<symbol-name> = "_R" [<decimal-number>] <path> [<instantiating-crate>]
//	<instantiating-crate> = <path>
//
// We've already skipped the "_R".
func (rst *rustState) symbolName() {
	if len(rst.str) < 1 {
		rst.fail("expected symbol-name")
	}

	if isDigit(rst.str[0]) {
		rst.fail("unsupported Rust encoding version")
	}

	rst.path(true)

	if len(rst.str) > 0 {
		rst.skip = true
		rst.path(false)
	}
}

// path parses:
//
//	<path> = "C" <identifier>                    // crate root
//	       | "M" <impl-path> <type>              // <T> (inherent impl)
//	       | "X" <impl-path> <type> <path>       // <T as Trait> (trait impl)
//	       | "Y" <type> <path>                   // <T as Trait> (trait definition)
//	       | "N" <namespace> <path> <identifier> // ...::ident (nested path)
//	       | "I" <path> {<generic-arg>} "E"      // ...<T, U> (generic args)
//	       | <backref>
//	<namespace> = "C"      // closure
//	            | "S"      // shim
//	            | <A-Z>    // other special namespaces
//	            | <a-z>    // internal namespaces
//
// needsSeparator is true if we need to write out :: for a generic;
// it is passed as false if we are in the middle of a type.
func (rst *rustState) path(needsSeparator bool) {
	if len(rst.str) < 1 {
		rst.fail("expected path")
	}
	switch c := rst.str[0]; c {
	case 'C':
		rst.advance(1)
		_, ident := rst.identifier()
		rst.writeString(ident)
	case 'M', 'X':
		rst.advance(1)
		rst.implPath()
		rst.writeByte('<')
		rst.demangleType()
		if c == 'X' {
			rst.writeString(" as ")
			rst.path(false)
		}
		rst.writeByte('>')
	case 'Y':
		rst.advance(1)
		rst.writeByte('<')
		rst.demangleType()
		rst.writeString(" as ")
		rst.path(false)
		rst.writeByte('>')
	case 'N':
		rst.advance(1)

		if len(rst.str) < 1 {
			rst.fail("expected namespace")
		}
		ns := rst.str[0]
		switch {
		case ns >= 'a' && ns <= 'z':
		case ns >= 'A' && ns <= 'Z':
		default:
			rst.fail("invalid namespace character")
		}
		rst.advance(1)

		rst.path(needsSeparator)

		dis, ident := rst.identifier()

		if ns >= 'A' && ns <= 'Z' {
			rst.writeString("::{")
			switch ns {
			case 'C':
				rst.writeString("closure")
			case 'S':
				rst.writeString("shim")
			default:
				rst.writeByte(ns)
			}
			if len(ident) > 0 {
				rst.writeByte(':')
				rst.writeString(ident)
			}
			if !rst.skip {
				fmt.Fprintf(&rst.buf, "#%d}", dis)
				rst.last = '}'
			}
		} else {
			rst.writeString("::")
			rst.writeString(ident)
		}
	case 'I':
		rst.advance(1)
		rst.path(needsSeparator)
		if needsSeparator {
			rst.writeString("::")
		}
		rst.writeByte('<')
		rst.genericArgs()
		rst.writeByte('>')
		rst.checkChar('E')
	case 'B':
		rst.backref(func() { rst.path(needsSeparator) })
	default:
		rst.fail("unrecognized letter in path")
	}
}

// implPath parses:
//
//	<impl-path> = [<disambiguator>] <path>
func (rst *rustState) implPath() {
	// This path is not part of the demangled string.
	hold := rst.skip
	rst.skip = true
	defer func() {
		rst.skip = hold
	}()

	rst.disambiguator()
	rst.path(false)
}

// identifier parses:
//
//	<identifier> = [<disambiguator>] <undisambiguated-identifier>
//
// It returns the disambiguator and the identifier.
func (rst *rustState) identifier() (int64, string) {
	dis := rst.disambiguator()
	ident, _ := rst.undisambiguatedIdentifier()
	return dis, ident
}

// disambiguator parses an optional:
//
//	<disambiguator> = "s" <base-62-number>
func (rst *rustState) disambiguator() int64 {
	if len(rst.str) == 0 || rst.str[0] != 's' {
		return 0
	}
	rst.advance(1)
	return rst.base62Number() + 1
}

// undisambiguatedIdentifier parses:
//
//	<undisambiguated-identifier> = ["u"] <decimal-number> ["_"] <bytes>
func (rst *rustState) undisambiguatedIdentifier() (id string, isPunycode bool) {
	isPunycode = false
	if len(rst.str) > 0 && rst.str[0] == 'u' {
		rst.advance(1)
		isPunycode = true
	}

	val := rst.decimalNumber()

	if len(rst.str) > 0 && rst.str[0] == '_' {
		rst.advance(1)
	}

	if len(rst.str) < val {
		rst.fail("not enough characters for identifier")
	}
	id = rst.str[:val]
	rst.advance(val)

	for i := 0; i < len(id); i++ {
		c := id[i]
		switch {
		case c >= '0' && c <= '9':
		case c >= 'A' && c <= 'Z':
		case c >= 'a' && c <= 'z':
		case c == '_':
		default:
			rst.fail("invalid character in identifier")
		}
	}

	if isPunycode {
		id = rst.expandPunycode(id)
	}

	return id, isPunycode
}

// expandPunycode decodes the Rust version of punycode.
// This algorithm is taken from RFC 3492 section 6.2.
func (rst *rustState) expandPunycode(s string) string {
	const (
		base        = 36
		tmin        = 1
		tmax        = 26
		skew        = 38
		damp        = 700
		initialBias = 72
		initialN    = 128
	)

	var (
		output   []rune
		encoding string
	)
	idx := strings.LastIndex(s, "_")
	if idx >= 0 {
		output = []rune(s[:idx])
		encoding = s[idx+1:]
	} else {
		encoding = s
	}

	i := 0
	n := initialN
	bias := initialBias

	pos := 0
	for pos < len(encoding) {
		oldI := i
		w := 1
		for k := base; ; k += base {
			if pos == len(encoding) {
				rst.fail("unterminated punycode")
			}

			var digit byte
			d := encoding[pos]
			pos++
			switch {
			case '0' <= d && d <= '9':
				digit = d - '0' + 26
			case 'A' <= d && d <= 'Z':
				digit = d - 'A'
			case 'a' <= d && d <= 'z':
				digit = d - 'a'
			default:
				rst.fail("invalid punycode digit")
			}

			i += int(digit) * w
			if i < 0 {
				rst.fail("punycode number overflow")
			}

			var t int
			if k <= bias {
				t = tmin
			} else if k > bias+tmax {
				t = tmax
			} else {
				t = k - bias
			}

			if int(digit) < t {
				break
			}

			if w >= math.MaxInt32/base {
				rst.fail("punycode number overflow")
			}
			w *= base - t
		}

		delta := i - oldI
		numPoints := len(output) + 1
		firstTime := oldI == 0
		if firstTime {
			delta /= damp
		} else {
			delta /= 2
		}
		delta += delta / numPoints
		k := 0
		for delta > ((base-tmin)*tmax)/2 {
			delta /= base - tmin
			k += base
		}
		bias = k + ((base-tmin+1)*delta)/(delta+skew)

		n += i / (len(output) + 1)
		if n > utf8.MaxRune {
			rst.fail("punycode rune overflow")
		} else if !utf8.ValidRune(rune(n)) {
			rst.fail("punycode invalid code point")
		}
		i %= len(output) + 1
		output = append(output, 0)
		copy(output[i+1:], output[i:])
		output[i] = rune(n)
		i++
	}

	return string(output)
}

// genericArgs prints a list of generic arguments, without angle brackets.
func (rst *rustState) genericArgs() {
	if rst.noGenericArgs {
		hold := rst.skip
		rst.skip = true
		defer func() {
			rst.skip = hold
		}()
	}

	first := true
	for len(rst.str) > 0 && rst.str[0] != 'E' {
		if first {
			first = false
		} else {
			rst.writeString(", ")
		}
		rst.genericArg()
	}
}

// genericArg parses:
//
//	<generic-arg> = <lifetime>
//	              | <type>
//	              | "K" <const> // forward-compat for const generics
//	<lifetime> = "L" <base-62-number>
func (rst *rustState) genericArg() {
	if len(rst.str) < 1 {
		rst.fail("expected generic-arg")
	}
	if rst.str[0] == 'L' {
		rst.advance(1)
		rst.writeLifetime(rst.base62Number())
	} else if rst.str[0] == 'K' {
		rst.advance(1)
		rst.demangleConst()
	} else {
		rst.demangleType()
	}
}

// binder parses an optional:
//
//	<binder> = "G" <base-62-number>
func (rst *rustState) binder() {
	if len(rst.str) < 1 || rst.str[0] != 'G' {
		return
	}
	rst.advance(1)

	binderLifetimes := rst.base62Number() + 1

	// Every bound lifetime should be referenced later.
	if binderLifetimes >= int64(len(rst.str))-rst.lifetimes {
		rst.fail("binder lifetimes overflow")
	}

	rst.writeString("for<")
	for i := int64(0); i < binderLifetimes; i++ {
		if i > 0 {
			rst.writeString(", ")
		}
		rst.lifetimes++
		rst.writeLifetime(1)
	}
	rst.writeString("> ")
}

// demangleType parses:
//
//	<type> = <basic-type>
//	       | <path>                      // named type
//	       | "A" <type> <const>          // [T; N]
//	       | "S" <type>                  // [T]
//	       | "T" {<type>} "E"            // (T1, T2, T3, ...)
//	       | "R" [<lifetime>] <type>     // &T
//	       | "Q" [<lifetime>] <type>     // &mut T
//	       | "P" <type>                  // *const T
//	       | "O" <type>                  // *mut T
//	       | "F" <fn-sig>                // fn(...) -> ...
//	       | "D" <dyn-bounds> <lifetime> // dyn Trait<Assoc = X> + Send + 'a
//	       | <backref>
func (rst *rustState) demangleType() {
	if len(rst.str) < 1 {
		rst.fail("expected type")
	}
	c := rst.str[0]
	if c >= 'a' && c <= 'z' {
		rst.basicType()
		return
	}
	switch c {
	case 'C', 'M', 'X', 'Y', 'N', 'I':
		rst.path(false)
	case 'A', 'S':
		rst.advance(1)
		rst.writeByte('[')
		rst.demangleType()
		if c == 'A' {
			rst.writeString("; ")
			rst.demangleConst()
		}
		rst.writeByte(']')
	case 'T':
		rst.advance(1)
		rst.writeByte('(')
		c := 0
		for len(rst.str) > 0 && rst.str[0] != 'E' {
			if c > 0 {
				rst.writeString(", ")
			}
			c++
			rst.demangleType()
		}
		if c == 1 {
			rst.writeByte(',')
		}
		rst.writeByte(')')
		rst.checkChar('E')
	case 'R', 'Q':
		rst.advance(1)
		rst.writeByte('&')
		if len(rst.str) > 0 && rst.str[0] == 'L' {
			rst.advance(1)
			if lifetime := rst.base62Number(); lifetime > 0 {
				rst.writeLifetime(lifetime)
				rst.writeByte(' ')
			}
		}
		if c == 'Q' {
			rst.writeString("mut ")
		}
		rst.demangleType()
	case 'P':
		rst.advance(1)
		rst.writeString("*const ")
		rst.demangleType()
	case 'O':
		rst.advance(1)
		rst.writeString("*mut ")
		rst.demangleType()
	case 'F':
		rst.advance(1)
		hold := rst.lifetimes
		rst.fnSig()
		rst.lifetimes = hold
	case 'D':
		rst.advance(1)
		hold := rst.lifetimes
		rst.dynBounds()
		rst.lifetimes = hold
		if len(rst.str) == 0 || rst.str[0] != 'L' {
			rst.fail("expected L")
		}
		rst.advance(1)
		if lifetime := rst.base62Number(); lifetime > 0 {
			if rst.last != ' ' {
				rst.writeByte(' ')
			}
			rst.writeString("+ ")
			rst.writeLifetime(lifetime)
		}
	case 'B':
		rst.backref(rst.demangleType)
	default:
		rst.fail("unrecognized character in type")
	}
}

var rustBasicTypes = map[byte]string{
	'a': "i8",
	'b': "bool",
	'c': "char",
	'd': "f64",
	'e': "str",
	'f': "f32",
	'h': "u8",
	'i': "isize",
	'j': "usize",
	'l': "i32",
	'm': "u32",
	'n': "i128",
	'o': "u128",
	'p': "_",
	's': "i16",
	't': "u16",
	'u': "()",
	'v': "...",
	'x': "i64",
	'y': "u64",
	'z': "!",
}

// basicType parses:
//
//	<basic-type>
func (rst *rustState) basicType() {
	if len(rst.str) < 1 {
		rst.fail("expected basic type")
	}
	str, ok := rustBasicTypes[rst.str[0]]
	if !ok {
		rst.fail("unrecognized basic type character")
	}
	rst.advance(1)
	rst.writeString(str)
}

// fnSig parses:
//
//	<fn-sig> = [<binder>] ["U"] ["K" <abi>] {<type>} "E" <type>
//	<abi> = "C"
//	      | <undisambiguated-identifier>
func (rst *rustState) fnSig() {
	rst.binder()
	if len(rst.str) > 0 && rst.str[0] == 'U' {
		rst.advance(1)
		rst.writeString("unsafe ")
	}
	if len(rst.str) > 0 && rst.str[0] == 'K' {
		rst.advance(1)
		if len(rst.str) > 0 && rst.str[0] == 'C' {
			rst.advance(1)
			rst.writeString(`extern "C" `)
		} else {
			rst.writeString(`extern "`)
			id, isPunycode := rst.undisambiguatedIdentifier()
			if isPunycode {
				rst.fail("punycode used in ABI string")
			}
			id = strings.ReplaceAll(id, "_", "-")
			rst.writeString(id)
			rst.writeString(`" `)
		}
	}
	rst.writeString("fn(")
	first := true
	for len(rst.str) > 0 && rst.str[0] != 'E' {
		if first {
			first = false
		} else {
			rst.writeString(", ")
		}
		rst.demangleType()
	}
	rst.checkChar('E')
	rst.writeByte(')')
	if len(rst.str) > 0 && rst.str[0] == 'u' {
		rst.advance(1)
	} else {
		rst.writeString(" -> ")
		rst.demangleType()
	}
}

// dynBounds parses:
//
//	<dyn-bounds> = [<binder>] {<dyn-trait>} "E"
func (rst *rustState) dynBounds() {
	rst.writeString("dyn ")
	rst.binder()
	first := true
	for len(rst.str) > 0 && rst.str[0] != 'E' {
		if first {
			first = false
		} else {
			rst.writeString(" + ")
		}
		rst.dynTrait()
	}
	rst.checkChar('E')
}

// dynTrait parses:
//
//	<dyn-trait> = <path> {<dyn-trait-assoc-binding>}
//	<dyn-trait-assoc-binding> = "p" <undisambiguated-identifier> <type>
func (rst *rustState) dynTrait() {
	started := rst.pathStartGenerics()
	for len(rst.str) > 0 && rst.str[0] == 'p' {
		rst.advance(1)
		if started {
			rst.writeString(", ")
		} else {
			rst.writeByte('<')
			started = true
		}
		id, _ := rst.undisambiguatedIdentifier()
		rst.writeString(id)
		rst.writeString(" = ")
		rst.demangleType()
	}
	if started {
		rst.writeByte('>')
	}
}

// pathStartGenerics is like path but if it sees an I to start generic
// arguments it won't close them. It reports whether it started generics.
func (rst *rustState) pathStartGenerics() bool {
	if len(rst.str) < 1 {
		rst.fail("expected path")
	}
	switch rst.str[0] {
	case 'I':
		rst.advance(1)
		rst.path(false)
		rst.writeByte('<')
		rst.genericArgs()
		rst.checkChar('E')
		return true
	case 'B':
		var started bool
		rst.backref(func() { started = rst.pathStartGenerics() })
		return started
	default:
		rst.path(false)
		return false
	}
}

// writeLifetime writes out a lifetime binding.
func (rst *rustState) writeLifetime(lifetime int64) {
	rst.writeByte('\'')
	if lifetime == 0 {
		rst.writeByte('_')
		return
	}
	depth := rst.lifetimes - lifetime
	if depth < 0 {
		rst.fail("invalid lifetime")
	} else if depth < 26 {
		rst.writeByte('a' + byte(depth))
	} else {
		rst.writeByte('z')
		if !rst.skip {
			fmt.Fprintf(&rst.buf, "%d", depth-26+1)
			rst.last = '0'
		}
	}
}

// demangleConst parses:
//
//	<const> = <type> <const-data>
//	        | "p" // placeholder, shown as _
//	        | <backref>
//	<const-data> = ["n"] {<hex-digit>} "_"
func (rst *rustState) demangleConst() {
	if len(rst.str) < 1 {
		rst.fail("expected constant")
	}

	if rst.str[0] == 'B' {
		rst.backref(rst.demangleConst)
		return
	}

	if rst.str[0] == 'p' {
		rst.advance(1)
		rst.writeByte('_')
		return
	}

	typ := rst.str[0]

	const (
		invalid = iota
		signedInt
		unsignedInt
		boolean
		character
	)

	var kind int
	switch typ {
	case 'a', 's', 'l', 'x', 'n', 'i':
		kind = signedInt
	case 'h', 't', 'm', 'y', 'o', 'j':
		kind = unsignedInt
	case 'b':
		kind = boolean
	case 'c':
		kind = character
	default:
		rst.fail("unrecognized constant type")
	}

	rst.advance(1)

	if kind == signedInt && len(rst.str) > 0 && rst.str[0] == 'n' {
		rst.advance(1)
		rst.writeByte('-')
	}

	start := rst.str
	digits := 0
	val := uint64(0)
digitLoop:
	for len(rst.str) > 0 {
		c := rst.str[0]
		var digit uint64
		switch {
		case c >= '0' && c <= '9':
			digit = uint64(c - '0')
		case c >= 'a' && c <= 'f':
			digit = uint64(c - 'a' + 10)
		case c == '_':
			rst.advance(1)
			break digitLoop
		default:
			rst.fail("expected hex digit or _")
		}
		rst.advance(1)
		if val == 0 && digit == 0 && (len(rst.str) == 0 || rst.str[0] != '_') {
			rst.fail("invalid leading 0 in constant")
		}
		val *= 16
		val += digit
		digits++
	}

	if digits == 0 {
		rst.fail("expected constant")
	}

	switch kind {
	case signedInt, unsignedInt:
		if digits > 16 {
			// Value too big, just write out the string.
			rst.writeString("0x")
			rst.writeString(start[:digits])
		} else {
			if !rst.skip {
				fmt.Fprintf(&rst.buf, "%d", val)
				rst.last = '0'
			}
		}
	case boolean:
		if digits > 1 {
			rst.fail("boolean value too large")
		} else if val == 0 {
			rst.writeString("false")
		} else if val == 1 {
			rst.writeString("true")
		} else {
			rst.fail("invalid boolean value")
		}
	case character:
		if digits > 6 {
			rst.fail("character value too large")
		}
		rst.writeByte('\'')
		if val == '\t' {
			rst.writeString(`\t`)
		} else if val == '\r' {
			rst.writeString(`\r`)
		} else if val == '\n' {
			rst.writeString(`\n`)
		} else if val == '\\' {
			rst.writeString(`\\`)
		} else if val == '\'' {
			rst.writeString(`\'`)
		} else if val >= ' ' && val <= '~' {
			// printable ASCII character
			rst.writeByte(byte(val))
		} else {
			if !rst.skip {
				fmt.Fprintf(&rst.buf, `\u{%x}`, val)
				rst.last = '}'
			}
		}
		rst.writeByte('\'')
	default:
		panic("internal error")
	}
}

// base62Number parses:
//
//	<base-62-number> = {<0-9a-zA-Z>} "_"
func (rst *rustState) base62Number() int64 {
	if len(rst.str) > 0 && rst.str[0] == '_' {
		rst.advance(1)
		return 0
	}
	val := int64(0)
	for len(rst.str) > 0 {
		c := rst.str[0]
		rst.advance(1)
		if c == '_' {
			return val + 1
		}
		val *= 62
		if c >= '0' && c <= '9' {
			val += int64(c - '0')
		} else if c >= 'a' && c <= 'z' {
			val += int64(c - 'a' + 10)
		} else if c >= 'A' && c <= 'Z' {
			val += int64(c - 'A' + 36)
		} else {
			rst.fail("invalid digit in base 62 number")
		}
	}
	rst.fail("expected _ after base 62 number")
	return 0
}

// backref parses:
//
//	<backref> = "B" <base-62-number>
func (rst *rustState) backref(demangle func()) {
	backoff := rst.off

	rst.checkChar('B')
	idx64 := rst.base62Number()

	if rst.skip {
		return
	}
	if rst.max > 0 && rst.buf.Len() > rst.max {
		return
	}

	idx := int(idx64)
	if int64(idx) != idx64 {
		rst.fail("backref index overflow")
	}
	if idx < 0 || idx >= backoff {
		rst.fail("invalid backref index")
	}

	holdStr := rst.str
	holdOff := rst.off
	rst.str = rst.orig[idx:backoff]
	rst.off = idx
	defer func() {
		rst.str = holdStr
		rst.off = holdOff
	}()

	demangle()
}

func (rst *rustState) decimalNumber() int {
	if len(rst.str) == 0 {
		rst.fail("expected number")
	}

	val := 0
	for len(rst.str) > 0 && isDigit(rst.str[0]) {
		add := int(rst.str[0] - '0')
		if val >= math.MaxInt32/10-add {
			rst.fail("decimal number overflow")
		}
		val *= 10
		val += add
		rst.advance(1)
	}
	return val
}

// oldRustToString demangles a Rust symbol using the old demangling.
// The second result reports whether this is a valid Rust mangled name.
func oldRustToString(name string, options []Option) (string, bool) {
	max := 0
	for _, o := range options {
		if isMaxLength(o) {
			max = maxLength(o)
		}
	}

	// We know that the string starts with _ZN.
	name = name[3:]

	hexDigit := func(c byte) (byte, bool) {
		switch {
		case c >= '0' && c <= '9':
			return c - '0', true
		case c >= 'a' && c <= 'f':
			return c - 'a' + 10, true
		default:
			return 0, false
		}
	}

	// We know that the strings end with "17h" followed by 16 characters
	// followed by "E". We check that the 16 characters are all hex digits.
	// Also the hex digits must contain at least 5 distinct digits.
	seen := uint16(0)
	for i := len(name) - 17; i < len(name)-1; i++ {
		digit, ok := hexDigit(name[i])
		if !ok {
			return "", false
		}
		seen |= 1 << digit
	}
	if bits.OnesCount16(seen) < 5 {
		return "", false
	}
	name = name[:len(name)-20]

	// The name is a sequence of length-preceded identifiers.
	var sb strings.Builder
	for len(name) > 0 {
		if max > 0 && sb.Len() > max {
			break
		}

		if !isDigit(name[0]) {
			return "", false
		}

		val := 0
		for len(name) > 0 && isDigit(name[0]) {
			add := int(name[0] - '0')
			if val >= math.MaxInt32/10-add {
				return "", false
			}
			val *= 10
			val += add
			name = name[1:]
		}

		// An optional trailing underscore can separate the
		// length from the identifier.
		if len(name) > 0 && name[0] == '_' {
			name = name[1:]
			val--
		}

		if len(name) < val {
			return "", false
		}

		id := name[:val]
		name = name[val:]

		if sb.Len() > 0 {
			sb.WriteString("::")
		}

		// Ignore leading underscores preceding escape sequences.
		if strings.HasPrefix(id, "_$") {
			id = id[1:]
		}

		// The identifier can have escape sequences.
	escape:
		for len(id) > 0 {
			switch c := id[0]; c {
			case '$':
				codes := map[string]byte{
					"SP": '@',
					"BP": '*',
					"RF": '&',
					"LT": '<',
					"GT": '>',
					"LP": '(',
					"RP": ')',
				}

				valid := true
				if len(id) > 2 && id[1] == 'C' && id[2] == '$' {
					sb.WriteByte(',')
					id = id[3:]
				} else if len(id) > 4 && id[1] == 'u' && id[4] == '$' {
					dig1, ok1 := hexDigit(id[2])
					dig2, ok2 := hexDigit(id[3])
					val := (dig1 << 4) | dig2
					if !ok1 || !ok2 || dig1 > 7 || val < ' ' {
						valid = false
					} else {
						sb.WriteByte(val)
						id = id[5:]
					}
				} else if len(id) > 3 && id[3] == '$' {
					if code, ok := codes[id[1:3]]; !ok {
						valid = false
					} else {
						sb.WriteByte(code)
						id = id[4:]
					}
				} else {
					valid = false
				}
				if !valid {
					sb.WriteString(id)
					break escape
				}
			case '.':
				if strings.HasPrefix(id, "..") {
					sb.WriteString("::")
					id = id[2:]
				} else {
					sb.WriteByte(c)
					id = id[1:]
				}
			default:
				sb.WriteByte(c)
				id = id[1:]
			}
		}
	}

	s := sb.String()
	if max > 0 && len(s) > max {
		s = s[:max]
	}
	return s, true
}
```