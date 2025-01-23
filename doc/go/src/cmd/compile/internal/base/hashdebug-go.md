Response:
Let's break down the thought process for analyzing the provided Go code snippet.

1. **Understanding the Goal:** The request asks for the functionality of the `hashdebug.go` file, specifically within the context of the Go compiler. The ultimate goal is to understand its purpose and how it's used for debugging.

2. **Initial Scan and Keyword Spotting:**  I'll quickly scan the code for keywords and patterns that hint at its purpose. Key terms that stand out are: `hash`, `debug`, `match`, `exclude`, `bisect`, `log`, `inline`, `pos`, `pkg`, `func`. These immediately suggest a debugging mechanism based on hashing, potentially to target specific code sections or execution paths.

3. **Identifying Core Data Structures:**  The `hashAndMask` struct and the `HashDebug` struct are crucial.

    * **`hashAndMask`:**  This looks like a way to define a matching rule. The `hash` and `mask` combination likely allows for prefix or suffix matching on hash values. The `name` is for identification.

    * **`HashDebug`:** This is the main structure. The mutex suggests thread safety. `name` is likely the name of the debug flag. `logfile` indicates logging. `matches` and `excludes` store matching/exclusion rules. `bisect` is a separate mechanism. `fileSuffixOnly` and `inlineSuffixOnly` are flags affecting how positions are handled.

4. **Analyzing Key Methods:**  I'll focus on the most important methods:

    * **`SetInlineSuffixOnly`:** This is straightforward – a setter for a boolean flag.

    * **Global `HashDebug` Variables:**  `hashDebug`, `FmaHash`, `LoopVarHash`, `PGOHash`, `MergeLocalsHash`. These strongly suggest that this debugging system is used for various specific compiler features or optimizations.

    * **`DebugHashMatchPkgFunc`:**  This is a central function. The docstring is very detailed and provides a clear explanation of how the `Gossahash` flag works. It handles various cases, including simple "y/n", suffix matching, and more complex include/exclude patterns. The logging behavior is also described. This function appears to be the primary interface for triggering debug behavior based on package and function names.

    * **`DebugHashMatchPos`:** Similar to `DebugHashMatchPkgFunc`, but operates on source code positions.

    * **`HasDebugHash`:** A simple check for whether the debug flag is set.

    * **`toHashAndMask`:** Converts a string (likely a binary representation) into a `hashAndMask`.

    * **`NewHashDebug`:**  The constructor for `HashDebug`. It handles parsing the debug flag value, supporting both the newer `bisect` approach and the older include/exclude pattern.

    * **`excluded` and `match`:**  These implement the logic for checking if a hash is excluded or matches a defined rule (within the older, non-bisect mechanism).

    * **`hashString`:** Converts a hash to its binary string representation.

    * **`MatchPkgFunc` and `matchPkgFunc`:** The public and private versions of the package/function matching logic, delegating to `matchAndLog`.

    * **`MatchPos`, `matchPos`, `matchPosWithInfo`:**  Similar to the package/function matching, but for source positions.

    * **`matchAndLog`:** The core matching and logging logic. It handles both the `bisect` and the older pattern matching.

    * **`short`:**  Handles shortening file paths based on the `fileSuffixOnly` flag.

    * **`hashPos`:** Calculates the hash of a source code position, taking inlining into account.

    * **`fmtPos`:** Formats a source code position into a string, including inlining information.

    * **`log`:**  Performs the actual logging, handling the `GSHS_LOGFILE` environment variable.

5. **Identifying the "Why":**  Based on the function names and the detailed explanation in `DebugHashMatchPkgFunc`, the primary purpose of this code is to enable **fine-grained debugging and testing within the Go compiler**. It allows developers to selectively enable or disable certain code paths or optimizations based on the hash of specific functions or source locations. This is extremely useful for:

    * **Isolating bugs:** When a compiler bug appears in a specific function or during the processing of a particular code section, this mechanism allows developers to target that area.
    * **A/B testing of compiler changes:** By using hashes, developers can compare the behavior of the compiler with and without a specific change for particular code snippets.
    * **Automated bug finding (using `gossahash`):** The integration with `gossahash` is a key aspect. This tool can automatically explore different hash combinations to pinpoint the exact code change or function responsible for a regression.
    * **Debugging inlining:** The position-based hashing is critical for debugging issues related to function inlining.

6. **Code Example and Assumptions:**  To illustrate the usage, I'll create a simple example demonstrating how `DebugHashMatchPkgFunc` could be used within the compiler. The assumptions are that the compiler has access to the `base` package and that the `Flags.Gossahash` variable is populated from the command-line `-d` flag.

7. **Command-Line Arguments:** I'll explain how the `-d=gossahash=...` flag would be used to set the `Flags.Gossahash` variable and how the different formats (y/n, suffix, include/exclude) work.

8. **Common Mistakes:** I'll think about potential pitfalls for users, focusing on the complexity of the include/exclude pattern and the need to rebuild the compiler.

9. **Review and Refine:** Finally, I'll review my analysis, ensuring that I've covered all aspects of the request and that the explanation is clear and accurate. I'll double-check the code examples and the explanation of the command-line arguments. I'll also ensure the identified functionalities directly map to the code provided.
`go/src/cmd/compile/internal/base/hashdebug.go` 文件的主要功能是提供一种基于哈希值的调试机制，用于在 Go 编译器的开发过程中，有选择地启用或禁用特定的代码路径。 这对于追踪难以复现的 bug，或者进行 A/B 测试非常有用。

下面列举其主要功能：

1. **基于哈希值的条件执行:**  核心功能是根据输入（可以是包名和函数名，也可以是源代码的位置信息）的哈希值，与预定义的模式进行匹配，从而决定是否执行特定的代码段。

2. **多种匹配模式:** 支持多种哈希匹配模式，包括：
   - 完全匹配：哈希值与预设的哈希值完全相同。
   - 后缀匹配：预设的字符串是哈希值的后缀。
   - 排除模式：哈希值与排除模式匹配，则不执行。
   - 基于位掩码的匹配：通过 `hashAndMask` 结构体，可以实现更灵活的位级别的匹配。

3. **支持包名/函数名哈希:**  `DebugHashMatchPkgFunc` 函数用于匹配包名和函数名的组合的哈希值。

4. **支持源代码位置哈希:** `DebugHashMatchPos` 函数用于匹配源代码位置（包括内联信息）的哈希值。

5. **灵活的配置方式:**  通过环境变量（例如 `Flags.Gossahash`）来配置哈希匹配的规则。

6. **日志记录:**  当哈希匹配成功时，可以将触发信息记录到指定的日志文件（通过环境变量 `GSHS_LOGFILE` 配置）或标准输出。 这有助于追踪哪些代码路径被哈希调试机制触发。

7. **与 `bisect` 包集成:**  集成了 `internal/bisect` 包，提供更高级的二分查找式的调试能力。

**它是什么Go语言功能的实现？**

这个文件实现的是一种**条件断点**或者更精确地说，是**条件执行**的机制，但它是基于哈希值的。 它可以看作是 Go 编译器开发者为了更精细地控制编译过程而创建的内部调试工具。  它不是 Go 语言本身的标准功能，而是 `cmd/compile` 工具链的一部分。

**Go 代码举例说明:**

假设我们在编译器的某个优化阶段，想要调试 `逃逸分析` 在处理 `pkg/example.MyFunction` 函数时的行为。  我们可以添加如下代码：

```go
package escape

import (
	"cmd/compile/internal/base"
	"cmd/compile/internal/ir"
)

func someOptimizationOnFunction(fn *ir.Func) {
	if !base.DebugHashMatchPkgFunc(fn.Sym().Pkg.Path, fn.Sym().Name) {
		return // 如果哈希不匹配，则跳过这段代码
	}
	// 哈希匹配，执行特定的调试逻辑
	println("Debugging escape analysis for:", fn.Sym().Pkg.Path, fn.Sym().Name)
	// ... 具体的调试代码 ...
}
```

**假设的输入与输出:**

假设我们设置了环境变量 `GOCOMPILEDEBUG=gossahash=abcdef` （这里 `abcdef` 是一个哈希值的后缀）。

- **输入:**  编译器正在编译 `pkg/example.MyFunction` 函数。 `base.DebugHashMatchPkgFunc("pkg/example", "MyFunction")` 被调用。
- **计算哈希:** `DebugHashMatchPkgFunc` 内部会计算 `"pkg/example.MyFunction"` 的 SHA1 哈希值，并将其转换为二进制字符串。 假设计算出的哈希值二进制表示为 `11001010101101101001111010abcdef`。
- **匹配:** 因为环境变量 `gossahash` 的值 `abcdef` 是计算出的哈希值的后缀，所以匹配成功。
- **输出:**  如果设置了 `GSHS_LOGFILE` 环境变量，则会在该文件中记录类似 `gossahash triggered pkg/example.MyFunction 11001010101101101001111010abcdef` 的信息。同时，`println` 语句会被执行，输出 `Debugging escape analysis for: pkg/example MyFunction`。

如果环境变量设置为 `GOCOMPILEDEBUG=gossahash=xyz`, 则由于 `xyz` 不是哈希值的后缀，匹配会失败，调试代码块将被跳过。

**命令行参数的具体处理:**

当 Go 编译器启动时，会解析 `-gcflags` 等命令行参数，其中 `-d` 标志用于设置调试变量。  例如：

```bash
go build -gcflags="-d=gossahash=101101" mypackage.go
```

这里，`-d=gossahash=101101`  告诉编译器设置 `base.hashDebug` 变量。 `NewHashDebug` 函数会被调用，解析字符串 `101101` 并将其转换为 `hashAndMask` 结构体，用于后续的哈希匹配。

`NewHashDebug` 函数的逻辑如下：

- 如果 `-d=gossahash=` 后面为空，则 `hashDebug` 为 `nil`，所有的 `DebugHashMatch...` 函数都会返回 `true`（相当于不启用任何哈希调试）。
- 如果 `-d=gossahash=y` 或 `-d=gossahash=Y`，`DebugHashMatch...` 函数总是返回 `true`。
- 如果 `-d=gossahash=n` 或 `-d=gossahash=N`，`DebugHashMatch...` 函数总是返回 `false`。
- 如果 `-d=gossahash=<binary_string>`，则会尝试将 `<binary_string>` 作为哈希值的后缀进行匹配。
- 更复杂的模式：可以使用斜杠 `/` 分隔包含和排除模式。  例如 `-d=gossahash=-101/010` 表示排除以 `101` 结尾的哈希，包含以 `010` 结尾的哈希。  可以有多个包含模式，并用数字后缀命名（例如 `gossahash0`, `gossahash1` 等）。

**使用者易犯错的点:**

1. **误解匹配规则的优先级:**  复杂的哈希匹配字符串（包含 `-` 排除和多个包含）可能会让使用者难以理解哪个规则会生效。  理解排除规则优先于包含规则很重要。

   **例子:**  如果 `GOCOMPILEDEBUG=gossahash=-101/101`，即使哈希值以 `101` 结尾，由于排除规则的存在，匹配仍然会失败。

2. **忘记重新编译:**  修改了包含 `base.DebugHashMatch...` 的代码后，或者更改了 `GOCOMPILEDEBUG` 环境变量，必须重新编译 Go 编译器，新的设置才会生效。

3. **哈希值计算的不确定性:**  虽然对于相同的输入，哈希值是确定的，但使用者可能不清楚编译器内部哈希是如何计算的，导致设置的匹配规则无法生效。  例如，对于 `DebugHashMatchPos`，内联信息会影响哈希值，如果内联策略发生变化，之前设置的哈希可能就不再匹配了。

4. **对 `bisect` 功能的不熟悉:**  当使用不带 `/` 的简单字符串时，实际上是在使用 `bisect` 包的功能，这与传统的哈希后缀匹配不同。使用者可能不理解这种二分查找式的调试机制。

总而言之，`hashdebug.go` 提供了一个强大但相对底层的调试工具，需要对编译器的内部机制和哈希匹配原理有一定的理解才能有效使用。

### 提示词
```
这是路径为go/src/cmd/compile/internal/base/hashdebug.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
```

### 源代码
```go
// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package base

import (
	"bytes"
	"cmd/internal/obj"
	"cmd/internal/src"
	"fmt"
	"internal/bisect"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
)

type hashAndMask struct {
	// a hash h matches if (h^hash)&mask == 0
	hash uint64
	mask uint64
	name string // base name, or base name + "0", "1", etc.
}

type HashDebug struct {
	mu   sync.Mutex // for logfile, posTmp, bytesTmp
	name string     // base name of the flag/variable.
	// what file (if any) receives the yes/no logging?
	// default is os.Stdout
	logfile          io.Writer
	posTmp           []src.Pos
	bytesTmp         bytes.Buffer
	matches          []hashAndMask // A hash matches if one of these matches.
	excludes         []hashAndMask // explicitly excluded hash suffixes
	bisect           *bisect.Matcher
	fileSuffixOnly   bool // for Pos hashes, remove the directory prefix.
	inlineSuffixOnly bool // for Pos hashes, remove all but the most inline position.
}

// SetInlineSuffixOnly controls whether hashing and reporting use the entire
// inline position, or just the most-inline suffix.  Compiler debugging tends
// to want the whole inlining, debugging user problems (loopvarhash, e.g.)
// typically does not need to see the entire inline tree, there is just one
// copy of the source code.
func (d *HashDebug) SetInlineSuffixOnly(b bool) *HashDebug {
	d.inlineSuffixOnly = b
	return d
}

// The default compiler-debugging HashDebug, for "-d=gossahash=..."
var hashDebug *HashDebug

var FmaHash *HashDebug         // for debugging fused-multiply-add floating point changes
var LoopVarHash *HashDebug     // for debugging shared/private loop variable changes
var PGOHash *HashDebug         // for debugging PGO optimization decisions
var MergeLocalsHash *HashDebug // for debugging local stack slot merging changes

// DebugHashMatchPkgFunc reports whether debug variable Gossahash
//
//  1. is empty (returns true; this is a special more-quickly implemented case of 4 below)
//
//  2. is "y" or "Y" (returns true)
//
//  3. is "n" or "N" (returns false)
//
//  4. does not explicitly exclude the sha1 hash of pkgAndName (see step 6)
//
//  5. is a suffix of the sha1 hash of pkgAndName (returns true)
//
//  6. OR
//     if the (non-empty) value is in the regular language
//     "(-[01]+/)+?([01]+(/[01]+)+?"
//     (exclude..)(....include...)
//     test the [01]+ exclude substrings, if any suffix-match, return false (4 above)
//     test the [01]+ include substrings, if any suffix-match, return true
//     The include substrings AFTER the first slash are numbered 0,1, etc and
//     are named fmt.Sprintf("%s%d", varname, number)
//     As an extra-special case for multiple failure search,
//     an excludes-only string ending in a slash (terminated, not separated)
//     implicitly specifies the include string "0/1", that is, match everything.
//     (Exclude strings are used for automated search for multiple failures.)
//     Clause 6 is not really intended for human use and only
//     matters for failures that require multiple triggers.
//
// Otherwise it returns false.
//
// Unless Flags.Gossahash is empty, when DebugHashMatchPkgFunc returns true the message
//
//	"%s triggered %s\n", varname, pkgAndName
//
// is printed on the file named in environment variable GSHS_LOGFILE,
// or standard out if that is empty.  "Varname" is either the name of
// the variable or the name of the substring, depending on which matched.
//
// Typical use:
//
//  1. you make a change to the compiler, say, adding a new phase
//
//  2. it is broken in some mystifying way, for example, make.bash builds a broken
//     compiler that almost works, but crashes compiling a test in run.bash.
//
//  3. add this guard to the code, which by default leaves it broken, but does not
//     run the broken new code if Flags.Gossahash is non-empty and non-matching:
//
//     if !base.DebugHashMatch(ir.PkgFuncName(fn)) {
//     return nil // early exit, do nothing
//     }
//
//  4. rebuild w/o the bad code,
//     GOCOMPILEDEBUG=gossahash=n ./all.bash
//     to verify that you put the guard in the right place with the right sense of the test.
//
//  5. use github.com/dr2chase/gossahash to search for the error:
//
//     go install github.com/dr2chase/gossahash@latest
//
//     gossahash -- <the thing that fails>
//
//     for example: GOMAXPROCS=1 gossahash -- ./all.bash
//
//  6. gossahash should return a single function whose miscompilation
//     causes the problem, and you can focus on that.
func DebugHashMatchPkgFunc(pkg, fn string) bool {
	return hashDebug.MatchPkgFunc(pkg, fn, nil)
}

func DebugHashMatchPos(pos src.XPos) bool {
	return hashDebug.MatchPos(pos, nil)
}

// HasDebugHash returns true if Flags.Gossahash is non-empty, which
// results in hashDebug being not-nil.  I.e., if !HasDebugHash(),
// there is no need to create the string for hashing and testing.
func HasDebugHash() bool {
	return hashDebug != nil
}

// TODO: Delete when we switch to bisect-only.
func toHashAndMask(s, varname string) hashAndMask {
	l := len(s)
	if l > 64 {
		s = s[l-64:]
		l = 64
	}
	m := ^(^uint64(0) << l)
	h, err := strconv.ParseUint(s, 2, 64)
	if err != nil {
		Fatalf("Could not parse %s (=%s) as a binary number", varname, s)
	}

	return hashAndMask{name: varname, hash: h, mask: m}
}

// NewHashDebug returns a new hash-debug tester for the
// environment variable ev.  If ev is not set, it returns
// nil, allowing a lightweight check for normal-case behavior.
func NewHashDebug(ev, s string, file io.Writer) *HashDebug {
	if s == "" {
		return nil
	}

	hd := &HashDebug{name: ev, logfile: file}
	if !strings.Contains(s, "/") {
		m, err := bisect.New(s)
		if err != nil {
			Fatalf("%s: %v", ev, err)
		}
		hd.bisect = m
		return hd
	}

	// TODO: Delete remainder of function when we switch to bisect-only.
	ss := strings.Split(s, "/")
	// first remove any leading exclusions; these are preceded with "-"
	i := 0
	for len(ss) > 0 {
		s := ss[0]
		if len(s) == 0 || len(s) > 0 && s[0] != '-' {
			break
		}
		ss = ss[1:]
		hd.excludes = append(hd.excludes, toHashAndMask(s[1:], fmt.Sprintf("%s%d", "HASH_EXCLUDE", i)))
		i++
	}
	// hash searches may use additional EVs with 0, 1, 2, ... suffixes.
	i = 0
	for _, s := range ss {
		if s == "" {
			if i != 0 || len(ss) > 1 && ss[1] != "" || len(ss) > 2 {
				Fatalf("Empty hash match string for %s should be first (and only) one", ev)
			}
			// Special case of should match everything.
			hd.matches = append(hd.matches, toHashAndMask("0", fmt.Sprintf("%s0", ev)))
			hd.matches = append(hd.matches, toHashAndMask("1", fmt.Sprintf("%s1", ev)))
			break
		}
		if i == 0 {
			hd.matches = append(hd.matches, toHashAndMask(s, ev))
		} else {
			hd.matches = append(hd.matches, toHashAndMask(s, fmt.Sprintf("%s%d", ev, i-1)))
		}
		i++
	}
	return hd
}

// TODO: Delete when we switch to bisect-only.
func (d *HashDebug) excluded(hash uint64) bool {
	for _, m := range d.excludes {
		if (m.hash^hash)&m.mask == 0 {
			return true
		}
	}
	return false
}

// TODO: Delete when we switch to bisect-only.
func hashString(hash uint64) string {
	hstr := ""
	if hash == 0 {
		hstr = "0"
	} else {
		for ; hash != 0; hash = hash >> 1 {
			hstr = string('0'+byte(hash&1)) + hstr
		}
	}
	if len(hstr) > 24 {
		hstr = hstr[len(hstr)-24:]
	}
	return hstr
}

// TODO: Delete when we switch to bisect-only.
func (d *HashDebug) match(hash uint64) *hashAndMask {
	for i, m := range d.matches {
		if (m.hash^hash)&m.mask == 0 {
			return &d.matches[i]
		}
	}
	return nil
}

// MatchPkgFunc returns true if either the variable used to create d is
// unset, or if its value is y, or if it is a suffix of the base-two
// representation of the hash of pkg and fn.  If the variable is not nil,
// then a true result is accompanied by stylized output to d.logfile, which
// is used for automated bug search.
func (d *HashDebug) MatchPkgFunc(pkg, fn string, note func() string) bool {
	if d == nil {
		return true
	}
	// Written this way to make inlining likely.
	return d.matchPkgFunc(pkg, fn, note)
}

func (d *HashDebug) matchPkgFunc(pkg, fn string, note func() string) bool {
	hash := bisect.Hash(pkg, fn)
	return d.matchAndLog(hash, func() string { return pkg + "." + fn }, note)
}

// MatchPos is similar to MatchPkgFunc, but for hash computation
// it uses the source position including all inlining information instead of
// package name and path.
// Note that the default answer for no environment variable (d == nil)
// is "yes", do the thing.
func (d *HashDebug) MatchPos(pos src.XPos, desc func() string) bool {
	if d == nil {
		return true
	}
	// Written this way to make inlining likely.
	return d.matchPos(Ctxt, pos, desc)
}

func (d *HashDebug) matchPos(ctxt *obj.Link, pos src.XPos, note func() string) bool {
	return d.matchPosWithInfo(ctxt, pos, nil, note)
}

func (d *HashDebug) matchPosWithInfo(ctxt *obj.Link, pos src.XPos, info any, note func() string) bool {
	hash := d.hashPos(ctxt, pos)
	if info != nil {
		hash = bisect.Hash(hash, info)
	}
	return d.matchAndLog(hash,
		func() string {
			r := d.fmtPos(ctxt, pos)
			if info != nil {
				r += fmt.Sprintf(" (%v)", info)
			}
			return r
		},
		note)
}

// MatchPosWithInfo is similar to MatchPos, but with additional information
// that is included for hash computation, so it can distinguish multiple
// matches on the same source location.
// Note that the default answer for no environment variable (d == nil)
// is "yes", do the thing.
func (d *HashDebug) MatchPosWithInfo(pos src.XPos, info any, desc func() string) bool {
	if d == nil {
		return true
	}
	// Written this way to make inlining likely.
	return d.matchPosWithInfo(Ctxt, pos, info, desc)
}

// matchAndLog is the core matcher. It reports whether the hash matches the pattern.
// If a report needs to be printed, match prints that report to the log file.
// The text func must be non-nil and should return a user-readable
// representation of what was hashed. The note func may be nil; if non-nil,
// it should return additional information to display to the user when this
// change is selected.
func (d *HashDebug) matchAndLog(hash uint64, text, note func() string) bool {
	if d.bisect != nil {
		enabled := d.bisect.ShouldEnable(hash)
		if d.bisect.ShouldPrint(hash) {
			disabled := ""
			if !enabled {
				disabled = " [DISABLED]"
			}
			var t string
			if !d.bisect.MarkerOnly() {
				t = text()
				if note != nil {
					if n := note(); n != "" {
						t += ": " + n + disabled
						disabled = ""
					}
				}
			}
			d.log(d.name, hash, strings.TrimSpace(t+disabled))
		}
		return enabled
	}

	// TODO: Delete rest of function body when we switch to bisect-only.
	if d.excluded(hash) {
		return false
	}
	if m := d.match(hash); m != nil {
		d.log(m.name, hash, text())
		return true
	}
	return false
}

// short returns the form of file name to use for d.
// The default is the full path, but fileSuffixOnly selects
// just the final path element.
func (d *HashDebug) short(name string) string {
	if d.fileSuffixOnly {
		return filepath.Base(name)
	}
	return name
}

// hashPos returns a hash of the position pos, including its entire inline stack.
// If d.inlineSuffixOnly is true, hashPos only considers the innermost (leaf) position on the inline stack.
func (d *HashDebug) hashPos(ctxt *obj.Link, pos src.XPos) uint64 {
	if d.inlineSuffixOnly {
		p := ctxt.InnermostPos(pos)
		return bisect.Hash(d.short(p.Filename()), p.Line(), p.Col())
	}
	h := bisect.Hash()
	ctxt.AllPos(pos, func(p src.Pos) {
		h = bisect.Hash(h, d.short(p.Filename()), p.Line(), p.Col())
	})
	return h
}

// fmtPos returns a textual formatting of the position pos, including its entire inline stack.
// If d.inlineSuffixOnly is true, fmtPos only considers the innermost (leaf) position on the inline stack.
func (d *HashDebug) fmtPos(ctxt *obj.Link, pos src.XPos) string {
	format := func(p src.Pos) string {
		return fmt.Sprintf("%s:%d:%d", d.short(p.Filename()), p.Line(), p.Col())
	}
	if d.inlineSuffixOnly {
		return format(ctxt.InnermostPos(pos))
	}
	var stk []string
	ctxt.AllPos(pos, func(p src.Pos) {
		stk = append(stk, format(p))
	})
	return strings.Join(stk, "; ")
}

// log prints a match with the given hash and textual formatting.
// TODO: Delete varname parameter when we switch to bisect-only.
func (d *HashDebug) log(varname string, hash uint64, text string) {
	d.mu.Lock()
	defer d.mu.Unlock()

	file := d.logfile
	if file == nil {
		if tmpfile := os.Getenv("GSHS_LOGFILE"); tmpfile != "" {
			var err error
			file, err = os.OpenFile(tmpfile, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)
			if err != nil {
				Fatalf("could not open hash-testing logfile %s", tmpfile)
				return
			}
		}
		if file == nil {
			file = os.Stdout
		}
		d.logfile = file
	}

	// Bisect output.
	fmt.Fprintf(file, "%s %s\n", text, bisect.Marker(hash))

	// Gossahash output.
	// TODO: Delete rest of function when we switch to bisect-only.
	fmt.Fprintf(file, "%s triggered %s %s\n", varname, text, hashString(hash))
}
```