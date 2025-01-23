Response: Let's break down the thought process for analyzing the provided Go code snippet.

1. **Understand the Goal:** The first step is to recognize that this code is a test file (`_test.go`) for a package related to building Go programs (`go/src/cmd/go/internal/work`). The filename `security_test.go` strongly suggests it's testing security aspects, specifically around compiler and linker flags.

2. **Identify Key Components:**  Scan the code for the core data structures and functions. We immediately see:
    * `goodCompilerFlags`: A slice of string slices, likely representing valid compiler flags.
    * `badCompilerFlags`:  A slice of string slices, likely representing *invalid* or *potentially dangerous* compiler flags.
    * `goodLinkerFlags`:  Similar to `goodCompilerFlags`, but for linker flags.
    * `badLinkerFlags`: Similar to `badCompilerFlags`, but for linker flags.
    * `TestCheckCompilerFlags(t *testing.T)`: A test function that iterates through `goodCompilerFlags` and `badCompilerFlags`, calling `checkCompilerFlags`.
    * `TestCheckLinkerFlags(t *testing.T)`: A similar test function for linker flags.
    * `TestCheckFlagAllowDisallow(t *testing.T)`: A test function involving environment variables `CGO_TEST_ALLOW` and `CGO_TEST_DISALLOW`.
    * `TestCheckCompilerFlagsForInternalLink(t *testing.T)`: A test function calling `checkCompilerFlagsForInternalLink`.

3. **Deduce Functionality of `checkCompilerFlags` and `checkLinkerFlags`:** Based on the test setup, it's highly likely that:
    * `checkCompilerFlags(pkgName, toolName, flags)` checks if the provided `flags` are valid and safe for the compiler. It probably returns an error if a flag is considered bad.
    * `checkLinkerFlags(pkgName, toolName, flags)` does the same for linker flags.

4. **Infer Functionality of `checkCompilerFlagsForInternalLink`:** The test `TestCheckCompilerFlagsForInternalLink` checks if certain flags trigger "external linking". This implies:
    * `checkCompilerFlagsForInternalLink(pkgName, toolName, flags)` checks if the given compiler flags would force the Go build process to use an external linker instead of the internal Go linker. This is often a security consideration or a performance optimization. The comments specifically mention `-flto` as a trigger.

5. **Analyze Test Cases:** Examine the specific flags in `goodCompilerFlags` and `badCompilerFlags`. This helps understand the criteria for good vs. bad. Look for patterns:
    * **Good Compiler Flags:**  Standard compiler options like `-D`, `-U`, `-I`, `-O`, `-W`, `-f...`, `-m...`, `-std`, `-x`. Notice the handling of flags with and without separate arguments (e.g., `{"-DFOO"}` vs. `{"-D", "FOO"}`).
    * **Bad Compiler Flags:**  Flags containing `@` or starting with `-` in places where they shouldn't (e.g., `"-D@X"`, `"-I-dir"`). This suggests a mechanism to prevent arbitrary paths or characters that could be used for malicious purposes.

6. **Analyze Test Cases for Linker Flags:**  Similar analysis for `goodLinkerFlags` and `badLinkerFlags`:
    * **Good Linker Flags:** `-F`, `-l`, `-L`, `-fpic`/`-fPIE` variations, `-Wl,...` (passing flags to the external linker), library names, framework options.
    * **Bad Linker Flags:** Many of the same "bad" patterns as compiler flags, plus some flags that are valid for compilers but not desirable/safe for linkers in this context (e.g., `-DFOO`, `-Wall`). Flags that might introduce unexpected linking behavior are also present (e.g., those with `@` in file paths or unexpected commas).

7. **Understand the `TestCheckFlagAllowDisallow` Logic:**  This test deals with environment variables. It suggests a mechanism to explicitly *allow* or *disallow* certain flags, overriding the default "good" and "bad" lists. The order of precedence (`DISALLOW` wins) is also important. The use of regular expressions (`-fplugin.*`) is worth noting.

8. **Formulate the Description:** Based on the above analysis, start structuring the description:
    * **Core Function:** Identify the main purpose of the code (security testing of compiler/linker flags).
    * **Key Functions:** Describe the role of `checkCompilerFlags`, `checkLinkerFlags`, and `checkCompilerFlagsForInternalLink`.
    * **Data Structures:** Explain the purpose of the `good...Flags` and `bad...Flags` slices.
    * **Inferred Functionality (with code examples):**  Provide examples of how these checking functions likely work, showcasing both valid and invalid flag scenarios and their expected outcomes.
    * **Command-line Argument Handling (CGO_...):** Explain how the environment variables `CGO_TEST_ALLOW` and `CGO_TEST_DISALLOW` are used to customize flag validation.
    * **Common Mistakes:** Identify potential pitfalls for users, focusing on scenarios where allowed/disallowed flags might lead to unexpected behavior.

9. **Refine and Review:**  Read through the description to ensure clarity, accuracy, and completeness. Check for any logical gaps or areas that could be explained more effectively. For example, initially, I might just say "checks compiler flags."  Refining this leads to "validates the safety and correctness of compiler flags...". Similarly, elaborating on "external linking" improves the explanation.

This methodical approach, combining code examination, pattern recognition, and logical deduction, allows for a comprehensive understanding of the code's purpose and functionality, even without having access to the implementation of the `check...Flags` functions themselves.
这段代码是 Go 语言 `cmd/go` 工具内部 `work` 包的一部分，专门用于 **安全地验证传递给 C/C++ 编译和链接器的标志 (flags)**。它旨在防止恶意或不安全的标志被传递，从而避免潜在的安全风险或构建问题。

以下是它的主要功能：

1. **定义了“好”的编译器标志列表 (`goodCompilerFlags`)**:  这个列表包含了被认为是安全且常见的编译器标志。例如：
    *  定义宏：`-DFOO`, `-Dfoo=bar`
    *  取消定义宏：`-Ufoo`
    *  指定头文件搜索路径：`-I/usr/include`, `-I.`
    *  优化级别：`-O`, `-O2`, `-Osmall`
    *  警告选项：`-W`, `-Wall`
    *  预处理器选项：`-Wp,-Dfoo=bar`
    *  代码生成选项：`-flto`, `-fobjc-arc`, `-fomit-frame-pointer` 等
    *  架构和 CPU 相关选项：`-march=souza`, `-mcpu=123` 等
    *  标准选项：`-std=c99`
    *  指定输入文件类型：`-xc`
    *  以及带空格分隔的标志：`-D FOO`, `-I .`

2. **定义了“坏”的编译器标志列表 (`badCompilerFlags`)**: 这个列表包含了被认为是不安全或可能导致问题的编译器标志。例如，包含 `@` 符号的标志，这可能允许执行任意命令或访问不应访问的文件：
    *  `-D@X`
    *  `-F@dir`
    *  `-I@dir`
    *  `-O@1`
    *  `-W@foo`
    *  `-g@gdb`
    *  `-march=@dawn`
    *  `-std=@c99`
    *  `-x@c`
    *  以及带空格分隔的类似标志。
    *  一些看似合法的但可能存在风险的标志，例如以 `-` 开头的参数值 `-I -foo`。

3. **定义了“好”的链接器标志列表 (`goodLinkerFlags`)**:  这个列表包含了被认为是安全且常见的链接器标志。例如：
    *  指定库文件搜索路径：`-Lbar`
    *  链接库文件：`-lbar`
    *  指定 Framework 路径：`-Fbar`
    *  传递选项给链接器：`-Wl,--hash-style=both`, `-Wl,-rpath,foo`
    *  指定要链接的库文件：`foo.so`, `libcgosotest.dylib`
    *  以及带空格分隔的标志：`-F framework`, `-l .`

4. **定义了“坏”的链接器标志列表 (`badLinkerFlags`)**:  这个列表包含了被认为是不安全或可能导致问题的链接器标志。  与编译器标志类似，包含 `@` 符号的标志是主要的禁止对象。同时，一些编译器标志也被列为不良的链接器标志。
    *  `-L @foo`
    *  `-Wl,-framework,@Home`
    *  `-Wl,-rpath,@foo`
    *  以及一些可能导致意外行为的标志，例如在 `-Wl,-R` 后缺少路径或者包含逗号分隔的多个路径等。

5. **`TestCheckCompilerFlags` 函数**:  这是一个测试函数，它遍历 `goodCompilerFlags` 和 `badCompilerFlags` 列表，并使用 `checkCompilerFlags` 函数来验证标志的安全性。
    *   对于 `goodCompilerFlags` 中的每个标志，它期望 `checkCompilerFlags` 不返回错误。
    *   对于 `badCompilerFlags` 中的每个标志，它期望 `checkCompilerFlags` 返回错误。

6. **`TestCheckLinkerFlags` 函数**: 类似于 `TestCheckCompilerFlags`，但用于验证链接器标志。

7. **`TestCheckFlagAllowDisallow` 函数**:  测试通过环境变量 `CGO_<TOOL>_ALLOW` 和 `CGO_<TOOL>_DISALLOW` 来允许或禁止特定标志的功能。这里的 `<TOOL>` 会被替换为测试函数名的大写形式，例如 "TEST"。
    *   它演示了如何使用这两个环境变量来覆盖默认的“好”和“坏”标志列表。
    *   `CGO_TEST_ALLOW` 用于允许通常被认为是“坏”的标志。
    *   `CGO_TEST_DISALLOW` 用于禁止通常被认为是“好”的标志。
    *   `CGO_TEST_DISALLOW` 的优先级高于 `CGO_TEST_ALLOW`。
    *   它还演示了可以使用正则表达式来匹配多个标志。

8. **`TestCheckCompilerFlagsForInternalLink` 函数**:  这个测试函数使用 `checkCompilerFlagsForInternalLink` 来判断给定的编译器标志是否会强制使用外部链接器。 通常，Go 工具链会尝试使用内部链接器以提高效率和安全性。某些编译器标志（例如 `-flto`，即链接时优化）可能需要外部链接器。  这个测试验证了 “坏” 的编译器标志以及 `-flto` 会触发外部链接。

**推断的 Go 语言功能实现：**

虽然没有给出 `checkCompilerFlags` 和 `checkLinkerFlags` 的具体实现，但我们可以推断它们的功能。它们很可能包含一系列的规则和模式匹配，用于检查给定的标志是否在白名单（`goodCompilerFlags` 和 `goodLinkerFlags`）中，或者是否匹配黑名单中的模式（例如包含 `@` 符号）。

**Go 代码示例（假设的 `checkCompilerFlags` 实现）：**

```go
package work

import (
	"fmt"
	"regexp"
	"strings"
)

var disallowedFlagChars = regexp.MustCompile(`[@-]`)

func checkCompilerFlags(pkgName, toolName string, flags []string) error {
	for _, flagSet := range flags {
		for _, flag := range strings.Split(flagSet, " ") { // 处理带空格的标志
			if strings.HasPrefix(flag, "-D") || strings.HasPrefix(flag, "-U") || strings.HasPrefix(flag, "-I") || strings.HasPrefix(flag, "-F") || strings.HasPrefix(flag, "-Wp,") || strings.HasPrefix(flag, "-x") {
				if disallowedFlagChars.MatchString(flag[2:]) { // 假设有前缀，从第三个字符开始检查
					return fmt.Errorf("compiler flag %q contains disallowed characters", flag)
				}
			} else if strings.HasPrefix(flag, "-g") || strings.HasPrefix(flag, "-march=") || strings.HasPrefix(flag, "-mcmodel=") || strings.HasPrefix(flag, "-std=") {
				if strings.Contains(flag, "@") || strings.HasPrefix(strings.SplitN(flag, "=", 2)[1], "-") {
					return fmt.Errorf("compiler flag %q contains disallowed patterns", flag)
				}
			} else if strings.HasPrefix(flag, "-f") {
				// 允许一些 -f 开头的标志，但可能需要更细致的检查
			}
			// ... 其他更详细的检查规则 ...
		}
	}
	return nil
}

func checkLinkerFlags(pkgName, toolName string, flags []string) error {
	for _, flagSet := range flags {
		for _, flag := range strings.Split(flagSet, " ") {
			if strings.HasPrefix(flag, "-L") || strings.HasPrefix(flag, "-F") || strings.HasPrefix(flag, "-Wl,") {
				if strings.Contains(flag, "@") {
					return fmt.Errorf("linker flag %q contains disallowed characters", flag)
				}
				if strings.HasPrefix(flag, "-Wl,-rpath,") && strings.HasSuffix(flag, ",") {
					return fmt.Errorf("linker flag %q ends with a comma", flag)
				}
			}
			// ... 其他链接器标志的检查规则 ...
		}
	}
	return nil
}

func checkCompilerFlagsForInternalLink(pkgName, toolName string, flags []string) error {
	for _, flagSet := range flags {
		for _, flag := range strings.Split(flagSet, " ") {
			if strings.HasPrefix(flag, "-flto") {
				return fmt.Errorf("compiler flag %q requires external linking", flag)
			}
			// 假设 "坏" 的编译器标志也会触发外部链接
			for _, badFlag := range badCompilerFlags {
				if len(badFlag) == 1 && badFlag[0] == flag { // 简单的字符串匹配
					return fmt.Errorf("compiler flag %q triggers external linking due to being a bad flag", flag)
				}
			}
		}
	}
	return nil
}
```

**假设的输入与输出：**

**`checkCompilerFlags` 示例：**

* **输入：** `pkgName = "mypackage"`, `toolName = "compile"`, `flags = []string{"-DDEBUG"}`
* **输出：** `nil` (没有错误，因为 `-DDEBUG` 是一个“好”的标志)

* **输入：** `pkgName = "mypackage"`, `toolName = "compile"`, `flags = []string{"-D@EVIL"}`
* **输出：** `error: compiler flag "-D@EVIL" contains disallowed characters`

**`checkLinkerFlags` 示例：**

* **输入：** `pkgName = "mypackage"`, `toolName = "link"`, `flags = []string{"-lm"}`
* **输出：** `nil` (没有错误，`-lm` 通常是安全的)

* **输入：** `pkgName = "mypackage"`, `toolName = "link"`, `flags = []string{"-L@/evil/path"}`
* **输出：** `error: linker flag "-L@/evil/path" contains disallowed characters`

**`checkCompilerFlagsForInternalLink` 示例：**

* **输入：** `pkgName = "mypackage"`, `toolName = "compile"`, `flags = []string{"-O2"}`
* **输出：** `nil` (没有错误，`-O2` 不会强制使用外部链接器)

* **输入：** `pkgName = "mypackage"`, `toolName = "compile"`, `flags = []string{"-flto"}`
* **输出：** `error: compiler flag "-flto" requires external linking`

* **输入：** `pkgName = "mypackage"`, `toolName = "compile"`, `flags = []string{"-D@EVIL"}`
* **输出：** `error: compiler flag "-D@EVIL" triggers external linking due to being a bad flag`

**命令行参数的具体处理：**

`TestCheckFlagAllowDisallow` 函数展示了如何通过环境变量来动态地允许或禁止标志。

* **`CGO_<TOOL>_ALLOW`**:  这个环境变量包含一个以空格分隔的允许标志的列表（可以使用正则表达式）。如果设置了这个变量，即使某个标志在 `badCompilerFlags` 或 `badLinkerFlags` 中，如果它匹配 `CGO_<TOOL>_ALLOW` 中的条目，那么它将被认为是允许的。
    * **示例：** `export CGO_TEST_ALLOW="-D@.*"`  会允许所有以 `-D@` 开头的编译器标志。
* **`CGO_<TOOL>_DISALLOW`**: 这个环境变量包含一个以空格分隔的禁止标志的列表（可以使用正则表达式）。如果设置了这个变量，即使某个标志在 `goodCompilerFlags` 或 `goodLinkerFlags` 中，如果它匹配 `CGO_<TOOL>_DISALLOW` 中的条目，那么它将被认为是禁止的。
    * **示例：** `export CGO_TEST_DISALLOW="-Wall"` 会禁止使用 `-Wall` 编译器标志。

**优先级：** `CGO_<TOOL>_DISALLOW` 的优先级高于 `CGO_<TOOL>_ALLOW`。如果一个标志同时匹配了 `ALLOW` 和 `DISALLOW` 列表，那么它将被禁止。

**使用者易犯错的点：**

1. **误解 `CGO_<TOOL>_ALLOW` 和 `CGO_<TOOL>_DISALLOW` 的作用域**: 这些环境变量只在 `go` 工具链的构建过程中起作用，特别是涉及到 C/C++ 代码编译和链接的场景（例如使用 `cgo`）。它们不会影响纯 Go 代码的编译。

2. **正则表达式的错误使用**:  `CGO_<TOOL>_ALLOW` 和 `CGO_<TOOL>_DISALLOW` 支持正则表达式，但如果正则表达式写得不正确，可能会导致意外地允许或禁止了不应该被允许或禁止的标志。 例如，如果想要允许所有以 `-fplugin=` 开头的标志，应该使用 `-fplugin=.*`，而不是 `-fplugin=*`。

3. **忘记 `DISALLOW` 优先级更高**:  如果同时设置了 `ALLOW` 和 `DISALLOW`，并且同一个标志匹配了两者，那么该标志将被禁止。用户可能会错误地认为 `ALLOW` 会覆盖 `DISALLOW`。

4. **假设“好”标志总是安全的**: 即使某个标志在 `goodCompilerFlags` 或 `goodLinkerFlags` 中，在特定的上下文下，它仍然可能引发问题。这些列表提供了一个基本的安全基线，但不能保证绝对安全。

总而言之，`security_test.go` 文件通过维护“好”和“坏”的编译器和链接器标志列表，并提供通过环境变量动态控制的能力，来增强 `go` 工具链的安全性，防止用户在构建过程中意外或恶意地引入不安全的构建选项。

### 提示词
```
这是路径为go/src/cmd/go/internal/work/security_test.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
```

### 源代码
```go
// Copyright 2018 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package work

import (
	"os"
	"strings"
	"testing"
)

var goodCompilerFlags = [][]string{
	{"-DFOO"},
	{"-Dfoo=bar"},
	{"-Ufoo"},
	{"-Ufoo1"},
	{"-F/Qt"},
	{"-F", "/Qt"},
	{"-I/"},
	{"-I/etc/passwd"},
	{"-I."},
	{"-O"},
	{"-O2"},
	{"-Osmall"},
	{"-W"},
	{"-Wall"},
	{"-Wp,-Dfoo=bar"},
	{"-Wp,-Ufoo"},
	{"-Wp,-Dfoo1"},
	{"-Wp,-Ufoo1"},
	{"-flto"},
	{"-fobjc-arc"},
	{"-fno-objc-arc"},
	{"-fomit-frame-pointer"},
	{"-fno-omit-frame-pointer"},
	{"-fpic"},
	{"-fno-pic"},
	{"-fPIC"},
	{"-fno-PIC"},
	{"-fpie"},
	{"-fno-pie"},
	{"-fPIE"},
	{"-fno-PIE"},
	{"-fsplit-stack"},
	{"-fno-split-stack"},
	{"-fstack-xxx"},
	{"-fno-stack-xxx"},
	{"-fsanitize=hands"},
	{"-ftls-model=local-dynamic"},
	{"-g"},
	{"-ggdb"},
	{"-march=souza"},
	{"-mcmodel=medium"},
	{"-mcpu=123"},
	{"-mfpu=123"},
	{"-mlarge-data-threshold=16"},
	{"-mtune=happybirthday"},
	{"-mstack-overflow"},
	{"-mno-stack-overflow"},
	{"-mmacosx-version"},
	{"-mnop-fun-dllimport"},
	{"-pthread"},
	{"-std=c99"},
	{"-xc"},
	{"-D", "FOO"},
	{"-D", "foo=bar"},
	{"-I", "."},
	{"-I", "/etc/passwd"},
	{"-I", "世界"},
	{"-I", "=/usr/include/libxml2"},
	{"-I", "dir"},
	{"-I", "$SYSROOT/dir"},
	{"-isystem", "/usr/include/mozjs-68"},
	{"-include", "/usr/include/mozjs-68/RequiredDefines.h"},
	{"-framework", "Chocolate"},
	{"-x", "c"},
	{"-v"},
}

var badCompilerFlags = [][]string{
	{"-D@X"},
	{"-D-X"},
	{"-Ufoo=bar"},
	{"-F@dir"},
	{"-F-dir"},
	{"-I@dir"},
	{"-I-dir"},
	{"-O@1"},
	{"-Wa,-foo"},
	{"-W@foo"},
	{"-Wp,-DX,-D@X"},
	{"-Wp,-UX,-U@X"},
	{"-g@gdb"},
	{"-g-gdb"},
	{"-march=@dawn"},
	{"-march=-dawn"},
	{"-mcmodel=@model"},
	{"-mlarge-data-threshold=@12"},
	{"-std=@c99"},
	{"-std=-c99"},
	{"-x@c"},
	{"-x-c"},
	{"-D", "@foo"},
	{"-D", "-foo"},
	{"-I", "@foo"},
	{"-I", "-foo"},
	{"-I", "=@obj"},
	{"-include", "@foo"},
	{"-framework", "-Caffeine"},
	{"-framework", "@Home"},
	{"-x", "--c"},
	{"-x", "@obj"},
}

func TestCheckCompilerFlags(t *testing.T) {
	for _, f := range goodCompilerFlags {
		if err := checkCompilerFlags("test", "test", f); err != nil {
			t.Errorf("unexpected error for %q: %v", f, err)
		}
	}
	for _, f := range badCompilerFlags {
		if err := checkCompilerFlags("test", "test", f); err == nil {
			t.Errorf("missing error for %q", f)
		}
	}
}

var goodLinkerFlags = [][]string{
	{"-Fbar"},
	{"-lbar"},
	{"-Lbar"},
	{"-fpic"},
	{"-fno-pic"},
	{"-fPIC"},
	{"-fno-PIC"},
	{"-fpie"},
	{"-fno-pie"},
	{"-fPIE"},
	{"-fno-PIE"},
	{"-fsanitize=hands"},
	{"-g"},
	{"-ggdb"},
	{"-march=souza"},
	{"-mcpu=123"},
	{"-mfpu=123"},
	{"-mtune=happybirthday"},
	{"-pic"},
	{"-pthread"},
	{"-Wl,--hash-style=both"},
	{"-Wl,-rpath,foo"},
	{"-Wl,-rpath,$ORIGIN/foo"},
	{"-Wl,-R", "/foo"},
	{"-Wl,-R", "foo"},
	{"-Wl,-R,foo"},
	{"-Wl,--just-symbols=foo"},
	{"-Wl,--just-symbols,foo"},
	{"-Wl,--warn-error"},
	{"-Wl,--no-warn-error"},
	{"foo.so"},
	{"_世界.dll"},
	{"./x.o"},
	{"libcgosotest.dylib"},
	{"-F", "framework"},
	{"-l", "."},
	{"-l", "/etc/passwd"},
	{"-l", "世界"},
	{"-L", "framework"},
	{"-framework", "Chocolate"},
	{"-v"},
	{"-Wl,-sectcreate,__TEXT,__info_plist,${SRCDIR}/Info.plist"},
	{"-Wl,-framework", "-Wl,Chocolate"},
	{"-Wl,-framework,Chocolate"},
	{"-Wl,-unresolved-symbols=ignore-all"},
	{"-Wl,-z,relro"},
	{"-Wl,-z,relro,-z,now"},
	{"-Wl,-z,now"},
	{"-Wl,-z,noexecstack"},
	{"libcgotbdtest.tbd"},
	{"./libcgotbdtest.tbd"},
	{"-Wl,--push-state"},
	{"-Wl,--pop-state"},
	{"-Wl,--push-state,--as-needed"},
	{"-Wl,--push-state,--no-as-needed,-Bstatic"},
	{"-Wl,--just-symbols,."},
	{"-Wl,-framework,."},
	{"-Wl,-rpath,."},
	{"-Wl,-rpath-link,."},
	{"-Wl,-sectcreate,.,.,."},
	{"-Wl,-syslibroot,."},
	{"-Wl,-undefined,."},
}

var badLinkerFlags = [][]string{
	{"-DFOO"},
	{"-Dfoo=bar"},
	{"-W"},
	{"-Wall"},
	{"-fobjc-arc"},
	{"-fno-objc-arc"},
	{"-fomit-frame-pointer"},
	{"-fno-omit-frame-pointer"},
	{"-fsplit-stack"},
	{"-fno-split-stack"},
	{"-fstack-xxx"},
	{"-fno-stack-xxx"},
	{"-mstack-overflow"},
	{"-mno-stack-overflow"},
	{"-mnop-fun-dllimport"},
	{"-std=c99"},
	{"-xc"},
	{"-D", "FOO"},
	{"-D", "foo=bar"},
	{"-I", "FOO"},
	{"-L", "@foo"},
	{"-L", "-foo"},
	{"-x", "c"},
	{"-D@X"},
	{"-D-X"},
	{"-I@dir"},
	{"-I-dir"},
	{"-O@1"},
	{"-Wa,-foo"},
	{"-W@foo"},
	{"-g@gdb"},
	{"-g-gdb"},
	{"-march=@dawn"},
	{"-march=-dawn"},
	{"-std=@c99"},
	{"-std=-c99"},
	{"-x@c"},
	{"-x-c"},
	{"-D", "@foo"},
	{"-D", "-foo"},
	{"-I", "@foo"},
	{"-I", "-foo"},
	{"-l", "@foo"},
	{"-l", "-foo"},
	{"-framework", "-Caffeine"},
	{"-framework", "@Home"},
	{"-Wl,-framework,-Caffeine"},
	{"-Wl,-framework", "-Wl,@Home"},
	{"-Wl,-framework", "@Home"},
	{"-Wl,-framework,Chocolate,@Home"},
	{"-Wl,--hash-style=foo"},
	{"-x", "--c"},
	{"-x", "@obj"},
	{"-Wl,-rpath,@foo"},
	{"-Wl,-R,foo,bar"},
	{"-Wl,-R,@foo"},
	{"-Wl,--just-symbols,@foo"},
	{"../x.o"},
	{"-Wl,-R,"},
	{"-Wl,-O"},
	{"-Wl,-e="},
	{"-Wl,-e,"},
	{"-Wl,-R,-flag"},
	{"-Wl,--push-state,"},
	{"-Wl,--push-state,@foo"},
	{"-fplugin=./-Wl,--push-state,-R.so"},
	{"./-Wl,--push-state,-R.c"},
}

func TestCheckLinkerFlags(t *testing.T) {
	for _, f := range goodLinkerFlags {
		if err := checkLinkerFlags("test", "test", f); err != nil {
			t.Errorf("unexpected error for %q: %v", f, err)
		}
	}
	for _, f := range badLinkerFlags {
		if err := checkLinkerFlags("test", "test", f); err == nil {
			t.Errorf("missing error for %q", f)
		}
	}
}

func TestCheckFlagAllowDisallow(t *testing.T) {
	if err := checkCompilerFlags("TEST", "test", []string{"-disallow"}); err == nil {
		t.Fatalf("missing error for -disallow")
	}
	os.Setenv("CGO_TEST_ALLOW", "-disallo")
	if err := checkCompilerFlags("TEST", "test", []string{"-disallow"}); err == nil {
		t.Fatalf("missing error for -disallow with CGO_TEST_ALLOW=-disallo")
	}
	os.Setenv("CGO_TEST_ALLOW", "-disallow")
	if err := checkCompilerFlags("TEST", "test", []string{"-disallow"}); err != nil {
		t.Fatalf("unexpected error for -disallow with CGO_TEST_ALLOW=-disallow: %v", err)
	}
	os.Unsetenv("CGO_TEST_ALLOW")

	if err := checkCompilerFlags("TEST", "test", []string{"-Wall"}); err != nil {
		t.Fatalf("unexpected error for -Wall: %v", err)
	}
	os.Setenv("CGO_TEST_DISALLOW", "-Wall")
	if err := checkCompilerFlags("TEST", "test", []string{"-Wall"}); err == nil {
		t.Fatalf("missing error for -Wall with CGO_TEST_DISALLOW=-Wall")
	}
	os.Setenv("CGO_TEST_ALLOW", "-Wall") // disallow wins
	if err := checkCompilerFlags("TEST", "test", []string{"-Wall"}); err == nil {
		t.Fatalf("missing error for -Wall with CGO_TEST_DISALLOW=-Wall and CGO_TEST_ALLOW=-Wall")
	}

	os.Setenv("CGO_TEST_ALLOW", "-fplugin.*")
	os.Setenv("CGO_TEST_DISALLOW", "-fplugin=lint.so")
	if err := checkCompilerFlags("TEST", "test", []string{"-fplugin=faster.so"}); err != nil {
		t.Fatalf("unexpected error for -fplugin=faster.so: %v", err)
	}
	if err := checkCompilerFlags("TEST", "test", []string{"-fplugin=lint.so"}); err == nil {
		t.Fatalf("missing error for -fplugin=lint.so: %v", err)
	}
}

func TestCheckCompilerFlagsForInternalLink(t *testing.T) {
	// Any "bad" compiler flag should trigger external linking.
	for _, f := range badCompilerFlags {
		if err := checkCompilerFlagsForInternalLink("test", "test", f); err == nil {
			t.Errorf("missing error for %q", f)
		}
	}

	// All "good" compiler flags should not trigger external linking,
	// except for anything that begins with "-flto".
	for _, f := range goodCompilerFlags {
		foundLTO := false
		for _, s := range f {
			if strings.Contains(s, "-flto") {
				foundLTO = true
			}
		}
		if err := checkCompilerFlagsForInternalLink("test", "test", f); err != nil {
			// expect error for -flto
			if !foundLTO {
				t.Errorf("unexpected error for %q: %v", f, err)
			}
		} else {
			// expect no error for everything else
			if foundLTO {
				t.Errorf("missing error for %q: %v", f, err)
			}
		}
	}
}
```