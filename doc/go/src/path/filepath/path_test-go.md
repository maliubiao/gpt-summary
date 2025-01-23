Response:
My goal is to understand the functionality of the provided Go code snippet, which is part of `go/src/path/filepath/path_test.go`. Here's my thinking process to arrive at the summary:

1. **Identify the Core Purpose:** The file name `path_test.go` immediately suggests this is a test file for the `path/filepath` package. This package deals with file path manipulation. The import statement confirms this.

2. **Scan for Test Functions:** I look for functions that start with `Test`. The snippet contains several: `TestClean`, `TestIsLocal`, `TestLocalize`, `TestFromAndToSlash`, `TestSplitList`, `TestSplit`, `TestJoin`, `TestExt`, `TestWalk`, `TestWalkDir`, `TestWalkSkipDirOnFile`, `TestWalkSkipAllOnFile`, `TestWalkFileError`, `TestWalkSymlinkRoot`, `TestBase`, `TestDir`, `TestIsAbs`, `TestEvalSymlinks`, `TestEvalSymlinksIsNotExist`, and `TestIssue13582`, `TestRelativeSymlinkToAbsolute`. Each of these likely tests a specific function or aspect of the `filepath` package.

3. **Examine Test Data Structures:** The code defines several `struct` types (`PathTest`, `IsLocalTest`, `LocalizeTest`, `SplitListTest`, `SplitTest`, `JoinTest`, `ExtTest`, `EvalSymlinksTest`, `IsAbsTest`) and initializes slices of these structs (e.g., `cleantests`, `nonwincleantests`, `wincleantests`, `islocaltests`, etc.). These structures and their associated data likely represent test cases for the functions being tested. For example, `cleantests` likely provides input paths and their expected cleaned versions for the `filepath.Clean` function.

4. **Infer Functionality from Test Names and Data:** Based on the test function names and the associated test data, I can infer the functionality being tested:
    * `TestClean`: Tests the `filepath.Clean` function, which likely normalizes file paths by removing redundant elements.
    * `TestIsLocal`: Tests the `filepath.IsLocal` function, probably to determine if a path is considered "local" (relative to the current directory).
    * `TestLocalize`: Tests the `filepath.Localize` function, likely related to converting paths to a more localized representation.
    * `TestFromAndToSlash`: Tests `filepath.FromSlash` and `filepath.ToSlash`, likely for converting paths between Unix-style slashes and the operating system's native path separators.
    * `TestSplitList`: Tests `filepath.SplitList`, probably for splitting a list of paths based on the system's path list separator.
    * `TestSplit`: Tests `filepath.Split`, which likely separates a path into its directory and file components.
    * `TestJoin`: Tests `filepath.Join`, used for constructing a path by joining path elements.
    * `TestExt`: Tests `filepath.Ext`, likely to extract the file extension from a path.
    * `TestWalk` and `TestWalkDir`: Test `filepath.Walk` and `filepath.WalkDir`, functions for recursively traversing a directory tree. The different names suggest potentially subtle differences in their behavior or the arguments they accept.
    * The `TestWalkSkip*` tests likely focus on the behavior of `filepath.Walk` and `filepath.WalkDir` when encountering special return values like `filepath.SkipDir` and `filepath.SkipAll` during traversal.
    * `TestWalkFileError` tests how `filepath.Walk` handles errors encountered while accessing files or directories.
    * `TestWalkSymlinkRoot` checks how `filepath.Walk` behaves when the root path is a symbolic link.
    * `TestBase`: Tests `filepath.Base`, likely for extracting the last element of a path.
    * `TestDir`: Tests `filepath.Dir`, which probably returns the directory part of a path.
    * `TestIsAbs`: Tests `filepath.IsAbs`, used to determine if a path is absolute.
    * `TestEvalSymlinks`: Tests `filepath.EvalSymlinks`, which resolves symbolic links in a path to their target.
    * `TestEvalSymlinksIsNotExist`: Focuses on the behavior of `EvalSymlinks` when encountering non-existent symlink targets.
    * `TestIssue13582` and `TestRelativeSymlinkToAbsolute`: These tests are named after specific GitHub issues, suggesting they address particular bugs or edge cases related to symbolic link handling.

5. **Note OS-Specific Tests:**  The presence of `nonwincleantests`, `wincleantests`, `winislocaltests`, `plan9islocaltests`, `winlocalizetests`, `unixlocalizetests`, `winsplitlisttests`, `winsplittests`, `nonwinjointests`, `winjointests`, `winbasetests`, `nonwindirtests`, `windirtests`, and `winisabstests` strongly indicates that the tests are designed to cover platform-specific path handling differences, particularly between Windows and Unix-like systems. The code explicitly checks `runtime.GOOS` to select the appropriate test cases.

6. **Identify Auxiliary Functions:** Functions like `walkTree`, `makeTree`, `markTree`, `checkMarks`, `mark`, `tempDirCanonical`, and `touch` are helper functions used to set up the testing environment, create test directory structures, and verify the results of the tests. These are not directly testing `filepath` functions but are crucial for the testing process.

7. **Synthesize the Summary:**  Based on the above observations, I can formulate a summary of the code's functionality. The key is that this is a *test* file for the `path/filepath` package, and it tests a variety of path manipulation functions, considering platform-specific behavior.

This methodical approach of examining the file name, imports, test function names, test data structures, and auxiliary functions allows me to accurately determine the purpose and scope of the provided Go code snippet.
这是go语言标准库中 `path/filepath` 包的一部分测试代码。 它主要用于测试 `path/filepath` 包中提供的各种文件路径操作相关的功能。

**它的主要功能是：**

1. **测试路径清理功能 (`Clean`)**:  测试 `filepath.Clean` 函数，该函数用于规范化路径，例如移除多余的斜杠、点号(`.`) 和双点号(`..`)等。

2. **测试判断路径是否本地 (`IsLocal`)**: 测试 `filepath.IsLocal` 函数，该函数用于判断给定的路径是否被认为是“本地”路径（例如，不以斜杠开头，或者不是设备名等）。

3. **测试路径本地化 (`Localize`)**: 测试 `filepath.Localize` 函数，该函数尝试将一个路径转换为更本地化的表示形式，如果无法本地化则返回错误。

4. **测试斜杠与系统分隔符之间的转换 (`FromSlash`, `ToSlash`)**: 测试 `filepath.FromSlash` 和 `filepath.ToSlash` 函数，用于在 Unix 风格的斜杠(`/`)和当前操作系统使用的路径分隔符之间进行转换。

5. **测试路径列表的分割 (`SplitList`)**: 测试 `filepath.SplitList` 函数，该函数根据操作系统特定的路径列表分隔符将字符串分割成路径列表。

6. **测试路径的分割 (`Split`)**: 测试 `filepath.Split` 函数，该函数将路径分割成目录部分和文件名部分。

7. **测试路径的连接 (`Join`)**: 测试 `filepath.Join` 函数，该函数将多个路径元素连接成一个完整的路径。

8. **测试文件扩展名的提取 (`Ext`)**: 测试 `filepath.Ext` 函数，该函数提取路径的文件扩展名。

9. **测试目录树的遍历 (`Walk`, `WalkDir`)**: 测试 `filepath.Walk` 和 `filepath.WalkDir` 函数，用于递归地遍历目录树，并对每个访问到的文件或目录执行指定的操作。 其中包括测试 `filepath.SkipDir` 和 `filepath.SkipAll` 的行为。

10. **测试获取路径的基础名称 (`Base`)**: 测试 `filepath.Base` 函数，该函数返回路径的最后一个元素。

11. **测试获取路径的目录部分 (`Dir`)**: 测试 `filepath.Dir` 函数，该函数返回路径的目录部分。

12. **测试判断路径是否为绝对路径 (`IsAbs`)**: 测试 `filepath.IsAbs` 函数，该函数判断给定的路径是否为绝对路径。

13. **测试符号链接的解析 (`EvalSymlinks`)**: 测试 `filepath.EvalSymlinks` 函数，该函数解析路径中的所有符号链接，返回最终的真实路径。

**可以推理出它是什么go语言功能的实现:**

这段代码主要测试的是 Go 语言中用于处理文件路径的功能，特别是 `path/filepath` 标准库。

**Go 代码举例说明 (以 `filepath.Clean` 为例):**

假设我们想测试 `filepath.Clean` 函数的功能。

```go
package main

import (
	"fmt"
	"path/filepath"
)

func main() {
	testCases := []struct {
		input    string
		expected string
	}{
		{"/a/b/../c", "/a/c"},
		{"a//b//c", "a/b/c"},
		{"a/./b", "a/b"},
		{"a/b/", "a/b"},
		{"", "."},
	}

	for _, tc := range testCases {
		cleanedPath := filepath.Clean(tc.input)
		if cleanedPath == tc.expected {
			fmt.Printf("Clean(%q) = %q (成功)\n", tc.input, cleanedPath)
		} else {
			fmt.Printf("Clean(%q) = %q, want %q (失败)\n", tc.input, cleanedPath, tc.expected)
		}
	}
}
```

**假设的输入与输出 (以 `filepath.Clean` 为例):**

* **输入:** "/a/b/../c"
* **输出:** "/a/c"

* **输入:** "a//b//c"
* **输出:** "a/b/c"

* **输入:** "a/./b"
* **输出:** "a/b"

* **输入:** "a/b/"
* **输出:** "a/b"

* **输入:** ""
* **输出:** "."

**命令行参数的具体处理:**

这段代码本身是测试代码，不直接处理命令行参数。它通过定义不同的测试用例（例如 `cleantests` 变量）来覆盖 `path/filepath` 包中不同函数的各种输入情况。在运行测试时（通常使用 `go test` 命令），Go 的测试框架会加载并执行这些测试函数，并根据预期的结果进行断言。

**归纳一下它的功能:**

这段代码是 `path/filepath` Go 语言标准库的一部分测试，旨在全面验证该库提供的各种文件路径操作函数的正确性和可靠性。 它通过定义一系列包含不同输入和预期输出的测试用例，覆盖了路径清理、路径判断、路径转换、路径分割、路径连接、文件扩展名提取以及目录树遍历等多种文件路径处理场景，并且考虑了不同操作系统平台下的差异性。

### 提示词
```
这是路径为go/src/path/filepath/path_test.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```go
// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package filepath_test

import (
	"errors"
	"fmt"
	"internal/testenv"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"slices"
	"strings"
	"syscall"
	"testing"
)

type PathTest struct {
	path, result string
}

var cleantests = []PathTest{
	// Already clean
	{"abc", "abc"},
	{"abc/def", "abc/def"},
	{"a/b/c", "a/b/c"},
	{".", "."},
	{"..", ".."},
	{"../..", "../.."},
	{"../../abc", "../../abc"},
	{"/abc", "/abc"},
	{"/", "/"},

	// Empty is current dir
	{"", "."},

	// Remove trailing slash
	{"abc/", "abc"},
	{"abc/def/", "abc/def"},
	{"a/b/c/", "a/b/c"},
	{"./", "."},
	{"../", ".."},
	{"../../", "../.."},
	{"/abc/", "/abc"},

	// Remove doubled slash
	{"abc//def//ghi", "abc/def/ghi"},
	{"abc//", "abc"},

	// Remove . elements
	{"abc/./def", "abc/def"},
	{"/./abc/def", "/abc/def"},
	{"abc/.", "abc"},

	// Remove .. elements
	{"abc/def/ghi/../jkl", "abc/def/jkl"},
	{"abc/def/../ghi/../jkl", "abc/jkl"},
	{"abc/def/..", "abc"},
	{"abc/def/../..", "."},
	{"/abc/def/../..", "/"},
	{"abc/def/../../..", ".."},
	{"/abc/def/../../..", "/"},
	{"abc/def/../../../ghi/jkl/../../../mno", "../../mno"},
	{"/../abc", "/abc"},
	{"a/../b:/../../c", `../c`},

	// Combinations
	{"abc/./../def", "def"},
	{"abc//./../def", "def"},
	{"abc/../../././../def", "../../def"},
}

var nonwincleantests = []PathTest{
	// Remove leading doubled slash
	{"//abc", "/abc"},
	{"///abc", "/abc"},
	{"//abc//", "/abc"},
}

var wincleantests = []PathTest{
	{`c:`, `c:.`},
	{`c:\`, `c:\`},
	{`c:\abc`, `c:\abc`},
	{`c:abc\..\..\.\.\..\def`, `c:..\..\def`},
	{`c:\abc\def\..\..`, `c:\`},
	{`c:\..\abc`, `c:\abc`},
	{`c:..\abc`, `c:..\abc`},
	{`c:\b:\..\..\..\d`, `c:\d`},
	{`\`, `\`},
	{`/`, `\`},
	{`\\i\..\c$`, `\\i\..\c$`},
	{`\\i\..\i\c$`, `\\i\..\i\c$`},
	{`\\i\..\I\c$`, `\\i\..\I\c$`},
	{`\\host\share\foo\..\bar`, `\\host\share\bar`},
	{`//host/share/foo/../baz`, `\\host\share\baz`},
	{`\\host\share\foo\..\..\..\..\bar`, `\\host\share\bar`},
	{`\\.\C:\a\..\..\..\..\bar`, `\\.\C:\bar`},
	{`\\.\C:\\\\a`, `\\.\C:\a`},
	{`\\a\b\..\c`, `\\a\b\c`},
	{`\\a\b`, `\\a\b`},
	{`.\c:`, `.\c:`},
	{`.\c:\foo`, `.\c:\foo`},
	{`.\c:foo`, `.\c:foo`},
	{`//abc`, `\\abc`},
	{`///abc`, `\\\abc`},
	{`//abc//`, `\\abc\\`},
	{`\\?\C:\`, `\\?\C:\`},
	{`\\?\C:\a`, `\\?\C:\a`},

	// Don't allow cleaning to move an element with a colon to the start of the path.
	{`a/../c:`, `.\c:`},
	{`a\..\c:`, `.\c:`},
	{`a/../c:/a`, `.\c:\a`},
	{`a/../../c:`, `..\c:`},
	{`foo:bar`, `foo:bar`},

	// Don't allow cleaning to create a Root Local Device path like \??\a.
	{`/a/../??/a`, `\.\??\a`},
}

func TestClean(t *testing.T) {
	tests := cleantests
	if runtime.GOOS == "windows" {
		for i := range tests {
			tests[i].result = filepath.FromSlash(tests[i].result)
		}
		tests = append(tests, wincleantests...)
	} else {
		tests = append(tests, nonwincleantests...)
	}
	for _, test := range tests {
		if s := filepath.Clean(test.path); s != test.result {
			t.Errorf("Clean(%q) = %q, want %q", test.path, s, test.result)
		}
		if s := filepath.Clean(test.result); s != test.result {
			t.Errorf("Clean(%q) = %q, want %q", test.result, s, test.result)
		}
	}

	if testing.Short() {
		t.Skip("skipping malloc count in short mode")
	}
	if runtime.GOMAXPROCS(0) > 1 {
		t.Log("skipping AllocsPerRun checks; GOMAXPROCS>1")
		return
	}

	for _, test := range tests {
		allocs := testing.AllocsPerRun(100, func() { filepath.Clean(test.result) })
		if allocs > 0 {
			t.Errorf("Clean(%q): %v allocs, want zero", test.result, allocs)
		}
	}
}

type IsLocalTest struct {
	path    string
	isLocal bool
}

var islocaltests = []IsLocalTest{
	{"", false},
	{".", true},
	{"..", false},
	{"../a", false},
	{"/", false},
	{"/a", false},
	{"/a/../..", false},
	{"a", true},
	{"a/../a", true},
	{"a/", true},
	{"a/.", true},
	{"a/./b/./c", true},
	{`a/../b:/../../c`, false},
}

var winislocaltests = []IsLocalTest{
	{"NUL", false},
	{"nul", false},
	{"nul ", false},
	{"nul.", false},
	{"a/nul:", false},
	{"a/nul : a", false},
	{"com0", true},
	{"com1", false},
	{"com2", false},
	{"com3", false},
	{"com4", false},
	{"com5", false},
	{"com6", false},
	{"com7", false},
	{"com8", false},
	{"com9", false},
	{"com¹", false},
	{"com²", false},
	{"com³", false},
	{"com¹ : a", false},
	{"cOm1", false},
	{"lpt1", false},
	{"LPT1", false},
	{"lpt³", false},
	{"./nul", false},
	{`\`, false},
	{`\a`, false},
	{`C:`, false},
	{`C:\a`, false},
	{`..\a`, false},
	{`a/../c:`, false},
	{`CONIN$`, false},
	{`conin$`, false},
	{`CONOUT$`, false},
	{`conout$`, false},
	{`dollar$`, true}, // not a special file name
}

var plan9islocaltests = []IsLocalTest{
	{"#a", false},
}

func TestIsLocal(t *testing.T) {
	tests := islocaltests
	if runtime.GOOS == "windows" {
		tests = append(tests, winislocaltests...)
	}
	if runtime.GOOS == "plan9" {
		tests = append(tests, plan9islocaltests...)
	}
	for _, test := range tests {
		if got := filepath.IsLocal(test.path); got != test.isLocal {
			t.Errorf("IsLocal(%q) = %v, want %v", test.path, got, test.isLocal)
		}
	}
}

type LocalizeTest struct {
	path string
	want string
}

var localizetests = []LocalizeTest{
	{"", ""},
	{".", "."},
	{"..", ""},
	{"a/..", ""},
	{"/", ""},
	{"/a", ""},
	{"a\xffb", ""},
	{"a/", ""},
	{"a/./b", ""},
	{"\x00", ""},
	{"a", "a"},
	{"a/b/c", "a/b/c"},
}

var plan9localizetests = []LocalizeTest{
	{"#a", ""},
	{`a\b:c`, `a\b:c`},
}

var unixlocalizetests = []LocalizeTest{
	{"#a", "#a"},
	{`a\b:c`, `a\b:c`},
}

var winlocalizetests = []LocalizeTest{
	{"#a", "#a"},
	{"c:", ""},
	{`a\b`, ""},
	{`a:b`, ""},
	{`a/b:c`, ""},
	{`NUL`, ""},
	{`a/NUL`, ""},
	{`./com1`, ""},
	{`a/nul/b`, ""},
}

func TestLocalize(t *testing.T) {
	tests := localizetests
	switch runtime.GOOS {
	case "plan9":
		tests = append(tests, plan9localizetests...)
	case "windows":
		tests = append(tests, winlocalizetests...)
		for i := range tests {
			tests[i].want = filepath.FromSlash(tests[i].want)
		}
	default:
		tests = append(tests, unixlocalizetests...)
	}
	for _, test := range tests {
		got, err := filepath.Localize(test.path)
		wantErr := "<nil>"
		if test.want == "" {
			wantErr = "error"
		}
		if got != test.want || ((err == nil) != (test.want != "")) {
			t.Errorf("IsLocal(%q) = %q, %v want %q, %v", test.path, got, err, test.want, wantErr)
		}
	}
}

const sep = filepath.Separator

var slashtests = []PathTest{
	{"", ""},
	{"/", string(sep)},
	{"/a/b", string([]byte{sep, 'a', sep, 'b'})},
	{"a//b", string([]byte{'a', sep, sep, 'b'})},
}

func TestFromAndToSlash(t *testing.T) {
	for _, test := range slashtests {
		if s := filepath.FromSlash(test.path); s != test.result {
			t.Errorf("FromSlash(%q) = %q, want %q", test.path, s, test.result)
		}
		if s := filepath.ToSlash(test.result); s != test.path {
			t.Errorf("ToSlash(%q) = %q, want %q", test.result, s, test.path)
		}
	}
}

type SplitListTest struct {
	list   string
	result []string
}

const lsep = filepath.ListSeparator

var splitlisttests = []SplitListTest{
	{"", []string{}},
	{string([]byte{'a', lsep, 'b'}), []string{"a", "b"}},
	{string([]byte{lsep, 'a', lsep, 'b'}), []string{"", "a", "b"}},
}

var winsplitlisttests = []SplitListTest{
	// quoted
	{`"a"`, []string{`a`}},

	// semicolon
	{`";"`, []string{`;`}},
	{`"a;b"`, []string{`a;b`}},
	{`";";`, []string{`;`, ``}},
	{`;";"`, []string{``, `;`}},

	// partially quoted
	{`a";"b`, []string{`a;b`}},
	{`a; ""b`, []string{`a`, ` b`}},
	{`"a;b`, []string{`a;b`}},
	{`""a;b`, []string{`a`, `b`}},
	{`"""a;b`, []string{`a;b`}},
	{`""""a;b`, []string{`a`, `b`}},
	{`a";b`, []string{`a;b`}},
	{`a;b";c`, []string{`a`, `b;c`}},
	{`"a";b";c`, []string{`a`, `b;c`}},
}

func TestSplitList(t *testing.T) {
	tests := splitlisttests
	if runtime.GOOS == "windows" {
		tests = append(tests, winsplitlisttests...)
	}
	for _, test := range tests {
		if l := filepath.SplitList(test.list); !slices.Equal(l, test.result) {
			t.Errorf("SplitList(%#q) = %#q, want %#q", test.list, l, test.result)
		}
	}
}

type SplitTest struct {
	path, dir, file string
}

var unixsplittests = []SplitTest{
	{"a/b", "a/", "b"},
	{"a/b/", "a/b/", ""},
	{"a/", "a/", ""},
	{"a", "", "a"},
	{"/", "/", ""},
}

var winsplittests = []SplitTest{
	{`c:`, `c:`, ``},
	{`c:/`, `c:/`, ``},
	{`c:/foo`, `c:/`, `foo`},
	{`c:/foo/bar`, `c:/foo/`, `bar`},
	{`//host/share`, `//host/share`, ``},
	{`//host/share/`, `//host/share/`, ``},
	{`//host/share/foo`, `//host/share/`, `foo`},
	{`\\host\share`, `\\host\share`, ``},
	{`\\host\share\`, `\\host\share\`, ``},
	{`\\host\share\foo`, `\\host\share\`, `foo`},
}

func TestSplit(t *testing.T) {
	var splittests []SplitTest
	splittests = unixsplittests
	if runtime.GOOS == "windows" {
		splittests = append(splittests, winsplittests...)
	}
	for _, test := range splittests {
		if d, f := filepath.Split(test.path); d != test.dir || f != test.file {
			t.Errorf("Split(%q) = %q, %q, want %q, %q", test.path, d, f, test.dir, test.file)
		}
	}
}

type JoinTest struct {
	elem []string
	path string
}

var jointests = []JoinTest{
	// zero parameters
	{[]string{}, ""},

	// one parameter
	{[]string{""}, ""},
	{[]string{"/"}, "/"},
	{[]string{"a"}, "a"},

	// two parameters
	{[]string{"a", "b"}, "a/b"},
	{[]string{"a", ""}, "a"},
	{[]string{"", "b"}, "b"},
	{[]string{"/", "a"}, "/a"},
	{[]string{"/", "a/b"}, "/a/b"},
	{[]string{"/", ""}, "/"},
	{[]string{"/a", "b"}, "/a/b"},
	{[]string{"a", "/b"}, "a/b"},
	{[]string{"/a", "/b"}, "/a/b"},
	{[]string{"a/", "b"}, "a/b"},
	{[]string{"a/", ""}, "a"},
	{[]string{"", ""}, ""},

	// three parameters
	{[]string{"/", "a", "b"}, "/a/b"},
}

var nonwinjointests = []JoinTest{
	{[]string{"//", "a"}, "/a"},
}

var winjointests = []JoinTest{
	{[]string{`directory`, `file`}, `directory\file`},
	{[]string{`C:\Windows\`, `System32`}, `C:\Windows\System32`},
	{[]string{`C:\Windows\`, ``}, `C:\Windows`},
	{[]string{`C:\`, `Windows`}, `C:\Windows`},
	{[]string{`C:`, `a`}, `C:a`},
	{[]string{`C:`, `a\b`}, `C:a\b`},
	{[]string{`C:`, `a`, `b`}, `C:a\b`},
	{[]string{`C:`, ``, `b`}, `C:b`},
	{[]string{`C:`, ``, ``, `b`}, `C:b`},
	{[]string{`C:`, ``}, `C:.`},
	{[]string{`C:`, ``, ``}, `C:.`},
	{[]string{`C:`, `\a`}, `C:\a`},
	{[]string{`C:`, ``, `\a`}, `C:\a`},
	{[]string{`C:.`, `a`}, `C:a`},
	{[]string{`C:a`, `b`}, `C:a\b`},
	{[]string{`C:a`, `b`, `d`}, `C:a\b\d`},
	{[]string{`\\host\share`, `foo`}, `\\host\share\foo`},
	{[]string{`\\host\share\foo`}, `\\host\share\foo`},
	{[]string{`//host/share`, `foo/bar`}, `\\host\share\foo\bar`},
	{[]string{`\`}, `\`},
	{[]string{`\`, ``}, `\`},
	{[]string{`\`, `a`}, `\a`},
	{[]string{`\\`, `a`}, `\\a`},
	{[]string{`\`, `a`, `b`}, `\a\b`},
	{[]string{`\\`, `a`, `b`}, `\\a\b`},
	{[]string{`\`, `\\a\b`, `c`}, `\a\b\c`},
	{[]string{`\\a`, `b`, `c`}, `\\a\b\c`},
	{[]string{`\\a\`, `b`, `c`}, `\\a\b\c`},
	{[]string{`//`, `a`}, `\\a`},
	{[]string{`a:\b\c`, `x\..\y:\..\..\z`}, `a:\b\z`},
	{[]string{`\`, `??\a`}, `\.\??\a`},
}

func TestJoin(t *testing.T) {
	if runtime.GOOS == "windows" {
		jointests = append(jointests, winjointests...)
	} else {
		jointests = append(jointests, nonwinjointests...)
	}
	for _, test := range jointests {
		expected := filepath.FromSlash(test.path)
		if p := filepath.Join(test.elem...); p != expected {
			t.Errorf("join(%q) = %q, want %q", test.elem, p, expected)
		}
	}
}

type ExtTest struct {
	path, ext string
}

var exttests = []ExtTest{
	{"path.go", ".go"},
	{"path.pb.go", ".go"},
	{"a.dir/b", ""},
	{"a.dir/b.go", ".go"},
	{"a.dir/", ""},
}

func TestExt(t *testing.T) {
	for _, test := range exttests {
		if x := filepath.Ext(test.path); x != test.ext {
			t.Errorf("Ext(%q) = %q, want %q", test.path, x, test.ext)
		}
	}
}

type Node struct {
	name    string
	entries []*Node // nil if the entry is a file
	mark    int
}

var tree = &Node{
	"testdata",
	[]*Node{
		{"a", nil, 0},
		{"b", []*Node{}, 0},
		{"c", nil, 0},
		{
			"d",
			[]*Node{
				{"x", nil, 0},
				{"y", []*Node{}, 0},
				{
					"z",
					[]*Node{
						{"u", nil, 0},
						{"v", nil, 0},
					},
					0,
				},
			},
			0,
		},
	},
	0,
}

func walkTree(n *Node, path string, f func(path string, n *Node)) {
	f(path, n)
	for _, e := range n.entries {
		walkTree(e, filepath.Join(path, e.name), f)
	}
}

func makeTree(t *testing.T) {
	walkTree(tree, tree.name, func(path string, n *Node) {
		if n.entries == nil {
			fd, err := os.Create(path)
			if err != nil {
				t.Errorf("makeTree: %v", err)
				return
			}
			fd.Close()
		} else {
			os.Mkdir(path, 0770)
		}
	})
}

func markTree(n *Node) { walkTree(n, "", func(path string, n *Node) { n.mark++ }) }

func checkMarks(t *testing.T, report bool) {
	walkTree(tree, tree.name, func(path string, n *Node) {
		if n.mark != 1 && report {
			t.Errorf("node %s mark = %d; expected 1", path, n.mark)
		}
		n.mark = 0
	})
}

// Assumes that each node name is unique. Good enough for a test.
// If clear is true, any incoming error is cleared before return. The errors
// are always accumulated, though.
func mark(d fs.DirEntry, err error, errors *[]error, clear bool) error {
	name := d.Name()
	walkTree(tree, tree.name, func(path string, n *Node) {
		if n.name == name {
			n.mark++
		}
	})
	if err != nil {
		*errors = append(*errors, err)
		if clear {
			return nil
		}
		return err
	}
	return nil
}

// tempDirCanonical returns a temporary directory for the test to use, ensuring
// that the returned path does not contain symlinks.
func tempDirCanonical(t *testing.T) string {
	dir := t.TempDir()

	cdir, err := filepath.EvalSymlinks(dir)
	if err != nil {
		t.Errorf("tempDirCanonical: %v", err)
	}

	return cdir
}

func TestWalk(t *testing.T) {
	walk := func(root string, fn fs.WalkDirFunc) error {
		return filepath.Walk(root, func(path string, info fs.FileInfo, err error) error {
			return fn(path, fs.FileInfoToDirEntry(info), err)
		})
	}
	testWalk(t, walk, 1)
}

func TestWalkDir(t *testing.T) {
	testWalk(t, filepath.WalkDir, 2)
}

func testWalk(t *testing.T, walk func(string, fs.WalkDirFunc) error, errVisit int) {
	t.Chdir(t.TempDir())

	makeTree(t)
	errors := make([]error, 0, 10)
	clear := true
	markFn := func(path string, d fs.DirEntry, err error) error {
		return mark(d, err, &errors, clear)
	}
	// Expect no errors.
	err := walk(tree.name, markFn)
	if err != nil {
		t.Fatalf("no error expected, found: %s", err)
	}
	if len(errors) != 0 {
		t.Fatalf("unexpected errors: %s", errors)
	}
	checkMarks(t, true)
	errors = errors[0:0]

	t.Run("PermErr", func(t *testing.T) {
		// Test permission errors. Only possible if we're not root
		// and only on some file systems (AFS, FAT).  To avoid errors during
		// all.bash on those file systems, skip during go test -short.
		// Chmod is not supported on wasip1.
		if runtime.GOOS == "windows" || runtime.GOOS == "wasip1" {
			t.Skip("skipping on " + runtime.GOOS)
		}
		if os.Getuid() == 0 {
			t.Skip("skipping as root")
		}
		if testing.Short() {
			t.Skip("skipping in short mode")
		}

		// introduce 2 errors: chmod top-level directories to 0
		os.Chmod(filepath.Join(tree.name, tree.entries[1].name), 0)
		os.Chmod(filepath.Join(tree.name, tree.entries[3].name), 0)

		// 3) capture errors, expect two.
		// mark respective subtrees manually
		markTree(tree.entries[1])
		markTree(tree.entries[3])
		// correct double-marking of directory itself
		tree.entries[1].mark -= errVisit
		tree.entries[3].mark -= errVisit
		err := walk(tree.name, markFn)
		if err != nil {
			t.Fatalf("expected no error return from Walk, got %s", err)
		}
		if len(errors) != 2 {
			t.Errorf("expected 2 errors, got %d: %s", len(errors), errors)
		}
		// the inaccessible subtrees were marked manually
		checkMarks(t, true)
		errors = errors[0:0]

		// 4) capture errors, stop after first error.
		// mark respective subtrees manually
		markTree(tree.entries[1])
		markTree(tree.entries[3])
		// correct double-marking of directory itself
		tree.entries[1].mark -= errVisit
		tree.entries[3].mark -= errVisit
		clear = false // error will stop processing
		err = walk(tree.name, markFn)
		if err == nil {
			t.Fatalf("expected error return from Walk")
		}
		if len(errors) != 1 {
			t.Errorf("expected 1 error, got %d: %s", len(errors), errors)
		}
		// the inaccessible subtrees were marked manually
		checkMarks(t, false)
		errors = errors[0:0]

		// restore permissions
		os.Chmod(filepath.Join(tree.name, tree.entries[1].name), 0770)
		os.Chmod(filepath.Join(tree.name, tree.entries[3].name), 0770)
	})
}

func touch(t *testing.T, name string) {
	f, err := os.Create(name)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestWalkSkipDirOnFile(t *testing.T) {
	td := t.TempDir()

	if err := os.MkdirAll(filepath.Join(td, "dir"), 0755); err != nil {
		t.Fatal(err)
	}
	touch(t, filepath.Join(td, "dir/foo1"))
	touch(t, filepath.Join(td, "dir/foo2"))

	sawFoo2 := false
	walker := func(path string) error {
		if strings.HasSuffix(path, "foo2") {
			sawFoo2 = true
		}
		if strings.HasSuffix(path, "foo1") {
			return filepath.SkipDir
		}
		return nil
	}
	walkFn := func(path string, _ fs.FileInfo, _ error) error { return walker(path) }
	walkDirFn := func(path string, _ fs.DirEntry, _ error) error { return walker(path) }

	check := func(t *testing.T, walk func(root string) error, root string) {
		t.Helper()
		sawFoo2 = false
		err := walk(root)
		if err != nil {
			t.Fatal(err)
		}
		if sawFoo2 {
			t.Errorf("SkipDir on file foo1 did not block processing of foo2")
		}
	}

	t.Run("Walk", func(t *testing.T) {
		Walk := func(root string) error { return filepath.Walk(td, walkFn) }
		check(t, Walk, td)
		check(t, Walk, filepath.Join(td, "dir"))
	})
	t.Run("WalkDir", func(t *testing.T) {
		WalkDir := func(root string) error { return filepath.WalkDir(td, walkDirFn) }
		check(t, WalkDir, td)
		check(t, WalkDir, filepath.Join(td, "dir"))
	})
}

func TestWalkSkipAllOnFile(t *testing.T) {
	td := t.TempDir()

	if err := os.MkdirAll(filepath.Join(td, "dir", "subdir"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(td, "dir2"), 0755); err != nil {
		t.Fatal(err)
	}

	touch(t, filepath.Join(td, "dir", "foo1"))
	touch(t, filepath.Join(td, "dir", "foo2"))
	touch(t, filepath.Join(td, "dir", "subdir", "foo3"))
	touch(t, filepath.Join(td, "dir", "foo4"))
	touch(t, filepath.Join(td, "dir2", "bar"))
	touch(t, filepath.Join(td, "last"))

	remainingWereSkipped := true
	walker := func(path string) error {
		if strings.HasSuffix(path, "foo2") {
			return filepath.SkipAll
		}

		if strings.HasSuffix(path, "foo3") ||
			strings.HasSuffix(path, "foo4") ||
			strings.HasSuffix(path, "bar") ||
			strings.HasSuffix(path, "last") {
			remainingWereSkipped = false
		}
		return nil
	}

	walkFn := func(path string, _ fs.FileInfo, _ error) error { return walker(path) }
	walkDirFn := func(path string, _ fs.DirEntry, _ error) error { return walker(path) }

	check := func(t *testing.T, walk func(root string) error, root string) {
		t.Helper()
		remainingWereSkipped = true
		if err := walk(root); err != nil {
			t.Fatal(err)
		}
		if !remainingWereSkipped {
			t.Errorf("SkipAll on file foo2 did not block processing of remaining files and directories")
		}
	}

	t.Run("Walk", func(t *testing.T) {
		Walk := func(_ string) error { return filepath.Walk(td, walkFn) }
		check(t, Walk, td)
		check(t, Walk, filepath.Join(td, "dir"))
	})
	t.Run("WalkDir", func(t *testing.T) {
		WalkDir := func(_ string) error { return filepath.WalkDir(td, walkDirFn) }
		check(t, WalkDir, td)
		check(t, WalkDir, filepath.Join(td, "dir"))
	})
}

func TestWalkFileError(t *testing.T) {
	td := t.TempDir()

	touch(t, filepath.Join(td, "foo"))
	touch(t, filepath.Join(td, "bar"))
	dir := filepath.Join(td, "dir")
	if err := os.MkdirAll(filepath.Join(td, "dir"), 0755); err != nil {
		t.Fatal(err)
	}
	touch(t, filepath.Join(dir, "baz"))
	touch(t, filepath.Join(dir, "stat-error"))
	defer func() {
		*filepath.LstatP = os.Lstat
	}()
	statErr := errors.New("some stat error")
	*filepath.LstatP = func(path string) (fs.FileInfo, error) {
		if strings.HasSuffix(path, "stat-error") {
			return nil, statErr
		}
		return os.Lstat(path)
	}
	got := map[string]error{}
	err := filepath.Walk(td, func(path string, fi fs.FileInfo, err error) error {
		rel, _ := filepath.Rel(td, path)
		got[filepath.ToSlash(rel)] = err
		return nil
	})
	if err != nil {
		t.Errorf("Walk error: %v", err)
	}
	want := map[string]error{
		".":              nil,
		"foo":            nil,
		"bar":            nil,
		"dir":            nil,
		"dir/baz":        nil,
		"dir/stat-error": statErr,
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("Walked %#v; want %#v", got, want)
	}
}

func TestWalkSymlinkRoot(t *testing.T) {
	testenv.MustHaveSymlink(t)

	td := t.TempDir()
	dir := filepath.Join(td, "dir")
	if err := os.MkdirAll(filepath.Join(td, "dir"), 0755); err != nil {
		t.Fatal(err)
	}
	touch(t, filepath.Join(dir, "foo"))

	link := filepath.Join(td, "link")
	if err := os.Symlink("dir", link); err != nil {
		t.Fatal(err)
	}

	abslink := filepath.Join(td, "abslink")
	if err := os.Symlink(dir, abslink); err != nil {
		t.Fatal(err)
	}

	linklink := filepath.Join(td, "linklink")
	if err := os.Symlink("link", linklink); err != nil {
		t.Fatal(err)
	}

	// Per https://pubs.opengroup.org/onlinepubs/9699919799.2013edition/basedefs/V1_chap04.html#tag_04_12:
	// “A pathname that contains at least one non- <slash> character and that ends
	// with one or more trailing <slash> characters shall not be resolved
	// successfully unless the last pathname component before the trailing <slash>
	// characters names an existing directory [...].”
	//
	// Since Walk does not traverse symlinks itself, its behavior should depend on
	// whether the path passed to Walk ends in a slash: if it does not end in a slash,
	// Walk should report the symlink itself (since it is the last pathname component);
	// but if it does end in a slash, Walk should walk the directory to which the symlink
	// refers (since it must be fully resolved before walking).
	for _, tt := range []struct {
		desc      string
		root      string
		want      []string
		buggyGOOS []string
	}{
		{
			desc: "no slash",
			root: link,
			want: []string{link},
		},
		{
			desc: "slash",
			root: link + string(filepath.Separator),
			want: []string{link, filepath.Join(link, "foo")},
		},
		{
			desc: "abs no slash",
			root: abslink,
			want: []string{abslink},
		},
		{
			desc: "abs with slash",
			root: abslink + string(filepath.Separator),
			want: []string{abslink, filepath.Join(abslink, "foo")},
		},
		{
			desc: "double link no slash",
			root: linklink,
			want: []string{linklink},
		},
		{
			desc:      "double link with slash",
			root:      linklink + string(filepath.Separator),
			want:      []string{linklink, filepath.Join(linklink, "foo")},
			buggyGOOS: []string{"darwin", "ios"}, // https://go.dev/issue/59586
		},
	} {
		tt := tt
		t.Run(tt.desc, func(t *testing.T) {
			var walked []string
			err := filepath.Walk(tt.root, func(path string, info fs.FileInfo, err error) error {
				if err != nil {
					return err
				}
				t.Logf("%#q: %v", path, info.Mode())
				walked = append(walked, filepath.Clean(path))
				return nil
			})
			if err != nil {
				t.Fatal(err)
			}

			if !slices.Equal(walked, tt.want) {
				t.Logf("Walk(%#q) visited %#q; want %#q", tt.root, walked, tt.want)
				if slices.Contains(tt.buggyGOOS, runtime.GOOS) {
					t.Logf("(ignoring known bug on %v)", runtime.GOOS)
				} else {
					t.Fail()
				}
			}
		})
	}
}

var basetests = []PathTest{
	{"", "."},
	{".", "."},
	{"/.", "."},
	{"/", "/"},
	{"////", "/"},
	{"x/", "x"},
	{"abc", "abc"},
	{"abc/def", "def"},
	{"a/b/.x", ".x"},
	{"a/b/c.", "c."},
	{"a/b/c.x", "c.x"},
}

var winbasetests = []PathTest{
	{`c:\`, `\`},
	{`c:.`, `.`},
	{`c:\a\b`, `b`},
	{`c:a\b`, `b`},
	{`c:a\b\c`, `c`},
	{`\\host\share\`, `\`},
	{`\\host\share\a`, `a`},
	{`\\host\share\a\b`, `b`},
}

func TestBase(t *testing.T) {
	tests := basetests
	if runtime.GOOS == "windows" {
		// make unix tests work on windows
		for i := range tests {
			tests[i].result = filepath.Clean(tests[i].result)
		}
		// add windows specific tests
		tests = append(tests, winbasetests...)
	}
	for _, test := range tests {
		if s := filepath.Base(test.path); s != test.result {
			t.Errorf("Base(%q) = %q, want %q", test.path, s, test.result)
		}
	}
}

var dirtests = []PathTest{
	{"", "."},
	{".", "."},
	{"/.", "/"},
	{"/", "/"},
	{"/foo", "/"},
	{"x/", "x"},
	{"abc", "."},
	{"abc/def", "abc"},
	{"a/b/.x", "a/b"},
	{"a/b/c.", "a/b"},
	{"a/b/c.x", "a/b"},
}

var nonwindirtests = []PathTest{
	{"////", "/"},
}

var windirtests = []PathTest{
	{`c:\`, `c:\`},
	{`c:.`, `c:.`},
	{`c:\a\b`, `c:\a`},
	{`c:a\b`, `c:a`},
	{`c:a\b\c`, `c:a\b`},
	{`\\host\share`, `\\host\share`},
	{`\\host\share\`, `\\host\share\`},
	{`\\host\share\a`, `\\host\share\`},
	{`\\host\share\a\b`, `\\host\share\a`},
	{`\\\\`, `\\\\`},
}

func TestDir(t *testing.T) {
	tests := dirtests
	if runtime.GOOS == "windows" {
		// make unix tests work on windows
		for i := range tests {
			tests[i].result = filepath.Clean(tests[i].result)
		}
		// add windows specific tests
		tests = append(tests, windirtests...)
	} else {
		tests = append(tests, nonwindirtests...)
	}
	for _, test := range tests {
		if s := filepath.Dir(test.path); s != test.result {
			t.Errorf("Dir(%q) = %q, want %q", test.path, s, test.result)
		}
	}
}

type IsAbsTest struct {
	path  string
	isAbs bool
}

var isabstests = []IsAbsTest{
	{"", false},
	{"/", true},
	{"/usr/bin/gcc", true},
	{"..", false},
	{"/a/../bb", true},
	{".", false},
	{"./", false},
	{"lala", false},
}

var winisabstests = []IsAbsTest{
	{`C:\`, true},
	{`c\`, false},
	{`c::`, false},
	{`c:`, false},
	{`/`, false},
	{`\`, false},
	{`\Windows`, false},
	{`c:a\b`, false},
	{`c:\a\b`, true},
	{`c:/a/b`, true},
	{`\\host\share`, true},
	{`\\host\share\`, true},
	{`\\host\share\foo`, true},
	{`//host/share/foo/bar`, true},
	{`\\?\a\b\c`, true},
	{`\??\a\b\c`, true},
}

func TestIsAbs(t *testing.T) {
	var tests []IsAbsTest
	if runtime.GOOS == "windows" {
		tests = append(tests, winisabstests...)
		// All non-windows tests should fail, because they have no volume letter.
		for _, test := range isabstests {
			tests = append(tests, IsAbsTest{test.path, false})
		}
		// All non-windows test should work as intended if prefixed with volume letter.
		for _, test := range isabstests {
			tests = append(tests, IsAbsTest{"c:" + test.path, test.isAbs})
		}
	} else {
		tests = isabstests
	}

	for _, test := range tests {
		if r := filepath.IsAbs(test.path); r != test.isAbs {
			t.Errorf("IsAbs(%q) = %v, want %v", test.path, r, test.isAbs)
		}
	}
}

type EvalSymlinksTest struct {
	// If dest is empty, the path is created; otherwise the dest is symlinked to the path.
	path, dest string
}

var EvalSymlinksTestDirs = []EvalSymlinksTest{
	{"test", ""},
	{"test/dir", ""},
	{"test/dir/link3", "../../"},
	{"test/link1", "../test"},
	{"test/link2", "dir"},
	{"test/linkabs", "/"},
	{"test/link4", "../test2"},
	{"test2", "test/dir"},
	// Issue 23444.
	{"src", ""},
	{"src/pool", ""},
	{"src/pool/test", ""},
	{"src/versions", ""},
	{"src/versions/current", "../../version"},
	{"src/versions/v1", ""},
	{"src/versions/v1/modules", ""},
	{"src/versions/v1/modules/test", "../../../pool/test"},
	{"version", "src/versions/v1"},
}

var EvalSymlinksTests = []EvalSymlinksTest{
	{"test", "test"},
	{"test/dir", "test/dir"},
	{"test/dir/../..", "."},
	{"test/link1", "test"},
	{"test/link2", "test/dir"},
	{"test/link1/dir", "test/dir"},
	{"test/link2/..", "test"},
	{"test/dir/link3", "."},
	{"test/link2/link3/test", "test"},
	{"test/linkabs", "/"},
	{"test/link4/..", "test"},
	{"src/versions/current/modules/test", "src/pool/test"},
}

// simpleJoin builds a file name from the directory and path.
// It does not use Join because we don't want ".." to be evaluated.
func simpleJoin(dir, path string) string {
	return dir + string(filepath.Separator) + path
}

func testEvalSymlinks(t *testing.T, path, want string) {
	have, err := filepath.EvalSymlinks(path)
	if err != nil {
		t.Errorf("EvalSymlinks(%q) error: %v", path, err)
		return
	}
	if filepath.Clean(have) != filepath.Clean(want) {
		t.Errorf("EvalSymlinks(%q) returns %q, want %q", path, have, want)
	}
}

func testEvalSymlinksAfterChdir(t *testing.T, wd, path, want string) {
	t.Chdir(wd)
	have, err := filepath.EvalSymlinks(path)
	if err != nil {
		t.Errorf("EvalSymlinks(%q) in %q directory error: %v", path, wd, err)
		return
	}
	if filepath.Clean(have) != filepath.Clean(want) {
		t.Errorf("EvalSymlinks(%q) in %q directory returns %q, want %q", path, wd, have, want)
	}
}

func TestEvalSymlinks(t *testing.T) {
	testenv.MustHaveSymlink(t)

	tmpDir := t.TempDir()

	// /tmp may itself be a symlink! Avoid the confusion, although
	// it means trusting the thing we're testing.
	var err error
	tmpDir, err = filepath.EvalSymlinks(tmpDir)
	if err != nil {
		t.Fatal("eval symlink for tmp dir:", err)
	}

	// Create the symlink farm using relative paths.
	for _, d := range EvalSymlinksTestDirs {
		var err error
		path := simpleJoin(tmpDir, d.path)
		if d.dest == "" {
			err = os.Mkdir(path, 0755)
		} else {
			err = os.Symlink(d.dest, path)
		}
		if err != nil {
			t.Fatal(err)
		}
	}

	// Evaluate the symlink farm.
	for _, test := range EvalSymlinksTests {
		path := simpleJoin(tmpDir, test.path)

		dest := simpleJoin(tmpDir, test.dest)
		if filepath.IsAbs(test.dest) || os.IsPathSeparator(test.dest[0]) {
			dest = test.dest
		}
		testEvalSymlinks(t, path, dest)

		// test EvalSymlinks(".")
		testEvalSymlinksAfterChdir(t, path, ".", ".")

		// test EvalSymlinks("C:.") on Windows
		if runtime.GOOS == "windows" {
			volDot := filepath.VolumeName(tmpDir) + "."
			testEvalSymlinksAfterChdir(t, path, volDot, volDot)
		}

		// test EvalSymlinks(".."+path)
		dotdotPath := simpleJoin("..", test.dest)
		if filepath.IsAbs(test.dest) || os.IsPathSeparator(test.dest[0]) {
			dotdotPath = test.dest
		}
		testEvalSymlinksAfterChdir(t,
			simpleJoin(tmpDir, "test"),
			simpleJoin("..", test.path),
			dotdotPath)

		// test EvalSymlinks(p) where p is relative path
		testEvalSymlinksAfterChdir(t, tmpDir, test.path, test.dest)
	}
}

func TestEvalSymlinksIsNotExist(t *testing.T) {
	testenv.MustHaveSymlink(t)
	t.Chdir(t.TempDir())

	_, err := filepath.EvalSymlinks("notexist")
	if !os.IsNotExist(err) {
		t.Errorf("expected the file is not found, got %v\n", err)
	}

	err = os.Symlink("notexist", "link")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove("link")

	_, err = filepath.EvalSymlinks("link")
	if !os.IsNotExist(err) {
		t.Errorf("expected the file is not found, got %v\n", err)
	}
}

func TestIssue13582(t *testing.T) {
	testenv.MustHaveSymlink(t)

	tmpDir := t.TempDir()

	dir := filepath.Join(tmpDir, "dir")
	err := os.Mkdir(dir, 0755)
	if err != nil {
		t.Fatal(err)
	}
	linkToDir := filepath.Join(tmpDir, "link_to_dir")
	err = os.Symlink(dir, linkToDir)
	if err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(linkToDir, "file")
	err = os.WriteFile(file, nil, 0644)
	if err != nil {
		t.Fatal(err)
	}
	link1 := filepath.Join(linkToDir, "link1")
	err = os.Symlink(file, link1)
	if err != nil {
		t.Fatal(err)
	}
	link2 := filepath.Join(linkToDir, "link2")
	err = os.Symlink(link1, link2)
	if err != nil {
		t.Fatal(err)
	}

	// /tmp may itself be a symlink!
	realTmpDir, err := filepath.EvalSymlinks(tmpDir)
	if err != nil {
		t.Fatal(err)
	}
	realDir := filepath.Join(realTmpDir, "dir")
	realFile := filepath.Join(realDir, "file")

	tests := []struct {
		path, want string
	}{
		{dir, realDir},
		{linkToDir, realDir},
		{file, realFile},
		{link1, realFile},
		{link2, realFile},
	}
	for i, test := range tests {
		have, err := filepath.EvalSymlinks(test.path)
		if err != nil {
			t.Fatal(err)
		}
		if have != test.want {
			t.Errorf("test#%d: EvalSymlinks(%q) returns %q, want %q", i, test.path, have, test.want)
		}
	}
}

// Issue 57905.
func TestRelativeSymlinkToAbsolute(t *testing.T) {
	testenv.MustHaveSymlink(t)
	// Not parallel: uses t.Chdir.

	tmpDir := t.TempDir()
	t.Chdir(tmpDir)

	// Create "link" in the current working directory as a symlink to an arbitrary
	// absolute path. On macOS, this path is likely to begin with a symlink
	// itself: generally either in /var (symlinked to "private/var") or /tmp
	// (symlinked to "private/tmp").
	if err := os.Symlink(tmpDir, "link"); err != nil {
		t.Fatal(err)
	}
	t.Logf(`os.Symlink(%q, "link")`, tmpDir)

	p, err := filepath.EvalSymlinks("link")
	if err != nil {
		t.Fatalf(`EvalSymlinks("link"): %v`, err)
	}
	want, err := filepath.EvalSymlinks(tmpDir)
	if err != nil {
		t.Fatalf(`EvalSymlinks(%q): %v`, tmpDir, err)
	}
	if p != want {
		t.Errorf(`EvalSymlinks("link"
```