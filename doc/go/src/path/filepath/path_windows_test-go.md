Response:
Let's break down the thought process for analyzing this Go test file.

**1. Initial Scan and Keywords:**

The first step is a quick scan of the file, looking for recognizable keywords and patterns. I immediately see:

* `package filepath_test`: This tells me it's a test file for the `path/filepath` package.
* `import`:  A standard Go import section, listing dependencies like `os`, `exec`, `testing`, etc. This hints at the types of operations being tested (file system interactions, running external commands).
* `func Test...`:  This is the standard Go testing function naming convention. Each function starting with `Test` will be run as a test. I can see several test functions like `TestWinSplitListTestsAreValid`, `TestWindowsEvalSymlinks`, `TestEvalSymlinksCanonicalNames`, etc. Each of these is likely testing a specific aspect of the `filepath` package.
* Specific function names from the `filepath` package appear within the tests: `filepath.Clean`, `filepath.VolumeName`, `filepath.Join`, `filepath.EvalSymlinks`, `filepath.ToNorm`, `filepath.Glob`, `filepath.Abs`. This is a crucial clue about the functionality being tested.
* Windows-specific things:  References to `%ComSpec%`, `SystemRoot`, `mklink`, `fsutil`, volume names like `C:`, UNC paths (`\\host\share`), and the frequent use of backslashes in paths. This clearly indicates that the file is focused on Windows-specific behavior of `path/filepath`.

**2. Analyzing Individual Test Functions:**

Now, I start looking at the individual test functions to understand their purpose:

* **`TestWinSplitListTestsAreValid` and `testWinSplitListTestIsValid`:**  The names suggest testing the `SplitList` function (though I don't see it directly in the provided snippet, it's implied by the test setup). The code creates temporary directories and files (`printdir.cmd`) and then runs a command (`comspec /c cmdfile`) with different `Path` environment variables. This likely tests how `SplitList` parses environment variables like `PATH` on Windows, especially considering the handling of relative paths and ensuring the commands are found.

* **`TestWindowsEvalSymlinks`:** The name strongly suggests testing the `EvalSymlinks` function on Windows. The use of `testenv.MustHaveSymlink(t)` confirms this. The test creates symbolic links and then calls `testEvalSymlinks` and `testEvalSymlinksAfterChdir`. This focuses on resolving symbolic links under different conditions (initial path, after changing directories).

* **`TestEvalSymlinksCanonicalNames`:** This test focuses on whether `EvalSymlinks` returns the "canonical" (standardized) path on Windows. It creates directories with mixed casing and then checks if `EvalSymlinks` returns the correct case-insensitive path. The section about 8.3 names is also important here, indicating a test of how `EvalSymlinks` behaves when short 8.3 filenames are involved (or disabled).

* **`TestEvalSymlinksCanonicalNamesWith8dot3Disabled`:** This test explicitly manipulates the 8.3 filename generation setting on a volume using `fsutil` and then reruns `TestEvalSymlinksCanonicalNames`. This is testing the interaction of `EvalSymlinks` with that specific Windows setting.

* **`TestToNorm`:**  The name suggests testing a `ToNorm` function (which is present in the code). The tests compare the output of `filepath.ToNorm` with expected normalized paths, covering various path formats (absolute, relative, UNC). The `stubBase` function suggests the `ToNorm` function likely takes a base normalization function as an argument.

* **`TestUNC`:** This seems like a stress test or a test for potential infinite recursion issues when dealing with UNC paths and `filepath.Glob`.

* **`testWalkMklink`, `TestWalkDirectoryJunction`, `TestWalkDirectorySymlink`:** These tests are clearly about testing the behavior of `filepath.Walk` (though not explicitly in the snippet) when encountering directory junctions and symbolic links created using `mklink`.

* **`TestEvalSymlinksJunctionToVolumeID`:** This is a more specific test for `EvalSymlinks` dealing with directory junctions that point to volume IDs, a Windows-specific feature.

* **`TestEvalSymlinksMountPointRecursion`:**  Focuses on ensuring `EvalSymlinks` doesn't get stuck in infinite loops when encountering recursive mount points.

* **`TestNTNamespaceSymlink`:** This tests how `EvalSymlinks` handles symbolic links that target the NT namespace (using volume GUIDs).

* **`TestIssue52476`:**  This is a regression test for a specific bug (issue 52476) in `filepath.Join`. It tests edge cases of joining paths with drive letters and relative components.

* **`TestAbsWindows`:** This test focuses on the `filepath.Abs` function on Windows, verifying it correctly handles absolute paths, UNC paths, and device names like `NUL` and `COM1`.

**3. Identifying Go Feature Implementations:**

Based on the tested functions, I can infer the Go language features being implemented:

* **Path manipulation:** Functions like `Clean`, `Join`, `VolumeName`, `ToNorm` deal with parsing, cleaning, and manipulating file paths according to Windows conventions.
* **Symbolic links and junctions:**  `EvalSymlinks` is the core function for resolving symbolic links and directory junctions. The tests cover various scenarios, including relative and absolute links, and links to volume IDs.
* **File system interaction:** The tests use `os.MkdirAll`, `os.Stat`, `os.Symlink`, `os.Remove`, and `os.WriteFile`, indicating that the `filepath` package relies on these lower-level OS functions.
* **External command execution:** The use of `exec.Command` to run `cmd`, `mklink`, and `fsutil` shows that the tests (and potentially the `filepath` package itself in some edge cases) need to interact with the operating system's command-line tools.

**4. Code Examples and Assumptions:**

For code examples, I choose functions that are explicitly tested and illustrate common use cases. I make reasonable assumptions about input and output based on the test logic.

**5. Command-Line Argument Handling:**

The `-run_fs_modify_tests` flag is the only command-line argument processing in this snippet. I note its purpose and how it controls the execution of tests that modify file system settings.

**6. Common Mistakes:**

I consider potential pitfalls for users based on the test scenarios, such as the complexities of symbolic links, junctions, and the differences between relative and absolute paths on Windows.

**7. Language and Structure:**

Finally, I structure the answer in clear, concise Chinese, addressing each part of the prompt. I use code blocks for examples and provide explanations for each function and test.

This detailed process of scanning, analyzing, inferring, and synthesizing information allows for a comprehensive understanding of the Go test file and the underlying `path/filepath` functionality it covers on Windows.
这个`go/src/path/filepath/path_windows_test.go` 文件是 Go 语言标准库中 `path/filepath` 包在 Windows 操作系统下的测试代码。它包含了多个测试函数，用于验证 `path/filepath` 包在 Windows 下的路径操作行为是否符合预期。

以下是该文件主要的功能点：

1. **测试 `SplitList` 函数在 Windows 下的行为:**  `TestWinSplitListTestsAreValid` 和 `testWinSplitListTestIsValid` 函数旨在测试 `filepath.SplitList` 函数在 Windows 下如何正确地分割由分号分隔的路径列表（例如 `PATH` 环境变量）。它通过创建临时目录和包含特定内容的 `.cmd` 文件，模拟程序在不同路径下查找可执行文件的过程，以此验证 `SplitList` 的结果是否正确。

   **Go 代码示例 (假设 `SplitListTest` 结构体和 `winsplitlisttests` 变量已定义):**

   ```go
   package main

   import (
       "fmt"
       "path/filepath"
   )

   func main() {
       pathList := `C:\Windows\System32;C:\Program Files\Go\bin;.`
       splitPaths := filepath.SplitList(pathList)
       fmt.Println(splitPaths) // 输出类似: [C:\Windows\System32 C:\Program Files\Go\bin .]
   }
   ```

   **假设的输入与输出:**

   * **输入:**  `pathList = "C:\\Windows\\System32;C:\\Program Files\\Go\\bin;."`
   * **输出:** `[]string{"C:\\Windows\\System32", "C:\\Program Files\\Go\\bin", "."}`

2. **测试 `EvalSymlinks` 函数在 Windows 下对符号链接和目录连接点的解析:** `TestWindowsEvalSymlinks`, `TestEvalSymlinksCanonicalNames`, `TestEvalSymlinksCanonicalNamesWith8dot3Disabled`, `TestEvalSymlinksJunctionToVolumeID`, `TestEvalSymlinksMountPointRecursion`, 和 `TestNTNamespaceSymlink` 等函数主要测试 `filepath.EvalSymlinks` 函数在 Windows 下如何解析符号链接 (symbolic links) 和目录连接点 (directory junctions)。这些测试涵盖了各种情况，例如：
   * 解析绝对路径和相对路径的符号链接。
   * 解析指向目录和文件的符号链接。
   * 解析目录连接点。
   * 测试当 8.3 短文件名被禁用时 `EvalSymlinks` 的行为。
   * 测试 `EvalSymlinks` 如何处理指向卷 ID 的目录连接点。
   * 确保 `EvalSymlinks` 不会陷入递归挂载点的循环。
   * 测试 `EvalSymlinks` 如何处理指向 NT 命名空间的符号链接。

   **Go 代码示例:**

   ```go
   package main

   import (
       "fmt"
       "os"
       "path/filepath"
   )

   func main() {
       // 假设在 C:\temp 目录下创建了一个名为 "mylink" 的符号链接，指向 "C:\windows\system32"
       linkPath := `C:\temp\mylink`
       resolvedPath, err := filepath.EvalSymlinks(linkPath)
       if err != nil {
           fmt.Println("解析符号链接失败:", err)
           return
       }
       fmt.Println("解析后的路径:", resolvedPath) // 输出类似: C:\windows\system32
   }
   ```

   **假设的输入与输出:**

   * **假设:** 存在一个符号链接 `C:\temp\mylink` 指向 `C:\windows\system32`。
   * **输入:** `linkPath = "C:\\temp\\mylink"`
   * **输出:** `resolvedPath = "C:\\windows\\system32"`

3. **测试 `ToNorm` 函数:** `TestToNorm` 函数测试 `filepath.ToNorm` 函数，该函数用于将路径转换为规范化的形式，通常是将路径中的斜杠转换为反斜杠，并将盘符转换为大写。

   **Go 代码示例:**

   ```go
   package main

   import (
       "fmt"
       "path/filepath"
   )

   func main() {
       path := "c:/users/test/file.txt"
       normalizedPath, err := filepath.ToNorm(path, filepath.Clean) // 使用 filepath.Clean 作为 base 函数
       if err != nil {
           fmt.Println("规范化路径失败:", err)
           return
       }
       fmt.Println("规范化后的路径:", normalizedPath) // 输出: C:\users\test\file.txt
   }
   ```

   **假设的输入与输出:**

   * **输入:** `path = "c:/users/test/file.txt"`
   * **输出:** `normalizedPath = "C:\\users\\test\\file.txt"`

4. **测试处理 UNC 路径的能力:** `TestUNC` 函数主要测试 `filepath` 包是否能正确处理 UNC (Universal Naming Convention) 路径，并防止在处理 UNC 路径时出现无限递归等问题。

   **Go 代码示例:**

   ```go
   package main

   import (
       "fmt"
       "path/filepath"
   )

   func main() {
       uncPath := `\\server\share\folder\file.txt`
       matches, err := filepath.Glob(uncPath + "*")
       if err != nil {
           fmt.Println("Glob 失败:", err)
           return
       }
       fmt.Println("匹配的文件:", matches) // 输出可能匹配到的文件列表
   }
   ```

   **假设的输入与输出:**

   * **假设:** 在 `\\server\share\folder\` 目录下存在文件 `file.txt` 和 `file2.txt`。
   * **输入:** `uncPath = "\\\\server\\share\\folder\\file.txt"`
   * **输出:** `matches = []string{"\\\\server\\share\\folder\\file.txt", "\\\\server\\share\\folder\\file2.txt"}` (取决于实际文件系统)

5. **测试与 `mklink` 命令的交互 (通过 `testWalkMklink`, `TestWalkDirectoryJunction`, `TestWalkDirectorySymlink`):** 这些测试函数通过调用 Windows 的 `mklink` 命令创建符号链接和目录连接点，并结合 `filepath.Walk` (虽然这段代码中没有直接展示 `filepath.Walk` 的使用，但测试名称暗示了这一点) 来验证 `filepath` 包在遍历包含符号链接和连接点的目录时的行为是否正确。

6. **测试 `Abs` 函数在 Windows 下的行为:** `TestAbsWindows` 函数测试 `filepath.Abs` 函数在 Windows 下如何将相对路径转换为绝对路径，并处理设备名称（如 `NUL`, `COM1`）。

   **Go 代码示例:**

   ```go
   package main

   import (
       "fmt"
       "os"
       "path/filepath"
   )

   func main() {
       currentDir, _ := os.Getwd()
       relativePath := "file.txt"
       absPath, err := filepath.Abs(relativePath)
       if err != nil {
           fmt.Println("获取绝对路径失败:", err)
           return
       }
       fmt.Println("绝对路径:", absPath) // 输出类似: C:\current\working\directory\file.txt
   }
   ```

   **假设的输入与输出:**

   * **假设:** 当前工作目录是 `C:\current\working\directory`。
   * **输入:** `relativePath = "file.txt"`
   * **输出:** `absPath = "C:\\current\\working\\directory\\file.txt"`

**代码推理:**

代码中频繁使用了 `os/exec` 包来执行 Windows 的命令行工具，例如 `cmd`，`mklink` 和 `fsutil`。这表明这些测试依赖于底层的操作系统功能来创建和操作文件系统对象，以此来验证 `path/filepath` 包的正确性。

**命令行参数的具体处理:**

该文件中定义了一个名为 `runFSModifyTests` 的 `flag.Bool` 类型的变量：

```go
var runFSModifyTests = flag.Bool("run_fs_modify_tests", false, "run tests which modify filesystem parameters")
```

这个命令行参数 `-run_fs_modify_tests` 用于控制是否运行那些会修改文件系统参数的测试，例如 `TestEvalSymlinksCanonicalNamesWith8dot3Disabled`，它会修改卷的 8.3 短文件名生成设置。

* **默认值:** `false`，意味着默认情况下，这些修改文件系统的测试不会被执行。
* **使用方式:**  在运行 `go test` 命令时，加上 `-run_fs_modify_tests` 参数，例如：`go test -run_fs_modify_tests`，这样就会执行那些修改文件系统设置的测试。

**使用者易犯错的点:**

在使用 `path/filepath` 包时，Windows 用户可能会犯以下错误：

1. **混淆正斜杠和反斜杠:** Windows 路径通常使用反斜杠 `\` 作为分隔符，而 Go 字符串中反斜杠需要转义，容易出错。虽然 `path/filepath` 包的函数通常能处理两种斜杠，但显式使用反斜杠可能更符合 Windows 习惯。
2. **不理解相对路径的基准:** 在进行相对路径操作时，可能会对当前工作目录的理解有偏差，导致路径解析错误。
3. **不了解符号链接和目录连接点的区别和行为:**  Windows 下的符号链接和目录连接点在某些方面行为不同，例如删除链接本身是否会影响目标。不了解这些差异可能导致对 `EvalSymlinks` 等函数的行为产生误解。
4. **忽略大小写不敏感的文件系统:** Windows 文件系统通常大小写不敏感，但在比较路径字符串时需要注意这一点。`path/filepath` 包的某些函数会进行规范化处理，例如 `ToNorm`。

**例子说明混淆斜杠的问题:**

```go
package main

import (
	"fmt"
	"path/filepath"
)

func main() {
	// 错误的写法，可能在其他系统上正常，但在 Windows 上不够规范
	path1 := "C:/Users/Test/file.txt"
	fmt.Println(path1) // 输出: C:/Users/Test/file.txt

	// 推荐的写法，更符合 Windows 习惯
	path2 := "C:\\Users\\Test\\file.txt"
	fmt.Println(path2) // 输出: C:\Users\Test\file.txt

	// filepath 包通常可以处理正斜杠
	cleanedPath := filepath.Clean(path1)
	fmt.Println(cleanedPath) // 输出: C:\Users\Test\file.txt
}
```

总而言之，这个测试文件全面地测试了 `path/filepath` 包在 Windows 操作系统下的各种路径操作功能，确保其在 Windows 环境中的稳定性和正确性。

### 提示词
```
这是路径为go/src/path/filepath/path_windows_test.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
```

### 源代码
```go
// Copyright 2013 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package filepath_test

import (
	"flag"
	"fmt"
	"internal/godebug"
	"internal/testenv"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"runtime/debug"
	"slices"
	"strings"
	"testing"
)

func TestWinSplitListTestsAreValid(t *testing.T) {
	comspec := os.Getenv("ComSpec")
	if comspec == "" {
		t.Fatal("%ComSpec% must be set")
	}

	for ti, tt := range winsplitlisttests {
		testWinSplitListTestIsValid(t, ti, tt, comspec)
	}
}

func testWinSplitListTestIsValid(t *testing.T, ti int, tt SplitListTest,
	comspec string) {

	const (
		cmdfile             = `printdir.cmd`
		perm    fs.FileMode = 0700
	)

	tmp := t.TempDir()
	for i, d := range tt.result {
		if d == "" {
			continue
		}
		if cd := filepath.Clean(d); filepath.VolumeName(cd) != "" ||
			cd[0] == '\\' || cd == ".." || (len(cd) >= 3 && cd[0:3] == `..\`) {
			t.Errorf("%d,%d: %#q refers outside working directory", ti, i, d)
			return
		}
		dd := filepath.Join(tmp, d)
		if _, err := os.Stat(dd); err == nil {
			t.Errorf("%d,%d: %#q already exists", ti, i, d)
			return
		}
		if err := os.MkdirAll(dd, perm); err != nil {
			t.Errorf("%d,%d: MkdirAll(%#q) failed: %v", ti, i, dd, err)
			return
		}
		fn, data := filepath.Join(dd, cmdfile), []byte("@echo "+d+"\r\n")
		if err := os.WriteFile(fn, data, perm); err != nil {
			t.Errorf("%d,%d: WriteFile(%#q) failed: %v", ti, i, fn, err)
			return
		}
	}

	// on some systems, SystemRoot is required for cmd to work
	systemRoot := os.Getenv("SystemRoot")

	for i, d := range tt.result {
		if d == "" {
			continue
		}
		exp := []byte(d + "\r\n")
		cmd := &exec.Cmd{
			Path: comspec,
			Args: []string{`/c`, cmdfile},
			Env:  []string{`Path=` + systemRoot + "/System32;" + tt.list, `SystemRoot=` + systemRoot},
			Dir:  tmp,
		}
		out, err := cmd.CombinedOutput()
		switch {
		case err != nil:
			t.Errorf("%d,%d: execution error %v\n%q", ti, i, err, out)
			return
		case !slices.Equal(out, exp):
			t.Errorf("%d,%d: expected %#q, got %#q", ti, i, exp, out)
			return
		default:
			// unshadow cmdfile in next directory
			err = os.Remove(filepath.Join(tmp, d, cmdfile))
			if err != nil {
				t.Fatalf("Remove test command failed: %v", err)
			}
		}
	}
}

func TestWindowsEvalSymlinks(t *testing.T) {
	testenv.MustHaveSymlink(t)

	tmpDir := tempDirCanonical(t)

	if len(tmpDir) < 3 {
		t.Fatalf("tmpDir path %q is too short", tmpDir)
	}
	if tmpDir[1] != ':' {
		t.Fatalf("tmpDir path %q must have drive letter in it", tmpDir)
	}
	test := EvalSymlinksTest{"test/linkabswin", tmpDir[:3]}

	// Create the symlink farm using relative paths.
	testdirs := append(EvalSymlinksTestDirs, test)
	for _, d := range testdirs {
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

	path := simpleJoin(tmpDir, test.path)

	testEvalSymlinks(t, path, test.dest)

	testEvalSymlinksAfterChdir(t, path, ".", test.dest)

	testEvalSymlinksAfterChdir(t,
		path,
		filepath.VolumeName(tmpDir)+".",
		test.dest)

	testEvalSymlinksAfterChdir(t,
		simpleJoin(tmpDir, "test"),
		simpleJoin("..", test.path),
		test.dest)

	testEvalSymlinksAfterChdir(t, tmpDir, test.path, test.dest)
}

// TestEvalSymlinksCanonicalNames verify that EvalSymlinks
// returns "canonical" path names on windows.
func TestEvalSymlinksCanonicalNames(t *testing.T) {
	ctmp := tempDirCanonical(t)
	dirs := []string{
		"test",
		"test/dir",
		"testing_long_dir",
		"TEST2",
	}

	for _, d := range dirs {
		dir := filepath.Join(ctmp, d)
		err := os.Mkdir(dir, 0755)
		if err != nil {
			t.Fatal(err)
		}
		cname, err := filepath.EvalSymlinks(dir)
		if err != nil {
			t.Errorf("EvalSymlinks(%q) error: %v", dir, err)
			continue
		}
		if dir != cname {
			t.Errorf("EvalSymlinks(%q) returns %q, but should return %q", dir, cname, dir)
			continue
		}
		// test non-canonical names
		test := strings.ToUpper(dir)
		p, err := filepath.EvalSymlinks(test)
		if err != nil {
			t.Errorf("EvalSymlinks(%q) error: %v", test, err)
			continue
		}
		if p != cname {
			t.Errorf("EvalSymlinks(%q) returns %q, but should return %q", test, p, cname)
			continue
		}
		// another test
		test = strings.ToLower(dir)
		p, err = filepath.EvalSymlinks(test)
		if err != nil {
			t.Errorf("EvalSymlinks(%q) error: %v", test, err)
			continue
		}
		if p != cname {
			t.Errorf("EvalSymlinks(%q) returns %q, but should return %q", test, p, cname)
			continue
		}
	}
}

// checkVolume8dot3Setting runs "fsutil 8dot3name query c:" command
// (where c: is vol parameter) to discover "8dot3 name creation state".
// The state is combination of 2 flags. The global flag controls if it
// is per volume or global setting:
//
//	0 - Enable 8dot3 name creation on all volumes on the system
//	1 - Disable 8dot3 name creation on all volumes on the system
//	2 - Set 8dot3 name creation on a per volume basis
//	3 - Disable 8dot3 name creation on all volumes except the system volume
//
// If global flag is set to 2, then per-volume flag needs to be examined:
//
//	0 - Enable 8dot3 name creation on this volume
//	1 - Disable 8dot3 name creation on this volume
//
// checkVolume8dot3Setting verifies that "8dot3 name creation" flags
// are set to 2 and 0, if enabled parameter is true, or 2 and 1, if enabled
// is false. Otherwise checkVolume8dot3Setting returns error.
func checkVolume8dot3Setting(vol string, enabled bool) error {
	// It appears, on some systems "fsutil 8dot3name query ..." command always
	// exits with error. Ignore exit code, and look at fsutil output instead.
	out, _ := exec.Command("fsutil", "8dot3name", "query", vol).CombinedOutput()
	// Check that system has "Volume level setting" set.
	expected := "The registry state of NtfsDisable8dot3NameCreation is 2, the default (Volume level setting)"
	if !strings.Contains(string(out), expected) {
		// Windows 10 version of fsutil has different output message.
		expectedWindow10 := "The registry state is: 2 (Per volume setting - the default)"
		if !strings.Contains(string(out), expectedWindow10) {
			return fmt.Errorf("fsutil output should contain %q, but is %q", expected, string(out))
		}
	}
	// Now check the volume setting.
	expected = "Based on the above two settings, 8dot3 name creation is %s on %s"
	if enabled {
		expected = fmt.Sprintf(expected, "enabled", vol)
	} else {
		expected = fmt.Sprintf(expected, "disabled", vol)
	}
	if !strings.Contains(string(out), expected) {
		return fmt.Errorf("unexpected fsutil output: %q", string(out))
	}
	return nil
}

func setVolume8dot3Setting(vol string, enabled bool) error {
	cmd := []string{"fsutil", "8dot3name", "set", vol}
	if enabled {
		cmd = append(cmd, "0")
	} else {
		cmd = append(cmd, "1")
	}
	// It appears, on some systems "fsutil 8dot3name set ..." command always
	// exits with error. Ignore exit code, and look at fsutil output instead.
	out, _ := exec.Command(cmd[0], cmd[1:]...).CombinedOutput()
	if string(out) != "\r\nSuccessfully set 8dot3name behavior.\r\n" {
		// Windows 10 version of fsutil has different output message.
		expectedWindow10 := "Successfully %s 8dot3name generation on %s\r\n"
		if enabled {
			expectedWindow10 = fmt.Sprintf(expectedWindow10, "enabled", vol)
		} else {
			expectedWindow10 = fmt.Sprintf(expectedWindow10, "disabled", vol)
		}
		if string(out) != expectedWindow10 {
			return fmt.Errorf("%v command failed: %q", cmd, string(out))
		}
	}
	return nil
}

var runFSModifyTests = flag.Bool("run_fs_modify_tests", false, "run tests which modify filesystem parameters")

// This test assumes registry state of NtfsDisable8dot3NameCreation is 2,
// the default (Volume level setting).
func TestEvalSymlinksCanonicalNamesWith8dot3Disabled(t *testing.T) {
	if !*runFSModifyTests {
		t.Skip("skipping test that modifies file system setting; enable with -run_fs_modify_tests")
	}
	tempVol := filepath.VolumeName(os.TempDir())
	if len(tempVol) != 2 {
		t.Fatalf("unexpected temp volume name %q", tempVol)
	}

	err := checkVolume8dot3Setting(tempVol, true)
	if err != nil {
		t.Fatal(err)
	}
	err = setVolume8dot3Setting(tempVol, false)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		err := setVolume8dot3Setting(tempVol, true)
		if err != nil {
			t.Fatal(err)
		}
		err = checkVolume8dot3Setting(tempVol, true)
		if err != nil {
			t.Fatal(err)
		}
	}()
	err = checkVolume8dot3Setting(tempVol, false)
	if err != nil {
		t.Fatal(err)
	}
	TestEvalSymlinksCanonicalNames(t)
}

func TestToNorm(t *testing.T) {
	stubBase := func(path string) (string, error) {
		vol := filepath.VolumeName(path)
		path = path[len(vol):]

		if strings.Contains(path, "/") {
			return "", fmt.Errorf("invalid path is given to base: %s", vol+path)
		}

		if path == "" || path == "." || path == `\` {
			return "", fmt.Errorf("invalid path is given to base: %s", vol+path)
		}

		i := strings.LastIndexByte(path, filepath.Separator)
		if i == len(path)-1 { // trailing '\' is invalid
			return "", fmt.Errorf("invalid path is given to base: %s", vol+path)
		}
		if i == -1 {
			return strings.ToUpper(path), nil
		}

		return strings.ToUpper(path[i+1:]), nil
	}

	// On this test, toNorm should be same as string.ToUpper(filepath.Clean(path)) except empty string.
	tests := []struct {
		arg  string
		want string
	}{
		{"", ""},
		{".", "."},
		{"./foo/bar", `FOO\BAR`},
		{"/", `\`},
		{"/foo/bar", `\FOO\BAR`},
		{"/foo/bar/baz/qux", `\FOO\BAR\BAZ\QUX`},
		{"foo/bar", `FOO\BAR`},
		{"C:/foo/bar", `C:\FOO\BAR`},
		{"C:foo/bar", `C:FOO\BAR`},
		{"c:/foo/bar", `C:\FOO\BAR`},
		{"C:/foo/bar", `C:\FOO\BAR`},
		{"C:/foo/bar/", `C:\FOO\BAR`},
		{`C:\foo\bar`, `C:\FOO\BAR`},
		{`C:\foo/bar\`, `C:\FOO\BAR`},
		{"C:/ふー/バー", `C:\ふー\バー`},
	}

	for _, test := range tests {
		var path string
		if test.arg != "" {
			path = filepath.Clean(test.arg)
		}
		got, err := filepath.ToNorm(path, stubBase)
		if err != nil {
			t.Errorf("toNorm(%s) failed: %v\n", test.arg, err)
		} else if got != test.want {
			t.Errorf("toNorm(%s) returns %s, but %s expected\n", test.arg, got, test.want)
		}
	}

	testPath := `{{tmp}}\test\foo\bar`

	testsDir := []struct {
		wd   string
		arg  string
		want string
	}{
		// test absolute paths
		{".", `{{tmp}}\test\foo\bar`, `{{tmp}}\test\foo\bar`},
		{".", `{{tmp}}\.\test/foo\bar`, `{{tmp}}\test\foo\bar`},
		{".", `{{tmp}}\test\..\test\foo\bar`, `{{tmp}}\test\foo\bar`},
		{".", `{{tmp}}\TEST\FOO\BAR`, `{{tmp}}\test\foo\bar`},

		// test relative paths begin with drive letter
		{`{{tmp}}\test`, `{{tmpvol}}.`, `{{tmpvol}}.`},
		{`{{tmp}}\test`, `{{tmpvol}}..`, `{{tmpvol}}..`},
		{`{{tmp}}\test`, `{{tmpvol}}foo\bar`, `{{tmpvol}}foo\bar`},
		{`{{tmp}}\test`, `{{tmpvol}}.\foo\bar`, `{{tmpvol}}foo\bar`},
		{`{{tmp}}\test`, `{{tmpvol}}foo\..\foo\bar`, `{{tmpvol}}foo\bar`},
		{`{{tmp}}\test`, `{{tmpvol}}FOO\BAR`, `{{tmpvol}}foo\bar`},

		// test relative paths begin with '\'
		{"{{tmp}}", `{{tmpnovol}}\test\foo\bar`, `{{tmpnovol}}\test\foo\bar`},
		{"{{tmp}}", `{{tmpnovol}}\.\test\foo\bar`, `{{tmpnovol}}\test\foo\bar`},
		{"{{tmp}}", `{{tmpnovol}}\test\..\test\foo\bar`, `{{tmpnovol}}\test\foo\bar`},
		{"{{tmp}}", `{{tmpnovol}}\TEST\FOO\BAR`, `{{tmpnovol}}\test\foo\bar`},

		// test relative paths begin without '\'
		{`{{tmp}}\test`, ".", `.`},
		{`{{tmp}}\test`, "..", `..`},
		{`{{tmp}}\test`, `foo\bar`, `foo\bar`},
		{`{{tmp}}\test`, `.\foo\bar`, `foo\bar`},
		{`{{tmp}}\test`, `foo\..\foo\bar`, `foo\bar`},
		{`{{tmp}}\test`, `FOO\BAR`, `foo\bar`},

		// test UNC paths
		{".", `\\localhost\c$`, `\\localhost\c$`},
	}

	ctmp := tempDirCanonical(t)
	if err := os.MkdirAll(strings.ReplaceAll(testPath, "{{tmp}}", ctmp), 0777); err != nil {
		t.Fatal(err)
	}

	cwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	t.Chdir(".") // Ensure cwd is restored after the test.

	tmpVol := filepath.VolumeName(ctmp)
	if len(tmpVol) != 2 {
		t.Fatalf("unexpected temp volume name %q", tmpVol)
	}

	tmpNoVol := ctmp[len(tmpVol):]

	replacer := strings.NewReplacer("{{tmp}}", ctmp, "{{tmpvol}}", tmpVol, "{{tmpnovol}}", tmpNoVol)

	for _, test := range testsDir {
		wd := replacer.Replace(test.wd)
		arg := replacer.Replace(test.arg)
		want := replacer.Replace(test.want)

		if test.wd == "." {
			err := os.Chdir(cwd)
			if err != nil {
				t.Error(err)

				continue
			}
		} else {
			err := os.Chdir(wd)
			if err != nil {
				t.Error(err)

				continue
			}
		}
		if arg != "" {
			arg = filepath.Clean(arg)
		}
		got, err := filepath.ToNorm(arg, filepath.NormBase)
		if err != nil {
			t.Errorf("toNorm(%s) failed: %v (wd=%s)\n", arg, err, wd)
		} else if got != want {
			t.Errorf("toNorm(%s) returns %s, but %s expected (wd=%s)\n", arg, got, want, wd)
		}
	}
}

func TestUNC(t *testing.T) {
	// Test that this doesn't go into an infinite recursion.
	// See golang.org/issue/15879.
	defer debug.SetMaxStack(debug.SetMaxStack(1e6))
	filepath.Glob(`\\?\c:\*`)
}

func testWalkMklink(t *testing.T, linktype string) {
	output, _ := exec.Command("cmd", "/c", "mklink", "/?").Output()
	if !strings.Contains(string(output), fmt.Sprintf(" /%s ", linktype)) {
		t.Skipf(`skipping test; mklink does not supports /%s parameter`, linktype)
	}
	testWalkSymlink(t, func(target, link string) error {
		output, err := exec.Command("cmd", "/c", "mklink", "/"+linktype, link, target).CombinedOutput()
		if err != nil {
			return fmt.Errorf(`"mklink /%s %v %v" command failed: %v\n%v`, linktype, link, target, err, string(output))
		}
		return nil
	})
}

func TestWalkDirectoryJunction(t *testing.T) {
	testenv.MustHaveSymlink(t)
	testWalkMklink(t, "J")
}

func TestWalkDirectorySymlink(t *testing.T) {
	testenv.MustHaveSymlink(t)
	testWalkMklink(t, "D")
}

func createMountPartition(t *testing.T, vhd string, args string) []byte {
	testenv.MustHaveExecPath(t, "powershell")
	t.Cleanup(func() {
		cmd := testenv.Command(t, "powershell", "-Command", fmt.Sprintf("Dismount-VHD %q", vhd))
		out, err := cmd.CombinedOutput()
		if err != nil {
			if t.Skipped() {
				// Probably failed to dismount because we never mounted it in
				// the first place. Log the error, but ignore it.
				t.Logf("%v: %v (skipped)\n%s", cmd, err, out)
			} else {
				// Something went wrong, and we don't want to leave dangling VHDs.
				// Better to fail the test than to just log the error and continue.
				t.Errorf("%v: %v\n%s", cmd, err, out)
			}
		}
	})

	script := filepath.Join(t.TempDir(), "test.ps1")
	cmd := strings.Join([]string{
		"$ErrorActionPreference = \"Stop\"",
		fmt.Sprintf("$vhd = New-VHD -Path %q -SizeBytes 3MB -Fixed", vhd),
		"$vhd | Mount-VHD",
		fmt.Sprintf("$vhd = Get-VHD %q", vhd),
		"$vhd | Get-Disk | Initialize-Disk -PartitionStyle GPT",
		"$part = $vhd | Get-Disk | New-Partition -UseMaximumSize -AssignDriveLetter:$false",
		"$vol = $part | Format-Volume -FileSystem NTFS",
		args,
	}, "\n")

	err := os.WriteFile(script, []byte(cmd), 0666)
	if err != nil {
		t.Fatal(err)
	}
	output, err := testenv.Command(t, "powershell", "-File", script).CombinedOutput()
	if err != nil {
		// This can happen if Hyper-V is not installed or enabled.
		t.Skip("skipping test because failed to create VHD: ", err, string(output))
	}
	return output
}

var winsymlink = godebug.New("winsymlink")
var winreadlinkvolume = godebug.New("winreadlinkvolume")

func TestEvalSymlinksJunctionToVolumeID(t *testing.T) {
	// Test that EvalSymlinks resolves a directory junction which
	// is mapped to volumeID (instead of drive letter). See go.dev/issue/39786.
	if winsymlink.Value() == "0" {
		t.Skip("skipping test because winsymlink is not enabled")
	}
	t.Parallel()

	output, _ := exec.Command("cmd", "/c", "mklink", "/?").Output()
	if !strings.Contains(string(output), " /J ") {
		t.Skip("skipping test because mklink command does not support junctions")
	}

	tmpdir := tempDirCanonical(t)
	vhd := filepath.Join(tmpdir, "Test.vhdx")
	output = createMountPartition(t, vhd, "Write-Host $vol.Path -NoNewline")
	vol := string(output)

	dirlink := filepath.Join(tmpdir, "dirlink")
	output, err := testenv.Command(t, "cmd", "/c", "mklink", "/J", dirlink, vol).CombinedOutput()
	if err != nil {
		t.Fatalf("failed to run mklink %v %v: %v %q", dirlink, vol, err, output)
	}
	got, err := filepath.EvalSymlinks(dirlink)
	if err != nil {
		t.Fatal(err)
	}
	if got != dirlink {
		t.Errorf(`EvalSymlinks(%q): got %q, want %q`, dirlink, got, dirlink)
	}
}

func TestEvalSymlinksMountPointRecursion(t *testing.T) {
	// Test that EvalSymlinks doesn't follow recursive mount points.
	// See go.dev/issue/40176.
	if winsymlink.Value() == "0" {
		t.Skip("skipping test because winsymlink is not enabled")
	}
	t.Parallel()

	tmpdir := tempDirCanonical(t)
	dirlink := filepath.Join(tmpdir, "dirlink")
	err := os.Mkdir(dirlink, 0755)
	if err != nil {
		t.Fatal(err)
	}

	vhd := filepath.Join(tmpdir, "Test.vhdx")
	createMountPartition(t, vhd, fmt.Sprintf("$part | Add-PartitionAccessPath -AccessPath %q\n", dirlink))

	got, err := filepath.EvalSymlinks(dirlink)
	if err != nil {
		t.Fatal(err)
	}
	if got != dirlink {
		t.Errorf(`EvalSymlinks(%q): got %q, want %q`, dirlink, got, dirlink)
	}
}

func TestNTNamespaceSymlink(t *testing.T) {
	output, _ := exec.Command("cmd", "/c", "mklink", "/?").Output()
	if !strings.Contains(string(output), " /J ") {
		t.Skip("skipping test because mklink command does not support junctions")
	}

	tmpdir := tempDirCanonical(t)

	vol := filepath.VolumeName(tmpdir)
	output, err := exec.Command("cmd", "/c", "mountvol", vol, "/L").CombinedOutput()
	if err != nil {
		t.Fatalf("failed to run mountvol %v /L: %v %q", vol, err, output)
	}
	target := strings.Trim(string(output), " \n\r")

	dirlink := filepath.Join(tmpdir, "dirlink")
	output, err = exec.Command("cmd", "/c", "mklink", "/J", dirlink, target).CombinedOutput()
	if err != nil {
		t.Fatalf("failed to run mklink %v %v: %v %q", dirlink, target, err, output)
	}

	got, err := filepath.EvalSymlinks(dirlink)
	if err != nil {
		t.Fatal(err)
	}
	var want string
	if winsymlink.Value() == "0" {
		if winreadlinkvolume.Value() == "0" {
			want = vol + `\`
		} else {
			want = target
		}
	} else {
		want = dirlink
	}
	if got != want {
		t.Errorf(`EvalSymlinks(%q): got %q, want %q`, dirlink, got, want)
	}

	// Make sure we have sufficient privilege to run mklink command.
	testenv.MustHaveSymlink(t)

	file := filepath.Join(tmpdir, "file")
	err = os.WriteFile(file, []byte(""), 0666)
	if err != nil {
		t.Fatal(err)
	}

	target = filepath.Join(target, file[len(filepath.VolumeName(file)):])

	filelink := filepath.Join(tmpdir, "filelink")
	output, err = exec.Command("cmd", "/c", "mklink", filelink, target).CombinedOutput()
	if err != nil {
		t.Fatalf("failed to run mklink %v %v: %v %q", filelink, target, err, output)
	}

	got, err = filepath.EvalSymlinks(filelink)
	if err != nil {
		t.Fatal(err)
	}

	if winreadlinkvolume.Value() == "0" {
		want = file
	} else {
		want = target
	}
	if got != want {
		t.Errorf(`EvalSymlinks(%q): got %q, want %q`, filelink, got, want)
	}
}

func TestIssue52476(t *testing.T) {
	tests := []struct {
		lhs, rhs string
		want     string
	}{
		{`..\.`, `C:`, `..\C:`},
		{`..`, `C:`, `..\C:`},
		{`.`, `:`, `.\:`},
		{`.`, `C:`, `.\C:`},
		{`.`, `C:/a/b/../c`, `.\C:\a\c`},
		{`.`, `\C:`, `.\C:`},
		{`C:\`, `.`, `C:\`},
		{`C:\`, `C:\`, `C:\C:`},
		{`C`, `:`, `C\:`},
		{`\.`, `C:`, `\C:`},
		{`\`, `C:`, `\C:`},
	}

	for _, test := range tests {
		got := filepath.Join(test.lhs, test.rhs)
		if got != test.want {
			t.Errorf(`Join(%q, %q): got %q, want %q`, test.lhs, test.rhs, got, test.want)
		}
	}
}

func TestAbsWindows(t *testing.T) {
	for _, test := range []struct {
		path string
		want string
	}{
		{`C:\foo`, `C:\foo`},
		{`\\host\share\foo`, `\\host\share\foo`},
		{`\\host`, `\\host`},
		{`\\.\NUL`, `\\.\NUL`},
		{`NUL`, `\\.\NUL`},
		{`COM1`, `\\.\COM1`},
		{`a/NUL`, `\\.\NUL`},
	} {
		got, err := filepath.Abs(test.path)
		if err != nil || got != test.want {
			t.Errorf("Abs(%q) = %q, %v; want %q, nil", test.path, got, err, test.want)
		}
	}
}
```