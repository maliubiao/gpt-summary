Response:
The user has provided a second part of a Go test file (`path_test.go`) and is asking for a summary of its functionalities. I need to analyze the provided Go code snippets and identify the primary functions being tested and what aspects of the `path/filepath` package they cover.

Based on the code, I can identify the following functionalities being tested:

1. **`filepath.Abs`**:  Tests the functionality of converting a relative path to an absolute path. It handles different cases, including paths relative to the current directory and paths containing `.` and `..`. It also has special handling for Windows paths with drive letters.
2. **`filepath.Rel`**: Tests the functionality of finding the relative path between two given paths. It covers various scenarios, including paths within the same directory, subdirectories, parent directories, and absolute paths. It also includes platform-specific tests for Windows.
3. **`filepath.VolumeName`**: Tests the functionality of extracting the volume name (like "C:") from a given path, primarily for Windows.
4. **`filepath.EvalSymlinks`**: Tests the functionality of resolving symbolic links in a path. It covers cases with nested symlinks, symlinks pointing to directories, and edge cases involving traversing above the root directory.
5. **`filepath.Walk` and `filepath.WalkDir`**: Tests the functionality of recursively traversing a directory tree. It verifies the order of traversal and the ability to skip directories during the walk. It also includes tests for handling permissions errors during the walk.
6. **Edge Cases and Error Handling**:  The tests also cover edge cases such as empty paths, paths with trailing separators, and error conditions like attempting to find the relative path between paths on different volumes (Windows).

I will now summarize these findings in a concise manner.
这是 `go/src/path/filepath/path_test.go` 文件的一部分，它主要测试了 Go 语言 `path/filepath` 包中的以下功能：

**核心功能归纳：**

这部分代码主要集中在测试 `path/filepath` 包中处理路径的几个关键函数：

1. **`filepath.Abs` 函数的功能测试:**  验证将一个相对路径转换为绝对路径的功能。
2. **`filepath.Rel` 函数的功能测试:** 验证计算两个路径之间的相对路径的功能。
3. **`filepath.VolumeName` 函数的功能测试:** 验证提取路径中卷名（例如 Windows 下的 "C:"）的功能。
4. **`filepath.EvalSymlinks` 函数的功能测试:** 验证解析路径中的符号链接的功能。
5. **`filepath.Walk` 和 `filepath.WalkDir` 函数的功能测试:** 验证递归遍历目录树的功能。

**具体功能及代码示例：**

*   **`filepath.Abs` (获取绝对路径):**

    此功能测试 `filepath.Abs` 函数，它将给定的路径转换为绝对路径。

    ```go
    package main

    import (
    	"fmt"
    	"path/filepath"
    	"os"
    )

    func main() {
    	// 假设当前工作目录是 /home/user
    	absPath, err := filepath.Abs("test.txt")
    	if err != nil {
    		fmt.Println("Error:", err)
    		return
    	}
    	fmt.Println("Absolute path:", absPath) // 输出: Absolute path: /home/user/test.txt
    }
    ```

    **假设输入:** 当前工作目录为 `/home/user`，输入路径为 `"test.txt"`。
    **预期输出:** `/home/user/test.txt` (或类似的绝对路径)。

*   **`filepath.Rel` (获取相对路径):**

    此功能测试 `filepath.Rel` 函数，它计算从一个路径到另一个路径的相对路径。

    ```go
    package main

    import (
    	"fmt"
    	"path/filepath"
    )

    func main() {
    	relPath, err := filepath.Rel("/a/b", "/a/b/c/d")
    	if err != nil {
    		fmt.Println("Error:", err)
    		return
    	}
    	fmt.Println("Relative path:", relPath) // 输出: Relative path: c/d
    }
    ```

    **假设输入:** `root` 路径为 `"/a/b"`，`path` 路径为 `"/a/b/c/d"`。
    **预期输出:** `"c/d"`。

*   **`filepath.VolumeName` (获取卷名):**

    此功能测试 `filepath.VolumeName` 函数，主要用于 Windows 系统，提取路径中的卷名。

    ```go
    package main

    import (
    	"fmt"
    	"path/filepath"
    	"runtime"
    )

    func main() {
    	if runtime.GOOS == "windows" {
    		volume := filepath.VolumeName(`C:\Users\Public`)
    		fmt.Println("Volume name:", volume) // 输出: Volume name: C:
    	}
    }
    ```

    **假设输入:** Windows 系统下，路径为 `"C:\\Users\\Public"`。
    **预期输出:** `"C:"`。

*   **`filepath.EvalSymlinks` (解析符号链接):**

    此功能测试 `filepath.EvalSymlinks` 函数，用于解析路径中的符号链接，返回解析后的真实路径。

    ```go
    package main

    import (
    	"fmt"
    	"path/filepath"
    	"os"
    )

    func main() {
    	// 假设存在一个名为 "link" 的符号链接，指向 "/tmp" 目录
    	resolvedPath, err := filepath.EvalSymlinks("link")
    	if err != nil {
    		fmt.Println("Error:", err)
    		return
    	}
    	fmt.Println("Resolved path:", resolvedPath) // 输出: Resolved path: /tmp
    }
    ```

    **假设输入:** 当前目录下存在一个名为 `link` 的符号链接，它指向 `/tmp` 目录。
    **预期输出:** `/tmp`。

*   **`filepath.Walk` 和 `filepath.WalkDir` (遍历目录):**

    此功能测试 `filepath.Walk` 和 `filepath.WalkDir` 函数，用于递归地遍历目录树。

    ```go
    package main

    import (
    	"fmt"
    	"path/filepath"
    	"os"
    	"io/fs"
    )

    func main() {
    	root := "test_dir"
    	os.Mkdir(root, 0777)
    	defer os.RemoveAll(root)
    	os.Mkdir(filepath.Join(root, "subdir"), 0777)
    	os.Create(filepath.Join(root, "file.txt"))
    	os.Create(filepath.Join(root, "subdir", "subfile.txt"))

    	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
    		if err != nil {
    			return err
    		}
    		fmt.Println("Visited:", path)
    		return nil
    	})
    	if err != nil {
    		fmt.Println("Error during walk:", err)
    	}
    }
    ```

    **假设输入:** 当前目录下有一个名为 `test_dir` 的目录，包含子目录和文件。
    **预期输出:** 遍历 `test_dir` 及其子目录下的所有文件和目录，并打印其路径。 例如:
    ```
    Visited: test_dir
    Visited: test_dir/file.txt
    Visited: test_dir/subdir
    Visited: test_dir/subdir/subfile.txt
    ```

**命令行参数处理：**

这段代码本身不直接处理命令行参数。它是一个测试文件，主要通过 Go 的 testing 包来运行测试用例。

**使用者易犯错的点：**

在 `filepath.Rel` 的测试中，可以看到一些会被标记为 "err" 的用例，这表示在某些情况下，无法单纯地通过词法分析来确定相对路径，例如：

*   从父目录 (`..`) 到当前目录 (`.`) 或子目录。
*   从一个绝对路径到另一个绝对路径，但它们属于不同的卷（在 Windows 上）。

使用者可能会错误地期望 `filepath.Rel` 在这些情况下也能给出有效的结果，但实际上它会返回错误。

**总结其功能:**

总的来说，这部分代码是对 Go 语言 `path/filepath` 包中路径处理核心功能的细致测试，涵盖了获取绝对路径、计算相对路径、提取卷名、解析符号链接以及遍历目录等关键操作，并考虑了不同操作系统下的行为和潜在的错误情况。

### 提示词
```
这是路径为go/src/path/filepath/path_test.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第2部分，共2部分，请归纳一下它的功能
```

### 源代码
```go
) = %q; want %q`, p, want)
	}
	t.Logf(`EvalSymlinks("link") = %q`, p)
}

// Test directories relative to temporary directory.
// The tests are run in absTestDirs[0].
var absTestDirs = []string{
	"a",
	"a/b",
	"a/b/c",
}

// Test paths relative to temporary directory. $ expands to the directory.
// The tests are run in absTestDirs[0].
// We create absTestDirs first.
var absTests = []string{
	".",
	"b",
	"b/",
	"../a",
	"../a/b",
	"../a/b/./c/../../.././a",
	"../a/b/./c/../../.././a/",
	"$",
	"$/.",
	"$/a/../a/b",
	"$/a/b/c/../../.././a",
	"$/a/b/c/../../.././a/",
}

func TestAbs(t *testing.T) {
	root := t.TempDir()
	t.Chdir(root)

	for _, dir := range absTestDirs {
		err := os.Mkdir(dir, 0777)
		if err != nil {
			t.Fatal("Mkdir failed: ", err)
		}
	}

	// Make sure the global absTests slice is not
	// modified by multiple invocations of TestAbs.
	tests := absTests
	if runtime.GOOS == "windows" {
		vol := filepath.VolumeName(root)
		var extra []string
		for _, path := range absTests {
			if strings.Contains(path, "$") {
				continue
			}
			path = vol + path
			extra = append(extra, path)
		}
		tests = append(slices.Clip(tests), extra...)
	}

	err := os.Chdir(absTestDirs[0])
	if err != nil {
		t.Fatal("chdir failed: ", err)
	}

	for _, path := range tests {
		path = strings.ReplaceAll(path, "$", root)
		info, err := os.Stat(path)
		if err != nil {
			t.Errorf("%s: %s", path, err)
			continue
		}

		abspath, err := filepath.Abs(path)
		if err != nil {
			t.Errorf("Abs(%q) error: %v", path, err)
			continue
		}
		absinfo, err := os.Stat(abspath)
		if err != nil || !os.SameFile(absinfo, info) {
			t.Errorf("Abs(%q)=%q, not the same file", path, abspath)
		}
		if !filepath.IsAbs(abspath) {
			t.Errorf("Abs(%q)=%q, not an absolute path", path, abspath)
		}
		if filepath.IsAbs(abspath) && abspath != filepath.Clean(abspath) {
			t.Errorf("Abs(%q)=%q, isn't clean", path, abspath)
		}
	}
}

// Empty path needs to be special-cased on Windows. See golang.org/issue/24441.
// We test it separately from all other absTests because the empty string is not
// a valid path, so it can't be used with os.Stat.
func TestAbsEmptyString(t *testing.T) {
	root := t.TempDir()
	t.Chdir(root)

	info, err := os.Stat(root)
	if err != nil {
		t.Fatalf("%s: %s", root, err)
	}

	abspath, err := filepath.Abs("")
	if err != nil {
		t.Fatalf(`Abs("") error: %v`, err)
	}
	absinfo, err := os.Stat(abspath)
	if err != nil || !os.SameFile(absinfo, info) {
		t.Errorf(`Abs("")=%q, not the same file`, abspath)
	}
	if !filepath.IsAbs(abspath) {
		t.Errorf(`Abs("")=%q, not an absolute path`, abspath)
	}
	if filepath.IsAbs(abspath) && abspath != filepath.Clean(abspath) {
		t.Errorf(`Abs("")=%q, isn't clean`, abspath)
	}
}

type RelTests struct {
	root, path, want string
}

var reltests = []RelTests{
	{"a/b", "a/b", "."},
	{"a/b/.", "a/b", "."},
	{"a/b", "a/b/.", "."},
	{"./a/b", "a/b", "."},
	{"a/b", "./a/b", "."},
	{"ab/cd", "ab/cde", "../cde"},
	{"ab/cd", "ab/c", "../c"},
	{"a/b", "a/b/c/d", "c/d"},
	{"a/b", "a/b/../c", "../c"},
	{"a/b/../c", "a/b", "../b"},
	{"a/b/c", "a/c/d", "../../c/d"},
	{"a/b", "c/d", "../../c/d"},
	{"a/b/c/d", "a/b", "../.."},
	{"a/b/c/d", "a/b/", "../.."},
	{"a/b/c/d/", "a/b", "../.."},
	{"a/b/c/d/", "a/b/", "../.."},
	{"../../a/b", "../../a/b/c/d", "c/d"},
	{"/a/b", "/a/b", "."},
	{"/a/b/.", "/a/b", "."},
	{"/a/b", "/a/b/.", "."},
	{"/ab/cd", "/ab/cde", "../cde"},
	{"/ab/cd", "/ab/c", "../c"},
	{"/a/b", "/a/b/c/d", "c/d"},
	{"/a/b", "/a/b/../c", "../c"},
	{"/a/b/../c", "/a/b", "../b"},
	{"/a/b/c", "/a/c/d", "../../c/d"},
	{"/a/b", "/c/d", "../../c/d"},
	{"/a/b/c/d", "/a/b", "../.."},
	{"/a/b/c/d", "/a/b/", "../.."},
	{"/a/b/c/d/", "/a/b", "../.."},
	{"/a/b/c/d/", "/a/b/", "../.."},
	{"/../../a/b", "/../../a/b/c/d", "c/d"},
	{".", "a/b", "a/b"},
	{".", "..", ".."},

	// can't do purely lexically
	{"..", ".", "err"},
	{"..", "a", "err"},
	{"../..", "..", "err"},
	{"a", "/a", "err"},
	{"/a", "a", "err"},
}

var winreltests = []RelTests{
	{`C:a\b\c`, `C:a/b/d`, `..\d`},
	{`C:\`, `D:\`, `err`},
	{`C:`, `D:`, `err`},
	{`C:\Projects`, `c:\projects\src`, `src`},
	{`C:\Projects`, `c:\projects`, `.`},
	{`C:\Projects\a\..`, `c:\projects`, `.`},
	{`\\host\share`, `\\host\share\file.txt`, `file.txt`},
}

func TestRel(t *testing.T) {
	tests := append([]RelTests{}, reltests...)
	if runtime.GOOS == "windows" {
		for i := range tests {
			tests[i].want = filepath.FromSlash(tests[i].want)
		}
		tests = append(tests, winreltests...)
	}
	for _, test := range tests {
		got, err := filepath.Rel(test.root, test.path)
		if test.want == "err" {
			if err == nil {
				t.Errorf("Rel(%q, %q)=%q, want error", test.root, test.path, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("Rel(%q, %q): want %q, got error: %s", test.root, test.path, test.want, err)
		}
		if got != test.want {
			t.Errorf("Rel(%q, %q)=%q, want %q", test.root, test.path, got, test.want)
		}
	}
}

type VolumeNameTest struct {
	path string
	vol  string
}

var volumenametests = []VolumeNameTest{
	{`c:/foo/bar`, `c:`},
	{`c:`, `c:`},
	{`c:\`, `c:`},
	{`2:`, `2:`},
	{``, ``},
	{`\\\host`, `\\\host`},
	{`\\\host\`, `\\\host`},
	{`\\\host\share`, `\\\host`},
	{`\\\host\\share`, `\\\host`},
	{`\\host`, `\\host`},
	{`//host`, `\\host`},
	{`\\host\`, `\\host\`},
	{`//host/`, `\\host\`},
	{`\\host\share`, `\\host\share`},
	{`//host/share`, `\\host\share`},
	{`\\host\share\`, `\\host\share`},
	{`//host/share/`, `\\host\share`},
	{`\\host\share\foo`, `\\host\share`},
	{`//host/share/foo`, `\\host\share`},
	{`\\host\share\\foo\\\bar\\\\baz`, `\\host\share`},
	{`//host/share//foo///bar////baz`, `\\host\share`},
	{`\\host\share\foo\..\bar`, `\\host\share`},
	{`//host/share/foo/../bar`, `\\host\share`},
	{`//.`, `\\.`},
	{`//./`, `\\.\`},
	{`//./NUL`, `\\.\NUL`},
	{`//?`, `\\?`},
	{`//?/`, `\\?\`},
	{`//?/NUL`, `\\?\NUL`},
	{`/??`, `\??`},
	{`/??/`, `\??\`},
	{`/??/NUL`, `\??\NUL`},
	{`//./a/b`, `\\.\a`},
	{`//./C:`, `\\.\C:`},
	{`//./C:/`, `\\.\C:`},
	{`//./C:/a/b/c`, `\\.\C:`},
	{`//./UNC/host/share/a/b/c`, `\\.\UNC\host\share`},
	{`//./UNC/host`, `\\.\UNC\host`},
	{`//./UNC/host\`, `\\.\UNC\host\`},
	{`//./UNC`, `\\.\UNC`},
	{`//./UNC/`, `\\.\UNC\`},
	{`\\?\x`, `\\?\x`},
	{`\??\x`, `\??\x`},
}

func TestVolumeName(t *testing.T) {
	if runtime.GOOS != "windows" {
		return
	}
	for _, v := range volumenametests {
		if vol := filepath.VolumeName(v.path); vol != v.vol {
			t.Errorf("VolumeName(%q)=%q, want %q", v.path, vol, v.vol)
		}
	}
}

func TestDriveLetterInEvalSymlinks(t *testing.T) {
	if runtime.GOOS != "windows" {
		return
	}
	wd, _ := os.Getwd()
	if len(wd) < 3 {
		t.Errorf("Current directory path %q is too short", wd)
	}
	lp := strings.ToLower(wd)
	up := strings.ToUpper(wd)
	flp, err := filepath.EvalSymlinks(lp)
	if err != nil {
		t.Fatalf("EvalSymlinks(%q) failed: %q", lp, err)
	}
	fup, err := filepath.EvalSymlinks(up)
	if err != nil {
		t.Fatalf("EvalSymlinks(%q) failed: %q", up, err)
	}
	if flp != fup {
		t.Errorf("Results of EvalSymlinks do not match: %q and %q", flp, fup)
	}
}

func TestBug3486(t *testing.T) { // https://golang.org/issue/3486
	if runtime.GOOS == "ios" {
		t.Skipf("skipping on %s/%s", runtime.GOOS, runtime.GOARCH)
	}
	root := filepath.Join(testenv.GOROOT(t), "src", "unicode")
	utf16 := filepath.Join(root, "utf16")
	utf8 := filepath.Join(root, "utf8")
	seenUTF16 := false
	seenUTF8 := false
	err := filepath.Walk(root, func(pth string, info fs.FileInfo, err error) error {
		if err != nil {
			t.Fatal(err)
		}

		switch pth {
		case utf16:
			seenUTF16 = true
			return filepath.SkipDir
		case utf8:
			if !seenUTF16 {
				t.Fatal("filepath.Walk out of order - utf8 before utf16")
			}
			seenUTF8 = true
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if !seenUTF8 {
		t.Fatalf("%q not seen", utf8)
	}
}

func testWalkSymlink(t *testing.T, mklink func(target, link string) error) {
	tmpdir := t.TempDir()
	t.Chdir(tmpdir)

	err := mklink(tmpdir, "link")
	if err != nil {
		t.Fatal(err)
	}

	var visited []string
	err = filepath.Walk(tmpdir, func(path string, info fs.FileInfo, err error) error {
		if err != nil {
			t.Fatal(err)
		}
		rel, err := filepath.Rel(tmpdir, path)
		if err != nil {
			t.Fatal(err)
		}
		visited = append(visited, rel)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	slices.Sort(visited)
	want := []string{".", "link"}
	if fmt.Sprintf("%q", visited) != fmt.Sprintf("%q", want) {
		t.Errorf("unexpected paths visited %q, want %q", visited, want)
	}
}

func TestWalkSymlink(t *testing.T) {
	testenv.MustHaveSymlink(t)
	testWalkSymlink(t, os.Symlink)
}

func TestIssue29372(t *testing.T) {
	tmpDir := t.TempDir()

	path := filepath.Join(tmpDir, "file.txt")
	err := os.WriteFile(path, nil, 0644)
	if err != nil {
		t.Fatal(err)
	}

	pathSeparator := string(filepath.Separator)
	tests := []string{
		path + strings.Repeat(pathSeparator, 1),
		path + strings.Repeat(pathSeparator, 2),
		path + strings.Repeat(pathSeparator, 1) + ".",
		path + strings.Repeat(pathSeparator, 2) + ".",
		path + strings.Repeat(pathSeparator, 1) + "..",
		path + strings.Repeat(pathSeparator, 2) + "..",
	}

	for i, test := range tests {
		_, err = filepath.EvalSymlinks(test)
		if err != syscall.ENOTDIR {
			t.Fatalf("test#%d: want %q, got %q", i, syscall.ENOTDIR, err)
		}
	}
}

// Issue 30520 part 1.
func TestEvalSymlinksAboveRoot(t *testing.T) {
	testenv.MustHaveSymlink(t)

	t.Parallel()

	tmpDir := t.TempDir()

	evalTmpDir, err := filepath.EvalSymlinks(tmpDir)
	if err != nil {
		t.Fatal(err)
	}

	if err := os.Mkdir(filepath.Join(evalTmpDir, "a"), 0777); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(evalTmpDir, "a"), filepath.Join(evalTmpDir, "b")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(evalTmpDir, "a", "file"), nil, 0666); err != nil {
		t.Fatal(err)
	}

	// Count the number of ".." elements to get to the root directory.
	vol := filepath.VolumeName(evalTmpDir)
	c := strings.Count(evalTmpDir[len(vol):], string(os.PathSeparator))
	var dd []string
	for i := 0; i < c+2; i++ {
		dd = append(dd, "..")
	}

	wantSuffix := strings.Join([]string{"a", "file"}, string(os.PathSeparator))

	// Try different numbers of "..".
	for _, i := range []int{c, c + 1, c + 2} {
		check := strings.Join([]string{evalTmpDir, strings.Join(dd[:i], string(os.PathSeparator)), evalTmpDir[len(vol)+1:], "b", "file"}, string(os.PathSeparator))
		resolved, err := filepath.EvalSymlinks(check)
		switch {
		case runtime.GOOS == "darwin" && errors.Is(err, fs.ErrNotExist):
			// On darwin, the temp dir is sometimes cleaned up mid-test (issue 37910).
			testenv.SkipFlaky(t, 37910)
		case err != nil:
			t.Errorf("EvalSymlinks(%q) failed: %v", check, err)
		case !strings.HasSuffix(resolved, wantSuffix):
			t.Errorf("EvalSymlinks(%q) = %q does not end with %q", check, resolved, wantSuffix)
		default:
			t.Logf("EvalSymlinks(%q) = %q", check, resolved)
		}
	}
}

// Issue 30520 part 2.
func TestEvalSymlinksAboveRootChdir(t *testing.T) {
	testenv.MustHaveSymlink(t)
	t.Chdir(t.TempDir())

	subdir := filepath.Join("a", "b")
	if err := os.MkdirAll(subdir, 0777); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(subdir, "c"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(subdir, "file"), nil, 0666); err != nil {
		t.Fatal(err)
	}

	subdir = filepath.Join("d", "e", "f")
	if err := os.MkdirAll(subdir, 0777); err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(subdir); err != nil {
		t.Fatal(err)
	}

	check := filepath.Join("..", "..", "..", "c", "file")
	wantSuffix := filepath.Join("a", "b", "file")
	if resolved, err := filepath.EvalSymlinks(check); err != nil {
		t.Errorf("EvalSymlinks(%q) failed: %v", check, err)
	} else if !strings.HasSuffix(resolved, wantSuffix) {
		t.Errorf("EvalSymlinks(%q) = %q does not end with %q", check, resolved, wantSuffix)
	} else {
		t.Logf("EvalSymlinks(%q) = %q", check, resolved)
	}
}

func TestIssue51617(t *testing.T) {
	dir := t.TempDir()
	for _, sub := range []string{"a", filepath.Join("a", "bad"), filepath.Join("a", "next")} {
		if err := os.Mkdir(filepath.Join(dir, sub), 0755); err != nil {
			t.Fatal(err)
		}
	}
	bad := filepath.Join(dir, "a", "bad")
	if err := os.Chmod(bad, 0); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(bad, 0700) // avoid errors on cleanup
	var saw []string
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return filepath.SkipDir
		}
		if d.IsDir() {
			rel, err := filepath.Rel(dir, path)
			if err != nil {
				t.Fatal(err)
			}
			saw = append(saw, rel)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{".", "a", filepath.Join("a", "bad"), filepath.Join("a", "next")}
	if !slices.Equal(saw, want) {
		t.Errorf("got directories %v, want %v", saw, want)
	}
}

func TestEscaping(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(t.TempDir())

	for _, p := range []string{
		filepath.Join(dir, "x"),
	} {
		if !filepath.IsLocal(p) {
			continue
		}
		f, err := os.Create(p)
		if err != nil {
			f.Close()
		}
		ents, err := os.ReadDir(dir)
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range ents {
			t.Fatalf("found: %v", e.Name())
		}
	}
}

func TestEvalSymlinksTooManyLinks(t *testing.T) {
	testenv.MustHaveSymlink(t)
	dir := filepath.Join(t.TempDir(), "dir")
	err := os.Symlink(dir, dir)
	if err != nil {
		t.Fatal(err)
	}
	_, err = filepath.EvalSymlinks(dir)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}
```