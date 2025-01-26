Response:
The user wants to understand the functionalities of the provided Go code snippet, which is a part of the `os_test.go` file.

Here's a breakdown of how to approach this:

1. **Identify the main testing functions:** Look for functions starting with `Test...`. These are the primary entry points for understanding the tested features.
2. **Analyze individual test functions:** For each `Test...` function, understand what specific `os` package function it is testing.
3. **Look for helper functions:** Functions like `testChtimes`, `testOpenError`, `writeFile` are used by the test functions. Analyzing these helps understand the setup and assertions.
4. **Pay attention to platform-specific logic:** The code uses `runtime.GOOS` to handle differences across operating systems. Note these variations.
5. **Infer the tested `os` package functionalities:** Based on the test functions and their logic, deduce which core `os` package functionalities are being exercised.
6. **Provide Go code examples:** For key functionalities, create simple examples demonstrating their usage.
7. **Address error-prone areas:** Based on the tests (especially the `t.Error` calls and platform-specific handling), identify potential pitfalls for users.
8. **Summarize the functionality of the current snippet:** Condense the findings into a concise summary.
这是Go语言 `os` 包测试文件 `os_test.go` 的一部分，主要集中在测试与文件和目录操作相关的功能，特别是关于时间戳修改、工作目录变更、文件打开和读写等方面的行为。

**功能归纳 (基于提供的代码片段):**

这段代码主要测试了以下 `os` 包的功能：

* **`Chtimes`**: 修改文件或目录的访问时间和修改时间。
* **`Chdir` 和 `Getwd`**: 改变和获取当前工作目录。
* **`File.Chdir`**: 通过文件描述符改变当前工作目录。
* **`Open` 和 `OpenFile`**: 打开文件或目录，并测试各种打开模式下的行为（只读、只写、读写、追加等）。
* **`Seek`**:  移动文件读写指针。
* **`ReadAt` 和 `WriteAt`**: 在指定偏移量读取和写入文件内容。
* **`Hostname`**: 获取主机名。
* **`Stat`**: 获取文件或目录的状态信息。
* **`SameFile`**: 判断两个 `FileInfo` 是否指向同一个文件。
* **`DevNull`**:  测试 `/dev/null` (或 Windows 下的 `nul`) 的行为。
* **`Stdout` 和 `Stderr`**:  测试标准输出和标准错误流的写入。
* **`Chmod`**: 修改文件或目录的权限。
* **`Stdin`**:  测试标准输入流的状态。
* **`Symlink` 和 `Link`**: 创建符号链接和硬链接。
* **`Truncate`**: 截断文件。
* **`Kill` 和 `FindProcess`**:  发送信号给进程。
* **`Getppid`**: 获取父进程 ID。

**Go 代码示例说明:**

以下是一些 `os` 包功能的代码示例，结合了代码片段中的测试逻辑：

**1. `Chtimes` (修改文件时间戳):**

```go
package main

import (
	"fmt"
	"os"
	"time"
)

func main() {
	filename := "test.txt"
	os.WriteFile(filename, []byte("hello"), 0644) // 创建一个文件

	// 获取文件的初始状态
	fileInfo, err := os.Stat(filename)
	if err != nil {
		fmt.Println("Error getting file info:", err)
		return
	}
	initialAccessTime := os.Atime(fileInfo)
	initialModTime := fileInfo.ModTime()

	fmt.Println("Initial Access Time:", initialAccessTime)
	fmt.Println("Initial Modification Time:", initialModTime)

	// 将访问时间和修改时间都往前推 1 小时
	newAccessTime := initialAccessTime.Add(-1 * time.Hour)
	newModTime := initialModTime.Add(-1 * time.Hour)

	err = os.Chtimes(filename, newAccessTime, newModTime)
	if err != nil {
		fmt.Println("Error changing file times:", err)
		return
	}

	// 再次获取文件状态并打印
	fileInfo, err = os.Stat(filename)
	if err != nil {
		fmt.Println("Error getting file info:", err)
		return
	}
	updatedAccessTime := os.Atime(fileInfo)
	updatedModTime := fileInfo.ModTime()

	fmt.Println("Updated Access Time:", updatedAccessTime)
	fmt.Println("Updated Modification Time:", updatedModTime)
}

// 假设输入：一个名为 test.txt 的文件已存在
// 预期输出：
// Initial Access Time: 2023-10-27 10:00:00 +0000 UTC
// Initial Modification Time: 2023-10-27 10:00:00 +0000 UTC
// Updated Access Time: 2023-10-27 09:00:00 +0000 UTC
// Updated Modification Time: 2023-10-27 09:00:00 +0000 UTC
```

**2. `Chdir` 和 `Getwd` (改变和获取工作目录):**

```go
package main

import (
	"fmt"
	"os"
	"path/filepath"
)

func main() {
	originalDir, err := os.Getwd()
	if err != nil {
		fmt.Println("Error getting current directory:", err)
		return
	}
	fmt.Println("Original Directory:", originalDir)

	// 创建一个临时目录
	tmpDir, err := os.MkdirTemp("", "example")
	if err != nil {
		fmt.Println("Error creating temporary directory:", err)
		return
	}
	defer os.RemoveAll(tmpDir) // 清理临时目录

	err = os.Chdir(tmpDir)
	if err != nil {
		fmt.Println("Error changing directory:", err)
		return
	}

	currentDir, err := os.Getwd()
	if err != nil {
		fmt.Println("Error getting current directory:", err)
		return
	}
	fmt.Println("Current Directory:", currentDir)

	// 恢复到原始目录
	err = os.Chdir(originalDir)
	if err != nil {
		fmt.Println("Error changing directory back:", err)
		return
	}
}

// 假设输入：程序在某个目录下运行
// 预期输出：
// Original Directory: /path/to/original/directory
// Current Directory: /tmp/example123 (或类似的临时目录路径)
```

**3. `ReadAt` 和 `WriteAt` (在指定偏移量读写):**

```go
package main

import (
	"fmt"
	"os"
)

func main() {
	filename := "data.txt"
	content := []byte("This is some initial content.")
	os.WriteFile(filename, content, 0644)

	file, err := os.OpenFile(filename, os.O_RDWR, 0644)
	if err != nil {
		fmt.Println("Error opening file:", err)
		return
	}
	defer file.Close()

	// 在偏移量 5 写入 "WAS"
	n, err := file.WriteAt([]byte("WAS"), 5)
	if err != nil {
		fmt.Println("Error writing at offset:", err)
		return
	}
	fmt.Println("Bytes written:", n)

	// 从偏移量 0 读取 10 个字节
	buffer := make([]byte, 10)
	n, err = file.ReadAt(buffer, 0)
	if err != nil {
		fmt.Println("Error reading at offset:", err)
		return
	}
	fmt.Println("Bytes read:", n)
	fmt.Println("Content read:", string(buffer[:n]))

	// 读取整个文件内容进行验证
	updatedContent, err := os.ReadFile(filename)
	if err != nil {
		fmt.Println("Error reading file:", err)
		return
	}
	fmt.Println("Updated file content:", string(updatedContent))
}

// 假设输入：一个名为 data.txt 的文件被创建并写入初始内容
// 预期输出：
// Bytes written: 3
// Bytes read: 10
// Content read: This WAS is
// Updated file content: This WAS some initial content.
```

**命令行参数的具体处理:**

这段代码本身主要是测试框架，没有直接处理用户传递的命令行参数。但是，`os` 包本身提供了处理命令行参数的功能，例如 `os.Args` 可以获取命令行参数。

**使用者易犯错的点 (基于代码片段):**

1. **`Chtimes` 在不同操作系统上的行为差异:** 代码中针对 DragonFly BSD 和 NetBSD 进行了特殊处理，说明在这些系统上修改文件时间戳可能存在一些行为上的差异，例如某些文件系统可能不支持修改访问时间或者在特定挂载选项下不生效。使用者需要注意这些平台差异。

2. **`WriteAt` 在追加模式下的行为:** 测试用例 `TestWriteAtInAppendMode` 明确指出，在以 `O_APPEND` 模式打开的文件上调用 `WriteAt` 会返回 `ErrWriteAtInAppendMode` 错误。使用者需要了解这个限制，如果需要在特定位置写入，应该避免使用追加模式。

3. **文件权限问题:** 测试用例 `TestFilePermissions` 强调了文件权限的设置和影响。使用者在创建文件时需要正确设置权限，否则可能会导致读写操作失败。

4. **工作目录变更的程序范围影响:**  `TestProgWideChdir`  测试用例说明了 `Chdir` 的影响是程序全局的，即使在不同的 Goroutine 中也会生效。使用者需要注意这种全局性，避免在并发场景下出现意外的工作目录问题。

**这段代码的功能归纳:**

这段代码是 `os_test.go` 的一部分，它专注于测试 Go 语言 `os` 包中与文件和目录操作密切相关的功能，包括文件时间戳的修改、工作目录的管理、文件的打开和读写操作、主机名的获取、文件状态的查询、文件类型的判断、以及进程管理等功能。 这些测试用例旨在验证这些功能在不同操作系统上的正确性和一致性，并识别潜在的错误和平台差异。

Prompt: 
```
这是路径为go/src/os/os_test.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第2部分，共3部分，请归纳一下它的功能

"""
PDIR to point to a tmpfs
				// (e.g. /var/run/shm), this exception can be removed.
				t.Log(errormsg)
				t.Log("Known DragonFly BSD issue (atime not supported on hammer2); ignoring.")
			}
		case "netbsd":
			if !omitAt && hasNoatime() {
				t.Log(errormsg)
				t.Log("Known NetBSD issue (atime not changed on fs mounted with noatime); ignoring.")
			} else {
				t.Error(errormsg)
			}
		default:
			t.Error(errormsg)
		}
	}
	if !gotMtime.Equal(wantMtime) {
		errormsg := fmt.Sprintf("mtime mismatch, got: %q, want: %q", gotMtime, wantMtime)
		switch runtime.GOOS {
		case "dragonfly":
			if omitAt && omitMt {
				t.Log(errormsg)
				t.Log("Known DragonFly BSD issue (won't work when both times are omitted); ignoring.")
			} else {
				t.Error(errormsg)
			}
		default:
			t.Error(errormsg)
		}
	}
}

func TestChtimesDir(t *testing.T) {
	t.Parallel()

	testChtimes(t, t.TempDir())
}

func testChtimes(t *testing.T, name string) {
	st, err := Stat(name)
	if err != nil {
		t.Fatalf("Stat %s: %s", name, err)
	}
	preStat := st

	// Move access and modification time back a second
	at := Atime(preStat)
	mt := preStat.ModTime()
	err = Chtimes(name, at.Add(-time.Second), mt.Add(-time.Second))
	if err != nil {
		t.Fatalf("Chtimes %s: %s", name, err)
	}

	st, err = Stat(name)
	if err != nil {
		t.Fatalf("second Stat %s: %s", name, err)
	}
	postStat := st

	pat := Atime(postStat)
	pmt := postStat.ModTime()
	if !pat.Before(at) {
		errormsg := fmt.Sprintf("AccessTime didn't go backwards; was=%v, after=%v", at, pat)
		switch runtime.GOOS {
		case "plan9":
			// Mtime is the time of the last change of
			// content.  Similarly, atime is set whenever
			// the contents are accessed; also, it is set
			// whenever mtime is set.
		case "netbsd":
			if hasNoatime() {
				t.Log(errormsg)
				t.Log("Known NetBSD issue (atime not changed on fs mounted with noatime); ignoring.")
			} else {
				t.Error(errormsg)
			}
		default:
			t.Error(errormsg)
		}
	}

	if !pmt.Before(mt) {
		t.Errorf("ModTime didn't go backwards; was=%v, after=%v", mt, pmt)
	}
}

func TestChtimesToUnixZero(t *testing.T) {
	file := newFile(t)
	fn := file.Name()
	if _, err := file.Write([]byte("hi")); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}

	unixZero := time.Unix(0, 0)
	if err := Chtimes(fn, unixZero, unixZero); err != nil {
		t.Fatalf("Chtimes failed: %v", err)
	}

	st, err := Stat(fn)
	if err != nil {
		t.Fatal(err)
	}

	if mt := st.ModTime(); mt != unixZero {
		t.Errorf("mtime is %v, want %v", mt, unixZero)
	}
}

func TestFileChdir(t *testing.T) {
	wd, err := Getwd()
	if err != nil {
		t.Fatalf("Getwd: %s", err)
	}
	t.Chdir(".") // Ensure wd is restored after the test.

	fd, err := Open(".")
	if err != nil {
		t.Fatalf("Open .: %s", err)
	}
	defer fd.Close()

	if err := Chdir("/"); err != nil {
		t.Fatalf("Chdir /: %s", err)
	}

	if err := fd.Chdir(); err != nil {
		t.Fatalf("fd.Chdir: %s", err)
	}

	wdNew, err := Getwd()
	if err != nil {
		t.Fatalf("Getwd: %s", err)
	}

	wdInfo, err := fd.Stat()
	if err != nil {
		t.Fatal(err)
	}
	newInfo, err := Stat(wdNew)
	if err != nil {
		t.Fatal(err)
	}
	if !SameFile(wdInfo, newInfo) {
		t.Fatalf("fd.Chdir failed: got %s, want %s", wdNew, wd)
	}
}

func TestChdirAndGetwd(t *testing.T) {
	t.Chdir(t.TempDir()) // Ensure wd is restored after the test.

	// These are chosen carefully not to be symlinks on a Mac
	// (unlike, say, /var, /etc), except /tmp, which we handle below.
	dirs := []string{"/", "/usr/bin", "/tmp"}
	// /usr/bin does not usually exist on Plan 9 or Android.
	switch runtime.GOOS {
	case "android":
		dirs = []string{"/system/bin"}
	case "plan9":
		dirs = []string{"/", "/usr"}
	case "ios", "windows", "wasip1":
		dirs = nil
		for _, dir := range []string{t.TempDir(), t.TempDir()} {
			// Expand symlinks so path equality tests work.
			dir, err := filepath.EvalSymlinks(dir)
			if err != nil {
				t.Fatalf("EvalSymlinks: %v", err)
			}
			dirs = append(dirs, dir)
		}
	}
	for mode := 0; mode < 2; mode++ {
		for _, d := range dirs {
			var err error
			if mode == 0 {
				err = Chdir(d)
			} else {
				fd1, err1 := Open(d)
				if err1 != nil {
					t.Errorf("Open %s: %s", d, err1)
					continue
				}
				err = fd1.Chdir()
				fd1.Close()
			}
			if d == "/tmp" {
				Setenv("PWD", "/tmp")
			}
			pwd, err1 := Getwd()
			if err != nil {
				t.Fatalf("Chdir %s: %s", d, err)
			}
			if err1 != nil {
				t.Fatalf("Getwd in %s: %s", d, err1)
			}
			if !equal(pwd, d) {
				t.Fatalf("Getwd returned %q want %q", pwd, d)
			}
		}
	}
}

// Test that Chdir+Getwd is program-wide.
func TestProgWideChdir(t *testing.T) {
	const N = 10
	var wg sync.WaitGroup
	hold := make(chan struct{})
	done := make(chan struct{})

	d := t.TempDir()
	t.Chdir(d)

	// Note the deferred Wait must be called after the deferred close(done),
	// to ensure the N goroutines have been released even if the main goroutine
	// calls Fatalf. It must be called before the Chdir back to the original
	// directory, and before the deferred deletion implied by TempDir,
	// so as not to interfere while the N goroutines are still running.
	defer wg.Wait()
	defer close(done)

	for i := 0; i < N; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			// Lock half the goroutines in their own operating system
			// thread to exercise more scheduler possibilities.
			if i%2 == 1 {
				// On Plan 9, after calling LockOSThread, the goroutines
				// run on different processes which don't share the working
				// directory. This used to be an issue because Go expects
				// the working directory to be program-wide.
				// See issue 9428.
				runtime.LockOSThread()
			}
			select {
			case <-done:
				return
			case <-hold:
			}
			// Getwd might be wrong
			f0, err := Stat(".")
			if err != nil {
				t.Error(err)
				return
			}
			pwd, err := Getwd()
			if err != nil {
				t.Errorf("Getwd: %v", err)
				return
			}
			if pwd != d {
				t.Errorf("Getwd() = %q, want %q", pwd, d)
				return
			}
			f1, err := Stat(pwd)
			if err != nil {
				t.Error(err)
				return
			}
			if !SameFile(f0, f1) {
				t.Errorf(`Samefile(Stat("."), Getwd()) reports false (%s != %s)`, f0.Name(), f1.Name())
				return
			}
		}(i)
	}
	var err error
	if err = Chdir(d); err != nil {
		t.Fatalf("Chdir: %v", err)
	}
	// OS X sets TMPDIR to a symbolic link.
	// So we resolve our working directory again before the test.
	d, err = Getwd()
	if err != nil {
		t.Fatalf("Getwd: %v", err)
	}
	close(hold)
	wg.Wait()
}

func TestSeek(t *testing.T) {
	t.Parallel()

	f := newFile(t)

	const data = "hello, world\n"
	io.WriteString(f, data)

	type test struct {
		in     int64
		whence int
		out    int64
	}
	var tests = []test{
		{0, io.SeekCurrent, int64(len(data))},
		{0, io.SeekStart, 0},
		{5, io.SeekStart, 5},
		{0, io.SeekEnd, int64(len(data))},
		{0, io.SeekStart, 0},
		{-1, io.SeekEnd, int64(len(data)) - 1},
		{1 << 33, io.SeekStart, 1 << 33},
		{1 << 33, io.SeekEnd, 1<<33 + int64(len(data))},

		// Issue 21681, Windows 4G-1, etc:
		{1<<32 - 1, io.SeekStart, 1<<32 - 1},
		{0, io.SeekCurrent, 1<<32 - 1},
		{2<<32 - 1, io.SeekStart, 2<<32 - 1},
		{0, io.SeekCurrent, 2<<32 - 1},
	}
	for i, tt := range tests {
		off, err := f.Seek(tt.in, tt.whence)
		if off != tt.out || err != nil {
			t.Errorf("#%d: Seek(%v, %v) = %v, %v want %v, nil", i, tt.in, tt.whence, off, err, tt.out)
		}
	}
}

func TestSeekError(t *testing.T) {
	switch runtime.GOOS {
	case "js", "plan9", "wasip1":
		t.Skipf("skipping test on %v", runtime.GOOS)
	}
	t.Parallel()

	r, w, err := Pipe()
	if err != nil {
		t.Fatal(err)
	}
	_, err = r.Seek(0, 0)
	if err == nil {
		t.Fatal("Seek on pipe should fail")
	}
	if perr, ok := err.(*PathError); !ok || perr.Err != syscall.ESPIPE {
		t.Errorf("Seek returned error %v, want &PathError{Err: syscall.ESPIPE}", err)
	}
	_, err = w.Seek(0, 0)
	if err == nil {
		t.Fatal("Seek on pipe should fail")
	}
	if perr, ok := err.(*PathError); !ok || perr.Err != syscall.ESPIPE {
		t.Errorf("Seek returned error %v, want &PathError{Err: syscall.ESPIPE}", err)
	}
}

func TestOpenError(t *testing.T) {
	t.Parallel()
	dir := makefs(t, []string{
		"is-a-file",
		"is-a-dir/",
	})
	t.Run("NoRoot", func(t *testing.T) { testOpenError(t, dir, false) })
	t.Run("InRoot", func(t *testing.T) { testOpenError(t, dir, true) })
}
func testOpenError(t *testing.T, dir string, rooted bool) {
	t.Parallel()
	var r *Root
	if rooted {
		var err error
		r, err = OpenRoot(dir)
		if err != nil {
			t.Fatal(err)
		}
		defer r.Close()
	}
	for _, tt := range []struct {
		path  string
		mode  int
		error error
	}{{
		"no-such-file",
		O_RDONLY,
		syscall.ENOENT,
	}, {
		"is-a-dir",
		O_WRONLY,
		syscall.EISDIR,
	}, {
		"is-a-file/no-such-file",
		O_WRONLY,
		syscall.ENOTDIR,
	}} {
		var f *File
		var err error
		var name string
		if rooted {
			name = fmt.Sprintf("Root(%q).OpenFile(%q, %d)", dir, tt.path, tt.mode)
			f, err = r.OpenFile(tt.path, tt.mode, 0)
		} else {
			path := filepath.Join(dir, tt.path)
			name = fmt.Sprintf("OpenFile(%q, %d)", path, tt.mode)
			f, err = OpenFile(path, tt.mode, 0)
		}
		if err == nil {
			t.Errorf("%v succeeded", name)
			f.Close()
			continue
		}
		perr, ok := err.(*PathError)
		if !ok {
			t.Errorf("%v returns error of %T type; want *PathError", name, err)
		}
		if perr.Err != tt.error {
			if runtime.GOOS == "plan9" {
				syscallErrStr := perr.Err.Error()
				expectedErrStr := strings.Replace(tt.error.Error(), "file ", "", 1)
				if !strings.HasSuffix(syscallErrStr, expectedErrStr) {
					// Some Plan 9 file servers incorrectly return
					// EPERM or EACCES rather than EISDIR when a directory is
					// opened for write.
					if tt.error == syscall.EISDIR &&
						(strings.HasSuffix(syscallErrStr, syscall.EPERM.Error()) ||
							strings.HasSuffix(syscallErrStr, syscall.EACCES.Error())) {
						continue
					}
					t.Errorf("%v = _, %q; want suffix %q", name, syscallErrStr, expectedErrStr)
				}
				continue
			}
			if runtime.GOOS == "dragonfly" {
				// DragonFly incorrectly returns EACCES rather
				// EISDIR when a directory is opened for write.
				if tt.error == syscall.EISDIR && perr.Err == syscall.EACCES {
					continue
				}
			}
			t.Errorf("%v = _, %q; want %q", name, perr.Err.Error(), tt.error.Error())
		}
	}
}

func TestOpenNoName(t *testing.T) {
	f, err := Open("")
	if err == nil {
		f.Close()
		t.Fatal(`Open("") succeeded`)
	}
}

func runBinHostname(t *testing.T) string {
	// Run /bin/hostname and collect output.
	r, w, err := Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()

	path, err := exec.LookPath("hostname")
	if err != nil {
		if errors.Is(err, exec.ErrNotFound) {
			t.Skip("skipping test; test requires hostname but it does not exist")
		}
		t.Fatal(err)
	}

	argv := []string{"hostname"}
	if runtime.GOOS == "aix" {
		argv = []string{"hostname", "-s"}
	}
	p, err := StartProcess(path, argv, &ProcAttr{Files: []*File{nil, w, Stderr}})
	if err != nil {
		t.Fatal(err)
	}
	w.Close()

	var b strings.Builder
	io.Copy(&b, r)
	_, err = p.Wait()
	if err != nil {
		t.Fatalf("run hostname Wait: %v", err)
	}
	err = p.Kill()
	if err == nil {
		t.Errorf("expected an error from Kill running 'hostname'")
	}
	output := b.String()
	if n := len(output); n > 0 && output[n-1] == '\n' {
		output = output[0 : n-1]
	}
	if output == "" {
		t.Fatalf("/bin/hostname produced no output")
	}

	return output
}

func testWindowsHostname(t *testing.T, hostname string) {
	cmd := testenv.Command(t, "hostname")
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("Failed to execute hostname command: %v %s", err, out)
	}
	want := strings.Trim(string(out), "\r\n")
	if hostname != want {
		t.Fatalf("Hostname() = %q != system hostname of %q", hostname, want)
	}
}

func TestHostname(t *testing.T) {
	t.Parallel()

	hostname, err := Hostname()
	if err != nil {
		t.Fatal(err)
	}
	if hostname == "" {
		t.Fatal("Hostname returned empty string and no error")
	}
	if strings.Contains(hostname, "\x00") {
		t.Fatalf("unexpected zero byte in hostname: %q", hostname)
	}

	// There is no other way to fetch hostname on windows, but via winapi.
	// On Plan 9 it can be taken from #c/sysname as Hostname() does.
	switch runtime.GOOS {
	case "android", "plan9":
		// No /bin/hostname to verify against.
		return
	case "windows":
		testWindowsHostname(t, hostname)
		return
	}

	testenv.MustHaveExec(t)

	// Check internal Hostname() against the output of /bin/hostname.
	// Allow that the internal Hostname returns a Fully Qualified Domain Name
	// and the /bin/hostname only returns the first component
	want := runBinHostname(t)
	if hostname != want {
		host, _, ok := strings.Cut(hostname, ".")
		if !ok || host != want {
			t.Errorf("Hostname() = %q, want %q", hostname, want)
		}
	}
}

func TestReadAt(t *testing.T) {
	t.Parallel()

	f := newFile(t)

	const data = "hello, world\n"
	io.WriteString(f, data)

	b := make([]byte, 5)
	n, err := f.ReadAt(b, 7)
	if err != nil || n != len(b) {
		t.Fatalf("ReadAt 7: %d, %v", n, err)
	}
	if string(b) != "world" {
		t.Fatalf("ReadAt 7: have %q want %q", string(b), "world")
	}
}

// Verify that ReadAt doesn't affect seek offset.
// In the Plan 9 kernel, there used to be a bug in the implementation of
// the pread syscall, where the channel offset was erroneously updated after
// calling pread on a file.
func TestReadAtOffset(t *testing.T) {
	t.Parallel()

	f := newFile(t)

	const data = "hello, world\n"
	io.WriteString(f, data)

	f.Seek(0, 0)
	b := make([]byte, 5)

	n, err := f.ReadAt(b, 7)
	if err != nil || n != len(b) {
		t.Fatalf("ReadAt 7: %d, %v", n, err)
	}
	if string(b) != "world" {
		t.Fatalf("ReadAt 7: have %q want %q", string(b), "world")
	}

	n, err = f.Read(b)
	if err != nil || n != len(b) {
		t.Fatalf("Read: %d, %v", n, err)
	}
	if string(b) != "hello" {
		t.Fatalf("Read: have %q want %q", string(b), "hello")
	}
}

// Verify that ReadAt doesn't allow negative offset.
func TestReadAtNegativeOffset(t *testing.T) {
	t.Parallel()

	f := newFile(t)

	const data = "hello, world\n"
	io.WriteString(f, data)

	f.Seek(0, 0)
	b := make([]byte, 5)

	n, err := f.ReadAt(b, -10)

	const wantsub = "negative offset"
	if !strings.Contains(fmt.Sprint(err), wantsub) || n != 0 {
		t.Errorf("ReadAt(-10) = %v, %v; want 0, ...%q...", n, err, wantsub)
	}
}

func TestWriteAt(t *testing.T) {
	t.Parallel()

	f := newFile(t)

	const data = "hello, world\n"
	io.WriteString(f, data)

	n, err := f.WriteAt([]byte("WORLD"), 7)
	if err != nil || n != 5 {
		t.Fatalf("WriteAt 7: %d, %v", n, err)
	}

	b, err := ReadFile(f.Name())
	if err != nil {
		t.Fatalf("ReadFile %s: %v", f.Name(), err)
	}
	if string(b) != "hello, WORLD\n" {
		t.Fatalf("after write: have %q want %q", string(b), "hello, WORLD\n")
	}
}

// Verify that WriteAt doesn't allow negative offset.
func TestWriteAtNegativeOffset(t *testing.T) {
	t.Parallel()

	f := newFile(t)

	n, err := f.WriteAt([]byte("WORLD"), -10)

	const wantsub = "negative offset"
	if !strings.Contains(fmt.Sprint(err), wantsub) || n != 0 {
		t.Errorf("WriteAt(-10) = %v, %v; want 0, ...%q...", n, err, wantsub)
	}
}

// Verify that WriteAt doesn't work in append mode.
func TestWriteAtInAppendMode(t *testing.T) {
	t.Chdir(t.TempDir())
	f, err := OpenFile("write_at_in_append_mode.txt", O_APPEND|O_CREATE, 0666)
	if err != nil {
		t.Fatalf("OpenFile: %v", err)
	}
	defer f.Close()

	_, err = f.WriteAt([]byte(""), 1)
	if err != ErrWriteAtInAppendMode {
		t.Fatalf("f.WriteAt returned %v, expected %v", err, ErrWriteAtInAppendMode)
	}
}

func writeFile(t *testing.T, r *Root, fname string, flag int, text string) string {
	t.Helper()
	var f *File
	var err error
	if r == nil {
		f, err = OpenFile(fname, flag, 0666)
	} else {
		f, err = r.OpenFile(fname, flag, 0666)
	}
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	n, err := io.WriteString(f, text)
	if err != nil {
		t.Fatalf("WriteString: %d, %v", n, err)
	}
	f.Close()
	data, err := ReadFile(fname)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	return string(data)
}

func TestAppend(t *testing.T) {
	testMaybeRooted(t, func(t *testing.T, r *Root) {
		const f = "append.txt"
		s := writeFile(t, r, f, O_CREATE|O_TRUNC|O_RDWR, "new")
		if s != "new" {
			t.Fatalf("writeFile: have %q want %q", s, "new")
		}
		s = writeFile(t, r, f, O_APPEND|O_RDWR, "|append")
		if s != "new|append" {
			t.Fatalf("writeFile: have %q want %q", s, "new|append")
		}
		s = writeFile(t, r, f, O_CREATE|O_APPEND|O_RDWR, "|append")
		if s != "new|append|append" {
			t.Fatalf("writeFile: have %q want %q", s, "new|append|append")
		}
		err := Remove(f)
		if err != nil {
			t.Fatalf("Remove: %v", err)
		}
		s = writeFile(t, r, f, O_CREATE|O_APPEND|O_RDWR, "new&append")
		if s != "new&append" {
			t.Fatalf("writeFile: after append have %q want %q", s, "new&append")
		}
		s = writeFile(t, r, f, O_CREATE|O_RDWR, "old")
		if s != "old&append" {
			t.Fatalf("writeFile: after create have %q want %q", s, "old&append")
		}
		s = writeFile(t, r, f, O_CREATE|O_TRUNC|O_RDWR, "new")
		if s != "new" {
			t.Fatalf("writeFile: after truncate have %q want %q", s, "new")
		}
	})
}

// TestFilePermissions tests setting Unix permission bits on file creation.
func TestFilePermissions(t *testing.T) {
	if Getuid() == 0 {
		t.Skip("skipping test when running as root")
	}
	for _, test := range []struct {
		name string
		mode FileMode
	}{
		{"r", 0o444},
		{"w", 0o222},
		{"rw", 0o666},
	} {
		t.Run(test.name, func(t *testing.T) {
			switch runtime.GOOS {
			case "windows":
				if test.mode&0444 == 0 {
					t.Skip("write-only files not supported on " + runtime.GOOS)
				}
			case "wasip1":
				t.Skip("file permissions not supported on " + runtime.GOOS)
			}
			testMaybeRooted(t, func(t *testing.T, r *Root) {
				const filename = "f"
				var f *File
				var err error
				if r == nil {
					f, err = OpenFile(filename, O_RDWR|O_CREATE|O_EXCL, test.mode)
				} else {
					f, err = r.OpenFile(filename, O_RDWR|O_CREATE|O_EXCL, test.mode)
				}
				if err != nil {
					t.Fatal(err)
				}
				f.Close()
				b, err := ReadFile(filename)
				if test.mode&0o444 != 0 {
					if err != nil {
						t.Errorf("ReadFile = %v; want success", err)
					}
				} else {
					if err == nil {
						t.Errorf("ReadFile = %q, <nil>; want failure", string(b))
					}
				}
				_, err = Stat(filename)
				if err != nil {
					t.Errorf("Stat = %v; want success", err)
				}
				err = WriteFile(filename, nil, 0666)
				if test.mode&0o222 != 0 {
					if err != nil {
						t.Errorf("WriteFile = %v; want success", err)
						b, err := ReadFile(filename)
						t.Errorf("ReadFile: %v", err)
						t.Errorf("file contents: %q", b)
					}
				} else {
					if err == nil {
						t.Errorf("WriteFile(%q) = <nil>; want failure", filename)
						st, err := Stat(filename)
						if err == nil {
							t.Errorf("mode: %s", st.Mode())
						}
						b, err := ReadFile(filename)
						t.Errorf("ReadFile: %v", err)
						t.Errorf("file contents: %q", b)
					}
				}
			})
		})
	}

}

// TestFileRDWRFlags tests the O_RDONLY, O_WRONLY, and O_RDWR flags.
func TestFileRDWRFlags(t *testing.T) {
	for _, test := range []struct {
		name string
		flag int
	}{
		{"O_RDONLY", O_RDONLY},
		{"O_WRONLY", O_WRONLY},
		{"O_RDWR", O_RDWR},
	} {
		t.Run(test.name, func(t *testing.T) {
			testMaybeRooted(t, func(t *testing.T, r *Root) {
				const filename = "f"
				content := []byte("content")
				if err := WriteFile(filename, content, 0666); err != nil {
					t.Fatal(err)
				}
				var f *File
				var err error
				if r == nil {
					f, err = OpenFile(filename, test.flag, 0)
				} else {
					f, err = r.OpenFile(filename, test.flag, 0)
				}
				if err != nil {
					t.Fatal(err)
				}
				defer f.Close()
				got, err := io.ReadAll(f)
				if test.flag == O_WRONLY {
					if err == nil {
						t.Errorf("read file: %q, %v; want error", got, err)
					}
				} else {
					if err != nil || !bytes.Equal(got, content) {
						t.Errorf("read file: %q, %v; want %q, <nil>", got, err, content)
					}
				}
				if _, err := f.Seek(0, 0); err != nil {
					t.Fatalf("f.Seek: %v", err)
				}
				newcontent := []byte("CONTENT")
				_, err = f.Write(newcontent)
				if test.flag == O_RDONLY {
					if err == nil {
						t.Errorf("write file: succeeded, want error")
					}
				} else {
					if err != nil {
						t.Errorf("write file: %v, want success", err)
					}
				}
				f.Close()
				got, err = ReadFile(filename)
				if err != nil {
					t.Fatal(err)
				}
				want := content
				if test.flag != O_RDONLY {
					want = newcontent
				}
				if !bytes.Equal(got, want) {
					t.Fatalf("after write, file contains %q, want %q", got, want)
				}
			})
		})
	}
}

func TestStatDirWithTrailingSlash(t *testing.T) {
	t.Parallel()

	// Create new temporary directory and arrange to clean it up.
	path := t.TempDir()

	// Stat of path should succeed.
	if _, err := Stat(path); err != nil {
		t.Fatalf("stat %s failed: %s", path, err)
	}

	// Stat of path+"/" should succeed too.
	path += "/"
	if _, err := Stat(path); err != nil {
		t.Fatalf("stat %s failed: %s", path, err)
	}
}

func TestNilProcessStateString(t *testing.T) {
	var ps *ProcessState
	s := ps.String()
	if s != "<nil>" {
		t.Errorf("(*ProcessState)(nil).String() = %q, want %q", s, "<nil>")
	}
}

func TestSameFile(t *testing.T) {
	t.Chdir(t.TempDir())
	fa, err := Create("a")
	if err != nil {
		t.Fatalf("Create(a): %v", err)
	}
	fa.Close()
	fb, err := Create("b")
	if err != nil {
		t.Fatalf("Create(b): %v", err)
	}
	fb.Close()

	ia1, err := Stat("a")
	if err != nil {
		t.Fatalf("Stat(a): %v", err)
	}
	ia2, err := Stat("a")
	if err != nil {
		t.Fatalf("Stat(a): %v", err)
	}
	if !SameFile(ia1, ia2) {
		t.Errorf("files should be same")
	}

	ib, err := Stat("b")
	if err != nil {
		t.Fatalf("Stat(b): %v", err)
	}
	if SameFile(ia1, ib) {
		t.Errorf("files should be different")
	}
}

func testDevNullFileInfo(t *testing.T, statname, devNullName string, fi FileInfo) {
	pre := fmt.Sprintf("%s(%q): ", statname, devNullName)
	if fi.Size() != 0 {
		t.Errorf(pre+"wrong file size have %d want 0", fi.Size())
	}
	if fi.Mode()&ModeDevice == 0 {
		t.Errorf(pre+"wrong file mode %q: ModeDevice is not set", fi.Mode())
	}
	if fi.Mode()&ModeCharDevice == 0 {
		t.Errorf(pre+"wrong file mode %q: ModeCharDevice is not set", fi.Mode())
	}
	if fi.Mode().IsRegular() {
		t.Errorf(pre+"wrong file mode %q: IsRegular returns true", fi.Mode())
	}
}

func testDevNullFile(t *testing.T, devNullName string) {
	f, err := Open(devNullName)
	if err != nil {
		t.Fatalf("Open(%s): %v", devNullName, err)
	}
	defer f.Close()

	fi, err := f.Stat()
	if err != nil {
		t.Fatalf("Stat(%s): %v", devNullName, err)
	}
	testDevNullFileInfo(t, "f.Stat", devNullName, fi)

	fi, err = Stat(devNullName)
	if err != nil {
		t.Fatalf("Stat(%s): %v", devNullName, err)
	}
	testDevNullFileInfo(t, "Stat", devNullName, fi)
}

func TestDevNullFile(t *testing.T) {
	t.Parallel()

	testDevNullFile(t, DevNull)
	if runtime.GOOS == "windows" {
		testDevNullFile(t, "./nul")
		testDevNullFile(t, "//./nul")
	}
}

var testLargeWrite = flag.Bool("large_write", false, "run TestLargeWriteToConsole test that floods console with output")

func TestLargeWriteToConsole(t *testing.T) {
	if !*testLargeWrite {
		t.Skip("skipping console-flooding test; enable with -large_write")
	}
	b := make([]byte, 32000)
	for i := range b {
		b[i] = '.'
	}
	b[len(b)-1] = '\n'
	n, err := Stdout.Write(b)
	if err != nil {
		t.Fatalf("Write to os.Stdout failed: %v", err)
	}
	if n != len(b) {
		t.Errorf("Write to os.Stdout should return %d; got %d", len(b), n)
	}
	n, err = Stderr.Write(b)
	if err != nil {
		t.Fatalf("Write to os.Stderr failed: %v", err)
	}
	if n != len(b) {
		t.Errorf("Write to os.Stderr should return %d; got %d", len(b), n)
	}
}

func TestStatDirModeExec(t *testing.T) {
	if runtime.GOOS == "wasip1" {
		t.Skip("Chmod is not supported on " + runtime.GOOS)
	}
	t.Parallel()

	const mode = 0111

	path := t.TempDir()
	if err := Chmod(path, 0777); err != nil {
		t.Fatalf("Chmod %q 0777: %v", path, err)
	}

	dir, err := Stat(path)
	if err != nil {
		t.Fatalf("Stat %q (looking for mode %#o): %s", path, mode, err)
	}
	if dir.Mode()&mode != mode {
		t.Errorf("Stat %q: mode %#o want %#o", path, dir.Mode()&mode, mode)
	}
}

func TestStatStdin(t *testing.T) {
	switch runtime.GOOS {
	case "android", "plan9":
		t.Skipf("%s doesn't have /bin/sh", runtime.GOOS)
	}

	if Getenv("GO_WANT_HELPER_PROCESS") == "1" {
		st, err := Stdin.Stat()
		if err != nil {
			t.Fatalf("Stat failed: %v", err)
		}
		fmt.Println(st.Mode() & ModeNamedPipe)
		Exit(0)
	}

	t.Parallel()
	exe := testenv.Executable(t)

	fi, err := Stdin.Stat()
	if err != nil {
		t.Fatal(err)
	}
	switch mode := fi.Mode(); {
	case mode&ModeCharDevice != 0 && mode&ModeDevice != 0:
	case mode&ModeNamedPipe != 0:
	default:
		t.Fatalf("unexpected Stdin mode (%v), want ModeCharDevice or ModeNamedPipe", mode)
	}

	cmd := testenv.Command(t, exe, "-test.run=^TestStatStdin$")
	cmd = testenv.CleanCmdEnv(cmd)
	cmd.Env = append(cmd.Env, "GO_WANT_HELPER_PROCESS=1")
	// This will make standard input a pipe.
	cmd.Stdin = strings.NewReader("output")

	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("Failed to spawn child process: %v %q", err, string(output))
	}

	// result will be like "prw-rw-rw"
	if len(output) < 1 || output[0] != 'p' {
		t.Fatalf("Child process reports stdin is not pipe '%v'", string(output))
	}
}

func TestStatRelativeSymlink(t *testing.T) {
	testenv.MustHaveSymlink(t)
	t.Parallel()

	tmpdir := t.TempDir()
	target := filepath.Join(tmpdir, "target")
	f, err := Create(target)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	st, err := f.Stat()
	if err != nil {
		t.Fatal(err)
	}

	link := filepath.Join(tmpdir, "link")
	err = Symlink(filepath.Base(target), link)
	if err != nil {
		t.Fatal(err)
	}

	st1, err := Stat(link)
	if err != nil {
		t.Fatal(err)
	}

	if !SameFile(st, st1) {
		t.Error("Stat doesn't follow relative symlink")
	}

	if runtime.GOOS == "windows" {
		Remove(link)
		err = Symlink(target[len(filepath.VolumeName(target)):], link)
		if err != nil {
			t.Fatal(err)
		}

		st1, err := Stat(link)
		if err != nil {
			t.Fatal(err)
		}

		if !SameFile(st, st1) {
			t.Error("Stat doesn't follow relative symlink")
		}
	}
}

func TestReadAtEOF(t *testing.T) {
	t.Parallel()

	f := newFile(t)

	_, err := f.ReadAt(make([]byte, 10), 0)
	switch err {
	case io.EOF:
		// all good
	case nil:
		t.Fatalf("ReadAt succeeded")
	default:
		t.Fatalf("ReadAt failed: %s", err)
	}
}

func TestLongPath(t *testing.T) {
	t.Parallel()

	tmpdir := t.TempDir()

	// Test the boundary of 247 and fewer bytes (normal) and 248 and more bytes (adjusted).
	sizes := []int{247, 248, 249, 400}
	for len(tmpdir) < 400 {
		tmpdir += "/dir3456789"
	}
	for _, sz := range sizes {
		t.Run(fmt.Sprintf("length=%d", sz), func(t *testing.T) {
			sizedTempDir := tmpdir[:sz-1] + "x" // Ensure it does not end with a slash.

			// The various sized runs are for this call to trigger the boundary
			// condition.
			if err := MkdirAll(sizedTempDir, 0755); err != nil {
				t.Fatalf("MkdirAll failed: %v", err)
			}
			data := []byte("hello world\n")
			if err := WriteFile(sizedTempDir+"/foo.txt", data, 0644); err != nil {
				t.Fatalf("os.WriteFile() failed: %v", err)
			}
			if err := Rename(sizedTempDir+"/foo.txt", sizedTempDir+"/bar.txt"); err != nil {
				t.Fatalf("Rename failed: %v", err)
			}
			mtime := time.Now().Truncate(time.Minute)
			if err := Chtimes(sizedTempDir+"/bar.txt", mtime, mtime); err != nil {
				t.Fatalf("Chtimes failed: %v", err)
			}
			names := []string{"bar.txt"}
			if testenv.HasSymlink() {
				if err := Symlink(sizedTempDir+"/bar.txt", sizedTempDir+"/symlink.txt"); err != nil {
					t.Fatalf("Symlink failed: %v", err)
				}
				names = append(names, "symlink.txt")
			}
			if testenv.HasLink() {
				if err := Link(sizedTempDir+"/bar.txt", sizedTempDir+"/link.txt"); err != nil {
					t.Fatalf("Link failed: %v", err)
				}
				names = append(names, "link.txt")
			}
			for _, wantSize := range []int64{int64(len(data)), 0} {
				for _, name := range names {
					path := sizedTempDir + "/" + name
					dir, err := Stat(path)
					if err != nil {
						t.Fatalf("Stat(%q) failed: %v", path, err)
					}
					filesize := size(path, t)
					if dir.Size() != filesize || filesize != wantSize {
						t.Errorf("Size(%q) is %d, len(ReadFile()) is %d, want %d", path, dir.Size(), filesize, wantSize)
					}
					if runtime.GOOS != "wasip1" { // Chmod is not supported on wasip1
						err = Chmod(path, dir.Mode())
						if err != nil {
							t.Fatalf("Chmod(%q) failed: %v", path, err)
						}
					}
				}
				if err := Truncate(sizedTempDir+"/bar.txt", 0); err != nil {
					t.Fatalf("Truncate failed: %v", err)
				}
			}
		})
	}
}

func testKillProcess(t *testing.T, processKiller func(p *Process)) {
	t.Parallel()

	// Re-exec the test binary to start a process that hangs until stdin is closed.
	cmd := testenv.Command(t, testenv.Executable(t))
	cmd.Env = append(cmd.Environ(), "GO_OS_TEST_DRAIN_STDIN=1")
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	err = cmd.Start()
	if err != nil {
		t.Fatalf("Failed to start test process: %v", err)
	}

	defer func() {
		if err := cmd.Wait(); err == nil {
			t.Errorf("Test process succeeded, but expected to fail")
		}
		stdin.Close() // Keep stdin alive until the process has finished dying.
	}()

	// Wait for the process to be started.
	// (It will close its stdout when it reaches TestMain.)
	io.Copy(io.Discard, stdout)

	processKiller(cmd.Process)
}

func TestKillStartProcess(t *testing.T) {
	testKillProcess(t, func(p *Process) {
		err := p.Kill()
		if err != nil {
			t.Fatalf("Failed to kill test process: %v", err)
		}
	})
}

func TestGetppid(t *testing.T) {
	if runtime.GOOS == "plan9" {
		// TODO: golang.org/issue/8206
		t.Skipf("skipping test on plan9; see issue 8206")
	}

	if Getenv("GO_WANT_HELPER_PROCESS") == "1" {
		fmt.Print(Getppid())
		Exit(0)
	}

	t.Parallel()

	cmd := testenv.Command(t, testenv.Executable(t), "-test.run=^TestGetppid$")
	cmd.Env = append(Environ(), "GO_WANT_HELPER_PROCESS=1")

	// verify that Getppid() from the forked process reports our process id
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("Failed to spawn child process: %v %q", err, string(output))
	}

	childPpid := string(output)
	ourPid := fmt.Sprintf("%d", Getpid())
	if childPpid != ourPid {
		t.Fatalf("Child process reports parent process id '%v', expected '%v'", childPpid, ourPid)
	}
}

func TestKillFindProcess(t *testing.T) {
	testKillProcess(t, func(p *Process) {
		p2, err := FindProcess(p.Pid)
		if err != nil {
			t.Fatalf("Failed to find test process: %v", err)
		}
		err = p2.Kill()
		if err != nil {
			t.Fatalf("Failed to kill test process: %v", err)
		}
	})
}

var nilFileMethodTests = []struct {
	name string
	f    func(*File) error
}{
	{"Chdir", func(f *File) error { return f.Chdir() }},
	{"Close", func(f *File) error { return f.Close() }},
	{"Chmod", func(f *File) error { return f.Chmod(0) }},
	{"Chown", func(f *File) error { return f.Chown(0, 0) }},
	{"Read", func(f *File) error { _, err := f.Read(make([]byte, 0)); return err }},
	{"ReadAt", func(f *File) error { _, err := f.ReadAt(make([]byte, 0), 0); return err }},
	{"Readdir", func(f *File) error { _, err := f.Readdir(1); return err }},
	{"Readdirnames", func(f *File) error { _, err := f.Readdirnames(1); return err }},
	{"Seek", func(f *File) error { _, err := f.Seek(0, io.SeekStart); return err }},
	{"Stat", func(f *File) error { _, err := f.Stat(); return err }},
	{"Sync", func(f *File) error { return f.Sync() }},
	{"Truncate", func(f *File) error { return f.Truncate(0) }},
	{"Write", func(f *File) error { _, err := f.Write(make([]byte, 0)); return err }},
	{"WriteAt", func(f *File) error { _, err := f.WriteAt(make([]byte, 0), 0); return err }},
	{"WriteString", func(f *File) error { _, err := f.WriteString(""); return err }},
}

// Test that all File methods give ErrInvalid if the receiver is nil.
func TestNilFileMethods(t *testing.T) {
	t.Parallel()

	for _, tt := range nilFileMethodTests {
		var file *File
		got := tt.f(file)
		if got != ErrInvalid {
			t.Errorf("%v should fail when f is nil; got %v", tt.name, got)
		}
	}
}

func mkdirTree(t *testing.T, root string, level, max int) {
	if level >= max {
		return
	}
	level++
	for i := 'a'; i < 'c'; i++ {
		dir := filepath.Join(root, string(i))
		if err := Mkdir(dir, 0700); err != nil {
			t.Fatal(err)
		}
		mkdirTree(t, dir, level, max)
	}
}

// Test that simultaneous RemoveAll do not report an error.
// As long as it gets removed, we should be happy.
func TestRemoveAllRace(t *testing.T) {
	if runtime.GOOS == "windows" {
		// Windows has very strict rules about things like
		//
"""




```