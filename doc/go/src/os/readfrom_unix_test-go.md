Response:
Let's break down the thought process for analyzing the given Go code.

1. **Identify the Core Functionality:** The file name `readfrom_unix_test.go` and the presence of `TestCopyFile` immediately suggest that the primary goal of this code is to test the `io.Copy` function's behavior when copying between files, specifically focusing on underlying OS-level optimizations like `copy_file_range` and `sendfile`. The build constraint `//go:build freebsd || linux || solaris` reinforces this, indicating these OSes are where these optimizations are expected.

2. **Analyze the Test Structure:**  The `TestCopyFile` function is the main entry point. It uses `t.Run` to create subtests, which helps organize the testing and provides more granular output. The subtests cover various scenarios:
    * **Basic:** Copying files of different sizes.
    * **Limited:** Copying with a limited number of bytes using `io.LimitedReader`.
    * **DoesntTryInAppendMode:**  Checking that optimizations aren't used when the destination file is opened in append mode.
    * **CopyFileItself:**  Testing the edge case where the source and destination are the same file.
    * **NotRegular:** Testing copying to and from pipes (non-regular files).
    * **Nil:** Testing copying with nil `*os.File` values.

3. **Examine Helper Functions:**  Several helper functions simplify the tests:
    * `testCopyFiles`: A central function to execute the copying logic with different sizes and limits.
    * `mustContainData`: Verifies that the destination file contains the expected data.
    * `mustSeekStart`: Ensures a file pointer is at the beginning.
    * `newCopyFileTest`: Creates temporary source and destination files with random data.
    * `createTempFile`: Creates a temporary file and populates it with data.
    * `copyFileHook` and related logic:  This is crucial. It's designed to intercept the low-level file copying operations (like `copy_file_range` and `sendfile`). The hook allows the tests to verify *if* and *how* these optimizations are being used.

4. **Focus on Key Test Scenarios and their Intent:**

    * **Varying Sizes:** Testing different file sizes ensures that the `io.Copy` implementation handles various data amounts correctly. The inclusion of `syscall.Getpagesize() + 1` suggests an awareness of potential page boundary issues in the underlying system calls.
    * **Limited Reader:** This verifies that `io.Copy` correctly handles the `io.Reader` interface and doesn't try to read beyond the specified limit.
    * **Append Mode:**  The test for append mode is important because `copy_file_range` and `sendfile` might have different behavior or be disallowed in append mode. The platform-specific checks highlight inconsistencies.
    * **Copying Itself:** This is a tricky edge case. `copy_file_range` can fail if source and destination overlap. The test verifies the expected fallback behavior. `sendfile` might handle this case differently.
    * **Pipes:** Pipes are non-seekable and represent a different I/O model. The tests here check if the optimizations are attempted (and likely skipped) correctly in these scenarios. The platform-specific differences are again notable.
    * **Nil Files:** This is a basic sanity check for error handling with invalid file pointers.

5. **Infer the Underlying Go Feature:**  Based on the tests, the code is clearly testing the `io.Copy` function and, more specifically, how it leverages zero-copy techniques (like `copy_file_range` and `sendfile`) when copying between regular files on Unix-like systems. The `copyFileHook` mechanism is a strong indicator of this.

6. **Construct Go Code Examples:** To illustrate the functionality, create simple examples showing `io.Copy` in action. Include scenarios where the optimizations are likely to be used (copying between regular files) and where they might not be (copying to/from pipes). Highlight the usage of `io.LimitedReader`.

7. **Address Command-Line Arguments (Absence Thereof):**  The provided code is a *test file*. Test files typically don't directly handle command-line arguments. Mention this explicitly.

8. **Identify Potential Pitfalls:** Think about common mistakes developers might make when working with file copying:
    * Not closing files properly.
    * Assuming zero-copy is *always* used (the tests show it's not).
    * Incorrectly handling errors from `io.Copy`.
    * Not being aware of the behavior with append mode or when copying a file to itself.

9. **Structure the Answer:** Organize the findings into clear sections as requested: functionality, Go feature explanation, code examples, command-line arguments, and potential pitfalls. Use clear and concise language.

10. **Review and Refine:**  Read through the answer to ensure accuracy, clarity, and completeness. Check for any inconsistencies or areas where more explanation might be needed. For example, initially, I might have focused too much on the individual test cases. Realizing that the core is about `io.Copy` and its optimizations helps to frame the answer better. The platform-specific behavior also needs to be emphasized.
这段代码是 Go 语言标准库 `os` 包中 `readfrom_unix_test.go` 文件的一部分，它专门用于测试 `io.Copy` 函数在 Unix-like 系统上的特定行为，特别是当源和目标都是文件时，`io.Copy` 底层可能会尝试使用更高效的零拷贝技术，例如 `copy_file_range` 或 `sendfile` 系统调用。

**功能列举:**

1. **测试 `io.Copy` 的基本功能:**  验证在不同大小的文件之间进行复制时，`io.Copy` 是否能正确地将数据从源文件复制到目标文件。
2. **测试 `io.Copy` 在有读取限制时的行为:** 使用 `io.LimitedReader` 限制从源文件读取的字节数，测试 `io.Copy` 是否能正确处理这种情况。
3. **测试 `io.Copy` 在目标文件以追加模式打开时的行为:** 验证当目标文件以 `O_APPEND` 模式打开时，`io.Copy` 是否会避免使用 `copy_file_range` 或 `sendfile` 等零拷贝技术。
4. **测试 `io.Copy` 复制自身时的行为:**  测试将一个文件的内容复制到自身时，`io.Copy` 的行为。这涉及到源文件和目标文件是同一个文件的情况，需要避免无限循环或数据损坏。
5. **测试 `io.Copy` 处理非普通文件 (例如管道) 的行为:** 验证当源或目标是管道时，`io.Copy` 的处理方式。由于管道不支持 seek 操作，零拷贝技术通常不适用。
6. **测试 `io.Copy` 处理 `nil` `*os.File` 的情况:** 验证当传入 `nil` 的 `*os.File` 指针时，`io.Copy` 能否正确返回错误。
7. **测试 `io.Copy` 底层是否调用了零拷贝相关的系统调用 (`copy_file_range` 或 `sendfile`)**: 通过 hook 函数 (`copyFileHook`) 检查 `io.Copy` 是否尝试使用了 `copy_file_range` 或 `sendfile`，并验证传递给这些系统调用的文件描述符是否正确。

**实现的 Go 语言功能：`io.Copy` 的底层优化**

`io.Copy` 是 Go 语言 `io` 包中一个非常常用的函数，用于将数据从 `io.Reader` 复制到 `io.Writer`。 在 Unix-like 系统上，当源和目标都是普通文件时，`io.Copy` 的底层实现会尝试使用更高效的系统调用来避免在用户空间进行数据拷贝，从而提高性能。

* **`copy_file_range`:**  这是一个 Linux 系统调用，允许在两个文件描述符之间直接复制数据，无需将数据读入用户空间再写回。
* **`sendfile`:**  这是一个在多个 Unix-like 系统上可用的系统调用，专门用于将数据从一个文件描述符发送到另一个套接字描述符（也可以用于文件描述符到文件描述符的复制，尽管可能不是其主要用途）。

这段测试代码的目的就是验证 `io.Copy` 在满足特定条件时，是否正确地使用了这些零拷贝技术。

**Go 代码举例说明:**

假设我们有两个文件 `src.txt` 和 `dst.txt`。

```go
package main

import (
	"fmt"
	"io"
	"os"
)

func main() {
	// 创建源文件并写入一些数据
	src, err := os.CreateTemp("", "src")
	if err != nil {
		fmt.Println("创建源文件失败:", err)
		return
	}
	defer os.Remove(src.Name()) // 程序退出时删除临时文件
	defer src.Close()

	_, err = src.WriteString("Hello, world!")
	if err != nil {
		fmt.Println("写入源文件失败:", err)
		return
	}

	// 创建目标文件
	dst, err := os.CreateTemp("", "dst")
	if err != nil {
		fmt.Println("创建目标文件失败:", err)
		return
	}
	defer os.Remove(dst.Name()) // 程序退出时删除临时文件
	defer dst.Close()

	// 将源文件内容复制到目标文件
	srcFile, err := os.Open(src.Name())
	if err != nil {
		fmt.Println("打开源文件失败:", err)
		return
	}
	defer srcFile.Close()

	dstFile, err := os.OpenFile(dst.Name(), os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		fmt.Println("打开目标文件失败:", err)
		return
	}
	defer dstFile.Close()

	n, err := io.Copy(dstFile, srcFile)
	if err != nil {
		fmt.Println("复制文件失败:", err)
		return
	}

	fmt.Printf("成功复制了 %d 字节\n", n)

	// 验证目标文件内容
	content, err := os.ReadFile(dst.Name())
	if err != nil {
		fmt.Println("读取目标文件失败:", err)
		return
	}
	fmt.Printf("目标文件内容: %s\n", string(content))
}
```

**假设的输入与输出:**

在这个例子中，我们没有命令行参数。输入是程序内部创建的临时文件 `src.txt`，其内容为 "Hello, world!"。

**输出:**

```
成功复制了 13 字节
目标文件内容: Hello, world!
```

**代码推理:**

测试代码中的 `copyFileHook` 类型和相关的逻辑，例如 `hookCopyFileRange` 和 `hookSendFile`，是为了在测试环境中模拟和检查 `io.Copy` 是否调用了 `copy_file_range` 或 `sendfile`。

例如，`copyFileHook` 结构体包含 `called` 字段，用于标记 hook 函数是否被调用，以及 `dstfd` 和 `srcfd` 字段，用于记录传递给系统调用的文件描述符。

在 `TestCopyFile` 函数中，会创建临时文件，然后调用 `io.Copy` 进行复制。之后，会检查 `copyFileHook` 的状态，以确定是否按预期使用了零拷贝技术。

**使用者易犯错的点:**

1. **假设 `io.Copy` 总是使用零拷贝:**  开发者可能会错误地认为 `io.Copy` 在任何情况下都会使用零拷贝技术。但实际上，只有当源和目标都是普通文件，且满足其他条件时，才会尝试使用这些优化。例如，如果目标文件是以追加模式打开的，或者源或目标是管道，则不会使用。

   **错误示例:**  假设开发者在目标文件以 `os.O_APPEND` 模式打开的情况下，仍然期望 `io.Copy` 使用零拷贝，可能会导致性能上的误判。

   ```go
   dstFile, err := os.OpenFile(dst.Name(), os.O_WRONLY|os.O_APPEND, 0644)
   // ... 期望 io.Copy 高效复制，但可能不会使用零拷贝
   ```

2. **没有正确处理 `io.Copy` 的错误:**  与任何 I/O 操作一样，`io.Copy` 也可能返回错误。开发者应该始终检查并处理这些错误。

3. **在不适用的场景下期望零拷贝带来的性能提升:**  对于小文件或者网络 I/O，零拷贝带来的性能提升可能并不显著，甚至可能因为额外的系统调用开销而降低性能。

**总结:**

这段测试代码专注于验证 `os` 包中 `io.Copy` 函数在 Unix-like 系统上进行文件复制时的底层优化行为。它通过创建各种测试场景，包括不同大小的文件、读取限制、追加模式、复制自身以及处理管道等，来确保 `io.Copy` 在合适的条件下能够利用零拷贝技术提高效率，并在不适用的情况下能够正确回退到传统的复制方式。理解这些测试用例有助于开发者更好地理解 `io.Copy` 的工作原理及其潜在的优化策略。

Prompt: 
```
这是路径为go/src/os/readfrom_unix_test.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。

"""
// Copyright 2024 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build freebsd || linux || solaris

package os_test

import (
	"bytes"
	"io"
	"math/rand"
	. "os"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

type (
	copyFileTestFunc func(*testing.T, int64) (*File, *File, []byte, *copyFileHook, string)
	copyFileTestHook func(*testing.T) (*copyFileHook, string)
)

func TestCopyFile(t *testing.T) {
	sizes := []int{
		1,
		42,
		1025,
		syscall.Getpagesize() + 1,
		32769,
	}
	t.Run("Basic", func(t *testing.T) {
		for _, size := range sizes {
			t.Run(strconv.Itoa(size), func(t *testing.T) {
				testCopyFiles(t, int64(size), -1)
			})
		}
	})
	t.Run("Limited", func(t *testing.T) {
		t.Run("OneLess", func(t *testing.T) {
			for _, size := range sizes {
				t.Run(strconv.Itoa(size), func(t *testing.T) {
					testCopyFiles(t, int64(size), int64(size)-1)
				})
			}
		})
		t.Run("Half", func(t *testing.T) {
			for _, size := range sizes {
				t.Run(strconv.Itoa(size), func(t *testing.T) {
					testCopyFiles(t, int64(size), int64(size)/2)
				})
			}
		})
		t.Run("More", func(t *testing.T) {
			for _, size := range sizes {
				t.Run(strconv.Itoa(size), func(t *testing.T) {
					testCopyFiles(t, int64(size), int64(size)+7)
				})
			}
		})
	})
	t.Run("DoesntTryInAppendMode", func(t *testing.T) {
		for _, newTest := range copyFileTests {
			dst, src, data, hook, testName := newTest(t, 42)

			dst2, err := OpenFile(dst.Name(), O_RDWR|O_APPEND, 0755)
			if err != nil {
				t.Fatalf("%s: %v", testName, err)
			}
			defer dst2.Close()

			if _, err := io.Copy(dst2, src); err != nil {
				t.Fatalf("%s: %v", testName, err)
			}
			switch runtime.GOOS {
			case "illumos", "solaris": // sendfile() on SunOS allows target file with O_APPEND set.
				if !hook.called {
					t.Fatalf("%s: should have called the hook even with destination in O_APPEND mode", testName)
				}
			default:
				if hook.called {
					t.Fatalf("%s: hook shouldn't be called with destination in O_APPEND mode", testName)
				}
			}
			mustSeekStart(t, dst2)
			mustContainData(t, dst2, data) // through traditional means
		}
	})
	t.Run("CopyFileItself", func(t *testing.T) {
		for _, hookFunc := range copyFileHooks {
			hook, testName := hookFunc(t)

			f, err := CreateTemp("", "file-readfrom-itself-test")
			if err != nil {
				t.Fatalf("%s: failed to create tmp file: %v", testName, err)
			}
			t.Cleanup(func() {
				f.Close()
				Remove(f.Name())
			})

			data := []byte("hello world!")
			if _, err := f.Write(data); err != nil {
				t.Fatalf("%s: failed to create and feed the file: %v", testName, err)
			}

			if err := f.Sync(); err != nil {
				t.Fatalf("%s: failed to save the file: %v", testName, err)
			}

			// Rewind it.
			if _, err := f.Seek(0, io.SeekStart); err != nil {
				t.Fatalf("%s: failed to rewind the file: %v", testName, err)
			}

			// Read data from the file itself.
			if _, err := io.Copy(f, f); err != nil {
				t.Fatalf("%s: failed to read from the file: %v", testName, err)
			}

			if hook.written != 0 || hook.handled || hook.err != nil {
				t.Fatalf("%s: File.readFrom is expected not to use any zero-copy techniques when copying itself."+
					"got hook.written=%d, hook.handled=%t, hook.err=%v; expected hook.written=0, hook.handled=false, hook.err=nil",
					testName, hook.written, hook.handled, hook.err)
			}

			switch testName {
			case "hookCopyFileRange":
				// For copy_file_range(2), it fails and returns EINVAL when the source and target
				// refer to the same file and their ranges overlap. The hook should be called to
				// get the returned error and fall back to generic copy.
				if !hook.called {
					t.Fatalf("%s: should have called the hook", testName)
				}
			case "hookSendFile", "hookSendFileOverCopyFileRange":
				// For sendfile(2), it allows the source and target to refer to the same file and overlap.
				// The hook should not be called and just fall back to generic copy directly.
				if hook.called {
					t.Fatalf("%s: shouldn't have called the hook", testName)
				}
			default:
				t.Fatalf("%s: unexpected test", testName)
			}

			// Rewind it.
			if _, err := f.Seek(0, io.SeekStart); err != nil {
				t.Fatalf("%s: failed to rewind the file: %v", testName, err)
			}

			data2, err := io.ReadAll(f)
			if err != nil {
				t.Fatalf("%s: failed to read from the file: %v", testName, err)
			}

			// It should wind up a double of the original data.
			if s := strings.Repeat(string(data), 2); s != string(data2) {
				t.Fatalf("%s: file contained %s, expected %s", testName, data2, s)
			}
		}
	})
	t.Run("NotRegular", func(t *testing.T) {
		t.Run("BothPipes", func(t *testing.T) {
			for _, hookFunc := range copyFileHooks {
				hook, testName := hookFunc(t)

				pr1, pw1, err := Pipe()
				if err != nil {
					t.Fatalf("%s: %v", testName, err)
				}
				defer pr1.Close()
				defer pw1.Close()

				pr2, pw2, err := Pipe()
				if err != nil {
					t.Fatalf("%s: %v", testName, err)
				}
				defer pr2.Close()
				defer pw2.Close()

				// The pipe is empty, and PIPE_BUF is large enough
				// for this, by (POSIX) definition, so there is no
				// need for an additional goroutine.
				data := []byte("hello")
				if _, err := pw1.Write(data); err != nil {
					t.Fatalf("%s: %v", testName, err)
				}
				pw1.Close()

				n, err := io.Copy(pw2, pr1)
				if err != nil {
					t.Fatalf("%s: %v", testName, err)
				}
				if n != int64(len(data)) {
					t.Fatalf("%s: transferred %d, want %d", testName, n, len(data))
				}
				switch runtime.GOOS {
				case "illumos", "solaris":
					// On solaris, We rely on File.Stat to get the size of the source file,
					// which doesn't work for pipe.
					// On illumos, We skip anything other than regular files conservatively
					// for the target file, therefore the hook shouldn't have been called.
					if hook.called {
						t.Fatalf("%s: shouldn't have called the hook with a source or a destination of pipe", testName)
					}
				default:
					if !hook.called {
						t.Fatalf("%s: should have called the hook with both source and destination of pipe", testName)
					}
				}
				pw2.Close()
				mustContainData(t, pr2, data)
			}
		})
		t.Run("DstPipe", func(t *testing.T) {
			for _, newTest := range copyFileTests {
				dst, src, data, hook, testName := newTest(t, 255)
				dst.Close()

				pr, pw, err := Pipe()
				if err != nil {
					t.Fatalf("%s: %v", testName, err)
				}
				defer pr.Close()
				defer pw.Close()

				n, err := io.Copy(pw, src)
				if err != nil {
					t.Fatalf("%s: %v", testName, err)
				}
				if n != int64(len(data)) {
					t.Fatalf("%s: transferred %d, want %d", testName, n, len(data))
				}
				switch runtime.GOOS {
				case "illumos":
					// On illumos, We skip anything other than regular files conservatively
					// for the target file, therefore the hook shouldn't have been called.
					if hook.called {
						t.Fatalf("%s: shouldn't have called the hook with a destination of pipe", testName)
					}
				default:
					if !hook.called {
						t.Fatalf("%s: should have called the hook with a destination of pipe", testName)
					}
				}
				pw.Close()
				mustContainData(t, pr, data)
			}
		})
		t.Run("SrcPipe", func(t *testing.T) {
			for _, newTest := range copyFileTests {
				dst, src, data, hook, testName := newTest(t, 255)
				src.Close()

				pr, pw, err := Pipe()
				if err != nil {
					t.Fatalf("%s: %v", testName, err)
				}
				defer pr.Close()
				defer pw.Close()

				// The pipe is empty, and PIPE_BUF is large enough
				// for this, by (POSIX) definition, so there is no
				// need for an additional goroutine.
				if _, err := pw.Write(data); err != nil {
					t.Fatalf("%s: %v", testName, err)
				}
				pw.Close()

				n, err := io.Copy(dst, pr)
				if err != nil {
					t.Fatalf("%s: %v", testName, err)
				}
				if n != int64(len(data)) {
					t.Fatalf("%s: transferred %d, want %d", testName, n, len(data))
				}
				switch runtime.GOOS {
				case "illumos", "solaris":
					// On SunOS, We rely on File.Stat to get the size of the source file,
					// which doesn't work for pipe.
					if hook.called {
						t.Fatalf("%s: shouldn't have called the hook with a source of pipe", testName)
					}
				default:
					if !hook.called {
						t.Fatalf("%s: should have called the hook with a source of pipe", testName)
					}
				}
				mustSeekStart(t, dst)
				mustContainData(t, dst, data)
			}
		})
	})
	t.Run("Nil", func(t *testing.T) {
		var nilFile *File
		anyFile, err := CreateTemp("", "")
		if err != nil {
			t.Fatal(err)
		}
		defer Remove(anyFile.Name())
		defer anyFile.Close()

		if _, err := io.Copy(nilFile, nilFile); err != ErrInvalid {
			t.Errorf("io.Copy(nilFile, nilFile) = %v, want %v", err, ErrInvalid)
		}
		if _, err := io.Copy(anyFile, nilFile); err != ErrInvalid {
			t.Errorf("io.Copy(anyFile, nilFile) = %v, want %v", err, ErrInvalid)
		}
		if _, err := io.Copy(nilFile, anyFile); err != ErrInvalid {
			t.Errorf("io.Copy(nilFile, anyFile) = %v, want %v", err, ErrInvalid)
		}

		if _, err := nilFile.ReadFrom(nilFile); err != ErrInvalid {
			t.Errorf("nilFile.ReadFrom(nilFile) = %v, want %v", err, ErrInvalid)
		}
		if _, err := anyFile.ReadFrom(nilFile); err != ErrInvalid {
			t.Errorf("anyFile.ReadFrom(nilFile) = %v, want %v", err, ErrInvalid)
		}
		if _, err := nilFile.ReadFrom(anyFile); err != ErrInvalid {
			t.Errorf("nilFile.ReadFrom(anyFile) = %v, want %v", err, ErrInvalid)
		}
	})
}

func testCopyFile(t *testing.T, dst, src *File, data []byte, hook *copyFileHook, limit int64, testName string) {
	// If we have a limit, wrap the reader.
	var (
		realsrc io.Reader
		lr      *io.LimitedReader
	)
	if limit >= 0 {
		lr = &io.LimitedReader{N: limit, R: src}
		realsrc = lr
		if limit < int64(len(data)) {
			data = data[:limit]
		}
	} else {
		realsrc = src
	}

	// Now call ReadFrom (through io.Copy), which will hopefully call
	// poll.CopyFileRange or poll.SendFile.
	n, err := io.Copy(dst, realsrc)
	if err != nil {
		t.Fatalf("%s: %v", testName, err)
	}

	// If we didn't have a limit or had a positive limit, we should have called
	// poll.CopyFileRange or poll.SendFile with the right file descriptor arguments.
	if limit != 0 && !hook.called {
		t.Fatalf("%s: never called the hook", testName)
	}
	if hook.called && hook.dstfd != int(dst.Fd()) {
		t.Fatalf("%s: wrong destination file descriptor: got %d, want %d", testName, hook.dstfd, dst.Fd())
	}
	if hook.called && hook.srcfd != int(src.Fd()) {
		t.Fatalf("%s: wrong source file descriptor: got %d, want %d", testName, hook.srcfd, src.Fd())
	}

	// Check that the offsets after the transfer make sense, that the size
	// of the transfer was reported correctly, and that the destination
	// file contains exactly the bytes we expect it to contain.
	dstoff, err := dst.Seek(0, io.SeekCurrent)
	if err != nil {
		t.Fatalf("%s: %v", testName, err)
	}
	srcoff, err := src.Seek(0, io.SeekCurrent)
	if err != nil {
		t.Fatalf("%s: %v", testName, err)
	}
	if dstoff != srcoff {
		t.Errorf("%s: offsets differ: dstoff = %d, srcoff = %d", testName, dstoff, srcoff)
	}
	if dstoff != int64(len(data)) {
		t.Errorf("%s: dstoff = %d, want %d", testName, dstoff, len(data))
	}
	if n != int64(len(data)) {
		t.Errorf("%s: short ReadFrom: wrote %d bytes, want %d", testName, n, len(data))
	}
	mustSeekStart(t, dst)
	mustContainData(t, dst, data)

	// If we had a limit, check that it was updated.
	if lr != nil {
		if want := limit - n; lr.N != want {
			t.Fatalf("%s: didn't update limit correctly: got %d, want %d", testName, lr.N, want)
		}
	}
}

// mustContainData ensures that the specified file contains exactly the
// specified data.
func mustContainData(t *testing.T, f *File, data []byte) {
	t.Helper()

	got := make([]byte, len(data))
	if _, err := io.ReadFull(f, got); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, data) {
		t.Fatalf("didn't get the same data back from %s", f.Name())
	}
	if _, err := f.Read(make([]byte, 1)); err != io.EOF {
		t.Fatalf("not at EOF")
	}
}

func mustSeekStart(t *testing.T, f *File) {
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		t.Fatal(err)
	}
}

// newCopyFileTest initializes a new test for copying data between files.
// It creates source and destination files, and populates the source file
// with random data of the specified size, then rewind it, so it can be
// consumed by copy_file_range(2) or sendfile(2).
func newCopyFileTest(t *testing.T, size int64) (dst, src *File, data []byte) {
	src, data = createTempFile(t, "test-copy-file-src", size)

	dst, err := CreateTemp(t.TempDir(), "test-copy-file-dst")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { dst.Close() })

	return
}

type copyFileHook struct {
	called bool
	dstfd  int
	srcfd  int

	written int64
	handled bool
	err     error
}

func createTempFile(tb testing.TB, name string, size int64) (*File, []byte) {
	f, err := CreateTemp(tb.TempDir(), name)
	if err != nil {
		tb.Fatalf("failed to create temporary file: %v", err)
	}
	tb.Cleanup(func() {
		f.Close()
	})

	randSeed := time.Now().Unix()
	tb.Logf("random data seed: %d\n", randSeed)
	prng := rand.New(rand.NewSource(randSeed))
	data := make([]byte, size)
	prng.Read(data)
	if _, err := f.Write(data); err != nil {
		tb.Fatalf("failed to create and feed the file: %v", err)
	}
	if err := f.Sync(); err != nil {
		tb.Fatalf("failed to save the file: %v", err)
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		tb.Fatalf("failed to rewind the file: %v", err)
	}

	return f, data
}

"""



```