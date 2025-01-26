Response:
The user wants to understand the functionality of the provided Go code snippet `timeout_test.go`. I need to analyze the code and explain its purpose, which seems to be testing the timeout functionality of `os` package operations like `Read` and `Write` on files and pipes.

Here's a breakdown of the steps:

1. **Identify the main goal:** The file name and the presence of functions like `TestReadTimeout`, `TestWriteTimeout`, and `TestVariousDeadlines` strongly suggest that the primary purpose is to test the timeout mechanisms of file operations in the `os` package.

2. **Analyze individual test functions:** I need to go through each test function and understand what specific timeout scenarios it covers.

3. **Infer the underlying Go feature:**  The code uses methods like `SetDeadline`, `SetReadDeadline`, and `SetWriteDeadline` on `os.File` objects. This points to the Go feature that allows setting deadlines for I/O operations.

4. **Provide Go code examples:** I should demonstrate how to use these deadline-setting methods in a simple program.

5. **Discuss code reasoning:**  If there are interesting logic parts, like the dynamic timeout adjustment in `TestReadTimeoutFluctuation` and `TestWriteTimeoutFluctuation`, I need to explain the reasoning behind it, including the assumptions made.

6. **Check for command-line arguments:** This file appears to be a testing file and doesn't directly process command-line arguments. However, the test execution itself might have command-line options (like `-short`). I need to consider this context.

7. **Identify common pitfalls:**  Think about the potential errors developers might encounter when using deadlines, like incorrect error checking or misunderstanding the behavior of deadlines.

8. **Structure the answer:** Organize the information logically, starting with the main functionality and then going into details with code examples, reasoning, etc.
这段Go语言代码文件 `go/src/os/timeout_test.go` 的主要功能是**测试 `os` 包中关于 I/O 操作超时机制的实现**。它通过各种测试用例，验证了在文件和管道上设置读取、写入和通用截止时间 (`Deadline`) 的行为是否符合预期，特别是超时发生时是否会返回 `os.ErrDeadlineExceeded` 错误。

更具体地说，它测试了以下几个方面：

1. **`SetDeadline`、`SetReadDeadline` 和 `SetWriteDeadline` 在不可轮询的文件上的行为:**  例如普通文件，这些方法应该返回 `os.ErrNoDeadline`。
2. **读取操作的超时机制:** 验证设置读取截止时间后，如果超时发生，`Read` 操作会返回 `os.ErrDeadlineExceeded` 错误。同时，也测试了在数据已经准备好的情况下，超时是否仍然生效。
3. **写入操作的超时机制:** 类似于读取操作，验证设置写入截止时间后，如果超时发生，`Write` 操作会返回 `os.ErrDeadlineExceeded` 错误。
4. **取消截止时间:** 测试使用零值的 `time.Time` 来取消之前设置的截止时间。
5. **超时时间的波动性:** 测试在不同超时时间下，`Read` 和 `Write` 操作是否能在合理的时间内返回超时错误。它使用动态调整超时时间的方法，以适应不同机器的性能。
6. **多种截止时间的组合使用:** 测试同时设置读取和写入截止时间的情况。
7. **并发场景下的截止时间:** 测试在多个 goroutine 并发进行 `Read` 和 `Write` 操作并设置截止时间时的行为，以检测是否存在竞态条件。
8. **在截止时间发生后修改读写缓冲区是否安全:**  测试在 `Read` 或 `Write` 操作因超时返回后，立即修改其使用的缓冲区是否会导致问题。
9. **关闭 TTY 设备时的行为:** 测试在从 TTY 设备读取数据时关闭该设备是否会导致程序 hang 住。

**它是什么go语言功能的实现？**

这段代码测试的是 `os` 包中 `File` 类型的 `SetDeadline`、`SetReadDeadline` 和 `SetWriteDeadline` 方法的实现。这些方法允许为文件或管道的 I/O 操作设置一个截止时间。当操作在截止时间到达前没有完成时，会返回一个超时错误。

**Go 代码举例说明:**

```go
package main

import (
	"fmt"
	"os"
	"time"
)

func main() {
	r, w, err := os.Pipe()
	if err != nil {
		fmt.Println("Error creating pipe:", err)
		return
	}
	defer r.Close()
	defer w.Close()

	// 设置读取截止时间为 100 毫秒后
	deadline := time.Now().Add(100 * time.Millisecond)
	err = r.SetReadDeadline(deadline)
	if err != nil {
		fmt.Println("Error setting read deadline:", err)
		return
	}

	buf := make([]byte, 10)
	n, err := r.Read(buf)

	if err != nil {
		if os.IsTimeout(err) {
			fmt.Println("Read timed out as expected.")
		} else {
			fmt.Println("Read error:", err)
		}
	} else {
		fmt.Printf("Read %d bytes: %s\n", n, string(buf[:n]))
	}

	// 设置写入截止时间为 50 毫秒后
	deadline = time.Now().Add(50 * time.Millisecond)
	err = w.SetWriteDeadline(deadline)
	if err != nil {
		fmt.Println("Error setting write deadline:", err)
		return
	}

	_, err = w.Write([]byte("hello"))
	if err != nil {
		if os.IsTimeout(err) {
			fmt.Println("Write timed out as expected.")
		} else {
			fmt.Println("Write error:", err)
		}
	} else {
		fmt.Println("Write successful.")
	}
}
```

**假设的输入与输出 (针对上面的代码示例):**

**假设:** 在读取操作的 100 毫秒截止时间之前，没有数据写入管道。

**输出:**

```
Read timed out as expected.
Write successful.
```

**解释:** 由于在设置的读取截止时间之前没有数据写入管道，`r.Read(buf)` 会因为超时而返回一个错误，并且 `os.IsTimeout(err)` 将返回 `true`。写入操作没有设置任何阻止条件，因此很可能在 50 毫秒的截止时间前完成。

**代码推理:**

在 `TestReadTimeoutFluctuation` 和 `TestWriteTimeoutFluctuation` 函数中，代码使用了一种动态调整超时时间的方法。其目的是在不同的系统负载和速度下，都能可靠地测试超时机制。

**假设的输入:**  系统运行缓慢，导致 I/O 操作需要比预期更长的时间才能完成。

**推理过程:**

1. **初始超时时间:**  测试开始时，会设置一个较小的超时时间 `minDynamicTimeout`。
2. **执行 I/O 操作:**  执行 `Read` 或 `Write` 操作。
3. **检查是否超时:** 检查操作是否返回了超时错误 (`isDeadlineExceeded(err)`)。
4. **检查实际耗时:** 计算实际操作花费的时间 `actual`。
5. **与预期比较:** 将 `actual` 与预期的最大超时时间 `timeoutUpperBound(d)` 进行比较。`timeoutUpperBound` 函数会根据操作系统调整预期的最大超时时间，考虑到不同操作系统的调度特性。
6. **动态调整:**
   - 如果操作没有超时，或者实际耗时在预期范围内，则测试认为当前超时设置是合理的。
   - 如果操作超时，但实际耗时超过了预期，说明系统可能比较慢，需要更长的超时时间。此时，`nextTimeout` 函数会计算一个新的、更长的超时时间，并更新 `d`，然后进行下一次迭代测试。
   - 如果实际耗时非常长，超过了 `maxDynamicTimeout`，则认为测试失败，因为超时时间已经过长，无法准确测试。

**输出:**  测试日志会显示每次设置的超时时间以及实际操作花费的时间。如果系统较慢，日志中会看到超时时间逐渐增加，直到操作能够超时或者达到最大超时时间。

**命令行参数:**

这段代码本身是一个测试文件，通常通过 `go test` 命令来运行。 `go test` 命令本身有很多参数，例如：

* **`-v`**:  显示详细的测试输出。
* **`-run <regexp>`**:  只运行匹配正则表达式的测试用例。
* **`-short`**:  运行时间较短的测试用例，会跳过一些耗时的测试。
* **`-timeout <duration>`**: 设置测试用例的整体超时时间。

例如，要运行 `timeout_test.go` 文件中的所有测试用例，可以使用命令：

```bash
go test go/src/os/timeout_test.go
```

要运行名称包含 "ReadTimeout" 的测试用例，可以使用：

```bash
go test -run ReadTimeout go/src/os/timeout_test.go
```

**使用者易犯错的点:**

在使用截止时间时，一个常见的错误是**没有正确检查错误类型**。当 I/O 操作超时时，会返回 `os.ErrDeadlineExceeded` 错误。开发者应该使用 `os.IsTimeout(err)` 函数来判断错误是否是超时错误，而不是直接比较错误字符串或者使用 `errors.Is` 或 `errors.As` 检查 `os.ErrDeadlineExceeded`。

**错误示例:**

```go
n, err := r.Read(buf)
if err != nil {
	if err == os.ErrDeadlineExceeded { // 错误的方式
		fmt.Println("Read timed out")
	} else {
		fmt.Println("Read error:", err)
	}
}
```

**正确示例:**

```go
n, err := r.Read(buf)
if err != nil {
	if os.IsTimeout(err) { // 正确的方式
		fmt.Println("Read timed out")
	} else {
		fmt.Println("Read error:", err)
	}
}
```

使用 `os.IsTimeout(err)` 可以更健壮地处理超时错误，因为它考虑了可能发生的错误包装。

Prompt: 
```
这是路径为go/src/os/timeout_test.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。

"""
// Copyright 2017 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build !js && !plan9 && !wasip1 && !windows

package os_test

import (
	"fmt"
	"io"
	"math/rand"
	"os"
	"os/signal"
	"runtime"
	"sync"
	"syscall"
	"testing"
	"time"
)

func TestNonpollableDeadline(t *testing.T) {
	// On BSD systems regular files seem to be pollable,
	// so just run this test on Linux.
	if runtime.GOOS != "linux" {
		t.Skipf("skipping on %s", runtime.GOOS)
	}
	t.Parallel()

	f, err := os.CreateTemp("", "ostest")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(f.Name())
	defer f.Close()
	deadline := time.Now().Add(10 * time.Second)
	if err := f.SetDeadline(deadline); err != os.ErrNoDeadline {
		t.Errorf("SetDeadline on file returned %v, wanted %v", err, os.ErrNoDeadline)
	}
	if err := f.SetReadDeadline(deadline); err != os.ErrNoDeadline {
		t.Errorf("SetReadDeadline on file returned %v, wanted %v", err, os.ErrNoDeadline)
	}
	if err := f.SetWriteDeadline(deadline); err != os.ErrNoDeadline {
		t.Errorf("SetWriteDeadline on file returned %v, wanted %v", err, os.ErrNoDeadline)
	}
}

// noDeadline is a zero time.Time value, which cancels a deadline.
var noDeadline time.Time

var readTimeoutTests = []struct {
	timeout time.Duration
	xerrs   [2]error // expected errors in transition
}{
	// Tests that read deadlines work, even if there's data ready
	// to be read.
	{-5 * time.Second, [2]error{os.ErrDeadlineExceeded, os.ErrDeadlineExceeded}},

	{50 * time.Millisecond, [2]error{nil, os.ErrDeadlineExceeded}},
}

// There is a very similar copy of this in net/timeout_test.go.
func TestReadTimeout(t *testing.T) {
	t.Parallel()

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	defer w.Close()

	if _, err := w.Write([]byte("READ TIMEOUT TEST")); err != nil {
		t.Fatal(err)
	}

	for i, tt := range readTimeoutTests {
		if err := r.SetReadDeadline(time.Now().Add(tt.timeout)); err != nil {
			t.Fatalf("#%d: %v", i, err)
		}
		var b [1]byte
		for j, xerr := range tt.xerrs {
			for {
				n, err := r.Read(b[:])
				if xerr != nil {
					if !isDeadlineExceeded(err) {
						t.Fatalf("#%d/%d: %v", i, j, err)
					}
				}
				if err == nil {
					time.Sleep(tt.timeout / 3)
					continue
				}
				if n != 0 {
					t.Fatalf("#%d/%d: read %d; want 0", i, j, n)
				}
				break
			}
		}
	}
}

// There is a very similar copy of this in net/timeout_test.go.
func TestReadTimeoutMustNotReturn(t *testing.T) {
	t.Parallel()

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	defer w.Close()

	max := time.NewTimer(100 * time.Millisecond)
	defer max.Stop()
	ch := make(chan error)
	go func() {
		if err := r.SetDeadline(time.Now().Add(-5 * time.Second)); err != nil {
			t.Error(err)
		}
		if err := r.SetWriteDeadline(time.Now().Add(-5 * time.Second)); err != nil {
			t.Error(err)
		}
		if err := r.SetReadDeadline(noDeadline); err != nil {
			t.Error(err)
		}
		var b [1]byte
		_, err := r.Read(b[:])
		ch <- err
	}()

	select {
	case err := <-ch:
		t.Fatalf("expected Read to not return, but it returned with %v", err)
	case <-max.C:
		w.Close()
		err := <-ch // wait for tester goroutine to stop
		if os.IsTimeout(err) {
			t.Fatal(err)
		}
	}
}

var writeTimeoutTests = []struct {
	timeout time.Duration
	xerrs   [2]error // expected errors in transition
}{
	// Tests that write deadlines work, even if there's buffer
	// space available to write.
	{-5 * time.Second, [2]error{os.ErrDeadlineExceeded, os.ErrDeadlineExceeded}},

	{10 * time.Millisecond, [2]error{nil, os.ErrDeadlineExceeded}},
}

// There is a very similar copy of this in net/timeout_test.go.
func TestWriteTimeout(t *testing.T) {
	t.Parallel()

	for i, tt := range writeTimeoutTests {
		t.Run(fmt.Sprintf("#%d", i), func(t *testing.T) {
			r, w, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			defer r.Close()
			defer w.Close()

			if err := w.SetWriteDeadline(time.Now().Add(tt.timeout)); err != nil {
				t.Fatalf("%v", err)
			}
			for j, xerr := range tt.xerrs {
				for {
					n, err := w.Write([]byte("WRITE TIMEOUT TEST"))
					if xerr != nil {
						if !isDeadlineExceeded(err) {
							t.Fatalf("%d: %v", j, err)
						}
					}
					if err == nil {
						time.Sleep(tt.timeout / 3)
						continue
					}
					if n != 0 {
						t.Fatalf("%d: wrote %d; want 0", j, n)
					}
					break
				}
			}
		})
	}
}

// There is a very similar copy of this in net/timeout_test.go.
func TestWriteTimeoutMustNotReturn(t *testing.T) {
	t.Parallel()

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	defer w.Close()

	max := time.NewTimer(100 * time.Millisecond)
	defer max.Stop()
	ch := make(chan error)
	go func() {
		if err := w.SetDeadline(time.Now().Add(-5 * time.Second)); err != nil {
			t.Error(err)
		}
		if err := w.SetReadDeadline(time.Now().Add(-5 * time.Second)); err != nil {
			t.Error(err)
		}
		if err := w.SetWriteDeadline(noDeadline); err != nil {
			t.Error(err)
		}
		var b [1]byte
		for {
			if _, err := w.Write(b[:]); err != nil {
				ch <- err
				break
			}
		}
	}()

	select {
	case err := <-ch:
		t.Fatalf("expected Write to not return, but it returned with %v", err)
	case <-max.C:
		r.Close()
		err := <-ch // wait for tester goroutine to stop
		if os.IsTimeout(err) {
			t.Fatal(err)
		}
	}
}

const (
	// minDynamicTimeout is the minimum timeout to attempt for
	// tests that automatically increase timeouts until success.
	//
	// Lower values may allow tests to succeed more quickly if the value is close
	// to the true minimum, but may require more iterations (and waste more time
	// and CPU power on failed attempts) if the timeout is too low.
	minDynamicTimeout = 1 * time.Millisecond

	// maxDynamicTimeout is the maximum timeout to attempt for
	// tests that automatically increase timeouts until success.
	//
	// This should be a strict upper bound on the latency required to hit a
	// timeout accurately, even on a slow or heavily-loaded machine. If a test
	// would increase the timeout beyond this value, the test fails.
	maxDynamicTimeout = 4 * time.Second
)

// timeoutUpperBound returns the maximum time that we expect a timeout of
// duration d to take to return the caller.
func timeoutUpperBound(d time.Duration) time.Duration {
	switch runtime.GOOS {
	case "openbsd", "netbsd":
		// NetBSD and OpenBSD seem to be unable to reliably hit deadlines even when
		// the absolute durations are long.
		// In https://build.golang.org/log/c34f8685d020b98377dd4988cd38f0c5bd72267e,
		// we observed that an openbsd-amd64-68 builder took 4.090948779s for a
		// 2.983020682s timeout (37.1% overhead).
		// (See https://go.dev/issue/50189 for further detail.)
		// Give them lots of slop to compensate.
		return d * 3 / 2
	}
	// Other platforms seem to hit their deadlines more reliably,
	// at least when they are long enough to cover scheduling jitter.
	return d * 11 / 10
}

// nextTimeout returns the next timeout to try after an operation took the given
// actual duration with a timeout shorter than that duration.
func nextTimeout(actual time.Duration) (next time.Duration, ok bool) {
	if actual >= maxDynamicTimeout {
		return maxDynamicTimeout, false
	}
	// Since the previous attempt took actual, we can't expect to beat that
	// duration by any significant margin. Try the next attempt with an arbitrary
	// factor above that, so that our growth curve is at least exponential.
	next = actual * 5 / 4
	if next > maxDynamicTimeout {
		return maxDynamicTimeout, true
	}
	return next, true
}

// There is a very similar copy of this in net/timeout_test.go.
func TestReadTimeoutFluctuation(t *testing.T) {
	t.Parallel()

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	defer w.Close()

	d := minDynamicTimeout
	b := make([]byte, 256)
	for {
		t.Logf("SetReadDeadline(+%v)", d)
		t0 := time.Now()
		deadline := t0.Add(d)
		if err = r.SetReadDeadline(deadline); err != nil {
			t.Fatalf("SetReadDeadline(%v): %v", deadline, err)
		}
		var n int
		n, err = r.Read(b)
		t1 := time.Now()

		if n != 0 || err == nil || !isDeadlineExceeded(err) {
			t.Errorf("Read did not return (0, timeout): (%d, %v)", n, err)
		}

		actual := t1.Sub(t0)
		if t1.Before(deadline) {
			t.Errorf("Read took %s; expected at least %s", actual, d)
		}
		if t.Failed() {
			return
		}
		if want := timeoutUpperBound(d); actual > want {
			next, ok := nextTimeout(actual)
			if !ok {
				t.Fatalf("Read took %s; expected at most %v", actual, want)
			}
			// Maybe this machine is too slow to reliably schedule goroutines within
			// the requested duration. Increase the timeout and try again.
			t.Logf("Read took %s (expected %s); trying with longer timeout", actual, d)
			d = next
			continue
		}

		break
	}
}

// There is a very similar copy of this in net/timeout_test.go.
func TestWriteTimeoutFluctuation(t *testing.T) {
	t.Parallel()

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	defer w.Close()

	d := minDynamicTimeout
	for {
		t.Logf("SetWriteDeadline(+%v)", d)
		t0 := time.Now()
		deadline := t0.Add(d)
		if err := w.SetWriteDeadline(deadline); err != nil {
			t.Fatalf("SetWriteDeadline(%v): %v", deadline, err)
		}
		var n int64
		var err error
		for {
			var dn int
			dn, err = w.Write([]byte("TIMEOUT TRANSMITTER"))
			n += int64(dn)
			if err != nil {
				break
			}
		}
		t1 := time.Now()
		// Inv: err != nil
		if !isDeadlineExceeded(err) {
			t.Fatalf("Write did not return (any, timeout): (%d, %v)", n, err)
		}

		actual := t1.Sub(t0)
		if t1.Before(deadline) {
			t.Errorf("Write took %s; expected at least %s", actual, d)
		}
		if t.Failed() {
			return
		}
		if want := timeoutUpperBound(d); actual > want {
			if n > 0 {
				// SetWriteDeadline specifies a time “after which I/O operations fail
				// instead of blocking”. However, the kernel's send buffer is not yet
				// full, we may be able to write some arbitrary (but finite) number of
				// bytes to it without blocking.
				t.Logf("Wrote %d bytes into send buffer; retrying until buffer is full", n)
				if d <= maxDynamicTimeout/2 {
					// We don't know how long the actual write loop would have taken if
					// the buffer were full, so just guess and double the duration so that
					// the next attempt can make twice as much progress toward filling it.
					d *= 2
				}
			} else if next, ok := nextTimeout(actual); !ok {
				t.Fatalf("Write took %s; expected at most %s", actual, want)
			} else {
				// Maybe this machine is too slow to reliably schedule goroutines within
				// the requested duration. Increase the timeout and try again.
				t.Logf("Write took %s (expected %s); trying with longer timeout", actual, d)
				d = next
			}
			continue
		}

		break
	}
}

// There is a very similar copy of this in net/timeout_test.go.
func TestVariousDeadlines(t *testing.T) {
	t.Parallel()
	testVariousDeadlines(t)
}

// There is a very similar copy of this in net/timeout_test.go.
func TestVariousDeadlines1Proc(t *testing.T) {
	// Cannot use t.Parallel - modifies global GOMAXPROCS.
	if testing.Short() {
		t.Skip("skipping in short mode")
	}
	defer runtime.GOMAXPROCS(runtime.GOMAXPROCS(1))
	testVariousDeadlines(t)
}

// There is a very similar copy of this in net/timeout_test.go.
func TestVariousDeadlines4Proc(t *testing.T) {
	// Cannot use t.Parallel - modifies global GOMAXPROCS.
	if testing.Short() {
		t.Skip("skipping in short mode")
	}
	defer runtime.GOMAXPROCS(runtime.GOMAXPROCS(4))
	testVariousDeadlines(t)
}

type neverEnding byte

func (b neverEnding) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = byte(b)
	}
	return len(p), nil
}

func testVariousDeadlines(t *testing.T) {
	type result struct {
		n   int64
		err error
		d   time.Duration
	}

	handler := func(w *os.File, pasvch chan result) {
		// The writer, with no timeouts of its own,
		// sending bytes to clients as fast as it can.
		t0 := time.Now()
		n, err := io.Copy(w, neverEnding('a'))
		dt := time.Since(t0)
		pasvch <- result{n, err, dt}
	}

	for _, timeout := range []time.Duration{
		1 * time.Nanosecond,
		2 * time.Nanosecond,
		5 * time.Nanosecond,
		50 * time.Nanosecond,
		100 * time.Nanosecond,
		200 * time.Nanosecond,
		500 * time.Nanosecond,
		750 * time.Nanosecond,
		1 * time.Microsecond,
		5 * time.Microsecond,
		25 * time.Microsecond,
		250 * time.Microsecond,
		500 * time.Microsecond,
		1 * time.Millisecond,
		5 * time.Millisecond,
		100 * time.Millisecond,
		250 * time.Millisecond,
		500 * time.Millisecond,
		1 * time.Second,
	} {
		numRuns := 3
		if testing.Short() {
			numRuns = 1
			if timeout > 500*time.Microsecond {
				continue
			}
		}
		for run := 0; run < numRuns; run++ {
			t.Run(fmt.Sprintf("%v-%d", timeout, run+1), func(t *testing.T) {
				r, w, err := os.Pipe()
				if err != nil {
					t.Fatal(err)
				}
				defer r.Close()
				defer w.Close()

				pasvch := make(chan result)
				go handler(w, pasvch)

				tooLong := 5 * time.Second
				max := time.NewTimer(tooLong)
				defer max.Stop()
				actvch := make(chan result)
				go func() {
					t0 := time.Now()
					if err := r.SetDeadline(t0.Add(timeout)); err != nil {
						t.Error(err)
					}
					n, err := io.Copy(io.Discard, r)
					dt := time.Since(t0)
					r.Close()
					actvch <- result{n, err, dt}
				}()

				select {
				case res := <-actvch:
					if !isDeadlineExceeded(err) {
						t.Logf("good client timeout after %v, reading %d bytes", res.d, res.n)
					} else {
						t.Fatalf("client Copy = %d, %v; want timeout", res.n, res.err)
					}
				case <-max.C:
					t.Fatalf("timeout (%v) waiting for client to timeout (%v) reading", tooLong, timeout)
				}

				select {
				case res := <-pasvch:
					t.Logf("writer in %v wrote %d: %v", res.d, res.n, res.err)
				case <-max.C:
					t.Fatalf("timeout waiting for writer to finish writing")
				}
			})
		}
	}
}

// There is a very similar copy of this in net/timeout_test.go.
func TestReadWriteDeadlineRace(t *testing.T) {
	t.Parallel()

	N := 1000
	if testing.Short() {
		N = 50
	}

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	defer w.Close()

	var wg sync.WaitGroup
	wg.Add(3)
	go func() {
		defer wg.Done()
		tic := time.NewTicker(2 * time.Microsecond)
		defer tic.Stop()
		for i := 0; i < N; i++ {
			if err := r.SetReadDeadline(time.Now().Add(2 * time.Microsecond)); err != nil {
				break
			}
			if err := w.SetWriteDeadline(time.Now().Add(2 * time.Microsecond)); err != nil {
				break
			}
			<-tic.C
		}
	}()
	go func() {
		defer wg.Done()
		var b [1]byte
		for i := 0; i < N; i++ {
			_, err := r.Read(b[:])
			if err != nil && !isDeadlineExceeded(err) {
				t.Error("Read returned non-timeout error", err)
			}
		}
	}()
	go func() {
		defer wg.Done()
		var b [1]byte
		for i := 0; i < N; i++ {
			_, err := w.Write(b[:])
			if err != nil && !isDeadlineExceeded(err) {
				t.Error("Write returned non-timeout error", err)
			}
		}
	}()
	wg.Wait() // wait for tester goroutine to stop
}

// TestRacyRead tests that it is safe to mutate the input Read buffer
// immediately after cancellation has occurred.
func TestRacyRead(t *testing.T) {
	t.Parallel()

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	defer w.Close()

	var wg sync.WaitGroup
	defer wg.Wait()

	go io.Copy(w, rand.New(rand.NewSource(0)))

	r.SetReadDeadline(time.Now().Add(time.Millisecond))
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()

			b1 := make([]byte, 1024)
			b2 := make([]byte, 1024)
			for j := 0; j < 100; j++ {
				_, err := r.Read(b1)
				copy(b1, b2) // Mutate b1 to trigger potential race
				if err != nil {
					if !isDeadlineExceeded(err) {
						t.Error(err)
					}
					r.SetReadDeadline(time.Now().Add(time.Millisecond))
				}
			}
		}()
	}
}

// TestRacyWrite tests that it is safe to mutate the input Write buffer
// immediately after cancellation has occurred.
func TestRacyWrite(t *testing.T) {
	t.Parallel()

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	defer w.Close()

	var wg sync.WaitGroup
	defer wg.Wait()

	go io.Copy(io.Discard, r)

	w.SetWriteDeadline(time.Now().Add(time.Millisecond))
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()

			b1 := make([]byte, 1024)
			b2 := make([]byte, 1024)
			for j := 0; j < 100; j++ {
				_, err := w.Write(b1)
				copy(b1, b2) // Mutate b1 to trigger potential race
				if err != nil {
					if !isDeadlineExceeded(err) {
						t.Error(err)
					}
					w.SetWriteDeadline(time.Now().Add(time.Millisecond))
				}
			}
		}()
	}
}

// Closing a TTY while reading from it should not hang.  Issue 23943.
func TestTTYClose(t *testing.T) {
	// Ignore SIGTTIN in case we are running in the background.
	signal.Ignore(syscall.SIGTTIN)
	defer signal.Reset(syscall.SIGTTIN)

	f, err := os.Open("/dev/tty")
	if err != nil {
		t.Skipf("skipping because opening /dev/tty failed: %v", err)
	}

	go func() {
		var buf [1]byte
		f.Read(buf[:])
	}()

	// Give the goroutine a chance to enter the read.
	// It doesn't matter much if it occasionally fails to do so,
	// we won't be testing what we want to test but the test will pass.
	time.Sleep(time.Millisecond)

	c := make(chan bool)
	go func() {
		defer close(c)
		f.Close()
	}()

	select {
	case <-c:
	case <-time.After(time.Second):
		t.Error("timed out waiting for close")
	}

	// On some systems the goroutines may now be hanging.
	// There's not much we can do about that.
}

"""



```