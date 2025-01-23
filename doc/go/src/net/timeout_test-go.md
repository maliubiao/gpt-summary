Response:
Let's break down the thought process for analyzing the Go code snippet.

1. **Understand the Request:** The primary goal is to understand the functionality of the given Go code (`timeout_test.go`) and explain it in Chinese. The request specifically asks for:
    * Listing the functions.
    * Inferring the purpose/Go feature it tests.
    * Providing Go code examples.
    * Handling assumptions for code examples.
    * Detailing command-line arguments (if applicable).
    * Identifying common mistakes.

2. **Initial Code Scan and High-Level Overview:**
    * **Package:** `net`. This immediately tells us it's related to network operations in Go's standard library.
    * **Imports:** `context`, `errors`, `fmt`, `io`, `os`, `runtime`, `sync`, `testing`, `time`. The presence of `testing` strongly suggests this is a test file. The `time` package hints at timeouts and deadlines.
    * **Function Names:**  Names like `TestDialTimeout`, `TestAcceptTimeout`, `TestReadTimeout`, `TestWriteTimeout`, `TestReadFromTimeout`, `TestWriteToTimeout`, `TestVariousDeadlines` are very indicative of what's being tested. They clearly point towards testing different network operations with timeout functionalities.
    * **Global Variable:** `dialTimeoutTests`. This is likely a table-driven testing approach for the `TestDialTimeout` function.
    * **`init()` Function:** The `init()` function that modifies `testHookStepTime` suggests a workaround for system timer granularity issues, particularly on Windows.

3. **Deconstructing Each Test Function:**  This is the core of the analysis. For each `Test...` function, ask:
    * **What operation is being tested?** (Dial, Accept, Read, Write, ReadFrom, WriteTo).
    * **What is the core aspect being tested?** (Timeouts, deadlines).
    * **How is the timeout/deadline set?** (Using `Dialer.Timeout`, `Dialer.Deadline`, `SetReadDeadline`, `SetWriteDeadline`, `SetDeadline`).
    * **What are the expected outcomes?** (Errors, specifically timeout errors).
    * **What are the test cases?** (Look for loop structures and data structures like `dialTimeoutTests`, `readTimeoutTests`, etc.). Note the different timeout durations being tested, including negative values (representing deadlines in the past).

4. **Inferring the Go Feature:**  Based on the function names and the use of `time` and error checking, it's clear this file tests the **timeout and deadline mechanisms** provided by the `net` package for various network operations.

5. **Generating Go Code Examples:**  For each key operation (Dial, Accept, Read, Write), create a concise example demonstrating how to set and handle timeouts/deadlines. This involves:
    * Choosing a network type (TCP is a good general choice).
    * Setting up a listener.
    * Using `Dialer` for dialing with timeouts.
    * Using `SetDeadline`, `SetReadDeadline`, `SetWriteDeadline` on connections and listeners.
    * Demonstrating how to check for timeout errors using type assertions and the `Timeout()` method of the `net.Error` interface.
    * **Crucially, include error handling!** Timeout checks are usually within `if err != nil` blocks.

6. **Handling Assumptions and Inputs/Outputs:**  For the code examples, explicitly state the assumptions:
    * A server is running on a specific address.
    * Network connectivity exists.
    * Briefly mention the *expected* output – typically, a timeout error message.

7. **Command-Line Arguments:**  Carefully examine the code for any interaction with `os.Args` or other command-line parsing mechanisms. In this specific file, there are *no* explicit command-line argument handling sections. State this clearly.

8. **Identifying Common Mistakes:** Think about common pitfalls developers might encounter when working with network timeouts:
    * **Not checking for timeout errors specifically:** Just checking `err != nil` is insufficient.
    * **Confusing timeouts and deadlines:**  Explain the difference clearly.
    * **Setting inappropriate timeouts:**  Too short or too long.
    * **Ignoring the `Temporary()` method:** Briefly mention its relevance.

9. **Structuring the Answer in Chinese:**  Translate the findings into clear and concise Chinese. Use appropriate technical terms and explain concepts in a way that a Chinese-speaking developer would understand. Maintain the order requested in the prompt.

10. **Review and Refine:** Reread the generated answer and the original code to ensure accuracy, completeness, and clarity. Check for any grammatical errors or awkward phrasing in the Chinese translation. Ensure that the code examples are correct and easy to understand. For example, initially, I might forget to `defer ln.Close()` in the example, so reviewing helps catch these errors. Also, double-check if the examples align with the inferred functionality.

This systematic approach ensures that all aspects of the request are addressed accurately and comprehensively. It involves a combination of code reading, logical reasoning, and practical experience with Go's networking features.
这个 `go/src/net/timeout_test.go` 文件是 Go 语言标准库 `net` 包的一部分，专门用于测试网络操作中的超时和截止时间（deadline）功能。它涵盖了 `Dial`, `Accept`, `Read`, `Write` 等网络操作的超时行为。

**主要功能:**

1. **测试连接超时 (`TestDialTimeout`):**  测试在尝试建立连接时，如果超过了设置的超时时间或截止时间，`Dial` 函数是否会返回超时错误。
2. **测试大超时时间 (`TestDialTimeoutMaxDuration`):** 测试当设置非常大的超时时间或截止时间时，`Dial` 函数的行为是否正常，不会出现溢出等问题。
3. **测试监听器接受连接超时 (`TestAcceptTimeout`):** 测试当监听器在等待接受连接时，如果超过了设置的截止时间，`Accept` 函数是否会返回超时错误。
4. **测试 `Accept` 超时必须返回 (`TestAcceptTimeoutMustReturn`):** 验证设置了截止时间后，即使没有连接请求，`Accept` 也应该在截止时间到达时返回。
5. **测试 `Accept` 在无超时时不应返回 (`TestAcceptTimeoutMustNotReturn`):** 验证在没有设置超时时间的情况下，`Accept` 会一直阻塞等待连接，除非监听器被关闭。
6. **测试读取超时 (`TestReadTimeout` 和 `TestReadTimeoutMustNotReturn`):** 测试在从连接中读取数据时，如果超过了设置的读取截止时间，`Read` 函数是否会返回超时错误。同时也测试了在没有设置读取截止时间的情况下，`Read` 会一直阻塞等待数据。
7. **测试带地址的读取超时 (`TestReadFromTimeout`):**  针对无连接的 socket (如 UDP)，测试 `ReadFrom` 函数在读取数据时，如果超过了设置的读取截止时间，是否会返回超时错误。
8. **测试写入超时 (`TestWriteTimeout` 和 `TestWriteTimeoutMustNotReturn`):** 测试在向连接中写入数据时，如果超过了设置的写入截止时间，`Write` 函数是否会返回超时错误。同时也测试了在没有设置写入截止时间的情况下，`Write` 会一直阻塞等待写入完成。
9. **测试带地址的写入超时 (`TestWriteToTimeout`):** 针对无连接的 socket (如 UDP)，测试 `WriteTo` 函数在写入数据时，如果超过了设置的写入截止时间，是否会返回超时错误。
10. **测试超时时间的波动 (`TestReadTimeoutFluctuation`, `TestReadFromTimeoutFluctuation`, `TestWriteTimeoutFluctuation`):**  测试在不同的超时时间下，读取和写入操作是否能在预期的超时时间内返回。这些测试会动态调整超时时间，以验证超时机制的准确性。
11. **测试各种不同的截止时间 (`TestVariousDeadlines`, `TestVariousDeadlines1Proc`, `TestVariousDeadlines4Proc`):** 测试使用各种不同的极短的截止时间（从纳秒到秒级别），来验证超时机制的精度。
12. **测试长时间的读写超时 (`TestReadWriteProlongedTimeout`):** 测试在长时间的读写操作中设置和修改截止时间是否会导致竞态条件。
13. **测试读写截止时间的竞态 (`TestReadWriteDeadlineRace`):** 测试并发地设置读写截止时间是否会导致竞态条件。
14. **测试并发设置截止时间 (`TestConcurrentSetDeadline`):** 测试多个 goroutine 并发地为一个连接设置读写截止时间是否会导致问题。
15. **辅助函数 (`isDeadlineExceeded`):** 提供一个方便的函数来判断错误是否是由于截止时间超出导致的。

**它是什么 Go 语言功能的实现？**

这个文件主要测试了 `net` 包中与超时和截止时间相关的核心功能，包括：

* **`Dialer.Timeout`:**  用于设置 `Dial` 函数的连接超时时间。
* **`Dialer.Deadline`:** 用于设置 `Dial` 函数的连接截止时间。
* **`Conn.SetDeadline(t time.Time)`:**  用于设置连接的读取和写入操作的截止时间。
* **`Conn.SetReadDeadline(t time.Time)`:** 用于设置连接的读取操作的截止时间。
* **`Conn.SetWriteDeadline(t time.Time)`:** 用于设置连接的写入操作的截止时间。
* **`Listener.SetDeadline(t time.Time)`:** 用于设置监听器 `Accept` 操作的截止时间。
* **错误类型 `net.Error` 及其 `Timeout()` 方法:** 用于判断网络操作是否因为超时而失败。

**Go 代码举例说明:**

**1. 使用 `Dialer` 设置连接超时:**

```go
package main

import (
	"fmt"
	"net"
	"time"
)

func main() {
	dialer := net.Dialer{Timeout: 100 * time.Millisecond} // 设置 100 毫秒超时
	conn, err := dialer.Dial("tcp", "10.255.255.1:80") // 假设这个地址不可达或响应很慢
	if err != nil {
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			fmt.Println("连接超时:", err) // 假设输出: 连接超时: dial tcp 10.255.255.1:80: i/o timeout
		} else {
			fmt.Println("连接错误:", err)
		}
		return
	}
	defer conn.Close()
	fmt.Println("连接成功!")
}
```

**假设的输入与输出:**

* **假设输入:**  尝试连接一个不存在或者响应非常慢的 IP 地址 `10.255.255.1:80`。
* **假设输出:**  `连接超时: dial tcp 10.255.255.1:80: i/o timeout`

**2. 使用 `Conn.SetDeadline` 设置读写截止时间:**

```go
package main

import (
	"fmt"
	"net"
	"time"
)

func main() {
	ln, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		panic(err)
	}
	defer ln.Close()

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			fmt.Println("Accept error:", err)
			return
		}
		defer conn.Close()
		// 模拟服务器端不发送数据
		time.Sleep(200 * time.Millisecond)
	}()

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		panic(err)
	}
	defer conn.Close()

	// 设置 100 毫秒的读截止时间
	err = conn.SetDeadline(time.Now().Add(100 * time.Millisecond))
	if err != nil {
		panic(err)
	}

	buf := make([]byte, 1024)
	_, err = conn.Read(buf)
	if err != nil {
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			fmt.Println("读取超时:", err) // 假设输出: 读取超时: read tcp [::1]:xxxxx->[::1]:yyyyy: i/o timeout
		} else {
			fmt.Println("读取错误:", err)
		}
		return
	}
	fmt.Println("读取到数据")
}
```

**假设的输入与输出:**

* **假设输入:**  客户端连接到服务端，服务端延迟 200 毫秒后才可能发送数据，而客户端设置了 100 毫秒的读截止时间。
* **假设输出:**  `读取超时: read tcp [::1]:xxxxx->[::1]:yyyyy: i/o timeout` （具体的本地端口会不同）

**命令行参数:**

这个 `timeout_test.go` 文件本身是一个测试文件，主要通过 `go test` 命令来运行。它不直接处理任何用户提供的命令行参数。`go test` 命令本身有一些参数，例如 `-v` (显示详细输出), `-run` (指定运行的测试用例) 等，但这与 `timeout_test.go` 内部的逻辑无关。

**使用者易犯错的点:**

1. **没有正确检查超时错误:**  开发者可能会只检查 `err != nil`，而没有进一步判断错误是否是由于超时引起的。应该使用类型断言和 `net.Error` 接口的 `Timeout()` 方法来明确判断。

   ```go
   conn, err := net.DialTimeout("tcp", "example.com:80", 50*time.Millisecond)
   if err != nil {
       // 错误，但不知道是不是超时
       fmt.Println("连接失败:", err)
   }

   // 正确的做法
   if err != nil {
       if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
           fmt.Println("连接超时:", err)
       } else {
           fmt.Println("其他连接错误:", err)
       }
       return
   }
   ```

2. **混淆 Timeout 和 Deadline 的概念:**  `Timeout` 是一个持续时间，表示操作允许的最大耗时。`Deadline` 是一个具体的时刻，表示操作必须在这个时间点之前完成。

   * 使用 `Dialer.Timeout` 设置的是连接建立的最大时长。
   * 使用 `Conn.SetDeadline` 设置的是一个绝对的时间点，如果当前时间超过了这个时间点，任何读写操作都会立即返回超时错误。

3. **设置过短的超时时间:**  如果网络环境不稳定或者服务器响应较慢，设置过短的超时时间可能会导致操作频繁超时，即使最终操作可以成功。应该根据实际情况设置合理的超时时间。

4. **在不需要超时的情况下设置了超时时间:**  有时候，某些操作可能需要一直等待，例如监听端口等待连接。在这种情况下，设置了超时时间反而可能会导致意外的错误。应该只在确实需要限制操作时间的情况下才设置超时或截止时间。

5. **忘记处理临时的网络错误 (`Temporary()`):**  `net.Error` 接口还提供了 `Temporary()` 方法，用于判断错误是否是临时的。在某些需要重试的网络操作中，应该同时考虑超时错误和临时错误。

总而言之，`go/src/net/timeout_test.go` 是一个非常重要的测试文件，它确保了 Go 语言 `net` 包中超时和截止时间功能的正确性和健壮性，这对于构建可靠的网络应用程序至关重要。理解这个文件中的测试用例可以帮助开发者更好地理解和使用 Go 的网络超时机制。

### 提示词
```
这是路径为go/src/net/timeout_test.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
```

### 源代码
```go
// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package net

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"
	"sync"
	"testing"
	"time"
)

func init() {
	// Install a hook to ensure that a 1ns timeout will always
	// be exceeded by the time Dial gets to the relevant system call.
	//
	// Without this, systems with a very large timer granularity — such as
	// Windows — may be able to accept connections without measurably exceeding
	// even an implausibly short deadline.
	testHookStepTime = func() {
		now := time.Now()
		for time.Since(now) == 0 {
			time.Sleep(1 * time.Nanosecond)
		}
	}
}

var dialTimeoutTests = []struct {
	initialTimeout time.Duration
	initialDelta   time.Duration // for deadline
}{
	// Tests that dial timeouts, deadlines in the past work.
	{-5 * time.Second, 0},
	{0, -5 * time.Second},
	{-5 * time.Second, 5 * time.Second}, // timeout over deadline
	{-1 << 63, 0},
	{0, -1 << 63},

	{1 * time.Millisecond, 0},
	{0, 1 * time.Millisecond},
	{1 * time.Millisecond, 5 * time.Second}, // timeout over deadline
}

func TestDialTimeout(t *testing.T) {
	switch runtime.GOOS {
	case "plan9":
		t.Skipf("not supported on %s", runtime.GOOS)
	}

	t.Parallel()

	ln := newLocalListener(t, "tcp")
	defer func() {
		if err := ln.Close(); err != nil {
			t.Error(err)
		}
	}()

	for _, tt := range dialTimeoutTests {
		t.Run(fmt.Sprintf("%v/%v", tt.initialTimeout, tt.initialDelta), func(t *testing.T) {
			// We don't run these subtests in parallel because we don't know how big
			// the kernel's accept queue is, and we don't want to accidentally saturate
			// it with concurrent calls. (That could cause the Dial to fail with
			// ECONNREFUSED or ECONNRESET instead of a timeout error.)
			d := Dialer{Timeout: tt.initialTimeout}
			delta := tt.initialDelta

			var (
				beforeDial time.Time
				afterDial  time.Time
				err        error
			)
			for {
				if delta != 0 {
					d.Deadline = time.Now().Add(delta)
				}

				beforeDial = time.Now()

				var c Conn
				c, err = d.Dial(ln.Addr().Network(), ln.Addr().String())
				afterDial = time.Now()

				if err != nil {
					break
				}

				// Even though we're not calling Accept on the Listener, the kernel may
				// spuriously accept connections on its behalf. If that happens, we will
				// close the connection (to try to get it out of the kernel's accept
				// queue) and try a shorter timeout.
				//
				// We assume that we will reach a point where the call actually does
				// time out, although in theory (since this socket is on a loopback
				// address) a sufficiently clever kernel could notice that no Accept
				// call is pending and bypass both the queue and the timeout to return
				// another error immediately.
				t.Logf("closing spurious connection from Dial")
				c.Close()

				if delta <= 1 && d.Timeout <= 1 {
					t.Fatalf("can't reduce Timeout or Deadline")
				}
				if delta > 1 {
					delta /= 2
					t.Logf("reducing Deadline delta to %v", delta)
				}
				if d.Timeout > 1 {
					d.Timeout /= 2
					t.Logf("reducing Timeout to %v", d.Timeout)
				}
			}

			if d.Deadline.IsZero() || afterDial.Before(d.Deadline) {
				delay := afterDial.Sub(beforeDial)
				if delay < d.Timeout {
					t.Errorf("Dial returned after %v; want ≥%v", delay, d.Timeout)
				}
			}

			if perr := parseDialError(err); perr != nil {
				t.Errorf("unexpected error from Dial: %v", perr)
			}
			if nerr, ok := err.(Error); !ok || !nerr.Timeout() {
				t.Errorf("Dial: %v, want timeout", err)
			}
		})
	}
}

func TestDialTimeoutMaxDuration(t *testing.T) {
	ln := newLocalListener(t, "tcp")
	defer func() {
		if err := ln.Close(); err != nil {
			t.Error(err)
		}
	}()

	for _, tt := range []struct {
		timeout time.Duration
		delta   time.Duration // for deadline
	}{
		// Large timeouts that will overflow an int64 unix nanos.
		{1<<63 - 1, 0},
		{0, 1<<63 - 1},
	} {
		t.Run(fmt.Sprintf("timeout=%s/delta=%s", tt.timeout, tt.delta), func(t *testing.T) {
			d := Dialer{Timeout: tt.timeout}
			if tt.delta != 0 {
				d.Deadline = time.Now().Add(tt.delta)
			}
			c, err := d.Dial(ln.Addr().Network(), ln.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			if err := c.Close(); err != nil {
				t.Error(err)
			}
		})
	}
}

func TestAcceptTimeout(t *testing.T) {
	t.Parallel()

	switch runtime.GOOS {
	case "plan9":
		t.Skipf("not supported on %s", runtime.GOOS)
	}

	timeouts := []time.Duration{
		-5 * time.Second,
		10 * time.Millisecond,
	}

	for _, timeout := range timeouts {
		timeout := timeout
		t.Run(fmt.Sprintf("%v", timeout), func(t *testing.T) {
			t.Parallel()

			ln := newLocalListener(t, "tcp")
			defer ln.Close()

			if timeout >= 0 {
				// Don't dial the listener at all, so that Accept will hang.
			} else {
				// A deadline in the past should cause Accept to fail even if there are
				// incoming connections available. Try to make one available before the
				// call to Accept happens. (It's ok if the timing doesn't always work
				// out that way, though: the test should pass regardless.)
				ctx, cancel := context.WithCancel(context.Background())
				dialDone := make(chan struct{})

				// Ensure that our background Dial returns before we close the listener.
				// Otherwise, the listener's port could be reused immediately and we
				// might spuriously Dial some completely unrelated socket, causing some
				// other test to see an unexpected extra connection.
				defer func() {
					cancel()
					<-dialDone
				}()

				go func() {
					defer close(dialDone)
					d := Dialer{}
					c, err := d.DialContext(ctx, ln.Addr().Network(), ln.Addr().String())
					if err != nil {
						// If the timing didn't work out, it is possible for this Dial
						// to return an error (depending on the kernel's buffering behavior).
						// In https://go.dev/issue/65240 we saw failures with ECONNREFUSED
						// and ECONNRESET.
						//
						// What this test really cares about is the behavior of Accept, not
						// Dial, so just log the error and ignore it.
						t.Logf("DialContext: %v", err)
						return
					}
					t.Logf("Dialed %v -> %v", c.LocalAddr(), c.RemoteAddr())
					c.Close()
				}()

				time.Sleep(10 * time.Millisecond)
			}

			if err := ln.(*TCPListener).SetDeadline(time.Now().Add(timeout)); err != nil {
				t.Fatal(err)
			}
			t.Logf("ln.SetDeadline(time.Now().Add(%v))", timeout)

			c, err := ln.Accept()
			if err == nil {
				c.Close()
			}
			t.Logf("ln.Accept: %v", err)

			if perr := parseAcceptError(err); perr != nil {
				t.Error(perr)
			}
			if !isDeadlineExceeded(err) {
				t.Error("wanted deadline exceeded")
			}
		})
	}
}

func TestAcceptTimeoutMustReturn(t *testing.T) {
	t.Parallel()

	switch runtime.GOOS {
	case "plan9":
		t.Skipf("not supported on %s", runtime.GOOS)
	}

	ln := newLocalListener(t, "tcp")
	defer ln.Close()

	if err := ln.(*TCPListener).SetDeadline(noDeadline); err != nil {
		t.Error(err)
	}
	if err := ln.(*TCPListener).SetDeadline(time.Now().Add(10 * time.Millisecond)); err != nil {
		t.Error(err)
	}
	c, err := ln.Accept()
	if err == nil {
		c.Close()
	}

	if perr := parseAcceptError(err); perr != nil {
		t.Error(perr)
	}
	if !isDeadlineExceeded(err) {
		t.Fatal(err)
	}
}

func TestAcceptTimeoutMustNotReturn(t *testing.T) {
	t.Parallel()

	switch runtime.GOOS {
	case "plan9":
		t.Skipf("not supported on %s", runtime.GOOS)
	}

	ln := newLocalListener(t, "tcp")
	defer ln.Close()

	maxch := make(chan *time.Timer)
	ch := make(chan error)
	go func() {
		if err := ln.(*TCPListener).SetDeadline(time.Now().Add(-5 * time.Second)); err != nil {
			t.Error(err)
		}
		if err := ln.(*TCPListener).SetDeadline(noDeadline); err != nil {
			t.Error(err)
		}
		maxch <- time.NewTimer(100 * time.Millisecond)
		_, err := ln.Accept()
		ch <- err
	}()

	max := <-maxch
	defer max.Stop()

	select {
	case err := <-ch:
		if perr := parseAcceptError(err); perr != nil {
			t.Error(perr)
		}
		t.Fatalf("expected Accept to not return, but it returned with %v", err)
	case <-max.C:
		ln.Close()
		<-ch // wait for tester goroutine to stop
	}
}

var readTimeoutTests = []struct {
	timeout time.Duration
	xerrs   [2]error // expected errors in transition
}{
	// Tests that read deadlines work, even if there's data ready
	// to be read.
	{-5 * time.Second, [2]error{os.ErrDeadlineExceeded, os.ErrDeadlineExceeded}},

	{50 * time.Millisecond, [2]error{nil, os.ErrDeadlineExceeded}},
}

// There is a very similar copy of this in os/timeout_test.go.
func TestReadTimeout(t *testing.T) {
	handler := func(ls *localServer, ln Listener) {
		c, err := ln.Accept()
		if err != nil {
			t.Error(err)
			return
		}
		c.Write([]byte("READ TIMEOUT TEST"))
		defer c.Close()
	}
	ls := newLocalServer(t, "tcp")
	defer ls.teardown()
	if err := ls.buildup(handler); err != nil {
		t.Fatal(err)
	}

	c, err := Dial(ls.Listener.Addr().Network(), ls.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	for i, tt := range readTimeoutTests {
		if err := c.SetReadDeadline(time.Now().Add(tt.timeout)); err != nil {
			t.Fatalf("#%d: %v", i, err)
		}
		var b [1]byte
		for j, xerr := range tt.xerrs {
			for {
				n, err := c.Read(b[:])
				if xerr != nil {
					if perr := parseReadError(err); perr != nil {
						t.Errorf("#%d/%d: %v", i, j, perr)
					}
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

// There is a very similar copy of this in os/timeout_test.go.
func TestReadTimeoutMustNotReturn(t *testing.T) {
	t.Parallel()

	switch runtime.GOOS {
	case "plan9":
		t.Skipf("not supported on %s", runtime.GOOS)
	}

	ln := newLocalListener(t, "tcp")
	defer ln.Close()

	c, err := Dial(ln.Addr().Network(), ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	maxch := make(chan *time.Timer)
	ch := make(chan error)
	go func() {
		if err := c.SetDeadline(time.Now().Add(-5 * time.Second)); err != nil {
			t.Error(err)
		}
		if err := c.SetWriteDeadline(time.Now().Add(-5 * time.Second)); err != nil {
			t.Error(err)
		}
		if err := c.SetReadDeadline(noDeadline); err != nil {
			t.Error(err)
		}
		maxch <- time.NewTimer(100 * time.Millisecond)
		var b [1]byte
		_, err := c.Read(b[:])
		ch <- err
	}()

	max := <-maxch
	defer max.Stop()

	select {
	case err := <-ch:
		if perr := parseReadError(err); perr != nil {
			t.Error(perr)
		}
		t.Fatalf("expected Read to not return, but it returned with %v", err)
	case <-max.C:
		c.Close()
		err := <-ch // wait for tester goroutine to stop
		if perr := parseReadError(err); perr != nil {
			t.Error(perr)
		}
		if nerr, ok := err.(Error); !ok || nerr.Timeout() || nerr.Temporary() {
			t.Fatal(err)
		}
	}
}

var readFromTimeoutTests = []struct {
	timeout time.Duration
	xerrs   [2]error // expected errors in transition
}{
	// Tests that read deadlines work, even if there's data ready
	// to be read.
	{-5 * time.Second, [2]error{os.ErrDeadlineExceeded, os.ErrDeadlineExceeded}},

	{50 * time.Millisecond, [2]error{nil, os.ErrDeadlineExceeded}},
}

func TestReadFromTimeout(t *testing.T) {
	ch := make(chan Addr)
	defer close(ch)
	handler := func(ls *localPacketServer, c PacketConn) {
		if dst, ok := <-ch; ok {
			c.WriteTo([]byte("READFROM TIMEOUT TEST"), dst)
		}
	}
	ls := newLocalPacketServer(t, "udp")
	defer ls.teardown()
	if err := ls.buildup(handler); err != nil {
		t.Fatal(err)
	}

	host, _, err := SplitHostPort(ls.PacketConn.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	c, err := ListenPacket(ls.PacketConn.LocalAddr().Network(), JoinHostPort(host, "0"))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	ch <- c.LocalAddr()

	for i, tt := range readFromTimeoutTests {
		if err := c.SetReadDeadline(time.Now().Add(tt.timeout)); err != nil {
			t.Fatalf("#%d: %v", i, err)
		}
		var b [1]byte
		for j, xerr := range tt.xerrs {
			for {
				n, _, err := c.ReadFrom(b[:])
				if xerr != nil {
					if perr := parseReadError(err); perr != nil {
						t.Errorf("#%d/%d: %v", i, j, perr)
					}
					if !isDeadlineExceeded(err) {
						t.Fatalf("#%d/%d: %v", i, j, err)
					}
				}
				if err == nil {
					time.Sleep(tt.timeout / 3)
					continue
				}
				if nerr, ok := err.(Error); ok && nerr.Timeout() && n != 0 {
					t.Fatalf("#%d/%d: read %d; want 0", i, j, n)
				}
				break
			}
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

// There is a very similar copy of this in os/timeout_test.go.
func TestWriteTimeout(t *testing.T) {
	t.Parallel()

	ln := newLocalListener(t, "tcp")
	defer ln.Close()

	for i, tt := range writeTimeoutTests {
		c, err := Dial(ln.Addr().Network(), ln.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()

		if err := c.SetWriteDeadline(time.Now().Add(tt.timeout)); err != nil {
			t.Fatalf("#%d: %v", i, err)
		}
		for j, xerr := range tt.xerrs {
			for {
				n, err := c.Write([]byte("WRITE TIMEOUT TEST"))
				if xerr != nil {
					if perr := parseWriteError(err); perr != nil {
						t.Errorf("#%d/%d: %v", i, j, perr)
					}
					if !isDeadlineExceeded(err) {
						t.Fatalf("#%d/%d: %v", i, j, err)
					}
				}
				if err == nil {
					time.Sleep(tt.timeout / 3)
					continue
				}
				if n != 0 {
					t.Fatalf("#%d/%d: wrote %d; want 0", i, j, n)
				}
				break
			}
		}
	}
}

// There is a very similar copy of this in os/timeout_test.go.
func TestWriteTimeoutMustNotReturn(t *testing.T) {
	t.Parallel()

	switch runtime.GOOS {
	case "plan9":
		t.Skipf("not supported on %s", runtime.GOOS)
	}

	ln := newLocalListener(t, "tcp")
	defer ln.Close()

	c, err := Dial(ln.Addr().Network(), ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	maxch := make(chan *time.Timer)
	ch := make(chan error)
	go func() {
		if err := c.SetDeadline(time.Now().Add(-5 * time.Second)); err != nil {
			t.Error(err)
		}
		if err := c.SetReadDeadline(time.Now().Add(-5 * time.Second)); err != nil {
			t.Error(err)
		}
		if err := c.SetWriteDeadline(noDeadline); err != nil {
			t.Error(err)
		}
		maxch <- time.NewTimer(100 * time.Millisecond)
		var b [1024]byte
		for {
			if _, err := c.Write(b[:]); err != nil {
				ch <- err
				break
			}
		}
	}()

	max := <-maxch
	defer max.Stop()

	select {
	case err := <-ch:
		if perr := parseWriteError(err); perr != nil {
			t.Error(perr)
		}
		t.Fatalf("expected Write to not return, but it returned with %v", err)
	case <-max.C:
		c.Close()
		err := <-ch // wait for tester goroutine to stop
		if perr := parseWriteError(err); perr != nil {
			t.Error(perr)
		}
		if nerr, ok := err.(Error); !ok || nerr.Timeout() || nerr.Temporary() {
			t.Fatal(err)
		}
	}
}

func TestWriteToTimeout(t *testing.T) {
	t.Parallel()

	c1 := newLocalPacketListener(t, "udp")
	defer c1.Close()

	host, _, err := SplitHostPort(c1.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}

	timeouts := []time.Duration{
		-5 * time.Second,
		10 * time.Millisecond,
	}

	for _, timeout := range timeouts {
		t.Run(fmt.Sprint(timeout), func(t *testing.T) {
			c2, err := ListenPacket(c1.LocalAddr().Network(), JoinHostPort(host, "0"))
			if err != nil {
				t.Fatal(err)
			}
			defer c2.Close()

			if err := c2.SetWriteDeadline(time.Now().Add(timeout)); err != nil {
				t.Fatalf("SetWriteDeadline: %v", err)
			}
			backoff := 1 * time.Millisecond
			nDeadlineExceeded := 0
			for j := 0; nDeadlineExceeded < 2; j++ {
				n, err := c2.WriteTo([]byte("WRITETO TIMEOUT TEST"), c1.LocalAddr())
				t.Logf("#%d: WriteTo: %d, %v", j, n, err)
				if err == nil && timeout >= 0 && nDeadlineExceeded == 0 {
					// If the timeout is nonnegative, some number of WriteTo calls may
					// succeed before the timeout takes effect.
					t.Logf("WriteTo succeeded; sleeping %v", timeout/3)
					time.Sleep(timeout / 3)
					continue
				}
				if isENOBUFS(err) {
					t.Logf("WriteTo: %v", err)
					// We're looking for a deadline exceeded error, but if the kernel's
					// network buffers are saturated we may see ENOBUFS instead (see
					// https://go.dev/issue/49930). Give it some time to unsaturate.
					time.Sleep(backoff)
					backoff *= 2
					continue
				}
				if perr := parseWriteError(err); perr != nil {
					t.Errorf("failed to parse error: %v", perr)
				}
				if !isDeadlineExceeded(err) {
					t.Errorf("error is not 'deadline exceeded'")
				}
				if n != 0 {
					t.Errorf("unexpectedly wrote %d bytes", n)
				}
				if !t.Failed() {
					t.Logf("WriteTo timed out as expected")
				}
				nDeadlineExceeded++
			}
		})
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

// There is a very similar copy of this in os/timeout_test.go.
func TestReadTimeoutFluctuation(t *testing.T) {
	ln := newLocalListener(t, "tcp")
	defer ln.Close()

	c, err := Dial(ln.Addr().Network(), ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	d := minDynamicTimeout
	b := make([]byte, 256)
	for {
		t.Logf("SetReadDeadline(+%v)", d)
		t0 := time.Now()
		deadline := t0.Add(d)
		if err = c.SetReadDeadline(deadline); err != nil {
			t.Fatalf("SetReadDeadline(%v): %v", deadline, err)
		}
		var n int
		n, err = c.Read(b)
		t1 := time.Now()

		if n != 0 || err == nil || !err.(Error).Timeout() {
			t.Errorf("Read did not return (0, timeout): (%d, %v)", n, err)
		}
		if perr := parseReadError(err); perr != nil {
			t.Error(perr)
		}
		if !isDeadlineExceeded(err) {
			t.Errorf("Read error is not DeadlineExceeded: %v", err)
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

// There is a very similar copy of this in os/timeout_test.go.
func TestReadFromTimeoutFluctuation(t *testing.T) {
	c1 := newLocalPacketListener(t, "udp")
	defer c1.Close()

	c2, err := Dial(c1.LocalAddr().Network(), c1.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c2.Close()

	d := minDynamicTimeout
	b := make([]byte, 256)
	for {
		t.Logf("SetReadDeadline(+%v)", d)
		t0 := time.Now()
		deadline := t0.Add(d)
		if err = c2.SetReadDeadline(deadline); err != nil {
			t.Fatalf("SetReadDeadline(%v): %v", deadline, err)
		}
		var n int
		n, _, err = c2.(PacketConn).ReadFrom(b)
		t1 := time.Now()

		if n != 0 || err == nil || !err.(Error).Timeout() {
			t.Errorf("ReadFrom did not return (0, timeout): (%d, %v)", n, err)
		}
		if perr := parseReadError(err); perr != nil {
			t.Error(perr)
		}
		if !isDeadlineExceeded(err) {
			t.Errorf("ReadFrom error is not DeadlineExceeded: %v", err)
		}

		actual := t1.Sub(t0)
		if t1.Before(deadline) {
			t.Errorf("ReadFrom took %s; expected at least %s", actual, d)
		}
		if t.Failed() {
			return
		}
		if want := timeoutUpperBound(d); actual > want {
			next, ok := nextTimeout(actual)
			if !ok {
				t.Fatalf("ReadFrom took %s; expected at most %s", actual, want)
			}
			// Maybe this machine is too slow to reliably schedule goroutines within
			// the requested duration. Increase the timeout and try again.
			t.Logf("ReadFrom took %s (expected %s); trying with longer timeout", actual, d)
			d = next
			continue
		}

		break
	}
}

func TestWriteTimeoutFluctuation(t *testing.T) {
	switch runtime.GOOS {
	case "plan9":
		t.Skipf("not supported on %s", runtime.GOOS)
	}

	ln := newLocalListener(t, "tcp")
	defer ln.Close()

	c, err := Dial(ln.Addr().Network(), ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	d := minDynamicTimeout
	for {
		t.Logf("SetWriteDeadline(+%v)", d)
		t0 := time.Now()
		deadline := t0.Add(d)
		if err := c.SetWriteDeadline(deadline); err != nil {
			t.Fatalf("SetWriteDeadline(%v): %v", deadline, err)
		}
		var n int64
		var err error
		for {
			var dn int
			dn, err = c.Write([]byte("TIMEOUT TRANSMITTER"))
			n += int64(dn)
			if err != nil {
				break
			}
		}
		t1 := time.Now()
		// Inv: err != nil
		if !err.(Error).Timeout() {
			t.Fatalf("Write did not return (any, timeout): (%d, %v)", n, err)
		}
		if perr := parseWriteError(err); perr != nil {
			t.Error(perr)
		}
		if !isDeadlineExceeded(err) {
			t.Errorf("Write error is not DeadlineExceeded: %v", err)
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

// There is a very similar copy of this in os/timeout_test.go.
func TestVariousDeadlines(t *testing.T) {
	t.Parallel()
	testVariousDeadlines(t)
}

// There is a very similar copy of this in os/timeout_test.go.
func TestVariousDeadlines1Proc(t *testing.T) {
	// Cannot use t.Parallel - modifies global GOMAXPROCS.
	if testing.Short() {
		t.Skip("skipping in short mode")
	}
	defer runtime.GOMAXPROCS(runtime.GOMAXPROCS(1))
	testVariousDeadlines(t)
}

// There is a very similar copy of this in os/timeout_test.go.
func TestVariousDeadlines4Proc(t *testing.T) {
	// Cannot use t.Parallel - modifies global GOMAXPROCS.
	if testing.Short() {
		t.Skip("skipping in short mode")
	}
	defer runtime.GOMAXPROCS(runtime.GOMAXPROCS(4))
	testVariousDeadlines(t)
}

func testVariousDeadlines(t *testing.T) {
	handler := func(ls *localServer, ln Listener) {
		for {
			c, err := ln.Accept()
			if err != nil {
				break
			}
			c.Read(make([]byte, 1)) // wait for client to close connection
			c.Close()
		}
	}
	ls := newLocalServer(t, "tcp")
	defer ls.teardown()
	if err := ls.buildup(handler); err != nil {
		t.Fatal(err)
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
			name := fmt.Sprintf("%v %d/%d", timeout, run, numRuns)
			t.Log(name)

			c, err := Dial(ls.Listener.Addr().Network(), ls.Listener.Addr().String())
			if err != nil {
				t.Fatal(err)
			}

			t0 := time.Now()
			if err := c.SetDeadline(t0.Add(timeout)); err != nil {
				t.Error(err)
			}
			n, err := io.Copy(io.Discard, c)
			dt := time.Since(t0)
			c.Close()

			if nerr, ok := err.(Error); ok && nerr.Timeout() {
				t.Logf("%v: good timeout after %v; %d bytes", name, dt, n)
			} else {
				t.Fatalf("%v: Copy = %d, %v; want timeout", name, n, err)
			}
		}
	}
}

// TestReadWriteProlongedTimeout tests concurrent deadline
// modification. Known to cause data races in the past.
func TestReadWriteProlongedTimeout(t *testing.T) {
	t.Parallel()

	switch runtime.GOOS {
	case "plan9":
		t.Skipf("not supported on %s", runtime.GOOS)
	}

	handler := func(ls *localServer, ln Listener) {
		c, err := ln.Accept()
		if err != nil {
			t.Error(err)
			return
		}
		defer c.Close()

		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			defer wg.Done()
			var b [1]byte
			for {
				if err := c.SetReadDeadline(time.Now().Add(time.Hour)); err != nil {
					if perr := parseCommonError(err); perr != nil {
						t.Error(perr)
					}
					t.Error(err)
					return
				}
				if _, err := c.Read(b[:]); err != nil {
					if perr := parseReadError(err); perr != nil {
						t.Error(perr)
					}
					return
				}
			}
		}()
		go func() {
			defer wg.Done()
			var b [1]byte
			for {
				if err := c.SetWriteDeadline(time.Now().Add(time.Hour)); err != nil {
					if perr := parseCommonError(err); perr != nil {
						t.Error(perr)
					}
					t.Error(err)
					return
				}
				if _, err := c.Write(b[:]); err != nil {
					if perr := parseWriteError(err); perr != nil {
						t.Error(perr)
					}
					return
				}
			}
		}()
		wg.Wait()
	}
	ls := newLocalServer(t, "tcp")
	defer ls.teardown()
	if err := ls.buildup(handler); err != nil {
		t.Fatal(err)
	}

	c, err := Dial(ls.Listener.Addr().Network(), ls.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	var b [1]byte
	for i := 0; i < 1000; i++ {
		c.Write(b[:])
		c.Read(b[:])
	}
}

// There is a very similar copy of this in os/timeout_test.go.
func TestReadWriteDeadlineRace(t *testing.T) {
	t.Parallel()

	N := 1000
	if testing.Short() {
		N = 50
	}

	ln := newLocalListener(t, "tcp")
	defer ln.Close()

	c, err := Dial(ln.Addr().Network(), ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	var wg sync.WaitGroup
	wg.Add(3)
	go func() {
		defer wg.Done()
		tic := time.NewTicker(2 * time.Microsecond)
		defer tic.Stop()
		for i := 0; i < N; i++ {
			if err := c.SetReadDeadline(time.Now().Add(2 * time.Microsecond)); err != nil {
				if perr := parseCommonError(err); perr != nil {
					t.Error(perr)
				}
				break
			}
			if err := c.SetWriteDeadline(time.Now().Add(2 * time.Microsecond)); err != nil {
				if perr := parseCommonError(err); perr != nil {
					t.Error(perr)
				}
				break
			}
			<-tic.C
		}
	}()
	go func() {
		defer wg.Done()
		var b [1]byte
		for i := 0; i < N; i++ {
			c.Read(b[:]) // ignore possible timeout errors
		}
	}()
	go func() {
		defer wg.Done()
		var b [1]byte
		for i := 0; i < N; i++ {
			c.Write(b[:]) // ignore possible timeout errors
		}
	}()
	wg.Wait() // wait for tester goroutine to stop
}

// Issue 35367.
func TestConcurrentSetDeadline(t *testing.T) {
	ln := newLocalListener(t, "tcp")
	defer ln.Close()

	const goroutines = 8
	const conns = 10
	const tries = 100

	var c [conns]Conn
	for i := 0; i < conns; i++ {
		var err error
		c[i], err = Dial(ln.Addr().Network(), ln.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		defer c[i].Close()
	}

	var wg sync.WaitGroup
	wg.Add(goroutines)
	now := time.Now()
	for i := 0; i < goroutines; i++ {
		go func(i int) {
			defer wg.Done()
			// Make the deadlines steadily earlier,
			// to trigger runtime adjusttimers calls.
			for j := tries; j > 0; j-- {
				for k := 0; k < conns; k++ {
					c[k].SetReadDeadline(now.Add(2*time.Hour + time.Duration(i*j*k)*time.Second))
					c[k].SetWriteDeadline(now.Add(1*time.Hour + time.Duration(i*j*k)*time.Second))
				}
			}
		}(i)
	}
	wg.Wait()
}

// isDeadlineExceeded reports whether err is or wraps os.ErrDeadlineExceeded.
// We also check that the error implements net.Error, and that the
// Timeout method returns true.
func isDeadlineExceeded(err error) bool {
	nerr, ok := err.(Error)
	if !ok {
		return false
	}
	if !nerr.Timeout() {
		return false
	}
	if !errors.Is(err, os.ErrDeadlineExceeded) {
		return false
	}
	return true
}
```