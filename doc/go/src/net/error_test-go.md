Response:
The user wants to understand the functionality of the provided Go code snippet from `go/src/net/error_test.go`. I need to analyze the code and identify its purpose, which seems to be testing the error handling behavior of the `net` package.

Here's a breakdown of the code's functionality:

1. **Error Validation:** The `isValid` method checks the internal consistency of the `OpError` struct.
2. **Error Parsing Functions:** Several functions (`parseDialError`, `parseReadError`, `parseWriteError`, `parseCloseError`, `parseAcceptError`, `parseCommonError`, `parseLookupPortError`) are defined to validate the types and structure of errors returned by various networking operations (dialing, reading, writing, closing, accepting, etc.). These functions essentially ensure that the returned errors conform to the expected error hierarchy and contain the necessary information.
3. **Test Functions for Different Operations:** The code includes several test functions (`TestDialError`, `TestProtocolDialError`, `TestDialAddrError`, `TestListenError`, `TestListenPacketError`, `TestProtocolListenError`, `TestCloseError`, `TestAcceptError`, `TestFileError`, `TestContextError`). These functions use the error parsing functions to verify the correctness of errors returned by the corresponding `net` package functions.
4. **Test Cases:** Each test function contains a set of test cases with different inputs (e.g., invalid network names, addresses, port numbers) to trigger various error conditions.
5. **Mocking/Stubbing:** The code utilizes `testHookLookupIP` and `socktest` to simulate error conditions during DNS resolution and socket operations.
6. **Platform-Specific Handling:** The code includes checks for specific operating systems (`runtime.GOOS`) to skip tests that are not applicable or might behave differently on those platforms.

Based on this analysis, I can infer that the code's primary goal is to test the error handling mechanisms within the `net` package in Go. It ensures that the correct types of errors are returned for various networking operations and that these errors contain the expected information.

I will now construct the answer by listing the functionalities, explaining the purpose with a code example, providing examples of assumptions, inputs, and outputs where applicable, and highlighting potential pitfalls for users.
这是一个Go语言的测试文件，路径为 `go/src/net/error_test.go`。它的主要功能是**测试 `net` 包中各种网络操作可能产生的错误类型及其结构是否符合预期**。换句话说，它验证了当网络操作（如连接、监听、读写、关闭等）失败时，`net` 包是否返回了正确类型的错误，并且这些错误对象（特别是 `OpError`）的字段是否被正确填充。

以下是它更具体的功能点：

1. **`OpError` 结构的有效性检查 (`isValid` 方法):**  这个方法用于验证 `OpError` 结构体的字段是否被正确设置，例如 `Op`（操作类型），`Net`（网络类型），`Source`（源地址），`Addr`（目标地址），和 `Err`（底层错误）。它确保这些字段在错误发生时提供了有意义的信息。

2. **错误解析函数 (`parseDialError`, `parseReadError` 等):** 这些函数负责解析嵌套的错误，并判断这些错误是否是来自特定网络操作（如 `Dial`, `Read`, `Write`, `Close`, `Accept`）的有效错误。它们检查错误的类型和结构，以确保 `net` 包返回了预期的错误类型。这些函数允许测试代码断言在特定场景下会返回特定的错误类型。

3. **针对不同网络操作的错误测试 (`TestDialError`, `TestListenError` 等):** 文件中包含多个以 `Test` 开头的函数，每个函数都专注于测试特定网络操作可能产生的错误。例如，`TestDialError` 测试 `Dial` 函数在各种错误场景下的行为，`TestListenError` 测试 `Listen` 函数的错误处理。

4. **测试各种错误的触发场景:** 这些测试函数会尝试使用各种无效的参数或者模拟网络错误来触发不同的错误情况，例如无效的网络协议名、无效的地址格式、连接超时、拒绝连接等。

5. **使用 `socktest` 模拟底层错误:**  为了更全面地测试错误处理，该文件使用了 `net/internal/socktest` 包来模拟底层的 socket 错误，例如连接被拒绝或操作不被支持等。

**可以推理出它是什么go语言功能的实现：错误处理机制的测试**

这个文件主要测试 Go 语言中 `net` 包的错误处理机制。Go 语言的错误处理通常通过返回 `error` 类型的值来实现。`net` 包定义了一些特定的错误类型，例如 `OpError`，`AddrError`，`DNSError` 等，以便调用者能够更精确地了解错误的原因。这个测试文件就是用来确保这些错误类型被正确地使用和返回的。

**Go 代码举例说明:**

假设我们想测试 `net.Dial` 函数在尝试连接到一个不存在的主机时是否返回了预期的 `DNSError`。

```go
package net_test

import (
	"context"
	"net"
	"testing"
	"time"
)

func TestDialNonExistentHost(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	conn, err := net.DialTimeout("tcp", "nonexistent.example.com:80", 500*time.Millisecond)
	if err == nil {
		t.Fatalf("Dial should have failed, but succeeded with connection: %v", conn)
	}

	dnsErr, ok := err.(*net.DNSError)
	if !ok {
		t.Fatalf("Expected a DNSError, but got: %T, error: %v", err, err)
	}

	if dnsErr.IsNotFound {
		t.Logf("Dial failed as expected with DNSError: %v", dnsErr)
	} else {
		t.Errorf("Expected IsNotFound to be true, but got false for error: %v", dnsErr)
	}
}
```

**假设的输入与输出:**

*   **输入:** 调用 `net.DialTimeout("tcp", "nonexistent.example.com:80", 500*time.Millisecond)` 尝试连接到一个不存在的主机。
*   **输出:** 应该返回一个非 nil 的 `error`，并且这个 `error` 应该可以断言为 `*net.DNSError` 类型，且 `dnsErr.IsNotFound` 应该为 `true`。测试日志会显示 "Dial failed as expected with DNSError: ..."。

**涉及命令行参数的具体处理:**

这段代码主要关注的是单元测试，通常不直接处理命令行参数。`go test` 命令会执行这些测试，但测试代码本身并不解析命令行参数。

**使用者易犯错的点:**

在理解和使用 `net` 包的错误处理时，开发者容易犯以下错误：

1. **只检查 `err != nil`，不检查具体的错误类型:** 仅仅判断是否有错误发生是不够的，很多时候需要根据具体的错误类型来采取不同的处理措施。例如，如果是 `net.DNSError`，可能需要提示用户检查主机名是否正确；如果是连接超时，可能需要重试。

    ```go
    // 错误的做法：
    conn, err := net.Dial("tcp", "example.com:80")
    if err != nil {
        // 笼统地处理错误，可能不够精确
        println("连接失败:", err.Error())
        return
    }

    // 更好的做法：
    conn, err := net.Dial("tcp", "example.com:80")
    if err != nil {
        if dnsErr, ok := err.(*net.DNSError); ok {
            if dnsErr.IsNotFound {
                println("主机名未找到:", dnsErr.Error())
            } else if dnsErr.IsTimeout {
                println("DNS 解析超时:", dnsErr.Error())
            } else {
                println("DNS 解析错误:", dnsErr.Error())
            }
        } else {
            println("连接失败:", err.Error())
        }
        return
    }
    ```

2. **忽略嵌套的错误:**  `net` 包的错误经常是嵌套的，例如 `OpError` 内部包含了底层的错误。如果只检查最外层的错误，可能会丢失重要的错误信息。可以使用 `errors.Is` 或类型断言来检查嵌套的错误。

    ```go
    conn, err := net.Dial("tcp", "invalid-address")
    if err != nil {
        if opErr, ok := err.(*net.OpError); ok {
            println("操作:", opErr.Op)
            println("网络:", opErr.Net)
            println("错误:", opErr.Err) // 检查内部的错误
        } else {
            println("其他错误:", err)
        }
    }
    ```

总而言之，`go/src/net/error_test.go` 这个文件是 `net` 包质量保证的重要组成部分，它通过大量的测试用例来验证网络操作在各种错误场景下的行为是否符合预期，帮助开发者更可靠地使用 `net` 包进行网络编程。

Prompt: 
```
这是路径为go/src/net/error_test.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。

"""
// Copyright 2015 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package net

import (
	"context"
	"errors"
	"fmt"
	"internal/poll"
	"io"
	"io/fs"
	"net/internal/socktest"
	"os"
	"runtime"
	"strings"
	"testing"
	"time"
)

func (e *OpError) isValid() error {
	if e.Op == "" {
		return fmt.Errorf("OpError.Op is empty: %v", e)
	}
	if e.Net == "" {
		return fmt.Errorf("OpError.Net is empty: %v", e)
	}
	for _, addr := range []Addr{e.Source, e.Addr} {
		switch addr := addr.(type) {
		case nil:
		case *TCPAddr:
			if addr == nil {
				return fmt.Errorf("OpError.Source or Addr is non-nil interface: %#v, %v", addr, e)
			}
		case *UDPAddr:
			if addr == nil {
				return fmt.Errorf("OpError.Source or Addr is non-nil interface: %#v, %v", addr, e)
			}
		case *IPAddr:
			if addr == nil {
				return fmt.Errorf("OpError.Source or Addr is non-nil interface: %#v, %v", addr, e)
			}
		case *IPNet:
			if addr == nil {
				return fmt.Errorf("OpError.Source or Addr is non-nil interface: %#v, %v", addr, e)
			}
		case *UnixAddr:
			if addr == nil {
				return fmt.Errorf("OpError.Source or Addr is non-nil interface: %#v, %v", addr, e)
			}
		case *pipeAddr:
			if addr == nil {
				return fmt.Errorf("OpError.Source or Addr is non-nil interface: %#v, %v", addr, e)
			}
		case fileAddr:
			if addr == "" {
				return fmt.Errorf("OpError.Source or Addr is empty: %#v, %v", addr, e)
			}
		default:
			return fmt.Errorf("OpError.Source or Addr is unknown type: %T, %v", addr, e)
		}
	}
	if e.Err == nil {
		return fmt.Errorf("OpError.Err is empty: %v", e)
	}
	return nil
}

// parseDialError parses nestedErr and reports whether it is a valid
// error value from Dial, Listen functions.
// It returns nil when nestedErr is valid.
func parseDialError(nestedErr error) error {
	if nestedErr == nil {
		return nil
	}

	switch err := nestedErr.(type) {
	case *OpError:
		if err := err.isValid(); err != nil {
			return err
		}
		nestedErr = err.Err
		goto second
	}
	return fmt.Errorf("unexpected type on 1st nested level: %T", nestedErr)

second:
	if isPlatformError(nestedErr) {
		return nil
	}
	switch err := nestedErr.(type) {
	case *AddrError, *timeoutError, *DNSError, InvalidAddrError, *ParseError, *poll.DeadlineExceededError, UnknownNetworkError:
		return nil
	case interface{ isAddrinfoErrno() }:
		return nil
	case *os.SyscallError:
		nestedErr = err.Err
		goto third
	case *fs.PathError: // for Plan 9
		nestedErr = err.Err
		goto third
	}
	switch nestedErr {
	case errCanceled, ErrClosed, errMissingAddress, errNoSuitableAddress,
		context.DeadlineExceeded, context.Canceled:
		return nil
	}
	return fmt.Errorf("unexpected type on 2nd nested level: %T", nestedErr)

third:
	if isPlatformError(nestedErr) {
		return nil
	}
	return fmt.Errorf("unexpected type on 3rd nested level: %T", nestedErr)
}

var dialErrorTests = []struct {
	network, address string
}{
	{"foo", ""},
	{"bar", "baz"},
	{"datakit", "mh/astro/r70"},
	{"tcp", ""},
	{"tcp", "127.0.0.1:☺"},
	{"tcp", "no-such-name:80"},
	{"tcp", "mh/astro/r70:http"},

	{"tcp", JoinHostPort("127.0.0.1", "-1")},
	{"tcp", JoinHostPort("127.0.0.1", "123456789")},
	{"udp", JoinHostPort("127.0.0.1", "-1")},
	{"udp", JoinHostPort("127.0.0.1", "123456789")},
	{"ip:icmp", "127.0.0.1"},

	{"unix", "/path/to/somewhere"},
	{"unixgram", "/path/to/somewhere"},
	{"unixpacket", "/path/to/somewhere"},
}

func TestDialError(t *testing.T) {
	switch runtime.GOOS {
	case "plan9":
		t.Skipf("%s does not have full support of socktest", runtime.GOOS)
	}

	origTestHookLookupIP := testHookLookupIP
	defer func() { testHookLookupIP = origTestHookLookupIP }()
	testHookLookupIP = func(ctx context.Context, fn func(context.Context, string, string) ([]IPAddr, error), network, host string) ([]IPAddr, error) {
		return nil, &DNSError{Err: "dial error test", Name: "name", Server: "server", IsTimeout: true}
	}
	sw.Set(socktest.FilterConnect, func(so *socktest.Status) (socktest.AfterFilter, error) {
		return nil, errOpNotSupported
	})
	defer sw.Set(socktest.FilterConnect, nil)

	d := Dialer{Timeout: someTimeout}
	for i, tt := range dialErrorTests {
		i, tt := i, tt
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			c, err := d.Dial(tt.network, tt.address)
			if err == nil {
				t.Errorf("should fail; %s:%s->%s", c.LocalAddr().Network(), c.LocalAddr(), c.RemoteAddr())
				c.Close()
				return
			}
			if tt.network == "tcp" || tt.network == "udp" {
				nerr := err
				if op, ok := nerr.(*OpError); ok {
					nerr = op.Err
				}
				if sys, ok := nerr.(*os.SyscallError); ok {
					nerr = sys.Err
				}
				if nerr == errOpNotSupported {
					t.Fatalf("should fail without %v; %s:%s->", nerr, tt.network, tt.address)
				}
			}
			if c != nil {
				t.Errorf("Dial returned non-nil interface %T(%v) with err != nil", c, c)
			}
			if err = parseDialError(err); err != nil {
				t.Error(err)
			}
		})
	}
}

func TestProtocolDialError(t *testing.T) {
	switch runtime.GOOS {
	case "solaris", "illumos":
		t.Skipf("not supported on %s", runtime.GOOS)
	}

	for _, network := range []string{"tcp", "udp", "ip:4294967296", "unix", "unixpacket", "unixgram"} {
		var err error
		switch network {
		case "tcp":
			_, err = DialTCP(network, nil, &TCPAddr{Port: 1 << 16})
		case "udp":
			_, err = DialUDP(network, nil, &UDPAddr{Port: 1 << 16})
		case "ip:4294967296":
			_, err = DialIP(network, nil, nil)
		case "unix", "unixpacket", "unixgram":
			_, err = DialUnix(network, nil, &UnixAddr{Name: "//"})
		}
		if err == nil {
			t.Errorf("%s: should fail", network)
			continue
		}
		if err := parseDialError(err); err != nil {
			t.Errorf("%s: %v", network, err)
			continue
		}
		t.Logf("%s: error as expected: %v", network, err)
	}
}

func TestDialAddrError(t *testing.T) {
	switch runtime.GOOS {
	case "plan9":
		t.Skipf("not supported on %s", runtime.GOOS)
	}

	if !supportsIPv4() || !supportsIPv6() {
		t.Skip("both IPv4 and IPv6 are required")
	}

	for _, tt := range []struct {
		network string
		lit     string
		addr    *TCPAddr
	}{
		{"tcp4", "::1", nil},
		{"tcp4", "", &TCPAddr{IP: IPv6loopback}},
		// We don't test the {"tcp6", "byte sequence", nil}
		// case for now because there is no easy way to
		// control name resolution.
		{"tcp6", "", &TCPAddr{IP: IP{0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef}}},
	} {
		desc := tt.lit
		if desc == "" {
			desc = tt.addr.String()
		}
		t.Run(fmt.Sprintf("%s/%s", tt.network, desc), func(t *testing.T) {
			var err error
			var c Conn
			var op string
			if tt.lit != "" {
				c, err = Dial(tt.network, JoinHostPort(tt.lit, "0"))
				op = fmt.Sprintf("Dial(%q, %q)", tt.network, JoinHostPort(tt.lit, "0"))
			} else {
				c, err = DialTCP(tt.network, nil, tt.addr)
				op = fmt.Sprintf("DialTCP(%q, %q)", tt.network, tt.addr)
			}
			t.Logf("%s: %v", op, err)
			if err == nil {
				c.Close()
				t.Fatalf("%s succeeded, want error", op)
			}
			if perr := parseDialError(err); perr != nil {
				t.Fatal(perr)
			}
			operr := err.(*OpError).Err
			aerr, ok := operr.(*AddrError)
			if !ok {
				t.Fatalf("OpError.Err is %T, want *AddrError", operr)
			}
			want := tt.lit
			if tt.lit == "" {
				want = tt.addr.IP.String()
			}
			if aerr.Addr != want {
				t.Errorf("error Addr=%q, want %q", aerr.Addr, want)
			}
		})
	}
}

var listenErrorTests = []struct {
	network, address string
}{
	{"foo", ""},
	{"bar", "baz"},
	{"datakit", "mh/astro/r70"},
	{"tcp", "127.0.0.1:☺"},
	{"tcp", "no-such-name:80"},
	{"tcp", "mh/astro/r70:http"},

	{"tcp", JoinHostPort("127.0.0.1", "-1")},
	{"tcp", JoinHostPort("127.0.0.1", "123456789")},

	{"unix", "/path/to/somewhere"},
	{"unixpacket", "/path/to/somewhere"},
}

func TestListenError(t *testing.T) {
	switch runtime.GOOS {
	case "plan9":
		t.Skipf("%s does not have full support of socktest", runtime.GOOS)
	}

	origTestHookLookupIP := testHookLookupIP
	defer func() { testHookLookupIP = origTestHookLookupIP }()
	testHookLookupIP = func(_ context.Context, fn func(context.Context, string, string) ([]IPAddr, error), network, host string) ([]IPAddr, error) {
		return nil, &DNSError{Err: "listen error test", Name: "name", Server: "server", IsTimeout: true}
	}
	sw.Set(socktest.FilterListen, func(so *socktest.Status) (socktest.AfterFilter, error) {
		return nil, errOpNotSupported
	})
	defer sw.Set(socktest.FilterListen, nil)

	for i, tt := range listenErrorTests {
		t.Run(fmt.Sprintf("%s_%s", tt.network, tt.address), func(t *testing.T) {
			ln, err := Listen(tt.network, tt.address)
			if err == nil {
				t.Errorf("#%d: should fail; %s:%s->", i, ln.Addr().Network(), ln.Addr())
				ln.Close()
				return
			}
			if tt.network == "tcp" {
				nerr := err
				if op, ok := nerr.(*OpError); ok {
					nerr = op.Err
				}
				if sys, ok := nerr.(*os.SyscallError); ok {
					nerr = sys.Err
				}
				if nerr == errOpNotSupported {
					t.Fatalf("#%d: should fail without %v; %s:%s->", i, nerr, tt.network, tt.address)
				}
			}
			if ln != nil {
				t.Errorf("Listen returned non-nil interface %T(%v) with err != nil", ln, ln)
			}
			if err = parseDialError(err); err != nil {
				t.Errorf("#%d: %v", i, err)
			}
		})
	}
}

var listenPacketErrorTests = []struct {
	network, address string
}{
	{"foo", ""},
	{"bar", "baz"},
	{"datakit", "mh/astro/r70"},
	{"udp", "127.0.0.1:☺"},
	{"udp", "no-such-name:80"},
	{"udp", "mh/astro/r70:http"},

	{"udp", JoinHostPort("127.0.0.1", "-1")},
	{"udp", JoinHostPort("127.0.0.1", "123456789")},
}

func TestListenPacketError(t *testing.T) {
	switch runtime.GOOS {
	case "plan9":
		t.Skipf("%s does not have full support of socktest", runtime.GOOS)
	}

	origTestHookLookupIP := testHookLookupIP
	defer func() { testHookLookupIP = origTestHookLookupIP }()
	testHookLookupIP = func(_ context.Context, fn func(context.Context, string, string) ([]IPAddr, error), network, host string) ([]IPAddr, error) {
		return nil, &DNSError{Err: "listen error test", Name: "name", Server: "server", IsTimeout: true}
	}

	for i, tt := range listenPacketErrorTests {
		t.Run(fmt.Sprintf("%s_%s", tt.network, tt.address), func(t *testing.T) {
			c, err := ListenPacket(tt.network, tt.address)
			if err == nil {
				t.Errorf("#%d: should fail; %s:%s->", i, c.LocalAddr().Network(), c.LocalAddr())
				c.Close()
				return
			}
			if c != nil {
				t.Errorf("ListenPacket returned non-nil interface %T(%v) with err != nil", c, c)
			}
			if err = parseDialError(err); err != nil {
				t.Errorf("#%d: %v", i, err)
			}
		})
	}
}

func TestProtocolListenError(t *testing.T) {
	switch runtime.GOOS {
	case "plan9":
		t.Skipf("not supported on %s", runtime.GOOS)
	}

	for _, network := range []string{"tcp", "udp", "ip:4294967296", "unix", "unixpacket", "unixgram"} {
		var err error
		switch network {
		case "tcp":
			_, err = ListenTCP(network, &TCPAddr{Port: 1 << 16})
		case "udp":
			_, err = ListenUDP(network, &UDPAddr{Port: 1 << 16})
		case "ip:4294967296":
			_, err = ListenIP(network, nil)
		case "unix", "unixpacket":
			_, err = ListenUnix(network, &UnixAddr{Name: "//"})
		case "unixgram":
			_, err = ListenUnixgram(network, &UnixAddr{Name: "//"})
		}
		if err == nil {
			t.Errorf("%s: should fail", network)
			continue
		}
		if err = parseDialError(err); err != nil {
			t.Errorf("%s: %v", network, err)
			continue
		}
	}
}

// parseReadError parses nestedErr and reports whether it is a valid
// error value from Read functions.
// It returns nil when nestedErr is valid.
func parseReadError(nestedErr error) error {
	if nestedErr == nil {
		return nil
	}

	switch err := nestedErr.(type) {
	case *OpError:
		if err := err.isValid(); err != nil {
			return err
		}
		nestedErr = err.Err
		goto second
	}
	if nestedErr == io.EOF {
		return nil
	}
	return fmt.Errorf("unexpected type on 1st nested level: %T", nestedErr)

second:
	if isPlatformError(nestedErr) {
		return nil
	}
	switch err := nestedErr.(type) {
	case *os.SyscallError:
		nestedErr = err.Err
		goto third
	}
	switch nestedErr {
	case ErrClosed, errTimeout, poll.ErrNotPollable, os.ErrDeadlineExceeded:
		return nil
	}
	return fmt.Errorf("unexpected type on 2nd nested level: %T", nestedErr)

third:
	if isPlatformError(nestedErr) {
		return nil
	}
	return fmt.Errorf("unexpected type on 3rd nested level: %T", nestedErr)
}

// parseWriteError parses nestedErr and reports whether it is a valid
// error value from Write functions.
// It returns nil when nestedErr is valid.
func parseWriteError(nestedErr error) error {
	if nestedErr == nil {
		return nil
	}

	switch err := nestedErr.(type) {
	case *OpError:
		if err := err.isValid(); err != nil {
			return err
		}
		nestedErr = err.Err
		goto second
	}
	return fmt.Errorf("unexpected type on 1st nested level: %T", nestedErr)

second:
	if isPlatformError(nestedErr) {
		return nil
	}
	switch err := nestedErr.(type) {
	case *AddrError, *timeoutError, *DNSError, InvalidAddrError, *ParseError, *poll.DeadlineExceededError, UnknownNetworkError:
		return nil
	case interface{ isAddrinfoErrno() }:
		return nil
	case *os.SyscallError:
		nestedErr = err.Err
		goto third
	}
	switch nestedErr {
	case errCanceled, ErrClosed, errMissingAddress, errTimeout, os.ErrDeadlineExceeded, ErrWriteToConnected, io.ErrUnexpectedEOF:
		return nil
	}
	return fmt.Errorf("unexpected type on 2nd nested level: %T", nestedErr)

third:
	if isPlatformError(nestedErr) {
		return nil
	}
	return fmt.Errorf("unexpected type on 3rd nested level: %T", nestedErr)
}

// parseCloseError parses nestedErr and reports whether it is a valid
// error value from Close functions.
// It returns nil when nestedErr is valid.
func parseCloseError(nestedErr error, isShutdown bool) error {
	if nestedErr == nil {
		return nil
	}

	// Because historically we have not exported the error that we
	// return for an operation on a closed network connection,
	// there are programs that test for the exact error string.
	// Verify that string here so that we don't break those
	// programs unexpectedly. See issues #4373 and #19252.
	want := "use of closed network connection"
	if !isShutdown && !strings.Contains(nestedErr.Error(), want) {
		return fmt.Errorf("error string %q does not contain expected string %q", nestedErr, want)
	}

	if !isShutdown && !errors.Is(nestedErr, ErrClosed) {
		return fmt.Errorf("errors.Is(%v, errClosed) returns false, want true", nestedErr)
	}

	switch err := nestedErr.(type) {
	case *OpError:
		if err := err.isValid(); err != nil {
			return err
		}
		nestedErr = err.Err
		goto second
	}
	return fmt.Errorf("unexpected type on 1st nested level: %T", nestedErr)

second:
	if isPlatformError(nestedErr) {
		return nil
	}
	switch err := nestedErr.(type) {
	case *os.SyscallError:
		nestedErr = err.Err
		goto third
	case *fs.PathError: // for Plan 9
		nestedErr = err.Err
		goto third
	}
	switch nestedErr {
	case ErrClosed:
		return nil
	}
	return fmt.Errorf("unexpected type on 2nd nested level: %T", nestedErr)

third:
	if isPlatformError(nestedErr) {
		return nil
	}
	switch nestedErr {
	case fs.ErrClosed: // for Plan 9
		return nil
	}
	return fmt.Errorf("unexpected type on 3rd nested level: %T", nestedErr)
}

func TestCloseError(t *testing.T) {
	t.Run("tcp", func(t *testing.T) {
		ln := newLocalListener(t, "tcp")
		defer ln.Close()
		c, err := Dial(ln.Addr().Network(), ln.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()

		for i := 0; i < 3; i++ {
			err = c.(*TCPConn).CloseRead()
			if perr := parseCloseError(err, true); perr != nil {
				t.Errorf("#%d: %v", i, perr)
			}
		}
		for i := 0; i < 3; i++ {
			err = c.(*TCPConn).CloseWrite()
			if perr := parseCloseError(err, true); perr != nil {
				t.Errorf("#%d: %v", i, perr)
			}
		}
		for i := 0; i < 3; i++ {
			err = c.Close()
			if perr := parseCloseError(err, false); perr != nil {
				t.Errorf("#%d: %v", i, perr)
			}
			err = ln.Close()
			if perr := parseCloseError(err, false); perr != nil {
				t.Errorf("#%d: %v", i, perr)
			}
		}
	})

	t.Run("udp", func(t *testing.T) {
		if !testableNetwork("udp") {
			t.Skipf("skipping: udp not available")
		}

		pc, err := ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer pc.Close()

		for i := 0; i < 3; i++ {
			err = pc.Close()
			if perr := parseCloseError(err, false); perr != nil {
				t.Errorf("#%d: %v", i, perr)
			}
		}
	})
}

// parseAcceptError parses nestedErr and reports whether it is a valid
// error value from Accept functions.
// It returns nil when nestedErr is valid.
func parseAcceptError(nestedErr error) error {
	if nestedErr == nil {
		return nil
	}

	switch err := nestedErr.(type) {
	case *OpError:
		if err := err.isValid(); err != nil {
			return err
		}
		nestedErr = err.Err
		goto second
	}
	return fmt.Errorf("unexpected type on 1st nested level: %T", nestedErr)

second:
	if isPlatformError(nestedErr) {
		return nil
	}
	switch err := nestedErr.(type) {
	case *os.SyscallError:
		nestedErr = err.Err
		goto third
	case *fs.PathError: // for Plan 9
		nestedErr = err.Err
		goto third
	}
	switch nestedErr {
	case ErrClosed, errTimeout, poll.ErrNotPollable, os.ErrDeadlineExceeded:
		return nil
	}
	return fmt.Errorf("unexpected type on 2nd nested level: %T", nestedErr)

third:
	if isPlatformError(nestedErr) {
		return nil
	}
	return fmt.Errorf("unexpected type on 3rd nested level: %T", nestedErr)
}

func TestAcceptError(t *testing.T) {
	handler := func(ls *localServer, ln Listener) {
		for {
			ln.(*TCPListener).SetDeadline(time.Now().Add(5 * time.Millisecond))
			c, err := ln.Accept()
			if perr := parseAcceptError(err); perr != nil {
				t.Error(perr)
			}
			if err != nil {
				if c != nil {
					t.Errorf("Accept returned non-nil interface %T(%v) with err != nil", c, c)
				}
				if nerr, ok := err.(Error); !ok || (!nerr.Timeout() && !nerr.Temporary()) {
					return
				}
				continue
			}
			c.Close()
		}
	}
	ls := newLocalServer(t, "tcp")
	if err := ls.buildup(handler); err != nil {
		ls.teardown()
		t.Fatal(err)
	}

	time.Sleep(100 * time.Millisecond)
	ls.teardown()
}

// parseCommonError parses nestedErr and reports whether it is a valid
// error value from miscellaneous functions.
// It returns nil when nestedErr is valid.
func parseCommonError(nestedErr error) error {
	if nestedErr == nil {
		return nil
	}

	switch err := nestedErr.(type) {
	case *OpError:
		if err := err.isValid(); err != nil {
			return err
		}
		nestedErr = err.Err
		goto second
	}
	return fmt.Errorf("unexpected type on 1st nested level: %T", nestedErr)

second:
	if isPlatformError(nestedErr) {
		return nil
	}
	switch err := nestedErr.(type) {
	case *os.SyscallError:
		nestedErr = err.Err
		goto third
	case *os.LinkError:
		nestedErr = err.Err
		goto third
	case *fs.PathError:
		nestedErr = err.Err
		goto third
	}
	switch nestedErr {
	case ErrClosed:
		return nil
	}
	return fmt.Errorf("unexpected type on 2nd nested level: %T", nestedErr)

third:
	if isPlatformError(nestedErr) {
		return nil
	}
	return fmt.Errorf("unexpected type on 3rd nested level: %T", nestedErr)
}

func TestFileError(t *testing.T) {
	switch runtime.GOOS {
	case "windows":
		t.Skipf("not supported on %s", runtime.GOOS)
	}

	f, err := os.CreateTemp("", "go-nettest")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(f.Name())
	defer f.Close()

	c, err := FileConn(f)
	if err != nil {
		if c != nil {
			t.Errorf("FileConn returned non-nil interface %T(%v) with err != nil", c, c)
		}
		if perr := parseCommonError(err); perr != nil {
			t.Error(perr)
		}
	} else {
		c.Close()
		t.Error("should fail")
	}
	ln, err := FileListener(f)
	if err != nil {
		if ln != nil {
			t.Errorf("FileListener returned non-nil interface %T(%v) with err != nil", ln, ln)
		}
		if perr := parseCommonError(err); perr != nil {
			t.Error(perr)
		}
	} else {
		ln.Close()
		t.Error("should fail")
	}
	pc, err := FilePacketConn(f)
	if err != nil {
		if pc != nil {
			t.Errorf("FilePacketConn returned non-nil interface %T(%v) with err != nil", pc, pc)
		}
		if perr := parseCommonError(err); perr != nil {
			t.Error(perr)
		}
	} else {
		pc.Close()
		t.Error("should fail")
	}

	ln = newLocalListener(t, "tcp")

	for i := 0; i < 3; i++ {
		f, err := ln.(*TCPListener).File()
		if err != nil {
			if perr := parseCommonError(err); perr != nil {
				t.Error(perr)
			}
		} else {
			f.Close()
		}
		ln.Close()
	}
}

func parseLookupPortError(nestedErr error) error {
	if nestedErr == nil {
		return nil
	}

	switch nestedErr.(type) {
	case *AddrError, *DNSError:
		return nil
	case *fs.PathError: // for Plan 9
		return nil
	}
	return fmt.Errorf("unexpected type on 1st nested level: %T", nestedErr)
}

func TestContextError(t *testing.T) {
	if !errors.Is(errCanceled, context.Canceled) {
		t.Error("errCanceled is not context.Canceled")
	}
	if !errors.Is(errTimeout, context.DeadlineExceeded) {
		t.Error("errTimeout is not context.DeadlineExceeded")
	}
}

"""



```