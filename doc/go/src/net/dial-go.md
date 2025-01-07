Response:
My goal is to analyze the provided Go code snippet from `go/src/net/dial.go` and explain its functionality in detail, including illustrative examples and potential pitfalls. Here's my thought process:

1. **Identify the Core Functionality:**  The file name `dial.go` strongly suggests this code deals with establishing network connections (dialing) and listening for incoming connections. A quick scan confirms this, revealing the `Dialer` and `ListenConfig` structs, along with `Dial`, `DialContext`, and `Listen` functions.

2. **Break Down Key Components:** I'll analyze the code by focusing on the main structures and functions:

    * **`Dialer` struct:**  This struct holds configuration options for establishing outbound connections. I'll need to list its fields and their purposes.
    * **`ListenConfig` struct:** This struct holds configuration options for listening for inbound connections. I'll list its fields and their purposes.
    * **`Dial` and `DialContext` functions:** These are the primary entry points for establishing connections. I'll explain their differences (context handling).
    * **`Listen` and `ListenPacket` functions:** These are the primary entry points for setting up listeners. I'll explain their differences (connection-oriented vs. connectionless).
    * **Multipath TCP (MPTCP) handling:**  The code has explicit support for MPTCP. I'll need to explain the associated constants, variables, and methods (`mptcpStatusDial`, `mptcpStatusListen`, `MultipathTCP`, `SetMultipathTCP`).
    * **Fast Fallback (Happy Eyeballs):** The `DualStack` and `FallbackDelay` fields relate to this. I'll need to explain how this works for faster connection establishment with IPv4/IPv6.
    * **Timeouts and Deadlines:**  These are crucial for preventing indefinite blocking. I'll explain the `Timeout` and `Deadline` fields in `Dialer`.
    * **Keep-Alive:** The `KeepAlive` and `KeepAliveConfig` fields manage connection keep-alive probes.
    * **`Control` and `ControlContext`:** These allow low-level manipulation of the underlying socket.
    * **Resolving Addresses:** The interaction with the `Resolver` needs explanation.

3. **Infer Functionality and Provide Examples:**  For each key component, I'll try to infer the underlying Go functionality being implemented and provide concise code examples to illustrate its usage.

    * **Dialing:** Show examples of dialing TCP, UDP, and perhaps a Unix socket. Include examples with and without timeouts.
    * **Listening:** Show examples of listening on TCP and UDP ports.
    * **MPTCP:**  Demonstrate how to enable/disable MPTCP using `SetMultipathTCP`.
    * **Timeouts:**  Show how to use `DialTimeout` or set the `Timeout` in `Dialer`.
    * **Local Address:** Demonstrate setting a specific local address.

4. **Address Code Reasoning (with Assumptions):**  Where the code involves logical flow (like `dialParallel` and `dialSerial`), I'll make reasonable assumptions about the input and trace the execution to explain the output. For `dialParallel`, I'll assume a scenario where both IPv4 and IPv6 addresses are available and explain how the fallback mechanism works.

5. **Explain Command-Line Parameters:** The code mentions `GODEBUG=multipathtcp`. I need to explain how this environment variable affects MPTCP behavior.

6. **Identify Common Mistakes:** Based on my understanding of networking and the Go `net` package, I'll highlight potential pitfalls. Examples include:

    * **Not handling errors:** Crucial in network programming.
    * **Incorrect address formats:**  Emphasize the importance of `host:port` for TCP/UDP.
    * **Context cancellation:** Explain how contexts can be used to manage connection attempts.
    * **Misunderstanding timeouts:** Clarify the interaction between `Timeout` and `Deadline`.

7. **Structure the Answer:** I'll organize the information logically with clear headings and bullet points to enhance readability. I'll use Chinese as requested.

8. **Review and Refine:**  After drafting the answer, I'll review it for accuracy, clarity, and completeness, ensuring it addresses all aspects of the prompt. I'll double-check the code examples for correctness and ensure the explanations are easy to understand. For instance, I initially missed the details about the deprecated `DualStack` and `Cancel` fields and added them during the review. I also made sure to explicitly mention the default values for MPTCP.

By following these steps, I can effectively analyze the Go code snippet and provide a comprehensive and informative answer in Chinese, addressing all the requirements of the prompt.
这段代码是 Go 语言标准库 `net` 包中 `dial.go` 文件的一部分，主要负责建立网络连接（dialing）的功能。 它定义了 `Dialer` 结构体，该结构体允许用户自定义连接行为，并提供了 `Dial` 和 `DialContext` 函数用于创建各种类型的网络连接。

以下是它的主要功能：

1. **配置连接选项:** `Dialer` 结构体允许用户配置建立连接时的各种选项，例如：
    * **Timeout:**  设置连接建立的最大等待时间。
    * **Deadline:** 设置连接建立的绝对截止时间。
    * **LocalAddr:** 指定用于连接的本地地址。
    * **FallbackDelay (之前是 DualStack):**  用于 "Happy Eyeballs" 算法，在尝试 IPv6 连接失败后，延迟多久开始尝试 IPv4 连接。
    * **KeepAlive:** 设置连接的 keep-alive 探测间隔。
    * **KeepAliveConfig:** 更细粒度的 keep-alive 配置。
    * **Resolver:**  允许使用自定义的 DNS 解析器。
    * **Cancel (已弃用):**  一个通道，关闭时会取消连接尝试。推荐使用 `DialContext`。
    * **Control / ControlContext:** 允许在连接建立但尚未真正拨号之前执行自定义操作，可以用于设置 socket 选项。
    * **mptcpStatus:** 控制是否使用 Multipath TCP (MPTCP)。

2. **建立连接:**  提供了 `Dial(network, address string)` 和 `DialContext(ctx context.Context, network, address string)` 函数用于建立到指定网络和地址的连接。
    * `Dial` 函数内部使用 `context.Background()`。
    * `DialContext` 允许传入一个 `context.Context`，可以用于控制连接的生命周期和取消连接。

3. **支持多种网络协议:**  代码能够处理多种网络协议，例如 TCP、UDP、IP 和 Unix 域套接字。它会根据传入的 `network` 参数（例如 "tcp"、"udp"、"unix"）来选择合适的连接方式。

4. **地址解析:**  在建立 TCP 或 UDP 连接时，如果 `address` 参数包含主机名，则会使用 `Resolver` 进行 DNS 地址解析，将主机名解析为 IP 地址。

5. **"Happy Eyeballs" 算法:**  通过 `FallbackDelay` (以前的 `DualStack`)  实现了 RFC 6555 中定义的 "Happy Eyeballs" 算法。当连接到同时支持 IPv4 和 IPv6 的主机时，会同时或几乎同时尝试连接这两种地址族，以提高连接速度和可靠性。

6. **Multipath TCP (MPTCP) 支持:**  代码支持 MPTCP，这是一种允许 TCP 连接使用多个网络路径的技术，可以提高吞吐量和容错能力。可以通过 `Dialer` 的 `SetMultipathTCP` 方法或全局的 `GODEBUG` 环境变量来控制是否使用 MPTCP。

**它是什么 Go 语言功能的实现？**

这段代码是 Go 语言网络编程中 **建立连接（dialing）** 功能的核心实现。它封装了底层的 socket 创建和连接过程，并提供了灵活的配置选项，使得开发者可以方便地创建各种类型的网络连接。

**Go 代码举例说明:**

```go
package main

import (
	"context"
	"fmt"
	"net"
	"time"
)

func main() {
	// 使用默认配置建立 TCP 连接
	conn, err := net.Dial("tcp", "www.google.com:80")
	if err != nil {
		fmt.Println("连接失败:", err)
		return
	}
	defer conn.Close()
	fmt.Println("成功连接到 www.google.com:80")

	// 使用 Dialer 配置超时时间建立 TCP 连接
	dialer := net.Dialer{Timeout: 5 * time.Second}
	connWithTimeout, err := dialer.Dial("tcp", "www.example.com:80")
	if err != nil {
		fmt.Println("带超时的连接失败:", err)
	} else {
		defer connWithTimeout.Close()
		fmt.Println("成功连接到 www.example.com:80 (带超时)")
	}

	// 使用 DialContext 和 context 控制连接
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	var dialerWithContext net.Dialer
	connWithContext, err := dialerWithContext.DialContext(ctx, "tcp", "www.facebook.com:80")
	if err != nil {
		fmt.Println("带 Context 的连接失败:", err)
		if err == context.DeadlineExceeded {
			fmt.Println("连接超时")
		}
	} else {
		defer connWithContext.Close()
		fmt.Println("成功连接到 www.facebook.com:80 (带 Context)")
	}

	// 设置本地地址建立连接 (假设本地有一个 IP 地址是 192.168.1.100)
	localAddr, err := net.ResolveTCPAddr("tcp", "192.168.1.100:0")
	if err == nil {
		dialerWithLocalAddr := net.Dialer{LocalAddr: localAddr}
		connWithLocalAddr, err := dialerWithLocalAddr.Dial("tcp", "www.baidu.com:80")
		if err != nil {
			fmt.Println("设置本地地址连接失败:", err)
		} else {
			defer connWithLocalAddr.Close()
			fmt.Println("成功连接到 www.baidu.com:80 (使用本地地址)")
		}
	}
}
```

**假设的输入与输出 (针对 `dialParallel` 和 `dialSerial` 函数的推理):**

这两个函数是 `DialContext` 内部使用的，用于实现 "Happy Eyeballs"。

**假设输入:**

* `sd`: 一个 `sysDialer` 实例，包含了配置信息，例如要连接的网络类型 ("tcp") 和目标地址 ("www.example.com:80")。
* `primaries`: 一个 `addrList`，包含了目标主机解析出的 IPv6 地址列表。
* `fallbacks`: 一个 `addrList`，包含了目标主机解析出的 IPv4 地址列表。
* `ctx`: 一个 `context.Context`，可能设置了超时时间。
* `sd.Dialer.FallbackDelay`:  设置为 300 毫秒。

**`dialParallel` 的推理:**

1. `dialParallel` 首先尝试使用 `dialSerial` 并行连接 `primaries` (IPv6 地址)。
2. 它会启动一个计时器，等待 `FallbackDelay` (300 毫秒)。
3. 如果在 300 毫秒内，与任何一个 IPv6 地址的连接建立成功，则关闭所有其他连接尝试，并返回成功的连接。
4. 如果 300 毫秒后，与所有 IPv6 地址的连接都失败了，`dialParallel` 会启动另一个 `dialSerial` goroutine 来连接 `fallbacks` (IPv4 地址)。
5. 如果与任何一个 IPv4 地址的连接建立成功，则关闭所有其他连接尝试，并返回成功的连接。
6. 如果所有 IPv6 和 IPv4 连接尝试都失败，则返回第一个连接尝试产生的错误。

**可能的输出:**

* **场景 1 (IPv6 连接快):**  如果与某个 IPv6 地址的连接在 300 毫秒内建立成功，输出可能是 "成功连接到 www.example.com:80 (IPv6)" (假设 `dialSingle` 函数中会记录连接类型)。
* **场景 2 (IPv6 连接慢，IPv4 连接快):** 如果所有 IPv6 连接都比较慢，超过 300 毫秒才失败或仍在尝试，而与某个 IPv4 地址的连接在启动后很快建立成功，输出可能是 "成功连接到 www.example.com:80 (IPv4)"。
* **场景 3 (所有连接都失败):** 如果所有 IPv6 和 IPv4 连接尝试都超时或遇到其他错误，输出可能是 "dial tcp [2001:db8::...]:80: i/o timeout" (假设第一个尝试连接的 IPv6 地址超时)。

**`dialSerial` 的推理:**

1. `dialSerial` 接收一个 `addrList` (例如，一组 IPv6 地址或一组 IPv4 地址)。
2. 它会按顺序遍历地址列表。
3. 对于每个地址，它会调用 `dialSingle` 尝试建立连接。
4. 如果连接成功，则立即返回该连接。
5. 如果连接失败，则记录错误，并继续尝试下一个地址。
6. 如果所有地址都尝试失败，则返回第一个遇到的错误。

**可能的输出 (假设输入的是 IPv6 地址列表):**

* **场景 1 (第一个 IPv6 地址连接成功):** 如果列表中的第一个 IPv6 地址可以成功连接，`dialSerial` 会立即返回该连接。
* **场景 2 (中间的 IPv6 地址连接成功):** 如果前几个 IPv6 地址连接失败（例如，超时），但列表中间的某个 IPv6 地址连接成功，`dialSerial` 会在尝试到该地址时返回连接。
* **场景 3 (所有 IPv6 地址都失败):** 如果所有 IPv6 地址都无法连接（例如，都超时），`dialSerial` 会返回尝试连接第一个 IPv6 地址时遇到的错误。

**命令行参数的具体处理:**

该代码通过 `internal/godebug` 包处理名为 `multipathtcp` 的 `GODEBUG` 环境变量。

* **`GODEBUG=multipathtcp=0`:**  强制禁用 MPTCP。即使 `Dialer` 或 `ListenConfig` 中设置了启用 MPTCP，也会被覆盖。
* **`GODEBUG=multipathtcp=1`:** 强制启用 MPTCP 用于拨号和监听。
* **`GODEBUG=multipathtcp=2`:** 强制启用 MPTCP 仅用于监听。
* **`GODEBUG=multipathtcp=3`:** 强制启用 MPTCP 仅用于拨号。

例如，要在运行 Go 程序时禁用 MPTCP，可以在命令行中设置环境变量：

```bash
GODEBUG=multipathtcp=0 go run your_program.go
```

**使用者易犯错的点:**

1. **不处理错误:**  网络操作很容易出错，例如连接超时、地址不可达等。使用者容易忽略 `Dial` 或 `DialContext` 返回的错误，导致程序行为异常。

   ```go
   conn, _ := net.Dial("tcp", "invalid-address") // 忽略了错误
   // 后面使用 conn 可能会导致 panic
   ```

2. **不设置超时:**  如果目标主机不可达或网络不稳定，`Dial` 操作可能会无限期阻塞。应该使用 `Dialer` 的 `Timeout` 或 `DialContext` 来设置超时时间。

   ```go
   // 可能会永远阻塞
   conn, err := net.Dial("tcp", "some-unreachable-host:80")
   if err != nil {
       fmt.Println("连接失败:", err)
   }
   ```

3. **混淆 `Timeout` 和 `Deadline`:**  `Timeout` 是一个相对时间，表示从调用 `Dial` 开始计算的超时时长。`Deadline` 是一个绝对时间点，表示连接尝试必须在该时间点之前完成。

4. **错误地使用 `LocalAddr`:**  如果指定的 `LocalAddr` 与要连接的网络类型不兼容，或者本地系统没有该地址，连接会失败。

5. **不理解 "Happy Eyeballs" 的行为:**  有时开发者可能会看到程序同时尝试连接 IPv4 和 IPv6 地址，这可能是 "Happy Eyeballs" 算法在起作用。不理解其原理可能会导致困惑。

6. **在 `Control` 函数中执行耗时操作:** `Control` 函数会在连接建立但尚未真正拨号之前被调用。在这个函数中执行耗时操作会延迟连接建立，甚至可能导致连接超时。

7. **不正确地使用 Context 取消:**  如果使用了 `DialContext`，需要正确地传递和管理 `context.Context`，以便在需要时取消连接尝试。

8. **误以为设置了 `DualStack` 就能保证同时连接 IPv4 和 IPv6:** `DualStack` 已经被 `FallbackDelay` 替代，并且即使设置了 `FallbackDelay`，也只是在 IPv6 连接看起来有问题时才会触发 IPv4 的尝试，并非总是并行连接。

通过理解这段代码的功能和注意事项，开发者可以更有效地使用 Go 语言进行网络编程。

Prompt: 
```
这是路径为go/src/net/dial.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。

"""
// Copyright 2010 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package net

import (
	"context"
	"internal/bytealg"
	"internal/godebug"
	"internal/nettrace"
	"syscall"
	"time"
)

const (
	// defaultTCPKeepAliveIdle is a default constant value for TCP_KEEPIDLE.
	// See go.dev/issue/31510 for details.
	defaultTCPKeepAliveIdle = 15 * time.Second

	// defaultTCPKeepAliveInterval is a default constant value for TCP_KEEPINTVL.
	// It is the same as defaultTCPKeepAliveIdle, see go.dev/issue/31510 for details.
	defaultTCPKeepAliveInterval = 15 * time.Second

	// defaultTCPKeepAliveCount is a default constant value for TCP_KEEPCNT.
	defaultTCPKeepAliveCount = 9

	// For the moment, MultiPath TCP is used by default with listeners, if
	// available, but not with dialers.
	// See go.dev/issue/56539
	defaultMPTCPEnabledListen = true
	defaultMPTCPEnabledDial   = false
)

// The type of service offered
//
//	0 == MPTCP disabled
//	1 == MPTCP enabled
//	2 == MPTCP enabled on listeners only
//	3 == MPTCP enabled on dialers only
var multipathtcp = godebug.New("multipathtcp")

// mptcpStatusDial is a tristate for Multipath TCP on clients,
// see go.dev/issue/56539
type mptcpStatusDial uint8

const (
	// The value 0 is the system default, linked to defaultMPTCPEnabledDial
	mptcpUseDefaultDial mptcpStatusDial = iota
	mptcpEnabledDial
	mptcpDisabledDial
)

func (m *mptcpStatusDial) get() bool {
	switch *m {
	case mptcpEnabledDial:
		return true
	case mptcpDisabledDial:
		return false
	}

	// If MPTCP is forced via GODEBUG=multipathtcp=1
	if multipathtcp.Value() == "1" || multipathtcp.Value() == "3" {
		multipathtcp.IncNonDefault()

		return true
	}

	return defaultMPTCPEnabledDial
}

func (m *mptcpStatusDial) set(use bool) {
	if use {
		*m = mptcpEnabledDial
	} else {
		*m = mptcpDisabledDial
	}
}

// mptcpStatusListen is a tristate for Multipath TCP on servers,
// see go.dev/issue/56539
type mptcpStatusListen uint8

const (
	// The value 0 is the system default, linked to defaultMPTCPEnabledListen
	mptcpUseDefaultListen mptcpStatusListen = iota
	mptcpEnabledListen
	mptcpDisabledListen
)

func (m *mptcpStatusListen) get() bool {
	switch *m {
	case mptcpEnabledListen:
		return true
	case mptcpDisabledListen:
		return false
	}

	// If MPTCP is disabled via GODEBUG=multipathtcp=0 or only
	// enabled on dialers, but not on listeners.
	if multipathtcp.Value() == "0" || multipathtcp.Value() == "3" {
		multipathtcp.IncNonDefault()

		return false
	}

	return defaultMPTCPEnabledListen
}

func (m *mptcpStatusListen) set(use bool) {
	if use {
		*m = mptcpEnabledListen
	} else {
		*m = mptcpDisabledListen
	}
}

// A Dialer contains options for connecting to an address.
//
// The zero value for each field is equivalent to dialing
// without that option. Dialing with the zero value of Dialer
// is therefore equivalent to just calling the [Dial] function.
//
// It is safe to call Dialer's methods concurrently.
type Dialer struct {
	// Timeout is the maximum amount of time a dial will wait for
	// a connect to complete. If Deadline is also set, it may fail
	// earlier.
	//
	// The default is no timeout.
	//
	// When using TCP and dialing a host name with multiple IP
	// addresses, the timeout may be divided between them.
	//
	// With or without a timeout, the operating system may impose
	// its own earlier timeout. For instance, TCP timeouts are
	// often around 3 minutes.
	Timeout time.Duration

	// Deadline is the absolute point in time after which dials
	// will fail. If Timeout is set, it may fail earlier.
	// Zero means no deadline, or dependent on the operating system
	// as with the Timeout option.
	Deadline time.Time

	// LocalAddr is the local address to use when dialing an
	// address. The address must be of a compatible type for the
	// network being dialed.
	// If nil, a local address is automatically chosen.
	LocalAddr Addr

	// DualStack previously enabled RFC 6555 Fast Fallback
	// support, also known as "Happy Eyeballs", in which IPv4 is
	// tried soon if IPv6 appears to be misconfigured and
	// hanging.
	//
	// Deprecated: Fast Fallback is enabled by default. To
	// disable, set FallbackDelay to a negative value.
	DualStack bool

	// FallbackDelay specifies the length of time to wait before
	// spawning a RFC 6555 Fast Fallback connection. That is, this
	// is the amount of time to wait for IPv6 to succeed before
	// assuming that IPv6 is misconfigured and falling back to
	// IPv4.
	//
	// If zero, a default delay of 300ms is used.
	// A negative value disables Fast Fallback support.
	FallbackDelay time.Duration

	// KeepAlive specifies the interval between keep-alive
	// probes for an active network connection.
	//
	// KeepAlive is ignored if KeepAliveConfig.Enable is true.
	//
	// If zero, keep-alive probes are sent with a default value
	// (currently 15 seconds), if supported by the protocol and operating
	// system. Network protocols or operating systems that do
	// not support keep-alive ignore this field.
	// If negative, keep-alive probes are disabled.
	KeepAlive time.Duration

	// KeepAliveConfig specifies the keep-alive probe configuration
	// for an active network connection, when supported by the
	// protocol and operating system.
	//
	// If KeepAliveConfig.Enable is true, keep-alive probes are enabled.
	// If KeepAliveConfig.Enable is false and KeepAlive is negative,
	// keep-alive probes are disabled.
	KeepAliveConfig KeepAliveConfig

	// Resolver optionally specifies an alternate resolver to use.
	Resolver *Resolver

	// Cancel is an optional channel whose closure indicates that
	// the dial should be canceled. Not all types of dials support
	// cancellation.
	//
	// Deprecated: Use DialContext instead.
	Cancel <-chan struct{}

	// If Control is not nil, it is called after creating the network
	// connection but before actually dialing.
	//
	// Network and address parameters passed to Control function are not
	// necessarily the ones passed to Dial. Calling Dial with TCP networks
	// will cause the Control function to be called with "tcp4" or "tcp6",
	// UDP networks become "udp4" or "udp6", IP networks become "ip4" or "ip6",
	// and other known networks are passed as-is.
	//
	// Control is ignored if ControlContext is not nil.
	Control func(network, address string, c syscall.RawConn) error

	// If ControlContext is not nil, it is called after creating the network
	// connection but before actually dialing.
	//
	// Network and address parameters passed to ControlContext function are not
	// necessarily the ones passed to Dial. Calling Dial with TCP networks
	// will cause the ControlContext function to be called with "tcp4" or "tcp6",
	// UDP networks become "udp4" or "udp6", IP networks become "ip4" or "ip6",
	// and other known networks are passed as-is.
	//
	// If ControlContext is not nil, Control is ignored.
	ControlContext func(ctx context.Context, network, address string, c syscall.RawConn) error

	// If mptcpStatus is set to a value allowing Multipath TCP (MPTCP) to be
	// used, any call to Dial with "tcp(4|6)" as network will use MPTCP if
	// supported by the operating system.
	mptcpStatus mptcpStatusDial
}

func (d *Dialer) dualStack() bool { return d.FallbackDelay >= 0 }

func minNonzeroTime(a, b time.Time) time.Time {
	if a.IsZero() {
		return b
	}
	if b.IsZero() || a.Before(b) {
		return a
	}
	return b
}

// deadline returns the earliest of:
//   - now+Timeout
//   - d.Deadline
//   - the context's deadline
//
// Or zero, if none of Timeout, Deadline, or context's deadline is set.
func (d *Dialer) deadline(ctx context.Context, now time.Time) (earliest time.Time) {
	if d.Timeout != 0 { // including negative, for historical reasons
		earliest = now.Add(d.Timeout)
	}
	if d, ok := ctx.Deadline(); ok {
		earliest = minNonzeroTime(earliest, d)
	}
	return minNonzeroTime(earliest, d.Deadline)
}

func (d *Dialer) resolver() *Resolver {
	if d.Resolver != nil {
		return d.Resolver
	}
	return DefaultResolver
}

// partialDeadline returns the deadline to use for a single address,
// when multiple addresses are pending.
func partialDeadline(now, deadline time.Time, addrsRemaining int) (time.Time, error) {
	if deadline.IsZero() {
		return deadline, nil
	}
	timeRemaining := deadline.Sub(now)
	if timeRemaining <= 0 {
		return time.Time{}, errTimeout
	}
	// Tentatively allocate equal time to each remaining address.
	timeout := timeRemaining / time.Duration(addrsRemaining)
	// If the time per address is too short, steal from the end of the list.
	const saneMinimum = 2 * time.Second
	if timeout < saneMinimum {
		if timeRemaining < saneMinimum {
			timeout = timeRemaining
		} else {
			timeout = saneMinimum
		}
	}
	return now.Add(timeout), nil
}

func (d *Dialer) fallbackDelay() time.Duration {
	if d.FallbackDelay > 0 {
		return d.FallbackDelay
	} else {
		return 300 * time.Millisecond
	}
}

func parseNetwork(ctx context.Context, network string, needsProto bool) (afnet string, proto int, err error) {
	i := bytealg.LastIndexByteString(network, ':')
	if i < 0 { // no colon
		switch network {
		case "tcp", "tcp4", "tcp6":
		case "udp", "udp4", "udp6":
		case "ip", "ip4", "ip6":
			if needsProto {
				return "", 0, UnknownNetworkError(network)
			}
		case "unix", "unixgram", "unixpacket":
		default:
			return "", 0, UnknownNetworkError(network)
		}
		return network, 0, nil
	}
	afnet = network[:i]
	switch afnet {
	case "ip", "ip4", "ip6":
		protostr := network[i+1:]
		proto, i, ok := dtoi(protostr)
		if !ok || i != len(protostr) {
			proto, err = lookupProtocol(ctx, protostr)
			if err != nil {
				return "", 0, err
			}
		}
		return afnet, proto, nil
	}
	return "", 0, UnknownNetworkError(network)
}

// resolveAddrList resolves addr using hint and returns a list of
// addresses. The result contains at least one address when error is
// nil.
func (r *Resolver) resolveAddrList(ctx context.Context, op, network, addr string, hint Addr) (addrList, error) {
	afnet, _, err := parseNetwork(ctx, network, true)
	if err != nil {
		return nil, err
	}
	if op == "dial" && addr == "" {
		return nil, errMissingAddress
	}
	switch afnet {
	case "unix", "unixgram", "unixpacket":
		addr, err := ResolveUnixAddr(afnet, addr)
		if err != nil {
			return nil, err
		}
		if op == "dial" && hint != nil && addr.Network() != hint.Network() {
			return nil, &AddrError{Err: "mismatched local address type", Addr: hint.String()}
		}
		return addrList{addr}, nil
	}
	addrs, err := r.internetAddrList(ctx, afnet, addr)
	if err != nil || op != "dial" || hint == nil {
		return addrs, err
	}
	var (
		tcp      *TCPAddr
		udp      *UDPAddr
		ip       *IPAddr
		wildcard bool
	)
	switch hint := hint.(type) {
	case *TCPAddr:
		tcp = hint
		wildcard = tcp.isWildcard()
	case *UDPAddr:
		udp = hint
		wildcard = udp.isWildcard()
	case *IPAddr:
		ip = hint
		wildcard = ip.isWildcard()
	}
	naddrs := addrs[:0]
	for _, addr := range addrs {
		if addr.Network() != hint.Network() {
			return nil, &AddrError{Err: "mismatched local address type", Addr: hint.String()}
		}
		switch addr := addr.(type) {
		case *TCPAddr:
			if !wildcard && !addr.isWildcard() && !addr.IP.matchAddrFamily(tcp.IP) {
				continue
			}
			naddrs = append(naddrs, addr)
		case *UDPAddr:
			if !wildcard && !addr.isWildcard() && !addr.IP.matchAddrFamily(udp.IP) {
				continue
			}
			naddrs = append(naddrs, addr)
		case *IPAddr:
			if !wildcard && !addr.isWildcard() && !addr.IP.matchAddrFamily(ip.IP) {
				continue
			}
			naddrs = append(naddrs, addr)
		}
	}
	if len(naddrs) == 0 {
		return nil, &AddrError{Err: errNoSuitableAddress.Error(), Addr: hint.String()}
	}
	return naddrs, nil
}

// MultipathTCP reports whether MPTCP will be used.
//
// This method doesn't check if MPTCP is supported by the operating
// system or not.
func (d *Dialer) MultipathTCP() bool {
	return d.mptcpStatus.get()
}

// SetMultipathTCP directs the [Dial] methods to use, or not use, MPTCP,
// if supported by the operating system. This method overrides the
// system default and the GODEBUG=multipathtcp=... setting if any.
//
// If MPTCP is not available on the host or not supported by the server,
// the Dial methods will fall back to TCP.
func (d *Dialer) SetMultipathTCP(use bool) {
	d.mptcpStatus.set(use)
}

// Dial connects to the address on the named network.
//
// Known networks are "tcp", "tcp4" (IPv4-only), "tcp6" (IPv6-only),
// "udp", "udp4" (IPv4-only), "udp6" (IPv6-only), "ip", "ip4"
// (IPv4-only), "ip6" (IPv6-only), "unix", "unixgram" and
// "unixpacket".
//
// For TCP and UDP networks, the address has the form "host:port".
// The host must be a literal IP address, or a host name that can be
// resolved to IP addresses.
// The port must be a literal port number or a service name.
// If the host is a literal IPv6 address it must be enclosed in square
// brackets, as in "[2001:db8::1]:80" or "[fe80::1%zone]:80".
// The zone specifies the scope of the literal IPv6 address as defined
// in RFC 4007.
// The functions [JoinHostPort] and [SplitHostPort] manipulate a pair of
// host and port in this form.
// When using TCP, and the host resolves to multiple IP addresses,
// Dial will try each IP address in order until one succeeds.
//
// Examples:
//
//	Dial("tcp", "golang.org:http")
//	Dial("tcp", "192.0.2.1:http")
//	Dial("tcp", "198.51.100.1:80")
//	Dial("udp", "[2001:db8::1]:domain")
//	Dial("udp", "[fe80::1%lo0]:53")
//	Dial("tcp", ":80")
//
// For IP networks, the network must be "ip", "ip4" or "ip6" followed
// by a colon and a literal protocol number or a protocol name, and
// the address has the form "host". The host must be a literal IP
// address or a literal IPv6 address with zone.
// It depends on each operating system how the operating system
// behaves with a non-well known protocol number such as "0" or "255".
//
// Examples:
//
//	Dial("ip4:1", "192.0.2.1")
//	Dial("ip6:ipv6-icmp", "2001:db8::1")
//	Dial("ip6:58", "fe80::1%lo0")
//
// For TCP, UDP and IP networks, if the host is empty or a literal
// unspecified IP address, as in ":80", "0.0.0.0:80" or "[::]:80" for
// TCP and UDP, "", "0.0.0.0" or "::" for IP, the local system is
// assumed.
//
// For Unix networks, the address must be a file system path.
func Dial(network, address string) (Conn, error) {
	var d Dialer
	return d.Dial(network, address)
}

// DialTimeout acts like [Dial] but takes a timeout.
//
// The timeout includes name resolution, if required.
// When using TCP, and the host in the address parameter resolves to
// multiple IP addresses, the timeout is spread over each consecutive
// dial, such that each is given an appropriate fraction of the time
// to connect.
//
// See func Dial for a description of the network and address
// parameters.
func DialTimeout(network, address string, timeout time.Duration) (Conn, error) {
	d := Dialer{Timeout: timeout}
	return d.Dial(network, address)
}

// sysDialer contains a Dial's parameters and configuration.
type sysDialer struct {
	Dialer
	network, address string
	testHookDialTCP  func(ctx context.Context, net string, laddr, raddr *TCPAddr) (*TCPConn, error)
}

// Dial connects to the address on the named network.
//
// See func Dial for a description of the network and address
// parameters.
//
// Dial uses [context.Background] internally; to specify the context, use
// [Dialer.DialContext].
func (d *Dialer) Dial(network, address string) (Conn, error) {
	return d.DialContext(context.Background(), network, address)
}

// DialContext connects to the address on the named network using
// the provided context.
//
// The provided Context must be non-nil. If the context expires before
// the connection is complete, an error is returned. Once successfully
// connected, any expiration of the context will not affect the
// connection.
//
// When using TCP, and the host in the address parameter resolves to multiple
// network addresses, any dial timeout (from d.Timeout or ctx) is spread
// over each consecutive dial, such that each is given an appropriate
// fraction of the time to connect.
// For example, if a host has 4 IP addresses and the timeout is 1 minute,
// the connect to each single address will be given 15 seconds to complete
// before trying the next one.
//
// See func [Dial] for a description of the network and address
// parameters.
func (d *Dialer) DialContext(ctx context.Context, network, address string) (Conn, error) {
	if ctx == nil {
		panic("nil context")
	}
	deadline := d.deadline(ctx, time.Now())
	if !deadline.IsZero() {
		testHookStepTime()
		if d, ok := ctx.Deadline(); !ok || deadline.Before(d) {
			subCtx, cancel := context.WithDeadline(ctx, deadline)
			defer cancel()
			ctx = subCtx
		}
	}
	if oldCancel := d.Cancel; oldCancel != nil {
		subCtx, cancel := context.WithCancel(ctx)
		defer cancel()
		go func() {
			select {
			case <-oldCancel:
				cancel()
			case <-subCtx.Done():
			}
		}()
		ctx = subCtx
	}

	// Shadow the nettrace (if any) during resolve so Connect events don't fire for DNS lookups.
	resolveCtx := ctx
	if trace, _ := ctx.Value(nettrace.TraceKey{}).(*nettrace.Trace); trace != nil {
		shadow := *trace
		shadow.ConnectStart = nil
		shadow.ConnectDone = nil
		resolveCtx = context.WithValue(resolveCtx, nettrace.TraceKey{}, &shadow)
	}

	addrs, err := d.resolver().resolveAddrList(resolveCtx, "dial", network, address, d.LocalAddr)
	if err != nil {
		return nil, &OpError{Op: "dial", Net: network, Source: nil, Addr: nil, Err: err}
	}

	sd := &sysDialer{
		Dialer:  *d,
		network: network,
		address: address,
	}

	var primaries, fallbacks addrList
	if d.dualStack() && network == "tcp" {
		primaries, fallbacks = addrs.partition(isIPv4)
	} else {
		primaries = addrs
	}

	return sd.dialParallel(ctx, primaries, fallbacks)
}

// dialParallel races two copies of dialSerial, giving the first a
// head start. It returns the first established connection and
// closes the others. Otherwise it returns an error from the first
// primary address.
func (sd *sysDialer) dialParallel(ctx context.Context, primaries, fallbacks addrList) (Conn, error) {
	if len(fallbacks) == 0 {
		return sd.dialSerial(ctx, primaries)
	}

	returned := make(chan struct{})
	defer close(returned)

	type dialResult struct {
		Conn
		error
		primary bool
		done    bool
	}
	results := make(chan dialResult) // unbuffered

	startRacer := func(ctx context.Context, primary bool) {
		ras := primaries
		if !primary {
			ras = fallbacks
		}
		c, err := sd.dialSerial(ctx, ras)
		select {
		case results <- dialResult{Conn: c, error: err, primary: primary, done: true}:
		case <-returned:
			if c != nil {
				c.Close()
			}
		}
	}

	var primary, fallback dialResult

	// Start the main racer.
	primaryCtx, primaryCancel := context.WithCancel(ctx)
	defer primaryCancel()
	go startRacer(primaryCtx, true)

	// Start the timer for the fallback racer.
	fallbackTimer := time.NewTimer(sd.fallbackDelay())
	defer fallbackTimer.Stop()

	for {
		select {
		case <-fallbackTimer.C:
			fallbackCtx, fallbackCancel := context.WithCancel(ctx)
			defer fallbackCancel()
			go startRacer(fallbackCtx, false)

		case res := <-results:
			if res.error == nil {
				return res.Conn, nil
			}
			if res.primary {
				primary = res
			} else {
				fallback = res
			}
			if primary.done && fallback.done {
				return nil, primary.error
			}
			if res.primary && fallbackTimer.Stop() {
				// If we were able to stop the timer, that means it
				// was running (hadn't yet started the fallback), but
				// we just got an error on the primary path, so start
				// the fallback immediately (in 0 nanoseconds).
				fallbackTimer.Reset(0)
			}
		}
	}
}

// dialSerial connects to a list of addresses in sequence, returning
// either the first successful connection, or the first error.
func (sd *sysDialer) dialSerial(ctx context.Context, ras addrList) (Conn, error) {
	var firstErr error // The error from the first address is most relevant.

	for i, ra := range ras {
		select {
		case <-ctx.Done():
			return nil, &OpError{Op: "dial", Net: sd.network, Source: sd.LocalAddr, Addr: ra, Err: mapErr(ctx.Err())}
		default:
		}

		dialCtx := ctx
		if deadline, hasDeadline := ctx.Deadline(); hasDeadline {
			partialDeadline, err := partialDeadline(time.Now(), deadline, len(ras)-i)
			if err != nil {
				// Ran out of time.
				if firstErr == nil {
					firstErr = &OpError{Op: "dial", Net: sd.network, Source: sd.LocalAddr, Addr: ra, Err: err}
				}
				break
			}
			if partialDeadline.Before(deadline) {
				var cancel context.CancelFunc
				dialCtx, cancel = context.WithDeadline(ctx, partialDeadline)
				defer cancel()
			}
		}

		c, err := sd.dialSingle(dialCtx, ra)
		if err == nil {
			return c, nil
		}
		if firstErr == nil {
			firstErr = err
		}
	}

	if firstErr == nil {
		firstErr = &OpError{Op: "dial", Net: sd.network, Source: nil, Addr: nil, Err: errMissingAddress}
	}
	return nil, firstErr
}

// dialSingle attempts to establish and returns a single connection to
// the destination address.
func (sd *sysDialer) dialSingle(ctx context.Context, ra Addr) (c Conn, err error) {
	trace, _ := ctx.Value(nettrace.TraceKey{}).(*nettrace.Trace)
	if trace != nil {
		raStr := ra.String()
		if trace.ConnectStart != nil {
			trace.ConnectStart(sd.network, raStr)
		}
		if trace.ConnectDone != nil {
			defer func() { trace.ConnectDone(sd.network, raStr, err) }()
		}
	}
	la := sd.LocalAddr
	switch ra := ra.(type) {
	case *TCPAddr:
		la, _ := la.(*TCPAddr)
		if sd.MultipathTCP() {
			c, err = sd.dialMPTCP(ctx, la, ra)
		} else {
			c, err = sd.dialTCP(ctx, la, ra)
		}
	case *UDPAddr:
		la, _ := la.(*UDPAddr)
		c, err = sd.dialUDP(ctx, la, ra)
	case *IPAddr:
		la, _ := la.(*IPAddr)
		c, err = sd.dialIP(ctx, la, ra)
	case *UnixAddr:
		la, _ := la.(*UnixAddr)
		c, err = sd.dialUnix(ctx, la, ra)
	default:
		return nil, &OpError{Op: "dial", Net: sd.network, Source: la, Addr: ra, Err: &AddrError{Err: "unexpected address type", Addr: sd.address}}
	}
	if err != nil {
		return nil, &OpError{Op: "dial", Net: sd.network, Source: la, Addr: ra, Err: err} // c is non-nil interface containing nil pointer
	}
	return c, nil
}

// ListenConfig contains options for listening to an address.
type ListenConfig struct {
	// If Control is not nil, it is called after creating the network
	// connection but before binding it to the operating system.
	//
	// Network and address parameters passed to Control function are not
	// necessarily the ones passed to Listen. Calling Listen with TCP networks
	// will cause the Control function to be called with "tcp4" or "tcp6",
	// UDP networks become "udp4" or "udp6", IP networks become "ip4" or "ip6",
	// and other known networks are passed as-is.
	Control func(network, address string, c syscall.RawConn) error

	// KeepAlive specifies the keep-alive period for network
	// connections accepted by this listener.
	//
	// KeepAlive is ignored if KeepAliveConfig.Enable is true.
	//
	// If zero, keep-alive are enabled if supported by the protocol
	// and operating system. Network protocols or operating systems
	// that do not support keep-alive ignore this field.
	// If negative, keep-alive are disabled.
	KeepAlive time.Duration

	// KeepAliveConfig specifies the keep-alive probe configuration
	// for an active network connection, when supported by the
	// protocol and operating system.
	//
	// If KeepAliveConfig.Enable is true, keep-alive probes are enabled.
	// If KeepAliveConfig.Enable is false and KeepAlive is negative,
	// keep-alive probes are disabled.
	KeepAliveConfig KeepAliveConfig

	// If mptcpStatus is set to a value allowing Multipath TCP (MPTCP) to be
	// used, any call to Listen with "tcp(4|6)" as network will use MPTCP if
	// supported by the operating system.
	mptcpStatus mptcpStatusListen
}

// MultipathTCP reports whether MPTCP will be used.
//
// This method doesn't check if MPTCP is supported by the operating
// system or not.
func (lc *ListenConfig) MultipathTCP() bool {
	return lc.mptcpStatus.get()
}

// SetMultipathTCP directs the [Listen] method to use, or not use, MPTCP,
// if supported by the operating system. This method overrides the
// system default and the GODEBUG=multipathtcp=... setting if any.
//
// If MPTCP is not available on the host or not supported by the client,
// the Listen method will fall back to TCP.
func (lc *ListenConfig) SetMultipathTCP(use bool) {
	lc.mptcpStatus.set(use)
}

// Listen announces on the local network address.
//
// See func Listen for a description of the network and address
// parameters.
//
// The ctx argument is used while resolving the address on which to listen;
// it does not affect the returned Listener.
func (lc *ListenConfig) Listen(ctx context.Context, network, address string) (Listener, error) {
	addrs, err := DefaultResolver.resolveAddrList(ctx, "listen", network, address, nil)
	if err != nil {
		return nil, &OpError{Op: "listen", Net: network, Source: nil, Addr: nil, Err: err}
	}
	sl := &sysListener{
		ListenConfig: *lc,
		network:      network,
		address:      address,
	}
	var l Listener
	la := addrs.first(isIPv4)
	switch la := la.(type) {
	case *TCPAddr:
		if sl.MultipathTCP() {
			l, err = sl.listenMPTCP(ctx, la)
		} else {
			l, err = sl.listenTCP(ctx, la)
		}
	case *UnixAddr:
		l, err = sl.listenUnix(ctx, la)
	default:
		return nil, &OpError{Op: "listen", Net: sl.network, Source: nil, Addr: la, Err: &AddrError{Err: "unexpected address type", Addr: address}}
	}
	if err != nil {
		return nil, &OpError{Op: "listen", Net: sl.network, Source: nil, Addr: la, Err: err} // l is non-nil interface containing nil pointer
	}
	return l, nil
}

// ListenPacket announces on the local network address.
//
// See func ListenPacket for a description of the network and address
// parameters.
//
// The ctx argument is used while resolving the address on which to listen;
// it does not affect the returned Listener.
func (lc *ListenConfig) ListenPacket(ctx context.Context, network, address string) (PacketConn, error) {
	addrs, err := DefaultResolver.resolveAddrList(ctx, "listen", network, address, nil)
	if err != nil {
		return nil, &OpError{Op: "listen", Net: network, Source: nil, Addr: nil, Err: err}
	}
	sl := &sysListener{
		ListenConfig: *lc,
		network:      network,
		address:      address,
	}
	var c PacketConn
	la := addrs.first(isIPv4)
	switch la := la.(type) {
	case *UDPAddr:
		c, err = sl.listenUDP(ctx, la)
	case *IPAddr:
		c, err = sl.listenIP(ctx, la)
	case *UnixAddr:
		c, err = sl.listenUnixgram(ctx, la)
	default:
		return nil, &OpError{Op: "listen", Net: sl.network, Source: nil, Addr: la, Err: &AddrError{Err: "unexpected address type", Addr: address}}
	}
	if err != nil {
		return nil, &OpError{Op: "listen", Net: sl.network, Source: nil, Addr: la, Err: err} // c is non-nil interface containing nil pointer
	}
	return c, nil
}

// sysListener contains a Listen's parameters and configuration.
type sysListener struct {
	ListenConfig
	network, address string
}

// Listen announces on the local network address.
//
// The network must be "tcp", "tcp4", "tcp6", "unix" or "unixpacket".
//
// For TCP networks, if the host in the address parameter is empty or
// a literal unspecified IP address, Listen listens on all available
// unicast and anycast IP addresses of the local system.
// To only use IPv4, use network "tcp4".
// The address can use a host name, but this is not recommended,
// because it will create a listener for at most one of the host's IP
// addresses.
// If the port in the address parameter is empty or "0", as in
// "127.0.0.1:" or "[::1]:0", a port number is automatically chosen.
// The [Addr] method of [Listener] can be used to discover the chosen
// port.
//
// See func [Dial] for a description of the network and address
// parameters.
//
// Listen uses context.Background internally; to specify the context, use
// [ListenConfig.Listen].
func Listen(network, address string) (Listener, error) {
	var lc ListenConfig
	return lc.Listen(context.Background(), network, address)
}

// ListenPacket announces on the local network address.
//
// The network must be "udp", "udp4", "udp6", "unixgram", or an IP
// transport. The IP transports are "ip", "ip4", or "ip6" followed by
// a colon and a literal protocol number or a protocol name, as in
// "ip:1" or "ip:icmp".
//
// For UDP and IP networks, if the host in the address parameter is
// empty or a literal unspecified IP address, ListenPacket listens on
// all available IP addresses of the local system except multicast IP
// addresses.
// To only use IPv4, use network "udp4" or "ip4:proto".
// The address can use a host name, but this is not recommended,
// because it will create a listener for at most one of the host's IP
// addresses.
// If the port in the address parameter is empty or "0", as in
// "127.0.0.1:" or "[::1]:0", a port number is automatically chosen.
// The LocalAddr method of [PacketConn] can be used to discover the
// chosen port.
//
// See func [Dial] for a description of the network and address
// parameters.
//
// ListenPacket uses context.Background internally; to specify the context, use
// [ListenConfig.ListenPacket].
func ListenPacket(network, address string) (PacketConn, error) {
	var lc ListenConfig
	return lc.ListenPacket(context.Background(), network, address)
}

"""



```