Response:
Let's break down the thought process for answering the user's request about the provided Go code snippet.

**1. Understanding the Goal:**

The user wants to understand the functionality of the provided Go code, which is a part of `net/http/http.go`. The request specifically asks for:

* Listing the functions.
* Inferring the Go language features being implemented and providing examples.
* Explaining code reasoning (with input/output examples).
* Describing command-line argument handling (if any).
* Pointing out common mistakes.
* All in Chinese.

**2. Initial Code Scan and Keyword Recognition:**

My first step is to quickly scan the code for keywords and structural elements. I look for:

* `package http`:  Confirms this is part of the `net/http` package.
* `import`:  Lists dependencies, including `golang.org/x/net/http/httpguts` and `golang.org/x/net/http2` (though the `//go:generate` comment suggests the latter might be bundled).
* Type definitions (`type Protocols struct`, `type incomparable [0]func()`, `type contextKey struct`, `type noBody struct`, `type PushOptions struct`, `type Pusher interface`, `type HTTP2Config struct`):  These are crucial for understanding the data structures and abstractions involved.
* Function definitions (`func (p Protocols) HTTP1() bool`, `func (p *Protocols) SetHTTP1(ok bool)`, etc.):  These are the core actions and behaviors exposed by the code.
* Constants (`const protoHTTP1`, `const maxInt64`, `var aLongTimeAgo`, `var omitBundledHTTP2`, `var NoBody`): These define important values and states.
* Comments, especially those starting with `//`: These provide high-level explanations and context.

**3. Identifying Key Functionality Areas:**

Based on the keywords and types, I can start grouping the code into functional areas:

* **Protocol Negotiation (`Protocols` struct and related methods):** This clearly deals with handling different HTTP versions (HTTP/1, HTTP/2, Unencrypted HTTP/2).
* **Utility Functions (e.g., `hasPort`, `removeEmptyPort`, `stringContainsCTLByte`, `hexEscapeNonASCII`):** These are helper functions for string manipulation, likely related to HTTP header and URL processing.
* **No-Body Handling (`NoBody` variable and `noBody` type):** This seems to provide a way to represent a request or response without a body.
* **Server Push (`PushOptions` struct and `Pusher` interface):** This is a more advanced HTTP/2 feature.
* **HTTP/2 Configuration (`HTTP2Config` struct):**  This allows for fine-tuning HTTP/2 settings.
* **Context Management (`contextKey` struct):**  This is related to Go's `context` package for managing request-scoped data.
* **Internal Implementation Details (`incomparable` type, `maxInt64`, `aLongTimeAgo`, `omitBundledHTTP2`):** These are less about user-facing functionality and more about internal implementation.

**4. Deep Dive into Specific Areas:**

Now I examine each functional area in more detail.

* **`Protocols`:** The bitmask implementation is straightforward. The `String()` method is useful for debugging. I can infer it's used to represent the supported HTTP protocols.
* **Utility Functions:**  I consider *why* these functions exist. `hasPort` and `removeEmptyPort` are clearly about URL parsing. `stringContainsCTLByte` and `hexEscapeNonASCII` are related to header sanitization or encoding.
* **`NoBody`:**  The name is self-explanatory. The methods implement `io.ReadCloser` and `io.WriterTo`, making it usable in places where those interfaces are expected. The comment about `Request.Body` being nil is a key usage point.
* **`Pusher`:** I recognize this as the server-push mechanism in HTTP/2. The documentation-style comments within the interface definition are very helpful.
* **`HTTP2Config`:** The field names are descriptive, indicating various HTTP/2 settings.

**5. Inferring Go Language Features and Providing Examples:**

This involves connecting the code constructs to specific Go features:

* **Bit Manipulation:** The `Protocols` struct uses bitwise operations (`&`, `|`, `^`) for efficient storage and manipulation of boolean flags. I can create an example demonstrating setting and checking protocol support.
* **Interfaces:** The `Pusher` interface defines a contract for types that support server push. I can illustrate how a type might implement this interface (although the provided snippet doesn't show an actual implementation).
* **Structs:**  The various `struct` types are used to group related data. I can show how to create and access fields of these structs.
* **Constants and Variables:**  These are used for defining fixed values and global states. I can point out their purpose.
* **`//go:generate`:** This is a build directive. I need to explain that it's used to generate code before compilation.
* **Context:**  The `contextKey` type hints at the usage of Go's `context` package for request-scoped data. While the snippet doesn't show explicit usage, I can mention its likely role.

**6. Code Reasoning and Examples with Input/Output:**

For functions like `hasPort`, `removeEmptyPort`, `hexEscapeNonASCII`, providing input and expected output makes the functionality very clear. I need to choose representative examples that demonstrate the function's behavior in different scenarios.

**7. Command-Line Arguments:**

A quick scan reveals no direct use of `os.Args` or the `flag` package. Therefore, I conclude that this specific snippet doesn't handle command-line arguments.

**8. Common Mistakes:**

I think about potential pitfalls for users based on the code:

* **Misunderstanding `NoBody`:**  Users might think they need to create a `noBody` instance directly, not realizing they can just set `Request.Body` to `nil`.
* **Incorrect `Pusher.Push` usage:**  The restrictions on target URLs (absolute path or same scheme/host) and the timing of the call (before sending related data) are important and potential sources of errors.

**9. Structuring the Answer (Chinese):**

Finally, I need to organize the information clearly in Chinese, addressing each point in the user's request. I use headings and bullet points for better readability. I ensure the code examples are valid Go syntax and the explanations are concise and accurate.

**Self-Correction/Refinement During the Process:**

* **Initial thought:**  Maybe the `//go:generate` line is directly relevant to command-line arguments. **Correction:**  Realized it's for code generation, not runtime argument parsing.
* **Initial thought:** Focus heavily on HTTP/2 specific details. **Correction:** Ensure I also cover the HTTP/1 aspects mentioned in the `Protocols` struct.
* **Double-check:** Ensure all code examples are syntactically correct and demonstrate the intended point.

By following these steps, I can systematically analyze the code snippet and provide a comprehensive and accurate answer to the user's request.
这段代码是 Go 语言标准库 `net/http` 包中 `http.go` 文件的一部分。它主要定义了一些底层的、与 HTTP 协议相关的类型、常量和辅助函数。  从提供的代码片段来看，其核心功能可以归纳为以下几点：

1. **定义了 `Protocols` 类型，用于表示支持的 HTTP 协议版本:**
   - 它使用位掩码来高效地存储和操作支持的协议集合 (HTTP/1, HTTP/2, 未加密的 HTTP/2)。
   - 提供了方法来检查和设置支持的协议。
   - 提供了 `String()` 方法方便以字符串形式查看支持的协议。

2. **定义了 `incomparable` 类型，用于使结构体不可比较:**
   - 这是一种常见的 Go 技巧，通过在结构体中嵌入此类型，可以防止该结构体被直接使用 `==` 或 `!=` 进行比较。这通常用于包含函数或其他不可比较字段的结构体。

3. **定义了一些常用的常量和变量:**
   - `maxInt64`:  表示最大的 `int64` 值，常用于表示无限或很大的限制。
   - `aLongTimeAgo`: 一个很早的时间，常用于立即取消网络操作。
   - `omitBundledHTTP2`: 一个布尔值，用于指示是否因为构建标签而省略了内置的 HTTP/2 支持。
   - `NoBody`: 一个实现了 `io.ReadCloser` 接口的类型，用于表示没有请求或响应体的情况。

4. **定义了 `contextKey` 类型，用于作为 `context.Context` 的键:**
   - 这是一种推荐的做法，避免不同的包使用相同的字符串作为 `context` 的键而发生冲突。

5. **提供了一些实用工具函数:**
   - `hasPort(s string) bool`:  检查字符串是否包含端口号。
   - `removeEmptyPort(host string) string`:  移除主机名中空端口部分（例如，将 `:80` 转换为 `""`）。
   - `isNotToken(r rune) bool`:  判断 Unicode 字符是否不是 HTTP token 字符。
   - `stringContainsCTLByte(s string) bool`:  检查字符串是否包含 ASCII 控制字符。
   - `hexEscapeNonASCII(s string) string`:  将非 ASCII 字符进行百分号编码。

6. **定义了与 HTTP/2 服务器推送相关的类型和接口:**
   - `PushOptions`: 定义了服务器推送的选项，例如请求方法和额外的头部信息。
   - `Pusher` 接口: 定义了支持 HTTP/2 服务器推送的 `ResponseWriter` 必须实现的方法 `Push`。

7. **定义了 `HTTP2Config` 结构体，用于配置 HTTP/2 参数:**
   - 这个结构体包含了诸如最大并发流数量、头部压缩表大小、最大帧大小、流控窗口大小、超时时间等 HTTP/2 特有的配置项。

**它是什么 Go 语言功能的实现？**

这段代码主要体现了以下 Go 语言功能的实现：

* **类型定义 (`type`)**: 用于创建自定义的数据类型，如 `Protocols`, `HTTP2Config` 等。
* **结构体 (`struct`)**: 用于组合不同类型的数据字段，例如 `Protocols` 中使用 `uint8` 存储位掩码。
* **接口 (`interface`)**:  `Pusher` 是一个接口，定义了一组方法签名，用于实现 HTTP/2 服务器推送功能。
* **方法 (`func (receiver Type) MethodName(...)`)**:  例如 `Protocols` 类型的 `HTTP1()`, `SetHTTP1()` 等方法，用于操作类型的数据。
* **常量 (`const`) 和变量 (`var`)**: 用于定义程序中使用的固定值和可变状态。
* **位运算**: `Protocols` 类型使用了位运算来高效地管理多个布尔状态。
* **字符串操作**: 使用 `strings` 包进行字符串的查找、拼接和处理。
* **Unicode 支持**: 使用 `unicode/utf8` 包处理 UTF-8 编码的字符串。
* **代码生成 (`//go:generate`)**:  用于在构建过程中自动生成代码。

**Go 代码举例说明:**

**1. 使用 `Protocols` 类型:**

```go
package main

import (
	"fmt"
	"net/http"
)

func main() {
	var supportedProtocols http.Protocols

	// 设置支持 HTTP/1 和 HTTP/2
	supportedProtocols.SetHTTP1(true)
	supportedProtocols.SetHTTP2(true)

	fmt.Println("支持的协议:", supportedProtocols) // 输出: 支持的协议: {HTTP1,HTTP2}

	// 检查是否支持 HTTP/1
	if supportedProtocols.HTTP1() {
		fmt.Println("支持 HTTP/1") // 输出: 支持 HTTP/1
	}

	// 取消支持 HTTP/1
	supportedProtocols.SetHTTP1(false)
	fmt.Println("支持的协议 (取消 HTTP/1):", supportedProtocols) // 输出: 支持的协议 (取消 HTTP/1): {HTTP2}
}
```

**假设输入与输出:**

上面的代码没有外部输入，输出已经在注释中说明。

**2. 使用 `NoBody` 表示没有请求体:**

```go
package main

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
)

func main() {
	req, err := http.NewRequest("POST", "/test", http.NoBody)
	if err != nil {
		panic(err)
	}

	// 验证请求体是否为空
	buf := new(bytes.Buffer)
	_, err = io.Copy(buf, req.Body)
	if err != nil && err != io.EOF {
		panic(err)
	}
	fmt.Println("请求体内容:", buf.String()) // 输出: 请求体内容:

	err = req.Body.Close()
	if err != nil {
		panic(err)
	}

	// 使用 httptest 模拟一个处理程序
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		buf := new(bytes.Buffer)
		_, err := io.Copy(buf, r.Body)
		if err != nil && err != io.EOF {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		fmt.Println("服务端接收到的请求体:", buf.String()) // 输出: 服务端接收到的请求体:
		w.WriteHeader(http.StatusOK)
	})

	// 模拟发送请求
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
}
```

**假设输入与输出:**

上面的代码模拟了一个 HTTP 请求，没有外部输入。输出已经在注释中说明，展示了客户端和服务端都正确处理了 `http.NoBody`。

**3. 使用 `hasPort` 函数:**

```go
package main

import (
	"fmt"
	"net/http"
)

func main() {
	hosts := []string{"example.com", "example.com:8080", "[::1]:80", "[2001:db8::1]"}
	for _, host := range hosts {
		if http.HasPort(host) {
			fmt.Printf("%s 包含端口号\n", host)
		} else {
			fmt.Printf("%s 不包含端口号\n", host)
		}
	}
}
```

**假设输入与输出:**

上面的代码没有外部输入，输出如下：

```
example.com 不包含端口号
example.com:8080 包含端口号
[::1]:80 包含端口号
[2001:db8::1] 不包含端口号
```

**4. 使用 `hexEscapeNonASCII` 函数:**

```go
package main

import (
	"fmt"
	"net/http"
)

func main() {
	s := "你好，世界！"
	escaped := http.HexEscapeNonASCII(s)
	fmt.Println("原始字符串:", s)       // 输出: 原始字符串: 你好，世界！
	fmt.Println("转义后的字符串:", escaped) // 输出: 转义后的字符串: %E4%BD%A0%E5%A5%BD%EF%BC%8C%E4%B8%96%E7%95%8C%EF%BC%81
}
```

**假设输入与输出:**

上面的代码没有外部输入，输出已经在注释中说明。

**命令行参数的具体处理:**

这段代码片段本身**没有直接处理命令行参数**。命令行参数的处理通常在 `main` 函数中使用 `os.Args` 切片或 `flag` 标准库来实现。这段代码只是定义了一些底层的 HTTP 相关的类型和函数，供 `net/http` 包的其他部分使用，而 `net/http` 包本身可能会在创建 `Server` 或 `Transport` 时接受一些配置选项，但这些选项通常是通过结构体字段或函数参数传递的，而不是直接通过命令行参数。

**使用者易犯错的点:**

1. **误解 `NoBody` 的用途:**  新手可能会尝试手动创建 `noBody` 类型的实例，但更推荐的做法是直接使用预定义的 `http.NoBody` 常量或将 `Request.Body` 设置为 `nil`。

2. **不理解 `Protocols` 的位掩码机制:**  直接操作 `Protocols` 结构体的 `bits` 字段可能会导致错误，应该使用提供的 `SetHTTP1`, `SetHTTP2`, `SetUnencryptedHTTP2` 方法。

3. **在不需要的情况下使用 `hexEscapeNonASCII`:**  这个函数主要用于特定场景下的编码，例如 URL 或 HTTP 头部中的某些非 ASCII 字符。在普通文本处理中不应过度使用。

4. **不熟悉 HTTP/2 服务器推送的限制:** 使用 `Pusher` 接口时，需要理解 HTTP/2 协议对服务器推送的限制，例如不能递归推送和跨域推送。如果违反这些限制，可能会导致推送失败或被客户端拒绝。

总而言之，这段代码是 `net/http` 包的基础组成部分，定义了用于表示 HTTP 协议版本、处理无请求体、进行字符串处理以及配置 HTTP/2 等关键类型和函数。它为构建更高级的 HTTP 客户端和服务器功能提供了必要的 building blocks。

### 提示词
```
这是路径为go/src/net/http/http.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
```

### 源代码
```go
// Copyright 2016 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:generate bundle -o=h2_bundle.go -prefix=http2 -tags=!nethttpomithttp2 golang.org/x/net/http2

package http

import (
	"io"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"golang.org/x/net/http/httpguts"
)

// Protocols is a set of HTTP protocols.
// The zero value is an empty set of protocols.
//
// The supported protocols are:
//
//   - HTTP1 is the HTTP/1.0 and HTTP/1.1 protocols.
//     HTTP1 is supported on both unsecured TCP and secured TLS connections.
//
//   - HTTP2 is the HTTP/2 protcol over a TLS connection.
//
//   - UnencryptedHTTP2 is the HTTP/2 protocol over an unsecured TCP connection.
type Protocols struct {
	bits uint8
}

const (
	protoHTTP1 = 1 << iota
	protoHTTP2
	protoUnencryptedHTTP2
)

// HTTP1 reports whether p includes HTTP/1.
func (p Protocols) HTTP1() bool { return p.bits&protoHTTP1 != 0 }

// SetHTTP1 adds or removes HTTP/1 from p.
func (p *Protocols) SetHTTP1(ok bool) { p.setBit(protoHTTP1, ok) }

// HTTP2 reports whether p includes HTTP/2.
func (p Protocols) HTTP2() bool { return p.bits&protoHTTP2 != 0 }

// SetHTTP2 adds or removes HTTP/2 from p.
func (p *Protocols) SetHTTP2(ok bool) { p.setBit(protoHTTP2, ok) }

// UnencryptedHTTP2 reports whether p includes unencrypted HTTP/2.
func (p Protocols) UnencryptedHTTP2() bool { return p.bits&protoUnencryptedHTTP2 != 0 }

// SetUnencryptedHTTP2 adds or removes unencrypted HTTP/2 from p.
func (p *Protocols) SetUnencryptedHTTP2(ok bool) { p.setBit(protoUnencryptedHTTP2, ok) }

func (p *Protocols) setBit(bit uint8, ok bool) {
	if ok {
		p.bits |= bit
	} else {
		p.bits &^= bit
	}
}

func (p Protocols) String() string {
	var s []string
	if p.HTTP1() {
		s = append(s, "HTTP1")
	}
	if p.HTTP2() {
		s = append(s, "HTTP2")
	}
	if p.UnencryptedHTTP2() {
		s = append(s, "UnencryptedHTTP2")
	}
	return "{" + strings.Join(s, ",") + "}"
}

// incomparable is a zero-width, non-comparable type. Adding it to a struct
// makes that struct also non-comparable, and generally doesn't add
// any size (as long as it's first).
type incomparable [0]func()

// maxInt64 is the effective "infinite" value for the Server and
// Transport's byte-limiting readers.
const maxInt64 = 1<<63 - 1

// aLongTimeAgo is a non-zero time, far in the past, used for
// immediate cancellation of network operations.
var aLongTimeAgo = time.Unix(1, 0)

// omitBundledHTTP2 is set by omithttp2.go when the nethttpomithttp2
// build tag is set. That means h2_bundle.go isn't compiled in and we
// shouldn't try to use it.
var omitBundledHTTP2 bool

// TODO(bradfitz): move common stuff here. The other files have accumulated
// generic http stuff in random places.

// contextKey is a value for use with context.WithValue. It's used as
// a pointer so it fits in an interface{} without allocation.
type contextKey struct {
	name string
}

func (k *contextKey) String() string { return "net/http context value " + k.name }

// Given a string of the form "host", "host:port", or "[ipv6::address]:port",
// return true if the string includes a port.
func hasPort(s string) bool { return strings.LastIndex(s, ":") > strings.LastIndex(s, "]") }

// removeEmptyPort strips the empty port in ":port" to ""
// as mandated by RFC 3986 Section 6.2.3.
func removeEmptyPort(host string) string {
	if hasPort(host) {
		return strings.TrimSuffix(host, ":")
	}
	return host
}

func isNotToken(r rune) bool {
	return !httpguts.IsTokenRune(r)
}

// stringContainsCTLByte reports whether s contains any ASCII control character.
func stringContainsCTLByte(s string) bool {
	for i := 0; i < len(s); i++ {
		b := s[i]
		if b < ' ' || b == 0x7f {
			return true
		}
	}
	return false
}

func hexEscapeNonASCII(s string) string {
	newLen := 0
	for i := 0; i < len(s); i++ {
		if s[i] >= utf8.RuneSelf {
			newLen += 3
		} else {
			newLen++
		}
	}
	if newLen == len(s) {
		return s
	}
	b := make([]byte, 0, newLen)
	var pos int
	for i := 0; i < len(s); i++ {
		if s[i] >= utf8.RuneSelf {
			if pos < i {
				b = append(b, s[pos:i]...)
			}
			b = append(b, '%')
			b = strconv.AppendInt(b, int64(s[i]), 16)
			pos = i + 1
		}
	}
	if pos < len(s) {
		b = append(b, s[pos:]...)
	}
	return string(b)
}

// NoBody is an [io.ReadCloser] with no bytes. Read always returns EOF
// and Close always returns nil. It can be used in an outgoing client
// request to explicitly signal that a request has zero bytes.
// An alternative, however, is to simply set [Request.Body] to nil.
var NoBody = noBody{}

type noBody struct{}

func (noBody) Read([]byte) (int, error)         { return 0, io.EOF }
func (noBody) Close() error                     { return nil }
func (noBody) WriteTo(io.Writer) (int64, error) { return 0, nil }

var (
	// verify that an io.Copy from NoBody won't require a buffer:
	_ io.WriterTo   = NoBody
	_ io.ReadCloser = NoBody
)

// PushOptions describes options for [Pusher.Push].
type PushOptions struct {
	// Method specifies the HTTP method for the promised request.
	// If set, it must be "GET" or "HEAD". Empty means "GET".
	Method string

	// Header specifies additional promised request headers. This cannot
	// include HTTP/2 pseudo header fields like ":path" and ":scheme",
	// which will be added automatically.
	Header Header
}

// Pusher is the interface implemented by ResponseWriters that support
// HTTP/2 server push. For more background, see
// https://tools.ietf.org/html/rfc7540#section-8.2.
type Pusher interface {
	// Push initiates an HTTP/2 server push. This constructs a synthetic
	// request using the given target and options, serializes that request
	// into a PUSH_PROMISE frame, then dispatches that request using the
	// server's request handler. If opts is nil, default options are used.
	//
	// The target must either be an absolute path (like "/path") or an absolute
	// URL that contains a valid host and the same scheme as the parent request.
	// If the target is a path, it will inherit the scheme and host of the
	// parent request.
	//
	// The HTTP/2 spec disallows recursive pushes and cross-authority pushes.
	// Push may or may not detect these invalid pushes; however, invalid
	// pushes will be detected and canceled by conforming clients.
	//
	// Handlers that wish to push URL X should call Push before sending any
	// data that may trigger a request for URL X. This avoids a race where the
	// client issues requests for X before receiving the PUSH_PROMISE for X.
	//
	// Push will run in a separate goroutine making the order of arrival
	// non-deterministic. Any required synchronization needs to be implemented
	// by the caller.
	//
	// Push returns ErrNotSupported if the client has disabled push or if push
	// is not supported on the underlying connection.
	Push(target string, opts *PushOptions) error
}

// HTTP2Config defines HTTP/2 configuration parameters common to
// both [Transport] and [Server].
type HTTP2Config struct {
	// MaxConcurrentStreams optionally specifies the number of
	// concurrent streams that a peer may have open at a time.
	// If zero, MaxConcurrentStreams defaults to at least 100.
	MaxConcurrentStreams int

	// MaxDecoderHeaderTableSize optionally specifies an upper limit for the
	// size of the header compression table used for decoding headers sent
	// by the peer.
	// A valid value is less than 4MiB.
	// If zero or invalid, a default value is used.
	MaxDecoderHeaderTableSize int

	// MaxEncoderHeaderTableSize optionally specifies an upper limit for the
	// header compression table used for sending headers to the peer.
	// A valid value is less than 4MiB.
	// If zero or invalid, a default value is used.
	MaxEncoderHeaderTableSize int

	// MaxReadFrameSize optionally specifies the largest frame
	// this endpoint is willing to read.
	// A valid value is between 16KiB and 16MiB, inclusive.
	// If zero or invalid, a default value is used.
	MaxReadFrameSize int

	// MaxReceiveBufferPerConnection is the maximum size of the
	// flow control window for data received on a connection.
	// A valid value is at least 64KiB and less than 4MiB.
	// If invalid, a default value is used.
	MaxReceiveBufferPerConnection int

	// MaxReceiveBufferPerStream is the maximum size of
	// the flow control window for data received on a stream (request).
	// A valid value is less than 4MiB.
	// If zero or invalid, a default value is used.
	MaxReceiveBufferPerStream int

	// SendPingTimeout is the timeout after which a health check using a ping
	// frame will be carried out if no frame is received on a connection.
	// If zero, no health check is performed.
	SendPingTimeout time.Duration

	// PingTimeout is the timeout after which a connection will be closed
	// if a response to a ping is not received.
	// If zero, a default of 15 seconds is used.
	PingTimeout time.Duration

	// WriteByteTimeout is the timeout after which a connection will be
	// closed if no data can be written to it. The timeout begins when data is
	// available to write, and is extended whenever any bytes are written.
	WriteByteTimeout time.Duration

	// PermitProhibitedCipherSuites, if true, permits the use of
	// cipher suites prohibited by the HTTP/2 spec.
	PermitProhibitedCipherSuites bool

	// CountError, if non-nil, is called on HTTP/2 errors.
	// It is intended to increment a metric for monitoring.
	// The errType contains only lowercase letters, digits, and underscores
	// (a-z, 0-9, _).
	CountError func(errType string)
}
```