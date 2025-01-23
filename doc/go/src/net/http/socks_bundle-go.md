Response:
Let's break down the thought process to analyze the provided Go code for the SOCKS implementation.

**1. Understanding the Request:**

The core request is to understand the *functionality* of the provided Go code snippet. The prompt also asks for specifics like:

* Identifying the Go feature being implemented.
* Providing a code example.
* Detailing command-line arguments (if any).
* Highlighting common mistakes.

**2. Initial Code Scan and Identification of Core Components:**

My first step is to quickly scan the code for keywords and structure. I immediately notice:

* **Package `http`:**  This suggests integration with Go's built-in HTTP library, but the comments indicate it's a SOCKS implementation. This implies it's providing SOCKS proxy support for HTTP requests.
* **Constants (e.g., `socksVersion5`, `socksCmdConnect`):** These strongly point towards an implementation of the SOCKS protocol. The specific version (5) is mentioned in the comments.
* **Structs (e.g., `socksDialer`, `socksConn`, `socksAddr`):** These represent the core data structures for the SOCKS client. `socksDialer` is likely responsible for establishing connections.
* **Functions (e.g., `connect`, `DialContext`, `Authenticate`):** These are the actions the SOCKS client can perform. `DialContext` is a standard Go interface for network dialing, indicating how this fits into the broader Go networking model. `Authenticate` clearly handles authentication.
* **Error Handling:** The code extensively uses `error` returns and creates `net.OpError` which is standard Go practice for network operations.

**3. Deduction of Functionality - SOCKS Client Implementation:**

Based on the keywords and structure, I can confidently deduce that this code implements a **SOCKS (specifically version 5) client**. It allows Go applications to route network connections through a SOCKS proxy server.

**4. Identifying the Go Feature - Custom Dialer:**

The presence of `socksDialer` and its `DialContext` method strongly suggests this is implementing a **custom `net.Dialer`**. Go's `net/http` package allows using custom dialers to modify the connection process. This is the key Go feature being utilized.

**5. Crafting the Code Example:**

To illustrate the custom dialer, I need to demonstrate how it would be used with `http.Client`. The example should:

* Import necessary packages (`net/http`, `net/url`, the current package, potentially `context`).
* Create a `socksDialer` instance, specifying the proxy address.
* Create an `http.Transport` using the `DialContext` method of the `socksDialer`.
* Create an `http.Client` with the custom `Transport`.
* Make an HTTP request using the client.

This example clearly shows how to integrate the SOCKS client with standard Go HTTP requests.

**6. Analyzing Specific Functions:**

* **`connect`:** This function seems to handle the core SOCKS handshake, including version negotiation, authentication, and sending the connect request. I notice the handling of different address types (IPv4, IPv6, FQDN).
* **`sockssplitHostPort`:** A utility for parsing host:port strings.
* **`Authenticate` (in `socksUsernamePassword`):** Implements the username/password authentication mechanism.

**7. Command-Line Arguments:**

I carefully review the code and comments. There's no direct processing of command-line arguments *within this specific snippet*. The `//go:generate bundle` comment indicates this file is generated, implying the configuration might come from elsewhere (the `bundle` tool itself). Therefore, the answer should state that no command-line arguments are directly handled in *this* code.

**8. Identifying Potential Mistakes:**

I look for common pitfalls when using SOCKS proxies:

* **Incorrect Proxy Address:**  A very common issue.
* **Authentication Errors:**  Wrong username/password.
* **Unsupported Authentication Methods:** The server might not support the client's chosen method.
* **Network Issues:** General connectivity problems between the client and the proxy.
* **DNS Resolution Issues (with FQDN proxies):** The client needs to be able to resolve the proxy's hostname.

I choose the "Incorrect Proxy Address" as a simple and illustrative example. The code snippet demonstrates how to *create* the dialer but not how to *configure* it from external sources, making the proxy address a crucial configuration point.

**9. Structuring the Answer:**

Finally, I organize the information into a clear and logical format, following the structure requested in the prompt:

* Start with a high-level summary of the functionality.
* Explain the specific Go feature being implemented (custom dialer).
* Provide the code example.
* Address command-line arguments (or lack thereof).
* Explain the reasoning behind the example.
* Highlight a common mistake with an example.
* Use clear and concise Chinese.

**Self-Correction/Refinement:**

* Initially, I might have focused too much on the low-level SOCKS protocol details. However, the prompt also asks about the *Go feature*. Realizing it's about the custom `net.Dialer` is crucial.
* I considered including examples of other common mistakes, but sticking to one clear example is better for understanding.
* I double-checked that the code example was complete and runnable (conceptually, as it depends on the surrounding project).

By following this structured approach, I can effectively analyze the code and provide a comprehensive and accurate answer to the prompt.
这段Go语言代码是 `net/http` 包中用于支持 **SOCKS 代理** 功能的一部分。它实现了一个 **SOCKS 客户端**，允许 Go 程序通过 SOCKS 代理服务器建立网络连接。

**功能列举：**

1. **创建 SOCKS 连接:**  `socksDialer` 结构体及其相关方法负责创建与 SOCKS 代理服务器的连接，并协商 SOCKS 协议。
2. **支持 SOCKS 版本 5:** 代码中的常量 `socksVersion5` 表明它主要针对 SOCKS 协议的第五版。
3. **支持多种 SOCKS 命令:**  支持 `CONNECT` 命令 (`socksCmdConnect`)，用于建立主动开放的转发代理连接。代码中也定义了 `BIND` 命令 (`sockscmdBind`)，但注释中提到建立的是被动开放的连接，可能在当前的上下文中没有被广泛使用或完整实现。
4. **支持多种认证方式:**
    * **无需认证:**  如果 `AuthMethods` 为空或 `Authenticate` 为 `nil`，则尝试无需认证 (`socksAuthMethodNotRequired`)。
    * **用户名/密码认证:**  通过 `socksUsernamePassword` 结构体和 `Authenticate` 方法实现用户名和密码的认证 (`socksAuthMethodUsernamePassword`)。
5. **处理目标地址:**  能够处理 IPv4、IPv6 地址和域名 (`socksAddrTypeIPv4`, `socksAddrTypeIPv6`, `socksAddrTypeFQDN`) 作为连接目标。
6. **处理连接上下文:**  `connect` 和 `DialContext` 方法都接受 `context.Context`，允许取消或设置连接超时。
7. **返回 SOCKS 连接对象:**  `DialContext` 方法返回一个 `socksConn` 结构体，它包装了底层的 `net.Conn`，并可以提供代理服务器分配的绑定地址 (`BoundAddr`)。
8. **提供 `Dialer` 接口:**  `socksDialer` 实现了 `net.Dialer` 接口的部分功能，可以被 `http.Transport` 等使用，以实现 HTTP 请求通过 SOCKS 代理。

**实现的 Go 语言功能：自定义 `net.Dialer`**

这段代码核心实现的是一个 **自定义的 `net.Dialer`**。Go 的 `net` 包提供了 `Dialer` 接口，允许用户自定义网络连接的建立过程。 `socksDialer` 结构体及其 `DialContext` 方法就是这个自定义 `Dialer` 的实现。

**Go 代码举例说明：**

假设我们需要通过一个 SOCKS5 代理服务器 `127.0.0.1:1080` 连接到 `www.example.com:80`。

```go
package main

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	socks "net/http" // 注意这里的 import 别名，避免与标准库的 net 包冲突
)

func main() {
	proxyURL, _ := url.Parse("socks5://127.0.0.1:1080")

	// 创建一个自定义的 dialer
	dialer := socks.NewDialer("tcp", proxyURL.Host)

	// 如果代理需要用户名密码认证
	// dialer.Authenticate = (&socks.UsernamePassword{
	// 	Username: "your_username",
	// 	Password: "your_password",
	// }).Authenticate
	// dialer.AuthMethods = []socks.socksAuthMethod{socks.socksAuthMethodUsernamePassword}

	// 创建一个使用自定义 dialer 的 http.Transport
	transport := &http.Transport{
		DialContext: dialer.DialContext,
	}

	// 创建一个使用自定义 Transport 的 http.Client
	client := &http.Client{
		Transport: transport,
		Timeout:   10 * time.Second,
	}

	// 发起 HTTP GET 请求
	resp, err := client.Get("http://www.example.com")
	if err != nil {
		fmt.Println("Error:", err)
		return
	}
	defer resp.Body.Close()

	// 读取响应内容
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Println("Error reading body:", err)
		return
	}

	fmt.Println("Response status:", resp.Status)
	fmt.Println("Response body:", string(body))
}
```

**假设的输入与输出：**

* **假设输入:**
    * 代理服务器地址: `127.0.0.1:1080` (无需认证)
    * 目标地址: `www.example.com:80`
* **预期输出:**
    * 如果连接成功，程序将打印 `www.example.com` 的 HTTP 响应状态码 (如 `200 OK`) 和 HTML 内容。
    * 如果连接失败（例如，代理服务器未运行或网络错误），程序将打印相应的错误信息。

**代码推理：**

1. **`socks.NewDialer("tcp", proxyURL.Host)`:**  创建一个 `socksDialer` 实例，指定代理服务器的网络类型为 "tcp"，地址为 `127.0.0.1:1080`。
2. **`transport := &http.Transport{DialContext: dialer.DialContext}`:** 创建一个 `http.Transport`，并将自定义的 `dialer.DialContext` 方法赋值给 `Transport` 的 `DialContext` 字段。这意味着当 `http.Client` 需要建立 TCP 连接时，它会调用我们自定义的 SOCKS dialer。
3. **`client := &http.Client{Transport: transport}`:** 创建一个 `http.Client`，使用我们配置了 SOCKS 代理的 `transport`。
4. **`client.Get("http://www.example.com")`:**  发起一个 HTTP GET 请求。由于 `client` 使用了配置了 SOCKS 代理的 `transport`，这个请求会先连接到 SOCKS 代理服务器，然后由代理服务器连接到 `www.example.com`。

**命令行参数的具体处理：**

这段代码本身并没有直接处理命令行参数。SOCKS 代理服务器的地址通常是在代码中硬编码（如上面的例子），或者从配置文件、环境变量中读取。如果要处理命令行参数，你需要使用 Go 的 `flag` 包或其他命令行参数解析库。

例如，你可以这样处理代理服务器地址：

```go
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	socks "net/http"
)

func main() {
	proxyAddr := flag.String("proxy", "", "SOCKS proxy address (e.g., 127.0.0.1:1080)")
	flag.Parse()

	if *proxyAddr == "" {
		fmt.Println("Error: Proxy address is required.")
		return
	}

	proxyURL, err := url.Parse("socks5://" + *proxyAddr)
	if err != nil {
		fmt.Println("Error parsing proxy URL:", err)
		return
	}

	dialer := socks.NewDialer("tcp", proxyURL.Host)

	// ... 后续代码与之前的例子相同 ...
}
```

在这个修改后的例子中，用户可以通过 `--proxy` 命令行参数指定 SOCKS 代理服务器的地址。

**使用者易犯错的点：**

1. **代理服务器地址格式错误:** 容易忘记指定协议 (如 `socks5://`) 或端口号，或者使用了错误的 IP 地址或域名。
    * **错误示例:**  只写 `127.0.0.1` 而不是 `127.0.0.1:1080`。
2. **认证配置错误:**  如果 SOCKS 代理服务器需要认证，忘记设置 `Authenticate` 函数和 `AuthMethods`，或者用户名和密码错误。
    * **错误示例:** 代理需要用户名密码，但代码中没有设置 `dialer.Authenticate` 和 `dialer.AuthMethods`。
3. **网络连接问题:**  SOCKS 代理服务器未运行，或者客户端无法连接到代理服务器。
    * **错误示例:**  代理服务器程序没有启动，导致连接超时或连接被拒绝。
4. **目标地址无法访问:**  即使通过了 SOCKS 代理，目标地址可能仍然无法访问（例如，目标服务器宕机）。
5. **上下文使用不当:**  没有正确使用 `context.Context` 设置超时，可能导致程序长时间阻塞。

总而言之，这段代码提供了一个构建 SOCKS 客户端的关键组件，它允许 Go 程序方便地通过 SOCKS 代理服务器进行网络通信。理解其功能和使用方法对于需要实现代理功能的 Go 应用非常重要。

### 提示词
```
这是路径为go/src/net/http/socks_bundle.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
```

### 源代码
```go
// Code generated by golang.org/x/tools/cmd/bundle. DO NOT EDIT.
//go:generate bundle -o socks_bundle.go -prefix socks golang.org/x/net/internal/socks

// Package socks provides a SOCKS version 5 client implementation.
//
// SOCKS protocol version 5 is defined in RFC 1928.
// Username/Password authentication for SOCKS version 5 is defined in
// RFC 1929.
//

package http

import (
	"context"
	"errors"
	"io"
	"net"
	"strconv"
	"time"
)

var (
	socksnoDeadline   = time.Time{}
	socksaLongTimeAgo = time.Unix(1, 0)
)

func (d *socksDialer) connect(ctx context.Context, c net.Conn, address string) (_ net.Addr, ctxErr error) {
	host, port, err := sockssplitHostPort(address)
	if err != nil {
		return nil, err
	}
	if deadline, ok := ctx.Deadline(); ok && !deadline.IsZero() {
		c.SetDeadline(deadline)
		defer c.SetDeadline(socksnoDeadline)
	}
	if ctx != context.Background() {
		errCh := make(chan error, 1)
		done := make(chan struct{})
		defer func() {
			close(done)
			if ctxErr == nil {
				ctxErr = <-errCh
			}
		}()
		go func() {
			select {
			case <-ctx.Done():
				c.SetDeadline(socksaLongTimeAgo)
				errCh <- ctx.Err()
			case <-done:
				errCh <- nil
			}
		}()
	}

	b := make([]byte, 0, 6+len(host)) // the size here is just an estimate
	b = append(b, socksVersion5)
	if len(d.AuthMethods) == 0 || d.Authenticate == nil {
		b = append(b, 1, byte(socksAuthMethodNotRequired))
	} else {
		ams := d.AuthMethods
		if len(ams) > 255 {
			return nil, errors.New("too many authentication methods")
		}
		b = append(b, byte(len(ams)))
		for _, am := range ams {
			b = append(b, byte(am))
		}
	}
	if _, ctxErr = c.Write(b); ctxErr != nil {
		return
	}

	if _, ctxErr = io.ReadFull(c, b[:2]); ctxErr != nil {
		return
	}
	if b[0] != socksVersion5 {
		return nil, errors.New("unexpected protocol version " + strconv.Itoa(int(b[0])))
	}
	am := socksAuthMethod(b[1])
	if am == socksAuthMethodNoAcceptableMethods {
		return nil, errors.New("no acceptable authentication methods")
	}
	if d.Authenticate != nil {
		if ctxErr = d.Authenticate(ctx, c, am); ctxErr != nil {
			return
		}
	}

	b = b[:0]
	b = append(b, socksVersion5, byte(d.cmd), 0)
	if ip := net.ParseIP(host); ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			b = append(b, socksAddrTypeIPv4)
			b = append(b, ip4...)
		} else if ip6 := ip.To16(); ip6 != nil {
			b = append(b, socksAddrTypeIPv6)
			b = append(b, ip6...)
		} else {
			return nil, errors.New("unknown address type")
		}
	} else {
		if len(host) > 255 {
			return nil, errors.New("FQDN too long")
		}
		b = append(b, socksAddrTypeFQDN)
		b = append(b, byte(len(host)))
		b = append(b, host...)
	}
	b = append(b, byte(port>>8), byte(port))
	if _, ctxErr = c.Write(b); ctxErr != nil {
		return
	}

	if _, ctxErr = io.ReadFull(c, b[:4]); ctxErr != nil {
		return
	}
	if b[0] != socksVersion5 {
		return nil, errors.New("unexpected protocol version " + strconv.Itoa(int(b[0])))
	}
	if cmdErr := socksReply(b[1]); cmdErr != socksStatusSucceeded {
		return nil, errors.New("unknown error " + cmdErr.String())
	}
	if b[2] != 0 {
		return nil, errors.New("non-zero reserved field")
	}
	l := 2
	var a socksAddr
	switch b[3] {
	case socksAddrTypeIPv4:
		l += net.IPv4len
		a.IP = make(net.IP, net.IPv4len)
	case socksAddrTypeIPv6:
		l += net.IPv6len
		a.IP = make(net.IP, net.IPv6len)
	case socksAddrTypeFQDN:
		if _, err := io.ReadFull(c, b[:1]); err != nil {
			return nil, err
		}
		l += int(b[0])
	default:
		return nil, errors.New("unknown address type " + strconv.Itoa(int(b[3])))
	}
	if cap(b) < l {
		b = make([]byte, l)
	} else {
		b = b[:l]
	}
	if _, ctxErr = io.ReadFull(c, b); ctxErr != nil {
		return
	}
	if a.IP != nil {
		copy(a.IP, b)
	} else {
		a.Name = string(b[:len(b)-2])
	}
	a.Port = int(b[len(b)-2])<<8 | int(b[len(b)-1])
	return &a, nil
}

func sockssplitHostPort(address string) (string, int, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return "", 0, err
	}
	portnum, err := strconv.Atoi(port)
	if err != nil {
		return "", 0, err
	}
	if 1 > portnum || portnum > 0xffff {
		return "", 0, errors.New("port number out of range " + port)
	}
	return host, portnum, nil
}

// A Command represents a SOCKS command.
type socksCommand int

func (cmd socksCommand) String() string {
	switch cmd {
	case socksCmdConnect:
		return "socks connect"
	case sockscmdBind:
		return "socks bind"
	default:
		return "socks " + strconv.Itoa(int(cmd))
	}
}

// An AuthMethod represents a SOCKS authentication method.
type socksAuthMethod int

// A Reply represents a SOCKS command reply code.
type socksReply int

func (code socksReply) String() string {
	switch code {
	case socksStatusSucceeded:
		return "succeeded"
	case 0x01:
		return "general SOCKS server failure"
	case 0x02:
		return "connection not allowed by ruleset"
	case 0x03:
		return "network unreachable"
	case 0x04:
		return "host unreachable"
	case 0x05:
		return "connection refused"
	case 0x06:
		return "TTL expired"
	case 0x07:
		return "command not supported"
	case 0x08:
		return "address type not supported"
	default:
		return "unknown code: " + strconv.Itoa(int(code))
	}
}

// Wire protocol constants.
const (
	socksVersion5 = 0x05

	socksAddrTypeIPv4 = 0x01
	socksAddrTypeFQDN = 0x03
	socksAddrTypeIPv6 = 0x04

	socksCmdConnect socksCommand = 0x01 // establishes an active-open forward proxy connection
	sockscmdBind    socksCommand = 0x02 // establishes a passive-open forward proxy connection

	socksAuthMethodNotRequired         socksAuthMethod = 0x00 // no authentication required
	socksAuthMethodUsernamePassword    socksAuthMethod = 0x02 // use username/password
	socksAuthMethodNoAcceptableMethods socksAuthMethod = 0xff // no acceptable authentication methods

	socksStatusSucceeded socksReply = 0x00
)

// An Addr represents a SOCKS-specific address.
// Either Name or IP is used exclusively.
type socksAddr struct {
	Name string // fully-qualified domain name
	IP   net.IP
	Port int
}

func (a *socksAddr) Network() string { return "socks" }

func (a *socksAddr) String() string {
	if a == nil {
		return "<nil>"
	}
	port := strconv.Itoa(a.Port)
	if a.IP == nil {
		return net.JoinHostPort(a.Name, port)
	}
	return net.JoinHostPort(a.IP.String(), port)
}

// A Conn represents a forward proxy connection.
type socksConn struct {
	net.Conn

	boundAddr net.Addr
}

// BoundAddr returns the address assigned by the proxy server for
// connecting to the command target address from the proxy server.
func (c *socksConn) BoundAddr() net.Addr {
	if c == nil {
		return nil
	}
	return c.boundAddr
}

// A Dialer holds SOCKS-specific options.
type socksDialer struct {
	cmd          socksCommand // either CmdConnect or cmdBind
	proxyNetwork string       // network between a proxy server and a client
	proxyAddress string       // proxy server address

	// ProxyDial specifies the optional dial function for
	// establishing the transport connection.
	ProxyDial func(context.Context, string, string) (net.Conn, error)

	// AuthMethods specifies the list of request authentication
	// methods.
	// If empty, SOCKS client requests only AuthMethodNotRequired.
	AuthMethods []socksAuthMethod

	// Authenticate specifies the optional authentication
	// function. It must be non-nil when AuthMethods is not empty.
	// It must return an error when the authentication is failed.
	Authenticate func(context.Context, io.ReadWriter, socksAuthMethod) error
}

// DialContext connects to the provided address on the provided
// network.
//
// The returned error value may be a net.OpError. When the Op field of
// net.OpError contains "socks", the Source field contains a proxy
// server address and the Addr field contains a command target
// address.
//
// See func Dial of the net package of standard library for a
// description of the network and address parameters.
func (d *socksDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if err := d.validateTarget(network, address); err != nil {
		proxy, dst, _ := d.pathAddrs(address)
		return nil, &net.OpError{Op: d.cmd.String(), Net: network, Source: proxy, Addr: dst, Err: err}
	}
	if ctx == nil {
		proxy, dst, _ := d.pathAddrs(address)
		return nil, &net.OpError{Op: d.cmd.String(), Net: network, Source: proxy, Addr: dst, Err: errors.New("nil context")}
	}
	var err error
	var c net.Conn
	if d.ProxyDial != nil {
		c, err = d.ProxyDial(ctx, d.proxyNetwork, d.proxyAddress)
	} else {
		var dd net.Dialer
		c, err = dd.DialContext(ctx, d.proxyNetwork, d.proxyAddress)
	}
	if err != nil {
		proxy, dst, _ := d.pathAddrs(address)
		return nil, &net.OpError{Op: d.cmd.String(), Net: network, Source: proxy, Addr: dst, Err: err}
	}
	a, err := d.connect(ctx, c, address)
	if err != nil {
		c.Close()
		proxy, dst, _ := d.pathAddrs(address)
		return nil, &net.OpError{Op: d.cmd.String(), Net: network, Source: proxy, Addr: dst, Err: err}
	}
	return &socksConn{Conn: c, boundAddr: a}, nil
}

// DialWithConn initiates a connection from SOCKS server to the target
// network and address using the connection c that is already
// connected to the SOCKS server.
//
// It returns the connection's local address assigned by the SOCKS
// server.
func (d *socksDialer) DialWithConn(ctx context.Context, c net.Conn, network, address string) (net.Addr, error) {
	if err := d.validateTarget(network, address); err != nil {
		proxy, dst, _ := d.pathAddrs(address)
		return nil, &net.OpError{Op: d.cmd.String(), Net: network, Source: proxy, Addr: dst, Err: err}
	}
	if ctx == nil {
		proxy, dst, _ := d.pathAddrs(address)
		return nil, &net.OpError{Op: d.cmd.String(), Net: network, Source: proxy, Addr: dst, Err: errors.New("nil context")}
	}
	a, err := d.connect(ctx, c, address)
	if err != nil {
		proxy, dst, _ := d.pathAddrs(address)
		return nil, &net.OpError{Op: d.cmd.String(), Net: network, Source: proxy, Addr: dst, Err: err}
	}
	return a, nil
}

// Dial connects to the provided address on the provided network.
//
// Unlike DialContext, it returns a raw transport connection instead
// of a forward proxy connection.
//
// Deprecated: Use DialContext or DialWithConn instead.
func (d *socksDialer) Dial(network, address string) (net.Conn, error) {
	if err := d.validateTarget(network, address); err != nil {
		proxy, dst, _ := d.pathAddrs(address)
		return nil, &net.OpError{Op: d.cmd.String(), Net: network, Source: proxy, Addr: dst, Err: err}
	}
	var err error
	var c net.Conn
	if d.ProxyDial != nil {
		c, err = d.ProxyDial(context.Background(), d.proxyNetwork, d.proxyAddress)
	} else {
		c, err = net.Dial(d.proxyNetwork, d.proxyAddress)
	}
	if err != nil {
		proxy, dst, _ := d.pathAddrs(address)
		return nil, &net.OpError{Op: d.cmd.String(), Net: network, Source: proxy, Addr: dst, Err: err}
	}
	if _, err := d.DialWithConn(context.Background(), c, network, address); err != nil {
		c.Close()
		return nil, err
	}
	return c, nil
}

func (d *socksDialer) validateTarget(network, address string) error {
	switch network {
	case "tcp", "tcp6", "tcp4":
	default:
		return errors.New("network not implemented")
	}
	switch d.cmd {
	case socksCmdConnect, sockscmdBind:
	default:
		return errors.New("command not implemented")
	}
	return nil
}

func (d *socksDialer) pathAddrs(address string) (proxy, dst net.Addr, err error) {
	for i, s := range []string{d.proxyAddress, address} {
		host, port, err := sockssplitHostPort(s)
		if err != nil {
			return nil, nil, err
		}
		a := &socksAddr{Port: port}
		a.IP = net.ParseIP(host)
		if a.IP == nil {
			a.Name = host
		}
		if i == 0 {
			proxy = a
		} else {
			dst = a
		}
	}
	return
}

// NewDialer returns a new Dialer that dials through the provided
// proxy server's network and address.
func socksNewDialer(network, address string) *socksDialer {
	return &socksDialer{proxyNetwork: network, proxyAddress: address, cmd: socksCmdConnect}
}

const (
	socksauthUsernamePasswordVersion = 0x01
	socksauthStatusSucceeded         = 0x00
)

// UsernamePassword are the credentials for the username/password
// authentication method.
type socksUsernamePassword struct {
	Username string
	Password string
}

// Authenticate authenticates a pair of username and password with the
// proxy server.
func (up *socksUsernamePassword) Authenticate(ctx context.Context, rw io.ReadWriter, auth socksAuthMethod) error {
	switch auth {
	case socksAuthMethodNotRequired:
		return nil
	case socksAuthMethodUsernamePassword:
		if len(up.Username) == 0 || len(up.Username) > 255 || len(up.Password) > 255 {
			return errors.New("invalid username/password")
		}
		b := []byte{socksauthUsernamePasswordVersion}
		b = append(b, byte(len(up.Username)))
		b = append(b, up.Username...)
		b = append(b, byte(len(up.Password)))
		b = append(b, up.Password...)
		// TODO(mikio): handle IO deadlines and cancelation if
		// necessary
		if _, err := rw.Write(b); err != nil {
			return err
		}
		if _, err := io.ReadFull(rw, b[:2]); err != nil {
			return err
		}
		if b[0] != socksauthUsernamePasswordVersion {
			return errors.New("invalid username/password version")
		}
		if b[1] != socksauthStatusSucceeded {
			return errors.New("username/password authentication failed")
		}
		return nil
	}
	return errors.New("unsupported authentication method " + strconv.Itoa(int(auth)))
}
```