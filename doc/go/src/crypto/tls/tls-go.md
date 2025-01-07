Response:
The user wants to understand the functionality of the provided Go code snippet from `go/src/crypto/tls/tls.go`. I need to:

1. **List the functionalities**: Identify the main actions and data structures defined in the code.
2. **Infer Go language feature implementation**: Deduce which high-level TLS concepts are being implemented.
3. **Provide Go code examples**: Illustrate the usage of the identified features with runnable code.
4. **Include input and output for code examples**: Specify the expected input and output of the example code.
5. **Explain command-line argument handling**: Detail how any command-line arguments are processed (though the provided snippet doesn't seem to directly handle them, it uses `internal/godebug`).
6. **Point out common mistakes**: Identify potential pitfalls for users of this code.

Let's break down the code section by section:

- **Package declaration and imports**:  Indicates this is part of the `tls` package and imports necessary crypto and network libraries.
- **`Server` function**: Creates a TLS server-side connection.
- **`Client` function**: Creates a TLS client-side connection.
- **`listener` struct and related functions (`Accept`, `NewListener`, `Listen`)**: Implements a TLS listener for accepting incoming connections.
- **`timeoutError` struct**: Defines a custom error type for timeouts.
- **`DialWithDialer` and `dial` functions**: Implement TLS dialing with a custom dialer.
- **`Dial` function**: Implements basic TLS dialing.
- **`Dialer` struct and related functions (`Dial`, `DialContext`)**: Provides a more configurable TLS dialer.
- **`LoadX509KeyPair` and `X509KeyPair` functions**: Handle loading and parsing X.509 key pairs from files or byte slices.
- **`parsePrivateKey` function**: Parses different private key formats.
- **`godebug` usage**:  Shows the use of an internal package for debugging flags.

Based on this analysis, I can formulate the answer.
这段代码是Go语言标准库 `crypto/tls` 包的一部分，主要负责实现 **传输层安全协议（TLS）** 的核心功能，用于建立加密的网络连接。具体来说，它提供了构建TLS客户端和服务器的基础结构。

以下是代码中列举的功能：

1. **创建 TLS 服务器连接 (`Server` 函数)**:
    *   接收一个底层的 `net.Conn` 连接和一个 `Config` 配置对象作为输入。
    *   返回一个新的 `Conn` 对象，该对象代表一个 TLS 服务器端连接。
    *   设置连接的握手函数为 `serverHandshake`，表明这是一个服务器连接。
    *   **推理：**  这是实现 TLS 服务器的关键步骤，用于包装一个普通的网络连接，使其支持 TLS 加密。

    ```go
    package main

    import (
        "crypto/tls"
        "log"
        "net"
    )

    func main() {
        // 假设已经有一个 net.Listener 在监听
        listener, err := net.Listen("tcp", ":8080")
        if err != nil {
            log.Fatal(err)
        }
        defer listener.Close()

        config := &tls.Config{
            // 至少需要配置一个证书
            Certificates: make([]tls.Certificate, 1), // 实际使用时需要加载证书
        }

        for {
            conn, err := listener.Accept()
            if err != nil {
                log.Println(err)
                continue
            }
            defer conn.Close()

            // 将普通的 net.Conn 升级为 TLS 连接
            tlsConn := tls.Server(conn, config)

            // 在 tlsConn 上进行 TLS 握手和数据传输
            // ...
        }
    }
    ```
    **假设输入：** 一个已经建立的 `net.Conn` 对象和一个包含服务器证书的 `tls.Config` 对象。
    **输出：** 一个指向 `tls.Conn` 对象的指针，该对象封装了底层的连接，并准备进行 TLS 握手。

2. **创建 TLS 客户端连接 (`Client` 函数)**:
    *   接收一个底层的 `net.Conn` 连接和一个 `Config` 配置对象作为输入。
    *   返回一个新的 `Conn` 对象，该对象代表一个 TLS 客户端连接。
    *   设置连接的 `isClient` 标志为 `true`。
    *   设置连接的握手函数为 `clientHandshake`，表明这是一个客户端连接。
    *   **推理：** 这是实现 TLS 客户端的关键步骤，用于包装一个普通的网络连接，使其能够发起 TLS 连接。

    ```go
    package main

    import (
        "crypto/tls"
        "log"
        "net"
    )

    func main() {
        config := &tls.Config{
            InsecureSkipVerify: true, // 生产环境不建议使用
            ServerName:         "example.com", // 目标服务器的域名
        }

        // 建立一个普通的 TCP 连接
        conn, err := net.Dial("tcp", "example.com:443")
        if err != nil {
            log.Fatal(err)
        }
        defer conn.Close()

        // 将普通的 net.Conn 升级为 TLS 连接
        tlsConn := tls.Client(conn, config)

        // 在 tlsConn 上进行 TLS 握手
        err = tlsConn.Handshake()
        if err != nil {
            log.Fatal(err)
        }

        // 现在可以使用 tlsConn 进行加密的数据传输了
        // ...
    }
    ```
    **假设输入：** 一个已经建立的 `net.Conn` 对象和一个包含服务器名称或跳过证书验证的 `tls.Config` 对象。
    **输出：** 一个指向 `tls.Conn` 对象的指针，该对象封装了底层的连接，并准备发起 TLS 握手。

3. **创建 TLS 监听器 (`listener` 类型和相关函数)**:
    *   `listener` 结构体封装了一个底层的 `net.Listener` 和一个 `tls.Config`。
    *   `Accept()` 方法等待并接受下一个到来的连接，然后使用 `Server()` 函数将其包装成 TLS 服务器连接。
    *   `NewListener()` 函数创建一个新的 TLS 监听器，它接受一个底层的 `net.Listener` 和一个 `tls.Config` 作为输入。
    *   `Listen()` 函数创建一个在给定网络地址上监听的 TLS 监听器。它首先使用 `net.Listen` 创建一个底层的监听器，然后使用 `NewListener` 将其包装成 TLS 监听器。
    *   **推理：**  这是构建 TLS 服务器的关键组件，它负责监听连接请求并将普通连接升级为 TLS 连接。

    ```go
    package main

    import (
        "crypto/tls"
        "log"
        "net"
    )

    func main() {
        cert, err := tls.LoadX509KeyPair("server.crt", "server.key")
        if err != nil {
            log.Fatal(err)
        }

        config := &tls.Config{
            Certificates: []tls.Certificate{cert},
        }

        // 创建一个 TLS 监听器
        listener, err := tls.Listen("tcp", ":8443", config)
        if err != nil {
            log.Fatal(err)
        }
        defer listener.Close()

        log.Println("TLS server listening on :8443")

        for {
            conn, err := listener.Accept()
            if err != nil {
                log.Println(err)
                continue
            }
            defer conn.Close()

            // conn 现在是 *tls.Conn 类型，可以直接进行加密通信
            go handleConnection(conn)
        }
    }

    func handleConnection(conn net.Conn) {
        // ... 处理连接 ...
    }
    ```
    **假设输入：** 网络类型 (例如 "tcp")，监听地址 (例如 ":443") 和包含服务器证书的 `tls.Config` 对象。
    **输出：** 一个实现了 `net.Listener` 接口的 TLS 监听器，可以接受 TLS 连接。

4. **实现带超时的连接 (`timeoutError` 类型)**:
    *   定义了一个自定义的错误类型 `timeoutError`，用于表示连接超时。
    *   该类型实现了 `error` 接口的 `Error()` 方法，以及 `net.Error` 接口的 `Timeout()` 和 `Temporary()` 方法。
    *   **推理：** 用于更精细地控制连接过程中的超时行为。

5. **通过 `Dialer` 进行连接 (`DialWithDialer` 和 `dial` 函数)**:
    *   `DialWithDialer` 函数使用给定的 `net.Dialer` 连接到指定网络地址，并初始化 TLS 握手。它可以传递 `net.Dialer` 中设置的超时或截止时间。
    *   `dial` 函数是 `DialWithDialer` 的底层实现，它接收一个 `context.Context` 对象，允许更细粒度的超时和取消控制。
    *   **推理：** 提供了更灵活的 TLS 连接方式，允许自定义底层的连接行为，例如设置超时时间。

    ```go
    package main

    import (
        "context"
        "crypto/tls"
        "log"
        "net"
        "time"
    )

    func main() {
        dialer := &net.Dialer{
            Timeout: 5 * time.Second,
        }

        config := &tls.Config{
            InsecureSkipVerify: true,
            ServerName:         "example.com",
        }

        // 使用 DialWithDialer 进行连接，并设置超时
        conn, err := tls.DialWithDialer(dialer, "tcp", "example.com:443", config)
        if err != nil {
            log.Fatal(err)
        }
        defer conn.Close()

        log.Println("Successfully connected to example.com via TLS")
    }
    ```
    **假设输入：** 一个配置好的 `net.Dialer`，网络类型，目标地址，以及 `tls.Config`。
    **输出：** 一个指向 `tls.Conn` 对象的指针，代表已建立的 TLS 连接，或者一个错误。

6. **简化的连接方法 (`Dial` 函数)**:
    *   使用默认的 `net.Dialer` 连接到指定网络地址并进行 TLS 握手。
    *   **推理：** 提供了一种更简洁的创建 TLS 客户端连接的方式。

    ```go
    package main

    import (
        "crypto/tls"
        "log"
    )

    func main() {
        config := &tls.Config{
            InsecureSkipVerify: true,
            ServerName:         "example.com",
        }

        // 使用 Dial 函数进行连接
        conn, err := tls.Dial("tcp", "example.com:443", config)
        if err != nil {
            log.Fatal(err)
        }
        defer conn.Close()

        log.Println("Successfully connected to example.com via TLS")
    }
    ```
    **假设输入：** 网络类型，目标地址，以及 `tls.Config`。
    **输出：** 一个指向 `tls.Conn` 对象的指针，代表已建立的 TLS 连接，或者一个错误。

7. **可配置的 TLS 连接器 (`Dialer` 类型和相关函数)**:
    *   `Dialer` 结构体允许用户自定义底层的 `net.Dialer` 和 TLS 配置。
    *   `Dial()` 方法使用内部的 `net.Dialer` 和配置连接到指定地址。
    *   `DialContext()` 方法允许使用 `context.Context` 来控制连接过程。
    *   **推理：** 提供了更细粒度的控制 TLS 客户端连接的方式，可以自定义底层的网络连接行为和 TLS 配置。

    ```go
    package main

    import (
        "context"
        "crypto/tls"
        "log"
        "net"
        "time"
    )

    func main() {
        dialer := tls.Dialer{
            NetDialer: &net.Dialer{
                Timeout: 3 * time.Second,
            },
            Config: &tls.Config{
                InsecureSkipVerify: true,
                ServerName:         "example.com",
            },
        }

        // 使用 Dialer.DialContext 进行连接，并设置超时
        ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
        defer cancel()

        conn, err := dialer.DialContext(ctx, "tcp", "example.com:443")
        if err != nil {
            log.Fatal(err)
        }
        defer conn.Close()

        log.Println("Successfully connected to example.com via TLS")
    }
    ```
    **假设输入：** 网络类型和目标地址。`Dialer` 结构体已经配置了 `NetDialer` 和 `Config`。对于 `DialContext`，还需要一个 `context.Context`。
    **输出：** 一个指向 `tls.Conn` 对象的指针，代表已建立的 TLS 连接，或者一个错误。

8. **加载 X.509 密钥对 (`LoadX509KeyPair` 和 `X509KeyPair` 函数)**:
    *   `LoadX509KeyPair` 从文件中读取 PEM 编码的证书和私钥。
    *   `X509KeyPair` 从字节切片中解析 PEM 编码的证书和私钥。
    *   这两个函数都会尝试解析证书链，并验证私钥与公钥是否匹配。
    *   **推理：** 这是配置 TLS 服务器或客户端证书的关键步骤。

    ```go
    package main

    import (
        "crypto/tls"
        "log"
    )

    func main() {
        // 从文件中加载密钥对
        cert, err := tls.LoadX509KeyPair("server.crt", "server.key")
        if err != nil {
            log.Fatal(err)
        }
        log.Printf("Successfully loaded certificate with Common Name: %s\n", cert.Leaf.Subject.CommonName)

        // 从字节切片加载密钥对
        certPEM := []byte(`-----BEGIN CERTIFICATE----- ... -----END CERTIFICATE-----`)
        keyPEM := []byte(`-----BEGIN PRIVATE KEY----- ... -----END PRIVATE KEY-----`)
        cert2, err := tls.X509KeyPair(certPEM, keyPEM)
        if err != nil {
            log.Fatal(err)
        }
        log.Printf("Successfully loaded certificate from bytes with Common Name: %s\n", cert2.Leaf.Subject.CommonName)
    }
    ```
    **假设输入 (`LoadX509KeyPair`):** 证书文件路径 ("server.crt") 和私钥文件路径 ("server.key")。
    **输出 (`LoadX509KeyPair`):** 一个包含解析后的证书和私钥的 `tls.Certificate` 对象，或者一个错误。

    **假设输入 (`X509KeyPair`):** PEM 编码的证书字节切片和私钥字节切片。
    **输出 (`X509KeyPair`):** 一个包含解析后的证书和私钥的 `tls.Certificate` 对象，或者一个错误。

9. **解析私钥 (`parsePrivateKey` 函数)**:
    *   尝试解析不同格式的私钥，包括 PKCS#1、PKCS#8 和 SEC1 EC 私钥。
    *   **推理：** 提供了对不同私钥格式的兼容性。

    ```go
    package main

    import (
        "crypto"
        "crypto/tls"
        "encoding/pem"
        "log"
    )

    func main() {
        keyPEM := []byte(`-----BEGIN PRIVATE KEY----- ... -----END PRIVATE KEY-----`)
        block, _ := pem.Decode(keyPEM)
        if block == nil {
            log.Fatal("failed to decode PEM block")
        }

        // 假设 block.Bytes 包含了私钥的 DER 编码
        privateKey, err := tls.parsePrivateKey(block.Bytes)
        if err != nil {
            log.Fatalf("failed to parse private key: %v", err)
        }

        switch privateKey.(type) {
        case *crypto.RSA:
            log.Println("Parsed RSA private key")
        case *crypto.ECDSA:
            log.Println("Parsed ECDSA private key")
        case crypto.PrivateKey:
            log.Println("Parsed unknown private key type")
        }
    }
    ```
    **假设输入：** 私钥的 DER 编码字节切片。
    **输出：** 一个实现了 `crypto.PrivateKey` 接口的私钥对象，或者一个错误。

**关于命令行参数的具体处理：**

这段代码本身并没有直接处理命令行参数。`internal/godebug` 包用于读取环境变量 `GODEBUG` 的值，以控制一些内部的调试行为，例如是否填充 `Certificate.Leaf` 字段。例如，设置环境变量 `GODEBUG=x509keypairleaf=0` 可以禁用填充 `Certificate.Leaf` 的行为。这不是通过命令行参数直接控制的，而是通过环境变量。

**使用者易犯错的点：**

1. **`Config` 配置不正确：**
    *   **服务器端：** 忘记在 `Config` 中设置 `Certificates` 或 `GetCertificate`，导致无法进行 TLS 握手。
        ```go
        // 错误示例：缺少证书配置
        config := &tls.Config{}
        ln, err := tls.Listen("tcp", ":443", config) // 这会导致错误
        ```
    *   **客户端：**  没有设置 `ServerName` 或 `InsecureSkipVerify`，导致无法进行服务器身份验证。在生产环境中，不应轻易使用 `InsecureSkipVerify: true`。
        ```go
        // 错误示例：缺少 ServerName 且 InsecureSkipVerify 为 false (默认)
        config := &tls.Config{}
        conn, err := tls.Dial("tcp", "example.com:443", config) // 这会导致证书验证错误
        ```

2. **证书和私钥文件路径错误：**  在使用 `LoadX509KeyPair` 时，如果提供的证书或私钥文件路径不正确，会导致加载失败。
    ```go
    // 错误示例：文件路径错误
    cert, err := tls.LoadX509KeyPair("wrong_cert.pem", "wrong_key.pem")
    if err != nil {
        log.Fatal(err) // 可能会打印 "no such file or directory" 错误
    }
    ```

3. **PEM 编码格式错误：** `X509KeyPair` 函数依赖于正确的 PEM 编码格式。如果提供的字节切片不是有效的 PEM 格式，解析会失败。
    ```go
    // 错误示例：PEM 格式错误
    certPEM := []byte("invalid pem data")
    keyPEM := []byte("invalid pem data")
    _, err := tls.X509KeyPair(certPEM, keyPEM) // 会导致解析错误
    ```

4. **私钥与公钥不匹配：**  加载的私钥必须与证书中的公钥匹配，否则 TLS 握手会失败。`LoadX509KeyPair` 和 `X509KeyPair` 会进行基本的验证，但确保文件内容正确是用户的责任。

5. **不理解 `InsecureSkipVerify` 的风险：**  在客户端配置中使用 `InsecureSkipVerify: true` 会跳过服务器证书的验证，这在测试环境中可能方便，但在生产环境中会带来严重的安全风险，可能导致中间人攻击。

总而言之，这段代码提供了构建 TLS 连接的核心功能，包括创建服务器和客户端连接、监听 TLS 连接、以及加载和解析证书密钥对。正确理解和配置 `tls.Config` 对象以及正确处理证书和密钥是使用此包的关键。

Prompt: 
```
这是路径为go/src/crypto/tls/tls.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。

"""
// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package tls partially implements TLS 1.2, as specified in RFC 5246,
// and TLS 1.3, as specified in RFC 8446.
package tls

// BUG(agl): The crypto/tls package only implements some countermeasures
// against Lucky13 attacks on CBC-mode encryption, and only on SHA1
// variants. See http://www.isg.rhul.ac.uk/tls/TLStiming.pdf and
// https://www.imperialviolet.org/2013/02/04/luckythirteen.html.

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"internal/godebug"
	"net"
	"os"
	"strings"
)

// Server returns a new TLS server side connection
// using conn as the underlying transport.
// The configuration config must be non-nil and must include
// at least one certificate or else set GetCertificate.
func Server(conn net.Conn, config *Config) *Conn {
	c := &Conn{
		conn:   conn,
		config: config,
	}
	c.handshakeFn = c.serverHandshake
	return c
}

// Client returns a new TLS client side connection
// using conn as the underlying transport.
// The config cannot be nil: users must set either ServerName or
// InsecureSkipVerify in the config.
func Client(conn net.Conn, config *Config) *Conn {
	c := &Conn{
		conn:     conn,
		config:   config,
		isClient: true,
	}
	c.handshakeFn = c.clientHandshake
	return c
}

// A listener implements a network listener (net.Listener) for TLS connections.
type listener struct {
	net.Listener
	config *Config
}

// Accept waits for and returns the next incoming TLS connection.
// The returned connection is of type *Conn.
func (l *listener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return Server(c, l.config), nil
}

// NewListener creates a Listener which accepts connections from an inner
// Listener and wraps each connection with [Server].
// The configuration config must be non-nil and must include
// at least one certificate or else set GetCertificate.
func NewListener(inner net.Listener, config *Config) net.Listener {
	l := new(listener)
	l.Listener = inner
	l.config = config
	return l
}

// Listen creates a TLS listener accepting connections on the
// given network address using net.Listen.
// The configuration config must be non-nil and must include
// at least one certificate or else set GetCertificate.
func Listen(network, laddr string, config *Config) (net.Listener, error) {
	// If this condition changes, consider updating http.Server.ServeTLS too.
	if config == nil || len(config.Certificates) == 0 &&
		config.GetCertificate == nil && config.GetConfigForClient == nil {
		return nil, errors.New("tls: neither Certificates, GetCertificate, nor GetConfigForClient set in Config")
	}
	l, err := net.Listen(network, laddr)
	if err != nil {
		return nil, err
	}
	return NewListener(l, config), nil
}

type timeoutError struct{}

func (timeoutError) Error() string   { return "tls: DialWithDialer timed out" }
func (timeoutError) Timeout() bool   { return true }
func (timeoutError) Temporary() bool { return true }

// DialWithDialer connects to the given network address using dialer.Dial and
// then initiates a TLS handshake, returning the resulting TLS connection. Any
// timeout or deadline given in the dialer apply to connection and TLS
// handshake as a whole.
//
// DialWithDialer interprets a nil configuration as equivalent to the zero
// configuration; see the documentation of [Config] for the defaults.
//
// DialWithDialer uses context.Background internally; to specify the context,
// use [Dialer.DialContext] with NetDialer set to the desired dialer.
func DialWithDialer(dialer *net.Dialer, network, addr string, config *Config) (*Conn, error) {
	return dial(context.Background(), dialer, network, addr, config)
}

func dial(ctx context.Context, netDialer *net.Dialer, network, addr string, config *Config) (*Conn, error) {
	if netDialer.Timeout != 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, netDialer.Timeout)
		defer cancel()
	}

	if !netDialer.Deadline.IsZero() {
		var cancel context.CancelFunc
		ctx, cancel = context.WithDeadline(ctx, netDialer.Deadline)
		defer cancel()
	}

	rawConn, err := netDialer.DialContext(ctx, network, addr)
	if err != nil {
		return nil, err
	}

	colonPos := strings.LastIndex(addr, ":")
	if colonPos == -1 {
		colonPos = len(addr)
	}
	hostname := addr[:colonPos]

	if config == nil {
		config = defaultConfig()
	}
	// If no ServerName is set, infer the ServerName
	// from the hostname we're connecting to.
	if config.ServerName == "" {
		// Make a copy to avoid polluting argument or default.
		c := config.Clone()
		c.ServerName = hostname
		config = c
	}

	conn := Client(rawConn, config)
	if err := conn.HandshakeContext(ctx); err != nil {
		rawConn.Close()
		return nil, err
	}
	return conn, nil
}

// Dial connects to the given network address using net.Dial
// and then initiates a TLS handshake, returning the resulting
// TLS connection.
// Dial interprets a nil configuration as equivalent to
// the zero configuration; see the documentation of Config
// for the defaults.
func Dial(network, addr string, config *Config) (*Conn, error) {
	return DialWithDialer(new(net.Dialer), network, addr, config)
}

// Dialer dials TLS connections given a configuration and a Dialer for the
// underlying connection.
type Dialer struct {
	// NetDialer is the optional dialer to use for the TLS connections'
	// underlying TCP connections.
	// A nil NetDialer is equivalent to the net.Dialer zero value.
	NetDialer *net.Dialer

	// Config is the TLS configuration to use for new connections.
	// A nil configuration is equivalent to the zero
	// configuration; see the documentation of Config for the
	// defaults.
	Config *Config
}

// Dial connects to the given network address and initiates a TLS
// handshake, returning the resulting TLS connection.
//
// The returned [Conn], if any, will always be of type *[Conn].
//
// Dial uses context.Background internally; to specify the context,
// use [Dialer.DialContext].
func (d *Dialer) Dial(network, addr string) (net.Conn, error) {
	return d.DialContext(context.Background(), network, addr)
}

func (d *Dialer) netDialer() *net.Dialer {
	if d.NetDialer != nil {
		return d.NetDialer
	}
	return new(net.Dialer)
}

// DialContext connects to the given network address and initiates a TLS
// handshake, returning the resulting TLS connection.
//
// The provided Context must be non-nil. If the context expires before
// the connection is complete, an error is returned. Once successfully
// connected, any expiration of the context will not affect the
// connection.
//
// The returned [Conn], if any, will always be of type *[Conn].
func (d *Dialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	c, err := dial(ctx, d.netDialer(), network, addr, d.Config)
	if err != nil {
		// Don't return c (a typed nil) in an interface.
		return nil, err
	}
	return c, nil
}

// LoadX509KeyPair reads and parses a public/private key pair from a pair of
// files. The files must contain PEM encoded data. The certificate file may
// contain intermediate certificates following the leaf certificate to form a
// certificate chain. On successful return, Certificate.Leaf will be populated.
//
// Before Go 1.23 Certificate.Leaf was left nil, and the parsed certificate was
// discarded. This behavior can be re-enabled by setting "x509keypairleaf=0"
// in the GODEBUG environment variable.
func LoadX509KeyPair(certFile, keyFile string) (Certificate, error) {
	certPEMBlock, err := os.ReadFile(certFile)
	if err != nil {
		return Certificate{}, err
	}
	keyPEMBlock, err := os.ReadFile(keyFile)
	if err != nil {
		return Certificate{}, err
	}
	return X509KeyPair(certPEMBlock, keyPEMBlock)
}

var x509keypairleaf = godebug.New("x509keypairleaf")

// X509KeyPair parses a public/private key pair from a pair of
// PEM encoded data. On successful return, Certificate.Leaf will be populated.
//
// Before Go 1.23 Certificate.Leaf was left nil, and the parsed certificate was
// discarded. This behavior can be re-enabled by setting "x509keypairleaf=0"
// in the GODEBUG environment variable.
func X509KeyPair(certPEMBlock, keyPEMBlock []byte) (Certificate, error) {
	fail := func(err error) (Certificate, error) { return Certificate{}, err }

	var cert Certificate
	var skippedBlockTypes []string
	for {
		var certDERBlock *pem.Block
		certDERBlock, certPEMBlock = pem.Decode(certPEMBlock)
		if certDERBlock == nil {
			break
		}
		if certDERBlock.Type == "CERTIFICATE" {
			cert.Certificate = append(cert.Certificate, certDERBlock.Bytes)
		} else {
			skippedBlockTypes = append(skippedBlockTypes, certDERBlock.Type)
		}
	}

	if len(cert.Certificate) == 0 {
		if len(skippedBlockTypes) == 0 {
			return fail(errors.New("tls: failed to find any PEM data in certificate input"))
		}
		if len(skippedBlockTypes) == 1 && strings.HasSuffix(skippedBlockTypes[0], "PRIVATE KEY") {
			return fail(errors.New("tls: failed to find certificate PEM data in certificate input, but did find a private key; PEM inputs may have been switched"))
		}
		return fail(fmt.Errorf("tls: failed to find \"CERTIFICATE\" PEM block in certificate input after skipping PEM blocks of the following types: %v", skippedBlockTypes))
	}

	skippedBlockTypes = skippedBlockTypes[:0]
	var keyDERBlock *pem.Block
	for {
		keyDERBlock, keyPEMBlock = pem.Decode(keyPEMBlock)
		if keyDERBlock == nil {
			if len(skippedBlockTypes) == 0 {
				return fail(errors.New("tls: failed to find any PEM data in key input"))
			}
			if len(skippedBlockTypes) == 1 && skippedBlockTypes[0] == "CERTIFICATE" {
				return fail(errors.New("tls: found a certificate rather than a key in the PEM for the private key"))
			}
			return fail(fmt.Errorf("tls: failed to find PEM block with type ending in \"PRIVATE KEY\" in key input after skipping PEM blocks of the following types: %v", skippedBlockTypes))
		}
		if keyDERBlock.Type == "PRIVATE KEY" || strings.HasSuffix(keyDERBlock.Type, " PRIVATE KEY") {
			break
		}
		skippedBlockTypes = append(skippedBlockTypes, keyDERBlock.Type)
	}

	// We don't need to parse the public key for TLS, but we so do anyway
	// to check that it looks sane and matches the private key.
	x509Cert, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return fail(err)
	}

	if x509keypairleaf.Value() != "0" {
		cert.Leaf = x509Cert
	} else {
		x509keypairleaf.IncNonDefault()
	}

	cert.PrivateKey, err = parsePrivateKey(keyDERBlock.Bytes)
	if err != nil {
		return fail(err)
	}

	switch pub := x509Cert.PublicKey.(type) {
	case *rsa.PublicKey:
		priv, ok := cert.PrivateKey.(*rsa.PrivateKey)
		if !ok {
			return fail(errors.New("tls: private key type does not match public key type"))
		}
		if pub.N.Cmp(priv.N) != 0 {
			return fail(errors.New("tls: private key does not match public key"))
		}
	case *ecdsa.PublicKey:
		priv, ok := cert.PrivateKey.(*ecdsa.PrivateKey)
		if !ok {
			return fail(errors.New("tls: private key type does not match public key type"))
		}
		if pub.X.Cmp(priv.X) != 0 || pub.Y.Cmp(priv.Y) != 0 {
			return fail(errors.New("tls: private key does not match public key"))
		}
	case ed25519.PublicKey:
		priv, ok := cert.PrivateKey.(ed25519.PrivateKey)
		if !ok {
			return fail(errors.New("tls: private key type does not match public key type"))
		}
		if !bytes.Equal(priv.Public().(ed25519.PublicKey), pub) {
			return fail(errors.New("tls: private key does not match public key"))
		}
	default:
		return fail(errors.New("tls: unknown public key algorithm"))
	}

	return cert, nil
}

// Attempt to parse the given private key DER block. OpenSSL 0.9.8 generates
// PKCS #1 private keys by default, while OpenSSL 1.0.0 generates PKCS #8 keys.
// OpenSSL ecparam generates SEC1 EC private keys for ECDSA. We try all three.
func parsePrivateKey(der []byte) (crypto.PrivateKey, error) {
	if key, err := x509.ParsePKCS1PrivateKey(der); err == nil {
		return key, nil
	}
	if key, err := x509.ParsePKCS8PrivateKey(der); err == nil {
		switch key := key.(type) {
		case *rsa.PrivateKey, *ecdsa.PrivateKey, ed25519.PrivateKey:
			return key, nil
		default:
			return nil, errors.New("tls: found unknown private key type in PKCS#8 wrapping")
		}
	}
	if key, err := x509.ParseECPrivateKey(der); err == nil {
		return key, nil
	}

	return nil, errors.New("tls: failed to parse private key")
}

"""



```