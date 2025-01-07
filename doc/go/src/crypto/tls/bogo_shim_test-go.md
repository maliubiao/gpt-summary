Response:
The user wants to understand the functionality of the provided Go code snippet, specifically the `bogo_shim_test.go` file within the `crypto/tls` package. I need to analyze the code and identify its purpose, highlighting key features and how they are implemented.

Here's a breakdown of the steps:

1. **Identify the core functionality:**  The filename and the presence of command-line flags suggest this is a test utility or shim for testing TLS implementations. The `bogoShim` function is the main entry point.

2. **Analyze command-line flags:**  List and explain the purpose of each flag. These flags likely control various aspects of the TLS handshake and connection.

3. **Understand the `bogoShim` function:**
    - How it uses the command-line flags to configure a `tls.Config`.
    - Whether it acts as a TLS client or server.
    - How it interacts with a network connection.
    - What kind of assertions or checks it performs.

4. **Infer the purpose of `TestBogoSuite`:** This function seems to orchestrate external testing, likely by running a separate TLS implementation (like BoringSSL) and comparing its behavior.

5. **Provide Go code examples:**  Illustrate how some of the key TLS features are used in the `bogoShim` function, including configuration and connection establishment.

6. **Discuss potential user errors:**  Based on the flags and functionality, identify common mistakes users might make when using this tool.这段代码是 Go 语言标准库 `crypto/tls` 包中的 `bogo_shim_test.go` 文件的一部分，它的主要功能是 **作为一个灵活的 TLS 客户端或服务器，用于与其他 TLS 实现进行互操作性测试**。它通过一系列命令行参数来配置 TLS 连接的各种细节，并能执行一些断言来验证连接状态和行为是否符合预期。

**功能列表:**

1. **作为 TLS 服务器或客户端:** 通过 `-server` 标志控制。
2. **指定监听或连接的端口:** 通过 `-port` 标志指定。
3. **支持测试握手器是否被支持:**  通过 `-is-handshaker-supported` 标志，但实际代码中只是简单打印 "No"。
4. **加载服务器证书和私钥:** 通过 `-key-file` 和 `-cert-file` 标志指定。
5. **信任特定的 CA 证书:** 通过 `-trust-cert` 标志指定。
6. **设置允许的 TLS 版本范围:** 通过 `-min-version` 和 `-max-version` 标志指定。还可以通过 `-no-tls1`, `-no-tls11`, `-no-tls12`, `-no-tls13` 更细粒度地禁用特定版本。
7. **期望连接使用的 TLS 版本:** 通过 `-expect-version` 标志指定。
8. **配置是否需要客户端证书:** 通过 `-require-any-client-certificate` 和 `-verify-peer` 标志指定。
9. **控制初始数据写入方:** 通过 `-shim-writes-first` 标志指定，决定在握手完成后谁先写入数据。
10. **控制会话恢复的次数:** 通过 `-resume-count` 标志指定。
11. **指定支持的椭圆曲线:** 通过 `-curves` 标志指定。
12. **期望协商的椭圆曲线:** 通过 `-expect-curve-id` 标志指定。
13. **发送一个 shim ID:** 通过 `-shim-id` 标志指定，并在连接建立后发送给对方。
14. **配置和验证加密客户端 Hello (ECH):**
    - 提供 ECH 配置列表：`-ech-config-list`
    - 期望 ECH 被接受：`-expect-ech-accept`
    - 期望服务器发送 HelloRetryRequest (HRR)：`-expect-hrr`
    - 期望服务器不发送 HRR：`-expect-no-hrr`
    - 期望特定的 ECH 重试配置：`-expect-ech-retry-configs`
    - 期望没有 ECH 重试配置：`-expect-no-ech-retry-configs`
    - 在初始连接和恢复连接时分别期望 ECH 被接受：`-on-initial-expect-ech-accept`, `-onResumeExpectECHAccepted`
    - 在恢复连接时提供 ECH 配置列表：`-on-resume-ech-config-list`
    - 期望在恢复连接时拒绝早期数据：`-on-resume-expect-reject-early-data`
    - 期望特定的服务器名称：`-expect-server-name`
    - 配置作为 ECH 服务器：`-ech-server-config`, `-ech-server-key`, `-ech-is-retry-config`
15. **期望会话未命中 (不恢复会话):** 通过 `-expect-session-miss` 标志指定。
16. **配置和验证应用层协议协商 (ALPN):**
    - 声明支持的 ALPN 协议：`-advertise-alpn`
    - 期望协商的 ALPN 协议：`-expect-alpn`
    - 拒绝 ALPN：`-reject-alpn`
    - 不提供 ALPN：`-decline-alpn`
    - 期望通告的 ALPN 协议：`-expect-advertised-alpn`
    - 选择特定的 ALPN 协议：`-select-alpn`
17. **设置服务器名称指示 (SNI):** 通过 `-host-name` 标志指定。
18. **控制恢复连接时的初始数据写入方:** 通过 `-onResumeShimWritesFirst` 标志指定。

**Go 语言功能实现示例:**

这段代码主要使用了 `crypto/tls` 包提供的 `Config` 结构体和 `Listen` 或 `Dial` 函数来创建 TLS 服务器或客户端。

**场景 1: 创建一个简单的 TLS 服务器**

**假设输入:**
- 命令行参数: `-server -port=8080 -cert-file=server.crt -key-file=server.key`
- `server.crt` 和 `server.key` 是有效的证书和私钥文件。

**Go 代码:**

```go
package main

import (
	"crypto/tls"
	"flag"
	"log"
	"net"
)

var (
	port     = flag.String("port", "", "监听端口")
	certFile = flag.String("cert-file", "", "证书文件路径")
	keyFile  = flag.String("key-file", "", "私钥文件路径")
	server   = flag.Bool("server", false, "是否作为服务器运行")
)

func main() {
	flag.Parse()

	if !*server {
		log.Fatal("请使用 -server 标志运行服务器")
		return
	}

	cert, err := tls.LoadX509KeyPair(*certFile, *keyFile)
	if err != nil {
		log.Fatalf("加载证书失败: %v", err)
	}

	config := &tls.Config{
		Certificates: []tls.Certificate{cert},
	}

	ln, err := net.Listen("tcp", ":"+*port)
	if err != nil {
		log.Fatalf("监听失败: %v", err)
	}
	defer ln.Close()

	log.Printf("服务器监听在端口 %s", *port)

	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Fatalf("接受连接失败: %v", err)
		}
		defer conn.Close()

		tlsConn := tls.Server(conn, config)
		go handleConnection(tlsConn)
	}
}

func handleConnection(conn *tls.Conn) {
	defer conn.Close()
	log.Println("接受了一个新的连接")
	// 处理连接逻辑
}
```

**预期输出:**  服务器开始监听在 8080 端口，并等待客户端连接。

**场景 2: 创建一个连接到 TLS 服务器的客户端**

**假设输入:**
- 命令行参数: `-port=8080 -host-name=example.com` (假设服务器在本地 8080 端口运行，并且期望的服务器名称是 example.com)

**Go 代码:**

```go
package main

import (
	"crypto/tls"
	"flag"
	"log"
	"net"
)

var (
	port     = flag.String("port", "", "服务器端口")
	hostName = flag.String("host-name", "", "服务器名称")
	server   = flag.Bool("server", false, "是否作为服务器运行")
)

func main() {
	flag.Parse()

	if *server {
		log.Fatal("请不要使用 -server 标志运行客户端")
		return
	}

	config := &tls.Config{
		InsecureSkipVerify: true, // 生产环境不建议这样做
		ServerName:         *hostName,
	}

	conn, err := net.Dial("tcp", "localhost:"+*port)
	if err != nil {
		log.Fatalf("连接失败: %v", err)
	}
	defer conn.Close()

	tlsConn := tls.Client(conn, config)
	defer tlsConn.Close()

	log.Println("成功连接到服务器")
	// 进行后续通信
}
```

**预期输出:** 客户端成功连接到运行在本地 8080 端口的 TLS 服务器。

**代码推理 (涉及假设的输入与输出):**

`bogoShim` 函数的核心逻辑在于根据命令行参数构建一个 `tls.Config` 结构体，然后根据 `-server` 标志决定是作为服务器监听连接还是作为客户端连接到指定的地址。

**假设输入 (作为客户端):**
- `-port=1234`
- `-expect-version=771` (TLS 1.2 的数值)

**代码片段:**

```go
	cfg := &Config{
		ServerName: "test", // 默认值

		MinVersion: uint16(*minVersion),
		MaxVersion: uint16(*maxVersion),

		ClientSessionCache: NewLRUClientSessionCache(0),

		// ... 其他配置 ...
	}

	if *expectVersion != 0 {
		// ... 在连接建立后检查版本 ...
		if cs.Version != uint16(*expectVersion) {
			log.Fatalf("expected ssl version %q, got %q", uint16(*expectVersion), cs.Version)
		}
	}

	conn, err := net.Dial("tcp", net.JoinHostPort("localhost", *port))
	// ... 错误处理 ...
	tlsConn := Client(conn, cfg)
	// ... 错误处理 ...
	cs := tlsConn.ConnectionState()
```

**推理:**  这段代码会创建一个 TLS 客户端连接到本地的 1234 端口。连接建立后，它会获取连接状态 `cs` 并检查 `cs.Version` 是否等于通过 `-expect-version` 传入的 771 (TLS 1.2)。

**预期输出:** 如果连接协商的 TLS 版本不是 TLS 1.2，程序会打印错误信息并退出，例如: `expected ssl version 771, got 770` (假设实际协商的是 TLS 1.1)。如果协商的版本是 TLS 1.2，则不会有 `log.Fatalf` 引起的错误。

**命令行参数的具体处理:**

代码开头使用 `flag` 包来处理命令行参数。例如：

```go
var (
	port   = flag.String("port", "", "")
	server = flag.Bool("server", false, "")
	// ... 其他参数 ...
)

func bogoShim() {
	flag.Parse() // 解析命令行参数

	if *server {
		// 作为服务器运行
	} else {
		// 作为客户端运行
	}

	// 使用 *port 获取端口号的值
	// 使用 *minVersion 获取最小 TLS 版本的值
	// ... 等等
}
```

`flag.String`, `flag.Bool`, `flag.Int` 等函数用于定义不同类型的命令行参数，并指定默认值和帮助信息 (这里大部分帮助信息为空字符串)。在 `bogoShim` 函数中调用 `flag.Parse()` 后，就可以通过解引用这些变量 (例如 `*port`) 来获取命令行传入的值。

**使用者易犯错的点:**

1. **证书和私钥路径错误:** 如果使用 `-cert-file` 和 `-key-file` 标志，但提供的路径指向不存在或不可访问的文件，会导致程序启动失败。

   **示例:** 运行命令 `go run bogo_shim_test.go -server -port=8080 -cert-file=nonexistent.crt -key-file=nonexistent.key` 将会因为无法加载证书而报错。

2. **端口被占用:**  如果作为服务器运行，但指定的端口已经被其他程序占用，会导致监听失败。

   **示例:** 如果另一个程序已经在监听 8080 端口，运行 `go run bogo_shim_test.go -server -port=8080` 将会报错，提示无法绑定地址。

3. **TLS 版本配置冲突:** 同时使用 `-min-version`, `-max-version` 和 `-no-tls1` 等标志可能会导致配置冲突，使得没有可用的 TLS 版本，从而导致连接失败。

   **示例:** 运行 `go run bogo_shim_test.go -min-version=771 -no-tls12` (假设 771 是 TLS 1.2 的值) 可能会导致没有交集，因为明确禁用了 TLS 1.2。

4. **ECH 配置错误:**  配置 ECH 相关的参数，例如 `-ech-config-list`, `-ech-server-config`, `-ech-server-key` 等，需要按照正确的格式进行 base64 编码。如果编码错误或参数不匹配，会导致握手失败。

   **示例:** `-ech-config-list` 的值必须是 base64 编码的 ECH 配置列表。如果提供了一个非法的 base64 字符串，程序会报错。

5. **ALPN 配置不匹配:**  如果客户端和服务器配置的 ALPN 协议不一致，并且没有共同支持的协议，握手后 `cs.NegotiatedProtocol` 将为空字符串，可能导致后续操作失败。

   **示例:** 客户端使用 `-advertise-alpn=\x02h2` (HTTP/2) 而服务器没有配置支持 HTTP/2，则协商的协议将为空。

这段代码的主要目标是提供一个高度可配置的 TLS 测试工具，因此理解这些命令行参数及其组合方式对于正确使用和调试 TLS 互操作性问题至关重要。

Prompt: 
```
这是路径为go/src/crypto/tls/bogo_shim_test.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。

"""
// Copyright 2024 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

import (
	"bytes"
	"crypto/internal/cryptotest"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"internal/byteorder"
	"internal/testenv"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/crypto/cryptobyte"
)

var (
	port   = flag.String("port", "", "")
	server = flag.Bool("server", false, "")

	isHandshakerSupported = flag.Bool("is-handshaker-supported", false, "")

	keyfile  = flag.String("key-file", "", "")
	certfile = flag.String("cert-file", "", "")

	trustCert = flag.String("trust-cert", "", "")

	minVersion    = flag.Int("min-version", VersionSSL30, "")
	maxVersion    = flag.Int("max-version", VersionTLS13, "")
	expectVersion = flag.Int("expect-version", 0, "")

	noTLS1  = flag.Bool("no-tls1", false, "")
	noTLS11 = flag.Bool("no-tls11", false, "")
	noTLS12 = flag.Bool("no-tls12", false, "")
	noTLS13 = flag.Bool("no-tls13", false, "")

	requireAnyClientCertificate = flag.Bool("require-any-client-certificate", false, "")

	shimWritesFirst = flag.Bool("shim-writes-first", false, "")

	resumeCount = flag.Int("resume-count", 0, "")

	curves        = flagStringSlice("curves", "")
	expectedCurve = flag.String("expect-curve-id", "", "")

	shimID = flag.Uint64("shim-id", 0, "")
	_      = flag.Bool("ipv6", false, "")

	echConfigListB64           = flag.String("ech-config-list", "", "")
	expectECHAccepted          = flag.Bool("expect-ech-accept", false, "")
	expectHRR                  = flag.Bool("expect-hrr", false, "")
	expectNoHRR                = flag.Bool("expect-no-hrr", false, "")
	expectedECHRetryConfigs    = flag.String("expect-ech-retry-configs", "", "")
	expectNoECHRetryConfigs    = flag.Bool("expect-no-ech-retry-configs", false, "")
	onInitialExpectECHAccepted = flag.Bool("on-initial-expect-ech-accept", false, "")
	_                          = flag.Bool("expect-no-ech-name-override", false, "")
	_                          = flag.String("expect-ech-name-override", "", "")
	_                          = flag.Bool("reverify-on-resume", false, "")
	onResumeECHConfigListB64   = flag.String("on-resume-ech-config-list", "", "")
	_                          = flag.Bool("on-resume-expect-reject-early-data", false, "")
	onResumeExpectECHAccepted  = flag.Bool("on-resume-expect-ech-accept", false, "")
	_                          = flag.Bool("on-resume-expect-no-ech-name-override", false, "")
	expectedServerName         = flag.String("expect-server-name", "", "")
	echServerConfig            = flagStringSlice("ech-server-config", "")
	echServerKey               = flagStringSlice("ech-server-key", "")
	echServerRetryConfig       = flagStringSlice("ech-is-retry-config", "")

	expectSessionMiss = flag.Bool("expect-session-miss", false, "")

	_                       = flag.Bool("enable-early-data", false, "")
	_                       = flag.Bool("on-resume-expect-accept-early-data", false, "")
	_                       = flag.Bool("expect-ticket-supports-early-data", false, "")
	onResumeShimWritesFirst = flag.Bool("on-resume-shim-writes-first", false, "")

	advertiseALPN        = flag.String("advertise-alpn", "", "")
	expectALPN           = flag.String("expect-alpn", "", "")
	rejectALPN           = flag.Bool("reject-alpn", false, "")
	declineALPN          = flag.Bool("decline-alpn", false, "")
	expectAdvertisedALPN = flag.String("expect-advertised-alpn", "", "")
	selectALPN           = flag.String("select-alpn", "", "")

	hostName = flag.String("host-name", "", "")

	verifyPeer = flag.Bool("verify-peer", false, "")
	_          = flag.Bool("use-custom-verify-callback", false, "")
)

type stringSlice []string

func flagStringSlice(name, usage string) *stringSlice {
	f := &stringSlice{}
	flag.Var(f, name, usage)
	return f
}

func (saf *stringSlice) String() string {
	return strings.Join(*saf, ",")
}

func (saf *stringSlice) Set(s string) error {
	*saf = append(*saf, s)
	return nil
}

func bogoShim() {
	if *isHandshakerSupported {
		fmt.Println("No")
		return
	}

	cfg := &Config{
		ServerName: "test",

		MinVersion: uint16(*minVersion),
		MaxVersion: uint16(*maxVersion),

		ClientSessionCache: NewLRUClientSessionCache(0),

		GetConfigForClient: func(chi *ClientHelloInfo) (*Config, error) {

			if *expectAdvertisedALPN != "" {

				s := cryptobyte.String(*expectAdvertisedALPN)

				var expectedALPNs []string

				for !s.Empty() {
					var alpn cryptobyte.String
					if !s.ReadUint8LengthPrefixed(&alpn) {
						return nil, fmt.Errorf("unexpected error while parsing arguments for -expect-advertised-alpn")
					}
					expectedALPNs = append(expectedALPNs, string(alpn))
				}

				if !slices.Equal(chi.SupportedProtos, expectedALPNs) {
					return nil, fmt.Errorf("unexpected ALPN: got %q, want %q", chi.SupportedProtos, expectedALPNs)
				}
			}
			return nil, nil
		},
	}

	if *noTLS1 {
		cfg.MinVersion = VersionTLS11
		if *noTLS11 {
			cfg.MinVersion = VersionTLS12
			if *noTLS12 {
				cfg.MinVersion = VersionTLS13
				if *noTLS13 {
					log.Fatalf("no supported versions enabled")
				}
			}
		}
	} else if *noTLS13 {
		cfg.MaxVersion = VersionTLS12
		if *noTLS12 {
			cfg.MaxVersion = VersionTLS11
			if *noTLS11 {
				cfg.MaxVersion = VersionTLS10
				if *noTLS1 {
					log.Fatalf("no supported versions enabled")
				}
			}
		}
	}

	if *advertiseALPN != "" {
		alpns := *advertiseALPN
		for len(alpns) > 0 {
			alpnLen := int(alpns[0])
			cfg.NextProtos = append(cfg.NextProtos, alpns[1:1+alpnLen])
			alpns = alpns[alpnLen+1:]
		}
	}

	if *rejectALPN {
		cfg.NextProtos = []string{"unnegotiableprotocol"}
	}

	if *declineALPN {
		cfg.NextProtos = []string{}
	}
	if *selectALPN != "" {
		cfg.NextProtos = []string{*selectALPN}
	}

	if *hostName != "" {
		cfg.ServerName = *hostName
	}

	if *keyfile != "" || *certfile != "" {
		pair, err := LoadX509KeyPair(*certfile, *keyfile)
		if err != nil {
			log.Fatalf("load key-file err: %s", err)
		}
		cfg.Certificates = []Certificate{pair}
	}
	if *trustCert != "" {
		pool := x509.NewCertPool()
		certFile, err := os.ReadFile(*trustCert)
		if err != nil {
			log.Fatalf("load trust-cert err: %s", err)
		}
		block, _ := pem.Decode(certFile)
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			log.Fatalf("parse trust-cert err: %s", err)
		}
		pool.AddCert(cert)
		cfg.RootCAs = pool
	}

	if *requireAnyClientCertificate {
		cfg.ClientAuth = RequireAnyClientCert
	}
	if *verifyPeer {
		cfg.ClientAuth = VerifyClientCertIfGiven
	}

	if *echConfigListB64 != "" {
		echConfigList, err := base64.StdEncoding.DecodeString(*echConfigListB64)
		if err != nil {
			log.Fatalf("parse ech-config-list err: %s", err)
		}
		cfg.EncryptedClientHelloConfigList = echConfigList
		cfg.MinVersion = VersionTLS13
	}

	if len(*curves) != 0 {
		for _, curveStr := range *curves {
			id, err := strconv.Atoi(curveStr)
			if err != nil {
				log.Fatalf("failed to parse curve id %q: %s", curveStr, err)
			}
			cfg.CurvePreferences = append(cfg.CurvePreferences, CurveID(id))
		}
	}

	if len(*echServerConfig) != 0 {
		if len(*echServerConfig) != len(*echServerKey) || len(*echServerConfig) != len(*echServerRetryConfig) {
			log.Fatal("-ech-server-config, -ech-server-key, and -ech-is-retry-config mismatch")
		}

		for i, c := range *echServerConfig {
			configBytes, err := base64.StdEncoding.DecodeString(c)
			if err != nil {
				log.Fatalf("parse ech-server-config err: %s", err)
			}
			privBytes, err := base64.StdEncoding.DecodeString((*echServerKey)[i])
			if err != nil {
				log.Fatalf("parse ech-server-key err: %s", err)
			}

			cfg.EncryptedClientHelloKeys = append(cfg.EncryptedClientHelloKeys, EncryptedClientHelloKey{
				Config:      configBytes,
				PrivateKey:  privBytes,
				SendAsRetry: (*echServerRetryConfig)[i] == "1",
			})
		}
	}

	for i := 0; i < *resumeCount+1; i++ {
		if i > 0 && (*onResumeECHConfigListB64 != "") {
			echConfigList, err := base64.StdEncoding.DecodeString(*onResumeECHConfigListB64)
			if err != nil {
				log.Fatalf("parse ech-config-list err: %s", err)
			}
			cfg.EncryptedClientHelloConfigList = echConfigList
		}

		conn, err := net.Dial("tcp", net.JoinHostPort("localhost", *port))
		if err != nil {
			log.Fatalf("dial err: %s", err)
		}
		defer conn.Close()

		// Write the shim ID we were passed as a little endian uint64
		shimIDBytes := make([]byte, 8)
		byteorder.LEPutUint64(shimIDBytes, *shimID)
		if _, err := conn.Write(shimIDBytes); err != nil {
			log.Fatalf("failed to write shim id: %s", err)
		}

		var tlsConn *Conn
		if *server {
			tlsConn = Server(conn, cfg)
		} else {
			tlsConn = Client(conn, cfg)
		}

		if i == 0 && *shimWritesFirst {
			if _, err := tlsConn.Write([]byte("hello")); err != nil {
				log.Fatalf("write err: %s", err)
			}
		}

		for {
			buf := make([]byte, 500)
			var n int
			n, err = tlsConn.Read(buf)
			if err != nil {
				break
			}
			buf = buf[:n]
			for i := range buf {
				buf[i] ^= 0xff
			}
			if _, err = tlsConn.Write(buf); err != nil {
				break
			}
		}
		if err != nil && err != io.EOF {
			retryErr, ok := err.(*ECHRejectionError)
			if !ok {
				log.Fatalf("unexpected error type returned: %v", err)
			}
			if *expectNoECHRetryConfigs && len(retryErr.RetryConfigList) > 0 {
				log.Fatalf("expected no ECH retry configs, got some")
			}
			if *expectedECHRetryConfigs != "" {
				expectedRetryConfigs, err := base64.StdEncoding.DecodeString(*expectedECHRetryConfigs)
				if err != nil {
					log.Fatalf("failed to decode expected retry configs: %s", err)
				}
				if !bytes.Equal(retryErr.RetryConfigList, expectedRetryConfigs) {
					log.Fatalf("unexpected retry list returned: got %x, want %x", retryErr.RetryConfigList, expectedRetryConfigs)
				}
			}
			log.Fatalf("conn error: %s", err)
		}

		cs := tlsConn.ConnectionState()
		if cs.HandshakeComplete {
			if *expectALPN != "" && cs.NegotiatedProtocol != *expectALPN {
				log.Fatalf("unexpected protocol negotiated: want %q, got %q", *expectALPN, cs.NegotiatedProtocol)
			}

			if *selectALPN != "" && cs.NegotiatedProtocol != *selectALPN {
				log.Fatalf("unexpected protocol negotiated: want %q, got %q", *selectALPN, cs.NegotiatedProtocol)
			}

			if *expectVersion != 0 && cs.Version != uint16(*expectVersion) {
				log.Fatalf("expected ssl version %q, got %q", uint16(*expectVersion), cs.Version)
			}
			if *declineALPN && cs.NegotiatedProtocol != "" {
				log.Fatal("unexpected ALPN protocol")
			}
			if *expectECHAccepted && !cs.ECHAccepted {
				log.Fatal("expected ECH to be accepted, but connection state shows it was not")
			} else if i == 0 && *onInitialExpectECHAccepted && !cs.ECHAccepted {
				log.Fatal("expected ECH to be accepted, but connection state shows it was not")
			} else if i > 0 && *onResumeExpectECHAccepted && !cs.ECHAccepted {
				log.Fatal("expected ECH to be accepted on resumption, but connection state shows it was not")
			} else if i == 0 && !*expectECHAccepted && cs.ECHAccepted {
				log.Fatal("did not expect ECH, but it was accepted")
			}

			if *expectHRR && !cs.testingOnlyDidHRR {
				log.Fatal("expected HRR but did not do it")
			}

			if *expectNoHRR && cs.testingOnlyDidHRR {
				log.Fatal("expected no HRR but did do it")
			}

			if *expectSessionMiss && cs.DidResume {
				log.Fatal("unexpected session resumption")
			}

			if *expectedServerName != "" && cs.ServerName != *expectedServerName {
				log.Fatalf("unexpected server name: got %q, want %q", cs.ServerName, *expectedServerName)
			}
		}

		if *expectedCurve != "" {
			expectedCurveID, err := strconv.Atoi(*expectedCurve)
			if err != nil {
				log.Fatalf("failed to parse -expect-curve-id: %s", err)
			}
			if tlsConn.curveID != CurveID(expectedCurveID) {
				log.Fatalf("unexpected curve id: want %d, got %d", expectedCurveID, tlsConn.curveID)
			}
		}
	}
}

func TestBogoSuite(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping in short mode")
	}
	if testenv.Builder() != "" && runtime.GOOS == "windows" {
		t.Skip("#66913: windows network connections are flakey on builders")
	}
	skipFIPS(t)

	// In order to make Go test caching work as expected, we stat the
	// bogo_config.json file, so that the Go testing hooks know that it is
	// important for this test and will invalidate a cached test result if the
	// file changes.
	if _, err := os.Stat("bogo_config.json"); err != nil {
		t.Fatal(err)
	}

	var bogoDir string
	if *bogoLocalDir != "" {
		bogoDir = *bogoLocalDir
	} else {
		const boringsslModVer = "v0.0.0-20241120195446-5cce3fbd23e1"
		bogoDir = cryptotest.FetchModule(t, "boringssl.googlesource.com/boringssl.git", boringsslModVer)
	}

	cwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}

	resultsFile := filepath.Join(t.TempDir(), "results.json")

	args := []string{
		"test",
		".",
		fmt.Sprintf("-shim-config=%s", filepath.Join(cwd, "bogo_config.json")),
		fmt.Sprintf("-shim-path=%s", os.Args[0]),
		"-shim-extra-flags=-bogo-mode",
		"-allow-unimplemented",
		"-loose-errors", // TODO(roland): this should be removed eventually
		fmt.Sprintf("-json-output=%s", resultsFile),
	}
	if *bogoFilter != "" {
		args = append(args, fmt.Sprintf("-test=%s", *bogoFilter))
	}

	cmd := testenv.Command(t, testenv.GoToolPath(t), args...)
	out := &strings.Builder{}
	cmd.Stderr = out
	cmd.Dir = filepath.Join(bogoDir, "ssl/test/runner")
	err = cmd.Run()
	// NOTE: we don't immediately check the error, because the failure could be either because
	// the runner failed for some unexpected reason, or because a test case failed, and we
	// cannot easily differentiate these cases. We check if the JSON results file was written,
	// which should only happen if the failure was because of a test failure, and use that
	// to determine the failure mode.

	resultsJSON, jsonErr := os.ReadFile(resultsFile)
	if jsonErr != nil {
		if err != nil {
			t.Fatalf("bogo failed: %s\n%s", err, out)
		}
		t.Fatalf("failed to read results JSON file: %s", jsonErr)
	}

	var results bogoResults
	if err := json.Unmarshal(resultsJSON, &results); err != nil {
		t.Fatalf("failed to parse results JSON: %s", err)
	}

	// assertResults contains test results we want to make sure
	// are present in the output. They are only checked if -bogo-filter
	// was not passed.
	assertResults := map[string]string{
		"CurveTest-Client-MLKEM-TLS13": "PASS",
		"CurveTest-Server-MLKEM-TLS13": "PASS",
	}

	for name, result := range results.Tests {
		// This is not really the intended way to do this... but... it works?
		t.Run(name, func(t *testing.T) {
			if result.Actual == "FAIL" && result.IsUnexpected {
				t.Fatal(result.Error)
			}
			if expectedResult, ok := assertResults[name]; ok && expectedResult != result.Actual {
				t.Fatalf("unexpected result: got %s, want %s", result.Actual, assertResults[name])
			}
			delete(assertResults, name)
			if result.Actual == "SKIP" {
				t.Skip()
			}
		})
	}
	if *bogoFilter == "" {
		// Anything still in assertResults did not show up in the results, so we should fail
		for name, expectedResult := range assertResults {
			t.Run(name, func(t *testing.T) {
				t.Fatalf("expected test to run with result %s, but it was not present in the test results", expectedResult)
			})
		}
	}
}

// bogoResults is a copy of boringssl.googlesource.com/boringssl/testresults.Results
type bogoResults struct {
	Version           int            `json:"version"`
	Interrupted       bool           `json:"interrupted"`
	PathDelimiter     string         `json:"path_delimiter"`
	SecondsSinceEpoch float64        `json:"seconds_since_epoch"`
	NumFailuresByType map[string]int `json:"num_failures_by_type"`
	Tests             map[string]struct {
		Actual       string `json:"actual"`
		Expected     string `json:"expected"`
		IsUnexpected bool   `json:"is_unexpected"`
		Error        string `json:"error,omitempty"`
	} `json:"tests"`
}

"""



```