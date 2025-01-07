Response:
Let's break down the thought process for analyzing this Go code snippet.

**1. Understanding the Goal:**

The core request is to understand the *functionality* of the provided Go code, which is part of `handshake_client_test.go` in the `crypto/tls` package. The request specifically asks for the overall purpose, example usage, potential pitfalls, and a summary.

**2. Initial Code Scan and Keyword Spotting:**

I'd start by quickly scanning the code for prominent keywords and structures. This gives a high-level overview:

* **Package `tls`:**  Indicates this code is about TLS/SSL.
* **`import` statements:**  Reveals dependencies like `crypto/*`, `net`, `os/exec`, `testing`, `time`, etc. This suggests interactions with cryptography, network connections, external processes, and testing frameworks.
* **`// Copyright` and license:** Standard Go boilerplate.
* **`// Note: see comment in handshake_test.go...`:** Hints at integration with other test files.
* **`opensslInputEvent`, `opensslInput`:**  Suggests a way to interact with an `openssl` process.
* **`opensslOutputSink`:** Likely a way to capture output from the `openssl` process.
* **`clientTest` struct:** This is a crucial data structure that defines a test case. Its fields (like `name`, `args`, `config`, `cert`, `key`, `validate`, `numRenegotiations`, etc.) provide valuable clues about the testing scenarios.
* **`serverCommand`:**  Confirms the use of `openssl s_server` as a reference implementation.
* **`connFromCommand()`:**  This function is key! It clearly starts an `openssl` server and establishes a connection.
* **`run()` method:**  This is the heart of the test execution logic. It handles setting up connections (either real via `connFromCommand` or replaying from saved data), configuring the TLS client, and performing actions like writing and reading.
* **Numerous `TestHandshakeClient...` functions:**  These are individual test cases targeting specific cipher suites, key types, and TLS versions.
* **`TestResumption()`:** Focuses on testing session resumption.
* **`serializingClientCache`, `LRUClientSessionCache`:**  Indicates testing of client-side session caching.

**3. Focusing on Key Structures and Functions:**

After the initial scan, I'd zoom in on the most important elements:

* **`clientTest` struct:** I'd analyze each field to understand what aspects of the TLS client handshake are being tested. For instance:
    * `name`:  Test identification.
    * `args`: Command-line arguments for `openssl s_server`, controlling its behavior.
    * `config`: Custom TLS client configurations.
    * `cert`, `key`: Server certificates and keys.
    * `extensions`:  Testing TLS extensions.
    * `validate`: Custom verification of the connection state.
    * `numRenegotiations`, `renegotiationExpectedToFail`: Testing renegotiation scenarios.
    * `sendKeyUpdate`: Testing the Key Update mechanism.
* **`connFromCommand()`:** I'd trace the steps:
    1. Prepare server certificate and key files.
    2. Construct the `openssl s_server` command with specific arguments.
    3. Start the `openssl` process.
    4. Establish a TCP connection to the `openssl` server.
    5. Wrap the TCP connection in a `recordingConn` (presumably to capture the TLS handshake).
* **`run()`:** I'd follow the execution flow:
    1. Decide whether to run against a live `openssl` server (`write = true`) or replay saved data.
    2. Create a TLS client using `tls.Client()`.
    3. Perform basic communication (`client.Write`).
    4. Handle renegotiation scenarios (if specified).
    5. Handle Key Update scenarios (if specified).
    6. Call the `validate` function.
    7. If in `write` mode, save the captured TLS handshake data.

**4. Inferring Functionality and Providing Examples:**

Based on the code and the keywords, I could start inferring the functionality. For example:

* The code tests the TLS client handshake by running it against an `openssl s_server` instance.
* It supports testing various TLS versions, cipher suites, key exchange methods, and client authentication.
* The `clientTest` struct allows for defining a wide range of test scenarios.
* The `recordingConn` and replaying mechanism facilitate capturing and replaying TLS handshakes for consistent testing.
* Features like renegotiation and Key Update are explicitly tested.

To provide Go code examples, I'd focus on how the `tls.Client` function is used and how the `clientTest` struct is structured:

```go
// Example of using tls.Client
conn, err := net.Dial("tcp", "example.com:443")
if err != nil {
  // Handle error
}
defer conn.Close()

config := &tls.Config{
  InsecureSkipVerify: true, // For demonstration purposes, don't do this in production
}

clientConn := tls.Client(conn, config)
defer clientConn.Close()

err = clientConn.Handshake()
if err != nil {
  // Handle handshake error
}

// Example of a basic clientTest
test := &clientTest{
  name: "BasicTLS13Handshake",
  args: []string{"-tls1_3"},
}
```

**5. Identifying Potential Pitfalls and Command-Line Arguments:**

* **Pitfalls:** The heavy reliance on `openssl` and file system interactions (temporary files) are potential points of failure if the environment isn't set up correctly. Also, discrepancies between the Go TLS implementation and `openssl` might lead to unexpected test failures. The logic around renegotiation and Key Update, involving channels and goroutines, could be tricky.
* **Command-Line Arguments:** I'd look at how the `test.args` field is used to construct the `openssl s_server` command. The comments and the structure of the test cases provide clues about the meaning of flags like `-tls1_3`, `-cipher`, `-ciphersuites`, `-Verify`, etc.

**6. Structuring the Answer:**

Finally, I'd organize the information into the requested sections:

* **功能归纳:** Start with a concise summary of the overall purpose.
* **Go语言功能实现:**  Provide concrete Go code examples demonstrating the use of relevant `tls` package functions.
* **代码推理 (with assumptions):** Illustrate how the test framework works by showing the setup and execution of a test case, including assumptions about input and output.
* **命令行参数:** Detail the command-line arguments used for `openssl s_server` and their effects.
* **使用者易犯错的点:**  Highlight potential issues and common mistakes when using or extending this testing framework.

**Self-Correction/Refinement During the Process:**

* **Initial thought:** "This is just testing the TLS client."
* **Correction:** "It's more than that. It's using `openssl` as a reference and has a framework for capturing and replaying handshakes, which is quite sophisticated for testing."
* **Initial thought about examples:** "Just show `tls.Dial`."
* **Refinement:** "No, `tls.Client` is more relevant here, given the context of the code. And illustrating the structure of `clientTest` is crucial for understanding how tests are defined."
* **Realization about pitfalls:**  "It's not just about Go code. The external dependency on `openssl` is a significant point."

By following this systematic approach, combining code analysis, keyword spotting, logical inference, and some trial-and-error in understanding the flow, I can arrive at a comprehensive and accurate answer like the example provided in the initial prompt.
好的，让我们来分析一下这段 Go 语言代码的功能。

**功能归纳**

这段代码是 Go 语言 `crypto/tls` 包中 `handshake_client_test.go` 文件的一部分，其主要功能是：

1. **测试 TLS 客户端握手过程:** 它通过启动一个参考 TLS 服务器（使用 OpenSSL 的 `s_server` 命令），然后创建一个 Go TLS 客户端与该服务器进行握手，以此来测试 Go 语言 TLS 客户端的实现是否正确。
2. **支持多种测试场景:**  通过 `clientTest` 结构体定义了各种不同的测试场景，包括不同的 TLS 版本（TLS 1.0, 1.1, 1.2, 1.3）、不同的密码套件、不同的密钥类型（RSA, ECDSA, EdDSA）、客户端证书认证、会话恢复 (resumption)、密钥更新 (KeyUpdate) 等。
3. **记录和回放握手过程:**  为了实现可重复的测试，代码可以记录与 OpenSSL 服务器交互的数据流，并将这些数据保存到文件中。在后续的测试中，可以不启动 OpenSSL 服务器，而是直接回放之前记录的数据流来测试客户端的行为。
4. **验证连接状态:**  测试用例可以定义一个 `validate` 函数，用于检查握手完成后连接的状态是否符合预期。
5. **模拟 OpenSSL 服务器的行为:**  通过 `opensslInput` 和 `opensslOutputSink` 类型，代码可以向 OpenSSL 服务器发送指令（例如，请求重新协商、发送数据、请求密钥更新）并解析 OpenSSL 服务器的输出，以判断握手是否成功以及服务器的行为是否符合预期。

**Go 语言功能实现举例**

这段代码主要测试的是 `crypto/tls` 包中 `Client` 函数的用法以及 `Config` 结构体的配置。

```go
package main

import (
	"crypto/tls"
	"fmt"
	"net"
)

func main() {
	// 假设我们已经有了一个 TCP 连接 conn
	conn, err := net.Dial("tcp", "example.com:443")
	if err != nil {
		fmt.Println("连接失败:", err)
		return
	}
	defer conn.Close()

	// 配置 TLS 客户端
	config := &tls.Config{
		InsecureSkipVerify: true, // 注意：在生产环境中不要这样做
	}

	// 创建 TLS 客户端连接
	clientConn := tls.Client(conn, config)
	defer clientConn.Close()

	// 进行 TLS 握手
	err = clientConn.Handshake()
	if err != nil {
		fmt.Println("TLS 握手失败:", err)
		return
	}

	fmt.Println("TLS 握手成功!")

	// 可以开始进行安全的通信了
}
```

**假设的输入与输出 (基于代码推理)**

假设我们正在运行一个名为 `TestHandshakeClientRSARC4` 的测试用例，该用例旨在测试使用 RSA 和 RC4-SHA 密码套件的 TLS 客户端握手。

**输入 (模拟 `run` 函数的执行):**

1. **`write` 为 `true`:** 表示要启动 OpenSSL 服务器并记录握手过程。
2. **`test.name`:** "RSA-RC4"
3. **`test.args`:** `[]string{"-cipher", "RC4-SHA"}`
4. **`testConfig`:** 一个默认的 TLS 客户端配置。
5. **`testRSACertificate` 和 `testRSAPrivateKey`:**  预定义的 RSA 服务器证书和私钥。

**OpenSSL 服务器的命令行:**

```bash
openssl s_server -no_ticket -num_tickets 0 -tls1 -cipher RC4-SHA -cert <临时证书路径> -certform DER -key <临时私钥路径> -accept 24323
```

**输出 (预期):**

1. **OpenSSL 服务器启动成功，监听在 24323 端口。**
2. **Go TLS 客户端连接到 OpenSSL 服务器。**
3. **Go TLS 客户端和 OpenSSL 服务器之间成功完成 TLS 握手，使用的密码套件是 RC4-SHA。**
4. **如果 `write` 为 `true`，握手过程中客户端和服务器之间的数据流会被记录到 `testdata/Client-TLSv10-RSA-RC4` (假设是 TLS 1.0 测试) 文件中。**
5. **`stdout` 的 `handshakeComplete` 通道会收到一个信号，表明 OpenSSL 服务器已完成握手。**

**命令行参数的具体处理**

在 `connFromCommand` 函数中，`clientTest` 结构体的 `args` 字段会被用来构建 OpenSSL `s_server` 命令的参数。例如：

* **`-cipher <密码套件>`:**  指定 OpenSSL 服务器使用的密码套件，例如 "RC4-SHA", "AES128-GCM-SHA256" 等。
* **`-tls1`, `-tls1_1`, `-tls1_2`, `-tls1_3`:** 指定 OpenSSL 服务器支持的 TLS 版本。
* **`-cert <证书路径>` 和 `-key <私钥路径>`:**  指定 OpenSSL 服务器使用的证书和私钥文件。
* **`-certform DER`:**  指定证书格式为 DER 编码。
* **`-accept <端口号>`:** 指定 OpenSSL 服务器监听的端口号。
* **`-state`:**  使 OpenSSL 服务器在标准输出中打印握手状态信息，这对于测试重新协商和密钥更新非常重要。
* **`-serverinfo <文件路径>`:** 指定包含服务器扩展信息的文件。
* **`-no_ticket`, `-num_tickets 0`:**  禁用会话票据。
* **`-ciphersuites <密码套件列表>`:**  用于 TLS 1.3，指定支持的密码套件列表。
* **`-curves <曲线列表>`:** 指定支持的椭圆曲线列表。
* **`-Verify <级别>`:**  启用客户端证书验证。
* **`-client_sigalgs <签名算法列表>`, `-sigalgs <签名算法列表>`:** 指定客户端和服务器支持的签名算法。

**使用者易犯错的点**

1. **忘记启动 OpenSSL 服务器:**  如果 `write` 为 `false`，代码会尝试加载预先记录的握手数据。如果文件不存在或数据不正确，测试将会失败。如果 `write` 为 `true`，则需要确保机器上安装了 OpenSSL，并且 `s_server` 命令可以正常执行。
2. **OpenSSL 版本不兼容:** 不同版本的 OpenSSL 的行为可能略有不同，可能导致测试结果不一致。
3. **端口冲突:**  代码中硬编码了 OpenSSL 服务器监听的端口号 (24323)。如果该端口被占用，测试将会失败。
4. **依赖外部环境:** 测试依赖于文件系统（用于存储证书、密钥和记录的数据）和外部命令 (OpenSSL)。确保测试环境配置正确。
5. **证书和密钥配置错误:**  如果提供的证书或密钥文件格式不正确或者与预期的算法不匹配，握手将会失败。例如，使用 ECDSA 的密码套件时，需要提供 ECDSA 的证书和私钥。
6. **测试用例数据过时:** 如果修改了 Go TLS 客户端的实现，可能需要更新 `testdata` 目录下的记录数据，否则基于旧数据的回放测试可能会失败。

总而言之，这段代码是一个强大的 TLS 客户端测试框架，它通过与 OpenSSL 服务器进行交互，并结合记录和回放机制，能够全面地测试 Go 语言 TLS 客户端的各种功能和场景。理解 `clientTest` 结构体和 `run` 函数的工作流程是理解这段代码的关键。

Prompt: 
```
这是路径为go/src/crypto/tls/handshake_client_test.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第1部分，共3部分，请归纳一下它的功能

"""
// Copyright 2010 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls/internal/fips140tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"internal/byteorder"
	"io"
	"math/big"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"
)

// Note: see comment in handshake_test.go for details of how the reference
// tests work.

// opensslInputEvent enumerates possible inputs that can be sent to an `openssl
// s_client` process.
type opensslInputEvent int

const (
	// opensslRenegotiate causes OpenSSL to request a renegotiation of the
	// connection.
	opensslRenegotiate opensslInputEvent = iota

	// opensslSendBanner causes OpenSSL to send the contents of
	// opensslSentinel on the connection.
	opensslSendSentinel

	// opensslKeyUpdate causes OpenSSL to send a key update message to the
	// client and request one back.
	opensslKeyUpdate
)

const opensslSentinel = "SENTINEL\n"

type opensslInput chan opensslInputEvent

func (i opensslInput) Read(buf []byte) (n int, err error) {
	for event := range i {
		switch event {
		case opensslRenegotiate:
			return copy(buf, []byte("R\n")), nil
		case opensslKeyUpdate:
			return copy(buf, []byte("K\n")), nil
		case opensslSendSentinel:
			return copy(buf, []byte(opensslSentinel)), nil
		default:
			panic("unknown event")
		}
	}

	return 0, io.EOF
}

// opensslOutputSink is an io.Writer that receives the stdout and stderr from an
// `openssl` process and sends a value to handshakeComplete or readKeyUpdate
// when certain messages are seen.
type opensslOutputSink struct {
	handshakeComplete chan struct{}
	readKeyUpdate     chan struct{}
	all               []byte
	line              []byte
}

func newOpensslOutputSink() *opensslOutputSink {
	return &opensslOutputSink{make(chan struct{}), make(chan struct{}), nil, nil}
}

// opensslEndOfHandshake is a message that the “openssl s_server” tool will
// print when a handshake completes if run with “-state”.
const opensslEndOfHandshake = "SSL_accept:SSLv3/TLS write finished"

// opensslReadKeyUpdate is a message that the “openssl s_server” tool will
// print when a KeyUpdate message is received if run with “-state”.
const opensslReadKeyUpdate = "SSL_accept:TLSv1.3 read client key update"

func (o *opensslOutputSink) Write(data []byte) (n int, err error) {
	o.line = append(o.line, data...)
	o.all = append(o.all, data...)

	for {
		line, next, ok := bytes.Cut(o.line, []byte("\n"))
		if !ok {
			break
		}

		if bytes.Equal([]byte(opensslEndOfHandshake), line) {
			o.handshakeComplete <- struct{}{}
		}
		if bytes.Equal([]byte(opensslReadKeyUpdate), line) {
			o.readKeyUpdate <- struct{}{}
		}
		o.line = next
	}

	return len(data), nil
}

func (o *opensslOutputSink) String() string {
	return string(o.all)
}

// clientTest represents a test of the TLS client handshake against a reference
// implementation.
type clientTest struct {
	// name is a freeform string identifying the test and the file in which
	// the expected results will be stored.
	name string
	// args, if not empty, contains a series of arguments for the
	// command to run for the reference server.
	args []string
	// config, if not nil, contains a custom Config to use for this test.
	config *Config
	// cert, if not empty, contains a DER-encoded certificate for the
	// reference server.
	cert []byte
	// key, if not nil, contains either a *rsa.PrivateKey, ed25519.PrivateKey or
	// *ecdsa.PrivateKey which is the private key for the reference server.
	key any
	// extensions, if not nil, contains a list of extension data to be returned
	// from the ServerHello. The data should be in standard TLS format with
	// a 2-byte uint16 type, 2-byte data length, followed by the extension data.
	extensions [][]byte
	// validate, if not nil, is a function that will be called with the
	// ConnectionState of the resulting connection. It returns a non-nil
	// error if the ConnectionState is unacceptable.
	validate func(ConnectionState) error
	// numRenegotiations is the number of times that the connection will be
	// renegotiated.
	numRenegotiations int
	// renegotiationExpectedToFail, if not zero, is the number of the
	// renegotiation attempt that is expected to fail.
	renegotiationExpectedToFail int
	// checkRenegotiationError, if not nil, is called with any error
	// arising from renegotiation. It can map expected errors to nil to
	// ignore them.
	checkRenegotiationError func(renegotiationNum int, err error) error
	// sendKeyUpdate will cause the server to send a KeyUpdate message.
	sendKeyUpdate bool
}

var serverCommand = []string{"openssl", "s_server", "-no_ticket", "-num_tickets", "0"}

// connFromCommand starts the reference server process, connects to it and
// returns a recordingConn for the connection. The stdin return value is an
// opensslInput for the stdin of the child process. It must be closed before
// Waiting for child.
func (test *clientTest) connFromCommand() (conn *recordingConn, child *exec.Cmd, stdin opensslInput, stdout *opensslOutputSink, err error) {
	cert := testRSACertificate
	if len(test.cert) > 0 {
		cert = test.cert
	}
	certPath := tempFile(string(cert))
	defer os.Remove(certPath)

	var key any = testRSAPrivateKey
	if test.key != nil {
		key = test.key
	}
	derBytes, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		panic(err)
	}

	var pemOut bytes.Buffer
	pem.Encode(&pemOut, &pem.Block{Type: "PRIVATE KEY", Bytes: derBytes})

	keyPath := tempFile(pemOut.String())
	defer os.Remove(keyPath)

	var command []string
	command = append(command, serverCommand...)
	command = append(command, test.args...)
	command = append(command, "-cert", certPath, "-certform", "DER", "-key", keyPath)
	// serverPort contains the port that OpenSSL will listen on. OpenSSL
	// can't take "0" as an argument here so we have to pick a number and
	// hope that it's not in use on the machine. Since this only occurs
	// when -update is given and thus when there's a human watching the
	// test, this isn't too bad.
	const serverPort = 24323
	command = append(command, "-accept", strconv.Itoa(serverPort))

	if len(test.extensions) > 0 {
		var serverInfo bytes.Buffer
		for _, ext := range test.extensions {
			pem.Encode(&serverInfo, &pem.Block{
				Type:  fmt.Sprintf("SERVERINFO FOR EXTENSION %d", byteorder.BEUint16(ext)),
				Bytes: ext,
			})
		}
		serverInfoPath := tempFile(serverInfo.String())
		defer os.Remove(serverInfoPath)
		command = append(command, "-serverinfo", serverInfoPath)
	}

	if test.numRenegotiations > 0 || test.sendKeyUpdate {
		found := false
		for _, flag := range command[1:] {
			if flag == "-state" {
				found = true
				break
			}
		}

		if !found {
			panic("-state flag missing to OpenSSL, you need this if testing renegotiation or KeyUpdate")
		}
	}

	cmd := exec.Command(command[0], command[1:]...)
	stdin = opensslInput(make(chan opensslInputEvent))
	cmd.Stdin = stdin
	out := newOpensslOutputSink()
	cmd.Stdout = out
	cmd.Stderr = out
	if err := cmd.Start(); err != nil {
		return nil, nil, nil, nil, err
	}

	// OpenSSL does print an "ACCEPT" banner, but it does so *before*
	// opening the listening socket, so we can't use that to wait until it
	// has started listening. Thus we are forced to poll until we get a
	// connection.
	var tcpConn net.Conn
	for i := uint(0); i < 5; i++ {
		tcpConn, err = net.DialTCP("tcp", nil, &net.TCPAddr{
			IP:   net.IPv4(127, 0, 0, 1),
			Port: serverPort,
		})
		if err == nil {
			break
		}
		time.Sleep((1 << i) * 5 * time.Millisecond)
	}
	if err != nil {
		close(stdin)
		cmd.Process.Kill()
		err = fmt.Errorf("error connecting to the OpenSSL server: %v (%v)\n\n%s", err, cmd.Wait(), out)
		return nil, nil, nil, nil, err
	}

	record := &recordingConn{
		Conn: tcpConn,
	}

	return record, cmd, stdin, out, nil
}

func (test *clientTest) dataPath() string {
	return filepath.Join("testdata", "Client-"+test.name)
}

func (test *clientTest) loadData() (flows [][]byte, err error) {
	in, err := os.Open(test.dataPath())
	if err != nil {
		return nil, err
	}
	defer in.Close()
	return parseTestData(in)
}

func (test *clientTest) run(t *testing.T, write bool) {
	var clientConn net.Conn
	var recordingConn *recordingConn
	var childProcess *exec.Cmd
	var stdin opensslInput
	var stdout *opensslOutputSink

	if write {
		var err error
		recordingConn, childProcess, stdin, stdout, err = test.connFromCommand()
		if err != nil {
			t.Fatalf("Failed to start subcommand: %s", err)
		}
		clientConn = recordingConn
		defer func() {
			if t.Failed() {
				t.Logf("OpenSSL output:\n\n%s", stdout.all)
			}
		}()
	} else {
		flows, err := test.loadData()
		if err != nil {
			t.Fatalf("failed to load data from %s: %v", test.dataPath(), err)
		}
		clientConn = &replayingConn{t: t, flows: flows, reading: false}
	}

	config := test.config
	if config == nil {
		config = testConfig
	}
	client := Client(clientConn, config)
	defer client.Close()

	if _, err := client.Write([]byte("hello\n")); err != nil {
		t.Errorf("Client.Write failed: %s", err)
		return
	}

	for i := 1; i <= test.numRenegotiations; i++ {
		// The initial handshake will generate a
		// handshakeComplete signal which needs to be quashed.
		if i == 1 && write {
			<-stdout.handshakeComplete
		}

		// OpenSSL will try to interleave application data and
		// a renegotiation if we send both concurrently.
		// Therefore: ask OpensSSL to start a renegotiation, run
		// a goroutine to call client.Read and thus process the
		// renegotiation request, watch for OpenSSL's stdout to
		// indicate that the handshake is complete and,
		// finally, have OpenSSL write something to cause
		// client.Read to complete.
		if write {
			stdin <- opensslRenegotiate
		}

		signalChan := make(chan struct{})

		go func() {
			defer close(signalChan)

			buf := make([]byte, 256)
			n, err := client.Read(buf)

			if test.checkRenegotiationError != nil {
				newErr := test.checkRenegotiationError(i, err)
				if err != nil && newErr == nil {
					return
				}
				err = newErr
			}

			if err != nil {
				t.Errorf("Client.Read failed after renegotiation #%d: %s", i, err)
				return
			}

			buf = buf[:n]
			if !bytes.Equal([]byte(opensslSentinel), buf) {
				t.Errorf("Client.Read returned %q, but wanted %q", string(buf), opensslSentinel)
			}

			if expected := i + 1; client.handshakes != expected {
				t.Errorf("client should have recorded %d handshakes, but believes that %d have occurred", expected, client.handshakes)
			}
		}()

		if write && test.renegotiationExpectedToFail != i {
			<-stdout.handshakeComplete
			stdin <- opensslSendSentinel
		}
		<-signalChan
	}

	if test.sendKeyUpdate {
		if write {
			<-stdout.handshakeComplete
			stdin <- opensslKeyUpdate
		}

		doneRead := make(chan struct{})

		go func() {
			defer close(doneRead)

			buf := make([]byte, 256)
			n, err := client.Read(buf)

			if err != nil {
				t.Errorf("Client.Read failed after KeyUpdate: %s", err)
				return
			}

			buf = buf[:n]
			if !bytes.Equal([]byte(opensslSentinel), buf) {
				t.Errorf("Client.Read returned %q, but wanted %q", string(buf), opensslSentinel)
			}
		}()

		if write {
			// There's no real reason to wait for the client KeyUpdate to
			// send data with the new server keys, except that s_server
			// drops writes if they are sent at the wrong time.
			<-stdout.readKeyUpdate
			stdin <- opensslSendSentinel
		}
		<-doneRead

		if _, err := client.Write([]byte("hello again\n")); err != nil {
			t.Errorf("Client.Write failed: %s", err)
			return
		}
	}

	if test.validate != nil {
		if err := test.validate(client.ConnectionState()); err != nil {
			t.Errorf("validate callback returned error: %s", err)
		}
	}

	// If the server sent us an alert after our last flight, give it a
	// chance to arrive.
	if write && test.renegotiationExpectedToFail == 0 {
		if err := peekError(client); err != nil {
			t.Errorf("final Read returned an error: %s", err)
		}
	}

	if write {
		client.Close()
		path := test.dataPath()
		out, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
		if err != nil {
			t.Fatalf("Failed to create output file: %s", err)
		}
		defer out.Close()
		recordingConn.Close()
		close(stdin)
		childProcess.Process.Kill()
		childProcess.Wait()
		if len(recordingConn.flows) < 3 {
			t.Fatalf("Client connection didn't work")
		}
		recordingConn.WriteTo(out)
		t.Logf("Wrote %s\n", path)
	}
}

// peekError does a read with a short timeout to check if the next read would
// cause an error, for example if there is an alert waiting on the wire.
func peekError(conn net.Conn) error {
	conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
	if n, err := conn.Read(make([]byte, 1)); n != 0 {
		return errors.New("unexpectedly read data")
	} else if err != nil {
		if netErr, ok := err.(net.Error); !ok || !netErr.Timeout() {
			return err
		}
	}
	return nil
}

func runClientTestForVersion(t *testing.T, template *clientTest, version, option string) {
	// Make a deep copy of the template before going parallel.
	test := *template
	if template.config != nil {
		test.config = template.config.Clone()
	}
	test.name = version + "-" + test.name
	test.args = append([]string{option}, test.args...)

	runTestAndUpdateIfNeeded(t, version, test.run, false)
}

func runClientTestTLS10(t *testing.T, template *clientTest) {
	runClientTestForVersion(t, template, "TLSv10", "-tls1")
}

func runClientTestTLS11(t *testing.T, template *clientTest) {
	runClientTestForVersion(t, template, "TLSv11", "-tls1_1")
}

func runClientTestTLS12(t *testing.T, template *clientTest) {
	runClientTestForVersion(t, template, "TLSv12", "-tls1_2")
}

func runClientTestTLS13(t *testing.T, template *clientTest) {
	runClientTestForVersion(t, template, "TLSv13", "-tls1_3")
}

func TestHandshakeClientRSARC4(t *testing.T) {
	test := &clientTest{
		name: "RSA-RC4",
		args: []string{"-cipher", "RC4-SHA"},
	}
	runClientTestTLS10(t, test)
	runClientTestTLS11(t, test)
	runClientTestTLS12(t, test)
}

func TestHandshakeClientRSAAES128GCM(t *testing.T) {
	test := &clientTest{
		name: "AES128-GCM-SHA256",
		args: []string{"-cipher", "AES128-GCM-SHA256"},
	}
	runClientTestTLS12(t, test)
}

func TestHandshakeClientRSAAES256GCM(t *testing.T) {
	test := &clientTest{
		name: "AES256-GCM-SHA384",
		args: []string{"-cipher", "AES256-GCM-SHA384"},
	}
	runClientTestTLS12(t, test)
}

func TestHandshakeClientECDHERSAAES(t *testing.T) {
	test := &clientTest{
		name: "ECDHE-RSA-AES",
		args: []string{"-cipher", "ECDHE-RSA-AES128-SHA"},
	}
	runClientTestTLS10(t, test)
	runClientTestTLS11(t, test)
	runClientTestTLS12(t, test)
}

func TestHandshakeClientECDHEECDSAAES(t *testing.T) {
	test := &clientTest{
		name: "ECDHE-ECDSA-AES",
		args: []string{"-cipher", "ECDHE-ECDSA-AES128-SHA"},
		cert: testECDSACertificate,
		key:  testECDSAPrivateKey,
	}
	runClientTestTLS10(t, test)
	runClientTestTLS11(t, test)
	runClientTestTLS12(t, test)
}

func TestHandshakeClientECDHEECDSAAESGCM(t *testing.T) {
	test := &clientTest{
		name: "ECDHE-ECDSA-AES-GCM",
		args: []string{"-cipher", "ECDHE-ECDSA-AES128-GCM-SHA256"},
		cert: testECDSACertificate,
		key:  testECDSAPrivateKey,
	}
	runClientTestTLS12(t, test)
}

func TestHandshakeClientAES256GCMSHA384(t *testing.T) {
	test := &clientTest{
		name: "ECDHE-ECDSA-AES256-GCM-SHA384",
		args: []string{"-cipher", "ECDHE-ECDSA-AES256-GCM-SHA384"},
		cert: testECDSACertificate,
		key:  testECDSAPrivateKey,
	}
	runClientTestTLS12(t, test)
}

func TestHandshakeClientAES128CBCSHA256(t *testing.T) {
	test := &clientTest{
		name: "AES128-SHA256",
		args: []string{"-cipher", "AES128-SHA256"},
	}
	runClientTestTLS12(t, test)
}

func TestHandshakeClientECDHERSAAES128CBCSHA256(t *testing.T) {
	test := &clientTest{
		name: "ECDHE-RSA-AES128-SHA256",
		args: []string{"-cipher", "ECDHE-RSA-AES128-SHA256"},
	}
	runClientTestTLS12(t, test)
}

func TestHandshakeClientECDHEECDSAAES128CBCSHA256(t *testing.T) {
	test := &clientTest{
		name: "ECDHE-ECDSA-AES128-SHA256",
		args: []string{"-cipher", "ECDHE-ECDSA-AES128-SHA256"},
		cert: testECDSACertificate,
		key:  testECDSAPrivateKey,
	}
	runClientTestTLS12(t, test)
}

func TestHandshakeClientX25519(t *testing.T) {
	config := testConfig.Clone()
	config.CurvePreferences = []CurveID{X25519}

	test := &clientTest{
		name:   "X25519-ECDHE",
		args:   []string{"-cipher", "ECDHE-RSA-AES128-GCM-SHA256", "-curves", "X25519"},
		config: config,
	}

	runClientTestTLS12(t, test)
	runClientTestTLS13(t, test)
}

func TestHandshakeClientP256(t *testing.T) {
	config := testConfig.Clone()
	config.CurvePreferences = []CurveID{CurveP256}

	test := &clientTest{
		name:   "P256-ECDHE",
		args:   []string{"-cipher", "ECDHE-RSA-AES128-GCM-SHA256", "-curves", "P-256"},
		config: config,
	}

	runClientTestTLS12(t, test)
	runClientTestTLS13(t, test)
}

func TestHandshakeClientHelloRetryRequest(t *testing.T) {
	config := testConfig.Clone()
	config.CurvePreferences = []CurveID{X25519, CurveP256}

	test := &clientTest{
		name:   "HelloRetryRequest",
		args:   []string{"-cipher", "ECDHE-RSA-AES128-GCM-SHA256", "-curves", "P-256"},
		config: config,
		validate: func(cs ConnectionState) error {
			if !cs.testingOnlyDidHRR {
				return errors.New("expected HelloRetryRequest")
			}
			return nil
		},
	}

	runClientTestTLS13(t, test)
}

func TestHandshakeClientECDHERSAChaCha20(t *testing.T) {
	config := testConfig.Clone()
	config.CipherSuites = []uint16{TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305}

	test := &clientTest{
		name:   "ECDHE-RSA-CHACHA20-POLY1305",
		args:   []string{"-cipher", "ECDHE-RSA-CHACHA20-POLY1305"},
		config: config,
	}

	runClientTestTLS12(t, test)
}

func TestHandshakeClientECDHEECDSAChaCha20(t *testing.T) {
	config := testConfig.Clone()
	config.CipherSuites = []uint16{TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305}

	test := &clientTest{
		name:   "ECDHE-ECDSA-CHACHA20-POLY1305",
		args:   []string{"-cipher", "ECDHE-ECDSA-CHACHA20-POLY1305"},
		config: config,
		cert:   testECDSACertificate,
		key:    testECDSAPrivateKey,
	}

	runClientTestTLS12(t, test)
}

func TestHandshakeClientAES128SHA256(t *testing.T) {
	test := &clientTest{
		name: "AES128-SHA256",
		args: []string{"-ciphersuites", "TLS_AES_128_GCM_SHA256"},
	}
	runClientTestTLS13(t, test)
}
func TestHandshakeClientAES256SHA384(t *testing.T) {
	test := &clientTest{
		name: "AES256-SHA384",
		args: []string{"-ciphersuites", "TLS_AES_256_GCM_SHA384"},
	}
	runClientTestTLS13(t, test)
}
func TestHandshakeClientCHACHA20SHA256(t *testing.T) {
	test := &clientTest{
		name: "CHACHA20-SHA256",
		args: []string{"-ciphersuites", "TLS_CHACHA20_POLY1305_SHA256"},
	}
	runClientTestTLS13(t, test)
}

func TestHandshakeClientECDSATLS13(t *testing.T) {
	test := &clientTest{
		name: "ECDSA",
		cert: testECDSACertificate,
		key:  testECDSAPrivateKey,
	}
	runClientTestTLS13(t, test)
}

func TestHandshakeClientEd25519(t *testing.T) {
	test := &clientTest{
		name: "Ed25519",
		cert: testEd25519Certificate,
		key:  testEd25519PrivateKey,
	}
	runClientTestTLS12(t, test)
	runClientTestTLS13(t, test)

	config := testConfig.Clone()
	cert, _ := X509KeyPair([]byte(clientEd25519CertificatePEM), []byte(clientEd25519KeyPEM))
	config.Certificates = []Certificate{cert}

	test = &clientTest{
		name:   "ClientCert-Ed25519",
		args:   []string{"-Verify", "1"},
		config: config,
	}

	runClientTestTLS12(t, test)
	runClientTestTLS13(t, test)
}

func TestHandshakeClientCertRSA(t *testing.T) {
	config := testConfig.Clone()
	cert, _ := X509KeyPair([]byte(clientCertificatePEM), []byte(clientKeyPEM))
	config.Certificates = []Certificate{cert}

	test := &clientTest{
		name:   "ClientCert-RSA-RSA",
		args:   []string{"-cipher", "AES128", "-Verify", "1"},
		config: config,
	}

	runClientTestTLS10(t, test)
	runClientTestTLS12(t, test)

	test = &clientTest{
		name:   "ClientCert-RSA-ECDSA",
		args:   []string{"-cipher", "ECDHE-ECDSA-AES128-SHA", "-Verify", "1"},
		config: config,
		cert:   testECDSACertificate,
		key:    testECDSAPrivateKey,
	}

	runClientTestTLS10(t, test)
	runClientTestTLS12(t, test)
	runClientTestTLS13(t, test)

	test = &clientTest{
		name:   "ClientCert-RSA-AES256-GCM-SHA384",
		args:   []string{"-cipher", "ECDHE-RSA-AES256-GCM-SHA384", "-Verify", "1"},
		config: config,
		cert:   testRSACertificate,
		key:    testRSAPrivateKey,
	}

	runClientTestTLS12(t, test)
}

func TestHandshakeClientCertECDSA(t *testing.T) {
	config := testConfig.Clone()
	cert, _ := X509KeyPair([]byte(clientECDSACertificatePEM), []byte(clientECDSAKeyPEM))
	config.Certificates = []Certificate{cert}

	test := &clientTest{
		name:   "ClientCert-ECDSA-RSA",
		args:   []string{"-cipher", "AES128", "-Verify", "1"},
		config: config,
	}

	runClientTestTLS10(t, test)
	runClientTestTLS12(t, test)
	runClientTestTLS13(t, test)

	test = &clientTest{
		name:   "ClientCert-ECDSA-ECDSA",
		args:   []string{"-cipher", "ECDHE-ECDSA-AES128-SHA", "-Verify", "1"},
		config: config,
		cert:   testECDSACertificate,
		key:    testECDSAPrivateKey,
	}

	runClientTestTLS10(t, test)
	runClientTestTLS12(t, test)
}

// TestHandshakeClientCertRSAPSS tests rsa_pss_rsae_sha256 signatures from both
// client and server certificates. It also serves from both sides a certificate
// signed itself with RSA-PSS, mostly to check that crypto/x509 chain validation
// works.
func TestHandshakeClientCertRSAPSS(t *testing.T) {
	cert, err := x509.ParseCertificate(testRSAPSSCertificate)
	if err != nil {
		panic(err)
	}
	rootCAs := x509.NewCertPool()
	rootCAs.AddCert(cert)

	config := testConfig.Clone()
	// Use GetClientCertificate to bypass the client certificate selection logic.
	config.GetClientCertificate = func(*CertificateRequestInfo) (*Certificate, error) {
		return &Certificate{
			Certificate: [][]byte{testRSAPSSCertificate},
			PrivateKey:  testRSAPrivateKey,
		}, nil
	}
	config.RootCAs = rootCAs

	test := &clientTest{
		name: "ClientCert-RSA-RSAPSS",
		args: []string{"-cipher", "AES128", "-Verify", "1", "-client_sigalgs",
			"rsa_pss_rsae_sha256", "-sigalgs", "rsa_pss_rsae_sha256"},
		config: config,
		cert:   testRSAPSSCertificate,
		key:    testRSAPrivateKey,
	}
	runClientTestTLS12(t, test)
	runClientTestTLS13(t, test)
}

func TestHandshakeClientCertRSAPKCS1v15(t *testing.T) {
	config := testConfig.Clone()
	cert, _ := X509KeyPair([]byte(clientCertificatePEM), []byte(clientKeyPEM))
	config.Certificates = []Certificate{cert}

	test := &clientTest{
		name: "ClientCert-RSA-RSAPKCS1v15",
		args: []string{"-cipher", "AES128", "-Verify", "1", "-client_sigalgs",
			"rsa_pkcs1_sha256", "-sigalgs", "rsa_pkcs1_sha256"},
		config: config,
	}

	runClientTestTLS12(t, test)
}

func TestClientKeyUpdate(t *testing.T) {
	test := &clientTest{
		name:          "KeyUpdate",
		args:          []string{"-state"},
		sendKeyUpdate: true,
	}
	runClientTestTLS13(t, test)
}

func TestResumption(t *testing.T) {
	t.Run("TLSv12", func(t *testing.T) { testResumption(t, VersionTLS12) })
	t.Run("TLSv13", func(t *testing.T) { testResumption(t, VersionTLS13) })
}

func testResumption(t *testing.T, version uint16) {
	if testing.Short() {
		t.Skip("skipping in -short mode")
	}

	// Note: using RSA 2048 test certificates because they are compatible with FIPS mode.
	testCertificates := []Certificate{{Certificate: [][]byte{testRSA2048Certificate}, PrivateKey: testRSA2048PrivateKey}}
	serverConfig := &Config{
		MaxVersion:   version,
		CipherSuites: []uint16{TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384},
		Certificates: testCertificates,
	}

	issuer, err := x509.ParseCertificate(testRSA2048CertificateIssuer)
	if err != nil {
		panic(err)
	}

	rootCAs := x509.NewCertPool()
	rootCAs.AddCert(issuer)

	clientConfig := &Config{
		MaxVersion:         version,
		CipherSuites:       []uint16{TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256},
		ClientSessionCache: NewLRUClientSessionCache(32),
		RootCAs:            rootCAs,
		ServerName:         "example.golang",
	}

	testResumeState := func(test string, didResume bool) {
		t.Helper()
		_, hs, err := testHandshake(t, clientConfig, serverConfig)
		if err != nil {
			t.Fatalf("%s: handshake failed: %s", test, err)
		}
		if hs.DidResume != didResume {
			t.Fatalf("%s resumed: %v, expected: %v", test, hs.DidResume, didResume)
		}
		if didResume && (hs.PeerCertificates == nil || hs.VerifiedChains == nil) {
			t.Fatalf("expected non-nil certificates after resumption. Got peerCertificates: %#v, verifiedCertificates: %#v", hs.PeerCertificates, hs.VerifiedChains)
		}
		if got, want := hs.ServerName, clientConfig.ServerName; got != want {
			t.Errorf("%s: server name %s, want %s", test, got, want)
		}
	}

	getTicket := func() []byte {
		return clientConfig.ClientSessionCache.(*lruSessionCache).q.Front().Value.(*lruSessionCacheEntry).state.session.ticket
	}
	deleteTicket := func() {
		ticketKey := clientConfig.ClientSessionCache.(*lruSessionCache).q.Front().Value.(*lruSessionCacheEntry).sessionKey
		clientConfig.ClientSessionCache.Put(ticketKey, nil)
	}
	corruptTicket := func() {
		clientConfig.ClientSessionCache.(*lruSessionCache).q.Front().Value.(*lruSessionCacheEntry).state.session.secret[0] ^= 0xff
	}
	randomKey := func() [32]byte {
		var k [32]byte
		if _, err := io.ReadFull(serverConfig.rand(), k[:]); err != nil {
			t.Fatalf("Failed to read new SessionTicketKey: %s", err)
		}
		return k
	}

	testResumeState("Handshake", false)
	ticket := getTicket()
	testResumeState("Resume", true)
	if bytes.Equal(ticket, getTicket()) {
		t.Fatal("ticket didn't change after resumption")
	}

	// An old session ticket is replaced with a ticket encrypted with a fresh key.
	ticket = getTicket()
	serverConfig.Time = func() time.Time { return time.Now().Add(24*time.Hour + time.Minute) }
	testResumeState("ResumeWithOldTicket", true)
	if bytes.Equal(ticket, getTicket()) {
		t.Fatal("old first ticket matches the fresh one")
	}

	// Once the session master secret is expired, a full handshake should occur.
	ticket = getTicket()
	serverConfig.Time = func() time.Time { return time.Now().Add(24*8*time.Hour + time.Minute) }
	testResumeState("ResumeWithExpiredTicket", false)
	if bytes.Equal(ticket, getTicket()) {
		t.Fatal("expired first ticket matches the fresh one")
	}

	serverConfig.Time = func() time.Time { return time.Now() } // reset the time back
	key1 := randomKey()
	serverConfig.SetSessionTicketKeys([][32]byte{key1})

	testResumeState("InvalidSessionTicketKey", false)
	testResumeState("ResumeAfterInvalidSessionTicketKey", true)

	key2 := randomKey()
	serverConfig.SetSessionTicketKeys([][32]byte{key2, key1})
	ticket = getTicket()
	testResumeState("KeyChange", true)
	if bytes.Equal(ticket, getTicket()) {
		t.Fatal("new ticket wasn't included while resuming")
	}
	testResumeState("KeyChangeFinish", true)

	// Age the session ticket a bit, but not yet expired.
	serverConfig.Time = func() time.Time { return time.Now().Add(24*time.Hour + time.Minute) }
	testResumeState("OldSessionTicket", true)
	ticket = getTicket()
	// Expire the session ticket, which would force a full handshake.
	serverConfig.Time = func() time.Time { return time.Now().Add(24*8*time.Hour + time.Minute) }
	testResumeState("ExpiredSessionTicket", false)
	if bytes.Equal(ticket, getTicket()) {
		t.Fatal("new ticket wasn't provided after old ticket expired")
	}

	// Age the session ticket a bit at a time, but don't expire it.
	d := 0 * time.Hour
	serverConfig.Time = func() time.Time { return time.Now().Add(d) }
	deleteTicket()
	testResumeState("GetFreshSessionTicket", false)
	for i := 0; i < 13; i++ {
		d += 12 * time.Hour
		testResumeState("OldSessionTicket", true)
	}
	// Expire it (now a little more than 7 days) and make sure a full
	// handshake occurs for TLS 1.2. Resumption should still occur for
	// TLS 1.3 since the client should be using a fresh ticket sent over
	// by the server.
	d += 12 * time.Hour
	if version == VersionTLS13 {
		testResumeState("ExpiredSessionTicket", true)
	} else {
		testResumeState("ExpiredSessionTicket", false)
	}
	if bytes.Equal(ticket, getTicket()) {
		t.Fatal("new ticket wasn't provided after old ticket expired")
	}

	// Reset serverConfig to ensure that calling SetSessionTicketKeys
	// before the serverConfig is used works.
	serverConfig = &Config{
		MaxVersion:   version,
		CipherSuites: []uint16{TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384},
		Certificates: testCertificates,
	}
	serverConfig.SetSessionTicketKeys([][32]byte{key2})

	testResumeState("FreshConfig", true)

	// In TLS 1.3, cross-cipher suite resumption is allowed as long as the KDF
	// hash matches. Also, Config.CipherSuites does not apply to TLS 1.3.
	if version != VersionTLS13 {
		clientConfig.CipherSuites = []uint16{TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384}
		testResumeState("DifferentCipherSuite", false)
		testResumeState("DifferentCipherSuiteRecovers", true)
	}

	deleteTicket()
	testResumeState("WithoutSessionTicket", false)

	// In TLS 1.3, HelloRetryRequest is sent after incorrect key share.
	// See https://www.rfc-editor.org/rfc/rfc8446#page-14.
	if version == VersionTLS13 {
		deleteTicket()
		serverConfig = &Config{
			// Use a different curve than the client to force a HelloRetryRequest.
			CurvePreferences: []CurveID{CurveP521, CurveP384, CurveP256},
			MaxVersion:       version,
			Certificates:     testCertificates,
		}
		testResumeState("InitialHandshake", false)
		testResumeState("WithHelloRetryRequest", true)

		// Reset serverConfig back.
		serverConfig = &Config{
			MaxVersion:   version,
			CipherSuites: []uint16{TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384},
			Certificates: testCertificates,
		}
	}

	// Session resumption should work when using client certificates
	deleteTicket()
	serverConfig.ClientCAs = rootCAs
	serverConfig.ClientAuth = RequireAndVerifyClientCert
	clientConfig.Certificates = serverConfig.Certificates
	testResumeState("InitialHandshake", false)
	testResumeState("WithClientCertificates", true)
	serverConfig.ClientAuth = NoClientCert

	// Tickets should be removed from the session cache on TLS handshake
	// failure, and the client should recover from a corrupted PSK
	testResumeState("FetchTicketToCorrupt", false)
	corruptTicket()
	_, _, err = testHandshake(t, clientConfig, serverConfig)
	if err == nil {
		t.Fatalf("handshake did not fail with a corrupted client secret")
	}
	testResumeState("AfterHandshakeFailure", false)

	clientConfig.ClientSessionCache = nil
	testResumeState("WithoutSessionCache", false)

	clientConfig.ClientSessionCache = &serializingClientCache{t: t}
	testResumeState("BeforeSerializingCache", false)
	testResumeState("WithSerializingCache", true)
}

type serializingClientCache struct {
	t *testing.T

	ticket, state []byte
}

func (c *serializingClientCache) Get(sessionKey string) (session *ClientSessionState, ok bool) {
	if c.ticket == nil {
		return nil, false
	}
	state, err := ParseSessionState(c.state)
	if err != nil {
		c.t.Error(err)
		return nil, false
	}
	cs, err := NewResumptionState(c.ticket, state)
	if err != nil {
		c.t.Error(err)
		return nil, false
	}
	return cs, true
}

func (c *serializingClientCache) Put(sessionKey string, cs *ClientSessionState) {
	if cs == nil {
		c.ticket, c.state = nil, nil
		return
	}
	ticket, state, err := cs.ResumptionState()
	if err != nil {
		c.t.Error(err)
		return
	}
	stateBytes, err := state.Bytes()
	if err != nil {
		c.t.Error(err)
		return
	}
	c.ticket, c.state = ticket, stateBytes
}

func TestLRUClientSessionCache(t *testing.T) {
	// Initialize cache of capacity 4.
	cache := NewLRUClientSessionCache(4)
	cs := make([]ClientSessionState, 6)
	keys := []string{"0", "1", "2", "3", "4", "5", "6"}

	// Add 4 entries to the cache and look them up.
	for i := 0; i < 4; i++ {
		cache.Put(keys[i], &cs[i])
	}
	for i := 0; i < 4; i++ {
		if s, ok := cache.Get(keys[i]); !ok || s != &cs[i] {
			t.Fatalf("session cache failed lookup for added key: %s", keys[i])
		}
	}

	// Add 2 more entries to the cache. First 2 should be evicted.
	for i := 4; i < 6; i++ {
		cache.Put(keys[i], &cs[i])
	}
	for i := 0; i < 2; i++ {
		if s, ok := cache.Get(keys[i]); ok || s != nil {
			t.Fatalf("session cache should have evicted key: %s", keys[i])
		}
	}

	// Touch entry 2. LRU should evict 3 next.
	cache.Get(keys[2])
	cache.Put(keys[0], &cs[0])
	if s, ok := cache.Get(keys[3]); ok || s != nil {
		t.Fatalf("session cache should have evicted key 3")
	}

	// Update entry 0 in place.
	cache.Put(keys[0], &cs[3])
	if s, ok := cache.Get(keys[0]); !ok || s != &cs[3] {
		t.Fatalf("session cache failed update for key 0")
	}

	// Calling Put with a nil entry 
"""




```