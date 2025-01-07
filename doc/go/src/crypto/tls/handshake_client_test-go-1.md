Response:
这是对`go/src/crypto/tls/handshake_client_test.go` 文件中一部分代码的功能进行分析。要求列举功能，推理 Go 语言特性并举例，解释命令行参数，指出易错点，并最终归纳这段代码的功能。这是第二部分。

**初步分析代码结构和功能点:**

1. **`TestCacheDelete` 函数:**  测试 TLS 会话缓存的删除功能，包括删除单个键和根据 LRU 策略删除。
2. **`TestKeyLogTLS12` 和 `TestKeyLogTLS13` 函数:** 测试 TLS 1.2 和 TLS 1.3 握手过程中密钥日志的记录功能。
3. **`TestHandshakeClientALPNMatch` 函数:** 测试客户端在 TLS 握手过程中应用层协议协商 (ALPN) 的匹配功能。
4. **`TestServerSelectingUnconfiguredApplicationProtocol` 函数:** 测试服务器不能选择客户端未提供的 ALPN 协议。
5. **`TestHandshakClientSCTs` 函数:** 测试客户端处理从服务器接收到的签名证书时间戳 (SCTs) 的功能。
6. **`TestRenegotiationRejected`, `TestRenegotiateOnce`, `TestRenegotiateTwice`, `TestRenegotiateTwiceRejected` 函数:**  测试 TLS 重协商的不同场景，包括拒绝重协商和允许重协商一次或多次。
7. **`TestHandshakeClientExportKeyingMaterial` 函数:** 测试客户端导出密钥材料的功能。
8. **`TestHostnameInSNI` 函数:** 测试客户端在 ClientHello 消息中设置服务器名称指示 (SNI) 的功能，并验证不同类型的服务器名称的处理。
9. **`TestServerSelectingUnconfiguredCipherSuite` 函数:** 测试服务器不能选择客户端未提供的密码套件。
10. **`TestVerifyConnection` 和 `testVerifyConnection` 函数:** 测试 `Config` 结构体中的 `VerifyConnection` 回调函数的功能，用于自定义连接验证。
11. **`TestVerifyPeerCertificate` 和 `testVerifyPeerCertificate` 函数:** 测试 `Config` 结构体中的 `VerifyPeerCertificate` 回调函数的功能，用于自定义对端证书验证。
12. **`TestFailedWrite` 函数:** 测试握手过程中写入失败的处理。
13. **`TestBuffering` 和 `testBuffering` 函数:** 测试 TLS 握手过程中的数据缓冲行为。
14. **`TestAlertFlushing` 函数:**  测试告警信息的刷新机制。

**代码推理与 Go 语言特性:**

- **会话缓存:**  `TestCacheDelete` 演示了 `sync.Map` 或类似的键值存储结构在实现会话缓存时的用法。
- **KeyLog:** `TestKeyLogTLS12` 和 `TestKeyLogTLS13` 涉及到 `io.Writer` 接口，用于将密钥信息写入缓冲区。
- **ALPN:** `TestHandshakeClientALPNMatch` 和 `TestServerSelectingUnconfiguredApplicationProtocol` 涉及到切片 (`[]string`) 用于存储支持的协议列表。
- **SCTs:** `TestHandshakClientSCTs` 涉及 `encoding/base64` 包进行 Base64 解码，以及切片 (`[][]byte`) 存储 SCT 数据。
- **重协商:**  多个 `TestRenegotiate...` 函数演示了枚举类型 (`RenegotiationSupport`) 的使用，以及错误处理 (`error` 接口)。
- **密钥导出:** `TestHandshakeClientExportKeyingMaterial` 展示了方法调用和参数传递。
- **SNI:** `TestHostnameInSNI` 涉及到结构体 (`clientHelloMsg`) 的字段访问和字符串处理。
- **连接和证书验证:** `TestVerifyConnection` 和 `TestVerifyPeerCertificate` 演示了函数作为参数（回调函数）的使用，以及结构体 (`ConnectionState`, `Config`) 的字段访问。
- **错误处理:** 多个测试函数都展示了 `error` 接口的使用和 `strings.Contains` 等函数进行错误信息判断。
- **管道通信:**  `localPipe` 函数用于创建本地的 `net.Conn` 连接对，用于模拟客户端和服务器之间的通信。
- **Go 并发:** 使用 `go func()` 启动 goroutine 来模拟客户端和服务器的并发行为，并使用 `chan` 进行同步。

**归纳功能:**

这段代码主要集中在测试 TLS 客户端在握手过程中的各种功能，包括：

- **会话管理:**  测试会话缓存的删除操作和 LRU 策略。
- **密钥记录:** 测试密钥日志功能的正确性，包括 TLS 1.2 和 TLS 1.3。
- **应用层协议协商 (ALPN):** 测试客户端的 ALPN 匹配行为和服务器的协议选择限制。
- **签名证书时间戳 (SCTs):** 测试客户端处理服务器提供的 SCTs 的能力。
- **TLS 重协商:** 测试客户端在不同重协商策略下的行为。
- **密钥材料导出:** 测试客户端导出密钥材料的功能。
- **服务器名称指示 (SNI):** 测试客户端在握手时发送 SNI 的功能。
- **密码套件协商:** 测试服务器密码套件选择的限制。
- **连接和证书验证:** 测试客户端和服务器自定义连接和对端证书验证的回调函数。
- **错误处理:** 测试握手过程中出现的写入错误的处理。
- **数据缓冲:** 测试握手过程中的数据缓冲行为。
- **告警信息处理:** 测试告警信息的刷新机制。

总而言之，这部分代码是 `crypto/tls` 包中关于客户端握手功能的详尽测试集，覆盖了 TLS 协议的多个关键方面，并利用 Go 语言的特性进行实现和验证。

这是 `go/src/crypto/tls/handshake_client_test.go` 文件第二部分代码的功能归纳。

**本部分代码主要测试了 TLS 客户端在握手过程中的以下功能：**

1. **会话缓存的删除功能:**
   - 测试了从客户端会话缓存中删除指定密钥的能力。
   - 测试了基于 LRU (最近最少使用) 策略的删除机制，验证删除特定条目后，缓存仍然保留最近使用的条目。

2. **密钥日志记录 (KeyLog):**
   - 分别针对 TLS 1.2 和 TLS 1.3 版本测试了密钥日志记录功能。
   - 验证了客户端和服务器端是否都正确地生成了密钥日志。
   - 针对 TLS 1.2，验证了密钥日志行的格式和长度是否符合预期，并检查了客户端随机数是否正确记录。
   - 针对 TLS 1.3，验证了客户端和服务器端都记录了预期的多行密钥日志。

3. **应用层协议协商 (ALPN) 的匹配:**
   - 测试了客户端在 TLS 握手过程中，根据自身支持的协议列表和服务器的选择，最终协商出一致的应用层协议的功能。
   - 使用命令行参数模拟了客户端支持的 ALPN 协议。

4. **服务器选择未配置的应用层协议的拒绝:**
   - 测试了服务器不能选择客户端未在 `NextProtos` 中声明的应用层协议的情况。
   - 验证了在这种情况下，客户端会收到包含 "server selected unadvertised ALPN protocol" 错误信息的错误。

5. **处理服务器发送的签名证书时间戳 (SCTs):**
   - 测试了客户端能够正确解析和存储服务器在握手过程中通过扩展发送的 SCTs。
   - 使用 Base64 编码的 SCTs 数据进行测试。

6. **TLS 重协商的控制:**
   - 测试了客户端对 TLS 重协商的不同策略：
     - **拒绝重协商:** 验证了在默认情况下或配置为拒绝重协商时，服务器发起的重协商会被客户端拒绝。
     - **允许重协商一次:** 验证了配置为允许重协商一次时，客户端可以完成一次重协商。
     - **允许自由重协商:** 验证了配置为允许自由重协商时，客户端可以完成多次重协商。
     - **部分拒绝重协商:** 验证了配置为允许重协商一次的情况下，第二次重协商会被拒绝。

7. **导出密钥材料:**
   - 测试了客户端可以使用 `ExportKeyingMaterial` 方法导出密钥材料的功能。
   - 验证了导出的密钥材料的长度是否正确。

8. **服务器名称指示 (SNI) 的处理:**
   - 测试了客户端在发起握手时，能够根据 `Config.ServerName` 正确设置 ClientHello 消息中的 SNI 字段。
   - 测试了不同类型的服务器名称（域名、IP 地址等）的处理情况，验证了非域名格式的服务器名称不会被放入 SNI。

9. **服务器选择未配置的密码套件的拒绝:**
   - 测试了服务器不能选择客户端未在 `CipherSuites` 中声明的密码套件的情况。
   - 验证了在这种情况下，客户端会收到包含 "unconfigured cipher" 错误信息的错误。

10. **`VerifyConnection` 回调函数:**
    - 测试了 `Config` 中的 `VerifyConnection` 回调函数在客户端和服务器端的调用时机和传递的 `ConnectionState` 参数。
    - 验证了回调函数能够访问到连接状态的各种信息，例如协议版本、握手是否完成、服务器名称、协商的协议、密码套件、是否是会话恢复等。
    - 测试了在不同的客户端认证模式下，`VerifyConnection` 的行为。

11. **`VerifyPeerCertificate` 回调函数:**
    - 测试了 `Config` 中的 `VerifyPeerCertificate` 回调函数在客户端和服务器端的调用，用于自定义对端证书的验证逻辑。
    - 验证了回调函数能够接收到原始证书数据和验证后的证书链。
    - 测试了设置 `InsecureSkipVerify` 后，`VerifyPeerCertificate` 的调用和 `validatedChains` 的状态。
    - 测试了 `VerifyPeerCertificate` 和 `VerifyConnection` 同时存在时的执行顺序和错误处理。

12. **握手过程中写入失败的处理:**
    - 通过模拟连接写入失败的情况，测试了客户端在握手过程中遇到写入错误时的处理机制。
    - 验证了客户端能够正确捕获并返回写入错误。

13. **握手过程中的数据缓冲:**
    - 测试了客户端和服务器在 TLS 握手过程中，发送消息时的缓冲行为。
    - 验证了在 TLS 1.2 和 TLS 1.3 下，完成握手所需的写入次数是否符合预期。

14. **告警信息的刷新:**
    -  这部分的代码片段到此结束，关于告警信息刷新的测试逻辑在后续的代码中。

**总而言之，这部分代码集中测试了 TLS 客户端在握手阶段的各种核心功能和错误处理机制，涵盖了会话管理、密钥协商、协议选择、证书验证、重协商控制以及底层连接错误处理等多个方面。**

Prompt: 
```
这是路径为go/src/crypto/tls/handshake_client_test.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第2部分，共3部分，请归纳一下它的功能

"""
deletes the key.
	cache.Put(keys[0], nil)
	if _, ok := cache.Get(keys[0]); ok {
		t.Fatalf("session cache failed to delete key 0")
	}

	// Delete entry 2. LRU should keep 4 and 5
	cache.Put(keys[2], nil)
	if _, ok := cache.Get(keys[2]); ok {
		t.Fatalf("session cache failed to delete key 4")
	}
	for i := 4; i < 6; i++ {
		if s, ok := cache.Get(keys[i]); !ok || s != &cs[i] {
			t.Fatalf("session cache should not have deleted key: %s", keys[i])
		}
	}
}

func TestKeyLogTLS12(t *testing.T) {
	var serverBuf, clientBuf bytes.Buffer

	clientConfig := testConfig.Clone()
	clientConfig.KeyLogWriter = &clientBuf
	clientConfig.MaxVersion = VersionTLS12

	serverConfig := testConfig.Clone()
	serverConfig.KeyLogWriter = &serverBuf
	serverConfig.MaxVersion = VersionTLS12

	c, s := localPipe(t)
	done := make(chan bool)

	go func() {
		defer close(done)

		if err := Server(s, serverConfig).Handshake(); err != nil {
			t.Errorf("server: %s", err)
			return
		}
		s.Close()
	}()

	if err := Client(c, clientConfig).Handshake(); err != nil {
		t.Fatalf("client: %s", err)
	}

	c.Close()
	<-done

	checkKeylogLine := func(side, loggedLine string) {
		if len(loggedLine) == 0 {
			t.Fatalf("%s: no keylog line was produced", side)
		}
		const expectedLen = 13 /* "CLIENT_RANDOM" */ +
			1 /* space */ +
			32*2 /* hex client nonce */ +
			1 /* space */ +
			48*2 /* hex master secret */ +
			1 /* new line */
		if len(loggedLine) != expectedLen {
			t.Fatalf("%s: keylog line has incorrect length (want %d, got %d): %q", side, expectedLen, len(loggedLine), loggedLine)
		}
		if !strings.HasPrefix(loggedLine, "CLIENT_RANDOM "+strings.Repeat("0", 64)+" ") {
			t.Fatalf("%s: keylog line has incorrect structure or nonce: %q", side, loggedLine)
		}
	}

	checkKeylogLine("client", clientBuf.String())
	checkKeylogLine("server", serverBuf.String())
}

func TestKeyLogTLS13(t *testing.T) {
	var serverBuf, clientBuf bytes.Buffer

	clientConfig := testConfig.Clone()
	clientConfig.KeyLogWriter = &clientBuf

	serverConfig := testConfig.Clone()
	serverConfig.KeyLogWriter = &serverBuf

	c, s := localPipe(t)
	done := make(chan bool)

	go func() {
		defer close(done)

		if err := Server(s, serverConfig).Handshake(); err != nil {
			t.Errorf("server: %s", err)
			return
		}
		s.Close()
	}()

	if err := Client(c, clientConfig).Handshake(); err != nil {
		t.Fatalf("client: %s", err)
	}

	c.Close()
	<-done

	checkKeylogLines := func(side, loggedLines string) {
		loggedLines = strings.TrimSpace(loggedLines)
		lines := strings.Split(loggedLines, "\n")
		if len(lines) != 4 {
			t.Errorf("Expected the %s to log 4 lines, got %d", side, len(lines))
		}
	}

	checkKeylogLines("client", clientBuf.String())
	checkKeylogLines("server", serverBuf.String())
}

func TestHandshakeClientALPNMatch(t *testing.T) {
	config := testConfig.Clone()
	config.NextProtos = []string{"proto2", "proto1"}

	test := &clientTest{
		name: "ALPN",
		// Note that this needs OpenSSL 1.0.2 because that is the first
		// version that supports the -alpn flag.
		args:   []string{"-alpn", "proto1,proto2"},
		config: config,
		validate: func(state ConnectionState) error {
			// The server's preferences should override the client.
			if state.NegotiatedProtocol != "proto1" {
				return fmt.Errorf("Got protocol %q, wanted proto1", state.NegotiatedProtocol)
			}
			return nil
		},
	}
	runClientTestTLS12(t, test)
	runClientTestTLS13(t, test)
}

func TestServerSelectingUnconfiguredApplicationProtocol(t *testing.T) {
	// This checks that the server can't select an application protocol that the
	// client didn't offer.

	c, s := localPipe(t)
	errChan := make(chan error, 1)

	go func() {
		client := Client(c, &Config{
			ServerName:   "foo",
			CipherSuites: []uint16{TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256},
			NextProtos:   []string{"http", "something-else"},
		})
		errChan <- client.Handshake()
	}()

	var header [5]byte
	if _, err := io.ReadFull(s, header[:]); err != nil {
		t.Fatal(err)
	}
	recordLen := int(header[3])<<8 | int(header[4])

	record := make([]byte, recordLen)
	if _, err := io.ReadFull(s, record); err != nil {
		t.Fatal(err)
	}

	serverHello := &serverHelloMsg{
		vers:         VersionTLS12,
		random:       make([]byte, 32),
		cipherSuite:  TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		alpnProtocol: "how-about-this",
	}
	serverHelloBytes := mustMarshal(t, serverHello)

	s.Write([]byte{
		byte(recordTypeHandshake),
		byte(VersionTLS12 >> 8),
		byte(VersionTLS12 & 0xff),
		byte(len(serverHelloBytes) >> 8),
		byte(len(serverHelloBytes)),
	})
	s.Write(serverHelloBytes)
	s.Close()

	if err := <-errChan; !strings.Contains(err.Error(), "server selected unadvertised ALPN protocol") {
		t.Fatalf("Expected error about unconfigured ALPN protocol but got %q", err)
	}
}

// sctsBase64 contains data from `openssl s_client -serverinfo 18 -connect ritter.vg:443`
const sctsBase64 = "ABIBaQFnAHUApLkJkLQYWBSHuxOizGdwCjw1mAT5G9+443fNDsgN3BAAAAFHl5nuFgAABAMARjBEAiAcS4JdlW5nW9sElUv2zvQyPoZ6ejKrGGB03gjaBZFMLwIgc1Qbbn+hsH0RvObzhS+XZhr3iuQQJY8S9G85D9KeGPAAdgBo9pj4H2SCvjqM7rkoHUz8cVFdZ5PURNEKZ6y7T0/7xAAAAUeX4bVwAAAEAwBHMEUCIDIhFDgG2HIuADBkGuLobU5a4dlCHoJLliWJ1SYT05z6AiEAjxIoZFFPRNWMGGIjskOTMwXzQ1Wh2e7NxXE1kd1J0QsAdgDuS723dc5guuFCaR+r4Z5mow9+X7By2IMAxHuJeqj9ywAAAUhcZIqHAAAEAwBHMEUCICmJ1rBT09LpkbzxtUC+Hi7nXLR0J+2PmwLp+sJMuqK+AiEAr0NkUnEVKVhAkccIFpYDqHOlZaBsuEhWWrYpg2RtKp0="

func TestHandshakClientSCTs(t *testing.T) {
	config := testConfig.Clone()

	scts, err := base64.StdEncoding.DecodeString(sctsBase64)
	if err != nil {
		t.Fatal(err)
	}

	// Note that this needs OpenSSL 1.0.2 because that is the first
	// version that supports the -serverinfo flag.
	test := &clientTest{
		name:       "SCT",
		config:     config,
		extensions: [][]byte{scts},
		validate: func(state ConnectionState) error {
			expectedSCTs := [][]byte{
				scts[8:125],
				scts[127:245],
				scts[247:],
			}
			if n := len(state.SignedCertificateTimestamps); n != len(expectedSCTs) {
				return fmt.Errorf("Got %d scts, wanted %d", n, len(expectedSCTs))
			}
			for i, expected := range expectedSCTs {
				if sct := state.SignedCertificateTimestamps[i]; !bytes.Equal(sct, expected) {
					return fmt.Errorf("SCT #%d contained %x, expected %x", i, sct, expected)
				}
			}
			return nil
		},
	}
	runClientTestTLS12(t, test)

	// TLS 1.3 moved SCTs to the Certificate extensions and -serverinfo only
	// supports ServerHello extensions.
}

func TestRenegotiationRejected(t *testing.T) {
	config := testConfig.Clone()
	test := &clientTest{
		name:                        "RenegotiationRejected",
		args:                        []string{"-state"},
		config:                      config,
		numRenegotiations:           1,
		renegotiationExpectedToFail: 1,
		checkRenegotiationError: func(renegotiationNum int, err error) error {
			if err == nil {
				return errors.New("expected error from renegotiation but got nil")
			}
			if !strings.Contains(err.Error(), "no renegotiation") {
				return fmt.Errorf("expected renegotiation to be rejected but got %q", err)
			}
			return nil
		},
	}
	runClientTestTLS12(t, test)
}

func TestRenegotiateOnce(t *testing.T) {
	config := testConfig.Clone()
	config.Renegotiation = RenegotiateOnceAsClient

	test := &clientTest{
		name:              "RenegotiateOnce",
		args:              []string{"-state"},
		config:            config,
		numRenegotiations: 1,
	}

	runClientTestTLS12(t, test)
}

func TestRenegotiateTwice(t *testing.T) {
	config := testConfig.Clone()
	config.Renegotiation = RenegotiateFreelyAsClient

	test := &clientTest{
		name:              "RenegotiateTwice",
		args:              []string{"-state"},
		config:            config,
		numRenegotiations: 2,
	}

	runClientTestTLS12(t, test)
}

func TestRenegotiateTwiceRejected(t *testing.T) {
	config := testConfig.Clone()
	config.Renegotiation = RenegotiateOnceAsClient

	test := &clientTest{
		name:                        "RenegotiateTwiceRejected",
		args:                        []string{"-state"},
		config:                      config,
		numRenegotiations:           2,
		renegotiationExpectedToFail: 2,
		checkRenegotiationError: func(renegotiationNum int, err error) error {
			if renegotiationNum == 1 {
				return err
			}

			if err == nil {
				return errors.New("expected error from renegotiation but got nil")
			}
			if !strings.Contains(err.Error(), "no renegotiation") {
				return fmt.Errorf("expected renegotiation to be rejected but got %q", err)
			}
			return nil
		},
	}

	runClientTestTLS12(t, test)
}

func TestHandshakeClientExportKeyingMaterial(t *testing.T) {
	test := &clientTest{
		name:   "ExportKeyingMaterial",
		config: testConfig.Clone(),
		validate: func(state ConnectionState) error {
			if km, err := state.ExportKeyingMaterial("test", nil, 42); err != nil {
				return fmt.Errorf("ExportKeyingMaterial failed: %v", err)
			} else if len(km) != 42 {
				return fmt.Errorf("Got %d bytes from ExportKeyingMaterial, wanted %d", len(km), 42)
			}
			return nil
		},
	}
	runClientTestTLS10(t, test)
	runClientTestTLS12(t, test)
	runClientTestTLS13(t, test)
}

var hostnameInSNITests = []struct {
	in, out string
}{
	// Opaque string
	{"", ""},
	{"localhost", "localhost"},
	{"foo, bar, baz and qux", "foo, bar, baz and qux"},

	// DNS hostname
	{"golang.org", "golang.org"},
	{"golang.org.", "golang.org"},

	// Literal IPv4 address
	{"1.2.3.4", ""},

	// Literal IPv6 address
	{"::1", ""},
	{"::1%lo0", ""}, // with zone identifier
	{"[::1]", ""},   // as per RFC 5952 we allow the [] style as IPv6 literal
	{"[::1%lo0]", ""},
}

func TestHostnameInSNI(t *testing.T) {
	for _, tt := range hostnameInSNITests {
		c, s := localPipe(t)

		go func(host string) {
			Client(c, &Config{ServerName: host, InsecureSkipVerify: true}).Handshake()
		}(tt.in)

		var header [5]byte
		if _, err := io.ReadFull(s, header[:]); err != nil {
			t.Fatal(err)
		}
		recordLen := int(header[3])<<8 | int(header[4])

		record := make([]byte, recordLen)
		if _, err := io.ReadFull(s, record[:]); err != nil {
			t.Fatal(err)
		}

		c.Close()
		s.Close()

		var m clientHelloMsg
		if !m.unmarshal(record) {
			t.Errorf("unmarshaling ClientHello for %q failed", tt.in)
			continue
		}
		if tt.in != tt.out && m.serverName == tt.in {
			t.Errorf("prohibited %q found in ClientHello: %x", tt.in, record)
		}
		if m.serverName != tt.out {
			t.Errorf("expected %q not found in ClientHello: %x", tt.out, record)
		}
	}
}

func TestServerSelectingUnconfiguredCipherSuite(t *testing.T) {
	// This checks that the server can't select a cipher suite that the
	// client didn't offer. See #13174.

	c, s := localPipe(t)
	errChan := make(chan error, 1)

	go func() {
		client := Client(c, &Config{
			ServerName:   "foo",
			CipherSuites: []uint16{TLS_RSA_WITH_AES_128_GCM_SHA256},
		})
		errChan <- client.Handshake()
	}()

	var header [5]byte
	if _, err := io.ReadFull(s, header[:]); err != nil {
		t.Fatal(err)
	}
	recordLen := int(header[3])<<8 | int(header[4])

	record := make([]byte, recordLen)
	if _, err := io.ReadFull(s, record); err != nil {
		t.Fatal(err)
	}

	// Create a ServerHello that selects a different cipher suite than the
	// sole one that the client offered.
	serverHello := &serverHelloMsg{
		vers:        VersionTLS12,
		random:      make([]byte, 32),
		cipherSuite: TLS_RSA_WITH_AES_256_GCM_SHA384,
	}
	serverHelloBytes := mustMarshal(t, serverHello)

	s.Write([]byte{
		byte(recordTypeHandshake),
		byte(VersionTLS12 >> 8),
		byte(VersionTLS12 & 0xff),
		byte(len(serverHelloBytes) >> 8),
		byte(len(serverHelloBytes)),
	})
	s.Write(serverHelloBytes)
	s.Close()

	if err := <-errChan; !strings.Contains(err.Error(), "unconfigured cipher") {
		t.Fatalf("Expected error about unconfigured cipher suite but got %q", err)
	}
}

func TestVerifyConnection(t *testing.T) {
	t.Run("TLSv12", func(t *testing.T) { testVerifyConnection(t, VersionTLS12) })
	t.Run("TLSv13", func(t *testing.T) { testVerifyConnection(t, VersionTLS13) })
}

func testVerifyConnection(t *testing.T, version uint16) {
	checkFields := func(c ConnectionState, called *int, errorType string) error {
		if c.Version != version {
			return fmt.Errorf("%s: got Version %v, want %v", errorType, c.Version, version)
		}
		if c.HandshakeComplete {
			return fmt.Errorf("%s: got HandshakeComplete, want false", errorType)
		}
		if c.ServerName != "example.golang" {
			return fmt.Errorf("%s: got ServerName %s, want %s", errorType, c.ServerName, "example.golang")
		}
		if c.NegotiatedProtocol != "protocol1" {
			return fmt.Errorf("%s: got NegotiatedProtocol %s, want %s", errorType, c.NegotiatedProtocol, "protocol1")
		}
		if c.CipherSuite == 0 {
			return fmt.Errorf("%s: got CipherSuite 0, want non-zero", errorType)
		}
		wantDidResume := false
		if *called == 2 { // if this is the second time, then it should be a resumption
			wantDidResume = true
		}
		if c.DidResume != wantDidResume {
			return fmt.Errorf("%s: got DidResume %t, want %t", errorType, c.DidResume, wantDidResume)
		}
		return nil
	}

	tests := []struct {
		name            string
		configureServer func(*Config, *int)
		configureClient func(*Config, *int)
	}{
		{
			name: "RequireAndVerifyClientCert",
			configureServer: func(config *Config, called *int) {
				config.ClientAuth = RequireAndVerifyClientCert
				config.VerifyConnection = func(c ConnectionState) error {
					*called++
					if l := len(c.PeerCertificates); l != 1 {
						return fmt.Errorf("server: got len(PeerCertificates) = %d, wanted 1", l)
					}
					if len(c.VerifiedChains) == 0 {
						return fmt.Errorf("server: got len(VerifiedChains) = 0, wanted non-zero")
					}
					return checkFields(c, called, "server")
				}
			},
			configureClient: func(config *Config, called *int) {
				config.VerifyConnection = func(c ConnectionState) error {
					*called++
					if l := len(c.PeerCertificates); l != 1 {
						return fmt.Errorf("client: got len(PeerCertificates) = %d, wanted 1", l)
					}
					if len(c.VerifiedChains) == 0 {
						return fmt.Errorf("client: got len(VerifiedChains) = 0, wanted non-zero")
					}
					if c.DidResume {
						return nil
						// The SCTs and OCSP Response are dropped on resumption.
						// See http://golang.org/issue/39075.
					}
					if len(c.OCSPResponse) == 0 {
						return fmt.Errorf("client: got len(OCSPResponse) = 0, wanted non-zero")
					}
					if len(c.SignedCertificateTimestamps) == 0 {
						return fmt.Errorf("client: got len(SignedCertificateTimestamps) = 0, wanted non-zero")
					}
					return checkFields(c, called, "client")
				}
			},
		},
		{
			name: "InsecureSkipVerify",
			configureServer: func(config *Config, called *int) {
				config.ClientAuth = RequireAnyClientCert
				config.InsecureSkipVerify = true
				config.VerifyConnection = func(c ConnectionState) error {
					*called++
					if l := len(c.PeerCertificates); l != 1 {
						return fmt.Errorf("server: got len(PeerCertificates) = %d, wanted 1", l)
					}
					if c.VerifiedChains != nil {
						return fmt.Errorf("server: got Verified Chains %v, want nil", c.VerifiedChains)
					}
					return checkFields(c, called, "server")
				}
			},
			configureClient: func(config *Config, called *int) {
				config.InsecureSkipVerify = true
				config.VerifyConnection = func(c ConnectionState) error {
					*called++
					if l := len(c.PeerCertificates); l != 1 {
						return fmt.Errorf("client: got len(PeerCertificates) = %d, wanted 1", l)
					}
					if c.VerifiedChains != nil {
						return fmt.Errorf("server: got Verified Chains %v, want nil", c.VerifiedChains)
					}
					if c.DidResume {
						return nil
						// The SCTs and OCSP Response are dropped on resumption.
						// See http://golang.org/issue/39075.
					}
					if len(c.OCSPResponse) == 0 {
						return fmt.Errorf("client: got len(OCSPResponse) = 0, wanted non-zero")
					}
					if len(c.SignedCertificateTimestamps) == 0 {
						return fmt.Errorf("client: got len(SignedCertificateTimestamps) = 0, wanted non-zero")
					}
					return checkFields(c, called, "client")
				}
			},
		},
		{
			name: "NoClientCert",
			configureServer: func(config *Config, called *int) {
				config.ClientAuth = NoClientCert
				config.VerifyConnection = func(c ConnectionState) error {
					*called++
					return checkFields(c, called, "server")
				}
			},
			configureClient: func(config *Config, called *int) {
				config.VerifyConnection = func(c ConnectionState) error {
					*called++
					return checkFields(c, called, "client")
				}
			},
		},
		{
			name: "RequestClientCert",
			configureServer: func(config *Config, called *int) {
				config.ClientAuth = RequestClientCert
				config.VerifyConnection = func(c ConnectionState) error {
					*called++
					return checkFields(c, called, "server")
				}
			},
			configureClient: func(config *Config, called *int) {
				config.Certificates = nil // clear the client cert
				config.VerifyConnection = func(c ConnectionState) error {
					*called++
					if l := len(c.PeerCertificates); l != 1 {
						return fmt.Errorf("client: got len(PeerCertificates) = %d, wanted 1", l)
					}
					if len(c.VerifiedChains) == 0 {
						return fmt.Errorf("client: got len(VerifiedChains) = 0, wanted non-zero")
					}
					if c.DidResume {
						return nil
						// The SCTs and OCSP Response are dropped on resumption.
						// See http://golang.org/issue/39075.
					}
					if len(c.OCSPResponse) == 0 {
						return fmt.Errorf("client: got len(OCSPResponse) = 0, wanted non-zero")
					}
					if len(c.SignedCertificateTimestamps) == 0 {
						return fmt.Errorf("client: got len(SignedCertificateTimestamps) = 0, wanted non-zero")
					}
					return checkFields(c, called, "client")
				}
			},
		},
	}
	for _, test := range tests {
		// Note: using RSA 2048 test certificates because they are compatible with FIPS mode.
		testCertificates := []Certificate{{Certificate: [][]byte{testRSA2048Certificate}, PrivateKey: testRSA2048PrivateKey}}

		issuer, err := x509.ParseCertificate(testRSA2048CertificateIssuer)
		if err != nil {
			panic(err)
		}
		rootCAs := x509.NewCertPool()
		rootCAs.AddCert(issuer)

		var serverCalled, clientCalled int

		serverConfig := &Config{
			MaxVersion:   version,
			Certificates: testCertificates,
			ClientCAs:    rootCAs,
			NextProtos:   []string{"protocol1"},
		}
		serverConfig.Certificates[0].SignedCertificateTimestamps = [][]byte{[]byte("dummy sct 1"), []byte("dummy sct 2")}
		serverConfig.Certificates[0].OCSPStaple = []byte("dummy ocsp")
		test.configureServer(serverConfig, &serverCalled)

		clientConfig := &Config{
			MaxVersion:         version,
			ClientSessionCache: NewLRUClientSessionCache(32),
			RootCAs:            rootCAs,
			ServerName:         "example.golang",
			Certificates:       testCertificates,
			NextProtos:         []string{"protocol1"},
		}
		test.configureClient(clientConfig, &clientCalled)

		testHandshakeState := func(name string, didResume bool) {
			_, hs, err := testHandshake(t, clientConfig, serverConfig)
			if err != nil {
				t.Fatalf("%s: handshake failed: %s", name, err)
			}
			if hs.DidResume != didResume {
				t.Errorf("%s: resumed: %v, expected: %v", name, hs.DidResume, didResume)
			}
			wantCalled := 1
			if didResume {
				wantCalled = 2 // resumption would mean this is the second time it was called in this test
			}
			if clientCalled != wantCalled {
				t.Errorf("%s: expected client VerifyConnection called %d times, did %d times", name, wantCalled, clientCalled)
			}
			if serverCalled != wantCalled {
				t.Errorf("%s: expected server VerifyConnection called %d times, did %d times", name, wantCalled, serverCalled)
			}
		}
		testHandshakeState(fmt.Sprintf("%s-FullHandshake", test.name), false)
		testHandshakeState(fmt.Sprintf("%s-Resumption", test.name), true)
	}
}

func TestVerifyPeerCertificate(t *testing.T) {
	t.Run("TLSv12", func(t *testing.T) { testVerifyPeerCertificate(t, VersionTLS12) })
	t.Run("TLSv13", func(t *testing.T) { testVerifyPeerCertificate(t, VersionTLS13) })
}

func testVerifyPeerCertificate(t *testing.T, version uint16) {
	// Note: using RSA 2048 test certificates because they are compatible with FIPS mode.
	issuer, err := x509.ParseCertificate(testRSA2048CertificateIssuer)
	if err != nil {
		panic(err)
	}

	rootCAs := x509.NewCertPool()
	rootCAs.AddCert(issuer)

	now := func() time.Time { return time.Unix(1476984729, 0) }

	sentinelErr := errors.New("TestVerifyPeerCertificate")

	verifyPeerCertificateCallback := func(called *bool, rawCerts [][]byte, validatedChains [][]*x509.Certificate) error {
		if l := len(rawCerts); l != 1 {
			return fmt.Errorf("got len(rawCerts) = %d, wanted 1", l)
		}
		if len(validatedChains) == 0 {
			return errors.New("got len(validatedChains) = 0, wanted non-zero")
		}
		*called = true
		return nil
	}
	verifyConnectionCallback := func(called *bool, isClient bool, c ConnectionState) error {
		if l := len(c.PeerCertificates); l != 1 {
			return fmt.Errorf("got len(PeerCertificates) = %d, wanted 1", l)
		}
		if len(c.VerifiedChains) == 0 {
			return fmt.Errorf("got len(VerifiedChains) = 0, wanted non-zero")
		}
		if isClient && len(c.OCSPResponse) == 0 {
			return fmt.Errorf("got len(OCSPResponse) = 0, wanted non-zero")
		}
		*called = true
		return nil
	}

	tests := []struct {
		configureServer func(*Config, *bool)
		configureClient func(*Config, *bool)
		validate        func(t *testing.T, testNo int, clientCalled, serverCalled bool, clientErr, serverErr error)
	}{
		{
			configureServer: func(config *Config, called *bool) {
				config.InsecureSkipVerify = false
				config.VerifyPeerCertificate = func(rawCerts [][]byte, validatedChains [][]*x509.Certificate) error {
					return verifyPeerCertificateCallback(called, rawCerts, validatedChains)
				}
			},
			configureClient: func(config *Config, called *bool) {
				config.InsecureSkipVerify = false
				config.VerifyPeerCertificate = func(rawCerts [][]byte, validatedChains [][]*x509.Certificate) error {
					return verifyPeerCertificateCallback(called, rawCerts, validatedChains)
				}
			},
			validate: func(t *testing.T, testNo int, clientCalled, serverCalled bool, clientErr, serverErr error) {
				if clientErr != nil {
					t.Errorf("test[%d]: client handshake failed: %v", testNo, clientErr)
				}
				if serverErr != nil {
					t.Errorf("test[%d]: server handshake failed: %v", testNo, serverErr)
				}
				if !clientCalled {
					t.Errorf("test[%d]: client did not call callback", testNo)
				}
				if !serverCalled {
					t.Errorf("test[%d]: server did not call callback", testNo)
				}
			},
		},
		{
			configureServer: func(config *Config, called *bool) {
				config.InsecureSkipVerify = false
				config.VerifyPeerCertificate = func(rawCerts [][]byte, validatedChains [][]*x509.Certificate) error {
					return sentinelErr
				}
			},
			configureClient: func(config *Config, called *bool) {
				config.VerifyPeerCertificate = nil
			},
			validate: func(t *testing.T, testNo int, clientCalled, serverCalled bool, clientErr, serverErr error) {
				if serverErr != sentinelErr {
					t.Errorf("#%d: got server error %v, wanted sentinelErr", testNo, serverErr)
				}
			},
		},
		{
			configureServer: func(config *Config, called *bool) {
				config.InsecureSkipVerify = false
			},
			configureClient: func(config *Config, called *bool) {
				config.VerifyPeerCertificate = func(rawCerts [][]byte, validatedChains [][]*x509.Certificate) error {
					return sentinelErr
				}
			},
			validate: func(t *testing.T, testNo int, clientCalled, serverCalled bool, clientErr, serverErr error) {
				if clientErr != sentinelErr {
					t.Errorf("#%d: got client error %v, wanted sentinelErr", testNo, clientErr)
				}
			},
		},
		{
			configureServer: func(config *Config, called *bool) {
				config.InsecureSkipVerify = false
			},
			configureClient: func(config *Config, called *bool) {
				config.InsecureSkipVerify = true
				config.VerifyPeerCertificate = func(rawCerts [][]byte, validatedChains [][]*x509.Certificate) error {
					if l := len(rawCerts); l != 1 {
						return fmt.Errorf("got len(rawCerts) = %d, wanted 1", l)
					}
					// With InsecureSkipVerify set, this
					// callback should still be called but
					// validatedChains must be empty.
					if l := len(validatedChains); l != 0 {
						return fmt.Errorf("got len(validatedChains) = %d, wanted zero", l)
					}
					*called = true
					return nil
				}
			},
			validate: func(t *testing.T, testNo int, clientCalled, serverCalled bool, clientErr, serverErr error) {
				if clientErr != nil {
					t.Errorf("test[%d]: client handshake failed: %v", testNo, clientErr)
				}
				if serverErr != nil {
					t.Errorf("test[%d]: server handshake failed: %v", testNo, serverErr)
				}
				if !clientCalled {
					t.Errorf("test[%d]: client did not call callback", testNo)
				}
			},
		},
		{
			configureServer: func(config *Config, called *bool) {
				config.InsecureSkipVerify = false
				config.VerifyConnection = func(c ConnectionState) error {
					return verifyConnectionCallback(called, false, c)
				}
			},
			configureClient: func(config *Config, called *bool) {
				config.InsecureSkipVerify = false
				config.VerifyConnection = func(c ConnectionState) error {
					return verifyConnectionCallback(called, true, c)
				}
			},
			validate: func(t *testing.T, testNo int, clientCalled, serverCalled bool, clientErr, serverErr error) {
				if clientErr != nil {
					t.Errorf("test[%d]: client handshake failed: %v", testNo, clientErr)
				}
				if serverErr != nil {
					t.Errorf("test[%d]: server handshake failed: %v", testNo, serverErr)
				}
				if !clientCalled {
					t.Errorf("test[%d]: client did not call callback", testNo)
				}
				if !serverCalled {
					t.Errorf("test[%d]: server did not call callback", testNo)
				}
			},
		},
		{
			configureServer: func(config *Config, called *bool) {
				config.InsecureSkipVerify = false
				config.VerifyConnection = func(c ConnectionState) error {
					return sentinelErr
				}
			},
			configureClient: func(config *Config, called *bool) {
				config.InsecureSkipVerify = false
				config.VerifyConnection = nil
			},
			validate: func(t *testing.T, testNo int, clientCalled, serverCalled bool, clientErr, serverErr error) {
				if serverErr != sentinelErr {
					t.Errorf("#%d: got server error %v, wanted sentinelErr", testNo, serverErr)
				}
			},
		},
		{
			configureServer: func(config *Config, called *bool) {
				config.InsecureSkipVerify = false
				config.VerifyConnection = nil
			},
			configureClient: func(config *Config, called *bool) {
				config.InsecureSkipVerify = false
				config.VerifyConnection = func(c ConnectionState) error {
					return sentinelErr
				}
			},
			validate: func(t *testing.T, testNo int, clientCalled, serverCalled bool, clientErr, serverErr error) {
				if clientErr != sentinelErr {
					t.Errorf("#%d: got client error %v, wanted sentinelErr", testNo, clientErr)
				}
			},
		},
		{
			configureServer: func(config *Config, called *bool) {
				config.InsecureSkipVerify = false
				config.VerifyPeerCertificate = func(rawCerts [][]byte, validatedChains [][]*x509.Certificate) error {
					return verifyPeerCertificateCallback(called, rawCerts, validatedChains)
				}
				config.VerifyConnection = func(c ConnectionState) error {
					return sentinelErr
				}
			},
			configureClient: func(config *Config, called *bool) {
				config.InsecureSkipVerify = false
				config.VerifyPeerCertificate = nil
				config.VerifyConnection = nil
			},
			validate: func(t *testing.T, testNo int, clientCalled, serverCalled bool, clientErr, serverErr error) {
				if serverErr != sentinelErr {
					t.Errorf("#%d: got server error %v, wanted sentinelErr", testNo, serverErr)
				}
				if !serverCalled {
					t.Errorf("test[%d]: server did not call callback", testNo)
				}
			},
		},
		{
			configureServer: func(config *Config, called *bool) {
				config.InsecureSkipVerify = false
				config.VerifyPeerCertificate = nil
				config.VerifyConnection = nil
			},
			configureClient: func(config *Config, called *bool) {
				config.InsecureSkipVerify = false
				config.VerifyPeerCertificate = func(rawCerts [][]byte, validatedChains [][]*x509.Certificate) error {
					return verifyPeerCertificateCallback(called, rawCerts, validatedChains)
				}
				config.VerifyConnection = func(c ConnectionState) error {
					return sentinelErr
				}
			},
			validate: func(t *testing.T, testNo int, clientCalled, serverCalled bool, clientErr, serverErr error) {
				if clientErr != sentinelErr {
					t.Errorf("#%d: got client error %v, wanted sentinelErr", testNo, clientErr)
				}
				if !clientCalled {
					t.Errorf("test[%d]: client did not call callback", testNo)
				}
			},
		},
	}

	for i, test := range tests {
		c, s := localPipe(t)
		done := make(chan error)

		var clientCalled, serverCalled bool

		go func() {
			config := testConfig.Clone()
			config.ServerName = "example.golang"
			config.ClientAuth = RequireAndVerifyClientCert
			config.ClientCAs = rootCAs
			config.Time = now
			config.MaxVersion = version
			config.Certificates = make([]Certificate, 1)
			config.Certificates[0].Certificate = [][]byte{testRSA2048Certificate}
			config.Certificates[0].PrivateKey = testRSA2048PrivateKey
			config.Certificates[0].SignedCertificateTimestamps = [][]byte{[]byte("dummy sct 1"), []byte("dummy sct 2")}
			config.Certificates[0].OCSPStaple = []byte("dummy ocsp")
			test.configureServer(config, &serverCalled)

			err = Server(s, config).Handshake()
			s.Close()
			done <- err
		}()

		config := testConfig.Clone()
		config.Certificates = []Certificate{{Certificate: [][]byte{testRSA2048Certificate}, PrivateKey: testRSA2048PrivateKey}}
		config.ServerName = "example.golang"
		config.RootCAs = rootCAs
		config.Time = now
		config.MaxVersion = version
		test.configureClient(config, &clientCalled)
		clientErr := Client(c, config).Handshake()
		c.Close()
		serverErr := <-done

		test.validate(t, i, clientCalled, serverCalled, clientErr, serverErr)
	}
}

// brokenConn wraps a net.Conn and causes all Writes after a certain number to
// fail with brokenConnErr.
type brokenConn struct {
	net.Conn

	// breakAfter is the number of successful writes that will be allowed
	// before all subsequent writes fail.
	breakAfter int

	// numWrites is the number of writes that have been done.
	numWrites int
}

// brokenConnErr is the error that brokenConn returns once exhausted.
var brokenConnErr = errors.New("too many writes to brokenConn")

func (b *brokenConn) Write(data []byte) (int, error) {
	if b.numWrites >= b.breakAfter {
		return 0, brokenConnErr
	}

	b.numWrites++
	return b.Conn.Write(data)
}

func TestFailedWrite(t *testing.T) {
	// Test that a write error during the handshake is returned.
	for _, breakAfter := range []int{0, 1} {
		c, s := localPipe(t)
		done := make(chan bool)

		go func() {
			Server(s, testConfig).Handshake()
			s.Close()
			done <- true
		}()

		brokenC := &brokenConn{Conn: c, breakAfter: breakAfter}
		err := Client(brokenC, testConfig).Handshake()
		if err != brokenConnErr {
			t.Errorf("#%d: expected error from brokenConn but got %q", breakAfter, err)
		}
		brokenC.Close()

		<-done
	}
}

// writeCountingConn wraps a net.Conn and counts the number of Write calls.
type writeCountingConn struct {
	net.Conn

	// numWrites is the number of writes that have been done.
	numWrites int
}

func (wcc *writeCountingConn) Write(data []byte) (int, error) {
	wcc.numWrites++
	return wcc.Conn.Write(data)
}

func TestBuffering(t *testing.T) {
	t.Run("TLSv12", func(t *testing.T) { testBuffering(t, VersionTLS12) })
	t.Run("TLSv13", func(t *testing.T) { testBuffering(t, VersionTLS13) })
}

func testBuffering(t *testing.T, version uint16) {
	c, s := localPipe(t)
	done := make(chan bool)

	clientWCC := &writeCountingConn{Conn: c}
	serverWCC := &writeCountingConn{Conn: s}

	go func() {
		config := testConfig.Clone()
		config.MaxVersion = version
		Server(serverWCC, config).Handshake()
		serverWCC.Close()
		done <- true
	}()

	err := Client(clientWCC, testConfig).Handshake()
	if err != nil {
		t.Fatal(err)
	}
	clientWCC.Close()
	<-done

	var expectedClient, expectedServer int
	if version == VersionTLS13 {
		expectedClient = 2
		expectedServer = 1
	} else {
		expectedClient = 2
		expectedServer = 2
	}

	if n := clientWCC.numWrites; n != expectedClient {
		t.Errorf("expected client handshake to complete with %d writes, but saw %d", expectedClient, n)
	}

	if n := serverWCC.numWrites; n != expectedServer {
		t.Errorf("expected server handshake to complete with %d writes, but saw %d", expectedServer, n)
	}
}

func TestAlertFlushing(t *testing.T) {
	c, s := localPipe(t)
	done := make(chan bool)

	clientWCC := &writeCountingConn{Conn: c}
	serverWCC := &writeCountingConn{Conn: s}

	serverConfig := testConfig.Clone()

	// Cause a signature-time error
	brokenKey := 
"""




```