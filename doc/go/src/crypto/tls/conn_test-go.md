Response:
Let's break down the thought process for analyzing the provided Go code snippet.

**1. Initial Scan and Understanding the Context:**

* **File Path:** `go/src/crypto/tls/conn_test.go`. This immediately tells us it's a *test file* for the `conn.go` file within the `crypto/tls` package. This means the code's primary purpose is to verify the functionality of TLS connections.
* **Package Declaration:** `package tls`. Confirms the scope.
* **Imports:** `bytes`, `io`, `net`, `testing`. These are standard Go libraries used for byte manipulation, input/output, networking, and writing tests, respectively. This reinforces the idea that it's a test file.

**2. Analyzing Individual Test Functions:**

* **`TestRoundUp(t *testing.T)`:**  This is a straightforward unit test. The name `RoundUp` and the logic within suggest it's testing a function that rounds an integer up to the nearest multiple of another integer (in this case, 16). I can infer the function signature `func roundUp(n, multiple int) int`.
* **`TestRemovePadding(t *testing.T)`:** This test iterates through `paddingTests`. The structure of `paddingTests` suggests it's testing a function that extracts padding from a byte slice. The `good` and `expectedLen` fields hint at validating the padding and determining the original data length after removing the padding. I can infer the function signature `func extractPadding(data []byte) (paddingLen int, good bool)`. The `padding255Bad` and `padding255Good` variables give more context about the padding scheme likely involving the byte value `255`.
* **`TestCertificateSelection(t *testing.T)`:** This test involves `Config`, `Certificate`, and `ClientHelloInfo`. The code builds a `Config` with multiple certificates and then uses `getCertificate` based on a `ServerName`. This clearly tests the logic for selecting the appropriate TLS certificate based on the server name provided by the client during the handshake. I can infer the function signature `func (c *Config) getCertificate(clientHello *ClientHelloInfo) (*Certificate, error)`. The provided `certExampleCom`, `certWildcardExampleCom`, and `certFooExampleCom` are likely PEM-encoded certificates in hexadecimal format.
* **`runDynamicRecordSizingTest(t *testing.T, config *Config)`:** This function sets up a local pipe, creates TLS client and server connections with the given `config`, performs a handshake, and then sends data. It monitors the sizes of the TLS records sent by the server. The name and the logic strongly suggest this is testing a feature where the TLS implementation dynamically adjusts the size of the records it sends, potentially based on network conditions or other factors.
* **`TestDynamicRecordSizingWith...`:** These functions call `runDynamicRecordSizingTest` with specific `CipherSuites` and TLS versions. This confirms the `runDynamicRecordSizingTest` is a general testing function for the dynamic record sizing feature and that it's being tested with different TLS configurations.
* **`TestHairpinInClose(t *testing.T)`:** The `hairpinConn` struct and the `Close()` method that calls `conn.tlsConn.ConnectionState()` suggest a test for a specific scenario where closing the underlying network connection triggers an action within the TLS connection. This aims to prevent deadlocks in such situations.
* **`TestRecordBadVersionTLS13(t *testing.T)`:** This test sets up a TLS 1.3 connection and then artificially changes the TLS version in the client's connection. The server then attempts to read data. This is clearly testing how the TLS implementation handles receiving records with unexpected versions.

**3. Inferring Go Language Features:**

Based on the analysis of the test functions, the key Go language feature being tested is **TLS (Transport Layer Security)**. This includes:

* **Handshakes:** The `Handshake()` calls are central to establishing a secure TLS connection.
* **Certificate Management:** The `CertificateSelection` tests directly deal with loading, selecting, and using TLS certificates.
* **Record Sizing:** The `DynamicRecordSizingTest` functions specifically target the logic for managing the size of TLS records.
* **Connection Handling:** The `hairpinConn` test explores the nuances of closing TLS connections and the underlying network connections.
* **Error Handling:** Tests like `TestRecordBadVersionTLS13` verify how the implementation handles invalid or unexpected data.

**4. Providing Code Examples (as requested):**

This involves taking the inferences about the functions being tested and creating illustrative examples of how those functions might be used in a non-test context. This was done for `roundUp`, `extractPadding`, and the certificate selection logic.

**5. Addressing Other Requirements:**

* **Command-line arguments:**  Since this is a test file, it doesn't directly handle command-line arguments in the same way an application might. The `testing` package handles test execution. This is explicitly stated in the answer.
* **User errors:** Identifying potential user errors comes from understanding how someone might misuse the features being tested. For example, not calling `BuildNameToCertificate()` could lead to certificate selection issues.
* **Language:** The entire response is provided in Chinese as requested.

**Self-Correction/Refinement during the process:**

* Initially, I might have focused too much on the individual test cases without realizing the overarching theme of TLS functionality. Stepping back and looking at the bigger picture helps in identifying the core Go feature being tested.
* When inferring function signatures, I considered the types of the inputs and outputs based on how they are used in the test functions.
* For the code examples, I aimed for simplicity and clarity to illustrate the functionality without unnecessary complexity.
* When explaining potential user errors, I tried to think about common mistakes developers might make when working with TLS configurations.

By following this structured approach, combining code analysis with an understanding of the testing context, I was able to generate the comprehensive answer provided previously.
这个go语言实现的文件 `go/src/crypto/tls/conn_test.go` 是 `crypto/tls` 包的一部分，专门用于测试 TLS 连接相关的功能。 让我们逐个分析其功能和实现。

**主要功能：**

1. **单元测试辅助函数 `roundUp`**:  测试一个名为 `roundUp` 的函数，该函数将一个整数向上舍入到指定的倍数。
2. **测试 TLS 记录的去除填充 (`extractPadding`) 功能**: 测试一个用于从 TLS 记录中移除填充的函数，并验证填充的正确性。
3. **测试证书选择逻辑 (`getCertificate`)**: 测试 TLS 连接在建立过程中，根据客户端提供的 Server Name Indication (SNI) 选择合适的服务器证书的机制。
4. **测试动态调整 TLS 记录大小的功能**:  测试 TLS 连接在传输数据时，能够动态调整记录大小以优化性能的功能。
5. **测试在关闭连接时可能出现的“发夹弯” (hairpin) 情况**: 模拟并测试在关闭底层的网络连接时，TLS 连接内部的回调是否会引发死锁。
6. **测试处理接收到错误版本 TLS 记录的情况**:  测试当 TLS 连接接收到预期版本之外的记录时，如何进行错误处理。

**更详细的分析和代码示例：**

**1. 单元测试辅助函数 `roundUp`**

   - **功能:** 将整数 `n` 向上舍入到最接近但不小于 `n` 的 `multiple` 的倍数。
   - **代码示例:**
     ```go
     func roundUp(n, multiple int) int {
         if multiple <= 0 {
             return n // 或者可以 panic，取决于具体需求
         }
         remainder := n % multiple
         if remainder == 0 {
             return n
         }
         return n + multiple - remainder
     }

     // 假设输入与输出：
     // roundUp(1, 16)  -> 输出 16
     // roundUp(15, 16) -> 输出 16
     // roundUp(17, 16) -> 输出 32
     ```

**2. 测试 TLS 记录的去除填充 (`extractPadding`) 功能**

   - **功能:**  TLS 协议中，为了防止流量分析，可能会在加密数据后添加填充。此功能用于检测并移除这些填充。填充的最后一个字节表示填充的长度。如果填充字节的值不一致，或者最后一个字节的值大于填充的实际长度，则认为填充无效。
   - **代码推理:**  从 `paddingTests` 的结构可以看出，`extractPadding` 函数可能接受一个 `[]byte` 作为输入，并返回填充的长度和一个布尔值表示填充是否有效。如果填充有效，返回的长度用于计算原始数据的长度。
   - **代码示例 (推测):**
     ```go
     func extractPadding(data []byte) (paddingLen int, good bool) {
         if len(data) == 0 {
             return 0, true
         }
         paddingValue := data[len(data)-1]
         paddingLen = int(paddingValue)
         if paddingLen > len(data) {
             return 0, false
         }
         for i := len(data) - 1; i > len(data)-1-paddingLen; i-- {
             if data[i] != paddingValue {
                 return 0, false
             }
         }
         return paddingLen, true
     }

     // 假设输入与输出 (基于 paddingTests):
     // extractPadding([]byte{1, 2, 3, 4, 4, 4, 4, 4}) -> 输出: paddingLen=4, good=true
     // extractPadding([]byte{1, 2, 3, 4, 0})       -> 输出: paddingLen=0, good=true (这里 0 表示无填充或填充长度为0)
     // extractPadding([]byte{1, 2, 3, 4, 99, 99})    -> 输出: paddingLen=0, good=false
     ```

**3. 测试证书选择逻辑 (`getCertificate`)**

   - **功能:** 当客户端发起 TLS 连接时，可以通过 SNI (Server Name Indication) 告知服务器它想要连接哪个域名。服务器根据 SNI 选择与该域名匹配的证书。
   - **代码推理:** `TestCertificateSelection` 函数创建了一个 `Config` 结构体，其中包含了多个 `Certificate`。每个 `Certificate` 对应一个域名（或通配符域名）。`config.BuildNameToCertificate()`  很可能预处理这些证书，建立域名到证书的映射。然后，通过模拟不同的 `ServerName` 的 `ClientHelloInfo`，调用 `config.getCertificate()` 来测试证书选择是否正确。
   - **代码示例 (推测，基于测试代码):**
     ```go
     type Config struct {
         Certificates []Certificate
         NameToCertificate map[string]*Certificate
     }

     type Certificate struct {
         Certificate [][]byte
         // ... 其他证书相关信息
     }

     type ClientHelloInfo struct {
         ServerName string
     }

     func (c *Config) BuildNameToCertificate() {
         c.NameToCertificate = make(map[string]*Certificate)
         for i := range c.Certificates {
             cert := &c.Certificates[i]
             // 假设证书中包含了域名信息，这里简化处理
             // 实际情况会解析证书的 Subject Alternative Name 等字段
             domain := extractDomainFromCertificate(cert)
             c.NameToCertificate[domain] = cert
         }
     }

     func (c *Config) getCertificate(clientHello *ClientHelloInfo) (*Certificate, error) {
         if cert, ok := c.NameToCertificate[clientHello.ServerName]; ok {
             return cert, nil
         }
         // 处理通配符匹配等更复杂的情况
         return nil, fmt.Errorf("no certificate for %s", clientHello.ServerName)
     }

     func extractDomainFromCertificate(cert *Certificate) string {
         // 实际实现会解析 X.509 证书
         if bytes.Contains(cert.Certificate[0], []byte("example.com")) {
             return "example.com"
         } else if bytes.Contains(cert.Certificate[0], []byte("*.example.com")) {
             return "*.example.com"
         } else if bytes.Contains(cert.Certificate[0], []byte("foo.example.com")) {
             return "foo.example.com"
         }
         return ""
     }

     // 假设输入与输出 (基于测试用例):
     // clientHello := &ClientHelloInfo{ServerName: "example.com"}
     // config.getCertificate(clientHello) -> 返回与 "example.com" 关联的证书

     // clientHello := &ClientHelloInfo{ServerName: "bar.example.com"}
     // config.getCertificate(clientHello) -> 返回与 "*.example.com" 关联的证书

     // clientHello := &ClientHelloInfo{ServerName: "foo.example.com"}
     // config.getCertificate(clientHello) -> 返回与 "foo.example.com" 关联的证书
     ```

**4. 测试动态调整 TLS 记录大小的功能**

   - **功能:** TLS 允许将应用数据分成多个记录进行传输。动态记录大小调整功能根据网络状况（例如，估计的 MSS - 最大报文段大小）来调整每个记录的大小，以提高传输效率并避免 IP 分片。
   - **代码推理:** `runDynamicRecordSizingTest` 函数创建了客户端和服务器端的 TLS 连接，并模拟了服务器发送不同大小的数据。它检查客户端接收到的 TLS 记录的大小，验证动态记录大小调整是否按预期工作。例如，在连接初期或网络状况不佳时，记录大小可能会较小，之后逐渐增大到最大值。
   - **命令行参数:**  此测试本身不直接处理命令行参数。它通过 Go 的 `testing` 包运行。`testing` 包提供了一些命令行标志（例如 `-v` 用于显示详细输出），但这些标志不是 `conn_test.go` 特有的。
   - **假设输入与输出:**  该测试没有明确的 "输入"，它的逻辑在于配置不同的 TLS 参数（例如 CipherSuites，TLS 版本）来触发不同的动态记录大小调整行为，并验证输出的记录大小是否符合预期。 输出是客户端接收到的 TLS 记录的大小序列。
   - **易犯错的点:**  使用者在配置 TLS 连接时，可能会错误地认为设置了 `MaxRecordSize` 就会固定记录的大小。但实际上，动态记录大小调整可能会根据网络情况调整记录大小，即使设置了 `MaxRecordSize` 也可能不会立即达到该值。

**5. 测试在关闭连接时可能出现的“发夹弯” (hairpin) 情况**

   - **功能:**  当 TLS 连接关闭时，底层的网络连接也会被关闭。在某些情况下，关闭底层连接的操作可能会触发 TLS 连接内部的回调（例如，获取连接状态）。如果处理不当，这种回调可能会导致死锁。此测试模拟这种情况，确保不会发生死锁。
   - **代码推理:** `hairpinConn` 结构体包装了一个 `net.Conn`，并在其 `Close()` 方法中调用了 `tlsConn.ConnectionState()`。这模拟了关闭底层连接时回调 TLS 连接内部方法的情况。`TestHairpinInClose` 测试确保在这种情况下调用 `tlsConn.Close()` 不会发生死锁。

**6. 测试处理接收到错误版本 TLS 记录的情况**

   - **功能:**  TLS 协议的版本协商是连接建立的重要部分。如果连接建立后，接收到不符合当前协商版本的 TLS 记录，则可能是协议错误或攻击。此测试验证 TLS 实现能够正确检测并处理这种情况。
   - **代码推理:** `TestRecordBadVersionTLS13` 创建了一个 TLS 1.3 连接，然后在客户端人为地修改了 TLS 记录的版本号。服务器尝试读取数据时，应该会检测到版本不匹配并返回错误。
   - **假设输入与输出:**
     - **输入:** 客户端发送一个 TLS 记录，其版本号被修改为 `0x1111`。
     - **输出:** 服务器尝试读取数据时返回一个特定的错误，例如 "tls: received record with version 1111 when expecting version 303"。

总而言之，`go/src/crypto/tls/conn_test.go` 文件通过各种测试用例，细致地验证了 Go 语言 `crypto/tls` 包中 TLS 连接建立、数据传输、证书选择、记录大小调整以及错误处理等关键功能的正确性和健壮性。 这对于确保 Go 语言实现的 TLS 协议的安全性至关重要。

Prompt: 
```
这是路径为go/src/crypto/tls/conn_test.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。

"""
// Copyright 2010 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

import (
	"bytes"
	"io"
	"net"
	"testing"
)

func TestRoundUp(t *testing.T) {
	if roundUp(0, 16) != 0 ||
		roundUp(1, 16) != 16 ||
		roundUp(15, 16) != 16 ||
		roundUp(16, 16) != 16 ||
		roundUp(17, 16) != 32 {
		t.Error("roundUp broken")
	}
}

// will be initialized with {0, 255, 255, ..., 255}
var padding255Bad = [256]byte{}

// will be initialized with {255, 255, 255, ..., 255}
var padding255Good = [256]byte{255}

var paddingTests = []struct {
	in          []byte
	good        bool
	expectedLen int
}{
	{[]byte{1, 2, 3, 4, 0}, true, 4},
	{[]byte{1, 2, 3, 4, 0, 1}, false, 0},
	{[]byte{1, 2, 3, 4, 99, 99}, false, 0},
	{[]byte{1, 2, 3, 4, 1, 1}, true, 4},
	{[]byte{1, 2, 3, 2, 2, 2}, true, 3},
	{[]byte{1, 2, 3, 3, 3, 3}, true, 2},
	{[]byte{1, 2, 3, 4, 3, 3}, false, 0},
	{[]byte{1, 4, 4, 4, 4, 4}, true, 1},
	{[]byte{5, 5, 5, 5, 5, 5}, true, 0},
	{[]byte{6, 6, 6, 6, 6, 6}, false, 0},
	{padding255Bad[:], false, 0},
	{padding255Good[:], true, 0},
}

func TestRemovePadding(t *testing.T) {
	for i := 1; i < len(padding255Bad); i++ {
		padding255Bad[i] = 255
		padding255Good[i] = 255
	}
	for i, test := range paddingTests {
		paddingLen, good := extractPadding(test.in)
		expectedGood := byte(255)
		if !test.good {
			expectedGood = 0
		}
		if good != expectedGood {
			t.Errorf("#%d: wrong validity, want:%d got:%d", i, expectedGood, good)
		}
		if good == 255 && len(test.in)-paddingLen != test.expectedLen {
			t.Errorf("#%d: got %d, want %d", i, len(test.in)-paddingLen, test.expectedLen)
		}
	}
}

var certExampleCom = `308201713082011ba003020102021005a75ddf21014d5f417083b7a010ba2e300d06092a864886f70d01010b050030123110300e060355040a130741636d6520436f301e170d3136303831373231343135335a170d3137303831373231343135335a30123110300e060355040a130741636d6520436f305c300d06092a864886f70d0101010500034b003048024100b37f0fdd67e715bf532046ac34acbd8fdc4dabe2b598588f3f58b1f12e6219a16cbfe54d2b4b665396013589262360b6721efa27d546854f17cc9aeec6751db10203010001a34d304b300e0603551d0f0101ff0404030205a030130603551d25040c300a06082b06010505070301300c0603551d130101ff0402300030160603551d11040f300d820b6578616d706c652e636f6d300d06092a864886f70d01010b050003410059fc487866d3d855503c8e064ca32aac5e9babcece89ec597f8b2b24c17867f4a5d3b4ece06e795bfc5448ccbd2ffca1b3433171ebf3557a4737b020565350a0`

var certWildcardExampleCom = `308201743082011ea003020102021100a7aa6297c9416a4633af8bec2958c607300d06092a864886f70d01010b050030123110300e060355040a130741636d6520436f301e170d3136303831373231343231395a170d3137303831373231343231395a30123110300e060355040a130741636d6520436f305c300d06092a864886f70d0101010500034b003048024100b105afc859a711ee864114e7d2d46c2dcbe392d3506249f6c2285b0eb342cc4bf2d803677c61c0abde443f084745c1a6d62080e5664ef2cc8f50ad8a0ab8870b0203010001a34f304d300e0603551d0f0101ff0404030205a030130603551d25040c300a06082b06010505070301300c0603551d130101ff0402300030180603551d110411300f820d2a2e6578616d706c652e636f6d300d06092a864886f70d01010b0500034100af26088584d266e3f6566360cf862c7fecc441484b098b107439543144a2b93f20781988281e108c6d7656934e56950e1e5f2bcf38796b814ccb729445856c34`

var certFooExampleCom = `308201753082011fa00302010202101bbdb6070b0aeffc49008cde74deef29300d06092a864886f70d01010b050030123110300e060355040a130741636d6520436f301e170d3136303831373231343234345a170d3137303831373231343234345a30123110300e060355040a130741636d6520436f305c300d06092a864886f70d0101010500034b003048024100f00ac69d8ca2829f26216c7b50f1d4bbabad58d447706476cd89a2f3e1859943748aa42c15eedc93ac7c49e40d3b05ed645cb6b81c4efba60d961f44211a54eb0203010001a351304f300e0603551d0f0101ff0404030205a030130603551d25040c300a06082b06010505070301300c0603551d130101ff04023000301a0603551d1104133011820f666f6f2e6578616d706c652e636f6d300d06092a864886f70d01010b0500034100a0957fca6d1e0f1ef4b247348c7a8ca092c29c9c0ecc1898ea6b8065d23af6d922a410dd2335a0ea15edd1394cef9f62c9e876a21e35250a0b4fe1ddceba0f36`

func TestCertificateSelection(t *testing.T) {
	config := Config{
		Certificates: []Certificate{
			{
				Certificate: [][]byte{fromHex(certExampleCom)},
			},
			{
				Certificate: [][]byte{fromHex(certWildcardExampleCom)},
			},
			{
				Certificate: [][]byte{fromHex(certFooExampleCom)},
			},
		},
	}

	config.BuildNameToCertificate()

	pointerToIndex := func(c *Certificate) int {
		for i := range config.Certificates {
			if c == &config.Certificates[i] {
				return i
			}
		}
		return -1
	}

	certificateForName := func(name string) *Certificate {
		clientHello := &ClientHelloInfo{
			ServerName: name,
		}
		if cert, err := config.getCertificate(clientHello); err != nil {
			t.Errorf("unable to get certificate for name '%s': %s", name, err)
			return nil
		} else {
			return cert
		}
	}

	if n := pointerToIndex(certificateForName("example.com")); n != 0 {
		t.Errorf("example.com returned certificate %d, not 0", n)
	}
	if n := pointerToIndex(certificateForName("bar.example.com")); n != 1 {
		t.Errorf("bar.example.com returned certificate %d, not 1", n)
	}
	if n := pointerToIndex(certificateForName("foo.example.com")); n != 2 {
		t.Errorf("foo.example.com returned certificate %d, not 2", n)
	}
	if n := pointerToIndex(certificateForName("foo.bar.example.com")); n != 0 {
		t.Errorf("foo.bar.example.com returned certificate %d, not 0", n)
	}
}

// Run with multiple crypto configs to test the logic for computing TLS record overheads.
func runDynamicRecordSizingTest(t *testing.T, config *Config) {
	clientConn, serverConn := localPipe(t)

	serverConfig := config.Clone()
	serverConfig.DynamicRecordSizingDisabled = false
	tlsConn := Server(serverConn, serverConfig)

	handshakeDone := make(chan struct{})
	recordSizesChan := make(chan []int, 1)
	defer func() { <-recordSizesChan }() // wait for the goroutine to exit
	go func() {
		// This goroutine performs a TLS handshake over clientConn and
		// then reads TLS records until EOF. It writes a slice that
		// contains all the record sizes to recordSizesChan.
		defer close(recordSizesChan)
		defer clientConn.Close()

		tlsConn := Client(clientConn, config)
		if err := tlsConn.Handshake(); err != nil {
			t.Errorf("Error from client handshake: %v", err)
			return
		}
		close(handshakeDone)

		var recordHeader [recordHeaderLen]byte
		var record []byte
		var recordSizes []int

		for {
			n, err := io.ReadFull(clientConn, recordHeader[:])
			if err == io.EOF {
				break
			}
			if err != nil || n != len(recordHeader) {
				t.Errorf("io.ReadFull = %d, %v", n, err)
				return
			}

			length := int(recordHeader[3])<<8 | int(recordHeader[4])
			if len(record) < length {
				record = make([]byte, length)
			}

			n, err = io.ReadFull(clientConn, record[:length])
			if err != nil || n != length {
				t.Errorf("io.ReadFull = %d, %v", n, err)
				return
			}

			recordSizes = append(recordSizes, recordHeaderLen+length)
		}

		recordSizesChan <- recordSizes
	}()

	if err := tlsConn.Handshake(); err != nil {
		t.Fatalf("Error from server handshake: %s", err)
	}
	<-handshakeDone

	// The server writes these plaintexts in order.
	plaintext := bytes.Join([][]byte{
		bytes.Repeat([]byte("x"), recordSizeBoostThreshold),
		bytes.Repeat([]byte("y"), maxPlaintext*2),
		bytes.Repeat([]byte("z"), maxPlaintext),
	}, nil)

	if _, err := tlsConn.Write(plaintext); err != nil {
		t.Fatalf("Error from server write: %s", err)
	}
	if err := tlsConn.Close(); err != nil {
		t.Fatalf("Error from server close: %s", err)
	}

	recordSizes := <-recordSizesChan
	if recordSizes == nil {
		t.Fatalf("Client encountered an error")
	}

	// Drop the size of the second to last record, which is likely to be
	// truncated, and the last record, which is a close_notify alert.
	recordSizes = recordSizes[:len(recordSizes)-2]

	// recordSizes should contain a series of records smaller than
	// tcpMSSEstimate followed by some larger than maxPlaintext.
	seenLargeRecord := false
	for i, size := range recordSizes {
		if !seenLargeRecord {
			if size > (i+1)*tcpMSSEstimate {
				t.Fatalf("Record #%d has size %d, which is too large too soon", i, size)
			}
			if size >= maxPlaintext {
				seenLargeRecord = true
			}
		} else if size <= maxPlaintext {
			t.Fatalf("Record #%d has size %d but should be full sized", i, size)
		}
	}

	if !seenLargeRecord {
		t.Fatalf("No large records observed")
	}
}

func TestDynamicRecordSizingWithStreamCipher(t *testing.T) {
	skipFIPS(t) // No RC4 in FIPS mode.

	config := testConfig.Clone()
	config.MaxVersion = VersionTLS12
	config.CipherSuites = []uint16{TLS_RSA_WITH_RC4_128_SHA}
	runDynamicRecordSizingTest(t, config)
}

func TestDynamicRecordSizingWithCBC(t *testing.T) {
	skipFIPS(t) // No CBC cipher suites in defaultCipherSuitesFIPS.

	config := testConfig.Clone()
	config.MaxVersion = VersionTLS12
	config.CipherSuites = []uint16{TLS_RSA_WITH_AES_256_CBC_SHA}
	runDynamicRecordSizingTest(t, config)
}

func TestDynamicRecordSizingWithAEAD(t *testing.T) {
	config := testConfig.Clone()
	config.MaxVersion = VersionTLS12
	config.CipherSuites = []uint16{TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256}
	runDynamicRecordSizingTest(t, config)
}

func TestDynamicRecordSizingWithTLSv13(t *testing.T) {
	config := testConfig.Clone()
	runDynamicRecordSizingTest(t, config)
}

// hairpinConn is a net.Conn that makes a “hairpin” call when closed, back into
// the tls.Conn which is calling it.
type hairpinConn struct {
	net.Conn
	tlsConn *Conn
}

func (conn *hairpinConn) Close() error {
	conn.tlsConn.ConnectionState()
	return nil
}

func TestHairpinInClose(t *testing.T) {
	// This tests that the underlying net.Conn can call back into the
	// tls.Conn when being closed without deadlocking.
	client, server := localPipe(t)
	defer server.Close()
	defer client.Close()

	conn := &hairpinConn{client, nil}
	tlsConn := Server(conn, &Config{
		GetCertificate: func(*ClientHelloInfo) (*Certificate, error) {
			panic("unreachable")
		},
	})
	conn.tlsConn = tlsConn

	// This call should not deadlock.
	tlsConn.Close()
}

func TestRecordBadVersionTLS13(t *testing.T) {
	client, server := localPipe(t)
	defer server.Close()
	defer client.Close()

	config := testConfig.Clone()
	config.MinVersion, config.MaxVersion = VersionTLS13, VersionTLS13

	go func() {
		tlsConn := Client(client, config)
		if err := tlsConn.Handshake(); err != nil {
			t.Errorf("Error from client handshake: %v", err)
			return
		}
		tlsConn.vers = 0x1111
		tlsConn.Write([]byte{1})
	}()

	tlsConn := Server(server, config)
	if err := tlsConn.Handshake(); err != nil {
		t.Errorf("Error from client handshake: %v", err)
		return
	}

	expectedErr := "tls: received record with version 1111 when expecting version 303"

	_, err := tlsConn.Read(make([]byte, 10))
	if err.Error() != expectedErr {
		t.Fatalf("unexpected error: got %q, want %q", err, expectedErr)
	}
}

"""



```