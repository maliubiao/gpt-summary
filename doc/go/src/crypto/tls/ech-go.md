Response:
The user wants to understand the functionality of the provided Go code snippet. This code seems to implement Encrypted Client Hello (ECH), a privacy-enhancing feature for TLS.

Here's a breakdown of the thought process to generate the answer:

1. **Identify the core functionality:**  The package name `tls` and the file name `ech.go` strongly suggest this code deals with TLS and specifically ECH. Keywords like `ECHConfig`, `encryptedClientHello`, `innerClientHello`, and `outerClientHello` reinforce this.

2. **Analyze key data structures:**
    * `echConfig`:  Represents the server's ECH configuration. It contains information like the KEM ID, public key, supported ciphersuites, and the public name.
    * `echCipher`: Represents a supported cipher suite for ECH, consisting of KDF and AEAD algorithms.
    * `echExtension`: A generic extension within the ECHConfig.

3. **Analyze key functions and their purpose:**
    * `parseECHConfig`, `parseECHConfigList`: Functions for parsing the binary representation of ECH configurations.
    * `pickECHConfig`:  Selects a suitable ECH configuration from a list, considering supported algorithms and mandatory extensions.
    * `encodeInnerClientHello`, `decodeInnerClientHello`:  Handle the creation and reconstruction of the "inner" ClientHello, which is encrypted.
    * `decryptECHPayload`:  Decrypts the encrypted part of the ClientHello.
    * `generateOuterECHExt`: Creates the ECH extension that wraps the encrypted inner ClientHello.
    * `computeAndUpdateOuterECHExtension`:  Combines the inner ClientHello, encryption, and the creation of the outer ECH extension.
    * `processECHClientHello`:  The server-side logic for processing a ClientHello that includes ECH.
    * `buildRetryConfigList`:  Constructs a list of ECH configurations for the server to send back to the client in case of rejection.

4. **Infer the overall ECH workflow:** The code seems to implement both the client and server sides of ECH. The client encrypts a modified ClientHello (the "inner" one) and wraps it in an ECH extension in the real ClientHello (the "outer" one). The server receives this, decrypts it, and processes the inner ClientHello.

5. **Illustrate with Go code examples:**  Create simple examples to show:
    * Parsing an `ECHConfigList`.
    * Selecting an `ECHConfig`.
    * Encoding and decoding the inner ClientHello.
    * The server-side processing of ECH.

6. **Address potential user errors:** Think about common mistakes when dealing with TLS extensions and complex configurations:
    * Incorrectly formatting the `ECHConfigList`.
    * Providing an unsupported KEM, KDF, or AEAD algorithm.
    * Not handling the retry mechanism correctly.

7. **Consider command-line arguments:**  While the code itself doesn't directly process command-line arguments, think about where these configurations might come from in a real-world application (e.g., configuration files, command-line flags). Mention the possibility but acknowledge the code doesn't handle it directly.

8. **Structure the answer clearly:**  Use headings and bullet points to organize the information logically. Start with a high-level summary and then go into more detail.

9. **Use precise terminology:**  Refer to "inner ClientHello," "outer ClientHello," "ECHConfig," etc., to maintain accuracy.

10. **Review and refine:**  Read through the generated answer to ensure clarity, accuracy, and completeness. For instance, initially, I might have focused too much on individual functions. The refinement step ensures the explanation covers the overall flow and purpose.
这段代码是 Go 语言 `crypto/tls` 包中关于 **Encrypted Client Hello (ECH)** 功能的一部分实现。ECH 是一种 TLS 扩展，旨在加密 TLS 握手过程中的 ClientHello 消息的大部分内容，以提高用户隐私。

以下是这段代码的主要功能：

1. **定义了 ECH 相关的数据结构:**
   - `echConfig`: 表示服务器提供的 ECH 配置信息，包含了版本、配置 ID、密钥协商算法 (KEM) ID、公钥、对称加密套件、最大名称长度、公共名称和扩展信息。
   - `echCipher`: 表示 ECH 使用的对称加密套件，包含密钥派生函数 (KDF) ID 和认证加密与关联数据 (AEAD) 算法 ID。
   - `echExtension`: 表示 ECH 配置中的扩展信息。
   - `echExtType`:  枚举类型，用于区分 ECH 扩展是内部的还是外部的。

2. **实现了 ECH 配置的解析:**
   - `parseECHConfig(enc []byte)`: 解析单个 `ECHConfig` 的二进制数据。它负责从字节数组中读取各个字段，并进行基本的格式验证。如果版本不匹配或者数据格式错误，会返回相应的错误。如果 `ECHConfig` 的版本不是 `extensionEncryptedClientHello`，则会跳过解析。
   - `parseECHConfigList(data []byte)`: 解析 `ECHConfigList`，它是一个包含多个 `ECHConfig` 的列表。该函数首先读取列表的长度，然后循环解析每个 `ECHConfig`。

3. **实现了 ECH 配置的选择:**
   - `pickECHConfig(list []echConfig)`:  从解析后的 `ECHConfig` 列表中选择一个客户端支持的配置。选择的标准包括：
     - 服务器使用的 KEM 算法是否被客户端支持 (`hpke.SupportedKEMs`)。
     - 服务器提供的对称加密套件中的 KDF 和 AEAD 算法是否都被客户端支持 (`hpke.SupportedKDFs`, `hpke.SupportedAEADs`)。
     - `PublicName` 是否是有效的 DNS 名称 (`validDNSName`)。
     - 是否存在客户端不支持的**强制**扩展（高位设置为 1 的扩展）。

4. **实现了内部 ClientHello 的编码和解码:**
   - `encodeInnerClientHello(inner *clientHelloMsg, maxNameLength int)`: 将内部的 ClientHello 消息编码为字节数组。内部 ClientHello 是实际要发送的 ClientHello 消息，但其 `server_name` 扩展会被加密。此函数还会添加填充，以隐藏原始 `server_name` 的长度。
   - `decodeInnerClientHello(outer *clientHelloMsg, encoded []byte)`: 从加密后的字节数组中解码出内部的 ClientHello 消息。这个过程比较复杂，因为它需要从外部的 ClientHello 中提取原始扩展信息，并将其重新插入到内部 ClientHello 中，以恢复原始的扩展顺序。

5. **实现了 ECH 负载的加密和解密:**
   - `decryptECHPayload(context *hpke.Receipient, hello, payload []byte)`: 使用 HPKE（Hybrid Public Key Encryption）解密 ECH 的负载数据。负载数据包含加密后的内部 ClientHello。

6. **实现了外部 ECH 扩展的生成:**
   - `generateOuterECHExt(id uint8, kdfID, aeadID uint16, encodedKey []byte, payload []byte)`:  生成外部的 ECH 扩展数据。外部 ECH 扩展包含了加密后的内部 ClientHello 以及相关的元数据，例如使用的 KDF、AEAD 算法 ID，配置 ID 和封装的密钥。

7. **实现了外部 ECH 扩展的计算和更新:**
   - `computeAndUpdateOuterECHExtension(outer, inner *clientHelloMsg, ech *echClientContext, useKey bool)`:  计算并更新外部的 ECH 扩展。它首先编码内部 ClientHello，然后使用 HPKE 加密，最后生成包含加密后数据的外部 ECH 扩展。

8. **实现了服务器端对 ECH ClientHello 的处理:**
   - `processECHClientHello(outer *clientHelloMsg)`: 服务器端处理包含 ECH 扩展的 ClientHello 消息。它会解析 ECH 扩展，尝试解密内部 ClientHello，并返回解密后的内部 ClientHello 消息和一个 `echServerContext` 对象。如果解密失败，则可能返回原始的外部 ClientHello。

9. **定义了 ECH 拒绝错误:**
   - `ECHRejectionError`:  当服务器拒绝 ECH 连接时返回的错误类型。它可能包含一个 `RetryConfigList`，供客户端重试。

10. **定义了辅助函数:**
    - `validDNSName(name string)`:  一个简单的 DNS 名称验证函数，用于检查 ECH 配置中的 `PublicName` 是否有效。
    - `skipUint8LengthPrefixed`, `skipUint16LengthPrefixed`:  用于跳过具有长度前缀的字节序列。
    - `extractRawExtensions(hello *clientHelloMsg)`: 从外部 ClientHello 中提取原始的扩展信息。
    - `marshalEncryptedClientHelloConfigList(configs []EncryptedClientHelloKey)`:  将 ECH 配置列表序列化为字节数组。
    - `buildRetryConfigList(keys []EncryptedClientHelloKey)`: 构建用于重试的 ECH 配置列表。

**这段代码实现了 ECH 协议的核心逻辑，包括配置的解析、选择、ClientHello 的加密和解密，以及服务器端的处理流程。**

**Go 代码举例说明:**

假设我们有一个 ECH 配置列表的字节数组 `echConfigListData`，我们可以使用 `parseECHConfigList` 来解析它：

```go
package main

import (
	"fmt"
	"log"

	"go/src/crypto/tls" // 假设你的代码在这个路径下
)

func main() {
	// 假设这是从某个地方获取的 ECHConfigList 的字节数组
	echConfigListData := []byte{
		0x00, 0x2a, // Length of the ECHConfigList (42 bytes)
		0x00, 0x26, // Length of the first ECHConfig (38 bytes)
		0xff, 0x0a, // Version (extensionEncryptedClientHello)
		0x00, 0x22, // Length of the ECHConfig (34 bytes)
		0x01,       // ConfigID
		0x00, 0x20, // KemID (DHKEM_X25519_HKDF_SHA256)
		0x00, 0x20, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, // PublicKey (32 bytes)
		0x00, 0x04, // Length of SymmetricCipherSuite (4 bytes)
		0x00, 0x01, // KDFID (HKDF_SHA256)
		0x00, 0x01, // AEADID (AEAD_AES128GCM)
		0x05,       // MaxNameLength
		0x00, 0x04, 0x74, 0x65, 0x73, 0x74, // PublicName ("test")
		0x00, 0x00, // Extensions Length (0 bytes)
	}

	configs, err := tls.ParseECHConfigList(echConfigListData)
	if err != nil {
		log.Fatalf("解析 ECHConfigList 失败: %v", err)
	}

	fmt.Printf("解析到的 ECHConfig 数量: %d\n", len(configs))
	if len(configs) > 0 {
		fmt.Printf("第一个 ECHConfig 的版本: 0x%x\n", configs[0].Version)
		fmt.Printf("第一个 ECHConfig 的 ConfigID: %d\n", configs[0].ConfigID)
		fmt.Printf("第一个 ECHConfig 的 KemID: 0x%x\n", configs[0].KemID)
		fmt.Printf("第一个 ECHConfig 的 PublicKey: %x\n", configs[0].PublicKey)
		fmt.Printf("第一个 ECHConfig 的 SymmetricCipherSuite: %+v\n", configs[0].SymmetricCipherSuite)
		fmt.Printf("第一个 ECHConfig 的 MaxNameLength: %d\n", configs[0].MaxNameLength)
		fmt.Printf("第一个 ECHConfig 的 PublicName: %s\n", configs[0].PublicName)
	}
}
```

**假设的输入与输出:**

**输入:** `echConfigListData` 如上述代码所示。

**输出:**

```
解析到的 ECHConfig 数量: 1
第一个 ECHConfig 的版本: 0xff0a
第一个 ECHConfig 的 ConfigID: 1
第一个 ECHConfig 的 KemID: 0x20
第一个 ECHConfig 的 PublicKey: aabbccddeeff00112233445566778899aabbccddeeff0011223344556677
第一个 ECHConfig 的 SymmetricCipherSuite: [{KDFID:1 AEADID:1}]
第一个 ECHConfig 的 MaxNameLength: 5
第一个 ECHConfig 的 PublicName: test
```

**代码推理:**

- `parseECHConfigList` 函数首先读取了 `echConfigListData` 的前两个字节 `0x00, 0x2a`，表示整个列表的长度为 42 字节。
- 然后，它读取接下来的两个字节 `0x00, 0x26`，表示第一个 `ECHConfig` 的长度为 38 字节。
- 接着调用 `parseECHConfig` 解析第一个 `ECHConfig`，它会读取版本、长度、ConfigID、KemID、PublicKey 等字段。
- 例如，读取 KemID 时，会读取两个字节 `0x00, 0x20`，对应 `hpke.DHKEM_X25519_HKDF_SHA256`。
- 读取 PublicKey 时，会先读取长度 `0x00, 0x20` (32 字节)，然后读取后面的 32 字节公钥数据。
- SymmetricCipherSuite 的长度为 `0x00, 0x04`，包含一个 `echCipher` 结构，KDFID 和 AEADID 分别为 `0x00, 0x01`。
- 最终解析出 `MaxNameLength` 为 5，`PublicName` 的长度为 4，内容为 "test"。

**命令行参数的具体处理:**

这段代码本身并不直接处理命令行参数。ECH 配置通常是通过以下方式获取：

1. **DNS 查询:** 客户端可以查询特定类型的 DNS 记录（例如 HTTPS 记录）来获取服务器的 ECH 配置。
2. **本地配置:** 某些客户端可能允许用户手动配置 ECH 参数。
3. **通过其他协议或机制获取:** 例如，通过一个单独的 API 或配置文件。

具体的命令行参数处理逻辑会存在于使用 `crypto/tls` 包构建的更上层的应用程序中。例如，一个支持 ECH 的 HTTP 客户端可能会有类似 `--ech-config-list` 的命令行参数，允许用户指定一个本地的 ECH 配置列表。

**使用者易犯错的点:**

1. **`ECHConfigList` 格式错误:** 手动创建或修改 `ECHConfigList` 的字节数组时，很容易出错，例如长度字段不正确、字段顺序错误或数据类型不匹配。这会导致解析失败。

   **例如:** 如果将上述例子中的 `echConfigListData` 的总长度 `0x00, 0x2a` 修改为错误的值，`parseECHConfigList` 将会返回 `errMalformedECHConfig` 错误。

2. **不支持的 KEM、KDF 或 AEAD 算法:**  客户端和服务端需要支持相同的 HPKE 算法套件。如果服务器提供的 `ECHConfig` 中包含客户端不支持的算法，`pickECHConfig` 将会返回 `nil`，导致 ECH 协商失败。

   **例如:** 如果服务器配置了使用 `KEM_P256`，但客户端的 `hpke.SupportedKEMs` 中没有包含这个算法，则该配置会被跳过。

3. **强制扩展不被支持:** 如果 `ECHConfig` 中包含高位设置为 1 的扩展，表示这是一个强制扩展。如果客户端不理解或不支持这个扩展，`pickECHConfig` 会跳过该配置。

4. **重试机制处理不当:**  客户端在收到 `ECHRejectionError` 时，应该正确解析 `RetryConfigList` 并尝试使用新的配置进行重连。如果客户端忽略或错误地处理重试配置，可能导致连接失败。

5. **服务端密钥配置错误:** 服务器端需要在 `tls.Config` 中配置正确的 `EncryptedClientHelloKeys`，包括私钥和对应的 `ECHConfig`。配置错误会导致解密失败。

理解 ECH 的规范和流程对于避免这些错误至关重要。这段代码提供的是底层的构建块，上层应用需要正确地使用这些功能来实现完整的 ECH 支持。

### 提示词
```
这是路径为go/src/crypto/tls/ech.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
```

### 源代码
```go
// Copyright 2024 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

import (
	"bytes"
	"crypto/internal/hpke"
	"errors"
	"fmt"
	"slices"
	"strings"

	"golang.org/x/crypto/cryptobyte"
)

// sortedSupportedAEADs is just a sorted version of hpke.SupportedAEADS.
// We need this so that when we insert them into ECHConfigs the ordering
// is stable.
var sortedSupportedAEADs []uint16

func init() {
	for aeadID := range hpke.SupportedAEADs {
		sortedSupportedAEADs = append(sortedSupportedAEADs, aeadID)
	}
	slices.Sort(sortedSupportedAEADs)
}

type echCipher struct {
	KDFID  uint16
	AEADID uint16
}

type echExtension struct {
	Type uint16
	Data []byte
}

type echConfig struct {
	raw []byte

	Version uint16
	Length  uint16

	ConfigID             uint8
	KemID                uint16
	PublicKey            []byte
	SymmetricCipherSuite []echCipher

	MaxNameLength uint8
	PublicName    []byte
	Extensions    []echExtension
}

var errMalformedECHConfig = errors.New("tls: malformed ECHConfigList")

func parseECHConfig(enc []byte) (skip bool, ec echConfig, err error) {
	s := cryptobyte.String(enc)
	ec.raw = []byte(enc)
	if !s.ReadUint16(&ec.Version) {
		return false, echConfig{}, errMalformedECHConfig
	}
	if !s.ReadUint16(&ec.Length) {
		return false, echConfig{}, errMalformedECHConfig
	}
	if len(ec.raw) < int(ec.Length)+4 {
		return false, echConfig{}, errMalformedECHConfig
	}
	ec.raw = ec.raw[:ec.Length+4]
	if ec.Version != extensionEncryptedClientHello {
		s.Skip(int(ec.Length))
		return true, echConfig{}, nil
	}
	if !s.ReadUint8(&ec.ConfigID) {
		return false, echConfig{}, errMalformedECHConfig
	}
	if !s.ReadUint16(&ec.KemID) {
		return false, echConfig{}, errMalformedECHConfig
	}
	if !readUint16LengthPrefixed(&s, &ec.PublicKey) {
		return false, echConfig{}, errMalformedECHConfig
	}
	var cipherSuites cryptobyte.String
	if !s.ReadUint16LengthPrefixed(&cipherSuites) {
		return false, echConfig{}, errMalformedECHConfig
	}
	for !cipherSuites.Empty() {
		var c echCipher
		if !cipherSuites.ReadUint16(&c.KDFID) {
			return false, echConfig{}, errMalformedECHConfig
		}
		if !cipherSuites.ReadUint16(&c.AEADID) {
			return false, echConfig{}, errMalformedECHConfig
		}
		ec.SymmetricCipherSuite = append(ec.SymmetricCipherSuite, c)
	}
	if !s.ReadUint8(&ec.MaxNameLength) {
		return false, echConfig{}, errMalformedECHConfig
	}
	var publicName cryptobyte.String
	if !s.ReadUint8LengthPrefixed(&publicName) {
		return false, echConfig{}, errMalformedECHConfig
	}
	ec.PublicName = publicName
	var extensions cryptobyte.String
	if !s.ReadUint16LengthPrefixed(&extensions) {
		return false, echConfig{}, errMalformedECHConfig
	}
	for !extensions.Empty() {
		var e echExtension
		if !extensions.ReadUint16(&e.Type) {
			return false, echConfig{}, errMalformedECHConfig
		}
		if !extensions.ReadUint16LengthPrefixed((*cryptobyte.String)(&e.Data)) {
			return false, echConfig{}, errMalformedECHConfig
		}
		ec.Extensions = append(ec.Extensions, e)
	}

	return false, ec, nil
}

// parseECHConfigList parses a draft-ietf-tls-esni-18 ECHConfigList, returning a
// slice of parsed ECHConfigs, in the same order they were parsed, or an error
// if the list is malformed.
func parseECHConfigList(data []byte) ([]echConfig, error) {
	s := cryptobyte.String(data)
	var length uint16
	if !s.ReadUint16(&length) {
		return nil, errMalformedECHConfig
	}
	if length != uint16(len(data)-2) {
		return nil, errMalformedECHConfig
	}
	var configs []echConfig
	for len(s) > 0 {
		if len(s) < 4 {
			return nil, errors.New("tls: malformed ECHConfig")
		}
		configLen := uint16(s[2])<<8 | uint16(s[3])
		skip, ec, err := parseECHConfig(s)
		if err != nil {
			return nil, err
		}
		s = s[configLen+4:]
		if !skip {
			configs = append(configs, ec)
		}
	}
	return configs, nil
}

func pickECHConfig(list []echConfig) *echConfig {
	for _, ec := range list {
		if _, ok := hpke.SupportedKEMs[ec.KemID]; !ok {
			continue
		}
		var validSCS bool
		for _, cs := range ec.SymmetricCipherSuite {
			if _, ok := hpke.SupportedAEADs[cs.AEADID]; !ok {
				continue
			}
			if _, ok := hpke.SupportedKDFs[cs.KDFID]; !ok {
				continue
			}
			validSCS = true
			break
		}
		if !validSCS {
			continue
		}
		if !validDNSName(string(ec.PublicName)) {
			continue
		}
		var unsupportedExt bool
		for _, ext := range ec.Extensions {
			// If high order bit is set to 1 the extension is mandatory.
			// Since we don't support any extensions, if we see a mandatory
			// bit, we skip the config.
			if ext.Type&uint16(1<<15) != 0 {
				unsupportedExt = true
			}
		}
		if unsupportedExt {
			continue
		}
		return &ec
	}
	return nil
}

func pickECHCipherSuite(suites []echCipher) (echCipher, error) {
	for _, s := range suites {
		// NOTE: all of the supported AEADs and KDFs are fine, rather than
		// imposing some sort of preference here, we just pick the first valid
		// suite.
		if _, ok := hpke.SupportedAEADs[s.AEADID]; !ok {
			continue
		}
		if _, ok := hpke.SupportedKDFs[s.KDFID]; !ok {
			continue
		}
		return s, nil
	}
	return echCipher{}, errors.New("tls: no supported symmetric ciphersuites for ECH")
}

func encodeInnerClientHello(inner *clientHelloMsg, maxNameLength int) ([]byte, error) {
	h, err := inner.marshalMsg(true)
	if err != nil {
		return nil, err
	}
	h = h[4:] // strip four byte prefix

	var paddingLen int
	if inner.serverName != "" {
		paddingLen = max(0, maxNameLength-len(inner.serverName))
	} else {
		paddingLen = maxNameLength + 9
	}
	paddingLen = 31 - ((len(h) + paddingLen - 1) % 32)

	return append(h, make([]byte, paddingLen)...), nil
}

func skipUint8LengthPrefixed(s *cryptobyte.String) bool {
	var skip uint8
	if !s.ReadUint8(&skip) {
		return false
	}
	return s.Skip(int(skip))
}

func skipUint16LengthPrefixed(s *cryptobyte.String) bool {
	var skip uint16
	if !s.ReadUint16(&skip) {
		return false
	}
	return s.Skip(int(skip))
}

type rawExtension struct {
	extType uint16
	data    []byte
}

func extractRawExtensions(hello *clientHelloMsg) ([]rawExtension, error) {
	s := cryptobyte.String(hello.original)
	if !s.Skip(4+2+32) || // header, version, random
		!skipUint8LengthPrefixed(&s) || // session ID
		!skipUint16LengthPrefixed(&s) || // cipher suites
		!skipUint8LengthPrefixed(&s) { // compression methods
		return nil, errors.New("tls: malformed outer client hello")
	}
	var rawExtensions []rawExtension
	var extensions cryptobyte.String
	if !s.ReadUint16LengthPrefixed(&extensions) {
		return nil, errors.New("tls: malformed outer client hello")
	}

	for !extensions.Empty() {
		var extension uint16
		var extData cryptobyte.String
		if !extensions.ReadUint16(&extension) ||
			!extensions.ReadUint16LengthPrefixed(&extData) {
			return nil, errors.New("tls: invalid inner client hello")
		}
		rawExtensions = append(rawExtensions, rawExtension{extension, extData})
	}
	return rawExtensions, nil
}

func decodeInnerClientHello(outer *clientHelloMsg, encoded []byte) (*clientHelloMsg, error) {
	// Reconstructing the inner client hello from its encoded form is somewhat
	// complicated. It is missing its header (message type and length), session
	// ID, and the extensions may be compressed. Since we need to put the
	// extensions back in the same order as they were in the raw outer hello,
	// and since we don't store the raw extensions, or the order we parsed them
	// in, we need to reparse the raw extensions from the outer hello in order
	// to properly insert them into the inner hello. This _should_ result in raw
	// bytes which match the hello as it was generated by the client.
	innerReader := cryptobyte.String(encoded)
	var versionAndRandom, sessionID, cipherSuites, compressionMethods []byte
	var extensions cryptobyte.String
	if !innerReader.ReadBytes(&versionAndRandom, 2+32) ||
		!readUint8LengthPrefixed(&innerReader, &sessionID) ||
		len(sessionID) != 0 ||
		!readUint16LengthPrefixed(&innerReader, &cipherSuites) ||
		!readUint8LengthPrefixed(&innerReader, &compressionMethods) ||
		!innerReader.ReadUint16LengthPrefixed(&extensions) {
		return nil, errors.New("tls: invalid inner client hello")
	}

	// The specification says we must verify that the trailing padding is all
	// zeros. This is kind of weird for TLS messages, where we generally just
	// throw away any trailing garbage.
	for _, p := range innerReader {
		if p != 0 {
			return nil, errors.New("tls: invalid inner client hello")
		}
	}

	rawOuterExts, err := extractRawExtensions(outer)
	if err != nil {
		return nil, err
	}

	recon := cryptobyte.NewBuilder(nil)
	recon.AddUint8(typeClientHello)
	recon.AddUint24LengthPrefixed(func(recon *cryptobyte.Builder) {
		recon.AddBytes(versionAndRandom)
		recon.AddUint8LengthPrefixed(func(recon *cryptobyte.Builder) {
			recon.AddBytes(outer.sessionId)
		})
		recon.AddUint16LengthPrefixed(func(recon *cryptobyte.Builder) {
			recon.AddBytes(cipherSuites)
		})
		recon.AddUint8LengthPrefixed(func(recon *cryptobyte.Builder) {
			recon.AddBytes(compressionMethods)
		})
		recon.AddUint16LengthPrefixed(func(recon *cryptobyte.Builder) {
			for !extensions.Empty() {
				var extension uint16
				var extData cryptobyte.String
				if !extensions.ReadUint16(&extension) ||
					!extensions.ReadUint16LengthPrefixed(&extData) {
					recon.SetError(errors.New("tls: invalid inner client hello"))
					return
				}
				if extension == extensionECHOuterExtensions {
					if !extData.ReadUint8LengthPrefixed(&extData) {
						recon.SetError(errors.New("tls: invalid inner client hello"))
						return
					}
					var i int
					for !extData.Empty() {
						var extType uint16
						if !extData.ReadUint16(&extType) {
							recon.SetError(errors.New("tls: invalid inner client hello"))
							return
						}
						if extType == extensionEncryptedClientHello {
							recon.SetError(errors.New("tls: invalid outer extensions"))
							return
						}
						for ; i <= len(rawOuterExts); i++ {
							if i == len(rawOuterExts) {
								recon.SetError(errors.New("tls: invalid outer extensions"))
								return
							}
							if rawOuterExts[i].extType == extType {
								break
							}
						}
						recon.AddUint16(rawOuterExts[i].extType)
						recon.AddUint16LengthPrefixed(func(recon *cryptobyte.Builder) {
							recon.AddBytes(rawOuterExts[i].data)
						})
					}
				} else {
					recon.AddUint16(extension)
					recon.AddUint16LengthPrefixed(func(recon *cryptobyte.Builder) {
						recon.AddBytes(extData)
					})
				}
			}
		})
	})

	reconBytes, err := recon.Bytes()
	if err != nil {
		return nil, err
	}
	inner := &clientHelloMsg{}
	if !inner.unmarshal(reconBytes) {
		return nil, errors.New("tls: invalid reconstructed inner client hello")
	}

	if !bytes.Equal(inner.encryptedClientHello, []byte{uint8(innerECHExt)}) {
		return nil, errors.New("tls: client sent invalid encrypted_client_hello extension")
	}

	if len(inner.supportedVersions) != 1 || (len(inner.supportedVersions) >= 1 && inner.supportedVersions[0] != VersionTLS13) {
		return nil, errors.New("tls: client sent encrypted_client_hello extension and offered incompatible versions")
	}

	return inner, nil
}

func decryptECHPayload(context *hpke.Receipient, hello, payload []byte) ([]byte, error) {
	outerAAD := bytes.Replace(hello[4:], payload, make([]byte, len(payload)), 1)
	return context.Open(outerAAD, payload)
}

func generateOuterECHExt(id uint8, kdfID, aeadID uint16, encodedKey []byte, payload []byte) ([]byte, error) {
	var b cryptobyte.Builder
	b.AddUint8(0) // outer
	b.AddUint16(kdfID)
	b.AddUint16(aeadID)
	b.AddUint8(id)
	b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes(encodedKey) })
	b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes(payload) })
	return b.Bytes()
}

func computeAndUpdateOuterECHExtension(outer, inner *clientHelloMsg, ech *echClientContext, useKey bool) error {
	var encapKey []byte
	if useKey {
		encapKey = ech.encapsulatedKey
	}
	encodedInner, err := encodeInnerClientHello(inner, int(ech.config.MaxNameLength))
	if err != nil {
		return err
	}
	// NOTE: the tag lengths for all of the supported AEADs are the same (16
	// bytes), so we have hardcoded it here. If we add support for another AEAD
	// with a different tag length, we will need to change this.
	encryptedLen := len(encodedInner) + 16 // AEAD tag length
	outer.encryptedClientHello, err = generateOuterECHExt(ech.config.ConfigID, ech.kdfID, ech.aeadID, encapKey, make([]byte, encryptedLen))
	if err != nil {
		return err
	}
	serializedOuter, err := outer.marshal()
	if err != nil {
		return err
	}
	serializedOuter = serializedOuter[4:] // strip the four byte prefix
	encryptedInner, err := ech.hpkeContext.Seal(serializedOuter, encodedInner)
	if err != nil {
		return err
	}
	outer.encryptedClientHello, err = generateOuterECHExt(ech.config.ConfigID, ech.kdfID, ech.aeadID, encapKey, encryptedInner)
	if err != nil {
		return err
	}
	return nil
}

// validDNSName is a rather rudimentary check for the validity of a DNS name.
// This is used to check if the public_name in a ECHConfig is valid when we are
// picking a config. This can be somewhat lax because even if we pick a
// valid-looking name, the DNS layer will later reject it anyway.
func validDNSName(name string) bool {
	if len(name) > 253 {
		return false
	}
	labels := strings.Split(name, ".")
	if len(labels) <= 1 {
		return false
	}
	for _, l := range labels {
		labelLen := len(l)
		if labelLen == 0 {
			return false
		}
		for i, r := range l {
			if r == '-' && (i == 0 || i == labelLen-1) {
				return false
			}
			if (r < '0' || r > '9') && (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') && r != '-' {
				return false
			}
		}
	}
	return true
}

// ECHRejectionError is the error type returned when ECH is rejected by a remote
// server. If the server offered a ECHConfigList to use for retries, the
// RetryConfigList field will contain this list.
//
// The client may treat an ECHRejectionError with an empty set of RetryConfigs
// as a secure signal from the server.
type ECHRejectionError struct {
	RetryConfigList []byte
}

func (e *ECHRejectionError) Error() string {
	return "tls: server rejected ECH"
}

var errMalformedECHExt = errors.New("tls: malformed encrypted_client_hello extension")

type echExtType uint8

const (
	innerECHExt echExtType = 1
	outerECHExt echExtType = 0
)

func parseECHExt(ext []byte) (echType echExtType, cs echCipher, configID uint8, encap []byte, payload []byte, err error) {
	data := make([]byte, len(ext))
	copy(data, ext)
	s := cryptobyte.String(data)
	var echInt uint8
	if !s.ReadUint8(&echInt) {
		err = errMalformedECHExt
		return
	}
	echType = echExtType(echInt)
	if echType == innerECHExt {
		if !s.Empty() {
			err = errMalformedECHExt
			return
		}
		return echType, cs, 0, nil, nil, nil
	}
	if echType != outerECHExt {
		err = errMalformedECHExt
		return
	}
	if !s.ReadUint16(&cs.KDFID) {
		err = errMalformedECHExt
		return
	}
	if !s.ReadUint16(&cs.AEADID) {
		err = errMalformedECHExt
		return
	}
	if !s.ReadUint8(&configID) {
		err = errMalformedECHExt
		return
	}
	if !readUint16LengthPrefixed(&s, &encap) {
		err = errMalformedECHExt
		return
	}
	if !readUint16LengthPrefixed(&s, &payload) {
		err = errMalformedECHExt
		return
	}

	// NOTE: clone encap and payload so that mutating them does not mutate the
	// raw extension bytes.
	return echType, cs, configID, bytes.Clone(encap), bytes.Clone(payload), nil
}

func marshalEncryptedClientHelloConfigList(configs []EncryptedClientHelloKey) ([]byte, error) {
	builder := cryptobyte.NewBuilder(nil)
	builder.AddUint16LengthPrefixed(func(builder *cryptobyte.Builder) {
		for _, c := range configs {
			builder.AddBytes(c.Config)
		}
	})
	return builder.Bytes()
}

func (c *Conn) processECHClientHello(outer *clientHelloMsg) (*clientHelloMsg, *echServerContext, error) {
	echType, echCiphersuite, configID, encap, payload, err := parseECHExt(outer.encryptedClientHello)
	if err != nil {
		c.sendAlert(alertDecodeError)
		return nil, nil, errors.New("tls: client sent invalid encrypted_client_hello extension")
	}

	if echType == innerECHExt {
		return outer, &echServerContext{inner: true}, nil
	}

	if len(c.config.EncryptedClientHelloKeys) == 0 {
		return outer, nil, nil
	}

	for _, echKey := range c.config.EncryptedClientHelloKeys {
		skip, config, err := parseECHConfig(echKey.Config)
		if err != nil || skip {
			c.sendAlert(alertInternalError)
			return nil, nil, fmt.Errorf("tls: invalid EncryptedClientHelloKeys Config: %s", err)
		}
		if skip {
			continue
		}
		echPriv, err := hpke.ParseHPKEPrivateKey(config.KemID, echKey.PrivateKey)
		if err != nil {
			c.sendAlert(alertInternalError)
			return nil, nil, fmt.Errorf("tls: invalid EncryptedClientHelloKeys PrivateKey: %s", err)
		}
		info := append([]byte("tls ech\x00"), echKey.Config...)
		hpkeContext, err := hpke.SetupReceipient(hpke.DHKEM_X25519_HKDF_SHA256, echCiphersuite.KDFID, echCiphersuite.AEADID, echPriv, info, encap)
		if err != nil {
			// attempt next trial decryption
			continue
		}

		encodedInner, err := decryptECHPayload(hpkeContext, outer.original, payload)
		if err != nil {
			// attempt next trial decryption
			continue
		}

		// NOTE: we do not enforce that the sent server_name matches the ECH
		// configs PublicName, since this is not particularly important, and
		// the client already had to know what it was in order to properly
		// encrypt the payload. This is only a MAY in the spec, so we're not
		// doing anything revolutionary.

		echInner, err := decodeInnerClientHello(outer, encodedInner)
		if err != nil {
			c.sendAlert(alertIllegalParameter)
			return nil, nil, errors.New("tls: client sent invalid encrypted_client_hello extension")
		}

		c.echAccepted = true

		return echInner, &echServerContext{
			hpkeContext: hpkeContext,
			configID:    configID,
			ciphersuite: echCiphersuite,
		}, nil
	}

	return outer, nil, nil
}

func buildRetryConfigList(keys []EncryptedClientHelloKey) ([]byte, error) {
	var atLeastOneRetryConfig bool
	var retryBuilder cryptobyte.Builder
	retryBuilder.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
		for _, c := range keys {
			if !c.SendAsRetry {
				continue
			}
			atLeastOneRetryConfig = true
			b.AddBytes(c.Config)
		}
	})
	if !atLeastOneRetryConfig {
		return nil, nil
	}
	return retryBuilder.Bytes()
}
```