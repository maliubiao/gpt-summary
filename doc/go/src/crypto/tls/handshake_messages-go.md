Response:
Let's break down the thought process for analyzing the provided Go code snippet.

**1. Initial Scan and Identification of Core Purpose:**

The first step is to quickly scan the code and identify its main areas of concern. Keywords like `package tls`, `handshake_messages`, and structures like `clientHelloMsg` and `serverHelloMsg` immediately suggest this code deals with the TLS handshake process, specifically the messages exchanged during this process.

**2. Examining Key Data Structures:**

Next, I'd focus on the significant data structures defined:

* **`marshalingFunction`:**  This looks like a utility type to adapt functions for use with the `cryptobyte` library. The `Marshal` method confirms this.
* **Helper functions like `addBytesWithLength`, `addUint64`, `readUint64`, etc.:** These are clearly for encoding and decoding data in a specific format (likely network byte order), which is common in network protocols. The names are quite descriptive.
* **`clientHelloMsg`:** This structure holds a wealth of information. I'd go through each field and try to understand its purpose. Many field names (like `vers`, `random`, `cipherSuites`, `serverName`, various `extension` fields) are standard TLS terms, providing strong hints about their roles in the ClientHello message. The comments mentioning RFCs are invaluable here.
* **`serverHelloMsg`:**  Similar to `clientHelloMsg`, this structure represents the ServerHello message, containing fields relevant to the server's response.
* **`encryptedExtensionsMsg`:** This seems to be a specific message type related to encrypted extensions in TLS 1.3.

**3. Analyzing Functions and Their Logic:**

After understanding the data structures, I'd examine the functions associated with them:

* **Functions related to `marshalingFunction`:** These are straightforward utility functions for encoding data.
* **`marshalMsg` and `marshal` (for `clientHelloMsg` and `serverHelloMsg`):** These functions are responsible for serializing the message structures into byte arrays. The use of `cryptobyte.Builder` indicates a controlled way of building the byte representation. The logic within these functions builds the message byte by byte, including different extensions based on the fields in the structure.
* **`unmarshal` (for `clientHelloMsg`, `serverHelloMsg`, and `encryptedExtensionsMsg`):** These functions perform the reverse operation of `marshal`, parsing a byte array and populating the message structure. The use of `cryptobyte.String` for reading data is evident. The handling of extensions with a loop and a `switch` statement based on the extension type is a common pattern.
* **`marshalWithoutBinders` and `updateBinders`:** These are specific to `clientHelloMsg` and deal with the Pre-Shared Key (PSK) binders in TLS 1.3.
* **`originalBytes` and `clone`:** These are utility methods for accessing the raw bytes and creating a copy of the message.

**4. Inferring the Overall Functionality:**

By piecing together the data structures and functions, the overall functionality becomes clear:

* **Representation of TLS Handshake Messages:** The code defines Go structures that directly correspond to the `ClientHello`, `ServerHello`, and `EncryptedExtensions` messages in the TLS protocol.
* **Serialization and Deserialization:** The `marshal` and `unmarshal` methods provide the mechanisms to convert these structured messages into byte streams suitable for network transmission and vice-versa.
* **Handling of TLS Extensions:**  The code explicitly handles various TLS extensions, demonstrating its ability to support advanced TLS features. The conditional logic based on fields and the loops processing extensions are key to this.
* **Use of `cryptobyte`:** The code relies on the `golang.org/x/crypto/cryptobyte` library for efficient and safe byte manipulation during encoding and decoding.

**5. Identifying Potential Go Language Features and Illustrating with Examples:**

Based on the code, several Go features are apparent:

* **Structs:**  Used to represent the TLS messages.
* **Methods on Structs:**  `marshal`, `unmarshal`, etc., are methods associated with the message structs.
* **Slices:** Used to store lists of cipher suites, compression methods, extensions, etc.
* **Error Handling:**  Functions return `error` to indicate failures during marshaling or unmarshaling.
* **Type Embedding/Composition (though not directly used in this snippet):**  While not explicitly shown, the design with specific message structs hints at potentially more generic message structures being composed.
* **Use of External Libraries:**  Demonstrated by the import of `golang.org/x/crypto/cryptobyte`.

The example code provided in the initial good answer directly demonstrates the use of these structs and their `marshal` and `unmarshal` methods.

**6. Code Reasoning and Assumptions (If applicable):**

In this particular snippet, the logic is relatively straightforward encoding and decoding based on the TLS specifications. There isn't much complex logic requiring extensive reasoning. The assumptions are largely based on understanding the TLS protocol itself. For example, the assumption that `cryptobyte` handles byte order conversions correctly.

**7. Command-Line Arguments and User Errors (If applicable):**

This specific code snippet focuses on the internal representation of TLS messages. It doesn't directly handle command-line arguments. Potential user errors would likely occur at a higher level where these messages are created or processed, such as providing incorrect configuration data leading to invalid message contents.

**8. Summarization of Functionality:**

Finally, the summarization involves concisely stating the key responsibilities of the code, focusing on message representation, serialization, and deserialization within the context of the TLS handshake.

By following these steps, I can systematically analyze the code snippet, understand its purpose, and generate a comprehensive explanation. The key is to break down the code into manageable parts, identify the core concepts, and leverage existing knowledge of the domain (in this case, TLS).
这是 `go/src/crypto/tls/handshake_messages.go` 文件的一部分，主要负责定义和处理 TLS 握手过程中各种消息的结构体和相关的序列化/反序列化方法。

**功能归纳:**

1. **定义 TLS 握手消息结构体:** 该部分代码定义了 `clientHelloMsg`、`serverHelloMsg` 和 `encryptedExtensionsMsg` 这三个重要的 TLS 握手消息的结构体。这些结构体包含了握手消息中各种字段的信息，例如协议版本、随机数、会话 ID、密码套件、扩展等。

2. **实现消息的序列化 (marshal):**  为每个消息结构体提供了 `marshal()` 方法，用于将结构体中的数据按照 TLS 协议规定的格式编码成字节流。  这些方法使用了 `cryptobyte.Builder` 来高效地构建字节流。

3. **实现消息的反序列化 (unmarshal):**  为每个消息结构体提供了 `unmarshal()` 方法，用于将接收到的字节流按照 TLS 协议规定的格式解析到对应的结构体中。这些方法使用了 `cryptobyte.String` 来方便地读取字节流中的数据。

4. **提供辅助的序列化/反序列化函数:** 定义了一些辅助函数，例如 `addBytesWithLength`、`addUint64`、`readUint64`、`readUint8LengthPrefixed` 等，用于处理特定类型的数据编码和解码，例如带长度前缀的字节数组、大端序的 64 位整数等。这些函数基于 `cryptobyte` 库进行操作。

5. **处理 TLS 扩展:**  消息结构体中包含了大量的字段用于表示各种 TLS 扩展，并且 `marshal` 和 `unmarshal` 方法中包含了处理这些扩展的逻辑。例如，`clientHelloMsg` 中包含了 `serverName`、`supportedCurves`、`alpnProtocols` 等字段，以及对应的扩展处理代码。

**它是什么 Go 语言功能的实现？**

这段代码主要实现了 TLS 协议中客户端和服务器之间握手消息的编解码功能。更具体地说，它负责以下消息的结构化表示和字节流转换：

* **ClientHello:**  客户端向服务器发送的第一个握手消息，包含客户端支持的协议版本、密码套件、扩展等信息。
* **ServerHello:** 服务器对 ClientHello 的响应，包含服务器选择的协议版本、密码套件、会话 ID、扩展等信息。
* **EncryptedExtensions:** TLS 1.3 中引入的消息，用于在 ServerHello 之后发送一些加密的扩展信息。

**Go 代码举例说明:**

以下代码示例演示了如何创建一个 `clientHelloMsg` 结构体，并将其序列化为字节流：

```go
package main

import (
	"crypto/rand"
	"crypto/tls"
	"fmt"
	"log"
)

func main() {
	clientHello := &tls.ClientHelloMsg{
		Vers: tls.VersionTLS13,
		Random: func() []byte {
			b := make([]byte, 32)
			_, err := rand.Read(b)
			if err != nil {
				log.Fatal(err)
			}
			return b
		}(),
		CipherSuites: []uint16{
			tls.TLS_AES_128_GCM_SHA256,
			tls.TLS_CHACHA20_POLY1305_SHA256,
		},
		CompressionMethods: []uint8{0}, // No compression
		ServerName:       "example.com",
		SupportedCurves:  []tls.CurveID{tls.CurveP256, tls.X25519},
		ALPNProtocols:    []string{"h2", "http/1.1"},
		SupportedVersions: []uint16{tls.VersionTLS13, tls.VersionTLS12},
	}

	// 序列化 ClientHello 消息
	serialized, err := clientHello.Marshal()
	if err != nil {
		log.Fatalf("Failed to marshal ClientHello: %v", err)
	}

	fmt.Printf("Serialized ClientHello (first few bytes): %X...\n", serialized[:20])

	// 反序列化 ClientHello 消息 (假设我们接收到了这个字节流)
	receivedHello := &tls.ClientHelloMsg{}
	if ok := receivedHello.Unmarshal(serialized); !ok {
		log.Fatalf("Failed to unmarshal ClientHello")
	}

	fmt.Printf("Deserialized Server Name: %s\n", receivedHello.ServerName)
	fmt.Printf("Deserialized ALPN Protocols: %v\n", receivedHello.ALPNProtocols)
}
```

**假设的输入与输出:**

在上面的例子中，`clientHello.Marshal()` 函数会将 `clientHello` 结构体序列化为一个字节切片。输出会类似于：

```
Serialized ClientHello (first few bytes): 160000E90303...
Deserialized Server Name: example.com
Deserialized ALPN Protocols: [h2 http/1.1]
```

这里的 `16` 是 `typeClientHello` 的值，`0000E9` 表示消息的长度（十六进制），后面的字节是具体的握手信息。反序列化后，我们可以从 `receivedHello` 结构体中恢复原始的握手信息。

**命令行参数的具体处理:**

这段代码本身不直接处理命令行参数。命令行参数的处理通常发生在调用 TLS 库的代码中，例如 `net/http` 包或者自定义的网络应用。这些应用会根据命令行参数（例如服务器地址、端口等）来配置 TLS 连接。

**使用者易犯错的点:**

由于这段代码是 TLS 库的内部实现，直接使用它的人员较少。主要的错误可能发生在更高层次的 TLS 连接配置和使用中，例如：

* **密码套件配置错误:**  选择了不兼容的密码套件组合，导致握手失败。
* **TLS 版本配置错误:** 客户端和服务器配置了不兼容的 TLS 版本。
* **扩展使用不当:**  错误地添加或解析 TLS 扩展，导致握手失败或功能异常。

**总结:**

这段 `handshake_messages.go` 代码的主要功能是定义 TLS 握手过程中关键消息的结构体，并提供将这些结构体序列化和反序列化为字节流的能力。它是 `crypto/tls` 包实现 TLS 协议的核心组成部分，为建立安全的 TLS 连接奠定了基础。

Prompt: 
```
这是路径为go/src/crypto/tls/handshake_messages.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第1部分，共2部分，请归纳一下它的功能

"""
// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

import (
	"errors"
	"fmt"
	"slices"
	"strings"

	"golang.org/x/crypto/cryptobyte"
)

// The marshalingFunction type is an adapter to allow the use of ordinary
// functions as cryptobyte.MarshalingValue.
type marshalingFunction func(b *cryptobyte.Builder) error

func (f marshalingFunction) Marshal(b *cryptobyte.Builder) error {
	return f(b)
}

// addBytesWithLength appends a sequence of bytes to the cryptobyte.Builder. If
// the length of the sequence is not the value specified, it produces an error.
func addBytesWithLength(b *cryptobyte.Builder, v []byte, n int) {
	b.AddValue(marshalingFunction(func(b *cryptobyte.Builder) error {
		if len(v) != n {
			return fmt.Errorf("invalid value length: expected %d, got %d", n, len(v))
		}
		b.AddBytes(v)
		return nil
	}))
}

// addUint64 appends a big-endian, 64-bit value to the cryptobyte.Builder.
func addUint64(b *cryptobyte.Builder, v uint64) {
	b.AddUint32(uint32(v >> 32))
	b.AddUint32(uint32(v))
}

// readUint64 decodes a big-endian, 64-bit value into out and advances over it.
// It reports whether the read was successful.
func readUint64(s *cryptobyte.String, out *uint64) bool {
	var hi, lo uint32
	if !s.ReadUint32(&hi) || !s.ReadUint32(&lo) {
		return false
	}
	*out = uint64(hi)<<32 | uint64(lo)
	return true
}

// readUint8LengthPrefixed acts like s.ReadUint8LengthPrefixed, but targets a
// []byte instead of a cryptobyte.String.
func readUint8LengthPrefixed(s *cryptobyte.String, out *[]byte) bool {
	return s.ReadUint8LengthPrefixed((*cryptobyte.String)(out))
}

// readUint16LengthPrefixed acts like s.ReadUint16LengthPrefixed, but targets a
// []byte instead of a cryptobyte.String.
func readUint16LengthPrefixed(s *cryptobyte.String, out *[]byte) bool {
	return s.ReadUint16LengthPrefixed((*cryptobyte.String)(out))
}

// readUint24LengthPrefixed acts like s.ReadUint24LengthPrefixed, but targets a
// []byte instead of a cryptobyte.String.
func readUint24LengthPrefixed(s *cryptobyte.String, out *[]byte) bool {
	return s.ReadUint24LengthPrefixed((*cryptobyte.String)(out))
}

type clientHelloMsg struct {
	original                         []byte
	vers                             uint16
	random                           []byte
	sessionId                        []byte
	cipherSuites                     []uint16
	compressionMethods               []uint8
	serverName                       string
	ocspStapling                     bool
	supportedCurves                  []CurveID
	supportedPoints                  []uint8
	ticketSupported                  bool
	sessionTicket                    []uint8
	supportedSignatureAlgorithms     []SignatureScheme
	supportedSignatureAlgorithmsCert []SignatureScheme
	secureRenegotiationSupported     bool
	secureRenegotiation              []byte
	extendedMasterSecret             bool
	alpnProtocols                    []string
	scts                             bool
	supportedVersions                []uint16
	cookie                           []byte
	keyShares                        []keyShare
	earlyData                        bool
	pskModes                         []uint8
	pskIdentities                    []pskIdentity
	pskBinders                       [][]byte
	quicTransportParameters          []byte
	encryptedClientHello             []byte
	// extensions are only populated on the servers-ide of a handshake
	extensions []uint16
}

func (m *clientHelloMsg) marshalMsg(echInner bool) ([]byte, error) {
	var exts cryptobyte.Builder
	if len(m.serverName) > 0 {
		// RFC 6066, Section 3
		exts.AddUint16(extensionServerName)
		exts.AddUint16LengthPrefixed(func(exts *cryptobyte.Builder) {
			exts.AddUint16LengthPrefixed(func(exts *cryptobyte.Builder) {
				exts.AddUint8(0) // name_type = host_name
				exts.AddUint16LengthPrefixed(func(exts *cryptobyte.Builder) {
					exts.AddBytes([]byte(m.serverName))
				})
			})
		})
	}
	if len(m.supportedPoints) > 0 && !echInner {
		// RFC 4492, Section 5.1.2
		exts.AddUint16(extensionSupportedPoints)
		exts.AddUint16LengthPrefixed(func(exts *cryptobyte.Builder) {
			exts.AddUint8LengthPrefixed(func(exts *cryptobyte.Builder) {
				exts.AddBytes(m.supportedPoints)
			})
		})
	}
	if m.ticketSupported && !echInner {
		// RFC 5077, Section 3.2
		exts.AddUint16(extensionSessionTicket)
		exts.AddUint16LengthPrefixed(func(exts *cryptobyte.Builder) {
			exts.AddBytes(m.sessionTicket)
		})
	}
	if m.secureRenegotiationSupported && !echInner {
		// RFC 5746, Section 3.2
		exts.AddUint16(extensionRenegotiationInfo)
		exts.AddUint16LengthPrefixed(func(exts *cryptobyte.Builder) {
			exts.AddUint8LengthPrefixed(func(exts *cryptobyte.Builder) {
				exts.AddBytes(m.secureRenegotiation)
			})
		})
	}
	if m.extendedMasterSecret && !echInner {
		// RFC 7627
		exts.AddUint16(extensionExtendedMasterSecret)
		exts.AddUint16(0) // empty extension_data
	}
	if m.scts {
		// RFC 6962, Section 3.3.1
		exts.AddUint16(extensionSCT)
		exts.AddUint16(0) // empty extension_data
	}
	if m.earlyData {
		// RFC 8446, Section 4.2.10
		exts.AddUint16(extensionEarlyData)
		exts.AddUint16(0) // empty extension_data
	}
	if m.quicTransportParameters != nil { // marshal zero-length parameters when present
		// RFC 9001, Section 8.2
		exts.AddUint16(extensionQUICTransportParameters)
		exts.AddUint16LengthPrefixed(func(exts *cryptobyte.Builder) {
			exts.AddBytes(m.quicTransportParameters)
		})
	}
	if len(m.encryptedClientHello) > 0 {
		exts.AddUint16(extensionEncryptedClientHello)
		exts.AddUint16LengthPrefixed(func(exts *cryptobyte.Builder) {
			exts.AddBytes(m.encryptedClientHello)
		})
	}
	// Note that any extension that can be compressed during ECH must be
	// contiguous. If any additional extensions are to be compressed they must
	// be added to the following block, so that they can be properly
	// decompressed on the other side.
	var echOuterExts []uint16
	if m.ocspStapling {
		// RFC 4366, Section 3.6
		if echInner {
			echOuterExts = append(echOuterExts, extensionStatusRequest)
		} else {
			exts.AddUint16(extensionStatusRequest)
			exts.AddUint16LengthPrefixed(func(exts *cryptobyte.Builder) {
				exts.AddUint8(1)  // status_type = ocsp
				exts.AddUint16(0) // empty responder_id_list
				exts.AddUint16(0) // empty request_extensions
			})
		}
	}
	if len(m.supportedCurves) > 0 {
		// RFC 4492, sections 5.1.1 and RFC 8446, Section 4.2.7
		if echInner {
			echOuterExts = append(echOuterExts, extensionSupportedCurves)
		} else {
			exts.AddUint16(extensionSupportedCurves)
			exts.AddUint16LengthPrefixed(func(exts *cryptobyte.Builder) {
				exts.AddUint16LengthPrefixed(func(exts *cryptobyte.Builder) {
					for _, curve := range m.supportedCurves {
						exts.AddUint16(uint16(curve))
					}
				})
			})
		}
	}
	if len(m.supportedSignatureAlgorithms) > 0 {
		// RFC 5246, Section 7.4.1.4.1
		if echInner {
			echOuterExts = append(echOuterExts, extensionSignatureAlgorithms)
		} else {
			exts.AddUint16(extensionSignatureAlgorithms)
			exts.AddUint16LengthPrefixed(func(exts *cryptobyte.Builder) {
				exts.AddUint16LengthPrefixed(func(exts *cryptobyte.Builder) {
					for _, sigAlgo := range m.supportedSignatureAlgorithms {
						exts.AddUint16(uint16(sigAlgo))
					}
				})
			})
		}
	}
	if len(m.supportedSignatureAlgorithmsCert) > 0 {
		// RFC 8446, Section 4.2.3
		if echInner {
			echOuterExts = append(echOuterExts, extensionSignatureAlgorithmsCert)
		} else {
			exts.AddUint16(extensionSignatureAlgorithmsCert)
			exts.AddUint16LengthPrefixed(func(exts *cryptobyte.Builder) {
				exts.AddUint16LengthPrefixed(func(exts *cryptobyte.Builder) {
					for _, sigAlgo := range m.supportedSignatureAlgorithmsCert {
						exts.AddUint16(uint16(sigAlgo))
					}
				})
			})
		}
	}
	if len(m.alpnProtocols) > 0 {
		// RFC 7301, Section 3.1
		if echInner {
			echOuterExts = append(echOuterExts, extensionALPN)
		} else {
			exts.AddUint16(extensionALPN)
			exts.AddUint16LengthPrefixed(func(exts *cryptobyte.Builder) {
				exts.AddUint16LengthPrefixed(func(exts *cryptobyte.Builder) {
					for _, proto := range m.alpnProtocols {
						exts.AddUint8LengthPrefixed(func(exts *cryptobyte.Builder) {
							exts.AddBytes([]byte(proto))
						})
					}
				})
			})
		}
	}
	if len(m.supportedVersions) > 0 {
		// RFC 8446, Section 4.2.1
		if echInner {
			echOuterExts = append(echOuterExts, extensionSupportedVersions)
		} else {
			exts.AddUint16(extensionSupportedVersions)
			exts.AddUint16LengthPrefixed(func(exts *cryptobyte.Builder) {
				exts.AddUint8LengthPrefixed(func(exts *cryptobyte.Builder) {
					for _, vers := range m.supportedVersions {
						exts.AddUint16(vers)
					}
				})
			})
		}
	}
	if len(m.cookie) > 0 {
		// RFC 8446, Section 4.2.2
		if echInner {
			echOuterExts = append(echOuterExts, extensionCookie)
		} else {
			exts.AddUint16(extensionCookie)
			exts.AddUint16LengthPrefixed(func(exts *cryptobyte.Builder) {
				exts.AddUint16LengthPrefixed(func(exts *cryptobyte.Builder) {
					exts.AddBytes(m.cookie)
				})
			})
		}
	}
	if len(m.keyShares) > 0 {
		// RFC 8446, Section 4.2.8
		if echInner {
			echOuterExts = append(echOuterExts, extensionKeyShare)
		} else {
			exts.AddUint16(extensionKeyShare)
			exts.AddUint16LengthPrefixed(func(exts *cryptobyte.Builder) {
				exts.AddUint16LengthPrefixed(func(exts *cryptobyte.Builder) {
					for _, ks := range m.keyShares {
						exts.AddUint16(uint16(ks.group))
						exts.AddUint16LengthPrefixed(func(exts *cryptobyte.Builder) {
							exts.AddBytes(ks.data)
						})
					}
				})
			})
		}
	}
	if len(m.pskModes) > 0 {
		// RFC 8446, Section 4.2.9
		if echInner {
			echOuterExts = append(echOuterExts, extensionPSKModes)
		} else {
			exts.AddUint16(extensionPSKModes)
			exts.AddUint16LengthPrefixed(func(exts *cryptobyte.Builder) {
				exts.AddUint8LengthPrefixed(func(exts *cryptobyte.Builder) {
					exts.AddBytes(m.pskModes)
				})
			})
		}
	}
	if len(echOuterExts) > 0 && echInner {
		exts.AddUint16(extensionECHOuterExtensions)
		exts.AddUint16LengthPrefixed(func(exts *cryptobyte.Builder) {
			exts.AddUint8LengthPrefixed(func(exts *cryptobyte.Builder) {
				for _, e := range echOuterExts {
					exts.AddUint16(e)
				}
			})
		})
	}
	if len(m.pskIdentities) > 0 { // pre_shared_key must be the last extension
		// RFC 8446, Section 4.2.11
		exts.AddUint16(extensionPreSharedKey)
		exts.AddUint16LengthPrefixed(func(exts *cryptobyte.Builder) {
			exts.AddUint16LengthPrefixed(func(exts *cryptobyte.Builder) {
				for _, psk := range m.pskIdentities {
					exts.AddUint16LengthPrefixed(func(exts *cryptobyte.Builder) {
						exts.AddBytes(psk.label)
					})
					exts.AddUint32(psk.obfuscatedTicketAge)
				}
			})
			exts.AddUint16LengthPrefixed(func(exts *cryptobyte.Builder) {
				for _, binder := range m.pskBinders {
					exts.AddUint8LengthPrefixed(func(exts *cryptobyte.Builder) {
						exts.AddBytes(binder)
					})
				}
			})
		})
	}
	extBytes, err := exts.Bytes()
	if err != nil {
		return nil, err
	}

	var b cryptobyte.Builder
	b.AddUint8(typeClientHello)
	b.AddUint24LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddUint16(m.vers)
		addBytesWithLength(b, m.random, 32)
		b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) {
			if !echInner {
				b.AddBytes(m.sessionId)
			}
		})
		b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
			for _, suite := range m.cipherSuites {
				b.AddUint16(suite)
			}
		})
		b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) {
			b.AddBytes(m.compressionMethods)
		})

		if len(extBytes) > 0 {
			b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
				b.AddBytes(extBytes)
			})
		}
	})

	return b.Bytes()
}

func (m *clientHelloMsg) marshal() ([]byte, error) {
	return m.marshalMsg(false)
}

// marshalWithoutBinders returns the ClientHello through the
// PreSharedKeyExtension.identities field, according to RFC 8446, Section
// 4.2.11.2. Note that m.pskBinders must be set to slices of the correct length.
func (m *clientHelloMsg) marshalWithoutBinders() ([]byte, error) {
	bindersLen := 2 // uint16 length prefix
	for _, binder := range m.pskBinders {
		bindersLen += 1 // uint8 length prefix
		bindersLen += len(binder)
	}

	var fullMessage []byte
	if m.original != nil {
		fullMessage = m.original
	} else {
		var err error
		fullMessage, err = m.marshal()
		if err != nil {
			return nil, err
		}
	}
	return fullMessage[:len(fullMessage)-bindersLen], nil
}

// updateBinders updates the m.pskBinders field. The supplied binders must have
// the same length as the current m.pskBinders.
func (m *clientHelloMsg) updateBinders(pskBinders [][]byte) error {
	if len(pskBinders) != len(m.pskBinders) {
		return errors.New("tls: internal error: pskBinders length mismatch")
	}
	for i := range m.pskBinders {
		if len(pskBinders[i]) != len(m.pskBinders[i]) {
			return errors.New("tls: internal error: pskBinders length mismatch")
		}
	}
	m.pskBinders = pskBinders

	return nil
}

func (m *clientHelloMsg) unmarshal(data []byte) bool {
	*m = clientHelloMsg{original: data}
	s := cryptobyte.String(data)

	if !s.Skip(4) || // message type and uint24 length field
		!s.ReadUint16(&m.vers) || !s.ReadBytes(&m.random, 32) ||
		!readUint8LengthPrefixed(&s, &m.sessionId) {
		return false
	}

	var cipherSuites cryptobyte.String
	if !s.ReadUint16LengthPrefixed(&cipherSuites) {
		return false
	}
	m.cipherSuites = []uint16{}
	m.secureRenegotiationSupported = false
	for !cipherSuites.Empty() {
		var suite uint16
		if !cipherSuites.ReadUint16(&suite) {
			return false
		}
		if suite == scsvRenegotiation {
			m.secureRenegotiationSupported = true
		}
		m.cipherSuites = append(m.cipherSuites, suite)
	}

	if !readUint8LengthPrefixed(&s, &m.compressionMethods) {
		return false
	}

	if s.Empty() {
		// ClientHello is optionally followed by extension data
		return true
	}

	var extensions cryptobyte.String
	if !s.ReadUint16LengthPrefixed(&extensions) || !s.Empty() {
		return false
	}

	seenExts := make(map[uint16]bool)
	for !extensions.Empty() {
		var extension uint16
		var extData cryptobyte.String
		if !extensions.ReadUint16(&extension) ||
			!extensions.ReadUint16LengthPrefixed(&extData) {
			return false
		}

		if seenExts[extension] {
			return false
		}
		seenExts[extension] = true
		m.extensions = append(m.extensions, extension)

		switch extension {
		case extensionServerName:
			// RFC 6066, Section 3
			var nameList cryptobyte.String
			if !extData.ReadUint16LengthPrefixed(&nameList) || nameList.Empty() {
				return false
			}
			for !nameList.Empty() {
				var nameType uint8
				var serverName cryptobyte.String
				if !nameList.ReadUint8(&nameType) ||
					!nameList.ReadUint16LengthPrefixed(&serverName) ||
					serverName.Empty() {
					return false
				}
				if nameType != 0 {
					continue
				}
				if len(m.serverName) != 0 {
					// Multiple names of the same name_type are prohibited.
					return false
				}
				m.serverName = string(serverName)
				// An SNI value may not include a trailing dot.
				if strings.HasSuffix(m.serverName, ".") {
					return false
				}
			}
		case extensionStatusRequest:
			// RFC 4366, Section 3.6
			var statusType uint8
			var ignored cryptobyte.String
			if !extData.ReadUint8(&statusType) ||
				!extData.ReadUint16LengthPrefixed(&ignored) ||
				!extData.ReadUint16LengthPrefixed(&ignored) {
				return false
			}
			m.ocspStapling = statusType == statusTypeOCSP
		case extensionSupportedCurves:
			// RFC 4492, sections 5.1.1 and RFC 8446, Section 4.2.7
			var curves cryptobyte.String
			if !extData.ReadUint16LengthPrefixed(&curves) || curves.Empty() {
				return false
			}
			for !curves.Empty() {
				var curve uint16
				if !curves.ReadUint16(&curve) {
					return false
				}
				m.supportedCurves = append(m.supportedCurves, CurveID(curve))
			}
		case extensionSupportedPoints:
			// RFC 4492, Section 5.1.2
			if !readUint8LengthPrefixed(&extData, &m.supportedPoints) ||
				len(m.supportedPoints) == 0 {
				return false
			}
		case extensionSessionTicket:
			// RFC 5077, Section 3.2
			m.ticketSupported = true
			extData.ReadBytes(&m.sessionTicket, len(extData))
		case extensionSignatureAlgorithms:
			// RFC 5246, Section 7.4.1.4.1
			var sigAndAlgs cryptobyte.String
			if !extData.ReadUint16LengthPrefixed(&sigAndAlgs) || sigAndAlgs.Empty() {
				return false
			}
			for !sigAndAlgs.Empty() {
				var sigAndAlg uint16
				if !sigAndAlgs.ReadUint16(&sigAndAlg) {
					return false
				}
				m.supportedSignatureAlgorithms = append(
					m.supportedSignatureAlgorithms, SignatureScheme(sigAndAlg))
			}
		case extensionSignatureAlgorithmsCert:
			// RFC 8446, Section 4.2.3
			var sigAndAlgs cryptobyte.String
			if !extData.ReadUint16LengthPrefixed(&sigAndAlgs) || sigAndAlgs.Empty() {
				return false
			}
			for !sigAndAlgs.Empty() {
				var sigAndAlg uint16
				if !sigAndAlgs.ReadUint16(&sigAndAlg) {
					return false
				}
				m.supportedSignatureAlgorithmsCert = append(
					m.supportedSignatureAlgorithmsCert, SignatureScheme(sigAndAlg))
			}
		case extensionRenegotiationInfo:
			// RFC 5746, Section 3.2
			if !readUint8LengthPrefixed(&extData, &m.secureRenegotiation) {
				return false
			}
			m.secureRenegotiationSupported = true
		case extensionExtendedMasterSecret:
			// RFC 7627
			m.extendedMasterSecret = true
		case extensionALPN:
			// RFC 7301, Section 3.1
			var protoList cryptobyte.String
			if !extData.ReadUint16LengthPrefixed(&protoList) || protoList.Empty() {
				return false
			}
			for !protoList.Empty() {
				var proto cryptobyte.String
				if !protoList.ReadUint8LengthPrefixed(&proto) || proto.Empty() {
					return false
				}
				m.alpnProtocols = append(m.alpnProtocols, string(proto))
			}
		case extensionSCT:
			// RFC 6962, Section 3.3.1
			m.scts = true
		case extensionSupportedVersions:
			// RFC 8446, Section 4.2.1
			var versList cryptobyte.String
			if !extData.ReadUint8LengthPrefixed(&versList) || versList.Empty() {
				return false
			}
			for !versList.Empty() {
				var vers uint16
				if !versList.ReadUint16(&vers) {
					return false
				}
				m.supportedVersions = append(m.supportedVersions, vers)
			}
		case extensionCookie:
			// RFC 8446, Section 4.2.2
			if !readUint16LengthPrefixed(&extData, &m.cookie) ||
				len(m.cookie) == 0 {
				return false
			}
		case extensionKeyShare:
			// RFC 8446, Section 4.2.8
			var clientShares cryptobyte.String
			if !extData.ReadUint16LengthPrefixed(&clientShares) {
				return false
			}
			for !clientShares.Empty() {
				var ks keyShare
				if !clientShares.ReadUint16((*uint16)(&ks.group)) ||
					!readUint16LengthPrefixed(&clientShares, &ks.data) ||
					len(ks.data) == 0 {
					return false
				}
				m.keyShares = append(m.keyShares, ks)
			}
		case extensionEarlyData:
			// RFC 8446, Section 4.2.10
			m.earlyData = true
		case extensionPSKModes:
			// RFC 8446, Section 4.2.9
			if !readUint8LengthPrefixed(&extData, &m.pskModes) {
				return false
			}
		case extensionQUICTransportParameters:
			m.quicTransportParameters = make([]byte, len(extData))
			if !extData.CopyBytes(m.quicTransportParameters) {
				return false
			}
		case extensionPreSharedKey:
			// RFC 8446, Section 4.2.11
			if !extensions.Empty() {
				return false // pre_shared_key must be the last extension
			}
			var identities cryptobyte.String
			if !extData.ReadUint16LengthPrefixed(&identities) || identities.Empty() {
				return false
			}
			for !identities.Empty() {
				var psk pskIdentity
				if !readUint16LengthPrefixed(&identities, &psk.label) ||
					!identities.ReadUint32(&psk.obfuscatedTicketAge) ||
					len(psk.label) == 0 {
					return false
				}
				m.pskIdentities = append(m.pskIdentities, psk)
			}
			var binders cryptobyte.String
			if !extData.ReadUint16LengthPrefixed(&binders) || binders.Empty() {
				return false
			}
			for !binders.Empty() {
				var binder []byte
				if !readUint8LengthPrefixed(&binders, &binder) ||
					len(binder) == 0 {
					return false
				}
				m.pskBinders = append(m.pskBinders, binder)
			}
		case extensionEncryptedClientHello:
			if !extData.ReadBytes(&m.encryptedClientHello, len(extData)) {
				return false
			}
		default:
			// Ignore unknown extensions.
			continue
		}

		if !extData.Empty() {
			return false
		}
	}

	return true
}

func (m *clientHelloMsg) originalBytes() []byte {
	return m.original
}

func (m *clientHelloMsg) clone() *clientHelloMsg {
	return &clientHelloMsg{
		original:                         slices.Clone(m.original),
		vers:                             m.vers,
		random:                           slices.Clone(m.random),
		sessionId:                        slices.Clone(m.sessionId),
		cipherSuites:                     slices.Clone(m.cipherSuites),
		compressionMethods:               slices.Clone(m.compressionMethods),
		serverName:                       m.serverName,
		ocspStapling:                     m.ocspStapling,
		supportedCurves:                  slices.Clone(m.supportedCurves),
		supportedPoints:                  slices.Clone(m.supportedPoints),
		ticketSupported:                  m.ticketSupported,
		sessionTicket:                    slices.Clone(m.sessionTicket),
		supportedSignatureAlgorithms:     slices.Clone(m.supportedSignatureAlgorithms),
		supportedSignatureAlgorithmsCert: slices.Clone(m.supportedSignatureAlgorithmsCert),
		secureRenegotiationSupported:     m.secureRenegotiationSupported,
		secureRenegotiation:              slices.Clone(m.secureRenegotiation),
		extendedMasterSecret:             m.extendedMasterSecret,
		alpnProtocols:                    slices.Clone(m.alpnProtocols),
		scts:                             m.scts,
		supportedVersions:                slices.Clone(m.supportedVersions),
		cookie:                           slices.Clone(m.cookie),
		keyShares:                        slices.Clone(m.keyShares),
		earlyData:                        m.earlyData,
		pskModes:                         slices.Clone(m.pskModes),
		pskIdentities:                    slices.Clone(m.pskIdentities),
		pskBinders:                       slices.Clone(m.pskBinders),
		quicTransportParameters:          slices.Clone(m.quicTransportParameters),
		encryptedClientHello:             slices.Clone(m.encryptedClientHello),
	}
}

type serverHelloMsg struct {
	original                     []byte
	vers                         uint16
	random                       []byte
	sessionId                    []byte
	cipherSuite                  uint16
	compressionMethod            uint8
	ocspStapling                 bool
	ticketSupported              bool
	secureRenegotiationSupported bool
	secureRenegotiation          []byte
	extendedMasterSecret         bool
	alpnProtocol                 string
	scts                         [][]byte
	supportedVersion             uint16
	serverShare                  keyShare
	selectedIdentityPresent      bool
	selectedIdentity             uint16
	supportedPoints              []uint8
	encryptedClientHello         []byte
	serverNameAck                bool

	// HelloRetryRequest extensions
	cookie        []byte
	selectedGroup CurveID
}

func (m *serverHelloMsg) marshal() ([]byte, error) {
	var exts cryptobyte.Builder
	if m.ocspStapling {
		exts.AddUint16(extensionStatusRequest)
		exts.AddUint16(0) // empty extension_data
	}
	if m.ticketSupported {
		exts.AddUint16(extensionSessionTicket)
		exts.AddUint16(0) // empty extension_data
	}
	if m.secureRenegotiationSupported {
		exts.AddUint16(extensionRenegotiationInfo)
		exts.AddUint16LengthPrefixed(func(exts *cryptobyte.Builder) {
			exts.AddUint8LengthPrefixed(func(exts *cryptobyte.Builder) {
				exts.AddBytes(m.secureRenegotiation)
			})
		})
	}
	if m.extendedMasterSecret {
		exts.AddUint16(extensionExtendedMasterSecret)
		exts.AddUint16(0) // empty extension_data
	}
	if len(m.alpnProtocol) > 0 {
		exts.AddUint16(extensionALPN)
		exts.AddUint16LengthPrefixed(func(exts *cryptobyte.Builder) {
			exts.AddUint16LengthPrefixed(func(exts *cryptobyte.Builder) {
				exts.AddUint8LengthPrefixed(func(exts *cryptobyte.Builder) {
					exts.AddBytes([]byte(m.alpnProtocol))
				})
			})
		})
	}
	if len(m.scts) > 0 {
		exts.AddUint16(extensionSCT)
		exts.AddUint16LengthPrefixed(func(exts *cryptobyte.Builder) {
			exts.AddUint16LengthPrefixed(func(exts *cryptobyte.Builder) {
				for _, sct := range m.scts {
					exts.AddUint16LengthPrefixed(func(exts *cryptobyte.Builder) {
						exts.AddBytes(sct)
					})
				}
			})
		})
	}
	if m.supportedVersion != 0 {
		exts.AddUint16(extensionSupportedVersions)
		exts.AddUint16LengthPrefixed(func(exts *cryptobyte.Builder) {
			exts.AddUint16(m.supportedVersion)
		})
	}
	if m.serverShare.group != 0 {
		exts.AddUint16(extensionKeyShare)
		exts.AddUint16LengthPrefixed(func(exts *cryptobyte.Builder) {
			exts.AddUint16(uint16(m.serverShare.group))
			exts.AddUint16LengthPrefixed(func(exts *cryptobyte.Builder) {
				exts.AddBytes(m.serverShare.data)
			})
		})
	}
	if m.selectedIdentityPresent {
		exts.AddUint16(extensionPreSharedKey)
		exts.AddUint16LengthPrefixed(func(exts *cryptobyte.Builder) {
			exts.AddUint16(m.selectedIdentity)
		})
	}

	if len(m.cookie) > 0 {
		exts.AddUint16(extensionCookie)
		exts.AddUint16LengthPrefixed(func(exts *cryptobyte.Builder) {
			exts.AddUint16LengthPrefixed(func(exts *cryptobyte.Builder) {
				exts.AddBytes(m.cookie)
			})
		})
	}
	if m.selectedGroup != 0 {
		exts.AddUint16(extensionKeyShare)
		exts.AddUint16LengthPrefixed(func(exts *cryptobyte.Builder) {
			exts.AddUint16(uint16(m.selectedGroup))
		})
	}
	if len(m.supportedPoints) > 0 {
		exts.AddUint16(extensionSupportedPoints)
		exts.AddUint16LengthPrefixed(func(exts *cryptobyte.Builder) {
			exts.AddUint8LengthPrefixed(func(exts *cryptobyte.Builder) {
				exts.AddBytes(m.supportedPoints)
			})
		})
	}
	if len(m.encryptedClientHello) > 0 {
		exts.AddUint16(extensionEncryptedClientHello)
		exts.AddUint16LengthPrefixed(func(exts *cryptobyte.Builder) {
			exts.AddBytes(m.encryptedClientHello)
		})
	}
	if m.serverNameAck {
		exts.AddUint16(extensionServerName)
		exts.AddUint16(0)
	}

	extBytes, err := exts.Bytes()
	if err != nil {
		return nil, err
	}

	var b cryptobyte.Builder
	b.AddUint8(typeServerHello)
	b.AddUint24LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddUint16(m.vers)
		addBytesWithLength(b, m.random, 32)
		b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) {
			b.AddBytes(m.sessionId)
		})
		b.AddUint16(m.cipherSuite)
		b.AddUint8(m.compressionMethod)

		if len(extBytes) > 0 {
			b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
				b.AddBytes(extBytes)
			})
		}
	})

	return b.Bytes()
}

func (m *serverHelloMsg) unmarshal(data []byte) bool {
	*m = serverHelloMsg{original: data}
	s := cryptobyte.String(data)

	if !s.Skip(4) || // message type and uint24 length field
		!s.ReadUint16(&m.vers) || !s.ReadBytes(&m.random, 32) ||
		!readUint8LengthPrefixed(&s, &m.sessionId) ||
		!s.ReadUint16(&m.cipherSuite) ||
		!s.ReadUint8(&m.compressionMethod) {
		return false
	}

	if s.Empty() {
		// ServerHello is optionally followed by extension data
		return true
	}

	var extensions cryptobyte.String
	if !s.ReadUint16LengthPrefixed(&extensions) || !s.Empty() {
		return false
	}

	seenExts := make(map[uint16]bool)
	for !extensions.Empty() {
		var extension uint16
		var extData cryptobyte.String
		if !extensions.ReadUint16(&extension) ||
			!extensions.ReadUint16LengthPrefixed(&extData) {
			return false
		}

		if seenExts[extension] {
			return false
		}
		seenExts[extension] = true

		switch extension {
		case extensionStatusRequest:
			m.ocspStapling = true
		case extensionSessionTicket:
			m.ticketSupported = true
		case extensionRenegotiationInfo:
			if !readUint8LengthPrefixed(&extData, &m.secureRenegotiation) {
				return false
			}
			m.secureRenegotiationSupported = true
		case extensionExtendedMasterSecret:
			m.extendedMasterSecret = true
		case extensionALPN:
			var protoList cryptobyte.String
			if !extData.ReadUint16LengthPrefixed(&protoList) || protoList.Empty() {
				return false
			}
			var proto cryptobyte.String
			if !protoList.ReadUint8LengthPrefixed(&proto) ||
				proto.Empty() || !protoList.Empty() {
				return false
			}
			m.alpnProtocol = string(proto)
		case extensionSCT:
			var sctList cryptobyte.String
			if !extData.ReadUint16LengthPrefixed(&sctList) || sctList.Empty() {
				return false
			}
			for !sctList.Empty() {
				var sct []byte
				if !readUint16LengthPrefixed(&sctList, &sct) ||
					len(sct) == 0 {
					return false
				}
				m.scts = append(m.scts, sct)
			}
		case extensionSupportedVersions:
			if !extData.ReadUint16(&m.supportedVersion) {
				return false
			}
		case extensionCookie:
			if !readUint16LengthPrefixed(&extData, &m.cookie) ||
				len(m.cookie) == 0 {
				return false
			}
		case extensionKeyShare:
			// This extension has different formats in SH and HRR, accept either
			// and let the handshake logic decide. See RFC 8446, Section 4.2.8.
			if len(extData) == 2 {
				if !extData.ReadUint16((*uint16)(&m.selectedGroup)) {
					return false
				}
			} else {
				if !extData.ReadUint16((*uint16)(&m.serverShare.group)) ||
					!readUint16LengthPrefixed(&extData, &m.serverShare.data) {
					return false
				}
			}
		case extensionPreSharedKey:
			m.selectedIdentityPresent = true
			if !extData.ReadUint16(&m.selectedIdentity) {
				return false
			}
		case extensionSupportedPoints:
			// RFC 4492, Section 5.1.2
			if !readUint8LengthPrefixed(&extData, &m.supportedPoints) ||
				len(m.supportedPoints) == 0 {
				return false
			}
		case extensionEncryptedClientHello: // encrypted_client_hello
			m.encryptedClientHello = make([]byte, len(extData))
			if !extData.CopyBytes(m.encryptedClientHello) {
				return false
			}
		case extensionServerName:
			if len(extData) != 0 {
				return false
			}
			m.serverNameAck = true
		default:
			// Ignore unknown extensions.
			continue
		}

		if !extData.Empty() {
			return false
		}
	}

	return true
}

func (m *serverHelloMsg) originalBytes() []byte {
	return m.original
}

type encryptedExtensionsMsg struct {
	alpnProtocol            string
	quicTransportParameters []byte
	earlyData               bool
	echRetryConfigs         []byte
}

func (m *encryptedExtensionsMsg) marshal() ([]byte, error) {
	var b cryptobyte.Builder
	b.AddUint8(typeEncryptedExtensions)
	b.AddUint24LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
			if len(m.alpnProtocol) > 0 {
				b.AddUint16(extensionALPN)
				b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
					b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
						b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) {
							b.AddBytes([]byte(m.alpnProtocol))
						})
					})
				})
			}
			if m.quicTransportParameters != nil { // marshal zero-length parameters when present
				// draft-ietf-quic-tls-32, Section 8.2
				b.AddUint16(extensionQUICTransportParameters)
				b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
					b.AddBytes(m.quicTransportParameters)
				})
			}
			if m.earlyData {
				// RFC 8446, Section 4.2.10
				b.AddUint16(extensionEarlyData)
				b.AddUint16(0) // empty extension_data
			}
			if len(m.echRetryConfigs) > 0 {
				b.AddUint16(extensionEncryptedClientHello)
				b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
					b.AddBytes(m.echRetryConfigs)
				})
			}
		})
	})

	return b.Bytes()
}

func (m *encryptedExtensionsMsg) unmarshal(data []byte) bool {
	*m = encryptedExtensionsMsg{}
	s := cryptobyte.String(data)

	var extensions cryptobyte.String
	if !s.Skip(4) || // message type and uint24 length field
		!s.ReadUint16LengthPrefixed(&extensions) || !s.Empty() {
		return false
	}

	for !extensions.Empty() {
		var extension uint16
		var extData cryptobyte.String
		if !extensions.ReadUint16(&extension) ||
			!extensions.ReadUint16LengthPrefixed(&extData) {
			return false
		}

		switch extension {
		case extensionALPN:
			var protoList cryptobyte.String
			if !extData.ReadUint16LengthPrefixed(&protoList) || protoList.Empty() {
				return false
			}
			var proto cryptobyte.String
			if !protoList.ReadUint8LengthPrefixed(&proto) ||
				proto.Empty() || !protoList.Empty() {
				return false
			}
			m.alpnProtocol = string(proto)
		case extensionQUICTransportParameters:
			m.quicTransportParameters = make([]byte, len(extData))
			if !extData.CopyBytes(m.quicTransportParameters) {
				return false
			}
		case extensionEarlyData:
			// RFC 8446, Section 4.2.10
			m.earlyData = true
		case extensionEncryptedClientHello:
			m.echRetryConfigs = make([]byte, len(extData))
			if !extData.CopyBytes(m.echRetryConfigs) {
				return false
			}
		default:
			// Ignore unknown extensions.
			continue
		}

		if !extData.Empty() {
			return false
		}
	}

	return true
}

typ
"""




```