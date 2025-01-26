Response:
Let's break down the thought process for answering this multi-part question about the Go code snippet.

**1. Understanding the Request:**

The request asks for an analysis of a Go code snippet that defines a data structure related to cipher suites. It has multiple sub-questions, requiring:

* **Functionality:** What does this code *do*?
* **Go Feature:** What Go language feature is being used? Provide an example.
* **Code Reasoning:** If the answer involves code interpretation, provide examples with input/output.
* **Command-line Arguments:** Does this code handle command-line arguments?
* **Common Mistakes:** What errors might users make?
* **Summary (Part 2):** A concise overview of the functionality.

**2. Initial Observation and Interpretation:**

The code defines a `CipherSuite` struct and then initializes a `map` called `CipherSuites` where the keys are strings (cipher suite names) and the values are `CipherSuite` structs. This immediately suggests that the code is a *data definition* of various TLS/SSL cipher suites. It's not directly *performing* an action, but rather *describing* something.

**3. Addressing the "Functionality" Question:**

Based on the observation, the primary function is to provide a structured representation of different cipher suites. Each cipher suite entry includes details like its official IANA name, GnuTLS name, NSS name, supported protocol, key exchange algorithm (`Kx`), authentication algorithm (`Au`), encryption details (`Enc`), message authentication code (`Mac`), and a numerical code.

**4. Identifying the Go Language Feature:**

The core Go feature being used here is the combination of **structs** and **maps**. Structs are used to define the `CipherSuite` type, allowing for grouping related data. Maps are then used to create a collection of these structs, indexed by their string names.

**5. Crafting the Go Code Example:**

To illustrate how this data structure might be used, we need a simple example that demonstrates accessing and using the information stored in the `CipherSuites` map. A natural use case is to look up a cipher suite by its name and then print some of its attributes. This leads to the example code that retrieves a specific cipher suite ("TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256") and prints its IANA name, protocol, and encryption algorithm. The input is the hardcoded string "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", and the output is the formatted string containing the retrieved information.

**6. Considering Command-line Arguments:**

Reviewing the provided code, there is no explicit handling of command-line arguments. It's purely data definition. Therefore, the answer should state that command-line arguments are not processed in this snippet.

**7. Identifying Potential Mistakes:**

The most likely mistake users could make is attempting to access a cipher suite by a name that doesn't exist in the map. This would result in retrieving the zero value of the `CipherSuite` struct, which might lead to unexpected behavior or errors if the code doesn't handle this case properly. The example illustrating this would be trying to access "NON_EXISTENT_CIPHER".

**8. Addressing the "Summary (Part 2)" Question:**

The summary should concisely reiterate the core functionality. It defines a Go map that stores detailed information about various TLS/SSL cipher suites. This information can be used by other parts of the `tls-observatory` project to analyze or interact with TLS connections.

**Self-Correction/Refinement During the Process:**

* **Initial thought:**  Maybe this code is part of a function that actively negotiates TLS connections.
* **Correction:**  Looking closer, it's just a data structure. The names suggest these are *definitions*, not active connection logic.
* **Considering edge cases for mistakes:** What's the most common error when working with maps?  Accessing non-existent keys.
* **Ensuring clarity in the example:**  The example needs to clearly show how the map is accessed and what kind of information is retrieved. Using `fmt.Printf` with format specifiers makes the output readable.

By following this structured thought process, we can address each part of the request comprehensively and accurately, providing a clear and informative explanation of the Go code snippet.
## 功能列举

这段Go语言代码定义了一个名为 `CipherSuites` 的全局 `map` 变量。这个 `map` 的键（key）是字符串类型，代表了各种不同的密码套件的名称（例如 "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"）。值（value）是 `CipherSuite` 结构体类型的实例，包含了对应密码套件的详细信息。

具体来说，每个 `CipherSuite` 结构体包含了以下字段，描述了密码套件的各种属性：

* **IANAName:**  该密码套件在互联网号码分配机构（IANA）的标准名称。
* **GnuTLSName:** 该密码套件在 GnuTLS 库中的名称。
* **NSSName:** 该密码套件在 Network Security Services (NSS) 库中的名称。
* **Protocol:**  该密码套件支持的 TLS/SSL 协议版本（例如 "TLSv1.2"）。
* **ProtocolCode:**  该密码套件对应协议版本的数值代码。
* **Kx:**  密钥交换算法 (Key Exchange Algorithm)，例如 "ECDH" (椭圆曲线 Diffie-Hellman)。
* **Au:**  认证算法 (Authentication Algorithm)，例如 "RSA"。
* **Enc:**  一个嵌套的 `Encryption` 结构体，描述了加密算法。
    * **Cipher:**  使用的加密算法名称，例如 "AES"。
    * **Bits:**  加密密钥的位数，例如 128。
* **Mac:**  消息认证码算法 (Message Authentication Code Algorithm)，例如 "SHA256"。
* **Code:**  该密码套件的数值代码。

**总结来说，这段代码的功能是：**

1. **定义了 `CipherSuite` 结构体:**  用于组织和存储单个密码套件的详细属性信息。
2. **创建了 `CipherSuites` 映射表:**  存储了大量的 `CipherSuite` 实例，并以密码套件名称作为索引，方便快速查找和访问。
3. **提供了各种密码套件的元数据:**  包含了每个密码套件在不同标准和库中的名称、支持的协议、使用的密钥交换、认证、加密和消息认证算法等关键信息。

## Go语言功能实现举例 (结构体和映射)

这段代码主要使用了 Go 语言的 **结构体 (struct)** 和 **映射 (map)** 这两个核心数据结构。

**结构体 (struct)** 用于定义自定义的数据类型，可以将不同类型的数据字段组合在一起。`CipherSuite` 和 `Encryption` 就是结构体的例子。

**映射 (map)** 是一种键值对的数据结构，可以高效地根据键来查找对应的值。 `CipherSuites` 就是一个映射，将密码套件的名称映射到其详细信息。

**Go 代码示例：**

假设我们需要根据密码套件的名称来获取其加密算法的信息，可以像下面这样操作：

```go
package main

import "fmt"

// 假设这是你提供的代码片段中的结构体定义
type Encryption struct {
	Cipher string
	Bits   int
}

type CipherSuite struct {
	IANAName   string
	GnuTLSName string
	NSSName    string
	Protocol   string
	ProtocolCode int
	Kx         string
	Au         string
	Enc        Encryption
	Mac        string
	Code       int
}

var CipherSuites = map[string]CipherSuite{
	"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256": {
		IANAName:   "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
		GnuTLSName: "TLS_ECDHE_RSA_AES_128_GCM_SHA256",
		NSSName:    "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
		Protocol:   "TLSv1.2", ProtocolCode: 771,
		Kx: "ECDH",
		Au: "RSA",
		Enc: Encryption{
			Cipher: "AES",
			Bits:   128,
		},
		Mac:  "SHA256",
		Code: 49199,
	},
	// ... 其他密码套件的定义
}

func main() {
	cipherName := "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
	cipherInfo, ok := CipherSuites[cipherName]
	if ok {
		fmt.Printf("密码套件名称: %s\n", cipherName)
		fmt.Printf("加密算法: %s\n", cipherInfo.Enc.Cipher)
		fmt.Printf("密钥长度: %d 位\n", cipherInfo.Enc.Bits)
	} else {
		fmt.Printf("未找到密码套件: %s\n", cipherName)
	}
}
```

**假设的输入与输出：**

**输入:**  运行上面的 Go 代码。

**输出:**

```
密码套件名称: TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
加密算法: AES
密钥长度: 128 位
```

如果将 `cipherName` 改为一个不存在的密码套件名称，例如 `"NON_EXISTENT_CIPHER"`, 则输出会是：

```
未找到密码套件: NON_EXISTENT_CIPHER
```

## 命令行参数处理

这段代码本身并没有直接处理命令行参数。它只是一个数据定义的模块，用于存储密码套件的信息。如果需要在命令行中使用这些信息，需要编写额外的代码来读取命令行参数，并利用 `CipherSuites` 映射表中的数据进行相应的操作。

例如，可以编写一个命令行工具，接受一个密码套件名称作为参数，然后查找并打印该密码套件的详细信息。这需要使用 Go 语言的 `os` 包和 `flag` 包来处理命令行参数。

## 使用者易犯错的点

一个容易犯错的点是 **尝试访问不存在的密码套件名称**。由于 `CipherSuites` 是一个 `map`，如果使用一个不存在的键去访问，会返回该值类型的零值。对于 `CipherSuite` 结构体来说，这意味着所有字段都会是其类型的默认值（例如，字符串是空字符串，数字是 0）。  **使用者需要在使用前进行检查，确保要访问的密码套件名称是存在的。**

**示例：**

```go
package main

import "fmt"

// ... (CipherSuite 和 CipherSuites 的定义同上)

func main() {
	cipherName := "NON_EXISTENT_CIPHER"
	cipherInfo := CipherSuites[cipherName] // 这里不会报错，但 cipherInfo 是零值

	// 错误的使用方式，可能会导致意料之外的结果
	fmt.Println("协议:", cipherInfo.Protocol) // 输出：协议:
	fmt.Println("加密算法:", cipherInfo.Enc.Cipher) // 输出：加密算法:
}
```

为了避免这种情况，应该在使用前检查键是否存在：

```go
package main

import "fmt"

// ... (CipherSuite 和 CipherSuites 的定义同上)

func main() {
	cipherName := "NON_EXISTENT_CIPHER"
	cipherInfo, ok := CipherSuites[cipherName]
	if ok {
		// 安全地使用 cipherInfo
		fmt.Println("协议:", cipherInfo.Protocol)
	} else {
		fmt.Println("密码套件不存在")
	}
}
```

## 功能归纳 (第2部分)

总而言之，这段代码作为 `tls-observatory` 项目的一部分，其核心功能是 **提供一个静态的、结构化的密码套件信息数据库**。这个数据库包含了各种 TLS/SSL 密码套件的详细属性，例如它们在不同标准和库中的名称、支持的协议版本以及使用的加密算法等。  其他模块或功能可以利用这些数据来进行 TLS 连接分析、安全策略评估或其他与 TLS 相关的操作。 它可以被看作是一个 **预定义的常量集合**，方便程序内部引用和使用。

Prompt: 
```
这是路径为go/src/github.com/alecthomas/gometalinter/_linters/src/github.com/mozilla/tls-observatory/constants/ciphersuites.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第2部分，共2部分，请归纳一下它的功能

"""
ES_256_CBC_SHA384",
		Protocol:   "TLSv1.2", ProtocolCode: 771,
		Kx: "ECDH",
		Au: "RSA",
		Enc: Encryption{
			Cipher: "AES",
			Bits:   256,
		},
		Mac:  "SHA384",
		Code: 49192,
	},
	"ECDHE-RSA-CAMELLIA128-SHA256": CipherSuite{
		IANAName:   "TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256",
		GnuTLSName: "TLS_ECDHE_RSA_CAMELLIA_128_CBC_SHA256",
		NSSName:    "",
		Protocol:   "TLSv1.2", ProtocolCode: 771,
		Kx: "ECDH",
		Au: "RSA",
		Enc: Encryption{
			Cipher: "Camellia",
			Bits:   128,
		},
		Mac:  "SHA256",
		Code: 49270,
	},
	"ECDHE-RSA-CAMELLIA256-SHA384": CipherSuite{
		IANAName:   "TLS_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384",
		GnuTLSName: "TLS_ECDHE_RSA_CAMELLIA_256_CBC_SHA384",
		NSSName:    "",
		Protocol:   "TLSv1.2", ProtocolCode: 771,
		Kx: "ECDH",
		Au: "RSA",
		Enc: Encryption{
			Cipher: "Camellia",
			Bits:   256,
		},
		Mac:  "SHA384",
		Code: 49271,
	},
	"ECDHE-RSA-CHACHA20-POLY1305-OLD": CipherSuite{
		IANAName:   "",
		GnuTLSName: "",
		NSSName:    "",
		Protocol:   "TLSv1.2", ProtocolCode: 771,
		Kx: "ECDH",
		Au: "RSA",
		Enc: Encryption{
			Cipher: "ChaCha20",
			Bits:   256,
		},
		Mac:  "AEAD",
		Code: 52243,
	},
	"ECDHE-RSA-CHACHA20-POLY1305": CipherSuite{
		IANAName:   "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305",
		GnuTLSName: "TLS_ECDHE_RSA_CHACHA20_POLY1305",
		NSSName:    "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
		Protocol:   "TLSv1.2", ProtocolCode: 771,
		Kx: "ECDH",
		Au: "RSA",
		Enc: Encryption{
			Cipher: "ChaCha20",
			Bits:   256,
		},
		Mac:  "AEAD",
		Code: 52392,
	},
	"ECDHE-RSA-DES-CBC3-SHA": CipherSuite{
		IANAName:   "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA",
		GnuTLSName: "TLS_ECDHE_RSA_3DES_EDE_CBC_SHA1",
		NSSName:    "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA",
		Protocol:   "SSLv3", ProtocolCode: 768,
		Kx: "ECDH",
		Au: "RSA",
		Enc: Encryption{
			Cipher: "3DES",
			Bits:   168,
		},
		Mac:  "SHA1",
		Code: 49170,
	},
	"ECDHE-RSA-RC4-SHA": CipherSuite{
		IANAName:   "TLS_ECDHE_RSA_WITH_RC4_128_SHA",
		GnuTLSName: "TLS_ECDHE_RSA_ARCFOUR_128_SHA1",
		NSSName:    "TLS_ECDHE_RSA_WITH_RC4_128_SHA",
		Protocol:   "SSLv3", ProtocolCode: 768,
		Kx: "ECDH",
		Au: "RSA",
		Enc: Encryption{
			Cipher: "RC4",
			Bits:   128,
		},
		Mac:  "SHA1",
		Code: 49169,
	},
	"EDH-DSS-DES-CBC3-SHA": CipherSuite{
		IANAName:   "TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA",
		GnuTLSName: "TLS_DHE_DSS_3DES_EDE_CBC_SHA1",
		NSSName:    "TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA",
		Protocol:   "SSLv3", ProtocolCode: 768,
		Kx: "DH",
		Au: "DSS",
		Enc: Encryption{
			Cipher: "3DES",
			Bits:   168,
		},
		Mac:  "SHA1",
		Code: 19,
	},
	"EDH-RSA-DES-CBC3-SHA": CipherSuite{
		IANAName:   "TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA",
		GnuTLSName: "TLS_DHE_RSA_3DES_EDE_CBC_SHA1",
		NSSName:    "TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA",
		Protocol:   "SSLv3", ProtocolCode: 768,
		Kx: "DH",
		Au: "RSA",
		Enc: Encryption{
			Cipher: "3DES",
			Bits:   168,
		},
		Mac:  "SHA1",
		Code: 22,
	},
	"IDEA-CBC-SHA": CipherSuite{
		IANAName:   "TLS_RSA_WITH_IDEA_CBC_SHA",
		GnuTLSName: "",
		NSSName:    "TLS_RSA_WITH_IDEA_CBC_SHA",
		Protocol:   "SSLv3", ProtocolCode: 768,
		Kx: "RSA",
		Au: "RSA",
		Enc: Encryption{
			Cipher: "IDEA",
			Bits:   128,
		},
		Mac:  "SHA1",
		Code: 7,
	},
	"PSK-3DES-EDE-CBC-SHA": CipherSuite{
		IANAName:   "TLS_PSK_WITH_3DES_EDE_CBC_SHA",
		GnuTLSName: "TLS_PSK_3DES_EDE_CBC_SHA1",
		NSSName:    "",
		Protocol:   "SSLv3", ProtocolCode: 768,
		Kx: "PSK",
		Au: "PSK",
		Enc: Encryption{
			Cipher: "3DES",
			Bits:   168,
		},
		Mac:  "SHA1",
		Code: 139,
	},
	"PSK-AES128-CBC-SHA": CipherSuite{
		IANAName:   "TLS_PSK_WITH_AES_128_CBC_SHA",
		GnuTLSName: "TLS_PSK_AES_128_CBC_SHA1",
		NSSName:    "",
		Protocol:   "SSLv3", ProtocolCode: 768,
		Kx: "PSK",
		Au: "PSK",
		Enc: Encryption{
			Cipher: "AES",
			Bits:   128,
		},
		Mac:  "SHA1",
		Code: 140,
	},
	"PSK-AES256-CBC-SHA": CipherSuite{
		IANAName:   "TLS_PSK_WITH_AES_256_CBC_SHA",
		GnuTLSName: "TLS_PSK_AES_256_CBC_SHA1",
		NSSName:    "",
		Protocol:   "SSLv3", ProtocolCode: 768,
		Kx: "PSK",
		Au: "PSK",
		Enc: Encryption{
			Cipher: "AES",
			Bits:   256,
		},
		Mac:  "SHA1",
		Code: 141,
	},
	"PSK-RC4-SHA": CipherSuite{
		IANAName:   "TLS_PSK_WITH_RC4_128_SHA",
		GnuTLSName: "TLS_PSK_ARCFOUR_128_SHA1",
		NSSName:    "",
		Protocol:   "SSLv3", ProtocolCode: 768,
		Kx: "PSK",
		Au: "PSK",
		Enc: Encryption{
			Cipher: "RC4",
			Bits:   128,
		},
		Mac:  "SHA1",
		Code: 138,
	},
	"RC4-MD5": CipherSuite{
		IANAName:   "TLS_RSA_WITH_RC4_128_MD5",
		GnuTLSName: "TLS_RSA_ARCFOUR_128_MD5",
		NSSName:    "TLS_RSA_WITH_RC4_128_MD5",
		Protocol:   "SSLv3", ProtocolCode: 768,
		Kx: "RSA",
		Au: "RSA",
		Enc: Encryption{
			Cipher: "RC4",
			Bits:   128,
		},
		Mac:  "MD5",
		Code: 4,
	},
	"RC4-SHA": CipherSuite{
		IANAName:   "TLS_RSA_WITH_RC4_128_SHA",
		GnuTLSName: "TLS_RSA_ARCFOUR_128_SHA1",
		NSSName:    "TLS_RSA_WITH_RC4_128_SHA",
		Protocol:   "SSLv3", ProtocolCode: 768,
		Kx: "RSA",
		Au: "RSA",
		Enc: Encryption{
			Cipher: "RC4",
			Bits:   128,
		},
		Mac:  "SHA1",
		Code: 5,
	},
	"RSA-PSK-3DES-EDE-CBC-SHA": CipherSuite{
		IANAName:   "TLS_RSA_PSK_WITH_3DES_EDE_CBC_SHA",
		GnuTLSName: "TLS_RSA_PSK_3DES_EDE_CBC_SHA1",
		NSSName:    "",
		Protocol:   "SSLv3", ProtocolCode: 768,
		Kx: "RSAPSK",
		Au: "RSA",
		Enc: Encryption{
			Cipher: "3DES",
			Bits:   168,
		},
		Mac:  "SHA1",
		Code: 147,
	},
	"RSA-PSK-AES128-CBC-SHA": CipherSuite{
		IANAName:   "TLS_RSA_PSK_WITH_AES_128_CBC_SHA",
		GnuTLSName: "TLS_RSA_PSK_AES_128_CBC_SHA1",
		NSSName:    "",
		Protocol:   "SSLv3", ProtocolCode: 768,
		Kx: "RSAPSK",
		Au: "RSA",
		Enc: Encryption{
			Cipher: "AES",
			Bits:   128,
		},
		Mac:  "SHA1",
		Code: 148,
	},
	"RSA-PSK-AES256-CBC-SHA": CipherSuite{
		IANAName:   "TLS_RSA_PSK_WITH_AES_256_CBC_SHA",
		GnuTLSName: "TLS_RSA_PSK_AES_256_CBC_SHA1",
		NSSName:    "",
		Protocol:   "SSLv3", ProtocolCode: 768,
		Kx: "RSAPSK",
		Au: "RSA",
		Enc: Encryption{
			Cipher: "AES",
			Bits:   256,
		},
		Mac:  "SHA1",
		Code: 149,
	},
	"RSA-PSK-RC4-SHA": CipherSuite{
		IANAName:   "TLS_RSA_PSK_WITH_RC4_128_SHA",
		GnuTLSName: "TLS_RSA_PSK_ARCFOUR_128_SHA1",
		NSSName:    "",
		Protocol:   "SSLv3", ProtocolCode: 768,
		Kx: "RSAPSK",
		Au: "RSA",
		Enc: Encryption{
			Cipher: "RC4",
			Bits:   128,
		},
		Mac:  "SHA1",
		Code: 146,
	},
	"SEED-SHA": CipherSuite{
		IANAName:   "TLS_RSA_WITH_SEED_CBC_SHA",
		GnuTLSName: "",
		NSSName:    "TLS_RSA_WITH_SEED_CBC_SHA",
		Protocol:   "SSLv3", ProtocolCode: 768,
		Kx: "RSA",
		Au: "RSA",
		Enc: Encryption{
			Cipher: "SEED",
			Bits:   128,
		},
		Mac:  "SHA1",
		Code: 150,
	},
	"SRP-3DES-EDE-CBC-SHA": CipherSuite{
		IANAName:   "TLS_SRP_SHA_WITH_3DES_EDE_CBC_SHA",
		GnuTLSName: "TLS_SRP_SHA_3DES_EDE_CBC_SHA1",
		NSSName:    "",
		Protocol:   "SSLv3", ProtocolCode: 768,
		Kx: "SRP",
		Au: "SRP",
		Enc: Encryption{
			Cipher: "3DES",
			Bits:   168,
		},
		Mac:  "SHA1",
		Code: 49178,
	},
	"SRP-AES-128-CBC-SHA": CipherSuite{
		IANAName:   "TLS_SRP_SHA_WITH_AES_128_CBC_SHA",
		GnuTLSName: "TLS_SRP_SHA_AES_128_CBC_SHA1",
		NSSName:    "",
		Protocol:   "SSLv3", ProtocolCode: 768,
		Kx: "SRP",
		Au: "SRP",
		Enc: Encryption{
			Cipher: "AES",
			Bits:   128,
		},
		Mac:  "SHA1",
		Code: 49181,
	},
	"SRP-AES-256-CBC-SHA": CipherSuite{
		IANAName:   "TLS_SRP_SHA_WITH_AES_256_CBC_SHA",
		GnuTLSName: "TLS_SRP_SHA_AES_256_CBC_SHA1",
		NSSName:    "",
		Protocol:   "SSLv3", ProtocolCode: 768,
		Kx: "SRP",
		Au: "SRP",
		Enc: Encryption{
			Cipher: "AES",
			Bits:   256,
		},
		Mac:  "SHA1",
		Code: 49184,
	},
	"SRP-DSS-3DES-EDE-CBC-SHA": CipherSuite{
		IANAName:   "TLS_SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA",
		GnuTLSName: "TLS_SRP_SHA_DSS_3DES_EDE_CBC_SHA1",
		NSSName:    "",
		Protocol:   "SSLv3", ProtocolCode: 768,
		Kx: "SRP",
		Au: "DSS",
		Enc: Encryption{
			Cipher: "3DES",
			Bits:   168,
		},
		Mac:  "SHA1",
		Code: 49180,
	},
	"SRP-DSS-AES-128-CBC-SHA": CipherSuite{
		IANAName:   "TLS_SRP_SHA_DSS_WITH_AES_128_CBC_SHA",
		GnuTLSName: "TLS_SRP_SHA_DSS_AES_128_CBC_SHA1",
		NSSName:    "",
		Protocol:   "SSLv3", ProtocolCode: 768,
		Kx: "SRP",
		Au: "DSS",
		Enc: Encryption{
			Cipher: "AES",
			Bits:   128,
		},
		Mac:  "SHA1",
		Code: 49183,
	},
	"SRP-DSS-AES-256-CBC-SHA": CipherSuite{
		IANAName:   "TLS_SRP_SHA_DSS_WITH_AES_256_CBC_SHA",
		GnuTLSName: "TLS_SRP_SHA_DSS_AES_256_CBC_SHA1",
		NSSName:    "",
		Protocol:   "SSLv3", ProtocolCode: 768,
		Kx: "SRP",
		Au: "DSS",
		Enc: Encryption{
			Cipher: "AES",
			Bits:   256,
		},
		Mac:  "SHA1",
		Code: 49186,
	},
	"SRP-RSA-3DES-EDE-CBC-SHA": CipherSuite{
		IANAName:   "TLS_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA",
		GnuTLSName: "TLS_SRP_SHA_RSA_3DES_EDE_CBC_SHA1",
		NSSName:    "",
		Protocol:   "SSLv3", ProtocolCode: 768,
		Kx: "SRP",
		Au: "RSA",
		Enc: Encryption{
			Cipher: "3DES",
			Bits:   168,
		},
		Mac:  "SHA1",
		Code: 49179,
	},
	"SRP-RSA-AES-128-CBC-SHA": CipherSuite{
		IANAName:   "TLS_SRP_SHA_RSA_WITH_AES_128_CBC_SHA",
		GnuTLSName: "TLS_SRP_SHA_RSA_AES_128_CBC_SHA1",
		NSSName:    "",
		Protocol:   "SSLv3", ProtocolCode: 768,
		Kx: "SRP",
		Au: "RSA",
		Enc: Encryption{
			Cipher: "AES",
			Bits:   128,
		},
		Mac:  "SHA1",
		Code: 49182,
	},
	"SRP-RSA-AES-256-CBC-SHA": CipherSuite{
		IANAName:   "TLS_SRP_SHA_RSA_WITH_AES_256_CBC_SHA",
		GnuTLSName: "TLS_SRP_SHA_RSA_AES_256_CBC_SHA1",
		NSSName:    "",
		Protocol:   "SSLv3", ProtocolCode: 768,
		Kx: "SRP",
		Au: "RSA",
		Enc: Encryption{
			Cipher: "AES",
			Bits:   256,
		},
		Mac:  "SHA1",
		Code: 49185,
	},
}

"""




```