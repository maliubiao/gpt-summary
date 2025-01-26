Response:
Let's break down the thought process for answering this request.

1. **Understand the Goal:** The request asks for the functionality of the provided Go code, explanations of its Go features, examples, command-line handling (if any), common mistakes, and a summary. It's crucial to identify this is part 1 of 2, implying more context might come later.

2. **Initial Code Analysis (Structure):**
   - The code defines a `CipherSuite` struct. This immediately suggests it's about representing different TLS/SSL cipher suites.
   - The `CipherSuite` struct has fields for various names (IANA, GnuTLS, NSS), protocol information, key exchange (`Kx`), authentication (`Au`), encryption details (`Enc`), MAC algorithm, and a numerical code. This reinforces the idea of representing cipher suite characteristics.
   - An `Encryption` struct is nested within `CipherSuite`, holding the cipher name and bit size.
   - A `map[string]CipherSuite` named `CipherSuites` is declared and initialized with numerous entries. The keys of this map are human-readable cipher suite names (like "AES128-GCM-SHA256"). The values are `CipherSuite` structs containing detailed information.

3. **Inferring Functionality:** Based on the structure and field names, the primary function is to **provide a data structure and a pre-populated map containing information about various TLS/SSL cipher suites.**  This information is likely used to look up details about a specific cipher suite based on its common name.

4. **Identifying Go Features:**
   - **Structs (`type CipherSuite struct { ... }` and `type Encryption struct { ... }`):**  This is a fundamental Go feature for defining custom data types.
   - **Struct Tags (`json:"..."`):** These tags indicate the structs are intended for serialization/deserialization, most likely to JSON format. This suggests the data might be used in an API or configuration file.
   - **Maps (`var CipherSuites = map[string]CipherSuite{ ... }`):** Go's built-in associative data structure, perfect for looking up cipher suite information by name.
   - **String Literals and Basic Types:** The data within the map utilizes string literals, `uint64`, and `int`.

5. **Crafting Go Code Examples:**
   - **Accessing Cipher Suite Information:**  The most obvious use case is to look up a cipher suite by its string key. The example should demonstrate accessing fields within the `CipherSuite` struct.
   - **Iterating Through Cipher Suites:** Another common use case is to process all available cipher suites. The example should show how to iterate over the map.
   - **JSON Serialization (Based on Struct Tags):** Since the struct tags suggest JSON usage, an example demonstrating how to marshal the `CipherSuites` map to JSON is valuable.

6. **Considering Command-Line Arguments:**  Based on the provided code snippet alone, there's no direct indication of command-line argument processing. It's a data definition file. Therefore, the answer should state this lack of direct handling. However, it's good to mention that *users* of this data *might* use command-line arguments to select or filter cipher suites.

7. **Identifying Common Mistakes:**
   - **Case Sensitivity:**  Map lookups in Go are case-sensitive. Users might incorrectly assume the key is case-insensitive.
   - **Incorrect Key:**  Typos or using an unsupported cipher suite name will result in a `nil` or zero-value lookup.
   - **Assuming All Fields Are Always Present:** Some `NSSName` fields are empty. Users need to handle cases where optional fields might be missing.

8. **Summarizing Functionality (Part 1):**  The summary should be concise and highlight the key purpose: defining a data structure and a map containing TLS/SSL cipher suite information for programmatic access.

9. **Review and Refine:** Read through the generated answer to ensure clarity, accuracy, and completeness based on the given information. Check for any inconsistencies or areas that could be explained better. Make sure to explicitly mention that this is based *only* on the provided snippet.

**Self-Correction/Refinement During the Process:**

- Initially, I might have focused too much on the individual fields of the `CipherSuite` struct without first establishing the overall purpose. It's important to start with the high-level functionality.
- I might have initially missed the implication of the JSON struct tags. Recognizing these tags leads to a more complete understanding of how the data is likely used.
- I might have considered command-line arguments too early. It's crucial to stick to what the provided code *actually* does. While speculating about potential usage is helpful, the core answer should focus on the given code.

By following these steps, including careful analysis, feature identification, example crafting, and consideration of potential issues, a comprehensive and accurate answer can be constructed. The iterative refinement process helps to catch any initial oversights or areas needing more clarity.
好的，让我们来分析一下这段 Go 语言代码的功能。

**功能归纳（第1部分）：**

这段 Go 代码的主要功能是**定义并存储了关于各种 TLS/SSL 密码套件的详细信息**。它通过以下方式实现：

1. **定义了两个结构体 `CipherSuite` 和 `Encryption`:**
   - `CipherSuite` 结构体用于描述一个完整的密码套件，包含了该密码套件在不同标准和库（IANA, GnuTLS, NSS）中的名称、所使用的 TLS/SSL 协议版本、密钥交换算法 (`Kx`)、认证算法 (`Au`)、加密算法 (`Enc`)、消息认证码算法 (`Mac`) 以及一个数值编码 (`Code`)。
   - `Encryption` 结构体是 `CipherSuite` 的一个组成部分，用于描述加密算法的名称 (`Cipher`) 和密钥长度 (`Bits`)。

2. **创建了一个全局的 `map` 变量 `CipherSuites`:**
   - 这个 `map` 的键是字符串类型，代表密码套件的通用名称（例如 "AES128-GCM-SHA256"）。
   - 这个 `map` 的值是 `CipherSuite` 结构体，包含了对应密码套件的详细信息。

3. **预先填充了 `CipherSuites` map 大量的密码套件数据:**
   - 代码中硬编码了许多常见的 TLS/SSL 密码套件及其详细信息，包括不同的加密算法（AES, Camellia, 3DES, ChaCha20, RC4, SEED）、不同的密钥长度、不同的哈希算法（SHA1, SHA256, SHA384）以及不同的密钥交换和认证机制（RSA, DH, ECDH, ECDSA）。
   - 对于每个密码套件，都尽可能地提供了在 IANA、GnuTLS 和 NSS 这三个常见 TLS/SSL 库中的名称，方便跨平台和库的使用。

**可以推理出的 Go 语言功能实现及代码示例：**

这段代码主要使用了 Go 语言的以下特性：

* **结构体 (Structs):** 用于定义复杂的数据类型，将相关的字段组合在一起。
* **结构体标签 (Struct Tags):**  `json:"..."` 这样的标签用于指导 JSON 序列化和反序列化的过程，表明这些结构体很可能用于数据的外部表示和传输。
* **Map (字典):** 用于存储键值对，方便根据密码套件名称快速查找其详细信息.
* **常量 (Constants - 隐式):** 虽然没有显式定义常量，但是 `CipherSuites` 这个 `map` 可以被认为是存储了一组常量数据。

**代码示例：**

假设我们需要获取 "AES128-GCM-SHA256" 密码套件的详细信息，并打印出它的 IANA 名称和加密算法：

```go
package main

import (
	"fmt"
	"go/src/github.com/alecthomas/gometalinter/_linters/src/github.com/mozilla/tls-observatory/constants" // 假设你的代码在这个路径下
)

func main() {
	cipherSuite, ok := constants.CipherSuites["AES128-GCM-SHA256"]
	if ok {
		fmt.Println("IANA Name:", cipherSuite.IANAName)
		fmt.Println("Encryption Cipher:", cipherSuite.Enc.Cipher)
	} else {
		fmt.Println("Cipher suite not found")
	}
}

// 假设的输出：
// IANA Name: TLS_RSA_WITH_AES_128_GCM_SHA256
// Encryption Cipher: AESGCM
```

再比如，我们可以遍历 `CipherSuites` 这个 `map`，打印出所有支持的密码套件名称和协议：

```go
package main

import (
	"fmt"
	"go/src/github.com/alecthomas/gometalinter/_linters/src/github.com/mozilla/tls-observatory/constants" // 假设你的代码在这个路径下
)

func main() {
	for name, suite := range constants.CipherSuites {
		fmt.Printf("Cipher Suite: %s, Protocol: %s\n", name, suite.Protocol)
	}
}

// 假设的输出（部分）：
// Cipher Suite: AES128-GCM-SHA256, Protocol: TLSv1.2
// Cipher Suite: AES128-SHA, Protocol: SSLv3
// ... (其他密码套件)
```

**命令行参数的具体处理：**

从这段代码本身来看，**并没有涉及任何命令行参数的处理**。这段代码只是定义了一些数据结构和数据，它更像是一个数据存储或者常量定义的文件。

如果该代码被其他模块使用，那么处理命令行参数的方式取决于使用它的那个模块的具体实现。例如，一个使用这个 `constants` 包的工具可能会使用 `flag` 包或者其他命令行解析库来接收用户输入的密码套件名称，然后从 `CipherSuites` map 中查找相应的信息。

**使用者易犯错的点：**

1. **拼写错误或大小写错误：** 在使用 `CipherSuites` 这个 map 时，键是字符串，因此对大小写敏感。如果输入的密码套件名称拼写错误或者大小写不一致，将无法找到对应的密码套件信息。

   ```go
   // 错误示例：
   cipherSuite, ok := constants.CipherSuites["aes128-gcm-sha256"] // 小写 'a'
   if !ok {
       fmt.Println("Cipher suite not found") // 很有可能输出这个
   }
   ```

2. **假设所有字段都存在：**  可以看到有些密码套件的 `NSSName` 字段是空字符串 `""`。如果使用者没有考虑到这种情况，直接访问 `cipherSuite.NSSName`，可能会得到空字符串，而没有进行合适的处理。

**总结（针对第1部分）：**

这段代码定义了一个 Go 包 `constants`，其核心功能是维护一个包含各种 TLS/SSL 密码套件详细信息的 `map`。这个 `map` 的键是密码套件的通用名称，值是一个包含了密码套件在不同标准和库中名称、协议、加密算法、认证算法等详细信息的结构体。这段代码主要用于提供一个方便查询和使用 TLS/SSL 密码套件信息的常量数据源，供其他模块使用。它本身不处理命令行参数，使用者需要注意字符串键的大小写和可能存在的空字段。

Prompt: 
```
这是路径为go/src/github.com/alecthomas/gometalinter/_linters/src/github.com/mozilla/tls-observatory/constants/ciphersuites.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第1部分，共2部分，请归纳一下它的功能

"""
package constants

type CipherSuite struct {
	IANAName     string     `json:"iana_name"`
	GnuTLSName   string     `json:"gnutls_name"`
	NSSName      string     `json:"nss_name"`
	Protocol     string     `json:"protocol"`
	ProtocolCode uint64     `json:"protocol_code"`
	Kx           string     `json:"kx"`
	Au           string     `json:"au"`
	Enc          Encryption `json:"encryption"`
	Mac          string     `json:"mac"`
	Code         uint64     `json:"code"`
}

type Encryption struct {
	Cipher string `json:"cipher"`
	Bits   int    `json:"bits"`
}

var CipherSuites = map[string]CipherSuite{
	"AES128-GCM-SHA256": CipherSuite{
		IANAName:   "TLS_RSA_WITH_AES_128_GCM_SHA256",
		GnuTLSName: "TLS_RSA_AES_128_GCM_SHA256",
		NSSName:    "TLS_RSA_WITH_AES_128_GCM_SHA256",
		Protocol:   "TLSv1.2", ProtocolCode: 771,
		Kx: "RSA",
		Au: "RSA",
		Enc: Encryption{
			Cipher: "AESGCM",
			Bits:   128,
		},
		Mac:  "AEAD",
		Code: 156,
	},
	"AES128-SHA": CipherSuite{
		IANAName:   "TLS_RSA_WITH_AES_128_CBC_SHA",
		GnuTLSName: "TLS_RSA_AES_128_CBC_SHA1",
		NSSName:    "TLS_RSA_WITH_AES_128_CBC_SHA",
		Protocol:   "SSLv3", ProtocolCode: 768,
		Kx: "RSA",
		Au: "RSA",
		Enc: Encryption{
			Cipher: "AES",
			Bits:   128,
		},
		Mac:  "SHA1",
		Code: 47,
	},
	"AES128-SHA256": CipherSuite{
		IANAName:   "TLS_RSA_WITH_AES_128_CBC_SHA256",
		GnuTLSName: "TLS_RSA_AES_128_CBC_SHA256",
		NSSName:    "TLS_RSA_WITH_AES_128_CBC_SHA256",
		Protocol:   "TLSv1.2", ProtocolCode: 771,
		Kx: "RSA",
		Au: "RSA",
		Enc: Encryption{
			Cipher: "AES",
			Bits:   128,
		},
		Mac:  "SHA256",
		Code: 60,
	},
	"AES256-GCM-SHA384": CipherSuite{
		IANAName:   "TLS_RSA_WITH_AES_256_GCM_SHA384",
		GnuTLSName: "TLS_RSA_AES_256_GCM_SHA384",
		NSSName:    "TLS_RSA_WITH_AES_256_GCM_SHA384",
		Protocol:   "TLSv1.2", ProtocolCode: 771,
		Kx: "RSA",
		Au: "RSA",
		Enc: Encryption{
			Cipher: "AESGCM",
			Bits:   256,
		},
		Mac:  "AEAD",
		Code: 157,
	},
	"AES256-SHA": CipherSuite{
		IANAName:   "TLS_RSA_WITH_AES_256_CBC_SHA",
		GnuTLSName: "TLS_RSA_AES_256_CBC_SHA1",
		NSSName:    "TLS_RSA_WITH_AES_256_CBC_SHA",
		Protocol:   "SSLv3", ProtocolCode: 768,
		Kx: "RSA",
		Au: "RSA",
		Enc: Encryption{
			Cipher: "AES",
			Bits:   256,
		},
		Mac:  "SHA1",
		Code: 53,
	},
	"AES256-SHA256": CipherSuite{
		IANAName:   "TLS_RSA_WITH_AES_256_CBC_SHA256",
		GnuTLSName: "TLS_RSA_AES_256_CBC_SHA256",
		NSSName:    "TLS_RSA_WITH_AES_256_CBC_SHA256",
		Protocol:   "TLSv1.2", ProtocolCode: 771,
		Kx: "RSA",
		Au: "RSA",
		Enc: Encryption{
			Cipher: "AES",
			Bits:   256,
		},
		Mac:  "SHA256",
		Code: 61,
	},
	"CAMELLIA128-SHA": CipherSuite{
		IANAName:   "TLS_RSA_WITH_CAMELLIA_128_CBC_SHA",
		GnuTLSName: "TLS_RSA_CAMELLIA_128_CBC_SHA1",
		NSSName:    "TLS_RSA_WITH_CAMELLIA_128_CBC_SHA",
		Protocol:   "SSLv3", ProtocolCode: 768,
		Kx: "RSA",
		Au: "RSA",
		Enc: Encryption{
			Cipher: "Camellia",
			Bits:   128,
		},
		Mac:  "SHA1",
		Code: 65,
	},
	"CAMELLIA128-SHA256": CipherSuite{
		IANAName:   "TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256",
		GnuTLSName: "TLS_RSA_CAMELLIA_128_CBC_SHA256",
		NSSName:    "",
		Protocol:   "TLSv1.2", ProtocolCode: 771,
		Kx: "RSA",
		Au: "RSA",
		Enc: Encryption{
			Cipher: "Camellia",
			Bits:   128,
		},
		Mac:  "SHA256",
		Code: 186,
	},
	"CAMELLIA256-SHA": CipherSuite{
		IANAName:   "TLS_RSA_WITH_CAMELLIA_256_CBC_SHA",
		GnuTLSName: "TLS_RSA_CAMELLIA_256_CBC_SHA1",
		NSSName:    "TLS_RSA_WITH_CAMELLIA_256_CBC_SHA",
		Protocol:   "SSLv3", ProtocolCode: 768,
		Kx: "RSA",
		Au: "RSA",
		Enc: Encryption{
			Cipher: "Camellia",
			Bits:   256,
		},
		Mac:  "SHA1",
		Code: 132,
	},
	"CAMELLIA256-SHA256": CipherSuite{
		IANAName:   "TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256",
		GnuTLSName: "TLS_RSA_CAMELLIA_256_CBC_SHA256",
		NSSName:    "",
		Protocol:   "TLSv1.2", ProtocolCode: 771,
		Kx: "RSA",
		Au: "RSA",
		Enc: Encryption{
			Cipher: "Camellia",
			Bits:   256,
		},
		Mac:  "SHA256",
		Code: 192,
	},
	"DES-CBC3-SHA": CipherSuite{
		IANAName:   "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
		GnuTLSName: "TLS_RSA_3DES_EDE_CBC_SHA1",
		NSSName:    "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
		Protocol:   "SSLv3", ProtocolCode: 768,
		Kx: "RSA",
		Au: "RSA",
		Enc: Encryption{
			Cipher: "3DES",
			Bits:   168,
		},
		Mac:  "SHA1",
		Code: 10,
	},
	"DH-DSS-AES128-GCM-SHA256": CipherSuite{
		IANAName:   "TLS_DH_DSS_WITH_AES_128_GCM_SHA256",
		GnuTLSName: "",
		NSSName:    "",
		Protocol:   "TLSv1.2", ProtocolCode: 771,
		Kx: "DH/DSS",
		Au: "DH",
		Enc: Encryption{
			Cipher: "AESGCM",
			Bits:   128,
		},
		Mac:  "AEAD",
		Code: 164,
	},
	"DH-DSS-AES128-SHA": CipherSuite{
		IANAName:   "TLS_DH_DSS_WITH_AES_128_CBC_SHA",
		GnuTLSName: "",
		NSSName:    "TLS_DH_DSS_WITH_AES_128_CBC_SHA",
		Protocol:   "SSLv3", ProtocolCode: 768,
		Kx: "DH/DSS",
		Au: "DH",
		Enc: Encryption{
			Cipher: "AES",
			Bits:   128,
		},
		Mac:  "SHA1",
		Code: 48,
	},
	"DH-DSS-AES128-SHA256": CipherSuite{
		IANAName:   "TLS_DH_DSS_WITH_AES_128_CBC_SHA256",
		GnuTLSName: "",
		NSSName:    "",
		Protocol:   "TLSv1.2", ProtocolCode: 771,
		Kx: "DH/DSS",
		Au: "DH",
		Enc: Encryption{
			Cipher: "AES",
			Bits:   128,
		},
		Mac:  "SHA256",
		Code: 62,
	},
	"DH-DSS-AES256-GCM-SHA384": CipherSuite{
		IANAName:   "TLS_DH_DSS_WITH_AES_256_GCM_SHA384",
		GnuTLSName: "",
		NSSName:    "",
		Protocol:   "TLSv1.2", ProtocolCode: 771,
		Kx: "DH/DSS",
		Au: "DH",
		Enc: Encryption{
			Cipher: "AESGCM",
			Bits:   256,
		},
		Mac:  "AEAD",
		Code: 165,
	},
	"DH-DSS-AES256-SHA": CipherSuite{
		IANAName:   "TLS_DH_DSS_WITH_AES_256_CBC_SHA",
		GnuTLSName: "",
		NSSName:    "TLS_DH_DSS_WITH_AES_256_CBC_SHA",
		Protocol:   "SSLv3", ProtocolCode: 768,
		Kx: "DH/DSS",
		Au: "DH",
		Enc: Encryption{
			Cipher: "AES",
			Bits:   256,
		},
		Mac:  "SHA1",
		Code: 54,
	},
	"DH-DSS-AES256-SHA256": CipherSuite{
		IANAName:   "TLS_DH_DSS_WITH_AES_256_CBC_SHA256",
		GnuTLSName: "",
		NSSName:    "",
		Protocol:   "TLSv1.2", ProtocolCode: 771,
		Kx: "DH/DSS",
		Au: "DH",
		Enc: Encryption{
			Cipher: "AES",
			Bits:   256,
		},
		Mac:  "SHA256",
		Code: 104,
	},
	"DH-DSS-CAMELLIA128-SHA": CipherSuite{
		IANAName:   "TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA",
		GnuTLSName: "",
		NSSName:    "TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA",
		Protocol:   "SSLv3", ProtocolCode: 768,
		Kx: "DH/DSS",
		Au: "DH",
		Enc: Encryption{
			Cipher: "Camellia",
			Bits:   128,
		},
		Mac:  "SHA1",
		Code: 66,
	},
	"DH-DSS-CAMELLIA128-SHA256": CipherSuite{
		IANAName:   "TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA256",
		GnuTLSName: "",
		NSSName:    "",
		Protocol:   "TLSv1.2", ProtocolCode: 771,
		Kx: "DH/DSS",
		Au: "DH",
		Enc: Encryption{
			Cipher: "Camellia",
			Bits:   128,
		},
		Mac:  "SHA256",
		Code: 187,
	},
	"DH-DSS-CAMELLIA256-SHA": CipherSuite{
		IANAName:   "TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA",
		GnuTLSName: "",
		NSSName:    "TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA",
		Protocol:   "SSLv3", ProtocolCode: 768,
		Kx: "DH/DSS",
		Au: "DH",
		Enc: Encryption{
			Cipher: "Camellia",
			Bits:   256,
		},
		Mac:  "SHA1",
		Code: 133,
	},
	"DH-DSS-CAMELLIA256-SHA256": CipherSuite{
		IANAName:   "TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA256",
		GnuTLSName: "",
		NSSName:    "",
		Protocol:   "TLSv1.2", ProtocolCode: 771,
		Kx: "DH/DSS",
		Au: "DH",
		Enc: Encryption{
			Cipher: "Camellia",
			Bits:   256,
		},
		Mac:  "SHA256",
		Code: 193,
	},
	"DH-DSS-DES-CBC3-SHA": CipherSuite{
		IANAName:   "TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA",
		GnuTLSName: "",
		NSSName:    "TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA",
		Protocol:   "SSLv3", ProtocolCode: 768,
		Kx: "DH/DSS",
		Au: "DH",
		Enc: Encryption{
			Cipher: "3DES",
			Bits:   168,
		},
		Mac:  "SHA1",
		Code: 13,
	},
	"DH-DSS-SEED-SHA": CipherSuite{
		IANAName:   "TLS_DH_DSS_WITH_SEED_CBC_SHA",
		GnuTLSName: "",
		NSSName:    "",
		Protocol:   "SSLv3", ProtocolCode: 768,
		Kx: "DH/DSS",
		Au: "DH",
		Enc: Encryption{
			Cipher: "SEED",
			Bits:   128,
		},
		Mac:  "SHA1",
		Code: 151,
	},
	"DH-RSA-AES128-GCM-SHA256": CipherSuite{
		IANAName:   "TLS_DH_RSA_WITH_AES_128_GCM_SHA256",
		GnuTLSName: "",
		NSSName:    "",
		Protocol:   "TLSv1.2", ProtocolCode: 771,
		Kx: "DH/RSA",
		Au: "DH",
		Enc: Encryption{
			Cipher: "AESGCM",
			Bits:   128,
		},
		Mac:  "AEAD",
		Code: 160,
	},
	"DH-RSA-AES128-SHA": CipherSuite{
		IANAName:   "TLS_DH_RSA_WITH_AES_128_CBC_SHA",
		GnuTLSName: "",
		NSSName:    "TLS_DH_RSA_WITH_AES_128_CBC_SHA",
		Protocol:   "SSLv3", ProtocolCode: 768,
		Kx: "DH/RSA",
		Au: "DH",
		Enc: Encryption{
			Cipher: "AES",
			Bits:   128,
		},
		Mac:  "SHA1",
		Code: 49,
	},
	"DH-RSA-AES128-SHA256": CipherSuite{
		IANAName:   "TLS_DH_RSA_WITH_AES_128_CBC_SHA256",
		GnuTLSName: "",
		NSSName:    "",
		Protocol:   "TLSv1.2", ProtocolCode: 771,
		Kx: "DH/RSA",
		Au: "DH",
		Enc: Encryption{
			Cipher: "AES",
			Bits:   128,
		},
		Mac:  "SHA256",
		Code: 63,
	},
	"DH-RSA-AES256-GCM-SHA384": CipherSuite{
		IANAName:   "TLS_DH_RSA_WITH_AES_256_GCM_SHA384",
		GnuTLSName: "",
		NSSName:    "",
		Protocol:   "TLSv1.2", ProtocolCode: 771,
		Kx: "DH/RSA",
		Au: "DH",
		Enc: Encryption{
			Cipher: "AESGCM",
			Bits:   256,
		},
		Mac:  "AEAD",
		Code: 161,
	},
	"DH-RSA-AES256-SHA": CipherSuite{
		IANAName:   "TLS_DH_RSA_WITH_AES_256_CBC_SHA",
		GnuTLSName: "",
		NSSName:    "TLS_DH_RSA_WITH_AES_256_CBC_SHA",
		Protocol:   "SSLv3", ProtocolCode: 768,
		Kx: "DH/RSA",
		Au: "DH",
		Enc: Encryption{
			Cipher: "AES",
			Bits:   256,
		},
		Mac:  "SHA1",
		Code: 55,
	},
	"DH-RSA-AES256-SHA256": CipherSuite{
		IANAName:   "TLS_DH_RSA_WITH_AES_256_CBC_SHA256",
		GnuTLSName: "",
		NSSName:    "",
		Protocol:   "TLSv1.2", ProtocolCode: 771,
		Kx: "DH/RSA",
		Au: "DH",
		Enc: Encryption{
			Cipher: "AES",
			Bits:   256,
		},
		Mac:  "SHA256",
		Code: 105,
	},
	"DH-RSA-CAMELLIA128-SHA": CipherSuite{
		IANAName:   "TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA",
		GnuTLSName: "",
		NSSName:    "TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA",
		Protocol:   "SSLv3", ProtocolCode: 768,
		Kx: "DH/RSA",
		Au: "DH",
		Enc: Encryption{
			Cipher: "Camellia",
			Bits:   128,
		},
		Mac:  "SHA1",
		Code: 67,
	},
	"DH-RSA-CAMELLIA128-SHA256": CipherSuite{
		IANAName:   "TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA256",
		GnuTLSName: "",
		NSSName:    "",
		Protocol:   "TLSv1.2", ProtocolCode: 771,
		Kx: "DH/RSA",
		Au: "DH",
		Enc: Encryption{
			Cipher: "Camellia",
			Bits:   128,
		},
		Mac:  "SHA256",
		Code: 188,
	},
	"DH-RSA-CAMELLIA256-SHA": CipherSuite{
		IANAName:   "TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA",
		GnuTLSName: "",
		NSSName:    "TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA",
		Protocol:   "SSLv3", ProtocolCode: 768,
		Kx: "DH/RSA",
		Au: "DH",
		Enc: Encryption{
			Cipher: "Camellia",
			Bits:   256,
		},
		Mac:  "SHA1",
		Code: 134,
	},
	"DH-RSA-CAMELLIA256-SHA256": CipherSuite{
		IANAName:   "TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA256",
		GnuTLSName: "",
		NSSName:    "",
		Protocol:   "TLSv1.2", ProtocolCode: 771,
		Kx: "DH/RSA",
		Au: "DH",
		Enc: Encryption{
			Cipher: "Camellia",
			Bits:   256,
		},
		Mac:  "SHA256",
		Code: 194,
	},
	"DH-RSA-DES-CBC3-SHA": CipherSuite{
		IANAName:   "TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA",
		GnuTLSName: "",
		NSSName:    "TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA",
		Protocol:   "SSLv3", ProtocolCode: 768,
		Kx: "DH/RSA",
		Au: "DH",
		Enc: Encryption{
			Cipher: "3DES",
			Bits:   168,
		},
		Mac:  "SHA1",
		Code: 16,
	},
	"DH-RSA-SEED-SHA": CipherSuite{
		IANAName:   "TLS_DH_RSA_WITH_SEED_CBC_SHA",
		GnuTLSName: "",
		NSSName:    "",
		Protocol:   "SSLv3", ProtocolCode: 768,
		Kx: "DH/RSA",
		Au: "DH",
		Enc: Encryption{
			Cipher: "SEED",
			Bits:   128,
		},
		Mac:  "SHA1",
		Code: 152,
	},
	"DHE-DSS-AES128-GCM-SHA256": CipherSuite{
		IANAName:   "TLS_DHE_DSS_WITH_AES_128_GCM_SHA256",
		GnuTLSName: "TLS_DHE_DSS_AES_128_GCM_SHA256",
		NSSName:    "TLS_DHE_DSS_WITH_AES_128_GCM_SHA256",
		Protocol:   "TLSv1.2", ProtocolCode: 771,
		Kx: "DH",
		Au: "DSS",
		Enc: Encryption{
			Cipher: "AESGCM",
			Bits:   128,
		},
		Mac:  "AEAD",
		Code: 162,
	},
	"DHE-DSS-AES128-SHA": CipherSuite{
		IANAName:   "TLS_DHE_DSS_WITH_AES_128_CBC_SHA",
		GnuTLSName: "TLS_DHE_DSS_AES_128_CBC_SHA1",
		NSSName:    "TLS_DHE_DSS_WITH_AES_128_CBC_SHA",
		Protocol:   "SSLv3", ProtocolCode: 768,
		Kx: "DH",
		Au: "DSS",
		Enc: Encryption{
			Cipher: "AES",
			Bits:   128,
		},
		Mac:  "SHA1",
		Code: 50,
	},
	"DHE-DSS-AES128-SHA256": CipherSuite{
		IANAName:   "TLS_DHE_DSS_WITH_AES_128_CBC_SHA256",
		GnuTLSName: "TLS_DHE_DSS_AES_128_CBC_SHA256",
		NSSName:    "TLS_DHE_DSS_WITH_AES_128_CBC_SHA256",
		Protocol:   "TLSv1.2", ProtocolCode: 771,
		Kx: "DH",
		Au: "DSS",
		Enc: Encryption{
			Cipher: "AES",
			Bits:   128,
		},
		Mac:  "SHA256",
		Code: 64,
	},
	"DHE-DSS-AES256-GCM-SHA384": CipherSuite{
		IANAName:   "TLS_DHE_DSS_WITH_AES_256_GCM_SHA384",
		GnuTLSName: "TLS_DHE_DSS_AES_256_GCM_SHA384",
		NSSName:    "TLS_DHE_DSS_WITH_AES_256_GCM_SHA384",
		Protocol:   "TLSv1.2", ProtocolCode: 771,
		Kx: "DH",
		Au: "DSS",
		Enc: Encryption{
			Cipher: "AESGCM",
			Bits:   256,
		},
		Mac:  "AEAD",
		Code: 163,
	},
	"DHE-DSS-AES256-SHA": CipherSuite{
		IANAName:   "TLS_DHE_DSS_WITH_AES_256_CBC_SHA",
		GnuTLSName: "TLS_DHE_DSS_AES_256_CBC_SHA1",
		NSSName:    "TLS_DHE_DSS_WITH_AES_256_CBC_SHA",
		Protocol:   "SSLv3", ProtocolCode: 768,
		Kx: "DH",
		Au: "DSS",
		Enc: Encryption{
			Cipher: "AES",
			Bits:   256,
		},
		Mac:  "SHA1",
		Code: 56,
	},
	"DHE-DSS-AES256-SHA256": CipherSuite{
		IANAName:   "TLS_DHE_DSS_WITH_AES_256_CBC_SHA256",
		GnuTLSName: "TLS_DHE_DSS_AES_256_CBC_SHA256",
		NSSName:    "TLS_DHE_DSS_WITH_AES_256_CBC_SHA256",
		Protocol:   "TLSv1.2", ProtocolCode: 771,
		Kx: "DH",
		Au: "DSS",
		Enc: Encryption{
			Cipher: "AES",
			Bits:   256,
		},
		Mac:  "SHA256",
		Code: 106,
	},
	"DHE-DSS-CAMELLIA128-SHA": CipherSuite{
		IANAName:   "TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA",
		GnuTLSName: "TLS_DHE_DSS_CAMELLIA_128_CBC_SHA1",
		NSSName:    "TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA",
		Protocol:   "SSLv3", ProtocolCode: 768,
		Kx: "DH",
		Au: "DSS",
		Enc: Encryption{
			Cipher: "Camellia",
			Bits:   128,
		},
		Mac:  "SHA1",
		Code: 68,
	},
	"DHE-DSS-CAMELLIA128-SHA256": CipherSuite{
		IANAName:   "TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA256",
		GnuTLSName: "TLS_DHE_DSS_CAMELLIA_128_CBC_SHA256",
		NSSName:    "",
		Protocol:   "TLSv1.2", ProtocolCode: 771,
		Kx: "DH",
		Au: "DSS",
		Enc: Encryption{
			Cipher: "Camellia",
			Bits:   128,
		},
		Mac:  "SHA256",
		Code: 189,
	},
	"DHE-DSS-CAMELLIA256-SHA": CipherSuite{
		IANAName:   "TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA",
		GnuTLSName: "TLS_DHE_DSS_CAMELLIA_256_CBC_SHA1",
		NSSName:    "TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA",
		Protocol:   "SSLv3", ProtocolCode: 768,
		Kx: "DH",
		Au: "DSS",
		Enc: Encryption{
			Cipher: "Camellia",
			Bits:   256,
		},
		Mac:  "SHA1",
		Code: 135,
	},
	"DHE-DSS-CAMELLIA256-SHA256": CipherSuite{
		IANAName:   "TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA256",
		GnuTLSName: "TLS_DHE_DSS_CAMELLIA_256_CBC_SHA256",
		NSSName:    "",
		Protocol:   "TLSv1.2", ProtocolCode: 771,
		Kx: "DH",
		Au: "DSS",
		Enc: Encryption{
			Cipher: "Camellia",
			Bits:   256,
		},
		Mac:  "SHA256",
		Code: 195,
	},
	"DHE-DSS-RC4-SHA": CipherSuite{
		IANAName:   "",
		GnuTLSName: "",
		NSSName:    "",
		Protocol:   "SSLv3", ProtocolCode: 768,
		Kx: "DH",
		Au: "DSS",
		Enc: Encryption{
			Cipher: "RC4",
			Bits:   128,
		},
		Mac:  "SHA1",
		Code: 102,
	},
	"DHE-DSS-SEED-SHA": CipherSuite{
		IANAName:   "TLS_DHE_DSS_WITH_SEED_CBC_SHA",
		GnuTLSName: "",
		NSSName:    "",
		Protocol:   "SSLv3", ProtocolCode: 768,
		Kx: "DH",
		Au: "DSS",
		Enc: Encryption{
			Cipher: "SEED",
			Bits:   128,
		},
		Mac:  "SHA1",
		Code: 153,
	},
	"DHE-RSA-AES128-GCM-SHA256": CipherSuite{
		IANAName:   "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256",
		GnuTLSName: "TLS_DHE_RSA_AES_128_GCM_SHA256",
		NSSName:    "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256",
		Protocol:   "TLSv1.2", ProtocolCode: 771,
		Kx: "DH",
		Au: "RSA",
		Enc: Encryption{
			Cipher: "AESGCM",
			Bits:   128,
		},
		Mac:  "AEAD",
		Code: 158,
	},
	"DHE-RSA-AES128-SHA": CipherSuite{
		IANAName:   "TLS_DHE_RSA_WITH_AES_128_CBC_SHA",
		GnuTLSName: "TLS_DHE_RSA_AES_128_CBC_SHA1",
		NSSName:    "TLS_DHE_RSA_WITH_AES_128_CBC_SHA",
		Protocol:   "SSLv3", ProtocolCode: 768,
		Kx: "DH",
		Au: "RSA",
		Enc: Encryption{
			Cipher: "AES",
			Bits:   128,
		},
		Mac:  "SHA1",
		Code: 51,
	},
	"DHE-RSA-AES128-SHA256": CipherSuite{
		IANAName:   "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256",
		GnuTLSName: "TLS_DHE_RSA_AES_128_CBC_SHA256",
		NSSName:    "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256",
		Protocol:   "TLSv1.2", ProtocolCode: 771,
		Kx: "DH",
		Au: "RSA",
		Enc: Encryption{
			Cipher: "AES",
			Bits:   128,
		},
		Mac:  "SHA256",
		Code: 103,
	},
	"DHE-RSA-AES256-GCM-SHA384": CipherSuite{
		IANAName:   "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384",
		GnuTLSName: "TLS_DHE_RSA_AES_256_GCM_SHA384",
		NSSName:    "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384",
		Protocol:   "TLSv1.2", ProtocolCode: 771,
		Kx: "DH",
		Au: "RSA",
		Enc: Encryption{
			Cipher: "AESGCM",
			Bits:   256,
		},
		Mac:  "AEAD",
		Code: 159,
	},
	"DHE-RSA-AES256-SHA": CipherSuite{
		IANAName:   "TLS_DHE_RSA_WITH_AES_256_CBC_SHA",
		GnuTLSName: "TLS_DHE_RSA_AES_256_CBC_SHA1",
		NSSName:    "TLS_DHE_RSA_WITH_AES_256_CBC_SHA",
		Protocol:   "SSLv3", ProtocolCode: 768,
		Kx: "DH",
		Au: "RSA",
		Enc: Encryption{
			Cipher: "AES",
			Bits:   256,
		},
		Mac:  "SHA1",
		Code: 57,
	},
	"DHE-RSA-AES256-SHA256": CipherSuite{
		IANAName:   "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256",
		GnuTLSName: "TLS_DHE_RSA_AES_256_CBC_SHA256",
		NSSName:    "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256",
		Protocol:   "TLSv1.2", ProtocolCode: 771,
		Kx: "DH",
		Au: "RSA",
		Enc: Encryption{
			Cipher: "AES",
			Bits:   256,
		},
		Mac:  "SHA256",
		Code: 107,
	},
	"DHE-RSA-CAMELLIA128-SHA": CipherSuite{
		IANAName:   "TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA",
		GnuTLSName: "TLS_DHE_RSA_CAMELLIA_128_CBC_SHA1",
		NSSName:    "TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA",
		Protocol:   "SSLv3", ProtocolCode: 768,
		Kx: "DH",
		Au: "RSA",
		Enc: Encryption{
			Cipher: "Camellia",
			Bits:   128,
		},
		Mac:  "SHA1",
		Code: 69,
	},
	"DHE-RSA-CAMELLIA128-SHA256": CipherSuite{
		IANAName:   "TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256",
		GnuTLSName: "TLS_DHE_RSA_CAMELLIA_128_CBC_SHA256",
		NSSName:    "",
		Protocol:   "TLSv1.2", ProtocolCode: 771,
		Kx: "DH",
		Au: "RSA",
		Enc: Encryption{
			Cipher: "Camellia",
			Bits:   128,
		},
		Mac:  "SHA256",
		Code: 190,
	},
	"DHE-RSA-CAMELLIA256-SHA": CipherSuite{
		IANAName:   "TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA",
		GnuTLSName: "TLS_DHE_RSA_CAMELLIA_256_CBC_SHA1",
		NSSName:    "TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA",
		Protocol:   "SSLv3", ProtocolCode: 768,
		Kx: "DH",
		Au: "RSA",
		Enc: Encryption{
			Cipher: "Camellia",
			Bits:   256,
		},
		Mac:  "SHA1",
		Code: 136,
	},
	"DHE-RSA-CAMELLIA256-SHA256": CipherSuite{
		IANAName:   "TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256",
		GnuTLSName: "TLS_DHE_RSA_CAMELLIA_256_CBC_SHA256",
		NSSName:    "",
		Protocol:   "TLSv1.2", ProtocolCode: 771,
		Kx: "DH",
		Au: "RSA",
		Enc: Encryption{
			Cipher: "Camellia",
			Bits:   256,
		},
		Mac:  "SHA256",
		Code: 196,
	},
	"DHE-RSA-CHACHA20-POLY1305-OLD": CipherSuite{
		IANAName:   "",
		GnuTLSName: "",
		NSSName:    "",
		Protocol:   "TLSv1.2", ProtocolCode: 771,
		Kx: "DH",
		Au: "RSA",
		Enc: Encryption{
			Cipher: "ChaCha20",
			Bits:   256,
		},
		Mac:  "AEAD",
		Code: 52245,
	},
	"DHE-RSA-CHACHA20-POLY1305": CipherSuite{
		IANAName:   "",
		GnuTLSName: "TLS_DHE_RSA_CHACHA20_POLY1305",
		NSSName:    "TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256,",
		Protocol:   "TLSv1.2", ProtocolCode: 771,
		Kx: "DH",
		Au: "RSA",
		Enc: Encryption{
			Cipher: "ChaCha20",
			Bits:   256,
		},
		Mac:  "AEAD",
		Code: 52394,
	},
	"DHE-RSA-SEED-SHA": CipherSuite{
		IANAName:   "TLS_DHE_RSA_WITH_SEED_CBC_SHA",
		GnuTLSName: "",
		NSSName:    "",
		Protocol:   "SSLv3", ProtocolCode: 768,
		Kx: "DH",
		Au: "RSA",
		Enc: Encryption{
			Cipher: "SEED",
			Bits:   128,
		},
		Mac:  "SHA1",
		Code: 154,
	},
	"ECDH-ECDSA-AES128-GCM-SHA256": CipherSuite{
		IANAName:   "TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256",
		GnuTLSName: "",
		NSSName:    "TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256",
		Protocol:   "TLSv1.2", ProtocolCode: 771,
		Kx: "ECDH/ECDSA",
		Au: "ECDH",
		Enc: Encryption{
			Cipher: "AESGCM",
			Bits:   128,
		},
		Mac:  "AEAD",
		Code: 49197,
	},
	"ECDH-ECDSA-AES128-SHA": CipherSuite{
		IANAName:   "TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA",
		GnuTLSName: "",
		NSSName:    "TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA",
		Protocol:   "SSLv3", ProtocolCode: 768,
		Kx: "ECDH/ECDSA",
		Au: "ECDH",
		Enc: Encryption{
			Cipher: "AES",
			Bits:   128,
		},
		Mac:  "SHA1",
		Code: 49156,
	},
	"ECDH-ECDSA-AES128-SHA256": CipherSuite{
		IANAName:   "TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256",
		GnuTLSName: "",
		NSSName:    "",
		Protocol:   "TLSv1.2", ProtocolCode: 771,
		Kx: "ECDH/ECDSA",
		Au: "ECDH",
		Enc: Encryption{
			Cipher: "AES",
			Bits:   128,
		},
		Mac:  "SHA256",
		Code: 49189,
	},
	"ECDH-ECDSA-AES256-GCM-SHA384": CipherSuite{
		IANAName:   "TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384",
		GnuTLSName: "",
		NSSName:    "",
		Protocol:   "TLSv1.2", ProtocolCode: 771,
		Kx: "ECDH/ECDSA",
		Au: "ECDH",
		Enc: Encryption{
			Cipher: "AESGCM",
			Bits:   256,
		},
		Mac:  "AEAD",
		Code: 49198,
	},
	"ECDH-ECDSA-AES256-SHA": CipherSuite{
		IANAName:   "TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA",
		GnuTLSName: "",
		NSSName:    "TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA",
		Protocol:   "SSLv3", ProtocolCode: 768,
		Kx: "ECDH/ECDSA",
		Au: "ECDH",
		Enc: Encryption{
			Cipher: "AES",
			Bits:   256,
		},
		Mac:  "SHA1",
		Code: 49157,
	},
	"ECDH-ECDSA-AES256-SHA384": CipherSuite{
		IANAName:   "TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384",
		GnuTLSName: "",
		NSSName:    "",
		Protocol:   "TLSv1.2", ProtocolCode: 771,
		Kx: "ECDH/ECDSA",
		Au: "ECDH",
		Enc: Encryption{
			Cipher: "AES",
			Bits:   256,
		},
		Mac:  "SHA384",
		Code: 49190,
	},
	"ECDH-ECDSA-CAMELLIA128-SHA256": CipherSuite{
		IANAName:   "TLS_ECDH_ECDSA_WITH_CAMELLIA_128_CBC_SHA256",
		GnuTLSName: "",
		NSSName:    "",
		Protocol:   "TLSv1.2", ProtocolCode: 771,
		Kx: "ECDH/ECDSA",
		Au: "ECDH",
		Enc: Encryption{
			Cipher: "Camellia",
			Bits:   128,
		},
		Mac:  "SHA256",
		Code: 49268,
	},
	"ECDH-ECDSA-CAMELLIA256-SHA384": CipherSuite{
		IANAName:   "TLS_ECDH_ECDSA_WITH_CAMELLIA_256_CBC_SHA384",
		GnuTLSName: "",
		NSSName:    "",
		Protocol:   "TLSv1.2", ProtocolCode: 771,
		Kx: "ECDH/ECDSA",
		Au: "ECDH",
		Enc: Encryption{
			Cipher: "Camellia",
			Bits:   256,
		},
		Mac:  "SHA384",
		Code: 49269,
	},
	"ECDH-ECDSA-DES-CBC3-SHA": CipherSuite{
		IANAName:   "TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA",
		GnuTLSName: "",
		NSSName:    "TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA",
		Protocol:   "SSLv3", ProtocolCode: 768,
		Kx: "ECDH/ECDSA",
		Au: "ECDH",
		Enc: Encryption{
			Cipher: "3DES",
			Bits:   168,
		},
		Mac:  "SHA1",
		Code: 49155,
	},
	"ECDH-ECDSA-RC4-SHA": CipherSuite{
		IANAName:   "TLS_ECDH_ECDSA_WITH_RC4_128_SHA",
		GnuTLSName: "",
		NSSName:    "TLS_ECDH_ECDSA_WITH_RC4_128_SHA",
		Protocol:   "SSLv3", ProtocolCode: 768,
		Kx: "ECDH/ECDSA",
		Au: "ECDH",
		Enc: Encryption{
			Cipher: "RC4",
			Bits:   128,
		},
		Mac:  "SHA1",
		Code: 49154,
	},
	"ECDH-RSA-AES128-GCM-SHA256": CipherSuite{
		IANAName:   "TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256",
		GnuTLSName: "",
		NSSName:    "TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256",
		Protocol:   "TLSv1.2", ProtocolCode: 771,
		Kx: "ECDH/RSA",
		Au: "ECDH",
		Enc: Encryption{
			Cipher: "AESGCM",
			Bits:   128,
		},
		Mac:  "AEAD",
		Code: 49201,
	},
	"ECDH-RSA-AES128-SHA": CipherSuite{
		IANAName:   "TLS_ECDH_RSA_WITH_AES_128_CBC_SHA",
		GnuTLSName: "",
		NSSName:    "TLS_ECDH_RSA_WITH_AES_128_CBC_SHA",
		Protocol:   "SSLv3", ProtocolCode: 768,
		Kx: "ECDH/RSA",
		Au: "ECDH",
		Enc: Encryption{
			Cipher: "AES",
			Bits:   128,
		},
		Mac:  "SHA1",
		Code: 49166,
	},
	"ECDH-RSA-AES128-SHA256": CipherSuite{
		IANAName:   "TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256",
		GnuTLSName: "",
		NSSName:    "",
		Protocol:   "TLSv1.2", ProtocolCode: 771,
		Kx: "ECDH/RSA",
		Au: "ECDH",
		Enc: Encryption{
			Cipher: "AES",
			Bits:   128,
		},
		Mac:  "SHA256",
		Code: 49193,
	},
	"ECDH-RSA-AES256-GCM-SHA384": CipherSuite{
		IANAName:   "TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384",
		GnuTLSName: "",
		NSSName:    "",
		Protocol:   "TLSv1.2", ProtocolCode: 771,
		Kx: "ECDH/RSA",
		Au: "ECDH",
		Enc: Encryption{
			Cipher: "AESGCM",
			Bits:   256,
		},
		Mac:  "AEAD",
		Code: 49202,
	},
	"ECDH-RSA-AES256-SHA": CipherSuite{
		IANAName:   "TLS_ECDH_RSA_WITH_AES_256_CBC_SHA",
		GnuTLSName: "",
		NSSName:    "TLS_ECDH_RSA_WITH_AES_256_CBC_SHA",
		Protocol:   "SSLv3", ProtocolCode: 768,
		Kx: "ECDH/RSA",
		Au: "ECDH",
		Enc: Encryption{
			Cipher: "AES",
			Bits:   256,
		},
		Mac:  "SHA1",
		Code: 49167,
	},
	"ECDH-RSA-AES256-SHA384": CipherSuite{
		IANAName:   "TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384",
		GnuTLSName: "",
		NSSName:    "",
		Protocol:   "TLSv1.2", ProtocolCode: 771,
		Kx: "ECDH/RSA",
		Au: "ECDH",
		Enc: Encryption{
			Cipher: "AES",
			Bits:   256,
		},
		Mac:  "SHA384",
		Code: 49194,
	},
	"ECDH-RSA-CAMELLIA128-SHA256": CipherSuite{
		IANAName:   "TLS_ECDH_RSA_WITH_CAMELLIA_128_CBC_SHA256",
		GnuTLSName: "",
		NSSName:    "",
		Protocol:   "TLSv1.2", ProtocolCode: 771,
		Kx: "ECDH/RSA",
		Au: "ECDH",
		Enc: Encryption{
			Cipher: "Camellia",
			Bits:   128,
		},
		Mac:  "SHA256",
		Code: 49272,
	},
	"ECDH-RSA-CAMELLIA256-SHA384": CipherSuite{
		IANAName:   "TLS_ECDH_RSA_WITH_CAMELLIA_256_CBC_SHA384",
		GnuTLSName: "",
		NSSName:    "",
		Protocol:   "TLSv1.2", ProtocolCode: 771,
		Kx: "ECDH/RSA",
		Au: "ECDH",
		Enc: Encryption{
			Cipher: "Camellia",
			Bits:   256,
		},
		Mac:  "SHA384",
		Code: 49273,
	},
	"ECDH-RSA-DES-CBC3-SHA": CipherSuite{
		IANAName:   "TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA",
		GnuTLSName: "",
		NSSName:    "TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA",
		Protocol:   "SSLv3", ProtocolCode: 768,
		Kx: "ECDH/RSA",
		Au: "ECDH",
		Enc: Encryption{
			Cipher: "3DES",
			Bits:   168,
		},
		Mac:  "SHA1",
		Code: 49165,
	},
	"ECDH-RSA-RC4-SHA": CipherSuite{
		IANAName:   "TLS_ECDH_RSA_WITH_RC4_128_SHA",
		GnuTLSName: "",
		NSSName:    "TLS_ECDH_RSA_WITH_RC4_128_SHA",
		Protocol:   "SSLv3", ProtocolCode: 768,
		Kx: "ECDH/RSA",
		Au: "ECDH",
		Enc: Encryption{
			Cipher: "RC4",
			Bits:   128,
		},
		Mac:  "SHA1",
		Code: 49164,
	},
	"ECDHE-ECDSA-AES128-GCM-SHA256": CipherSuite{
		IANAName:   "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
		GnuTLSName: "TLS_ECDHE_ECDSA_AES_128_GCM_SHA256",
		NSSName:    "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
		Protocol:   "TLSv1.2", ProtocolCode: 771,
		Kx: "ECDH",
		Au: "ECDSA",
		Enc: Encryption{
			Cipher: "AESGCM",
			Bits:   128,
		},
		Mac:  "AEAD",
		Code: 49195,
	},
	"ECDHE-ECDSA-AES128-SHA": CipherSuite{
		IANAName:   "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
		GnuTLSName: "TLS_ECDHE_ECDSA_AES_128_CBC_SHA1",
		NSSName:    "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
		Protocol:   "SSLv3", ProtocolCode: 768,
		Kx: "ECDH",
		Au: "ECDSA",
		Enc: Encryption{
			Cipher: "AES",
			Bits:   128,
		},
		Mac:  "SHA1",
		Code: 49161,
	},
	"ECDHE-ECDSA-AES128-SHA256": CipherSuite{
		IANAName:   "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256",
		GnuTLSName: "TLS_ECDHE_ECDSA_AES_128_CBC_SHA256",
		NSSName:    "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256",
		Protocol:   "TLSv1.2", ProtocolCode: 771,
		Kx: "ECDH",
		Au: "ECDSA",
		Enc: Encryption{
			Cipher: "AES",
			Bits:   128,
		},
		Mac:  "SHA256",
		Code: 49187,
	},
	"ECDHE-ECDSA-AES256-GCM-SHA384": CipherSuite{
		IANAName:   "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
		GnuTLSName: "TLS_ECDHE_ECDSA_AES_256_GCM_SHA384",
		NSSName:    "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
		Protocol:   "TLSv1.2", ProtocolCode: 771,
		Kx: "ECDH",
		Au: "ECDSA",
		Enc: Encryption{
			Cipher: "AESGCM",
			Bits:   256,
		},
		Mac:  "AEAD",
		Code: 49196,
	},
	"ECDHE-ECDSA-AES256-SHA": CipherSuite{
		IANAName:   "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
		GnuTLSName: "TLS_ECDHE_ECDSA_AES_256_CBC_SHA1",
		NSSName:    "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
		Protocol:   "SSLv3", ProtocolCode: 768,
		Kx: "ECDH",
		Au: "ECDSA",
		Enc: Encryption{
			Cipher: "AES",
			Bits:   256,
		},
		Mac:  "SHA1",
		Code: 49162,
	},
	"ECDHE-ECDSA-AES256-SHA384": CipherSuite{
		IANAName:   "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384",
		GnuTLSName: "TLS_ECDHE_ECDSA_AES_256_CBC_SHA384",
		NSSName:    "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384",
		Protocol:   "TLSv1.2", ProtocolCode: 771,
		Kx: "ECDH",
		Au: "ECDSA",
		Enc: Encryption{
			Cipher: "AES",
			Bits:   256,
		},
		Mac:  "SHA384",
		Code: 49188,
	},
	"ECDHE-ECDSA-CAMELLIA128-SHA256": CipherSuite{
		IANAName:   "TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256",
		GnuTLSName: "TLS_ECDHE_ECDSA_CAMELLIA_128_CBC_SHA256",
		NSSName:    "",
		Protocol:   "TLSv1.2", ProtocolCode: 771,
		Kx: "ECDH",
		Au: "ECDSA",
		Enc: Encryption{
			Cipher: "Camellia",
			Bits:   128,
		},
		Mac:  "SHA256",
		Code: 49266,
	},
	"ECDHE-ECDSA-CAMELLIA256-SHA384": CipherSuite{
		IANAName:   "TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384",
		GnuTLSName: "TLS_ECDHE_ECDSA_CAMELLIA_256_CBC_SHA384",
		NSSName:    "",
		Protocol:   "TLSv1.2", ProtocolCode: 771,
		Kx: "ECDH",
		Au: "ECDSA",
		Enc: Encryption{
			Cipher: "Camellia",
			Bits:   256,
		},
		Mac:  "SHA384",
		Code: 49267,
	},
	"ECDHE-ECDSA-CHACHA20-POLY1305-OLD": CipherSuite{
		IANAName:   "",
		GnuTLSName: "",
		NSSName:    "",
		Protocol:   "TLSv1.2", ProtocolCode: 771,
		Kx: "ECDH",
		Au: "ECDSA",
		Enc: Encryption{
			Cipher: "ChaCha20",
			Bits:   256,
		},
		Mac:  "AEAD",
		Code: 52244,
	},
	"ECDHE-ECDSA-CHACHA20-POLY1305": CipherSuite{
		IANAName:   "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305",
		GnuTLSName: "TLS_ECDHE_ECDSA_CHACHA20_POLY1305",
		NSSName:    "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
		Protocol:   "TLSv1.2", ProtocolCode: 771,
		Kx: "ECDH",
		Au: "ECDSA",
		Enc: Encryption{
			Cipher: "ChaCha20",
			Bits:   256,
		},
		Mac:  "AEAD",
		Code: 52393,
	},
	"ECDHE-ECDSA-DES-CBC3-SHA": CipherSuite{
		IANAName:   "TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA",
		GnuTLSName: "TLS_ECDHE_ECDSA_3DES_EDE_CBC_SHA1",
		NSSName:    "TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA",
		Protocol:   "SSLv3", ProtocolCode: 768,
		Kx: "ECDH",
		Au: "ECDSA",
		Enc: Encryption{
			Cipher: "3DES",
			Bits:   168,
		},
		Mac:  "SHA1",
		Code: 49160,
	},
	"ECDHE-ECDSA-RC4-SHA": CipherSuite{
		IANAName:   "TLS_ECDHE_ECDSA_WITH_RC4_128_SHA",
		GnuTLSName: "TLS_ECDHE_ECDSA_ARCFOUR_128_SHA1",
		NSSName:    "TLS_ECDHE_ECDSA_WITH_RC4_128_SHA",
		Protocol:   "SSLv3", ProtocolCode: 768,
		Kx: "ECDH",
		Au: "ECDSA",
		Enc: Encryption{
			Cipher: "RC4",
			Bits:   128,
		},
		Mac:  "SHA1",
		Code: 49159,
	},
	"ECDHE-RSA-AES128-GCM-SHA256": CipherSuite{
		IANAName:   "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
		GnuTLSName: "TLS_ECDHE_RSA_AES_128_GCM_SHA256",
		NSSName:    "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
		Protocol:   "TLSv1.2", ProtocolCode: 771,
		Kx: "ECDH",
		Au: "RSA",
		Enc: Encryption{
			Cipher: "AESGCM",
			Bits:   128,
		},
		Mac:  "AEAD",
		Code: 49199,
	},
	"ECDHE-RSA-AES128-SHA": CipherSuite{
		IANAName:   "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
		GnuTLSName: "TLS_ECDHE_RSA_AES_128_CBC_SHA1",
		NSSName:    "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
		Protocol:   "SSLv3", ProtocolCode: 768,
		Kx: "ECDH",
		Au: "RSA",
		Enc: Encryption{
			Cipher: "AES",
			Bits:   128,
		},
		Mac:  "SHA1",
		Code: 49171,
	},
	"ECDHE-RSA-AES128-SHA256": CipherSuite{
		IANAName:   "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
		GnuTLSName: "TLS_ECDHE_RSA_AES_128_CBC_SHA256",
		NSSName:    "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
		Protocol:   "TLSv1.2", ProtocolCode: 771,
		Kx: "ECDH",
		Au: "RSA",
		Enc: Encryption{
			Cipher: "AES",
			Bits:   128,
		},
		Mac:  "SHA256",
		Code: 49191,
	},
	"ECDHE-RSA-AES256-GCM-SHA384": CipherSuite{
		IANAName:   "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
		GnuTLSName: "TLS_ECDHE_RSA_AES_256_GCM_SHA384",
		NSSName:    "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
		Protocol:   "TLSv1.2", ProtocolCode: 771,
		Kx: "ECDH",
		Au: "RSA",
		Enc: Encryption{
			Cipher: "AESGCM",
			Bits:   256,
		},
		Mac:  "AEAD",
		Code: 49200,
	},
	"ECDHE-RSA-AES256-SHA": CipherSuite{
		IANAName:   "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
		GnuTLSName: "TLS_ECDHE_RSA_AES_256_CBC_SHA1",
		NSSName:    "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
		Protocol:   "SSLv3", ProtocolCode: 768,
		Kx: "ECDH",
		Au: "RSA",
		Enc: Encryption{
			Cipher: "AES",
			Bits:   256,
		},
		Mac:  "SHA1",
		Code: 49172,
	},
	"ECDHE-RSA-AES256-SHA384": CipherSuite{
		IANAName:   "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384",
		GnuTLSName: "TLS_ECDHE_RSA_AES_256_CBC_SHA384",
		NSSName:    "TLS_ECDHE_RSA_WITH_A
"""




```