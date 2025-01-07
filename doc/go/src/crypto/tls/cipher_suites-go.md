Response:
Let's break down the thought process to answer the request about `cipher_suites.go`.

1. **Understanding the Goal:** The request asks for the functionality of the given Go code, explanations of Go features used, code examples with assumptions, handling of command-line arguments (if any), and common mistakes. The target audience is someone who wants to understand this specific Go file within the context of TLS.

2. **Initial Code Scan and High-Level Purpose:**  The first step is to quickly read through the code, identifying key data structures and function names. I see `CipherSuite`, `cipherSuite`, `cipherSuiteTLS13`, various constants prefixed with `TLS_`, functions like `CipherSuites`, `InsecureCipherSuites`, `CipherSuiteName`, and a few `selectCipherSuite` variants. This immediately suggests the file is about defining and managing TLS cipher suites.

3. **Dissecting Key Data Structures:**

   * **`CipherSuite`:** This struct has `ID`, `Name`, `SupportedVersions`, and `Insecure`. This seems to be a user-facing representation of a cipher suite, containing its official name, ID, the TLS versions it's compatible with, and whether it's considered insecure.

   * **`cipherSuite`:** This struct appears to be an internal representation for TLS 1.0-1.2. It includes more implementation details like key lengths, MAC lengths, initialization vector lengths, key agreement functions (`ka`), cipher and MAC functions, and an AEAD function. The `flags` field also hints at categorizing cipher suites based on properties like ECDHE, ECDSA, and TLS version support.

   * **`cipherSuiteTLS13`:**  This is a simplified internal representation specifically for TLS 1.3, focusing on the AEAD algorithm and the hash algorithm used with HKDF.

4. **Analyzing Key Functions:**

   * **`CipherSuites()` and `InsecureCipherSuites()`:** These functions clearly return lists of `CipherSuite` objects, separating secure and insecure ones. This suggests the file maintains a curated list of supported cipher suites.

   * **`CipherSuiteName(id uint16)`:** This function translates a cipher suite ID to its name. The looping through both secure and insecure lists indicates it tries to find the name regardless of security status.

   * **`selectCipherSuite(...)` and `mutualCipherSuite(...)`:** These functions seem to be involved in negotiating cipher suites, selecting a compatible one from a list of supported options.

   * **`cipherRC4`, `cipherAES`, `macSHA1`, `aeadAESGCM`, etc.:** These are implementation details for specific cryptographic algorithms used within the cipher suites.

5. **Identifying Go Language Features:**

   * **Structs:** `CipherSuite`, `cipherSuite`, `cipherSuiteTLS13` are fundamental Go structs for organizing data.
   * **Slices:** The `SupportedVersions` field in `CipherSuite` and the return types of `CipherSuites` and `InsecureCipherSuites` use slices.
   * **Functions as First-Class Citizens:** The `ka`, `cipher`, `mac`, and `aead` fields in `cipherSuite` store function pointers, demonstrating this feature.
   * **Constants:**  The numerous `TLS_...` constants define the cipher suite IDs.
   * **Maps:** The `disabledCipherSuites`, `rsaKexCiphers`, `tdesCiphers`, and `aesgcmCiphers` use maps to efficiently check for the presence of specific cipher suites.
   * **Anonymous Functions:**  Used within functions like `macSHA1` to create hash functions.
   * **Interfaces:** The `aead` interface defines a contract for AEAD implementations.
   * **`go:linkname`:** This special directive is used to access unexported variables from other packages, indicating a workaround for tight coupling or specific needs by external libraries.
   * **Init Functions (Implicit):** Although not explicitly shown in this snippet, the package likely has `init()` functions to perform setup tasks.

6. **Inferring Functionality (Putting It All Together):** Based on the structures and functions, I can infer the file's main responsibilities:

   * **Defining Cipher Suites:** It defines the properties (ID, name, supported versions, security status) of various TLS cipher suites.
   * **Providing Lists of Cipher Suites:** It offers functions to get lists of both secure and insecure cipher suites.
   * **Mapping IDs to Names:** It allows retrieving the standard name for a given cipher suite ID.
   * **Internal Representation:** It maintains internal structures (`cipherSuite`, `cipherSuiteTLS13`) that hold the cryptographic details of each cipher suite.
   * **Cipher Suite Selection:** It provides functions for selecting a suitable cipher suite during TLS negotiation.
   * **Implementing Cryptographic Algorithms:** It includes implementations or wrappers for the cryptographic algorithms used in the cipher suites.
   * **Managing Security Policies:** It categorizes cipher suites as secure or insecure and provides lists accordingly.

7. **Crafting Code Examples:**  To illustrate the functionality, I'll create examples for:

   * Getting the list of secure cipher suites.
   * Getting the name of a cipher suite.
   * Checking if a cipher suite is insecure.
   * Demonstrating the `selectCipherSuite` function (requiring assumptions about the input).

8. **Addressing Command-Line Arguments:** A careful review of the code reveals no direct handling of command-line arguments within this specific file. The configuration and selection of cipher suites are typically done programmatically through the `tls.Config` struct.

9. **Identifying Common Mistakes:**  The most obvious mistake is using insecure cipher suites. I'll provide an example of how someone might inadvertently enable an insecure cipher suite. Another potential mistake is misunderstanding the preference order of cipher suites.

10. **Structuring the Answer:**  Finally, I'll organize the gathered information into a clear and structured answer, using headings and code blocks to improve readability. I'll address each point of the original request systematically.

**Self-Correction/Refinement during the process:**

* **Initial thought:** Maybe the preference order directly dictates which cipher suite is used. **Correction:** The preference order influences selection, but the client and server must both support a cipher suite for it to be chosen.
* **Initial thought:**  Focus heavily on the cryptographic algorithm implementations. **Correction:** While important, the file's primary role is managing and defining the cipher suites, not necessarily implementing all the low-level crypto (some are imported).
* **Initial thought:** Assume the user understands TLS concepts. **Correction:** While some familiarity is expected, providing context about cipher suites and TLS negotiation will be helpful.

By following this thought process, combining code analysis with understanding of the TLS protocol, and iteratively refining my understanding, I can generate a comprehensive and accurate answer to the user's request.
这段代码是 Go 语言 `crypto/tls` 包中 `cipher_suites.go` 文件的一部分，它主要负责定义和管理 TLS/SSL 协议中使用的密码套件 (Cipher Suites)。

**它的主要功能包括：**

1. **定义 `CipherSuite` 结构体:**  该结构体用于表示一个 TLS 密码套件，包含了它的 ID、名称、支持的 TLS 版本以及是否被认为是不安全的。这是密码套件的外部抽象表示。

   ```go
   type CipherSuite struct {
       ID   uint16
       Name string
       SupportedVersions []uint16
       Insecure bool
   }
   ```

2. **提供安全和不安全密码套件的列表:**
   - `CipherSuites()` 函数返回当前包实现的安全密码套件列表。这些是推荐使用的密码套件。
   - `InsecureCipherSuites()` 函数返回当前包实现但已知存在安全问题的密码套件列表。应用程序通常应该避免使用这些套件。

3. **根据 ID 获取密码套件名称:**
   - `CipherSuiteName(id uint16)` 函数接收一个密码套件的 ID，并返回其标准的字符串名称（例如 "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"）。如果该 ID 对应的密码套件未实现，则返回该 ID 的十六进制表示。

4. **定义内部使用的密码套件结构体 (`cipherSuite` 和 `cipherSuiteTLS13`):**
   - `cipherSuite` 用于表示 TLS 1.0 到 1.2 的密码套件，包含了更底层的加密算法细节，如密钥长度、MAC 长度、初始化向量长度、密钥交换算法、加密算法、MAC 算法和 AEAD 算法等。
   - `cipherSuiteTLS13` 用于表示 TLS 1.3 的密码套件，只定义了 AEAD 算法和用于 HKDF 的哈希算法。

5. **存储已实现的密码套件列表:**
   - `cipherSuites` 变量是一个 `cipherSuite` 结构体切片，包含了 TLS 1.0 到 1.2 支持的密码套件的详细信息。
   - `cipherSuitesTLS13` 变量是一个 `cipherSuiteTLS13` 结构体切片，包含了 TLS 1.3 支持的密码套件的详细信息。

6. **提供选择密码套件的函数:**
   - `selectCipherSuite` 函数用于从客户端提供的密码套件列表和服务器支持的密码套件列表中选择一个共同支持的密码套件（针对 TLS 1.0-1.2）。
   - `mutualCipherSuite` 函数用于检查给定的密码套件 ID 是否在提供的支持列表中（针对 TLS 1.0-1.2）。
   - `mutualCipherSuiteTLS13` 和 `cipherSuiteTLS13ByID` 函数提供了类似的功能，但专门针对 TLS 1.3 的密码套件。

7. **定义密码套件的偏好顺序:**
   - `cipherSuitesPreferenceOrder` 和 `cipherSuitesPreferenceOrderNoAES` 变量定义了服务器选择（或客户端声明）TLS 1.0 到 1.2 密码套件的偏好顺序。这个顺序考虑了安全性、性能和硬件支持等因素。

8. **维护禁用密码套件的列表:**
   - `disabledCipherSuites` 变量是一个映射，包含了默认情况下被禁用的密码套件 ID。

9. **维护基于 RSA 密钥交换和 3DES 加密的密码套件列表:**
   - `rsaKexCiphers` 和 `tdesCiphers` 变量分别包含了使用 RSA 密钥交换和 3DES 加密的密码套件，这些套件在默认情况下也会被禁用，除非设置了特定的 GODEBUG 环境变量。

10. **检测 AES-GCM 硬件加速:**
    - 代码中包含检测 CPU 是否支持 AES-GCM 硬件加速的逻辑 (`hasGCMAsmAMD64`, `hasGCMAsmARM64` 等)，并据此影响密码套件的选择偏好。

11. **实现具体的加密和 MAC 算法:**
    - 代码中定义了 `cipherRC4`, `cipher3DES`, `cipherAES` 等函数，用于创建不同的对称加密算法的实例。
    - `macSHA1`, `macSHA256` 函数用于创建基于 SHA-1 和 SHA-256 的 MAC 算法的实例。

12. **实现 AEAD (Authenticated Encryption with Associated Data) 算法:**
    - 定义了 `aead` 接口以及 `prefixNonceAEAD`, `xorNonceAEAD` 等结构体来实现 AEAD 算法，例如 `aeadAESGCM` 和 `aeadChaCha20Poly1305`。

13. **常量定义:** 定义了大量的常量，以 `TLS_` 开头，表示各种不同的密码套件 ID。

**推理 Go 语言功能的实现：**

这段代码体现了 Go 语言的一些核心特性：

* **结构体 (Structs):**  `CipherSuite`, `cipherSuite`, `cipherSuiteTLS13` 是结构体的典型应用，用于组织和表示数据。
* **切片 (Slices):** `supportedUpToTLS12`, `cipherSuites`, `cipherSuitesTLS13`, `cipherSuitesPreferenceOrder` 等都是切片的例子，用于存储和操作同类型的数据集合。
* **函数作为一等公民 (First-class functions):** `cipherSuite` 结构体中的 `ka`, `cipher`, `mac`, `aead` 字段存储的是函数，这允许在运行时选择不同的加密算法。
* **常量 (Constants):**  大量的 `TLS_` 开头的常量定义了密码套件的 ID，增强了代码的可读性和可维护性。
* **映射 (Maps):** `disabledCipherSuites`, `rsaKexCiphers`, `tdesCiphers` 等使用了映射来存储需要快速查找的数据。
* **接口 (Interfaces):** `aead` 接口定义了 AEAD 算法需要实现的方法，实现了多态。
* **`go:linkname` 指令:**  `//go:linkname cipherSuitesTLS13` 和 `//go:linkname aeadAESGCMTLS13`  是特殊的编译器指令，用于链接到内部的未导出变量，这通常用于一些特殊的优化或与其他包的紧密集成。

**Go 代码示例：**

假设我们想获取所有安全密码套件的名称：

```go
package main

import (
	"crypto/tls"
	"fmt"
)

func main() {
	suites := tls.CipherSuites()
	fmt.Println("安全密码套件:")
	for _, suite := range suites {
		fmt.Printf("ID: 0x%04X, Name: %s, Supported Versions: %v\n", suite.ID, suite.Name, suite.SupportedVersions)
	}
}

// 假设的输出（部分）：
// 安全密码套件:
// ID: 0x1301, Name: TLS_AES_128_GCM_SHA256, Supported Versions: [772]
// ID: 0x1302, Name: TLS_AES_256_GCM_SHA384, Supported Versions: [772]
// ID: 0x1303, Name: TLS_CHACHA20_POLY1305_SHA256, Supported Versions: [772]
// ID: 0xc009, Name: TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA, Supported Versions: [769 770 771]
// ...
```

假设我们想根据 ID 获取密码套件的名称：

```go
package main

import (
	"crypto/tls"
	"fmt"
)

func main() {
	id := uint16(0xc02f) // TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
	name := tls.CipherSuiteName(id)
	fmt.Printf("密码套件 ID 0x%04X 的名称是: %s\n", id, name)

	insecureID := uint16(0x0005) // TLS_RSA_WITH_RC4_128_SHA
	insecureName := tls.CipherSuiteName(insecureID)
	fmt.Printf("密码套件 ID 0x%04X 的名称是: %s\n", insecureID, insecureName)

	unknownID := uint16(0xFFFF)
	unknownName := tls.CipherSuiteName(unknownID)
	fmt.Printf("密码套件 ID 0x%04X 的名称是: %s\n", unknownID, unknownName)
}

// 假设的输出：
// 密码套件 ID 0xc02f 的名称是: TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
// 密码套件 ID 0x0005 的名称是: TLS_RSA_WITH_RC4_128_SHA
// 密码套件 ID 0xffff 的名称是: 0xFFFF
```

**命令行参数的具体处理：**

这段代码本身并没有直接处理命令行参数。TLS 库的配置通常是通过 `tls.Config` 结构体来完成的，例如，可以通过 `Config.CipherSuites` 字段来指定允许使用的密码套件。

例如，在创建一个 TLS 服务器时，你可以这样配置允许的密码套件：

```go
package main

import (
	"crypto/tls"
	"fmt"
	"log"
	"net/http"
)

func main() {
	config := &tls.Config{
		CipherSuites: []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_AES_256_GCM_SHA384,
		},
		// ... 其他配置
	}

	server := &http.Server{
		Addr:    ":https",
		Handler: http.HandlerFunc(handler),
		TLSConfig: config,
	}

	fmt.Println("启动 HTTPS 服务器...")
	err := server.ListenAndServeTLS("server.crt", "server.key")
	if err != nil {
		log.Fatal("ListenAndServeTLS error: ", err)
	}
}

func handler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "HTTPS 连接成功！")
}
```

在这个例子中，`config.CipherSuites` 明确指定了服务器允许使用的密码套件。这些 ID 对应于 `cipher_suites.go` 中定义的常量。

**使用者易犯错的点：**

1. **使用不安全的密码套件：**  开发者可能会无意中配置或允许使用 `InsecureCipherSuites()` 返回的密码套件，这会降低连接的安全性。例如，仍然允许使用 `TLS_RSA_WITH_RC4_128_SHA` 这样的 RC4 加密套件。

   ```go
   config := &tls.Config{
       CipherSuites: []uint16{
           tls.TLS_RSA_WITH_RC4_128_SHA, // 错误：使用了不安全的 RC4 密码套件
           tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
       },
   }
   ```

2. **不理解密码套件的偏好顺序：** 在服务端，如果 `Config.CipherSuites` 未设置，Go 会使用默认的偏好顺序选择密码套件。开发者可能没有意识到这个顺序，或者误以为客户端的偏好会完全主导选择。

3. **错误地配置 `MinVersion` 和 `MaxVersion`:**  密码套件的支持版本与 TLS 协议版本相关。如果配置了不匹配的 `MinVersion` 或 `MaxVersion`，可能会导致无法建立连接。例如，一个只支持 TLS 1.3 的密码套件不能用于 TLS 1.2 的连接。

4. **忽略硬件加速的优势：**  现代 CPU 通常对 AES-GCM 等算法有硬件加速。如果程序运行在支持硬件加速的平台上，但配置的密码套件没有利用这些加速，可能会影响性能。

5. **依赖默认设置而不进行显式配置：** 虽然 Go 的 TLS 库提供了合理的默认设置，但在安全敏感的应用中，应该根据具体需求显式地配置允许的密码套件，而不是完全依赖默认行为。

总而言之，`cipher_suites.go` 文件是 Go 语言 `crypto/tls` 包的核心组成部分，它定义了 TLS 密码套件的结构、列表、选择逻辑以及相关的加密算法实现，为构建安全的 TLS 连接提供了基础。理解这个文件的内容对于正确配置和使用 Go 的 TLS 功能至关重要。

Prompt: 
```
这是路径为go/src/crypto/tls/cipher_suites.go的go语言实现的一部分， 请列举一下它的功能, 　
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
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/hmac"
	"crypto/internal/boring"
	fipsaes "crypto/internal/fips140/aes"
	"crypto/internal/fips140/aes/gcm"
	"crypto/rc4"
	"crypto/sha1"
	"crypto/sha256"
	"fmt"
	"hash"
	"internal/cpu"
	"runtime"
	_ "unsafe" // for linkname

	"golang.org/x/crypto/chacha20poly1305"
)

// CipherSuite is a TLS cipher suite. Note that most functions in this package
// accept and expose cipher suite IDs instead of this type.
type CipherSuite struct {
	ID   uint16
	Name string

	// Supported versions is the list of TLS protocol versions that can
	// negotiate this cipher suite.
	SupportedVersions []uint16

	// Insecure is true if the cipher suite has known security issues
	// due to its primitives, design, or implementation.
	Insecure bool
}

var (
	supportedUpToTLS12 = []uint16{VersionTLS10, VersionTLS11, VersionTLS12}
	supportedOnlyTLS12 = []uint16{VersionTLS12}
	supportedOnlyTLS13 = []uint16{VersionTLS13}
)

// CipherSuites returns a list of cipher suites currently implemented by this
// package, excluding those with security issues, which are returned by
// [InsecureCipherSuites].
//
// The list is sorted by ID. Note that the default cipher suites selected by
// this package might depend on logic that can't be captured by a static list,
// and might not match those returned by this function.
func CipherSuites() []*CipherSuite {
	return []*CipherSuite{
		{TLS_AES_128_GCM_SHA256, "TLS_AES_128_GCM_SHA256", supportedOnlyTLS13, false},
		{TLS_AES_256_GCM_SHA384, "TLS_AES_256_GCM_SHA384", supportedOnlyTLS13, false},
		{TLS_CHACHA20_POLY1305_SHA256, "TLS_CHACHA20_POLY1305_SHA256", supportedOnlyTLS13, false},

		{TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA, "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA", supportedUpToTLS12, false},
		{TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA, "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA", supportedUpToTLS12, false},
		{TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA, "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA", supportedUpToTLS12, false},
		{TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA, "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA", supportedUpToTLS12, false},
		{TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256", supportedOnlyTLS12, false},
		{TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384, "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384", supportedOnlyTLS12, false},
		{TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", supportedOnlyTLS12, false},
		{TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384, "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", supportedOnlyTLS12, false},
		{TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256, "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256", supportedOnlyTLS12, false},
		{TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256, "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256", supportedOnlyTLS12, false},
	}
}

// InsecureCipherSuites returns a list of cipher suites currently implemented by
// this package and which have security issues.
//
// Most applications should not use the cipher suites in this list, and should
// only use those returned by [CipherSuites].
func InsecureCipherSuites() []*CipherSuite {
	// This list includes RC4, CBC_SHA256, and 3DES cipher suites. See
	// cipherSuitesPreferenceOrder for details.
	return []*CipherSuite{
		{TLS_RSA_WITH_RC4_128_SHA, "TLS_RSA_WITH_RC4_128_SHA", supportedUpToTLS12, true},
		{TLS_RSA_WITH_3DES_EDE_CBC_SHA, "TLS_RSA_WITH_3DES_EDE_CBC_SHA", supportedUpToTLS12, true},
		{TLS_RSA_WITH_AES_128_CBC_SHA, "TLS_RSA_WITH_AES_128_CBC_SHA", supportedUpToTLS12, true},
		{TLS_RSA_WITH_AES_256_CBC_SHA, "TLS_RSA_WITH_AES_256_CBC_SHA", supportedUpToTLS12, true},
		{TLS_RSA_WITH_AES_128_CBC_SHA256, "TLS_RSA_WITH_AES_128_CBC_SHA256", supportedOnlyTLS12, true},
		{TLS_RSA_WITH_AES_128_GCM_SHA256, "TLS_RSA_WITH_AES_128_GCM_SHA256", supportedOnlyTLS12, true},
		{TLS_RSA_WITH_AES_256_GCM_SHA384, "TLS_RSA_WITH_AES_256_GCM_SHA384", supportedOnlyTLS12, true},
		{TLS_ECDHE_ECDSA_WITH_RC4_128_SHA, "TLS_ECDHE_ECDSA_WITH_RC4_128_SHA", supportedUpToTLS12, true},
		{TLS_ECDHE_RSA_WITH_RC4_128_SHA, "TLS_ECDHE_RSA_WITH_RC4_128_SHA", supportedUpToTLS12, true},
		{TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA, "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA", supportedUpToTLS12, true},
		{TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256, "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256", supportedOnlyTLS12, true},
		{TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256, "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256", supportedOnlyTLS12, true},
	}
}

// CipherSuiteName returns the standard name for the passed cipher suite ID
// (e.g. "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"), or a fallback representation
// of the ID value if the cipher suite is not implemented by this package.
func CipherSuiteName(id uint16) string {
	for _, c := range CipherSuites() {
		if c.ID == id {
			return c.Name
		}
	}
	for _, c := range InsecureCipherSuites() {
		if c.ID == id {
			return c.Name
		}
	}
	return fmt.Sprintf("0x%04X", id)
}

const (
	// suiteECDHE indicates that the cipher suite involves elliptic curve
	// Diffie-Hellman. This means that it should only be selected when the
	// client indicates that it supports ECC with a curve and point format
	// that we're happy with.
	suiteECDHE = 1 << iota
	// suiteECSign indicates that the cipher suite involves an ECDSA or
	// EdDSA signature and therefore may only be selected when the server's
	// certificate is ECDSA or EdDSA. If this is not set then the cipher suite
	// is RSA based.
	suiteECSign
	// suiteTLS12 indicates that the cipher suite should only be advertised
	// and accepted when using TLS 1.2.
	suiteTLS12
	// suiteSHA384 indicates that the cipher suite uses SHA384 as the
	// handshake hash.
	suiteSHA384
)

// A cipherSuite is a TLS 1.0–1.2 cipher suite, and defines the key exchange
// mechanism, as well as the cipher+MAC pair or the AEAD.
type cipherSuite struct {
	id uint16
	// the lengths, in bytes, of the key material needed for each component.
	keyLen int
	macLen int
	ivLen  int
	ka     func(version uint16) keyAgreement
	// flags is a bitmask of the suite* values, above.
	flags  int
	cipher func(key, iv []byte, isRead bool) any
	mac    func(key []byte) hash.Hash
	aead   func(key, fixedNonce []byte) aead
}

var cipherSuites = []*cipherSuite{ // TODO: replace with a map, since the order doesn't matter.
	{TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305, 32, 0, 12, ecdheRSAKA, suiteECDHE | suiteTLS12, nil, nil, aeadChaCha20Poly1305},
	{TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305, 32, 0, 12, ecdheECDSAKA, suiteECDHE | suiteECSign | suiteTLS12, nil, nil, aeadChaCha20Poly1305},
	{TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, 16, 0, 4, ecdheRSAKA, suiteECDHE | suiteTLS12, nil, nil, aeadAESGCM},
	{TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, 16, 0, 4, ecdheECDSAKA, suiteECDHE | suiteECSign | suiteTLS12, nil, nil, aeadAESGCM},
	{TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384, 32, 0, 4, ecdheRSAKA, suiteECDHE | suiteTLS12 | suiteSHA384, nil, nil, aeadAESGCM},
	{TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384, 32, 0, 4, ecdheECDSAKA, suiteECDHE | suiteECSign | suiteTLS12 | suiteSHA384, nil, nil, aeadAESGCM},
	{TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256, 16, 32, 16, ecdheRSAKA, suiteECDHE | suiteTLS12, cipherAES, macSHA256, nil},
	{TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA, 16, 20, 16, ecdheRSAKA, suiteECDHE, cipherAES, macSHA1, nil},
	{TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256, 16, 32, 16, ecdheECDSAKA, suiteECDHE | suiteECSign | suiteTLS12, cipherAES, macSHA256, nil},
	{TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA, 16, 20, 16, ecdheECDSAKA, suiteECDHE | suiteECSign, cipherAES, macSHA1, nil},
	{TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA, 32, 20, 16, ecdheRSAKA, suiteECDHE, cipherAES, macSHA1, nil},
	{TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA, 32, 20, 16, ecdheECDSAKA, suiteECDHE | suiteECSign, cipherAES, macSHA1, nil},
	{TLS_RSA_WITH_AES_128_GCM_SHA256, 16, 0, 4, rsaKA, suiteTLS12, nil, nil, aeadAESGCM},
	{TLS_RSA_WITH_AES_256_GCM_SHA384, 32, 0, 4, rsaKA, suiteTLS12 | suiteSHA384, nil, nil, aeadAESGCM},
	{TLS_RSA_WITH_AES_128_CBC_SHA256, 16, 32, 16, rsaKA, suiteTLS12, cipherAES, macSHA256, nil},
	{TLS_RSA_WITH_AES_128_CBC_SHA, 16, 20, 16, rsaKA, 0, cipherAES, macSHA1, nil},
	{TLS_RSA_WITH_AES_256_CBC_SHA, 32, 20, 16, rsaKA, 0, cipherAES, macSHA1, nil},
	{TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA, 24, 20, 8, ecdheRSAKA, suiteECDHE, cipher3DES, macSHA1, nil},
	{TLS_RSA_WITH_3DES_EDE_CBC_SHA, 24, 20, 8, rsaKA, 0, cipher3DES, macSHA1, nil},
	{TLS_RSA_WITH_RC4_128_SHA, 16, 20, 0, rsaKA, 0, cipherRC4, macSHA1, nil},
	{TLS_ECDHE_RSA_WITH_RC4_128_SHA, 16, 20, 0, ecdheRSAKA, suiteECDHE, cipherRC4, macSHA1, nil},
	{TLS_ECDHE_ECDSA_WITH_RC4_128_SHA, 16, 20, 0, ecdheECDSAKA, suiteECDHE | suiteECSign, cipherRC4, macSHA1, nil},
}

// selectCipherSuite returns the first TLS 1.0–1.2 cipher suite from ids which
// is also in supportedIDs and passes the ok filter.
func selectCipherSuite(ids, supportedIDs []uint16, ok func(*cipherSuite) bool) *cipherSuite {
	for _, id := range ids {
		candidate := cipherSuiteByID(id)
		if candidate == nil || !ok(candidate) {
			continue
		}

		for _, suppID := range supportedIDs {
			if id == suppID {
				return candidate
			}
		}
	}
	return nil
}

// A cipherSuiteTLS13 defines only the pair of the AEAD algorithm and hash
// algorithm to be used with HKDF. See RFC 8446, Appendix B.4.
type cipherSuiteTLS13 struct {
	id     uint16
	keyLen int
	aead   func(key, fixedNonce []byte) aead
	hash   crypto.Hash
}

// cipherSuitesTLS13 should be an internal detail,
// but widely used packages access it using linkname.
// Notable members of the hall of shame include:
//   - github.com/quic-go/quic-go
//   - github.com/sagernet/quic-go
//
// Do not remove or change the type signature.
// See go.dev/issue/67401.
//
//go:linkname cipherSuitesTLS13
var cipherSuitesTLS13 = []*cipherSuiteTLS13{ // TODO: replace with a map.
	{TLS_AES_128_GCM_SHA256, 16, aeadAESGCMTLS13, crypto.SHA256},
	{TLS_CHACHA20_POLY1305_SHA256, 32, aeadChaCha20Poly1305, crypto.SHA256},
	{TLS_AES_256_GCM_SHA384, 32, aeadAESGCMTLS13, crypto.SHA384},
}

// cipherSuitesPreferenceOrder is the order in which we'll select (on the
// server) or advertise (on the client) TLS 1.0–1.2 cipher suites.
//
// Cipher suites are filtered but not reordered based on the application and
// peer's preferences, meaning we'll never select a suite lower in this list if
// any higher one is available. This makes it more defensible to keep weaker
// cipher suites enabled, especially on the server side where we get the last
// word, since there are no known downgrade attacks on cipher suites selection.
//
// The list is sorted by applying the following priority rules, stopping at the
// first (most important) applicable one:
//
//   - Anything else comes before RC4
//
//     RC4 has practically exploitable biases. See https://www.rc4nomore.com.
//
//   - Anything else comes before CBC_SHA256
//
//     SHA-256 variants of the CBC ciphersuites don't implement any Lucky13
//     countermeasures. See https://www.isg.rhul.ac.uk/tls/Lucky13.html and
//     https://www.imperialviolet.org/2013/02/04/luckythirteen.html.
//
//   - Anything else comes before 3DES
//
//     3DES has 64-bit blocks, which makes it fundamentally susceptible to
//     birthday attacks. See https://sweet32.info.
//
//   - ECDHE comes before anything else
//
//     Once we got the broken stuff out of the way, the most important
//     property a cipher suite can have is forward secrecy. We don't
//     implement FFDHE, so that means ECDHE.
//
//   - AEADs come before CBC ciphers
//
//     Even with Lucky13 countermeasures, MAC-then-Encrypt CBC cipher suites
//     are fundamentally fragile, and suffered from an endless sequence of
//     padding oracle attacks. See https://eprint.iacr.org/2015/1129,
//     https://www.imperialviolet.org/2014/12/08/poodleagain.html, and
//     https://blog.cloudflare.com/yet-another-padding-oracle-in-openssl-cbc-ciphersuites/.
//
//   - AES comes before ChaCha20
//
//     When AES hardware is available, AES-128-GCM and AES-256-GCM are faster
//     than ChaCha20Poly1305.
//
//     When AES hardware is not available, AES-128-GCM is one or more of: much
//     slower, way more complex, and less safe (because not constant time)
//     than ChaCha20Poly1305.
//
//     We use this list if we think both peers have AES hardware, and
//     cipherSuitesPreferenceOrderNoAES otherwise.
//
//   - AES-128 comes before AES-256
//
//     The only potential advantages of AES-256 are better multi-target
//     margins, and hypothetical post-quantum properties. Neither apply to
//     TLS, and AES-256 is slower due to its four extra rounds (which don't
//     contribute to the advantages above).
//
//   - ECDSA comes before RSA
//
//     The relative order of ECDSA and RSA cipher suites doesn't matter,
//     as they depend on the certificate. Pick one to get a stable order.
var cipherSuitesPreferenceOrder = []uint16{
	// AEADs w/ ECDHE
	TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
	TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384, TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
	TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305, TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,

	// CBC w/ ECDHE
	TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA, TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
	TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA, TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,

	// AEADs w/o ECDHE
	TLS_RSA_WITH_AES_128_GCM_SHA256,
	TLS_RSA_WITH_AES_256_GCM_SHA384,

	// CBC w/o ECDHE
	TLS_RSA_WITH_AES_128_CBC_SHA,
	TLS_RSA_WITH_AES_256_CBC_SHA,

	// 3DES
	TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,
	TLS_RSA_WITH_3DES_EDE_CBC_SHA,

	// CBC_SHA256
	TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256, TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
	TLS_RSA_WITH_AES_128_CBC_SHA256,

	// RC4
	TLS_ECDHE_ECDSA_WITH_RC4_128_SHA, TLS_ECDHE_RSA_WITH_RC4_128_SHA,
	TLS_RSA_WITH_RC4_128_SHA,
}

var cipherSuitesPreferenceOrderNoAES = []uint16{
	// ChaCha20Poly1305
	TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305, TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,

	// AES-GCM w/ ECDHE
	TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
	TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384, TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,

	// The rest of cipherSuitesPreferenceOrder.
	TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA, TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
	TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA, TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
	TLS_RSA_WITH_AES_128_GCM_SHA256,
	TLS_RSA_WITH_AES_256_GCM_SHA384,
	TLS_RSA_WITH_AES_128_CBC_SHA,
	TLS_RSA_WITH_AES_256_CBC_SHA,
	TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,
	TLS_RSA_WITH_3DES_EDE_CBC_SHA,
	TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256, TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
	TLS_RSA_WITH_AES_128_CBC_SHA256,
	TLS_ECDHE_ECDSA_WITH_RC4_128_SHA, TLS_ECDHE_RSA_WITH_RC4_128_SHA,
	TLS_RSA_WITH_RC4_128_SHA,
}

// disabledCipherSuites are not used unless explicitly listed in Config.CipherSuites.
var disabledCipherSuites = map[uint16]bool{
	// CBC_SHA256
	TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256: true,
	TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256:   true,
	TLS_RSA_WITH_AES_128_CBC_SHA256:         true,

	// RC4
	TLS_ECDHE_ECDSA_WITH_RC4_128_SHA: true,
	TLS_ECDHE_RSA_WITH_RC4_128_SHA:   true,
	TLS_RSA_WITH_RC4_128_SHA:         true,
}

// rsaKexCiphers contains the ciphers which use RSA based key exchange,
// which we also disable by default unless a GODEBUG is set.
var rsaKexCiphers = map[uint16]bool{
	TLS_RSA_WITH_RC4_128_SHA:        true,
	TLS_RSA_WITH_3DES_EDE_CBC_SHA:   true,
	TLS_RSA_WITH_AES_128_CBC_SHA:    true,
	TLS_RSA_WITH_AES_256_CBC_SHA:    true,
	TLS_RSA_WITH_AES_128_CBC_SHA256: true,
	TLS_RSA_WITH_AES_128_GCM_SHA256: true,
	TLS_RSA_WITH_AES_256_GCM_SHA384: true,
}

// tdesCiphers contains 3DES ciphers,
// which we also disable by default unless a GODEBUG is set.
var tdesCiphers = map[uint16]bool{
	TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA: true,
	TLS_RSA_WITH_3DES_EDE_CBC_SHA:       true,
}

var (
	// Keep in sync with crypto/internal/fips140/aes/gcm.supportsAESGCM.
	hasGCMAsmAMD64 = cpu.X86.HasAES && cpu.X86.HasPCLMULQDQ && cpu.X86.HasSSE41 && cpu.X86.HasSSSE3
	hasGCMAsmARM64 = cpu.ARM64.HasAES && cpu.ARM64.HasPMULL
	hasGCMAsmS390X = cpu.S390X.HasAES && cpu.S390X.HasAESCTR && cpu.S390X.HasGHASH
	hasGCMAsmPPC64 = runtime.GOARCH == "ppc64" || runtime.GOARCH == "ppc64le"

	hasAESGCMHardwareSupport = hasGCMAsmAMD64 || hasGCMAsmARM64 || hasGCMAsmS390X || hasGCMAsmPPC64
)

var aesgcmCiphers = map[uint16]bool{
	// TLS 1.2
	TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:   true,
	TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:   true,
	TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256: true,
	TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384: true,
	// TLS 1.3
	TLS_AES_128_GCM_SHA256: true,
	TLS_AES_256_GCM_SHA384: true,
}

// aesgcmPreferred returns whether the first known cipher in the preference list
// is an AES-GCM cipher, implying the peer has hardware support for it.
func aesgcmPreferred(ciphers []uint16) bool {
	for _, cID := range ciphers {
		if c := cipherSuiteByID(cID); c != nil {
			return aesgcmCiphers[cID]
		}
		if c := cipherSuiteTLS13ByID(cID); c != nil {
			return aesgcmCiphers[cID]
		}
	}
	return false
}

func cipherRC4(key, iv []byte, isRead bool) any {
	cipher, _ := rc4.NewCipher(key)
	return cipher
}

func cipher3DES(key, iv []byte, isRead bool) any {
	block, _ := des.NewTripleDESCipher(key)
	if isRead {
		return cipher.NewCBCDecrypter(block, iv)
	}
	return cipher.NewCBCEncrypter(block, iv)
}

func cipherAES(key, iv []byte, isRead bool) any {
	block, _ := aes.NewCipher(key)
	if isRead {
		return cipher.NewCBCDecrypter(block, iv)
	}
	return cipher.NewCBCEncrypter(block, iv)
}

// macSHA1 returns a SHA-1 based constant time MAC.
func macSHA1(key []byte) hash.Hash {
	h := sha1.New
	// The BoringCrypto SHA1 does not have a constant-time
	// checksum function, so don't try to use it.
	if !boring.Enabled {
		h = newConstantTimeHash(h)
	}
	return hmac.New(h, key)
}

// macSHA256 returns a SHA-256 based MAC. This is only supported in TLS 1.2 and
// is currently only used in disabled-by-default cipher suites.
func macSHA256(key []byte) hash.Hash {
	return hmac.New(sha256.New, key)
}

type aead interface {
	cipher.AEAD

	// explicitNonceLen returns the number of bytes of explicit nonce
	// included in each record. This is eight for older AEADs and
	// zero for modern ones.
	explicitNonceLen() int
}

const (
	aeadNonceLength   = 12
	noncePrefixLength = 4
)

// prefixNonceAEAD wraps an AEAD and prefixes a fixed portion of the nonce to
// each call.
type prefixNonceAEAD struct {
	// nonce contains the fixed part of the nonce in the first four bytes.
	nonce [aeadNonceLength]byte
	aead  cipher.AEAD
}

func (f *prefixNonceAEAD) NonceSize() int        { return aeadNonceLength - noncePrefixLength }
func (f *prefixNonceAEAD) Overhead() int         { return f.aead.Overhead() }
func (f *prefixNonceAEAD) explicitNonceLen() int { return f.NonceSize() }

func (f *prefixNonceAEAD) Seal(out, nonce, plaintext, additionalData []byte) []byte {
	copy(f.nonce[4:], nonce)
	return f.aead.Seal(out, f.nonce[:], plaintext, additionalData)
}

func (f *prefixNonceAEAD) Open(out, nonce, ciphertext, additionalData []byte) ([]byte, error) {
	copy(f.nonce[4:], nonce)
	return f.aead.Open(out, f.nonce[:], ciphertext, additionalData)
}

// xorNonceAEAD wraps an AEAD by XORing in a fixed pattern to the nonce
// before each call.
type xorNonceAEAD struct {
	nonceMask [aeadNonceLength]byte
	aead      cipher.AEAD
}

func (f *xorNonceAEAD) NonceSize() int        { return 8 } // 64-bit sequence number
func (f *xorNonceAEAD) Overhead() int         { return f.aead.Overhead() }
func (f *xorNonceAEAD) explicitNonceLen() int { return 0 }

func (f *xorNonceAEAD) Seal(out, nonce, plaintext, additionalData []byte) []byte {
	for i, b := range nonce {
		f.nonceMask[4+i] ^= b
	}
	result := f.aead.Seal(out, f.nonceMask[:], plaintext, additionalData)
	for i, b := range nonce {
		f.nonceMask[4+i] ^= b
	}

	return result
}

func (f *xorNonceAEAD) Open(out, nonce, ciphertext, additionalData []byte) ([]byte, error) {
	for i, b := range nonce {
		f.nonceMask[4+i] ^= b
	}
	result, err := f.aead.Open(out, f.nonceMask[:], ciphertext, additionalData)
	for i, b := range nonce {
		f.nonceMask[4+i] ^= b
	}

	return result, err
}

func aeadAESGCM(key, noncePrefix []byte) aead {
	if len(noncePrefix) != noncePrefixLength {
		panic("tls: internal error: wrong nonce length")
	}
	aes, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	var aead cipher.AEAD
	if boring.Enabled {
		aead, err = boring.NewGCMTLS(aes)
	} else {
		boring.Unreachable()
		aead, err = gcm.NewGCMForTLS12(aes.(*fipsaes.Block))
	}
	if err != nil {
		panic(err)
	}

	ret := &prefixNonceAEAD{aead: aead}
	copy(ret.nonce[:], noncePrefix)
	return ret
}

// aeadAESGCMTLS13 should be an internal detail,
// but widely used packages access it using linkname.
// Notable members of the hall of shame include:
//   - github.com/xtls/xray-core
//   - github.com/v2fly/v2ray-core
//
// Do not remove or change the type signature.
// See go.dev/issue/67401.
//
//go:linkname aeadAESGCMTLS13
func aeadAESGCMTLS13(key, nonceMask []byte) aead {
	if len(nonceMask) != aeadNonceLength {
		panic("tls: internal error: wrong nonce length")
	}
	aes, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	var aead cipher.AEAD
	if boring.Enabled {
		aead, err = boring.NewGCMTLS13(aes)
	} else {
		boring.Unreachable()
		aead, err = gcm.NewGCMForTLS13(aes.(*fipsaes.Block))
	}
	if err != nil {
		panic(err)
	}

	ret := &xorNonceAEAD{aead: aead}
	copy(ret.nonceMask[:], nonceMask)
	return ret
}

func aeadChaCha20Poly1305(key, nonceMask []byte) aead {
	if len(nonceMask) != aeadNonceLength {
		panic("tls: internal error: wrong nonce length")
	}
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		panic(err)
	}

	ret := &xorNonceAEAD{aead: aead}
	copy(ret.nonceMask[:], nonceMask)
	return ret
}

type constantTimeHash interface {
	hash.Hash
	ConstantTimeSum(b []byte) []byte
}

// cthWrapper wraps any hash.Hash that implements ConstantTimeSum, and replaces
// with that all calls to Sum. It's used to obtain a ConstantTimeSum-based HMAC.
type cthWrapper struct {
	h constantTimeHash
}

func (c *cthWrapper) Size() int                   { return c.h.Size() }
func (c *cthWrapper) BlockSize() int              { return c.h.BlockSize() }
func (c *cthWrapper) Reset()                      { c.h.Reset() }
func (c *cthWrapper) Write(p []byte) (int, error) { return c.h.Write(p) }
func (c *cthWrapper) Sum(b []byte) []byte         { return c.h.ConstantTimeSum(b) }

func newConstantTimeHash(h func() hash.Hash) func() hash.Hash {
	boring.Unreachable()
	return func() hash.Hash {
		return &cthWrapper{h().(constantTimeHash)}
	}
}

// tls10MAC implements the TLS 1.0 MAC function. RFC 2246, Section 6.2.3.
func tls10MAC(h hash.Hash, out, seq, header, data, extra []byte) []byte {
	h.Reset()
	h.Write(seq)
	h.Write(header)
	h.Write(data)
	res := h.Sum(out)
	if extra != nil {
		h.Write(extra)
	}
	return res
}

func rsaKA(version uint16) keyAgreement {
	return rsaKeyAgreement{}
}

func ecdheECDSAKA(version uint16) keyAgreement {
	return &ecdheKeyAgreement{
		isRSA:   false,
		version: version,
	}
}

func ecdheRSAKA(version uint16) keyAgreement {
	return &ecdheKeyAgreement{
		isRSA:   true,
		version: version,
	}
}

// mutualCipherSuite returns a cipherSuite given a list of supported
// ciphersuites and the id requested by the peer.
func mutualCipherSuite(have []uint16, want uint16) *cipherSuite {
	for _, id := range have {
		if id == want {
			return cipherSuiteByID(id)
		}
	}
	return nil
}

func cipherSuiteByID(id uint16) *cipherSuite {
	for _, cipherSuite := range cipherSuites {
		if cipherSuite.id == id {
			return cipherSuite
		}
	}
	return nil
}

func mutualCipherSuiteTLS13(have []uint16, want uint16) *cipherSuiteTLS13 {
	for _, id := range have {
		if id == want {
			return cipherSuiteTLS13ByID(id)
		}
	}
	return nil
}

func cipherSuiteTLS13ByID(id uint16) *cipherSuiteTLS13 {
	for _, cipherSuite := range cipherSuitesTLS13 {
		if cipherSuite.id == id {
			return cipherSuite
		}
	}
	return nil
}

// A list of cipher suite IDs that are, or have been, implemented by this
// package.
//
// See https://www.iana.org/assignments/tls-parameters/tls-parameters.xml
const (
	// TLS 1.0 - 1.2 cipher suites.
	TLS_RSA_WITH_RC4_128_SHA                      uint16 = 0x0005
	TLS_RSA_WITH_3DES_EDE_CBC_SHA                 uint16 = 0x000a
	TLS_RSA_WITH_AES_128_CBC_SHA                  uint16 = 0x002f
	TLS_RSA_WITH_AES_256_CBC_SHA                  uint16 = 0x0035
	TLS_RSA_WITH_AES_128_CBC_SHA256               uint16 = 0x003c
	TLS_RSA_WITH_AES_128_GCM_SHA256               uint16 = 0x009c
	TLS_RSA_WITH_AES_256_GCM_SHA384               uint16 = 0x009d
	TLS_ECDHE_ECDSA_WITH_RC4_128_SHA              uint16 = 0xc007
	TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA          uint16 = 0xc009
	TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA          uint16 = 0xc00a
	TLS_ECDHE_RSA_WITH_RC4_128_SHA                uint16 = 0xc011
	TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA           uint16 = 0xc012
	TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA            uint16 = 0xc013
	TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA            uint16 = 0xc014
	TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256       uint16 = 0xc023
	TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256         uint16 = 0xc027
	TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256         uint16 = 0xc02f
	TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256       uint16 = 0xc02b
	TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384         uint16 = 0xc030
	TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384       uint16 = 0xc02c
	TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256   uint16 = 0xcca8
	TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 uint16 = 0xcca9

	// TLS 1.3 cipher suites.
	TLS_AES_128_GCM_SHA256       uint16 = 0x1301
	TLS_AES_256_GCM_SHA384       uint16 = 0x1302
	TLS_CHACHA20_POLY1305_SHA256 uint16 = 0x1303

	// TLS_FALLBACK_SCSV isn't a standard cipher suite but an indicator
	// that the client is doing version fallback. See RFC 7507.
	TLS_FALLBACK_SCSV uint16 = 0x5600

	// Legacy names for the corresponding cipher suites with the correct _SHA256
	// suffix, retained for backward compatibility.
	TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305   = TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
	TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305 = TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
)

"""



```