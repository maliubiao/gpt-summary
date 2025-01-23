Response:
Let's break down the thought process for analyzing this Go code snippet.

**1. Initial Understanding - Context is Key:**

The first thing I notice is the import path: `go/src/crypto/x509/root_windows.go`. This immediately tells me this code is specifically dealing with X.509 certificates on Windows. The `root_windows.go` filename hints at managing root certificates, which are crucial for trust establishment in certificate verification.

**2. Function-by-Function Analysis:**

I'll go through each function and try to understand its purpose:

* **`loadSystemRoots()`:**  The name is very suggestive. "Load system roots" implies accessing the operating system's trusted root certificates. The return value `*CertPool, error` confirms it's likely loading these roots into a `CertPool` structure (defined elsewhere in the `x509` package). The implementation `return &CertPool{systemPool: true}, nil` suggests it's not actually loading them immediately, but rather marking the `CertPool` as one that will use the system's store later. This is a common pattern for lazy loading or indicating a specific type of pool.

* **`createStoreContext()`:**  This function deals with `syscall.CertContext` and mentions an "in-memory certificate store."  The purpose seems to be creating a temporary store containing a leaf certificate and optionally its intermediates. The use of `syscall` strongly indicates interaction with the Windows CryptoAPI. The comments about automatic freeing reinforce this.

* **`extractSimpleChain()`:** The name and the `syscall.CertSimpleChain` type point towards extracting a certificate chain from the Windows API's representation. The use of `unsafe` package indicates direct memory manipulation, which is often necessary when interacting with C APIs like the Windows CryptoAPI. The function iterates through the `CertSimpleChain` structure and parses the raw certificate data.

* **`checkChainTrustStatus()`:** This function looks at the `TrustStatus` of a `syscall.CertChainContext`. It's clearly responsible for translating Windows-specific trust error codes into Go's `CertificateInvalidError` or `UnknownAuthorityError`. This is essential for making the verification results understandable in a Go context.

* **`checkChainSSLServerPolicy()`:**  The name and the `AUTHTYPE_SERVER` constant clearly indicate this function checks if a certificate chain is valid for use by an SSL/TLS server. It takes a `DNSName` as input, suggesting it performs hostname verification. Again, `syscall.CertVerifyCertificateChainPolicy` confirms interaction with the Windows API.

* **`verifyChain()`:** This function appears to orchestrate the chain verification process. It calls `checkChainTrustStatus` and `checkChainSSLServerPolicy`. It then extracts the chain using `extractSimpleChain`. The comment about CVE-2020-0601 is a crucial piece of information, indicating a security mitigation by double-checking ECDSA signatures.

* **`systemVerify()`:**  This looks like the main entry point for verifying a certificate using the Windows CryptoAPI. It creates a store context, sets up parameters for the Windows API call (`syscall.CertGetCertificateChain`), and then iterates through the returned chains, calling `verifyChain` to process each one.

**3. Identifying Go Language Features:**

As I analyze the functions, I look for common Go features being used:

* **Structs:** `CertPool`, `VerifyOptions`, `Certificate` (though not defined in this snippet, its usage is clear).
* **Pointers:**  Extensive use of pointers, especially when interacting with the `syscall` package (C-style APIs).
* **Slices:**  Used for handling lists of certificates and raw byte data.
* **Error Handling:**  Consistent use of `error` as a return value and checking for `nil` to detect errors.
* **`defer`:**  Used for resource cleanup (freeing memory and closing handles).
* **`unsafe` package:** Used for low-level memory access when interacting with the C API.
* **Constants:** `syscall.X509_ASN_ENCODING`, `syscall.CERT_STORE_PROV_MEMORY`, etc.
* **Maps:** `windowsExtKeyUsageOIDs`.
* **`init()` function:**  For initializing global variables.

**4. Code Reasoning and Example Construction:**

For functions like `createStoreContext`, I can imagine how it would be used. I'd need a `Certificate` and `VerifyOptions`. The output would be a `syscall.CertContext`. This allows me to construct a simple usage example (even without knowing the exact structure of `Certificate` and `VerifyOptions`).

For `extractSimpleChain`, I recognize the pattern of converting C-style arrays to Go slices using `unsafe.Slice`. I know the input is a pointer to a pointer, indicating the Windows API might allocate the memory. The output is a `[]*Certificate`.

**5. Command-Line Parameters (Not Applicable Here):**

I scan the code for any usage of `os.Args` or the `flag` package, which are common for handling command-line arguments in Go. Since I don't find any, I conclude that this specific snippet doesn't directly process command-line arguments. It's part of a larger library.

**6. Common Mistakes:**

I consider potential pitfalls, especially when interacting with C APIs:

* **Memory Leaks:** Forgetting to `defer syscall.CertFreeCertificateContext` or `syscall.CertCloseStore` could lead to memory leaks.
* **Incorrectly Handling Pointers:** Misusing `unsafe.Pointer` can cause crashes or unexpected behavior.
* **Ignoring Error Codes:** Not properly checking the error return values from `syscall` functions is a common mistake.
* **Assumptions about Data Structures:**  Making incorrect assumptions about the layout of the Windows API structures could lead to errors.

**7. Structuring the Answer:**

Finally, I organize my findings into the requested sections:

* **功能:**  A high-level summary of what the code does.
* **Go语言功能实现:**  Concrete examples with assumed inputs and outputs to illustrate how the functions work.
* **代码推理:**  Explaining the logic behind key functions.
* **命令行参数:** Explicitly stating that this snippet doesn't handle them.
* **易犯错的点:**  Listing common mistakes based on the analysis.

By following these steps, I can systematically analyze the code, understand its purpose, and provide a comprehensive and accurate answer. The key is to start with the context, analyze each function individually, look for common patterns and Go features, and then synthesize the information into a coherent explanation.
这段代码是 Go 语言 `crypto/x509` 包在 Windows 平台上的特定实现，主要负责与 Windows 系统底层的证书存储和验证机制进行交互。以下是其主要功能：

**1. 加载系统根证书:**

*   `loadSystemRoots() (*CertPool, error)` 函数的功能是加载 Windows 系统信任的根证书。实际上，从代码来看，它并没有直接加载证书数据，而是返回一个 `CertPool` 结构体，并将 `systemPool` 字段设置为 `true`。这表明该 `CertPool` 将会在后续的证书验证过程中指示使用 Windows 系统的证书存储。

**2. 创建包含叶子证书和中间证书的内存证书存储上下文:**

*   `createStoreContext(leaf *Certificate, opts *VerifyOptions) (*syscall.CertContext, error)` 函数创建一个临时的、基于内存的证书存储，其中包含待验证的叶子证书以及 `VerifyOptions` 中指定的中间证书。
    *   它首先使用 `syscall.CertCreateCertificateContext` 创建叶子证书的上下文。
    *   然后使用 `syscall.CertOpenStore` 创建一个内存证书存储。
    *   接着使用 `syscall.CertAddCertificateContextToStore` 将叶子证书添加到该存储中。
    *   如果 `opts.Intermediates` 中有中间证书，它会遍历这些证书，并逐个添加到内存证书存储中。
    *   最后返回一个指向该内存证书存储中叶子证书的 `syscall.CertContext` 指针。这个返回的 `CertContext` 的 `Store` 字段指向创建的内存存储，并且当使用 `syscall.CertFreeCertificateContext` 释放该 `CertContext` 时，该内存存储也会被自动释放。

**3. 从 CertSimpleChain 中提取最终的证书链:**

*   `extractSimpleChain(simpleChain **syscall.CertSimpleChain, count int) (chain []*Certificate, err error)` 函数将 Windows API 返回的 `CertSimpleChain` 结构转换为 Go 语言的 `[]*Certificate` 类型的证书链。
    *   它通过 `unsafe.Slice` 将 C 风格的数组转换为 Go 的切片。
    *   遍历 `CertSimpleChain` 中的每个元素，每个元素都包含一个证书上下文。
    *   从证书上下文中提取原始的证书编码数据 (`EncodedCert`)。
    *   使用 `ParseCertificate` 函数将原始的证书数据解析为 Go 的 `Certificate` 对象。
    *   将解析后的 `Certificate` 对象添加到返回的证书链中。

**4. 检查证书链的信任状态:**

*   `checkChainTrustStatus(c *Certificate, chainCtx *syscall.CertChainContext) error` 函数检查 Windows API 返回的证书链上下文 (`chainCtx`) 中的信任状态，并将 Windows 特定的错误代码转换为 Go 语言的错误类型。
    *   它检查 `chainCtx.TrustStatus.ErrorStatus` 字段，该字段表示证书链的信任错误状态。
    *   根据不同的错误代码，返回相应的 Go 错误，例如 `CertificateInvalidError` (证书过期或用途不符) 或 `UnknownAuthorityError` (未知颁发机构)。

**5. 检查证书链是否适用于 SSL/TLS 服务器:**

*   `checkChainSSLServerPolicy(c *Certificate, chainCtx *syscall.CertChainContext, opts *VerifyOptions) error` 函数使用 Windows API 检查证书链是否适合作为 SSL/TLS 服务器证书使用。
    *   它使用 `syscall.UTF16PtrFromString` 将 `opts.DNSName` 转换为 Windows API 可以接受的 UTF-16 字符串指针。
    *   创建一个 `syscall.SSLExtraCertChainPolicyPara` 结构体，指定认证类型为服务器 (`syscall.AUTHTYPE_SERVER`) 和服务器名称。
    *   创建一个 `syscall.CertChainPolicyPara` 结构体，并将 `SSLExtraCertChainPolicyPara` 结构体作为额外策略参数传递。
    *   调用 `syscall.CertVerifyCertificateChainPolicy` 函数执行证书链策略验证。
    *   根据返回的状态码，返回相应的 Go 错误，例如 `CertificateInvalidError` (证书过期), `HostnameError` (主机名不匹配) 或 `UnknownAuthorityError` (未知颁发机构)。

**6. 证书链验证的核心逻辑:**

*   `verifyChain(c *Certificate, chainCtx *syscall.CertChainContext, opts *VerifyOptions) (chain []*Certificate, err error)` 函数是使用 Windows 系统 API 验证证书链的核心逻辑。
    *   首先调用 `checkChainTrustStatus` 检查基本的信任状态。
    *   如果提供了 `opts.DNSName`，则调用 `checkChainSSLServerPolicy` 检查是否适用于 SSL/TLS 服务器。
    *   调用 `extractSimpleChain` 从 Windows API 的结构中提取证书链。
    *   为了缓解 CVE-2020-0601 安全漏洞，它会对链中所有非根证书的 ECDSA 签名进行二次校验，确保 Windows 系统验证器没有被欺骗使用了错误的椭圆曲线参数。

**7. 使用系统 API 进行证书验证:**

*   `(c *Certificate) systemVerify(opts *VerifyOptions) (chains [][]*Certificate, err error)` 函数是 `Certificate` 类型的扩展方法，它使用 Windows CryptoAPI 来构建和验证证书链。
    *   它首先调用 `createStoreContext` 创建一个包含待验证证书及其可能中间证书的内存存储上下文。
    *   然后配置 `syscall.CertChainPara` 结构体，包括请求的扩展密钥用途 (`opts.KeyUsages`) 和验证时间 (`opts.CurrentTime`)。
    *   调用 `syscall.CertGetCertificateChain` 函数，该函数会利用 Windows 系统的证书存储（包括系统根证书）来尝试构建完整的、可信任的证书链。
    *   `CERT_CHAIN_RETURN_LOWER_QUALITY_CONTEXTS` 标志指示 Windows API 返回所有质量的证书链，而不仅仅是最佳的。
    *   调用 `verifyChain` 函数来验证主要的证书链 (`topCtx`)。
    *   如果存在低质量的证书链 (`topCtx.LowerQualityChainCount > 0`)，它会遍历这些链并分别进行验证。
    *   最终返回所有成功验证的证书链。

**推理 Go 语言功能的实现:**

这段代码主要利用 Go 语言的 `syscall` 包来调用 Windows 操作系统的底层 API (通常称为 WinAPI 或 Windows API)，特别是与证书管理相关的 CryptoAPI。

**Go 代码举例说明 (假设输入与输出):**

```go
package main

import (
	"crypto/x59"
	"fmt"
	"time"
)

func main() {
	// 假设我们有一个已解析的叶子证书 leafCert
	leafCert, err := x509.ParseCertificate([]byte{ /* 证书的 DER 编码 */ })
	if err != nil {
		fmt.Println("解析叶子证书失败:", err)
		return
	}

	// 配置验证选项
	opts := &x509.VerifyOptions{
		DNSName:     "example.com",
		CurrentTime: time.Now(),
		KeyUsages:   []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	// 使用 systemVerify 进行系统验证
	chains, err := leafCert.SystemVerify(opts)
	if err != nil {
		fmt.Println("证书验证失败:", err)
		return
	}

	fmt.Println("证书验证成功，找到以下证书链:")
	for i, chain := range chains {
		fmt.Printf("链 %d:\n", i+1)
		for _, cert := range chain {
			fmt.Printf("  主题: %s\n", cert.Subject.CommonName)
			fmt.Printf("  颁发者: %s\n", cert.Issuer.CommonName)
		}
	}
}
```

**假设的输入与输出:**

*   **输入:**
    *   `leafCert`: 一个包含 `example.com` 证书信息的 `x509.Certificate` 对象。
    *   `opts`: 一个 `x509.VerifyOptions` 对象，指定要验证的主机名是 "example.com"，当前时间为某个时间点，并且期望的密钥用途是 `x509.ExtKeyUsageServerAuth`。
*   **输出:**
    *   `chains`: 一个 `[][]*x509.Certificate` 类型的切片，包含所有通过系统验证的证书链。每个链都是一个 `[]*x509.Certificate`，从叶子证书到根证书排列。
    *   如果验证失败，`err` 将会包含描述失败原因的错误信息。

**命令行参数的具体处理:**

这段代码本身并没有直接处理命令行参数。它是一个库的一部分，用于提供证书验证功能。上层应用如果需要接收命令行参数，需要使用 Go 语言的 `flag` 包或者其他命令行参数解析库来实现。

**使用者易犯错的点:**

1. **忘记处理错误:** 调用 `SystemVerify` 后，需要检查返回的 `error`，以确定证书验证是否成功。忽略错误可能导致安全漏洞或程序异常。
2. **错误的 `VerifyOptions` 配置:**  `VerifyOptions` 中的 `DNSName`、`CurrentTime` 和 `KeyUsages` 等参数会影响验证结果。例如，如果 `DNSName` 设置不正确，可能会导致主机名验证失败。如果 `CurrentTime` 不正确，可能会导致证书过期或未生效的判断错误。
3. **假设 Windows 系统证书存储的可用性:**  这段代码依赖于 Windows 系统中配置的证书存储。如果用户的 Windows 系统缺少必要的根证书，证书验证可能会失败。
4. **不了解 Windows 证书链构建的机制:**  Windows 的证书链构建可能涉及到多种策略和设置。不了解这些机制可能会导致对验证结果的误解。例如，某些情况下，即使证书本身有效，但由于吊销列表不可用等原因，验证也可能失败。

**示例说明易犯错的点:**

假设开发者错误地将 `VerifyOptions` 中的 `DNSName` 设置为与证书实际 CN 或 SAN 不符的值：

```go
// ... (前面相同的代码)

	// 错误的 DNSName
	opts := &x509.VerifyOptions{
		DNSName:     "wrong-example.com", // 与证书不匹配
		CurrentTime: time.Now(),
		KeyUsages:   []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	chains, err := leafCert.SystemVerify(opts)
	if err != nil {
		// 此时 err 可能会是一个 x509.HostnameError，指示主机名不匹配
		fmt.Println("证书验证失败:", err) // 输出: 证书验证失败: x509: certificate is valid for example.com, not wrong-example.com
		return
	}

	// ... (不会执行到这里)
```

在这个例子中，由于 `DNSName` 设置错误，`checkChainSSLServerPolicy` 函数会检测到主机名不匹配，并返回一个 `HostnameError`。开发者需要正确处理这个错误，而不是假设验证总是成功。

### 提示词
```
这是路径为go/src/crypto/x509/root_windows.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
```

### 源代码
```go
// Copyright 2012 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package x509

import (
	"bytes"
	"errors"
	"strings"
	"syscall"
	"unsafe"
)

func loadSystemRoots() (*CertPool, error) {
	return &CertPool{systemPool: true}, nil
}

// Creates a new *syscall.CertContext representing the leaf certificate in an in-memory
// certificate store containing itself and all of the intermediate certificates specified
// in the opts.Intermediates CertPool.
//
// A pointer to the in-memory store is available in the returned CertContext's Store field.
// The store is automatically freed when the CertContext is freed using
// syscall.CertFreeCertificateContext.
func createStoreContext(leaf *Certificate, opts *VerifyOptions) (*syscall.CertContext, error) {
	var storeCtx *syscall.CertContext

	leafCtx, err := syscall.CertCreateCertificateContext(syscall.X509_ASN_ENCODING|syscall.PKCS_7_ASN_ENCODING, &leaf.Raw[0], uint32(len(leaf.Raw)))
	if err != nil {
		return nil, err
	}
	defer syscall.CertFreeCertificateContext(leafCtx)

	handle, err := syscall.CertOpenStore(syscall.CERT_STORE_PROV_MEMORY, 0, 0, syscall.CERT_STORE_DEFER_CLOSE_UNTIL_LAST_FREE_FLAG, 0)
	if err != nil {
		return nil, err
	}
	defer syscall.CertCloseStore(handle, 0)

	err = syscall.CertAddCertificateContextToStore(handle, leafCtx, syscall.CERT_STORE_ADD_ALWAYS, &storeCtx)
	if err != nil {
		return nil, err
	}

	if opts.Intermediates != nil {
		for i := 0; i < opts.Intermediates.len(); i++ {
			intermediate, _, err := opts.Intermediates.cert(i)
			if err != nil {
				return nil, err
			}
			ctx, err := syscall.CertCreateCertificateContext(syscall.X509_ASN_ENCODING|syscall.PKCS_7_ASN_ENCODING, &intermediate.Raw[0], uint32(len(intermediate.Raw)))
			if err != nil {
				return nil, err
			}

			err = syscall.CertAddCertificateContextToStore(handle, ctx, syscall.CERT_STORE_ADD_ALWAYS, nil)
			syscall.CertFreeCertificateContext(ctx)
			if err != nil {
				return nil, err
			}
		}
	}

	return storeCtx, nil
}

// extractSimpleChain extracts the final certificate chain from a CertSimpleChain.
func extractSimpleChain(simpleChain **syscall.CertSimpleChain, count int) (chain []*Certificate, err error) {
	if simpleChain == nil || count == 0 {
		return nil, errors.New("x509: invalid simple chain")
	}

	simpleChains := unsafe.Slice(simpleChain, count)
	lastChain := simpleChains[count-1]
	elements := unsafe.Slice(lastChain.Elements, lastChain.NumElements)
	for i := 0; i < int(lastChain.NumElements); i++ {
		// Copy the buf, since ParseCertificate does not create its own copy.
		cert := elements[i].CertContext
		encodedCert := unsafe.Slice(cert.EncodedCert, cert.Length)
		buf := bytes.Clone(encodedCert)
		parsedCert, err := ParseCertificate(buf)
		if err != nil {
			return nil, err
		}
		chain = append(chain, parsedCert)
	}

	return chain, nil
}

// checkChainTrustStatus checks the trust status of the certificate chain, translating
// any errors it finds into Go errors in the process.
func checkChainTrustStatus(c *Certificate, chainCtx *syscall.CertChainContext) error {
	if chainCtx.TrustStatus.ErrorStatus != syscall.CERT_TRUST_NO_ERROR {
		status := chainCtx.TrustStatus.ErrorStatus
		switch status {
		case syscall.CERT_TRUST_IS_NOT_TIME_VALID:
			return CertificateInvalidError{c, Expired, ""}
		case syscall.CERT_TRUST_IS_NOT_VALID_FOR_USAGE:
			return CertificateInvalidError{c, IncompatibleUsage, ""}
		// TODO(filippo): surface more error statuses.
		default:
			return UnknownAuthorityError{c, nil, nil}
		}
	}
	return nil
}

// checkChainSSLServerPolicy checks that the certificate chain in chainCtx is valid for
// use as a certificate chain for a SSL/TLS server.
func checkChainSSLServerPolicy(c *Certificate, chainCtx *syscall.CertChainContext, opts *VerifyOptions) error {
	servernamep, err := syscall.UTF16PtrFromString(strings.TrimSuffix(opts.DNSName, "."))
	if err != nil {
		return err
	}
	sslPara := &syscall.SSLExtraCertChainPolicyPara{
		AuthType:   syscall.AUTHTYPE_SERVER,
		ServerName: servernamep,
	}
	sslPara.Size = uint32(unsafe.Sizeof(*sslPara))

	para := &syscall.CertChainPolicyPara{
		ExtraPolicyPara: (syscall.Pointer)(unsafe.Pointer(sslPara)),
	}
	para.Size = uint32(unsafe.Sizeof(*para))

	status := syscall.CertChainPolicyStatus{}
	err = syscall.CertVerifyCertificateChainPolicy(syscall.CERT_CHAIN_POLICY_SSL, chainCtx, para, &status)
	if err != nil {
		return err
	}

	// TODO(mkrautz): use the lChainIndex and lElementIndex fields
	// of the CertChainPolicyStatus to provide proper context, instead
	// using c.
	if status.Error != 0 {
		switch status.Error {
		case syscall.CERT_E_EXPIRED:
			return CertificateInvalidError{c, Expired, ""}
		case syscall.CERT_E_CN_NO_MATCH:
			return HostnameError{c, opts.DNSName}
		case syscall.CERT_E_UNTRUSTEDROOT:
			return UnknownAuthorityError{c, nil, nil}
		default:
			return UnknownAuthorityError{c, nil, nil}
		}
	}

	return nil
}

// windowsExtKeyUsageOIDs are the C NUL-terminated string representations of the
// OIDs for use with the Windows API.
var windowsExtKeyUsageOIDs = make(map[ExtKeyUsage][]byte, len(extKeyUsageOIDs))

func init() {
	for _, eku := range extKeyUsageOIDs {
		windowsExtKeyUsageOIDs[eku.extKeyUsage] = []byte(eku.oid.String() + "\x00")
	}
}

func verifyChain(c *Certificate, chainCtx *syscall.CertChainContext, opts *VerifyOptions) (chain []*Certificate, err error) {
	err = checkChainTrustStatus(c, chainCtx)
	if err != nil {
		return nil, err
	}

	if opts != nil && len(opts.DNSName) > 0 {
		err = checkChainSSLServerPolicy(c, chainCtx, opts)
		if err != nil {
			return nil, err
		}
	}

	chain, err = extractSimpleChain(chainCtx.Chains, int(chainCtx.ChainCount))
	if err != nil {
		return nil, err
	}
	if len(chain) == 0 {
		return nil, errors.New("x509: internal error: system verifier returned an empty chain")
	}

	// Mitigate CVE-2020-0601, where the Windows system verifier might be
	// tricked into using custom curve parameters for a trusted root, by
	// double-checking all ECDSA signatures. If the system was tricked into
	// using spoofed parameters, the signature will be invalid for the correct
	// ones we parsed. (We don't support custom curves ourselves.)
	for i, parent := range chain[1:] {
		if parent.PublicKeyAlgorithm != ECDSA {
			continue
		}
		if err := parent.CheckSignature(chain[i].SignatureAlgorithm,
			chain[i].RawTBSCertificate, chain[i].Signature); err != nil {
			return nil, err
		}
	}
	return chain, nil
}

// systemVerify is like Verify, except that it uses CryptoAPI calls
// to build certificate chains and verify them.
func (c *Certificate) systemVerify(opts *VerifyOptions) (chains [][]*Certificate, err error) {
	storeCtx, err := createStoreContext(c, opts)
	if err != nil {
		return nil, err
	}
	defer syscall.CertFreeCertificateContext(storeCtx)

	para := new(syscall.CertChainPara)
	para.Size = uint32(unsafe.Sizeof(*para))

	keyUsages := opts.KeyUsages
	if len(keyUsages) == 0 {
		keyUsages = []ExtKeyUsage{ExtKeyUsageServerAuth}
	}
	oids := make([]*byte, 0, len(keyUsages))
	for _, eku := range keyUsages {
		if eku == ExtKeyUsageAny {
			oids = nil
			break
		}
		if oid, ok := windowsExtKeyUsageOIDs[eku]; ok {
			oids = append(oids, &oid[0])
		}
	}
	if oids != nil {
		para.RequestedUsage.Type = syscall.USAGE_MATCH_TYPE_OR
		para.RequestedUsage.Usage.Length = uint32(len(oids))
		para.RequestedUsage.Usage.UsageIdentifiers = &oids[0]
	} else {
		para.RequestedUsage.Type = syscall.USAGE_MATCH_TYPE_AND
		para.RequestedUsage.Usage.Length = 0
		para.RequestedUsage.Usage.UsageIdentifiers = nil
	}

	var verifyTime *syscall.Filetime
	if opts != nil && !opts.CurrentTime.IsZero() {
		ft := syscall.NsecToFiletime(opts.CurrentTime.UnixNano())
		verifyTime = &ft
	}

	// The default is to return only the highest quality chain,
	// setting this flag will add additional lower quality contexts.
	// These are returned in the LowerQualityChains field.
	const CERT_CHAIN_RETURN_LOWER_QUALITY_CONTEXTS = 0x00000080

	// CertGetCertificateChain will traverse Windows's root stores in an attempt to build a verified certificate chain
	var topCtx *syscall.CertChainContext
	err = syscall.CertGetCertificateChain(syscall.Handle(0), storeCtx, verifyTime, storeCtx.Store, para, CERT_CHAIN_RETURN_LOWER_QUALITY_CONTEXTS, 0, &topCtx)
	if err != nil {
		return nil, err
	}
	defer syscall.CertFreeCertificateChain(topCtx)

	chain, topErr := verifyChain(c, topCtx, opts)
	if topErr == nil {
		chains = append(chains, chain)
	}

	if lqCtxCount := topCtx.LowerQualityChainCount; lqCtxCount > 0 {
		lqCtxs := unsafe.Slice(topCtx.LowerQualityChains, lqCtxCount)
		for _, ctx := range lqCtxs {
			chain, err := verifyChain(c, ctx, opts)
			if err == nil {
				chains = append(chains, chain)
			}
		}
	}

	if len(chains) == 0 {
		// Return the error from the highest quality context.
		return nil, topErr
	}

	return chains, nil
}
```