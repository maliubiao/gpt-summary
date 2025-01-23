Response:
Let's break down the request and the provided Go code snippet.

**Request Analysis:**

The core request is to understand the functionality of the Go code in `go/src/crypto/x509/verify_test.go`. The decomposed requirements are:

1. **List Functionality:**  Provide a summary of what the code does.
2. **Infer Go Feature:** If possible, deduce the broader Go feature being tested.
3. **Go Code Example:** Illustrate the inferred Go feature with a code example (including assumed inputs and outputs if applicable).
4. **Command-Line Arguments:** Detail any command-line parameter handling.
5. **Common Mistakes:** Point out potential pitfalls for users of this functionality.
6. **Part 1 Summary:** Specifically summarize the functionality of this *first part* of the code.

**Code Analysis (Initial Scan):**

* **Package and Imports:**  The code belongs to the `x509` package and imports standard Go crypto libraries (`crypto`, `crypto/ecdsa`, `crypto/elliptic`, `crypto/rand`, `crypto/x509/pkix`), encoding libraries (`encoding/asn1`, `encoding/pem`), standard libraries (`errors`, `fmt`, `math/big`, `os`, `runtime`, `slices`, `strconv`, `strings`, `testing`, `time`), and an internal testing utility (`internal/testenv`). This immediately suggests testing related to X.509 certificate verification.
* **`verifyTest` struct:** This structure defines the parameters for individual test cases. Key fields include `leaf` (the certificate being tested), `intermediates` (intermediate certificates), `roots` (root certificates), `currentTime`, `dnsName`, and `expectedChains`. The presence of `errorCallback` strongly indicates testing for both successful and failed verification scenarios.
* **`verifyTests` variable:** This slice holds a series of `verifyTest` instances, each representing a distinct verification scenario (e.g., "Valid", "HostnameMismatch", "Expired").
* **Helper Functions (`expectHostnameError`, `expectExpired`, etc.):** These functions are designed to assert the type and content of expected errors during verification.
* **`certificateFromPEM` function:**  This utility parses a PEM-encoded certificate.
* **`testVerify` function:** This is the core test function. It takes a `verifyTest` and a boolean `useSystemRoots` as input. It sets up `VerifyOptions`, parses certificates, calls `leaf.Verify(opts)`, and then compares the resulting certificate chains against the `expectedChains`. It also handles error conditions.
* **`TestGoVerify` and `TestSystemVerify` functions:** These are the actual Go test functions that iterate through `verifyTests` and call `testVerify` with and without using system root certificates.
* **Certificate Constants:** The code defines many string constants representing PEM-encoded certificates (e.g., `gtsIntermediate`, `gtsRoot`, `googleLeaf`). These are the input data for the tests.

**Deductions and Planning:**

1. **Functionality:** The primary function is to test the X.509 certificate verification process in Go's `crypto/x509` package. This involves checking if a given certificate (the "leaf") can be successfully validated against a set of intermediate and root certificates, considering factors like hostname matching, expiration, key usage, and name constraints.
2. **Go Feature:** The code tests the `Verify` method of the `Certificate` type and the associated `VerifyOptions` struct in the `crypto/x509` package.
3. **Code Example:** I can create a simple example demonstrating how to use `x509.ParseCertificates`, `x509.NewCertPool`, append certificates, and call `Verify`.
4. **Command-Line Arguments:**  Based on the code, there are no direct command-line arguments being processed within this file. The tests are likely executed using the standard `go test` command.
5. **Common Mistakes:**  I need to think about common errors when working with certificate verification, such as incorrect root CA setup, hostname mismatches, and not handling potential errors.
6. **Part 1 Summary:** This specific part of the code defines the test infrastructure and test cases for X.509 certificate verification. It sets up various scenarios with different certificates, expected outcomes (success or specific errors), and verification options.

**Constraint Checklist & Confidence Score:**

*列举一下它的功能: Yes.
*如果你能推理出它是什么go语言功能的实现: Yes.
*请用go代码举例说明: Yes.
*如果涉及代码推理，需要带上假设的输入与输出: Yes.
*如果涉及命令行参数的具体处理，请详细介绍一下: Yes (will state that there are none directly in this file).
*如果有哪些使用者易犯错的点，请举例说明: Yes.
*请用中文回答: Yes.
*这是第1部分，共4部分，请归纳一下它的功能: Yes.

Confidence Score: 5/5  I have a good understanding of the code and can address all parts of the request.

**Mental Sandbox (Thinking through potential issues):**

* **Error Handling:**  The `errorCallback` functions are interesting. They allow specific error checks, which is crucial for comprehensive testing.
* **System Roots:** The `useSystemRoots` flag in `testVerify` and the separate `TestSystemVerify` function indicate testing against both custom and system-provided root certificates.
* **`systemLax` and `systemSkip`:** These flags suggest that the behavior when using system root certificates might differ across operating systems or have known inconsistencies, which the tests need to accommodate.
* **PEM Decoding:** The `certificateFromPEM` function highlights the importance of correctly decoding certificates from PEM format.

Strategizing complete. I will now proceed to generate the response based on these insights.
这段代码是 Go 语言标准库 `crypto/x509` 包中 `verify_test.go` 文件的一部分。它的主要功能是 **测试 X.509 证书的验证逻辑**。

更具体地说，这段代码定义了一系列的测试用例，用于验证 `crypto/x509` 包中的证书验证功能是否按预期工作。它涵盖了各种场景，包括：

1. **验证成功的场景:**  例如，一个有效的证书链，主机名匹配等。
2. **验证失败的场景:** 例如，证书过期、主机名不匹配、缺少中间证书、根证书不在信任列表中、使用了不被允许的密钥用途扩展 (Extended Key Usage, EKU) 等。
3. **不同类型的证书链:** 包括带有中间证书和只有根证书的情况。
4. **不同的证书配置:** 例如，包含使用者可选名称 (Subject Alternative Name, SANs) 的证书、包含名称约束的证书、使用不同哈希算法签名的证书等。
5. **使用自定义根证书和系统根证书两种情况进行验证。**

**它是什么Go语言功能的实现？**

这段代码主要测试的是 `crypto/x59` 包中 `Certificate` 类型的 `Verify` 方法以及相关的 `VerifyOptions` 结构体。  `Verify` 方法用于验证一个证书链是否有效，`VerifyOptions` 则用于指定验证过程中的各种参数，例如信任的根证书、当前时间、期望的主机名等。

**Go 代码举例说明:**

假设我们有三个 PEM 格式的证书：一个叶子证书 (`leafCertPEM`)，一个中间证书 (`intermediateCertPEM`)，和一个根证书 (`rootCertPEM`)。我们可以使用以下 Go 代码来验证叶子证书：

```go
package main

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"time"
)

const leafCertPEM = `-----BEGIN CERTIFICATE-----
... (叶子证书内容) ...
-----END CERTIFICATE-----`

const intermediateCertPEM = `-----BEGIN CERTIFICATE-----
... (中间证书内容) ...
-----END CERTIFICATE-----`

const rootCertPEM = `-----BEGIN CERTIFICATE-----
... (根证书内容) ...
-----END CERTIFICATE-----`

func main() {
	// 解析叶子证书
	block, _ := pem.Decode([]byte(leafCertPEM))
	if block == nil {
		panic("failed to decode leaf certificate PEM")
	}
	leafCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		panic(err)
	}

	// 解析中间证书
	block, _ = pem.Decode([]byte(intermediateCertPEM))
	if block == nil {
		panic("failed to decode intermediate certificate PEM")
	}
	intermediateCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		panic(err)
	}

	// 解析根证书
	block, _ = pem.Decode([]byte(rootCertPEM))
	if block == nil {
		panic("failed to decode root certificate PEM")
	}
	rootCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		panic(err)
	}

	// 创建证书池并添加根证书和中间证书
	roots := x509.NewCertPool()
	roots.AddCert(rootCert)

	intermediates := x509.NewCertPool()
	intermediates.AddCert(intermediateCert)

	// 配置验证选项
	opts := x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		CurrentTime:   time.Now(), // 使用当前时间进行验证
		DNSName:       "www.example.com", // 假设叶子证书是给 www.example.com 颁发的
	}

	// 执行验证
	chains, err := leafCert.Verify(opts)
	if err != nil {
		fmt.Println("证书验证失败:", err)
	} else {
		fmt.Println("证书验证成功，发现以下证书链:")
		for _, chain := range chains {
			fmt.Println("  证书链:")
			for _, cert := range chain {
				fmt.Printf("    主题: %s\n", cert.Subject.CommonName)
			}
		}
	}
}
```

**假设的输入与输出:**

* **输入:**
    * `leafCertPEM`: 一个有效的、为 `www.example.com` 颁发的叶子证书的 PEM 编码。
    * `intermediateCertPEM`: 颁发该叶子证书的中间证书的 PEM 编码。
    * `rootCertPEM`: 颁发该中间证书的根证书的 PEM 编码。
* **输出:**
    ```
    证书验证成功，发现以下证书链:
      证书链:
        主题: www.example.com
        主题: <中间证书的 Common Name>
        主题: <根证书的 Common Name>
    ```

如果 `opts.DNSName` 设置为与叶子证书不匹配的名称，例如 `"www.google.com"`，则输出可能是：

```
证书验证失败: x509: certificate is valid for www.example.com, not www.google.com
```

**命令行参数的具体处理:**

在这段代码中，没有直接处理命令行参数。  `verify_test.go` 文件是一个测试文件，它通常通过 Go 的测试工具 `go test` 来运行。  `go test` 命令本身可以接受一些参数，例如指定要运行的测试用例或显示更详细的输出，但这部分代码本身并不解析这些参数。

**使用者易犯错的点:**

在实际使用 `crypto/x509` 包进行证书验证时，使用者容易犯以下错误：

1. **未正确加载根证书:**  如果提供的 `VerifyOptions` 中的 `Roots` 为空或者不包含信任的根证书，那么任何非自签名的证书验证都会失败，并抛出 `x509: certificate signed by unknown authority` 错误。
2. **主机名不匹配:**  如果在 `VerifyOptions` 中指定了 `DNSName`，但叶子证书的 `Subject` 或 `SubjectAlternativeName` 中不包含该名称，则验证会失败。
3. **时间不正确:**  如果系统时间与证书的有效期不符（例如，系统时间早于证书的 `NotBefore` 或晚于 `NotAfter`），则验证会失败。
4. **缺少中间证书:**  如果证书链中缺少必要的中间证书，且这些证书不在系统的信任存储中，验证也会失败。
5. **未处理错误:**  在调用 `leafCert.Verify(opts)` 后，必须检查返回的 `error`，并根据错误类型进行相应的处理。忽略错误可能导致安全漏洞。
6. **混淆证书池的使用:**  容易混淆 `Roots` 和 `Intermediates` 的使用。根证书应该添加到 `Roots` 池中，而中间证书应该添加到 `Intermediates` 池中。
7. **依赖 Common Name 进行主机名验证:**  虽然一些旧的证书可能只包含 Common Name，但现代证书更推荐使用 Subject Alternative Name (SANs) 来指定证书适用的主机名。依赖 Common Name 可能导致验证失败。

**功能归纳（第1部分）:**

这段代码（作为 `verify_test.go` 的一部分）的主要功能是 **定义了用于测试 Go 语言 `crypto/x509` 包中证书验证功能的各种测试用例和辅助函数**。它通过构建不同的证书链和验证选项，模拟各种成功和失败的场景，以确保证书验证逻辑的正确性和健壮性。 这部分代码的核心是 `verifyTests` 变量，它包含了多个 `verifyTest` 结构体的实例，每个实例代表一个特定的验证场景及其预期结果。同时，它定义了一些辅助函数，用于解析 PEM 格式的证书以及检查验证过程中出现的特定错误类型。

### 提示词
```
这是路径为go/src/crypto/x509/verify_test.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第1部分，共4部分，请归纳一下它的功能
```

### 源代码
```go
// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package x509

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"internal/testenv"
	"math/big"
	"os"
	"os/exec"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"
)

type verifyTest struct {
	name          string
	leaf          string
	intermediates []string
	roots         []string
	currentTime   int64
	dnsName       string
	systemSkip    bool
	systemLax     bool
	keyUsages     []ExtKeyUsage

	errorCallback  func(*testing.T, error)
	expectedChains [][]string
}

var verifyTests = []verifyTest{
	{
		name:          "Valid",
		leaf:          googleLeaf,
		intermediates: []string{gtsIntermediate},
		roots:         []string{gtsRoot},
		currentTime:   1677615892,
		dnsName:       "www.google.com",

		expectedChains: [][]string{
			{"www.google.com", "GTS CA 1C3", "GTS Root R1"},
		},
	},
	{
		name:          "Valid (fqdn)",
		leaf:          googleLeaf,
		intermediates: []string{gtsIntermediate},
		roots:         []string{gtsRoot},
		currentTime:   1677615892,
		dnsName:       "www.google.com.",

		expectedChains: [][]string{
			{"www.google.com", "GTS CA 1C3", "GTS Root R1"},
		},
	},
	{
		name:          "MixedCase",
		leaf:          googleLeaf,
		intermediates: []string{gtsIntermediate},
		roots:         []string{gtsRoot},
		currentTime:   1677615892,
		dnsName:       "WwW.GooGLE.coM",

		expectedChains: [][]string{
			{"www.google.com", "GTS CA 1C3", "GTS Root R1"},
		},
	},
	{
		name:          "HostnameMismatch",
		leaf:          googleLeaf,
		intermediates: []string{gtsIntermediate},
		roots:         []string{gtsRoot},
		currentTime:   1677615892,
		dnsName:       "www.example.com",

		errorCallback: expectHostnameError("certificate is valid for"),
	},
	{
		name:          "IPMissing",
		leaf:          googleLeaf,
		intermediates: []string{gtsIntermediate},
		roots:         []string{gtsRoot},
		currentTime:   1677615892,
		dnsName:       "1.2.3.4",

		errorCallback: expectHostnameError("doesn't contain any IP SANs"),
	},
	{
		name:          "Expired",
		leaf:          googleLeaf,
		intermediates: []string{gtsIntermediate},
		roots:         []string{gtsRoot},
		currentTime:   1,
		dnsName:       "www.example.com",

		errorCallback: expectExpired,
	},
	{
		name:        "MissingIntermediate",
		leaf:        googleLeaf,
		roots:       []string{gtsRoot},
		currentTime: 1677615892,
		dnsName:     "www.google.com",

		// Skip when using systemVerify, since Windows
		// *will* find the missing intermediate cert.
		systemSkip:    true,
		errorCallback: expectAuthorityUnknown,
	},
	{
		name:          "RootInIntermediates",
		leaf:          googleLeaf,
		intermediates: []string{gtsRoot, gtsIntermediate},
		roots:         []string{gtsRoot},
		currentTime:   1677615892,
		dnsName:       "www.google.com",

		expectedChains: [][]string{
			{"www.google.com", "GTS CA 1C3", "GTS Root R1"},
		},
		// CAPI doesn't build the chain with the duplicated GeoTrust
		// entry so the results don't match.
		systemLax: true,
	},
	{
		name:          "InvalidHash",
		leaf:          googleLeafWithInvalidHash,
		intermediates: []string{gtsIntermediate},
		roots:         []string{gtsRoot},
		currentTime:   1677615892,
		dnsName:       "www.google.com",

		// The specific error message may not occur when using system
		// verification.
		systemLax:     true,
		errorCallback: expectHashError,
	},
	// EKULeaf tests use an unconstrained chain leading to a leaf certificate
	// with an E-mail Protection EKU but not a Server Auth one, checking that
	// the EKUs on the leaf are enforced.
	{
		name:          "EKULeaf",
		leaf:          smimeLeaf,
		intermediates: []string{smimeIntermediate},
		roots:         []string{smimeRoot},
		currentTime:   1594673418,

		errorCallback: expectUsageError,
	},
	{
		name:          "EKULeafExplicit",
		leaf:          smimeLeaf,
		intermediates: []string{smimeIntermediate},
		roots:         []string{smimeRoot},
		currentTime:   1594673418,
		keyUsages:     []ExtKeyUsage{ExtKeyUsageServerAuth},

		errorCallback: expectUsageError,
	},
	{
		name:          "EKULeafValid",
		leaf:          smimeLeaf,
		intermediates: []string{smimeIntermediate},
		roots:         []string{smimeRoot},
		currentTime:   1594673418,
		keyUsages:     []ExtKeyUsage{ExtKeyUsageEmailProtection},

		expectedChains: [][]string{
			{"CORPORATIVO FICTICIO ACTIVO", "EAEko Herri Administrazioen CA - CA AAPP Vascas (2)", "IZENPE S.A."},
		},
	},
	{
		// Check that a name constrained intermediate works even when
		// it lists multiple constraints.
		name:          "MultipleConstraints",
		leaf:          nameConstraintsLeaf,
		intermediates: []string{nameConstraintsIntermediate1, nameConstraintsIntermediate2},
		roots:         []string{globalSignRoot},
		currentTime:   1524771953,
		dnsName:       "udctest.ads.vt.edu",

		expectedChains: [][]string{
			{
				"udctest.ads.vt.edu",
				"Virginia Tech Global Qualified Server CA",
				"Trusted Root CA SHA256 G2",
				"GlobalSign",
			},
		},
	},
	{
		// Check that SHA-384 intermediates (which are popping up)
		// work.
		name:          "SHA-384",
		leaf:          trustAsiaLeaf,
		intermediates: []string{trustAsiaSHA384Intermediate},
		roots:         []string{digicertRoot},
		currentTime:   1558051200,
		dnsName:       "tm.cn",

		// CryptoAPI can find alternative validation paths.
		systemLax: true,

		expectedChains: [][]string{
			{
				"tm.cn",
				"TrustAsia ECC OV TLS Pro CA",
				"DigiCert Global Root CA",
			},
		},
	},
	{
		// Putting a certificate as a root directly should work as a
		// way of saying “exactly this”.
		name:        "LeafInRoots",
		leaf:        selfSigned,
		roots:       []string{selfSigned},
		currentTime: 1471624472,
		dnsName:     "foo.example",
		systemSkip:  true, // does not chain to a system root

		expectedChains: [][]string{
			{"Acme Co"},
		},
	},
	{
		// Putting a certificate as a root directly should not skip
		// other checks however.
		name:        "LeafInRootsInvalid",
		leaf:        selfSigned,
		roots:       []string{selfSigned},
		currentTime: 1471624472,
		dnsName:     "notfoo.example",
		systemSkip:  true, // does not chain to a system root

		errorCallback: expectHostnameError("certificate is valid for"),
	},
	{
		// An X.509 v1 certificate should not be accepted as an
		// intermediate.
		name:          "X509v1Intermediate",
		leaf:          x509v1TestLeaf,
		intermediates: []string{x509v1TestIntermediate},
		roots:         []string{x509v1TestRoot},
		currentTime:   1481753183,
		systemSkip:    true, // does not chain to a system root

		errorCallback: expectNotAuthorizedError,
	},
	{
		name:        "IgnoreCNWithSANs",
		leaf:        ignoreCNWithSANLeaf,
		dnsName:     "foo.example.com",
		roots:       []string{ignoreCNWithSANRoot},
		currentTime: 1486684488,
		systemSkip:  true, // does not chain to a system root

		errorCallback: expectHostnameError("certificate is not valid for any names"),
	},
	{
		// Test that excluded names are respected.
		name:          "ExcludedNames",
		leaf:          excludedNamesLeaf,
		dnsName:       "bender.local",
		intermediates: []string{excludedNamesIntermediate},
		roots:         []string{excludedNamesRoot},
		currentTime:   1486684488,
		systemSkip:    true, // does not chain to a system root

		errorCallback: expectNameConstraintsError,
	},
	{
		// Test that unknown critical extensions in a leaf cause a
		// verify error.
		name:          "CriticalExtLeaf",
		leaf:          criticalExtLeafWithExt,
		intermediates: []string{criticalExtIntermediate},
		roots:         []string{criticalExtRoot},
		currentTime:   1486684488,
		systemSkip:    true, // does not chain to a system root

		errorCallback: expectUnhandledCriticalExtension,
	},
	{
		// Test that unknown critical extensions in an intermediate
		// cause a verify error.
		name:          "CriticalExtIntermediate",
		leaf:          criticalExtLeaf,
		intermediates: []string{criticalExtIntermediateWithExt},
		roots:         []string{criticalExtRoot},
		currentTime:   1486684488,
		systemSkip:    true, // does not chain to a system root

		errorCallback: expectUnhandledCriticalExtension,
	},
	{
		name:        "ValidCN",
		leaf:        validCNWithoutSAN,
		dnsName:     "foo.example.com",
		roots:       []string{invalidCNRoot},
		currentTime: 1540000000,
		systemSkip:  true, // does not chain to a system root

		errorCallback: expectHostnameError("certificate relies on legacy Common Name field"),
	},
	{
		// A certificate with an AKID should still chain to a parent without SKID.
		// See Issue 30079.
		name:        "AKIDNoSKID",
		leaf:        leafWithAKID,
		roots:       []string{rootWithoutSKID},
		currentTime: 1550000000,
		dnsName:     "example",
		systemSkip:  true, // does not chain to a system root

		expectedChains: [][]string{
			{"Acme LLC", "Acme Co"},
		},
	},
	{
		// When there are two parents, one with an incorrect subject but matching SKID
		// and one with a correct subject but missing SKID, the latter should be
		// considered as a possible parent.
		leaf:        leafMatchingAKIDMatchingIssuer,
		roots:       []string{rootMatchingSKIDMismatchingSubject, rootMismatchingSKIDMatchingSubject},
		currentTime: 1550000000,
		dnsName:     "example",
		systemSkip:  true,

		expectedChains: [][]string{
			{"Leaf", "Root B"},
		},
	},
}

func expectHostnameError(msg string) func(*testing.T, error) {
	return func(t *testing.T, err error) {
		if _, ok := err.(HostnameError); !ok {
			t.Fatalf("error was not a HostnameError: %v", err)
		}
		if !strings.Contains(err.Error(), msg) {
			t.Fatalf("HostnameError did not contain %q: %v", msg, err)
		}
	}
}

func expectExpired(t *testing.T, err error) {
	if inval, ok := err.(CertificateInvalidError); !ok || inval.Reason != Expired {
		t.Fatalf("error was not Expired: %v", err)
	}
}

func expectUsageError(t *testing.T, err error) {
	if inval, ok := err.(CertificateInvalidError); !ok || inval.Reason != IncompatibleUsage {
		t.Fatalf("error was not IncompatibleUsage: %v", err)
	}
}

func expectAuthorityUnknown(t *testing.T, err error) {
	e, ok := err.(UnknownAuthorityError)
	if !ok {
		t.Fatalf("error was not UnknownAuthorityError: %v", err)
	}
	if e.Cert == nil {
		t.Fatalf("error was UnknownAuthorityError, but missing Cert: %v", err)
	}
}

func expectHashError(t *testing.T, err error) {
	if err == nil {
		t.Fatalf("no error resulted from invalid hash")
	}
	if expected := "algorithm unimplemented"; !strings.Contains(err.Error(), expected) {
		t.Fatalf("error resulting from invalid hash didn't contain '%s', rather it was: %v", expected, err)
	}
}

func expectNameConstraintsError(t *testing.T, err error) {
	if inval, ok := err.(CertificateInvalidError); !ok || inval.Reason != CANotAuthorizedForThisName {
		t.Fatalf("error was not a CANotAuthorizedForThisName: %v", err)
	}
}

func expectNotAuthorizedError(t *testing.T, err error) {
	if inval, ok := err.(CertificateInvalidError); !ok || inval.Reason != NotAuthorizedToSign {
		t.Fatalf("error was not a NotAuthorizedToSign: %v", err)
	}
}

func expectUnhandledCriticalExtension(t *testing.T, err error) {
	if _, ok := err.(UnhandledCriticalExtension); !ok {
		t.Fatalf("error was not an UnhandledCriticalExtension: %v", err)
	}
}

func certificateFromPEM(pemBytes string) (*Certificate, error) {
	block, _ := pem.Decode([]byte(pemBytes))
	if block == nil {
		return nil, errors.New("failed to decode PEM")
	}
	return ParseCertificate(block.Bytes)
}

func testVerify(t *testing.T, test verifyTest, useSystemRoots bool) {
	opts := VerifyOptions{
		Intermediates: NewCertPool(),
		DNSName:       test.dnsName,
		CurrentTime:   time.Unix(test.currentTime, 0),
		KeyUsages:     test.keyUsages,
	}

	if !useSystemRoots {
		opts.Roots = NewCertPool()
		for j, root := range test.roots {
			ok := opts.Roots.AppendCertsFromPEM([]byte(root))
			if !ok {
				t.Fatalf("failed to parse root #%d", j)
			}
		}
	}

	for j, intermediate := range test.intermediates {
		ok := opts.Intermediates.AppendCertsFromPEM([]byte(intermediate))
		if !ok {
			t.Fatalf("failed to parse intermediate #%d", j)
		}
	}

	leaf, err := certificateFromPEM(test.leaf)
	if err != nil {
		t.Fatalf("failed to parse leaf: %v", err)
	}

	chains, err := leaf.Verify(opts)

	if test.errorCallback == nil && err != nil {
		if runtime.GOOS == "windows" && strings.HasSuffix(testenv.Builder(), "-2008") && err.Error() == "x509: certificate signed by unknown authority" {
			testenv.SkipFlaky(t, 19564)
		}
		t.Fatalf("unexpected error: %v", err)
	}
	if test.errorCallback != nil {
		if useSystemRoots && test.systemLax {
			if err == nil {
				t.Fatalf("expected error")
			}
		} else {
			test.errorCallback(t, err)
		}
	}

	doesMatch := func(expectedChain []string, chain []*Certificate) bool {
		if len(chain) != len(expectedChain) {
			return false
		}

		for k, cert := range chain {
			if !strings.Contains(nameToKey(&cert.Subject), expectedChain[k]) {
				return false
			}
		}
		return true
	}

	// Every expected chain should match one (or more) returned chain. We tolerate multiple
	// matches, as due to root store semantics it is plausible that (at least on the system
	// verifiers) multiple identical (looking) chains may be returned when two roots with the
	// same subject are present.
	for _, expectedChain := range test.expectedChains {
		var match bool
		for _, chain := range chains {
			if doesMatch(expectedChain, chain) {
				match = true
				break
			}
		}

		if !match {
			t.Errorf("No match found for %v", expectedChain)
		}
	}

	// Every returned chain should match 1 expected chain (or <2 if testing against the system)
	for _, chain := range chains {
		nMatched := 0
		for _, expectedChain := range test.expectedChains {
			if doesMatch(expectedChain, chain) {
				nMatched++
			}
		}
		// Allow additional unknown chains if systemLax is set
		if nMatched == 0 && test.systemLax == false || nMatched > 1 {
			t.Errorf("Got %v matches for chain %v", nMatched, chainToDebugString(chain))
			for _, expectedChain := range test.expectedChains {
				if doesMatch(expectedChain, chain) {
					t.Errorf("\t matched %v", expectedChain)
				}
			}
		}
	}
}

func TestGoVerify(t *testing.T) {
	for _, test := range verifyTests {
		t.Run(test.name, func(t *testing.T) {
			testVerify(t, test, false)
		})
	}
}

func TestSystemVerify(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skipf("skipping verify test using system APIs on %q", runtime.GOOS)
	}

	for _, test := range verifyTests {
		t.Run(test.name, func(t *testing.T) {
			if test.systemSkip {
				t.SkipNow()
			}
			testVerify(t, test, true)
		})
	}
}

func chainToDebugString(chain []*Certificate) string {
	var chainStr string
	for _, cert := range chain {
		if len(chainStr) > 0 {
			chainStr += " -> "
		}
		chainStr += nameToKey(&cert.Subject)
	}
	return chainStr
}

func nameToKey(name *pkix.Name) string {
	return strings.Join(name.Country, ",") + "/" + strings.Join(name.Organization, ",") + "/" + strings.Join(name.OrganizationalUnit, ",") + "/" + name.CommonName
}

const gtsIntermediate = `-----BEGIN CERTIFICATE-----
MIIFljCCA36gAwIBAgINAgO8U1lrNMcY9QFQZjANBgkqhkiG9w0BAQsFADBHMQsw
CQYDVQQGEwJVUzEiMCAGA1UEChMZR29vZ2xlIFRydXN0IFNlcnZpY2VzIExMQzEU
MBIGA1UEAxMLR1RTIFJvb3QgUjEwHhcNMjAwODEzMDAwMDQyWhcNMjcwOTMwMDAw
MDQyWjBGMQswCQYDVQQGEwJVUzEiMCAGA1UEChMZR29vZ2xlIFRydXN0IFNlcnZp
Y2VzIExMQzETMBEGA1UEAxMKR1RTIENBIDFDMzCCASIwDQYJKoZIhvcNAQEBBQAD
ggEPADCCAQoCggEBAPWI3+dijB43+DdCkH9sh9D7ZYIl/ejLa6T/belaI+KZ9hzp
kgOZE3wJCor6QtZeViSqejOEH9Hpabu5dOxXTGZok3c3VVP+ORBNtzS7XyV3NzsX
lOo85Z3VvMO0Q+sup0fvsEQRY9i0QYXdQTBIkxu/t/bgRQIh4JZCF8/ZK2VWNAcm
BA2o/X3KLu/qSHw3TT8An4Pf73WELnlXXPxXbhqW//yMmqaZviXZf5YsBvcRKgKA
gOtjGDxQSYflispfGStZloEAoPtR28p3CwvJlk/vcEnHXG0g/Zm0tOLKLnf9LdwL
tmsTDIwZKxeWmLnwi/agJ7u2441Rj72ux5uxiZ0CAwEAAaOCAYAwggF8MA4GA1Ud
DwEB/wQEAwIBhjAdBgNVHSUEFjAUBggrBgEFBQcDAQYIKwYBBQUHAwIwEgYDVR0T
AQH/BAgwBgEB/wIBADAdBgNVHQ4EFgQUinR/r4XN7pXNPZzQ4kYU83E1HScwHwYD
VR0jBBgwFoAU5K8rJnEaK0gnhS9SZizv8IkTcT4waAYIKwYBBQUHAQEEXDBaMCYG
CCsGAQUFBzABhhpodHRwOi8vb2NzcC5wa2kuZ29vZy9ndHNyMTAwBggrBgEFBQcw
AoYkaHR0cDovL3BraS5nb29nL3JlcG8vY2VydHMvZ3RzcjEuZGVyMDQGA1UdHwQt
MCswKaAnoCWGI2h0dHA6Ly9jcmwucGtpLmdvb2cvZ3RzcjEvZ3RzcjEuY3JsMFcG
A1UdIARQME4wOAYKKwYBBAHWeQIFAzAqMCgGCCsGAQUFBwIBFhxodHRwczovL3Br
aS5nb29nL3JlcG9zaXRvcnkvMAgGBmeBDAECATAIBgZngQwBAgIwDQYJKoZIhvcN
AQELBQADggIBAIl9rCBcDDy+mqhXlRu0rvqrpXJxtDaV/d9AEQNMwkYUuxQkq/BQ
cSLbrcRuf8/xam/IgxvYzolfh2yHuKkMo5uhYpSTld9brmYZCwKWnvy15xBpPnrL
RklfRuFBsdeYTWU0AIAaP0+fbH9JAIFTQaSSIYKCGvGjRFsqUBITTcFTNvNCCK9U
+o53UxtkOCcXCb1YyRt8OS1b887U7ZfbFAO/CVMkH8IMBHmYJvJh8VNS/UKMG2Yr
PxWhu//2m+OBmgEGcYk1KCTd4b3rGS3hSMs9WYNRtHTGnXzGsYZbr8w0xNPM1IER
lQCh9BIiAfq0g3GvjLeMcySsN1PCAJA/Ef5c7TaUEDu9Ka7ixzpiO2xj2YC/WXGs
Yye5TBeg2vZzFb8q3o/zpWwygTMD0IZRcZk0upONXbVRWPeyk+gB9lm+cZv9TSjO
z23HFtz30dZGm6fKa+l3D/2gthsjgx0QGtkJAITgRNOidSOzNIb2ILCkXhAd4FJG
AJ2xDx8hcFH1mt0G/FX0Kw4zd8NLQsLxdxP8c4CU6x+7Nz/OAipmsHMdMqUybDKw
juDEI/9bfU1lcKwrmz3O2+BtjjKAvpafkmO8l7tdufThcV4q5O8DIrGKZTqPwJNl
1IXNDw9bg1kWRxYtnCQ6yICmJhSFm/Y3m6xv+cXDBlHz4n/FsRC6UfTd
-----END CERTIFICATE-----`

const gtsRoot = `-----BEGIN CERTIFICATE-----
MIIFVzCCAz+gAwIBAgINAgPlk28xsBNJiGuiFzANBgkqhkiG9w0BAQwFADBHMQsw
CQYDVQQGEwJVUzEiMCAGA1UEChMZR29vZ2xlIFRydXN0IFNlcnZpY2VzIExMQzEU
MBIGA1UEAxMLR1RTIFJvb3QgUjEwHhcNMTYwNjIyMDAwMDAwWhcNMzYwNjIyMDAw
MDAwWjBHMQswCQYDVQQGEwJVUzEiMCAGA1UEChMZR29vZ2xlIFRydXN0IFNlcnZp
Y2VzIExMQzEUMBIGA1UEAxMLR1RTIFJvb3QgUjEwggIiMA0GCSqGSIb3DQEBAQUA
A4ICDwAwggIKAoICAQC2EQKLHuOhd5s73L+UPreVp0A8of2C+X0yBoJx9vaMf/vo
27xqLpeXo4xL+Sv2sfnOhB2x+cWX3u+58qPpvBKJXqeqUqv4IyfLpLGcY9vXmX7w
Cl7raKb0xlpHDU0QM+NOsROjyBhsS+z8CZDfnWQpJSMHobTSPS5g4M/SCYe7zUjw
TcLCeoiKu7rPWRnWr4+wB7CeMfGCwcDfLqZtbBkOtdh+JhpFAz2weaSUKK0Pfybl
qAj+lug8aJRT7oM6iCsVlgmy4HqMLnXWnOunVmSPlk9orj2XwoSPwLxAwAtcvfaH
szVsrBhQf4TgTM2S0yDpM7xSma8ytSmzJSq0SPly4cpk9+aCEI3oncKKiPo4Zor8
Y/kB+Xj9e1x3+naH+uzfsQ55lVe0vSbv1gHR6xYKu44LtcXFilWr06zqkUspzBmk
MiVOKvFlRNACzqrOSbTqn3yDsEB750Orp2yjj32JgfpMpf/VjsPOS+C12LOORc92
wO1AK/1TD7Cn1TsNsYqiA94xrcx36m97PtbfkSIS5r762DL8EGMUUXLeXdYWk70p
aDPvOmbsB4om3xPXV2V4J95eSRQAogB/mqghtqmxlbCluQ0WEdrHbEg8QOB+DVrN
VjzRlwW5y0vtOUucxD/SVRNuJLDWcfr0wbrM7Rv1/oFB2ACYPTrIrnqYNxgFlQID
AQABo0IwQDAOBgNVHQ8BAf8EBAMCAYYwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4E
FgQU5K8rJnEaK0gnhS9SZizv8IkTcT4wDQYJKoZIhvcNAQEMBQADggIBAJ+qQibb
C5u+/x6Wki4+omVKapi6Ist9wTrYggoGxval3sBOh2Z5ofmmWJyq+bXmYOfg6LEe
QkEzCzc9zolwFcq1JKjPa7XSQCGYzyI0zzvFIoTgxQ6KfF2I5DUkzps+GlQebtuy
h6f88/qBVRRiClmpIgUxPoLW7ttXNLwzldMXG+gnoot7TiYaelpkttGsN/H9oPM4
7HLwEXWdyzRSjeZ2axfG34arJ45JK3VmgRAhpuo+9K4l/3wV3s6MJT/KYnAK9y8J
ZgfIPxz88NtFMN9iiMG1D53Dn0reWVlHxYciNuaCp+0KueIHoI17eko8cdLiA6Ef
MgfdG+RCzgwARWGAtQsgWSl4vflVy2PFPEz0tv/bal8xa5meLMFrUKTX5hgUvYU/
Z6tGn6D/Qqc6f1zLXbBwHSs09dR2CQzreExZBfMzQsNhFRAbd03OIozUhfJFfbdT
6u9AWpQKXCBfTkBdYiJ23//OYb2MI3jSNwLgjt7RETeJ9r/tSQdirpLsQBqvFAnZ
0E6yove+7u7Y/9waLd64NnHi/Hm3lCXRSHNboTXns5lndcEZOitHTtNCjv0xyBZm
2tIMPNuzjsmhDYAPexZ3FL//2wmUspO8IFgV6dtxQ/PeEMMA3KgqlbbC1j+Qa3bb
bP6MvPJwNQzcmRk13NfIRmPVNnGuV/u3gm3c
-----END CERTIFICATE-----`

const googleLeaf = `-----BEGIN CERTIFICATE-----
MIIFUjCCBDqgAwIBAgIQERmRWTzVoz0SMeozw2RM3DANBgkqhkiG9w0BAQsFADBG
MQswCQYDVQQGEwJVUzEiMCAGA1UEChMZR29vZ2xlIFRydXN0IFNlcnZpY2VzIExM
QzETMBEGA1UEAxMKR1RTIENBIDFDMzAeFw0yMzAxMDIwODE5MTlaFw0yMzAzMjcw
ODE5MThaMBkxFzAVBgNVBAMTDnd3dy5nb29nbGUuY29tMIIBIjANBgkqhkiG9w0B
AQEFAAOCAQ8AMIIBCgKCAQEAq30odrKMT54TJikMKL8S+lwoCMT5geP0u9pWjk6a
wdB6i3kO+UE4ijCAmhbcZKeKaLnGJ38weZNwB1ayabCYyX7hDiC/nRcZU49LX5+o
55kDVaNn14YKkg2kCeX25HDxSwaOsNAIXKPTqiQL5LPvc4Twhl8HY51hhNWQrTEr
N775eYbixEULvyVLq5BLbCOpPo8n0/MTjQ32ku1jQq3GIYMJC/Rf2VW5doF6t9zs
KleflAN8OdKp0ME9OHg0T1P3yyb67T7n0SpisHbeG06AmQcKJF9g/9VPJtRf4l1Q
WRPDC+6JUqzXCxAGmIRGZ7TNMxPMBW/7DRX6w8oLKVNb0wIDAQABo4ICZzCCAmMw
DgYDVR0PAQH/BAQDAgWgMBMGA1UdJQQMMAoGCCsGAQUFBwMBMAwGA1UdEwEB/wQC
MAAwHQYDVR0OBBYEFBnboj3lf9+Xat4oEgo6ZtIMr8ZuMB8GA1UdIwQYMBaAFIp0
f6+Fze6VzT2c0OJGFPNxNR0nMGoGCCsGAQUFBwEBBF4wXDAnBggrBgEFBQcwAYYb
aHR0cDovL29jc3AucGtpLmdvb2cvZ3RzMWMzMDEGCCsGAQUFBzAChiVodHRwOi8v
cGtpLmdvb2cvcmVwby9jZXJ0cy9ndHMxYzMuZGVyMBkGA1UdEQQSMBCCDnd3dy5n
b29nbGUuY29tMCEGA1UdIAQaMBgwCAYGZ4EMAQIBMAwGCisGAQQB1nkCBQMwPAYD
VR0fBDUwMzAxoC+gLYYraHR0cDovL2NybHMucGtpLmdvb2cvZ3RzMWMzL1FPdkow
TjFzVDJBLmNybDCCAQQGCisGAQQB1nkCBAIEgfUEgfIA8AB2AHoyjFTYty22IOo4
4FIe6YQWcDIThU070ivBOlejUutSAAABhXHHOiUAAAQDAEcwRQIgBUkikUIXdo+S
3T8PP0/cvokhUlumRE3GRWGL4WRMLpcCIQDY+bwK384mZxyXGZ5lwNRTAPNzT8Fx
1+//nbaGK3BQMAB2AOg+0No+9QY1MudXKLyJa8kD08vREWvs62nhd31tBr1uAAAB
hXHHOfQAAAQDAEcwRQIgLoVydNfMFKV9IoZR+M0UuJ2zOqbxIRum7Sn9RMPOBGMC
IQD1/BgzCSDTvYvco6kpB6ifKSbg5gcb5KTnYxQYwRW14TANBgkqhkiG9w0BAQsF
AAOCAQEA2bQQu30e3OFu0bmvQHmcqYvXBu6tF6e5b5b+hj4O+Rn7BXTTmaYX3M6p
MsfRH4YVJJMB/dc3PROR2VtnKFC6gAZX+RKM6nXnZhIlOdmQnonS1ecOL19PliUd
VXbwKjXqAO0Ljd9y9oXaXnyPyHmUJNI5YXAcxE+XXiOZhcZuMYyWmoEKJQ/XlSga
zWfTn1IcKhA3IC7A1n/5bkkWD1Xi1mdWFQ6DQDMp//667zz7pKOgFMlB93aPDjvI
c78zEqNswn6xGKXpWF5xVwdFcsx9HKhJ6UAi2bQ/KQ1yb7LPUOR6wXXWrG1cLnNP
i8eNLnKL9PXQ+5SwJFCzfEhcIZuhzg==
-----END CERTIFICATE-----`

// googleLeafWithInvalidHash is the same as googleLeaf, but the signature
// algorithm in the certificate contains a nonsense OID.
const googleLeafWithInvalidHash = `-----BEGIN CERTIFICATE-----
MIIFUjCCBDqgAwIBAgIQERmRWTzVoz0SMeozw2RM3DANBgkqhkiG9w0BAQ4FADBG
MQswCQYDVQQGEwJVUzEiMCAGA1UEChMZR29vZ2xlIFRydXN0IFNlcnZpY2VzIExM
QzETMBEGA1UEAxMKR1RTIENBIDFDMzAeFw0yMzAxMDIwODE5MTlaFw0yMzAzMjcw
ODE5MThaMBkxFzAVBgNVBAMTDnd3dy5nb29nbGUuY29tMIIBIjANBgkqhkiG9w0B
AQEFAAOCAQ8AMIIBCgKCAQEAq30odrKMT54TJikMKL8S+lwoCMT5geP0u9pWjk6a
wdB6i3kO+UE4ijCAmhbcZKeKaLnGJ38weZNwB1ayabCYyX7hDiC/nRcZU49LX5+o
55kDVaNn14YKkg2kCeX25HDxSwaOsNAIXKPTqiQL5LPvc4Twhl8HY51hhNWQrTEr
N775eYbixEULvyVLq5BLbCOpPo8n0/MTjQ32ku1jQq3GIYMJC/Rf2VW5doF6t9zs
KleflAN8OdKp0ME9OHg0T1P3yyb67T7n0SpisHbeG06AmQcKJF9g/9VPJtRf4l1Q
WRPDC+6JUqzXCxAGmIRGZ7TNMxPMBW/7DRX6w8oLKVNb0wIDAQABo4ICZzCCAmMw
DgYDVR0PAQH/BAQDAgWgMBMGA1UdJQQMMAoGCCsGAQUFBwMBMAwGA1UdEwEB/wQC
MAAwHQYDVR0OBBYEFBnboj3lf9+Xat4oEgo6ZtIMr8ZuMB8GA1UdIwQYMBaAFIp0
f6+Fze6VzT2c0OJGFPNxNR0nMGoGCCsGAQUFBwEBBF4wXDAnBggrBgEFBQcwAYYb
aHR0cDovL29jc3AucGtpLmdvb2cvZ3RzMWMzMDEGCCsGAQUFBzAChiVodHRwOi8v
cGtpLmdvb2cvcmVwby9jZXJ0cy9ndHMxYzMuZGVyMBkGA1UdEQQSMBCCDnd3dy5n
b29nbGUuY29tMCEGA1UdIAQaMBgwCAYGZ4EMAQIBMAwGCisGAQQB1nkCBQMwPAYD
VR0fBDUwMzAxoC+gLYYraHR0cDovL2NybHMucGtpLmdvb2cvZ3RzMWMzL1FPdkow
TjFzVDJBLmNybDCCAQQGCisGAQQB1nkCBAIEgfUEgfIA8AB2AHoyjFTYty22IOo4
4FIe6YQWcDIThU070ivBOlejUutSAAABhXHHOiUAAAQDAEcwRQIgBUkikUIXdo+S
3T8PP0/cvokhUlumRE3GRWGL4WRMLpcCIQDY+bwK384mZxyXGZ5lwNRTAPNzT8Fx
1+//nbaGK3BQMAB2AOg+0No+9QY1MudXKLyJa8kD08vREWvs62nhd31tBr1uAAAB
hXHHOfQAAAQDAEcwRQIgLoVydNfMFKV9IoZR+M0UuJ2zOqbxIRum7Sn9RMPOBGMC
IQD1/BgzCSDTvYvco6kpB6ifKSbg5gcb5KTnYxQYwRW14TANBgkqhkiG9w0BAQ4F
AAOCAQEA2bQQu30e3OFu0bmvQHmcqYvXBu6tF6e5b5b+hj4O+Rn7BXTTmaYX3M6p
MsfRH4YVJJMB/dc3PROR2VtnKFC6gAZX+RKM6nXnZhIlOdmQnonS1ecOL19PliUd
VXbwKjXqAO0Ljd9y9oXaXnyPyHmUJNI5YXAcxE+XXiOZhcZuMYyWmoEKJQ/XlSga
zWfTn1IcKhA3IC7A1n/5bkkWD1Xi1mdWFQ6DQDMp//667zz7pKOgFMlB93aPDjvI
c78zEqNswn6xGKXpWF5xVwdFcsx9HKhJ6UAi2bQ/KQ1yb7LPUOR6wXXWrG1cLnNP
i8eNLnKL9PXQ+5SwJFCzfEhcIZuhzg==
-----END CERTIFICATE-----`

const smimeLeaf = `-----BEGIN CERTIFICATE-----
MIIIPDCCBiSgAwIBAgIQaMDxFS0pOMxZZeOBxoTJtjANBgkqhkiG9w0BAQsFADCB
nTELMAkGA1UEBhMCRVMxFDASBgNVBAoMC0laRU5QRSBTLkEuMTowOAYDVQQLDDFB
WlogWml1cnRhZ2lyaSBwdWJsaWtvYSAtIENlcnRpZmljYWRvIHB1YmxpY28gU0NB
MTwwOgYDVQQDDDNFQUVrbyBIZXJyaSBBZG1pbmlzdHJhemlvZW4gQ0EgLSBDQSBB
QVBQIFZhc2NhcyAoMikwHhcNMTcwNzEyMDg1MzIxWhcNMjEwNzEyMDg1MzIxWjCC
AQwxDzANBgNVBAoMBklaRU5QRTE4MDYGA1UECwwvWml1cnRhZ2lyaSBrb3Jwb3Jh
dGlib2EtQ2VydGlmaWNhZG8gY29ycG9yYXRpdm8xQzBBBgNVBAsMOkNvbmRpY2lv
bmVzIGRlIHVzbyBlbiB3d3cuaXplbnBlLmNvbSBub2xhIGVyYWJpbGkgamFraXRl
a28xFzAVBgNVBC4TDi1kbmkgOTk5OTk5ODlaMSQwIgYDVQQDDBtDT1JQT1JBVElW
TyBGSUNUSUNJTyBBQ1RJVk8xFDASBgNVBCoMC0NPUlBPUkFUSVZPMREwDwYDVQQE
DAhGSUNUSUNJTzESMBAGA1UEBRMJOTk5OTk5ODlaMIIBIjANBgkqhkiG9w0BAQEF
AAOCAQ8AMIIBCgKCAQEAwVOMwUDfBtsH0XuxYnb+v/L774jMH8valX7RPH8cl2Lb
SiqSo0RchW2RGA2d1yuYHlpChC9jGmt0X/g66/E/+q2hUJlfJtqVDJFwtFYV4u2S
yzA3J36V4PRkPQrKxAsbzZriFXAF10XgiHQz9aVeMMJ9GBhmh9+DK8Tm4cMF6i8l
+AuC35KdngPF1x0ealTYrYZplpEJFO7CiW42aLi6vQkDR2R7nmZA4AT69teqBWsK
0DZ93/f0G/3+vnWwNTBF0lB6dIXoaz8OMSyHLqGnmmAtMrzbjAr/O/WWgbB/BqhR
qjJQ7Ui16cuDldXaWQ/rkMzsxmsAox0UF+zdQNvXUQIDAQABo4IDBDCCAwAwgccG
A1UdEgSBvzCBvIYVaHR0cDovL3d3dy5pemVucGUuY29tgQ9pbmZvQGl6ZW5wZS5j
b22kgZEwgY4xRzBFBgNVBAoMPklaRU5QRSBTLkEuIC0gQ0lGIEEwMTMzNzI2MC1S
TWVyYy5WaXRvcmlhLUdhc3RlaXogVDEwNTUgRjYyIFM4MUMwQQYDVQQJDDpBdmRh
IGRlbCBNZWRpdGVycmFuZW8gRXRvcmJpZGVhIDE0IC0gMDEwMTAgVml0b3JpYS1H
YXN0ZWl6MB4GA1UdEQQXMBWBE2ZpY3RpY2lvQGl6ZW5wZS5ldXMwDgYDVR0PAQH/
BAQDAgXgMCkGA1UdJQQiMCAGCCsGAQUFBwMCBggrBgEFBQcDBAYKKwYBBAGCNxQC
AjAdBgNVHQ4EFgQUyeoOD4cgcljKY0JvrNuX2waFQLAwHwYDVR0jBBgwFoAUwKlK
90clh/+8taaJzoLSRqiJ66MwggEnBgNVHSAEggEeMIIBGjCCARYGCisGAQQB8zkB
AQEwggEGMDMGCCsGAQUFBwIBFidodHRwOi8vd3d3Lml6ZW5wZS5jb20vcnBhc2Nh
Y29ycG9yYXRpdm8wgc4GCCsGAQUFBwICMIHBGoG+Wml1cnRhZ2lyaWEgRXVza2Fs
IEF1dG9ub21pYSBFcmtpZGVnb2tvIHNla3RvcmUgcHVibGlrb2tvIGVyYWt1bmRl
ZW4gYmFybmUtc2FyZWV0YW4gYmFrYXJyaWsgZXJhYmlsIGRhaXRla2UuIFVzbyBy
ZXN0cmluZ2lkbyBhbCBhbWJpdG8gZGUgcmVkZXMgaW50ZXJuYXMgZGUgRW50aWRh
ZGVzIGRlbCBTZWN0b3IgUHVibGljbyBWYXNjbzAyBggrBgEFBQcBAQQmMCQwIgYI
KwYBBQUHMAGGFmh0dHA6Ly9vY3NwLml6ZW5wZS5jb20wOgYDVR0fBDMwMTAvoC2g
K4YpaHR0cDovL2NybC5pemVucGUuY29tL2NnaS1iaW4vY3JsaW50ZXJuYTIwDQYJ
KoZIhvcNAQELBQADggIBAIy5PQ+UZlCRq6ig43vpHwlwuD9daAYeejV0Q+ZbgWAE
GtO0kT/ytw95ZEJMNiMw3fYfPRlh27ThqiT0VDXZJDlzmn7JZd6QFcdXkCsiuv4+
ZoXAg/QwnA3SGUUO9aVaXyuOIIuvOfb9MzoGp9xk23SMV3eiLAaLMLqwB5DTfBdt
BGI7L1MnGJBv8RfP/TL67aJ5bgq2ri4S8vGHtXSjcZ0+rCEOLJtmDNMnTZxancg3
/H5edeNd+n6Z48LO+JHRxQufbC4mVNxVLMIP9EkGUejlq4E4w6zb5NwCQczJbSWL
i31rk2orsNsDlyaLGsWZp3JSNX6RmodU4KAUPor4jUJuUhrrm3Spb73gKlV/gcIw
bCE7mML1Kss3x1ySaXsis6SZtLpGWKkW2iguPWPs0ydV6RPhmsCxieMwPPIJ87vS
5IejfgyBae7RSuAIHyNFy4uI5xwvwUFf6OZ7az8qtW7ImFOgng3Ds+W9k1S2CNTx
d0cnKTfA6IpjGo8EeHcxnIXT8NPImWaRj0qqonvYady7ci6U4m3lkNSdXNn1afgw
mYust+gxVtOZs1gk2MUCgJ1V1X+g7r/Cg7viIn6TLkLrpS1kS1hvMqkl9M+7XqPo
Qd95nJKOkusQpy99X4dF/lfbYAQnnjnqh3DLD2gvYObXFaAYFaiBKTiMTV2X72F+
-----END CERTIFICATE-----`

const smimeIntermediate = `-----BEGIN CERTIFICATE-----
MIIHNzCCBSGgAwIBAgIQJMXIqlZvjuhMvqcFXOFkpDALBgkqhkiG9w0BAQswODEL
MAkGA1UEBhMCRVMxFDASBgNVBAoMC0laRU5QRSBTLkEuMRMwEQYDVQQDDApJemVu
cGUuY29tMB4XDTEwMTAyMDA4MjMzM1oXDTM3MTIxMjIzMDAwMFowgZ0xCzAJBgNV
BAYTAkVTMRQwEgYDVQQKDAtJWkVOUEUgUy5BLjE6MDgGA1UECwwxQVpaIFppdXJ0
YWdpcmkgcHVibGlrb2EgLSBDZXJ0aWZpY2FkbyBwdWJsaWNvIFNDQTE8MDoGA1UE
AwwzRUFFa28gSGVycmkgQWRtaW5pc3RyYXppb2VuIENBIC0gQ0EgQUFQUCBWYXNj
YXMgKDIpMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAoIM7nEdI0N1h
rR5T4xuV/usKDoMIasaiKvfLhbwxaNtTt+a7W/6wV5bv3svQFIy3sUXjjdzV1nG2
To2wo/YSPQiOt8exWvOapvL21ogiof+kelWnXFjWaKJI/vThHYLgIYEMj/y4HdtU
ojI646rZwqsb4YGAopwgmkDfUh5jOhV2IcYE3TgJAYWVkj6jku9PLaIsHiarAHjD
PY8dig8a4SRv0gm5Yk7FXLmW1d14oxQBDeHZ7zOEXfpafxdEDO2SNaRJjpkh8XRr
PGqkg2y1Q3gT6b4537jz+StyDIJ3omylmlJsGCwqT7p8mEqjGJ5kC5I2VnjXKuNn
soShc72khWZVUJiJo5SGuAkNE2ZXqltBVm5Jv6QweQKsX6bkcMc4IZok4a+hx8FM
8IBpGf/I94pU6HzGXqCyc1d46drJgDY9mXa+6YDAJFl3xeXOOW2iGCfwXqhiCrKL
MYvyMZzqF3QH5q4nb3ZnehYvraeMFXJXDn+Utqp8vd2r7ShfQJz01KtM4hgKdgSg
jtW+shkVVN5ng/fPN85ovfAH2BHXFfHmQn4zKsYnLitpwYM/7S1HxlT61cdQ7Nnk
3LZTYEgAoOmEmdheklT40WAYakksXGM5VrzG7x9S7s1Tm+Vb5LSThdHC8bxxwyTb
KsDRDNJ84N9fPDO6qHnzaL2upQ43PycCAwEAAaOCAdkwggHVMIHHBgNVHREEgb8w
gbyGFWh0dHA6Ly93d3cuaXplbnBlLmNvbYEPaW5mb0BpemVucGUuY29tpIGRMIGO
MUcwRQYDVQQKDD5JWkVOUEUgUy5BLiAtIENJRiBBMDEzMzcyNjAtUk1lcmMuVml0
b3JpYS1HYXN0ZWl6IFQxMDU1IEY2MiBTODFDMEEGA1UECQw6QXZkYSBkZWwgTWVk
aXRlcnJhbmVvIEV0b3JiaWRlYSAxNCAtIDAxMDEwIFZpdG9yaWEtR2FzdGVpejAP
BgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwIBBjAdBgNVHQ4EFgQUwKlK90cl
h/+8taaJzoLSRqiJ66MwHwYDVR0jBBgwFoAUHRxlDqjyJXu0kc/ksbHmvVV0bAUw
OgYDVR0gBDMwMTAvBgRVHSAAMCcwJQYIKwYBBQUHAgEWGWh0dHA6Ly93d3cuaXpl
bnBlLmNvbS9jcHMwNwYIKwYBBQUHAQEEKzApMCcGCCsGAQUFBzABhhtodHRwOi8v
b2NzcC5pemVucGUuY29tOjgwOTQwMwYDVR0fBCwwKjAooCagJIYiaHR0cDovL2Ny
bC5pemVucGUuY29tL2NnaS1iaW4vYXJsMjALBgkqhkiG9w0BAQsDggIBAMbjc3HM
3DG9ubWPkzsF0QsktukpujbTTcGk4h20G7SPRy1DiiTxrRzdAMWGjZioOP3/fKCS
M539qH0M+gsySNie+iKlbSZJUyE635T1tKw+G7bDUapjlH1xyv55NC5I6wCXGC6E
3TEP5B/E7dZD0s9E4lS511ubVZivFgOzMYo1DO96diny/N/V1enaTCpRl1qH1OyL
xUYTijV4ph2gL6exwuG7pxfRcVNHYlrRaXWfTz3F6NBKyULxrI3P/y6JAtN1GqT4
VF/+vMygx22n0DufGepBwTQz6/rr1ulSZ+eMnuJiTXgh/BzQnkUsXTb8mHII25iR
0oYF2qAsk6ecWbLiDpkHKIDHmML21MZE13MS8NSvTHoqJO4LyAmDe6SaeNHtrPlK
b6mzE1BN2ug+ZaX8wLA5IMPFaf0jKhb/Cxu8INsxjt00brsErCc9ip1VNaH0M4bi
1tGxfiew2436FaeyUxW7Pl6G5GgkNbuUc7QIoRy06DdU/U38BxW3uyJMY60zwHvS
FlKAn0OvYp4niKhAJwaBVN3kowmJuOU5Rid+TUnfyxbJ9cttSgzaF3hP/N4zgMEM
5tikXUskeckt8LUK96EH0QyssavAMECUEb/xrupyRdYWwjQGvNLq6T5+fViDGyOw
k+lzD44wofy8paAy9uC9Owae0zMEzhcsyRm7
-----END CERTIFICATE-----`

const smimeRoot = `-----BEGIN CERTIFICATE-----
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
-----END CERTIFICATE-----`

var nameConstraintsLeaf = `-----BEGIN CERTIFICATE-----
MIIG+jCCBOKgAwIBAgIQWj9gbtPPkZs65N6TKyutRjANBgkqhkiG9w0BAQsFADCB
yzELMAkGA1UEBhMCVVMxETAPBgNVBAgTCFZpcmdpbmlhMRMwEQYDVQQHEwpCbGFj
a3NidXJnMSMwIQYDVQQLExpHbG9iYWwgUXVhbGlmaWVkIFNlcnZlciBDQTE8MDoG
A1UEChMzVmlyZ2luaWEgUG9seXRlY2huaWMgSW5zdGl0dXRlIGFuZCBTdGF0ZSBV
bml2ZXJzaXR5MTEwLwYDVQQDEyhWaXJnaW5pYSBUZWNoIEdsb2JhbCBRdWFsaWZp
ZWQgU2VydmVyIENBMB4XDTE4MDQyNjE5NDU1M1oXDTE5MTIxMDAwMDAwMFowgZAx
CzAJBgNVBAYTAlVTMREwDwYDVQQIEwhWaXJnaW5pYTETMBEGA1UEBxMKQmxhY2tz
YnVyZzE8MDoGA1UEChMzVmlyZ2luaWEgUG9seXRlY2huaWMgSW5zdGl0dXRlIGFu
ZCBTdGF0ZSBVbml2ZXJzaXR5MRswGQYDVQQDExJ1ZGN0ZXN0LmFkcy52dC5lZHUw
ggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCcoVBeV3AzdSGMzRWH0tuM
VluEj+sq4r9PuLDBAdgjjHi4ED8npT2/fgOalswInXspRvFS+pkEwTrmeZ7HPzRJ
HUE5YlX5Nc6WI8ZXPVg5E6GyoMy6gNlALwqsIvDCvqxBMc39oG6yOuGmQXdF6s0N
BJMrXc4aPz60s4QMWNO2OHL0pmnZqE1TxYRBHUY/dk3cfsIepIDDuSxRsNE/P/MI
pxm/uVOyiLEnPmOMsL430SZ7nC8PxUMqya9ok6Zaf7k54g7JJXDjE96VMCjMszIv
Ud9qe1PbokTOxlG/4QW7Qm0dPbiJhTUuoBzVAxzlOOkSFdXqSYKjC9tFcbr8y+pT
AgMBAAGjggIRMIICDTCBtgYIKwYBBQUHAQEEgakwgaYwXwYIKwYBBQUHMAKGU2h0
dHA6Ly93d3cucGtpLnZ0LmVkdS9nbG9iYWxxdWFsaWZpZWRzZXJ2ZXIvY2FjZXJ0
L2dsb2JhbHF1YWxpZmllZHNlcnZlcl9zaGEyNTYuY3J0MEMGCCsGAQUFBzABhjdo
dHRwOi8vdnRjYS5wa2kudnQuZWR1OjgwODAvZWpiY2EvcHVibGljd2ViL3N0YXR1
cy9vY3NwMB0GA1UdDgQWBBSzDLXee0wbgXpVQxvBQCophQDZbTAMBgNVHRMBAf8E
AjAAMB8GA1UdIwQYMBaAFLxiYCfV4zVIF+lLq0Vq0Miod3GMMGoGA1UdIARjMGEw
DgYMKwYBBAG0aAUCAgIBMA4GDCsGAQQBtGgFAgIBATA/BgwrBgEEAbRoBQICAwEw
LzAtBggrBgEFBQcCARYhaHR0cDovL3d3dy5wa2kudnQuZWR1L2dsb2JhbC9jcHMv
MEoGA1UdHwRDMEEwP6A9oDuGOWh0dHA6Ly93d3cucGtpLnZ0LmVkdS9nbG9iYWxx
dWFsaWZpZWRzZXJ2ZXIvY3JsL2NhY3JsLmNybDAOBgNVHQ8BAf8EBAMCBeAwHQYD
VR0lBBYwFAYIKwYBBQUHAwIGCCsGAQUFBwMBMB0GA1UdEQQWMBSCEnVkY3Rlc3Qu
YWRzLnZ0LmVkdTANBgkqhkiG9w0BAQsFAAOCAgEAD79kuyZbwQJCSBOVq9lA0lj4
juHM7RMBfp2GuWvhk5F90OMKQCNdITva3oq4uQzt013TtwposYXq/d0Jobk6RHxj
OJzRZVvEPsXLvKm8oLhz7/qgI8gcVeJFR9WgdNhjN1upn++EnABHUdDR77fgixuH
F
```