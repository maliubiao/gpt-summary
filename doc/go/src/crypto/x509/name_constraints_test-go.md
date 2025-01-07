Response:
Let's break down the thought process for summarizing the provided Go code snippet.

1. **Understand the Goal:** The request asks for a summary of the functionality of the given Go code. It's explicitly identified as part of `go/src/crypto/x509/name_constraints_test.go`. This immediately suggests the code is focused on testing the name constraints feature of X.509 certificates.

2. **Initial Scan for Keywords:** Quickly scan the code for prominent keywords and patterns:
    * `package x509`: Confirms the package context.
    * `import`: Lists the necessary Go packages. Note `testing` is present, reinforcing the test file nature.
    * `const`:  Identifies constants, like `testNameConstraintsAgainstOpenSSL`. These hints at testing methodologies.
    * `type`:  Highlights the custom data structures being used, like `nameConstraintsTest`, `constraintsSpec`, and `leafSpec`. These are likely the core input structures for the tests.
    * `var nameConstraintsTests`: This strongly suggests a collection of test cases.
    * Comments starting with `// #`:  These are clearly test case identifiers.
    * String literals within the test cases (e.g., `"dns:example.com"`, `"expectedError"`):  These indicate the types of inputs and expected outcomes.

3. **Analyze the Data Structures:**  Examine the custom types in more detail:
    * `nameConstraintsTest`:  Contains lists of root and intermediate CA constraints, a leaf certificate specification, expected errors, and flags related to OpenSSL testing. This structure represents a single test case setup.
    * `constraintsSpec`: Defines allowed (`ok`), disallowed (`bad`), and extended key usage (`ekus`) constraints for a CA certificate.
    * `leafSpec`: Describes the subject alternative names (`sans`), extended key usage (`ekus`), and common name (`cn`) of a leaf certificate.

4. **Infer the Testing Logic:**  Based on the data structures and the file name, it's reasonable to infer the core testing process:
    * Generate a certificate chain based on the specifications in `nameConstraintsTest`. This involves root CAs, intermediate CAs (potentially multiple levels), and a leaf certificate.
    * Apply name constraints as defined in the `constraintsSpec` for the CA certificates.
    * Verify the leaf certificate against the generated chain.
    * Check if the verification outcome (success or failure, and the specific error message) matches the `expectedError` in the test case.
    * The presence of `testNameConstraintsAgainstOpenSSL` suggests an optional comparison of the Go implementation against OpenSSL's behavior.

5. **Identify Key Functionality:**  Based on the analysis, list the core functionalities being tested:
    * **Permitted DNS Names:** Testing allowed domain names and subdomains.
    * **Excluded DNS Names:** Testing disallowed domain names and subdomains.
    * **Permitted and Excluded IP Addresses (IPv4 and IPv6):** Testing allowed and disallowed IP address ranges.
    * **Email Address Constraints:** Testing allowed email addresses and domains.
    * **URI Constraints:** Testing allowed URI hosts.
    * **Extended Key Usage (EKU):** Testing the enforcement of EKU constraints in the certificate chain.
    * **Chain Building with Constraints:** Testing if the certificate verification process correctly selects valid chains based on name constraints.
    * **Handling of Unknown Name Types:**  Testing how the system behaves with unsupported or unrecognized name types in certificates.
    * **Edge Cases and Invalid Inputs:**  Testing how the system handles invalid DNS names, email addresses, and other edge cases.

6. **Structure the Summary:** Organize the findings into a coherent summary, focusing on the main purpose and key features:

    * Start with the main goal: testing X.509 name constraints.
    * Explain the data structures used to define test cases.
    * Describe the types of constraints being tested (DNS, IP, email, URI).
    * Highlight the testing of both "positive" (allowed) and "negative" (disallowed) constraints.
    * Mention the handling of intermediate CAs and chain building.
    * Include the testing of Extended Key Usage.
    * Note the optional OpenSSL comparison.

7. **Refine and Clarify:** Review the summary for clarity and accuracy. Ensure the language is concise and easy to understand. For instance, initially, I might just say "tests DNS constraints," but refining it to "testing permitted and excluded DNS names (including wildcards/subdomains)" provides more detail.

This systematic approach allows for a comprehensive understanding of the code's purpose and functionality, even without examining the detailed implementation of the test functions themselves. The key is to leverage the structure of the code (package, imports, types, variables) and the context provided by the file name to make informed deductions.
这是一个Go语言测试文件的片段，主要用于测试 `crypto/x509` 包中关于 **X.509 证书名称约束 (Name Constraints)** 功能的实现。

**功能归纳:**

这个代码片段定义了一系列的测试用例 (`nameConstraintsTests`)，用于验证 X.509 证书链在存在名称约束时，证书验证的行为是否符合预期。  它主要关注以下几个方面：

* **允许的名称约束 (Permitted Subtrees):**  测试根证书或中间证书设置的允许的域名、IP地址、邮箱或URI范围是否正确地限制了下级证书的主题备用名称 (Subject Alternative Name, SAN)。
* **禁止的名称约束 (Excluded Subtrees):** 测试根证书或中间证书设置的禁止的域名、IP地址、邮箱或URI范围是否正确地阻止了下级证书的主题备用名称。
* **不同类型的名称约束:**  测试 DNS 名称、IP 地址 (IPv4 和 IPv6)、邮箱和 URI 等不同类型的名称约束的有效性。
* **多层级证书链:**  测试名称约束在包含多层中间证书的证书链中的传递和生效。
* **扩展密钥用法 (Extended Key Usage, EKU):** 测试 EKU 约束在证书验证过程中的作用。
* **错误处理:** 测试当证书违反名称约束时，是否能正确地返回预期的错误信息。
* **与 OpenSSL 的对比测试 (可选):** 提供了与系统安装的 OpenSSL 进行对比测试的功能（默认关闭）。
* **处理未知名称类型:** 测试在遇到未知类型的名称约束时，系统的处理方式。

**Go 代码示例 (推理):**

虽然没有给出完整的测试函数，但我们可以推断出测试的基本流程。  每个 `nameConstraintsTest` 结构体定义了一个测试场景，通常会生成一个或多个 CA 证书和一个叶子证书，然后使用 `x509.Verify` 函数来验证叶子证书的有效性。

假设我们想测试一个根证书限制只允许 `example.com` 域名的场景（对应代码中的 `#3` 测试用例）。  可能的测试代码结构如下：

```go
func TestNameConstraints_DNSExampleCom(t *testing.T) {
	// 定义根证书的约束：只允许 dns:example.com
	rootConstraints := constraintsSpec{
		ok: []string{"dns:example.com"},
	}

	// 创建根 CA 证书
	rootKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	rootCert, _ := makeConstraintsCACert(rootConstraints, "Root CA", rootKey, nil, nil)

	// 定义叶子证书的 SAN：dns:test.example.com (允许)
	leafSpecGood := leafSpec{
		sans: []string{"dns:test.example.com"},
	}
	leafKeyGood, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leafCertGood, _ := makeConstraintsLeafCert(leafSpecGood, leafKeyGood, rootCert, rootKey)

	// 定义叶子证书的 SAN：dns:notallowed.com (不允许)
	leafSpecBad := leafSpec{
		sans: []string{"dns:notallowed.com"},
	}
	leafKeyBad, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leafCertBad, _ := makeConstraintsLeafCert(leafSpecBad, leafKeyBad, rootCert, rootKey)

	// 构建证书池
	roots := NewCertPool()
	roots.AddCert(rootCert)

	// 验证允许的证书
	optsGood := VerifyOptions{
		Roots: roots,
	}
	_, errGood := leafCertGood.Verify(optsGood)
	if errGood != nil {
		t.Errorf("Expected verification to succeed, but got error: %v", errGood)
	}

	// 验证不允许的证书
	optsBad := VerifyOptions{
		Roots: roots,
	}
	_, errBad := leafCertBad.Verify(optsBad)
	if errBad == nil {
		t.Errorf("Expected verification to fail, but it succeeded")
	} else if !strings.Contains(errBad.Error(), "\"notallowed.com\" is not permitted") {
		t.Errorf("Expected specific error message, got: %v", errBad)
	}
}
```

**假设的输入与输出:**

* **输入 (对于 `#3` 测试用例):**
    * 根 CA 证书，其名称约束设置为允许 `dns:example.com`。
    * 叶子证书，其 SAN 设置为 `dns:test.example.com`。
* **输出:**  `x509.Verify` 函数应该返回 `nil` (表示验证成功)。

* **输入 (对于 `#3` 测试用例的负面测试):**
    * 根 CA 证书，其名称约束设置为允许 `dns:example.com`。
    * 叶子证书，其 SAN 设置为 `dns:notallowed.com`。
* **输出:** `x509.Verify` 函数应该返回一个错误，其错误信息包含 `"notallowed.com" is not permitted`。

**命令行参数处理:**

代码中定义了两个常量：

* `testNameConstraintsAgainstOpenSSL`:  如果设置为 `true`，测试将会尝试使用系统安装的 OpenSSL 工具进行额外的验证。 这通常需要在运行测试时手动修改此常量。
* `debugOpenSSLFailure`:  如果 `testNameConstraintsAgainstOpenSSL` 为 `true` 且测试失败，则设置为 `true` 可以保留中间生成的文件用于调试。

这两个常量不是通过命令行参数直接设置的，而是需要在代码中修改。  这意味着使用者如果想启用 OpenSSL 对比测试，需要修改源代码并重新编译运行测试。

**使用者易犯错的点:**

由于这段代码是测试代码，使用者主要是 Go 语言的开发者。  在阅读和理解这些测试用例时，一些容易犯错的点包括：

* **混淆 `ok` 和 `bad` 约束:**  不清楚 `constraintsSpec` 中的 `ok` 字段表示允许的，`bad` 字段表示禁止的。
* **对通配符的理解:**  对于 DNS 名称约束中以 `.` 开头的域名（例如 `.example.com`），其含义是匹配子域名，而不是域名本身。  例如，`.example.com` 匹配 `foo.example.com`，但不匹配 `example.com`。
* **IP 地址范围的表示:**  不熟悉 IP 地址范围的 CIDR 表示法（例如 `10.0.0.0/8`）。
* **URI 约束的匹配规则:**  URI 约束只匹配 URI 的主机部分，不包括路径、端口等。
* **邮件地址约束的规则:**  邮件地址约束可以是精确匹配，也可以是匹配整个域名或子域名。  需要注意大小写敏感性。
* **扩展密钥用法的理解:**  不清楚不同的 EKU 值代表的含义，以及它们在证书验证中的作用。
* **忽略错误信息:**  在阅读测试用例时，可能会忽略 `expectedError` 字段，从而不能理解某些测试用例的意图。

总而言之，这段代码定义了一套详尽的测试用例，用于验证 Go 语言 `crypto/x509` 包中名称约束功能的正确性和健壮性。它涵盖了各种常见的名称约束类型和场景，并通过与 OpenSSL 的可选对比测试来提高测试的可靠性。

Prompt: 
```
这是路径为go/src/crypto/x509/name_constraints_test.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第1部分，共2部分，请归纳一下它的功能

"""
// Copyright 2017 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package x509

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/url"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

const (
	// testNameConstraintsAgainstOpenSSL can be set to true to run tests
	// against the system OpenSSL. This is disabled by default because Go
	// cannot depend on having OpenSSL installed at testing time.
	testNameConstraintsAgainstOpenSSL = false

	// debugOpenSSLFailure can be set to true, when
	// testNameConstraintsAgainstOpenSSL is also true, to cause
	// intermediate files to be preserved for debugging.
	debugOpenSSLFailure = false
)

type nameConstraintsTest struct {
	roots         []constraintsSpec
	intermediates [][]constraintsSpec
	leaf          leafSpec
	requestedEKUs []ExtKeyUsage
	expectedError string
	noOpenSSL     bool
	ignoreCN      bool
}

type constraintsSpec struct {
	ok   []string
	bad  []string
	ekus []string
}

type leafSpec struct {
	sans []string
	ekus []string
	cn   string
}

var nameConstraintsTests = []nameConstraintsTest{
	// #0: dummy test for the certificate generation process itself.
	{
		roots: make([]constraintsSpec, 1),
		leaf: leafSpec{
			sans: []string{"dns:example.com"},
		},
	},

	// #1: dummy test for the certificate generation process itself: single
	// level of intermediate.
	{
		roots: make([]constraintsSpec, 1),
		intermediates: [][]constraintsSpec{
			{
				{},
			},
		},
		leaf: leafSpec{
			sans: []string{"dns:example.com"},
		},
	},

	// #2: dummy test for the certificate generation process itself: two
	// levels of intermediates.
	{
		roots: make([]constraintsSpec, 1),
		intermediates: [][]constraintsSpec{
			{
				{},
			},
			{
				{},
			},
		},
		leaf: leafSpec{
			sans: []string{"dns:example.com"},
		},
	},

	// #3: matching DNS constraint in root
	{
		roots: []constraintsSpec{
			{
				ok: []string{"dns:example.com"},
			},
		},
		intermediates: [][]constraintsSpec{
			{
				{},
			},
		},
		leaf: leafSpec{
			sans: []string{"dns:example.com"},
		},
	},

	// #4: matching DNS constraint in intermediate.
	{
		roots: make([]constraintsSpec, 1),
		intermediates: [][]constraintsSpec{
			{
				{
					ok: []string{"dns:example.com"},
				},
			},
		},
		leaf: leafSpec{
			sans: []string{"dns:example.com"},
		},
	},

	// #5: .example.com only matches subdomains.
	{
		roots: []constraintsSpec{
			{
				ok: []string{"dns:.example.com"},
			},
		},
		intermediates: [][]constraintsSpec{
			{
				{},
			},
		},
		leaf: leafSpec{
			sans: []string{"dns:example.com"},
		},
		expectedError: "\"example.com\" is not permitted",
	},

	// #6: .example.com matches subdomains.
	{
		roots: make([]constraintsSpec, 1),
		intermediates: [][]constraintsSpec{
			{
				{
					ok: []string{"dns:.example.com"},
				},
			},
		},
		leaf: leafSpec{
			sans: []string{"dns:foo.example.com"},
		},
	},

	// #7: .example.com matches multiple levels of subdomains
	{
		roots: []constraintsSpec{
			{
				ok: []string{"dns:.example.com"},
			},
		},
		intermediates: [][]constraintsSpec{
			{
				{},
			},
		},
		leaf: leafSpec{
			sans: []string{"dns:foo.bar.example.com"},
		},
	},

	// #8: specifying a permitted list of names does not exclude other name
	// types
	{
		roots: []constraintsSpec{
			{
				ok: []string{"dns:.example.com"},
			},
		},
		intermediates: [][]constraintsSpec{
			{
				{},
			},
		},
		leaf: leafSpec{
			sans: []string{"ip:10.1.1.1"},
		},
	},

	// #9: specifying a permitted list of names does not exclude other name
	// types
	{
		roots: []constraintsSpec{
			{
				ok: []string{"ip:10.0.0.0/8"},
			},
		},
		intermediates: [][]constraintsSpec{
			{
				{},
			},
		},
		leaf: leafSpec{
			sans: []string{"dns:example.com"},
		},
	},

	// #10: intermediates can try to permit other names, which isn't
	// forbidden if the leaf doesn't mention them. I.e. name constraints
	// apply to names, not constraints themselves.
	{
		roots: []constraintsSpec{
			{
				ok: []string{"dns:example.com"},
			},
		},
		intermediates: [][]constraintsSpec{
			{
				{
					ok: []string{"dns:example.com", "dns:foo.com"},
				},
			},
		},
		leaf: leafSpec{
			sans: []string{"dns:example.com"},
		},
	},

	// #11: intermediates cannot add permitted names that the root doesn't
	// grant them.
	{
		roots: []constraintsSpec{
			{
				ok: []string{"dns:example.com"},
			},
		},
		intermediates: [][]constraintsSpec{
			{
				{
					ok: []string{"dns:example.com", "dns:foo.com"},
				},
			},
		},
		leaf: leafSpec{
			sans: []string{"dns:foo.com"},
		},
		expectedError: "\"foo.com\" is not permitted",
	},

	// #12: intermediates can further limit their scope if they wish.
	{
		roots: []constraintsSpec{
			{
				ok: []string{"dns:.example.com"},
			},
		},
		intermediates: [][]constraintsSpec{
			{
				{
					ok: []string{"dns:.bar.example.com"},
				},
			},
		},
		leaf: leafSpec{
			sans: []string{"dns:foo.bar.example.com"},
		},
	},

	// #13: intermediates can further limit their scope and that limitation
	// is effective
	{
		roots: []constraintsSpec{
			{
				ok: []string{"dns:.example.com"},
			},
		},
		intermediates: [][]constraintsSpec{
			{
				{
					ok: []string{"dns:.bar.example.com"},
				},
			},
		},
		leaf: leafSpec{
			sans: []string{"dns:foo.notbar.example.com"},
		},
		expectedError: "\"foo.notbar.example.com\" is not permitted",
	},

	// #14: roots can exclude subtrees and that doesn't affect other names.
	{
		roots: []constraintsSpec{
			{
				bad: []string{"dns:.example.com"},
			},
		},
		intermediates: [][]constraintsSpec{
			{
				{},
			},
		},
		leaf: leafSpec{
			sans: []string{"dns:foo.com"},
		},
	},

	// #15: roots exclusions are effective.
	{
		roots: []constraintsSpec{
			{
				bad: []string{"dns:.example.com"},
			},
		},
		intermediates: [][]constraintsSpec{
			{
				{},
			},
		},
		leaf: leafSpec{
			sans: []string{"dns:foo.example.com"},
		},
		expectedError: "\"foo.example.com\" is excluded",
	},

	// #16: intermediates can also exclude names and that doesn't affect
	// other names.
	{
		roots: make([]constraintsSpec, 1),
		intermediates: [][]constraintsSpec{
			{
				{
					bad: []string{"dns:.example.com"},
				},
			},
		},
		leaf: leafSpec{
			sans: []string{"dns:foo.com"},
		},
	},

	// #17: intermediate exclusions are effective.
	{
		roots: make([]constraintsSpec, 1),
		intermediates: [][]constraintsSpec{
			{
				{
					bad: []string{"dns:.example.com"},
				},
			},
		},
		leaf: leafSpec{
			sans: []string{"dns:foo.example.com"},
		},
		expectedError: "\"foo.example.com\" is excluded",
	},

	// #18: having an exclusion doesn't prohibit other types of names.
	{
		roots: []constraintsSpec{
			{
				bad: []string{"dns:.example.com"},
			},
		},
		intermediates: [][]constraintsSpec{
			{
				{},
			},
		},
		leaf: leafSpec{
			sans: []string{"dns:foo.com", "ip:10.1.1.1"},
		},
	},

	// #19: IP-based exclusions are permitted and don't affect unrelated IP
	// addresses.
	{
		roots: []constraintsSpec{
			{
				bad: []string{"ip:10.0.0.0/8"},
			},
		},
		intermediates: [][]constraintsSpec{
			{
				{},
			},
		},
		leaf: leafSpec{
			sans: []string{"ip:192.168.1.1"},
		},
	},

	// #20: IP-based exclusions are effective
	{
		roots: []constraintsSpec{
			{
				bad: []string{"ip:10.0.0.0/8"},
			},
		},
		intermediates: [][]constraintsSpec{
			{
				{},
			},
		},
		leaf: leafSpec{
			sans: []string{"ip:10.0.0.1"},
		},
		expectedError: "\"10.0.0.1\" is excluded",
	},

	// #21: intermediates can further constrain IP ranges.
	{
		roots: []constraintsSpec{
			{
				bad: []string{"ip:0.0.0.0/1"},
			},
		},
		intermediates: [][]constraintsSpec{
			{
				{
					bad: []string{"ip:11.0.0.0/8"},
				},
			},
		},
		leaf: leafSpec{
			sans: []string{"ip:11.0.0.1"},
		},
		expectedError: "\"11.0.0.1\" is excluded",
	},

	// #22: when multiple intermediates are present, chain building can
	// avoid intermediates with incompatible constraints.
	{
		roots: make([]constraintsSpec, 1),
		intermediates: [][]constraintsSpec{
			{
				{
					ok: []string{"dns:.foo.com"},
				},
				{
					ok: []string{"dns:.example.com"},
				},
			},
		},
		leaf: leafSpec{
			sans: []string{"dns:foo.example.com"},
		},
		noOpenSSL: true, // OpenSSL's chain building is not informed by constraints.
	},

	// #23: (same as the previous test, but in the other order in ensure
	// that we don't pass it by luck.)
	{
		roots: make([]constraintsSpec, 1),
		intermediates: [][]constraintsSpec{
			{
				{
					ok: []string{"dns:.example.com"},
				},
				{
					ok: []string{"dns:.foo.com"},
				},
			},
		},
		leaf: leafSpec{
			sans: []string{"dns:foo.example.com"},
		},
		noOpenSSL: true, // OpenSSL's chain building is not informed by constraints.
	},

	// #24: when multiple roots are valid, chain building can avoid roots
	// with incompatible constraints.
	{
		roots: []constraintsSpec{
			{},
			{
				ok: []string{"dns:foo.com"},
			},
		},
		intermediates: [][]constraintsSpec{
			{
				{},
			},
		},
		leaf: leafSpec{
			sans: []string{"dns:example.com"},
		},
		noOpenSSL: true, // OpenSSL's chain building is not informed by constraints.
	},

	// #25: (same as the previous test, but in the other order in ensure
	// that we don't pass it by luck.)
	{
		roots: []constraintsSpec{
			{
				ok: []string{"dns:foo.com"},
			},
			{},
		},
		intermediates: [][]constraintsSpec{
			{
				{},
			},
		},
		leaf: leafSpec{
			sans: []string{"dns:example.com"},
		},
		noOpenSSL: true, // OpenSSL's chain building is not informed by constraints.
	},

	// #26: chain building can find a valid path even with multiple levels
	// of alternative intermediates and alternative roots.
	{
		roots: []constraintsSpec{
			{
				ok: []string{"dns:foo.com"},
			},
			{
				ok: []string{"dns:example.com"},
			},
			{},
		},
		intermediates: [][]constraintsSpec{
			{
				{},
				{
					ok: []string{"dns:foo.com"},
				},
			},
			{
				{},
				{
					ok: []string{"dns:foo.com"},
				},
			},
		},
		leaf: leafSpec{
			sans: []string{"dns:bar.com"},
		},
		noOpenSSL: true, // OpenSSL's chain building is not informed by constraints.
	},

	// #27: chain building doesn't get stuck when there is no valid path.
	{
		roots: []constraintsSpec{
			{
				ok: []string{"dns:foo.com"},
			},
			{
				ok: []string{"dns:example.com"},
			},
		},
		intermediates: [][]constraintsSpec{
			{
				{},
				{
					ok: []string{"dns:foo.com"},
				},
			},
			{
				{
					ok: []string{"dns:bar.com"},
				},
				{
					ok: []string{"dns:foo.com"},
				},
			},
		},
		leaf: leafSpec{
			sans: []string{"dns:bar.com"},
		},
		expectedError: "\"bar.com\" is not permitted",
	},

	// #28: unknown name types don't cause a problem without constraints.
	{
		roots: make([]constraintsSpec, 1),
		intermediates: [][]constraintsSpec{
			{
				{},
			},
		},
		leaf: leafSpec{
			sans: []string{"unknown:"},
		},
	},

	// #29: unknown name types are allowed even in constrained chains.
	{
		roots: []constraintsSpec{
			{
				ok: []string{"dns:foo.com", "dns:.foo.com"},
			},
		},
		intermediates: [][]constraintsSpec{
			{
				{},
			},
		},
		leaf: leafSpec{
			sans: []string{"unknown:"},
		},
	},

	// #30: without SANs, a certificate with a CN is still accepted in a
	// constrained chain, since we ignore the CN in VerifyHostname.
	{
		roots: []constraintsSpec{
			{
				ok: []string{"dns:foo.com", "dns:.foo.com"},
			},
		},
		intermediates: [][]constraintsSpec{
			{
				{},
			},
		},
		leaf: leafSpec{
			sans: []string{},
			cn:   "foo.com",
		},
	},

	// #31: IPv6 addresses work in constraints: roots can permit them as
	// expected.
	{
		roots: []constraintsSpec{
			{
				ok: []string{"ip:2000:abcd::/32"},
			},
		},
		intermediates: [][]constraintsSpec{
			{
				{},
			},
		},
		leaf: leafSpec{
			sans: []string{"ip:2000:abcd:1234::"},
		},
	},

	// #32: IPv6 addresses work in constraints: root restrictions are
	// effective.
	{
		roots: []constraintsSpec{
			{
				ok: []string{"ip:2000:abcd::/32"},
			},
		},
		intermediates: [][]constraintsSpec{
			{
				{},
			},
		},
		leaf: leafSpec{
			sans: []string{"ip:2000:1234:abcd::"},
		},
		expectedError: "\"2000:1234:abcd::\" is not permitted",
	},

	// #33: An IPv6 permitted subtree doesn't affect DNS names.
	{
		roots: []constraintsSpec{
			{
				ok: []string{"ip:2000:abcd::/32"},
			},
		},
		intermediates: [][]constraintsSpec{
			{
				{},
			},
		},
		leaf: leafSpec{
			sans: []string{"ip:2000:abcd::", "dns:foo.com"},
		},
	},

	// #34: IPv6 exclusions don't affect unrelated addresses.
	{
		roots: []constraintsSpec{
			{
				bad: []string{"ip:2000:abcd::/32"},
			},
		},
		intermediates: [][]constraintsSpec{
			{
				{},
			},
		},
		leaf: leafSpec{
			sans: []string{"ip:2000:1234::"},
		},
	},

	// #35: IPv6 exclusions are effective.
	{
		roots: []constraintsSpec{
			{
				bad: []string{"ip:2000:abcd::/32"},
			},
		},
		intermediates: [][]constraintsSpec{
			{
				{},
			},
		},
		leaf: leafSpec{
			sans: []string{"ip:2000:abcd::"},
		},
		expectedError: "\"2000:abcd::\" is excluded",
	},

	// #36: IPv6 constraints do not permit IPv4 addresses.
	{
		roots: []constraintsSpec{
			{
				ok: []string{"ip:2000:abcd::/32"},
			},
		},
		intermediates: [][]constraintsSpec{
			{
				{},
			},
		},
		leaf: leafSpec{
			sans: []string{"ip:10.0.0.1"},
		},
		expectedError: "\"10.0.0.1\" is not permitted",
	},

	// #37: IPv4 constraints do not permit IPv6 addresses.
	{
		roots: []constraintsSpec{
			{
				ok: []string{"ip:10.0.0.0/8"},
			},
		},
		intermediates: [][]constraintsSpec{
			{
				{},
			},
		},
		leaf: leafSpec{
			sans: []string{"ip:2000:abcd::"},
		},
		expectedError: "\"2000:abcd::\" is not permitted",
	},

	// #38: an exclusion of an unknown type doesn't affect other names.
	{
		roots: []constraintsSpec{
			{
				bad: []string{"unknown:"},
			},
		},
		intermediates: [][]constraintsSpec{
			{
				{},
			},
		},
		leaf: leafSpec{
			sans: []string{"dns:example.com"},
		},
	},

	// #39: a permitted subtree of an unknown type doesn't affect other
	// name types.
	{
		roots: []constraintsSpec{
			{
				ok: []string{"unknown:"},
			},
		},
		intermediates: [][]constraintsSpec{
			{
				{},
			},
		},
		leaf: leafSpec{
			sans: []string{"dns:example.com"},
		},
	},

	// #40: exact email constraints work
	{
		roots: []constraintsSpec{
			{
				ok: []string{"email:foo@example.com"},
			},
		},
		intermediates: [][]constraintsSpec{
			{
				{},
			},
		},
		leaf: leafSpec{
			sans: []string{"email:foo@example.com"},
		},
	},

	// #41: exact email constraints are effective
	{
		roots: []constraintsSpec{
			{
				ok: []string{"email:foo@example.com"},
			},
		},
		intermediates: [][]constraintsSpec{
			{
				{},
			},
		},
		leaf: leafSpec{
			sans: []string{"email:bar@example.com"},
		},
		expectedError: "\"bar@example.com\" is not permitted",
	},

	// #42: email canonicalisation works.
	{
		roots: []constraintsSpec{
			{
				ok: []string{"email:foo@example.com"},
			},
		},
		intermediates: [][]constraintsSpec{
			{
				{},
			},
		},
		leaf: leafSpec{
			sans: []string{"email:\"\\f\\o\\o\"@example.com"},
		},
		noOpenSSL: true, // OpenSSL doesn't canonicalise email addresses before matching
	},

	// #43: limiting email addresses to a host works.
	{
		roots: []constraintsSpec{
			{
				ok: []string{"email:example.com"},
			},
		},
		intermediates: [][]constraintsSpec{
			{
				{},
			},
		},
		leaf: leafSpec{
			sans: []string{"email:foo@example.com"},
		},
	},

	// #44: a leading dot matches hosts one level deep
	{
		roots: []constraintsSpec{
			{
				ok: []string{"email:.example.com"},
			},
		},
		intermediates: [][]constraintsSpec{
			{
				{},
			},
		},
		leaf: leafSpec{
			sans: []string{"email:foo@sub.example.com"},
		},
	},

	// #45: a leading dot does not match the host itself
	{
		roots: []constraintsSpec{
			{
				ok: []string{"email:.example.com"},
			},
		},
		intermediates: [][]constraintsSpec{
			{
				{},
			},
		},
		leaf: leafSpec{
			sans: []string{"email:foo@example.com"},
		},
		expectedError: "\"foo@example.com\" is not permitted",
	},

	// #46: a leading dot also matches two (or more) levels deep.
	{
		roots: []constraintsSpec{
			{
				ok: []string{"email:.example.com"},
			},
		},
		intermediates: [][]constraintsSpec{
			{
				{},
			},
		},
		leaf: leafSpec{
			sans: []string{"email:foo@sub.sub.example.com"},
		},
	},

	// #47: the local part of an email is case-sensitive
	{
		roots: []constraintsSpec{
			{
				ok: []string{"email:foo@example.com"},
			},
		},
		intermediates: [][]constraintsSpec{
			{
				{},
			},
		},
		leaf: leafSpec{
			sans: []string{"email:Foo@example.com"},
		},
		expectedError: "\"Foo@example.com\" is not permitted",
	},

	// #48: the domain part of an email is not case-sensitive
	{
		roots: []constraintsSpec{
			{
				ok: []string{"email:foo@EXAMPLE.com"},
			},
		},
		intermediates: [][]constraintsSpec{
			{
				{},
			},
		},
		leaf: leafSpec{
			sans: []string{"email:foo@example.com"},
		},
	},

	// #49: the domain part of a DNS constraint is also not case-sensitive.
	{
		roots: []constraintsSpec{
			{
				ok: []string{"dns:EXAMPLE.com"},
			},
		},
		intermediates: [][]constraintsSpec{
			{
				{},
			},
		},
		leaf: leafSpec{
			sans: []string{"dns:example.com"},
		},
	},

	// #50: URI constraints only cover the host part of the URI
	{
		roots: []constraintsSpec{
			{
				ok: []string{"uri:example.com"},
			},
		},
		intermediates: [][]constraintsSpec{
			{
				{},
			},
		},
		leaf: leafSpec{
			sans: []string{
				"uri:http://example.com/bar",
				"uri:http://example.com:8080/",
				"uri:https://example.com/wibble#bar",
			},
		},
	},

	// #51: URIs with IPs are rejected
	{
		roots: []constraintsSpec{
			{
				ok: []string{"uri:example.com"},
			},
		},
		intermediates: [][]constraintsSpec{
			{
				{},
			},
		},
		leaf: leafSpec{
			sans: []string{"uri:http://1.2.3.4/"},
		},
		expectedError: "URI with IP",
	},

	// #52: URIs with IPs and ports are rejected
	{
		roots: []constraintsSpec{
			{
				ok: []string{"uri:example.com"},
			},
		},
		intermediates: [][]constraintsSpec{
			{
				{},
			},
		},
		leaf: leafSpec{
			sans: []string{"uri:http://1.2.3.4:43/"},
		},
		expectedError: "URI with IP",
	},

	// #53: URIs with IPv6 addresses are also rejected
	{
		roots: []constraintsSpec{
			{
				ok: []string{"uri:example.com"},
			},
		},
		intermediates: [][]constraintsSpec{
			{
				{},
			},
		},
		leaf: leafSpec{
			sans: []string{"uri:http://[2006:abcd::1]/"},
		},
		expectedError: "URI with IP",
	},

	// #54: URIs with IPv6 addresses with ports are also rejected
	{
		roots: []constraintsSpec{
			{
				ok: []string{"uri:example.com"},
			},
		},
		intermediates: [][]constraintsSpec{
			{
				{},
			},
		},
		leaf: leafSpec{
			sans: []string{"uri:http://[2006:abcd::1]:16/"},
		},
		expectedError: "URI with IP",
	},

	// #55: URI constraints are effective
	{
		roots: []constraintsSpec{
			{
				ok: []string{"uri:example.com"},
			},
		},
		intermediates: [][]constraintsSpec{
			{
				{},
			},
		},
		leaf: leafSpec{
			sans: []string{"uri:http://bar.com/"},
		},
		expectedError: "\"http://bar.com/\" is not permitted",
	},

	// #56: URI constraints are effective
	{
		roots: []constraintsSpec{
			{
				bad: []string{"uri:foo.com"},
			},
		},
		intermediates: [][]constraintsSpec{
			{
				{},
			},
		},
		leaf: leafSpec{
			sans: []string{"uri:http://foo.com/"},
		},
		expectedError: "\"http://foo.com/\" is excluded",
	},

	// #57: URI constraints can allow subdomains
	{
		roots: []constraintsSpec{
			{
				ok: []string{"uri:.foo.com"},
			},
		},
		intermediates: [][]constraintsSpec{
			{
				{},
			},
		},
		leaf: leafSpec{
			sans: []string{"uri:http://www.foo.com/"},
		},
	},

	// #58: excluding an IPv4-mapped-IPv6 address doesn't affect the IPv4
	// version of that address.
	{
		roots: []constraintsSpec{
			{
				bad: []string{"ip:::ffff:1.2.3.4/128"},
			},
		},
		intermediates: [][]constraintsSpec{
			{
				{},
			},
		},
		leaf: leafSpec{
			sans: []string{"ip:1.2.3.4"},
		},
	},

	// #59: a URI constraint isn't matched by a URN.
	{
		roots: []constraintsSpec{
			{
				ok: []string{"uri:example.com"},
			},
		},
		intermediates: [][]constraintsSpec{
			{
				{},
			},
		},
		leaf: leafSpec{
			sans: []string{"uri:urn:example"},
		},
		expectedError: "URI with empty host",
	},

	// #60: excluding all IPv6 addresses doesn't exclude all IPv4 addresses
	// too, even though IPv4 is mapped into the IPv6 range.
	{
		roots: []constraintsSpec{
			{
				ok:  []string{"ip:1.2.3.0/24"},
				bad: []string{"ip:::0/0"},
			},
		},
		intermediates: [][]constraintsSpec{
			{
				{},
			},
		},
		leaf: leafSpec{
			sans: []string{"ip:1.2.3.4"},
		},
	},

	// #61: omitting extended key usage in a CA certificate implies that
	// any usage is ok.
	{
		roots: make([]constraintsSpec, 1),
		intermediates: [][]constraintsSpec{
			{
				{},
			},
		},
		leaf: leafSpec{
			sans: []string{"dns:example.com"},
			ekus: []string{"serverAuth", "other"},
		},
	},

	// #62: The “any” EKU also means that any usage is ok.
	{
		roots: make([]constraintsSpec, 1),
		intermediates: [][]constraintsSpec{
			{
				{
					ekus: []string{"any"},
				},
			},
		},
		leaf: leafSpec{
			sans: []string{"dns:example.com"},
			ekus: []string{"serverAuth", "other"},
		},
	},

	// #63: An intermediate with enumerated EKUs causes a failure if we
	// test for an EKU not in that set. (ServerAuth is required by
	// default.)
	{
		roots: make([]constraintsSpec, 1),
		intermediates: [][]constraintsSpec{
			{
				{
					ekus: []string{"email"},
				},
			},
		},
		leaf: leafSpec{
			sans: []string{"dns:example.com"},
			ekus: []string{"serverAuth"},
		},
		expectedError: "incompatible key usage",
	},

	// #64: an unknown EKU in the leaf doesn't break anything, even if it's not
	// correctly nested.
	{
		roots: make([]constraintsSpec, 1),
		intermediates: [][]constraintsSpec{
			{
				{
					ekus: []string{"email"},
				},
			},
		},
		leaf: leafSpec{
			sans: []string{"dns:example.com"},
			ekus: []string{"other"},
		},
		requestedEKUs: []ExtKeyUsage{ExtKeyUsageAny},
	},

	// #65: trying to add extra permitted key usages in an intermediate
	// (after a limitation in the root) is acceptable so long as the leaf
	// certificate doesn't use them.
	{
		roots: []constraintsSpec{
			{
				ekus: []string{"serverAuth"},
			},
		},
		intermediates: [][]constraintsSpec{
			{
				{
					ekus: []string{"serverAuth", "email"},
				},
			},
		},
		leaf: leafSpec{
			sans: []string{"dns:example.com"},
			ekus: []string{"serverAuth"},
		},
	},

	// #66: EKUs in roots are not ignored.
	{
		roots: []constraintsSpec{
			{
				ekus: []string{"email"},
			},
		},
		intermediates: [][]constraintsSpec{
			{
				{
					ekus: []string{"serverAuth"},
				},
			},
		},
		leaf: leafSpec{
			sans: []string{"dns:example.com"},
			ekus: []string{"serverAuth"},
		},
		expectedError: "incompatible key usage",
	},

	// #67: SGC key usages used to permit serverAuth and clientAuth,
	// but don't anymore.
	{
		roots: []constraintsSpec{
			{},
		},
		intermediates: [][]constraintsSpec{
			{
				{
					ekus: []string{"netscapeSGC"},
				},
			},
		},
		leaf: leafSpec{
			sans: []string{"dns:example.com"},
			ekus: []string{"serverAuth", "clientAuth"},
		},
		expectedError: "incompatible key usage",
	},

	// #68: SGC key usages used to permit serverAuth and clientAuth,
	// but don't anymore.
	{
		roots: make([]constraintsSpec, 1),
		intermediates: [][]constraintsSpec{
			{
				{
					ekus: []string{"msSGC"},
				},
			},
		},
		leaf: leafSpec{
			sans: []string{"dns:example.com"},
			ekus: []string{"serverAuth", "clientAuth"},
		},
		expectedError: "incompatible key usage",
	},

	// #69: an empty DNS constraint should allow anything.
	{
		roots: []constraintsSpec{
			{
				ok: []string{"dns:"},
			},
		},
		intermediates: [][]constraintsSpec{
			{
				{},
			},
		},
		leaf: leafSpec{
			sans: []string{"dns:example.com"},
		},
	},

	// #70: an empty DNS constraint should also reject everything.
	{
		roots: []constraintsSpec{
			{
				bad: []string{"dns:"},
			},
		},
		intermediates: [][]constraintsSpec{
			{
				{},
			},
		},
		leaf: leafSpec{
			sans: []string{"dns:example.com"},
		},
		expectedError: "\"example.com\" is excluded",
	},

	// #71: an empty email constraint should allow anything
	{
		roots: []constraintsSpec{
			{
				ok: []string{"email:"},
			},
		},
		intermediates: [][]constraintsSpec{
			{
				{},
			},
		},
		leaf: leafSpec{
			sans: []string{"email:foo@example.com"},
		},
	},

	// #72: an empty email constraint should also reject everything.
	{
		roots: []constraintsSpec{
			{
				bad: []string{"email:"},
			},
		},
		intermediates: [][]constraintsSpec{
			{
				{},
			},
		},
		leaf: leafSpec{
			sans: []string{"email:foo@example.com"},
		},
		expectedError: "\"foo@example.com\" is excluded",
	},

	// #73: an empty URI constraint should allow anything
	{
		roots: []constraintsSpec{
			{
				ok: []string{"uri:"},
			},
		},
		intermediates: [][]constraintsSpec{
			{
				{},
			},
		},
		leaf: leafSpec{
			sans: []string{"uri:https://example.com/test"},
		},
	},

	// #74: an empty URI constraint should also reject everything.
	{
		roots: []constraintsSpec{
			{
				bad: []string{"uri:"},
			},
		},
		intermediates: [][]constraintsSpec{
			{
				{},
			},
		},
		leaf: leafSpec{
			sans: []string{"uri:https://example.com/test"},
		},
		expectedError: "\"https://example.com/test\" is excluded",
	},

	// #75: serverAuth in a leaf shouldn't permit clientAuth when requested in
	// VerifyOptions.
	{
		roots: make([]constraintsSpec, 1),
		intermediates: [][]constraintsSpec{
			{
				{},
			},
		},
		leaf: leafSpec{
			sans: []string{"dns:example.com"},
			ekus: []string{"serverAuth"},
		},
		requestedEKUs: []ExtKeyUsage{ExtKeyUsageClientAuth},
		expectedError: "incompatible key usage",
	},

	// #76: MSSGC in a leaf used to match a request for serverAuth, but doesn't
	// anymore.
	{
		roots: make([]constraintsSpec, 1),
		intermediates: [][]constraintsSpec{
			{
				{},
			},
		},
		leaf: leafSpec{
			sans: []string{"dns:example.com"},
			ekus: []string{"msSGC"},
		},
		requestedEKUs: []ExtKeyUsage{ExtKeyUsageServerAuth},
		expectedError: "incompatible key usage",
	},

	// An invalid DNS SAN should be detected only at validation time so
	// that we can process CA certificates in the wild that have invalid SANs.
	// See https://github.com/golang/go/issues/23995

	// #77: an invalid DNS or mail SAN will not be detected if name constraint
	// checking is not triggered.
	{
		roots: make([]constraintsSpec, 1),
		intermediates: [][]constraintsSpec{
			{
				{},
			},
		},
		leaf: leafSpec{
			sans: []string{"dns:this is invalid", "email:this @ is invalid"},
		},
	},

	// #78: an invalid DNS SAN will be detected if any name constraint checking
	// is triggered.
	{
		roots: []constraintsSpec{
			{
				bad: []string{"uri:"},
			},
		},
		intermediates: [][]constraintsSpec{
			{
				{},
			},
		},
		leaf: leafSpec{
			sans: []string{"dns:this is invalid"},
		},
		expectedError: "cannot parse dnsName",
	},

	// #79: an invalid email SAN will be detected if any name constraint
	// checking is triggered.
	{
		roots: []constraintsSpec{
			{
				bad: []string{"uri:"},
			},
		},
		intermediates: [][]constraintsSpec{
			{
				{},
			},
		},
		leaf: leafSpec{
			sans: []string{"email:this @ is invalid"},
		},
		expectedError: "cannot parse rfc822Name",
	},

	// #80: if several EKUs are requested, satisfying any of them is sufficient.
	{
		roots: make([]constraintsSpec, 1),
		intermediates: [][]constraintsSpec{
			{
				{},
			},
		},
		leaf: leafSpec{
			sans: []string{"dns:example.com"},
			ekus: []string{"email"},
		},
		requestedEKUs: []ExtKeyUsage{ExtKeyUsageClientAuth, ExtKeyUsageEmailProtection},
	},

	// #81: EKUs that are not asserted in VerifyOpts are not required to be
	// nested.
	{
		roots: make([]constraintsSpec, 1),
		intermediates: [][]constraintsSpec{
			{
				{
					ekus: []string{"serverAuth"},
				},
			},
		},
		leaf: leafSpec{
			sans: []string{"dns:example.com"},
			// There's no email EKU in the intermediate. This would be rejected if
			// full nesting was required.
			ekus: []string{"email", "serverAuth"},
		},
	},

	// #82: a certificate without SANs and CN is accepted in a constrained chain.
	{
		roots: []constraintsSpec{
			{
				ok: []string{"dns:foo.com", "dns:.foo.com"},
			},
		},
		intermediates: [][]constraintsSpec{
			{
				{},
			},
		},
		leaf: leafSpec{
			sans: []string{},
		},
	},

	// #83: a certificate without SANs and with a CN that does not parse as a
	// hostname is accepted in a constrained chain.
	{
		roots: []constraintsSpec{
			{
				ok: []string{"dns:foo.com", "dns:.foo.com"},
			},
		},
		intermediates: [][]constraintsSpec{
			{
				{},
			},
		},
		leaf: leafSpec{
			sans: []string{},
			cn:   "foo,bar",
		},
	},

	// #84: a certificate with SANs and CN is accepted in a constrained chain.
	{
		roots: []constraintsSpec{
			{
				ok: []string{"dns:foo.com", "dns:.foo.com"},
			},
		},
		intermediates: [][]constraintsSpec{
			{
				{},
			},
		},
		leaf: leafSpec{
			sans: []string{"dns:foo.com"},
			cn:   "foo.bar",
		},
	},

	// #85: .example.com is an invalid DNS name, it should not match the
	// constraint example.com.
	{
		roots:         []constraintsSpec{{ok: []string{"dns:example.com"}}},
		leaf:          leafSpec{sans: []string{"dns:.example.com"}},
		expectedError: "cannot parse dnsName \".example.com\"",
	},
}

func makeConstraintsCACert(constraints constraintsSpec, name string, key *ecdsa.PrivateKey, parent *Certificate, parentKey *ecdsa.PrivateKey) (*Certificate, error) {
	var serialBytes [16]byte
	rand.Read(serialBytes[:])

	template := &Certificate{
		SerialNumber: new(big.Int).SetBytes(serialBytes[:]),
		Subject: pkix.Name{
			CommonName: name,
		},
		NotBefore:             time.Unix(1000, 0),
		NotAfter:              time.Unix(2000, 0),
		KeyUsage:              KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	if err := addConstraintsToTemplate(constraints, template); err != nil {
		return nil, err
	}

	if parent == nil {
		parent = template
	}
	derBytes, err := CreateCertificate(rand.Reader, template, parent, &key.PublicKey, parentKey)
	if err != nil {
		return nil, err
	}

	caCert, err := ParseCertificate(derBytes)
	if err != nil {
		return nil, err
	}

	return caCert, nil
}

func makeConstraintsLeafCert(leaf leafSpec, key *ecdsa.PrivateKey, parent *Certificate, parentKey *ecdsa.PrivateKey) (*Certificate, error) {
	var serialBytes [16]byte
	rand.Read(serialBytes[:])

	template := &Certificate{
		SerialNumber: new(big.Int).SetBytes(serialBytes[:]),
		Subject: pkix.Name{
			OrganizationalUnit: []string{"Leaf"},
			CommonName:         leaf.cn,
		},
		NotBefore:             time.Unix(1000, 0),
		NotAfter:              time.Unix(2000, 0),
		KeyUsage:              KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  false,
	}

	for _, name := range leaf.sans {
		switch {
		case strings.HasPrefix(name, "dns:"):
			template.DNSNames = append(template.DNSNames, name[4:])

		case strings.HasPrefix(name, "ip:"):
			ip := net.ParseIP(name[3:])
			if ip == nil {
				return nil, fmt.Errorf("cannot parse IP %q", name[3:])
			}
			template.IPAddresses = append(template.IPAddresses, ip)

		case strings.HasPrefix(name, "invalidip:"):
			ipBytes, err := hex.DecodeString(name[10:])
			if err != nil {
				return nil, fmt.Errorf("cannot parse invalid IP: %s", err)
			}
			template.IPAddresses = append(template.IPAddresses, net.IP(ipBytes))

		case strings.HasPrefix(name, "email:"):
			template.EmailAddresses = append(template.EmailAddresses, name[6:])

		case strings.HasPrefix(name, "uri:"):
			uri, err := url.Parse(name[4:])
			if err != nil {
				return nil, fmt.Errorf("cannot parse URI %q: %s", name[4:], err)
			}
			template.URIs = append(template.URIs, uri)

		case strings.HasPrefix(name, "unknown:"):
			// This is a special case for testing unknown
			// name types. A custom SAN extension is
			// injected into the certificate.
			if len(leaf.sans) != 1 {
				panic("when using unknown name types, it must be the sole name")
			}

			template.ExtraExtensions = append(template.ExtraExtensions, pkix.Extension{
				Id: []int{2, 5, 29, 17},
				Value: []byte{
					0x30, // SEQUENCE
					3,    // three bytes
					9,    // undefined GeneralName type 9
					1,
					1,
				},
			})

		default:
			return nil, fmt.Errorf("unknown name type %q", name)
		}
	}

	var err erro
"""




```