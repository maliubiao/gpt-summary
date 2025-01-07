Response:
Let's break down the thought process for summarizing the provided Go code snippet.

1. **Understand the Goal:** The request asks for a summary of the Go code's functionality, especially considering it's part of a larger test file (`name_constraints_test.go`). The request emphasizes focusing on the functionality demonstrated in *this specific snippet*.

2. **Initial Skim and Identify Key Functions:**  Read through the code and identify the top-level functions. In this case, they are:
    * `makeConstraintsCACert`
    * `makeConstraintsLeafCert`
    * `customConstraintsExtension`
    * `addConstraintsToTemplate`
    * `parseEKUs`
    * `TestConstraintCases`
    * `writePEMsToTempFile`
    * `testChainAgainstOpenSSL`
    * `rfc2821Tests` and `TestRFC2821Parsing`
    * `TestBadNamesInConstraints`
    * `TestBadNamesInSANs`

3. **Analyze Each Function's Purpose:**  Go through each function and try to understand what it does individually.

    * **`makeConstraintsCACert`:** Creates a certificate, specifically for Certificate Authority (CA) purposes. It takes constraints as input, suggesting it's involved in setting up name constraints.
    * **`makeConstraintsLeafCert`:** Creates a regular (non-CA) certificate, also taking constraints, implying a similar role to the CA function but for end-entity certificates.
    * **`customConstraintsExtension`:**  This function seems to be creating a raw ASN.1 extension for name constraints. The "tag" and "context-specific" keywords are strong indicators of ASN.1 manipulation.
    * **`addConstraintsToTemplate`:** This function takes a `constraintsSpec` and modifies a `Certificate` template. It parses different constraint types (DNS, IP, email, URI) from strings and adds them to the template. It also handles a "special" constraint.
    * **`parseEKUs`:** Parses Extended Key Usage (EKU) strings into their corresponding internal representations.
    * **`TestConstraintCases`:** This is clearly a test function. It iterates through test cases and uses the other functions to create and verify certificate chains, focusing on name constraints. The interaction with `OpenSSL` is also notable.
    * **`writePEMsToTempFile`:** Writes certificate data to a temporary file in PEM format. This is likely used for interacting with external tools like OpenSSL.
    * **`testChainAgainstOpenSSL`:**  This function explicitly runs `openssl` to verify a certificate chain. This is crucial for testing compatibility and correctness against a standard tool.
    * **`rfc2821Tests` and `TestRFC2821Parsing`:**  These are related to parsing email addresses according to RFC 2821. This likely ties into the email address name constraint functionality.
    * **`TestBadNamesInConstraints`:** This test function checks how the code handles invalid input strings for name constraints.
    * **`TestBadNamesInSANs`:** This test function checks how the code handles invalid input strings for Subject Alternative Names (SANs).

4. **Identify the Core Functionality:**  Based on the individual function analysis, it becomes clear that the core purpose of this code is to:
    * **Create certificates with name constraints:** The `makeConstraintsCACert` and `makeConstraintsLeafCert` functions are central to this.
    * **Define and parse name constraints:** The `addConstraintsToTemplate` function handles the parsing of different constraint types.
    * **Represent name constraints in ASN.1:** The `customConstraintsExtension` function shows how name constraints are encoded in the certificate.
    * **Verify certificates against name constraints:** The `TestConstraintCases` function demonstrates the verification logic.
    * **Test against OpenSSL:** The `testChainAgainstOpenSSL` function highlights the importance of interoperability.
    * **Handle different name types:** The code deals with DNS names, IP addresses, email addresses, and URIs.
    * **Validate input:** The "BadNames" test functions show the code's ability to reject invalid input.

5. **Group and Summarize:** Organize the identified functionalities into a coherent summary. Group related functions together. Use clear and concise language. Highlight the key aspects. Mention the testing focus.

6. **Refine and Elaborate (for the initial part of the prompt):** For the first part of the prompt (before the "归纳一下它的功能"), provide specific examples and explain the purpose of each function in more detail. Include code examples where possible (though not explicitly requested for the summary part). Address the other points in the prompt, such as assumptions, input/output, command-line arguments (though less relevant here), and potential pitfalls.

7. **Focus on "归纳一下它的功能":** For the final summarization, be brief and focus on the most important aspects. Avoid going into the details of individual functions unless absolutely necessary for clarity.

8. **Self-Correction/Refinement:** After drafting the summary, review it to ensure accuracy and completeness. Ask yourself:
    * Does this accurately reflect the code's purpose?
    * Is it easy to understand?
    * Are there any missing key aspects?
    * Is it concise enough?

For instance, I might initially focus too much on individual test cases. During refinement, I would realize the higher-level goal is testing the *name constraint functionality* itself, not just the individual cases. Similarly, recognizing the significance of the OpenSSL testing is crucial for a complete understanding.
这是对Go语言 `crypto/x509` 包中关于 **名称约束 (Name Constraints)** 功能的测试代码片段。

**它的主要功能可以归纳为：**

**测试 x509 证书名称约束的生成、解析和验证功能。**  具体来说，它测试了在证书中设置和解释名称约束扩展，以及在证书验证过程中如何根据这些约束来判断证书的有效性。

**更详细的功能分解：**

1. **创建带有名称约束的证书:**  代码中定义了 `makeConstraintsCACert` 和 `makeConstraintsLeafCert` 函数，这两个函数能够创建带有特定名称约束的证书。这些名称约束可以限制证书可以用于哪些域名、IP 地址、邮箱地址和 URI。

2. **定义和添加自定义名称约束扩展:** `customConstraintsExtension` 函数允许创建自定义的名称约束扩展，这可以用于测试一些非标准的或特殊的约束场景。

3. **解析和处理名称约束字符串:** `addConstraintsToTemplate` 函数负责解析各种格式的名称约束字符串 (例如 "dns:example.com", "ip:192.168.1.0/24", "email:user@example.com", "uri:http://example.com")，并将它们添加到证书模板中。

4. **解析扩展密钥用途 (EKU):** `parseEKUs` 函数用于解析表示扩展密钥用途的字符串，例如 "serverAuth" 或 "clientAuth"。

5. **测试不同的名称约束场景:** `TestConstraintCases` 是一个主要的测试函数，它遍历一系列预定义的测试用例 (`nameConstraintsTests`)，每个用例定义了不同的根证书、中间证书、叶子证书以及期望的名称约束。该函数会创建这些证书，并使用 `Verify` 方法来验证叶子证书是否在给定的约束下有效。

6. **与 OpenSSL 进行互操作性测试:**  `testChainAgainstOpenSSL` 函数允许使用 OpenSSL 命令行工具来验证生成的证书链。这有助于确保 Go 语言的实现与广泛使用的 OpenSSL 库的行为一致。

7. **测试邮箱地址解析:** `TestRFC2821Parsing` 函数专门测试了符合 RFC 2821 规范的邮箱地址的解析。这是名称约束中关于邮箱地址约束的基础。

8. **测试错误的名称约束和 SAN:** `TestBadNamesInConstraints` 和 `TestBadNamesInSANs` 函数用于测试代码如何处理无效的或格式错误的名称约束和 Subject Alternative Name (SAN) 输入，确保代码能够正确地拒绝这些不合法的输入。

**Go 语言功能实现示例 (基于代码推理):**

从代码中可以看出，Go 语言的 `crypto/x509` 包通过以下结构体和方法来实现名称约束的功能：

* **`pkix.Extension` 结构体:** 用于表示证书扩展，名称约束也是一个扩展。`Id` 字段通常是 `[]int{2, 5, 29, 30}`，对应于 `nameConstraints` 的 OID。`Value` 字段包含了编码后的名称约束数据。
* **`Certificate` 结构体:**  包含 `PermittedDNSDomains`、`ExcludedDNSDomains`、`PermittedIPRanges`、`ExcludedIPRanges`、`PermittedEmailAddresses`、`ExcludedEmailAddresses`、`PermittedURIDomains`、`ExcludedURIDomains` 等字段，用于存储解析后的名称约束。
* **`VerifyOptions` 结构体:**  在证书验证时，`VerifyOptions` 结构体会被传递给 `Certificate.Verify` 方法。该方法会根据证书中的名称约束，以及 `VerifyOptions` 中的根证书和中间证书，来判断证书的有效性。

**代码示例 (创建带有 DNS 名称约束的证书):**

```go
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"net"
	"os"
	"time"
)

func main() {
	// 创建一个用于测试的私钥
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatal(err)
	}

	// 定义证书模板
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Example Org"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour),
		BasicConstraintsValid: true,
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		SubjectKeyId:          []byte{1, 2, 3},
		// 添加名称约束：只允许 example.com 及其子域名
		PermittedDNSDomains: []string{"example.com"},
	}

	// 使用相同的密钥作为签名者
	certBytes, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	if err != nil {
		log.Fatal(err)
	}

	// 将证书编码为 PEM 格式
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certBytes})
	fmt.Println(string(pemBytes))

	//  ---  验证过程 (简化) ---
	//  假设我们有一个要验证的叶子证书，它的域名是 test.example.com
	leafCert, _ := x509.ParseCertificate(certBytes) // 这里简化了叶子证书的创建

	roots := x509.NewCertPool()
	roots.AddCert(leafCert)

	opts := x509.VerifyOptions{
		Roots: roots,
		DNSName: "test.example.com", // 尝试验证一个在允许域名内的域名
	}

	_, err = leafCert.Verify(opts)
	if err != nil {
		fmt.Println("验证失败:", err)
	} else {
		fmt.Println("验证成功!")
	}

	optsInvalid := x509.VerifyOptions{
		Roots: roots,
		DNSName: "another.com", // 尝试验证一个不在允许域名内的域名
	}

	_, err = leafCert.Verify(optsInvalid)
	if err != nil {
		fmt.Println("预期验证失败:", err)
	} else {
		fmt.Println("意外验证成功!")
	}
}
```

**假设的输入与输出 (针对 `addConstraintsToTemplate` 函数):**

**假设输入:**

```go
constraints := constraintsSpec{
	ok:  []string{"dns:example.com", "ip:192.168.1.0/24", "email:user@example.com"},
	bad: []string{"uri:http://bad.example.com"},
}
template := &x509.Certificate{}
```

**预期输出 (修改后的 `template`):**

```go
&x509.Certificate{
	PermittedDNSDomains:   []string{"example.com"},
	PermittedIPRanges:     []*net.IPNet{/* 包含 192.168.1.0/24 的 net.IPNet 对象 */},
	PermittedEmailAddresses: []string{"user@example.com"},
	ExcludedURIDomains:    []string{"bad.example.com"},
}
```

**使用者易犯错的点:**

* **名称约束的格式错误:**  使用者可能会错误地编写名称约束字符串，例如忘记 "dns:", "ip:" 前缀，或者 IP 地址使用了错误的 CIDR 表示法。这会导致解析错误。

  **示例:** 使用 `"example.com"` 而不是 `"dns:example.com"`。

* **混淆 Permitted 和 Excluded 约束:**  容易混淆哪些约束是允许的，哪些是排除的。错误地配置会导致证书验证出现意外的结果。

* **忽略约束的继承性:**  在证书链中，子证书的约束必须是父证书约束的子集。如果子证书的约束范围超过了父证书，验证将会失败。使用者需要理解这种继承关系。

* **不理解不同约束类型的优先级:**  当存在多种类型的约束时 (例如 DNS 和 IP)，需要理解它们的生效方式。例如，如果同时设置了允许的 DNS 域名和排除的 IP 范围，验证时会同时考虑这两种约束。

总而言之，这个代码片段是 Go 语言 `crypto/x509` 包中名称约束功能的核心测试部分，它涵盖了创建、解析和验证带有名称约束的证书的各种场景，并确保了该功能的正确性和与 OpenSSL 的互操作性。

Prompt: 
```
这是路径为go/src/crypto/x509/name_constraints_test.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第2部分，共2部分，请归纳一下它的功能

"""
r
	if template.ExtKeyUsage, template.UnknownExtKeyUsage, err = parseEKUs(leaf.ekus); err != nil {
		return nil, err
	}

	if parent == nil {
		parent = template
	}

	derBytes, err := CreateCertificate(rand.Reader, template, parent, &key.PublicKey, parentKey)
	if err != nil {
		return nil, err
	}

	return ParseCertificate(derBytes)
}

func customConstraintsExtension(typeNum int, constraint []byte, isExcluded bool) pkix.Extension {
	appendConstraint := func(contents []byte, tag uint8) []byte {
		contents = append(contents, tag|32 /* constructed */ |0x80 /* context-specific */)
		contents = append(contents, byte(4+len(constraint)) /* length */)
		contents = append(contents, 0x30 /* SEQUENCE */)
		contents = append(contents, byte(2+len(constraint)) /* length */)
		contents = append(contents, byte(typeNum) /* GeneralName type */)
		contents = append(contents, byte(len(constraint)))
		return append(contents, constraint...)
	}

	var contents []byte
	if !isExcluded {
		contents = appendConstraint(contents, 0 /* tag 0 for permitted */)
	} else {
		contents = appendConstraint(contents, 1 /* tag 1 for excluded */)
	}

	var value []byte
	value = append(value, 0x30 /* SEQUENCE */)
	value = append(value, byte(len(contents)))
	value = append(value, contents...)

	return pkix.Extension{
		Id:    []int{2, 5, 29, 30},
		Value: value,
	}
}

func addConstraintsToTemplate(constraints constraintsSpec, template *Certificate) error {
	parse := func(constraints []string) (dnsNames []string, ips []*net.IPNet, emailAddrs []string, uriDomains []string, err error) {
		for _, constraint := range constraints {
			switch {
			case strings.HasPrefix(constraint, "dns:"):
				dnsNames = append(dnsNames, constraint[4:])

			case strings.HasPrefix(constraint, "ip:"):
				_, ipNet, err := net.ParseCIDR(constraint[3:])
				if err != nil {
					return nil, nil, nil, nil, err
				}
				ips = append(ips, ipNet)

			case strings.HasPrefix(constraint, "email:"):
				emailAddrs = append(emailAddrs, constraint[6:])

			case strings.HasPrefix(constraint, "uri:"):
				uriDomains = append(uriDomains, constraint[4:])

			default:
				return nil, nil, nil, nil, fmt.Errorf("unknown constraint %q", constraint)
			}
		}

		return dnsNames, ips, emailAddrs, uriDomains, err
	}

	handleSpecialConstraint := func(constraint string, isExcluded bool) bool {
		switch {
		case constraint == "unknown:":
			template.ExtraExtensions = append(template.ExtraExtensions, customConstraintsExtension(9 /* undefined GeneralName type */, []byte{1}, isExcluded))

		default:
			return false
		}

		return true
	}

	if len(constraints.ok) == 1 && len(constraints.bad) == 0 {
		if handleSpecialConstraint(constraints.ok[0], false) {
			return nil
		}
	}

	if len(constraints.bad) == 1 && len(constraints.ok) == 0 {
		if handleSpecialConstraint(constraints.bad[0], true) {
			return nil
		}
	}

	var err error
	template.PermittedDNSDomains, template.PermittedIPRanges, template.PermittedEmailAddresses, template.PermittedURIDomains, err = parse(constraints.ok)
	if err != nil {
		return err
	}

	template.ExcludedDNSDomains, template.ExcludedIPRanges, template.ExcludedEmailAddresses, template.ExcludedURIDomains, err = parse(constraints.bad)
	if err != nil {
		return err
	}

	if template.ExtKeyUsage, template.UnknownExtKeyUsage, err = parseEKUs(constraints.ekus); err != nil {
		return err
	}

	return nil
}

func parseEKUs(ekuStrs []string) (ekus []ExtKeyUsage, unknowns []asn1.ObjectIdentifier, err error) {
	for _, s := range ekuStrs {
		switch s {
		case "serverAuth":
			ekus = append(ekus, ExtKeyUsageServerAuth)
		case "clientAuth":
			ekus = append(ekus, ExtKeyUsageClientAuth)
		case "email":
			ekus = append(ekus, ExtKeyUsageEmailProtection)
		case "netscapeSGC":
			ekus = append(ekus, ExtKeyUsageNetscapeServerGatedCrypto)
		case "msSGC":
			ekus = append(ekus, ExtKeyUsageMicrosoftServerGatedCrypto)
		case "any":
			ekus = append(ekus, ExtKeyUsageAny)
		case "other":
			unknowns = append(unknowns, asn1.ObjectIdentifier{2, 4, 1, 2, 3})
		default:
			return nil, nil, fmt.Errorf("unknown EKU %q", s)
		}
	}

	return
}

func TestConstraintCases(t *testing.T) {
	privateKeys := sync.Pool{
		New: func() any {
			priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			if err != nil {
				panic(err)
			}
			return priv
		},
	}

	for i, test := range nameConstraintsTests {
		t.Run(fmt.Sprintf("#%d", i), func(t *testing.T) {
			rootPool := NewCertPool()
			rootKey := privateKeys.Get().(*ecdsa.PrivateKey)
			rootName := "Root " + strconv.Itoa(i)

			// keys keeps track of all the private keys used in a given
			// test and puts them back in the privateKeys pool at the end.
			keys := []*ecdsa.PrivateKey{rootKey}

			// At each level (root, intermediate(s), leaf), parent points to
			// an example parent certificate and parentKey the key for the
			// parent level. Since all certificates at a given level have
			// the same name and public key, any parent certificate is
			// sufficient to get the correct issuer name and authority
			// key ID.
			var parent *Certificate
			parentKey := rootKey

			for _, root := range test.roots {
				rootCert, err := makeConstraintsCACert(root, rootName, rootKey, nil, rootKey)
				if err != nil {
					t.Fatalf("failed to create root: %s", err)
				}

				parent = rootCert
				rootPool.AddCert(rootCert)
			}

			intermediatePool := NewCertPool()

			for level, intermediates := range test.intermediates {
				levelKey := privateKeys.Get().(*ecdsa.PrivateKey)
				keys = append(keys, levelKey)
				levelName := "Intermediate level " + strconv.Itoa(level)
				var last *Certificate

				for _, intermediate := range intermediates {
					caCert, err := makeConstraintsCACert(intermediate, levelName, levelKey, parent, parentKey)
					if err != nil {
						t.Fatalf("failed to create %q: %s", levelName, err)
					}

					last = caCert
					intermediatePool.AddCert(caCert)
				}

				parent = last
				parentKey = levelKey
			}

			leafKey := privateKeys.Get().(*ecdsa.PrivateKey)
			keys = append(keys, leafKey)

			leafCert, err := makeConstraintsLeafCert(test.leaf, leafKey, parent, parentKey)
			if err != nil {
				t.Fatalf("cannot create leaf: %s", err)
			}

			// Skip tests with CommonName set because OpenSSL will try to match it
			// against name constraints, while we ignore it when it's not hostname-looking.
			if !test.noOpenSSL && testNameConstraintsAgainstOpenSSL && test.leaf.cn == "" {
				output, err := testChainAgainstOpenSSL(t, leafCert, intermediatePool, rootPool)
				if err == nil && len(test.expectedError) > 0 {
					t.Error("unexpectedly succeeded against OpenSSL")
					if debugOpenSSLFailure {
						return
					}
				}

				if err != nil {
					if _, ok := err.(*exec.ExitError); !ok {
						t.Errorf("OpenSSL failed to run: %s", err)
					} else if len(test.expectedError) == 0 {
						t.Errorf("OpenSSL unexpectedly failed: %v", output)
						if debugOpenSSLFailure {
							return
						}
					}
				}
			}

			verifyOpts := VerifyOptions{
				Roots:         rootPool,
				Intermediates: intermediatePool,
				CurrentTime:   time.Unix(1500, 0),
				KeyUsages:     test.requestedEKUs,
			}
			_, err = leafCert.Verify(verifyOpts)

			logInfo := true
			if len(test.expectedError) == 0 {
				if err != nil {
					t.Errorf("unexpected failure: %s", err)
				} else {
					logInfo = false
				}
			} else {
				if err == nil {
					t.Error("unexpected success")
				} else if !strings.Contains(err.Error(), test.expectedError) {
					t.Errorf("expected error containing %q, but got: %s", test.expectedError, err)
				} else {
					logInfo = false
				}
			}

			if logInfo {
				certAsPEM := func(cert *Certificate) string {
					var buf bytes.Buffer
					pem.Encode(&buf, &pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
					return buf.String()
				}
				t.Errorf("root:\n%s", certAsPEM(rootPool.mustCert(t, 0)))
				if intermediates := allCerts(t, intermediatePool); len(intermediates) > 0 {
					for ii, intermediate := range intermediates {
						t.Errorf("intermediate %d:\n%s", ii, certAsPEM(intermediate))
					}
				}
				t.Errorf("leaf:\n%s", certAsPEM(leafCert))
			}

			for _, key := range keys {
				privateKeys.Put(key)
			}
		})
	}
}

func writePEMsToTempFile(certs []*Certificate) *os.File {
	file, err := os.CreateTemp("", "name_constraints_test")
	if err != nil {
		panic("cannot create tempfile")
	}

	pemBlock := &pem.Block{Type: "CERTIFICATE"}
	for _, cert := range certs {
		pemBlock.Bytes = cert.Raw
		pem.Encode(file, pemBlock)
	}

	return file
}

func testChainAgainstOpenSSL(t *testing.T, leaf *Certificate, intermediates, roots *CertPool) (string, error) {
	args := []string{"verify", "-no_check_time"}

	rootsFile := writePEMsToTempFile(allCerts(t, roots))
	if debugOpenSSLFailure {
		println("roots file:", rootsFile.Name())
	} else {
		defer os.Remove(rootsFile.Name())
	}
	args = append(args, "-CAfile", rootsFile.Name())

	if intermediates.len() > 0 {
		intermediatesFile := writePEMsToTempFile(allCerts(t, intermediates))
		if debugOpenSSLFailure {
			println("intermediates file:", intermediatesFile.Name())
		} else {
			defer os.Remove(intermediatesFile.Name())
		}
		args = append(args, "-untrusted", intermediatesFile.Name())
	}

	leafFile := writePEMsToTempFile([]*Certificate{leaf})
	if debugOpenSSLFailure {
		println("leaf file:", leafFile.Name())
	} else {
		defer os.Remove(leafFile.Name())
	}
	args = append(args, leafFile.Name())

	var output bytes.Buffer
	cmd := exec.Command("openssl", args...)
	cmd.Stdout = &output
	cmd.Stderr = &output

	err := cmd.Run()
	return output.String(), err
}

var rfc2821Tests = []struct {
	in                string
	localPart, domain string
}{
	{"foo@example.com", "foo", "example.com"},
	{"@example.com", "", ""},
	{"\"@example.com", "", ""},
	{"\"\"@example.com", "", "example.com"},
	{"\"a\"@example.com", "a", "example.com"},
	{"\"\\a\"@example.com", "a", "example.com"},
	{"a\"@example.com", "", ""},
	{"foo..bar@example.com", "", ""},
	{".foo.bar@example.com", "", ""},
	{"foo.bar.@example.com", "", ""},
	{"|{}?'@example.com", "|{}?'", "example.com"},

	// Examples from RFC 3696
	{"Abc\\@def@example.com", "Abc@def", "example.com"},
	{"Fred\\ Bloggs@example.com", "Fred Bloggs", "example.com"},
	{"Joe.\\\\Blow@example.com", "Joe.\\Blow", "example.com"},
	{"\"Abc@def\"@example.com", "Abc@def", "example.com"},
	{"\"Fred Bloggs\"@example.com", "Fred Bloggs", "example.com"},
	{"customer/department=shipping@example.com", "customer/department=shipping", "example.com"},
	{"$A12345@example.com", "$A12345", "example.com"},
	{"!def!xyz%abc@example.com", "!def!xyz%abc", "example.com"},
	{"_somename@example.com", "_somename", "example.com"},
}

func TestRFC2821Parsing(t *testing.T) {
	for i, test := range rfc2821Tests {
		mailbox, ok := parseRFC2821Mailbox(test.in)
		expectedFailure := len(test.localPart) == 0 && len(test.domain) == 0

		if ok && expectedFailure {
			t.Errorf("#%d: %q unexpectedly parsed as (%q, %q)", i, test.in, mailbox.local, mailbox.domain)
			continue
		}

		if !ok && !expectedFailure {
			t.Errorf("#%d: unexpected failure for %q", i, test.in)
			continue
		}

		if !ok {
			continue
		}

		if mailbox.local != test.localPart || mailbox.domain != test.domain {
			t.Errorf("#%d: %q parsed as (%q, %q), but wanted (%q, %q)", i, test.in, mailbox.local, mailbox.domain, test.localPart, test.domain)
		}
	}
}

func TestBadNamesInConstraints(t *testing.T) {
	constraintParseError := func(err error) bool {
		str := err.Error()
		return strings.Contains(str, "failed to parse ") && strings.Contains(str, "constraint")
	}

	encodingError := func(err error) bool {
		return strings.Contains(err.Error(), "cannot be encoded as an IA5String")
	}

	// Bad names in constraints should not parse.
	badNames := []struct {
		name    string
		matcher func(error) bool
	}{
		{"dns:foo.com.", constraintParseError},
		{"email:abc@foo.com.", constraintParseError},
		{"email:foo.com.", constraintParseError},
		{"uri:example.com.", constraintParseError},
		{"uri:1.2.3.4", constraintParseError},
		{"uri:ffff::1", constraintParseError},
		{"dns:not–hyphen.com", encodingError},
		{"email:foo@not–hyphen.com", encodingError},
		{"uri:not–hyphen.com", encodingError},
	}

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}

	for _, test := range badNames {
		_, err := makeConstraintsCACert(constraintsSpec{
			ok: []string{test.name},
		}, "TestAbsoluteNamesInConstraints", priv, nil, priv)

		if err == nil {
			t.Errorf("bad name %q unexpectedly accepted in name constraint", test.name)
			continue
		} else {
			if !test.matcher(err) {
				t.Errorf("bad name %q triggered unrecognised error: %s", test.name, err)
			}
		}
	}
}

func TestBadNamesInSANs(t *testing.T) {
	// Bad names in URI and IP SANs should not parse. Bad DNS and email SANs
	// will parse and are tested in name constraint tests at the top of this
	// file.
	badNames := []string{
		"uri:https://example.com./dsf",
		"invalidip:0102",
		"invalidip:0102030405",
	}

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}

	for _, badName := range badNames {
		_, err := makeConstraintsLeafCert(leafSpec{sans: []string{badName}}, priv, nil, priv)

		if err == nil {
			t.Errorf("bad name %q unexpectedly accepted in SAN", badName)
			continue
		}

		if str := err.Error(); !strings.Contains(str, "cannot parse ") {
			t.Errorf("bad name %q triggered unrecognised error: %s", badName, str)
		}
	}
}

"""




```