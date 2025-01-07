Response:
Let's break down the thought process for analyzing this Go code snippet and fulfilling the request.

1. **Understanding the Goal:** The request asks for an analysis of a Go test file (`verify_test.go`) related to X.509 certificate verification. The output needs to cover functionality, potential Go language features being tested, code examples (with input/output if applicable), handling of command-line arguments (though unlikely in a test file), common mistakes, and a summary of the functionality. The request also specifies that this is part 3 of 4.

2. **Initial Scan and Keyword Identification:** I'll quickly scan the code for key terms and patterns:
    * `package`: `x509` - confirms the area of focus.
    * `import`: Standard testing (`testing`), crypto libraries (`crypto`, `ecdsa`, `elliptic`), standard libraries (`fmt`, `errors`, `strings`, `time`, `math/big`, `runtime`, `os/exec`, `strconv`, `slices`), and the `internal/testenv` package.
    * Function names:  `TestValidHostname`, `generateCert`, `TestPathologicalChain`, `TestLongChain`, `TestSystemRootsError`, `TestSystemRootsErrorUnwrap`, `macosMajorVersion`, `TestIssue51759`, `trustGraphEdge`, `rootDescription`, `trustGraphDescription`, `genCertEdge`, `buildTrustGraph`, `chainsToStrings`, `TestPathBuilding`, `TestEKUEnforcement`. The "Test..." prefixes clearly indicate test functions. Other names suggest helper functions for certificate generation and graph manipulation.
    * Constants: `criticalExtRoot`, `criticalExtIntermediate`, etc. - These are likely PEM-encoded certificates used in tests.
    * Structs: `trustGraphEdge`, `rootDescription`, `trustGraphDescription` -  These are data structures for defining test scenarios, particularly for path building.

3. **Categorizing Functionality:** Based on the function names and imported packages, I can start grouping the functionality:
    * **Hostname Validation:** `TestValidHostname`, `validHostnamePattern`, `validHostnameInput`.
    * **Certificate Generation:** `generateCert`.
    * **Chain Verification:**  `TestPathologicalChain`, `TestLongChain`, `TestSystemRootsError`, `TestSystemRootsErrorUnwrap`, `TestIssue51759`, `TestPathBuilding`, `TestEKUEnforcement`. This seems to be the core focus.
    * **macOS Version Check:** `macosMajorVersion` - likely specific to a platform-dependent test.
    * **Test Data Structures:** `trustGraphEdge`, `rootDescription`, `trustGraphDescription`.
    * **Helper Functions for Test Setup:** `genCertEdge`, `buildTrustGraph`, `chainsToStrings`.

4. **Deep Dive into Key Functions:** I'll pick some of the more complex or central functions for closer inspection:
    * **`TestValidHostname`:** Iterates through test cases to validate hostname patterns and inputs. This is a straightforward test of string validation logic.
    * **`generateCert`:**  Generates a self-signed or subordinate certificate based on provided parameters. It uses the `crypto/ecdsa` and `crypto/x509` packages.
    * **`TestPathologicalChain` and `TestLongChain`:** These test the performance and limitations of chain verification with very deep chains. The difference likely lies in the structure of the intermediate certificates.
    * **`TestSystemRootsError` and `TestSystemRootsErrorUnwrap`:**  Specifically test the handling of errors when system root certificates are not available.
    * **`TestIssue51759`:**  Targets a specific bug related to certificate parsing on macOS.
    * **`TestPathBuilding`:**  This is a significant test that uses the `trustGraphDescription` to define complex certificate graphs and verifies that the correct valid paths are found. This is a core part of certificate path validation logic.
    * **`TestEKUEnforcement`:**  Focuses on testing the enforcement of Extended Key Usage (EKU) during certificate verification.

5. **Identifying Go Language Features:**  As I analyze the code, I note the Go features being used:
    * **Testing framework (`testing`):**  The `Test...` functions and `t *testing.T` parameter.
    * **Structs:**  Used to define test cases and data structures.
    * **Slices:** Used extensively for storing certificates and chains.
    * **Maps:** Used in `buildTrustGraph` to store certificates and keys.
    * **Interfaces (`crypto.PrivateKey`, `crypto.Signer`):**  For working with cryptographic keys.
    * **Error handling:**  Returning and checking errors. The `errors.Is` function is used in `TestSystemRootsErrorUnwrap`.
    * **Closures (anonymous functions):** Used in `TestPathBuilding` within the `trustGraphEdge` and `rootDescription` structs.
    * **Constants:** For storing PEM-encoded certificates.
    * **String manipulation:**  Functions from the `strings` package.
    * **Time manipulation:** Functions from the `time` package.
    * **Platform-specific logic:** Using `runtime.GOOS` to skip tests on certain operating systems.
    * **External commands:** Using `os/exec` in `macosMajorVersion`.

6. **Inferring Functionality and Generating Examples:**  Based on the function names and code, I can infer the purpose and create illustrative examples where needed (though the request didn't demand examples for *every* function). For example, the `TestValidHostname` function clearly tests the `validHostnamePattern` and `validHostnameInput` functions.

7. **Considering Command-Line Arguments:** I'll review the code for any use of `os.Args` or the `flag` package. In this test file, it's highly unlikely to find command-line argument processing, so I'll note that.

8. **Identifying Potential Mistakes:** I consider what errors developers might make when using the `crypto/x509` package based on the tests being performed. For example, misinterpreting wildcard matching in hostnames, incorrect configuration of `VerifyOptions`, or not handling `SystemRootsError`.

9. **Structuring the Output:** I organize the analysis according to the request's points: functionality, Go features, code examples, command-line arguments, common mistakes, and summary.

10. **Drafting and Refining:** I write the initial draft of the analysis and then review and refine it for clarity, accuracy, and completeness. I ensure the language is Chinese as requested. I also pay attention to the "part 3 of 4" instruction for the summary.

This iterative process of scanning, categorizing, analyzing, inferring, and structuring allows me to systematically understand the purpose and functionality of the given Go code snippet and generate a comprehensive response.
```chinese
这是路径为go/src/crypto/x509/verify_test.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明,
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第3部分，共4部分，请归纳一下它的功能
```

基于提供的代码片段，我们可以归纳出 `go/src/crypto/x509/verify_test.go` 的以下功能：

**核心功能：X.509 证书链验证的单元测试**

这段代码主要用于测试 Go 语言 `crypto/x509` 包中证书链验证相关的功能。它包含了多个测试函数，模拟各种场景来验证证书链的有效性、错误处理以及特定边界情况。

**具体功能点：**

1. **主机名验证测试 (`TestValidHostname`)：**
   - 测试 `validHostnamePattern` 和 `validHostnameInput` 函数，这两个函数用于验证给定的字符串是否符合主机名或主机名模式的规范。
   - **示例：**
     ```go
     func TestValidHostname(t *testing.T) {
         tests := []struct {
             host                     string
             validInput, validPattern bool
         }{
             {host: "example.com", validInput: true, validPattern: true},
             {host: "*.example.com", validPattern: true},
             {host: "-eXample123-.com"}, // 期望 validInput 和 validPattern 都是 false
         }
         for _, tt := range tests {
             if got := validHostnamePattern(tt.host); got != tt.validPattern {
                 t.Errorf("validHostnamePattern(%q) = %v, want %v", tt.host, got, tt.validPattern)
             }
             if got := validHostnameInput(tt.host); got != tt.validInput {
                 t.Errorf("validHostnameInput(%q) = %v, want %v", tt.host, got, tt.validInput)
             }
         }
     }
     ```
   - **假设输入:** 一系列字符串，例如 "example.com", "*.example.com", "-invalid.com"。
   - **预期输出:** 测试断言会检查 `validHostnamePattern` 和 `validHostnameInput` 的返回值是否与预期相符。

2. **证书生成辅助函数 (`generateCert`)：**
   - 提供一个方便生成测试用证书的函数，可以生成根证书、中间证书和叶子证书。
   - **示例：**
     ```go
     func generateCert(cn string, isCA bool, issuer *Certificate, issuerKey crypto.PrivateKey) (*Certificate, crypto.PrivateKey, error) {
         // ... (代码实现) ...
     }

     func TestSomeCertificateVerification(t *testing.T) {
         rootCert, rootKey, err := generateCert("Root CA", true, nil, nil)
         if err != nil {
             t.Fatal(err)
         }
         // ... 使用 rootCert 进行后续测试 ...
     }
     ```
   - **假设输入:**  证书的通用名称 (CN)、是否为 CA 证书、颁发者证书和颁发者私钥。
   - **预期输出:** 返回生成的 `*Certificate` 和对应的私钥，如果发生错误则返回 error。

3. **病态证书链测试 (`TestPathologicalChain`)：**
   - 测试处理包含大量相同主题的中间证书的病态证书链时的性能和限制，验证是否会触发签名检查次数限制。
   - **目的:** 验证代码在遇到可能导致无限循环或性能问题的证书链时是否能正确处理。

4. **长证书链测试 (`TestLongChain`)：**
   - 测试验证较长但合法的证书链的性能。
   - **目的:** 确保在常见的长链场景下验证的效率和正确性。

5. **系统根证书错误测试 (`TestSystemRootsError` 和 `TestSystemRootsErrorUnwrap`)：**
   - 测试在无法加载系统根证书时是否会返回特定的 `SystemRootsError` 错误。
   - `TestSystemRootsErrorUnwrap` 测试了 `SystemRootsError` 的 `Unwrap` 方法是否能正确返回内部的错误。
   - **目的:** 验证在特定环境（例如没有系统根证书）下，验证过程的错误处理是否符合预期。

6. **macOS 特定问题测试 (`TestIssue51759`)：**
   - 针对 macOS 平台上的一个特定 issue (51759) 编写的测试，该 issue 与 macOS 的 `SecCertificateCreateWithData` 函数拒绝某些 Go 可以解析的证书有关。
   - **目的:** 确保在 macOS 上也能正确处理特定的证书格式问题。
   - **涉及命令行参数：** `macosMajorVersion` 函数会执行 `sw_vers -productVersion` 命令来获取 macOS 的主版本号。 这就是命令行参数的具体处理。

7. **证书信任图构建和路径查找测试 (`TestPathBuilding`)：**
   - 使用 `trustGraphDescription` 结构体定义复杂的证书信任图，包括根证书、中间证书和叶子证书之间的关系。
   - 测试证书链构建和路径查找的逻辑，验证是否能找到所有有效的证书链，并排除无效的链。
   - 包含了各种复杂的场景，例如包含策略约束、扩展密钥用途 (EKU) 约束、名称约束等。
   - **示例：** `trustGraphDescription` 结构体定义了证书之间的颁发关系和类型，`trustGraphEdge` 定义了具体的证书关系，并可以指定一些突变函数来修改证书模板。
   - **假设输入:** 一个 `trustGraphDescription` 结构体，描述了一个证书信任图。
   - **预期输出:**  验证找到的证书链是否与 `expectedChains` 中定义的相符，或者验证是否返回了预期的错误。

8. **扩展密钥用途 (EKU) 强制执行测试 (`TestEKUEnforcement`)：**
   - 测试证书链验证过程中对 EKU 扩展的强制执行情况。
   - 验证只有当证书链中所有证书的 EKU 都包含所需的 EKU 时，验证才会成功。

**涉及的 Go 语言功能实现推理：**

这段代码主要测试 `crypto/x509` 包中以下功能的实现：

- **证书解析 (`ParseCertificate`)**：用于将 PEM 或 DER 编码的证书数据解析为 `Certificate` 结构体。
- **证书创建 (`CreateCertificate`)**：用于根据模板创建新的证书。
- **证书验证 (`Verify`)**：这是核心功能，用于验证证书链的有效性，包括签名验证、时间有效性、密钥用途、扩展约束等。
- **证书池 (`CertPool`)**：用于存储受信任的根证书和中间证书。
- **主机名验证 (`validHostnamePattern`, `validHostnameInput`)**：用于检查主机名是否符合规范。
- **错误类型 (`SystemRootsError`)**：定义了无法加载系统根证书时返回的特定错误类型。

**命令行参数的具体处理：**

在提供的代码片段中，**`macosMajorVersion` 函数是唯一涉及命令行参数处理的地方**。它使用 `internal/testenv` 包中的 `Command` 函数来执行 `sw_vers -productVersion` 命令，并解析其输出以获取 macOS 的主版本号。

**使用者易犯错的点：**

虽然这是测试代码，但可以推断出使用者在使用 `crypto/x509` 包时容易犯的错误：

- **不正确的 `VerifyOptions` 配置：** 例如，没有提供正确的根证书或中间证书池，或者没有设置正确的 `CurrentTime` 进行时间验证。
- **主机名验证的误解：** 对通配符主机名匹配规则理解不透彻，导致验证失败。
- **忽略 `SystemRootsError`：** 在某些环境下（例如 Docker 容器），可能无法访问系统根证书，需要提供自定义的根证书池。
- **对扩展约束理解不足：** 例如，对名称约束、策略约束、EKU 约束的理解不足，导致验证结果与预期不符。

**归纳一下它的功能 (作为第 3 部分，共 4 部分)：**

作为 X.509 证书验证测试的第三部分，这段代码片段主要关注**复杂证书链场景的验证**。它深入测试了路径构建算法，包括处理包含循环、无效 EKU、名称约束等情况的证书链。此外，它还针对 macOS 平台上的特定证书处理问题进行了测试。  与前一部分可能关注基础的证书解析和验证不同，这一部分着重于验证在更复杂的、贴近实际应用场景下的证书链验证逻辑的正确性和健壮性。 结合后续部分，可以更全面地了解整个证书验证测试的覆盖范围。

Prompt: 
```
这是路径为go/src/crypto/x509/verify_test.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第3部分，共4部分，请归纳一下它的功能

"""
wMDAw
MDBaMB0xDDAKBgNVBAoTA09yZzENMAsGA1UEAxMEUm9vdDBZMBMGByqGSM49AgEG
CCqGSM49AwEHA0IABJGp9joiG2QSQA+1FczEDAsWo84rFiP3GTL+n+ugcS6TyNib
gzMsdbJgVi+a33y0SzLZxB+YvU3/4KTk8yKLC+2jejB4MA4GA1UdDwEB/wQEAwIC
BDAdBgNVHSUEFjAUBggrBgEFBQcDAQYIKwYBBQUHAwIwDwYDVR0TAQH/BAUwAwEB
/zAZBgNVHQ4EEgQQQDfXAftAL7gcflQEJ4xZATAbBgNVHSMEFDASgBBAN9cB+0Av
uBx+VAQnjFkBMAoGCCqGSM49BAMCA0gAMEUCIFeSV00fABFceWR52K+CfIgOHotY
FizzGiLB47hGwjMuAiEA8e0um2Kr8FPQ4wmFKaTRKHMaZizCGl3m+RG5QsE1KWo=
-----END CERTIFICATE-----`

const criticalExtIntermediate = `-----BEGIN CERTIFICATE-----
MIIBszCCAVmgAwIBAgIJAL2kcGZKpzVqMAoGCCqGSM49BAMCMB0xDDAKBgNVBAoT
A09yZzENMAsGA1UEAxMEUm9vdDAeFw0xNTAxMDEwMDAwMDBaFw0yNTAxMDEwMDAw
MDBaMCUxDDAKBgNVBAoTA09yZzEVMBMGA1UEAxMMSW50ZXJtZWRpYXRlMFkwEwYH
KoZIzj0CAQYIKoZIzj0DAQcDQgAESqVq92iPEq01cL4o99WiXDc5GZjpjNlzMS1n
rk8oHcVDp4tQRRQG3F4A6dF1rn/L923ha3b0fhDLlAvXZB+7EKN6MHgwDgYDVR0P
AQH/BAQDAgIEMB0GA1UdJQQWMBQGCCsGAQUFBwMBBggrBgEFBQcDAjAPBgNVHRMB
Af8EBTADAQH/MBkGA1UdDgQSBBCMGmiotXbbXVd7H40UsgajMBsGA1UdIwQUMBKA
EEA31wH7QC+4HH5UBCeMWQEwCgYIKoZIzj0EAwIDSAAwRQIhAOhhNRb6KV7h3wbE
cdap8bojzvUcPD78fbsQPCNw1jPxAiBOeAJhlTwpKn9KHpeJphYSzydj9NqcS26Y
xXbdbm27KQ==
-----END CERTIFICATE-----`

const criticalExtLeafWithExt = `-----BEGIN CERTIFICATE-----
MIIBxTCCAWugAwIBAgIJAJZAUtw5ccb1MAoGCCqGSM49BAMCMCUxDDAKBgNVBAoT
A09yZzEVMBMGA1UEAxMMSW50ZXJtZWRpYXRlMB4XDTE1MDEwMTAwMDAwMFoXDTI1
MDEwMTAwMDAwMFowJDEMMAoGA1UEChMDT3JnMRQwEgYDVQQDEwtleGFtcGxlLmNv
bTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABF3ABa2+B6gUyg6ayCaRQWYY/+No
6PceLqEavZNUeVNuz7bS74Toy8I7R3bGMkMgbKpLSPlPTroAATvebTXoBaijgYQw
gYEwDgYDVR0PAQH/BAQDAgWgMB0GA1UdJQQWMBQGCCsGAQUFBwMBBggrBgEFBQcD
AjAMBgNVHRMBAf8EAjAAMBkGA1UdDgQSBBBRNtBL2vq8nCV3qVp7ycxMMBsGA1Ud
IwQUMBKAEIwaaKi1dttdV3sfjRSyBqMwCgYDUQMEAQH/BAAwCgYIKoZIzj0EAwID
SAAwRQIgVjy8GBgZFiagexEuDLqtGjIRJQtBcf7lYgf6XFPH1h4CIQCT6nHhGo6E
I+crEm4P5q72AnA/Iy0m24l7OvLuXObAmg==
-----END CERTIFICATE-----`

const criticalExtIntermediateWithExt = `-----BEGIN CERTIFICATE-----
MIIB2TCCAX6gAwIBAgIIQD3NrSZtcUUwCgYIKoZIzj0EAwIwHTEMMAoGA1UEChMD
T3JnMQ0wCwYDVQQDEwRSb290MB4XDTE1MDEwMTAwMDAwMFoXDTI1MDEwMTAwMDAw
MFowPTEMMAoGA1UEChMDT3JnMS0wKwYDVQQDEyRJbnRlcm1lZGlhdGUgd2l0aCBD
cml0aWNhbCBFeHRlbnNpb24wWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQtnmzH
mcRm10bdDBnJE7xQEJ25cLCL5okuEphRR0Zneo6+nQZikoh+UBbtt5GV3Dms7LeP
oF5HOplYDCd8wi/wo4GHMIGEMA4GA1UdDwEB/wQEAwICBDAdBgNVHSUEFjAUBggr
BgEFBQcDAQYIKwYBBQUHAwIwDwYDVR0TAQH/BAUwAwEB/zAZBgNVHQ4EEgQQKxdv
UuQZ6sO3XvBsxgNZ3zAbBgNVHSMEFDASgBBAN9cB+0AvuBx+VAQnjFkBMAoGA1ED
BAEB/wQAMAoGCCqGSM49BAMCA0kAMEYCIQCQzTPd6XKex+OAPsKT/1DsoMsg8vcG
c2qZ4Q0apT/kvgIhAKu2TnNQMIUdcO0BYQIl+Uhxc78dc9h4lO+YJB47pHGx
-----END CERTIFICATE-----`

const criticalExtLeaf = `-----BEGIN CERTIFICATE-----
MIIBzzCCAXWgAwIBAgIJANoWFIlhCI9MMAoGCCqGSM49BAMCMD0xDDAKBgNVBAoT
A09yZzEtMCsGA1UEAxMkSW50ZXJtZWRpYXRlIHdpdGggQ3JpdGljYWwgRXh0ZW5z
aW9uMB4XDTE1MDEwMTAwMDAwMFoXDTI1MDEwMTAwMDAwMFowJDEMMAoGA1UEChMD
T3JnMRQwEgYDVQQDEwtleGFtcGxlLmNvbTBZMBMGByqGSM49AgEGCCqGSM49AwEH
A0IABG1Lfh8A0Ho2UvZN5H0+ONil9c8jwtC0y0xIZftyQE+Fwr9XwqG3rV2g4M1h
GnJa9lV9MPHg8+b85Hixm0ZSw7SjdzB1MA4GA1UdDwEB/wQEAwIFoDAdBgNVHSUE
FjAUBggrBgEFBQcDAQYIKwYBBQUHAwIwDAYDVR0TAQH/BAIwADAZBgNVHQ4EEgQQ
UNhY4JhezH9gQYqvDMWrWDAbBgNVHSMEFDASgBArF29S5Bnqw7de8GzGA1nfMAoG
CCqGSM49BAMCA0gAMEUCIQClA3d4tdrDu9Eb5ZBpgyC+fU1xTZB0dKQHz6M5fPZA
2AIgN96lM+CPGicwhN24uQI6flOsO3H0TJ5lNzBYLtnQtlc=
-----END CERTIFICATE-----`

func TestValidHostname(t *testing.T) {
	tests := []struct {
		host                     string
		validInput, validPattern bool
	}{
		{host: "example.com", validInput: true, validPattern: true},
		{host: "eXample123-.com", validInput: true, validPattern: true},
		{host: "-eXample123-.com"},
		{host: ""},
		{host: "."},
		{host: "example..com"},
		{host: ".example.com"},
		{host: "example.com.", validInput: true},
		{host: "*.example.com."},
		{host: "*.example.com", validPattern: true},
		{host: "*foo.example.com"},
		{host: "foo.*.example.com"},
		{host: "exa_mple.com", validInput: true, validPattern: true},
		{host: "foo,bar"},
		{host: "project-dev:us-central1:main"},
	}
	for _, tt := range tests {
		if got := validHostnamePattern(tt.host); got != tt.validPattern {
			t.Errorf("validHostnamePattern(%q) = %v, want %v", tt.host, got, tt.validPattern)
		}
		if got := validHostnameInput(tt.host); got != tt.validInput {
			t.Errorf("validHostnameInput(%q) = %v, want %v", tt.host, got, tt.validInput)
		}
	}
}

func generateCert(cn string, isCA bool, issuer *Certificate, issuerKey crypto.PrivateKey) (*Certificate, crypto.PrivateKey, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, _ := rand.Int(rand.Reader, serialNumberLimit)

	template := &Certificate{
		SerialNumber: serialNumber,
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),

		KeyUsage:              KeyUsageKeyEncipherment | KeyUsageDigitalSignature | KeyUsageCertSign,
		ExtKeyUsage:           []ExtKeyUsage{ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  isCA,
	}
	if issuer == nil {
		issuer = template
		issuerKey = priv
	}

	derBytes, err := CreateCertificate(rand.Reader, template, issuer, priv.Public(), issuerKey)
	if err != nil {
		return nil, nil, err
	}
	cert, err := ParseCertificate(derBytes)
	if err != nil {
		return nil, nil, err
	}

	return cert, priv, nil
}

func TestPathologicalChain(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping generation of a long chain of certificates in short mode")
	}

	// Build a chain where all intermediates share the same subject, to hit the
	// path building worst behavior.
	roots, intermediates := NewCertPool(), NewCertPool()

	parent, parentKey, err := generateCert("Root CA", true, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	roots.AddCert(parent)

	for i := 1; i < 100; i++ {
		parent, parentKey, err = generateCert("Intermediate CA", true, parent, parentKey)
		if err != nil {
			t.Fatal(err)
		}
		intermediates.AddCert(parent)
	}

	leaf, _, err := generateCert("Leaf", false, parent, parentKey)
	if err != nil {
		t.Fatal(err)
	}

	start := time.Now()
	_, err = leaf.Verify(VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
	})
	t.Logf("verification took %v", time.Since(start))

	if err == nil || !strings.Contains(err.Error(), "signature check attempts limit") {
		t.Errorf("expected verification to fail with a signature checks limit error; got %v", err)
	}
}

func TestLongChain(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping generation of a long chain of certificates in short mode")
	}

	roots, intermediates := NewCertPool(), NewCertPool()

	parent, parentKey, err := generateCert("Root CA", true, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	roots.AddCert(parent)

	for i := 1; i < 15; i++ {
		name := fmt.Sprintf("Intermediate CA #%d", i)
		parent, parentKey, err = generateCert(name, true, parent, parentKey)
		if err != nil {
			t.Fatal(err)
		}
		intermediates.AddCert(parent)
	}

	leaf, _, err := generateCert("Leaf", false, parent, parentKey)
	if err != nil {
		t.Fatal(err)
	}

	start := time.Now()
	if _, err := leaf.Verify(VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
	}); err != nil {
		t.Error(err)
	}
	t.Logf("verification took %v", time.Since(start))
}

func TestSystemRootsError(t *testing.T) {
	if runtime.GOOS == "windows" || runtime.GOOS == "darwin" || runtime.GOOS == "ios" {
		t.Skip("Windows and darwin do not use (or support) systemRoots")
	}

	defer func(oldSystemRoots *CertPool) { systemRoots = oldSystemRoots }(systemRootsPool())

	opts := VerifyOptions{
		Intermediates: NewCertPool(),
		DNSName:       "www.google.com",
		CurrentTime:   time.Unix(1677615892, 0),
	}

	if ok := opts.Intermediates.AppendCertsFromPEM([]byte(gtsIntermediate)); !ok {
		t.Fatalf("failed to parse intermediate")
	}

	leaf, err := certificateFromPEM(googleLeaf)
	if err != nil {
		t.Fatalf("failed to parse leaf: %v", err)
	}

	systemRoots = nil

	_, err = leaf.Verify(opts)
	if _, ok := err.(SystemRootsError); !ok {
		t.Errorf("error was not SystemRootsError: %v", err)
	}
}

func TestSystemRootsErrorUnwrap(t *testing.T) {
	var err1 = errors.New("err1")
	err := SystemRootsError{Err: err1}
	if !errors.Is(err, err1) {
		t.Error("errors.Is failed, wanted success")
	}
}

func macosMajorVersion(t *testing.T) (int, error) {
	cmd := testenv.Command(t, "sw_vers", "-productVersion")
	out, err := cmd.Output()
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok && len(ee.Stderr) > 0 {
			return 0, fmt.Errorf("%v: %v\n%s", cmd, err, ee.Stderr)
		}
		return 0, fmt.Errorf("%v: %v", cmd, err)
	}
	before, _, ok := strings.Cut(string(out), ".")
	major, err := strconv.Atoi(before)
	if !ok || err != nil {
		return 0, fmt.Errorf("%v: unexpected output: %q", cmd, out)
	}

	return major, nil
}

func TestIssue51759(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("only affects darwin")
	}

	testenv.MustHaveExecPath(t, "sw_vers")
	if vers, err := macosMajorVersion(t); err != nil {
		if builder := testenv.Builder(); builder != "" {
			t.Fatalf("unable to determine macOS version: %s", err)
		} else {
			t.Skip("unable to determine macOS version")
		}
	} else if vers < 11 {
		t.Skip("behavior only enforced in macOS 11 and after")
	}

	// badCertData contains a cert that we parse as valid
	// but that macOS SecCertificateCreateWithData rejects.
	const badCertData = "0\x82\x01U0\x82\x01\a\xa0\x03\x02\x01\x02\x02\x01\x020\x05\x06\x03+ep0R1P0N\x06\x03U\x04\x03\x13Gderpkey8dc58100b2493614ee1692831a461f3f4dd3f9b3b088e244f887f81b4906ac260\x1e\x17\r220112235755Z\x17\r220313235755Z0R1P0N\x06\x03U\x04\x03\x13Gderpkey8dc58100b2493614ee1692831a461f3f4dd3f9b3b088e244f887f81b4906ac260*0\x05\x06\x03+ep\x03!\x00bA\xd8e\xadW\xcb\xefZ\x89\xb5\"\x1eR\x9d\xba\x0e:\x1042Q@\u007f\xbd\xfb{ks\x04\xd1£\x020\x000\x05\x06\x03+ep\x03A\x00[\xa7\x06y\x86(\x94\x97\x9eLwA\x00\x01x\xaa\xbc\xbd Ê]\n(΅!ف0\xf5\x9a%I\x19<\xffo\xf1\xeaaf@\xb1\xa7\xaf\xfd\xe9R\xc7\x0f\x8d&\xd5\xfc\x0f;Ϙ\x82\x84a\xbc\r"
	badCert, err := ParseCertificate([]byte(badCertData))
	if err != nil {
		t.Fatal(err)
	}

	t.Run("leaf", func(t *testing.T) {
		opts := VerifyOptions{}
		expectedErr := "invalid leaf certificate"
		_, err = badCert.Verify(opts)
		if err == nil || err.Error() != expectedErr {
			t.Fatalf("unexpected error: want %q, got %q", expectedErr, err)
		}
	})

	goodCert, err := certificateFromPEM(googleLeaf)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("intermediate", func(t *testing.T) {
		opts := VerifyOptions{
			Intermediates: NewCertPool(),
		}
		opts.Intermediates.AddCert(badCert)
		expectedErr := "SecCertificateCreateWithData: invalid certificate"
		_, err = goodCert.Verify(opts)
		if err == nil || err.Error() != expectedErr {
			t.Fatalf("unexpected error: want %q, got %q", expectedErr, err)
		}
	})
}

type trustGraphEdge struct {
	Issuer         string
	Subject        string
	Type           int
	MutateTemplate func(*Certificate)
	Constraint     func([]*Certificate) error
}

type rootDescription struct {
	Subject        string
	MutateTemplate func(*Certificate)
	Constraint     func([]*Certificate) error
}

type trustGraphDescription struct {
	Roots []rootDescription
	Leaf  string
	Graph []trustGraphEdge
}

func genCertEdge(t *testing.T, subject string, key crypto.Signer, mutateTmpl func(*Certificate), certType int, issuer *Certificate, signer crypto.Signer) *Certificate {
	t.Helper()

	serial, err := rand.Int(rand.Reader, big.NewInt(100))
	if err != nil {
		t.Fatalf("failed to generate test serial: %s", err)
	}
	tmpl := &Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: subject},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	if certType == rootCertificate || certType == intermediateCertificate {
		tmpl.IsCA, tmpl.BasicConstraintsValid = true, true
		tmpl.KeyUsage = KeyUsageCertSign
	} else if certType == leafCertificate {
		tmpl.DNSNames = []string{"localhost"}
	}
	if mutateTmpl != nil {
		mutateTmpl(tmpl)
	}

	if certType == rootCertificate {
		issuer = tmpl
		signer = key
	}

	d, err := CreateCertificate(rand.Reader, tmpl, issuer, key.Public(), signer)
	if err != nil {
		t.Fatalf("failed to generate test cert: %s", err)
	}
	c, err := ParseCertificate(d)
	if err != nil {
		t.Fatalf("failed to parse test cert: %s", err)
	}
	return c
}

func buildTrustGraph(t *testing.T, d trustGraphDescription) (*CertPool, *CertPool, *Certificate) {
	t.Helper()

	certs := map[string]*Certificate{}
	keys := map[string]crypto.Signer{}
	rootPool := NewCertPool()
	for _, r := range d.Roots {
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatalf("failed to generate test key: %s", err)
		}
		root := genCertEdge(t, r.Subject, k, r.MutateTemplate, rootCertificate, nil, nil)
		if r.Constraint != nil {
			rootPool.AddCertWithConstraint(root, r.Constraint)
		} else {
			rootPool.AddCert(root)
		}
		certs[r.Subject] = root
		keys[r.Subject] = k
	}

	intermediatePool := NewCertPool()
	var leaf *Certificate
	for _, e := range d.Graph {
		issuerCert, ok := certs[e.Issuer]
		if !ok {
			t.Fatalf("unknown issuer %s", e.Issuer)
		}
		issuerKey, ok := keys[e.Issuer]
		if !ok {
			t.Fatalf("unknown issuer %s", e.Issuer)
		}

		k, ok := keys[e.Subject]
		if !ok {
			var err error
			k, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			if err != nil {
				t.Fatalf("failed to generate test key: %s", err)
			}
			keys[e.Subject] = k
		}
		cert := genCertEdge(t, e.Subject, k, e.MutateTemplate, e.Type, issuerCert, issuerKey)
		certs[e.Subject] = cert
		if e.Subject == d.Leaf {
			leaf = cert
		} else {
			if e.Constraint != nil {
				intermediatePool.AddCertWithConstraint(cert, e.Constraint)
			} else {
				intermediatePool.AddCert(cert)
			}
		}
	}

	return rootPool, intermediatePool, leaf
}

func chainsToStrings(chains [][]*Certificate) []string {
	chainStrings := []string{}
	for _, chain := range chains {
		names := []string{}
		for _, c := range chain {
			names = append(names, c.Subject.String())
		}
		chainStrings = append(chainStrings, strings.Join(names, " -> "))
	}
	slices.Sort(chainStrings)
	return chainStrings
}

func TestPathBuilding(t *testing.T) {
	tests := []struct {
		name           string
		graph          trustGraphDescription
		expectedChains []string
		expectedErr    string
	}{
		{
			// Build the following graph from RFC 4158, figure 7 (note that in this graph edges represent
			// certificates where the parent is the issuer and the child is the subject.) For the certificate
			// C->B, use an unsupported ExtKeyUsage (in this case ExtKeyUsageCodeSigning) which invalidates
			// the path Trust Anchor -> C -> B -> EE. The remaining valid paths should be:
			//   * Trust Anchor -> A -> B -> EE
			//   * Trust Anchor -> C -> A -> B -> EE
			//
			//     +---------+
			//     |  Trust  |
			//     | Anchor  |
			//     +---------+
			//      |       |
			//      v       v
			//   +---+    +---+
			//   | A |<-->| C |
			//   +---+    +---+
			//    |         |
			//    |  +---+  |
			//    +->| B |<-+
			//       +---+
			//         |
			//         v
			//       +----+
			//       | EE |
			//       +----+
			name: "bad EKU",
			graph: trustGraphDescription{
				Roots: []rootDescription{{Subject: "root"}},
				Leaf:  "leaf",
				Graph: []trustGraphEdge{
					{
						Issuer:  "root",
						Subject: "inter a",
						Type:    intermediateCertificate,
					},
					{
						Issuer:  "root",
						Subject: "inter c",
						Type:    intermediateCertificate,
					},
					{
						Issuer:  "inter c",
						Subject: "inter a",
						Type:    intermediateCertificate,
					},
					{
						Issuer:  "inter a",
						Subject: "inter c",
						Type:    intermediateCertificate,
					},
					{
						Issuer:  "inter c",
						Subject: "inter b",
						Type:    intermediateCertificate,
						MutateTemplate: func(t *Certificate) {
							t.ExtKeyUsage = []ExtKeyUsage{ExtKeyUsageCodeSigning}
						},
					},
					{
						Issuer:  "inter a",
						Subject: "inter b",
						Type:    intermediateCertificate,
					},
					{
						Issuer:  "inter b",
						Subject: "leaf",
						Type:    leafCertificate,
					},
				},
			},
			expectedChains: []string{
				"CN=leaf -> CN=inter b -> CN=inter a -> CN=inter c -> CN=root",
				"CN=leaf -> CN=inter b -> CN=inter a -> CN=root",
			},
		},
		{
			// Build the following graph from RFC 4158, figure 7 (note that in this graph edges represent
			// certificates where the parent is the issuer and the child is the subject.) For the certificate
			// C->B, use a unconstrained SAN which invalidates the path Trust Anchor -> C -> B -> EE. The
			// remaining valid paths should be:
			//   * Trust Anchor -> A -> B -> EE
			//   * Trust Anchor -> C -> A -> B -> EE
			//
			//     +---------+
			//     |  Trust  |
			//     | Anchor  |
			//     +---------+
			//      |       |
			//      v       v
			//   +---+    +---+
			//   | A |<-->| C |
			//   +---+    +---+
			//    |         |
			//    |  +---+  |
			//    +->| B |<-+
			//       +---+
			//         |
			//         v
			//       +----+
			//       | EE |
			//       +----+
			name: "bad EKU",
			graph: trustGraphDescription{
				Roots: []rootDescription{{Subject: "root"}},
				Leaf:  "leaf",
				Graph: []trustGraphEdge{
					{
						Issuer:  "root",
						Subject: "inter a",
						Type:    intermediateCertificate,
					},
					{
						Issuer:  "root",
						Subject: "inter c",
						Type:    intermediateCertificate,
					},
					{
						Issuer:  "inter c",
						Subject: "inter a",
						Type:    intermediateCertificate,
					},
					{
						Issuer:  "inter a",
						Subject: "inter c",
						Type:    intermediateCertificate,
					},
					{
						Issuer:  "inter c",
						Subject: "inter b",
						Type:    intermediateCertificate,
						MutateTemplate: func(t *Certificate) {
							t.PermittedDNSDomains = []string{"good"}
							t.DNSNames = []string{"bad"}
						},
					},
					{
						Issuer:  "inter a",
						Subject: "inter b",
						Type:    intermediateCertificate,
					},
					{
						Issuer:  "inter b",
						Subject: "leaf",
						Type:    leafCertificate,
					},
				},
			},
			expectedChains: []string{
				"CN=leaf -> CN=inter b -> CN=inter a -> CN=inter c -> CN=root",
				"CN=leaf -> CN=inter b -> CN=inter a -> CN=root",
			},
		},
		{
			// Build the following graph, we should find both paths:
			//   * Trust Anchor -> A -> C -> EE
			//   * Trust Anchor -> A -> B -> C -> EE
			//
			//	       +---------+
			//	       |  Trust  |
			//	       | Anchor  |
			//	       +---------+
			//	            |
			//	            v
			//	          +---+
			//	          | A |
			//	          +---+
			//	           | |
			//	           | +----+
			//	           |      v
			//	           |    +---+
			//	           |    | B |
			//	           |    +---+
			//	           |      |
			//	           |  +---v
			//	           v  v
			//            +---+
			//            | C |
			//            +---+
			//              |
			//              v
			//            +----+
			//            | EE |
			//            +----+
			name: "all paths",
			graph: trustGraphDescription{
				Roots: []rootDescription{{Subject: "root"}},
				Leaf:  "leaf",
				Graph: []trustGraphEdge{
					{
						Issuer:  "root",
						Subject: "inter a",
						Type:    intermediateCertificate,
					},
					{
						Issuer:  "inter a",
						Subject: "inter b",
						Type:    intermediateCertificate,
					},
					{
						Issuer:  "inter a",
						Subject: "inter c",
						Type:    intermediateCertificate,
					},
					{
						Issuer:  "inter b",
						Subject: "inter c",
						Type:    intermediateCertificate,
					},
					{
						Issuer:  "inter c",
						Subject: "leaf",
						Type:    leafCertificate,
					},
				},
			},
			expectedChains: []string{
				"CN=leaf -> CN=inter c -> CN=inter a -> CN=root",
				"CN=leaf -> CN=inter c -> CN=inter b -> CN=inter a -> CN=root",
			},
		},
		{
			// Build the following graph, which contains a cross-signature loop
			// (A and C cross sign each other). Paths that include the A -> C -> A
			// (and vice versa) loop should be ignored, resulting in the paths:
			//   * Trust Anchor -> A -> B -> EE
			//   * Trust Anchor -> C -> B -> EE
			//   * Trust Anchor -> A -> C -> B -> EE
			//   * Trust Anchor -> C -> A -> B -> EE
			//
			//     +---------+
			//     |  Trust  |
			//     | Anchor  |
			//     +---------+
			//      |       |
			//      v       v
			//   +---+    +---+
			//   | A |<-->| C |
			//   +---+    +---+
			//    |         |
			//    |  +---+  |
			//    +->| B |<-+
			//       +---+
			//         |
			//         v
			//       +----+
			//       | EE |
			//       +----+
			name: "ignore cross-sig loops",
			graph: trustGraphDescription{
				Roots: []rootDescription{{Subject: "root"}},
				Leaf:  "leaf",
				Graph: []trustGraphEdge{
					{
						Issuer:  "root",
						Subject: "inter a",
						Type:    intermediateCertificate,
					},
					{
						Issuer:  "root",
						Subject: "inter c",
						Type:    intermediateCertificate,
					},
					{
						Issuer:  "inter c",
						Subject: "inter a",
						Type:    intermediateCertificate,
					},
					{
						Issuer:  "inter a",
						Subject: "inter c",
						Type:    intermediateCertificate,
					},
					{
						Issuer:  "inter c",
						Subject: "inter b",
						Type:    intermediateCertificate,
					},
					{
						Issuer:  "inter a",
						Subject: "inter b",
						Type:    intermediateCertificate,
					},
					{
						Issuer:  "inter b",
						Subject: "leaf",
						Type:    leafCertificate,
					},
				},
			},
			expectedChains: []string{
				"CN=leaf -> CN=inter b -> CN=inter a -> CN=inter c -> CN=root",
				"CN=leaf -> CN=inter b -> CN=inter a -> CN=root",
				"CN=leaf -> CN=inter b -> CN=inter c -> CN=inter a -> CN=root",
				"CN=leaf -> CN=inter b -> CN=inter c -> CN=root",
			},
		},
		{
			// Build a simple two node graph, where the leaf is directly issued from
			// the root and both certificates have matching subject and public key, but
			// the leaf has SANs.
			name: "leaf with same subject, key, as parent but with SAN",
			graph: trustGraphDescription{
				Roots: []rootDescription{{Subject: "root"}},
				Leaf:  "root",
				Graph: []trustGraphEdge{
					{
						Issuer:  "root",
						Subject: "root",
						Type:    leafCertificate,
						MutateTemplate: func(c *Certificate) {
							c.DNSNames = []string{"localhost"}
						},
					},
				},
			},
			expectedChains: []string{
				"CN=root -> CN=root",
			},
		},
		{
			// Build a basic graph with two paths from leaf to root, but the path passing
			// through C should be ignored, because it has invalid EKU nesting.
			name: "ignore invalid EKU path",
			graph: trustGraphDescription{
				Roots: []rootDescription{{Subject: "root"}},
				Leaf:  "leaf",
				Graph: []trustGraphEdge{
					{
						Issuer:  "root",
						Subject: "inter a",
						Type:    intermediateCertificate,
					},
					{
						Issuer:  "root",
						Subject: "inter c",
						Type:    intermediateCertificate,
					},
					{
						Issuer:  "inter c",
						Subject: "inter b",
						Type:    intermediateCertificate,
						MutateTemplate: func(t *Certificate) {
							t.ExtKeyUsage = []ExtKeyUsage{ExtKeyUsageCodeSigning}
						},
					},
					{
						Issuer:  "inter a",
						Subject: "inter b",
						Type:    intermediateCertificate,
						MutateTemplate: func(t *Certificate) {
							t.ExtKeyUsage = []ExtKeyUsage{ExtKeyUsageServerAuth}
						},
					},
					{
						Issuer:  "inter b",
						Subject: "leaf",
						Type:    leafCertificate,
						MutateTemplate: func(t *Certificate) {
							t.ExtKeyUsage = []ExtKeyUsage{ExtKeyUsageServerAuth}
						},
					},
				},
			},
			expectedChains: []string{
				"CN=leaf -> CN=inter b -> CN=inter a -> CN=root",
			},
		},
		{
			// A name constraint on the root should apply to any names that appear
			// on the intermediate, meaning there is no valid chain.
			name: "constrained root, invalid intermediate",
			graph: trustGraphDescription{
				Roots: []rootDescription{
					{
						Subject: "root",
						MutateTemplate: func(t *Certificate) {
							t.PermittedDNSDomains = []string{"example.com"}
						},
					},
				},
				Leaf: "leaf",
				Graph: []trustGraphEdge{
					{
						Issuer:  "root",
						Subject: "inter",
						Type:    intermediateCertificate,
						MutateTemplate: func(t *Certificate) {
							t.DNSNames = []string{"beep.com"}
						},
					},
					{
						Issuer:  "inter",
						Subject: "leaf",
						Type:    leafCertificate,
						MutateTemplate: func(t *Certificate) {
							t.DNSNames = []string{"www.example.com"}
						},
					},
				},
			},
			expectedErr: "x509: a root or intermediate certificate is not authorized to sign for this name: DNS name \"beep.com\" is not permitted by any constraint",
		},
		{
			// A name constraint on the intermediate does not apply to the intermediate
			// itself, so this is a valid chain.
			name: "constrained intermediate, non-matching SAN",
			graph: trustGraphDescription{
				Roots: []rootDescription{{Subject: "root"}},
				Leaf:  "leaf",
				Graph: []trustGraphEdge{
					{
						Issuer:  "root",
						Subject: "inter",
						Type:    intermediateCertificate,
						MutateTemplate: func(t *Certificate) {
							t.DNSNames = []string{"beep.com"}
							t.PermittedDNSDomains = []string{"example.com"}
						},
					},
					{
						Issuer:  "inter",
						Subject: "leaf",
						Type:    leafCertificate,
						MutateTemplate: func(t *Certificate) {
							t.DNSNames = []string{"www.example.com"}
						},
					},
				},
			},
			expectedChains: []string{"CN=leaf -> CN=inter -> CN=root"},
		},
		{
			// A code constraint on the root, applying to one of two intermediates in the graph, should
			// result in only one valid chain.
			name: "code constrained root, two paths, one valid",
			graph: trustGraphDescription{
				Roots: []rootDescription{{Subject: "root", Constraint: func(chain []*Certificate) error {
					for _, c := range chain {
						if c.Subject.CommonName == "inter a" {
							return errors.New("bad")
						}
					}
					return nil
				}}},
				Leaf: "leaf",
				Graph: []trustGraphEdge{
					{
						Issuer:  "root",
						Subject: "inter a",
						Type:    intermediateCertificate,
					},
					{
						Issuer:  "root",
						Subject: "inter b",
						Type:    intermediateCertificate,
					},
					{
						Issuer:  "inter a",
						Subject: "inter c",
						Type:    intermediateCertificate,
					},
					{
						Issuer:  "inter b",
						Subject: "inter c",
						Type:    intermediateCertificate,
					},
					{
						Issuer:  "inter c",
						Subject: "leaf",
						Type:    leafCertificate,
					},
				},
			},
			expectedChains: []string{"CN=leaf -> CN=inter c -> CN=inter b -> CN=root"},
		},
		{
			// A code constraint on the root, applying to the only path, should result in an error.
			name: "code constrained root, one invalid path",
			graph: trustGraphDescription{
				Roots: []rootDescription{{Subject: "root", Constraint: func(chain []*Certificate) error {
					for _, c := range chain {
						if c.Subject.CommonName == "leaf" {
							return errors.New("bad")
						}
					}
					return nil
				}}},
				Leaf: "leaf",
				Graph: []trustGraphEdge{
					{
						Issuer:  "root",
						Subject: "inter",
						Type:    intermediateCertificate,
					},
					{
						Issuer:  "inter",
						Subject: "leaf",
						Type:    leafCertificate,
					},
				},
			},
			expectedErr: "x509: certificate signed by unknown authority (possibly because of \"bad\" while trying to verify candidate authority certificate \"root\")",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			roots, intermediates, leaf := buildTrustGraph(t, tc.graph)
			chains, err := leaf.Verify(VerifyOptions{
				Roots:         roots,
				Intermediates: intermediates,
			})
			if err != nil && err.Error() != tc.expectedErr {
				t.Fatalf("unexpected error: got %q, want %q", err, tc.expectedErr)
			}
			if len(tc.expectedChains) == 0 {
				return
			}
			gotChains := chainsToStrings(chains)
			if !slices.Equal(gotChains, tc.expectedChains) {
				t.Errorf("unexpected chains returned:\ngot:\n\t%s\nwant:\n\t%s", strings.Join(gotChains, "\n\t"), strings.Join(tc.expectedChains, "\n\t"))
			}
		})
	}
}

func TestEKUEnforcement(t *testing.T) {
	type ekuDescs struct {
		EKUs    []ExtKeyUsage
		Unknown []asn1.ObjectIdentifier
	}
	tests := []struct {
		name       string
		root       ekuDescs
		inters     []ekuDescs
		leaf       ekuDescs
		verifyEKUs []ExtKeyUsage
		err        string
	}{
		{
			name:       "valid, full chain",
			root:       ekuDescs{EKUs: []ExtKeyUsage{ExtKeyUsageServerAuth}},
			inters:     []ekuDescs{ekuDescs{EKUs: []ExtKeyUsage{ExtKeyUsageServerAuth}}},
			leaf:       ekuDescs{EKUs: []ExtKeyUsage{ExtKeyUsageServerAuth}},
			verifyEKUs: []ExtKeyUsage{ExtKeyUsageServerAuth},
		},
		{
			name:       "valid, only leaf has EKU",
			root:       ekuDescs{},
			inters:     []ekuDescs{ekuDescs{}},
			leaf:       ekuDescs{EKUs: []ExtKeyUsage{ExtKeyUsageServerAuth}},
			verifyEKUs: []ExtKeyUsage{ExtKeyUsageServerAuth},
		},
		{
			name:       "invalid, serverAuth not nested",
			root:       ekuDescs{EKUs: []ExtKeyUsage{ExtKeyUsageClientAuth}},
			inters:     []ekuDescs{ekuDescs{EKUs: []ExtKeyUsage{ExtKeyUsageServerAuth, ExtKeyUsageClientAuth}}},
			leaf:       ekuDescs{EKUs: []ExtKeyUsage{ExtKeyUsageServerAuth, ExtKeyUsageClientAuth}},
			verifyEKUs: []ExtKeyUsage{ExtKeyUsageServerAuth},
			err:        "x509: certificate specifies an incompatible key usage",
		},
		{
			name:       "valid, two EKUs, one path",
			root:       ekuDescs{EKUs: []ExtKeyUsage{ExtKeyUsageServerAuth}},
			inters:     []ekuDescs{ekuDescs{EKUs: []ExtKeyUsage{ExtKeyUsageServerAuth, ExtKeyUsageClientAuth}}},
			leaf:       ekuDescs{EKUs: []ExtKeyUsage{ExtKeyUsageServerAuth, ExtKeyUsageClientAuth}},
			verifyEKUs: []ExtKeyUsage{ExtKeyUsageServerAuth, ExtKeyUsageClientAuth},
		},
		{
			name: "invalid, ladder",
			root: ekuDescs{EKUs: []ExtKeyUsage{ExtKeyUsageServerAuth}},
			inters: []ekuDescs{
				ekuDescs{EKUs: []ExtKeyUsage{ExtKeyUsageServerAuth, ExtKeyUsageClientAuth}},
				ekuDescs{EKUs: []ExtKeyUsage{ExtKeyUsageClientAuth}},
				ekuDescs{EKUs: []ExtKeyUsage{ExtKeyUsageServerAuth, ExtKeyUsageClientAuth}},
				ekuDescs{EKUs: []ExtKeyUsage{ExtKeyUsageServerAuth}},
			},
			leaf:       ekuDescs{EKUs: []ExtKeyUsage{ExtKeyUsageServerAuth}},
			verifyEKUs: []ExtKeyUsage{ExtKeyUsageServerAuth, ExtKeyUsageClientAuth},
			err:        "x509: certificate specifies an incompatible key usage",
		},
		{
			name:       "valid, intermediate has no EKU",
			root:       ekuDescs{EKUs: []ExtKeyUsage{ExtKeyUsageServerAuth}},
			inters:     []ekuDescs{ekuDescs{}},
			leaf:       ekuDescs{EKUs: []ExtKeyUsage{ExtKeyUsageServerAuth}},
			verifyEKUs: []ExtKeyUsage{ExtKeyUsageServerAuth},
		},
		{
			name:       "invalid, intermediate has no EKU and no nested path",
			root:       ekuDescs{EKUs: []ExtKeyUsage{ExtKeyUsageClientAuth}},
			inters:     []ekuDescs{ekuDescs{}},
			leaf:       ekuDescs{EKUs: []ExtKeyUsage{ExtKeyUsageServerAuth}},
			verifyEKUs: []ExtKeyUsage{ExtKeyUsageServerAuth, ExtKeyUsageClientAuth},
			err:        "x509: certificate specifies an incompatible key usage",
		},
		{
			name:       "invalid, intermediate has unknown EKU",
			root:       ekuDescs{EKUs: []ExtKeyUsage{ExtKeyUsageServerAuth}},
			inters:     []ekuDescs{ekuDescs{Unknown: []asn1.ObjectIdentifier{{1, 2, 3}}}},
			leaf:       ekuDescs{EKUs: []ExtKeyUsage{ExtKeyUsageServerAuth}},
			verifyEKUs: []ExtKeyUsage{ExtKeyUsageServerAuth},
			err:        "x509: certificate specifies an incompatible key usage",
		},
	}

	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate test key: %s", err)
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rootPool := NewCertPool()
			root := genCertEdge(t, "root", k, func(c *Certificate) {
				c.ExtKeyUsage = tc.root.EKUs
				c.UnknownExtKeyUsage = tc.root.Unknown
			}, rootCertificate, nil, k)
			rootPool.AddCert(root)

			parent := root
			interPool := NewCertPool()
			for i, interEKUs := range tc.inters {
				inter := genCertEdge(t, fmt.Sprintf("inter %d", i), k, func(c *Certificate) {
					c.ExtKeyUsage = interEKUs.EKUs
					c.UnknownExtKeyUsage = interEKUs.Unknown
				}, intermediateCertificate, parent, k)
				interPool.AddCert(inter)
				parent = inter
			}

			leaf := genCertEdge(t, "leaf", k, func(c *Certificate) {
				c.ExtKeyUsage = tc.leaf.EKUs
				c.UnknownExtKeyUs
"""




```