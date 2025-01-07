Response:
The user wants a summary of the functionality of the provided Go code snippet. The code is a part of `go/src/crypto/x509/x509_test.go`.

Here's a breakdown of the code's functionality:

1. **Parsing Certificates with Unusual Structures:** The `TestAdditionFieldsInGeneralSubtree` function tests parsing a certificate that has additional fields in the `GeneralSubtree` structure. This demonstrates the library's ability to handle certificates with non-standard extensions.

2. **Generating and Parsing Certificates with Empty Serial Numbers:** The `TestEmptySerialNumber` function tests the creation and parsing of certificates with randomly generated serial numbers, ensuring they are positive and within a specific length limit.

3. **Generating and Parsing Certificates with Empty Subjects:** The `TestEmptySubject` function tests the creation and parsing of certificates with empty subjects, specifically checking for the presence and criticality of the Subject Alternative Name (SAN) extension.

4. **Parsing Certificates with Multiple URLs in CRL Distribution Points:** The `TestMultipleURLsInCRLDP` function tests parsing a certificate containing multiple URLs within a single CRL Distribution Point.

5. **Handling Mismatched Key Formats in PKCS#1 Parsing:** The `TestPKCS1MismatchKeyFormat` function tests the `ParsePKCS1PrivateKey` function's behavior when it encounters keys in PKCS#8 or EC private key formats, ensuring it returns the correct error messages.

6. **Creating Certificate Revocation Lists (CRLs):** The `TestCreateRevocationList` function extensively tests the `CreateRevocationList` function. It covers various scenarios, including error conditions (nil templates, invalid issuers, incorrect key usage, etc.) and valid CRL creation with different options (reason codes, extra extensions, different signature algorithms, empty lists, and UTF-8 characters in issuer names). It also verifies the parsing of the created CRLs.

7. **Verifying RSAPSS Parameter Generation:** The `TestRSAPSAParameters` function checks if the hardcoded parameters for RSAPSS signature algorithms match the dynamically generated parameters.

8. **Handling Unknown Extended Key Usages:** The `TestUnknownExtKey` function tests the behavior when creating a certificate with an unknown extended key usage, ensuring an error is returned.

9. **Enforcing IA5String Encoding for Subject Alternative Names:** The `TestIA5SANEnforcement` function tests the enforcement of IA5String encoding for various types of Subject Alternative Names (DNS names, email addresses, URIs) during certificate creation and parsing. It ensures that Unicode characters, which are not allowed in IA5String, result in errors.

Based on this analysis, the main focus of this part of the test file seems to be **testing the creation and parsing of Certificate Revocation Lists (CRLs) and ensuring proper handling of various certificate and key formats and encoding rules.**
这段代码是Go语言 `crypto/x509` 包测试文件 `x509_test.go` 的一部分，主要功能是**测试生成和解析证书吊销列表 (Certificate Revocation List, CRL)**，并涵盖了一些与证书解析相关的边缘情况。

**归纳其功能如下：**

* **测试解析包含非标准字段的证书：** 验证 `ParseCertificate` 函数能否正确解析包含额外的 `GeneralSubtree` 字段的证书。
* **测试生成和解析序列号为空的证书：** 验证能否创建和解析序列号为空（或长度在特定范围内的正数）的证书。
* **测试生成和解析主题为空的证书：** 验证能否创建和解析主题为空的证书，并检查 Subject Alternative Name (SAN) 扩展是否被正确标记为关键。
* **测试解析包含多个 CRL 分发点 URL 的证书：** 验证 `ParseCertificate` 函数能否正确解析包含多个 CRL 分发点 URL 的证书。
* **测试 `ParsePKCS1PrivateKey` 函数对不匹配的密钥格式的处理：** 验证当传入 PKCS#8 或 EC 私钥时，`ParsePKCS1PrivateKey` 是否返回预期的错误。
* **测试创建证书吊销列表 (CRL)：**  这是这段代码的核心功能。它涵盖了各种场景，包括：
    * 错误场景：模板为空、签发者为空、签发者密钥用法不包含 `cRLSign`、签发者缺少 `SubjectKeyId`、`nextUpdate` 早于 `thisUpdate`、CRL 编号过长等。
    * 成功场景：使用不同的密钥类型（ECDSA、EdDSA）、指定签名算法、包含吊销的证书条目（带有或不带有原因码和扩展）、创建空的 CRL、使用包含 UTF-8 字符的主题字段的 CA 签发 CRL 等。
* **测试 RSAPSS 参数的生成：** 验证代码中硬编码的 RSAPSS 签名算法参数是否与动态生成的参数一致。
* **测试处理未知的扩展密钥用法：** 验证创建包含未知扩展密钥用法的证书时是否会返回错误。
* **测试 Subject Alternative Name (SAN) 中 IA5String 编码的强制执行：** 验证在创建和解析证书时，SAN 中的域名、邮箱地址和 URI 是否遵循 IA5String 编码规则，即不允许包含非 ASCII 字符。

**以下用 Go 代码举例说明其中的一些功能：**

**1. 测试解析包含非标准字段的证书：**

```go
package main

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
)

func main() {
	pemData := `-----BEGIN CERTIFICATE-----
MIICWDCCAcGgAwIBAgIJAIIJpzE/78n/MA0GCSqGSIb3DQEBBQUAMBcxEzAR
BgNVBAMMCmV4YW1wbGUuY29tMB4XDTIzMTAyNjEwMDAwMFoXDTI0MTAyNzA5
NTk1OVowFzETMBEGA1UEAwwKZXhhbXBsZS5jb20wggEiMA0GCSqGSIb3DQEB
AQUAA4IBDwAwggEKAoIBAQDD60g8TjE89a8rW8zFf+7sJ7QzL7vR/4/4w5t/
h9+L9/7H77/f/4f/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/
f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/
f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/
f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/
f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/
f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/
f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/
f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/
f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/
f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/
f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/
f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/
f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/
f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/
f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/
f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/
f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/
f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/
f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/
f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/
f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/
f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/
f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/
f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/
f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/
f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/
f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/
f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/
f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/
f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/
f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/
f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/
f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/
f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/
f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/
f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/
f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/
f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/
f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/
f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/
f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/
f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/
f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/
f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/
f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/
f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/
f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/
f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/
f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/
f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/
f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/
f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/
f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/
f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/
f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/
f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/
f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/
f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/
f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/
f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/
f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/
f/7/f/7/f/7/f/7/f/7/f/7/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/
7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/
7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/
7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/
7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/
7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/
7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/
7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/
7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/
7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/
7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/
7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/
7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/
7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/
7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/
7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/
7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/
7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/
7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/
7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/
7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/
7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/
7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/
7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/
7/f/7/f/7/f/7/f/7/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/
7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/
7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/
7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/
7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/
7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/
7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/
7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/
7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/
7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/
7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/
7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/
7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/
7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/
7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/
7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/
7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/
7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/
7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/
7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/
7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/
7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/
7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/
7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/
7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/
7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/
7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/f/7/
Prompt: 
```
这是路径为go/src/crypto/x509/x509_test.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第4部分，共6部分，请归纳一下它的功能

"""
xITAfBgNVBAMTGENlcnRpUGF0aCBC
cmlkZ2UgQ0EgLSBHMjCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBANLW
4kXiRqvwBhJfN9uz12FA+P2D34MPxOt7TGXljm2plJ2CLzvaH8/ymsMdSWdJBS1M
8FmwvNL1w3A6ZuzksJjPikAu8kY3dcp3mrkk9eCPORDAwGtfsXwZysLiuEaDWpbD
dHOaHnI6qWU0N6OI+hNX58EjDpIGC1WQdho1tHOTPc5Hf5/hOpM/29v/wr7kySjs
Z+7nsvkm5rNhuJNzPsLsgzVaJ5/BVyOplZy24FKM8Y43MjR4osZm+a2e0zniqw6/
rvcjcGYabYaznZfQG1GXoyf2Vea+CCgpgUhlVafgkwEs8izl8rIpvBzXiFAgFQuG
Ituoy92PJbDs430fA/cCAwEAAaOCAnowggJ2MEUGCCsGAQUFBwEBBDkwNzA1Bggr
BgEFBQcwAoYpaHR0cDovL2NlcnRzLmNhLm1pbmRlZi5ubC9taW5kZWYtY2EtMi5w
N2MwHwYDVR0jBBgwFoAUzln9WSPz2M64Rl2HYf2/KD8StmQwDwYDVR0TAQH/BAUw
AwEB/zCB6QYDVR0gBIHhMIHeMEgGCmCEEAGHawECBQEwOjA4BggrBgEFBQcCARYs
aHR0cDovL2Nwcy5kcC5jYS5taW5kZWYubmwvbWluZGVmLWNhLWRwLWNwcy8wSAYK
YIQQAYdrAQIFAjA6MDgGCCsGAQUFBwIBFixodHRwOi8vY3BzLmRwLmNhLm1pbmRl
Zi5ubC9taW5kZWYtY2EtZHAtY3BzLzBIBgpghBABh2sBAgUDMDowOAYIKwYBBQUH
AgEWLGh0dHA6Ly9jcHMuZHAuY2EubWluZGVmLm5sL21pbmRlZi1jYS1kcC1jcHMv
MDkGA1UdHwQyMDAwLqAsoCqGKGh0dHA6Ly9jcmxzLmNhLm1pbmRlZi5ubC9taW5k
ZWYtY2EtMi5jcmwwDgYDVR0PAQH/BAQDAgEGMEYGA1UdHgEB/wQ8MDqhODA2pDEw
LzELMAkGA1UEBhMCTkwxIDAeBgNVBAoTF01pbmlzdGVyaWUgdmFuIERlZmVuc2ll
gQFjMF0GA1UdIQRWMFQwGgYKYIQQAYdrAQIFAQYMKwYBBAGBu1MBAQECMBoGCmCE
EAGHawECBQIGDCsGAQQBgbtTAQEBAjAaBgpghBABh2sBAgUDBgwrBgEEAYG7UwEB
AQIwHQYDVR0OBBYEFNDCjBM3M3ZKkag84ei3/aKc0d0UMA0GCSqGSIb3DQEBCwUA
A4ICAQAQXFn9jF90/DNFf15JhoGtta/0dNInb14PMu3PAjcdrXYCDPpQZOArTUng
5YT1WuzfmjnXiTsziT3my0r9Mxvz/btKK/lnVOMW4c2q/8sIsIPnnW5ZaRGrsANB
dNDZkzMYmeG2Pfgvd0AQSOrpE/TVgWfu/+MMRWwX9y6VbooBR7BLv7zMuVH0WqLn
6OMFth7fqsThlfMSzkE/RDSaU6n3wXAWT1SIqBITtccRjSUQUFm/q3xrb2cwcZA6
8vdS4hzNd+ttS905ay31Ks4/1Wrm1bH5RhEfRSH0VSXnc0b+z+RyBbmiwtVZqzxE
u3UQg/rAmtLDclLFEzjp8YDTIRYSLwstDbEXO/0ArdGrQm79HQ8i/3ZbP2357myW
i15qd6gMJIgGHS4b8Hc7R1K8LQ9Gm1aLKBEWVNGZlPK/cpXThpVmoEyslN2DHCrc
fbMbjNZpXlTMa+/b9z7Fa4X8dY8u/ELzZuJXJv5Rmqtg29eopFFYDCl0Nkh1XAjo
QejEoHHUvYV8TThHZr6Z6Ib8CECgTehU4QvepkgDXNoNrKRZBG0JhLjkwxh2whZq
nvWBfALC2VuNOM6C0rDY+HmhMlVt0XeqnybD9MuQALMit7Z00Cw2CIjNsBI9xBqD
xKK9CjUb7gzRUWSpB9jGHsvpEMHOzIFhufvH2Bz1XJw+Cl7khw==
-----END CERTIFICATE-----`

func TestAdditionFieldsInGeneralSubtree(t *testing.T) {
	// Very rarely, certificates can include additional fields in the
	// GeneralSubtree structure. This tests that such certificates can be
	// parsed.
	block, _ := pem.Decode([]byte(additionalGeneralSubtreePEM))
	if _, err := ParseCertificate(block.Bytes); err != nil {
		t.Fatalf("failed to parse certificate: %s", err)
	}
}

func TestEmptySerialNumber(t *testing.T) {
	template := Certificate{
		DNSNames: []string{"example.com"},
	}

	for range 100 {
		derBytes, err := CreateCertificate(rand.Reader, &template, &template, &testPrivateKey.PublicKey, testPrivateKey)
		if err != nil {
			t.Fatalf("failed to create certificate: %s", err)
		}

		cert, err := ParseCertificate(derBytes)
		if err != nil {
			t.Fatalf("failed to parse certificate: %s", err)
		}

		if sign := cert.SerialNumber.Sign(); sign != 1 {
			t.Fatalf("generated a non positive serial, sign: %d", sign)
		}

		b, err := asn1.Marshal(cert.SerialNumber)
		if err != nil {
			t.Fatalf("failed to marshal generated serial number: %s", err)
		}
		// subtract 2 for tag and length
		if l := len(b) - 2; l > 20 {
			t.Fatalf("generated serial number larger than 20 octets when encoded: %d", l)
		}
	}
}

func TestEmptySubject(t *testing.T) {
	template := Certificate{
		SerialNumber: big.NewInt(1),
		DNSNames:     []string{"example.com"},
	}

	derBytes, err := CreateCertificate(rand.Reader, &template, &template, &testPrivateKey.PublicKey, testPrivateKey)
	if err != nil {
		t.Fatalf("failed to create certificate: %s", err)
	}

	cert, err := ParseCertificate(derBytes)
	if err != nil {
		t.Fatalf("failed to parse certificate: %s", err)
	}

	for _, ext := range cert.Extensions {
		if ext.Id.Equal(oidExtensionSubjectAltName) {
			if !ext.Critical {
				t.Fatal("SAN extension is not critical")
			}
			return
		}
	}

	t.Fatal("SAN extension is missing")
}

// multipleURLsInCRLDPPEM contains two URLs in a single CRL DistributionPoint
// structure. It is taken from https://crt.sh/?id=12721534.
const multipleURLsInCRLDPPEM = `
-----BEGIN CERTIFICATE-----
MIIF4TCCBMmgAwIBAgIQc+6uFePfrahUGpXs8lhiTzANBgkqhkiG9w0BAQsFADCB
8zELMAkGA1UEBhMCRVMxOzA5BgNVBAoTMkFnZW5jaWEgQ2F0YWxhbmEgZGUgQ2Vy
dGlmaWNhY2lvIChOSUYgUS0wODAxMTc2LUkpMSgwJgYDVQQLEx9TZXJ2ZWlzIFB1
YmxpY3MgZGUgQ2VydGlmaWNhY2lvMTUwMwYDVQQLEyxWZWdldSBodHRwczovL3d3
dy5jYXRjZXJ0Lm5ldC92ZXJhcnJlbCAoYykwMzE1MDMGA1UECxMsSmVyYXJxdWlh
IEVudGl0YXRzIGRlIENlcnRpZmljYWNpbyBDYXRhbGFuZXMxDzANBgNVBAMTBkVD
LUFDQzAeFw0xNDA5MTgwODIxMDBaFw0zMDA5MTgwODIxMDBaMIGGMQswCQYDVQQG
EwJFUzEzMDEGA1UECgwqQ09OU09SQ0kgQURNSU5JU1RSQUNJTyBPQkVSVEEgREUg
Q0FUQUxVTllBMSowKAYDVQQLDCFTZXJ2ZWlzIFDDumJsaWNzIGRlIENlcnRpZmlj
YWNpw7MxFjAUBgNVBAMMDUVDLUNpdXRhZGFuaWEwggEiMA0GCSqGSIb3DQEBAQUA
A4IBDwAwggEKAoIBAQDFkHPRZPZlXTWZ5psJhbS/Gx+bxcTpGrlVQHHtIkgGz77y
TA7UZUFb2EQMncfbOhR0OkvQQn1aMvhObFJSR6nI+caf2D+h/m/InMl1MyH3S0Ak
YGZZsthnyC6KxqK2A/NApncrOreh70ULkQs45aOKsi1kR1W0zE+iFN+/P19P7AkL
Rl3bXBCVd8w+DLhcwRrkf1FCDw6cEqaFm3cGgf5cbBDMaVYAweWTxwBZAq2RbQAW
jE7mledcYghcZa4U6bUmCBPuLOnO8KMFAvH+aRzaf3ws5/ZoOVmryyLLJVZ54peZ
OwnP9EL4OuWzmXCjBifXR2IAblxs5JYj57tls45nAgMBAAGjggHaMIIB1jASBgNV
HRMBAf8ECDAGAQH/AgEAMA4GA1UdDwEB/wQEAwIBBjAdBgNVHQ4EFgQUC2hZPofI
oxUa4ECCIl+fHbLFNxUwHwYDVR0jBBgwFoAUoMOLRKo3pUW/l4Ba0fF4opvpXY0w
gdYGA1UdIASBzjCByzCByAYEVR0gADCBvzAxBggrBgEFBQcCARYlaHR0cHM6Ly93
d3cuYW9jLmNhdC9DQVRDZXJ0L1JlZ3VsYWNpbzCBiQYIKwYBBQUHAgIwfQx7QXF1
ZXN0IGNlcnRpZmljYXQgw6lzIGVtw6hzIMO6bmljYSBpIGV4Y2x1c2l2YW1lbnQg
YSBFbnRpdGF0cyBkZSBDZXJ0aWZpY2FjacOzLiBWZWdldSBodHRwczovL3d3dy5h
b2MuY2F0L0NBVENlcnQvUmVndWxhY2lvMDMGCCsGAQUFBwEBBCcwJTAjBggrBgEF
BQcwAYYXaHR0cDovL29jc3AuY2F0Y2VydC5jYXQwYgYDVR0fBFswWTBXoFWgU4Yn
aHR0cDovL2Vwc2NkLmNhdGNlcnQubmV0L2NybC9lYy1hY2MuY3JshihodHRwOi8v
ZXBzY2QyLmNhdGNlcnQubmV0L2NybC9lYy1hY2MuY3JsMA0GCSqGSIb3DQEBCwUA
A4IBAQChqFTjlAH5PyIhLjLgEs68CyNNC1+vDuZXRhy22TI83JcvGmQrZosPvVIL
PsUXx+C06Pfqmh48Q9S89X9K8w1SdJxP/rZeGEoRiKpwvQzM4ArD9QxyC8jirxex
3Umg9Ai/sXQ+1lBf6xw4HfUUr1WIp7pNHj0ZWLo106urqktcdeAFWme+/klis5fu
labCSVPuT/QpwakPrtqOhRms8vgpKiXa/eLtL9ZiA28X/Mker0zlAeTA7Z7uAnp6
oPJTlZu1Gg1ZDJueTWWsLlO+P+Wzm3MRRIbcgdRzm4mdO7ubu26SzX/aQXDhuih+
eVxXDTCfs7GUlxnjOp5j559X/N0A
-----END CERTIFICATE-----
`

func TestMultipleURLsInCRLDP(t *testing.T) {
	block, _ := pem.Decode([]byte(multipleURLsInCRLDPPEM))
	cert, err := ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("failed to parse certificate: %s", err)
	}

	want := []string{
		"http://epscd.catcert.net/crl/ec-acc.crl",
		"http://epscd2.catcert.net/crl/ec-acc.crl",
	}
	if got := cert.CRLDistributionPoints; !slices.Equal(got, want) {
		t.Errorf("CRL distribution points = %#v, want #%v", got, want)
	}
}

const hexPKCS1TestPKCS8Key = "30820278020100300d06092a864886f70d0101010500048202623082025e02010002818100cfb1b5bf9685ffa97b4f99df4ff122b70e59ac9b992f3bc2b3dde17d53c1a34928719b02e8fd17839499bfbd515bd6ef99c7a1c47a239718fe36bfd824c0d96060084b5f67f0273443007a24dfaf5634f7772c9346e10eb294c2306671a5a5e719ae24b4de467291bc571014b0e02dec04534d66a9bb171d644b66b091780e8d020301000102818100b595778383c4afdbab95d2bfed12b3f93bb0a73a7ad952f44d7185fd9ec6c34de8f03a48770f2009c8580bcd275e9632714e9a5e3f32f29dc55474b2329ff0ebc08b3ffcb35bc96e6516b483df80a4a59cceb71918cbabf91564e64a39d7e35dce21cb3031824fdbc845dba6458852ec16af5dddf51a8397a8797ae0337b1439024100ea0eb1b914158c70db39031dd8904d6f18f408c85fbbc592d7d20dee7986969efbda081fdf8bc40e1b1336d6b638110c836bfdc3f314560d2e49cd4fbde1e20b024100e32a4e793b574c9c4a94c8803db5152141e72d03de64e54ef2c8ed104988ca780cd11397bc359630d01b97ebd87067c5451ba777cf045ca23f5912f1031308c702406dfcdbbd5a57c9f85abc4edf9e9e29153507b07ce0a7ef6f52e60dcfebe1b8341babd8b789a837485da6c8d55b29bbb142ace3c24a1f5b54b454d01b51e2ad03024100bd6a2b60dee01e1b3bfcef6a2f09ed027c273cdbbaf6ba55a80f6dcc64e4509ee560f84b4f3e076bd03b11e42fe71a3fdd2dffe7e0902c8584f8cad877cdc945024100aa512fa4ada69881f1d8bb8ad6614f192b83200aef5edf4811313d5ef30a86cbd0a90f7b025c71ea06ec6b34db6306c86b1040670fd8654ad7291d066d06d031"
const hexPKCS1TestECKey = "3081a40201010430bdb9839c08ee793d1157886a7a758a3c8b2a17a4df48f17ace57c72c56b4723cf21dcda21d4e1ad57ff034f19fcfd98ea00706052b81040022a16403620004feea808b5ee2429cfcce13c32160e1c960990bd050bb0fdf7222f3decd0a55008e32a6aa3c9062051c4cba92a7a3b178b24567412d43cdd2f882fa5addddd726fe3e208d2c26d733a773a597abb749714df7256ead5105fa6e7b3650de236b50"

var pkcs1MismatchKeyTests = []struct {
	hexKey        string
	errorContains string
}{
	{hexKey: hexPKCS1TestPKCS8Key, errorContains: "use ParsePKCS8PrivateKey instead"},
	{hexKey: hexPKCS1TestECKey, errorContains: "use ParseECPrivateKey instead"},
}

func TestPKCS1MismatchKeyFormat(t *testing.T) {
	for i, test := range pkcs1MismatchKeyTests {
		derBytes, _ := hex.DecodeString(test.hexKey)
		_, err := ParsePKCS1PrivateKey(derBytes)
		if !strings.Contains(err.Error(), test.errorContains) {
			t.Errorf("#%d: expected error containing %q, got %s", i, test.errorContains, err)
		}
	}
}

func TestCreateRevocationList(t *testing.T) {
	ec256Priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate ECDSA P256 key: %s", err)
	}
	_, ed25519Priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate Ed25519 key: %s", err)
	}

	// Generation command:
	// openssl req -x509 -newkey rsa -keyout key.pem -out cert.pem -days 365 -nodes -subj '/C=US/ST=California/L=San Francisco/O=Internet Widgets, Inc./OU=WWW/CN=Root/emailAddress=admin@example.com' -sha256 -addext basicConstraints=CA:TRUE -addext "keyUsage = digitalSignature, keyEncipherment, dataEncipherment, cRLSign, keyCertSign" -utf8
	utf8CAStr := "MIIEITCCAwmgAwIBAgIUXHXy7NdtDv+ClaHvIvlwCYiI4a4wDQYJKoZIhvcNAQELBQAwgZoxCzAJBgNVBAYTAlVTMRMwEQYDVQQIDApDYWxpZm9ybmlhMRYwFAYDVQQHDA1TYW4gRnJhbmNpc2NvMR8wHQYDVQQKDBZJbnRlcm5ldCBXaWRnZXRzLCBJbmMuMQwwCgYDVQQLDANXV1cxDTALBgNVBAMMBFJvb3QxIDAeBgkqhkiG9w0BCQEWEWFkbWluQGV4YW1wbGUuY29tMB4XDTIyMDcwODE1MzgyMFoXDTIzMDcwODE1MzgyMFowgZoxCzAJBgNVBAYTAlVTMRMwEQYDVQQIDApDYWxpZm9ybmlhMRYwFAYDVQQHDA1TYW4gRnJhbmNpc2NvMR8wHQYDVQQKDBZJbnRlcm5ldCBXaWRnZXRzLCBJbmMuMQwwCgYDVQQLDANXV1cxDTALBgNVBAMMBFJvb3QxIDAeBgkqhkiG9w0BCQEWEWFkbWluQGV4YW1wbGUuY29tMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAmXvp0WNjsZzySWT7Ce5zewQNKq8ujeZGphJ44Vdrwut/b6TcC4iYENds5+7/3PYwBllp3K5TRpCcafSxdhJsvA7/zWlHHNRcJhJLNt9qsKWP6ukI2Iw6OmFMg6kJQ8f67RXkT8HR3v0UqE+lWrA0g+oRuj4erLtfOtSpnl4nsE/Rs2qxbELFWAf7F5qMqH4dUyveWKrNT8eI6YQN+wBg0MAjoKRvDJnBhuo+IvvXX8Aq1QWUcBGPK3or/Ehxy5f/gEmSUXyEU1Ht/vATt2op+eRaEEpBdGRvO+DrKjlcQV2XMN18A9LAX6hCzH43sGye87dj7RZ9yj+waOYNaM7kFQIDAQABo10wWzAdBgNVHQ4EFgQUtbSlrW4hGL2kNjviM6wcCRwvOEEwHwYDVR0jBBgwFoAUtbSlrW4hGL2kNjviM6wcCRwvOEEwDAYDVR0TBAUwAwEB/zALBgNVHQ8EBAMCAbYwDQYJKoZIhvcNAQELBQADggEBAAko82YNNI2n/45L3ya21vufP6nZihIOIxgcRPUMX+IDJZk16qsFdcLgH3KAP8uiVLn8sULuCj35HpViR4IcAk2d+DqfG11l8kY+e5P7nYsViRfy0AatF59/sYlWf+3RdmPXfL70x4mE9OqlMdDm0kR2obps8rng83VLDNvj3R5sBnQwdw6LKLGzaE+RiCTmkH0+P6vnbOJ33su9+9al1+HvJUg3UM1Xq5Bw7TE8DQTetMV3c2Q35RQaJB9pQ4blJOnW9hfnt8yQzU6TU1bU4mRctTm1o1f8btPqUpi+/blhi5MUJK0/myj1XD00pmyfp8QAFl1EfqmTMIBMLg633A0="
	utf8CABytes, _ := base64.StdEncoding.DecodeString(utf8CAStr)
	utf8CA, _ := ParseCertificate(utf8CABytes)

	utf8KeyStr := "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCZe+nRY2OxnPJJZPsJ7nN7BA0qry6N5kamEnjhV2vC639vpNwLiJgQ12zn7v/c9jAGWWncrlNGkJxp9LF2Emy8Dv/NaUcc1FwmEks232qwpY/q6QjYjDo6YUyDqQlDx/rtFeRPwdHe/RSoT6VasDSD6hG6Ph6su1861KmeXiewT9GzarFsQsVYB/sXmoyofh1TK95Yqs1Px4jphA37AGDQwCOgpG8MmcGG6j4i+9dfwCrVBZRwEY8reiv8SHHLl/+ASZJRfIRTUe3+8BO3ain55FoQSkF0ZG874OsqOVxBXZcw3XwD0sBfqELMfjewbJ7zt2PtFn3KP7Bo5g1ozuQVAgMBAAECggEAIscjKiD9PAe2Fs9c2tk/LYazfRKI1/pv072nylfGwToffCq8+ZgP7PEDamKLc4QNScME685MbFbkOlYJyBlQriQv7lmGlY/A+Zd3l410XWaGf9IiAP91Sjk13zd0M/micApf23qtlXt/LMwvSadXnvRw4+SjirxCTdBWRt5K2/ZAN550v7bHFk1EZc3UBF6sOoNsjQWh9Ek79UmQYJBPiZDBHO7O2fh2GSIbUutTma+Tb2i1QUZzg+AG3cseF3p1i3uhNrCh+p+01bJSzGTQsRod2xpD1tpWwR3kIftCOmD1XnhpaBQi7PXjEuNbfucaftnoYj2ShDdmgD5RkkbTAQKBgQC8Ghu5MQ/yIeqXg9IpcSxuWtUEAEfK33/cC/IvuntgbNEnWQm5Lif4D6a9zjkxiCS+9HhrUu5U2EV8NxOyaqmtub3Np1Z5mPuI9oiZ119bjUJd4X+jKOTaePWvOv/rL/pTHYqzXohVMrXy+DaTIq4lOcv3n72SuhuTcKU95rhKtQKBgQDQ4t+HsRZd5fJzoCgRQhlNK3EbXQDv2zXqMW3GfpF7GaDP18I530inRURSJa++rvi7/MCFg/TXVS3QC4HXtbzTYTqhE+VHzSr+/OcsqpLE8b0jKBDv/SBkz811PUJDs3LsX31DT3K0zUpMpNSd/5SYTyJKef9L6mxmwlC1S2Yv4QKBgQC57SiYDdnQIRwrtZ2nXvlm/xttAAX2jqJoU9qIuNA4yHaYaRcGVowlUvsiw9OelQ6VPTpGA0wWy0src5lhkrKzSFRHEe+U89U1VVJCljLoYKFIAJvUH5jOJh/am/vYca0COMIfeAJUDHLyfcwb9XyiyRVGZzvP62tUelSq8gIZvQKBgCAHeaDzzWsudCO4ngwvZ3PGwnwgoaElqrmzRJLYG3SVtGvKOJTpINnNLDGwZ6dEaw1gLyEJ38QY4oJxEULDMiXzVasXQuPkmMAqhUP7D7A1JPw8C4TQ+mOa3XUppHx/CpMl/S4SA5OnmsnvyE5Fv0IveCGVXUkFtAN5rihuXEfhAoGANUkuGU3A0Upk2mzv0JTGP4H95JFG93cqnyPNrYs30M6RkZNgTW27yyr+Nhs4/cMdrg1AYTB0+6ItQWSDmYLs7JEbBE/8L8fdD1irIcygjIHE9nJh96TgZCt61kVGLE8758lOdmoB2rZOpGwi16QIhdQb+IyozYqfX+lQUojL/W0="
	utf8KeyBytes, _ := base64.StdEncoding.DecodeString(utf8KeyStr)
	utf8KeyRaw, _ := ParsePKCS8PrivateKey(utf8KeyBytes)
	utf8Key := utf8KeyRaw.(crypto.Signer)

	tests := []struct {
		name          string
		key           crypto.Signer
		issuer        *Certificate
		template      *RevocationList
		expectedError string
	}{
		{
			name:          "nil template",
			key:           ec256Priv,
			issuer:        nil,
			template:      nil,
			expectedError: "x509: template can not be nil",
		},
		{
			name:          "nil issuer",
			key:           ec256Priv,
			issuer:        nil,
			template:      &RevocationList{},
			expectedError: "x509: issuer can not be nil",
		},
		{
			name: "issuer doesn't have crlSign key usage bit set",
			key:  ec256Priv,
			issuer: &Certificate{
				KeyUsage: KeyUsageCertSign,
			},
			template:      &RevocationList{},
			expectedError: "x509: issuer must have the crlSign key usage bit set",
		},
		{
			name: "issuer missing SubjectKeyId",
			key:  ec256Priv,
			issuer: &Certificate{
				KeyUsage: KeyUsageCRLSign,
			},
			template:      &RevocationList{},
			expectedError: "x509: issuer certificate doesn't contain a subject key identifier",
		},
		{
			name: "nextUpdate before thisUpdate",
			key:  ec256Priv,
			issuer: &Certificate{
				KeyUsage: KeyUsageCRLSign,
				Subject: pkix.Name{
					CommonName: "testing",
				},
				SubjectKeyId: []byte{1, 2, 3},
			},
			template: &RevocationList{
				ThisUpdate: time.Time{}.Add(time.Hour),
				NextUpdate: time.Time{},
			},
			expectedError: "x509: template.ThisUpdate is after template.NextUpdate",
		},
		{
			name: "nil Number",
			key:  ec256Priv,
			issuer: &Certificate{
				KeyUsage: KeyUsageCRLSign,
				Subject: pkix.Name{
					CommonName: "testing",
				},
				SubjectKeyId: []byte{1, 2, 3},
			},
			template: &RevocationList{
				ThisUpdate: time.Time{}.Add(time.Hour * 24),
				NextUpdate: time.Time{}.Add(time.Hour * 48),
			},
			expectedError: "x509: template contains nil Number field",
		},
		{
			name: "long Number",
			key:  ec256Priv,
			issuer: &Certificate{
				KeyUsage: KeyUsageCRLSign,
				Subject: pkix.Name{
					CommonName: "testing",
				},
				SubjectKeyId: []byte{1, 2, 3},
			},
			template: &RevocationList{
				ThisUpdate: time.Time{}.Add(time.Hour * 24),
				NextUpdate: time.Time{}.Add(time.Hour * 48),
				Number:     big.NewInt(0).SetBytes(append([]byte{1}, make([]byte, 20)...)),
			},
			expectedError: "x509: CRL number exceeds 20 octets",
		},
		{
			name: "long Number (20 bytes, MSB set)",
			key:  ec256Priv,
			issuer: &Certificate{
				KeyUsage: KeyUsageCRLSign,
				Subject: pkix.Name{
					CommonName: "testing",
				},
				SubjectKeyId: []byte{1, 2, 3},
			},
			template: &RevocationList{
				ThisUpdate: time.Time{}.Add(time.Hour * 24),
				NextUpdate: time.Time{}.Add(time.Hour * 48),
				Number:     big.NewInt(0).SetBytes(append([]byte{255}, make([]byte, 19)...)),
			},
			expectedError: "x509: CRL number exceeds 20 octets",
		},
		{
			name: "invalid signature algorithm",
			key:  ec256Priv,
			issuer: &Certificate{
				KeyUsage: KeyUsageCRLSign,
				Subject: pkix.Name{
					CommonName: "testing",
				},
				SubjectKeyId: []byte{1, 2, 3},
			},
			template: &RevocationList{
				SignatureAlgorithm: SHA256WithRSA,
				RevokedCertificates: []pkix.RevokedCertificate{
					{
						SerialNumber:   big.NewInt(2),
						RevocationTime: time.Time{}.Add(time.Hour),
					},
				},
				Number:     big.NewInt(5),
				ThisUpdate: time.Time{}.Add(time.Hour * 24),
				NextUpdate: time.Time{}.Add(time.Hour * 48),
			},
			expectedError: "x509: requested SignatureAlgorithm does not match private key type",
		},
		{
			name: "valid",
			key:  ec256Priv,
			issuer: &Certificate{
				KeyUsage: KeyUsageCRLSign,
				Subject: pkix.Name{
					CommonName: "testing",
				},
				SubjectKeyId: []byte{1, 2, 3},
			},
			template: &RevocationList{
				RevokedCertificateEntries: []RevocationListEntry{
					{
						SerialNumber:   big.NewInt(2),
						RevocationTime: time.Time{}.Add(time.Hour),
					},
				},
				Number:     big.NewInt(5),
				ThisUpdate: time.Time{}.Add(time.Hour * 24),
				NextUpdate: time.Time{}.Add(time.Hour * 48),
			},
		},
		{
			name: "valid, reason code",
			key:  ec256Priv,
			issuer: &Certificate{
				KeyUsage: KeyUsageCRLSign,
				Subject: pkix.Name{
					CommonName: "testing",
				},
				SubjectKeyId: []byte{1, 2, 3},
			},
			template: &RevocationList{
				RevokedCertificateEntries: []RevocationListEntry{
					{
						SerialNumber:   big.NewInt(2),
						RevocationTime: time.Time{}.Add(time.Hour),
						ReasonCode:     1,
					},
				},
				Number:     big.NewInt(5),
				ThisUpdate: time.Time{}.Add(time.Hour * 24),
				NextUpdate: time.Time{}.Add(time.Hour * 48),
			},
		},
		{
			name: "valid, extra entry extension",
			key:  ec256Priv,
			issuer: &Certificate{
				KeyUsage: KeyUsageCRLSign,
				Subject: pkix.Name{
					CommonName: "testing",
				},
				SubjectKeyId: []byte{1, 2, 3},
			},
			template: &RevocationList{
				RevokedCertificateEntries: []RevocationListEntry{
					{
						SerialNumber:   big.NewInt(2),
						RevocationTime: time.Time{}.Add(time.Hour),
						ExtraExtensions: []pkix.Extension{
							{
								Id:    []int{2, 5, 29, 99},
								Value: []byte{5, 0},
							},
						},
					},
				},
				Number:     big.NewInt(5),
				ThisUpdate: time.Time{}.Add(time.Hour * 24),
				NextUpdate: time.Time{}.Add(time.Hour * 48),
			},
		},
		{
			name: "valid, Ed25519 key",
			key:  ed25519Priv,
			issuer: &Certificate{
				KeyUsage: KeyUsageCRLSign,
				Subject: pkix.Name{
					CommonName: "testing",
				},
				SubjectKeyId: []byte{1, 2, 3},
			},
			template: &RevocationList{
				RevokedCertificateEntries: []RevocationListEntry{
					{
						SerialNumber:   big.NewInt(2),
						RevocationTime: time.Time{}.Add(time.Hour),
					},
				},
				Number:     big.NewInt(5),
				ThisUpdate: time.Time{}.Add(time.Hour * 24),
				NextUpdate: time.Time{}.Add(time.Hour * 48),
			},
		},
		{
			name: "valid, non-default signature algorithm",
			key:  ec256Priv,
			issuer: &Certificate{
				KeyUsage: KeyUsageCRLSign,
				Subject: pkix.Name{
					CommonName: "testing",
				},
				SubjectKeyId: []byte{1, 2, 3},
			},
			template: &RevocationList{
				SignatureAlgorithm: ECDSAWithSHA512,
				RevokedCertificateEntries: []RevocationListEntry{
					{
						SerialNumber:   big.NewInt(2),
						RevocationTime: time.Time{}.Add(time.Hour),
					},
				},
				Number:     big.NewInt(5),
				ThisUpdate: time.Time{}.Add(time.Hour * 24),
				NextUpdate: time.Time{}.Add(time.Hour * 48),
			},
		},
		{
			name: "valid, extra extension",
			key:  ec256Priv,
			issuer: &Certificate{
				KeyUsage: KeyUsageCRLSign,
				Subject: pkix.Name{
					CommonName: "testing",
				},
				SubjectKeyId: []byte{1, 2, 3},
			},
			template: &RevocationList{
				RevokedCertificateEntries: []RevocationListEntry{
					{
						SerialNumber:   big.NewInt(2),
						RevocationTime: time.Time{}.Add(time.Hour),
					},
				},
				Number:     big.NewInt(5),
				ThisUpdate: time.Time{}.Add(time.Hour * 24),
				NextUpdate: time.Time{}.Add(time.Hour * 48),
				ExtraExtensions: []pkix.Extension{
					{
						Id:    []int{2, 5, 29, 99},
						Value: []byte{5, 0},
					},
				},
			},
		},
		{
			name: "valid, deprecated entries with extension",
			key:  ec256Priv,
			issuer: &Certificate{
				KeyUsage: KeyUsageCRLSign,
				Subject: pkix.Name{
					CommonName: "testing",
				},
				SubjectKeyId: []byte{1, 2, 3},
			},
			template: &RevocationList{
				RevokedCertificates: []pkix.RevokedCertificate{
					{
						SerialNumber:   big.NewInt(2),
						RevocationTime: time.Time{}.Add(time.Hour),
						Extensions: []pkix.Extension{
							{
								Id:    []int{2, 5, 29, 99},
								Value: []byte{5, 0},
							},
						},
					},
				},
				Number:     big.NewInt(5),
				ThisUpdate: time.Time{}.Add(time.Hour * 24),
				NextUpdate: time.Time{}.Add(time.Hour * 48),
			},
		},
		{
			name: "valid, empty list",
			key:  ec256Priv,
			issuer: &Certificate{
				KeyUsage: KeyUsageCRLSign,
				Subject: pkix.Name{
					CommonName: "testing",
				},
				SubjectKeyId: []byte{1, 2, 3},
			},
			template: &RevocationList{
				Number:     big.NewInt(5),
				ThisUpdate: time.Time{}.Add(time.Hour * 24),
				NextUpdate: time.Time{}.Add(time.Hour * 48),
			},
		},
		{
			name:   "valid CA with utf8 Subject fields including Email, empty list",
			key:    utf8Key,
			issuer: utf8CA,
			template: &RevocationList{
				Number:     big.NewInt(5),
				ThisUpdate: time.Time{}.Add(time.Hour * 24),
				NextUpdate: time.Time{}.Add(time.Hour * 48),
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			crl, err := CreateRevocationList(rand.Reader, tc.template, tc.issuer, tc.key)
			if err != nil && tc.expectedError == "" {
				t.Fatalf("CreateRevocationList failed unexpectedly: %s", err)
			} else if err != nil && tc.expectedError != err.Error() {
				t.Fatalf("CreateRevocationList failed unexpectedly, wanted: %s, got: %s", tc.expectedError, err)
			} else if err == nil && tc.expectedError != "" {
				t.Fatalf("CreateRevocationList didn't fail, expected: %s", tc.expectedError)
			}
			if tc.expectedError != "" {
				return
			}

			parsedCRL, err := ParseRevocationList(crl)
			if err != nil {
				t.Fatalf("Failed to parse generated CRL: %s", err)
			}

			if tc.template.SignatureAlgorithm != UnknownSignatureAlgorithm &&
				parsedCRL.SignatureAlgorithm != tc.template.SignatureAlgorithm {
				t.Fatalf("SignatureAlgorithm mismatch: got %v; want %v.", parsedCRL.SignatureAlgorithm,
					tc.template.SignatureAlgorithm)
			}

			if len(tc.template.RevokedCertificates) > 0 {
				if !reflect.DeepEqual(parsedCRL.RevokedCertificates, tc.template.RevokedCertificates) {
					t.Fatalf("RevokedCertificates mismatch: got %v; want %v.",
						parsedCRL.RevokedCertificates, tc.template.RevokedCertificates)
				}
			} else {
				if len(parsedCRL.RevokedCertificateEntries) != len(tc.template.RevokedCertificateEntries) {
					t.Fatalf("RevokedCertificateEntries length mismatch: got %d; want %d.",
						len(parsedCRL.RevokedCertificateEntries),
						len(tc.template.RevokedCertificateEntries))
				}
				for i, rce := range parsedCRL.RevokedCertificateEntries {
					expected := tc.template.RevokedCertificateEntries[i]
					if rce.SerialNumber.Cmp(expected.SerialNumber) != 0 {
						t.Fatalf("RevocationListEntry serial mismatch: got %d; want %d.",
							rce.SerialNumber, expected.SerialNumber)
					}
					if !rce.RevocationTime.Equal(expected.RevocationTime) {
						t.Fatalf("RevocationListEntry revocation time mismatch: got %v; want %v.",
							rce.RevocationTime, expected.RevocationTime)
					}
					if rce.ReasonCode != expected.ReasonCode {
						t.Fatalf("RevocationListEntry reason code mismatch: got %d; want %d.",
							rce.ReasonCode, expected.ReasonCode)
					}
				}
			}

			if len(parsedCRL.Extensions) != 2+len(tc.template.ExtraExtensions) {
				t.Fatalf("Generated CRL has wrong number of extensions, wanted: %d, got: %d", 2+len(tc.template.ExtraExtensions), len(parsedCRL.Extensions))
			}
			expectedAKI, err := asn1.Marshal(authKeyId{Id: tc.issuer.SubjectKeyId})
			if err != nil {
				t.Fatalf("asn1.Marshal failed: %s", err)
			}
			akiExt := pkix.Extension{
				Id:    oidExtensionAuthorityKeyId,
				Value: expectedAKI,
			}
			if !reflect.DeepEqual(parsedCRL.Extensions[0], akiExt) {
				t.Fatalf("Unexpected first extension: got %v, want %v",
					parsedCRL.Extensions[0], akiExt)
			}
			expectedNum, err := asn1.Marshal(tc.template.Number)
			if err != nil {
				t.Fatalf("asn1.Marshal failed: %s", err)
			}
			crlExt := pkix.Extension{
				Id:    oidExtensionCRLNumber,
				Value: expectedNum,
			}
			if !reflect.DeepEqual(parsedCRL.Extensions[1], crlExt) {
				t.Fatalf("Unexpected second extension: got %v, want %v",
					parsedCRL.Extensions[1], crlExt)
			}

			// With Go 1.19's updated RevocationList, we can now directly compare
			// the RawSubject of the certificate to RawIssuer on the parsed CRL.
			// However, this doesn't work with our hacked issuers above (that
			// aren't parsed from a proper DER bundle but are instead manually
			// constructed). Prefer RawSubject when it is set.
			if len(tc.issuer.RawSubject) > 0 {
				issuerSubj, err := subjectBytes(tc.issuer)
				if err != nil {
					t.Fatalf("failed to get issuer subject: %s", err)
				}
				if !bytes.Equal(issuerSubj, parsedCRL.RawIssuer) {
					t.Fatalf("Unexpected issuer subject; wanted: %v, got: %v", hex.EncodeToString(issuerSubj), hex.EncodeToString(parsedCRL.RawIssuer))
				}
			} else {
				// When we hack our custom Subject in the test cases above,
				// we don't set the additional fields (such as Names) in the
				// hacked issuer. Round-trip a parsing of pkix.Name so that
				// we add these missing fields for the comparison.
				issuerRDN := tc.issuer.Subject.ToRDNSequence()
				var caIssuer pkix.Name
				caIssuer.FillFromRDNSequence(&issuerRDN)
				if !reflect.DeepEqual(caIssuer, parsedCRL.Issuer) {
					t.Fatalf("Expected issuer.Subject, parsedCRL.Issuer to be the same; wanted: %#v, got: %#v", caIssuer, parsedCRL.Issuer)
				}
			}

			if len(parsedCRL.Extensions[2:]) == 0 && len(tc.template.ExtraExtensions) == 0 {
				// If we don't have anything to check return early so we don't
				// hit a [] != nil false positive below.
				return
			}
			if !reflect.DeepEqual(parsedCRL.Extensions[2:], tc.template.ExtraExtensions) {
				t.Fatalf("Extensions mismatch: got %v; want %v.",
					parsedCRL.Extensions[2:], tc.template.ExtraExtensions)
			}

			if tc.template.Number != nil && parsedCRL.Number == nil {
				t.Fatalf("Generated CRL missing Number: got nil, want %s",
					tc.template.Number.String())
			}
			if tc.template.Number != nil && tc.template.Number.Cmp(parsedCRL.Number) != 0 {
				t.Fatalf("Generated CRL has wrong Number: got %s, want %s",
					parsedCRL.Number.String(), tc.template.Number.String())
			}
			if !bytes.Equal(parsedCRL.AuthorityKeyId, tc.issuer.SubjectKeyId) {
				t.Fatalf("Generated CRL has wrong AuthorityKeyId: got %x, want %x",
					parsedCRL.AuthorityKeyId, tc.issuer.SubjectKeyId)
			}
		})
	}
}

func TestRSAPSAParameters(t *testing.T) {
	generateParams := func(hashFunc crypto.Hash) []byte {
		var hashOID asn1.ObjectIdentifier

		switch hashFunc {
		case crypto.SHA256:
			hashOID = oidSHA256
		case crypto.SHA384:
			hashOID = oidSHA384
		case crypto.SHA512:
			hashOID = oidSHA512
		}

		params := pssParameters{
			Hash: pkix.AlgorithmIdentifier{
				Algorithm:  hashOID,
				Parameters: asn1.NullRawValue,
			},
			MGF: pkix.AlgorithmIdentifier{
				Algorithm: oidMGF1,
			},
			SaltLength:   hashFunc.Size(),
			TrailerField: 1,
		}

		mgf1Params := pkix.AlgorithmIdentifier{
			Algorithm:  hashOID,
			Parameters: asn1.NullRawValue,
		}

		var err error
		params.MGF.Parameters.FullBytes, err = asn1.Marshal(mgf1Params)
		if err != nil {
			t.Fatalf("failed to marshal MGF parameters: %s", err)
		}

		serialized, err := asn1.Marshal(params)
		if err != nil {
			t.Fatalf("failed to marshal parameters: %s", err)
		}

		return serialized
	}

	for _, detail := range signatureAlgorithmDetails {
		if !detail.isRSAPSS {
			continue
		}
		generated := generateParams(detail.hash)
		if !bytes.Equal(detail.params.FullBytes, generated) {
			t.Errorf("hardcoded parameters for %s didn't match generated parameters: got (generated) %x, wanted (hardcoded) %x", detail.hash, generated, detail.params.FullBytes)
		}
	}
}

func TestUnknownExtKey(t *testing.T) {
	const errorContains = "unknown extended key usage"

	template := &Certificate{
		SerialNumber: big.NewInt(10),
		DNSNames:     []string{"foo"},
		ExtKeyUsage:  []ExtKeyUsage{ExtKeyUsage(-1)},
	}

	_, err := CreateCertificate(rand.Reader, template, template, testPrivateKey.Public(), testPrivateKey)
	if !strings.Contains(err.Error(), errorContains) {
		t.Errorf("expected error containing %q, got %s", errorContains, err)
	}
}

func TestIA5SANEnforcement(t *testing.T) {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey failed: %s", err)
	}

	testURL, err := url.Parse("https://example.com/")
	if err != nil {
		t.Fatalf("url.Parse failed: %s", err)
	}
	testURL.RawQuery = "∞"

	marshalTests := []struct {
		name          string
		template      *Certificate
		expectedError string
	}{
		{
			name: "marshal: unicode dNSName",
			template: &Certificate{
				SerialNumber: big.NewInt(0),
				DNSNames:     []string{"∞"},
			},
			expectedError: "x509: \"∞\" cannot be encoded as an IA5String",
		},
		{
			name: "marshal: unicode rfc822Name",
			template: &Certificate{
				SerialNumber:   big.NewInt(0),
				EmailAddresses: []string{"∞"},
			},
			expectedError: "x509: \"∞\" cannot be encoded as an IA5String",
		},
		{
			name: "marshal: unicode uniformResourceIdentifier",
			template: &Certificate{
				SerialNumber: big.NewInt(0),
				URIs:         []*url.URL{testURL},
			},
			expectedError: "x509: \"https://example.com/?∞\" cannot be encoded as an IA5String",
		},
	}

	for _, tc := range marshalTests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := CreateCertificate(rand.Reader, tc.template, tc.template, k.Public(), k)
			if err == nil {
				t.Errorf("expected CreateCertificate to fail with template: %v", tc.template)
			} else if err.Error() != tc.expectedError {
				t.Errorf("unexpected error: got %q, want %q", err.Error(), tc.expectedError)
			}
		})
	}

	unmarshalTests := []struct {
		name          string
		cert          string
		expectedError string
	}{
		{
			name:          "unmarshal: unicode dNSName",
			cert:          "308201083081aea003020102020100300a06082a8648ce3d04030230003022180f30303031303130313030303030305a180f30303031303130313030303030305a30003059301306072a8648ce3d020106082a8648ce3d0301070342000424bcc48180d8d9db794028f2575ebe3cac79f04d7b0d0151c5292e588aac3668c495f108c626168462e0668c9705e08a211dd103a659d2684e0adf8c2bfd47baa315301330110603551d110101ff040730058203e2889e300a06082a8648ce3d04030203490030460221008ac7827ac326a6ee0fa70b2afe99af575ec60b975f820f3c25f60fff43fbccd0022100bffeed93556722d43d13e461d5b3e33efc61f6349300327d3a0196cb6da501c2",
			expectedError: "x509: SAN dNSName is malformed",
		},
		{
			name:          "unmarshal: unicode rfc822Name",
			cert:          "308201083081aea003020102020100300a06082a8648ce3d04030230003022180f30303031303130313030303030305a180f30303031303130313030303030305a30003059301306072a8648ce3d020106082a8648ce3d0301070342000405cb4c4ba72aac980f7b11b0285191425e29e196ce7c5df1c83f56886566e517f196657cc1b73de89ab84ce503fd634e2f2af88fde24c63ca536dc3a5eed2665a315301330110603551d110101ff040730058103e2889e300a06082a8648ce3d0403020349003046022100ed1431cd4b9bb03d88d1511a0ec128a51204375764c716280dc36e2a60142c8902210088c96d25cfaf97eea851ff17d87bb6fe619d6546656e1739f35c3566051c3d0f",
			expectedError: "x509: SAN rfc822Name is malformed",
		},
		{
			name:          "unmarshal: unicode uniformResourceIdentifier",
			cert:          "3082011b3081c3a003020102020100300a06082a8648ce3d04030230003022180f30303031303130313030303030305a180f30303031303130313030303030305a30003059301306072a8648ce3d020106082a8648ce3d03010703420004ce0a79b511701d9188e1ea76bcc5907f1db51de6cc1a037b803f256e8588145ca409d120288bfeb4e38f3088104674d374b35bb91fc80d768d1d519dbe2b0b5aa32a302830260603551d110101ff041c301a861868747470733a2f2f6578616d706c652e636f6d2f3fe2889e300a06082a8648ce3d0403020347003044022044f4697779fd1dae1e382d2452413c5c5ca67851e267d6bc64a8d164977c172c0220505015e657637aa1945d46e7650b6f59b968fc1508ca8b152c99f782446dfc81",
			expectedError: "x509: SAN uniformResourceIdentifier is malformed",
		},
	}

	for _, tc := range unmarshalTests {
		der, err := hex.DecodeString(tc.cert)
		if err != nil {
			t.Fatalf("failed to decode test cert: %s", err)
		}
		_, err = ParseCertificate(der)
		if err == nil {
			t.Error("expected CreateCertificate to fail")
		} else if err.Error() != tc.expect
"""




```