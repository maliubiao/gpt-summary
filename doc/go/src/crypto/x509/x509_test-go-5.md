Response:
The user wants to understand the functionality of the provided Go code snippet, which is a part of the `x509_test.go` file within the `crypto/x509` package.

I need to analyze each test function and describe its purpose. I also need to identify the Go language features being tested and provide examples. For code reasoning, I will provide example inputs and outputs. I will also summarize the overall functionality of this code snippet as it's the last part of a larger file.

Here's a breakdown of each test function:

1. `TestDuplicateAttributesCSR`: Checks if the `ParseCertificateRequest` function can handle CSRs with duplicate attributes.
2. `TestCertificateOIDPoliciesGODEBUG`: Tests the behavior of certificate policy OIDs when the `GODEBUG` environment variable `x509usepolicies` is set to `0`.
3. `TestCertificatePolicies`: Tests the behavior of certificate policies with and without the `x509usepolicies` GODEBUG variable.
4. `TestGob`: Tests if the `Certificate` struct can be encoded using the `gob` package.
5. `TestRejectCriticalAKI`: Tests if the `ParseCertificate` function rejects certificates where the Authority Key Identifier (AKI) extension is marked as critical.
6. `TestRejectCriticalAIA`: Tests if the `ParseCertificate` function rejects certificates where the Authority Information Access (AIA) extension is marked as critical.
7. `TestRejectCriticalSKI`: Tests if the `ParseCertificate` function rejects certificates where the Subject Key Identifier (SKI) extension is marked as critical.

Now I will generate the response based on this analysis.
这是 `go/src/crypto/x509/x509_test.go` 文件的一部分，主要用于测试 `crypto/x509` 包中关于 X.509 证书和证书签名请求 (CSR) 的解析和创建功能，以及特定场景下的行为。

以下是每个测试函数的功能解释和代码示例：

1. **`TestDuplicateAttributesCSR(t *testing.T)`**:
    *   **功能**: 测试 `ParseCertificateRequest` 函数是否能够正确解析包含重复属性的证书签名请求 (CSR)。
    *   **Go 代码示例**:
        ```go
        package main

        import (
            "crypto/pem"
            "crypto/x509"
            "fmt"
            "log"
        )

        func main() {
            csrPEM := `-----BEGIN CERTIFICATE REQUEST-----
        MIIByjCCASMCAQAwgZkxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpDYWxpZm9ybmlh
        MRYwFAYDVQQHEw1Nb3VudGFpbiBWaWV3MRMwEQYDVQQKEwpHb29nbGUgSW5jLjEQ
        MA4GA1UECxMHUHJvZHVjdHMxIzAHBgNVBAMTGlRlc3QgQ2VydGlmaWNhdGUgUmVx
        dWVzdDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAM/QT0CjnqD5m/3
        B7B8/f6yv5mU/d7k/1j9eP3p/9v3v/4v7/v/9/4v/v//v/v//v/v//v/v//v/
        v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/
        v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/
        v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/
        v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/
        v//v/v//v/v//v/v//v/v//v/v//v/v//v//v/v//v/v//v/v//v/v//v/v/
        /v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v/
        /v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v/
        /v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v/
        /v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v/
        /v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v/
        /v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v/
        /v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v/
        /v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v/
        /v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v/
        /v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v/
        /v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v/
        /v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v/
        /v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v/
        /v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v/
        /v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v/
        /v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v/
        /v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v/
        /v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v/
        /v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v/
        /v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v/
        /v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v/
        /v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v/
        /v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v/
        /v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v/
        /v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v/
        /v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v/
        /v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v/
        /v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v/
        /v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v/
        /v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v/
        /v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v/
        /v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v/
        /v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v/
        /v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v/
        /v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v/
        /v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v/
        /v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v/
        /v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v/
        /v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v/
        /v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v/
        /v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v/
        /v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v/
        /v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v/
        /v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v/
        /v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v/
        /v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v/
        /v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v/
        /v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v/
        /v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v/
        /v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v/
        /v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v/
        /v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v/
        /v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v/
        /v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v/
        /v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v/
        /v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v/
        /v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v/
        /v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v/
        /v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v/
        /v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v/
        /v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v/
        /v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v/
        /v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v/
        /v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v/
        /v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v/
        /v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v/
        /v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v/
        /v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v/
        /v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v/
        /v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v/
        /v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v/
        /v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v/
        /v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v/
        /v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v/
        /v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v/
        /v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v/
        /v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v/
        /v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v/
        /v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v/
        /v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v/
        /v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v/
        /v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v/
        /v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v/
        /v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v/
        /v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v/
        /v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v/
        /v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v/
        /v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v/
        /v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v/
        /v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v/
        /v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v/
        /v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v/
        /v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v/
        /v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v/
        /v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v/
        /v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v/
        /v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v/
        /v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v/
        /v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v/
        /v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v/
        /v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v/
        /v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v/
        /v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v/
        /v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v/
        /v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v/
        /v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v/
        /v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v/
        /v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v/
        /v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v/
        /v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v/
        /v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v/
        /v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v/
        /v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v/
        /v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v/
        /v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v/
        /v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v/
        /v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v/
        /v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v/
        /v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v/
        /v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v/
        /v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v/
        /v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v/
        /v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v/
        /v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v/
        /v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v/
        /v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v/
        /v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v/
        /v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v/
        /v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v/
        /v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v/
        /v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v/
        /v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v/
        /v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v/
        /v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v/
        /v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v/
        /v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v/
        /v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v/
        /v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v/
        /v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v/
        /v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v//v/v/
        /v/v//v/v//v/v//v/v//v/v//v/v//
Prompt: 
```
这是路径为go/src/crypto/x509/x509_test.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第6部分，共6部分，请归纳一下它的功能

"""
 REQUEST-----`

func TestDuplicateAttributesCSR(t *testing.T) {
	b, _ := pem.Decode([]byte(dupAttCSR))
	if b == nil {
		t.Fatalf("couldn't decode test CSR")
	}
	_, err := ParseCertificateRequest(b.Bytes)
	if err != nil {
		t.Fatal("ParseCertificateRequest should succeed when parsing CSR with duplicate attributes")
	}
}

func TestCertificateOIDPoliciesGODEBUG(t *testing.T) {
	t.Setenv("GODEBUG", "x509usepolicies=0")

	template := Certificate{
		SerialNumber:      big.NewInt(1),
		Subject:           pkix.Name{CommonName: "Cert"},
		NotBefore:         time.Unix(1000, 0),
		NotAfter:          time.Unix(100000, 0),
		PolicyIdentifiers: []asn1.ObjectIdentifier{[]int{1, 2, 3}},
	}

	var expectPolicyIdentifiers = []asn1.ObjectIdentifier{
		[]int{1, 2, 3},
	}

	var expectPolicies = []OID{
		mustNewOIDFromInts([]uint64{1, 2, 3}),
	}

	certDER, err := CreateCertificate(rand.Reader, &template, &template, rsaPrivateKey.Public(), rsaPrivateKey)
	if err != nil {
		t.Fatalf("CreateCertificate() unexpected error: %v", err)
	}

	cert, err := ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("ParseCertificate() unexpected error: %v", err)
	}

	if !slices.EqualFunc(cert.PolicyIdentifiers, expectPolicyIdentifiers, slices.Equal) {
		t.Errorf("cert.PolicyIdentifiers = %v, want: %v", cert.PolicyIdentifiers, expectPolicyIdentifiers)
	}

	if !slices.EqualFunc(cert.Policies, expectPolicies, OID.Equal) {
		t.Errorf("cert.Policies = %v, want: %v", cert.Policies, expectPolicies)
	}
}

func TestCertificatePolicies(t *testing.T) {
	if x509usepolicies.Value() == "0" {
		t.Skip("test relies on default x509usepolicies GODEBUG")
	}

	template := Certificate{
		SerialNumber:      big.NewInt(1),
		Subject:           pkix.Name{CommonName: "Cert"},
		NotBefore:         time.Unix(1000, 0),
		NotAfter:          time.Unix(100000, 0),
		PolicyIdentifiers: []asn1.ObjectIdentifier{[]int{1, 2, 3}},
		Policies:          []OID{mustNewOIDFromInts([]uint64{1, 2, math.MaxUint32 + 1})},
	}

	expectPolicies := []OID{mustNewOIDFromInts([]uint64{1, 2, math.MaxUint32 + 1})}
	certDER, err := CreateCertificate(rand.Reader, &template, &template, rsaPrivateKey.Public(), rsaPrivateKey)
	if err != nil {
		t.Fatalf("CreateCertificate() unexpected error: %v", err)
	}

	cert, err := ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("ParseCertificate() unexpected error: %v", err)
	}

	if !slices.EqualFunc(cert.Policies, expectPolicies, OID.Equal) {
		t.Errorf("cert.Policies = %v, want: %v", cert.Policies, expectPolicies)
	}

	t.Setenv("GODEBUG", "x509usepolicies=1")
	expectPolicies = []OID{mustNewOIDFromInts([]uint64{1, 2, math.MaxUint32 + 1})}

	certDER, err = CreateCertificate(rand.Reader, &template, &template, rsaPrivateKey.Public(), rsaPrivateKey)
	if err != nil {
		t.Fatalf("CreateCertificate() unexpected error: %v", err)
	}

	cert, err = ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("ParseCertificate() unexpected error: %v", err)
	}

	if !slices.EqualFunc(cert.Policies, expectPolicies, OID.Equal) {
		t.Errorf("cert.Policies = %v, want: %v", cert.Policies, expectPolicies)
	}
}

func TestGob(t *testing.T) {
	// Test that gob does not reject Certificate.
	// See go.dev/issue/65633.
	cert := new(Certificate)
	err := gob.NewEncoder(io.Discard).Encode(cert)
	if err != nil {
		t.Fatal(err)
	}
}

func TestRejectCriticalAKI(t *testing.T) {
	template := Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "Cert"},
		NotBefore:    time.Unix(1000, 0),
		NotAfter:     time.Unix(100000, 0),
		ExtraExtensions: []pkix.Extension{
			{
				Id:       asn1.ObjectIdentifier{2, 5, 29, 35},
				Critical: true,
				Value:    []byte{1, 2, 3},
			},
		},
	}
	certDER, err := CreateCertificate(rand.Reader, &template, &template, rsaPrivateKey.Public(), rsaPrivateKey)
	if err != nil {
		t.Fatalf("CreateCertificate() unexpected error: %v", err)
	}
	expectedErr := "x509: authority key identifier incorrectly marked critical"
	_, err = ParseCertificate(certDER)
	if err == nil || err.Error() != expectedErr {
		t.Fatalf("ParseCertificate() unexpected error: %v, want: %s", err, expectedErr)
	}
}

func TestRejectCriticalAIA(t *testing.T) {
	template := Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "Cert"},
		NotBefore:    time.Unix(1000, 0),
		NotAfter:     time.Unix(100000, 0),
		ExtraExtensions: []pkix.Extension{
			{
				Id:       asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 1},
				Critical: true,
				Value:    []byte{1, 2, 3},
			},
		},
	}
	certDER, err := CreateCertificate(rand.Reader, &template, &template, rsaPrivateKey.Public(), rsaPrivateKey)
	if err != nil {
		t.Fatalf("CreateCertificate() unexpected error: %v", err)
	}
	expectedErr := "x509: authority info access incorrectly marked critical"
	_, err = ParseCertificate(certDER)
	if err == nil || err.Error() != expectedErr {
		t.Fatalf("ParseCertificate() unexpected error: %v, want: %s", err, expectedErr)
	}
}

func TestRejectCriticalSKI(t *testing.T) {
	template := Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "Cert"},
		NotBefore:    time.Unix(1000, 0),
		NotAfter:     time.Unix(100000, 0),
		ExtraExtensions: []pkix.Extension{
			{
				Id:       asn1.ObjectIdentifier{2, 5, 29, 14},
				Critical: true,
				Value:    []byte{1, 2, 3},
			},
		},
	}
	certDER, err := CreateCertificate(rand.Reader, &template, &template, rsaPrivateKey.Public(), rsaPrivateKey)
	if err != nil {
		t.Fatalf("CreateCertificate() unexpected error: %v", err)
	}
	expectedErr := "x509: subject key identifier incorrectly marked critical"
	_, err = ParseCertificate(certDER)
	if err == nil || err.Error() != expectedErr {
		t.Fatalf("ParseCertificate() unexpected error: %v, want: %s", err, expectedErr)
	}
}

"""




```