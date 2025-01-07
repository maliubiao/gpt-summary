Response:
The user wants to understand the functionality of a Go code snippet from `go/src/crypto/x509/parser_test.go`. I need to analyze the code and explain:

1. **Functionality of the code:** Describe what the test functions are doing.
2. **Underlying Go features:** Identify the Go features being tested and provide code examples.
3. **Code inference with input/output:** For functions doing data transformation, provide examples with assumed inputs and outputs.
4. **Command-line argument handling:** Check if the code processes any command-line arguments and explain how.
5. **Common mistakes:**  Point out any common pitfalls users might encounter when using the functionalities being tested.

Based on the code:

-   `TestParseASN1String`: Tests the `parseASN1String` function, which seems to parse ASN.1 encoded strings with different tags.
-   `TestPolicyParse`: Tests the parsing of certificate policies from a PEM-encoded certificate.
-   `TestParsePolicies`: Tests the error handling when parsing certificates with specific policy-related issues.

Let's break down each part and formulate the answer.
这段代码是 Go 语言标准库 `crypto/x509` 包中 `parser_test.go` 文件的一部分，它主要用于测试 X.509 证书解析过程中的一些特定功能。具体来说，它测试了以下两个主要方面：

**1. ASN.1 字符串解析功能：**

`TestParseASN1String` 函数测试了 `parseASN1String` 函数的功能。根据测试用例来看，`parseASN1String` 函数的作用是将 ASN.1 编码的字符串根据其不同的标签（Tag）解析成 Go 字符串。ASN.1 中定义了多种字符串类型，例如 `T61String`、`PrintableString`、`UTF8String` 等，它们的编码方式和允许包含的字符集有所不同。

**Go 代码举例说明：**

```go
package main

import (
	"fmt"
	"golang.org/x/crypto/cryptobyte/asn1"
	"unicode/utf8"
)

func main() {
	// 假设我们有一个 ASN.1 编码的 UTF8String
	utf8Bytes := []byte{0x50, 0x51, 0x52} // "PQR" 的 UTF-8 编码
	parsedUTF8, err := parseASN1String(asn1.UTF8String, utf8Bytes)
	if err != nil {
		fmt.Println("解析 UTF8String 失败:", err)
	} else {
		fmt.Println("解析的 UTF8String:", parsedUTF8) // 输出: 解析的 UTF8String: PQR
	}

	// 假设我们有一个 ASN.1 编码的 BMPString
	bmpBytes := []byte{0x50, 0x81} // 字符 "偑" 的 BMP 编码
	parsedBMP, err := parseASN1String(asn1.Tag(asn1.TagBMPString), bmpBytes)
	if err != nil {
		fmt.Println("解析 BMPString 失败:", err)
	} else {
		fmt.Println("解析的 BMPString:", parsedBMP) // 输出: 解析的 BMPString: 偑
	}

	// 尝试解析一个无效的 PrintableString
	invalidPrintableBytes := []byte{0x01, 0x02, 0x03}
	_, err = parseASN1String(asn1.PrintableString, invalidPrintableBytes)
	if err != nil {
		fmt.Println("解析 PrintableString 失败:", err) // 输出: 解析 PrintableString 失败: invalid PrintableString
	}
}

// 注意：parseASN1String 函数在给定的代码片段中并没有实现，这里只是为了演示其可能的用法。
func parseASN1String(tag asn1.Tag, value []byte) (string, error) {
	switch tag {
	case asn1.T61String, asn1.PrintableString, asn1.UTF8String, asn1.IA5String, asn1.Tag(asn1.TagNumericString):
		return string(value), nil // 简化实现，实际需要根据不同的字符串类型进行校验和解码
	case asn1.Tag(asn1.TagBMPString):
		if len(value)%2 != 0 {
			return "", fmt.Errorf("invalid BMPString")
		}
		runes := make([]rune, len(value)/2)
		for i := 0; i < len(value); i += 2 {
			runes[i/2] = rune(uint16(value[i])<<8 | uint16(value[i+1]))
		}
		return string(runes), nil
	default:
		return "", fmt.Errorf("unsupported ASN.1 string tag: %v", tag)
	}
}
```

**假设的输入与输出：**

| 测试名称                  | `tag`                      | `value`        | 预期输出   | 预期错误                  |
| ------------------------- | -------------------------- | -------------- | -------- | ------------------------- |
| T61String                | `cryptobyte_asn1.T61String` | `[]byte{80, 81, 82}` | `"PQR"`  |                           |
| PrintableString          | `cryptobyte_asn1.PrintableString` | `[]byte{80, 81, 82}` | `"PQR"`  |                           |
| PrintableString (invalid) | `cryptobyte_asn1.PrintableString` | `[]byte{1, 2, 3}`  |          | `"invalid PrintableString"` |
| UTF8String               | `cryptobyte_asn1.UTF8String`    | `[]byte{80, 81, 82}` | `"PQR"`  |                           |
| UTF8String (invalid)     | `cryptobyte_asn1.UTF8String`    | `[]byte{255}`    |          | `"invalid UTF-8 string"`    |
| BMPString                | `asn1.Tag(asn1.TagBMPString)` | `[]byte{80, 81}`  | `"偑"`  |                           |
| BMPString (invalid length) | `asn1.Tag(asn1.TagBMPString)` | `[]byte{255}`    |          | `"invalid BMPString"`     |
| IA5String                | `cryptobyte_asn1.IA5String`    | `[]byte{80, 81}`  | `"PQ"`   |                           |
| IA5String (invalid)      | `cryptobyte_asn1.IA5String`    | `[]byte{255}`    |          | `"invalid IA5String"`       |
| NumericString            | `asn1.Tag(asn1.TagNumericString)` | `[]byte{49, 50}`  | `"12"`   |                           |
| NumericString (invalid)  | `asn1.Tag(asn1.TagNumericString)` | `[]byte{80}`    |          | `"invalid NumericString"`   |

**2. 证书策略 (Policy) 解析功能：**

`TestPolicyParse` 函数测试了从 PEM 编码的证书中解析策略相关信息的功能。这涉及到证书中的 `Certificate Policies` 扩展和相关的策略映射 (Policy Mappings) 等。

**Go 代码举例说明：**

```go
package main

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
)

const policyPEM = `-----BEGIN CERTIFICATE-----
MIIGeDCCBWCgAwIBAgIUED9KQBi0ScBDoufB2mgAJ63G5uIwDQYJKoZIhvcNAQEL
BQAwVTELMAkGA1UEBhMCVVMxGDAWBgNVBAoTD1UuUy4gR292ZXJubWVudDENMAsG
A1UECxMERlBLSTEdMBsGA1UEAxMURmVkZXJhbCBCcmlkZ2UgQ0EgRzQwHhcNMjAx
MDIyMTcwNDE5WhcNMjMxMDIyMTcwNDE5WjCBgTELMAkGA1UEBhMCVVMxHTAbBgNV
BAoTFFN5bWFudGVjIENvcnBvcmF0aW9uMR8wHQYDVQQLExZTeW1hbnRlYyBUcnVz
dCBOZXR3b3JrMTIwMAYDVQQDEylTeW1hbnRlYyBDbGFzcyAzIFNTUCBJbnRlcm1l
ZGlhdGUgQ0EgLSBHMzCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAL2p
75cMpx86sS2aH4r+0o8r+m/KTrPrknWP0RA9Kp6sewAzkNa7BVwg0jOhyamiv1iP
Cns10usoH93nxYbXLWF54vOLRdYU/53KEPNmgkj2ipMaTLuaReBghNibikWSnAmy
S8RItaDMs8tdF2goKPI4xWiamNwqe92VC+pic2tq0Nva3Y4kvMDJjtyje3uduTtL
oyoaaHkrX7i7gE67psnMKj1THUtre1JV1ohl9+oOuyot4p3eSxVlrMWiiwb11bnk
CakecOz/mP2DHMGg6pZ/BeJ+ThaLUylAXECARIqHc9UwRPKC9BfLaCX4edIoeYiB
loRs4KdqLdg/I9eTwKkCAwEAAaOCAxEwggMNMB0GA1UdDgQWBBQ1Jn1QleGhwb0F
1cOdd0LHDBOWjDAfBgNVHSMEGDAWgBR58ABJ6393wl1BAmU0ipAjmx4HbzAOBgNV
HQ8BAf8EBAMCAQYwDwYDVR0TAQH/BAUwAwEB/zCBiAYDVR0gBIGAMH4wDAYKYIZI
AWUDAgEDAzAMBgpghkgBZQMCAQMMMAwGCmCGSAFlAwIBAw4wDAYKYIZIAWUDAgED
DzAMBgpghkgBZQMCAQMSMAwGCmCGSAFlAwIBAxMwDAYKYIZIAWUDAgEDFDAMBgpg
hkgBZQMCAQMlMAwGCmCGSAFlAwIBAyYwggESBgNVHSEEggEJMIIBBTAbBgpghkgB
ZQMCAQMDBg1ghkgBhvhFAQcXAwEGMBsGCmCGSAFlAwIBAwwGDWCGSAGG+EUBBxcD
AQcwGwYKYIZIAWUDAgEDDgYNYIZIAYb4RQEHFwMBDjAbBgpghkgBZQMCAQMPBg1g
hkgBhvhFAQcXAwEPMBsGCmCGSAFlAwIBAxIGDWCGSAGG+EUBBxcDARIwGwYKYIZI
AWUDAgEDEwYNYIZIAYb4RQEHFwMBETAbBgpghkgBZQMCAQMUBg1ghkgBhvhFAQcX
AwEUMBsGCmCGSAFlAwIBAyUGDWCGSAGG+EUBBxcDAQgwGwYKYIZIAWUDAgEDJgYN
YIZIAYb4RQEHFwMBJDBgBggrBgEFBQcBCwRUMFIwUAYIKwYBBQUHMAWGRGh0dHA6
Ly9zc3Atc2lhLnN5bWF1dGguY29tL1NUTlNTUC9DZXJ0c19Jc3N1ZWRfYnlfQ2xh
czMzU1NQQ0EtRzMucDdjMA8GA1UdJAQIMAaAAQCBAQAwCgYDVR02BAMCAQAwUQYI
KwYBBQUHAQEERTBDMEEGCCsGAQUFBzAChjVodHRwOi8vcmVwby5mcGtpLmdvdi9i
cmlkZ2UvY2FDZXJ0c0lzc3VlZFRvZmJjYWc0LnA3YzA3BgNVHR8EMDAuMCygKqAo
hiZodHRwOi8vcmVwby5mcGtpLmdvdi9icmlkZ2UvZmJjYWc0LmNybDANBgkqhkiG
9w0BAQsFAAOCAQEAA751TycC1fWTkHmedF9ZWxP58Jstmwvkyo8bKueJ0eF7LTG
BgQlzE2B9vke4sFhd4V+BdgOPGE1dsGzllYKCWg0BhkCBs5kIJ7F6Ay6G1TBuGU1
Ie8247GL+P9pcC5TVvXHC/62R2w3DuD/vAPLbYEbSQjobXlsqt8Kmtd6yK/jVuDV
BTZMdZmvoNtjemqmgcBXHsf0ctVm0m6tH5uYqyVxu8tfyUis6Cf303PHj+spWP1k
gc5PYnVF0ot7qAmNFENIpbKg3BdusBkF9rGxLaDSUBvSc7+s9iQz9d/iRuAebrYu
+eqUlJ2lsjS1U8qyPmlH+spfPNbAEQEsuP32Aw==
-----END CERTIFICATE-----
`

func main() {
	block, _ := pem.Decode([]byte(policyPEM))
	if block == nil || block.Type != "CERTIFICATE" {
		log.Fatal("failed to decode PEM block containing certificate")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		log.Fatalf("failed to parse certificate: %v", err)
	}

	fmt.Println("策略数量:", len(cert.Policies))
	fmt.Println("策略映射数量:", len(cert.PolicyMappings))
	fmt.Println("RequireExplicitPolicyZero:", cert.RequireExplicitPolicyZero)
	fmt.Println("InhibitPolicyMappingZero:", cert.InhibitPolicyMappingZero)
	fmt.Println("InhibitAnyPolicyZero:", cert.InhibitAnyPolicyZero)
}
```

**假设的输入与输出：**

对于 `TestPolicyParse` 函数，输入是 `policyPEM` 常量中定义的 PEM 编码的证书。输出是解析后的证书对象的 `Policies`、`PolicyMappings` 字段的长度以及 `RequireExplicitPolicyZero`、`InhibitPolicyMappingZero` 和 `InhibitAnyPolicyZero` 字段的值。

**3. 错误策略解析测试：**

`TestParsePolicies` 函数测试了当解析包含特定错误策略的证书时，`ParseCertificate` 函数是否会正确返回错误。它加载了两个测试文件 `policy_leaf_duplicate.pem` 和 `policy_leaf_invalid.pem`，这两个文件分别代表了包含重复策略和无效策略的证书。

**Go 代码举例说明：**

由于这个测试主要是验证错误处理，所以代码主要是检查 `ParseCertificate` 是否返回了非 nil 的错误。

```go
package main

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"log"
)

func main() {
	testFiles := []string{
		"testdata/policy_leaf_duplicate.pem", // 假设存在这个文件
		"testdata/policy_leaf_invalid.pem",   // 假设存在这个文件
	}

	for _, filename := range testFiles {
		certBytes, err := os.ReadFile(filename)
		if err != nil {
			log.Fatalf("无法读取文件 %s: %v", filename, err)
		}
		block, _ := pem.Decode(certBytes)
		if block == nil || block.Type != "CERTIFICATE" {
			log.Fatalf("无法解码 %s 中的 PEM 块", filename)
		}
		_, err = x509.ParseCertificate(block.Bytes)
		if err != nil {
			fmt.Printf("解析文件 %s 时出现错误: %v\n", filename, err)
		} else {
			fmt.Printf("解析文件 %s 应该失败但没有失败\n", filename)
		}
	}
}
```

**命令行参数的具体处理：**

这段代码本身没有直接处理命令行参数。它主要通过读取预定义的 PEM 字符串或本地文件来进行测试。

**使用者易犯错的点：**

1. **ASN.1 字符串类型混淆：**  开发者在处理 ASN.1 编码的数据时，可能会错误地使用不同的字符串类型标签，导致解析失败或得到乱码。例如，将一个 UTF-8 编码的字符串误认为 PrintableString 进行解析。

    ```go
    // 错误的示例：将 UTF-8 编码的 "你好" 当作 PrintableString 解析
    utf8Bytes := []byte{0xe4, 0xbd, 0xa0, 0xe5, 0xa5, 0xbd} // "你好" 的 UTF-8 编码
    _, err := parseASN1String(asn1.PrintableString, utf8Bytes)
    if err != nil {
        fmt.Println("解析出错:", err) // 会输出 "invalid PrintableString"
    }
    ```

2. **PEM 编码格式错误：** 在解析证书时，如果 PEM 编码的格式不正确（例如，缺少 BEGIN/END 行，或者内容不是 Base64 编码），`pem.Decode` 函数会返回 `nil`，导致后续的 `ParseCertificate` 调用出现问题。

    ```go
    invalidPEM := []byte("INVALID CERTIFICATE DATA")
    block, _ := pem.Decode(invalidPEM)
    if block == nil {
        fmt.Println("PEM 解码失败") // 会输出 "PEM 解码失败"
    }
    ```

3. **依赖测试数据：** `TestParsePolicies` 函数依赖于 `testdata` 目录下的特定文件。如果这些文件不存在或内容被修改，测试将会失败。使用者在复制或迁移这些测试代码时需要注意包含这些测试数据。

总而言之，这段测试代码覆盖了 `crypto/x509` 包中关于 ASN.1 字符串解析和证书策略解析的关键功能，帮助确保这些功能的正确性和健壮性。

Prompt: 
```
这是路径为go/src/crypto/x509/parser_test.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。

"""
// Copyright 2021 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package x509

import (
	"encoding/asn1"
	"encoding/pem"
	"os"
	"testing"

	cryptobyte_asn1 "golang.org/x/crypto/cryptobyte/asn1"
)

func TestParseASN1String(t *testing.T) {
	tests := []struct {
		name        string
		tag         cryptobyte_asn1.Tag
		value       []byte
		expected    string
		expectedErr string
	}{
		{
			name:     "T61String",
			tag:      cryptobyte_asn1.T61String,
			value:    []byte{80, 81, 82},
			expected: string("PQR"),
		},
		{
			name:     "PrintableString",
			tag:      cryptobyte_asn1.PrintableString,
			value:    []byte{80, 81, 82},
			expected: string("PQR"),
		},
		{
			name:        "PrintableString (invalid)",
			tag:         cryptobyte_asn1.PrintableString,
			value:       []byte{1, 2, 3},
			expectedErr: "invalid PrintableString",
		},
		{
			name:     "UTF8String",
			tag:      cryptobyte_asn1.UTF8String,
			value:    []byte{80, 81, 82},
			expected: string("PQR"),
		},
		{
			name:        "UTF8String (invalid)",
			tag:         cryptobyte_asn1.UTF8String,
			value:       []byte{255},
			expectedErr: "invalid UTF-8 string",
		},
		{
			name:     "BMPString",
			tag:      cryptobyte_asn1.Tag(asn1.TagBMPString),
			value:    []byte{80, 81},
			expected: string("偑"),
		},
		{
			name:        "BMPString (invalid length)",
			tag:         cryptobyte_asn1.Tag(asn1.TagBMPString),
			value:       []byte{255},
			expectedErr: "invalid BMPString",
		},
		{
			name:     "IA5String",
			tag:      cryptobyte_asn1.IA5String,
			value:    []byte{80, 81},
			expected: string("PQ"),
		},
		{
			name:        "IA5String (invalid)",
			tag:         cryptobyte_asn1.IA5String,
			value:       []byte{255},
			expectedErr: "invalid IA5String",
		},
		{
			name:     "NumericString",
			tag:      cryptobyte_asn1.Tag(asn1.TagNumericString),
			value:    []byte{49, 50},
			expected: string("12"),
		},
		{
			name:        "NumericString (invalid)",
			tag:         cryptobyte_asn1.Tag(asn1.TagNumericString),
			value:       []byte{80},
			expectedErr: "invalid NumericString",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			out, err := parseASN1String(tc.tag, tc.value)
			if err != nil && err.Error() != tc.expectedErr {
				t.Fatalf("parseASN1String returned unexpected error: got %q, want %q", err, tc.expectedErr)
			} else if err == nil && tc.expectedErr != "" {
				t.Fatalf("parseASN1String didn't fail, expected: %s", tc.expectedErr)
			}
			if out != tc.expected {
				t.Fatalf("parseASN1String returned unexpected value: got %q, want %q", out, tc.expected)
			}
		})
	}
}

const policyPEM = `-----BEGIN CERTIFICATE-----
MIIGeDCCBWCgAwIBAgIUED9KQBi0ScBDoufB2mgAJ63G5uIwDQYJKoZIhvcNAQEL
BQAwVTELMAkGA1UEBhMCVVMxGDAWBgNVBAoTD1UuUy4gR292ZXJubWVudDENMAsG
A1UECxMERlBLSTEdMBsGA1UEAxMURmVkZXJhbCBCcmlkZ2UgQ0EgRzQwHhcNMjAx
MDIyMTcwNDE5WhcNMjMxMDIyMTcwNDE5WjCBgTELMAkGA1UEBhMCVVMxHTAbBgNV
BAoTFFN5bWFudGVjIENvcnBvcmF0aW9uMR8wHQYDVQQLExZTeW1hbnRlYyBUcnVz
dCBOZXR3b3JrMTIwMAYDVQQDEylTeW1hbnRlYyBDbGFzcyAzIFNTUCBJbnRlcm1l
ZGlhdGUgQ0EgLSBHMzCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAL2p
75cMpx86sS2aH4r+0o8r+m/KTrPrknWP0RA9Kp6sewAzkNa7BVwg0jOhyamiv1iP
Cns10usoH93nxYbXLWF54vOLRdYU/53KEPNmgkj2ipMaTLuaReBghNibikWSnAmy
S8RItaDMs8tdF2goKPI4xWiamNwqe92VC+pic2tq0Nva3Y4kvMDJjtyje3uduTtL
oyoaaHkrX7i7gE67psnMKj1THUtre1JV1ohl9+oOuyot4p3eSxVlrMWiiwb11bnk
CakecOz/mP2DHMGg6pZ/BeJ+ThaLUylAXECARIqHc9UwRPKC9BfLaCX4edIoeYiB
loRs4KdqLdg/I9eTwKkCAwEAAaOCAxEwggMNMB0GA1UdDgQWBBQ1Jn1QleGhwb0F
1cOdd0LHDBOWjDAfBgNVHSMEGDAWgBR58ABJ6393wl1BAmU0ipAjmx4HbzAOBgNV
HQ8BAf8EBAMCAQYwDwYDVR0TAQH/BAUwAwEB/zCBiAYDVR0gBIGAMH4wDAYKYIZI
AWUDAgEDAzAMBgpghkgBZQMCAQMMMAwGCmCGSAFlAwIBAw4wDAYKYIZIAWUDAgED
DzAMBgpghkgBZQMCAQMSMAwGCmCGSAFlAwIBAxMwDAYKYIZIAWUDAgEDFDAMBgpg
hkgBZQMCAQMlMAwGCmCGSAFlAwIBAyYwggESBgNVHSEEggEJMIIBBTAbBgpghkgB
ZQMCAQMDBg1ghkgBhvhFAQcXAwEGMBsGCmCGSAFlAwIBAwwGDWCGSAGG+EUBBxcD
AQcwGwYKYIZIAWUDAgEDDgYNYIZIAYb4RQEHFwMBDjAbBgpghkgBZQMCAQMPBg1g
hkgBhvhFAQcXAwEPMBsGCmCGSAFlAwIBAxIGDWCGSAGG+EUBBxcDARIwGwYKYIZI
AWUDAgEDEwYNYIZIAYb4RQEHFwMBETAbBgpghkgBZQMCAQMUBg1ghkgBhvhFAQcX
AwEUMBsGCmCGSAFlAwIBAyUGDWCGSAGG+EUBBxcDAQgwGwYKYIZIAWUDAgEDJgYN
YIZIAYb4RQEHFwMBJDBgBggrBgEFBQcBCwRUMFIwUAYIKwYBBQUHMAWGRGh0dHA6
Ly9zc3Atc2lhLnN5bWF1dGguY29tL1NUTlNTUC9DZXJ0c19Jc3N1ZWRfYnlfQ2xh
c3MzU1NQQ0EtRzMucDdjMA8GA1UdJAQIMAaAAQCBAQAwCgYDVR02BAMCAQAwUQYI
KwYBBQUHAQEERTBDMEEGCCsGAQUFBzAChjVodHRwOi8vcmVwby5mcGtpLmdvdi9i
cmlkZ2UvY2FDZXJ0c0lzc3VlZFRvZmJjYWc0LnA3YzA3BgNVHR8EMDAuMCygKqAo
hiZodHRwOi8vcmVwby5mcGtpLmdvdi9icmlkZ2UvZmJjYWc0LmNybDANBgkqhkiG
9w0BAQsFAAOCAQEAA751TycC1f/WTkHmedF9ZWxP58Jstmwvkyo8bKueJ0eF7LTG
BgQlzE2B9vke4sFhd4V+BdgOPGE1dsGzllYKCWg0BhkCBs5kIJ7F6Ay6G1TBuGU1
Ie8247GL+P9pcC5TVvXHC/62R2w3DuD/vAPLbYEbSQjobXlsqt8Kmtd6yK/jVuDV
BTZMdZmvoNtjemqmgcBXHsf0ctVm0m6tH5uYqyVxu8tfyUis6Cf303PHj+spWP1k
gc5PYnVF0ot7qAmNFENIpbKg3BdusBkF9rGxLaDSUBvSc7+s9iQz9d/iRuAebrYu
+eqUlJ2lsjS1U8qyPmlH+spfPNbAEQEsuP32Aw==
-----END CERTIFICATE-----
`

func TestPolicyParse(t *testing.T) {
	b, _ := pem.Decode([]byte(policyPEM))
	c, err := ParseCertificate(b.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Policies) != 9 {
		t.Errorf("unexpected number of policies: got %d, want %d", len(c.Policies), 9)
	}
	if len(c.PolicyMappings) != 9 {
		t.Errorf("unexpected number of policy mappings: got %d, want %d", len(c.PolicyMappings), 9)
	}
	if !c.RequireExplicitPolicyZero {
		t.Error("expected RequireExplicitPolicyZero to be set")
	}
	if !c.InhibitPolicyMappingZero {
		t.Error("expected InhibitPolicyMappingZero to be set")
	}
	if !c.InhibitAnyPolicyZero {
		t.Error("expected InhibitAnyPolicyZero to be set")
	}
}

func TestParsePolicies(t *testing.T) {
	for _, tc := range []string{
		"testdata/policy_leaf_duplicate.pem",
		"testdata/policy_leaf_invalid.pem",
	} {
		t.Run(tc, func(t *testing.T) {
			b, err := os.ReadFile(tc)
			if err != nil {
				t.Fatal(err)
			}
			p, _ := pem.Decode(b)
			_, err = ParseCertificate(p.Bytes)
			if err == nil {
				t.Error("parsing should've failed")
			}
		})
	}
}

"""



```