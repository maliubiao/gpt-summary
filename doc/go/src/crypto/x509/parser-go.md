Response:
My thought process to answer the request goes like this:

1. **Understand the Goal:** The primary goal is to analyze the provided Go code snippet (`parser.go`) and describe its functionality, particularly focusing on parsing X.509 certificate data. The request also asks for a summary of the functionality for this first part.

2. **Initial Code Scan (Keywords and Structure):** I'll quickly scan the code looking for key terms and the overall structure. I see imports related to cryptography (`crypto/*`), ASN.1 encoding (`encoding/asn1`, `golang.org/x/crypto/cryptobyte*`), time (`time`), networking (`net`, `net/url`), and string manipulation (`strings`, `unicode/*`). This strongly suggests the code deals with parsing structured data, likely related to network security and certificates. The filename `parser.go` confirms this.

3. **Identify Core Functions:** I'll then look for the main functions and their purpose based on their names and what they do. Key functions I notice are:

    * `isPrintable`:  Checks if a byte is within the printable ASCII range (with some exceptions).
    * `parseASN1String`: Parses various ASN.1 string types.
    * `parseName`: Parses a DER-encoded distinguished name.
    * `parseAI`: Parses an AlgorithmIdentifier.
    * `parseTime`, `parseValidity`: Parse time representations.
    * `parseExtension`: Parses a certificate extension.
    * `parsePublicKey`: Parses the public key information within a certificate.
    * `parseKeyUsageExtension`, `parseBasicConstraintsExtension`, `parseSANExtension`, `parseAuthorityKeyIdentifier`, `parseExtKeyUsageExtension`, `parseCertificatePoliciesExtension`, `parseNameConstraintsExtension`: These all parse specific X.509 certificate extensions.
    * `isValidIPMask`: Checks the validity of an IP address mask.
    * `forEachSAN`:  A helper function for iterating through Subject Alternative Names.

4. **Infer Overall Functionality:**  Based on the imported packages and the names of the core functions, I can conclude that this code is responsible for parsing the structure and data within X.509 certificates. It deals with ASN.1 decoding, specific field extraction (like issuer, subject, validity dates, public key), and the parsing of various standard certificate extensions.

5. **Focus on the Request's Specific Points:**

    * **Functionality Listing:**  I will explicitly list the functionalities I identified in step 4.

    * **Go Language Feature (ASN.1 Parsing):** The prominent feature is handling ASN.1 encoded data. I'll provide a simple Go example demonstrating how `encoding/asn1` is used for basic encoding and decoding. *Initially, I considered directly using `cryptobyte`, but `encoding/asn1` is a more standard and easily understandable example of ASN.1 handling in Go.*

    * **Code Inference (String Parsing):**  I will choose a simple function like `parseASN1String` to illustrate code inference. I'll provide a few example inputs (different ASN.1 string types) and the expected outputs, highlighting how the function handles different tags.

    * **Command-Line Arguments:** I'll carefully review the code for any handling of command-line arguments. Since there isn't any direct `os.Args` usage or `flag` package usage in this snippet, I'll explicitly state that this part of the code doesn't handle command-line arguments.

    * **User Mistakes:** I will consider potential common errors users might make when interacting with this *parsing* code, such as providing invalid DER-encoded certificates or expecting the parser to handle non-standard certificate formats. I'll provide examples of invalid input and explain why they would cause errors.

    * **Summary of Functionality (for Part 1):** I'll condense the overall functionality identified earlier into a concise summary.

6. **Structure the Answer:**  I'll organize the answer using the headings and subheadings requested, ensuring clarity and readability. I'll use code blocks for Go examples and clearly label inputs and outputs for the inference section.

7. **Review and Refine:** Before submitting, I will review my answer to ensure accuracy, completeness, and clarity. I'll double-check that the code examples are correct and the explanations are easy to understand. I'll also make sure I haven't missed any aspects of the prompt. For example, I made sure to specify *which* language feature I was demonstrating (ASN.1 parsing with `encoding/asn1`).

This systematic approach helps me break down the problem, extract relevant information from the code, and address all aspects of the request in a structured and informative way. The iterative refinement and review steps are crucial for ensuring the quality and correctness of the final answer.
这是对 Go 语言 `crypto/x509` 包中 `parser.go` 文件一部分代码的分析。从提供的代码片段来看，它的主要功能是**解析 X.509 证书及其相关数据结构的 ASN.1 编码**。

更具体地说，这段代码包含了一系列函数，用于解析证书中不同字段和扩展项的 ASN.1 结构。这些函数负责将原始的字节流（DER 编码）转换为 Go 语言中易于操作的数据结构。

**具体功能归纳:**

1. **ASN.1 字符串解析:**
   - `parseASN1String`:  能够解析多种 ASN.1 字符串类型，如 `T61String`, `PrintableString`, `UTF8String`, `BMPString`, `IA5String`, 和 `NumericString`。这对于处理证书中各种文本信息（例如主题和颁发者名称）至关重要。

2. **名称解析 (Distinguished Name):**
   - `parseName`:  解析 DER 编码的 X.509 证书中的名称（Name），将其转换为 `pkix.RDNSequence` 结构。这用于解析证书的 Issuer 和 Subject 字段。

3. **算法标识符解析:**
   - `parseAI`: 解析 ASN.1 编码的算法标识符 (`AlgorithmIdentifier`)，用于确定证书中使用的签名算法和公钥算法。

4. **时间解析:**
   - `parseTime`: 解析 ASN.1 编码的时间值，支持 `UTCTime` 和 `GeneralizedTime` 两种格式。
   - `parseValidity`: 解析证书的有效期，包括 Not Before 和 Not After 两个时间。

5. **扩展项解析:**
   - `parseExtension`: 解析证书的扩展项，包括扩展项的 OID（对象标识符）、是否为关键项以及扩展项的值。
   - 针对不同的扩展项，提供了专门的解析函数：
     - `parseKeyUsageExtension`: 解析密钥用途扩展项。
     - `parseBasicConstraintsExtension`: 解析基本约束扩展项，用于确定证书是否为 CA 证书。
     - `parseSANExtension`: 解析主题备用名称 (Subject Alternative Name) 扩展项，包括 DNS 名称、Email 地址、IP 地址和 URI。
     - `parseAuthorityKeyIdentifier`: 解析颁发机构密钥标识符扩展项。
     - `parseExtKeyUsageExtension`: 解析扩展密钥用途扩展项。
     - `parseCertificatePoliciesExtension`: 解析证书策略扩展项。
     - `parseNameConstraintsExtension`: 解析名称约束扩展项，用于限制证书可以颁发的名称范围。

6. **公钥解析:**
   - `parsePublicKey`:  根据公钥算法的 OID 解析 ASN.1 编码的公钥，支持 RSA、ECDSA、Ed25519、X25519 和 DSA 算法。

7. **辅助功能:**
   - `isPrintable`:  判断一个字节是否属于 ASN.1 `PrintableString` 字符集。
   - `isValidIPMask`:  判断 IP 地址掩码是否有效。
   - `forEachSAN`:  一个辅助函数，用于遍历和处理 Subject Alternative Name 扩展项中的各个条目。

**推理其实现的 Go 语言功能：ASN.1 编码处理**

这段代码的核心功能是处理 ASN.1 编码的数据。Go 语言标准库中的 `encoding/asn1` 包提供了基本的 ASN.1 编码和解码功能。然而，`crypto/x509` 包为了更高的性能和更精细的控制，使用了 `golang.org/x/crypto/cryptobyte` 包，这是一个专门为高效处理密码学数据而设计的库。

**Go 代码示例 (使用 `encoding/asn1` 演示基本 ASN.1 解析概念):**

虽然 `parser.go` 内部使用了 `cryptobyte`, 但为了演示 ASN.1 解析的基本概念，我们可以使用 `encoding/asn1` 包。

```go
package main

import (
	"encoding/asn1"
	"fmt"
	"log"
)

// 定义一个简单的 ASN.1 结构
type Person struct {
	Name  string `asn1:"utf8"`
	Age   int    `asn1:"optional"`
}

func main() {
	// 假设我们有以下 DER 编码的 ASN.1 数据
	// 这段数据表示 Name: "Alice", Age: 30
	derData := []byte{0x30, 0x0d, 0x0c, 0x05, 0x41, 0x6c, 0x69, 0x63, 0x65, 0x02, 0x02, 0x00, 0x1e}

	var person Person
	_, err := asn1.Unmarshal(derData, &person)
	if err != nil {
		log.Fatalf("Failed to unmarshal ASN.1 data: %v", err)
	}

	fmt.Printf("Name: %s, Age: %d\n", person.Name, person.Age)
}
```

**假设的输入与输出 (针对 `parseASN1String` 函数):**

假设我们有以下 ASN.1 编码的字符串数据和对应的 tag：

**输入 1:**

```
tag: cryptobyte_asn1.UTF8String
value: []byte{0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x2c, 0x20, 0x57, 0x6f, 0x72, 0x6c, 0x64} // "Hello, World" 的 UTF-8 编码
```

**输出 1:**

```
string: "Hello, World"
error: nil
```

**输入 2:**

```
tag: cryptobyte_asn1.PrintableString
value: []byte{0x41, 0x42, 0x43, 0x31, 0x32, 0x33} // "ABC123"
```

**输出 2:**

```
string: "ABC123"
error: nil
```

**输入 3 (错误的 PrintableString):**

```
tag: cryptobyte_asn1.PrintableString
value: []byte{0x41, 0x42, 0xe4, 0xb8, 0xad} // 包含非 PrintableString 字符 (中)
```

**输出 3:**

```
string: ""
error: errors.New("invalid PrintableString")
```

**命令行参数处理:**

这段代码本身并没有直接处理命令行参数。命令行参数的处理通常在调用这些解析功能的上层代码中进行。例如，可能有一个命令行工具接受证书文件的路径作为参数，然后读取文件内容并调用 `parseCertificate` 函数进行解析。

**使用者易犯错的点 (以 `parseASN1String` 为例):**

使用者可能容易犯错的地方在于**假设了错误的字符串类型**。例如，如果一个证书字段实际上是 `UTF8String` 编码的，但使用者误以为是 `PrintableString`，那么使用 `parseASN1String` 函数并指定错误的 tag 就会导致解析错误。

**示例：**

假设证书的 Common Name (CN) 属性包含非 ASCII 字符，因此它是 `UTF8String` 类型。如果上层代码在解析 CN 时，错误地使用了 `cryptobyte_asn1.PrintableString` 这个 tag 调用 `parseASN1String`，那么 `parseASN1String` 函数会返回一个 `invalid PrintableString` 的错误。

**功能归纳 (针对提供的代码片段 - 第 1 部分):**

总而言之，这段 `parser.go` 代码的主要功能是**提供了一系列底层的函数，用于将 X.509 证书及其组成部分的 ASN.1 编码数据解析成 Go 语言可以操作的数据结构**。它专注于处理证书的各个字段（如版本号、序列号、颁发者、主题、有效期、公钥信息）以及各种标准扩展项。这段代码是 `crypto/x509` 包实现证书解析功能的核心组成部分。

### 提示词
```
这是路径为go/src/crypto/x509/parser.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```go
// Copyright 2021 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package x509

import (
	"bytes"
	"crypto/dsa"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"internal/godebug"
	"math/big"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode/utf16"
	"unicode/utf8"

	"golang.org/x/crypto/cryptobyte"
	cryptobyte_asn1 "golang.org/x/crypto/cryptobyte/asn1"
)

// isPrintable reports whether the given b is in the ASN.1 PrintableString set.
// This is a simplified version of encoding/asn1.isPrintable.
func isPrintable(b byte) bool {
	return 'a' <= b && b <= 'z' ||
		'A' <= b && b <= 'Z' ||
		'0' <= b && b <= '9' ||
		'\'' <= b && b <= ')' ||
		'+' <= b && b <= '/' ||
		b == ' ' ||
		b == ':' ||
		b == '=' ||
		b == '?' ||
		// This is technically not allowed in a PrintableString.
		// However, x509 certificates with wildcard strings don't
		// always use the correct string type so we permit it.
		b == '*' ||
		// This is not technically allowed either. However, not
		// only is it relatively common, but there are also a
		// handful of CA certificates that contain it. At least
		// one of which will not expire until 2027.
		b == '&'
}

// parseASN1String parses the ASN.1 string types T61String, PrintableString,
// UTF8String, BMPString, IA5String, and NumericString. This is mostly copied
// from the respective encoding/asn1.parse... methods, rather than just
// increasing the API surface of that package.
func parseASN1String(tag cryptobyte_asn1.Tag, value []byte) (string, error) {
	switch tag {
	case cryptobyte_asn1.T61String:
		return string(value), nil
	case cryptobyte_asn1.PrintableString:
		for _, b := range value {
			if !isPrintable(b) {
				return "", errors.New("invalid PrintableString")
			}
		}
		return string(value), nil
	case cryptobyte_asn1.UTF8String:
		if !utf8.Valid(value) {
			return "", errors.New("invalid UTF-8 string")
		}
		return string(value), nil
	case cryptobyte_asn1.Tag(asn1.TagBMPString):
		if len(value)%2 != 0 {
			return "", errors.New("invalid BMPString")
		}

		// Strip terminator if present.
		if l := len(value); l >= 2 && value[l-1] == 0 && value[l-2] == 0 {
			value = value[:l-2]
		}

		s := make([]uint16, 0, len(value)/2)
		for len(value) > 0 {
			s = append(s, uint16(value[0])<<8+uint16(value[1]))
			value = value[2:]
		}

		return string(utf16.Decode(s)), nil
	case cryptobyte_asn1.IA5String:
		s := string(value)
		if isIA5String(s) != nil {
			return "", errors.New("invalid IA5String")
		}
		return s, nil
	case cryptobyte_asn1.Tag(asn1.TagNumericString):
		for _, b := range value {
			if !('0' <= b && b <= '9' || b == ' ') {
				return "", errors.New("invalid NumericString")
			}
		}
		return string(value), nil
	}
	return "", fmt.Errorf("unsupported string type: %v", tag)
}

// parseName parses a DER encoded Name as defined in RFC 5280. We may
// want to export this function in the future for use in crypto/tls.
func parseName(raw cryptobyte.String) (*pkix.RDNSequence, error) {
	if !raw.ReadASN1(&raw, cryptobyte_asn1.SEQUENCE) {
		return nil, errors.New("x509: invalid RDNSequence")
	}

	var rdnSeq pkix.RDNSequence
	for !raw.Empty() {
		var rdnSet pkix.RelativeDistinguishedNameSET
		var set cryptobyte.String
		if !raw.ReadASN1(&set, cryptobyte_asn1.SET) {
			return nil, errors.New("x509: invalid RDNSequence")
		}
		for !set.Empty() {
			var atav cryptobyte.String
			if !set.ReadASN1(&atav, cryptobyte_asn1.SEQUENCE) {
				return nil, errors.New("x509: invalid RDNSequence: invalid attribute")
			}
			var attr pkix.AttributeTypeAndValue
			if !atav.ReadASN1ObjectIdentifier(&attr.Type) {
				return nil, errors.New("x509: invalid RDNSequence: invalid attribute type")
			}
			var rawValue cryptobyte.String
			var valueTag cryptobyte_asn1.Tag
			if !atav.ReadAnyASN1(&rawValue, &valueTag) {
				return nil, errors.New("x509: invalid RDNSequence: invalid attribute value")
			}
			var err error
			attr.Value, err = parseASN1String(valueTag, rawValue)
			if err != nil {
				return nil, fmt.Errorf("x509: invalid RDNSequence: invalid attribute value: %s", err)
			}
			rdnSet = append(rdnSet, attr)
		}

		rdnSeq = append(rdnSeq, rdnSet)
	}

	return &rdnSeq, nil
}

func parseAI(der cryptobyte.String) (pkix.AlgorithmIdentifier, error) {
	ai := pkix.AlgorithmIdentifier{}
	if !der.ReadASN1ObjectIdentifier(&ai.Algorithm) {
		return ai, errors.New("x509: malformed OID")
	}
	if der.Empty() {
		return ai, nil
	}
	var params cryptobyte.String
	var tag cryptobyte_asn1.Tag
	if !der.ReadAnyASN1Element(&params, &tag) {
		return ai, errors.New("x509: malformed parameters")
	}
	ai.Parameters.Tag = int(tag)
	ai.Parameters.FullBytes = params
	return ai, nil
}

func parseTime(der *cryptobyte.String) (time.Time, error) {
	var t time.Time
	switch {
	case der.PeekASN1Tag(cryptobyte_asn1.UTCTime):
		if !der.ReadASN1UTCTime(&t) {
			return t, errors.New("x509: malformed UTCTime")
		}
	case der.PeekASN1Tag(cryptobyte_asn1.GeneralizedTime):
		if !der.ReadASN1GeneralizedTime(&t) {
			return t, errors.New("x509: malformed GeneralizedTime")
		}
	default:
		return t, errors.New("x509: unsupported time format")
	}
	return t, nil
}

func parseValidity(der cryptobyte.String) (time.Time, time.Time, error) {
	notBefore, err := parseTime(&der)
	if err != nil {
		return time.Time{}, time.Time{}, err
	}
	notAfter, err := parseTime(&der)
	if err != nil {
		return time.Time{}, time.Time{}, err
	}

	return notBefore, notAfter, nil
}

func parseExtension(der cryptobyte.String) (pkix.Extension, error) {
	var ext pkix.Extension
	if !der.ReadASN1ObjectIdentifier(&ext.Id) {
		return ext, errors.New("x509: malformed extension OID field")
	}
	if der.PeekASN1Tag(cryptobyte_asn1.BOOLEAN) {
		if !der.ReadASN1Boolean(&ext.Critical) {
			return ext, errors.New("x509: malformed extension critical field")
		}
	}
	var val cryptobyte.String
	if !der.ReadASN1(&val, cryptobyte_asn1.OCTET_STRING) {
		return ext, errors.New("x509: malformed extension value field")
	}
	ext.Value = val
	return ext, nil
}

func parsePublicKey(keyData *publicKeyInfo) (any, error) {
	oid := keyData.Algorithm.Algorithm
	params := keyData.Algorithm.Parameters
	der := cryptobyte.String(keyData.PublicKey.RightAlign())
	switch {
	case oid.Equal(oidPublicKeyRSA):
		// RSA public keys must have a NULL in the parameters.
		// See RFC 3279, Section 2.3.1.
		if !bytes.Equal(params.FullBytes, asn1.NullBytes) {
			return nil, errors.New("x509: RSA key missing NULL parameters")
		}

		p := &pkcs1PublicKey{N: new(big.Int)}
		if !der.ReadASN1(&der, cryptobyte_asn1.SEQUENCE) {
			return nil, errors.New("x509: invalid RSA public key")
		}
		if !der.ReadASN1Integer(p.N) {
			return nil, errors.New("x509: invalid RSA modulus")
		}
		if !der.ReadASN1Integer(&p.E) {
			return nil, errors.New("x509: invalid RSA public exponent")
		}

		if p.N.Sign() <= 0 {
			return nil, errors.New("x509: RSA modulus is not a positive number")
		}
		if p.E <= 0 {
			return nil, errors.New("x509: RSA public exponent is not a positive number")
		}

		pub := &rsa.PublicKey{
			E: p.E,
			N: p.N,
		}
		return pub, nil
	case oid.Equal(oidPublicKeyECDSA):
		paramsDer := cryptobyte.String(params.FullBytes)
		namedCurveOID := new(asn1.ObjectIdentifier)
		if !paramsDer.ReadASN1ObjectIdentifier(namedCurveOID) {
			return nil, errors.New("x509: invalid ECDSA parameters")
		}
		namedCurve := namedCurveFromOID(*namedCurveOID)
		if namedCurve == nil {
			return nil, errors.New("x509: unsupported elliptic curve")
		}
		x, y := elliptic.Unmarshal(namedCurve, der)
		if x == nil {
			return nil, errors.New("x509: failed to unmarshal elliptic curve point")
		}
		pub := &ecdsa.PublicKey{
			Curve: namedCurve,
			X:     x,
			Y:     y,
		}
		return pub, nil
	case oid.Equal(oidPublicKeyEd25519):
		// RFC 8410, Section 3
		// > For all of the OIDs, the parameters MUST be absent.
		if len(params.FullBytes) != 0 {
			return nil, errors.New("x509: Ed25519 key encoded with illegal parameters")
		}
		if len(der) != ed25519.PublicKeySize {
			return nil, errors.New("x509: wrong Ed25519 public key size")
		}
		return ed25519.PublicKey(der), nil
	case oid.Equal(oidPublicKeyX25519):
		// RFC 8410, Section 3
		// > For all of the OIDs, the parameters MUST be absent.
		if len(params.FullBytes) != 0 {
			return nil, errors.New("x509: X25519 key encoded with illegal parameters")
		}
		return ecdh.X25519().NewPublicKey(der)
	case oid.Equal(oidPublicKeyDSA):
		y := new(big.Int)
		if !der.ReadASN1Integer(y) {
			return nil, errors.New("x509: invalid DSA public key")
		}
		pub := &dsa.PublicKey{
			Y: y,
			Parameters: dsa.Parameters{
				P: new(big.Int),
				Q: new(big.Int),
				G: new(big.Int),
			},
		}
		paramsDer := cryptobyte.String(params.FullBytes)
		if !paramsDer.ReadASN1(&paramsDer, cryptobyte_asn1.SEQUENCE) ||
			!paramsDer.ReadASN1Integer(pub.Parameters.P) ||
			!paramsDer.ReadASN1Integer(pub.Parameters.Q) ||
			!paramsDer.ReadASN1Integer(pub.Parameters.G) {
			return nil, errors.New("x509: invalid DSA parameters")
		}
		if pub.Y.Sign() <= 0 || pub.Parameters.P.Sign() <= 0 ||
			pub.Parameters.Q.Sign() <= 0 || pub.Parameters.G.Sign() <= 0 {
			return nil, errors.New("x509: zero or negative DSA parameter")
		}
		return pub, nil
	default:
		return nil, errors.New("x509: unknown public key algorithm")
	}
}

func parseKeyUsageExtension(der cryptobyte.String) (KeyUsage, error) {
	var usageBits asn1.BitString
	if !der.ReadASN1BitString(&usageBits) {
		return 0, errors.New("x509: invalid key usage")
	}

	var usage int
	for i := 0; i < 9; i++ {
		if usageBits.At(i) != 0 {
			usage |= 1 << uint(i)
		}
	}
	return KeyUsage(usage), nil
}

func parseBasicConstraintsExtension(der cryptobyte.String) (bool, int, error) {
	var isCA bool
	if !der.ReadASN1(&der, cryptobyte_asn1.SEQUENCE) {
		return false, 0, errors.New("x509: invalid basic constraints")
	}
	if der.PeekASN1Tag(cryptobyte_asn1.BOOLEAN) {
		if !der.ReadASN1Boolean(&isCA) {
			return false, 0, errors.New("x509: invalid basic constraints")
		}
	}
	maxPathLen := -1
	if der.PeekASN1Tag(cryptobyte_asn1.INTEGER) {
		if !der.ReadASN1Integer(&maxPathLen) {
			return false, 0, errors.New("x509: invalid basic constraints")
		}
	}

	// TODO: map out.MaxPathLen to 0 if it has the -1 default value? (Issue 19285)
	return isCA, maxPathLen, nil
}

func forEachSAN(der cryptobyte.String, callback func(tag int, data []byte) error) error {
	if !der.ReadASN1(&der, cryptobyte_asn1.SEQUENCE) {
		return errors.New("x509: invalid subject alternative names")
	}
	for !der.Empty() {
		var san cryptobyte.String
		var tag cryptobyte_asn1.Tag
		if !der.ReadAnyASN1(&san, &tag) {
			return errors.New("x509: invalid subject alternative name")
		}
		if err := callback(int(tag^0x80), san); err != nil {
			return err
		}
	}

	return nil
}

func parseSANExtension(der cryptobyte.String) (dnsNames, emailAddresses []string, ipAddresses []net.IP, uris []*url.URL, err error) {
	err = forEachSAN(der, func(tag int, data []byte) error {
		switch tag {
		case nameTypeEmail:
			email := string(data)
			if err := isIA5String(email); err != nil {
				return errors.New("x509: SAN rfc822Name is malformed")
			}
			emailAddresses = append(emailAddresses, email)
		case nameTypeDNS:
			name := string(data)
			if err := isIA5String(name); err != nil {
				return errors.New("x509: SAN dNSName is malformed")
			}
			dnsNames = append(dnsNames, string(name))
		case nameTypeURI:
			uriStr := string(data)
			if err := isIA5String(uriStr); err != nil {
				return errors.New("x509: SAN uniformResourceIdentifier is malformed")
			}
			uri, err := url.Parse(uriStr)
			if err != nil {
				return fmt.Errorf("x509: cannot parse URI %q: %s", uriStr, err)
			}
			if len(uri.Host) > 0 {
				if _, ok := domainToReverseLabels(uri.Host); !ok {
					return fmt.Errorf("x509: cannot parse URI %q: invalid domain", uriStr)
				}
			}
			uris = append(uris, uri)
		case nameTypeIP:
			switch len(data) {
			case net.IPv4len, net.IPv6len:
				ipAddresses = append(ipAddresses, data)
			default:
				return errors.New("x509: cannot parse IP address of length " + strconv.Itoa(len(data)))
			}
		}

		return nil
	})

	return
}

func parseAuthorityKeyIdentifier(e pkix.Extension) ([]byte, error) {
	// RFC 5280, Section 4.2.1.1
	if e.Critical {
		// Conforming CAs MUST mark this extension as non-critical
		return nil, errors.New("x509: authority key identifier incorrectly marked critical")
	}
	val := cryptobyte.String(e.Value)
	var akid cryptobyte.String
	if !val.ReadASN1(&akid, cryptobyte_asn1.SEQUENCE) {
		return nil, errors.New("x509: invalid authority key identifier")
	}
	if akid.PeekASN1Tag(cryptobyte_asn1.Tag(0).ContextSpecific()) {
		if !akid.ReadASN1(&akid, cryptobyte_asn1.Tag(0).ContextSpecific()) {
			return nil, errors.New("x509: invalid authority key identifier")
		}
		return akid, nil
	}
	return nil, nil
}

func parseExtKeyUsageExtension(der cryptobyte.String) ([]ExtKeyUsage, []asn1.ObjectIdentifier, error) {
	var extKeyUsages []ExtKeyUsage
	var unknownUsages []asn1.ObjectIdentifier
	if !der.ReadASN1(&der, cryptobyte_asn1.SEQUENCE) {
		return nil, nil, errors.New("x509: invalid extended key usages")
	}
	for !der.Empty() {
		var eku asn1.ObjectIdentifier
		if !der.ReadASN1ObjectIdentifier(&eku) {
			return nil, nil, errors.New("x509: invalid extended key usages")
		}
		if extKeyUsage, ok := extKeyUsageFromOID(eku); ok {
			extKeyUsages = append(extKeyUsages, extKeyUsage)
		} else {
			unknownUsages = append(unknownUsages, eku)
		}
	}
	return extKeyUsages, unknownUsages, nil
}

func parseCertificatePoliciesExtension(der cryptobyte.String) ([]OID, error) {
	var oids []OID
	seenOIDs := map[string]bool{}
	if !der.ReadASN1(&der, cryptobyte_asn1.SEQUENCE) {
		return nil, errors.New("x509: invalid certificate policies")
	}
	for !der.Empty() {
		var cp cryptobyte.String
		var OIDBytes cryptobyte.String
		if !der.ReadASN1(&cp, cryptobyte_asn1.SEQUENCE) || !cp.ReadASN1(&OIDBytes, cryptobyte_asn1.OBJECT_IDENTIFIER) {
			return nil, errors.New("x509: invalid certificate policies")
		}
		if seenOIDs[string(OIDBytes)] {
			return nil, errors.New("x509: invalid certificate policies")
		}
		seenOIDs[string(OIDBytes)] = true
		oid, ok := newOIDFromDER(OIDBytes)
		if !ok {
			return nil, errors.New("x509: invalid certificate policies")
		}
		oids = append(oids, oid)
	}
	return oids, nil
}

// isValidIPMask reports whether mask consists of zero or more 1 bits, followed by zero bits.
func isValidIPMask(mask []byte) bool {
	seenZero := false

	for _, b := range mask {
		if seenZero {
			if b != 0 {
				return false
			}

			continue
		}

		switch b {
		case 0x00, 0x80, 0xc0, 0xe0, 0xf0, 0xf8, 0xfc, 0xfe:
			seenZero = true
		case 0xff:
		default:
			return false
		}
	}

	return true
}

func parseNameConstraintsExtension(out *Certificate, e pkix.Extension) (unhandled bool, err error) {
	// RFC 5280, 4.2.1.10

	// NameConstraints ::= SEQUENCE {
	//      permittedSubtrees       [0]     GeneralSubtrees OPTIONAL,
	//      excludedSubtrees        [1]     GeneralSubtrees OPTIONAL }
	//
	// GeneralSubtrees ::= SEQUENCE SIZE (1..MAX) OF GeneralSubtree
	//
	// GeneralSubtree ::= SEQUENCE {
	//      base                    GeneralName,
	//      minimum         [0]     BaseDistance DEFAULT 0,
	//      maximum         [1]     BaseDistance OPTIONAL }
	//
	// BaseDistance ::= INTEGER (0..MAX)

	outer := cryptobyte.String(e.Value)
	var toplevel, permitted, excluded cryptobyte.String
	var havePermitted, haveExcluded bool
	if !outer.ReadASN1(&toplevel, cryptobyte_asn1.SEQUENCE) ||
		!outer.Empty() ||
		!toplevel.ReadOptionalASN1(&permitted, &havePermitted, cryptobyte_asn1.Tag(0).ContextSpecific().Constructed()) ||
		!toplevel.ReadOptionalASN1(&excluded, &haveExcluded, cryptobyte_asn1.Tag(1).ContextSpecific().Constructed()) ||
		!toplevel.Empty() {
		return false, errors.New("x509: invalid NameConstraints extension")
	}

	if !havePermitted && !haveExcluded || len(permitted) == 0 && len(excluded) == 0 {
		// From RFC 5280, Section 4.2.1.10:
		//   “either the permittedSubtrees field
		//   or the excludedSubtrees MUST be
		//   present”
		return false, errors.New("x509: empty name constraints extension")
	}

	getValues := func(subtrees cryptobyte.String) (dnsNames []string, ips []*net.IPNet, emails, uriDomains []string, err error) {
		for !subtrees.Empty() {
			var seq, value cryptobyte.String
			var tag cryptobyte_asn1.Tag
			if !subtrees.ReadASN1(&seq, cryptobyte_asn1.SEQUENCE) ||
				!seq.ReadAnyASN1(&value, &tag) {
				return nil, nil, nil, nil, fmt.Errorf("x509: invalid NameConstraints extension")
			}

			var (
				dnsTag   = cryptobyte_asn1.Tag(2).ContextSpecific()
				emailTag = cryptobyte_asn1.Tag(1).ContextSpecific()
				ipTag    = cryptobyte_asn1.Tag(7).ContextSpecific()
				uriTag   = cryptobyte_asn1.Tag(6).ContextSpecific()
			)

			switch tag {
			case dnsTag:
				domain := string(value)
				if err := isIA5String(domain); err != nil {
					return nil, nil, nil, nil, errors.New("x509: invalid constraint value: " + err.Error())
				}

				trimmedDomain := domain
				if len(trimmedDomain) > 0 && trimmedDomain[0] == '.' {
					// constraints can have a leading
					// period to exclude the domain
					// itself, but that's not valid in a
					// normal domain name.
					trimmedDomain = trimmedDomain[1:]
				}
				if _, ok := domainToReverseLabels(trimmedDomain); !ok {
					return nil, nil, nil, nil, fmt.Errorf("x509: failed to parse dnsName constraint %q", domain)
				}
				dnsNames = append(dnsNames, domain)

			case ipTag:
				l := len(value)
				var ip, mask []byte

				switch l {
				case 8:
					ip = value[:4]
					mask = value[4:]

				case 32:
					ip = value[:16]
					mask = value[16:]

				default:
					return nil, nil, nil, nil, fmt.Errorf("x509: IP constraint contained value of length %d", l)
				}

				if !isValidIPMask(mask) {
					return nil, nil, nil, nil, fmt.Errorf("x509: IP constraint contained invalid mask %x", mask)
				}

				ips = append(ips, &net.IPNet{IP: net.IP(ip), Mask: net.IPMask(mask)})

			case emailTag:
				constraint := string(value)
				if err := isIA5String(constraint); err != nil {
					return nil, nil, nil, nil, errors.New("x509: invalid constraint value: " + err.Error())
				}

				// If the constraint contains an @ then
				// it specifies an exact mailbox name.
				if strings.Contains(constraint, "@") {
					if _, ok := parseRFC2821Mailbox(constraint); !ok {
						return nil, nil, nil, nil, fmt.Errorf("x509: failed to parse rfc822Name constraint %q", constraint)
					}
				} else {
					// Otherwise it's a domain name.
					domain := constraint
					if len(domain) > 0 && domain[0] == '.' {
						domain = domain[1:]
					}
					if _, ok := domainToReverseLabels(domain); !ok {
						return nil, nil, nil, nil, fmt.Errorf("x509: failed to parse rfc822Name constraint %q", constraint)
					}
				}
				emails = append(emails, constraint)

			case uriTag:
				domain := string(value)
				if err := isIA5String(domain); err != nil {
					return nil, nil, nil, nil, errors.New("x509: invalid constraint value: " + err.Error())
				}

				if net.ParseIP(domain) != nil {
					return nil, nil, nil, nil, fmt.Errorf("x509: failed to parse URI constraint %q: cannot be IP address", domain)
				}

				trimmedDomain := domain
				if len(trimmedDomain) > 0 && trimmedDomain[0] == '.' {
					// constraints can have a leading
					// period to exclude the domain itself,
					// but that's not valid in a normal
					// domain name.
					trimmedDomain = trimmedDomain[1:]
				}
				if _, ok := domainToReverseLabels(trimmedDomain); !ok {
					return nil, nil, nil, nil, fmt.Errorf("x509: failed to parse URI constraint %q", domain)
				}
				uriDomains = append(uriDomains, domain)

			default:
				unhandled = true
			}
		}

		return dnsNames, ips, emails, uriDomains, nil
	}

	if out.PermittedDNSDomains, out.PermittedIPRanges, out.PermittedEmailAddresses, out.PermittedURIDomains, err = getValues(permitted); err != nil {
		return false, err
	}
	if out.ExcludedDNSDomains, out.ExcludedIPRanges, out.ExcludedEmailAddresses, out.ExcludedURIDomains, err = getValues(excluded); err != nil {
		return false, err
	}
	out.PermittedDNSDomainsCritical = e.Critical

	return unhandled, nil
}

func processExtensions(out *Certificate) error {
	var err error
	for _, e := range out.Extensions {
		unhandled := false

		if len(e.Id) == 4 && e.Id[0] == 2 && e.Id[1] == 5 && e.Id[2] == 29 {
			switch e.Id[3] {
			case 15:
				out.KeyUsage, err = parseKeyUsageExtension(e.Value)
				if err != nil {
					return err
				}
			case 19:
				out.IsCA, out.MaxPathLen, err = parseBasicConstraintsExtension(e.Value)
				if err != nil {
					return err
				}
				out.BasicConstraintsValid = true
				out.MaxPathLenZero = out.MaxPathLen == 0
			case 17:
				out.DNSNames, out.EmailAddresses, out.IPAddresses, out.URIs, err = parseSANExtension(e.Value)
				if err != nil {
					return err
				}

				if len(out.DNSNames) == 0 && len(out.EmailAddresses) == 0 && len(out.IPAddresses) == 0 && len(out.URIs) == 0 {
					// If we didn't parse anything then we do the critical check, below.
					unhandled = true
				}

			case 30:
				unhandled, err = parseNameConstraintsExtension(out, e)
				if err != nil {
					return err
				}

			case 31:
				// RFC 5280, 4.2.1.13

				// CRLDistributionPoints ::= SEQUENCE SIZE (1..MAX) OF DistributionPoint
				//
				// DistributionPoint ::= SEQUENCE {
				//     distributionPoint       [0]     DistributionPointName OPTIONAL,
				//     reasons                 [1]     ReasonFlags OPTIONAL,
				//     cRLIssuer               [2]     GeneralNames OPTIONAL }
				//
				// DistributionPointName ::= CHOICE {
				//     fullName                [0]     GeneralNames,
				//     nameRelativeToCRLIssuer [1]     RelativeDistinguishedName }
				val := cryptobyte.String(e.Value)
				if !val.ReadASN1(&val, cryptobyte_asn1.SEQUENCE) {
					return errors.New("x509: invalid CRL distribution points")
				}
				for !val.Empty() {
					var dpDER cryptobyte.String
					if !val.ReadASN1(&dpDER, cryptobyte_asn1.SEQUENCE) {
						return errors.New("x509: invalid CRL distribution point")
					}
					var dpNameDER cryptobyte.String
					var dpNamePresent bool
					if !dpDER.ReadOptionalASN1(&dpNameDER, &dpNamePresent, cryptobyte_asn1.Tag(0).Constructed().ContextSpecific()) {
						return errors.New("x509: invalid CRL distribution point")
					}
					if !dpNamePresent {
						continue
					}
					if !dpNameDER.ReadASN1(&dpNameDER, cryptobyte_asn1.Tag(0).Constructed().ContextSpecific()) {
						return errors.New("x509: invalid CRL distribution point")
					}
					for !dpNameDER.Empty() {
						if !dpNameDER.PeekASN1Tag(cryptobyte_asn1.Tag(6).ContextSpecific()) {
							break
						}
						var uri cryptobyte.String
						if !dpNameDER.ReadASN1(&uri, cryptobyte_asn1.Tag(6).ContextSpecific()) {
							return errors.New("x509: invalid CRL distribution point")
						}
						out.CRLDistributionPoints = append(out.CRLDistributionPoints, string(uri))
					}
				}

			case 35:
				out.AuthorityKeyId, err = parseAuthorityKeyIdentifier(e)
				if err != nil {
					return err
				}
			case 36:
				val := cryptobyte.String(e.Value)
				if !val.ReadASN1(&val, cryptobyte_asn1.SEQUENCE) {
					return errors.New("x509: invalid policy constraints extension")
				}
				if val.PeekASN1Tag(cryptobyte_asn1.Tag(0).ContextSpecific()) {
					var v int64
					if !val.ReadASN1Int64WithTag(&v, cryptobyte_asn1.Tag(0).ContextSpecific()) {
						return errors.New("x509: invalid policy constraints extension")
					}
					out.RequireExplicitPolicy = int(v)
					// Check for overflow.
					if int64(out.RequireExplicitPolicy) != v {
						return errors.New("x509: policy constraints requireExplicitPolicy field overflows int")
					}
					out.RequireExplicitPolicyZero = out.RequireExplicitPolicy == 0
				}
				if val.PeekASN1Tag(cryptobyte_asn1.Tag(1).ContextSpecific()) {
					var v int64
					if !val.ReadASN1Int64WithTag(&v, cryptobyte_asn1.Tag(1).ContextSpecific()) {
						return errors.New("x509: invalid policy constraints extension")
					}
					out.InhibitPolicyMapping = int(v)
					// Check for overflow.
					if int64(out.InhibitPolicyMapping) != v {
						return errors.New("x509: policy constraints inhibitPolicyMapping field overflows int")
					}
					out.InhibitPolicyMappingZero = out.InhibitPolicyMapping == 0
				}
			case 37:
				out.ExtKeyUsage, out.UnknownExtKeyUsage, err = parseExtKeyUsageExtension(e.Value)
				if err != nil {
					return err
				}
			case 14: // RFC 5280, 4.2.1.2
				if e.Critical {
					// Conforming CAs MUST mark this extension as non-critical
					return errors.New("x509: subject key identifier incorrectly marked critical")
				}
				val := cryptobyte.String(e.Value)
				var skid cryptobyte.String
				if !val.ReadASN1(&skid, cryptobyte_asn1.OCTET_STRING) {
					return errors.New("x509: invalid subject key identifier")
				}
				out.SubjectKeyId = skid
			case 32:
				out.Policies, err = parseCertificatePoliciesExtension(e.Value)
				if err != nil {
					return err
				}
				out.PolicyIdentifiers = make([]asn1.ObjectIdentifier, 0, len(out.Policies))
				for _, oid := range out.Policies {
					if oid, ok := oid.toASN1OID(); ok {
						out.PolicyIdentifiers = append(out.PolicyIdentifiers, oid)
					}
				}
			case 33:
				val := cryptobyte.String(e.Value)
				if !val.ReadASN1(&val, cryptobyte_asn1.SEQUENCE) {
					return errors.New("x509: invalid policy mappings extension")
				}
				for !val.Empty() {
					var s cryptobyte.String
					var issuer, subject cryptobyte.String
					if !val.ReadASN1(&s, cryptobyte_asn1.SEQUENCE) ||
						!s.ReadASN1(&issuer, cryptobyte_asn1.OBJECT_IDENTIFIER) ||
						!s.ReadASN1(&subject, cryptobyte_asn1.OBJECT_IDENTIFIER) {
						return errors.New("x509: invalid policy mappings extension")
					}
					out.PolicyMappings = append(out.PolicyMappings, PolicyMapping{OID{issuer}, OID{subject}})
				}
			case 54:
				val := cryptobyte.String(e.Value)
				if !val.ReadASN1Integer(&out.InhibitAnyPolicy) {
					return errors.New("x509: invalid inhibit any policy extension")
				}
				out.InhibitAnyPolicyZero = out.InhibitAnyPolicy == 0
			default:
				// Unknown extensions are recorded if critical.
				unhandled = true
			}
		} else if e.Id.Equal(oidExtensionAuthorityInfoAccess) {
			// RFC 5280 4.2.2.1: Authority Information Access
			if e.Critical {
				// Conforming CAs MUST mark this extension as non-critical
				return errors.New("x509: authority info access incorrectly marked critical")
			}
			val := cryptobyte.String(e.Value)
			if !val.ReadASN1(&val, cryptobyte_asn1.SEQUENCE) {
				return errors.New("x509: invalid authority info access")
			}
			for !val.Empty() {
				var aiaDER cryptobyte.String
				if !val.ReadASN1(&aiaDER, cryptobyte_asn1.SEQUENCE) {
					return errors.New("x509: invalid authority info access")
				}
				var method asn1.ObjectIdentifier
				if !aiaDER.ReadASN1ObjectIdentifier(&method) {
					return errors.New("x509: invalid authority info access")
				}
				if !aiaDER.PeekASN1Tag(cryptobyte_asn1.Tag(6).ContextSpecific()) {
					continue
				}
				if !aiaDER.ReadASN1(&aiaDER, cryptobyte_asn1.Tag(6).ContextSpecific()) {
					return errors.New("x509: invalid authority info access")
				}
				switch {
				case method.Equal(oidAuthorityInfoAccessOcsp):
					out.OCSPServer = append(out.OCSPServer, string(aiaDER))
				case method.Equal(oidAuthorityInfoAccessIssuers):
					out.IssuingCertificateURL = append(out.IssuingCertificateURL, string(aiaDER))
				}
			}
		} else {
			// Unknown extensions are recorded if critical.
			unhandled = true
		}

		if e.Critical && unhandled {
			out.UnhandledCriticalExtensions = append(out.UnhandledCriticalExtensions, e.Id)
		}
	}

	return nil
}

var x509negativeserial = godebug.New("x509negativeserial")

func parseCertificate(der []byte) (*Certificate, error) {
	cert := &Certificate{}

	input := cryptobyte.String(der)
	// we read the SEQUENCE including length and tag bytes so that
	// we can populate Certificate.Raw, before unwrapping the
	// SEQUENCE so it can be operated on
	if !input.ReadASN1Element(&input, cryptobyte_asn1.SEQUENCE) {
		return nil, errors.New("x509: malformed certificate")
	}
	cert.Raw = input
	if !input.ReadASN1(&input, cryptobyte_asn1.SEQUENCE) {
		return nil, errors.New("x509: malformed certificate")
	}

	var tbs cryptobyte.String
	// do the same trick again as above to extract the raw
	// bytes for Certificate.RawTBSCertificate
	if !input.ReadASN1Element(&tbs, cryptobyte_asn1.SEQUENCE) {
		return nil, errors.New("x509: malformed tbs certificate")
	}
	cert.RawTBSCertificate = tbs
	if !tbs.ReadASN1(&tbs, cryptobyte_asn1.SEQUENCE) {
		return nil, errors.New("x509: malformed tbs certificate")
	}

	if !tbs.ReadOptionalASN1Integer(&cert.Version, cryptobyte_asn1.Tag(0).Constructed().ContextSpecific(), 0) {
		return nil, errors.New("x509: malformed version")
	}
	if cert.Version < 0 {
		return nil, errors.New("x509: malformed version")
	}
	// for backwards compat reasons Version is one-indexed,
	// rather than zero-indexed as defined in 5280
	cert.Version++
	if cert.Version > 3 {
		return nil, errors.New("x509: invalid version")
	}

	serial := new(big.Int)
	if !tbs.ReadASN1Integer(serial) {
		return nil, errors.New("x509: malformed serial number")
	}
	if serial.Sign() == -1 {
		if x509negativeserial.Value() != "1" {
			return nil, errors.New("x509: negative serial number")
		} else {
			x509negativeserial.IncNonDefault()
		}
	}
	cert.SerialNumber = serial

	var sigAISeq cryptobyte.String
	if !tbs.ReadASN1(&sigAISeq, cryptobyte_asn1.SEQUENCE) {
		return nil, errors.New("x509: malformed signature algorithm identifier")
	}
	// Before parsing the inner algorithm identifier, extract
	// the outer algorithm identifier and make sure that they
	// match.
	var outerSigAISeq cryptobyte.String
	if !input.ReadASN1(&outerSigAISeq, cryptobyte_asn1.SEQUENCE) {
		return nil, errors.New("x509: malformed algorithm identifier")
	}
	if !bytes.Equal(outerSigAISeq, sigAISeq) {
		return nil, errors.New("x509: inner and outer signature algorithm identifiers don't match")
	}
	sigAI, err := parseAI(sigAISeq)
	if err != nil {
		return nil, err
	}
	cert.SignatureAlgorithm = getSignatureAlgorithmFromAI(sigAI)

	var issuerSeq cryptobyte.String
	if !tbs.ReadASN1Element(&issuerSeq, cryptobyte_asn1.SEQUENCE) {
		return nil, errors.New("x509: malformed issuer")
	}
	cert.RawIssuer = issuerSeq
	issuerRDNs, err := parseName(issuerSeq)
	if err != nil {
		return nil, err
	}
	cert.Issuer.FillFromRDNSequence(issuerRDNs)

	var validity cryptobyte.String
	if !tbs.ReadASN1(&validity, cryptobyte_asn1.SEQUENCE) {
		return nil, errors.New("x509: malformed validity")
	}
	cert.NotBefore, cert.NotAfter, err = parseValidity(validity)
	if err != nil {
		return nil, err
	}

	var subjectSeq cryptobyte.String
	if !tbs.ReadASN1Element(&subjectSeq, cryptobyte_asn1.SEQUENCE) {
		return nil, errors.New("x509: malformed issuer")
	}
	cert.RawSubject = subjectSeq
	subjectRDNs, err := parseName(subjectSeq)
	if err != nil {
		return nil, err
	}
	cert.Subject.FillFromRDNSequence(subjectRDNs)

	var spki cryptobyte.String
	if !tbs.ReadASN1Element(&spki, cryptobyte_asn1.SEQUENCE) {
		return nil, errors.New("x509: malformed spki")
	}
	cert.RawSubjectPublicKeyInfo = spki
	if !spki.ReadASN1(&spki, cryptobyte_asn1.SEQUENCE) {
		return nil, errors.New("x509: malformed spki")
	}
	var pkAISeq cryptobyte.String
	if !spki.ReadASN1(&pkAISeq, cryptobyte_asn1.SEQUENCE) {
		return nil, errors.New("x509: malformed public key algorithm identifier")
	}
	pkAI, err := parseAI(pkAISeq)
	if err != nil {
		return nil, err
	}
	cert.PublicKeyAlgorithm = getPublicKeyAlgorithmFromOID(pkAI.Algorithm)
	var spk asn1.BitString
	if !spki.ReadASN1BitString(&spk) {
		return nil, errors.New("x509: malformed subjectPublicKey")
	}
	if cert.PublicKeyAlgorithm != UnknownPublicKeyAlgorithm {
		cert.PublicKey, err = parsePublicKey(&publicKeyInfo{
			Algorithm: pkAI,
			PublicKey: spk,
		})
		if err != nil {
			return nil, err
		}
	}

	if cert.Version > 1 {
		if !tbs.SkipOptionalASN1(cryptobyte_asn1.Tag(1).ContextSpecific()) {
			return nil, errors.New("x509: malformed issuerUniqueID")
		}
		if !tbs.SkipOptionalASN1(cryptobyte_asn1.Tag(2).ContextSpecific()) {
			return nil, errors.New("x509: malformed subjectUniqueID")
		}
		if cert.Version == 3 {
			var extensions cryptobyte.String
			var present bool
			if !tbs.ReadOptionalASN1(&extensions, &present, cryptobyte_asn1.Tag(3).Constructed().ContextSpecific()) {
				return nil, errors.New("x509: malformed extensions")
			}
			if present {
				seenExts :=
```