Response:
My goal is to analyze the provided Go code snippet and answer the user's question in Chinese. Here's a breakdown of my thought process:

1. **Understand the User's Request:** The user provided a segment of a Go test file (`go/src/crypto/x509/x509_test.go`) and wants to know its functionality. They've explicitly asked for a breakdown of its features, examples of Go language functionalities it implements, code examples with assumed inputs/outputs for code inference, handling of command-line arguments (if any), common mistakes users might make, and a summary of its function as part one of a larger series.

2. **Initial Code Scan and Keyword Recognition:** I started by scanning the code for prominent keywords and function names related to X.509 certificates and cryptographic operations. Keywords like `TestParsePKCS1PrivateKey`, `TestParsePKIXPublicKey`, `TestMarshalRSAPrivateKey`, `TestVerifyHostname`, `CreateCertificate`, and imports like `crypto/rsa`, `crypto/ecdsa`, `encoding/pem`, `encoding/asn1` immediately suggest the code's primary focus. The `testing` import confirms it's a test file.

3. **Categorizing Functionality:** Based on the initial scan, I mentally categorized the code into key areas:
    * **Parsing Private Keys:**  Functions like `TestParsePKCS1PrivateKey` and `TestMarshalRSAPrivateKey` and related constants (e.g., `pemPrivateKey`) are clearly about handling RSA private keys.
    * **Parsing Public Keys:**  Functions like `TestParsePKIXPublicKey` and `TestMarshalRSAPublicKey`, along with `pemPublicKey`, deal with public keys (both PKCS#1 and PKIX formats). The presence of `pemEd25519Key` and `pemX25519Key` indicates support for other key types as well.
    * **Public Key Format Mismatches:**  `TestPKCS1MismatchPublicKeyFormat` and `TestPKIXMismatchPublicKeyFormat` suggest the code tests error handling when trying to parse keys with the wrong format.
    * **Certificate Creation:** `TestCreateSelfSignedCertificate` is explicitly about generating self-signed certificates.
    * **Hostname Verification:** `TestMatchHostnames` and `TestMatchIP` focus on verifying hostnames against certificate DNS names and IP addresses.
    * **Certificate Parsing:**  `TestCertificateParse` and `certBytes` are involved in parsing and examining X.509 certificates.
    * **Error Handling:** Many tests check for expected errors, which is a crucial part of testing.

4. **Detailed Analysis of Key Functions:** I then focused on understanding the core functions:
    * **`ParsePKCS1PrivateKey` and `ParsePKIXPublicKey`:** These functions are responsible for decoding PEM-encoded or DER-encoded private and public keys, respectively. The tests demonstrate parsing and comparing the results with expected values.
    * **`MarshalPKCS1PrivateKey` and `MarshalPKIXPublicKey`:** These functions perform the reverse operation, encoding private and public keys into DER format. The tests check if the original key can be reconstructed by parsing the marshaled output.
    * **`VerifyHostname`:** This function appears to be crucial for validating if a given hostname matches the names specified in a certificate. The tests cover various wildcard scenarios and edge cases.
    * **`CreateCertificate`:** This function generates a self-signed X.509 certificate based on a provided template and key pair. The test checks various fields of the generated certificate.

5. **Inferring Go Language Features:** The code clearly uses several Go features:
    * **Standard Library Packages:**  Extensive use of `crypto`, `encoding`, `net`, `strings`, `testing`, `time`, etc.
    * **Pointers and Structs:**  Working with `rsa.PrivateKey`, `rsa.PublicKey`, `Certificate`, etc.
    * **Error Handling:**  Checking for `err != nil`.
    * **Testing Framework:**  Using `testing.T` for test functions and assertions (`t.Errorf`, `t.Fatalf`).
    * **PEM Encoding:**  Using `encoding/pem` for encoding and decoding.
    * **ASN.1 Encoding:** Using `encoding/asn1` for encoding and decoding.
    * **Interfaces:** The `crypto.PrivateKey` and `crypto.PublicKey` interfaces are implicitly used.

6. **Code Examples and Assumptions:**  For code inference, I selected the key parsing and marshaling functions and created simple examples demonstrating their usage, assuming the existence of PEM-encoded keys. I included the assumed input (PEM string) and the expected output (the parsed key structure or marshaled bytes).

7. **Command-Line Arguments:**  I observed that the provided code snippet is primarily focused on testing and doesn't directly process command-line arguments. Therefore, I concluded that this particular part doesn't handle them.

8. **Common Mistakes:**  I identified the primary common mistake as attempting to parse keys using the incorrect function (e.g., using `ParsePKCS1PublicKey` for a PKIX-formatted key). The "MismatchPublicKeyFormat" tests directly address this.

9. **Summarizing Functionality (Part 1):**  Finally, I synthesized the information gathered into a concise summary of the code's functionality, emphasizing its role in testing the parsing, marshaling, and basic operations related to X.509 certificates and cryptographic keys within the `crypto/x509` package. I explicitly noted that it focuses on testing functionalities related to RSA, ECDSA, and EdDSA keys, public and private key parsing and serialization, and hostname verification.

10. **Review and Refinement:** I reviewed my analysis to ensure accuracy, clarity, and completeness, ensuring all aspects of the user's request were addressed. I paid attention to using correct Chinese terminology and formatting. I double-checked the code examples to ensure they were valid and illustrative.

This iterative process of scanning, categorizing, analyzing, inferring, and summarizing allowed me to construct a comprehensive and accurate response to the user's query.
这段 Go 语言代码文件 `go/src/crypto/x509/x509_test.go` 的一部分主要功能是**测试 Go 语言标准库中 `crypto/x509` 包关于 X.509 证书和密钥处理的功能。**

具体来说，这部分代码涵盖了以下方面的测试：

* **私钥解析 (Private Key Parsing):**
    * 测试解析 PKCS#1 格式的 RSA 私钥 (`TestParsePKCS1PrivateKey`)。
    * 测试将 `rsa.PrivateKey` 结构体序列化为 PKCS#1 DER 格式 (`TestMarshalRSAPrivateKey`)，并能再次反序列化。
    * 测试解析损坏的 PKCS#1 RSA 私钥，并验证是否会报错 (`TestMarshalRSAPrivateKeyInvalid`)。

* **公钥解析 (Public Key Parsing):**
    * 测试解析 PKCS#1 格式的 RSA 公钥 (`TestMarshalRSAPublicKey`)。
    * 测试解析 PKIX 格式的各种公钥 (RSA, Ed25519, X25519) (`TestParsePKIXPublicKey`)。
    * 测试将 `rsa.PublicKey` 结构体序列化为 PKCS#1 DER 格式 (`TestMarshalRSAPublicKey`)。

* **公钥格式不匹配错误处理 (Public Key Format Mismatch Error Handling):**
    * 测试当尝试用 `ParsePKCS1PublicKey` 解析 PKIX 格式的公钥时，会返回预期的错误 (`TestPKCS1MismatchPublicKeyFormat`)。
    * 测试当尝试用 `ParsePKIXPublicKey` 解析 PKCS#1 格式的公钥时，会返回预期的错误 (`TestPKIXMismatchPublicKeyFormat`)。

* **无效公钥处理 (Invalid Public Key Handling):**
    * 测试尝试序列化无效的公钥结构体时会报错 (`TestMarshalInvalidPublicKey`)。

* **主机名匹配 (Hostname Matching):**
    * 测试 `VerifyHostname` 方法，验证给定的主机名是否与证书中的 DNSNames 匹配，包括通配符的情况 (`TestMatchHostnames`)。
    * 测试 `VerifyHostname` 方法，验证给定的 IP 地址是否与证书中的 IPAddresses 匹配 (`TestMatchIP`)。

* **证书解析 (Certificate Parsing):**
    * 测试解析多个证书 (`TestCertificateParse`)。
    * 测试 `CheckSignatureFrom` 方法，验证证书的签名是否由另一个证书签发。
    * 测试 `VerifyHostname` 方法对已解析证书的验证。
    * 测试证书扩展字段的解析。

* **证书相等性比较 (Certificate Equality):**
    * 测试 `Equal` 方法在 nil 证书上的行为 (`TestCertificateEqualOnNil`)。

* **签名算法不匹配错误处理 (Mismatched Signature Algorithm Error Handling):**
    * 测试当使用错误的签名算法验证证书签名时，会返回预期的错误 (`TestMismatchedSignatureAlgorithm`)。

* **自签名证书创建 (Self-Signed Certificate Creation):**
    * 测试 `CreateCertificate` 函数，创建各种密钥类型的自签名证书 (RSA, ECDSA, Ed25519) (`TestCreateSelfSignedCertificate`)。
    * 验证创建的证书的各个字段是否符合预期，例如 Subject, Issuer, 有效期, 密钥用法, 扩展字段等。

**用 Go 代码举例说明:**

```go
package main

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
)

func main() {
	// 假设我们有一个 PEM 编码的 RSA 私钥
	pemPrivateKey := `-----BEGIN RSA PRIVATE KEY-----
MIICXAIBAAKBgQCxoeCUW5KJxNPxMp+KmCxKLc1Zv9Ny+4CFqcUXVUYH69L3mQ7v
IWrJ9GBfcaA7BPQqUlWxWM+OCEQZH1EZNIuqRMNQVuIGCbz5UQ8w6tS0gcgdeGX7
J7jgCQ4RK3F/PuCM38QBLaHx988qG8NMc6VKErBjctCXFHQt14lerd5KpQIDAQAB
... (省略剩余部分)
-----END RSA PRIVATE KEY-----`

	// 将 PEM 解码为 block
	block, _ := pem.Decode([]byte(pemPrivateKey))
	if block == nil {
		log.Fatal("failed to decode PEM private key")
	}

	// 使用 ParsePKCS1PrivateKey 解析私钥
	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		log.Fatalf("failed to parse private key: %v", err)
	}

	fmt.Printf("解析后的私钥 N 的值: %v\n", privateKey.PublicKey.N)

	// 将私钥重新序列化为 DER 格式
	derBytes := x509.MarshalPKCS1PrivateKey(privateKey)
	fmt.Printf("重新序列化后的私钥 (DER 格式前 20 字节): %x\n", derBytes[:20])

	// 假设我们有一个 PEM 编码的 RSA 公钥
	pemPublicKey := `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA3VoPN9PKUjKFLMwOge6+
wnDi8sbETGIx2FKXGgqtAKpzmem53kRGEQg8WeqRmp12wgp74TGpkEXsGae7RS1k
enJCnma4fii+noGH7R0qKgHvPrI2Bwa9hzsH8tHxpyM3qrXslOmD45EH9SxIDUBJ
FehNdaPbLP1gFyahKMsdfxFJLUvbUycuZSJ2ZnIgeVxwm4qbSvZInL9Iu4FzuPtg
fINKcbbovy1qq4KvPIrXzhbY3PWDc6btxCf3SE0JdE1MCPThntB62/bLMSQ7xdDR
FF53oIpvxe/SCOymfWq/LW849Ytv3Xwod0+wzAP8STXG4HSELS4UedPYeHJJJYcZ
+QIDAQAB
-----END PUBLIC KEY-----`

	// 将 PEM 解码为 block
	blockPub, _ := pem.Decode([]byte(pemPublicKey))
	if blockPub == nil {
		log.Fatal("failed to decode PEM public key")
	}

	// 使用 ParsePKIXPublicKey 解析公钥
	publicKeyInterface, err := x509.ParsePKIXPublicKey(blockPub.Bytes)
	if err != nil {
		log.Fatalf("failed to parse public key: %v", err)
	}

	// 类型断言到 rsa.PublicKey
	publicKey, ok := publicKeyInterface.(*rsa.PublicKey)
	if !ok {
		log.Fatal("parsed public key is not an RSA public key")
	}

	fmt.Printf("解析后的公钥 N 的值: %v\n", publicKey.N)
}
```

**假设的输入与输出:**

**输入 (假设的 PEM 编码的 RSA 私钥):**

```
-----BEGIN RSA PRIVATE KEY-----
MIICXAIBAAKBgQCxoeCUW5KJxNPxMp+KmCxKLc1Zv9Ny+4CFqcUXVUYH69L3mQ7v
IWrJ9GBfcaA7BPQqUlWxWM+OCEQZH1EZNIuqRMNQVuIGCbz5UQ8w6tS0gcgdeGX7
J7jgCQ4RK3F/PuCM38QBLaHx988qG8NMc6VKErBjctCXFHQt14lerd5KpQIDAQAB
AoGAYrf6Hbk+mT5AI33k2Jt1kcweodBP7UkExkPxeuQzRVe0KVJw0EkcFhywKpr1
V5eLMrILWcJnpyHE5slWwtFHBG6a5fLaNtsBBtcAIfqTQ0Vfj5c6SzVaJv0Z5rOd
7gQF6isy3t3w9IF3We9wXQKzT6q5ypPGdm6fciKQ8RnzREkCQQDZwppKATqQ41/R
vhSj90fFifrGE6aVKC1hgSpxGQa4oIdsYYHwMzyhBmWW9Xv/R+fPyr8ZwPxp2c12
33QwOLPLAkEA0NNUb+z4ebVVHyvSwF5jhfJxigim+s49KuzJ1+A2RaSApGyBZiwS
rWvWkB471POAKUYt5ykIWVZ83zcceQiNTwJBAMJUFQZX5GDqWFc/zwGoKkeR49Yi
MTXIvf7Wmv6E++eFcnT461FlGAUHRV+bQQXGsItR/opIG7mGogIkVXa3E1MCQARX
AAA7eoZ9AEHflUeuLn9QJI/r0hyQQLEtrpwv6rDT1GCWaLII5HJ6NUFVf4TTcqxo
6vdM4QGKTJoO+SaCyP0CQFdpcxSAuzpFcKv0IlJ8XzS/cy+mweCMwyJ1PFEc4FX6
wg/HcAJWY60xZTJDFN+Qfx8ZQvBEin6c2/h+zZi5IVY=
-----END RSA PRIVATE KEY-----
```

**输出 (假设的解析后的私钥 N 的值):**

```
解析后的私钥 N 的值: 124737666279038955318614287965056875799409043964547386061640914307192830334599556034328900586693254156136128122194531292927142396093148164407300419162827624945636708870992355233833321488652786796134504707628792159725681555822420087112284637501705261187690946267527866880072856272532711620639179596808018872997
```

**输出 (假设的重新序列化后的私钥 DER 格式前 20 字节):**

```
重新序列化后的私钥 (DER 格式前 20 字节): 30 82 04 89 02 01 00 02 82 01 01 00 8b a1 e0 94 b7 92 
```

**命令行参数的具体处理:**

这段代码主要是测试代码，**不涉及直接处理命令行参数**。它依赖于 Go 的 `testing` 包来运行测试用例，通常是通过 `go test` 命令来执行。

**使用者易犯错的点:**

* **使用错误的解析函数:**  初学者容易混淆 `ParsePKCS1PrivateKey` 和 `ParsePKIXPublicKey` 的使用场景，导致解析失败。例如，用 `ParsePKCS1PrivateKey` 解析 PKIX 格式的公钥或私钥，反之亦然。
    ```go
    // 错误示例：尝试用 ParsePKCS1PrivateKey 解析 PKIX 格式的公钥
    block, _ := pem.Decode([]byte(pemPublicKey)) // pemPublicKey 是 PKIX 格式
    _, err := x509.ParsePKCS1PrivateKey(block.Bytes)
    if err == nil {
        fmt.Println("错误：应该报错，但没有")
    }
    ```
* **PEM 解码失败:**  如果 PEM 编码的字符串格式不正确（例如，缺少 BEGIN/END 标记，内容损坏），`pem.Decode` 会返回 `nil`，需要进行错误检查。
    ```go
    invalidPEM := "invalid pem data"
    block, _ := pem.Decode([]byte(invalidPEM))
    if block == nil {
        fmt.Println("错误：PEM 解码失败")
    }
    ```
* **类型断言错误:**  `ParsePKIXPublicKey` 返回的是 `crypto.PublicKey` 接口，需要进行类型断言才能使用具体类型的方法和字段。如果断言的类型不正确，会导致 panic。
    ```go
    blockPub, _ := pem.Decode([]byte(pemPublicKey))
    pubInterface, _ := x509.ParsePKIXPublicKey(blockPub.Bytes)
    // 错误示例：假设 pubInterface 是 ECDSA 公钥，却断言为 RSA 公钥
    _, ok := pubInterface.(*rsa.PublicKey)
    if !ok {
        fmt.Println("错误：类型断言失败")
    }
    ```

**功能归纳 (第1部分):**

这段代码的主要功能是 **测试 Go 语言 `crypto/x509` 包中关于密钥（主要是 RSA）的解析和序列化功能，以及证书的基本解析和主机名验证功能。** 它涵盖了 PKCS#1 和 PKIX 两种密钥格式的解析，并测试了在格式不匹配时的错误处理。此外，还包括了证书的解析、签名验证以及基于 DNS 名称和 IP 地址的主机名匹配验证的测试。最后，它也包含了创建自签名证书的测试用例。

### 提示词
```
这是路径为go/src/crypto/x509/x509_test.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第1部分，共6部分，请归纳一下它的功能
```

### 源代码
```go
// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package x509

import (
	"bytes"
	"crypto"
	"crypto/dsa"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	_ "crypto/sha256"
	_ "crypto/sha512"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/gob"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"internal/testenv"
	"io"
	"math"
	"math/big"
	"net"
	"net/url"
	"os/exec"
	"reflect"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestParsePKCS1PrivateKey(t *testing.T) {
	block, _ := pem.Decode([]byte(pemPrivateKey))
	priv, err := ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		t.Errorf("Failed to parse private key: %s", err)
		return
	}
	if priv.PublicKey.N.Cmp(rsaPrivateKey.PublicKey.N) != 0 ||
		priv.PublicKey.E != rsaPrivateKey.PublicKey.E ||
		priv.D.Cmp(rsaPrivateKey.D) != 0 ||
		priv.Primes[0].Cmp(rsaPrivateKey.Primes[0]) != 0 ||
		priv.Primes[1].Cmp(rsaPrivateKey.Primes[1]) != 0 {
		t.Errorf("got:%+v want:%+v", priv, rsaPrivateKey)
	}

	// This private key includes an invalid prime that
	// rsa.PrivateKey.Validate should reject.
	data := []byte("0\x16\x02\x00\x02\x02\u007f\x00\x02\x0200\x02\x0200\x02\x02\x00\x01\x02\x02\u007f\x00")
	if _, err := ParsePKCS1PrivateKey(data); err == nil {
		t.Errorf("parsing invalid private key did not result in an error")
	}
}

func TestPKCS1MismatchPublicKeyFormat(t *testing.T) {

	const pkixPublicKey = "30820122300d06092a864886f70d01010105000382010f003082010a0282010100dd5a0f37d3ca5232852ccc0e81eebec270e2f2c6c44c6231d852971a0aad00aa7399e9b9de444611083c59ea919a9d76c20a7be131a99045ec19a7bb452d647a72429e66b87e28be9e8187ed1d2a2a01ef3eb2360706bd873b07f2d1f1a72337aab5ec94e983e39107f52c480d404915e84d75a3db2cfd601726a128cb1d7f11492d4bdb53272e652276667220795c709b8a9b4af6489cbf48bb8173b8fb607c834a71b6e8bf2d6aab82af3c8ad7ce16d8dcf58373a6edc427f7484d09744d4c08f4e19ed07adbf6cb31243bc5d0d1145e77a08a6fc5efd208eca67d6abf2d6f38f58b6fdd7c28774fb0cc03fc4935c6e074842d2e1479d3d8787249258719f90203010001"
	const errorContains = "use ParsePKIXPublicKey instead"
	derBytes, _ := hex.DecodeString(pkixPublicKey)
	_, err := ParsePKCS1PublicKey(derBytes)
	if !strings.Contains(err.Error(), errorContains) {
		t.Errorf("expected error containing %q, got %s", errorContains, err)
	}
}

func TestMarshalInvalidPublicKey(t *testing.T) {
	_, err := MarshalPKIXPublicKey(&ecdsa.PublicKey{})
	if err == nil {
		t.Errorf("expected error, got MarshalPKIXPublicKey success")
	}
	_, err = MarshalPKIXPublicKey(&ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     big.NewInt(1), Y: big.NewInt(2),
	})
	if err == nil {
		t.Errorf("expected error, got MarshalPKIXPublicKey success")
	}
}

func testParsePKIXPublicKey(t *testing.T, pemBytes string) (pub any) {
	block, _ := pem.Decode([]byte(pemBytes))
	pub, err := ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		t.Fatalf("Failed to parse public key: %s", err)
	}

	pubBytes2, err := MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Errorf("Failed to marshal public key for the second time: %s", err)
		return
	}
	if !bytes.Equal(pubBytes2, block.Bytes) {
		t.Errorf("Reserialization of public key didn't match. got %x, want %x", pubBytes2, block.Bytes)
	}
	return
}

func TestParsePKIXPublicKey(t *testing.T) {
	t.Run("RSA", func(t *testing.T) {
		pub := testParsePKIXPublicKey(t, pemPublicKey)
		_, ok := pub.(*rsa.PublicKey)
		if !ok {
			t.Errorf("Value returned from ParsePKIXPublicKey was not an RSA public key")
		}
	})
	t.Run("Ed25519", func(t *testing.T) {
		pub := testParsePKIXPublicKey(t, pemEd25519Key)
		_, ok := pub.(ed25519.PublicKey)
		if !ok {
			t.Errorf("Value returned from ParsePKIXPublicKey was not an Ed25519 public key")
		}
	})
	t.Run("X25519", func(t *testing.T) {
		pub := testParsePKIXPublicKey(t, pemX25519Key)
		k, ok := pub.(*ecdh.PublicKey)
		if !ok || k.Curve() != ecdh.X25519() {
			t.Errorf("Value returned from ParsePKIXPublicKey was not an X25519 public key")
		}
	})
}

var pemPublicKey = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA3VoPN9PKUjKFLMwOge6+
wnDi8sbETGIx2FKXGgqtAKpzmem53kRGEQg8WeqRmp12wgp74TGpkEXsGae7RS1k
enJCnma4fii+noGH7R0qKgHvPrI2Bwa9hzsH8tHxpyM3qrXslOmD45EH9SxIDUBJ
FehNdaPbLP1gFyahKMsdfxFJLUvbUycuZSJ2ZnIgeVxwm4qbSvZInL9Iu4FzuPtg
fINKcbbovy1qq4KvPIrXzhbY3PWDc6btxCf3SE0JdE1MCPThntB62/bLMSQ7xdDR
FF53oIpvxe/SCOymfWq/LW849Ytv3Xwod0+wzAP8STXG4HSELS4UedPYeHJJJYcZ
+QIDAQAB
-----END PUBLIC KEY-----
`

var pemPrivateKey = testingKey(`
-----BEGIN RSA TESTING KEY-----
MIICXAIBAAKBgQCxoeCUW5KJxNPxMp+KmCxKLc1Zv9Ny+4CFqcUXVUYH69L3mQ7v
IWrJ9GBfcaA7BPQqUlWxWM+OCEQZH1EZNIuqRMNQVuIGCbz5UQ8w6tS0gcgdeGX7
J7jgCQ4RK3F/PuCM38QBLaHx988qG8NMc6VKErBjctCXFHQt14lerd5KpQIDAQAB
AoGAYrf6Hbk+mT5AI33k2Jt1kcweodBP7UkExkPxeuQzRVe0KVJw0EkcFhywKpr1
V5eLMrILWcJnpyHE5slWwtFHBG6a5fLaNtsBBtcAIfqTQ0Vfj5c6SzVaJv0Z5rOd
7gQF6isy3t3w9IF3We9wXQKzT6q5ypPGdm6fciKQ8RnzREkCQQDZwppKATqQ41/R
vhSj90fFifrGE6aVKC1hgSpxGQa4oIdsYYHwMzyhBmWW9Xv/R+fPyr8ZwPxp2c12
33QwOLPLAkEA0NNUb+z4ebVVHyvSwF5jhfJxigim+s49KuzJ1+A2RaSApGyBZiwS
rWvWkB471POAKUYt5ykIWVZ83zcceQiNTwJBAMJUFQZX5GDqWFc/zwGoKkeR49Yi
MTXIvf7Wmv6E++eFcnT461FlGAUHRV+bQQXGsItR/opIG7mGogIkVXa3E1MCQARX
AAA7eoZ9AEHflUeuLn9QJI/r0hyQQLEtrpwv6rDT1GCWaLII5HJ6NUFVf4TTcqxo
6vdM4QGKTJoO+SaCyP0CQFdpcxSAuzpFcKv0IlJ8XzS/cy+mweCMwyJ1PFEc4FX6
wg/HcAJWY60xZTJDFN+Qfx8ZQvBEin6c2/h+zZi5IVY=
-----END RSA TESTING KEY-----
`)

// pemEd25519Key is the example from RFC 8410, Section 4.
var pemEd25519Key = `
-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAGb9ECWmEzf6FQbrBZ9w7lshQhqowtrbLDFw4rXAxZuE=
-----END PUBLIC KEY-----
`

// pemX25519Key was generated from pemX25519Key with "openssl pkey -pubout".
var pemX25519Key = `
-----BEGIN PUBLIC KEY-----
MCowBQYDK2VuAyEA5yGXrH/6OzxuWEhEWS01/f4OP+Of3Yrddy6/J1kDTVM=
-----END PUBLIC KEY-----
`

func TestPKIXMismatchPublicKeyFormat(t *testing.T) {

	const pkcs1PublicKey = "308201080282010100817cfed98bcaa2e2a57087451c7674e0c675686dc33ff1268b0c2a6ee0202dec710858ee1c31bdf5e7783582e8ca800be45f3275c6576adc35d98e26e95bb88ca5beb186f853b8745d88bc9102c5f38753bcda519fb05948d5c77ac429255ff8aaf27d9f45d1586e95e2e9ba8a7cb771b8a09dd8c8fed3f933fd9b439bc9f30c475953418ef25f71a2b6496f53d94d39ce850aa0cc75d445b5f5b4f4ee4db78ab197a9a8d8a852f44529a007ac0ac23d895928d60ba538b16b0b087a7f903ed29770e215019b77eaecc360f35f7ab11b6d735978795b2c4a74e5bdea4dc6594cd67ed752a108e666729a753ab36d6c4f606f8760f507e1765be8cd744007e629020103"
	const errorContains = "use ParsePKCS1PublicKey instead"
	derBytes, _ := hex.DecodeString(pkcs1PublicKey)
	_, err := ParsePKIXPublicKey(derBytes)
	if !strings.Contains(err.Error(), errorContains) {
		t.Errorf("expected error containing %q, got %s", errorContains, err)
	}
}

var testPrivateKey *rsa.PrivateKey

func init() {
	block, _ := pem.Decode([]byte(pemPrivateKey))

	var err error
	if testPrivateKey, err = ParsePKCS1PrivateKey(block.Bytes); err != nil {
		panic("Failed to parse private key: " + err.Error())
	}
}

func bigFromString(s string) *big.Int {
	ret := new(big.Int)
	ret.SetString(s, 10)
	return ret
}

func fromBase10(base10 string) *big.Int {
	i := new(big.Int)
	i.SetString(base10, 10)
	return i
}

func bigFromHexString(s string) *big.Int {
	ret := new(big.Int)
	ret.SetString(s, 16)
	return ret
}

var rsaPrivateKey = &rsa.PrivateKey{
	PublicKey: rsa.PublicKey{
		N: bigFromString("124737666279038955318614287965056875799409043964547386061640914307192830334599556034328900586693254156136128122194531292927142396093148164407300419162827624945636708870992355233833321488652786796134504707628792159725681555822420087112284637501705261187690946267527866880072856272532711620639179596808018872997"),
		E: 65537,
	},
	D: bigFromString("69322600686866301945688231018559005300304807960033948687567105312977055197015197977971637657636780793670599180105424702854759606794705928621125408040473426339714144598640466128488132656829419518221592374964225347786430566310906679585739468938549035854760501049443920822523780156843263434219450229353270690889"),
	Primes: []*big.Int{
		bigFromString("11405025354575369741595561190164746858706645478381139288033759331174478411254205003127028642766986913445391069745480057674348716675323735886284176682955723"),
		bigFromString("10937079261204603443118731009201819560867324167189758120988909645641782263430128449826989846631183550578761324239709121189827307416350485191350050332642639"),
	},
}

func TestMarshalRSAPrivateKey(t *testing.T) {
	priv := &rsa.PrivateKey{
		PublicKey: rsa.PublicKey{
			N: fromBase10("16346378922382193400538269749936049106320265317511766357599732575277382844051791096569333808598921852351577762718529818072849191122419410612033592401403764925096136759934497687765453905884149505175426053037420486697072448609022753683683718057795566811401938833367954642951433473337066311978821180526439641496973296037000052546108507805269279414789035461158073156772151892452251106173507240488993608650881929629163465099476849643165682709047462010581308719577053905787496296934240246311806555924593059995202856826239801816771116902778517096212527979497399966526283516447337775509777558018145573127308919204297111496233"),
			E: 3,
		},
		D: fromBase10("10897585948254795600358846499957366070880176878341177571733155050184921896034527397712889205732614568234385175145686545381899460748279607074689061600935843283397424506622998458510302603922766336783617368686090042765718290914099334449154829375179958369993407724946186243249568928237086215759259909861748642124071874879861299389874230489928271621259294894142840428407196932444474088857746123104978617098858619445675532587787023228852383149557470077802718705420275739737958953794088728369933811184572620857678792001136676902250566845618813972833750098806496641114644760255910789397593428910198080271317419213080834885003"),
		Primes: []*big.Int{
			fromBase10("1025363189502892836833747188838978207017355117492483312747347695538428729137306368764177201532277413433182799108299960196606011786562992097313508180436744488171474690412562218914213688661311117337381958560443"),
			fromBase10("3467903426626310123395340254094941045497208049900750380025518552334536945536837294961497712862519984786362199788654739924501424784631315081391467293694361474867825728031147665777546570788493758372218019373"),
			fromBase10("4597024781409332673052708605078359346966325141767460991205742124888960305710298765592730135879076084498363772408626791576005136245060321874472727132746643162385746062759369754202494417496879741537284589047"),
		},
	}

	derBytes := MarshalPKCS1PrivateKey(priv)

	priv2, err := ParsePKCS1PrivateKey(derBytes)
	if err != nil {
		t.Errorf("error parsing serialized key: %s", err)
		return
	}
	if priv.PublicKey.N.Cmp(priv2.PublicKey.N) != 0 ||
		priv.PublicKey.E != priv2.PublicKey.E ||
		priv.D.Cmp(priv2.D) != 0 ||
		len(priv2.Primes) != 3 ||
		priv.Primes[0].Cmp(priv2.Primes[0]) != 0 ||
		priv.Primes[1].Cmp(priv2.Primes[1]) != 0 ||
		priv.Primes[2].Cmp(priv2.Primes[2]) != 0 {
		t.Errorf("wrong priv:\ngot  %+v\nwant %+v", priv2, priv)
	}

	if priv.Precomputed.Dp == nil {
		t.Fatalf("Precomputed.Dp is nil")
	}
}

func TestMarshalRSAPrivateKeyInvalid(t *testing.T) {
	block, _ := pem.Decode([]byte(strings.ReplaceAll(
		`-----BEGIN RSA TESTING KEY-----
MIIEowIBAAKCAQEAsPnoGUOnrpiSqt4XynxA+HRP7S+BSObI6qJ7fQAVSPtRkqso
tWxQYLEYzNEx5ZSHTGypibVsJylvCfuToDTfMul8b/CZjP2Ob0LdpYrNH6l5hvFE
89FU1nZQF15oVLOpUgA7wGiHuEVawrGfey92UE68mOyUVXGweJIVDdxqdMoPvNNU
l86BU02vlBiESxOuox+dWmuVV7vfYZ79Toh/LUK43YvJh+rhv4nKuF7iHjVjBd9s
B6iDjj70HFldzOQ9r8SRI+9NirupPTkF5AKNe6kUhKJ1luB7S27ZkvB3tSTT3P59
3VVJvnzOjaA1z6Cz+4+eRvcysqhrRgFlwI9TEwIDAQABAoIBAEEYiyDP29vCzx/+
dS3LqnI5BjUuJhXUnc6AWX/PCgVAO+8A+gZRgvct7PtZb0sM6P9ZcLrweomlGezI
FrL0/6xQaa8bBr/ve/a8155OgcjFo6fZEw3Dz7ra5fbSiPmu4/b/kvrg+Br1l77J
aun6uUAs1f5B9wW+vbR7tzbT/mxaUeDiBzKpe15GwcvbJtdIVMa2YErtRjc1/5B2
BGVXyvlJv0SIlcIEMsHgnAFOp1ZgQ08aDzvilLq8XVMOahAhP1O2A3X8hKdXPyrx
IVWE9bS9ptTo+eF6eNl+d7htpKGEZHUxinoQpWEBTv+iOoHsVunkEJ3vjLP3lyI/
fY0NQ1ECgYEA3RBXAjgvIys2gfU3keImF8e/TprLge1I2vbWmV2j6rZCg5r/AS0u
pii5CvJ5/T5vfJPNgPBy8B/yRDs+6PJO1GmnlhOkG9JAIPkv0RBZvR0PMBtbp6nT
Y3yo1lwamBVBfY6rc0sLTzosZh2aGoLzrHNMQFMGaauORzBFpY5lU50CgYEAzPHl
u5DI6Xgep1vr8QvCUuEesCOgJg8Yh1UqVoY/SmQh6MYAv1I9bLGwrb3WW/7kqIoD
fj0aQV5buVZI2loMomtU9KY5SFIsPV+JuUpy7/+VE01ZQM5FdY8wiYCQiVZYju9X
Wz5LxMNoz+gT7pwlLCsC4N+R8aoBk404aF1gum8CgYAJ7VTq7Zj4TFV7Soa/T1eE
k9y8a+kdoYk3BASpCHJ29M5R2KEA7YV9wrBklHTz8VzSTFTbKHEQ5W5csAhoL5Fo
qoHzFFi3Qx7MHESQb9qHyolHEMNx6QdsHUn7rlEnaTTyrXh3ifQtD6C0yTmFXUIS
CW9wKApOrnyKJ9nI0HcuZQKBgQCMtoV6e9VGX4AEfpuHvAAnMYQFgeBiYTkBKltQ
XwozhH63uMMomUmtSG87Sz1TmrXadjAhy8gsG6I0pWaN7QgBuFnzQ/HOkwTm+qKw
AsrZt4zeXNwsH7QXHEJCFnCmqw9QzEoZTrNtHJHpNboBuVnYcoueZEJrP8OnUG3r
UjmopwKBgAqB2KYYMUqAOvYcBnEfLDmyZv9BTVNHbR2lKkMYqv5LlvDaBxVfilE0
2riO4p6BaAdvzXjKeRrGNEKoHNBpOSfYCOM16NjL8hIZB1CaV3WbT5oY+jp7Mzd5
7d56RZOE+ERK2uz/7JX9VSsM/LbH9pJibd4e8mikDS9ntciqOH/3
-----END RSA TESTING KEY-----`, "TESTING KEY", "PRIVATE KEY")))
	testRSA2048, _ := ParsePKCS1PrivateKey(block.Bytes)

	broken := *testRSA2048
	broken.Precomputed.Dp = new(big.Int).SetUint64(42)

	parsed, err := ParsePKCS1PrivateKey(MarshalPKCS1PrivateKey(&broken))
	if err == nil {
		t.Errorf("expected error, got success")
	}

	t.Setenv("GODEBUG", "x509rsacrt=0")

	parsed, err = ParsePKCS1PrivateKey(MarshalPKCS1PrivateKey(&broken))
	if err != nil {
		t.Fatalf("expected success, got error: %v", err)
	}
	// Dp should have been recomputed.
	if parsed.Precomputed.Dp.Cmp(testRSA2048.Precomputed.Dp) != 0 {
		t.Errorf("Dp recomputation failed: got %v, want %v", parsed.Precomputed.Dp, testRSA2048.Precomputed.Dp)
	}
}

func TestMarshalRSAPublicKey(t *testing.T) {
	pub := &rsa.PublicKey{
		N: fromBase10("16346378922382193400538269749936049106320265317511766357599732575277382844051791096569333808598921852351577762718529818072849191122419410612033592401403764925096136759934497687765453905884149505175426053037420486697072448609022753683683718057795566811401938833367954642951433473337066311978821180526439641496973296037000052546108507805269279414789035461158073156772151892452251106173507240488993608650881929629163465099476849643165682709047462010581308719577053905787496296934240246311806555924593059995202856826239801816771116902778517096212527979497399966526283516447337775509777558018145573127308919204297111496233"),
		E: 3,
	}
	derBytes := MarshalPKCS1PublicKey(pub)
	pub2, err := ParsePKCS1PublicKey(derBytes)
	if err != nil {
		t.Errorf("ParsePKCS1PublicKey: %s", err)
	}
	if pub.N.Cmp(pub2.N) != 0 || pub.E != pub2.E {
		t.Errorf("ParsePKCS1PublicKey = %+v, want %+v", pub, pub2)
	}

	// It's never been documented that asn1.Marshal/Unmarshal on rsa.PublicKey works,
	// but it does, and we know of code that depends on it.
	// Lock that in, even though we'd prefer that people use MarshalPKCS1PublicKey and ParsePKCS1PublicKey.
	derBytes2, err := asn1.Marshal(*pub)
	if err != nil {
		t.Errorf("Marshal(rsa.PublicKey): %v", err)
	} else if !bytes.Equal(derBytes, derBytes2) {
		t.Errorf("Marshal(rsa.PublicKey) = %x, want %x", derBytes2, derBytes)
	}
	pub3 := new(rsa.PublicKey)
	rest, err := asn1.Unmarshal(derBytes, pub3)
	if err != nil {
		t.Errorf("Unmarshal(rsa.PublicKey): %v", err)
	}
	if len(rest) != 0 || pub.N.Cmp(pub3.N) != 0 || pub.E != pub3.E {
		t.Errorf("Unmarshal(rsa.PublicKey) = %+v, %q want %+v, %q", pub, rest, pub2, []byte(nil))
	}

	publicKeys := []struct {
		derBytes          []byte
		expectedErrSubstr string
	}{
		{
			derBytes: []byte{
				0x30, 6, // SEQUENCE, 6 bytes
				0x02, 1, // INTEGER, 1 byte
				17,
				0x02, 1, // INTEGER, 1 byte
				3, // 3
			},
		}, {
			derBytes: []byte{
				0x30, 6, // SEQUENCE
				0x02, 1, // INTEGER, 1 byte
				0xff,    // -1
				0x02, 1, // INTEGER, 1 byte
				3,
			},
			expectedErrSubstr: "zero or negative",
		}, {
			derBytes: []byte{
				0x30, 6, // SEQUENCE
				0x02, 1, // INTEGER, 1 byte
				17,
				0x02, 1, // INTEGER, 1 byte
				0xff, // -1
			},
			expectedErrSubstr: "zero or negative",
		}, {
			derBytes: []byte{
				0x30, 6, // SEQUENCE
				0x02, 1, // INTEGER, 1 byte
				17,
				0x02, 1, // INTEGER, 1 byte
				3,
				1,
			},
			expectedErrSubstr: "trailing data",
		}, {
			derBytes: []byte{
				0x30, 9, // SEQUENCE
				0x02, 1, // INTEGER, 1 byte
				17,
				0x02, 4, // INTEGER, 4 bytes
				0x7f, 0xff, 0xff, 0xff,
			},
		}, {
			derBytes: []byte{
				0x30, 10, // SEQUENCE
				0x02, 1, // INTEGER, 1 byte
				17,
				0x02, 5, // INTEGER, 5 bytes
				0x00, 0x80, 0x00, 0x00, 0x00,
			},
			// On 64-bit systems, encoding/asn1 will accept the
			// public exponent, but ParsePKCS1PublicKey will return
			// an error. On 32-bit systems, encoding/asn1 will
			// return the error. The common substring of both error
			// is the word “large”.
			expectedErrSubstr: "large",
		},
	}

	for i, test := range publicKeys {
		shouldFail := len(test.expectedErrSubstr) > 0
		pub, err := ParsePKCS1PublicKey(test.derBytes)
		if shouldFail {
			if err == nil {
				t.Errorf("#%d: unexpected success, got %#v", i, pub)
			} else if !strings.Contains(err.Error(), test.expectedErrSubstr) {
				t.Errorf("#%d: expected error containing %q, got %s", i, test.expectedErrSubstr, err)
			}
		} else {
			if err != nil {
				t.Errorf("#%d: unexpected failure: %s", i, err)
				continue
			}
			reserialized := MarshalPKCS1PublicKey(pub)
			if !bytes.Equal(reserialized, test.derBytes) {
				t.Errorf("#%d: failed to reserialize: got %x, expected %x", i, reserialized, test.derBytes)
			}
		}
	}
}

type matchHostnamesTest struct {
	pattern, host string
	ok            bool
}

var matchHostnamesTests = []matchHostnamesTest{
	{"a.b.c", "a.b.c", true},
	{"a.b.c", "b.b.c", false},
	{"", "b.b.c", false},
	{"a.b.c", "", false},
	{"example.com", "example.com", true},
	{"example.com", "www.example.com", false},
	{"*.example.com", "example.com", false},
	{"*.example.com", "www.example.com", true},
	{"*.example.com", "www.example.com.", true},
	{"*.example.com", "xyz.www.example.com", false},
	{"*.example.com", "https://www.example.com", false}, // Issue 27591
	{"*.example..com", "www.example..com", false},
	{"www.example..com", "www.example..com", true},
	{"*.*.example.com", "xyz.www.example.com", false},
	{"*.www.*.com", "xyz.www.example.com", false},
	{"*bar.example.com", "foobar.example.com", false},
	{"f*.example.com", "foobar.example.com", false},
	{"www.example.com", "*.example.com", false},
	{"", ".", false},
	{".", "", false},
	{".", ".", false},
	{"example.com", "example.com.", true},
	{"example.com.", "example.com", false},
	{"example.com.", "example.com.", true}, // perfect matches allow trailing dots in patterns
	{"*.com.", "example.com.", false},
	{"*.com.", "example.com", false},
	{"*.com", "example.com", true},
	{"*.com", "example.com.", true},
	{"foo:bar", "foo:bar", true},
	{"*.foo:bar", "xxx.foo:bar", false},
	{"*.2.3.4", "1.2.3.4", false},
	{"*.2.3.4", "[1.2.3.4]", false},
	{"*:4860:4860::8888", "2001:4860:4860::8888", false},
	{"*:4860:4860::8888", "[2001:4860:4860::8888]", false},
	{"2001:4860:4860::8888", "2001:4860:4860::8888", false},
	{"2001:4860:4860::8888", "[2001:4860:4860::8888]", false},
	{"[2001:4860:4860::8888]", "2001:4860:4860::8888", false},
	{"[2001:4860:4860::8888]", "[2001:4860:4860::8888]", false},
}

func TestMatchHostnames(t *testing.T) {
	for i, test := range matchHostnamesTests {
		c := &Certificate{DNSNames: []string{test.pattern}}
		r := c.VerifyHostname(test.host) == nil
		if r != test.ok {
			t.Errorf("#%d mismatch got: %t want: %t when matching '%s' against '%s'", i, r, test.ok, test.host, test.pattern)
		}
	}
}

func TestMatchIP(t *testing.T) {
	// Check that pattern matching is working.
	c := &Certificate{
		DNSNames: []string{"*.foo.bar.baz"},
		Subject: pkix.Name{
			CommonName: "*.foo.bar.baz",
		},
	}
	err := c.VerifyHostname("quux.foo.bar.baz")
	if err != nil {
		t.Fatalf("VerifyHostname(quux.foo.bar.baz): %v", err)
	}

	// But check that if we change it to be matching against an IP address,
	// it is rejected.
	c = &Certificate{
		DNSNames: []string{"*.2.3.4"},
		Subject: pkix.Name{
			CommonName: "*.2.3.4",
		},
	}
	err = c.VerifyHostname("1.2.3.4")
	if err == nil {
		t.Fatalf("VerifyHostname(1.2.3.4) should have failed, did not")
	}

	c = &Certificate{
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
	}
	err = c.VerifyHostname("127.0.0.1")
	if err != nil {
		t.Fatalf("VerifyHostname(127.0.0.1): %v", err)
	}
	err = c.VerifyHostname("::1")
	if err != nil {
		t.Fatalf("VerifyHostname(::1): %v", err)
	}
	err = c.VerifyHostname("[::1]")
	if err != nil {
		t.Fatalf("VerifyHostname([::1]): %v", err)
	}
}

func TestCertificateParse(t *testing.T) {
	s, _ := base64.StdEncoding.DecodeString(certBytes)
	certs, err := ParseCertificates(s)
	if err != nil {
		t.Error(err)
	}
	if len(certs) != 2 {
		t.Errorf("Wrong number of certs: got %d want 2", len(certs))
		return
	}

	err = certs[0].CheckSignatureFrom(certs[1])
	if err != nil {
		t.Error(err)
	}

	if err := certs[0].VerifyHostname("mail.google.com"); err != nil {
		t.Error(err)
	}

	const expectedExtensions = 10
	if n := len(certs[0].Extensions); n != expectedExtensions {
		t.Errorf("want %d extensions, got %d", expectedExtensions, n)
	}
}

func TestCertificateEqualOnNil(t *testing.T) {
	cNonNil := new(Certificate)
	var cNil1, cNil2 *Certificate
	if !cNil1.Equal(cNil2) {
		t.Error("Nil certificates: cNil1 is not equal to cNil2")
	}
	if !cNil2.Equal(cNil1) {
		t.Error("Nil certificates: cNil2 is not equal to cNil1")
	}
	if cNil1.Equal(cNonNil) {
		t.Error("Unexpectedly cNil1 is equal to cNonNil")
	}
	if cNonNil.Equal(cNil1) {
		t.Error("Unexpectedly cNonNil is equal to cNil1")
	}
}

func TestMismatchedSignatureAlgorithm(t *testing.T) {
	der, _ := pem.Decode([]byte(rsaPSSSelfSignedPEM))
	if der == nil {
		t.Fatal("Failed to find PEM block")
	}

	cert, err := ParseCertificate(der.Bytes)
	if err != nil {
		t.Fatal(err)
	}

	if err = cert.CheckSignature(ECDSAWithSHA256, nil, nil); err == nil {
		t.Fatal("CheckSignature unexpectedly return no error")
	}

	const expectedSubstring = " but have public key of type "
	if !strings.Contains(err.Error(), expectedSubstring) {
		t.Errorf("Expected error containing %q, but got %q", expectedSubstring, err)
	}
}

var certBytes = "MIIE0jCCA7qgAwIBAgIQWcvS+TTB3GwCAAAAAGEAWzANBgkqhkiG9w0BAQsFADBCMQswCQYD" +
	"VQQGEwJVUzEeMBwGA1UEChMVR29vZ2xlIFRydXN0IFNlcnZpY2VzMRMwEQYDVQQDEwpHVFMg" +
	"Q0EgMU8xMB4XDTIwMDQwMTEyNTg1NloXDTIwMDYyNDEyNTg1NlowaTELMAkGA1UEBhMCVVMx" +
	"EzARBgNVBAgTCkNhbGlmb3JuaWExFjAUBgNVBAcTDU1vdW50YWluIFZpZXcxEzARBgNVBAoT" +
	"Ckdvb2dsZSBMTEMxGDAWBgNVBAMTD21haWwuZ29vZ2xlLmNvbTBZMBMGByqGSM49AgEGCCqG" +
	"SM49AwEHA0IABO+dYiPnkFl+cZVf6mrWeNp0RhQcJSBGH+sEJxjvc+cYlW3QJCnm57qlpFdd" +
	"pz3MPyVejvXQdM6iI1mEWP4C2OujggJmMIICYjAOBgNVHQ8BAf8EBAMCB4AwEwYDVR0lBAww" +
	"CgYIKwYBBQUHAwEwDAYDVR0TAQH/BAIwADAdBgNVHQ4EFgQUI6pZhnQ/lQgmPDwSKR2A54G7" +
	"AS4wHwYDVR0jBBgwFoAUmNH4bhDrz5vsYJ8YkBug630J/SswZAYIKwYBBQUHAQEEWDBWMCcG" +
	"CCsGAQUFBzABhhtodHRwOi8vb2NzcC5wa2kuZ29vZy9ndHMxbzEwKwYIKwYBBQUHMAKGH2h0" +
	"dHA6Ly9wa2kuZ29vZy9nc3IyL0dUUzFPMS5jcnQwLAYDVR0RBCUwI4IPbWFpbC5nb29nbGUu" +
	"Y29tghBpbmJveC5nb29nbGUuY29tMCEGA1UdIAQaMBgwCAYGZ4EMAQICMAwGCisGAQQB1nkC" +
	"BQMwLwYDVR0fBCgwJjAkoCKgIIYeaHR0cDovL2NybC5wa2kuZ29vZy9HVFMxTzEuY3JsMIIB" +
	"AwYKKwYBBAHWeQIEAgSB9ASB8QDvAHYAsh4FzIuizYogTodm+Su5iiUgZ2va+nDnsklTLe+L" +
	"kF4AAAFxNgmxKgAABAMARzBFAiEA12/OHdTGXQ3qHHC3NvYCyB8aEz/+ZFOLCAI7lhqj28sC" +
	"IG2/7Yz2zK6S6ai+dH7cTMZmoFGo39gtaTqtZAqEQX7nAHUAXqdz+d9WwOe1Nkh90EngMnqR" +
	"mgyEoRIShBh1loFxRVgAAAFxNgmxTAAABAMARjBEAiA7PNq+MFfv6O9mBkxFViS2TfU66yRB" +
	"/njcebWglLQjZQIgOyRKhxlEizncFRml7yn4Bg48ktXKGjo+uiw6zXEINb0wDQYJKoZIhvcN" +
	"AQELBQADggEBADM2Rh306Q10PScsolYMxH1B/K4Nb2WICvpY0yDPJFdnGjqCYym196TjiEvs" +
	"R6etfeHdyzlZj6nh82B4TVyHjiWM02dQgPalOuWQcuSy0OvLh7F1E7CeHzKlczdFPBTOTdM1" +
	"RDTxlvw1bAqc0zueM8QIAyEy3opd7FxAcGQd5WRIJhzLBL+dbbMOW/LTeW7cm/Xzq8cgCybN" +
	"BSZAvhjseJ1L29OlCTZL97IfnX0IlFQzWuvvHy7V2B0E3DHlzM0kjwkkCKDUUp/wajv2NZKC" +
	"TkhEyERacZRKc9U0ADxwsAzHrdz5+5zfD2usEV/MQ5V6d8swLXs+ko0X6swrd4YCiB8wggRK" +
	"MIIDMqADAgECAg0B47SaoY2KqYElaVC4MA0GCSqGSIb3DQEBCwUAMEwxIDAeBgNVBAsTF0ds" +
	"b2JhbFNpZ24gUm9vdCBDQSAtIFIyMRMwEQYDVQQKEwpHbG9iYWxTaWduMRMwEQYDVQQDEwpH" +
	"bG9iYWxTaWduMB4XDTE3MDYxNTAwMDA0MloXDTIxMTIxNTAwMDA0MlowQjELMAkGA1UEBhMC" +
	"VVMxHjAcBgNVBAoTFUdvb2dsZSBUcnVzdCBTZXJ2aWNlczETMBEGA1UEAxMKR1RTIENBIDFP" +
	"MTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBANAYz0XUi83TnORA73603WkhG8nP" +
	"PI5MdbkPMRmEPZ48Ke9QDRCTbwWAgJ8qoL0SSwLhPZ9YFiT+MJ8LdHdVkx1L903hkoIQ9lGs" +
	"DMOyIpQPNGuYEEnnC52DOd0gxhwt79EYYWXnI4MgqCMS/9Ikf9Qv50RqW03XUGawr55CYwX7" +
	"4BzEY2Gvn2oz/2KXvUjZ03wUZ9x13C5p6PhteGnQtxAFuPExwjsk/RozdPgj4OxrGYoWxuPN" +
	"pM0L27OkWWA4iDutHbnGjKdTG/y82aSrvN08YdeTFZjugb2P4mRHIEAGTtesl+i5wFkSoUkl" +
	"I+TtcDQspbRjfPmjPYPRzW0krAcCAwEAAaOCATMwggEvMA4GA1UdDwEB/wQEAwIBhjAdBgNV" +
	"HSUEFjAUBggrBgEFBQcDAQYIKwYBBQUHAwIwEgYDVR0TAQH/BAgwBgEB/wIBADAdBgNVHQ4E" +
	"FgQUmNH4bhDrz5vsYJ8YkBug630J/SswHwYDVR0jBBgwFoAUm+IHV2ccHsBqBt5ZtJot39wZ" +
	"hi4wNQYIKwYBBQUHAQEEKTAnMCUGCCsGAQUFBzABhhlodHRwOi8vb2NzcC5wa2kuZ29vZy9n" +
	"c3IyMDIGA1UdHwQrMCkwJ6AloCOGIWh0dHA6Ly9jcmwucGtpLmdvb2cvZ3NyMi9nc3IyLmNy" +
	"bDA/BgNVHSAEODA2MDQGBmeBDAECAjAqMCgGCCsGAQUFBwIBFhxodHRwczovL3BraS5nb29n" +
	"L3JlcG9zaXRvcnkvMA0GCSqGSIb3DQEBCwUAA4IBAQAagD42efvzLqlGN31eVBY1rsdOCJn+" +
	"vdE0aSZSZgc9CrpJy2L08RqO/BFPaJZMdCvTZ96yo6oFjYRNTCBlD6WW2g0W+Gw7228EI4hr" +
	"OmzBYL1on3GO7i1YNAfw1VTphln9e14NIZT1jMmo+NjyrcwPGvOap6kEJ/mjybD/AnhrYbrH" +
	"NSvoVvpPwxwM7bY8tEvq7czhPOzcDYzWPpvKQliLzBYhF0C8otZm79rEFVvNiaqbCSbnMtIN" +
	"bmcgAlsQsJAJnAwfnq3YO+qh/GzoEFwIUhlRKnG7rHq13RXtK8kIKiyKtKYhq2P/11JJUNCJ" +
	"t63yr/tQri/hlQ3zRq2dnPXK"

func parseCIDR(s string) *net.IPNet {
	_, net, err := net.ParseCIDR(s)
	if err != nil {
		panic(err)
	}
	return net
}

func parseURI(s string) *url.URL {
	uri, err := url.Parse(s)
	if err != nil {
		panic(err)
	}
	return uri
}

func TestCreateSelfSignedCertificate(t *testing.T) {
	random := rand.Reader

	ecdsaPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate ECDSA key: %s", err)
	}

	ed25519Pub, ed25519Priv, err := ed25519.GenerateKey(random)
	if err != nil {
		t.Fatalf("Failed to generate Ed25519 key: %s", err)
	}

	tests := []struct {
		name      string
		pub, priv any
		checkSig  bool
		sigAlgo   SignatureAlgorithm
	}{
		{"RSA/RSA", &testPrivateKey.PublicKey, testPrivateKey, true, SHA384WithRSA},
		{"RSA/ECDSA", &testPrivateKey.PublicKey, ecdsaPriv, false, ECDSAWithSHA384},
		{"ECDSA/RSA", &ecdsaPriv.PublicKey, testPrivateKey, false, SHA256WithRSA},
		{"ECDSA/ECDSA", &ecdsaPriv.PublicKey, ecdsaPriv, true, ECDSAWithSHA256},
		{"RSAPSS/RSAPSS", &testPrivateKey.PublicKey, testPrivateKey, true, SHA256WithRSAPSS},
		{"ECDSA/RSAPSS", &ecdsaPriv.PublicKey, testPrivateKey, false, SHA256WithRSAPSS},
		{"RSAPSS/ECDSA", &testPrivateKey.PublicKey, ecdsaPriv, false, ECDSAWithSHA384},
		{"Ed25519", ed25519Pub, ed25519Priv, true, PureEd25519},
	}

	testExtKeyUsage := []ExtKeyUsage{ExtKeyUsageClientAuth, ExtKeyUsageServerAuth}
	testUnknownExtKeyUsage := []asn1.ObjectIdentifier{[]int{1, 2, 3}, []int{2, 59, 1}}
	extraExtensionData := []byte("extra extension")

	for _, test := range tests {
		commonName := "test.example.com"
		template := Certificate{
			SerialNumber: big.NewInt(1),
			Subject: pkix.Name{
				CommonName:   commonName,
				Organization: []string{"Σ Acme Co"},
				Country:      []string{"US"},
				ExtraNames: []pkix.AttributeTypeAndValue{
					{
						Type:  []int{2, 5, 4, 42},
						Value: "Gopher",
					},
					// This should override the Country, above.
					{
						Type:  []int{2, 5, 4, 6},
						Value: "NL",
					},
				},
			},
			NotBefore: time.Unix(1000, 0),
			NotAfter:  time.Unix(100000, 0),

			SignatureAlgorithm: test.sigAlgo,

			SubjectKeyId: []byte{1, 2, 3, 4},
			KeyUsage:     KeyUsageCertSign,

			ExtKeyUsage:        testExtKeyUsage,
			UnknownExtKeyUsage: testUnknownExtKeyUsage,

			BasicConstraintsValid: true,
			IsCA:                  true,

			OCSPServer:            []string{"http://ocsp.example.com"},
			IssuingCertificateURL: []string{"http://crt.example.com/ca1.crt"},

			DNSNames:       []string{"test.example.com"},
			EmailAddresses: []string{"gopher@golang.org"},
			IPAddresses:    []net.IP{net.IPv4(127, 0, 0, 1).To4(), net.ParseIP("2001:4860:0:2001::68")},
			URIs:           []*url.URL{parseURI("https://foo.com/wibble#foo")},

			Policies:                []OID{mustNewOIDFromInts([]uint64{1, 2, 3, math.MaxUint32, math.MaxUint64})},
			PermittedDNSDomains:     []string{".example.com", "example.com"},
			ExcludedDNSDomains:      []string{"bar.example.com"},
			PermittedIPRanges:       []*net.IPNet{parseCIDR("192.168.1.1/16"), parseCIDR("1.2.3.4/8")},
			ExcludedIPRanges:        []*net.IPNet{parseCIDR("2001:db8::/48")},
			PermittedEmailAddresses: []string{"foo@example.com"},
			ExcludedEmailAddresses:  []string{".example.com", "example.com"},
			PermittedURIDomains:     []string{".bar.com", "bar.com"},
			ExcludedURIDomains:      []string{".bar2.com", "bar2.com"},

			CRLDistributionPoints: []string{"http://crl1.example.com/ca1.crl", "http://crl2.example.com/ca1.crl"},

			ExtraExtensions: []pkix.Extension{
				{
					Id:    []int{1, 2, 3, 4},
					Value: extraExtensionData,
				},
				// This extension should override the SubjectKeyId, above.
				{
					Id:       oidExtensionSubjectKeyId,
					Critical: false,
					Value:    []byte{0x04, 0x04, 4, 3, 2, 1},
				},
			},
		}

		derBytes, err := CreateCertificate(random, &template, &template, test.pub, test.priv)
		if err != nil {
			t.Errorf("%s: failed to create certificate: %s", test.name, err)
			continue
		}

		cert, err := ParseCertificate(derBytes)
		if err != nil {
			t.Errorf("%s: failed to parse certificate: %s", test.name, err)
			continue
		}

		if len(cert.Policies) != 1 || !cert.Policies[0].Equal(template.Policies[0]) {
			t.Errorf("%s: failed to parse policy identifiers: got:%#v want:%#v", test.name, cert.PolicyIdentifiers, template.Policies)
		}

		if len(cert.PermittedDNSDomains) != 2 || cert.PermittedDNSDomains[0] != ".example.com" || cert.PermittedDNSDomains[1] != "example.com" {
			t.Errorf("%s: failed to parse name constraints: %#v", test.name, cert.PermittedDNSDomains)
		}

		if len(cert.ExcludedDNSDomains) != 1 || cert.ExcludedDNSDomains[0] != "bar.example.com" {
			t.Errorf("%s: failed to parse name constraint exclusions: %#v", test.name, cert.ExcludedDNSDomains)
		}

		if len(cert.PermittedIPRanges) != 2 || cert.PermittedIPRanges[0].String() != "192.168.0.0/16" || cert.PermittedIPRanges[1].String() != "1.0.0.0/8" {
			t.Errorf("%s: failed to parse IP constraints: %#v", test.name, cert.PermittedIPRanges)
		}

		if len(cert.ExcludedIPRanges) != 1 || cert.ExcludedIPRanges[0].String() != "2001:db8::/48" {
			t.Errorf("%s: failed to parse IP constraint exclusions: %#v", test.name, cert.ExcludedIPRanges)
		}

		if len(cert.PermittedEmailAddresses) != 1 || cert.PermittedEmailAddresses[0] != "foo@example.com" {
			t.Errorf("%s: failed to parse permitted email addresses: %#v", test.name, cert.PermittedEmailAddresses)
		}

		if len(cert.ExcludedEmailAddresses) != 2 || cert.ExcludedEmailAddresses[0] != ".example.com" || cert.ExcludedEmailAddresses[1] != "example.com" {
			t.Errorf("%s: failed to parse excluded email addresses: %#v", test.name, cert.ExcludedEmailAddresses)
		}

		if len(cert.PermittedURIDomains) != 2 || cert.PermittedURIDomains[0] != ".bar.com" || cert.PermittedURIDomains[1] != "bar.com" {
			t.Errorf("%s: failed to parse permitted URIs: %#v", test.name, cert.PermittedURIDomains)
		}

		if len(cert.ExcludedURIDomains) != 2 || cert.ExcludedURIDomains[0] != ".bar2.com" || cert.ExcludedURIDomains[1] != "bar2.com" {
			t.Errorf("%s: failed to parse excluded URIs: %#v", test.name, cert.ExcludedURIDomains)
		}

		if cert.Subject.CommonName != commonName {
			t.Errorf("%s: subject wasn't correctly copied from the template. Got %s, want %s", test.name, cert.Subject.CommonName, commonName)
		}

		if len(cert.Subject.Country) != 1 || cert.Subject.Country[0] != "NL" {
			t.Errorf("%s: ExtraNames didn't override Country", test.name)
		}

		for _, ext := range cert.Extensions {
			if ext.Id.Equal(oidExtensionSubjectAltName) {
				if ext.Critical {
					t.Fatal("SAN extension is marked critical")
				}
			}
		}

		found := false
		for _, atv := range cert.Subject.Names {
			if atv.Type.Equal([]int{2, 5, 4, 42}) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("%s: Names didn't contain oid 2.5.4.42 from ExtraNames", test.name)
		}

		if cert.Issuer.CommonName != commonName {
			t.Errorf("%s: issuer wasn't correctly copied from the template. Got %s, want %s", test.name, cert.Issuer.CommonName, commonName)
		}

		if cert.SignatureAlgorithm != test.sigAlgo {
```