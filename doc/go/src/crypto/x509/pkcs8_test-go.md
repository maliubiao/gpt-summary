Response:
The user wants to understand the functionality of the provided Go code snippet, which is part of the `pkcs8_test.go` file within the `crypto/x509` package. The file name suggests it's related to testing the PKCS#8 standard for private key encoding.

Here's a breakdown of the thinking process to arrive at the answer:

1. **Identify the Core Purpose:** The file name `pkcs8_test.go` immediately signals that this code is for testing PKCS#8 functionality. Specifically, since it's in the `crypto/x509` package, it's likely testing the `x509` package's ability to handle PKCS#8 encoded private keys.

2. **Analyze the Imports:** The imported packages provide clues about the code's functions:
    * `"bytes"`:  Likely used for comparing byte arrays, suggesting verification of encoding/decoding.
    * `"crypto/ecdh"`, `"crypto/ecdsa"`, `"crypto/ed25519"`, `"crypto/elliptic"`, `"crypto/rsa"`: These indicate testing with various private key types (RSA, ECDSA with different curves, EdDSA, ECDH).
    * `"encoding/hex"`: Suggests the test data is represented in hexadecimal strings.
    * `"reflect"`:  Likely used for comparing the types of the decoded keys.
    * `"strings"`:  Could be used for string manipulation, perhaps in error checking.
    * `"testing"`:  Confirms this is a testing file.

3. **Examine the Test Data:** The code defines several variables with names like `pkcs8RSAPrivateKeyHex`, `pkcs8P224PrivateKeyHex`, etc. These clearly hold hexadecimal representations of PKCS#8 encoded private keys for different algorithms. The comments above these variables even explain how they were generated using `openssl`.

4. **Focus on the `TestPKCS8` Function:** This is the primary test function. Its structure reveals the testing logic:
    * It defines a `tests` slice of structs, each representing a test case for a specific key type.
    * Each test case includes the key name, the hexadecimal representation of the PKCS#8 encoded key, the expected key type (using `reflect.TypeOf`), and the expected elliptic curve (if applicable).
    * Inside the loop iterating through the tests:
        * The hexadecimal string is decoded.
        * `ParsePKCS8PrivateKey` is called to decode the PKCS#8 data. This is a key function being tested.
        * The type of the decoded key is checked against the expected type.
        * For EC keys, the curve is checked.
        * `MarshalPKCS8PrivateKey` is called to re-encode the decoded key back into PKCS#8 format. This checks the encoding functionality.
        * The re-encoded data is compared to the original input to ensure round-trip integrity.
        * For ECDSA keys, there's an attempt to convert to ECDH and re-serialize, indicating a test related to interoperability between ECDSA and ECDH.

5. **Analyze `TestPKCS8MismatchKeyFormat`:** This function tests the negative case: attempting to parse a PKCS#8 encoded key using the wrong parsing function (e.g., trying to parse a PKCS#8 encoded EC key with a function meant for PKCS#1 RSA keys). It checks for specific error messages.

6. **Infer the Functionality:** Based on the observations above, the main functionality of this code is to test the `ParsePKCS8PrivateKey` and `MarshalPKCS8PrivateKey` functions within the `crypto/x509` package. These functions are responsible for decoding and encoding private keys in the PKCS#8 format.

7. **Provide Go Code Examples:** To illustrate how these functions are used, create simple examples that demonstrate parsing and marshaling. Include different key types (RSA and ECDSA).

8. **Address Potential Mistakes:** Think about common errors users might encounter when working with PKCS#8:
    * Trying to use `ParsePKCS8PrivateKey` on keys not encoded in PKCS#8 (like PKCS#1).
    * Incorrectly handling or decoding the hexadecimal representation.

9. **Structure the Answer:** Organize the information logically, starting with a general overview of the functionality, then providing code examples, and finally addressing potential mistakes. Use clear and concise language.
这个 `go/src/crypto/x509/pkcs8_test.go` 文件是 Go 语言 `crypto/x509` 包的一部分，专门用于测试 PKCS#8 私钥的解析和序列化功能。

**主要功能:**

1. **测试 `ParsePKCS8PrivateKey` 函数:**
   - 该文件包含了多个测试用例，每个用例都包含一个十六进制表示的 PKCS#8 编码的私钥。
   - 它使用 `hex.DecodeString` 将十六进制字符串解码为字节切片。
   - 然后调用 `x509.ParsePKCS8PrivateKey` 函数来解析这些字节切片，将其转换为 Go 语言中对应的私钥类型（例如 `*rsa.PrivateKey`, `*ecdsa.PrivateKey`, `ed25519.PrivateKey`, `*ecdh.PrivateKey`）。
   - 测试会验证解析后的私钥类型是否与预期相符，对于椭圆曲线密钥，还会验证其曲线是否正确。

2. **测试 `MarshalPKCS8PrivateKey` 函数:**
   - 对于成功解析的私钥，测试会调用 `x509.MarshalPKCS8PrivateKey` 函数将其重新序列化为 PKCS#8 格式的字节切片。
   - 然后，测试会将重新序列化后的字节切片与原始的输入字节切片进行比较，以确保序列化和反序列化的过程没有丢失信息，实现了数据的完整性。

3. **测试不同类型的私钥:**
   - 文件中包含了多种类型的私钥的 PKCS#8 编码，涵盖了：
     - RSA 私钥
     - ECDSA 私钥 (使用不同的椭圆曲线，例如 P-224, P-256, P-384, P-521)
     - EdDSA (Ed25519) 私钥
     - ECDH (X25519) 私钥
   - 这表明该文件旨在全面测试 `ParsePKCS8PrivateKey` 和 `MarshalPKCS8PrivateKey` 函数对于各种常见私钥算法的支持。

4. **测试错误的输入格式:**
   - `TestPKCS8MismatchKeyFormat` 函数测试了当尝试使用 `ParsePKCS8PrivateKey` 解析非 PKCS#8 格式的私钥时，是否会返回预期的错误。这有助于确保函数的健壮性，能够正确处理不符合预期格式的输入。

**它是什么Go语言功能的实现？**

这个测试文件主要测试了 Go 语言 `crypto/x509` 包中用于处理 PKCS#8 编码私钥的功能。PKCS#8 是一种标准的私钥信息语法，定义了私钥的存储格式，使其可以在不同的系统和应用程序之间交换。 `ParsePKCS8PrivateKey` 函数负责将这种编码格式的私钥转换为 Go 程序可以使用的私钥对象，而 `MarshalPKCS8PrivateKey` 则执行相反的操作。

**Go代码举例说明:**

```go
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"log"
)

func main() {
	// 假设我们有一个 PKCS#8 编码的 RSA 私钥 (这里使用测试文件中的数据)
	pkcs8RSAPrivateKeyHex := `30820278020100300d06092a864886f70d0101010500048202623082025e02010002818100cfb1b5bf9685ffa97b4f99df4ff122b70e59ac9b992f3bc2b3dde17d53c1a34928719b02e8fd17839499bfbd515bd6ef99c7a1c47a239718fe36bfd824c0d96060084b5f67f0273443007a24dfaf5634f7772c9346e10eb294c2306671a5a5e719ae24b4de467291bc571014b0e02dec04534d66a9bb171d644b66b091780e8d020301000102818100b595778383c4afdbab95d2bfed12b3f93bb0a73a7ad952f44d7185fd9ec6c34de8f03a48770f2009c8580bcd275e9632714e9a5e3f32f29dc55474b2329ff0ebc08b3ffcb35bc96e6516b483df80a4a59cceb71918cbabf91564e64a39d7e35dce21cb3031824fdbc845dba6458852ec16af5dddf51a8397a8797ae0337b1439024100ea0eb1b914158c70db39031dd8904d6f18f408c85fbbc592d7d20dee7986969efbda081fdf8bc40e1b1336d6b638110c836bfdc3f314560d2e49cd4fbde1e20b024100e32a4e793b574c9c4a94c8803db5152141e72d03de64e54ef2c8ed104988ca780cd11397bc359630d01b97ebd87067c5451ba777cf045ca23f5912f1031308c702406dfcdbbd5a57c9f85abc4edf9e9e29153507b07ce0a7ef6f52e60dcfebe1b8341babd8b789a837485da6c8d55b29bbb142ace3c24a1f5b54b454d01b51e2ad03024100bd6a2b60dee01e1b3bfcef6a2f09ed027c273cdbbaf6ba55a80f6dcc64e4509ee560f84b4f3e076bd03b11e42fe71a3fdd2dffe7e0902c8584f8cad877cdc945024100aa512fa4ada69881f1d8bb8ad6614f192b83200aef5edf4811313d5ef30a86cbd0a90f7b025c71ea06ec6b34db6306c86b1040670fd8654ad7291d066d06d031`

	// 将十六进制字符串解码为字节切片
	derBytes, err := hex.DecodeString(pkcs8RSAPrivateKeyHex)
	if err != nil {
		log.Fatalf("解码失败: %v", err)
	}

	// 解析 PKCS#8 编码的私钥
	privateKey, err := x509.ParsePKCS8PrivateKey(derBytes)
	if err != nil {
		log.Fatalf("解析 PKCS#8 私钥失败: %v", err)
	}

	// 类型断言以使用 RSA 私钥的特定方法
	rsaPrivateKey, ok := privateKey.(*rsa.PrivateKey)
	if ok {
		fmt.Printf("成功解析 RSA 私钥，模数长度: %d\n", rsaPrivateKey.N.BitLen())
	} else {
		fmt.Println("解析后的不是 RSA 私钥")
	}

	// 将解析后的私钥重新序列化为 PKCS#8 格式
	reserializedData, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		log.Fatalf("序列化 PKCS#8 私钥失败: %v", err)
	}

	// 可以将 reserializedData 保存到文件或通过网络传输
	fmt.Printf("重新序列化的 PKCS#8 数据 (前 50 字节): %x...\n", reserializedData[:50])

	// 示例：解析 ECDSA 私钥
	pkcs8P256PrivateKeyHex := `308187020100301306072a8648ce3d020106082a8648ce3d030107046d306b0201010420dad6b2f49ca774c36d8ae9517e935226f667c929498f0343d2424d0b9b591b43a14403420004b9c9b90095476afe7b860d8bd43568cab7bcb2eed7b8bf2fa0ce1762dd20b04193f859d2d782b1e4cbfd48492f1f533113a6804903f292258513837f07fda735`
	ecdsaDerBytes, err := hex.DecodeString(pkcs8P256PrivateKeyHex)
	if err != nil {
		log.Fatalf("解码 ECDSA 失败: %v", err)
	}
	ecdsaPrivateKey, err := x509.ParsePKCS8PrivateKey(ecdsaDerBytes)
	if err != nil {
		log.Fatalf("解析 ECDSA PKCS#8 私钥失败: %v", err)
	}
	if ecdsaKey, ok := ecdsaPrivateKey.(*ecdsa.PrivateKey); ok {
		fmt.Printf("成功解析 ECDSA 私钥，曲线: %s\n", ecdsaKey.Curve.Params().Name)
	} else {
		fmt.Println("解析后的不是 ECDSA 私钥")
	}
}
```

**假设的输入与输出:**

在上面的 RSA 私钥示例中：

**输入:**  `pkcs8RSAPrivateKeyHex` 变量中的十六进制字符串。

**输出:**

- `x509.ParsePKCS8PrivateKey` 函数会返回一个 `*rsa.PrivateKey` 类型的指针，该指针指向从 PKCS#8 数据中解析出的 RSA 私钥结构体。
- 打印输出类似于：`成功解析 RSA 私钥，模数长度: 1024` (因为示例中的 RSA 密钥是 1024 位的)。
- `x509.MarshalPKCS8PrivateKey` 函数会返回一个字节切片 `reserializedData`，其内容与解码前的 `derBytes` 相同。
- 打印输出类似于：`重新序列化的 PKCS#8 数据 (前 50 字节): 30820278020100300d06092a864886f70d0101010500048202623082025e02010002818100cfb1b5bf9685ff...`

**命令行参数的具体处理:**

这个测试文件本身并不直接处理命令行参数。它是一个单元测试文件，通常通过 `go test` 命令来运行。`go test` 命令会扫描当前目录及其子目录中所有以 `_test.go` 结尾的文件，并执行其中的测试函数。

**使用者易犯错的点:**

1. **输入数据格式错误:**
   - 容易犯错的是提供的 PKCS#8 编码数据不是有效的格式。例如，数据可能被损坏、截断，或者根本就不是 PKCS#8 编码。
   ```go
   // 错误的十六进制字符串（故意截断）
   invalidHex := "30820278020100300d06092a864886f70d010101050004820262308"
   invalidDerBytes, _ := hex.DecodeString(invalidHex) // 忽略错误，仅为演示
   _, err := x509.ParsePKCS8PrivateKey(invalidDerBytes)
   if err != nil {
       fmt.Printf("解析失败 (预期): %v\n", err) // 输出类似 "asn1: structure error: integer too short" 的错误
   }
   ```

2. **尝试使用 `ParsePKCS8PrivateKey` 解析其他格式的私钥:**
   - `ParsePKCS8PrivateKey` 只能解析 PKCS#8 格式的私钥。如果尝试解析 PKCS#1 或其他格式的私钥，将会失败。测试文件中的 `TestPKCS8MismatchKeyFormat` 就验证了这一点。
   ```go
   // 假设 hexPKCS1Key 是一个 PKCS#1 格式的私钥的十六进制字符串
   hexPKCS1Key := "3082025c02010002818100b1a1e094..." // 假设的 PKCS#1 数据
   pkcs1DerBytes, _ := hex.DecodeString(hexPKCS1Key)
   _, err := x509.ParsePKCS8PrivateKey(pkcs1DerBytes)
   if err != nil {
       fmt.Printf("解析失败 (预期): %v\n", err) // 输出类似 "asn1: structure error: tags don't match (16 vs {48 49})" 的错误
   }
   ```
   应该使用 `x509.ParsePKCS1PrivateKey` 来解析 PKCS#1 格式的私钥。

3. **没有正确处理错误:**
   - 在实际应用中，`ParsePKCS8PrivateKey` 可能会返回错误，使用者必须妥善处理这些错误，而不是简单地忽略它们。
   ```go
   derBytes, err := hex.DecodeString(pkcs8RSAPrivateKeyHex)
   if err != nil {
       log.Fatalf("解码失败: %v", err)
   }
   privateKey, err := x509.ParsePKCS8PrivateKey(derBytes)
   if err != nil {
       log.Fatalf("解析 PKCS#8 私钥失败: %v", err) // 如果解析失败，程序应该退出或采取其他适当的措施
   }
   // ... 使用 privateKey
   ```

总而言之，这个测试文件的主要目的是确保 Go 语言的 `crypto/x509` 包能够正确地解析和序列化各种类型的 PKCS#8 编码的私钥，并且能够处理格式不匹配的情况，从而保证了 Go 语言在处理数字证书和加密相关的安全性。

### 提示词
```
这是路径为go/src/crypto/x509/pkcs8_test.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
```

### 源代码
```go
// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package x509

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/hex"
	"reflect"
	"strings"
	"testing"
)

// Generated using:
//
//	openssl genrsa 1024 | openssl pkcs8 -topk8 -nocrypt
var pkcs8RSAPrivateKeyHex = `30820278020100300d06092a864886f70d0101010500048202623082025e02010002818100cfb1b5bf9685ffa97b4f99df4ff122b70e59ac9b992f3bc2b3dde17d53c1a34928719b02e8fd17839499bfbd515bd6ef99c7a1c47a239718fe36bfd824c0d96060084b5f67f0273443007a24dfaf5634f7772c9346e10eb294c2306671a5a5e719ae24b4de467291bc571014b0e02dec04534d66a9bb171d644b66b091780e8d020301000102818100b595778383c4afdbab95d2bfed12b3f93bb0a73a7ad952f44d7185fd9ec6c34de8f03a48770f2009c8580bcd275e9632714e9a5e3f32f29dc55474b2329ff0ebc08b3ffcb35bc96e6516b483df80a4a59cceb71918cbabf91564e64a39d7e35dce21cb3031824fdbc845dba6458852ec16af5dddf51a8397a8797ae0337b1439024100ea0eb1b914158c70db39031dd8904d6f18f408c85fbbc592d7d20dee7986969efbda081fdf8bc40e1b1336d6b638110c836bfdc3f314560d2e49cd4fbde1e20b024100e32a4e793b574c9c4a94c8803db5152141e72d03de64e54ef2c8ed104988ca780cd11397bc359630d01b97ebd87067c5451ba777cf045ca23f5912f1031308c702406dfcdbbd5a57c9f85abc4edf9e9e29153507b07ce0a7ef6f52e60dcfebe1b8341babd8b789a837485da6c8d55b29bbb142ace3c24a1f5b54b454d01b51e2ad03024100bd6a2b60dee01e1b3bfcef6a2f09ed027c273cdbbaf6ba55a80f6dcc64e4509ee560f84b4f3e076bd03b11e42fe71a3fdd2dffe7e0902c8584f8cad877cdc945024100aa512fa4ada69881f1d8bb8ad6614f192b83200aef5edf4811313d5ef30a86cbd0a90f7b025c71ea06ec6b34db6306c86b1040670fd8654ad7291d066d06d031`

// Generated using:
//
//	openssl ecparam -genkey -name secp224r1 | openssl pkcs8 -topk8 -nocrypt
var pkcs8P224PrivateKeyHex = `3078020100301006072a8648ce3d020106052b810400210461305f020101041cca3d72b3e88fed2684576dad9b80a9180363a5424986900e3abcab3fa13c033a0004f8f2a6372872a4e61263ed893afb919576a4cacfecd6c081a2cbc76873cf4ba8530703c6042b3a00e2205087e87d2435d2e339e25702fae1`

// Generated using:
//
//	openssl ecparam -genkey -name secp256r1 | openssl pkcs8 -topk8 -nocrypt
var pkcs8P256PrivateKeyHex = `308187020100301306072a8648ce3d020106082a8648ce3d030107046d306b0201010420dad6b2f49ca774c36d8ae9517e935226f667c929498f0343d2424d0b9b591b43a14403420004b9c9b90095476afe7b860d8bd43568cab7bcb2eed7b8bf2fa0ce1762dd20b04193f859d2d782b1e4cbfd48492f1f533113a6804903f292258513837f07fda735`

// Generated using:
//
//	openssl ecparam -genkey -name secp384r1 | openssl pkcs8 -topk8 -nocrypt
var pkcs8P384PrivateKeyHex = `3081b6020100301006072a8648ce3d020106052b8104002204819e30819b02010104309bf832f6aaaeacb78ce47ffb15e6fd0fd48683ae79df6eca39bfb8e33829ac94aa29d08911568684c2264a08a4ceb679a164036200049070ad4ed993c7770d700e9f6dc2baa83f63dd165b5507f98e8ff29b5d2e78ccbe05c8ddc955dbf0f7497e8222cfa49314fe4e269459f8e880147f70d785e530f2939e4bf9f838325bb1a80ad4cf59272ae0e5efe9a9dc33d874492596304bd3`

// Generated using:
//
//	openssl ecparam -genkey -name secp521r1 | openssl pkcs8 -topk8 -nocrypt
//
// Note that OpenSSL will truncate the private key if it can (i.e. it emits it
// like an integer, even though it's an OCTET STRING field). Thus if you
// regenerate this you may, randomly, find that it's a byte shorter than
// expected and the Go test will fail to recreate it exactly.
var pkcs8P521PrivateKeyHex = `3081ee020100301006072a8648ce3d020106052b810400230481d63081d3020101044200cfe0b87113a205cf291bb9a8cd1a74ac6c7b2ebb8199aaa9a5010d8b8012276fa3c22ac913369fa61beec2a3b8b4516bc049bde4fb3b745ac11b56ab23ac52e361a1818903818600040138f75acdd03fbafa4f047a8e4b272ba9d555c667962b76f6f232911a5786a0964e5edea6bd21a6f8725720958de049c6e3e6661c1c91b227cebee916c0319ed6ca003db0a3206d372229baf9dd25d868bf81140a518114803ce40c1855074d68c4e9dab9e65efba7064c703b400f1767f217dac82715ac1f6d88c74baf47a7971de4ea`

// From RFC 8410, Section 7.
var pkcs8Ed25519PrivateKeyHex = `302e020100300506032b657004220420d4ee72dbf913584ad5b6d8f1f769f8ad3afe7c28cbf1d4fbe097a88f44755842`

// Generated using:
//
//	openssl genpkey -algorithm x25519
var pkcs8X25519PrivateKeyHex = `302e020100300506032b656e0422042068ff93a73c5adefd6d498b24e588fd4daa10924d992afed01b43ca5725025a6b`

func TestPKCS8(t *testing.T) {
	tests := []struct {
		name    string
		keyHex  string
		keyType reflect.Type
		curve   elliptic.Curve
	}{
		{
			name:    "RSA private key",
			keyHex:  pkcs8RSAPrivateKeyHex,
			keyType: reflect.TypeOf(&rsa.PrivateKey{}),
		},
		{
			name:    "P-224 private key",
			keyHex:  pkcs8P224PrivateKeyHex,
			keyType: reflect.TypeOf(&ecdsa.PrivateKey{}),
			curve:   elliptic.P224(),
		},
		{
			name:    "P-256 private key",
			keyHex:  pkcs8P256PrivateKeyHex,
			keyType: reflect.TypeOf(&ecdsa.PrivateKey{}),
			curve:   elliptic.P256(),
		},
		{
			name:    "P-384 private key",
			keyHex:  pkcs8P384PrivateKeyHex,
			keyType: reflect.TypeOf(&ecdsa.PrivateKey{}),
			curve:   elliptic.P384(),
		},
		{
			name:    "P-521 private key",
			keyHex:  pkcs8P521PrivateKeyHex,
			keyType: reflect.TypeOf(&ecdsa.PrivateKey{}),
			curve:   elliptic.P521(),
		},
		{
			name:    "Ed25519 private key",
			keyHex:  pkcs8Ed25519PrivateKeyHex,
			keyType: reflect.TypeOf(ed25519.PrivateKey{}),
		},
		{
			name:    "X25519 private key",
			keyHex:  pkcs8X25519PrivateKeyHex,
			keyType: reflect.TypeOf(&ecdh.PrivateKey{}),
		},
	}

	for _, test := range tests {
		derBytes, err := hex.DecodeString(test.keyHex)
		if err != nil {
			t.Errorf("%s: failed to decode hex: %s", test.name, err)
			continue
		}
		privKey, err := ParsePKCS8PrivateKey(derBytes)
		if err != nil {
			t.Errorf("%s: failed to decode PKCS#8: %s", test.name, err)
			continue
		}
		if reflect.TypeOf(privKey) != test.keyType {
			t.Errorf("%s: decoded PKCS#8 returned unexpected key type: %T", test.name, privKey)
			continue
		}
		if ecKey, isEC := privKey.(*ecdsa.PrivateKey); isEC && ecKey.Curve != test.curve {
			t.Errorf("%s: decoded PKCS#8 returned unexpected curve %#v", test.name, ecKey.Curve)
			continue
		}
		reserialised, err := MarshalPKCS8PrivateKey(privKey)
		if err != nil {
			t.Errorf("%s: failed to marshal into PKCS#8: %s", test.name, err)
			continue
		}
		if !bytes.Equal(derBytes, reserialised) {
			t.Errorf("%s: marshaled PKCS#8 didn't match original: got %x, want %x", test.name, reserialised, derBytes)
			continue
		}

		if ecKey, isEC := privKey.(*ecdsa.PrivateKey); isEC {
			ecdhKey, err := ecKey.ECDH()
			if err != nil {
				if ecKey.Curve != elliptic.P224() {
					t.Errorf("%s: failed to convert to ecdh: %s", test.name, err)
				}
				continue
			}
			reserialised, err := MarshalPKCS8PrivateKey(ecdhKey)
			if err != nil {
				t.Errorf("%s: failed to marshal into PKCS#8: %s", test.name, err)
				continue
			}
			if !bytes.Equal(derBytes, reserialised) {
				t.Errorf("%s: marshaled PKCS#8 didn't match original: got %x, want %x", test.name, reserialised, derBytes)
				continue
			}
		}
	}
}

const hexPKCS8TestPKCS1Key = "3082025c02010002818100b1a1e0945b9289c4d3f1329f8a982c4a2dcd59bfd372fb8085a9c517554607ebd2f7990eef216ac9f4605f71a03b04f42a5255b158cf8e0844191f5119348baa44c35056e20609bcf9510f30ead4b481c81d7865fb27b8e0090e112b717f3ee08cdfc4012da1f1f7cf2a1bc34c73a54a12b06372d09714742dd7895eadde4aa5020301000102818062b7fa1db93e993e40237de4d89b7591cc1ea1d04fed4904c643f17ae4334557b4295270d0491c161cb02a9af557978b32b20b59c267a721c4e6c956c2d147046e9ae5f2da36db0106d70021fa9343455f8f973a4b355a26fd19e6b39dee0405ea2b32deddf0f4817759ef705d02b34faab9ca93c6766e9f722290f119f34449024100d9c29a4a013a90e35fd1be14a3f747c589fac613a695282d61812a711906b8a0876c6181f0333ca1066596f57bff47e7cfcabf19c0fc69d9cd76df743038b3cb024100d0d3546fecf879b5551f2bd2c05e6385f2718a08a6face3d2aecc9d7e03645a480a46c81662c12ad6bd6901e3bd4f38029462de7290859567cdf371c79088d4f024100c254150657e460ea58573fcf01a82a4791e3d6223135c8bdfed69afe84fbe7857274f8eb5165180507455f9b4105c6b08b51fe8a481bb986a202245576b713530240045700003b7a867d0041df9547ae2e7f50248febd21c9040b12dae9c2feab0d3d4609668b208e4727a3541557f84d372ac68eaf74ce1018a4c9a0ef92682c8fd02405769731480bb3a4570abf422527c5f34bf732fa6c1e08cc322753c511ce055fac20fc770025663ad3165324314df907f1f1942f0448a7e9cdbf87ecd98b92156"
const hexPKCS8TestECKey = "3081a40201010430bdb9839c08ee793d1157886a7a758a3c8b2a17a4df48f17ace57c72c56b4723cf21dcda21d4e1ad57ff034f19fcfd98ea00706052b81040022a16403620004feea808b5ee2429cfcce13c32160e1c960990bd050bb0fdf7222f3decd0a55008e32a6aa3c9062051c4cba92a7a3b178b24567412d43cdd2f882fa5addddd726fe3e208d2c26d733a773a597abb749714df7256ead5105fa6e7b3650de236b50"

var pkcs8MismatchKeyTests = []struct {
	hexKey        string
	errorContains string
}{
	{hexKey: hexPKCS8TestECKey, errorContains: "use ParseECPrivateKey instead"},
	{hexKey: hexPKCS8TestPKCS1Key, errorContains: "use ParsePKCS1PrivateKey instead"},
}

func TestPKCS8MismatchKeyFormat(t *testing.T) {
	for i, test := range pkcs8MismatchKeyTests {
		derBytes, _ := hex.DecodeString(test.hexKey)
		_, err := ParsePKCS8PrivateKey(derBytes)
		if !strings.Contains(err.Error(), test.errorContains) {
			t.Errorf("#%d: expected error containing %q, got %s", i, test.errorContains, err)
		}
	}
}
```