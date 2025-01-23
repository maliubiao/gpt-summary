Response:
Let's break down the thought process for analyzing the provided Go code and answering the user's request.

1. **Understand the Goal:** The user wants to know the functionality of the Go code snippet, which is a test file (`pem_decrypt_test.go`) within the `crypto/x509` package. The focus should be on what it *tests*.

2. **Identify Key Functions and Structures:**  Scan the code for important function names and data structures.
    * `TestDecrypt(t *testing.T)`:  Immediately suggests testing the decryption functionality.
    * `TestEncrypt(t *testing.T)`: Suggests testing the encryption functionality.
    * `testData`: A slice of structs, likely containing test cases. Examining its fields (`kind`, `password`, `pemData`, `plainDER`) gives a strong hint about the data involved in encryption/decryption tests.
    * `DecryptPEMBlock`: A function being called within `TestDecrypt`. This is a prime candidate for the core decryption logic being tested.
    * `EncryptPEMBlock`: Similarly, this is likely the core encryption logic being tested in `TestEncrypt`.
    * `ParsePKCS1PrivateKey`: Used in `TestDecrypt`, implying that the decrypted data should represent a valid PKCS#1 private key.
    * `pem.Decode`:  Used to parse PEM-encoded data.
    * `base64.StdEncoding.DecodeString`: Used to decode base64 encoded data.
    * `bytes.Equal`: Used for comparing byte slices.
    * `IsEncryptedPEMBlock`: Used in `TestEncrypt` to check if a PEM block is encrypted.
    * `testingKey`: A helper function for modifying strings.
    * `TestIncompleteBlock`: Another test function, focusing on handling incomplete PEM blocks.

3. **Analyze `TestDecrypt`:**
    * The loop iterates through `testData`.
    * `pem.Decode(data.pemData)` decodes a PEM-encoded string. The `pemData` likely represents an *encrypted* private key.
    * `DecryptPEMBlock(block, data.password)` attempts to decrypt the PEM block using the provided password. This is the central functionality being tested.
    * `ParsePKCS1PrivateKey(der)` checks if the decrypted data (`der`) is a valid PKCS#1 private key. This provides a post-decryption validation.
    * `base64.StdEncoding.DecodeString(data.plainDER)` decodes the expected *unencrypted* private key in DER format.
    * `bytes.Equal(der, plainDER)` compares the decrypted data with the expected unencrypted data.

4. **Analyze `TestEncrypt`:**
    * The loop iterates through `testData`.
    * `base64.StdEncoding.DecodeString(data.plainDER)` gets the unencrypted private key in DER format.
    * `EncryptPEMBlock(rand.Reader, "RSA PRIVATE KEY", plainDER, password, data.kind)` encrypts the DER data using a specified encryption algorithm (`data.kind`), password, and block type.
    * `IsEncryptedPEMBlock(block)` verifies that the resulting PEM block is marked as encrypted.
    * The code then checks the `block.Type` and headers for correctness.
    * `DecryptPEMBlock(block, password)` decrypts the *newly encrypted* data.
    * `bytes.Equal(der, plainDER)` verifies that decrypting the encrypted data produces the original unencrypted data.

5. **Analyze `testData`:**
    * The `kind` field indicates the encryption algorithm used (DES, 3DES, AES variants).
    * `password` is the password for encryption/decryption.
    * `pemData` is the PEM-encoded, *encrypted* private key.
    * `plainDER` is the base64 encoded, *unencrypted* private key in DER format. This is the expected output of decryption.

6. **Analyze `TestIncompleteBlock`:**
    * Decodes an intentionally incomplete PEM block.
    * Attempts to decrypt it.
    * Checks if an error occurs and if the error message contains "block size," indicating the expected behavior for incomplete blocks.

7. **Infer Go Functionality:** Based on the tests, the code is testing the implementation of encrypting and decrypting PEM-encoded private keys using various symmetric encryption algorithms. The `crypto/x509` package likely provides the `EncryptPEMBlock` and `DecryptPEMBlock` functions.

8. **Provide Go Code Examples:**  Illustrate how to use the inferred `EncryptPEMBlock` and `DecryptPEMBlock` functions. This requires creating example PEM data (both encrypted and unencrypted).

9. **Consider Command-line Arguments:** The code itself doesn't directly handle command-line arguments. However, the `testing` package is used, and Go tests are typically run using the `go test` command. Mentioning this is relevant.

10. **Identify Potential User Errors:**  Think about common mistakes users might make when working with encryption:
    * Incorrect password.
    * Using the wrong encryption algorithm.
    * Handling PEM encoding/decoding incorrectly.

11. **Structure the Answer:**  Organize the findings into the sections requested by the user: functionality, Go code examples, code reasoning, command-line arguments, and common errors. Use clear and concise language. Provide specific examples for potential errors.

12. **Review and Refine:** Read through the answer to ensure accuracy, clarity, and completeness. Make sure the code examples are runnable and the explanations are easy to understand. For instance, initially I might just say "it tests decryption", but refining this to "tests the encryption and decryption of PEM-encoded private keys" is more precise. Also, initially, I might forget to explicitly mention the involvement of the `crypto/rand` package in `EncryptPEMBlock`. Reviewing helps catch these omissions.
这段Go语言代码文件 `pem_decrypt_test.go` 是 `crypto/x509` 包的一部分，专门用于测试 **PEM 格式加密的私钥的解密和加密功能**。

**主要功能：**

1. **测试解密功能 (`TestDecrypt` 函数):**
   - 遍历一组预定义的测试数据 (`testData`)，每个数据包含一个加密的 PEM 格式的私钥 (`pemData`)、解密密码 (`password`) 以及对应的未加密的 DER 格式的私钥 (`plainDER`)。
   - 使用 `pem.Decode` 函数解析 PEM 数据块。
   - 调用 `DecryptPEMBlock` 函数，尝试使用提供的密码解密 PEM 数据块。
   - 验证解密是否成功 (没有错误)。
   - 使用 `ParsePKCS1PrivateKey` 函数验证解密后的数据是否是有效的 PKCS#1 私钥。
   - 将解密后的数据与预期的未加密 DER 数据进行比较，确保解密结果的正确性。

2. **测试加密功能 (`TestEncrypt` 函数):**
   - 遍历相同的测试数据 (`testData`)。
   - 将预期的未加密 DER 数据 (`plainDER`) 进行 base64 解码。
   - 使用 `EncryptPEMBlock` 函数，使用随机源 (`rand.Reader`)、指定的密钥类型 `"RSA PRIVATE KEY"`、未加密的 DER 数据、一个固定的密码 `"kremvax1"` 和测试数据中定义的加密算法 (`data.kind`) 来加密数据。
   - 验证加密是否成功 (没有错误)。
   - 使用 `IsEncryptedPEMBlock` 函数检查生成的 PEM 数据块是否被标记为已加密。
   - 检查生成的 PEM 数据块的类型是否为 `"RSA PRIVATE KEY"`。
   - 检查生成的 PEM 数据块的头部是否包含 `"Proc-Type": "4,ENCRYPTED"`，这是加密 PEM 块的标识。
   - 调用 `DecryptPEMBlock` 函数，使用相同的密码解密刚刚加密的 PEM 数据块。
   - 验证解密是否成功 (没有错误)。
   - 将解密后的数据与原始的未加密 DER 数据进行比较，确保加密和解密过程的一致性。

3. **测试不完整的 PEM 数据块 (`TestIncompleteBlock` 函数):**
   - 使用一个故意不完整的加密 PEM 数据块 (`incompleteBlockPEM`) 进行测试。
   - 尝试使用 `DecryptPEMBlock` 解密这个不完整的数据块。
   - 验证解密是否失败，并且错误信息中包含 "block size"，这表明 `DecryptPEMBlock` 正确地处理了不完整的输入。

4. **辅助函数 (`testingKey`):**
   -  一个简单的辅助函数，用于将字符串中的 `"TESTING KEY"` 替换为 `"PRIVATE KEY"`，这可能是为了在测试数据中使用一种更通用的密钥类型名称。

**Go 语言功能的实现推断 (并举例说明):**

根据代码的测试内容，可以推断 `crypto/x509` 包中实现了以下功能：

- **`DecryptPEMBlock(block *pem.Block, password []byte) ([]byte, error)`:**  这个函数接收一个 PEM 数据块和一个密码作为输入，尝试解密该 PEM 数据块，并返回解密后的原始数据 (DER 格式的私钥) 和一个错误 (如果解密失败)。

  ```go
  package main

  import (
  	"crypto/x509"
  	"encoding/pem"
  	"fmt"
  	"log"
  )

  func main() {
  	encryptedPEM := `
  -----BEGIN RSA PRIVATE KEY-----
  Proc-Type: 4,ENCRYPTED
  DEK-Info: AES-128-CBC,D4492E793FC835CC038A728ED174F78A

  EyfQSzXSjv6BaNH+NHdXRlkHdimpF9izWlugVJAPApgXrq5YldPe2aGIOFXyJ+QE
  ZIG20DYqaPzJRjTEbPNZ6Es0S2JJ5yCpKxwJuDkgJZKtF39Q2i36JeGbSZQIuWJE
  GZbBpf1jDH/pr0iGonuAdl2PCCZUiy+8eLsD2tyviHUkFLOB+ykYoJ5t8ngZ/B6D
  33U43LLb7+9zD4y3Q9OVHqBFGyHcxCY9+9Qh4ZnFp7DTf6RY5TNEvE3s4g6aDpBs
  3NbvRVvYTgs8K9EPk4K+5R+P2kD8J8KvEIGxVa1vz8QoCJ/jr7Ka2rvNgPCex5/E
  080LzLHPCrXKdlr/f50yhNWq08ZxMWQFkui+FDHPDUaEELKAXV8/5PDxw80Rtybo
  AVYoCVIbZXZCuCO81op8UcOgEpTtyU5Lgh3Mw5scQL0=
  -----END RSA PRIVATE KEY-----
  `
  	password := []byte("asdf")

  	block, _ := pem.Decode([]byte(encryptedPEM))
  	if block == nil {
  		log.Fatal("Failed to decode PEM block")
  	}

  	decryptedData, err := x509.DecryptPEMBlock(block, password)
  	if err != nil {
  		log.Fatalf("Failed to decrypt PEM block: %v", err)
  	}

  	fmt.Printf("Decrypted data (first 20 bytes): %x\n", decryptedData[:20])
  }
  ```

  **假设输入:** `encryptedPEM` 变量包含一个使用密码 "asdf" 和 AES-128-CBC 加密的 RSA 私钥的 PEM 编码字符串。

  **预期输出:**  成功解密后，`decryptedData` 将包含未加密的私钥数据 (DER 格式)。控制台会打印解密后数据的前 20 个字节的十六进制表示。

- **`EncryptPEMBlock(rand io.Reader, type string, data []byte, password []byte, alg PEMCipher) (*pem.Block, error)`:** 这个函数接收一个随机数生成器、PEM 数据块类型 (例如 `"RSA PRIVATE KEY"`)、原始数据 (DER 格式的私钥)、加密密码和一个加密算法 (`PEMCipher` 枚举类型) 作为输入，返回加密后的 PEM 数据块和一个错误 (如果加密失败)。

  ```go
  package main

  import (
  	"crypto/rand"
  	"crypto/x509"
  	"encoding/base64"
  	"encoding/pem"
  	"fmt"
  	"log"
  )

  func main() {
  	plainDERBase64 := "MIIBOgIBAAJBAMBlj5FxYtqbcy8wY89d/S7n0+r5MzD9F63BA/Lpl78vQKtdJ5dT" +
  		"cDGh/rBt1ufRrNp0WihcmZi7Mpl/3jHjiWECAwEAAQJABNOHYnKhtDIqFYj1OAJ3" +
  		"k3GlU0OlERmIOoeY/cL2V4lgwllPBEs7r134AY4wMmZSBUj8UR/O4SNO668ElKPE" +
  		"cQIhAOuqY7/115x5KCdGDMWi+jNaMxIvI4ETGwV40ykGzqlzAiEA0P9oEC3m9tHB" +
  		"kbpjSTxaNkrXxDgdEOZz8X0uOUUwHNsCIAwzcSCiGLyYJTULUmP1ESERfW1mlV78" +
  		"XzzESaJpIM/zAiBQkSTcl9VhcJreQqvjn5BnPZLP4ZHS4gPwJAGdsj5J4QIhAOVR" +
  		"B3WlRNTXR2WsJ5JdByezg9xzdXzULqmga0OE339a"
  	password := []byte("kremvax1")

  	plainDER, err := base64.StdEncoding.DecodeString(plainDERBase64)
  	if err != nil {
  		log.Fatalf("Failed to decode base64: %v", err)
  	}

  	encryptedBlock, err := x509.EncryptPEMBlock(rand.Reader, "RSA PRIVATE KEY", plainDER, password, x509.PEMCipherAES128)
  	if err != nil {
  		log.Fatalf("Failed to encrypt PEM block: %v", err)
  	}

  	encryptedPEM := pem.EncodeToMemory(encryptedBlock)
  	fmt.Println(string(encryptedPEM))
  }
  ```

  **假设输入:** `plainDERBase64` 变量包含一个未加密的 RSA 私钥的 DER 格式的 base64 编码字符串。

  **预期输出:** 控制台会打印加密后的 PEM 格式的私钥字符串，该私钥使用密码 "kremvax1" 和 AES-128-CBC 算法加密。

- **`IsEncryptedPEMBlock(b *pem.Block) bool`:**  这个函数接收一个 PEM 数据块作为输入，返回一个布尔值，指示该数据块是否被标记为已加密 (即头部包含 `"Proc-Type": "4,ENCRYPTED"` )。

**命令行参数的具体处理：**

这段代码是一个测试文件，它本身不直接处理命令行参数。Go 语言的测试通常通过 `go test` 命令来运行。你可以使用 `go test` 的一些标志来控制测试的执行，例如：

- `-v`:  显示所有测试的详细输出，包括 `t.Logf` 的信息。
- `-run <regexp>`:  运行名称与正则表达式匹配的测试函数。例如，`go test -run Decrypt` 将只运行包含 "Decrypt" 的测试函数。

**使用者易犯错的点：**

1. **密码错误：**  解密时使用了错误的密码会导致解密失败。这是最常见也是最容易犯的错误。

   ```go
   // 错误示例：使用了错误的密码
   decryptedData, err := x509.DecryptPEMBlock(block, []byte("wrongpassword"))
   if err != nil {
       log.Println("解密失败:", err) // 输出类似于 "解密失败: asn1: structure error: integer too large" 的错误
   }
   ```

2. **PEM 数据块不完整或格式错误：**  如果提供的 PEM 数据块不是一个有效的加密 PEM 块，例如缺少头部信息或者数据部分不完整，`pem.Decode` 可能会返回 `nil`，或者 `DecryptPEMBlock` 会返回错误。`TestIncompleteBlock` 就是用来测试这种情况的。

   ```go
   // 错误示例：PEM 数据块不完整
   incompletePEM := `
   -----BEGIN RSA PRIVATE KEY-----
   Proc-Type: 4,ENCRYPTED
   DEK-Info: AES-128-CBC,74611ABC2571AF11B1BF9B69E62C89E7
   `
   block, _ := pem.Decode([]byte(incompletePEM))
   if block == nil {
       log.Println("PEM 解码失败") // 这里 block 会是 nil
   } else {
       _, err := x509.DecryptPEMBlock(block, []byte("asdf"))
       if err != nil {
           log.Println("解密失败:", err) // 可能输出 "解密失败: unexpected end of input" 之类的错误
       }
   }
   ```

3. **混淆加密算法：**  加密时使用的算法与解密时 `DecryptPEMBlock` 函数内部尝试的算法不匹配也可能导致解密失败。不过，`DecryptPEMBlock` 函数通常会根据 PEM 块的头部信息（`DEK-Info`）自动识别加密算法，所以这种情况不太常见。

总而言之，这段测试代码覆盖了 `crypto/x509` 包中关于加密和解密 PEM 格式私钥的核心功能，并通过多种测试用例验证了这些功能的正确性和健壮性。

### 提示词
```
这是路径为go/src/crypto/x509/pem_decrypt_test.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
```

### 源代码
```go
// Copyright 2012 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package x509

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/pem"
	"strings"
	"testing"
)

func TestDecrypt(t *testing.T) {
	for i, data := range testData {
		t.Logf("test %v. %v", i, data.kind)
		block, rest := pem.Decode(data.pemData)
		if len(rest) > 0 {
			t.Error("extra data")
		}
		der, err := DecryptPEMBlock(block, data.password)
		if err != nil {
			t.Error("decrypt failed: ", err)
			continue
		}
		if _, err := ParsePKCS1PrivateKey(der); err != nil {
			t.Error("invalid private key: ", err)
		}
		plainDER, err := base64.StdEncoding.DecodeString(data.plainDER)
		if err != nil {
			t.Fatal("cannot decode test DER data: ", err)
		}
		if !bytes.Equal(der, plainDER) {
			t.Error("data mismatch")
		}
	}
}

func TestEncrypt(t *testing.T) {
	for i, data := range testData {
		t.Logf("test %v. %v", i, data.kind)
		plainDER, err := base64.StdEncoding.DecodeString(data.plainDER)
		if err != nil {
			t.Fatal("cannot decode test DER data: ", err)
		}
		password := []byte("kremvax1")
		block, err := EncryptPEMBlock(rand.Reader, "RSA PRIVATE KEY", plainDER, password, data.kind)
		if err != nil {
			t.Error("encrypt: ", err)
			continue
		}
		if !IsEncryptedPEMBlock(block) {
			t.Error("PEM block does not appear to be encrypted")
		}
		if block.Type != "RSA PRIVATE KEY" {
			t.Errorf("unexpected block type; got %q want %q", block.Type, "RSA PRIVATE KEY")
		}
		if block.Headers["Proc-Type"] != "4,ENCRYPTED" {
			t.Errorf("block does not have correct Proc-Type header")
		}
		der, err := DecryptPEMBlock(block, password)
		if err != nil {
			t.Error("decrypt: ", err)
			continue
		}
		if !bytes.Equal(der, plainDER) {
			t.Errorf("data mismatch")
		}
	}
}

var testData = []struct {
	kind     PEMCipher
	password []byte
	pemData  []byte
	plainDER string
}{
	{
		kind:     PEMCipherDES,
		password: []byte("asdf"),
		pemData: []byte(testingKey(`
-----BEGIN RSA TESTING KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: DES-CBC,34F09A4FC8DE22B5

WXxy8kbZdiZvANtKvhmPBLV7eVFj2A5z6oAxvI9KGyhG0ZK0skfnt00C24vfU7m5
ICXeoqP67lzJ18xCzQfHjDaBNs53DSDT+Iz4e8QUep1xQ30+8QKX2NA2coee3nwc
6oM1cuvhNUDemBH2i3dKgMVkfaga0zQiiOq6HJyGSncCMSruQ7F9iWEfRbFcxFCx
qtHb1kirfGKEtgWTF+ynyco6+2gMXNu70L7nJcnxnV/RLFkHt7AUU1yrclxz7eZz
XOH9VfTjb52q/I8Suozq9coVQwg4tXfIoYUdT//O+mB7zJb9HI9Ps77b9TxDE6Gm
4C9brwZ3zg2vqXcwwV6QRZMtyll9rOpxkbw6NPlpfBqkc3xS51bbxivbO/Nve4KD
r12ymjFNF4stXCfJnNqKoZ50BHmEEUDu5Wb0fpVn82XrGw7CYc4iug==
-----END RSA TESTING KEY-----`)),
		plainDER: `
MIIBPAIBAAJBAPASZe+tCPU6p80AjHhDkVsLYa51D35e/YGa8QcZyooeZM8EHozo
KD0fNiKI+53bHdy07N+81VQ8/ejPcRoXPlsCAwEAAQJBAMTxIuSq27VpR+zZ7WJf
c6fvv1OBvpMZ0/d1pxL/KnOAgq2rD5hDtk9b0LGhTPgQAmrrMTKuSeGoIuYE+gKQ
QvkCIQD+GC1m+/do+QRurr0uo46Kx1LzLeSCrjBk34wiOp2+dwIhAPHfTLRXS2fv
7rljm0bYa4+eDZpz+E8RcXEgzhhvcQQ9AiAI5eHZJGOyml3MXnQjiPi55WcDOw0w
glcRgT6QCEtz2wIhANSyqaFtosIkHKqrDUGfz/bb5tqMYTAnBruVPaf/WEOBAiEA
9xORWeRG1tRpso4+dYy4KdDkuLPIO01KY6neYGm3BCM=`,
	},
	{
		kind:     PEMCipher3DES,
		password: []byte("asdf"),
		pemData: []byte(testingKey(`
-----BEGIN RSA TESTING KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: DES-EDE3-CBC,C1F4A6A03682C2C7

0JqVdBEH6iqM7drTkj+e2W/bE3LqakaiWhb9WUVonFkhyu8ca/QzebY3b5gCvAZQ
YwBvDcT/GHospKqPx+cxDHJNsUASDZws6bz8ZXWJGwZGExKzr0+Qx5fgXn44Ms3x
8g1ENFuTXtxo+KoNK0zuAMAqp66Llcds3Fjl4XR18QaD0CrVNAfOdgATWZm5GJxk
Fgx5f84nT+/ovvreG+xeOzWgvtKo0UUZVrhGOgfKLpa57adumcJ6SkUuBtEFpZFB
ldw5w7WC7d13x2LsRkwo8ZrDKgIV+Y9GNvhuCCkTzNP0V3gNeJpd201HZHR+9n3w
3z0VjR/MGqsfcy1ziEWMNOO53At3zlG6zP05aHMnMcZoVXadEK6L1gz++inSSDCq
gI0UJP4e3JVB7AkgYymYAwiYALAkoEIuanxoc50njJk=
-----END RSA TESTING KEY-----`)),
		plainDER: `
MIIBOwIBAAJBANOCXKdoNS/iP/MAbl9cf1/SF3P+Ns7ZeNL27CfmDh0O6Zduaax5
NBiumd2PmjkaCu7lQ5JOibHfWn+xJsc3kw0CAwEAAQJANX/W8d1Q/sCqzkuAn4xl
B5a7qfJWaLHndu1QRLNTRJPn0Ee7OKJ4H0QKOhQM6vpjRrz+P2u9thn6wUxoPsef
QQIhAP/jCkfejFcy4v15beqKzwz08/tslVjF+Yq41eJGejmxAiEA05pMoqfkyjcx
fyvGhpoOyoCp71vSGUfR2I9CR65oKh0CIC1Msjs66LlfJtQctRq6bCEtFCxEcsP+
eEjYo/Sk6WphAiEAxpgWPMJeU/shFT28gS+tmhjPZLpEoT1qkVlC14u0b3ECIQDX
tZZZxCtPAm7shftEib0VU77Lk8MsXJcx2C4voRsjEw==`,
	},
	{
		kind:     PEMCipherAES128,
		password: []byte("asdf"),
		pemData: []byte(testingKey(`
-----BEGIN RSA TESTING KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-128-CBC,D4492E793FC835CC038A728ED174F78A

EyfQSzXSjv6BaNH+NHdXRlkHdimpF9izWlugVJAPApgXrq5YldPe2aGIOFXyJ+QE
ZIG20DYqaPzJRjTEbPNZ6Es0S2JJ5yCpKxwJuDkgJZKtF39Q2i36JeGbSZQIuWJE
GZbBpf1jDH/pr0iGonuAdl2PCCZUiy+8eLsD2tyviHUkFLOB+ykYoJ5t8ngZ/B6D
33U43LLb7+9zD4y3Q9OVHqBFGyHcxCY9+9Qh4ZnFp7DTf6RY5TNEvE3s4g6aDpBs
3NbvRVvYTgs8K9EPk4K+5R+P2kD8J8KvEIGxVa1vz8QoCJ/jr7Ka2rvNgPCex5/E
080LzLHPCrXKdlr/f50yhNWq08ZxMWQFkui+FDHPDUaEELKAXV8/5PDxw80Rtybo
AVYoCVIbZXZCuCO81op8UcOgEpTtyU5Lgh3Mw5scQL0=
-----END RSA TESTING KEY-----`)),
		plainDER: `
MIIBOgIBAAJBAMBlj5FxYtqbcy8wY89d/S7n0+r5MzD9F63BA/Lpl78vQKtdJ5dT
cDGh/rBt1ufRrNp0WihcmZi7Mpl/3jHjiWECAwEAAQJABNOHYnKhtDIqFYj1OAJ3
k3GlU0OlERmIOoeY/cL2V4lgwllPBEs7r134AY4wMmZSBUj8UR/O4SNO668ElKPE
cQIhAOuqY7/115x5KCdGDMWi+jNaMxIvI4ETGwV40ykGzqlzAiEA0P9oEC3m9tHB
kbpjSTxaNkrXxDgdEOZz8X0uOUUwHNsCIAwzcSCiGLyYJTULUmP1ESERfW1mlV78
XzzESaJpIM/zAiBQkSTcl9VhcJreQqvjn5BnPZLP4ZHS4gPwJAGdsj5J4QIhAOVR
B3WlRNTXR2WsJ5JdByezg9xzdXzULqmga0OE339a`,
	},
	{
		kind:     PEMCipherAES192,
		password: []byte("asdf"),
		pemData: []byte(testingKey(`
-----BEGIN RSA TESTING KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-192-CBC,E2C9FB02BCA23ADE1829F8D8BC5F5369

cqVslvHqDDM6qwU6YjezCRifXmKsrgEev7ng6Qs7UmDJOpHDgJQZI9fwMFUhIyn5
FbCu1SHkLMW52Ld3CuEqMnzWMlhPrW8tFvUOrMWPYSisv7nNq88HobZEJcUNL2MM
Y15XmHW6IJwPqhKyLHpWXyOCVEh4ODND2nV15PCoi18oTa475baxSk7+1qH7GuIs
Rb7tshNTMqHbCpyo9Rn3UxeFIf9efdl8YLiMoIqc7J8E5e9VlbeQSdLMQOgDAQJG
ReUtTw8exmKsY4gsSjhkg5uiw7/ZB1Ihto0qnfQJgjGc680qGkT1d6JfvOfeYAk6
xn5RqS/h8rYAYm64KnepfC9vIujo4NqpaREDmaLdX5MJPQ+SlytITQvgUsUq3q/t
Ss85xjQEZH3hzwjQqdJvmA4hYP6SUjxYpBM+02xZ1Xw=
-----END RSA TESTING KEY-----`)),
		plainDER: `
MIIBOwIBAAJBAMGcRrZiNNmtF20zyS6MQ7pdGx17aFDl+lTl+qnLuJRUCMUG05xs
OmxmL/O1Qlf+bnqR8Bgg65SfKg21SYuLhiMCAwEAAQJBAL94uuHyO4wux2VC+qpj
IzPykjdU7XRcDHbbvksf4xokSeUFjjD3PB0Qa83M94y89ZfdILIqS9x5EgSB4/lX
qNkCIQD6cCIqLfzq/lYbZbQgAAjpBXeQVYsbvVtJrPrXJAlVVQIhAMXpDKMeFPMn
J0g2rbx1gngx0qOa5r5iMU5w/noN4W2XAiBjf+WzCG5yFvazD+dOx3TC0A8+4x3P
uZ3pWbaXf5PNuQIgAcdXarvhelH2w2piY1g3BPeFqhzBSCK/yLGxR82KIh8CIQDD
+qGKsd09NhQ/G27y/DARzOYtml1NvdmCQAgsDIIOLA==`,
	},
	{
		kind:     PEMCipherAES256,
		password: []byte("asdf"),
		pemData: []byte(testingKey(`
-----BEGIN RSA TESTING KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-256-CBC,8E7ED5CD731902CE938957A886A5FFBD

4Mxr+KIzRVwoOP0wwq6caSkvW0iS+GE2h2Ov/u+n9ZTMwL83PRnmjfjzBgfRZLVf
JFPXxUK26kMNpIdssNnqGOds+DhB+oSrsNKoxgxSl5OBoYv9eJTVYm7qOyAFIsjr
DRKAcjYCmzfesr7PVTowwy0RtHmYwyXMGDlAzzZrEvaiySFFmMyKKvtoavwaFoc7
Pz3RZScwIuubzTGJ1x8EzdffYOsdCa9Mtgpp3L136+23dOd6L/qK2EG2fzrJSHs/
2XugkleBFSMKzEp9mxXKRfa++uidQvMZTFLDK9w5YjrRvMBo/l2BoZIsq0jAIE1N
sv5Z/KwlX+3MDEpPQpUwGPlGGdLnjI3UZ+cjgqBcoMiNc6HfgbBgYJSU6aDSHuCk
clCwByxWkBNgJ2GrkwNrF26v+bGJJJNR4SKouY1jQf0=
-----END RSA TESTING KEY-----`)),
		plainDER: `
MIIBOgIBAAJBAKy3GFkstoCHIEeUU/qO8207m8WSrjksR+p9B4tf1w5k+2O1V/GY
AQ5WFCApItcOkQe/I0yZZJk/PmCqMzSxrc8CAwEAAQJAOCAz0F7AW9oNelVQSP8F
Sfzx7O1yom+qWyAQQJF/gFR11gpf9xpVnnyu1WxIRnDUh1LZwUsjwlDYb7MB74id
oQIhANPcOiLwOPT4sIUpRM5HG6BF1BI7L77VpyGVk8xNP7X/AiEA0LMHZtk4I+lJ
nClgYp4Yh2JZ1Znbu7IoQMCEJCjwKDECIGd8Dzm5tViTkUW6Hs3Tlf73nNs65duF
aRnSglss8I3pAiEAonEnKruawgD8RavDFR+fUgmQiPz4FnGGeVgfwpGG1JECIBYq
PXHYtPqxQIbD2pScR5qum7iGUh11lEUPkmt+2uqS`,
	},
	{
		// generated with:
		// openssl genrsa -aes128 -passout pass:asdf -out server.orig.key 128
		kind:     PEMCipherAES128,
		password: []byte("asdf"),
		pemData: []byte(testingKey(`
-----BEGIN RSA TESTING KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-128-CBC,74611ABC2571AF11B1BF9B69E62C89E7

6ei/MlytjE0FFgZOGQ+jrwomKfpl8kdefeE0NSt/DMRrw8OacHAzBNi3pPEa0eX3
eND9l7C9meCirWovjj9QWVHrXyugFuDIqgdhQ8iHTgCfF3lrmcttVrbIfMDw+smD
hTP8O1mS/MHl92NE0nhv0w==
-----END RSA TESTING KEY-----`)),
		plainDER: `
MGMCAQACEQC6ssxmYuauuHGOCDAI54RdAgMBAAECEQCWIn6Yv2O+kBcDF7STctKB
AgkA8SEfu/2i3g0CCQDGNlXbBHX7kQIIK3Ww5o0cYbECCQDCimPb0dYGsQIIeQ7A
jryIst8=`,
	},
}

var incompleteBlockPEM = testingKey(`
-----BEGIN RSA TESTING KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-128-CBC,74611ABC2571AF11B1BF9B69E62C89E7

6L8yXK2MTQUWBk4ZD6OvCiYp+mXyR1594TQ1K38MxGvDw5pwcDME2Lek8RrR5fd40P2XsL2Z4KKt
ai+OP1BZUetfK6AW4MiqB2FDyIdOAJ8XeWuZy21Wtsh8wPD6yYOFM/w7WZL8weX3Y0TSeG/T
-----END RSA TESTING KEY-----`)

func TestIncompleteBlock(t *testing.T) {
	// incompleteBlockPEM contains ciphertext that is not a multiple of the
	// block size. This previously panicked. See #11215.
	block, _ := pem.Decode([]byte(incompleteBlockPEM))
	_, err := DecryptPEMBlock(block, []byte("foo"))
	if err == nil {
		t.Fatal("Bad PEM data decrypted successfully")
	}
	const expectedSubstr = "block size"
	if e := err.Error(); !strings.Contains(e, expectedSubstr) {
		t.Fatalf("Expected error containing %q but got: %q", expectedSubstr, e)
	}
}

func testingKey(s string) string { return strings.ReplaceAll(s, "TESTING KEY", "PRIVATE KEY") }
```