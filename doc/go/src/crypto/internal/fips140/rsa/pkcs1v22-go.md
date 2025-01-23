Response:
The user wants to understand the functionality of the provided Go code snippet. The code is located in `go/src/crypto/internal/fips140/rsa/pkcs1v22.go` and deals with RSA signature and encryption schemes based on PKCS #1 v2.2 (RFC 8017).

Here's a plan to answer the user's request:

1. **Identify the main functions:** Look for functions with clear names related to signature and encryption.
2. **Describe each function's purpose:**  Explain what each function does based on its name and code logic.
3. **Infer the overall Go functionality:** Determine what higher-level cryptographic features this code implements.
4. **Provide Go code examples:** Demonstrate the usage of the identified functions. This requires making assumptions about inputs and showing the expected output structure (not necessarily exact byte values).
5. **Address code reasoning:** For complex logic, explain the steps involved with assumed inputs and outputs.
6. **Check for command-line arguments:**  This file doesn't seem to handle command-line arguments directly.
7. **Highlight common mistakes:** Identify potential pitfalls for users interacting with this code, focusing on parameter handling and expected input formats.
这段Go语言代码实现了 **PKCS #1 v2.2** 标准中定义的两种 RSA 相关的密码学方案：

1. **RSASSA-PSS (RSA Signature Scheme with Appendix - Probabilistic Signature Scheme):** 用于数字签名。
2. **RSAES-OAEP (RSA Encryption Scheme - Optimal Asymmetric Encryption Padding):** 用于加密。

下面分别介绍代码中的主要功能：

**1. RSASSA-PSS 相关功能:**

* **`emsaPSSEncode(mHash []byte, emBits int, salt []byte, hash fips140.Hash) ([]byte, error)`:**  此函数实现了 **EMSA-PSS 编码操作**，将已哈希的消息 (`mHash`) 和盐值 (`salt`) 编码成一个用于 RSA 签名的消息编码 (`EM`)。
    * **输入:**
        * `mHash`:  已使用指定的哈希函数计算过的消息摘要。
        * `emBits`:  RSA 模数的比特长度减 1。
        * `salt`:  随机生成的盐值。
        * `hash`:  用于哈希运算的 `fips140.Hash` 接口的实现 (例如 `sha256.Digest`)。
    * **输出:**
        * `[]byte`:  编码后的消息 `EM`。
        * `error`:  如果编码过程中发生错误，则返回错误信息。
    * **代码推理:** 函数内部实现了 RFC 8017 Section 9.1.1 中描述的 EMSA-PSS 编码步骤，包括生成 PS 填充，构建 DB 数据块，应用 MGF1 掩码生成函数，最终生成 EM。
    * **假设输入与输出:**
        ```go
        package main

        import (
            "crypto/internal/fips140"
            "crypto/internal/fips140/sha256"
            "fmt"
        )

        func main() {
            mHash := []byte("example message hash") // 假设的消息哈希值
            emBits := 2047                      // 假设 RSA 模数为 2048 位
            salt := []byte("random salt")       // 假设的盐值
            hash := &sha256.Digest{}           // 使用 SHA256 哈希

            em, err := emsaPSSEncode(mHash, emBits, salt, hash)
            if err != nil {
                fmt.Println("编码错误:", err)
                return
            }
            fmt.Printf("编码后的 EM: %x\n", em) // 输出编码后的 EM
        }
        ```
        **假设输出:**  （输出会根据输入的随机盐值而变化，这里仅展示结构）
        ```
        编码后的 EM: ... (一串十六进制数据) ...
        ```

* **`emsaPSSVerify(mHash, em []byte, emBits, sLen int, hash fips140.Hash) error`:** 此函数实现了 **EMSA-PSS 验证操作**，用于验证给定的消息哈希 (`mHash`) 和消息编码 (`em`) 的签名是否有效。
    * **输入:**
        * `mHash`:  已使用指定的哈希函数计算过的消息摘要。
        * `em`:  待验证的签名消息编码。
        * `emBits`:  RSA 模数的比特长度减 1。
        * `sLen`:  盐值的长度。可以是 `pssSaltLengthAutodetect` (-1) 表示自动检测。
        * `hash`:  用于哈希运算的 `fips140.Hash` 接口的实现。
    * **输出:**
        * `error`:  如果签名有效则返回 `nil`，否则返回 `ErrVerification` 错误。
    * **代码推理:** 函数内部实现了 RFC 8017 Section 9.1.2 中描述的 EMSA-PSS 验证步骤，包括检查 EM 的格式，逆向 MGF1 掩码操作，验证 DB 数据块的结构，并最终验证哈希值。
    * **假设输入与输出:**
        ```go
        package main

        import (
            "bytes"
            "crypto/internal/fips140"
            "crypto/internal/fips140/sha256"
            "fmt"
        )

        func main() {
            mHash := []byte("example message hash") // 假设的消息哈希值
            em := []byte{ /* 假设的签名 EM 数据 */ }
            emBits := 2047
            saltLength := 16
            hash := &sha256.Digest{}

            err := emsaPSSVerify(mHash, em, emBits, saltLength, hash)
            if err != nil {
                fmt.Println("签名验证失败:", err)
            } else {
                fmt.Println("签名验证成功")
            }
        }
        ```
        **假设输出:**  （取决于 `em` 的内容是否是有效的签名）
        ```
        签名验证成功
        ```
        或者
        ```
        签名验证失败: rsa: verification error
        ```

* **`PSSMaxSaltLength(pub *PublicKey, hash fips140.Hash) (int, error)`:**  计算给定公钥和哈希函数下，PSS 签名允许的最大盐值长度。
* **`SignPSS(rand io.Reader, priv *PrivateKey, hash fips140.Hash, hashed []byte, saltLength int) ([]byte, error)`:** 使用 RSASSA-PSS 方案对已哈希的消息进行签名。
    * **输入:**
        * `rand`:  随机数生成器。
        * `priv`:  RSA 私钥。
        * `hash`:  用于哈希运算的 `fips140.Hash` 接口的实现。
        * `hashed`:  已使用指定的哈希函数计算过的消息摘要。
        * `saltLength`:  盐值的长度。
    * **输出:**
        * `[]byte`:  生成的 RSA PSS 签名。
        * `error`:  如果签名过程中发生错误，则返回错误信息。
    * **代码推理:**  此函数首先生成指定长度的随机盐值，然后调用 `emsaPSSEncode` 进行编码，最后使用私钥进行解密（在 RSA 中，签名操作实际上是使用私钥进行“解密”）。
    * **假设输入与输出:**
        ```go
        package main

        import (
            "crypto/internal/fips140"
            "crypto/internal/fips140/rsa"
            "crypto/internal/fips140/sha256"
            "crypto/rand"
            "fmt"
            "log"
        )

        func main() {
            priv, err := rsa.GenerateKey(rand.Reader, 2048)
            if err != nil {
                log.Fatal(err)
            }
            hashed := []byte("message to be signed")
            hash := &sha256.Digest{}
            hash.Write(hashed)
            hashedBytes := hash.Sum(nil)
            saltLength := 16

            signature, err := SignPSS(rand.Reader, priv, hash, hashedBytes, saltLength)
            if err != nil {
                fmt.Println("签名错误:", err)
                return
            }
            fmt.Printf("生成的签名: %x\n", signature)
        }
        ```
        **假设输出:**
        ```
        生成的签名: ... (一串十六进制数据) ...
        ```

* **`VerifyPSS(pub *PublicKey, hash fips140.Hash, digest []byte, sig []byte) error`:** 使用 RSASSA-PSS 方案验证签名，自动检测盐值长度。
* **`VerifyPSSWithSaltLength(pub *PublicKey, hash fips140.Hash, digest []byte, sig []byte, saltLength int) error`:** 使用 RSASSA-PSS 方案验证签名，并指定预期的盐值长度。
* **`verifyPSS(pub *PublicKey, hash fips140.Hash, digest []byte, sig []byte, saltLength int) error`:**  内部的 PSS 签名验证实现。
    * **输入:**
        * `pub`:  RSA 公钥。
        * `hash`:  用于哈希运算的 `fips140.Hash` 接口的实现。
        * `digest`:  已使用指定的哈希函数计算过的消息摘要。
        * `sig`:  待验证的 RSA PSS 签名。
        * `saltLength`:  盐值的长度。可以是 `pssSaltLengthAutodetect` (-1) 表示自动检测。
    * **输出:**
        * `error`:  如果签名有效则返回 `nil`，否则返回 `ErrVerification` 错误。
    * **代码推理:** 此函数首先使用公钥进行“加密”（在 RSA 中，验证操作实际上是使用公钥进行“加密”），得到编码后的消息，然后调用 `emsaPSSVerify` 进行验证。
    * **假设输入与输出:**
        ```go
        package main

        import (
            "crypto/internal/fips140"
            "crypto/internal/fips140/rsa"
            "crypto/internal/fips140/sha256"
            "crypto/rand"
            "fmt"
            "log"
        )

        func main() {
            priv, err := rsa.GenerateKey(rand.Reader, 2048)
            if err != nil {
                log.Fatal(err)
            }
            pub := &priv.PublicKey
            hashed := []byte("message to be signed")
            hash := &sha256.Digest{}
            hash.Write(hashed)
            hashedBytes := hash.Sum(nil)
            saltLength := 16

            signature, err := SignPSS(rand.Reader, priv, hash, hashedBytes, saltLength)
            if err != nil {
                fmt.Println("签名错误:", err)
                return
            }

            err = VerifyPSS(pub, hash, hashedBytes, signature)
            if err != nil {
                fmt.Println("签名验证失败:", err)
            } else {
                fmt.Println("签名验证成功")
            }
        }
        ```
        **假设输出:**
        ```
        签名验证成功
        ```

**2. RSAES-OAEP 相关功能:**

* **`EncryptOAEP(hash, mgfHash fips140.Hash, random io.Reader, pub *PublicKey, msg []byte, label []byte) ([]byte, error)`:** 使用 RSAES-OAEP 方案加密消息。
    * **输入:**
        * `hash`:  用于 OAEP 填充的哈希函数。
        * `mgfHash`: 用于掩码生成函数 (MGF1) 的哈希函数。
        * `random`:  随机数生成器。
        * `pub`:  RSA 公钥。
        * `msg`:  要加密的消息。
        * `label`:  可选的标签，可以为 `nil`。
    * **输出:**
        * `[]byte`:  加密后的密文。
        * `error`:  如果加密过程中发生错误，则返回错误信息。
    * **代码推理:**  此函数实现了 RFC 8017 Section 7.1.1 中描述的 RSAES-OAEP 加密操作，包括生成种子，进行 DB 数据块的填充和掩码，最终使用公钥进行加密。
    * **假设输入与输出:**
        ```go
        package main

        import (
            "crypto/internal/fips140"
            "crypto/internal/fips140/rsa"
            "crypto/internal/fips140/sha256"
            "crypto/rand"
            "fmt"
            "log"
        )

        func main() {
            pub, priv, err := generateKeyPair()
            if err != nil {
                log.Fatal(err)
            }
            msg := []byte("secret message")
            label := []byte("encryption label")
            hash := &sha256.Digest{}
            mgfHash := &sha256.Digest{}

            ciphertext, err := EncryptOAEP(hash, mgfHash, rand.Reader, pub, msg, label)
            if err != nil {
                fmt.Println("加密错误:", err)
                return
            }
            fmt.Printf("加密后的密文: %x\n", ciphertext)
        }

        func generateKeyPair() (*rsa.PublicKey, *rsa.PrivateKey, error) {
            priv, err := rsa.GenerateKey(rand.Reader, 2048)
            if err != nil {
                return nil, nil, err
            }
            return &priv.PublicKey, priv, nil
        }
        ```
        **假设输出:**
        ```
        加密后的密文: ... (一串十六进制数据) ...
        ```

* **`DecryptOAEP(hash, mgfHash fips140.Hash, priv *PrivateKey, ciphertext []byte, label []byte) ([]byte, error)`:** 使用 RSAES-OAEP 方案解密密文。
    * **输入:**
        * `hash`:  用于 OAEP 填充的哈希函数。
        * `mgfHash`: 用于掩码生成函数 (MGF1) 的哈希函数。
        * `priv`:  RSA 私钥。
        * `ciphertext`:  要解密的密文。
        * `label`:  加密时使用的标签，可以为 `nil`。
    * **输出:**
        * `[]byte`:  解密后的消息。
        * `error`:  如果解密过程中发生错误，则返回错误信息。
    * **代码推理:** 此函数实现了 RFC 8017 Section 7.1.2 中描述的 RSAES-OAEP 解密操作，包括使用私钥进行解密，逆向 MGF1 掩码操作，验证 DB 数据块的结构，最终提取原始消息。 此函数特别注意了抵抗计时攻击，使用常量时间比较操作。
    * **假设输入与输出:**
        ```go
        package main

        import (
            "crypto/internal/fips140"
            "crypto/internal/fips140/rsa"
            "crypto/internal/fips140/sha256"
            "crypto/rand"
            "fmt"
            "log"
        )

        func main() {
            pub, priv, err := generateKeyPair()
            if err != nil {
                log.Fatal(err)
            }
            msg := []byte("secret message")
            label := []byte("encryption label")
            hash := &sha256.Digest{}
            mgfHash := &sha256.Digest{}

            ciphertext, err := EncryptOAEP(hash, mgfHash, rand.Reader, pub, msg, label)
            if err != nil {
                fmt.Println("加密错误:", err)
                return
            }

            plaintext, err := DecryptOAEP(hash, mgfHash, priv, ciphertext, label)
            if err != nil {
                fmt.Println("解密错误:", err)
                return
            }
            fmt.Printf("解密后的消息: %s\n", plaintext)
        }

        func generateKeyPair() (*rsa.PublicKey, *rsa.PrivateKey, error) {
            priv, err := rsa.GenerateKey(rand.Reader, 2048)
            if err != nil {
                return nil, nil, err
            }
            return &priv.PublicKey, priv, nil
        }
        ```
        **假设输出:**
        ```
        解密后的消息: secret message
        ```

**辅助函数:**

* **`incCounter(c *[4]byte)`:**  递增一个四字节的大端计数器。用于 MGF1 函数。
* **`mgf1XOR(out []byte, hash fips140.Hash, seed []byte)`:**  使用 MGF1 函数生成的掩码与 `out` 进行异或操作。
* **`checkApprovedHash(hash fips140.Hash)`:** 检查提供的哈希函数是否是被 FIPS 批准的。

**此代码实现的是 Go 语言的 RSA 数字签名和加密功能。**  更具体地说，它实现了符合 PKCS #1 v2.2 标准的 RSASSA-PSS 签名方案和 RSAES-OAEP 加密方案。这些是现代密码学中常用的安全 RSA 操作模式。

**命令行参数处理:**

这段代码本身并没有直接处理命令行参数。它是一个库文件，提供了一些函数供其他 Go 程序调用。如果需要使用这些功能，需要在你的 Go 程序中导入相应的包，并使用代码调用这些函数。

**使用者易犯错的点:**

1. **哈希函数不匹配:**  进行签名和验证，或者加密和解密时，使用的哈希函数 (`hash` 和 `mgfHash`) 必须一致。如果不一致，验证会失败，解密也会出错。
    * **错误示例:**  签名时使用 SHA256，验证时使用 SHA512。
2. **标签不匹配 (OAEP):**  在使用 RSAES-OAEP 进行加密和解密时，提供的 `label` 必须完全一致。否则，解密将会失败。
    * **错误示例:** 加密时 `label` 为 "A"，解密时 `label` 为 "B"。
3. **盐值长度错误 (PSS):**  在 `VerifyPSSWithSaltLength` 中，如果提供的 `saltLength` 与签名时使用的盐值长度不一致，验证会失败。虽然 `VerifyPSS` 可以自动检测，但如果已知盐值长度，使用 `VerifyPSSWithSaltLength` 更为明确。
4. **输入未哈希 (PSS):** `SignPSS` 和 `VerifyPSS` 期望的输入是已经过哈希的消息摘要 (`hashed` 或 `digest`)，而不是原始消息。使用者容易忘记先对消息进行哈希处理。
5. **密钥类型错误:**  加密操作需要使用公钥 (`*PublicKey`)，签名操作需要使用私钥 (`*PrivateKey`)。使用者可能会混淆密钥类型。
6. **数据长度超出限制 (OAEP):**  `EncryptOAEP` 中，要加密的消息长度不能超过 `k-2*hash.Size()-2`，其中 `k` 是公钥的字节长度。如果消息过长，会返回 `ErrMessageTooLong` 错误。
7. **随机数来源不安全:**  签名和加密操作依赖于安全的随机数生成器 (`io.Reader`)。如果提供的随机数来源不安全，可能会导致密钥泄露或其他安全问题。应该使用 `crypto/rand` 包提供的 `rand.Reader`。

这段代码是 `crypto/internal/fips140` 包的一部分，表明它可能用于满足 FIPS 140 标准的要求。这意味着在使用时需要注意相关的安全性和合规性要求。

### 提示词
```
这是路径为go/src/crypto/internal/fips140/rsa/pkcs1v22.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
```

### 源代码
```go
// Copyright 2013 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package rsa

// This file implements the RSASSA-PSS signature scheme and the RSAES-OAEP
// encryption scheme according to RFC 8017, aka PKCS #1 v2.2.

import (
	"bytes"
	"crypto/internal/fips140"
	"crypto/internal/fips140/drbg"
	"crypto/internal/fips140/sha256"
	"crypto/internal/fips140/sha3"
	"crypto/internal/fips140/sha512"
	"crypto/internal/fips140/subtle"
	"errors"
	"io"
)

// Per RFC 8017, Section 9.1
//
//     EM = MGF1 xor DB || H( 8*0x00 || mHash || salt ) || 0xbc
//
// where
//
//     DB = PS || 0x01 || salt
//
// and PS can be empty so
//
//     emLen = dbLen + hLen + 1 = psLen + sLen + hLen + 2
//

// incCounter increments a four byte, big-endian counter.
func incCounter(c *[4]byte) {
	if c[3]++; c[3] != 0 {
		return
	}
	if c[2]++; c[2] != 0 {
		return
	}
	if c[1]++; c[1] != 0 {
		return
	}
	c[0]++
}

// mgf1XOR XORs the bytes in out with a mask generated using the MGF1 function
// specified in PKCS #1 v2.1.
func mgf1XOR(out []byte, hash fips140.Hash, seed []byte) {
	var counter [4]byte
	var digest []byte

	done := 0
	for done < len(out) {
		hash.Reset()
		hash.Write(seed)
		hash.Write(counter[0:4])
		digest = hash.Sum(digest[:0])

		for i := 0; i < len(digest) && done < len(out); i++ {
			out[done] ^= digest[i]
			done++
		}
		incCounter(&counter)
	}
}

func emsaPSSEncode(mHash []byte, emBits int, salt []byte, hash fips140.Hash) ([]byte, error) {
	// See RFC 8017, Section 9.1.1.

	hLen := hash.Size()
	sLen := len(salt)
	emLen := (emBits + 7) / 8

	// 1.  If the length of M is greater than the input limitation for the
	//     hash function (2^61 - 1 octets for SHA-1), output "message too
	//     long" and stop.
	//
	// 2.  Let mHash = Hash(M), an octet string of length hLen.

	if len(mHash) != hLen {
		return nil, errors.New("crypto/rsa: input must be hashed with given hash")
	}

	// 3.  If emLen < hLen + sLen + 2, output "encoding error" and stop.

	if emLen < hLen+sLen+2 {
		return nil, ErrMessageTooLong
	}

	em := make([]byte, emLen)
	psLen := emLen - sLen - hLen - 2
	db := em[:psLen+1+sLen]
	h := em[psLen+1+sLen : emLen-1]

	// 4.  Generate a random octet string salt of length sLen; if sLen = 0,
	//     then salt is the empty string.
	//
	// 5.  Let
	//       M' = (0x)00 00 00 00 00 00 00 00 || mHash || salt;
	//
	//     M' is an octet string of length 8 + hLen + sLen with eight
	//     initial zero octets.
	//
	// 6.  Let H = Hash(M'), an octet string of length hLen.

	var prefix [8]byte

	hash.Reset()
	hash.Write(prefix[:])
	hash.Write(mHash)
	hash.Write(salt)

	h = hash.Sum(h[:0])

	// 7.  Generate an octet string PS consisting of emLen - sLen - hLen - 2
	//     zero octets. The length of PS may be 0.
	//
	// 8.  Let DB = PS || 0x01 || salt; DB is an octet string of length
	//     emLen - hLen - 1.

	db[psLen] = 0x01
	copy(db[psLen+1:], salt)

	// 9.  Let dbMask = MGF(H, emLen - hLen - 1).
	//
	// 10. Let maskedDB = DB \xor dbMask.

	mgf1XOR(db, hash, h)

	// 11. Set the leftmost 8 * emLen - emBits bits of the leftmost octet in
	//     maskedDB to zero.

	db[0] &= 0xff >> (8*emLen - emBits)

	// 12. Let EM = maskedDB || H || 0xbc.
	em[emLen-1] = 0xbc

	// 13. Output EM.
	return em, nil
}

const pssSaltLengthAutodetect = -1

func emsaPSSVerify(mHash, em []byte, emBits, sLen int, hash fips140.Hash) error {
	// See RFC 8017, Section 9.1.2.

	hLen := hash.Size()
	emLen := (emBits + 7) / 8
	if emLen != len(em) {
		return errors.New("rsa: internal error: inconsistent length")
	}

	// 1.  If the length of M is greater than the input limitation for the
	//     hash function (2^61 - 1 octets for SHA-1), output "inconsistent"
	//     and stop.
	//
	// 2.  Let mHash = Hash(M), an octet string of length hLen.
	if hLen != len(mHash) {
		return ErrVerification
	}

	// 3.  If emLen < hLen + sLen + 2, output "inconsistent" and stop.
	if emLen < hLen+sLen+2 {
		return ErrVerification
	}

	// 4.  If the rightmost octet of EM does not have hexadecimal value
	//     0xbc, output "inconsistent" and stop.
	if em[emLen-1] != 0xbc {
		return ErrVerification
	}

	// 5.  Let maskedDB be the leftmost emLen - hLen - 1 octets of EM, and
	//     let H be the next hLen octets.
	db := em[:emLen-hLen-1]
	h := em[emLen-hLen-1 : emLen-1]

	// 6.  If the leftmost 8 * emLen - emBits bits of the leftmost octet in
	//     maskedDB are not all equal to zero, output "inconsistent" and
	//     stop.
	var bitMask byte = 0xff >> (8*emLen - emBits)
	if em[0] & ^bitMask != 0 {
		return ErrVerification
	}

	// 7.  Let dbMask = MGF(H, emLen - hLen - 1).
	//
	// 8.  Let DB = maskedDB \xor dbMask.
	mgf1XOR(db, hash, h)

	// 9.  Set the leftmost 8 * emLen - emBits bits of the leftmost octet in DB
	//     to zero.
	db[0] &= bitMask

	// If we don't know the salt length, look for the 0x01 delimiter.
	if sLen == pssSaltLengthAutodetect {
		psLen := bytes.IndexByte(db, 0x01)
		if psLen < 0 {
			return ErrVerification
		}
		sLen = len(db) - psLen - 1
	}

	// FIPS 186-5, Section 5.4(g): "the length (in bytes) of the salt (sLen)
	// shall satisfy 0 ≤ sLen ≤ hLen".
	if sLen > hLen {
		fips140.RecordNonApproved()
	}

	// 10. If the emLen - hLen - sLen - 2 leftmost octets of DB are not zero
	//     or if the octet at position emLen - hLen - sLen - 1 (the leftmost
	//     position is "position 1") does not have hexadecimal value 0x01,
	//     output "inconsistent" and stop.
	psLen := emLen - hLen - sLen - 2
	for _, e := range db[:psLen] {
		if e != 0x00 {
			return ErrVerification
		}
	}
	if db[psLen] != 0x01 {
		return ErrVerification
	}

	// 11.  Let salt be the last sLen octets of DB.
	salt := db[len(db)-sLen:]

	// 12.  Let
	//          M' = (0x)00 00 00 00 00 00 00 00 || mHash || salt ;
	//     M' is an octet string of length 8 + hLen + sLen with eight
	//     initial zero octets.
	//
	// 13. Let H' = Hash(M'), an octet string of length hLen.
	hash.Reset()
	var prefix [8]byte
	hash.Write(prefix[:])
	hash.Write(mHash)
	hash.Write(salt)

	h0 := hash.Sum(nil)

	// 14. If H = H', output "consistent." Otherwise, output "inconsistent."
	if !bytes.Equal(h0, h) { // TODO: constant time?
		return ErrVerification
	}
	return nil
}

// PSSMaxSaltLength returns the maximum salt length for a given public key and
// hash function.
func PSSMaxSaltLength(pub *PublicKey, hash fips140.Hash) (int, error) {
	saltLength := (pub.N.BitLen()-1+7)/8 - 2 - hash.Size()
	if saltLength < 0 {
		return 0, ErrMessageTooLong
	}
	// FIPS 186-5, Section 5.4(g): "the length (in bytes) of the salt (sLen)
	// shall satisfy 0 ≤ sLen ≤ hLen".
	if fips140.Enabled && saltLength > hash.Size() {
		return hash.Size(), nil
	}
	return saltLength, nil
}

// SignPSS calculates the signature of hashed using RSASSA-PSS.
func SignPSS(rand io.Reader, priv *PrivateKey, hash fips140.Hash, hashed []byte, saltLength int) ([]byte, error) {
	fipsSelfTest()
	fips140.RecordApproved()
	checkApprovedHash(hash)

	// Note that while we don't commit to deterministic execution with respect
	// to the rand stream, we also don't apply MaybeReadByte, so per Hyrum's Law
	// it's probably relied upon by some. It's a tolerable promise because a
	// well-specified number of random bytes is included in the signature, in a
	// well-specified way.

	if saltLength < 0 {
		return nil, errors.New("crypto/rsa: salt length cannot be negative")
	}
	// FIPS 186-5, Section 5.4(g): "the length (in bytes) of the salt (sLen)
	// shall satisfy 0 ≤ sLen ≤ hLen".
	if saltLength > hash.Size() {
		fips140.RecordNonApproved()
	}
	salt := make([]byte, saltLength)
	if err := drbg.ReadWithReaderDeterministic(rand, salt); err != nil {
		return nil, err
	}

	emBits := priv.pub.N.BitLen() - 1
	em, err := emsaPSSEncode(hashed, emBits, salt, hash)
	if err != nil {
		return nil, err
	}

	// RFC 8017: "Note that the octet length of EM will be one less than k if
	// modBits - 1 is divisible by 8 and equal to k otherwise, where k is the
	// length in octets of the RSA modulus n." 🙄
	//
	// This is extremely annoying, as all other encrypt and decrypt inputs are
	// always the exact same size as the modulus. Since it only happens for
	// weird modulus sizes, fix it by padding inefficiently.
	if emLen, k := len(em), priv.pub.Size(); emLen < k {
		emNew := make([]byte, k)
		copy(emNew[k-emLen:], em)
		em = emNew
	}

	return decrypt(priv, em, withCheck)
}

// VerifyPSS verifies sig with RSASSA-PSS automatically detecting the salt length.
func VerifyPSS(pub *PublicKey, hash fips140.Hash, digest []byte, sig []byte) error {
	return verifyPSS(pub, hash, digest, sig, pssSaltLengthAutodetect)
}

// VerifyPSS verifies sig with RSASSA-PSS and an expected salt length.
func VerifyPSSWithSaltLength(pub *PublicKey, hash fips140.Hash, digest []byte, sig []byte, saltLength int) error {
	if saltLength < 0 {
		return errors.New("crypto/rsa: salt length cannot be negative")
	}
	return verifyPSS(pub, hash, digest, sig, saltLength)
}

func verifyPSS(pub *PublicKey, hash fips140.Hash, digest []byte, sig []byte, saltLength int) error {
	fipsSelfTest()
	fips140.RecordApproved()
	checkApprovedHash(hash)
	if fipsApproved, err := checkPublicKey(pub); err != nil {
		return err
	} else if !fipsApproved {
		fips140.RecordNonApproved()
	}

	if len(sig) != pub.Size() {
		return ErrVerification
	}

	emBits := pub.N.BitLen() - 1
	emLen := (emBits + 7) / 8
	em, err := encrypt(pub, sig)
	if err != nil {
		return ErrVerification
	}

	// Like in signPSSWithSalt, deal with mismatches between emLen and the size
	// of the modulus. The spec would have us wire emLen into the encoding
	// function, but we'd rather always encode to the size of the modulus and
	// then strip leading zeroes if necessary. This only happens for weird
	// modulus sizes anyway.
	for len(em) > emLen && len(em) > 0 {
		if em[0] != 0 {
			return ErrVerification
		}
		em = em[1:]
	}

	return emsaPSSVerify(digest, em, emBits, saltLength, hash)
}

func checkApprovedHash(hash fips140.Hash) {
	switch hash.(type) {
	case *sha256.Digest, *sha512.Digest, *sha3.Digest:
	default:
		fips140.RecordNonApproved()
	}
}

// EncryptOAEP encrypts the given message with RSAES-OAEP.
func EncryptOAEP(hash, mgfHash fips140.Hash, random io.Reader, pub *PublicKey, msg []byte, label []byte) ([]byte, error) {
	// Note that while we don't commit to deterministic execution with respect
	// to the random stream, we also don't apply MaybeReadByte, so per Hyrum's
	// Law it's probably relied upon by some. It's a tolerable promise because a
	// well-specified number of random bytes is included in the ciphertext, in a
	// well-specified way.

	fipsSelfTest()
	fips140.RecordApproved()
	checkApprovedHash(hash)
	if fipsApproved, err := checkPublicKey(pub); err != nil {
		return nil, err
	} else if !fipsApproved {
		fips140.RecordNonApproved()
	}
	k := pub.Size()
	if len(msg) > k-2*hash.Size()-2 {
		return nil, ErrMessageTooLong
	}

	hash.Reset()
	hash.Write(label)
	lHash := hash.Sum(nil)

	em := make([]byte, k)
	seed := em[1 : 1+hash.Size()]
	db := em[1+hash.Size():]

	copy(db[0:hash.Size()], lHash)
	db[len(db)-len(msg)-1] = 1
	copy(db[len(db)-len(msg):], msg)

	if err := drbg.ReadWithReaderDeterministic(random, seed); err != nil {
		return nil, err
	}

	mgf1XOR(db, mgfHash, seed)
	mgf1XOR(seed, mgfHash, db)

	return encrypt(pub, em)
}

// DecryptOAEP decrypts ciphertext using RSAES-OAEP.
func DecryptOAEP(hash, mgfHash fips140.Hash, priv *PrivateKey, ciphertext []byte, label []byte) ([]byte, error) {
	fipsSelfTest()
	fips140.RecordApproved()
	checkApprovedHash(hash)

	k := priv.pub.Size()
	if len(ciphertext) > k ||
		k < hash.Size()*2+2 {
		return nil, ErrDecryption
	}

	em, err := decrypt(priv, ciphertext, noCheck)
	if err != nil {
		return nil, err
	}

	hash.Reset()
	hash.Write(label)
	lHash := hash.Sum(nil)

	firstByteIsZero := subtle.ConstantTimeByteEq(em[0], 0)

	seed := em[1 : hash.Size()+1]
	db := em[hash.Size()+1:]

	mgf1XOR(seed, mgfHash, db)
	mgf1XOR(db, mgfHash, seed)

	lHash2 := db[0:hash.Size()]

	// We have to validate the plaintext in constant time in order to avoid
	// attacks like: J. Manger. A Chosen Ciphertext Attack on RSA Optimal
	// Asymmetric Encryption Padding (OAEP) as Standardized in PKCS #1
	// v2.0. In J. Kilian, editor, Advances in Cryptology.
	lHash2Good := subtle.ConstantTimeCompare(lHash, lHash2)

	// The remainder of the plaintext must be zero or more 0x00, followed
	// by 0x01, followed by the message.
	//   lookingForIndex: 1 iff we are still looking for the 0x01
	//   index: the offset of the first 0x01 byte
	//   invalid: 1 iff we saw a non-zero byte before the 0x01.
	var lookingForIndex, index, invalid int
	lookingForIndex = 1
	rest := db[hash.Size():]

	for i := 0; i < len(rest); i++ {
		equals0 := subtle.ConstantTimeByteEq(rest[i], 0)
		equals1 := subtle.ConstantTimeByteEq(rest[i], 1)
		index = subtle.ConstantTimeSelect(lookingForIndex&equals1, i, index)
		lookingForIndex = subtle.ConstantTimeSelect(equals1, 0, lookingForIndex)
		invalid = subtle.ConstantTimeSelect(lookingForIndex&^equals0, 1, invalid)
	}

	if firstByteIsZero&lHash2Good&^invalid&^lookingForIndex != 1 {
		return nil, ErrDecryption
	}

	return rest[index+1:], nil
}
```