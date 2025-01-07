Response:
Let's break down the request and the provided Go code snippet.

**1. Understanding the Goal:**

The user wants to understand the functionality of a specific part of a Go test file (`gcm_test.go`) related to the `crypto/cipher` package. The request is broken down into specific points:

* **List Functionality:**  What does this code do?
* **Infer Go Feature:** What Go feature does it test/demonstrate?
* **Provide Go Code Example:** Illustrate the feature with a code example (potentially simplified).
* **Include Assumptions/Inputs/Outputs (for code inference):** If I need to infer, I need to show how I arrived at that conclusion with examples.
* **Describe Command-Line Arguments (if applicable):**  This part is less likely for test code, but I need to check.
* **Highlight Common Mistakes:**  Are there any pitfalls users should avoid when working with this code or the underlying feature?
* **Use Chinese:** The response must be in Chinese.
* **Part 2 Summary:** Summarize the functionality of *this specific* code segment. The prompt indicates this is the second part of a larger file.

**2. Analyzing the Code Snippet - Individual Functions:**

* **`TestGCMCounterWrap`:**  The name strongly suggests this function tests how the GCM counter handles wrapping (reaching its maximum value and resetting). It iterates through a set of test cases, each with a nonce and expected tag. It creates a GCM cipher, seals data, and verifies the generated tag. It also attempts to open the sealed data to ensure integrity. The counter values mentioned in the comments are key to understanding what's being tested.
* **`TestGCMAsm`:**  This function seems to be testing an assembly-optimized implementation of GCM against a generic Go implementation. It creates both versions of the cipher, generates various plaintext and additional data with different alignments and lengths, and then compares the output of `Seal` and `Open` for both implementations. It also checks if an assembly implementation is even present.
* **`TestGCMAEAD`:** This function appears to be testing the GCM implementation against a general `cipher.AEAD` interface tester. This likely means it's verifying that the GCM implementation adheres to the standard authenticated encryption with associated data (AEAD) interface contracts. It tests different key sizes, tag sizes, and nonce sizes. It also has a specific check related to `NewGCMWithRandomNonce` and BoringSSL.
* **`TestFIPSServiceIndicator`:** This function looks like it's testing a FIPS (Federal Information Processing Standard) related feature. It seems to be checking if the GCM implementation correctly sets a "service indicator" based on nonce usage, potentially related to security compliance. It uses `fipsaes` and `gcm.NewGCMWithCounterNonce`. The tests involve specific nonce patterns and expectations of panics.
* **`TestGCMForSSH`:**  This test function is specifically designed to test GCM's behavior in the context of SSH (Secure Shell). It includes a function `incIV` (increment Initialization Vector) which is common in SSH protocols. It tests scenarios around IV incrementing and expected panics when certain IV limits are reached.
* **`decodeHex`:** A helper function to decode hexadecimal strings into byte arrays, used for setting up test data.

**3. Inferring the Go Feature:**

The primary Go feature being tested here is the **`crypto/cipher` package's implementation of Galois/Counter Mode (GCM)**, which provides authenticated encryption with associated data. Specifically, the tests cover:

* **Counter Wrapping:** How GCM handles the counter reaching its maximum value.
* **Assembly Optimization:** Comparing the performance and correctness of assembly-optimized GCM against the generic Go version.
* **AEAD Interface Compliance:** Ensuring GCM adheres to the standard `cipher.AEAD` interface.
* **Nonce Handling:** Testing different nonce sizes and the `NewGCMWithRandomNonce` function.
* **Tag Size Flexibility:** Testing non-standard tag sizes.
* **FIPS Compliance:**  Testing a specific behavior related to FIPS certification and nonce usage.
* **SSH Compatibility:** Testing GCM's suitability for use in SSH protocols, particularly around IV handling.

**4. Structuring the Response (Chinese):**

I need to organize the information in a clear and logical way, addressing each point in the user's request. The use of bullet points and code blocks will be helpful.

**5. Handling Assumptions/Inputs/Outputs for Code Inference:**

For `TestGCMCounterWrap`, I can show the input nonces and the expected output tags to demonstrate the counter wrapping behavior. For `TestGCMAsm`, the inputs are randomly generated, but I can highlight the purpose of varying alignment and length. For `TestFIPSServiceIndicator` and `TestGCMForSSH`, the specific nonce values and the expected `true`/`panic` outcomes are the key inputs and outputs to showcase.

**6. Command-Line Arguments:**

Test files in Go typically don't directly involve command-line arguments in the same way as executable programs. The `testing` package handles running the tests. I need to state this explicitly.

**7. Common Mistakes:**

For GCM in general (though not explicitly shown in this *snippet*), common mistakes include nonce reuse. I should mention this as a potential pitfall. The FIPS test also highlights nonce handling constraints.

**8. Part 2 Summary:**

The summary should focus on the collective purpose of these test functions within the broader `gcm_test.go` file, which is to comprehensively test the various aspects of the GCM implementation.

**Final Check:**  Before generating the response, I need to ensure all aspects of the prompt are addressed and the language is accurate and clear in Chinese. The structure should be: 功能列表 -> Go 功能推断及代码示例 -> 代码推理假设及输入输出 -> 命令行参数 -> 易犯错的点 -> 功能归纳.
这是 `go/src/crypto/cipher/gcm_test.go` 文件的一部分，它主要包含了一系列用于测试 Go 语言中 GCM（Galois/Counter Mode）实现的功能。由于这是第 2 部分，我会侧重于归纳这部分代码的功能，并在必要时结合前一部分进行理解。

**功能归纳:**

这部分代码的主要功能是 **对 Go 语言 `crypto/cipher` 包中 GCM 模式的各种场景进行全面的单元测试，以确保其实现的正确性和健壮性**。 具体来说，它涵盖了以下几个关键方面的测试：

1. **GCM 计数器回绕 (Counter Wrap) 的处理:**  `TestGCMCounterWrap` 函数专门测试了当 GCM 内部的计数器达到最大值并回绕时，加密和认证是否仍然能够正确工作。这对于保证长时间或大量数据加密的安全性至关重要。

2. **GCM 的汇编优化实现与通用 Go 实现的对比测试:** `TestGCMAsm` 函数旨在验证 GCM 的汇编优化版本（如果存在）与通用的 Go 实现是否产生相同的结果。这有助于确保性能优化的正确性，并作为一种交叉验证机制。

3. **GCM 作为 `cipher.AEAD` 接口的实现是否符合规范:** `TestGCMAEAD` 函数使用 `cryptotest.TestAEAD` 框架来验证 GCM 实现是否正确地满足了 `cipher.AEAD` 接口的约定。这包括对不同密钥长度、nonce 大小和 tag 大小的测试。

4. **FIPS (联邦信息处理标准) 服务指示器的测试:** `TestFIPSServiceIndicator` 函数针对特定的 FIPS 场景，测试 GCM 实现是否正确地设置了服务指示器。这通常涉及到对 nonce 使用的特定约束和行为的验证。

5. **GCM 在 SSH 协议中的应用场景测试:** `TestGCMForSSH` 函数模拟了 GCM 在 SSH 协议中的使用方式，特别是针对初始化向量 (IV) 的递增和回绕处理进行测试。这确保了 GCM 可以在 SSH 环境中安全可靠地使用。

**更详细的功能描述和代码示例（结合可能的第 1 部分内容）：**

基于这部分代码，我们可以推断出 `gcm_test.go` 的前一部分很可能包含了基础的 GCM 加密解密测试，以及可能与其他 AEAD 模式的通用测试。

**1. GCM 计数器回绕 (Counter Wrap) 的处理:**

* **功能:**  测试当 GCM 内部用于计数的 32 位计数器达到最大值并回绕时，加密过程是否能生成正确的认证标签，并且解密过程是否能成功验证标签。
* **Go 代码示例:**
```go
func testGCMCounterWrap(t *testing.T, newCipher func(key []byte) cipher.Block) {
	tests := []struct {
		nonce, tag string
	}{
		{"0fa72e25", "37e1948cdfff09fbde0c40ad99fee4a7"}, // 假设此 nonce 会导致计数器接近回绕
		// ... 更多的测试用例
	}
	key := newCipher(make([]byte, 16))
	plaintext := make([]byte, 16) // 假设是 16 字节的明文
	for i, test := range tests {
		nonce, _ := hex.DecodeString(test.nonce)
		want, _ := hex.DecodeString(test.tag)
		aead, err := cipher.NewGCMWithNonceSize(key, len(nonce))
		if err != nil {
			t.Fatal(err)
		}
		got := aead.Seal(nil, nonce, plaintext, nil)
		if !bytes.Equal(got[len(plaintext):], want) {
			t.Errorf("test[%v]: got: %x, want: %x", i, got[len(plaintext):], want)
		}
		_, err = aead.Open(nil, nonce, got, nil)
		if err != nil {
			t.Errorf("test[%v]: authentication failed", i)
		}
	}
}
```
* **假设的输入与输出:**  例如，对于 nonce `0fa72e25`，假设内部计数器在加密过程中会递增到接近 32 位最大值并回绕。预期的 tag `37e1948cdfff09fbde0c40ad99fee4a7` 就是在这种回绕情况下计算出来的正确结果。

**2. GCM 的汇编优化实现与通用 Go 实现的对比测试:**

* **功能:** 验证汇编优化版本的 GCM 加密和解密结果与纯 Go 实现的版本是否一致。这有助于发现汇编代码中的错误，并确保性能优化的正确性。
* **Go 代码示例:**
```go
func TestGCMAsm(t *testing.T) {
	newAESGCM := func(key []byte) (asm, generic cipher.AEAD, err error) {
		block, err := aes.NewCipher(key[:])
		if err != nil {
			return nil, nil, err
		}
		asm, err = cipher.NewGCM(block) // 获取汇编优化版本
		if err != nil {
			return nil, nil, err
		}
		generic, err = cipher.NewGCM(wrap(block)) // 获取通用 Go 版本 (wrap 可能是一个禁用汇编优化的包装器)
		if err != nil {
			return nil, nil, err
		}
		return asm, generic, nil
	}

	var key [16]byte
	asm, generic, err := newAESGCM(key[:])
	// ... 省略后续的随机数据生成和加密解密对比
}
```
* **代码推理:** `wrap(block)` 很可能是一个辅助函数，用于创建一个 GCM 对象，但强制使用通用的 Go 实现，而不是潜在的汇编优化版本。通过比较 `asm.Seal` 和 `generic.Seal` 的输出，可以验证两种实现的正确性一致。

**3. GCM 作为 `cipher.AEAD` 接口的实现是否符合规范:**

* **功能:** 使用 `cryptotest` 包提供的工具，自动测试 GCM 实现是否满足 `cipher.AEAD` 接口的所有要求，例如正确的加密、解密和认证行为。
* **Go 代码示例:**
```go
func testGCMAEAD(t *testing.T, newCipher func(key []byte) cipher.Block) {
	cryptotest.TestAEAD(t, func() (cipher.AEAD, error) {
		block := newCipher(make([]byte, 16)) // 使用给定的 cipher.Block 创建 GCM
		return cipher.NewGCM(block)
	})
	// ... 针对不同 nonce 和 tag 大小的测试
}
```
* **命令行参数:**  `cryptotest.TestAEAD` 本身并不直接涉及命令行参数。通常，Go 语言的测试是通过 `go test` 命令运行的，可以通过 `-v` 增加输出详细程度，或者使用 `-run` 指定要运行的测试函数。例如：
    ```bash
    go test -v -run TestGCMAEAD ./crypto/cipher
    ```
    这个命令会运行 `crypto/cipher` 包中名为 `TestGCMAEAD` 的测试函数，并显示详细的输出。

**4. FIPS (联邦信息处理标准) 服务指示器的测试:**

* **功能:**  验证在符合 FIPS 要求的环境中，GCM 实现是否按照规范设置了特定的服务指示器。这通常涉及到对 nonce 的使用方式进行限制。
* **Go 代码示例:**
```go
func TestFIPSServiceIndicator(t *testing.T) {
	newGCM := func() cipher.AEAD {
		key := make([]byte, 16)
		block, _ := fipsaes.New(key) // 使用符合 FIPS 的 AES 实现
		aead, _ := gcm.NewGCMWithCounterNonce(block) // 创建使用计数器 nonce 的 GCM
		return aead
	}
	// ... 后续的 nonce 尝试和断言
}
```
* **代码推理:** `fipsaes.New(key)` 表明这段测试是针对符合 FIPS 140 标准的 AES 实现。`gcm.NewGCMWithCounterNonce`  暗示了 FIPS 模式下可能对 nonce 的生成和使用有特定的要求。测试用例通过尝试不同的 nonce 值，并检查是否触发了服务指示器或导致 panic，来验证这些要求是否被正确实施。

**5. GCM 在 SSH 协议中的应用场景测试:**

* **功能:** 模拟 SSH 协议中使用 GCM 的情况，重点测试初始化向量 (IV) 的递增方式和限制。
* **Go 代码示例:**
```go
func TestGCMForSSH(t *testing.T) {
	incIV := func(iv []byte) { // 模拟 SSH 中 IV 的递增方式
		for i := 4 + 7; i >= 4; i-- {
			iv[i]++
			if iv[i] != 0 {
				break
			}
		}
	}
	// ... 后续的 IV 设置和加密尝试
}
```
* **代码推理:** `incIV` 函数模拟了 SSH 中特定的 IV 递增方式，只递增 IV 的一部分字节。测试用例通过设置不同的 IV 值，并调用 `aead.Seal` 来模拟 SSH 加密过程，并断言在某些 IV 值下是否会发生 panic，这可能与 SSH 协议对 IV 的重用限制有关。

**使用者易犯错的点 (可能在整个 `gcm_test.go` 中体现):**

虽然这部分代码没有直接展示使用者如何错误地使用 GCM，但根据 GCM 的特性和常见的错误，可以推断出一些易犯错的点，这些点可能在 `gcm_test.go` 的其他部分有所体现：

* **Nonce 重用:** 对于同一个密钥，使用相同的 nonce 加密不同的消息是灾难性的，会导致密钥流重用，从而破坏安全性。测试中应该有专门的用例来验证 nonce 重用会导致解密失败或认证失败。
* **Nonce 大小错误:** `cipher.NewGCMWithNonceSize` 允许指定 nonce 的大小，如果使用错误的 nonce 大小进行加密和解密，会导致错误。测试中会覆盖不同 nonce 大小的场景。
* **Tag 截断:** GCM 的认证标签可以截断，但这会降低安全性。测试中可能会验证不同 tag 大小的兼容性，并可能包含警告或错误处理相关的测试。

总而言之，这部分 `gcm_test.go` 代码深入测试了 Go 语言 GCM 实现的各种边界情况和特定场景，确保其在不同环境和使用方式下都能保持安全和正确。

Prompt: 
```
这是路径为go/src/crypto/cipher/gcm_test.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第2部分，共2部分，请归纳一下它的功能

"""
 {
	testAllImplementations(t, testGCMCounterWrap)
}

func testGCMCounterWrap(t *testing.T, newCipher func(key []byte) cipher.Block) {
	// Test that the last 32-bits of the counter wrap correctly.
	tests := []struct {
		nonce, tag string
	}{
		{"0fa72e25", "37e1948cdfff09fbde0c40ad99fee4a7"},   // counter: 7eb59e4d961dad0dfdd75aaffffffff0
		{"afe05cc1", "438f3aa9fee5e54903b1927bca26bbdf"},   // counter: 75d492a7e6e6bfc979ad3a8ffffffff4
		{"9ffecbef", "7b88ca424df9703e9e8611071ec7e16e"},   // counter: c8bb108b0ecdc71747b9d57ffffffff5
		{"ffc3e5b3", "38d49c86e0abe853ac250e66da54c01a"},   // counter: 706414d2de9b36ab3b900a9ffffffff6
		{"cfdd729d", "e08402eaac36a1a402e09b1bd56500e8"},   // counter: cd0b96fe36b04e750584e56ffffffff7
		{"010ae3d486", "5405bb490b1f95d01e2ba735687154bc"}, // counter: e36c18e69406c49722808104fffffff8
		{"01b1107a9d", "939a585f342e01e17844627492d44dbf"}, // counter: e6d56eaf9127912b6d62c6dcffffffff
	}
	key := newCipher(make([]byte, 16))
	plaintext := make([]byte, 16*17+1)
	for i, test := range tests {
		nonce, _ := hex.DecodeString(test.nonce)
		want, _ := hex.DecodeString(test.tag)
		aead, err := cipher.NewGCMWithNonceSize(key, len(nonce))
		if err != nil {
			t.Fatal(err)
		}
		got := aead.Seal(nil, nonce, plaintext, nil)
		if !bytes.Equal(got[len(plaintext):], want) {
			t.Errorf("test[%v]: got: %x, want: %x", i, got[len(plaintext):], want)
		}
		_, err = aead.Open(nil, nonce, got, nil)
		if err != nil {
			t.Errorf("test[%v]: authentication failed", i)
		}
	}
}

func TestGCMAsm(t *testing.T) {
	// Create a new pair of AEADs, one using the assembly implementation
	// and one using the generic Go implementation.
	newAESGCM := func(key []byte) (asm, generic cipher.AEAD, err error) {
		block, err := aes.NewCipher(key[:])
		if err != nil {
			return nil, nil, err
		}
		asm, err = cipher.NewGCM(block)
		if err != nil {
			return nil, nil, err
		}
		generic, err = cipher.NewGCM(wrap(block))
		if err != nil {
			return nil, nil, err
		}
		return asm, generic, nil
	}

	// check for assembly implementation
	var key [16]byte
	asm, generic, err := newAESGCM(key[:])
	if err != nil {
		t.Fatal(err)
	}
	if reflect.TypeOf(asm) == reflect.TypeOf(generic) {
		t.Skipf("no assembly implementation of GCM")
	}

	// generate permutations
	type pair struct{ align, length int }
	lengths := []int{0, 156, 8192, 8193, 8208}
	keySizes := []int{16, 24, 32}
	alignments := []int{0, 1, 2, 3}
	if testing.Short() {
		keySizes = []int{16}
		alignments = []int{1}
	}
	perms := make([]pair, 0)
	for _, l := range lengths {
		for _, a := range alignments {
			if a != 0 && l == 0 {
				continue
			}
			perms = append(perms, pair{align: a, length: l})
		}
	}

	// run test for all permutations
	test := func(ks int, pt, ad []byte) error {
		key := make([]byte, ks)
		if _, err := io.ReadFull(rand.Reader, key); err != nil {
			return err
		}
		asm, generic, err := newAESGCM(key)
		if err != nil {
			return err
		}
		if _, err := io.ReadFull(rand.Reader, pt); err != nil {
			return err
		}
		if _, err := io.ReadFull(rand.Reader, ad); err != nil {
			return err
		}
		nonce := make([]byte, 12)
		if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
			return err
		}
		want := generic.Seal(nil, nonce, pt, ad)
		got := asm.Seal(nil, nonce, pt, ad)
		if !bytes.Equal(want, got) {
			return errors.New("incorrect Seal output")
		}
		got, err = asm.Open(nil, nonce, want, ad)
		if err != nil {
			return errors.New("authentication failed")
		}
		if !bytes.Equal(pt, got) {
			return errors.New("incorrect Open output")
		}
		return nil
	}
	for _, a := range perms {
		ad := make([]byte, a.align+a.length)
		ad = ad[a.align:]
		for _, p := range perms {
			pt := make([]byte, p.align+p.length)
			pt = pt[p.align:]
			for _, ks := range keySizes {
				if err := test(ks, pt, ad); err != nil {
					t.Error(err)
					t.Errorf("	key size: %v", ks)
					t.Errorf("	plaintext alignment: %v", p.align)
					t.Errorf("	plaintext length: %v", p.length)
					t.Errorf("	additionalData alignment: %v", a.align)
					t.Fatalf("	additionalData length: %v", a.length)
				}
			}
		}
	}
}

// Test GCM against the general cipher.AEAD interface tester.
func TestGCMAEAD(t *testing.T) {
	testAllImplementations(t, testGCMAEAD)
}

func testGCMAEAD(t *testing.T, newCipher func(key []byte) cipher.Block) {
	minTagSize := 12

	for _, keySize := range []int{128, 192, 256} {
		// Use AES as underlying block cipher at different key sizes for GCM.
		t.Run(fmt.Sprintf("AES-%d", keySize), func(t *testing.T) {
			rng := newRandReader(t)

			key := make([]byte, keySize/8)
			rng.Read(key)

			block := newCipher(key)

			// Test GCM with the current AES block with the standard nonce and tag
			// sizes.
			cryptotest.TestAEAD(t, func() (cipher.AEAD, error) { return cipher.NewGCM(block) })

			// Test non-standard tag sizes.
			t.Run("MinTagSize", func(t *testing.T) {
				cryptotest.TestAEAD(t, func() (cipher.AEAD, error) { return cipher.NewGCMWithTagSize(block, minTagSize) })
			})

			// Test non-standard nonce sizes.
			for _, nonceSize := range []int{1, 16, 100} {
				t.Run(fmt.Sprintf("NonceSize-%d", nonceSize), func(t *testing.T) {
					cryptotest.TestAEAD(t, func() (cipher.AEAD, error) { return cipher.NewGCMWithNonceSize(block, nonceSize) })
				})
			}

			// Test NewGCMWithRandomNonce.
			t.Run("GCMWithRandomNonce", func(t *testing.T) {
				if _, ok := block.(*wrapper); ok || boring.Enabled {
					t.Skip("NewGCMWithRandomNonce requires an AES block cipher")
				}
				cryptotest.TestAEAD(t, func() (cipher.AEAD, error) { return cipher.NewGCMWithRandomNonce(block) })
			})
		})
	}
}

func TestFIPSServiceIndicator(t *testing.T) {
	newGCM := func() cipher.AEAD {
		key := make([]byte, 16)
		block, _ := fipsaes.New(key)
		aead, _ := gcm.NewGCMWithCounterNonce(block)
		return aead
	}
	tryNonce := func(aead cipher.AEAD, nonce []byte) bool {
		fips140.ResetServiceIndicator()
		aead.Seal(nil, nonce, []byte("x"), nil)
		return fips140.ServiceIndicator()
	}
	expectTrue := func(t *testing.T, aead cipher.AEAD, nonce []byte) {
		t.Helper()
		if !tryNonce(aead, nonce) {
			t.Errorf("expected service indicator true for %x", nonce)
		}
	}
	expectPanic := func(t *testing.T, aead cipher.AEAD, nonce []byte) {
		t.Helper()
		defer func() {
			t.Helper()
			if recover() == nil {
				t.Errorf("expected panic for %x", nonce)
			}
		}()
		tryNonce(aead, nonce)
	}

	g := newGCM()
	expectTrue(t, g, []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0})
	expectTrue(t, g, []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1})
	expectTrue(t, g, []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 100})
	expectTrue(t, g, []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0})
	expectTrue(t, g, []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0})
	expectTrue(t, g, []byte{0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0})
	expectTrue(t, g, []byte{0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0})
	expectTrue(t, g, []byte{0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0})
	expectTrue(t, g, []byte{0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0})
	expectTrue(t, g, []byte{0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0})
	// Changed name.
	expectPanic(t, g, []byte{0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0})

	g = newGCM()
	expectTrue(t, g, []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1})
	// Went down.
	expectPanic(t, g, []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0})

	g = newGCM()
	expectTrue(t, g, []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12})
	expectTrue(t, g, []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 13})
	// Did not increment.
	expectPanic(t, g, []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 13})

	g = newGCM()
	expectTrue(t, g, []byte{1, 2, 3, 4, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00})
	expectTrue(t, g, []byte{1, 2, 3, 4, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff})
	// Wrap is ok as long as we don't run out of values.
	expectTrue(t, g, []byte{1, 2, 3, 4, 0, 0, 0, 0, 0, 0, 0, 0})
	expectTrue(t, g, []byte{1, 2, 3, 4, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe, 0xfe})
	// Run out of counters.
	expectPanic(t, g, []byte{1, 2, 3, 4, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe, 0xff})

	g = newGCM()
	expectTrue(t, g, []byte{1, 2, 3, 4, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff})
	// Wrap with overflow.
	expectPanic(t, g, []byte{1, 2, 3, 5, 0, 0, 0, 0, 0, 0, 0, 0})
}

func TestGCMForSSH(t *testing.T) {
	// incIV from x/crypto/ssh/cipher.go.
	incIV := func(iv []byte) {
		for i := 4 + 7; i >= 4; i-- {
			iv[i]++
			if iv[i] != 0 {
				break
			}
		}
	}

	expectOK := func(aead cipher.AEAD, iv []byte) {
		aead.Seal(nil, iv, []byte("hello, world"), nil)
	}

	expectPanic := func(aead cipher.AEAD, iv []byte) {
		defer func() {
			if recover() == nil {
				t.Errorf("expected panic")
			}
		}()
		aead.Seal(nil, iv, []byte("hello, world"), nil)
	}

	key := make([]byte, 16)
	block, _ := fipsaes.New(key)
	aead, err := gcm.NewGCMForSSH(block)
	if err != nil {
		t.Fatal(err)
	}
	iv := decodeHex(t, "11223344"+"0000000000000000")
	expectOK(aead, iv)
	incIV(iv)
	expectOK(aead, iv)
	iv = decodeHex(t, "11223344"+"fffffffffffffffe")
	expectOK(aead, iv)
	incIV(iv)
	expectPanic(aead, iv)

	aead, _ = gcm.NewGCMForSSH(block)
	iv = decodeHex(t, "11223344"+"fffffffffffffffe")
	expectOK(aead, iv)
	incIV(iv)
	expectOK(aead, iv)
	incIV(iv)
	expectOK(aead, iv)
	incIV(iv)
	expectOK(aead, iv)

	aead, _ = gcm.NewGCMForSSH(block)
	iv = decodeHex(t, "11223344"+"aaaaaaaaaaaaaaaa")
	expectOK(aead, iv)
	iv = decodeHex(t, "11223344"+"ffffffffffffffff")
	expectOK(aead, iv)
	incIV(iv)
	expectOK(aead, iv)
	iv = decodeHex(t, "11223344"+"aaaaaaaaaaaaaaa8")
	expectOK(aead, iv)
	incIV(iv)
	expectPanic(aead, iv)
	iv = decodeHex(t, "11223344"+"bbbbbbbbbbbbbbbb")
	expectPanic(aead, iv)
}

func decodeHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

"""




```