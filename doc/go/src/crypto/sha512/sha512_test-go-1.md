Response:
Let's break down the thought process for answering this multi-part question about the provided Go code snippet.

**1. Understanding the Request:**

The core request is to analyze a snippet of Go test code (`go/src/crypto/sha512/sha512_test.go`) and infer its functionality. The prompt also has specific constraints:

* **Function Listing:** Enumerate the functions.
* **Go Feature Identification:**  Infer what Go language feature is being tested.
* **Code Example:** Provide a Go code example illustrating the feature.
* **Input/Output for Code:** If providing a code example, include assumed input and output.
* **Command-Line Arguments:** Explain any command-line arguments (though none are present in this snippet).
* **Common Mistakes:** Identify potential errors users might make (not applicable here).
* **Language:**  Respond in Chinese.
* **Part Number:** Acknowledge it's part 2 of 4.
* **Summary:**  Provide a concise summary of the functionality.

**2. Initial Code Examination:**

The provided code consists of two Go slices of structs: `golden` and `golden384`. Each struct in these slices has three fields: a string representing a hash, a string representing the input, and a string that appears to be a combination of a prefix ("sha\x06\"1!" or "sha\x04˻\x9d]") followed by the input and some trailing null bytes and a length indicator.

**3. Inferring the Functionality:**

* **File Path:** The file path `go/src/crypto/sha512/sha512_test.go` strongly suggests this code is related to testing the SHA-512 cryptographic hash function. The "sha512" part is a dead giveaway.
* **Data Structure:** The `sha512Test` struct clearly defines test cases. It contains the expected hash output (`sum`), the input string (`in`), and a `SBOX` field which is likely used for a specific internal testing purpose related to the SHA-512 algorithm.
* **Slice Names:** The names `golden` and `golden384` suggest pre-computed, correct hash values (golden values) for SHA-512 and SHA-384, respectively. SHA-384 is a variant of SHA-512, which explains why it's in the same test file.
* **SBOX Field:** The `SBOX` field's content is more complex. The prefix "sha\x06\"1!" looks like a magic number or version indicator. The input string is present within it. The trailing null bytes and the final byte seem to indicate padding and possibly the length of the original input. This suggests a test for the internal S-box transformation or a specific implementation detail of the SHA algorithm.

**4. Identifying the Go Feature:**

This code is clearly testing the implementation of the SHA-512 and SHA-384 hash algorithms in the `crypto/sha512` package. The use of a slice of structs to hold test cases is a common practice in Go testing.

**5. Constructing the Go Code Example:**

To demonstrate the SHA-512 functionality, a simple Go program that calculates the SHA-512 hash of a string is needed. This involves importing the `crypto/sha512` and `fmt` packages, creating a string, calculating its SHA-512 hash using `sha512.Sum512`, and then formatting the result.

* **Input/Output for the Example:** Choose a simple input string (e.g., "hello") and manually calculate its SHA-512 hash or look up a known value to use as the expected output.

**6. Addressing Other Points:**

* **Command-Line Arguments:**  This code snippet doesn't process command-line arguments. State this explicitly.
* **Common Mistakes:**  Since this is a test file, common user errors are less relevant. If this were the actual SHA-512 implementation, potential mistakes like using the wrong hash size or not handling errors would be mentioned. Since it's a test, no specific user-error example is really needed.
* **Language:** Ensure the entire response is in Chinese.
* **Part Number:** Acknowledge that this is part 2.

**7. Summarizing the Functionality:**

The summary should be a concise statement of what the provided code does. It tests the SHA-512 and SHA-384 hash algorithms against known input-output pairs.

**8. Review and Refine:**

Read through the entire response to ensure accuracy, clarity, and completeness, addressing all parts of the prompt. Ensure the Chinese is grammatically correct and natural-sounding. Specifically double-check the hex representations and make sure they match the data in the snippet.

**Self-Correction Example During Thought Process:**

Initially, one might focus solely on the `golden` slice and assume it's just testing basic SHA-512. However, noticing the `golden384` slice and the slight difference in the `SBOX` prefix indicates that it's also testing SHA-384. The `SBOX` field is not immediately obvious, but by looking at the structure (prefix, input, padding, length), a reasonable inference can be made about its purpose in testing internal implementation details. It's important not to just say "it's some internal data" but to try and deduce its role.
好的，让我们来归纳一下这段Go语言测试代码的功能。

**功能归纳：**

这段代码定义了一系列用于测试 Go 语言 `crypto/sha512` 包中 SHA-512 和 SHA-384 哈希算法实现的数据。具体来说，它包含了两个预定义的“黄金”测试用例数据集：

* **`golden`:**  用于测试 SHA-512 算法。
* **`golden384`:** 用于测试 SHA-384 算法。

每个测试用例都包含以下信息：

* **`sum` (哈希值):**  预先计算好的，对应特定输入数据的 SHA-512 或 SHA-384 哈希值的十六进制字符串表示。
* **`in` (输入):** 用于生成哈希值的原始字符串输入。
* **`SBOX`:**  这是一个比较复杂的字段，它似乎是为了测试 SHA 算法实现的**内部状态**或**中间步骤**而设计的。  它可能包含了特定的魔数（如 "sha\x06\"1!" 或 "sha\x04˻\x9d]"），原始输入的一部分，以及填充数据和长度信息。

**总而言之，这段代码的主要功能是提供了一组预定义的输入和期望的输出（包括最终哈希值和某种中间状态表示），用于验证 `crypto/sha512` 包中 SHA-512 和 SHA-384 算法实现的正确性。**

**它测试了以下几个方面 (推测)：**

1. **基本哈希生成：** 验证对于给定的输入，算法能否生成正确的 SHA-512 和 SHA-384 哈希值。
2. **特定内部状态/步骤：**  通过 `SBOX` 字段，可能用于验证算法在处理输入过程中，内部的特定状态或者转换步骤是否符合预期。这是一种更细粒度的测试，可以帮助发现算法实现中的潜在问题，即使最终的哈希值是正确的。

在接下来的部分，可能会有使用这些 `golden` 和 `golden384` 数据集的测试函数，来驱动实际的 SHA-512 和 SHA-384 计算并与预期结果进行比较。

### 提示词
```
这是路径为go/src/crypto/sha512/sha512_test.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第2部分，共4部分，请归纳一下它的功能
```

### 源代码
```go
x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x05",
	},
	{
		"690c8ad3916cefd3ad29226d9875965e3ee9ec0d4482eacc248f2ff4aa0d8e5b",
		"Discard medicine more than two years old.",
		"sha\x06\"1!\x94\xfc+\xf7,\x9fU_\xa3\xc8Ld\xc2#\x93\xb8koS\xb1Q\x968w\x19Y@꽖(>⨎\xff\xe3\xbe^\x1e%S\x869\x92+\x01\x99\xfc,\x85\xb8\xaa\x0e\xb7-܁\xc5,\xa2Discard medicine mor\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x14",
	},
	{
		"25938ca49f7ef1178ce81620842b65e576245fcaed86026a36b516b80bb86b3b",
		"He who has a shady past knows that nice guys finish last.",
		"sha\x06\"1!\x94\xfc+\xf7,\x9fU_\xa3\xc8Ld\xc2#\x93\xb8koS\xb1Q\x968w\x19Y@꽖(>⨎\xff\xe3\xbe^\x1e%S\x869\x92+\x01\x99\xfc,\x85\xb8\xaa\x0e\xb7-܁\xc5,\xa2He who has a shady past know\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x1c",
	},
	{
		"698e420c3a7038e53d8e73f4be2b02e03b93464ac1a61ebe69f557079921ef65",
		"I wouldn't marry him with a ten foot pole.",
		"sha\x06\"1!\x94\xfc+\xf7,\x9fU_\xa3\xc8Ld\xc2#\x93\xb8koS\xb1Q\x968w\x19Y@꽖(>⨎\xff\xe3\xbe^\x1e%S\x869\x92+\x01\x99\xfc,\x85\xb8\xaa\x0e\xb7-܁\xc5,\xa2I wouldn't marry him \x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x15",
	},
	{
		"839b414d7e3900ee243aa3d1f9b6955720e64041f5ab9bedd3eb0a08da5a2ca8",
		"Free! Free!/A trip/to Mars/for 900/empty jars/Burma Shave",
		"sha\x06\"1!\x94\xfc+\xf7,\x9fU_\xa3\xc8Ld\xc2#\x93\xb8koS\xb1Q\x968w\x19Y@꽖(>⨎\xff\xe3\xbe^\x1e%S\x869\x92+\x01\x99\xfc,\x85\xb8\xaa\x0e\xb7-܁\xc5,\xa2Free! Free!/A trip/to Mars/f\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x1c",
	},
	{
		"5625ecb9d284e54c00b257b67a8cacb25a78db2845c60ef2d29e43c84f236e8e",
		"The days of the digital watch are numbered.  -Tom Stoppard",
		"sha\x06\"1!\x94\xfc+\xf7,\x9fU_\xa3\xc8Ld\xc2#\x93\xb8koS\xb1Q\x968w\x19Y@꽖(>⨎\xff\xe3\xbe^\x1e%S\x869\x92+\x01\x99\xfc,\x85\xb8\xaa\x0e\xb7-܁\xc5,\xa2The days of the digital watch\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x1d",
	},
	{
		"9b81d06bca2f985e6ad3249096ff3c0f2a9ec5bb16ef530d738d19d81e7806f2",
		"Nepal premier won't resign.",
		"sha\x06\"1!\x94\xfc+\xf7,\x9fU_\xa3\xc8Ld\xc2#\x93\xb8koS\xb1Q\x968w\x19Y@꽖(>⨎\xff\xe3\xbe^\x1e%S\x869\x92+\x01\x99\xfc,\x85\xb8\xaa\x0e\xb7-܁\xc5,\xa2Nepal premier\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\r",
	},
	{
		"08241df8d91edfcd68bb1a1dada6e0ae1475a5c6e7b8f12d8e24ca43a38240a9",
		"For every action there is an equal and opposite government program.",
		"sha\x06\"1!\x94\xfc+\xf7,\x9fU_\xa3\xc8Ld\xc2#\x93\xb8koS\xb1Q\x968w\x19Y@꽖(>⨎\xff\xe3\xbe^\x1e%S\x869\x92+\x01\x99\xfc,\x85\xb8\xaa\x0e\xb7-܁\xc5,\xa2For every action there is an equa\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00!",
	},
	{
		"4ff74d9213a8117745f5d37b5353a774ec81c5dfe65c4c8986a56fc01f2c551e",
		"His money is twice tainted: 'taint yours and 'taint mine.",
		"sha\x06\"1!\x94\xfc+\xf7,\x9fU_\xa3\xc8Ld\xc2#\x93\xb8koS\xb1Q\x968w\x19Y@꽖(>⨎\xff\xe3\xbe^\x1e%S\x869\x92+\x01\x99\xfc,\x85\xb8\xaa\x0e\xb7-܁\xc5,\xa2His money is twice tainted: \x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x1c",
	},
	{
		"b5baf747c307f98849ec881cf0d48605ae4edd386372aea9b26e71db517e650b",
		"There is no reason for any individual to have a computer in their home. -Ken Olsen, 1977",
		"sha\x06\"1!\x94\xfc+\xf7,\x9fU_\xa3\xc8Ld\xc2#\x93\xb8koS\xb1Q\x968w\x19Y@꽖(>⨎\xff\xe3\xbe^\x1e%S\x869\x92+\x01\x99\xfc,\x85\xb8\xaa\x0e\xb7-܁\xc5,\xa2There is no reason for any individual to hav\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00,",
	},
	{
		"7eef0538ebd7ecf18611d23b0e1cd26a74d65b929a2e374197dc66e755ca4944",
		"It's a tiny change to the code and not completely disgusting. - Bob Manchek",
		"sha\x06\"1!\x94\xfc+\xf7,\x9fU_\xa3\xc8Ld\xc2#\x93\xb8koS\xb1Q\x968w\x19Y@꽖(>⨎\xff\xe3\xbe^\x1e%S\x869\x92+\x01\x99\xfc,\x85\xb8\xaa\x0e\xb7-܁\xc5,\xa2It's a tiny change to the code and no\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00%",
	},
	{
		"d05600964f83f55323104aadab434f32391c029718a7690d08ddb2d7e8708443",
		"size:  a.out:  bad magic",
		"sha\x06\"1!\x94\xfc+\xf7,\x9fU_\xa3\xc8Ld\xc2#\x93\xb8koS\xb1Q\x968w\x19Y@꽖(>⨎\xff\xe3\xbe^\x1e%S\x869\x92+\x01\x99\xfc,\x85\xb8\xaa\x0e\xb7-܁\xc5,\xa2size:  a.out\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\f",
	},
	{
		"53ed5f9b5c0b674ac0f3425d9f9a5d462655b07cc90f5d0f692eec093884a607",
		"The major problem is with sendmail.  -Mark Horton",
		"sha\x06\"1!\x94\xfc+\xf7,\x9fU_\xa3\xc8Ld\xc2#\x93\xb8koS\xb1Q\x968w\x19Y@꽖(>⨎\xff\xe3\xbe^\x1e%S\x869\x92+\x01\x99\xfc,\x85\xb8\xaa\x0e\xb7-܁\xc5,\xa2The major problem is wit\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x18",
	},
	{
		"5a0147685a44eea2435dbd582724efca7637acd9c428e5e1a05115bc3bc2a0e0",
		"Give me a rock, paper and scissors and I will move the world.  CCFestoon",
		"sha\x06\"1!\x94\xfc+\xf7,\x9fU_\xa3\xc8Ld\xc2#\x93\xb8koS\xb1Q\x968w\x19Y@꽖(>⨎\xff\xe3\xbe^\x1e%S\x869\x92+\x01\x99\xfc,\x85\xb8\xaa\x0e\xb7-܁\xc5,\xa2Give me a rock, paper and scissors a\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00$",
	},
	{
		"1152c9b27a99dbf4057d21438f4e63dd0cd0977d5ff12317c64d3b97fcac875a",
		"If the enemy is within range, then so are you.",
		"sha\x06\"1!\x94\xfc+\xf7,\x9fU_\xa3\xc8Ld\xc2#\x93\xb8koS\xb1Q\x968w\x19Y@꽖(>⨎\xff\xe3\xbe^\x1e%S\x869\x92+\x01\x99\xfc,\x85\xb8\xaa\x0e\xb7-܁\xc5,\xa2If the enemy is within \x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x17",
	},
	{
		"105e890f5d5cf1748d9a7b4cdaf58b69855779deebc2097747c2210a17b2cb51",
		"It's well we cannot hear the screams/That we create in others' dreams.",
		"sha\x06\"1!\x94\xfc+\xf7,\x9fU_\xa3\xc8Ld\xc2#\x93\xb8koS\xb1Q\x968w\x19Y@꽖(>⨎\xff\xe3\xbe^\x1e%S\x869\x92+\x01\x99\xfc,\x85\xb8\xaa\x0e\xb7-܁\xc5,\xa2It's well we cannot hear the scream\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00#",
	},
	{
		"74644ead770da1434365cd912656fe1aca2056d3039d39f10eb1151bddb32cf3",
		"You remind me of a TV show, but that's all right: I watch it anyway.",
		"sha\x06\"1!\x94\xfc+\xf7,\x9fU_\xa3\xc8Ld\xc2#\x93\xb8koS\xb1Q\x968w\x19Y@꽖(>⨎\xff\xe3\xbe^\x1e%S\x869\x92+\x01\x99\xfc,\x85\xb8\xaa\x0e\xb7-܁\xc5,\xa2You remind me of a TV show, but th\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\"",
	},
	{
		"50a234625de5587581883dad9ef399460928032a5ea6bd005d7dc7b68d8cc3d6",
		"C is as portable as Stonehedge!!",
		"sha\x06\"1!\x94\xfc+\xf7,\x9fU_\xa3\xc8Ld\xc2#\x93\xb8koS\xb1Q\x968w\x19Y@꽖(>⨎\xff\xe3\xbe^\x1e%S\x869\x92+\x01\x99\xfc,\x85\xb8\xaa\x0e\xb7-܁\xc5,\xa2C is as portable\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x10",
	},
	{
		"a7a3846005f8a9935a0a2d43e7fd56d95132a9a3609bf3296ef80b8218acffa0",
		"Even if I could be Shakespeare, I think I should still choose to be Faraday. - A. Huxley",
		"sha\x06\"1!\x94\xfc+\xf7,\x9fU_\xa3\xc8Ld\xc2#\x93\xb8koS\xb1Q\x968w\x19Y@꽖(>⨎\xff\xe3\xbe^\x1e%S\x869\x92+\x01\x99\xfc,\x85\xb8\xaa\x0e\xb7-܁\xc5,\xa2Even if I could be Shakespeare, I think I sh\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00,",
	},
	{
		"688ff03e367680757aa9906cb1e2ad218c51f4526dc0426ea229a5ba9d002c69",
		"The fugacity of a constituent in a mixture of gases at a given temperature is proportional to its mole fraction.  Lewis-Randall Rule",
		"sha\x06\"1!\x94\xfc+\xf7,\x9fU_\xa3\xc8Ld\xc2#\x93\xb8koS\xb1Q\x968w\x19Y@꽖(>⨎\xff\xe3\xbe^\x1e%S\x869\x92+\x01\x99\xfc,\x85\xb8\xaa\x0e\xb7-܁\xc5,\xa2The fugacity of a constituent in a mixture of gases at a given tem\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00B",
	},
	{
		"3fa46d52094b01021cff5af9a438982b887a5793f624c0a6644149b6b7c3f485",
		"How can you write a big system without C++?  -Paul Glick",
		"sha\x06\"1!\x94\xfc+\xf7,\x9fU_\xa3\xc8Ld\xc2#\x93\xb8koS\xb1Q\x968w\x19Y@꽖(>⨎\xff\xe3\xbe^\x1e%S\x869\x92+\x01\x99\xfc,\x85\xb8\xaa\x0e\xb7-܁\xc5,\xa2How can you write a big syst\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x1c",
	},
}

var golden384 = []sha512Test{
	{
		"38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b",
		"",
		"sha\x04˻\x9d]\xc1\x05\x9e\xd8b\x9a)*6|\xd5\a\x91Y\x01Z0p\xdd\x17\x15/\xec\xd8\xf7\x0eY9g3&g\xff\xc0\v1\x8e\xb4J\x87hX\x15\x11\xdb\f.\rd\xf9\x8f\xa7G\xb5H\x1d\xbe\xfaO\xa4\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
	},
	{
		"54a59b9f22b0b80880d8427e548b7c23abd873486e1f035dce9cd697e85175033caa88e6d57bc35efae0b5afd3145f31",
		"a",
		"sha\x04˻\x9d]\xc1\x05\x9e\xd8b\x9a)*6|\xd5\a\x91Y\x01Z0p\xdd\x17\x15/\xec\xd8\xf7\x0eY9g3&g\xff\xc0\v1\x8e\xb4J\x87hX\x15\x11\xdb\f.\rd\xf9\x8f\xa7G\xb5H\x1d\xbe\xfaO\xa4\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
	},
	{
		"c7be03ba5bcaa384727076db0018e99248e1a6e8bd1b9ef58a9ec9dd4eeebb3f48b836201221175befa74ddc3d35afdd",
		"ab",
		"sha\x04˻\x9d]\xc1\x05\x9e\xd8b\x9a)*6|\xd5\a\x91Y\x01Z0p\xdd\x17\x15/\xec\xd8\xf7\x0eY9g3&g\xff\xc0\v1\x8e\xb4J\x87hX\x15\x11\xdb\f.\rd\xf9\x8f\xa7G\xb5H\x1d\xbe\xfaO\xa4a\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01",
	},
	{
		"cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7",
		"abc",
		"sha\x04˻\x9d]\xc1\x05\x9e\xd8b\x9a)*6|\xd5\a\x91Y\x01Z0p\xdd\x17\x15/\xec\xd8\xf7\x0eY9g3&g\xff\xc0\v1\x8e\xb4J\x87hX\x15\x11\xdb\f.\rd\xf9\x8f\xa7G\xb5H\x1d\xbe\xfaO\xa4a\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01",
	},
	{
		"1165b3406ff0b52a3d24721f785462ca2276c9f454a116c2b2ba20171a7905ea5a026682eb659c4d5f115c363aa3c79b",
		"abcd",
		"sha\x04˻\x9d]\xc1\x05\x9e\xd8b\x9a)*6|\xd5\a\x91Y\x01Z0p\xdd\x17\x15/\xec\xd8\xf7\x0eY9g3&g\xff\xc0\v1\x8e\xb4J\x87hX\x15\x11\xdb\f.\rd\xf9\x8f\xa7G\xb5H\x1d\xbe\xfaO\xa4ab\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02",
	},
	{
		"4c525cbeac729eaf4b4665815bc5db0c84fe6300068a727cf74e2813521565abc0ec57a37ee4d8be89d097c0d2ad52f0",
		"abcde",
		"sha\x04˻\x9d]\xc1\x05\x9e\xd8b\x9a)*6|\xd5\a\x91Y\x01Z0p\xdd\x17\x15/\xec\xd8\xf7\x0eY9g3&g\xff\xc0\v1\x8e\xb4J\x87hX\x15\x11\xdb\f.\rd\xf9\x8f\xa7G\xb5H\x1d\xbe\xfaO\xa4ab\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02",
	},
	{
		"c6a4c65b227e7387b9c3e839d44869c4cfca3ef583dea64117859b808c1e3d8ae689e1e314eeef52a6ffe22681aa11f5",
		"abcdef",
		"sha\x04˻\x9d]\xc1\x05\x9e\xd8b\x9a)*6|\xd5\a\x91Y\x01Z0p\xdd\x17\x15/\xec\xd8\xf7\x0eY9g3&g\xff\xc0\v1\x8e\xb4J\x87hX\x15\x11\xdb\f.\rd\xf9\x8f\xa7G\xb5H\x1d\xbe\xfaO\xa4abc\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x03",
	},
	{
		"9f11fc131123f844c1226f429b6a0a6af0525d9f40f056c7fc16cdf1b06bda08e302554417a59fa7dcf6247421959d22",
		"abcdefg",
		"sha\x04˻\x9d]\xc1\x05\x9e\xd8b\x9a)*6|\xd5\a\x91Y\x01Z0p\xdd\x17\x15/\xec\xd8\xf7\x0eY9g3&g\xff\xc0\v1\x8e\xb4J\x87hX\x15\x11\xdb\f.\rd\xf9\x8f\xa7G\xb5H\x1d\xbe\xfaO\xa4abc\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x03",
	},
	{
		"9000cd7cada59d1d2eb82912f7f24e5e69cc5517f68283b005fa27c285b61e05edf1ad1a8a9bded6fd29eb87d75ad806",
		"abcdefgh",
		"sha\x04˻\x9d]\xc1\x05\x9e\xd8b\x9a)*6|\xd5\a\x91Y\x01Z0p\xdd\x17\x15/\xec\xd8\xf7\x0eY9g3&g\xff\xc0\v1\x8e\xb4J\x87hX\x15\x11\xdb\f.\rd\xf9\x8f\xa7G\xb5H\x1d\xbe\xfaO\xa4abcd\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x04",
	},
	{
		"ef54915b60cf062b8dd0c29ae3cad69abe6310de63ac081f46ef019c5c90897caefd79b796cfa81139788a260ded52df",
		"abcdefghi",
		"sha\x04˻\x9d]\xc1\x05\x9e\xd8b\x9a)*6|\xd5\a\x91Y\x01Z0p\xdd\x17\x15/\xec\xd8\xf7\x0eY9g3&g\xff\xc0\v1\x8e\xb4J\x87hX\x15\x11\xdb\f.\rd\xf9\x8f\xa7G\xb5H\x1d\xbe\xfaO\xa4abcd\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x04",
	},
	{
		"a12070030a02d86b0ddacd0d3a5b598344513d0a051e7355053e556a0055489c1555399b03342845c4adde2dc44ff66c",
		"abcdefghij",
		"sha\x04˻\x9d]\xc1\x05\x9e\xd8b\x9a)*6|\xd5\a\x91Y\x01Z0p\xdd\x17\x15/\xec\xd8\xf7\x0eY9g3&g\xff\xc0\v1\x8e\xb4J\x87hX\x15\x11\xdb\f.\rd\xf9\x8f\xa7G\xb5H\x1d\xbe\xfaO\xa4abcde\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x05",
	},
	{
		"86f58ec2d74d1b7f8eb0c2ff0967316699639e8d4eb129de54bdf34c96cdbabe200d052149f2dd787f43571ba74670d4",
		"Discard medicine more than two years old.",
		"sha\x04˻\x9d]\xc1\x05\x9e\xd8b\x9a)*6|\xd5\a\x91Y\x01Z0p\xdd\x17\x15/\xec\xd8\xf7\x0eY9g3&g\xff\xc0\v1\x8e\xb4J\x87hX\x15\x11\xdb\f.\rd\xf9\x8f\xa7G\xb5H\x1d\xbe\xfaO\xa4Discard medicine mor\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x14",
	},
	{
		"ae4a2b639ca9bfa04b1855d5a05fe7f230994f790891c6979103e2605f660c4c1262a48142dcbeb57a1914ba5f7c3fa7",
		"He who has a shady past knows that nice guys finish last.",
		"sha\x04˻\x9d]\xc1\x05\x9e\xd8b\x9a)*6|\xd5\a\x91Y\x01Z0p\xdd\x17\x15/\xec\xd8\xf7\x0eY9g3&g\xff\xc0\v1\x8e\xb4J\x87hX\x15\x11\xdb\f.\rd\xf9\x8f\xa7G\xb5H\x1d\xbe\xfaO\xa4He who has a shady past know\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x1c",
	},
	{
		"40ae213df6436eca952aa6841886fcdb82908ef1576a99c8f49bb9dd5023169f7c53035abdda0b54c302f4974e2105e7",
		"I wouldn't marry him with a ten foot pole.",
		"sha\x04˻\x9d]\xc1\x05\x9e\xd8b\x9a)*6|\xd5\a\x91Y\x01Z0p\xdd\x17\x15/\xec\xd8\xf7\x0eY9g3&g\xff\xc0\v1\x8e\xb4J\x87hX\x15\x11\xdb\f.\rd\xf9\x8f\xa7G\xb5H\x1d\xbe\xfaO\xa4I wouldn't marry him \x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x15",
	},
	{
		"e7cf8b873c9bc950f06259aa54309f349cefa72c00d597aebf903e6519a50011dfe355afff064a10701c705693848df9",
		"Free! Free!/A trip/to Mars/for 900/empty jars/Burma Shave",
		"sha\x04˻\x9d]\xc1\x05\x9e\xd8b\x9a)*6|\xd5\a\x91Y\x01Z0p\xdd\x17\x15/\xec\xd8\xf7\x0eY9g3&g\xff\xc0\v1\x8e\xb4J\x87hX\x15\x11\xdb\f.\rd\xf9\x8f\xa7G\xb5H\x1d\xbe\xfaO\xa4Free! Free!/A trip/to Mars/f\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x1c",
	},
	{
		"c3d4f0f4047181c7d39d34703365f7bf70207183caf2c2f6145f04da895ef69124d9cdeb635da636c3a474e61024e29b",
		"The days of the digital watch are numbered.  -Tom Stoppard",
		"sha\x04˻\x9d]\xc1\x05\x9e\xd8b\x9a)*6|\xd5\a\x91Y\x01Z0p\xdd\x17\x15/\xec\xd8\xf7\x0eY9g3&g\xff\xc0\v1\x8e\xb4J\x87hX\x15\x11\xdb\f.\rd\xf9\x8f\xa7G\xb5H\x1d\xbe\xfaO\xa4The days of the digital watch\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x1d",
	},
	{
		"a097aab567e167d5cf93676ed73252a69f9687cb3179bb2d27c9878119e94bf7b7c4b58dc90582edfaf66e11388ed714",
		"Nepal premier won't resign.",
		"sha\x04˻\x9d]\xc1\x05\x9e\xd8b\x9a)*6|\xd5\a\x91Y\x01Z0p\xdd\x17\x15/\xec\xd8\xf7\x0eY9g3&g\xff\xc0\v1\x8e\xb4J\x87hX\x15\x11\xdb\f.\rd\xf9\x8f\xa7G\xb5H\x1d\xbe\xfaO\xa4Nepal premier\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\r",
	},
	{
		"5026ca45c41fc64712eb65065da92f6467541c78f8966d3fe2c8e3fb769a3ec14215f819654b47bd64f7f0eac17184f3",
		"For every action there is an equal and opposite government program.",
		"sha\x04˻\x9d]\xc1\x05\x9e\xd8b\x9a)*6|\xd5\a\x91Y\x01Z0p\xdd\x17\x15/\xec\xd8\xf7\x0eY9g3&g\xff\xc0\v1\x8e\xb4J\x87hX\x15\x11\xdb\f.\rd\xf9\x8f\xa7G\xb5H\x1d\xbe\xfaO\xa4For every action there is an equa\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00!",
	},
	{
		"ac1cc0f5ac8d5f5514a7b738ac322b7fb52a161b449c3672e9b6a6ad1a5e4b26b001cf3bad24c56598676ca17d4b445a",
		"His money is twice tainted: 'taint yours and 'taint mine.",
		"sha\x04˻\x9d]\xc1\x05\x9e\xd8b\x9a)*6|\xd5\a\x91Y\x01Z0p\xdd\x17\x15/\xec\xd8\xf7\x0eY9g3&g\xff\xc0\v1\x8e\xb4J\x87hX\x15\x11\xdb\f.\rd\xf9\x8f\xa7G\xb5H\x1d\xbe\xfaO\xa4His money is twice tainted: \x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x1c",
	},
	{
		"722d10c5de371ec0c8c4b5247ac8a5f1d240d68c73f8da13d8b25f0166d6f309bf9561979a111a0049405771d201941a",
		"There is no reason for any individual to have a computer in their home. -Ken Olsen, 1977",
		"sha\x04˻\x9d]\xc1\x05\x9e\xd8b\x9a)*6|\xd5\a\x91Y\x01Z0p\xdd\x17\x15/\xec\xd8\xf7\x0eY9g3&g\xff\xc0\v1\x8e\xb4J\x87hX\x15\x11\xdb\f.\rd\xf9\x8f\xa7G\xb5H\x1d\xbe\xfaO\xa4There is no reason for any individual to hav\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00,",
	},
	{
		"dc2d3ea18bfa10549c63bf2b75b39b5167a80c12aff0e05443168ea87ff149fb0eda5e0bd234eb5d48c7d02ffc5807f1",
		"It's a tiny change to the code and not completely disgusting. - Bob Manchek",
		"sha\x04˻\x9d]\xc1\x05\x9e\xd8b\x9a)*6|\xd5\a\x91Y\x01Z0p\xdd\x17\x15/\xec\xd8\xf7\x0eY9g3&g\xff\xc0\v1\x8e\xb4J\x87hX\x15\x11\xdb\f.\rd\xf9\x8f\xa7G\xb5H\x1d\xbe\xfaO\xa4It's a tiny change to the code and no\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\
```