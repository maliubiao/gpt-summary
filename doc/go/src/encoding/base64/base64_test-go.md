Response:
Let's break down the thought process for analyzing this Go code snippet for `base64_test.go`.

1. **Identify the Core Purpose:** The filename `base64_test.go` immediately signals that this code is for *testing* the `encoding/base64` package in Go. Therefore, its primary function is to verify the correctness of base64 encoding and decoding implementations.

2. **Examine the Imports:** The `import` statements provide clues about the functionalities being tested and the tools used for testing:
    * `"bytes"`:  Likely used for comparing byte slices, which is common in encoding/decoding tests.
    * `"errors"`: Used for creating and checking errors, important for verifying error handling in the base64 implementation.
    * `"fmt"`: For formatting output in test messages (e.g., using `Errorf`).
    * `"io"`:  Indicates testing of input/output operations, which are relevant to `Encoder` and `Decoder`.
    * `"math"`: Might be used for edge cases or boundary testing, perhaps related to the length of input/output.
    * `"reflect"`:  Used for deep equality checks (`reflect.DeepEqual`), often necessary for comparing complex data structures or errors.
    * `"runtime/debug"`: Suggests that the tests might involve checking for panics or recovering from them.
    * `"strconv"`: Likely used for converting numbers to strings, possibly for handling sizes or lengths.
    * `"strings"`:  Used for string manipulation, particularly in constructing test cases and comparing results.
    * `"testing"`: The core package for writing Go tests.
    * `"time"`: Hints at tests that might involve timeouts or delays, although its specific use needs further inspection.

3. **Analyze the Top-Level Declarations:**  Look for global variables and type definitions:
    * `type testpair struct { decoded, encoded string }`: This is a fundamental structure for testing. It defines pairs of decoded and their corresponding encoded strings. This is the core test data.
    * `var pairs = []testpair{ ... }`: This initializes a slice of `testpair` with various standard base64 examples (RFC 3548, RFC 4648, Wikipedia). This confirms the core functionality being tested: standard base64 encoding.
    * `func stdRef(ref string) string { ... }`, `func urlRef(ref string) string { ... }`, etc.: These functions suggest that the tests cover different base64 encodings (standard, URL-safe, raw). This indicates the package supports variations of base64.
    * `const encodeStd = "..."`: Defines the standard base64 encoding alphabet.
    * `var funnyEncoding = NewEncoding(encodeStd).WithPadding(rune('@'))`:  This shows the ability to create custom base64 encodings, a feature of the package.
    * `type encodingTest struct { enc *Encoding, conv func(string) string }`:  This structure is used to iterate through different encoding types and their corresponding reference string conversion functions.
    * `var encodingTests = []encodingTest{ ... }`: This initializes the different encoding configurations to be tested.
    * `var bigtest = testpair{ ... }`:  This suggests testing with larger input strings.
    * `func testEqual(t *testing.T, msg string, args ...any) bool { ... }`: A helper function for comparing test results and reporting errors.

4. **Examine the Test Functions (Functions starting with `Test`):**  Each `Test...` function focuses on a specific aspect of the `base64` package:
    * `TestEncode`: Tests the basic encoding functionality using `EncodeToString` and `AppendEncode`.
    * `TestEncoder`: Tests the `Encoder` type, which uses an `io.Writer` interface.
    * `TestEncoderBuffering`: Tests the `Encoder` with different buffer sizes to ensure correct handling of data chunks.
    * `TestDecode`: Tests the decoding functionality using `Decode`, `DecodeString`, and `AppendDecode`.
    * `TestDecoder`: Tests the `Decoder` type, which uses an `io.Reader` interface.
    * `TestDecoderBuffering`: Tests the `Decoder` with different buffer sizes.
    * `TestDecodeCorrupt`: Tests how the decoder handles invalid base64 input (corruption). The `CorruptInputError` type is key here.
    * `TestDecodeBounds`: Checks for potential out-of-bounds access during decoding.
    * `TestEncodedLen`: Tests the `EncodedLen` function, which calculates the encoded length of a given input size. It also checks for potential integer overflow issues.
    * `TestDecodedLen`: Tests the `DecodedLen` function, which calculates the decoded length of a given encoded size. It also checks for potential integer overflow issues.
    * `TestBig`: Tests encoding and decoding with a large input.
    * `TestNewLineCharacters`: Checks if the decoder correctly handles newline characters within the encoded string.
    * `TestDecoderIssue3577`, `TestDecoderIssue4779`, `TestDecoderIssue7733`, `TestDecoderIssue15656`: These are specific regression tests, likely addressing previously reported bugs. Examining the issue numbers might provide more context. They often test edge cases or error conditions.
    * `TestDecoderRaw`: Tests the `RawURLEncoding` and how it interacts with the `NewDecoder`.

5. **Analyze the Benchmark Functions (Functions starting with `Benchmark`):** These functions measure the performance of different base64 operations:
    * `BenchmarkEncodeToString`: Benchmarks the `EncodeToString` function.
    * `BenchmarkDecodeString`: Benchmarks the `DecodeString` function for different input sizes.
    * `BenchmarkNewEncoding`: Benchmarks the creation of a new `Encoding`.

6. **Synthesize the Findings:** Based on the above analysis, compile the list of functionalities tested and infer the corresponding `encoding/base64` features.

7. **Code Examples and Reasoning:** For each identified feature, construct simple Go code examples demonstrating its usage. Include:
    * **Imports:** Necessary import statements.
    * **Example Usage:** Clear and concise code demonstrating the feature.
    * **Assumptions (Inputs):** Specify the input data for the example.
    * **Expected Output:**  Clearly state the anticipated output.
    * **Reasoning:** Explain *why* the example works and what it illustrates.

8. **Command-Line Arguments (If Applicable):** In this case, the code primarily focuses on testing the *library* functionality. Command-line arguments are not directly processed within this test file. The `go test` command itself has arguments, but they aren't specific to *this* code. Therefore, acknowledge that command-line arguments aren't a primary focus here.

9. **Common Mistakes:** Identify potential pitfalls for users based on the tests, such as forgetting to close the `Encoder`, mishandling errors from `Decode`, or using the wrong encoding for a specific purpose.

10. **Structure and Language:** Organize the answer logically using clear headings and subheadings. Use precise and understandable Chinese.

By following these steps, we can systematically analyze the code, understand its purpose, identify the features being tested, and provide a comprehensive explanation with relevant examples and practical considerations.
这个 `go/src/encoding/base64/base64_test.go` 文件是 Go 语言标准库中 `encoding/base64` 包的测试文件。它的主要功能是验证 `base64` 包提供的各种 base64 编码和解码功能的正确性。

以下是它所测试的一些核心功能：

1. **基本的 Base64 编码和解码 (标准编码)：**  测试使用标准 Base64 编码（RFC 4648）对字符串进行编码和解码。
2. **URL 安全的 Base64 编码和解码：** 测试使用 URL 和文件名安全的 Base64 编码（RFC 4648）对字符串进行编码和解码，这种编码会将 `+` 和 `/` 替换为 `-` 和 `_`。
3. **无填充的 Base64 编码和解码 (Raw 标准和 Raw URL)：** 测试在编码时不添加填充字符 `=` 的情况。
4. **自定义填充字符的 Base64 编码和解码：** 测试使用自定义的填充字符进行编码和解码。
5. **严格模式的 Base64 解码：** 测试在解码时，如果输入包含无效字符或格式不正确，严格模式会返回错误。
6. **`Encoder` 类型的使用：** 测试使用 `NewEncoder` 创建编码器，并通过 `Write` 方法逐步写入数据进行编码。这涉及到测试缓冲和 `Close` 方法。
7. **`Decoder` 类型的使用：** 测试使用 `NewDecoder` 创建解码器，并通过 `Read` 方法读取解码后的数据。这涉及到测试缓冲和处理 `io.EOF`。
8. **处理损坏的 Base64 输入：** 测试解码器在遇到格式错误的 Base64 输入时是否能正确检测并返回 `CorruptInputError`。
9. **计算编码后和解码后的长度：** 测试 `EncodedLen` 和 `DecodedLen` 函数的正确性，这两个函数用于计算给定输入长度的编码后长度或给定编码长度的解码后长度。
10. **处理大量的输入数据：** 测试编码和解码器处理较大数据量的能力。
11. **处理 Base64 编码字符串中的换行符：** 测试解码器是否能正确忽略 Base64 编码字符串中的换行符。
12. **测试 `Decoder` 读取底层 `io.Reader` 时的错误处理：** 确保解码器不会忽略底层读取器返回的错误。
13. **测试解码器在遇到多余填充字符时的行为 (Issue 7733)：** 验证解码器在遇到例如 `=====` 这样的多余填充字符时能正确报错。
14. **性能测试 (Benchmark)：**  包含了一些性能测试，用于衡量编码和解码操作的效率。

**Go 代码示例说明：**

假设我们要测试标准 Base64 编码和解码：

```go
package main

import (
	"encoding/base64"
	"fmt"
	"log"
)

func main() {
	// 假设的输入
	input := []byte("Hello, World!")

	// 使用标准编码进行编码
	encoded := base64.StdEncoding.EncodeToString(input)
	fmt.Println("Encoded:", encoded) // 输出: Encoded: SGVsbG8sIFdvcmxkIQ==

	// 使用标准编码进行解码
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("Decoded:", string(decoded)) // 输出: Decoded: Hello, World!
}
```

**假设的输入与输出：**

* **编码：**
    * 假设输入：`[]byte("Test String")`
    * 预期输出：`VGVzdCBTdHJpbmc=`

* **解码：**
    * 假设输入：`VGVzdCBTdHJpbmc=`
    * 预期输出：`[]byte("Test String")`

**代码推理示例：**

在测试文件中，你可以看到类似这样的代码片段：

```go
func TestEncode(t *testing.T) {
	for _, p := range pairs {
		for _, tt := range encodingTests {
			got := tt.enc.EncodeToString([]byte(p.decoded))
			testEqual(t, "Encode(%q) = %q, want %q", p.decoded, got, tt.conv(p.encoded))
		}
	}
}
```

这段代码遍历了预定义的 `pairs` (包含解码和编码的字符串对) 和 `encodingTests` (包含不同的编码配置和对应的转换函数)。对于每一对解码/编码字符串以及每种编码配置，它会使用当前的编码器 (`tt.enc`) 对解码后的字符串进行编码，然后使用 `testEqual` 函数来比较实际编码结果 (`got`) 和期望的编码结果 (`tt.conv(p.encoded)`，这里 `tt.conv` 会根据不同的编码类型对预期的编码字符串进行调整，例如 URL 安全编码)。

**命令行参数的具体处理：**

这个测试文件本身不直接处理命令行参数。 Go 语言的测试是通过 `go test` 命令来运行的。你可以使用 `go test` 的一些参数来影响测试的执行，例如：

* `-v`:  显示更详细的测试输出。
* `-run <regexp>`:  只运行匹配正则表达式的测试函数。
* `-bench <regexp>`:  运行性能测试。
* `-count n`:  运行每个测试 `n` 次。

例如，要运行 `base64_test.go` 文件中的所有测试，你可以在 `go/src/encoding/base64` 目录下执行：

```bash
go test
```

要运行名称包含 "Encode" 的测试，可以执行：

```bash
go test -run Encode
```

要运行性能测试，可以执行：

```bash
go test -bench .
```

**使用者易犯错的点：**

1. **忘记 `Encoder` 的 `Close` 方法：** 当使用 `NewEncoder` 创建编码器后，如果向其写入数据，最后需要调用 `Close` 方法来刷新缓冲区，确保所有数据都被编码并写入到 `io.Writer` 中。如果不调用 `Close`，可能会导致部分数据丢失。

   ```go
   package main

   import (
   	"encoding/base64"
   	"fmt"
   	"os"
   )

   func main() {
   	encoder := base64.NewEncoder(base64.StdEncoding, os.Stdout)
   	encoder.Write([]byte("Some data"))
   	// 容易忘记调用 Close()
   	encoder.Close()
   	fmt.Println()
   }
   ```

2. **使用错误的编码方式进行解码：** 如果使用 URL 安全的编码进行了编码，解码时也需要使用 `base64.URLEncoding`，反之亦然。使用错误的编码方式会导致解码失败或得到错误的结果。

   ```go
   package main

   import (
   	"encoding/base64"
   	"fmt"
   	"log"
   )

   func main() {
   	// 使用 URL 安全编码
   	encoded := base64.URLEncoding.EncodeToString([]byte("data+with/slash"))
   	fmt.Println("URL Encoded:", encoded) // 输出类似: data-with_slash

   	// 错误地使用标准编码解码
   	decoded, err := base64.StdEncoding.DecodeString(encoded)
   	if err != nil {
   		log.Println("Decode error:", err) // 会报错
   	} else {
   		fmt.Println("Incorrectly Decoded:", string(decoded))
   	}

   	// 正确地使用 URL 安全编码解码
   	decodedCorrect, err := base64.URLEncoding.DecodeString(encoded)
   	if err != nil {
   		log.Fatal(err)
   	}
   	fmt.Println("Correctly Decoded:", string(decodedCorrect))
   }
   ```

3. **忽略 `DecodeString` 返回的错误：**  `DecodeString` 在解码失败时会返回错误，例如输入包含无效的 Base64 字符。 应该检查并处理这个错误。

   ```go
   package main

   import (
   	"encoding/base64"
   	"fmt"
   	"log"
   )

   func main() {
   	invalidBase64 := "SGVsbG8sIFdvcmxkIQ===" // 末尾多了一个 =
   	decoded, err := base64.StdEncoding.DecodeString(invalidBase64)
   	if err != nil {
   		log.Println("Decode error:", err) // 应该处理这个错误
   	} else {
   		fmt.Println("Decoded:", string(decoded))
   	}
   }
   ```

理解这些测试用例的功能可以帮助我们更好地理解 `encoding/base64` 包的各种特性和用法，以及在使用时需要注意的地方。

Prompt: 
```
这是路径为go/src/encoding/base64/base64_test.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。

"""
// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package base64

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"math"
	"reflect"
	"runtime/debug"
	"strconv"
	"strings"
	"testing"
	"time"
)

type testpair struct {
	decoded, encoded string
}

var pairs = []testpair{
	// RFC 3548 examples
	{"\x14\xfb\x9c\x03\xd9\x7e", "FPucA9l+"},
	{"\x14\xfb\x9c\x03\xd9", "FPucA9k="},
	{"\x14\xfb\x9c\x03", "FPucAw=="},

	// RFC 4648 examples
	{"", ""},
	{"f", "Zg=="},
	{"fo", "Zm8="},
	{"foo", "Zm9v"},
	{"foob", "Zm9vYg=="},
	{"fooba", "Zm9vYmE="},
	{"foobar", "Zm9vYmFy"},

	// Wikipedia examples
	{"sure.", "c3VyZS4="},
	{"sure", "c3VyZQ=="},
	{"sur", "c3Vy"},
	{"su", "c3U="},
	{"leasure.", "bGVhc3VyZS4="},
	{"easure.", "ZWFzdXJlLg=="},
	{"asure.", "YXN1cmUu"},
	{"sure.", "c3VyZS4="},
}

// Do nothing to a reference base64 string (leave in standard format)
func stdRef(ref string) string {
	return ref
}

// Convert a reference string to URL-encoding
func urlRef(ref string) string {
	ref = strings.ReplaceAll(ref, "+", "-")
	ref = strings.ReplaceAll(ref, "/", "_")
	return ref
}

// Convert a reference string to raw, unpadded format
func rawRef(ref string) string {
	return strings.TrimRight(ref, "=")
}

// Both URL and unpadding conversions
func rawURLRef(ref string) string {
	return rawRef(urlRef(ref))
}

const encodeStd = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

// A nonstandard encoding with a funny padding character, for testing
var funnyEncoding = NewEncoding(encodeStd).WithPadding(rune('@'))

func funnyRef(ref string) string {
	return strings.ReplaceAll(ref, "=", "@")
}

type encodingTest struct {
	enc  *Encoding           // Encoding to test
	conv func(string) string // Reference string converter
}

var encodingTests = []encodingTest{
	{StdEncoding, stdRef},
	{URLEncoding, urlRef},
	{RawStdEncoding, rawRef},
	{RawURLEncoding, rawURLRef},
	{funnyEncoding, funnyRef},
	{StdEncoding.Strict(), stdRef},
	{URLEncoding.Strict(), urlRef},
	{RawStdEncoding.Strict(), rawRef},
	{RawURLEncoding.Strict(), rawURLRef},
	{funnyEncoding.Strict(), funnyRef},
}

var bigtest = testpair{
	"Twas brillig, and the slithy toves",
	"VHdhcyBicmlsbGlnLCBhbmQgdGhlIHNsaXRoeSB0b3Zlcw==",
}

func testEqual(t *testing.T, msg string, args ...any) bool {
	t.Helper()
	if args[len(args)-2] != args[len(args)-1] {
		t.Errorf(msg, args...)
		return false
	}
	return true
}

func TestEncode(t *testing.T) {
	for _, p := range pairs {
		for _, tt := range encodingTests {
			got := tt.enc.EncodeToString([]byte(p.decoded))
			testEqual(t, "Encode(%q) = %q, want %q", p.decoded, got, tt.conv(p.encoded))
			dst := tt.enc.AppendEncode([]byte("lead"), []byte(p.decoded))
			testEqual(t, `AppendEncode("lead", %q) = %q, want %q`, p.decoded, string(dst), "lead"+tt.conv(p.encoded))
		}
	}
}

func TestEncoder(t *testing.T) {
	for _, p := range pairs {
		bb := &strings.Builder{}
		encoder := NewEncoder(StdEncoding, bb)
		encoder.Write([]byte(p.decoded))
		encoder.Close()
		testEqual(t, "Encode(%q) = %q, want %q", p.decoded, bb.String(), p.encoded)
	}
}

func TestEncoderBuffering(t *testing.T) {
	input := []byte(bigtest.decoded)
	for bs := 1; bs <= 12; bs++ {
		bb := &strings.Builder{}
		encoder := NewEncoder(StdEncoding, bb)
		for pos := 0; pos < len(input); pos += bs {
			end := pos + bs
			if end > len(input) {
				end = len(input)
			}
			n, err := encoder.Write(input[pos:end])
			testEqual(t, "Write(%q) gave error %v, want %v", input[pos:end], err, error(nil))
			testEqual(t, "Write(%q) gave length %v, want %v", input[pos:end], n, end-pos)
		}
		err := encoder.Close()
		testEqual(t, "Close gave error %v, want %v", err, error(nil))
		testEqual(t, "Encoding/%d of %q = %q, want %q", bs, bigtest.decoded, bb.String(), bigtest.encoded)
	}
}

func TestDecode(t *testing.T) {
	for _, p := range pairs {
		for _, tt := range encodingTests {
			encoded := tt.conv(p.encoded)
			dbuf := make([]byte, tt.enc.DecodedLen(len(encoded)))
			count, err := tt.enc.Decode(dbuf, []byte(encoded))
			testEqual(t, "Decode(%q) = error %v, want %v", encoded, err, error(nil))
			testEqual(t, "Decode(%q) = length %v, want %v", encoded, count, len(p.decoded))
			testEqual(t, "Decode(%q) = %q, want %q", encoded, string(dbuf[0:count]), p.decoded)

			dbuf, err = tt.enc.DecodeString(encoded)
			testEqual(t, "DecodeString(%q) = error %v, want %v", encoded, err, error(nil))
			testEqual(t, "DecodeString(%q) = %q, want %q", encoded, string(dbuf), p.decoded)

			dst, err := tt.enc.AppendDecode([]byte("lead"), []byte(encoded))
			testEqual(t, "AppendDecode(%q) = error %v, want %v", p.encoded, err, error(nil))
			testEqual(t, `AppendDecode("lead", %q) = %q, want %q`, p.encoded, string(dst), "lead"+p.decoded)

			dst2, err := tt.enc.AppendDecode(dst[:0:len(p.decoded)], []byte(encoded))
			testEqual(t, "AppendDecode(%q) = error %v, want %v", p.encoded, err, error(nil))
			testEqual(t, `AppendDecode("", %q) = %q, want %q`, p.encoded, string(dst2), p.decoded)
			if len(dst) > 0 && len(dst2) > 0 && &dst[0] != &dst2[0] {
				t.Errorf("unexpected capacity growth: got %d, want %d", cap(dst2), cap(dst))
			}
		}
	}
}

func TestDecoder(t *testing.T) {
	for _, p := range pairs {
		decoder := NewDecoder(StdEncoding, strings.NewReader(p.encoded))
		dbuf := make([]byte, StdEncoding.DecodedLen(len(p.encoded)))
		count, err := decoder.Read(dbuf)
		if err != nil && err != io.EOF {
			t.Fatal("Read failed", err)
		}
		testEqual(t, "Read from %q = length %v, want %v", p.encoded, count, len(p.decoded))
		testEqual(t, "Decoding of %q = %q, want %q", p.encoded, string(dbuf[0:count]), p.decoded)
		if err != io.EOF {
			_, err = decoder.Read(dbuf)
		}
		testEqual(t, "Read from %q = %v, want %v", p.encoded, err, io.EOF)
	}
}

func TestDecoderBuffering(t *testing.T) {
	for bs := 1; bs <= 12; bs++ {
		decoder := NewDecoder(StdEncoding, strings.NewReader(bigtest.encoded))
		buf := make([]byte, len(bigtest.decoded)+12)
		var total int
		var n int
		var err error
		for total = 0; total < len(bigtest.decoded) && err == nil; {
			n, err = decoder.Read(buf[total : total+bs])
			total += n
		}
		if err != nil && err != io.EOF {
			t.Errorf("Read from %q at pos %d = %d, unexpected error %v", bigtest.encoded, total, n, err)
		}
		testEqual(t, "Decoding/%d of %q = %q, want %q", bs, bigtest.encoded, string(buf[0:total]), bigtest.decoded)
	}
}

func TestDecodeCorrupt(t *testing.T) {
	testCases := []struct {
		input  string
		offset int // -1 means no corruption.
	}{
		{"", -1},
		{"\n", -1},
		{"AAA=\n", -1},
		{"AAAA\n", -1},
		{"!!!!", 0},
		{"====", 0},
		{"x===", 1},
		{"=AAA", 0},
		{"A=AA", 1},
		{"AA=A", 2},
		{"AA==A", 4},
		{"AAA=AAAA", 4},
		{"AAAAA", 4},
		{"AAAAAA", 4},
		{"A=", 1},
		{"A==", 1},
		{"AA=", 3},
		{"AA==", -1},
		{"AAA=", -1},
		{"AAAA", -1},
		{"AAAAAA=", 7},
		{"YWJjZA=====", 8},
		{"A!\n", 1},
		{"A=\n", 1},
	}
	for _, tc := range testCases {
		dbuf := make([]byte, StdEncoding.DecodedLen(len(tc.input)))
		_, err := StdEncoding.Decode(dbuf, []byte(tc.input))
		if tc.offset == -1 {
			if err != nil {
				t.Error("Decoder wrongly detected corruption in", tc.input)
			}
			continue
		}
		switch err := err.(type) {
		case CorruptInputError:
			testEqual(t, "Corruption in %q at offset %v, want %v", tc.input, int(err), tc.offset)
		default:
			t.Error("Decoder failed to detect corruption in", tc)
		}
	}
}

func TestDecodeBounds(t *testing.T) {
	var buf [32]byte
	s := StdEncoding.EncodeToString(buf[:])
	defer func() {
		if err := recover(); err != nil {
			t.Fatalf("Decode panicked unexpectedly: %v\n%s", err, debug.Stack())
		}
	}()
	n, err := StdEncoding.Decode(buf[:], []byte(s))
	if n != len(buf) || err != nil {
		t.Fatalf("StdEncoding.Decode = %d, %v, want %d, nil", n, err, len(buf))
	}
}

func TestEncodedLen(t *testing.T) {
	type test struct {
		enc  *Encoding
		n    int
		want int64
	}
	tests := []test{
		{RawStdEncoding, 0, 0},
		{RawStdEncoding, 1, 2},
		{RawStdEncoding, 2, 3},
		{RawStdEncoding, 3, 4},
		{RawStdEncoding, 7, 10},
		{StdEncoding, 0, 0},
		{StdEncoding, 1, 4},
		{StdEncoding, 2, 4},
		{StdEncoding, 3, 4},
		{StdEncoding, 4, 8},
		{StdEncoding, 7, 12},
	}
	// check overflow
	switch strconv.IntSize {
	case 32:
		tests = append(tests, test{RawStdEncoding, (math.MaxInt-5)/8 + 1, 357913942})
		tests = append(tests, test{RawStdEncoding, math.MaxInt/4*3 + 2, math.MaxInt})
	case 64:
		tests = append(tests, test{RawStdEncoding, (math.MaxInt-5)/8 + 1, 1537228672809129302})
		tests = append(tests, test{RawStdEncoding, math.MaxInt/4*3 + 2, math.MaxInt})
	}
	for _, tt := range tests {
		if got := tt.enc.EncodedLen(tt.n); int64(got) != tt.want {
			t.Errorf("EncodedLen(%d): got %d, want %d", tt.n, got, tt.want)
		}
	}
}

func TestDecodedLen(t *testing.T) {
	type test struct {
		enc  *Encoding
		n    int
		want int64
	}
	tests := []test{
		{RawStdEncoding, 0, 0},
		{RawStdEncoding, 2, 1},
		{RawStdEncoding, 3, 2},
		{RawStdEncoding, 4, 3},
		{RawStdEncoding, 10, 7},
		{StdEncoding, 0, 0},
		{StdEncoding, 4, 3},
		{StdEncoding, 8, 6},
	}
	// check overflow
	switch strconv.IntSize {
	case 32:
		tests = append(tests, test{RawStdEncoding, math.MaxInt/6 + 1, 268435456})
		tests = append(tests, test{RawStdEncoding, math.MaxInt, 1610612735})
	case 64:
		tests = append(tests, test{RawStdEncoding, math.MaxInt/6 + 1, 1152921504606846976})
		tests = append(tests, test{RawStdEncoding, math.MaxInt, 6917529027641081855})
	}
	for _, tt := range tests {
		if got := tt.enc.DecodedLen(tt.n); int64(got) != tt.want {
			t.Errorf("DecodedLen(%d): got %d, want %d", tt.n, got, tt.want)
		}
	}
}

func TestBig(t *testing.T) {
	n := 3*1000 + 1
	raw := make([]byte, n)
	const alpha = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	for i := 0; i < n; i++ {
		raw[i] = alpha[i%len(alpha)]
	}
	encoded := new(bytes.Buffer)
	w := NewEncoder(StdEncoding, encoded)
	nn, err := w.Write(raw)
	if nn != n || err != nil {
		t.Fatalf("Encoder.Write(raw) = %d, %v want %d, nil", nn, err, n)
	}
	err = w.Close()
	if err != nil {
		t.Fatalf("Encoder.Close() = %v want nil", err)
	}
	decoded, err := io.ReadAll(NewDecoder(StdEncoding, encoded))
	if err != nil {
		t.Fatalf("io.ReadAll(NewDecoder(...)): %v", err)
	}

	if !bytes.Equal(raw, decoded) {
		var i int
		for i = 0; i < len(decoded) && i < len(raw); i++ {
			if decoded[i] != raw[i] {
				break
			}
		}
		t.Errorf("Decode(Encode(%d-byte string)) failed at offset %d", n, i)
	}
}

func TestNewLineCharacters(t *testing.T) {
	// Each of these should decode to the string "sure", without errors.
	const expected = "sure"
	examples := []string{
		"c3VyZQ==",
		"c3VyZQ==\r",
		"c3VyZQ==\n",
		"c3VyZQ==\r\n",
		"c3VyZ\r\nQ==",
		"c3V\ryZ\nQ==",
		"c3V\nyZ\rQ==",
		"c3VyZ\nQ==",
		"c3VyZQ\n==",
		"c3VyZQ=\n=",
		"c3VyZQ=\r\n\r\n=",
	}
	for _, e := range examples {
		buf, err := StdEncoding.DecodeString(e)
		if err != nil {
			t.Errorf("Decode(%q) failed: %v", e, err)
			continue
		}
		if s := string(buf); s != expected {
			t.Errorf("Decode(%q) = %q, want %q", e, s, expected)
		}
	}
}

type nextRead struct {
	n   int   // bytes to return
	err error // error to return
}

// faultInjectReader returns data from source, rate-limited
// and with the errors as written to nextc.
type faultInjectReader struct {
	source string
	nextc  <-chan nextRead
}

func (r *faultInjectReader) Read(p []byte) (int, error) {
	nr := <-r.nextc
	if len(p) > nr.n {
		p = p[:nr.n]
	}
	n := copy(p, r.source)
	r.source = r.source[n:]
	return n, nr.err
}

// tests that we don't ignore errors from our underlying reader
func TestDecoderIssue3577(t *testing.T) {
	next := make(chan nextRead, 10)
	wantErr := errors.New("my error")
	next <- nextRead{5, nil}
	next <- nextRead{10, wantErr}
	next <- nextRead{0, wantErr}
	d := NewDecoder(StdEncoding, &faultInjectReader{
		source: "VHdhcyBicmlsbGlnLCBhbmQgdGhlIHNsaXRoeSB0b3Zlcw==", // twas brillig...
		nextc:  next,
	})
	errc := make(chan error, 1)
	go func() {
		_, err := io.ReadAll(d)
		errc <- err
	}()
	select {
	case err := <-errc:
		if err != wantErr {
			t.Errorf("got error %v; want %v", err, wantErr)
		}
	case <-time.After(5 * time.Second):
		t.Errorf("timeout; Decoder blocked without returning an error")
	}
}

func TestDecoderIssue4779(t *testing.T) {
	encoded := `CP/EAT8AAAEF
AQEBAQEBAAAAAAAAAAMAAQIEBQYHCAkKCwEAAQUBAQEBAQEAAAAAAAAAAQACAwQFBgcICQoLEAAB
BAEDAgQCBQcGCAUDDDMBAAIRAwQhEjEFQVFhEyJxgTIGFJGhsUIjJBVSwWIzNHKC0UMHJZJT8OHx
Y3M1FqKygyZEk1RkRcKjdDYX0lXiZfKzhMPTdePzRieUpIW0lcTU5PSltcXV5fVWZnaGlqa2xtbm
9jdHV2d3h5ent8fX5/cRAAICAQIEBAMEBQYHBwYFNQEAAhEDITESBEFRYXEiEwUygZEUobFCI8FS
0fAzJGLhcoKSQ1MVY3M08SUGFqKygwcmNcLSRJNUoxdkRVU2dGXi8rOEw9N14/NGlKSFtJXE1OT0
pbXF1eX1VmZ2hpamtsbW5vYnN0dXZ3eHl6e3x//aAAwDAQACEQMRAD8A9VSSSSUpJJJJSkkkJ+Tj
1kiy1jCJJDnAcCTykpKkuQ6p/jN6FgmxlNduXawwAzaGH+V6jn/R/wCt71zdn+N/qL3kVYFNYB4N
ji6PDVjWpKp9TSXnvTf8bFNjg3qOEa2n6VlLpj/rT/pf567DpX1i6L1hs9Py67X8mqdtg/rUWbbf
+gkp0kkkklKSSSSUpJJJJT//0PVUkkklKVLq3WMDpGI7KzrNjADtYNXvI/Mqr/Pd/q9W3vaxjnvM
NaCXE9gNSvGPrf8AWS3qmba5jjsJhoB0DAf0NDf6sevf+/lf8Hj0JJATfWT6/dV6oXU1uOLQeKKn
EQP+Hubtfe/+R7Mf/g7f5xcocp++Z11JMCJPgFBxOg7/AOuqDx8I/ikpkXkmSdU8mJIJA/O8EMAy
j+mSARB/17pKVXYWHXjsj7yIex0PadzXMO1zT5KHoNA3HT8ietoGhgjsfA+CSnvvqh/jJtqsrwOv
2b6NGNzXfTYexzJ+nU7/ALkf4P8Awv6P9KvTQQ4AgyDqCF85Pho3CTB7eHwXoH+LT65uZbX9X+o2
bqbPb06551Y4
`
	encodedShort := strings.ReplaceAll(encoded, "\n", "")

	dec := NewDecoder(StdEncoding, strings.NewReader(encoded))
	res1, err := io.ReadAll(dec)
	if err != nil {
		t.Errorf("ReadAll failed: %v", err)
	}

	dec = NewDecoder(StdEncoding, strings.NewReader(encodedShort))
	var res2 []byte
	res2, err = io.ReadAll(dec)
	if err != nil {
		t.Errorf("ReadAll failed: %v", err)
	}

	if !bytes.Equal(res1, res2) {
		t.Error("Decoded results not equal")
	}
}

func TestDecoderIssue7733(t *testing.T) {
	s, err := StdEncoding.DecodeString("YWJjZA=====")
	want := CorruptInputError(8)
	if !reflect.DeepEqual(want, err) {
		t.Errorf("Error = %v; want CorruptInputError(8)", err)
	}
	if string(s) != "abcd" {
		t.Errorf("DecodeString = %q; want abcd", s)
	}
}

func TestDecoderIssue15656(t *testing.T) {
	_, err := StdEncoding.Strict().DecodeString("WvLTlMrX9NpYDQlEIFlnDB==")
	want := CorruptInputError(22)
	if !reflect.DeepEqual(want, err) {
		t.Errorf("Error = %v; want CorruptInputError(22)", err)
	}
	_, err = StdEncoding.Strict().DecodeString("WvLTlMrX9NpYDQlEIFlnDA==")
	if err != nil {
		t.Errorf("Error = %v; want nil", err)
	}
	_, err = StdEncoding.DecodeString("WvLTlMrX9NpYDQlEIFlnDB==")
	if err != nil {
		t.Errorf("Error = %v; want nil", err)
	}
}

func BenchmarkEncodeToString(b *testing.B) {
	data := make([]byte, 8192)
	b.SetBytes(int64(len(data)))
	for i := 0; i < b.N; i++ {
		StdEncoding.EncodeToString(data)
	}
}

func BenchmarkDecodeString(b *testing.B) {
	sizes := []int{2, 4, 8, 64, 8192}
	benchFunc := func(b *testing.B, benchSize int) {
		data := StdEncoding.EncodeToString(make([]byte, benchSize))
		b.SetBytes(int64(len(data)))
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			StdEncoding.DecodeString(data)
		}
	}
	for _, size := range sizes {
		b.Run(fmt.Sprintf("%d", size), func(b *testing.B) {
			benchFunc(b, size)
		})
	}
}

func BenchmarkNewEncoding(b *testing.B) {
	b.SetBytes(int64(len(Encoding{}.decodeMap)))
	for i := 0; i < b.N; i++ {
		e := NewEncoding(encodeStd)
		for _, v := range e.decodeMap {
			_ = v
		}
	}
}

func TestDecoderRaw(t *testing.T) {
	source := "AAAAAA"
	want := []byte{0, 0, 0, 0}

	// Direct.
	dec1, err := RawURLEncoding.DecodeString(source)
	if err != nil || !bytes.Equal(dec1, want) {
		t.Errorf("RawURLEncoding.DecodeString(%q) = %x, %v, want %x, nil", source, dec1, err, want)
	}

	// Through reader. Used to fail.
	r := NewDecoder(RawURLEncoding, bytes.NewReader([]byte(source)))
	dec2, err := io.ReadAll(io.LimitReader(r, 100))
	if err != nil || !bytes.Equal(dec2, want) {
		t.Errorf("reading NewDecoder(RawURLEncoding, %q) = %x, %v, want %x, nil", source, dec2, err, want)
	}

	// Should work with padding.
	r = NewDecoder(URLEncoding, bytes.NewReader([]byte(source+"==")))
	dec3, err := io.ReadAll(r)
	if err != nil || !bytes.Equal(dec3, want) {
		t.Errorf("reading NewDecoder(URLEncoding, %q) = %x, %v, want %x, nil", source+"==", dec3, err, want)
	}
}

"""



```