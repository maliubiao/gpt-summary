Response:
Let's break down the thought process for analyzing the provided Go code snippet.

1. **Identify the Core Functionality:** The file name `crc64_test.go` and the package declaration `package crc64` immediately suggest that this code is testing the functionality of a CRC64 implementation in Go. The presence of `testing` import reinforces this.

2. **Analyze the `golden` Variable:** The `golden` variable is a slice of structs named `test`. Each `test` struct contains `outISO`, `outECMA`, `in`, `halfStateISO`, and `halfStateECMA`. This structure strongly implies that the CRC64 implementation supports at least two different polynomial standards (ISO and ECMA), and that the tests involve comparing calculated CRC64 checksums against known "golden" values for various input strings. The "halfState" fields suggest testing the ability to serialize and deserialize the internal state of the CRC64 calculation.

3. **Examine the `TestGolden` Function:** This function iterates through the `golden` slice. For each test case, it creates two `crc64.New` instances, one with the `ISO` table and one with the `ECMA` table. It then writes the input string (`g.in`) to each and compares the calculated checksum (`c.Sum64()`) against the expected `outISO` and `outECMA` values. This confirms the core functionality: calculating CRC64 checksums using different polynomial tables.

4. **Analyze the `TestGoldenMarshal` Function:**  This function, separated into "ISO" and "ECMA" subtests, focuses on the `encoding.BinaryMarshaler` and `encoding.BinaryUnmarshaler` interfaces. It calculates the CRC64 of the first half of the input string, marshals the state, and then checks if the marshaled state matches the expected `halfStateISO` or `halfStateECMA`. It then unmarshals the state into a new `crc64.New` instance and calculates the CRC64 of the second half of the input string. Finally, it verifies that the checksums calculated by processing the input in two halves (with state serialization/deserialization) match the checksum calculated by processing the entire input at once. This points to the Go feature of state serialization/deserialization using the `encoding` package.

5. **Understand `TestMarshalTableMismatch`:** This test attempts to unmarshal the state of a CRC64 object initialized with the ISO table into a CRC64 object initialized with the ECMA table. It expects an error, indicating that you cannot interchange states between different polynomial configurations.

6. **Interpret the `bench` and `BenchmarkCrc64` Functions:** These functions are standard Go benchmark tests. They measure the performance of CRC64 calculation for different input sizes and polynomial tables. The `b.SetBytes` and `b.ResetTimer` are common benchmark setup steps.

7. **Infer the Go Features:** Based on the above analysis, the code demonstrates the following Go features:
    * **Testing:** Using the `testing` package for unit and benchmark tests.
    * **Interfaces:** Implementing `io.Writer`, `encoding.BinaryMarshaler`, `encoding.BinaryUnmarshaler`, and `encoding.BinaryAppender` interfaces.
    * **Data Structures:** Using structs (`test`) and slices (`golden`) to organize test data.
    * **Benchmarking:** Using the `testing` package for performance measurements.
    * **Error Handling:** Checking for errors during marshaling and unmarshaling.

8. **Identify Potential User Errors:**  The `TestMarshalTableMismatch` function highlights a crucial point: **users should not attempt to unmarshal the state of a CRC64 object initialized with one polynomial table into an object initialized with a different table.**  This would lead to incorrect checksum calculations.

9. **Formulate the Answer:**  Finally, structure the answer in Chinese as requested, covering the identified functionalities, the inferred Go features with illustrative examples, the implications of table mismatches, and explicitly mentioning the absence of command-line argument handling. Ensure the examples use appropriate syntax and explain the purpose of each part.
这个 Go 语言代码文件 `crc64_test.go` 的主要功能是 **测试 `hash/crc64` 包中 CRC64（循环冗余校验码，64位）的实现是否正确**。

更具体地说，它做了以下几件事：

1. **定义测试用例:**  通过 `golden` 变量定义了一系列测试用例。每个测试用例包含：
    * `outISO`: 使用 ISO 多项式计算出的预期 CRC64 值。
    * `outECMA`: 使用 ECMA 多项式计算出的预期 CRC64 值。
    * `in`: 作为 CRC64 计算的输入字符串。
    * `halfStateISO`:  输入字符串前半部分处理后，使用 ISO 多项式计算的 CRC64 状态的序列化表示。
    * `halfStateECMA`: 输入字符串前半部分处理后，使用 ECMA 多项式计算的 CRC64 状态的序列化表示。

2. **测试基本的 CRC64 计算 (`TestGolden` 函数):**
   - 它创建了分别使用 ISO 和 ECMA 多项式的 CRC64 计算器 (`crc64.New`)。
   - 对于每个测试用例，它将输入字符串写入计算器 (`io.WriteString`)。
   - 它获取计算出的 CRC64 值 (`c.Sum64()`)，并将其与预期的 `outISO` 和 `outECMA` 值进行比较。
   - 如果计算出的值与预期值不符，则测试失败。

3. **测试 CRC64 状态的序列化和反序列化 (`TestGoldenMarshal` 函数):**
   - 这个测试用例验证了 CRC64 计算器的状态是否可以正确地被序列化 (`MarshalBinary`) 和反序列化 (`UnmarshalBinary`)。
   - 它将输入字符串分成两半。
   - 它使用前半部分字符串更新一个 CRC64 计算器，然后序列化其状态。
   - 它将序列化后的状态与预期的 `halfStateISO` 或 `halfStateECMA` 进行比较。
   - 它创建一个新的 CRC64 计算器，并使用之前序列化的状态进行初始化。
   - 它使用后半部分字符串更新两个计算器（一个是原始的，一个是反序列化状态后的）。
   - 它比较两个计算器最终的 CRC64 值，确保它们一致。

4. **测试不同多项式表之间的状态不兼容性 (`TestMarshalTableMismatch` 函数):**
   - 这个测试用例验证了使用 ISO 多项式表初始化的 CRC64 计算器的状态，不能被反序列化到使用 ECMA 多项式表初始化的计算器中，反之亦然。这确保了状态序列化和反序列化的安全性，避免了混淆不同算法的结果。

5. **性能基准测试 (`BenchmarkCrc64` 函数):**
   - 它提供了一些基准测试用例，用于衡量不同输入大小和不同多项式下 CRC64 计算的性能。

**它可以推理出 `hash/crc64` 包实现了 CRC64 校验和功能。**

以下是用 Go 代码举例说明如何使用 `hash/crc64` 包计算 CRC64 校验和：

```go
package main

import (
	"fmt"
	"hash/crc64"
)

func main() {
	data := []byte("Hello, world!")

	// 使用 ISO 多项式创建 CRC64 计算器
	isoTable := crc64.MakeTable(crc64.ISO)
	isoChecksum := crc64.New(isoTable)
	isoChecksum.Write(data)
	isoResult := isoChecksum.Sum64()
	fmt.Printf("ISO CRC64 checksum: 0x%X\n", isoResult) // 输出: ISO CRC64 checksum: 0x99BD3047B9591362

	// 使用 ECMA 多项式创建 CRC64 计算器
	ecmaTable := crc64.MakeTable(crc64.ECMA)
	ecmaChecksum := crc64.New(ecmaTable)
	ecmaChecksum.Write(data)
	ecmaResult := ecmaChecksum.Sum64()
	fmt.Printf("ECMA CRC64 checksum: 0xCBF4392629521879\n", ecmaResult) // 输出: ECMA CRC64 checksum: 0xCBF4392629521879
}
```

**代码推理与假设的输入输出:**

在 `TestGolden` 函数中，一个假设的测试用例是：

```go
{outISO: 0x3420000000000000, outECMA: 0x330284772e652b05, in: "a"}
```

**假设输入:** 字符串 "a"

**预期输出:**
* 使用 ISO 多项式计算出的 CRC64 值为 `0x3420000000000000`。
* 使用 ECMA 多项式计算出的 CRC64 值为 `0x330284772e652b05`。

`TestGolden` 函数会创建两个 `crc64.New` 实例，分别使用 `crc64.ISO` 和 `crc64.ECMA` 生成的表。然后将 "a" 写入这两个实例，并调用 `Sum64()` 方法。如果返回的值与上述预期输出不符，测试将会失败。

**命令行参数的具体处理:**

这段代码是测试代码，它本身不处理任何命令行参数。它是由 `go test` 命令执行的，`go test` 命令自身可以接受一些参数，例如指定要运行的测试文件或函数，但这些参数与这段 `crc64_test.go` 的内部逻辑无关。

**使用者易犯错的点:**

一个容易犯错的点是在使用 `encoding.BinaryMarshaler` 和 `encoding.BinaryUnmarshaler` 接口进行状态序列化和反序列化时，**尝试跨不同的多项式表进行操作**。

**举例说明:**

```go
package main

import (
	"bytes"
	"encoding"
	"fmt"
	"hash/crc64"
	"log"
)

func main() {
	// 创建一个使用 ISO 多项式的 CRC64 计算器
	isoTable := crc64.MakeTable(crc64.ISO)
	isoChecksum := crc64.New(isoTable)
	isoChecksum.Write([]byte("part1"))

	// 序列化 ISO 计算器的状态
	marshaler, ok := isoChecksum.(encoding.BinaryMarshaler)
	if !ok {
		log.Fatal("CRC64 with ISO table does not implement BinaryMarshaler")
	}
	state, err := marshaler.MarshalBinary()
	if err != nil {
		log.Fatalf("Error marshaling state: %v", err)
	}

	// 创建一个使用 ECMA 多项式的 CRC64 计算器
	ecmaTable := crc64.MakeTable(crc64.ECMA)
	ecmaChecksum := crc64.New(ecmaTable)

	// 尝试将 ISO 计算器的状态反序列化到 ECMA 计算器
	unmarshaler, ok := ecmaChecksum.(encoding.BinaryUnmarshaler)
	if !ok {
		log.Fatal("CRC64 with ECMA table does not implement BinaryUnmarshaler")
	}
	err = unmarshaler.UnmarshalBinary(state)
	if err != nil {
		fmt.Printf("Error unmarshaling state (expected): %v\n", err)
	} else {
		fmt.Println("Error: Successfully unmarshaled state with mismatched table!")
	}

	// 正确的做法是使用相同的多项式表进行反序列化
	isoChecksum2 := crc64.New(isoTable)
	unmarshaler2, ok := isoChecksum2.(encoding.BinaryUnmarshaler)
	if !ok {
		log.Fatal("CRC64 with ISO table does not implement BinaryUnmarshaler")
	}
	err = unmarshaler2.UnmarshalBinary(state)
	if err != nil {
		log.Fatalf("Error unmarshaling state: %v", err)
	}
	isoChecksum2.Write([]byte("part2"))
	fmt.Printf("Correct CRC64 after unmarshaling: 0x%X\n", isoChecksum2.Sum64())
}
```

在这个例子中，尝试将使用 ISO 多项式计算器的状态反序列化到使用 ECMA 多项式的计算器将会（期望地）失败，因为它们的内部状态结构不同。这是使用者需要注意的地方。应该确保序列化和反序列化操作使用相同的多项式表。

### 提示词
```
这是路径为go/src/hash/crc64/crc64_test.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
```

### 源代码
```go
// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package crc64

import (
	"encoding"
	"io"
	"testing"
)

type test struct {
	outISO        uint64
	outECMA       uint64
	in            string
	halfStateISO  string // ISO marshaled hash state after first half of in written, used by TestGoldenMarshal
	halfStateECMA string // ECMA marshaled hash state after first half of in written, used by TestGoldenMarshal
}

var golden = []test{
	{0x0, 0x0, "", "crc\x02s\xba\x84\x84\xbb\xcd]\xef\x00\x00\x00\x00\x00\x00\x00\x00", "crc\x02`&\x9aR\xe1\xb7\xfee\x00\x00\x00\x00\x00\x00\x00\x00"},
	{0x3420000000000000, 0x330284772e652b05, "a", "crc\x02s\xba\x84\x84\xbb\xcd]\xef\x00\x00\x00\x00\x00\x00\x00\x00", "crc\x02`&\x9aR\xe1\xb7\xfee\x00\x00\x00\x00\x00\x00\x00\x00"},
	{0x36c4200000000000, 0xbc6573200e84b046, "ab", "crc\x02s\xba\x84\x84\xbb\xcd]\xef4 \x00\x00\x00\x00\x00\x00", "crc\x02`&\x9aR\xe1\xb7\xfee3\x02\x84w.e+\x05"},
	{0x3776c42000000000, 0x2cd8094a1a277627, "abc", "crc\x02s\xba\x84\x84\xbb\xcd]\xef4 \x00\x00\x00\x00\x00\x00", "crc\x02`&\x9aR\xe1\xb7\xfee3\x02\x84w.e+\x05"},
	{0x336776c420000000, 0x3c9d28596e5960ba, "abcd", "crc\x02s\xba\x84\x84\xbb\xcd]\xef6\xc4 \x00\x00\x00\x00\x00", "crc\x02`&\x9aR\xe1\xb7\xfee\xbces \x0e\x84\xb0F"},
	{0x32d36776c4200000, 0x40bdf58fb0895f2, "abcde", "crc\x02s\xba\x84\x84\xbb\xcd]\xef6\xc4 \x00\x00\x00\x00\x00", "crc\x02`&\x9aR\xe1\xb7\xfee\xbces \x0e\x84\xb0F"},
	{0x3002d36776c42000, 0xd08e9f8545a700f4, "abcdef", "crc\x02s\xba\x84\x84\xbb\xcd]\xef7v\xc4 \x00\x00\x00\x00", "crc\x02`&\x9aR\xe1\xb7\xfee,\xd8\tJ\x1a'v'"},
	{0x31b002d36776c420, 0xec20a3a8cc710e66, "abcdefg", "crc\x02s\xba\x84\x84\xbb\xcd]\xef7v\xc4 \x00\x00\x00\x00", "crc\x02`&\x9aR\xe1\xb7\xfee,\xd8\tJ\x1a'v'"},
	{0xe21b002d36776c4, 0x67b4f30a647a0c59, "abcdefgh", "crc\x02s\xba\x84\x84\xbb\xcd]\xef3gv\xc4 \x00\x00\x00", "crc\x02`&\x9aR\xe1\xb7\xfee<\x9d(YnY`\xba"},
	{0x8b6e21b002d36776, 0x9966f6c89d56ef8e, "abcdefghi", "crc\x02s\xba\x84\x84\xbb\xcd]\xef3gv\xc4 \x00\x00\x00", "crc\x02`&\x9aR\xe1\xb7\xfee<\x9d(YnY`\xba"},
	{0x7f5b6e21b002d367, 0x32093a2ecd5773f4, "abcdefghij", "crc\x02s\xba\x84\x84\xbb\xcd]\xef2\xd3gv\xc4 \x00\x00", "crc\x02`&\x9aR\xe1\xb7\xfee\x04\v\xdfX\xfb\b\x95\xf2"},
	{0x8ec0e7c835bf9cdf, 0x8a0825223ea6d221, "Discard medicine more than two years old.", "crc\x02s\xba\x84\x84\xbb\xcd]\xef\xc6\xc0\f\xac'\x11\x12\xd5", "crc\x02`&\x9aR\xe1\xb7\xfee\xfd%\xc0&\xa0R\xef\x95"},
	{0xc7db1759e2be5ab4, 0x8562c0ac2ab9a00d, "He who has a shady past knows that nice guys finish last.", "crc\x02s\xba\x84\x84\xbb\xcd]\xef\t\xcb\xd15X[r\t", "crc\x02`&\x9aR\xe1\xb7\xfee\a\x02\xe8|+\xc1\x06\xe3"},
	{0xfbf9d9603a6fa020, 0x3ee2a39c083f38b4, "I wouldn't marry him with a ten foot pole.", "crc\x02s\xba\x84\x84\xbb\xcd]\xef\x19\xc8d\xbe\x84\x14\x87_", "crc\x02`&\x9aR\xe1\xb7\xfee˷\xd3\xeeG\xdcE\x8c"},
	{0xeafc4211a6daa0ef, 0x1f603830353e518a, "Free! Free!/A trip/to Mars/for 900/empty jars/Burma Shave", "crc\x02s\xba\x84\x84\xbb\xcd]\xef\xad\x1b*\xc0\xb1\xf3i(", "crc\x02`&\x9aR\xe1\xb7\xfee\xa7\x8a\xdb\xf6\xd2R\t\x96"},
	{0x3e05b21c7a4dc4da, 0x2fd681d7b2421fd, "The days of the digital watch are numbered.  -Tom Stoppard", "crc\x02s\xba\x84\x84\xbb\xcd]\xefv78\x1ak\x02\x8f\xff", "crc\x02`&\x9aR\xe1\xb7\xfeeT\xcbl\x10\xfb\x87K*"},
	{0x5255866ad6ef28a6, 0x790ef2b16a745a41, "Nepal premier won't resign.", "crc\x02s\xba\x84\x84\xbb\xcd]\xef\xcbf\x11R\xbfh\xde\xc9", "crc\x02`&\x9aR\xe1\xb7\xfee6\x13ُ\x06_\xbd\x9a"},
	{0x8a79895be1e9c361, 0x3ef8f06daccdcddf, "For every action there is an equal and opposite government program.", "crc\x02s\xba\x84\x84\xbb\xcd]\xef\xf3pV\x01c_Wu", "crc\x02`&\x9aR\xe1\xb7\xfee\xe7\xc6\n\b\x12FL\xa0"},
	{0x8878963a649d4916, 0x49e41b2660b106d, "His money is twice tainted: 'taint yours and 'taint mine.", "crc\x02s\xba\x84\x84\xbb\xcd]\xefñ\xff\xf1\xe0/Δ", "crc\x02`&\x9aR\xe1\xb7\xfeeOL/\xb1\xec\xa2\x14\x87"},
	{0xa7b9d53ea87eb82f, 0x561cc0cfa235ac68, "There is no reason for any individual to have a computer in their home. -Ken Olsen, 1977", "crc\x02s\xba\x84\x84\xbb\xcd]\xefݸa\xe1\xb5\xf8\xb9W", "crc\x02`&\x9aR\xe1\xb7\xfee\x87)GQ\x03\xf4K\t"},
	{0xdb6805c0966a2f9c, 0xd4fe9ef082e69f59, "It's a tiny change to the code and not completely disgusting. - Bob Manchek", "crc\x02s\xba\x84\x84\xbb\xcd]\xefV\xba\x12\x91\x81\x1fNU", "crc\x02`&\x9aR\xe1\xb7\xfee\n\xb8\x81v?\xdeL\xcb"},
	{0xf3553c65dacdadd2, 0xe3b5e46cd8d63a4d, "size:  a.out:  bad magic", "crc\x02s\xba\x84\x84\xbb\xcd]\xefG\xad\xbc\xb2\xa8y\xc9\xdc", "crc\x02`&\x9aR\xe1\xb7\xfee\xcc\xce\xe5\xe6\x89p\x01\xb8"},
	{0x9d5e034087a676b9, 0x865aaf6b94f2a051, "The major problem is with sendmail.  -Mark Horton", "crc\x02s\xba\x84\x84\xbb\xcd]\uf8acn\x8aT;&\xd5", "crc\x02`&\x9aR\xe1\xb7\xfeeFf\x9c\x1f\xc9x\xbfa"},
	{0xa6db2d7f8da96417, 0x7eca10d2f8136eb4, "Give me a rock, paper and scissors and I will move the world.  CCFestoon", "crc\x02s\xba\x84\x84\xbb\xcd]\xef\xeb\x18\xbf\xf9}\x91\xe5|", "crc\x02`&\x9aR\xe1\xb7\xfeea\x9e\x05:\xce[\xe7\x19"},
	{0x325e00cd2fe819f9, 0xd7dd118c98e98727, "If the enemy is within range, then so are you.", "crc\x02s\xba\x84\x84\xbb\xcd]\xef^5k\xd0Aj_{", "crc\x02`&\x9aR\xe1\xb7\xfee\v#\x99\xa8r\x83YR"},
	{0x88c6600ce58ae4c6, 0x70fb33c119c29318, "It's well we cannot hear the screams/That we create in others' dreams.", "crc\x02s\xba\x84\x84\xbb\xcd]\xef|\xb5\x02\xdcw\x18/\x86", "crc\x02`&\x9aR\xe1\xb7\xfee]\x9d-\xed\x8c\xf9r9"},
	{0x28c4a3f3b769e078, 0x57c891e39a97d9b7, "You remind me of a TV show, but that's all right: I watch it anyway.", "crc\x02s\xba\x84\x84\xbb\xcd]\xef\x03\x8bd\x1c\xb0_\x16\x98", "crc\x02`&\x9aR\xe1\xb7\xfee\xafW\x98\xaa\"\xe7\xd7|"},
	{0xa698a34c9d9f1dca, 0xa1f46ba20ad06eb7, "C is as portable as Stonehedge!!", "crc\x02s\xba\x84\x84\xbb\xcd]\xef.P\xe1I\xc6pi\xdc", "crc\x02`&\x9aR\xe1\xb7\xfee֚\x06\x01(\xc0\x1e\x8b"},
	{0xf6c1e2a8c26c5cfc, 0x7ad25fafa1710407, "Even if I could be Shakespeare, I think I should still choose to be Faraday. - A. Huxley", "crc\x02s\xba\x84\x84\xbb\xcd]\xef\xf7\xa04\x8a\xf2o\xe0;", "crc\x02`&\x9aR\xe1\xb7\xfee<[\xd2%\x9em\x94\x04"},
	{0xd402559dfe9b70c, 0x73cef1666185c13f, "The fugacity of a constituent in a mixture of gases at a given temperature is proportional to its mole fraction.  Lewis-Randall Rule", "crc\x02s\xba\x84\x84\xbb\xcd]\xef\u007f\xae\xb9\xbaX=\x19v", "crc\x02`&\x9aR\xe1\xb7\xfee\xb2˦Y\xc5\xd0G\x03"},
	{0xdb6efff26aa94946, 0xb41858f73c389602, "How can you write a big system without C++?  -Paul Glick", "crc\x02s\xba\x84\x84\xbb\xcd]\xefa\xed$js\xb9\xa5A", "crc\x02`&\x9aR\xe1\xb7\xfeeZm\x96\x8a\xe2\xaf\x13p"},
	{0xe7fcf1006b503b61, 0x27db187fc15bbc72, "This is a test of the emergency broadcast system.", "crc\x02s\xba\x84\x84\xbb\xcd]\xef}\xee[q\x16\xcb\xe4\x8d", "crc\x02`&\x9aR\xe1\xb7\xfee\xb1\x93] \xeb\xa9am"},
}

func TestGolden(t *testing.T) {
	tabISO := MakeTable(ISO)
	tabECMA := MakeTable(ECMA)
	for i := 0; i < len(golden); i++ {
		g := golden[i]
		c := New(tabISO)
		io.WriteString(c, g.in)
		s := c.Sum64()
		if s != g.outISO {
			t.Fatalf("ISO crc64(%s) = 0x%x want 0x%x", g.in, s, g.outISO)
		}
		c = New(tabECMA)
		io.WriteString(c, g.in)
		s = c.Sum64()
		if s != g.outECMA {
			t.Fatalf("ECMA crc64(%s) = 0x%x want 0x%x", g.in, s, g.outECMA)
		}
	}
}

func TestGoldenMarshal(t *testing.T) {
	t.Run("ISO", func(t *testing.T) {
		table := MakeTable(ISO)
		for _, g := range golden {
			h := New(table)
			h2 := New(table)

			io.WriteString(h, g.in[:len(g.in)/2])

			state, err := h.(encoding.BinaryMarshaler).MarshalBinary()
			if err != nil {
				t.Errorf("could not marshal: %v", err)
				continue
			}

			stateAppend, err := h.(encoding.BinaryAppender).AppendBinary(make([]byte, 4, 32))
			if err != nil {
				t.Errorf("could not marshal: %v", err)
				continue
			}
			stateAppend = stateAppend[4:]

			if string(state) != g.halfStateISO {
				t.Errorf("ISO crc64(%q) state = %q, want %q", g.in, state, g.halfStateISO)
				continue
			}

			if string(stateAppend) != g.halfStateISO {
				t.Errorf("ISO crc64(%q) state = %q, want %q", g.in, stateAppend, g.halfStateISO)
				continue
			}

			if err := h2.(encoding.BinaryUnmarshaler).UnmarshalBinary(state); err != nil {
				t.Errorf("could not unmarshal: %v", err)
				continue
			}

			io.WriteString(h, g.in[len(g.in)/2:])
			io.WriteString(h2, g.in[len(g.in)/2:])

			if h.Sum64() != h2.Sum64() {
				t.Errorf("ISO crc64(%s) = 0x%x != marshaled (0x%x)", g.in, h.Sum64(), h2.Sum64())
			}
		}
	})
	t.Run("ECMA", func(t *testing.T) {
		table := MakeTable(ECMA)
		for _, g := range golden {
			h := New(table)
			h2 := New(table)

			io.WriteString(h, g.in[:len(g.in)/2])

			state, err := h.(encoding.BinaryMarshaler).MarshalBinary()
			if err != nil {
				t.Errorf("could not marshal: %v", err)
				continue
			}

			stateAppend, err := h.(encoding.BinaryAppender).AppendBinary(make([]byte, 4, 32))
			if err != nil {
				t.Errorf("could not marshal: %v", err)
				continue
			}
			stateAppend = stateAppend[4:]

			if string(state) != g.halfStateECMA {
				t.Errorf("ECMA crc64(%q) state = %q, want %q", g.in, state, g.halfStateECMA)
				continue
			}

			if string(stateAppend) != g.halfStateECMA {
				t.Errorf("ECMA crc64(%q) state = %q, want %q", g.in, stateAppend, g.halfStateECMA)
				continue
			}

			if err := h2.(encoding.BinaryUnmarshaler).UnmarshalBinary(state); err != nil {
				t.Errorf("could not unmarshal: %v", err)
				continue
			}

			io.WriteString(h, g.in[len(g.in)/2:])
			io.WriteString(h2, g.in[len(g.in)/2:])

			if h.Sum64() != h2.Sum64() {
				t.Errorf("ECMA crc64(%s) = 0x%x != marshaled (0x%x)", g.in, h.Sum64(), h2.Sum64())
			}
		}
	})
}

func TestMarshalTableMismatch(t *testing.T) {
	h1 := New(MakeTable(ISO))
	h2 := New(MakeTable(ECMA))

	state1, err := h1.(encoding.BinaryMarshaler).MarshalBinary()
	if err != nil {
		t.Errorf("could not marshal: %v", err)
	}

	if err := h2.(encoding.BinaryUnmarshaler).UnmarshalBinary(state1); err == nil {
		t.Errorf("no error when one was expected")
	}
}

func bench(b *testing.B, poly uint64, size int64) {
	b.SetBytes(size)
	data := make([]byte, size)
	for i := range data {
		data[i] = byte(i)
	}
	h := New(MakeTable(poly))
	in := make([]byte, 0, h.Size())

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		h.Reset()
		h.Write(data)
		h.Sum(in)
	}
}

func BenchmarkCrc64(b *testing.B) {
	b.Run("ISO64KB", func(b *testing.B) {
		bench(b, ISO, 64<<10)
	})
	b.Run("ISO4KB", func(b *testing.B) {
		bench(b, ISO, 4<<10)
	})
	b.Run("ISO1KB", func(b *testing.B) {
		bench(b, ISO, 1<<10)
	})
	b.Run("ECMA64KB", func(b *testing.B) {
		bench(b, ECMA, 64<<10)
	})
	b.Run("Random64KB", func(b *testing.B) {
		bench(b, 0x777, 64<<10)
	})
	b.Run("Random16KB", func(b *testing.B) {
		bench(b, 0x777, 16<<10)
	})
}
```