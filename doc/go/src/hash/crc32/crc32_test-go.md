Response:
我的目标是分析给定的 Go 代码片段（`go/src/hash/crc32/crc32_test.go` 的一部分），并用中文回答其功能，解释其实现的 Go 语言特性，提供代码示例，处理命令行参数（如果适用），并指出常见的错误。

**1. 理解代码的功能：**

我将逐行阅读代码，识别关键的函数、变量和测试用例。重点关注测试用例是如何验证 `crc32` 包的功能的。

*   `TestCastagnoliRace`:  看起来是为了测试并发场景下 `MakeTable(Castagnoli)` 的线程安全性。
*   `test` 结构体和 `golden` 变量： 存储了不同输入字符串和对应的 IEEE 及 Castagnoli CRC32 校验和，以及中间状态的 marshaled 数据。这显然是用于进行黄金标准测试。
*   `testGoldenIEEE` 和 `testGoldenCastagnoli`: 这两个函数使用 `golden` 数据来验证 CRC32 计算的正确性，分别针对 IEEE 和 Castagnoli 算法。
*   `testCrossCheck`: 这个函数生成随机数据，并使用不同的 CRC32 更新函数进行计算，以确保结果的一致性。这似乎是为了验证不同实现方式的正确性。
*   `TestSimple`: 测试了基于简单通用算法的 CRC32 计算。
*   `TestGoldenMarshal`:  测试了 CRC32 哈希状态的序列化和反序列化功能。这涉及 `encoding.BinaryMarshaler` 和 `encoding.BinaryUnmarshaler` 接口。
*   `TestMarshalTableMismatch`: 测试了尝试使用不匹配的 Table 进行反序列化是否会报错。
*   `TestSlicing`: 测试了基于 slicing 算法的 CRC32 计算，并与简单算法进行交叉验证。
*   `TestArchIEEE` 和 `TestArchCastagnoli`:  测试了特定架构优化的 CRC32 实现。
*   `TestGolden`:  总体的黄金标准测试，也包括了对数据分段写入的支持。
*   `BenchmarkCRC32` 和相关函数： 用于性能基准测试。

**2. 推理 Go 语言功能的实现：**

从代码结构和使用的包可以推断出：

*   **`hash` 包的使用**:  表明 `crc32` 包实现了 `hash.Hash32` 接口，提供了 `Write`，`Sum32` 和 `Reset` 等方法。
*   **`encoding` 包的使用**: 表明 `crc32` 的实现支持数据的序列化和反序列化，可能用于持久化或传输哈希状态。
*   **`testing` 包的使用**:  这是一个测试文件，使用了 Go 的标准测试框架。
*   **并发 (`go` 关键字)**:  `TestCastagnoliRace` 展示了对并发的支持和测试。

**3. 举例说明 Go 语言功能：**

我将选择 `encoding.BinaryMarshaler` 和 `encoding.BinaryUnmarshaler` 接口来举例说明，因为这是代码中一个比较明确的 Go 特性应用。

**4. 代码推理（带假设的输入与输出）：**

我将选择 `testGoldenIEEE` 函数，并假设一个 `golden` 变量中的条目，来演示其工作原理。

**5. 命令行参数处理：**

这个代码片段是一个测试文件，通常不直接处理命令行参数。但是，Go 的测试框架 `go test` 可以接受一些参数，例如 `-v` (显示详细输出)。我需要说明这一点。

**6. 易犯错的点：**

我将重点关注 `TestMarshalTableMismatch`  所测试的场景，即尝试使用错误的 Table 来反序列化 CRC32 的状态。这是使用者容易犯的错误。

**7. 组织答案：**

我将按照提问的顺序组织答案，使用清晰的中文进行解释，并在代码示例中添加注释。

**反思和微调：**

*   确保对每个测试用例的功能进行简明扼要的描述。
*   代码示例要简洁易懂，突出所解释的 Go 语言特性。
*   命令行参数部分需要解释清楚是 `go test` 命令的参数，而不是代码本身处理的参数。
*   易犯错的点要结合代码中的测试用例进行说明。

通过以上思考过程，我能够更系统地分析代码，并生成更准确和全面的答案。
这是一个 Go 语言的测试文件，用于测试 `hash/crc32` 包的功能。 从代码内容来看，它主要关注以下几个方面：

**1. CRC32 校验和计算的正确性:**

*   **功能:**  测试了使用 IEEE 和 Castagnoli 两种不同多项式计算 CRC32 校验和的正确性。
*   **实现:**  通过 `golden` 变量预定义了一系列输入字符串及其对应的正确 CRC32 校验和，然后使用 `testGoldenIEEE` 和 `testGoldenCastagnoli` 函数进行对比验证。
*   **代码示例:**

```go
import "testing"
import "hash/crc32"

func TestExampleIEEE(t *testing.T) {
	data := []byte("hello world")
	checksum := crc32.ChecksumIEEE(data)
	expected := uint32(0xd915b97e) // 假设的正确校验和
	if checksum != expected {
		t.Errorf("ChecksumIEEE(\"hello world\") = 0x%x, want 0x%x", checksum, expected)
	}
}

func TestExampleCastagnoli(t *testing.T) {
	data := []byte("hello world")
	castagnoliTable := crc32.MakeTable(crc32.Castagnoli)
	checksum := crc32.New(castagnoliTable).Sum32()
	crc := crc32.Update(0, castagnoliTable, data)
	expected := uint32(0xe410588a) // 假设的正确校验和
	if crc != expected {
		t.Errorf("Castagnoli(\"hello world\") = 0x%x, want 0x%x", crc, expected)
	}
}
```

*   **假设的输入与输出:**
    *   输入: 字符串 "hello world"
    *   使用 `crc32.ChecksumIEEE`: 输出 `0xd915b97e` (这是一个假设值，实际值需要根据 CRC32 算法计算)
    *   使用 Castagnoli 多项式: 输出 `0xe410588a` (这也是一个假设值)

**2. 不同 CRC32 计算方法的交叉验证:**

*   **功能:** 验证不同的 CRC32 计算实现（例如，简单实现 `simpleUpdate` 和 slicing 实现 `slicingUpdate`）对于相同的输入，能够得到相同的结果。
*   **实现:** `testCrossCheck` 函数生成随机长度的字节切片，并使用两个不同的 CRC32 更新函数进行计算，然后比较结果是否一致。
*   **代码示例:**  （这部分代码主要在测试文件中，不容易单独提取出来，因为它依赖于 `testCrossCheck` 函数）

**3. CRC32 哈希状态的序列化和反序列化:**

*   **功能:** 测试 `crc32.digest` 类型是否正确地实现了 `encoding.BinaryMarshaler` 和 `encoding.BinaryUnmarshaler` 接口，即可以将其内部状态序列化为二进制数据，并在之后恢复。
*   **实现:** `TestGoldenMarshal` 函数创建了两个相同的 CRC32 哈希对象，向其中一个写入一部分数据，然后将其状态序列化。接着，将序列化的状态反序列化到另一个哈希对象，并向两个对象写入剩余的数据。最后，比较它们的最终校验和是否一致。
*   **代码示例:**

```go
import (
	"bytes"
	"encoding/binary"
	"hash/crc32"
	"testing"
)

func TestMarshalUnmarshal(t *testing.T) {
	h1 := crc32.NewIEEE()
	h1.Write([]byte("part1"))

	// 序列化 h1 的状态
	marshaler, ok := h1.(binary.Marshaler)
	if !ok {
		t.Fatal("crc32.digest does not implement binary.Marshaler")
	}
	state, err := marshaler.MarshalBinary()
	if err != nil {
		t.Fatalf("Error marshaling: %v", err)
	}

	// 创建一个新的哈希对象 h2
	h2 := crc32.NewIEEE()
	unmarshaler, ok := h2.(binary.Unmarshaler)
	if !ok {
		t.Fatal("crc32.digest does not implement binary.Unmarshaler")
	}

	// 反序列化状态到 h2
	if err := unmarshaler.UnmarshalBinary(state); err != nil {
		t.Fatalf("Error unmarshaling: %v", err)
	}

	// 向 h1 和 h2 写入剩余的数据
	h1.Write([]byte("part2"))
	h2.Write([]byte("part2"))

	// 比较最终的校验和
	if h1.Sum32() != h2.Sum32() {
		t.Errorf("Sum32 mismatch after marshal/unmarshal: 0x%x != 0x%x", h1.Sum32(), h2.Sum32())
	}
}
```

*   **假设的输入与输出:**
    *   假设 `h1` 写入 "part1" 后的序列化状态为 `stateBytes` (一个字节切片)。
    *   反序列化 `stateBytes` 到 `h2` 后， `h2` 的内部状态应该与 `h1` 写入 "part1" 后的状态相同。
    *   最终 `h1.Sum32()` 和 `h2.Sum32()` 的输出应该一致。

**4. 尝试反序列化时 Table 不匹配的错误处理:**

*   **功能:** 验证当尝试使用与序列化时不同的 Table 反序列化 CRC32 哈希状态时，会产生错误。
*   **实现:** `TestMarshalTableMismatch` 函数创建了使用不同 Table 的两个 CRC32 哈希对象，然后尝试将一个对象的状态反序列化到另一个对象，并断言会发生错误。

**5. 不同架构优化实现的测试:**

*   **功能:**  测试针对特定 CPU 架构优化的 CRC32 计算实现（例如，使用 CPU 指令加速）。
*   **实现:** `TestArchIEEE` 和 `TestArchCastagnoli` 函数会检查当前架构是否支持相应的优化实现，如果支持，则使用架构特定的函数与通用的 slicing 实现进行交叉验证。

**6. 并发安全性测试:**

*   **功能:** 测试在并发环境下使用 `MakeTable(Castagnoli)` 是否安全，避免出现竞态条件。
*   **实现:** `TestCastagnoliRace` 函数并发地调用 `MakeTable(Castagnoli)` 和 `ieee.Write`，以检测潜在的竞态问题。

**7. 性能基准测试:**

*   **功能:**  测试不同 CRC32 计算方法的性能。
*   **实现:** `BenchmarkCRC32` 函数使用 Go 的 benchmark 框架来测量不同配置下 CRC32 计算的速度。

**涉及的 Go 语言功能:**

*   **`testing` 包:** 用于编写和运行单元测试和基准测试。
*   **`hash` 包:**  定义了哈希函数的接口，`crc32` 包实现了 `hash.Hash32` 接口。
*   **`io` 包:**  `io.WriteString` 用于向哈希对象写入字符串数据。
*   **`encoding` 包:** `encoding.BinaryMarshaler` 和 `encoding.BinaryUnmarshaler` 接口用于支持对象的序列化和反序列化。
*   **`math/rand` 包:** 用于生成随机数据进行交叉验证。
*   **`fmt` 包:** 用于格式化输出，例如在 benchmark 中生成测试用例名称。
*   **goroutine (`go` 关键字):**  用于测试并发安全性。

**命令行参数的具体处理:**

这个测试文件本身不直接处理命令行参数。但是，当你使用 `go test` 命令运行测试时，Go 的测试框架会处理一些参数，例如：

*   `-v`:  显示详细的测试输出，包括每个测试用例的名称和结果。
*   `-run <正则表达式>`:  只运行名称匹配指定正则表达式的测试用例。
*   `-bench <正则表达式>`:  只运行名称匹配指定正则表达式的基准测试。
*   `-cpuprofile <文件>`:  将 CPU profile 写入指定文件。
*   `-memprofile <文件>`:  将内存 profile 写入指定文件。

例如，要运行 `crc32_test.go` 文件中的所有测试用例，可以使用命令：

```bash
go test go/src/hash/crc32/crc32_test.go
```

要运行名称包含 "Golden" 的测试用例，可以使用命令：

```bash
go test -run Golden go/src/hash/crc32/crc32_test.go
```

要运行所有的基准测试，可以使用命令：

```bash
go test -bench . go/src/hash/crc32/crc32_test.go
```

**使用者易犯错的点:**

*   **使用错误的 Table 进行反序列化:**  正如 `TestMarshalTableMismatch` 所测试的，如果你尝试使用与序列化时不同的 Table 来反序列化 CRC32 的状态，会导致错误或不可预测的结果。  例如：

```go
import (
	"encoding/binary"
	"hash/crc32"
	"testing"
)

func ExampleWrongTableUnmarshal(t *testing.T) {
	h1 := crc32.NewIEEE()
	state, _ := binary.Marshal(h1) // 假设这里简化了 Marshal 操作

	h2 := crc32.New(crc32.MakeTable(crc32.Castagnoli)) // 使用了不同的 Table
	err := binary.Unmarshal(state, h2) // 尝试使用错误的 Table 反序列化
	if err == nil {
		t.Error("Expected an error when unmarshaling with a different table")
	}
}
```

在这个例子中，`h1` 使用了 IEEE Table，而 `h2` 使用了 Castagnoli Table。尝试将 `h1` 的状态反序列化到 `h2` 会导致错误，因为状态中包含了 Table 的信息，而 `h2` 的 Table 与之不匹配。

总而言之，这个测试文件非常全面地测试了 `hash/crc32` 包的各种功能，包括不同多项式的计算正确性、不同实现的一致性、状态的序列化和反序列化、并发安全性以及性能。

Prompt: 
```
这是路径为go/src/hash/crc32/crc32_test.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。

"""
// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package crc32

import (
	"encoding"
	"fmt"
	"hash"
	"io"
	"math/rand"
	"testing"
)

// First test, so that it can be the one to initialize castagnoliTable.
func TestCastagnoliRace(t *testing.T) {
	// The MakeTable(Castagnoli) lazily initializes castagnoliTable,
	// which races with the switch on tab during Write to check
	// whether tab == castagnoliTable.
	ieee := NewIEEE()
	go MakeTable(Castagnoli)
	ieee.Write([]byte("hello"))
}

type test struct {
	ieee, castagnoli    uint32
	in                  string
	halfStateIEEE       string // IEEE marshaled hash state after first half of in written, used by TestGoldenMarshal
	halfStateCastagnoli string // Castagnoli marshaled hash state after first half of in written, used by TestGoldenMarshal
}

var golden = []test{
	{0x0, 0x0, "", "crc\x01ʇ\x91M\x00\x00\x00\x00", "crc\x01wB\x84\x81\x00\x00\x00\x00"},
	{0xe8b7be43, 0xc1d04330, "a", "crc\x01ʇ\x91M\x00\x00\x00\x00", "crc\x01wB\x84\x81\x00\x00\x00\x00"},
	{0x9e83486d, 0xe2a22936, "ab", "crc\x01ʇ\x91M跾C", "crc\x01wB\x84\x81\xc1\xd0C0"},
	{0x352441c2, 0x364b3fb7, "abc", "crc\x01ʇ\x91M跾C", "crc\x01wB\x84\x81\xc1\xd0C0"},
	{0xed82cd11, 0x92c80a31, "abcd", "crc\x01ʇ\x91M\x9e\x83Hm", "crc\x01wB\x84\x81\xe2\xa2)6"},
	{0x8587d865, 0xc450d697, "abcde", "crc\x01ʇ\x91M\x9e\x83Hm", "crc\x01wB\x84\x81\xe2\xa2)6"},
	{0x4b8e39ef, 0x53bceff1, "abcdef", "crc\x01ʇ\x91M5$A\xc2", "crc\x01wB\x84\x816K?\xb7"},
	{0x312a6aa6, 0xe627f441, "abcdefg", "crc\x01ʇ\x91M5$A\xc2", "crc\x01wB\x84\x816K?\xb7"},
	{0xaeef2a50, 0xa9421b7, "abcdefgh", "crc\x01ʇ\x91M\xed\x82\xcd\x11", "crc\x01wB\x84\x81\x92\xc8\n1"},
	{0x8da988af, 0x2ddc99fc, "abcdefghi", "crc\x01ʇ\x91M\xed\x82\xcd\x11", "crc\x01wB\x84\x81\x92\xc8\n1"},
	{0x3981703a, 0xe6599437, "abcdefghij", "crc\x01ʇ\x91M\x85\x87\xd8e", "crc\x01wB\x84\x81\xc4P֗"},
	{0x6b9cdfe7, 0xb2cc01fe, "Discard medicine more than two years old.", "crc\x01ʇ\x91M\xfd\xe5\xc2J", "crc\x01wB\x84\x81S\"(\xe0"},
	{0xc90ef73f, 0xe28207f, "He who has a shady past knows that nice guys finish last.", "crc\x01ʇ\x91M\x01ǋ+", "crc\x01wB\x84\x81'\xdaR\x15"},
	{0xb902341f, 0xbe93f964, "I wouldn't marry him with a ten foot pole.", "crc\x01ʇ\x91M\x9d\x13\xce\x10", "crc\x01wB\x84\x81\xc3\xed\xabG"},
	{0x42080e8, 0x9e3be0c3, "Free! Free!/A trip/to Mars/for 900/empty jars/Burma Shave", "crc\x01ʇ\x91M-\xed\xf7\x94", "crc\x01wB\x84\x81\xce\xceb\x81"},
	{0x154c6d11, 0xf505ef04, "The days of the digital watch are numbered.  -Tom Stoppard", "crc\x01ʇ\x91MOa\xa5\r", "crc\x01wB\x84\x81\xd3s\x9dP"},
	{0x4c418325, 0x85d3dc82, "Nepal premier won't resign.", "crc\x01ʇ\x91M\xa8S9\x85", "crc\x01wB\x84\x81{\x90\x8a\x14"},
	{0x33955150, 0xc5142380, "For every action there is an equal and opposite government program.", "crc\x01ʇ\x91Ma\xe9>\x86", "crc\x01wB\x84\x81\xaa@\xc4\x1c"},
	{0x26216a4b, 0x75eb77dd, "His money is twice tainted: 'taint yours and 'taint mine.", "crc\x01ʇ\x91M\\\x1an\x88", "crc\x01wB\x84\x81W\a8Z"},
	{0x1abbe45e, 0x91ebe9f7, "There is no reason for any individual to have a computer in their home. -Ken Olsen, 1977", "crc\x01ʇ\x91M\xb7\xf5\xf2\xca", "crc\x01wB\x84\x81\xc4o\x9d\x85"},
	{0xc89a94f7, 0xf0b1168e, "It's a tiny change to the code and not completely disgusting. - Bob Manchek", "crc\x01ʇ\x91M\x84g1\xe8", "crc\x01wB\x84\x81#\x98\f\xab"},
	{0xab3abe14, 0x572b74e2, "size:  a.out:  bad magic", "crc\x01ʇ\x91M\x8a\x0f\xad\b", "crc\x01wB\x84\x81\x80\xc9n\xd8"},
	{0xbab102b6, 0x8a58a6d5, "The major problem is with sendmail.  -Mark Horton", "crc\x01ʇ\x91M\a\xf0\xb3\x15", "crc\x01wB\x84\x81liS\xcc"},
	{0x999149d7, 0x9c426c50, "Give me a rock, paper and scissors and I will move the world.  CCFestoon", "crc\x01ʇ\x91M\x0fa\xbc.", "crc\x01wB\x84\x81\xdb͏C"},
	{0x6d52a33c, 0x735400a4, "If the enemy is within range, then so are you.", "crc\x01ʇ\x91My\x1b\x99\xf8", "crc\x01wB\x84\x81\xaaB\x037"},
	{0x90631e8d, 0xbec49c95, "It's well we cannot hear the screams/That we create in others' dreams.", "crc\x01ʇ\x91M\bqfY", "crc\x01wB\x84\x81\x16y\xa1\xd2"},
	{0x78309130, 0xa95a2079, "You remind me of a TV show, but that's all right: I watch it anyway.", "crc\x01ʇ\x91M\xbdO,\xc2", "crc\x01wB\x84\x81f&\xc5\xe4"},
	{0x7d0a377f, 0xde2e65c5, "C is as portable as Stonehedge!!", "crc\x01ʇ\x91M\xf7\xd6\x00\xd5", "crc\x01wB\x84\x81de\\\xf8"},
	{0x8c79fd79, 0x297a88ed, "Even if I could be Shakespeare, I think I should still choose to be Faraday. - A. Huxley", "crc\x01ʇ\x91Ml+\xb8\xa7", "crc\x01wB\x84\x81\xbf\xd6S\xdd"},
	{0xa20b7167, 0x66ed1d8b, "The fugacity of a constituent in a mixture of gases at a given temperature is proportional to its mole fraction.  Lewis-Randall Rule", "crc\x01ʇ\x91M<lR[", "crc\x01wB\x84\x81{\xaco\xb1"},
	{0x8e0bb443, 0xdcded527, "How can you write a big system without C++?  -Paul Glick", "crc\x01ʇ\x91M\x0e\x88\x89\xed", "crc\x01wB\x84\x813\xd7C\u007f"},
}

// testGoldenIEEE verifies that the given function returns
// correct IEEE checksums.
func testGoldenIEEE(t *testing.T, crcFunc func(b []byte) uint32) {
	for _, g := range golden {
		if crc := crcFunc([]byte(g.in)); crc != g.ieee {
			t.Errorf("IEEE(%s) = 0x%x want 0x%x", g.in, crc, g.ieee)
		}
	}
}

// testGoldenCastagnoli verifies that the given function returns
// correct IEEE checksums.
func testGoldenCastagnoli(t *testing.T, crcFunc func(b []byte) uint32) {
	for _, g := range golden {
		if crc := crcFunc([]byte(g.in)); crc != g.castagnoli {
			t.Errorf("Castagnoli(%s) = 0x%x want 0x%x", g.in, crc, g.castagnoli)
		}
	}
}

// testCrossCheck generates random buffers of various lengths and verifies that
// the two "update" functions return the same result.
func testCrossCheck(t *testing.T, crcFunc1, crcFunc2 func(crc uint32, b []byte) uint32) {
	// The AMD64 implementation has some cutoffs at lengths 168*3=504 and
	// 1344*3=4032. We should make sure lengths around these values are in the
	// list.
	lengths := []int{0, 1, 2, 3, 4, 5, 10, 16, 50, 63, 64, 65, 100,
		127, 128, 129, 255, 256, 257, 300, 312, 384, 416, 448, 480,
		500, 501, 502, 503, 504, 505, 512, 513, 1000, 1024, 2000,
		4030, 4031, 4032, 4033, 4036, 4040, 4048, 4096, 5000, 10000}
	for _, length := range lengths {
		p := make([]byte, length)
		_, _ = rand.Read(p)
		crcInit := uint32(rand.Int63())
		crc1 := crcFunc1(crcInit, p)
		crc2 := crcFunc2(crcInit, p)
		if crc1 != crc2 {
			t.Errorf("mismatch: 0x%x vs 0x%x (buffer length %d)", crc1, crc2, length)
		}
	}
}

// TestSimple tests the simple generic algorithm.
func TestSimple(t *testing.T) {
	tab := simpleMakeTable(IEEE)
	testGoldenIEEE(t, func(b []byte) uint32 {
		return simpleUpdate(0, tab, b)
	})

	tab = simpleMakeTable(Castagnoli)
	testGoldenCastagnoli(t, func(b []byte) uint32 {
		return simpleUpdate(0, tab, b)
	})
}

func TestGoldenMarshal(t *testing.T) {
	t.Run("IEEE", func(t *testing.T) {
		for _, g := range golden {
			h := New(IEEETable)
			h2 := New(IEEETable)

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

			if string(state) != g.halfStateIEEE {
				t.Errorf("IEEE(%q) state = %q, want %q", g.in, state, g.halfStateIEEE)
				continue
			}

			if string(stateAppend) != g.halfStateIEEE {
				t.Errorf("IEEE(%q) state = %q, want %q", g.in, stateAppend, g.halfStateIEEE)
				continue
			}

			if err := h2.(encoding.BinaryUnmarshaler).UnmarshalBinary(state); err != nil {
				t.Errorf("could not unmarshal: %v", err)
				continue
			}

			io.WriteString(h, g.in[len(g.in)/2:])
			io.WriteString(h2, g.in[len(g.in)/2:])

			if h.Sum32() != h2.Sum32() {
				t.Errorf("IEEE(%s) = 0x%x != marshaled 0x%x", g.in, h.Sum32(), h2.Sum32())
			}
		}
	})
	t.Run("Castagnoli", func(t *testing.T) {
		table := MakeTable(Castagnoli)
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

			if string(state) != g.halfStateCastagnoli {
				t.Errorf("Castagnoli(%q) state = %q, want %q", g.in, state, g.halfStateCastagnoli)
				continue
			}

			if string(stateAppend) != g.halfStateCastagnoli {
				t.Errorf("Castagnoli(%q) state = %q, want %q", g.in, stateAppend, g.halfStateCastagnoli)
				continue
			}

			if err := h2.(encoding.BinaryUnmarshaler).UnmarshalBinary(state); err != nil {
				t.Errorf("could not unmarshal: %v", err)
				continue
			}

			io.WriteString(h, g.in[len(g.in)/2:])
			io.WriteString(h2, g.in[len(g.in)/2:])

			if h.Sum32() != h2.Sum32() {
				t.Errorf("Castagnoli(%s) = 0x%x != marshaled 0x%x", g.in, h.Sum32(), h2.Sum32())
			}
		}
	})
}

func TestMarshalTableMismatch(t *testing.T) {
	h1 := New(IEEETable)
	h2 := New(MakeTable(Castagnoli))

	state1, err := h1.(encoding.BinaryMarshaler).MarshalBinary()
	if err != nil {
		t.Errorf("could not marshal: %v", err)
	}

	if err := h2.(encoding.BinaryUnmarshaler).UnmarshalBinary(state1); err == nil {
		t.Errorf("no error when one was expected")
	}
}

// TestSlicing tests the slicing-by-8 algorithm.
func TestSlicing(t *testing.T) {
	tab := slicingMakeTable(IEEE)
	testGoldenIEEE(t, func(b []byte) uint32 {
		return slicingUpdate(0, tab, b)
	})

	tab = slicingMakeTable(Castagnoli)
	testGoldenCastagnoli(t, func(b []byte) uint32 {
		return slicingUpdate(0, tab, b)
	})

	// Cross-check various polys against the simple algorithm.
	for _, poly := range []uint32{IEEE, Castagnoli, Koopman, 0xD5828281} {
		t1 := simpleMakeTable(poly)
		f1 := func(crc uint32, b []byte) uint32 {
			return simpleUpdate(crc, t1, b)
		}
		t2 := slicingMakeTable(poly)
		f2 := func(crc uint32, b []byte) uint32 {
			return slicingUpdate(crc, t2, b)
		}
		testCrossCheck(t, f1, f2)
	}
}

func TestArchIEEE(t *testing.T) {
	if !archAvailableIEEE() {
		t.Skip("Arch-specific IEEE not available.")
	}
	archInitIEEE()
	slicingTable := slicingMakeTable(IEEE)
	testCrossCheck(t, archUpdateIEEE, func(crc uint32, b []byte) uint32 {
		return slicingUpdate(crc, slicingTable, b)
	})
}

func TestArchCastagnoli(t *testing.T) {
	if !archAvailableCastagnoli() {
		t.Skip("Arch-specific Castagnoli not available.")
	}
	archInitCastagnoli()
	slicingTable := slicingMakeTable(Castagnoli)
	testCrossCheck(t, archUpdateCastagnoli, func(crc uint32, b []byte) uint32 {
		return slicingUpdate(crc, slicingTable, b)
	})
}

func TestGolden(t *testing.T) {
	testGoldenIEEE(t, ChecksumIEEE)

	// Some implementations have special code to deal with misaligned
	// data; test that as well.
	for delta := 1; delta <= 7; delta++ {
		testGoldenIEEE(t, func(b []byte) uint32 {
			ieee := NewIEEE()
			d := delta
			if d >= len(b) {
				d = len(b)
			}
			ieee.Write(b[:d])
			ieee.Write(b[d:])
			return ieee.Sum32()
		})
	}

	castagnoliTab := MakeTable(Castagnoli)
	if castagnoliTab == nil {
		t.Errorf("nil Castagnoli Table")
	}

	testGoldenCastagnoli(t, func(b []byte) uint32 {
		castagnoli := New(castagnoliTab)
		castagnoli.Write(b)
		return castagnoli.Sum32()
	})

	// Some implementations have special code to deal with misaligned
	// data; test that as well.
	for delta := 1; delta <= 7; delta++ {
		testGoldenCastagnoli(t, func(b []byte) uint32 {
			castagnoli := New(castagnoliTab)
			d := delta
			if d >= len(b) {
				d = len(b)
			}
			castagnoli.Write(b[:d])
			castagnoli.Write(b[d:])
			return castagnoli.Sum32()
		})
	}
}

func BenchmarkCRC32(b *testing.B) {
	b.Run("poly=IEEE", benchmarkAll(NewIEEE()))
	b.Run("poly=Castagnoli", benchmarkAll(New(MakeTable(Castagnoli))))
	b.Run("poly=Koopman", benchmarkAll(New(MakeTable(Koopman))))
}

func benchmarkAll(h hash.Hash32) func(b *testing.B) {
	return func(b *testing.B) {
		for _, size := range []int{15, 40, 512, 1 << 10, 4 << 10, 32 << 10} {
			name := fmt.Sprint(size)
			if size >= 1024 {
				name = fmt.Sprintf("%dkB", size/1024)
			}
			b.Run("size="+name, func(b *testing.B) {
				for align := 0; align <= 1; align++ {
					b.Run(fmt.Sprintf("align=%d", align), func(b *testing.B) {
						benchmark(b, h, int64(size), int64(align))
					})
				}
			})
		}
	}
}

func benchmark(b *testing.B, h hash.Hash32, n, alignment int64) {
	b.SetBytes(n)
	data := make([]byte, n+alignment)
	data = data[alignment:]
	for i := range data {
		data[i] = byte(i)
	}
	in := make([]byte, 0, h.Size())

	// Warm up
	h.Reset()
	h.Write(data)
	h.Sum(in)
	// Avoid further allocations
	in = in[:0]

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		h.Reset()
		h.Write(data)
		h.Sum(in)
		in = in[:0]
	}
}

"""



```