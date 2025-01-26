Response:
Let's break down the thought process for analyzing the provided Go code snippet for `entry_test.go`.

**1. Initial Understanding of the File Path and Name:**

* The file path `go/src/debug/dwarf/entry_test.go` immediately tells us a few key things:
    * It's part of the Go standard library (`go/src`).
    * It belongs to the `debug/dwarf` package, which deals with parsing and interpreting DWARF debugging information.
    * The `_test.go` suffix indicates this is a test file.
    * The `entry` part suggests it likely focuses on testing the handling of DWARF entries (the basic building blocks of DWARF information).

**2. Examining the Imports:**

* `debug/dwarf`: This confirms the core purpose of the tests – verifying the functionality of the `debug/dwarf` package itself.
* `encoding/binary`:  Suggests that the code might be dealing with the binary format of DWARF data, likely for handling endianness or parsing specific data types.
* `path/filepath`: This hints at interaction with the file system, likely for loading test data from files.
* `reflect`: This strongly suggests that the tests involve comparing complex data structures for equality, which is common in testing.
* `testing`: The standard Go testing package, confirming the file's purpose.
* The dot import `.` for `debug/dwarf` is a bit unusual but means the tests can directly access exported members of the `debug/dwarf` package without the package qualifier (e.g., `TagCompileUnit` instead of `dwarf.TagCompileUnit`). This is often done in test files for brevity.

**3. Analyzing Individual Test Functions:**

* **`TestSplit(t *testing.T)`:**
    * The comment `// debug/dwarf doesn't (currently) support split DWARF...` is a crucial piece of information. It reveals the *negative* goal of the test: to ensure the code *doesn't fail* when encountering split DWARF attributes, even though full support isn't implemented.
    * It loads DWARF data from `testdata/split.elf`.
    * It checks that a `TagCompileUnit` entry is read.
    * It specifically looks for an attribute `AttrGNUAddrBase` and verifies its type and class. The existence of a custom `Attr` constant (0x2133) and the `ClassUnknown` assertion indicate handling of potentially unrecognized DWARF extensions.

* **`TestReaderSeek(t *testing.T)` and `TestRangesSection(t *testing.T)` and `TestRangesRnglistx(t *testing.T)`:**
    * The name `TestReaderSeek` and the presence of a `wantRange` struct strongly suggest this tests the ability of the DWARF reader to efficiently locate DWARF entries based on program counter (PC) values.
    * The `wantRange` struct holds a PC and expected address ranges for the compilation unit containing that PC.
    * `testRanges` is a helper function used by these tests. It loads DWARF data from different ELF files and uses `r.SeekPC(w.pc)` to find the entry corresponding to the given PC. It then calls `d.Ranges(entry)` to retrieve the address ranges and compares them against the expected values.
    * `TestRangesSection` and `TestRangesRnglistx` likely test different ways address ranges are stored in DWARF (directly in sections vs. using index tables).

* **`TestReaderRanges(t *testing.T)`:**
    * This test appears to iterate through DWARF entries and specifically checks entries with `TagSubprogram`.
    * It verifies the name and address ranges associated with each subprogram. This likely tests the correct parsing and association of address range information with function definitions.

* **`Test64Bit(t *testing.T)`:**
    * The comment `// I don't know how to generate a 64-bit DWARF debug...` is informative.
    * This test constructs DWARF data in memory (instead of loading from a file) to test handling of 32-bit and 64-bit DWARF formats, as well as different endianness. It checks the `AddressSize()` and `ByteOrder()` of the reader.

* **`TestUnitIteration(t *testing.T)`:**
    * This test checks the consistency of iterating through compilation units, both by sequentially reading entries and by using `r.SkipChildren()`. It ensures that both methods find the same set of compilation units.

* **`TestIssue51758(t *testing.T)` and `TestIssue52045(t *testing.T)`:**
    * These tests are explicitly designed to address specific bug reports (issues 51758 and 52045).
    * `TestIssue51758` focuses on handling malformed or truncated DWARF data without panicking.
    * `TestIssue52045` likely tests a scenario with minimal DWARF information (empty abbrev table).

**4. Inferring Go Language Features:**

* The code heavily uses the `debug/dwarf` package, demonstrating how to parse and interpret DWARF debugging information.
* It showcases the use of `d.Reader()` to get a reader for iterating through DWARF entries.
* The use of `r.Next()` and `r.SeekPC()` demonstrates different ways to navigate DWARF data.
* The `entry.Tag` and `entry.Val(AttrName)` calls show how to access information within a DWARF entry.
* The `d.Ranges(entry)` call illustrates how to retrieve address ranges associated with an entry.
* The `reflect.DeepEqual()` function highlights the need for deep comparison of complex data structures.

**5. Identifying Potential User Errors:**

* The `TestSplit` function hints at a potential error: assuming that all DWARF attributes will have a known class. Users might need to handle `ClassUnknown` attributes.
* The tests involving `SeekPC` and `Ranges` suggest that users might incorrectly assume that a valid address range will always be found for a given PC. The `ErrUnknownPC` error needs to be handled.

**6. Considering Command-Line Arguments:**

* The code itself doesn't directly process command-line arguments. The `testing` package handles running the tests. However, the tests load data files, so the location of these files could be considered an implicit dependency. If the `testdata` directory is not in the expected location, the tests will fail.

By following these steps, we can systematically analyze the code and extract its functionality, infer the underlying Go features, and identify potential issues or areas for user caution. The key is to start with the high-level context and progressively delve into the details of each function and the imported packages.
这段Go语言代码是 `debug/dwarf` 包的一部分，专门用于测试DWARF调试信息的解析和读取功能，特别是针对 DWARF 条目 (entries) 的处理。

以下是它的主要功能：

**1. 测试对 Split DWARF 的基本读取能力:**

   * **功能:** `TestSplit` 函数测试了即使 `debug/dwarf` 包目前不支持 Split DWARF (将调试信息分散在不同的文件中)，它至少能够读取包含指向 Split DWARF 的属性的 DWARF 数据而不会完全失败。
   * **实现原理:** 该测试加载一个包含 Split DWARF 相关属性的 ELF 文件 (`testdata/split.elf`)，然后读取它的 DWARF 信息。它特别检查了是否能解析一个未知的 section offset 字段 (`AttrGNUAddrBase`)，即使无法确定其 DWARF 类。
   * **Go 代码示例:**
     ```go
     package main

     import (
         "debug/dwarf"
         "debug/elf"
         "fmt"
         "log"
     )

     func main() {
         f, err := elf.Open("testdata/split.elf") // 假设 split.elf 文件存在
         if err != nil {
             log.Fatal(err)
         }
         defer f.Close()

         dwarfData, err := f.DWARF()
         if err != nil {
             log.Fatal(err)
         }

         reader := dwarfData.Reader()
         entry, err := reader.Next()
         if err != nil {
             log.Fatal(err)
         }

         if entry.Tag == dwarf.TagCompileUnit {
             fmt.Println("Successfully read Compile Unit tag")
             // 尝试访问特定的属性
             const AttrGNUAddrBase dwarf.Attr = 0x2133
             attr := entry.AttrField(AttrGNUAddrBase)
             if attr != nil {
                 fmt.Printf("Found attribute %v with value type %T and class %v\n", AttrGNUAddrBase, attr.Val, attr.Class)
             } else {
                 fmt.Println("Attribute AttrGNUAddrBase not found")
             }
         }
     }
     ```
     **假设输入:**  `testdata/split.elf` 文件包含 DWARF 信息，其中包含一个类型为 `TagCompileUnit` 的条目，并且该条目包含一个 `AttrGNUAddrBase` 属性。
     **预期输出:**  程序将输出 "Successfully read Compile Unit tag" 和 "Found attribute 0x2133 with value type int64 and class Unknown"。

**2. 测试 DWARF Reader 的 PC 查找功能:**

   * **功能:** `TestReaderSeek` 函数测试了 `dwarf.Reader` 的 `SeekPC` 方法，该方法用于查找包含给定程序计数器 (PC) 的编译单元 (Compilation Unit)。
   * **实现原理:** 它定义了一个 `wantRange` 结构体来存储要查找的 PC 值以及期望的地址范围。然后，它使用不同的 ELF 文件（包含不同的 DWARF 信息，如不同版本的 DWARF 或压缩方式）进行测试，验证 `SeekPC` 是否能正确找到对应的编译单元，并使用 `d.Ranges` 方法获取该编译单元的地址范围，与预期值进行比较。
   * **Go 代码示例:**
     ```go
     package main

     import (
         "debug/dwarf"
         "debug/elf"
         "fmt"
         "log"
     )

     func main() {
         f, err := elf.Open("testdata/line-gcc.elf") // 假设 line-gcc.elf 文件存在
         if err != nil {
             log.Fatal(err)
         }
         defer f.Close()

         dwarfData, err := f.DWARF()
         if err != nil {
             log.Fatal(err)
         }

         reader := dwarfData.Reader()
         pc := uint64(0x40059d)
         entry, err := reader.SeekPC(pc)
         if err != nil {
             log.Fatalf("Error seeking PC %#x: %v", pc, err)
         }

         if entry != nil && entry.Tag == dwarf.TagCompileUnit {
             ranges, err := dwarfData.Ranges(entry)
             if err != nil {
                 log.Fatalf("Error getting ranges: %v", err)
             }
             fmt.Printf("Found Compilation Unit for PC %#x with ranges: %v\n", pc, ranges)
         } else {
             fmt.Printf("No Compilation Unit found for PC %#x\n", pc)
         }
     }
     ```
     **假设输入:** `testdata/line-gcc.elf` 文件包含 DWARF 信息。
     **预期输出:**  程序将输出 "Found Compilation Unit for PC 0x40059d with ranges: [[1073808861 1073808961]]" (实际数值可能因编译而异）。

**3. 测试获取 DWARF 条目的地址范围:**

   * **功能:** `TestRangesSection` 和 `TestRangesRnglistx` 函数测试了从 DWARF 信息中获取特定条目的地址范围的功能。`TestRangesSection` 针对直接在 `.debug_ranges` 节中定义的范围，而 `TestRangesRnglistx` 针对使用 `.debug_rnglists` 和 `.debug_rnglistx` 节定义的范围（DWARF5 新增）。
   * **实现原理:**  与 `TestReaderSeek` 类似，它们加载包含不同地址范围信息的 ELF 文件，并使用 `d.Ranges` 方法获取特定编译单元的地址范围并进行比较。

**4. 测试遍历 DWARF 条目并获取子程序范围:**

   * **功能:** `TestReaderRanges` 函数测试了遍历 DWARF 信息并获取所有子程序 (TagSubprogram) 的地址范围。
   * **实现原理:** 它加载不同的 ELF 文件，遍历 DWARF 条目，当遇到 `TagSubprogram` 类型的条目时，获取其名称和地址范围，并与预期的值进行比较。

**5. 测试处理不同位数的 DWARF 信息:**

   * **功能:** `Test64Bit` 函数测试了 `debug/dwarf` 包处理 32 位和 64 位 DWARF 调试信息的能力，以及对不同字节序 (endianness) 的支持。
   * **实现原理:** 它不依赖于外部文件，而是手动构造了包含 32 位和 64 位 DWARF 头部信息的字节数组，并使用 `New` 函数创建 `dwarf.Data` 对象，然后检查读取器的地址大小和字节序是否正确。

**6. 测试单元迭代的一致性:**

   * **功能:** `TestUnitIteration` 函数测试了以两种不同的方式迭代编译单元时，是否能得到相同的结果。
   * **实现原理:** 它遍历所有 `testdata` 目录下的 ELF 文件，并使用两种方法迭代编译单元：一种是简单地调用 `r.Next()`，另一种是在遇到非编译单元条目时调用 `r.SkipChildren()` 跳过其子条目。然后比较两种方法得到的编译单元集合是否一致。

**7. 测试处理格式错误的 DWARF 数据:**

   * **功能:** `TestIssue51758` 函数旨在测试当遇到格式错误的 DWARF 数据时，`debug/dwarf` 包是否能安全地处理，避免 panic 或其他不良行为。
   * **实现原理:** 它构造了一些包含错误或截断的 DWARF 数据的字节数组，尝试使用 `New` 函数创建 `dwarf.Data` 对象，并断言会返回错误。

**8. 测试处理极简的 DWARF 数据:**

   * **功能:** `TestIssue52045` 函数测试了处理包含最少信息的 DWARF 数据（例如，只有头部，没有 DIEs，并且 abbrev 表为空）的情况。
   * **实现原理:** 它构造了一个包含最小 .debug_info 和空 abbrev 表的 DWARF 数据，尝试创建一个 `dwarf.Data` 对象，并尝试使用 `SeekPC` 方法，主要目的是确保不会崩溃。

**关于命令行参数的具体处理:**

这段代码本身是测试代码，不直接处理命令行参数。测试的运行通常是通过 `go test` 命令，该命令会执行当前目录或指定包下的所有测试函数。

**使用者易犯错的点:**

* **假设所有 DWARF 文件都遵循严格的标准:**  `TestSplit` 提醒我们，有时会遇到包含非标准或扩展属性的 DWARF 信息。使用者在解析 DWARF 信息时，应该考虑到这种情况，并采取适当的措施来处理未知属性，而不是假设所有属性都有预期的结构和类型。
* **错误地假设 `SeekPC` 总能找到条目:**  `TestReaderSeek` 明确测试了 `SeekPC` 在找不到匹配的编译单元时返回 `ErrUnknownPC`。使用者需要正确处理这个错误，而不是假设对于任何 PC 值都能找到对应的 DWARF 条目。
* **忽略错误处理:** 在实际使用 `debug/dwarf` 包时，任何解析和读取操作都可能返回错误。使用者需要仔细检查并处理这些错误，例如在调用 `r.Next()`, `r.SeekPC()`, `d.Ranges()` 等方法时。

总而言之，这段测试代码覆盖了 `debug/dwarf` 包中关于 DWARF 条目处理的多个重要方面，包括基本读取、PC 查找、地址范围获取、不同 DWARF 格式的支持以及对错误数据的健壮性。它帮助确保 `debug/dwarf` 包能够正确且可靠地解析和使用 DWARF 调试信息。

Prompt: 
```
这是路径为go/src/debug/dwarf/entry_test.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。

"""
// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package dwarf_test

import (
	. "debug/dwarf"
	"encoding/binary"
	"path/filepath"
	"reflect"
	"testing"
)

func TestSplit(t *testing.T) {
	// debug/dwarf doesn't (currently) support split DWARF, but
	// the attributes that pointed to the split DWARF used to
	// cause loading the DWARF data to fail entirely (issue
	// #12592). Test that we can at least read the DWARF data.
	d := elfData(t, "testdata/split.elf")
	r := d.Reader()
	e, err := r.Next()
	if err != nil {
		t.Fatal(err)
	}
	if e.Tag != TagCompileUnit {
		t.Fatalf("bad tag: have %s, want %s", e.Tag, TagCompileUnit)
	}
	// Check that we were able to parse the unknown section offset
	// field, even if we can't figure out its DWARF class.
	const AttrGNUAddrBase Attr = 0x2133
	f := e.AttrField(AttrGNUAddrBase)
	if _, ok := f.Val.(int64); !ok {
		t.Fatalf("bad attribute value type: have %T, want int64", f.Val)
	}
	if f.Class != ClassUnknown {
		t.Fatalf("bad class: have %s, want %s", f.Class, ClassUnknown)
	}
}

// wantRange maps from a PC to the ranges of the compilation unit
// containing that PC.
type wantRange struct {
	pc     uint64
	ranges [][2]uint64
}

func TestReaderSeek(t *testing.T) {
	want := []wantRange{
		{0x40059d, [][2]uint64{{0x40059d, 0x400601}}},
		{0x400600, [][2]uint64{{0x40059d, 0x400601}}},
		{0x400601, [][2]uint64{{0x400601, 0x400611}}},
		{0x4005f0, [][2]uint64{{0x40059d, 0x400601}}}, // loop test
		{0x10, nil},
		{0x400611, nil},
	}
	testRanges(t, "testdata/line-gcc.elf", want)

	want = []wantRange{
		{0x401122, [][2]uint64{{0x401122, 0x401166}}},
		{0x401165, [][2]uint64{{0x401122, 0x401166}}},
		{0x401166, [][2]uint64{{0x401166, 0x401179}}},
	}
	testRanges(t, "testdata/line-gcc-dwarf5.elf", want)

	want = []wantRange{
		{0x401130, [][2]uint64{{0x401130, 0x40117e}}},
		{0x40117d, [][2]uint64{{0x401130, 0x40117e}}},
		{0x40117e, nil},
	}
	testRanges(t, "testdata/line-clang-dwarf5.elf", want)

	want = []wantRange{
		{0x401126, [][2]uint64{{0x401126, 0x40116a}}},
		{0x40116a, [][2]uint64{{0x40116a, 0x401180}}},
	}
	testRanges(t, "testdata/line-gcc-zstd.elf", want)
}

func TestRangesSection(t *testing.T) {
	want := []wantRange{
		{0x400500, [][2]uint64{{0x400500, 0x400549}, {0x400400, 0x400408}}},
		{0x400400, [][2]uint64{{0x400500, 0x400549}, {0x400400, 0x400408}}},
		{0x400548, [][2]uint64{{0x400500, 0x400549}, {0x400400, 0x400408}}},
		{0x400407, [][2]uint64{{0x400500, 0x400549}, {0x400400, 0x400408}}},
		{0x400408, nil},
		{0x400449, nil},
		{0x4003ff, nil},
	}
	testRanges(t, "testdata/ranges.elf", want)
}

func TestRangesRnglistx(t *testing.T) {
	want := []wantRange{
		{0x401000, [][2]uint64{{0x401020, 0x40102c}, {0x401000, 0x40101d}}},
		{0x40101c, [][2]uint64{{0x401020, 0x40102c}, {0x401000, 0x40101d}}},
		{0x40101d, nil},
		{0x40101f, nil},
		{0x401020, [][2]uint64{{0x401020, 0x40102c}, {0x401000, 0x40101d}}},
		{0x40102b, [][2]uint64{{0x401020, 0x40102c}, {0x401000, 0x40101d}}},
		{0x40102c, nil},
	}
	testRanges(t, "testdata/rnglistx.elf", want)
}

func testRanges(t *testing.T, name string, want []wantRange) {
	d := elfData(t, name)
	r := d.Reader()
	for _, w := range want {
		entry, err := r.SeekPC(w.pc)
		if err != nil {
			if w.ranges != nil {
				t.Errorf("%s: missing Entry for %#x", name, w.pc)
			}
			if err != ErrUnknownPC {
				t.Errorf("%s: expected ErrUnknownPC for %#x, got %v", name, w.pc, err)
			}
			continue
		}

		ranges, err := d.Ranges(entry)
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		if !reflect.DeepEqual(ranges, w.ranges) {
			t.Errorf("%s: for %#x got %x, expected %x", name, w.pc, ranges, w.ranges)
		}
	}
}

func TestReaderRanges(t *testing.T) {
	type subprograms []struct {
		name   string
		ranges [][2]uint64
	}
	tests := []struct {
		filename    string
		subprograms subprograms
	}{
		{
			"testdata/line-gcc.elf",
			subprograms{
				{"f1", [][2]uint64{{0x40059d, 0x4005e7}}},
				{"main", [][2]uint64{{0x4005e7, 0x400601}}},
				{"f2", [][2]uint64{{0x400601, 0x400611}}},
			},
		},
		{
			"testdata/line-gcc-dwarf5.elf",
			subprograms{
				{"main", [][2]uint64{{0x401147, 0x401166}}},
				{"f1", [][2]uint64{{0x401122, 0x401147}}},
				{"f2", [][2]uint64{{0x401166, 0x401179}}},
			},
		},
		{
			"testdata/line-clang-dwarf5.elf",
			subprograms{
				{"main", [][2]uint64{{0x401130, 0x401144}}},
				{"f1", [][2]uint64{{0x401150, 0x40117e}}},
				{"f2", [][2]uint64{{0x401180, 0x401197}}},
			},
		},
		{
			"testdata/line-gcc-zstd.elf",
			subprograms{
				{"f2", nil},
				{"main", [][2]uint64{{0x40114b, 0x40116a}}},
				{"f1", [][2]uint64{{0x401126, 0x40114b}}},
				{"f2", [][2]uint64{{0x40116a, 0x401180}}},
			},
		},
	}

	for _, test := range tests {
		d := elfData(t, test.filename)
		subprograms := test.subprograms

		r := d.Reader()
		i := 0
		for entry, err := r.Next(); entry != nil && err == nil; entry, err = r.Next() {
			if entry.Tag != TagSubprogram {
				continue
			}

			if i > len(subprograms) {
				t.Fatalf("%s: too many subprograms (expected at most %d)", test.filename, i)
			}

			if got := entry.Val(AttrName).(string); got != subprograms[i].name {
				t.Errorf("%s: subprogram %d name is %s, expected %s", test.filename, i, got, subprograms[i].name)
			}
			ranges, err := d.Ranges(entry)
			if err != nil {
				t.Errorf("%s: subprogram %d: %v", test.filename, i, err)
				continue
			}
			if !reflect.DeepEqual(ranges, subprograms[i].ranges) {
				t.Errorf("%s: subprogram %d ranges are %x, expected %x", test.filename, i, ranges, subprograms[i].ranges)
			}
			i++
		}

		if i < len(subprograms) {
			t.Errorf("%s: saw only %d subprograms, expected %d", test.filename, i, len(subprograms))
		}
	}
}

func Test64Bit(t *testing.T) {
	// I don't know how to generate a 64-bit DWARF debug
	// compilation unit except by using XCOFF, so this is
	// hand-written.
	tests := []struct {
		name      string
		info      []byte
		addrSize  int
		byteOrder binary.ByteOrder
	}{
		{
			"32-bit little",
			[]byte{0x30, 0, 0, 0, // comp unit length
				4, 0, // DWARF version 4
				0, 0, 0, 0, // abbrev offset
				8, // address size
				0,
				0, 0, 0, 0, 0, 0, 0, 0,
				0, 0, 0, 0, 0, 0, 0, 0,
				0, 0, 0, 0, 0, 0, 0, 0,
				0, 0, 0, 0, 0, 0, 0, 0,
				0, 0, 0, 0, 0, 0, 0, 0,
			},
			8, binary.LittleEndian,
		},
		{
			"64-bit little",
			[]byte{0xff, 0xff, 0xff, 0xff, // 64-bit DWARF
				0x30, 0, 0, 0, 0, 0, 0, 0, // comp unit length
				4, 0, // DWARF version 4
				0, 0, 0, 0, 0, 0, 0, 0, // abbrev offset
				8, // address size
				0, 0, 0, 0, 0,
				0, 0, 0, 0, 0, 0, 0, 0,
				0, 0, 0, 0, 0, 0, 0, 0,
				0, 0, 0, 0, 0, 0, 0, 0,
				0, 0, 0, 0, 0, 0, 0, 0,
			},
			8, binary.LittleEndian,
		},
		{
			"64-bit big",
			[]byte{0xff, 0xff, 0xff, 0xff, // 64-bit DWARF
				0, 0, 0, 0, 0, 0, 0, 0x30, // comp unit length
				0, 4, // DWARF version 4
				0, 0, 0, 0, 0, 0, 0, 0, // abbrev offset
				8, // address size
				0, 0, 0, 0, 0,
				0, 0, 0, 0, 0, 0, 0, 0,
				0, 0, 0, 0, 0, 0, 0, 0,
				0, 0, 0, 0, 0, 0, 0, 0,
				0, 0, 0, 0, 0, 0, 0, 0,
			},
			8, binary.BigEndian,
		},
	}

	for _, test := range tests {
		data, err := New(nil, nil, nil, test.info, nil, nil, nil, nil)
		if err != nil {
			t.Errorf("%s: %v", test.name, err)
		}

		r := data.Reader()
		if r.AddressSize() != test.addrSize {
			t.Errorf("%s: got address size %d, want %d", test.name, r.AddressSize(), test.addrSize)
		}
		if r.ByteOrder() != test.byteOrder {
			t.Errorf("%s: got byte order %s, want %s", test.name, r.ByteOrder(), test.byteOrder)
		}
	}
}

func TestUnitIteration(t *testing.T) {
	// Iterate over all ELF test files we have and ensure that
	// we get the same set of compilation units skipping (method 0)
	// and not skipping (method 1) CU children.
	files, err := filepath.Glob(filepath.Join("testdata", "*.elf"))
	if err != nil {
		t.Fatal(err)
	}
	for _, file := range files {
		t.Run(file, func(t *testing.T) {
			d := elfData(t, file)
			var units [2][]any
			for method := range units {
				for r := d.Reader(); ; {
					ent, err := r.Next()
					if err != nil {
						t.Fatal(err)
					}
					if ent == nil {
						break
					}
					if ent.Tag == TagCompileUnit {
						units[method] = append(units[method], ent.Val(AttrName))
					}
					if method == 0 {
						if ent.Tag != TagCompileUnit {
							t.Fatalf("found unexpected tag %v on top level", ent.Tag)
						}
						r.SkipChildren()
					}
				}
			}
			t.Logf("skipping CUs:     %v", units[0])
			t.Logf("not-skipping CUs: %v", units[1])
			if !reflect.DeepEqual(units[0], units[1]) {
				t.Fatal("set of CUs differ")
			}
		})
	}
}

func TestIssue51758(t *testing.T) {
	abbrev := []byte{0x21, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x5c,
		0x5c, 0x33, 0x37, 0x37, 0x5c, 0x5c, 0x33, 0x37, 0x37, 0x5c, 0x5c,
		0x33, 0x37, 0x37, 0x5c, 0x5c, 0x33, 0x37, 0x37, 0x5c, 0x5c, 0x33,
		0x37, 0x37, 0x5c, 0x5c, 0x33, 0x37, 0x37, 0x5c, 0x5c, 0x33, 0x37,
		0x37, 0x5c, 0x5c, 0x33, 0x37, 0x37, 0x5c, 0x5c, 0x33, 0x37, 0x37,
		0x5c, 0x5c, 0x33, 0x37, 0x37, 0x5c, 0x5c, 0x33, 0x37, 0x37, 0x5c,
		0x5c, 0x33, 0x37, 0x37, 0x5c, 0x5c, 0x33, 0x37, 0x37, 0x5c, 0x5c,
		0x33, 0x37, 0x37, 0x5c, 0x5c, 0x33, 0x37, 0x37, 0x5c, 0x5c, 0x33,
		0x37, 0x37, 0x5c, 0x5c, 0x33, 0x37, 0x37, 0x5c, 0x5c, 0x33, 0x37,
		0x37, 0x5c, 0x5c, 0x33, 0x37, 0x37, 0x5c, 0x5c, 0x33, 0x37, 0x37,
		0x5c, 0x5c, 0x33, 0x37, 0x37, 0x5c, 0x5c, 0x33, 0x37, 0x37, 0x5c,
		0x5c, 0x33, 0x37, 0x37, 0x5c, 0x5c, 0x33, 0x37, 0x37, 0x5c, 0x5c,
		0x33, 0x37, 0x37, 0x5c, 0x5c, 0x33, 0x37, 0x37, 0x5c, 0x5c, 0x33,
		0x37, 0x37, 0x5c, 0x5c, 0x33, 0x37, 0x37, 0x5c, 0x5c, 0x33, 0x37,
		0x37, 0x5c, 0x5c, 0x33, 0x37, 0x37, 0x5c, 0x5c, 0x33, 0x37, 0x37,
		0x5c, 0x5c, 0x33, 0x37, 0x37, 0x5c, 0x5c, 0x33, 0x37, 0x37, 0x5c,
		0x5c, 0x33, 0x37, 0x37, 0x5c, 0x5c, 0x33, 0x37, 0x37, 0x5c, 0x5c,
		0x33, 0x37, 0x37, 0x5c, 0x5c, 0x33, 0x37, 0x37, 0x5c, 0x22, 0x5c,
		0x6e, 0x20, 0x20, 0x20, 0x20, 0x69, 0x6e, 0x66, 0x6f, 0x3a, 0x20,
		0x5c, 0x22, 0x5c, 0x5c, 0x30, 0x30, 0x35, 0x5c, 0x5c, 0x30, 0x30,
		0x30, 0x5c, 0x5c, 0x30, 0x30, 0x30, 0x5c, 0x5c, 0x30, 0x30, 0x30,
		0x5c, 0x5c, 0x30, 0x30, 0x34, 0x5c, 0x5c, 0x30, 0x30, 0x30, 0x5c,
		0x5c, 0x30, 0x30, 0x30, 0x2d, 0x5c, 0x5c, 0x30, 0x30, 0x30, 0x5c,
		0x22, 0x5c, 0x6e, 0x20, 0x20, 0x7d, 0x5c, 0x6e, 0x7d, 0x5c, 0x6e,
		0x22, 0x0a, 0x20, 0x20, 0x20, 0x20, 0x66, 0x72, 0x61, 0x6d, 0x65,
		0x3a, 0x20, 0x22, 0x21, 0x5c, 0x33, 0x37, 0x37, 0x5c, 0x33, 0x37,
		0x37, 0x5c, 0x33, 0x37, 0x37, 0x5c, 0x33, 0x37, 0x37, 0x5c, 0x33,
		0x37, 0x37, 0x5c, 0x33, 0x37, 0x37, 0x5c, 0x33, 0x37, 0x37, 0x5c,
		0x33, 0x37, 0x37, 0x5c, 0x33, 0x37, 0x37, 0x5c, 0x33, 0x37, 0x37,
		0x5c, 0x33, 0x37, 0x37, 0x5c, 0x33, 0x37, 0x37, 0x5c, 0x33, 0x37,
		0x37, 0x5c, 0x33, 0x37, 0x37, 0x5c, 0x33, 0x37, 0x37, 0x5c, 0x33,
		0x37, 0x37, 0x5c, 0x33, 0x37, 0x37, 0x5c, 0x33, 0x37, 0x37, 0x5c,
		0x33, 0x37, 0x37, 0x5c, 0x33, 0x37, 0x37, 0x5c, 0x33, 0x37, 0x37,
		0x5c, 0x33, 0x37, 0x37, 0x5c, 0x33, 0x37, 0x37, 0x5c, 0x33, 0x37,
		0x37, 0x5c, 0x33, 0x37, 0x37, 0x5c, 0x33, 0x37, 0x37, 0x5c, 0x33,
		0x37, 0x37, 0x5c, 0x33, 0x37, 0x37, 0x5c, 0x33, 0x37, 0x37, 0x5c,
		0x33, 0x37, 0x37, 0x5c, 0x33, 0x37, 0x37, 0x5c, 0x33, 0x37, 0x37,
		0x5c, 0x33, 0x37, 0x37, 0x5c, 0x33, 0x37, 0x37, 0x5c, 0x33, 0x37,
		0x37, 0x5c, 0x33, 0x37, 0x37, 0x5c, 0x33, 0x37, 0x37, 0x5c, 0x33,
		0x37, 0x37, 0x5c, 0x33, 0x37, 0x37, 0x5c, 0x33, 0x37, 0x37, 0x5c,
		0x33, 0x37, 0x37, 0x5c, 0x33, 0x37, 0x37, 0x5c, 0x33, 0x37, 0x37,
		0x5c, 0x33, 0x37, 0x37, 0x22, 0x0a, 0x20, 0x20, 0x20, 0x20, 0x69,
		0x6e, 0x66, 0x6f, 0x3a, 0x20, 0x22, 0x5c, 0x30, 0x30, 0x35, 0x5c,
		0x30, 0x30, 0x30, 0x5c, 0x30, 0x30, 0x30, 0x5c, 0x30, 0x30, 0x30,
		0x5c, 0x30, 0x30, 0x34, 0x5c, 0x30, 0x30, 0x30, 0x5c, 0x30, 0x30,
		0x30, 0x2d, 0x5c, 0x30, 0x30, 0x30, 0x22, 0x0a, 0x20, 0x20, 0x7d,
		0x0a, 0x7d, 0x0a, 0x6c, 0x69, 0x73, 0x74, 0x20, 0x7b, 0x0a, 0x7d,
		0x0a, 0x6c, 0x69, 0x73, 0x74, 0x20, 0x7b, 0x0a, 0x7d, 0x0a, 0x6c,
		0x69, 0x73, 0x74, 0x20, 0x7b, 0x0a, 0x20, 0x20, 0x4e, 0x65, 0x77,
		0x20, 0x7b, 0x0a, 0x20, 0x20, 0x20, 0x20, 0x61, 0x62, 0x62, 0x72,
		0x65, 0x76, 0x3a, 0x20, 0x22, 0x5c, 0x30, 0x30, 0x35, 0x5c, 0x30,
		0x30, 0x30, 0x5c, 0x30, 0x30, 0x30, 0x5c, 0x30, 0x30, 0x30, 0x5c,
		0x30, 0x30, 0x34, 0x5c, 0x30, 0x30, 0x30, 0x5c, 0x30, 0x30, 0x30,
		0x2d, 0x5c, 0x30, 0x30, 0x30, 0x6c, 0x69, 0x73, 0x74, 0x20, 0x7b,
		0x5c, 0x6e, 0x20, 0x20, 0x4e, 0x65, 0x77, 0x20, 0x7b, 0x5c, 0x6e,
		0x20, 0x20, 0x20, 0x20, 0x61, 0x62, 0x62, 0x72, 0x65, 0x76, 0x3a,
		0x20, 0x5c, 0x22, 0x21, 0x5c, 0x5c, 0x33, 0x37, 0x37, 0x5c, 0x5c,
		0x33, 0x37, 0x37, 0x5c, 0x5c, 0x33, 0x37, 0x37, 0x5c, 0x5c, 0x33,
		0x37, 0x37, 0x5c, 0x5c, 0x33, 0x37, 0x37, 0x5c, 0x5c, 0x33, 0x37,
		0x37, 0x5c, 0x5c, 0x33, 0x37, 0x37, 0x5c, 0x5c, 0x33, 0x37, 0x37,
		0x5c, 0x5c, 0x33, 0x37, 0x37, 0x5c, 0x5c, 0x33, 0x37, 0x37, 0x5c,
		0x5c, 0x33, 0x37, 0x37, 0x5c, 0x5c, 0x33, 0x37, 0x37, 0x5c, 0x5c,
		0x33, 0x37, 0x37, 0x5c, 0x5c, 0x33, 0x37, 0x37, 0x5c, 0x5c, 0x33,
		0x37, 0x37, 0x5c, 0x5c, 0x33, 0x37, 0x37, 0x5c, 0x5c, 0x33, 0x37,
		0x37, 0x5c, 0x5c, 0x33, 0x37, 0x37, 0x5c, 0x5c, 0x33, 0x37, 0x37,
		0x5c, 0x5c, 0x33, 0x37, 0x37, 0x5c, 0x5c, 0x33, 0x37, 0x37, 0x5c,
		0x5c, 0x33, 0x37, 0x37, 0x5c, 0x5c, 0x33, 0x37, 0x37, 0x5c, 0x5c,
		0x33, 0x37, 0x37, 0x5c, 0x5c, 0x33, 0x37, 0x37, 0x5c, 0x5c, 0x33,
		0x37, 0x37, 0x5c, 0x5c, 0x33, 0x37, 0x37, 0x5c, 0x5c, 0x33, 0x37,
		0x37, 0x5c, 0x5c, 0x33, 0x37, 0x37, 0x5c, 0x5c, 0x33, 0x37, 0x37,
		0x5c, 0x5c, 0x33, 0x37, 0x37, 0x5c, 0x5c, 0x33, 0x37, 0x37, 0x5c,
		0x5c, 0x33, 0x37, 0x37, 0x5c, 0x5c, 0x33, 0x37, 0x37, 0x5c, 0x5c,
		0x33, 0x37, 0x37, 0x5c, 0x5c, 0x33, 0x37, 0x37, 0x5c, 0x5c, 0x33,
		0x37, 0x37, 0x5c, 0x5c, 0x33, 0x37, 0x37, 0x5c, 0x5c, 0x33, 0x37,
		0x37, 0x5c, 0x5c, 0x33, 0x37, 0x37, 0x5c, 0x5c, 0x33, 0x37, 0x37,
		0x5c, 0x5c, 0x33, 0x37, 0x37, 0x5c, 0x5c, 0x33, 0x37, 0x37, 0x5c,
		0x5c, 0x33, 0x37, 0x37, 0x5c, 0x22, 0x5c, 0x6e, 0x20, 0x20, 0x20,
		0x20, 0x69, 0x6e, 0x66, 0x6f, 0x3a, 0x20, 0x5c, 0x22, 0x5c, 0x5c,
		0x30, 0x30, 0x35, 0x5c, 0x5c, 0x30, 0x30, 0x30, 0x5c, 0x5c, 0x30,
		0x30, 0x30, 0x5c, 0x5c, 0x30, 0x30, 0x30, 0x5c, 0x5c, 0x30, 0x30,
		0x34, 0x5c, 0x5c, 0x30, 0x30, 0x30, 0x5c, 0x5c, 0x30, 0x30, 0x30,
		0x2d, 0x5c, 0x5c, 0x30, 0x30, 0x30, 0x5c, 0x22, 0x5c, 0x6e, 0x20,
		0x20, 0x7d, 0x5c, 0x6e, 0x7d, 0x5c, 0x6e, 0x22, 0x0a, 0x20, 0x20,
		0x20, 0x20, 0x66, 0x72, 0x61, 0x6d, 0x65, 0x3a, 0x20, 0x22, 0x21,
		0x5c, 0x33, 0x37, 0x37, 0x5c, 0x33, 0x37, 0x37, 0x5c, 0x33, 0x37,
		0x37, 0x5c, 0x33, 0x37, 0x37, 0x5c, 0x33, 0x37, 0x37, 0x5c, 0x33,
		0x37, 0x37, 0x5c, 0x33, 0x37, 0x37, 0x5c, 0x33, 0x37, 0x37, 0x5c,
		0x33, 0x37, 0x37, 0x5c, 0x33, 0x37, 0x37, 0x5c, 0x33, 0x37, 0x37,
		0x5c, 0x33, 0x37, 0x37, 0x5c, 0x33, 0x37, 0x37, 0x5c, 0x33, 0x37,
		0x37, 0x5c, 0x33, 0x37, 0x37, 0x5c, 0x33, 0x37, 0x37, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff}
	aranges := []byte{0x2c}
	frame := []byte{}
	info := []byte{0x5, 0x0, 0x0, 0x0, 0x4, 0x0, 0x0, 0x2d, 0x0, 0x5,
		0x0, 0x0, 0x0, 0x4, 0x0, 0x0, 0x2d, 0x0}

	// The input above is malformed; the goal here it just to make sure
	// that we don't get a panic or other bad behavior while trying to
	// construct a dwarf.Data object from the input.  For good measure,
	// test to make sure we can handle the case where the input is
	// truncated as well.
	for i := 0; i <= len(info); i++ {
		truncated := info[:i]
		dw, err := New(abbrev, aranges, frame, truncated, nil, nil, nil, nil)
		if err == nil {
			t.Errorf("expected error")
		} else {
			if dw != nil {
				t.Errorf("got non-nil dw, wanted nil")
			}
		}
	}
}

func TestIssue52045(t *testing.T) {
	var abbrev, aranges, frame, line, pubnames, ranges, str []byte
	info := []byte{0x7, 0x0, 0x0, 0x0, 0x2, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}

	// A hand-crafted input corresponding to a minimal-size
	// .debug_info (header only, no DIEs) and an empty abbrev table.
	data0, _ := New(abbrev, aranges, frame, info, line, pubnames, ranges, str)
	reader0 := data0.Reader()
	entry0, _ := reader0.SeekPC(0x0)
	// main goal is to make sure we can get here without crashing
	if entry0 != nil {
		t.Errorf("got non-nil entry0, wanted nil")
	}
}

"""



```