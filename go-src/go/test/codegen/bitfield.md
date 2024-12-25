Response: Let's break down the thought process for analyzing this Go code snippet.

**1. Initial Scan and Keywords:**

First, I'd quickly scan the code for recognizable patterns and keywords. I see function definitions, bitwise operators (`<<`, `>>`, `&`, `|`, `^`), and comments containing architecture-specific assembly instructions (e.g., `arm64:"EXTR"`). The filename `bitfield.go` and the package name `codegen` strongly suggest this code is about generating or testing code for bit field manipulation.

**2. Understanding the Core Purpose:**

The comments starting with `// arm64:` are crucial. They indicate the *expected* assembly instructions for ARM64 architecture. This immediately suggests the code is testing the compiler's ability to optimize certain bitwise operations into specific efficient machine instructions. The presence of `asmcheck` at the beginning of the file reinforces this idea – it's a test file that verifies generated assembly.

**3. Analyzing Individual Functions (Pattern Recognition):**

I'd then start examining the functions one by one, looking for patterns:

* **`extr` functions:**  They combine a left shift on one variable with a right shift on another, followed by `+`, `|`, or `^`. The `arm64:"EXTR"` comments confirm the expectation that these are being optimized into the `EXTR` (extract register) instruction on ARM64.

* **`mask` functions:**  These involve left and right shifts by the same amount. The `arm64:"AND\t[$]...,"` comments indicate the compiler is expected to optimize these into an `AND` operation with a mask. This is a common technique for isolating specific bits.

* **`bfi` and `bfxil` functions:** Their names are suggestive of "bit field insert" and "bit field extract and insert lower." The code uses bitwise AND and OR operations to combine parts of the input variables. The `arm64:"BFI"` and `arm64:"BFXIL"` comments confirm these are related to bit field manipulation instructions.

* **`sbfiz` and `sbfx` functions:** The 's' prefix suggests signed operations. These functions use shifts and type conversions (`int64(x)`) and have comments like `arm64:"SBFIZ"` and `arm64:"SBFX"`, indicating signed bit field insert/extract instructions. The comments also note "merge shifts," which is a key optimization the test is verifying.

* **`ubfiz` and `ubfx` functions:** The 'u' prefix indicates unsigned operations. Similar to the 's' functions, these involve shifts, type conversions (`uint64(x)`), and expected `arm64:"UBFIZ"` and `arm64:"UBFX"` instructions for unsigned bit field operations.

* **`rev16` and `rev16w` functions:** The names suggest reversing the byte order within 16-bit chunks. The `arm64:"REV16"` and `arm64:"REV16W"` comments confirm this.

* **`shift` function:** This function performs right shifts and additions. The comments show it's testing that unnecessary `MOVWU`, `MOVHU`, `MOVBU` instructions (for zero-extension) are omitted when converting to `uint64` before shifting.

* **`shift_no_cmp` function:** The `//go:nosplit` directive is a hint about low-level details. The comments check for the *absence* of comparison instructions (`-` followed by `CMP`). This suggests it's testing an optimization where a shift by a constant amount doesn't require a bounds check.

**4. Inferring the Overall Functionality:**

Based on the analysis of individual functions, the main purpose of this code is to test the Go compiler's ability to recognize common bit manipulation patterns and optimize them into efficient, architecture-specific assembly instructions, particularly on ARM64. It also checks for the absence of unnecessary instructions.

**5. Generating Go Examples:**

To demonstrate the functionality, I'd create simple `main` functions that call these test functions with sample inputs. This illustrates *how* these functions are used in Go code and how the compiler is expected to optimize them.

**6. Considering Command-Line Arguments (Not Present):**

A careful reading of the code reveals no direct interaction with command-line arguments. The `asmcheck` tag at the beginning hints at a separate testing mechanism (likely involving running the Go compiler and inspecting the generated assembly), but this code itself doesn't parse command-line arguments.

**7. Identifying Potential Pitfalls (Limited in this Code):**

This code primarily serves as a compiler test. There aren't many ways a *user* would directly misuse these specific functions in a way that would cause errors *beyond* incorrect logic. However, I could point out that misunderstanding the bitwise operations themselves could lead to incorrect results, even if the compiler optimizes them correctly. I'd also highlight the architecture-specific nature of the optimizations – these specific assembly instructions are for ARM64 (and sometimes s390x), and the optimizations might not apply to other architectures in the same way.

**8. Refinement and Structure:**

Finally, I'd structure the explanation clearly, starting with a high-level summary and then going into more detail about the individual functions, examples, and potential issues. Using clear headings and bullet points helps to organize the information. I would also double-check the assembly instruction mnemonics and their descriptions for accuracy.
这个 `go/test/codegen/bitfield.go` 文件是 Go 语言编译器的一个代码生成测试文件，专门用于测试编译器在处理位字段（bit field）操作时的优化能力。

**功能归纳:**

该文件的主要功能是定义了一系列 Go 函数，这些函数都涉及到对整型变量的位进行提取、插入、屏蔽和旋转等操作。这些函数的设计目标是触发 Go 编译器进行特定的位操作优化，特别是针对 ARM64 架构，同时也包含对 s390x 等架构的测试。

**推理其是什么 Go 语言功能的实现:**

虽然这个文件本身不是 Go 语言特性的直接实现，但它测试的是 Go 编译器对位运算的优化。Go 语言本身并没有像 C 语言那样提供显式的位域结构体，但程序员可以通过位运算符（`&`, `|`, `^`, `<<`, `>>`）来手动实现位字段的操作。这个测试文件就是验证编译器能否将这些手动的位运算高效地转换为目标架构上的位操作指令。

**Go 代码举例说明:**

以下代码演示了 `bitfield.go` 中 `extr1` 函数所测试的位字段提取操作：

```go
package main

import "fmt"

func extr1(x, x2 uint64) uint64 {
	return x<<7 + x2>>57
}

func main() {
	var a uint64 = 0b00000001_00000000_00000000_00000000_00000000_00000000_00000000_00000000 // x
	var b uint64 = 0b10000000_00000000_00000000_00000000_00000000_00000000_00000000_00000000 // x2

	result := extr1(a, b)
	fmt.Printf("Input x:  %b\n", a)
	fmt.Printf("Input x2: %b\n", b)
	fmt.Printf("Result:   %b\n", result) // 预期输出包含 x2 的高 7 位和 x 的低位
}
```

在这个例子中，`extr1` 函数将 `x` 左移 7 位，并将 `x2` 右移 57 位。在 ARM64 架构上，编译器应该能够将这个操作优化为一条 `EXTR` 指令，该指令可以高效地从两个寄存器中提取指定长度的位字段并组合起来。

**代码逻辑介绍 (带假设的输入与输出):**

以 `bfi1` 函数为例：

```go
func bfi1(x, y uint64) uint64 {
	return ((x & 0xfff) << 4) | (y & 0xffffffffffff000f)
}
```

**假设输入:**

* `x` = `0b00000000_00000000_00000000_00000000_00000000_00000000_00000010_10101010` (十进制 2730)
* `y` = `0b11111111_11111111_11111111_11111111_11111111_11111111_11111111_11111111` (全 1)

**代码逻辑:**

1. `(x & 0xfff)`:  提取 `x` 的低 12 位 (0x00000AAA)。
2. `((x & 0xfff) << 4)`: 将提取的低 12 位左移 4 位 (0x0000AAA0)。
3. `(y & 0xffffffffffff000f)`:  提取 `y` 的低 4 位和高 52 位，中间的 12 位被屏蔽 (0xFFFFFFFFFFFFF00F)。
4. `((x & 0xfff) << 4) | (y & 0xffffffffffff000f)`: 将步骤 2 和步骤 3 的结果进行按位或运算。这意味着将 `x` 的低 12 位插入到 `y` 的特定位置。

**预期输出:**

`0b11111111_11111111_11111111_11111111_11111111_11111111_11111010_1010000F`

在 ARM64 架构上，编译器应该将这个操作优化为一条 `BFI` (Bit Field Insert) 指令。

**命令行参数的具体处理:**

这个代码文件本身不涉及命令行参数的处理。它是 Go 语言编译器测试套件的一部分，通常通过 `go test` 命令来运行。`go test` 命令会编译并执行该文件中的测试函数，并通过检查生成的汇编代码是否符合预期来验证编译器的优化能力。

该文件开头的 `// asmcheck` 注释是一个特殊的标记，用于告知测试工具需要检查生成的汇编代码。测试工具会读取 `arm64:"..."` 或其他架构特定的注释，并验证实际生成的汇编代码是否包含这些指令。

**使用者易犯错的点:**

这个文件主要是给 Go 语言编译器开发者看的，普通 Go 语言使用者不会直接使用或修改它。因此，从使用者角度来说，不存在直接 "犯错" 的情况。

然而，如果理解不到位，可能会对 Go 语言处理位操作的效率产生误解。例如，可能会认为手动的位运算效率低下。实际上，Go 编译器在这种情况下会尽力进行优化，生成高效的机器码。

另一个需要注意的是，虽然 Go 提供了位运算，但在处理需要精细控制内存布局的场景（例如，与硬件交互或处理特定的数据格式）时，可能仍然需要依赖 `unsafe` 包或者考虑使用 Cgo 与 C 代码进行交互，因为 Go 本身并没有提供像 C 语言中 `struct` 位域那样的直接语法支持。

总而言之，`go/test/codegen/bitfield.go` 是一个底层的测试文件，用于确保 Go 编译器能够正确且高效地处理位字段相关的操作，这对于生成高性能的代码至关重要。

Prompt: 
```
这是路径为go/test/codegen/bitfield.go的go语言实现的一部分， 请归纳一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果介绍代码逻辑，则建议带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，

"""
// asmcheck

// Copyright 2018 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package codegen

// This file contains codegen tests related to bit field
// insertion/extraction simplifications/optimizations.

func extr1(x, x2 uint64) uint64 {
	return x<<7 + x2>>57 // arm64:"EXTR\t[$]57,"
}

func extr2(x, x2 uint64) uint64 {
	return x<<7 | x2>>57 // arm64:"EXTR\t[$]57,"
}

func extr3(x, x2 uint64) uint64 {
	return x<<7 ^ x2>>57 // arm64:"EXTR\t[$]57,"
}

func extr4(x, x2 uint32) uint32 {
	return x<<7 + x2>>25 // arm64:"EXTRW\t[$]25,"
}

func extr5(x, x2 uint32) uint32 {
	return x<<7 | x2>>25 // arm64:"EXTRW\t[$]25,"
}

func extr6(x, x2 uint32) uint32 {
	return x<<7 ^ x2>>25 // arm64:"EXTRW\t[$]25,"
}

// check 32-bit shift masking
func mask32(x uint32) uint32 {
	return (x << 29) >> 29 // arm64:"AND\t[$]7, R[0-9]+",-"LSR",-"LSL"
}

// check 16-bit shift masking
func mask16(x uint16) uint16 {
	return (x << 14) >> 14 // arm64:"AND\t[$]3, R[0-9]+",-"LSR",-"LSL"
}

// check 8-bit shift masking
func mask8(x uint8) uint8 {
	return (x << 7) >> 7 // arm64:"AND\t[$]1, R[0-9]+",-"LSR",-"LSL"
}

func maskshift(x uint64) uint64 {
	// arm64:"AND\t[$]4095, R[0-9]+",-"LSL",-"LSR",-"UBFIZ",-"UBFX"
	return ((x << 5) & (0xfff << 5)) >> 5
}

// bitfield ops
// bfi
func bfi1(x, y uint64) uint64 {
	// arm64:"BFI\t[$]4, R[0-9]+, [$]12",-"LSL",-"LSR",-"AND"
	return ((x & 0xfff) << 4) | (y & 0xffffffffffff000f)
}

func bfi2(x, y uint64) uint64 {
	// arm64:"BFI\t[$]12, R[0-9]+, [$]40",-"LSL",-"LSR",-"AND"
	return (x << 24 >> 12) | (y & 0xfff0000000000fff)
}

// bfxil
func bfxil1(x, y uint64) uint64 {
	// arm64:"BFXIL\t[$]5, R[0-9]+, [$]12",-"LSL",-"LSR",-"AND"
	return ((x >> 5) & 0xfff) | (y & 0xfffffffffffff000)
}

func bfxil2(x, y uint64) uint64 {
	// arm64:"BFXIL\t[$]12, R[0-9]+, [$]40",-"LSL",-"LSR",-"AND"
	return (x << 12 >> 24) | (y & 0xffffff0000000000)
}

// sbfiz
// merge shifts into sbfiz: (x << lc) >> rc && lc > rc.
func sbfiz1(x int64) int64 {
	// arm64:"SBFIZ\t[$]1, R[0-9]+, [$]60",-"LSL",-"ASR"
	return (x << 4) >> 3
}

// merge shift and sign-extension into sbfiz.
func sbfiz2(x int32) int64 {
	return int64(x << 3) // arm64:"SBFIZ\t[$]3, R[0-9]+, [$]29",-"LSL"
}

func sbfiz3(x int16) int64 {
	return int64(x << 3) // arm64:"SBFIZ\t[$]3, R[0-9]+, [$]13",-"LSL"
}

func sbfiz4(x int8) int64 {
	return int64(x << 3) // arm64:"SBFIZ\t[$]3, R[0-9]+, [$]5",-"LSL"
}

// sbfiz combinations.
// merge shift with sbfiz into sbfiz.
func sbfiz5(x int32) int32 {
	// arm64:"SBFIZ\t[$]1, R[0-9]+, [$]28",-"LSL",-"ASR"
	return (x << 4) >> 3
}

func sbfiz6(x int16) int64 {
	return int64(x+1) << 3 // arm64:"SBFIZ\t[$]3, R[0-9]+, [$]16",-"LSL"
}

func sbfiz7(x int8) int64 {
	return int64(x+1) << 62 // arm64:"SBFIZ\t[$]62, R[0-9]+, [$]2",-"LSL"
}

func sbfiz8(x int32) int64 {
	return int64(x+1) << 40 // arm64:"SBFIZ\t[$]40, R[0-9]+, [$]24",-"LSL"
}

// sbfx
// merge shifts into sbfx: (x << lc) >> rc && lc <= rc.
func sbfx1(x int64) int64 {
	return (x << 3) >> 4 // arm64:"SBFX\t[$]1, R[0-9]+, [$]60",-"LSL",-"ASR"
}

func sbfx2(x int64) int64 {
	return (x << 60) >> 60 // arm64:"SBFX\t[$]0, R[0-9]+, [$]4",-"LSL",-"ASR"
}

// merge shift and sign-extension into sbfx.
func sbfx3(x int32) int64 {
	return int64(x) >> 3 // arm64:"SBFX\t[$]3, R[0-9]+, [$]29",-"ASR"
}

func sbfx4(x int16) int64 {
	return int64(x) >> 3 // arm64:"SBFX\t[$]3, R[0-9]+, [$]13",-"ASR"
}

func sbfx5(x int8) int64 {
	return int64(x) >> 3 // arm64:"SBFX\t[$]3, R[0-9]+, [$]5",-"ASR"
}

func sbfx6(x int32) int64 {
	return int64(x >> 30) // arm64:"SBFX\t[$]30, R[0-9]+, [$]2"
}

func sbfx7(x int16) int64 {
	return int64(x >> 10) // arm64:"SBFX\t[$]10, R[0-9]+, [$]6"
}

func sbfx8(x int8) int64 {
	return int64(x >> 5) // arm64:"SBFX\t[$]5, R[0-9]+, [$]3"
}

// sbfx combinations.
// merge shifts with sbfiz into sbfx.
func sbfx9(x int32) int32 {
	return (x << 3) >> 4 // arm64:"SBFX\t[$]1, R[0-9]+, [$]28",-"LSL",-"ASR"
}

// merge sbfx and sign-extension into sbfx.
func sbfx10(x int32) int64 {
	c := x + 5
	return int64(c >> 20) // arm64"SBFX\t[$]20, R[0-9]+, [$]12",-"MOVW\tR[0-9]+, R[0-9]+"
}

// ubfiz
// merge shifts into ubfiz: (x<<lc)>>rc && lc>rc
func ubfiz1(x uint64) uint64 {
	// arm64:"UBFIZ\t[$]1, R[0-9]+, [$]60",-"LSL",-"LSR"
	// s390x:"RISBGZ\t[$]3, [$]62, [$]1, ",-"SLD",-"SRD"
	return (x << 4) >> 3
}

// merge shift and zero-extension into ubfiz.
func ubfiz2(x uint32) uint64 {
	return uint64(x+1) << 3 // arm64:"UBFIZ\t[$]3, R[0-9]+, [$]32",-"LSL"
}

func ubfiz3(x uint16) uint64 {
	return uint64(x+1) << 3 // arm64:"UBFIZ\t[$]3, R[0-9]+, [$]16",-"LSL"
}

func ubfiz4(x uint8) uint64 {
	return uint64(x+1) << 3 // arm64:"UBFIZ\t[$]3, R[0-9]+, [$]8",-"LSL"
}

func ubfiz5(x uint8) uint64 {
	return uint64(x) << 60 // arm64:"UBFIZ\t[$]60, R[0-9]+, [$]4",-"LSL"
}

func ubfiz6(x uint32) uint64 {
	return uint64(x << 30) // arm64:"UBFIZ\t[$]30, R[0-9]+, [$]2",
}

func ubfiz7(x uint16) uint64 {
	return uint64(x << 10) // arm64:"UBFIZ\t[$]10, R[0-9]+, [$]6",
}

func ubfiz8(x uint8) uint64 {
	return uint64(x << 7) // arm64:"UBFIZ\t[$]7, R[0-9]+, [$]1",
}

// merge ANDconst into ubfiz.
func ubfiz9(x uint64) uint64 {
	// arm64:"UBFIZ\t[$]3, R[0-9]+, [$]12",-"LSL",-"AND"
	// s390x:"RISBGZ\t[$]49, [$]60, [$]3,",-"SLD",-"AND"
	return (x & 0xfff) << 3
}

func ubfiz10(x uint64) uint64 {
	// arm64:"UBFIZ\t[$]4, R[0-9]+, [$]12",-"LSL",-"AND"
	// s390x:"RISBGZ\t[$]48, [$]59, [$]4,",-"SLD",-"AND"
	return (x << 4) & 0xfff0
}

// ubfiz combinations
func ubfiz11(x uint32) uint32 {
	// arm64:"UBFIZ\t[$]1, R[0-9]+, [$]28",-"LSL",-"LSR"
	return (x << 4) >> 3
}

func ubfiz12(x uint64) uint64 {
	// arm64:"UBFIZ\t[$]1, R[0-9]+, [$]20",-"LSL",-"LSR"
	// s390x:"RISBGZ\t[$]43, [$]62, [$]1, ",-"SLD",-"SRD",-"AND"
	return ((x & 0xfffff) << 4) >> 3
}

func ubfiz13(x uint64) uint64 {
	// arm64:"UBFIZ\t[$]5, R[0-9]+, [$]13",-"LSL",-"LSR",-"AND"
	return ((x << 3) & 0xffff) << 2
}

func ubfiz14(x uint64) uint64 {
	// arm64:"UBFIZ\t[$]7, R[0-9]+, [$]12",-"LSL",-"LSR",-"AND"
	// s390x:"RISBGZ\t[$]45, [$]56, [$]7, ",-"SLD",-"SRD",-"AND"
	return ((x << 5) & (0xfff << 5)) << 2
}

// ubfx
// merge shifts into ubfx: (x<<lc)>>rc && lc<rc
func ubfx1(x uint64) uint64 {
	// arm64:"UBFX\t[$]1, R[0-9]+, [$]62",-"LSL",-"LSR"
	// s390x:"RISBGZ\t[$]2, [$]63, [$]63,",-"SLD",-"SRD"
	return (x << 1) >> 2
}

// merge shift and zero-extension into ubfx.
func ubfx2(x uint32) uint64 {
	return uint64(x >> 15) // arm64:"UBFX\t[$]15, R[0-9]+, [$]17",-"LSR"
}

func ubfx3(x uint16) uint64 {
	return uint64(x >> 9) // arm64:"UBFX\t[$]9, R[0-9]+, [$]7",-"LSR"
}

func ubfx4(x uint8) uint64 {
	return uint64(x >> 3) // arm64:"UBFX\t[$]3, R[0-9]+, [$]5",-"LSR"
}

func ubfx5(x uint32) uint64 {
	return uint64(x) >> 30 // arm64:"UBFX\t[$]30, R[0-9]+, [$]2"
}

func ubfx6(x uint16) uint64 {
	return uint64(x) >> 10 // arm64:"UBFX\t[$]10, R[0-9]+, [$]6"
}

func ubfx7(x uint8) uint64 {
	return uint64(x) >> 3 // arm64:"UBFX\t[$]3, R[0-9]+, [$]5"
}

// merge ANDconst into ubfx.
func ubfx8(x uint64) uint64 {
	// arm64:"UBFX\t[$]25, R[0-9]+, [$]10",-"LSR",-"AND"
	// s390x:"RISBGZ\t[$]54, [$]63, [$]39, ",-"SRD",-"AND"
	return (x >> 25) & 1023
}

func ubfx9(x uint64) uint64 {
	// arm64:"UBFX\t[$]4, R[0-9]+, [$]8",-"LSR",-"AND"
	// s390x:"RISBGZ\t[$]56, [$]63, [$]60, ",-"SRD",-"AND"
	return (x & 0x0ff0) >> 4
}

// ubfx combinations.
func ubfx10(x uint32) uint32 {
	// arm64:"UBFX\t[$]1, R[0-9]+, [$]30",-"LSL",-"LSR"
	return (x << 1) >> 2
}

func ubfx11(x uint64) uint64 {
	// arm64:"UBFX\t[$]1, R[0-9]+, [$]12",-"LSL",-"LSR",-"AND"
	// s390x:"RISBGZ\t[$]52, [$]63, [$]63,",-"SLD",-"SRD",-"AND"
	return ((x << 1) >> 2) & 0xfff
}

func ubfx12(x uint64) uint64 {
	// arm64:"UBFX\t[$]4, R[0-9]+, [$]11",-"LSL",-"LSR",-"AND"
	// s390x:"RISBGZ\t[$]53, [$]63, [$]60, ",-"SLD",-"SRD",-"AND"
	return ((x >> 3) & 0xfff) >> 1
}

func ubfx13(x uint64) uint64 {
	// arm64:"UBFX\t[$]5, R[0-9]+, [$]56",-"LSL",-"LSR"
	// s390x:"RISBGZ\t[$]8, [$]63, [$]59, ",-"SLD",-"SRD"
	return ((x >> 2) << 5) >> 8
}

func ubfx14(x uint64) uint64 {
	// arm64:"UBFX\t[$]1, R[0-9]+, [$]19",-"LSL",-"LSR"
	// s390x:"RISBGZ\t[$]45, [$]63, [$]63, ",-"SLD",-"SRD",-"AND"
	return ((x & 0xfffff) << 3) >> 4
}

// merge ubfx and zero-extension into ubfx.
func ubfx15(x uint64) bool {
	midr := x + 10
	part_num := uint16((midr >> 4) & 0xfff)
	if part_num == 0xd0c { // arm64:"UBFX\t[$]4, R[0-9]+, [$]12",-"MOVHU\tR[0-9]+, R[0-9]+"
		return true
	}
	return false
}

// merge ANDconst and ubfx into ubfx
func ubfx16(x uint64) uint64 {
	// arm64:"UBFX\t[$]4, R[0-9]+, [$]6",-"AND\t[$]63"
	return ((x >> 3) & 0xfff) >> 1 & 0x3f
}

// Check that we don't emit comparisons for constant shifts.
//
//go:nosplit
func shift_no_cmp(x int) int {
	// arm64:`LSL\t[$]17`,-`CMP`
	// mips64:`SLLV\t[$]17`,-`SGT`
	return x << 17
}

func rev16(c uint64) (uint64, uint64, uint64) {
	// arm64:`REV16`,-`AND`,-`LSR`,-`AND`,-`ORR\tR[0-9]+<<8`
	b1 := ((c & 0xff00ff00ff00ff00) >> 8) | ((c & 0x00ff00ff00ff00ff) << 8)
	// arm64:-`ADD\tR[0-9]+<<8`
	b2 := ((c & 0xff00ff00ff00ff00) >> 8) + ((c & 0x00ff00ff00ff00ff) << 8)
	// arm64:-`EOR\tR[0-9]+<<8`
	b3 := ((c & 0xff00ff00ff00ff00) >> 8) ^ ((c & 0x00ff00ff00ff00ff) << 8)
	return b1, b2, b3
}

func rev16w(c uint32) (uint32, uint32, uint32) {
	// arm64:`REV16W`,-`AND`,-`UBFX`,-`AND`,-`ORR\tR[0-9]+<<8`
	b1 := ((c & 0xff00ff00) >> 8) | ((c & 0x00ff00ff) << 8)
	// arm64:-`ADD\tR[0-9]+<<8`
	b2 := ((c & 0xff00ff00) >> 8) + ((c & 0x00ff00ff) << 8)
	// arm64:-`EOR\tR[0-9]+<<8`
	b3 := ((c & 0xff00ff00) >> 8) ^ ((c & 0x00ff00ff) << 8)
	return b1, b2, b3
}

func shift(x uint32, y uint16, z uint8) uint64 {
	// arm64:-`MOVWU`,-`LSR\t[$]32`
	// loong64:-`MOVWU`,-`SRLV\t[$]32`
	a := uint64(x) >> 32
	// arm64:-`MOVHU
	// loong64:-`MOVHU`,-`SRLV\t[$]16`
	b := uint64(y) >> 16
	// arm64:-`MOVBU`
	// loong64:-`MOVBU`,-`SRLV\t[$]8`
	c := uint64(z) >> 8
	// arm64:`MOVD\tZR`,-`ADD\tR[0-9]+>>16`,-`ADD\tR[0-9]+>>8`,
	// loong64:`MOVV\t[$]0`,-`ADDVU`
	return a + b + c
}

"""



```