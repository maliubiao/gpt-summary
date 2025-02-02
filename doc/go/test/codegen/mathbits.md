Response: My goal is to analyze the provided Go code snippet and summarize its functionality. Here's a breakdown of my thought process:

1. **Identify the Core Purpose:** The first few lines mention `package codegen` and import `math/bits`. This immediately suggests the code is related to code generation and likely involves low-level bit manipulation operations provided by the `math/bits` package. The `// asmcheck` comment at the beginning also indicates this code is used for testing assembly code generation.

2. **Group Functions by Functionality:** I notice a clear structure in the code. Sections are demarcated by comments like `// ----------------------- //` and function names correspond to functions in the `bits` package (e.g., `LeadingZeros`, `Len`, `OnesCount`, etc.). This strongly suggests the code is providing wrappers or tests for the functions in `math/bits`.

3. **Analyze Individual Function Wrappers:**  For each group of functions, I observe a consistent pattern:
    * A function in the `codegen` package is defined (e.g., `LeadingZeros`).
    * This function takes an unsigned integer as input (with varying bit widths: `uint`, `uint64`, `uint32`, etc.).
    * Inside the function, it directly calls the corresponding function from the `math/bits` package (e.g., `bits.LeadingZeros(n)`).
    * The assembly directives within the comments `// amd64/v1...` are key. These are *asmcheck* directives, indicating which assembly instructions should be generated for different architectures and CPU features.

4. **Infer Overall Functionality:** Based on the observation in step 3, I conclude that the primary function of this code is to *test the assembly code generated by the Go compiler* for various `math/bits` functions across different architectures. The `asmcheck` directives are used to verify that specific assembly instructions are present (or absent) in the generated code.

5. **Determine the "Go Language Feature":** The code directly relates to the `math/bits` package. Therefore, the Go language feature it implements is the set of bit manipulation functions provided by this package.

6. **Illustrate with Go Code Example:** To demonstrate the usage of these functions, I need to show how a user would call the functions defined in `codegen/mathbits.go`. Since these functions are simple wrappers, the usage is identical to calling the `math/bits` functions directly. I choose a few representative functions (e.g., `LeadingZeros`, `Len`, `OnesCount`) and show example calls and their expected outputs.

7. **Describe Code Logic:** The logic is straightforward. Each function in `codegen/mathbits.go` simply calls the corresponding function in `math/bits`. The key aspect is the `asmcheck` comments, which are directives for the testing tool, not part of the runtime logic. I need to explain that these directives specify the expected assembly instructions for different architectures.

8. **Address Command-Line Arguments:**  I carefully reviewed the code and found *no direct handling of command-line arguments*. The file is a standard Go source file containing function definitions. It relies on Go's testing framework and `asmcheck` tool, which are invoked via command-line, but the file itself doesn't parse arguments. Therefore, I conclude there are no command-line arguments handled by this specific file.

9. **Identify Potential User Errors:** Since the functions are direct wrappers around `math/bits`, the potential for user errors is the same as using the `math/bits` package directly. A common error would be passing arguments of the wrong type (e.g., a signed integer when an unsigned is expected). I provide a simple example of this, showing the compiler error. Another potential error is misinterpreting the results of functions like `LeadingZeros` or `TrailingZeros` when the input is zero.

10. **Review and Refine:** I reread my analysis to ensure accuracy, clarity, and completeness. I double-check that my Go code examples are correct and that my explanations about `asmcheck` and the absence of command-line arguments are accurate. I also confirm that the identified user error is relevant and well-explained.

By following this step-by-step process, I can systematically analyze the code and generate a comprehensive and accurate summary of its functionality. The key was recognizing the pattern of wrapping `math/bits` functions and understanding the purpose of the `asmcheck` directives.
这是 `go/test/codegen/mathbits.go` 文件的一部分，其主要功能是**作为 Go 编译器代码生成质量的测试用例**，特别是针对 `math/bits` 标准库中的函数。

更具体地说，这个文件定义了一系列与 `math/bits` 中同名的函数，例如 `LeadingZeros`、`Len`、`OnesCount` 等。 这些函数本身并没有复杂的逻辑，它们通常只是简单地调用 `math/bits` 包中对应的函数。

**这个文件的核心价值在于其注释中的 `// asmcheck` 指令。** 这些指令指示 Go 编译器在针对特定架构（例如 amd64/v1, amd64/v3, arm64, s390x 等）生成汇编代码时，应该包含或排除特定的汇编指令。

**可以推理出它是什么 Go 语言功能的实现：**

这个文件本身**不是** `math/bits` 功能的实现，而是**针对 `math/bits` 功能的代码生成测试**。 它利用 Go 的 `asm` 测试机制来验证编译器是否能够为 `math/bits` 中的函数生成高效且正确的汇编代码。

**Go 代码举例说明:**

虽然 `codegen/mathbits.go` 本身是测试代码，但我们可以用一个简单的 Go 程序来演示 `math/bits` 包中函数的使用，因为 `codegen/mathbits.go` 中的函数最终会调用它们：

```go
package main

import (
	"fmt"
	"math/bits"
)

func main() {
	n := uint(12) // 二进制: 1100
	lz := bits.LeadingZeros(n)
	fmt.Printf("Leading zeros of %d: %d\n", n, lz) // 输出: Leading zeros of 12: 60 (假设是 64 位系统)

	l := bits.Len(n)
	fmt.Printf("Length of %d: %d\n", n, l)       // 输出: Length of 12: 4

	oc := bits.OnesCount(n)
	fmt.Printf("Ones count of %d: %d\n", n, oc)   // 输出: Ones count of 12: 2
}
```

**代码逻辑介绍 (带假设的输入与输出):**

以 `LeadingZeros` 函数为例：

```go
func LeadingZeros(n uint) int {
	// amd64/v1,amd64/v2:"BSRQ"
	// amd64/v3:"LZCNTQ", -"BSRQ"
	// ... (其他架构的指令)
	return bits.LeadingZeros(n)
}
```

**假设输入:** `n = uint(12)` (二进制表示为 `0000...00001100`，假设是 64 位系统)

**代码逻辑:**

1. `LeadingZeros(n)` 函数被调用，传入 `n = 12`。
2. 函数内部直接调用 `bits.LeadingZeros(n)`，将输入 `n` 传递给标准库的实现。
3. `bits.LeadingZeros(n)` 计算 `n` 的二进制表示中，从最高位开始有多少个连续的 0。
4. 在 64 位系统中，`12` 的二进制表示为 `0000000000000000000000000000000000000000000000000000000000001100`。
5. 因此，`bits.LeadingZeros(12)` 返回 `60`。
6. `LeadingZeros(n)` 函数将 `60` 作为结果返回。

**输出:**  `60`

**`asmcheck` 指令的含义:**

注释 `// amd64/v1,amd64/v2:"BSRQ"` 表示：在 AMD64 架构的 v1 和 v2 版本中，Go 编译器应该为 `LeadingZeros` 函数生成包含 `BSRQ` 汇编指令的代码。`BSRQ` 指令用于查找最高有效位的位置。

注释 `// amd64/v3:"LZCNTQ", -"BSRQ"` 表示：在 AMD64 架构的 v3 版本中，Go 编译器应该生成包含 `LZCNTQ` 汇编指令（用于计算前导零）但不包含 `BSRQ` 指令的代码。

这些指令帮助 Go 团队验证编译器是否利用了特定 CPU 提供的硬件指令来优化 `math/bits` 函数的性能。

**命令行参数的具体处理:**

这个 `codegen/mathbits.go` 文件本身**不处理任何命令行参数**。 它是作为 Go 代码生成测试的一部分被 Go 的测试框架（`go test` 命令）使用。

通常，你会使用以下命令运行与代码生成相关的测试，但这个文件本身并没有定义如何解析这些参数：

```bash
go test -run=Mathbits  # 可能会有类似的测试用例名字
```

具体的参数控制由 Go 的测试框架和可能的自定义测试脚本来处理，而不是由 `codegen/mathbits.go` 文件自身来处理。

**使用者易犯错的点:**

由于 `codegen/mathbits.go` 是测试代码，普通 Go 开发者通常不会直接使用或修改它。  然而，如果开发者试图理解或维护 Go 编译器，可能会遇到以下易错点：

1. **误解 `asmcheck` 指令的含义:** 不理解 `asmcheck` 指令的语法和作用，可能错误地添加或修改这些指令，导致测试失败或无法有效地验证代码生成。例如，错误地指定了应该存在或不存在的指令。

2. **不了解目标架构的指令集:**  在编写或修改 `asmcheck` 指令时，必须对目标架构的汇编指令集有深入的了解。不正确的指令名称或用法会导致测试失败。

3. **忽略架构变体:** 注意到代码中针对 `amd64/v1`, `amd64/v2`, `amd64/v3` 等不同的架构变体有不同的 `asmcheck` 指令。 忽略这些变体可能导致测试在某些平台上通过，但在其他平台上失败。例如，较新的 CPU 可能支持更高效的指令。

4. **修改代码后未更新 `asmcheck`:**  如果修改了 `codegen/mathbits.go` 中的 Go 代码（即使只是很小的改动），也需要检查相关的 `asmcheck` 指令是否仍然正确。代码的微小变化可能会导致编译器生成不同的汇编代码。

**举例说明一个潜在的错误 (针对 Go 编译器开发者):**

假设一个开发者错误地认为所有 AMD64 架构都支持 `LZCNTQ` 指令，并将 `LeadingZeros` 函数的 `asmcheck` 指令修改为：

```go
func LeadingZeros(n uint) int {
	// amd64:"LZCNTQ" // 错误：v1 和 v2 不一定支持
	return bits.LeadingZeros(n)
}
```

这将导致在较老的 AMD64 处理器上运行测试时失败，因为这些处理器不支持 `LZCNTQ` 指令，编译器不会生成该指令，从而导致 `asmcheck` 失败。正确的做法是保留针对不同 AMD64 版本的区分。

### 提示词
```
这是路径为go/test/codegen/mathbits.go的go语言实现的一部分， 请归纳一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果介绍代码逻辑，则建议带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
```

### 源代码
```
// asmcheck

// Copyright 2018 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package codegen

import "math/bits"

// ----------------------- //
//    bits.LeadingZeros    //
// ----------------------- //

func LeadingZeros(n uint) int {
	// amd64/v1,amd64/v2:"BSRQ"
	// amd64/v3:"LZCNTQ", -"BSRQ"
	// s390x:"FLOGR"
	// arm:"CLZ" arm64:"CLZ"
	// loong64:"CLZV",-"SUB"
	// mips:"CLZ"
	// wasm:"I64Clz"
	// ppc64x:"CNTLZD"
	return bits.LeadingZeros(n)
}

func LeadingZeros64(n uint64) int {
	// amd64/v1,amd64/v2:"BSRQ"
	// amd64/v3:"LZCNTQ", -"BSRQ"
	// s390x:"FLOGR"
	// arm:"CLZ" arm64:"CLZ"
	// loong64:"CLZV",-"SUB"
	// mips:"CLZ"
	// wasm:"I64Clz"
	// ppc64x:"CNTLZD"
	return bits.LeadingZeros64(n)
}

func LeadingZeros32(n uint32) int {
	// amd64/v1,amd64/v2:"BSRQ","LEAQ",-"CMOVQEQ"
	// amd64/v3: "LZCNTL",- "BSRL"
	// s390x:"FLOGR"
	// arm:"CLZ" arm64:"CLZW"
	// loong64:"CLZW",-"SUB"
	// mips:"CLZ"
	// wasm:"I64Clz"
	// ppc64x:"CNTLZW"
	return bits.LeadingZeros32(n)
}

func LeadingZeros16(n uint16) int {
	// amd64/v1,amd64/v2:"BSRL","LEAL",-"CMOVQEQ"
	// amd64/v3: "LZCNTL",- "BSRL"
	// s390x:"FLOGR"
	// arm:"CLZ" arm64:"CLZ"
	// loong64:"CLZV"
	// mips:"CLZ"
	// wasm:"I64Clz"
	// ppc64x:"CNTLZD"
	return bits.LeadingZeros16(n)
}

func LeadingZeros8(n uint8) int {
	// amd64/v1,amd64/v2:"BSRL","LEAL",-"CMOVQEQ"
	// amd64/v3: "LZCNTL",- "BSRL"
	// s390x:"FLOGR"
	// arm:"CLZ" arm64:"CLZ"
	// loong64:"CLZV"
	// mips:"CLZ"
	// wasm:"I64Clz"
	// ppc64x:"CNTLZD"
	return bits.LeadingZeros8(n)
}

// --------------- //
//    bits.Len*    //
// --------------- //

func Len(n uint) int {
	// amd64/v1,amd64/v2:"BSRQ"
	// amd64/v3: "LZCNTQ"
	// s390x:"FLOGR"
	// arm:"CLZ" arm64:"CLZ"
	// loong64:"CLZV"
	// mips:"CLZ"
	// wasm:"I64Clz"
	// ppc64x:"SUBC","CNTLZD"
	return bits.Len(n)
}

func Len64(n uint64) int {
	// amd64/v1,amd64/v2:"BSRQ"
	// amd64/v3: "LZCNTQ"
	// s390x:"FLOGR"
	// arm:"CLZ" arm64:"CLZ"
	// loong64:"CLZV"
	// mips:"CLZ"
	// wasm:"I64Clz"
	// ppc64x:"SUBC","CNTLZD"
	return bits.Len64(n)
}

func SubFromLen64(n uint64) int {
	// loong64:"CLZV",-"ADD"
	// ppc64x:"CNTLZD",-"SUBC"
	return 64 - bits.Len64(n)
}

func CompareWithLen64(n uint64) bool {
	// loong64:"CLZV",-"ADD",-"[$]64",-"[$]9"
	return bits.Len64(n) < 9
}

func Len32(n uint32) int {
	// amd64/v1,amd64/v2:"BSRQ","LEAQ",-"CMOVQEQ"
	// amd64/v3: "LZCNTL"
	// s390x:"FLOGR"
	// arm:"CLZ" arm64:"CLZ"
	// loong64:"CLZW"
	// mips:"CLZ"
	// wasm:"I64Clz"
	// ppc64x: "CNTLZW"
	return bits.Len32(n)
}

func Len16(n uint16) int {
	// amd64/v1,amd64/v2:"BSRL","LEAL",-"CMOVQEQ"
	// amd64/v3: "LZCNTL"
	// s390x:"FLOGR"
	// arm:"CLZ" arm64:"CLZ"
	// loong64:"CLZV"
	// mips:"CLZ"
	// wasm:"I64Clz"
	// ppc64x:"SUBC","CNTLZD"
	return bits.Len16(n)
}

func Len8(n uint8) int {
	// amd64/v1,amd64/v2:"BSRL","LEAL",-"CMOVQEQ"
	// amd64/v3: "LZCNTL"
	// s390x:"FLOGR"
	// arm:"CLZ" arm64:"CLZ"
	// loong64:"CLZV"
	// mips:"CLZ"
	// wasm:"I64Clz"
	// ppc64x:"SUBC","CNTLZD"
	return bits.Len8(n)
}

// -------------------- //
//    bits.OnesCount    //
// -------------------- //

// TODO(register args) Restore a m d 6 4 / v 1 :.*x86HasPOPCNT when only one ABI is tested.
func OnesCount(n uint) int {
	// amd64/v2:-".*x86HasPOPCNT" amd64/v3:-".*x86HasPOPCNT"
	// amd64:"POPCNTQ"
	// arm64:"VCNT","VUADDLV"
	// loong64:"VPCNTV"
	// s390x:"POPCNT"
	// ppc64x:"POPCNTD"
	// wasm:"I64Popcnt"
	return bits.OnesCount(n)
}

func OnesCount64(n uint64) int {
	// amd64/v2:-".*x86HasPOPCNT" amd64/v3:-".*x86HasPOPCNT"
	// amd64:"POPCNTQ"
	// arm64:"VCNT","VUADDLV"
	// loong64:"VPCNTV"
	// s390x:"POPCNT"
	// ppc64x:"POPCNTD"
	// wasm:"I64Popcnt"
	return bits.OnesCount64(n)
}

func OnesCount32(n uint32) int {
	// amd64/v2:-".*x86HasPOPCNT" amd64/v3:-".*x86HasPOPCNT"
	// amd64:"POPCNTL"
	// arm64:"VCNT","VUADDLV"
	// loong64:"VPCNTW"
	// s390x:"POPCNT"
	// ppc64x:"POPCNTW"
	// wasm:"I64Popcnt"
	return bits.OnesCount32(n)
}

func OnesCount16(n uint16) int {
	// amd64/v2:-".*x86HasPOPCNT" amd64/v3:-".*x86HasPOPCNT"
	// amd64:"POPCNTL"
	// arm64:"VCNT","VUADDLV"
	// loong64:"VPCNTH"
	// s390x:"POPCNT"
	// ppc64x:"POPCNTW"
	// wasm:"I64Popcnt"
	return bits.OnesCount16(n)
}

func OnesCount8(n uint8) int {
	// s390x:"POPCNT"
	// ppc64x:"POPCNTB"
	// wasm:"I64Popcnt"
	return bits.OnesCount8(n)
}

// ------------------ //
//    bits.Reverse    //
// ------------------ //

func Reverse(n uint) uint {
	// loong64:"BITREVV"
	return bits.Reverse(n)
}

func Reverse64(n uint64) uint64 {
	// loong64:"BITREVV"
	return bits.Reverse64(n)
}

func Reverse32(n uint32) uint32 {
	// loong64:"BITREVW"
	return bits.Reverse32(n)
}

func Reverse16(n uint16) uint16 {
	// loong64:"BITREV4B","REVB2H"
	return bits.Reverse16(n)
}

func Reverse8(n uint8) uint8 {
	// loong64:"BITREV4B"
	return bits.Reverse8(n)
}

// ----------------------- //
//    bits.ReverseBytes    //
// ----------------------- //

func ReverseBytes(n uint) uint {
	// amd64:"BSWAPQ"
	// 386:"BSWAPL"
	// s390x:"MOVDBR"
	// arm64:"REV"
	// loong64:"REVBV"
	return bits.ReverseBytes(n)
}

func ReverseBytes64(n uint64) uint64 {
	// amd64:"BSWAPQ"
	// 386:"BSWAPL"
	// s390x:"MOVDBR"
	// arm64:"REV"
	// ppc64x/power10: "BRD"
	// loong64:"REVBV"
	return bits.ReverseBytes64(n)
}

func ReverseBytes32(n uint32) uint32 {
	// amd64:"BSWAPL"
	// 386:"BSWAPL"
	// s390x:"MOVWBR"
	// arm64:"REVW"
	// loong64:"REVB2W"
	// ppc64x/power10: "BRW"
	return bits.ReverseBytes32(n)
}

func ReverseBytes16(n uint16) uint16 {
	// amd64:"ROLW"
	// arm64:"REV16W",-"UBFX",-"ORR"
	// arm/5:"SLL","SRL","ORR"
	// arm/6:"REV16"
	// arm/7:"REV16"
	// loong64:"REVB2H"
	// ppc64x/power10: "BRH"
	return bits.ReverseBytes16(n)
}

// --------------------- //
//    bits.RotateLeft    //
// --------------------- //

func RotateLeft64(n uint64) uint64 {
	// amd64:"ROLQ"
	// arm64:"ROR"
	// loong64:"ROTRV"
	// ppc64x:"ROTL"
	// riscv64:"RORI"
	// s390x:"RISBGZ\t[$]0, [$]63, [$]37, "
	// wasm:"I64Rotl"
	return bits.RotateLeft64(n, 37)
}

func RotateLeft32(n uint32) uint32 {
	// amd64:"ROLL" 386:"ROLL"
	// arm:`MOVW\tR[0-9]+@>23`
	// arm64:"RORW"
	// loong64:"ROTR\t"
	// ppc64x:"ROTLW"
	// riscv64:"RORIW"
	// s390x:"RLL"
	// wasm:"I32Rotl"
	return bits.RotateLeft32(n, 9)
}

func RotateLeft16(n uint16, s int) uint16 {
	// amd64:"ROLW" 386:"ROLW"
	// arm64:"RORW",-"CSEL"
	// loong64:"ROTR\t","SLLV"
	return bits.RotateLeft16(n, s)
}

func RotateLeft8(n uint8, s int) uint8 {
	// amd64:"ROLB" 386:"ROLB"
	// arm64:"LSL","LSR",-"CSEL"
	// loong64:"OR","SLLV","SRLV"
	return bits.RotateLeft8(n, s)
}

func RotateLeftVariable(n uint, m int) uint {
	// amd64:"ROLQ"
	// arm64:"ROR"
	// loong64:"ROTRV"
	// ppc64x:"ROTL"
	// riscv64:"ROL"
	// s390x:"RLLG"
	// wasm:"I64Rotl"
	return bits.RotateLeft(n, m)
}

func RotateLeftVariable64(n uint64, m int) uint64 {
	// amd64:"ROLQ"
	// arm64:"ROR"
	// loong64:"ROTRV"
	// ppc64x:"ROTL"
	// riscv64:"ROL"
	// s390x:"RLLG"
	// wasm:"I64Rotl"
	return bits.RotateLeft64(n, m)
}

func RotateLeftVariable32(n uint32, m int) uint32 {
	// arm:`MOVW\tR[0-9]+@>R[0-9]+`
	// amd64:"ROLL"
	// arm64:"RORW"
	// loong64:"ROTR\t"
	// ppc64x:"ROTLW"
	// riscv64:"ROLW"
	// s390x:"RLL"
	// wasm:"I32Rotl"
	return bits.RotateLeft32(n, m)
}

// ------------------------ //
//    bits.TrailingZeros    //
// ------------------------ //

func TrailingZeros(n uint) int {
	// amd64/v1,amd64/v2:"BSFQ","MOVL\t\\$64","CMOVQEQ"
	// amd64/v3:"TZCNTQ"
	// 386:"BSFL"
	// arm:"CLZ"
	// arm64:"RBIT","CLZ"
	// loong64:"CTZV"
	// s390x:"FLOGR"
	// ppc64x/power8:"ANDN","POPCNTD"
	// ppc64x/power9: "CNTTZD"
	// wasm:"I64Ctz"
	return bits.TrailingZeros(n)
}

func TrailingZeros64(n uint64) int {
	// amd64/v1,amd64/v2:"BSFQ","MOVL\t\\$64","CMOVQEQ"
	// amd64/v3:"TZCNTQ"
	// 386:"BSFL"
	// arm64:"RBIT","CLZ"
	// loong64:"CTZV"
	// s390x:"FLOGR"
	// ppc64x/power8:"ANDN","POPCNTD"
	// ppc64x/power9: "CNTTZD"
	// wasm:"I64Ctz"
	return bits.TrailingZeros64(n)
}

func TrailingZeros64Subtract(n uint64) int {
	// ppc64x/power8:"NEG","SUBC","ANDN","POPCNTD"
	// ppc64x/power9:"SUBC","CNTTZD"
	return bits.TrailingZeros64(1 - n)
}

func TrailingZeros32(n uint32) int {
	// amd64/v1,amd64/v2:"BTSQ\\t\\$32","BSFQ"
	// amd64/v3:"TZCNTL"
	// 386:"BSFL"
	// arm:"CLZ"
	// arm64:"RBITW","CLZW"
	// loong64:"CTZW"
	// s390x:"FLOGR","MOVWZ"
	// ppc64x/power8:"ANDN","POPCNTW"
	// ppc64x/power9: "CNTTZW"
	// wasm:"I64Ctz"
	return bits.TrailingZeros32(n)
}

func TrailingZeros16(n uint16) int {
	// amd64:"BSFL","ORL\\t\\$65536"
	// 386:"BSFL\t"
	// arm:"ORR\t\\$65536","CLZ",-"MOVHU\tR"
	// arm64:"ORR\t\\$65536","RBITW","CLZW",-"MOVHU\tR",-"RBIT\t",-"CLZ\t"
	// loong64:"CTZV"
	// s390x:"FLOGR","OR\t\\$65536"
	// ppc64x/power8:"POPCNTD","ORIS\\t\\$1"
	// ppc64x/power9:"CNTTZD","ORIS\\t\\$1"
	// wasm:"I64Ctz"
	return bits.TrailingZeros16(n)
}

func TrailingZeros8(n uint8) int {
	// amd64:"BSFL","ORL\\t\\$256"
	// 386:"BSFL"
	// arm:"ORR\t\\$256","CLZ",-"MOVBU\tR"
	// arm64:"ORR\t\\$256","RBITW","CLZW",-"MOVBU\tR",-"RBIT\t",-"CLZ\t"
	// loong64:"CTZV"
	// s390x:"FLOGR","OR\t\\$256"
	// wasm:"I64Ctz"
	return bits.TrailingZeros8(n)
}

// IterateBitsNN checks special handling of TrailingZerosNN when the input is known to be non-zero.

func IterateBits(n uint) int {
	i := 0
	for n != 0 {
		// amd64/v1,amd64/v2:"BSFQ",-"CMOVEQ"
		// amd64/v3:"TZCNTQ"
		i += bits.TrailingZeros(n)
		n &= n - 1
	}
	return i
}

func IterateBits64(n uint64) int {
	i := 0
	for n != 0 {
		// amd64/v1,amd64/v2:"BSFQ",-"CMOVEQ"
		// amd64/v3:"TZCNTQ"
		i += bits.TrailingZeros64(n)
		n &= n - 1
	}
	return i
}

func IterateBits32(n uint32) int {
	i := 0
	for n != 0 {
		// amd64/v1,amd64/v2:"BSFL",-"BTSQ"
		// amd64/v3:"TZCNTL"
		i += bits.TrailingZeros32(n)
		n &= n - 1
	}
	return i
}

func IterateBits16(n uint16) int {
	i := 0
	for n != 0 {
		// amd64/v1,amd64/v2:"BSFL",-"BTSL"
		// amd64/v3:"TZCNTL"
		// arm64:"RBITW","CLZW",-"ORR"
		i += bits.TrailingZeros16(n)
		n &= n - 1
	}
	return i
}

func IterateBits8(n uint8) int {
	i := 0
	for n != 0 {
		// amd64/v1,amd64/v2:"BSFL",-"BTSL"
		// amd64/v3:"TZCNTL"
		// arm64:"RBITW","CLZW",-"ORR"
		i += bits.TrailingZeros8(n)
		n &= n - 1
	}
	return i
}

// --------------- //
//    bits.Add*    //
// --------------- //

func Add(x, y, ci uint) (r, co uint) {
	// arm64:"ADDS","ADCS","ADC",-"ADD\t",-"CMP"
	// amd64:"NEGL","ADCQ","SBBQ","NEGQ"
	// ppc64x: "ADDC", "ADDE", "ADDZE"
	// s390x:"ADDE","ADDC\t[$]-1,"
	// riscv64: "ADD","SLTU"
	return bits.Add(x, y, ci)
}

func AddC(x, ci uint) (r, co uint) {
	// arm64:"ADDS","ADCS","ADC",-"ADD\t",-"CMP"
	// amd64:"NEGL","ADCQ","SBBQ","NEGQ"
	// loong64: "ADDV", "SGTU"
	// ppc64x: "ADDC", "ADDE", "ADDZE"
	// s390x:"ADDE","ADDC\t[$]-1,"
	// mips64:"ADDV","SGTU"
	// riscv64: "ADD","SLTU"
	return bits.Add(x, 7, ci)
}

func AddZ(x, y uint) (r, co uint) {
	// arm64:"ADDS","ADC",-"ADCS",-"ADD\t",-"CMP"
	// amd64:"ADDQ","SBBQ","NEGQ",-"NEGL",-"ADCQ"
	// loong64: "ADDV", "SGTU"
	// ppc64x: "ADDC", -"ADDE", "ADDZE"
	// s390x:"ADDC",-"ADDC\t[$]-1,"
	// mips64:"ADDV","SGTU"
	// riscv64: "ADD","SLTU"
	return bits.Add(x, y, 0)
}

func AddR(x, y, ci uint) uint {
	// arm64:"ADDS","ADCS",-"ADD\t",-"CMP"
	// amd64:"NEGL","ADCQ",-"SBBQ",-"NEGQ"
	// loong64: "ADDV", -"SGTU"
	// ppc64x: "ADDC", "ADDE", -"ADDZE"
	// s390x:"ADDE","ADDC\t[$]-1,"
	// mips64:"ADDV",-"SGTU"
	// riscv64: "ADD",-"SLTU"
	r, _ := bits.Add(x, y, ci)
	return r
}

func AddM(p, q, r *[3]uint) {
	var c uint
	r[0], c = bits.Add(p[0], q[0], c)
	// arm64:"ADCS",-"ADD\t",-"CMP"
	// amd64:"ADCQ",-"NEGL",-"SBBQ",-"NEGQ"
	// s390x:"ADDE",-"ADDC\t[$]-1,"
	r[1], c = bits.Add(p[1], q[1], c)
	r[2], c = bits.Add(p[2], q[2], c)
}

func Add64(x, y, ci uint64) (r, co uint64) {
	// arm64:"ADDS","ADCS","ADC",-"ADD\t",-"CMP"
	// amd64:"NEGL","ADCQ","SBBQ","NEGQ"
	// loong64: "ADDV", "SGTU"
	// ppc64x: "ADDC", "ADDE", "ADDZE"
	// s390x:"ADDE","ADDC\t[$]-1,"
	// mips64:"ADDV","SGTU"
	// riscv64: "ADD","SLTU"
	return bits.Add64(x, y, ci)
}

func Add64C(x, ci uint64) (r, co uint64) {
	// arm64:"ADDS","ADCS","ADC",-"ADD\t",-"CMP"
	// amd64:"NEGL","ADCQ","SBBQ","NEGQ"
	// loong64: "ADDV", "SGTU"
	// ppc64x: "ADDC", "ADDE", "ADDZE"
	// s390x:"ADDE","ADDC\t[$]-1,"
	// mips64:"ADDV","SGTU"
	// riscv64: "ADD","SLTU"
	return bits.Add64(x, 7, ci)
}

func Add64Z(x, y uint64) (r, co uint64) {
	// arm64:"ADDS","ADC",-"ADCS",-"ADD\t",-"CMP"
	// amd64:"ADDQ","SBBQ","NEGQ",-"NEGL",-"ADCQ"
	// loong64: "ADDV", "SGTU"
	// ppc64x: "ADDC", -"ADDE", "ADDZE"
	// s390x:"ADDC",-"ADDC\t[$]-1,"
	// mips64:"ADDV","SGTU"
	// riscv64: "ADD","SLTU"
	return bits.Add64(x, y, 0)
}

func Add64R(x, y, ci uint64) uint64 {
	// arm64:"ADDS","ADCS",-"ADD\t",-"CMP"
	// amd64:"NEGL","ADCQ",-"SBBQ",-"NEGQ"
	// loong64: "ADDV", -"SGTU"
	// ppc64x: "ADDC", "ADDE", -"ADDZE"
	// s390x:"ADDE","ADDC\t[$]-1,"
	// mips64:"ADDV",-"SGTU"
	// riscv64: "ADD",-"SLTU"
	r, _ := bits.Add64(x, y, ci)
	return r
}

func Add64M(p, q, r *[3]uint64) {
	var c uint64
	r[0], c = bits.Add64(p[0], q[0], c)
	// arm64:"ADCS",-"ADD\t",-"CMP"
	// amd64:"ADCQ",-"NEGL",-"SBBQ",-"NEGQ"
	// ppc64x: -"ADDC", "ADDE", -"ADDZE"
	// s390x:"ADDE",-"ADDC\t[$]-1,"
	r[1], c = bits.Add64(p[1], q[1], c)
	r[2], c = bits.Add64(p[2], q[2], c)
}

func Add64M0(p, q, r *[3]uint64) {
	var c uint64
	r[0], c = bits.Add64(p[0], q[0], 0)
	// ppc64x: -"ADDC", -"ADDE", "ADDZE\tR[1-9]"
	r[1], c = bits.Add64(p[1], 0, c)
	// ppc64x: -"ADDC", "ADDE", -"ADDZE"
	r[2], c = bits.Add64(p[2], p[2], c)
}

func Add64MSaveC(p, q, r, c *[2]uint64) {
	// ppc64x: "ADDC\tR", "ADDZE"
	r[0], c[0] = bits.Add64(p[0], q[0], 0)
	// ppc64x: "ADDC\t[$]-1", "ADDE", "ADDZE"
	r[1], c[1] = bits.Add64(p[1], q[1], c[0])
}

func Add64PanicOnOverflowEQ(a, b uint64) uint64 {
	r, c := bits.Add64(a, b, 0)
	// s390x:"BRC\t[$]3,",-"ADDE"
	if c == 1 {
		panic("overflow")
	}
	return r
}

func Add64PanicOnOverflowNE(a, b uint64) uint64 {
	r, c := bits.Add64(a, b, 0)
	// s390x:"BRC\t[$]3,",-"ADDE"
	if c != 0 {
		panic("overflow")
	}
	return r
}

func Add64PanicOnOverflowGT(a, b uint64) uint64 {
	r, c := bits.Add64(a, b, 0)
	// s390x:"BRC\t[$]3,",-"ADDE"
	if c > 0 {
		panic("overflow")
	}
	return r
}

func Add64MPanicOnOverflowEQ(a, b [2]uint64) [2]uint64 {
	var r [2]uint64
	var c uint64
	r[0], c = bits.Add64(a[0], b[0], c)
	r[1], c = bits.Add64(a[1], b[1], c)
	// s390x:"BRC\t[$]3,"
	if c == 1 {
		panic("overflow")
	}
	return r
}

func Add64MPanicOnOverflowNE(a, b [2]uint64) [2]uint64 {
	var r [2]uint64
	var c uint64
	r[0], c = bits.Add64(a[0], b[0], c)
	r[1], c = bits.Add64(a[1], b[1], c)
	// s390x:"BRC\t[$]3,"
	if c != 0 {
		panic("overflow")
	}
	return r
}

func Add64MPanicOnOverflowGT(a, b [2]uint64) [2]uint64 {
	var r [2]uint64
	var c uint64
	r[0], c = bits.Add64(a[0], b[0], c)
	r[1], c = bits.Add64(a[1], b[1], c)
	// s390x:"BRC\t[$]3,"
	if c > 0 {
		panic("overflow")
	}
	return r
}

// Verify independent carry chain operations are scheduled efficiently
// and do not cause unnecessary save/restore of the CA bit.
//
// This is an example of why CarryChainTail priority must be lower
// (earlier in the block) than Memory. f[0]=f1 could be scheduled
// after the first two lower 64 bit limb adds, but before either
// high 64 bit limbs are added.
//
// This is what happened on PPC64 when compiling
// crypto/internal/edwards25519/field.feMulGeneric.
func Add64MultipleChains(a, b, c, d [2]uint64) {
	var cx, d1, d2 uint64
	a1, a2 := a[0], a[1]
	b1, b2 := b[0], b[1]
	c1, c2 := c[0], c[1]

	// ppc64x: "ADDC\tR\\d+,", -"ADDE", -"MOVD\tXER"
	d1, cx = bits.Add64(a1, b1, 0)
	// ppc64x: "ADDE", -"ADDC", -"MOVD\t.*, XER"
	d2, _ = bits.Add64(a2, b2, cx)

	// ppc64x: "ADDC\tR\\d+,", -"ADDE", -"MOVD\tXER"
	d1, cx = bits.Add64(c1, d1, 0)
	// ppc64x: "ADDE", -"ADDC", -"MOVD\t.*, XER"
	d2, _ = bits.Add64(c2, d2, cx)
	d[0] = d1
	d[1] = d2
}

// --------------- //
//    bits.Sub*    //
// --------------- //

func Sub(x, y, ci uint) (r, co uint) {
	// amd64:"NEGL","SBBQ","NEGQ"
	// arm64:"NEGS","SBCS","NGC","NEG",-"ADD",-"SUB",-"CMP"
	// loong64:"SUBV","SGTU"
	// ppc64x:"SUBC", "SUBE", "SUBZE", "NEG"
	// s390x:"SUBE"
	// mips64:"SUBV","SGTU"
	// riscv64: "SUB","SLTU"
	return bits.Sub(x, y, ci)
}

func SubC(x, ci uint) (r, co uint) {
	// amd64:"NEGL","SBBQ","NEGQ"
	// arm64:"NEGS","SBCS","NGC","NEG",-"ADD",-"SUB",-"CMP"
	// loong64:"SUBV","SGTU"
	// ppc64x:"SUBC", "SUBE", "SUBZE", "NEG"
	// s390x:"SUBE"
	// mips64:"SUBV","SGTU"
	// riscv64: "SUB","SLTU"
	return bits.Sub(x, 7, ci)
}

func SubZ(x, y uint) (r, co uint) {
	// amd64:"SUBQ","SBBQ","NEGQ",-"NEGL"
	// arm64:"SUBS","NGC","NEG",-"SBCS",-"ADD",-"SUB\t",-"CMP"
	// loong64:"SUBV","SGTU"
	// ppc64x:"SUBC", -"SUBE", "SUBZE", "NEG"
	// s390x:"SUBC"
	// mips64:"SUBV","SGTU"
	// riscv64: "SUB","SLTU"
	return bits.Sub(x, y, 0)
}

func SubR(x, y, ci uint) uint {
	// amd64:"NEGL","SBBQ",-"NEGQ"
	// arm64:"NEGS","SBCS",-"NGC",-"NEG\t",-"ADD",-"SUB",-"CMP"
	// loong64:"SUBV",-"SGTU"
	// ppc64x:"SUBC", "SUBE", -"SUBZE", -"NEG"
	// s390x:"SUBE"
	// riscv64: "SUB",-"SLTU"
	r, _ := bits.Sub(x, y, ci)
	return r
}
func SubM(p, q, r *[3]uint) {
	var c uint
	r[0], c = bits.Sub(p[0], q[0], c)
	// amd64:"SBBQ",-"NEGL",-"NEGQ"
	// arm64:"SBCS",-"NEGS",-"NGC",-"NEG",-"ADD",-"SUB",-"CMP"
	// ppc64x:-"SUBC", "SUBE", -"SUBZE", -"NEG"
	// s390x:"SUBE"
	r[1], c = bits.Sub(p[1], q[1], c)
	r[2], c = bits.Sub(p[2], q[2], c)
}

func Sub64(x, y, ci uint64) (r, co uint64) {
	// amd64:"NEGL","SBBQ","NEGQ"
	// arm64:"NEGS","SBCS","NGC","NEG",-"ADD",-"SUB",-"CMP"
	// loong64:"SUBV","SGTU"
	// ppc64x:"SUBC", "SUBE", "SUBZE", "NEG"
	// s390x:"SUBE"
	// mips64:"SUBV","SGTU"
	// riscv64: "SUB","SLTU"
	return bits.Sub64(x, y, ci)
}

func Sub64C(x, ci uint64) (r, co uint64) {
	// amd64:"NEGL","SBBQ","NEGQ"
	// arm64:"NEGS","SBCS","NGC","NEG",-"ADD",-"SUB",-"CMP"
	// loong64:"SUBV","SGTU"
	// ppc64x:"SUBC", "SUBE", "SUBZE", "NEG"
	// s390x:"SUBE"
	// mips64:"SUBV","SGTU"
	// riscv64: "SUB","SLTU"
	return bits.Sub64(x, 7, ci)
}

func Sub64Z(x, y uint64) (r, co uint64) {
	// amd64:"SUBQ","SBBQ","NEGQ",-"NEGL"
	// arm64:"SUBS","NGC","NEG",-"SBCS",-"ADD",-"SUB\t",-"CMP"
	// loong64:"SUBV","SGTU"
	// ppc64x:"SUBC", -"SUBE", "SUBZE", "NEG"
	// s390x:"SUBC"
	// mips64:"SUBV","SGTU"
	// riscv64: "SUB","SLTU"
	return bits.Sub64(x, y, 0)
}

func Sub64R(x, y, ci uint64) uint64 {
	// amd64:"NEGL","SBBQ",-"NEGQ"
	// arm64:"NEGS","SBCS",-"NGC",-"NEG\t",-"ADD",-"SUB",-"CMP"
	// loong64:"SUBV",-"SGTU"
	// ppc64x:"SUBC", "SUBE", -"SUBZE", -"NEG"
	// s390x:"SUBE"
	// riscv64: "SUB",-"SLTU"
	r, _ := bits.Sub64(x, y, ci)
	return r
}
func Sub64M(p, q, r *[3]uint64) {
	var c uint64
	r[0], c = bits.Sub64(p[0], q[0], c)
	// amd64:"SBBQ",-"NEGL",-"NEGQ"
	// arm64:"SBCS",-"NEGS",-"NGC",-"NEG",-"ADD",-"SUB",-"CMP"
	// s390x:"SUBE"
	r[1], c = bits.Sub64(p[1], q[1], c)
	r[2], c = bits.Sub64(p[2], q[2], c)
}

func Sub64MSaveC(p, q, r, c *[2]uint64) {
	// ppc64x:"SUBC\tR\\d+, R\\d+,", "SUBZE", "NEG"
	r[0], c[0] = bits.Sub64(p[0], q[0], 0)
	// ppc64x:"SUBC\tR\\d+, [$]0,", "SUBE", "SUBZE", "NEG"
	r[1], c[1] = bits.Sub64(p[1], q[1], c[0])
}

func Sub64PanicOnOverflowEQ(a, b uint64) uint64 {
	r, b := bits.Sub64(a, b, 0)
	// s390x:"BRC\t[$]12,",-"ADDE",-"SUBE"
	if b == 1 {
		panic("overflow")
	}
	return r
}

func Sub64PanicOnOverflowNE(a, b uint64) uint64 {
	r, b := bits.Sub64(a, b, 0)
	// s390x:"BRC\t[$]12,",-"ADDE",-"SUBE"
	if b != 0 {
		panic("overflow")
	}
	return r
}

func Sub64PanicOnOverflowGT(a, b uint64) uint64 {
	r, b := bits.Sub64(a, b, 0)
	// s390x:"BRC\t[$]12,",-"ADDE",-"SUBE"
	if b > 0 {
		panic("overflow")
	}
	return r
}

func Sub64MPanicOnOverflowEQ(a, b [2]uint64) [2]uint64 {
	var r [2]uint64
	var c uint64
	r[0], c = bits.Sub64(a[0], b[0], c)
	r[1], c = bits.Sub64(a[1], b[1], c)
	// s390x:"BRC\t[$]12,"
	if c == 1 {
		panic("overflow")
	}
	return r
}

func Sub64MPanicOnOverflowNE(a, b [2]uint64) [2]uint64 {
	var r [2]uint64
	var c uint64
	r[0], c = bits.Sub64(a[0], b[0], c)
	r[1], c = bits.Sub64(a[1], b[1], c)
	// s390x:"BRC\t[$]12,"
	if c != 0 {
		panic("overflow")
	}
	return r
}

func Sub64MPanicOnOverflowGT(a, b [2]uint64) [2]uint64 {
	var r [2]uint64
	var c uint64
	r[0], c = bits.Sub64(a[0], b[0], c)
	r[1], c = bits.Sub64(a[1], b[1], c)
	// s390x:"BRC\t[$]12,"
	if c > 0 {
		panic("overflow")
	}
	return r
}

// --------------- //
//    bits.Mul*    //
// --------------- //

func Mul(x, y uint) (hi, lo uint) {
	// amd64:"MULQ"
	// arm64:"UMULH","MUL"
	// ppc64x:"MULHDU","MULLD"
	// s390x:"MLGR"
	// mips64: "MULVU"
	// riscv64:"MULHU","MUL"
	return bits.Mul(x, y)
}

func Mul64(x, y uint64) (hi, lo uint64) {
	// amd64:"MULQ"
	// arm64:"UMULH","MUL"
	// ppc64x:"MULHDU","MULLD"
	// s390x:"MLGR"
	// mips64: "MULVU"
	// riscv64:"MULHU","MUL"
	return bits.Mul64(x, y)
}

func Mul64HiOnly(x, y uint64) uint64 {
	// arm64:"UMULH",-"MUL"
	// riscv64:"MULHU",-"MUL\t"
	hi, _ := bits.Mul64(x, y)
	return hi
}

func Mul64LoOnly(x, y uint64) uint64 {
	// arm64:"MUL",-"UMULH"
	// riscv64:"MUL\t",-"MULHU"
	_, lo := bits.Mul64(x, y)
	return lo
}

// --------------- //
//    bits.Div*    //
// --------------- //

func Div(hi, lo, x uint) (q, r uint) {
	// amd64:"DIVQ"
	return bits.Div(hi, lo, x)
}

func Div32(hi, lo, x uint32) (q, r uint32) {
	// arm64:"ORR","UDIV","MSUB",-"UREM"
	return bits.Div32(hi, lo, x)
}

func Div64(hi, lo, x uint64) (q, r uint64) {
	// amd64:"DIVQ"
	return bits.Div64(hi, lo, x)
}

func Div64degenerate(x uint64) (q, r uint64) {
	// amd64:-"DIVQ"
	return bits.Div64(0, x, 5)
}
```