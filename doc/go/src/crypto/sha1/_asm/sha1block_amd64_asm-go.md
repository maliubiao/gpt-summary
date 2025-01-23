Response:
Let's break down the thought process for analyzing this assembly code generator.

1. **Initial Understanding - What is this?** The first lines are crucial. We see `// Copyright`, a package declaration (`package main`), and import statements including `github.com/mmcloughlin/avo/build`. The `//go:generate` comment strongly suggests this is code that *generates* other Go code, specifically assembly. The filename `sha1block_amd64_asm.go` reinforces that the target is assembly for SHA1 on AMD64.

2. **Core Library - Avo:**  The imports involving `avo` are key. A quick search reveals that Avo is a Go library for generating x86 assembly code. This immediately tells us the primary function of this file: to programmatically create assembly instructions for SHA1.

3. **Overall Structure - `main` function:** The `main` function is the entry point. It calls `Package`, `ConstraintExpr`, `blockAMD64`, `blockAVX2`, and `Generate`. This suggests:
    * `Package`:  Sets the target Go package.
    * `ConstraintExpr`:  Likely adds a build constraint (e.g., ensuring this assembly is only used when `purego` isn't set).
    * `blockAMD64` and `blockAVX2`:  These clearly generate assembly code for different instruction sets (base AMD64 and AVX2).
    * `Generate`:  This is the trigger to actually produce the assembly output.

4. **Decomposition -  Helper Functions:** The code is then filled with many functions like `LOAD`, `SHUFFLE`, `FUNC1` through `FUNC4`, `MIX`, `ROUND1` through `ROUND4`, `PRECALC_*`, and `CALC_*`. These look like building blocks for the SHA1 algorithm:
    * **`LOAD`, `SHUFFLE`**:  Suggest data manipulation, likely loading data into registers and rearranging it.
    * **`FUNC1`-`FUNC4`**:  These likely represent the different logical functions used in the SHA1 rounds.
    * **`MIX`**:  Looks like a core operation combining registers and constants.
    * **`ROUND1`-`ROUND4`**:  Combine the above functions to implement the different rounds of SHA1. The `x` variant likely indicates a slight variation or optimization.
    * **`PRECALC_*`**:  These are specific to the AVX2 implementation and hint at pre-computing values for optimization, as the comments describe.
    * **`CALC_*`**:  These appear to be the core calculation steps within the AVX2 SHA1 implementation, again with variations for different rounds.

5. **Implementation Logic - `blockAMD64` and `blockAVX2`:** These functions are where the assembly generation happens for the two architectures:
    * **`blockAMD64`**:  Uses standard x86-64 instructions. It loads parameters (digest, input pointer, length), sets up registers, and then enters a loop (`loop_amd64`). The loop iterates through the input data, performing the SHA1 rounds.
    * **`blockAVX2`**:  Uses AVX2 instructions for parallel processing. It also has a `PRECALC` function to prepare data and then a `loop_avx2` and `begin` structure for the main processing. The comments within `blockAVX2` are very helpful in understanding the optimization techniques.

6. **Instruction Level - Avo Syntax:**  The code uses Avo's syntax (e.g., `MOVL`, `ADDL`, `XORL`, `ROLL`, `Mem`, `Imm`, `GPPhysical`, `VecPhysical`). This syntax maps directly to x86 assembly instructions and operands. Understanding Avo's conventions is essential for truly grasping the generated assembly.

7. **Inferring Functionality - SHA1:** The function names, the presence of rounds, logical functions, and the overall structure strongly point to an implementation of the SHA1 hash algorithm. The constants used in the `MIX` and `PRECALC_*` functions are also characteristic of SHA1.

8. **Code Example Construction:** To provide a Go example, we need to show how this generated assembly would be used. Since this code is within the `crypto/sha1` package, we can assume it's replacing the standard Go implementation when the `!purego` constraint is met. Therefore, a standard use of `crypto/sha1` would demonstrate its functionality.

9. **Command Line Arguments:** The `//go:generate` line is the key here. It shows how to run this program: `go run . -out ../sha1block_amd64.s -pkg sha1`. This reveals the command-line flags for specifying the output file (`-out`) and the package name (`-pkg`).

10. **Common Mistakes:**  Considering the complexity of assembly generation and optimization, potential mistakes include:
    * **Incorrect Avo syntax:**  Typos or misunderstandings of Avo's rules.
    * **Register allocation errors:**  Using the wrong registers or not saving/restoring them correctly.
    * **Logic errors in the SHA1 algorithm:**  Implementing the rounds or functions incorrectly.
    * **AVX2 specific errors:**  Incorrect usage of vector instructions or alignment issues.

11. **Summarization (Part 1):** The request specifically asks for a summary of the first part. This involves focusing on the overall purpose, the AMD64 implementation, and the role of the helper functions up to that point.

By following these steps, we can systematically dissect the provided Go code, understand its purpose, and address all the points raised in the prompt. The key is to start with the high-level structure and gradually delve into the details, leveraging the available comments and knowledge of the underlying technologies (Go, assembly, SHA1, Avo).
这是第1部分，主要负责生成用于计算 SHA1 哈希值的 AMD64 架构的汇编代码。它使用了 `github.com/mmcloughlin/avo` 这个库来构建汇编指令。

**功能归纳:**

1. **生成 SHA1 算法的 AMD64 汇编实现:**  核心目标是创建高效的汇编代码，用于在 AMD64 架构的处理器上计算 SHA1 哈希值。
2. **提供两种实现方式:**
    * **`blockAMD64()`:** 生成基础的 AMD64 指令实现的 SHA1 块处理函数。
    * **`blockAVX2()`:** 生成利用 AVX2 指令集优化的 SHA1 块处理函数，以提高性能。
3. **使用 Avo 库简化汇编代码生成:**  利用 Avo 库提供的 Go 语言 API 来构造汇编指令，例如 `MOVL` (移动 32 位值), `ADDL` (加法), `XORL` (异或), `ROLL` (循环左移) 等。这比直接编写汇编代码更易于理解和维护。
4. **定义了 SHA1 算法的各个步骤:**  通过一系列的 Go 函数（如 `LOAD`, `SHUFFLE`, `FUNC1`-`FUNC4`, `MIX`, `ROUND1`-`ROUND4`）抽象地定义了 SHA1 算法的各个组成部分和计算步骤。
5. **`blockAMD64()` 函数实现了 SHA1 的主循环:**  该函数包含了 SHA1 算法的核心循环，通过调用 `ROUND` 系列函数来执行 80 轮的计算。
6. **`blockAVX2()` 函数实现了利用 AVX2 优化的 SHA1 算法:**  该函数使用 AVX2 指令集进行并行计算，并采用了预计算等优化策略，以获得更高的性能。

**更详细的功能分解:**

* **`//go:generate go run . -out ../sha1block_amd64.s -pkg sha1`**:  这是一个 Go 指令，指示在构建时运行当前代码。
    * `go run .`: 运行当前目录下的 `main.go` 文件。
    * `-out ../sha1block_amd64.s`:  指定生成的汇编代码输出到 `../sha1block_amd64.s` 文件。
    * `-pkg sha1`:  指定生成的汇编代码属于 `sha1` 包。
* **`main()` 函数:**  程序的入口点，负责调用各个汇编代码生成函数。
    * `Package("crypto/sha1")`:  设置生成的汇编代码所属的 Go 包为 `crypto/sha1`。
    * `ConstraintExpr("!purego")`:  添加一个构建约束，意味着这段汇编代码只在 `purego` 构建标签未设置时才会被编译。这通常用于提供特定平台的优化实现，而 `purego` 标签则表示使用纯 Go 实现。
    * `blockAMD64()`: 调用生成基础 AMD64 实现的函数。
    * `blockAVX2()`: 调用生成 AVX2 优化实现的函数。
    * `Generate()`:  触发 Avo 库生成汇编代码。
* **`LOAD(index int)`:**  从内存中加载一个 32 位字（4 字节）到寄存器 `R10L`，然后进行字节序转换 (`BSWAPL`)，最后存回到栈上的指定位置。这可能是为了按正确的顺序处理输入数据。
* **`SHUFFLE(index int)`:**  从栈上加载四个 32 位字，进行异或和循环左移操作，并将结果存回栈上的指定位置。这对应于 SHA1 算法中的消息扩展步骤。
* **`FUNC1(a, b, c, d, e GPPhysical)` - `FUNC4(a, b, c, d, e GPPhysical)`:**  定义了 SHA1 算法中使用的四个不同的非线性函数。这些函数接收五个通用寄存器作为输入。
* **`MIX(a, b, c, d, e GPPhysical, konst int)`:**  执行一系列的位操作和加法，将中间结果混合在一起，并加上一个常量。这对应于 SHA1 算法中的核心计算步骤。
* **`ROUND1(a, b, c, d, e GPPhysical, index int)` - `ROUND4(a, b, c, d, e GPPhysical, index int)`:**  定义了 SHA1 算法的四种不同类型的轮函数，分别调用了 `LOAD` 或 `SHUFFLE`，对应的 `FUNC` 函数和 `MIX` 函数。
* **`blockAMD64()` 函数的详细流程:**
    * `Implement("blockAMD64")`:  声明要实现的汇编函数名为 `blockAMD64`。
    * `Attributes(NOSPLIT)`:  指定该函数不进行栈分裂优化。
    * `AllocLocal(64)`:  在栈上分配 64 字节的本地存储空间。
    * `Load(Param("dig"), RBP)`:  加载名为 `dig` 的参数到 `RBP` 寄存器，这个参数很可能指向存储哈希值的摘要（digest）的内存区域。
    * `Load(Param("p").Base(), RSI)`: 加载名为 `p` 的参数的基地址到 `RSI` 寄存器，`p` 很可能指向输入数据。
    * `Load(Param("p").Len(), RDX)`: 加载名为 `p` 的参数的长度到 `RDX` 寄存器。
    * `SHRQ(Imm(6), RDX)` / `SHLQ(Imm(6), RDX)`:  对输入数据长度进行位运算，这可能是为了处理 64 字节的块。
    * `LEAQ(Mem{Base: SI, Index: DX, Scale: 1}, RDI)`: 计算输入数据末尾的地址。
    * 加载初始的哈希值（从 `dig` 参数中）到 `EAX`, `EBX`, `ECX`, `EDX`, `EBP` 寄存器。
    * `CMPQ(RSI, RDI)` / `JEQ(LabelRef("end"))`:  检查输入数据是否为空。
    * `loop_amd64()`:  跳转到主循环。
    * `end()`:  标签，表示处理结束。
* **`loop_amd64()` 函数的详细流程:**
    * `Label("loop")`:  定义循环的标签。
    * 将当前的哈希值备份到 `R11L` - `R15L` 寄存器。
    * 执行 16 轮 `ROUND1` 计算。
    * 执行 4 轮 `ROUND1x` 计算。
    * 执行 20 轮 `ROUND2` 计算。
    * 执行 20 轮 `ROUND3` 计算。
    * 执行 20 轮 `ROUND4` 计算。
    * 将计算结果加回到原始的哈希值。
    * `ADDQ(Imm(64), RSI)`:  将输入数据指针移动到下一个 64 字节块。
    * `CMPQ(RSI, RDI)` / `JB(LabelRef("loop"))`:  检查是否还有更多数据需要处理，如果有则跳转回循环开始。
* **`end()` 函数:**
    * `Label("end")`: 定义结束标签。
    * `Load(Param("dig"), RDI)`:  加载 `dig` 参数到 `RDI` 寄存器。
    * 将计算得到的哈希值从寄存器存回到 `dig` 指向的内存位置。
    * `RET()`:  返回。

**推断 Go 语言功能的实现:**

这段代码是 `crypto/sha1` 包中 `block` 函数的汇编优化实现。`block` 函数负责处理输入数据的 64 字节块，并更新 SHA1 的内部状态（即哈希值）。

**Go 代码示例:**

```go
package main

import (
	"crypto/sha1"
	"fmt"
)

func main() {
	data := []byte("hello world")
	h := sha1.New()
	h.Write(data)
	bs := h.Sum(nil)
	fmt.Printf("%x\n", bs) // 输出 SHA1 哈希值
}
```

**假设的输入与输出:**

如果 `blockAMD64` 函数接收的参数 `dig` 指向一个 20 字节的数组，且初始值为全零，`p` 指向包含 "hello world" 字符串的内存，`len(p)` 为 11，那么经过 `blockAMD64` (或其循环部分，因为 "hello world" 不满一个 64 字节的块) 处理后，`dig` 指向的数组将会存储 "hello world" 的 SHA1 哈希值的中间状态（如果数据不满 64 字节，则不会完成完整的 block 处理）。对于完整的 64 字节块，输出将是该块处理后的 SHA1 状态。

**命令行参数的具体处理:**

在 `//go:generate` 指令中：

* **`.`**: 表示运行当前目录。
* **`-out ../sha1block_amd64.s`**:  `avo` 库会接收这个参数，并将生成的汇编代码输出到相对于当前文件路径的 `../sha1block_amd64.s` 文件中。
* **`-pkg sha1`**: `avo` 库会接收这个参数，并将生成的汇编代码声明为属于 `sha1` 包。

**使用者易犯错的点:**

由于这段代码是汇编代码的生成器，直接的用户不太可能与之交互。开发者在使用 `avo` 编写类似代码时，容易犯错的点包括：

* **错误的 Avo API 使用:**  例如，使用了不存在的指令、错误的寄存器名称或操作数类型。
* **对汇编指令理解不透彻:**  可能生成了不符合预期或效率低下的汇编代码。
* **寄存器分配错误:**  没有正确地保存和恢复寄存器的值，导致数据污染。
* **逻辑错误:** 在实现 SHA1 算法的步骤时出现错误，例如，循环次数不对，或者位运算顺序错误。

总而言之，这段代码是 `crypto/sha1` 包为了提高性能而提供的针对 AMD64 架构的汇编优化实现生成器。它利用 `avo` 库，通过 Go 代码定义了 SHA1 算法的各个步骤，并能生成相应的汇编代码。

### 提示词
```
这是路径为go/src/crypto/sha1/_asm/sha1block_amd64_asm.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```go
// Copyright 2024 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	. "github.com/mmcloughlin/avo/build"
	. "github.com/mmcloughlin/avo/operand"
	. "github.com/mmcloughlin/avo/reg"
)

//go:generate go run . -out ../sha1block_amd64.s -pkg sha1

// AVX2 version by Intel, same algorithm as code in Linux kernel:
// https://github.com/torvalds/linux/blob/master/arch/x86/crypto/sha1_avx2_x86_64_asm.S
// Authors:
// Ilya Albrekht <ilya.albrekht@intel.com>
// Maxim Locktyukhin <maxim.locktyukhin@intel.com>
// Ronen Zohar <ronen.zohar@intel.com>
// Chandramouli Narayanan <mouli@linux.intel.com>

func main() {
	Package("crypto/sha1")
	ConstraintExpr("!purego")
	blockAMD64()
	blockAVX2()
	Generate()
}

func LOAD(index int) {
	MOVL(Mem{Base: SI}.Offset(index*4), R10L)
	BSWAPL(R10L)
	MOVL(R10L, Mem{Base: SP}.Offset(index*4))
}

func SHUFFLE(index int) {
	MOVL(Mem{Base: SP}.Offset(((index)&0xf)*4), R10L)
	XORL(Mem{Base: SP}.Offset(((index-3)&0xf)*4), R10L)
	XORL(Mem{Base: SP}.Offset(((index-8)&0xf)*4), R10L)
	XORL(Mem{Base: SP}.Offset(((index-14)&0xf)*4), R10L)
	ROLL(Imm(1), R10L)
	MOVL(R10L, Mem{Base: SP}.Offset(((index)&0xf)*4))
}

func FUNC1(a, b, c, d, e GPPhysical) {
	MOVL(d, R9L)
	XORL(c, R9L)
	ANDL(b, R9L)
	XORL(d, R9L)
}

func FUNC2(a, b, c, d, e GPPhysical) {
	MOVL(b, R9L)
	XORL(c, R9L)
	XORL(d, R9L)
}

func FUNC3(a, b, c, d, e GPPhysical) {
	MOVL(b, R8L)
	ORL(c, R8L)
	ANDL(d, R8L)
	MOVL(b, R9L)
	ANDL(c, R9L)
	ORL(R8L, R9L)
}

func FUNC4(a, b, c, d, e GPPhysical) {
	FUNC2(a, b, c, d, e)
}

func MIX(a, b, c, d, e GPPhysical, konst int) {
	ROLL(Imm(30), b)
	ADDL(R9L, e)
	MOVL(a, R8L)
	ROLL(Imm(5), R8L)
	LEAL(Mem{Base: e, Index: R10L, Scale: 1}.Offset(konst), e)
	ADDL(R8L, e)
}

func ROUND1(a, b, c, d, e GPPhysical, index int) {
	LOAD(index)
	FUNC1(a, b, c, d, e)
	MIX(a, b, c, d, e, 0x5A827999)
}

func ROUND1x(a, b, c, d, e GPPhysical, index int) {
	SHUFFLE(index)
	FUNC1(a, b, c, d, e)
	MIX(a, b, c, d, e, 0x5A827999)
}

func ROUND2(a, b, c, d, e GPPhysical, index int) {
	SHUFFLE(index)
	FUNC2(a, b, c, d, e)
	MIX(a, b, c, d, e, 0x6ED9EBA1)
}

func ROUND3(a, b, c, d, e GPPhysical, index int) {
	SHUFFLE(index)
	FUNC3(a, b, c, d, e)
	MIX(a, b, c, d, e, 0x8F1BBCDC)
}

func ROUND4(a, b, c, d, e GPPhysical, index int) {
	SHUFFLE(index)
	FUNC4(a, b, c, d, e)
	MIX(a, b, c, d, e, 0xCA62C1D6)
}

func blockAMD64() {
	Implement("blockAMD64")
	Attributes(NOSPLIT)
	AllocLocal(64)

	Load(Param("dig"), RBP)
	Load(Param("p").Base(), RSI)
	Load(Param("p").Len(), RDX)
	SHRQ(Imm(6), RDX)
	SHLQ(Imm(6), RDX)

	LEAQ(Mem{Base: SI, Index: DX, Scale: 1}, RDI)
	MOVL(Mem{Base: BP}.Offset(0*4), EAX)
	MOVL(Mem{Base: BP}.Offset(1*4), EBX)
	MOVL(Mem{Base: BP}.Offset(2*4), ECX)
	MOVL(Mem{Base: BP}.Offset(3*4), EDX)
	MOVL(Mem{Base: BP}.Offset(4*4), EBP)

	CMPQ(RSI, RDI)
	JEQ(LabelRef("end"))

	loop_amd64()
	end()
}

func loop_amd64() {
	Label("loop")
	MOVL(EAX, R11L)
	MOVL(EBX, R12L)
	MOVL(ECX, R13L)
	MOVL(EDX, R14L)
	MOVL(EBP, R15L)

	ROUND1(EAX, EBX, ECX, EDX, EBP, 0)
	ROUND1(EBP, EAX, EBX, ECX, EDX, 1)
	ROUND1(EDX, EBP, EAX, EBX, ECX, 2)
	ROUND1(ECX, EDX, EBP, EAX, EBX, 3)
	ROUND1(EBX, ECX, EDX, EBP, EAX, 4)
	ROUND1(EAX, EBX, ECX, EDX, EBP, 5)
	ROUND1(EBP, EAX, EBX, ECX, EDX, 6)
	ROUND1(EDX, EBP, EAX, EBX, ECX, 7)
	ROUND1(ECX, EDX, EBP, EAX, EBX, 8)
	ROUND1(EBX, ECX, EDX, EBP, EAX, 9)
	ROUND1(EAX, EBX, ECX, EDX, EBP, 10)
	ROUND1(EBP, EAX, EBX, ECX, EDX, 11)
	ROUND1(EDX, EBP, EAX, EBX, ECX, 12)
	ROUND1(ECX, EDX, EBP, EAX, EBX, 13)
	ROUND1(EBX, ECX, EDX, EBP, EAX, 14)
	ROUND1(EAX, EBX, ECX, EDX, EBP, 15)

	ROUND1x(EBP, EAX, EBX, ECX, EDX, 16)
	ROUND1x(EDX, EBP, EAX, EBX, ECX, 17)
	ROUND1x(ECX, EDX, EBP, EAX, EBX, 18)
	ROUND1x(EBX, ECX, EDX, EBP, EAX, 19)

	ROUND2(EAX, EBX, ECX, EDX, EBP, 20)
	ROUND2(EBP, EAX, EBX, ECX, EDX, 21)
	ROUND2(EDX, EBP, EAX, EBX, ECX, 22)
	ROUND2(ECX, EDX, EBP, EAX, EBX, 23)
	ROUND2(EBX, ECX, EDX, EBP, EAX, 24)
	ROUND2(EAX, EBX, ECX, EDX, EBP, 25)
	ROUND2(EBP, EAX, EBX, ECX, EDX, 26)
	ROUND2(EDX, EBP, EAX, EBX, ECX, 27)
	ROUND2(ECX, EDX, EBP, EAX, EBX, 28)
	ROUND2(EBX, ECX, EDX, EBP, EAX, 29)
	ROUND2(EAX, EBX, ECX, EDX, EBP, 30)
	ROUND2(EBP, EAX, EBX, ECX, EDX, 31)
	ROUND2(EDX, EBP, EAX, EBX, ECX, 32)
	ROUND2(ECX, EDX, EBP, EAX, EBX, 33)
	ROUND2(EBX, ECX, EDX, EBP, EAX, 34)
	ROUND2(EAX, EBX, ECX, EDX, EBP, 35)
	ROUND2(EBP, EAX, EBX, ECX, EDX, 36)
	ROUND2(EDX, EBP, EAX, EBX, ECX, 37)
	ROUND2(ECX, EDX, EBP, EAX, EBX, 38)
	ROUND2(EBX, ECX, EDX, EBP, EAX, 39)

	ROUND3(EAX, EBX, ECX, EDX, EBP, 40)
	ROUND3(EBP, EAX, EBX, ECX, EDX, 41)
	ROUND3(EDX, EBP, EAX, EBX, ECX, 42)
	ROUND3(ECX, EDX, EBP, EAX, EBX, 43)
	ROUND3(EBX, ECX, EDX, EBP, EAX, 44)
	ROUND3(EAX, EBX, ECX, EDX, EBP, 45)
	ROUND3(EBP, EAX, EBX, ECX, EDX, 46)
	ROUND3(EDX, EBP, EAX, EBX, ECX, 47)
	ROUND3(ECX, EDX, EBP, EAX, EBX, 48)
	ROUND3(EBX, ECX, EDX, EBP, EAX, 49)
	ROUND3(EAX, EBX, ECX, EDX, EBP, 50)
	ROUND3(EBP, EAX, EBX, ECX, EDX, 51)
	ROUND3(EDX, EBP, EAX, EBX, ECX, 52)
	ROUND3(ECX, EDX, EBP, EAX, EBX, 53)
	ROUND3(EBX, ECX, EDX, EBP, EAX, 54)
	ROUND3(EAX, EBX, ECX, EDX, EBP, 55)
	ROUND3(EBP, EAX, EBX, ECX, EDX, 56)
	ROUND3(EDX, EBP, EAX, EBX, ECX, 57)
	ROUND3(ECX, EDX, EBP, EAX, EBX, 58)
	ROUND3(EBX, ECX, EDX, EBP, EAX, 59)

	ROUND4(EAX, EBX, ECX, EDX, EBP, 60)
	ROUND4(EBP, EAX, EBX, ECX, EDX, 61)
	ROUND4(EDX, EBP, EAX, EBX, ECX, 62)
	ROUND4(ECX, EDX, EBP, EAX, EBX, 63)
	ROUND4(EBX, ECX, EDX, EBP, EAX, 64)
	ROUND4(EAX, EBX, ECX, EDX, EBP, 65)
	ROUND4(EBP, EAX, EBX, ECX, EDX, 66)
	ROUND4(EDX, EBP, EAX, EBX, ECX, 67)
	ROUND4(ECX, EDX, EBP, EAX, EBX, 68)
	ROUND4(EBX, ECX, EDX, EBP, EAX, 69)
	ROUND4(EAX, EBX, ECX, EDX, EBP, 70)
	ROUND4(EBP, EAX, EBX, ECX, EDX, 71)
	ROUND4(EDX, EBP, EAX, EBX, ECX, 72)
	ROUND4(ECX, EDX, EBP, EAX, EBX, 73)
	ROUND4(EBX, ECX, EDX, EBP, EAX, 74)
	ROUND4(EAX, EBX, ECX, EDX, EBP, 75)
	ROUND4(EBP, EAX, EBX, ECX, EDX, 76)
	ROUND4(EDX, EBP, EAX, EBX, ECX, 77)
	ROUND4(ECX, EDX, EBP, EAX, EBX, 78)
	ROUND4(EBX, ECX, EDX, EBP, EAX, 79)

	ADDL(R11L, EAX)
	ADDL(R12L, EBX)
	ADDL(R13L, ECX)
	ADDL(R14L, EDX)
	ADDL(R15L, EBP)

	ADDQ(Imm(64), RSI)
	CMPQ(RSI, RDI)
	JB(LabelRef("loop"))
}

func end() {
	Label("end")
	Load(Param("dig"), RDI)
	MOVL(EAX, Mem{Base: DI}.Offset(0*4))
	MOVL(EBX, Mem{Base: DI}.Offset(1*4))
	MOVL(ECX, Mem{Base: DI}.Offset(2*4))
	MOVL(EDX, Mem{Base: DI}.Offset(3*4))
	MOVL(EBP, Mem{Base: DI}.Offset(4*4))
	RET()
}

// This is the implementation using AVX2, BMI1 and BMI2. It is based on:
// "SHA-1 implementation with Intel(R) AVX2 instruction set extensions"
// From http://software.intel.com/en-us/articles
// (look for improving-the-performance-of-the-secure-hash-algorithm-1)
// This implementation is 2x unrolled, and interleaves vector instructions,
// used to precompute W, with scalar computation of current round
// for optimal scheduling.

// Trivial helper macros.

func UPDATE_HASH(A, TB, C, D, E GPPhysical) {
	ADDL(Mem{Base: R9}, A)
	MOVL(A, Mem{Base: R9})
	ADDL(Mem{Base: R9}.Offset(4), TB)
	MOVL(TB, Mem{Base: R9}.Offset(4))
	ADDL(Mem{Base: R9}.Offset(8), C)
	MOVL(C, Mem{Base: R9}.Offset(8))
	ADDL(Mem{Base: R9}.Offset(12), D)
	MOVL(D, Mem{Base: R9}.Offset(12))
	ADDL(Mem{Base: R9}.Offset(16), E)
	MOVL(E, Mem{Base: R9}.Offset(16))
}

// Helper macros for PRECALC, which does precomputations

func PRECALC_0(OFFSET int) {
	VMOVDQU(Mem{Base: R10}.Offset(OFFSET), X0)
}

func PRECALC_1(OFFSET int) {
	VINSERTI128(Imm(1), Mem{Base: R13}.Offset(OFFSET), Y0, Y0)
}

func PRECALC_2(YREG VecPhysical) {
	VPSHUFB(Y10, Y0, YREG)
}

func PRECALC_4(YREG VecPhysical, K_OFFSET int) {
	VPADDD(Mem{Base: R8}.Offset(K_OFFSET), YREG, Y0)
}

func PRECALC_7(OFFSET int) {
	VMOVDQU(Y0, Mem{Base: R14}.Offset(OFFSET*2))
}

// Message scheduling pre-compute for rounds 0-15
//
//   - R13 is a pointer to even 64-byte block
//   - R10 is a pointer to odd 64-byte block
//   - R14 is a pointer to temp buffer
//   - X0 is used as temp register
//   - YREG is clobbered as part of computation
//   - OFFSET chooses 16 byte chunk within a block
//   - R8 is a pointer to constants block
//   - K_OFFSET chooses K constants relevant to this round
//   - X10 holds swap mask
func PRECALC_00_15(OFFSET int, YREG VecPhysical) {
	PRECALC_0(OFFSET)
	PRECALC_1(OFFSET)
	PRECALC_2(YREG)
	PRECALC_4(YREG, 0x0)
	PRECALC_7(OFFSET)
}

// Helper macros for PRECALC_16_31

func PRECALC_16(REG_SUB_16, REG_SUB_12, REG_SUB_4, REG VecPhysical) {
	VPALIGNR(Imm(8), REG_SUB_16, REG_SUB_12, REG) // w[i-14]
	VPSRLDQ(Imm(4), REG_SUB_4, Y0)                // w[i-3]
}

func PRECALC_17(REG_SUB_16, REG_SUB_8, REG VecPhysical) {
	VPXOR(REG_SUB_8, REG, REG)
	VPXOR(REG_SUB_16, Y0, Y0)
}

func PRECALC_18(REG VecPhysical) {
	VPXOR(Y0, REG, REG)
	VPSLLDQ(Imm(12), REG, Y9)
}

func PRECALC_19(REG VecPhysical) {
	VPSLLD(Imm(1), REG, Y0)
	VPSRLD(Imm(31), REG, REG)
}

func PRECALC_20(REG VecPhysical) {
	VPOR(REG, Y0, Y0)
	VPSLLD(Imm(2), Y9, REG)
}

func PRECALC_21(REG VecPhysical) {
	VPSRLD(Imm(30), Y9, Y9)
	VPXOR(REG, Y0, Y0)
}

func PRECALC_23(REG VecPhysical, K_OFFSET, OFFSET int) {
	VPXOR(Y9, Y0, REG)
	VPADDD(Mem{Base: R8}.Offset(K_OFFSET), REG, Y0)
	VMOVDQU(Y0, Mem{Base: R14}.Offset(OFFSET))
}

// Message scheduling pre-compute for rounds 16-31
//   - calculating last 32 w[i] values in 8 XMM registers
//   - pre-calculate K+w[i] values and store to mem
//   - for later load by ALU add instruction.
//   - "brute force" vectorization for rounds 16-31 only
//   - due to w[i]->w[i-3] dependency.
//   - clobbers 5 input ymm registers REG_SUB*
//   - uses X0 and X9 as temp registers
//   - As always, R8 is a pointer to constants block
//   - and R14 is a pointer to temp buffer
func PRECALC_16_31(REG, REG_SUB_4, REG_SUB_8, REG_SUB_12, REG_SUB_16 VecPhysical, K_OFFSET, OFFSET int) {
	PRECALC_16(REG_SUB_16, REG_SUB_12, REG_SUB_4, REG)
	PRECALC_17(REG_SUB_16, REG_SUB_8, REG)
	PRECALC_18(REG)
	PRECALC_19(REG)
	PRECALC_20(REG)
	PRECALC_21(REG)
	PRECALC_23(REG, K_OFFSET, OFFSET)
}

// Helper macros for PRECALC_32_79

func PRECALC_32(REG_SUB_8, REG_SUB_4 VecPhysical) {
	VPALIGNR(Imm(8), REG_SUB_8, REG_SUB_4, Y0)
}

func PRECALC_33(REG_SUB_28, REG VecPhysical) {
	VPXOR(REG_SUB_28, REG, REG)
}

func PRECALC_34(REG_SUB_16 VecPhysical) {
	VPXOR(REG_SUB_16, Y0, Y0)
}

func PRECALC_35(REG VecPhysical) {
	VPXOR(Y0, REG, REG)
}

func PRECALC_36(REG VecPhysical) {
	VPSLLD(Imm(2), REG, Y0)
}

func PRECALC_37(REG VecPhysical) {
	VPSRLD(Imm(30), REG, REG)
	VPOR(REG, Y0, REG)
}

func PRECALC_39(REG VecPhysical, K_OFFSET, OFFSET int) {
	VPADDD(Mem{Base: R8}.Offset(K_OFFSET), REG, Y0)
	VMOVDQU(Y0, Mem{Base: R14}.Offset(OFFSET))
}

// Message scheduling pre-compute for rounds 32-79
// In SHA-1 specification we have:
// w[i] = (w[i-3] ^ w[i-8]  ^ w[i-14] ^ w[i-16]) rol 1
// Which is the same as:
// w[i] = (w[i-6] ^ w[i-16] ^ w[i-28] ^ w[i-32]) rol 2
// This allows for more efficient vectorization,
// since w[i]->w[i-3] dependency is broken

func PRECALC_32_79(REG, REG_SUB_4, REG_SUB_8, REG_SUB_16, REG_SUB_28 VecPhysical, K_OFFSET, OFFSET int) {
	PRECALC_32(REG_SUB_8, REG_SUB_4)
	PRECALC_33(REG_SUB_28, REG)
	PRECALC_34(REG_SUB_16)
	PRECALC_35(REG)
	PRECALC_36(REG)
	PRECALC_37(REG)
	PRECALC_39(REG, K_OFFSET, OFFSET)
}

func PRECALC() {
	PRECALC_00_15(0, Y15)
	PRECALC_00_15(0x10, Y14)
	PRECALC_00_15(0x20, Y13)
	PRECALC_00_15(0x30, Y12)
	PRECALC_16_31(Y8, Y12, Y13, Y14, Y15, 0, 0x80)
	PRECALC_16_31(Y7, Y8, Y12, Y13, Y14, 0x20, 0xa0)
	PRECALC_16_31(Y5, Y7, Y8, Y12, Y13, 0x20, 0xc0)
	PRECALC_16_31(Y3, Y5, Y7, Y8, Y12, 0x20, 0xe0)
	PRECALC_32_79(Y15, Y3, Y5, Y8, Y14, 0x20, 0x100)
	PRECALC_32_79(Y14, Y15, Y3, Y7, Y13, 0x20, 0x120)
	PRECALC_32_79(Y13, Y14, Y15, Y5, Y12, 0x40, 0x140)
	PRECALC_32_79(Y12, Y13, Y14, Y3, Y8, 0x40, 0x160)
	PRECALC_32_79(Y8, Y12, Y13, Y15, Y7, 0x40, 0x180)
	PRECALC_32_79(Y7, Y8, Y12, Y14, Y5, 0x40, 0x1a0)
	PRECALC_32_79(Y5, Y7, Y8, Y13, Y3, 0x40, 0x1c0)
	PRECALC_32_79(Y3, Y5, Y7, Y12, Y15, 0x60, 0x1e0)
	PRECALC_32_79(Y15, Y3, Y5, Y8, Y14, 0x60, 0x200)
	PRECALC_32_79(Y14, Y15, Y3, Y7, Y13, 0x60, 0x220)
	PRECALC_32_79(Y13, Y14, Y15, Y5, Y12, 0x60, 0x240)
	PRECALC_32_79(Y12, Y13, Y14, Y3, Y8, 0x60, 0x260)
}

// Macros calculating individual rounds have general form
// CALC_ROUND_PRE + PRECALC_ROUND + CALC_ROUND_POST
// CALC_ROUND_{PRE,POST} macros follow

func CALC_F1_PRE(OFFSET int, REG_A, REG_B, REG_C, REG_E GPPhysical) {
	ADDL(Mem{Base: R15}.Offset(OFFSET), REG_E)
	ANDNL(REG_C, REG_A, EBP)
	LEAL(Mem{Base: REG_E, Index: REG_B, Scale: 1}, REG_E) // Add F from the previous round
	RORXL(Imm(0x1b), REG_A, R12L)
	RORXL(Imm(2), REG_A, REG_B) //                           for next round
}

func CALC_F1_POST(REG_A, REG_B, REG_E GPPhysical) {
	ANDL(REG_B, REG_A)                                  // b&c
	XORL(EBP, REG_A)                                    // F1 = (b&c) ^ (~b&d)
	LEAL(Mem{Base: REG_E, Index: R12, Scale: 1}, REG_E) // E += A >>> 5
}

// Registers are cyclically rotated DX -> AX -> DI -> SI -> BX -> CX

func CALC_0() {
	MOVL(ESI, EBX) // Precalculating first round
	RORXL(Imm(2), ESI, ESI)
	ANDNL(EAX, EBX, EBP)
	ANDL(EDI, EBX)
	XORL(EBP, EBX)
	CALC_F1_PRE(0x0, ECX, EBX, EDI, EDX)
	PRECALC_0(0x80)
	CALC_F1_POST(ECX, ESI, EDX)
}

func CALC_1() {
	CALC_F1_PRE(0x4, EDX, ECX, ESI, EAX)
	PRECALC_1(0x80)
	CALC_F1_POST(EDX, EBX, EAX)
}

func CALC_2() {
	CALC_F1_PRE(0x8, EAX, EDX, EBX, EDI)
	PRECALC_2(Y15)
	CALC_F1_POST(EAX, ECX, EDI)
}

func CALC_3() {
	CALC_F1_PRE(0xc, EDI, EAX, ECX, ESI)
	CALC_F1_POST(EDI, EDX, ESI)
}

func CALC_4() {
	CALC_F1_PRE(0x20, ESI, EDI, EDX, EBX)
	PRECALC_4(Y15, 0x0)
	CALC_F1_POST(ESI, EAX, EBX)
}

func CALC_5() {
	CALC_F1_PRE(0x24, EBX, ESI, EAX, ECX)
	CALC_F1_POST(EBX, EDI, ECX)
}

func CALC_6() {
	CALC_F1_PRE(0x28, ECX, EBX, EDI, EDX)
	CALC_F1_POST(ECX, ESI, EDX)
}

func CALC_7() {
	CALC_F1_PRE(0x2c, EDX, ECX, ESI, EAX)
	PRECALC_7(0x0)
	CALC_F1_POST(EDX, EBX, EAX)
}

func CALC_8() {
	CALC_F1_PRE(0x40, EAX, EDX, EBX, EDI)
	PRECALC_0(0x90)
	CALC_F1_POST(EAX, ECX, EDI)
}

func CALC_9() {
	CALC_F1_PRE(0x44, EDI, EAX, ECX, ESI)
	PRECALC_1(0x90)
	CALC_F1_POST(EDI, EDX, ESI)
}

func CALC_10() {
	CALC_F1_PRE(0x48, ESI, EDI, EDX, EBX)
	PRECALC_2(Y14)
	CALC_F1_POST(ESI, EAX, EBX)
}

func CALC_11() {
	CALC_F1_PRE(0x4c, EBX, ESI, EAX, ECX)
	CALC_F1_POST(EBX, EDI, ECX)
}

func CALC_12() {
	CALC_F1_PRE(0x60, ECX, EBX, EDI, EDX)
	PRECALC_4(Y14, 0x0)
	CALC_F1_POST(ECX, ESI, EDX)
}

func CALC_13() {
	CALC_F1_PRE(0x64, EDX, ECX, ESI, EAX)
	CALC_F1_POST(EDX, EBX, EAX)
}

func CALC_14() {
	CALC_F1_PRE(0x68, EAX, EDX, EBX, EDI)
	CALC_F1_POST(EAX, ECX, EDI)
}

func CALC_15() {
	CALC_F1_PRE(0x6c, EDI, EAX, ECX, ESI)
	PRECALC_7(0x10)
	CALC_F1_POST(EDI, EDX, ESI)
}

func CALC_16() {
	CALC_F1_PRE(0x80, ESI, EDI, EDX, EBX)
	PRECALC_0(0xa0)
	CALC_F1_POST(ESI, EAX, EBX)
}

func CALC_17() {
	CALC_F1_PRE(0x84, EBX, ESI, EAX, ECX)
	PRECALC_1(0xa0)
	CALC_F1_POST(EBX, EDI, ECX)
}

func CALC_18() {
	CALC_F1_PRE(0x88, ECX, EBX, EDI, EDX)
	PRECALC_2(Y13)
	CALC_F1_POST(ECX, ESI, EDX)
}

func CALC_F2_PRE(OFFSET int, REG_A, REG_B, REG_E GPPhysical) {
	ADDL(Mem{Base: R15}.Offset(OFFSET), REG_E)
	LEAL(Mem{Base: REG_E, Index: REG_B, Scale: 1}, REG_E) // Add F from the previous round
	RORXL(Imm(0x1b), REG_A, R12L)
	RORXL(Imm(2), REG_A, REG_B) //                           for next round
}

func CALC_F2_POST(REG_A, REG_B, REG_C, REG_E GPPhysical) {
	XORL(REG_B, REG_A)
	ADDL(R12L, REG_E)
	XORL(REG_C, REG_A)
}

func CALC_19() {
	CALC_F2_PRE(0x8c, EDX, ECX, EAX)
	CALC_F2_POST(EDX, EBX, ESI, EAX)
}

func CALC_20() {
	CALC_F2_PRE(0xa0, EAX, EDX, EDI)
	PRECALC_4(Y13, 0x0)
	CALC_F2_POST(EAX, ECX, EBX, EDI)
}

func CALC_21() {
	CALC_F2_PRE(0xa4, EDI, EAX, ESI)
	CALC_F2_POST(EDI, EDX, ECX, ESI)
}

func CALC_22() {
	CALC_F2_PRE(0xa8, ESI, EDI, EBX)
	CALC_F2_POST(ESI, EAX, EDX, EBX)
}

func CALC_23() {
	CALC_F2_PRE(0xac, EBX, ESI, ECX)
	PRECALC_7(0x20)
	CALC_F2_POST(EBX, EDI, EAX, ECX)
}

func CALC_24() {
	CALC_F2_PRE(0xc0, ECX, EBX, EDX)
	PRECALC_0(0xb0)
	CALC_F2_POST(ECX, ESI, EDI, EDX)
}

func CALC_25() {
	CALC_F2_PRE(0xc4, EDX, ECX, EAX)
	PRECALC_1(0xb0)
	CALC_F2_POST(EDX, EBX, ESI, EAX)
}

func CALC_26() {
	CALC_F2_PRE(0xc8, EAX, EDX, EDI)
	PRECALC_2(Y12)
	CALC_F2_POST(EAX, ECX, EBX, EDI)
}

func CALC_27() {
	CALC_F2_PRE(0xcc, EDI, EAX, ESI)
	CALC_F2_POST(EDI, EDX, ECX, ESI)
}

func CALC_28() {
	CALC_F2_PRE(0xe0, ESI, EDI, EBX)
	PRECALC_4(Y12, 0x0)
	CALC_F2_POST(ESI, EAX, EDX, EBX)
}

func CALC_29() {
	CALC_F2_PRE(0xe4, EBX, ESI, ECX)
	CALC_F2_POST(EBX, EDI, EAX, ECX)
}

func CALC_30() {
	CALC_F2_PRE(0xe8, ECX, EBX, EDX)
	CALC_F2_POST(ECX, ESI, EDI, EDX)
}

func CALC_31() {
	CALC_F2_PRE(0xec, EDX, ECX, EAX)
	PRECALC_7(0x30)
	CALC_F2_POST(EDX, EBX, ESI, EAX)
}

func CALC_32() {
	CALC_F2_PRE(0x100, EAX, EDX, EDI)
	PRECALC_16(Y15, Y14, Y12, Y8)
	CALC_F2_POST(EAX, ECX, EBX, EDI)
}

func CALC_33() {
	CALC_F2_PRE(0x104, EDI, EAX, ESI)
	PRECALC_17(Y15, Y13, Y8)
	CALC_F2_POST(EDI, EDX, ECX, ESI)
}

func CALC_34() {
	CALC_F2_PRE(0x108, ESI, EDI, EBX)
	PRECALC_18(Y8)
	CALC_F2_POST(ESI, EAX, EDX, EBX)
}

func CALC_35() {
	CALC_F2_PRE(0x10c, EBX, ESI, ECX)
	PRECALC_19(Y8)
	CALC_F2_POST(EBX, EDI, EAX, ECX)
}

func CALC_36() {
	CALC_F2_PRE(0x120, ECX, EBX, EDX)
	PRECALC_20(Y8)
	CALC_F2_POST(ECX, ESI, EDI, EDX)
}

func CALC_37() {
	CALC_F2_PRE(0x124, EDX, ECX, EAX)
	PRECALC_21(Y8)
	CALC_F2_POST(EDX, EBX, ESI, EAX)
}

func CALC_38() {
	CALC_F2_PRE(0x128, EAX, EDX, EDI)
	CALC_F2_POST(EAX, ECX, EBX, EDI)
}

func CALC_F3_PRE(OFFSET int, REG_E GPPhysical) {
	ADDL(Mem{Base: R15}.Offset(OFFSET), REG_E)
}

func CALC_F3_POST(REG_A, REG_B, REG_C, REG_E, REG_TB GPPhysical) {
	LEAL(Mem{Base: REG_E, Index: REG_TB, Scale: 1}, REG_E) // Add F from the previous round
	MOVL(REG_B, EBP)
	ORL(REG_A, EBP)
	RORXL(Imm(0x1b), REG_A, R12L)
	RORXL(Imm(2), REG_A, REG_TB)
	ANDL(REG_C, EBP)
	ANDL(REG_B, REG_A)
	ORL(EBP, REG_A)
	ADDL(R12L, REG_E)
}

func CALC_39() {
	CALC_F3_PRE(0x12c, ESI)
	PRECALC_23(Y8, 0x0, 0x80)
	CALC_F3_POST(EDI, EDX, ECX, ESI, EAX)
}

func CALC_40() {
	CALC_F3_PRE(0x140, EBX)
	PRECALC_16(Y14, Y13, Y8, Y7)
	CALC_F3_POST(ESI, EAX, EDX, EBX, EDI)
}

func CALC_41() {
	CALC_F3_PRE(0x144, ECX)
	PRECALC_17(Y14, Y12, Y7)
	CALC_F3_POST(EBX, EDI, EAX, ECX, ESI)
}

func CALC_42() {
	CALC_F3_PRE(0x148, EDX)
	PRECALC_18(Y7)
	CALC_F3_POST(ECX, ESI, EDI, EDX, EBX)
}

func CALC_43() {
	CALC_F3_PRE(0x14c, EAX)
	PRECALC_19(Y7)
	CALC_F3_POST(EDX, EBX, ESI, EAX, ECX)
}

func CALC_44() {
	CALC_F3_PRE(0x160, EDI)
	PRECALC_20(Y7)
	CALC_F3_POST(EAX, ECX, EBX, EDI, EDX)
}

func CALC_45() {
	CALC_F3_PRE(0x164, ESI)
	PRECALC_21(Y7)
	CALC_F3_POST(EDI, EDX, ECX, ESI, EAX)
}

func CALC_46() {
	CALC_F3_PRE(0x168, EBX)
	CALC_F3_POST(ESI, EAX, EDX, EBX, EDI)
}

func CALC_47() {
	CALC_F3_PRE(0x16c, ECX)
	VPXOR(Y9, Y0, Y7)
	VPADDD(Mem{Base: R8}.Offset(0x20), Y7, Y0)
	VMOVDQU(Y0, Mem{Base: R14}.Offset(0xa0))
	CALC_F3_POST(EBX, EDI, EAX, ECX, ESI)
}

func CALC_48() {
	CALC_F3_PRE(0x180, EDX)
	PRECALC_16(Y13, Y12, Y7, Y5)
	CALC_F3_POST(ECX, ESI, EDI, EDX, EBX)
}

func CALC_49() {
	CALC_F3_PRE(0x184, EAX)
	PRECALC_17(Y13, Y8, Y5)
	CALC_F3_POST(EDX, EBX, ESI, EAX, ECX)
}

func CALC_50() {
	CALC_F3_PRE(0x188, EDI)
	PRECALC_18(Y5)
	CALC_F3_POST(EAX, ECX, EBX, EDI, EDX)
}

func CALC_51() {
	CALC_F3_PRE(0x18c, ESI)
	PRECALC_19(Y5)
	CALC_F3_POST(EDI, EDX, ECX, ESI, EAX)
}

func CALC_52() {
	CALC_F3_PRE(0x1a0, EBX)
	PRECALC_20(Y5)
	CALC_F3_POST(ESI, EAX, EDX, EBX, EDI)
}

func CALC_53() {
	CALC_F3_PRE(0x1a4, ECX)
	PRECALC_21(Y5)
	CALC_F3_POST(EBX, EDI, EAX, ECX, ESI)
}

func CALC_54() {
	CALC_F3_PRE(0x1a8, EDX)
	CALC_F3_POST(ECX, ESI, EDI, EDX, EBX)
}

func CALC_55() {
	CALC_F3_PRE(0x1ac, EAX)
	PRECALC_23(Y5, 0x20, 0xc0)
	CALC_F3_POST(EDX, EBX, ESI, EAX, ECX)
}

func CALC_56() {
	CALC_F3_PRE(0x1c0, EDI)
	PRECALC_16(Y12, Y8, Y5, Y3)
	CALC_F3_POST(EAX, ECX, EBX, EDI, EDX)
}

func CALC_57() {
	CALC_F3_PRE(0x1c4, ESI)
	PRECALC_17(Y12, Y7, Y3)
	CALC_F3_POST(EDI, EDX, ECX, ESI, EAX)
}

func CALC_58() {
	CALC_F3_PRE(0x1c8, EBX)
	PRECALC_18(Y3)
	CALC_F3_POST(ESI, EAX, EDX, EBX, EDI)
}

func CALC_59() {
	CALC_F2_PRE(0x1cc, EBX, ESI, ECX)
	PRECALC_19(Y3)
	CALC_F2_POST(EBX, EDI, EAX, ECX)
}

func CALC_60() {
	CALC_F2_PRE(0x1e0, ECX, EBX, EDX)
	PRECALC_20(Y3)
	CALC_F2_POST(ECX, ESI, EDI, EDX)
}

func CALC_61() {
	CALC_F2_PRE(0x1e4, EDX, ECX, EAX)
	PRECALC_21(Y3)
	CALC_F2_POST(EDX, EBX, ESI, EAX)
}

func CALC_62() {
	CALC_F2_PRE(0x1e8, EAX, EDX, EDI)
	CALC_F2_POST(EAX, ECX, EBX, EDI)
}

func CALC_63() {
	CALC_F2_PRE(0x1ec, EDI, EAX, ESI)
	PRECALC_23(Y3, 0x20, 0xe0)
	CALC_F2_POST(EDI, EDX, ECX, ESI)
}

func CALC_64() {
	CALC_F2_PRE(0x200, ESI, EDI, EBX)
	PRECALC_32(Y5, Y3)
	CALC_F2_POST(ESI, EAX, EDX, EBX)
}

func CALC_65() {
	CALC_F2_PRE(0x204, EBX, ESI, ECX)
	PRECALC_33(Y14, Y15)
	CALC_F2_POST(EBX, EDI, EAX, ECX)
}

func CALC_66() {
	CALC_F2_PRE(0x208, ECX, EBX, EDX)
	PRECALC_34(Y8)
	CALC_F2_POST(ECX, ESI, EDI, EDX)
}

func CALC_67() {
	CALC_F2_PRE(0x20c, EDX, ECX, EAX)
	PRECALC_35(Y15)
	CALC_F2_POST(EDX, EBX, ESI, EAX)
}

func CALC_68() {
	CALC_F2_PRE(0x220, EAX, EDX, EDI)
	PRECALC_36(Y15)
	CALC_F2_POST(EAX, ECX, EBX, EDI)
}

func CALC_69() {
	CALC_F2_PRE(0x224, EDI, EAX, ESI)
	PRECALC_37(Y15)
	CALC_F2_POST(EDI, EDX, ECX, ESI)
}

func CALC_70() {
	CALC_F2_PRE(0x228, ESI, EDI, EBX)
	CALC_F2_POST(ESI, EAX, EDX, EBX)
}

func CALC_71() {
	CALC_F2_PRE(0x22c, EBX, ESI, ECX)
	PRECALC_39(Y15, 0x20, 0x100)
	CALC_F2_POST(EBX, EDI, EAX, ECX)
}

func CALC_72() {
	CALC_F2_PRE(0x240, ECX, EBX, EDX)
	PRECALC_32(Y3, Y15)
	CALC_F2_POST(ECX, ESI, EDI, EDX)
}

func CALC_73() {
	CALC_F2_PRE(0x244, EDX, ECX, EAX)
	PRECALC_33(Y13, Y14)
	CALC_F2_POST(EDX, EBX, ESI, EAX)
}

func CALC_74() {
	CALC_F2_PRE(0x248, EAX, EDX, EDI)
	PRECALC_34(Y7)
	CALC_F2_POST(EAX, ECX, EBX, EDI)
}

func CALC_75() {
	CALC_F2_PRE(0x24c, EDI, EAX, ESI)
	PRECALC_35(Y14)
	CALC_F2_POST(EDI, EDX, ECX, ESI)
}

func CALC_76() {
	CALC_F2_PRE(0x260, ESI, EDI, EBX)
	PRECALC_36(Y14)
	CALC_F2_POST(ESI, EAX, EDX, EBX)
}

func CALC_77() {
	CALC_F2_PRE(0x264, EBX, ESI, ECX)
	PRECALC_37(Y14)
	CALC_F2_POST(EBX, EDI, EAX, ECX)
}

func CALC_78() {
	CALC_F2_PRE(0x268, ECX, EBX, EDX)
	CALC_F2_POST(ECX, ESI, EDI, EDX)
}

func CALC_79() {
	ADDL(Mem{Base: R15}.Offset(0x26c), EAX)
	LEAL(Mem{Base: AX, Index: CX, Scale: 1}, EAX)
	RORXL(Imm(0x1b), EDX, R12L)
	PRECALC_39(Y14, 0x20, 0x120)
	ADDL(R12L, EAX)
}

// Similar to CALC_0
func CALC_80() {
	MOVL(ECX, EDX)
	RORXL(Imm(2), ECX, ECX)
	ANDNL(ESI, EDX, EBP)
	ANDL(EBX, EDX)
	XORL(EBP, EDX)
	CALC_F1_PRE(0x10, EAX, EDX, EBX, EDI)
	PRECALC_32(Y15, Y14)
	CALC_F1_POST(EAX, ECX, EDI)
}

func CALC_81() {
	CALC_F1_PRE(0x14, EDI, EAX, ECX, ESI)
	PRECALC_33(Y12, Y13)
	CALC_F1_POST(EDI, EDX, ESI)
}

func CALC_82() {
	CALC_F1_PRE(0x18, ESI, EDI, EDX, EBX)
	PRECALC_34(Y5)
	CALC_F1_POST(ESI, EAX, EBX)
}

func CALC_83() {
	CALC_F1_PRE(0x1c, EBX, ESI, EAX, ECX)
	PRECALC_35(Y13)
	CALC_F1_POST(EBX, EDI, ECX)
}

func CALC_84() {
	CALC_F1_PRE(0x30, ECX, EBX, EDI, EDX)
	PRECALC_36(Y13)
	CALC_F1_POST(ECX, ESI, EDX)
}

func CALC_85() {
	CALC_F1_PRE(0x34, EDX, ECX, ESI, EAX)
	PRECALC_37(Y13)
	CALC_F1_POST(EDX, EBX, EAX)
}

func CALC_86() {
	CALC_F1_PRE(0x38, EAX, EDX, EBX, EDI)
	CALC_F1_POST(EAX, ECX, EDI)
}

func CALC_87() {
	CALC_F1_PRE(0x3c, EDI, EAX, ECX, ESI)
	PRECALC_39(Y13, 0x40, 0x140)
	CALC_F1_POST(EDI, EDX, ESI)
}

func CALC_88() {
	CALC_F1_PRE(0x50, ESI, EDI, EDX, EBX)
	PRECALC_32(Y14, Y13)
	CALC_F1_POST(ESI, EAX, EBX)
}

func CALC_89() {
	CALC_F1_PRE(0x54, EBX, ESI, EAX, ECX)
	PRECALC_33(Y8, Y12)
	CALC_F1_POST(EBX, EDI, ECX)
}

func CALC_90() {
	CALC_F1_PRE(0x58, ECX, EBX, EDI, EDX)
	PRECALC_34(Y3)
	CALC_F1_POST(ECX, ESI, EDX)
}

func CALC_91() {
	CALC_F1_PRE(0x5c, EDX, ECX, ESI, EAX)
	PRECALC_35(Y12)
	CALC_F1_POST(EDX, EBX, EAX)
}

func CALC_92() {
	CALC_F1_PRE(0x70, EAX, EDX, EBX, EDI)
	PRECALC_36(Y12)
	CALC_F1_POST(EAX, ECX, EDI)
}

func CALC_93() {
	CALC_F1_PRE(0x74, EDI, EAX, ECX, ESI)
	PRECALC_37(Y12)
	CALC_F1_POST(EDI, EDX, ESI)
}

func CALC_94() {
	CALC_F1_PRE(0x78, ESI, EDI, EDX, EBX)
	CALC_F1_POST(ESI, EAX, EBX)
}

func CALC_95() {
	CALC_F1_PRE(0x7c, EBX, ESI, EAX, ECX)
	PRECALC_39(Y12, 0x40, 0x160)
	CALC_F1_POST(EBX, EDI, ECX)
}

func CALC_96() {
	CALC_F1_PRE(0x90, ECX, EBX, EDI, EDX)
	PRECALC_32(Y13, Y12)
	CALC_F1_POST(ECX, ESI, EDX)
}

func CALC_97() {
	CALC_F1_PRE(0x94, EDX, ECX, ESI, EAX)
	PRECALC_33(Y7, Y8)
	CALC_F1_POST(EDX, EBX, EAX)
}

func CALC_98() {
	CALC_F1_PRE(0x98, EAX, EDX, EBX, EDI)
	PRECALC_34(Y15)
	CALC_F1_POST(EAX, ECX, EDI)
}

func CALC_99() {
	CALC_F2_PRE(0x9c, EDI, EAX, ESI)
	PRECALC_35(Y8)
	CALC_F2_POST(EDI, EDX, ECX, ESI)
}

func CALC_100() {
	CALC_F2_PRE(0xb0, ESI, EDI, EBX)
	PRECALC_36(Y8)
	CALC_F2_POST(ESI, EAX, EDX, EBX)
}

func CALC_101() {
	CALC_F2_PRE(0xb4, EBX, ESI, ECX)
	PRECALC_37(Y8)
	CALC_F2_POST(EBX, EDI, EAX, ECX)
}

func CALC_102() {
	CALC_F2_PRE(0xb8, ECX, EBX, EDX)
	CALC_F2_POST(ECX, ESI, EDI, EDX)
}

func CALC_103() {
	CALC_F2_PRE(0xbc, EDX, ECX, EAX)
	PRECALC_39(Y8, 0x40, 0x180)
	CALC_F2_POST(EDX, EBX, ESI, EAX)
}

func CALC_104() {
	CALC_F2_PRE(0xd0, EAX, EDX, EDI)
	PRECALC_32(Y12, Y8)
	CALC_F2_POST(EAX, ECX, EBX, EDI)
}

func CALC_105() {
	CALC_F2_PRE(0xd4, EDI, EAX, ESI)
	PRECALC_33(Y5, Y7)
	CALC_F2_POST(EDI, EDX, ECX, ESI)
}

func CALC_106() {
	CALC_F2_PRE(0xd8, ESI, EDI, EBX)
	PRECALC_34(Y14)
	CALC_F2_POST(ESI, EAX, EDX, EBX)
}

func CALC_107() {
	CALC_F2_PRE(0xdc, EBX, ESI, ECX)
	PRECALC_35(Y7)
	CALC_F2_POST(EBX, EDI, EAX, ECX)
}

func CALC_108() {
	CALC_F2_PRE(0xf0, ECX, EBX, EDX)
	PRECALC_36(Y7)
	CALC_F2_POST(ECX, ESI, EDI, EDX)
}

func CALC_109() {
	CALC_F2_PRE(0xf4, EDX, ECX, EAX)
	PRECALC_37(Y7)
	CALC_F2_POST(EDX, EBX, ESI, EAX)
}

func CALC_110() {
	CALC_F2_PRE(0xf8, EAX, EDX, EDI)
	CALC_F2_POST(EAX, ECX, EBX, EDI)
}

func CALC_111() {
	CALC_F2_PRE(0xfc, EDI, EAX, ESI)
	PRECALC_39(Y7, 0x40, 0x1a0)
	CALC_F2_POST(EDI, EDX, ECX, ESI)
}

func CALC_112() {
	CALC_F2_PRE(0x110, ESI, EDI, EBX)
	PRECALC_32(Y8, Y7)
	CALC_F2_POST(ESI, EAX, EDX, EBX)
}

func CALC_113() {
	CALC_F2_PRE(0x114, EBX, ESI, ECX)
	PRECALC_33(Y3, Y5)
	CALC_F2_POST(EBX, EDI, EAX, ECX)
}

func CALC_114() {
	CALC_F2_PRE(0x118, ECX, EBX, EDX)
	PRECALC_34(Y13)
	CALC_F2_POST(ECX, ESI, EDI, EDX)
}

func CALC_115() {
	CALC_F2_PRE(0x11c, EDX, ECX, EAX)
	PRECALC_35(Y5)
	CALC_F2_POST(EDX, EBX, ESI, EAX)
}

func CALC_116() {
	CALC_F2_PRE(0x130, EAX, EDX, EDI)
	PRECALC_36(Y5)
	CALC_F2_POST(EAX, ECX, EBX, EDI)
}

func CALC_117() {
	CALC_F2_PRE(0x134, EDI, EAX, ESI)
	PRECALC_37(Y5)
	CALC_F2_POST(EDI, EDX, ECX, ESI)
}

func CALC_118() {
	CALC_F2_PRE(0x138, ESI, EDI, EBX)
	CALC_F2_POST(ESI, EAX, EDX, EBX)
}

func CALC_119() {
	CALC_F3_PRE(0x13c, ECX)
	PRECALC_39(Y5, 0x40, 0x1c0)
	CALC_F3_POST(EBX, EDI, EAX, ECX, ESI)
}

func CALC_120() {
	CALC_F3_PRE(0x150, EDX)
	PRECALC_32(Y7, Y5)
	CALC_F3_POST(ECX, ESI, EDI, EDX, EBX)
}

func CALC_121() {
	CALC_F3_PRE(0x154, EAX)
	PRECALC_33(Y15, Y3)
	CALC_F3_POST(EDX, EBX, ESI, EAX, ECX)
}

func CALC_122() {
	CALC_F3_PRE(0x158, EDI)
	PRECALC_34(Y12)
	CALC_F3_POST(EAX, ECX, EBX, EDI, EDX)
}

func CALC_123() {
	CALC_F3_PRE(0x15c, ESI)
	PRECALC_35(Y3)
	CALC_F3_POST(EDI, EDX, ECX, ESI, EAX)
}

func CALC_124() {
	CALC_F3_PRE(0x170, EBX)
	PRECALC_36(Y3)
	CALC_F3_POST(ESI, EAX, EDX, EBX, EDI)
}

func CALC_125() {
	CALC_F3_PRE(0x174, ECX)
	PRECALC_37(Y3)
	CALC_F3_POST(EBX, EDI, EAX, ECX, ESI)
}

func CALC_126() {
	CALC_F3_PRE(0x178, EDX)
	CALC_F3_POST(ECX, ESI, EDI, EDX, EBX)
}

func CALC_127() {
	CALC_F3_PRE(0x17c, EAX)
	PRECALC_39(Y3, 0x60, 0x1e0)
	CALC_F3_POST(EDX, EBX, ESI, EAX, ECX)
}

func CALC_128() {
	CALC_F3_PRE(0x190, EDI)
	PRECALC_32(Y5, Y3)
	CALC_F3_POST(EAX, ECX, EBX, EDI, EDX)
}

func CALC_129() {
	CALC_F3_PRE(0x194, ESI)
	PRECALC_33(Y14, Y15)
	CALC_F3_POST(EDI, EDX, ECX, ESI, EAX)
}

func CALC_130() {
	CALC_F3_PRE(0x198, EBX)
	PRECALC_34(Y8)
	CALC_F3_POST(ESI, EAX, EDX, EBX, EDI)
}

func CALC_131() {
	CALC_F3_PRE(0x19c, ECX)
	PRECALC_35(Y15)
	CALC_F3_POST(EBX, EDI, EAX, ECX, ESI)
}

func CALC_132() {
	CALC_F3_PRE(0x1b0, EDX)
	PRECALC_36(Y15)
	CALC_F3_POST(ECX, ESI, EDI, EDX, EBX)
}

func CALC_133() {
	CALC_F3_PRE(0x1b4, EAX)
	PRECALC_37(Y15)
	CALC_F3_POST(EDX, EBX, ESI, EAX, ECX)
}

func CALC_134() {
	CALC_F3_PRE(0x1b8, EDI)
	CALC_F3_POST(EAX, ECX, EBX, EDI, EDX)
}

func CALC_135() {
	CALC_F3_PRE(0x1bc, ESI)
	PRECALC_39(Y15, 0x60, 0x200)
	CALC_F3_POST(EDI, EDX, ECX, ESI, EAX)
}

func CALC_136() {
	CALC_F3_PRE(0x1d0, EBX)
	PRECALC_32(Y3, Y15)
	CALC_F3_POST(ESI, EAX, EDX, EBX, EDI)
}

func CALC_137() {
	CALC_F3_PRE(0x1d4, ECX)
	PRECALC_33(Y13, Y14)
	CALC_F3_POST(EBX, EDI, EAX, ECX, ESI)
}

func CALC_138() {
	CALC_F3_PRE(0x1d8, EDX)
	PRECALC_34(Y7)
	CALC_F3_POST(ECX, ESI, EDI, EDX, EBX)
}

func CALC_139() {
	CALC_F2_PRE(0x1dc, EDX, ECX, EAX)
	PRECALC_35(Y14)
	CALC_F2_POST(EDX, EBX, ESI, EAX)
}

func CALC_140() {
	CALC_F2_PRE(0x1f0, EAX, EDX, EDI)
	PRECALC_36(Y14)
	CALC_F2_POST(EAX, ECX, EBX, EDI)
}

func CALC_141() {
	CALC_F2_PRE(0x1f4, EDI, EAX, ESI)
	PRECALC_37(Y14)
	CALC_F2_POST(EDI, EDX, ECX, ESI)
}

func CALC_142() {
	CALC_F2_PRE(0x1f8, ESI, EDI, EBX)
	CALC_F2_POST(ESI, EAX, EDX, EBX)
}

func CALC_143() {
	CALC_F2_PRE(0x1fc, EBX, ESI, ECX)
	PRECALC_39(Y14, 0x60, 0x220)
	CALC_F2_POST(EBX, EDI, EAX, ECX)
}

func CALC_144() {
	CALC_F2_PRE(0x210, ECX, EBX, EDX)
	PRECALC_32(Y15, Y14)
	CALC_F2_POST(ECX, ESI, EDI, EDX)
}

func CALC_145() {
	CALC_F2_PRE(0x214, EDX, ECX, EAX)
	PRECALC_33(Y12, Y13)
	CALC_F2_POST(EDX, EBX, ESI, EAX)
}

func CALC_146() {
	CALC_F2_PRE(0x218, EAX, EDX, EDI)
	PRECALC_34(Y5)
	CALC_F2_POST(EAX, ECX, EBX, EDI)
}

func CALC_147() {
	CALC_F2_PRE(0x21c, EDI, EAX, ESI)
	PRECALC_35(Y13)
	CALC_F2_POST(EDI, EDX, ECX, ESI)
}

func CALC_148() {
	CALC_F2_PRE(0x230, ESI, EDI, EBX)
	PRECALC_36(Y13)
	CALC_F2_POST(ESI, EAX, EDX, EBX)
}

func CALC_149() {
	CALC_F2_PRE(0x234, EBX, ESI, ECX)
	PRECALC_37(Y13)
	CALC_F2_POST(EBX, EDI, EAX, ECX)
}

func CALC_150() {
	CALC_F2_PRE(0x238, ECX, EBX, EDX)
	CALC_F2_POST(ECX, ESI, EDI, EDX)
}

func CALC_151() {
	CALC_F2_PRE(0x23c, EDX, ECX, EAX)
	PRECALC_39(Y13, 0x60, 0x240)
	CALC_F2_POST(EDX, EBX, ESI, EAX)
}

func CALC_152() {
	CALC_F2_PRE(0x250, EAX, EDX, EDI)
	PRECALC_32(Y14, Y13)
	CALC_F2_POST(EAX, ECX, EBX, EDI)
}

func CALC_153() {
	CALC_F2_PRE(0x254, EDI, EAX, ESI)
	PRECALC_33(Y8, Y12)
	CALC_F2_POST(EDI, EDX, ECX, ESI)
}

func CALC_154() {
	CALC_F2_PRE(0x258, ESI, EDI, EBX)
	PRECALC_34(Y3)
	CALC_F2_POST(ESI, EAX, EDX, EBX)
}

func CALC_155() {
	CALC_F2_PRE(0x25c, EBX, ESI, ECX)
	PRECALC_35(Y12)
	CALC_F2_POST(EBX, EDI, EAX, ECX)
}

func CALC_156() {
	CALC_F2_PRE(0x270, ECX, EBX, EDX)
	PRECALC_36(Y12)
	CALC_F2_POST(ECX, ESI, EDI, EDX)
}

func CALC_157() {
	CALC_F2_PRE(0x274, EDX, ECX, EAX)
	PRECALC_37(Y12)
	CALC_F2_POST(EDX, EBX, ESI, EAX)
}

func CALC_158() {
	CALC_F2_PRE(0x278, EAX, EDX, EDI)
	CALC_F2_POST(EAX, ECX, EBX, EDI)
}

func CALC_159() {
	ADDL(Mem{Base: R15}.Offset(0x27c), ESI)
	LEAL(Mem{Base: SI, Index: AX, Scale: 1}, ESI)
	RORXL(Imm(0x1b), EDI, R12L)
	PRECALC_39(Y12, 0x60, 0x260)
	ADDL(R12L, ESI)
}

func CALC() {
	MOVL(Mem{Base: R9}, ECX)
	MOVL(Mem{Base: R9}.Offset(4), ESI)
	MOVL(Mem{Base: R9}.Offset(8), EDI)
	MOVL(Mem{Base: R9}.Offset(12), EAX)
	MOVL(Mem{Base: R9}.Offset(16), EDX)
	MOVQ(RSP, R14)
	LEAQ(Mem{Base: SP}.Offset(2*4*80+32), R15)
	PRECALC() // Precalc WK for first 2 blocks
	XCHGQ(R15, R14)
	loop_avx2()
	begin()
}

// this loops is unrolled
func loop_avx2() {
	Label("loop")
	CMPQ(R10, R8) // we use R8 value (set below) as a signal of a last block
	JNE(LabelRef("begin"))
	VZEROUPPER()
	RET()
}

func begin() {
	Label("begin")
	CALC_0()
	CALC_1()
	CALC_2()
	CALC_3()
	CALC_4()
	CALC_5()
	CALC_6()
	CALC_7()
	CALC_8()
	CALC_9()
	CALC_10()
	CALC_11()
	CALC_12()
	CALC_13()
	CALC_14()
	CALC_15()
	CALC_16()
	CALC_17()
	CALC_18()
	CALC_19()
	CALC_20()
	CALC_21()
	CALC_22()
	CALC_23()
	CALC_24()
	CALC_25()
	CALC_26()
	CALC_27()
	CALC_28()
	CALC_29()
	CALC_30()
	CALC_31()
	CALC_32()
	CALC_33()
	CALC_34()
	CALC_35()
	CALC_36()
	CALC_37()
	CALC_38()
	CALC_39()
	CALC_40()
	CALC_41()
	CALC_42()
	CALC_43()
	CALC_44()
	CALC_45()
	CALC_46()
	CALC_47()
	CALC_48()
	CALC_49()
	CALC_50()
	CALC_51()
	CALC_52()
	CALC_53()
	CALC_54()
	CALC_55()
	CALC_56()
	CALC_57()
	CALC_58()
	CALC_59()
	ADDQ(Imm(128), R10) // move to next even-64-byte block
	CMPQ(R10, R11)      // is current block the last one?
	CMOVQCC(R8, R10)    // signal the last iteration smartly
	CALC_60()
	CALC_61()
	CALC_62()
	CALC_63()
	CALC_64()
	CALC_65()
	CALC_66()
	CALC_67()
	CALC_68()
	CALC_69()
	CALC_70()
	CALC_71()
	CALC_72()
	CALC_73()
	CALC_74()
	CALC_75()
	CALC_76()
	CALC_77()
	CALC_78()
	CALC_79()
	UPDATE_HASH(EAX, EDX, EBX, ESI, EDI)
	CMPQ(R10, R8) // is current block the last one?
	JE(LabelRef("loop"))
	MOVL(EDX, ECX)
	CALC_80()
	CALC_81()
	CALC_82()
	CALC_83()
	CALC_84()
	CALC_85()
	CALC_86()
	CALC_87()
	CALC_88()
	CALC_89()
	CALC_90()
	CALC_91()
	CALC_92()
	CALC_93()
	CALC_94()
	CALC_95()
	CALC_96()
	CALC_97(
```