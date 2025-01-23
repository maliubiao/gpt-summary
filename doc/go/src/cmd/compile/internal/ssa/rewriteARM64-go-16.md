Response:
My goal is to analyze the provided Go code snippet and explain its functionality, relate it to Go language features, provide illustrative examples, discuss command-line arguments (if applicable), highlight common errors, and summarize its purpose within the larger context of the `rewriteARM64.go` file.

**Thinking Process:**

1. **Identify the Core Functionality:** The code consists of several Go functions, all named `rewriteValueARM64_Op...`. This naming convention strongly suggests that these functions are responsible for rewriting or optimizing specific SSA (Static Single Assignment) operations for the ARM64 architecture.

2. **Analyze Individual Functions:**  I'll go through each function, paying attention to:
    * **Function Signature:**  `func rewriteValueARM64_Op...(v *Value) bool`. This indicates that each function takes an SSA `Value` as input and returns a boolean, likely indicating whether a rewrite occurred.
    * **Matching Patterns:**  The comments like `// match: (OpRsh64x64 <t> x y)` describe patterns in the SSA graph that the function attempts to match. These patterns represent specific Go operations (e.g., `OpRsh64x64` for right shift of a 64-bit integer by a 64-bit integer).
    * **Conditions (`cond`):** These are boolean expressions that must be true for the rewrite to be applied. They often check properties of the operands or the current compilation context (e.g., `shiftIsBounded(v)`).
    * **Rewriting Logic (`result`):**  This specifies how the matched SSA operation should be replaced with a sequence of lower-level ARM64 operations (e.g., `(SRA <t> x y)` for arithmetic right shift). It often involves creating new SSA values (using `b.NewValue0`) representing ARM64 instructions.
    * **Specific ARM64 Instructions:** I'll note the ARM64 instructions being used (e.g., `SRA`, `SRL`, `CSEL`, `UMULH`, `ADCSflags`, `SBCSflags`, `MUL`, `STP`, `MOVBstore`, etc.).
    * **Helper Functions:** Functions like `shiftIsBounded`, `int64ToAuxInt`, `opToAuxInt`, `auxToType`, `auxIntToInt64`, `isSameCall`, `isInlinableMemmove`, and `clobber` are used within the rewrite logic. I'll infer their purpose based on their names and usage.

3. **Relate to Go Features:** The operations being rewritten (like `Rsh`, `Select0`, `Select1`, `Store`, `Zero`) directly correspond to fundamental Go language constructs:
    * **Bitwise Operations:** `Rsh` (right shift)
    * **Multi-value Returns:** `Select0`, `Select1` (accessing elements of tuple results)
    * **Memory Operations:** `Store` (writing to memory), `Zero` (zeroing memory)
    * **Function Calls:** `SelectN` in the context of `runtime.memmove`.

4. **Provide Go Code Examples:** For each type of rewrite, I'll construct a simple Go code snippet that would generate the SSA operation being targeted. I'll also provide the expected output in terms of lower-level ARM64 instructions based on the rewrite rules.

5. **Address Code Reasoning (with Assumptions):**  The examples will inherently involve code reasoning. I'll make explicit assumptions about the input values and how the Go compiler translates the code into SSA.

6. **Command-Line Arguments:** Since this code deals with low-level code generation, it's unlikely to directly interact with command-line arguments. I'll mention this and explain that command-line flags influencing compilation might indirectly affect the rewriting process.

7. **Common Errors:**  I'll consider potential pitfalls for users who might be working with or extending this kind of code, such as incorrect assumptions about SSA representation or ARM64 instruction semantics.

8. **Summarize Functionality:** I'll synthesize the information gathered to provide a concise summary of the code's overall purpose within the `rewriteARM64.go` file.

9. **Consider the "Part 17 of 20" Context:**  Knowing this is part of a larger file, I'll emphasize that this snippet focuses on a specific set of optimizations related to bit shifts, multi-value returns, and memory operations on the ARM64 architecture. The broader file likely handles other Go operations and ARM64-specific optimizations.

**Self-Correction/Refinement during Thinking:**

* **Initial Thought:**  Focusing solely on the ARM64 instructions might be too low-level. It's important to connect them back to the higher-level Go operations being optimized.
* **Refinement:**  Explicitly link each rewrite rule to the corresponding Go language feature to make the explanation more understandable.
* **Initial Thought:**  Providing all possible examples might be too verbose.
* **Refinement:** Focus on representative examples that illustrate the core concepts of each rewrite.
* **Initial Thought:**  Overlooking the helper functions would make the explanation incomplete.
* **Refinement:** Briefly explain the likely purpose of the key helper functions.

By following these steps, I can generate a comprehensive and accurate explanation of the provided Go code snippet.
这段代码是Go语言编译器中用于将中间表示（SSA，Static Single Assignment）转换为ARM64汇编指令的一部分，具体来说，它定义了一系列用于 **重写（rewrite）** 特定SSA操作（Op）的规则，以生成更高效的ARM64代码。

**功能归纳:**

这段代码主要负责针对ARM64架构，优化以下Go语言操作的SSA表示：

* **右移操作 (`OpRsh` 系列):**  针对不同类型的右移操作（有符号、无符号，以及不同大小的操作数），根据移位量是否越界（`shiftIsBounded`），选择使用不同的ARM64指令，例如 `SRA` (算术右移)、`SRL` (逻辑右移) 以及 `CSEL` (条件选择) 指令来处理移位量越界的情况。
* **多返回值选择 (`OpSelect0`, `OpSelect1`, `OpSelectN`):**  优化从具有多个返回值的操作中选择特定返回值的方式。例如，将 `Mul64uhilo`（64位无符号乘法，返回高低两位）的 `Select0` 重写为 `UMULH` (无符号乘法高位)，`Select1` 重写为 `MUL` (乘法低位)。 对于涉及 `runtime.memmove` 的 `SelectN` 操作，尝试直接转换为 `Move` 指令进行优化。
* **掩码生成 (`OpSlicemask`):** 将生成切片掩码的操作重写为 ARM64 的 `SRAconst` 和 `NEG` 指令组合。
* **内存存储 (`OpStore`):**  根据存储数据的大小和类型，选择合适的ARM64存储指令，如 `MOVBstore` (字节存储)、`MOVHstore` (半字存储)、`MOVWstore` (字存储)、`MOVDstore` (双字存储) 以及浮点数存储指令 `FMOVSstore` 和 `FMOVDstore`。
* **内存清零 (`OpZero`):**  针对不同大小的内存清零操作，选择合适的ARM64指令序列进行优化，包括使用 `MOVBstore`、`MOVHstore`、`MOVWstore`、`MOVDstore` 以及成对存储指令 `STP`，并尝试使用 `DUFFZERO` 优化较大的内存清零操作。如果 `DUFFZERO` 不适用，则使用循环的 `LoweredZero` 实现。
* **控制流块的重写 (`rewriteBlockARM64`):**  针对特定的控制流块类型 (`BlockARM64EQ`)，优化条件判断。例如，将 `CMPconst [0]` 与 `AND` 操作结合的判断重写为 `TST` 指令。

**Go语言功能实现推断与代码示例:**

1. **右移操作 (`OpRsh64x64`):**  实现了Go语言的 `>>` 运算符用于 64 位整数右移。

   ```go
   package main

   import "fmt"

   func main() {
       x := uint64(0xFFFFFFFFFFFFFFFF)
       y := uint64(4)
       result := x >> y
       fmt.Printf("0x%X >> %d = 0x%X\n", x, y, result) // 输出: 0xFFFFFFFFFFFFFFFF >> 4 = 0xFFFFFFFFFFFFFFF
   }
   ```

   **假设输入 SSA (简化):**

   ```
   v1 = OpConst64 {65535}
   v2 = OpConst64 {4}
   v3 = OpRsh64x64 v1 v2
   ```

   **当 `shiftIsBounded(v3)` 为真时，预期输出 ARM64 (简化):**

   ```assembly
   SRA X寄存器_v1, X寄存器_v2
   ```

   **当 `shiftIsBounded(v3)` 为假时，预期输出 ARM64 (简化):**

   ```assembly
   // ... 计算移位量，确保不超过 63 ...
   CMP 移位寄存器, #64
   CSEL 移位寄存器, 移位寄存器, #63, LT // 如果移位寄存器小于 64，保持原值，否则使用 63
   SRA X寄存器_v1, 移位寄存器
   ```

2. **多返回值选择 (`OpSelect0`):**  例如，实现了Go语言中访问函数多返回值的第一个返回值。

   ```go
   package main

   import "fmt"

   func multiplyAndCarry(a, b uint64) (uint64, uint64) {
       hi := a * b >> 64
       lo := a * b
       return hi, lo
   }

   func main() {
       x := uint64(10)
       y := uint64(20)
       high, _ := multiplyAndCarry(x, y)
       fmt.Println("High part:", high) // 输出: High part: 0
   }
   ```

   **假设输入 SSA (简化):**

   ```
   v1 = OpConst64 {10}
   v2 = OpConst64 {20}
   v3 = OpMul64uhilo v1 v2 // 假设 multiplyAndCarry 编译为此操作
   v4 = OpSelect0 v3
   ```

   **预期输出 ARM64 (简化):**

   ```assembly
   UMULH X寄存器_v1, X寄存器_v2, X寄存器_v4
   ```

3. **内存存储 (`OpStore`):**  实现了Go语言的赋值操作。

   ```go
   package main

   func main() {
       var x int32 = 12345
       ptr := &x
       *ptr = 67890
   }
   ```

   **假设输入 SSA (简化):**

   ```
   v1 = OpAddr {&x}
   v2 = OpConst32 {67890}
   v3 = OpStore {int32} v1 v2 mem
   ```

   **预期输出 ARM64 (简化):**

   ```assembly
   MOVW X寄存器_v2, [X寄存器_v1]
   ```

4. **内存清零 (`OpZero`):**  实现了使用 `make` 创建切片或使用 `new` 创建对象时的内存初始化。

   ```go
   package main

   func main() {
       s := make([]int, 10) // 创建一个包含 10 个 int 的切片，会被零值初始化
       _ = s
   }
   ```

   **假设输入 SSA (简化，针对 `make([]int, 10)`):**

   ```
   v1 = OpSliceMakeLenCap {int} {10} {10}
   v2 = OpZero {[40]} (OpPtrIndex {int} (OpSlicePtr v1) [0]) mem // 假设 int 大小为 4 字节，10 个 int 共 40 字节
   ```

   **预期输出 ARM64 (针对大小为 40 的清零，可能会使用 STP 指令):**

   ```assembly
   // 使用 STP 指令成对存储 0
   MOV X寄存器_const0, #0
   STP X寄存器_const0, X寄存器_const0, [X寄存器_ptr]
   STP X寄存器_const0, X寄存器_const0, [X寄存器_ptr, #16]
   STP X寄存器_const0, X寄存器_const0, [X寄存器_ptr, #32]
   ```

**命令行参数:**

这段代码本身不直接处理命令行参数。然而，Go编译器的构建过程和编译选项会影响代码的生成和优化。例如，使用 `-gcflags` 传递给编译器的参数可能会影响到SSA的生成和后续的重写过程。

**使用者易犯错的点 (针对开发者):**

* **不理解 `shiftIsBounded` 的含义:** 错误地认为所有移位操作都可以直接使用 `SRA` 或 `SRL`，而忽略了移位量越界的情况，导致生成错误的代码。
* **对 SSA 的理解不足:**  不清楚特定的Go语言结构会被翻译成哪些SSA操作，导致无法正确地编写重写规则。
* **ARM64 指令理解不足:**  对ARM64指令的语义和限制不熟悉，可能导致使用了错误的指令或者参数。例如，错误地使用了无符号乘法指令处理有符号乘法。
* **忽略 `clobber` 函数的作用:**  在 `OpSelectN` 的重写规则中，`clobber` 函数用于标记被替换的指令不再使用，如果忘记调用可能导致后续优化出现问题。
* **对 `DUFFZERO` 的理解不足:**  不清楚 `DUFFZERO` 优化的适用条件和原理，可能在不合适的情况下使用，或者错过了使用 `DUFFZERO` 的机会。

**`rewriteARM64.go` 的第 17 部分的功能:**

作为 `rewriteARM64.go` 的第 17 部分，这段代码延续了该文件的主要功能，即定义将Go语言的特定高级操作转换为更底层的、更接近硬件的ARM64指令的规则。它专注于 **位运算（右移）、多返回值处理和基本的内存操作（存储和清零）** 的优化。可以推断，前后的部分可能涵盖了其他类型的操作，例如算术运算、比较运算、控制流操作等等，共同构成了一个完整的SSA到ARM64指令的转换和优化过程。

总而言之，这段代码是Go语言编译器中至关重要的一部分，它负责将抽象的Go语言代码转换为高效的ARM64机器码，是Go语言性能优化的关键环节之一。

### 提示词
```
这是路径为go/src/cmd/compile/internal/ssa/rewriteARM64.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第17部分，共20部分，请归纳一下它的功能
```

### 源代码
```go
ssThanU)
		v1 := b.NewValue0(v.Pos, OpConst64, y.Type)
		v1.AuxInt = int64ToAuxInt(63)
		v2 := b.NewValue0(v.Pos, OpARM64CMPconst, types.TypeFlags)
		v2.AuxInt = int64ToAuxInt(64)
		v3 := b.NewValue0(v.Pos, OpZeroExt32to64, typ.UInt64)
		v3.AddArg(y)
		v2.AddArg(v3)
		v0.AddArg3(y, v1, v2)
		v.AddArg2(x, v0)
		return true
	}
	return false
}
func rewriteValueARM64_OpRsh64x64(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Rsh64x64 <t> x y)
	// cond: shiftIsBounded(v)
	// result: (SRA <t> x y)
	for {
		t := v.Type
		x := v_0
		y := v_1
		if !(shiftIsBounded(v)) {
			break
		}
		v.reset(OpARM64SRA)
		v.Type = t
		v.AddArg2(x, y)
		return true
	}
	// match: (Rsh64x64 x y)
	// cond: !shiftIsBounded(v)
	// result: (SRA x (CSEL [OpARM64LessThanU] <y.Type> y (Const64 <y.Type> [63]) (CMPconst [64] y)))
	for {
		x := v_0
		y := v_1
		if !(!shiftIsBounded(v)) {
			break
		}
		v.reset(OpARM64SRA)
		v0 := b.NewValue0(v.Pos, OpARM64CSEL, y.Type)
		v0.AuxInt = opToAuxInt(OpARM64LessThanU)
		v1 := b.NewValue0(v.Pos, OpConst64, y.Type)
		v1.AuxInt = int64ToAuxInt(63)
		v2 := b.NewValue0(v.Pos, OpARM64CMPconst, types.TypeFlags)
		v2.AuxInt = int64ToAuxInt(64)
		v2.AddArg(y)
		v0.AddArg3(y, v1, v2)
		v.AddArg2(x, v0)
		return true
	}
	return false
}
func rewriteValueARM64_OpRsh64x8(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Rsh64x8 <t> x y)
	// cond: shiftIsBounded(v)
	// result: (SRA <t> x y)
	for {
		t := v.Type
		x := v_0
		y := v_1
		if !(shiftIsBounded(v)) {
			break
		}
		v.reset(OpARM64SRA)
		v.Type = t
		v.AddArg2(x, y)
		return true
	}
	// match: (Rsh64x8 x y)
	// cond: !shiftIsBounded(v)
	// result: (SRA x (CSEL [OpARM64LessThanU] <y.Type> y (Const64 <y.Type> [63]) (CMPconst [64] (ZeroExt8to64 y))))
	for {
		x := v_0
		y := v_1
		if !(!shiftIsBounded(v)) {
			break
		}
		v.reset(OpARM64SRA)
		v0 := b.NewValue0(v.Pos, OpARM64CSEL, y.Type)
		v0.AuxInt = opToAuxInt(OpARM64LessThanU)
		v1 := b.NewValue0(v.Pos, OpConst64, y.Type)
		v1.AuxInt = int64ToAuxInt(63)
		v2 := b.NewValue0(v.Pos, OpARM64CMPconst, types.TypeFlags)
		v2.AuxInt = int64ToAuxInt(64)
		v3 := b.NewValue0(v.Pos, OpZeroExt8to64, typ.UInt64)
		v3.AddArg(y)
		v2.AddArg(v3)
		v0.AddArg3(y, v1, v2)
		v.AddArg2(x, v0)
		return true
	}
	return false
}
func rewriteValueARM64_OpRsh8Ux16(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Rsh8Ux16 <t> x y)
	// cond: shiftIsBounded(v)
	// result: (SRL <t> (ZeroExt8to64 x) y)
	for {
		t := v.Type
		x := v_0
		y := v_1
		if !(shiftIsBounded(v)) {
			break
		}
		v.reset(OpARM64SRL)
		v.Type = t
		v0 := b.NewValue0(v.Pos, OpZeroExt8to64, typ.UInt64)
		v0.AddArg(x)
		v.AddArg2(v0, y)
		return true
	}
	// match: (Rsh8Ux16 <t> x y)
	// cond: !shiftIsBounded(v)
	// result: (CSEL [OpARM64LessThanU] (SRL <t> (ZeroExt8to64 x) y) (Const64 <t> [0]) (CMPconst [64] (ZeroExt16to64 y)))
	for {
		t := v.Type
		x := v_0
		y := v_1
		if !(!shiftIsBounded(v)) {
			break
		}
		v.reset(OpARM64CSEL)
		v.AuxInt = opToAuxInt(OpARM64LessThanU)
		v0 := b.NewValue0(v.Pos, OpARM64SRL, t)
		v1 := b.NewValue0(v.Pos, OpZeroExt8to64, typ.UInt64)
		v1.AddArg(x)
		v0.AddArg2(v1, y)
		v2 := b.NewValue0(v.Pos, OpConst64, t)
		v2.AuxInt = int64ToAuxInt(0)
		v3 := b.NewValue0(v.Pos, OpARM64CMPconst, types.TypeFlags)
		v3.AuxInt = int64ToAuxInt(64)
		v4 := b.NewValue0(v.Pos, OpZeroExt16to64, typ.UInt64)
		v4.AddArg(y)
		v3.AddArg(v4)
		v.AddArg3(v0, v2, v3)
		return true
	}
	return false
}
func rewriteValueARM64_OpRsh8Ux32(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Rsh8Ux32 <t> x y)
	// cond: shiftIsBounded(v)
	// result: (SRL <t> (ZeroExt8to64 x) y)
	for {
		t := v.Type
		x := v_0
		y := v_1
		if !(shiftIsBounded(v)) {
			break
		}
		v.reset(OpARM64SRL)
		v.Type = t
		v0 := b.NewValue0(v.Pos, OpZeroExt8to64, typ.UInt64)
		v0.AddArg(x)
		v.AddArg2(v0, y)
		return true
	}
	// match: (Rsh8Ux32 <t> x y)
	// cond: !shiftIsBounded(v)
	// result: (CSEL [OpARM64LessThanU] (SRL <t> (ZeroExt8to64 x) y) (Const64 <t> [0]) (CMPconst [64] (ZeroExt32to64 y)))
	for {
		t := v.Type
		x := v_0
		y := v_1
		if !(!shiftIsBounded(v)) {
			break
		}
		v.reset(OpARM64CSEL)
		v.AuxInt = opToAuxInt(OpARM64LessThanU)
		v0 := b.NewValue0(v.Pos, OpARM64SRL, t)
		v1 := b.NewValue0(v.Pos, OpZeroExt8to64, typ.UInt64)
		v1.AddArg(x)
		v0.AddArg2(v1, y)
		v2 := b.NewValue0(v.Pos, OpConst64, t)
		v2.AuxInt = int64ToAuxInt(0)
		v3 := b.NewValue0(v.Pos, OpARM64CMPconst, types.TypeFlags)
		v3.AuxInt = int64ToAuxInt(64)
		v4 := b.NewValue0(v.Pos, OpZeroExt32to64, typ.UInt64)
		v4.AddArg(y)
		v3.AddArg(v4)
		v.AddArg3(v0, v2, v3)
		return true
	}
	return false
}
func rewriteValueARM64_OpRsh8Ux64(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Rsh8Ux64 <t> x y)
	// cond: shiftIsBounded(v)
	// result: (SRL <t> (ZeroExt8to64 x) y)
	for {
		t := v.Type
		x := v_0
		y := v_1
		if !(shiftIsBounded(v)) {
			break
		}
		v.reset(OpARM64SRL)
		v.Type = t
		v0 := b.NewValue0(v.Pos, OpZeroExt8to64, typ.UInt64)
		v0.AddArg(x)
		v.AddArg2(v0, y)
		return true
	}
	// match: (Rsh8Ux64 <t> x y)
	// cond: !shiftIsBounded(v)
	// result: (CSEL [OpARM64LessThanU] (SRL <t> (ZeroExt8to64 x) y) (Const64 <t> [0]) (CMPconst [64] y))
	for {
		t := v.Type
		x := v_0
		y := v_1
		if !(!shiftIsBounded(v)) {
			break
		}
		v.reset(OpARM64CSEL)
		v.AuxInt = opToAuxInt(OpARM64LessThanU)
		v0 := b.NewValue0(v.Pos, OpARM64SRL, t)
		v1 := b.NewValue0(v.Pos, OpZeroExt8to64, typ.UInt64)
		v1.AddArg(x)
		v0.AddArg2(v1, y)
		v2 := b.NewValue0(v.Pos, OpConst64, t)
		v2.AuxInt = int64ToAuxInt(0)
		v3 := b.NewValue0(v.Pos, OpARM64CMPconst, types.TypeFlags)
		v3.AuxInt = int64ToAuxInt(64)
		v3.AddArg(y)
		v.AddArg3(v0, v2, v3)
		return true
	}
	return false
}
func rewriteValueARM64_OpRsh8Ux8(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Rsh8Ux8 <t> x y)
	// cond: shiftIsBounded(v)
	// result: (SRL <t> (ZeroExt8to64 x) y)
	for {
		t := v.Type
		x := v_0
		y := v_1
		if !(shiftIsBounded(v)) {
			break
		}
		v.reset(OpARM64SRL)
		v.Type = t
		v0 := b.NewValue0(v.Pos, OpZeroExt8to64, typ.UInt64)
		v0.AddArg(x)
		v.AddArg2(v0, y)
		return true
	}
	// match: (Rsh8Ux8 <t> x y)
	// cond: !shiftIsBounded(v)
	// result: (CSEL [OpARM64LessThanU] (SRL <t> (ZeroExt8to64 x) y) (Const64 <t> [0]) (CMPconst [64] (ZeroExt8to64 y)))
	for {
		t := v.Type
		x := v_0
		y := v_1
		if !(!shiftIsBounded(v)) {
			break
		}
		v.reset(OpARM64CSEL)
		v.AuxInt = opToAuxInt(OpARM64LessThanU)
		v0 := b.NewValue0(v.Pos, OpARM64SRL, t)
		v1 := b.NewValue0(v.Pos, OpZeroExt8to64, typ.UInt64)
		v1.AddArg(x)
		v0.AddArg2(v1, y)
		v2 := b.NewValue0(v.Pos, OpConst64, t)
		v2.AuxInt = int64ToAuxInt(0)
		v3 := b.NewValue0(v.Pos, OpARM64CMPconst, types.TypeFlags)
		v3.AuxInt = int64ToAuxInt(64)
		v4 := b.NewValue0(v.Pos, OpZeroExt8to64, typ.UInt64)
		v4.AddArg(y)
		v3.AddArg(v4)
		v.AddArg3(v0, v2, v3)
		return true
	}
	return false
}
func rewriteValueARM64_OpRsh8x16(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Rsh8x16 <t> x y)
	// cond: shiftIsBounded(v)
	// result: (SRA <t> (SignExt8to64 x) y)
	for {
		t := v.Type
		x := v_0
		y := v_1
		if !(shiftIsBounded(v)) {
			break
		}
		v.reset(OpARM64SRA)
		v.Type = t
		v0 := b.NewValue0(v.Pos, OpSignExt8to64, typ.Int64)
		v0.AddArg(x)
		v.AddArg2(v0, y)
		return true
	}
	// match: (Rsh8x16 x y)
	// cond: !shiftIsBounded(v)
	// result: (SRA (SignExt8to64 x) (CSEL [OpARM64LessThanU] <y.Type> y (Const64 <y.Type> [63]) (CMPconst [64] (ZeroExt16to64 y))))
	for {
		x := v_0
		y := v_1
		if !(!shiftIsBounded(v)) {
			break
		}
		v.reset(OpARM64SRA)
		v0 := b.NewValue0(v.Pos, OpSignExt8to64, typ.Int64)
		v0.AddArg(x)
		v1 := b.NewValue0(v.Pos, OpARM64CSEL, y.Type)
		v1.AuxInt = opToAuxInt(OpARM64LessThanU)
		v2 := b.NewValue0(v.Pos, OpConst64, y.Type)
		v2.AuxInt = int64ToAuxInt(63)
		v3 := b.NewValue0(v.Pos, OpARM64CMPconst, types.TypeFlags)
		v3.AuxInt = int64ToAuxInt(64)
		v4 := b.NewValue0(v.Pos, OpZeroExt16to64, typ.UInt64)
		v4.AddArg(y)
		v3.AddArg(v4)
		v1.AddArg3(y, v2, v3)
		v.AddArg2(v0, v1)
		return true
	}
	return false
}
func rewriteValueARM64_OpRsh8x32(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Rsh8x32 <t> x y)
	// cond: shiftIsBounded(v)
	// result: (SRA <t> (SignExt8to64 x) y)
	for {
		t := v.Type
		x := v_0
		y := v_1
		if !(shiftIsBounded(v)) {
			break
		}
		v.reset(OpARM64SRA)
		v.Type = t
		v0 := b.NewValue0(v.Pos, OpSignExt8to64, typ.Int64)
		v0.AddArg(x)
		v.AddArg2(v0, y)
		return true
	}
	// match: (Rsh8x32 x y)
	// cond: !shiftIsBounded(v)
	// result: (SRA (SignExt8to64 x) (CSEL [OpARM64LessThanU] <y.Type> y (Const64 <y.Type> [63]) (CMPconst [64] (ZeroExt32to64 y))))
	for {
		x := v_0
		y := v_1
		if !(!shiftIsBounded(v)) {
			break
		}
		v.reset(OpARM64SRA)
		v0 := b.NewValue0(v.Pos, OpSignExt8to64, typ.Int64)
		v0.AddArg(x)
		v1 := b.NewValue0(v.Pos, OpARM64CSEL, y.Type)
		v1.AuxInt = opToAuxInt(OpARM64LessThanU)
		v2 := b.NewValue0(v.Pos, OpConst64, y.Type)
		v2.AuxInt = int64ToAuxInt(63)
		v3 := b.NewValue0(v.Pos, OpARM64CMPconst, types.TypeFlags)
		v3.AuxInt = int64ToAuxInt(64)
		v4 := b.NewValue0(v.Pos, OpZeroExt32to64, typ.UInt64)
		v4.AddArg(y)
		v3.AddArg(v4)
		v1.AddArg3(y, v2, v3)
		v.AddArg2(v0, v1)
		return true
	}
	return false
}
func rewriteValueARM64_OpRsh8x64(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Rsh8x64 <t> x y)
	// cond: shiftIsBounded(v)
	// result: (SRA <t> (SignExt8to64 x) y)
	for {
		t := v.Type
		x := v_0
		y := v_1
		if !(shiftIsBounded(v)) {
			break
		}
		v.reset(OpARM64SRA)
		v.Type = t
		v0 := b.NewValue0(v.Pos, OpSignExt8to64, typ.Int64)
		v0.AddArg(x)
		v.AddArg2(v0, y)
		return true
	}
	// match: (Rsh8x64 x y)
	// cond: !shiftIsBounded(v)
	// result: (SRA (SignExt8to64 x) (CSEL [OpARM64LessThanU] <y.Type> y (Const64 <y.Type> [63]) (CMPconst [64] y)))
	for {
		x := v_0
		y := v_1
		if !(!shiftIsBounded(v)) {
			break
		}
		v.reset(OpARM64SRA)
		v0 := b.NewValue0(v.Pos, OpSignExt8to64, typ.Int64)
		v0.AddArg(x)
		v1 := b.NewValue0(v.Pos, OpARM64CSEL, y.Type)
		v1.AuxInt = opToAuxInt(OpARM64LessThanU)
		v2 := b.NewValue0(v.Pos, OpConst64, y.Type)
		v2.AuxInt = int64ToAuxInt(63)
		v3 := b.NewValue0(v.Pos, OpARM64CMPconst, types.TypeFlags)
		v3.AuxInt = int64ToAuxInt(64)
		v3.AddArg(y)
		v1.AddArg3(y, v2, v3)
		v.AddArg2(v0, v1)
		return true
	}
	return false
}
func rewriteValueARM64_OpRsh8x8(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Rsh8x8 <t> x y)
	// cond: shiftIsBounded(v)
	// result: (SRA <t> (SignExt8to64 x) y)
	for {
		t := v.Type
		x := v_0
		y := v_1
		if !(shiftIsBounded(v)) {
			break
		}
		v.reset(OpARM64SRA)
		v.Type = t
		v0 := b.NewValue0(v.Pos, OpSignExt8to64, typ.Int64)
		v0.AddArg(x)
		v.AddArg2(v0, y)
		return true
	}
	// match: (Rsh8x8 x y)
	// cond: !shiftIsBounded(v)
	// result: (SRA (SignExt8to64 x) (CSEL [OpARM64LessThanU] <y.Type> y (Const64 <y.Type> [63]) (CMPconst [64] (ZeroExt8to64 y))))
	for {
		x := v_0
		y := v_1
		if !(!shiftIsBounded(v)) {
			break
		}
		v.reset(OpARM64SRA)
		v0 := b.NewValue0(v.Pos, OpSignExt8to64, typ.Int64)
		v0.AddArg(x)
		v1 := b.NewValue0(v.Pos, OpARM64CSEL, y.Type)
		v1.AuxInt = opToAuxInt(OpARM64LessThanU)
		v2 := b.NewValue0(v.Pos, OpConst64, y.Type)
		v2.AuxInt = int64ToAuxInt(63)
		v3 := b.NewValue0(v.Pos, OpARM64CMPconst, types.TypeFlags)
		v3.AuxInt = int64ToAuxInt(64)
		v4 := b.NewValue0(v.Pos, OpZeroExt8to64, typ.UInt64)
		v4.AddArg(y)
		v3.AddArg(v4)
		v1.AddArg3(y, v2, v3)
		v.AddArg2(v0, v1)
		return true
	}
	return false
}
func rewriteValueARM64_OpSelect0(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Select0 (Mul64uhilo x y))
	// result: (UMULH x y)
	for {
		if v_0.Op != OpMul64uhilo {
			break
		}
		y := v_0.Args[1]
		x := v_0.Args[0]
		v.reset(OpARM64UMULH)
		v.AddArg2(x, y)
		return true
	}
	// match: (Select0 (Add64carry x y c))
	// result: (Select0 <typ.UInt64> (ADCSflags x y (Select1 <types.TypeFlags> (ADDSconstflags [-1] c))))
	for {
		if v_0.Op != OpAdd64carry {
			break
		}
		c := v_0.Args[2]
		x := v_0.Args[0]
		y := v_0.Args[1]
		v.reset(OpSelect0)
		v.Type = typ.UInt64
		v0 := b.NewValue0(v.Pos, OpARM64ADCSflags, types.NewTuple(typ.UInt64, types.TypeFlags))
		v1 := b.NewValue0(v.Pos, OpSelect1, types.TypeFlags)
		v2 := b.NewValue0(v.Pos, OpARM64ADDSconstflags, types.NewTuple(typ.UInt64, types.TypeFlags))
		v2.AuxInt = int64ToAuxInt(-1)
		v2.AddArg(c)
		v1.AddArg(v2)
		v0.AddArg3(x, y, v1)
		v.AddArg(v0)
		return true
	}
	// match: (Select0 (Sub64borrow x y bo))
	// result: (Select0 <typ.UInt64> (SBCSflags x y (Select1 <types.TypeFlags> (NEGSflags bo))))
	for {
		if v_0.Op != OpSub64borrow {
			break
		}
		bo := v_0.Args[2]
		x := v_0.Args[0]
		y := v_0.Args[1]
		v.reset(OpSelect0)
		v.Type = typ.UInt64
		v0 := b.NewValue0(v.Pos, OpARM64SBCSflags, types.NewTuple(typ.UInt64, types.TypeFlags))
		v1 := b.NewValue0(v.Pos, OpSelect1, types.TypeFlags)
		v2 := b.NewValue0(v.Pos, OpARM64NEGSflags, types.NewTuple(typ.UInt64, types.TypeFlags))
		v2.AddArg(bo)
		v1.AddArg(v2)
		v0.AddArg3(x, y, v1)
		v.AddArg(v0)
		return true
	}
	// match: (Select0 (Mul64uover x y))
	// result: (MUL x y)
	for {
		if v_0.Op != OpMul64uover {
			break
		}
		y := v_0.Args[1]
		x := v_0.Args[0]
		v.reset(OpARM64MUL)
		v.AddArg2(x, y)
		return true
	}
	return false
}
func rewriteValueARM64_OpSelect1(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Select1 (Mul64uhilo x y))
	// result: (MUL x y)
	for {
		if v_0.Op != OpMul64uhilo {
			break
		}
		y := v_0.Args[1]
		x := v_0.Args[0]
		v.reset(OpARM64MUL)
		v.AddArg2(x, y)
		return true
	}
	// match: (Select1 (Add64carry x y c))
	// result: (ADCzerocarry <typ.UInt64> (Select1 <types.TypeFlags> (ADCSflags x y (Select1 <types.TypeFlags> (ADDSconstflags [-1] c)))))
	for {
		if v_0.Op != OpAdd64carry {
			break
		}
		c := v_0.Args[2]
		x := v_0.Args[0]
		y := v_0.Args[1]
		v.reset(OpARM64ADCzerocarry)
		v.Type = typ.UInt64
		v0 := b.NewValue0(v.Pos, OpSelect1, types.TypeFlags)
		v1 := b.NewValue0(v.Pos, OpARM64ADCSflags, types.NewTuple(typ.UInt64, types.TypeFlags))
		v2 := b.NewValue0(v.Pos, OpSelect1, types.TypeFlags)
		v3 := b.NewValue0(v.Pos, OpARM64ADDSconstflags, types.NewTuple(typ.UInt64, types.TypeFlags))
		v3.AuxInt = int64ToAuxInt(-1)
		v3.AddArg(c)
		v2.AddArg(v3)
		v1.AddArg3(x, y, v2)
		v0.AddArg(v1)
		v.AddArg(v0)
		return true
	}
	// match: (Select1 (Sub64borrow x y bo))
	// result: (NEG <typ.UInt64> (NGCzerocarry <typ.UInt64> (Select1 <types.TypeFlags> (SBCSflags x y (Select1 <types.TypeFlags> (NEGSflags bo))))))
	for {
		if v_0.Op != OpSub64borrow {
			break
		}
		bo := v_0.Args[2]
		x := v_0.Args[0]
		y := v_0.Args[1]
		v.reset(OpARM64NEG)
		v.Type = typ.UInt64
		v0 := b.NewValue0(v.Pos, OpARM64NGCzerocarry, typ.UInt64)
		v1 := b.NewValue0(v.Pos, OpSelect1, types.TypeFlags)
		v2 := b.NewValue0(v.Pos, OpARM64SBCSflags, types.NewTuple(typ.UInt64, types.TypeFlags))
		v3 := b.NewValue0(v.Pos, OpSelect1, types.TypeFlags)
		v4 := b.NewValue0(v.Pos, OpARM64NEGSflags, types.NewTuple(typ.UInt64, types.TypeFlags))
		v4.AddArg(bo)
		v3.AddArg(v4)
		v2.AddArg3(x, y, v3)
		v1.AddArg(v2)
		v0.AddArg(v1)
		v.AddArg(v0)
		return true
	}
	// match: (Select1 (Mul64uover x y))
	// result: (NotEqual (CMPconst (UMULH <typ.UInt64> x y) [0]))
	for {
		if v_0.Op != OpMul64uover {
			break
		}
		y := v_0.Args[1]
		x := v_0.Args[0]
		v.reset(OpARM64NotEqual)
		v0 := b.NewValue0(v.Pos, OpARM64CMPconst, types.TypeFlags)
		v0.AuxInt = int64ToAuxInt(0)
		v1 := b.NewValue0(v.Pos, OpARM64UMULH, typ.UInt64)
		v1.AddArg2(x, y)
		v0.AddArg(v1)
		v.AddArg(v0)
		return true
	}
	return false
}
func rewriteValueARM64_OpSelectN(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	config := b.Func.Config
	// match: (SelectN [0] call:(CALLstatic {sym} s1:(MOVDstore _ (MOVDconst [sz]) s2:(MOVDstore _ src s3:(MOVDstore {t} _ dst mem)))))
	// cond: sz >= 0 && isSameCall(sym, "runtime.memmove") && s1.Uses == 1 && s2.Uses == 1 && s3.Uses == 1 && isInlinableMemmove(dst, src, sz, config) && clobber(s1, s2, s3, call)
	// result: (Move [sz] dst src mem)
	for {
		if auxIntToInt64(v.AuxInt) != 0 {
			break
		}
		call := v_0
		if call.Op != OpARM64CALLstatic || len(call.Args) != 1 {
			break
		}
		sym := auxToCall(call.Aux)
		s1 := call.Args[0]
		if s1.Op != OpARM64MOVDstore {
			break
		}
		_ = s1.Args[2]
		s1_1 := s1.Args[1]
		if s1_1.Op != OpARM64MOVDconst {
			break
		}
		sz := auxIntToInt64(s1_1.AuxInt)
		s2 := s1.Args[2]
		if s2.Op != OpARM64MOVDstore {
			break
		}
		_ = s2.Args[2]
		src := s2.Args[1]
		s3 := s2.Args[2]
		if s3.Op != OpARM64MOVDstore {
			break
		}
		mem := s3.Args[2]
		dst := s3.Args[1]
		if !(sz >= 0 && isSameCall(sym, "runtime.memmove") && s1.Uses == 1 && s2.Uses == 1 && s3.Uses == 1 && isInlinableMemmove(dst, src, sz, config) && clobber(s1, s2, s3, call)) {
			break
		}
		v.reset(OpMove)
		v.AuxInt = int64ToAuxInt(sz)
		v.AddArg3(dst, src, mem)
		return true
	}
	// match: (SelectN [0] call:(CALLstatic {sym} dst src (MOVDconst [sz]) mem))
	// cond: sz >= 0 && isSameCall(sym, "runtime.memmove") && call.Uses == 1 && isInlinableMemmove(dst, src, sz, config) && clobber(call)
	// result: (Move [sz] dst src mem)
	for {
		if auxIntToInt64(v.AuxInt) != 0 {
			break
		}
		call := v_0
		if call.Op != OpARM64CALLstatic || len(call.Args) != 4 {
			break
		}
		sym := auxToCall(call.Aux)
		mem := call.Args[3]
		dst := call.Args[0]
		src := call.Args[1]
		call_2 := call.Args[2]
		if call_2.Op != OpARM64MOVDconst {
			break
		}
		sz := auxIntToInt64(call_2.AuxInt)
		if !(sz >= 0 && isSameCall(sym, "runtime.memmove") && call.Uses == 1 && isInlinableMemmove(dst, src, sz, config) && clobber(call)) {
			break
		}
		v.reset(OpMove)
		v.AuxInt = int64ToAuxInt(sz)
		v.AddArg3(dst, src, mem)
		return true
	}
	return false
}
func rewriteValueARM64_OpSlicemask(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	// match: (Slicemask <t> x)
	// result: (SRAconst (NEG <t> x) [63])
	for {
		t := v.Type
		x := v_0
		v.reset(OpARM64SRAconst)
		v.AuxInt = int64ToAuxInt(63)
		v0 := b.NewValue0(v.Pos, OpARM64NEG, t)
		v0.AddArg(x)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueARM64_OpStore(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (Store {t} ptr val mem)
	// cond: t.Size() == 1
	// result: (MOVBstore ptr val mem)
	for {
		t := auxToType(v.Aux)
		ptr := v_0
		val := v_1
		mem := v_2
		if !(t.Size() == 1) {
			break
		}
		v.reset(OpARM64MOVBstore)
		v.AddArg3(ptr, val, mem)
		return true
	}
	// match: (Store {t} ptr val mem)
	// cond: t.Size() == 2
	// result: (MOVHstore ptr val mem)
	for {
		t := auxToType(v.Aux)
		ptr := v_0
		val := v_1
		mem := v_2
		if !(t.Size() == 2) {
			break
		}
		v.reset(OpARM64MOVHstore)
		v.AddArg3(ptr, val, mem)
		return true
	}
	// match: (Store {t} ptr val mem)
	// cond: t.Size() == 4 && !t.IsFloat()
	// result: (MOVWstore ptr val mem)
	for {
		t := auxToType(v.Aux)
		ptr := v_0
		val := v_1
		mem := v_2
		if !(t.Size() == 4 && !t.IsFloat()) {
			break
		}
		v.reset(OpARM64MOVWstore)
		v.AddArg3(ptr, val, mem)
		return true
	}
	// match: (Store {t} ptr val mem)
	// cond: t.Size() == 8 && !t.IsFloat()
	// result: (MOVDstore ptr val mem)
	for {
		t := auxToType(v.Aux)
		ptr := v_0
		val := v_1
		mem := v_2
		if !(t.Size() == 8 && !t.IsFloat()) {
			break
		}
		v.reset(OpARM64MOVDstore)
		v.AddArg3(ptr, val, mem)
		return true
	}
	// match: (Store {t} ptr val mem)
	// cond: t.Size() == 4 && t.IsFloat()
	// result: (FMOVSstore ptr val mem)
	for {
		t := auxToType(v.Aux)
		ptr := v_0
		val := v_1
		mem := v_2
		if !(t.Size() == 4 && t.IsFloat()) {
			break
		}
		v.reset(OpARM64FMOVSstore)
		v.AddArg3(ptr, val, mem)
		return true
	}
	// match: (Store {t} ptr val mem)
	// cond: t.Size() == 8 && t.IsFloat()
	// result: (FMOVDstore ptr val mem)
	for {
		t := auxToType(v.Aux)
		ptr := v_0
		val := v_1
		mem := v_2
		if !(t.Size() == 8 && t.IsFloat()) {
			break
		}
		v.reset(OpARM64FMOVDstore)
		v.AddArg3(ptr, val, mem)
		return true
	}
	return false
}
func rewriteValueARM64_OpZero(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	config := b.Func.Config
	typ := &b.Func.Config.Types
	// match: (Zero [0] _ mem)
	// result: mem
	for {
		if auxIntToInt64(v.AuxInt) != 0 {
			break
		}
		mem := v_1
		v.copyOf(mem)
		return true
	}
	// match: (Zero [1] ptr mem)
	// result: (MOVBstore ptr (MOVDconst [0]) mem)
	for {
		if auxIntToInt64(v.AuxInt) != 1 {
			break
		}
		ptr := v_0
		mem := v_1
		v.reset(OpARM64MOVBstore)
		v0 := b.NewValue0(v.Pos, OpARM64MOVDconst, typ.UInt64)
		v0.AuxInt = int64ToAuxInt(0)
		v.AddArg3(ptr, v0, mem)
		return true
	}
	// match: (Zero [2] ptr mem)
	// result: (MOVHstore ptr (MOVDconst [0]) mem)
	for {
		if auxIntToInt64(v.AuxInt) != 2 {
			break
		}
		ptr := v_0
		mem := v_1
		v.reset(OpARM64MOVHstore)
		v0 := b.NewValue0(v.Pos, OpARM64MOVDconst, typ.UInt64)
		v0.AuxInt = int64ToAuxInt(0)
		v.AddArg3(ptr, v0, mem)
		return true
	}
	// match: (Zero [4] ptr mem)
	// result: (MOVWstore ptr (MOVDconst [0]) mem)
	for {
		if auxIntToInt64(v.AuxInt) != 4 {
			break
		}
		ptr := v_0
		mem := v_1
		v.reset(OpARM64MOVWstore)
		v0 := b.NewValue0(v.Pos, OpARM64MOVDconst, typ.UInt64)
		v0.AuxInt = int64ToAuxInt(0)
		v.AddArg3(ptr, v0, mem)
		return true
	}
	// match: (Zero [3] ptr mem)
	// result: (MOVBstore [2] ptr (MOVDconst [0]) (MOVHstore ptr (MOVDconst [0]) mem))
	for {
		if auxIntToInt64(v.AuxInt) != 3 {
			break
		}
		ptr := v_0
		mem := v_1
		v.reset(OpARM64MOVBstore)
		v.AuxInt = int32ToAuxInt(2)
		v0 := b.NewValue0(v.Pos, OpARM64MOVDconst, typ.UInt64)
		v0.AuxInt = int64ToAuxInt(0)
		v1 := b.NewValue0(v.Pos, OpARM64MOVHstore, types.TypeMem)
		v1.AddArg3(ptr, v0, mem)
		v.AddArg3(ptr, v0, v1)
		return true
	}
	// match: (Zero [5] ptr mem)
	// result: (MOVBstore [4] ptr (MOVDconst [0]) (MOVWstore ptr (MOVDconst [0]) mem))
	for {
		if auxIntToInt64(v.AuxInt) != 5 {
			break
		}
		ptr := v_0
		mem := v_1
		v.reset(OpARM64MOVBstore)
		v.AuxInt = int32ToAuxInt(4)
		v0 := b.NewValue0(v.Pos, OpARM64MOVDconst, typ.UInt64)
		v0.AuxInt = int64ToAuxInt(0)
		v1 := b.NewValue0(v.Pos, OpARM64MOVWstore, types.TypeMem)
		v1.AddArg3(ptr, v0, mem)
		v.AddArg3(ptr, v0, v1)
		return true
	}
	// match: (Zero [6] ptr mem)
	// result: (MOVHstore [4] ptr (MOVDconst [0]) (MOVWstore ptr (MOVDconst [0]) mem))
	for {
		if auxIntToInt64(v.AuxInt) != 6 {
			break
		}
		ptr := v_0
		mem := v_1
		v.reset(OpARM64MOVHstore)
		v.AuxInt = int32ToAuxInt(4)
		v0 := b.NewValue0(v.Pos, OpARM64MOVDconst, typ.UInt64)
		v0.AuxInt = int64ToAuxInt(0)
		v1 := b.NewValue0(v.Pos, OpARM64MOVWstore, types.TypeMem)
		v1.AddArg3(ptr, v0, mem)
		v.AddArg3(ptr, v0, v1)
		return true
	}
	// match: (Zero [7] ptr mem)
	// result: (MOVWstore [3] ptr (MOVDconst [0]) (MOVWstore ptr (MOVDconst [0]) mem))
	for {
		if auxIntToInt64(v.AuxInt) != 7 {
			break
		}
		ptr := v_0
		mem := v_1
		v.reset(OpARM64MOVWstore)
		v.AuxInt = int32ToAuxInt(3)
		v0 := b.NewValue0(v.Pos, OpARM64MOVDconst, typ.UInt64)
		v0.AuxInt = int64ToAuxInt(0)
		v1 := b.NewValue0(v.Pos, OpARM64MOVWstore, types.TypeMem)
		v1.AddArg3(ptr, v0, mem)
		v.AddArg3(ptr, v0, v1)
		return true
	}
	// match: (Zero [8] ptr mem)
	// result: (MOVDstore ptr (MOVDconst [0]) mem)
	for {
		if auxIntToInt64(v.AuxInt) != 8 {
			break
		}
		ptr := v_0
		mem := v_1
		v.reset(OpARM64MOVDstore)
		v0 := b.NewValue0(v.Pos, OpARM64MOVDconst, typ.UInt64)
		v0.AuxInt = int64ToAuxInt(0)
		v.AddArg3(ptr, v0, mem)
		return true
	}
	// match: (Zero [9] ptr mem)
	// result: (MOVBstore [8] ptr (MOVDconst [0]) (MOVDstore ptr (MOVDconst [0]) mem))
	for {
		if auxIntToInt64(v.AuxInt) != 9 {
			break
		}
		ptr := v_0
		mem := v_1
		v.reset(OpARM64MOVBstore)
		v.AuxInt = int32ToAuxInt(8)
		v0 := b.NewValue0(v.Pos, OpARM64MOVDconst, typ.UInt64)
		v0.AuxInt = int64ToAuxInt(0)
		v1 := b.NewValue0(v.Pos, OpARM64MOVDstore, types.TypeMem)
		v1.AddArg3(ptr, v0, mem)
		v.AddArg3(ptr, v0, v1)
		return true
	}
	// match: (Zero [10] ptr mem)
	// result: (MOVHstore [8] ptr (MOVDconst [0]) (MOVDstore ptr (MOVDconst [0]) mem))
	for {
		if auxIntToInt64(v.AuxInt) != 10 {
			break
		}
		ptr := v_0
		mem := v_1
		v.reset(OpARM64MOVHstore)
		v.AuxInt = int32ToAuxInt(8)
		v0 := b.NewValue0(v.Pos, OpARM64MOVDconst, typ.UInt64)
		v0.AuxInt = int64ToAuxInt(0)
		v1 := b.NewValue0(v.Pos, OpARM64MOVDstore, types.TypeMem)
		v1.AddArg3(ptr, v0, mem)
		v.AddArg3(ptr, v0, v1)
		return true
	}
	// match: (Zero [11] ptr mem)
	// result: (MOVDstore [3] ptr (MOVDconst [0]) (MOVDstore ptr (MOVDconst [0]) mem))
	for {
		if auxIntToInt64(v.AuxInt) != 11 {
			break
		}
		ptr := v_0
		mem := v_1
		v.reset(OpARM64MOVDstore)
		v.AuxInt = int32ToAuxInt(3)
		v0 := b.NewValue0(v.Pos, OpARM64MOVDconst, typ.UInt64)
		v0.AuxInt = int64ToAuxInt(0)
		v1 := b.NewValue0(v.Pos, OpARM64MOVDstore, types.TypeMem)
		v1.AddArg3(ptr, v0, mem)
		v.AddArg3(ptr, v0, v1)
		return true
	}
	// match: (Zero [12] ptr mem)
	// result: (MOVWstore [8] ptr (MOVDconst [0]) (MOVDstore ptr (MOVDconst [0]) mem))
	for {
		if auxIntToInt64(v.AuxInt) != 12 {
			break
		}
		ptr := v_0
		mem := v_1
		v.reset(OpARM64MOVWstore)
		v.AuxInt = int32ToAuxInt(8)
		v0 := b.NewValue0(v.Pos, OpARM64MOVDconst, typ.UInt64)
		v0.AuxInt = int64ToAuxInt(0)
		v1 := b.NewValue0(v.Pos, OpARM64MOVDstore, types.TypeMem)
		v1.AddArg3(ptr, v0, mem)
		v.AddArg3(ptr, v0, v1)
		return true
	}
	// match: (Zero [13] ptr mem)
	// result: (MOVDstore [5] ptr (MOVDconst [0]) (MOVDstore ptr (MOVDconst [0]) mem))
	for {
		if auxIntToInt64(v.AuxInt) != 13 {
			break
		}
		ptr := v_0
		mem := v_1
		v.reset(OpARM64MOVDstore)
		v.AuxInt = int32ToAuxInt(5)
		v0 := b.NewValue0(v.Pos, OpARM64MOVDconst, typ.UInt64)
		v0.AuxInt = int64ToAuxInt(0)
		v1 := b.NewValue0(v.Pos, OpARM64MOVDstore, types.TypeMem)
		v1.AddArg3(ptr, v0, mem)
		v.AddArg3(ptr, v0, v1)
		return true
	}
	// match: (Zero [14] ptr mem)
	// result: (MOVDstore [6] ptr (MOVDconst [0]) (MOVDstore ptr (MOVDconst [0]) mem))
	for {
		if auxIntToInt64(v.AuxInt) != 14 {
			break
		}
		ptr := v_0
		mem := v_1
		v.reset(OpARM64MOVDstore)
		v.AuxInt = int32ToAuxInt(6)
		v0 := b.NewValue0(v.Pos, OpARM64MOVDconst, typ.UInt64)
		v0.AuxInt = int64ToAuxInt(0)
		v1 := b.NewValue0(v.Pos, OpARM64MOVDstore, types.TypeMem)
		v1.AddArg3(ptr, v0, mem)
		v.AddArg3(ptr, v0, v1)
		return true
	}
	// match: (Zero [15] ptr mem)
	// result: (MOVDstore [7] ptr (MOVDconst [0]) (MOVDstore ptr (MOVDconst [0]) mem))
	for {
		if auxIntToInt64(v.AuxInt) != 15 {
			break
		}
		ptr := v_0
		mem := v_1
		v.reset(OpARM64MOVDstore)
		v.AuxInt = int32ToAuxInt(7)
		v0 := b.NewValue0(v.Pos, OpARM64MOVDconst, typ.UInt64)
		v0.AuxInt = int64ToAuxInt(0)
		v1 := b.NewValue0(v.Pos, OpARM64MOVDstore, types.TypeMem)
		v1.AddArg3(ptr, v0, mem)
		v.AddArg3(ptr, v0, v1)
		return true
	}
	// match: (Zero [16] ptr mem)
	// result: (STP [0] ptr (MOVDconst [0]) (MOVDconst [0]) mem)
	for {
		if auxIntToInt64(v.AuxInt) != 16 {
			break
		}
		ptr := v_0
		mem := v_1
		v.reset(OpARM64STP)
		v.AuxInt = int32ToAuxInt(0)
		v0 := b.NewValue0(v.Pos, OpARM64MOVDconst, typ.UInt64)
		v0.AuxInt = int64ToAuxInt(0)
		v.AddArg4(ptr, v0, v0, mem)
		return true
	}
	// match: (Zero [32] ptr mem)
	// result: (STP [16] ptr (MOVDconst [0]) (MOVDconst [0]) (STP [0] ptr (MOVDconst [0]) (MOVDconst [0]) mem))
	for {
		if auxIntToInt64(v.AuxInt) != 32 {
			break
		}
		ptr := v_0
		mem := v_1
		v.reset(OpARM64STP)
		v.AuxInt = int32ToAuxInt(16)
		v0 := b.NewValue0(v.Pos, OpARM64MOVDconst, typ.UInt64)
		v0.AuxInt = int64ToAuxInt(0)
		v1 := b.NewValue0(v.Pos, OpARM64STP, types.TypeMem)
		v1.AuxInt = int32ToAuxInt(0)
		v1.AddArg4(ptr, v0, v0, mem)
		v.AddArg4(ptr, v0, v0, v1)
		return true
	}
	// match: (Zero [48] ptr mem)
	// result: (STP [32] ptr (MOVDconst [0]) (MOVDconst [0]) (STP [16] ptr (MOVDconst [0]) (MOVDconst [0]) (STP [0] ptr (MOVDconst [0]) (MOVDconst [0]) mem)))
	for {
		if auxIntToInt64(v.AuxInt) != 48 {
			break
		}
		ptr := v_0
		mem := v_1
		v.reset(OpARM64STP)
		v.AuxInt = int32ToAuxInt(32)
		v0 := b.NewValue0(v.Pos, OpARM64MOVDconst, typ.UInt64)
		v0.AuxInt = int64ToAuxInt(0)
		v1 := b.NewValue0(v.Pos, OpARM64STP, types.TypeMem)
		v1.AuxInt = int32ToAuxInt(16)
		v2 := b.NewValue0(v.Pos, OpARM64STP, types.TypeMem)
		v2.AuxInt = int32ToAuxInt(0)
		v2.AddArg4(ptr, v0, v0, mem)
		v1.AddArg4(ptr, v0, v0, v2)
		v.AddArg4(ptr, v0, v0, v1)
		return true
	}
	// match: (Zero [64] ptr mem)
	// result: (STP [48] ptr (MOVDconst [0]) (MOVDconst [0]) (STP [32] ptr (MOVDconst [0]) (MOVDconst [0]) (STP [16] ptr (MOVDconst [0]) (MOVDconst [0]) (STP [0] ptr (MOVDconst [0]) (MOVDconst [0]) mem))))
	for {
		if auxIntToInt64(v.AuxInt) != 64 {
			break
		}
		ptr := v_0
		mem := v_1
		v.reset(OpARM64STP)
		v.AuxInt = int32ToAuxInt(48)
		v0 := b.NewValue0(v.Pos, OpARM64MOVDconst, typ.UInt64)
		v0.AuxInt = int64ToAuxInt(0)
		v1 := b.NewValue0(v.Pos, OpARM64STP, types.TypeMem)
		v1.AuxInt = int32ToAuxInt(32)
		v2 := b.NewValue0(v.Pos, OpARM64STP, types.TypeMem)
		v2.AuxInt = int32ToAuxInt(16)
		v3 := b.NewValue0(v.Pos, OpARM64STP, types.TypeMem)
		v3.AuxInt = int32ToAuxInt(0)
		v3.AddArg4(ptr, v0, v0, mem)
		v2.AddArg4(ptr, v0, v0, v3)
		v1.AddArg4(ptr, v0, v0, v2)
		v.AddArg4(ptr, v0, v0, v1)
		return true
	}
	// match: (Zero [s] ptr mem)
	// cond: s%16 != 0 && s%16 <= 8 && s > 16
	// result: (Zero [8] (OffPtr <ptr.Type> ptr [s-8]) (Zero [s-s%16] ptr mem))
	for {
		s := auxIntToInt64(v.AuxInt)
		ptr := v_0
		mem := v_1
		if !(s%16 != 0 && s%16 <= 8 && s > 16) {
			break
		}
		v.reset(OpZero)
		v.AuxInt = int64ToAuxInt(8)
		v0 := b.NewValue0(v.Pos, OpOffPtr, ptr.Type)
		v0.AuxInt = int64ToAuxInt(s - 8)
		v0.AddArg(ptr)
		v1 := b.NewValue0(v.Pos, OpZero, types.TypeMem)
		v1.AuxInt = int64ToAuxInt(s - s%16)
		v1.AddArg2(ptr, mem)
		v.AddArg2(v0, v1)
		return true
	}
	// match: (Zero [s] ptr mem)
	// cond: s%16 != 0 && s%16 > 8 && s > 16
	// result: (Zero [16] (OffPtr <ptr.Type> ptr [s-16]) (Zero [s-s%16] ptr mem))
	for {
		s := auxIntToInt64(v.AuxInt)
		ptr := v_0
		mem := v_1
		if !(s%16 != 0 && s%16 > 8 && s > 16) {
			break
		}
		v.reset(OpZero)
		v.AuxInt = int64ToAuxInt(16)
		v0 := b.NewValue0(v.Pos, OpOffPtr, ptr.Type)
		v0.AuxInt = int64ToAuxInt(s - 16)
		v0.AddArg(ptr)
		v1 := b.NewValue0(v.Pos, OpZero, types.TypeMem)
		v1.AuxInt = int64ToAuxInt(s - s%16)
		v1.AddArg2(ptr, mem)
		v.AddArg2(v0, v1)
		return true
	}
	// match: (Zero [s] ptr mem)
	// cond: s%16 == 0 && s > 64 && s <= 16*64 && !config.noDuffDevice
	// result: (DUFFZERO [4 * (64 - s/16)] ptr mem)
	for {
		s := auxIntToInt64(v.AuxInt)
		ptr := v_0
		mem := v_1
		if !(s%16 == 0 && s > 64 && s <= 16*64 && !config.noDuffDevice) {
			break
		}
		v.reset(OpARM64DUFFZERO)
		v.AuxInt = int64ToAuxInt(4 * (64 - s/16))
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (Zero [s] ptr mem)
	// cond: s%16 == 0 && (s > 16*64 || config.noDuffDevice)
	// result: (LoweredZero ptr (ADDconst <ptr.Type> [s-16] ptr) mem)
	for {
		s := auxIntToInt64(v.AuxInt)
		ptr := v_0
		mem := v_1
		if !(s%16 == 0 && (s > 16*64 || config.noDuffDevice)) {
			break
		}
		v.reset(OpARM64LoweredZero)
		v0 := b.NewValue0(v.Pos, OpARM64ADDconst, ptr.Type)
		v0.AuxInt = int64ToAuxInt(s - 16)
		v0.AddArg(ptr)
		v.AddArg3(ptr, v0, mem)
		return true
	}
	return false
}
func rewriteBlockARM64(b *Block) bool {
	typ := &b.Func.Config.Types
	switch b.Kind {
	case BlockARM64EQ:
		// match: (EQ (CMPconst [0] z:(AND x y)) yes no)
		// cond: z.Uses == 1
		// result: (EQ (TST x y) yes no)
		for b.Controls[0].Op == OpARM64CMPconst {
			v_0 := b.Controls[0]
			if auxIntToInt64(v_0.AuxInt) != 0 {
				break
			}
			z := v_0.Args[0]
			if z.Op != OpARM64AND {
				break
			}
			_ = z.Args[1]
			z_0 := z.Args[0]
			z_1 := z.Args[1]
			for _i0 := 0; _i0 <= 1; _i0, z_0, z_1 = _i0+1, z_1, z_0 {
				x := z_0
				y := z_1
				if !(z.Uses == 1) {
					continue
				}
				v0 := b.NewValue0(v_0.Pos, OpARM64TST, types.TypeFlags)
				v0.AddArg2(x, y)
				b.resetWithControl(BlockARM64EQ, v0)
				return true
			}
			break
		}
		// match: (EQ (CMPconst [0] x:(ANDconst [c] y)) yes no)
		// cond: x.Uses == 1
		// result: (EQ (TSTconst [c] y) yes no)
		for b.Controls[0].Op == OpARM64CMPconst {
			v_0 := b.Controls[0]
			if auxIntToInt64(v_0.AuxInt) != 0 {
				break
			}
			x := v_0.Args[0]
			if x.Op != OpARM64ANDconst {
				break
			}
			c := auxIntToInt64(x.AuxInt)
			y := x.Args[0
```