Response:
Let's break down the thought process for answering this request.

1. **Understanding the Goal:** The primary goal is to analyze a Go code snippet from `rewriteLOONG64.go` and explain its function, ideally connecting it to higher-level Go language features. The request also asks for examples, potential errors, and a summary of this specific part.

2. **Initial Code Scan - Identifying Patterns:** The first step is to quickly scan the provided code. Several patterns immediately jump out:
    * **Function Naming:**  The functions are named `rewriteValueLOONG64_Op...`. This strongly suggests these functions are part of a rewriting or optimization phase within the Go compiler, specifically targeting the LOONG64 architecture. The `Op` part likely refers to specific Go intermediate representation (IR) operations.
    * **`match:` and `result:` Comments:** These comments are crucial. They describe a pattern to be matched in the IR and the corresponding transformation. This is a classic pattern for rewrite rules in compilers.
    * **`v.reset(...)`:** This indicates that the current IR node `v` is being replaced with a new operation.
    * **`b.NewValue0(...)`:**  This suggests creating new IR nodes.
    * **`AddArg(...)` and `AddArg2(...)`:** These methods are used to build the arguments of the new IR nodes.
    * **Targeted Operations:** The code deals with operations like `PopCount`, `RotateLeft`, `Rsh` (right shift), `Select0`, `Select1`, and `SelectN`. These are a mix of bit manipulation and tuple access operations.
    * **Architecture-Specific Opcodes:**  Opcodes like `OpLOONG64MOVWfpgp`, `OpLOONG64VPCNT16`, `OpLOONG64ROTR`, `OpLOONG64SRAV`, etc., clearly point to LOONG64 assembly instructions.
    * **Type Handling:** The code frequently uses `typ := &b.Func.Config.Types` to access Go's type system information, showing type-aware transformations.

3. **Deduction - Rewrite Rules for Optimization:** Based on the patterns, the primary function of this code is to define architecture-specific rewrite rules. These rules take high-level Go operations and transform them into more efficient or direct sequences of LOONG64 instructions. This is a core part of the compiler's backend optimization.

4. **Focusing on Specific Examples (Instruction #2):** The request asks for examples of the Go language features being implemented. Let's take a few examples from the code:

    * **`PopCount`:** The `PopCount` functions are clearly implementing the counting of set bits. This is a standard bit manipulation operation. We can easily provide a Go example for `bits.OnesCount*`.
    * **`RotateLeft`:** The `RotateLeft` functions implement left bit rotation. Go's `bits` package provides `bits.RotateLeft*`.
    * **`Rsh` (Right Shift):** The `Rsh` functions implement right bit shifts, both signed and unsigned. Standard Go shift operators (`>>` and `>>>`) cover this. The code shows how Go's generic right shift operations are translated into LOONG64's specific instructions, including handling cases where the shift amount might be out of bounds.
    * **`Select0`, `Select1`, `SelectN`:** These are related to accessing elements from tuples or multi-value returns. Go functions can return multiple values.

5. **Code Example Generation (Instruction #3):**  Now we write Go code examples that would trigger these rewrite rules. The key is to use the corresponding Go language constructs:

    ```go
    package main

    import "math/bits"

    func main() {
        var x uint16 = 10
        var y uint32 = 12345
        var z uint64 = 9876543210

        _ = bits.OnesCount16(x)
        _ = bits.RotateLeft16(x, 2)
        _ = x >> 2  // Unsigned right shift
        _ = int16(x) >> 2 // Signed right shift

        a, _ := multiReturn()
        _ = a
    }

    func multiReturn() (int, bool) {
        return 1, true
    }
    ```

6. **Reasoning and Assumptions (Instruction #4):** While generating the examples, we make assumptions:

    * **Compiler Behavior:** We assume the Go compiler, when targeting LOONG64, will apply these rewrite rules during the SSA optimization phase.
    * **`Op...` Mapping:** We infer that `OpPopCount16` corresponds to `bits.OnesCount16`, `OpRotateLeft16` to `bits.RotateLeft16`, and so on.
    * **Shift Operator Mapping:** We assume `>>` will be translated to the appropriate `Rsh` operations based on the operand types.

7. **Command-line Arguments (Instruction #5):** This code doesn't directly process command-line arguments. The `cmd/compile` package itself *does* handle command-line arguments for compilation (like `-o`, `-gcflags`, etc.), but this specific file is about internal compiler transformations. So, the answer is that this snippet doesn't handle command-line arguments.

8. **Common Mistakes (Instruction #6):**  Thinking about potential errors, a user might not be directly interacting with this code. However, understanding these rewrites can help in:

    * **Performance Awareness:** Knowing how Go operations translate to specific instructions on an architecture helps understand performance implications. For example, realizing that a simple rotate might involve a sequence of shifts and ORs.
    * **Debugging Assembly:** If debugging at the assembly level, recognizing these patterns can be useful.

9. **Summarization (Instruction #7):** Finally, summarize the identified functionalities concisely. Focus on the core purpose: optimizing Go code for LOONG64 by rewriting IR operations into efficient instruction sequences.

10. **Review and Refine:** Read through the entire answer to ensure clarity, accuracy, and completeness. Check that all parts of the original request have been addressed. For instance, confirm that the code examples make sense in relation to the rewrite rules.

This detailed thought process combines code analysis, pattern recognition, knowledge of compiler design (specifically SSA and rewrite rules), and an understanding of the target architecture (LOONG64) and the Go language. It moves from low-level code details to higher-level language concepts and practical implications.
这是go语言编译器中针对LOONG64架构进行代码优化的一个环节，具体来说，它属于**SSA（Static Single Assignment）中间表示**的**rewrite阶段**，专注于将一些通用的SSA操作符转换为LOONG64架构特有的、更高效的指令序列。

**具体功能归纳:**

这个代码片段的主要功能是针对一些特定的Go语言操作，将其在SSA中间表示阶段转换为更底层的、针对LOONG64架构优化的指令序列。 这些操作主要包括：

* **位计数 (PopCount):**  将计算一个数中置位比特数量的操作，转换为LOONG64架构下利用浮点寄存器和向量指令 `VPCNT16`, `VPCNT32`, `VPCNT64` 的高效实现。
* **循环移位 (RotateLeft):** 将左循环移位操作转换为LOONG64架构下的 `ROTR` (Rotate Right) 指令，并结合取反操作来模拟左循环移位。对于常量移位，则会转换为移位和或操作的组合。
* **算术右移 (Rsh - Signed Right Shift):** 将有符号数的右移操作，针对不同大小的移位量，转换为LOONG64架构下的 `SRAV` (Shift Right Algebraic Variable) 指令，并巧妙地处理移位量超出范围的情况。
* **逻辑右移 (RshU - Unsigned Right Shift):** 将无符号数的右移操作，针对不同大小的移位量，转换为LOONG64架构下的 `SRLV` (Shift Right Logical Variable) 指令，并使用 `MASKEQZ` 和 `SGTU` 指令来处理移位量超出范围的情况。
* **Select0 和 Select1:**  用于从返回多个值的操作中选择特定的返回值。这里针对 `Mul64uhilo` (64位无符号数乘法，返回高低位) 和 `Add64carry`/`Sub64borrow` (带进位/借位的加减法) 进行了优化，直接映射到LOONG64架构的指令，或者通过组合LOONG64指令来实现。
* **SelectN:**  用于从函数调用返回的多个值中选择第N个值。这里特别针对 `runtime.memmove` 进行了优化，当满足特定条件时，会将 `CALLstatic` 转换为更底层的 `Move` 操作。

**Go语言功能实现举例 (带代码推理):**

**1. 位计数 (PopCount):**

**Go 代码:**

```go
package main

import "fmt"
import "math/bits"

func main() {
	var x uint16 = 0b1011001100001111
	count := bits.OnesCount16(x)
	fmt.Println(count) // Output: 10
}
```

**SSA 转换和 LOONG64 指令:**

**假设输入 SSA (简化):**

```
v1 = OpPopCount16 <uint16> x
```

**rewriteLOONG64.go 中的代码转换:**

```go
// match: (PopCount16 <t> x)
// result: (MOVWfpgp <t> (VPCNT16 <typ.Float32> (MOVWgpfp <typ.Float32> (ZeroExt16to32 x))))
```

**推理出的 LOONG64 指令序列:**

1. `ZeroExt16to32 x`:  将 16 位的 `x` 零扩展到 32 位。
2. `MOVWgpfp <typ.Float32> (ZeroExt16to32 x)`: 将 32 位整数移动到浮点寄存器。
3. `VPCNT16 <typ.Float32> (...)`: 使用 LOONG64 的向量指令 `VPCNT16` 计算 16 位数的位计数 (尽管这里操作的是 32 位，但 `VPCNT16` 可能按 16 位处理)。
4. `MOVWfpgp <t> (...)`: 将浮点寄存器中的结果移动回整数寄存器。

**2. 循环左移 (RotateLeft):**

**Go 代码:**

```go
package main

import "fmt"
import "math/bits"

func main() {
	var x uint16 = 0b0000000000000001
	rotated := bits.RotateLeft16(x, 3)
	fmt.Printf("%b\n", rotated) // Output: 1000
}
```

**SSA 转换和 LOONG64 指令:**

**假设输入 SSA (简化):**

```
v2 = OpRotateLeft16 <uint16> x (MOVVconst [3])
```

**rewriteLOONG64.go 中的代码转换:**

```go
// match: (RotateLeft16 <t> x (MOVVconst [c]))
// result: (Or16 (Lsh16x64 <t> x (MOVVconst [c&15])) (Rsh16Ux64 <t> x (MOVVconst [-c&15])))
```

**推理出的 LOONG64 指令序列:**

1. `MOVVconst [3&15]`: 创建常量 3。
2. `Lsh16x64 <t> x ...`: 将 `x` 左移 3 位。
3. `MOVVconst [-3&15]`: 创建常量 13 (16 - 3)。
4. `Rsh16Ux64 <t> x ...`: 将 `x` 无符号右移 13 位。
5. `Or16 ... ...`: 将左移和右移的结果进行按位或运算，实现循环左移。

**3. Select0 (从 Mul64uhilo 获取低位):**

**Go 代码:**

```go
package main

import "fmt"

func main() {
	var a uint64 = 10
	var b uint64 = 20
	low, _ := mul64uhilo(a, b)
	fmt.Println(low) // Output: 200
}

func mul64uhilo(x, y uint64) (uint64, uint64) {
	p := x * y
	return p, p // 实际编译器会使用特殊的mul操作
}
```

**SSA 转换和 LOONG64 指令:**

**假设输入 SSA (简化):**

```
v3 = OpMul64uhilo a b
v4 = OpSelect0 v3
```

**rewriteLOONG64.go 中的代码转换:**

```go
// match: (Select0 (Mul64uhilo x y))
// result: (MULHVU x y)
```

**推理出的 LOONG64 指令序列:**

`MULV a b`:  使用 LOONG64 的 `MULV` 指令执行 64 位无符号乘法，并将低 64 位结果存储到目标寄存器。  (注意 `MULHVU` 通常用于获取高位，这里可能是笔误或者上下文有其他处理). 实际上，`Select0` 应该对应低位，所以可能是直接使用标准的乘法指令，或者 `MULV` 可能同时返回低位。

**命令行参数:**

这个代码片段本身不直接处理命令行参数。它是 Go 编译器内部 `cmd/compile` 包的一部分，而 `cmd/compile` 在编译 Go 代码时会接收各种命令行参数，例如：

* `-o <output file>`:  指定输出文件的名称。
* `-gcflags <arguments>`:  将参数传递给 Go 汇编器。
* `-l`:  禁用内联优化。
* `-N`:  禁用优化。
* `-S`:  打印汇编代码。

这些命令行参数会影响编译器的行为，包括是否启用某些优化，但 `rewriteLOONG64.go`  是在这些参数处理之后，编译器内部执行代码转换的一个阶段。

**使用者易犯错的点:**

开发者通常不会直接与 `rewriteLOONG64.go` 这样的编译器内部代码交互。 这个文件的作用是对生成的中间代码进行优化。  因此，使用者不会直接因为这个文件而犯错。

然而，理解这些底层的优化可以帮助开发者更好地理解 Go 代码在特定架构上的性能特征。 例如，了解循环移位是如何实现的，有助于理解其性能开销。

**第7部分功能归纳:**

这部分 `rewriteLOONG64.go` 的主要功能是定义了一系列**SSA 重写规则**，用于将 Go 语言的通用操作转换为更底层的、针对 **LOONG64 架构优化的指令序列**。  它涵盖了位计数、循环移位、算术和逻辑右移以及从多返回值函数中选择特定返回值的优化。 这些规则旨在提升在 LOONG64 架构上运行的 Go 程序的性能。

### 提示词
```
这是路径为go/src/cmd/compile/internal/ssa/rewriteLOONG64.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第7部分，共8部分，请归纳一下它的功能
```

### 源代码
```go
PopCount16(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (PopCount16 <t> x)
	// result: (MOVWfpgp <t> (VPCNT16 <typ.Float32> (MOVWgpfp <typ.Float32> (ZeroExt16to32 x))))
	for {
		t := v.Type
		x := v_0
		v.reset(OpLOONG64MOVWfpgp)
		v.Type = t
		v0 := b.NewValue0(v.Pos, OpLOONG64VPCNT16, typ.Float32)
		v1 := b.NewValue0(v.Pos, OpLOONG64MOVWgpfp, typ.Float32)
		v2 := b.NewValue0(v.Pos, OpZeroExt16to32, typ.UInt32)
		v2.AddArg(x)
		v1.AddArg(v2)
		v0.AddArg(v1)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueLOONG64_OpPopCount32(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (PopCount32 <t> x)
	// result: (MOVWfpgp <t> (VPCNT32 <typ.Float32> (MOVWgpfp <typ.Float32> x)))
	for {
		t := v.Type
		x := v_0
		v.reset(OpLOONG64MOVWfpgp)
		v.Type = t
		v0 := b.NewValue0(v.Pos, OpLOONG64VPCNT32, typ.Float32)
		v1 := b.NewValue0(v.Pos, OpLOONG64MOVWgpfp, typ.Float32)
		v1.AddArg(x)
		v0.AddArg(v1)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueLOONG64_OpPopCount64(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (PopCount64 <t> x)
	// result: (MOVVfpgp <t> (VPCNT64 <typ.Float64> (MOVVgpfp <typ.Float64> x)))
	for {
		t := v.Type
		x := v_0
		v.reset(OpLOONG64MOVVfpgp)
		v.Type = t
		v0 := b.NewValue0(v.Pos, OpLOONG64VPCNT64, typ.Float64)
		v1 := b.NewValue0(v.Pos, OpLOONG64MOVVgpfp, typ.Float64)
		v1.AddArg(x)
		v0.AddArg(v1)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueLOONG64_OpRotateLeft16(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (RotateLeft16 <t> x (MOVVconst [c]))
	// result: (Or16 (Lsh16x64 <t> x (MOVVconst [c&15])) (Rsh16Ux64 <t> x (MOVVconst [-c&15])))
	for {
		t := v.Type
		x := v_0
		if v_1.Op != OpLOONG64MOVVconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		v.reset(OpOr16)
		v0 := b.NewValue0(v.Pos, OpLsh16x64, t)
		v1 := b.NewValue0(v.Pos, OpLOONG64MOVVconst, typ.UInt64)
		v1.AuxInt = int64ToAuxInt(c & 15)
		v0.AddArg2(x, v1)
		v2 := b.NewValue0(v.Pos, OpRsh16Ux64, t)
		v3 := b.NewValue0(v.Pos, OpLOONG64MOVVconst, typ.UInt64)
		v3.AuxInt = int64ToAuxInt(-c & 15)
		v2.AddArg2(x, v3)
		v.AddArg2(v0, v2)
		return true
	}
	// match: (RotateLeft16 <t> x y)
	// result: (ROTR <t> (OR <typ.UInt32> (ZeroExt16to32 x) (SLLVconst <t> (ZeroExt16to32 x) [16])) (NEGV <typ.Int64> y))
	for {
		t := v.Type
		x := v_0
		y := v_1
		v.reset(OpLOONG64ROTR)
		v.Type = t
		v0 := b.NewValue0(v.Pos, OpLOONG64OR, typ.UInt32)
		v1 := b.NewValue0(v.Pos, OpZeroExt16to32, typ.UInt32)
		v1.AddArg(x)
		v2 := b.NewValue0(v.Pos, OpLOONG64SLLVconst, t)
		v2.AuxInt = int64ToAuxInt(16)
		v2.AddArg(v1)
		v0.AddArg2(v1, v2)
		v3 := b.NewValue0(v.Pos, OpLOONG64NEGV, typ.Int64)
		v3.AddArg(y)
		v.AddArg2(v0, v3)
		return true
	}
}
func rewriteValueLOONG64_OpRotateLeft32(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (RotateLeft32 x y)
	// result: (ROTR x (NEGV <y.Type> y))
	for {
		x := v_0
		y := v_1
		v.reset(OpLOONG64ROTR)
		v0 := b.NewValue0(v.Pos, OpLOONG64NEGV, y.Type)
		v0.AddArg(y)
		v.AddArg2(x, v0)
		return true
	}
}
func rewriteValueLOONG64_OpRotateLeft64(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (RotateLeft64 x y)
	// result: (ROTRV x (NEGV <y.Type> y))
	for {
		x := v_0
		y := v_1
		v.reset(OpLOONG64ROTRV)
		v0 := b.NewValue0(v.Pos, OpLOONG64NEGV, y.Type)
		v0.AddArg(y)
		v.AddArg2(x, v0)
		return true
	}
}
func rewriteValueLOONG64_OpRotateLeft8(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (RotateLeft8 <t> x (MOVVconst [c]))
	// result: (Or8 (Lsh8x64 <t> x (MOVVconst [c&7])) (Rsh8Ux64 <t> x (MOVVconst [-c&7])))
	for {
		t := v.Type
		x := v_0
		if v_1.Op != OpLOONG64MOVVconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		v.reset(OpOr8)
		v0 := b.NewValue0(v.Pos, OpLsh8x64, t)
		v1 := b.NewValue0(v.Pos, OpLOONG64MOVVconst, typ.UInt64)
		v1.AuxInt = int64ToAuxInt(c & 7)
		v0.AddArg2(x, v1)
		v2 := b.NewValue0(v.Pos, OpRsh8Ux64, t)
		v3 := b.NewValue0(v.Pos, OpLOONG64MOVVconst, typ.UInt64)
		v3.AuxInt = int64ToAuxInt(-c & 7)
		v2.AddArg2(x, v3)
		v.AddArg2(v0, v2)
		return true
	}
	// match: (RotateLeft8 <t> x y)
	// result: (OR <t> (SLLV <t> x (ANDconst <typ.Int64> [7] y)) (SRLV <t> (ZeroExt8to64 x) (ANDconst <typ.Int64> [7] (NEGV <typ.Int64> y))))
	for {
		t := v.Type
		x := v_0
		y := v_1
		v.reset(OpLOONG64OR)
		v.Type = t
		v0 := b.NewValue0(v.Pos, OpLOONG64SLLV, t)
		v1 := b.NewValue0(v.Pos, OpLOONG64ANDconst, typ.Int64)
		v1.AuxInt = int64ToAuxInt(7)
		v1.AddArg(y)
		v0.AddArg2(x, v1)
		v2 := b.NewValue0(v.Pos, OpLOONG64SRLV, t)
		v3 := b.NewValue0(v.Pos, OpZeroExt8to64, typ.UInt64)
		v3.AddArg(x)
		v4 := b.NewValue0(v.Pos, OpLOONG64ANDconst, typ.Int64)
		v4.AuxInt = int64ToAuxInt(7)
		v5 := b.NewValue0(v.Pos, OpLOONG64NEGV, typ.Int64)
		v5.AddArg(y)
		v4.AddArg(v5)
		v2.AddArg2(v3, v4)
		v.AddArg2(v0, v2)
		return true
	}
}
func rewriteValueLOONG64_OpRsh16Ux16(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Rsh16Ux16 <t> x y)
	// result: (MASKEQZ (SRLV <t> (ZeroExt16to64 x) (ZeroExt16to64 y)) (SGTU (MOVVconst <typ.UInt64> [64]) (ZeroExt16to64 y)))
	for {
		t := v.Type
		x := v_0
		y := v_1
		v.reset(OpLOONG64MASKEQZ)
		v0 := b.NewValue0(v.Pos, OpLOONG64SRLV, t)
		v1 := b.NewValue0(v.Pos, OpZeroExt16to64, typ.UInt64)
		v1.AddArg(x)
		v2 := b.NewValue0(v.Pos, OpZeroExt16to64, typ.UInt64)
		v2.AddArg(y)
		v0.AddArg2(v1, v2)
		v3 := b.NewValue0(v.Pos, OpLOONG64SGTU, typ.Bool)
		v4 := b.NewValue0(v.Pos, OpLOONG64MOVVconst, typ.UInt64)
		v4.AuxInt = int64ToAuxInt(64)
		v3.AddArg2(v4, v2)
		v.AddArg2(v0, v3)
		return true
	}
}
func rewriteValueLOONG64_OpRsh16Ux32(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Rsh16Ux32 <t> x y)
	// result: (MASKEQZ (SRLV <t> (ZeroExt16to64 x) (ZeroExt32to64 y)) (SGTU (MOVVconst <typ.UInt64> [64]) (ZeroExt32to64 y)))
	for {
		t := v.Type
		x := v_0
		y := v_1
		v.reset(OpLOONG64MASKEQZ)
		v0 := b.NewValue0(v.Pos, OpLOONG64SRLV, t)
		v1 := b.NewValue0(v.Pos, OpZeroExt16to64, typ.UInt64)
		v1.AddArg(x)
		v2 := b.NewValue0(v.Pos, OpZeroExt32to64, typ.UInt64)
		v2.AddArg(y)
		v0.AddArg2(v1, v2)
		v3 := b.NewValue0(v.Pos, OpLOONG64SGTU, typ.Bool)
		v4 := b.NewValue0(v.Pos, OpLOONG64MOVVconst, typ.UInt64)
		v4.AuxInt = int64ToAuxInt(64)
		v3.AddArg2(v4, v2)
		v.AddArg2(v0, v3)
		return true
	}
}
func rewriteValueLOONG64_OpRsh16Ux64(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Rsh16Ux64 <t> x y)
	// result: (MASKEQZ (SRLV <t> (ZeroExt16to64 x) y) (SGTU (MOVVconst <typ.UInt64> [64]) y))
	for {
		t := v.Type
		x := v_0
		y := v_1
		v.reset(OpLOONG64MASKEQZ)
		v0 := b.NewValue0(v.Pos, OpLOONG64SRLV, t)
		v1 := b.NewValue0(v.Pos, OpZeroExt16to64, typ.UInt64)
		v1.AddArg(x)
		v0.AddArg2(v1, y)
		v2 := b.NewValue0(v.Pos, OpLOONG64SGTU, typ.Bool)
		v3 := b.NewValue0(v.Pos, OpLOONG64MOVVconst, typ.UInt64)
		v3.AuxInt = int64ToAuxInt(64)
		v2.AddArg2(v3, y)
		v.AddArg2(v0, v2)
		return true
	}
}
func rewriteValueLOONG64_OpRsh16Ux8(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Rsh16Ux8 <t> x y)
	// result: (MASKEQZ (SRLV <t> (ZeroExt16to64 x) (ZeroExt8to64 y)) (SGTU (MOVVconst <typ.UInt64> [64]) (ZeroExt8to64 y)))
	for {
		t := v.Type
		x := v_0
		y := v_1
		v.reset(OpLOONG64MASKEQZ)
		v0 := b.NewValue0(v.Pos, OpLOONG64SRLV, t)
		v1 := b.NewValue0(v.Pos, OpZeroExt16to64, typ.UInt64)
		v1.AddArg(x)
		v2 := b.NewValue0(v.Pos, OpZeroExt8to64, typ.UInt64)
		v2.AddArg(y)
		v0.AddArg2(v1, v2)
		v3 := b.NewValue0(v.Pos, OpLOONG64SGTU, typ.Bool)
		v4 := b.NewValue0(v.Pos, OpLOONG64MOVVconst, typ.UInt64)
		v4.AuxInt = int64ToAuxInt(64)
		v3.AddArg2(v4, v2)
		v.AddArg2(v0, v3)
		return true
	}
}
func rewriteValueLOONG64_OpRsh16x16(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Rsh16x16 <t> x y)
	// result: (SRAV (SignExt16to64 x) (OR <t> (NEGV <t> (SGTU (ZeroExt16to64 y) (MOVVconst <typ.UInt64> [63]))) (ZeroExt16to64 y)))
	for {
		t := v.Type
		x := v_0
		y := v_1
		v.reset(OpLOONG64SRAV)
		v0 := b.NewValue0(v.Pos, OpSignExt16to64, typ.Int64)
		v0.AddArg(x)
		v1 := b.NewValue0(v.Pos, OpLOONG64OR, t)
		v2 := b.NewValue0(v.Pos, OpLOONG64NEGV, t)
		v3 := b.NewValue0(v.Pos, OpLOONG64SGTU, typ.Bool)
		v4 := b.NewValue0(v.Pos, OpZeroExt16to64, typ.UInt64)
		v4.AddArg(y)
		v5 := b.NewValue0(v.Pos, OpLOONG64MOVVconst, typ.UInt64)
		v5.AuxInt = int64ToAuxInt(63)
		v3.AddArg2(v4, v5)
		v2.AddArg(v3)
		v1.AddArg2(v2, v4)
		v.AddArg2(v0, v1)
		return true
	}
}
func rewriteValueLOONG64_OpRsh16x32(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Rsh16x32 <t> x y)
	// result: (SRAV (SignExt16to64 x) (OR <t> (NEGV <t> (SGTU (ZeroExt32to64 y) (MOVVconst <typ.UInt64> [63]))) (ZeroExt32to64 y)))
	for {
		t := v.Type
		x := v_0
		y := v_1
		v.reset(OpLOONG64SRAV)
		v0 := b.NewValue0(v.Pos, OpSignExt16to64, typ.Int64)
		v0.AddArg(x)
		v1 := b.NewValue0(v.Pos, OpLOONG64OR, t)
		v2 := b.NewValue0(v.Pos, OpLOONG64NEGV, t)
		v3 := b.NewValue0(v.Pos, OpLOONG64SGTU, typ.Bool)
		v4 := b.NewValue0(v.Pos, OpZeroExt32to64, typ.UInt64)
		v4.AddArg(y)
		v5 := b.NewValue0(v.Pos, OpLOONG64MOVVconst, typ.UInt64)
		v5.AuxInt = int64ToAuxInt(63)
		v3.AddArg2(v4, v5)
		v2.AddArg(v3)
		v1.AddArg2(v2, v4)
		v.AddArg2(v0, v1)
		return true
	}
}
func rewriteValueLOONG64_OpRsh16x64(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Rsh16x64 <t> x y)
	// result: (SRAV (SignExt16to64 x) (OR <t> (NEGV <t> (SGTU y (MOVVconst <typ.UInt64> [63]))) y))
	for {
		t := v.Type
		x := v_0
		y := v_1
		v.reset(OpLOONG64SRAV)
		v0 := b.NewValue0(v.Pos, OpSignExt16to64, typ.Int64)
		v0.AddArg(x)
		v1 := b.NewValue0(v.Pos, OpLOONG64OR, t)
		v2 := b.NewValue0(v.Pos, OpLOONG64NEGV, t)
		v3 := b.NewValue0(v.Pos, OpLOONG64SGTU, typ.Bool)
		v4 := b.NewValue0(v.Pos, OpLOONG64MOVVconst, typ.UInt64)
		v4.AuxInt = int64ToAuxInt(63)
		v3.AddArg2(y, v4)
		v2.AddArg(v3)
		v1.AddArg2(v2, y)
		v.AddArg2(v0, v1)
		return true
	}
}
func rewriteValueLOONG64_OpRsh16x8(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Rsh16x8 <t> x y)
	// result: (SRAV (SignExt16to64 x) (OR <t> (NEGV <t> (SGTU (ZeroExt8to64 y) (MOVVconst <typ.UInt64> [63]))) (ZeroExt8to64 y)))
	for {
		t := v.Type
		x := v_0
		y := v_1
		v.reset(OpLOONG64SRAV)
		v0 := b.NewValue0(v.Pos, OpSignExt16to64, typ.Int64)
		v0.AddArg(x)
		v1 := b.NewValue0(v.Pos, OpLOONG64OR, t)
		v2 := b.NewValue0(v.Pos, OpLOONG64NEGV, t)
		v3 := b.NewValue0(v.Pos, OpLOONG64SGTU, typ.Bool)
		v4 := b.NewValue0(v.Pos, OpZeroExt8to64, typ.UInt64)
		v4.AddArg(y)
		v5 := b.NewValue0(v.Pos, OpLOONG64MOVVconst, typ.UInt64)
		v5.AuxInt = int64ToAuxInt(63)
		v3.AddArg2(v4, v5)
		v2.AddArg(v3)
		v1.AddArg2(v2, v4)
		v.AddArg2(v0, v1)
		return true
	}
}
func rewriteValueLOONG64_OpRsh32Ux16(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Rsh32Ux16 <t> x y)
	// result: (MASKEQZ (SRLV <t> (ZeroExt32to64 x) (ZeroExt16to64 y)) (SGTU (MOVVconst <typ.UInt64> [64]) (ZeroExt16to64 y)))
	for {
		t := v.Type
		x := v_0
		y := v_1
		v.reset(OpLOONG64MASKEQZ)
		v0 := b.NewValue0(v.Pos, OpLOONG64SRLV, t)
		v1 := b.NewValue0(v.Pos, OpZeroExt32to64, typ.UInt64)
		v1.AddArg(x)
		v2 := b.NewValue0(v.Pos, OpZeroExt16to64, typ.UInt64)
		v2.AddArg(y)
		v0.AddArg2(v1, v2)
		v3 := b.NewValue0(v.Pos, OpLOONG64SGTU, typ.Bool)
		v4 := b.NewValue0(v.Pos, OpLOONG64MOVVconst, typ.UInt64)
		v4.AuxInt = int64ToAuxInt(64)
		v3.AddArg2(v4, v2)
		v.AddArg2(v0, v3)
		return true
	}
}
func rewriteValueLOONG64_OpRsh32Ux32(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Rsh32Ux32 <t> x y)
	// result: (MASKEQZ (SRLV <t> (ZeroExt32to64 x) (ZeroExt32to64 y)) (SGTU (MOVVconst <typ.UInt64> [64]) (ZeroExt32to64 y)))
	for {
		t := v.Type
		x := v_0
		y := v_1
		v.reset(OpLOONG64MASKEQZ)
		v0 := b.NewValue0(v.Pos, OpLOONG64SRLV, t)
		v1 := b.NewValue0(v.Pos, OpZeroExt32to64, typ.UInt64)
		v1.AddArg(x)
		v2 := b.NewValue0(v.Pos, OpZeroExt32to64, typ.UInt64)
		v2.AddArg(y)
		v0.AddArg2(v1, v2)
		v3 := b.NewValue0(v.Pos, OpLOONG64SGTU, typ.Bool)
		v4 := b.NewValue0(v.Pos, OpLOONG64MOVVconst, typ.UInt64)
		v4.AuxInt = int64ToAuxInt(64)
		v3.AddArg2(v4, v2)
		v.AddArg2(v0, v3)
		return true
	}
}
func rewriteValueLOONG64_OpRsh32Ux64(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Rsh32Ux64 <t> x y)
	// result: (MASKEQZ (SRLV <t> (ZeroExt32to64 x) y) (SGTU (MOVVconst <typ.UInt64> [64]) y))
	for {
		t := v.Type
		x := v_0
		y := v_1
		v.reset(OpLOONG64MASKEQZ)
		v0 := b.NewValue0(v.Pos, OpLOONG64SRLV, t)
		v1 := b.NewValue0(v.Pos, OpZeroExt32to64, typ.UInt64)
		v1.AddArg(x)
		v0.AddArg2(v1, y)
		v2 := b.NewValue0(v.Pos, OpLOONG64SGTU, typ.Bool)
		v3 := b.NewValue0(v.Pos, OpLOONG64MOVVconst, typ.UInt64)
		v3.AuxInt = int64ToAuxInt(64)
		v2.AddArg2(v3, y)
		v.AddArg2(v0, v2)
		return true
	}
}
func rewriteValueLOONG64_OpRsh32Ux8(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Rsh32Ux8 <t> x y)
	// result: (MASKEQZ (SRLV <t> (ZeroExt32to64 x) (ZeroExt8to64 y)) (SGTU (MOVVconst <typ.UInt64> [64]) (ZeroExt8to64 y)))
	for {
		t := v.Type
		x := v_0
		y := v_1
		v.reset(OpLOONG64MASKEQZ)
		v0 := b.NewValue0(v.Pos, OpLOONG64SRLV, t)
		v1 := b.NewValue0(v.Pos, OpZeroExt32to64, typ.UInt64)
		v1.AddArg(x)
		v2 := b.NewValue0(v.Pos, OpZeroExt8to64, typ.UInt64)
		v2.AddArg(y)
		v0.AddArg2(v1, v2)
		v3 := b.NewValue0(v.Pos, OpLOONG64SGTU, typ.Bool)
		v4 := b.NewValue0(v.Pos, OpLOONG64MOVVconst, typ.UInt64)
		v4.AuxInt = int64ToAuxInt(64)
		v3.AddArg2(v4, v2)
		v.AddArg2(v0, v3)
		return true
	}
}
func rewriteValueLOONG64_OpRsh32x16(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Rsh32x16 <t> x y)
	// result: (SRAV (SignExt32to64 x) (OR <t> (NEGV <t> (SGTU (ZeroExt16to64 y) (MOVVconst <typ.UInt64> [63]))) (ZeroExt16to64 y)))
	for {
		t := v.Type
		x := v_0
		y := v_1
		v.reset(OpLOONG64SRAV)
		v0 := b.NewValue0(v.Pos, OpSignExt32to64, typ.Int64)
		v0.AddArg(x)
		v1 := b.NewValue0(v.Pos, OpLOONG64OR, t)
		v2 := b.NewValue0(v.Pos, OpLOONG64NEGV, t)
		v3 := b.NewValue0(v.Pos, OpLOONG64SGTU, typ.Bool)
		v4 := b.NewValue0(v.Pos, OpZeroExt16to64, typ.UInt64)
		v4.AddArg(y)
		v5 := b.NewValue0(v.Pos, OpLOONG64MOVVconst, typ.UInt64)
		v5.AuxInt = int64ToAuxInt(63)
		v3.AddArg2(v4, v5)
		v2.AddArg(v3)
		v1.AddArg2(v2, v4)
		v.AddArg2(v0, v1)
		return true
	}
}
func rewriteValueLOONG64_OpRsh32x32(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Rsh32x32 <t> x y)
	// result: (SRAV (SignExt32to64 x) (OR <t> (NEGV <t> (SGTU (ZeroExt32to64 y) (MOVVconst <typ.UInt64> [63]))) (ZeroExt32to64 y)))
	for {
		t := v.Type
		x := v_0
		y := v_1
		v.reset(OpLOONG64SRAV)
		v0 := b.NewValue0(v.Pos, OpSignExt32to64, typ.Int64)
		v0.AddArg(x)
		v1 := b.NewValue0(v.Pos, OpLOONG64OR, t)
		v2 := b.NewValue0(v.Pos, OpLOONG64NEGV, t)
		v3 := b.NewValue0(v.Pos, OpLOONG64SGTU, typ.Bool)
		v4 := b.NewValue0(v.Pos, OpZeroExt32to64, typ.UInt64)
		v4.AddArg(y)
		v5 := b.NewValue0(v.Pos, OpLOONG64MOVVconst, typ.UInt64)
		v5.AuxInt = int64ToAuxInt(63)
		v3.AddArg2(v4, v5)
		v2.AddArg(v3)
		v1.AddArg2(v2, v4)
		v.AddArg2(v0, v1)
		return true
	}
}
func rewriteValueLOONG64_OpRsh32x64(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Rsh32x64 <t> x y)
	// result: (SRAV (SignExt32to64 x) (OR <t> (NEGV <t> (SGTU y (MOVVconst <typ.UInt64> [63]))) y))
	for {
		t := v.Type
		x := v_0
		y := v_1
		v.reset(OpLOONG64SRAV)
		v0 := b.NewValue0(v.Pos, OpSignExt32to64, typ.Int64)
		v0.AddArg(x)
		v1 := b.NewValue0(v.Pos, OpLOONG64OR, t)
		v2 := b.NewValue0(v.Pos, OpLOONG64NEGV, t)
		v3 := b.NewValue0(v.Pos, OpLOONG64SGTU, typ.Bool)
		v4 := b.NewValue0(v.Pos, OpLOONG64MOVVconst, typ.UInt64)
		v4.AuxInt = int64ToAuxInt(63)
		v3.AddArg2(y, v4)
		v2.AddArg(v3)
		v1.AddArg2(v2, y)
		v.AddArg2(v0, v1)
		return true
	}
}
func rewriteValueLOONG64_OpRsh32x8(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Rsh32x8 <t> x y)
	// result: (SRAV (SignExt32to64 x) (OR <t> (NEGV <t> (SGTU (ZeroExt8to64 y) (MOVVconst <typ.UInt64> [63]))) (ZeroExt8to64 y)))
	for {
		t := v.Type
		x := v_0
		y := v_1
		v.reset(OpLOONG64SRAV)
		v0 := b.NewValue0(v.Pos, OpSignExt32to64, typ.Int64)
		v0.AddArg(x)
		v1 := b.NewValue0(v.Pos, OpLOONG64OR, t)
		v2 := b.NewValue0(v.Pos, OpLOONG64NEGV, t)
		v3 := b.NewValue0(v.Pos, OpLOONG64SGTU, typ.Bool)
		v4 := b.NewValue0(v.Pos, OpZeroExt8to64, typ.UInt64)
		v4.AddArg(y)
		v5 := b.NewValue0(v.Pos, OpLOONG64MOVVconst, typ.UInt64)
		v5.AuxInt = int64ToAuxInt(63)
		v3.AddArg2(v4, v5)
		v2.AddArg(v3)
		v1.AddArg2(v2, v4)
		v.AddArg2(v0, v1)
		return true
	}
}
func rewriteValueLOONG64_OpRsh64Ux16(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Rsh64Ux16 <t> x y)
	// result: (MASKEQZ (SRLV <t> x (ZeroExt16to64 y)) (SGTU (MOVVconst <typ.UInt64> [64]) (ZeroExt16to64 y)))
	for {
		t := v.Type
		x := v_0
		y := v_1
		v.reset(OpLOONG64MASKEQZ)
		v0 := b.NewValue0(v.Pos, OpLOONG64SRLV, t)
		v1 := b.NewValue0(v.Pos, OpZeroExt16to64, typ.UInt64)
		v1.AddArg(y)
		v0.AddArg2(x, v1)
		v2 := b.NewValue0(v.Pos, OpLOONG64SGTU, typ.Bool)
		v3 := b.NewValue0(v.Pos, OpLOONG64MOVVconst, typ.UInt64)
		v3.AuxInt = int64ToAuxInt(64)
		v2.AddArg2(v3, v1)
		v.AddArg2(v0, v2)
		return true
	}
}
func rewriteValueLOONG64_OpRsh64Ux32(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Rsh64Ux32 <t> x y)
	// result: (MASKEQZ (SRLV <t> x (ZeroExt32to64 y)) (SGTU (MOVVconst <typ.UInt64> [64]) (ZeroExt32to64 y)))
	for {
		t := v.Type
		x := v_0
		y := v_1
		v.reset(OpLOONG64MASKEQZ)
		v0 := b.NewValue0(v.Pos, OpLOONG64SRLV, t)
		v1 := b.NewValue0(v.Pos, OpZeroExt32to64, typ.UInt64)
		v1.AddArg(y)
		v0.AddArg2(x, v1)
		v2 := b.NewValue0(v.Pos, OpLOONG64SGTU, typ.Bool)
		v3 := b.NewValue0(v.Pos, OpLOONG64MOVVconst, typ.UInt64)
		v3.AuxInt = int64ToAuxInt(64)
		v2.AddArg2(v3, v1)
		v.AddArg2(v0, v2)
		return true
	}
}
func rewriteValueLOONG64_OpRsh64Ux64(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Rsh64Ux64 <t> x y)
	// result: (MASKEQZ (SRLV <t> x y) (SGTU (MOVVconst <typ.UInt64> [64]) y))
	for {
		t := v.Type
		x := v_0
		y := v_1
		v.reset(OpLOONG64MASKEQZ)
		v0 := b.NewValue0(v.Pos, OpLOONG64SRLV, t)
		v0.AddArg2(x, y)
		v1 := b.NewValue0(v.Pos, OpLOONG64SGTU, typ.Bool)
		v2 := b.NewValue0(v.Pos, OpLOONG64MOVVconst, typ.UInt64)
		v2.AuxInt = int64ToAuxInt(64)
		v1.AddArg2(v2, y)
		v.AddArg2(v0, v1)
		return true
	}
}
func rewriteValueLOONG64_OpRsh64Ux8(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Rsh64Ux8 <t> x y)
	// result: (MASKEQZ (SRLV <t> x (ZeroExt8to64 y)) (SGTU (MOVVconst <typ.UInt64> [64]) (ZeroExt8to64 y)))
	for {
		t := v.Type
		x := v_0
		y := v_1
		v.reset(OpLOONG64MASKEQZ)
		v0 := b.NewValue0(v.Pos, OpLOONG64SRLV, t)
		v1 := b.NewValue0(v.Pos, OpZeroExt8to64, typ.UInt64)
		v1.AddArg(y)
		v0.AddArg2(x, v1)
		v2 := b.NewValue0(v.Pos, OpLOONG64SGTU, typ.Bool)
		v3 := b.NewValue0(v.Pos, OpLOONG64MOVVconst, typ.UInt64)
		v3.AuxInt = int64ToAuxInt(64)
		v2.AddArg2(v3, v1)
		v.AddArg2(v0, v2)
		return true
	}
}
func rewriteValueLOONG64_OpRsh64x16(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Rsh64x16 <t> x y)
	// result: (SRAV x (OR <t> (NEGV <t> (SGTU (ZeroExt16to64 y) (MOVVconst <typ.UInt64> [63]))) (ZeroExt16to64 y)))
	for {
		t := v.Type
		x := v_0
		y := v_1
		v.reset(OpLOONG64SRAV)
		v0 := b.NewValue0(v.Pos, OpLOONG64OR, t)
		v1 := b.NewValue0(v.Pos, OpLOONG64NEGV, t)
		v2 := b.NewValue0(v.Pos, OpLOONG64SGTU, typ.Bool)
		v3 := b.NewValue0(v.Pos, OpZeroExt16to64, typ.UInt64)
		v3.AddArg(y)
		v4 := b.NewValue0(v.Pos, OpLOONG64MOVVconst, typ.UInt64)
		v4.AuxInt = int64ToAuxInt(63)
		v2.AddArg2(v3, v4)
		v1.AddArg(v2)
		v0.AddArg2(v1, v3)
		v.AddArg2(x, v0)
		return true
	}
}
func rewriteValueLOONG64_OpRsh64x32(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Rsh64x32 <t> x y)
	// result: (SRAV x (OR <t> (NEGV <t> (SGTU (ZeroExt32to64 y) (MOVVconst <typ.UInt64> [63]))) (ZeroExt32to64 y)))
	for {
		t := v.Type
		x := v_0
		y := v_1
		v.reset(OpLOONG64SRAV)
		v0 := b.NewValue0(v.Pos, OpLOONG64OR, t)
		v1 := b.NewValue0(v.Pos, OpLOONG64NEGV, t)
		v2 := b.NewValue0(v.Pos, OpLOONG64SGTU, typ.Bool)
		v3 := b.NewValue0(v.Pos, OpZeroExt32to64, typ.UInt64)
		v3.AddArg(y)
		v4 := b.NewValue0(v.Pos, OpLOONG64MOVVconst, typ.UInt64)
		v4.AuxInt = int64ToAuxInt(63)
		v2.AddArg2(v3, v4)
		v1.AddArg(v2)
		v0.AddArg2(v1, v3)
		v.AddArg2(x, v0)
		return true
	}
}
func rewriteValueLOONG64_OpRsh64x64(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Rsh64x64 <t> x y)
	// result: (SRAV x (OR <t> (NEGV <t> (SGTU y (MOVVconst <typ.UInt64> [63]))) y))
	for {
		t := v.Type
		x := v_0
		y := v_1
		v.reset(OpLOONG64SRAV)
		v0 := b.NewValue0(v.Pos, OpLOONG64OR, t)
		v1 := b.NewValue0(v.Pos, OpLOONG64NEGV, t)
		v2 := b.NewValue0(v.Pos, OpLOONG64SGTU, typ.Bool)
		v3 := b.NewValue0(v.Pos, OpLOONG64MOVVconst, typ.UInt64)
		v3.AuxInt = int64ToAuxInt(63)
		v2.AddArg2(y, v3)
		v1.AddArg(v2)
		v0.AddArg2(v1, y)
		v.AddArg2(x, v0)
		return true
	}
}
func rewriteValueLOONG64_OpRsh64x8(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Rsh64x8 <t> x y)
	// result: (SRAV x (OR <t> (NEGV <t> (SGTU (ZeroExt8to64 y) (MOVVconst <typ.UInt64> [63]))) (ZeroExt8to64 y)))
	for {
		t := v.Type
		x := v_0
		y := v_1
		v.reset(OpLOONG64SRAV)
		v0 := b.NewValue0(v.Pos, OpLOONG64OR, t)
		v1 := b.NewValue0(v.Pos, OpLOONG64NEGV, t)
		v2 := b.NewValue0(v.Pos, OpLOONG64SGTU, typ.Bool)
		v3 := b.NewValue0(v.Pos, OpZeroExt8to64, typ.UInt64)
		v3.AddArg(y)
		v4 := b.NewValue0(v.Pos, OpLOONG64MOVVconst, typ.UInt64)
		v4.AuxInt = int64ToAuxInt(63)
		v2.AddArg2(v3, v4)
		v1.AddArg(v2)
		v0.AddArg2(v1, v3)
		v.AddArg2(x, v0)
		return true
	}
}
func rewriteValueLOONG64_OpRsh8Ux16(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Rsh8Ux16 <t> x y)
	// result: (MASKEQZ (SRLV <t> (ZeroExt8to64 x) (ZeroExt16to64 y)) (SGTU (MOVVconst <typ.UInt64> [64]) (ZeroExt16to64 y)))
	for {
		t := v.Type
		x := v_0
		y := v_1
		v.reset(OpLOONG64MASKEQZ)
		v0 := b.NewValue0(v.Pos, OpLOONG64SRLV, t)
		v1 := b.NewValue0(v.Pos, OpZeroExt8to64, typ.UInt64)
		v1.AddArg(x)
		v2 := b.NewValue0(v.Pos, OpZeroExt16to64, typ.UInt64)
		v2.AddArg(y)
		v0.AddArg2(v1, v2)
		v3 := b.NewValue0(v.Pos, OpLOONG64SGTU, typ.Bool)
		v4 := b.NewValue0(v.Pos, OpLOONG64MOVVconst, typ.UInt64)
		v4.AuxInt = int64ToAuxInt(64)
		v3.AddArg2(v4, v2)
		v.AddArg2(v0, v3)
		return true
	}
}
func rewriteValueLOONG64_OpRsh8Ux32(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Rsh8Ux32 <t> x y)
	// result: (MASKEQZ (SRLV <t> (ZeroExt8to64 x) (ZeroExt32to64 y)) (SGTU (MOVVconst <typ.UInt64> [64]) (ZeroExt32to64 y)))
	for {
		t := v.Type
		x := v_0
		y := v_1
		v.reset(OpLOONG64MASKEQZ)
		v0 := b.NewValue0(v.Pos, OpLOONG64SRLV, t)
		v1 := b.NewValue0(v.Pos, OpZeroExt8to64, typ.UInt64)
		v1.AddArg(x)
		v2 := b.NewValue0(v.Pos, OpZeroExt32to64, typ.UInt64)
		v2.AddArg(y)
		v0.AddArg2(v1, v2)
		v3 := b.NewValue0(v.Pos, OpLOONG64SGTU, typ.Bool)
		v4 := b.NewValue0(v.Pos, OpLOONG64MOVVconst, typ.UInt64)
		v4.AuxInt = int64ToAuxInt(64)
		v3.AddArg2(v4, v2)
		v.AddArg2(v0, v3)
		return true
	}
}
func rewriteValueLOONG64_OpRsh8Ux64(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Rsh8Ux64 <t> x y)
	// result: (MASKEQZ (SRLV <t> (ZeroExt8to64 x) y) (SGTU (MOVVconst <typ.UInt64> [64]) y))
	for {
		t := v.Type
		x := v_0
		y := v_1
		v.reset(OpLOONG64MASKEQZ)
		v0 := b.NewValue0(v.Pos, OpLOONG64SRLV, t)
		v1 := b.NewValue0(v.Pos, OpZeroExt8to64, typ.UInt64)
		v1.AddArg(x)
		v0.AddArg2(v1, y)
		v2 := b.NewValue0(v.Pos, OpLOONG64SGTU, typ.Bool)
		v3 := b.NewValue0(v.Pos, OpLOONG64MOVVconst, typ.UInt64)
		v3.AuxInt = int64ToAuxInt(64)
		v2.AddArg2(v3, y)
		v.AddArg2(v0, v2)
		return true
	}
}
func rewriteValueLOONG64_OpRsh8Ux8(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Rsh8Ux8 <t> x y)
	// result: (MASKEQZ (SRLV <t> (ZeroExt8to64 x) (ZeroExt8to64 y)) (SGTU (MOVVconst <typ.UInt64> [64]) (ZeroExt8to64 y)))
	for {
		t := v.Type
		x := v_0
		y := v_1
		v.reset(OpLOONG64MASKEQZ)
		v0 := b.NewValue0(v.Pos, OpLOONG64SRLV, t)
		v1 := b.NewValue0(v.Pos, OpZeroExt8to64, typ.UInt64)
		v1.AddArg(x)
		v2 := b.NewValue0(v.Pos, OpZeroExt8to64, typ.UInt64)
		v2.AddArg(y)
		v0.AddArg2(v1, v2)
		v3 := b.NewValue0(v.Pos, OpLOONG64SGTU, typ.Bool)
		v4 := b.NewValue0(v.Pos, OpLOONG64MOVVconst, typ.UInt64)
		v4.AuxInt = int64ToAuxInt(64)
		v3.AddArg2(v4, v2)
		v.AddArg2(v0, v3)
		return true
	}
}
func rewriteValueLOONG64_OpRsh8x16(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Rsh8x16 <t> x y)
	// result: (SRAV (SignExt8to64 x) (OR <t> (NEGV <t> (SGTU (ZeroExt16to64 y) (MOVVconst <typ.UInt64> [63]))) (ZeroExt16to64 y)))
	for {
		t := v.Type
		x := v_0
		y := v_1
		v.reset(OpLOONG64SRAV)
		v0 := b.NewValue0(v.Pos, OpSignExt8to64, typ.Int64)
		v0.AddArg(x)
		v1 := b.NewValue0(v.Pos, OpLOONG64OR, t)
		v2 := b.NewValue0(v.Pos, OpLOONG64NEGV, t)
		v3 := b.NewValue0(v.Pos, OpLOONG64SGTU, typ.Bool)
		v4 := b.NewValue0(v.Pos, OpZeroExt16to64, typ.UInt64)
		v4.AddArg(y)
		v5 := b.NewValue0(v.Pos, OpLOONG64MOVVconst, typ.UInt64)
		v5.AuxInt = int64ToAuxInt(63)
		v3.AddArg2(v4, v5)
		v2.AddArg(v3)
		v1.AddArg2(v2, v4)
		v.AddArg2(v0, v1)
		return true
	}
}
func rewriteValueLOONG64_OpRsh8x32(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Rsh8x32 <t> x y)
	// result: (SRAV (SignExt8to64 x) (OR <t> (NEGV <t> (SGTU (ZeroExt32to64 y) (MOVVconst <typ.UInt64> [63]))) (ZeroExt32to64 y)))
	for {
		t := v.Type
		x := v_0
		y := v_1
		v.reset(OpLOONG64SRAV)
		v0 := b.NewValue0(v.Pos, OpSignExt8to64, typ.Int64)
		v0.AddArg(x)
		v1 := b.NewValue0(v.Pos, OpLOONG64OR, t)
		v2 := b.NewValue0(v.Pos, OpLOONG64NEGV, t)
		v3 := b.NewValue0(v.Pos, OpLOONG64SGTU, typ.Bool)
		v4 := b.NewValue0(v.Pos, OpZeroExt32to64, typ.UInt64)
		v4.AddArg(y)
		v5 := b.NewValue0(v.Pos, OpLOONG64MOVVconst, typ.UInt64)
		v5.AuxInt = int64ToAuxInt(63)
		v3.AddArg2(v4, v5)
		v2.AddArg(v3)
		v1.AddArg2(v2, v4)
		v.AddArg2(v0, v1)
		return true
	}
}
func rewriteValueLOONG64_OpRsh8x64(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Rsh8x64 <t> x y)
	// result: (SRAV (SignExt8to64 x) (OR <t> (NEGV <t> (SGTU y (MOVVconst <typ.UInt64> [63]))) y))
	for {
		t := v.Type
		x := v_0
		y := v_1
		v.reset(OpLOONG64SRAV)
		v0 := b.NewValue0(v.Pos, OpSignExt8to64, typ.Int64)
		v0.AddArg(x)
		v1 := b.NewValue0(v.Pos, OpLOONG64OR, t)
		v2 := b.NewValue0(v.Pos, OpLOONG64NEGV, t)
		v3 := b.NewValue0(v.Pos, OpLOONG64SGTU, typ.Bool)
		v4 := b.NewValue0(v.Pos, OpLOONG64MOVVconst, typ.UInt64)
		v4.AuxInt = int64ToAuxInt(63)
		v3.AddArg2(y, v4)
		v2.AddArg(v3)
		v1.AddArg2(v2, y)
		v.AddArg2(v0, v1)
		return true
	}
}
func rewriteValueLOONG64_OpRsh8x8(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Rsh8x8 <t> x y)
	// result: (SRAV (SignExt8to64 x) (OR <t> (NEGV <t> (SGTU (ZeroExt8to64 y) (MOVVconst <typ.UInt64> [63]))) (ZeroExt8to64 y)))
	for {
		t := v.Type
		x := v_0
		y := v_1
		v.reset(OpLOONG64SRAV)
		v0 := b.NewValue0(v.Pos, OpSignExt8to64, typ.Int64)
		v0.AddArg(x)
		v1 := b.NewValue0(v.Pos, OpLOONG64OR, t)
		v2 := b.NewValue0(v.Pos, OpLOONG64NEGV, t)
		v3 := b.NewValue0(v.Pos, OpLOONG64SGTU, typ.Bool)
		v4 := b.NewValue0(v.Pos, OpZeroExt8to64, typ.UInt64)
		v4.AddArg(y)
		v5 := b.NewValue0(v.Pos, OpLOONG64MOVVconst, typ.UInt64)
		v5.AuxInt = int64ToAuxInt(63)
		v3.AddArg2(v4, v5)
		v2.AddArg(v3)
		v1.AddArg2(v2, v4)
		v.AddArg2(v0, v1)
		return true
	}
}
func rewriteValueLOONG64_OpSelect0(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	// match: (Select0 (Mul64uhilo x y))
	// result: (MULHVU x y)
	for {
		if v_0.Op != OpMul64uhilo {
			break
		}
		y := v_0.Args[1]
		x := v_0.Args[0]
		v.reset(OpLOONG64MULHVU)
		v.AddArg2(x, y)
		return true
	}
	// match: (Select0 (Mul64uover x y))
	// result: (MULV x y)
	for {
		if v_0.Op != OpMul64uover {
			break
		}
		y := v_0.Args[1]
		x := v_0.Args[0]
		v.reset(OpLOONG64MULV)
		v.AddArg2(x, y)
		return true
	}
	// match: (Select0 <t> (Add64carry x y c))
	// result: (ADDV (ADDV <t> x y) c)
	for {
		t := v.Type
		if v_0.Op != OpAdd64carry {
			break
		}
		c := v_0.Args[2]
		x := v_0.Args[0]
		y := v_0.Args[1]
		v.reset(OpLOONG64ADDV)
		v0 := b.NewValue0(v.Pos, OpLOONG64ADDV, t)
		v0.AddArg2(x, y)
		v.AddArg2(v0, c)
		return true
	}
	// match: (Select0 <t> (Sub64borrow x y c))
	// result: (SUBV (SUBV <t> x y) c)
	for {
		t := v.Type
		if v_0.Op != OpSub64borrow {
			break
		}
		c := v_0.Args[2]
		x := v_0.Args[0]
		y := v_0.Args[1]
		v.reset(OpLOONG64SUBV)
		v0 := b.NewValue0(v.Pos, OpLOONG64SUBV, t)
		v0.AddArg2(x, y)
		v.AddArg2(v0, c)
		return true
	}
	return false
}
func rewriteValueLOONG64_OpSelect1(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Select1 (Mul64uhilo x y))
	// result: (MULV x y)
	for {
		if v_0.Op != OpMul64uhilo {
			break
		}
		y := v_0.Args[1]
		x := v_0.Args[0]
		v.reset(OpLOONG64MULV)
		v.AddArg2(x, y)
		return true
	}
	// match: (Select1 (Mul64uover x y))
	// result: (SGTU <typ.Bool> (MULHVU x y) (MOVVconst <typ.UInt64> [0]))
	for {
		if v_0.Op != OpMul64uover {
			break
		}
		y := v_0.Args[1]
		x := v_0.Args[0]
		v.reset(OpLOONG64SGTU)
		v.Type = typ.Bool
		v0 := b.NewValue0(v.Pos, OpLOONG64MULHVU, typ.UInt64)
		v0.AddArg2(x, y)
		v1 := b.NewValue0(v.Pos, OpLOONG64MOVVconst, typ.UInt64)
		v1.AuxInt = int64ToAuxInt(0)
		v.AddArg2(v0, v1)
		return true
	}
	// match: (Select1 <t> (Add64carry x y c))
	// result: (OR (SGTU <t> x s:(ADDV <t> x y)) (SGTU <t> s (ADDV <t> s c)))
	for {
		t := v.Type
		if v_0.Op != OpAdd64carry {
			break
		}
		c := v_0.Args[2]
		x := v_0.Args[0]
		y := v_0.Args[1]
		v.reset(OpLOONG64OR)
		v0 := b.NewValue0(v.Pos, OpLOONG64SGTU, t)
		s := b.NewValue0(v.Pos, OpLOONG64ADDV, t)
		s.AddArg2(x, y)
		v0.AddArg2(x, s)
		v2 := b.NewValue0(v.Pos, OpLOONG64SGTU, t)
		v3 := b.NewValue0(v.Pos, OpLOONG64ADDV, t)
		v3.AddArg2(s, c)
		v2.AddArg2(s, v3)
		v.AddArg2(v0, v2)
		return true
	}
	// match: (Select1 <t> (Sub64borrow x y c))
	// result: (OR (SGTU <t> s:(SUBV <t> x y) x) (SGTU <t> (SUBV <t> s c) s))
	for {
		t := v.Type
		if v_0.Op != OpSub64borrow {
			break
		}
		c := v_0.Args[2]
		x := v_0.Args[0]
		y := v_0.Args[1]
		v.reset(OpLOONG64OR)
		v0 := b.NewValue0(v.Pos, OpLOONG64SGTU, t)
		s := b.NewValue0(v.Pos, OpLOONG64SUBV, t)
		s.AddArg2(x, y)
		v0.AddArg2(s, x)
		v2 := b.NewValue0(v.Pos, OpLOONG64SGTU, t)
		v3 := b.NewValue0(v.Pos, OpLOONG64SUBV, t)
		v3.AddArg2(s, c)
		v2.AddArg2(v3, s)
		v.AddArg2(v0, v2)
		return true
	}
	return false
}
func rewriteValueLOONG64_OpSelectN(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	config := b.Func.Config
	// match: (SelectN [0] call:(CALLstatic {sym} dst src (MOVVconst [sz]) mem))
	// cond: sz >= 0 && isSameCall(sym, "runtime.memmove") && call.Uses == 1 && isInlinableMemmove(dst, src, sz, config) && clobber(call)
	// result: (Move [sz] dst src mem)
	for {
		if auxIntToInt64(v.AuxInt) != 0 {
			break
		}
		call := v_0
		if call.Op != OpLOONG64CALLstatic || len(call.Args) != 4 {
			break
		}
		sym := auxToCall(call.Aux)
		mem := call.Args[3]
		dst := call.Args[0]
		src := call.Args[1]
		call_2 := call.Args[2]
		if call_2.Op != OpLOONG64MOVVconst {
			break
		}
		sz := auxIntToInt64
```