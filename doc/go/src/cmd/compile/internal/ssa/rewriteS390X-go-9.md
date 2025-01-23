Response:
Let's break down the thought process for analyzing this Go code snippet and generating the detailed explanation.

**1. Understanding the Goal:**

The core request is to analyze a specific Go file (`rewriteS390X.go`) and explain its functionality. The prompt explicitly mentions it's part of the Go compiler (`cmd/compile/internal/ssa`) and deals with rewriting SSA (Static Single Assignment) for the S390X architecture. This immediately gives us crucial context. Rewriting SSA means optimizing the intermediate representation of Go code for a specific target architecture.

**2. Initial Code Scan and Pattern Recognition:**

The code consists of a series of functions with names like `rewriteValueS390X_Op...`. This naming convention is a strong indicator of what each function does: it rewrites a specific SSA operation (`Op`) for the S390X architecture. The functions take a `*Value` as input, which represents an SSA value.

**3. Deconstructing a Single Function (e.g., `rewriteValueS390X_OpS390XSLWconst`):**

* **Name:** `rewriteValueS390X_OpS390XSLWconst` -  This tells us it's rewriting the `OpS390XSLWconst` operation. "SLW" likely refers to Shift Left Word. The "const" part suggests it involves a constant operand.
* **Input:** `v *Value` - The SSA value to be potentially rewritten.
* **Logic:** The function checks if the auxiliary integer (`v.AuxInt`) of the `SLWconst` operation is zero. If it is, it replaces the `SLWconst` operation with its first argument (`v.Args[0]`).
* **Inference:**  Shifting a value left by zero bits doesn't change the value. This rewrite is a simple optimization.

**4. Generalizing the Pattern:**

After analyzing a few functions, a clear pattern emerges:

* **Matching Specific Operations:** Each function targets a specific S390X SSA operation.
* **Analyzing Operands:** The code often examines the operands of the operation (`v.Args`) and their types (e.g., checking if an operand is a `MOVDconst`).
* **Applying Rewrite Rules:** Based on the operands, the code applies specific rewrite rules, often simplifying the operation or replacing it with a more efficient equivalent.
* **Auxiliary Information:** `v.AuxInt` and `v.Aux` are used to store additional information related to the operation (like constant values or symbols).

**5. Inferring Functionality from Operation Names:**

Based on common assembly instruction naming conventions, we can infer the purpose of many operations:

* `SLWconst`: Shift Left Word Constant
* `SRAD`: Shift Right Arithmetic Doubleword
* `SRADconst`: Shift Right Arithmetic Doubleword Constant
* `SRAW`: Shift Right Arithmetic Word
* `SRAWconst`: Shift Right Arithmetic Word Constant
* `SRD`: Shift Right Doubleword
* `SRDconst`: Shift Right Doubleword Constant
* `SRW`: Shift Right Word
* `SRWconst`: Shift Right Word Constant
* `STM2`, `STM4`, `STMG2`, `STMG4`: Store Multiple (likely words and doublewords)
* `SUB`, `SUBW`: Subtract (Doubleword and Word)
* `SUBE`: Subtract Extended (likely with carry/borrow)
* `XOR`, `XORW`: Exclusive OR (Doubleword and Word)

**6. Considering Go Language Features:**

The rewrites often involve constants and register moves. This relates to how Go compilers optimize basic arithmetic and data movement. The presence of load and store operations (`MOVDload`, `MOVWload`, `MOVDstore`) suggests that these rewrites are also related to memory access patterns.

**7. Example Generation (Mental Walkthrough):**

For a function like `rewriteValueS390X_OpS390XSLWconst`, the example is straightforward:

* **Input:** An SSA `Value` representing `SLWconst x [0]`.
* **Rewrite:** The function identifies the constant `0` and replaces the operation with just `x`.
* **Go Equivalent:** Shifting by zero is a no-op.

For more complex functions (e.g., `rewriteValueS390X_OpS390XSRAD`), the thought process is more involved:

* **Identify Patterns:** Look for common operand patterns like `SRAD x (MOVDconst [c])`.
* **Infer Optimization:**  Using a constant shift amount is often a direct instruction.
* **Consider Edge Cases:** What happens if the constant is larger than the word size? The `c & 63` suggests masking to keep the shift within bounds.
* **Look for Compound Operations:** The rewrite involving `RISBGZ` suggests optimizing combinations of rotate and mask operations.

**8. Command-Line Arguments and Common Mistakes:**

Since this code is part of the compiler's internal workings, it's unlikely to have direct command-line arguments affecting it. Common mistakes would involve misunderstanding the effects of specific S390X instructions or not considering all the possible operand combinations. However, the structure of the code (explicit matching) helps to mitigate these errors.

**9. Synthesizing the Summary:**

The final step is to summarize the overall functionality. The key points are:

* **SSA Rewriting:** The code optimizes Go's intermediate representation.
* **S390X Architecture Specific:**  The rewrites are tailored for the S390X.
* **Pattern Matching:** The code uses pattern matching to identify opportunities for optimization.
* **Instruction-Level Optimization:** The rewrites often involve replacing sequences of operations with single, more efficient instructions.
* **Constant Folding:** Many rewrites involve constants.

**10. Refinement and Language:**

Throughout the process, it's important to use clear and concise language, explaining the technical terms (like SSA) and providing illustrative examples. The use of "假设输入" and "预期输出" helps to make the examples more concrete.

By following this structured approach, we can effectively analyze and explain the functionality of this complex compiler code snippet.
这是一个Go语言编译器的代码文件，路径为 `go/src/cmd/compile/internal/ssa/rewriteS390X.go`。它的主要功能是为S390X架构**优化**和**转换**静态单赋值（SSA）形式的中间代码。

**具体功能归纳:**

这个代码片段（第10部分，共13部分）主要集中在对S390X架构的**移位操作**（Shift）和一些**存储操作**进行优化和重写。具体来说，它处理了以下几种操作码（OpCode）：

* **`OpS390XSLWconst`**:  对带立即数的左移字操作进行重写。
* **`OpS390XSRAD`**: 对算术右移双字操作进行重写。
* **`OpS390XSRADconst`**: 对带立即数的算术右移双字操作进行重写。
* **`OpS390XSRAW`**: 对算术右移字操作进行重写。
* **`OpS390XSRAWconst`**: 对带立即数的算术右移字操作进行重写。
* **`OpS390XSRD`**: 对右移双字操作进行重写。
* **`OpS390XSRDconst`**: 对带立即数的右移双字操作进行重写。
* **`OpS390XSRW`**: 对右移字操作进行重写。
* **`OpS390XSRWconst`**: 对带立即数的右移字操作进行重写。
* **`OpS390XSTM2`**: 对存储两个寄存器操作进行重写和优化。
* **`OpS390XSTMG2`**: 对存储多个通用寄存器操作进行重写和优化。
* **`OpS390XSUB`**: 对减法操作进行重写和优化。
* **`OpS390XSUBE`**: 对带借位的减法操作进行重写。
* **`OpS390XSUBW`**: 对字减法操作进行重写和优化。
* **`OpS390XSUBWconst`**: 对带立即数的字减法操作进行重写。
* **`OpS390XSUBWload`**: 对从内存加载并进行字减法操作进行重写。
* **`OpS390XSUBconst`**: 对带立即数的减法操作进行重写和优化。
* **`OpS390XSUBload`**: 对从内存加载并进行减法操作进行重写。
* **`OpS390XSumBytes2`, `OpS390XSumBytes4`, `OpS390XSumBytes8`**:  计算字节和的操作进行重写（可能是用于优化某些特定的字节操作）。
* **`OpS390XXOR`**: 对异或操作进行重写和优化。
* **`OpS390XXORW`**: 对字异或操作进行重写和优化。
* **`OpS390XXORWconst`**: 对带立即数的字异或操作进行重写。

**它是什么Go语言功能的实现 (推理并举例说明):**

这些代码片段是Go语言编译器后端的一部分，负责将Go语言的高级操作转换为更底层的、特定于S390X架构的指令。它主要关注性能优化，例如：

1. **常量折叠 (Constant Folding):**  当移位或算术运算的操作数是常量时，可以直接在编译时计算出结果，避免运行时执行。

   ```go
   // 假设输入的 SSA 代码表示 x << 0
   // rewriteValueS390X_OpS390XSLWconst 会将它优化为直接使用 x

   var x int32 = 10
   var result int32 = x << 0 // 编译器优化后，相当于 result = x
   ```

2. **强度削弱 (Strength Reduction):** 将一些开销较大的操作替换为开销较小的等价操作。虽然这个片段中没有明显的强度削弱的例子，但整个 `rewriteS390X.go` 文件中可能存在。

3. **模式匹配和指令选择 (Pattern Matching and Instruction Selection):**  识别特定的 SSA 操作模式，并将其转换为更合适的 S390X 汇编指令序列。例如，将带常量的移位操作直接映射到 S390X 的移位指令。

4. **内存操作优化:**  合并或简化内存加载和存储操作。

   ```go
   // rewriteValueS390X_OpS390XSTM2 尝试将连续的 STM2 合并为 STM4

   var arr [4]int64
   var a, b, c, d int64

   // 假设 SSA 代码中存在连续存储操作
   arr[0] = a
   arr[1] = b
   arr[2] = c
   arr[3] = d

   // 编译器可能会将前两个存储合并成一个 STM2 或 STMG2，
   // 然后 rewriteValueS390X_OpS390XSTM2 可能会将两个 STM2 合并为 STM4
   ```

**代码推理 (带假设的输入与输出):**

以 `rewriteValueS390X_OpS390XSRAD` 函数为例：

**假设输入 (SSA `Value` v):**

```
Op: OpS390XSRAD  // 算术右移双字
Args:
  0: (REG) //  假设一个寄存器值
  1: (MOVDconst) AuxInt: 3  //  一个双字常量 3
```

**预期输出 (函数返回 true，且 v 被修改为):**

```
Op: OpS390XSRADconst // 带立即数的算术右移双字
AuxInt: 3            // 常量 3
Args:
  0: (REG)          // 原始的寄存器值
```

**推理过程:**

`rewriteValueS390X_OpS390XSRAD` 函数检测到右移操作的第二个参数是一个双字常量 (`MOVDconst`)。  S390X 架构通常有直接支持带立即数的移位指令，因此将 `SRAD x (MOVDconst [c])` 转换为 `SRADconst x [c]` 是一种优化，可以直接使用带立即数的移位指令。  `c & 63` 的目的是确保移位量不会超过 63 位，这是 S390X 架构中双字移位的最大值。

**命令行参数的具体处理:**

这个代码片段本身并不直接处理命令行参数。它是Go编译器内部的一部分，由编译器驱动程序 `go` 命令调用。编译器的命令行参数（如 `-O` 优化级别）会影响到是否以及如何应用这些重写规则。更高优化级别可能会启用更多的重写规则以提高性能。

**使用者易犯错的点:**

作为编译器开发者，在编写或修改这类重写规则时，容易犯错的点包括：

1. **没有充分理解S390X指令集的特性:**  可能会错过一些可以利用的指令或特性，导致优化不足。
2. **引入错误的转换:**  编写的重写规则必须保证语义不变性，即转换后的代码必须与原始代码执行相同的操作。例如，错误的移位量计算或条件判断可能导致逻辑错误。
3. **没有考虑所有可能的输入模式:**  重写规则可能只针对特定的输入模式有效，而忽略了其他情况，导致某些情况下没有进行优化或者引入错误。
4. **性能测试不足:**  在修改重写规则后，需要进行充分的性能测试，以确保修改确实带来了性能提升，并且没有引入性能下降。

**总结一下它的功能 (针对第10部分):**

这部分 `rewriteS390X.go` 代码的主要功能是针对S390X架构，对**移位操作**和部分**存储操作**进行细致的模式匹配和优化转换。它通过识别特定的操作数模式（例如，移位量是常量），并将其转换为更高效的S390X指令，从而提升最终生成代码的性能。例如，将通用的移位操作转换为带立即数的移位操作，或者尝试合并连续的存储操作。 此外，它还包含对减法和异或等基本算术逻辑操作的优化重写。

### 提示词
```
这是路径为go/src/cmd/compile/internal/ssa/rewriteS390X.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第10部分，共13部分，请归纳一下它的功能
```

### 源代码
```go
c rewriteValueS390X_OpS390XSLWconst(v *Value) bool {
	v_0 := v.Args[0]
	// match: (SLWconst x [0])
	// result: x
	for {
		if auxIntToUint8(v.AuxInt) != 0 {
			break
		}
		x := v_0
		v.copyOf(x)
		return true
	}
	return false
}
func rewriteValueS390X_OpS390XSRAD(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (SRAD x (MOVDconst [c]))
	// result: (SRADconst x [uint8(c&63)])
	for {
		x := v_0
		if v_1.Op != OpS390XMOVDconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		v.reset(OpS390XSRADconst)
		v.AuxInt = uint8ToAuxInt(uint8(c & 63))
		v.AddArg(x)
		return true
	}
	// match: (SRAD x (RISBGZ y {r}))
	// cond: r.Amount == 0 && r.OutMask()&63 == 63
	// result: (SRAD x y)
	for {
		x := v_0
		if v_1.Op != OpS390XRISBGZ {
			break
		}
		r := auxToS390xRotateParams(v_1.Aux)
		y := v_1.Args[0]
		if !(r.Amount == 0 && r.OutMask()&63 == 63) {
			break
		}
		v.reset(OpS390XSRAD)
		v.AddArg2(x, y)
		return true
	}
	// match: (SRAD x (AND (MOVDconst [c]) y))
	// result: (SRAD x (ANDWconst <typ.UInt32> [int32(c&63)] y))
	for {
		x := v_0
		if v_1.Op != OpS390XAND {
			break
		}
		_ = v_1.Args[1]
		v_1_0 := v_1.Args[0]
		v_1_1 := v_1.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, v_1_0, v_1_1 = _i0+1, v_1_1, v_1_0 {
			if v_1_0.Op != OpS390XMOVDconst {
				continue
			}
			c := auxIntToInt64(v_1_0.AuxInt)
			y := v_1_1
			v.reset(OpS390XSRAD)
			v0 := b.NewValue0(v.Pos, OpS390XANDWconst, typ.UInt32)
			v0.AuxInt = int32ToAuxInt(int32(c & 63))
			v0.AddArg(y)
			v.AddArg2(x, v0)
			return true
		}
		break
	}
	// match: (SRAD x (ANDWconst [c] y))
	// cond: c&63 == 63
	// result: (SRAD x y)
	for {
		x := v_0
		if v_1.Op != OpS390XANDWconst {
			break
		}
		c := auxIntToInt32(v_1.AuxInt)
		y := v_1.Args[0]
		if !(c&63 == 63) {
			break
		}
		v.reset(OpS390XSRAD)
		v.AddArg2(x, y)
		return true
	}
	// match: (SRAD x (MOVWreg y))
	// result: (SRAD x y)
	for {
		x := v_0
		if v_1.Op != OpS390XMOVWreg {
			break
		}
		y := v_1.Args[0]
		v.reset(OpS390XSRAD)
		v.AddArg2(x, y)
		return true
	}
	// match: (SRAD x (MOVHreg y))
	// result: (SRAD x y)
	for {
		x := v_0
		if v_1.Op != OpS390XMOVHreg {
			break
		}
		y := v_1.Args[0]
		v.reset(OpS390XSRAD)
		v.AddArg2(x, y)
		return true
	}
	// match: (SRAD x (MOVBreg y))
	// result: (SRAD x y)
	for {
		x := v_0
		if v_1.Op != OpS390XMOVBreg {
			break
		}
		y := v_1.Args[0]
		v.reset(OpS390XSRAD)
		v.AddArg2(x, y)
		return true
	}
	// match: (SRAD x (MOVWZreg y))
	// result: (SRAD x y)
	for {
		x := v_0
		if v_1.Op != OpS390XMOVWZreg {
			break
		}
		y := v_1.Args[0]
		v.reset(OpS390XSRAD)
		v.AddArg2(x, y)
		return true
	}
	// match: (SRAD x (MOVHZreg y))
	// result: (SRAD x y)
	for {
		x := v_0
		if v_1.Op != OpS390XMOVHZreg {
			break
		}
		y := v_1.Args[0]
		v.reset(OpS390XSRAD)
		v.AddArg2(x, y)
		return true
	}
	// match: (SRAD x (MOVBZreg y))
	// result: (SRAD x y)
	for {
		x := v_0
		if v_1.Op != OpS390XMOVBZreg {
			break
		}
		y := v_1.Args[0]
		v.reset(OpS390XSRAD)
		v.AddArg2(x, y)
		return true
	}
	return false
}
func rewriteValueS390X_OpS390XSRADconst(v *Value) bool {
	v_0 := v.Args[0]
	// match: (SRADconst x [0])
	// result: x
	for {
		if auxIntToUint8(v.AuxInt) != 0 {
			break
		}
		x := v_0
		v.copyOf(x)
		return true
	}
	// match: (SRADconst [c] (MOVDconst [d]))
	// result: (MOVDconst [d>>uint64(c)])
	for {
		c := auxIntToUint8(v.AuxInt)
		if v_0.Op != OpS390XMOVDconst {
			break
		}
		d := auxIntToInt64(v_0.AuxInt)
		v.reset(OpS390XMOVDconst)
		v.AuxInt = int64ToAuxInt(d >> uint64(c))
		return true
	}
	return false
}
func rewriteValueS390X_OpS390XSRAW(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (SRAW x (MOVDconst [c]))
	// cond: c&32 == 0
	// result: (SRAWconst x [uint8(c&31)])
	for {
		x := v_0
		if v_1.Op != OpS390XMOVDconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		if !(c&32 == 0) {
			break
		}
		v.reset(OpS390XSRAWconst)
		v.AuxInt = uint8ToAuxInt(uint8(c & 31))
		v.AddArg(x)
		return true
	}
	// match: (SRAW x (MOVDconst [c]))
	// cond: c&32 != 0
	// result: (SRAWconst x [31])
	for {
		x := v_0
		if v_1.Op != OpS390XMOVDconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		if !(c&32 != 0) {
			break
		}
		v.reset(OpS390XSRAWconst)
		v.AuxInt = uint8ToAuxInt(31)
		v.AddArg(x)
		return true
	}
	// match: (SRAW x (RISBGZ y {r}))
	// cond: r.Amount == 0 && r.OutMask()&63 == 63
	// result: (SRAW x y)
	for {
		x := v_0
		if v_1.Op != OpS390XRISBGZ {
			break
		}
		r := auxToS390xRotateParams(v_1.Aux)
		y := v_1.Args[0]
		if !(r.Amount == 0 && r.OutMask()&63 == 63) {
			break
		}
		v.reset(OpS390XSRAW)
		v.AddArg2(x, y)
		return true
	}
	// match: (SRAW x (AND (MOVDconst [c]) y))
	// result: (SRAW x (ANDWconst <typ.UInt32> [int32(c&63)] y))
	for {
		x := v_0
		if v_1.Op != OpS390XAND {
			break
		}
		_ = v_1.Args[1]
		v_1_0 := v_1.Args[0]
		v_1_1 := v_1.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, v_1_0, v_1_1 = _i0+1, v_1_1, v_1_0 {
			if v_1_0.Op != OpS390XMOVDconst {
				continue
			}
			c := auxIntToInt64(v_1_0.AuxInt)
			y := v_1_1
			v.reset(OpS390XSRAW)
			v0 := b.NewValue0(v.Pos, OpS390XANDWconst, typ.UInt32)
			v0.AuxInt = int32ToAuxInt(int32(c & 63))
			v0.AddArg(y)
			v.AddArg2(x, v0)
			return true
		}
		break
	}
	// match: (SRAW x (ANDWconst [c] y))
	// cond: c&63 == 63
	// result: (SRAW x y)
	for {
		x := v_0
		if v_1.Op != OpS390XANDWconst {
			break
		}
		c := auxIntToInt32(v_1.AuxInt)
		y := v_1.Args[0]
		if !(c&63 == 63) {
			break
		}
		v.reset(OpS390XSRAW)
		v.AddArg2(x, y)
		return true
	}
	// match: (SRAW x (MOVWreg y))
	// result: (SRAW x y)
	for {
		x := v_0
		if v_1.Op != OpS390XMOVWreg {
			break
		}
		y := v_1.Args[0]
		v.reset(OpS390XSRAW)
		v.AddArg2(x, y)
		return true
	}
	// match: (SRAW x (MOVHreg y))
	// result: (SRAW x y)
	for {
		x := v_0
		if v_1.Op != OpS390XMOVHreg {
			break
		}
		y := v_1.Args[0]
		v.reset(OpS390XSRAW)
		v.AddArg2(x, y)
		return true
	}
	// match: (SRAW x (MOVBreg y))
	// result: (SRAW x y)
	for {
		x := v_0
		if v_1.Op != OpS390XMOVBreg {
			break
		}
		y := v_1.Args[0]
		v.reset(OpS390XSRAW)
		v.AddArg2(x, y)
		return true
	}
	// match: (SRAW x (MOVWZreg y))
	// result: (SRAW x y)
	for {
		x := v_0
		if v_1.Op != OpS390XMOVWZreg {
			break
		}
		y := v_1.Args[0]
		v.reset(OpS390XSRAW)
		v.AddArg2(x, y)
		return true
	}
	// match: (SRAW x (MOVHZreg y))
	// result: (SRAW x y)
	for {
		x := v_0
		if v_1.Op != OpS390XMOVHZreg {
			break
		}
		y := v_1.Args[0]
		v.reset(OpS390XSRAW)
		v.AddArg2(x, y)
		return true
	}
	// match: (SRAW x (MOVBZreg y))
	// result: (SRAW x y)
	for {
		x := v_0
		if v_1.Op != OpS390XMOVBZreg {
			break
		}
		y := v_1.Args[0]
		v.reset(OpS390XSRAW)
		v.AddArg2(x, y)
		return true
	}
	return false
}
func rewriteValueS390X_OpS390XSRAWconst(v *Value) bool {
	v_0 := v.Args[0]
	// match: (SRAWconst x [0])
	// result: x
	for {
		if auxIntToUint8(v.AuxInt) != 0 {
			break
		}
		x := v_0
		v.copyOf(x)
		return true
	}
	// match: (SRAWconst [c] (MOVDconst [d]))
	// result: (MOVDconst [int64(int32(d))>>uint64(c)])
	for {
		c := auxIntToUint8(v.AuxInt)
		if v_0.Op != OpS390XMOVDconst {
			break
		}
		d := auxIntToInt64(v_0.AuxInt)
		v.reset(OpS390XMOVDconst)
		v.AuxInt = int64ToAuxInt(int64(int32(d)) >> uint64(c))
		return true
	}
	return false
}
func rewriteValueS390X_OpS390XSRD(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (SRD x (MOVDconst [c]))
	// result: (SRDconst x [uint8(c&63)])
	for {
		x := v_0
		if v_1.Op != OpS390XMOVDconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		v.reset(OpS390XSRDconst)
		v.AuxInt = uint8ToAuxInt(uint8(c & 63))
		v.AddArg(x)
		return true
	}
	// match: (SRD x (RISBGZ y {r}))
	// cond: r.Amount == 0 && r.OutMask()&63 == 63
	// result: (SRD x y)
	for {
		x := v_0
		if v_1.Op != OpS390XRISBGZ {
			break
		}
		r := auxToS390xRotateParams(v_1.Aux)
		y := v_1.Args[0]
		if !(r.Amount == 0 && r.OutMask()&63 == 63) {
			break
		}
		v.reset(OpS390XSRD)
		v.AddArg2(x, y)
		return true
	}
	// match: (SRD x (AND (MOVDconst [c]) y))
	// result: (SRD x (ANDWconst <typ.UInt32> [int32(c&63)] y))
	for {
		x := v_0
		if v_1.Op != OpS390XAND {
			break
		}
		_ = v_1.Args[1]
		v_1_0 := v_1.Args[0]
		v_1_1 := v_1.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, v_1_0, v_1_1 = _i0+1, v_1_1, v_1_0 {
			if v_1_0.Op != OpS390XMOVDconst {
				continue
			}
			c := auxIntToInt64(v_1_0.AuxInt)
			y := v_1_1
			v.reset(OpS390XSRD)
			v0 := b.NewValue0(v.Pos, OpS390XANDWconst, typ.UInt32)
			v0.AuxInt = int32ToAuxInt(int32(c & 63))
			v0.AddArg(y)
			v.AddArg2(x, v0)
			return true
		}
		break
	}
	// match: (SRD x (ANDWconst [c] y))
	// cond: c&63 == 63
	// result: (SRD x y)
	for {
		x := v_0
		if v_1.Op != OpS390XANDWconst {
			break
		}
		c := auxIntToInt32(v_1.AuxInt)
		y := v_1.Args[0]
		if !(c&63 == 63) {
			break
		}
		v.reset(OpS390XSRD)
		v.AddArg2(x, y)
		return true
	}
	// match: (SRD x (MOVWreg y))
	// result: (SRD x y)
	for {
		x := v_0
		if v_1.Op != OpS390XMOVWreg {
			break
		}
		y := v_1.Args[0]
		v.reset(OpS390XSRD)
		v.AddArg2(x, y)
		return true
	}
	// match: (SRD x (MOVHreg y))
	// result: (SRD x y)
	for {
		x := v_0
		if v_1.Op != OpS390XMOVHreg {
			break
		}
		y := v_1.Args[0]
		v.reset(OpS390XSRD)
		v.AddArg2(x, y)
		return true
	}
	// match: (SRD x (MOVBreg y))
	// result: (SRD x y)
	for {
		x := v_0
		if v_1.Op != OpS390XMOVBreg {
			break
		}
		y := v_1.Args[0]
		v.reset(OpS390XSRD)
		v.AddArg2(x, y)
		return true
	}
	// match: (SRD x (MOVWZreg y))
	// result: (SRD x y)
	for {
		x := v_0
		if v_1.Op != OpS390XMOVWZreg {
			break
		}
		y := v_1.Args[0]
		v.reset(OpS390XSRD)
		v.AddArg2(x, y)
		return true
	}
	// match: (SRD x (MOVHZreg y))
	// result: (SRD x y)
	for {
		x := v_0
		if v_1.Op != OpS390XMOVHZreg {
			break
		}
		y := v_1.Args[0]
		v.reset(OpS390XSRD)
		v.AddArg2(x, y)
		return true
	}
	// match: (SRD x (MOVBZreg y))
	// result: (SRD x y)
	for {
		x := v_0
		if v_1.Op != OpS390XMOVBZreg {
			break
		}
		y := v_1.Args[0]
		v.reset(OpS390XSRD)
		v.AddArg2(x, y)
		return true
	}
	return false
}
func rewriteValueS390X_OpS390XSRDconst(v *Value) bool {
	v_0 := v.Args[0]
	// match: (SRDconst (SLDconst x [c]) [d])
	// result: (RISBGZ x {s390x.NewRotateParams(d, uint8(min(63, int8(63-c+d))), uint8(int8(c-d)&63))})
	for {
		d := auxIntToUint8(v.AuxInt)
		if v_0.Op != OpS390XSLDconst {
			break
		}
		c := auxIntToUint8(v_0.AuxInt)
		x := v_0.Args[0]
		v.reset(OpS390XRISBGZ)
		v.Aux = s390xRotateParamsToAux(s390x.NewRotateParams(d, uint8(min(63, int8(63-c+d))), uint8(int8(c-d)&63)))
		v.AddArg(x)
		return true
	}
	// match: (SRDconst (RISBGZ x {r}) [c])
	// cond: s390x.NewRotateParams(c, 63, -c&63).InMerge(r.OutMask()) != nil
	// result: (RISBGZ x {(*s390x.NewRotateParams(c, 63, -c&63).InMerge(r.OutMask())).RotateLeft(r.Amount)})
	for {
		c := auxIntToUint8(v.AuxInt)
		if v_0.Op != OpS390XRISBGZ {
			break
		}
		r := auxToS390xRotateParams(v_0.Aux)
		x := v_0.Args[0]
		if !(s390x.NewRotateParams(c, 63, -c&63).InMerge(r.OutMask()) != nil) {
			break
		}
		v.reset(OpS390XRISBGZ)
		v.Aux = s390xRotateParamsToAux((*s390x.NewRotateParams(c, 63, -c&63).InMerge(r.OutMask())).RotateLeft(r.Amount))
		v.AddArg(x)
		return true
	}
	// match: (SRDconst x [0])
	// result: x
	for {
		if auxIntToUint8(v.AuxInt) != 0 {
			break
		}
		x := v_0
		v.copyOf(x)
		return true
	}
	return false
}
func rewriteValueS390X_OpS390XSRW(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (SRW x (MOVDconst [c]))
	// cond: c&32 == 0
	// result: (SRWconst x [uint8(c&31)])
	for {
		x := v_0
		if v_1.Op != OpS390XMOVDconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		if !(c&32 == 0) {
			break
		}
		v.reset(OpS390XSRWconst)
		v.AuxInt = uint8ToAuxInt(uint8(c & 31))
		v.AddArg(x)
		return true
	}
	// match: (SRW _ (MOVDconst [c]))
	// cond: c&32 != 0
	// result: (MOVDconst [0])
	for {
		if v_1.Op != OpS390XMOVDconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		if !(c&32 != 0) {
			break
		}
		v.reset(OpS390XMOVDconst)
		v.AuxInt = int64ToAuxInt(0)
		return true
	}
	// match: (SRW x (RISBGZ y {r}))
	// cond: r.Amount == 0 && r.OutMask()&63 == 63
	// result: (SRW x y)
	for {
		x := v_0
		if v_1.Op != OpS390XRISBGZ {
			break
		}
		r := auxToS390xRotateParams(v_1.Aux)
		y := v_1.Args[0]
		if !(r.Amount == 0 && r.OutMask()&63 == 63) {
			break
		}
		v.reset(OpS390XSRW)
		v.AddArg2(x, y)
		return true
	}
	// match: (SRW x (AND (MOVDconst [c]) y))
	// result: (SRW x (ANDWconst <typ.UInt32> [int32(c&63)] y))
	for {
		x := v_0
		if v_1.Op != OpS390XAND {
			break
		}
		_ = v_1.Args[1]
		v_1_0 := v_1.Args[0]
		v_1_1 := v_1.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, v_1_0, v_1_1 = _i0+1, v_1_1, v_1_0 {
			if v_1_0.Op != OpS390XMOVDconst {
				continue
			}
			c := auxIntToInt64(v_1_0.AuxInt)
			y := v_1_1
			v.reset(OpS390XSRW)
			v0 := b.NewValue0(v.Pos, OpS390XANDWconst, typ.UInt32)
			v0.AuxInt = int32ToAuxInt(int32(c & 63))
			v0.AddArg(y)
			v.AddArg2(x, v0)
			return true
		}
		break
	}
	// match: (SRW x (ANDWconst [c] y))
	// cond: c&63 == 63
	// result: (SRW x y)
	for {
		x := v_0
		if v_1.Op != OpS390XANDWconst {
			break
		}
		c := auxIntToInt32(v_1.AuxInt)
		y := v_1.Args[0]
		if !(c&63 == 63) {
			break
		}
		v.reset(OpS390XSRW)
		v.AddArg2(x, y)
		return true
	}
	// match: (SRW x (MOVWreg y))
	// result: (SRW x y)
	for {
		x := v_0
		if v_1.Op != OpS390XMOVWreg {
			break
		}
		y := v_1.Args[0]
		v.reset(OpS390XSRW)
		v.AddArg2(x, y)
		return true
	}
	// match: (SRW x (MOVHreg y))
	// result: (SRW x y)
	for {
		x := v_0
		if v_1.Op != OpS390XMOVHreg {
			break
		}
		y := v_1.Args[0]
		v.reset(OpS390XSRW)
		v.AddArg2(x, y)
		return true
	}
	// match: (SRW x (MOVBreg y))
	// result: (SRW x y)
	for {
		x := v_0
		if v_1.Op != OpS390XMOVBreg {
			break
		}
		y := v_1.Args[0]
		v.reset(OpS390XSRW)
		v.AddArg2(x, y)
		return true
	}
	// match: (SRW x (MOVWZreg y))
	// result: (SRW x y)
	for {
		x := v_0
		if v_1.Op != OpS390XMOVWZreg {
			break
		}
		y := v_1.Args[0]
		v.reset(OpS390XSRW)
		v.AddArg2(x, y)
		return true
	}
	// match: (SRW x (MOVHZreg y))
	// result: (SRW x y)
	for {
		x := v_0
		if v_1.Op != OpS390XMOVHZreg {
			break
		}
		y := v_1.Args[0]
		v.reset(OpS390XSRW)
		v.AddArg2(x, y)
		return true
	}
	// match: (SRW x (MOVBZreg y))
	// result: (SRW x y)
	for {
		x := v_0
		if v_1.Op != OpS390XMOVBZreg {
			break
		}
		y := v_1.Args[0]
		v.reset(OpS390XSRW)
		v.AddArg2(x, y)
		return true
	}
	return false
}
func rewriteValueS390X_OpS390XSRWconst(v *Value) bool {
	v_0 := v.Args[0]
	// match: (SRWconst x [0])
	// result: x
	for {
		if auxIntToUint8(v.AuxInt) != 0 {
			break
		}
		x := v_0
		v.copyOf(x)
		return true
	}
	return false
}
func rewriteValueS390X_OpS390XSTM2(v *Value) bool {
	v_3 := v.Args[3]
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (STM2 [i] {s} p w2 w3 x:(STM2 [i-8] {s} p w0 w1 mem))
	// cond: x.Uses == 1 && is20Bit(int64(i)-8) && setPos(v, x.Pos) && clobber(x)
	// result: (STM4 [i-8] {s} p w0 w1 w2 w3 mem)
	for {
		i := auxIntToInt32(v.AuxInt)
		s := auxToSym(v.Aux)
		p := v_0
		w2 := v_1
		w3 := v_2
		x := v_3
		if x.Op != OpS390XSTM2 || auxIntToInt32(x.AuxInt) != i-8 || auxToSym(x.Aux) != s {
			break
		}
		mem := x.Args[3]
		if p != x.Args[0] {
			break
		}
		w0 := x.Args[1]
		w1 := x.Args[2]
		if !(x.Uses == 1 && is20Bit(int64(i)-8) && setPos(v, x.Pos) && clobber(x)) {
			break
		}
		v.reset(OpS390XSTM4)
		v.AuxInt = int32ToAuxInt(i - 8)
		v.Aux = symToAux(s)
		v.AddArg6(p, w0, w1, w2, w3, mem)
		return true
	}
	// match: (STM2 [i] {s} p (SRDconst [32] x) x mem)
	// result: (MOVDstore [i] {s} p x mem)
	for {
		i := auxIntToInt32(v.AuxInt)
		s := auxToSym(v.Aux)
		p := v_0
		if v_1.Op != OpS390XSRDconst || auxIntToUint8(v_1.AuxInt) != 32 {
			break
		}
		x := v_1.Args[0]
		if x != v_2 {
			break
		}
		mem := v_3
		v.reset(OpS390XMOVDstore)
		v.AuxInt = int32ToAuxInt(i)
		v.Aux = symToAux(s)
		v.AddArg3(p, x, mem)
		return true
	}
	return false
}
func rewriteValueS390X_OpS390XSTMG2(v *Value) bool {
	v_3 := v.Args[3]
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (STMG2 [i] {s} p w2 w3 x:(STMG2 [i-16] {s} p w0 w1 mem))
	// cond: x.Uses == 1 && is20Bit(int64(i)-16) && setPos(v, x.Pos) && clobber(x)
	// result: (STMG4 [i-16] {s} p w0 w1 w2 w3 mem)
	for {
		i := auxIntToInt32(v.AuxInt)
		s := auxToSym(v.Aux)
		p := v_0
		w2 := v_1
		w3 := v_2
		x := v_3
		if x.Op != OpS390XSTMG2 || auxIntToInt32(x.AuxInt) != i-16 || auxToSym(x.Aux) != s {
			break
		}
		mem := x.Args[3]
		if p != x.Args[0] {
			break
		}
		w0 := x.Args[1]
		w1 := x.Args[2]
		if !(x.Uses == 1 && is20Bit(int64(i)-16) && setPos(v, x.Pos) && clobber(x)) {
			break
		}
		v.reset(OpS390XSTMG4)
		v.AuxInt = int32ToAuxInt(i - 16)
		v.Aux = symToAux(s)
		v.AddArg6(p, w0, w1, w2, w3, mem)
		return true
	}
	return false
}
func rewriteValueS390X_OpS390XSUB(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (SUB x (MOVDconst [c]))
	// cond: is32Bit(c)
	// result: (SUBconst x [int32(c)])
	for {
		x := v_0
		if v_1.Op != OpS390XMOVDconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		if !(is32Bit(c)) {
			break
		}
		v.reset(OpS390XSUBconst)
		v.AuxInt = int32ToAuxInt(int32(c))
		v.AddArg(x)
		return true
	}
	// match: (SUB (MOVDconst [c]) x)
	// cond: is32Bit(c)
	// result: (NEG (SUBconst <v.Type> x [int32(c)]))
	for {
		if v_0.Op != OpS390XMOVDconst {
			break
		}
		c := auxIntToInt64(v_0.AuxInt)
		x := v_1
		if !(is32Bit(c)) {
			break
		}
		v.reset(OpS390XNEG)
		v0 := b.NewValue0(v.Pos, OpS390XSUBconst, v.Type)
		v0.AuxInt = int32ToAuxInt(int32(c))
		v0.AddArg(x)
		v.AddArg(v0)
		return true
	}
	// match: (SUB x x)
	// result: (MOVDconst [0])
	for {
		x := v_0
		if x != v_1 {
			break
		}
		v.reset(OpS390XMOVDconst)
		v.AuxInt = int64ToAuxInt(0)
		return true
	}
	// match: (SUB <t> x g:(MOVDload [off] {sym} ptr mem))
	// cond: ptr.Op != OpSB && is20Bit(int64(off)) && canMergeLoadClobber(v, g, x) && clobber(g)
	// result: (SUBload <t> [off] {sym} x ptr mem)
	for {
		t := v.Type
		x := v_0
		g := v_1
		if g.Op != OpS390XMOVDload {
			break
		}
		off := auxIntToInt32(g.AuxInt)
		sym := auxToSym(g.Aux)
		mem := g.Args[1]
		ptr := g.Args[0]
		if !(ptr.Op != OpSB && is20Bit(int64(off)) && canMergeLoadClobber(v, g, x) && clobber(g)) {
			break
		}
		v.reset(OpS390XSUBload)
		v.Type = t
		v.AuxInt = int32ToAuxInt(off)
		v.Aux = symToAux(sym)
		v.AddArg3(x, ptr, mem)
		return true
	}
	return false
}
func rewriteValueS390X_OpS390XSUBE(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (SUBE x y (FlagGT))
	// result: (SUBC x y)
	for {
		x := v_0
		y := v_1
		if v_2.Op != OpS390XFlagGT {
			break
		}
		v.reset(OpS390XSUBC)
		v.AddArg2(x, y)
		return true
	}
	// match: (SUBE x y (FlagOV))
	// result: (SUBC x y)
	for {
		x := v_0
		y := v_1
		if v_2.Op != OpS390XFlagOV {
			break
		}
		v.reset(OpS390XSUBC)
		v.AddArg2(x, y)
		return true
	}
	// match: (SUBE x y (Select1 (SUBC (MOVDconst [0]) (NEG (Select0 (SUBE (MOVDconst [0]) (MOVDconst [0]) c))))))
	// result: (SUBE x y c)
	for {
		x := v_0
		y := v_1
		if v_2.Op != OpSelect1 {
			break
		}
		v_2_0 := v_2.Args[0]
		if v_2_0.Op != OpS390XSUBC {
			break
		}
		_ = v_2_0.Args[1]
		v_2_0_0 := v_2_0.Args[0]
		if v_2_0_0.Op != OpS390XMOVDconst || auxIntToInt64(v_2_0_0.AuxInt) != 0 {
			break
		}
		v_2_0_1 := v_2_0.Args[1]
		if v_2_0_1.Op != OpS390XNEG {
			break
		}
		v_2_0_1_0 := v_2_0_1.Args[0]
		if v_2_0_1_0.Op != OpSelect0 {
			break
		}
		v_2_0_1_0_0 := v_2_0_1_0.Args[0]
		if v_2_0_1_0_0.Op != OpS390XSUBE {
			break
		}
		c := v_2_0_1_0_0.Args[2]
		v_2_0_1_0_0_0 := v_2_0_1_0_0.Args[0]
		if v_2_0_1_0_0_0.Op != OpS390XMOVDconst || auxIntToInt64(v_2_0_1_0_0_0.AuxInt) != 0 {
			break
		}
		v_2_0_1_0_0_1 := v_2_0_1_0_0.Args[1]
		if v_2_0_1_0_0_1.Op != OpS390XMOVDconst || auxIntToInt64(v_2_0_1_0_0_1.AuxInt) != 0 {
			break
		}
		v.reset(OpS390XSUBE)
		v.AddArg3(x, y, c)
		return true
	}
	return false
}
func rewriteValueS390X_OpS390XSUBW(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (SUBW x (MOVDconst [c]))
	// result: (SUBWconst x [int32(c)])
	for {
		x := v_0
		if v_1.Op != OpS390XMOVDconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		v.reset(OpS390XSUBWconst)
		v.AuxInt = int32ToAuxInt(int32(c))
		v.AddArg(x)
		return true
	}
	// match: (SUBW (MOVDconst [c]) x)
	// result: (NEGW (SUBWconst <v.Type> x [int32(c)]))
	for {
		if v_0.Op != OpS390XMOVDconst {
			break
		}
		c := auxIntToInt64(v_0.AuxInt)
		x := v_1
		v.reset(OpS390XNEGW)
		v0 := b.NewValue0(v.Pos, OpS390XSUBWconst, v.Type)
		v0.AuxInt = int32ToAuxInt(int32(c))
		v0.AddArg(x)
		v.AddArg(v0)
		return true
	}
	// match: (SUBW x x)
	// result: (MOVDconst [0])
	for {
		x := v_0
		if x != v_1 {
			break
		}
		v.reset(OpS390XMOVDconst)
		v.AuxInt = int64ToAuxInt(0)
		return true
	}
	// match: (SUBW <t> x g:(MOVWload [off] {sym} ptr mem))
	// cond: ptr.Op != OpSB && is20Bit(int64(off)) && canMergeLoadClobber(v, g, x) && clobber(g)
	// result: (SUBWload <t> [off] {sym} x ptr mem)
	for {
		t := v.Type
		x := v_0
		g := v_1
		if g.Op != OpS390XMOVWload {
			break
		}
		off := auxIntToInt32(g.AuxInt)
		sym := auxToSym(g.Aux)
		mem := g.Args[1]
		ptr := g.Args[0]
		if !(ptr.Op != OpSB && is20Bit(int64(off)) && canMergeLoadClobber(v, g, x) && clobber(g)) {
			break
		}
		v.reset(OpS390XSUBWload)
		v.Type = t
		v.AuxInt = int32ToAuxInt(off)
		v.Aux = symToAux(sym)
		v.AddArg3(x, ptr, mem)
		return true
	}
	// match: (SUBW <t> x g:(MOVWZload [off] {sym} ptr mem))
	// cond: ptr.Op != OpSB && is20Bit(int64(off)) && canMergeLoadClobber(v, g, x) && clobber(g)
	// result: (SUBWload <t> [off] {sym} x ptr mem)
	for {
		t := v.Type
		x := v_0
		g := v_1
		if g.Op != OpS390XMOVWZload {
			break
		}
		off := auxIntToInt32(g.AuxInt)
		sym := auxToSym(g.Aux)
		mem := g.Args[1]
		ptr := g.Args[0]
		if !(ptr.Op != OpSB && is20Bit(int64(off)) && canMergeLoadClobber(v, g, x) && clobber(g)) {
			break
		}
		v.reset(OpS390XSUBWload)
		v.Type = t
		v.AuxInt = int32ToAuxInt(off)
		v.Aux = symToAux(sym)
		v.AddArg3(x, ptr, mem)
		return true
	}
	return false
}
func rewriteValueS390X_OpS390XSUBWconst(v *Value) bool {
	v_0 := v.Args[0]
	// match: (SUBWconst [c] x)
	// cond: int32(c) == 0
	// result: x
	for {
		c := auxIntToInt32(v.AuxInt)
		x := v_0
		if !(int32(c) == 0) {
			break
		}
		v.copyOf(x)
		return true
	}
	// match: (SUBWconst [c] x)
	// result: (ADDWconst [-int32(c)] x)
	for {
		c := auxIntToInt32(v.AuxInt)
		x := v_0
		v.reset(OpS390XADDWconst)
		v.AuxInt = int32ToAuxInt(-int32(c))
		v.AddArg(x)
		return true
	}
}
func rewriteValueS390X_OpS390XSUBWload(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (SUBWload [off1] {sym} x (ADDconst [off2] ptr) mem)
	// cond: ptr.Op != OpSB && is20Bit(int64(off1)+int64(off2))
	// result: (SUBWload [off1+off2] {sym} x ptr mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		x := v_0
		if v_1.Op != OpS390XADDconst {
			break
		}
		off2 := auxIntToInt32(v_1.AuxInt)
		ptr := v_1.Args[0]
		mem := v_2
		if !(ptr.Op != OpSB && is20Bit(int64(off1)+int64(off2))) {
			break
		}
		v.reset(OpS390XSUBWload)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(sym)
		v.AddArg3(x, ptr, mem)
		return true
	}
	// match: (SUBWload [o1] {s1} x (MOVDaddr [o2] {s2} ptr) mem)
	// cond: ptr.Op != OpSB && is20Bit(int64(o1)+int64(o2)) && canMergeSym(s1, s2)
	// result: (SUBWload [o1+o2] {mergeSym(s1, s2)} x ptr mem)
	for {
		o1 := auxIntToInt32(v.AuxInt)
		s1 := auxToSym(v.Aux)
		x := v_0
		if v_1.Op != OpS390XMOVDaddr {
			break
		}
		o2 := auxIntToInt32(v_1.AuxInt)
		s2 := auxToSym(v_1.Aux)
		ptr := v_1.Args[0]
		mem := v_2
		if !(ptr.Op != OpSB && is20Bit(int64(o1)+int64(o2)) && canMergeSym(s1, s2)) {
			break
		}
		v.reset(OpS390XSUBWload)
		v.AuxInt = int32ToAuxInt(o1 + o2)
		v.Aux = symToAux(mergeSym(s1, s2))
		v.AddArg3(x, ptr, mem)
		return true
	}
	return false
}
func rewriteValueS390X_OpS390XSUBconst(v *Value) bool {
	v_0 := v.Args[0]
	// match: (SUBconst [0] x)
	// result: x
	for {
		if auxIntToInt32(v.AuxInt) != 0 {
			break
		}
		x := v_0
		v.copyOf(x)
		return true
	}
	// match: (SUBconst [c] x)
	// cond: c != -(1<<31)
	// result: (ADDconst [-c] x)
	for {
		c := auxIntToInt32(v.AuxInt)
		x := v_0
		if !(c != -(1 << 31)) {
			break
		}
		v.reset(OpS390XADDconst)
		v.AuxInt = int32ToAuxInt(-c)
		v.AddArg(x)
		return true
	}
	// match: (SUBconst (MOVDconst [d]) [c])
	// result: (MOVDconst [d-int64(c)])
	for {
		c := auxIntToInt32(v.AuxInt)
		if v_0.Op != OpS390XMOVDconst {
			break
		}
		d := auxIntToInt64(v_0.AuxInt)
		v.reset(OpS390XMOVDconst)
		v.AuxInt = int64ToAuxInt(d - int64(c))
		return true
	}
	// match: (SUBconst (SUBconst x [d]) [c])
	// cond: is32Bit(-int64(c)-int64(d))
	// result: (ADDconst [-c-d] x)
	for {
		c := auxIntToInt32(v.AuxInt)
		if v_0.Op != OpS390XSUBconst {
			break
		}
		d := auxIntToInt32(v_0.AuxInt)
		x := v_0.Args[0]
		if !(is32Bit(-int64(c) - int64(d))) {
			break
		}
		v.reset(OpS390XADDconst)
		v.AuxInt = int32ToAuxInt(-c - d)
		v.AddArg(x)
		return true
	}
	return false
}
func rewriteValueS390X_OpS390XSUBload(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (SUBload <t> [off] {sym} x ptr1 (FMOVDstore [off] {sym} ptr2 y _))
	// cond: isSamePtr(ptr1, ptr2)
	// result: (SUB x (LGDR <t> y))
	for {
		t := v.Type
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		x := v_0
		ptr1 := v_1
		if v_2.Op != OpS390XFMOVDstore || auxIntToInt32(v_2.AuxInt) != off || auxToSym(v_2.Aux) != sym {
			break
		}
		y := v_2.Args[1]
		ptr2 := v_2.Args[0]
		if !(isSamePtr(ptr1, ptr2)) {
			break
		}
		v.reset(OpS390XSUB)
		v0 := b.NewValue0(v_2.Pos, OpS390XLGDR, t)
		v0.AddArg(y)
		v.AddArg2(x, v0)
		return true
	}
	// match: (SUBload [off1] {sym} x (ADDconst [off2] ptr) mem)
	// cond: ptr.Op != OpSB && is20Bit(int64(off1)+int64(off2))
	// result: (SUBload [off1+off2] {sym} x ptr mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		x := v_0
		if v_1.Op != OpS390XADDconst {
			break
		}
		off2 := auxIntToInt32(v_1.AuxInt)
		ptr := v_1.Args[0]
		mem := v_2
		if !(ptr.Op != OpSB && is20Bit(int64(off1)+int64(off2))) {
			break
		}
		v.reset(OpS390XSUBload)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(sym)
		v.AddArg3(x, ptr, mem)
		return true
	}
	// match: (SUBload [o1] {s1} x (MOVDaddr [o2] {s2} ptr) mem)
	// cond: ptr.Op != OpSB && is20Bit(int64(o1)+int64(o2)) && canMergeSym(s1, s2)
	// result: (SUBload [o1+o2] {mergeSym(s1, s2)} x ptr mem)
	for {
		o1 := auxIntToInt32(v.AuxInt)
		s1 := auxToSym(v.Aux)
		x := v_0
		if v_1.Op != OpS390XMOVDaddr {
			break
		}
		o2 := auxIntToInt32(v_1.AuxInt)
		s2 := auxToSym(v_1.Aux)
		ptr := v_1.Args[0]
		mem := v_2
		if !(ptr.Op != OpSB && is20Bit(int64(o1)+int64(o2)) && canMergeSym(s1, s2)) {
			break
		}
		v.reset(OpS390XSUBload)
		v.AuxInt = int32ToAuxInt(o1 + o2)
		v.Aux = symToAux(mergeSym(s1, s2))
		v.AddArg3(x, ptr, mem)
		return true
	}
	return false
}
func rewriteValueS390X_OpS390XSumBytes2(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (SumBytes2 x)
	// result: (ADDW (SRWconst <typ.UInt8> x [8]) x)
	for {
		x := v_0
		v.reset(OpS390XADDW)
		v0 := b.NewValue0(v.Pos, OpS390XSRWconst, typ.UInt8)
		v0.AuxInt = uint8ToAuxInt(8)
		v0.AddArg(x)
		v.AddArg2(v0, x)
		return true
	}
}
func rewriteValueS390X_OpS390XSumBytes4(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (SumBytes4 x)
	// result: (SumBytes2 (ADDW <typ.UInt16> (SRWconst <typ.UInt16> x [16]) x))
	for {
		x := v_0
		v.reset(OpS390XSumBytes2)
		v0 := b.NewValue0(v.Pos, OpS390XADDW, typ.UInt16)
		v1 := b.NewValue0(v.Pos, OpS390XSRWconst, typ.UInt16)
		v1.AuxInt = uint8ToAuxInt(16)
		v1.AddArg(x)
		v0.AddArg2(v1, x)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueS390X_OpS390XSumBytes8(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (SumBytes8 x)
	// result: (SumBytes4 (ADDW <typ.UInt32> (SRDconst <typ.UInt32> x [32]) x))
	for {
		x := v_0
		v.reset(OpS390XSumBytes4)
		v0 := b.NewValue0(v.Pos, OpS390XADDW, typ.UInt32)
		v1 := b.NewValue0(v.Pos, OpS390XSRDconst, typ.UInt32)
		v1.AuxInt = uint8ToAuxInt(32)
		v1.AddArg(x)
		v0.AddArg2(v1, x)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueS390X_OpS390XXOR(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (XOR x (MOVDconst [c]))
	// cond: isU32Bit(c)
	// result: (XORconst [c] x)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			if v_1.Op != OpS390XMOVDconst {
				continue
			}
			c := auxIntToInt64(v_1.AuxInt)
			if !(isU32Bit(c)) {
				continue
			}
			v.reset(OpS390XXORconst)
			v.AuxInt = int64ToAuxInt(c)
			v.AddArg(x)
			return true
		}
		break
	}
	// match: (XOR (MOVDconst [c]) (MOVDconst [d]))
	// result: (MOVDconst [c^d])
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpS390XMOVDconst {
				continue
			}
			c := auxIntToInt64(v_0.AuxInt)
			if v_1.Op != OpS390XMOVDconst {
				continue
			}
			d := auxIntToInt64(v_1.AuxInt)
			v.reset(OpS390XMOVDconst)
			v.AuxInt = int64ToAuxInt(c ^ d)
			return true
		}
		break
	}
	// match: (XOR x x)
	// result: (MOVDconst [0])
	for {
		x := v_0
		if x != v_1 {
			break
		}
		v.reset(OpS390XMOVDconst)
		v.AuxInt = int64ToAuxInt(0)
		return true
	}
	// match: (XOR <t> x g:(MOVDload [off] {sym} ptr mem))
	// cond: ptr.Op != OpSB && is20Bit(int64(off)) && canMergeLoadClobber(v, g, x) && clobber(g)
	// result: (XORload <t> [off] {sym} x ptr mem)
	for {
		t := v.Type
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			g := v_1
			if g.Op != OpS390XMOVDload {
				continue
			}
			off := auxIntToInt32(g.AuxInt)
			sym := auxToSym(g.Aux)
			mem := g.Args[1]
			ptr := g.Args[0]
			if !(ptr.Op != OpSB && is20Bit(int64(off)) && canMergeLoadClobber(v, g, x) && clobber(g)) {
				continue
			}
			v.reset(OpS390XXORload)
			v.Type = t
			v.AuxInt = int32ToAuxInt(off)
			v.Aux = symToAux(sym)
			v.AddArg3(x, ptr, mem)
			return true
		}
		break
	}
	return false
}
func rewriteValueS390X_OpS390XXORW(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (XORW x (MOVDconst [c]))
	// result: (XORWconst [int32(c)] x)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			if v_1.Op != OpS390XMOVDconst {
				continue
			}
			c := auxIntToInt64(v_1.AuxInt)
			v.reset(OpS390XXORWconst)
			v.AuxInt = int32ToAuxInt(int32(c))
			v.AddArg(x)
			return true
		}
		break
	}
	// match: (XORW x x)
	// result: (MOVDconst [0])
	for {
		x := v_0
		if x != v_1 {
			break
		}
		v.reset(OpS390XMOVDconst)
		v.AuxInt = int64ToAuxInt(0)
		return true
	}
	// match: (XORW <t> x g:(MOVWload [off] {sym} ptr mem))
	// cond: ptr.Op != OpSB && is20Bit(int64(off)) && canMergeLoadClobber(v, g, x) && clobber(g)
	// result: (XORWload <t> [off] {sym} x ptr mem)
	for {
		t := v.Type
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			g := v_1
			if g.Op != OpS390XMOVWload {
				continue
			}
			off := auxIntToInt32(g.AuxInt)
			sym := auxToSym(g.Aux)
			mem := g.Args[1]
			ptr := g.Args[0]
			if !(ptr.Op != OpSB && is20Bit(int64(off)) && canMergeLoadClobber(v, g, x) && clobber(g)) {
				continue
			}
			v.reset(OpS390XXORWload)
			v.Type = t
			v.AuxInt = int32ToAuxInt(off)
			v.Aux = symToAux(sym)
			v.AddArg3(x, ptr, mem)
			return true
		}
		break
	}
	// match: (XORW <t> x g:(MOVWZload [off] {sym} ptr mem))
	// cond: ptr.Op != OpSB && is20Bit(int64(off)) && canMergeLoadClobber(v, g, x) && clobber(g)
	// result: (XORWload <t> [off] {sym} x ptr mem)
	for {
		t := v.Type
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			g := v_1
			if g.Op != OpS390XMOVWZload {
				continue
			}
			off := auxIntToInt32(g.AuxInt)
			sym := auxToSym(g.Aux)
			mem := g.Args[1]
			ptr := g.Args[0]
			if !(ptr.Op != OpSB && is20Bit(int64(off)) && canMergeLoadClobber(v, g, x) && clobber(g)) {
				continue
			}
			v.reset(OpS390XXORWload)
			v.Type = t
			v.AuxInt = int32ToAuxInt(off)
			v.Aux = symToAux(sym)
			v.AddArg3(x, ptr, mem)
			return true
		}
		break
	}
	return false
}
func rewriteValueS390X_OpS390XXORWconst(v *Value) bool {
	v_0 := v.Args[0]
	// match: (XORWconst [c] x)
	// cond: int32(c)==0
	// result: x
	for {
		c := auxIntToInt32(v.AuxInt)
		x := v_0
		if !(int32(c) == 0) {
			break
		}
		v.copyOf(x)
		return true
	}
	// match: (XORWconst [c] (MOVDconst [d]))
	// result: (MOVDconst [int64(c)^d])
	for {
		c := auxIntToInt32(v.AuxInt)
		if v_0.Op != OpS390XMOVDconst {
			break
		}
		d := auxIntToInt64(v_0.Au
```