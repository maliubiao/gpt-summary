Response:
My thought process for analyzing the provided Go code snippet goes like this:

1. **Identify the Core Functionality:** The code is within a function called `rewriteValueAMD64`. The name strongly suggests it's part of a compiler optimization or code transformation phase specifically targeting the AMD64 architecture. The `rewrite` part indicates it's looking for specific patterns in the intermediate representation of the code and replacing them with more efficient or canonical forms.

2. **Recognize the Pattern Matching:** The code is structured with a series of `for { ... break }` loops, each starting with a `match:` comment. This immediately tells me it's performing pattern matching on the structure of the intermediate representation (likely an Abstract Syntax Tree or a similar graph-based representation).

3. **Understand the Goal of Each Pattern:**  Each `match:` comment describes a specific pattern of operations. The `result:` comment indicates how that pattern will be rewritten. I need to understand what each matched operation does and how the replacement is an optimization.

4. **Analyze Individual Rewrite Rules (Examples):**

   * **`SETNEstore ... TESTLconst ...` to `SETBstore ... BTLconst ...`:** This rule looks for a "Set Not Equal Store" operation based on the result of a "Test Long Constant" instruction. The rewrite replaces it with a "Set if Below Store" operation based on a "Bit Test Long Constant" instruction. This suggests that testing against a power of two can be more efficiently implemented with a bit test.

   * **`SETNEstore ... CMPLconst [1] s:(ANDLconst [1] _)` to `SETEQstore ... CMPLconst [0] s`:** This rule looks for a "Set Not Equal Store" based on comparing against 1 where the value being compared is the result of an "And Long Constant 1". It rewrites this to a "Set Equal Store" based on comparing against 0. This is because if `(x & 1) == 1`, then `(x & 1) != 0` is equivalent to `(x & 1) == 1`. The rewrite likely simplifies the comparison.

   * **`SETNEstore ... TESTQ z1:(SHLQconst [63] (SHRQconst [63] x)) z2 ...` to `SETBstore ... BTQconst [63] x`:** This rule checks if the most significant bit of `x` is set. The `SHLQconst [63]` shifts left by 63, and `SHRQconst [63]` shifts right by 63. If they are equal after the test, it means the MSB was either 0 or 1, and the test is effectively checking the MSB. The rewrite directly uses a "Bit Test Quad Constant" instruction targeting bit 63.

   * **`SETNEstore [off1] ... (ADDQconst [off2] base) ...` to `SETNEstore [off1+off2] ... base ...`:** This rule is about optimizing memory access. If the address is calculated by adding a constant to a base address, and the store operation has its own offset, these offsets can be combined.

5. **Identify Common Themes:**  Several patterns emerge:

   * **Replacing Comparisons with Bit Tests:** Optimizing comparisons against powers of two.
   * **Simplifying Logical Operations:**  Rewriting comparisons based on `AND` operations.
   * **Optimizing Memory Access:** Combining offsets in address calculations.
   * **Handling Flags:**  Rewriting stores based on flag values (like `FlagEQ`, `FlagLT_ULT`).

6. **Infer the Overall Function:** Based on the individual rewrite rules, the primary function of this code is to perform **peephole optimizations** on the SSA (Static Single Assignment) intermediate representation of Go code for the AMD64 architecture. It identifies common, less efficient patterns and replaces them with more optimal AMD64 instructions.

7. **Address Specific Questions:**

   * **Go Language Feature:** This code isn't directly implementing a specific Go language feature. Instead, it's *optimizing* the compiled output of Go code. The features involved are things like boolean expressions, comparisons, bitwise operations, and memory access.

   * **Go Code Example:** I would construct a Go example that would likely trigger some of these rewrite rules, like checking if a number is a power of two or using bitwise AND with 1 to check the least significant bit.

   * **Assumptions for Code Reasoning:** The primary assumption is that the input `v` is a node in the SSA graph representing a store operation (`SETNEstore`). The other arguments (`v_0`, `v_1`, `v_2`) are its operands. The code assumes the structure of these operands matches the patterns being checked.

   * **Command-line Arguments:** This code snippet doesn't directly process command-line arguments. It's part of the compiler's internal optimization pipeline.

   * **User Mistakes:**  Users don't directly interact with this level of compiler optimization. The compiler handles it automatically.

8. **Synthesize the Summary:**  Combine the individual observations and the inferred overall function to create a concise summary of the code's purpose. Emphasize that it's part of the compiler's optimization process for AMD64.

By following these steps, I can systematically analyze the code snippet and arrive at a comprehensive understanding of its functionality and its role within the Go compiler.
这是一个Go语言编译器的部分代码，位于 `go/src/cmd/compile/internal/ssa/rewriteAMD64.go` 文件中，专门针对 AMD64 架构进行代码优化的。这个代码片段是第15部分，很可能专注于 `SETNEstore` (Set if Not Equal and Store) 操作的重写规则。

**功能归纳:**

这段代码的主要功能是定义了一系列针对 `SETNEstore` 操作的重写规则，旨在将某些特定的 `SETNEstore` 模式转换为更高效的 AMD64 指令序列。 这些规则通过匹配 `SETNEstore` 指令的输入操作数（特别是第二个操作数，通常是条件判断的结果），然后根据匹配到的模式进行转换。 转换的目标通常是使用更底层的位操作指令或者更简洁的比较和存储指令。

**具体功能解释和Go代码示例:**

下面我们来详细解释每个匹配规则的功能，并尝试用Go代码举例说明可能触发这些规则的场景。

1. **将基于 `TESTLconst` 和 `TESTQconst` 的 `SETNEstore` 转换为基于 `BTLconst` 和 `BTQconst` 的 `SETBstore`:**

   * **功能:** 当 `SETNEstore` 的条件判断是测试一个寄存器 `x` 与一个 2 的幂次方的常量 `c` 进行 `AND` 运算的结果是否非零时，可以将其转换为直接测试 `x` 的对应位是否为 1，然后将结果 (0 或 1) 存储到内存中。
   * **原理:**  `TESTLconst c x` 实际上等价于检查 `x & c` 是否为零。如果 `c` 是 2 的幂，那么这等价于检查 `x` 的某一位是否为 1。 `BTLconst` (Bit Test Long Constant) 和 `BTQconst` (Bit Test Quad Constant) 指令可以直接测试指定位。`SETBstore` 会根据零标志位设置存储的值 (0 或 1)。
   * **Go代码示例:**
     ```go
     package main

     func main() {
         var flag bool
         var x uint32 = 4 // 二进制 0100
         const c uint32 = 4 // 2的2次方

         if x&c != 0 {
             flag = true
         } else {
             flag = false
         }

         println(flag) // 输出 true
     }
     ```
     **假设的SSA输入 (简化):**
     ```
     v1 = Load <mem>
     v2 = Const <int32> [4]
     v3 = ANDL <int32> v1 v2
     v4 = Const <int32> [0]
     v5 = CMPL v3 v4
     v6 = SETNEstore [offset] {sym} ptr v5 mem
     ```
     **优化后的SSA输出 (简化):**
     ```
     v1 = Load <mem>
     v2 = Const <int8> [2] // log32(4)
     v3 = BTLconst v2 v1
     v4 = SETBstore [offset] {sym} ptr v3 mem
     ```

2. **将基于 `TESTQ (MOVQconst [c]) x` 的 `SETNEstore` 转换为基于 `BTQconst` 的 `SETBstore`:**

   * **功能:** 类似于第一条规则，但匹配的是 `TESTQ` 指令，其一个操作数是立即数常量。
   * **Go代码示例:** 类似上面的例子，只是数据类型可能是 `uint64`。

3. **将基于 `CMPLconst [1] s:(ANDLconst [1] _)` 和 `CMPQconst [1] s:(ANDQconst [1] _)` 的 `SETNEstore` 转换为 `SETEQstore`:**

   * **功能:**  当 `SETNEstore` 的条件是比较一个与 1 进行 `AND` 运算的结果是否不等于 1 时，可以转换为比较该结果是否等于 0。
   * **原理:** `(x & 1) != 1` 等价于 `(x & 1) == 0`。
   * **Go代码示例:**
     ```go
     package main

     func main() {
         var flag bool
         var x int = 3 // 二进制 0011

         if (x & 1) != 1 {
             flag = true
         } else {
             flag = false
         }
         println(flag) // 输出 false
     }
     ```
     **假设的SSA输入 (简化):**
     ```
     v1 = Load <mem>
     v2 = Const <int32> [1]
     v3 = ANDL <int32> v1 v2
     v4 = Const <int32> [1]
     v5 = CMPL v3 v4
     v6 = SETNEstore [offset] {sym} ptr v5 mem
     ```
     **优化后的SSA输出 (简化):**
     ```
     v1 = Load <mem>
     v2 = Const <int32> [1]
     v3 = ANDL <int32> v1 v2
     v4 = Const <int32> [0]
     v5 = CMPL v3 v4
     v6 = SETEQstore [offset] {sym} ptr v5 mem
     ```

4. **将基于位移操作和 `TESTQ`/`TESTL` 的 `SETNEstore` 转换为基于 `BTQconst`/`BTLconst` 的 `SETBstore`:**

   * **功能:** 识别出检查特定位是否为 1 的模式，即使该模式通过移位操作实现。例如，检查最高位。
   * **原理:**  例如 `TESTQ z1:(SHLQconst [63] (SHRQconst [63] x)) z2`，如果 `z1 == z2`，那么这意味着 `x` 的最高位被移动到了最低位，并与自身进行比较，实际上是在检查最高位是否为 1。
   * **Go代码示例:**
     ```go
     package main

     func main() {
         var flag bool
         var x uint64 = 1 << 63 // 最高位为 1

         if (x << 63) >> 63 != 0 {
             flag = true
         } else {
             flag = false
         }
         println(flag) // 输出 true
     }
     ```

5. **将基于 `InvertFlags` 的 `SETNEstore` 简化:**

   * **功能:**  `InvertFlags` 操作会反转条件码，所以 `SETNEstore` 后面跟着 `InvertFlags` 可以直接移除 `InvertFlags`，因为 `SETNE` 本身已经包含了“不等于”的含义。

6. **合并 `ADDQconst` 或 `LEAQ` 指令的偏移量:**

   * **功能:** 如果 `SETNEstore` 的目标地址是通过 `ADDQconst` 或 `LEAQ` 指令计算出来的，并且这些指令本身带有偏移量，那么可以将这些偏移量合并到 `SETNEstore` 指令的 `AuxInt` 中。
   * **原理:** 减少指令数量，优化地址计算。
   * **Go代码示例:**
     ```go
     package main

     func main() {
         var arr [10]int
         var flag bool
         offset := 5
         value := 10

         if arr[offset] != value {
             flag = true
         } else {
             flag = false
         }
         println(flag)
     }
     ```
     **假设的SSA输入 (简化):**
     ```
     v1 = Const <intptr> [address of arr]
     v2 = Const <int64> [5]
     v3 = ADDQconst v1 v2
     v4 = Load <int> v3
     v5 = Const <int> [10]
     v6 = CMP v4 v5
     v7 = SETNEstore [0] {} v3 v6 mem
     ```
     **优化后的SSA输出 (简化):**
     ```
     v1 = Const <intptr> [address of arr]
     v2 = Const <int64> [5]
     v3 = ADDQconst v1 v2 // 可能会被优化掉
     v4 = Load <int> (address of arr + 5 * size of int)
     v5 = Const <int> [10]
     v6 = CMP v4 v5
     v7 = SETNEstore [offset_of_element_5] {} v1 v6 mem
     ```

7. **将基于标志位 (例如 `FlagEQ`, `FlagLT_ULT`) 的 `SETNEstore` 转换为 `MOVBstore` 存储 0 或 1:**

   * **功能:**  当 `SETNEstore` 的条件直接是某些标志位时，可以将其转换为直接存储 0 或 1 到内存中。
   * **原理:**  例如，如果条件是 `FlagEQ` (相等标志)，那么 `SETNEstore` 实际上是在“如果不相等则存储”，这意味着如果相等，则应该存储 0，如果不相等，则应该存储 1。这里利用了 `SETNE` 的“非”的含义。
   * **Go代码示例:** 这种模式更底层，通常不会直接在Go代码中体现，而是编译器内部对条件判断的优化。

**涉及的Go语言功能:**

这些重写规则涉及到 Go 语言的以下概念和操作：

* **比较操作:** `!=`
* **位运算:** `&`, `<<`, `>>`
* **布尔类型:** `bool`
* **条件语句:** `if...else`
* **内存访问:** 数组访问，变量赋值

**代码推理的假设输入与输出:**

在上面的每个具体功能解释中，我都尝试提供了简化的 SSA 输入和输出作为例子。  实际的 SSA 形式会更复杂，包含更多的类型信息和控制流信息。

**命令行参数的具体处理:**

这段代码本身不直接处理命令行参数。它是 Go 编译器内部优化流程的一部分。编译器的命令行参数可能会影响到优化级别，从而间接影响这些重写规则是否会被应用。 例如，`-gcflags "-N"` 可以禁用优化。

**使用者易犯错的点:**

普通 Go 开发者通常不需要直接关注这些底层的编译器优化规则。  这些是编译器自动完成的工作。  因此，不存在使用者易犯错的点。

**总结这段代码的功能:**

总而言之，这段 `rewriteAMD64.go` 代码的特定部分专注于优化 AMD64 架构下的 `SETNEstore` 指令。 它通过模式匹配，将一些常见的基于比较和逻辑运算的 `SETNEstore` 模式，转换为更有效率的位测试指令、直接的存储指令或者合并地址计算，从而提升最终生成代码的性能。 这是 Go 编译器进行低级代码优化的一个典型例子。

### 提示词
```
这是路径为go/src/cmd/compile/internal/ssa/rewriteAMD64.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第15部分，共23部分，请归纳一下它的功能
```

### 源代码
```go
h: (SETNEstore [off] {sym} ptr (TESTLconst [c] x) mem)
	// cond: isUint32PowerOfTwo(int64(c))
	// result: (SETBstore [off] {sym} ptr (BTLconst [int8(log32(c))] x) mem)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		if v_1.Op != OpAMD64TESTLconst {
			break
		}
		c := auxIntToInt32(v_1.AuxInt)
		x := v_1.Args[0]
		mem := v_2
		if !(isUint32PowerOfTwo(int64(c))) {
			break
		}
		v.reset(OpAMD64SETBstore)
		v.AuxInt = int32ToAuxInt(off)
		v.Aux = symToAux(sym)
		v0 := b.NewValue0(v.Pos, OpAMD64BTLconst, types.TypeFlags)
		v0.AuxInt = int8ToAuxInt(int8(log32(c)))
		v0.AddArg(x)
		v.AddArg3(ptr, v0, mem)
		return true
	}
	// match: (SETNEstore [off] {sym} ptr (TESTQconst [c] x) mem)
	// cond: isUint64PowerOfTwo(int64(c))
	// result: (SETBstore [off] {sym} ptr (BTQconst [int8(log32(c))] x) mem)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		if v_1.Op != OpAMD64TESTQconst {
			break
		}
		c := auxIntToInt32(v_1.AuxInt)
		x := v_1.Args[0]
		mem := v_2
		if !(isUint64PowerOfTwo(int64(c))) {
			break
		}
		v.reset(OpAMD64SETBstore)
		v.AuxInt = int32ToAuxInt(off)
		v.Aux = symToAux(sym)
		v0 := b.NewValue0(v.Pos, OpAMD64BTQconst, types.TypeFlags)
		v0.AuxInt = int8ToAuxInt(int8(log32(c)))
		v0.AddArg(x)
		v.AddArg3(ptr, v0, mem)
		return true
	}
	// match: (SETNEstore [off] {sym} ptr (TESTQ (MOVQconst [c]) x) mem)
	// cond: isUint64PowerOfTwo(c)
	// result: (SETBstore [off] {sym} ptr (BTQconst [int8(log64(c))] x) mem)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		if v_1.Op != OpAMD64TESTQ {
			break
		}
		_ = v_1.Args[1]
		v_1_0 := v_1.Args[0]
		v_1_1 := v_1.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, v_1_0, v_1_1 = _i0+1, v_1_1, v_1_0 {
			if v_1_0.Op != OpAMD64MOVQconst {
				continue
			}
			c := auxIntToInt64(v_1_0.AuxInt)
			x := v_1_1
			mem := v_2
			if !(isUint64PowerOfTwo(c)) {
				continue
			}
			v.reset(OpAMD64SETBstore)
			v.AuxInt = int32ToAuxInt(off)
			v.Aux = symToAux(sym)
			v0 := b.NewValue0(v.Pos, OpAMD64BTQconst, types.TypeFlags)
			v0.AuxInt = int8ToAuxInt(int8(log64(c)))
			v0.AddArg(x)
			v.AddArg3(ptr, v0, mem)
			return true
		}
		break
	}
	// match: (SETNEstore [off] {sym} ptr (CMPLconst [1] s:(ANDLconst [1] _)) mem)
	// result: (SETEQstore [off] {sym} ptr (CMPLconst [0] s) mem)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		if v_1.Op != OpAMD64CMPLconst || auxIntToInt32(v_1.AuxInt) != 1 {
			break
		}
		s := v_1.Args[0]
		if s.Op != OpAMD64ANDLconst || auxIntToInt32(s.AuxInt) != 1 {
			break
		}
		mem := v_2
		v.reset(OpAMD64SETEQstore)
		v.AuxInt = int32ToAuxInt(off)
		v.Aux = symToAux(sym)
		v0 := b.NewValue0(v.Pos, OpAMD64CMPLconst, types.TypeFlags)
		v0.AuxInt = int32ToAuxInt(0)
		v0.AddArg(s)
		v.AddArg3(ptr, v0, mem)
		return true
	}
	// match: (SETNEstore [off] {sym} ptr (CMPQconst [1] s:(ANDQconst [1] _)) mem)
	// result: (SETEQstore [off] {sym} ptr (CMPQconst [0] s) mem)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		if v_1.Op != OpAMD64CMPQconst || auxIntToInt32(v_1.AuxInt) != 1 {
			break
		}
		s := v_1.Args[0]
		if s.Op != OpAMD64ANDQconst || auxIntToInt32(s.AuxInt) != 1 {
			break
		}
		mem := v_2
		v.reset(OpAMD64SETEQstore)
		v.AuxInt = int32ToAuxInt(off)
		v.Aux = symToAux(sym)
		v0 := b.NewValue0(v.Pos, OpAMD64CMPQconst, types.TypeFlags)
		v0.AuxInt = int32ToAuxInt(0)
		v0.AddArg(s)
		v.AddArg3(ptr, v0, mem)
		return true
	}
	// match: (SETNEstore [off] {sym} ptr (TESTQ z1:(SHLQconst [63] (SHRQconst [63] x)) z2) mem)
	// cond: z1==z2
	// result: (SETBstore [off] {sym} ptr (BTQconst [63] x) mem)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		if v_1.Op != OpAMD64TESTQ {
			break
		}
		_ = v_1.Args[1]
		v_1_0 := v_1.Args[0]
		v_1_1 := v_1.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, v_1_0, v_1_1 = _i0+1, v_1_1, v_1_0 {
			z1 := v_1_0
			if z1.Op != OpAMD64SHLQconst || auxIntToInt8(z1.AuxInt) != 63 {
				continue
			}
			z1_0 := z1.Args[0]
			if z1_0.Op != OpAMD64SHRQconst || auxIntToInt8(z1_0.AuxInt) != 63 {
				continue
			}
			x := z1_0.Args[0]
			z2 := v_1_1
			mem := v_2
			if !(z1 == z2) {
				continue
			}
			v.reset(OpAMD64SETBstore)
			v.AuxInt = int32ToAuxInt(off)
			v.Aux = symToAux(sym)
			v0 := b.NewValue0(v.Pos, OpAMD64BTQconst, types.TypeFlags)
			v0.AuxInt = int8ToAuxInt(63)
			v0.AddArg(x)
			v.AddArg3(ptr, v0, mem)
			return true
		}
		break
	}
	// match: (SETNEstore [off] {sym} ptr (TESTL z1:(SHLLconst [31] (SHRLconst [31] x)) z2) mem)
	// cond: z1==z2
	// result: (SETBstore [off] {sym} ptr (BTLconst [31] x) mem)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		if v_1.Op != OpAMD64TESTL {
			break
		}
		_ = v_1.Args[1]
		v_1_0 := v_1.Args[0]
		v_1_1 := v_1.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, v_1_0, v_1_1 = _i0+1, v_1_1, v_1_0 {
			z1 := v_1_0
			if z1.Op != OpAMD64SHLLconst || auxIntToInt8(z1.AuxInt) != 31 {
				continue
			}
			z1_0 := z1.Args[0]
			if z1_0.Op != OpAMD64SHRLconst || auxIntToInt8(z1_0.AuxInt) != 31 {
				continue
			}
			x := z1_0.Args[0]
			z2 := v_1_1
			mem := v_2
			if !(z1 == z2) {
				continue
			}
			v.reset(OpAMD64SETBstore)
			v.AuxInt = int32ToAuxInt(off)
			v.Aux = symToAux(sym)
			v0 := b.NewValue0(v.Pos, OpAMD64BTLconst, types.TypeFlags)
			v0.AuxInt = int8ToAuxInt(31)
			v0.AddArg(x)
			v.AddArg3(ptr, v0, mem)
			return true
		}
		break
	}
	// match: (SETNEstore [off] {sym} ptr (TESTQ z1:(SHRQconst [63] (SHLQconst [63] x)) z2) mem)
	// cond: z1==z2
	// result: (SETBstore [off] {sym} ptr (BTQconst [0] x) mem)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		if v_1.Op != OpAMD64TESTQ {
			break
		}
		_ = v_1.Args[1]
		v_1_0 := v_1.Args[0]
		v_1_1 := v_1.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, v_1_0, v_1_1 = _i0+1, v_1_1, v_1_0 {
			z1 := v_1_0
			if z1.Op != OpAMD64SHRQconst || auxIntToInt8(z1.AuxInt) != 63 {
				continue
			}
			z1_0 := z1.Args[0]
			if z1_0.Op != OpAMD64SHLQconst || auxIntToInt8(z1_0.AuxInt) != 63 {
				continue
			}
			x := z1_0.Args[0]
			z2 := v_1_1
			mem := v_2
			if !(z1 == z2) {
				continue
			}
			v.reset(OpAMD64SETBstore)
			v.AuxInt = int32ToAuxInt(off)
			v.Aux = symToAux(sym)
			v0 := b.NewValue0(v.Pos, OpAMD64BTQconst, types.TypeFlags)
			v0.AuxInt = int8ToAuxInt(0)
			v0.AddArg(x)
			v.AddArg3(ptr, v0, mem)
			return true
		}
		break
	}
	// match: (SETNEstore [off] {sym} ptr (TESTL z1:(SHRLconst [31] (SHLLconst [31] x)) z2) mem)
	// cond: z1==z2
	// result: (SETBstore [off] {sym} ptr (BTLconst [0] x) mem)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		if v_1.Op != OpAMD64TESTL {
			break
		}
		_ = v_1.Args[1]
		v_1_0 := v_1.Args[0]
		v_1_1 := v_1.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, v_1_0, v_1_1 = _i0+1, v_1_1, v_1_0 {
			z1 := v_1_0
			if z1.Op != OpAMD64SHRLconst || auxIntToInt8(z1.AuxInt) != 31 {
				continue
			}
			z1_0 := z1.Args[0]
			if z1_0.Op != OpAMD64SHLLconst || auxIntToInt8(z1_0.AuxInt) != 31 {
				continue
			}
			x := z1_0.Args[0]
			z2 := v_1_1
			mem := v_2
			if !(z1 == z2) {
				continue
			}
			v.reset(OpAMD64SETBstore)
			v.AuxInt = int32ToAuxInt(off)
			v.Aux = symToAux(sym)
			v0 := b.NewValue0(v.Pos, OpAMD64BTLconst, types.TypeFlags)
			v0.AuxInt = int8ToAuxInt(0)
			v0.AddArg(x)
			v.AddArg3(ptr, v0, mem)
			return true
		}
		break
	}
	// match: (SETNEstore [off] {sym} ptr (TESTQ z1:(SHRQconst [63] x) z2) mem)
	// cond: z1==z2
	// result: (SETBstore [off] {sym} ptr (BTQconst [63] x) mem)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		if v_1.Op != OpAMD64TESTQ {
			break
		}
		_ = v_1.Args[1]
		v_1_0 := v_1.Args[0]
		v_1_1 := v_1.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, v_1_0, v_1_1 = _i0+1, v_1_1, v_1_0 {
			z1 := v_1_0
			if z1.Op != OpAMD64SHRQconst || auxIntToInt8(z1.AuxInt) != 63 {
				continue
			}
			x := z1.Args[0]
			z2 := v_1_1
			mem := v_2
			if !(z1 == z2) {
				continue
			}
			v.reset(OpAMD64SETBstore)
			v.AuxInt = int32ToAuxInt(off)
			v.Aux = symToAux(sym)
			v0 := b.NewValue0(v.Pos, OpAMD64BTQconst, types.TypeFlags)
			v0.AuxInt = int8ToAuxInt(63)
			v0.AddArg(x)
			v.AddArg3(ptr, v0, mem)
			return true
		}
		break
	}
	// match: (SETNEstore [off] {sym} ptr (TESTL z1:(SHRLconst [31] x) z2) mem)
	// cond: z1==z2
	// result: (SETBstore [off] {sym} ptr (BTLconst [31] x) mem)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		if v_1.Op != OpAMD64TESTL {
			break
		}
		_ = v_1.Args[1]
		v_1_0 := v_1.Args[0]
		v_1_1 := v_1.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, v_1_0, v_1_1 = _i0+1, v_1_1, v_1_0 {
			z1 := v_1_0
			if z1.Op != OpAMD64SHRLconst || auxIntToInt8(z1.AuxInt) != 31 {
				continue
			}
			x := z1.Args[0]
			z2 := v_1_1
			mem := v_2
			if !(z1 == z2) {
				continue
			}
			v.reset(OpAMD64SETBstore)
			v.AuxInt = int32ToAuxInt(off)
			v.Aux = symToAux(sym)
			v0 := b.NewValue0(v.Pos, OpAMD64BTLconst, types.TypeFlags)
			v0.AuxInt = int8ToAuxInt(31)
			v0.AddArg(x)
			v.AddArg3(ptr, v0, mem)
			return true
		}
		break
	}
	// match: (SETNEstore [off] {sym} ptr (InvertFlags x) mem)
	// result: (SETNEstore [off] {sym} ptr x mem)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		if v_1.Op != OpAMD64InvertFlags {
			break
		}
		x := v_1.Args[0]
		mem := v_2
		v.reset(OpAMD64SETNEstore)
		v.AuxInt = int32ToAuxInt(off)
		v.Aux = symToAux(sym)
		v.AddArg3(ptr, x, mem)
		return true
	}
	// match: (SETNEstore [off1] {sym} (ADDQconst [off2] base) val mem)
	// cond: is32Bit(int64(off1)+int64(off2))
	// result: (SETNEstore [off1+off2] {sym} base val mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		if v_0.Op != OpAMD64ADDQconst {
			break
		}
		off2 := auxIntToInt32(v_0.AuxInt)
		base := v_0.Args[0]
		val := v_1
		mem := v_2
		if !(is32Bit(int64(off1) + int64(off2))) {
			break
		}
		v.reset(OpAMD64SETNEstore)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(sym)
		v.AddArg3(base, val, mem)
		return true
	}
	// match: (SETNEstore [off1] {sym1} (LEAQ [off2] {sym2} base) val mem)
	// cond: is32Bit(int64(off1)+int64(off2)) && canMergeSym(sym1, sym2)
	// result: (SETNEstore [off1+off2] {mergeSym(sym1,sym2)} base val mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym1 := auxToSym(v.Aux)
		if v_0.Op != OpAMD64LEAQ {
			break
		}
		off2 := auxIntToInt32(v_0.AuxInt)
		sym2 := auxToSym(v_0.Aux)
		base := v_0.Args[0]
		val := v_1
		mem := v_2
		if !(is32Bit(int64(off1)+int64(off2)) && canMergeSym(sym1, sym2)) {
			break
		}
		v.reset(OpAMD64SETNEstore)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(mergeSym(sym1, sym2))
		v.AddArg3(base, val, mem)
		return true
	}
	// match: (SETNEstore [off] {sym} ptr (FlagEQ) mem)
	// result: (MOVBstore [off] {sym} ptr (MOVLconst <typ.UInt8> [0]) mem)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		if v_1.Op != OpAMD64FlagEQ {
			break
		}
		mem := v_2
		v.reset(OpAMD64MOVBstore)
		v.AuxInt = int32ToAuxInt(off)
		v.Aux = symToAux(sym)
		v0 := b.NewValue0(v.Pos, OpAMD64MOVLconst, typ.UInt8)
		v0.AuxInt = int32ToAuxInt(0)
		v.AddArg3(ptr, v0, mem)
		return true
	}
	// match: (SETNEstore [off] {sym} ptr (FlagLT_ULT) mem)
	// result: (MOVBstore [off] {sym} ptr (MOVLconst <typ.UInt8> [1]) mem)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		if v_1.Op != OpAMD64FlagLT_ULT {
			break
		}
		mem := v_2
		v.reset(OpAMD64MOVBstore)
		v.AuxInt = int32ToAuxInt(off)
		v.Aux = symToAux(sym)
		v0 := b.NewValue0(v.Pos, OpAMD64MOVLconst, typ.UInt8)
		v0.AuxInt = int32ToAuxInt(1)
		v.AddArg3(ptr, v0, mem)
		return true
	}
	// match: (SETNEstore [off] {sym} ptr (FlagLT_UGT) mem)
	// result: (MOVBstore [off] {sym} ptr (MOVLconst <typ.UInt8> [1]) mem)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		if v_1.Op != OpAMD64FlagLT_UGT {
			break
		}
		mem := v_2
		v.reset(OpAMD64MOVBstore)
		v.AuxInt = int32ToAuxInt(off)
		v.Aux = symToAux(sym)
		v0 := b.NewValue0(v.Pos, OpAMD64MOVLconst, typ.UInt8)
		v0.AuxInt = int32ToAuxInt(1)
		v.AddArg3(ptr, v0, mem)
		return true
	}
	// match: (SETNEstore [off] {sym} ptr (FlagGT_ULT) mem)
	// result: (MOVBstore [off] {sym} ptr (MOVLconst <typ.UInt8> [1]) mem)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		if v_1.Op != OpAMD64FlagGT_ULT {
			break
		}
		mem := v_2
		v.reset(OpAMD64MOVBstore)
		v.AuxInt = int32ToAuxInt(off)
		v.Aux = symToAux(sym)
		v0 := b.NewValue0(v.Pos, OpAMD64MOVLconst, typ.UInt8)
		v0.AuxInt = int32ToAuxInt(1)
		v.AddArg3(ptr, v0, mem)
		return true
	}
	// match: (SETNEstore [off] {sym} ptr (FlagGT_UGT) mem)
	// result: (MOVBstore [off] {sym} ptr (MOVLconst <typ.UInt8> [1]) mem)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		if v_1.Op != OpAMD64FlagGT_UGT {
			break
		}
		mem := v_2
		v.reset(OpAMD64MOVBstore)
		v.AuxInt = int32ToAuxInt(off)
		v.Aux = symToAux(sym)
		v0 := b.NewValue0(v.Pos, OpAMD64MOVLconst, typ.UInt8)
		v0.AuxInt = int32ToAuxInt(1)
		v.AddArg3(ptr, v0, mem)
		return true
	}
	return false
}
func rewriteValueAMD64_OpAMD64SHLL(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (SHLL x (MOVQconst [c]))
	// result: (SHLLconst [int8(c&31)] x)
	for {
		x := v_0
		if v_1.Op != OpAMD64MOVQconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		v.reset(OpAMD64SHLLconst)
		v.AuxInt = int8ToAuxInt(int8(c & 31))
		v.AddArg(x)
		return true
	}
	// match: (SHLL x (MOVLconst [c]))
	// result: (SHLLconst [int8(c&31)] x)
	for {
		x := v_0
		if v_1.Op != OpAMD64MOVLconst {
			break
		}
		c := auxIntToInt32(v_1.AuxInt)
		v.reset(OpAMD64SHLLconst)
		v.AuxInt = int8ToAuxInt(int8(c & 31))
		v.AddArg(x)
		return true
	}
	// match: (SHLL x (ADDQconst [c] y))
	// cond: c & 31 == 0
	// result: (SHLL x y)
	for {
		x := v_0
		if v_1.Op != OpAMD64ADDQconst {
			break
		}
		c := auxIntToInt32(v_1.AuxInt)
		y := v_1.Args[0]
		if !(c&31 == 0) {
			break
		}
		v.reset(OpAMD64SHLL)
		v.AddArg2(x, y)
		return true
	}
	// match: (SHLL x (NEGQ <t> (ADDQconst [c] y)))
	// cond: c & 31 == 0
	// result: (SHLL x (NEGQ <t> y))
	for {
		x := v_0
		if v_1.Op != OpAMD64NEGQ {
			break
		}
		t := v_1.Type
		v_1_0 := v_1.Args[0]
		if v_1_0.Op != OpAMD64ADDQconst {
			break
		}
		c := auxIntToInt32(v_1_0.AuxInt)
		y := v_1_0.Args[0]
		if !(c&31 == 0) {
			break
		}
		v.reset(OpAMD64SHLL)
		v0 := b.NewValue0(v.Pos, OpAMD64NEGQ, t)
		v0.AddArg(y)
		v.AddArg2(x, v0)
		return true
	}
	// match: (SHLL x (ANDQconst [c] y))
	// cond: c & 31 == 31
	// result: (SHLL x y)
	for {
		x := v_0
		if v_1.Op != OpAMD64ANDQconst {
			break
		}
		c := auxIntToInt32(v_1.AuxInt)
		y := v_1.Args[0]
		if !(c&31 == 31) {
			break
		}
		v.reset(OpAMD64SHLL)
		v.AddArg2(x, y)
		return true
	}
	// match: (SHLL x (NEGQ <t> (ANDQconst [c] y)))
	// cond: c & 31 == 31
	// result: (SHLL x (NEGQ <t> y))
	for {
		x := v_0
		if v_1.Op != OpAMD64NEGQ {
			break
		}
		t := v_1.Type
		v_1_0 := v_1.Args[0]
		if v_1_0.Op != OpAMD64ANDQconst {
			break
		}
		c := auxIntToInt32(v_1_0.AuxInt)
		y := v_1_0.Args[0]
		if !(c&31 == 31) {
			break
		}
		v.reset(OpAMD64SHLL)
		v0 := b.NewValue0(v.Pos, OpAMD64NEGQ, t)
		v0.AddArg(y)
		v.AddArg2(x, v0)
		return true
	}
	// match: (SHLL x (ADDLconst [c] y))
	// cond: c & 31 == 0
	// result: (SHLL x y)
	for {
		x := v_0
		if v_1.Op != OpAMD64ADDLconst {
			break
		}
		c := auxIntToInt32(v_1.AuxInt)
		y := v_1.Args[0]
		if !(c&31 == 0) {
			break
		}
		v.reset(OpAMD64SHLL)
		v.AddArg2(x, y)
		return true
	}
	// match: (SHLL x (NEGL <t> (ADDLconst [c] y)))
	// cond: c & 31 == 0
	// result: (SHLL x (NEGL <t> y))
	for {
		x := v_0
		if v_1.Op != OpAMD64NEGL {
			break
		}
		t := v_1.Type
		v_1_0 := v_1.Args[0]
		if v_1_0.Op != OpAMD64ADDLconst {
			break
		}
		c := auxIntToInt32(v_1_0.AuxInt)
		y := v_1_0.Args[0]
		if !(c&31 == 0) {
			break
		}
		v.reset(OpAMD64SHLL)
		v0 := b.NewValue0(v.Pos, OpAMD64NEGL, t)
		v0.AddArg(y)
		v.AddArg2(x, v0)
		return true
	}
	// match: (SHLL x (ANDLconst [c] y))
	// cond: c & 31 == 31
	// result: (SHLL x y)
	for {
		x := v_0
		if v_1.Op != OpAMD64ANDLconst {
			break
		}
		c := auxIntToInt32(v_1.AuxInt)
		y := v_1.Args[0]
		if !(c&31 == 31) {
			break
		}
		v.reset(OpAMD64SHLL)
		v.AddArg2(x, y)
		return true
	}
	// match: (SHLL x (NEGL <t> (ANDLconst [c] y)))
	// cond: c & 31 == 31
	// result: (SHLL x (NEGL <t> y))
	for {
		x := v_0
		if v_1.Op != OpAMD64NEGL {
			break
		}
		t := v_1.Type
		v_1_0 := v_1.Args[0]
		if v_1_0.Op != OpAMD64ANDLconst {
			break
		}
		c := auxIntToInt32(v_1_0.AuxInt)
		y := v_1_0.Args[0]
		if !(c&31 == 31) {
			break
		}
		v.reset(OpAMD64SHLL)
		v0 := b.NewValue0(v.Pos, OpAMD64NEGL, t)
		v0.AddArg(y)
		v.AddArg2(x, v0)
		return true
	}
	// match: (SHLL l:(MOVLload [off] {sym} ptr mem) x)
	// cond: buildcfg.GOAMD64 >= 3 && canMergeLoad(v, l) && clobber(l)
	// result: (SHLXLload [off] {sym} ptr x mem)
	for {
		l := v_0
		if l.Op != OpAMD64MOVLload {
			break
		}
		off := auxIntToInt32(l.AuxInt)
		sym := auxToSym(l.Aux)
		mem := l.Args[1]
		ptr := l.Args[0]
		x := v_1
		if !(buildcfg.GOAMD64 >= 3 && canMergeLoad(v, l) && clobber(l)) {
			break
		}
		v.reset(OpAMD64SHLXLload)
		v.AuxInt = int32ToAuxInt(off)
		v.Aux = symToAux(sym)
		v.AddArg3(ptr, x, mem)
		return true
	}
	return false
}
func rewriteValueAMD64_OpAMD64SHLLconst(v *Value) bool {
	v_0 := v.Args[0]
	// match: (SHLLconst [1] (SHRLconst [1] x))
	// result: (ANDLconst [-2] x)
	for {
		if auxIntToInt8(v.AuxInt) != 1 || v_0.Op != OpAMD64SHRLconst || auxIntToInt8(v_0.AuxInt) != 1 {
			break
		}
		x := v_0.Args[0]
		v.reset(OpAMD64ANDLconst)
		v.AuxInt = int32ToAuxInt(-2)
		v.AddArg(x)
		return true
	}
	// match: (SHLLconst x [0])
	// result: x
	for {
		if auxIntToInt8(v.AuxInt) != 0 {
			break
		}
		x := v_0
		v.copyOf(x)
		return true
	}
	// match: (SHLLconst [d] (MOVLconst [c]))
	// result: (MOVLconst [c << uint64(d)])
	for {
		d := auxIntToInt8(v.AuxInt)
		if v_0.Op != OpAMD64MOVLconst {
			break
		}
		c := auxIntToInt32(v_0.AuxInt)
		v.reset(OpAMD64MOVLconst)
		v.AuxInt = int32ToAuxInt(c << uint64(d))
		return true
	}
	return false
}
func rewriteValueAMD64_OpAMD64SHLQ(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (SHLQ x (MOVQconst [c]))
	// result: (SHLQconst [int8(c&63)] x)
	for {
		x := v_0
		if v_1.Op != OpAMD64MOVQconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		v.reset(OpAMD64SHLQconst)
		v.AuxInt = int8ToAuxInt(int8(c & 63))
		v.AddArg(x)
		return true
	}
	// match: (SHLQ x (MOVLconst [c]))
	// result: (SHLQconst [int8(c&63)] x)
	for {
		x := v_0
		if v_1.Op != OpAMD64MOVLconst {
			break
		}
		c := auxIntToInt32(v_1.AuxInt)
		v.reset(OpAMD64SHLQconst)
		v.AuxInt = int8ToAuxInt(int8(c & 63))
		v.AddArg(x)
		return true
	}
	// match: (SHLQ x (ADDQconst [c] y))
	// cond: c & 63 == 0
	// result: (SHLQ x y)
	for {
		x := v_0
		if v_1.Op != OpAMD64ADDQconst {
			break
		}
		c := auxIntToInt32(v_1.AuxInt)
		y := v_1.Args[0]
		if !(c&63 == 0) {
			break
		}
		v.reset(OpAMD64SHLQ)
		v.AddArg2(x, y)
		return true
	}
	// match: (SHLQ x (NEGQ <t> (ADDQconst [c] y)))
	// cond: c & 63 == 0
	// result: (SHLQ x (NEGQ <t> y))
	for {
		x := v_0
		if v_1.Op != OpAMD64NEGQ {
			break
		}
		t := v_1.Type
		v_1_0 := v_1.Args[0]
		if v_1_0.Op != OpAMD64ADDQconst {
			break
		}
		c := auxIntToInt32(v_1_0.AuxInt)
		y := v_1_0.Args[0]
		if !(c&63 == 0) {
			break
		}
		v.reset(OpAMD64SHLQ)
		v0 := b.NewValue0(v.Pos, OpAMD64NEGQ, t)
		v0.AddArg(y)
		v.AddArg2(x, v0)
		return true
	}
	// match: (SHLQ x (ANDQconst [c] y))
	// cond: c & 63 == 63
	// result: (SHLQ x y)
	for {
		x := v_0
		if v_1.Op != OpAMD64ANDQconst {
			break
		}
		c := auxIntToInt32(v_1.AuxInt)
		y := v_1.Args[0]
		if !(c&63 == 63) {
			break
		}
		v.reset(OpAMD64SHLQ)
		v.AddArg2(x, y)
		return true
	}
	// match: (SHLQ x (NEGQ <t> (ANDQconst [c] y)))
	// cond: c & 63 == 63
	// result: (SHLQ x (NEGQ <t> y))
	for {
		x := v_0
		if v_1.Op != OpAMD64NEGQ {
			break
		}
		t := v_1.Type
		v_1_0 := v_1.Args[0]
		if v_1_0.Op != OpAMD64ANDQconst {
			break
		}
		c := auxIntToInt32(v_1_0.AuxInt)
		y := v_1_0.Args[0]
		if !(c&63 == 63) {
			break
		}
		v.reset(OpAMD64SHLQ)
		v0 := b.NewValue0(v.Pos, OpAMD64NEGQ, t)
		v0.AddArg(y)
		v.AddArg2(x, v0)
		return true
	}
	// match: (SHLQ x (ADDLconst [c] y))
	// cond: c & 63 == 0
	// result: (SHLQ x y)
	for {
		x := v_0
		if v_1.Op != OpAMD64ADDLconst {
			break
		}
		c := auxIntToInt32(v_1.AuxInt)
		y := v_1.Args[0]
		if !(c&63 == 0) {
			break
		}
		v.reset(OpAMD64SHLQ)
		v.AddArg2(x, y)
		return true
	}
	// match: (SHLQ x (NEGL <t> (ADDLconst [c] y)))
	// cond: c & 63 == 0
	// result: (SHLQ x (NEGL <t> y))
	for {
		x := v_0
		if v_1.Op != OpAMD64NEGL {
			break
		}
		t := v_1.Type
		v_1_0 := v_1.Args[0]
		if v_1_0.Op != OpAMD64ADDLconst {
			break
		}
		c := auxIntToInt32(v_1_0.AuxInt)
		y := v_1_0.Args[0]
		if !(c&63 == 0) {
			break
		}
		v.reset(OpAMD64SHLQ)
		v0 := b.NewValue0(v.Pos, OpAMD64NEGL, t)
		v0.AddArg(y)
		v.AddArg2(x, v0)
		return true
	}
	// match: (SHLQ x (ANDLconst [c] y))
	// cond: c & 63 == 63
	// result: (SHLQ x y)
	for {
		x := v_0
		if v_1.Op != OpAMD64ANDLconst {
			break
		}
		c := auxIntToInt32(v_1.AuxInt)
		y := v_1.Args[0]
		if !(c&63 == 63) {
			break
		}
		v.reset(OpAMD64SHLQ)
		v.AddArg2(x, y)
		return true
	}
	// match: (SHLQ x (NEGL <t> (ANDLconst [c] y)))
	// cond: c & 63 == 63
	// result: (SHLQ x (NEGL <t> y))
	for {
		x := v_0
		if v_1.Op != OpAMD64NEGL {
			break
		}
		t := v_1.Type
		v_1_0 := v_1.Args[0]
		if v_1_0.Op != OpAMD64ANDLconst {
			break
		}
		c := auxIntToInt32(v_1_0.AuxInt)
		y := v_1_0.Args[0]
		if !(c&63 == 63) {
			break
		}
		v.reset(OpAMD64SHLQ)
		v0 := b.NewValue0(v.Pos, OpAMD64NEGL, t)
		v0.AddArg(y)
		v.AddArg2(x, v0)
		return true
	}
	// match: (SHLQ l:(MOVQload [off] {sym} ptr mem) x)
	// cond: buildcfg.GOAMD64 >= 3 && canMergeLoad(v, l) && clobber(l)
	// result: (SHLXQload [off] {sym} ptr x mem)
	for {
		l := v_0
		if l.Op != OpAMD64MOVQload {
			break
		}
		off := auxIntToInt32(l.AuxInt)
		sym := auxToSym(l.Aux)
		mem := l.Args[1]
		ptr := l.Args[0]
		x := v_1
		if !(buildcfg.GOAMD64 >= 3 && canMergeLoad(v, l) && clobber(l)) {
			break
		}
		v.reset(OpAMD64SHLXQload)
		v.AuxInt = int32ToAuxInt(off)
		v.Aux = symToAux(sym)
		v.AddArg3(ptr, x, mem)
		return true
	}
	return false
}
func rewriteValueAMD64_OpAMD64SHLQconst(v *Value) bool {
	v_0 := v.Args[0]
	// match: (SHLQconst [1] (SHRQconst [1] x))
	// result: (ANDQconst [-2] x)
	for {
		if auxIntToInt8(v.AuxInt) != 1 || v_0.Op != OpAMD64SHRQconst || auxIntToInt8(v_0.AuxInt) != 1 {
			break
		}
		x := v_0.Args[0]
		v.reset(OpAMD64ANDQconst)
		v.AuxInt = int32ToAuxInt(-2)
		v.AddArg(x)
		return true
	}
	// match: (SHLQconst x [0])
	// result: x
	for {
		if auxIntToInt8(v.AuxInt) != 0 {
			break
		}
		x := v_0
		v.copyOf(x)
		return true
	}
	// match: (SHLQconst [d] (MOVQconst [c]))
	// result: (MOVQconst [c << uint64(d)])
	for {
		d := auxIntToInt8(v.AuxInt)
		if v_0.Op != OpAMD64MOVQconst {
			break
		}
		c := auxIntToInt64(v_0.AuxInt)
		v.reset(OpAMD64MOVQconst)
		v.AuxInt = int64ToAuxInt(c << uint64(d))
		return true
	}
	// match: (SHLQconst [d] (MOVLconst [c]))
	// result: (MOVQconst [int64(c) << uint64(d)])
	for {
		d := auxIntToInt8(v.AuxInt)
		if v_0.Op != OpAMD64MOVLconst {
			break
		}
		c := auxIntToInt32(v_0.AuxInt)
		v.reset(OpAMD64MOVQconst)
		v.AuxInt = int64ToAuxInt(int64(c) << uint64(d))
		return true
	}
	return false
}
func rewriteValueAMD64_OpAMD64SHLXLload(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (SHLXLload [off] {sym} ptr (MOVLconst [c]) mem)
	// result: (SHLLconst [int8(c&31)] (MOVLload [off] {sym} ptr mem))
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		if v_1.Op != OpAMD64MOVLconst {
			break
		}
		c := auxIntToInt32(v_1.AuxInt)
		mem := v_2
		v.reset(OpAMD64SHLLconst)
		v.AuxInt = int8ToAuxInt(int8(c & 31))
		v0 := b.NewValue0(v.Pos, OpAMD64MOVLload, typ.UInt32)
		v0.AuxInt = int32ToAuxInt(off)
		v0.Aux = symToAux(sym)
		v0.AddArg2(ptr, mem)
		v.AddArg(v0)
		return true
	}
	return false
}
func rewriteValueAMD64_OpAMD64SHLXQload(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (SHLXQload [off] {sym} ptr (MOVQconst [c]) mem)
	// result: (SHLQconst [int8(c&63)] (MOVQload [off] {sym} ptr mem))
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		if v_1.Op != OpAMD64MOVQconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		mem := v_2
		v.reset(OpAMD64SHLQconst)
		v.AuxInt = int8ToAuxInt(int8(c & 63))
		v0 := b.NewValue0(v.Pos, OpAMD64MOVQload, typ.UInt64)
		v0.AuxInt = int32ToAuxInt(off)
		v0.Aux = symToAux(sym)
		v0.AddArg2(ptr, mem)
		v.AddArg(v0)
		return true
	}
	// match: (SHLXQload [off] {sym} ptr (MOVLconst [c]) mem)
	// result: (SHLQconst [int8(c&63)] (MOVQload [off] {sym} ptr mem))
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		if v_1.Op != OpAMD64MOVLconst {
			break
		}
		c := auxIntToInt32(v_1.AuxInt)
		mem := v_2
		v.reset(OpAMD64SHLQconst)
		v.AuxInt = int8ToAuxInt(int8(c & 63))
		v0 := b.NewValue0(v.Pos, OpAMD64MOVQload, typ.UInt64)
		v0.AuxInt = int32ToAuxInt(off)
		v0.Aux = symToAux(sym)
		v0.AddArg2(ptr, mem)
		v.AddArg(v0)
		return true
	}
	return false
}
func rewriteValueAMD64_OpAMD64SHRB(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (SHRB x (MOVQconst [c]))
	// cond: c&31 < 8
	// result: (SHRBconst [int8(c&31)] x)
	for {
		x := v_0
		if v_1.Op != OpAMD64MOVQconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		if !(c&31 < 8) {
			break
		}
		v.reset(OpAMD64SHRBconst)
		v.AuxInt = int8ToAuxInt(int8(c & 31))
		v.AddArg(x)
		return true
	}
	// match: (SHRB x (MOVLconst [c]))
	// cond: c&31 < 8
	// result: (SHRBconst [int8(c&31)] x)
	for {
		x := v_0
		if v_1.Op != OpAMD64MOVLconst {
			break
		}
		c := auxIntToInt32(v_1.AuxInt)
		if !(c&31 < 8) {
			break
		}
		v.reset(OpAMD64SHRBconst)
		v.AuxInt = int8ToAuxInt(int8(c & 31))
		v.AddArg(x)
		return true
	}
	// match: (SHRB _ (MOVQconst [c]))
	// cond: c&31 >= 8
	// result: (MOVLconst [0])
	for {
		if v_1.Op != OpAMD64MOVQconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		if !(c&31 >= 8) {
			break
		}
		v.reset(OpAMD64MOVLconst)
		v.AuxInt = int32ToAuxInt(0)
		return true
	}
	// match: (SHRB _ (MOVLconst [c]))
	// cond: c&31 >= 8
	// result: (MOVLconst [0])
	for {
		if v_1.Op != OpAMD64MOVLconst {
			break
		}
		c := auxIntToInt32(v_1.AuxInt)
		if !(c&31 >= 8) {
			break
		}
		v.reset(OpAMD64MOVLconst)
		v.AuxInt = int32ToAuxInt(0)
		return true
	}
	return false
}
func rewriteValueAMD64_OpAMD64SHRBconst(v *Value) bool {
	v_0 := v.Args[0]
	// match: (SHRBconst x [0])
	// result: x
	for {
		if auxIntToInt8(v.AuxInt) != 0 {
			break
		}
		x := v_0
		v.copyOf(x)
		return true
	}
	return false
}
func rewriteValueAMD64_OpAMD64SHRL(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (SHRL x (MOVQconst [c]))
	// result: (SHRLconst [int8(c&31)] x)
	for {
		x := v_0
		if v_1.Op != OpAMD64MOVQconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		v.reset(OpAMD64SHRLconst)
		v.AuxInt = int8ToAuxInt(int8(c & 31))
		v.AddArg(x)
		return true
	}
	// match: (SHRL x (MOVLconst [c]))
	// result: (SHRLconst [int8(c&31)] x)
	for {
		x := v_0
		if v_1.Op != OpAMD64MOVLconst {
			break
		}
		c := auxIntToInt32(v_1.AuxInt)
		v.reset(OpAMD64SHRLconst)
		v.AuxInt = int8ToAuxInt(int8(c & 31))
		v.AddArg(x)
		return true
	}
	// match: (SHRL x (ADDQconst [c] y))
	// cond: c & 31 == 0
	// result: (SHRL x y)
	for {
		x := v_0
		if v_1.Op != OpAMD64ADDQconst {
			break
		}
		c := auxIntToInt32(v_1.AuxInt)
		y := v_1.Args[0]
		if !(c&31 == 0) {
			break
		}
		v.reset(OpAMD64SHRL)
		v.AddArg2(x, y)
		return true
	}
	// match: (SHRL x (NEGQ <t> (ADDQconst [c] y)))
	// cond: c & 31 == 0
	// result: (SHRL x (NEGQ <t> y))
	for {
		x := v_0
		if v_1.Op != OpAMD64NEGQ {
			break
		}
		t := v_1.Type
		v_1_0 := v_1.Args[0]
		if v_1_0.Op != OpAMD64ADDQconst {
			break
		}
		c := auxIntToInt32(v_1_0.AuxInt)
		y := v_1_0.Args[0]
		if !(c&31 == 0) {
			break
		}
		v.reset(OpAMD64SHRL)
		v0 := b.NewValue0(v.Pos, OpAMD64NEGQ, t)
		v0.AddArg(y)
		v.AddArg2(x, v0)
		return true
	}
	// match: (SHRL x (ANDQconst [c] y))
	// cond: c & 31 == 31
	// result: (SHRL x y)
	for {
		x := v_0
		if v_1.Op != OpAMD64ANDQconst {
			break
		}
		c := auxIntToInt32(v_1.AuxInt)
		y := v_1.Args[0]
		if !(c&31 == 31) {
			break
		}
		v.reset(OpAMD64SHRL)
		v.AddArg2(x, y)
		return true
	}
	// match: (SHRL x (NEGQ <t> (ANDQconst [c] y)))
	// cond: c & 31 == 31
	// result: (SHRL x (NEGQ <t> y))
	for {
		x := v_0
		if v_1.Op != OpAMD64NEGQ {
			break
		}
		t := v_1.Type
		v_1_0 := v_1.Args[0]
		if v_1_0.Op != OpAMD64ANDQconst {
			break
		}
		c := auxIntToInt32(v_1_0.AuxInt)
		y := v_1_0.Args[0]
		if !(c&31 == 31) {
			break
		}
		v.reset(OpAMD64SHRL)
		v0 := b.NewValue0(v.Pos, OpAMD64NEGQ, t)
		v0.AddArg(y)
		v.AddArg2(x, v0)
		return true
	}
	// match: (SHRL x (ADDLconst [c] y))
	// cond: c & 31 == 0
	// result: (SHRL x y)
	for {
		x := v_0
		if v_1.Op != OpAMD64ADDLconst {
			break
		}
		c := auxIntToInt32(v_1.AuxInt)
		y := v_1.Args[0]
		if !(c&31 == 0) {
			break
		}
		v.reset(OpAMD64SHRL)
		v.AddArg2(x, y)
		return true
	}
	// match: (SHRL x (NEGL <t> (ADDLconst [c] y)))
	// cond: c & 31 == 0
	// result: (SHRL x (NEGL <t> y))
	for {
		x := v_0
		if v_1.Op != OpAMD64NEGL {
			break
		}
		t := v_1.Type
		v_1_0 := v_1.Args[0]
		if v_1_0.Op != OpAMD64ADDLconst {
			break
		}
		c := auxIntToInt32(v_1_0.AuxInt)
		y := v_1_0.Args[0]
		if !(c&31 == 0) {
			break
		}
		v.reset(OpAMD64SHRL)
		v0 := b.NewValue0(v.Pos, OpAMD64NEGL, t)
		v0.AddArg(y)
		v.AddArg2(x, v0)
		return true
	}
	// match: (SHRL x (ANDLconst [c] y))
	// cond: c & 31 == 31
	// result: (SHRL x y)
	for {
		x := v_0
		if v_1.Op != OpAMD64ANDLconst {
			break
		}
		c := auxIntToInt32(v_1.AuxInt)
		y := v_1.Args[0]
		if !(c&31 == 31) {
			break
		}
		v.reset(OpAMD64SHRL)
		v.AddArg2(x, y)
		return true
	}
	// match: (SHRL x (NEGL <t> (ANDLconst [c] y)))
	// cond: c & 31 == 31
	// result: (SHRL x (NEGL <t> y))
	for {
		x := v_0
		if v_1.Op != OpAMD64NEGL {
			break
		}
		t := v_1.Type
		v_1_0 := v_1.Args[0]
		if v_1_0.Op != OpAMD64ANDLconst {
			break
		}
		c := auxIntToInt32(v_1_0.AuxInt)
		y := v_1_0.Args[0]
		if !(c&31 == 31) {
			break
		}
		v.reset(OpAMD64SHRL)
		v0 := b.NewValue0(v.Pos, OpAMD64NEGL, t)
		v0.AddArg(y)
		v.AddArg2(x, v0)
		return true
	}
	// match: (SHRL l:(MOVLload [off] {sym} ptr mem) x)
	// cond: buildcfg.GOAMD64 >= 3 && canMergeLoad(v, l) && clobber(l)
	// result: (SHRXLload [off] {sym} ptr x mem)
	for {
		l := v_0
		if l.Op != OpAMD64MOVLload {
			break
		}
		off := auxIntToInt32(l.AuxInt)
		sym := auxToSym(l.Aux)
		mem := l.Args[1]
		ptr := l.Args[0]
		x := v_1
		if !(buildcfg.GOAMD64 >= 3 && canMergeLoad(v, l) && clobber(l)) {
			break
		}
		v.reset(OpAMD64SHRXLload)
		v.AuxInt = int32ToAuxInt(off)
		v.Aux = symToAux(sym)
		v.AddArg3(ptr, x, mem)
		return true
	}
	return false
}
func rewriteValueAMD64_OpAMD64SHRLconst(v *Value) bool {
	v_0 := v.Args[0]
	// match: (SHRLconst [1] (SHLLconst [1] x))
	// result: (ANDLconst [0x7fffffff] x)
	for {
		if auxIntToInt8(v.AuxInt) != 1 || v_0.Op != OpAMD64SHLLconst || auxIntToInt8(v_0.AuxInt) != 1 {
			break
		}
		x := v_0.Args[0]
		v.reset(OpAMD64ANDLconst)
		v.AuxInt = int32ToAuxInt(0x7fffffff)
		v.AddArg(x)
		return true
	}
	// match: (SHRLconst x [0])
	// result: x
	for {
		if auxIntToInt8(v.AuxInt) != 0 {
			break
		}
		x := v_0
		v.copyOf(x)
		return true
	}
	return false
}
func rewriteValueAMD64_OpAMD64SHRQ(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (SHRQ x (MOVQconst [c]))
	// result: (SHRQconst [int8(c&63)] x)
	for {
		x := v_0
		if v_1.Op != OpAMD64MOVQconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		v.reset(OpAMD64SHRQconst)
		v.AuxInt = int8ToAuxInt(int8(c & 63))
		v.AddArg(x)
		return true
	}
	// match: (SHRQ x (MOVLconst [c]))
	// result: (SHRQconst [int8(c&63)] x)
	for {
		x := v_0
		if v_1.Op != OpAMD64MOVLconst {
			break
		}
		c := auxIntToInt32(v_1.AuxInt)
		v.reset(OpAMD64SHRQconst)
		v.AuxInt = int8ToAuxInt(int8(c & 63))
		v.AddArg(x)
		return true
	}
	// match: (SHRQ x (ADDQconst [c] y))
	// cond: c & 63 == 0
	// result: (SHRQ x y)
	for {
		x := v_0
		if v_1.Op != OpAMD64ADDQconst {
			break
		}
		c := auxIntToInt32(v_1.AuxInt)
		y := v_1.Args[0]
		if !(c&63 == 0) {
			break
		}
		v.reset(OpAMD64SHRQ)
		v.AddArg2(x, y)
		return true
	}
	// match: (SHRQ x (NEGQ <t> (ADDQconst [c] y)))
	// cond: c & 63 == 0
	/
```