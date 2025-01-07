Response:
The user wants to understand the functionality of the provided Go code snippet, which is a part of the `rewritegeneric.go` file in the Go compiler. This file seems to be responsible for applying optimization rules during the SSA (Static Single Assignment) phase of compilation.

The code consists of several functions named `rewriteValuegeneric_Op...` and `rewriteBlockgeneric`. These functions appear to implement specific rewrite rules for different SSA operations (like `OpXor64`, `OpZero`, `OpIf`). Each function checks for specific patterns in the SSA representation and transforms them into more efficient equivalents.

To address the user's request, I need to:

1. **List the functions' functionalities:** Describe what each function does in terms of SSA optimization.
2. **Provide examples:** For interesting or non-trivial optimizations, show a before-and-after Go code example and the corresponding SSA transformation (input and output).
3. **Explain code reasoning:** If a function implements a complex optimization, explain the logic behind it.
4. **Address command-line arguments:**  The provided snippet doesn't seem to directly handle command-line arguments. I should state this explicitly.
5. **Highlight common mistakes:** Analyze the optimization rules to identify potential pitfalls for developers (though this seems more relevant for code *generation* than *rewriting*). If there are no obvious pitfalls, I should say so.
6. **Summarize the overall functionality:** Provide a concise overview of what this part of the `rewritegeneric.go` file achieves.

Let's break down the individual functions:

*   `rewriteValuegeneric_OpXor64`: Handles optimizations for the XOR operation on 64-bit integers. It looks for patterns involving shifts and constants that can be rewritten as rotate operations.
*   `rewriteValuegeneric_OpXor8`:  Similar to `OpXor64`, but for 8-bit integers. It includes optimizations for constants, identities, and rotate operations.
*   `rewriteValuegeneric_OpZero`: Deals with the `Zero` operation, likely used for zeroing memory. It looks for opportunities to eliminate redundant zeroing or move operations.
*   `rewriteValuegeneric_OpZeroExt...`: Handles zero extension operations for different bit sizes. It optimizes cases involving constants and right shifts.
*   `rewriteBlockgeneric`: Applies rewrite rules to control flow blocks, specifically `BlockIf`. It optimizes `if` statements based on the condition.

Now, I'll formulate the answer based on this analysis.
这是 `go/src/cmd/compile/internal/ssa/rewritegeneric.go` 文件中关于 SSA 优化的第 26 部分，也是最后一部分。 从代码来看，这部分主要定义了一些通用的 SSA 重写规则，用于在编译器的 SSA 中间表示阶段进行优化。这些规则针对特定的操作码 (Opcode) 和代码模式进行匹配，并将它们转换为更高效或更简洁的形式。

以下是代码中各个函数的功能：

**1. `rewriteValuegeneric_OpXor64(v *Value) bool`**

*   **功能:**  优化 64 位整数的异或 (`Xor64`) 操作。
*   **具体优化:**
    *   将两个常量异或直接计算出结果常量。
    *   将自身与自身异或替换为常量 0。
    *   将常量 0 与任何值异或替换为该值本身。
    *   将所有位都为 1 的常量 (-1) 与任何值异或替换为该值的按位取反 (`Com64`)。
    *   将 `x ^ (x ^ y)` 替换为 `y`。
    *   调整嵌套异或操作的顺序，以便常量能够被合并。
    *   识别左移和右移的特定模式，并将其转换为循环移位 (`RotateLeft64`) 操作，例如将 `(x << y) ^ (x >> (64 - y))` 优化为 `RotateLeft64(x, y)`。

**Go 代码示例 (RotateLeft64 优化):**

```go
package main

func rotate(x uint64, y uint32) uint64 {
	return (x << y) | (x >> (64 - y))
}

func main() {
	a := uint64(0b1010000000000000000000000000000000000000000000000000000000000000)
	b := uint32(2)
	result := rotate(a, b)
	println(result) // Output: 43690
}
```

**假设的 SSA 输入 (`rotate` 函数内部):**

```
v1 = Param: x (uint64)
v2 = Param: y (uint32)
v3 = Lsh64x32 v1 v2
v4 = Sub32Const <uint32> [64] v2
v5 = Conv32to64 v4
v6 = Rsh64Ux64 v1 v5
v7 = Or64 v3 v6
Ret v7
```

**假设的 SSA 输出 (经过 `rewriteValuegeneric_OpXor64` 优化后):**  （这里 `rewriteValuegeneric_OpXor64` 没有直接处理 `Or64`，但类似的逻辑会应用到 `Xor64` 上，目的是识别循环移位模式）

```
v1 = Param: x (uint64)
v2 = Param: y (uint32)
v3 = RotateLeft64 v1 v2
Ret v3
```

**2. `rewriteValuegeneric_OpXor8(v *Value) bool`**

*   **功能:**  优化 8 位整数的异或 (`Xor8`) 操作，逻辑与 `rewriteValuegeneric_OpXor64` 类似，只是操作数是 8 位。
*   **具体优化:** 包括常量异或、自身异或、与 0 异或、与 -1 异或以及循环移位 (`RotateLeft8`) 的识别和优化。

**3. `rewriteValuegeneric_OpZero(v *Value) bool`**

*   **功能:**  优化内存清零 (`Zero`) 操作。
*   **具体优化:**
    *   当分配新对象并立即清零时，可以将清零操作优化掉。
    *   如果一个 `Zero` 操作紧跟着对同一内存区域的 `Store` 操作，并且 `Store` 操作覆盖了整个清零区域，可以移除 `Zero` 操作。
    *   如果一个 `Zero` 操作紧跟着对同一内存区域的 `Move` 操作，可以移除 `Zero` 操作。
    *   如果一个 `Zero` 操作紧跟着一个 `VarDef` 包含对同一内存区域的 `Move` 操作，可以优化掉 `Move` 操作。
    *   移除冗余的连续 `Zero` 操作。

**4. `rewriteValuegeneric_OpZeroExt16to32(v *Value) bool`**, **`rewriteValuegeneric_OpZeroExt16to64(v *Value) bool`**, **`rewriteValuegeneric_OpZeroExt32to64(v *Value) bool`**, **`rewriteValuegeneric_OpZeroExt8to16(v *Value) bool`**, **`rewriteValuegeneric_OpZeroExt8to32(v *Value) bool`**, **`rewriteValuegeneric_OpZeroExt8to64(v *Value) bool`**

*   **功能:**  优化零扩展操作 (`ZeroExt`)，将较小的整数类型零扩展到较大的整数类型。
*   **具体优化:**
    *   将常量零扩展直接计算出结果常量。
    *   如果零扩展的操作数是通过右移后再截断得到的，并且右移的位数足够大，可以直接使用右移前的原始值，避免截断和扩展。

**Go 代码示例 (ZeroExt 优化):**

```go
package main

func extend(x uint32) uint64 {
	return uint64(uint32(x >> 32)) // 理论上 x >> 32 会被优化掉
}

func main() {
	a := uint64(0xFFFFFFFF00000000)
	result := extend(uint32(a))
	println(result)
}
```

**假设的 SSA 输入 ( `extend` 函数内部):**

```
v1 = Param: x (uint32)
v2 = Conv32to64 v1
v3 = Rsh64Ux64 v2 (Const64 <uint64> [32])
v4 = Trunc64to32 v3
v5 = ZeroExt32to64 v4
Ret v5
```

**假设的 SSA 输出 (经过 `rewriteValuegeneric_OpZeroExt32to64` 优化后):**

```
v1 = Param: x (uint32)
v2 = Conv32to64 v1
Ret v2
```

**5. `rewriteBlockgeneric(b *Block) bool`**

*   **功能:**  优化控制流块 (`Block`)，这里主要针对 `If` 类型的块。
*   **具体优化:**
    *   将条件为 `!(cond)` 的 `If` 块转换为条件为 `cond`，并交换 `yes` 和 `no` 分支。
    *   如果 `If` 块的条件是常量 `true`，则直接跳转到 `yes` 分支。
    *   如果 `If` 块的条件是常量 `false`，则直接跳转到 `no` 分支。

**命令行参数:**

这段代码本身不直接处理命令行参数。 这些是编译器内部的优化规则，在编译过程中自动应用。

**使用者易犯错的点:**

作为编译器开发者，在编写或修改这些重写规则时，容易犯以下错误：

*   **模式匹配错误:**  编写的匹配条件不够精确，导致错误的优化或无法匹配应该优化的代码。
*   **条件判断错误:**  `cond` 中的条件判断不正确，导致在不应该优化的情况下进行了优化。
*   **引入死循环:**  重写规则如果设计不当，可能导致 SSA 图的无限循环重写。
*   **破坏 SSA 属性:**  重写规则必须保证转换后的代码仍然满足 SSA 的特性。

**总结 `rewritegeneric.go` 的功能 (到目前为止):**

到第 26 部分为止，`go/src/cmd/compile/internal/ssa/rewritegeneric.go` 文件的功能是定义了一系列通用的、与特定架构无关的 SSA 重写规则。这些规则旨在通过模式匹配和转换，优化各种 SSA 操作，例如算术运算（加、减、异或等）、位运算（移位、取反等）、内存操作（清零、移动等）和控制流。 这些优化旨在提高生成代码的性能和效率。

Prompt: 
```
这是路径为go/src/cmd/compile/internal/ssa/rewritegeneric.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第26部分，共26部分，请归纳一下它的功能

"""
(shiftIsBounded(left) || shiftIsBounded(right)) && canRotate(config, 64)
	// result: (RotateLeft64 x y)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			left := v_0
			if left.Op != OpLsh64x32 {
				continue
			}
			y := left.Args[1]
			x := left.Args[0]
			right := v_1
			if right.Op != OpRsh64Ux32 {
				continue
			}
			_ = right.Args[1]
			if x != right.Args[0] {
				continue
			}
			right_1 := right.Args[1]
			if right_1.Op != OpSub32 {
				continue
			}
			_ = right_1.Args[1]
			right_1_0 := right_1.Args[0]
			if right_1_0.Op != OpConst32 || auxIntToInt32(right_1_0.AuxInt) != 64 || y != right_1.Args[1] || !((shiftIsBounded(left) || shiftIsBounded(right)) && canRotate(config, 64)) {
				continue
			}
			v.reset(OpRotateLeft64)
			v.AddArg2(x, y)
			return true
		}
		break
	}
	// match: (Xor64 left:(Lsh64x16 x y) right:(Rsh64Ux16 x (Sub16 (Const16 [64]) y)))
	// cond: (shiftIsBounded(left) || shiftIsBounded(right)) && canRotate(config, 64)
	// result: (RotateLeft64 x y)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			left := v_0
			if left.Op != OpLsh64x16 {
				continue
			}
			y := left.Args[1]
			x := left.Args[0]
			right := v_1
			if right.Op != OpRsh64Ux16 {
				continue
			}
			_ = right.Args[1]
			if x != right.Args[0] {
				continue
			}
			right_1 := right.Args[1]
			if right_1.Op != OpSub16 {
				continue
			}
			_ = right_1.Args[1]
			right_1_0 := right_1.Args[0]
			if right_1_0.Op != OpConst16 || auxIntToInt16(right_1_0.AuxInt) != 64 || y != right_1.Args[1] || !((shiftIsBounded(left) || shiftIsBounded(right)) && canRotate(config, 64)) {
				continue
			}
			v.reset(OpRotateLeft64)
			v.AddArg2(x, y)
			return true
		}
		break
	}
	// match: (Xor64 left:(Lsh64x8 x y) right:(Rsh64Ux8 x (Sub8 (Const8 [64]) y)))
	// cond: (shiftIsBounded(left) || shiftIsBounded(right)) && canRotate(config, 64)
	// result: (RotateLeft64 x y)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			left := v_0
			if left.Op != OpLsh64x8 {
				continue
			}
			y := left.Args[1]
			x := left.Args[0]
			right := v_1
			if right.Op != OpRsh64Ux8 {
				continue
			}
			_ = right.Args[1]
			if x != right.Args[0] {
				continue
			}
			right_1 := right.Args[1]
			if right_1.Op != OpSub8 {
				continue
			}
			_ = right_1.Args[1]
			right_1_0 := right_1.Args[0]
			if right_1_0.Op != OpConst8 || auxIntToInt8(right_1_0.AuxInt) != 64 || y != right_1.Args[1] || !((shiftIsBounded(left) || shiftIsBounded(right)) && canRotate(config, 64)) {
				continue
			}
			v.reset(OpRotateLeft64)
			v.AddArg2(x, y)
			return true
		}
		break
	}
	// match: (Xor64 right:(Rsh64Ux64 x y) left:(Lsh64x64 x z:(Sub64 (Const64 [64]) y)))
	// cond: (shiftIsBounded(left) || shiftIsBounded(right)) && canRotate(config, 64)
	// result: (RotateLeft64 x z)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			right := v_0
			if right.Op != OpRsh64Ux64 {
				continue
			}
			y := right.Args[1]
			x := right.Args[0]
			left := v_1
			if left.Op != OpLsh64x64 {
				continue
			}
			_ = left.Args[1]
			if x != left.Args[0] {
				continue
			}
			z := left.Args[1]
			if z.Op != OpSub64 {
				continue
			}
			_ = z.Args[1]
			z_0 := z.Args[0]
			if z_0.Op != OpConst64 || auxIntToInt64(z_0.AuxInt) != 64 || y != z.Args[1] || !((shiftIsBounded(left) || shiftIsBounded(right)) && canRotate(config, 64)) {
				continue
			}
			v.reset(OpRotateLeft64)
			v.AddArg2(x, z)
			return true
		}
		break
	}
	// match: (Xor64 right:(Rsh64Ux32 x y) left:(Lsh64x32 x z:(Sub32 (Const32 [64]) y)))
	// cond: (shiftIsBounded(left) || shiftIsBounded(right)) && canRotate(config, 64)
	// result: (RotateLeft64 x z)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			right := v_0
			if right.Op != OpRsh64Ux32 {
				continue
			}
			y := right.Args[1]
			x := right.Args[0]
			left := v_1
			if left.Op != OpLsh64x32 {
				continue
			}
			_ = left.Args[1]
			if x != left.Args[0] {
				continue
			}
			z := left.Args[1]
			if z.Op != OpSub32 {
				continue
			}
			_ = z.Args[1]
			z_0 := z.Args[0]
			if z_0.Op != OpConst32 || auxIntToInt32(z_0.AuxInt) != 64 || y != z.Args[1] || !((shiftIsBounded(left) || shiftIsBounded(right)) && canRotate(config, 64)) {
				continue
			}
			v.reset(OpRotateLeft64)
			v.AddArg2(x, z)
			return true
		}
		break
	}
	// match: (Xor64 right:(Rsh64Ux16 x y) left:(Lsh64x16 x z:(Sub16 (Const16 [64]) y)))
	// cond: (shiftIsBounded(left) || shiftIsBounded(right)) && canRotate(config, 64)
	// result: (RotateLeft64 x z)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			right := v_0
			if right.Op != OpRsh64Ux16 {
				continue
			}
			y := right.Args[1]
			x := right.Args[0]
			left := v_1
			if left.Op != OpLsh64x16 {
				continue
			}
			_ = left.Args[1]
			if x != left.Args[0] {
				continue
			}
			z := left.Args[1]
			if z.Op != OpSub16 {
				continue
			}
			_ = z.Args[1]
			z_0 := z.Args[0]
			if z_0.Op != OpConst16 || auxIntToInt16(z_0.AuxInt) != 64 || y != z.Args[1] || !((shiftIsBounded(left) || shiftIsBounded(right)) && canRotate(config, 64)) {
				continue
			}
			v.reset(OpRotateLeft64)
			v.AddArg2(x, z)
			return true
		}
		break
	}
	// match: (Xor64 right:(Rsh64Ux8 x y) left:(Lsh64x8 x z:(Sub8 (Const8 [64]) y)))
	// cond: (shiftIsBounded(left) || shiftIsBounded(right)) && canRotate(config, 64)
	// result: (RotateLeft64 x z)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			right := v_0
			if right.Op != OpRsh64Ux8 {
				continue
			}
			y := right.Args[1]
			x := right.Args[0]
			left := v_1
			if left.Op != OpLsh64x8 {
				continue
			}
			_ = left.Args[1]
			if x != left.Args[0] {
				continue
			}
			z := left.Args[1]
			if z.Op != OpSub8 {
				continue
			}
			_ = z.Args[1]
			z_0 := z.Args[0]
			if z_0.Op != OpConst8 || auxIntToInt8(z_0.AuxInt) != 64 || y != z.Args[1] || !((shiftIsBounded(left) || shiftIsBounded(right)) && canRotate(config, 64)) {
				continue
			}
			v.reset(OpRotateLeft64)
			v.AddArg2(x, z)
			return true
		}
		break
	}
	return false
}
func rewriteValuegeneric_OpXor8(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	config := b.Func.Config
	// match: (Xor8 (Const8 [c]) (Const8 [d]))
	// result: (Const8 [c^d])
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpConst8 {
				continue
			}
			c := auxIntToInt8(v_0.AuxInt)
			if v_1.Op != OpConst8 {
				continue
			}
			d := auxIntToInt8(v_1.AuxInt)
			v.reset(OpConst8)
			v.AuxInt = int8ToAuxInt(c ^ d)
			return true
		}
		break
	}
	// match: (Xor8 x x)
	// result: (Const8 [0])
	for {
		x := v_0
		if x != v_1 {
			break
		}
		v.reset(OpConst8)
		v.AuxInt = int8ToAuxInt(0)
		return true
	}
	// match: (Xor8 (Const8 [0]) x)
	// result: x
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpConst8 || auxIntToInt8(v_0.AuxInt) != 0 {
				continue
			}
			x := v_1
			v.copyOf(x)
			return true
		}
		break
	}
	// match: (Xor8 (Com8 x) x)
	// result: (Const8 [-1])
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpCom8 {
				continue
			}
			x := v_0.Args[0]
			if x != v_1 {
				continue
			}
			v.reset(OpConst8)
			v.AuxInt = int8ToAuxInt(-1)
			return true
		}
		break
	}
	// match: (Xor8 (Const8 [-1]) x)
	// result: (Com8 x)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpConst8 || auxIntToInt8(v_0.AuxInt) != -1 {
				continue
			}
			x := v_1
			v.reset(OpCom8)
			v.AddArg(x)
			return true
		}
		break
	}
	// match: (Xor8 x (Xor8 x y))
	// result: y
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			if v_1.Op != OpXor8 {
				continue
			}
			_ = v_1.Args[1]
			v_1_0 := v_1.Args[0]
			v_1_1 := v_1.Args[1]
			for _i1 := 0; _i1 <= 1; _i1, v_1_0, v_1_1 = _i1+1, v_1_1, v_1_0 {
				if x != v_1_0 {
					continue
				}
				y := v_1_1
				v.copyOf(y)
				return true
			}
		}
		break
	}
	// match: (Xor8 (Xor8 i:(Const8 <t>) z) x)
	// cond: (z.Op != OpConst8 && x.Op != OpConst8)
	// result: (Xor8 i (Xor8 <t> z x))
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpXor8 {
				continue
			}
			_ = v_0.Args[1]
			v_0_0 := v_0.Args[0]
			v_0_1 := v_0.Args[1]
			for _i1 := 0; _i1 <= 1; _i1, v_0_0, v_0_1 = _i1+1, v_0_1, v_0_0 {
				i := v_0_0
				if i.Op != OpConst8 {
					continue
				}
				t := i.Type
				z := v_0_1
				x := v_1
				if !(z.Op != OpConst8 && x.Op != OpConst8) {
					continue
				}
				v.reset(OpXor8)
				v0 := b.NewValue0(v.Pos, OpXor8, t)
				v0.AddArg2(z, x)
				v.AddArg2(i, v0)
				return true
			}
		}
		break
	}
	// match: (Xor8 (Const8 <t> [c]) (Xor8 (Const8 <t> [d]) x))
	// result: (Xor8 (Const8 <t> [c^d]) x)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpConst8 {
				continue
			}
			t := v_0.Type
			c := auxIntToInt8(v_0.AuxInt)
			if v_1.Op != OpXor8 {
				continue
			}
			_ = v_1.Args[1]
			v_1_0 := v_1.Args[0]
			v_1_1 := v_1.Args[1]
			for _i1 := 0; _i1 <= 1; _i1, v_1_0, v_1_1 = _i1+1, v_1_1, v_1_0 {
				if v_1_0.Op != OpConst8 || v_1_0.Type != t {
					continue
				}
				d := auxIntToInt8(v_1_0.AuxInt)
				x := v_1_1
				v.reset(OpXor8)
				v0 := b.NewValue0(v.Pos, OpConst8, t)
				v0.AuxInt = int8ToAuxInt(c ^ d)
				v.AddArg2(v0, x)
				return true
			}
		}
		break
	}
	// match: (Xor8 (Lsh8x64 x z:(Const64 <t> [c])) (Rsh8Ux64 x (Const64 [d])))
	// cond: c < 8 && d == 8-c && canRotate(config, 8)
	// result: (RotateLeft8 x z)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpLsh8x64 {
				continue
			}
			_ = v_0.Args[1]
			x := v_0.Args[0]
			z := v_0.Args[1]
			if z.Op != OpConst64 {
				continue
			}
			c := auxIntToInt64(z.AuxInt)
			if v_1.Op != OpRsh8Ux64 {
				continue
			}
			_ = v_1.Args[1]
			if x != v_1.Args[0] {
				continue
			}
			v_1_1 := v_1.Args[1]
			if v_1_1.Op != OpConst64 {
				continue
			}
			d := auxIntToInt64(v_1_1.AuxInt)
			if !(c < 8 && d == 8-c && canRotate(config, 8)) {
				continue
			}
			v.reset(OpRotateLeft8)
			v.AddArg2(x, z)
			return true
		}
		break
	}
	// match: (Xor8 left:(Lsh8x64 x y) right:(Rsh8Ux64 x (Sub64 (Const64 [8]) y)))
	// cond: (shiftIsBounded(left) || shiftIsBounded(right)) && canRotate(config, 8)
	// result: (RotateLeft8 x y)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			left := v_0
			if left.Op != OpLsh8x64 {
				continue
			}
			y := left.Args[1]
			x := left.Args[0]
			right := v_1
			if right.Op != OpRsh8Ux64 {
				continue
			}
			_ = right.Args[1]
			if x != right.Args[0] {
				continue
			}
			right_1 := right.Args[1]
			if right_1.Op != OpSub64 {
				continue
			}
			_ = right_1.Args[1]
			right_1_0 := right_1.Args[0]
			if right_1_0.Op != OpConst64 || auxIntToInt64(right_1_0.AuxInt) != 8 || y != right_1.Args[1] || !((shiftIsBounded(left) || shiftIsBounded(right)) && canRotate(config, 8)) {
				continue
			}
			v.reset(OpRotateLeft8)
			v.AddArg2(x, y)
			return true
		}
		break
	}
	// match: (Xor8 left:(Lsh8x32 x y) right:(Rsh8Ux32 x (Sub32 (Const32 [8]) y)))
	// cond: (shiftIsBounded(left) || shiftIsBounded(right)) && canRotate(config, 8)
	// result: (RotateLeft8 x y)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			left := v_0
			if left.Op != OpLsh8x32 {
				continue
			}
			y := left.Args[1]
			x := left.Args[0]
			right := v_1
			if right.Op != OpRsh8Ux32 {
				continue
			}
			_ = right.Args[1]
			if x != right.Args[0] {
				continue
			}
			right_1 := right.Args[1]
			if right_1.Op != OpSub32 {
				continue
			}
			_ = right_1.Args[1]
			right_1_0 := right_1.Args[0]
			if right_1_0.Op != OpConst32 || auxIntToInt32(right_1_0.AuxInt) != 8 || y != right_1.Args[1] || !((shiftIsBounded(left) || shiftIsBounded(right)) && canRotate(config, 8)) {
				continue
			}
			v.reset(OpRotateLeft8)
			v.AddArg2(x, y)
			return true
		}
		break
	}
	// match: (Xor8 left:(Lsh8x16 x y) right:(Rsh8Ux16 x (Sub16 (Const16 [8]) y)))
	// cond: (shiftIsBounded(left) || shiftIsBounded(right)) && canRotate(config, 8)
	// result: (RotateLeft8 x y)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			left := v_0
			if left.Op != OpLsh8x16 {
				continue
			}
			y := left.Args[1]
			x := left.Args[0]
			right := v_1
			if right.Op != OpRsh8Ux16 {
				continue
			}
			_ = right.Args[1]
			if x != right.Args[0] {
				continue
			}
			right_1 := right.Args[1]
			if right_1.Op != OpSub16 {
				continue
			}
			_ = right_1.Args[1]
			right_1_0 := right_1.Args[0]
			if right_1_0.Op != OpConst16 || auxIntToInt16(right_1_0.AuxInt) != 8 || y != right_1.Args[1] || !((shiftIsBounded(left) || shiftIsBounded(right)) && canRotate(config, 8)) {
				continue
			}
			v.reset(OpRotateLeft8)
			v.AddArg2(x, y)
			return true
		}
		break
	}
	// match: (Xor8 left:(Lsh8x8 x y) right:(Rsh8Ux8 x (Sub8 (Const8 [8]) y)))
	// cond: (shiftIsBounded(left) || shiftIsBounded(right)) && canRotate(config, 8)
	// result: (RotateLeft8 x y)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			left := v_0
			if left.Op != OpLsh8x8 {
				continue
			}
			y := left.Args[1]
			x := left.Args[0]
			right := v_1
			if right.Op != OpRsh8Ux8 {
				continue
			}
			_ = right.Args[1]
			if x != right.Args[0] {
				continue
			}
			right_1 := right.Args[1]
			if right_1.Op != OpSub8 {
				continue
			}
			_ = right_1.Args[1]
			right_1_0 := right_1.Args[0]
			if right_1_0.Op != OpConst8 || auxIntToInt8(right_1_0.AuxInt) != 8 || y != right_1.Args[1] || !((shiftIsBounded(left) || shiftIsBounded(right)) && canRotate(config, 8)) {
				continue
			}
			v.reset(OpRotateLeft8)
			v.AddArg2(x, y)
			return true
		}
		break
	}
	// match: (Xor8 right:(Rsh8Ux64 x y) left:(Lsh8x64 x z:(Sub64 (Const64 [8]) y)))
	// cond: (shiftIsBounded(left) || shiftIsBounded(right)) && canRotate(config, 8)
	// result: (RotateLeft8 x z)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			right := v_0
			if right.Op != OpRsh8Ux64 {
				continue
			}
			y := right.Args[1]
			x := right.Args[0]
			left := v_1
			if left.Op != OpLsh8x64 {
				continue
			}
			_ = left.Args[1]
			if x != left.Args[0] {
				continue
			}
			z := left.Args[1]
			if z.Op != OpSub64 {
				continue
			}
			_ = z.Args[1]
			z_0 := z.Args[0]
			if z_0.Op != OpConst64 || auxIntToInt64(z_0.AuxInt) != 8 || y != z.Args[1] || !((shiftIsBounded(left) || shiftIsBounded(right)) && canRotate(config, 8)) {
				continue
			}
			v.reset(OpRotateLeft8)
			v.AddArg2(x, z)
			return true
		}
		break
	}
	// match: (Xor8 right:(Rsh8Ux32 x y) left:(Lsh8x32 x z:(Sub32 (Const32 [8]) y)))
	// cond: (shiftIsBounded(left) || shiftIsBounded(right)) && canRotate(config, 8)
	// result: (RotateLeft8 x z)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			right := v_0
			if right.Op != OpRsh8Ux32 {
				continue
			}
			y := right.Args[1]
			x := right.Args[0]
			left := v_1
			if left.Op != OpLsh8x32 {
				continue
			}
			_ = left.Args[1]
			if x != left.Args[0] {
				continue
			}
			z := left.Args[1]
			if z.Op != OpSub32 {
				continue
			}
			_ = z.Args[1]
			z_0 := z.Args[0]
			if z_0.Op != OpConst32 || auxIntToInt32(z_0.AuxInt) != 8 || y != z.Args[1] || !((shiftIsBounded(left) || shiftIsBounded(right)) && canRotate(config, 8)) {
				continue
			}
			v.reset(OpRotateLeft8)
			v.AddArg2(x, z)
			return true
		}
		break
	}
	// match: (Xor8 right:(Rsh8Ux16 x y) left:(Lsh8x16 x z:(Sub16 (Const16 [8]) y)))
	// cond: (shiftIsBounded(left) || shiftIsBounded(right)) && canRotate(config, 8)
	// result: (RotateLeft8 x z)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			right := v_0
			if right.Op != OpRsh8Ux16 {
				continue
			}
			y := right.Args[1]
			x := right.Args[0]
			left := v_1
			if left.Op != OpLsh8x16 {
				continue
			}
			_ = left.Args[1]
			if x != left.Args[0] {
				continue
			}
			z := left.Args[1]
			if z.Op != OpSub16 {
				continue
			}
			_ = z.Args[1]
			z_0 := z.Args[0]
			if z_0.Op != OpConst16 || auxIntToInt16(z_0.AuxInt) != 8 || y != z.Args[1] || !((shiftIsBounded(left) || shiftIsBounded(right)) && canRotate(config, 8)) {
				continue
			}
			v.reset(OpRotateLeft8)
			v.AddArg2(x, z)
			return true
		}
		break
	}
	// match: (Xor8 right:(Rsh8Ux8 x y) left:(Lsh8x8 x z:(Sub8 (Const8 [8]) y)))
	// cond: (shiftIsBounded(left) || shiftIsBounded(right)) && canRotate(config, 8)
	// result: (RotateLeft8 x z)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			right := v_0
			if right.Op != OpRsh8Ux8 {
				continue
			}
			y := right.Args[1]
			x := right.Args[0]
			left := v_1
			if left.Op != OpLsh8x8 {
				continue
			}
			_ = left.Args[1]
			if x != left.Args[0] {
				continue
			}
			z := left.Args[1]
			if z.Op != OpSub8 {
				continue
			}
			_ = z.Args[1]
			z_0 := z.Args[0]
			if z_0.Op != OpConst8 || auxIntToInt8(z_0.AuxInt) != 8 || y != z.Args[1] || !((shiftIsBounded(left) || shiftIsBounded(right)) && canRotate(config, 8)) {
				continue
			}
			v.reset(OpRotateLeft8)
			v.AddArg2(x, z)
			return true
		}
		break
	}
	return false
}
func rewriteValuegeneric_OpZero(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Zero (SelectN [0] call:(StaticLECall _ _)) mem:(SelectN [1] call))
	// cond: isSameCall(call.Aux, "runtime.newobject")
	// result: mem
	for {
		if v_0.Op != OpSelectN || auxIntToInt64(v_0.AuxInt) != 0 {
			break
		}
		call := v_0.Args[0]
		if call.Op != OpStaticLECall || len(call.Args) != 2 {
			break
		}
		mem := v_1
		if mem.Op != OpSelectN || auxIntToInt64(mem.AuxInt) != 1 || call != mem.Args[0] || !(isSameCall(call.Aux, "runtime.newobject")) {
			break
		}
		v.copyOf(mem)
		return true
	}
	// match: (Zero {t1} [n] p1 store:(Store {t2} (OffPtr [o2] p2) _ mem))
	// cond: isSamePtr(p1, p2) && store.Uses == 1 && n >= o2 + t2.Size() && clobber(store)
	// result: (Zero {t1} [n] p1 mem)
	for {
		n := auxIntToInt64(v.AuxInt)
		t1 := auxToType(v.Aux)
		p1 := v_0
		store := v_1
		if store.Op != OpStore {
			break
		}
		t2 := auxToType(store.Aux)
		mem := store.Args[2]
		store_0 := store.Args[0]
		if store_0.Op != OpOffPtr {
			break
		}
		o2 := auxIntToInt64(store_0.AuxInt)
		p2 := store_0.Args[0]
		if !(isSamePtr(p1, p2) && store.Uses == 1 && n >= o2+t2.Size() && clobber(store)) {
			break
		}
		v.reset(OpZero)
		v.AuxInt = int64ToAuxInt(n)
		v.Aux = typeToAux(t1)
		v.AddArg2(p1, mem)
		return true
	}
	// match: (Zero {t} [n] dst1 move:(Move {t} [n] dst2 _ mem))
	// cond: move.Uses == 1 && isSamePtr(dst1, dst2) && clobber(move)
	// result: (Zero {t} [n] dst1 mem)
	for {
		n := auxIntToInt64(v.AuxInt)
		t := auxToType(v.Aux)
		dst1 := v_0
		move := v_1
		if move.Op != OpMove || auxIntToInt64(move.AuxInt) != n || auxToType(move.Aux) != t {
			break
		}
		mem := move.Args[2]
		dst2 := move.Args[0]
		if !(move.Uses == 1 && isSamePtr(dst1, dst2) && clobber(move)) {
			break
		}
		v.reset(OpZero)
		v.AuxInt = int64ToAuxInt(n)
		v.Aux = typeToAux(t)
		v.AddArg2(dst1, mem)
		return true
	}
	// match: (Zero {t} [n] dst1 vardef:(VarDef {x} move:(Move {t} [n] dst2 _ mem)))
	// cond: move.Uses == 1 && vardef.Uses == 1 && isSamePtr(dst1, dst2) && clobber(move, vardef)
	// result: (Zero {t} [n] dst1 (VarDef {x} mem))
	for {
		n := auxIntToInt64(v.AuxInt)
		t := auxToType(v.Aux)
		dst1 := v_0
		vardef := v_1
		if vardef.Op != OpVarDef {
			break
		}
		x := auxToSym(vardef.Aux)
		move := vardef.Args[0]
		if move.Op != OpMove || auxIntToInt64(move.AuxInt) != n || auxToType(move.Aux) != t {
			break
		}
		mem := move.Args[2]
		dst2 := move.Args[0]
		if !(move.Uses == 1 && vardef.Uses == 1 && isSamePtr(dst1, dst2) && clobber(move, vardef)) {
			break
		}
		v.reset(OpZero)
		v.AuxInt = int64ToAuxInt(n)
		v.Aux = typeToAux(t)
		v0 := b.NewValue0(v.Pos, OpVarDef, types.TypeMem)
		v0.Aux = symToAux(x)
		v0.AddArg(mem)
		v.AddArg2(dst1, v0)
		return true
	}
	// match: (Zero {t} [s] dst1 zero:(Zero {t} [s] dst2 _))
	// cond: isSamePtr(dst1, dst2)
	// result: zero
	for {
		s := auxIntToInt64(v.AuxInt)
		t := auxToType(v.Aux)
		dst1 := v_0
		zero := v_1
		if zero.Op != OpZero || auxIntToInt64(zero.AuxInt) != s || auxToType(zero.Aux) != t {
			break
		}
		dst2 := zero.Args[0]
		if !(isSamePtr(dst1, dst2)) {
			break
		}
		v.copyOf(zero)
		return true
	}
	// match: (Zero {t} [s] dst1 vardef:(VarDef (Zero {t} [s] dst2 _)))
	// cond: isSamePtr(dst1, dst2)
	// result: vardef
	for {
		s := auxIntToInt64(v.AuxInt)
		t := auxToType(v.Aux)
		dst1 := v_0
		vardef := v_1
		if vardef.Op != OpVarDef {
			break
		}
		vardef_0 := vardef.Args[0]
		if vardef_0.Op != OpZero || auxIntToInt64(vardef_0.AuxInt) != s || auxToType(vardef_0.Aux) != t {
			break
		}
		dst2 := vardef_0.Args[0]
		if !(isSamePtr(dst1, dst2)) {
			break
		}
		v.copyOf(vardef)
		return true
	}
	return false
}
func rewriteValuegeneric_OpZeroExt16to32(v *Value) bool {
	v_0 := v.Args[0]
	// match: (ZeroExt16to32 (Const16 [c]))
	// result: (Const32 [int32(uint16(c))])
	for {
		if v_0.Op != OpConst16 {
			break
		}
		c := auxIntToInt16(v_0.AuxInt)
		v.reset(OpConst32)
		v.AuxInt = int32ToAuxInt(int32(uint16(c)))
		return true
	}
	// match: (ZeroExt16to32 (Trunc32to16 x:(Rsh32Ux64 _ (Const64 [s]))))
	// cond: s >= 16
	// result: x
	for {
		if v_0.Op != OpTrunc32to16 {
			break
		}
		x := v_0.Args[0]
		if x.Op != OpRsh32Ux64 {
			break
		}
		_ = x.Args[1]
		x_1 := x.Args[1]
		if x_1.Op != OpConst64 {
			break
		}
		s := auxIntToInt64(x_1.AuxInt)
		if !(s >= 16) {
			break
		}
		v.copyOf(x)
		return true
	}
	return false
}
func rewriteValuegeneric_OpZeroExt16to64(v *Value) bool {
	v_0 := v.Args[0]
	// match: (ZeroExt16to64 (Const16 [c]))
	// result: (Const64 [int64(uint16(c))])
	for {
		if v_0.Op != OpConst16 {
			break
		}
		c := auxIntToInt16(v_0.AuxInt)
		v.reset(OpConst64)
		v.AuxInt = int64ToAuxInt(int64(uint16(c)))
		return true
	}
	// match: (ZeroExt16to64 (Trunc64to16 x:(Rsh64Ux64 _ (Const64 [s]))))
	// cond: s >= 48
	// result: x
	for {
		if v_0.Op != OpTrunc64to16 {
			break
		}
		x := v_0.Args[0]
		if x.Op != OpRsh64Ux64 {
			break
		}
		_ = x.Args[1]
		x_1 := x.Args[1]
		if x_1.Op != OpConst64 {
			break
		}
		s := auxIntToInt64(x_1.AuxInt)
		if !(s >= 48) {
			break
		}
		v.copyOf(x)
		return true
	}
	return false
}
func rewriteValuegeneric_OpZeroExt32to64(v *Value) bool {
	v_0 := v.Args[0]
	// match: (ZeroExt32to64 (Const32 [c]))
	// result: (Const64 [int64(uint32(c))])
	for {
		if v_0.Op != OpConst32 {
			break
		}
		c := auxIntToInt32(v_0.AuxInt)
		v.reset(OpConst64)
		v.AuxInt = int64ToAuxInt(int64(uint32(c)))
		return true
	}
	// match: (ZeroExt32to64 (Trunc64to32 x:(Rsh64Ux64 _ (Const64 [s]))))
	// cond: s >= 32
	// result: x
	for {
		if v_0.Op != OpTrunc64to32 {
			break
		}
		x := v_0.Args[0]
		if x.Op != OpRsh64Ux64 {
			break
		}
		_ = x.Args[1]
		x_1 := x.Args[1]
		if x_1.Op != OpConst64 {
			break
		}
		s := auxIntToInt64(x_1.AuxInt)
		if !(s >= 32) {
			break
		}
		v.copyOf(x)
		return true
	}
	return false
}
func rewriteValuegeneric_OpZeroExt8to16(v *Value) bool {
	v_0 := v.Args[0]
	// match: (ZeroExt8to16 (Const8 [c]))
	// result: (Const16 [int16( uint8(c))])
	for {
		if v_0.Op != OpConst8 {
			break
		}
		c := auxIntToInt8(v_0.AuxInt)
		v.reset(OpConst16)
		v.AuxInt = int16ToAuxInt(int16(uint8(c)))
		return true
	}
	// match: (ZeroExt8to16 (Trunc16to8 x:(Rsh16Ux64 _ (Const64 [s]))))
	// cond: s >= 8
	// result: x
	for {
		if v_0.Op != OpTrunc16to8 {
			break
		}
		x := v_0.Args[0]
		if x.Op != OpRsh16Ux64 {
			break
		}
		_ = x.Args[1]
		x_1 := x.Args[1]
		if x_1.Op != OpConst64 {
			break
		}
		s := auxIntToInt64(x_1.AuxInt)
		if !(s >= 8) {
			break
		}
		v.copyOf(x)
		return true
	}
	return false
}
func rewriteValuegeneric_OpZeroExt8to32(v *Value) bool {
	v_0 := v.Args[0]
	// match: (ZeroExt8to32 (Const8 [c]))
	// result: (Const32 [int32( uint8(c))])
	for {
		if v_0.Op != OpConst8 {
			break
		}
		c := auxIntToInt8(v_0.AuxInt)
		v.reset(OpConst32)
		v.AuxInt = int32ToAuxInt(int32(uint8(c)))
		return true
	}
	// match: (ZeroExt8to32 (Trunc32to8 x:(Rsh32Ux64 _ (Const64 [s]))))
	// cond: s >= 24
	// result: x
	for {
		if v_0.Op != OpTrunc32to8 {
			break
		}
		x := v_0.Args[0]
		if x.Op != OpRsh32Ux64 {
			break
		}
		_ = x.Args[1]
		x_1 := x.Args[1]
		if x_1.Op != OpConst64 {
			break
		}
		s := auxIntToInt64(x_1.AuxInt)
		if !(s >= 24) {
			break
		}
		v.copyOf(x)
		return true
	}
	return false
}
func rewriteValuegeneric_OpZeroExt8to64(v *Value) bool {
	v_0 := v.Args[0]
	// match: (ZeroExt8to64 (Const8 [c]))
	// result: (Const64 [int64( uint8(c))])
	for {
		if v_0.Op != OpConst8 {
			break
		}
		c := auxIntToInt8(v_0.AuxInt)
		v.reset(OpConst64)
		v.AuxInt = int64ToAuxInt(int64(uint8(c)))
		return true
	}
	// match: (ZeroExt8to64 (Trunc64to8 x:(Rsh64Ux64 _ (Const64 [s]))))
	// cond: s >= 56
	// result: x
	for {
		if v_0.Op != OpTrunc64to8 {
			break
		}
		x := v_0.Args[0]
		if x.Op != OpRsh64Ux64 {
			break
		}
		_ = x.Args[1]
		x_1 := x.Args[1]
		if x_1.Op != OpConst64 {
			break
		}
		s := auxIntToInt64(x_1.AuxInt)
		if !(s >= 56) {
			break
		}
		v.copyOf(x)
		return true
	}
	return false
}
func rewriteBlockgeneric(b *Block) bool {
	switch b.Kind {
	case BlockIf:
		// match: (If (Not cond) yes no)
		// result: (If cond no yes)
		for b.Controls[0].Op == OpNot {
			v_0 := b.Controls[0]
			cond := v_0.Args[0]
			b.resetWithControl(BlockIf, cond)
			b.swapSuccessors()
			return true
		}
		// match: (If (ConstBool [c]) yes no)
		// cond: c
		// result: (First yes no)
		for b.Controls[0].Op == OpConstBool {
			v_0 := b.Controls[0]
			c := auxIntToBool(v_0.AuxInt)
			if !(c) {
				break
			}
			b.Reset(BlockFirst)
			return true
		}
		// match: (If (ConstBool [c]) yes no)
		// cond: !c
		// result: (First no yes)
		for b.Controls[0].Op == OpConstBool {
			v_0 := b.Controls[0]
			c := auxIntToBool(v_0.AuxInt)
			if !(!c) {
				break
			}
			b.Reset(BlockFirst)
			b.swapSuccessors()
			return true
		}
	}
	return false
}

"""




```