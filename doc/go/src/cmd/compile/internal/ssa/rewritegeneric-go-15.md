Response:
My goal is to analyze the given Go code snippet and extract its functionality, relate it to Go features, provide examples, and summarize its role within the larger file.

**Thinking Process:**

1. **Identify the Code's Purpose:** The function names (`rewriteValuegeneric_OpNeq32F`, `rewriteValuegeneric_OpNeq64`, etc.) and the structure of the code (nested loops, `v.reset`, `v.AuxInt`, `v.AddArg`) strongly suggest this code is part of a compiler optimization or rewriting pass. Specifically, it seems to be looking for specific patterns of operations (like `Neq32F`, `Neq64`) and transforming them into simpler or more efficient equivalents.

2. **Analyze Individual Functions:** I'll go through each function (`rewriteValuegeneric_OpNeq32F`, `rewriteValuegeneric_OpNeq64`, etc.) and try to understand what specific operation it's handling and what kind of rewrites it's performing.

   * **`rewriteValuegeneric_OpNeq32F` and `rewriteValuegeneric_OpNeq64F`:** These functions deal with the "not equal" operation on floating-point numbers. The core logic seems to be simplifying the comparison of two constants to a single boolean constant.

   * **`rewriteValuegeneric_OpNeq64`:** This function handles the "not equal" operation on 64-bit integers. It has more complex rewrite rules, including:
      * Simplifying `Neq64 x x` to `false`.
      * Simplifying `Neq64 (Const c) (Add64 (Const d) x)` to `Neq64 (Const c-d) x`.
      * Simplifying `Neq64 (Const c) (Const d)` to `c != d`.
      * Recognizing and simplifying a bitmasking pattern involving shifts, adds, and constants.
      * Simplifying `Neq64 (Sub64 x y) 0` to `Neq64 x y`.
      * Simplifying a specific bitwise AND comparison with a single-bit constant.

   * **`rewriteValuegeneric_OpNeq8`:**  Similar to `OpNeq64`, but for 8-bit integers. It follows similar simplification patterns.

   * **`rewriteValuegeneric_OpNeqB`:** Handles "not equal" for boolean values. It has rules for constant booleans and for negating expressions.

   * **`rewriteValuegeneric_OpNeqInter`:** Deals with "not equal" for interface types. It rewrites the interface comparison to a pointer comparison of the interface table (itab).

   * **`rewriteValuegeneric_OpNeqPtr`:** Handles "not equal" for pointers. It has a wide variety of rules for comparing different forms of pointer expressions (addresses, offsets, constants, nil).

   * **`rewriteValuegeneric_OpNeqSlice`:** Handles "not equal" for slices. It rewrites slice inequality to pointer inequality of the underlying slice pointers.

   * **`rewriteValuegeneric_OpNilCheck`:**  Deals with explicit nil checks. It aims to remove redundant or unnecessary nil checks based on the preceding operation (like `GetG`, `StaticLECall` for `newobject`, address of global symbols).

   * **`rewriteValuegeneric_OpNot`:** Handles the logical NOT operation. It rewrites `Not` applied to comparison operations to their inverse (e.g., `Not (Eq)` becomes `Neq`).

   * **`rewriteValuegeneric_OpOffPtr`:** Handles the `OffPtr` operation (pointer with offset). It simplifies nested `OffPtr` operations and removes zero offsets.

   * **`rewriteValuegeneric_OpOr16`:** Handles the bitwise OR operation for 16-bit integers. It has rules for constants, commutativity, identity, absorption, and some more complex patterns involving AND and complement.

3. **Infer Go Feature Implementation:** The code is performing low-level optimizations on the SSA (Static Single Assignment) intermediate representation of Go code. The specific optimizations target basic comparison operations (`!=`, `!`), pointer manipulation, and bitwise operations. These are fundamental aspects of Go's semantics.

4. **Provide Go Code Examples:**  For each function, I'll construct simple Go code snippets that would result in the specific SSA patterns being matched by the rewrite rules. This helps illustrate the practical effect of the optimizations.

5. **Address Command-Line Arguments and Common Mistakes (If Applicable):**  This specific code snippet doesn't directly handle command-line arguments. Common mistakes would likely be in understanding the underlying SSA representation or in creating rewrite rules that are incorrect or overly broad. Since the prompt asked to include if applicable, and this part of the compiler generally doesn't have user-facing parameters, I'll focus on the conceptual aspect of potential errors in rule creation.

6. **Summarize the Functionality:**  I'll synthesize the analysis of the individual functions into a concise summary of the file's overall purpose within the Go compiler.

7. **Consider the "Part X of Y" Context:**  Since this is part 16 of 26, I should frame the summary in the context of a larger optimization pipeline. This part likely focuses on boolean and comparison simplification.

**Self-Correction/Refinement during the thought process:**

* Initially, I might have focused too much on the exact bitwise manipulations without clearly stating the overall goal of simplifying comparisons and boolean logic. I need to ensure the explanation is accessible.
* I should avoid getting bogged down in the very specific details of each rewrite rule and instead focus on the general categories of optimizations being performed.
* I need to make sure the Go code examples are simple and directly relate to the corresponding rewrite rules. Avoid overly complex examples.
* When discussing potential errors, I should frame it from the perspective of a compiler developer writing these rewrite rules, not a typical Go user.

By following these steps, I can provide a comprehensive and accurate explanation of the provided Go code snippet.
这是 `go/src/cmd/compile/internal/ssa/rewritegeneric.go` 文件的一部分，它负责实现**通用类型的 SSA 重写规则**。

**功能归纳（第 16 部分）：**

这一部分主要定义了针对以下 SSA 操作码（OpCode）的重写规则：

* **OpNeq32F, OpNeq64F:**  浮点数不等比较操作。
* **OpNeq64:** 64位整数不等比较操作。
* **OpNeq8:** 8位整数不等比较操作。
* **OpNeqB:** 布尔类型不等比较操作。
* **OpNeqInter:** 接口类型不等比较操作。
* **OpNeqPtr:** 指针类型不等比较操作。
* **OpNeqSlice:** 切片类型不等比较操作。
* **OpNilCheck:** 空指针检查操作。
* **OpNot:** 逻辑非操作。
* **OpOffPtr:** 指针偏移操作。
* **OpOr16:** 16位整数按位或操作。

**更具体的功能描述:**

这些重写规则的目标是**简化和优化 SSA 代码**，使其更易于进一步处理和最终生成高效的机器码。  常见的优化手段包括：

* **常量折叠:** 将涉及常量的运算直接计算出结果，替换为常量。例如，`Neq32F (Const32F [1.0]) (Const32F [2.0])` 可以直接被替换为 `ConstBool [true]`。
* **代数简化:** 利用代数恒等式简化表达式。例如，`Neq64 x x` 总是 `false`，可以被替换为 `ConstBool [false]`。
* **模式匹配和替换:** 识别特定的操作模式，并将其替换为更高效或更简单的等价形式。例如，将某些复杂的位运算模式识别出来并替换为更直接的 `And` 操作。
* **消除冗余操作:**  去除不必要的或重复的操作。例如，某些情况下可以移除多余的空指针检查。
* **操作符转换:** 将一个操作符转换为另一个等价但可能更易于后续处理的操作符。例如，`NeqInter x y` 被转换为 `NeqPtr (ITab x) (ITab y)`，将接口不等比较转换为指针不等比较。
* **利用已知属性:**  根据操作数的已知属性进行优化。例如，如果知道一个减法的结果只被使用一次，可以将一个与零比较的不等式转换为对减法操作数的比较。

**Go 语言功能实现推断与代码示例:**

这些重写规则是 Go 编译器在**中间代码生成和优化阶段**的一部分。它们作用于 SSA 形式的 Go 代码，这种形式更接近于机器码，便于进行各种优化。

**示例 1: 常量折叠 (OpNeq32F)**

假设有以下 Go 代码：

```go
package main

func main() {
	a := 1.0
	b := 2.0
	println(a != b)
}
```

在编译过程中，`a != b` 会被表示为 SSA 中的 `OpNeq32F` 节点。`rewriteValuegeneric_OpNeq32F` 函数中的如下规则会被匹配：

```go
// match: (Neq32F (Const32F [c]) (Const32F [d]))
// result: (ConstBool [c != d])
for {
	for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
		if v_0.Op != OpConst32F {
			continue
		}
		c := auxIntToFloat32(v_0.AuxInt)
		if v_1.Op != OpConst32F {
			continue
		}
		d := auxIntToFloat32(v_1.AuxInt)
		v.reset(OpConstBool)
		v.AuxInt = boolToAuxInt(c != d)
		return true
	}
	break
}
```

* **假设输入 SSA:**  `v` 是一个 `OpNeq32F` 节点，其参数 `v_0` 是 `Const32F [1.0]`，`v_1` 是 `Const32F [2.0]`。
* **输出 SSA:** `v` 被重置为 `OpConstBool`，其 `AuxInt` 被设置为 `boolToAuxInt(true)`，即 `true` 的布尔常量。

**示例 2: 代数简化 (OpNeq64)**

假设有以下 Go 代码：

```go
package main

func main() {
	var x int64 = 10
	println(x != x)
}
```

在编译过程中，`x != x` 会被表示为 SSA 中的 `OpNeq64` 节点。`rewriteValuegeneric_OpNeq64` 函数中的如下规则会被匹配：

```go
// match: (Neq64 x x)
// result: (ConstBool [false])
for {
	x := v_0
	if x != v_1 {
		break
	}
	v.reset(OpConstBool)
	v.AuxInt = boolToAuxInt(false)
	return true
}
```

* **假设输入 SSA:** `v` 是一个 `OpNeq64` 节点，其两个参数 `v_0` 和 `v_1` 指向同一个表示变量 `x` 的 SSA 值。
* **输出 SSA:** `v` 被重置为 `OpConstBool`，其 `AuxInt` 被设置为 `boolToAuxInt(false)`，即 `false` 的布尔常量。

**示例 3: 操作符转换 (OpNeqInter)**

假设有以下 Go 代码：

```go
package main

type I interface {
	M()
}

type T1 struct{}
func (T1) M() {}

type T2 struct{}
func (T2) M() {}

func main() {
	var i1 I = T1{}
	var i2 I = T2{}
	println(i1 != i2)
}
```

在编译过程中，`i1 != i2` 会被表示为 `OpNeqInter` 节点。`rewriteValuegeneric_OpNeqInter` 函数中的如下规则会被匹配：

```go
// match: (NeqInter x y)
// result: (NeqPtr (ITab x) (ITab y))
for {
	x := v_0
	y := v_1
	v.reset(OpNeqPtr)
	v0 := b.NewValue0(v.Pos, OpITab, typ.Uintptr)
	v0.AddArg(x)
	v1 := b.NewValue0(v.Pos, OpITab, typ.Uintptr)
	v1.AddArg(y)
	v.AddArg2(v0, v1)
	return true
}
```

* **假设输入 SSA:** `v` 是一个 `OpNeqInter` 节点，其参数 `v_0` 和 `v_1` 代表接口 `i1` 和 `i2`。
* **输出 SSA:** `v` 被重置为 `OpNeqPtr` 节点，它的两个参数分别是 `OpITab` 节点，分别提取了 `i1` 和 `i2` 的接口类型表 (itab) 指针。

**命令行参数:**

这个代码片段本身不直接处理命令行参数。它是 Go 编译器内部优化流程的一部分，通常由编译器驱动，无需用户直接干预。  Go 编译器的命令行参数（如 `-gcflags`）可能会影响到优化级别，从而间接影响到这些重写规则的应用。

**使用者易犯错的点:**

作为 Go 语言的使用者，一般不会直接接触到这些底层的 SSA 重写规则。这些是编译器开发者需要关注的。  然而，理解这些规则可以帮助我们更好地理解 Go 编译器的优化行为，从而写出更高效的代码。

**总结第 16 部分的功能:**

总而言之，`rewritegeneric.go` 文件的第 16 部分定义了针对多种比较操作（包括浮点数、整数、布尔值、接口和指针）以及逻辑非、指针偏移和按位或操作的通用重写规则。这些规则旨在在编译过程中对 SSA 中间代码进行优化，通过常量折叠、代数简化、模式匹配和替换等手段，生成更高效的目标代码。这是 Go 编译器优化管道中的关键环节，对最终程序的性能至关重要。

### 提示词
```
这是路径为go/src/cmd/compile/internal/ssa/rewritegeneric.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第16部分，共26部分，请归纳一下它的功能
```

### 源代码
```go
_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpConst32F {
				continue
			}
			c := auxIntToFloat32(v_0.AuxInt)
			if v_1.Op != OpConst32F {
				continue
			}
			d := auxIntToFloat32(v_1.AuxInt)
			v.reset(OpConstBool)
			v.AuxInt = boolToAuxInt(c != d)
			return true
		}
		break
	}
	return false
}
func rewriteValuegeneric_OpNeq64(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Neq64 x x)
	// result: (ConstBool [false])
	for {
		x := v_0
		if x != v_1 {
			break
		}
		v.reset(OpConstBool)
		v.AuxInt = boolToAuxInt(false)
		return true
	}
	// match: (Neq64 (Const64 <t> [c]) (Add64 (Const64 <t> [d]) x))
	// result: (Neq64 (Const64 <t> [c-d]) x)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpConst64 {
				continue
			}
			t := v_0.Type
			c := auxIntToInt64(v_0.AuxInt)
			if v_1.Op != OpAdd64 {
				continue
			}
			_ = v_1.Args[1]
			v_1_0 := v_1.Args[0]
			v_1_1 := v_1.Args[1]
			for _i1 := 0; _i1 <= 1; _i1, v_1_0, v_1_1 = _i1+1, v_1_1, v_1_0 {
				if v_1_0.Op != OpConst64 || v_1_0.Type != t {
					continue
				}
				d := auxIntToInt64(v_1_0.AuxInt)
				x := v_1_1
				v.reset(OpNeq64)
				v0 := b.NewValue0(v.Pos, OpConst64, t)
				v0.AuxInt = int64ToAuxInt(c - d)
				v.AddArg2(v0, x)
				return true
			}
		}
		break
	}
	// match: (Neq64 (Const64 [c]) (Const64 [d]))
	// result: (ConstBool [c != d])
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpConst64 {
				continue
			}
			c := auxIntToInt64(v_0.AuxInt)
			if v_1.Op != OpConst64 {
				continue
			}
			d := auxIntToInt64(v_1.AuxInt)
			v.reset(OpConstBool)
			v.AuxInt = boolToAuxInt(c != d)
			return true
		}
		break
	}
	// match: (Neq64 n (Lsh64x64 (Rsh64x64 (Add64 <t> n (Rsh64Ux64 <t> (Rsh64x64 <t> n (Const64 <typ.UInt64> [63])) (Const64 <typ.UInt64> [kbar]))) (Const64 <typ.UInt64> [k])) (Const64 <typ.UInt64> [k])) )
	// cond: k > 0 && k < 63 && kbar == 64 - k
	// result: (Neq64 (And64 <t> n (Const64 <t> [1<<uint(k)-1])) (Const64 <t> [0]))
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			n := v_0
			if v_1.Op != OpLsh64x64 {
				continue
			}
			_ = v_1.Args[1]
			v_1_0 := v_1.Args[0]
			if v_1_0.Op != OpRsh64x64 {
				continue
			}
			_ = v_1_0.Args[1]
			v_1_0_0 := v_1_0.Args[0]
			if v_1_0_0.Op != OpAdd64 {
				continue
			}
			t := v_1_0_0.Type
			_ = v_1_0_0.Args[1]
			v_1_0_0_0 := v_1_0_0.Args[0]
			v_1_0_0_1 := v_1_0_0.Args[1]
			for _i1 := 0; _i1 <= 1; _i1, v_1_0_0_0, v_1_0_0_1 = _i1+1, v_1_0_0_1, v_1_0_0_0 {
				if n != v_1_0_0_0 || v_1_0_0_1.Op != OpRsh64Ux64 || v_1_0_0_1.Type != t {
					continue
				}
				_ = v_1_0_0_1.Args[1]
				v_1_0_0_1_0 := v_1_0_0_1.Args[0]
				if v_1_0_0_1_0.Op != OpRsh64x64 || v_1_0_0_1_0.Type != t {
					continue
				}
				_ = v_1_0_0_1_0.Args[1]
				if n != v_1_0_0_1_0.Args[0] {
					continue
				}
				v_1_0_0_1_0_1 := v_1_0_0_1_0.Args[1]
				if v_1_0_0_1_0_1.Op != OpConst64 || v_1_0_0_1_0_1.Type != typ.UInt64 || auxIntToInt64(v_1_0_0_1_0_1.AuxInt) != 63 {
					continue
				}
				v_1_0_0_1_1 := v_1_0_0_1.Args[1]
				if v_1_0_0_1_1.Op != OpConst64 || v_1_0_0_1_1.Type != typ.UInt64 {
					continue
				}
				kbar := auxIntToInt64(v_1_0_0_1_1.AuxInt)
				v_1_0_1 := v_1_0.Args[1]
				if v_1_0_1.Op != OpConst64 || v_1_0_1.Type != typ.UInt64 {
					continue
				}
				k := auxIntToInt64(v_1_0_1.AuxInt)
				v_1_1 := v_1.Args[1]
				if v_1_1.Op != OpConst64 || v_1_1.Type != typ.UInt64 || auxIntToInt64(v_1_1.AuxInt) != k || !(k > 0 && k < 63 && kbar == 64-k) {
					continue
				}
				v.reset(OpNeq64)
				v0 := b.NewValue0(v.Pos, OpAnd64, t)
				v1 := b.NewValue0(v.Pos, OpConst64, t)
				v1.AuxInt = int64ToAuxInt(1<<uint(k) - 1)
				v0.AddArg2(n, v1)
				v2 := b.NewValue0(v.Pos, OpConst64, t)
				v2.AuxInt = int64ToAuxInt(0)
				v.AddArg2(v0, v2)
				return true
			}
		}
		break
	}
	// match: (Neq64 s:(Sub64 x y) (Const64 [0]))
	// cond: s.Uses == 1
	// result: (Neq64 x y)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			s := v_0
			if s.Op != OpSub64 {
				continue
			}
			y := s.Args[1]
			x := s.Args[0]
			if v_1.Op != OpConst64 || auxIntToInt64(v_1.AuxInt) != 0 || !(s.Uses == 1) {
				continue
			}
			v.reset(OpNeq64)
			v.AddArg2(x, y)
			return true
		}
		break
	}
	// match: (Neq64 (And64 <t> x (Const64 <t> [y])) (Const64 <t> [y]))
	// cond: oneBit64(y)
	// result: (Eq64 (And64 <t> x (Const64 <t> [y])) (Const64 <t> [0]))
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpAnd64 {
				continue
			}
			t := v_0.Type
			_ = v_0.Args[1]
			v_0_0 := v_0.Args[0]
			v_0_1 := v_0.Args[1]
			for _i1 := 0; _i1 <= 1; _i1, v_0_0, v_0_1 = _i1+1, v_0_1, v_0_0 {
				x := v_0_0
				if v_0_1.Op != OpConst64 || v_0_1.Type != t {
					continue
				}
				y := auxIntToInt64(v_0_1.AuxInt)
				if v_1.Op != OpConst64 || v_1.Type != t || auxIntToInt64(v_1.AuxInt) != y || !(oneBit64(y)) {
					continue
				}
				v.reset(OpEq64)
				v0 := b.NewValue0(v.Pos, OpAnd64, t)
				v1 := b.NewValue0(v.Pos, OpConst64, t)
				v1.AuxInt = int64ToAuxInt(y)
				v0.AddArg2(x, v1)
				v2 := b.NewValue0(v.Pos, OpConst64, t)
				v2.AuxInt = int64ToAuxInt(0)
				v.AddArg2(v0, v2)
				return true
			}
		}
		break
	}
	return false
}
func rewriteValuegeneric_OpNeq64F(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (Neq64F (Const64F [c]) (Const64F [d]))
	// result: (ConstBool [c != d])
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpConst64F {
				continue
			}
			c := auxIntToFloat64(v_0.AuxInt)
			if v_1.Op != OpConst64F {
				continue
			}
			d := auxIntToFloat64(v_1.AuxInt)
			v.reset(OpConstBool)
			v.AuxInt = boolToAuxInt(c != d)
			return true
		}
		break
	}
	return false
}
func rewriteValuegeneric_OpNeq8(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Neq8 x x)
	// result: (ConstBool [false])
	for {
		x := v_0
		if x != v_1 {
			break
		}
		v.reset(OpConstBool)
		v.AuxInt = boolToAuxInt(false)
		return true
	}
	// match: (Neq8 (Const8 <t> [c]) (Add8 (Const8 <t> [d]) x))
	// result: (Neq8 (Const8 <t> [c-d]) x)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpConst8 {
				continue
			}
			t := v_0.Type
			c := auxIntToInt8(v_0.AuxInt)
			if v_1.Op != OpAdd8 {
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
				v.reset(OpNeq8)
				v0 := b.NewValue0(v.Pos, OpConst8, t)
				v0.AuxInt = int8ToAuxInt(c - d)
				v.AddArg2(v0, x)
				return true
			}
		}
		break
	}
	// match: (Neq8 (Const8 [c]) (Const8 [d]))
	// result: (ConstBool [c != d])
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
			v.reset(OpConstBool)
			v.AuxInt = boolToAuxInt(c != d)
			return true
		}
		break
	}
	// match: (Neq8 n (Lsh8x64 (Rsh8x64 (Add8 <t> n (Rsh8Ux64 <t> (Rsh8x64 <t> n (Const64 <typ.UInt64> [ 7])) (Const64 <typ.UInt64> [kbar]))) (Const64 <typ.UInt64> [k])) (Const64 <typ.UInt64> [k])) )
	// cond: k > 0 && k < 7 && kbar == 8 - k
	// result: (Neq8 (And8 <t> n (Const8 <t> [1<<uint(k)-1])) (Const8 <t> [0]))
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			n := v_0
			if v_1.Op != OpLsh8x64 {
				continue
			}
			_ = v_1.Args[1]
			v_1_0 := v_1.Args[0]
			if v_1_0.Op != OpRsh8x64 {
				continue
			}
			_ = v_1_0.Args[1]
			v_1_0_0 := v_1_0.Args[0]
			if v_1_0_0.Op != OpAdd8 {
				continue
			}
			t := v_1_0_0.Type
			_ = v_1_0_0.Args[1]
			v_1_0_0_0 := v_1_0_0.Args[0]
			v_1_0_0_1 := v_1_0_0.Args[1]
			for _i1 := 0; _i1 <= 1; _i1, v_1_0_0_0, v_1_0_0_1 = _i1+1, v_1_0_0_1, v_1_0_0_0 {
				if n != v_1_0_0_0 || v_1_0_0_1.Op != OpRsh8Ux64 || v_1_0_0_1.Type != t {
					continue
				}
				_ = v_1_0_0_1.Args[1]
				v_1_0_0_1_0 := v_1_0_0_1.Args[0]
				if v_1_0_0_1_0.Op != OpRsh8x64 || v_1_0_0_1_0.Type != t {
					continue
				}
				_ = v_1_0_0_1_0.Args[1]
				if n != v_1_0_0_1_0.Args[0] {
					continue
				}
				v_1_0_0_1_0_1 := v_1_0_0_1_0.Args[1]
				if v_1_0_0_1_0_1.Op != OpConst64 || v_1_0_0_1_0_1.Type != typ.UInt64 || auxIntToInt64(v_1_0_0_1_0_1.AuxInt) != 7 {
					continue
				}
				v_1_0_0_1_1 := v_1_0_0_1.Args[1]
				if v_1_0_0_1_1.Op != OpConst64 || v_1_0_0_1_1.Type != typ.UInt64 {
					continue
				}
				kbar := auxIntToInt64(v_1_0_0_1_1.AuxInt)
				v_1_0_1 := v_1_0.Args[1]
				if v_1_0_1.Op != OpConst64 || v_1_0_1.Type != typ.UInt64 {
					continue
				}
				k := auxIntToInt64(v_1_0_1.AuxInt)
				v_1_1 := v_1.Args[1]
				if v_1_1.Op != OpConst64 || v_1_1.Type != typ.UInt64 || auxIntToInt64(v_1_1.AuxInt) != k || !(k > 0 && k < 7 && kbar == 8-k) {
					continue
				}
				v.reset(OpNeq8)
				v0 := b.NewValue0(v.Pos, OpAnd8, t)
				v1 := b.NewValue0(v.Pos, OpConst8, t)
				v1.AuxInt = int8ToAuxInt(1<<uint(k) - 1)
				v0.AddArg2(n, v1)
				v2 := b.NewValue0(v.Pos, OpConst8, t)
				v2.AuxInt = int8ToAuxInt(0)
				v.AddArg2(v0, v2)
				return true
			}
		}
		break
	}
	// match: (Neq8 s:(Sub8 x y) (Const8 [0]))
	// cond: s.Uses == 1
	// result: (Neq8 x y)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			s := v_0
			if s.Op != OpSub8 {
				continue
			}
			y := s.Args[1]
			x := s.Args[0]
			if v_1.Op != OpConst8 || auxIntToInt8(v_1.AuxInt) != 0 || !(s.Uses == 1) {
				continue
			}
			v.reset(OpNeq8)
			v.AddArg2(x, y)
			return true
		}
		break
	}
	// match: (Neq8 (And8 <t> x (Const8 <t> [y])) (Const8 <t> [y]))
	// cond: oneBit8(y)
	// result: (Eq8 (And8 <t> x (Const8 <t> [y])) (Const8 <t> [0]))
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpAnd8 {
				continue
			}
			t := v_0.Type
			_ = v_0.Args[1]
			v_0_0 := v_0.Args[0]
			v_0_1 := v_0.Args[1]
			for _i1 := 0; _i1 <= 1; _i1, v_0_0, v_0_1 = _i1+1, v_0_1, v_0_0 {
				x := v_0_0
				if v_0_1.Op != OpConst8 || v_0_1.Type != t {
					continue
				}
				y := auxIntToInt8(v_0_1.AuxInt)
				if v_1.Op != OpConst8 || v_1.Type != t || auxIntToInt8(v_1.AuxInt) != y || !(oneBit8(y)) {
					continue
				}
				v.reset(OpEq8)
				v0 := b.NewValue0(v.Pos, OpAnd8, t)
				v1 := b.NewValue0(v.Pos, OpConst8, t)
				v1.AuxInt = int8ToAuxInt(y)
				v0.AddArg2(x, v1)
				v2 := b.NewValue0(v.Pos, OpConst8, t)
				v2.AuxInt = int8ToAuxInt(0)
				v.AddArg2(v0, v2)
				return true
			}
		}
		break
	}
	return false
}
func rewriteValuegeneric_OpNeqB(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (NeqB (ConstBool [c]) (ConstBool [d]))
	// result: (ConstBool [c != d])
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpConstBool {
				continue
			}
			c := auxIntToBool(v_0.AuxInt)
			if v_1.Op != OpConstBool {
				continue
			}
			d := auxIntToBool(v_1.AuxInt)
			v.reset(OpConstBool)
			v.AuxInt = boolToAuxInt(c != d)
			return true
		}
		break
	}
	// match: (NeqB (ConstBool [false]) x)
	// result: x
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpConstBool || auxIntToBool(v_0.AuxInt) != false {
				continue
			}
			x := v_1
			v.copyOf(x)
			return true
		}
		break
	}
	// match: (NeqB (ConstBool [true]) x)
	// result: (Not x)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpConstBool || auxIntToBool(v_0.AuxInt) != true {
				continue
			}
			x := v_1
			v.reset(OpNot)
			v.AddArg(x)
			return true
		}
		break
	}
	// match: (NeqB (Not x) (Not y))
	// result: (NeqB x y)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpNot {
				continue
			}
			x := v_0.Args[0]
			if v_1.Op != OpNot {
				continue
			}
			y := v_1.Args[0]
			v.reset(OpNeqB)
			v.AddArg2(x, y)
			return true
		}
		break
	}
	return false
}
func rewriteValuegeneric_OpNeqInter(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (NeqInter x y)
	// result: (NeqPtr (ITab x) (ITab y))
	for {
		x := v_0
		y := v_1
		v.reset(OpNeqPtr)
		v0 := b.NewValue0(v.Pos, OpITab, typ.Uintptr)
		v0.AddArg(x)
		v1 := b.NewValue0(v.Pos, OpITab, typ.Uintptr)
		v1.AddArg(y)
		v.AddArg2(v0, v1)
		return true
	}
}
func rewriteValuegeneric_OpNeqPtr(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (NeqPtr x x)
	// result: (ConstBool [false])
	for {
		x := v_0
		if x != v_1 {
			break
		}
		v.reset(OpConstBool)
		v.AuxInt = boolToAuxInt(false)
		return true
	}
	// match: (NeqPtr (Addr {x} _) (Addr {y} _))
	// result: (ConstBool [x != y])
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpAddr {
				continue
			}
			x := auxToSym(v_0.Aux)
			if v_1.Op != OpAddr {
				continue
			}
			y := auxToSym(v_1.Aux)
			v.reset(OpConstBool)
			v.AuxInt = boolToAuxInt(x != y)
			return true
		}
		break
	}
	// match: (NeqPtr (Addr {x} _) (OffPtr [o] (Addr {y} _)))
	// result: (ConstBool [x != y || o != 0])
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpAddr {
				continue
			}
			x := auxToSym(v_0.Aux)
			if v_1.Op != OpOffPtr {
				continue
			}
			o := auxIntToInt64(v_1.AuxInt)
			v_1_0 := v_1.Args[0]
			if v_1_0.Op != OpAddr {
				continue
			}
			y := auxToSym(v_1_0.Aux)
			v.reset(OpConstBool)
			v.AuxInt = boolToAuxInt(x != y || o != 0)
			return true
		}
		break
	}
	// match: (NeqPtr (OffPtr [o1] (Addr {x} _)) (OffPtr [o2] (Addr {y} _)))
	// result: (ConstBool [x != y || o1 != o2])
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpOffPtr {
				continue
			}
			o1 := auxIntToInt64(v_0.AuxInt)
			v_0_0 := v_0.Args[0]
			if v_0_0.Op != OpAddr {
				continue
			}
			x := auxToSym(v_0_0.Aux)
			if v_1.Op != OpOffPtr {
				continue
			}
			o2 := auxIntToInt64(v_1.AuxInt)
			v_1_0 := v_1.Args[0]
			if v_1_0.Op != OpAddr {
				continue
			}
			y := auxToSym(v_1_0.Aux)
			v.reset(OpConstBool)
			v.AuxInt = boolToAuxInt(x != y || o1 != o2)
			return true
		}
		break
	}
	// match: (NeqPtr (LocalAddr {x} _ _) (LocalAddr {y} _ _))
	// result: (ConstBool [x != y])
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpLocalAddr {
				continue
			}
			x := auxToSym(v_0.Aux)
			if v_1.Op != OpLocalAddr {
				continue
			}
			y := auxToSym(v_1.Aux)
			v.reset(OpConstBool)
			v.AuxInt = boolToAuxInt(x != y)
			return true
		}
		break
	}
	// match: (NeqPtr (LocalAddr {x} _ _) (OffPtr [o] (LocalAddr {y} _ _)))
	// result: (ConstBool [x != y || o != 0])
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpLocalAddr {
				continue
			}
			x := auxToSym(v_0.Aux)
			if v_1.Op != OpOffPtr {
				continue
			}
			o := auxIntToInt64(v_1.AuxInt)
			v_1_0 := v_1.Args[0]
			if v_1_0.Op != OpLocalAddr {
				continue
			}
			y := auxToSym(v_1_0.Aux)
			v.reset(OpConstBool)
			v.AuxInt = boolToAuxInt(x != y || o != 0)
			return true
		}
		break
	}
	// match: (NeqPtr (OffPtr [o1] (LocalAddr {x} _ _)) (OffPtr [o2] (LocalAddr {y} _ _)))
	// result: (ConstBool [x != y || o1 != o2])
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpOffPtr {
				continue
			}
			o1 := auxIntToInt64(v_0.AuxInt)
			v_0_0 := v_0.Args[0]
			if v_0_0.Op != OpLocalAddr {
				continue
			}
			x := auxToSym(v_0_0.Aux)
			if v_1.Op != OpOffPtr {
				continue
			}
			o2 := auxIntToInt64(v_1.AuxInt)
			v_1_0 := v_1.Args[0]
			if v_1_0.Op != OpLocalAddr {
				continue
			}
			y := auxToSym(v_1_0.Aux)
			v.reset(OpConstBool)
			v.AuxInt = boolToAuxInt(x != y || o1 != o2)
			return true
		}
		break
	}
	// match: (NeqPtr (OffPtr [o1] p1) p2)
	// cond: isSamePtr(p1, p2)
	// result: (ConstBool [o1 != 0])
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpOffPtr {
				continue
			}
			o1 := auxIntToInt64(v_0.AuxInt)
			p1 := v_0.Args[0]
			p2 := v_1
			if !(isSamePtr(p1, p2)) {
				continue
			}
			v.reset(OpConstBool)
			v.AuxInt = boolToAuxInt(o1 != 0)
			return true
		}
		break
	}
	// match: (NeqPtr (OffPtr [o1] p1) (OffPtr [o2] p2))
	// cond: isSamePtr(p1, p2)
	// result: (ConstBool [o1 != o2])
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpOffPtr {
				continue
			}
			o1 := auxIntToInt64(v_0.AuxInt)
			p1 := v_0.Args[0]
			if v_1.Op != OpOffPtr {
				continue
			}
			o2 := auxIntToInt64(v_1.AuxInt)
			p2 := v_1.Args[0]
			if !(isSamePtr(p1, p2)) {
				continue
			}
			v.reset(OpConstBool)
			v.AuxInt = boolToAuxInt(o1 != o2)
			return true
		}
		break
	}
	// match: (NeqPtr (Const32 [c]) (Const32 [d]))
	// result: (ConstBool [c != d])
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpConst32 {
				continue
			}
			c := auxIntToInt32(v_0.AuxInt)
			if v_1.Op != OpConst32 {
				continue
			}
			d := auxIntToInt32(v_1.AuxInt)
			v.reset(OpConstBool)
			v.AuxInt = boolToAuxInt(c != d)
			return true
		}
		break
	}
	// match: (NeqPtr (Const64 [c]) (Const64 [d]))
	// result: (ConstBool [c != d])
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpConst64 {
				continue
			}
			c := auxIntToInt64(v_0.AuxInt)
			if v_1.Op != OpConst64 {
				continue
			}
			d := auxIntToInt64(v_1.AuxInt)
			v.reset(OpConstBool)
			v.AuxInt = boolToAuxInt(c != d)
			return true
		}
		break
	}
	// match: (NeqPtr (Convert (Addr {x} _) _) (Addr {y} _))
	// result: (ConstBool [x!=y])
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpConvert {
				continue
			}
			v_0_0 := v_0.Args[0]
			if v_0_0.Op != OpAddr {
				continue
			}
			x := auxToSym(v_0_0.Aux)
			if v_1.Op != OpAddr {
				continue
			}
			y := auxToSym(v_1.Aux)
			v.reset(OpConstBool)
			v.AuxInt = boolToAuxInt(x != y)
			return true
		}
		break
	}
	// match: (NeqPtr (LocalAddr _ _) (Addr _))
	// result: (ConstBool [true])
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpLocalAddr || v_1.Op != OpAddr {
				continue
			}
			v.reset(OpConstBool)
			v.AuxInt = boolToAuxInt(true)
			return true
		}
		break
	}
	// match: (NeqPtr (OffPtr (LocalAddr _ _)) (Addr _))
	// result: (ConstBool [true])
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpOffPtr {
				continue
			}
			v_0_0 := v_0.Args[0]
			if v_0_0.Op != OpLocalAddr || v_1.Op != OpAddr {
				continue
			}
			v.reset(OpConstBool)
			v.AuxInt = boolToAuxInt(true)
			return true
		}
		break
	}
	// match: (NeqPtr (LocalAddr _ _) (OffPtr (Addr _)))
	// result: (ConstBool [true])
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpLocalAddr || v_1.Op != OpOffPtr {
				continue
			}
			v_1_0 := v_1.Args[0]
			if v_1_0.Op != OpAddr {
				continue
			}
			v.reset(OpConstBool)
			v.AuxInt = boolToAuxInt(true)
			return true
		}
		break
	}
	// match: (NeqPtr (OffPtr (LocalAddr _ _)) (OffPtr (Addr _)))
	// result: (ConstBool [true])
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpOffPtr {
				continue
			}
			v_0_0 := v_0.Args[0]
			if v_0_0.Op != OpLocalAddr || v_1.Op != OpOffPtr {
				continue
			}
			v_1_0 := v_1.Args[0]
			if v_1_0.Op != OpAddr {
				continue
			}
			v.reset(OpConstBool)
			v.AuxInt = boolToAuxInt(true)
			return true
		}
		break
	}
	// match: (NeqPtr (AddPtr p1 o1) p2)
	// cond: isSamePtr(p1, p2)
	// result: (IsNonNil o1)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpAddPtr {
				continue
			}
			o1 := v_0.Args[1]
			p1 := v_0.Args[0]
			p2 := v_1
			if !(isSamePtr(p1, p2)) {
				continue
			}
			v.reset(OpIsNonNil)
			v.AddArg(o1)
			return true
		}
		break
	}
	// match: (NeqPtr (Const32 [0]) p)
	// result: (IsNonNil p)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpConst32 || auxIntToInt32(v_0.AuxInt) != 0 {
				continue
			}
			p := v_1
			v.reset(OpIsNonNil)
			v.AddArg(p)
			return true
		}
		break
	}
	// match: (NeqPtr (Const64 [0]) p)
	// result: (IsNonNil p)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpConst64 || auxIntToInt64(v_0.AuxInt) != 0 {
				continue
			}
			p := v_1
			v.reset(OpIsNonNil)
			v.AddArg(p)
			return true
		}
		break
	}
	// match: (NeqPtr (ConstNil) p)
	// result: (IsNonNil p)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpConstNil {
				continue
			}
			p := v_1
			v.reset(OpIsNonNil)
			v.AddArg(p)
			return true
		}
		break
	}
	return false
}
func rewriteValuegeneric_OpNeqSlice(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (NeqSlice x y)
	// result: (NeqPtr (SlicePtr x) (SlicePtr y))
	for {
		x := v_0
		y := v_1
		v.reset(OpNeqPtr)
		v0 := b.NewValue0(v.Pos, OpSlicePtr, typ.BytePtr)
		v0.AddArg(x)
		v1 := b.NewValue0(v.Pos, OpSlicePtr, typ.BytePtr)
		v1.AddArg(y)
		v.AddArg2(v0, v1)
		return true
	}
}
func rewriteValuegeneric_OpNilCheck(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	fe := b.Func.fe
	// match: (NilCheck ptr:(GetG mem) mem)
	// result: ptr
	for {
		ptr := v_0
		if ptr.Op != OpGetG {
			break
		}
		mem := ptr.Args[0]
		if mem != v_1 {
			break
		}
		v.copyOf(ptr)
		return true
	}
	// match: (NilCheck ptr:(SelectN [0] call:(StaticLECall _ _)) _)
	// cond: isSameCall(call.Aux, "runtime.newobject") && warnRule(fe.Debug_checknil(), v, "removed nil check")
	// result: ptr
	for {
		ptr := v_0
		if ptr.Op != OpSelectN || auxIntToInt64(ptr.AuxInt) != 0 {
			break
		}
		call := ptr.Args[0]
		if call.Op != OpStaticLECall || len(call.Args) != 2 || !(isSameCall(call.Aux, "runtime.newobject") && warnRule(fe.Debug_checknil(), v, "removed nil check")) {
			break
		}
		v.copyOf(ptr)
		return true
	}
	// match: (NilCheck ptr:(OffPtr (SelectN [0] call:(StaticLECall _ _))) _)
	// cond: isSameCall(call.Aux, "runtime.newobject") && warnRule(fe.Debug_checknil(), v, "removed nil check")
	// result: ptr
	for {
		ptr := v_0
		if ptr.Op != OpOffPtr {
			break
		}
		ptr_0 := ptr.Args[0]
		if ptr_0.Op != OpSelectN || auxIntToInt64(ptr_0.AuxInt) != 0 {
			break
		}
		call := ptr_0.Args[0]
		if call.Op != OpStaticLECall || len(call.Args) != 2 || !(isSameCall(call.Aux, "runtime.newobject") && warnRule(fe.Debug_checknil(), v, "removed nil check")) {
			break
		}
		v.copyOf(ptr)
		return true
	}
	// match: (NilCheck ptr:(Addr {_} (SB)) _)
	// result: ptr
	for {
		ptr := v_0
		if ptr.Op != OpAddr {
			break
		}
		ptr_0 := ptr.Args[0]
		if ptr_0.Op != OpSB {
			break
		}
		v.copyOf(ptr)
		return true
	}
	// match: (NilCheck ptr:(Convert (Addr {_} (SB)) _) _)
	// result: ptr
	for {
		ptr := v_0
		if ptr.Op != OpConvert {
			break
		}
		ptr_0 := ptr.Args[0]
		if ptr_0.Op != OpAddr {
			break
		}
		ptr_0_0 := ptr_0.Args[0]
		if ptr_0_0.Op != OpSB {
			break
		}
		v.copyOf(ptr)
		return true
	}
	// match: (NilCheck ptr:(NilCheck _ _) _ )
	// result: ptr
	for {
		ptr := v_0
		if ptr.Op != OpNilCheck {
			break
		}
		v.copyOf(ptr)
		return true
	}
	return false
}
func rewriteValuegeneric_OpNot(v *Value) bool {
	v_0 := v.Args[0]
	// match: (Not (ConstBool [c]))
	// result: (ConstBool [!c])
	for {
		if v_0.Op != OpConstBool {
			break
		}
		c := auxIntToBool(v_0.AuxInt)
		v.reset(OpConstBool)
		v.AuxInt = boolToAuxInt(!c)
		return true
	}
	// match: (Not (Eq64 x y))
	// result: (Neq64 x y)
	for {
		if v_0.Op != OpEq64 {
			break
		}
		y := v_0.Args[1]
		x := v_0.Args[0]
		v.reset(OpNeq64)
		v.AddArg2(x, y)
		return true
	}
	// match: (Not (Eq32 x y))
	// result: (Neq32 x y)
	for {
		if v_0.Op != OpEq32 {
			break
		}
		y := v_0.Args[1]
		x := v_0.Args[0]
		v.reset(OpNeq32)
		v.AddArg2(x, y)
		return true
	}
	// match: (Not (Eq16 x y))
	// result: (Neq16 x y)
	for {
		if v_0.Op != OpEq16 {
			break
		}
		y := v_0.Args[1]
		x := v_0.Args[0]
		v.reset(OpNeq16)
		v.AddArg2(x, y)
		return true
	}
	// match: (Not (Eq8 x y))
	// result: (Neq8 x y)
	for {
		if v_0.Op != OpEq8 {
			break
		}
		y := v_0.Args[1]
		x := v_0.Args[0]
		v.reset(OpNeq8)
		v.AddArg2(x, y)
		return true
	}
	// match: (Not (EqB x y))
	// result: (NeqB x y)
	for {
		if v_0.Op != OpEqB {
			break
		}
		y := v_0.Args[1]
		x := v_0.Args[0]
		v.reset(OpNeqB)
		v.AddArg2(x, y)
		return true
	}
	// match: (Not (EqPtr x y))
	// result: (NeqPtr x y)
	for {
		if v_0.Op != OpEqPtr {
			break
		}
		y := v_0.Args[1]
		x := v_0.Args[0]
		v.reset(OpNeqPtr)
		v.AddArg2(x, y)
		return true
	}
	// match: (Not (Eq64F x y))
	// result: (Neq64F x y)
	for {
		if v_0.Op != OpEq64F {
			break
		}
		y := v_0.Args[1]
		x := v_0.Args[0]
		v.reset(OpNeq64F)
		v.AddArg2(x, y)
		return true
	}
	// match: (Not (Eq32F x y))
	// result: (Neq32F x y)
	for {
		if v_0.Op != OpEq32F {
			break
		}
		y := v_0.Args[1]
		x := v_0.Args[0]
		v.reset(OpNeq32F)
		v.AddArg2(x, y)
		return true
	}
	// match: (Not (Neq64 x y))
	// result: (Eq64 x y)
	for {
		if v_0.Op != OpNeq64 {
			break
		}
		y := v_0.Args[1]
		x := v_0.Args[0]
		v.reset(OpEq64)
		v.AddArg2(x, y)
		return true
	}
	// match: (Not (Neq32 x y))
	// result: (Eq32 x y)
	for {
		if v_0.Op != OpNeq32 {
			break
		}
		y := v_0.Args[1]
		x := v_0.Args[0]
		v.reset(OpEq32)
		v.AddArg2(x, y)
		return true
	}
	// match: (Not (Neq16 x y))
	// result: (Eq16 x y)
	for {
		if v_0.Op != OpNeq16 {
			break
		}
		y := v_0.Args[1]
		x := v_0.Args[0]
		v.reset(OpEq16)
		v.AddArg2(x, y)
		return true
	}
	// match: (Not (Neq8 x y))
	// result: (Eq8 x y)
	for {
		if v_0.Op != OpNeq8 {
			break
		}
		y := v_0.Args[1]
		x := v_0.Args[0]
		v.reset(OpEq8)
		v.AddArg2(x, y)
		return true
	}
	// match: (Not (NeqB x y))
	// result: (EqB x y)
	for {
		if v_0.Op != OpNeqB {
			break
		}
		y := v_0.Args[1]
		x := v_0.Args[0]
		v.reset(OpEqB)
		v.AddArg2(x, y)
		return true
	}
	// match: (Not (NeqPtr x y))
	// result: (EqPtr x y)
	for {
		if v_0.Op != OpNeqPtr {
			break
		}
		y := v_0.Args[1]
		x := v_0.Args[0]
		v.reset(OpEqPtr)
		v.AddArg2(x, y)
		return true
	}
	// match: (Not (Neq64F x y))
	// result: (Eq64F x y)
	for {
		if v_0.Op != OpNeq64F {
			break
		}
		y := v_0.Args[1]
		x := v_0.Args[0]
		v.reset(OpEq64F)
		v.AddArg2(x, y)
		return true
	}
	// match: (Not (Neq32F x y))
	// result: (Eq32F x y)
	for {
		if v_0.Op != OpNeq32F {
			break
		}
		y := v_0.Args[1]
		x := v_0.Args[0]
		v.reset(OpEq32F)
		v.AddArg2(x, y)
		return true
	}
	// match: (Not (Less64 x y))
	// result: (Leq64 y x)
	for {
		if v_0.Op != OpLess64 {
			break
		}
		y := v_0.Args[1]
		x := v_0.Args[0]
		v.reset(OpLeq64)
		v.AddArg2(y, x)
		return true
	}
	// match: (Not (Less32 x y))
	// result: (Leq32 y x)
	for {
		if v_0.Op != OpLess32 {
			break
		}
		y := v_0.Args[1]
		x := v_0.Args[0]
		v.reset(OpLeq32)
		v.AddArg2(y, x)
		return true
	}
	// match: (Not (Less16 x y))
	// result: (Leq16 y x)
	for {
		if v_0.Op != OpLess16 {
			break
		}
		y := v_0.Args[1]
		x := v_0.Args[0]
		v.reset(OpLeq16)
		v.AddArg2(y, x)
		return true
	}
	// match: (Not (Less8 x y))
	// result: (Leq8 y x)
	for {
		if v_0.Op != OpLess8 {
			break
		}
		y := v_0.Args[1]
		x := v_0.Args[0]
		v.reset(OpLeq8)
		v.AddArg2(y, x)
		return true
	}
	// match: (Not (Less64U x y))
	// result: (Leq64U y x)
	for {
		if v_0.Op != OpLess64U {
			break
		}
		y := v_0.Args[1]
		x := v_0.Args[0]
		v.reset(OpLeq64U)
		v.AddArg2(y, x)
		return true
	}
	// match: (Not (Less32U x y))
	// result: (Leq32U y x)
	for {
		if v_0.Op != OpLess32U {
			break
		}
		y := v_0.Args[1]
		x := v_0.Args[0]
		v.reset(OpLeq32U)
		v.AddArg2(y, x)
		return true
	}
	// match: (Not (Less16U x y))
	// result: (Leq16U y x)
	for {
		if v_0.Op != OpLess16U {
			break
		}
		y := v_0.Args[1]
		x := v_0.Args[0]
		v.reset(OpLeq16U)
		v.AddArg2(y, x)
		return true
	}
	// match: (Not (Less8U x y))
	// result: (Leq8U y x)
	for {
		if v_0.Op != OpLess8U {
			break
		}
		y := v_0.Args[1]
		x := v_0.Args[0]
		v.reset(OpLeq8U)
		v.AddArg2(y, x)
		return true
	}
	// match: (Not (Leq64 x y))
	// result: (Less64 y x)
	for {
		if v_0.Op != OpLeq64 {
			break
		}
		y := v_0.Args[1]
		x := v_0.Args[0]
		v.reset(OpLess64)
		v.AddArg2(y, x)
		return true
	}
	// match: (Not (Leq32 x y))
	// result: (Less32 y x)
	for {
		if v_0.Op != OpLeq32 {
			break
		}
		y := v_0.Args[1]
		x := v_0.Args[0]
		v.reset(OpLess32)
		v.AddArg2(y, x)
		return true
	}
	// match: (Not (Leq16 x y))
	// result: (Less16 y x)
	for {
		if v_0.Op != OpLeq16 {
			break
		}
		y := v_0.Args[1]
		x := v_0.Args[0]
		v.reset(OpLess16)
		v.AddArg2(y, x)
		return true
	}
	// match: (Not (Leq8 x y))
	// result: (Less8 y x)
	for {
		if v_0.Op != OpLeq8 {
			break
		}
		y := v_0.Args[1]
		x := v_0.Args[0]
		v.reset(OpLess8)
		v.AddArg2(y, x)
		return true
	}
	// match: (Not (Leq64U x y))
	// result: (Less64U y x)
	for {
		if v_0.Op != OpLeq64U {
			break
		}
		y := v_0.Args[1]
		x := v_0.Args[0]
		v.reset(OpLess64U)
		v.AddArg2(y, x)
		return true
	}
	// match: (Not (Leq32U x y))
	// result: (Less32U y x)
	for {
		if v_0.Op != OpLeq32U {
			break
		}
		y := v_0.Args[1]
		x := v_0.Args[0]
		v.reset(OpLess32U)
		v.AddArg2(y, x)
		return true
	}
	// match: (Not (Leq16U x y))
	// result: (Less16U y x)
	for {
		if v_0.Op != OpLeq16U {
			break
		}
		y := v_0.Args[1]
		x := v_0.Args[0]
		v.reset(OpLess16U)
		v.AddArg2(y, x)
		return true
	}
	// match: (Not (Leq8U x y))
	// result: (Less8U y x)
	for {
		if v_0.Op != OpLeq8U {
			break
		}
		y := v_0.Args[1]
		x := v_0.Args[0]
		v.reset(OpLess8U)
		v.AddArg2(y, x)
		return true
	}
	return false
}
func rewriteValuegeneric_OpOffPtr(v *Value) bool {
	v_0 := v.Args[0]
	// match: (OffPtr (OffPtr p [y]) [x])
	// result: (OffPtr p [x+y])
	for {
		x := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpOffPtr {
			break
		}
		y := auxIntToInt64(v_0.AuxInt)
		p := v_0.Args[0]
		v.reset(OpOffPtr)
		v.AuxInt = int64ToAuxInt(x + y)
		v.AddArg(p)
		return true
	}
	// match: (OffPtr p [0])
	// cond: v.Type.Compare(p.Type) == types.CMPeq
	// result: p
	for {
		if auxIntToInt64(v.AuxInt) != 0 {
			break
		}
		p := v_0
		if !(v.Type.Compare(p.Type) == types.CMPeq) {
			break
		}
		v.copyOf(p)
		return true
	}
	return false
}
func rewriteValuegeneric_OpOr16(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	config := b.Func.Config
	// match: (Or16 (Const16 [c]) (Const16 [d]))
	// result: (Const16 [c|d])
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpConst16 {
				continue
			}
			c := auxIntToInt16(v_0.AuxInt)
			if v_1.Op != OpConst16 {
				continue
			}
			d := auxIntToInt16(v_1.AuxInt)
			v.reset(OpConst16)
			v.AuxInt = int16ToAuxInt(c | d)
			return true
		}
		break
	}
	// match: (Or16 <t> (Com16 x) (Com16 y))
	// result: (Com16 (And16 <t> x y))
	for {
		t := v.Type
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpCom16 {
				continue
			}
			x := v_0.Args[0]
			if v_1.Op != OpCom16 {
				continue
			}
			y := v_1.Args[0]
			v.reset(OpCom16)
			v0 := b.NewValue0(v.Pos, OpAnd16, t)
			v0.AddArg2(x, y)
			v.AddArg(v0)
			return true
		}
		break
	}
	// match: (Or16 x x)
	// result: x
	for {
		x := v_0
		if x != v_1 {
			break
		}
		v.copyOf(x)
		return true
	}
	// match: (Or16 (Const16 [0]) x)
	// result: x
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpConst16 || auxIntToInt16(v_0.AuxInt) != 0 {
				continue
			}
			x := v_1
			v.copyOf(x)
			return true
		}
		break
	}
	// match: (Or16 (Const16 [-1]) _)
	// result: (Const16 [-1])
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpConst16 || auxIntToInt16(v_0.AuxInt) != -1 {
				continue
			}
			v.reset(OpConst16)
			v.AuxInt = int16ToAuxInt(-1)
			return true
		}
		break
	}
	// match: (Or16 (Com16 x) x)
	// result: (Const16 [-1])
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpCom16 {
				continue
			}
			x := v_0.Args[0]
			if x != v_1 {
				continue
			}
			v.reset(OpConst16)
			v.AuxInt = int16ToAuxInt(-1)
			return true
		}
		break
	}
	// match: (Or16 x (Or16 x y))
	// result: (Or16 x y)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			if v_1.Op != OpOr16 {
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
				v.reset(OpOr16)
				v.AddArg2(x, y)
				return true
			}
		}
		break
	}
	// match: (Or16 (And16 x (Const16 [c2])) (Const16 <t> [c1]))
	// cond: ^(c1 | c2) == 0
	// result: (Or16 (Const16 <t> [c1]) x)
	for
```