Response:
My thought process to answer the request goes like this:

1. **Understand the Goal:** The core request is to analyze a Go code snippet from `rewritegeneric.go` and describe its function, infer its higher-level purpose, provide examples, and summarize its role within the larger file. The "part 18 of 26" hints at a specific stage in a larger compiler optimization or transformation process.

2. **Identify the Code's Scope:** The provided code consists of two Go functions: `rewriteValuegeneric_OpOr64` and `rewriteValuegeneric_OpOr8`. The naming convention `rewriteValuegeneric_Op...` strongly suggests that this code is part of a rewrite rule system for the SSA (Static Single Assignment) intermediate representation used in the Go compiler. Specifically, these functions are likely responsible for optimizing `Or` operations on 64-bit and 8-bit integers.

3. **Analyze Individual Functions:**

   * **`rewriteValuegeneric_OpOr64`:**  I see a series of `for` loops with `if` conditions inside. Each loop checks for specific patterns of SSA operations (`OpOr64`, `OpConst64`, `OpLsh64x...`, `OpRsh64Ux...`, `OpSub...`, etc.) involving `Or` operations on 64-bit values. The `reset` and `AddArg` calls indicate that the code is transforming these patterns into potentially more efficient equivalent operations. The presence of `OpRotateLeft64` as a target operation strongly suggests that this function is looking for opportunities to optimize bitwise OR operations into rotate left operations. The `canRotate` and `shiftIsBounded` conditions hint at architecture-specific optimizations or checks for valid shift amounts.

   * **`rewriteValuegeneric_OpOr8`:** This function mirrors the structure of `rewriteValuegeneric_OpOr64`, but it operates on 8-bit integers (`OpOr8`, `OpConst8`, `OpLsh8x...`, `OpRsh8Ux...`, etc.). The same logic of pattern matching and transformation applies, aiming to optimize 8-bit OR operations, including potential transformations into `OpRotateLeft8`. The inclusion of complementary operations like `OpCom8` (complement) and the pattern `(Com8 x) (Com8 y)` being rewritten to `Com8 (And8 x y)` (De Morgan's Law) indicates broader logical optimizations.

4. **Infer Higher-Level Functionality:** Based on the analysis of the individual functions, I can infer that `rewritegeneric.go` (or at least this part of it) implements *peephole optimizations* on the SSA representation. It looks for common patterns of bitwise operations and replaces them with more efficient or canonical forms. The focus on `Or` and the introduction of `RotateLeft` operations suggest that these optimizations are geared towards improving the performance of bit manipulation tasks.

5. **Construct Examples:** To illustrate the transformations, I create simple Go code snippets that would generate the SSA patterns the rewrite rules are targeting. For instance, the `Or64` with left and right shifts that sum to 64 is a classic pattern for a rotate operation. I provide the *input* Go code and the *expected optimized* Go code (or the corresponding SSA operation).

6. **Address Command-Line Arguments and Common Mistakes:** I realize that the provided code snippet doesn't directly handle command-line arguments. This part of the Go compiler typically operates internally. Regarding common mistakes, a developer modifying these rules might introduce errors in the pattern matching logic or the transformation logic, leading to incorrect or inefficient code generation. I include an example of a potentially incorrect transformation to illustrate this.

7. **Summarize the Function:**  Finally, I synthesize the information gathered into a concise summary, emphasizing the pattern matching and replacement nature of the code and its role in SSA optimization. I also highlight the specific optimizations related to rotate operations. Given the "part 18 of 26" context, I emphasize its place within a larger sequence of compiler passes.

8. **Refine and Organize:** I review my answer to ensure clarity, accuracy, and proper formatting. I use clear headings and bullet points to organize the information logically. I double-check the Go code examples for correctness.

By following these steps, I can effectively analyze the provided code snippet and generate a comprehensive and informative response that addresses all aspects of the user's request.


这个go语言实现文件 `go/src/cmd/compile/internal/ssa/rewritegeneric.go` 的一部分，主要负责对SSA（Static Single Assignment）中间表示进行**通用化的重写规则**定义。

具体来说，这段代码定义了针对 **`Or` (或) 操作** 的重写规则，旨在将某些特定的 `Or` 操作模式转换为更简洁或更高效的操作。  由于这是第 18 部分，我们可以推断前面和后面的部分可能定义了针对其他 SSA 操作的重写规则。

**这段代码的主要功能可以归纳为：**

1. **模式匹配 (Pattern Matching):**  它定义了一系列模式，用于匹配SSA图中特定的 `Or` 操作结构。这些模式涵盖了不同类型的操作数，例如常量、位移操作、取反操作等。
2. **条件判断 (Condition Evaluation):**  对于每个匹配到的模式，它会执行一些条件判断。这些条件可能涉及到常量的值、操作数的类型、以及编译器配置信息（例如 `canRotate` 判断目标架构是否支持旋转指令）。
3. **重写规则 (Rewriting Rules):**  如果模式匹配成功且条件满足，代码会将当前的 `Or` 操作节点重置为新的操作，并添加新的参数。这实际上是将一种运算模式转换成另一种等价但可能更优的模式。

**这段代码很可能实现了以下 Go 语言功能的优化：**

**1. 位旋转优化:**

这段代码的核心目标之一是识别可以转换为**位旋转操作**的 `Or` 运算。位旋转在某些架构上比单独的移位和或运算更高效。

```go
// 假设输入 SSA 代码表示了这样的 Go 代码：
a := x << s | x >> (64 - s)  // 对于 uint64 类型
```

代码中的多个 `match` 块，例如：

```go
// match: (Or64 left:(Lsh64x64 x z:(Const64 <t> [c])) right:(Rsh64Ux64 x (Const64 [d])))
// cond: c < 64 && d == 64-c && canRotate(config, 64)
// result: (RotateLeft64 x z)
```

就对应了这种优化。

**Go 代码示例：**

```go
package main

import "fmt"

func main() {
	var x uint64 = 0b0000000100000000
	var s uint64 = 1

	// 原始代码
	rotated := (x << s) | (x >> (64 - s))
	fmt.Printf("Rotated: %b\n", rotated)
}
```

**假设的 SSA 输入 (简化)：**

```
v1 = Lsh64x64 x const_1
v2 = Sub64 const_64 const_1
v3 = Rsh64Ux64 x v2
v4 = Or64 v1 v3
```

**假设的 SSA 输出 (优化后)：**

```
v4 = RotateLeft64 x const_1
```

**2. 常量折叠和逻辑简化:**

代码中还包含针对常量 `Or` 操作的优化：

```go
// match: (Or64 (Const64 [c]) (Const64 [d]))
// result: (Const64 [c|d])
```

以及利用德摩根定律简化逻辑表达式：

```go
// match: (Or64 <t> (Com64 x) (Com64 y))
// result: (Com64 (And64 <t> x y))
```

**Go 代码示例 (常量折叠):**

```go
package main

import "fmt"

func main() {
	result := 1 | 2
	fmt.Println(result) // 输出 3
}
```

编译器在 SSA 阶段会直接计算 `1 | 2` 的结果。

**Go 代码示例 (德摩根定律):**

```go
package main

import "fmt"

func main() {
	x := 5
	y := 3
	result := (^x) | (^y)
	// 等价于: result := ^(x & y)
	fmt.Println(result)
}
```

编译器可能会将 `(^x) | (^y)` 的 SSA 表示优化为 `^(x & y)`。

**3. 消除冗余 `Or` 操作:**

```go
// match: (Or64 x x)
// result: x
```

如果 `Or` 操作的两个操作数相同，则结果就是该操作数本身。

**Go 代码示例:**

```go
package main

import "fmt"

func main() {
	x := 10
	result := x | x
	fmt.Println(result) // 输出 10
}
```

**4. 与零或与全1的优化:**

```go
// match: (Or64 (Const64 [0]) x)
// result: x

// match: (Or64 (Const64 [-1]) _)
// result: (Const64 [-1])
```

任何值与 0 进行 `Or` 操作，结果是其本身。任何值与 -1 (所有位都是 1) 进行 `Or` 操作，结果是 -1。

**命令行参数的具体处理：**

这段代码本身不直接处理命令行参数。它是 Go 编译器内部的一部分，在编译过程中被调用。Go 编译器的命令行参数处理在 `go/src/cmd/compile/main.go` 等文件中进行。

**使用者易犯错的点：**

由于这段代码是编译器内部的实现细节，一般的 Go 开发者不会直接接触到它，因此不容易犯错。但是，如果有人修改 Go 编译器，可能会在添加新的重写规则时犯错，例如：

* **模式匹配错误：**  定义的模式不正确，导致应该匹配的 SSA 结构没有被匹配到，或者错误地匹配了不应该匹配的结构。
* **条件判断错误：**  条件判断的逻辑错误，导致重写规则在不应该应用的情况下被应用，或者应该应用的情况下没有应用。
* **重写逻辑错误：**  将 SSA 节点重置为新的操作时，参数添加错误，导致生成的代码逻辑不正确。

**功能归纳 (作为第 18 部分)：**

作为 `rewritegeneric.go` 文件的第 18 部分，这段代码专注于 **`Or` 操作的通用化重写规则**。它通过模式匹配和条件判断，将各种 `Or` 操作的特定组合转换为更优的等价形式，例如位旋转、常量折叠、逻辑简化和冗余消除。这部分是 Go 编译器 SSA 优化过程中的一个环节，旨在提高最终生成代码的效率。 考虑到这是 26 部分中的一部分，可以推测这是一个逐步进行各种 SSA 操作优化的过程。  前面的部分可能处理了其他类型的操作，而后面的部分可能会处理更复杂的优化或与架构相关的优化。

### 提示词
```
这是路径为go/src/cmd/compile/internal/ssa/rewritegeneric.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第18部分，共26部分，请归纳一下它的功能
```

### 源代码
```go
right)) && canRotate(config, 64)) {
				continue
			}
			v.reset(OpRotateLeft64)
			v.AddArg2(x, z)
			return true
		}
		break
	}
	// match: (Or64 right:(Rsh64Ux16 x y) left:(Lsh64x16 x z:(Sub16 (Const16 [64]) y)))
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
	// match: (Or64 right:(Rsh64Ux8 x y) left:(Lsh64x8 x z:(Sub8 (Const8 [64]) y)))
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
func rewriteValuegeneric_OpOr8(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	config := b.Func.Config
	// match: (Or8 (Const8 [c]) (Const8 [d]))
	// result: (Const8 [c|d])
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
			v.AuxInt = int8ToAuxInt(c | d)
			return true
		}
		break
	}
	// match: (Or8 <t> (Com8 x) (Com8 y))
	// result: (Com8 (And8 <t> x y))
	for {
		t := v.Type
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpCom8 {
				continue
			}
			x := v_0.Args[0]
			if v_1.Op != OpCom8 {
				continue
			}
			y := v_1.Args[0]
			v.reset(OpCom8)
			v0 := b.NewValue0(v.Pos, OpAnd8, t)
			v0.AddArg2(x, y)
			v.AddArg(v0)
			return true
		}
		break
	}
	// match: (Or8 x x)
	// result: x
	for {
		x := v_0
		if x != v_1 {
			break
		}
		v.copyOf(x)
		return true
	}
	// match: (Or8 (Const8 [0]) x)
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
	// match: (Or8 (Const8 [-1]) _)
	// result: (Const8 [-1])
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpConst8 || auxIntToInt8(v_0.AuxInt) != -1 {
				continue
			}
			v.reset(OpConst8)
			v.AuxInt = int8ToAuxInt(-1)
			return true
		}
		break
	}
	// match: (Or8 (Com8 x) x)
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
	// match: (Or8 x (Or8 x y))
	// result: (Or8 x y)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			if v_1.Op != OpOr8 {
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
				v.reset(OpOr8)
				v.AddArg2(x, y)
				return true
			}
		}
		break
	}
	// match: (Or8 (And8 x (Const8 [c2])) (Const8 <t> [c1]))
	// cond: ^(c1 | c2) == 0
	// result: (Or8 (Const8 <t> [c1]) x)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpAnd8 {
				continue
			}
			_ = v_0.Args[1]
			v_0_0 := v_0.Args[0]
			v_0_1 := v_0.Args[1]
			for _i1 := 0; _i1 <= 1; _i1, v_0_0, v_0_1 = _i1+1, v_0_1, v_0_0 {
				x := v_0_0
				if v_0_1.Op != OpConst8 {
					continue
				}
				c2 := auxIntToInt8(v_0_1.AuxInt)
				if v_1.Op != OpConst8 {
					continue
				}
				t := v_1.Type
				c1 := auxIntToInt8(v_1.AuxInt)
				if !(^(c1 | c2) == 0) {
					continue
				}
				v.reset(OpOr8)
				v0 := b.NewValue0(v.Pos, OpConst8, t)
				v0.AuxInt = int8ToAuxInt(c1)
				v.AddArg2(v0, x)
				return true
			}
		}
		break
	}
	// match: (Or8 (Or8 i:(Const8 <t>) z) x)
	// cond: (z.Op != OpConst8 && x.Op != OpConst8)
	// result: (Or8 i (Or8 <t> z x))
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpOr8 {
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
				v.reset(OpOr8)
				v0 := b.NewValue0(v.Pos, OpOr8, t)
				v0.AddArg2(z, x)
				v.AddArg2(i, v0)
				return true
			}
		}
		break
	}
	// match: (Or8 (Const8 <t> [c]) (Or8 (Const8 <t> [d]) x))
	// result: (Or8 (Const8 <t> [c|d]) x)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpConst8 {
				continue
			}
			t := v_0.Type
			c := auxIntToInt8(v_0.AuxInt)
			if v_1.Op != OpOr8 {
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
				v.reset(OpOr8)
				v0 := b.NewValue0(v.Pos, OpConst8, t)
				v0.AuxInt = int8ToAuxInt(c | d)
				v.AddArg2(v0, x)
				return true
			}
		}
		break
	}
	// match: (Or8 (Lsh8x64 x z:(Const64 <t> [c])) (Rsh8Ux64 x (Const64 [d])))
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
	// match: (Or8 left:(Lsh8x64 x y) right:(Rsh8Ux64 x (Sub64 (Const64 [8]) y)))
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
	// match: (Or8 left:(Lsh8x32 x y) right:(Rsh8Ux32 x (Sub32 (Const32 [8]) y)))
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
	// match: (Or8 left:(Lsh8x16 x y) right:(Rsh8Ux16 x (Sub16 (Const16 [8]) y)))
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
	// match: (Or8 left:(Lsh8x8 x y) right:(Rsh8Ux8 x (Sub8 (Const8 [8]) y)))
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
	// match: (Or8 right:(Rsh8Ux64 x y) left:(Lsh8x64 x z:(Sub64 (Const64 [8]) y)))
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
	// match: (Or8 right:(Rsh8Ux32 x y) left:(Lsh8x32 x z:(Sub32 (Const32 [8]) y)))
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
	// match: (Or8 right:(Rsh8Ux16 x y) left:(Lsh8x16 x z:(Sub16 (Const16 [8]) y)))
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
	// match: (Or8 right:(Rsh8Ux8 x y) left:(Lsh8x8 x z:(Sub8 (Const8 [8]) y)))
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
func rewriteValuegeneric_OpOrB(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (OrB (Less64 (Const64 [c]) x) (Less64 x (Const64 [d])))
	// cond: c >= d
	// result: (Less64U (Const64 <x.Type> [c-d]) (Sub64 <x.Type> x (Const64 <x.Type> [d])))
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpLess64 {
				continue
			}
			x := v_0.Args[1]
			v_0_0 := v_0.Args[0]
			if v_0_0.Op != OpConst64 {
				continue
			}
			c := auxIntToInt64(v_0_0.AuxInt)
			if v_1.Op != OpLess64 {
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
			if !(c >= d) {
				continue
			}
			v.reset(OpLess64U)
			v0 := b.NewValue0(v.Pos, OpConst64, x.Type)
			v0.AuxInt = int64ToAuxInt(c - d)
			v1 := b.NewValue0(v.Pos, OpSub64, x.Type)
			v2 := b.NewValue0(v.Pos, OpConst64, x.Type)
			v2.AuxInt = int64ToAuxInt(d)
			v1.AddArg2(x, v2)
			v.AddArg2(v0, v1)
			return true
		}
		break
	}
	// match: (OrB (Leq64 (Const64 [c]) x) (Less64 x (Const64 [d])))
	// cond: c >= d
	// result: (Leq64U (Const64 <x.Type> [c-d]) (Sub64 <x.Type> x (Const64 <x.Type> [d])))
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpLeq64 {
				continue
			}
			x := v_0.Args[1]
			v_0_0 := v_0.Args[0]
			if v_0_0.Op != OpConst64 {
				continue
			}
			c := auxIntToInt64(v_0_0.AuxInt)
			if v_1.Op != OpLess64 {
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
			if !(c >= d) {
				continue
			}
			v.reset(OpLeq64U)
			v0 := b.NewValue0(v.Pos, OpConst64, x.Type)
			v0.AuxInt = int64ToAuxInt(c - d)
			v1 := b.NewValue0(v.Pos, OpSub64, x.Type)
			v2 := b.NewValue0(v.Pos, OpConst64, x.Type)
			v2.AuxInt = int64ToAuxInt(d)
			v1.AddArg2(x, v2)
			v.AddArg2(v0, v1)
			return true
		}
		break
	}
	// match: (OrB (Less32 (Const32 [c]) x) (Less32 x (Const32 [d])))
	// cond: c >= d
	// result: (Less32U (Const32 <x.Type> [c-d]) (Sub32 <x.Type> x (Const32 <x.Type> [d])))
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpLess32 {
				continue
			}
			x := v_0.Args[1]
			v_0_0 := v_0.Args[0]
			if v_0_0.Op != OpConst32 {
				continue
			}
			c := auxIntToInt32(v_0_0.AuxInt)
			if v_1.Op != OpLess32 {
				continue
			}
			_ = v_1.Args[1]
			if x != v_1.Args[0] {
				continue
			}
			v_1_1 := v_1.Args[1]
			if v_1_1.Op != OpConst32 {
				continue
			}
			d := auxIntToInt32(v_1_1.AuxInt)
			if !(c >= d) {
				continue
			}
			v.reset(OpLess32U)
			v0 := b.NewValue0(v.Pos, OpConst32, x.Type)
			v0.AuxInt = int32ToAuxInt(c - d)
			v1 := b.NewValue0(v.Pos, OpSub32, x.Type)
			v2 := b.NewValue0(v.Pos, OpConst32, x.Type)
			v2.AuxInt = int32ToAuxInt(d)
			v1.AddArg2(x, v2)
			v.AddArg2(v0, v1)
			return true
		}
		break
	}
	// match: (OrB (Leq32 (Const32 [c]) x) (Less32 x (Const32 [d])))
	// cond: c >= d
	// result: (Leq32U (Const32 <x.Type> [c-d]) (Sub32 <x.Type> x (Const32 <x.Type> [d])))
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpLeq32 {
				continue
			}
			x := v_0.Args[1]
			v_0_0 := v_0.Args[0]
			if v_0_0.Op != OpConst32 {
				continue
			}
			c := auxIntToInt32(v_0_0.AuxInt)
			if v_1.Op != OpLess32 {
				continue
			}
			_ = v_1.Args[1]
			if x != v_1.Args[0] {
				continue
			}
			v_1_1 := v_1.Args[1]
			if v_1_1.Op != OpConst32 {
				continue
			}
			d := auxIntToInt32(v_1_1.AuxInt)
			if !(c >= d) {
				continue
			}
			v.reset(OpLeq32U)
			v0 := b.NewValue0(v.Pos, OpConst32, x.Type)
			v0.AuxInt = int32ToAuxInt(c - d)
			v1 := b.NewValue0(v.Pos, OpSub32, x.Type)
			v2 := b.NewValue0(v.Pos, OpConst32, x.Type)
			v2.AuxInt = int32ToAuxInt(d)
			v1.AddArg2(x, v2)
			v.AddArg2(v0, v1)
			return true
		}
		break
	}
	// match: (OrB (Less16 (Const16 [c]) x) (Less16 x (Const16 [d])))
	// cond: c >= d
	// result: (Less16U (Const16 <x.Type> [c-d]) (Sub16 <x.Type> x (Const16 <x.Type> [d])))
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpLess16 {
				continue
			}
			x := v_0.Args[1]
			v_0_0 := v_0.Args[0]
			if v_0_0.Op != OpConst16 {
				continue
			}
			c := auxIntToInt16(v_0_0.AuxInt)
			if v_1.Op != OpLess16 {
				continue
			}
			_ = v_1.Args[1]
			if x != v_1.Args[0] {
				continue
			}
			v_1_1 := v_1.Args[1]
			if v_1_1.Op != OpConst16 {
				continue
			}
			d := auxIntToInt16(v_1_1.AuxInt)
			if !(c >= d) {
				continue
			}
			v.reset(OpLess16U)
			v0 := b.NewValue0(v.Pos, OpConst16, x.Type)
			v0.AuxInt = int16ToAuxInt(c - d)
			v1 := b.NewValue0(v.Pos, OpSub16, x.Type)
			v2 := b.NewValue0(v.Pos, OpConst16, x.Type)
			v2.AuxInt = int16ToAuxInt(d)
			v1.AddArg2(x, v2)
			v.AddArg2(v0, v1)
			return true
		}
		break
	}
	// match: (OrB (Leq16 (Const16 [c]) x) (Less16 x (Const16 [d])))
	// cond: c >= d
	// result: (Leq16U (Const16 <x.Type> [c-d]) (Sub16 <x.Type> x (Const16 <x.Type> [d])))
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpLeq16 {
				continue
			}
			x := v_0.Args[1]
			v_0_0 := v_0.Args[0]
			if v_0_0.Op != OpConst16 {
				continue
			}
			c := auxIntToInt16(v_0_0.AuxInt)
			if v_1.Op != OpLess16 {
				continue
			}
			_ = v_1.Args[1]
			if x != v_1.Args[0] {
				continue
			}
			v_1_1 := v_1.Args[1]
			if v_1_1.Op != OpConst16 {
				continue
			}
			d := auxIntToInt16(v_1_1.AuxInt)
			if !(c >= d) {
				continue
			}
			v.reset(OpLeq16U)
			v0 := b.NewValue0(v.Pos, OpConst16, x.Type)
			v0.AuxInt = int16ToAuxInt(c - d)
			v1 := b.NewValue0(v.Pos, OpSub16, x.Type)
			v2 := b.NewValue0(v.Pos, OpConst16, x.Type)
			v2.AuxInt = int16ToAuxInt(d)
			v1.AddArg2(x, v2)
			v.AddArg2(v0, v1)
			return true
		}
		break
	}
	// match: (OrB (Less8 (Const8 [c]) x) (Less8 x (Const8 [d])))
	// cond: c >= d
	// result: (Less8U (Const8 <x.Type> [c-d]) (Sub8 <x.Type> x (Const8 <x.Type> [d])))
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpLess8 {
				continue
			}
			x := v_0.Args[1]
			v_0_0 := v_0.Args[0]
			if v_0_0.Op != OpConst8 {
				continue
			}
			c := auxIntToInt8(v_0_0.AuxInt)
			if v_1.Op != OpLess8 {
				continue
			}
			_ = v_1.Args[1]
			if x != v_1.Args[0] {
				continue
			}
			v_1_1 := v_1.Args[1]
			if v_1_1.Op != OpConst8 {
				continue
			}
			d := auxIntToInt8(v_1_1.AuxInt)
			if !(c >= d) {
				continue
			}
			v.reset(OpLess8U)
			v0 := b.NewValue0(v.Pos, OpConst8, x.Type)
			v0.AuxInt = int8ToAuxInt(c - d)
			v1 := b.NewValue0(v.Pos, OpSub8, x.Type)
			v2 := b.NewValue0(v.Pos, OpConst8, x.Type)
			v2.AuxInt = int8ToAuxInt(d)
			v1.AddArg2(x, v2)
			v.AddArg2(v0, v1)
			return true
		}
		break
	}
	// match: (OrB (Leq8 (Const8 [c]) x) (Less8 x (Const8 [d])))
	// cond: c >= d
	// result: (Leq8U (Const8 <x.Type> [c-d]) (Sub8 <x.Type> x (Const8 <x.Type> [d])))
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpLeq8 {
				continue
			}
			x := v_0.Args[1]
			v_0_0 := v_0.Args[0]
			if v_0_0.Op != OpConst8 {
				continue
			}
			c := auxIntToInt8(v_0_0.AuxInt)
			if v_1.Op != OpLess8 {
				continue
			}
			_ = v_1.Args[1]
			if x != v_1.Args[0] {
				continue
			}
			v_1_1 := v_1.Args[1]
			if v_1_1.Op != OpConst8 {
				continue
			}
			d := auxIntToInt8(v_1_1.AuxInt)
			if !(c >= d) {
				continue
			}
			v.reset(OpLeq8U)
			v0 := b.NewValue0(v.Pos, OpConst8, x.Type)
			v0.AuxInt = int8ToAuxInt(c - d)
			v1 := b.NewValue0(v.Pos, OpSub8, x.Type)
			v2 := b.NewValue0(v.Pos, OpConst8, x.Type)
			v2.AuxInt = int8ToAuxInt(d)
			v1.AddArg2(x, v2)
			v.AddArg2(v0, v1)
			return true
		}
		break
	}
	// match: (OrB (Less64 (Const64 [c]) x) (Leq64 x (Const64 [d])))
	// cond: c >= d+1 && d+1 > d
	// result: (Less64U (Const64 <x.Type> [c-d-1]) (Sub64 <x.Type> x (Const64 <x.Type> [d+1])))
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpLess64 {
				continue
			}
			x := v_0.Args[1]
			v_0_0 := v_0.Args[0]
			if v_0_0.Op != OpConst64 {
				continue
			}
			c := auxIntToInt64(v_0_0.AuxInt)
			if v_1.Op != OpLeq64 {
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
			if !(c >= d+1 && d+1 > d) {
				continue
			}
			v.reset(OpLess64U)
			v0 := b.NewValue0(v.Pos, OpConst64, x.Type)
			v0.AuxInt = int64ToAuxInt(c - d - 1)
			v1 := b.NewValue0(v.Pos, OpSub64, x.Type)
			v2 := b.NewValue0(v.Pos, OpConst64, x.Type)
			v2.AuxInt = int64ToAuxInt(d + 1)
			v1.AddArg2(x, v2)
			v.AddArg2(v0, v1)
			return true
		}
		break
	}
	// match: (OrB (Leq64 (Const64 [c]) x) (Leq64 x (Const64 [d])))
	// cond: c >= d+1 && d+1 > d
	// result: (Leq64U (Const64 <x.Type> [c-d-1]) (Sub64 <x.Type> x (Const64 <x.Type> [d+1])))
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpLeq64 {
				continue
			}
			x := v_0.Args[1]
			v_0_0 := v_0.Args[0]
			if v_0_0.Op != OpConst64 {
				continue
			}
			c := auxIntToInt64(v_0_0.AuxInt)
			if v_1.Op != OpLeq64 {
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
			if !(c >= d+1 && d+1 > d) {
				continue
			}
			v.reset(OpLeq64U)
			v0 := b.NewValue0(v.Pos, OpConst64, x.Type)
			v0.AuxInt = int64ToAuxInt(c - d - 1)
			v1 := b.NewValue0(v.Pos, OpSub64, x.Type)
			v2 := b.NewValue0(v.Pos, OpConst64, x.Type)
			v2.AuxInt = int64ToAuxInt(d + 1)
			v1.AddArg2(x, v2)
			v.AddArg2(v0, v1)
			return true
		}
		break
	}
	// match: (OrB (Less32 (Const32 [c]) x) (Leq32 x (Const32 [d])))
	// cond: c >= d+1 && d+1 > d
	// result: (Less32U (Const32 <x.Type> [c-d-1]) (Sub32 <x.Type> x (Const32 <x.Type> [d+1])))
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpLess32 {
				continue
			}
			x := v_0.Args[1]
			v_0_0 := v_0.Args[0]
			if v_0_0.Op != OpConst32 {
				continue
			}
			c := auxIntToInt32(v_0_0.AuxInt)
			if v_1.Op != OpLeq32 {
				continue
			}
			_ = v_1.Args[1]
			if x != v_1.Args[0] {
				continue
			}
			v_1_1 := v_1.Args[1]
			if v_1_1.Op != OpConst32 {
				continue
			}
			d := auxIntToInt32(v_1_1.AuxInt)
			if !(c >= d+1 && d+1 > d) {
				continue
			}
			v.reset(OpLess32U)
			v0 := b.NewValue0(v.Pos, OpConst32, x.Type)
			v0.AuxInt = int32ToAuxInt(c - d - 1)
			v1 := b.NewValue0(v.Pos, OpSub32, x.Type)
			v2 := b.NewValue0(v.Pos, OpConst32, x.Type)
			v2.AuxInt = int32ToAuxInt(d + 1)
			v1.AddArg2(x, v2)
			v.AddArg2(v0, v1)
			return true
		}
		break
	}
	// match: (OrB (Leq32 (Const32 [c]) x) (Leq32 x (Const32 [d])))
	// cond: c >= d+1 && d+1 > d
	// result: (Leq32U (Const32 <x.Type> [c-d-1]) (Sub32 <x.Type> x (Const32 <x.Type> [d+1])))
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpLeq32 {
				continue
			}
			x := v_0.Args[1]
			v_0_0 := v_0.Args[0]
			if v_0_0.Op != OpConst32 {
				continue
			}
			c := auxIntToInt32(v_0_0.AuxInt)
			if v_1.Op != OpLeq32 {
				continue
			}
			_ = v_1.Args[1]
			if x != v_1.Args[0] {
				continue
			}
			v_1_1 := v_1.Args[1]
			if v_1_1.Op != OpConst32 {
				continue
			}
			d := auxIntToInt32(v_1_1.AuxInt)
			if !(c >= d+1 && d+1 > d) {
				continue
			}
			v.reset(OpLeq32U)
			v0 := b.NewValue0(v.Pos, OpConst32, x.Type)
			v0.AuxInt = int32ToAuxInt(c - d - 1)
			v1 := b.NewValue0(v.Pos, OpSub32, x.Type)
			v2 := b.NewValue0(v.Pos, OpConst32, x.Type)
			v2.AuxInt = int32ToAuxInt(d + 1)
			v1.AddArg2(x, v2)
			v.AddArg2(v0, v1)
			return true
		}
		break
	}
	// match: (OrB (Less16 (Const16 [c]) x) (Leq16 x (Const16 [d])))
	// cond: c >= d+1 && d+1 > d
	// result: (Less16U (Const16 <x.Type> [c-d-1]) (Sub16 <x.Type> x (Const16 <x.Type> [d+1])))
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpLess16 {
				continue
			}
			x := v_0.Args[1]
			v_0_0 := v_0.Args[0]
			if v_0_0.Op != OpConst16 {
				continue
			}
			c := auxIntToInt16(v_0_0.AuxInt)
			if v_1.Op != OpLeq16 {
				continue
			}
			_ = v_1.Args[1]
			if x != v_1.Args[0] {
				continue
			}
			v_1_1 := v_1.Args[1]
			if v_1_1.Op != OpConst16 {
				continue
			}
			d := auxIntToInt16(v_1_1.AuxInt)
			if !(c >= d+1 && d+1 > d) {
				continue
			}
			v.reset(OpLess16U)
			v0 := b.NewValue0(v.Pos, OpConst16, x.Type)
			v0.AuxInt = int16ToAuxInt(c - d - 1)
			v1 := b.NewValue0(v.Pos, OpSub16, x.Type)
			v2 := b.NewValue0(v.Pos, OpConst16, x.Type)
			v2.AuxInt = int16ToAuxInt(d + 1)
			v1.AddArg2(x, v2)
			v.AddArg2(v0, v1)
			return true
		}
		break
	}
	// match: (OrB (Leq16 (Const16 [c]) x) (Leq16 x (Const16 [d])))
	// cond: c >= d+1 && d+1 > d
	// result: (Leq16U (Const16 <x.Type> [c-d-1]) (Sub16 <x.Type> x (Const16 <x.Type> [d+1])))
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpLeq16 {
				continue
			}
			x := v_0.Args[1]
			v_0_0 := v_0.Args[0]
			if v_0_0.Op != OpConst16 {
				continue
			}
			c := auxIntToInt16(v_0_0.AuxInt)
			if v_1.Op != OpLeq16 {
				continue
			}
			_ = v_1.Args[1]
			if x != v_1.Args[0] {
				continue
			}
			v_1_1 := v_1.Args[1]
			if v_1_1.Op != OpConst16 {
				continue
			}
			d := auxIntToInt16(v_1_1.AuxInt)
			if !(c >= d+1 && d+1 > d) {
				continue
			}
			v.reset(OpLeq16U)
			v0 := b.NewValue0(v.Pos, OpConst16, x.Type)
			v0.AuxInt = int16ToAuxInt(c - d - 1)
			v1 := b.NewValue0(v.Pos, OpSub16, x.Type)
			v2 := b.NewValue0(v.Pos, OpConst16, x.Type)
			v2.AuxInt = int16ToAuxInt(d + 1)
			v1.AddArg2(x, v2)
			v.AddArg2(v0, v1)
			return true
		}
		break
	}
	// match: (OrB (Less8 (Const8 [c]) x) (Leq8 x (Const8 [d])))
	// cond: c >= d+1 && d+1 > d
	// result: (Less8U (Const8 <x.Type> [c-d-1]) (Sub8 <x.Type> x (Const8 <x.Type> [d+1])))
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpLess8 {
				continue
			}
			x := v_0.Args[1]
			v_0_0 := v_0.Args[0]
			if v_0_0.Op != OpConst8 {
				continue
			}
			c := auxIntToInt8(v_0_0.AuxInt)
			if v_1.Op != OpLeq8 {
				continue
			}
			_ = v_1.Args[1]
			if x != v_1.Args[0] {
				continue
			}
			v_1_1 := v_1.Args[1]
			if v_1_1.Op != OpConst8 {
				continue
			}
			d := auxIntToInt8(v_1_1.AuxInt)
			if !(c >= d+1 && d+1 > d) {
				continue
			}
			v.reset(OpLess8U)
			v0 := b.NewValue0(v.Pos, OpConst8, x.Type)
			v0.AuxInt = int8ToAuxInt(c - d - 1)
			v1 := b.NewValue0(v.Pos, OpSub8, x.Type)
			v2 := b.NewValue0(v.Pos, OpConst8, x.Type)
			v2.AuxInt = int8ToAuxInt(d + 1)
			v1.AddArg2(x, v2)
			v.AddArg2(v0, v1)
			return true
		}
		break
	}
	// match: (OrB (Leq8 (Const8 [c]) x) (Leq8 x (Const8 [d])))
	// cond: c >= d+1 && d+1 > d
	// result: (Leq8U (Const8 <x.Type> [c-d-1]) (Sub8 <x.Type> x (Const8 <x.Type> [d+1])))
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpLeq8 {
				continue
			}
			x := v_0.Args[1]
			v_0_0 := v_0.Args[0]
			if v_0_0.Op != OpConst8 {
				continue
			}
			c := auxIntToInt8(v_0_0.AuxInt)
			if v_1.Op != OpLeq8 {
				continue
			}
			_ = v_1.Args[1]
			if x != v_1.Args[0] {
				continue
			}
			v_1_1 := v_1.Args[1]
			if v_1_1.Op != OpConst8 {
				continue
			}
			d := auxIntToInt8(v_1_1.AuxInt)
			if !(c >= d+1 && d+1 > d) {
				continue
			}
			v.reset(OpLeq8U)
			v0 := b.NewValue0(v.Pos, OpConst8, x.Type)
			v0.AuxInt = int8ToAuxInt(c - d - 1)
			v1 := b.NewValue0(v.Pos, OpSub8, x.Type)
			v2 := b.NewValue0(v.Pos, OpConst8, x.Type)
			v2.AuxInt = int8ToAuxInt(d + 1)
			v1.AddArg2(x, v2)
			v.AddArg2(v0, v1)
			return true
		}
		break
	}
	// match: (OrB (Less64U (Const64 [c]) x) (Less64U x (Const64 [d])))
	// cond: uint64(c) >= uint64(d)
	// result: (Less64U (Const64 <x.Type> [c-d]) (Sub64 <x.Type> x (Const64 <x.Type> [d])))
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpLess64U {
				continue
			}
			x := v_0.Args[1]
			v_0_0 := v_0.Args[0]
			if v_0_0.Op != OpConst64 {
				continue
			}
			c := auxIntToInt64(v_0_0.AuxInt)
			if v_1.Op != OpLess64U {
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
			if !(uint64(c) >= uint64(d)) {
				continue
			}
			v.reset(OpLess64U)
			v0 := b.NewValue0(v.Pos, OpConst64, x.Type)
			v0.AuxInt = int64ToAuxInt(c - d)
			v1 := b.NewValue0(v.Pos, OpSub64, x.Type)
			v2 := b.NewValue0(v.Pos, OpConst64, x.Type)
			v2.AuxInt = int64ToAuxInt(d)
			v1.AddArg2(x, v2)
			v.AddArg2(v0, v1)
			return true
		}
		break
	}
	// match: (OrB (Leq64U (Const64 [c]) x) (Less64U x (Const64 [d])))
	// cond: uint64(c) >= uint64(d)
	// result: (Leq64U (Const64 <x.Type> [c-d]) (Sub64 <x.Type> x (Const64 <x.Type> [d])))
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpLeq64U {
				continue
			}
			x := v_0.Args[1]
			v_0_0 := v_0.Args[0]
			if v_0_0.Op != OpConst64 {
				continue
			}
			c := auxIntToInt64(v_0_0.AuxInt)
			if v_1.Op != OpLess64U {
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
			if !(uint64(c) >= uint64(d)) {
				continue
			}
			v.reset(OpLeq64U)
			v0 := b.NewValue0(v.Pos, OpConst64, x.Type)
			v0.AuxInt = int64ToAuxInt(c - d)
			v1 := b.NewValue0(v.Pos, OpSub64, x.Type)
			v2 := b.NewValue0(v.Pos, OpConst64, x.Type)
			v2.AuxInt = int64ToAuxInt(d)
			v1.AddArg2(x, v2)
			v.AddArg2(v0, v1)
			return true
		}
		break
	}
	// match: (OrB (Less32U (Const32 [c]) x) (Less32U x (Const32 [d])))
	// cond: uint32(c) >= uint32(d)
	// result: (Less32U (Const32 <x.Type> [c-d]) (Sub32 <x.Type> x (Const32 <x.Type> [d])))
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpLess32U {
				continue
			}
			x := v_0.Args[1]
			v_0_0 := v_0.Args[0]
			if v_0_0.Op != OpConst32 {
				continue
			}
			c := auxIntToInt32(v_0_0.AuxInt)
			if v_1.Op != OpLess32U {
				continue
			}
			_ = v_1.Args[1]
			if x != v_1.Args[0] {
				continue
			}
			v_1_1 := v_1.Args[1]
			if v_1_1.Op != OpConst32 {
				continue
			}
			d := auxIntToInt32(v_1_1.AuxInt)
			if !(uint32(c) >= uint32(d)) {
				continue
			}
			v.reset(OpLess32U)
			v0 := b.NewValue0(v.Pos, OpConst32, x.Type)
			v0.AuxInt = int32ToAuxInt(c - d)
			v1 := b.NewValue0(v.Pos, OpSub32, x.Type)
			v2 := b.NewValue0(v.Pos, OpConst32, x.Type)
			v2.AuxInt = int32ToAuxInt(d)
			v1.AddArg2(x, v2)
			v.AddArg2(v0, v1)
			return true
		}
		break
	}
	// match: (OrB (Leq32U (Co
```