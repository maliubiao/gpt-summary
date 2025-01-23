Response:
My thought process to answer the request goes like this:

1. **Understand the Goal:** The user wants to understand the functionality of a specific Go code snippet from `rewritegeneric.go`. They also want to know what Go feature it might be related to, see examples, and identify potential pitfalls. The prompt specifies this is part 14 of 26.

2. **Identify the Core Function:** The provided code consists of several functions named `rewriteValuegeneric_Op...`. The naming convention strongly suggests these functions are responsible for rewriting or optimizing specific generic operations within the Go compiler's SSA (Static Single Assignment) intermediate representation. The "generic" part likely means these rewrites apply to various types.

3. **Focus on the `rewriteValuegeneric_OpMove` Function:** The bulk of the snippet is dedicated to the `rewriteValuegeneric_OpMove` function. This immediately suggests the primary focus of this part of the code is optimizing `move` operations. In SSA, a "move" often represents copying data from one memory location to another.

4. **Analyze the `rewriteValuegeneric_OpMove` Logic (Pattern Matching):** The `rewriteValuegeneric_OpMove` function contains a series of `match:` and `cond:` blocks followed by `result:`. This pattern is typical of rewrite rules in compilers. It means the code is looking for specific patterns of operations in the SSA graph (`match`), checking certain conditions (`cond`), and then replacing those patterns with a more efficient equivalent (`result`).

5. **Break Down the `rewriteValuegeneric_OpMove` Rules:** I'll go through some of the prominent rule types to understand their intent:

    * **Early Exits:**  The initial `if` statements checking for `v.Block.Func.Config.hasBadPtr()` suggest handling cases where invalid pointers might be involved, preventing further optimization.

    * **Combining Stores:**  Several rules check for sequences of `Store` operations that are writing to consecutive memory locations and can be optimized. The conditions like `isSamePtr`, `Alignment`, and `registerizable` are related to ensuring the safety and efficiency of these combined stores. The `VarDef` checks likely relate to scenarios where the memory being written to is freshly allocated.

    * **Store followed by Zero:**  Some rules look for a `Store` operation followed by a `Zero` operation that clears a larger block of memory. These are optimized by extending the `Zero` operation to cover the region written by the `Store`.

    * **Move Chaining:** The rules involving nested `Move` operations with temporary variables (`tmp1`, `tmp2`) suggest optimizations where redundant intermediate moves can be eliminated. The `disjoint` and `isInlinableMemmove` conditions are crucial for ensuring data integrity and inlining opportunities.

    * **Self-Move Elimination:** The final rule `isSamePtr(dst, src)` directly eliminates moves where the source and destination are the same.

6. **Infer the Go Feature:** Based on the optimization of `Move` and `Zero` operations, especially in the context of consecutive memory locations and potentially newly allocated memory (`VarDef`), the most likely Go feature being implemented here is **memory initialization** and **copying** of data structures, likely involving slices, structs, and arrays.

7. **Construct Go Examples:**  To illustrate the optimizations, I'll create Go code snippets that would generate the SSA patterns being optimized:

    * **Combining Stores:**  Creating a struct and assigning values to its fields.
    * **Store followed by Zero:**  Initializing a slice and then zeroing out its remaining elements.
    * **Move Chaining:**  While less direct to generate in simple Go code, it can occur during compiler optimizations of more complex data manipulations. I'll illustrate a scenario where the compiler might create such intermediate moves.
    * **Self-Move:**  While seemingly trivial, it can occur in generated code or through certain programming patterns.

8. **Address Command-Line Parameters:** The code snippet doesn't directly handle command-line parameters. This section of the answer will state that explicitly. However, I'll briefly mention that the Go compiler as a whole uses command-line flags for optimization levels, etc., which indirectly affect this code's execution.

9. **Identify Potential Pitfalls:** The main pitfall for users is usually related to **incorrect assumptions about memory layout** or **violating alignment requirements** when using unsafe operations. I'll provide an example using `unsafe.Pointer` to illustrate this.

10. **Summarize the Function:**  I'll provide a concise summary stating that this part of the code optimizes generic `move` operations in the SSA representation, specifically focusing on combining stores, optimizing stores followed by zeroing, eliminating redundant moves, and handling self-moves.

11. **Structure the Answer:**  I'll organize the answer with clear headings for each part of the request (functionality, Go feature, examples, command-line parameters, pitfalls, summary). I'll use code blocks for Go examples and format the output for readability.

12. **Review and Refine:**  Finally, I'll review the entire answer to ensure accuracy, clarity, and completeness, making sure it directly addresses all parts of the user's request. I'll double-check the logic of the rewrite rules and the relevance of the Go examples.
这是 `go/src/cmd/compile/internal/ssa/rewritegeneric.go` 文件的一部分，主要负责针对 **通用类型 (generic types)** 的 SSA (Static Single Assignment) 中间表示进行重写和优化的规则定义。

**功能归纳:**

这段代码定义了一系列针对 `OpMove` 操作的重写规则。`OpMove` 通常表示将一块内存从一个位置复制到另一个位置。这些规则旨在识别特定的 `OpMove` 模式，并在满足特定条件时将其转换为更高效的操作序列，例如：

* **合并连续的 Store 操作:** 将多个连续的 `Store` 操作合并为一个 `Move` 操作，或者将一个 `Move` 操作拆解为多个 `Store` 操作，以适应目标架构或优化场景。
* **优化 Move 后紧跟 Zero 的操作:**  如果一个 `Move` 操作之后紧跟着对同一块内存进行 `Zero` 操作，可以进行合并或优化。
* **消除冗余的 Move 操作:**  识别并消除不必要的 `Move` 操作，例如源地址和目标地址相同的情况。
* **利用 VarDef 信息优化:**  如果 `Move` 操作的目标内存是通过 `VarDef` 声明的，即新分配的内存，可以利用这个信息进行优化。

**推断的 Go 语言功能实现：**

基于这些 `OpMove` 的优化规则，可以推断这段代码可能与以下 Go 语言功能的实现有关：

1. **结构体 (struct) 和数组 (array) 的赋值和拷贝:** 当你将一个结构体或数组赋值给另一个变量时，底层会进行内存拷贝操作。这些规则可能旨在优化这些拷贝过程。
2. **切片 (slice) 的拷贝:**  切片的复制也会涉及内存拷贝，这些规则可能用于提升切片复制的效率。
3. **`copy()` 内建函数:**  `copy()` 函数用于在切片之间或切片和数组之间复制元素，其底层实现很可能涉及到 `OpMove` 操作，这些规则可以优化 `copy()` 的性能。
4. **`make()` 函数 для 切片, map 和 channel:** `make()` 函数在创建切片、map 或 channel 时，可能会涉及内存的初始化（例如用零值填充），这可能与 `Move` 后跟 `Zero` 的优化相关。

**Go 代码举例说明:**

以下是一些 Go 代码示例，这些示例可能会触发上述 `rewritegeneric.go` 中的优化规则：

**示例 1: 结构体赋值 (可能触发合并 Store 操作的优化)**

```go
package main

type Point struct {
	X int
	Y int
}

func main() {
	p1 := Point{X: 10, Y: 20}
	p2 := p1 // 结构体赋值，会进行内存拷贝
	println(p2.X, p2.Y)
}
```

**假设的 SSA 输入 (简化):**

```
v1 = Const64 [10]
v2 = OffPtr <type.Point> [0]  // X 字段的偏移量
v3 = Store {int} v2 v1 mem

v4 = Const64 [20]
v5 = OffPtr <type.Point> [8]  // Y 字段的偏移量 (假设 int 大小为 8)
v6 = Store {int} v5 v4 v3

v7 = Alloc <type.Point>  // 为 p2 分配内存
v8 = Move <type.Point> [16] v7 &p1 v6 // 拷贝 p1 到 p2
```

**可能的 SSA 输出 (优化后):**

`Move` 操作可能会被保留，但其内部实现可能会利用更底层的指令进行高效拷贝。或者，在某些情况下，如果编译器能够确定类型信息，可能会将 `Move` 展开为更细粒度的 `Store` 操作。

**示例 2: 切片初始化和部分赋值 (可能触发 Move 后跟 Zero 的优化)**

```go
package main

func main() {
	s := make([]int, 10)
	s[0] = 1
	s[1] = 2
	// ... 后续可能对部分元素赋值，剩余元素为零值
	println(s[0], s[9])
}
```

**假设的 SSA 输入 (简化):**

```
v1 = Const64 [10]
v2 = MakeSlice <[]int> v1  // 创建切片，底层可能进行 Zero 初始化

v3 = Const64 [1]
v4 = OffPtr <[]int> [0]
v5 = Store {int} v4 v3 v2

v6 = Const64 [2]
v7 = OffPtr <[]int> [8]
v8 = Store {int} v7 v6 v5

// ... 可能还有其他 Store 操作

// 如果没有对所有元素赋值，剩余部分可能是隐式的 Zero 操作
```

**可能的 SSA 输出 (优化后):**

编译器可能会识别出 `make([]int, 10)` 隐含的零值初始化，并与后续的赋值操作结合进行优化，避免重复的零值写入。

**示例 3: 同地址赋值 (可能触发消除冗余 Move 操作的优化)**

```go
package main

func main() {
	x := 5
	var p *int = &x
	*p = 5 // 本质上是对 x 赋值，可能被优化掉 Move
	println(x)
}
```

**假设的 SSA 输入 (简化):**

```
v1 = Const64 [5]
v2 = LocalAddr {int} x
v3 = Store {int} v2 v1 mem

v4 = Load {*int} v2 mem
v5 = Store {int} v4 v1 v3 // 理论上这里可能出现 Move，但会被优化掉
```

**可能的 SSA 输出 (优化后):**

编译器会识别出 `*p = 5` 实际上是对 `x` 赋值，可能直接使用之前对 `x` 的 `Store` 操作，消除掉冗余的 `Move`。

**命令行参数的具体处理:**

这段代码本身是 Go 编译器内部的一部分，并不直接处理命令行参数。但是，Go 编译器的命令行参数，例如 `-gcflags` 和 `-ldflags`，以及 `-O` 优化级别等，会影响编译器生成的 SSA 代码，从而间接影响这些重写规则的执行。

例如，使用 `-gcflags="-N"` 可以禁用优化，这将阻止这些重写规则的生效。而使用更高的优化级别（例如 `-O2`）可能会触发更多更复杂的优化，其中就包括这里的 `OpMove` 重写。

**使用者易犯错的点:**

作为编译器开发者，在编写这些重写规则时，容易犯错的点包括：

* **条件判断不完整或错误:** `cond:` 部分的条件判断如果写得不正确，可能会导致错误的优化，甚至产生错误的代码。例如，没有正确考虑内存对齐、类型大小等因素。
* **模式匹配错误:** `match:` 部分的模式匹配如果写错，可能导致规则无法匹配到应该优化的代码模式。
* **引入新的错误或性能问题:**  优化后的 `result:` 部分引入了新的操作，如果这些新操作本身有缺陷，或者在某些情况下反而更慢，就会导致问题。
* **没有充分考虑所有可能的输入 SSA 结构:**  SSA 图的结构可能非常复杂，需要考虑各种不同的情况，确保重写规则的通用性和正确性。

**总结一下它的功能 (针对第 14 部分):**

第 14 部分的 `rewritegeneric.go` 代码主要定义了针对 `OpMove` 操作的多种重写规则。这些规则旨在通过识别和转换特定的 `OpMove` 模式来优化通用类型的内存拷贝操作。其核心功能是提升结构体、数组、切片等数据结构的赋值、拷贝以及相关操作的性能。它通过合并连续的存储操作，优化 Move 后跟 Zero 的场景，消除冗余的 Move，并利用 `VarDef` 信息来实现这些优化。 这部分代码是 Go 编译器优化流程中的一个关键环节，对于生成高效的目标代码至关重要。

### 提示词
```
这是路径为go/src/cmd/compile/internal/ssa/rewritegeneric.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第14部分，共26部分，请归纳一下它的功能
```

### 源代码
```go
Pos, OpOffPtr, tt4)
		v4.AuxInt = int64ToAuxInt(o4)
		v4.AddArg(dst)
		v5 := b.NewValue0(v.Pos, OpStore, types.TypeMem)
		v5.Aux = typeToAux(t5)
		v6 := b.NewValue0(v.Pos, OpOffPtr, tt5)
		v6.AuxInt = int64ToAuxInt(0)
		v6.AddArg(dst)
		v5.AddArg3(v6, d4, mem)
		v3.AddArg3(v4, d3, v5)
		v1.AddArg3(v2, d2, v3)
		v.AddArg3(v0, d1, v1)
		return true
	}
	// match: (Move {t1} [n] dst p1 mem:(VarDef (Store {t2} op2:(OffPtr <tt2> [o2] p2) d1 (Store {t3} op3:(OffPtr <tt3> [0] p3) d2 _))))
	// cond: isSamePtr(p1, p2) && isSamePtr(p2, p3) && t2.Alignment() <= t1.Alignment() && t3.Alignment() <= t1.Alignment() && registerizable(b, t2) && registerizable(b, t3) && o2 == t3.Size() && n == t2.Size() + t3.Size()
	// result: (Store {t2} (OffPtr <tt2> [o2] dst) d1 (Store {t3} (OffPtr <tt3> [0] dst) d2 mem))
	for {
		n := auxIntToInt64(v.AuxInt)
		t1 := auxToType(v.Aux)
		dst := v_0
		p1 := v_1
		mem := v_2
		if mem.Op != OpVarDef {
			break
		}
		mem_0 := mem.Args[0]
		if mem_0.Op != OpStore {
			break
		}
		t2 := auxToType(mem_0.Aux)
		_ = mem_0.Args[2]
		op2 := mem_0.Args[0]
		if op2.Op != OpOffPtr {
			break
		}
		tt2 := op2.Type
		o2 := auxIntToInt64(op2.AuxInt)
		p2 := op2.Args[0]
		d1 := mem_0.Args[1]
		mem_0_2 := mem_0.Args[2]
		if mem_0_2.Op != OpStore {
			break
		}
		t3 := auxToType(mem_0_2.Aux)
		d2 := mem_0_2.Args[1]
		op3 := mem_0_2.Args[0]
		if op3.Op != OpOffPtr {
			break
		}
		tt3 := op3.Type
		if auxIntToInt64(op3.AuxInt) != 0 {
			break
		}
		p3 := op3.Args[0]
		if !(isSamePtr(p1, p2) && isSamePtr(p2, p3) && t2.Alignment() <= t1.Alignment() && t3.Alignment() <= t1.Alignment() && registerizable(b, t2) && registerizable(b, t3) && o2 == t3.Size() && n == t2.Size()+t3.Size()) {
			break
		}
		v.reset(OpStore)
		v.Aux = typeToAux(t2)
		v0 := b.NewValue0(v.Pos, OpOffPtr, tt2)
		v0.AuxInt = int64ToAuxInt(o2)
		v0.AddArg(dst)
		v1 := b.NewValue0(v.Pos, OpStore, types.TypeMem)
		v1.Aux = typeToAux(t3)
		v2 := b.NewValue0(v.Pos, OpOffPtr, tt3)
		v2.AuxInt = int64ToAuxInt(0)
		v2.AddArg(dst)
		v1.AddArg3(v2, d2, mem)
		v.AddArg3(v0, d1, v1)
		return true
	}
	// match: (Move {t1} [n] dst p1 mem:(VarDef (Store {t2} op2:(OffPtr <tt2> [o2] p2) d1 (Store {t3} op3:(OffPtr <tt3> [o3] p3) d2 (Store {t4} op4:(OffPtr <tt4> [0] p4) d3 _)))))
	// cond: isSamePtr(p1, p2) && isSamePtr(p2, p3) && isSamePtr(p3, p4) && t2.Alignment() <= t1.Alignment() && t3.Alignment() <= t1.Alignment() && t4.Alignment() <= t1.Alignment() && registerizable(b, t2) && registerizable(b, t3) && registerizable(b, t4) && o3 == t4.Size() && o2-o3 == t3.Size() && n == t2.Size() + t3.Size() + t4.Size()
	// result: (Store {t2} (OffPtr <tt2> [o2] dst) d1 (Store {t3} (OffPtr <tt3> [o3] dst) d2 (Store {t4} (OffPtr <tt4> [0] dst) d3 mem)))
	for {
		n := auxIntToInt64(v.AuxInt)
		t1 := auxToType(v.Aux)
		dst := v_0
		p1 := v_1
		mem := v_2
		if mem.Op != OpVarDef {
			break
		}
		mem_0 := mem.Args[0]
		if mem_0.Op != OpStore {
			break
		}
		t2 := auxToType(mem_0.Aux)
		_ = mem_0.Args[2]
		op2 := mem_0.Args[0]
		if op2.Op != OpOffPtr {
			break
		}
		tt2 := op2.Type
		o2 := auxIntToInt64(op2.AuxInt)
		p2 := op2.Args[0]
		d1 := mem_0.Args[1]
		mem_0_2 := mem_0.Args[2]
		if mem_0_2.Op != OpStore {
			break
		}
		t3 := auxToType(mem_0_2.Aux)
		_ = mem_0_2.Args[2]
		op3 := mem_0_2.Args[0]
		if op3.Op != OpOffPtr {
			break
		}
		tt3 := op3.Type
		o3 := auxIntToInt64(op3.AuxInt)
		p3 := op3.Args[0]
		d2 := mem_0_2.Args[1]
		mem_0_2_2 := mem_0_2.Args[2]
		if mem_0_2_2.Op != OpStore {
			break
		}
		t4 := auxToType(mem_0_2_2.Aux)
		d3 := mem_0_2_2.Args[1]
		op4 := mem_0_2_2.Args[0]
		if op4.Op != OpOffPtr {
			break
		}
		tt4 := op4.Type
		if auxIntToInt64(op4.AuxInt) != 0 {
			break
		}
		p4 := op4.Args[0]
		if !(isSamePtr(p1, p2) && isSamePtr(p2, p3) && isSamePtr(p3, p4) && t2.Alignment() <= t1.Alignment() && t3.Alignment() <= t1.Alignment() && t4.Alignment() <= t1.Alignment() && registerizable(b, t2) && registerizable(b, t3) && registerizable(b, t4) && o3 == t4.Size() && o2-o3 == t3.Size() && n == t2.Size()+t3.Size()+t4.Size()) {
			break
		}
		v.reset(OpStore)
		v.Aux = typeToAux(t2)
		v0 := b.NewValue0(v.Pos, OpOffPtr, tt2)
		v0.AuxInt = int64ToAuxInt(o2)
		v0.AddArg(dst)
		v1 := b.NewValue0(v.Pos, OpStore, types.TypeMem)
		v1.Aux = typeToAux(t3)
		v2 := b.NewValue0(v.Pos, OpOffPtr, tt3)
		v2.AuxInt = int64ToAuxInt(o3)
		v2.AddArg(dst)
		v3 := b.NewValue0(v.Pos, OpStore, types.TypeMem)
		v3.Aux = typeToAux(t4)
		v4 := b.NewValue0(v.Pos, OpOffPtr, tt4)
		v4.AuxInt = int64ToAuxInt(0)
		v4.AddArg(dst)
		v3.AddArg3(v4, d3, mem)
		v1.AddArg3(v2, d2, v3)
		v.AddArg3(v0, d1, v1)
		return true
	}
	// match: (Move {t1} [n] dst p1 mem:(VarDef (Store {t2} op2:(OffPtr <tt2> [o2] p2) d1 (Store {t3} op3:(OffPtr <tt3> [o3] p3) d2 (Store {t4} op4:(OffPtr <tt4> [o4] p4) d3 (Store {t5} op5:(OffPtr <tt5> [0] p5) d4 _))))))
	// cond: isSamePtr(p1, p2) && isSamePtr(p2, p3) && isSamePtr(p3, p4) && isSamePtr(p4, p5) && t2.Alignment() <= t1.Alignment() && t3.Alignment() <= t1.Alignment() && t4.Alignment() <= t1.Alignment() && t5.Alignment() <= t1.Alignment() && registerizable(b, t2) && registerizable(b, t3) && registerizable(b, t4) && registerizable(b, t5) && o4 == t5.Size() && o3-o4 == t4.Size() && o2-o3 == t3.Size() && n == t2.Size() + t3.Size() + t4.Size() + t5.Size()
	// result: (Store {t2} (OffPtr <tt2> [o2] dst) d1 (Store {t3} (OffPtr <tt3> [o3] dst) d2 (Store {t4} (OffPtr <tt4> [o4] dst) d3 (Store {t5} (OffPtr <tt5> [0] dst) d4 mem))))
	for {
		n := auxIntToInt64(v.AuxInt)
		t1 := auxToType(v.Aux)
		dst := v_0
		p1 := v_1
		mem := v_2
		if mem.Op != OpVarDef {
			break
		}
		mem_0 := mem.Args[0]
		if mem_0.Op != OpStore {
			break
		}
		t2 := auxToType(mem_0.Aux)
		_ = mem_0.Args[2]
		op2 := mem_0.Args[0]
		if op2.Op != OpOffPtr {
			break
		}
		tt2 := op2.Type
		o2 := auxIntToInt64(op2.AuxInt)
		p2 := op2.Args[0]
		d1 := mem_0.Args[1]
		mem_0_2 := mem_0.Args[2]
		if mem_0_2.Op != OpStore {
			break
		}
		t3 := auxToType(mem_0_2.Aux)
		_ = mem_0_2.Args[2]
		op3 := mem_0_2.Args[0]
		if op3.Op != OpOffPtr {
			break
		}
		tt3 := op3.Type
		o3 := auxIntToInt64(op3.AuxInt)
		p3 := op3.Args[0]
		d2 := mem_0_2.Args[1]
		mem_0_2_2 := mem_0_2.Args[2]
		if mem_0_2_2.Op != OpStore {
			break
		}
		t4 := auxToType(mem_0_2_2.Aux)
		_ = mem_0_2_2.Args[2]
		op4 := mem_0_2_2.Args[0]
		if op4.Op != OpOffPtr {
			break
		}
		tt4 := op4.Type
		o4 := auxIntToInt64(op4.AuxInt)
		p4 := op4.Args[0]
		d3 := mem_0_2_2.Args[1]
		mem_0_2_2_2 := mem_0_2_2.Args[2]
		if mem_0_2_2_2.Op != OpStore {
			break
		}
		t5 := auxToType(mem_0_2_2_2.Aux)
		d4 := mem_0_2_2_2.Args[1]
		op5 := mem_0_2_2_2.Args[0]
		if op5.Op != OpOffPtr {
			break
		}
		tt5 := op5.Type
		if auxIntToInt64(op5.AuxInt) != 0 {
			break
		}
		p5 := op5.Args[0]
		if !(isSamePtr(p1, p2) && isSamePtr(p2, p3) && isSamePtr(p3, p4) && isSamePtr(p4, p5) && t2.Alignment() <= t1.Alignment() && t3.Alignment() <= t1.Alignment() && t4.Alignment() <= t1.Alignment() && t5.Alignment() <= t1.Alignment() && registerizable(b, t2) && registerizable(b, t3) && registerizable(b, t4) && registerizable(b, t5) && o4 == t5.Size() && o3-o4 == t4.Size() && o2-o3 == t3.Size() && n == t2.Size()+t3.Size()+t4.Size()+t5.Size()) {
			break
		}
		v.reset(OpStore)
		v.Aux = typeToAux(t2)
		v0 := b.NewValue0(v.Pos, OpOffPtr, tt2)
		v0.AuxInt = int64ToAuxInt(o2)
		v0.AddArg(dst)
		v1 := b.NewValue0(v.Pos, OpStore, types.TypeMem)
		v1.Aux = typeToAux(t3)
		v2 := b.NewValue0(v.Pos, OpOffPtr, tt3)
		v2.AuxInt = int64ToAuxInt(o3)
		v2.AddArg(dst)
		v3 := b.NewValue0(v.Pos, OpStore, types.TypeMem)
		v3.Aux = typeToAux(t4)
		v4 := b.NewValue0(v.Pos, OpOffPtr, tt4)
		v4.AuxInt = int64ToAuxInt(o4)
		v4.AddArg(dst)
		v5 := b.NewValue0(v.Pos, OpStore, types.TypeMem)
		v5.Aux = typeToAux(t5)
		v6 := b.NewValue0(v.Pos, OpOffPtr, tt5)
		v6.AuxInt = int64ToAuxInt(0)
		v6.AddArg(dst)
		v5.AddArg3(v6, d4, mem)
		v3.AddArg3(v4, d3, v5)
		v1.AddArg3(v2, d2, v3)
		v.AddArg3(v0, d1, v1)
		return true
	}
	// match: (Move {t1} [n] dst p1 mem:(Store {t2} op2:(OffPtr <tt2> [o2] p2) d1 (Zero {t3} [n] p3 _)))
	// cond: isSamePtr(p1, p2) && isSamePtr(p2, p3) && t2.Alignment() <= t1.Alignment() && t3.Alignment() <= t1.Alignment() && registerizable(b, t2) && n >= o2 + t2.Size()
	// result: (Store {t2} (OffPtr <tt2> [o2] dst) d1 (Zero {t1} [n] dst mem))
	for {
		n := auxIntToInt64(v.AuxInt)
		t1 := auxToType(v.Aux)
		dst := v_0
		p1 := v_1
		mem := v_2
		if mem.Op != OpStore {
			break
		}
		t2 := auxToType(mem.Aux)
		_ = mem.Args[2]
		op2 := mem.Args[0]
		if op2.Op != OpOffPtr {
			break
		}
		tt2 := op2.Type
		o2 := auxIntToInt64(op2.AuxInt)
		p2 := op2.Args[0]
		d1 := mem.Args[1]
		mem_2 := mem.Args[2]
		if mem_2.Op != OpZero || auxIntToInt64(mem_2.AuxInt) != n {
			break
		}
		t3 := auxToType(mem_2.Aux)
		p3 := mem_2.Args[0]
		if !(isSamePtr(p1, p2) && isSamePtr(p2, p3) && t2.Alignment() <= t1.Alignment() && t3.Alignment() <= t1.Alignment() && registerizable(b, t2) && n >= o2+t2.Size()) {
			break
		}
		v.reset(OpStore)
		v.Aux = typeToAux(t2)
		v0 := b.NewValue0(v.Pos, OpOffPtr, tt2)
		v0.AuxInt = int64ToAuxInt(o2)
		v0.AddArg(dst)
		v1 := b.NewValue0(v.Pos, OpZero, types.TypeMem)
		v1.AuxInt = int64ToAuxInt(n)
		v1.Aux = typeToAux(t1)
		v1.AddArg2(dst, mem)
		v.AddArg3(v0, d1, v1)
		return true
	}
	// match: (Move {t1} [n] dst p1 mem:(Store {t2} (OffPtr <tt2> [o2] p2) d1 (Store {t3} (OffPtr <tt3> [o3] p3) d2 (Zero {t4} [n] p4 _))))
	// cond: isSamePtr(p1, p2) && isSamePtr(p2, p3) && isSamePtr(p3, p4) && t2.Alignment() <= t1.Alignment() && t3.Alignment() <= t1.Alignment() && t4.Alignment() <= t1.Alignment() && registerizable(b, t2) && registerizable(b, t3) && n >= o2 + t2.Size() && n >= o3 + t3.Size()
	// result: (Store {t2} (OffPtr <tt2> [o2] dst) d1 (Store {t3} (OffPtr <tt3> [o3] dst) d2 (Zero {t1} [n] dst mem)))
	for {
		n := auxIntToInt64(v.AuxInt)
		t1 := auxToType(v.Aux)
		dst := v_0
		p1 := v_1
		mem := v_2
		if mem.Op != OpStore {
			break
		}
		t2 := auxToType(mem.Aux)
		_ = mem.Args[2]
		mem_0 := mem.Args[0]
		if mem_0.Op != OpOffPtr {
			break
		}
		tt2 := mem_0.Type
		o2 := auxIntToInt64(mem_0.AuxInt)
		p2 := mem_0.Args[0]
		d1 := mem.Args[1]
		mem_2 := mem.Args[2]
		if mem_2.Op != OpStore {
			break
		}
		t3 := auxToType(mem_2.Aux)
		_ = mem_2.Args[2]
		mem_2_0 := mem_2.Args[0]
		if mem_2_0.Op != OpOffPtr {
			break
		}
		tt3 := mem_2_0.Type
		o3 := auxIntToInt64(mem_2_0.AuxInt)
		p3 := mem_2_0.Args[0]
		d2 := mem_2.Args[1]
		mem_2_2 := mem_2.Args[2]
		if mem_2_2.Op != OpZero || auxIntToInt64(mem_2_2.AuxInt) != n {
			break
		}
		t4 := auxToType(mem_2_2.Aux)
		p4 := mem_2_2.Args[0]
		if !(isSamePtr(p1, p2) && isSamePtr(p2, p3) && isSamePtr(p3, p4) && t2.Alignment() <= t1.Alignment() && t3.Alignment() <= t1.Alignment() && t4.Alignment() <= t1.Alignment() && registerizable(b, t2) && registerizable(b, t3) && n >= o2+t2.Size() && n >= o3+t3.Size()) {
			break
		}
		v.reset(OpStore)
		v.Aux = typeToAux(t2)
		v0 := b.NewValue0(v.Pos, OpOffPtr, tt2)
		v0.AuxInt = int64ToAuxInt(o2)
		v0.AddArg(dst)
		v1 := b.NewValue0(v.Pos, OpStore, types.TypeMem)
		v1.Aux = typeToAux(t3)
		v2 := b.NewValue0(v.Pos, OpOffPtr, tt3)
		v2.AuxInt = int64ToAuxInt(o3)
		v2.AddArg(dst)
		v3 := b.NewValue0(v.Pos, OpZero, types.TypeMem)
		v3.AuxInt = int64ToAuxInt(n)
		v3.Aux = typeToAux(t1)
		v3.AddArg2(dst, mem)
		v1.AddArg3(v2, d2, v3)
		v.AddArg3(v0, d1, v1)
		return true
	}
	// match: (Move {t1} [n] dst p1 mem:(Store {t2} (OffPtr <tt2> [o2] p2) d1 (Store {t3} (OffPtr <tt3> [o3] p3) d2 (Store {t4} (OffPtr <tt4> [o4] p4) d3 (Zero {t5} [n] p5 _)))))
	// cond: isSamePtr(p1, p2) && isSamePtr(p2, p3) && isSamePtr(p3, p4) && isSamePtr(p4, p5) && t2.Alignment() <= t1.Alignment() && t3.Alignment() <= t1.Alignment() && t4.Alignment() <= t1.Alignment() && t5.Alignment() <= t1.Alignment() && registerizable(b, t2) && registerizable(b, t3) && registerizable(b, t4) && n >= o2 + t2.Size() && n >= o3 + t3.Size() && n >= o4 + t4.Size()
	// result: (Store {t2} (OffPtr <tt2> [o2] dst) d1 (Store {t3} (OffPtr <tt3> [o3] dst) d2 (Store {t4} (OffPtr <tt4> [o4] dst) d3 (Zero {t1} [n] dst mem))))
	for {
		n := auxIntToInt64(v.AuxInt)
		t1 := auxToType(v.Aux)
		dst := v_0
		p1 := v_1
		mem := v_2
		if mem.Op != OpStore {
			break
		}
		t2 := auxToType(mem.Aux)
		_ = mem.Args[2]
		mem_0 := mem.Args[0]
		if mem_0.Op != OpOffPtr {
			break
		}
		tt2 := mem_0.Type
		o2 := auxIntToInt64(mem_0.AuxInt)
		p2 := mem_0.Args[0]
		d1 := mem.Args[1]
		mem_2 := mem.Args[2]
		if mem_2.Op != OpStore {
			break
		}
		t3 := auxToType(mem_2.Aux)
		_ = mem_2.Args[2]
		mem_2_0 := mem_2.Args[0]
		if mem_2_0.Op != OpOffPtr {
			break
		}
		tt3 := mem_2_0.Type
		o3 := auxIntToInt64(mem_2_0.AuxInt)
		p3 := mem_2_0.Args[0]
		d2 := mem_2.Args[1]
		mem_2_2 := mem_2.Args[2]
		if mem_2_2.Op != OpStore {
			break
		}
		t4 := auxToType(mem_2_2.Aux)
		_ = mem_2_2.Args[2]
		mem_2_2_0 := mem_2_2.Args[0]
		if mem_2_2_0.Op != OpOffPtr {
			break
		}
		tt4 := mem_2_2_0.Type
		o4 := auxIntToInt64(mem_2_2_0.AuxInt)
		p4 := mem_2_2_0.Args[0]
		d3 := mem_2_2.Args[1]
		mem_2_2_2 := mem_2_2.Args[2]
		if mem_2_2_2.Op != OpZero || auxIntToInt64(mem_2_2_2.AuxInt) != n {
			break
		}
		t5 := auxToType(mem_2_2_2.Aux)
		p5 := mem_2_2_2.Args[0]
		if !(isSamePtr(p1, p2) && isSamePtr(p2, p3) && isSamePtr(p3, p4) && isSamePtr(p4, p5) && t2.Alignment() <= t1.Alignment() && t3.Alignment() <= t1.Alignment() && t4.Alignment() <= t1.Alignment() && t5.Alignment() <= t1.Alignment() && registerizable(b, t2) && registerizable(b, t3) && registerizable(b, t4) && n >= o2+t2.Size() && n >= o3+t3.Size() && n >= o4+t4.Size()) {
			break
		}
		v.reset(OpStore)
		v.Aux = typeToAux(t2)
		v0 := b.NewValue0(v.Pos, OpOffPtr, tt2)
		v0.AuxInt = int64ToAuxInt(o2)
		v0.AddArg(dst)
		v1 := b.NewValue0(v.Pos, OpStore, types.TypeMem)
		v1.Aux = typeToAux(t3)
		v2 := b.NewValue0(v.Pos, OpOffPtr, tt3)
		v2.AuxInt = int64ToAuxInt(o3)
		v2.AddArg(dst)
		v3 := b.NewValue0(v.Pos, OpStore, types.TypeMem)
		v3.Aux = typeToAux(t4)
		v4 := b.NewValue0(v.Pos, OpOffPtr, tt4)
		v4.AuxInt = int64ToAuxInt(o4)
		v4.AddArg(dst)
		v5 := b.NewValue0(v.Pos, OpZero, types.TypeMem)
		v5.AuxInt = int64ToAuxInt(n)
		v5.Aux = typeToAux(t1)
		v5.AddArg2(dst, mem)
		v3.AddArg3(v4, d3, v5)
		v1.AddArg3(v2, d2, v3)
		v.AddArg3(v0, d1, v1)
		return true
	}
	// match: (Move {t1} [n] dst p1 mem:(Store {t2} (OffPtr <tt2> [o2] p2) d1 (Store {t3} (OffPtr <tt3> [o3] p3) d2 (Store {t4} (OffPtr <tt4> [o4] p4) d3 (Store {t5} (OffPtr <tt5> [o5] p5) d4 (Zero {t6} [n] p6 _))))))
	// cond: isSamePtr(p1, p2) && isSamePtr(p2, p3) && isSamePtr(p3, p4) && isSamePtr(p4, p5) && isSamePtr(p5, p6) && t2.Alignment() <= t1.Alignment() && t3.Alignment() <= t1.Alignment() && t4.Alignment() <= t1.Alignment() && t5.Alignment() <= t1.Alignment() && t6.Alignment() <= t1.Alignment() && registerizable(b, t2) && registerizable(b, t3) && registerizable(b, t4) && registerizable(b, t5) && n >= o2 + t2.Size() && n >= o3 + t3.Size() && n >= o4 + t4.Size() && n >= o5 + t5.Size()
	// result: (Store {t2} (OffPtr <tt2> [o2] dst) d1 (Store {t3} (OffPtr <tt3> [o3] dst) d2 (Store {t4} (OffPtr <tt4> [o4] dst) d3 (Store {t5} (OffPtr <tt5> [o5] dst) d4 (Zero {t1} [n] dst mem)))))
	for {
		n := auxIntToInt64(v.AuxInt)
		t1 := auxToType(v.Aux)
		dst := v_0
		p1 := v_1
		mem := v_2
		if mem.Op != OpStore {
			break
		}
		t2 := auxToType(mem.Aux)
		_ = mem.Args[2]
		mem_0 := mem.Args[0]
		if mem_0.Op != OpOffPtr {
			break
		}
		tt2 := mem_0.Type
		o2 := auxIntToInt64(mem_0.AuxInt)
		p2 := mem_0.Args[0]
		d1 := mem.Args[1]
		mem_2 := mem.Args[2]
		if mem_2.Op != OpStore {
			break
		}
		t3 := auxToType(mem_2.Aux)
		_ = mem_2.Args[2]
		mem_2_0 := mem_2.Args[0]
		if mem_2_0.Op != OpOffPtr {
			break
		}
		tt3 := mem_2_0.Type
		o3 := auxIntToInt64(mem_2_0.AuxInt)
		p3 := mem_2_0.Args[0]
		d2 := mem_2.Args[1]
		mem_2_2 := mem_2.Args[2]
		if mem_2_2.Op != OpStore {
			break
		}
		t4 := auxToType(mem_2_2.Aux)
		_ = mem_2_2.Args[2]
		mem_2_2_0 := mem_2_2.Args[0]
		if mem_2_2_0.Op != OpOffPtr {
			break
		}
		tt4 := mem_2_2_0.Type
		o4 := auxIntToInt64(mem_2_2_0.AuxInt)
		p4 := mem_2_2_0.Args[0]
		d3 := mem_2_2.Args[1]
		mem_2_2_2 := mem_2_2.Args[2]
		if mem_2_2_2.Op != OpStore {
			break
		}
		t5 := auxToType(mem_2_2_2.Aux)
		_ = mem_2_2_2.Args[2]
		mem_2_2_2_0 := mem_2_2_2.Args[0]
		if mem_2_2_2_0.Op != OpOffPtr {
			break
		}
		tt5 := mem_2_2_2_0.Type
		o5 := auxIntToInt64(mem_2_2_2_0.AuxInt)
		p5 := mem_2_2_2_0.Args[0]
		d4 := mem_2_2_2.Args[1]
		mem_2_2_2_2 := mem_2_2_2.Args[2]
		if mem_2_2_2_2.Op != OpZero || auxIntToInt64(mem_2_2_2_2.AuxInt) != n {
			break
		}
		t6 := auxToType(mem_2_2_2_2.Aux)
		p6 := mem_2_2_2_2.Args[0]
		if !(isSamePtr(p1, p2) && isSamePtr(p2, p3) && isSamePtr(p3, p4) && isSamePtr(p4, p5) && isSamePtr(p5, p6) && t2.Alignment() <= t1.Alignment() && t3.Alignment() <= t1.Alignment() && t4.Alignment() <= t1.Alignment() && t5.Alignment() <= t1.Alignment() && t6.Alignment() <= t1.Alignment() && registerizable(b, t2) && registerizable(b, t3) && registerizable(b, t4) && registerizable(b, t5) && n >= o2+t2.Size() && n >= o3+t3.Size() && n >= o4+t4.Size() && n >= o5+t5.Size()) {
			break
		}
		v.reset(OpStore)
		v.Aux = typeToAux(t2)
		v0 := b.NewValue0(v.Pos, OpOffPtr, tt2)
		v0.AuxInt = int64ToAuxInt(o2)
		v0.AddArg(dst)
		v1 := b.NewValue0(v.Pos, OpStore, types.TypeMem)
		v1.Aux = typeToAux(t3)
		v2 := b.NewValue0(v.Pos, OpOffPtr, tt3)
		v2.AuxInt = int64ToAuxInt(o3)
		v2.AddArg(dst)
		v3 := b.NewValue0(v.Pos, OpStore, types.TypeMem)
		v3.Aux = typeToAux(t4)
		v4 := b.NewValue0(v.Pos, OpOffPtr, tt4)
		v4.AuxInt = int64ToAuxInt(o4)
		v4.AddArg(dst)
		v5 := b.NewValue0(v.Pos, OpStore, types.TypeMem)
		v5.Aux = typeToAux(t5)
		v6 := b.NewValue0(v.Pos, OpOffPtr, tt5)
		v6.AuxInt = int64ToAuxInt(o5)
		v6.AddArg(dst)
		v7 := b.NewValue0(v.Pos, OpZero, types.TypeMem)
		v7.AuxInt = int64ToAuxInt(n)
		v7.Aux = typeToAux(t1)
		v7.AddArg2(dst, mem)
		v5.AddArg3(v6, d4, v7)
		v3.AddArg3(v4, d3, v5)
		v1.AddArg3(v2, d2, v3)
		v.AddArg3(v0, d1, v1)
		return true
	}
	// match: (Move {t1} [n] dst p1 mem:(VarDef (Store {t2} op2:(OffPtr <tt2> [o2] p2) d1 (Zero {t3} [n] p3 _))))
	// cond: isSamePtr(p1, p2) && isSamePtr(p2, p3) && t2.Alignment() <= t1.Alignment() && t3.Alignment() <= t1.Alignment() && registerizable(b, t2) && n >= o2 + t2.Size()
	// result: (Store {t2} (OffPtr <tt2> [o2] dst) d1 (Zero {t1} [n] dst mem))
	for {
		n := auxIntToInt64(v.AuxInt)
		t1 := auxToType(v.Aux)
		dst := v_0
		p1 := v_1
		mem := v_2
		if mem.Op != OpVarDef {
			break
		}
		mem_0 := mem.Args[0]
		if mem_0.Op != OpStore {
			break
		}
		t2 := auxToType(mem_0.Aux)
		_ = mem_0.Args[2]
		op2 := mem_0.Args[0]
		if op2.Op != OpOffPtr {
			break
		}
		tt2 := op2.Type
		o2 := auxIntToInt64(op2.AuxInt)
		p2 := op2.Args[0]
		d1 := mem_0.Args[1]
		mem_0_2 := mem_0.Args[2]
		if mem_0_2.Op != OpZero || auxIntToInt64(mem_0_2.AuxInt) != n {
			break
		}
		t3 := auxToType(mem_0_2.Aux)
		p3 := mem_0_2.Args[0]
		if !(isSamePtr(p1, p2) && isSamePtr(p2, p3) && t2.Alignment() <= t1.Alignment() && t3.Alignment() <= t1.Alignment() && registerizable(b, t2) && n >= o2+t2.Size()) {
			break
		}
		v.reset(OpStore)
		v.Aux = typeToAux(t2)
		v0 := b.NewValue0(v.Pos, OpOffPtr, tt2)
		v0.AuxInt = int64ToAuxInt(o2)
		v0.AddArg(dst)
		v1 := b.NewValue0(v.Pos, OpZero, types.TypeMem)
		v1.AuxInt = int64ToAuxInt(n)
		v1.Aux = typeToAux(t1)
		v1.AddArg2(dst, mem)
		v.AddArg3(v0, d1, v1)
		return true
	}
	// match: (Move {t1} [n] dst p1 mem:(VarDef (Store {t2} (OffPtr <tt2> [o2] p2) d1 (Store {t3} (OffPtr <tt3> [o3] p3) d2 (Zero {t4} [n] p4 _)))))
	// cond: isSamePtr(p1, p2) && isSamePtr(p2, p3) && isSamePtr(p3, p4) && t2.Alignment() <= t1.Alignment() && t3.Alignment() <= t1.Alignment() && t4.Alignment() <= t1.Alignment() && registerizable(b, t2) && registerizable(b, t3) && n >= o2 + t2.Size() && n >= o3 + t3.Size()
	// result: (Store {t2} (OffPtr <tt2> [o2] dst) d1 (Store {t3} (OffPtr <tt3> [o3] dst) d2 (Zero {t1} [n] dst mem)))
	for {
		n := auxIntToInt64(v.AuxInt)
		t1 := auxToType(v.Aux)
		dst := v_0
		p1 := v_1
		mem := v_2
		if mem.Op != OpVarDef {
			break
		}
		mem_0 := mem.Args[0]
		if mem_0.Op != OpStore {
			break
		}
		t2 := auxToType(mem_0.Aux)
		_ = mem_0.Args[2]
		mem_0_0 := mem_0.Args[0]
		if mem_0_0.Op != OpOffPtr {
			break
		}
		tt2 := mem_0_0.Type
		o2 := auxIntToInt64(mem_0_0.AuxInt)
		p2 := mem_0_0.Args[0]
		d1 := mem_0.Args[1]
		mem_0_2 := mem_0.Args[2]
		if mem_0_2.Op != OpStore {
			break
		}
		t3 := auxToType(mem_0_2.Aux)
		_ = mem_0_2.Args[2]
		mem_0_2_0 := mem_0_2.Args[0]
		if mem_0_2_0.Op != OpOffPtr {
			break
		}
		tt3 := mem_0_2_0.Type
		o3 := auxIntToInt64(mem_0_2_0.AuxInt)
		p3 := mem_0_2_0.Args[0]
		d2 := mem_0_2.Args[1]
		mem_0_2_2 := mem_0_2.Args[2]
		if mem_0_2_2.Op != OpZero || auxIntToInt64(mem_0_2_2.AuxInt) != n {
			break
		}
		t4 := auxToType(mem_0_2_2.Aux)
		p4 := mem_0_2_2.Args[0]
		if !(isSamePtr(p1, p2) && isSamePtr(p2, p3) && isSamePtr(p3, p4) && t2.Alignment() <= t1.Alignment() && t3.Alignment() <= t1.Alignment() && t4.Alignment() <= t1.Alignment() && registerizable(b, t2) && registerizable(b, t3) && n >= o2+t2.Size() && n >= o3+t3.Size()) {
			break
		}
		v.reset(OpStore)
		v.Aux = typeToAux(t2)
		v0 := b.NewValue0(v.Pos, OpOffPtr, tt2)
		v0.AuxInt = int64ToAuxInt(o2)
		v0.AddArg(dst)
		v1 := b.NewValue0(v.Pos, OpStore, types.TypeMem)
		v1.Aux = typeToAux(t3)
		v2 := b.NewValue0(v.Pos, OpOffPtr, tt3)
		v2.AuxInt = int64ToAuxInt(o3)
		v2.AddArg(dst)
		v3 := b.NewValue0(v.Pos, OpZero, types.TypeMem)
		v3.AuxInt = int64ToAuxInt(n)
		v3.Aux = typeToAux(t1)
		v3.AddArg2(dst, mem)
		v1.AddArg3(v2, d2, v3)
		v.AddArg3(v0, d1, v1)
		return true
	}
	// match: (Move {t1} [n] dst p1 mem:(VarDef (Store {t2} (OffPtr <tt2> [o2] p2) d1 (Store {t3} (OffPtr <tt3> [o3] p3) d2 (Store {t4} (OffPtr <tt4> [o4] p4) d3 (Zero {t5} [n] p5 _))))))
	// cond: isSamePtr(p1, p2) && isSamePtr(p2, p3) && isSamePtr(p3, p4) && isSamePtr(p4, p5) && t2.Alignment() <= t1.Alignment() && t3.Alignment() <= t1.Alignment() && t4.Alignment() <= t1.Alignment() && t5.Alignment() <= t1.Alignment() && registerizable(b, t2) && registerizable(b, t3) && registerizable(b, t4) && n >= o2 + t2.Size() && n >= o3 + t3.Size() && n >= o4 + t4.Size()
	// result: (Store {t2} (OffPtr <tt2> [o2] dst) d1 (Store {t3} (OffPtr <tt3> [o3] dst) d2 (Store {t4} (OffPtr <tt4> [o4] dst) d3 (Zero {t1} [n] dst mem))))
	for {
		n := auxIntToInt64(v.AuxInt)
		t1 := auxToType(v.Aux)
		dst := v_0
		p1 := v_1
		mem := v_2
		if mem.Op != OpVarDef {
			break
		}
		mem_0 := mem.Args[0]
		if mem_0.Op != OpStore {
			break
		}
		t2 := auxToType(mem_0.Aux)
		_ = mem_0.Args[2]
		mem_0_0 := mem_0.Args[0]
		if mem_0_0.Op != OpOffPtr {
			break
		}
		tt2 := mem_0_0.Type
		o2 := auxIntToInt64(mem_0_0.AuxInt)
		p2 := mem_0_0.Args[0]
		d1 := mem_0.Args[1]
		mem_0_2 := mem_0.Args[2]
		if mem_0_2.Op != OpStore {
			break
		}
		t3 := auxToType(mem_0_2.Aux)
		_ = mem_0_2.Args[2]
		mem_0_2_0 := mem_0_2.Args[0]
		if mem_0_2_0.Op != OpOffPtr {
			break
		}
		tt3 := mem_0_2_0.Type
		o3 := auxIntToInt64(mem_0_2_0.AuxInt)
		p3 := mem_0_2_0.Args[0]
		d2 := mem_0_2.Args[1]
		mem_0_2_2 := mem_0_2.Args[2]
		if mem_0_2_2.Op != OpStore {
			break
		}
		t4 := auxToType(mem_0_2_2.Aux)
		_ = mem_0_2_2.Args[2]
		mem_0_2_2_0 := mem_0_2_2.Args[0]
		if mem_0_2_2_0.Op != OpOffPtr {
			break
		}
		tt4 := mem_0_2_2_0.Type
		o4 := auxIntToInt64(mem_0_2_2_0.AuxInt)
		p4 := mem_0_2_2_0.Args[0]
		d3 := mem_0_2_2.Args[1]
		mem_0_2_2_2 := mem_0_2_2.Args[2]
		if mem_0_2_2_2.Op != OpZero || auxIntToInt64(mem_0_2_2_2.AuxInt) != n {
			break
		}
		t5 := auxToType(mem_0_2_2_2.Aux)
		p5 := mem_0_2_2_2.Args[0]
		if !(isSamePtr(p1, p2) && isSamePtr(p2, p3) && isSamePtr(p3, p4) && isSamePtr(p4, p5) && t2.Alignment() <= t1.Alignment() && t3.Alignment() <= t1.Alignment() && t4.Alignment() <= t1.Alignment() && t5.Alignment() <= t1.Alignment() && registerizable(b, t2) && registerizable(b, t3) && registerizable(b, t4) && n >= o2+t2.Size() && n >= o3+t3.Size() && n >= o4+t4.Size()) {
			break
		}
		v.reset(OpStore)
		v.Aux = typeToAux(t2)
		v0 := b.NewValue0(v.Pos, OpOffPtr, tt2)
		v0.AuxInt = int64ToAuxInt(o2)
		v0.AddArg(dst)
		v1 := b.NewValue0(v.Pos, OpStore, types.TypeMem)
		v1.Aux = typeToAux(t3)
		v2 := b.NewValue0(v.Pos, OpOffPtr, tt3)
		v2.AuxInt = int64ToAuxInt(o3)
		v2.AddArg(dst)
		v3 := b.NewValue0(v.Pos, OpStore, types.TypeMem)
		v3.Aux = typeToAux(t4)
		v4 := b.NewValue0(v.Pos, OpOffPtr, tt4)
		v4.AuxInt = int64ToAuxInt(o4)
		v4.AddArg(dst)
		v5 := b.NewValue0(v.Pos, OpZero, types.TypeMem)
		v5.AuxInt = int64ToAuxInt(n)
		v5.Aux = typeToAux(t1)
		v5.AddArg2(dst, mem)
		v3.AddArg3(v4, d3, v5)
		v1.AddArg3(v2, d2, v3)
		v.AddArg3(v0, d1, v1)
		return true
	}
	// match: (Move {t1} [n] dst p1 mem:(VarDef (Store {t2} (OffPtr <tt2> [o2] p2) d1 (Store {t3} (OffPtr <tt3> [o3] p3) d2 (Store {t4} (OffPtr <tt4> [o4] p4) d3 (Store {t5} (OffPtr <tt5> [o5] p5) d4 (Zero {t6} [n] p6 _)))))))
	// cond: isSamePtr(p1, p2) && isSamePtr(p2, p3) && isSamePtr(p3, p4) && isSamePtr(p4, p5) && isSamePtr(p5, p6) && t2.Alignment() <= t1.Alignment() && t3.Alignment() <= t1.Alignment() && t4.Alignment() <= t1.Alignment() && t5.Alignment() <= t1.Alignment() && t6.Alignment() <= t1.Alignment() && registerizable(b, t2) && registerizable(b, t3) && registerizable(b, t4) && registerizable(b, t5) && n >= o2 + t2.Size() && n >= o3 + t3.Size() && n >= o4 + t4.Size() && n >= o5 + t5.Size()
	// result: (Store {t2} (OffPtr <tt2> [o2] dst) d1 (Store {t3} (OffPtr <tt3> [o3] dst) d2 (Store {t4} (OffPtr <tt4> [o4] dst) d3 (Store {t5} (OffPtr <tt5> [o5] dst) d4 (Zero {t1} [n] dst mem)))))
	for {
		n := auxIntToInt64(v.AuxInt)
		t1 := auxToType(v.Aux)
		dst := v_0
		p1 := v_1
		mem := v_2
		if mem.Op != OpVarDef {
			break
		}
		mem_0 := mem.Args[0]
		if mem_0.Op != OpStore {
			break
		}
		t2 := auxToType(mem_0.Aux)
		_ = mem_0.Args[2]
		mem_0_0 := mem_0.Args[0]
		if mem_0_0.Op != OpOffPtr {
			break
		}
		tt2 := mem_0_0.Type
		o2 := auxIntToInt64(mem_0_0.AuxInt)
		p2 := mem_0_0.Args[0]
		d1 := mem_0.Args[1]
		mem_0_2 := mem_0.Args[2]
		if mem_0_2.Op != OpStore {
			break
		}
		t3 := auxToType(mem_0_2.Aux)
		_ = mem_0_2.Args[2]
		mem_0_2_0 := mem_0_2.Args[0]
		if mem_0_2_0.Op != OpOffPtr {
			break
		}
		tt3 := mem_0_2_0.Type
		o3 := auxIntToInt64(mem_0_2_0.AuxInt)
		p3 := mem_0_2_0.Args[0]
		d2 := mem_0_2.Args[1]
		mem_0_2_2 := mem_0_2.Args[2]
		if mem_0_2_2.Op != OpStore {
			break
		}
		t4 := auxToType(mem_0_2_2.Aux)
		_ = mem_0_2_2.Args[2]
		mem_0_2_2_0 := mem_0_2_2.Args[0]
		if mem_0_2_2_0.Op != OpOffPtr {
			break
		}
		tt4 := mem_0_2_2_0.Type
		o4 := auxIntToInt64(mem_0_2_2_0.AuxInt)
		p4 := mem_0_2_2_0.Args[0]
		d3 := mem_0_2_2.Args[1]
		mem_0_2_2_2 := mem_0_2_2.Args[2]
		if mem_0_2_2_2.Op != OpStore {
			break
		}
		t5 := auxToType(mem_0_2_2_2.Aux)
		_ = mem_0_2_2_2.Args[2]
		mem_0_2_2_2_0 := mem_0_2_2_2.Args[0]
		if mem_0_2_2_2_0.Op != OpOffPtr {
			break
		}
		tt5 := mem_0_2_2_2_0.Type
		o5 := auxIntToInt64(mem_0_2_2_2_0.AuxInt)
		p5 := mem_0_2_2_2_0.Args[0]
		d4 := mem_0_2_2_2.Args[1]
		mem_0_2_2_2_2 := mem_0_2_2_2.Args[2]
		if mem_0_2_2_2_2.Op != OpZero || auxIntToInt64(mem_0_2_2_2_2.AuxInt) != n {
			break
		}
		t6 := auxToType(mem_0_2_2_2_2.Aux)
		p6 := mem_0_2_2_2_2.Args[0]
		if !(isSamePtr(p1, p2) && isSamePtr(p2, p3) && isSamePtr(p3, p4) && isSamePtr(p4, p5) && isSamePtr(p5, p6) && t2.Alignment() <= t1.Alignment() && t3.Alignment() <= t1.Alignment() && t4.Alignment() <= t1.Alignment() && t5.Alignment() <= t1.Alignment() && t6.Alignment() <= t1.Alignment() && registerizable(b, t2) && registerizable(b, t3) && registerizable(b, t4) && registerizable(b, t5) && n >= o2+t2.Size() && n >= o3+t3.Size() && n >= o4+t4.Size() && n >= o5+t5.Size()) {
			break
		}
		v.reset(OpStore)
		v.Aux = typeToAux(t2)
		v0 := b.NewValue0(v.Pos, OpOffPtr, tt2)
		v0.AuxInt = int64ToAuxInt(o2)
		v0.AddArg(dst)
		v1 := b.NewValue0(v.Pos, OpStore, types.TypeMem)
		v1.Aux = typeToAux(t3)
		v2 := b.NewValue0(v.Pos, OpOffPtr, tt3)
		v2.AuxInt = int64ToAuxInt(o3)
		v2.AddArg(dst)
		v3 := b.NewValue0(v.Pos, OpStore, types.TypeMem)
		v3.Aux = typeToAux(t4)
		v4 := b.NewValue0(v.Pos, OpOffPtr, tt4)
		v4.AuxInt = int64ToAuxInt(o4)
		v4.AddArg(dst)
		v5 := b.NewValue0(v.Pos, OpStore, types.TypeMem)
		v5.Aux = typeToAux(t5)
		v6 := b.NewValue0(v.Pos, OpOffPtr, tt5)
		v6.AuxInt = int64ToAuxInt(o5)
		v6.AddArg(dst)
		v7 := b.NewValue0(v.Pos, OpZero, types.TypeMem)
		v7.AuxInt = int64ToAuxInt(n)
		v7.Aux = typeToAux(t1)
		v7.AddArg2(dst, mem)
		v5.AddArg3(v6, d4, v7)
		v3.AddArg3(v4, d3, v5)
		v1.AddArg3(v2, d2, v3)
		v.AddArg3(v0, d1, v1)
		return true
	}
	// match: (Move {t1} [s] dst tmp1 midmem:(Move {t2} [s] tmp2 src _))
	// cond: t1.Compare(t2) == types.CMPeq && isSamePtr(tmp1, tmp2) && isStackPtr(src) && !isVolatile(src) && disjoint(src, s, tmp2, s) && (disjoint(src, s, dst, s) || isInlinableMemmove(dst, src, s, config))
	// result: (Move {t1} [s] dst src midmem)
	for {
		s := auxIntToInt64(v.AuxInt)
		t1 := auxToType(v.Aux)
		dst := v_0
		tmp1 := v_1
		midmem := v_2
		if midmem.Op != OpMove || auxIntToInt64(midmem.AuxInt) != s {
			break
		}
		t2 := auxToType(midmem.Aux)
		src := midmem.Args[1]
		tmp2 := midmem.Args[0]
		if !(t1.Compare(t2) == types.CMPeq && isSamePtr(tmp1, tmp2) && isStackPtr(src) && !isVolatile(src) && disjoint(src, s, tmp2, s) && (disjoint(src, s, dst, s) || isInlinableMemmove(dst, src, s, config))) {
			break
		}
		v.reset(OpMove)
		v.AuxInt = int64ToAuxInt(s)
		v.Aux = typeToAux(t1)
		v.AddArg3(dst, src, midmem)
		return true
	}
	// match: (Move {t1} [s] dst tmp1 midmem:(VarDef (Move {t2} [s] tmp2 src _)))
	// cond: t1.Compare(t2) == types.CMPeq && isSamePtr(tmp1, tmp2) && isStackPtr(src) && !isVolatile(src) && disjoint(src, s, tmp2, s) && (disjoint(src, s, dst, s) || isInlinableMemmove(dst, src, s, config))
	// result: (Move {t1} [s] dst src midmem)
	for {
		s := auxIntToInt64(v.AuxInt)
		t1 := auxToType(v.Aux)
		dst := v_0
		tmp1 := v_1
		midmem := v_2
		if midmem.Op != OpVarDef {
			break
		}
		midmem_0 := midmem.Args[0]
		if midmem_0.Op != OpMove || auxIntToInt64(midmem_0.AuxInt) != s {
			break
		}
		t2 := auxToType(midmem_0.Aux)
		src := midmem_0.Args[1]
		tmp2 := midmem_0.Args[0]
		if !(t1.Compare(t2) == types.CMPeq && isSamePtr(tmp1, tmp2) && isStackPtr(src) && !isVolatile(src) && disjoint(src, s, tmp2, s) && (disjoint(src, s, dst, s) || isInlinableMemmove(dst, src, s, config))) {
			break
		}
		v.reset(OpMove)
		v.AuxInt = int64ToAuxInt(s)
		v.Aux = typeToAux(t1)
		v.AddArg3(dst, src, midmem)
		return true
	}
	// match: (Move dst src mem)
	// cond: isSamePtr(dst, src)
	// result: mem
	for {
		dst := v_0
		src := v_1
		mem := v_2
		if !(isSamePtr(dst, src)) {
			break
		}
		v.copyOf(mem)
		return true
	}
	return false
}
func rewriteValuegeneric_OpMul16(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Mul16 (Const16 [c]) (Const16 [d]))
	// result: (Const16 [c*d])
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
			v.AuxInt = int16ToAuxInt(c * d)
			return true
		}
		break
	}
	// match: (Mul16 (Const16 [1]) x)
	// result: x
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpConst16 || auxIntToInt16(v_0.AuxInt) != 1 {
				continue
			}
			x := v_1
			v.copyOf(x)
			return true
		}
		break
	}
	// match: (Mul16 (Const16 [-1]) x)
	// result: (Neg16 x)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpConst16 || auxIntToInt16(v_0.AuxInt) != -1 {
				continue
			}
			x := v_1
			v.reset(OpNeg16)
			v.AddArg(x)
			return true
		}
		break
	}
	// match: (Mul16 <t> n (Const16 [c]))
	// cond: isPowerOfTwo(c)
	// result: (Lsh16x64 <t> n (Const64 <typ.UInt64> [log16(c)]))
	for {
		t := v.Type
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			n := v_0
			if v_1.Op != OpConst16 {
				continue
			}
			c := auxIntToInt16(v_1.AuxInt)
			if !(isPowerOfTwo(c)) {
				continue
			}
			v.reset(OpLsh16x64)
			v.Type = t
			v0 := b.NewValue0(v.Pos, OpConst64, typ.UInt64)
			v0.AuxInt = int64ToAuxInt(log16(c))
			v.AddArg2(n, v0)
			return true
		}
		break
	}
	// match: (Mul16 <t> n (Const16 [c]))
	// cond: t.IsSigned() && isPowerOfTwo(-c)
	// result: (Neg16 (Lsh16x64 <t> n (Const64 <typ.UInt64> [log16(-c)])))
	for {
		t := v.Type
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			n := v_0
			if v_1.Op != OpConst16 {
				continue
			}
			c := auxIntToInt16(v_1.AuxInt)
			if !(t.IsSigned() && isPowerOfTwo(-c)) {
				continue
			}
			v.reset(OpNeg16)
			v0 := b.NewValue0(v.Pos, OpL
```