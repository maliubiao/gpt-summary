Response:
我的思考过程如下：

1. **理解文件路径和上下文:**  文件路径 `go/src/cmd/compile/internal/ssa/rewritegeneric.go` 提示我这是一个 Go 编译器的内部代码，位于 SSA（Static Single Assignment）中间表示的优化阶段。文件名 `rewritegeneric.go` 暗示这个文件包含一些通用的重写规则。提供的代码片段是该文件的第 19 部分，总共 26 部分，说明这是一个较大的文件，其中包含多个优化规则。

2. **分析代码结构:** 代码主要由多个以 `rewriteValuegeneric_Op...` 为前缀的函数组成。每个函数都接受一个 `*Value` 类型的参数 `v`，并返回一个 `bool` 值。  `*Value` 很可能是 SSA 图中的一个节点，代表一个操作或值。 `bool` 返回值可能表示是否应用了重写规则。

3. **识别核心功能：基于模式匹配的 SSA 重写:**  每个函数内部都包含若干个 `match:` 开头的注释，后跟代码块。 这些 `match:` 注释描述了希望匹配的 SSA 模式，例如 `(OrB (Less32U (Const32 [c]) x) (Less32U x (Const32 [d])))`。 接下来的 `cond:` 注释描述了应用重写规则的条件。  `result:` 注释描述了重写后的结果。 代码块本身实现了模式匹配和重写逻辑。循环和条件语句用于遍历操作数的各种排列和检查条件。`v.reset(...)` 用于改变当前节点的操作类型，`b.NewValue0(...)` 用于创建新的 SSA 节点，`v.AddArg(...)` 用于添加操作数。

4. **推断主要功能：布尔运算和位运算的优化:** 仔细观察 `Op` 的类型（例如 `OpLeq32U`, `OpLess16U`, `OpOrB`, `OpRotateLeft16`），可以判断这段代码主要处理布尔运算（`OrB`）和位运算（各种比较操作和位移操作）。  优化的目标似乎是将一些复杂的布尔表达式和位运算表达式简化为更高效的形式，特别是当涉及到常量操作数时。

5. **代码举例说明:**  选择一个典型的优化规则进行代码举例。 例如：

   ```go
   // match: (OrB (Less32U (Const32 [c]) x) (Less32U x (Const32 [d])))
   // cond: uint32(c) >= uint32(d)
   // result: (Less32U (Const32 <x.Type> [c-d]) (Sub32 <x.Type> x (Const32 <x.Type> [d])))
   ```

   可以推断出，这个规则将形如 `(c < x) || (x < d)` 且 `c >= d` 的表达式转换为 `(c-d < x-d)`。  写出相应的 Go 代码：

   ```go
   package main

   func example(x uint32, c uint32, d uint32) bool {
       return c < x || x < d // 原始表达式
   }

   // 经过 rewritegeneric.go 的优化，如果 c >= d，则可能被转换为类似：
   func optimizedExample(x uint32, c uint32, d uint32) bool {
       return c-d < x-d
   }
   ```

   提供假设的输入和输出，以验证优化的正确性。

6. **推理 Go 语言功能:** 基于优化的目标和涉及的操作类型，可以推断这段代码主要实现了对 Go 语言中布尔运算和位运算的优化。 这类优化在编译器的后端非常常见，旨在提升程序的执行效率。

7. **关于命令行参数:**  这个代码片段本身不直接处理命令行参数。 `rewritegeneric.go` 是编译器内部的一个模块，其行为由编译器的整体流程控制，而不是通过独立的命令行参数配置。

8. **归纳功能 (第 19 部分):**  观察这一部分的代码，可以发现它主要集中在对 `OrB` (布尔 OR) 操作的重写，特别是当 `OrB` 的操作数是各种无符号整数的比较操作 (`Less`, `Leq`)，并且比较操作涉及常量时。  这些优化试图将两个相关的比较操作合并或简化为一个更紧凑的比较操作。 此外，也包含了一些 `Phi` 节点的简化，以及 `PtrIndex` 的优化，将其转化为 `AddPtr` 和 `Mul` 的组合。 最后开始涉及 `RotateLeft` 的优化。 因此，第 19 部分的主要功能是优化包含布尔 OR 运算的比较表达式，以及一些其他类型的通用 SSA 节点的简化和转换。

通过以上分析步骤，我能够比较全面地理解提供的 Go 语言代码片段的功能和上下文，并用中文进行解答。


这个go语言代码文件 `go/src/cmd/compile/internal/ssa/rewritegeneric.go` 的一部分，主要功能是**定义了一系列基于模式匹配的 SSA (Static Single Assignment) 重写规则，用于优化 Go 语言代码中的通用操作**。

具体来说，这段代码实现了针对特定操作符（OpCode）的优化，这些优化通常涉及以下几个方面：

1. **布尔运算的优化:**  代码片段中包含了多个针对 `OrB` (布尔 OR) 操作的重写规则。这些规则尝试将两个相关的比较操作合并或简化为一个更简单的比较操作。 例如，将 `(c < x) || (x < d)` 在特定条件下转换为 `(c-d < x-d)` 或其他等价形式。

2. **无符号整数比较的优化:** 这些针对 `OrB` 的规则，其操作数通常是无符号整数的比较操作，如 `LessU` (小于) 和 `LeqU` (小于等于)。 优化目标是减少比较的次数或将复杂的比较转换为更直接的形式。

3. **常量折叠和传播:**  规则中经常出现对常量操作数的判断和处理（例如 `Const32 [c]`）。这表明该文件的一个重要功能是进行常量折叠，即在编译时计算出常量表达式的值，并用该值替换表达式。

4. **位运算的优化 (开始涉及):** 在这段代码的末尾，开始出现 `RotateLeft16` 和 `RotateLeft32` 的优化规则。这预示着该文件还会包含针对位旋转等位运算的优化。

5. **Phi 函数的优化:**  代码中也包含对 `Phi` 函数的优化。 `Phi` 函数在 SSA 中用于合并来自不同控制流路径的值。这里的优化规则尝试将多个相同的常量 `Phi` 节点简化为一个常量节点，或者对 `Not` 操作嵌套的 `Phi` 节点进行转换。

6. **指针操作的优化:**  `rewriteValuegeneric_OpPtrIndex` 函数将指针索引操作转换为指针加法和乘法操作，这是一种更底层的表示，可能更方便后续的优化或目标代码生成。

**推理 Go 语言功能的实现:**

这段代码主要实现了 Go 语言中**布尔表达式和无符号整数比较运算的优化**。通过识别特定的模式，编译器可以将一些低效或冗余的表达式转换为更简洁高效的形式。

**Go 代码举例说明:**

以下是一个基于代码片段中 `OrB` 优化的例子：

```go
package main

import "fmt"

func main() {
	x := uint32(10)
	c := uint32(5)
	d := uint32(8)

	result1 := c < x || x < d
	fmt.Println("原始表达式结果:", result1)

	// rewritegeneric.go 中的规则会将上面的表达式在特定条件下转换为类似下面的形式
	// 假设 c >= d 的情况，虽然这个例子不满足，但为了演示转换思路
	c2 := uint32(9)
	d2 := uint32(6)
	result2 := c2-d2 < x-d2
	fmt.Println("优化后的表达式结果:", result2)
}
```

**假设的输入与输出:**

对于上面的例子，如果 `c = 5`, `x = 10`, `d = 8`，则：

* 原始表达式 `c < x || x < d`  为 `5 < 10 || 10 < 8`，结果为 `true || false`，输出 `true`。

对于 `c2 = 9`, `x = 10`, `d2 = 6`，虽然我们的例子不完全匹配规则的条件，但为了说明转换的思路：

* 优化后的表达式 `c2-d2 < x-d2` 为 `9-6 < 10-6`，即 `3 < 4`，结果为 `true`。

**注意:**  实际的优化发生在编译器的内部 SSA 阶段，开发者编写的 Go 代码直接使用这些优化带来的性能提升，通常不需要显式地写出优化后的形式。

**命令行参数的具体处理:**

这段代码本身不涉及命令行参数的处理。 `rewritegeneric.go` 是 Go 编译器内部的一部分，它在编译过程中被调用。 编译器的命令行参数（例如 `-O` 用于优化）会影响是否启用这些优化规则，但具体的规则逻辑在此文件中定义。

**使用者易犯错的点:**

开发者通常不需要直接与 `rewritegeneric.go` 文件打交道。 编译器会自动应用这些优化。 因此，使用者不易犯错。 理解这些优化规则有助于理解编译器的工作原理，但不会直接影响日常 Go 编程。

**第19部分的功能归纳:**

这段 `rewritegeneric.go` 的第 19 部分，其核心功能是**优化包含布尔 OR 运算的比较表达式**，特别是针对无符号整数的比较，并且比较中包含常量的情况。 此外，还包括一些 `Phi` 节点的简化和 `PtrIndex` 到更底层操作的转换，并开始涉及位旋转操作的优化。 总体目标是提高生成代码的效率。

### 提示词
```
这是路径为go/src/cmd/compile/internal/ssa/rewritegeneric.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第19部分，共26部分，请归纳一下它的功能
```

### 源代码
```go
nst32 [c]) x) (Less32U x (Const32 [d])))
	// cond: uint32(c) >= uint32(d)
	// result: (Leq32U (Const32 <x.Type> [c-d]) (Sub32 <x.Type> x (Const32 <x.Type> [d])))
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpLeq32U {
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
	// match: (OrB (Less16U (Const16 [c]) x) (Less16U x (Const16 [d])))
	// cond: uint16(c) >= uint16(d)
	// result: (Less16U (Const16 <x.Type> [c-d]) (Sub16 <x.Type> x (Const16 <x.Type> [d])))
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpLess16U {
				continue
			}
			x := v_0.Args[1]
			v_0_0 := v_0.Args[0]
			if v_0_0.Op != OpConst16 {
				continue
			}
			c := auxIntToInt16(v_0_0.AuxInt)
			if v_1.Op != OpLess16U {
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
			if !(uint16(c) >= uint16(d)) {
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
	// match: (OrB (Leq16U (Const16 [c]) x) (Less16U x (Const16 [d])))
	// cond: uint16(c) >= uint16(d)
	// result: (Leq16U (Const16 <x.Type> [c-d]) (Sub16 <x.Type> x (Const16 <x.Type> [d])))
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpLeq16U {
				continue
			}
			x := v_0.Args[1]
			v_0_0 := v_0.Args[0]
			if v_0_0.Op != OpConst16 {
				continue
			}
			c := auxIntToInt16(v_0_0.AuxInt)
			if v_1.Op != OpLess16U {
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
			if !(uint16(c) >= uint16(d)) {
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
	// match: (OrB (Less8U (Const8 [c]) x) (Less8U x (Const8 [d])))
	// cond: uint8(c) >= uint8(d)
	// result: (Less8U (Const8 <x.Type> [c-d]) (Sub8 <x.Type> x (Const8 <x.Type> [d])))
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpLess8U {
				continue
			}
			x := v_0.Args[1]
			v_0_0 := v_0.Args[0]
			if v_0_0.Op != OpConst8 {
				continue
			}
			c := auxIntToInt8(v_0_0.AuxInt)
			if v_1.Op != OpLess8U {
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
			if !(uint8(c) >= uint8(d)) {
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
	// match: (OrB (Leq8U (Const8 [c]) x) (Less8U x (Const8 [d])))
	// cond: uint8(c) >= uint8(d)
	// result: (Leq8U (Const8 <x.Type> [c-d]) (Sub8 <x.Type> x (Const8 <x.Type> [d])))
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpLeq8U {
				continue
			}
			x := v_0.Args[1]
			v_0_0 := v_0.Args[0]
			if v_0_0.Op != OpConst8 {
				continue
			}
			c := auxIntToInt8(v_0_0.AuxInt)
			if v_1.Op != OpLess8U {
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
			if !(uint8(c) >= uint8(d)) {
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
	// match: (OrB (Less64U (Const64 [c]) x) (Leq64U x (Const64 [d])))
	// cond: uint64(c) >= uint64(d+1) && uint64(d+1) > uint64(d)
	// result: (Less64U (Const64 <x.Type> [c-d-1]) (Sub64 <x.Type> x (Const64 <x.Type> [d+1])))
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
			if v_1.Op != OpLeq64U {
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
			if !(uint64(c) >= uint64(d+1) && uint64(d+1) > uint64(d)) {
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
	// match: (OrB (Leq64U (Const64 [c]) x) (Leq64U x (Const64 [d])))
	// cond: uint64(c) >= uint64(d+1) && uint64(d+1) > uint64(d)
	// result: (Leq64U (Const64 <x.Type> [c-d-1]) (Sub64 <x.Type> x (Const64 <x.Type> [d+1])))
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
			if v_1.Op != OpLeq64U {
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
			if !(uint64(c) >= uint64(d+1) && uint64(d+1) > uint64(d)) {
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
	// match: (OrB (Less32U (Const32 [c]) x) (Leq32U x (Const32 [d])))
	// cond: uint32(c) >= uint32(d+1) && uint32(d+1) > uint32(d)
	// result: (Less32U (Const32 <x.Type> [c-d-1]) (Sub32 <x.Type> x (Const32 <x.Type> [d+1])))
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
			if v_1.Op != OpLeq32U {
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
			if !(uint32(c) >= uint32(d+1) && uint32(d+1) > uint32(d)) {
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
	// match: (OrB (Leq32U (Const32 [c]) x) (Leq32U x (Const32 [d])))
	// cond: uint32(c) >= uint32(d+1) && uint32(d+1) > uint32(d)
	// result: (Leq32U (Const32 <x.Type> [c-d-1]) (Sub32 <x.Type> x (Const32 <x.Type> [d+1])))
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpLeq32U {
				continue
			}
			x := v_0.Args[1]
			v_0_0 := v_0.Args[0]
			if v_0_0.Op != OpConst32 {
				continue
			}
			c := auxIntToInt32(v_0_0.AuxInt)
			if v_1.Op != OpLeq32U {
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
			if !(uint32(c) >= uint32(d+1) && uint32(d+1) > uint32(d)) {
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
	// match: (OrB (Less16U (Const16 [c]) x) (Leq16U x (Const16 [d])))
	// cond: uint16(c) >= uint16(d+1) && uint16(d+1) > uint16(d)
	// result: (Less16U (Const16 <x.Type> [c-d-1]) (Sub16 <x.Type> x (Const16 <x.Type> [d+1])))
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpLess16U {
				continue
			}
			x := v_0.Args[1]
			v_0_0 := v_0.Args[0]
			if v_0_0.Op != OpConst16 {
				continue
			}
			c := auxIntToInt16(v_0_0.AuxInt)
			if v_1.Op != OpLeq16U {
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
			if !(uint16(c) >= uint16(d+1) && uint16(d+1) > uint16(d)) {
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
	// match: (OrB (Leq16U (Const16 [c]) x) (Leq16U x (Const16 [d])))
	// cond: uint16(c) >= uint16(d+1) && uint16(d+1) > uint16(d)
	// result: (Leq16U (Const16 <x.Type> [c-d-1]) (Sub16 <x.Type> x (Const16 <x.Type> [d+1])))
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpLeq16U {
				continue
			}
			x := v_0.Args[1]
			v_0_0 := v_0.Args[0]
			if v_0_0.Op != OpConst16 {
				continue
			}
			c := auxIntToInt16(v_0_0.AuxInt)
			if v_1.Op != OpLeq16U {
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
			if !(uint16(c) >= uint16(d+1) && uint16(d+1) > uint16(d)) {
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
	// match: (OrB (Less8U (Const8 [c]) x) (Leq8U x (Const8 [d])))
	// cond: uint8(c) >= uint8(d+1) && uint8(d+1) > uint8(d)
	// result: (Less8U (Const8 <x.Type> [c-d-1]) (Sub8 <x.Type> x (Const8 <x.Type> [d+1])))
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpLess8U {
				continue
			}
			x := v_0.Args[1]
			v_0_0 := v_0.Args[0]
			if v_0_0.Op != OpConst8 {
				continue
			}
			c := auxIntToInt8(v_0_0.AuxInt)
			if v_1.Op != OpLeq8U {
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
			if !(uint8(c) >= uint8(d+1) && uint8(d+1) > uint8(d)) {
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
	// match: (OrB (Leq8U (Const8 [c]) x) (Leq8U x (Const8 [d])))
	// cond: uint8(c) >= uint8(d+1) && uint8(d+1) > uint8(d)
	// result: (Leq8U (Const8 <x.Type> [c-d-1]) (Sub8 <x.Type> x (Const8 <x.Type> [d+1])))
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpLeq8U {
				continue
			}
			x := v_0.Args[1]
			v_0_0 := v_0.Args[0]
			if v_0_0.Op != OpConst8 {
				continue
			}
			c := auxIntToInt8(v_0_0.AuxInt)
			if v_1.Op != OpLeq8U {
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
			if !(uint8(c) >= uint8(d+1) && uint8(d+1) > uint8(d)) {
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
	return false
}
func rewriteValuegeneric_OpPhi(v *Value) bool {
	b := v.Block
	// match: (Phi (Const8 [c]) (Const8 [c]))
	// result: (Const8 [c])
	for {
		if len(v.Args) != 2 {
			break
		}
		_ = v.Args[1]
		v_0 := v.Args[0]
		if v_0.Op != OpConst8 {
			break
		}
		c := auxIntToInt8(v_0.AuxInt)
		v_1 := v.Args[1]
		if v_1.Op != OpConst8 || auxIntToInt8(v_1.AuxInt) != c {
			break
		}
		v.reset(OpConst8)
		v.AuxInt = int8ToAuxInt(c)
		return true
	}
	// match: (Phi (Const16 [c]) (Const16 [c]))
	// result: (Const16 [c])
	for {
		if len(v.Args) != 2 {
			break
		}
		_ = v.Args[1]
		v_0 := v.Args[0]
		if v_0.Op != OpConst16 {
			break
		}
		c := auxIntToInt16(v_0.AuxInt)
		v_1 := v.Args[1]
		if v_1.Op != OpConst16 || auxIntToInt16(v_1.AuxInt) != c {
			break
		}
		v.reset(OpConst16)
		v.AuxInt = int16ToAuxInt(c)
		return true
	}
	// match: (Phi (Const32 [c]) (Const32 [c]))
	// result: (Const32 [c])
	for {
		if len(v.Args) != 2 {
			break
		}
		_ = v.Args[1]
		v_0 := v.Args[0]
		if v_0.Op != OpConst32 {
			break
		}
		c := auxIntToInt32(v_0.AuxInt)
		v_1 := v.Args[1]
		if v_1.Op != OpConst32 || auxIntToInt32(v_1.AuxInt) != c {
			break
		}
		v.reset(OpConst32)
		v.AuxInt = int32ToAuxInt(c)
		return true
	}
	// match: (Phi (Const64 [c]) (Const64 [c]))
	// result: (Const64 [c])
	for {
		if len(v.Args) != 2 {
			break
		}
		_ = v.Args[1]
		v_0 := v.Args[0]
		if v_0.Op != OpConst64 {
			break
		}
		c := auxIntToInt64(v_0.AuxInt)
		v_1 := v.Args[1]
		if v_1.Op != OpConst64 || auxIntToInt64(v_1.AuxInt) != c {
			break
		}
		v.reset(OpConst64)
		v.AuxInt = int64ToAuxInt(c)
		return true
	}
	// match: (Phi <t> nx:(Not x) ny:(Not y))
	// cond: nx.Uses == 1 && ny.Uses == 1
	// result: (Not (Phi <t> x y))
	for {
		if len(v.Args) != 2 {
			break
		}
		t := v.Type
		_ = v.Args[1]
		nx := v.Args[0]
		if nx.Op != OpNot {
			break
		}
		x := nx.Args[0]
		ny := v.Args[1]
		if ny.Op != OpNot {
			break
		}
		y := ny.Args[0]
		if !(nx.Uses == 1 && ny.Uses == 1) {
			break
		}
		v.reset(OpNot)
		v0 := b.NewValue0(v.Pos, OpPhi, t)
		v0.AddArg2(x, y)
		v.AddArg(v0)
		return true
	}
	return false
}
func rewriteValuegeneric_OpPtrIndex(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	config := b.Func.Config
	typ := &b.Func.Config.Types
	// match: (PtrIndex <t> ptr idx)
	// cond: config.PtrSize == 4 && is32Bit(t.Elem().Size())
	// result: (AddPtr ptr (Mul32 <typ.Int> idx (Const32 <typ.Int> [int32(t.Elem().Size())])))
	for {
		t := v.Type
		ptr := v_0
		idx := v_1
		if !(config.PtrSize == 4 && is32Bit(t.Elem().Size())) {
			break
		}
		v.reset(OpAddPtr)
		v0 := b.NewValue0(v.Pos, OpMul32, typ.Int)
		v1 := b.NewValue0(v.Pos, OpConst32, typ.Int)
		v1.AuxInt = int32ToAuxInt(int32(t.Elem().Size()))
		v0.AddArg2(idx, v1)
		v.AddArg2(ptr, v0)
		return true
	}
	// match: (PtrIndex <t> ptr idx)
	// cond: config.PtrSize == 8
	// result: (AddPtr ptr (Mul64 <typ.Int> idx (Const64 <typ.Int> [t.Elem().Size()])))
	for {
		t := v.Type
		ptr := v_0
		idx := v_1
		if !(config.PtrSize == 8) {
			break
		}
		v.reset(OpAddPtr)
		v0 := b.NewValue0(v.Pos, OpMul64, typ.Int)
		v1 := b.NewValue0(v.Pos, OpConst64, typ.Int)
		v1.AuxInt = int64ToAuxInt(t.Elem().Size())
		v0.AddArg2(idx, v1)
		v.AddArg2(ptr, v0)
		return true
	}
	return false
}
func rewriteValuegeneric_OpRotateLeft16(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	config := b.Func.Config
	// match: (RotateLeft16 x (Const16 [c]))
	// cond: c%16 == 0
	// result: x
	for {
		x := v_0
		if v_1.Op != OpConst16 {
			break
		}
		c := auxIntToInt16(v_1.AuxInt)
		if !(c%16 == 0) {
			break
		}
		v.copyOf(x)
		return true
	}
	// match: (RotateLeft16 x (And64 y (Const64 [c])))
	// cond: c&15 == 15
	// result: (RotateLeft16 x y)
	for {
		x := v_0
		if v_1.Op != OpAnd64 {
			break
		}
		_ = v_1.Args[1]
		v_1_0 := v_1.Args[0]
		v_1_1 := v_1.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, v_1_0, v_1_1 = _i0+1, v_1_1, v_1_0 {
			y := v_1_0
			if v_1_1.Op != OpConst64 {
				continue
			}
			c := auxIntToInt64(v_1_1.AuxInt)
			if !(c&15 == 15) {
				continue
			}
			v.reset(OpRotateLeft16)
			v.AddArg2(x, y)
			return true
		}
		break
	}
	// match: (RotateLeft16 x (And32 y (Const32 [c])))
	// cond: c&15 == 15
	// result: (RotateLeft16 x y)
	for {
		x := v_0
		if v_1.Op != OpAnd32 {
			break
		}
		_ = v_1.Args[1]
		v_1_0 := v_1.Args[0]
		v_1_1 := v_1.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, v_1_0, v_1_1 = _i0+1, v_1_1, v_1_0 {
			y := v_1_0
			if v_1_1.Op != OpConst32 {
				continue
			}
			c := auxIntToInt32(v_1_1.AuxInt)
			if !(c&15 == 15) {
				continue
			}
			v.reset(OpRotateLeft16)
			v.AddArg2(x, y)
			return true
		}
		break
	}
	// match: (RotateLeft16 x (And16 y (Const16 [c])))
	// cond: c&15 == 15
	// result: (RotateLeft16 x y)
	for {
		x := v_0
		if v_1.Op != OpAnd16 {
			break
		}
		_ = v_1.Args[1]
		v_1_0 := v_1.Args[0]
		v_1_1 := v_1.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, v_1_0, v_1_1 = _i0+1, v_1_1, v_1_0 {
			y := v_1_0
			if v_1_1.Op != OpConst16 {
				continue
			}
			c := auxIntToInt16(v_1_1.AuxInt)
			if !(c&15 == 15) {
				continue
			}
			v.reset(OpRotateLeft16)
			v.AddArg2(x, y)
			return true
		}
		break
	}
	// match: (RotateLeft16 x (And8 y (Const8 [c])))
	// cond: c&15 == 15
	// result: (RotateLeft16 x y)
	for {
		x := v_0
		if v_1.Op != OpAnd8 {
			break
		}
		_ = v_1.Args[1]
		v_1_0 := v_1.Args[0]
		v_1_1 := v_1.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, v_1_0, v_1_1 = _i0+1, v_1_1, v_1_0 {
			y := v_1_0
			if v_1_1.Op != OpConst8 {
				continue
			}
			c := auxIntToInt8(v_1_1.AuxInt)
			if !(c&15 == 15) {
				continue
			}
			v.reset(OpRotateLeft16)
			v.AddArg2(x, y)
			return true
		}
		break
	}
	// match: (RotateLeft16 x (Neg64 (And64 y (Const64 [c]))))
	// cond: c&15 == 15
	// result: (RotateLeft16 x (Neg64 <y.Type> y))
	for {
		x := v_0
		if v_1.Op != OpNeg64 {
			break
		}
		v_1_0 := v_1.Args[0]
		if v_1_0.Op != OpAnd64 {
			break
		}
		_ = v_1_0.Args[1]
		v_1_0_0 := v_1_0.Args[0]
		v_1_0_1 := v_1_0.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, v_1_0_0, v_1_0_1 = _i0+1, v_1_0_1, v_1_0_0 {
			y := v_1_0_0
			if v_1_0_1.Op != OpConst64 {
				continue
			}
			c := auxIntToInt64(v_1_0_1.AuxInt)
			if !(c&15 == 15) {
				continue
			}
			v.reset(OpRotateLeft16)
			v0 := b.NewValue0(v.Pos, OpNeg64, y.Type)
			v0.AddArg(y)
			v.AddArg2(x, v0)
			return true
		}
		break
	}
	// match: (RotateLeft16 x (Neg32 (And32 y (Const32 [c]))))
	// cond: c&15 == 15
	// result: (RotateLeft16 x (Neg32 <y.Type> y))
	for {
		x := v_0
		if v_1.Op != OpNeg32 {
			break
		}
		v_1_0 := v_1.Args[0]
		if v_1_0.Op != OpAnd32 {
			break
		}
		_ = v_1_0.Args[1]
		v_1_0_0 := v_1_0.Args[0]
		v_1_0_1 := v_1_0.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, v_1_0_0, v_1_0_1 = _i0+1, v_1_0_1, v_1_0_0 {
			y := v_1_0_0
			if v_1_0_1.Op != OpConst32 {
				continue
			}
			c := auxIntToInt32(v_1_0_1.AuxInt)
			if !(c&15 == 15) {
				continue
			}
			v.reset(OpRotateLeft16)
			v0 := b.NewValue0(v.Pos, OpNeg32, y.Type)
			v0.AddArg(y)
			v.AddArg2(x, v0)
			return true
		}
		break
	}
	// match: (RotateLeft16 x (Neg16 (And16 y (Const16 [c]))))
	// cond: c&15 == 15
	// result: (RotateLeft16 x (Neg16 <y.Type> y))
	for {
		x := v_0
		if v_1.Op != OpNeg16 {
			break
		}
		v_1_0 := v_1.Args[0]
		if v_1_0.Op != OpAnd16 {
			break
		}
		_ = v_1_0.Args[1]
		v_1_0_0 := v_1_0.Args[0]
		v_1_0_1 := v_1_0.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, v_1_0_0, v_1_0_1 = _i0+1, v_1_0_1, v_1_0_0 {
			y := v_1_0_0
			if v_1_0_1.Op != OpConst16 {
				continue
			}
			c := auxIntToInt16(v_1_0_1.AuxInt)
			if !(c&15 == 15) {
				continue
			}
			v.reset(OpRotateLeft16)
			v0 := b.NewValue0(v.Pos, OpNeg16, y.Type)
			v0.AddArg(y)
			v.AddArg2(x, v0)
			return true
		}
		break
	}
	// match: (RotateLeft16 x (Neg8 (And8 y (Const8 [c]))))
	// cond: c&15 == 15
	// result: (RotateLeft16 x (Neg8 <y.Type> y))
	for {
		x := v_0
		if v_1.Op != OpNeg8 {
			break
		}
		v_1_0 := v_1.Args[0]
		if v_1_0.Op != OpAnd8 {
			break
		}
		_ = v_1_0.Args[1]
		v_1_0_0 := v_1_0.Args[0]
		v_1_0_1 := v_1_0.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, v_1_0_0, v_1_0_1 = _i0+1, v_1_0_1, v_1_0_0 {
			y := v_1_0_0
			if v_1_0_1.Op != OpConst8 {
				continue
			}
			c := auxIntToInt8(v_1_0_1.AuxInt)
			if !(c&15 == 15) {
				continue
			}
			v.reset(OpRotateLeft16)
			v0 := b.NewValue0(v.Pos, OpNeg8, y.Type)
			v0.AddArg(y)
			v.AddArg2(x, v0)
			return true
		}
		break
	}
	// match: (RotateLeft16 x (Add64 y (Const64 [c])))
	// cond: c&15 == 0
	// result: (RotateLeft16 x y)
	for {
		x := v_0
		if v_1.Op != OpAdd64 {
			break
		}
		_ = v_1.Args[1]
		v_1_0 := v_1.Args[0]
		v_1_1 := v_1.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, v_1_0, v_1_1 = _i0+1, v_1_1, v_1_0 {
			y := v_1_0
			if v_1_1.Op != OpConst64 {
				continue
			}
			c := auxIntToInt64(v_1_1.AuxInt)
			if !(c&15 == 0) {
				continue
			}
			v.reset(OpRotateLeft16)
			v.AddArg2(x, y)
			return true
		}
		break
	}
	// match: (RotateLeft16 x (Add32 y (Const32 [c])))
	// cond: c&15 == 0
	// result: (RotateLeft16 x y)
	for {
		x := v_0
		if v_1.Op != OpAdd32 {
			break
		}
		_ = v_1.Args[1]
		v_1_0 := v_1.Args[0]
		v_1_1 := v_1.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, v_1_0, v_1_1 = _i0+1, v_1_1, v_1_0 {
			y := v_1_0
			if v_1_1.Op != OpConst32 {
				continue
			}
			c := auxIntToInt32(v_1_1.AuxInt)
			if !(c&15 == 0) {
				continue
			}
			v.reset(OpRotateLeft16)
			v.AddArg2(x, y)
			return true
		}
		break
	}
	// match: (RotateLeft16 x (Add16 y (Const16 [c])))
	// cond: c&15 == 0
	// result: (RotateLeft16 x y)
	for {
		x := v_0
		if v_1.Op != OpAdd16 {
			break
		}
		_ = v_1.Args[1]
		v_1_0 := v_1.Args[0]
		v_1_1 := v_1.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, v_1_0, v_1_1 = _i0+1, v_1_1, v_1_0 {
			y := v_1_0
			if v_1_1.Op != OpConst16 {
				continue
			}
			c := auxIntToInt16(v_1_1.AuxInt)
			if !(c&15 == 0) {
				continue
			}
			v.reset(OpRotateLeft16)
			v.AddArg2(x, y)
			return true
		}
		break
	}
	// match: (RotateLeft16 x (Add8 y (Const8 [c])))
	// cond: c&15 == 0
	// result: (RotateLeft16 x y)
	for {
		x := v_0
		if v_1.Op != OpAdd8 {
			break
		}
		_ = v_1.Args[1]
		v_1_0 := v_1.Args[0]
		v_1_1 := v_1.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, v_1_0, v_1_1 = _i0+1, v_1_1, v_1_0 {
			y := v_1_0
			if v_1_1.Op != OpConst8 {
				continue
			}
			c := auxIntToInt8(v_1_1.AuxInt)
			if !(c&15 == 0) {
				continue
			}
			v.reset(OpRotateLeft16)
			v.AddArg2(x, y)
			return true
		}
		break
	}
	// match: (RotateLeft16 x (Sub64 (Const64 [c]) y))
	// cond: c&15 == 0
	// result: (RotateLeft16 x (Neg64 <y.Type> y))
	for {
		x := v_0
		if v_1.Op != OpSub64 {
			break
		}
		y := v_1.Args[1]
		v_1_0 := v_1.Args[0]
		if v_1_0.Op != OpConst64 {
			break
		}
		c := auxIntToInt64(v_1_0.AuxInt)
		if !(c&15 == 0) {
			break
		}
		v.reset(OpRotateLeft16)
		v0 := b.NewValue0(v.Pos, OpNeg64, y.Type)
		v0.AddArg(y)
		v.AddArg2(x, v0)
		return true
	}
	// match: (RotateLeft16 x (Sub32 (Const32 [c]) y))
	// cond: c&15 == 0
	// result: (RotateLeft16 x (Neg32 <y.Type> y))
	for {
		x := v_0
		if v_1.Op != OpSub32 {
			break
		}
		y := v_1.Args[1]
		v_1_0 := v_1.Args[0]
		if v_1_0.Op != OpConst32 {
			break
		}
		c := auxIntToInt32(v_1_0.AuxInt)
		if !(c&15 == 0) {
			break
		}
		v.reset(OpRotateLeft16)
		v0 := b.NewValue0(v.Pos, OpNeg32, y.Type)
		v0.AddArg(y)
		v.AddArg2(x, v0)
		return true
	}
	// match: (RotateLeft16 x (Sub16 (Const16 [c]) y))
	// cond: c&15 == 0
	// result: (RotateLeft16 x (Neg16 <y.Type> y))
	for {
		x := v_0
		if v_1.Op != OpSub16 {
			break
		}
		y := v_1.Args[1]
		v_1_0 := v_1.Args[0]
		if v_1_0.Op != OpConst16 {
			break
		}
		c := auxIntToInt16(v_1_0.AuxInt)
		if !(c&15 == 0) {
			break
		}
		v.reset(OpRotateLeft16)
		v0 := b.NewValue0(v.Pos, OpNeg16, y.Type)
		v0.AddArg(y)
		v.AddArg2(x, v0)
		return true
	}
	// match: (RotateLeft16 x (Sub8 (Const8 [c]) y))
	// cond: c&15 == 0
	// result: (RotateLeft16 x (Neg8 <y.Type> y))
	for {
		x := v_0
		if v_1.Op != OpSub8 {
			break
		}
		y := v_1.Args[1]
		v_1_0 := v_1.Args[0]
		if v_1_0.Op != OpConst8 {
			break
		}
		c := auxIntToInt8(v_1_0.AuxInt)
		if !(c&15 == 0) {
			break
		}
		v.reset(OpRotateLeft16)
		v0 := b.NewValue0(v.Pos, OpNeg8, y.Type)
		v0.AddArg(y)
		v.AddArg2(x, v0)
		return true
	}
	// match: (RotateLeft16 x (Const64 <t> [c]))
	// cond: config.PtrSize == 4
	// result: (RotateLeft16 x (Const32 <t> [int32(c)]))
	for {
		x := v_0
		if v_1.Op != OpConst64 {
			break
		}
		t := v_1.Type
		c := auxIntToInt64(v_1.AuxInt)
		if !(config.PtrSize == 4) {
			break
		}
		v.reset(OpRotateLeft16)
		v0 := b.NewValue0(v.Pos, OpConst32, t)
		v0.AuxInt = int32ToAuxInt(int32(c))
		v.AddArg2(x, v0)
		return true
	}
	// match: (RotateLeft16 (RotateLeft16 x c) d)
	// cond: c.Type.Size() == 8 && d.Type.Size() == 8
	// result: (RotateLeft16 x (Add64 <c.Type> c d))
	for {
		if v_0.Op != OpRotateLeft16 {
			break
		}
		c := v_0.Args[1]
		x := v_0.Args[0]
		d := v_1
		if !(c.Type.Size() == 8 && d.Type.Size() == 8) {
			break
		}
		v.reset(OpRotateLeft16)
		v0 := b.NewValue0(v.Pos, OpAdd64, c.Type)
		v0.AddArg2(c, d)
		v.AddArg2(x, v0)
		return true
	}
	// match: (RotateLeft16 (RotateLeft16 x c) d)
	// cond: c.Type.Size() == 4 && d.Type.Size() == 4
	// result: (RotateLeft16 x (Add32 <c.Type> c d))
	for {
		if v_0.Op != OpRotateLeft16 {
			break
		}
		c := v_0.Args[1]
		x := v_0.Args[0]
		d := v_1
		if !(c.Type.Size() == 4 && d.Type.Size() == 4) {
			break
		}
		v.reset(OpRotateLeft16)
		v0 := b.NewValue0(v.Pos, OpAdd32, c.Type)
		v0.AddArg2(c, d)
		v.AddArg2(x, v0)
		return true
	}
	// match: (RotateLeft16 (RotateLeft16 x c) d)
	// cond: c.Type.Size() == 2 && d.Type.Size() == 2
	// result: (RotateLeft16 x (Add16 <c.Type> c d))
	for {
		if v_0.Op != OpRotateLeft16 {
			break
		}
		c := v_0.Args[1]
		x := v_0.Args[0]
		d := v_1
		if !(c.Type.Size() == 2 && d.Type.Size() == 2) {
			break
		}
		v.reset(OpRotateLeft16)
		v0 := b.NewValue0(v.Pos, OpAdd16, c.Type)
		v0.AddArg2(c, d)
		v.AddArg2(x, v0)
		return true
	}
	// match: (RotateLeft16 (RotateLeft16 x c) d)
	// cond: c.Type.Size() == 1 && d.Type.Size() == 1
	// result: (RotateLeft16 x (Add8 <c.Type> c d))
	for {
		if v_0.Op != OpRotateLeft16 {
			break
		}
		c := v_0.Args[1]
		x := v_0.Args[0]
		d := v_1
		if !(c.Type.Size() == 1 && d.Type.Size() == 1) {
			break
		}
		v.reset(OpRotateLeft16)
		v0 := b.NewValue0(v.Pos, OpAdd8, c.Type)
		v0.AddArg2(c, d)
		v.AddArg2(x, v0)
		return true
	}
	return false
}
func rewriteValuegeneric_OpRotateLeft32(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	config := b.Func.Config
	// match: (RotateLeft32 x (Const32 [c]))
	// cond: c%32 == 0
	// result: x
	for {
		x := v_0
		if v_1.Op != OpConst32 {
			break
		}
		c := auxIntToInt32(v_1.AuxInt)
		if !(c%32 == 0) {
			break
		}
		v.copyOf(x)
		return true
	}
	// match: (RotateLeft32 x (And64 y (Const64 [c])))
	// cond: c&31 == 31
	// result: (RotateLeft32 x y)
	for {
		x := v_0
		if v_1.Op != OpAnd64 {
			break
		}
		_ = v_1.Args[1]
		v_1_0 := v_1.Args[0]
		v_1_1 := v_1.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, v_1_0, v_1_1 = _i0+1, v_1_1, v_1_0 {
			y := v_1_0
			if v_1_1.Op != OpConst64 {
				continue
			}
			c := auxIntToInt64(v_1_1.AuxInt)
			if !(c&31 == 31) {
				continue
			}
			v.reset(OpRotateLeft32)
			v.AddArg2(x, y)
			return true
		}
		break
	}
	// match: (RotateLeft32 x (And32 y (Const32 [c])))
	// cond: c&31 == 31
	// result: (RotateLeft32 x y)
	for {
		x := v_0
		if v_1.Op != OpAnd32 {
			break
		}
		_ = v_1.Args[1]
		v_1_0 := v_1.Args[0]
		v_1_1 := v_1.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, v_1_0, v_1_1 = _i0+1, v_1_1, v_1_0 {
			y := v_1_0
			if v_1_1.Op != OpConst32 {
				continue
			}
			c := auxIntToInt32(v_1_1.AuxInt)
			if !(c&31 == 31) {
				continue
			}
			v.reset(OpRotateLeft32)
			v.AddArg2(x, y)
			return true
		}
		break
	}
	// match: (RotateLeft32 x (And16 y (Const16 [c])))
	// cond: c&31 == 31
	// result: (RotateLeft32 x y)
	for {
		x := v_0
		if v_1.Op != OpAnd16 {
			break
		}
		_ = v_1.Args[1]
		v_1_0 := v_1.Args[0]
		v_1_1 := v_1.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, v_1_0, v_1_1 = _i0+1, v_1_1, v_1_0 {
			y := v_1_0
			if v_1_1.Op != OpConst16 {
				continue
			}
			c := auxIntToInt16(v_1_1.AuxInt)
			if !(c&31 == 31) {
				continue
			}
			v.reset(OpRotateLeft32)
			v.AddArg2(x, y)
			return true
		}
		break
	}
	// match: (RotateLeft32 x (And8 y (Const8 [c])))
	// cond: c&31 == 31
	// result: (RotateLeft32 x y)
	for {
		x := v_0
		if v_1.Op != OpAnd8 {
			break
		}
		_ = v_1.Args[1]
		v_1_0 := v_1.Args[0]
		v_1_1 := v_1.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, v_1_0, v_1_1 = _i0+1, v_1_1, v_1_0 {
			y := v_1_0
			if v_1_1.Op != OpConst8 {
				continue
			}
			c := auxIntToInt8(v_1_1.AuxInt)
			if !(c&31 == 31) {
				continue
			}
			v.reset(OpRotateLeft32)
			v.AddArg2(x, y)
			return true
		}
		break
	}
	// match: (RotateLeft32 x (Neg64 (And64 y (Const64 [c]))))
	// cond: c&31 == 31
	// result: (RotateLeft32 x (Neg64 <y.Type> y))
	for {
		x := v_0
		if v_1.Op != OpNeg64 {
			break
		}
		v_1_0 := v_1.Args[0]
		if v_1_0.Op != OpAnd64 {
			break
		}
		_ = v_1_0.Args[1]
		v_1_0_0 := v_1_0.Args[0]
		v_1_0_1 := v_1_0.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, v_1_0_0, v_1_0_1 = _i0+1, v_1_0_1, v_1_0_0 {
			y := v_1_0_0
			if v_1_0_1.Op != OpConst64 {
				continue
			}
			c := auxIntToInt64(v_1_0_1.AuxInt)
			if !(c&31 == 31) {
				continue
			}
			v.reset(OpRotateLeft32)
			v0 := b.NewValue0(v.Pos, OpNeg64, y.Type)
			v0.AddArg(y)
			v.AddArg2(x, v0)
			return true
		}
		break
	}
	// match: (RotateLeft32 x (Neg32 (And32 y (Const32 [c]))))
	// cond: c&31 == 31
	// result: (RotateLeft32 x (Neg32 <y.Type> y))
	for {
		x := v_0
		if v_1.Op != OpNeg32 {
			break
		}
		v_1_0 := v_1.Args[0]
		if v_1_0.Op != OpAnd32 {
			break
		}
		_ = v_1_0.Args[1]
		v_1_0_0 := v_1_0.Args[0]
		v_1_0_1 := v_1_0.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, v_1_0_0, v_1_0_1 = _i0+1, v_1_0_1, v_1_0_0 {
			y := v_1_0_0
			if v_1_0_1.Op != OpConst32 {
				continue
			}
			c := auxIntToInt32(v_1_0_1.AuxInt)
			if !(c&31 == 31) {
				continue
			}
			v.reset(OpRotateLeft32)
			v0 := b.NewValue0(v.Pos, OpNeg32, y.Type)
			v0.AddArg(y)
			v.AddArg2(x, v0)
			return true
		}
		break
	}
	// match: (RotateLeft32 x (Neg16 (And16 y (Const16 [c]))))
	// cond: c&31 == 31
	// result: (RotateLeft32 x (Neg16 <y.Type> y))
	for {
		x := v_0
		if v_1.Op != OpNeg16 {
			break
		}
		v_1_0 := v_1.Args[0]
		if v_1_0.Op != OpAnd16 {
			break
		}
		_ = v_1_0.Args[1]
		v_1_0_0 := v_1_0.Args[0]
		v_1_0_1 := v_1_0.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, v_1_0_0, v_1_0_1 = _i0+1, v_1_0_1, v_1_0_0 {
			y := v_1_0_0
			if v_1_0_1.Op != OpConst16 {
				continue
			}
			c := auxIntToInt16(v_1_0_1.AuxInt)
			if !(c&31 == 31) {
				continue
			}
			v.reset(OpRotateLeft32)
			v0 := b.NewValue0(v.Pos, OpNeg16, y.Type)
			v0.AddArg(y)
			v.AddArg2(x, v0)
			return true
		}
		break
	}
	// match: (RotateLeft32 x (Neg8 (And8 y (Const8 [c]))))
	// cond: c&31 == 31
	// result: (RotateLeft32 x (Neg8 <y.Type> y))
	for {
		x := v_0
		if v_1.Op != OpNeg8 {
			break
		}
		v_1_0 := v_1.Args[0]
		if v_1_0.Op != OpAnd8 {
			break
		}
		_ = v_1_0.Args[1]
		v_1_0_0 := v_1_0.Args[0]
		v_1_0_1 := v_1_0.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, v_1_0_0, v_1_0_1 = _i0+1, v_1_0_1, v_1_0_0 {
			y := v_1_0_0
			if v_1_0_1.Op != OpConst8 {
				continue
			}
			c := auxIntToInt8(v_1_0_1.AuxInt)
			if !(c&31 == 31) {
				continue
			}
			v.reset(OpRotateLeft32)
			v0 := b.NewValue0(v.Pos, OpNeg8, y.Type)
```