Response: My thinking process to answer the request about `rewriteARM.go` goes like this:

1. **Understand the Goal:** The user wants to know the function of the provided Go code snippet, which is a part of the Go compiler (`cmd/compile/internal/ssa`). The specific file is `rewriteARM.go`, suggesting it's related to rewriting SSA (Static Single Assignment) for the ARM architecture.

2. **Initial Analysis of the Code:** I quickly scan the code. Key observations:
    * **`// Code generated ... DO NOT EDIT.`:** This immediately tells me the file is auto-generated, likely from a set of rules or definitions. I shouldn't try to understand the logic too deeply at this level because it's a mechanical translation.
    * **`package ssa`:** Confirms it's part of the SSA package within the compiler.
    * **`import "internal/buildcfg"` and `import "cmd/compile/internal/types"`:**  These imports hint at interactions with build configuration and Go type information, both crucial for compiler operations.
    * **`func rewriteValueARM(v *Value) bool`:** This is the core function. It takes an SSA `Value` and returns a boolean, suggesting it modifies or "rewrites" the value. The "ARM" suffix clearly indicates architecture-specific logic.
    * **`switch v.Op { ... }`:** A large `switch` statement based on `v.Op`. This means the function handles different SSA operations.
    * **Cases like `OpARMADC`, `OpARMADD`, `OpARMMOVWconst`, etc.:** These are ARM-specific instruction mnemonics. This confirms the file's purpose is to handle ARM instructions within the SSA representation.
    * **Calls to functions like `rewriteValueARM_OpARMADC(v)`:**  This structure suggests a pattern: each ARM operation likely has its own rewrite function.

3. **Formulate the Core Functionality:** Based on the observations, the primary function is to transform SSA values representing generic operations into equivalent sequences of ARM-specific instructions. This is a crucial step in the compilation process, bridging the gap between the architecture-independent SSA and the target architecture.

4. **Infer Go Language Feature Implementation:**  The code deals with low-level operations like addition, subtraction, bitwise operations, loads, stores, and comparisons. These are fundamental building blocks for *all* Go language features. However, the *specific* implementation here is focused on *how these operations are realized on the ARM architecture*. There isn't one single Go language feature it implements; instead, it's the underlying mechanism for implementing many.

5. **Construct Go Code Examples:** To illustrate, I need to show how a generic Go operation might be translated to ARM instructions through these rewrite rules. I choose a simple addition (`+`) as an example.
    * **Input (Conceptual SSA):**  `x + y`  would be represented as an SSA `Value` with `Op = OpAdd32` (or `OpAdd64`, etc.).
    * **Rewrite Rule:** The `rewriteValueARM` function would identify the `OpAdd32` and likely have a case like `case OpAdd32: v.Op = OpARMADD; return true`. This changes the generic `OpAdd32` to the ARM-specific `OpARMADD`.
    * **Actual ARM Instruction (Hypothetical):** The *next* stage of compilation would then translate `OpARMADD` into the actual ARM assembly instruction (e.g., `ADD`).

6. **Address Code Reasoning (Input/Output):** Since the code is about *rewriting* SSA, the "input" is an SSA `Value` representing a generic operation, and the "output" is a modified `Value` with an ARM-specific operation. I need to provide a concrete example of this transformation, even if I don't know the exact details of the rewrite functions.

7. **Consider Command-Line Arguments:** This specific code snippet doesn't directly handle command-line arguments. The code is part of the *internal* workings of the compiler. Command-line flags that influence ARM compilation (like architecture version, floating-point ABI, etc.) would be processed *before* this stage, affecting the overall context in which these rewrites occur.

8. **Identify Potential Pitfalls for Users:**  Since this is internal compiler code, end-users don't directly interact with it. The "pitfalls" are for *compiler developers* who might modify or generate these rewrite rules. A common mistake could be creating incorrect or suboptimal rewrite rules, leading to inefficient or incorrect code generation. I provide a conceptual example of a flawed rule.

9. **Summarize the Function:**  Finally, I need to concisely summarize the functionality of this part of the code. The key points are: architecture-specific, SSA rewriting, translating generic operations to ARM instructions, and being auto-generated.

10. **Structure the Answer:** I organize my answer according to the user's request, addressing each point systematically. I use clear headings and explanations. I make sure to emphasize the auto-generated nature of the code and the distinction between generic SSA operations and ARM-specific instructions.

By following these steps, I can provide a comprehensive and accurate answer to the user's request, even without diving into the intricate details of every rewrite rule. The focus is on understanding the overall purpose and role of this code within the Go compilation process.
好的，让我们来分析一下 `go/src/cmd/compile/internal/ssa/rewriteARM.go` 这个文件的功能。

**功能归纳：**

这个 Go 语言源文件 `rewriteARM.go` 的主要功能是 **定义了一系列规则，用于将 Go 语言的中间表示（SSA，静态单赋值形式）中的通用操作转换为 ARM 架构特定的机器指令操作。**  换句话说，它负责将高级的、平台无关的操作，转化为可以在 ARM 处理器上执行的低级操作。

**更详细的功能描述：**

1. **SSA 值重写：**  核心函数 `rewriteValueARM(v *Value) bool` 负责遍历 SSA 图中的每一个 `Value`（代表一个操作和其结果），并尝试根据其操作类型 (`v.Op`) 应用特定的重写规则。

2. **ARM 指令映射：**  `switch v.Op` 语句包含了大量的 `case` 分支，每个 `case` 对应一个通用的 SSA 操作 (例如 `OpAdd32`, `OpLoad`, `OpMul16`)。 在每个 `case` 中，代码会将该通用操作 `v.Op` 替换为对应的 ARM 架构特定的操作 (例如 `OpARMADD`, `OpARMMOVWload`, `OpARMMUL`)。

3. **指令优化和模式匹配：** 除了简单的操作映射，这些重写规则还可能包含一些简单的优化和模式匹配。例如，将常量加法 `ADD x (MOVWconst [c])` 转换为 `ADDconst [c] x`，这可能允许后续的优化步骤更好地处理常量。

4. **辅助函数的调用：**  每个 `case` 分支通常会调用一个以 `rewriteValueARM_Op` 开头的辅助函数（例如 `rewriteValueARM_OpARMADC(v)`）。 这些辅助函数包含了针对特定操作的更详细的重写逻辑。

5. **自动生成代码：**  文件开头的注释 `// Code generated from _gen/ARM.rules using 'go generate'; DO NOT EDIT.` 表明这个文件是根据 `_gen/ARM.rules` 文件自动生成的。这意味着实际的转换规则定义在 `.rules` 文件中，而这个 `.go` 文件是根据这些规则生成的 Go 代码。

**推理其实现的 Go 语言功能，并用 Go 代码举例说明：**

这个文件本身并不直接实现某个特定的 Go 语言功能，而是 Go 语言编译器将各种 Go 语言构造（例如算术运算、内存访问、函数调用等）编译成 ARM 机器码的关键步骤。

**举例说明（假设的输入与输出）：**

假设我们有以下简单的 Go 代码：

```go
package main

func add(a, b int32) int32 {
	return a + b
}
```

在编译过程中，`a + b` 这个加法操作会被表示成 SSA 图中的一个 `Value`，其操作类型可能是 `OpAdd32`。

**假设的 SSA 输入：**

```
v1 = Param {noescape} a:int32
v2 = Param {noescape} b:int32
v3 = Add32 v1 v2
v4 = Return v3
```

当 `rewriteValueARM` 函数处理 `v3` 时，会匹配到 `case OpAdd32:` 分支，并执行相应的重写。

**`rewriteValueARM` 函数的执行过程（简化）：**

```go
func rewriteValueARM(v *Value) bool {
	switch v.Op {
	case OpAdd32:
		v.Op = OpARMADD // 将通用加法替换为 ARM 加法指令
		return true
	// ... 其他 case
	}
	return false
}
```

**假设的 SSA 输出（重写后）：**

```
v1 = Param {noescape} a:int32
v2 = Param {noescape} b:int32
v3 = ARMADD v1 v2  // Op 已经变为 ARMADD
v4 = Return v3
```

**涉及代码推理（带上假设的输入与输出）：**

让我们看一个更复杂的例子，涉及到常量优化：

**假设的 Go 代码：**

```go
package main

func main() {
	x := 10 + 5
	_ = x
}
```

**假设的 SSA 输入：**

```
v1 = Const32 [10]
v2 = Const32 [5]
v3 = Add32 v1 v2
v4 = LocalAddr {sym:_"".x}
v5 = Store v4 v3
```

当 `rewriteValueARM` 处理 `v3` 时，可能会有如下的重写规则：

```go
func rewriteValueARM(v *Value) bool {
	switch v.Op {
	case OpAdd32:
		// 假设的规则：如果加法的两个操作数都是常量，则直接计算结果
		if v.Args[0].Op == OpConst32 && v.Args[1].Op == OpConst32 {
			c1 := auxIntToInt32(v.Args[0].AuxInt)
			c2 := auxIntToInt32(v.Args[1].AuxInt)
			v.Op = OpARMMOVWconst // 使用 MOVWconst 指令将结果加载到寄存器
			v.AuxInt = int32ToAuxInt(c1 + c2)
			v.Args = nil // 清空操作数
			return true
		}
		v.Op = OpARMADD
		return true
	// ...
	}
	return false
}
```

**假设的 SSA 输出（常量折叠后）：**

```
v1 = Const32 [10]
v2 = Const32 [5]
v3 = ARMMOVWconst [15] // 加法直接被计算为常量 15
v4 = LocalAddr {sym:_"".x}
v5 = Store v4 v3
```

**涉及命令行参数的具体处理：**

这个特定的文件 `rewriteARM.go` 并不直接处理命令行参数。 命令行参数的处理通常发生在编译器的早期阶段，用于配置编译过程，例如目标架构版本 (`GOARM`)、优化级别等。  这些命令行参数会影响到后续 SSA 生成和重写的行为，例如，`GOARM` 的值会影响到哪些 ARM 指令是可用的。

**使用者易犯错的点：**

由于 `rewriteARM.go` 是 Go 编译器内部的代码，普通 Go 语言开发者不会直接修改或使用它。  **易犯错的点主要针对 Go 编译器的开发者：**

* **编写错误的重写规则：**  如果重写规则不正确，可能会导致生成的 ARM 代码功能错误。
* **编写低效的重写规则：**  即使功能正确，低效的规则可能会生成性能较差的 ARM 代码。
* **没有考虑到所有可能的 SSA 模式：**  如果规则覆盖不全，某些通用的 SSA 操作可能无法被正确转换为 ARM 指令。
* **与现有的优化步骤冲突：**  新的重写规则可能与编译器中其他的优化步骤产生冲突，导致意外的结果。

**这是第1部分，共8部分，请归纳一下它的功能**

根据你提供的代码片段，这是 `rewriteARM.go` 文件的 **第一部分**，主要负责定义 `rewriteValueARM` 函数的框架和处理一部分 ARM 架构相关的 SSA 操作的转换规则。  具体来说，这部分代码涵盖了：

* **基本的算术运算：**  `ADC`, `ADD`, `SUB` 及其带进位/借位的变种。
* **位运算：** `AND`, `OR`, `XOR`, `BIC` (位清除)。
* **比较运算：** `CMN`, `CMP`, 以及基于比较结果的条件移动指令 (`CMOVWHSconst`, `CMOVWLSconst`).
* **加载和存储操作：**  从内存加载和存储不同大小的数据 (`MOVB`, `MOVH`, `MOVW`, `MOVD`, `MOVF`)。
* **乘法运算：** `MUL`, `MULA` (乘加)。
* **位移操作：** `SLL` (逻辑左移), `SRL` (逻辑右移), `SRA` (算术右移), `ROR` (循环右移 - 在后续部分可能出现)。
* **逻辑非运算：** `MVN` (按位取反)。
* **浮点运算：**  一部分浮点加减乘除和类型转换指令 (`ADDD`, `ADDF`, `SUBD`, `SUBF`, `MULD`, `MULF`, `DIVD`, `DIVF`, `MOVFD`, `MOVDF` 等)。
* **其他杂项操作：**  例如绝对值 (`Abs`)，位反转 (`Bswap32`)，调用指令 (`ClosureCall`, `InterCall`, `StaticCall`, `TailCall`) 等。

总而言之，这第一部分奠定了将 Go 语言抽象操作转换为具体 ARM 指令的基础，并实现了大量核心的算术、逻辑、内存访问和控制流相关的转换规则。后续的部分可能会涉及更复杂的转换、特定的优化以及对其他 ARM 指令的支持。

### 提示词
```
这是路径为go/src/cmd/compile/internal/ssa/rewriteARM.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
这是第1部分，共8部分，请归纳一下它的功能
```

### 源代码
```go
// Code generated from _gen/ARM.rules using 'go generate'; DO NOT EDIT.

package ssa

import "internal/buildcfg"
import "cmd/compile/internal/types"

func rewriteValueARM(v *Value) bool {
	switch v.Op {
	case OpARMADC:
		return rewriteValueARM_OpARMADC(v)
	case OpARMADCconst:
		return rewriteValueARM_OpARMADCconst(v)
	case OpARMADCshiftLL:
		return rewriteValueARM_OpARMADCshiftLL(v)
	case OpARMADCshiftLLreg:
		return rewriteValueARM_OpARMADCshiftLLreg(v)
	case OpARMADCshiftRA:
		return rewriteValueARM_OpARMADCshiftRA(v)
	case OpARMADCshiftRAreg:
		return rewriteValueARM_OpARMADCshiftRAreg(v)
	case OpARMADCshiftRL:
		return rewriteValueARM_OpARMADCshiftRL(v)
	case OpARMADCshiftRLreg:
		return rewriteValueARM_OpARMADCshiftRLreg(v)
	case OpARMADD:
		return rewriteValueARM_OpARMADD(v)
	case OpARMADDD:
		return rewriteValueARM_OpARMADDD(v)
	case OpARMADDF:
		return rewriteValueARM_OpARMADDF(v)
	case OpARMADDS:
		return rewriteValueARM_OpARMADDS(v)
	case OpARMADDSshiftLL:
		return rewriteValueARM_OpARMADDSshiftLL(v)
	case OpARMADDSshiftLLreg:
		return rewriteValueARM_OpARMADDSshiftLLreg(v)
	case OpARMADDSshiftRA:
		return rewriteValueARM_OpARMADDSshiftRA(v)
	case OpARMADDSshiftRAreg:
		return rewriteValueARM_OpARMADDSshiftRAreg(v)
	case OpARMADDSshiftRL:
		return rewriteValueARM_OpARMADDSshiftRL(v)
	case OpARMADDSshiftRLreg:
		return rewriteValueARM_OpARMADDSshiftRLreg(v)
	case OpARMADDconst:
		return rewriteValueARM_OpARMADDconst(v)
	case OpARMADDshiftLL:
		return rewriteValueARM_OpARMADDshiftLL(v)
	case OpARMADDshiftLLreg:
		return rewriteValueARM_OpARMADDshiftLLreg(v)
	case OpARMADDshiftRA:
		return rewriteValueARM_OpARMADDshiftRA(v)
	case OpARMADDshiftRAreg:
		return rewriteValueARM_OpARMADDshiftRAreg(v)
	case OpARMADDshiftRL:
		return rewriteValueARM_OpARMADDshiftRL(v)
	case OpARMADDshiftRLreg:
		return rewriteValueARM_OpARMADDshiftRLreg(v)
	case OpARMAND:
		return rewriteValueARM_OpARMAND(v)
	case OpARMANDconst:
		return rewriteValueARM_OpARMANDconst(v)
	case OpARMANDshiftLL:
		return rewriteValueARM_OpARMANDshiftLL(v)
	case OpARMANDshiftLLreg:
		return rewriteValueARM_OpARMANDshiftLLreg(v)
	case OpARMANDshiftRA:
		return rewriteValueARM_OpARMANDshiftRA(v)
	case OpARMANDshiftRAreg:
		return rewriteValueARM_OpARMANDshiftRAreg(v)
	case OpARMANDshiftRL:
		return rewriteValueARM_OpARMANDshiftRL(v)
	case OpARMANDshiftRLreg:
		return rewriteValueARM_OpARMANDshiftRLreg(v)
	case OpARMBFX:
		return rewriteValueARM_OpARMBFX(v)
	case OpARMBFXU:
		return rewriteValueARM_OpARMBFXU(v)
	case OpARMBIC:
		return rewriteValueARM_OpARMBIC(v)
	case OpARMBICconst:
		return rewriteValueARM_OpARMBICconst(v)
	case OpARMBICshiftLL:
		return rewriteValueARM_OpARMBICshiftLL(v)
	case OpARMBICshiftLLreg:
		return rewriteValueARM_OpARMBICshiftLLreg(v)
	case OpARMBICshiftRA:
		return rewriteValueARM_OpARMBICshiftRA(v)
	case OpARMBICshiftRAreg:
		return rewriteValueARM_OpARMBICshiftRAreg(v)
	case OpARMBICshiftRL:
		return rewriteValueARM_OpARMBICshiftRL(v)
	case OpARMBICshiftRLreg:
		return rewriteValueARM_OpARMBICshiftRLreg(v)
	case OpARMCMN:
		return rewriteValueARM_OpARMCMN(v)
	case OpARMCMNconst:
		return rewriteValueARM_OpARMCMNconst(v)
	case OpARMCMNshiftLL:
		return rewriteValueARM_OpARMCMNshiftLL(v)
	case OpARMCMNshiftLLreg:
		return rewriteValueARM_OpARMCMNshiftLLreg(v)
	case OpARMCMNshiftRA:
		return rewriteValueARM_OpARMCMNshiftRA(v)
	case OpARMCMNshiftRAreg:
		return rewriteValueARM_OpARMCMNshiftRAreg(v)
	case OpARMCMNshiftRL:
		return rewriteValueARM_OpARMCMNshiftRL(v)
	case OpARMCMNshiftRLreg:
		return rewriteValueARM_OpARMCMNshiftRLreg(v)
	case OpARMCMOVWHSconst:
		return rewriteValueARM_OpARMCMOVWHSconst(v)
	case OpARMCMOVWLSconst:
		return rewriteValueARM_OpARMCMOVWLSconst(v)
	case OpARMCMP:
		return rewriteValueARM_OpARMCMP(v)
	case OpARMCMPD:
		return rewriteValueARM_OpARMCMPD(v)
	case OpARMCMPF:
		return rewriteValueARM_OpARMCMPF(v)
	case OpARMCMPconst:
		return rewriteValueARM_OpARMCMPconst(v)
	case OpARMCMPshiftLL:
		return rewriteValueARM_OpARMCMPshiftLL(v)
	case OpARMCMPshiftLLreg:
		return rewriteValueARM_OpARMCMPshiftLLreg(v)
	case OpARMCMPshiftRA:
		return rewriteValueARM_OpARMCMPshiftRA(v)
	case OpARMCMPshiftRAreg:
		return rewriteValueARM_OpARMCMPshiftRAreg(v)
	case OpARMCMPshiftRL:
		return rewriteValueARM_OpARMCMPshiftRL(v)
	case OpARMCMPshiftRLreg:
		return rewriteValueARM_OpARMCMPshiftRLreg(v)
	case OpARMEqual:
		return rewriteValueARM_OpARMEqual(v)
	case OpARMGreaterEqual:
		return rewriteValueARM_OpARMGreaterEqual(v)
	case OpARMGreaterEqualU:
		return rewriteValueARM_OpARMGreaterEqualU(v)
	case OpARMGreaterThan:
		return rewriteValueARM_OpARMGreaterThan(v)
	case OpARMGreaterThanU:
		return rewriteValueARM_OpARMGreaterThanU(v)
	case OpARMLessEqual:
		return rewriteValueARM_OpARMLessEqual(v)
	case OpARMLessEqualU:
		return rewriteValueARM_OpARMLessEqualU(v)
	case OpARMLessThan:
		return rewriteValueARM_OpARMLessThan(v)
	case OpARMLessThanU:
		return rewriteValueARM_OpARMLessThanU(v)
	case OpARMMOVBUload:
		return rewriteValueARM_OpARMMOVBUload(v)
	case OpARMMOVBUloadidx:
		return rewriteValueARM_OpARMMOVBUloadidx(v)
	case OpARMMOVBUreg:
		return rewriteValueARM_OpARMMOVBUreg(v)
	case OpARMMOVBload:
		return rewriteValueARM_OpARMMOVBload(v)
	case OpARMMOVBloadidx:
		return rewriteValueARM_OpARMMOVBloadidx(v)
	case OpARMMOVBreg:
		return rewriteValueARM_OpARMMOVBreg(v)
	case OpARMMOVBstore:
		return rewriteValueARM_OpARMMOVBstore(v)
	case OpARMMOVBstoreidx:
		return rewriteValueARM_OpARMMOVBstoreidx(v)
	case OpARMMOVDload:
		return rewriteValueARM_OpARMMOVDload(v)
	case OpARMMOVDstore:
		return rewriteValueARM_OpARMMOVDstore(v)
	case OpARMMOVFload:
		return rewriteValueARM_OpARMMOVFload(v)
	case OpARMMOVFstore:
		return rewriteValueARM_OpARMMOVFstore(v)
	case OpARMMOVHUload:
		return rewriteValueARM_OpARMMOVHUload(v)
	case OpARMMOVHUloadidx:
		return rewriteValueARM_OpARMMOVHUloadidx(v)
	case OpARMMOVHUreg:
		return rewriteValueARM_OpARMMOVHUreg(v)
	case OpARMMOVHload:
		return rewriteValueARM_OpARMMOVHload(v)
	case OpARMMOVHloadidx:
		return rewriteValueARM_OpARMMOVHloadidx(v)
	case OpARMMOVHreg:
		return rewriteValueARM_OpARMMOVHreg(v)
	case OpARMMOVHstore:
		return rewriteValueARM_OpARMMOVHstore(v)
	case OpARMMOVHstoreidx:
		return rewriteValueARM_OpARMMOVHstoreidx(v)
	case OpARMMOVWload:
		return rewriteValueARM_OpARMMOVWload(v)
	case OpARMMOVWloadidx:
		return rewriteValueARM_OpARMMOVWloadidx(v)
	case OpARMMOVWloadshiftLL:
		return rewriteValueARM_OpARMMOVWloadshiftLL(v)
	case OpARMMOVWloadshiftRA:
		return rewriteValueARM_OpARMMOVWloadshiftRA(v)
	case OpARMMOVWloadshiftRL:
		return rewriteValueARM_OpARMMOVWloadshiftRL(v)
	case OpARMMOVWnop:
		return rewriteValueARM_OpARMMOVWnop(v)
	case OpARMMOVWreg:
		return rewriteValueARM_OpARMMOVWreg(v)
	case OpARMMOVWstore:
		return rewriteValueARM_OpARMMOVWstore(v)
	case OpARMMOVWstoreidx:
		return rewriteValueARM_OpARMMOVWstoreidx(v)
	case OpARMMOVWstoreshiftLL:
		return rewriteValueARM_OpARMMOVWstoreshiftLL(v)
	case OpARMMOVWstoreshiftRA:
		return rewriteValueARM_OpARMMOVWstoreshiftRA(v)
	case OpARMMOVWstoreshiftRL:
		return rewriteValueARM_OpARMMOVWstoreshiftRL(v)
	case OpARMMUL:
		return rewriteValueARM_OpARMMUL(v)
	case OpARMMULA:
		return rewriteValueARM_OpARMMULA(v)
	case OpARMMULD:
		return rewriteValueARM_OpARMMULD(v)
	case OpARMMULF:
		return rewriteValueARM_OpARMMULF(v)
	case OpARMMULS:
		return rewriteValueARM_OpARMMULS(v)
	case OpARMMVN:
		return rewriteValueARM_OpARMMVN(v)
	case OpARMMVNshiftLL:
		return rewriteValueARM_OpARMMVNshiftLL(v)
	case OpARMMVNshiftLLreg:
		return rewriteValueARM_OpARMMVNshiftLLreg(v)
	case OpARMMVNshiftRA:
		return rewriteValueARM_OpARMMVNshiftRA(v)
	case OpARMMVNshiftRAreg:
		return rewriteValueARM_OpARMMVNshiftRAreg(v)
	case OpARMMVNshiftRL:
		return rewriteValueARM_OpARMMVNshiftRL(v)
	case OpARMMVNshiftRLreg:
		return rewriteValueARM_OpARMMVNshiftRLreg(v)
	case OpARMNEGD:
		return rewriteValueARM_OpARMNEGD(v)
	case OpARMNEGF:
		return rewriteValueARM_OpARMNEGF(v)
	case OpARMNMULD:
		return rewriteValueARM_OpARMNMULD(v)
	case OpARMNMULF:
		return rewriteValueARM_OpARMNMULF(v)
	case OpARMNotEqual:
		return rewriteValueARM_OpARMNotEqual(v)
	case OpARMOR:
		return rewriteValueARM_OpARMOR(v)
	case OpARMORconst:
		return rewriteValueARM_OpARMORconst(v)
	case OpARMORshiftLL:
		return rewriteValueARM_OpARMORshiftLL(v)
	case OpARMORshiftLLreg:
		return rewriteValueARM_OpARMORshiftLLreg(v)
	case OpARMORshiftRA:
		return rewriteValueARM_OpARMORshiftRA(v)
	case OpARMORshiftRAreg:
		return rewriteValueARM_OpARMORshiftRAreg(v)
	case OpARMORshiftRL:
		return rewriteValueARM_OpARMORshiftRL(v)
	case OpARMORshiftRLreg:
		return rewriteValueARM_OpARMORshiftRLreg(v)
	case OpARMRSB:
		return rewriteValueARM_OpARMRSB(v)
	case OpARMRSBSshiftLL:
		return rewriteValueARM_OpARMRSBSshiftLL(v)
	case OpARMRSBSshiftLLreg:
		return rewriteValueARM_OpARMRSBSshiftLLreg(v)
	case OpARMRSBSshiftRA:
		return rewriteValueARM_OpARMRSBSshiftRA(v)
	case OpARMRSBSshiftRAreg:
		return rewriteValueARM_OpARMRSBSshiftRAreg(v)
	case OpARMRSBSshiftRL:
		return rewriteValueARM_OpARMRSBSshiftRL(v)
	case OpARMRSBSshiftRLreg:
		return rewriteValueARM_OpARMRSBSshiftRLreg(v)
	case OpARMRSBconst:
		return rewriteValueARM_OpARMRSBconst(v)
	case OpARMRSBshiftLL:
		return rewriteValueARM_OpARMRSBshiftLL(v)
	case OpARMRSBshiftLLreg:
		return rewriteValueARM_OpARMRSBshiftLLreg(v)
	case OpARMRSBshiftRA:
		return rewriteValueARM_OpARMRSBshiftRA(v)
	case OpARMRSBshiftRAreg:
		return rewriteValueARM_OpARMRSBshiftRAreg(v)
	case OpARMRSBshiftRL:
		return rewriteValueARM_OpARMRSBshiftRL(v)
	case OpARMRSBshiftRLreg:
		return rewriteValueARM_OpARMRSBshiftRLreg(v)
	case OpARMRSCconst:
		return rewriteValueARM_OpARMRSCconst(v)
	case OpARMRSCshiftLL:
		return rewriteValueARM_OpARMRSCshiftLL(v)
	case OpARMRSCshiftLLreg:
		return rewriteValueARM_OpARMRSCshiftLLreg(v)
	case OpARMRSCshiftRA:
		return rewriteValueARM_OpARMRSCshiftRA(v)
	case OpARMRSCshiftRAreg:
		return rewriteValueARM_OpARMRSCshiftRAreg(v)
	case OpARMRSCshiftRL:
		return rewriteValueARM_OpARMRSCshiftRL(v)
	case OpARMRSCshiftRLreg:
		return rewriteValueARM_OpARMRSCshiftRLreg(v)
	case OpARMSBC:
		return rewriteValueARM_OpARMSBC(v)
	case OpARMSBCconst:
		return rewriteValueARM_OpARMSBCconst(v)
	case OpARMSBCshiftLL:
		return rewriteValueARM_OpARMSBCshiftLL(v)
	case OpARMSBCshiftLLreg:
		return rewriteValueARM_OpARMSBCshiftLLreg(v)
	case OpARMSBCshiftRA:
		return rewriteValueARM_OpARMSBCshiftRA(v)
	case OpARMSBCshiftRAreg:
		return rewriteValueARM_OpARMSBCshiftRAreg(v)
	case OpARMSBCshiftRL:
		return rewriteValueARM_OpARMSBCshiftRL(v)
	case OpARMSBCshiftRLreg:
		return rewriteValueARM_OpARMSBCshiftRLreg(v)
	case OpARMSLL:
		return rewriteValueARM_OpARMSLL(v)
	case OpARMSLLconst:
		return rewriteValueARM_OpARMSLLconst(v)
	case OpARMSRA:
		return rewriteValueARM_OpARMSRA(v)
	case OpARMSRAcond:
		return rewriteValueARM_OpARMSRAcond(v)
	case OpARMSRAconst:
		return rewriteValueARM_OpARMSRAconst(v)
	case OpARMSRL:
		return rewriteValueARM_OpARMSRL(v)
	case OpARMSRLconst:
		return rewriteValueARM_OpARMSRLconst(v)
	case OpARMSRR:
		return rewriteValueARM_OpARMSRR(v)
	case OpARMSUB:
		return rewriteValueARM_OpARMSUB(v)
	case OpARMSUBD:
		return rewriteValueARM_OpARMSUBD(v)
	case OpARMSUBF:
		return rewriteValueARM_OpARMSUBF(v)
	case OpARMSUBS:
		return rewriteValueARM_OpARMSUBS(v)
	case OpARMSUBSshiftLL:
		return rewriteValueARM_OpARMSUBSshiftLL(v)
	case OpARMSUBSshiftLLreg:
		return rewriteValueARM_OpARMSUBSshiftLLreg(v)
	case OpARMSUBSshiftRA:
		return rewriteValueARM_OpARMSUBSshiftRA(v)
	case OpARMSUBSshiftRAreg:
		return rewriteValueARM_OpARMSUBSshiftRAreg(v)
	case OpARMSUBSshiftRL:
		return rewriteValueARM_OpARMSUBSshiftRL(v)
	case OpARMSUBSshiftRLreg:
		return rewriteValueARM_OpARMSUBSshiftRLreg(v)
	case OpARMSUBconst:
		return rewriteValueARM_OpARMSUBconst(v)
	case OpARMSUBshiftLL:
		return rewriteValueARM_OpARMSUBshiftLL(v)
	case OpARMSUBshiftLLreg:
		return rewriteValueARM_OpARMSUBshiftLLreg(v)
	case OpARMSUBshiftRA:
		return rewriteValueARM_OpARMSUBshiftRA(v)
	case OpARMSUBshiftRAreg:
		return rewriteValueARM_OpARMSUBshiftRAreg(v)
	case OpARMSUBshiftRL:
		return rewriteValueARM_OpARMSUBshiftRL(v)
	case OpARMSUBshiftRLreg:
		return rewriteValueARM_OpARMSUBshiftRLreg(v)
	case OpARMTEQ:
		return rewriteValueARM_OpARMTEQ(v)
	case OpARMTEQconst:
		return rewriteValueARM_OpARMTEQconst(v)
	case OpARMTEQshiftLL:
		return rewriteValueARM_OpARMTEQshiftLL(v)
	case OpARMTEQshiftLLreg:
		return rewriteValueARM_OpARMTEQshiftLLreg(v)
	case OpARMTEQshiftRA:
		return rewriteValueARM_OpARMTEQshiftRA(v)
	case OpARMTEQshiftRAreg:
		return rewriteValueARM_OpARMTEQshiftRAreg(v)
	case OpARMTEQshiftRL:
		return rewriteValueARM_OpARMTEQshiftRL(v)
	case OpARMTEQshiftRLreg:
		return rewriteValueARM_OpARMTEQshiftRLreg(v)
	case OpARMTST:
		return rewriteValueARM_OpARMTST(v)
	case OpARMTSTconst:
		return rewriteValueARM_OpARMTSTconst(v)
	case OpARMTSTshiftLL:
		return rewriteValueARM_OpARMTSTshiftLL(v)
	case OpARMTSTshiftLLreg:
		return rewriteValueARM_OpARMTSTshiftLLreg(v)
	case OpARMTSTshiftRA:
		return rewriteValueARM_OpARMTSTshiftRA(v)
	case OpARMTSTshiftRAreg:
		return rewriteValueARM_OpARMTSTshiftRAreg(v)
	case OpARMTSTshiftRL:
		return rewriteValueARM_OpARMTSTshiftRL(v)
	case OpARMTSTshiftRLreg:
		return rewriteValueARM_OpARMTSTshiftRLreg(v)
	case OpARMXOR:
		return rewriteValueARM_OpARMXOR(v)
	case OpARMXORconst:
		return rewriteValueARM_OpARMXORconst(v)
	case OpARMXORshiftLL:
		return rewriteValueARM_OpARMXORshiftLL(v)
	case OpARMXORshiftLLreg:
		return rewriteValueARM_OpARMXORshiftLLreg(v)
	case OpARMXORshiftRA:
		return rewriteValueARM_OpARMXORshiftRA(v)
	case OpARMXORshiftRAreg:
		return rewriteValueARM_OpARMXORshiftRAreg(v)
	case OpARMXORshiftRL:
		return rewriteValueARM_OpARMXORshiftRL(v)
	case OpARMXORshiftRLreg:
		return rewriteValueARM_OpARMXORshiftRLreg(v)
	case OpARMXORshiftRR:
		return rewriteValueARM_OpARMXORshiftRR(v)
	case OpAbs:
		v.Op = OpARMABSD
		return true
	case OpAdd16:
		v.Op = OpARMADD
		return true
	case OpAdd32:
		v.Op = OpARMADD
		return true
	case OpAdd32F:
		v.Op = OpARMADDF
		return true
	case OpAdd32carry:
		v.Op = OpARMADDS
		return true
	case OpAdd32withcarry:
		v.Op = OpARMADC
		return true
	case OpAdd64F:
		v.Op = OpARMADDD
		return true
	case OpAdd8:
		v.Op = OpARMADD
		return true
	case OpAddPtr:
		v.Op = OpARMADD
		return true
	case OpAddr:
		return rewriteValueARM_OpAddr(v)
	case OpAnd16:
		v.Op = OpARMAND
		return true
	case OpAnd32:
		v.Op = OpARMAND
		return true
	case OpAnd8:
		v.Op = OpARMAND
		return true
	case OpAndB:
		v.Op = OpARMAND
		return true
	case OpAvg32u:
		return rewriteValueARM_OpAvg32u(v)
	case OpBitLen32:
		return rewriteValueARM_OpBitLen32(v)
	case OpBswap32:
		return rewriteValueARM_OpBswap32(v)
	case OpClosureCall:
		v.Op = OpARMCALLclosure
		return true
	case OpCom16:
		v.Op = OpARMMVN
		return true
	case OpCom32:
		v.Op = OpARMMVN
		return true
	case OpCom8:
		v.Op = OpARMMVN
		return true
	case OpConst16:
		return rewriteValueARM_OpConst16(v)
	case OpConst32:
		return rewriteValueARM_OpConst32(v)
	case OpConst32F:
		return rewriteValueARM_OpConst32F(v)
	case OpConst64F:
		return rewriteValueARM_OpConst64F(v)
	case OpConst8:
		return rewriteValueARM_OpConst8(v)
	case OpConstBool:
		return rewriteValueARM_OpConstBool(v)
	case OpConstNil:
		return rewriteValueARM_OpConstNil(v)
	case OpCtz16:
		return rewriteValueARM_OpCtz16(v)
	case OpCtz16NonZero:
		v.Op = OpCtz32
		return true
	case OpCtz32:
		return rewriteValueARM_OpCtz32(v)
	case OpCtz32NonZero:
		v.Op = OpCtz32
		return true
	case OpCtz8:
		return rewriteValueARM_OpCtz8(v)
	case OpCtz8NonZero:
		v.Op = OpCtz32
		return true
	case OpCvt32Fto32:
		v.Op = OpARMMOVFW
		return true
	case OpCvt32Fto32U:
		v.Op = OpARMMOVFWU
		return true
	case OpCvt32Fto64F:
		v.Op = OpARMMOVFD
		return true
	case OpCvt32Uto32F:
		v.Op = OpARMMOVWUF
		return true
	case OpCvt32Uto64F:
		v.Op = OpARMMOVWUD
		return true
	case OpCvt32to32F:
		v.Op = OpARMMOVWF
		return true
	case OpCvt32to64F:
		v.Op = OpARMMOVWD
		return true
	case OpCvt64Fto32:
		v.Op = OpARMMOVDW
		return true
	case OpCvt64Fto32F:
		v.Op = OpARMMOVDF
		return true
	case OpCvt64Fto32U:
		v.Op = OpARMMOVDWU
		return true
	case OpCvtBoolToUint8:
		v.Op = OpCopy
		return true
	case OpDiv16:
		return rewriteValueARM_OpDiv16(v)
	case OpDiv16u:
		return rewriteValueARM_OpDiv16u(v)
	case OpDiv32:
		return rewriteValueARM_OpDiv32(v)
	case OpDiv32F:
		v.Op = OpARMDIVF
		return true
	case OpDiv32u:
		return rewriteValueARM_OpDiv32u(v)
	case OpDiv64F:
		v.Op = OpARMDIVD
		return true
	case OpDiv8:
		return rewriteValueARM_OpDiv8(v)
	case OpDiv8u:
		return rewriteValueARM_OpDiv8u(v)
	case OpEq16:
		return rewriteValueARM_OpEq16(v)
	case OpEq32:
		return rewriteValueARM_OpEq32(v)
	case OpEq32F:
		return rewriteValueARM_OpEq32F(v)
	case OpEq64F:
		return rewriteValueARM_OpEq64F(v)
	case OpEq8:
		return rewriteValueARM_OpEq8(v)
	case OpEqB:
		return rewriteValueARM_OpEqB(v)
	case OpEqPtr:
		return rewriteValueARM_OpEqPtr(v)
	case OpFMA:
		return rewriteValueARM_OpFMA(v)
	case OpGetCallerPC:
		v.Op = OpARMLoweredGetCallerPC
		return true
	case OpGetCallerSP:
		v.Op = OpARMLoweredGetCallerSP
		return true
	case OpGetClosurePtr:
		v.Op = OpARMLoweredGetClosurePtr
		return true
	case OpHmul32:
		v.Op = OpARMHMUL
		return true
	case OpHmul32u:
		v.Op = OpARMHMULU
		return true
	case OpInterCall:
		v.Op = OpARMCALLinter
		return true
	case OpIsInBounds:
		return rewriteValueARM_OpIsInBounds(v)
	case OpIsNonNil:
		return rewriteValueARM_OpIsNonNil(v)
	case OpIsSliceInBounds:
		return rewriteValueARM_OpIsSliceInBounds(v)
	case OpLeq16:
		return rewriteValueARM_OpLeq16(v)
	case OpLeq16U:
		return rewriteValueARM_OpLeq16U(v)
	case OpLeq32:
		return rewriteValueARM_OpLeq32(v)
	case OpLeq32F:
		return rewriteValueARM_OpLeq32F(v)
	case OpLeq32U:
		return rewriteValueARM_OpLeq32U(v)
	case OpLeq64F:
		return rewriteValueARM_OpLeq64F(v)
	case OpLeq8:
		return rewriteValueARM_OpLeq8(v)
	case OpLeq8U:
		return rewriteValueARM_OpLeq8U(v)
	case OpLess16:
		return rewriteValueARM_OpLess16(v)
	case OpLess16U:
		return rewriteValueARM_OpLess16U(v)
	case OpLess32:
		return rewriteValueARM_OpLess32(v)
	case OpLess32F:
		return rewriteValueARM_OpLess32F(v)
	case OpLess32U:
		return rewriteValueARM_OpLess32U(v)
	case OpLess64F:
		return rewriteValueARM_OpLess64F(v)
	case OpLess8:
		return rewriteValueARM_OpLess8(v)
	case OpLess8U:
		return rewriteValueARM_OpLess8U(v)
	case OpLoad:
		return rewriteValueARM_OpLoad(v)
	case OpLocalAddr:
		return rewriteValueARM_OpLocalAddr(v)
	case OpLsh16x16:
		return rewriteValueARM_OpLsh16x16(v)
	case OpLsh16x32:
		return rewriteValueARM_OpLsh16x32(v)
	case OpLsh16x64:
		return rewriteValueARM_OpLsh16x64(v)
	case OpLsh16x8:
		return rewriteValueARM_OpLsh16x8(v)
	case OpLsh32x16:
		return rewriteValueARM_OpLsh32x16(v)
	case OpLsh32x32:
		return rewriteValueARM_OpLsh32x32(v)
	case OpLsh32x64:
		return rewriteValueARM_OpLsh32x64(v)
	case OpLsh32x8:
		return rewriteValueARM_OpLsh32x8(v)
	case OpLsh8x16:
		return rewriteValueARM_OpLsh8x16(v)
	case OpLsh8x32:
		return rewriteValueARM_OpLsh8x32(v)
	case OpLsh8x64:
		return rewriteValueARM_OpLsh8x64(v)
	case OpLsh8x8:
		return rewriteValueARM_OpLsh8x8(v)
	case OpMod16:
		return rewriteValueARM_OpMod16(v)
	case OpMod16u:
		return rewriteValueARM_OpMod16u(v)
	case OpMod32:
		return rewriteValueARM_OpMod32(v)
	case OpMod32u:
		return rewriteValueARM_OpMod32u(v)
	case OpMod8:
		return rewriteValueARM_OpMod8(v)
	case OpMod8u:
		return rewriteValueARM_OpMod8u(v)
	case OpMove:
		return rewriteValueARM_OpMove(v)
	case OpMul16:
		v.Op = OpARMMUL
		return true
	case OpMul32:
		v.Op = OpARMMUL
		return true
	case OpMul32F:
		v.Op = OpARMMULF
		return true
	case OpMul32uhilo:
		v.Op = OpARMMULLU
		return true
	case OpMul64F:
		v.Op = OpARMMULD
		return true
	case OpMul8:
		v.Op = OpARMMUL
		return true
	case OpNeg16:
		return rewriteValueARM_OpNeg16(v)
	case OpNeg32:
		return rewriteValueARM_OpNeg32(v)
	case OpNeg32F:
		v.Op = OpARMNEGF
		return true
	case OpNeg64F:
		v.Op = OpARMNEGD
		return true
	case OpNeg8:
		return rewriteValueARM_OpNeg8(v)
	case OpNeq16:
		return rewriteValueARM_OpNeq16(v)
	case OpNeq32:
		return rewriteValueARM_OpNeq32(v)
	case OpNeq32F:
		return rewriteValueARM_OpNeq32F(v)
	case OpNeq64F:
		return rewriteValueARM_OpNeq64F(v)
	case OpNeq8:
		return rewriteValueARM_OpNeq8(v)
	case OpNeqB:
		v.Op = OpARMXOR
		return true
	case OpNeqPtr:
		return rewriteValueARM_OpNeqPtr(v)
	case OpNilCheck:
		v.Op = OpARMLoweredNilCheck
		return true
	case OpNot:
		return rewriteValueARM_OpNot(v)
	case OpOffPtr:
		return rewriteValueARM_OpOffPtr(v)
	case OpOr16:
		v.Op = OpARMOR
		return true
	case OpOr32:
		v.Op = OpARMOR
		return true
	case OpOr8:
		v.Op = OpARMOR
		return true
	case OpOrB:
		v.Op = OpARMOR
		return true
	case OpPanicBounds:
		return rewriteValueARM_OpPanicBounds(v)
	case OpPanicExtend:
		return rewriteValueARM_OpPanicExtend(v)
	case OpRotateLeft16:
		return rewriteValueARM_OpRotateLeft16(v)
	case OpRotateLeft32:
		return rewriteValueARM_OpRotateLeft32(v)
	case OpRotateLeft8:
		return rewriteValueARM_OpRotateLeft8(v)
	case OpRound32F:
		v.Op = OpCopy
		return true
	case OpRound64F:
		v.Op = OpCopy
		return true
	case OpRsh16Ux16:
		return rewriteValueARM_OpRsh16Ux16(v)
	case OpRsh16Ux32:
		return rewriteValueARM_OpRsh16Ux32(v)
	case OpRsh16Ux64:
		return rewriteValueARM_OpRsh16Ux64(v)
	case OpRsh16Ux8:
		return rewriteValueARM_OpRsh16Ux8(v)
	case OpRsh16x16:
		return rewriteValueARM_OpRsh16x16(v)
	case OpRsh16x32:
		return rewriteValueARM_OpRsh16x32(v)
	case OpRsh16x64:
		return rewriteValueARM_OpRsh16x64(v)
	case OpRsh16x8:
		return rewriteValueARM_OpRsh16x8(v)
	case OpRsh32Ux16:
		return rewriteValueARM_OpRsh32Ux16(v)
	case OpRsh32Ux32:
		return rewriteValueARM_OpRsh32Ux32(v)
	case OpRsh32Ux64:
		return rewriteValueARM_OpRsh32Ux64(v)
	case OpRsh32Ux8:
		return rewriteValueARM_OpRsh32Ux8(v)
	case OpRsh32x16:
		return rewriteValueARM_OpRsh32x16(v)
	case OpRsh32x32:
		return rewriteValueARM_OpRsh32x32(v)
	case OpRsh32x64:
		return rewriteValueARM_OpRsh32x64(v)
	case OpRsh32x8:
		return rewriteValueARM_OpRsh32x8(v)
	case OpRsh8Ux16:
		return rewriteValueARM_OpRsh8Ux16(v)
	case OpRsh8Ux32:
		return rewriteValueARM_OpRsh8Ux32(v)
	case OpRsh8Ux64:
		return rewriteValueARM_OpRsh8Ux64(v)
	case OpRsh8Ux8:
		return rewriteValueARM_OpRsh8Ux8(v)
	case OpRsh8x16:
		return rewriteValueARM_OpRsh8x16(v)
	case OpRsh8x32:
		return rewriteValueARM_OpRsh8x32(v)
	case OpRsh8x64:
		return rewriteValueARM_OpRsh8x64(v)
	case OpRsh8x8:
		return rewriteValueARM_OpRsh8x8(v)
	case OpSelect0:
		return rewriteValueARM_OpSelect0(v)
	case OpSelect1:
		return rewriteValueARM_OpSelect1(v)
	case OpSignExt16to32:
		v.Op = OpARMMOVHreg
		return true
	case OpSignExt8to16:
		v.Op = OpARMMOVBreg
		return true
	case OpSignExt8to32:
		v.Op = OpARMMOVBreg
		return true
	case OpSignmask:
		return rewriteValueARM_OpSignmask(v)
	case OpSlicemask:
		return rewriteValueARM_OpSlicemask(v)
	case OpSqrt:
		v.Op = OpARMSQRTD
		return true
	case OpSqrt32:
		v.Op = OpARMSQRTF
		return true
	case OpStaticCall:
		v.Op = OpARMCALLstatic
		return true
	case OpStore:
		return rewriteValueARM_OpStore(v)
	case OpSub16:
		v.Op = OpARMSUB
		return true
	case OpSub32:
		v.Op = OpARMSUB
		return true
	case OpSub32F:
		v.Op = OpARMSUBF
		return true
	case OpSub32carry:
		v.Op = OpARMSUBS
		return true
	case OpSub32withcarry:
		v.Op = OpARMSBC
		return true
	case OpSub64F:
		v.Op = OpARMSUBD
		return true
	case OpSub8:
		v.Op = OpARMSUB
		return true
	case OpSubPtr:
		v.Op = OpARMSUB
		return true
	case OpTailCall:
		v.Op = OpARMCALLtail
		return true
	case OpTrunc16to8:
		v.Op = OpCopy
		return true
	case OpTrunc32to16:
		v.Op = OpCopy
		return true
	case OpTrunc32to8:
		v.Op = OpCopy
		return true
	case OpWB:
		v.Op = OpARMLoweredWB
		return true
	case OpXor16:
		v.Op = OpARMXOR
		return true
	case OpXor32:
		v.Op = OpARMXOR
		return true
	case OpXor8:
		v.Op = OpARMXOR
		return true
	case OpZero:
		return rewriteValueARM_OpZero(v)
	case OpZeroExt16to32:
		v.Op = OpARMMOVHUreg
		return true
	case OpZeroExt8to16:
		v.Op = OpARMMOVBUreg
		return true
	case OpZeroExt8to32:
		v.Op = OpARMMOVBUreg
		return true
	case OpZeromask:
		return rewriteValueARM_OpZeromask(v)
	}
	return false
}
func rewriteValueARM_OpARMADC(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (ADC (MOVWconst [c]) x flags)
	// result: (ADCconst [c] x flags)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpARMMOVWconst {
				continue
			}
			c := auxIntToInt32(v_0.AuxInt)
			x := v_1
			flags := v_2
			v.reset(OpARMADCconst)
			v.AuxInt = int32ToAuxInt(c)
			v.AddArg2(x, flags)
			return true
		}
		break
	}
	// match: (ADC x (SLLconst [c] y) flags)
	// result: (ADCshiftLL x y [c] flags)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			if v_1.Op != OpARMSLLconst {
				continue
			}
			c := auxIntToInt32(v_1.AuxInt)
			y := v_1.Args[0]
			flags := v_2
			v.reset(OpARMADCshiftLL)
			v.AuxInt = int32ToAuxInt(c)
			v.AddArg3(x, y, flags)
			return true
		}
		break
	}
	// match: (ADC x (SRLconst [c] y) flags)
	// result: (ADCshiftRL x y [c] flags)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			if v_1.Op != OpARMSRLconst {
				continue
			}
			c := auxIntToInt32(v_1.AuxInt)
			y := v_1.Args[0]
			flags := v_2
			v.reset(OpARMADCshiftRL)
			v.AuxInt = int32ToAuxInt(c)
			v.AddArg3(x, y, flags)
			return true
		}
		break
	}
	// match: (ADC x (SRAconst [c] y) flags)
	// result: (ADCshiftRA x y [c] flags)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			if v_1.Op != OpARMSRAconst {
				continue
			}
			c := auxIntToInt32(v_1.AuxInt)
			y := v_1.Args[0]
			flags := v_2
			v.reset(OpARMADCshiftRA)
			v.AuxInt = int32ToAuxInt(c)
			v.AddArg3(x, y, flags)
			return true
		}
		break
	}
	// match: (ADC x (SLL y z) flags)
	// result: (ADCshiftLLreg x y z flags)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			if v_1.Op != OpARMSLL {
				continue
			}
			z := v_1.Args[1]
			y := v_1.Args[0]
			flags := v_2
			v.reset(OpARMADCshiftLLreg)
			v.AddArg4(x, y, z, flags)
			return true
		}
		break
	}
	// match: (ADC x (SRL y z) flags)
	// result: (ADCshiftRLreg x y z flags)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			if v_1.Op != OpARMSRL {
				continue
			}
			z := v_1.Args[1]
			y := v_1.Args[0]
			flags := v_2
			v.reset(OpARMADCshiftRLreg)
			v.AddArg4(x, y, z, flags)
			return true
		}
		break
	}
	// match: (ADC x (SRA y z) flags)
	// result: (ADCshiftRAreg x y z flags)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			if v_1.Op != OpARMSRA {
				continue
			}
			z := v_1.Args[1]
			y := v_1.Args[0]
			flags := v_2
			v.reset(OpARMADCshiftRAreg)
			v.AddArg4(x, y, z, flags)
			return true
		}
		break
	}
	return false
}
func rewriteValueARM_OpARMADCconst(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (ADCconst [c] (ADDconst [d] x) flags)
	// result: (ADCconst [c+d] x flags)
	for {
		c := auxIntToInt32(v.AuxInt)
		if v_0.Op != OpARMADDconst {
			break
		}
		d := auxIntToInt32(v_0.AuxInt)
		x := v_0.Args[0]
		flags := v_1
		v.reset(OpARMADCconst)
		v.AuxInt = int32ToAuxInt(c + d)
		v.AddArg2(x, flags)
		return true
	}
	// match: (ADCconst [c] (SUBconst [d] x) flags)
	// result: (ADCconst [c-d] x flags)
	for {
		c := auxIntToInt32(v.AuxInt)
		if v_0.Op != OpARMSUBconst {
			break
		}
		d := auxIntToInt32(v_0.AuxInt)
		x := v_0.Args[0]
		flags := v_1
		v.reset(OpARMADCconst)
		v.AuxInt = int32ToAuxInt(c - d)
		v.AddArg2(x, flags)
		return true
	}
	return false
}
func rewriteValueARM_OpARMADCshiftLL(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (ADCshiftLL (MOVWconst [c]) x [d] flags)
	// result: (ADCconst [c] (SLLconst <x.Type> x [d]) flags)
	for {
		d := auxIntToInt32(v.AuxInt)
		if v_0.Op != OpARMMOVWconst {
			break
		}
		c := auxIntToInt32(v_0.AuxInt)
		x := v_1
		flags := v_2
		v.reset(OpARMADCconst)
		v.AuxInt = int32ToAuxInt(c)
		v0 := b.NewValue0(v.Pos, OpARMSLLconst, x.Type)
		v0.AuxInt = int32ToAuxInt(d)
		v0.AddArg(x)
		v.AddArg2(v0, flags)
		return true
	}
	// match: (ADCshiftLL x (MOVWconst [c]) [d] flags)
	// result: (ADCconst x [c<<uint64(d)] flags)
	for {
		d := auxIntToInt32(v.AuxInt)
		x := v_0
		if v_1.Op != OpARMMOVWconst {
			break
		}
		c := auxIntToInt32(v_1.AuxInt)
		flags := v_2
		v.reset(OpARMADCconst)
		v.AuxInt = int32ToAuxInt(c << uint64(d))
		v.AddArg2(x, flags)
		return true
	}
	return false
}
func rewriteValueARM_OpARMADCshiftLLreg(v *Value) bool {
	v_3 := v.Args[3]
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (ADCshiftLLreg (MOVWconst [c]) x y flags)
	// result: (ADCconst [c] (SLL <x.Type> x y) flags)
	for {
		if v_0.Op != OpARMMOVWconst {
			break
		}
		c := auxIntToInt32(v_0.AuxInt)
		x := v_1
		y := v_2
		flags := v_3
		v.reset(OpARMADCconst)
		v.AuxInt = int32ToAuxInt(c)
		v0 := b.NewValue0(v.Pos, OpARMSLL, x.Type)
		v0.AddArg2(x, y)
		v.AddArg2(v0, flags)
		return true
	}
	// match: (ADCshiftLLreg x y (MOVWconst [c]) flags)
	// cond: 0 <= c && c < 32
	// result: (ADCshiftLL x y [c] flags)
	for {
		x := v_0
		y := v_1
		if v_2.Op != OpARMMOVWconst {
			break
		}
		c := auxIntToInt32(v_2.AuxInt)
		flags := v_3
		if !(0 <= c && c < 32) {
			break
		}
		v.reset(OpARMADCshiftLL)
		v.AuxInt = int32ToAuxInt(c)
		v.AddArg3(x, y, flags)
		return true
	}
	return false
}
func rewriteValueARM_OpARMADCshiftRA(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (ADCshiftRA (MOVWconst [c]) x [d] flags)
	// result: (ADCconst [c] (SRAconst <x.Type> x [d]) flags)
	for {
		d := auxIntToInt32(v.AuxInt)
		if v_0.Op != OpARMMOVWconst {
			break
		}
		c := auxIntToInt32(v_0.AuxInt)
		x := v_1
		flags := v_2
		v.reset(OpARMADCconst)
		v.AuxInt = int32ToAuxInt(c)
		v0 := b.NewValue0(v.Pos, OpARMSRAconst, x.Type)
		v0.AuxInt = int32ToAuxInt(d)
		v0.AddArg(x)
		v.AddArg2(v0, flags)
		return true
	}
	// match: (ADCshiftRA x (MOVWconst [c]) [d] flags)
	// result: (ADCconst x [c>>uint64(d)] flags)
	for {
		d := auxIntToInt32(v.AuxInt)
		x := v_0
		if v_1.Op != OpARMMOVWconst {
			break
		}
		c := auxIntToInt32(v_1.AuxInt)
		flags := v_2
		v.reset(OpARMADCconst)
		v.AuxInt = int32ToAuxInt(c >> uint64(d))
		v.AddArg2(x, flags)
		return true
	}
	return false
}
func rewriteValueARM_OpARMADCshiftRAreg(v *Value) bool {
	v_3 := v.Args[3]
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (ADCshiftRAreg (MOVWconst [c]) x y flags)
	// result: (ADCconst [c] (SRA <x.Type> x y) flags)
	for {
		if v_0.Op != OpARMMOVWconst {
			break
		}
		c := auxIntToInt32(v_0.AuxInt)
		x := v_1
		y := v_2
		flags := v_3
		v.reset(OpARMADCconst)
		v.AuxInt = int32ToAuxInt(c)
		v0 := b.NewValue0(v.Pos, OpARMSRA, x.Type)
		v0.AddArg2(x, y)
		v.AddArg2(v0, flags)
		return true
	}
	// match: (ADCshiftRAreg x y (MOVWconst [c]) flags)
	// cond: 0 <= c && c < 32
	// result: (ADCshiftRA x y [c] flags)
	for {
		x := v_0
		y := v_1
		if v_2.Op != OpARMMOVWconst {
			break
		}
		c := auxIntToInt32(v_2.AuxInt)
		flags := v_3
		if !(0 <= c && c < 32) {
			break
		}
		v.reset(OpARMADCshiftRA)
		v.AuxInt = int32ToAuxInt(c)
		v.AddArg3(x, y, flags)
		return true
	}
	return false
}
func rewriteValueARM_OpARMADCshiftRL(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (ADCshiftRL (MOVWconst [c]) x [d] flags)
	// result: (ADCconst [c] (SRLconst <x.Type> x [d]) flags)
	for {
		d := auxIntToInt32(v.AuxInt)
		if v_0.Op != OpARMMOVWconst {
			break
		}
		c := auxIntToInt32(v_0.AuxInt)
		x := v_1
		flags := v_2
		v.reset(OpARMADCconst)
		v.AuxInt = int32ToAuxInt(c)
		v0 := b.NewValue0(v.Pos, OpARMSRLconst, x.Type)
		v0.AuxInt = int32ToAuxInt(d)
		v0.AddArg(x)
		v.AddArg2(v0, flags)
		return true
	}
	// match: (ADCshiftRL x (MOVWconst [c]) [d] flags)
	// result: (ADCconst x [int32(uint32(c)>>uint64(d))] flags)
	for {
		d := auxIntToInt32(v.AuxInt)
		x := v_0
		if v_1.Op != OpARMMOVWconst {
			break
		}
		c := auxIntToInt32(v_1.AuxInt)
		flags := v_2
		v.reset(OpARMADCconst)
		v.AuxInt = int32ToAuxInt(int32(uint32(c) >> uint64(d)))
		v.AddArg2(x, flags)
		return true
	}
	return false
}
func rewriteValueARM_OpARMADCshiftRLreg(v *Value) bool {
	v_3 := v.Args[3]
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (ADCshiftRLreg (MOVWconst [c]) x y flags)
	// result: (ADCconst [c] (SRL <x.Type> x y) flags)
	for {
		if v_0.Op != OpARMMOVWconst {
			break
		}
		c := auxIntToInt32(v_0.AuxInt)
		x := v_1
		y := v_2
		flags := v_3
		v.reset(OpARMADCconst)
		v.AuxInt = int32ToAuxInt(c)
		v0 := b.NewValue0(v.Pos, OpARMSRL, x.Type)
		v0.AddArg2(x, y)
		v.AddArg2(v0, flags)
		return true
	}
	// match: (ADCshiftRLreg x y (MOVWconst [c]) flags)
	// cond: 0 <= c && c < 32
	// result: (ADCshiftRL x y [c] flags)
	for {
		x := v_0
		y := v_1
		if v_2.Op != OpARMMOVWconst {
			break
		}
		c := auxIntToInt32(v_2.AuxInt)
		flags := v_3
		if !(0 <= c && c < 32) {
			break
		}
		v.reset(OpARMADCshiftRL)
		v.AuxInt = int32ToAuxInt(c)
		v.AddArg3(x, y, flags)
		return true
	}
	return false
}
func rewriteValueARM_OpARMADD(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (ADD x (MOVWconst <t> [c]))
	// cond: !t.IsPtr()
	// result: (ADDconst [c] x)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			if v_1.Op != OpARMMOVWconst {
				continue
			}
			t := v_1.Type
			c := auxIntToInt32(v_1.AuxInt)
			if !(!t.IsPtr()) {
				continue
			}
			v.reset(OpARMADDconst)
			v.AuxInt = int32ToAuxInt(c)
			v.AddArg(x)
			return true
		}
		break
	}
	// match: (ADD x (SLLconst [c] y))
	// result: (ADDshiftLL x y [c])
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			if v_1.Op != OpARMSLLconst {
				continue
			}
			c := auxIntToInt32(v_1.AuxInt)
			y := v_1.Args[0]
			v.reset(OpARMADDshiftLL)
			v.AuxInt = int32ToAuxInt(c)
			v.AddArg2(x, y)
			return true
		}
		break
	}
	// match: (ADD x (SRLconst [c] y))
	// result: (ADDshiftRL x y [c])
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			if v_1.Op != OpARMSRLconst {
				continue
			}
			c := auxIntToInt32(v_1.AuxInt)
			y := v_1.Args[0]
			v.reset(OpARMADDshiftRL)
			v.AuxInt = int32ToAuxInt(c)
			v.AddArg2(x, y)
			return true
		}
		break
	}
	// match: (ADD x (SRAconst [c] y))
	// result: (ADDshiftRA x y [c])
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			if v_1.Op != OpARMSRAconst {
				continue
			}
			c := auxIntToInt32(v_1.AuxInt)
			y := v_1.Args[0]
			v.reset(OpARMADDshiftRA)
			v.AuxInt = int32ToAuxInt(c)
			v.AddArg2(x, y)
			return true
		}
		break
	}
	// match: (ADD x (SLL y z))
	// result: (ADDshiftLLreg x y z)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			if v_1.Op != OpARMSLL {
				continue
			}
			z := v_1.Args[1]
			y := v_1.Args[0]
			v.reset(OpARMADDshiftLLreg)
			v.AddArg3(x, y, z)
			return true
		}
		break
	}
	// match: (ADD x (SRL y z))
	// result: (ADDshiftRLreg x y z)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			if v_1.Op != OpARMSRL {
				continue
			}
			z := v_1.Args[1]
			y := v_1.Args[0]
			v.reset(OpARMADDshiftRLreg)
			v.AddArg3(x, y, z)
			return true
		}
		break
	}
	// match: (ADD x (SRA y z))
	// result: (ADDshiftRAreg x y z)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			if v_1.Op != OpARMSRA {
				continue
			}
			z := v_1.Args[1]
			y := v_1.Args[0]
			v.reset(OpARMADDshiftRAreg)
			v.AddArg3(x, y, z)
			return true
		}
		break
	}
	// match: (ADD x (RSBconst [0] y))
	// result: (SUB x y)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			if v_1.Op != OpARMRSBconst || auxIntToInt32(v_1.AuxInt) != 0 {
				continue
			}
			y := v_1.Args[0]
			v.reset(OpARMSUB)
			v.AddArg2(x, y)
			return true
		}
		break
	}
	// match: (ADD <t> (RSBconst [c] x) (RSBconst [d] y))
	// result: (RSBconst [c+d] (ADD <t> x y))
	for {
		t := v.Type
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpARMRSBconst {
				continue
			}
			c := auxIntToInt32(v_0.AuxInt)
			x := v_0.Args[0]
			if v_1.Op != OpARMRSBconst {
				continue
			}
			d := auxIntToInt32(v_1.AuxInt)
			y := v_1.Args[0]
			v.reset(OpARMRSBconst)
			v.AuxInt = int32ToAuxInt(c + d)
			v0 := b.NewValue0(v.Pos, OpARMADD, t)
			v0.AddArg2(x, y)
			v.AddArg(v0)
			return true
		}
		break
	}
	// match: (ADD (MUL x y) a)
	// result: (MULA x y a)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpARMMUL {
				continue
			}
			y := v_0.Args[1]
			x := v_0.Args[0]
			a := v_1
			v.reset(OpARMMULA)
			v.AddArg3(x, y, a)
			return true
		}
		break
	}
	return false
}
func rewriteValueARM_OpARMADDD(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (ADDD a (MULD x y))
	// cond: a.Uses == 1 && buildcfg.GOARM.Version >= 6
	// result: (MULAD a x y)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			a := v_0
			if v_1.Op != OpARMMULD {
				continue
			}
			y := v_1.Args[1]
			x := v_1.Args[0]
			if !(a.Uses == 1 && buildcfg.GOARM.Version >= 6) {
				continue
			}
			v.reset(OpARMMULAD)
			v.AddArg3(a, x, y)
			return true
		}
		break
	}
	// match: (ADDD a (NMULD x y))
	// cond: a.Uses == 1 && buildcfg.GOARM.Version >= 6
	// result: (MULSD a x y)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			a := v_0
			if v_1.Op != OpARMNMULD {
				continue
			}
			y := v_1.Args[1]
			x := v_1.Args[0]
			if !(a.Uses == 1 && buildcfg.GOARM.Version >= 6) {
				continue
			}
			v.reset(OpARMMULSD)
			v.AddArg3(a, x, y)
			return true
		}
		break
	}
	return false
}
func rewriteValueARM_OpARMADDF(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (ADDF a (MULF x y))
	// cond: a.Uses == 1 && buildcfg.GOARM.Version >= 6
	// result: (MULAF a x y)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			a := v_0
			if v_1.Op != OpARMMULF {
				continue
			}
			y := v_1.Args[1]
			x := v_1.Args[0]
			if !(a.Uses == 1 && buildcfg.GOARM.Version >= 6) {
				continue
			}
			v.reset(OpARMMULAF)
			v.AddArg3(a, x, y)
			return true
		}
		break
	}
	// match: (ADDF a (NMULF x y))
	// cond: a.Uses == 1 && buildcfg.GOARM.Version >= 6
	// result: (MULSF a x y)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			a := v_0
			if v_1.Op != OpARMNMULF {
				continue
			}
			y := v_1.Args[1]
			x := v_1.Args[0]
			if !(a.Uses == 1 && buildcfg.GOARM.Version >= 6) {
				continue
			}
			v.reset(OpARMMULSF)
			v.AddArg3(a, x, y)
			return true
		}
		break
	}
	return false
}
func rewriteValueARM_OpARMADDS(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (ADDS x (MOVWconst [c]))
	// result: (ADDSconst [c] x)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			if v_1.Op != OpARMMOVWconst {
				continue
			}
			c := auxIntToInt32(v_1.AuxInt)
			v.reset(OpARMADDSconst)
			v.AuxInt = int32ToAuxInt(c)
			v.AddArg(x)
			return true
		}
		break
	}
	// match: (ADDS x (SLLconst [c] y))
	// result: (ADDSshiftLL x y [c])
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			if v_1.Op != OpARMSLLconst {
				continue
			}
			c := auxIntToInt32(v_1.AuxInt)
			y := v_1.Args[0]
			v.reset(OpARMADDSshiftLL)
			v.AuxInt = int32ToAuxInt(c)
			v.AddArg2(x, y)
			return true
		}
		break
	}
	// match: (ADDS x (SRLconst [c] y))
	// result: (ADDSshiftRL x y [c])
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			if v_1.Op != OpARMSRLconst {
				continue
			}
			c := auxIntToInt32(v_1.AuxInt)
			y := v_1.Args[0]
			v.reset(OpARMADDSshiftRL)
			v.AuxInt = int32ToAuxInt(c)
			v.AddArg2(x, y)
			return true
		}
		break
	}
	// match: (ADDS x (SRAconst [c] y))
	// result: (ADDSshiftRA x y [c])
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			if v_1.Op != OpARMSRAconst {
				continue
			}
			c := auxIntToInt32(v_1.AuxInt)
			y := v_1.Args[0]
			v.reset(OpARMADDSshiftRA)
			v.AuxInt = int32ToAuxInt(c)
			v.AddArg2(x, y)
			return true
		}
		break
	}
	// match: (ADDS x (SLL y z))
	// result: (ADDSshiftLLreg x y z)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			if v_1.Op != OpARMSLL {
				continue
			}
			z := v_1.Args[1]
			y := v_1.Args[0]
			v.reset(OpARMADDSshiftLLreg)
			v.AddArg3(x, y, z)
			return true
		}
		break
	}
	// match: (ADDS x (SRL y z))
	// result: (ADDSshiftRLreg x y z)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			if v_1.Op != OpARMSRL {
				continue
			}
			z := v_1.Args[1]
			y := v_1.Args[0]
			v.reset(OpARMADDSshiftRLreg)
			v.AddArg3(x, y, z)
			return true
		}
		break
	}
	// match: (ADDS x (SRA y z))
	// result: (ADDSshiftRAreg x y z)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			if v_1.Op != OpARMSRA {
				continue
			}
			z := v_1.Args[1]
			y := v_1.Args[0]
			v.reset(OpARMADDSshiftRAreg)
			v.AddArg3(x, y, z)
			return true
		}
		break
	}
	return false
}
func rewriteValueARM_OpARMADDSshiftLL(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (ADDSshiftLL (MOVWconst [c]) x [d])
	// result: (ADDSconst [c] (SLLconst <x.Type> x [d]))
	for {
		d := auxIntToInt32(v.AuxInt)
		if v_0.Op != OpARMMOVWconst {
			break
		}
		c := auxIntToInt32(v_0.AuxInt)
		x := v_1
		v.reset(OpARMADDSconst)
		v.AuxInt = int32ToAuxInt(c)
		v0 := b.NewValue0(v.Pos, OpARMSLLconst, x.Type)
		v0.AuxInt = int32ToAuxInt(d)
		v0.AddArg(x)
		v.AddArg(v0)
		return true
	}
	// match: (ADDSshiftLL x (MOVWconst [c]) [d])
	// result: (ADDSconst x [c<<uint64(d)])
	for {
		d := auxIntToInt32(v.AuxInt)
		x := v_0
		if v_1.Op != OpARMMOVWconst {
			break
		}
		c := auxIntToInt32(v_1.AuxInt)
		v.reset(OpARMADDSconst)
		v.AuxInt = int32ToAuxInt(c << uint64(d))
		v.AddArg(x)
		return true
	}
	return false
}
func rewriteValueARM_OpARMADDSshiftLLreg(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (ADDSshiftLLreg (MOVWconst [c]) x y)
	// result: (ADDSconst [c] (SLL <x.Type> x y))
	for {
		if v_0.Op != OpARMMOVWconst {
			break
		}
		c := auxIntToInt32(v_0.AuxInt)
		x := v_1
		y := v_2
		v.reset(OpARMADDSconst)
		v.AuxInt = int32ToAuxInt(c)
		v0 := b.NewValue0(v.Pos, OpARMSLL, x.Type)
		v0.AddArg2(x, y)
		v.AddArg(v0)
		return true
	}
	// match: (ADDSshiftLLreg x y (MOVWconst [c]))
	// cond: 0 <= c && c < 32
	// result: (ADDSshiftLL x y [c])
	for {
		x := v_0
		y := v_1
		if v_2.Op != OpARMMOVWconst {
			break
		}
		c := auxIntToInt32(v_2.AuxInt)
		if !(0 <= c && c < 32) {
			break
		}
		v.reset(OpARMADDSshiftLL)
		v.AuxInt = int32ToAuxInt(c)
		v.AddArg2(x, y)
		return true
	}
	return false
}
func rewriteValueARM_OpARMADDSshiftRA(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (ADDSshiftRA (MOVWconst [c]) x [d])
	// result: (ADDSconst [c] (SRAconst <x.Type> x [d]))
	for {
		d := auxIntToInt32(v.AuxInt)
		if v_0.Op != OpARMMOVWconst {
			break
		}
		c := auxIntToInt32(v_0.AuxInt)
		x := v_1
		v.reset(OpARMADDSconst)
		v.AuxInt = int32ToAuxInt(c)
		v0 := b.NewValue0(v.Pos, OpARMSRAconst, x.Type)
		v0.AuxInt = int32ToAuxInt(d)
		v0.AddArg(x)
		v.AddArg(v0)
		return true
	}
	// match: (ADDSshiftRA x (MOVWconst [c]) [d])
	// result: (ADDSconst x [c>>uint64(d)])
	for {
		d := auxIntToInt32(v.AuxInt)
		x := v_0
		if v_1.Op != OpARMMOVWconst {
			break
		}
		c := auxIntToInt32(v_1.AuxInt)
		v.reset(OpARMADDSconst)
		v.AuxInt = int32ToAuxInt(c >> uint64(d))
		v.AddArg(x)
		return true
	}
	return false
}
func rewriteValueARM_OpARMADDSshiftRAreg(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (ADDSshiftRAreg (MOVWconst [c]) x y)
	// result: (ADDSconst [c] (SRA <x.Type> x y))
	for {
		if v_0.Op != OpARMMOVWconst {
			break
		}
		c := auxIntToInt32(v_0.AuxInt)
		x := v_1
		y := v_2
		v.reset(OpARMADDSconst)
		v.AuxInt = int32ToAuxInt(c)
		v0 := b.NewValue0(v.Pos, OpARMSRA, x.Type)
		v0.AddArg2(x, y)
		v.AddArg(v0)
		return true
	}
	// match: (ADDSshiftRAreg x y (MOVWconst [c]))
	// cond: 0 <= c && c < 32
	// result: (ADDSshiftRA x y [c])
	for {
		x := v_0
		y := v_1
		if v_2.Op != OpARMMOVWconst {
			break
		}
		c := auxIntToInt32(v_2.AuxInt)
		if !(0 <= c && c < 32) {
			break
		}
		v.reset(OpARMADDSshiftRA)
		v.AuxInt = int32ToAuxInt(c)
		v.AddArg2(x, y)
		return true
	}
	return false
}
func rewriteValueARM_OpARMADDSshiftRL(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (ADDSshiftRL (MOVWconst [c]) x [d])
	// result: (ADDSconst [c] (SRLconst <x.Type> x [d]))
	for {
		d := auxIntToInt32(v.AuxInt)
		if v_0.Op != OpARMMOVWconst {
			break
		}
		c := auxIntToInt32(v_0.AuxInt)
		x := v_1
		v.reset(OpARMADDSconst)
		v.AuxInt = int32ToAuxInt(c)
		v0 := b.NewValue0(v.Pos, OpARMSRLconst, x.Type)
		v0.AuxInt = int32ToAuxInt(d)
		v0.AddArg(x)
		v.AddArg(v0)
		return true
	}
	// match: (ADDSshiftRL x (MOVWconst [c]) [d])
	// result: (ADDSconst x [int32(uint32(c)>>uint64(d))])
	for {
		d := auxIntToInt32(v.AuxInt)
		x := v_0
		if v_1.Op != OpARMMOVWconst {
			break
		}
		c := auxIntToInt32(v_1.AuxInt)
		v.reset(OpARMADDSconst)
		v.AuxInt = int32ToAuxInt(int32(uint32(c) >> uint64(d)))
		v.AddArg(x)
		return true
	}
	return false
}
func rewriteValueARM_OpARMADDSshiftRLreg(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (ADDSshiftRLreg (MOVWconst [c]) x y)
	// result: (ADDSconst [c] (SRL <x.Type> x y))
	for {
		if v_0.Op != OpARMMOVWconst {
			break
		}
		c := auxIntToInt32(v_0.AuxInt)
		x := v_1
		y := v_2
		v.reset(OpARMADDSconst)
		v.AuxInt = int32ToAuxInt(c)
		v0 := b.NewValue0(v.Pos, OpARMSRL, x.Type)
		v0.AddArg2(x, y)
		v.AddArg(v0)
		return true
	}
	// match: (ADDSshiftRLreg x y (MOVWconst [c]))
	// cond: 0 <= c && c < 32
	// result: (ADDSshiftRL x y [c])
	for {
		x := v_0
		y := v_1
		if v_2.Op != OpARMMOVWconst {
			break
		}
		c := auxIntToInt32(v_2.AuxInt)
		if !(0 <= c && c < 32) {
			break
		}
		v.reset(OpARMADDSshiftRL)
		v.AuxInt = int32ToAuxInt(c)
		v.AddArg2(x, y)
		return true
	}
	return false
}
func rewriteValueARM_OpARMADDconst(v *Value) bool {
	v_0 := v.Args[0]
	// match: (ADDconst [off1] (MOVWaddr [off2] {sym} ptr))
	// result: (MOVWaddr [off1+off2] {sym} ptr)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		if v_0.Op != OpARMMOVWaddr {
			break
		}
		off2 := auxIntToInt32(v_0.AuxInt)
		sym := auxToSym(v_0.Aux)
		ptr := v_0.Args[0]
		v.reset(OpARMMOVWaddr)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(sym)
		v.AddArg(ptr)
		return true
	}
	// match: (ADDconst [0] x)
	// result: x
	for {
		if auxIntToInt32(v.AuxInt) != 0 {
			break
		}
		x := v_0
		v.copyOf(x)
		return true
	}
	// match: (ADDconst [c] x)
	// cond: !isARMImmRot(uint32(c)) && isARMImmRot(uint32(-c))
	// result: (SUBconst [-c] x)
	for {
		c := auxIntToInt32(v.AuxInt)
		x := v_0
		if !(!isARMImmRot(uint32(c)) && isARMImmRot(uint32(-c))) {
			break
		}
		v.reset(OpARMSUBconst)
		v.AuxInt = int32ToAuxInt(-c)
		v.AddArg(x)
		return true
	}
	// match: (ADDconst [c] x)
	// cond: buildcfg.GOARM.Version==7 && !isARMImmRot(uint32(c)) && uint32(c)>0xffff && uint32(-c)<=0xffff
	// result: (SUBconst [-c] x)
	for {
		c := auxIntToInt32(v.AuxInt)
		x := v_0
		if !(buildcfg.GOARM.Version == 7 && !isARMImmRot(uint32(c)) && uint32(c) > 0xffff && uint32(-c) <= 0xffff) {
			break
		}
		v.reset(OpARMSUBconst)
		v.AuxInt = int32ToAuxInt(-c)
		v.AddArg(x)
		return true
	}
	// match: (ADDconst [c] (MOVWconst [d]))
	// result: (MOVWconst [c+d])
	for {
		c := auxIntToInt32(v.AuxInt)
		if v_0.Op != OpARMMOVWconst {
			break
		}
		d := auxIntToInt32(v_0.AuxInt)
		v.reset(OpARMMOVWconst)
		v.AuxInt = int32ToAuxInt(c + d)
		return true
	}
	// match: (ADDconst [c] (ADDconst [d] x))
	// result: (ADDconst [c+d] x)
	for {
		c := auxIntToInt32(v.AuxInt)
		if v_0.Op != OpARMADDconst {
			break
		}
		d := auxIntToInt32(v_0.AuxInt)
		x := v_0.Args[0]
		v.reset(OpARMADDconst)
		v.AuxInt = int32ToAuxInt(c + d)
		v.AddArg(x)
		return true
	}
	// match: (ADDconst [c] (SUBconst [d] x))
	// result: (ADDconst [c-d] x)
	for {
		c := auxIntToInt32(v.AuxInt)
		if v_0.Op != OpARMSUBconst {
			break
		}
		d := auxIntToInt32(v_0.AuxInt)
		x := v_0.Args[0]
		v.reset(OpARMADDconst)
		v.AuxInt = int32ToAuxInt(c - d)
		v.AddArg(x)
		return true
	}
	// match: (ADDconst [c] (RSBconst [d] x))
	// result: (RSBconst [c+d] x)
	for {
		c := auxIntToInt32(v.AuxInt)
		if v_0.Op != OpARMRSBconst {
			break
		}
		d := auxIntToInt32(v_0.AuxInt)
		x := v_0.Args[0]
		v.reset(OpARMRSBconst)
		v.AuxInt = int32ToAuxInt(c + d)
		v.AddArg(x)
		return true
	}
	return false
}
func rewriteValueARM_OpARMADDshiftLL(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (ADDshiftLL (MOVWconst [c]) x [d])
	// result: (ADDconst [c] (SLLconst <x.Type> x [d]))
	for {
		d := auxIntToInt32(v.AuxInt)
		if v_0.Op != OpARMMOVWconst {
			break
		}
		c := auxIntToInt32(v_0.AuxInt)
		x := v_1
		v.reset(OpARMADDconst)
		v.AuxInt = int32ToAuxInt(c)
		v0 := b.NewValue0(v.Pos, OpARMSLLconst, x.Type)
		v0.AuxInt = int32ToAuxInt(d)
		v0.AddArg(x)
		v.AddArg(v0)
		return true
	}
	// match: (ADDshiftLL x (MOVWconst [c]) [d])
	// result: (ADDconst x [c<<uint64(d)])
	for {
		d := auxIntToInt32(v.AuxInt)
		x := v_0
		if v_1.Op != OpARMMOVWconst {
			break
		}
		c := auxIntToInt32(v_1.AuxInt)
		v.reset(OpARMADDconst)
		v.AuxInt = int32ToAuxInt(c << uint64(d))
		v.AddArg(x)
		return true
	}
	// match: (ADDshiftLL <typ.UInt16> [8] (BFXU <typ.UInt16> [int32(armBFAuxInt(8, 8))] x) x)
	// result: (REV16 x)
	for {
		if v.Type != typ.UInt16 || auxIntToInt32(v.AuxInt) != 8 || v_0.Op != OpARMBFXU || v_0.Type != typ.UInt16 || auxIntToInt32(v_0.AuxInt) != int32(armBFAuxInt(8, 8)) {
			break
		}
		x := v_0.Args[0]
		if x != v_1 {
			break
		}
		v.reset(OpARMREV16)
		v.AddArg(x)
		return true
	}
	// match: (ADDshiftLL <typ.UInt16> [8] (SRLconst <typ.UInt16> [24] (SLLconst [16] x)) x)
	// cond: buildcfg.GOARM.Version>=6
	// result: (REV16 x)
	for {
		if v.Type != typ.UInt16 || auxIntToInt32(v.AuxInt) != 8 || v_0.Op != OpARMSRLconst || v_0.Type != typ.UInt16 || auxIntToInt32(v_0.AuxInt) != 24 {
			break
		}
		v_0_0 := v_0.Args[0]
		if v_0_0.Op != OpARMSLLconst || auxIntToInt32(v_0_0.AuxInt) != 16 {
			break
		}
		x := v_0_0.Args[0]
		if x != v_1 || !(buildcfg.GOARM.Version >= 6) {
			break
		}
		v.reset(OpARMREV16)
		v.AddArg(x)
		return true
	}
	return false
}
func rewriteValueARM_OpARMADDshiftLLreg(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (ADDshiftLLreg (MOVWconst [c]) x y)
	// result: (ADDconst [c] (SLL <x.Type> x y))
	for {
		if v_0.Op != OpARMMOVWconst {
			break
		}
		c := auxIntToInt32(v_0.AuxInt)
		x := v_1
		y := v_2
		v.reset(OpARMADDconst)
		v.AuxInt = int32ToAuxInt(c)
		v0 := b.NewValue0(v.Pos, OpARMSLL, x.Type)
		v0.AddArg2(x, y)
		v.AddArg(v0)
		return true
	}
	// match: (ADDshiftLLreg x y (MOVWconst [c]))
	// cond: 0 <= c && c < 32
	// result: (ADDshiftLL x y [c])
	for {
		x := v_0
		y := v_1
		if v_2.Op != OpARMMOVWconst {
			break
		}
		c := auxIntToInt32(v_2.AuxInt)
		if !(0 <= c && c < 32) {
			break
		}
		v.reset(OpARMADDshiftLL)
		v.AuxInt = int32ToAuxInt(c)
		v.AddArg2(x, y)
		return true
	}
	return false
}
func rewriteValueARM_OpARMADDshiftRA(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (ADDshiftRA (MOVWconst [c]) x [d])
	// result: (ADDconst [c] (SRAconst <x.Type> x [d]))
	for {
		d := auxIntToInt32(v.AuxInt)
		if v_0.Op != OpARMMOVWconst {
			break
		}
		c := auxIntToInt32(v_0.AuxInt)
		x := v_1
		v.reset(OpARMADDconst)
		v.AuxInt = int32ToAuxInt(c)
		v0 := b.NewValue0(v.Pos, OpARMSRAconst, x.Type)
		v0.AuxInt = int32ToAuxInt(d)
		v0.AddArg(x)
		v.AddArg(v0)
		return true
	}
	// match: (ADDshiftRA x (MOVWconst [c]) [d])
	// result: (ADDconst x [c>>uint64(d)])
	for {
		d := auxIntToInt32(v.AuxInt)
		x := v_0
		if v_1.Op != OpARMMOVWconst {
			break
		}
		c := auxIntToInt32(v_1.AuxInt)
		v.reset(OpARMADDconst)
		v.AuxInt = int32ToAuxInt(c >> uint64(d))
		v.AddArg(x)
		return true
	}
	return false
}
func rewriteValueARM_OpARMADDshiftRAreg(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (ADDshiftRAreg (MOVWconst [c]) x y)
	// result: (ADDconst [c] (SRA <x.Type> x y))
	for {
		if v_0.Op != OpARMMOVWconst {
			break
		}
		c := auxIntToInt32(v_0.AuxInt)
		x := v_1
		y := v_2
		v.reset(OpARMADDconst)
		v.AuxInt = int32ToAuxInt(c)
		v0 := b.NewValue0(v.Pos, OpARMSRA, x.Type)
		v0.AddArg2(x, y)
		v.AddArg(v0)
		return true
	}
	// match: (ADDshiftRAreg x y (MOVWconst [c]))
	// cond: 0 <= c && c < 32
	// result: (ADDshiftRA x y [c])
	for {
		x := v_0
		y := v_1
		if v_2.Op != OpARMMOVWconst {
			break
		}
		c := auxIntToInt32(v_2.AuxInt)
		if !(0 <= c && c < 32) {
			break
		}
		v.reset(OpARMADDshiftRA)
		v.AuxInt = int32ToAuxInt(c)
		v.AddArg2(x, y)
		return true
	}
	return false
}
func rewriteValueARM_OpARMADDshiftRL(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (ADDshiftRL (MOVWconst [c]) x [d])
	// result: (ADDconst [c] (SRLconst <x.Type> x [d]))
	for {
		d := auxIntToInt32(v.AuxInt)
		if v_0.Op != OpARMMOVWconst {
			break
		}
		c := auxIntToInt32(v_0.AuxInt)
		x := v_1
		v.reset(OpARMADDconst)
		v.AuxInt = int32ToAuxInt(c)
		v0 := b.NewValue0(v.Pos, OpARMSRLconst, x.Type)
		v0.AuxInt = int32ToAuxInt(d)
		v0.AddArg(x)
		v.AddArg(v0)
		return true
	}
	// match: (ADDshiftRL x (MOVWconst [c]) [d])
	// result: (ADDconst x [int32(uint32(c)>>uint64(d))])
	for {
		d := auxIntToInt32(v.AuxInt)
		x := v_0
		if v_1.Op != OpARMMOVWconst {
			break
		}
		c := auxIntToInt32(v_1.AuxInt)
		v.reset(OpARMADDconst)
		v.AuxInt = int32ToAuxInt(int32(uint32(c) >> uint64(d)))
		v.AddArg(x)
		return true
	}
	return false
}
func rewriteValueARM_OpARMADDshiftRLreg(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (ADDshiftRLreg (MOVWconst [c]) x y)
	// result: (ADDconst [c] (SRL <x.Type> x y))
	for {
		if v_0.Op != OpARMMOVWconst {
			break
		}
		c := auxIntToInt32(v_0.AuxInt)
		x := v_1
		y := v_2
		v.reset(OpARMADDconst)
		v.AuxInt = int32ToAuxInt(c)
		v0 := b.NewValue0(v.Pos, OpARMSRL, x.Type)
		v0.AddArg2(x, y)
		v.AddArg(v0)
		return true
	}
	// match: (ADDshiftRLreg x y (MOVWconst [c]))
	// cond: 0 <= c && c < 32
	// result: (ADDshiftRL x y [c])
	for {
		x := v_0
		y := v_1
		if v_2.Op != OpARMMOVWconst {
			break
		}
		c := auxIntToInt32(v_2.AuxInt)
		if !(0 <= c && c < 32) {
			break
		}
		v.reset(OpARMADDshiftRL)
		v.AuxInt = int32ToAuxInt(c)
		v.AddArg2(x, y)
		return true
	}
	return false
}
func rewriteValueARM_OpARMAND(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (AND x (MOVWconst [c]))
	// result: (ANDconst [c] x)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			if v_1.Op != OpARMMOVWconst {
				continue
			}
			c := auxIntToInt32(v_1.AuxInt)
			v.reset(OpARMANDconst)
			v.AuxInt = int32ToAuxInt(c)
			v.AddArg(x)
			return true
		}
		break
	}
	// match: (AND x (SLLconst [c] y))
	// result: (ANDshiftLL x y [c])
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			if v_1.Op != OpARMSLLconst {
				continue
			}
			c := auxIntToInt32(v_1.AuxInt)
			y := v_1.Args[0]
			v.reset(OpARMANDshiftLL)
			v.AuxInt = int32ToAuxInt(c)
			v.AddArg2(x, y)
			return true
		}
		break
	}
	// match: (AND x (SRLconst [c] y))
	// result: (ANDshiftRL x y [c])
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			if v_1.Op != OpARMSRLconst {
				continue
			}
			c := auxIntToInt32(v_1.AuxInt)
			y := v_1.Args[0]
			v.reset(OpARMANDshiftRL)
			v.AuxInt = int32ToAuxInt(c)
			v.AddArg2(x, y)
			return true
		}
		break
	}
	// match: (AND x (SRAconst [c] y))
	// result: (ANDshiftRA x y [c])
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			if v_1.Op != OpARMSRAconst {
				continue
			}
			c := auxIntToInt32(v_1.AuxInt)
			y := v_1.Args[0]
			v.reset(OpARMANDshiftRA)
			v.AuxInt = int32ToAuxInt(c)
			v.AddArg2(x, y)
			return true
		}
		break
	}
	// match: (AND x (SLL y z))
	// result: (ANDshiftLLreg x y z)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			if v_1.Op != OpARMSLL {
				continue
			}
			z := v_1.Args[1]
			y := v_1.Args[0]
			v.reset(OpARMANDshiftLLreg)
			v.AddArg3(x, y, z)
			return true
		}
		break
	}
	// match: (AND x (SRL y z))
	// result: (ANDshiftRLreg x y z)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			if v_1.Op != OpARMSRL {
				continue
			}
			z := v_1.Args[1]
			y := v_1.Args[0]
			v.reset(OpARMANDshiftRLreg)
			v.AddArg3(x, y, z)
			return true
		}
		break
	}
	// match: (AND x (SRA y z))
	// result: (ANDshiftRAreg x y z)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			if v_1.Op != OpARMSRA {
				continue
			}
			z := v_1.Args[1]
			y := v_1.Args[0]
			v.reset(OpARMANDshiftRAreg)
			v.AddArg3(x, y, z)
			return true
		}
		break
	}
	// match: (AND x x)
	// result: x
	for {
		x := v_0
		if x != v_1 {
			break
		}
		v.copyOf(x)
		return true
	}
	// match: (AND x (MVN y))
	// result: (BIC x y)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			if v_1.Op != OpARMMVN {
				continue
			}
			y := v_1.Args[0]
			v.reset(OpARMBIC)
			v.AddArg2(x, y)
			return true
		}
		break
	}
	// match: (AND x (MVNshiftLL y [c]))
	// result: (BICshiftLL x y [c])
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			if v_1.Op != OpARMMVNshiftLL {
				continue
			}
			c := auxIntToInt32(v_1.AuxInt)
			y := v_1.Args[0]
			v.reset(OpARMBICshiftLL)
			v.AuxInt = int32ToAuxInt(c)
			v.AddArg2(x, y)
			return true
		}
		break
	}
	// match: (AND x (MVNshiftRL y [c]))
	// result: (BICshiftRL x y [c])
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			if v_1.Op != OpARMMVNshiftRL {
				continue
			}
			c := auxIntToInt32(v_1.AuxInt)
			y := v_1.Args[0]
			v.reset(OpARMBICshiftRL)
			v.AuxInt = int32ToAuxInt(c)
			v.AddArg2(x, y)
			return true
		}
		break
	}
	// match: (AND x (MVNshiftRA y [c]))
	// result: (BICshiftRA x y [c])
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			if v_1.Op != OpARMMVNshiftRA {
				continue
			}
			c := auxIntToInt32(v_1.AuxInt)
			y := v_1.Args[0]
			v.reset(OpARMBICshiftRA)
			v.AuxInt = int32ToAuxInt(c)
			v.AddArg2(x, y)
			return true
		}
		break
	}
	return false
}
func rewriteValueARM_OpARMANDconst(v *Value) bool {
	v_0 := v.Args[0]
	// match: (ANDconst [0] _)
	// result: (MOVWconst [0])
	for {
		if auxIntToInt32(v.AuxInt) != 0 {
			break
		}
		v.reset(OpARMMOVWconst)
		v.AuxInt = int32ToAuxInt(0)
		return true
	}
	// match: (ANDconst [c] x)
	// cond: int32(c)==-1
	// result: x
	for {
		c := auxIntToInt32(v.AuxInt)
		x := v_0
		if !(int32(c) == -1) {
			break
		}
		v.copyOf(x)
		return true
	}
	// match: (ANDconst [c] x)
	// cond: !isARMImmRot(uint32(c)) && isARMImmRot(^uint32(c))
	// result: (BICconst [int32(^uint32(c))] x)
	for {
		c := auxIntToInt32(v.AuxInt)
		x := v_0
		if !(!isARMImmRot(uint32(c)) && isARMImmRot(^uint32(c))) {
			break
		}
		v.reset(OpARMBICconst)
		v.AuxInt = int32ToAuxInt(int32(^uint32(c)))
		v.AddArg(x)
		return true
	}
	// match: (ANDconst [c] x)
	// cond: buildcfg.GOARM.Version==7 && !isARMImmRot(uint32(c)) && uint32(c)>0xffff && ^uint32(c)<=0xffff
	// result: (BICconst [int32(^uint32(c))] x)
	for {
		c := auxIntToInt32(v.AuxInt)
		x := v_0
		if !(buildcfg.GOARM.Version == 7 && !isARMImmRot(uint32(c)) && uint32(c) > 0xffff && ^uint32(c) <= 0xffff) {
			break
		}
		v.reset(OpARMBICconst)
		v.AuxInt = int32ToAuxInt(int32(^uint32(c)))
		v.AddArg(x)
		return true
	}
	// match: (ANDconst [c] (MOVWconst [d]))
	// result: (MOVWconst [c&d])
	for {
		c := auxIntToInt32(v.AuxInt)
		if v_0.Op != OpARMMOVWconst {
			break
		}
		d := auxIntToInt32(v_0.AuxInt)
		v.reset(OpARMMOVWconst)
		v.AuxInt = int32ToAuxInt(c & d)
		return true
	}
	// match: (ANDconst [c] (ANDconst [d] x))
	// result: (ANDconst [c&d] x)
	for {
		c := auxIntToInt32(v.AuxInt)
		if v_0.Op != OpARMANDconst {
			break
		}
		d := auxIntToInt32(v_0.AuxInt)
		x := v_0.Args[0]
		v.reset(OpARMANDconst)
		v.AuxInt = int32ToAuxInt(c & d)
		v.AddArg(x)
		return true
	}
	return false
}
func rewriteValueARM_OpARMANDshiftLL(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (ANDshiftLL (MOVWconst [c]) x [d])
	// result: (ANDconst [c] (SLLconst <x.Type> x [d]))
	for {
		d := auxIntToInt32(v.AuxInt)
		if v_0.Op != OpARMMOVWconst {
			break
		}
		c := auxIntToInt32(v_0.AuxInt)
		x := v_1
		v.reset(OpARMANDconst)
		v.AuxInt = int32ToAuxInt(c)
		v0 := b.NewValue0(v.Pos, OpARMSLLconst, x.Type)
		v0.AuxInt = int32ToAuxInt(d)
		v0.AddArg(x)
		v.AddArg(v0)
		return true
	}
	// match: (ANDshiftLL x (MOVWconst [c]) [d])
	// result: (ANDconst x [c<<uint64(d)])
	for {
		d := auxIntToInt32(v.AuxInt)
		x := v_0
		if v_1.Op != OpARMMOVWconst {
			break
		}
		c := auxIntToInt32(v_1.AuxInt)
		v.reset(OpARMANDconst)
		v.AuxInt = int32ToAuxInt(c << uint64(d))
		v.AddArg(x)
		return true
	}
	// match: (ANDshiftLL y:(SLLconst x [c]) x [c])
	// result: y
	for {
		c := auxIntToInt32(v.AuxInt)
		y := v_0
		if y.Op != OpARMSLLconst || auxIntToInt32(y.AuxInt) != c {
			break
		}
		x := y.Args[0]
		if x != v_1 {
			break
		}
		v.copyOf(y)
		return true
	}
	return false
}
func rewriteValueARM_OpARMANDshiftLLreg(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (ANDshiftLLreg (MOVWconst [c]) x y)
	// result: (ANDconst [c] (SLL <x.Type> x y))
	for {
		if v_0.Op != OpARMMOVWconst {
			break
		}
		c := auxIntToInt32(v_0.AuxInt)
		x := v_1
		y := v_2
		v.reset(OpARMANDconst)
		v.AuxInt = int32ToAuxInt(c)
		v0 := b.NewValue0(v.Pos, OpARMSLL, x.Type)
		v0.AddArg2(x, y)
		v.AddArg(v0)
		return true
	}
	// match: (ANDshiftLLreg x y (MOVWconst [c]))
	// cond: 0 <= c && c < 32
	// result: (ANDshiftLL x y [c])
	for {
		x := v_0
		y := v_1
		if v_2.Op != OpARMMOVWconst {
			break
		}
		c := auxIntToInt32(v_2.AuxInt)
		if !(0 <= c && c < 32) {
			break
		}
		v.reset(OpARMANDshiftLL)
		v.AuxInt = int32ToAuxInt(c)
		v.AddArg2(x, y)
		return true
	}
	return false
}
func rewriteValueARM_OpARMANDshiftRA(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (ANDshiftRA (MOVWconst [c]) x [d])
	// result: (ANDconst [c] (SRAconst <x.Type> x [d]))
	for {
		d := auxIntToInt32(v.AuxInt)
		if v_0.Op != OpARMMOVWconst {
			break
		}
		c := auxIntToInt32(v_0.AuxInt)
		x := v_1
		v.reset(OpARMANDconst)
		v.AuxInt = int32ToAuxInt(c)
		v0 := b.NewValue0(v.Pos, OpARMSRAconst, x.Type)
		v0.AuxInt = int32ToAuxInt(d)
		v0.AddArg(x)
		v.AddArg(v0)
		return true
	}
	// match: (ANDshiftRA x (MOVWconst [c]) [d])
	// result: (ANDconst x [c>>uint64(d)])
	for {
		d := auxIntToInt32(v.AuxInt)
		x := v_0
		if v_1.Op != OpARMMOVWconst {
			break
		}
		c := auxIntToInt32(v_1.AuxInt)
		v.reset(OpARMANDconst)
		v.AuxInt = int32ToAuxInt(c >> uint64(d))
		v.AddArg(x)
		return true
	}
	// match: (ANDshiftRA y:(SRAconst x [c]) x [c])
	// result: y
	for {
		c := auxIntToInt32(v.AuxInt)
		y := v_0
		if y.Op != OpARMSRAconst || auxIntToInt32(y.AuxInt) != c {
			break
		}
		x := y.Args[0]
		if x != v_1 {
			break
		}
		v.copyOf(y)
		return true
	}
	return false
}
func rewriteValueARM_OpARMANDshiftRAreg(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (ANDshiftRAreg (MOVWconst [c]) x y)
	// result: (ANDconst [c] (SRA <x.Type> x y))
	for {
		if v_0.Op != OpARMMOVWconst {
			break
		}
		c := auxIntToInt32(v_0.AuxInt)
		x := v_1
		y := v_2
		v.reset(OpARMANDconst)
		v.AuxInt = int32ToAuxInt(c)
		v0 := b.NewValue0(v.Pos, OpARMSRA, x.Type)
		v0.AddArg2(x, y)
		v.AddArg(v0)
		return true
	}
	// match: (ANDshiftRAreg x y (MOVWconst [c]))
	// cond: 0 <= c && c < 32
	// result: (ANDshiftRA x y [c])
	for {
		x := v_0
		y := v_1
		if v_2.Op != OpARMMOVWconst {
			break
		}
		c := auxIntToInt32(v_2.AuxInt)
		if !(0 <= c && c < 32) {
			break
		}
		v.reset(OpARMANDshiftRA)
		v.AuxInt = int32ToAuxInt(c)
		v.AddArg2(x, y)
		return true
	}
	return false
}
func rewriteValueARM_OpARMANDshiftRL(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (ANDshiftRL (MOVWconst [c]) x [d])
	// result: (ANDconst [c] (SRLconst <x.Type> x [d]))
	for {
		d := auxIntToInt32(v.AuxInt)
		if v_0.Op != OpARMMOVWconst {
			break
		}
		c := auxIntToInt32(v_0.AuxInt)
		x := v_1
		v.reset(OpARMANDconst)
		v.AuxInt = int32ToAuxInt(c)
		v0 := b.NewValue0(v.Pos, OpARMSRLconst, x.Type)
		v0.AuxInt = int32ToAuxInt(d)
		v0.AddArg(x)
		v.AddArg(v0)
		return true
	}
	// match: (ANDshiftRL x (MOVWconst [c]) [d])
	// result: (ANDconst x [int32(uint32(c)>>uint64(d))])
	for {
		d := auxIntToInt32(v.AuxInt)
		x := v_0
		if v_1.Op != OpARMMOVWconst {
			break
		}
		c := auxIntToInt32(v_1.AuxInt)
		v.reset(OpAR
```