Response: My goal is to analyze the provided Go code snippet and extract its functionality, potential Go feature implementation, and identify any common mistakes. Here's a breakdown of the thinking process:

1. **Understand the Context:** The file path `go/src/cmd/compile/internal/ssa/rewriteAMD64.go` immediately tells me this code is part of the Go compiler, specifically the SSA (Static Single Assignment) intermediate representation for the AMD64 architecture. The `rewrite` prefix suggests this file contains optimization or transformation rules applied to the SSA. The `// Code generated` comment further indicates that the file is likely automatically generated based on some rules definition.

2. **Identify the Core Function:** The provided code defines a single function: `rewriteValueAMD64(v *Value) bool`. This function takes an SSA `Value` as input and returns a boolean. The boolean return likely indicates whether the value was successfully rewritten or not.

3. **Analyze the `switch` Statement:** The function's body consists of a large `switch` statement based on `v.Op`. This suggests that the function handles different SSA operations (`Op` codes). Each `case` corresponds to a specific AMD64 instruction or a higher-level Go operation that needs to be translated into AMD64 instructions.

4. **Recognize the Pattern:**  Within each `case`, there's a call to another function with a name like `rewriteValueAMD64_OpAMD64ADCQ(v)`, `rewriteValueAMD64_OpAdd16(v)`, etc. This strongly suggests a pattern where each SSA operation has a dedicated rewriting function.

5. **Infer Functionality (General):**  Based on the above observations, the primary function of `rewriteValueAMD64` is to **perform architecture-specific transformations and optimizations on the SSA representation of Go code for the AMD64 architecture**. It acts as a rule-based engine for lowering high-level Go operations and AMD64-specific pseudo-operations into more concrete AMD64 instructions.

6. **Infer Functionality (Specific Examples):**  By looking at the `case` labels, I can deduce specific functionalities:
    * **Arithmetic Operations:** `OpAMD64ADCQ`, `OpAMD64ADDL`, `OpAMD64SUBL`, `OpAMD64MULL`, `OpAMD64DIVSD`, etc., represent AMD64 arithmetic instructions. The rewrite rules likely aim to optimize these, possibly by using constant forms (`OpAMD64ADDLconst`), load/modify operations (`OpAMD64ADDLload`, `OpAMD64ADDLmodify`), or by recognizing patterns for LEA (Load Effective Address) instructions.
    * **Bitwise Operations:** `OpAMD64ANDL`, `OpAMD64ORQ`, `OpAMD64XORL`, `OpAMD64SHLL`, `OpAMD64SARQ`, etc., are AMD64 bitwise instructions. Rewrites might involve constant folding or recognizing specific bit manipulation idioms.
    * **Control Flow/Comparison:** `OpAMD64CMPL`, `OpAMD64SETA`, `OpAMD64CMOVLCC`, etc., relate to comparisons and conditional moves, used for implementing `if` statements, loops, and other control flow constructs.
    * **Memory Access:** `OpAMD64MOVBload`, `OpAMD64MOVQstore`, `OpAMD64AtomicLoad32`, `OpAMD64AtomicStore64`, etc., deal with loading and storing data from memory, including atomic operations for concurrency. Rewrites here might optimize load/store sequences or use more efficient addressing modes.
    * **Go Operations:**  `OpAdd32`, `OpMul64`, `OpEqPtr`, `OpCall`, `OpStore`, etc., represent higher-level Go operations. The rewrite rules translate these into corresponding AMD64 instruction sequences.

7. **Infer Go Feature Implementation:** The code handles a wide range of Go operations. It's not tied to a single, specific Go feature. Instead, it's fundamental to the compilation process for *all* Go code targeting the AMD64 architecture. It ensures that Go's abstract operations are correctly and efficiently implemented using the available AMD64 instruction set.

8. **Code Example (Illustrative):**  To illustrate, I can pick a simple Go operation like addition (`+`) and how it might be handled.

   ```go
   // Example Go code
   func add(a, b int32) int32 {
       return a + b
   }
   ```

   * **SSA Representation (Hypothetical):** The Go compiler would generate an SSA representation where the addition is represented by an `OpAdd32` node.
   * **`rewriteValueAMD64`'s Role:** The `rewriteValueAMD64` function, upon encountering an `OpAdd32` node, would transform it into the corresponding AMD64 instruction, likely `OpAMD64ADDL`.

9. **Command-line Arguments:**  This specific code snippet doesn't directly handle command-line arguments. The compilation process involves many stages and files. Command-line arguments for the Go compiler (like `-gcflags`, `-ldflags`, etc.) are processed in earlier stages and influence the overall compilation, but this particular file focuses on SSA rewriting.

10. **Common Mistakes:** Identifying common mistakes without seeing the individual rewriting functions is difficult. However, some potential areas for errors in *similar* code could be:
    * **Incorrect flag handling:**  Many AMD64 instructions set flags. Incorrectly assuming or manipulating these flags can lead to wrong results.
    * **Off-by-one errors in memory addressing:** When calculating memory offsets, it's easy to introduce errors.
    * **Incorrect register allocation (though this is handled in a later stage, rewrite rules might make assumptions).**
    * **Not considering all possible input combinations or edge cases.**

11. **Summarize Functionality:** The core functionality is to perform architecture-specific rewriting of SSA values for AMD64. This involves lowering high-level operations and optimizing AMD64 instructions.

12. **"Part 1 of 12":** This indicates a larger, multi-part file or a set of files related to AMD64 SSA rewriting. The functionality described applies specifically to this *part*. The other parts would likely handle different sets of operations or more complex rewriting scenarios.

This detailed thought process allows me to extract the key information from the code snippet and provide a comprehensive answer even without knowing the exact details of every rewrite rule.
这是路径为go/src/cmd/compile/internal/ssa/rewriteAMD64.go的go语言实现的一部分，它的主要功能是 **定义了一系列的重写规则，用于将 Go 语言的中间表示（SSA，Static Single Assignment）中的通用操作转换为 AMD64 架构特定的机器指令操作**。

简单来说，这个文件的作用是 **将抽象的 Go 语言操作“翻译”成具体的 AMD64 指令**，以便后续的代码生成阶段能够产生最终的可执行代码。

由于这只是第一部分，我们可以推断出它可能涵盖了 AMD64 指令集中的一部分基本算术、逻辑、比较和数据移动操作的转换规则。

**具体功能归纳:**

1. **定义 `rewriteValueAMD64(v *Value) bool` 函数:** 这是核心的重写函数，它接收一个 SSA `Value` 指针作为输入，并尝试根据其操作码 (`v.Op`) 应用相应的重写规则。如果成功应用了规则并修改了 `Value`，则返回 `true`，否则返回 `false`。

2. **`switch v.Op` 结构:**  该结构根据不同的 SSA 操作码 `v.Op` 分发到不同的处理逻辑。每个 `case` 对应一个特定的 SSA 操作或一组相关的操作。

3. **针对不同 AMD64 指令的重写规则:**  `case` 语句中调用了 `rewriteValueAMD64_OpXXX(v)` 形式的函数，例如 `rewriteValueAMD64_OpAMD64ADCQ(v)`，`rewriteValueAMD64_OpAMD64ADDL(v)` 等。 这些函数包含了针对特定 AMD64 指令的重写逻辑，例如：
    * **算术运算:**  `ADCQ`, `ADDL`, `ADDQ`, `SUBL`, `SUBQ`, `MULL`, `MULQ`, `DIVSD`, `DIVSS` 等的重写规则，可能包括常量折叠、使用 LEA 指令优化地址计算等。
    * **逻辑运算:** `ANDL`, `ANDQ`, `ORL`, `ORQ`, `XORL`, `XORQ`, `NOTL`, `NOTQ` 等的重写规则。
    * **位运算:** `SHLL`, `SHLQ`, `SARL`, `SARQ`, `ROLL`, `ROLQ`, `SHRL`, `SHRQ` 等的重写规则。
    * **比较运算:** `CMPB`, `CMPL`, `CMPQ`, `TESTB`, `TESTL`, `TESTQ` 以及条件设置指令 `SETA`, `SETB`, `SETEQ` 等的重写规则。
    * **数据移动:** `MOV`, `MOVB`, `MOVL`, `MOVQ`, `MOVSD`, `MOVSS` 等不同大小和类型的移动指令的重写规则，可能包括从内存加载或存储常量的优化。
    * **条件移动:** `CMOVLCC`, `CMOVQEQ` 等条件移动指令的重写规则。
    * **原子操作:** `CMPXCHGLlock`, `CMPXCHGQlock`, `XADDLlock`, `XADDQlock` 等原子操作的重写规则。
    * **类型转换:**  例如 `OpCvt32to64F` 转换为 `OpAMD64CVTSL2SD`。
    * **Go 语言的高级操作:** 将如 `OpAdd32`, `OpMul64`, `OpEqPtr` 等 Go 语言层面的操作转换为相应的 AMD64 指令。

4. **针对特定模式的优化:** 一些重写规则会识别特定的操作模式并进行优化，例如将 `ADD x, (MOVQconst c)` 转换为 `ADDQconst c, x`，或者使用 `LEA` 指令来优化某些加法和移位操作的组合。

**Go 语言功能实现推断 (示例):**

这个文件本身不直接实现一个特定的 Go 语言功能，而是 Go 语言编译过程中的一个关键步骤。但是，我们可以通过观察它处理的 Go 操作码来推断它参与了哪些 Go 语言功能的实现：

* **基本的算术和逻辑运算 (+, -, *, /, %, &, |, ^, <<, >>):**  `OpAdd32`, `OpMul64`, `OpAnd16`, `OpShl32x8` 等操作码的出现表明该文件负责将这些 Go 语言运算符转换为 AMD64 指令。

* **比较操作 (==, !=, <, <=, >, >=):** `OpEq32`, `OpLess64`, `OpLeqPtr` 等操作码的出现表明它负责将这些比较运算符转换为 AMD64 的比较指令和条件设置指令。

* **类型转换:** `OpCvt32to64`, `OpCvtFloat32ToFloat64` 等操作码的出现表明它负责处理 Go 语言中的类型转换操作。

* **内存访问 (读取和写入变量):** `OpLoad`, `OpStore`, `OpAtomicLoad32`, `OpAtomicStore64` 等操作码的出现表明它负责将 Go 语言的变量访问操作转换为 AMD64 的加载和存储指令。

* **函数调用:** `OpStaticCall`, `OpInterCall`, `OpClosureCall`, `OpTailCall` 的出现表明它负责处理 Go 语言中的各种函数调用方式。

**Go 代码举例说明 (假设):**

假设 Go 代码中有如下的加法操作：

```go
func add(a int32, b int32) int32 {
    return a + b
}
```

1. **输入 (SSA Value 的可能表示):** 在 SSA 中，`a + b` 可能会被表示为一个 `Value`，其 `Op` 可能是 `OpAdd32`，并包含操作数 `a` 和 `b`。

2. **`rewriteValueAMD64` 函数执行:** 当编译器处理到这个 `OpAdd32` 的 `Value` 时，会调用 `rewriteValueAMD64` 函数，并且 `v.Op` 将会是 `OpAdd32`。

3. **匹配 `case OpAdd32`:**  `switch` 语句会匹配到 `case OpAdd32:`。

4. **可能的重写规则:**  在这个 `case` 中，可能会有如下的重写规则：

   ```go
   case OpAdd32:
       v.Op = OpAMD64ADDL // 将 OpAdd32 转换为 AMD64 的 ADDL 指令
       return true
   ```

5. **输出 (SSA Value 的修改):**  `Value` 的 `Op` 会被修改为 `OpAMD64ADDL`，表示使用 AMD64 的 32 位加法指令。

**命令行参数的具体处理:**

这个代码片段本身并不直接处理命令行参数。命令行参数的处理发生在 Go 编译器的前端和主流程中。这个文件是编译器后端 SSA 优化和代码生成的一部分。

**使用者易犯错的点:**

作为开发者，通常不会直接与这个文件交互，因为它是编译器内部的实现细节。但是，如果你尝试理解或修改编译器的代码，可能会犯以下错误：

* **不熟悉 AMD64 指令集:**  错误地假设某个 Go 操作应该如何映射到 AMD64 指令。
* **忽略 SSA 的特性:**  例如，错误地修改了 SSA 值，破坏了 SSA 的静态单赋值特性。
* **对重写规则的副作用考虑不周:**  重写规则可能会影响后续的优化和代码生成阶段。
* **不了解指令的性能特性:**  可能选择了功能上正确但性能较差的指令。
* **没有充分测试修改后的编译器:** 修改编译器代码后，需要进行大量的测试以确保其正确性。

**总结一下它的功能:**

这是 Go 语言编译器中用于 AMD64 架构的 SSA 重写规则的一部分。它的主要功能是将 Go 语言的抽象操作转换为具体的 AMD64 机器指令操作，是代码生成过程中的关键步骤，负责将中间表示转化为目标架构的代码。 这部分代码涵盖了基础的算术、逻辑、位运算、比较和数据移动等操作的转换规则。

Prompt: 
```
这是路径为go/src/cmd/compile/internal/ssa/rewriteAMD64.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
这是第1部分，共12部分，请归纳一下它的功能

"""
// Code generated from _gen/AMD64.rules using 'go generate'; DO NOT EDIT.

package ssa

import "internal/buildcfg"
import "math"
import "cmd/internal/obj"
import "cmd/compile/internal/types"

func rewriteValueAMD64(v *Value) bool {
	switch v.Op {
	case OpAMD64ADCQ:
		return rewriteValueAMD64_OpAMD64ADCQ(v)
	case OpAMD64ADCQconst:
		return rewriteValueAMD64_OpAMD64ADCQconst(v)
	case OpAMD64ADDL:
		return rewriteValueAMD64_OpAMD64ADDL(v)
	case OpAMD64ADDLconst:
		return rewriteValueAMD64_OpAMD64ADDLconst(v)
	case OpAMD64ADDLconstmodify:
		return rewriteValueAMD64_OpAMD64ADDLconstmodify(v)
	case OpAMD64ADDLload:
		return rewriteValueAMD64_OpAMD64ADDLload(v)
	case OpAMD64ADDLmodify:
		return rewriteValueAMD64_OpAMD64ADDLmodify(v)
	case OpAMD64ADDQ:
		return rewriteValueAMD64_OpAMD64ADDQ(v)
	case OpAMD64ADDQcarry:
		return rewriteValueAMD64_OpAMD64ADDQcarry(v)
	case OpAMD64ADDQconst:
		return rewriteValueAMD64_OpAMD64ADDQconst(v)
	case OpAMD64ADDQconstmodify:
		return rewriteValueAMD64_OpAMD64ADDQconstmodify(v)
	case OpAMD64ADDQload:
		return rewriteValueAMD64_OpAMD64ADDQload(v)
	case OpAMD64ADDQmodify:
		return rewriteValueAMD64_OpAMD64ADDQmodify(v)
	case OpAMD64ADDSD:
		return rewriteValueAMD64_OpAMD64ADDSD(v)
	case OpAMD64ADDSDload:
		return rewriteValueAMD64_OpAMD64ADDSDload(v)
	case OpAMD64ADDSS:
		return rewriteValueAMD64_OpAMD64ADDSS(v)
	case OpAMD64ADDSSload:
		return rewriteValueAMD64_OpAMD64ADDSSload(v)
	case OpAMD64ANDL:
		return rewriteValueAMD64_OpAMD64ANDL(v)
	case OpAMD64ANDLconst:
		return rewriteValueAMD64_OpAMD64ANDLconst(v)
	case OpAMD64ANDLconstmodify:
		return rewriteValueAMD64_OpAMD64ANDLconstmodify(v)
	case OpAMD64ANDLload:
		return rewriteValueAMD64_OpAMD64ANDLload(v)
	case OpAMD64ANDLmodify:
		return rewriteValueAMD64_OpAMD64ANDLmodify(v)
	case OpAMD64ANDNL:
		return rewriteValueAMD64_OpAMD64ANDNL(v)
	case OpAMD64ANDNQ:
		return rewriteValueAMD64_OpAMD64ANDNQ(v)
	case OpAMD64ANDQ:
		return rewriteValueAMD64_OpAMD64ANDQ(v)
	case OpAMD64ANDQconst:
		return rewriteValueAMD64_OpAMD64ANDQconst(v)
	case OpAMD64ANDQconstmodify:
		return rewriteValueAMD64_OpAMD64ANDQconstmodify(v)
	case OpAMD64ANDQload:
		return rewriteValueAMD64_OpAMD64ANDQload(v)
	case OpAMD64ANDQmodify:
		return rewriteValueAMD64_OpAMD64ANDQmodify(v)
	case OpAMD64BSFQ:
		return rewriteValueAMD64_OpAMD64BSFQ(v)
	case OpAMD64BSWAPL:
		return rewriteValueAMD64_OpAMD64BSWAPL(v)
	case OpAMD64BSWAPQ:
		return rewriteValueAMD64_OpAMD64BSWAPQ(v)
	case OpAMD64BTCQconst:
		return rewriteValueAMD64_OpAMD64BTCQconst(v)
	case OpAMD64BTLconst:
		return rewriteValueAMD64_OpAMD64BTLconst(v)
	case OpAMD64BTQconst:
		return rewriteValueAMD64_OpAMD64BTQconst(v)
	case OpAMD64BTRQconst:
		return rewriteValueAMD64_OpAMD64BTRQconst(v)
	case OpAMD64BTSQconst:
		return rewriteValueAMD64_OpAMD64BTSQconst(v)
	case OpAMD64CMOVLCC:
		return rewriteValueAMD64_OpAMD64CMOVLCC(v)
	case OpAMD64CMOVLCS:
		return rewriteValueAMD64_OpAMD64CMOVLCS(v)
	case OpAMD64CMOVLEQ:
		return rewriteValueAMD64_OpAMD64CMOVLEQ(v)
	case OpAMD64CMOVLGE:
		return rewriteValueAMD64_OpAMD64CMOVLGE(v)
	case OpAMD64CMOVLGT:
		return rewriteValueAMD64_OpAMD64CMOVLGT(v)
	case OpAMD64CMOVLHI:
		return rewriteValueAMD64_OpAMD64CMOVLHI(v)
	case OpAMD64CMOVLLE:
		return rewriteValueAMD64_OpAMD64CMOVLLE(v)
	case OpAMD64CMOVLLS:
		return rewriteValueAMD64_OpAMD64CMOVLLS(v)
	case OpAMD64CMOVLLT:
		return rewriteValueAMD64_OpAMD64CMOVLLT(v)
	case OpAMD64CMOVLNE:
		return rewriteValueAMD64_OpAMD64CMOVLNE(v)
	case OpAMD64CMOVQCC:
		return rewriteValueAMD64_OpAMD64CMOVQCC(v)
	case OpAMD64CMOVQCS:
		return rewriteValueAMD64_OpAMD64CMOVQCS(v)
	case OpAMD64CMOVQEQ:
		return rewriteValueAMD64_OpAMD64CMOVQEQ(v)
	case OpAMD64CMOVQGE:
		return rewriteValueAMD64_OpAMD64CMOVQGE(v)
	case OpAMD64CMOVQGT:
		return rewriteValueAMD64_OpAMD64CMOVQGT(v)
	case OpAMD64CMOVQHI:
		return rewriteValueAMD64_OpAMD64CMOVQHI(v)
	case OpAMD64CMOVQLE:
		return rewriteValueAMD64_OpAMD64CMOVQLE(v)
	case OpAMD64CMOVQLS:
		return rewriteValueAMD64_OpAMD64CMOVQLS(v)
	case OpAMD64CMOVQLT:
		return rewriteValueAMD64_OpAMD64CMOVQLT(v)
	case OpAMD64CMOVQNE:
		return rewriteValueAMD64_OpAMD64CMOVQNE(v)
	case OpAMD64CMOVWCC:
		return rewriteValueAMD64_OpAMD64CMOVWCC(v)
	case OpAMD64CMOVWCS:
		return rewriteValueAMD64_OpAMD64CMOVWCS(v)
	case OpAMD64CMOVWEQ:
		return rewriteValueAMD64_OpAMD64CMOVWEQ(v)
	case OpAMD64CMOVWGE:
		return rewriteValueAMD64_OpAMD64CMOVWGE(v)
	case OpAMD64CMOVWGT:
		return rewriteValueAMD64_OpAMD64CMOVWGT(v)
	case OpAMD64CMOVWHI:
		return rewriteValueAMD64_OpAMD64CMOVWHI(v)
	case OpAMD64CMOVWLE:
		return rewriteValueAMD64_OpAMD64CMOVWLE(v)
	case OpAMD64CMOVWLS:
		return rewriteValueAMD64_OpAMD64CMOVWLS(v)
	case OpAMD64CMOVWLT:
		return rewriteValueAMD64_OpAMD64CMOVWLT(v)
	case OpAMD64CMOVWNE:
		return rewriteValueAMD64_OpAMD64CMOVWNE(v)
	case OpAMD64CMPB:
		return rewriteValueAMD64_OpAMD64CMPB(v)
	case OpAMD64CMPBconst:
		return rewriteValueAMD64_OpAMD64CMPBconst(v)
	case OpAMD64CMPBconstload:
		return rewriteValueAMD64_OpAMD64CMPBconstload(v)
	case OpAMD64CMPBload:
		return rewriteValueAMD64_OpAMD64CMPBload(v)
	case OpAMD64CMPL:
		return rewriteValueAMD64_OpAMD64CMPL(v)
	case OpAMD64CMPLconst:
		return rewriteValueAMD64_OpAMD64CMPLconst(v)
	case OpAMD64CMPLconstload:
		return rewriteValueAMD64_OpAMD64CMPLconstload(v)
	case OpAMD64CMPLload:
		return rewriteValueAMD64_OpAMD64CMPLload(v)
	case OpAMD64CMPQ:
		return rewriteValueAMD64_OpAMD64CMPQ(v)
	case OpAMD64CMPQconst:
		return rewriteValueAMD64_OpAMD64CMPQconst(v)
	case OpAMD64CMPQconstload:
		return rewriteValueAMD64_OpAMD64CMPQconstload(v)
	case OpAMD64CMPQload:
		return rewriteValueAMD64_OpAMD64CMPQload(v)
	case OpAMD64CMPW:
		return rewriteValueAMD64_OpAMD64CMPW(v)
	case OpAMD64CMPWconst:
		return rewriteValueAMD64_OpAMD64CMPWconst(v)
	case OpAMD64CMPWconstload:
		return rewriteValueAMD64_OpAMD64CMPWconstload(v)
	case OpAMD64CMPWload:
		return rewriteValueAMD64_OpAMD64CMPWload(v)
	case OpAMD64CMPXCHGLlock:
		return rewriteValueAMD64_OpAMD64CMPXCHGLlock(v)
	case OpAMD64CMPXCHGQlock:
		return rewriteValueAMD64_OpAMD64CMPXCHGQlock(v)
	case OpAMD64DIVSD:
		return rewriteValueAMD64_OpAMD64DIVSD(v)
	case OpAMD64DIVSDload:
		return rewriteValueAMD64_OpAMD64DIVSDload(v)
	case OpAMD64DIVSS:
		return rewriteValueAMD64_OpAMD64DIVSS(v)
	case OpAMD64DIVSSload:
		return rewriteValueAMD64_OpAMD64DIVSSload(v)
	case OpAMD64HMULL:
		return rewriteValueAMD64_OpAMD64HMULL(v)
	case OpAMD64HMULLU:
		return rewriteValueAMD64_OpAMD64HMULLU(v)
	case OpAMD64HMULQ:
		return rewriteValueAMD64_OpAMD64HMULQ(v)
	case OpAMD64HMULQU:
		return rewriteValueAMD64_OpAMD64HMULQU(v)
	case OpAMD64LEAL:
		return rewriteValueAMD64_OpAMD64LEAL(v)
	case OpAMD64LEAL1:
		return rewriteValueAMD64_OpAMD64LEAL1(v)
	case OpAMD64LEAL2:
		return rewriteValueAMD64_OpAMD64LEAL2(v)
	case OpAMD64LEAL4:
		return rewriteValueAMD64_OpAMD64LEAL4(v)
	case OpAMD64LEAL8:
		return rewriteValueAMD64_OpAMD64LEAL8(v)
	case OpAMD64LEAQ:
		return rewriteValueAMD64_OpAMD64LEAQ(v)
	case OpAMD64LEAQ1:
		return rewriteValueAMD64_OpAMD64LEAQ1(v)
	case OpAMD64LEAQ2:
		return rewriteValueAMD64_OpAMD64LEAQ2(v)
	case OpAMD64LEAQ4:
		return rewriteValueAMD64_OpAMD64LEAQ4(v)
	case OpAMD64LEAQ8:
		return rewriteValueAMD64_OpAMD64LEAQ8(v)
	case OpAMD64MOVBELstore:
		return rewriteValueAMD64_OpAMD64MOVBELstore(v)
	case OpAMD64MOVBEQstore:
		return rewriteValueAMD64_OpAMD64MOVBEQstore(v)
	case OpAMD64MOVBEWstore:
		return rewriteValueAMD64_OpAMD64MOVBEWstore(v)
	case OpAMD64MOVBQSX:
		return rewriteValueAMD64_OpAMD64MOVBQSX(v)
	case OpAMD64MOVBQSXload:
		return rewriteValueAMD64_OpAMD64MOVBQSXload(v)
	case OpAMD64MOVBQZX:
		return rewriteValueAMD64_OpAMD64MOVBQZX(v)
	case OpAMD64MOVBatomicload:
		return rewriteValueAMD64_OpAMD64MOVBatomicload(v)
	case OpAMD64MOVBload:
		return rewriteValueAMD64_OpAMD64MOVBload(v)
	case OpAMD64MOVBstore:
		return rewriteValueAMD64_OpAMD64MOVBstore(v)
	case OpAMD64MOVBstoreconst:
		return rewriteValueAMD64_OpAMD64MOVBstoreconst(v)
	case OpAMD64MOVLQSX:
		return rewriteValueAMD64_OpAMD64MOVLQSX(v)
	case OpAMD64MOVLQSXload:
		return rewriteValueAMD64_OpAMD64MOVLQSXload(v)
	case OpAMD64MOVLQZX:
		return rewriteValueAMD64_OpAMD64MOVLQZX(v)
	case OpAMD64MOVLatomicload:
		return rewriteValueAMD64_OpAMD64MOVLatomicload(v)
	case OpAMD64MOVLf2i:
		return rewriteValueAMD64_OpAMD64MOVLf2i(v)
	case OpAMD64MOVLi2f:
		return rewriteValueAMD64_OpAMD64MOVLi2f(v)
	case OpAMD64MOVLload:
		return rewriteValueAMD64_OpAMD64MOVLload(v)
	case OpAMD64MOVLstore:
		return rewriteValueAMD64_OpAMD64MOVLstore(v)
	case OpAMD64MOVLstoreconst:
		return rewriteValueAMD64_OpAMD64MOVLstoreconst(v)
	case OpAMD64MOVOload:
		return rewriteValueAMD64_OpAMD64MOVOload(v)
	case OpAMD64MOVOstore:
		return rewriteValueAMD64_OpAMD64MOVOstore(v)
	case OpAMD64MOVOstoreconst:
		return rewriteValueAMD64_OpAMD64MOVOstoreconst(v)
	case OpAMD64MOVQatomicload:
		return rewriteValueAMD64_OpAMD64MOVQatomicload(v)
	case OpAMD64MOVQf2i:
		return rewriteValueAMD64_OpAMD64MOVQf2i(v)
	case OpAMD64MOVQi2f:
		return rewriteValueAMD64_OpAMD64MOVQi2f(v)
	case OpAMD64MOVQload:
		return rewriteValueAMD64_OpAMD64MOVQload(v)
	case OpAMD64MOVQstore:
		return rewriteValueAMD64_OpAMD64MOVQstore(v)
	case OpAMD64MOVQstoreconst:
		return rewriteValueAMD64_OpAMD64MOVQstoreconst(v)
	case OpAMD64MOVSDload:
		return rewriteValueAMD64_OpAMD64MOVSDload(v)
	case OpAMD64MOVSDstore:
		return rewriteValueAMD64_OpAMD64MOVSDstore(v)
	case OpAMD64MOVSSload:
		return rewriteValueAMD64_OpAMD64MOVSSload(v)
	case OpAMD64MOVSSstore:
		return rewriteValueAMD64_OpAMD64MOVSSstore(v)
	case OpAMD64MOVWQSX:
		return rewriteValueAMD64_OpAMD64MOVWQSX(v)
	case OpAMD64MOVWQSXload:
		return rewriteValueAMD64_OpAMD64MOVWQSXload(v)
	case OpAMD64MOVWQZX:
		return rewriteValueAMD64_OpAMD64MOVWQZX(v)
	case OpAMD64MOVWload:
		return rewriteValueAMD64_OpAMD64MOVWload(v)
	case OpAMD64MOVWstore:
		return rewriteValueAMD64_OpAMD64MOVWstore(v)
	case OpAMD64MOVWstoreconst:
		return rewriteValueAMD64_OpAMD64MOVWstoreconst(v)
	case OpAMD64MULL:
		return rewriteValueAMD64_OpAMD64MULL(v)
	case OpAMD64MULLconst:
		return rewriteValueAMD64_OpAMD64MULLconst(v)
	case OpAMD64MULQ:
		return rewriteValueAMD64_OpAMD64MULQ(v)
	case OpAMD64MULQconst:
		return rewriteValueAMD64_OpAMD64MULQconst(v)
	case OpAMD64MULSD:
		return rewriteValueAMD64_OpAMD64MULSD(v)
	case OpAMD64MULSDload:
		return rewriteValueAMD64_OpAMD64MULSDload(v)
	case OpAMD64MULSS:
		return rewriteValueAMD64_OpAMD64MULSS(v)
	case OpAMD64MULSSload:
		return rewriteValueAMD64_OpAMD64MULSSload(v)
	case OpAMD64NEGL:
		return rewriteValueAMD64_OpAMD64NEGL(v)
	case OpAMD64NEGQ:
		return rewriteValueAMD64_OpAMD64NEGQ(v)
	case OpAMD64NOTL:
		return rewriteValueAMD64_OpAMD64NOTL(v)
	case OpAMD64NOTQ:
		return rewriteValueAMD64_OpAMD64NOTQ(v)
	case OpAMD64ORL:
		return rewriteValueAMD64_OpAMD64ORL(v)
	case OpAMD64ORLconst:
		return rewriteValueAMD64_OpAMD64ORLconst(v)
	case OpAMD64ORLconstmodify:
		return rewriteValueAMD64_OpAMD64ORLconstmodify(v)
	case OpAMD64ORLload:
		return rewriteValueAMD64_OpAMD64ORLload(v)
	case OpAMD64ORLmodify:
		return rewriteValueAMD64_OpAMD64ORLmodify(v)
	case OpAMD64ORQ:
		return rewriteValueAMD64_OpAMD64ORQ(v)
	case OpAMD64ORQconst:
		return rewriteValueAMD64_OpAMD64ORQconst(v)
	case OpAMD64ORQconstmodify:
		return rewriteValueAMD64_OpAMD64ORQconstmodify(v)
	case OpAMD64ORQload:
		return rewriteValueAMD64_OpAMD64ORQload(v)
	case OpAMD64ORQmodify:
		return rewriteValueAMD64_OpAMD64ORQmodify(v)
	case OpAMD64ROLB:
		return rewriteValueAMD64_OpAMD64ROLB(v)
	case OpAMD64ROLBconst:
		return rewriteValueAMD64_OpAMD64ROLBconst(v)
	case OpAMD64ROLL:
		return rewriteValueAMD64_OpAMD64ROLL(v)
	case OpAMD64ROLLconst:
		return rewriteValueAMD64_OpAMD64ROLLconst(v)
	case OpAMD64ROLQ:
		return rewriteValueAMD64_OpAMD64ROLQ(v)
	case OpAMD64ROLQconst:
		return rewriteValueAMD64_OpAMD64ROLQconst(v)
	case OpAMD64ROLW:
		return rewriteValueAMD64_OpAMD64ROLW(v)
	case OpAMD64ROLWconst:
		return rewriteValueAMD64_OpAMD64ROLWconst(v)
	case OpAMD64RORB:
		return rewriteValueAMD64_OpAMD64RORB(v)
	case OpAMD64RORL:
		return rewriteValueAMD64_OpAMD64RORL(v)
	case OpAMD64RORQ:
		return rewriteValueAMD64_OpAMD64RORQ(v)
	case OpAMD64RORW:
		return rewriteValueAMD64_OpAMD64RORW(v)
	case OpAMD64SARB:
		return rewriteValueAMD64_OpAMD64SARB(v)
	case OpAMD64SARBconst:
		return rewriteValueAMD64_OpAMD64SARBconst(v)
	case OpAMD64SARL:
		return rewriteValueAMD64_OpAMD64SARL(v)
	case OpAMD64SARLconst:
		return rewriteValueAMD64_OpAMD64SARLconst(v)
	case OpAMD64SARQ:
		return rewriteValueAMD64_OpAMD64SARQ(v)
	case OpAMD64SARQconst:
		return rewriteValueAMD64_OpAMD64SARQconst(v)
	case OpAMD64SARW:
		return rewriteValueAMD64_OpAMD64SARW(v)
	case OpAMD64SARWconst:
		return rewriteValueAMD64_OpAMD64SARWconst(v)
	case OpAMD64SARXLload:
		return rewriteValueAMD64_OpAMD64SARXLload(v)
	case OpAMD64SARXQload:
		return rewriteValueAMD64_OpAMD64SARXQload(v)
	case OpAMD64SBBLcarrymask:
		return rewriteValueAMD64_OpAMD64SBBLcarrymask(v)
	case OpAMD64SBBQ:
		return rewriteValueAMD64_OpAMD64SBBQ(v)
	case OpAMD64SBBQcarrymask:
		return rewriteValueAMD64_OpAMD64SBBQcarrymask(v)
	case OpAMD64SBBQconst:
		return rewriteValueAMD64_OpAMD64SBBQconst(v)
	case OpAMD64SETA:
		return rewriteValueAMD64_OpAMD64SETA(v)
	case OpAMD64SETAE:
		return rewriteValueAMD64_OpAMD64SETAE(v)
	case OpAMD64SETAEstore:
		return rewriteValueAMD64_OpAMD64SETAEstore(v)
	case OpAMD64SETAstore:
		return rewriteValueAMD64_OpAMD64SETAstore(v)
	case OpAMD64SETB:
		return rewriteValueAMD64_OpAMD64SETB(v)
	case OpAMD64SETBE:
		return rewriteValueAMD64_OpAMD64SETBE(v)
	case OpAMD64SETBEstore:
		return rewriteValueAMD64_OpAMD64SETBEstore(v)
	case OpAMD64SETBstore:
		return rewriteValueAMD64_OpAMD64SETBstore(v)
	case OpAMD64SETEQ:
		return rewriteValueAMD64_OpAMD64SETEQ(v)
	case OpAMD64SETEQstore:
		return rewriteValueAMD64_OpAMD64SETEQstore(v)
	case OpAMD64SETG:
		return rewriteValueAMD64_OpAMD64SETG(v)
	case OpAMD64SETGE:
		return rewriteValueAMD64_OpAMD64SETGE(v)
	case OpAMD64SETGEstore:
		return rewriteValueAMD64_OpAMD64SETGEstore(v)
	case OpAMD64SETGstore:
		return rewriteValueAMD64_OpAMD64SETGstore(v)
	case OpAMD64SETL:
		return rewriteValueAMD64_OpAMD64SETL(v)
	case OpAMD64SETLE:
		return rewriteValueAMD64_OpAMD64SETLE(v)
	case OpAMD64SETLEstore:
		return rewriteValueAMD64_OpAMD64SETLEstore(v)
	case OpAMD64SETLstore:
		return rewriteValueAMD64_OpAMD64SETLstore(v)
	case OpAMD64SETNE:
		return rewriteValueAMD64_OpAMD64SETNE(v)
	case OpAMD64SETNEstore:
		return rewriteValueAMD64_OpAMD64SETNEstore(v)
	case OpAMD64SHLL:
		return rewriteValueAMD64_OpAMD64SHLL(v)
	case OpAMD64SHLLconst:
		return rewriteValueAMD64_OpAMD64SHLLconst(v)
	case OpAMD64SHLQ:
		return rewriteValueAMD64_OpAMD64SHLQ(v)
	case OpAMD64SHLQconst:
		return rewriteValueAMD64_OpAMD64SHLQconst(v)
	case OpAMD64SHLXLload:
		return rewriteValueAMD64_OpAMD64SHLXLload(v)
	case OpAMD64SHLXQload:
		return rewriteValueAMD64_OpAMD64SHLXQload(v)
	case OpAMD64SHRB:
		return rewriteValueAMD64_OpAMD64SHRB(v)
	case OpAMD64SHRBconst:
		return rewriteValueAMD64_OpAMD64SHRBconst(v)
	case OpAMD64SHRL:
		return rewriteValueAMD64_OpAMD64SHRL(v)
	case OpAMD64SHRLconst:
		return rewriteValueAMD64_OpAMD64SHRLconst(v)
	case OpAMD64SHRQ:
		return rewriteValueAMD64_OpAMD64SHRQ(v)
	case OpAMD64SHRQconst:
		return rewriteValueAMD64_OpAMD64SHRQconst(v)
	case OpAMD64SHRW:
		return rewriteValueAMD64_OpAMD64SHRW(v)
	case OpAMD64SHRWconst:
		return rewriteValueAMD64_OpAMD64SHRWconst(v)
	case OpAMD64SHRXLload:
		return rewriteValueAMD64_OpAMD64SHRXLload(v)
	case OpAMD64SHRXQload:
		return rewriteValueAMD64_OpAMD64SHRXQload(v)
	case OpAMD64SUBL:
		return rewriteValueAMD64_OpAMD64SUBL(v)
	case OpAMD64SUBLconst:
		return rewriteValueAMD64_OpAMD64SUBLconst(v)
	case OpAMD64SUBLload:
		return rewriteValueAMD64_OpAMD64SUBLload(v)
	case OpAMD64SUBLmodify:
		return rewriteValueAMD64_OpAMD64SUBLmodify(v)
	case OpAMD64SUBQ:
		return rewriteValueAMD64_OpAMD64SUBQ(v)
	case OpAMD64SUBQborrow:
		return rewriteValueAMD64_OpAMD64SUBQborrow(v)
	case OpAMD64SUBQconst:
		return rewriteValueAMD64_OpAMD64SUBQconst(v)
	case OpAMD64SUBQload:
		return rewriteValueAMD64_OpAMD64SUBQload(v)
	case OpAMD64SUBQmodify:
		return rewriteValueAMD64_OpAMD64SUBQmodify(v)
	case OpAMD64SUBSD:
		return rewriteValueAMD64_OpAMD64SUBSD(v)
	case OpAMD64SUBSDload:
		return rewriteValueAMD64_OpAMD64SUBSDload(v)
	case OpAMD64SUBSS:
		return rewriteValueAMD64_OpAMD64SUBSS(v)
	case OpAMD64SUBSSload:
		return rewriteValueAMD64_OpAMD64SUBSSload(v)
	case OpAMD64TESTB:
		return rewriteValueAMD64_OpAMD64TESTB(v)
	case OpAMD64TESTBconst:
		return rewriteValueAMD64_OpAMD64TESTBconst(v)
	case OpAMD64TESTL:
		return rewriteValueAMD64_OpAMD64TESTL(v)
	case OpAMD64TESTLconst:
		return rewriteValueAMD64_OpAMD64TESTLconst(v)
	case OpAMD64TESTQ:
		return rewriteValueAMD64_OpAMD64TESTQ(v)
	case OpAMD64TESTQconst:
		return rewriteValueAMD64_OpAMD64TESTQconst(v)
	case OpAMD64TESTW:
		return rewriteValueAMD64_OpAMD64TESTW(v)
	case OpAMD64TESTWconst:
		return rewriteValueAMD64_OpAMD64TESTWconst(v)
	case OpAMD64XADDLlock:
		return rewriteValueAMD64_OpAMD64XADDLlock(v)
	case OpAMD64XADDQlock:
		return rewriteValueAMD64_OpAMD64XADDQlock(v)
	case OpAMD64XCHGL:
		return rewriteValueAMD64_OpAMD64XCHGL(v)
	case OpAMD64XCHGQ:
		return rewriteValueAMD64_OpAMD64XCHGQ(v)
	case OpAMD64XORL:
		return rewriteValueAMD64_OpAMD64XORL(v)
	case OpAMD64XORLconst:
		return rewriteValueAMD64_OpAMD64XORLconst(v)
	case OpAMD64XORLconstmodify:
		return rewriteValueAMD64_OpAMD64XORLconstmodify(v)
	case OpAMD64XORLload:
		return rewriteValueAMD64_OpAMD64XORLload(v)
	case OpAMD64XORLmodify:
		return rewriteValueAMD64_OpAMD64XORLmodify(v)
	case OpAMD64XORQ:
		return rewriteValueAMD64_OpAMD64XORQ(v)
	case OpAMD64XORQconst:
		return rewriteValueAMD64_OpAMD64XORQconst(v)
	case OpAMD64XORQconstmodify:
		return rewriteValueAMD64_OpAMD64XORQconstmodify(v)
	case OpAMD64XORQload:
		return rewriteValueAMD64_OpAMD64XORQload(v)
	case OpAMD64XORQmodify:
		return rewriteValueAMD64_OpAMD64XORQmodify(v)
	case OpAdd16:
		v.Op = OpAMD64ADDL
		return true
	case OpAdd32:
		v.Op = OpAMD64ADDL
		return true
	case OpAdd32F:
		v.Op = OpAMD64ADDSS
		return true
	case OpAdd64:
		v.Op = OpAMD64ADDQ
		return true
	case OpAdd64F:
		v.Op = OpAMD64ADDSD
		return true
	case OpAdd8:
		v.Op = OpAMD64ADDL
		return true
	case OpAddPtr:
		v.Op = OpAMD64ADDQ
		return true
	case OpAddr:
		return rewriteValueAMD64_OpAddr(v)
	case OpAnd16:
		v.Op = OpAMD64ANDL
		return true
	case OpAnd32:
		v.Op = OpAMD64ANDL
		return true
	case OpAnd64:
		v.Op = OpAMD64ANDQ
		return true
	case OpAnd8:
		v.Op = OpAMD64ANDL
		return true
	case OpAndB:
		v.Op = OpAMD64ANDL
		return true
	case OpAtomicAdd32:
		return rewriteValueAMD64_OpAtomicAdd32(v)
	case OpAtomicAdd64:
		return rewriteValueAMD64_OpAtomicAdd64(v)
	case OpAtomicAnd32:
		return rewriteValueAMD64_OpAtomicAnd32(v)
	case OpAtomicAnd32value:
		return rewriteValueAMD64_OpAtomicAnd32value(v)
	case OpAtomicAnd64value:
		return rewriteValueAMD64_OpAtomicAnd64value(v)
	case OpAtomicAnd8:
		return rewriteValueAMD64_OpAtomicAnd8(v)
	case OpAtomicCompareAndSwap32:
		return rewriteValueAMD64_OpAtomicCompareAndSwap32(v)
	case OpAtomicCompareAndSwap64:
		return rewriteValueAMD64_OpAtomicCompareAndSwap64(v)
	case OpAtomicExchange32:
		return rewriteValueAMD64_OpAtomicExchange32(v)
	case OpAtomicExchange64:
		return rewriteValueAMD64_OpAtomicExchange64(v)
	case OpAtomicExchange8:
		return rewriteValueAMD64_OpAtomicExchange8(v)
	case OpAtomicLoad32:
		return rewriteValueAMD64_OpAtomicLoad32(v)
	case OpAtomicLoad64:
		return rewriteValueAMD64_OpAtomicLoad64(v)
	case OpAtomicLoad8:
		return rewriteValueAMD64_OpAtomicLoad8(v)
	case OpAtomicLoadPtr:
		return rewriteValueAMD64_OpAtomicLoadPtr(v)
	case OpAtomicOr32:
		return rewriteValueAMD64_OpAtomicOr32(v)
	case OpAtomicOr32value:
		return rewriteValueAMD64_OpAtomicOr32value(v)
	case OpAtomicOr64value:
		return rewriteValueAMD64_OpAtomicOr64value(v)
	case OpAtomicOr8:
		return rewriteValueAMD64_OpAtomicOr8(v)
	case OpAtomicStore32:
		return rewriteValueAMD64_OpAtomicStore32(v)
	case OpAtomicStore64:
		return rewriteValueAMD64_OpAtomicStore64(v)
	case OpAtomicStore8:
		return rewriteValueAMD64_OpAtomicStore8(v)
	case OpAtomicStorePtrNoWB:
		return rewriteValueAMD64_OpAtomicStorePtrNoWB(v)
	case OpAvg64u:
		v.Op = OpAMD64AVGQU
		return true
	case OpBitLen16:
		return rewriteValueAMD64_OpBitLen16(v)
	case OpBitLen32:
		return rewriteValueAMD64_OpBitLen32(v)
	case OpBitLen64:
		return rewriteValueAMD64_OpBitLen64(v)
	case OpBitLen8:
		return rewriteValueAMD64_OpBitLen8(v)
	case OpBswap16:
		return rewriteValueAMD64_OpBswap16(v)
	case OpBswap32:
		v.Op = OpAMD64BSWAPL
		return true
	case OpBswap64:
		v.Op = OpAMD64BSWAPQ
		return true
	case OpCeil:
		return rewriteValueAMD64_OpCeil(v)
	case OpClosureCall:
		v.Op = OpAMD64CALLclosure
		return true
	case OpCom16:
		v.Op = OpAMD64NOTL
		return true
	case OpCom32:
		v.Op = OpAMD64NOTL
		return true
	case OpCom64:
		v.Op = OpAMD64NOTQ
		return true
	case OpCom8:
		v.Op = OpAMD64NOTL
		return true
	case OpCondSelect:
		return rewriteValueAMD64_OpCondSelect(v)
	case OpConst16:
		return rewriteValueAMD64_OpConst16(v)
	case OpConst32:
		v.Op = OpAMD64MOVLconst
		return true
	case OpConst32F:
		v.Op = OpAMD64MOVSSconst
		return true
	case OpConst64:
		v.Op = OpAMD64MOVQconst
		return true
	case OpConst64F:
		v.Op = OpAMD64MOVSDconst
		return true
	case OpConst8:
		return rewriteValueAMD64_OpConst8(v)
	case OpConstBool:
		return rewriteValueAMD64_OpConstBool(v)
	case OpConstNil:
		return rewriteValueAMD64_OpConstNil(v)
	case OpCtz16:
		return rewriteValueAMD64_OpCtz16(v)
	case OpCtz16NonZero:
		return rewriteValueAMD64_OpCtz16NonZero(v)
	case OpCtz32:
		return rewriteValueAMD64_OpCtz32(v)
	case OpCtz32NonZero:
		return rewriteValueAMD64_OpCtz32NonZero(v)
	case OpCtz64:
		return rewriteValueAMD64_OpCtz64(v)
	case OpCtz64NonZero:
		return rewriteValueAMD64_OpCtz64NonZero(v)
	case OpCtz8:
		return rewriteValueAMD64_OpCtz8(v)
	case OpCtz8NonZero:
		return rewriteValueAMD64_OpCtz8NonZero(v)
	case OpCvt32Fto32:
		v.Op = OpAMD64CVTTSS2SL
		return true
	case OpCvt32Fto64:
		v.Op = OpAMD64CVTTSS2SQ
		return true
	case OpCvt32Fto64F:
		v.Op = OpAMD64CVTSS2SD
		return true
	case OpCvt32to32F:
		v.Op = OpAMD64CVTSL2SS
		return true
	case OpCvt32to64F:
		v.Op = OpAMD64CVTSL2SD
		return true
	case OpCvt64Fto32:
		v.Op = OpAMD64CVTTSD2SL
		return true
	case OpCvt64Fto32F:
		v.Op = OpAMD64CVTSD2SS
		return true
	case OpCvt64Fto64:
		v.Op = OpAMD64CVTTSD2SQ
		return true
	case OpCvt64to32F:
		v.Op = OpAMD64CVTSQ2SS
		return true
	case OpCvt64to64F:
		v.Op = OpAMD64CVTSQ2SD
		return true
	case OpCvtBoolToUint8:
		v.Op = OpCopy
		return true
	case OpDiv128u:
		v.Op = OpAMD64DIVQU2
		return true
	case OpDiv16:
		return rewriteValueAMD64_OpDiv16(v)
	case OpDiv16u:
		return rewriteValueAMD64_OpDiv16u(v)
	case OpDiv32:
		return rewriteValueAMD64_OpDiv32(v)
	case OpDiv32F:
		v.Op = OpAMD64DIVSS
		return true
	case OpDiv32u:
		return rewriteValueAMD64_OpDiv32u(v)
	case OpDiv64:
		return rewriteValueAMD64_OpDiv64(v)
	case OpDiv64F:
		v.Op = OpAMD64DIVSD
		return true
	case OpDiv64u:
		return rewriteValueAMD64_OpDiv64u(v)
	case OpDiv8:
		return rewriteValueAMD64_OpDiv8(v)
	case OpDiv8u:
		return rewriteValueAMD64_OpDiv8u(v)
	case OpEq16:
		return rewriteValueAMD64_OpEq16(v)
	case OpEq32:
		return rewriteValueAMD64_OpEq32(v)
	case OpEq32F:
		return rewriteValueAMD64_OpEq32F(v)
	case OpEq64:
		return rewriteValueAMD64_OpEq64(v)
	case OpEq64F:
		return rewriteValueAMD64_OpEq64F(v)
	case OpEq8:
		return rewriteValueAMD64_OpEq8(v)
	case OpEqB:
		return rewriteValueAMD64_OpEqB(v)
	case OpEqPtr:
		return rewriteValueAMD64_OpEqPtr(v)
	case OpFMA:
		return rewriteValueAMD64_OpFMA(v)
	case OpFloor:
		return rewriteValueAMD64_OpFloor(v)
	case OpGetCallerPC:
		v.Op = OpAMD64LoweredGetCallerPC
		return true
	case OpGetCallerSP:
		v.Op = OpAMD64LoweredGetCallerSP
		return true
	case OpGetClosurePtr:
		v.Op = OpAMD64LoweredGetClosurePtr
		return true
	case OpGetG:
		return rewriteValueAMD64_OpGetG(v)
	case OpHasCPUFeature:
		return rewriteValueAMD64_OpHasCPUFeature(v)
	case OpHmul32:
		v.Op = OpAMD64HMULL
		return true
	case OpHmul32u:
		v.Op = OpAMD64HMULLU
		return true
	case OpHmul64:
		v.Op = OpAMD64HMULQ
		return true
	case OpHmul64u:
		v.Op = OpAMD64HMULQU
		return true
	case OpInterCall:
		v.Op = OpAMD64CALLinter
		return true
	case OpIsInBounds:
		return rewriteValueAMD64_OpIsInBounds(v)
	case OpIsNonNil:
		return rewriteValueAMD64_OpIsNonNil(v)
	case OpIsSliceInBounds:
		return rewriteValueAMD64_OpIsSliceInBounds(v)
	case OpLeq16:
		return rewriteValueAMD64_OpLeq16(v)
	case OpLeq16U:
		return rewriteValueAMD64_OpLeq16U(v)
	case OpLeq32:
		return rewriteValueAMD64_OpLeq32(v)
	case OpLeq32F:
		return rewriteValueAMD64_OpLeq32F(v)
	case OpLeq32U:
		return rewriteValueAMD64_OpLeq32U(v)
	case OpLeq64:
		return rewriteValueAMD64_OpLeq64(v)
	case OpLeq64F:
		return rewriteValueAMD64_OpLeq64F(v)
	case OpLeq64U:
		return rewriteValueAMD64_OpLeq64U(v)
	case OpLeq8:
		return rewriteValueAMD64_OpLeq8(v)
	case OpLeq8U:
		return rewriteValueAMD64_OpLeq8U(v)
	case OpLess16:
		return rewriteValueAMD64_OpLess16(v)
	case OpLess16U:
		return rewriteValueAMD64_OpLess16U(v)
	case OpLess32:
		return rewriteValueAMD64_OpLess32(v)
	case OpLess32F:
		return rewriteValueAMD64_OpLess32F(v)
	case OpLess32U:
		return rewriteValueAMD64_OpLess32U(v)
	case OpLess64:
		return rewriteValueAMD64_OpLess64(v)
	case OpLess64F:
		return rewriteValueAMD64_OpLess64F(v)
	case OpLess64U:
		return rewriteValueAMD64_OpLess64U(v)
	case OpLess8:
		return rewriteValueAMD64_OpLess8(v)
	case OpLess8U:
		return rewriteValueAMD64_OpLess8U(v)
	case OpLoad:
		return rewriteValueAMD64_OpLoad(v)
	case OpLocalAddr:
		return rewriteValueAMD64_OpLocalAddr(v)
	case OpLsh16x16:
		return rewriteValueAMD64_OpLsh16x16(v)
	case OpLsh16x32:
		return rewriteValueAMD64_OpLsh16x32(v)
	case OpLsh16x64:
		return rewriteValueAMD64_OpLsh16x64(v)
	case OpLsh16x8:
		return rewriteValueAMD64_OpLsh16x8(v)
	case OpLsh32x16:
		return rewriteValueAMD64_OpLsh32x16(v)
	case OpLsh32x32:
		return rewriteValueAMD64_OpLsh32x32(v)
	case OpLsh32x64:
		return rewriteValueAMD64_OpLsh32x64(v)
	case OpLsh32x8:
		return rewriteValueAMD64_OpLsh32x8(v)
	case OpLsh64x16:
		return rewriteValueAMD64_OpLsh64x16(v)
	case OpLsh64x32:
		return rewriteValueAMD64_OpLsh64x32(v)
	case OpLsh64x64:
		return rewriteValueAMD64_OpLsh64x64(v)
	case OpLsh64x8:
		return rewriteValueAMD64_OpLsh64x8(v)
	case OpLsh8x16:
		return rewriteValueAMD64_OpLsh8x16(v)
	case OpLsh8x32:
		return rewriteValueAMD64_OpLsh8x32(v)
	case OpLsh8x64:
		return rewriteValueAMD64_OpLsh8x64(v)
	case OpLsh8x8:
		return rewriteValueAMD64_OpLsh8x8(v)
	case OpMax32F:
		return rewriteValueAMD64_OpMax32F(v)
	case OpMax64F:
		return rewriteValueAMD64_OpMax64F(v)
	case OpMin32F:
		return rewriteValueAMD64_OpMin32F(v)
	case OpMin64F:
		return rewriteValueAMD64_OpMin64F(v)
	case OpMod16:
		return rewriteValueAMD64_OpMod16(v)
	case OpMod16u:
		return rewriteValueAMD64_OpMod16u(v)
	case OpMod32:
		return rewriteValueAMD64_OpMod32(v)
	case OpMod32u:
		return rewriteValueAMD64_OpMod32u(v)
	case OpMod64:
		return rewriteValueAMD64_OpMod64(v)
	case OpMod64u:
		return rewriteValueAMD64_OpMod64u(v)
	case OpMod8:
		return rewriteValueAMD64_OpMod8(v)
	case OpMod8u:
		return rewriteValueAMD64_OpMod8u(v)
	case OpMove:
		return rewriteValueAMD64_OpMove(v)
	case OpMul16:
		v.Op = OpAMD64MULL
		return true
	case OpMul32:
		v.Op = OpAMD64MULL
		return true
	case OpMul32F:
		v.Op = OpAMD64MULSS
		return true
	case OpMul64:
		v.Op = OpAMD64MULQ
		return true
	case OpMul64F:
		v.Op = OpAMD64MULSD
		return true
	case OpMul64uhilo:
		v.Op = OpAMD64MULQU2
		return true
	case OpMul8:
		v.Op = OpAMD64MULL
		return true
	case OpNeg16:
		v.Op = OpAMD64NEGL
		return true
	case OpNeg32:
		v.Op = OpAMD64NEGL
		return true
	case OpNeg32F:
		return rewriteValueAMD64_OpNeg32F(v)
	case OpNeg64:
		v.Op = OpAMD64NEGQ
		return true
	case OpNeg64F:
		return rewriteValueAMD64_OpNeg64F(v)
	case OpNeg8:
		v.Op = OpAMD64NEGL
		return true
	case OpNeq16:
		return rewriteValueAMD64_OpNeq16(v)
	case OpNeq32:
		return rewriteValueAMD64_OpNeq32(v)
	case OpNeq32F:
		return rewriteValueAMD64_OpNeq32F(v)
	case OpNeq64:
		return rewriteValueAMD64_OpNeq64(v)
	case OpNeq64F:
		return rewriteValueAMD64_OpNeq64F(v)
	case OpNeq8:
		return rewriteValueAMD64_OpNeq8(v)
	case OpNeqB:
		return rewriteValueAMD64_OpNeqB(v)
	case OpNeqPtr:
		return rewriteValueAMD64_OpNeqPtr(v)
	case OpNilCheck:
		v.Op = OpAMD64LoweredNilCheck
		return true
	case OpNot:
		return rewriteValueAMD64_OpNot(v)
	case OpOffPtr:
		return rewriteValueAMD64_OpOffPtr(v)
	case OpOr16:
		v.Op = OpAMD64ORL
		return true
	case OpOr32:
		v.Op = OpAMD64ORL
		return true
	case OpOr64:
		v.Op = OpAMD64ORQ
		return true
	case OpOr8:
		v.Op = OpAMD64ORL
		return true
	case OpOrB:
		v.Op = OpAMD64ORL
		return true
	case OpPanicBounds:
		return rewriteValueAMD64_OpPanicBounds(v)
	case OpPopCount16:
		return rewriteValueAMD64_OpPopCount16(v)
	case OpPopCount32:
		v.Op = OpAMD64POPCNTL
		return true
	case OpPopCount64:
		v.Op = OpAMD64POPCNTQ
		return true
	case OpPopCount8:
		return rewriteValueAMD64_OpPopCount8(v)
	case OpPrefetchCache:
		v.Op = OpAMD64PrefetchT0
		return true
	case OpPrefetchCacheStreamed:
		v.Op = OpAMD64PrefetchNTA
		return true
	case OpRotateLeft16:
		v.Op = OpAMD64ROLW
		return true
	case OpRotateLeft32:
		v.Op = OpAMD64ROLL
		return true
	case OpRotateLeft64:
		v.Op = OpAMD64ROLQ
		return true
	case OpRotateLeft8:
		v.Op = OpAMD64ROLB
		return true
	case OpRound32F:
		v.Op = OpCopy
		return true
	case OpRound64F:
		v.Op = OpCopy
		return true
	case OpRoundToEven:
		return rewriteValueAMD64_OpRoundToEven(v)
	case OpRsh16Ux16:
		return rewriteValueAMD64_OpRsh16Ux16(v)
	case OpRsh16Ux32:
		return rewriteValueAMD64_OpRsh16Ux32(v)
	case OpRsh16Ux64:
		return rewriteValueAMD64_OpRsh16Ux64(v)
	case OpRsh16Ux8:
		return rewriteValueAMD64_OpRsh16Ux8(v)
	case OpRsh16x16:
		return rewriteValueAMD64_OpRsh16x16(v)
	case OpRsh16x32:
		return rewriteValueAMD64_OpRsh16x32(v)
	case OpRsh16x64:
		return rewriteValueAMD64_OpRsh16x64(v)
	case OpRsh16x8:
		return rewriteValueAMD64_OpRsh16x8(v)
	case OpRsh32Ux16:
		return rewriteValueAMD64_OpRsh32Ux16(v)
	case OpRsh32Ux32:
		return rewriteValueAMD64_OpRsh32Ux32(v)
	case OpRsh32Ux64:
		return rewriteValueAMD64_OpRsh32Ux64(v)
	case OpRsh32Ux8:
		return rewriteValueAMD64_OpRsh32Ux8(v)
	case OpRsh32x16:
		return rewriteValueAMD64_OpRsh32x16(v)
	case OpRsh32x32:
		return rewriteValueAMD64_OpRsh32x32(v)
	case OpRsh32x64:
		return rewriteValueAMD64_OpRsh32x64(v)
	case OpRsh32x8:
		return rewriteValueAMD64_OpRsh32x8(v)
	case OpRsh64Ux16:
		return rewriteValueAMD64_OpRsh64Ux16(v)
	case OpRsh64Ux32:
		return rewriteValueAMD64_OpRsh64Ux32(v)
	case OpRsh64Ux64:
		return rewriteValueAMD64_OpRsh64Ux64(v)
	case OpRsh64Ux8:
		return rewriteValueAMD64_OpRsh64Ux8(v)
	case OpRsh64x16:
		return rewriteValueAMD64_OpRsh64x16(v)
	case OpRsh64x32:
		return rewriteValueAMD64_OpRsh64x32(v)
	case OpRsh64x64:
		return rewriteValueAMD64_OpRsh64x64(v)
	case OpRsh64x8:
		return rewriteValueAMD64_OpRsh64x8(v)
	case OpRsh8Ux16:
		return rewriteValueAMD64_OpRsh8Ux16(v)
	case OpRsh8Ux32:
		return rewriteValueAMD64_OpRsh8Ux32(v)
	case OpRsh8Ux64:
		return rewriteValueAMD64_OpRsh8Ux64(v)
	case OpRsh8Ux8:
		return rewriteValueAMD64_OpRsh8Ux8(v)
	case OpRsh8x16:
		return rewriteValueAMD64_OpRsh8x16(v)
	case OpRsh8x32:
		return rewriteValueAMD64_OpRsh8x32(v)
	case OpRsh8x64:
		return rewriteValueAMD64_OpRsh8x64(v)
	case OpRsh8x8:
		return rewriteValueAMD64_OpRsh8x8(v)
	case OpSelect0:
		return rewriteValueAMD64_OpSelect0(v)
	case OpSelect1:
		return rewriteValueAMD64_OpSelect1(v)
	case OpSelectN:
		return rewriteValueAMD64_OpSelectN(v)
	case OpSignExt16to32:
		v.Op = OpAMD64MOVWQSX
		return true
	case OpSignExt16to64:
		v.Op = OpAMD64MOVWQSX
		return true
	case OpSignExt32to64:
		v.Op = OpAMD64MOVLQSX
		return true
	case OpSignExt8to16:
		v.Op = OpAMD64MOVBQSX
		return true
	case OpSignExt8to32:
		v.Op = OpAMD64MOVBQSX
		return true
	case OpSignExt8to64:
		v.Op = OpAMD64MOVBQSX
		return true
	case OpSlicemask:
		return rewriteValueAMD64_OpSlicemask(v)
	case OpSpectreIndex:
		return rewriteValueAMD64_OpSpectreIndex(v)
	case OpSpectreSliceIndex:
		return rewriteValueAMD64_OpSpectreSliceIndex(v)
	case OpSqrt:
		v.Op = OpAMD64SQRTSD
		return true
	case OpSqrt32:
		v.Op = OpAMD64SQRTSS
		return true
	case OpStaticCall:
		v.Op = OpAMD64CALLstatic
		return true
	case OpStore:
		return rewriteValueAMD64_OpStore(v)
	case OpSub16:
		v.Op = OpAMD64SUBL
		return true
	case OpSub32:
		v.Op = OpAMD64SUBL
		return true
	case OpSub32F:
		v.Op = OpAMD64SUBSS
		return true
	case OpSub64:
		v.Op = OpAMD64SUBQ
		return true
	case OpSub64F:
		v.Op = OpAMD64SUBSD
		return true
	case OpSub8:
		v.Op = OpAMD64SUBL
		return true
	case OpSubPtr:
		v.Op = OpAMD64SUBQ
		return true
	case OpTailCall:
		v.Op = OpAMD64CALLtail
		return true
	case OpTrunc:
		return rewriteValueAMD64_OpTrunc(v)
	case OpTrunc16to8:
		v.Op = OpCopy
		return true
	case OpTrunc32to16:
		v.Op = OpCopy
		return true
	case OpTrunc32to8:
		v.Op = OpCopy
		return true
	case OpTrunc64to16:
		v.Op = OpCopy
		return true
	case OpTrunc64to32:
		v.Op = OpCopy
		return true
	case OpTrunc64to8:
		v.Op = OpCopy
		return true
	case OpWB:
		v.Op = OpAMD64LoweredWB
		return true
	case OpXor16:
		v.Op = OpAMD64XORL
		return true
	case OpXor32:
		v.Op = OpAMD64XORL
		return true
	case OpXor64:
		v.Op = OpAMD64XORQ
		return true
	case OpXor8:
		v.Op = OpAMD64XORL
		return true
	case OpZero:
		return rewriteValueAMD64_OpZero(v)
	case OpZeroExt16to32:
		v.Op = OpAMD64MOVWQZX
		return true
	case OpZeroExt16to64:
		v.Op = OpAMD64MOVWQZX
		return true
	case OpZeroExt32to64:
		v.Op = OpAMD64MOVLQZX
		return true
	case OpZeroExt8to16:
		v.Op = OpAMD64MOVBQZX
		return true
	case OpZeroExt8to32:
		v.Op = OpAMD64MOVBQZX
		return true
	case OpZeroExt8to64:
		v.Op = OpAMD64MOVBQZX
		return true
	}
	return false
}
func rewriteValueAMD64_OpAMD64ADCQ(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (ADCQ x (MOVQconst [c]) carry)
	// cond: is32Bit(c)
	// result: (ADCQconst x [int32(c)] carry)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			if v_1.Op != OpAMD64MOVQconst {
				continue
			}
			c := auxIntToInt64(v_1.AuxInt)
			carry := v_2
			if !(is32Bit(c)) {
				continue
			}
			v.reset(OpAMD64ADCQconst)
			v.AuxInt = int32ToAuxInt(int32(c))
			v.AddArg2(x, carry)
			return true
		}
		break
	}
	// match: (ADCQ x y (FlagEQ))
	// result: (ADDQcarry x y)
	for {
		x := v_0
		y := v_1
		if v_2.Op != OpAMD64FlagEQ {
			break
		}
		v.reset(OpAMD64ADDQcarry)
		v.AddArg2(x, y)
		return true
	}
	return false
}
func rewriteValueAMD64_OpAMD64ADCQconst(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (ADCQconst x [c] (FlagEQ))
	// result: (ADDQconstcarry x [c])
	for {
		c := auxIntToInt32(v.AuxInt)
		x := v_0
		if v_1.Op != OpAMD64FlagEQ {
			break
		}
		v.reset(OpAMD64ADDQconstcarry)
		v.AuxInt = int32ToAuxInt(c)
		v.AddArg(x)
		return true
	}
	return false
}
func rewriteValueAMD64_OpAMD64ADDL(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (ADDL x (MOVLconst [c]))
	// result: (ADDLconst [c] x)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			if v_1.Op != OpAMD64MOVLconst {
				continue
			}
			c := auxIntToInt32(v_1.AuxInt)
			v.reset(OpAMD64ADDLconst)
			v.AuxInt = int32ToAuxInt(c)
			v.AddArg(x)
			return true
		}
		break
	}
	// match: (ADDL x (SHLLconst [3] y))
	// result: (LEAL8 x y)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			if v_1.Op != OpAMD64SHLLconst || auxIntToInt8(v_1.AuxInt) != 3 {
				continue
			}
			y := v_1.Args[0]
			v.reset(OpAMD64LEAL8)
			v.AddArg2(x, y)
			return true
		}
		break
	}
	// match: (ADDL x (SHLLconst [2] y))
	// result: (LEAL4 x y)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			if v_1.Op != OpAMD64SHLLconst || auxIntToInt8(v_1.AuxInt) != 2 {
				continue
			}
			y := v_1.Args[0]
			v.reset(OpAMD64LEAL4)
			v.AddArg2(x, y)
			return true
		}
		break
	}
	// match: (ADDL x (SHLLconst [1] y))
	// result: (LEAL2 x y)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			if v_1.Op != OpAMD64SHLLconst || auxIntToInt8(v_1.AuxInt) != 1 {
				continue
			}
			y := v_1.Args[0]
			v.reset(OpAMD64LEAL2)
			v.AddArg2(x, y)
			return true
		}
		break
	}
	// match: (ADDL x (ADDL y y))
	// result: (LEAL2 x y)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			if v_1.Op != OpAMD64ADDL {
				continue
			}
			y := v_1.Args[1]
			if y != v_1.Args[0] {
				continue
			}
			v.reset(OpAMD64LEAL2)
			v.AddArg2(x, y)
			return true
		}
		break
	}
	// match: (ADDL x (ADDL x y))
	// result: (LEAL2 y x)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			if v_1.Op != OpAMD64ADDL {
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
				v.reset(OpAMD64LEAL2)
				v.AddArg2(y, x)
				return true
			}
		}
		break
	}
	// match: (ADDL (ADDLconst [c] x) y)
	// result: (LEAL1 [c] x y)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpAMD64ADDLconst {
				continue
			}
			c := auxIntToInt32(v_0.AuxInt)
			x := v_0.Args[0]
			y := v_1
			v.reset(OpAMD64LEAL1)
			v.AuxInt = int32ToAuxInt(c)
			v.AddArg2(x, y)
			return true
		}
		break
	}
	// match: (ADDL x (LEAL [c] {s} y))
	// cond: x.Op != OpSB && y.Op != OpSB
	// result: (LEAL1 [c] {s} x y)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			if v_1.Op != OpAMD64LEAL {
				continue
			}
			c := auxIntToInt32(v_1.AuxInt)
			s := auxToSym(v_1.Aux)
			y := v_1.Args[0]
			if !(x.Op != OpSB && y.Op != OpSB) {
				continue
			}
			v.reset(OpAMD64LEAL1)
			v.AuxInt = int32ToAuxInt(c)
			v.Aux = symToAux(s)
			v.AddArg2(x, y)
			return true
		}
		break
	}
	// match: (ADDL x (NEGL y))
	// result: (SUBL x y)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			if v_1.Op != OpAMD64NEGL {
				continue
			}
			y := v_1.Args[0]
			v.reset(OpAMD64SUBL)
			v.AddArg2(x, y)
			return true
		}
		break
	}
	// match: (ADDL x l:(MOVLload [off] {sym} ptr mem))
	// cond: canMergeLoadClobber(v, l, x) && clobber(l)
	// result: (ADDLload x [off] {sym} ptr mem)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			l := v_1
			if l.Op != OpAMD64MOVLload {
				continue
			}
			off := auxIntToInt32(l.AuxInt)
			sym := auxToSym(l.Aux)
			mem := l.Args[1]
			ptr := l.Args[0]
			if !(canMergeLoadClobber(v, l, x) && clobber(l)) {
				continue
			}
			v.reset(OpAMD64ADDLload)
			v.AuxInt = int32ToAuxInt(off)
			v.Aux = symToAux(sym)
			v.AddArg3(x, ptr, mem)
			return true
		}
		break
	}
	return false
}
func rewriteValueAMD64_OpAMD64ADDLconst(v *Value) bool {
	v_0 := v.Args[0]
	// match: (ADDLconst [c] (ADDL x y))
	// result: (LEAL1 [c] x y)
	for {
		c := auxIntToInt32(v.AuxInt)
		if v_0.Op != OpAMD64ADDL {
			break
		}
		y := v_0.Args[1]
		x := v_0.Args[0]
		v.reset(OpAMD64LEAL1)
		v.AuxInt = int32ToAuxInt(c)
		v.AddArg2(x, y)
		return true
	}
	// match: (ADDLconst [c] (SHLLconst [1] x))
	// result: (LEAL1 [c] x x)
	for {
		c := auxIntToInt32(v.AuxInt)
		if v_0.Op != OpAMD64SHLLconst || auxIntToInt8(v_0.AuxInt) != 1 {
			break
		}
		x := v_0.Args[0]
		v.reset(OpAMD64LEAL1)
		v.AuxInt = int32ToAuxInt(c)
		v.AddArg2(x, x)
		return true
	}
	// match: (ADDLconst [c] (LEAL [d] {s} x))
	// cond: is32Bit(int64(c)+int64(d))
	// result: (LEAL [c+d] {s} x)
	for {
		c := auxIntToInt32(v.AuxInt)
		if v_0.Op != OpAMD64LEAL {
			break
		}
		d := auxIntToInt32(v_0.AuxInt)
		s := auxToSym(v_0.Aux)
		x := v_0.Args[0]
		if !(is32Bit(int64(c) + int64(d))) {
			break
		}
		v.reset(OpAMD64LEAL)
		v.AuxInt = int32ToAuxInt(c + d)
		v.Aux = symToAux(s)
		v.AddArg(x)
		return true
	}
	// match: (ADDLconst [c] (LEAL1 [d] {s} x y))
	// cond: is32Bit(int64(c)+int64(d))
	// result: (LEAL1 [c+d] {s} x y)
	for {
		c := auxIntToInt32(v.AuxInt)
		if v_0.Op != OpAMD64LEAL1 {
			break
		}
		d := auxIntToInt32(v_0.AuxInt)
		s := auxToSym(v_0.Aux)
		y := v_0.Args[1]
		x := v_0.Args[0]
		if !(is32Bit(int64(c) + int64(d))) {
			break
		}
		v.reset(OpAMD64LEAL1)
		v.AuxInt = int32ToAuxInt(c + d)
		v.Aux = symToAux(s)
		v.AddArg2(x, y)
		return true
	}
	// match: (ADDLconst [c] (LEAL2 [d] {s} x y))
	// cond: is32Bit(int64(c)+int64(d))
	// result: (LEAL2 [c+d] {s} x y)
	for {
		c := auxIntToInt32(v.AuxInt)
		if v_0.Op != OpAMD64LEAL2 {
			break
		}
		d := auxIntToInt32(v_0.AuxInt)
		s := auxToSym(v_0.Aux)
		y := v_0.Args[1]
		x := v_0.Args[0]
		if !(is32Bit(int64(c) + int64(d))) {
			break
		}
		v.reset(OpAMD64LEAL2)
		v.AuxInt = int32ToAuxInt(c + d)
		v.Aux = symToAux(s)
		v.AddArg2(x, y)
		return true
	}
	// match: (ADDLconst [c] (LEAL4 [d] {s} x y))
	// cond: is32Bit(int64(c)+int64(d))
	// result: (LEAL4 [c+d] {s} x y)
	for {
		c := auxIntToInt32(v.AuxInt)
		if v_0.Op != OpAMD64LEAL4 {
			break
		}
		d := auxIntToInt32(v_0.AuxInt)
		s := auxToSym(v_0.Aux)
		y := v_0.Args[1]
		x := v_0.Args[0]
		if !(is32Bit(int64(c) + int64(d))) {
			break
		}
		v.reset(OpAMD64LEAL4)
		v.AuxInt = int32ToAuxInt(c + d)
		v.Aux = symToAux(s)
		v.AddArg2(x, y)
		return true
	}
	// match: (ADDLconst [c] (LEAL8 [d] {s} x y))
	// cond: is32Bit(int64(c)+int64(d))
	// result: (LEAL8 [c+d] {s} x y)
	for {
		c := auxIntToInt32(v.AuxInt)
		if v_0.Op != OpAMD64LEAL8 {
			break
		}
		d := auxIntToInt32(v_0.AuxInt)
		s := auxToSym(v_0.Aux)
		y := v_0.Args[1]
		x := v_0.Args[0]
		if !(is32Bit(int64(c) + int64(d))) {
			break
		}
		v.reset(OpAMD64LEAL8)
		v.AuxInt = int32ToAuxInt(c + d)
		v.Aux = symToAux(s)
		v.AddArg2(x, y)
		return true
	}
	// match: (ADDLconst [c] x)
	// cond: c==0
	// result: x
	for {
		c := auxIntToInt32(v.AuxInt)
		x := v_0
		if !(c == 0) {
			break
		}
		v.copyOf(x)
		return true
	}
	// match: (ADDLconst [c] (MOVLconst [d]))
	// result: (MOVLconst [c+d])
	for {
		c := auxIntToInt32(v.AuxInt)
		if v_0.Op != OpAMD64MOVLconst {
			break
		}
		d := auxIntToInt32(v_0.AuxInt)
		v.reset(OpAMD64MOVLconst)
		v.AuxInt = int32ToAuxInt(c + d)
		return true
	}
	// match: (ADDLconst [c] (ADDLconst [d] x))
	// result: (ADDLconst [c+d] x)
	for {
		c := auxIntToInt32(v.AuxInt)
		if v_0.Op != OpAMD64ADDLconst {
			break
		}
		d := auxIntToInt32(v_0.AuxInt)
		x := v_0.Args[0]
		v.reset(OpAMD64ADDLconst)
		v.AuxInt = int32ToAuxInt(c + d)
		v.AddArg(x)
		return true
	}
	// match: (ADDLconst [off] x:(SP))
	// result: (LEAL [off] x)
	for {
		off := auxIntToInt32(v.AuxInt)
		x := v_0
		if x.Op != OpSP {
			break
		}
		v.reset(OpAMD64LEAL)
		v.AuxInt = int32ToAuxInt(off)
		v.AddArg(x)
		return true
	}
	return false
}
func rewriteValueAMD64_OpAMD64ADDLconstmodify(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (ADDLconstmodify [valoff1] {sym} (ADDQconst [off2] base) mem)
	// cond: ValAndOff(valoff1).canAdd32(off2)
	// result: (ADDLconstmodify [ValAndOff(valoff1).addOffset32(off2)] {sym} base mem)
	for {
		valoff1 := auxIntToValAndOff(v.AuxInt)
		sym := auxToSym(v.Aux)
		if v_0.Op != OpAMD64ADDQconst {
			break
		}
		off2 := auxIntToInt32(v_0.AuxInt)
		base := v_0.Args[0]
		mem := v_1
		if !(ValAndOff(valoff1).canAdd32(off2)) {
			break
		}
		v.reset(OpAMD64ADDLconstmodify)
		v.AuxInt = valAndOffToAuxInt(ValAndOff(valoff1).addOffset32(off2))
		v.Aux = symToAux(sym)
		v.AddArg2(base, mem)
		return true
	}
	// match: (ADDLconstmodify [valoff1] {sym1} (LEAQ [off2] {sym2} base) mem)
	// cond: ValAndOff(valoff1).canAdd32(off2) && canMergeSym(sym1, sym2)
	// result: (ADDLconstmodify [ValAndOff(valoff1).addOffset32(off2)] {mergeSym(sym1,sym2)} base mem)
	for {
		valoff1 := auxIntToValAndOff(v.AuxInt)
		sym1 := auxToSym(v.Aux)
		if v_0.Op != OpAMD64LEAQ {
			break
		}
		off2 := auxIntToInt32(v_0.AuxInt)
		sym2 := auxToSym(v_0.Aux)
		base := v_0.Args[0]
		mem := v_1
		if !(ValAndOff(valoff1).canAdd32(off2) && canMergeSym(sym1, sym2)) {
			break
		}
		v.reset(OpAMD64ADDLconstmodify)
		v.AuxInt = valAndOffToAuxInt(ValAndOff(valoff1).addOffset32(off2))
		v.Aux = symToAux(mergeSym(sym1, sym2))
		v.AddArg2(base, mem)
		return true
	}
	return false
}
func rewriteValueAMD64_OpAMD64ADDLload(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (ADDLload [off1] {sym} val (ADDQconst [off2] base) mem)
	// cond: is32Bit(int64(off1)+int64(off2))
	// result: (ADDLload [off1+off2] {sym} val base mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		val := v_0
		if v_1.Op != OpAMD64ADDQconst {
			break
		}
		off2 := auxIntToInt32(v_1.AuxInt)
		base := v_1.Args[0]
		mem := v_2
		if !(is32Bit(int64(off1) + int64(off2))) {
			break
		}
		v.reset(OpAMD64ADDLload)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(sym)
		v.AddArg3(val, base, mem)
		return true
	}
	// match: (ADDLload [off1] {sym1} val (LEAQ [off2] {sym2} base) mem)
	// cond: is32Bit(int64(off1)+int64(off2)) && canMergeSym(sym1, sym2)
	// result: (ADDLload [off1+off2] {mergeSym(sym1,sym2)} val base mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym1 := auxToSym(v.Aux)
		val := v_0
		if v_1.Op != OpAMD64LEAQ {
			break
		}
		off2 := auxIntToInt32(v_1.AuxInt)
		sym2 := auxToSym(v_1.Aux)
		base := v_1.Args[0]
		mem := v_2
		if !(is32Bit(int64(off1)+int64(off2)) && canMergeSym(sym1, sym2)) {
			break
		}
		v.reset(OpAMD64ADDLload)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(mergeSym(sym1, sym2))
		v.AddArg3(val, base, mem)
		return true
	}
	// match: (ADDLload x [off] {sym} ptr (MOVSSstore [off] {sym} ptr y _))
	// result: (ADDL x (MOVLf2i y))
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		x := v_0
		ptr := v_1
		if v_2.Op != OpAMD64MOVSSstore || auxIntToInt32(v_2.AuxInt) != off || auxToSym(v_2.Aux) != sym {
			break
		}
		y := v_2.Args[1]
		if ptr != v_2.Args[0] {
			break
		}
		v.reset(OpAMD64ADDL)
		v0 := b.NewValue0(v_2.Pos, OpAMD64MOVLf2i, typ.UInt32)
		v0.AddArg(y)
		v.AddArg2(x, v0)
		return true
	}
	return false
}
func rewriteValueAMD64_OpAMD64ADDLmodify(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (ADDLmodify [off1] {sym} (ADDQconst [off2] base) val mem)
	// cond: is32Bit(int64(off1)+int64(off2))
	// result: (ADDLmodify [off1+off2] {sym} base val mem)
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
		v.reset(OpAMD64ADDLmodify)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(sym)
		v.AddArg3(base, val, mem)
		return true
	}
	// match: (ADDLmodify [off1] {sym1} (LEAQ [off2] {sym2} base) val mem)
	// cond: is32Bit(int64(off1)+int64(off2)) && canMergeSym(sym1, sym2)
	// result: (ADDLmodify [off1+off2] {mergeSym(sym1,sym2)} base val mem)
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
		v.reset(OpAMD64ADDLmodify)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(mergeSym(sym1, sym2))
		v.AddArg3(base, val, mem)
		return true
	}
	return false
}
func rewriteValueAMD64_OpAMD64ADDQ(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (ADDQ x (MOVQconst <t> [c]))
	// cond: is32Bit(c) && !t.IsPtr()
	// result: (ADDQconst [int32(c)] x)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			if v_1.Op != OpAMD64MOVQconst {
				continue
			}
			t := v_1.Type
			c := auxIntToInt64(v_1.AuxInt)
			if !(is32Bit(c) && !t.IsPtr()) {
				continue
			}
			v.reset(OpAMD64ADDQconst)
			v.AuxInt = int32ToAuxInt(int32(c))
			v.AddArg(x)
			return true
		}
		break
	}
	// match: (ADDQ x (MOVLconst [c]))
	// result: (ADDQconst [c] x)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			if v_1.Op != OpAMD64MOVLconst {
				continue
			}
			c := auxIntToInt32(v_1.AuxInt)
			v.reset(OpAMD64ADDQconst)
			v.AuxInt = int32ToAuxInt(c)
			v.AddArg(x)
			return true
		}
		break
	}
	// match: (ADDQ x (SHLQconst [3] y))
	// result: (LEAQ8 x y)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			if v_1.Op != OpAMD64SHLQconst || auxIntToInt8(v_1.AuxInt) != 3 {
				continue
			}
			y := v_1.Args[0]
			v.reset(OpAMD64LEAQ8)
			v.AddArg2(x, y)
			return true
		}
		break
	}
	// match: (ADDQ x (SHLQconst [2] y))
	// result: (LEAQ4 x y)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			if v_1.Op != OpAMD64SHLQconst || auxIntToInt8(v_1.AuxInt) != 2 {
				continue
			}
			y := v_1.Args[0]
			v.reset(OpAMD64LEAQ4)
			v.AddArg2(x, y)
			return true
		}
		break
	}
	// match: (ADDQ x (SHLQconst [1] y))
	// result: (LEAQ2 x y)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			if v_1.Op != OpAMD64SHLQconst || auxIntToInt8(v_1.AuxInt) != 1 {
				continue
			}
			y := v_1.Args[0]
			v.reset(OpAMD64LEAQ2)
			v.AddArg2(x, y)
			return true
		}
		break
	}
	// match: (ADDQ x (ADDQ y y))
	// result: (LEAQ2 x y)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			if v_1.Op != OpAMD64ADDQ {
				continue
			}
			y := v_1.Args[1]
			if y != v_1.Args[0] {
				continue
			}
			v.reset(OpAMD64LEAQ2)
			v.AddArg2(x, y)
			return true
		}
		break
	}
	// match: (ADDQ x (ADDQ x y))
	// result: (LEAQ2 y x)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			if v_1.Op != OpAMD64ADDQ {
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
				v.reset(OpAMD64LEAQ2)
				v.AddArg2(y, x)
				return true
			}
		}
		break
	}
	// match: (ADDQ (ADDQconst [c] x) y)
	// result: (LEAQ1 [c] x y)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpAMD64ADDQconst {
				continue
			}
			c := auxIntToInt32(v_0.AuxInt)
			x := v_0.Args[0]
			y := v_1
			v.reset(OpAMD64LEAQ1)
			v.AuxInt = int32ToAuxInt(c)
			v.AddArg2(x, y)
			return true
		}
		break
	}
	// match: (ADDQ x (LEAQ [c] {s} y))
	// cond: x.Op != OpSB && y.Op != OpSB
	// result: (LEAQ1 [c] {s} x y)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			if v_1.Op != OpAMD64LEAQ {
				continue
			}
			c := auxIntToInt32(v_1.AuxInt)
			s := auxToSym(v_1.Aux)
			y := v_1.Args[0]
			if !(x.Op != OpSB && y.Op != OpSB) {
				continue
			}
			v.reset(OpAMD64LEAQ1)
			v.AuxInt = int32ToAuxInt(c)
			v.Aux = symToAux(s)
			v.AddArg2(x, y)
			return true
		}
		break
	}
	// match: (ADDQ x (NEGQ y))
	// result: (SUBQ x y)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			if v_1.Op != OpAMD64NEGQ {
				continue
			}
			y := v_1.Args[0]
			v.reset(OpAMD64SUBQ)
			v.AddArg2(x, y)
			return true
		}
		break
	}
	// match: (ADDQ x l:(MOVQload [off] {sym} ptr mem))
	// cond: canMergeLoadClobber(v, l, x) && clobber(l)
	// result: (ADDQload x [off] {sym} ptr mem)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			l := v_1
			if l.Op != OpAMD64MOVQload {
				continue
			}
			off := auxIntToInt32(l.AuxInt)
			sym := auxToSym(l.Aux)
			mem := l.Args[1]
			ptr := l.Args[0]
			if !(canMergeLoadClobber(v, l, x) && clobber(l)) {
				continue
			}
			v.reset(OpAMD64ADDQload)
			v.AuxInt = int32ToAuxInt(off)
			v.Aux = symToAux(sym)
			v.AddArg3(x, ptr, mem)
			return true
		}
		break
	}
	return false
}
func rewriteValueAMD64_OpAMD64ADDQcarry(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (ADDQcarry x (MOVQconst [c]))
	// cond: is32Bit(c)
	// result: (ADDQconstcarry x [int32(c)])
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			if v_1.Op != OpAMD64MOVQconst {
				continue
			}
			c := auxIntToInt64(v_1.AuxInt)
			if !(is32Bit(c)) {
				continue
			}
			v.reset(OpAMD64ADDQconstcarry)
			v.AuxInt = int32ToAuxInt(int32(c))
			v.AddArg(x)
			return true
		}
		break
	}
	return false
}
func rewriteValueAMD64_OpAMD64ADDQconst(v *Value) bool {
	v_0 := v.Args[0]
	// match: (ADDQconst [c] (ADDQ x y))
	// result: (LEAQ1 [c] x y)
	for {
		c := auxIntToInt32(v.AuxInt)
		if v_0.Op != OpAMD64ADDQ {
			break
		}
		y := v_0.Args[1]
		x := v_0.Args[0]
		v.reset(OpAMD64LEAQ1)
		v.AuxInt = int32ToAuxInt(c)
		v.AddArg2(x, y)
		return true
	}
	// match: (ADDQconst [c] (SHLQconst [1] x))
	// result: (LEAQ1 [c] x x)
	for {
		c := auxIntToInt32(v.AuxInt)
		if v_0.Op != OpAMD64SHLQconst || auxIntToInt8(v_0.AuxInt) != 1 {
			break
		}
		x := v_0.Args[0]
		v.reset(OpAMD64LEAQ1)
		v.AuxInt = int32ToAuxInt(c)
		v.AddArg2(x, x)
		return true
	}
	// match: (ADDQconst [c] (LEAQ [d] {s} x))
	// cond: is32Bit(int64(c)+int64(d))
	// result: (LEAQ [c+d] {s} x)
	for {
		c := auxIntToInt32(v.AuxInt)
		if v_0.Op != OpAMD64LEAQ {
			break
		}
		d := auxIntToInt32(v_0.AuxInt)
		s := auxToSym(v_0.Aux)
		x := v_0.Args[0]
		if !(is32Bit(int64(c) + int64(d))) {
			break
		}
		v.reset(OpAMD64LEAQ)
		v.AuxInt = int32ToAuxInt(c + d)
		v.Aux = symToAux(s)
		v.AddArg(x)
		return true
	}
	// match: (ADDQconst [c] (LEAQ1 [d] {s} x y))
	// cond: is32Bit(int64(c)+int64(d))
	// result: (LEAQ1 [c+d] {s} x y)
	for {
		c := auxIntToInt32(v.AuxInt)
		if v_0.Op != OpAMD64LEAQ1 {
			break
		}
		d := auxIntToInt32(v_0.AuxInt)
		s := auxToSym(v_0.Aux)
		y := v_0.Args[1]
		x := v_0.Args[0]
		if !(is32Bit(int64(c) + int64(d))) {
			break
		}
		v.reset(OpAMD64LEAQ1)
		v.AuxInt = int32ToAuxInt(c + d)
		v.Aux = symToAux(s)
		v.AddArg2(x, y)
		return true
	}
	// match: (ADDQconst [c] (LEAQ2 [d] {s} x y))
	// cond: is32Bit(int64(c)+int64(d))
	// result: (LEAQ2 [c+d] {s} x y)
	for {
		c := auxIntToInt32(v.AuxInt)
		if v_0.Op != OpAMD64LEAQ2 {
			break
		}
		d := auxIntToInt32(v_0.AuxInt)
		s := auxToSym(v_0.Aux)
		y := v_0.Args[1]
		x := v_0.Args[0]
		if !(is32Bit(int64(c) + int64(d))) {
			break
		}
		v.reset(OpAMD64LEAQ2)
		v.AuxInt = int32ToAuxInt(c + d)
		v.Aux = symToAux(s)
		v.AddArg2(x, y)
		return true
	}
	// match: (ADDQconst [c] (LEAQ4 [d] {s} x y))
	// cond: is32Bit(int64(c)+int64(d))
	// result: (LEAQ4 [c+d] {s} x y)
	for {
		c := auxIntToInt32(v.AuxInt)
		if v_0.Op != OpAMD64LEAQ4 {
			break
		}
		d := auxIntToInt32(v_0.AuxInt)
		s := auxToSym(v_0.Aux)
		y := v_0.Args[1]
		x := v_0.Args[0]
		if !(is32Bit(int64(c) + int64(d))) {
			break
		}
		v.reset(OpAMD64LEAQ4)
		v.AuxInt = int32ToAuxInt(c + d)
		v.Aux = symToAux(s)
		v.AddArg2(x, y)
		return true
	}
	// match: (ADDQconst [c] (LEAQ8 [d] {s} x y))
	// cond: is32Bit(int64(c)+int64(d))
	// result: (LEAQ8 [c+d] {s} x y)
	for {
		c := auxIntToInt32(v.AuxInt)
		if v_0.Op != OpAMD64LEAQ8 {
			break
		}
		d := auxIntToInt32(v_0.AuxInt)
		s := auxToSym(v_0.Aux)
		y := v_0.Args[1]
		x := v_0.Args[0]
		if !(is32Bit(int64(c) + int64(d))) {
			break
		}
		v.reset(OpAMD64LEAQ8)
		v.AuxInt = int32ToAuxInt(c + d)
		v.Aux = symToAux(s)
		v.AddArg2(x, y)
		return true
	}
	// match: (ADDQconst [0] x)
	// result: x
	for {
		if auxIntToInt32(v.AuxInt) != 0 {
			break
		}
		x := v_0
		v.copyOf(x)
		return true
	}
	// match: (ADDQconst [c] (MOVQconst [d]))
	// result: (MOVQconst [int64(c)+d])
	for {
		c := auxIntToInt32(v.AuxInt)
		if v_0.Op != OpAMD64MOVQconst {
			break
		}
		d := auxIntToInt64(v_0.AuxInt)
		v.reset(OpAMD64MOVQconst)
		v.AuxInt = int64ToAuxInt(int64(c) + d)
		return true
	}
	// match: (ADDQconst [c] (ADDQconst [d] x))
	// cond: is32Bit(int64(c)+int64(d))
	// result: (ADDQconst [c+d] x)
	for {
		c := auxIntToInt32(v.AuxInt)
		if v_0.Op != OpAMD64ADDQconst {
			break
		}
		d := auxIntToInt32(v_0.AuxInt)
		x := v_0.Args[0]
		if !(is32Bit(int64(c) + int64(d))) {
			break
		}
		v.reset(OpAMD64ADDQconst)
		v.AuxInt = int32ToAuxInt(c + d)
		v.AddArg(x)
		return true
	}
	// match: (ADDQconst [off] x:(SP))
	// result: (LEAQ [off] x)
	for {
		off := auxIntToInt32(v.AuxInt)
		x := v_0
		if x.Op != OpSP {
			break
		}
		v.reset(OpAMD64LEAQ)
		v.AuxInt = int32ToAuxInt(off)
		v.AddArg(x)
		return true
	}
	return false
}
func rewriteValueAMD64_OpAMD64ADDQconstmodify(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (ADDQconstmodify [valoff1] {sym} (ADDQconst [off2] base) mem)
	// cond: ValAndOff(valoff1).canAdd32(off2)
	// result: (ADDQconstmodify [ValAndOff(valoff1).addOffset32(off2)] {sym} base mem)
	for {
		valoff1 := auxIntToValAndOff(v.AuxInt)
		sym := auxToSym(v.Aux)
		if v_0.Op != OpAMD64ADDQconst {
			break
		}
		off2 := auxIntToInt32(v_0.AuxInt)
		base := v_0.Args[0]
		mem := v_1
		if !(ValAndOff(valoff1).canAdd32(off2)) {
			break
		}
		v.reset(OpAMD64ADDQconstmodify)
		v.AuxInt = valAndOffToAuxInt(ValAndOff(valoff1).addOffset32(off2))
		v.Aux = symToAux(sym)
		v.AddArg2(base, mem)
		return true
	}
	// match: (ADDQconstmodify [valoff1] {sym1} (LEAQ [off2] {sym2} base) mem)
	// cond: ValAndOff(valoff1).canAdd32(off2) && canMergeSym(sym1, sym2)
	// result: (ADDQconstmodify [ValAndOff(valoff1).addOffset32(off2)] {mergeSym(sym1,sym2)} base mem)
	for {
		valoff1 := auxIntToValAndOff(v.AuxInt)
		sym1 := auxToSym(v.Aux)
		if v_0.Op != OpAMD64LEAQ {
			break
		}
		off2 := auxIntToInt32(v_0.AuxInt)
		sym2 := auxToSym(v_0.Aux)
		base := v_0.Args[0]
		mem := v_1
		if !(ValAndOff(valoff1).canAdd32(off2) && canMergeSym(sym1, sym2)) {
			break
		}
		v.reset(OpAMD64ADDQconstmodify)
		v.AuxInt = valAndOffToAuxInt(ValAndOff(valoff1).addOffset32(off2))
		v.Aux = symToAux(mergeSym(sym1, sym2))
		v.AddArg2(base, mem)
		return true
	}
	return false
}
func rewriteValueAMD64_OpAMD64ADDQload(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (ADDQload [off1] {sym} val (ADDQconst [off2] base) mem)
	// cond: is32Bit(int64(off1)+int64(off2))
	// result: (ADDQload [off1+off2] {sym} val base mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		val := v_0
		if v_1.Op != OpAMD64ADDQconst {
			break
		}
		off2 := auxIntToInt32(v_1.AuxInt)
		base := v_1.Args[0]
		mem := v_2
		if !(is32Bit(int64(off1) + int64(off2))) {
			break
		}
		v.reset(OpAMD64ADDQload)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(sym)
		v.AddArg3(val, base, mem)
		return true
	}
	// match: (ADDQload [off1] {sym1} val (LEAQ [off2] {sym2} base) mem)
	// cond: is32Bit(int64(off1)+int64(off2)) && canMergeSym(sym1, sym2)
	// result: (ADDQload [off1+off2] {mergeSym(sym1,sym2)} val base mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym1 := auxToSym(v.Aux)
		val := v_0
		if v_1.Op != OpAMD64LEAQ {
			break
		}
		off2 := auxIntToInt32(v_1.AuxInt)
		sym2 := auxToSym(v_1.Aux)
		base := v_1.Args[0]
		mem := v_2
		if !(is32Bit(int64(off1)+int64(off2)) && canMergeSym(sym1, sym2)) {
			break
		}
		v.reset(OpAMD64ADDQload)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(mergeSym(sym1, sym2))
		v.AddArg3(val, base, mem)
		return true
	}
	// match: (ADDQload x [off] {sym} ptr (MOVSDstore [off] {sym} ptr y _))
	// result: (ADDQ x (MOVQf2i y))
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		x := v_0
		ptr := v_1
		if v_2.Op != OpAMD64MOVSDstore || auxIntToInt32(v_2.AuxInt) != off || auxToSym(v_2.Aux) != sym {
			break
		}
		y := v_2.Args[1]
		if ptr != v_2.Args[0] {
			break
		}
		v.reset(OpAMD64ADDQ)
		v0 := b.NewValue0(v_2.Pos, OpAMD64MOVQf2i, typ.UInt64)
		v0.AddArg(y)
		v.AddArg2(x, v0)
		return true
	}
	return false
}
func rewriteValueAMD64_OpAMD64ADDQmodify(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (ADDQmodify [off1] {sym} (ADDQconst [off2] base) val mem)
	// cond: is32Bit(int64(off1)+int64(off2))
	// result: (ADDQmodify [off1+off2] {sym} base val mem)
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
		v.reset(OpAMD64ADDQmodify)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(sym)
		v.AddArg3(base, val, mem)
		return true
	}
	// match: (ADDQmodify [off1] {sym1} (LEAQ [off2] {sym2} base) val mem)
	// cond: is32Bit(int64(off1)+int64(off2)) && canMergeSym(sym1, sym2)
	// result: (ADDQmodify [off1+off2] {mergeSym(sym1,sym2)} base val mem)
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
		v.reset(OpAMD64ADDQmodify)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(mergeSym(sym1, sym2))
		v.AddArg3(base, val, mem)
		return true
	}
	return false
}
func rewriteValueAMD64_OpAMD64ADDSD(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (ADDSD x l:(MOVSDload [off] {sym} ptr mem))
	// cond: canMergeLoadClobber(v, l, x) && clobber(l)
	// result: (ADDSDload x [off] {sym} ptr mem)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			l := v_1
			if l.Op != OpAMD64MOVSDload {
				continue
			}
			off := auxIntToInt32(l.AuxInt)
			sym := auxToSym(l.Aux)
			mem := l.Args[1]
			ptr := l.Args[0]
			if !(canMergeLoadClobber(v, l, x) && clobber(l)) {
				continue
			}
			v.reset(OpAMD64ADDSDload)
			v.AuxInt = int32ToAuxInt(off)
			v.Aux = symToAux(sym)
			v.AddArg3(x, ptr, mem)
			return true
		}
		break
	}
	return false
}
func rewriteValueAMD64_OpAMD64ADDSDload(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (ADDSDload [off1] {sym} val (ADDQconst [off2] base) mem)
	// cond: is32Bit(int64(off1)+int64(off2))
	// result: (ADDSDload [off1+off2] {sym} val base mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		val := v_0
		if v_1.Op != OpAMD64ADDQconst {
			break
		}
		off2 := auxIntToInt32(v_1.AuxInt)
		base := v_1.Args[0]
		mem := v_2
		if !(is32Bit(int64(off1) + int64(off2))) {
			break
		}
		v.reset(OpAMD64ADDSDload)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(sym)
		v.AddArg3(val, base, mem)
		return true
	}
	// match: (ADDSDload [off1] {sym1} val (LEAQ [off2] {sym2} base) mem)
	// cond: is32Bit(int64(off1)+int64(off2)) && canMergeSym(sym1, sym2)
	// result: (ADDSDload [off1+off2] {mergeSym(sym1,sym2)} val base mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym1 := auxToSym(v.Aux)
		val := v_0
		if v_1.Op != OpAMD64LEAQ {
			break
		}
		off2 := auxIntToInt32(v_1.AuxInt)
		sym2 := auxToSym(v_1.Aux)
		base := v_1.Args[0]
		mem := v_2
		if !(is32Bit(int64(off1)+int64(off2)) && canMergeSym(sym1, sym2)) {
			break
		}
		v.reset(OpAMD64ADDSDload)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(mergeSym(sym1, sym2))
		v.AddArg3(val, base, mem)
		return true
	}
	// match: (ADDSDload x [off] {sym} ptr (MOVQstore [off] {sym} ptr y _))
	// result: (ADDSD x (MOVQi2f y))
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		x := v_0
		ptr := v_1
		if v_2.Op != OpAMD64MOVQstore || auxIntToInt32(v_2.AuxInt) != off || auxToSym(v_2.Aux) != sym {
			break
		}
		y := v_2.Args[1]
		if ptr != v_2.Args[0] {
			break
		}
		v.reset(OpAMD64ADDSD)
		v0 := b.NewValue0(v_2.Pos, OpAMD64MOVQi2f, typ.Float64)
		v0.AddArg(y)
		v.AddArg2(x, v0)
		return true
	}
	return false
}
func rewriteValueAMD64_OpAMD64ADDSS(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (ADDSS x l:(MOVSSload [off] {sym} ptr mem))
	// cond: canMergeLoadClobber(v, l, x) && clobber(l)
	// result: (ADDSSload x [off] {sym} ptr mem)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			l := v_1
			if l.Op != OpAMD64MOVSSload {
				continue
			}
			off := auxIntToInt32(l.AuxInt)
			sym := auxToSym(l.Aux)
			mem := l.Args[1]
			ptr := l.Args[0]
			if !(canMergeLoadClobber(v, l, x) && clobber(l)) {
				continue
			}
			v.reset(OpAMD64ADDSSload)
			v.AuxInt = int32ToAuxInt(off)
			v.Aux = symToAux(sym)
			v.AddArg3(x, ptr, mem)
			return true
		}
		break
	}
	return false
}
func rewriteValueAMD64_OpAMD64ADDSSload(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (ADDSSload [off1] {sym} val (ADDQconst [off2] base) mem)
	// cond: is32Bit(int64(off1)+int64(off2))
	// result: (ADDSSload [off1+off2] {sym} val base mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		val := v_0
		if v_1.Op != OpAMD64ADDQconst {
			break
		}
		off2 := auxIntToInt32(v_1.AuxInt)
		base := v_1.Args[0]
		mem := v_2
		if !(is32Bit(int64(off1) + int64(off2))) {
			break
		}
		v.reset(OpAMD64ADDSSload)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(sym)
		v.AddArg3(val, base, mem)
		return true
	}
	// match: (ADDSSload [off1] {sym1} val (LEAQ [off2] {sym2} base) mem)
	// cond: is32Bit(int64(off1)+in
"""




```