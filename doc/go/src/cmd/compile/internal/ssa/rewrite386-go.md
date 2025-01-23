Response: Let's break down the thought process for analyzing the provided Go code snippet.

**1. Initial Understanding of the Context:**

* **File Path:** `go/src/cmd/compile/internal/ssa/rewrite386.go`. This immediately tells us we're dealing with the Go compiler, specifically the SSA (Static Single Assignment) intermediate representation, and targeting the 386 architecture.
* **"Code generated..." comment:**  This is crucial. It means the core logic isn't handwritten in this file. It's likely generated from a set of rules. This shifts our focus from deeply understanding every line of *this* file to understanding the *purpose* and *structure* it embodies.
* **`package ssa` and imports:** Confirms we're in the SSA package within the compiler. The imports `math` and `cmd/compile/internal/types` are relevant to numerical operations and Go's type system, suggesting optimizations or transformations related to these.

**2. Examining the `rewriteValue386` Function:**

* **Signature:** `func rewriteValue386(v *Value) bool`. This strongly suggests a function that modifies or rewrites an SSA `Value`. The boolean return likely indicates whether a rewrite occurred.
* **`switch v.Op`:** The core structure is a large switch statement based on `v.Op`, which represents the *operation* of the SSA value. This is the key to understanding the file's functionality: it handles various 386-specific operations.
* **Case Structure:** Each `case` corresponds to a specific 386 instruction or a higher-level Go operation that needs to be translated or optimized for 386. The pattern `Op386<INSTRUCTION>` is evident.
* **`return rewriteValue386_Op386<INSTRUCTION>(v)`:**  This confirms the code generation aspect. Each `case` delegates to a specialized function, likely also generated, that handles the specific rewrite logic for that instruction.

**3. Inferring the High-Level Goal:**

Based on the filename and the function's structure, the primary goal of `rewrite386.go` is **low-level code generation and optimization for the 386 architecture within the Go compiler's SSA framework.** It takes generic SSA operations and transforms them into equivalent or more efficient 386 machine instructions.

**4. Identifying Key Functional Areas (Based on the `case` list):**

By scanning the `case` statements, we can categorize the kinds of operations being handled:

* **Arithmetic Operations:** `ADDL`, `ADCL`, `SUBL`, `SBBL`, `MULL`, `DIVL` (implied by `DIVW`, `DIVWU`, `DIVLU`), `NEGL`. These are fundamental integer operations.
* **Bitwise Operations:** `ANDL`, `ORL`, `XORL`, `NOTL`, `SHLL`, `SHRL`, `SARL`, `ROLL`, `RORL` (implied by `ROLB`, `ROLL`, `ROLW`).
* **Floating-Point Operations:** `ADDSS`, `ADDSD`, `SUBSS`, `SUBSD`, `MULSS`, `MULSD`, `DIVSS`, `DIVSD`, `SQRTSD`, `SQRTSS`, `CVT...` (conversion instructions).
* **Memory Access:** `MOVBload`, `MOVBstore`, `MOVLload`, `MOVLstore`, `MOVSDload`, `MOVSDstore`, `MOVSSload`, `MOVSSstore`, `LEAL` (Load Effective Address). The presence of "load" and "store" variants is significant.
* **Comparisons and Conditional Flags:** `CMPB`, `CMPL`, `CMPW`, `SETA`, `SETB`, `SETEQ`, etc. These relate to setting CPU flags based on comparisons.
* **Control Flow (Indirectly):** `CALLclosure`, `CALLinter`, `CALLstatic`, `CALLtail`. These are call instructions, indicating function calls.
* **Conversions and Extensions:** `MOVBLSX`, `MOVBLZX`, `MOVWLSX`, `MOVWLZX`, `OpSignExt...`, `OpZeroExt...`
* **Higher-Level Go Operations (Mapped to 386):** `OpAdd16`, `OpAdd32`, `OpEq32`, `OpLoad`, `OpStore`, etc. This is the crucial part – bridging the gap between Go's abstract operations and the concrete 386 instructions.

**5. Reasoning about Specific Go Features (Example - Addition):**

Let's take `OpAdd32` as an example. The code shows:

```go
case OpAdd32:
    v.Op = Op386ADDL
    return true
```

This implies:

* **Go Feature:** The `OpAdd32` represents 32-bit integer addition in Go's intermediate representation.
* **386 Instruction:**  The 386 instruction for 32-bit integer addition is `ADDL`.
* **Rewrite Rule:**  The rewrite rule simply replaces the generic `OpAdd32` with the architecture-specific `Op386ADDL`.

**6. Hypothetical Input/Output (Example - Addition):**

* **Input (SSA Value `v`):**  `v.Op = OpAdd32`, `v.Args = [arg1, arg2]` (where `arg1` and `arg2` are other SSA values representing the operands).
* **Output (After `rewriteValue386`):** `v.Op = Op386ADDL`, `v.Args = [arg1, arg2]`. The core operation is changed to the 386 instruction.

**7. Absence of Command-Line Arguments:**

The provided code snippet doesn't directly process command-line arguments. This part of the compilation process likely occurs elsewhere (e.g., in the `compile` package).

**8. Potential Pitfalls (General SSA Considerations):**

While this specific snippet doesn't show obvious user errors, common pitfalls in SSA manipulation (and thus potentially in the rules that generate this code) include:

* **Incorrect Type Handling:**  Mismatched types between Go's representation and the 386 instructions.
* **Incorrect Flag Handling:**  Not properly setting or interpreting CPU flags, especially for conditional operations.
* **Missing Optimizations:**  Failing to identify opportunities for more efficient 386 instructions.
* **Introducing Regressions:**  Changes to rewrite rules might unintentionally break existing correct code generation.

**9. Summarizing the Functionality for Part 1:**

The first part of `rewrite386.go` (as presented) focuses on the initial stage of rewriting SSA values for the 386 architecture. It establishes the core `rewriteValue386` function and handles a significant portion of basic arithmetic, logical, memory access, and comparison operations. It essentially maps many fundamental Go operations onto their direct 386 equivalents or sets the stage for further, more specific rewrites handled in the subsequent parts of the file. The use of generated code is a key characteristic.
The provided code snippet is the first part of a Go source file, `rewrite386.go`, which is part of the Go compiler's internal implementation. Specifically, it resides within the `ssa` package, which deals with Static Single Assignment form, an intermediate representation used during compilation.

**Functionality of Part 1:**

This part of the code defines a central function `rewriteValue386(v *Value) bool` and implements the initial set of rewrite rules for transforming SSA `Value` objects when targeting the 386 architecture. In essence, it performs the following:

1. **Operation-Specific Rewrites:** The core of the function is a large `switch` statement that examines the `Op` field of an SSA `Value`. Each `case` corresponds to a specific operation, either a generic Go operation (like `OpAdd32`, `OpLoad`) or a 386-specific instruction (like `Op386ADDL`, `Op386MOVLload`).

2. **Lowering High-Level Operations:**  Many of the `case` statements handle high-level Go operations by *lowering* them to their corresponding 386 instructions. For example:
   - `OpAdd32` is rewritten to `Op386ADDL`.
   - `OpLoad` will likely be further rewritten in subsequent parts, but this section might perform initial transformations related to loading.

3. **Introducing 386-Specific Optimizations:**  Some rewrites go beyond simple lowering and introduce optimizations specific to the 386 architecture. Examples include:
   - Rewriting `ADDL x (MOVLconst [c])` to `ADDLconst [c] x`.
   - Utilizing `LEAL` (Load Effective Address) for certain addition patterns.
   - Merging load operations into arithmetic operations like `ADDLload`.

4. **Handling Constants:** There are specific cases for operations involving constants, potentially leading to more efficient constant-based 386 instructions.

5. **Delegating to Specialized Rewrite Functions:** For many 386-specific instructions, the `switch` statement calls dedicated functions like `rewriteValue386_Op386ADCL(v)`. The provided snippet only shows the declaration of these functions, their actual implementations are likely in the subsequent parts of the file.

**Inferred Go Language Feature Implementation (with Examples):**

This part of `rewrite386.go` deals with the fundamental building blocks of many Go language features. Here are a few examples:

* **Integer Arithmetic:** The `OpAdd32`, `OpSub32`, `OpMul32`, `OpDiv32` cases (and their 8, 16 counterparts) are directly involved in implementing Go's integer arithmetic operations.

   ```go
   // Example of Go code using integer addition
   package main

   import "fmt"

   func main() {
       a := 10
       b := 5
       sum := a + b
       fmt.Println(sum) // Output: 15
   }
   ```
   The compiler, during its SSA phase, would represent the `a + b` operation as an `OpAdd32` (assuming 32-bit integers). This part of `rewrite386.go` would transform that `OpAdd32` into the 386 `ADDL` instruction.

* **Memory Access (Loads and Stores):** `OpLoad` and `OpStore` are crucial for accessing data in memory.

   ```go
   // Example of Go code using memory access
   package main

   import "fmt"

   func main() {
       x := 42
       ptr := &x
       value := *ptr // Load operation
       fmt.Println(value)

       *ptr = 100 // Store operation
       fmt.Println(x)
   }
   ```
   The `*ptr` would be represented by an `OpLoad`, and `*ptr = 100` by an `OpStore`. This part of the code initiates the process of converting these high-level operations into 386 `MOVLload` or `MOVLstore` instructions.

* **Comparisons:** `OpEq32`, `OpLess32`, etc., are used to implement Go's comparison operators (`==`, `<`, `>`, etc.).

   ```go
   // Example of Go code using comparison
   package main

   import "fmt"

   func main() {
       a := 10
       b := 5
       if a > b {
           fmt.Println("a is greater than b")
       }
   }
   ```
   The `a > b` would be represented using a comparison operation like `OpLess32` (and potentially inverted flags). This part of the code starts the process of translating this into 386 `CMPL` instructions and setting flags.

**Code Reasoning (with Assumptions):**

Let's look at a specific rewrite rule:

```go
	case OpAdd32:
		v.Op = Op386ADDL
		return true
```

* **Assumption:** We are dealing with a 32-bit integer addition operation in the SSA representation.
* **Input `v`:** An SSA `Value` object where `v.Op` is `OpAdd32`. The `v.Args` would contain the two operands for the addition.
* **Output `v`:** The `v.Op` is changed to `Op386ADDL`. The `v.Args` remain the same.
* **Reasoning:** This rule directly maps the generic 32-bit addition operation to the corresponding 386 instruction. Further rewrites in later parts of the file will likely refine the operands and potentially handle different addressing modes.

Another example:

```go
	// match: (ADDL x (MOVLconst <t> [c]))
	// cond: !t.IsPtr()
	// result: (ADDLconst [c] x)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			if v_1.Op != Op386MOVLconst {
				continue
			}
			t := v_1.Type
			c := auxIntToInt32(v_1.AuxInt)
			if !(!t.IsPtr()) {
				continue
			}
			v.reset(Op386ADDLconst)
			v.AuxInt = int32ToAuxInt(c)
			v.AddArg(x)
			return true
		}
		break
	}
```

* **Assumption:** We are in a phase where some operands might be represented as "move constant" operations (`MOVLconst`).
* **Input `v`:** An SSA `Value` object where `v.Op` is `Op386ADDL`, and one of its arguments is a `Op386MOVLconst`.
* **Output `v`:** The `v.Op` is changed to `Op386ADDLconst`. The constant value `c` is moved to the `AuxInt` field of `v`, and the other operand becomes the argument.
* **Reasoning:** This is an optimization. The 386 architecture has `ADD` instructions that can directly add a constant to a register or memory location. This rewrite makes the operation more explicit for the 386 backend. The `!t.IsPtr()` condition suggests this optimization is generally safe for non-pointer types, preventing accidental modification of addresses.

**Command-Line Parameter Handling:**

This specific code snippet doesn't directly handle command-line parameters. Command-line arguments for the Go compiler are typically processed in the `main` package of the `cmd/compile` directory and influence the overall compilation process, potentially affecting which rewrite rules are applied or how aggressively optimizations are performed.

**Common User Errors:**

Since this is compiler-internal code, it's not directly used by end-users writing Go programs. However, if there were errors in these rewrite rules, it could lead to:

* **Incorrect Code Generation:** The compiler might generate 386 assembly that doesn't correctly implement the intended Go code. This could manifest as bugs or unexpected behavior in the compiled program.
* **Performance Issues:**  Inefficient rewrite rules could lead to suboptimal 386 assembly, resulting in slower execution times.
* **Compiler Crashes:** In severe cases, incorrect manipulation of the SSA representation could lead to compiler crashes.

**Summary of Functionality (Part 1):**

In summary, the first part of `go/src/cmd/compile/internal/ssa/rewrite386.go` defines the initial set of rewrite rules within the Go compiler's SSA framework for the 386 architecture. Its primary functions are:

- To **lower** high-level Go operations into their corresponding 386 instructions.
- To apply **basic 386-specific optimizations**, such as utilizing constant-specific instructions and the `LEAL` instruction.
- To **prepare the SSA representation** for subsequent, more specialized rewrite passes.

This part lays the groundwork for translating Go code into efficient 386 machine code by transforming the architecture-independent SSA representation into a form that is closer to the target architecture's instruction set.

### 提示词
```
这是路径为go/src/cmd/compile/internal/ssa/rewrite386.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
这是第1部分，共5部分，请归纳一下它的功能
```

### 源代码
```go
// Code generated from _gen/386.rules using 'go generate'; DO NOT EDIT.

package ssa

import "math"
import "cmd/compile/internal/types"

func rewriteValue386(v *Value) bool {
	switch v.Op {
	case Op386ADCL:
		return rewriteValue386_Op386ADCL(v)
	case Op386ADDL:
		return rewriteValue386_Op386ADDL(v)
	case Op386ADDLcarry:
		return rewriteValue386_Op386ADDLcarry(v)
	case Op386ADDLconst:
		return rewriteValue386_Op386ADDLconst(v)
	case Op386ADDLconstmodify:
		return rewriteValue386_Op386ADDLconstmodify(v)
	case Op386ADDLload:
		return rewriteValue386_Op386ADDLload(v)
	case Op386ADDLmodify:
		return rewriteValue386_Op386ADDLmodify(v)
	case Op386ADDSD:
		return rewriteValue386_Op386ADDSD(v)
	case Op386ADDSDload:
		return rewriteValue386_Op386ADDSDload(v)
	case Op386ADDSS:
		return rewriteValue386_Op386ADDSS(v)
	case Op386ADDSSload:
		return rewriteValue386_Op386ADDSSload(v)
	case Op386ANDL:
		return rewriteValue386_Op386ANDL(v)
	case Op386ANDLconst:
		return rewriteValue386_Op386ANDLconst(v)
	case Op386ANDLconstmodify:
		return rewriteValue386_Op386ANDLconstmodify(v)
	case Op386ANDLload:
		return rewriteValue386_Op386ANDLload(v)
	case Op386ANDLmodify:
		return rewriteValue386_Op386ANDLmodify(v)
	case Op386CMPB:
		return rewriteValue386_Op386CMPB(v)
	case Op386CMPBconst:
		return rewriteValue386_Op386CMPBconst(v)
	case Op386CMPBload:
		return rewriteValue386_Op386CMPBload(v)
	case Op386CMPL:
		return rewriteValue386_Op386CMPL(v)
	case Op386CMPLconst:
		return rewriteValue386_Op386CMPLconst(v)
	case Op386CMPLload:
		return rewriteValue386_Op386CMPLload(v)
	case Op386CMPW:
		return rewriteValue386_Op386CMPW(v)
	case Op386CMPWconst:
		return rewriteValue386_Op386CMPWconst(v)
	case Op386CMPWload:
		return rewriteValue386_Op386CMPWload(v)
	case Op386DIVSD:
		return rewriteValue386_Op386DIVSD(v)
	case Op386DIVSDload:
		return rewriteValue386_Op386DIVSDload(v)
	case Op386DIVSS:
		return rewriteValue386_Op386DIVSS(v)
	case Op386DIVSSload:
		return rewriteValue386_Op386DIVSSload(v)
	case Op386LEAL:
		return rewriteValue386_Op386LEAL(v)
	case Op386LEAL1:
		return rewriteValue386_Op386LEAL1(v)
	case Op386LEAL2:
		return rewriteValue386_Op386LEAL2(v)
	case Op386LEAL4:
		return rewriteValue386_Op386LEAL4(v)
	case Op386LEAL8:
		return rewriteValue386_Op386LEAL8(v)
	case Op386MOVBLSX:
		return rewriteValue386_Op386MOVBLSX(v)
	case Op386MOVBLSXload:
		return rewriteValue386_Op386MOVBLSXload(v)
	case Op386MOVBLZX:
		return rewriteValue386_Op386MOVBLZX(v)
	case Op386MOVBload:
		return rewriteValue386_Op386MOVBload(v)
	case Op386MOVBstore:
		return rewriteValue386_Op386MOVBstore(v)
	case Op386MOVBstoreconst:
		return rewriteValue386_Op386MOVBstoreconst(v)
	case Op386MOVLload:
		return rewriteValue386_Op386MOVLload(v)
	case Op386MOVLstore:
		return rewriteValue386_Op386MOVLstore(v)
	case Op386MOVLstoreconst:
		return rewriteValue386_Op386MOVLstoreconst(v)
	case Op386MOVSDconst:
		return rewriteValue386_Op386MOVSDconst(v)
	case Op386MOVSDload:
		return rewriteValue386_Op386MOVSDload(v)
	case Op386MOVSDstore:
		return rewriteValue386_Op386MOVSDstore(v)
	case Op386MOVSSconst:
		return rewriteValue386_Op386MOVSSconst(v)
	case Op386MOVSSload:
		return rewriteValue386_Op386MOVSSload(v)
	case Op386MOVSSstore:
		return rewriteValue386_Op386MOVSSstore(v)
	case Op386MOVWLSX:
		return rewriteValue386_Op386MOVWLSX(v)
	case Op386MOVWLSXload:
		return rewriteValue386_Op386MOVWLSXload(v)
	case Op386MOVWLZX:
		return rewriteValue386_Op386MOVWLZX(v)
	case Op386MOVWload:
		return rewriteValue386_Op386MOVWload(v)
	case Op386MOVWstore:
		return rewriteValue386_Op386MOVWstore(v)
	case Op386MOVWstoreconst:
		return rewriteValue386_Op386MOVWstoreconst(v)
	case Op386MULL:
		return rewriteValue386_Op386MULL(v)
	case Op386MULLconst:
		return rewriteValue386_Op386MULLconst(v)
	case Op386MULLload:
		return rewriteValue386_Op386MULLload(v)
	case Op386MULSD:
		return rewriteValue386_Op386MULSD(v)
	case Op386MULSDload:
		return rewriteValue386_Op386MULSDload(v)
	case Op386MULSS:
		return rewriteValue386_Op386MULSS(v)
	case Op386MULSSload:
		return rewriteValue386_Op386MULSSload(v)
	case Op386NEGL:
		return rewriteValue386_Op386NEGL(v)
	case Op386NOTL:
		return rewriteValue386_Op386NOTL(v)
	case Op386ORL:
		return rewriteValue386_Op386ORL(v)
	case Op386ORLconst:
		return rewriteValue386_Op386ORLconst(v)
	case Op386ORLconstmodify:
		return rewriteValue386_Op386ORLconstmodify(v)
	case Op386ORLload:
		return rewriteValue386_Op386ORLload(v)
	case Op386ORLmodify:
		return rewriteValue386_Op386ORLmodify(v)
	case Op386ROLB:
		return rewriteValue386_Op386ROLB(v)
	case Op386ROLBconst:
		return rewriteValue386_Op386ROLBconst(v)
	case Op386ROLL:
		return rewriteValue386_Op386ROLL(v)
	case Op386ROLLconst:
		return rewriteValue386_Op386ROLLconst(v)
	case Op386ROLW:
		return rewriteValue386_Op386ROLW(v)
	case Op386ROLWconst:
		return rewriteValue386_Op386ROLWconst(v)
	case Op386SARB:
		return rewriteValue386_Op386SARB(v)
	case Op386SARBconst:
		return rewriteValue386_Op386SARBconst(v)
	case Op386SARL:
		return rewriteValue386_Op386SARL(v)
	case Op386SARLconst:
		return rewriteValue386_Op386SARLconst(v)
	case Op386SARW:
		return rewriteValue386_Op386SARW(v)
	case Op386SARWconst:
		return rewriteValue386_Op386SARWconst(v)
	case Op386SBBL:
		return rewriteValue386_Op386SBBL(v)
	case Op386SBBLcarrymask:
		return rewriteValue386_Op386SBBLcarrymask(v)
	case Op386SETA:
		return rewriteValue386_Op386SETA(v)
	case Op386SETAE:
		return rewriteValue386_Op386SETAE(v)
	case Op386SETB:
		return rewriteValue386_Op386SETB(v)
	case Op386SETBE:
		return rewriteValue386_Op386SETBE(v)
	case Op386SETEQ:
		return rewriteValue386_Op386SETEQ(v)
	case Op386SETG:
		return rewriteValue386_Op386SETG(v)
	case Op386SETGE:
		return rewriteValue386_Op386SETGE(v)
	case Op386SETL:
		return rewriteValue386_Op386SETL(v)
	case Op386SETLE:
		return rewriteValue386_Op386SETLE(v)
	case Op386SETNE:
		return rewriteValue386_Op386SETNE(v)
	case Op386SHLL:
		return rewriteValue386_Op386SHLL(v)
	case Op386SHLLconst:
		return rewriteValue386_Op386SHLLconst(v)
	case Op386SHRB:
		return rewriteValue386_Op386SHRB(v)
	case Op386SHRBconst:
		return rewriteValue386_Op386SHRBconst(v)
	case Op386SHRL:
		return rewriteValue386_Op386SHRL(v)
	case Op386SHRLconst:
		return rewriteValue386_Op386SHRLconst(v)
	case Op386SHRW:
		return rewriteValue386_Op386SHRW(v)
	case Op386SHRWconst:
		return rewriteValue386_Op386SHRWconst(v)
	case Op386SUBL:
		return rewriteValue386_Op386SUBL(v)
	case Op386SUBLcarry:
		return rewriteValue386_Op386SUBLcarry(v)
	case Op386SUBLconst:
		return rewriteValue386_Op386SUBLconst(v)
	case Op386SUBLload:
		return rewriteValue386_Op386SUBLload(v)
	case Op386SUBLmodify:
		return rewriteValue386_Op386SUBLmodify(v)
	case Op386SUBSD:
		return rewriteValue386_Op386SUBSD(v)
	case Op386SUBSDload:
		return rewriteValue386_Op386SUBSDload(v)
	case Op386SUBSS:
		return rewriteValue386_Op386SUBSS(v)
	case Op386SUBSSload:
		return rewriteValue386_Op386SUBSSload(v)
	case Op386XORL:
		return rewriteValue386_Op386XORL(v)
	case Op386XORLconst:
		return rewriteValue386_Op386XORLconst(v)
	case Op386XORLconstmodify:
		return rewriteValue386_Op386XORLconstmodify(v)
	case Op386XORLload:
		return rewriteValue386_Op386XORLload(v)
	case Op386XORLmodify:
		return rewriteValue386_Op386XORLmodify(v)
	case OpAdd16:
		v.Op = Op386ADDL
		return true
	case OpAdd32:
		v.Op = Op386ADDL
		return true
	case OpAdd32F:
		v.Op = Op386ADDSS
		return true
	case OpAdd32carry:
		v.Op = Op386ADDLcarry
		return true
	case OpAdd32withcarry:
		v.Op = Op386ADCL
		return true
	case OpAdd64F:
		v.Op = Op386ADDSD
		return true
	case OpAdd8:
		v.Op = Op386ADDL
		return true
	case OpAddPtr:
		v.Op = Op386ADDL
		return true
	case OpAddr:
		return rewriteValue386_OpAddr(v)
	case OpAnd16:
		v.Op = Op386ANDL
		return true
	case OpAnd32:
		v.Op = Op386ANDL
		return true
	case OpAnd8:
		v.Op = Op386ANDL
		return true
	case OpAndB:
		v.Op = Op386ANDL
		return true
	case OpAvg32u:
		v.Op = Op386AVGLU
		return true
	case OpBswap16:
		return rewriteValue386_OpBswap16(v)
	case OpBswap32:
		v.Op = Op386BSWAPL
		return true
	case OpClosureCall:
		v.Op = Op386CALLclosure
		return true
	case OpCom16:
		v.Op = Op386NOTL
		return true
	case OpCom32:
		v.Op = Op386NOTL
		return true
	case OpCom8:
		v.Op = Op386NOTL
		return true
	case OpConst16:
		return rewriteValue386_OpConst16(v)
	case OpConst32:
		v.Op = Op386MOVLconst
		return true
	case OpConst32F:
		v.Op = Op386MOVSSconst
		return true
	case OpConst64F:
		v.Op = Op386MOVSDconst
		return true
	case OpConst8:
		return rewriteValue386_OpConst8(v)
	case OpConstBool:
		return rewriteValue386_OpConstBool(v)
	case OpConstNil:
		return rewriteValue386_OpConstNil(v)
	case OpCtz16:
		return rewriteValue386_OpCtz16(v)
	case OpCtz16NonZero:
		v.Op = Op386BSFL
		return true
	case OpCtz32:
		v.Op = Op386LoweredCtz32
		return true
	case OpCtz32NonZero:
		v.Op = Op386BSFL
		return true
	case OpCtz64On32:
		v.Op = Op386LoweredCtz64
		return true
	case OpCtz8:
		return rewriteValue386_OpCtz8(v)
	case OpCtz8NonZero:
		v.Op = Op386BSFL
		return true
	case OpCvt32Fto32:
		v.Op = Op386CVTTSS2SL
		return true
	case OpCvt32Fto64F:
		v.Op = Op386CVTSS2SD
		return true
	case OpCvt32to32F:
		v.Op = Op386CVTSL2SS
		return true
	case OpCvt32to64F:
		v.Op = Op386CVTSL2SD
		return true
	case OpCvt64Fto32:
		v.Op = Op386CVTTSD2SL
		return true
	case OpCvt64Fto32F:
		v.Op = Op386CVTSD2SS
		return true
	case OpCvtBoolToUint8:
		v.Op = OpCopy
		return true
	case OpDiv16:
		v.Op = Op386DIVW
		return true
	case OpDiv16u:
		v.Op = Op386DIVWU
		return true
	case OpDiv32:
		v.Op = Op386DIVL
		return true
	case OpDiv32F:
		v.Op = Op386DIVSS
		return true
	case OpDiv32u:
		v.Op = Op386DIVLU
		return true
	case OpDiv64F:
		v.Op = Op386DIVSD
		return true
	case OpDiv8:
		return rewriteValue386_OpDiv8(v)
	case OpDiv8u:
		return rewriteValue386_OpDiv8u(v)
	case OpEq16:
		return rewriteValue386_OpEq16(v)
	case OpEq32:
		return rewriteValue386_OpEq32(v)
	case OpEq32F:
		return rewriteValue386_OpEq32F(v)
	case OpEq64F:
		return rewriteValue386_OpEq64F(v)
	case OpEq8:
		return rewriteValue386_OpEq8(v)
	case OpEqB:
		return rewriteValue386_OpEqB(v)
	case OpEqPtr:
		return rewriteValue386_OpEqPtr(v)
	case OpGetCallerPC:
		v.Op = Op386LoweredGetCallerPC
		return true
	case OpGetCallerSP:
		v.Op = Op386LoweredGetCallerSP
		return true
	case OpGetClosurePtr:
		v.Op = Op386LoweredGetClosurePtr
		return true
	case OpGetG:
		v.Op = Op386LoweredGetG
		return true
	case OpHmul32:
		v.Op = Op386HMULL
		return true
	case OpHmul32u:
		v.Op = Op386HMULLU
		return true
	case OpInterCall:
		v.Op = Op386CALLinter
		return true
	case OpIsInBounds:
		return rewriteValue386_OpIsInBounds(v)
	case OpIsNonNil:
		return rewriteValue386_OpIsNonNil(v)
	case OpIsSliceInBounds:
		return rewriteValue386_OpIsSliceInBounds(v)
	case OpLeq16:
		return rewriteValue386_OpLeq16(v)
	case OpLeq16U:
		return rewriteValue386_OpLeq16U(v)
	case OpLeq32:
		return rewriteValue386_OpLeq32(v)
	case OpLeq32F:
		return rewriteValue386_OpLeq32F(v)
	case OpLeq32U:
		return rewriteValue386_OpLeq32U(v)
	case OpLeq64F:
		return rewriteValue386_OpLeq64F(v)
	case OpLeq8:
		return rewriteValue386_OpLeq8(v)
	case OpLeq8U:
		return rewriteValue386_OpLeq8U(v)
	case OpLess16:
		return rewriteValue386_OpLess16(v)
	case OpLess16U:
		return rewriteValue386_OpLess16U(v)
	case OpLess32:
		return rewriteValue386_OpLess32(v)
	case OpLess32F:
		return rewriteValue386_OpLess32F(v)
	case OpLess32U:
		return rewriteValue386_OpLess32U(v)
	case OpLess64F:
		return rewriteValue386_OpLess64F(v)
	case OpLess8:
		return rewriteValue386_OpLess8(v)
	case OpLess8U:
		return rewriteValue386_OpLess8U(v)
	case OpLoad:
		return rewriteValue386_OpLoad(v)
	case OpLocalAddr:
		return rewriteValue386_OpLocalAddr(v)
	case OpLsh16x16:
		return rewriteValue386_OpLsh16x16(v)
	case OpLsh16x32:
		return rewriteValue386_OpLsh16x32(v)
	case OpLsh16x64:
		return rewriteValue386_OpLsh16x64(v)
	case OpLsh16x8:
		return rewriteValue386_OpLsh16x8(v)
	case OpLsh32x16:
		return rewriteValue386_OpLsh32x16(v)
	case OpLsh32x32:
		return rewriteValue386_OpLsh32x32(v)
	case OpLsh32x64:
		return rewriteValue386_OpLsh32x64(v)
	case OpLsh32x8:
		return rewriteValue386_OpLsh32x8(v)
	case OpLsh8x16:
		return rewriteValue386_OpLsh8x16(v)
	case OpLsh8x32:
		return rewriteValue386_OpLsh8x32(v)
	case OpLsh8x64:
		return rewriteValue386_OpLsh8x64(v)
	case OpLsh8x8:
		return rewriteValue386_OpLsh8x8(v)
	case OpMod16:
		v.Op = Op386MODW
		return true
	case OpMod16u:
		v.Op = Op386MODWU
		return true
	case OpMod32:
		v.Op = Op386MODL
		return true
	case OpMod32u:
		v.Op = Op386MODLU
		return true
	case OpMod8:
		return rewriteValue386_OpMod8(v)
	case OpMod8u:
		return rewriteValue386_OpMod8u(v)
	case OpMove:
		return rewriteValue386_OpMove(v)
	case OpMul16:
		v.Op = Op386MULL
		return true
	case OpMul32:
		v.Op = Op386MULL
		return true
	case OpMul32F:
		v.Op = Op386MULSS
		return true
	case OpMul32uhilo:
		v.Op = Op386MULLQU
		return true
	case OpMul64F:
		v.Op = Op386MULSD
		return true
	case OpMul8:
		v.Op = Op386MULL
		return true
	case OpNeg16:
		v.Op = Op386NEGL
		return true
	case OpNeg32:
		v.Op = Op386NEGL
		return true
	case OpNeg32F:
		return rewriteValue386_OpNeg32F(v)
	case OpNeg64F:
		return rewriteValue386_OpNeg64F(v)
	case OpNeg8:
		v.Op = Op386NEGL
		return true
	case OpNeq16:
		return rewriteValue386_OpNeq16(v)
	case OpNeq32:
		return rewriteValue386_OpNeq32(v)
	case OpNeq32F:
		return rewriteValue386_OpNeq32F(v)
	case OpNeq64F:
		return rewriteValue386_OpNeq64F(v)
	case OpNeq8:
		return rewriteValue386_OpNeq8(v)
	case OpNeqB:
		return rewriteValue386_OpNeqB(v)
	case OpNeqPtr:
		return rewriteValue386_OpNeqPtr(v)
	case OpNilCheck:
		v.Op = Op386LoweredNilCheck
		return true
	case OpNot:
		return rewriteValue386_OpNot(v)
	case OpOffPtr:
		return rewriteValue386_OpOffPtr(v)
	case OpOr16:
		v.Op = Op386ORL
		return true
	case OpOr32:
		v.Op = Op386ORL
		return true
	case OpOr8:
		v.Op = Op386ORL
		return true
	case OpOrB:
		v.Op = Op386ORL
		return true
	case OpPanicBounds:
		return rewriteValue386_OpPanicBounds(v)
	case OpPanicExtend:
		return rewriteValue386_OpPanicExtend(v)
	case OpRotateLeft16:
		v.Op = Op386ROLW
		return true
	case OpRotateLeft32:
		v.Op = Op386ROLL
		return true
	case OpRotateLeft8:
		v.Op = Op386ROLB
		return true
	case OpRound32F:
		v.Op = OpCopy
		return true
	case OpRound64F:
		v.Op = OpCopy
		return true
	case OpRsh16Ux16:
		return rewriteValue386_OpRsh16Ux16(v)
	case OpRsh16Ux32:
		return rewriteValue386_OpRsh16Ux32(v)
	case OpRsh16Ux64:
		return rewriteValue386_OpRsh16Ux64(v)
	case OpRsh16Ux8:
		return rewriteValue386_OpRsh16Ux8(v)
	case OpRsh16x16:
		return rewriteValue386_OpRsh16x16(v)
	case OpRsh16x32:
		return rewriteValue386_OpRsh16x32(v)
	case OpRsh16x64:
		return rewriteValue386_OpRsh16x64(v)
	case OpRsh16x8:
		return rewriteValue386_OpRsh16x8(v)
	case OpRsh32Ux16:
		return rewriteValue386_OpRsh32Ux16(v)
	case OpRsh32Ux32:
		return rewriteValue386_OpRsh32Ux32(v)
	case OpRsh32Ux64:
		return rewriteValue386_OpRsh32Ux64(v)
	case OpRsh32Ux8:
		return rewriteValue386_OpRsh32Ux8(v)
	case OpRsh32x16:
		return rewriteValue386_OpRsh32x16(v)
	case OpRsh32x32:
		return rewriteValue386_OpRsh32x32(v)
	case OpRsh32x64:
		return rewriteValue386_OpRsh32x64(v)
	case OpRsh32x8:
		return rewriteValue386_OpRsh32x8(v)
	case OpRsh8Ux16:
		return rewriteValue386_OpRsh8Ux16(v)
	case OpRsh8Ux32:
		return rewriteValue386_OpRsh8Ux32(v)
	case OpRsh8Ux64:
		return rewriteValue386_OpRsh8Ux64(v)
	case OpRsh8Ux8:
		return rewriteValue386_OpRsh8Ux8(v)
	case OpRsh8x16:
		return rewriteValue386_OpRsh8x16(v)
	case OpRsh8x32:
		return rewriteValue386_OpRsh8x32(v)
	case OpRsh8x64:
		return rewriteValue386_OpRsh8x64(v)
	case OpRsh8x8:
		return rewriteValue386_OpRsh8x8(v)
	case OpSelect0:
		return rewriteValue386_OpSelect0(v)
	case OpSelect1:
		return rewriteValue386_OpSelect1(v)
	case OpSignExt16to32:
		v.Op = Op386MOVWLSX
		return true
	case OpSignExt8to16:
		v.Op = Op386MOVBLSX
		return true
	case OpSignExt8to32:
		v.Op = Op386MOVBLSX
		return true
	case OpSignmask:
		return rewriteValue386_OpSignmask(v)
	case OpSlicemask:
		return rewriteValue386_OpSlicemask(v)
	case OpSqrt:
		v.Op = Op386SQRTSD
		return true
	case OpSqrt32:
		v.Op = Op386SQRTSS
		return true
	case OpStaticCall:
		v.Op = Op386CALLstatic
		return true
	case OpStore:
		return rewriteValue386_OpStore(v)
	case OpSub16:
		v.Op = Op386SUBL
		return true
	case OpSub32:
		v.Op = Op386SUBL
		return true
	case OpSub32F:
		v.Op = Op386SUBSS
		return true
	case OpSub32carry:
		v.Op = Op386SUBLcarry
		return true
	case OpSub32withcarry:
		v.Op = Op386SBBL
		return true
	case OpSub64F:
		v.Op = Op386SUBSD
		return true
	case OpSub8:
		v.Op = Op386SUBL
		return true
	case OpSubPtr:
		v.Op = Op386SUBL
		return true
	case OpTailCall:
		v.Op = Op386CALLtail
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
		v.Op = Op386LoweredWB
		return true
	case OpXor16:
		v.Op = Op386XORL
		return true
	case OpXor32:
		v.Op = Op386XORL
		return true
	case OpXor8:
		v.Op = Op386XORL
		return true
	case OpZero:
		return rewriteValue386_OpZero(v)
	case OpZeroExt16to32:
		v.Op = Op386MOVWLZX
		return true
	case OpZeroExt8to16:
		v.Op = Op386MOVBLZX
		return true
	case OpZeroExt8to32:
		v.Op = Op386MOVBLZX
		return true
	case OpZeromask:
		return rewriteValue386_OpZeromask(v)
	}
	return false
}
func rewriteValue386_Op386ADCL(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (ADCL x (MOVLconst [c]) f)
	// result: (ADCLconst [c] x f)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			if v_1.Op != Op386MOVLconst {
				continue
			}
			c := auxIntToInt32(v_1.AuxInt)
			f := v_2
			v.reset(Op386ADCLconst)
			v.AuxInt = int32ToAuxInt(c)
			v.AddArg2(x, f)
			return true
		}
		break
	}
	return false
}
func rewriteValue386_Op386ADDL(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (ADDL x (MOVLconst <t> [c]))
	// cond: !t.IsPtr()
	// result: (ADDLconst [c] x)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			if v_1.Op != Op386MOVLconst {
				continue
			}
			t := v_1.Type
			c := auxIntToInt32(v_1.AuxInt)
			if !(!t.IsPtr()) {
				continue
			}
			v.reset(Op386ADDLconst)
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
			if v_1.Op != Op386SHLLconst || auxIntToInt32(v_1.AuxInt) != 3 {
				continue
			}
			y := v_1.Args[0]
			v.reset(Op386LEAL8)
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
			if v_1.Op != Op386SHLLconst || auxIntToInt32(v_1.AuxInt) != 2 {
				continue
			}
			y := v_1.Args[0]
			v.reset(Op386LEAL4)
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
			if v_1.Op != Op386SHLLconst || auxIntToInt32(v_1.AuxInt) != 1 {
				continue
			}
			y := v_1.Args[0]
			v.reset(Op386LEAL2)
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
			if v_1.Op != Op386ADDL {
				continue
			}
			y := v_1.Args[1]
			if y != v_1.Args[0] {
				continue
			}
			v.reset(Op386LEAL2)
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
			if v_1.Op != Op386ADDL {
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
				v.reset(Op386LEAL2)
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
			if v_0.Op != Op386ADDLconst {
				continue
			}
			c := auxIntToInt32(v_0.AuxInt)
			x := v_0.Args[0]
			y := v_1
			v.reset(Op386LEAL1)
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
			if v_1.Op != Op386LEAL {
				continue
			}
			c := auxIntToInt32(v_1.AuxInt)
			s := auxToSym(v_1.Aux)
			y := v_1.Args[0]
			if !(x.Op != OpSB && y.Op != OpSB) {
				continue
			}
			v.reset(Op386LEAL1)
			v.AuxInt = int32ToAuxInt(c)
			v.Aux = symToAux(s)
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
			if l.Op != Op386MOVLload {
				continue
			}
			off := auxIntToInt32(l.AuxInt)
			sym := auxToSym(l.Aux)
			mem := l.Args[1]
			ptr := l.Args[0]
			if !(canMergeLoadClobber(v, l, x) && clobber(l)) {
				continue
			}
			v.reset(Op386ADDLload)
			v.AuxInt = int32ToAuxInt(off)
			v.Aux = symToAux(sym)
			v.AddArg3(x, ptr, mem)
			return true
		}
		break
	}
	// match: (ADDL x (NEGL y))
	// result: (SUBL x y)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			if v_1.Op != Op386NEGL {
				continue
			}
			y := v_1.Args[0]
			v.reset(Op386SUBL)
			v.AddArg2(x, y)
			return true
		}
		break
	}
	return false
}
func rewriteValue386_Op386ADDLcarry(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (ADDLcarry x (MOVLconst [c]))
	// result: (ADDLconstcarry [c] x)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			if v_1.Op != Op386MOVLconst {
				continue
			}
			c := auxIntToInt32(v_1.AuxInt)
			v.reset(Op386ADDLconstcarry)
			v.AuxInt = int32ToAuxInt(c)
			v.AddArg(x)
			return true
		}
		break
	}
	return false
}
func rewriteValue386_Op386ADDLconst(v *Value) bool {
	v_0 := v.Args[0]
	// match: (ADDLconst [c] (ADDL x y))
	// result: (LEAL1 [c] x y)
	for {
		c := auxIntToInt32(v.AuxInt)
		if v_0.Op != Op386ADDL {
			break
		}
		y := v_0.Args[1]
		x := v_0.Args[0]
		v.reset(Op386LEAL1)
		v.AuxInt = int32ToAuxInt(c)
		v.AddArg2(x, y)
		return true
	}
	// match: (ADDLconst [c] (LEAL [d] {s} x))
	// cond: is32Bit(int64(c)+int64(d))
	// result: (LEAL [c+d] {s} x)
	for {
		c := auxIntToInt32(v.AuxInt)
		if v_0.Op != Op386LEAL {
			break
		}
		d := auxIntToInt32(v_0.AuxInt)
		s := auxToSym(v_0.Aux)
		x := v_0.Args[0]
		if !(is32Bit(int64(c) + int64(d))) {
			break
		}
		v.reset(Op386LEAL)
		v.AuxInt = int32ToAuxInt(c + d)
		v.Aux = symToAux(s)
		v.AddArg(x)
		return true
	}
	// match: (ADDLconst [c] x:(SP))
	// result: (LEAL [c] x)
	for {
		c := auxIntToInt32(v.AuxInt)
		x := v_0
		if x.Op != OpSP {
			break
		}
		v.reset(Op386LEAL)
		v.AuxInt = int32ToAuxInt(c)
		v.AddArg(x)
		return true
	}
	// match: (ADDLconst [c] (LEAL1 [d] {s} x y))
	// cond: is32Bit(int64(c)+int64(d))
	// result: (LEAL1 [c+d] {s} x y)
	for {
		c := auxIntToInt32(v.AuxInt)
		if v_0.Op != Op386LEAL1 {
			break
		}
		d := auxIntToInt32(v_0.AuxInt)
		s := auxToSym(v_0.Aux)
		y := v_0.Args[1]
		x := v_0.Args[0]
		if !(is32Bit(int64(c) + int64(d))) {
			break
		}
		v.reset(Op386LEAL1)
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
		if v_0.Op != Op386LEAL2 {
			break
		}
		d := auxIntToInt32(v_0.AuxInt)
		s := auxToSym(v_0.Aux)
		y := v_0.Args[1]
		x := v_0.Args[0]
		if !(is32Bit(int64(c) + int64(d))) {
			break
		}
		v.reset(Op386LEAL2)
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
		if v_0.Op != Op386LEAL4 {
			break
		}
		d := auxIntToInt32(v_0.AuxInt)
		s := auxToSym(v_0.Aux)
		y := v_0.Args[1]
		x := v_0.Args[0]
		if !(is32Bit(int64(c) + int64(d))) {
			break
		}
		v.reset(Op386LEAL4)
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
		if v_0.Op != Op386LEAL8 {
			break
		}
		d := auxIntToInt32(v_0.AuxInt)
		s := auxToSym(v_0.Aux)
		y := v_0.Args[1]
		x := v_0.Args[0]
		if !(is32Bit(int64(c) + int64(d))) {
			break
		}
		v.reset(Op386LEAL8)
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
		if v_0.Op != Op386MOVLconst {
			break
		}
		d := auxIntToInt32(v_0.AuxInt)
		v.reset(Op386MOVLconst)
		v.AuxInt = int32ToAuxInt(c + d)
		return true
	}
	// match: (ADDLconst [c] (ADDLconst [d] x))
	// result: (ADDLconst [c+d] x)
	for {
		c := auxIntToInt32(v.AuxInt)
		if v_0.Op != Op386ADDLconst {
			break
		}
		d := auxIntToInt32(v_0.AuxInt)
		x := v_0.Args[0]
		v.reset(Op386ADDLconst)
		v.AuxInt = int32ToAuxInt(c + d)
		v.AddArg(x)
		return true
	}
	return false
}
func rewriteValue386_Op386ADDLconstmodify(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	config := b.Func.Config
	// match: (ADDLconstmodify [valoff1] {sym} (ADDLconst [off2] base) mem)
	// cond: valoff1.canAdd32(off2)
	// result: (ADDLconstmodify [valoff1.addOffset32(off2)] {sym} base mem)
	for {
		valoff1 := auxIntToValAndOff(v.AuxInt)
		sym := auxToSym(v.Aux)
		if v_0.Op != Op386ADDLconst {
			break
		}
		off2 := auxIntToInt32(v_0.AuxInt)
		base := v_0.Args[0]
		mem := v_1
		if !(valoff1.canAdd32(off2)) {
			break
		}
		v.reset(Op386ADDLconstmodify)
		v.AuxInt = valAndOffToAuxInt(valoff1.addOffset32(off2))
		v.Aux = symToAux(sym)
		v.AddArg2(base, mem)
		return true
	}
	// match: (ADDLconstmodify [valoff1] {sym1} (LEAL [off2] {sym2} base) mem)
	// cond: valoff1.canAdd32(off2) && canMergeSym(sym1, sym2) && (base.Op != OpSB || !config.ctxt.Flag_shared)
	// result: (ADDLconstmodify [valoff1.addOffset32(off2)] {mergeSym(sym1,sym2)} base mem)
	for {
		valoff1 := auxIntToValAndOff(v.AuxInt)
		sym1 := auxToSym(v.Aux)
		if v_0.Op != Op386LEAL {
			break
		}
		off2 := auxIntToInt32(v_0.AuxInt)
		sym2 := auxToSym(v_0.Aux)
		base := v_0.Args[0]
		mem := v_1
		if !(valoff1.canAdd32(off2) && canMergeSym(sym1, sym2) && (base.Op != OpSB || !config.ctxt.Flag_shared)) {
			break
		}
		v.reset(Op386ADDLconstmodify)
		v.AuxInt = valAndOffToAuxInt(valoff1.addOffset32(off2))
		v.Aux = symToAux(mergeSym(sym1, sym2))
		v.AddArg2(base, mem)
		return true
	}
	return false
}
func rewriteValue386_Op386ADDLload(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	config := b.Func.Config
	// match: (ADDLload [off1] {sym} val (ADDLconst [off2] base) mem)
	// cond: is32Bit(int64(off1)+int64(off2))
	// result: (ADDLload [off1+off2] {sym} val base mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		val := v_0
		if v_1.Op != Op386ADDLconst {
			break
		}
		off2 := auxIntToInt32(v_1.AuxInt)
		base := v_1.Args[0]
		mem := v_2
		if !(is32Bit(int64(off1) + int64(off2))) {
			break
		}
		v.reset(Op386ADDLload)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(sym)
		v.AddArg3(val, base, mem)
		return true
	}
	// match: (ADDLload [off1] {sym1} val (LEAL [off2] {sym2} base) mem)
	// cond: is32Bit(int64(off1)+int64(off2)) && canMergeSym(sym1, sym2) && (base.Op != OpSB || !config.ctxt.Flag_shared)
	// result: (ADDLload [off1+off2] {mergeSym(sym1,sym2)} val base mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym1 := auxToSym(v.Aux)
		val := v_0
		if v_1.Op != Op386LEAL {
			break
		}
		off2 := auxIntToInt32(v_1.AuxInt)
		sym2 := auxToSym(v_1.Aux)
		base := v_1.Args[0]
		mem := v_2
		if !(is32Bit(int64(off1)+int64(off2)) && canMergeSym(sym1, sym2) && (base.Op != OpSB || !config.ctxt.Flag_shared)) {
			break
		}
		v.reset(Op386ADDLload)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(mergeSym(sym1, sym2))
		v.AddArg3(val, base, mem)
		return true
	}
	return false
}
func rewriteValue386_Op386ADDLmodify(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	config := b.Func.Config
	// match: (ADDLmodify [off1] {sym} (ADDLconst [off2] base) val mem)
	// cond: is32Bit(int64(off1)+int64(off2))
	// result: (ADDLmodify [off1+off2] {sym} base val mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		if v_0.Op != Op386ADDLconst {
			break
		}
		off2 := auxIntToInt32(v_0.AuxInt)
		base := v_0.Args[0]
		val := v_1
		mem := v_2
		if !(is32Bit(int64(off1) + int64(off2))) {
			break
		}
		v.reset(Op386ADDLmodify)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(sym)
		v.AddArg3(base, val, mem)
		return true
	}
	// match: (ADDLmodify [off1] {sym1} (LEAL [off2] {sym2} base) val mem)
	// cond: is32Bit(int64(off1)+int64(off2)) && canMergeSym(sym1, sym2) && (base.Op != OpSB || !config.ctxt.Flag_shared)
	// result: (ADDLmodify [off1+off2] {mergeSym(sym1,sym2)} base val mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym1 := auxToSym(v.Aux)
		if v_0.Op != Op386LEAL {
			break
		}
		off2 := auxIntToInt32(v_0.AuxInt)
		sym2 := auxToSym(v_0.Aux)
		base := v_0.Args[0]
		val := v_1
		mem := v_2
		if !(is32Bit(int64(off1)+int64(off2)) && canMergeSym(sym1, sym2) && (base.Op != OpSB || !config.ctxt.Flag_shared)) {
			break
		}
		v.reset(Op386ADDLmodify)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(mergeSym(sym1, sym2))
		v.AddArg3(base, val, mem)
		return true
	}
	return false
}
func rewriteValue386_Op386ADDSD(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (ADDSD x l:(MOVSDload [off] {sym} ptr mem))
	// cond: canMergeLoadClobber(v, l, x) && clobber(l)
	// result: (ADDSDload x [off] {sym} ptr mem)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			l := v_1
			if l.Op != Op386MOVSDload {
				continue
			}
			off := auxIntToInt32(l.AuxInt)
			sym := auxToSym(l.Aux)
			mem := l.Args[1]
			ptr := l.Args[0]
			if !(canMergeLoadClobber(v, l, x) && clobber(l)) {
				continue
			}
			v.reset(Op386ADDSDload)
			v.AuxInt = int32ToAuxInt(off)
			v.Aux = symToAux(sym)
			v.AddArg3(x, ptr, mem)
			return true
		}
		break
	}
	return false
}
func rewriteValue386_Op386ADDSDload(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	config := b.Func.Config
	// match: (ADDSDload [off1] {sym} val (ADDLconst [off2] base) mem)
	// cond: is32Bit(int64(off1)+int64(off2))
	// result: (ADDSDload [off1+off2] {sym} val base mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		val := v_0
		if v_1.Op != Op386ADDLconst {
			break
		}
		off2 := auxIntToInt32(v_1.AuxInt)
		base := v_1.Args[0]
		mem := v_2
		if !(is32Bit(int64(off1) + int64(off2))) {
			break
		}
		v.reset(Op386ADDSDload)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(sym)
		v.AddArg3(val, base, mem)
		return true
	}
	// match: (ADDSDload [off1] {sym1} val (LEAL [off2] {sym2} base) mem)
	// cond: is32Bit(int64(off1)+int64(off2)) && canMergeSym(sym1, sym2) && (base.Op != OpSB || !config.ctxt.Flag_shared)
	// result: (ADDSDload [off1+off2] {mergeSym(sym1,sym2)} val base mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym1 := auxToSym(v.Aux)
		val := v_0
		if v_1.Op != Op386LEAL {
			break
		}
		off2 := auxIntToInt32(v_1.AuxInt)
		sym2 := auxToSym(v_1.Aux)
		base := v_1.Args[0]
		mem := v_2
		if !(is32Bit(int64(off1)+int64(off2)) && canMergeSym(sym1, sym2) && (base.Op != OpSB || !config.ctxt.Flag_shared)) {
			break
		}
		v.reset(Op386ADDSDload)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(mergeSym(sym1, sym2))
		v.AddArg3(val, base, mem)
		return true
	}
	return false
}
func rewriteValue386_Op386ADDSS(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (ADDSS x l:(MOVSSload [off] {sym} ptr mem))
	// cond: canMergeLoadClobber(v, l, x) && clobber(l)
	// result: (ADDSSload x [off] {sym} ptr mem)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			l := v_1
			if l.Op != Op386MOVSSload {
				continue
			}
			off := auxIntToInt32(l.AuxInt)
			sym := auxToSym(l.Aux)
			mem := l.Args[1]
			ptr := l.Args[0]
			if !(canMergeLoadClobber(v, l, x) && clobber(l)) {
				continue
			}
			v.reset(Op386ADDSSload)
			v.AuxInt = int32ToAuxInt(off)
			v.Aux = symToAux(sym)
			v.AddArg3(x, ptr, mem)
			return true
		}
		break
	}
	return false
}
func rewriteValue386_Op386ADDSSload(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	config := b.Func.Config
	// match: (ADDSSload [off1] {sym} val (ADDLconst [off2] base) mem)
	// cond: is32Bit(int64(off1)+int64(off2))
	// result: (ADDSSload [off1+off2] {sym} val base mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		val := v_0
		if v_1.Op != Op386ADDLconst {
			break
		}
		off2 := auxIntToInt32(v_1.AuxInt)
		base := v_1.Args[0]
		mem := v_2
		if !(is32Bit(int64(off1) + int64(off2))) {
			break
		}
		v.reset(Op386ADDSSload)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(sym)
		v.AddArg3(val, base, mem)
		return true
	}
	// match: (ADDSSload [off1] {sym1} val (LEAL [off2] {sym2} base) mem)
	// cond: is32Bit(int64(off1)+int64(off2)) && canMergeSym(sym1, sym2) && (base.Op != OpSB || !config.ctxt.Flag_shared)
	// result: (ADDSSload [off1+off2] {mergeSym(sym1,sym2)} val base mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym1 := auxToSym(v.Aux)
		val := v_0
		if v_1.Op != Op386LEAL {
			break
		}
		off2 := auxIntToInt32(v_1.AuxInt)
		sym2 := auxToSym(v_1.Aux)
		base := v_1.Args[0]
		mem := v_2
		if !(is32Bit(int64(off1)+int64(off2)) && canMergeSym(sym1, sym2) && (base.Op != OpSB || !config.ctxt.Flag_shared)) {
			break
		}
		v.reset(Op386ADDSSload)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(mergeSym(sym1, sym2))
		v.AddArg3(val, base, mem)
		return true
	}
	return false
}
func rewriteValue386_Op386ANDL(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (ANDL x (MOVLconst [c]))
	// result: (ANDLconst [c] x)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			if v_1.Op != Op386MOVLconst {
				continue
			}
			c := auxIntToInt32(v_1.AuxInt)
			v.reset(Op386ANDLconst)
			v.AuxInt = int32ToAuxInt(c)
			v.AddArg(x)
			return true
		}
		break
	}
	// match: (ANDL x l:(MOVLload [off] {sym} ptr mem))
	// cond: canMergeLoadClobber(v, l, x) && clobber(l)
	// result: (ANDLload x [off] {sym} ptr mem)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			l := v_1
			if l.Op != Op386MOVLload {
				continue
			}
			off := auxIntToInt32(l.AuxInt)
			sym := auxToSym(l.Aux)
			mem := l.Args[1]
			ptr := l.Args[0]
			if !(canMergeLoadClobber(v, l, x) && clobber(l)) {
				continue
			}
			v.reset(Op386ANDLload)
			v.AuxInt = int32ToAuxInt(off)
			v.Aux = symToAux(sym)
			v.AddArg3(x, ptr, mem)
			return true
		}
		break
	}
	// match: (ANDL x x)
	// result: x
	for {
		x := v_0
		if x != v_1 {
			break
		}
		v.copyOf(x)
		return true
	}
	return false
}
func rewriteValue386_Op386ANDLconst(v *Value) bool {
	v_0 := v.Args[0]
	// match: (ANDLconst [c] (ANDLconst [d] x))
	// result: (ANDLconst [c & d] x)
	for {
		c := auxIntToInt32(v.AuxInt)
		if v_0.Op != Op386ANDLconst {
			break
		}
		d := auxIntToInt32(v_0.AuxInt)
		x := v_0.Args[0]
		v.reset(Op386ANDLconst)
		v.AuxInt = int32ToAuxInt(c & d)
		v.AddArg(x)
		return true
	}
	// match: (ANDLconst [c] _)
	// cond: c==0
	// result: (MOVLconst [0])
	for {
		c := auxIntToInt32(v.AuxInt)
		if !(c == 0) {
			break
		}
		v.reset(Op386MOVLconst)
		v.AuxInt = int32ToAuxInt(0)
		return true
	}
	// match: (ANDLconst [c] x)
	// cond: c==-1
	// result: x
	for {
		c := auxIntToInt32(v.AuxInt)
		x := v_0
		if !(c == -1) {
			break
		}
		v.copyOf(x)
		return true
	}
	// match: (ANDLconst [c] (MOVLconst [d]))
	// result: (MOVLconst [c&d])
	for {
		c := auxIntToInt32(v.AuxInt)
		if v_0.Op != Op386MOVLconst {
			break
		}
		d := auxIntToInt32(v_0.AuxInt)
		v.reset(Op386MOVLconst)
		v.AuxInt = int32ToAuxInt(c & d)
		return true
	}
	return false
}
func rewriteValue386_Op386ANDLconstmodify(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	config := b.Func.Config
	// match: (ANDLconstmodify [valoff1] {sym} (ADDLconst [off2] base) mem)
	// cond: valoff1.canAdd32(off2)
	// result: (ANDLconstmodify [valoff1.addOffset32(off2)] {sym} base mem)
	for {
		valoff1 := auxIntToValAndOff(v.AuxInt)
		sym := auxToSym(v.Aux)
		if v_0.Op != Op386ADDLconst {
			break
		}
		off2 := auxIntToInt32(v_0.AuxInt)
		base := v_0.Args[0]
		mem := v_1
		if !(valoff1.canAdd32(off2)) {
			break
		}
		v.reset(Op386ANDLconstmodify)
		v.AuxInt = valAndOffToAuxInt(valoff1.addOffset32(off2))
		v.Aux = symToAux(sym)
		v.AddArg2(base, mem)
		return true
	}
	// match: (ANDLconstmodify [valoff1] {sym1} (LEAL [off2] {sym2} base) mem)
	// cond: valoff1.canAdd32(off2) && canMergeSym(sym1, sym2) && (base.Op != OpSB || !config.ctxt.Flag_shared)
	// result: (ANDLconstmodify [valoff1.addOffset32(off2)] {mergeSym(sym1,sym2)} base mem)
	for {
		valoff1 := auxIntToValAndOff(v.AuxInt)
		sym1 := auxToSym(v.Aux)
		if v_0.Op != Op386LEAL {
			break
		}
		off2 := auxIntToInt32(v_0.AuxInt)
		sym2 := auxToSym(v_0.Aux)
		base := v_0.Args[0]
		mem := v_1
		if !(valoff1.canAdd32(off2) && canMergeSym(sym1, sym2) && (base.Op != OpSB || !config.ctxt.Flag_shared)) {
			break
		}
		v.reset(Op386ANDLconstmodify)
		v.AuxInt = valAndOffToAuxInt(valoff1.addOffset32(off2))
		v.Aux = symToAux(mergeSym(sym1, sym2))
		v.AddArg2(base, mem)
		return true
	}
	return false
}
func rewriteValue386_Op386ANDLload(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	config := b.Func.Config
	// match: (ANDLload [off1] {sym} val (ADDLconst [off2] base) mem)
	// cond: is32Bit(int64(off1)+int64(off2))
	// result: (ANDLload [off1+off2] {sym} val base mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		val := v_0
		if v_1.Op != Op386ADDLconst {
			break
		}
		off2 := auxIntToInt32(v_1.AuxInt)
		base := v_1.Args[0]
		mem := v_2
		if !(is32Bit(int64(off1) + int64(off2))) {
			break
		}
		v.reset(Op386ANDLload)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(sym)
		v.AddArg3(val, base, mem)
		return true
	}
	// match: (ANDLload [off1] {sym1} val (LEAL [off2] {sym2} base) mem)
	// cond: is32Bit(int64(off1)+int64(off2)) && canMergeSym(sym1, sym2) && (base.Op != OpSB || !config.ctxt.Flag_shared)
	// result: (ANDLload [off1+off2] {mergeSym(sym1,sym2)} val base mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym1 := auxToSym(v.Aux)
		val := v_0
		if v_1.Op != Op386LEAL {
			break
		}
		off2 := auxIntToInt32(v_1.AuxInt)
		sym2 := auxToSym(v_1.Aux)
		base := v_1.Args[0]
		mem := v_2
		if !(is32Bit(int64(off1)+int64(off2)) && canMergeSym(sym1, sym2) && (base.Op != OpSB || !config.ctxt.Flag_shared)) {
			break
		}
		v.reset(Op386ANDLload)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(mergeSym(sym1, sym2))
		v.AddArg3(val, base, mem)
		return true
	}
	return false
}
func rewriteValue386_Op386ANDLmodify(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	config := b.Func.Config
	// match: (ANDLmodify [off1] {sym} (ADDLconst [off2] base) val mem)
	// cond: is32Bit(int64(off1)+int64(off2))
	// result: (ANDLmodify [off1+off2] {sym} base val mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		if v_0.Op != Op386ADDLconst {
			break
		}
		off2 := auxIntToInt32(v_0.AuxInt)
		base := v_0.Args[0]
		val := v_1
		mem := v_2
		if !(is32Bit(int64(off1) + int64(off2))) {
			break
		}
		v.reset(Op386ANDLmodify)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(sym)
		v.AddArg3(base, val, mem)
		return true
	}
	// match: (ANDLmodify [off1] {sym1} (LEAL [off2] {sym2} base) val mem)
	// cond: is32Bit(int64(off1)+int64(off2)) && canMergeSym(sym1, sym2) && (base.Op != OpSB || !config.ctxt.Flag_shared)
	// result: (ANDLmodify [off1+off2] {mergeSym(sym1,sym2)} base val mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym1 := auxToSym(v.Aux)
		if v_0.Op != Op386LEAL {
			break
		}
		off2 := auxIntToInt32(v_0.AuxInt)
		sym2 := auxToSym(v_0.Aux)
		base := v_0.Args[0]
		val := v_1
		mem := v_2
		if !(is32Bit(int64(off1)+int64(off2)) && canMergeSym(sym1, sym2) && (base.Op != OpSB || !config.ctxt.Flag_shared)) {
			break
		}
		v.reset(Op386ANDLmodify)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(mergeSym(sym1, sym2))
		v.AddArg3(base, val, mem)
		return true
	}
	return false
}
func rewriteValue386_Op386CMPB(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (CMPB x (MOVLconst [c]))
	// result: (CMPBconst x [int8(c)])
	for {
		x := v_0
		if v_1.Op != Op386MOVLconst {
			break
		}
		c := auxIntToInt32(v_1.AuxInt)
		v.reset(Op386CMPBconst)
		v.AuxInt = int8ToAuxInt(int8(c))
		v.AddArg(x)
		return true
	}
	// match: (CMPB (MOVLconst [c]) x)
	// result: (InvertFlags (CMPBconst x [int8(c)]))
	for {
		if v_0.Op != Op386MOVLconst {
			break
		}
		c := auxIntToInt32(v_0.AuxInt)
		x := v_1
		v.reset(Op386InvertFlags)
		v0 := b.NewValue0(v.Pos, Op386CMPBconst, types.TypeFlags)
		v0.AuxInt = int8ToAuxInt(int8(c))
		v0.AddArg(x)
		v.AddArg(v0)
		return true
	}
	// match: (CMPB x y)
	// cond: canonLessThan(x,y)
	// result: (InvertFlags (CMPB y x))
	for {
		x := v_0
		y := v_1
		if !(canonLessThan(x, y)) {
			break
		}
		v.reset(Op386InvertFlags)
		v0 := b.NewValue0(v.Pos, Op386CMPB, types.TypeFlags)
		v0.AddArg2(y, x)
		v.AddArg(v0)
		return true
	}
	// match: (CMPB l:(MOVBload {sym} [off] ptr mem) x)
	// cond: canMergeLoad(v, l) && clobber(l)
	// result: (CMPBload {sym} [off] ptr x mem)
	for {
		l := v_0
		if l.Op != Op386MOVBload {
			break
		}
		off := auxIntToInt32(l.AuxInt)
		sym := auxToSym(l.Aux)
		mem := l.Args[1]
		ptr := l.Args[0]
		x := v_1
		if !(canMergeLoad(v, l) && clobber(l)) {
			break
		}
		v.reset(Op386CMPBload)
		v.AuxInt = int32ToAuxInt(off)
		v.Aux = symToAux(sym)
		v.AddArg3(ptr, x, mem)
		return true
	}
	// match: (CMPB x l:(MOVBload {sym} [off] ptr mem))
	// cond: canMergeLoad(v, l) && clobber(l)
	// result: (InvertFlags (CMPBload {sym} [off] ptr x mem))
	for {
		x := v_0
		l := v_1
		if l.Op != Op386MOVBload {
			break
		}
		off := auxIntToInt32(l.AuxInt)
		sym := auxToSym(l.Aux)
		mem := l.Args[1]
		ptr := l.Args[0]
		if !(canMergeLoad(v, l) && clobber(l)) {
			break
		}
		v.reset(Op386InvertFlags)
		v0 := b.NewValue0(l.Pos, Op386CMPBload, types.TypeFlags)
		v0.AuxInt = int32ToAuxInt(off)
		v0.Aux = symToAux(sym)
		v0.AddArg3(ptr, x, mem)
		v.AddArg(v0)
		return true
	}
	return false
}
func rewriteValue386_Op386CMPBconst(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	// match: (CMPBconst (MOVLconst [x]) [y])
	// cond: int8(x)==y
	// result: (FlagEQ)
	for {
		y := auxIntToInt8(v.AuxInt)
		if v_0.Op != Op386MOVLconst {
			break
		}
		x := auxIntToInt32(v_0.AuxInt)
		if !(int8(x) == y) {
			break
		}
		v.reset(Op386FlagEQ)
		return true
	}
	// match: (CMPBconst (MOVLconst [x]) [y])
	// cond: int8(x)<y && uint8(x)<uint8(y)
	// result: (FlagLT_ULT)
	for {
		y := auxIntToInt8(v.AuxInt)
		if v_0.Op != Op386MOVLconst {
			break
		}
		x := auxIntToInt32(v_0.AuxInt)
		if !(int8(x) < y && uint8(x) < uint8(y)) {
			break
		}
		v.reset(Op386FlagLT_ULT)
		return true
	}
	// match: (CMPBconst (MOVLconst [x]) [y])
	// cond: int8(x)<y && uint8(x)>uint8(y)
	// result: (FlagLT_UGT)
	for {
		y := auxIntToInt8(v.AuxInt)
		if v_0.Op != Op386MOVLconst {
			break
		}
		x := auxIntToInt32(v_0.AuxInt)
		if !(int8(x) < y && uint8(x) > uint8(y)) {
			break
		}
		v.reset(Op386FlagLT_UGT)
		return true
	}
	// match: (CMPBconst (MOVLconst [x]) [y])
	// cond: int8(x)>y && uint8(x)<uint8(y)
	// result: (FlagGT_ULT)
	for {
		y := auxIntToInt8(v.AuxInt)
		if v_0.Op != Op386MOVLconst {
			break
		}
		x := auxIntToInt32(v_0.AuxInt)
		if !(int8(x) > y && uint8(x) < uint8(y)) {
			break
		}
		v.reset(Op386FlagGT_ULT)
		return true
	}
	// match: (CMPBconst (MOVLconst [x]) [y])
	// cond: int8(x)>y && uint8(x)>uint8(y)
	// result: (FlagGT_UGT)
	for {
		y := auxIntToInt8(v.AuxInt)
		if v_0.Op != Op386MOVLconst {
			break
		}
		x := auxIntToInt32(v_0.AuxInt)
		if !(int8(x) > y && uint8(x) > uint8(y)) {
			break
		}
		v.reset(Op386FlagGT_UGT)
		return true
	}
	// match: (CMPBconst (ANDLconst _ [m]) [n])
	// cond: 0 <= int8(m) && int8(m) < n
	// result: (FlagLT_ULT)
	for {
		n := auxIntToInt8(v.AuxInt)
		if v_0.Op != Op386ANDLconst {
			break
		}
		m := auxIntToInt32(v_0.AuxInt)
		if !(0 <= int8(m) && int8(m) < n) {
			break
		}
		v.reset(Op386FlagLT_ULT)
		return true
	}
	// match: (CMPBconst l:(ANDL x y) [0])
	// cond: l.Uses==1
	// result: (TESTB x y)
	for {
		if auxIntToInt8(v.AuxInt) != 0 {
			break
		}
		l := v_0
		if l.Op != Op386ANDL {
			break
		}
		y := l.Args[1]
		x := l.Args[0]
		if !(l.Uses == 1) {
			break
		}
		v.reset(Op386TESTB)
		v.AddArg2(x, y)
		return true
	}
	// match: (CMPBconst l:(ANDLconst [c] x) [0])
	// cond: l.Uses==1
	// result: (TESTBconst [int8(c)] x)
	for {
		if auxIntToInt8(v.AuxInt) != 0 {
			break
		}
		l := v_0
		if l.Op != Op386ANDLconst {
			break
		}
		c := auxIntToInt32(l.AuxInt)
		x := l.Args[0]
		if !(l.Uses == 1) {
			break
		}
		v.reset(Op386TESTBconst)
		v.AuxInt = int8ToAuxInt(int8(c))
		v.AddArg(x)
		return true
	}
	// match: (CMPBconst x [0])
	// result: (TESTB x x)
	for {
		if auxIntToInt8(v.AuxInt) != 0 {
			break
		}
		x := v_0
		v.reset(Op386TESTB)
		v.AddArg2(x, x)
		return true
	}
	// match: (CMPBconst l:(MOVBload {sym} [off] ptr mem) [c])
	// cond: l.Uses == 1 && clobber(l)
	// result: @l.Block (CMPBconstload {sym} [makeValAndOff(int32(c),off)] ptr mem)
	for {
		c := auxIntToInt8(v.AuxInt)
		l := v_0
		if l.Op != Op386MOVBload {
			break
		}
		off := auxIntToInt32(l.AuxInt)
		sym := auxToSym(l.Aux)
		mem := l.Args[1]
		ptr := l.Args[0]
		if !(l.Uses == 1 && clobber(l)) {
			break
		}
		b = l.Block
		v0 := b.NewValue0(l.Pos, Op386CMPBconstload, types.TypeFlags)
		v.copyOf(v0)
		v0.AuxInt = valAndOffToAuxInt(makeValAndOff(int32(c), off))
		v0.Aux = symToAux(sym)
		v0.AddArg2(ptr, mem)
		return true
	}
	return false
}
func rewriteValue386_Op386CMPBload(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (CMPBload {sym} [off] ptr (MOVLconst [c]) mem)
	// result: (CMPBconstload {sym} [makeValAndOff(int32(int8(c)),off)] ptr mem)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		if v_1.Op != Op386MOVLconst {
			break
		}
		c := auxIntToInt32(v_1.AuxInt)
		mem := v_2
		v.reset(Op386CMPBconstload)
		v.AuxInt = valAndOffToAuxInt(makeValAndOff(int32(int8(c)), off))
		v.Aux = symToAux(sym)
		v.AddArg2(ptr, mem)
		return true
	}
	return false
}
func rewriteValue386_Op386CMPL(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (CMPL x (MOVLconst [c]))
	// result: (CMPLconst x [c])
	for {
		x := v_0
		if v_1.Op != Op386MOVLconst {
			break
		}
		c := auxIntToInt32(v_1.AuxInt)
		v.reset(Op386CMPLconst)
		v.AuxInt = int32ToAuxInt(c)
		v.AddArg(x)
		return true
	}
	// match: (CMPL (MOVLconst [c]) x)
	// result: (InvertFlags (CMPLconst x [c]))
	for {
		if v_0.Op != Op386MOVLconst {
			break
		}
		c := auxIntToInt32(v_0.AuxInt)
		x := v_1
		v.reset(Op386InvertFlags)
		v0 := b.NewValue0(v.Pos, Op386CMPLconst, types.TypeFlags)
		v0.AuxInt = int32ToAuxInt(c)
		v0.AddArg(x)
		v.AddArg(v0)
		return true
	}
	// match: (CMPL x y)
	// cond: canonLessThan(x,y)
	// result: (InvertFlags (CMPL y x))
	for {
		x := v_0
		y := v_1
		if !(canonLessThan(x, y)) {
			break
		}
		v.reset(Op386InvertFlags)
		v0 := b.NewValue0(v.Pos, Op386CMPL, types.TypeFlags)
		v0.AddArg2(y, x)
		v.AddArg(v0)
		return true
	}
	// match: (CMPL l:(MOVLload {sym} [off] ptr mem) x)
	// cond: canMergeLoad(v, l) && clobber(l)
	// result: (CMPLload {sym} [off] ptr x mem)
	for {
		l := v_0
		if l.Op != Op386MOVLload {
			break
		}
		off := auxIntToInt32(l.AuxInt)
		sym := auxToSym(l.Aux)
		mem := l.Args[1]
		ptr := l.Args[0]
		x := v_1
		if !(canMergeLoad(v, l) && clobber(l)) {
			break
		}
		v.reset(Op386CMPLload)
		v.AuxInt = int32ToAuxInt(off)
		v.Aux = symToAux(sym)
		v.AddArg3(ptr, x, mem)
		return true
	}
	// match: (CMPL x l:(MOVLload {sym} [off] ptr mem))
	// cond: canMergeLoad(v, l) && clobber(l)
	// result: (InvertFlags (CMPLload {sym} [off] ptr x mem))
	for {
		x := v_0
		l := v_1
		if l.Op != Op386MOVLload {
			break
		}
		off := auxIntToInt32(l.AuxInt)
		sym := auxToSym(l.Aux)
		mem := l.Args[1]
		ptr := l.Args[0]
		if !(canMergeLoad(v, l) && clobber(l)) {
			break
		}
		v.reset(Op386InvertFlags)
		v0 := b.NewValue0(l.Pos, Op386CMPLload, types.TypeFlags)
		v0.AuxInt = int32ToAuxInt(off)
		v0.Aux = symToAux(sym)
		v0.AddArg3(ptr, x, mem)
		v.AddArg(v0)
		return true
	}
	return false
}
func rewriteValue386_Op386CMPLconst(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	// match: (CMPLconst (MOVLconst [x]) [y])
	// cond: x==y
	// result: (FlagEQ)
	for {
		y := auxIntToInt32(v.AuxInt)
		if v_0.Op != Op386MOVLconst {
			break
		}
		x := auxIntToInt32(v_0.AuxInt)
		if !(x == y) {
			break
		}
		v.reset(Op386FlagEQ)
		return true
	}
	// match: (CMPLconst (MOVLconst [x]) [y])
	// cond: x<y && uint32(x)<uint32(y)
	// result: (FlagLT_ULT)
	for {
		y := auxIntToInt32(v.AuxInt)
		if v_0.Op != Op386MOVLconst {
			break
		}
		x := auxIntToInt32(v_0.AuxInt)
		if !(x < y && uint32(x) < uint32(y)) {
			break
		}
		v.reset(Op386FlagLT_ULT)
		return true
	}
	// match: (CMPLconst (MOVLconst [x]) [y])
	// cond: x<y && uint32(x)>uint32(y)
	// result: (FlagLT_UGT)
	for {
		y := auxIntToInt32(v.AuxInt)
		if v_0.Op != Op386MOVLconst {
			break
		}
		x := auxIntToInt32(v_0.AuxInt)
		if !(x < y && uint32(x) > uint32(y)) {
			break
		}
		v.reset(Op386FlagLT_UGT)
		return true
	}
	// match: (CMPLconst (MOVLconst [x]) [y])
	// cond: x>y && uint32(x)<uint32(y)
	// result: (FlagGT_ULT)
	for {
		y := auxIntToInt32(v.AuxInt)
		if v_0.Op != Op386MOVLconst {
			break
		}
		x := auxIntToInt32(v_0.AuxInt)
		if !(x > y && uint32(x) < uint32(y)) {
			break
		}
		v.reset(Op386FlagGT_ULT)
		return true
	}
	// match: (CMPLconst (MOVLconst [x]) [y])
	// cond: x>y && uint32(x)>uint32(y)
	// result: (FlagGT_UGT)
	for {
		y := auxIntToInt32(v.AuxInt)
		if v_0.Op != Op386MOVLconst {
			break
		}
		x := auxIntToInt32(v_0.AuxInt)
		if !(x > y && uint32(x) > uint32(y)) {
			break
		}
		v.reset(Op386FlagGT_UGT)
		return true
	}
	// match: (CMPLconst (SHRLconst _ [c]) [n])
	// cond: 0 <= n && 0 < c && c <= 32 && (1<<uint64(32-c)) <= uint64(n)
	// result: (FlagLT_ULT)
	for {
		n := auxIntToInt32(v.AuxInt)
		if v_0.Op != Op386SHRLconst {
			break
		}
		c := auxIntToInt32(v_0.AuxInt)
		if !(0 <= n && 0 < c && c <= 32 && (1<<uint64(32-c)) <= uint64(n)) {
			break
		}
		v.reset(Op386FlagLT_ULT)
		return true
	}
	// match: (CMPLconst (ANDLconst _ [m]) [n])
	// cond: 0 <= m && m < n
	// result: (FlagLT_ULT)
	for {
		n := auxIntToInt32(v.AuxInt)
		if v_0.Op != Op386ANDLconst {
			break
		}
		m := auxIntToInt32(v_0.AuxInt)
		if !(0 <= m && m < n) {
			break
		}
		v.reset(Op386FlagLT_ULT)
		return true
	}
	// match: (CMPLconst l:(ANDL x y) [0])
	// cond: l.Uses==1
	// result: (TESTL x y)
	for {
		if auxIntToInt32(v.AuxInt) != 0 {
			break
		}
		l := v_0
		if l.Op != Op386ANDL {
			break
		}
		y := l.Args[1]
		x := l.Args[0]
		if !(l.Uses == 1) {
			break
		}
		v.reset(Op386TESTL)
		v.AddArg2(x, y)
		return true
	}
	// match: (CMPLconst l:(ANDLconst [c] x) [0])
	// cond: l.Uses==1
	// result: (TESTLconst [c] x)
	for {
		if auxIntToInt32(v.AuxInt) != 0 {
			break
		}
		l := v_0
		if l.Op != Op386ANDLconst {
			break
		}
		c := auxIntToInt32(l.AuxInt)
		x := l.Args[0]
		if !(l.Uses == 1) {
			break
		}
		v.reset(Op386TESTLconst)
		v.AuxInt = int32ToAuxInt(c)
		v.AddArg(x)
		return true
	}
	// match: (CMPLconst x [0])
	// result: (TESTL x x)
	for {
		if auxIntToInt32(v.AuxInt) != 0 {
			break
		}
		x := v_0
		v.reset(Op386TESTL)
		v.AddArg2(x, x)
		return true
	}
	// match: (CMPLconst l:(MOVLload {sym} [off] ptr mem) [c])
	// cond: l.Uses == 1 && clobber(l)
	// result: @l.Block (CMPLconstload {sym} [makeValAndOff(int32(c),off)] ptr mem)
	for {
		c := auxIntToInt32(v.AuxInt)
		l := v_0
		if l.Op != Op386MOVLload {
			break
		}
		off := auxIntToInt32(l.AuxInt)
		sym := auxToSym(l.Aux)
		mem := l.Args[1]
		ptr := l.Args[0]
		if !(l.Uses == 1 && clobber(l)) {
			break
		}
		b = l.Block
		v0 := b.NewValue0(l.Pos, Op386CMPLconstload, types.TypeFlags)
		v.copyOf(v0)
		v0.AuxInt = valAndOffToAuxInt(makeValAndOff(int32(c), off))
		v0.Aux = symToAux(sym)
		v0.AddArg2(ptr, mem)
		return true
	}
	return false
}
func rewriteValue386_Op386CMPLload(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (CMPLload {sym} [off] ptr (MOVLconst [c]) mem)
	// result: (CMPLconstload {sym} [makeValAndOff(c,off)] ptr mem)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		if v_1.Op != Op386MOVLconst {
			break
		}
		c := auxIntToInt32(v_1.AuxInt)
		mem := v_2
		v.reset(Op386CMPLconstload)
		v.AuxInt = valAndOffToAuxInt(makeValAndOff(c, off))
		v.Aux = symToAux(sym)
		v.AddArg2(ptr, mem)
		return true
	}
	return false
}
func rewriteValue386_Op386CMPW(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (CMPW x (MOVLconst [c]))
	// result: (CMPWconst x [int16(c)])
	for {
		x := v_0
		if v_1.Op != Op386MOVLconst {
			break
		}
		c := auxIntToInt32(v_1.AuxInt)
		v.reset(Op386CMPWconst)
		v.AuxInt = int16ToAuxInt(int16(c))
		v.AddArg(x)
		return true
	}
	// match: (CMPW (MOVLconst [c]) x)
	// result: (InvertFlags (CMPWconst x [int16(c)]))
	for {
		if v_0.Op != Op386MOVLconst {
			break
		}
		c := auxIntToInt32(v_0.AuxInt)
		x := v_1
		v.reset(Op386InvertFlags)
		v0 := b.NewValue0(v.Pos, Op386CMPWconst, types.TypeFlags)
		v0.AuxInt = int16ToAuxInt(int16(c))
		v0.AddArg(x)
		v.AddArg(v0)
		return true
	}
	// match: (CMPW x y)
	// cond: canonLessThan(x,y)
	// result: (InvertFlags (CMPW y x))
	for {
		x := v_0
		y := v_1
		if !(canonLessThan(x, y)) {
			break
		}
		v.reset(Op386InvertFlags)
		v0 := b.NewValue0(v.Pos, Op386CMPW, types.TypeFlags)
		v0.AddArg2(y, x)
		v.AddArg(v0)
		return true
	}
	// match: (CMPW l:(MOVWload {sym} [off] ptr mem) x)
	// cond: canMergeLoad(v, l) && clobber(l)
	// result: (CMPWload {sym} [off] ptr x mem)
	for {
		l := v_0
		if l.Op != Op386MOVWload {
			break
		}
		off := auxIntToInt32(l.AuxInt)
		sym := auxToSym(l.Aux)
		mem := l.Args[1]
		ptr := l.Args[0]
		x := v_1
		if !(canMergeLoad(v, l) && clobber(l)) {
			break
		}
		v.reset(Op386CMPWload)
		v.AuxInt = int32ToAuxInt(off)
		v.Aux = symToAux(sym)
		v.AddArg3(ptr, x, mem)
		return true
	}
	// match: (CMPW x l:(MOVWload {sym} [off] ptr mem))
	// cond: canMergeLoad(v, l) && clobber(l)
	// result: (InvertFlags (CMPWload {sym} [off] ptr x mem))
	for {
		x := v_0
		l := v_1
		if l.Op != Op386MOVWload {
			break
		}
		off := auxIntToInt32(l.AuxInt)
		sym := auxToSym(l.Aux)
		mem := l.Args[1]
		ptr := l.Args[0]
		if !(canMergeLoad(v, l) && clobber(l)) {
			break
		}
		v.reset(Op386InvertFlags)
		v0 := b.NewValue0(l.Pos, Op386CMPWload, types.TypeFlags)
		v0.AuxInt = int32ToAuxInt(off)
		v0.Aux = symToAux(sym)
		v0.AddArg3(ptr, x, mem)
		v.AddArg(v0)
		return true
	}
	return false
}
func rewriteValue386_Op386CMPWconst(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	// match: (CMPWconst (MOVLconst [x]) [y])
	// cond: int16(x)==y
	// result: (FlagEQ)
	for {
		y := auxIntToInt16(v.AuxInt)
		if v_0.Op != Op386MOVLconst {
			break
		}
		x := auxIntToInt32(v_0.AuxInt)
		if !(int16(x) == y) {
			break
		}
		v.reset(Op386FlagEQ)
		return true
	}
	// match: (CMPWconst (MOVLconst [x]) [y])
	// cond: int16(x)<y && uint16(x)<uint16(y)
	// result: (FlagLT_ULT)
	for {
		y := auxIntToInt16(v.AuxInt)
		if v_0.Op != Op386MOVLconst {
			break
		}
		x := auxIntToInt32(v_0.AuxInt)
		if !(int16(x) < y && uint16(x) < uint16(y)) {
			break
		}
		v.reset(Op386FlagLT_ULT)
		return true
	}
	// match: (CMPWconst (MOVLconst [x]) [y])
	// cond: int16(x)<y && uint16(x)>uint16(y)
	// result: (FlagLT_UGT)
	for {
		y := auxIntToInt16(v.AuxInt)
		if v_0.Op != Op386MOVLconst {
			break
		}
		x := auxIntToInt32(v_0.AuxInt)
		if !(int16(x) < y && uint16(x) > uint16(y)) {
			break
		}
		v.reset(Op386FlagLT_UGT)
		return true
	}
	// match: (CMPWconst (MOVLconst [x]) [y])
	// cond: int16(x)>y && uint16(x)<uint16(y)
	// result: (FlagGT_ULT)
	for {
		y := auxIntToInt16(v.AuxInt)
		if v_0.Op != Op386MOVLconst {
			break
		}
		x := auxIntToInt32(v_0.AuxInt)
		if !(int16(x) > y && uint16(x) < uint16(y)) {
			break
		}
		v.reset(Op386FlagGT_ULT)
		return true
	}
	// match: (CMPWconst (MOVLconst [x]) [y])
	// cond: int16(x)>y && uint16(x)>uint16(y)
	// result: (FlagGT_UGT)
	for {
		y := auxIntToInt16(v.AuxInt)
		if v_0.Op != Op386MOVLconst {
			break
		}
		x := auxIntToInt32(v_0.AuxInt)
		if !(int16(x) > y && uint16(x) > uint16(y)) {
			break
		}
		v.reset(Op386FlagGT_UGT)
		return true
	}
	// match: (CMPWconst (ANDLconst _ [m]) [n])
	// cond: 0 <= int16(m) && int16(m) < n
	// result: (FlagLT_ULT)
	for {
		n := auxIntToInt16(v.AuxInt)
		if v_0.Op != Op386ANDLconst {
			break
		}
		m := auxIntToInt32(v_0.AuxInt)
		if !(0 <= int16(m) && int16(m) < n) {
			break
		}
		v.reset(Op386FlagLT_ULT)
		return true
	}
	// match: (CMPWconst l:(ANDL x y) [0])
	// cond: l.Uses==1
	// result: (TESTW x y)
	for {
		if auxIntToInt16(v.AuxInt) != 0 {
			break
		}
		l := v_0
		if l.Op != Op386ANDL {
			break
		}
		y := l.Args[1]
		x := l.Args[0]
		if !(l.Uses == 1) {
			break
		}
		v.reset(Op386TESTW)
		v.AddArg2(x, y)
		return true
	}
	// match: (CMPWconst l:(ANDLconst [c] x) [0])
	// cond: l.Uses==1
	// result: (TESTWconst [int16(c)] x)
	for {
		if auxIntToInt16(v.AuxInt) != 0 {
			break
		}
		l := v_0
		if l.Op != Op386ANDLconst {
			break
		}
		c := auxIntToInt32(l.AuxInt)
		x := l.Args[0]
		if !(l.Uses == 1) {
			break
		}
		v.reset(Op386TESTWconst)
		v.AuxInt = int16ToAuxInt(int16(c))
		v.AddArg(x)
		return true
	}
	// match: (CMPWconst x [0])
	// result: (TESTW x x)
	for {
		if auxIntToInt16(v.AuxInt) != 0 {
			break
		}
		x := v_0
		v.reset(Op386TESTW)
		v.AddArg2(x, x)
		return true
	}
	// match: (CMPWconst l:(MOVWload {sym} [off] ptr mem) [c])
	// cond: l.Uses == 1 && clobber(l)
	// result: @l.Block (CMPWconstload {sym} [makeValAndOff(int32(c),off)] ptr mem)
	for {
		c := auxIntToInt16(v.AuxInt)
		l := v_0
		if l.Op != Op386MOVWload {
			break
		}
		off := auxIntToInt32(l.AuxInt)
		sym := auxToSym(l.Aux)
		mem := l.Args[1]
		ptr := l.Args[0]
		if !(l.Uses == 1 && clobber(l)) {
			break
		}
		b = l.Block
		v0 := b.NewValue0(l.Pos, Op386CMPWconstload, types.TypeFlags)
		v.copyOf(v0)
		v0.AuxInt = valAndOffToAuxInt(makeValAndOff(int32(c), off))
		v0.Aux = symToAux(sym)
		v0.AddArg2(ptr, mem)
		return true
	}
	return false
}
func rewriteValue386_Op386CMPWload(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (CMPWload {sym} [off] ptr (MOVLconst [c]) mem)
	// result: (CMPWconstload {sym} [makeValAndOff(int32(int16(c)),off)] ptr mem)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		if v_1.Op != Op386MOVLconst {
			break
		}
		c := auxIntToInt32(v_1.AuxInt)
		mem := v_2
		v.reset(Op386CMPWconstload)
		v.AuxInt = valAndOffToAuxInt(makeValAndOff(int32(int16(c)), off))
		v.Aux = symToAux(sym)
		v.AddArg2(ptr, mem)
		return true
	}
	return false
}
func rewriteValue386_Op386DIVSD(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (DIVSD x l:(MOVSDload [off] {sym} ptr mem))
	// cond: canMergeLoadClobber(v, l, x) && clobber(l)
	// result: (DIVSDload x [off] {sym} ptr mem)
	for {
		x := v_0
		l := v_1
		if l.Op != Op386MOVSDload {
			break
		}
		off := auxIntToInt32(l.AuxInt)
		sym := auxToSym(l.Aux)
		mem := l.Args[1]
		ptr := l.Args[0]
		if !(canMergeLoadClobber(v, l, x) && clobber(l)) {
			break
		}
		v.reset(Op386DIVSDload)
		v.AuxInt = int32ToAuxInt(off)
		v.Aux = symToAux(sym)
		v.AddArg3(x, ptr, mem)
		return true
	}
	return false
}
func rewriteValue386_Op386DIVSDload(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	config := b.Func.Config
	// match: (DIVSDload [off1] {sym} val (ADDLconst [off2] base) mem)
	// cond: is32Bit(int64(off1)+int64(off2))
	// result: (DIVSDload [off1+off2] {sym} val base mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		val := v_0
		if v_1.Op != Op386ADDLconst {
			break
		}
		off2 := auxIntToInt32(v_1.AuxInt)
		base := v_1.Args[0]
		mem := v_2
		if !(is32Bit(int64(off1) + int64(off2))) {
			break
		}
		v.reset(Op386DIVSDload)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(sym)
		v.AddArg3(val, base, mem)
		return true
	}
	// match: (DIVSDload [off1] {sym1} val (LEAL [off2] {sym2} base) mem)
	// cond: is32Bit(int64(off1)+int64(off2)) && canMergeSym(sym1, sym2) && (base.Op != OpSB || !config.ctxt.Flag_shared)
	// result: (DIVSDload [off1+off2] {mergeSym(sym1,sym2)} val base mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym1 := auxToSym(v.Aux)
		val := v_0
		if v_1.Op != Op386LEAL {
			break
		}
		off2 := auxIntToInt32(v_1.AuxInt)
		sym2 := auxToSym(v_1.Aux)
		base := v_1.Args[0]
		mem := v_2
		if !(is32Bit(int64(off1)+int64(off2)) && canMergeSym(sym1, sym2) && (base.Op != OpSB || !config.ctxt.Flag_shared)) {
			break
		}
		v.reset(Op386DIVSDload)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(mergeSym(sym1, sym2))
		v.AddArg3(val, base, mem)
		return true
	}
	return false
}
func rewriteValue386_Op386DIVSS(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (DIVSS x l:(MOVSSload [off] {sym} ptr mem))
	// cond: canMergeLoadClobber(v, l, x) && clobber(l)
	// result: (DIVSSload x [off] {sym} ptr mem)
	for {
		x := v_0
		l := v_1
		if l.Op != Op386MOVSSload {
			break
		}
		off := auxIntToInt32(l.AuxInt)
		sym := auxToSym(l.Aux)
		mem := l.Args[1]
		ptr := l.Args[0]
		if !(canMergeLoadClobber(v, l, x) && clobber(l)) {
			break
		}
		v.reset(Op386DIVSSload)
		v.AuxInt = int32ToAuxInt(off)
		v.Aux = symToAux(sym)
		v.AddArg3(x, ptr, mem)
		return true
	}
	return false
}
func rewriteValue386_Op386DIVSSload(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	config := b.Func.Config
	// match: (DIVSSload [off1] {sym} val (ADDLconst [off2] base) mem)
	// cond: is32Bit(int64(off1)+int64(off2))
	// result: (DIVSSload [off1+off2] {sym} val base mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		val := v_0
		if v_1.Op != Op386ADDLconst {
			break
		}
		off2 := auxIntToInt32(v_1.AuxInt)
		base := v_1.Args[0]
		mem := v_2
		if !(is32Bit(int64(off1) + int64(off2))) {
			break
		}
		v.reset(Op386DIVSSload)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(sym)
		v.AddArg3(val, base, mem)
		return true
	}
	// match: (DIVSSload [off1] {sym1} val (LEAL [off2] {sym2} base) mem)
	// cond: is32Bit(int64(off1)+int64(off2)) && canMergeSym(sym1, sym2) && (base.Op != OpSB || !config.ctxt.Flag_shared)
	// result: (DIVSSload [off1+off2] {mergeSym(sym1,sym2)} val base mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym1 := auxToSym(v.Aux)
		val := v_0
		if v_1.Op != Op386LEAL {
			break
		}
		off2 := auxIntToInt32(v_1.AuxInt)
		sym2 := auxToSym(v_1.Aux)
		base := v_1.Args[0]
		mem := v_2
		if !(is32Bit(int64(off1)+int64(off2)) && canMergeSym(sym1, sym2) && (base.Op != OpSB || !config.ctxt.Flag_shared)) {
			break
		}
		v.reset(Op386DIVSSload)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(mergeSym(sym1, sym2))
		v.AddArg3(val, base, mem)
		return true
	}
	return false
}
func rewriteValue386_Op386LEAL(v *Value) bool {
	v_0 := v.Args[0]
	// match: (LEAL [c] {s} (ADDLconst [d] x))
	// cond: is32Bit(int64(c)+int64(d))
	// result: (LEAL [c+d] {s} x)
	for {
		c := auxIntToInt32(v.AuxInt)
		s := auxToSym(v.Aux)
		if v_0.Op != Op386ADDLconst {
			break
		}
		d := auxIntToInt32(v_0.AuxInt)
		x := v_0.Args[0]
		if !(is32Bit(int64(c) + int64(d))) {
			break
		}
		v.reset(Op386LEAL)
		v.AuxInt = int32ToAuxInt(c + d)
		v.Aux = symToAux(s)
		v.AddArg(x)
		return true
	}
	// match: (LEAL [c] {s} (ADDL x y))
	// cond: x.Op != OpSB && y.Op != OpSB
	// result: (LEAL1 [c] {s} x y)
	for {
		c := auxIntToInt32(v.AuxInt)
		s := auxToSym(v.Aux)
		if v_0.Op != Op386ADDL {
			break
		}
		_ = v_0.Args[1]
		v_0_0 := v_0.Args[0]
		v_0_1 := v_0.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, v_0_0, v_0_1 = _i0+1, v_0_1, v_0_0 {
			x := v_0_0
			y := v_0_1
			if !(x.Op != OpSB && y.Op != OpSB) {
				continue
			}
			v.reset(Op386LEAL1)
			v.AuxInt = int32ToAuxInt(c)
			v.Aux = symToAux(s)
			v.AddArg2(x, y)
```