Response: Let's break down the thought process for analyzing the provided Go code snippet.

**1. Initial Understanding of the Request:**

The request asks for an analysis of a Go source file (`objz.go`) within the `cmd/internal/obj/s390x` package. The key points are:

* **Functionality Listing:** What does this code *do*?
* **Go Feature Inference:** What Go language features does it implement or relate to? Provide a code example.
* **Code Reasoning:** If the answer involves analyzing code logic, demonstrate with assumed inputs and outputs.
* **Command-Line Arguments:**  Are there any command-line flags handled in this code?
* **Common Mistakes:** Are there any pitfalls developers might encounter when using this code (or the related Go features)?

**2. High-Level Overview of the Code:**

The code is within the `s390x` package, suggesting it's specific to the S/390x architecture. The copyright notices at the beginning hint at its role in code generation or manipulation, likely within the Go compiler toolchain. The imports reinforce this: `cmd/internal/obj` (object representation), `cmd/internal/objabi` (ABI details), `cmd/internal/sys` (system architecture information).

**3. Identifying Key Functions:**

Scanning the code, the prominent functions are:

* `progedit`: This function takes a `obj.Prog` and modifies it. The comments suggest it rewrites instructions based on the symbol type and constant values. The `ctxt.Flag_dynlink` check is a strong clue about dynamic linking.
* `rewriteToUseGot`:  This function is explicitly tied to dynamic linking and mentions the "global offset table" (GOT). This strongly suggests it's part of the process of making code position-independent for shared libraries.
* `preprocess`: This function operates on a `obj.LSym` (linked symbol) and seems related to setting up the stack frame, handling leaf functions, and dealing with stack splitting.
* `stacksplitPre` and `stacksplitPost`: These are clearly responsible for generating the code to check for stack overflow and potentially call `runtime.morestack`.

**4. Analyzing Function Functionality (Iterative Process):**

* **`progedit`:**
    * **Rewrite Branches:**  The initial `switch` statement rewrites `BR` and `BL` instructions to `TYPE_BRANCH` if they target a symbol. This is a common optimization or canonicalization step.
    * **Float Constants:**  Float constants are moved to memory (creating external symbols for them) unless they are zero. This might be related to how the architecture handles immediate floating-point values.
    * **Large Constants:**  Integer constants that don't fit in an immediate field are also moved to memory.
    * **SUB to ADD:**  Subtracting a constant is rewritten as adding its negation. This is a standard compiler optimization.
    * **Dynamic Linking:** The call to `c.rewriteToUseGot(p)` connects this function to the dynamic linking logic.

* **`rewriteToUseGot`:**
    * **GOT Access:** The core purpose is to rewrite instructions to access global variables via the GOT. This is fundamental to position-independent code.
    * **Instruction Rewriting:**  The code handles cases like `MOVD $sym, Rx` and `MOVD sym, Ry`, replacing direct symbol access with GOT-relative access. It uses a temporary register (`REGTMP2`) when necessary.
    * **Error Handling:**  The function includes `ctxt.Diag` calls for cases it doesn't yet handle, indicating ongoing development or limitations.

* **`preprocess`:**
    * **Stack Frame Setup:**  Determines the stack frame size and handles the `NOFRAME` attribute.
    * **Leaf Function Detection:** Identifies leaf functions (those that don't call other functions).
    * **NOP Removal:** (Implicit from the description)
    * **RET Expansion:**  The `obj.ARET` handling shows how `RET` instructions are expanded, especially for non-leaf functions, involving restoring the link register and adjusting the stack pointer.
    * **Stack Splitting:** The calls to `stacksplitPre` and `stacksplitPost` are central to managing stack growth.
    * **Wrapper Functions:** Special handling for wrapper functions related to panic handling.
    * **SP Tracking:**  The code attempts to track stack pointer adjustments (`Spadj`).

* **`stacksplitPre` and `stacksplitPost`:**
    * **Stack Guard Check:**  Compares the stack pointer against the stack guard value to detect potential overflows.
    * **`runtime.morestack` Call:**  If a stack overflow is detected (or predicted), it calls a runtime function (`runtime.morestack`) to allocate a larger stack.
    * **Architecture-Specific Logic:** The logic differs slightly based on the stack frame size (small vs. large) to optimize the check. The `Flag_maymorestack` handling seems like an optional, possibly experimental feature.
    * **Unsafe Points:**  The use of `ctxt.StartUnsafePoint` and `ctxt.EndUnsafePoint` indicates regions where asynchronous preemption should be disabled.

**5. Inferring Go Features and Providing Examples:**

* **Dynamic Linking:**  The `rewriteToUseGot` function is a clear example of how Go supports dynamic linking.
    ```go
    // Assume a global variable 'myGlobal'
    var myGlobal int

    func main() {
        x := myGlobal // In dynamically linked code, this access might be rewritten
        println(x)
    }
    ```
    The compiler, with `-dynlink`, would transform the access to `myGlobal` to go through the GOT.

* **Stack Management/Growth:**  The `stacksplitPre` and `stacksplitPost` functions demonstrate Go's automatic stack growth mechanism.
    ```go
    func recursiveFunction(n int) {
        if n > 0 {
            recursiveFunction(n - 1) // Potentially needs more stack
        }
        // ... function logic ...
    }
    ```
    If the recursion goes deep enough, the stack guard check will trigger, and `runtime.morestack` will be called.

* **Compiler Optimizations:** The rewriting of `SUB` to `ADD` in `progedit` is a standard compiler optimization.

**6. Command-Line Arguments:**

The code explicitly checks `ctxt.Flag_dynlink` and `ctxt.Flag_maymorestack`. These are compiler flags passed during the build process.

* `-dynlink`: Enables dynamic linking.
* `-maymorestack`:  Likely enables an alternative or experimental stack growth mechanism.

**7. Common Mistakes:**

* **Manual Stack Management:** Go developers rarely need to worry about stack management directly. Trying to manually manipulate the stack pointer or frame in a way that interferes with the compiler's generated code will lead to crashes or unpredictable behavior. (This is more of a general Go concept than specific to this file).
* **Incorrect Assumptions about Dynamic Linking:** Developers might make assumptions about the memory layout of global variables in dynamically linked programs that are incorrect if they don't understand the role of the GOT.

**8. Structuring the Answer:**

Organize the findings logically, starting with the general functionality and then delving into specific functions and features. Use clear headings and bullet points for readability. Provide concise code examples and explanations for each inferred Go feature.

**Self-Correction/Refinement:**

During the process, I might initially focus too much on the low-level assembly details. It's important to step back and connect the code to higher-level Go concepts and features that developers interact with. For example, instead of just saying "it rewrites branches," explain *why* it does that (optimization, canonicalization). Similarly, with dynamic linking, explain the purpose of the GOT from a developer's perspective.

By following these steps, including an iterative analysis and refinement process, I can arrive at a comprehensive and accurate explanation of the provided Go code snippet.
Based on the provided Go code snippet from `go/src/cmd/internal/obj/s390x/objz.go`, here's a breakdown of its functionality:

**Core Functionality:**

This file is part of the S/390x architecture backend for the Go compiler's assembler and linker (`cmd/internal/obj`). Its primary function is to perform architecture-specific transformations and optimizations on the intermediate representation of Go code before final assembly and linking. It operates on `obj.Prog` structures, which represent individual assembly instructions.

**Specific Functions and Their Purposes:**

1. **`progedit(ctxt *obj.Link, p *obj.Prog, newprog obj.ProgAlloc)`:**
   - **Instruction Rewriting:** This function is the main entry point for instruction-level modifications. It examines each instruction (`p`) and rewrites it if necessary.
   - **Branch Target Handling:** It ensures that branch instructions (`ABR`, `ABL`, `ARET`, `ADUFFZERO`, `ADUFFCOPY`) targeting symbols are marked with `obj.TYPE_BRANCH`. This helps the assembler and linker correctly resolve branch targets.
   - **Floating-Point Constant Optimization:** It replaces floating-point constants in `AFMOVS` and `AFMOVD` instructions with references to memory locations where these constants are stored (unless the constant is +0). This is likely done because loading arbitrary floating-point constants as immediates might not be efficient or directly supported by the S/390x architecture.
   - **Large Integer Constant Handling:**  For `AMOVD` instructions with constant operands, it checks if the constant can be represented as a 32-bit signed or unsigned integer. If not, it moves the constant to a memory location and changes the operand to a memory reference. This is because S/390x might have limitations on the size of immediate values.
   - **SUB to ADD Optimization:** It rewrites `SUBC` and `SUB` instructions with constant operands to their `ADD` counterparts by negating the constant. This is a common compiler optimization.
   - **Dynamic Linking Support:** If the `-dynlink` flag is enabled, it calls `c.rewriteToUseGot(p)` to handle global symbol access via the Global Offset Table (GOT).

2. **`rewriteToUseGot(p *obj.Prog)`:**
   - **Global Symbol Access via GOT:** This function is responsible for rewriting instructions to access global variables and functions through the GOT when dynamic linking is enabled. This is crucial for creating position-independent executables and shared libraries.
   - **`MOVD $sym, Rx` to `MOVD sym@GOT, Rx`:** It transforms instructions that load the address of a global symbol into a register to load the address of the symbol's entry in the GOT.
   - **Handling Offsets:** For instructions like `MOVD $sym+<off>, Rx`, it might generate an additional `MOVD` instruction to calculate the final address after loading the GOT entry.
   - **`MOVD sym, Ry` and `MOVD Ry, sym` to GOT Access:** It rewrites memory access to global symbols by first loading the GOT entry into a temporary register and then accessing memory through that register.
   - **Exclusion of Certain Instructions:** It skips rewriting for instructions like `ATEXT`, `AFUNCDATA`, `ACALL`, `ARET`, `AJMP` as they have specific handling or don't directly access global data in the same way.

3. **`preprocess(ctxt *obj.Link, cursym *obj.LSym, newprog obj.ProgAlloc)`:**
   - **Function Prologue and Epilogue Generation:** This function is responsible for adding the necessary instructions at the beginning (prologue) and end (epilogue) of functions.
   - **Stack Frame Management:** It determines the size of the stack frame needed by the function (`textstksiz`) and adjusts the stack pointer accordingly.
   - **Leaf Function Optimization:** It identifies leaf functions (functions that don't call other functions) and marks them. Leaf functions can often have optimized prologues and epilogues.
   - **NOP Removal (Implicit):**  The comment mentions "strip NOPs," suggesting this function might remove unnecessary no-operation instructions.
   - **RET Expansion:** It expands `ARET` instructions into sequences that restore the link register and adjust the stack pointer, especially for non-leaf functions.
   - **Stack Overflow Checks (Stack Splitting):**  It inserts code to check if the current stack has enough space for the function's needs. If not, it calls a runtime function (`runtime.morestack`) to grow the stack. This logic is handled by `stacksplitPre` and `stacksplitPost`.
   - **Handling `NOFRAME` Functions:** It handles functions marked with `NOFRAME`, ensuring they have a stack size of 0.
   - **Wrapper Function Handling:** It inserts specific code for wrapper functions, often related to checking for panics.
   - **`GETCALLERPC` Handling:** It rewrites `AGETCALLERPC` to retrieve the caller's program counter, potentially from the link register for leaf functions or the stack for non-leaf functions.
   - **SP Write Flag:** It detects if the function modifies the stack pointer (`SP`) and sets a flag (`abi.FuncFlagSPWrite`) accordingly.

4. **`stacksplitPre(p *obj.Prog, framesize int32)`:**
   - **Generates Stack Check Prologue:** This function generates the initial part of the stack overflow check at the beginning of a function.
   - **Stack Guard Load:** It loads the stack guard value from the `g` (goroutine) structure.
   - **Comparison:** It compares the current stack pointer with the stack guard (taking into account the required frame size) to determine if more stack is needed.
   - **Conditional Branch:** It inserts a conditional branch instruction that jumps to the `stacksplitPost` epilogue if a stack overflow is detected.
   - **Handling `-maymorestack` Flag:** If the `-maymorestack` flag is set, it inserts a call to a user-defined `maymorestack` function before the standard stack check.

5. **`stacksplitPost(p *obj.Prog, pPre, pPreempt, pCheck *obj.Prog, framesize int32)`:**
   - **Generates Stack Growth Epilogue:** This function generates the code that is executed when a stack overflow is detected.
   - **Calls `runtime.morestack`:** It inserts a call to the appropriate `runtime.morestack` function (or `runtime.morestackc` for cgo calls) to allocate a larger stack.
   - **Jumps Back to Stack Check:** After `runtime.morestack` returns, it inserts an unconditional jump back to the beginning of the stack check (`pCheck`) to re-evaluate if the newly allocated stack is sufficient.

**Inference of Go Language Features:**

This code is fundamental to the implementation of several key Go features:

* **Function Calls and Stack Management:** The `preprocess`, `stacksplitPre`, and `stacksplitPost` functions directly implement how Go manages the call stack, including allocating and growing stacks as needed. This is a core part of Go's execution model.
* **Dynamic Linking (`-dynlink` flag):** The `rewriteToUseGot` function directly implements the mechanism for supporting dynamic linking in Go, allowing Go programs to link against shared libraries.
* **Compiler Optimizations:** The rewriting of `SUB` to `ADD` and the handling of constants are examples of compiler-level optimizations to generate more efficient code for the S/390x architecture.
* **Garbage Collection (Indirectly):** While not directly visible in this snippet, the stack management and the `g` structure (referencing the goroutine) are closely related to how Go's garbage collector manages memory.

**Go Code Example (Illustrating Stack Growth):**

```go
package main

import "fmt"

func recursiveFunction(n int) {
	fmt.Println("Depth:", n)
	if n > 0 {
		recursiveFunction(n - 1)
	}
}

func main() {
	recursiveFunction(1000) // This will likely trigger stack growth
}
```

**Explanation:** When `recursiveFunction` is called with a large value like 1000, it will make many nested calls. Without stack growth, this would lead to a stack overflow. The code in `objz.go` (specifically `stacksplitPre` and `stacksplitPost`) ensures that before a stack overflow occurs, the `runtime.morestack` function is called to allocate a larger stack, allowing the recursion to complete.

**Assumptions, Inputs, and Outputs (for `progedit` - Float Constant Optimization):**

**Assumption:** The S/390x architecture has limitations on directly encoding arbitrary floating-point constants within instructions.

**Input `obj.Prog` (Before):**

```
As: AFMOVD
From: {Type: obj.TYPE_FCONST, Val: 3.14159}
To:   {Type: obj.TYPE_REG, Reg: REG_F0}
```

**Output `obj.Prog` (After):**

```
As: AFMOVD
From: {Type: obj.TYPE_MEM, Sym: <symbol for 3.14159>, Name: obj.NAME_EXTERN, Offset: 0}
To:   {Type: obj.TYPE_REG, Reg: REG_F0}
```

**Explanation:** The `progedit` function, upon seeing the `AFMOVD` instruction with a floating-point constant, creates an external symbol representing that constant in the data section and rewrites the `From` operand to be a memory reference to that symbol.

**Command-Line Parameter Handling:**

The code explicitly checks for the following flags within the `progedit` and `stacksplitPre` functions:

* **`ctxt.Flag_dynlink`:** This flag, when set, indicates that the program is being linked dynamically. The `rewriteToUseGot` function is called conditionally based on this flag. This flag is typically passed to the `go build` command using `-ldflags=-linkmode=external`.
* **`ctxt.Flag_maymorestack`:** This flag seems to enable an optional or experimental mechanism for handling stack growth, potentially by calling a user-defined function before the standard `runtime.morestack`. This flag might be used for testing or specialized scenarios.

**Common Mistakes for Users:**

Since this code is part of the Go toolchain's internal implementation, typical Go developers don't directly interact with it or make mistakes related to its specific functions. However, understanding the underlying concepts can help avoid potential issues:

* **Assuming Global Variables are Accessed Directly (with `-dynlink`):** When `-dynlink` is used, developers should understand that global variable access might involve an extra level of indirection through the GOT. While the Go compiler handles this transparently, it's important to be aware of this when debugging or analyzing performance in dynamically linked scenarios.
* **Manual Stack Manipulation (Generally Discouraged in Go):** Although not directly related to this file's code, trying to manually manipulate the stack pointer or allocate stack space directly is generally unsafe and unnecessary in Go due to its automatic stack management.

In summary, `objz.go` plays a crucial role in the Go compilation process for the S/390x architecture by performing architecture-specific instruction transformations, handling dynamic linking, and implementing the stack management mechanisms that are fundamental to Go's execution model.

### 提示词
```
这是路径为go/src/cmd/internal/obj/s390x/objz.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
```

### 源代码
```go
// Based on cmd/internal/obj/ppc64/obj9.go.
//
//	Copyright © 1994-1999 Lucent Technologies Inc.  All rights reserved.
//	Portions Copyright © 1995-1997 C H Forsyth (forsyth@terzarima.net)
//	Portions Copyright © 1997-1999 Vita Nuova Limited
//	Portions Copyright © 2000-2008 Vita Nuova Holdings Limited (www.vitanuova.com)
//	Portions Copyright © 2004,2006 Bruce Ellis
//	Portions Copyright © 2005-2007 C H Forsyth (forsyth@terzarima.net)
//	Revisions Copyright © 2000-2008 Lucent Technologies Inc. and others
//	Portions Copyright © 2009 The Go Authors. All rights reserved.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.

package s390x

import (
	"cmd/internal/obj"
	"cmd/internal/objabi"
	"cmd/internal/sys"
	"internal/abi"
	"log"
	"math"
)

func progedit(ctxt *obj.Link, p *obj.Prog, newprog obj.ProgAlloc) {
	p.From.Class = 0
	p.To.Class = 0

	c := ctxtz{ctxt: ctxt, newprog: newprog}

	// Rewrite BR/BL to symbol as TYPE_BRANCH.
	switch p.As {
	case ABR, ABL, obj.ARET, obj.ADUFFZERO, obj.ADUFFCOPY:
		if p.To.Sym != nil {
			p.To.Type = obj.TYPE_BRANCH
		}
	}

	// Rewrite float constants to values stored in memory unless they are +0.
	switch p.As {
	case AFMOVS:
		if p.From.Type == obj.TYPE_FCONST {
			f32 := float32(p.From.Val.(float64))
			if math.Float32bits(f32) == 0 { // +0
				break
			}
			p.From.Type = obj.TYPE_MEM
			p.From.Sym = ctxt.Float32Sym(f32)
			p.From.Name = obj.NAME_EXTERN
			p.From.Offset = 0
		}

	case AFMOVD:
		if p.From.Type == obj.TYPE_FCONST {
			f64 := p.From.Val.(float64)
			if math.Float64bits(f64) == 0 { // +0
				break
			}
			p.From.Type = obj.TYPE_MEM
			p.From.Sym = ctxt.Float64Sym(f64)
			p.From.Name = obj.NAME_EXTERN
			p.From.Offset = 0
		}

		// put constants not loadable by LOAD IMMEDIATE into memory
	case AMOVD:
		if p.From.Type == obj.TYPE_CONST {
			val := p.From.Offset
			if int64(int32(val)) != val &&
				int64(uint32(val)) != val &&
				int64(uint64(val)&(0xffffffff<<32)) != val {
				p.From.Type = obj.TYPE_MEM
				p.From.Sym = ctxt.Int64Sym(p.From.Offset)
				p.From.Name = obj.NAME_EXTERN
				p.From.Offset = 0
			}
		}
	}

	// Rewrite SUB constants into ADD.
	switch p.As {
	case ASUBC:
		if p.From.Type == obj.TYPE_CONST && isint32(-p.From.Offset) {
			p.From.Offset = -p.From.Offset
			p.As = AADDC
		}

	case ASUB:
		if p.From.Type == obj.TYPE_CONST && isint32(-p.From.Offset) {
			p.From.Offset = -p.From.Offset
			p.As = AADD
		}
	}

	if c.ctxt.Flag_dynlink {
		c.rewriteToUseGot(p)
	}
}

// Rewrite p, if necessary, to access global data via the global offset table.
func (c *ctxtz) rewriteToUseGot(p *obj.Prog) {
	// At the moment EXRL instructions are not emitted by the compiler and only reference local symbols in
	// assembly code.
	if p.As == AEXRL {
		return
	}

	// We only care about global data: NAME_EXTERN means a global
	// symbol in the Go sense, and p.Sym.Local is true for a few
	// internally defined symbols.
	// Rewrites must not clobber flags and therefore cannot use the
	// ADD instruction.
	if p.From.Type == obj.TYPE_ADDR && p.From.Name == obj.NAME_EXTERN && !p.From.Sym.Local() {
		// MOVD $sym, Rx becomes MOVD sym@GOT, Rx
		// MOVD $sym+<off>, Rx becomes MOVD sym@GOT, Rx or REGTMP2; MOVD $<off>(Rx or REGTMP2), Rx
		if p.To.Type != obj.TYPE_REG || p.As != AMOVD {
			c.ctxt.Diag("do not know how to handle LEA-type insn to non-register in %v with -dynlink", p)
		}
		p.From.Type = obj.TYPE_MEM
		p.From.Name = obj.NAME_GOTREF
		q := p
		if p.From.Offset != 0 {
			target := p.To.Reg
			if target == REG_R0 {
				// Cannot use R0 as input to address calculation.
				// REGTMP might be used by the assembler.
				p.To.Reg = REGTMP2
			}
			q = obj.Appendp(q, c.newprog)
			q.As = AMOVD
			q.From.Type = obj.TYPE_ADDR
			q.From.Offset = p.From.Offset
			q.From.Reg = p.To.Reg
			q.To.Type = obj.TYPE_REG
			q.To.Reg = target
			p.From.Offset = 0
		}
	}
	if p.GetFrom3() != nil && p.GetFrom3().Name == obj.NAME_EXTERN {
		c.ctxt.Diag("don't know how to handle %v with -dynlink", p)
	}
	var source *obj.Addr
	// MOVD sym, Ry becomes MOVD sym@GOT, REGTMP2; MOVD (REGTMP2), Ry
	// MOVD Ry, sym becomes MOVD sym@GOT, REGTMP2; MOVD Ry, (REGTMP2)
	// An addition may be inserted between the two MOVs if there is an offset.
	if p.From.Name == obj.NAME_EXTERN && !p.From.Sym.Local() {
		if p.To.Name == obj.NAME_EXTERN && !p.To.Sym.Local() {
			c.ctxt.Diag("cannot handle NAME_EXTERN on both sides in %v with -dynlink", p)
		}
		source = &p.From
	} else if p.To.Name == obj.NAME_EXTERN && !p.To.Sym.Local() {
		source = &p.To
	} else {
		return
	}
	if p.As == obj.ATEXT || p.As == obj.AFUNCDATA || p.As == obj.ACALL || p.As == obj.ARET || p.As == obj.AJMP {
		return
	}
	if source.Sym.Type == objabi.STLSBSS {
		return
	}
	if source.Type != obj.TYPE_MEM {
		c.ctxt.Diag("don't know how to handle %v with -dynlink", p)
	}
	p1 := obj.Appendp(p, c.newprog)
	p2 := obj.Appendp(p1, c.newprog)

	p1.As = AMOVD
	p1.From.Type = obj.TYPE_MEM
	p1.From.Sym = source.Sym
	p1.From.Name = obj.NAME_GOTREF
	p1.To.Type = obj.TYPE_REG
	p1.To.Reg = REGTMP2

	p2.As = p.As
	p2.From = p.From
	p2.To = p.To
	if p.From.Name == obj.NAME_EXTERN {
		p2.From.Reg = REGTMP2
		p2.From.Name = obj.NAME_NONE
		p2.From.Sym = nil
	} else if p.To.Name == obj.NAME_EXTERN {
		p2.To.Reg = REGTMP2
		p2.To.Name = obj.NAME_NONE
		p2.To.Sym = nil
	} else {
		return
	}
	obj.Nopout(p)
}

func preprocess(ctxt *obj.Link, cursym *obj.LSym, newprog obj.ProgAlloc) {
	// TODO(minux): add morestack short-cuts with small fixed frame-size.
	if cursym.Func().Text == nil || cursym.Func().Text.Link == nil {
		return
	}

	c := ctxtz{ctxt: ctxt, cursym: cursym, newprog: newprog}

	p := c.cursym.Func().Text
	textstksiz := p.To.Offset
	if textstksiz == -8 {
		// Compatibility hack.
		p.From.Sym.Set(obj.AttrNoFrame, true)
		textstksiz = 0
	}
	if textstksiz%8 != 0 {
		c.ctxt.Diag("frame size %d not a multiple of 8", textstksiz)
	}
	if p.From.Sym.NoFrame() {
		if textstksiz != 0 {
			c.ctxt.Diag("NOFRAME functions must have a frame size of 0, not %d", textstksiz)
		}
	}

	c.cursym.Func().Args = p.To.Val.(int32)
	c.cursym.Func().Locals = int32(textstksiz)

	/*
	 * find leaf subroutines
	 * strip NOPs
	 * expand RET
	 */

	var q *obj.Prog
	for p := c.cursym.Func().Text; p != nil; p = p.Link {
		switch p.As {
		case obj.ATEXT:
			q = p
			p.Mark |= LEAF

		case ABL, ABCL:
			q = p
			c.cursym.Func().Text.Mark &^= LEAF
			fallthrough

		case ABC,
			ABRC,
			ABEQ,
			ABGE,
			ABGT,
			ABLE,
			ABLT,
			ABLEU,
			ABLTU,
			ABNE,
			ABR,
			ABVC,
			ABVS,
			ACRJ,
			ACGRJ,
			ACLRJ,
			ACLGRJ,
			ACIJ,
			ACGIJ,
			ACLIJ,
			ACLGIJ,
			ACMPBEQ,
			ACMPBGE,
			ACMPBGT,
			ACMPBLE,
			ACMPBLT,
			ACMPBNE,
			ACMPUBEQ,
			ACMPUBGE,
			ACMPUBGT,
			ACMPUBLE,
			ACMPUBLT,
			ACMPUBNE:
			q = p
			p.Mark |= BRANCH

		default:
			q = p
		}
	}

	autosize := int32(0)
	var pLast *obj.Prog
	var pPre *obj.Prog
	var pPreempt *obj.Prog
	var pCheck *obj.Prog
	wasSplit := false
	for p := c.cursym.Func().Text; p != nil; p = p.Link {
		pLast = p
		switch p.As {
		case obj.ATEXT:
			autosize = int32(textstksiz)

			if p.Mark&LEAF != 0 && autosize == 0 {
				// A leaf function with no locals has no frame.
				p.From.Sym.Set(obj.AttrNoFrame, true)
			}

			if !p.From.Sym.NoFrame() {
				// If there is a stack frame at all, it includes
				// space to save the LR.
				autosize += int32(c.ctxt.Arch.FixedFrameSize)
			}

			if p.Mark&LEAF != 0 && autosize < abi.StackSmall {
				// A leaf function with a small stack can be marked
				// NOSPLIT, avoiding a stack check.
				p.From.Sym.Set(obj.AttrNoSplit, true)
			}

			p.To.Offset = int64(autosize)

			q := p

			if !p.From.Sym.NoSplit() {
				p, pPreempt, pCheck = c.stacksplitPre(p, autosize) // emit pre part of split check
				pPre = p
				p = c.ctxt.EndUnsafePoint(p, c.newprog, -1)
				wasSplit = true //need post part of split
			}

			if autosize != 0 {
				// Make sure to save link register for non-empty frame, even if
				// it is a leaf function, so that traceback works.
				// Store link register before decrementing SP, so if a signal comes
				// during the execution of the function prologue, the traceback
				// code will not see a half-updated stack frame.
				// This sequence is not async preemptible, as if we open a frame
				// at the current SP, it will clobber the saved LR.
				q = c.ctxt.StartUnsafePoint(p, c.newprog)

				q = obj.Appendp(q, c.newprog)
				q.As = AMOVD
				q.From.Type = obj.TYPE_REG
				q.From.Reg = REG_LR
				q.To.Type = obj.TYPE_MEM
				q.To.Reg = REGSP
				q.To.Offset = int64(-autosize)

				q = obj.Appendp(q, c.newprog)
				q.As = AMOVD
				q.From.Type = obj.TYPE_ADDR
				q.From.Offset = int64(-autosize)
				q.From.Reg = REGSP // not actually needed - REGSP is assumed if no reg is provided
				q.To.Type = obj.TYPE_REG
				q.To.Reg = REGSP
				q.Spadj = autosize

				q = c.ctxt.EndUnsafePoint(q, c.newprog, -1)

				// On Linux, in a cgo binary we may get a SIGSETXID signal early on
				// before the signal stack is set, as glibc doesn't allow us to block
				// SIGSETXID. So a signal may land on the current stack and clobber
				// the content below the SP. We store the LR again after the SP is
				// decremented.
				q = obj.Appendp(q, c.newprog)
				q.As = AMOVD
				q.From.Type = obj.TYPE_REG
				q.From.Reg = REG_LR
				q.To.Type = obj.TYPE_MEM
				q.To.Reg = REGSP
				q.To.Offset = 0
			} else if c.cursym.Func().Text.Mark&LEAF == 0 {
				// A very few functions that do not return to their caller
				// (e.g. gogo) are not identified as leaves but still have
				// no frame.
				c.cursym.Func().Text.Mark |= LEAF
			}

			if c.cursym.Func().Text.Mark&LEAF != 0 {
				c.cursym.Set(obj.AttrLeaf, true)
				break
			}

			if c.cursym.Func().Text.From.Sym.Wrapper() {
				// if(g->panic != nil && g->panic->argp == FP) g->panic->argp = bottom-of-frame
				//
				//	MOVD g_panic(g), R3
				//	CMP R3, $0
				//	BEQ end
				//	MOVD panic_argp(R3), R4
				//	ADD $(autosize+8), R1, R5
				//	CMP R4, R5
				//	BNE end
				//	ADD $8, R1, R6
				//	MOVD R6, panic_argp(R3)
				// end:
				//	NOP
				//
				// The NOP is needed to give the jumps somewhere to land.
				// It is a liblink NOP, not a s390x NOP: it encodes to 0 instruction bytes.

				q = obj.Appendp(q, c.newprog)

				q.As = AMOVD
				q.From.Type = obj.TYPE_MEM
				q.From.Reg = REGG
				q.From.Offset = 4 * int64(c.ctxt.Arch.PtrSize) // G.panic
				q.To.Type = obj.TYPE_REG
				q.To.Reg = REG_R3

				q = obj.Appendp(q, c.newprog)
				q.As = ACMP
				q.From.Type = obj.TYPE_REG
				q.From.Reg = REG_R3
				q.To.Type = obj.TYPE_CONST
				q.To.Offset = 0

				q = obj.Appendp(q, c.newprog)
				q.As = ABEQ
				q.To.Type = obj.TYPE_BRANCH
				p1 := q

				q = obj.Appendp(q, c.newprog)
				q.As = AMOVD
				q.From.Type = obj.TYPE_MEM
				q.From.Reg = REG_R3
				q.From.Offset = 0 // Panic.argp
				q.To.Type = obj.TYPE_REG
				q.To.Reg = REG_R4

				q = obj.Appendp(q, c.newprog)
				q.As = AADD
				q.From.Type = obj.TYPE_CONST
				q.From.Offset = int64(autosize) + c.ctxt.Arch.FixedFrameSize
				q.Reg = REGSP
				q.To.Type = obj.TYPE_REG
				q.To.Reg = REG_R5

				q = obj.Appendp(q, c.newprog)
				q.As = ACMP
				q.From.Type = obj.TYPE_REG
				q.From.Reg = REG_R4
				q.To.Type = obj.TYPE_REG
				q.To.Reg = REG_R5

				q = obj.Appendp(q, c.newprog)
				q.As = ABNE
				q.To.Type = obj.TYPE_BRANCH
				p2 := q

				q = obj.Appendp(q, c.newprog)
				q.As = AADD
				q.From.Type = obj.TYPE_CONST
				q.From.Offset = c.ctxt.Arch.FixedFrameSize
				q.Reg = REGSP
				q.To.Type = obj.TYPE_REG
				q.To.Reg = REG_R6

				q = obj.Appendp(q, c.newprog)
				q.As = AMOVD
				q.From.Type = obj.TYPE_REG
				q.From.Reg = REG_R6
				q.To.Type = obj.TYPE_MEM
				q.To.Reg = REG_R3
				q.To.Offset = 0 // Panic.argp

				q = obj.Appendp(q, c.newprog)

				q.As = obj.ANOP
				p1.To.SetTarget(q)
				p2.To.SetTarget(q)
			}

		case obj.ARET:
			retTarget := p.To.Sym

			if c.cursym.Func().Text.Mark&LEAF != 0 {
				if autosize == 0 {
					p.As = ABR
					p.From = obj.Addr{}
					if retTarget == nil {
						p.To.Type = obj.TYPE_REG
						p.To.Reg = REG_LR
					} else {
						p.To.Type = obj.TYPE_BRANCH
						p.To.Sym = retTarget
					}
					p.Mark |= BRANCH
					break
				}

				p.As = AADD
				p.From.Type = obj.TYPE_CONST
				p.From.Offset = int64(autosize)
				p.To.Type = obj.TYPE_REG
				p.To.Reg = REGSP
				p.Spadj = -autosize

				q = obj.Appendp(p, c.newprog)
				q.As = ABR
				q.From = obj.Addr{}
				if retTarget == nil {
					q.To.Type = obj.TYPE_REG
					q.To.Reg = REG_LR
				} else {
					q.To.Type = obj.TYPE_BRANCH
					q.To.Sym = retTarget
				}
				q.Mark |= BRANCH
				q.Spadj = autosize
				break
			}

			p.As = AMOVD
			p.From.Type = obj.TYPE_MEM
			p.From.Reg = REGSP
			p.From.Offset = 0
			p.To = obj.Addr{
				Type: obj.TYPE_REG,
				Reg:  REG_LR,
			}

			q = p

			if autosize != 0 {
				q = obj.Appendp(q, c.newprog)
				q.As = AADD
				q.From.Type = obj.TYPE_CONST
				q.From.Offset = int64(autosize)
				q.To.Type = obj.TYPE_REG
				q.To.Reg = REGSP
				q.Spadj = -autosize
			}

			q = obj.Appendp(q, c.newprog)
			q.As = ABR
			q.From = obj.Addr{}
			if retTarget == nil {
				q.To.Type = obj.TYPE_REG
				q.To.Reg = REG_LR
			} else {
				q.To.Type = obj.TYPE_BRANCH
				q.To.Sym = retTarget
			}
			q.Mark |= BRANCH
			q.Spadj = autosize

		case AADD:
			if p.To.Type == obj.TYPE_REG && p.To.Reg == REGSP && p.From.Type == obj.TYPE_CONST {
				p.Spadj = int32(-p.From.Offset)
			}

		case obj.AGETCALLERPC:
			if cursym.Leaf() {
				/* MOVD LR, Rd */
				p.As = AMOVD
				p.From.Type = obj.TYPE_REG
				p.From.Reg = REG_LR
			} else {
				/* MOVD (RSP), Rd */
				p.As = AMOVD
				p.From.Type = obj.TYPE_MEM
				p.From.Reg = REGSP
			}
		}

		if p.To.Type == obj.TYPE_REG && p.To.Reg == REGSP && p.Spadj == 0 {
			f := c.cursym.Func()
			if f.FuncFlag&abi.FuncFlagSPWrite == 0 {
				c.cursym.Func().FuncFlag |= abi.FuncFlagSPWrite
				if ctxt.Debugvlog || !ctxt.IsAsm {
					ctxt.Logf("auto-SPWRITE: %s\n", c.cursym.Name)
					if !ctxt.IsAsm {
						ctxt.Diag("invalid auto-SPWRITE in non-assembly")
						ctxt.DiagFlush()
						log.Fatalf("bad SPWRITE")
					}
				}
			}
		}
	}
	if wasSplit {
		c.stacksplitPost(pLast, pPre, pPreempt, pCheck, autosize) // emit post part of split check
	}
}

// stacksplitPre generates the function stack check prologue following
// Prog p (which should be the TEXT Prog). It returns one or two
// branch Progs that must be patched to jump to the morestack epilogue,
// and the Prog that starts the morestack check.
func (c *ctxtz) stacksplitPre(p *obj.Prog, framesize int32) (pPre, pPreempt, pCheck *obj.Prog) {
	if c.ctxt.Flag_maymorestack != "" {
		// Save LR and REGCTXT
		const frameSize = 16
		p = c.ctxt.StartUnsafePoint(p, c.newprog)
		// MOVD LR, -16(SP)
		p = obj.Appendp(p, c.newprog)
		p.As = AMOVD
		p.From = obj.Addr{Type: obj.TYPE_REG, Reg: REG_LR}
		p.To = obj.Addr{Type: obj.TYPE_MEM, Reg: REGSP, Offset: -frameSize}
		// MOVD $-16(SP), SP
		p = obj.Appendp(p, c.newprog)
		p.As = AMOVD
		p.From = obj.Addr{Type: obj.TYPE_ADDR, Offset: -frameSize, Reg: REGSP}
		p.To = obj.Addr{Type: obj.TYPE_REG, Reg: REGSP}
		p.Spadj = frameSize
		// MOVD REGCTXT, 8(SP)
		p = obj.Appendp(p, c.newprog)
		p.As = AMOVD
		p.From = obj.Addr{Type: obj.TYPE_REG, Reg: REGCTXT}
		p.To = obj.Addr{Type: obj.TYPE_MEM, Reg: REGSP, Offset: 8}

		// BL maymorestack
		p = obj.Appendp(p, c.newprog)
		p.As = ABL
		// See ../x86/obj6.go
		sym := c.ctxt.LookupABI(c.ctxt.Flag_maymorestack, c.cursym.ABI())
		p.To = obj.Addr{Type: obj.TYPE_BRANCH, Sym: sym}

		// Restore LR and REGCTXT

		// MOVD REGCTXT, 8(SP)
		p = obj.Appendp(p, c.newprog)
		p.As = AMOVD
		p.From = obj.Addr{Type: obj.TYPE_MEM, Reg: REGSP, Offset: 8}
		p.To = obj.Addr{Type: obj.TYPE_REG, Reg: REGCTXT}
		// MOVD (SP), LR
		p = obj.Appendp(p, c.newprog)
		p.As = AMOVD
		p.From = obj.Addr{Type: obj.TYPE_MEM, Reg: REGSP, Offset: 0}
		p.To = obj.Addr{Type: obj.TYPE_REG, Reg: REG_LR}
		// MOVD $16(SP), SP
		p = obj.Appendp(p, c.newprog)
		p.As = AMOVD
		p.From = obj.Addr{Type: obj.TYPE_CONST, Reg: REGSP, Offset: frameSize}
		p.To = obj.Addr{Type: obj.TYPE_REG, Reg: REGSP}
		p.Spadj = -frameSize

		p = c.ctxt.EndUnsafePoint(p, c.newprog, -1)
	}

	// MOVD	g_stackguard(g), R3
	p = obj.Appendp(p, c.newprog)
	// Jump back to here after morestack returns.
	pCheck = p

	p.As = AMOVD
	p.From.Type = obj.TYPE_MEM
	p.From.Reg = REGG
	p.From.Offset = 2 * int64(c.ctxt.Arch.PtrSize) // G.stackguard0
	if c.cursym.CFunc() {
		p.From.Offset = 3 * int64(c.ctxt.Arch.PtrSize) // G.stackguard1
	}
	p.To.Type = obj.TYPE_REG
	p.To.Reg = REG_R3

	// Mark the stack bound check and morestack call async nonpreemptible.
	// If we get preempted here, when resumed the preemption request is
	// cleared, but we'll still call morestack, which will double the stack
	// unnecessarily. See issue #35470.
	p = c.ctxt.StartUnsafePoint(p, c.newprog)

	if framesize <= abi.StackSmall {
		// small stack: SP < stackguard
		//	CMPUBGE	stackguard, SP, label-of-call-to-morestack

		p = obj.Appendp(p, c.newprog)
		p.From.Type = obj.TYPE_REG
		p.From.Reg = REG_R3
		p.Reg = REGSP
		p.As = ACMPUBGE
		p.To.Type = obj.TYPE_BRANCH

		return p, nil, pCheck
	}

	// large stack: SP-framesize < stackguard-StackSmall

	offset := int64(framesize) - abi.StackSmall
	if framesize > abi.StackBig {
		// Such a large stack we need to protect against underflow.
		// The runtime guarantees SP > objabi.StackBig, but
		// framesize is large enough that SP-framesize may
		// underflow, causing a direct comparison with the
		// stack guard to incorrectly succeed. We explicitly
		// guard against underflow.
		//
		//	MOVD	$(framesize-StackSmall), R4
		//	CMPUBLT	SP, R4, label-of-call-to-morestack

		p = obj.Appendp(p, c.newprog)
		p.As = AMOVD
		p.From.Type = obj.TYPE_CONST
		p.From.Offset = offset
		p.To.Type = obj.TYPE_REG
		p.To.Reg = REG_R4

		p = obj.Appendp(p, c.newprog)
		pPreempt = p
		p.As = ACMPUBLT
		p.From.Type = obj.TYPE_REG
		p.From.Reg = REGSP
		p.Reg = REG_R4
		p.To.Type = obj.TYPE_BRANCH
	}

	// Check against the stack guard. We've ensured this won't underflow.
	//	ADD $-(framesize-StackSmall), SP, R4
	//	CMPUBGE stackguard, R4, label-of-call-to-morestack
	p = obj.Appendp(p, c.newprog)
	p.As = AADD
	p.From.Type = obj.TYPE_CONST
	p.From.Offset = -offset
	p.Reg = REGSP
	p.To.Type = obj.TYPE_REG
	p.To.Reg = REG_R4

	p = obj.Appendp(p, c.newprog)
	p.From.Type = obj.TYPE_REG
	p.From.Reg = REG_R3
	p.Reg = REG_R4
	p.As = ACMPUBGE
	p.To.Type = obj.TYPE_BRANCH

	return p, pPreempt, pCheck
}

// stacksplitPost generates the function epilogue that calls morestack
// and returns the new last instruction in the function.
//
// p is the last Prog in the function. pPre and pPreempt, if non-nil,
// are the instructions that branch to the epilogue. This will fill in
// their branch targets. pCheck is the Prog that begins the stack check.
func (c *ctxtz) stacksplitPost(p *obj.Prog, pPre, pPreempt, pCheck *obj.Prog, framesize int32) *obj.Prog {
	// Now we are at the end of the function, but logically
	// we are still in function prologue. We need to fix the
	// SP data and PCDATA.
	spfix := obj.Appendp(p, c.newprog)
	spfix.As = obj.ANOP
	spfix.Spadj = -framesize

	pcdata := c.ctxt.EmitEntryStackMap(c.cursym, spfix, c.newprog)
	pcdata = c.ctxt.StartUnsafePoint(pcdata, c.newprog)

	// MOVD	LR, R5
	p = obj.Appendp(pcdata, c.newprog)
	pPre.To.SetTarget(p)
	p.As = AMOVD
	p.From.Type = obj.TYPE_REG
	p.From.Reg = REG_LR
	p.To.Type = obj.TYPE_REG
	p.To.Reg = REG_R5
	if pPreempt != nil {
		pPreempt.To.SetTarget(p)
	}

	// BL	runtime.morestack(SB)
	p = obj.Appendp(p, c.newprog)

	p.As = ABL
	p.To.Type = obj.TYPE_BRANCH
	if c.cursym.CFunc() {
		p.To.Sym = c.ctxt.Lookup("runtime.morestackc")
	} else if !c.cursym.Func().Text.From.Sym.NeedCtxt() {
		p.To.Sym = c.ctxt.Lookup("runtime.morestack_noctxt")
	} else {
		p.To.Sym = c.ctxt.Lookup("runtime.morestack")
	}

	p = c.ctxt.EndUnsafePoint(p, c.newprog, -1)

	// BR	pCheck
	p = obj.Appendp(p, c.newprog)

	p.As = ABR
	p.To.Type = obj.TYPE_BRANCH
	p.To.SetTarget(pCheck)
	return p
}

var unaryDst = map[obj.As]bool{
	ASTCK:  true,
	ASTCKC: true,
	ASTCKE: true,
	ASTCKF: true,
	ANEG:   true,
	ANEGW:  true,
	AVONE:  true,
	AVZERO: true,
}

var Links390x = obj.LinkArch{
	Arch:           sys.ArchS390X,
	Init:           buildop,
	Preprocess:     preprocess,
	Assemble:       spanz,
	Progedit:       progedit,
	UnaryDst:       unaryDst,
	DWARFRegisters: S390XDWARFRegisters,
}
```