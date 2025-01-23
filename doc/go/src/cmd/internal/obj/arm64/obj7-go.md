Response: Let's break down the thought process for analyzing the provided Go code snippet.

1. **Identify the Core Purpose:** The very first thing to notice is the package declaration: `package arm64`. Combined with the file path `go/src/cmd/internal/obj/arm64/obj7.go`, it immediately signals that this code is part of the Go compiler's architecture-specific backend for ARM64. The `obj` part of the path suggests it deals with object code manipulation.

2. **Examine the Imports:**  The imports provide valuable context:
    * `cmd/internal/obj`: Core data structures for representing object code (like `Prog`, `Addr`, `LSym`).
    * `cmd/internal/objabi`:  Definitions for object code ABI (Application Binary Interface) details.
    * `cmd/internal/src`: Source code position tracking.
    * `cmd/internal/sys`: System architecture information.
    * `internal/abi`:  Internal ABI constants.
    * `internal/buildcfg`: Build configuration details.
    * `log`:  Logging capabilities.
    * `math`: Mathematical functions.

3. **Analyze Global Variables:** The `zrReplace` map stands out. Its purpose is clearly stated in the comment: to identify instructions where `$0` in the `From` operand should be replaced with `REGZERO`. This hints at a compiler optimization or code normalization step.

4. **Focus on Key Functions:** The code contains several functions. A good approach is to look for functions that seem to have a broader scope or handle common compiler tasks.
    * `stacksplit`:  The name strongly suggests it's responsible for handling stack splitting, a crucial aspect of Go's goroutine implementation. The code within confirms this, dealing with saving registers, calling `runtime.morestack`, and restoring state.
    * `progedit`:  This likely stands for "program edit" or "program editing." The comments and code within suggest it manipulates the instructions in a program, performing tasks like rewriting branches, handling constants, and dealing with dynamic linking.
    * `preprocess`:  The name implies this function runs before the main compilation/assembly phase. It examines function definitions, determines stack frame sizes, identifies leaf functions, and inserts stack checks.

5. **Deep Dive into `stacksplit`:**
    * **Trigger:** The `if c.ctxt.Flag_maymorestack != ""` condition tells us this logic is involved when the `-maymorestack` flag is used during compilation. This flag is likely for testing or specific runtime scenarios.
    * **Core Logic:** The code saves and restores registers (LR, FP, REGCTXT), calls a function named after the value of `Flag_maymorestack`, and then performs stack bound checks. The different logic for small, medium, and large stacks is interesting.
    * **Relate to Go:**  This clearly relates to Go's ability to grow stacks dynamically. When a function call might exceed the current stack space, `runtime.morestack` is called to allocate a larger stack.
    * **Example:**  A recursive function without tail-call optimization is a classic example that might trigger stack growth.

6. **Deep Dive into `progedit`:**
    * **Zero Replacement:** The code explicitly mentions the handling of `$0` and `zrReplace`, confirming the initial hypothesis.
    * **Branch Rewriting:**  The code rewrites `BR` and `BL` instructions to have `TYPE_BRANCH` operands, which is necessary for the linker.
    * **Constant Handling:** The code converts floating-point and vector constants into memory references. This is a common optimization to avoid embedding large constants directly in the instruction stream.
    * **Dynamic Linking:** The `rewriteToUseGot` function is a dead giveaway that this part handles dynamic linking by accessing global data via the Global Offset Table (GOT).
    * **Example:**  Accessing a global variable declared in another package in a dynamically linked program.

7. **Deep Dive into `preprocess`:**
    * **Frame Size Calculation:**  The code calculates the stack frame size (`autosize`) and considers the `NOFRAME` attribute.
    * **Leaf Function Identification:**  It identifies leaf functions (functions that don't call other functions) for optimization purposes.
    * **Stack Split Insertion:**  It calls `stacksplit` to insert the necessary stack check logic.
    * **Prologue Generation:**  It generates the function prologue, which sets up the stack frame, saves registers, and potentially calls runtime functions for stack management.
    * **Epilogue Generation (Implicit):**  While not a separate function, the handling of `obj.ARET` (return) effectively generates the function epilogue, restoring the stack and returning.
    * **Example:** Any Go function will go through this preprocessing step.

8. **Identify Potential Mistakes:**  Look for patterns that might lead to errors.
    * **Stack Size Calculation:**  The comment about unaligned frame sizes hints at a potential issue if developers manually try to manipulate stack sizes incorrectly (although this is unlikely in typical Go code).
    * **Dynamic Linking:** The complexity of `rewriteToUseGot` suggests that subtle errors in linker configurations or external library interactions could arise.

9. **Structure the Output:** Organize the findings logically, starting with the overall purpose and then detailing the functionality of each key component. Use code examples to illustrate the concepts and provide context. Address all parts of the prompt (functionality, Go features, code reasoning, command-line parameters (if any), and common mistakes).

10. **Review and Refine:**  Read through the analysis to ensure accuracy, clarity, and completeness. Check if all aspects of the provided code have been addressed. For instance, ensure the `zrReplace` logic is explained in `progedit`.

This detailed thought process, breaking down the code into smaller, manageable parts and connecting them to higher-level Go concepts, is crucial for understanding complex compiler code. The process involves a combination of code reading, inferring from names and comments, and relating the code to the known behavior of the Go runtime and compiler.
这是 Go 语言编译器 `cmd/compile` 中 ARM64 架构特定的对象文件处理代码 `obj7.go` 的一部分。它主要负责将中间表示的指令转换为最终的 ARM64 汇编指令，并进行一些架构相关的优化和处理。

以下是它的一些主要功能：

1. **`zrReplace` 变量:**  这是一个 `map[obj.As]bool`，用于指定某些 ARM64 指令（例如 `AMOVD`, `AMOVW` 等）的 `From` 操作数中如果使用了常量 `0`，则应该将其替换为 `REGZERO` 寄存器。这是一种代码规范化或者特定指令优化的手段。

2. **`stacksplit` 函数:** 这个函数负责在函数入口插入栈溢出检查的代码。它会根据函数的栈帧大小 (`framesize`) 生成不同的指令序列来检查剩余栈空间是否足够。如果栈空间不足，它会调用 `runtime.morestack` 或 `runtime.morestackc` 来扩展栈。
   - **`c.ctxt.Flag_maymorestack != ""` 分支:**  这个分支处理了 `-maymorestack` 编译选项的情况，它会保存一些寄存器，调用指定的函数，并在返回后恢复寄存器。这通常用于测试或特定的运行时场景。
   - **栈检查逻辑:** 根据 `framesize` 的大小，生成不同的栈检查指令：
     - 小栈 (`framesize <= abi.StackSmall`): 直接比较栈顶指针 `SP` 和栈警戒线 `stackguard`。
     - 中栈 (`framesize <= abi.StackBig`): 计算 `SP - (framesize - abi.StackSmall)`，然后与 `stackguard` 比较。
     - 大栈: 除了比较，还会检查是否发生下溢 (`SUBS` 指令)，如果下溢则直接跳转到 `morestack`。
   - **调用 `runtime.morestack`:** 如果栈空间不足，则调用运行时函数来扩展栈。`runtime.morestackc` 用于 C 函数调用的情况， `runtime.morestack_noctxt` 用于不需要上下文的场景。
   - **插入安全点:** 使用 `c.ctxt.StartUnsafePoint` 和 `c.ctxt.EndUnsafePoint` 标记栈检查和 `morestack` 调用为不可异步抢占的点。

3. **`progedit` 函数:**  这个函数负责对指令进行最终的编辑和调整，使其符合 ARM64 架构的规范和优化需求。
   - **`zrReplace` 处理:**  对于 `zrReplace` 中指定的指令，如果 `From` 操作数是常量 `0`，则将其替换为 `REGZERO`。
   - **分支指令类型重写:** 将 `BR` 和 `BL` 指令的目标符号类型设置为 `obj.TYPE_BRANCH`，方便后续处理。
   - **浮点数和向量常量处理:** 将浮点数和向量常量转换为内存中的值，并使用符号引用。这避免了在指令中直接嵌入大的常量值。
   - **动态链接处理 (`c.ctxt.Flag_dynlink`):**  如果启用了动态链接，则调用 `rewriteToUseGot` 函数来将全局数据的访问重写为通过全局偏移表 (GOT) 进行。

4. **`rewriteToUseGot` 函数:** 当启用动态链接时，这个函数会将对全局变量的直接访问转换为通过 GOT 表的间接访问。
   - **`ADUFFCOPY` 和 `ADUFFZERO` 处理:** 将对 `runtime.duffcopy` 和 `runtime.duffzero` 的调用转换为通过 GOT 表的间接调用。
   - **全局变量访问重写:** 将 `MOVD $sym, Rx` 形式的指令转换为 `MOVD sym@GOT, Rx`，如果存在偏移量，还会添加 `ADD` 指令。
   - **外部符号操作数处理:** 对于指令的操作数是外部符号的情况，将其转换为通过 GOT 表的访问。

5. **`preprocess` 函数:**  这个函数在汇编之前对函数进行预处理。
   - **栈帧大小计算:** 计算函数的栈帧大小，并处理 `NOFRAME` 属性。
   - **叶子函数识别:** 标记不调用其他函数的叶子函数，以便进行优化。
   - **插入栈溢出检查:** 调用 `stacksplit` 函数插入栈溢出检查代码。
   - **生成函数序言:** 生成函数的序言代码，包括保存链接寄存器 (LR)、帧指针 (FP) 和调整栈指针 (SP)。对于大栈帧，会先将 SP 减去整个栈帧大小，再保存 FP 和 LR。对于小栈帧，可以使用带有预递减的 `AMOVD` 指令一次完成 SP 的调整和 LR 的保存。
   - **处理包装器函数:**  对于包装器函数，插入额外的代码来检查和更新 `g->panic->argp`。
   - **生成函数结尾 (`obj.ARET` 处理):**  生成函数的结尾代码，包括恢复栈指针和帧指针，以及执行返回操作。对于叶子函数和非叶子函数，恢复栈的方式有所不同。
   - **`obj.AGETCALLERPC` 处理:**  根据是否为叶子函数，使用不同的指令获取调用者的程序计数器 (PC)。
   - **`obj.ADUFFCOPY` 和 `obj.ADUFFZERO` 展开:** 将这两个指令展开为一系列的 `ADR`, `STP`, `SUB` 指令。
   - **`Spadj` 调整:** 记录影响栈指针 `SP` 的指令，方便后续分析。
   - **移位操作处理:**  对移位操作的语法进行规范化。

6. **`nocache` 函数:**  这个函数用于清除指令的缓存相关信息，确保指令被重新处理。

7. **`Linkarm64` 变量:**  这是 `obj.LinkArch` 类型的变量，定义了 ARM64 架构的链接器配置，包括初始化函数、预处理函数、汇编函数、指令编辑函数等。

**可以推理出它是什么 go 语言功能的实现：**

从代码中可以看出，`obj7.go` 实现了 Go 语言中**goroutine 的栈管理**和**函数调用约定**在 ARM64 架构上的具体细节。

**Go 代码举例说明 `stacksplit` 的功能：**

```go
package main

import "fmt"

func recursiveFunc(n int) {
	fmt.Println("Entering recursiveFunc with n =", n)
	if n > 0 {
		recursiveFunc(n - 1)
	}
	fmt.Println("Exiting recursiveFunc with n =", n)
}

func main() {
	recursiveFunc(1000) // 假设这个深度可能超过初始栈大小
}
```

**假设的输入与输出：**

当编译 `main.go` 时，`preprocess` 函数会分析 `recursiveFunc` 并调用 `stacksplit`。由于 `recursiveFunc` 可能会导致栈溢出，`stacksplit` 会在 `recursiveFunc` 的入口处插入类似以下的汇编指令（简化版）：

```assembly
// ... 函数序言 ...
MOV	g_stackguard(g), RT1    // 加载栈警戒线
CMP	RT1, SP              // 比较栈顶指针和栈警戒线
BLS	do_morestack         // 如果栈空间不足，跳转到 do_morestack
// ... 函数体 ...

do_morestack:
  // ... 保存寄存器 ...
  BL	runtime.morestack    // 调用 runtime.morestack
  // ... 恢复寄存器 ...
  B	<函数入口>             // 跳转回函数入口重新执行
```

**命令行参数的具体处理:**

- **`-maymorestack`:**  如果编译时指定了 `-maymorestack=some_function_name`，那么 `stacksplit` 函数中的 `if c.ctxt.Flag_maymorestack != ""` 分支会被激活。它会生成额外的代码来保存和恢复寄存器，并调用名为 `some_function_name` 的函数。这个选项通常用于测试或调试目的，允许在栈扩展时执行自定义的逻辑。

**使用者易犯错的点 (与此代码直接相关的错误较少，更多是编译器开发者需要注意的点):**

- **栈帧大小计算错误:**  如果 `preprocess` 函数计算的栈帧大小不正确，会导致栈溢出检查失效或栈指针操作错误。
- **动态链接配置错误:**  在动态链接场景下，如果 GOT 表的生成或使用不正确，会导致链接错误或运行时访问全局变量失败。
- **指令模式匹配错误:** 在 `progedit` 中，如果对指令的操作数类型和格式判断不准确，可能导致错误的指令转换或优化。

总而言之，`go/src/cmd/internal/obj/arm64/obj7.go` 是 Go 语言编译器中负责将 Go 代码转换为 ARM64 机器码的关键部分，它处理了架构特定的指令转换、栈管理和动态链接等复杂任务。

### 提示词
```
这是路径为go/src/cmd/internal/obj/arm64/obj7.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
```

### 源代码
```go
// cmd/7l/noop.c, cmd/7l/obj.c, cmd/ld/pass.c from Vita Nuova.
// https://bitbucket.org/plan9-from-bell-labs/9-cc/src/master/
//
// 	Copyright © 1994-1999 Lucent Technologies Inc. All rights reserved.
// 	Portions Copyright © 1995-1997 C H Forsyth (forsyth@terzarima.net)
// 	Portions Copyright © 1997-1999 Vita Nuova Limited
// 	Portions Copyright © 2000-2007 Vita Nuova Holdings Limited (www.vitanuova.com)
// 	Portions Copyright © 2004,2006 Bruce Ellis
// 	Portions Copyright © 2005-2007 C H Forsyth (forsyth@terzarima.net)
// 	Revisions Copyright © 2000-2007 Lucent Technologies Inc. and others
// 	Portions Copyright © 2009 The Go Authors. All rights reserved.
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

package arm64

import (
	"cmd/internal/obj"
	"cmd/internal/objabi"
	"cmd/internal/src"
	"cmd/internal/sys"
	"internal/abi"
	"internal/buildcfg"
	"log"
	"math"
)

// zrReplace is the set of instructions for which $0 in the From operand
// should be replaced with REGZERO.
var zrReplace = map[obj.As]bool{
	AMOVD:  true,
	AMOVW:  true,
	AMOVWU: true,
	AMOVH:  true,
	AMOVHU: true,
	AMOVB:  true,
	AMOVBU: true,
	ASBC:   true,
	ASBCW:  true,
	ASBCS:  true,
	ASBCSW: true,
	AADC:   true,
	AADCW:  true,
	AADCS:  true,
	AADCSW: true,
	AFMOVD: true,
	AFMOVS: true,
	AMSR:   true,
}

func (c *ctxt7) stacksplit(p *obj.Prog, framesize int32) *obj.Prog {
	if c.ctxt.Flag_maymorestack != "" {
		p = c.cursym.Func().SpillRegisterArgs(p, c.newprog)

		// Save LR and make room for FP, REGCTXT. Leave room
		// for caller's saved FP.
		const frameSize = 32
		p = obj.Appendp(p, c.newprog)
		p.As = AMOVD
		p.From.Type = obj.TYPE_REG
		p.From.Reg = REGLINK
		p.To.Type = obj.TYPE_MEM
		p.Scond = C_XPRE
		p.To.Offset = -frameSize
		p.To.Reg = REGSP
		p.Spadj = frameSize

		// Save FP.
		p = obj.Appendp(p, c.newprog)
		p.As = AMOVD
		p.From.Type = obj.TYPE_REG
		p.From.Reg = REGFP
		p.To.Type = obj.TYPE_MEM
		p.To.Reg = REGSP
		p.To.Offset = -8

		p = obj.Appendp(p, c.newprog)
		p.As = ASUB
		p.From.Type = obj.TYPE_CONST
		p.From.Offset = 8
		p.Reg = REGSP
		p.To.Type = obj.TYPE_REG
		p.To.Reg = REGFP

		// Save REGCTXT (for simplicity we do this whether or
		// not we need it.)
		p = obj.Appendp(p, c.newprog)
		p.As = AMOVD
		p.From.Type = obj.TYPE_REG
		p.From.Reg = REGCTXT
		p.To.Type = obj.TYPE_MEM
		p.To.Reg = REGSP
		p.To.Offset = 8

		// BL maymorestack
		p = obj.Appendp(p, c.newprog)
		p.As = ABL
		p.To.Type = obj.TYPE_BRANCH
		// See ../x86/obj6.go
		p.To.Sym = c.ctxt.LookupABI(c.ctxt.Flag_maymorestack, c.cursym.ABI())

		// Restore REGCTXT.
		p = obj.Appendp(p, c.newprog)
		p.As = AMOVD
		p.From.Type = obj.TYPE_MEM
		p.From.Reg = REGSP
		p.From.Offset = 8
		p.To.Type = obj.TYPE_REG
		p.To.Reg = REGCTXT

		// Restore FP.
		p = obj.Appendp(p, c.newprog)
		p.As = AMOVD
		p.From.Type = obj.TYPE_MEM
		p.From.Reg = REGSP
		p.From.Offset = -8
		p.To.Type = obj.TYPE_REG
		p.To.Reg = REGFP

		// Restore LR and SP.
		p = obj.Appendp(p, c.newprog)
		p.As = AMOVD
		p.From.Type = obj.TYPE_MEM
		p.Scond = C_XPOST
		p.From.Offset = frameSize
		p.From.Reg = REGSP
		p.To.Type = obj.TYPE_REG
		p.To.Reg = REGLINK
		p.Spadj = -frameSize

		p = c.cursym.Func().UnspillRegisterArgs(p, c.newprog)
	}

	// Jump back to here after morestack returns.
	startPred := p

	// MOV	g_stackguard(g), RT1
	p = obj.Appendp(p, c.newprog)

	p.As = AMOVD
	p.From.Type = obj.TYPE_MEM
	p.From.Reg = REGG
	p.From.Offset = 2 * int64(c.ctxt.Arch.PtrSize) // G.stackguard0
	if c.cursym.CFunc() {
		p.From.Offset = 3 * int64(c.ctxt.Arch.PtrSize) // G.stackguard1
	}
	p.To.Type = obj.TYPE_REG
	p.To.Reg = REGRT1

	// Mark the stack bound check and morestack call async nonpreemptible.
	// If we get preempted here, when resumed the preemption request is
	// cleared, but we'll still call morestack, which will double the stack
	// unnecessarily. See issue #35470.
	p = c.ctxt.StartUnsafePoint(p, c.newprog)

	q := (*obj.Prog)(nil)
	if framesize <= abi.StackSmall {
		// small stack: SP < stackguard
		//	CMP	stackguard, SP

		p = obj.Appendp(p, c.newprog)
		p.As = ACMP
		p.From.Type = obj.TYPE_REG
		p.From.Reg = REGRT1
		p.Reg = REGSP
	} else if framesize <= abi.StackBig {
		// large stack: SP-framesize < stackguard-StackSmall
		//	SUB	$(framesize-StackSmall), SP, RT2
		//	CMP	stackguard, RT2
		p = obj.Appendp(p, c.newprog)

		p.As = ASUB
		p.From.Type = obj.TYPE_CONST
		p.From.Offset = int64(framesize) - abi.StackSmall
		p.Reg = REGSP
		p.To.Type = obj.TYPE_REG
		p.To.Reg = REGRT2

		p = obj.Appendp(p, c.newprog)
		p.As = ACMP
		p.From.Type = obj.TYPE_REG
		p.From.Reg = REGRT1
		p.Reg = REGRT2
	} else {
		// Such a large stack we need to protect against underflow.
		// The runtime guarantees SP > objabi.StackBig, but
		// framesize is large enough that SP-framesize may
		// underflow, causing a direct comparison with the
		// stack guard to incorrectly succeed. We explicitly
		// guard against underflow.
		//
		//	SUBS	$(framesize-StackSmall), SP, RT2
		//	// On underflow, jump to morestack
		//	BLO	label_of_call_to_morestack
		//	CMP	stackguard, RT2

		p = obj.Appendp(p, c.newprog)
		p.As = ASUBS
		p.From.Type = obj.TYPE_CONST
		p.From.Offset = int64(framesize) - abi.StackSmall
		p.Reg = REGSP
		p.To.Type = obj.TYPE_REG
		p.To.Reg = REGRT2

		p = obj.Appendp(p, c.newprog)
		q = p
		p.As = ABLO
		p.To.Type = obj.TYPE_BRANCH

		p = obj.Appendp(p, c.newprog)
		p.As = ACMP
		p.From.Type = obj.TYPE_REG
		p.From.Reg = REGRT1
		p.Reg = REGRT2
	}

	// BLS	do-morestack
	bls := obj.Appendp(p, c.newprog)
	bls.As = ABLS
	bls.To.Type = obj.TYPE_BRANCH

	end := c.ctxt.EndUnsafePoint(bls, c.newprog, -1)

	var last *obj.Prog
	for last = c.cursym.Func().Text; last.Link != nil; last = last.Link {
	}

	// Now we are at the end of the function, but logically
	// we are still in function prologue. We need to fix the
	// SP data and PCDATA.
	spfix := obj.Appendp(last, c.newprog)
	spfix.As = obj.ANOP
	spfix.Spadj = -framesize

	pcdata := c.ctxt.EmitEntryStackMap(c.cursym, spfix, c.newprog)
	pcdata = c.ctxt.StartUnsafePoint(pcdata, c.newprog)

	if q != nil {
		q.To.SetTarget(pcdata)
	}
	bls.To.SetTarget(pcdata)

	spill := c.cursym.Func().SpillRegisterArgs(pcdata, c.newprog)

	// MOV	LR, R3
	movlr := obj.Appendp(spill, c.newprog)
	movlr.As = AMOVD
	movlr.From.Type = obj.TYPE_REG
	movlr.From.Reg = REGLINK
	movlr.To.Type = obj.TYPE_REG
	movlr.To.Reg = REG_R3

	debug := movlr
	if false {
		debug = obj.Appendp(debug, c.newprog)
		debug.As = AMOVD
		debug.From.Type = obj.TYPE_CONST
		debug.From.Offset = int64(framesize)
		debug.To.Type = obj.TYPE_REG
		debug.To.Reg = REGTMP
	}

	// BL	runtime.morestack(SB)
	call := obj.Appendp(debug, c.newprog)
	call.As = ABL
	call.To.Type = obj.TYPE_BRANCH
	morestack := "runtime.morestack"
	switch {
	case c.cursym.CFunc():
		morestack = "runtime.morestackc"
	case !c.cursym.Func().Text.From.Sym.NeedCtxt():
		morestack = "runtime.morestack_noctxt"
	}
	call.To.Sym = c.ctxt.Lookup(morestack)

	// The instructions which unspill regs should be preemptible.
	pcdata = c.ctxt.EndUnsafePoint(call, c.newprog, -1)
	unspill := c.cursym.Func().UnspillRegisterArgs(pcdata, c.newprog)

	// B	start
	jmp := obj.Appendp(unspill, c.newprog)
	jmp.As = AB
	jmp.To.Type = obj.TYPE_BRANCH
	jmp.To.SetTarget(startPred.Link)
	jmp.Spadj = +framesize

	return end
}

func progedit(ctxt *obj.Link, p *obj.Prog, newprog obj.ProgAlloc) {
	c := ctxt7{ctxt: ctxt, newprog: newprog}

	p.From.Class = 0
	p.To.Class = 0

	// Previously we rewrote $0 to ZR, but we have now removed this change.
	// In order to be compatible with some previous legal instruction formats,
	// reserve the previous conversion for some specific instructions.
	if p.From.Type == obj.TYPE_CONST && p.From.Offset == 0 && zrReplace[p.As] {
		p.From.Type = obj.TYPE_REG
		p.From.Reg = REGZERO
	}

	// Rewrite BR/BL to symbol as TYPE_BRANCH.
	switch p.As {
	case AB,
		ABL,
		obj.ARET,
		obj.ADUFFZERO,
		obj.ADUFFCOPY:
		if p.To.Sym != nil {
			p.To.Type = obj.TYPE_BRANCH
		}
		break
	}

	// Rewrite float and vector constants to values stored in memory.
	switch p.As {
	case AVMOVS:
		if p.From.Type == obj.TYPE_CONST {
			p.From.Type = obj.TYPE_MEM
			p.From.Sym = c.ctxt.Int32Sym(p.From.Offset)
			p.From.Name = obj.NAME_EXTERN
			p.From.Offset = 0
		}

	case AVMOVD:
		if p.From.Type == obj.TYPE_CONST {
			p.From.Type = obj.TYPE_MEM
			p.From.Sym = c.ctxt.Int64Sym(p.From.Offset)
			p.From.Name = obj.NAME_EXTERN
			p.From.Offset = 0
		}

	case AVMOVQ:
		if p.From.Type == obj.TYPE_CONST {
			p.From.Type = obj.TYPE_MEM
			p.From.Sym = c.ctxt.Int128Sym(p.GetFrom3().Offset, p.From.Offset)
			p.From.Name = obj.NAME_EXTERN
			p.From.Offset = 0
			p.RestArgs = nil
		}

	case AFMOVS:
		if p.From.Type == obj.TYPE_FCONST {
			f64 := p.From.Val.(float64)
			f32 := float32(f64)
			if c.chipfloat7(f64) > 0 {
				break
			}
			if math.Float32bits(f32) == 0 {
				p.From.Type = obj.TYPE_REG
				p.From.Reg = REGZERO
				break
			}
			p.From.Type = obj.TYPE_MEM
			p.From.Sym = c.ctxt.Float32Sym(f32)
			p.From.Name = obj.NAME_EXTERN
			p.From.Offset = 0
		}

	case AFMOVD:
		if p.From.Type == obj.TYPE_FCONST {
			f64 := p.From.Val.(float64)
			if c.chipfloat7(f64) > 0 {
				break
			}
			if math.Float64bits(f64) == 0 {
				p.From.Type = obj.TYPE_REG
				p.From.Reg = REGZERO
				break
			}
			p.From.Type = obj.TYPE_MEM
			p.From.Sym = c.ctxt.Float64Sym(f64)
			p.From.Name = obj.NAME_EXTERN
			p.From.Offset = 0
		}
	}

	if c.ctxt.Flag_dynlink {
		c.rewriteToUseGot(p)
	}
}

// Rewrite p, if necessary, to access global data via the global offset table.
func (c *ctxt7) rewriteToUseGot(p *obj.Prog) {
	if p.As == obj.ADUFFCOPY || p.As == obj.ADUFFZERO {
		//     ADUFFxxx $offset
		// becomes
		//     MOVD runtime.duffxxx@GOT, REGTMP
		//     ADD $offset, REGTMP
		//     CALL REGTMP
		var sym *obj.LSym
		if p.As == obj.ADUFFZERO {
			sym = c.ctxt.LookupABI("runtime.duffzero", obj.ABIInternal)
		} else {
			sym = c.ctxt.LookupABI("runtime.duffcopy", obj.ABIInternal)
		}
		offset := p.To.Offset
		p.As = AMOVD
		p.From.Type = obj.TYPE_MEM
		p.From.Name = obj.NAME_GOTREF
		p.From.Sym = sym
		p.To.Type = obj.TYPE_REG
		p.To.Reg = REGTMP
		p.To.Name = obj.NAME_NONE
		p.To.Offset = 0
		p.To.Sym = nil
		p1 := obj.Appendp(p, c.newprog)
		p1.As = AADD
		p1.From.Type = obj.TYPE_CONST
		p1.From.Offset = offset
		p1.To.Type = obj.TYPE_REG
		p1.To.Reg = REGTMP
		p2 := obj.Appendp(p1, c.newprog)
		p2.As = obj.ACALL
		p2.To.Type = obj.TYPE_REG
		p2.To.Reg = REGTMP
	}

	// We only care about global data: NAME_EXTERN means a global
	// symbol in the Go sense, and p.Sym.Local is true for a few
	// internally defined symbols.
	if p.From.Type == obj.TYPE_ADDR && p.From.Name == obj.NAME_EXTERN && !p.From.Sym.Local() {
		// MOVD $sym, Rx becomes MOVD sym@GOT, Rx
		// MOVD $sym+<off>, Rx becomes MOVD sym@GOT, Rx; ADD <off>, Rx
		if p.As != AMOVD {
			c.ctxt.Diag("do not know how to handle TYPE_ADDR in %v with -dynlink", p)
		}
		if p.To.Type != obj.TYPE_REG {
			c.ctxt.Diag("do not know how to handle LEAQ-type insn to non-register in %v with -dynlink", p)
		}
		p.From.Type = obj.TYPE_MEM
		p.From.Name = obj.NAME_GOTREF
		if p.From.Offset != 0 {
			q := obj.Appendp(p, c.newprog)
			q.As = AADD
			q.From.Type = obj.TYPE_CONST
			q.From.Offset = p.From.Offset
			q.To = p.To
			p.From.Offset = 0
		}
	}
	if p.GetFrom3() != nil && p.GetFrom3().Name == obj.NAME_EXTERN {
		c.ctxt.Diag("don't know how to handle %v with -dynlink", p)
	}
	var source *obj.Addr
	// MOVx sym, Ry becomes MOVD sym@GOT, REGTMP; MOVx (REGTMP), Ry
	// MOVx Ry, sym becomes MOVD sym@GOT, REGTMP; MOVD Ry, (REGTMP)
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
	p1.To.Reg = REGTMP

	p2.As = p.As
	p2.From = p.From
	p2.To = p.To
	if p.From.Name == obj.NAME_EXTERN {
		p2.From.Reg = REGTMP
		p2.From.Name = obj.NAME_NONE
		p2.From.Sym = nil
	} else if p.To.Name == obj.NAME_EXTERN {
		p2.To.Reg = REGTMP
		p2.To.Name = obj.NAME_NONE
		p2.To.Sym = nil
	} else {
		return
	}
	obj.Nopout(p)
}

func preprocess(ctxt *obj.Link, cursym *obj.LSym, newprog obj.ProgAlloc) {
	if cursym.Func().Text == nil || cursym.Func().Text.Link == nil {
		return
	}

	c := ctxt7{ctxt: ctxt, newprog: newprog, cursym: cursym}

	p := c.cursym.Func().Text
	textstksiz := p.To.Offset
	if textstksiz == -8 {
		// Historical way to mark NOFRAME.
		p.From.Sym.Set(obj.AttrNoFrame, true)
		textstksiz = 0
	}
	if textstksiz < 0 {
		c.ctxt.Diag("negative frame size %d - did you mean NOFRAME?", textstksiz)
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
	 */
	for p := c.cursym.Func().Text; p != nil; p = p.Link {
		switch p.As {
		case obj.ATEXT:
			p.Mark |= LEAF

		case ABL,
			obj.ADUFFZERO,
			obj.ADUFFCOPY:
			c.cursym.Func().Text.Mark &^= LEAF
		}
	}

	var q *obj.Prog
	var q1 *obj.Prog
	for p := c.cursym.Func().Text; p != nil; p = p.Link {
		o := p.As
		switch o {
		case obj.ATEXT:
			c.cursym.Func().Text = p
			c.autosize = int32(textstksiz)

			if p.Mark&LEAF != 0 && c.autosize == 0 {
				// A leaf function with no locals has no frame.
				p.From.Sym.Set(obj.AttrNoFrame, true)
			}

			if !p.From.Sym.NoFrame() {
				// If there is a stack frame at all, it includes
				// space to save the LR.
				c.autosize += 8
			}

			if c.autosize != 0 {
				extrasize := int32(0)
				if c.autosize%16 == 8 {
					// Allocate extra 8 bytes on the frame top to save FP
					extrasize = 8
				} else if c.autosize&(16-1) == 0 {
					// Allocate extra 16 bytes to save FP for the old frame whose size is 8 mod 16
					extrasize = 16
				} else {
					c.ctxt.Diag("%v: unaligned frame size %d - must be 16 aligned", p, c.autosize-8)
				}
				c.autosize += extrasize
				c.cursym.Func().Locals += extrasize

				// low 32 bits for autosize
				// high 32 bits for extrasize
				p.To.Offset = int64(c.autosize) | int64(extrasize)<<32
			} else {
				// NOFRAME
				p.To.Offset = 0
			}

			if c.autosize == 0 && c.cursym.Func().Text.Mark&LEAF == 0 {
				if c.ctxt.Debugvlog {
					c.ctxt.Logf("save suppressed in: %s\n", c.cursym.Func().Text.From.Sym.Name)
				}
				c.cursym.Func().Text.Mark |= LEAF
			}

			if cursym.Func().Text.Mark&LEAF != 0 {
				cursym.Set(obj.AttrLeaf, true)
				if p.From.Sym.NoFrame() {
					break
				}
			}

			if p.Mark&LEAF != 0 && c.autosize < abi.StackSmall {
				// A leaf function with a small stack can be marked
				// NOSPLIT, avoiding a stack check.
				p.From.Sym.Set(obj.AttrNoSplit, true)
			}

			if !p.From.Sym.NoSplit() {
				p = c.stacksplit(p, c.autosize) // emit split check
			}

			var prologueEnd *obj.Prog

			aoffset := c.autosize
			if aoffset > 0xf0 {
				// MOVD.W offset variant range is -0x100 to 0xf8, SP should be 16-byte aligned.
				// so the maximum aoffset value is 0xf0.
				aoffset = 0xf0
			}

			// Frame is non-empty. Make sure to save link register, even if
			// it is a leaf function, so that traceback works.
			q = p
			if c.autosize > aoffset {
				// Frame size is too large for a MOVD.W instruction. Store the frame pointer
				// register and link register before decrementing SP, so if a signal comes
				// during the execution of the function prologue, the traceback code will
				// not see a half-updated stack frame.

				// SUB $autosize, RSP, R20
				q1 = obj.Appendp(q, c.newprog)
				q1.Pos = p.Pos
				q1.As = ASUB
				q1.From.Type = obj.TYPE_CONST
				q1.From.Offset = int64(c.autosize)
				q1.Reg = REGSP
				q1.To.Type = obj.TYPE_REG
				q1.To.Reg = REG_R20

				prologueEnd = q1

				// STP (R29, R30), -8(R20)
				q1 = obj.Appendp(q1, c.newprog)
				q1.Pos = p.Pos
				q1.As = ASTP
				q1.From.Type = obj.TYPE_REGREG
				q1.From.Reg = REGFP
				q1.From.Offset = REGLINK
				q1.To.Type = obj.TYPE_MEM
				q1.To.Reg = REG_R20
				q1.To.Offset = -8

				// This is not async preemptible, as if we open a frame
				// at the current SP, it will clobber the saved LR.
				q1 = c.ctxt.StartUnsafePoint(q1, c.newprog)

				// MOVD R20, RSP
				q1 = obj.Appendp(q1, c.newprog)
				q1.Pos = p.Pos
				q1.As = AMOVD
				q1.From.Type = obj.TYPE_REG
				q1.From.Reg = REG_R20
				q1.To.Type = obj.TYPE_REG
				q1.To.Reg = REGSP
				q1.Spadj = c.autosize

				q1 = c.ctxt.EndUnsafePoint(q1, c.newprog, -1)

				if buildcfg.GOOS == "ios" {
					// iOS does not support SA_ONSTACK. We will run the signal handler
					// on the G stack. If we write below SP, it may be clobbered by
					// the signal handler. So we save FP and LR after decrementing SP.
					// STP (R29, R30), -8(RSP)
					q1 = obj.Appendp(q1, c.newprog)
					q1.Pos = p.Pos
					q1.As = ASTP
					q1.From.Type = obj.TYPE_REGREG
					q1.From.Reg = REGFP
					q1.From.Offset = REGLINK
					q1.To.Type = obj.TYPE_MEM
					q1.To.Reg = REGSP
					q1.To.Offset = -8
				}
			} else {
				// small frame, update SP and save LR in a single MOVD.W instruction.
				// So if a signal comes during the execution of the function prologue,
				// the traceback code will not see a half-updated stack frame.
				// Also, on Linux, in a cgo binary we may get a SIGSETXID signal
				// early on before the signal stack is set, as glibc doesn't allow
				// us to block SIGSETXID. So it is important that we don't write below
				// the SP until the signal stack is set.
				// Luckily, all the functions from thread entry to setting the signal
				// stack have small frames.
				q1 = obj.Appendp(q, c.newprog)
				q1.As = AMOVD
				q1.Pos = p.Pos
				q1.From.Type = obj.TYPE_REG
				q1.From.Reg = REGLINK
				q1.To.Type = obj.TYPE_MEM
				q1.Scond = C_XPRE
				q1.To.Offset = int64(-aoffset)
				q1.To.Reg = REGSP
				q1.Spadj = aoffset

				prologueEnd = q1

				// Frame pointer.
				q1 = obj.Appendp(q1, c.newprog)
				q1.Pos = p.Pos
				q1.As = AMOVD
				q1.From.Type = obj.TYPE_REG
				q1.From.Reg = REGFP
				q1.To.Type = obj.TYPE_MEM
				q1.To.Reg = REGSP
				q1.To.Offset = -8
			}

			prologueEnd.Pos = prologueEnd.Pos.WithXlogue(src.PosPrologueEnd)

			q1 = obj.Appendp(q1, c.newprog)
			q1.Pos = p.Pos
			q1.As = ASUB
			q1.From.Type = obj.TYPE_CONST
			q1.From.Offset = 8
			q1.Reg = REGSP
			q1.To.Type = obj.TYPE_REG
			q1.To.Reg = REGFP

			if c.cursym.Func().Text.From.Sym.Wrapper() {
				// if(g->panic != nil && g->panic->argp == FP) g->panic->argp = bottom-of-frame
				//
				//	MOV  g_panic(g), RT1
				//	CBNZ checkargp
				// end:
				//	NOP
				// ... function body ...
				// checkargp:
				//	MOV  panic_argp(RT1), RT2
				//	ADD  $(autosize+8), RSP, R20
				//	CMP  RT2, R20
				//	BNE  end
				//	ADD  $8, RSP, R20
				//	MOVD R20, panic_argp(RT1)
				//	B    end
				//
				// The NOP is needed to give the jumps somewhere to land.
				// It is a liblink NOP, not an ARM64 NOP: it encodes to 0 instruction bytes.
				q = q1

				// MOV g_panic(g), RT1
				q = obj.Appendp(q, c.newprog)
				q.As = AMOVD
				q.From.Type = obj.TYPE_MEM
				q.From.Reg = REGG
				q.From.Offset = 4 * int64(c.ctxt.Arch.PtrSize) // G.panic
				q.To.Type = obj.TYPE_REG
				q.To.Reg = REGRT1

				// CBNZ RT1, checkargp
				cbnz := obj.Appendp(q, c.newprog)
				cbnz.As = ACBNZ
				cbnz.From.Type = obj.TYPE_REG
				cbnz.From.Reg = REGRT1
				cbnz.To.Type = obj.TYPE_BRANCH

				// Empty branch target at the top of the function body
				end := obj.Appendp(cbnz, c.newprog)
				end.As = obj.ANOP

				// find the end of the function
				var last *obj.Prog
				for last = end; last.Link != nil; last = last.Link {
				}

				// MOV panic_argp(RT1), RT2
				mov := obj.Appendp(last, c.newprog)
				mov.As = AMOVD
				mov.From.Type = obj.TYPE_MEM
				mov.From.Reg = REGRT1
				mov.From.Offset = 0 // Panic.argp
				mov.To.Type = obj.TYPE_REG
				mov.To.Reg = REGRT2

				// CBNZ branches to the MOV above
				cbnz.To.SetTarget(mov)

				// ADD $(autosize+8), SP, R20
				q = obj.Appendp(mov, c.newprog)
				q.As = AADD
				q.From.Type = obj.TYPE_CONST
				q.From.Offset = int64(c.autosize) + 8
				q.Reg = REGSP
				q.To.Type = obj.TYPE_REG
				q.To.Reg = REG_R20

				// CMP RT2, R20
				q = obj.Appendp(q, c.newprog)
				q.As = ACMP
				q.From.Type = obj.TYPE_REG
				q.From.Reg = REGRT2
				q.Reg = REG_R20

				// BNE end
				q = obj.Appendp(q, c.newprog)
				q.As = ABNE
				q.To.Type = obj.TYPE_BRANCH
				q.To.SetTarget(end)

				// ADD $8, SP, R20
				q = obj.Appendp(q, c.newprog)
				q.As = AADD
				q.From.Type = obj.TYPE_CONST
				q.From.Offset = 8
				q.Reg = REGSP
				q.To.Type = obj.TYPE_REG
				q.To.Reg = REG_R20

				// MOV R20, panic_argp(RT1)
				q = obj.Appendp(q, c.newprog)
				q.As = AMOVD
				q.From.Type = obj.TYPE_REG
				q.From.Reg = REG_R20
				q.To.Type = obj.TYPE_MEM
				q.To.Reg = REGRT1
				q.To.Offset = 0 // Panic.argp

				// B end
				q = obj.Appendp(q, c.newprog)
				q.As = AB
				q.To.Type = obj.TYPE_BRANCH
				q.To.SetTarget(end)
			}

		case obj.ARET:
			nocache(p)
			if p.From.Type == obj.TYPE_CONST {
				c.ctxt.Diag("using BECOME (%v) is not supported!", p)
				break
			}

			retJMP, retReg := p.To.Sym, p.To.Reg
			if retReg == 0 {
				retReg = REGLINK
			}
			p.To = obj.Addr{}
			aoffset := c.autosize
			if c.cursym.Func().Text.Mark&LEAF != 0 {
				if aoffset != 0 {
					// Restore frame pointer.
					// ADD $framesize-8, RSP, R29
					p.As = AADD
					p.From.Type = obj.TYPE_CONST
					p.From.Offset = int64(c.autosize) - 8
					p.Reg = REGSP
					p.To.Type = obj.TYPE_REG
					p.To.Reg = REGFP

					// Pop stack frame.
					// ADD $framesize, RSP, RSP
					p = obj.Appendp(p, c.newprog)
					p.As = AADD
					p.From.Type = obj.TYPE_CONST
					p.From.Offset = int64(c.autosize)
					p.To.Type = obj.TYPE_REG
					p.To.Reg = REGSP
					p.Spadj = -c.autosize
				}
			} else if aoffset <= 0xF0 {
				// small frame, restore LR and update SP in a single MOVD.P instruction.
				// There is no correctness issue to use a single LDP for LR and FP,
				// but the instructions are not pattern matched with the prologue's
				// MOVD.W and MOVD, which may cause performance issue in
				// store-forwarding.

				// MOVD -8(RSP), R29
				p.As = AMOVD
				p.From.Type = obj.TYPE_MEM
				p.From.Reg = REGSP
				p.From.Offset = -8
				p.To.Type = obj.TYPE_REG
				p.To.Reg = REGFP
				p = obj.Appendp(p, c.newprog)

				// MOVD.P offset(RSP), R30
				p.As = AMOVD
				p.From.Type = obj.TYPE_MEM
				p.Scond = C_XPOST
				p.From.Offset = int64(aoffset)
				p.From.Reg = REGSP
				p.To.Type = obj.TYPE_REG
				p.To.Reg = REGLINK
				p.Spadj = -aoffset
			} else {
				// LDP -8(RSP), (R29, R30)
				p.As = ALDP
				p.From.Type = obj.TYPE_MEM
				p.From.Offset = -8
				p.From.Reg = REGSP
				p.To.Type = obj.TYPE_REGREG
				p.To.Reg = REGFP
				p.To.Offset = REGLINK

				// ADD $aoffset, RSP, RSP
				q = newprog()
				q.As = AADD
				q.From.Type = obj.TYPE_CONST
				q.From.Offset = int64(aoffset)
				q.To.Type = obj.TYPE_REG
				q.To.Reg = REGSP
				q.Spadj = -aoffset
				q.Pos = p.Pos
				q.Link = p.Link
				p.Link = q
				p = q
			}

			// If enabled, this code emits 'MOV PC, R27' before every 'MOV LR, PC',
			// so that if you are debugging a low-level crash where PC and LR are zero,
			// you can look at R27 to see what jumped to the zero.
			// This is useful when bringing up Go on a new system.
			// (There is similar code in ../ppc64/obj9.go:/if.false.)
			const debugRETZERO = false
			if debugRETZERO {
				if p.As != obj.ARET {
					q = newprog()
					q.Pos = p.Pos
					q.Link = p.Link
					p.Link = q
					p = q
				}
				p.As = AADR
				p.From.Type = obj.TYPE_BRANCH
				p.From.Offset = 0
				p.To.Type = obj.TYPE_REG
				p.To.Reg = REGTMP

			}

			if p.As != obj.ARET {
				q = newprog()
				q.Pos = p.Pos
				q.Link = p.Link
				p.Link = q
				p = q
			}

			if retJMP != nil {
				p.As = AB
				p.To.Type = obj.TYPE_BRANCH
				p.To.Sym = retJMP
				p.Spadj = +c.autosize
				break
			}

			p.As = obj.ARET
			p.To.Type = obj.TYPE_MEM
			p.To.Offset = 0
			p.To.Reg = retReg
			p.Spadj = +c.autosize

		case AADD, ASUB:
			if p.To.Type == obj.TYPE_REG && p.To.Reg == REGSP && p.From.Type == obj.TYPE_CONST {
				if p.As == AADD {
					p.Spadj = int32(-p.From.Offset)
				} else {
					p.Spadj = int32(+p.From.Offset)
				}
			}

		case obj.AGETCALLERPC:
			if cursym.Leaf() {
				/* MOVD LR, Rd */
				p.As = AMOVD
				p.From.Type = obj.TYPE_REG
				p.From.Reg = REGLINK
			} else {
				/* MOVD (RSP), Rd */
				p.As = AMOVD
				p.From.Type = obj.TYPE_MEM
				p.From.Reg = REGSP
			}

		case obj.ADUFFCOPY:
			//  ADR	ret_addr, R27
			//  STP	(FP, R27), -24(SP)
			//  SUB	24, SP, FP
			//  DUFFCOPY
			// ret_addr:
			//  SUB	8, SP, FP

			q1 := p
			// copy DUFFCOPY from q1 to q4
			q4 := obj.Appendp(p, c.newprog)
			q4.Pos = p.Pos
			q4.As = obj.ADUFFCOPY
			q4.To = p.To

			q1.As = AADR
			q1.From.Type = obj.TYPE_BRANCH
			q1.To.Type = obj.TYPE_REG
			q1.To.Reg = REG_R27

			q2 := obj.Appendp(q1, c.newprog)
			q2.Pos = p.Pos
			q2.As = ASTP
			q2.From.Type = obj.TYPE_REGREG
			q2.From.Reg = REGFP
			q2.From.Offset = int64(REG_R27)
			q2.To.Type = obj.TYPE_MEM
			q2.To.Reg = REGSP
			q2.To.Offset = -24

			// maintain FP for DUFFCOPY
			q3 := obj.Appendp(q2, c.newprog)
			q3.Pos = p.Pos
			q3.As = ASUB
			q3.From.Type = obj.TYPE_CONST
			q3.From.Offset = 24
			q3.Reg = REGSP
			q3.To.Type = obj.TYPE_REG
			q3.To.Reg = REGFP

			q5 := obj.Appendp(q4, c.newprog)
			q5.Pos = p.Pos
			q5.As = ASUB
			q5.From.Type = obj.TYPE_CONST
			q5.From.Offset = 8
			q5.Reg = REGSP
			q5.To.Type = obj.TYPE_REG
			q5.To.Reg = REGFP
			q1.From.SetTarget(q5)
			p = q5

		case obj.ADUFFZERO:
			//  ADR	ret_addr, R27
			//  STP	(FP, R27), -24(SP)
			//  SUB	24, SP, FP
			//  DUFFZERO
			// ret_addr:
			//  SUB	8, SP, FP

			q1 := p
			// copy DUFFZERO from q1 to q4
			q4 := obj.Appendp(p, c.newprog)
			q4.Pos = p.Pos
			q4.As = obj.ADUFFZERO
			q4.To = p.To

			q1.As = AADR
			q1.From.Type = obj.TYPE_BRANCH
			q1.To.Type = obj.TYPE_REG
			q1.To.Reg = REG_R27

			q2 := obj.Appendp(q1, c.newprog)
			q2.Pos = p.Pos
			q2.As = ASTP
			q2.From.Type = obj.TYPE_REGREG
			q2.From.Reg = REGFP
			q2.From.Offset = int64(REG_R27)
			q2.To.Type = obj.TYPE_MEM
			q2.To.Reg = REGSP
			q2.To.Offset = -24

			// maintain FP for DUFFZERO
			q3 := obj.Appendp(q2, c.newprog)
			q3.Pos = p.Pos
			q3.As = ASUB
			q3.From.Type = obj.TYPE_CONST
			q3.From.Offset = 24
			q3.Reg = REGSP
			q3.To.Type = obj.TYPE_REG
			q3.To.Reg = REGFP

			q5 := obj.Appendp(q4, c.newprog)
			q5.Pos = p.Pos
			q5.As = ASUB
			q5.From.Type = obj.TYPE_CONST
			q5.From.Offset = 8
			q5.Reg = REGSP
			q5.To.Type = obj.TYPE_REG
			q5.To.Reg = REGFP
			q1.From.SetTarget(q5)
			p = q5
		}

		if p.To.Type == obj.TYPE_REG && p.To.Reg == REGSP && p.Spadj == 0 {
			f := c.cursym.Func()
			if f.FuncFlag&abi.FuncFlagSPWrite == 0 {
				c.cursym.Func().FuncFlag |= abi.FuncFlagSPWrite
				if ctxt.Debugvlog || !ctxt.IsAsm {
					ctxt.Logf("auto-SPWRITE: %s %v\n", c.cursym.Name, p)
					if !ctxt.IsAsm {
						ctxt.Diag("invalid auto-SPWRITE in non-assembly")
						ctxt.DiagFlush()
						log.Fatalf("bad SPWRITE")
					}
				}
			}
		}
		if p.From.Type == obj.TYPE_SHIFT && (p.To.Reg == REG_RSP || p.Reg == REG_RSP) {
			offset := p.From.Offset
			op := offset & (3 << 22)
			if op != SHIFT_LL {
				ctxt.Diag("illegal combination: %v", p)
			}
			r := (offset >> 16) & 31
			shift := (offset >> 10) & 63
			if shift > 4 {
				// the shift amount is out of range, in order to avoid repeated error
				// reportings, don't call ctxt.Diag, because asmout case 27 has the
				// same check.
				shift = 7
			}
			p.From.Type = obj.TYPE_REG
			p.From.Reg = int16(REG_LSL + r + (shift&7)<<5)
			p.From.Offset = 0
		}
	}
}

func nocache(p *obj.Prog) {
	p.Optab = 0
	p.From.Class = 0
	p.To.Class = 0
}

var unaryDst = map[obj.As]bool{
	AWORD:  true,
	ADWORD: true,
	ABL:    true,
	AB:     true,
	ACLREX: true,
}

var Linkarm64 = obj.LinkArch{
	Arch:           sys.ArchARM64,
	Init:           buildop,
	Preprocess:     preprocess,
	Assemble:       span7,
	Progedit:       progedit,
	UnaryDst:       unaryDst,
	DWARFRegisters: ARM64DWARFRegisters,
}
```