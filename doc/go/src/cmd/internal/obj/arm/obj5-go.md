Response: The user wants to understand the functionality of the Go code snippet provided, which is part of the ARM assembler in the Go compiler.

Here's a breakdown of the thinking process to answer the request:

1. **Identify the core purpose of the file:** The file path `go/src/cmd/internal/obj/arm/obj5.go` and the package declaration `package arm` strongly suggest this file is responsible for architecture-specific operations for the ARM architecture within the Go assembler (`cmd/internal/obj`).

2. **Analyze the `progedit` function:** This function takes a `Link` context and a `Prog` (instruction) as input. The code within modifies the `Prog` based on its opcode (`p.As`). This suggests `progedit` is a central point for instruction rewriting or modification before actual assembly.

3. **Examine the `progedit` switch statements:**
    * The first `switch p.As` handles `AB`, `ABL`, `ADUFFZERO`, and `ADUFFCOPY`, rewriting `TYPE_MEM` to `TYPE_BRANCH` for external or static symbols. This likely optimizes direct calls to known functions.
    * The second `switch p.As` specifically deals with `AMRC`. The code checks for a specific `To.Offset` pattern related to fetching the TLS register. For older ARM versions (`buildcfg.GOARM.Version < 7`), it replaces the `MRC` instruction with a call to `runtime.read_tls_fallback`. This is a crucial step in handling Thread-Local Storage (TLS) on platforms without direct hardware support.
    * The third `switch p.As` handles `AMOVF` and `AMOVD`, dealing with floating-point constants. It appears to move floating-point constants to memory locations. This is a common optimization technique in compilers.

4. **Analyze the `rewriteToUseGot` function:** This function is called if `ctxt.Flag_dynlink` is true, indicating dynamic linking is enabled. The code modifies instructions to access global data via the Global Offset Table (GOT). This is a fundamental part of dynamic linking.

5. **Analyze the `preprocess` function:** This function takes a `Link` context and a `LSym` (symbol) as input. It performs various tasks:
    * Calculates the frame size (`autosize`).
    * Identifies leaf functions.
    * Inserts stack overflow checks (`stacksplit`).
    * Handles function prologues (saving LR, adjusting SP).
    * Handles function epilogues (restoring SP, jumping back).
    * Deals with division and modulo operations (likely calling runtime functions).
    * Handles `GETCALLERPC`.
    * Checks for and flags functions that write to the stack pointer.

6. **Analyze the `stacksplit` function:** This function inserts the necessary code to check for stack overflow and call `runtime.morestack` if needed. It handles different stack sizes and considers the `maymorestack` flag.

7. **Analyze the `Linkarm` variable:** This variable of type `obj.LinkArch` defines the ARM architecture-specific linking functions. The presence of `Init`, `Preprocess`, `Assemble`, and `Progedit` confirms the file's role in the compilation pipeline.

8. **Infer Go language features:** Based on the code analysis, the file is involved in:
    * **Function calls:** Rewriting direct calls for optimization.
    * **Thread-Local Storage (TLS):**  Handling TLS access on different ARM versions.
    * **Floating-point operations:** Optimizing the handling of floating-point constants.
    * **Dynamic linking:**  Rewriting code to use the GOT.
    * **Stack management:**  Calculating frame sizes, inserting stack overflow checks, managing function prologues and epilogues.
    * **Division and modulo:**  Handling these operations, potentially through runtime calls.
    * **Getting the caller's PC:**  Implementing `runtime.Caller`.

9. **Construct Go code examples:** For each inferred feature, create a simple Go program that utilizes it. This helps illustrate the code's purpose in a practical context.

10. **Consider command-line arguments:** The code mentions `ctxt.Flag_dynlink` and `ctxt.Flag_maymorestack`. These are clearly command-line flags that influence the compilation process. Explain their purpose.

11. **Identify potential pitfalls:**  The `progedit` function checks if the TLS `MRC` instruction writes to `R0` and issues a diagnostic if it doesn't. This highlights a constraint that users might not be aware of. Similarly, the code mentions the historical way to mark `NOFRAME` with a frame size of -4, which is now discouraged.

12. **Structure the answer:** Organize the findings into clear sections, addressing each part of the user's request. Use code formatting and clear explanations.
这是 `go/src/cmd/internal/obj/arm/obj5.go` 文件的一部分，它是 Go 语言编译器中 ARM 架构的汇编器（assembler）的一部分。它主要负责以下功能：

**主要功能：**

1. **指令编辑 (`progedit` 函数):**  在汇编过程的早期阶段，对中间代码（`obj.Prog`）进行架构特定的修改和优化。这包括：
    * **将分支指令目标重写为 `TYPE_BRANCH`:**  对于 `B` 和 `BL` 指令，如果目标是外部或静态符号，则将其类型设置为 `TYPE_BRANCH`，这有助于后续的链接和代码生成。
    * **处理 TLS (Thread-Local Storage) 访问:**  对于较旧的 ARM 处理器，将直接访问 TLS 寄存器的指令 (`MRC 15, 0, <reg>, C13, C0, 3`) 替换为调用 `runtime.read_tls_fallback` 函数。这是因为旧的 ARM 架构可能没有原生的 TLS 支持，需要通过运行时库来模拟。
    * **将浮点常量移动到内存:** 对于 `MOVF` 和 `MOVD` 指令，如果源操作数是浮点常量，且该常量需要特殊处理（例如，负数或在条件执行中），则将其存储到内存中，并通过内存访问来加载。这可能是为了处理 ARM 架构上浮点常量的限制。
    * **处理动态链接 (`rewriteToUseGot` 函数):**  当使用动态链接时，将访问全局数据的指令重写为通过 Global Offset Table (GOT) 进行访问。这确保了在不同的加载地址下，程序仍然可以正确访问全局变量和函数。

2. **动态链接支持 (`rewriteToUseGot` 函数):** 当使用 `-dynlink` 标志进行编译时，这个函数会修改指令，使其通过 GOT 来访问全局数据。
    * 对于 `ADUFFCOPY` 和 `ADUFFZERO` 指令，会将其展开为一系列指令，先加载 `runtime.duffxxx` 函数的 GOT 地址到寄存器，然后通过该寄存器进行调用。
    * 对于访问全局变量的 `MOVW` 指令，如果源操作数是外部符号，则将其修改为从 GOT 表中加载地址。

3. **代码预处理 (`preprocess` 函数):**  在汇编之前对函数进行分析和准备。
    * **计算栈帧大小:**  确定局部变量所需的栈空间大小。
    * **识别叶子函数:**  判断函数是否为叶子函数（不调用其他函数），这可以用于优化函数调用和栈帧管理。
    * **插入栈溢出检查 (`stacksplit` 函数):** 在函数入口处插入代码，检查栈空间是否足够，如果不足则调用 `runtime.morestack` 来扩展栈。
    * **处理函数序言和尾声:**  生成保存和恢复寄存器、调整栈指针的指令。
    * **处理除法和取模运算:**  由于 ARM 架构的除法指令可能需要特殊处理，此函数会将除法和取模运算替换为调用运行时库中的函数 (`runtime.div`, `runtime.divu`, `runtime.mod`, `runtime.modu`)。
    * **处理 `GETCALLERPC` 指令:**  根据函数是否为叶子函数，生成获取调用者程序计数器的指令。

4. **定义链接架构 (`Linkarm` 变量):**  定义了 ARM 架构的链接器需要的各种函数，包括初始化、预处理、汇编和指令编辑等。

**推断的 Go 语言功能实现：**

基于代码内容，可以推断出此文件与以下 Go 语言功能的实现密切相关：

* **函数调用和返回:**  `progedit` 中对 `B` 和 `BL` 指令的处理，以及 `preprocess` 中对函数序言和尾声的处理，都与函数调用和返回机制有关。
* **Thread-Local Storage (TLS):**  `progedit` 中对 `MRC` 指令的替换，直接支持了 Go 语言的 TLS 特性。
* **浮点数运算:** `progedit` 中对 `AMOVF` 和 `AMOVD` 指令的处理，涉及到浮点常量的加载。
* **动态链接:** `rewriteToUseGot` 函数是实现 Go 动态链接的关键部分。
* **栈管理和栈溢出保护:** `preprocess` 中的栈帧大小计算和 `stacksplit` 函数的插入，确保了 Go 程序的栈安全。
* **整数除法和取模运算:** `preprocess` 中对除法和取模指令的处理，表明 Go 的整数除法和取模操作可能在底层通过运行时库函数实现。
* **获取调用者信息 (`runtime.Caller`):** `preprocess` 中对 `AGETCALLERPC` 指令的处理，支持了 `runtime.Caller` 等获取调用栈信息的函数。

**Go 代码举例说明：**

以下是一些简单的 Go 代码示例，可以帮助理解 `obj5.go` 中的功能：

**1. 函数调用:**

```go
package main

import "fmt"

func add(a, b int) int {
	return a + b
}

func main() {
	result := add(5, 3)
	fmt.Println(result)
}
```

在编译这段代码时，`progedit` 会处理 `add` 函数的调用指令 (`BL`)。

**2. Thread-Local Storage (TLS):**

```go
package main

import (
	"fmt"
	"runtime"
)

var tlsVar string

func main() {
	runtime.GOMAXPROCS(1) // 确保只有一个 Goroutine 运行以便观察 TLS

	go func() {
		tlsVar = "hello from goroutine 1"
		fmt.Println(tlsVar)
	}()

	go func() {
		tlsVar = "hello from goroutine 2"
		fmt.Println(tlsVar)
	}()

	// 等待 Goroutine 完成 (实际应用中需要更可靠的同步机制)
	var input string
	fmt.Scanln(&input)
}
```

当访问 `tlsVar` 时，如果目标 ARM 架构较旧，`progedit` 会将访问 TLS 寄存器的指令替换为调用 `runtime.read_tls_fallback`。

**3. 浮点数常量:**

```go
package main

import "fmt"

func main() {
	f := 3.14
	fmt.Println(f)
}
```

如果常量 `3.14` 需要特殊处理，`progedit` 会将其移动到内存中加载。

**4. 动态链接 (需要使用 `-buildmode=c-shared` 或 `-ldflags=-linkmode=external` 等标志编译):**

```go
package main

import "C"
import "fmt"

//export Hello
func Hello() {
	fmt.Println("Hello from shared library")
}

func main() {
	// 此处无需调用 Hello，因为它是导出函数，会被其他程序调用
	fmt.Println("Main program")
}
```

当编译为共享库时，`rewriteToUseGot` 会确保 `Hello` 函数的地址可以通过 GOT 正确访问。

**5. 栈溢出保护:**

```go
package main

func recursiveFunc(n int) {
	if n > 0 {
		var arr [100000]int // 尝试分配较大的局部变量
		recursiveFunc(n - 1)
		_ = arr
	}
}

func main() {
	recursiveFunc(100) // 可能会触发栈溢出
}
```

在调用 `recursiveFunc` 时，`preprocess` 会插入栈溢出检查，如果栈空间不足，则会调用 `runtime.morestack`。

**假设的输入与输出 (以 TLS 处理为例):**

**假设输入 (汇编指令):**

```assembly
MRC 15, 0, R3, C13, C0, 3  // 读取 TLS 寄存器到 R3 (旧 ARM 架构)
```

**假设输出 (经过 `progedit` 处理后的汇编指令，假设 `buildcfg.GOARM.Version < 7`):**

```assembly
MOVW	LR, R11
ABL	runtime.read_tls_fallback(SB)
MOVW	R11, LR
```

**解释:**  原始的 `MRC` 指令被替换为一系列指令：先保存 LR，然后调用 `runtime.read_tls_fallback` 函数，最后恢复 LR。  `runtime.read_tls_fallback` 负责获取 TLS 的地址并将其存储在特定的寄存器中（通常是 R0）。  后续可能还需要额外的指令将 TLS 值加载到 R3。

**命令行参数的具体处理:**

* **`ctxt.Flag_dynlink`:**  这是一个布尔标志，指示是否启用动态链接。该标志通常由编译器的 `-linkmode=external` 或 `-buildmode=c-shared` 等命令行选项设置。如果为 true，`rewriteToUseGot` 函数会被调用，修改指令以使用 GOT 表。
* **`ctxt.Flag_maymorestack`:** 这是一个字符串标志，用于指定一个替代的 `morestack` 函数的符号名称。这个标志允许在特定的场景下使用自定义的栈扩展逻辑。它通常不会直接被用户设置，而是由构建系统或特定的编译配置决定。

**使用者易犯错的点 (以 TLS 处理为例):**

* **假设所有 ARM 架构都支持直接 TLS 访问:**  开发者可能会编写依赖于直接 TLS 寄存器访问的汇编代码，而忽略了在旧的 ARM 架构上需要通过运行时库来模拟。Go 编译器通过 `progedit` 隐藏了这种差异，但如果直接编写汇编代码，就需要注意这一点。
    * **错误示例 (假设直接使用 `MRC`):**  直接在汇编代码中使用 `MRC 15, 0, <reg>, C13, C0, 3` 可能会在旧的 ARM 设备上崩溃或产生不可预测的结果。

**总结:**

`go/src/cmd/internal/obj/arm/obj5.go` 是 Go 编译器中 ARM 架构汇编器的核心组成部分，负责指令的架构特定处理、动态链接支持、栈管理以及与 Go 运行时库的交互。理解这个文件的功能有助于深入了解 Go 在 ARM 架构上的编译和执行机制。

### 提示词
```
这是路径为go/src/cmd/internal/obj/arm/obj5.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
```

### 源代码
```go
// Derived from Inferno utils/5c/swt.c
// https://bitbucket.org/inferno-os/inferno-os/src/master/utils/5c/swt.c
//
//	Copyright © 1994-1999 Lucent Technologies Inc.  All rights reserved.
//	Portions Copyright © 1995-1997 C H Forsyth (forsyth@terzarima.net)
//	Portions Copyright © 1997-1999 Vita Nuova Limited
//	Portions Copyright © 2000-2007 Vita Nuova Holdings Limited (www.vitanuova.com)
//	Portions Copyright © 2004,2006 Bruce Ellis
//	Portions Copyright © 2005-2007 C H Forsyth (forsyth@terzarima.net)
//	Revisions Copyright © 2000-2007 Lucent Technologies Inc. and others
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

package arm

import (
	"cmd/internal/obj"
	"cmd/internal/objabi"
	"cmd/internal/sys"
	"internal/abi"
	"internal/buildcfg"
	"log"
)

var progedit_tlsfallback *obj.LSym

func progedit(ctxt *obj.Link, p *obj.Prog, newprog obj.ProgAlloc) {
	p.From.Class = 0
	p.To.Class = 0

	c := ctxt5{ctxt: ctxt, newprog: newprog}

	// Rewrite B/BL to symbol as TYPE_BRANCH.
	switch p.As {
	case AB, ABL, obj.ADUFFZERO, obj.ADUFFCOPY:
		if p.To.Type == obj.TYPE_MEM && (p.To.Name == obj.NAME_EXTERN || p.To.Name == obj.NAME_STATIC) && p.To.Sym != nil {
			p.To.Type = obj.TYPE_BRANCH
		}
	}

	// Replace TLS register fetches on older ARM processors.
	switch p.As {
	// Treat MRC 15, 0, <reg>, C13, C0, 3 specially.
	case AMRC:
		if p.To.Offset&0xffff0fff == 0xee1d0f70 {
			// Because the instruction might be rewritten to a BL which returns in R0
			// the register must be zero.
			if p.To.Offset&0xf000 != 0 {
				ctxt.Diag("%v: TLS MRC instruction must write to R0 as it might get translated into a BL instruction", p.Line())
			}

			if buildcfg.GOARM.Version < 7 {
				// Replace it with BL runtime.read_tls_fallback(SB) for ARM CPUs that lack the tls extension.
				if progedit_tlsfallback == nil {
					progedit_tlsfallback = ctxt.Lookup("runtime.read_tls_fallback")
				}

				// MOVW	LR, R11
				p.As = AMOVW

				p.From.Type = obj.TYPE_REG
				p.From.Reg = REGLINK
				p.To.Type = obj.TYPE_REG
				p.To.Reg = REGTMP

				// BL	runtime.read_tls_fallback(SB)
				p = obj.Appendp(p, newprog)

				p.As = ABL
				p.To.Type = obj.TYPE_BRANCH
				p.To.Sym = progedit_tlsfallback
				p.To.Offset = 0

				// MOVW	R11, LR
				p = obj.Appendp(p, newprog)

				p.As = AMOVW
				p.From.Type = obj.TYPE_REG
				p.From.Reg = REGTMP
				p.To.Type = obj.TYPE_REG
				p.To.Reg = REGLINK
				break
			}
		}

		// Otherwise, MRC/MCR instructions need no further treatment.
		p.As = AWORD
	}

	// Rewrite float constants to values stored in memory.
	switch p.As {
	case AMOVF:
		if p.From.Type == obj.TYPE_FCONST && c.chipfloat5(p.From.Val.(float64)) < 0 && (c.chipzero5(p.From.Val.(float64)) < 0 || p.Scond&C_SCOND != C_SCOND_NONE) {
			f32 := float32(p.From.Val.(float64))
			p.From.Type = obj.TYPE_MEM
			p.From.Sym = ctxt.Float32Sym(f32)
			p.From.Name = obj.NAME_EXTERN
			p.From.Offset = 0
		}

	case AMOVD:
		if p.From.Type == obj.TYPE_FCONST && c.chipfloat5(p.From.Val.(float64)) < 0 && (c.chipzero5(p.From.Val.(float64)) < 0 || p.Scond&C_SCOND != C_SCOND_NONE) {
			p.From.Type = obj.TYPE_MEM
			p.From.Sym = ctxt.Float64Sym(p.From.Val.(float64))
			p.From.Name = obj.NAME_EXTERN
			p.From.Offset = 0
		}
	}

	if ctxt.Flag_dynlink {
		c.rewriteToUseGot(p)
	}
}

// Rewrite p, if necessary, to access global data via the global offset table.
func (c *ctxt5) rewriteToUseGot(p *obj.Prog) {
	if p.As == obj.ADUFFCOPY || p.As == obj.ADUFFZERO {
		//     ADUFFxxx $offset
		// becomes
		//     MOVW runtime.duffxxx@GOT, R9
		//     ADD $offset, R9
		//     CALL (R9)
		var sym *obj.LSym
		if p.As == obj.ADUFFZERO {
			sym = c.ctxt.Lookup("runtime.duffzero")
		} else {
			sym = c.ctxt.Lookup("runtime.duffcopy")
		}
		offset := p.To.Offset
		p.As = AMOVW
		p.From.Type = obj.TYPE_MEM
		p.From.Name = obj.NAME_GOTREF
		p.From.Sym = sym
		p.To.Type = obj.TYPE_REG
		p.To.Reg = REG_R9
		p.To.Name = obj.NAME_NONE
		p.To.Offset = 0
		p.To.Sym = nil
		p1 := obj.Appendp(p, c.newprog)
		p1.As = AADD
		p1.From.Type = obj.TYPE_CONST
		p1.From.Offset = offset
		p1.To.Type = obj.TYPE_REG
		p1.To.Reg = REG_R9
		p2 := obj.Appendp(p1, c.newprog)
		p2.As = obj.ACALL
		p2.To.Type = obj.TYPE_MEM
		p2.To.Reg = REG_R9
		return
	}

	// We only care about global data: NAME_EXTERN means a global
	// symbol in the Go sense, and p.Sym.Local is true for a few
	// internally defined symbols.
	if p.From.Type == obj.TYPE_ADDR && p.From.Name == obj.NAME_EXTERN && !p.From.Sym.Local() {
		// MOVW $sym, Rx becomes MOVW sym@GOT, Rx
		// MOVW $sym+<off>, Rx becomes MOVW sym@GOT, Rx; ADD <off>, Rx
		if p.As != AMOVW {
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
	// MOVx sym, Ry becomes MOVW sym@GOT, R9; MOVx (R9), Ry
	// MOVx Ry, sym becomes MOVW sym@GOT, R9; MOVx Ry, (R9)
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

	p1.As = AMOVW
	p1.From.Type = obj.TYPE_MEM
	p1.From.Sym = source.Sym
	p1.From.Name = obj.NAME_GOTREF
	p1.To.Type = obj.TYPE_REG
	p1.To.Reg = REG_R9

	p2.As = p.As
	p2.From = p.From
	p2.To = p.To
	if p.From.Name == obj.NAME_EXTERN {
		p2.From.Reg = REG_R9
		p2.From.Name = obj.NAME_NONE
		p2.From.Sym = nil
	} else if p.To.Name == obj.NAME_EXTERN {
		p2.To.Reg = REG_R9
		p2.To.Name = obj.NAME_NONE
		p2.To.Sym = nil
	} else {
		return
	}
	obj.Nopout(p)
}

// Prog.mark
const (
	FOLL  = 1 << 0
	LABEL = 1 << 1
	LEAF  = 1 << 2
)

func preprocess(ctxt *obj.Link, cursym *obj.LSym, newprog obj.ProgAlloc) {
	autosize := int32(0)

	if cursym.Func().Text == nil || cursym.Func().Text.Link == nil {
		return
	}

	c := ctxt5{ctxt: ctxt, cursym: cursym, newprog: newprog}

	p := c.cursym.Func().Text
	autoffset := int32(p.To.Offset)
	if autoffset == -4 {
		// Historical way to mark NOFRAME.
		p.From.Sym.Set(obj.AttrNoFrame, true)
		autoffset = 0
	}
	if autoffset < 0 || autoffset%4 != 0 {
		c.ctxt.Diag("frame size %d not 0 or a positive multiple of 4", autoffset)
	}
	if p.From.Sym.NoFrame() {
		if autoffset != 0 {
			c.ctxt.Diag("NOFRAME functions must have a frame size of 0, not %d", autoffset)
		}
	}

	cursym.Func().Locals = autoffset
	cursym.Func().Args = p.To.Val.(int32)

	/*
	 * find leaf subroutines
	 */
	for p := cursym.Func().Text; p != nil; p = p.Link {
		switch p.As {
		case obj.ATEXT:
			p.Mark |= LEAF

		case ADIV, ADIVU, AMOD, AMODU:
			cursym.Func().Text.Mark &^= LEAF

		case ABL,
			ABX,
			obj.ADUFFZERO,
			obj.ADUFFCOPY:
			cursym.Func().Text.Mark &^= LEAF
		}
	}

	var q2 *obj.Prog
	for p := cursym.Func().Text; p != nil; p = p.Link {
		o := p.As
		switch o {
		case obj.ATEXT:
			autosize = autoffset

			if p.Mark&LEAF != 0 && autosize == 0 {
				// A leaf function with no locals has no frame.
				p.From.Sym.Set(obj.AttrNoFrame, true)
			}

			if !p.From.Sym.NoFrame() {
				// If there is a stack frame at all, it includes
				// space to save the LR.
				autosize += 4
			}

			if autosize == 0 && cursym.Func().Text.Mark&LEAF == 0 {
				// A very few functions that do not return to their caller
				// are not identified as leaves but still have no frame.
				if ctxt.Debugvlog {
					ctxt.Logf("save suppressed in: %s\n", cursym.Name)
				}

				cursym.Func().Text.Mark |= LEAF
			}

			// FP offsets need an updated p.To.Offset.
			p.To.Offset = int64(autosize) - 4

			if cursym.Func().Text.Mark&LEAF != 0 {
				cursym.Set(obj.AttrLeaf, true)
				if p.From.Sym.NoFrame() {
					break
				}
			}

			if !p.From.Sym.NoSplit() {
				p = c.stacksplit(p, autosize) // emit split check
			}

			// MOVW.W		R14,$-autosize(SP)
			p = obj.Appendp(p, c.newprog)

			p.As = AMOVW
			p.Scond |= C_WBIT
			p.From.Type = obj.TYPE_REG
			p.From.Reg = REGLINK
			p.To.Type = obj.TYPE_MEM
			p.To.Offset = int64(-autosize)
			p.To.Reg = REGSP
			p.Spadj = autosize

			if cursym.Func().Text.From.Sym.Wrapper() {
				// if(g->panic != nil && g->panic->argp == FP) g->panic->argp = bottom-of-frame
				//
				//	MOVW g_panic(g), R1
				//	CMP  $0, R1
				//	B.NE checkargp
				// end:
				//	NOP
				// ... function ...
				// checkargp:
				//	MOVW panic_argp(R1), R2
				//	ADD  $(autosize+4), R13, R3
				//	CMP  R2, R3
				//	B.NE end
				//	ADD  $4, R13, R4
				//	MOVW R4, panic_argp(R1)
				//	B    end
				//
				// The NOP is needed to give the jumps somewhere to land.
				// It is a liblink NOP, not an ARM NOP: it encodes to 0 instruction bytes.

				p = obj.Appendp(p, newprog)
				p.As = AMOVW
				p.From.Type = obj.TYPE_MEM
				p.From.Reg = REGG
				p.From.Offset = 4 * int64(ctxt.Arch.PtrSize) // G.panic
				p.To.Type = obj.TYPE_REG
				p.To.Reg = REG_R1

				p = obj.Appendp(p, newprog)
				p.As = ACMP
				p.From.Type = obj.TYPE_CONST
				p.From.Offset = 0
				p.Reg = REG_R1

				// B.NE checkargp
				bne := obj.Appendp(p, newprog)
				bne.As = ABNE
				bne.To.Type = obj.TYPE_BRANCH

				// end: NOP
				end := obj.Appendp(bne, newprog)
				end.As = obj.ANOP

				// find end of function
				var last *obj.Prog
				for last = end; last.Link != nil; last = last.Link {
				}

				// MOVW panic_argp(R1), R2
				mov := obj.Appendp(last, newprog)
				mov.As = AMOVW
				mov.From.Type = obj.TYPE_MEM
				mov.From.Reg = REG_R1
				mov.From.Offset = 0 // Panic.argp
				mov.To.Type = obj.TYPE_REG
				mov.To.Reg = REG_R2

				// B.NE branch target is MOVW above
				bne.To.SetTarget(mov)

				// ADD $(autosize+4), R13, R3
				p = obj.Appendp(mov, newprog)
				p.As = AADD
				p.From.Type = obj.TYPE_CONST
				p.From.Offset = int64(autosize) + 4
				p.Reg = REG_R13
				p.To.Type = obj.TYPE_REG
				p.To.Reg = REG_R3

				// CMP R2, R3
				p = obj.Appendp(p, newprog)
				p.As = ACMP
				p.From.Type = obj.TYPE_REG
				p.From.Reg = REG_R2
				p.Reg = REG_R3

				// B.NE end
				p = obj.Appendp(p, newprog)
				p.As = ABNE
				p.To.Type = obj.TYPE_BRANCH
				p.To.SetTarget(end)

				// ADD $4, R13, R4
				p = obj.Appendp(p, newprog)
				p.As = AADD
				p.From.Type = obj.TYPE_CONST
				p.From.Offset = 4
				p.Reg = REG_R13
				p.To.Type = obj.TYPE_REG
				p.To.Reg = REG_R4

				// MOVW R4, panic_argp(R1)
				p = obj.Appendp(p, newprog)
				p.As = AMOVW
				p.From.Type = obj.TYPE_REG
				p.From.Reg = REG_R4
				p.To.Type = obj.TYPE_MEM
				p.To.Reg = REG_R1
				p.To.Offset = 0 // Panic.argp

				// B end
				p = obj.Appendp(p, newprog)
				p.As = AB
				p.To.Type = obj.TYPE_BRANCH
				p.To.SetTarget(end)

				// reset for subsequent passes
				p = end
			}

		case obj.ARET:
			nocache(p)
			if cursym.Func().Text.Mark&LEAF != 0 {
				if autosize == 0 {
					p.As = AB
					p.From = obj.Addr{}
					if p.To.Sym != nil { // retjmp
						p.To.Type = obj.TYPE_BRANCH
					} else {
						p.To.Type = obj.TYPE_MEM
						p.To.Offset = 0
						p.To.Reg = REGLINK
					}

					break
				}
			}

			p.As = AMOVW
			p.Scond |= C_PBIT
			p.From.Type = obj.TYPE_MEM
			p.From.Offset = int64(autosize)
			p.From.Reg = REGSP
			p.To.Type = obj.TYPE_REG
			p.To.Reg = REGPC

			// If there are instructions following
			// this ARET, they come from a branch
			// with the same stackframe, so no spadj.

			if p.To.Sym != nil { // retjmp
				p.To.Reg = REGLINK
				q2 = obj.Appendp(p, newprog)
				q2.As = AB
				q2.To.Type = obj.TYPE_BRANCH
				q2.To.Sym = p.To.Sym
				p.To.Sym = nil
				p.To.Name = obj.NAME_NONE
				p = q2
			}

		case AADD:
			if p.From.Type == obj.TYPE_CONST && p.From.Reg == 0 && p.To.Type == obj.TYPE_REG && p.To.Reg == REGSP {
				p.Spadj = int32(-p.From.Offset)
			}

		case ASUB:
			if p.From.Type == obj.TYPE_CONST && p.From.Reg == 0 && p.To.Type == obj.TYPE_REG && p.To.Reg == REGSP {
				p.Spadj = int32(p.From.Offset)
			}

		case ADIV, ADIVU, AMOD, AMODU:
			if cursym.Func().Text.From.Sym.NoSplit() {
				ctxt.Diag("cannot divide in NOSPLIT function")
			}
			const debugdivmod = false
			if debugdivmod {
				break
			}
			if p.From.Type != obj.TYPE_REG {
				break
			}
			if p.To.Type != obj.TYPE_REG {
				break
			}

			// Make copy because we overwrite p below.
			q1 := *p
			if q1.Reg == REGTMP || q1.Reg == 0 && q1.To.Reg == REGTMP {
				ctxt.Diag("div already using REGTMP: %v", p)
			}

			/* MOV m(g),REGTMP */
			p.As = AMOVW
			p.Pos = q1.Pos
			p.From.Type = obj.TYPE_MEM
			p.From.Reg = REGG
			p.From.Offset = 6 * 4 // offset of g.m
			p.Reg = 0
			p.To.Type = obj.TYPE_REG
			p.To.Reg = REGTMP

			/* MOV a,m_divmod(REGTMP) */
			p = obj.Appendp(p, newprog)
			p.As = AMOVW
			p.Pos = q1.Pos
			p.From.Type = obj.TYPE_REG
			p.From.Reg = q1.From.Reg
			p.To.Type = obj.TYPE_MEM
			p.To.Reg = REGTMP
			p.To.Offset = 8 * 4 // offset of m.divmod

			/* MOV b, R8 */
			p = obj.Appendp(p, newprog)
			p.As = AMOVW
			p.Pos = q1.Pos
			p.From.Type = obj.TYPE_REG
			p.From.Reg = q1.Reg
			if q1.Reg == 0 {
				p.From.Reg = q1.To.Reg
			}
			p.To.Type = obj.TYPE_REG
			p.To.Reg = REG_R8
			p.To.Offset = 0

			/* CALL appropriate */
			p = obj.Appendp(p, newprog)
			p.As = ABL
			p.Pos = q1.Pos
			p.To.Type = obj.TYPE_BRANCH
			switch o {
			case ADIV:
				p.To.Sym = symdiv
			case ADIVU:
				p.To.Sym = symdivu
			case AMOD:
				p.To.Sym = symmod
			case AMODU:
				p.To.Sym = symmodu
			}

			/* MOV REGTMP, b */
			p = obj.Appendp(p, newprog)
			p.As = AMOVW
			p.Pos = q1.Pos
			p.From.Type = obj.TYPE_REG
			p.From.Reg = REGTMP
			p.From.Offset = 0
			p.To.Type = obj.TYPE_REG
			p.To.Reg = q1.To.Reg

		case AMOVW:
			if (p.Scond&C_WBIT != 0) && p.To.Type == obj.TYPE_MEM && p.To.Reg == REGSP {
				p.Spadj = int32(-p.To.Offset)
			}
			if (p.Scond&C_PBIT != 0) && p.From.Type == obj.TYPE_MEM && p.From.Reg == REGSP && p.To.Reg != REGPC {
				p.Spadj = int32(-p.From.Offset)
			}
			if p.From.Type == obj.TYPE_ADDR && p.From.Reg == REGSP && p.To.Type == obj.TYPE_REG && p.To.Reg == REGSP {
				p.Spadj = int32(-p.From.Offset)
			}

		case obj.AGETCALLERPC:
			if cursym.Leaf() {
				/* MOVW LR, Rd */
				p.As = AMOVW
				p.From.Type = obj.TYPE_REG
				p.From.Reg = REGLINK
			} else {
				/* MOVW (RSP), Rd */
				p.As = AMOVW
				p.From.Type = obj.TYPE_MEM
				p.From.Reg = REGSP
			}
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
	}
}

func (c *ctxt5) stacksplit(p *obj.Prog, framesize int32) *obj.Prog {
	if c.ctxt.Flag_maymorestack != "" {
		// Save LR and make room for REGCTXT.
		const frameSize = 8
		// MOVW.W R14,$-8(SP)
		p = obj.Appendp(p, c.newprog)
		p.As = AMOVW
		p.Scond |= C_WBIT
		p.From.Type = obj.TYPE_REG
		p.From.Reg = REGLINK
		p.To.Type = obj.TYPE_MEM
		p.To.Offset = -frameSize
		p.To.Reg = REGSP
		p.Spadj = frameSize

		// MOVW REGCTXT, 4(SP)
		p = obj.Appendp(p, c.newprog)
		p.As = AMOVW
		p.From.Type = obj.TYPE_REG
		p.From.Reg = REGCTXT
		p.To.Type = obj.TYPE_MEM
		p.To.Offset = 4
		p.To.Reg = REGSP

		// CALL maymorestack
		p = obj.Appendp(p, c.newprog)
		p.As = obj.ACALL
		p.To.Type = obj.TYPE_BRANCH
		// See ../x86/obj6.go
		p.To.Sym = c.ctxt.LookupABI(c.ctxt.Flag_maymorestack, c.cursym.ABI())

		// Restore REGCTXT and LR.

		// MOVW 4(SP), REGCTXT
		p = obj.Appendp(p, c.newprog)
		p.As = AMOVW
		p.From.Type = obj.TYPE_MEM
		p.From.Offset = 4
		p.From.Reg = REGSP
		p.To.Type = obj.TYPE_REG
		p.To.Reg = REGCTXT

		// MOVW.P 8(SP), R14
		p.As = AMOVW
		p.Scond |= C_PBIT
		p.From.Type = obj.TYPE_MEM
		p.From.Offset = frameSize
		p.From.Reg = REGSP
		p.To.Type = obj.TYPE_REG
		p.To.Reg = REGLINK
		p.Spadj = -frameSize
	}

	// Jump back to here after morestack returns.
	startPred := p

	// MOVW g_stackguard(g), R1
	p = obj.Appendp(p, c.newprog)

	p.As = AMOVW
	p.From.Type = obj.TYPE_MEM
	p.From.Reg = REGG
	p.From.Offset = 2 * int64(c.ctxt.Arch.PtrSize) // G.stackguard0
	if c.cursym.CFunc() {
		p.From.Offset = 3 * int64(c.ctxt.Arch.PtrSize) // G.stackguard1
	}
	p.To.Type = obj.TYPE_REG
	p.To.Reg = REG_R1

	// Mark the stack bound check and morestack call async nonpreemptible.
	// If we get preempted here, when resumed the preemption request is
	// cleared, but we'll still call morestack, which will double the stack
	// unnecessarily. See issue #35470.
	p = c.ctxt.StartUnsafePoint(p, c.newprog)

	if framesize <= abi.StackSmall {
		// small stack: SP < stackguard
		//	CMP	stackguard, SP
		p = obj.Appendp(p, c.newprog)

		p.As = ACMP
		p.From.Type = obj.TYPE_REG
		p.From.Reg = REG_R1
		p.Reg = REGSP
	} else if framesize <= abi.StackBig {
		// large stack: SP-framesize < stackguard-StackSmall
		//	MOVW $-(framesize-StackSmall)(SP), R2
		//	CMP stackguard, R2
		p = obj.Appendp(p, c.newprog)

		p.As = AMOVW
		p.From.Type = obj.TYPE_ADDR
		p.From.Reg = REGSP
		p.From.Offset = -(int64(framesize) - abi.StackSmall)
		p.To.Type = obj.TYPE_REG
		p.To.Reg = REG_R2

		p = obj.Appendp(p, c.newprog)
		p.As = ACMP
		p.From.Type = obj.TYPE_REG
		p.From.Reg = REG_R1
		p.Reg = REG_R2
	} else {
		// Such a large stack we need to protect against underflow.
		// The runtime guarantees SP > objabi.StackBig, but
		// framesize is large enough that SP-framesize may
		// underflow, causing a direct comparison with the
		// stack guard to incorrectly succeed. We explicitly
		// guard against underflow.
		//
		//	// Try subtracting from SP and check for underflow.
		//	// If this underflows, it sets C to 0.
		//	SUB.S $(framesize-StackSmall), SP, R2
		//	// If C is 1 (unsigned >=), compare with guard.
		//	CMP.HS stackguard, R2

		p = obj.Appendp(p, c.newprog)
		p.As = ASUB
		p.Scond = C_SBIT
		p.From.Type = obj.TYPE_CONST
		p.From.Offset = int64(framesize) - abi.StackSmall
		p.Reg = REGSP
		p.To.Type = obj.TYPE_REG
		p.To.Reg = REG_R2

		p = obj.Appendp(p, c.newprog)
		p.As = ACMP
		p.Scond = C_SCOND_HS
		p.From.Type = obj.TYPE_REG
		p.From.Reg = REG_R1
		p.Reg = REG_R2
	}

	// BLS call-to-morestack (C is 0 or Z is 1)
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

	// MOVW	LR, R3
	movw := obj.Appendp(pcdata, c.newprog)
	movw.As = AMOVW
	movw.From.Type = obj.TYPE_REG
	movw.From.Reg = REGLINK
	movw.To.Type = obj.TYPE_REG
	movw.To.Reg = REG_R3

	bls.To.SetTarget(movw)

	// BL runtime.morestack
	call := obj.Appendp(movw, c.newprog)
	call.As = obj.ACALL
	call.To.Type = obj.TYPE_BRANCH
	morestack := "runtime.morestack"
	switch {
	case c.cursym.CFunc():
		morestack = "runtime.morestackc"
	case !c.cursym.Func().Text.From.Sym.NeedCtxt():
		morestack = "runtime.morestack_noctxt"
	}
	call.To.Sym = c.ctxt.Lookup(morestack)

	pcdata = c.ctxt.EndUnsafePoint(call, c.newprog, -1)

	// B start
	b := obj.Appendp(pcdata, c.newprog)
	b.As = obj.AJMP
	b.To.Type = obj.TYPE_BRANCH
	b.To.SetTarget(startPred.Link)
	b.Spadj = +framesize

	return end
}

var unaryDst = map[obj.As]bool{
	ASWI:  true,
	AWORD: true,
}

var Linkarm = obj.LinkArch{
	Arch:           sys.ArchARM,
	Init:           buildop,
	Preprocess:     preprocess,
	Assemble:       span5,
	Progedit:       progedit,
	UnaryDst:       unaryDst,
	DWARFRegisters: ARMDWARFRegisters,
}
```