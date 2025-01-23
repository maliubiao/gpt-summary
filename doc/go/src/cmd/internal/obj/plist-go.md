Response: The user wants to understand the functionality of the Go code snippet provided. I need to:

1. **Summarize the main purpose of the `plist.go` file.**  Looking at the code, it seems to handle the processing of a list of assembly program instructions (`Prog`s) associated with functions. Key functions like `Flushplist` suggest this involves linking, symbol management, and potentially generating metadata for debugging or runtime.

2. **Identify specific functions and their roles.**  I will examine functions like `Flushplist`, `InitTextSym`, `Globl`, `EmitEntryLiveness`, `StartUnsafePoint`, `EndUnsafePoint`, and `MarkUnsafePoints` to understand their individual contributions.

3. **Infer the broader Go feature being implemented.** Based on the functions and data structures, it seems related to the compilation and linking process, specifically dealing with assembly instructions and metadata generation. This likely relates to how Go code is translated into machine code.

4. **Provide Go code examples.** If I can identify a specific feature, I'll create a simple Go code example that would trigger the execution of code within `plist.go`. This will likely involve assembly code or function definitions.

5. **Explain code reasoning with assumptions.**  If I need to make assumptions about the input or context of the code to explain its behavior, I'll explicitly state those assumptions.

6. **Describe command-line parameter handling.** I'll look for any code that parses or reacts to command-line arguments. The presence of `ctxt.Debugasm` and `ctxt.Debugvlog` suggests some level of command-line control for debugging output.

7. **Point out potential pitfalls for users.**  Based on the code, I'll try to identify any common mistakes someone using this functionality might make. For instance, incorrect use of `FUNCDATA` directives in assembly could be a source of errors.

**Detailed Breakdown of the Code:**

* **`Plist`**: Seems to represent a list of program instructions for a function.
* **`Flushplist`**:  The core function. It iterates through the `Prog` list, identifies function boundaries (`ATEXT`), handles `FUNCDATA` directives, links instructions, and calls architecture-specific assembly and linking functions.
* **`InitTextSym`**: Likely initializes a symbol representing a text (code) segment, setting attributes and preparing it for code generation.
* **`Globl` / `GloblPos`**: Declares a global symbol with a given size and flags, assigning it to the data or BSS segment.
* **`EmitEntryLiveness` / `EmitEntryStackMap` / `EmitEntryUnsafePoint`**:  These functions appear to insert special instructions (`APCDATA`) to manage stack maps and mark safe/unsafe points for garbage collection or preemption.
* **`StartUnsafePoint` / `EndUnsafePoint`**:  Mark the beginning and end of code sections where asynchronous preemption is not allowed.
* **`MarkUnsafePoints`**:  A higher-level function that uses `StartUnsafePoint` and `EndUnsafePoint` to automatically insert markers based on predicates.

**Inferences about the Go feature:**

This code seems to be a part of the **Go compiler's assembler and linker**. It's responsible for taking the intermediate representation of Go code (likely after parsing and type checking) and generating machine code, managing symbols, and inserting metadata for runtime support (like garbage collection and stack unwinding).

**Potential User Errors:**

One area for potential errors is in **writing assembly code that interacts with Go's runtime**. Incorrectly specifying `FUNCDATA` directives or failing to mark unsafe points could lead to crashes or incorrect behavior.
`go/src/cmd/internal/obj/plist.go` 文件是 Go 语言工具链中 `cmd/compile` 和 `cmd/link` 的一部分，它主要负责处理和组织程序指令（`Prog` 类型）。  可以理解为，在将 Go 源代码编译成机器码的过程中，这个文件处理的是一个中间表示形式，即一系列待处理的指令。

以下是 `plist.go` 的主要功能点：

1. **维护指令列表:** `Plist` 结构体持有函数指令列表的头指针 (`Firstpc`) 以及当前处理的函数信息 (`Curfn`)。这表示它管理着一个函数内部指令的顺序。

2. **分配指令:**  `ProgAlloc` 类型定义了一个分配 `Prog` 结构体的函数类型。这允许使用缓存或批量分配的方式来管理 `Prog` 对象，提高性能。

3. **刷新指令列表 (`Flushplist`):**  这是核心功能。它遍历一个 `Plist` 中的指令，并执行以下操作：
    * **符号关联:** 将指令与符号（`LSym`）关联起来，特别是函数符号 (`ATEXT` 指令)。
    * **处理 `FUNCDATA` 指令:**  `FUNCDATA` 用于描述函数参数和局部变量的指针信息，供垃圾回收器使用。`Flushplist` 会根据符号名称（如 "go_args_stackmap" 和 "no_pointers_stackmap"）来查找或创建相应的符号，并将 `FUNCDATA` 指令关联到正确的符号上。
    * **为汇编函数添加 Go 参数引用:** 对于汇编编写的函数，如果没有显式声明参数信息，`Flushplist` 会自动添加对 `.args_stackmap` 和 `.arginfo` 符号的引用，以便运行时能够正确处理函数调用。
    * **将函数转换为机器码:**  遍历函数符号列表，并调用架构相关的函数 (`ctxt.Arch.ErrorCheck`, `linkpatch`, `ctxt.Arch.Preprocess`, `ctxt.Arch.Assemble`) 将函数指令转换为机器码。
    * **生成调试信息:** 调用 `linkpcln` 和 `ctxt.populateDWARF` 来生成行号信息和 DWARF 调试信息。
    * **处理 Windows SEH:** 在 Windows 平台上，如果定义了架构相关的 SEH 处理函数，则会调用它来生成 SEH 展开信息。

4. **初始化文本符号 (`InitTextSym`):**  用于初始化表示函数代码段的符号 (`LSym`)。它会检查符号是否已声明，设置函数的各种属性（如是否可以重复、是否禁止栈分裂等），并创建 DWARF 条目。

5. **声明全局符号 (`Globl`, `GloblPos`):**  用于声明全局变量或常量符号，指定其大小和属性（如是否可以重复、是否只读、是否不包含指针等），并将符号添加到相应的数据段或 BSS 段。

6. **生成入口活跃度信息 (`EmitEntryLiveness`, `EmitEntryStackMap`, `EmitEntryUnsafePoint`):**  这些函数用于在函数入口处插入特殊的 `APCDATA` 指令，以记录栈映射信息和标记不安全点，供垃圾回收器使用。

7. **标记不安全点 (`StartUnsafePoint`, `EndUnsafePoint`, `MarkUnsafePoints`):**  这些函数用于在代码中标记可能导致程序状态不一致的代码段（不安全点），例如执行系统调用或与其他 Goroutine 同步的代码。这对于实现抢占式调度和保证内存安全至关重要。`MarkUnsafePoints` 提供了一种更高级的方式，根据给定的谓词函数自动标记不安全点和可重启点。

**它是什么 Go 语言功能的实现？**

`plist.go` 是 **Go 编译器和链接器生成目标代码和元数据** 的关键部分。它处理了从中间表示到最终机器码的转换，并生成了运行时所需的各种辅助信息，例如栈映射、调试信息和抢占点信息。

**Go 代码示例：**

以下示例展示了如何在 Go 汇编中使用 `FUNCDATA` 指令，这会触发 `Flushplist` 中的相关逻辑。

```go
// myasm.s
#include "go_asm.h"
#include "go_defs.h"

// func MyFunc(a int) int
TEXT ·MyFunc(SB), ABIInternal, $0-8
    // Mark arguments as live.
    FUNCDATA $0, gclocals·myFuncArgs(SB)
    // Mark no local variables as live.
    FUNCDATA $1, gclocals·noLocals(SB)
    MOVQ  a+0(FP), AX
    ADDQ  AX, AX
    MOVQ  AX, ret+8(FP)
    RET

DATA gclocals·myFuncArgs+0(SB)/8, $0x00000001 // One argument is a pointer
GLOBL gclocals·myFuncArgs(SB), NOPTR|RODATA, $8

DATA gclocals·noLocals+0(SB)/8, $0x00000000
GLOBL gclocals·noLocals(SB), NOPTR|RODATA, $8

// mygo.go
package main

func MyFunc(a int) int

func main() {
	println(MyFunc(5))
}
```

**假设的输入与输出：**

当使用 `go build mygo.go` 编译上述代码时，`Flushplist` 会处理 `myasm.s` 中定义的 `MyFunc` 函数的指令。

* **输入 (简化表示):**
    * 一个包含 `ATEXT` 指令表示 `MyFunc` 函数开始的 `Prog` 列表。
    * 两个 `FUNCDATA` 指令，分别引用 `gclocals·myFuncArgs` 和 `gclocals·noLocals` 符号。
* **输出 (简化表示):**
    * `MyFunc` 函数的 `LSym` 对象会被创建或找到。
    * `FUNCDATA` 指令会关联到正确的符号，例如 `ctxt.LookupDerived(curtext, curtext.Name+".args_stackmap")` 可能会被调用来查找或创建 `.args_stackmap` 符号。
    * 最终，`MyFunc` 的指令会被转换为机器码，并生成相应的元数据，例如用于垃圾回收的栈映射信息。

**命令行参数的具体处理：**

`Flushplist` 中涉及到以下命令行参数的处理：

* **`ctxt.Debugasm > 0` 和 `ctxt.Debugvlog`:**  如果同时设置了这两个调试选项，`Flushplist` 会打印正在处理的每条指令 (`fmt.Printf("obj: %v\n", p)`)。这对于调试汇编代码生成过程非常有用。 这些参数通常通过 `go build -gcflags=-S -v` 或类似的组合来设置。 `-gcflags=-S` 会输出汇编代码， `-v` 会输出详细的编译信息，其中可能包含影响 `ctxt.Debugvlog` 的设置。

**使用者易犯错的点：**

在与 `plist.go` 相关的汇编编程中，一个常见的错误是 **不正确地使用 `FUNCDATA` 指令**，导致垃圾回收器无法正确识别指针，从而可能引发内存泄漏或程序崩溃。

**示例：**

假设汇编代码中定义了一个包含指针的结构体，但没有使用 `FUNCDATA` 正确标记这些指针：

```assembly
// badasm.s
#include "go_asm.h"
#include "go_defs.h"

// type MyStruct struct { P *int }
TEXT ·BadFunc(SB), ABIInternal, $8-0
    // 没有使用 FUNCDATA 标记结构体中的指针
    MOVQ  p+0(FP), AX
    RET
```

在这种情况下，垃圾回收器可能不会扫描 `MyStruct` 实例中的指针，如果该指针指向的内存不再被其他对象引用，则可能被错误地回收，导致悬挂指针。

正确的方式是使用 `FUNCDATA` 来描述 `MyStruct` 的内存布局，指出哪些字段是指针。这通常需要在 Go 代码中定义一个包含指针的变量，然后在汇编中使用 `gclocals` 伪指令来引用它。

总而言之，`go/src/cmd/internal/obj/plist.go` 是 Go 工具链中负责处理和组织底层指令的关键部分，它连接了编译器前端的抽象表示和链接器的最终机器码生成，并负责生成运行时所需的各种元数据。理解它的功能对于深入理解 Go 编译过程和进行底层编程非常重要。

### 提示词
```
这是路径为go/src/cmd/internal/obj/plist.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
```

### 源代码
```go
// Copyright 2013 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package obj

import (
	"cmd/internal/objabi"
	"cmd/internal/src"
	"fmt"
	"internal/abi"
	"strings"
)

type Plist struct {
	Firstpc *Prog
	Curfn   Func
}

// ProgAlloc is a function that allocates Progs.
// It is used to provide access to cached/bulk-allocated Progs to the assemblers.
type ProgAlloc func() *Prog

func Flushplist(ctxt *Link, plist *Plist, newprog ProgAlloc) {
	if ctxt.Pkgpath == "" {
		panic("Flushplist called without Pkgpath")
	}

	// Build list of symbols, and assign instructions to lists.
	var curtext *LSym
	var etext *Prog
	var text []*LSym

	var plink *Prog
	for p := plist.Firstpc; p != nil; p = plink {
		if ctxt.Debugasm > 0 && ctxt.Debugvlog {
			fmt.Printf("obj: %v\n", p)
		}
		plink = p.Link
		p.Link = nil

		switch p.As {
		case AEND:
			continue

		case ATEXT:
			s := p.From.Sym
			if s == nil {
				// func _() { }
				curtext = nil
				continue
			}
			text = append(text, s)
			etext = p
			curtext = s
			continue

		case AFUNCDATA:
			// Rewrite reference to go_args_stackmap(SB) to the Go-provided declaration information.
			if curtext == nil { // func _() {}
				continue
			}
			switch p.To.Sym.Name {
			case "go_args_stackmap":
				if p.From.Type != TYPE_CONST || p.From.Offset != abi.FUNCDATA_ArgsPointerMaps {
					ctxt.Diag("%s: FUNCDATA use of go_args_stackmap(SB) without FUNCDATA_ArgsPointerMaps", p.Pos)
				}
				p.To.Sym = ctxt.LookupDerived(curtext, curtext.Name+".args_stackmap")
			case "no_pointers_stackmap":
				if p.From.Type != TYPE_CONST || p.From.Offset != abi.FUNCDATA_LocalsPointerMaps {
					ctxt.Diag("%s: FUNCDATA use of no_pointers_stackmap(SB) without FUNCDATA_LocalsPointerMaps", p.Pos)
				}
				// funcdata for functions with no local variables in frame.
				// Define two zero-length bitmaps, because the same index is used
				// for the local variables as for the argument frame, and assembly
				// frames have two argument bitmaps, one without results and one with results.
				// Write []uint32{2, 0}.
				b := make([]byte, 8)
				ctxt.Arch.ByteOrder.PutUint32(b, 2)
				s := ctxt.GCLocalsSym(b)
				if !s.OnList() {
					ctxt.Globl(s, int64(len(s.P)), int(RODATA|DUPOK))
				}
				p.To.Sym = s
			}

		}

		if curtext == nil {
			etext = nil
			continue
		}
		etext.Link = p
		etext = p
	}

	if newprog == nil {
		newprog = ctxt.NewProg
	}

	// Add reference to Go arguments for assembly functions without them.
	if ctxt.IsAsm {
		pkgPrefix := objabi.PathToPrefix(ctxt.Pkgpath) + "."
		for _, s := range text {
			if !strings.HasPrefix(s.Name, pkgPrefix) {
				continue
			}
			// The current args_stackmap generation in the compiler assumes
			// that the function in question is ABI0, so avoid introducing
			// an args_stackmap reference if the func is not ABI0 (better to
			// have no stackmap than an incorrect/lying stackmap).
			if s.ABI() != ABI0 {
				continue
			}
			// runtime.addmoduledata is a host ABI function, so it doesn't
			// need FUNCDATA anyway. Moreover, cmd/link has special logic
			// for linking it in eccentric build modes, which breaks if it
			// has FUNCDATA references (e.g., cmd/cgo/internal/testplugin).
			//
			// TODO(cherryyz): Fix cmd/link's handling of plugins (see
			// discussion on CL 523355).
			if s.Name == "runtime.addmoduledata" {
				continue
			}
			foundArgMap, foundArgInfo := false, false
			for p := s.Func().Text; p != nil; p = p.Link {
				if p.As == AFUNCDATA && p.From.Type == TYPE_CONST {
					if p.From.Offset == abi.FUNCDATA_ArgsPointerMaps {
						foundArgMap = true
					}
					if p.From.Offset == abi.FUNCDATA_ArgInfo {
						foundArgInfo = true
					}
					if foundArgMap && foundArgInfo {
						break
					}
				}
			}
			if !foundArgMap {
				p := Appendp(s.Func().Text, newprog)
				p.As = AFUNCDATA
				p.From.Type = TYPE_CONST
				p.From.Offset = abi.FUNCDATA_ArgsPointerMaps
				p.To.Type = TYPE_MEM
				p.To.Name = NAME_EXTERN
				p.To.Sym = ctxt.LookupDerived(s, s.Name+".args_stackmap")
			}
			if !foundArgInfo {
				p := Appendp(s.Func().Text, newprog)
				p.As = AFUNCDATA
				p.From.Type = TYPE_CONST
				p.From.Offset = abi.FUNCDATA_ArgInfo
				p.To.Type = TYPE_MEM
				p.To.Name = NAME_EXTERN
				p.To.Sym = ctxt.LookupDerived(s, fmt.Sprintf("%s.arginfo%d", s.Name, s.ABI()))
			}
		}
	}

	// Turn functions into machine code images.
	for _, s := range text {
		mkfwd(s)
		if ctxt.Arch.ErrorCheck != nil {
			ctxt.Arch.ErrorCheck(ctxt, s)
		}
		linkpatch(ctxt, s, newprog)
		ctxt.Arch.Preprocess(ctxt, s, newprog)
		ctxt.Arch.Assemble(ctxt, s, newprog)
		if ctxt.Errors > 0 {
			continue
		}
		linkpcln(ctxt, s)
		ctxt.populateDWARF(plist.Curfn, s)
		if ctxt.Headtype == objabi.Hwindows && ctxt.Arch.SEH != nil {
			s.Func().sehUnwindInfoSym = ctxt.Arch.SEH(ctxt, s)
		}
	}
}

func (ctxt *Link) InitTextSym(s *LSym, flag int, start src.XPos) {
	if s == nil {
		// func _() { }
		return
	}
	if s.Func() != nil {
		ctxt.Diag("%s: symbol %s redeclared\n\t%s: other declaration of symbol %s", ctxt.PosTable.Pos(start), s.Name, ctxt.PosTable.Pos(s.Func().Text.Pos), s.Name)
		return
	}
	s.NewFuncInfo()
	if s.OnList() {
		ctxt.Diag("%s: symbol %s redeclared", ctxt.PosTable.Pos(start), s.Name)
		return
	}
	if strings.HasPrefix(s.Name, `"".`) {
		ctxt.Diag("%s: unqualified symbol name: %s", ctxt.PosTable.Pos(start), s.Name)
	}

	// startLine should be the same line number that would be displayed via
	// pcln, etc for the declaration (i.e., relative line number, as
	// adjusted by //line).
	_, startLine := ctxt.getFileIndexAndLine(start)

	s.Func().FuncID = objabi.GetFuncID(s.Name, flag&WRAPPER != 0 || flag&ABIWRAPPER != 0)
	s.Func().FuncFlag = ctxt.toFuncFlag(flag)
	s.Func().StartLine = startLine
	s.Set(AttrOnList, true)
	s.Set(AttrDuplicateOK, flag&DUPOK != 0)
	s.Set(AttrNoSplit, flag&NOSPLIT != 0)
	s.Set(AttrReflectMethod, flag&REFLECTMETHOD != 0)
	s.Set(AttrWrapper, flag&WRAPPER != 0)
	s.Set(AttrABIWrapper, flag&ABIWRAPPER != 0)
	s.Set(AttrNeedCtxt, flag&NEEDCTXT != 0)
	s.Set(AttrNoFrame, flag&NOFRAME != 0)
	s.Set(AttrPkgInit, flag&PKGINIT != 0)
	s.Type = objabi.STEXT
	s.setFIPSType(ctxt)
	ctxt.Text = append(ctxt.Text, s)

	// Set up DWARF entries for s
	ctxt.dwarfSym(s)
}

func (ctxt *Link) toFuncFlag(flag int) abi.FuncFlag {
	var out abi.FuncFlag
	if flag&TOPFRAME != 0 {
		out |= abi.FuncFlagTopFrame
	}
	if ctxt.IsAsm {
		out |= abi.FuncFlagAsm
	}
	return out
}

func (ctxt *Link) Globl(s *LSym, size int64, flag int) {
	ctxt.GloblPos(s, size, flag, src.NoXPos)
}
func (ctxt *Link) GloblPos(s *LSym, size int64, flag int, pos src.XPos) {
	if s.OnList() {
		// TODO: print where the first declaration was.
		ctxt.Diag("%s: symbol %s redeclared", ctxt.PosTable.Pos(pos), s.Name)
	}
	s.Set(AttrOnList, true)
	ctxt.Data = append(ctxt.Data, s)
	s.Size = size
	if s.Type == 0 {
		s.Type = objabi.SBSS
	}
	if flag&DUPOK != 0 {
		s.Set(AttrDuplicateOK, true)
	}
	if flag&RODATA != 0 {
		s.Type = objabi.SRODATA
	} else if flag&NOPTR != 0 {
		if s.Type.IsDATA() {
			s.Type = objabi.SNOPTRDATA
		} else {
			s.Type = objabi.SNOPTRBSS
		}
	} else if flag&TLSBSS != 0 {
		s.Type = objabi.STLSBSS
	}
	s.setFIPSType(ctxt)
}

// EmitEntryLiveness generates PCDATA Progs after p to switch to the
// liveness map active at the entry of function s. It returns the last
// Prog generated.
func (ctxt *Link) EmitEntryLiveness(s *LSym, p *Prog, newprog ProgAlloc) *Prog {
	pcdata := ctxt.EmitEntryStackMap(s, p, newprog)
	pcdata = ctxt.EmitEntryUnsafePoint(s, pcdata, newprog)
	return pcdata
}

// Similar to EmitEntryLiveness, but just emit stack map.
func (ctxt *Link) EmitEntryStackMap(s *LSym, p *Prog, newprog ProgAlloc) *Prog {
	pcdata := Appendp(p, newprog)
	pcdata.Pos = s.Func().Text.Pos
	pcdata.As = APCDATA
	pcdata.From.Type = TYPE_CONST
	pcdata.From.Offset = abi.PCDATA_StackMapIndex
	pcdata.To.Type = TYPE_CONST
	pcdata.To.Offset = -1 // pcdata starts at -1 at function entry

	return pcdata
}

// Similar to EmitEntryLiveness, but just emit unsafe point map.
func (ctxt *Link) EmitEntryUnsafePoint(s *LSym, p *Prog, newprog ProgAlloc) *Prog {
	pcdata := Appendp(p, newprog)
	pcdata.Pos = s.Func().Text.Pos
	pcdata.As = APCDATA
	pcdata.From.Type = TYPE_CONST
	pcdata.From.Offset = abi.PCDATA_UnsafePoint
	pcdata.To.Type = TYPE_CONST
	pcdata.To.Offset = -1

	return pcdata
}

// StartUnsafePoint generates PCDATA Progs after p to mark the
// beginning of an unsafe point. The unsafe point starts immediately
// after p.
// It returns the last Prog generated.
func (ctxt *Link) StartUnsafePoint(p *Prog, newprog ProgAlloc) *Prog {
	pcdata := Appendp(p, newprog)
	pcdata.As = APCDATA
	pcdata.From.Type = TYPE_CONST
	pcdata.From.Offset = abi.PCDATA_UnsafePoint
	pcdata.To.Type = TYPE_CONST
	pcdata.To.Offset = abi.UnsafePointUnsafe

	return pcdata
}

// EndUnsafePoint generates PCDATA Progs after p to mark the end of an
// unsafe point, restoring the register map index to oldval.
// The unsafe point ends right after p.
// It returns the last Prog generated.
func (ctxt *Link) EndUnsafePoint(p *Prog, newprog ProgAlloc, oldval int64) *Prog {
	pcdata := Appendp(p, newprog)
	pcdata.As = APCDATA
	pcdata.From.Type = TYPE_CONST
	pcdata.From.Offset = abi.PCDATA_UnsafePoint
	pcdata.To.Type = TYPE_CONST
	pcdata.To.Offset = oldval

	return pcdata
}

// MarkUnsafePoints inserts PCDATAs to mark nonpreemptible and restartable
// instruction sequences, based on isUnsafePoint and isRestartable predicate.
// p0 is the start of the instruction stream.
// isUnsafePoint(p) returns true if p is not safe for async preemption.
// isRestartable(p) returns true if we can restart at the start of p (this Prog)
// upon async preemption. (Currently multi-Prog restartable sequence is not
// supported.)
// isRestartable can be nil. In this case it is treated as always returning false.
// If isUnsafePoint(p) and isRestartable(p) are both true, it is treated as
// an unsafe point.
func MarkUnsafePoints(ctxt *Link, p0 *Prog, newprog ProgAlloc, isUnsafePoint, isRestartable func(*Prog) bool) {
	if isRestartable == nil {
		// Default implementation: nothing is restartable.
		isRestartable = func(*Prog) bool { return false }
	}
	prev := p0
	prevPcdata := int64(-1) // entry PC data value
	prevRestart := int64(0)
	for p := prev.Link; p != nil; p, prev = p.Link, p {
		if p.As == APCDATA && p.From.Offset == abi.PCDATA_UnsafePoint {
			prevPcdata = p.To.Offset
			continue
		}
		if prevPcdata == abi.UnsafePointUnsafe {
			continue // already unsafe
		}
		if isUnsafePoint(p) {
			q := ctxt.StartUnsafePoint(prev, newprog)
			q.Pc = p.Pc
			q.Link = p
			// Advance to the end of unsafe point.
			for p.Link != nil && isUnsafePoint(p.Link) {
				p = p.Link
			}
			if p.Link == nil {
				break // Reached the end, don't bother marking the end
			}
			p = ctxt.EndUnsafePoint(p, newprog, prevPcdata)
			p.Pc = p.Link.Pc
			continue
		}
		if isRestartable(p) {
			val := int64(abi.UnsafePointRestart1)
			if val == prevRestart {
				val = abi.UnsafePointRestart2
			}
			prevRestart = val
			q := Appendp(prev, newprog)
			q.As = APCDATA
			q.From.Type = TYPE_CONST
			q.From.Offset = abi.PCDATA_UnsafePoint
			q.To.Type = TYPE_CONST
			q.To.Offset = val
			q.Pc = p.Pc
			q.Link = p

			if p.Link == nil {
				break // Reached the end, don't bother marking the end
			}
			if isRestartable(p.Link) {
				// Next Prog is also restartable. No need to mark the end
				// of this sequence. We'll just go ahead mark the next one.
				continue
			}
			p = Appendp(p, newprog)
			p.As = APCDATA
			p.From.Type = TYPE_CONST
			p.From.Offset = abi.PCDATA_UnsafePoint
			p.To.Type = TYPE_CONST
			p.To.Offset = prevPcdata
			p.Pc = p.Link.Pc
		}
	}
}
```