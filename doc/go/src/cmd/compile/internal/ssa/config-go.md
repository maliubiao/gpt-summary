Response: Let's break down the thought process for analyzing the provided Go code snippet.

**1. Understanding the Goal:**

The request asks for the functionality of the `config.go` file within the Go compiler's SSA (Static Single Assignment) package. It also wants examples, potential errors, and command-line interaction details if applicable.

**2. Initial Skim and Keyword Recognition:**

The first step is to quickly read through the code, paying attention to keywords and structure. I see:

* `package ssa`: This tells me the context is the SSA optimization phase of the compiler.
* `type Config struct`: This is the central data structure, and its fields will be key to understanding the functionality.
* Field names like `arch`, `PtrSize`, `RegSize`, `registers`, `gpRegMask`, `fpRegMask`, `lowerBlock`, `lowerValue`, `ABI0`, `ABI1`, `optimize`, etc. These hints suggest the file is about configuring the compiler for different target architectures.
* `type Types struct`:  This likely holds pointers to core Go types, used during compilation.
* `type blockRewriter func(*Block) bool` and `type valueRewriter func(*Value) bool`: These suggest functions that transform the SSA representation.
* `func NewConfig(arch string, ...)`: This is a constructor, taking the target architecture as a primary argument.
* Conditional logic based on `arch`:  This reinforces the idea of architecture-specific configuration.
* References to `cmd/compile/internal/...` and `cmd/internal/obj`: This points to interactions with other parts of the compiler.

**3. Deeper Dive into the `Config` Struct:**

I'll now examine each field in the `Config` struct and try to infer its purpose:

* **Architecture-related:** `arch`, `PtrSize`, `RegSize`, `BigEndian`. These are clearly fundamental properties of the target architecture.
* **SSA Lowering:** `lowerBlock`, `lowerValue`, `lateLowerBlock`, `lateLowerValue`, `splitLoad`. These function types suggest the different stages and types of transformations applied to the SSA representation. The "lowering" terminology usually means translating high-level operations into more machine-specific ones.
* **Registers:** `registers`, `gpRegMask`, `fpRegMask`, `specialRegMask`, `intParamRegs`, `floatParamRegs`, `FPReg`, `LinkReg`, `hasGReg`, `GCRegMap`. This strongly indicates management of the target architecture's registers, including their types, masks, and special roles (frame pointer, link register, goroutine register).
* **ABI:** `ABI0`, `ABI1`. These likely represent Application Binary Interfaces, specifying how functions are called (parameter passing, return values).
* **Compiler Options:** `optimize`, `noDuffDevice`, `useSSE`, `useAvg`, `useHmul`, `SoftFloat`, `Race`, `UseFMA`, `unalignedOK`. These are flags controlling various compiler optimizations and features.
* **Context:** `ctxt *obj.Link`. This provides a link to general architecture information from the `obj` package.
* **Byte Swapping:** `haveBswap64`, `haveBswap32`, `haveBswap16`. Indicates hardware support for byte swapping.

**4. Analyzing `NewConfig` Function:**

This function is crucial. It takes the architecture string and other flags and populates the `Config` struct. The `switch arch` statement is the core logic for setting architecture-specific values. This confirms the primary function of `Config` is architecture-dependent configuration.

**5. Examining `Types` Struct and Related Functions:**

The `Types` struct and the `NewTypes` and `SetTypPtrs` functions are straightforward. They create and initialize a structure holding pointers to the fundamental Go types. This allows the SSA package to work with these types.

**6. Identifying Interfaces:**

The `Logger` and `Frontend` interfaces define the dependencies of the `ssa` package on other compiler components. `Logger` is for logging and error reporting. `Frontend` provides access to higher-level compiler information like string data, symbols, and the function being compiled.

**7. Inferring Go Language Feature Implementation:**

Based on the fields and the `NewConfig` function's logic, it's clear that this file is essential for the *compilation process itself*, specifically the **architecture-aware compilation** of Go code. It doesn't directly implement a user-facing Go language feature like goroutines or channels. Instead, it's a piece of the compiler's infrastructure.

**8. Constructing Examples:**

Since it's a compiler-internal component, direct user-level Go code examples are less relevant. Instead, I'll focus on illustrating how the *compiler* would use this. The key is showing how different architectures would lead to different `Config` values. I'll pick a few key fields like `PtrSize`, `gpRegMask`, and the lowering functions to demonstrate this.

**9. Considering Command-Line Arguments:**

The `NewConfig` function receives `optimize` and `softfloat` as arguments. These likely correspond to command-line flags passed to the `go build` command (e.g., `-N` to disable optimizations, although `softfloat` is less common). I'll elaborate on these.

**10. Identifying Potential Pitfalls:**

Since this is internal compiler code, the main "users" are compiler developers. Potential pitfalls include:

* **Incorrect Architecture String:** Providing an unsupported architecture string to `NewConfig` would cause a panic or incorrect compilation.
* **Mismatched Configuration:**  If the `Config` struct isn't correctly initialized for a given architecture, the generated assembly code could be wrong.

**11. Review and Refinement:**

Finally, I review my analysis, ensuring clarity, accuracy, and completeness. I double-check the relationships between the different parts of the code and ensure the examples effectively illustrate the concepts. I also make sure to address all parts of the original prompt.
这段代码是Go语言编译器中 `ssa` (Static Single Assignment) 中间表示的一个核心配置文件。它定义了 `Config` 结构体，该结构体包含了在编译过程中需要用到的只读配置信息，这些信息在编译的早期阶段创建并被所有编译过程共享。

**`config.go` 的主要功能：**

1. **存储目标架构的特定信息:**  `Config` 结构体存储了诸如目标架构的名称 (`arch`)、指针大小 (`PtrSize`)、寄存器大小 (`RegSize`)、大小端 (`BigEndian`) 等关键信息。这些信息对于生成正确的机器码至关重要。

2. **定义类型信息:**  `Types` 结构体存储了 Go 语言内置类型的指针，例如 `Bool`, `Int`, `Float64`, `String` 等。这使得 `ssa` 包中的代码能够方便地访问和操作这些类型信息。

3. **提供 SSA 降低 (Lowering) 函数:** `lowerBlock`, `lowerValue`, `lateLowerBlock`, `lateLowerValue`, `splitLoad` 等字段存储了函数类型的变量，这些函数负责将高级的 SSA 操作转换为更接近目标机器的底层操作。这些函数是架构特定的，因为不同架构支持的指令集和操作方式不同。

4. **管理寄存器信息:** `registers` 存储了目标架构的所有寄存器信息，包括通用寄存器、浮点寄存器和特殊寄存器。 `gpRegMask`, `fpRegMask`, `specialRegMask` 等字段是位掩码，用于快速判断寄存器的类型。 `intParamRegs`, `floatParamRegs` 存储了用于传递函数参数的寄存器编号。

5. **配置 ABI (Application Binary Interface):** `ABI0` 和 `ABI1` 字段存储了 ABI 配置信息，定义了函数调用约定，例如参数如何传递、返回值如何处理等。

6. **提供垃圾回收相关的寄存器映射:** `GCRegMap` 存储了垃圾回收器需要用到的寄存器映射信息。

7. **存储其他编译选项:**  `optimize`, `noDuffDevice`, `useSSE`, `SoftFloat`, `Race`, `UseFMA`, `unalignedOK` 等字段存储了各种编译优化选项和特性开关。

8. **提供与编译器其他部分的接口:**  `Logger` 和 `Frontend` 接口定义了 `ssa` 包与编译器前端以及日志记录功能的交互方式。

**推理 Go 语言功能的实现 (以指针大小为例):**

`Config` 结构体中的 `PtrSize` 字段直接影响着指针运算和内存访问。例如，在分配内存、计算结构体字段偏移量、以及进行指针类型转换时，都需要知道指针的大小。

**Go 代码示例:**

```go
package main

import (
	"fmt"
	"unsafe"
)

func main() {
	var i int
	var p *int = &i

	// unsafe.Sizeof 返回变量占用的大小，对于指针类型，其大小由 Config.PtrSize 决定
	pointerSize := unsafe.Sizeof(p)
	fmt.Printf("指针的大小: %d 字节\n", pointerSize)

	// 这段代码在不同的架构上运行，输出的指针大小会不同。
	// 在 64 位架构上，PtrSize 为 8，输出 "指针的大小: 8 字节"
	// 在 32 位架构上，PtrSize 为 4，输出 "指针的大小: 4 字节"
}
```

**假设的输入与输出:**

假设我们正在编译一段代码，目标架构是 `amd64`。在创建 `Config` 对象时，`arch` 参数会传入 `"amd64"`。

* **输入:** `arch = "amd64"`
* **输出 (部分):**
    * `c.PtrSize = 8`
    * `c.RegSize = 8`
    * `c.lowerBlock = rewriteBlockAMD64` (一个特定的函数)
    * `c.gpRegMask = gpRegMaskAMD64` (一个特定的寄存器掩码)

**命令行参数的具体处理:**

`NewConfig` 函数接收 `optimize` 和 `softfloat` 两个布尔类型的参数，这两个参数很可能对应于 `go build` 命令的命令行 flag：

* **`optimize` (对应 `-N` flag):** 当 `optimize` 为 `true` 时，表示启用代码优化。在 `go build` 命令中，不使用 `-N` flag 或者使用 `-l` flag 会启用优化。如果使用 `-N` flag，则 `optimize` 为 `false`。

* **`softfloat` (可能对应一些不常用的 build tag 或环境变量):** 当 `softfloat` 为 `true` 时，表示使用软件浮点运算。这在一些没有硬件浮点单元的平台上或者为了特定目的进行编译时使用。具体的命令行参数或环境变量可能需要查阅 Go 编译器的文档。

**使用者易犯错的点:**

由于 `config.go` 中的 `Config` 结构体是在编译器内部使用的，普通的 Go 开发者不会直接操作它。 因此，**使用者不易犯错**。  这里的“使用者”指的是使用 Go 语言进行开发的程序员。

然而，对于 **Go 编译器的开发者**来说，理解 `Config` 结构体的作用至关重要，并且在添加新的架构支持或者修改编译流程时，需要正确地更新和使用 `Config` 中的信息。 如果配置错误，会导致生成的机器码不正确或者编译器崩溃。

例如，如果错误地配置了 `PtrSize`，会导致指针运算错误，进而引发严重的运行时错误。又或者，如果 `lowerBlock` 或 `lowerValue` 函数实现有误，会导致生成的 SSA 代码无法正确转换为目标机器码。

总而言之，`go/src/cmd/compile/internal/ssa/config.go` 是 Go 语言编译器中 `ssa` 中间表示的核心配置文件，它包含了目标架构的各种关键信息以及编译选项，指导着 SSA 的转换和优化过程，最终生成正确的机器码。它主要服务于编译器内部，普通 Go 开发者无需直接与之交互。

### 提示词
```
这是路径为go/src/cmd/compile/internal/ssa/config.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
```

### 源代码
```go
// Copyright 2015 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ssa

import (
	"cmd/compile/internal/abi"
	"cmd/compile/internal/base"
	"cmd/compile/internal/ir"
	"cmd/compile/internal/types"
	"cmd/internal/obj"
	"cmd/internal/src"
	"internal/buildcfg"
)

// A Config holds readonly compilation information.
// It is created once, early during compilation,
// and shared across all compilations.
type Config struct {
	arch           string // "amd64", etc.
	PtrSize        int64  // 4 or 8; copy of cmd/internal/sys.Arch.PtrSize
	RegSize        int64  // 4 or 8; copy of cmd/internal/sys.Arch.RegSize
	Types          Types
	lowerBlock     blockRewriter  // block lowering function, first round
	lowerValue     valueRewriter  // value lowering function, first round
	lateLowerBlock blockRewriter  // block lowering function that needs to be run after the first round; only used on some architectures
	lateLowerValue valueRewriter  // value lowering function that needs to be run after the first round; only used on some architectures
	splitLoad      valueRewriter  // function for splitting merged load ops; only used on some architectures
	registers      []Register     // machine registers
	gpRegMask      regMask        // general purpose integer register mask
	fpRegMask      regMask        // floating point register mask
	fp32RegMask    regMask        // floating point register mask
	fp64RegMask    regMask        // floating point register mask
	specialRegMask regMask        // special register mask
	intParamRegs   []int8         // register numbers of integer param (in/out) registers
	floatParamRegs []int8         // register numbers of floating param (in/out) registers
	ABI1           *abi.ABIConfig // "ABIInternal" under development // TODO change comment when this becomes current
	ABI0           *abi.ABIConfig
	GCRegMap       []*Register // garbage collector register map, by GC register index
	FPReg          int8        // register number of frame pointer, -1 if not used
	LinkReg        int8        // register number of link register if it is a general purpose register, -1 if not used
	hasGReg        bool        // has hardware g register
	ctxt           *obj.Link   // Generic arch information
	optimize       bool        // Do optimization
	noDuffDevice   bool        // Don't use Duff's device
	useSSE         bool        // Use SSE for non-float operations
	useAvg         bool        // Use optimizations that need Avg* operations
	useHmul        bool        // Use optimizations that need Hmul* operations
	SoftFloat      bool        //
	Race           bool        // race detector enabled
	BigEndian      bool        //
	UseFMA         bool        // Use hardware FMA operation
	unalignedOK    bool        // Unaligned loads/stores are ok
	haveBswap64    bool        // architecture implements Bswap64
	haveBswap32    bool        // architecture implements Bswap32
	haveBswap16    bool        // architecture implements Bswap16
}

type (
	blockRewriter func(*Block) bool
	valueRewriter func(*Value) bool
)

type Types struct {
	Bool       *types.Type
	Int8       *types.Type
	Int16      *types.Type
	Int32      *types.Type
	Int64      *types.Type
	UInt8      *types.Type
	UInt16     *types.Type
	UInt32     *types.Type
	UInt64     *types.Type
	Int        *types.Type
	Float32    *types.Type
	Float64    *types.Type
	UInt       *types.Type
	Uintptr    *types.Type
	String     *types.Type
	BytePtr    *types.Type // TODO: use unsafe.Pointer instead?
	Int32Ptr   *types.Type
	UInt32Ptr  *types.Type
	IntPtr     *types.Type
	UintptrPtr *types.Type
	Float32Ptr *types.Type
	Float64Ptr *types.Type
	BytePtrPtr *types.Type
}

// NewTypes creates and populates a Types.
func NewTypes() *Types {
	t := new(Types)
	t.SetTypPtrs()
	return t
}

// SetTypPtrs populates t.
func (t *Types) SetTypPtrs() {
	t.Bool = types.Types[types.TBOOL]
	t.Int8 = types.Types[types.TINT8]
	t.Int16 = types.Types[types.TINT16]
	t.Int32 = types.Types[types.TINT32]
	t.Int64 = types.Types[types.TINT64]
	t.UInt8 = types.Types[types.TUINT8]
	t.UInt16 = types.Types[types.TUINT16]
	t.UInt32 = types.Types[types.TUINT32]
	t.UInt64 = types.Types[types.TUINT64]
	t.Int = types.Types[types.TINT]
	t.Float32 = types.Types[types.TFLOAT32]
	t.Float64 = types.Types[types.TFLOAT64]
	t.UInt = types.Types[types.TUINT]
	t.Uintptr = types.Types[types.TUINTPTR]
	t.String = types.Types[types.TSTRING]
	t.BytePtr = types.NewPtr(types.Types[types.TUINT8])
	t.Int32Ptr = types.NewPtr(types.Types[types.TINT32])
	t.UInt32Ptr = types.NewPtr(types.Types[types.TUINT32])
	t.IntPtr = types.NewPtr(types.Types[types.TINT])
	t.UintptrPtr = types.NewPtr(types.Types[types.TUINTPTR])
	t.Float32Ptr = types.NewPtr(types.Types[types.TFLOAT32])
	t.Float64Ptr = types.NewPtr(types.Types[types.TFLOAT64])
	t.BytePtrPtr = types.NewPtr(types.NewPtr(types.Types[types.TUINT8]))
}

type Logger interface {
	// Logf logs a message from the compiler.
	Logf(string, ...interface{})

	// Log reports whether logging is not a no-op
	// some logging calls account for more than a few heap allocations.
	Log() bool

	// Fatalf reports a compiler error and exits.
	Fatalf(pos src.XPos, msg string, args ...interface{})

	// Warnl writes compiler messages in the form expected by "errorcheck" tests
	Warnl(pos src.XPos, fmt_ string, args ...interface{})

	// Forwards the Debug flags from gc
	Debug_checknil() bool
}

type Frontend interface {
	Logger

	// StringData returns a symbol pointing to the given string's contents.
	StringData(string) *obj.LSym

	// Given the name for a compound type, returns the name we should use
	// for the parts of that compound type.
	SplitSlot(parent *LocalSlot, suffix string, offset int64, t *types.Type) LocalSlot

	// Syslook returns a symbol of the runtime function/variable with the
	// given name.
	Syslook(string) *obj.LSym

	// UseWriteBarrier reports whether write barrier is enabled
	UseWriteBarrier() bool

	// Func returns the ir.Func of the function being compiled.
	Func() *ir.Func
}

// NewConfig returns a new configuration object for the given architecture.
func NewConfig(arch string, types Types, ctxt *obj.Link, optimize, softfloat bool) *Config {
	c := &Config{arch: arch, Types: types}
	c.useAvg = true
	c.useHmul = true
	switch arch {
	case "amd64":
		c.PtrSize = 8
		c.RegSize = 8
		c.lowerBlock = rewriteBlockAMD64
		c.lowerValue = rewriteValueAMD64
		c.lateLowerBlock = rewriteBlockAMD64latelower
		c.lateLowerValue = rewriteValueAMD64latelower
		c.splitLoad = rewriteValueAMD64splitload
		c.registers = registersAMD64[:]
		c.gpRegMask = gpRegMaskAMD64
		c.fpRegMask = fpRegMaskAMD64
		c.specialRegMask = specialRegMaskAMD64
		c.intParamRegs = paramIntRegAMD64
		c.floatParamRegs = paramFloatRegAMD64
		c.FPReg = framepointerRegAMD64
		c.LinkReg = linkRegAMD64
		c.hasGReg = true
		c.unalignedOK = true
		c.haveBswap64 = true
		c.haveBswap32 = true
		c.haveBswap16 = true
	case "386":
		c.PtrSize = 4
		c.RegSize = 4
		c.lowerBlock = rewriteBlock386
		c.lowerValue = rewriteValue386
		c.splitLoad = rewriteValue386splitload
		c.registers = registers386[:]
		c.gpRegMask = gpRegMask386
		c.fpRegMask = fpRegMask386
		c.FPReg = framepointerReg386
		c.LinkReg = linkReg386
		c.hasGReg = false
		c.unalignedOK = true
		c.haveBswap32 = true
		c.haveBswap16 = true
	case "arm":
		c.PtrSize = 4
		c.RegSize = 4
		c.lowerBlock = rewriteBlockARM
		c.lowerValue = rewriteValueARM
		c.registers = registersARM[:]
		c.gpRegMask = gpRegMaskARM
		c.fpRegMask = fpRegMaskARM
		c.FPReg = framepointerRegARM
		c.LinkReg = linkRegARM
		c.hasGReg = true
	case "arm64":
		c.PtrSize = 8
		c.RegSize = 8
		c.lowerBlock = rewriteBlockARM64
		c.lowerValue = rewriteValueARM64
		c.lateLowerBlock = rewriteBlockARM64latelower
		c.lateLowerValue = rewriteValueARM64latelower
		c.registers = registersARM64[:]
		c.gpRegMask = gpRegMaskARM64
		c.fpRegMask = fpRegMaskARM64
		c.intParamRegs = paramIntRegARM64
		c.floatParamRegs = paramFloatRegARM64
		c.FPReg = framepointerRegARM64
		c.LinkReg = linkRegARM64
		c.hasGReg = true
		c.unalignedOK = true
		c.haveBswap64 = true
		c.haveBswap32 = true
		c.haveBswap16 = true
	case "ppc64":
		c.BigEndian = true
		fallthrough
	case "ppc64le":
		c.PtrSize = 8
		c.RegSize = 8
		c.lowerBlock = rewriteBlockPPC64
		c.lowerValue = rewriteValuePPC64
		c.lateLowerBlock = rewriteBlockPPC64latelower
		c.lateLowerValue = rewriteValuePPC64latelower
		c.registers = registersPPC64[:]
		c.gpRegMask = gpRegMaskPPC64
		c.fpRegMask = fpRegMaskPPC64
		c.specialRegMask = specialRegMaskPPC64
		c.intParamRegs = paramIntRegPPC64
		c.floatParamRegs = paramFloatRegPPC64
		c.FPReg = framepointerRegPPC64
		c.LinkReg = linkRegPPC64
		c.hasGReg = true
		c.unalignedOK = true
		// Note: ppc64 has register bswap ops only when GOPPC64>=10.
		// But it has bswap+load and bswap+store ops for all ppc64 variants.
		// That is the sense we're using them here - they are only used
		// in contexts where they can be merged with a load or store.
		c.haveBswap64 = true
		c.haveBswap32 = true
		c.haveBswap16 = true
	case "mips64":
		c.BigEndian = true
		fallthrough
	case "mips64le":
		c.PtrSize = 8
		c.RegSize = 8
		c.lowerBlock = rewriteBlockMIPS64
		c.lowerValue = rewriteValueMIPS64
		c.registers = registersMIPS64[:]
		c.gpRegMask = gpRegMaskMIPS64
		c.fpRegMask = fpRegMaskMIPS64
		c.specialRegMask = specialRegMaskMIPS64
		c.FPReg = framepointerRegMIPS64
		c.LinkReg = linkRegMIPS64
		c.hasGReg = true
	case "loong64":
		c.PtrSize = 8
		c.RegSize = 8
		c.lowerBlock = rewriteBlockLOONG64
		c.lowerValue = rewriteValueLOONG64
		c.registers = registersLOONG64[:]
		c.gpRegMask = gpRegMaskLOONG64
		c.fpRegMask = fpRegMaskLOONG64
		c.intParamRegs = paramIntRegLOONG64
		c.floatParamRegs = paramFloatRegLOONG64
		c.FPReg = framepointerRegLOONG64
		c.LinkReg = linkRegLOONG64
		c.hasGReg = true
	case "s390x":
		c.PtrSize = 8
		c.RegSize = 8
		c.lowerBlock = rewriteBlockS390X
		c.lowerValue = rewriteValueS390X
		c.registers = registersS390X[:]
		c.gpRegMask = gpRegMaskS390X
		c.fpRegMask = fpRegMaskS390X
		c.FPReg = framepointerRegS390X
		c.LinkReg = linkRegS390X
		c.hasGReg = true
		c.noDuffDevice = true
		c.BigEndian = true
		c.unalignedOK = true
		c.haveBswap64 = true
		c.haveBswap32 = true
		c.haveBswap16 = true // only for loads&stores, see ppc64 comment
	case "mips":
		c.BigEndian = true
		fallthrough
	case "mipsle":
		c.PtrSize = 4
		c.RegSize = 4
		c.lowerBlock = rewriteBlockMIPS
		c.lowerValue = rewriteValueMIPS
		c.registers = registersMIPS[:]
		c.gpRegMask = gpRegMaskMIPS
		c.fpRegMask = fpRegMaskMIPS
		c.specialRegMask = specialRegMaskMIPS
		c.FPReg = framepointerRegMIPS
		c.LinkReg = linkRegMIPS
		c.hasGReg = true
		c.noDuffDevice = true
	case "riscv64":
		c.PtrSize = 8
		c.RegSize = 8
		c.lowerBlock = rewriteBlockRISCV64
		c.lowerValue = rewriteValueRISCV64
		c.lateLowerBlock = rewriteBlockRISCV64latelower
		c.lateLowerValue = rewriteValueRISCV64latelower
		c.registers = registersRISCV64[:]
		c.gpRegMask = gpRegMaskRISCV64
		c.fpRegMask = fpRegMaskRISCV64
		c.intParamRegs = paramIntRegRISCV64
		c.floatParamRegs = paramFloatRegRISCV64
		c.FPReg = framepointerRegRISCV64
		c.hasGReg = true
	case "wasm":
		c.PtrSize = 8
		c.RegSize = 8
		c.lowerBlock = rewriteBlockWasm
		c.lowerValue = rewriteValueWasm
		c.registers = registersWasm[:]
		c.gpRegMask = gpRegMaskWasm
		c.fpRegMask = fpRegMaskWasm
		c.fp32RegMask = fp32RegMaskWasm
		c.fp64RegMask = fp64RegMaskWasm
		c.FPReg = framepointerRegWasm
		c.LinkReg = linkRegWasm
		c.hasGReg = true
		c.noDuffDevice = true
		c.useAvg = false
		c.useHmul = false
	default:
		ctxt.Diag("arch %s not implemented", arch)
	}
	c.ctxt = ctxt
	c.optimize = optimize
	c.useSSE = true
	c.UseFMA = true
	c.SoftFloat = softfloat
	if softfloat {
		c.floatParamRegs = nil // no FP registers in softfloat mode
	}

	c.ABI0 = abi.NewABIConfig(0, 0, ctxt.Arch.FixedFrameSize, 0)
	c.ABI1 = abi.NewABIConfig(len(c.intParamRegs), len(c.floatParamRegs), ctxt.Arch.FixedFrameSize, 1)

	// On Plan 9, floating point operations are not allowed in note handler.
	if buildcfg.GOOS == "plan9" {
		// Don't use FMA on Plan 9
		c.UseFMA = false

		// Don't use Duff's device and SSE on Plan 9 AMD64.
		if arch == "amd64" {
			c.noDuffDevice = true
			c.useSSE = false
		}
	}

	if ctxt.Flag_shared {
		// LoweredWB is secretly a CALL and CALLs on 386 in
		// shared mode get rewritten by obj6.go to go through
		// the GOT, which clobbers BX.
		opcodeTable[Op386LoweredWB].reg.clobbers |= 1 << 3 // BX
	}

	// Create the GC register map index.
	// TODO: This is only used for debug printing. Maybe export config.registers?
	gcRegMapSize := int16(0)
	for _, r := range c.registers {
		if r.gcNum+1 > gcRegMapSize {
			gcRegMapSize = r.gcNum + 1
		}
	}
	c.GCRegMap = make([]*Register, gcRegMapSize)
	for i, r := range c.registers {
		if r.gcNum != -1 {
			c.GCRegMap[r.gcNum] = &c.registers[i]
		}
	}

	return c
}

func (c *Config) Ctxt() *obj.Link { return c.ctxt }

func (c *Config) haveByteSwap(size int64) bool {
	switch size {
	case 8:
		return c.haveBswap64
	case 4:
		return c.haveBswap32
	case 2:
		return c.haveBswap16
	default:
		base.Fatalf("bad size %d\n", size)
		return false
	}
}
```