Response: Let's break down the thought process for analyzing the provided Go code.

1. **Understand the Goal:** The request asks for the functionality of the `abiutils.go` file, specifically within the context of the Go compiler (`cmd/compile`). It also probes for practical implications, usage examples, potential pitfalls, and connections to Go language features.

2. **Initial Scan and Structure Recognition:**  The first step is to skim the code and identify the major components:
    * **Package Declaration:** `package abi` immediately tells us this code is about Application Binary Interface (ABI) concerns.
    * **Imports:**  The imports (`cmd/compile/internal/...`, `cmd/internal/...`, standard library) confirm this is compiler-related code and deals with type information, intermediate representation, and architecture specifics.
    * **Key Data Structures:** The presence of `ABIParamResultInfo`, `RegIndex`, `ABIParamAssignment`, `RegAmounts`, and `ABIConfig` strongly suggests this code is involved in determining how function parameters and return values are handled at a low level.
    * **Functions:**  Functions like `ABIAnalyzeTypes`, `ABIAnalyzeFuncType`, `ABIAnalyze`, `FrameOffset`, `ComputePadding`, and helper functions like `align`, `alignTo`, `nextSlot`, `allocateRegs`, `setup` reveal the core logic.

3. **Focus on Core Functionality - `ABIParamResultInfo` and the `ABIAnalyze*` Functions:** The central data structure appears to be `ABIParamResultInfo`. Its fields (`inparams`, `outparams`, `offsetToSpillArea`, etc.) clearly relate to parameter passing mechanisms. The `ABIAnalyzeTypes` and `ABIAnalyzeFuncType` functions are likely the entry points for analyzing function signatures.

4. **Deduce the Purpose of Key Structures:**
    * `ABIParamResultInfo`: Stores the outcome of ABI analysis for a function (parameter locations, register assignments, stack layout).
    * `ABIParamAssignment`: Represents how a single parameter or result is passed (registers or stack, with offset or register index).
    * `ABIConfig`: Holds ABI-specific configuration like the number of available registers.
    * `RegIndex`:  An index into the register set used for parameter passing.

5. **Trace the Flow of Analysis:** The `ABIAnalyze*` functions seem to take a function type and an `ABIConfig` as input. They use an `assignState` struct to keep track of the current allocation state (used registers, stack offset). The `assignParam` function decides whether a parameter goes into a register or onto the stack. `tryAllocRegs` and `allocateRegs` handle the register allocation logic.

6. **Identify Key Concepts:**  Several important concepts emerge:
    * **Register Allocation:**  The code determines which parameters can be passed in registers for efficiency.
    * **Stack Allocation:** Parameters that don't fit in registers are placed on the stack.
    * **Spill Area:**  A region on the stack to save register values temporarily (e.g., for function calls).
    * **Frame Offset:** The offset from the frame pointer to access a parameter on the stack.
    * **ABI Configuration:** Architecture-specific rules for parameter passing.

7. **Connect to Go Language Features:**  The functionality directly relates to:
    * **Function Calls:** How arguments are passed to and results are returned from functions.
    * **Method Calls:** The receiver is treated as an input parameter.
    * **Interfaces, Slices, Strings:** These are handled specially during ABI analysis, often involving passing pointers and lengths.
    * **Compiler Optimization:** Register allocation is a crucial optimization.
    * **Runtime Interaction:**  The spill area is relevant for `morestack` and stack growth.

8. **Construct Usage Examples:**  Based on the identified functionality, create simple Go code examples to illustrate:
    * Passing simple types (int, bool) and observing potential register allocation.
    * Passing structs and observing how they might be split between registers and stack.
    * The concept of input and output parameters.

9. **Infer Potential Pitfalls:**  Think about what could go wrong or be misunderstood:
    * **Assuming Register Allocation:** Developers might incorrectly assume a parameter is always in a register.
    * **Ignoring Stack Layout:** Not understanding the stack layout can lead to debugging difficulties.
    * **ABI Variations:**  The ABI can change between Go versions or architectures.

10. **Address Specific Questions:**  Go back to the original request and ensure all parts are covered:
    * **Functionality Listing:**  Summarize the core functions.
    * **Go Feature Implementation:** Explain the connection to function calls, etc. with code examples.
    * **Code Reasoning:**  Explain the logic of register and stack allocation.
    * **Command-Line Arguments:** Recognize that this code *itself* doesn't directly process command-line arguments but is *used by* the compiler, which *does*.
    * **Common Mistakes:**  Provide concrete examples of potential developer errors.

11. **Refine and Organize:** Structure the answer logically with clear headings and explanations. Use code blocks for examples and present information in a digestible manner. Ensure accuracy and clarity. For example, when discussing command-line arguments, clarify the distinction between the `abiutils.go` code and the compiler's overall command-line handling.

This iterative process of scanning, deducing, connecting, and exemplifying helps to thoroughly analyze and explain the functionality of the given Go code snippet.
这段代码是 Go 编译器 `cmd/compile` 中 `abiutils.go` 文件的一部分，它主要负责 **分析 Go 函数的参数和返回值，并根据目标架构的 ABI（Application Binary Interface）规则，确定它们是如何传递的：通过寄存器还是通过栈。**

更具体地说，它实现了以下功能：

**1. 描述函数参数和返回值的布局：**

*   **`ABIParamResultInfo` 结构体:**  存储了对函数参数和返回值进行 ABI 分析后的结果。它包含了：
    *   `inparams`:  输入参数的 `ABIParamAssignment` 列表。
    *   `outparams`: 输出参数的 `ABIParamAssignment` 列表。
    *   `offsetToSpillArea`:  栈上用于存放被分配到寄存器但需要溢出（spill）的参数的区域的偏移量。
    *   `spillAreaSize`:  溢出区域的大小。
    *   `inRegistersUsed`:  用于输入参数的寄存器数量。
    *   `outRegistersUsed`: 用于输出参数的寄存器数量。
    *   `config`: 指向 `ABIConfig` 的指针，包含了目标架构的 ABI 配置信息。
*   **`ABIParamAssignment` 结构体:**  描述了单个参数或返回值的传递方式：
    *   `Type`: 参数或返回值的类型。
    *   `Name`: 参数或返回值的名称（可能为空）。
    *   `Registers`:  如果参数通过寄存器传递，则存储分配的寄存器索引列表。
    *   `offset`: 如果参数通过栈传递，则存储其在栈上的偏移量。

**2. ABI 分析的核心功能：**

*   **`ABIConfig` 结构体:**  存储了目标架构的 ABI 配置信息，例如用于参数传递的整数寄存器和浮点寄存器的数量。
*   **`NewABIConfig` 函数:**  创建一个新的 `ABIConfig` 实例。
*   **`ABIAnalyzeTypes` 函数:**  根据给定的参数和返回值类型切片以及 ABI 配置，分析参数和返回值的传递方式。这个函数主要用于处理没有具体函数类型的运行时函数。
*   **`ABIAnalyzeFuncType` 函数:**  接收一个函数类型 `types.Type` 和 ABI 配置，分析该函数的参数和返回值的传递方式。
*   **`ABIAnalyze` 函数:**  与 `ABIAnalyzeFuncType` 类似，但还会更新函数参数和返回值的 `types.Field` 中的偏移量信息，用于后续的代码生成。

**3. 辅助功能：**

*   **`RegIndex` 类型:**  表示寄存器索引，用于区分整数寄存器和浮点寄存器。
*   **`RegAmounts` 结构体:**  存储整数寄存器和浮点寄存器的数量。
*   **`FrameOffset` 方法:**  返回参数在栈帧中的偏移量（用于栈分配的参数）或溢出区域的偏移量（用于寄存器分配的参数）。
*   **`RegisterTypes` 函数:**  返回一个参数列表中所有通过寄存器传递的参数的类型切片。
*   **`appendParamTypes` 和 `appendParamOffsets` 函数:**  递归地处理复合类型（如结构体、数组），将其拆解为可以通过寄存器传递的标量类型，并计算相应的偏移量。
*   **`align` 和 `alignTo` 函数:**  用于内存对齐。
*   **`nextSlot` 函数:**  在栈上分配下一个可用的槽位。
*   **`tryAllocRegs` 和 `allocateRegs` 函数:**  尝试为参数分配寄存器。
*   **`ComputePadding` 方法:**  计算结构体在寄存器传递时，字段之间的填充字节数。

**推理它是什么 Go 语言功能的实现:**

这段代码是 **Go 函数调用约定（calling convention）** 的实现基础。它决定了当一个 Go 函数被调用时，参数和返回值如何有效地在调用者和被调用者之间传递。这直接影响了：

*   **代码效率:** 使用寄存器传递参数通常比使用栈传递更快。
*   **栈帧布局:**  编译器需要知道参数和返回值在栈上的位置，以便进行内存访问。
*   **与其他语言的互操作性 (Cgo):**  Go 的 ABI 需要与 C 的 ABI 保持一定的兼容性。

**Go 代码举例说明:**

```go
package main

func add(a int, b int) int {
	return a + b
}

type Point struct {
	X int
	Y int
}

func getPoint() Point {
	return Point{X: 1, Y: 2}
}

func main() {
	add(1, 2)
	getPoint()
}
```

当 Go 编译器编译 `add` 和 `getPoint` 函数时，`abiutils.go` 中的代码会被用来分析这两个函数的参数和返回值。

**假设的输入与输出 (以 `add` 函数为例，假设目标架构有足够的寄存器):**

**输入 (对于 `add` 函数):**

*   函数类型: `func(int, int) int`
*   目标架构的 `ABIConfig`:  假设配置了例如 6 个用于整数的寄存器。

**输出 (`ABIParamResultInfo`):**

```
&abi.ABIParamResultInfo{
    inparams: []abi.ABIParamAssignment{
        {Type: int, Name: "a", Registers: []abi.RegIndex{0}, offset: -1}, // 假设 'a' 分配到寄存器 0
        {Type: int, Name: "b", Registers: []abi.RegIndex{1}, offset: -1}, // 假设 'b' 分配到寄存器 1
    },
    outparams: []abi.ABIParamAssignment{
        {Type: int, Name: "", Registers: []abi.RegIndex{2}, offset: -1},  // 假设返回值分配到寄存器 2
    },
    offsetToSpillArea: 架构相关,
    spillAreaSize: 架构相关,
    inRegistersUsed: 2,
    outRegistersUsed: 1,
    config: *abi.ABIConfig{...},
}
```

**对于 `getPoint` 函数，如果 `Point` 结构体足够小，可能会尝试使用多个寄存器传递，如果太大，则可能通过栈传递。**

**命令行参数的具体处理:**

`abiutils.go` 本身 **不直接处理命令行参数**。 它的功能是被 Go 编译器 `cmd/compile` 调用，而 `cmd/compile` 会处理各种编译选项，例如 `-arch` (目标架构)。 `cmd/compile` 会根据 `-arch` 的值来选择合适的 ABI 配置，并使用 `abiutils.go` 中的函数进行参数和返回值的分析。

**例如，编译针对 `amd64` 架构的代码：**

```bash
go tool compile -arch=amd64 myprogram.go
```

在这种情况下，`cmd/compile` 会加载 `amd64` 架构的 ABI 配置，并将其传递给 `abiutils.go` 中的函数。

**使用者易犯错的点 (开发者通常不会直接使用 `abiutils.go`):**

虽然开发者通常不会直接与 `abiutils.go` 交互，但理解其背后的原理可以避免一些误解：

*   **错误地假设参数总是通过寄存器传递：**  参数是否通过寄存器传递取决于类型大小、ABI 规则和可用的寄存器数量。大型结构体或数组通常会通过栈传递。
*   **忽略了 ABI 差异：**  不同的架构有不同的 ABI 规则，例如寄存器的数量和使用约定。跨平台编译时，需要考虑到这些差异。

**举例说明 (虽然不是直接的代码错误，但属于理解上的偏差):**

假设开发者认为一个包含 10 个 `int` 字段的结构体在函数调用时总是会被放入 10 个寄存器传递。但实际上，根据目标架构的 ABI 规则，很可能这个结构体会被整体放入栈中传递，或者拆分成几个部分分别用寄存器和栈传递。开发者如果基于错误的假设进行性能分析或底层编程，可能会遇到困惑。

总结来说，`abiutils.go` 是 Go 编译器中一个至关重要的组成部分，它负责理解和实现不同架构下的函数调用约定，为生成高效、正确的机器码奠定了基础。 开发者虽然不直接使用它，但了解其功能有助于更深入地理解 Go 语言的底层机制。

Prompt: 
```
这是路径为go/src/cmd/compile/internal/abi/abiutils.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，

"""
// Copyright 2020 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package abi

import (
	"cmd/compile/internal/base"
	"cmd/compile/internal/ir"
	"cmd/compile/internal/types"
	"cmd/internal/obj"
	"cmd/internal/src"
	"fmt"
	"math"
	"sync"
)

//......................................................................
//
// Public/exported bits of the ABI utilities.
//

// ABIParamResultInfo stores the results of processing a given
// function type to compute stack layout and register assignments. For
// each input and output parameter we capture whether the param was
// register-assigned (and to which register(s)) or the stack offset
// for the param if is not going to be passed in registers according
// to the rules in the Go internal ABI specification (1.17).
type ABIParamResultInfo struct {
	inparams          []ABIParamAssignment // Includes receiver for method calls.  Does NOT include hidden closure pointer.
	outparams         []ABIParamAssignment
	offsetToSpillArea int64
	spillAreaSize     int64
	inRegistersUsed   int
	outRegistersUsed  int
	config            *ABIConfig // to enable String() method
}

func (a *ABIParamResultInfo) Config() *ABIConfig {
	return a.config
}

func (a *ABIParamResultInfo) InParams() []ABIParamAssignment {
	return a.inparams
}

func (a *ABIParamResultInfo) OutParams() []ABIParamAssignment {
	return a.outparams
}

func (a *ABIParamResultInfo) InRegistersUsed() int {
	return a.inRegistersUsed
}

func (a *ABIParamResultInfo) OutRegistersUsed() int {
	return a.outRegistersUsed
}

func (a *ABIParamResultInfo) InParam(i int) *ABIParamAssignment {
	return &a.inparams[i]
}

func (a *ABIParamResultInfo) OutParam(i int) *ABIParamAssignment {
	return &a.outparams[i]
}

func (a *ABIParamResultInfo) SpillAreaOffset() int64 {
	return a.offsetToSpillArea
}

func (a *ABIParamResultInfo) SpillAreaSize() int64 {
	return a.spillAreaSize
}

// ArgWidth returns the amount of stack needed for all the inputs
// and outputs of a function or method, including ABI-defined parameter
// slots and ABI-defined spill slots for register-resident parameters.
// The name is inherited from (*Type).ArgWidth(), which it replaces.
func (a *ABIParamResultInfo) ArgWidth() int64 {
	return a.spillAreaSize + a.offsetToSpillArea - a.config.LocalsOffset()
}

// RegIndex stores the index into the set of machine registers used by
// the ABI on a specific architecture for parameter passing.  RegIndex
// values 0 through N-1 (where N is the number of integer registers
// used for param passing according to the ABI rules) describe integer
// registers; values N through M (where M is the number of floating
// point registers used).  Thus if the ABI says there are 5 integer
// registers and 7 floating point registers, then RegIndex value of 4
// indicates the 5th integer register, and a RegIndex value of 11
// indicates the 7th floating point register.
type RegIndex uint8

// ABIParamAssignment holds information about how a specific param or
// result will be passed: in registers (in which case 'Registers' is
// populated) or on the stack (in which case 'Offset' is set to a
// non-negative stack offset). The values in 'Registers' are indices
// (as described above), not architected registers.
type ABIParamAssignment struct {
	Type      *types.Type
	Name      *ir.Name
	Registers []RegIndex
	offset    int32
}

// Offset returns the stack offset for addressing the parameter that "a" describes.
// This will panic if "a" describes a register-allocated parameter.
func (a *ABIParamAssignment) Offset() int32 {
	if len(a.Registers) > 0 {
		base.Fatalf("register allocated parameters have no offset")
	}
	return a.offset
}

// RegisterTypes returns a slice of the types of the registers
// corresponding to a slice of parameters.  The returned slice
// has capacity for one more, likely a memory type.
func RegisterTypes(apa []ABIParamAssignment) []*types.Type {
	rcount := 0
	for _, pa := range apa {
		rcount += len(pa.Registers)
	}
	if rcount == 0 {
		// Note that this catches top-level struct{} and [0]Foo, which are stack allocated.
		return make([]*types.Type, 0, 1)
	}
	rts := make([]*types.Type, 0, rcount+1)
	for _, pa := range apa {
		if len(pa.Registers) == 0 {
			continue
		}
		rts = appendParamTypes(rts, pa.Type)
	}
	return rts
}

func (pa *ABIParamAssignment) RegisterTypesAndOffsets() ([]*types.Type, []int64) {
	l := len(pa.Registers)
	if l == 0 {
		return nil, nil
	}
	typs := make([]*types.Type, 0, l)
	offs := make([]int64, 0, l)
	offs, _ = appendParamOffsets(offs, 0, pa.Type) // 0 is aligned for everything.
	return appendParamTypes(typs, pa.Type), offs
}

func appendParamTypes(rts []*types.Type, t *types.Type) []*types.Type {
	w := t.Size()
	if w == 0 {
		return rts
	}
	if t.IsScalar() || t.IsPtrShaped() {
		if t.IsComplex() {
			c := types.FloatForComplex(t)
			return append(rts, c, c)
		} else {
			if int(t.Size()) <= types.RegSize {
				return append(rts, t)
			}
			// assume 64bit int on 32-bit machine
			// TODO endianness? Should high-order (sign bits) word come first?
			if t.IsSigned() {
				rts = append(rts, types.Types[types.TINT32])
			} else {
				rts = append(rts, types.Types[types.TUINT32])
			}
			return append(rts, types.Types[types.TUINT32])
		}
	} else {
		typ := t.Kind()
		switch typ {
		case types.TARRAY:
			for i := int64(0); i < t.NumElem(); i++ { // 0 gets no registers, plus future-proofing.
				rts = appendParamTypes(rts, t.Elem())
			}
		case types.TSTRUCT:
			for _, f := range t.Fields() {
				if f.Type.Size() > 0 { // embedded zero-width types receive no registers
					rts = appendParamTypes(rts, f.Type)
				}
			}
		case types.TSLICE:
			return appendParamTypes(rts, synthSlice)
		case types.TSTRING:
			return appendParamTypes(rts, synthString)
		case types.TINTER:
			return appendParamTypes(rts, synthIface)
		}
	}
	return rts
}

// appendParamOffsets appends the offset(s) of type t, starting from "at",
// to input offsets, and returns the longer slice and the next unused offset.
// at should already be aligned for t.
func appendParamOffsets(offsets []int64, at int64, t *types.Type) ([]int64, int64) {
	w := t.Size()
	if w == 0 {
		return offsets, at
	}
	if t.IsScalar() || t.IsPtrShaped() {
		if t.IsComplex() || int(t.Size()) > types.RegSize { // complex and *int64 on 32-bit
			s := w / 2
			return append(offsets, at, at+s), at + w
		} else {
			return append(offsets, at), at + w
		}
	} else {
		typ := t.Kind()
		switch typ {
		case types.TARRAY:
			te := t.Elem()
			for i := int64(0); i < t.NumElem(); i++ {
				at = align(at, te)
				offsets, at = appendParamOffsets(offsets, at, te)
			}
		case types.TSTRUCT:
			at0 := at
			for i, f := range t.Fields() {
				at = at0 + f.Offset // Fields may be over-aligned, see wasm32.
				offsets, at = appendParamOffsets(offsets, at, f.Type)
				if f.Type.Size() == 0 && i == t.NumFields()-1 {
					at++ // last field has zero width
				}
			}
			at = align(at, t) // type size is rounded up to its alignment
		case types.TSLICE:
			return appendParamOffsets(offsets, at, synthSlice)
		case types.TSTRING:
			return appendParamOffsets(offsets, at, synthString)
		case types.TINTER:
			return appendParamOffsets(offsets, at, synthIface)
		}
	}
	return offsets, at
}

// FrameOffset returns the frame-pointer-relative location that a function
// would spill its input or output parameter to, if such a spill slot exists.
// If there is none defined (e.g., register-allocated outputs) it panics.
// For register-allocated inputs that is their spill offset reserved for morestack;
// for stack-allocated inputs and outputs, that is their location on the stack.
// (In a future version of the ABI, register-resident inputs may lose their defined
// spill area to help reduce stack sizes.)
func (a *ABIParamAssignment) FrameOffset(i *ABIParamResultInfo) int64 {
	if a.offset == -1 {
		base.Fatalf("function parameter has no ABI-defined frame-pointer offset")
	}
	if len(a.Registers) == 0 { // passed on stack
		return int64(a.offset) - i.config.LocalsOffset()
	}
	// spill area for registers
	return int64(a.offset) + i.SpillAreaOffset() - i.config.LocalsOffset()
}

// RegAmounts holds a specified number of integer/float registers.
type RegAmounts struct {
	intRegs   int
	floatRegs int
}

// ABIConfig captures the number of registers made available
// by the ABI rules for parameter passing and result returning.
type ABIConfig struct {
	// Do we need anything more than this?
	offsetForLocals int64 // e.g., obj.(*Link).Arch.FixedFrameSize -- extra linkage information on some architectures.
	regAmounts      RegAmounts
	which           obj.ABI
}

// NewABIConfig returns a new ABI configuration for an architecture with
// iRegsCount integer/pointer registers and fRegsCount floating point registers.
func NewABIConfig(iRegsCount, fRegsCount int, offsetForLocals int64, which uint8) *ABIConfig {
	return &ABIConfig{offsetForLocals: offsetForLocals, regAmounts: RegAmounts{iRegsCount, fRegsCount}, which: obj.ABI(which)}
}

// Copy returns config.
//
// TODO(mdempsky): Remove.
func (config *ABIConfig) Copy() *ABIConfig {
	return config
}

// Which returns the ABI number
func (config *ABIConfig) Which() obj.ABI {
	return config.which
}

// LocalsOffset returns the architecture-dependent offset from SP for args and results.
// In theory this is only used for debugging; it ought to already be incorporated into
// results from the ABI-related methods
func (config *ABIConfig) LocalsOffset() int64 {
	return config.offsetForLocals
}

// FloatIndexFor translates r into an index in the floating point parameter
// registers.  If the result is negative, the input index was actually for the
// integer parameter registers.
func (config *ABIConfig) FloatIndexFor(r RegIndex) int64 {
	return int64(r) - int64(config.regAmounts.intRegs)
}

// NumParamRegs returns the total number of registers used to
// represent a parameter of the given type, which must be register
// assignable.
func (config *ABIConfig) NumParamRegs(typ *types.Type) int {
	intRegs, floatRegs := typ.Registers()
	if intRegs == math.MaxUint8 && floatRegs == math.MaxUint8 {
		base.Fatalf("cannot represent parameters of type %v in registers", typ)
	}
	return int(intRegs) + int(floatRegs)
}

// ABIAnalyzeTypes takes slices of parameter and result types, and returns an ABIParamResultInfo,
// based on the given configuration.  This is the same result computed by config.ABIAnalyze applied to the
// corresponding method/function type, except that all the embedded parameter names are nil.
// This is intended for use by ssagen/ssa.go:(*state).rtcall, for runtime functions that lack a parsed function type.
func (config *ABIConfig) ABIAnalyzeTypes(params, results []*types.Type) *ABIParamResultInfo {
	setup()
	s := assignState{
		stackOffset: config.offsetForLocals,
		rTotal:      config.regAmounts,
	}

	assignParams := func(params []*types.Type, isResult bool) []ABIParamAssignment {
		res := make([]ABIParamAssignment, len(params))
		for i, param := range params {
			res[i] = s.assignParam(param, nil, isResult)
		}
		return res
	}

	info := &ABIParamResultInfo{config: config}

	// Inputs
	info.inparams = assignParams(params, false)
	s.stackOffset = types.RoundUp(s.stackOffset, int64(types.RegSize))
	info.inRegistersUsed = s.rUsed.intRegs + s.rUsed.floatRegs

	// Outputs
	s.rUsed = RegAmounts{}
	info.outparams = assignParams(results, true)
	// The spill area is at a register-aligned offset and its size is rounded up to a register alignment.
	// TODO in theory could align offset only to minimum required by spilled data types.
	info.offsetToSpillArea = alignTo(s.stackOffset, types.RegSize)
	info.spillAreaSize = alignTo(s.spillOffset, types.RegSize)
	info.outRegistersUsed = s.rUsed.intRegs + s.rUsed.floatRegs

	return info
}

// ABIAnalyzeFuncType takes a function type 'ft' and an ABI rules description
// 'config' and analyzes the function to determine how its parameters
// and results will be passed (in registers or on the stack), returning
// an ABIParamResultInfo object that holds the results of the analysis.
func (config *ABIConfig) ABIAnalyzeFuncType(ft *types.Type) *ABIParamResultInfo {
	setup()
	s := assignState{
		stackOffset: config.offsetForLocals,
		rTotal:      config.regAmounts,
	}

	assignParams := func(params []*types.Field, isResult bool) []ABIParamAssignment {
		res := make([]ABIParamAssignment, len(params))
		for i, param := range params {
			var name *ir.Name
			if param.Nname != nil {
				name = param.Nname.(*ir.Name)
			}
			res[i] = s.assignParam(param.Type, name, isResult)
		}
		return res
	}

	info := &ABIParamResultInfo{config: config}

	// Inputs
	info.inparams = assignParams(ft.RecvParams(), false)
	s.stackOffset = types.RoundUp(s.stackOffset, int64(types.RegSize))
	info.inRegistersUsed = s.rUsed.intRegs + s.rUsed.floatRegs

	// Outputs
	s.rUsed = RegAmounts{}
	info.outparams = assignParams(ft.Results(), true)
	// The spill area is at a register-aligned offset and its size is rounded up to a register alignment.
	// TODO in theory could align offset only to minimum required by spilled data types.
	info.offsetToSpillArea = alignTo(s.stackOffset, types.RegSize)
	info.spillAreaSize = alignTo(s.spillOffset, types.RegSize)
	info.outRegistersUsed = s.rUsed.intRegs + s.rUsed.floatRegs
	return info
}

// ABIAnalyze returns the same result as ABIAnalyzeFuncType, but also
// updates the offsets of all the receiver, input, and output fields.
// If setNname is true, it also sets the FrameOffset of the Nname for
// the field(s); this is for use when compiling a function and figuring out
// spill locations.  Doing this for callers can cause races for register
// outputs because their frame location transitions from BOGUS_FUNARG_OFFSET
// to zero to an as-if-AUTO offset that has no use for callers.
func (config *ABIConfig) ABIAnalyze(t *types.Type, setNname bool) *ABIParamResultInfo {
	result := config.ABIAnalyzeFuncType(t)

	// Fill in the frame offsets for receiver, inputs, results
	for i, f := range t.RecvParams() {
		config.updateOffset(result, f, result.inparams[i], false, setNname)
	}
	for i, f := range t.Results() {
		config.updateOffset(result, f, result.outparams[i], true, setNname)
	}
	return result
}

func (config *ABIConfig) updateOffset(result *ABIParamResultInfo, f *types.Field, a ABIParamAssignment, isResult, setNname bool) {
	if f.Offset != types.BADWIDTH {
		base.Fatalf("field offset for %s at %s has been set to %d", f.Sym, base.FmtPos(f.Pos), f.Offset)
	}

	// Everything except return values in registers has either a frame home (if not in a register) or a frame spill location.
	if !isResult || len(a.Registers) == 0 {
		// The type frame offset DOES NOT show effects of minimum frame size.
		// Getting this wrong breaks stackmaps, see liveness/plive.go:WriteFuncMap and typebits/typebits.go:Set
		off := a.FrameOffset(result)
		if setNname && f.Nname != nil {
			f.Nname.(*ir.Name).SetFrameOffset(off)
			f.Nname.(*ir.Name).SetIsOutputParamInRegisters(false)
		}
	} else {
		if setNname && f.Nname != nil {
			fname := f.Nname.(*ir.Name)
			fname.SetIsOutputParamInRegisters(true)
			fname.SetFrameOffset(0)
		}
	}
}

//......................................................................
//
// Non-public portions.

// regString produces a human-readable version of a RegIndex.
func (c *RegAmounts) regString(r RegIndex) string {
	if int(r) < c.intRegs {
		return fmt.Sprintf("I%d", int(r))
	} else if int(r) < c.intRegs+c.floatRegs {
		return fmt.Sprintf("F%d", int(r)-c.intRegs)
	}
	return fmt.Sprintf("<?>%d", r)
}

// ToString method renders an ABIParamAssignment in human-readable
// form, suitable for debugging or unit testing.
func (ri *ABIParamAssignment) ToString(config *ABIConfig, extra bool) string {
	regs := "R{"
	offname := "spilloffset" // offset is for spill for register(s)
	if len(ri.Registers) == 0 {
		offname = "offset" // offset is for memory arg
	}
	for _, r := range ri.Registers {
		regs += " " + config.regAmounts.regString(r)
		if extra {
			regs += fmt.Sprintf("(%d)", r)
		}
	}
	if extra {
		regs += fmt.Sprintf(" | #I=%d, #F=%d", config.regAmounts.intRegs, config.regAmounts.floatRegs)
	}
	return fmt.Sprintf("%s } %s: %d typ: %v", regs, offname, ri.offset, ri.Type)
}

// String method renders an ABIParamResultInfo in human-readable
// form, suitable for debugging or unit testing.
func (ri *ABIParamResultInfo) String() string {
	res := ""
	for k, p := range ri.inparams {
		res += fmt.Sprintf("IN %d: %s\n", k, p.ToString(ri.config, false))
	}
	for k, r := range ri.outparams {
		res += fmt.Sprintf("OUT %d: %s\n", k, r.ToString(ri.config, false))
	}
	res += fmt.Sprintf("offsetToSpillArea: %d spillAreaSize: %d",
		ri.offsetToSpillArea, ri.spillAreaSize)
	return res
}

// assignState holds intermediate state during the register assigning process
// for a given function signature.
type assignState struct {
	rTotal      RegAmounts // total reg amounts from ABI rules
	rUsed       RegAmounts // regs used by params completely assigned so far
	stackOffset int64      // current stack offset
	spillOffset int64      // current spill offset
}

// align returns a rounded up to t's alignment.
func align(a int64, t *types.Type) int64 {
	return alignTo(a, int(uint8(t.Alignment())))
}

// alignTo returns a rounded up to t, where t must be 0 or a power of 2.
func alignTo(a int64, t int) int64 {
	if t == 0 {
		return a
	}
	return types.RoundUp(a, int64(t))
}

// nextSlot allocates the next available slot for typ.
func nextSlot(offsetp *int64, typ *types.Type) int64 {
	offset := align(*offsetp, typ)
	*offsetp = offset + typ.Size()
	return offset
}

// allocateRegs returns an ordered list of register indices for a parameter or result
// that we've just determined to be register-assignable. The number of registers
// needed is assumed to be stored in state.pUsed.
func (state *assignState) allocateRegs(regs []RegIndex, t *types.Type) []RegIndex {
	if t.Size() == 0 {
		return regs
	}
	ri := state.rUsed.intRegs
	rf := state.rUsed.floatRegs
	if t.IsScalar() || t.IsPtrShaped() {
		if t.IsComplex() {
			regs = append(regs, RegIndex(rf+state.rTotal.intRegs), RegIndex(rf+1+state.rTotal.intRegs))
			rf += 2
		} else if t.IsFloat() {
			regs = append(regs, RegIndex(rf+state.rTotal.intRegs))
			rf += 1
		} else {
			n := (int(t.Size()) + types.RegSize - 1) / types.RegSize
			for i := 0; i < n; i++ { // looking ahead to really big integers
				regs = append(regs, RegIndex(ri))
				ri += 1
			}
		}
		state.rUsed.intRegs = ri
		state.rUsed.floatRegs = rf
		return regs
	} else {
		typ := t.Kind()
		switch typ {
		case types.TARRAY:
			for i := int64(0); i < t.NumElem(); i++ {
				regs = state.allocateRegs(regs, t.Elem())
			}
			return regs
		case types.TSTRUCT:
			for _, f := range t.Fields() {
				regs = state.allocateRegs(regs, f.Type)
			}
			return regs
		case types.TSLICE:
			return state.allocateRegs(regs, synthSlice)
		case types.TSTRING:
			return state.allocateRegs(regs, synthString)
		case types.TINTER:
			return state.allocateRegs(regs, synthIface)
		}
	}
	base.Fatalf("was not expecting type %s", t)
	panic("unreachable")
}

// synthOnce ensures that we only create the synth* fake types once.
var synthOnce sync.Once

// synthSlice, synthString, and syncIface are synthesized struct types
// meant to capture the underlying implementations of string/slice/interface.
var synthSlice *types.Type
var synthString *types.Type
var synthIface *types.Type

// setup performs setup for the register assignment utilities, manufacturing
// a small set of synthesized types that we'll need along the way.
func setup() {
	synthOnce.Do(func() {
		fname := types.BuiltinPkg.Lookup
		nxp := src.NoXPos
		bp := types.NewPtr(types.Types[types.TUINT8])
		it := types.Types[types.TINT]
		synthSlice = types.NewStruct([]*types.Field{
			types.NewField(nxp, fname("ptr"), bp),
			types.NewField(nxp, fname("len"), it),
			types.NewField(nxp, fname("cap"), it),
		})
		types.CalcStructSize(synthSlice)
		synthString = types.NewStruct([]*types.Field{
			types.NewField(nxp, fname("data"), bp),
			types.NewField(nxp, fname("len"), it),
		})
		types.CalcStructSize(synthString)
		unsp := types.Types[types.TUNSAFEPTR]
		synthIface = types.NewStruct([]*types.Field{
			types.NewField(nxp, fname("f1"), unsp),
			types.NewField(nxp, fname("f2"), unsp),
		})
		types.CalcStructSize(synthIface)
	})
}

// assignParam processes a given receiver, param, or result
// of field f to determine whether it can be register assigned.
// The result of the analysis is recorded in the result
// ABIParamResultInfo held in 'state'.
func (state *assignState) assignParam(typ *types.Type, name *ir.Name, isResult bool) ABIParamAssignment {
	registers := state.tryAllocRegs(typ)

	var offset int64 = -1
	if registers == nil { // stack allocated; needs stack slot
		offset = nextSlot(&state.stackOffset, typ)
	} else if !isResult { // register-allocated param; needs spill slot
		offset = nextSlot(&state.spillOffset, typ)
	}

	return ABIParamAssignment{
		Type:      typ,
		Name:      name,
		Registers: registers,
		offset:    int32(offset),
	}
}

// tryAllocRegs attempts to allocate registers to represent a
// parameter of the given type. If unsuccessful, it returns nil.
func (state *assignState) tryAllocRegs(typ *types.Type) []RegIndex {
	if typ.Size() == 0 {
		return nil // zero-size parameters are defined as being stack allocated
	}

	intRegs, floatRegs := typ.Registers()
	if int(intRegs) > state.rTotal.intRegs-state.rUsed.intRegs || int(floatRegs) > state.rTotal.floatRegs-state.rUsed.floatRegs {
		return nil // too few available registers
	}

	regs := make([]RegIndex, 0, int(intRegs)+int(floatRegs))
	return state.allocateRegs(regs, typ)
}

// ComputePadding returns a list of "post element" padding values in
// the case where we have a structure being passed in registers. Given
// a param assignment corresponding to a struct, it returns a list
// containing padding values for each field, e.g. the Kth element in
// the list is the amount of padding between field K and the following
// field. For things that are not structs (or structs without padding)
// it returns a list of zeros. Example:
//
//	type small struct {
//		x uint16
//		y uint8
//		z int32
//		w int32
//	}
//
// For this struct we would return a list [0, 1, 0, 0], meaning that
// we have one byte of padding after the second field, and no bytes of
// padding after any of the other fields. Input parameter "storage" is
// a slice with enough capacity to accommodate padding elements for
// the architected register set in question.
func (pa *ABIParamAssignment) ComputePadding(storage []uint64) []uint64 {
	nr := len(pa.Registers)
	padding := storage[:nr]
	for i := 0; i < nr; i++ {
		padding[i] = 0
	}
	if pa.Type.Kind() != types.TSTRUCT || nr == 0 {
		return padding
	}
	types := make([]*types.Type, 0, nr)
	types = appendParamTypes(types, pa.Type)
	if len(types) != nr {
		panic("internal error")
	}
	offsets, _ := appendParamOffsets([]int64{}, 0, pa.Type)
	off := int64(0)
	for idx, t := range types {
		ts := t.Size()
		off += int64(ts)
		if idx < len(types)-1 {
			noff := offsets[idx+1]
			if noff != off {
				padding[idx] = uint64(noff - off)
			}
		}
	}
	return padding
}

"""



```