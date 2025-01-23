Response: Let's break down the request and the provided Go code to address each point effectively.

**1. Understanding the Goal:**

The core request is to analyze a specific Go file (`go/src/cmd/compile/internal/ssa/op.go`) and explain its functionality. The request emphasizes connecting the code to Go language features and providing examples.

**2. Initial Code Scan & Keyword Spotting:**

I'll start by scanning the code for prominent keywords and structures:

* **`package ssa`**:  This immediately tells us it's part of the SSA (Static Single Assignment) intermediate representation used in the Go compiler.
* **`type Op int32`**: This defines a core type, `Op`, representing an operation within the SSA.
* **`opInfo` struct**: This structure holds metadata about each `Op`, such as its name, register usage, and properties like commutativity or side effects.
* **`regInfo` struct**:  Deals with register allocation constraints for inputs and outputs of operations.
* **`auxType` and various `Aux...` types**:  These relate to auxiliary information associated with an `Op`. `AuxCall` seems particularly important, dealing with function calls.
* **`SymEffect`**: Indicates the effect of an operation on a symbol.
* **`Sym` interface**:  Represents symbolic offsets (stack, global).
* **`ValAndOff`**:  Combines a value and an offset, likely used for memory addressing.
* **`BoundsKind`**: Enumerates different types of bounds checks.
* **Comments explaining various fields**:  These are valuable clues.

**3. Deeper Dive into Key Structures:**

* **`Op` and `opInfo`:** The combination of these tells me that `Op` is an enumeration of possible operations (like addition, subtraction, memory load, function calls, etc.). `opInfo` provides the *details* of how each operation behaves. The comments about generic and architecture-specific ops are important.

* **Register Allocation (`regInfo`):** The `inputs`, `outputs`, and `clobbers` fields in `regInfo` directly relate to how the SSA form is translated into machine code. The compiler needs to know which registers can be used for inputs, where the output will go, and which registers the operation might modify.

* **Auxiliary Information (`auxType`, `Aux...`):** The `aux` field of an SSA `Value` (not shown here but implied) allows attaching additional data to an operation. `AuxCall` is critical for function calls and stores information about the called function's signature (ABI). `AuxNameOffset` is likely used for accessing struct fields or local variables.

* **Function Calls (`AuxCall`):**  The extensive logic within `AuxCall` strongly suggests this part handles the complexities of calling conventions (ABI - Application Binary Interface). The code manipulates register assignments based on the function signature.

* **Bounds Checks (`BoundsKind`):** This section clearly relates to array/slice bounds checking. The `boundsABI` function hints at optimizations in register allocation for common bounds check patterns.

**4. Connecting to Go Language Features:**

* **`Op`**: Directly relates to the low-level operations needed to implement Go's semantics (arithmetic, memory access, control flow).
* **`AuxCall`**: Implements function calls, including handling multiple return values, passing arguments in registers, and managing stack frames. This is fundamental to all Go programs.
* **`AuxNameOffset`**: Supports accessing struct fields (`.field`) and local variables.
* **`BoundsKind`**:  Essential for safe array/slice access, preventing out-of-bounds errors. This connects to Go's safety guarantees.
* **`SymEffect`**:  Important for compiler optimizations. Knowing if an operation reads or writes memory can enable dead code elimination or reordering of operations.

**5. Planning Examples and Explanations:**

Now I'll plan how to illustrate these concepts with Go code examples.

* **`Op` Example:**  I can show a simple addition operation and how it might be represented with a specific `Op` and type.
* **`AuxCall` Example:** Demonstrating a function call with parameters and return values, highlighting how `AuxCall` stores the function's signature.
* **`AuxNameOffset` Example:** Accessing a struct field to show how the name and offset are used.
* **`BoundsKind` Example:**  Triggering a bounds check error with an out-of-bounds slice access.

**6. Addressing Specific Request Points:**

* **Functionality Listing:** I'll create a bulleted list summarizing the key functionalities of the code.
* **Go Feature Implementation:**  I'll connect the code structures to specific Go language features like function calls, struct access, and bounds checking.
* **Go Code Examples:**  I'll provide simple, illustrative Go code snippets.
* **Input/Output for Code Reasoning:** For the examples, I'll specify the input Go code and explain what the corresponding SSA representation (or at least the relevant `Op` and `Aux` fields) might look like. Since we don't have access to the actual SSA generation process within this exercise, it will be a reasoned *hypothetical* representation.
* **Command-Line Arguments:**  I'll carefully review the code for any direct handling of command-line arguments. If none are present, I'll explicitly state that.
* **Common Mistakes:** I'll consider potential pitfalls related to understanding how low-level compiler components work, such as assuming direct correspondence between Go code and specific SSA ops without considering compiler optimizations.

**7. Refinement and Organization:**

Finally, I'll organize the explanation logically, starting with a high-level overview and then diving into the details of each structure and its connection to Go features. I'll use clear and concise language, avoiding overly technical jargon where possible. The examples will be kept simple and focused.

This thought process ensures that I address all aspects of the request and provide a comprehensive and understandable explanation of the provided Go code. The iterative nature of reviewing, connecting, and planning helps to build a solid understanding before generating the final response.
这段代码是 Go 编译器中用于表示静态单赋值 (SSA) 中操作 (Operation) 的定义。它定义了 `Op` 类型，以及与 `Op` 相关的各种元数据和辅助信息，用于描述 SSA 中的各种操作。

**功能列举:**

1. **定义 SSA 操作码 (`Op`):**  `Op` 是一个 `int32` 类型的枚举，代表了 SSA 中可能出现的各种操作，例如加法、减法、内存加载、函数调用等等。

2. **描述操作码信息 (`opInfo`):**  `opInfo` 结构体包含了关于每个 `Op` 的详细信息，例如：
    * `name`: 操作的名称（字符串形式）。
    * `reg`:  `regInfo` 结构体，描述了该操作对寄存器的使用限制（输入、输出、覆盖）。
    * `auxType`:  `auxType` 枚举，指示了该操作的辅助信息 (aux) 的类型。
    * `argLen`:  操作需要的参数数量，-1 表示可变参数。
    * `asm`:  对应的汇编指令。
    * `generic`:  是否是架构无关的操作。
    * `rematerializeable`:  操作结果是否可以重新计算而不是必须存储。
    * `commutative`:  操作是否满足交换律（例如加法）。
    * `resultInArg0`:  操作的（第一个）输出结果必须和第一个输入参数分配到同一个寄存器。
    * `resultNotInArgs`: 操作的输出结果不能和任何输入参数分配到同一个寄存器。
    * `clobberFlags`: 操作是否会修改标志寄存器。
    * `needIntTemp`:  操作是否需要一个临时的空闲整数寄存器。
    * `call`:  是否是函数调用。
    * `tailCall`: 是否是尾调用。
    * `nilCheck`:  操作是否会对第一个参数进行 nil 检查。
    * `faultOnNilArg0`/`faultOnNilArg1`:  如果对应的参数为 nil 且辅助信息编码了小偏移量，则操作会发生错误。
    * `usesScratch`: 操作是否需要额外的内存空间。
    * `hasSideEffects`:  操作是否有副作用，不能被轻易消除。
    * `zeroWidth`:  操作是否不会生成任何机器码。
    * `unsafePoint`: 操作是否是不安全点，不适合异步抢占。
    * `symEffect`:  操作对辅助信息中符号的影响（读取、写入、取地址）。
    * `scale`:  amd64/386 索引加载的比例因子。

3. **定义寄存器使用信息 (`regInfo`):** `regInfo` 结构体描述了操作对寄存器的约束：
    * `inputs`:  一个 `inputInfo` 数组，描述了每个输入参数允许使用的寄存器集合。
    * `clobbers`:  一个 `regMask`，表示操作会覆盖的寄存器集合（除了输出寄存器）。
    * `outputs`: 一个 `outputInfo` 数组，描述了每个输出结果允许使用的寄存器集合。

4. **定义辅助信息类型 (`auxType`):** `auxType` 是一个枚举，定义了 `Value` 的 `aux` 字段可能存储的各种类型的数据，例如布尔值、整数、浮点数、字符串、符号、类型、函数调用信息等。

5. **定义各种辅助信息结构体 (`AuxNameOffset`, `AuxCall` 等):**  根据 `auxType` 的不同，定义了相应的结构体来存储具体的辅助信息。
    * **`AuxNameOffset`**: 用于存储带有偏移量的变量名，通常用于访问结构体字段或局部变量。
    * **`AuxCall`**: 用于存储函数调用的相关信息，包括被调用函数的符号、寄存器信息和 ABI 信息。它包含了处理函数参数和返回值的寄存器分配和栈布局的复杂逻辑。

6. **定义符号 (`Sym`):**  `Sym` 是一个接口，用于表示符号信息，可以是局部变量（`*ir.Name`）、全局变量（`*obj.LSym`）或者空（`nil`）。

7. **定义值和偏移量 (`ValAndOff`):**  `ValAndOff` 用于将一个 32 位的值和一个 32 位的偏移量打包到一个 64 位的整数中，常用于内存寻址。

8. **定义边界检查类型 (`BoundsKind`):**  `BoundsKind` 是一个枚举，定义了不同类型的边界检查，用于在运行时检测数组或切片访问是否越界。

**推理 Go 语言功能的实现:**

这个文件是 Go 编译器 SSA 中间表示的核心部分，它定义了构建和操作 SSA 图的基础元素。基于这些定义，可以推断出以下 Go 语言功能的实现与此相关：

* **算术运算:**  像 `OpAdd`, `OpSub`, `OpMul` 等操作码对应了 Go 语言中的加减乘除等算术运算符。

* **内存访问:**  像 `OpLoad`, `OpStore` 等操作码对应了 Go 语言中的变量读取和赋值操作。`AuxNameOffset` 用于计算局部变量或结构体字段的内存地址。

* **函数调用:** `AuxCall` 结构体和相关的逻辑是实现 Go 语言函数调用的关键。它处理了参数和返回值的传递，包括寄存器分配和栈帧布局。

* **类型转换:** 某些 `Op` 可能与类型转换相关，`auxTyp` 存储了转换的目标类型。

* **控制流:** 虽然这里没有直接体现，但 SSA 中的分支、跳转等操作（通常在其他的 `_gen/*Ops.go` 文件中定义）是实现 Go 语言控制流（例如 `if`, `for`, `switch`）的基础。

* **边界检查:** `BoundsKind` 枚举和相关的 `boundsABI` 函数实现了 Go 语言中对数组和切片的边界检查，确保程序的安全性。

**Go 代码示例说明 `AuxCall`:**

假设有以下简单的 Go 函数：

```go
package main

func add(a, b int) (int, bool) {
	sum := a + b
	return sum, sum > 10
}

func main() {
	result, ok := add(5, 7)
	println(result, ok)
}
```

在编译 `add` 函数时，编译器可能会生成包含 `AuxCall` 的 SSA 代码来表示函数调用。

**假设的 SSA 表示（简化）：**

```
// ... 函数 add 的 SSA 图 ...

// 在 main 函数中调用 add
v1 = ConstInt 5
v2 = ConstInt 7
v3 = StaticCall [AuxCall: add.funcInfo] v1 v2 mem  // 调用 add 函数
r0 = GetResult0 v3  // 获取第一个返回值
r1 = GetResult1 v3  // 获取第二个返回值
// ... 后续操作 ...
```

在这个例子中，`StaticCall` 操作的 `Aux` 字段会是一个 `AuxCall` 结构体，它包含了关于 `add` 函数的信息：

* **`Fn`**: 指向 `add` 函数的符号 (例如 `add.funcInfo`)。
* **`abiInfo`**: 包含 `add` 函数的 ABI (Application Binary Interface) 信息，例如参数和返回值的类型、寄存器分配等。例如，它会记录 `a` 和 `b` 作为 `int` 类型的参数，以及返回值类型为 `int` 和 `bool`。它还会记录参数和返回值如何通过寄存器或栈传递。
* **`reg`**:  可能会包含 `add` 函数调用所需的寄存器信息，例如哪些寄存器用于传递参数，哪些寄存器用于接收返回值。

**假设的输入与输出（对于 `AuxCall` 的 `Reg` 方法）：**

假设 `i` 是一个通用的 `regInfo` 结构体，其中包含一些默认的寄存器信息。`c` 是编译配置信息。

**输入 `a` (AuxCall):**  表示 `add` 函数调用的 `AuxCall` 结构体，其 `abiInfo` 已经包含了 `add` 函数的参数和返回值信息。

**输入 `i` (regInfo):**  一些通用的寄存器约束信息，可能为空或者包含一些默认的约束。

**输入 `c` (Config):**  编译器的配置信息，包含目标架构的寄存器信息等。

**输出 (通过 `a.Reg(i, c)`):**  一个新的 `regInfo` 结构体，其中包含了根据 `add` 函数的 ABI 信息和目标架构的寄存器信息调整后的寄存器约束。例如，它可能会指定参数 `a` 和 `b` 应该分配到特定的寄存器，返回值也应该分配到特定的寄存器。

**命令行参数的具体处理:**

这段代码本身并不直接处理命令行参数。命令行参数的处理通常发生在编译器的前端部分（例如词法分析、语法分析和类型检查）。这段代码所在的 `ssa` 包是编译器的中间阶段，它接收前端处理后的中间表示（IR）并将其转换为 SSA 形式。

**使用者易犯错的点:**

作为编译器开发者，在使用或理解这段代码时，可能会犯以下错误：

1. **错误理解操作码的语义:**  不同的 `Op` 有不同的语义，需要查阅相应的 `_gen/*Ops.go` 文件才能准确理解其行为。不能仅凭名称猜测。

2. **忽略辅助信息的重要性:**  `Op` 的具体行为可能受到 `aux` 字段的影响。例如，对于 `Load` 操作，`aux` 字段可能包含要加载的内存地址的符号信息。

3. **混淆架构相关的和架构无关的操作码:**  有些 `Op` 是通用的，可以在不同的架构上使用，而有些 `Op` 是特定于某个架构的。需要根据目标架构选择正确的操作码。

4. **不理解寄存器分配的约束:**  `regInfo` 描述了操作对寄存器的限制。在编写后端代码或进行代码生成时，必须遵守这些约束，否则会导致寄存器分配冲突。

5. **不了解 ABI 的细节:**  对于函数调用，`AuxCall` 中的 ABI 信息至关重要。错误地理解 ABI 会导致函数调用失败或产生错误的结果。例如，参数和返回值的传递方式（寄存器还是栈）以及栈帧的布局都由 ABI 决定。

总而言之，`go/src/cmd/compile/internal/ssa/op.go` 文件是 Go 编译器 SSA 中间表示的核心定义，它为描述和操作各种程序操作提供了基础结构和元数据。理解这个文件对于深入了解 Go 编译器的内部工作原理至关重要。

### 提示词
```
这是路径为go/src/cmd/compile/internal/ssa/op.go的go语言实现的一部分， 请列举一下它的功能, 　
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
	"cmd/compile/internal/ir"
	"cmd/compile/internal/types"
	"cmd/internal/obj"
	"fmt"
	"strings"
)

// An Op encodes the specific operation that a Value performs.
// Opcodes' semantics can be modified by the type and aux fields of the Value.
// For instance, OpAdd can be 32 or 64 bit, signed or unsigned, float or complex, depending on Value.Type.
// Semantics of each op are described in the opcode files in _gen/*Ops.go.
// There is one file for generic (architecture-independent) ops and one file
// for each architecture.
type Op int32

type opInfo struct {
	name              string
	reg               regInfo
	auxType           auxType
	argLen            int32 // the number of arguments, -1 if variable length
	asm               obj.As
	generic           bool      // this is a generic (arch-independent) opcode
	rematerializeable bool      // this op is rematerializeable
	commutative       bool      // this operation is commutative (e.g. addition)
	resultInArg0      bool      // (first, if a tuple) output of v and v.Args[0] must be allocated to the same register
	resultNotInArgs   bool      // outputs must not be allocated to the same registers as inputs
	clobberFlags      bool      // this op clobbers flags register
	needIntTemp       bool      // need a temporary free integer register
	call              bool      // is a function call
	tailCall          bool      // is a tail call
	nilCheck          bool      // this op is a nil check on arg0
	faultOnNilArg0    bool      // this op will fault if arg0 is nil (and aux encodes a small offset)
	faultOnNilArg1    bool      // this op will fault if arg1 is nil (and aux encodes a small offset)
	usesScratch       bool      // this op requires scratch memory space
	hasSideEffects    bool      // for "reasons", not to be eliminated.  E.g., atomic store, #19182.
	zeroWidth         bool      // op never translates into any machine code. example: copy, which may sometimes translate to machine code, is not zero-width.
	unsafePoint       bool      // this op is an unsafe point, i.e. not safe for async preemption
	symEffect         SymEffect // effect this op has on symbol in aux
	scale             uint8     // amd64/386 indexed load scale
}

type inputInfo struct {
	idx  int     // index in Args array
	regs regMask // allowed input registers
}

type outputInfo struct {
	idx  int     // index in output tuple
	regs regMask // allowed output registers
}

type regInfo struct {
	// inputs encodes the register restrictions for an instruction's inputs.
	// Each entry specifies an allowed register set for a particular input.
	// They are listed in the order in which regalloc should pick a register
	// from the register set (most constrained first).
	// Inputs which do not need registers are not listed.
	inputs []inputInfo
	// clobbers encodes the set of registers that are overwritten by
	// the instruction (other than the output registers).
	clobbers regMask
	// outputs is the same as inputs, but for the outputs of the instruction.
	outputs []outputInfo
}

func (r *regInfo) String() string {
	s := ""
	s += "INS:\n"
	for _, i := range r.inputs {
		mask := fmt.Sprintf("%64b", i.regs)
		mask = strings.Replace(mask, "0", ".", -1)
		s += fmt.Sprintf("%2d |%s|\n", i.idx, mask)
	}
	s += "OUTS:\n"
	for _, i := range r.outputs {
		mask := fmt.Sprintf("%64b", i.regs)
		mask = strings.Replace(mask, "0", ".", -1)
		s += fmt.Sprintf("%2d |%s|\n", i.idx, mask)
	}
	s += "CLOBBERS:\n"
	mask := fmt.Sprintf("%64b", r.clobbers)
	mask = strings.Replace(mask, "0", ".", -1)
	s += fmt.Sprintf("   |%s|\n", mask)
	return s
}

type auxType int8

type AuxNameOffset struct {
	Name   *ir.Name
	Offset int64
}

func (a *AuxNameOffset) CanBeAnSSAAux() {}
func (a *AuxNameOffset) String() string {
	return fmt.Sprintf("%s+%d", a.Name.Sym().Name, a.Offset)
}

func (a *AuxNameOffset) FrameOffset() int64 {
	return a.Name.FrameOffset() + a.Offset
}

type AuxCall struct {
	Fn      *obj.LSym
	reg     *regInfo // regInfo for this call
	abiInfo *abi.ABIParamResultInfo
}

// Reg returns the regInfo for a given call, combining the derived in/out register masks
// with the machine-specific register information in the input i.  (The machine-specific
// regInfo is much handier at the call site than it is when the AuxCall is being constructed,
// therefore do this lazily).
//
// TODO: there is a Clever Hack that allows pre-generation of a small-ish number of the slices
// of inputInfo and outputInfo used here, provided that we are willing to reorder the inputs
// and outputs from calls, so that all integer registers come first, then all floating registers.
// At this point (active development of register ABI) that is very premature,
// but if this turns out to be a cost, we could do it.
func (a *AuxCall) Reg(i *regInfo, c *Config) *regInfo {
	if a.reg.clobbers != 0 {
		// Already updated
		return a.reg
	}
	if a.abiInfo.InRegistersUsed()+a.abiInfo.OutRegistersUsed() == 0 {
		// Shortcut for zero case, also handles old ABI.
		a.reg = i
		return a.reg
	}

	k := len(i.inputs)
	for _, p := range a.abiInfo.InParams() {
		for _, r := range p.Registers {
			m := archRegForAbiReg(r, c)
			a.reg.inputs = append(a.reg.inputs, inputInfo{idx: k, regs: (1 << m)})
			k++
		}
	}
	a.reg.inputs = append(a.reg.inputs, i.inputs...) // These are less constrained, thus should come last
	k = len(i.outputs)
	for _, p := range a.abiInfo.OutParams() {
		for _, r := range p.Registers {
			m := archRegForAbiReg(r, c)
			a.reg.outputs = append(a.reg.outputs, outputInfo{idx: k, regs: (1 << m)})
			k++
		}
	}
	a.reg.outputs = append(a.reg.outputs, i.outputs...)
	a.reg.clobbers = i.clobbers
	return a.reg
}
func (a *AuxCall) ABI() *abi.ABIConfig {
	return a.abiInfo.Config()
}
func (a *AuxCall) ABIInfo() *abi.ABIParamResultInfo {
	return a.abiInfo
}
func (a *AuxCall) ResultReg(c *Config) *regInfo {
	if a.abiInfo.OutRegistersUsed() == 0 {
		return a.reg
	}
	if len(a.reg.inputs) > 0 {
		return a.reg
	}
	k := 0
	for _, p := range a.abiInfo.OutParams() {
		for _, r := range p.Registers {
			m := archRegForAbiReg(r, c)
			a.reg.inputs = append(a.reg.inputs, inputInfo{idx: k, regs: (1 << m)})
			k++
		}
	}
	return a.reg
}

// For ABI register index r, returns the (dense) register number used in
// SSA backend.
func archRegForAbiReg(r abi.RegIndex, c *Config) uint8 {
	var m int8
	if int(r) < len(c.intParamRegs) {
		m = c.intParamRegs[r]
	} else {
		m = c.floatParamRegs[int(r)-len(c.intParamRegs)]
	}
	return uint8(m)
}

// For ABI register index r, returns the register number used in the obj
// package (assembler).
func ObjRegForAbiReg(r abi.RegIndex, c *Config) int16 {
	m := archRegForAbiReg(r, c)
	return c.registers[m].objNum
}

// ArgWidth returns the amount of stack needed for all the inputs
// and outputs of a function or method, including ABI-defined parameter
// slots and ABI-defined spill slots for register-resident parameters.
//
// The name is taken from the types package's ArgWidth(<function type>),
// which predated changes to the ABI; this version handles those changes.
func (a *AuxCall) ArgWidth() int64 {
	return a.abiInfo.ArgWidth()
}

// ParamAssignmentForResult returns the ABI Parameter assignment for result which (indexed 0, 1, etc).
func (a *AuxCall) ParamAssignmentForResult(which int64) *abi.ABIParamAssignment {
	return a.abiInfo.OutParam(int(which))
}

// OffsetOfResult returns the SP offset of result which (indexed 0, 1, etc).
func (a *AuxCall) OffsetOfResult(which int64) int64 {
	n := int64(a.abiInfo.OutParam(int(which)).Offset())
	return n
}

// OffsetOfArg returns the SP offset of argument which (indexed 0, 1, etc).
// If the call is to a method, the receiver is the first argument (i.e., index 0)
func (a *AuxCall) OffsetOfArg(which int64) int64 {
	n := int64(a.abiInfo.InParam(int(which)).Offset())
	return n
}

// RegsOfResult returns the register(s) used for result which (indexed 0, 1, etc).
func (a *AuxCall) RegsOfResult(which int64) []abi.RegIndex {
	return a.abiInfo.OutParam(int(which)).Registers
}

// RegsOfArg returns the register(s) used for argument which (indexed 0, 1, etc).
// If the call is to a method, the receiver is the first argument (i.e., index 0)
func (a *AuxCall) RegsOfArg(which int64) []abi.RegIndex {
	return a.abiInfo.InParam(int(which)).Registers
}

// NameOfResult returns the ir.Name of result which (indexed 0, 1, etc).
func (a *AuxCall) NameOfResult(which int64) *ir.Name {
	return a.abiInfo.OutParam(int(which)).Name
}

// TypeOfResult returns the type of result which (indexed 0, 1, etc).
func (a *AuxCall) TypeOfResult(which int64) *types.Type {
	return a.abiInfo.OutParam(int(which)).Type
}

// TypeOfArg returns the type of argument which (indexed 0, 1, etc).
// If the call is to a method, the receiver is the first argument (i.e., index 0)
func (a *AuxCall) TypeOfArg(which int64) *types.Type {
	return a.abiInfo.InParam(int(which)).Type
}

// SizeOfResult returns the size of result which (indexed 0, 1, etc).
func (a *AuxCall) SizeOfResult(which int64) int64 {
	return a.TypeOfResult(which).Size()
}

// SizeOfArg returns the size of argument which (indexed 0, 1, etc).
// If the call is to a method, the receiver is the first argument (i.e., index 0)
func (a *AuxCall) SizeOfArg(which int64) int64 {
	return a.TypeOfArg(which).Size()
}

// NResults returns the number of results.
func (a *AuxCall) NResults() int64 {
	return int64(len(a.abiInfo.OutParams()))
}

// LateExpansionResultType returns the result type (including trailing mem)
// for a call that will be expanded later in the SSA phase.
func (a *AuxCall) LateExpansionResultType() *types.Type {
	var tys []*types.Type
	for i := int64(0); i < a.NResults(); i++ {
		tys = append(tys, a.TypeOfResult(i))
	}
	tys = append(tys, types.TypeMem)
	return types.NewResults(tys)
}

// NArgs returns the number of arguments (including receiver, if there is one).
func (a *AuxCall) NArgs() int64 {
	return int64(len(a.abiInfo.InParams()))
}

// String returns "AuxCall{<fn>}"
func (a *AuxCall) String() string {
	var fn string
	if a.Fn == nil {
		fn = "AuxCall{nil" // could be interface/closure etc.
	} else {
		fn = fmt.Sprintf("AuxCall{%v", a.Fn)
	}
	// TODO how much of the ABI should be printed?

	return fn + "}"
}

// StaticAuxCall returns an AuxCall for a static call.
func StaticAuxCall(sym *obj.LSym, paramResultInfo *abi.ABIParamResultInfo) *AuxCall {
	if paramResultInfo == nil {
		panic(fmt.Errorf("Nil paramResultInfo, sym=%v", sym))
	}
	var reg *regInfo
	if paramResultInfo.InRegistersUsed()+paramResultInfo.OutRegistersUsed() > 0 {
		reg = &regInfo{}
	}
	return &AuxCall{Fn: sym, abiInfo: paramResultInfo, reg: reg}
}

// InterfaceAuxCall returns an AuxCall for an interface call.
func InterfaceAuxCall(paramResultInfo *abi.ABIParamResultInfo) *AuxCall {
	var reg *regInfo
	if paramResultInfo.InRegistersUsed()+paramResultInfo.OutRegistersUsed() > 0 {
		reg = &regInfo{}
	}
	return &AuxCall{Fn: nil, abiInfo: paramResultInfo, reg: reg}
}

// ClosureAuxCall returns an AuxCall for a closure call.
func ClosureAuxCall(paramResultInfo *abi.ABIParamResultInfo) *AuxCall {
	var reg *regInfo
	if paramResultInfo.InRegistersUsed()+paramResultInfo.OutRegistersUsed() > 0 {
		reg = &regInfo{}
	}
	return &AuxCall{Fn: nil, abiInfo: paramResultInfo, reg: reg}
}

func (*AuxCall) CanBeAnSSAAux() {}

// OwnAuxCall returns a function's own AuxCall.
func OwnAuxCall(fn *obj.LSym, paramResultInfo *abi.ABIParamResultInfo) *AuxCall {
	// TODO if this remains identical to ClosureAuxCall above after new ABI is done, should deduplicate.
	var reg *regInfo
	if paramResultInfo.InRegistersUsed()+paramResultInfo.OutRegistersUsed() > 0 {
		reg = &regInfo{}
	}
	return &AuxCall{Fn: fn, abiInfo: paramResultInfo, reg: reg}
}

const (
	auxNone           auxType = iota
	auxBool                   // auxInt is 0/1 for false/true
	auxInt8                   // auxInt is an 8-bit integer
	auxInt16                  // auxInt is a 16-bit integer
	auxInt32                  // auxInt is a 32-bit integer
	auxInt64                  // auxInt is a 64-bit integer
	auxInt128                 // auxInt represents a 128-bit integer.  Always 0.
	auxUInt8                  // auxInt is an 8-bit unsigned integer
	auxFloat32                // auxInt is a float32 (encoded with math.Float64bits)
	auxFloat64                // auxInt is a float64 (encoded with math.Float64bits)
	auxFlagConstant           // auxInt is a flagConstant
	auxCCop                   // auxInt is a ssa.Op that represents a flags-to-bool conversion (e.g. LessThan)
	auxNameOffsetInt8         // aux is a &struct{Name ir.Name, Offset int64}; auxInt is index in parameter registers array
	auxString                 // aux is a string
	auxSym                    // aux is a symbol (a *gc.Node for locals, an *obj.LSym for globals, or nil for none)
	auxSymOff                 // aux is a symbol, auxInt is an offset
	auxSymValAndOff           // aux is a symbol, auxInt is a ValAndOff
	auxTyp                    // aux is a type
	auxTypSize                // aux is a type, auxInt is a size, must have Aux.(Type).Size() == AuxInt
	auxCall                   // aux is a *ssa.AuxCall
	auxCallOff                // aux is a *ssa.AuxCall, AuxInt is int64 param (in+out) size

	// architecture specific aux types
	auxARM64BitField     // aux is an arm64 bitfield lsb and width packed into auxInt
	auxS390XRotateParams // aux is a s390x rotate parameters object encoding start bit, end bit and rotate amount
	auxS390XCCMask       // aux is a s390x 4-bit condition code mask
	auxS390XCCMaskInt8   // aux is a s390x 4-bit condition code mask, auxInt is an int8 immediate
	auxS390XCCMaskUint8  // aux is a s390x 4-bit condition code mask, auxInt is a uint8 immediate
)

// A SymEffect describes the effect that an SSA Value has on the variable
// identified by the symbol in its Aux field.
type SymEffect int8

const (
	SymRead SymEffect = 1 << iota
	SymWrite
	SymAddr

	SymRdWr = SymRead | SymWrite

	SymNone SymEffect = 0
)

// A Sym represents a symbolic offset from a base register.
// Currently a Sym can be one of 3 things:
//   - a *gc.Node, for an offset from SP (the stack pointer)
//   - a *obj.LSym, for an offset from SB (the global pointer)
//   - nil, for no offset
type Sym interface {
	CanBeAnSSASym()
	CanBeAnSSAAux()
}

// A ValAndOff is used by the several opcodes. It holds
// both a value and a pointer offset.
// A ValAndOff is intended to be encoded into an AuxInt field.
// The zero ValAndOff encodes a value of 0 and an offset of 0.
// The high 32 bits hold a value.
// The low 32 bits hold a pointer offset.
type ValAndOff int64

func (x ValAndOff) Val() int32   { return int32(int64(x) >> 32) }
func (x ValAndOff) Val64() int64 { return int64(x) >> 32 }
func (x ValAndOff) Val16() int16 { return int16(int64(x) >> 32) }
func (x ValAndOff) Val8() int8   { return int8(int64(x) >> 32) }

func (x ValAndOff) Off64() int64 { return int64(int32(x)) }
func (x ValAndOff) Off() int32   { return int32(x) }

func (x ValAndOff) String() string {
	return fmt.Sprintf("val=%d,off=%d", x.Val(), x.Off())
}

// validVal reports whether the value can be used
// as an argument to makeValAndOff.
func validVal(val int64) bool {
	return val == int64(int32(val))
}

func makeValAndOff(val, off int32) ValAndOff {
	return ValAndOff(int64(val)<<32 + int64(uint32(off)))
}

func (x ValAndOff) canAdd32(off int32) bool {
	newoff := x.Off64() + int64(off)
	return newoff == int64(int32(newoff))
}
func (x ValAndOff) canAdd64(off int64) bool {
	newoff := x.Off64() + off
	return newoff == int64(int32(newoff))
}

func (x ValAndOff) addOffset32(off int32) ValAndOff {
	if !x.canAdd32(off) {
		panic("invalid ValAndOff.addOffset32")
	}
	return makeValAndOff(x.Val(), x.Off()+off)
}
func (x ValAndOff) addOffset64(off int64) ValAndOff {
	if !x.canAdd64(off) {
		panic("invalid ValAndOff.addOffset64")
	}
	return makeValAndOff(x.Val(), x.Off()+int32(off))
}

// int128 is a type that stores a 128-bit constant.
// The only allowed constant right now is 0, so we can cheat quite a bit.
type int128 int64

type BoundsKind uint8

const (
	BoundsIndex       BoundsKind = iota // indexing operation, 0 <= idx < len failed
	BoundsIndexU                        // ... with unsigned idx
	BoundsSliceAlen                     // 2-arg slicing operation, 0 <= high <= len failed
	BoundsSliceAlenU                    // ... with unsigned high
	BoundsSliceAcap                     // 2-arg slicing operation, 0 <= high <= cap failed
	BoundsSliceAcapU                    // ... with unsigned high
	BoundsSliceB                        // 2-arg slicing operation, 0 <= low <= high failed
	BoundsSliceBU                       // ... with unsigned low
	BoundsSlice3Alen                    // 3-arg slicing operation, 0 <= max <= len failed
	BoundsSlice3AlenU                   // ... with unsigned max
	BoundsSlice3Acap                    // 3-arg slicing operation, 0 <= max <= cap failed
	BoundsSlice3AcapU                   // ... with unsigned max
	BoundsSlice3B                       // 3-arg slicing operation, 0 <= high <= max failed
	BoundsSlice3BU                      // ... with unsigned high
	BoundsSlice3C                       // 3-arg slicing operation, 0 <= low <= high failed
	BoundsSlice3CU                      // ... with unsigned low
	BoundsConvert                       // conversion to array pointer failed
	BoundsKindCount
)

// boundsABI determines which register arguments a bounds check call should use. For an [a:b:c] slice, we do:
//
//	CMPQ c, cap
//	JA   fail1
//	CMPQ b, c
//	JA   fail2
//	CMPQ a, b
//	JA   fail3
//
// fail1: CALL panicSlice3Acap (c, cap)
// fail2: CALL panicSlice3B (b, c)
// fail3: CALL panicSlice3C (a, b)
//
// When we register allocate that code, we want the same register to be used for
// the first arg of panicSlice3Acap and the second arg to panicSlice3B. That way,
// initializing that register once will satisfy both calls.
// That desire ends up dividing the set of bounds check calls into 3 sets. This function
// determines which set to use for a given panic call.
// The first arg for set 0 should be the second arg for set 1.
// The first arg for set 1 should be the second arg for set 2.
func boundsABI(b int64) int {
	switch BoundsKind(b) {
	case BoundsSlice3Alen,
		BoundsSlice3AlenU,
		BoundsSlice3Acap,
		BoundsSlice3AcapU,
		BoundsConvert:
		return 0
	case BoundsSliceAlen,
		BoundsSliceAlenU,
		BoundsSliceAcap,
		BoundsSliceAcapU,
		BoundsSlice3B,
		BoundsSlice3BU:
		return 1
	case BoundsIndex,
		BoundsIndexU,
		BoundsSliceB,
		BoundsSliceBU,
		BoundsSlice3C,
		BoundsSlice3CU:
		return 2
	default:
		panic("bad BoundsKind")
	}
}

// arm64BitField is the GO type of ARM64BitField auxInt.
// if x is an ARM64BitField, then width=x&0xff, lsb=(x>>8)&0xff, and
// width+lsb<64 for 64-bit variant, width+lsb<32 for 32-bit variant.
// the meaning of width and lsb are instruction-dependent.
type arm64BitField int16
```