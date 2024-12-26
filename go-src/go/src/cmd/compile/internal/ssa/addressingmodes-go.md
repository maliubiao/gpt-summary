Response: My thought process for analyzing the Go code and generating the response went through these stages:

1. **Understanding the Goal:** The core request is to understand the functionality of the provided Go code snippet, which resides within the `ssa` (static single assignment) package of the Go compiler. The request specifically asks for:
    * A description of its function.
    * Identification of the Go language feature it implements.
    * Go code examples.
    * Details on command-line parameters (if applicable).
    * Common mistakes users might make (if applicable).

2. **High-Level Overview:** I first read through the code to grasp its overall purpose. The function name `addressingModes` and the comment "combines address calculations into memory operations that can perform complicated addressing modes" immediately suggest that this code is about optimizing memory access patterns. It aims to combine separate address calculation instructions with memory load/store instructions.

3. **Key Data Structures:** I identified the crucial data structures:
    * `combine`: A map that defines the combinations of operations that can be merged. The key is a pair of `Op` (operation codes), and the value is the combined `Op`. This is the heart of the transformation logic.
    * `combineFirst`: A set of `Op` codes that can appear as the first part of a `combine` key. This likely acts as an optimization to quickly filter potential candidates for combination.
    * `needSplit`: A set of `Op` codes that, after being combined, should be further split into more efficient two-instruction sequences. This indicates that the initial combination is an intermediate step toward optimal code generation.

4. **Algorithm Analysis:** I then focused on the `addressingModes` function:
    * **Architecture-Specific Immediate Range:** The code first checks the target architecture (`f.Config.arch`) to determine the valid range for immediate values used in addressing. This signifies that the optimization is architecture-dependent.
    * **Iterating Through Blocks and Values:** The nested loops iterate through the basic blocks and the instructions (values) within each block of the SSA representation. This is a standard way to process the intermediate representation during compilation.
    * **Filtering for Combinable Operations:** The `combineFirst` map is used to quickly skip instructions that cannot be the starting point of a combination.
    * **Identifying Potential Combinations:** The code checks if the current instruction (`v`) and its operand (`p`) form a key present in the `combine` map.
    * **Auxiliary Information Handling:** The code handles `Aux` and `AuxInt` values associated with the instructions. This is important for correctly representing offsets and symbolic information in memory addresses. The different cases in the `switch` statement handle various combinations of auxiliary information types.
    * **Combining Operations:** If a combination is found, the instruction's opcode (`v.Op`) is updated to the combined opcode (`c`), and the arguments are rearranged to reflect the combined operation.
    * **Splitting Combined Operations:** The `needSplit` map is used to identify cases where the combined instruction should be further decomposed into a more efficient sequence using `f.Config.splitLoad(v)`.

5. **Inferring the Go Language Feature:** Based on the code's functionality, I concluded that it implements optimizations related to **array and struct access**, potentially involving pointer arithmetic. The combination of load/store operations with address calculations (like addition or scaled indexing) is a common pattern in array and struct element access.

6. **Crafting Go Code Examples:** To illustrate the functionality, I created simple Go code snippets that would likely trigger the transformations performed by `addressingModes`. I focused on:
    * **Array Access:**  Accessing elements of an integer array using a loop.
    * **Struct Access:** Accessing fields of a struct.
    * I included hypothetical SSA before and after the optimization to show the effect of the code. I also considered different architectures (amd64 and a generic one) to demonstrate the conditional nature of the optimization.

7. **Command-Line Parameters:**  I recognized that this code operates within the Go compiler's internal workings and doesn't directly involve command-line parameters used by Go developers. Therefore, I stated that it doesn't directly process command-line arguments.

8. **Common Mistakes:** I considered potential pitfalls. While developers don't directly interact with this SSA optimization pass, I thought about the *intent* behind the optimization. Incorrect manual attempts to optimize memory access, like overly complex pointer arithmetic when simpler indexing would suffice, could be considered analogous to missing the point of this optimization. However, since the request asked about *user* mistakes with *this specific code*, I concluded that there aren't direct user errors since it's an internal compiler component.

9. **Review and Refinement:** I reviewed the generated response to ensure clarity, accuracy, and completeness, aligning it with the specific points raised in the original request. I paid attention to formatting and the use of code blocks for better readability. I made sure to explain the *why* behind the code's actions, not just the *what*.
这是一个Go语言编译器的内部实现，位于`cmd/compile/internal/ssa`包中，专门负责**优化代码中的内存寻址模式**。它的主要功能是将一些简单的地址计算操作与后续的内存访问操作（例如load、store）合并成更复杂的、通常也更高效的寻址模式。

**功能详细列举:**

1. **识别可合并的指令对:**  代码遍历SSA函数中的基本块和值（指令），查找特定的指令对，其中一个指令是内存访问操作 (load/store/compare)，另一个指令是地址计算操作 (例如加法 `ADDQ` 或带比例的地址计算 `LEAQ`)。`combine` 变量定义了这些可合并的指令对。

2. **架构相关的优化:** 优化行为取决于目标架构 (`f.Config.arch`)。目前，它主要针对 `amd64` 和 `386` 架构进行优化，对于 `s390x` 架构也有部分支持。对于其他架构，此优化不做任何处理。

3. **立即数范围检查:**  在合并地址计算时，会检查合并后的偏移量是否在目标架构支持的立即数范围内 (`isInImmediateRange`)。例如，在某些架构上，内存访问指令的偏移量只能是32位或20位的立即数。

4. **合并辅助信息 (Aux/AuxInt):**  当指令被合并时，来自地址计算指令的辅助信息（例如符号偏移量 `Aux` 和整数偏移量 `AuxInt`）会被合并到内存访问指令中。代码中针对不同的辅助信息类型 (`auxSymOff`, `auxInt32`, `auxSymValAndOff`, `auxNone`) 进行了处理，确保合并后的偏移量正确。

5. **指令重写:** 如果找到可以合并的指令对，原始的内存访问指令的 `Op` 代码会被修改为新的、合并后的 `Op` 代码。

6. **参数调整:**  合并后的指令的参数列表也会被调整。通常，地址计算指令的参数会被插入到内存访问指令的参数列表中，形成新的寻址模式。

7. **进一步拆分 (splitLoad):**  对于某些合并后的指令，例如 `CMPBloadidx1`，代码会调用 `f.Config.splitLoad(v)` 将其进一步拆分成两个更高效的指令。这是因为虽然合并操作本身是一种优化，但在某些情况下，特定的指令序列可能性能更佳。

**它是什么Go语言功能的实现 (推理):**

这个代码片段是Go语言编译器中实现**更高效的内存访问**功能的一部分。它利用了目标架构提供的复杂寻址模式，减少了执行指令的数量，从而提高了程序的运行效率。

**Go代码举例说明:**

假设有以下Go代码：

```go
package main

func main() {
	arr := [10]int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}
	index := 2
	val := arr[index+3]
	println(val)
}
```

**假设的SSA表示 (在优化前):**

在SSA中间表示中，`arr[index+3]` 的访问可能会被分解成以下操作 (以amd64为例，操作码是假设的):

```
// ... 一些初始化代码 ...
v1 = LEAQ <arr的地址>           // 获取数组的基地址
v2 = MOVQ index                 // 将 index 加载到寄存器
v3 = ADDQ v2, $3               // 计算 index + 3
v4 = SHLQ v3, $3               // 将 index + 3 左移 3 位 (乘以 8，因为是 int)
v5 = ADDQ v1, v4               // 计算目标元素的地址
v6 = MOVQload v5              // 从计算出的地址加载值
// ... 后续使用 v6 的代码 ...
```

**优化后的SSA表示 (通过 `addressingModes`):**

`addressingModes` 函数可能会将上述操作合并成一个使用索引寻址模式的指令：

```
// ... 一些初始化代码 ...
v1 = LEAQ <arr的地址>           // 获取数组的基地址
v2 = MOVQ index                 // 将 index 加载到寄存器
v6 = MOVQloadidx1 v1, v2, $3   // 使用基地址 + 索引 * 比例 + 偏移量 的寻址模式加载值
// ... 后续使用 v6 的代码 ...
```

在这个例子中，`MOVQloadidx1` 是一个假设的合并后的操作码，它直接执行了基地址加上索引乘以比例再加上偏移量的加载操作。

**假设的输入与输出:**

* **输入:**  一个包含上述未优化 SSA 指令序列的 `*Func` 对象。
* **输出:**  修改后的 `*Func` 对象，其中包含合并后的 `MOVQloadidx1` 指令。

**涉及命令行参数的具体处理:**

这个代码片段是Go编译器内部的优化步骤，**不直接涉及用户提供的命令行参数**。Go编译器的命令行参数主要控制编译过程的各个方面，例如目标架构、优化级别等。这些参数会影响编译器的整体行为，但不会直接传递到 `addressingModes` 函数中。`addressingModes` 函数会读取编译器的配置 (`f.Config`) 来确定目标架构，从而应用相应的优化策略。

**使用者易犯错的点:**

由于 `addressingModes` 是编译器内部的实现细节，**Go语言开发者通常不会直接与这段代码交互，因此不存在用户易犯错的点**。

然而，理解其背后的原理对于编写高性能的Go代码是有帮助的。开发者应该了解，编译器会尽力优化常见的内存访问模式。编写简洁、符合习惯的代码，例如直接使用数组索引 `arr[index+3]`，可以让编译器更好地进行优化，而避免手动进行复杂的指针运算，反而可能阻碍编译器的优化。

**总结:**

`addressingModes` 函数是Go编译器SSA优化阶段的关键组成部分，它通过合并地址计算和内存访问操作，利用目标架构提供的复杂寻址模式，来提升生成代码的效率。这是一种底层的优化，对Go开发者是透明的，但了解其原理有助于编写出更易于编译器优化的代码。

Prompt: 
```
这是路径为go/src/cmd/compile/internal/ssa/addressingmodes.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，

"""
// Copyright 2020 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ssa

// addressingModes combines address calculations into memory operations
// that can perform complicated addressing modes.
func addressingModes(f *Func) {
	isInImmediateRange := is32Bit
	switch f.Config.arch {
	default:
		// Most architectures can't do this.
		return
	case "amd64", "386":
	case "s390x":
		isInImmediateRange = is20Bit
	}

	var tmp []*Value
	for _, b := range f.Blocks {
		for _, v := range b.Values {
			if !combineFirst[v.Op] {
				continue
			}
			// All matched operations have the pointer in arg[0].
			// All results have the pointer in arg[0] and the index in arg[1].
			// *Except* for operations which update a register,
			// which are marked with resultInArg0. Those have
			// the pointer in arg[1], and the corresponding result op
			// has the pointer in arg[1] and the index in arg[2].
			ptrIndex := 0
			if opcodeTable[v.Op].resultInArg0 {
				ptrIndex = 1
			}
			p := v.Args[ptrIndex]
			c, ok := combine[[2]Op{v.Op, p.Op}]
			if !ok {
				continue
			}
			// See if we can combine the Aux/AuxInt values.
			switch [2]auxType{opcodeTable[v.Op].auxType, opcodeTable[p.Op].auxType} {
			case [2]auxType{auxSymOff, auxInt32}:
				// TODO: introduce auxSymOff32
				if !isInImmediateRange(v.AuxInt + p.AuxInt) {
					continue
				}
				v.AuxInt += p.AuxInt
			case [2]auxType{auxSymOff, auxSymOff}:
				if v.Aux != nil && p.Aux != nil {
					continue
				}
				if !isInImmediateRange(v.AuxInt + p.AuxInt) {
					continue
				}
				if p.Aux != nil {
					v.Aux = p.Aux
				}
				v.AuxInt += p.AuxInt
			case [2]auxType{auxSymValAndOff, auxInt32}:
				vo := ValAndOff(v.AuxInt)
				if !vo.canAdd64(p.AuxInt) {
					continue
				}
				v.AuxInt = int64(vo.addOffset64(p.AuxInt))
			case [2]auxType{auxSymValAndOff, auxSymOff}:
				vo := ValAndOff(v.AuxInt)
				if v.Aux != nil && p.Aux != nil {
					continue
				}
				if !vo.canAdd64(p.AuxInt) {
					continue
				}
				if p.Aux != nil {
					v.Aux = p.Aux
				}
				v.AuxInt = int64(vo.addOffset64(p.AuxInt))
			case [2]auxType{auxSymOff, auxNone}:
				// nothing to do
			case [2]auxType{auxSymValAndOff, auxNone}:
				// nothing to do
			default:
				f.Fatalf("unknown aux combining for %s and %s\n", v.Op, p.Op)
			}
			// Combine the operations.
			tmp = append(tmp[:0], v.Args[:ptrIndex]...)
			tmp = append(tmp, p.Args...)
			tmp = append(tmp, v.Args[ptrIndex+1:]...)
			v.resetArgs()
			v.Op = c
			v.AddArgs(tmp...)
			if needSplit[c] {
				// It turns out that some of the combined instructions have faster two-instruction equivalents,
				// but not the two instructions that led to them being combined here.  For example
				// (CMPBconstload c (ADDQ x y)) -> (CMPBconstloadidx1 c x y) -> (CMPB c (MOVBloadidx1 x y))
				// The final pair of instructions turns out to be notably faster, at least in some benchmarks.
				f.Config.splitLoad(v)
			}
		}
	}
}

// combineFirst contains ops which appear in combine as the
// first part of the key.
var combineFirst = map[Op]bool{}

func init() {
	for k := range combine {
		combineFirst[k[0]] = true
	}
}

// needSplit contains instructions that should be postprocessed by splitLoad
// into a more-efficient two-instruction form.
var needSplit = map[Op]bool{
	OpAMD64CMPBloadidx1: true,
	OpAMD64CMPWloadidx1: true,
	OpAMD64CMPLloadidx1: true,
	OpAMD64CMPQloadidx1: true,
	OpAMD64CMPWloadidx2: true,
	OpAMD64CMPLloadidx4: true,
	OpAMD64CMPQloadidx8: true,

	OpAMD64CMPBconstloadidx1: true,
	OpAMD64CMPWconstloadidx1: true,
	OpAMD64CMPLconstloadidx1: true,
	OpAMD64CMPQconstloadidx1: true,
	OpAMD64CMPWconstloadidx2: true,
	OpAMD64CMPLconstloadidx4: true,
	OpAMD64CMPQconstloadidx8: true,
}

// For each entry k, v in this map, if we have a value x with:
//
//	x.Op == k[0]
//	x.Args[0].Op == k[1]
//
// then we can set x.Op to v and set x.Args like this:
//
//	x.Args[0].Args + x.Args[1:]
//
// Additionally, the Aux/AuxInt from x.Args[0] is merged into x.
var combine = map[[2]Op]Op{
	// amd64
	[2]Op{OpAMD64MOVBload, OpAMD64ADDQ}:  OpAMD64MOVBloadidx1,
	[2]Op{OpAMD64MOVWload, OpAMD64ADDQ}:  OpAMD64MOVWloadidx1,
	[2]Op{OpAMD64MOVLload, OpAMD64ADDQ}:  OpAMD64MOVLloadidx1,
	[2]Op{OpAMD64MOVQload, OpAMD64ADDQ}:  OpAMD64MOVQloadidx1,
	[2]Op{OpAMD64MOVSSload, OpAMD64ADDQ}: OpAMD64MOVSSloadidx1,
	[2]Op{OpAMD64MOVSDload, OpAMD64ADDQ}: OpAMD64MOVSDloadidx1,

	[2]Op{OpAMD64MOVBstore, OpAMD64ADDQ}:  OpAMD64MOVBstoreidx1,
	[2]Op{OpAMD64MOVWstore, OpAMD64ADDQ}:  OpAMD64MOVWstoreidx1,
	[2]Op{OpAMD64MOVLstore, OpAMD64ADDQ}:  OpAMD64MOVLstoreidx1,
	[2]Op{OpAMD64MOVQstore, OpAMD64ADDQ}:  OpAMD64MOVQstoreidx1,
	[2]Op{OpAMD64MOVSSstore, OpAMD64ADDQ}: OpAMD64MOVSSstoreidx1,
	[2]Op{OpAMD64MOVSDstore, OpAMD64ADDQ}: OpAMD64MOVSDstoreidx1,

	[2]Op{OpAMD64MOVBstoreconst, OpAMD64ADDQ}: OpAMD64MOVBstoreconstidx1,
	[2]Op{OpAMD64MOVWstoreconst, OpAMD64ADDQ}: OpAMD64MOVWstoreconstidx1,
	[2]Op{OpAMD64MOVLstoreconst, OpAMD64ADDQ}: OpAMD64MOVLstoreconstidx1,
	[2]Op{OpAMD64MOVQstoreconst, OpAMD64ADDQ}: OpAMD64MOVQstoreconstidx1,

	[2]Op{OpAMD64MOVBload, OpAMD64LEAQ1}:  OpAMD64MOVBloadidx1,
	[2]Op{OpAMD64MOVWload, OpAMD64LEAQ1}:  OpAMD64MOVWloadidx1,
	[2]Op{OpAMD64MOVWload, OpAMD64LEAQ2}:  OpAMD64MOVWloadidx2,
	[2]Op{OpAMD64MOVLload, OpAMD64LEAQ1}:  OpAMD64MOVLloadidx1,
	[2]Op{OpAMD64MOVLload, OpAMD64LEAQ4}:  OpAMD64MOVLloadidx4,
	[2]Op{OpAMD64MOVLload, OpAMD64LEAQ8}:  OpAMD64MOVLloadidx8,
	[2]Op{OpAMD64MOVQload, OpAMD64LEAQ1}:  OpAMD64MOVQloadidx1,
	[2]Op{OpAMD64MOVQload, OpAMD64LEAQ8}:  OpAMD64MOVQloadidx8,
	[2]Op{OpAMD64MOVSSload, OpAMD64LEAQ1}: OpAMD64MOVSSloadidx1,
	[2]Op{OpAMD64MOVSSload, OpAMD64LEAQ4}: OpAMD64MOVSSloadidx4,
	[2]Op{OpAMD64MOVSDload, OpAMD64LEAQ1}: OpAMD64MOVSDloadidx1,
	[2]Op{OpAMD64MOVSDload, OpAMD64LEAQ8}: OpAMD64MOVSDloadidx8,

	[2]Op{OpAMD64MOVBstore, OpAMD64LEAQ1}:  OpAMD64MOVBstoreidx1,
	[2]Op{OpAMD64MOVWstore, OpAMD64LEAQ1}:  OpAMD64MOVWstoreidx1,
	[2]Op{OpAMD64MOVWstore, OpAMD64LEAQ2}:  OpAMD64MOVWstoreidx2,
	[2]Op{OpAMD64MOVLstore, OpAMD64LEAQ1}:  OpAMD64MOVLstoreidx1,
	[2]Op{OpAMD64MOVLstore, OpAMD64LEAQ4}:  OpAMD64MOVLstoreidx4,
	[2]Op{OpAMD64MOVLstore, OpAMD64LEAQ8}:  OpAMD64MOVLstoreidx8,
	[2]Op{OpAMD64MOVQstore, OpAMD64LEAQ1}:  OpAMD64MOVQstoreidx1,
	[2]Op{OpAMD64MOVQstore, OpAMD64LEAQ8}:  OpAMD64MOVQstoreidx8,
	[2]Op{OpAMD64MOVSSstore, OpAMD64LEAQ1}: OpAMD64MOVSSstoreidx1,
	[2]Op{OpAMD64MOVSSstore, OpAMD64LEAQ4}: OpAMD64MOVSSstoreidx4,
	[2]Op{OpAMD64MOVSDstore, OpAMD64LEAQ1}: OpAMD64MOVSDstoreidx1,
	[2]Op{OpAMD64MOVSDstore, OpAMD64LEAQ8}: OpAMD64MOVSDstoreidx8,

	[2]Op{OpAMD64MOVBstoreconst, OpAMD64LEAQ1}: OpAMD64MOVBstoreconstidx1,
	[2]Op{OpAMD64MOVWstoreconst, OpAMD64LEAQ1}: OpAMD64MOVWstoreconstidx1,
	[2]Op{OpAMD64MOVWstoreconst, OpAMD64LEAQ2}: OpAMD64MOVWstoreconstidx2,
	[2]Op{OpAMD64MOVLstoreconst, OpAMD64LEAQ1}: OpAMD64MOVLstoreconstidx1,
	[2]Op{OpAMD64MOVLstoreconst, OpAMD64LEAQ4}: OpAMD64MOVLstoreconstidx4,
	[2]Op{OpAMD64MOVQstoreconst, OpAMD64LEAQ1}: OpAMD64MOVQstoreconstidx1,
	[2]Op{OpAMD64MOVQstoreconst, OpAMD64LEAQ8}: OpAMD64MOVQstoreconstidx8,

	[2]Op{OpAMD64SETEQstore, OpAMD64LEAQ1}: OpAMD64SETEQstoreidx1,
	[2]Op{OpAMD64SETNEstore, OpAMD64LEAQ1}: OpAMD64SETNEstoreidx1,
	[2]Op{OpAMD64SETLstore, OpAMD64LEAQ1}:  OpAMD64SETLstoreidx1,
	[2]Op{OpAMD64SETLEstore, OpAMD64LEAQ1}: OpAMD64SETLEstoreidx1,
	[2]Op{OpAMD64SETGstore, OpAMD64LEAQ1}:  OpAMD64SETGstoreidx1,
	[2]Op{OpAMD64SETGEstore, OpAMD64LEAQ1}: OpAMD64SETGEstoreidx1,
	[2]Op{OpAMD64SETBstore, OpAMD64LEAQ1}:  OpAMD64SETBstoreidx1,
	[2]Op{OpAMD64SETBEstore, OpAMD64LEAQ1}: OpAMD64SETBEstoreidx1,
	[2]Op{OpAMD64SETAstore, OpAMD64LEAQ1}:  OpAMD64SETAstoreidx1,
	[2]Op{OpAMD64SETAEstore, OpAMD64LEAQ1}: OpAMD64SETAEstoreidx1,

	// These instructions are re-split differently for performance, see needSplit above.
	// TODO if 386 versions are created, also update needSplit and _gen/386splitload.rules
	[2]Op{OpAMD64CMPBload, OpAMD64ADDQ}: OpAMD64CMPBloadidx1,
	[2]Op{OpAMD64CMPWload, OpAMD64ADDQ}: OpAMD64CMPWloadidx1,
	[2]Op{OpAMD64CMPLload, OpAMD64ADDQ}: OpAMD64CMPLloadidx1,
	[2]Op{OpAMD64CMPQload, OpAMD64ADDQ}: OpAMD64CMPQloadidx1,

	[2]Op{OpAMD64CMPBload, OpAMD64LEAQ1}: OpAMD64CMPBloadidx1,
	[2]Op{OpAMD64CMPWload, OpAMD64LEAQ1}: OpAMD64CMPWloadidx1,
	[2]Op{OpAMD64CMPWload, OpAMD64LEAQ2}: OpAMD64CMPWloadidx2,
	[2]Op{OpAMD64CMPLload, OpAMD64LEAQ1}: OpAMD64CMPLloadidx1,
	[2]Op{OpAMD64CMPLload, OpAMD64LEAQ4}: OpAMD64CMPLloadidx4,
	[2]Op{OpAMD64CMPQload, OpAMD64LEAQ1}: OpAMD64CMPQloadidx1,
	[2]Op{OpAMD64CMPQload, OpAMD64LEAQ8}: OpAMD64CMPQloadidx8,

	[2]Op{OpAMD64CMPBconstload, OpAMD64ADDQ}: OpAMD64CMPBconstloadidx1,
	[2]Op{OpAMD64CMPWconstload, OpAMD64ADDQ}: OpAMD64CMPWconstloadidx1,
	[2]Op{OpAMD64CMPLconstload, OpAMD64ADDQ}: OpAMD64CMPLconstloadidx1,
	[2]Op{OpAMD64CMPQconstload, OpAMD64ADDQ}: OpAMD64CMPQconstloadidx1,

	[2]Op{OpAMD64CMPBconstload, OpAMD64LEAQ1}: OpAMD64CMPBconstloadidx1,
	[2]Op{OpAMD64CMPWconstload, OpAMD64LEAQ1}: OpAMD64CMPWconstloadidx1,
	[2]Op{OpAMD64CMPWconstload, OpAMD64LEAQ2}: OpAMD64CMPWconstloadidx2,
	[2]Op{OpAMD64CMPLconstload, OpAMD64LEAQ1}: OpAMD64CMPLconstloadidx1,
	[2]Op{OpAMD64CMPLconstload, OpAMD64LEAQ4}: OpAMD64CMPLconstloadidx4,
	[2]Op{OpAMD64CMPQconstload, OpAMD64LEAQ1}: OpAMD64CMPQconstloadidx1,
	[2]Op{OpAMD64CMPQconstload, OpAMD64LEAQ8}: OpAMD64CMPQconstloadidx8,

	[2]Op{OpAMD64ADDLload, OpAMD64ADDQ}: OpAMD64ADDLloadidx1,
	[2]Op{OpAMD64ADDQload, OpAMD64ADDQ}: OpAMD64ADDQloadidx1,
	[2]Op{OpAMD64SUBLload, OpAMD64ADDQ}: OpAMD64SUBLloadidx1,
	[2]Op{OpAMD64SUBQload, OpAMD64ADDQ}: OpAMD64SUBQloadidx1,
	[2]Op{OpAMD64ANDLload, OpAMD64ADDQ}: OpAMD64ANDLloadidx1,
	[2]Op{OpAMD64ANDQload, OpAMD64ADDQ}: OpAMD64ANDQloadidx1,
	[2]Op{OpAMD64ORLload, OpAMD64ADDQ}:  OpAMD64ORLloadidx1,
	[2]Op{OpAMD64ORQload, OpAMD64ADDQ}:  OpAMD64ORQloadidx1,
	[2]Op{OpAMD64XORLload, OpAMD64ADDQ}: OpAMD64XORLloadidx1,
	[2]Op{OpAMD64XORQload, OpAMD64ADDQ}: OpAMD64XORQloadidx1,

	[2]Op{OpAMD64ADDLload, OpAMD64LEAQ1}: OpAMD64ADDLloadidx1,
	[2]Op{OpAMD64ADDLload, OpAMD64LEAQ4}: OpAMD64ADDLloadidx4,
	[2]Op{OpAMD64ADDLload, OpAMD64LEAQ8}: OpAMD64ADDLloadidx8,
	[2]Op{OpAMD64ADDQload, OpAMD64LEAQ1}: OpAMD64ADDQloadidx1,
	[2]Op{OpAMD64ADDQload, OpAMD64LEAQ8}: OpAMD64ADDQloadidx8,
	[2]Op{OpAMD64SUBLload, OpAMD64LEAQ1}: OpAMD64SUBLloadidx1,
	[2]Op{OpAMD64SUBLload, OpAMD64LEAQ4}: OpAMD64SUBLloadidx4,
	[2]Op{OpAMD64SUBLload, OpAMD64LEAQ8}: OpAMD64SUBLloadidx8,
	[2]Op{OpAMD64SUBQload, OpAMD64LEAQ1}: OpAMD64SUBQloadidx1,
	[2]Op{OpAMD64SUBQload, OpAMD64LEAQ8}: OpAMD64SUBQloadidx8,
	[2]Op{OpAMD64ANDLload, OpAMD64LEAQ1}: OpAMD64ANDLloadidx1,
	[2]Op{OpAMD64ANDLload, OpAMD64LEAQ4}: OpAMD64ANDLloadidx4,
	[2]Op{OpAMD64ANDLload, OpAMD64LEAQ8}: OpAMD64ANDLloadidx8,
	[2]Op{OpAMD64ANDQload, OpAMD64LEAQ1}: OpAMD64ANDQloadidx1,
	[2]Op{OpAMD64ANDQload, OpAMD64LEAQ8}: OpAMD64ANDQloadidx8,
	[2]Op{OpAMD64ORLload, OpAMD64LEAQ1}:  OpAMD64ORLloadidx1,
	[2]Op{OpAMD64ORLload, OpAMD64LEAQ4}:  OpAMD64ORLloadidx4,
	[2]Op{OpAMD64ORLload, OpAMD64LEAQ8}:  OpAMD64ORLloadidx8,
	[2]Op{OpAMD64ORQload, OpAMD64LEAQ1}:  OpAMD64ORQloadidx1,
	[2]Op{OpAMD64ORQload, OpAMD64LEAQ8}:  OpAMD64ORQloadidx8,
	[2]Op{OpAMD64XORLload, OpAMD64LEAQ1}: OpAMD64XORLloadidx1,
	[2]Op{OpAMD64XORLload, OpAMD64LEAQ4}: OpAMD64XORLloadidx4,
	[2]Op{OpAMD64XORLload, OpAMD64LEAQ8}: OpAMD64XORLloadidx8,
	[2]Op{OpAMD64XORQload, OpAMD64LEAQ1}: OpAMD64XORQloadidx1,
	[2]Op{OpAMD64XORQload, OpAMD64LEAQ8}: OpAMD64XORQloadidx8,

	[2]Op{OpAMD64ADDLmodify, OpAMD64ADDQ}: OpAMD64ADDLmodifyidx1,
	[2]Op{OpAMD64ADDQmodify, OpAMD64ADDQ}: OpAMD64ADDQmodifyidx1,
	[2]Op{OpAMD64SUBLmodify, OpAMD64ADDQ}: OpAMD64SUBLmodifyidx1,
	[2]Op{OpAMD64SUBQmodify, OpAMD64ADDQ}: OpAMD64SUBQmodifyidx1,
	[2]Op{OpAMD64ANDLmodify, OpAMD64ADDQ}: OpAMD64ANDLmodifyidx1,
	[2]Op{OpAMD64ANDQmodify, OpAMD64ADDQ}: OpAMD64ANDQmodifyidx1,
	[2]Op{OpAMD64ORLmodify, OpAMD64ADDQ}:  OpAMD64ORLmodifyidx1,
	[2]Op{OpAMD64ORQmodify, OpAMD64ADDQ}:  OpAMD64ORQmodifyidx1,
	[2]Op{OpAMD64XORLmodify, OpAMD64ADDQ}: OpAMD64XORLmodifyidx1,
	[2]Op{OpAMD64XORQmodify, OpAMD64ADDQ}: OpAMD64XORQmodifyidx1,

	[2]Op{OpAMD64ADDLmodify, OpAMD64LEAQ1}: OpAMD64ADDLmodifyidx1,
	[2]Op{OpAMD64ADDLmodify, OpAMD64LEAQ4}: OpAMD64ADDLmodifyidx4,
	[2]Op{OpAMD64ADDLmodify, OpAMD64LEAQ8}: OpAMD64ADDLmodifyidx8,
	[2]Op{OpAMD64ADDQmodify, OpAMD64LEAQ1}: OpAMD64ADDQmodifyidx1,
	[2]Op{OpAMD64ADDQmodify, OpAMD64LEAQ8}: OpAMD64ADDQmodifyidx8,
	[2]Op{OpAMD64SUBLmodify, OpAMD64LEAQ1}: OpAMD64SUBLmodifyidx1,
	[2]Op{OpAMD64SUBLmodify, OpAMD64LEAQ4}: OpAMD64SUBLmodifyidx4,
	[2]Op{OpAMD64SUBLmodify, OpAMD64LEAQ8}: OpAMD64SUBLmodifyidx8,
	[2]Op{OpAMD64SUBQmodify, OpAMD64LEAQ1}: OpAMD64SUBQmodifyidx1,
	[2]Op{OpAMD64SUBQmodify, OpAMD64LEAQ8}: OpAMD64SUBQmodifyidx8,
	[2]Op{OpAMD64ANDLmodify, OpAMD64LEAQ1}: OpAMD64ANDLmodifyidx1,
	[2]Op{OpAMD64ANDLmodify, OpAMD64LEAQ4}: OpAMD64ANDLmodifyidx4,
	[2]Op{OpAMD64ANDLmodify, OpAMD64LEAQ8}: OpAMD64ANDLmodifyidx8,
	[2]Op{OpAMD64ANDQmodify, OpAMD64LEAQ1}: OpAMD64ANDQmodifyidx1,
	[2]Op{OpAMD64ANDQmodify, OpAMD64LEAQ8}: OpAMD64ANDQmodifyidx8,
	[2]Op{OpAMD64ORLmodify, OpAMD64LEAQ1}:  OpAMD64ORLmodifyidx1,
	[2]Op{OpAMD64ORLmodify, OpAMD64LEAQ4}:  OpAMD64ORLmodifyidx4,
	[2]Op{OpAMD64ORLmodify, OpAMD64LEAQ8}:  OpAMD64ORLmodifyidx8,
	[2]Op{OpAMD64ORQmodify, OpAMD64LEAQ1}:  OpAMD64ORQmodifyidx1,
	[2]Op{OpAMD64ORQmodify, OpAMD64LEAQ8}:  OpAMD64ORQmodifyidx8,
	[2]Op{OpAMD64XORLmodify, OpAMD64LEAQ1}: OpAMD64XORLmodifyidx1,
	[2]Op{OpAMD64XORLmodify, OpAMD64LEAQ4}: OpAMD64XORLmodifyidx4,
	[2]Op{OpAMD64XORLmodify, OpAMD64LEAQ8}: OpAMD64XORLmodifyidx8,
	[2]Op{OpAMD64XORQmodify, OpAMD64LEAQ1}: OpAMD64XORQmodifyidx1,
	[2]Op{OpAMD64XORQmodify, OpAMD64LEAQ8}: OpAMD64XORQmodifyidx8,

	[2]Op{OpAMD64ADDLconstmodify, OpAMD64ADDQ}: OpAMD64ADDLconstmodifyidx1,
	[2]Op{OpAMD64ADDQconstmodify, OpAMD64ADDQ}: OpAMD64ADDQconstmodifyidx1,
	[2]Op{OpAMD64ANDLconstmodify, OpAMD64ADDQ}: OpAMD64ANDLconstmodifyidx1,
	[2]Op{OpAMD64ANDQconstmodify, OpAMD64ADDQ}: OpAMD64ANDQconstmodifyidx1,
	[2]Op{OpAMD64ORLconstmodify, OpAMD64ADDQ}:  OpAMD64ORLconstmodifyidx1,
	[2]Op{OpAMD64ORQconstmodify, OpAMD64ADDQ}:  OpAMD64ORQconstmodifyidx1,
	[2]Op{OpAMD64XORLconstmodify, OpAMD64ADDQ}: OpAMD64XORLconstmodifyidx1,
	[2]Op{OpAMD64XORQconstmodify, OpAMD64ADDQ}: OpAMD64XORQconstmodifyidx1,

	[2]Op{OpAMD64ADDLconstmodify, OpAMD64LEAQ1}: OpAMD64ADDLconstmodifyidx1,
	[2]Op{OpAMD64ADDLconstmodify, OpAMD64LEAQ4}: OpAMD64ADDLconstmodifyidx4,
	[2]Op{OpAMD64ADDLconstmodify, OpAMD64LEAQ8}: OpAMD64ADDLconstmodifyidx8,
	[2]Op{OpAMD64ADDQconstmodify, OpAMD64LEAQ1}: OpAMD64ADDQconstmodifyidx1,
	[2]Op{OpAMD64ADDQconstmodify, OpAMD64LEAQ8}: OpAMD64ADDQconstmodifyidx8,
	[2]Op{OpAMD64ANDLconstmodify, OpAMD64LEAQ1}: OpAMD64ANDLconstmodifyidx1,
	[2]Op{OpAMD64ANDLconstmodify, OpAMD64LEAQ4}: OpAMD64ANDLconstmodifyidx4,
	[2]Op{OpAMD64ANDLconstmodify, OpAMD64LEAQ8}: OpAMD64ANDLconstmodifyidx8,
	[2]Op{OpAMD64ANDQconstmodify, OpAMD64LEAQ1}: OpAMD64ANDQconstmodifyidx1,
	[2]Op{OpAMD64ANDQconstmodify, OpAMD64LEAQ8}: OpAMD64ANDQconstmodifyidx8,
	[2]Op{OpAMD64ORLconstmodify, OpAMD64LEAQ1}:  OpAMD64ORLconstmodifyidx1,
	[2]Op{OpAMD64ORLconstmodify, OpAMD64LEAQ4}:  OpAMD64ORLconstmodifyidx4,
	[2]Op{OpAMD64ORLconstmodify, OpAMD64LEAQ8}:  OpAMD64ORLconstmodifyidx8,
	[2]Op{OpAMD64ORQconstmodify, OpAMD64LEAQ1}:  OpAMD64ORQconstmodifyidx1,
	[2]Op{OpAMD64ORQconstmodify, OpAMD64LEAQ8}:  OpAMD64ORQconstmodifyidx8,
	[2]Op{OpAMD64XORLconstmodify, OpAMD64LEAQ1}: OpAMD64XORLconstmodifyidx1,
	[2]Op{OpAMD64XORLconstmodify, OpAMD64LEAQ4}: OpAMD64XORLconstmodifyidx4,
	[2]Op{OpAMD64XORLconstmodify, OpAMD64LEAQ8}: OpAMD64XORLconstmodifyidx8,
	[2]Op{OpAMD64XORQconstmodify, OpAMD64LEAQ1}: OpAMD64XORQconstmodifyidx1,
	[2]Op{OpAMD64XORQconstmodify, OpAMD64LEAQ8}: OpAMD64XORQconstmodifyidx8,

	[2]Op{OpAMD64ADDSSload, OpAMD64LEAQ1}: OpAMD64ADDSSloadidx1,
	[2]Op{OpAMD64ADDSSload, OpAMD64LEAQ4}: OpAMD64ADDSSloadidx4,
	[2]Op{OpAMD64ADDSDload, OpAMD64LEAQ1}: OpAMD64ADDSDloadidx1,
	[2]Op{OpAMD64ADDSDload, OpAMD64LEAQ8}: OpAMD64ADDSDloadidx8,
	[2]Op{OpAMD64SUBSSload, OpAMD64LEAQ1}: OpAMD64SUBSSloadidx1,
	[2]Op{OpAMD64SUBSSload, OpAMD64LEAQ4}: OpAMD64SUBSSloadidx4,
	[2]Op{OpAMD64SUBSDload, OpAMD64LEAQ1}: OpAMD64SUBSDloadidx1,
	[2]Op{OpAMD64SUBSDload, OpAMD64LEAQ8}: OpAMD64SUBSDloadidx8,
	[2]Op{OpAMD64MULSSload, OpAMD64LEAQ1}: OpAMD64MULSSloadidx1,
	[2]Op{OpAMD64MULSSload, OpAMD64LEAQ4}: OpAMD64MULSSloadidx4,
	[2]Op{OpAMD64MULSDload, OpAMD64LEAQ1}: OpAMD64MULSDloadidx1,
	[2]Op{OpAMD64MULSDload, OpAMD64LEAQ8}: OpAMD64MULSDloadidx8,
	[2]Op{OpAMD64DIVSSload, OpAMD64LEAQ1}: OpAMD64DIVSSloadidx1,
	[2]Op{OpAMD64DIVSSload, OpAMD64LEAQ4}: OpAMD64DIVSSloadidx4,
	[2]Op{OpAMD64DIVSDload, OpAMD64LEAQ1}: OpAMD64DIVSDloadidx1,
	[2]Op{OpAMD64DIVSDload, OpAMD64LEAQ8}: OpAMD64DIVSDloadidx8,

	[2]Op{OpAMD64SARXLload, OpAMD64ADDQ}: OpAMD64SARXLloadidx1,
	[2]Op{OpAMD64SARXQload, OpAMD64ADDQ}: OpAMD64SARXQloadidx1,
	[2]Op{OpAMD64SHLXLload, OpAMD64ADDQ}: OpAMD64SHLXLloadidx1,
	[2]Op{OpAMD64SHLXQload, OpAMD64ADDQ}: OpAMD64SHLXQloadidx1,
	[2]Op{OpAMD64SHRXLload, OpAMD64ADDQ}: OpAMD64SHRXLloadidx1,
	[2]Op{OpAMD64SHRXQload, OpAMD64ADDQ}: OpAMD64SHRXQloadidx1,

	[2]Op{OpAMD64SARXLload, OpAMD64LEAQ1}: OpAMD64SARXLloadidx1,
	[2]Op{OpAMD64SARXLload, OpAMD64LEAQ4}: OpAMD64SARXLloadidx4,
	[2]Op{OpAMD64SARXLload, OpAMD64LEAQ8}: OpAMD64SARXLloadidx8,
	[2]Op{OpAMD64SARXQload, OpAMD64LEAQ1}: OpAMD64SARXQloadidx1,
	[2]Op{OpAMD64SARXQload, OpAMD64LEAQ8}: OpAMD64SARXQloadidx8,
	[2]Op{OpAMD64SHLXLload, OpAMD64LEAQ1}: OpAMD64SHLXLloadidx1,
	[2]Op{OpAMD64SHLXLload, OpAMD64LEAQ4}: OpAMD64SHLXLloadidx4,
	[2]Op{OpAMD64SHLXLload, OpAMD64LEAQ8}: OpAMD64SHLXLloadidx8,
	[2]Op{OpAMD64SHLXQload, OpAMD64LEAQ1}: OpAMD64SHLXQloadidx1,
	[2]Op{OpAMD64SHLXQload, OpAMD64LEAQ8}: OpAMD64SHLXQloadidx8,
	[2]Op{OpAMD64SHRXLload, OpAMD64LEAQ1}: OpAMD64SHRXLloadidx1,
	[2]Op{OpAMD64SHRXLload, OpAMD64LEAQ4}: OpAMD64SHRXLloadidx4,
	[2]Op{OpAMD64SHRXLload, OpAMD64LEAQ8}: OpAMD64SHRXLloadidx8,
	[2]Op{OpAMD64SHRXQload, OpAMD64LEAQ1}: OpAMD64SHRXQloadidx1,
	[2]Op{OpAMD64SHRXQload, OpAMD64LEAQ8}: OpAMD64SHRXQloadidx8,

	// amd64/v3
	[2]Op{OpAMD64MOVBELload, OpAMD64ADDQ}:  OpAMD64MOVBELloadidx1,
	[2]Op{OpAMD64MOVBEQload, OpAMD64ADDQ}:  OpAMD64MOVBEQloadidx1,
	[2]Op{OpAMD64MOVBELload, OpAMD64LEAQ1}: OpAMD64MOVBELloadidx1,
	[2]Op{OpAMD64MOVBELload, OpAMD64LEAQ4}: OpAMD64MOVBELloadidx4,
	[2]Op{OpAMD64MOVBELload, OpAMD64LEAQ8}: OpAMD64MOVBELloadidx8,
	[2]Op{OpAMD64MOVBEQload, OpAMD64LEAQ1}: OpAMD64MOVBEQloadidx1,
	[2]Op{OpAMD64MOVBEQload, OpAMD64LEAQ8}: OpAMD64MOVBEQloadidx8,

	[2]Op{OpAMD64MOVBEWstore, OpAMD64ADDQ}:  OpAMD64MOVBEWstoreidx1,
	[2]Op{OpAMD64MOVBELstore, OpAMD64ADDQ}:  OpAMD64MOVBELstoreidx1,
	[2]Op{OpAMD64MOVBEQstore, OpAMD64ADDQ}:  OpAMD64MOVBEQstoreidx1,
	[2]Op{OpAMD64MOVBEWstore, OpAMD64LEAQ1}: OpAMD64MOVBEWstoreidx1,
	[2]Op{OpAMD64MOVBEWstore, OpAMD64LEAQ2}: OpAMD64MOVBEWstoreidx2,
	[2]Op{OpAMD64MOVBELstore, OpAMD64LEAQ1}: OpAMD64MOVBELstoreidx1,
	[2]Op{OpAMD64MOVBELstore, OpAMD64LEAQ4}: OpAMD64MOVBELstoreidx4,
	[2]Op{OpAMD64MOVBELstore, OpAMD64LEAQ8}: OpAMD64MOVBELstoreidx8,
	[2]Op{OpAMD64MOVBEQstore, OpAMD64LEAQ1}: OpAMD64MOVBEQstoreidx1,
	[2]Op{OpAMD64MOVBEQstore, OpAMD64LEAQ8}: OpAMD64MOVBEQstoreidx8,

	// 386
	[2]Op{Op386MOVBload, Op386ADDL}:  Op386MOVBloadidx1,
	[2]Op{Op386MOVWload, Op386ADDL}:  Op386MOVWloadidx1,
	[2]Op{Op386MOVLload, Op386ADDL}:  Op386MOVLloadidx1,
	[2]Op{Op386MOVSSload, Op386ADDL}: Op386MOVSSloadidx1,
	[2]Op{Op386MOVSDload, Op386ADDL}: Op386MOVSDloadidx1,

	[2]Op{Op386MOVBstore, Op386ADDL}:  Op386MOVBstoreidx1,
	[2]Op{Op386MOVWstore, Op386ADDL}:  Op386MOVWstoreidx1,
	[2]Op{Op386MOVLstore, Op386ADDL}:  Op386MOVLstoreidx1,
	[2]Op{Op386MOVSSstore, Op386ADDL}: Op386MOVSSstoreidx1,
	[2]Op{Op386MOVSDstore, Op386ADDL}: Op386MOVSDstoreidx1,

	[2]Op{Op386MOVBstoreconst, Op386ADDL}: Op386MOVBstoreconstidx1,
	[2]Op{Op386MOVWstoreconst, Op386ADDL}: Op386MOVWstoreconstidx1,
	[2]Op{Op386MOVLstoreconst, Op386ADDL}: Op386MOVLstoreconstidx1,

	[2]Op{Op386MOVBload, Op386LEAL1}:  Op386MOVBloadidx1,
	[2]Op{Op386MOVWload, Op386LEAL1}:  Op386MOVWloadidx1,
	[2]Op{Op386MOVWload, Op386LEAL2}:  Op386MOVWloadidx2,
	[2]Op{Op386MOVLload, Op386LEAL1}:  Op386MOVLloadidx1,
	[2]Op{Op386MOVLload, Op386LEAL4}:  Op386MOVLloadidx4,
	[2]Op{Op386MOVSSload, Op386LEAL1}: Op386MOVSSloadidx1,
	[2]Op{Op386MOVSSload, Op386LEAL4}: Op386MOVSSloadidx4,
	[2]Op{Op386MOVSDload, Op386LEAL1}: Op386MOVSDloadidx1,
	[2]Op{Op386MOVSDload, Op386LEAL8}: Op386MOVSDloadidx8,

	[2]Op{Op386MOVBstore, Op386LEAL1}:  Op386MOVBstoreidx1,
	[2]Op{Op386MOVWstore, Op386LEAL1}:  Op386MOVWstoreidx1,
	[2]Op{Op386MOVWstore, Op386LEAL2}:  Op386MOVWstoreidx2,
	[2]Op{Op386MOVLstore, Op386LEAL1}:  Op386MOVLstoreidx1,
	[2]Op{Op386MOVLstore, Op386LEAL4}:  Op386MOVLstoreidx4,
	[2]Op{Op386MOVSSstore, Op386LEAL1}: Op386MOVSSstoreidx1,
	[2]Op{Op386MOVSSstore, Op386LEAL4}: Op386MOVSSstoreidx4,
	[2]Op{Op386MOVSDstore, Op386LEAL1}: Op386MOVSDstoreidx1,
	[2]Op{Op386MOVSDstore, Op386LEAL8}: Op386MOVSDstoreidx8,

	[2]Op{Op386MOVBstoreconst, Op386LEAL1}: Op386MOVBstoreconstidx1,
	[2]Op{Op386MOVWstoreconst, Op386LEAL1}: Op386MOVWstoreconstidx1,
	[2]Op{Op386MOVWstoreconst, Op386LEAL2}: Op386MOVWstoreconstidx2,
	[2]Op{Op386MOVLstoreconst, Op386LEAL1}: Op386MOVLstoreconstidx1,
	[2]Op{Op386MOVLstoreconst, Op386LEAL4}: Op386MOVLstoreconstidx4,

	[2]Op{Op386ADDLload, Op386LEAL4}: Op386ADDLloadidx4,
	[2]Op{Op386SUBLload, Op386LEAL4}: Op386SUBLloadidx4,
	[2]Op{Op386MULLload, Op386LEAL4}: Op386MULLloadidx4,
	[2]Op{Op386ANDLload, Op386LEAL4}: Op386ANDLloadidx4,
	[2]Op{Op386ORLload, Op386LEAL4}:  Op386ORLloadidx4,
	[2]Op{Op386XORLload, Op386LEAL4}: Op386XORLloadidx4,

	[2]Op{Op386ADDLmodify, Op386LEAL4}: Op386ADDLmodifyidx4,
	[2]Op{Op386SUBLmodify, Op386LEAL4}: Op386SUBLmodifyidx4,
	[2]Op{Op386ANDLmodify, Op386LEAL4}: Op386ANDLmodifyidx4,
	[2]Op{Op386ORLmodify, Op386LEAL4}:  Op386ORLmodifyidx4,
	[2]Op{Op386XORLmodify, Op386LEAL4}: Op386XORLmodifyidx4,

	[2]Op{Op386ADDLconstmodify, Op386LEAL4}: Op386ADDLconstmodifyidx4,
	[2]Op{Op386ANDLconstmodify, Op386LEAL4}: Op386ANDLconstmodifyidx4,
	[2]Op{Op386ORLconstmodify, Op386LEAL4}:  Op386ORLconstmodifyidx4,
	[2]Op{Op386XORLconstmodify, Op386LEAL4}: Op386XORLconstmodifyidx4,

	// s390x
	[2]Op{OpS390XMOVDload, OpS390XADD}: OpS390XMOVDloadidx,
	[2]Op{OpS390XMOVWload, OpS390XADD}: OpS390XMOVWloadidx,
	[2]Op{OpS390XMOVHload, OpS390XADD}: OpS390XMOVHloadidx,
	[2]Op{OpS390XMOVBload, OpS390XADD}: OpS390XMOVBloadidx,

	[2]Op{OpS390XMOVWZload, OpS390XADD}: OpS390XMOVWZloadidx,
	[2]Op{OpS390XMOVHZload, OpS390XADD}: OpS390XMOVHZloadidx,
	[2]Op{OpS390XMOVBZload, OpS390XADD}: OpS390XMOVBZloadidx,

	[2]Op{OpS390XMOVDBRload, OpS390XADD}: OpS390XMOVDBRloadidx,
	[2]Op{OpS390XMOVWBRload, OpS390XADD}: OpS390XMOVWBRloadidx,
	[2]Op{OpS390XMOVHBRload, OpS390XADD}: OpS390XMOVHBRloadidx,

	[2]Op{OpS390XFMOVDload, OpS390XADD}: OpS390XFMOVDloadidx,
	[2]Op{OpS390XFMOVSload, OpS390XADD}: OpS390XFMOVSloadidx,

	[2]Op{OpS390XMOVDstore, OpS390XADD}: OpS390XMOVDstoreidx,
	[2]Op{OpS390XMOVWstore, OpS390XADD}: OpS390XMOVWstoreidx,
	[2]Op{OpS390XMOVHstore, OpS390XADD}: OpS390XMOVHstoreidx,
	[2]Op{OpS390XMOVBstore, OpS390XADD}: OpS390XMOVBstoreidx,

	[2]Op{OpS390XMOVDBRstore, OpS390XADD}: OpS390XMOVDBRstoreidx,
	[2]Op{OpS390XMOVWBRstore, OpS390XADD}: OpS390XMOVWBRstoreidx,
	[2]Op{OpS390XMOVHBRstore, OpS390XADD}: OpS390XMOVHBRstoreidx,

	[2]Op{OpS390XFMOVDstore, OpS390XADD}: OpS390XFMOVDstoreidx,
	[2]Op{OpS390XFMOVSstore, OpS390XADD}: OpS390XFMOVSstoreidx,

	[2]Op{OpS390XMOVDload, OpS390XMOVDaddridx}: OpS390XMOVDloadidx,
	[2]Op{OpS390XMOVWload, OpS390XMOVDaddridx}: OpS390XMOVWloadidx,
	[2]Op{OpS390XMOVHload, OpS390XMOVDaddridx}: OpS390XMOVHloadidx,
	[2]Op{OpS390XMOVBload, OpS390XMOVDaddridx}: OpS390XMOVBloadidx,

	[2]Op{OpS390XMOVWZload, OpS390XMOVDaddridx}: OpS390XMOVWZloadidx,
	[2]Op{OpS390XMOVHZload, OpS390XMOVDaddridx}: OpS390XMOVHZloadidx,
	[2]Op{OpS390XMOVBZload, OpS390XMOVDaddridx}: OpS390XMOVBZloadidx,

	[2]Op{OpS390XMOVDBRload, OpS390XMOVDaddridx}: OpS390XMOVDBRloadidx,
	[2]Op{OpS390XMOVWBRload, OpS390XMOVDaddridx}: OpS390XMOVWBRloadidx,
	[2]Op{OpS390XMOVHBRload, OpS390XMOVDaddridx}: OpS390XMOVHBRloadidx,

	[2]Op{OpS390XFMOVDload, OpS390XMOVDaddridx}: OpS390XFMOVDloadidx,
	[2]Op{OpS390XFMOVSload, OpS390XMOVDaddridx}: OpS390XFMOVSloadidx,

	[2]Op{OpS390XMOVDstore, OpS390XMOVDaddridx}: OpS390XMOVDstoreidx,
	[2]Op{OpS390XMOVWstore, OpS390XMOVDaddridx}: OpS390XMOVWstoreidx,
	[2]Op{OpS390XMOVHstore, OpS390XMOVDaddridx}: OpS390XMOVHstoreidx,
	[2]Op{OpS390XMOVBstore, OpS390XMOVDaddridx}: OpS390XMOVBstoreidx,

	[2]Op{OpS390XMOVDBRstore, OpS390XMOVDaddridx}: OpS390XMOVDBRstoreidx,
	[2]Op{OpS390XMOVWBRstore, OpS390XMOVDaddridx}: OpS390XMOVWBRstoreidx,
	[2]Op{OpS390XMOVHBRstore, OpS390XMOVDaddridx}: OpS390XMOVHBRstoreidx,

	[2]Op{OpS390XFMOVDstore, OpS390XMOVDaddridx}: OpS390XFMOVDstoreidx,
	[2]Op{OpS390XFMOVSstore, OpS390XMOVDaddridx}: OpS390XFMOVSstoreidx,
}

"""



```