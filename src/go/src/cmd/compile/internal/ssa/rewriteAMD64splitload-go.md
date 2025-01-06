Response: Let's break down the thought process for analyzing the provided Go code.

1. **Understand the Context:** The file path `go/src/cmd/compile/internal/ssa/rewriteAMD64splitload.go` immediately tells us this code is part of the Go compiler, specifically related to the SSA (Static Single Assignment) intermediate representation and targeting the AMD64 architecture. The "rewrite" part suggests optimization or transformation of the SSA. The "splitload" hints at operations involving loading data from memory and perhaps separating those operations.

2. **High-Level Structure:** The code defines a function `rewriteValueAMD64splitload(v *Value) bool` and a series of helper functions named like `rewriteValueAMD64splitload_Op...`. This structure strongly suggests a pattern matching and rewriting approach. The main function dispatches based on the `v.Op` (the operation code of an SSA value).

3. **Focus on `rewriteValueAMD64splitload`:** This function acts as a central dispatcher. It takes an SSA `Value` as input. The `switch v.Op` statement iterates through various AMD64 comparison operations involving loading data (e.g., `OpAMD64CMPBconstload`, `OpAMD64CMPLloadidx4`). The return value `bool` likely indicates whether a rewrite rule was applied.

4. **Analyze Individual `rewriteValueAMD64splitload_Op...` Functions:**  Let's pick one example, `rewriteValueAMD64splitload_OpAMD64CMPBconstload`.

   * **Input:** It takes a `*Value` representing an `OpAMD64CMPBconstload` operation. The arguments are accessed as `v.Args[0]` and `v.Args[1]`, which the code assigns to `ptr` and `mem`.
   * **Matching:** The code uses a `for {}` loop (an infinite loop with `break` conditions) to implement pattern matching. The `// match:` comment describes the pattern being matched: `(CMPBconstload {sym} [vo] ptr mem)`. This means it's looking for a compare-byte-with-constant-loaded operation. `{sym}` and `[vo]` likely represent symbolic information and an offset/value pair associated with the load.
   * **Conditions:** The `// cond:` comments specify conditions for the rewrite. In the first case, it's `vo.Val() == 0`, meaning the constant value being compared against is zero.
   * **Rewriting (Result):**  The `// result:` comment shows the transformed operation: `(TESTB x:(MOVBload {sym} [vo.Off()] ptr mem) x)`. This indicates that when comparing a loaded byte with zero, the comparison is rewritten using a `TESTB` instruction. `TESTB` performs a bitwise AND and sets flags, which is equivalent to comparing with zero for equality. The `MOVBload` instruction loads the byte.
   * **Rewriting (Code):**  The code within the `if` block performs the actual SSA manipulation:
      * `v.reset(OpAMD64TESTB)` changes the operation code of the current value `v`.
      * `b.NewValue0(...)` creates a new SSA value representing the `MOVBload` operation.
      * `v.AddArg2(x, x)` sets the arguments of the `TESTB` operation to the loaded value (effectively testing if the loaded value is zero).
   * **Second Case:** The second `// match:` for `CMPBconstload` handles the case where the constant is *not* zero. It rewrites the operation into a `CMPBconst` (compare byte with constant) where the constant is explicitly provided.

5. **Generalizing the Observations:**

   * **Instruction Set Specialization:** The code is deeply tied to the AMD64 instruction set. It leverages specific instructions like `TESTB`, `TESTL`, `TESTQ` for comparisons with zero, which are often more efficient than a direct `CMP` with zero.
   * **Load Operation Optimization:** The "splitload" name becomes clearer. The code is taking combined compare-and-load operations (like `CMPBconstload`) and, under certain conditions, splitting them into separate load (`MOVBload`, `MOVLload`, etc.) and compare/test operations.
   * **Indexed Addressing:** The presence of `...idx1`, `...idx4`, `...idx8` operations indicates support for indexed memory access (e.g., `array[i]`). The number signifies the scaling factor for the index (e.g., multiplying the index by 1, 4, or 8 bytes).
   * **Constant Optimization:** The `...constload` operations are specifically handling cases where one operand of the comparison is a constant value loaded from memory.

6. **Inferring the Go Feature:**  Based on the operations and transformations, the most likely Go feature being implemented here is **memory access and comparison of basic data types (bytes, words, longs, quads)**. The optimizations are happening at a low level, aiming to generate efficient machine code for these fundamental operations. This is crucial for the performance of Go programs.

7. **Code Example (Hypothetical):**  Since this is compiler-internal code, we can't directly trigger these rewrites with standard Go code. However, we can imagine Go code that *would* lead to these SSA operations:

   ```go
   package main

   func main() {
       var arr [10]int32
       i := 5
       // This might generate CMPLloadidx4 in SSA
       if arr[i] == 10 {
           println("Value is 10")
       }

       var b byte
       // This might generate CMPBconstload in SSA (if b's address is known at compile time)
       if b == 0 {
           println("Byte is zero")
       }
   }
   ```

8. **No Command-Line Arguments or User Errors:** This code is part of the compiler's internal optimization pipeline. It doesn't directly involve command-line arguments or actions that typical Go users would perform. Therefore, there aren't really any user-prone errors at this level.

9. **Review and Refine:** After going through the details, reread the initial request and ensure all aspects have been addressed. Double-check the assumptions and inferences made. For instance, confirming that "vo" likely represents a value and offset was important.

This thought process, starting with the context, dissecting the code structure and individual functions, and then generalizing the observations, helps in understanding the purpose and functionality of such compiler-internal code.
The Go code snippet you provided is a part of the AMD64 backend of the Go compiler, specifically within the SSA (Static Single Assignment) optimization phase. This file, `rewriteAMD64splitload.go`, focuses on **rewriting certain comparison operations that involve loading data from memory to potentially more efficient sequences of instructions.**

Here's a breakdown of its functionality:

**Core Function: `rewriteValueAMD64splitload(v *Value) bool`**

* This is the main function in the snippet. It takes an SSA `Value` (`v`) as input.
* It uses a `switch` statement to check the operation code (`v.Op`) of the input `Value`.
* For each specific operation code (e.g., `OpAMD64CMPBconstload`, `OpAMD64CMPLloadidx4`), it calls a corresponding more specific rewrite function (e.g., `rewriteValueAMD64splitload_OpAMD64CMPBconstload`).
* These specific rewrite functions attempt to transform the input `Value` into a potentially better representation.
* The function returns `true` if a rewrite rule was applied, and `false` otherwise.

**Specific Rewrite Functions (e.g., `rewriteValueAMD64splitload_OpAMD64CMPBconstload`)**

These functions implement the actual rewrite rules. Let's analyze `rewriteValueAMD64splitload_OpAMD64CMPBconstload` as an example:

* **Input:** It receives a `*Value` representing an `OpAMD64CMPBconstload` operation. This operation likely represents comparing a byte loaded from memory with a constant value.
* **Pattern Matching:** It uses a `for` loop with `break` conditions to check if the input `Value` matches a specific pattern. The comments like `// match: (CMPBconstload {sym} [vo] ptr mem)` describe the pattern being looked for.
    * `{sym}` likely represents a symbol (e.g., a global variable name).
    * `[vo]` likely represents a value and offset.
    * `ptr` is the pointer to the memory location.
    * `mem` represents the memory state.
* **Conditions:**  The `// cond:` comments specify the conditions under which the rewrite should occur.
    * **Case 1: `vo.Val() == 0`:** If the constant value being compared against is 0.
    * **Case 2: `vo.Val() != 0`:** If the constant value is not 0.
* **Rewriting (Transformation):** Based on the conditions, the function rewrites the `OpAMD64CMPBconstload` operation into a different sequence of SSA operations.
    * **If `vo.Val() == 0`:** The comparison with a constant 0 is often optimized by using a `TESTB` instruction. The code generates a `MOVBload` to load the byte and then uses `TESTB` to check if it's zero.
    * **If `vo.Val() != 0`:** The code splits the operation into a `MOVBload` to load the byte and then a `CMPBconst` to compare the loaded byte with the non-zero constant.
* **Output:** The function modifies the input `Value` `v` to represent the new sequence of operations and returns `true`.

**General Functionality and Purpose:**

This code is performing a form of **peephole optimization** at the SSA level. It identifies specific patterns of operations and replaces them with equivalent but potentially more efficient instruction sequences for the AMD64 architecture.

The "splitload" in the filename suggests that a common theme is taking operations that combine a load and a comparison and potentially splitting them into separate load and compare instructions. This can be beneficial for various reasons, such as:

* **Improved instruction scheduling:** Separating the load might allow the scheduler to find better opportunities for parallelism or to hide memory latency.
* **Leveraging specific instructions:**  As seen in the `vo.Val() == 0` case, using `TESTB` for comparing with zero is often more efficient than a generic compare instruction.

**Illustrative Go Code Example (and SSA Inference):**

While you don't directly call these functions in your Go code, the compiler uses them during the compilation process. Here's a simplified example of Go code and how it *might* lead to the SSA operations this file is optimizing:

```go
package main

func main() {
	var x byte
	if x == 0 { // This might translate to a CMPBconstload in SSA
		println("x is zero")
	}

	var arr [10]int32
	i := 5
	if arr[i] == 10 { // This might translate to a CMPLloadidx4 in SSA
		println("arr[i] is ten")
	}
}
```

**Hypothetical SSA Representation (before optimization):**

```
// For 'if x == 0'
v1 = LocalAddr {sym: "x"} // Get the address of x
v2 = ConstInt8 [0]        // Constant value 0
v3 = CMPBconstload v1 v2   // Compare byte at address v1 with constant v2

// For 'if arr[i] == 10'
v4 = LocalAddr {sym: "arr"} // Get the address of arr
v5 = LoadReg i             // Load the value of i into a register
v6 = ConstInt32 [10]       // Constant value 10
v7 = CMPLloadidx4 v4 v5 v6  // Compare int32 at arr[i] with constant v6
```

**SSA Representation (after optimization by `rewriteAMD64splitload.go`):**

```
// For 'if x == 0' (if the condition vo.Val() == 0 was met)
v1 = LocalAddr {sym: "x"}
v4 = MOVBload v1           // Load the byte at address v1
v5 = TESTB v4 v4            // Test if v4 is zero

// For 'if arr[i] == 10' (the more general case)
v4 = LocalAddr {sym: "arr"}
v5 = LoadReg i
v8 = MOVLloadidx4 v4 v5    // Load int32 at arr[i]
v9 = ConstInt32 [10]
v10 = CMPL v8 v9           // Compare the loaded value with 10
```

**Code Reasoning and Assumptions:**

The code relies heavily on understanding the specific semantics of AMD64 instructions and how they map to SSA operations. The assumptions are:

* **Correctness of SSA:** The input SSA is assumed to be a correct representation of the Go code.
* **AMD64 Instruction Set Knowledge:** The rewrites are based on the compiler's knowledge of efficient AMD64 instruction sequences.
* **Performance Impact:** The rewrites are intended to improve the performance of the generated machine code.

**No Direct Command-Line Parameters:**

This code operates within the Go compiler's internal optimization pipeline. It doesn't directly interact with command-line parameters that a user would provide.

**Potential User Errors (Indirect):**

Users don't directly interact with this code, so there are no direct user errors. However, understanding how the compiler optimizes code can sometimes be helpful in writing more performant Go. For instance, knowing that comparisons with zero might be specially optimized could subtly influence coding styles in performance-critical sections, although the compiler generally does a good job regardless.

**In summary, `rewriteAMD64splitload.go` is a crucial part of the Go compiler's optimization process for the AMD64 architecture. It identifies opportunities to rewrite comparison operations involving memory loads into more efficient instruction sequences, contributing to the overall performance of Go programs.**

Prompt: 
```
这是路径为go/src/cmd/compile/internal/ssa/rewriteAMD64splitload.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，

"""
// Code generated from _gen/AMD64splitload.rules using 'go generate'; DO NOT EDIT.

package ssa

func rewriteValueAMD64splitload(v *Value) bool {
	switch v.Op {
	case OpAMD64CMPBconstload:
		return rewriteValueAMD64splitload_OpAMD64CMPBconstload(v)
	case OpAMD64CMPBconstloadidx1:
		return rewriteValueAMD64splitload_OpAMD64CMPBconstloadidx1(v)
	case OpAMD64CMPBload:
		return rewriteValueAMD64splitload_OpAMD64CMPBload(v)
	case OpAMD64CMPBloadidx1:
		return rewriteValueAMD64splitload_OpAMD64CMPBloadidx1(v)
	case OpAMD64CMPLconstload:
		return rewriteValueAMD64splitload_OpAMD64CMPLconstload(v)
	case OpAMD64CMPLconstloadidx1:
		return rewriteValueAMD64splitload_OpAMD64CMPLconstloadidx1(v)
	case OpAMD64CMPLconstloadidx4:
		return rewriteValueAMD64splitload_OpAMD64CMPLconstloadidx4(v)
	case OpAMD64CMPLload:
		return rewriteValueAMD64splitload_OpAMD64CMPLload(v)
	case OpAMD64CMPLloadidx1:
		return rewriteValueAMD64splitload_OpAMD64CMPLloadidx1(v)
	case OpAMD64CMPLloadidx4:
		return rewriteValueAMD64splitload_OpAMD64CMPLloadidx4(v)
	case OpAMD64CMPQconstload:
		return rewriteValueAMD64splitload_OpAMD64CMPQconstload(v)
	case OpAMD64CMPQconstloadidx1:
		return rewriteValueAMD64splitload_OpAMD64CMPQconstloadidx1(v)
	case OpAMD64CMPQconstloadidx8:
		return rewriteValueAMD64splitload_OpAMD64CMPQconstloadidx8(v)
	case OpAMD64CMPQload:
		return rewriteValueAMD64splitload_OpAMD64CMPQload(v)
	case OpAMD64CMPQloadidx1:
		return rewriteValueAMD64splitload_OpAMD64CMPQloadidx1(v)
	case OpAMD64CMPQloadidx8:
		return rewriteValueAMD64splitload_OpAMD64CMPQloadidx8(v)
	case OpAMD64CMPWconstload:
		return rewriteValueAMD64splitload_OpAMD64CMPWconstload(v)
	case OpAMD64CMPWconstloadidx1:
		return rewriteValueAMD64splitload_OpAMD64CMPWconstloadidx1(v)
	case OpAMD64CMPWconstloadidx2:
		return rewriteValueAMD64splitload_OpAMD64CMPWconstloadidx2(v)
	case OpAMD64CMPWload:
		return rewriteValueAMD64splitload_OpAMD64CMPWload(v)
	case OpAMD64CMPWloadidx1:
		return rewriteValueAMD64splitload_OpAMD64CMPWloadidx1(v)
	case OpAMD64CMPWloadidx2:
		return rewriteValueAMD64splitload_OpAMD64CMPWloadidx2(v)
	}
	return false
}
func rewriteValueAMD64splitload_OpAMD64CMPBconstload(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (CMPBconstload {sym} [vo] ptr mem)
	// cond: vo.Val() == 0
	// result: (TESTB x:(MOVBload {sym} [vo.Off()] ptr mem) x)
	for {
		vo := auxIntToValAndOff(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		mem := v_1
		if !(vo.Val() == 0) {
			break
		}
		v.reset(OpAMD64TESTB)
		x := b.NewValue0(v.Pos, OpAMD64MOVBload, typ.UInt8)
		x.AuxInt = int32ToAuxInt(vo.Off())
		x.Aux = symToAux(sym)
		x.AddArg2(ptr, mem)
		v.AddArg2(x, x)
		return true
	}
	// match: (CMPBconstload {sym} [vo] ptr mem)
	// cond: vo.Val() != 0
	// result: (CMPBconst (MOVBload {sym} [vo.Off()] ptr mem) [vo.Val8()])
	for {
		vo := auxIntToValAndOff(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		mem := v_1
		if !(vo.Val() != 0) {
			break
		}
		v.reset(OpAMD64CMPBconst)
		v.AuxInt = int8ToAuxInt(vo.Val8())
		v0 := b.NewValue0(v.Pos, OpAMD64MOVBload, typ.UInt8)
		v0.AuxInt = int32ToAuxInt(vo.Off())
		v0.Aux = symToAux(sym)
		v0.AddArg2(ptr, mem)
		v.AddArg(v0)
		return true
	}
	return false
}
func rewriteValueAMD64splitload_OpAMD64CMPBconstloadidx1(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (CMPBconstloadidx1 {sym} [vo] ptr idx mem)
	// cond: vo.Val() == 0
	// result: (TESTB x:(MOVBloadidx1 {sym} [vo.Off()] ptr idx mem) x)
	for {
		vo := auxIntToValAndOff(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		idx := v_1
		mem := v_2
		if !(vo.Val() == 0) {
			break
		}
		v.reset(OpAMD64TESTB)
		x := b.NewValue0(v.Pos, OpAMD64MOVBloadidx1, typ.UInt8)
		x.AuxInt = int32ToAuxInt(vo.Off())
		x.Aux = symToAux(sym)
		x.AddArg3(ptr, idx, mem)
		v.AddArg2(x, x)
		return true
	}
	// match: (CMPBconstloadidx1 {sym} [vo] ptr idx mem)
	// cond: vo.Val() != 0
	// result: (CMPBconst (MOVBloadidx1 {sym} [vo.Off()] ptr idx mem) [vo.Val8()])
	for {
		vo := auxIntToValAndOff(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		idx := v_1
		mem := v_2
		if !(vo.Val() != 0) {
			break
		}
		v.reset(OpAMD64CMPBconst)
		v.AuxInt = int8ToAuxInt(vo.Val8())
		v0 := b.NewValue0(v.Pos, OpAMD64MOVBloadidx1, typ.UInt8)
		v0.AuxInt = int32ToAuxInt(vo.Off())
		v0.Aux = symToAux(sym)
		v0.AddArg3(ptr, idx, mem)
		v.AddArg(v0)
		return true
	}
	return false
}
func rewriteValueAMD64splitload_OpAMD64CMPBload(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (CMPBload {sym} [off] ptr x mem)
	// result: (CMPB (MOVBload {sym} [off] ptr mem) x)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		x := v_1
		mem := v_2
		v.reset(OpAMD64CMPB)
		v0 := b.NewValue0(v.Pos, OpAMD64MOVBload, typ.UInt8)
		v0.AuxInt = int32ToAuxInt(off)
		v0.Aux = symToAux(sym)
		v0.AddArg2(ptr, mem)
		v.AddArg2(v0, x)
		return true
	}
}
func rewriteValueAMD64splitload_OpAMD64CMPBloadidx1(v *Value) bool {
	v_3 := v.Args[3]
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (CMPBloadidx1 {sym} [off] ptr idx x mem)
	// result: (CMPB (MOVBloadidx1 {sym} [off] ptr idx mem) x)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		idx := v_1
		x := v_2
		mem := v_3
		v.reset(OpAMD64CMPB)
		v0 := b.NewValue0(v.Pos, OpAMD64MOVBloadidx1, typ.UInt8)
		v0.AuxInt = int32ToAuxInt(off)
		v0.Aux = symToAux(sym)
		v0.AddArg3(ptr, idx, mem)
		v.AddArg2(v0, x)
		return true
	}
}
func rewriteValueAMD64splitload_OpAMD64CMPLconstload(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (CMPLconstload {sym} [vo] ptr mem)
	// cond: vo.Val() == 0
	// result: (TESTL x:(MOVLload {sym} [vo.Off()] ptr mem) x)
	for {
		vo := auxIntToValAndOff(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		mem := v_1
		if !(vo.Val() == 0) {
			break
		}
		v.reset(OpAMD64TESTL)
		x := b.NewValue0(v.Pos, OpAMD64MOVLload, typ.UInt32)
		x.AuxInt = int32ToAuxInt(vo.Off())
		x.Aux = symToAux(sym)
		x.AddArg2(ptr, mem)
		v.AddArg2(x, x)
		return true
	}
	// match: (CMPLconstload {sym} [vo] ptr mem)
	// cond: vo.Val() != 0
	// result: (CMPLconst (MOVLload {sym} [vo.Off()] ptr mem) [vo.Val()])
	for {
		vo := auxIntToValAndOff(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		mem := v_1
		if !(vo.Val() != 0) {
			break
		}
		v.reset(OpAMD64CMPLconst)
		v.AuxInt = int32ToAuxInt(vo.Val())
		v0 := b.NewValue0(v.Pos, OpAMD64MOVLload, typ.UInt32)
		v0.AuxInt = int32ToAuxInt(vo.Off())
		v0.Aux = symToAux(sym)
		v0.AddArg2(ptr, mem)
		v.AddArg(v0)
		return true
	}
	return false
}
func rewriteValueAMD64splitload_OpAMD64CMPLconstloadidx1(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (CMPLconstloadidx1 {sym} [vo] ptr idx mem)
	// cond: vo.Val() == 0
	// result: (TESTL x:(MOVLloadidx1 {sym} [vo.Off()] ptr idx mem) x)
	for {
		vo := auxIntToValAndOff(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		idx := v_1
		mem := v_2
		if !(vo.Val() == 0) {
			break
		}
		v.reset(OpAMD64TESTL)
		x := b.NewValue0(v.Pos, OpAMD64MOVLloadidx1, typ.UInt32)
		x.AuxInt = int32ToAuxInt(vo.Off())
		x.Aux = symToAux(sym)
		x.AddArg3(ptr, idx, mem)
		v.AddArg2(x, x)
		return true
	}
	// match: (CMPLconstloadidx1 {sym} [vo] ptr idx mem)
	// cond: vo.Val() != 0
	// result: (CMPLconst (MOVLloadidx1 {sym} [vo.Off()] ptr idx mem) [vo.Val()])
	for {
		vo := auxIntToValAndOff(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		idx := v_1
		mem := v_2
		if !(vo.Val() != 0) {
			break
		}
		v.reset(OpAMD64CMPLconst)
		v.AuxInt = int32ToAuxInt(vo.Val())
		v0 := b.NewValue0(v.Pos, OpAMD64MOVLloadidx1, typ.UInt32)
		v0.AuxInt = int32ToAuxInt(vo.Off())
		v0.Aux = symToAux(sym)
		v0.AddArg3(ptr, idx, mem)
		v.AddArg(v0)
		return true
	}
	return false
}
func rewriteValueAMD64splitload_OpAMD64CMPLconstloadidx4(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (CMPLconstloadidx4 {sym} [vo] ptr idx mem)
	// cond: vo.Val() == 0
	// result: (TESTL x:(MOVLloadidx4 {sym} [vo.Off()] ptr idx mem) x)
	for {
		vo := auxIntToValAndOff(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		idx := v_1
		mem := v_2
		if !(vo.Val() == 0) {
			break
		}
		v.reset(OpAMD64TESTL)
		x := b.NewValue0(v.Pos, OpAMD64MOVLloadidx4, typ.UInt32)
		x.AuxInt = int32ToAuxInt(vo.Off())
		x.Aux = symToAux(sym)
		x.AddArg3(ptr, idx, mem)
		v.AddArg2(x, x)
		return true
	}
	// match: (CMPLconstloadidx4 {sym} [vo] ptr idx mem)
	// cond: vo.Val() != 0
	// result: (CMPLconst (MOVLloadidx4 {sym} [vo.Off()] ptr idx mem) [vo.Val()])
	for {
		vo := auxIntToValAndOff(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		idx := v_1
		mem := v_2
		if !(vo.Val() != 0) {
			break
		}
		v.reset(OpAMD64CMPLconst)
		v.AuxInt = int32ToAuxInt(vo.Val())
		v0 := b.NewValue0(v.Pos, OpAMD64MOVLloadidx4, typ.UInt32)
		v0.AuxInt = int32ToAuxInt(vo.Off())
		v0.Aux = symToAux(sym)
		v0.AddArg3(ptr, idx, mem)
		v.AddArg(v0)
		return true
	}
	return false
}
func rewriteValueAMD64splitload_OpAMD64CMPLload(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (CMPLload {sym} [off] ptr x mem)
	// result: (CMPL (MOVLload {sym} [off] ptr mem) x)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		x := v_1
		mem := v_2
		v.reset(OpAMD64CMPL)
		v0 := b.NewValue0(v.Pos, OpAMD64MOVLload, typ.UInt32)
		v0.AuxInt = int32ToAuxInt(off)
		v0.Aux = symToAux(sym)
		v0.AddArg2(ptr, mem)
		v.AddArg2(v0, x)
		return true
	}
}
func rewriteValueAMD64splitload_OpAMD64CMPLloadidx1(v *Value) bool {
	v_3 := v.Args[3]
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (CMPLloadidx1 {sym} [off] ptr idx x mem)
	// result: (CMPL (MOVLloadidx1 {sym} [off] ptr idx mem) x)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		idx := v_1
		x := v_2
		mem := v_3
		v.reset(OpAMD64CMPL)
		v0 := b.NewValue0(v.Pos, OpAMD64MOVLloadidx1, typ.UInt32)
		v0.AuxInt = int32ToAuxInt(off)
		v0.Aux = symToAux(sym)
		v0.AddArg3(ptr, idx, mem)
		v.AddArg2(v0, x)
		return true
	}
}
func rewriteValueAMD64splitload_OpAMD64CMPLloadidx4(v *Value) bool {
	v_3 := v.Args[3]
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (CMPLloadidx4 {sym} [off] ptr idx x mem)
	// result: (CMPL (MOVLloadidx4 {sym} [off] ptr idx mem) x)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		idx := v_1
		x := v_2
		mem := v_3
		v.reset(OpAMD64CMPL)
		v0 := b.NewValue0(v.Pos, OpAMD64MOVLloadidx4, typ.UInt32)
		v0.AuxInt = int32ToAuxInt(off)
		v0.Aux = symToAux(sym)
		v0.AddArg3(ptr, idx, mem)
		v.AddArg2(v0, x)
		return true
	}
}
func rewriteValueAMD64splitload_OpAMD64CMPQconstload(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (CMPQconstload {sym} [vo] ptr mem)
	// cond: vo.Val() == 0
	// result: (TESTQ x:(MOVQload {sym} [vo.Off()] ptr mem) x)
	for {
		vo := auxIntToValAndOff(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		mem := v_1
		if !(vo.Val() == 0) {
			break
		}
		v.reset(OpAMD64TESTQ)
		x := b.NewValue0(v.Pos, OpAMD64MOVQload, typ.UInt64)
		x.AuxInt = int32ToAuxInt(vo.Off())
		x.Aux = symToAux(sym)
		x.AddArg2(ptr, mem)
		v.AddArg2(x, x)
		return true
	}
	// match: (CMPQconstload {sym} [vo] ptr mem)
	// cond: vo.Val() != 0
	// result: (CMPQconst (MOVQload {sym} [vo.Off()] ptr mem) [vo.Val()])
	for {
		vo := auxIntToValAndOff(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		mem := v_1
		if !(vo.Val() != 0) {
			break
		}
		v.reset(OpAMD64CMPQconst)
		v.AuxInt = int32ToAuxInt(vo.Val())
		v0 := b.NewValue0(v.Pos, OpAMD64MOVQload, typ.UInt64)
		v0.AuxInt = int32ToAuxInt(vo.Off())
		v0.Aux = symToAux(sym)
		v0.AddArg2(ptr, mem)
		v.AddArg(v0)
		return true
	}
	return false
}
func rewriteValueAMD64splitload_OpAMD64CMPQconstloadidx1(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (CMPQconstloadidx1 {sym} [vo] ptr idx mem)
	// cond: vo.Val() == 0
	// result: (TESTQ x:(MOVQloadidx1 {sym} [vo.Off()] ptr idx mem) x)
	for {
		vo := auxIntToValAndOff(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		idx := v_1
		mem := v_2
		if !(vo.Val() == 0) {
			break
		}
		v.reset(OpAMD64TESTQ)
		x := b.NewValue0(v.Pos, OpAMD64MOVQloadidx1, typ.UInt64)
		x.AuxInt = int32ToAuxInt(vo.Off())
		x.Aux = symToAux(sym)
		x.AddArg3(ptr, idx, mem)
		v.AddArg2(x, x)
		return true
	}
	// match: (CMPQconstloadidx1 {sym} [vo] ptr idx mem)
	// cond: vo.Val() != 0
	// result: (CMPQconst (MOVQloadidx1 {sym} [vo.Off()] ptr idx mem) [vo.Val()])
	for {
		vo := auxIntToValAndOff(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		idx := v_1
		mem := v_2
		if !(vo.Val() != 0) {
			break
		}
		v.reset(OpAMD64CMPQconst)
		v.AuxInt = int32ToAuxInt(vo.Val())
		v0 := b.NewValue0(v.Pos, OpAMD64MOVQloadidx1, typ.UInt64)
		v0.AuxInt = int32ToAuxInt(vo.Off())
		v0.Aux = symToAux(sym)
		v0.AddArg3(ptr, idx, mem)
		v.AddArg(v0)
		return true
	}
	return false
}
func rewriteValueAMD64splitload_OpAMD64CMPQconstloadidx8(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (CMPQconstloadidx8 {sym} [vo] ptr idx mem)
	// cond: vo.Val() == 0
	// result: (TESTQ x:(MOVQloadidx8 {sym} [vo.Off()] ptr idx mem) x)
	for {
		vo := auxIntToValAndOff(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		idx := v_1
		mem := v_2
		if !(vo.Val() == 0) {
			break
		}
		v.reset(OpAMD64TESTQ)
		x := b.NewValue0(v.Pos, OpAMD64MOVQloadidx8, typ.UInt64)
		x.AuxInt = int32ToAuxInt(vo.Off())
		x.Aux = symToAux(sym)
		x.AddArg3(ptr, idx, mem)
		v.AddArg2(x, x)
		return true
	}
	// match: (CMPQconstloadidx8 {sym} [vo] ptr idx mem)
	// cond: vo.Val() != 0
	// result: (CMPQconst (MOVQloadidx8 {sym} [vo.Off()] ptr idx mem) [vo.Val()])
	for {
		vo := auxIntToValAndOff(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		idx := v_1
		mem := v_2
		if !(vo.Val() != 0) {
			break
		}
		v.reset(OpAMD64CMPQconst)
		v.AuxInt = int32ToAuxInt(vo.Val())
		v0 := b.NewValue0(v.Pos, OpAMD64MOVQloadidx8, typ.UInt64)
		v0.AuxInt = int32ToAuxInt(vo.Off())
		v0.Aux = symToAux(sym)
		v0.AddArg3(ptr, idx, mem)
		v.AddArg(v0)
		return true
	}
	return false
}
func rewriteValueAMD64splitload_OpAMD64CMPQload(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (CMPQload {sym} [off] ptr x mem)
	// result: (CMPQ (MOVQload {sym} [off] ptr mem) x)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		x := v_1
		mem := v_2
		v.reset(OpAMD64CMPQ)
		v0 := b.NewValue0(v.Pos, OpAMD64MOVQload, typ.UInt64)
		v0.AuxInt = int32ToAuxInt(off)
		v0.Aux = symToAux(sym)
		v0.AddArg2(ptr, mem)
		v.AddArg2(v0, x)
		return true
	}
}
func rewriteValueAMD64splitload_OpAMD64CMPQloadidx1(v *Value) bool {
	v_3 := v.Args[3]
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (CMPQloadidx1 {sym} [off] ptr idx x mem)
	// result: (CMPQ (MOVQloadidx1 {sym} [off] ptr idx mem) x)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		idx := v_1
		x := v_2
		mem := v_3
		v.reset(OpAMD64CMPQ)
		v0 := b.NewValue0(v.Pos, OpAMD64MOVQloadidx1, typ.UInt64)
		v0.AuxInt = int32ToAuxInt(off)
		v0.Aux = symToAux(sym)
		v0.AddArg3(ptr, idx, mem)
		v.AddArg2(v0, x)
		return true
	}
}
func rewriteValueAMD64splitload_OpAMD64CMPQloadidx8(v *Value) bool {
	v_3 := v.Args[3]
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (CMPQloadidx8 {sym} [off] ptr idx x mem)
	// result: (CMPQ (MOVQloadidx8 {sym} [off] ptr idx mem) x)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		idx := v_1
		x := v_2
		mem := v_3
		v.reset(OpAMD64CMPQ)
		v0 := b.NewValue0(v.Pos, OpAMD64MOVQloadidx8, typ.UInt64)
		v0.AuxInt = int32ToAuxInt(off)
		v0.Aux = symToAux(sym)
		v0.AddArg3(ptr, idx, mem)
		v.AddArg2(v0, x)
		return true
	}
}
func rewriteValueAMD64splitload_OpAMD64CMPWconstload(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (CMPWconstload {sym} [vo] ptr mem)
	// cond: vo.Val() == 0
	// result: (TESTW x:(MOVWload {sym} [vo.Off()] ptr mem) x)
	for {
		vo := auxIntToValAndOff(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		mem := v_1
		if !(vo.Val() == 0) {
			break
		}
		v.reset(OpAMD64TESTW)
		x := b.NewValue0(v.Pos, OpAMD64MOVWload, typ.UInt16)
		x.AuxInt = int32ToAuxInt(vo.Off())
		x.Aux = symToAux(sym)
		x.AddArg2(ptr, mem)
		v.AddArg2(x, x)
		return true
	}
	// match: (CMPWconstload {sym} [vo] ptr mem)
	// cond: vo.Val() != 0
	// result: (CMPWconst (MOVWload {sym} [vo.Off()] ptr mem) [vo.Val16()])
	for {
		vo := auxIntToValAndOff(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		mem := v_1
		if !(vo.Val() != 0) {
			break
		}
		v.reset(OpAMD64CMPWconst)
		v.AuxInt = int16ToAuxInt(vo.Val16())
		v0 := b.NewValue0(v.Pos, OpAMD64MOVWload, typ.UInt16)
		v0.AuxInt = int32ToAuxInt(vo.Off())
		v0.Aux = symToAux(sym)
		v0.AddArg2(ptr, mem)
		v.AddArg(v0)
		return true
	}
	return false
}
func rewriteValueAMD64splitload_OpAMD64CMPWconstloadidx1(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (CMPWconstloadidx1 {sym} [vo] ptr idx mem)
	// cond: vo.Val() == 0
	// result: (TESTW x:(MOVWloadidx1 {sym} [vo.Off()] ptr idx mem) x)
	for {
		vo := auxIntToValAndOff(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		idx := v_1
		mem := v_2
		if !(vo.Val() == 0) {
			break
		}
		v.reset(OpAMD64TESTW)
		x := b.NewValue0(v.Pos, OpAMD64MOVWloadidx1, typ.UInt16)
		x.AuxInt = int32ToAuxInt(vo.Off())
		x.Aux = symToAux(sym)
		x.AddArg3(ptr, idx, mem)
		v.AddArg2(x, x)
		return true
	}
	// match: (CMPWconstloadidx1 {sym} [vo] ptr idx mem)
	// cond: vo.Val() != 0
	// result: (CMPWconst (MOVWloadidx1 {sym} [vo.Off()] ptr idx mem) [vo.Val16()])
	for {
		vo := auxIntToValAndOff(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		idx := v_1
		mem := v_2
		if !(vo.Val() != 0) {
			break
		}
		v.reset(OpAMD64CMPWconst)
		v.AuxInt = int16ToAuxInt(vo.Val16())
		v0 := b.NewValue0(v.Pos, OpAMD64MOVWloadidx1, typ.UInt16)
		v0.AuxInt = int32ToAuxInt(vo.Off())
		v0.Aux = symToAux(sym)
		v0.AddArg3(ptr, idx, mem)
		v.AddArg(v0)
		return true
	}
	return false
}
func rewriteValueAMD64splitload_OpAMD64CMPWconstloadidx2(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (CMPWconstloadidx2 {sym} [vo] ptr idx mem)
	// cond: vo.Val() == 0
	// result: (TESTW x:(MOVWloadidx2 {sym} [vo.Off()] ptr idx mem) x)
	for {
		vo := auxIntToValAndOff(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		idx := v_1
		mem := v_2
		if !(vo.Val() == 0) {
			break
		}
		v.reset(OpAMD64TESTW)
		x := b.NewValue0(v.Pos, OpAMD64MOVWloadidx2, typ.UInt16)
		x.AuxInt = int32ToAuxInt(vo.Off())
		x.Aux = symToAux(sym)
		x.AddArg3(ptr, idx, mem)
		v.AddArg2(x, x)
		return true
	}
	// match: (CMPWconstloadidx2 {sym} [vo] ptr idx mem)
	// cond: vo.Val() != 0
	// result: (CMPWconst (MOVWloadidx2 {sym} [vo.Off()] ptr idx mem) [vo.Val16()])
	for {
		vo := auxIntToValAndOff(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		idx := v_1
		mem := v_2
		if !(vo.Val() != 0) {
			break
		}
		v.reset(OpAMD64CMPWconst)
		v.AuxInt = int16ToAuxInt(vo.Val16())
		v0 := b.NewValue0(v.Pos, OpAMD64MOVWloadidx2, typ.UInt16)
		v0.AuxInt = int32ToAuxInt(vo.Off())
		v0.Aux = symToAux(sym)
		v0.AddArg3(ptr, idx, mem)
		v.AddArg(v0)
		return true
	}
	return false
}
func rewriteValueAMD64splitload_OpAMD64CMPWload(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (CMPWload {sym} [off] ptr x mem)
	// result: (CMPW (MOVWload {sym} [off] ptr mem) x)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		x := v_1
		mem := v_2
		v.reset(OpAMD64CMPW)
		v0 := b.NewValue0(v.Pos, OpAMD64MOVWload, typ.UInt16)
		v0.AuxInt = int32ToAuxInt(off)
		v0.Aux = symToAux(sym)
		v0.AddArg2(ptr, mem)
		v.AddArg2(v0, x)
		return true
	}
}
func rewriteValueAMD64splitload_OpAMD64CMPWloadidx1(v *Value) bool {
	v_3 := v.Args[3]
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (CMPWloadidx1 {sym} [off] ptr idx x mem)
	// result: (CMPW (MOVWloadidx1 {sym} [off] ptr idx mem) x)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		idx := v_1
		x := v_2
		mem := v_3
		v.reset(OpAMD64CMPW)
		v0 := b.NewValue0(v.Pos, OpAMD64MOVWloadidx1, typ.UInt16)
		v0.AuxInt = int32ToAuxInt(off)
		v0.Aux = symToAux(sym)
		v0.AddArg3(ptr, idx, mem)
		v.AddArg2(v0, x)
		return true
	}
}
func rewriteValueAMD64splitload_OpAMD64CMPWloadidx2(v *Value) bool {
	v_3 := v.Args[3]
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (CMPWloadidx2 {sym} [off] ptr idx x mem)
	// result: (CMPW (MOVWloadidx2 {sym} [off] ptr idx mem) x)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		idx := v_1
		x := v_2
		mem := v_3
		v.reset(OpAMD64CMPW)
		v0 := b.NewValue0(v.Pos, OpAMD64MOVWloadidx2, typ.UInt16)
		v0.AuxInt = int32ToAuxInt(off)
		v0.Aux = symToAux(sym)
		v0.AddArg3(ptr, idx, mem)
		v.AddArg2(v0, x)
		return true
	}
}
func rewriteBlockAMD64splitload(b *Block) bool {
	return false
}

"""



```