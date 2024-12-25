Response: Let's break down the thought process for analyzing this Go code snippet.

1. **Identify the Core Purpose:** The first thing that jumps out is the `// asmcheck` comment. This immediately signals that the code is not primarily about standard Go logic, but rather about verifying the generated assembly code for specific operations. The file path `go/test/codegen/memops.go` reinforces this idea – it's part of the Go compiler's testing infrastructure, specifically targeting code generation. The name "memops" suggests a focus on memory operations.

2. **High-Level Structure Analysis:**  Quickly scan the code for the types of operations being performed. We see:
    * Comparisons (`if x[1]`, `if t.x8 == 7`)
    * Indexed array access (`x[i+1]`, `y[16*i+1]`)
    * Arithmetic and bitwise operations with indexed array elements (`s += x[i+1]`, `p[0] |= 8`)
    * Operations involving different data types (bool, uint8, uint16, int, float32, float64).
    * Functions taking both values and pointers as arguments.

3. **Deconstruct Each Function:**  Go function by function and note the key operations and the associated assembly directives:

    * **`compMem1`:**  Compares elements of global arrays with constant values. Notice the `command-line-arguments` prefix in the assembly comments. This suggests global variables are addressed relative to some base address. The different `CMPB`, `CMPW`, `CMPL`, `CMPQ` instructions highlight comparisons of different byte sizes.

    * **`compMem2`:** Similar to `compMem1`, but operates on fields of a struct passed by value. The assembly comments show offsets from the stack pointer (`SP`), indicating the struct is passed on the stack.

    * **`compMem3`:**  Compares a register value with a value loaded from memory. The key is that the register is used *after* the comparison, demonstrating the compiler's ability to optimize this.

    * **`idxInt8`, `idxInt16`, `idxInt32`, `idxInt64`:**  These functions focus on indexed access to integer arrays. The assembly comments clearly show the scaled indexing: `([A-Z]+[0-9]*\*1)`, `([A-Z]+[0-9]*\*2)`, `([A-Z]+[0-9]*\*4)`, `([A-Z]+[0-9]*\*8)`, corresponding to the element sizes. The `MOVBLZX`, `MOVWLZX`, `MOVL`, `MOVQ` instructions are for loading, and `MOVB`, `MOVW`, `MOVL`, `MOVQ` for storing. The variations with constants like `16*i+1` test different scaling factors.

    * **`idxFloat32`, `idxFloat64`:** Similar to the integer indexing functions but for floating-point types. The `MOVSS` and `MOVSD` instructions are used, along with the different register names (`X[0-9]+`, `F[0-9]+`).

    * **`idxLoadPlusOp32`, `idxLoadPlusOp64`:**  These demonstrate loading a value from an indexed array element and then performing arithmetic operations with it. The assembly comments show the `ADDL`, `SUBL`, `IMULL`, `ANDL`, `ORL`, `XORL` (for `int32`) and `ADDQ`, `SUBQ`, `ANDQ`, `ORQ`, `XORQ` (for `int64`) instructions being applied directly to memory locations.

    * **`idxStorePlusOp32`, `idxStorePlusOp64`:** Similar to the load+op functions, but these perform in-place modifications to array elements using compound assignment operators (`+=`, `-=`, `&=`, etc.). The assembly comments reflect this with instructions like `ADDL reg, memory`.

    * **`idxCompare`:** Compares indexed array elements with each other and with constants. This checks the generated assembly for comparison instructions after loading values.

    * **`idxFloatOps`:** Demonstrates arithmetic operations on indexed floating-point array elements.

    * **`storeTest`:**  Shows how boolean values derived from bitwise operations are stored into a boolean array. The `BTL` (Bit Test and Logical AND) and `SETCS` (Set if Carry) instructions are key here.

    * **`bitOps`:** Focuses on bitwise operations directly on memory locations using constants. The assembly comments reveal instructions like `ORQ`, `BTSQ`, `ANDQ`, `BTRQ`, `XORQ`, and `BTCQ`.

4. **Synthesize the Functionality:** Based on the individual function analysis, conclude that the overall goal is to test the Go compiler's ability to generate efficient assembly code for common memory access patterns, including:
    * Comparing values in memory.
    * Accessing elements of arrays using indices and scaling.
    * Performing arithmetic and bitwise operations directly on memory locations.
    * Handling different data types correctly.

5. **Infer the Go Language Feature:**  The code is testing the fundamental aspects of how Go handles memory operations for various data types and array access patterns. It doesn't directly implement a *specific* high-level Go feature, but rather verifies the low-level implementation of core language constructs.

6. **Construct Example Usage (Conceptual):**  Since it's a testing file, direct execution isn't the point. However, to illustrate the *kind* of Go code being tested, create simple examples that would trigger the assembly patterns observed. These examples don't need to *call* the test functions, but rather demonstrate the equivalent Go code.

7. **Explain Code Logic with Hypothetical Input/Output:** Choose a few representative functions (e.g., `compMem1`, `idxInt32`) and explain their behavior with simple input values. Since the output of these functions is often dependent on the initial state of global variables (for `compMem1`) or input arrays, provide hypothetical initial states and expected return values.

8. **Address Command-Line Parameters (if applicable):** In this specific case, the code itself doesn't directly process command-line arguments. However, the `// asmcheck` comment indicates it's used within a testing framework that likely *does* have command-line options to specify the target architecture, etc. Therefore, mention the role of `asmcheck` and the likely presence of such parameters in the testing environment.

9. **Identify Potential Pitfalls for Users (if applicable):**  Think about scenarios where developers might misunderstand how Go's memory model or compiler optimizations work. In this case, the example of passing structs by value and the potential performance implications is a relevant point. The intricacies of compiler optimizations and the exact assembly generated can be another potential area of misunderstanding.

10. **Review and Refine:**  Read through the analysis, ensuring it's clear, concise, and addresses all aspects of the prompt. Check for any inconsistencies or areas that could be explained better. For instance, initially, I might have focused too much on the individual assembly instructions. A good refinement step is to pull back and emphasize the *purpose* of these instructions in the context of the Go language.
The Go code snippet located at `go/test/codegen/memops.go` is part of the Go compiler's testing infrastructure. Its primary function is to **verify the generated assembly code for various memory operations**. It uses specially crafted Go functions and global variables to force the compiler to emit specific assembly instructions, which are then checked against the expected patterns defined in the comments (lines starting with `// amd64:` or `// 386:`).

Essentially, this file tests the **correctness and efficiency of Go's memory access and manipulation at the assembly level**.

Here's a breakdown of the functionalities demonstrated in the code:

**1. Comparison Operations on Memory:**

The functions `compMem1` and `compMem2` test how the Go compiler generates assembly code for comparing values stored in memory.

* **`compMem1`:** Compares elements of globally declared arrays (`x`, `x8`, `x16`, `x32`, `x64`) with constant values. The assembly comments show that the compiler generates `CMPB`, `CMPW`, `CMPL`, and `CMPQ` instructions for byte, word, long, and quad-word comparisons respectively, directly against memory locations.

* **`compMem2`:** Compares fields of a struct (`T`) passed as a value argument. This verifies that comparisons work correctly when data is located on the stack. The assembly comments show comparisons against memory locations relative to the stack pointer (`SP`).

**Example (Illustrative Go Code - Not Directly Executing the Test):**

```go
package main

var globalBool [2]bool
var globalUint8 [2]uint8

func main() {
	globalBool[1] = true
	globalUint8[1] = 10

	if globalBool[1] { // This will likely trigger a CMPB instruction
		println("globalBool[1] is true")
	}

	if globalUint8[1] == 10 { // This will likely trigger a CMPB instruction
		println("globalUint8[1] is 10")
	}
}
```

**2. Comparing Register with Memory:**

The function `compMem3` verifies that the compiler can efficiently compare a value held in a register with a value loaded from memory. It specifically checks that the comparison can happen even if the register value is used later.

**Example (Illustrative Go Code):**

```go
package main

func compare(a int, b *int) (int, bool) {
	x := a // x will likely be in a register
	return x, x < *b // Comparison with memory location *b
}

func main() {
	val := 5
	res, isLess := compare(10, &val)
	println(res, isLess)
}
```

**3. Indexed Load and Store Operations:**

The functions `idxInt8`, `idxInt16`, `idxInt32`, `idxInt64`, `idxFloat32`, and `idxFloat64` test the generation of assembly instructions for accessing elements of arrays using an index. They cover different integer and floating-point types and variations in index calculations (e.g., `i+1`, `16*i+1`). The assembly comments show the expected `MOV` instructions with appropriate scaling based on the element size.

**Example (Illustrative Go Code):**

```go
package main

func accessArray(arr []int32, index int) {
	val := arr[index+1] // Indexed load
	arr[index+1] = 77    // Indexed store
	println(val)
}

func main() {
	myArray := []int32{1, 2, 3, 4}
	accessArray(myArray, 0)
	println(myArray[1])
}
```

**4. Indexed Load/Store with Arithmetic and Bitwise Operations:**

The functions `idxLoadPlusOp32`, `idxLoadPlusOp64`, `idxStorePlusOp32`, and `idxStorePlusOp64` check if the compiler can generate efficient assembly for combining indexed memory access with arithmetic and bitwise operations (like `+=`, `-=`, `*=`, `&=`, `|=`, `^=`).

**Example (Illustrative Go Code):**

```go
package main

func operateOnArray(arr []int32, index int) {
	arr[index+1] += 5
	arr[index+2] &= 0xFF
}

func main() {
	myArray := []int32{10, 20, 30}
	operateOnArray(myArray, 0)
	println(myArray[1], myArray[2])
}
```

**5. Indexed Comparison:**

The `idxCompare` function verifies the assembly generated when comparing indexed elements of arrays with each other and with constant values.

**Example (Illustrative Go Code):**

```go
package main

var globalInts [2]int32

func compareArrayElements(i int) bool {
	return globalInts[i+1] < globalInts[0]
}

func main() {
	globalInts[0] = 100
	globalInts[1] = 50
	println(compareArrayElements(0))
}
```

**6. Floating-Point Operations:**

The `idxFloatOps` function tests the generation of assembly for arithmetic operations (`+=`, `-=`, `*=`, `/=`) on indexed elements of floating-point arrays.

**Example (Illustrative Go Code):**

```go
package main

func operateOnFloatArray(arr []float64, index int) {
	arr[index+1] += 3.14
	arr[index+2] /= 2.0
}

func main() {
	floatArray := []float64{1.0, 2.0, 3.0}
	operateOnFloatArray(floatArray, 0)
	println(floatArray[1], floatArray[2])
}
```

**7. Storing Boolean Results of Bitwise Operations:**

The `storeTest` function checks how boolean values, resulting from bitwise operations, are stored into boolean arrays.

**Example (Illustrative Go Code):**

```go
package main

func storeBitwiseResult(arr []bool, val int) {
	arr[4] = val&1 != 0
	arr[5] = val&2 != 0
}

func main() {
	boolArray := make([]bool, 10)
	storeBitwiseResult(boolArray, 3)
	println(boolArray[4], boolArray[5])
}
```

**8. Bitwise Operations on Memory:**

The `bitOps` function tests the generation of assembly instructions for performing bitwise OR, AND NOT, and XOR operations directly on memory locations using constants. It uses bit set/clear/test instructions where applicable.

**Example (Illustrative Go Code):**

```go
package main

func bitwiseOps(val *uint64) {
	*val |= 0x08
	*val &^= 0xF0
	*val ^= 0x01
}

func main() {
	var num uint64 = 0
	bitwiseOps(&num)
	println(num)
}
```

**Command-Line Parameters:**

This specific Go file (`memops.go`) is not meant to be executed directly as a standalone program. It's part of the Go compiler's test suite. The testing framework that uses this file likely has command-line parameters to control aspects like:

* **Target Architecture:** Specifying the architecture for which assembly code should be generated and checked (e.g., `amd64`, `386`, `arm64`). The `// amd64:` and `// 386:` prefixes in the comments indicate architecture-specific assembly expectations.
* **Compiler Flags:**  Potentially passing specific compiler optimization flags to see how they affect the generated assembly.
* **Test Filtering:** Selecting specific tests to run within the larger test suite.

**Code Logic and Assumptions:**

The code works by:

1. **Defining global variables:**  These variables are used to represent memory locations that the compiler will need to access.
2. **Writing Go functions:** These functions perform specific memory operations (comparisons, loads, stores, arithmetic, bitwise).
3. **Embedding assembly expectations in comments:** The `// amd64:` and `// 386:` comments contain regular expressions that match the expected assembly instructions generated for the subsequent Go code on those architectures.
4. **Using `asmcheck`:** The `// asmcheck` directive at the top indicates that this file is intended to be used with an assembly checking tool. This tool (likely part of the Go compiler's testing infrastructure) compiles the Go code and then examines the generated assembly output, comparing it against the patterns in the comments.

**Example with Hypothetical Input and Output (for `compMem1`):**

**Assumption:** We are running on an `amd64` architecture.

**Input (Implicit - Global Variable Initialization):**

```go
var x [2]bool     // Initialized to [false, false] (zero values)
var x8 [2]uint8    // Initialized to [0, 0]
var x16 [2]uint16  // Initialized to [0, 0]
var x32 [2]uint32  // Initialized to [0, 0]
var x64 [2]uint64  // Initialized to [0, 0]
```

**Execution (Hypothetical - As Part of the Test):**

The `compMem1()` function is called.

**Code Logic Flow:**

1. `if x[1]` (which is `false`) - The `CMPB` instruction will compare the byte at the memory location of `x[1]` with `0`. The condition is false.
2. `if x8[1] == 7` (which is `0 == 7`) - The `CMPB` instruction will compare the byte at the memory location of `x8[1]` with `7`. The condition is false.
3. `if x16[1] == 7` (which is `0 == 7`) - The `CMPW` instruction will compare the word at the memory location of `x16[1]` with `7`. The condition is false.
4. `if x32[1] == 7` (which is `0 == 7`) - The `CMPL` instruction will compare the long word at the memory location of `x32[1]` with `7`. The condition is false.
5. `if x64[1] == 7` (which is `0 == 7`) - The `CMPQ` instruction will compare the quad word at the memory location of `x64[1]` with `7`. The condition is false.
6. The function returns `0`.

**Output (Return Value):** `0`

**User Mistakes:**

Since this code is primarily for internal compiler testing, typical Go developers wouldn't directly interact with it. However, if someone were trying to understand or modify these tests, they might make mistakes such as:

* **Incorrectly specifying assembly expectations:**  Writing regular expressions in the comments that don't accurately match the assembly generated by the compiler for a given architecture or optimization level. This would lead to test failures even if the compiler is generating correct code.
* **Misunderstanding the purpose of the tests:**  Trying to use these functions as examples of general Go programming practices. The code is deliberately crafted to test specific low-level scenarios and might not represent idiomatic Go.
* **Not considering different architectures:**  Assuming that the assembly expectations for one architecture are valid for another.

In summary, `go/test/codegen/memops.go` is a crucial part of the Go compiler's quality assurance process, ensuring that memory operations are handled correctly and efficiently at the lowest level. It utilizes a mechanism to verify the generated assembly code against predefined patterns.

Prompt: 
```
这是路径为go/test/codegen/memops.go的go语言实现的一部分， 请归纳一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果介绍代码逻辑，则建议带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，

"""
// asmcheck

// Copyright 2018 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package codegen

var x [2]bool
var x8 [2]uint8
var x16 [2]uint16
var x32 [2]uint32
var x64 [2]uint64

func compMem1() int {
	// amd64:`CMPB\tcommand-line-arguments.x\+1\(SB\), [$]0`
	if x[1] {
		return 1
	}
	// amd64:`CMPB\tcommand-line-arguments.x8\+1\(SB\), [$]7`
	if x8[1] == 7 {
		return 1
	}
	// amd64:`CMPW\tcommand-line-arguments.x16\+2\(SB\), [$]7`
	if x16[1] == 7 {
		return 1
	}
	// amd64:`CMPL\tcommand-line-arguments.x32\+4\(SB\), [$]7`
	if x32[1] == 7 {
		return 1
	}
	// amd64:`CMPQ\tcommand-line-arguments.x64\+8\(SB\), [$]7`
	if x64[1] == 7 {
		return 1
	}
	return 0
}

type T struct {
	x   bool
	x8  uint8
	x16 uint16
	x32 uint32
	x64 uint64
	a   [2]int // force it passed in memory
}

func compMem2(t T) int {
	// amd64:`CMPB\t.*\(SP\), [$]0`
	if t.x {
		return 1
	}
	// amd64:`CMPB\t.*\(SP\), [$]7`
	if t.x8 == 7 {
		return 1
	}
	// amd64:`CMPW\t.*\(SP\), [$]7`
	if t.x16 == 7 {
		return 1
	}
	// amd64:`CMPL\t.*\(SP\), [$]7`
	if t.x32 == 7 {
		return 1
	}
	// amd64:`CMPQ\t.*\(SP\), [$]7`
	if t.x64 == 7 {
		return 1
	}
	return 0
}

func compMem3(x, y *int) (int, bool) {
	// We can do comparisons of a register with memory even if
	// the register is used subsequently.
	r := *x
	// amd64:`CMPQ\t\(`
	// 386:`CMPL\t\(`
	return r, r < *y
}

// The following functions test that indexed load/store operations get generated.

func idxInt8(x, y []int8, i int) {
	var t int8
	// amd64: `MOVBL[SZ]X\t1\([A-Z]+[0-9]*\)\([A-Z]+[0-9]*\*1\), [A-Z]+[0-9]*`
	//   386: `MOVBL[SZ]X\t1\([A-Z]+[0-9]*\)\([A-Z]+[0-9]*\*1\), [A-Z]+[0-9]*`
	t = x[i+1]
	// amd64: `MOVB\t[A-Z]+[0-9]*, 1\([A-Z]+[0-9]*\)\([A-Z]+[0-9]*\*1\)`
	//   386: `MOVB\t[A-Z]+[0-9]*, 1\([A-Z]+[0-9]*\)\([A-Z]+[0-9]*\*1\)`
	y[i+1] = t
	// amd64: `MOVB\t[$]77, 1\([A-Z]+[0-9]*\)\([A-Z]+[0-9]*\*1\)`
	//   386: `MOVB\t[$]77, 1\([A-Z]+[0-9]*\)\([A-Z]+[0-9]*\*1\)`
	x[i+1] = 77
}

func idxInt16(x, y []int16, i int) {
	var t int16
	// amd64: `MOVWL[SZ]X\t2\([A-Z]+[0-9]*\)\([A-Z]+[0-9]*\*2\), [A-Z]+[0-9]*`
	//   386: `MOVWL[SZ]X\t2\([A-Z]+[0-9]*\)\([A-Z]+[0-9]*\*2\), [A-Z]+[0-9]*`
	t = x[i+1]
	// amd64: `MOVW\t[A-Z]+[0-9]*, 2\([A-Z]+[0-9]*\)\([A-Z]+[0-9]*\*2\)`
	//   386: `MOVW\t[A-Z]+[0-9]*, 2\([A-Z]+[0-9]*\)\([A-Z]+[0-9]*\*2\)`
	y[i+1] = t
	// amd64: `MOVWL[SZ]X\t2\([A-Z]+[0-9]*\)\([A-Z]+[0-9]*\*[12]\), [A-Z]+[0-9]*`
	//   386: `MOVWL[SZ]X\t2\([A-Z]+[0-9]*\)\([A-Z]+[0-9]*\*[12]\), [A-Z]+[0-9]*`
	t = x[16*i+1]
	// amd64: `MOVW\t[A-Z]+[0-9]*, 2\([A-Z]+[0-9]*\)\([A-Z]+[0-9]*\*[12]\)`
	//   386: `MOVW\t[A-Z]+[0-9]*, 2\([A-Z]+[0-9]*\)\([A-Z]+[0-9]*\*[12]\)`
	y[16*i+1] = t
	// amd64: `MOVW\t[$]77, 2\([A-Z]+[0-9]*\)\([A-Z]+[0-9]*\*2\)`
	//   386: `MOVW\t[$]77, 2\([A-Z]+[0-9]*\)\([A-Z]+[0-9]*\*2\)`
	x[i+1] = 77
	// amd64: `MOVW\t[$]77, 2\([A-Z]+[0-9]*\)\([A-Z]+[0-9]*\*[12]\)`
	//   386: `MOVW\t[$]77, 2\([A-Z]+[0-9]*\)\([A-Z]+[0-9]*\*[12]\)`
	x[16*i+1] = 77
}

func idxInt32(x, y []int32, i int) {
	var t int32
	// amd64: `MOVL\t4\([A-Z]+[0-9]*\)\([A-Z]+[0-9]*\*4\), [A-Z]+[0-9]*`
	//   386: `MOVL\t4\([A-Z]+[0-9]*\)\([A-Z]+[0-9]*\*4\), [A-Z]+[0-9]*`
	t = x[i+1]
	// amd64: `MOVL\t[A-Z]+[0-9]*, 4\([A-Z]+[0-9]*\)\([A-Z]+[0-9]*\*4\)`
	//   386: `MOVL\t[A-Z]+[0-9]*, 4\([A-Z]+[0-9]*\)\([A-Z]+[0-9]*\*4\)`
	y[i+1] = t
	// amd64: `MOVL\t4\([A-Z]+[0-9]*\)\([A-Z]+[0-9]*\*8\), [A-Z]+[0-9]*`
	t = x[2*i+1]
	// amd64: `MOVL\t[A-Z]+[0-9]*, 4\([A-Z]+[0-9]*\)\([A-Z]+[0-9]*\*8\)`
	y[2*i+1] = t
	// amd64: `MOVL\t4\([A-Z]+[0-9]*\)\([A-Z]+[0-9]*\*[14]\), [A-Z]+[0-9]*`
	//   386: `MOVL\t4\([A-Z]+[0-9]*\)\([A-Z]+[0-9]*\*[14]\), [A-Z]+[0-9]*`
	t = x[16*i+1]
	// amd64: `MOVL\t[A-Z]+[0-9]*, 4\([A-Z]+[0-9]*\)\([A-Z]+[0-9]*\*[14]\)`
	//   386: `MOVL\t[A-Z]+[0-9]*, 4\([A-Z]+[0-9]*\)\([A-Z]+[0-9]*\*[14]\)`
	y[16*i+1] = t
	// amd64: `MOVL\t[$]77, 4\([A-Z]+[0-9]*\)\([A-Z]+[0-9]*\*4\)`
	//   386: `MOVL\t[$]77, 4\([A-Z]+[0-9]*\)\([A-Z]+[0-9]*\*4\)`
	x[i+1] = 77
	// amd64: `MOVL\t[$]77, 4\([A-Z]+[0-9]*\)\([A-Z]+[0-9]*\*[14]\)`
	//   386: `MOVL\t[$]77, 4\([A-Z]+[0-9]*\)\([A-Z]+[0-9]*\*[14]\)`
	x[16*i+1] = 77
}

func idxInt64(x, y []int64, i int) {
	var t int64
	// amd64: `MOVQ\t8\([A-Z]+[0-9]*\)\([A-Z]+[0-9]*\*8\), [A-Z]+[0-9]*`
	t = x[i+1]
	// amd64: `MOVQ\t[A-Z]+[0-9]*, 8\([A-Z]+[0-9]*\)\([A-Z]+[0-9]*\*8\)`
	y[i+1] = t
	// amd64: `MOVQ\t8\([A-Z]+[0-9]*\)\([A-Z]+[0-9]*\*[18]\), [A-Z]+[0-9]*`
	t = x[16*i+1]
	// amd64: `MOVQ\t[A-Z]+[0-9]*, 8\([A-Z]+[0-9]*\)\([A-Z]+[0-9]*\*[18]\)`
	y[16*i+1] = t
	// amd64: `MOVQ\t[$]77, 8\([A-Z]+[0-9]*\)\([A-Z]+[0-9]*\*8\)`
	x[i+1] = 77
	// amd64: `MOVQ\t[$]77, 8\([A-Z]+[0-9]*\)\([A-Z]+[0-9]*\*[18]\)`
	x[16*i+1] = 77
}

func idxFloat32(x, y []float32, i int) {
	var t float32
	//    amd64: `MOVSS\t4\([A-Z]+[0-9]*\)\([A-Z]+[0-9]*\*4\), X[0-9]+`
	// 386/sse2: `MOVSS\t4\([A-Z]+[0-9]*\)\([A-Z]+[0-9]*\*4\), X[0-9]+`
	//    arm64: `FMOVS\t\(R[0-9]*\)\(R[0-9]*<<2\), F[0-9]+`
	t = x[i+1]
	//    amd64: `MOVSS\tX[0-9]+, 4\([A-Z]+[0-9]*\)\([A-Z]+[0-9]*\*4\)`
	// 386/sse2: `MOVSS\tX[0-9]+, 4\([A-Z]+[0-9]*\)\([A-Z]+[0-9]*\*4\)`
	//    arm64: `FMOVS\tF[0-9]+, \(R[0-9]*\)\(R[0-9]*<<2\)`
	y[i+1] = t
	//    amd64: `MOVSS\t4\([A-Z]+[0-9]*\)\([A-Z]+[0-9]*\*[14]\), X[0-9]+`
	// 386/sse2: `MOVSS\t4\([A-Z]+[0-9]*\)\([A-Z]+[0-9]*\*[14]\), X[0-9]+`
	t = x[16*i+1]
	//    amd64: `MOVSS\tX[0-9]+, 4\([A-Z]+[0-9]*\)\([A-Z]+[0-9]*\*[14]\)`
	// 386/sse2: `MOVSS\tX[0-9]+, 4\([A-Z]+[0-9]*\)\([A-Z]+[0-9]*\*[14]\)`
	y[16*i+1] = t
}

func idxFloat64(x, y []float64, i int) {
	var t float64
	//    amd64: `MOVSD\t8\([A-Z]+[0-9]*\)\([A-Z]+[0-9]*\*8\), X[0-9]+`
	// 386/sse2: `MOVSD\t8\([A-Z]+[0-9]*\)\([A-Z]+[0-9]*\*8\), X[0-9]+`
	//    arm64: `FMOVD\t\(R[0-9]*\)\(R[0-9]*<<3\), F[0-9]+`
	t = x[i+1]
	//    amd64: `MOVSD\tX[0-9]+, 8\([A-Z]+[0-9]*\)\([A-Z]+[0-9]*\*8\)`
	// 386/sse2: `MOVSD\tX[0-9]+, 8\([A-Z]+[0-9]*\)\([A-Z]+[0-9]*\*8\)`
	//    arm64: `FMOVD\tF[0-9]+, \(R[0-9]*\)\(R[0-9]*<<3\)`
	y[i+1] = t
	//    amd64: `MOVSD\t8\([A-Z]+[0-9]*\)\([A-Z]+[0-9]*\*[18]\), X[0-9]+`
	// 386/sse2: `MOVSD\t8\([A-Z]+[0-9]*\)\([A-Z]+[0-9]*\*[18]\), X[0-9]+`
	t = x[16*i+1]
	//    amd64: `MOVSD\tX[0-9]+, 8\([A-Z]+[0-9]*\)\([A-Z]+[0-9]*\*[18]\)`
	// 386/sse2: `MOVSD\tX[0-9]+, 8\([A-Z]+[0-9]*\)\([A-Z]+[0-9]*\*[18]\)`
	y[16*i+1] = t
}

func idxLoadPlusOp32(x []int32, i int) int32 {
	s := x[0]
	// 386: `ADDL\t4\([A-Z]+\)\([A-Z]+\*4\), [A-Z]+`
	// amd64: `ADDL\t4\([A-Z]+[0-9]*\)\([A-Z]+[0-9]*\*4\), [A-Z]+[0-9]*`
	s += x[i+1]
	// 386: `SUBL\t8\([A-Z]+\)\([A-Z]+\*4\), [A-Z]+`
	// amd64: `SUBL\t8\([A-Z]+[0-9]*\)\([A-Z]+[0-9]*\*4\), [A-Z]+[0-9]*`
	s -= x[i+2]
	// 386: `IMULL\t12\([A-Z]+\)\([A-Z]+\*4\), [A-Z]+`
	s *= x[i+3]
	// 386: `ANDL\t16\([A-Z]+\)\([A-Z]+\*4\), [A-Z]+`
	// amd64: `ANDL\t16\([A-Z]+[0-9]*\)\([A-Z]+[0-9]*\*4\), [A-Z]+[0-9]*`
	s &= x[i+4]
	// 386: `ORL\t20\([A-Z]+\)\([A-Z]+\*4\), [A-Z]+`
	// amd64: `ORL\t20\([A-Z]+[0-9]*\)\([A-Z]+[0-9]*\*4\), [A-Z]+[0-9]*`
	s |= x[i+5]
	// 386: `XORL\t24\([A-Z]+\)\([A-Z]+\*4\), [A-Z]+`
	// amd64: `XORL\t24\([A-Z]+[0-9]*\)\([A-Z]+[0-9]*\*4\), [A-Z]+[0-9]*`
	s ^= x[i+6]
	return s
}

func idxLoadPlusOp64(x []int64, i int) int64 {
	s := x[0]
	// amd64: `ADDQ\t8\([A-Z]+[0-9]*\)\([A-Z]+[0-9]*\*8\), [A-Z]+[0-9]*`
	s += x[i+1]
	// amd64: `SUBQ\t16\([A-Z]+[0-9]*\)\([A-Z]+[0-9]*\*8\), [A-Z]+[0-9]*`
	s -= x[i+2]
	// amd64: `ANDQ\t24\([A-Z]+[0-9]*\)\([A-Z]+[0-9]*\*8\), [A-Z]+[0-9]*`
	s &= x[i+3]
	// amd64: `ORQ\t32\([A-Z]+[0-9]*\)\([A-Z]+[0-9]*\*8\), [A-Z]+[0-9]*`
	s |= x[i+4]
	// amd64: `XORQ\t40\([A-Z]+[0-9]*\)\([A-Z]+[0-9]*\*8\), [A-Z]+[0-9]*`
	s ^= x[i+5]
	return s
}

func idxStorePlusOp32(x []int32, i int, v int32) {
	// 386: `ADDL\t[A-Z]+, 4\([A-Z]+\)\([A-Z]+\*4\)`
	// amd64: `ADDL\t[A-Z]+[0-9]*, 4\([A-Z]+[0-9]*\)\([A-Z]+[0-9]*\*4\)`
	x[i+1] += v
	// 386: `SUBL\t[A-Z]+, 8\([A-Z]+\)\([A-Z]+\*4\)`
	// amd64: `SUBL\t[A-Z]+[0-9]*, 8\([A-Z]+[0-9]*\)\([A-Z]+[0-9]*\*4\)`
	x[i+2] -= v
	// 386: `ANDL\t[A-Z]+, 12\([A-Z]+\)\([A-Z]+\*4\)`
	// amd64: `ANDL\t[A-Z]+[0-9]*, 12\([A-Z]+[0-9]*\)\([A-Z]+[0-9]*\*4\)`
	x[i+3] &= v
	// 386: `ORL\t[A-Z]+, 16\([A-Z]+\)\([A-Z]+\*4\)`
	// amd64: `ORL\t[A-Z]+[0-9]*, 16\([A-Z]+[0-9]*\)\([A-Z]+[0-9]*\*4\)`
	x[i+4] |= v
	// 386: `XORL\t[A-Z]+, 20\([A-Z]+\)\([A-Z]+\*4\)`
	// amd64: `XORL\t[A-Z]+[0-9]*, 20\([A-Z]+[0-9]*\)\([A-Z]+[0-9]*\*4\)`
	x[i+5] ^= v

	// 386: `ADDL\t[$]77, 24\([A-Z]+\)\([A-Z]+\*4\)`
	// amd64: `ADDL\t[$]77, 24\([A-Z]+[0-9]*\)\([A-Z]+[0-9]*\*4\)`
	x[i+6] += 77
	// 386: `ANDL\t[$]77, 28\([A-Z]+\)\([A-Z]+\*4\)`
	// amd64: `ANDL\t[$]77, 28\([A-Z]+[0-9]*\)\([A-Z]+[0-9]*\*4\)`
	x[i+7] &= 77
	// 386: `ORL\t[$]77, 32\([A-Z]+\)\([A-Z]+\*4\)`
	// amd64: `ORL\t[$]77, 32\([A-Z]+[0-9]*\)\([A-Z]+[0-9]*\*4\)`
	x[i+8] |= 77
	// 386: `XORL\t[$]77, 36\([A-Z]+\)\([A-Z]+\*4\)`
	// amd64: `XORL\t[$]77, 36\([A-Z]+[0-9]*\)\([A-Z]+[0-9]*\*4\)`
	x[i+9] ^= 77
}

func idxStorePlusOp64(x []int64, i int, v int64) {
	// amd64: `ADDQ\t[A-Z]+[0-9]*, 8\([A-Z]+[0-9]*\)\([A-Z]+[0-9]*\*8\)`
	x[i+1] += v
	// amd64: `SUBQ\t[A-Z]+[0-9]*, 16\([A-Z]+[0-9]*\)\([A-Z]+[0-9]*\*8\)`
	x[i+2] -= v
	// amd64: `ANDQ\t[A-Z]+[0-9]*, 24\([A-Z]+[0-9]*\)\([A-Z]+[0-9]*\*8\)`
	x[i+3] &= v
	// amd64: `ORQ\t[A-Z]+[0-9]*, 32\([A-Z]+[0-9]*\)\([A-Z]+[0-9]*\*8\)`
	x[i+4] |= v
	// amd64: `XORQ\t[A-Z]+[0-9]*, 40\([A-Z]+[0-9]*\)\([A-Z]+[0-9]*\*8\)`
	x[i+5] ^= v

	// amd64: `ADDQ\t[$]77, 48\([A-Z]+[0-9]*\)\([A-Z]+[0-9]*\*8\)`
	x[i+6] += 77
	// amd64: `ANDQ\t[$]77, 56\([A-Z]+[0-9]*\)\([A-Z]+[0-9]*\*8\)`
	x[i+7] &= 77
	// amd64: `ORQ\t[$]77, 64\([A-Z]+[0-9]*\)\([A-Z]+[0-9]*\*8\)`
	x[i+8] |= 77
	// amd64: `XORQ\t[$]77, 72\([A-Z]+[0-9]*\)\([A-Z]+[0-9]*\*8\)`
	x[i+9] ^= 77
}

func idxCompare(i int) int {
	// amd64: `MOVBLZX\t1\([A-Z]+[0-9]*\)\([A-Z]+[0-9]*\*1\), [A-Z]+[0-9]*`
	if x8[i+1] < x8[0] {
		return 0
	}
	// amd64: `MOVWLZX\t2\([A-Z]+[0-9]*\)\([A-Z]+[0-9]*\*2\), [A-Z]+[0-9]*`
	if x16[i+1] < x16[0] {
		return 0
	}
	// amd64: `MOVWLZX\t2\([A-Z]+[0-9]*\)\([A-Z]+[0-9]*\*[12]\), [A-Z]+[0-9]*`
	if x16[16*i+1] < x16[0] {
		return 0
	}
	// amd64: `MOVL\t4\([A-Z]+[0-9]*\)\([A-Z]+[0-9]*\*4\), [A-Z]+[0-9]*`
	if x32[i+1] < x32[0] {
		return 0
	}
	// amd64: `MOVL\t4\([A-Z]+[0-9]*\)\([A-Z]+[0-9]*\*[14]\), [A-Z]+[0-9]*`
	if x32[16*i+1] < x32[0] {
		return 0
	}
	// amd64: `MOVQ\t8\([A-Z]+[0-9]*\)\([A-Z]+[0-9]*\*8\), [A-Z]+[0-9]*`
	if x64[i+1] < x64[0] {
		return 0
	}
	// amd64: `MOVQ\t8\([A-Z]+[0-9]*\)\([A-Z]+[0-9]*\*[18]\), [A-Z]+[0-9]*`
	if x64[16*i+1] < x64[0] {
		return 0
	}
	// amd64: `MOVBLZX\t2\([A-Z]+[0-9]*\)\([A-Z]+[0-9]*\*1\), [A-Z]+[0-9]*`
	if x8[i+2] < 77 {
		return 0
	}
	// amd64: `MOVWLZX\t4\([A-Z]+[0-9]*\)\([A-Z]+[0-9]*\*2\), [A-Z]+[0-9]*`
	if x16[i+2] < 77 {
		return 0
	}
	// amd64: `MOVWLZX\t4\([A-Z]+[0-9]*\)\([A-Z]+[0-9]*\*[12]\), [A-Z]+[0-9]*`
	if x16[16*i+2] < 77 {
		return 0
	}
	// amd64: `MOVL\t8\([A-Z]+[0-9]*\)\([A-Z]+[0-9]*\*4\), [A-Z]+[0-9]*`
	if x32[i+2] < 77 {
		return 0
	}
	// amd64: `MOVL\t8\([A-Z]+[0-9]*\)\([A-Z]+[0-9]*\*[14]\), [A-Z]+[0-9]*`
	if x32[16*i+2] < 77 {
		return 0
	}
	// amd64: `MOVQ\t16\([A-Z]+[0-9]*\)\([A-Z]+[0-9]*\*8\), [A-Z]+[0-9]*`
	if x64[i+2] < 77 {
		return 0
	}
	// amd64: `MOVQ\t16\([A-Z]+[0-9]*\)\([A-Z]+[0-9]*\*[18]\), [A-Z]+[0-9]*`
	if x64[16*i+2] < 77 {
		return 0
	}
	return 1
}

func idxFloatOps(a []float64, b []float32, i int) (float64, float32) {
	c := float64(7)
	// amd64: `ADDSD\t8\([A-Z]+[0-9]*\)\([A-Z]+[0-9]*\*8\), X[0-9]+`
	c += a[i+1]
	// amd64: `SUBSD\t16\([A-Z]+[0-9]*\)\([A-Z]+[0-9]*\*8\), X[0-9]+`
	c -= a[i+2]
	// amd64: `MULSD\t24\([A-Z]+[0-9]*\)\([A-Z]+[0-9]*\*8\), X[0-9]+`
	c *= a[i+3]
	// amd64: `DIVSD\t32\([A-Z]+[0-9]*\)\([A-Z]+[0-9]*\*8\), X[0-9]+`
	c /= a[i+4]

	d := float32(8)
	// amd64: `ADDSS\t4\([A-Z]+[0-9]*\)\([A-Z]+[0-9]*\*4\), X[0-9]+`
	d += b[i+1]
	// amd64: `SUBSS\t8\([A-Z]+[0-9]*\)\([A-Z]+[0-9]*\*4\), X[0-9]+`
	d -= b[i+2]
	// amd64: `MULSS\t12\([A-Z]+[0-9]*\)\([A-Z]+[0-9]*\*4\), X[0-9]+`
	d *= b[i+3]
	// amd64: `DIVSS\t16\([A-Z]+[0-9]*\)\([A-Z]+[0-9]*\*4\), X[0-9]+`
	d /= b[i+4]
	return c, d
}

func storeTest(a []bool, v int, i int) {
	// amd64: `BTL\t\$0,`,`SETCS\t4\([A-Z]+[0-9]*\)`
	a[4] = v&1 != 0
	// amd64: `BTL\t\$1,`,`SETCS\t3\([A-Z]+[0-9]*\)\([A-Z]+[0-9]*\*1\)`
	a[3+i] = v&2 != 0
}

func bitOps(p *[12]uint64) {
	// amd64: `ORQ\t\$8, \(AX\)`
	p[0] |= 8
	// amd64: `ORQ\t\$1073741824, 8\(AX\)`
	p[1] |= 1 << 30
	// amd64: `BTSQ\t\$31, 16\(AX\)`
	p[2] |= 1 << 31
	// amd64: `BTSQ\t\$63, 24\(AX\)`
	p[3] |= 1 << 63

	// amd64: `ANDQ\t\$-9, 32\(AX\)`
	p[4] &^= 8
	// amd64: `ANDQ\t\$-1073741825, 40\(AX\)`
	p[5] &^= 1 << 30
	// amd64: `BTRQ\t\$31, 48\(AX\)`
	p[6] &^= 1 << 31
	// amd64: `BTRQ\t\$63, 56\(AX\)`
	p[7] &^= 1 << 63

	// amd64: `XORQ\t\$8, 64\(AX\)`
	p[8] ^= 8
	// amd64: `XORQ\t\$1073741824, 72\(AX\)`
	p[9] ^= 1 << 30
	// amd64: `BTCQ\t\$31, 80\(AX\)`
	p[10] ^= 1 << 31
	// amd64: `BTCQ\t\$63, 88\(AX\)`
	p[11] ^= 1 << 63
}

"""



```