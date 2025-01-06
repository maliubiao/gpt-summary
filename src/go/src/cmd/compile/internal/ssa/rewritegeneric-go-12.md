Response:
Let's break down the thought process for analyzing the provided Go code snippet.

**1. Understanding the Goal:**

The request asks for an analysis of a specific Go file (`rewritegeneric.go`) within the Go compiler's source code. The key is to understand *what this file does* within the larger compilation process. The prompt provides a snippet of the file's content.

**2. Initial Code Scan and Pattern Recognition:**

The first thing that jumps out is the repetitive structure of the functions. Each function has a name like `rewriteValuegeneric_OpSomething` and takes a `*Value` as input. Inside, there are loops checking the `Op` field of the input `Value` and then performing some transformations. The `// match:` and `// result:` comments are strong indicators of pattern matching and replacement.

**3. Identifying Key Data Structures and Operations:**

* **`Value`:** This is clearly a central data structure. The `Op` field suggests it represents an operation or instruction. The `Args` field suggests it has operands. Methods like `reset`, `copyOf`, and `AddArg` indicate it's mutable.
* **`Op...` Constants:** The code frequently checks `v_0.Op == OpSomething`. This strongly implies that `OpSomething` are constants representing different operation types.
* **`auxIntToInt...`, `int...ToAuxInt`:** These functions suggest the `AuxInt` field holds auxiliary integer data, and these functions handle conversions.
* **`config`:**  Used in the `Xor` functions with `canRotate(config, ...)`, suggesting this is a configuration object related to the target architecture or compilation settings.
* **`b`:**  Appears to be a block (`v.Block`). The use of `b.NewValue0` suggests it's part of a larger control flow graph representation.
* **`rewriteValuegeneric_Op...` Function Naming:** The naming convention is very strong evidence that each function handles the rewriting of a specific operation type.

**4. Formulating Hypotheses and Connecting to Compiler Concepts:**

Based on the patterns, we can hypothesize:

* **SSA (Static Single Assignment):** The manipulation of `Value` objects, the concept of "rewriting," and the presence of "blocks" strongly suggest this code is part of the SSA optimization passes in the Go compiler. SSA is a common intermediate representation in compilers.
* **Generic Rewriting:** The "generic" in the filename suggests these rewrites are not specific to a particular architecture.
* **Optimization:** The transformations appear to be simplifying or canonicalizing expressions. For example, `Xor x x` becomes `0`.
* **Pattern Matching:** The `// match:` and `// result:` comments clearly indicate a pattern matching and replacement system.

**5. Inferring the Purpose of Specific Rewrites:**

By examining individual rewrite rules, we can deduce their specific optimization goals:

* **Constant Folding:**  Rules like `Trunc64to16 (Const64 [c])` -> `Const16 [int16(c)]` perform constant folding.
* **Identity Elimination:** Rules like `Trunc32to8 (SignExt8to32 x)` -> `x` eliminate redundant operations.
* **Algebraic Simplification:** Rules like `Xor x x` -> `0` are algebraic simplifications.
* **Strength Reduction/Operation Substitution:**  The `Xor` rules involving shifts and `canRotate` suggest the substitution of XOR and shifts with a more efficient `RotateLeft` operation when possible.

**6. Constructing Examples:**

To illustrate the rewrites, we create simple Go code snippets that would produce the patterns being matched. This helps to solidify understanding and demonstrate the optimization in action. We also need to imagine what the compiler's intermediate representation might look like for these examples (the "hypothetical input").

**7. Addressing Specific Questions from the Prompt:**

* **Functionality:** List the types of optimizations being performed (constant folding, identity elimination, etc.).
* **Go Feature Implementation:** Connect the rewrites to general Go language features (integer types, bitwise operations).
* **Code Examples:** Provide the Go code snippets and the hypothetical SSA representation.
* **Command-line Arguments:**  Since the code doesn't directly handle command-line arguments, explain that this is a compiler *internal* and not directly influenced by user-provided flags.
* **Common Mistakes:**  As this is compiler code, user mistakes are not directly relevant.
* **Overall Function:** Summarize the role of the file within the Go compiler's optimization pipeline.
* **Part 13 of 13:** Note that this is the final part, suggesting it might be a culmination of the rewriting process.

**8. Refinement and Organization:**

Finally, organize the findings logically, providing clear explanations and examples. Use the terminology encountered in the code (like `Op`, `Value`, `AuxInt`).

**Self-Correction/Refinement During the Process:**

* Initially, one might focus too much on the low-level bit manipulations. Stepping back to see the higher-level patterns of function naming and the `// match:` comments is crucial.
*  Realizing that this is *generic* rewriting helps to understand why the optimizations are broad and not tied to specific CPU instructions (at this stage).
*  Connecting the concepts to compiler theory (SSA, optimization passes) provides a stronger framework for understanding the code's purpose.

By following this systematic approach of code scanning, pattern recognition, hypothesis formulation, example construction, and addressing the specific questions, we can effectively analyze and explain the functionality of the given Go code snippet.
This Go code snippet, residing in `go/src/cmd/compile/internal/ssa/rewritegeneric.go`, is a part of the **generic SSA (Static Single Assignment) rewriting rules** within the Go compiler. Being the 13th and final part suggests it contains the last set of these rules.

Here's a breakdown of its functionality:

**Core Functionality:**

This file defines a series of functions named `rewriteValuegeneric_Op...`. Each of these functions is responsible for **identifying and transforming specific patterns of SSA operations** into more efficient or canonical forms. This process is a crucial part of the Go compiler's optimization pipeline.

**Specific Operations Handled in This Snippet:**

This particular snippet focuses on rewriting operations related to:

* **Truncation (Casting to smaller integer types):**  `Trunc32to8`, `Trunc64to16`, `Trunc64to32`, `Trunc64to8`. These functions look for opportunities to simplify truncations based on the input value's properties.
* **Bitwise XOR:** `Xor16`, `Xor32`, `Xor64`, `Xor8`. These functions implement various algebraic simplifications and optimizations for XOR operations, including constant folding, identity laws, and recognizing rotate operations.
* **Zeroing Memory:** `Zero`. This function aims to optimize memory zeroing operations, potentially by recognizing and leveraging other memory operations.
* **Zero Extension (Casting to larger unsigned integer types):** `ZeroExt16to32`, `ZeroExt16to64`, `ZeroExt32to64`, `ZeroExt8to16`, `ZeroExt8to32`, `ZeroExt8to64`. These functions simplify zero extensions based on the input value.

**Illustrative Examples and Reasoning:**

Let's break down some of the rewrite rules with examples:

**1. Truncation Optimization:**

```go
// match: (Trunc32to8 (SignExt8to32 x))
// result: x
for {
	if v_0.Op != OpSignExt8to32 {
		break
	}
	x := v_0.Args[0]
	v.copyOf(x)
	return true
}
```

* **Function:** `rewriteValuegeneric_OpTrunc32to8`
* **Input (Hypothetical SSA):** `v = Trunc32to8(SignExt8to32(some_8bit_value))`
* **Reasoning:** If you sign-extend an 8-bit value to 32 bits and then immediately truncate it back to 8 bits, the sign extension is redundant. The original 8-bit value is sufficient.
* **Output (Hypothetical SSA):** `v = some_8bit_value`
* **Go Code Example:**

```go
package main

func main() {
	var a int8 = 10
	b := int32(a) // Implicit sign extension
	c := int8(b)  // Explicit truncation
	println(c)
}
```
In this example, the compiler's SSA rewriter might transform the intermediate representation of `c := int8(b)` to directly use the value of `a`.

**2. XOR Optimization (Constant Folding and Identity):**

```go
// match: (Xor16 (Const16 [c]) (Const16 [d]))
// result: (Const16 [c^d])
for {
	for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
		if v_0.Op != OpConst16 {
			continue
		}
		c := auxIntToInt16(v_0.AuxInt)
		if v_1.Op != OpConst16 {
			continue
		}
		d := auxIntToInt16(v_1.AuxInt)
		v.reset(OpConst16)
		v.AuxInt = int16ToAuxInt(c ^ d)
		return true
	}
	break
}

// match: (Xor16 x x)
// result: (Const16 [0])
for {
	x := v_0
	if x != v_1 {
		break
	}
	v.reset(OpConst16)
	v.AuxInt = int16ToAuxInt(0)
	return true
}
```

* **Function:** `rewriteValuegeneric_OpXor16`
* **Constant Folding Input (Hypothetical SSA):** `v = Xor16(Const16(5), Const16(3))`
* **Reasoning:**  If both operands of XOR are constants, the XOR operation can be performed at compile time.
* **Constant Folding Output (Hypothetical SSA):** `v = Const16(6)` (5 XOR 3 = 6)
* **Identity Input (Hypothetical SSA):** `v = Xor16(some_16bit_value, some_16bit_value)`
* **Reasoning:** XORing a value with itself always results in zero.
* **Identity Output (Hypothetical SSA):** `v = Const16(0)`
* **Go Code Example:**

```go
package main

func main() {
	a := 5 ^ 3
	var b uint16 = 10
	c := b ^ b
	println(a, c)
}
```
The compiler would perform the `5 ^ 3` at compile time and recognize that `b ^ b` is always 0.

**3. XOR Optimization (Rotation Recognition):**

```go
// match: (Xor16 (Lsh16x64 x z:(Const64 <t> [c])) (Rsh16Ux64 x (Const64 [d])))
// cond: c < 16 && d == 16-c && canRotate(config, 16)
// result: (RotateLeft16 x z)
```

* **Function:** `rewriteValuegeneric_OpXor16`
* **Input (Hypothetical SSA):** `v = Xor16(Lsh16x64(val, Const64(3)), Rsh16Ux64(val, Const64(13)))`
* **Reasoning:** This pattern recognizes the idiom for a left bitwise rotation. Left shifting by `c` bits and then XORing with the result of a right unsigned shift by `16-c` bits is equivalent to a rotate left operation, which might have a more efficient instruction on the target architecture. The `canRotate(config, 16)` condition checks if the target architecture supports a 16-bit rotate instruction.
* **Output (Hypothetical SSA):** `v = RotateLeft16(val, Const64(3))`
* **Go Code Example:**

```go
package main

func rotateLeft16(val uint16, k uint) uint16 {
	return (val << k) | (val >> (16 - k))
}

func main() {
	var a uint16 = 0b0000000000000001
	rotated := rotateLeft16(a, 3)
	println(rotated) // Output: 8
}
```
The compiler, upon seeing the shift and XOR pattern in the `rotateLeft16` function (or similar code), can potentially replace it with a dedicated rotate instruction if the architecture supports it.

**Command-line Parameters:**

This file doesn't directly handle command-line parameters. The SSA rewriting process is an internal step within the Go compiler. Compiler flags might indirectly influence which rewriting rules are applied or the overall optimization level, but this specific code focuses on the transformation logic itself.

**User Mistakes:**

Users don't directly interact with this code. It's part of the compiler's internal workings. However, understanding these rewrite rules can help explain why certain code patterns might be more efficient than others. For example, understanding rotate recognition might encourage using the shift and XOR idiom for rotation where a dedicated rotate function isn't available or obvious.

**Summary of Functionality (Part 13):**

As the final part of the generic SSA rewriting rules, this file completes the set of transformations for various generic operations. It focuses on further simplifying and optimizing common integer operations like truncation, bitwise XOR (including recognizing rotations), and memory zeroing. These rewrites contribute to generating more efficient machine code by transforming the intermediate representation into a better form before architecture-specific optimizations are applied. The "generic" nature means these optimizations are applicable across different target architectures.

Prompt: 
```
这是路径为go/src/cmd/compile/internal/ssa/rewritegeneric.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
这是第13部分，共13部分，请归纳一下它的功能

"""
result: x
	for {
		if v_0.Op != OpSignExt8to32 {
			break
		}
		x := v_0.Args[0]
		v.copyOf(x)
		return true
	}
	// match: (Trunc32to8 (And32 (Const32 [y]) x))
	// cond: y&0xFF == 0xFF
	// result: (Trunc32to8 x)
	for {
		if v_0.Op != OpAnd32 {
			break
		}
		_ = v_0.Args[1]
		v_0_0 := v_0.Args[0]
		v_0_1 := v_0.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, v_0_0, v_0_1 = _i0+1, v_0_1, v_0_0 {
			if v_0_0.Op != OpConst32 {
				continue
			}
			y := auxIntToInt32(v_0_0.AuxInt)
			x := v_0_1
			if !(y&0xFF == 0xFF) {
				continue
			}
			v.reset(OpTrunc32to8)
			v.AddArg(x)
			return true
		}
		break
	}
	return false
}
func rewriteValuegeneric_OpTrunc64to16(v *Value) bool {
	v_0 := v.Args[0]
	// match: (Trunc64to16 (Const64 [c]))
	// result: (Const16 [int16(c)])
	for {
		if v_0.Op != OpConst64 {
			break
		}
		c := auxIntToInt64(v_0.AuxInt)
		v.reset(OpConst16)
		v.AuxInt = int16ToAuxInt(int16(c))
		return true
	}
	// match: (Trunc64to16 (ZeroExt8to64 x))
	// result: (ZeroExt8to16 x)
	for {
		if v_0.Op != OpZeroExt8to64 {
			break
		}
		x := v_0.Args[0]
		v.reset(OpZeroExt8to16)
		v.AddArg(x)
		return true
	}
	// match: (Trunc64to16 (ZeroExt16to64 x))
	// result: x
	for {
		if v_0.Op != OpZeroExt16to64 {
			break
		}
		x := v_0.Args[0]
		v.copyOf(x)
		return true
	}
	// match: (Trunc64to16 (SignExt8to64 x))
	// result: (SignExt8to16 x)
	for {
		if v_0.Op != OpSignExt8to64 {
			break
		}
		x := v_0.Args[0]
		v.reset(OpSignExt8to16)
		v.AddArg(x)
		return true
	}
	// match: (Trunc64to16 (SignExt16to64 x))
	// result: x
	for {
		if v_0.Op != OpSignExt16to64 {
			break
		}
		x := v_0.Args[0]
		v.copyOf(x)
		return true
	}
	// match: (Trunc64to16 (And64 (Const64 [y]) x))
	// cond: y&0xFFFF == 0xFFFF
	// result: (Trunc64to16 x)
	for {
		if v_0.Op != OpAnd64 {
			break
		}
		_ = v_0.Args[1]
		v_0_0 := v_0.Args[0]
		v_0_1 := v_0.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, v_0_0, v_0_1 = _i0+1, v_0_1, v_0_0 {
			if v_0_0.Op != OpConst64 {
				continue
			}
			y := auxIntToInt64(v_0_0.AuxInt)
			x := v_0_1
			if !(y&0xFFFF == 0xFFFF) {
				continue
			}
			v.reset(OpTrunc64to16)
			v.AddArg(x)
			return true
		}
		break
	}
	return false
}
func rewriteValuegeneric_OpTrunc64to32(v *Value) bool {
	v_0 := v.Args[0]
	// match: (Trunc64to32 (Const64 [c]))
	// result: (Const32 [int32(c)])
	for {
		if v_0.Op != OpConst64 {
			break
		}
		c := auxIntToInt64(v_0.AuxInt)
		v.reset(OpConst32)
		v.AuxInt = int32ToAuxInt(int32(c))
		return true
	}
	// match: (Trunc64to32 (ZeroExt8to64 x))
	// result: (ZeroExt8to32 x)
	for {
		if v_0.Op != OpZeroExt8to64 {
			break
		}
		x := v_0.Args[0]
		v.reset(OpZeroExt8to32)
		v.AddArg(x)
		return true
	}
	// match: (Trunc64to32 (ZeroExt16to64 x))
	// result: (ZeroExt16to32 x)
	for {
		if v_0.Op != OpZeroExt16to64 {
			break
		}
		x := v_0.Args[0]
		v.reset(OpZeroExt16to32)
		v.AddArg(x)
		return true
	}
	// match: (Trunc64to32 (ZeroExt32to64 x))
	// result: x
	for {
		if v_0.Op != OpZeroExt32to64 {
			break
		}
		x := v_0.Args[0]
		v.copyOf(x)
		return true
	}
	// match: (Trunc64to32 (SignExt8to64 x))
	// result: (SignExt8to32 x)
	for {
		if v_0.Op != OpSignExt8to64 {
			break
		}
		x := v_0.Args[0]
		v.reset(OpSignExt8to32)
		v.AddArg(x)
		return true
	}
	// match: (Trunc64to32 (SignExt16to64 x))
	// result: (SignExt16to32 x)
	for {
		if v_0.Op != OpSignExt16to64 {
			break
		}
		x := v_0.Args[0]
		v.reset(OpSignExt16to32)
		v.AddArg(x)
		return true
	}
	// match: (Trunc64to32 (SignExt32to64 x))
	// result: x
	for {
		if v_0.Op != OpSignExt32to64 {
			break
		}
		x := v_0.Args[0]
		v.copyOf(x)
		return true
	}
	// match: (Trunc64to32 (And64 (Const64 [y]) x))
	// cond: y&0xFFFFFFFF == 0xFFFFFFFF
	// result: (Trunc64to32 x)
	for {
		if v_0.Op != OpAnd64 {
			break
		}
		_ = v_0.Args[1]
		v_0_0 := v_0.Args[0]
		v_0_1 := v_0.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, v_0_0, v_0_1 = _i0+1, v_0_1, v_0_0 {
			if v_0_0.Op != OpConst64 {
				continue
			}
			y := auxIntToInt64(v_0_0.AuxInt)
			x := v_0_1
			if !(y&0xFFFFFFFF == 0xFFFFFFFF) {
				continue
			}
			v.reset(OpTrunc64to32)
			v.AddArg(x)
			return true
		}
		break
	}
	return false
}
func rewriteValuegeneric_OpTrunc64to8(v *Value) bool {
	v_0 := v.Args[0]
	// match: (Trunc64to8 (Const64 [c]))
	// result: (Const8 [int8(c)])
	for {
		if v_0.Op != OpConst64 {
			break
		}
		c := auxIntToInt64(v_0.AuxInt)
		v.reset(OpConst8)
		v.AuxInt = int8ToAuxInt(int8(c))
		return true
	}
	// match: (Trunc64to8 (ZeroExt8to64 x))
	// result: x
	for {
		if v_0.Op != OpZeroExt8to64 {
			break
		}
		x := v_0.Args[0]
		v.copyOf(x)
		return true
	}
	// match: (Trunc64to8 (SignExt8to64 x))
	// result: x
	for {
		if v_0.Op != OpSignExt8to64 {
			break
		}
		x := v_0.Args[0]
		v.copyOf(x)
		return true
	}
	// match: (Trunc64to8 (And64 (Const64 [y]) x))
	// cond: y&0xFF == 0xFF
	// result: (Trunc64to8 x)
	for {
		if v_0.Op != OpAnd64 {
			break
		}
		_ = v_0.Args[1]
		v_0_0 := v_0.Args[0]
		v_0_1 := v_0.Args[1]
		for _i0 := 0; _i0 <= 1; _i0, v_0_0, v_0_1 = _i0+1, v_0_1, v_0_0 {
			if v_0_0.Op != OpConst64 {
				continue
			}
			y := auxIntToInt64(v_0_0.AuxInt)
			x := v_0_1
			if !(y&0xFF == 0xFF) {
				continue
			}
			v.reset(OpTrunc64to8)
			v.AddArg(x)
			return true
		}
		break
	}
	return false
}
func rewriteValuegeneric_OpXor16(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	config := b.Func.Config
	// match: (Xor16 (Const16 [c]) (Const16 [d]))
	// result: (Const16 [c^d])
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpConst16 {
				continue
			}
			c := auxIntToInt16(v_0.AuxInt)
			if v_1.Op != OpConst16 {
				continue
			}
			d := auxIntToInt16(v_1.AuxInt)
			v.reset(OpConst16)
			v.AuxInt = int16ToAuxInt(c ^ d)
			return true
		}
		break
	}
	// match: (Xor16 x x)
	// result: (Const16 [0])
	for {
		x := v_0
		if x != v_1 {
			break
		}
		v.reset(OpConst16)
		v.AuxInt = int16ToAuxInt(0)
		return true
	}
	// match: (Xor16 (Const16 [0]) x)
	// result: x
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpConst16 || auxIntToInt16(v_0.AuxInt) != 0 {
				continue
			}
			x := v_1
			v.copyOf(x)
			return true
		}
		break
	}
	// match: (Xor16 (Com16 x) x)
	// result: (Const16 [-1])
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpCom16 {
				continue
			}
			x := v_0.Args[0]
			if x != v_1 {
				continue
			}
			v.reset(OpConst16)
			v.AuxInt = int16ToAuxInt(-1)
			return true
		}
		break
	}
	// match: (Xor16 (Const16 [-1]) x)
	// result: (Com16 x)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpConst16 || auxIntToInt16(v_0.AuxInt) != -1 {
				continue
			}
			x := v_1
			v.reset(OpCom16)
			v.AddArg(x)
			return true
		}
		break
	}
	// match: (Xor16 x (Xor16 x y))
	// result: y
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			if v_1.Op != OpXor16 {
				continue
			}
			_ = v_1.Args[1]
			v_1_0 := v_1.Args[0]
			v_1_1 := v_1.Args[1]
			for _i1 := 0; _i1 <= 1; _i1, v_1_0, v_1_1 = _i1+1, v_1_1, v_1_0 {
				if x != v_1_0 {
					continue
				}
				y := v_1_1
				v.copyOf(y)
				return true
			}
		}
		break
	}
	// match: (Xor16 (Xor16 i:(Const16 <t>) z) x)
	// cond: (z.Op != OpConst16 && x.Op != OpConst16)
	// result: (Xor16 i (Xor16 <t> z x))
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpXor16 {
				continue
			}
			_ = v_0.Args[1]
			v_0_0 := v_0.Args[0]
			v_0_1 := v_0.Args[1]
			for _i1 := 0; _i1 <= 1; _i1, v_0_0, v_0_1 = _i1+1, v_0_1, v_0_0 {
				i := v_0_0
				if i.Op != OpConst16 {
					continue
				}
				t := i.Type
				z := v_0_1
				x := v_1
				if !(z.Op != OpConst16 && x.Op != OpConst16) {
					continue
				}
				v.reset(OpXor16)
				v0 := b.NewValue0(v.Pos, OpXor16, t)
				v0.AddArg2(z, x)
				v.AddArg2(i, v0)
				return true
			}
		}
		break
	}
	// match: (Xor16 (Const16 <t> [c]) (Xor16 (Const16 <t> [d]) x))
	// result: (Xor16 (Const16 <t> [c^d]) x)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpConst16 {
				continue
			}
			t := v_0.Type
			c := auxIntToInt16(v_0.AuxInt)
			if v_1.Op != OpXor16 {
				continue
			}
			_ = v_1.Args[1]
			v_1_0 := v_1.Args[0]
			v_1_1 := v_1.Args[1]
			for _i1 := 0; _i1 <= 1; _i1, v_1_0, v_1_1 = _i1+1, v_1_1, v_1_0 {
				if v_1_0.Op != OpConst16 || v_1_0.Type != t {
					continue
				}
				d := auxIntToInt16(v_1_0.AuxInt)
				x := v_1_1
				v.reset(OpXor16)
				v0 := b.NewValue0(v.Pos, OpConst16, t)
				v0.AuxInt = int16ToAuxInt(c ^ d)
				v.AddArg2(v0, x)
				return true
			}
		}
		break
	}
	// match: (Xor16 (Lsh16x64 x z:(Const64 <t> [c])) (Rsh16Ux64 x (Const64 [d])))
	// cond: c < 16 && d == 16-c && canRotate(config, 16)
	// result: (RotateLeft16 x z)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpLsh16x64 {
				continue
			}
			_ = v_0.Args[1]
			x := v_0.Args[0]
			z := v_0.Args[1]
			if z.Op != OpConst64 {
				continue
			}
			c := auxIntToInt64(z.AuxInt)
			if v_1.Op != OpRsh16Ux64 {
				continue
			}
			_ = v_1.Args[1]
			if x != v_1.Args[0] {
				continue
			}
			v_1_1 := v_1.Args[1]
			if v_1_1.Op != OpConst64 {
				continue
			}
			d := auxIntToInt64(v_1_1.AuxInt)
			if !(c < 16 && d == 16-c && canRotate(config, 16)) {
				continue
			}
			v.reset(OpRotateLeft16)
			v.AddArg2(x, z)
			return true
		}
		break
	}
	// match: (Xor16 left:(Lsh16x64 x y) right:(Rsh16Ux64 x (Sub64 (Const64 [16]) y)))
	// cond: (shiftIsBounded(left) || shiftIsBounded(right)) && canRotate(config, 16)
	// result: (RotateLeft16 x y)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			left := v_0
			if left.Op != OpLsh16x64 {
				continue
			}
			y := left.Args[1]
			x := left.Args[0]
			right := v_1
			if right.Op != OpRsh16Ux64 {
				continue
			}
			_ = right.Args[1]
			if x != right.Args[0] {
				continue
			}
			right_1 := right.Args[1]
			if right_1.Op != OpSub64 {
				continue
			}
			_ = right_1.Args[1]
			right_1_0 := right_1.Args[0]
			if right_1_0.Op != OpConst64 || auxIntToInt64(right_1_0.AuxInt) != 16 || y != right_1.Args[1] || !((shiftIsBounded(left) || shiftIsBounded(right)) && canRotate(config, 16)) {
				continue
			}
			v.reset(OpRotateLeft16)
			v.AddArg2(x, y)
			return true
		}
		break
	}
	// match: (Xor16 left:(Lsh16x32 x y) right:(Rsh16Ux32 x (Sub32 (Const32 [16]) y)))
	// cond: (shiftIsBounded(left) || shiftIsBounded(right)) && canRotate(config, 16)
	// result: (RotateLeft16 x y)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			left := v_0
			if left.Op != OpLsh16x32 {
				continue
			}
			y := left.Args[1]
			x := left.Args[0]
			right := v_1
			if right.Op != OpRsh16Ux32 {
				continue
			}
			_ = right.Args[1]
			if x != right.Args[0] {
				continue
			}
			right_1 := right.Args[1]
			if right_1.Op != OpSub32 {
				continue
			}
			_ = right_1.Args[1]
			right_1_0 := right_1.Args[0]
			if right_1_0.Op != OpConst32 || auxIntToInt32(right_1_0.AuxInt) != 16 || y != right_1.Args[1] || !((shiftIsBounded(left) || shiftIsBounded(right)) && canRotate(config, 16)) {
				continue
			}
			v.reset(OpRotateLeft16)
			v.AddArg2(x, y)
			return true
		}
		break
	}
	// match: (Xor16 left:(Lsh16x16 x y) right:(Rsh16Ux16 x (Sub16 (Const16 [16]) y)))
	// cond: (shiftIsBounded(left) || shiftIsBounded(right)) && canRotate(config, 16)
	// result: (RotateLeft16 x y)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			left := v_0
			if left.Op != OpLsh16x16 {
				continue
			}
			y := left.Args[1]
			x := left.Args[0]
			right := v_1
			if right.Op != OpRsh16Ux16 {
				continue
			}
			_ = right.Args[1]
			if x != right.Args[0] {
				continue
			}
			right_1 := right.Args[1]
			if right_1.Op != OpSub16 {
				continue
			}
			_ = right_1.Args[1]
			right_1_0 := right_1.Args[0]
			if right_1_0.Op != OpConst16 || auxIntToInt16(right_1_0.AuxInt) != 16 || y != right_1.Args[1] || !((shiftIsBounded(left) || shiftIsBounded(right)) && canRotate(config, 16)) {
				continue
			}
			v.reset(OpRotateLeft16)
			v.AddArg2(x, y)
			return true
		}
		break
	}
	// match: (Xor16 left:(Lsh16x8 x y) right:(Rsh16Ux8 x (Sub8 (Const8 [16]) y)))
	// cond: (shiftIsBounded(left) || shiftIsBounded(right)) && canRotate(config, 16)
	// result: (RotateLeft16 x y)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			left := v_0
			if left.Op != OpLsh16x8 {
				continue
			}
			y := left.Args[1]
			x := left.Args[0]
			right := v_1
			if right.Op != OpRsh16Ux8 {
				continue
			}
			_ = right.Args[1]
			if x != right.Args[0] {
				continue
			}
			right_1 := right.Args[1]
			if right_1.Op != OpSub8 {
				continue
			}
			_ = right_1.Args[1]
			right_1_0 := right_1.Args[0]
			if right_1_0.Op != OpConst8 || auxIntToInt8(right_1_0.AuxInt) != 16 || y != right_1.Args[1] || !((shiftIsBounded(left) || shiftIsBounded(right)) && canRotate(config, 16)) {
				continue
			}
			v.reset(OpRotateLeft16)
			v.AddArg2(x, y)
			return true
		}
		break
	}
	// match: (Xor16 right:(Rsh16Ux64 x y) left:(Lsh16x64 x z:(Sub64 (Const64 [16]) y)))
	// cond: (shiftIsBounded(left) || shiftIsBounded(right)) && canRotate(config, 16)
	// result: (RotateLeft16 x z)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			right := v_0
			if right.Op != OpRsh16Ux64 {
				continue
			}
			y := right.Args[1]
			x := right.Args[0]
			left := v_1
			if left.Op != OpLsh16x64 {
				continue
			}
			_ = left.Args[1]
			if x != left.Args[0] {
				continue
			}
			z := left.Args[1]
			if z.Op != OpSub64 {
				continue
			}
			_ = z.Args[1]
			z_0 := z.Args[0]
			if z_0.Op != OpConst64 || auxIntToInt64(z_0.AuxInt) != 16 || y != z.Args[1] || !((shiftIsBounded(left) || shiftIsBounded(right)) && canRotate(config, 16)) {
				continue
			}
			v.reset(OpRotateLeft16)
			v.AddArg2(x, z)
			return true
		}
		break
	}
	// match: (Xor16 right:(Rsh16Ux32 x y) left:(Lsh16x32 x z:(Sub32 (Const32 [16]) y)))
	// cond: (shiftIsBounded(left) || shiftIsBounded(right)) && canRotate(config, 16)
	// result: (RotateLeft16 x z)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			right := v_0
			if right.Op != OpRsh16Ux32 {
				continue
			}
			y := right.Args[1]
			x := right.Args[0]
			left := v_1
			if left.Op != OpLsh16x32 {
				continue
			}
			_ = left.Args[1]
			if x != left.Args[0] {
				continue
			}
			z := left.Args[1]
			if z.Op != OpSub32 {
				continue
			}
			_ = z.Args[1]
			z_0 := z.Args[0]
			if z_0.Op != OpConst32 || auxIntToInt32(z_0.AuxInt) != 16 || y != z.Args[1] || !((shiftIsBounded(left) || shiftIsBounded(right)) && canRotate(config, 16)) {
				continue
			}
			v.reset(OpRotateLeft16)
			v.AddArg2(x, z)
			return true
		}
		break
	}
	// match: (Xor16 right:(Rsh16Ux16 x y) left:(Lsh16x16 x z:(Sub16 (Const16 [16]) y)))
	// cond: (shiftIsBounded(left) || shiftIsBounded(right)) && canRotate(config, 16)
	// result: (RotateLeft16 x z)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			right := v_0
			if right.Op != OpRsh16Ux16 {
				continue
			}
			y := right.Args[1]
			x := right.Args[0]
			left := v_1
			if left.Op != OpLsh16x16 {
				continue
			}
			_ = left.Args[1]
			if x != left.Args[0] {
				continue
			}
			z := left.Args[1]
			if z.Op != OpSub16 {
				continue
			}
			_ = z.Args[1]
			z_0 := z.Args[0]
			if z_0.Op != OpConst16 || auxIntToInt16(z_0.AuxInt) != 16 || y != z.Args[1] || !((shiftIsBounded(left) || shiftIsBounded(right)) && canRotate(config, 16)) {
				continue
			}
			v.reset(OpRotateLeft16)
			v.AddArg2(x, z)
			return true
		}
		break
	}
	// match: (Xor16 right:(Rsh16Ux8 x y) left:(Lsh16x8 x z:(Sub8 (Const8 [16]) y)))
	// cond: (shiftIsBounded(left) || shiftIsBounded(right)) && canRotate(config, 16)
	// result: (RotateLeft16 x z)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			right := v_0
			if right.Op != OpRsh16Ux8 {
				continue
			}
			y := right.Args[1]
			x := right.Args[0]
			left := v_1
			if left.Op != OpLsh16x8 {
				continue
			}
			_ = left.Args[1]
			if x != left.Args[0] {
				continue
			}
			z := left.Args[1]
			if z.Op != OpSub8 {
				continue
			}
			_ = z.Args[1]
			z_0 := z.Args[0]
			if z_0.Op != OpConst8 || auxIntToInt8(z_0.AuxInt) != 16 || y != z.Args[1] || !((shiftIsBounded(left) || shiftIsBounded(right)) && canRotate(config, 16)) {
				continue
			}
			v.reset(OpRotateLeft16)
			v.AddArg2(x, z)
			return true
		}
		break
	}
	return false
}
func rewriteValuegeneric_OpXor32(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	config := b.Func.Config
	// match: (Xor32 (Const32 [c]) (Const32 [d]))
	// result: (Const32 [c^d])
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpConst32 {
				continue
			}
			c := auxIntToInt32(v_0.AuxInt)
			if v_1.Op != OpConst32 {
				continue
			}
			d := auxIntToInt32(v_1.AuxInt)
			v.reset(OpConst32)
			v.AuxInt = int32ToAuxInt(c ^ d)
			return true
		}
		break
	}
	// match: (Xor32 x x)
	// result: (Const32 [0])
	for {
		x := v_0
		if x != v_1 {
			break
		}
		v.reset(OpConst32)
		v.AuxInt = int32ToAuxInt(0)
		return true
	}
	// match: (Xor32 (Const32 [0]) x)
	// result: x
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpConst32 || auxIntToInt32(v_0.AuxInt) != 0 {
				continue
			}
			x := v_1
			v.copyOf(x)
			return true
		}
		break
	}
	// match: (Xor32 (Com32 x) x)
	// result: (Const32 [-1])
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpCom32 {
				continue
			}
			x := v_0.Args[0]
			if x != v_1 {
				continue
			}
			v.reset(OpConst32)
			v.AuxInt = int32ToAuxInt(-1)
			return true
		}
		break
	}
	// match: (Xor32 (Const32 [-1]) x)
	// result: (Com32 x)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpConst32 || auxIntToInt32(v_0.AuxInt) != -1 {
				continue
			}
			x := v_1
			v.reset(OpCom32)
			v.AddArg(x)
			return true
		}
		break
	}
	// match: (Xor32 x (Xor32 x y))
	// result: y
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			if v_1.Op != OpXor32 {
				continue
			}
			_ = v_1.Args[1]
			v_1_0 := v_1.Args[0]
			v_1_1 := v_1.Args[1]
			for _i1 := 0; _i1 <= 1; _i1, v_1_0, v_1_1 = _i1+1, v_1_1, v_1_0 {
				if x != v_1_0 {
					continue
				}
				y := v_1_1
				v.copyOf(y)
				return true
			}
		}
		break
	}
	// match: (Xor32 (Xor32 i:(Const32 <t>) z) x)
	// cond: (z.Op != OpConst32 && x.Op != OpConst32)
	// result: (Xor32 i (Xor32 <t> z x))
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpXor32 {
				continue
			}
			_ = v_0.Args[1]
			v_0_0 := v_0.Args[0]
			v_0_1 := v_0.Args[1]
			for _i1 := 0; _i1 <= 1; _i1, v_0_0, v_0_1 = _i1+1, v_0_1, v_0_0 {
				i := v_0_0
				if i.Op != OpConst32 {
					continue
				}
				t := i.Type
				z := v_0_1
				x := v_1
				if !(z.Op != OpConst32 && x.Op != OpConst32) {
					continue
				}
				v.reset(OpXor32)
				v0 := b.NewValue0(v.Pos, OpXor32, t)
				v0.AddArg2(z, x)
				v.AddArg2(i, v0)
				return true
			}
		}
		break
	}
	// match: (Xor32 (Const32 <t> [c]) (Xor32 (Const32 <t> [d]) x))
	// result: (Xor32 (Const32 <t> [c^d]) x)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpConst32 {
				continue
			}
			t := v_0.Type
			c := auxIntToInt32(v_0.AuxInt)
			if v_1.Op != OpXor32 {
				continue
			}
			_ = v_1.Args[1]
			v_1_0 := v_1.Args[0]
			v_1_1 := v_1.Args[1]
			for _i1 := 0; _i1 <= 1; _i1, v_1_0, v_1_1 = _i1+1, v_1_1, v_1_0 {
				if v_1_0.Op != OpConst32 || v_1_0.Type != t {
					continue
				}
				d := auxIntToInt32(v_1_0.AuxInt)
				x := v_1_1
				v.reset(OpXor32)
				v0 := b.NewValue0(v.Pos, OpConst32, t)
				v0.AuxInt = int32ToAuxInt(c ^ d)
				v.AddArg2(v0, x)
				return true
			}
		}
		break
	}
	// match: (Xor32 (Lsh32x64 x z:(Const64 <t> [c])) (Rsh32Ux64 x (Const64 [d])))
	// cond: c < 32 && d == 32-c && canRotate(config, 32)
	// result: (RotateLeft32 x z)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpLsh32x64 {
				continue
			}
			_ = v_0.Args[1]
			x := v_0.Args[0]
			z := v_0.Args[1]
			if z.Op != OpConst64 {
				continue
			}
			c := auxIntToInt64(z.AuxInt)
			if v_1.Op != OpRsh32Ux64 {
				continue
			}
			_ = v_1.Args[1]
			if x != v_1.Args[0] {
				continue
			}
			v_1_1 := v_1.Args[1]
			if v_1_1.Op != OpConst64 {
				continue
			}
			d := auxIntToInt64(v_1_1.AuxInt)
			if !(c < 32 && d == 32-c && canRotate(config, 32)) {
				continue
			}
			v.reset(OpRotateLeft32)
			v.AddArg2(x, z)
			return true
		}
		break
	}
	// match: (Xor32 left:(Lsh32x64 x y) right:(Rsh32Ux64 x (Sub64 (Const64 [32]) y)))
	// cond: (shiftIsBounded(left) || shiftIsBounded(right)) && canRotate(config, 32)
	// result: (RotateLeft32 x y)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			left := v_0
			if left.Op != OpLsh32x64 {
				continue
			}
			y := left.Args[1]
			x := left.Args[0]
			right := v_1
			if right.Op != OpRsh32Ux64 {
				continue
			}
			_ = right.Args[1]
			if x != right.Args[0] {
				continue
			}
			right_1 := right.Args[1]
			if right_1.Op != OpSub64 {
				continue
			}
			_ = right_1.Args[1]
			right_1_0 := right_1.Args[0]
			if right_1_0.Op != OpConst64 || auxIntToInt64(right_1_0.AuxInt) != 32 || y != right_1.Args[1] || !((shiftIsBounded(left) || shiftIsBounded(right)) && canRotate(config, 32)) {
				continue
			}
			v.reset(OpRotateLeft32)
			v.AddArg2(x, y)
			return true
		}
		break
	}
	// match: (Xor32 left:(Lsh32x32 x y) right:(Rsh32Ux32 x (Sub32 (Const32 [32]) y)))
	// cond: (shiftIsBounded(left) || shiftIsBounded(right)) && canRotate(config, 32)
	// result: (RotateLeft32 x y)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			left := v_0
			if left.Op != OpLsh32x32 {
				continue
			}
			y := left.Args[1]
			x := left.Args[0]
			right := v_1
			if right.Op != OpRsh32Ux32 {
				continue
			}
			_ = right.Args[1]
			if x != right.Args[0] {
				continue
			}
			right_1 := right.Args[1]
			if right_1.Op != OpSub32 {
				continue
			}
			_ = right_1.Args[1]
			right_1_0 := right_1.Args[0]
			if right_1_0.Op != OpConst32 || auxIntToInt32(right_1_0.AuxInt) != 32 || y != right_1.Args[1] || !((shiftIsBounded(left) || shiftIsBounded(right)) && canRotate(config, 32)) {
				continue
			}
			v.reset(OpRotateLeft32)
			v.AddArg2(x, y)
			return true
		}
		break
	}
	// match: (Xor32 left:(Lsh32x16 x y) right:(Rsh32Ux16 x (Sub16 (Const16 [32]) y)))
	// cond: (shiftIsBounded(left) || shiftIsBounded(right)) && canRotate(config, 32)
	// result: (RotateLeft32 x y)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			left := v_0
			if left.Op != OpLsh32x16 {
				continue
			}
			y := left.Args[1]
			x := left.Args[0]
			right := v_1
			if right.Op != OpRsh32Ux16 {
				continue
			}
			_ = right.Args[1]
			if x != right.Args[0] {
				continue
			}
			right_1 := right.Args[1]
			if right_1.Op != OpSub16 {
				continue
			}
			_ = right_1.Args[1]
			right_1_0 := right_1.Args[0]
			if right_1_0.Op != OpConst16 || auxIntToInt16(right_1_0.AuxInt) != 32 || y != right_1.Args[1] || !((shiftIsBounded(left) || shiftIsBounded(right)) && canRotate(config, 32)) {
				continue
			}
			v.reset(OpRotateLeft32)
			v.AddArg2(x, y)
			return true
		}
		break
	}
	// match: (Xor32 left:(Lsh32x8 x y) right:(Rsh32Ux8 x (Sub8 (Const8 [32]) y)))
	// cond: (shiftIsBounded(left) || shiftIsBounded(right)) && canRotate(config, 32)
	// result: (RotateLeft32 x y)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			left := v_0
			if left.Op != OpLsh32x8 {
				continue
			}
			y := left.Args[1]
			x := left.Args[0]
			right := v_1
			if right.Op != OpRsh32Ux8 {
				continue
			}
			_ = right.Args[1]
			if x != right.Args[0] {
				continue
			}
			right_1 := right.Args[1]
			if right_1.Op != OpSub8 {
				continue
			}
			_ = right_1.Args[1]
			right_1_0 := right_1.Args[0]
			if right_1_0.Op != OpConst8 || auxIntToInt8(right_1_0.AuxInt) != 32 || y != right_1.Args[1] || !((shiftIsBounded(left) || shiftIsBounded(right)) && canRotate(config, 32)) {
				continue
			}
			v.reset(OpRotateLeft32)
			v.AddArg2(x, y)
			return true
		}
		break
	}
	// match: (Xor32 right:(Rsh32Ux64 x y) left:(Lsh32x64 x z:(Sub64 (Const64 [32]) y)))
	// cond: (shiftIsBounded(left) || shiftIsBounded(right)) && canRotate(config, 32)
	// result: (RotateLeft32 x z)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			right := v_0
			if right.Op != OpRsh32Ux64 {
				continue
			}
			y := right.Args[1]
			x := right.Args[0]
			left := v_1
			if left.Op != OpLsh32x64 {
				continue
			}
			_ = left.Args[1]
			if x != left.Args[0] {
				continue
			}
			z := left.Args[1]
			if z.Op != OpSub64 {
				continue
			}
			_ = z.Args[1]
			z_0 := z.Args[0]
			if z_0.Op != OpConst64 || auxIntToInt64(z_0.AuxInt) != 32 || y != z.Args[1] || !((shiftIsBounded(left) || shiftIsBounded(right)) && canRotate(config, 32)) {
				continue
			}
			v.reset(OpRotateLeft32)
			v.AddArg2(x, z)
			return true
		}
		break
	}
	// match: (Xor32 right:(Rsh32Ux32 x y) left:(Lsh32x32 x z:(Sub32 (Const32 [32]) y)))
	// cond: (shiftIsBounded(left) || shiftIsBounded(right)) && canRotate(config, 32)
	// result: (RotateLeft32 x z)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			right := v_0
			if right.Op != OpRsh32Ux32 {
				continue
			}
			y := right.Args[1]
			x := right.Args[0]
			left := v_1
			if left.Op != OpLsh32x32 {
				continue
			}
			_ = left.Args[1]
			if x != left.Args[0] {
				continue
			}
			z := left.Args[1]
			if z.Op != OpSub32 {
				continue
			}
			_ = z.Args[1]
			z_0 := z.Args[0]
			if z_0.Op != OpConst32 || auxIntToInt32(z_0.AuxInt) != 32 || y != z.Args[1] || !((shiftIsBounded(left) || shiftIsBounded(right)) && canRotate(config, 32)) {
				continue
			}
			v.reset(OpRotateLeft32)
			v.AddArg2(x, z)
			return true
		}
		break
	}
	// match: (Xor32 right:(Rsh32Ux16 x y) left:(Lsh32x16 x z:(Sub16 (Const16 [32]) y)))
	// cond: (shiftIsBounded(left) || shiftIsBounded(right)) && canRotate(config, 32)
	// result: (RotateLeft32 x z)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			right := v_0
			if right.Op != OpRsh32Ux16 {
				continue
			}
			y := right.Args[1]
			x := right.Args[0]
			left := v_1
			if left.Op != OpLsh32x16 {
				continue
			}
			_ = left.Args[1]
			if x != left.Args[0] {
				continue
			}
			z := left.Args[1]
			if z.Op != OpSub16 {
				continue
			}
			_ = z.Args[1]
			z_0 := z.Args[0]
			if z_0.Op != OpConst16 || auxIntToInt16(z_0.AuxInt) != 32 || y != z.Args[1] || !((shiftIsBounded(left) || shiftIsBounded(right)) && canRotate(config, 32)) {
				continue
			}
			v.reset(OpRotateLeft32)
			v.AddArg2(x, z)
			return true
		}
		break
	}
	// match: (Xor32 right:(Rsh32Ux8 x y) left:(Lsh32x8 x z:(Sub8 (Const8 [32]) y)))
	// cond: (shiftIsBounded(left) || shiftIsBounded(right)) && canRotate(config, 32)
	// result: (RotateLeft32 x z)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			right := v_0
			if right.Op != OpRsh32Ux8 {
				continue
			}
			y := right.Args[1]
			x := right.Args[0]
			left := v_1
			if left.Op != OpLsh32x8 {
				continue
			}
			_ = left.Args[1]
			if x != left.Args[0] {
				continue
			}
			z := left.Args[1]
			if z.Op != OpSub8 {
				continue
			}
			_ = z.Args[1]
			z_0 := z.Args[0]
			if z_0.Op != OpConst8 || auxIntToInt8(z_0.AuxInt) != 32 || y != z.Args[1] || !((shiftIsBounded(left) || shiftIsBounded(right)) && canRotate(config, 32)) {
				continue
			}
			v.reset(OpRotateLeft32)
			v.AddArg2(x, z)
			return true
		}
		break
	}
	return false
}
func rewriteValuegeneric_OpXor64(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	config := b.Func.Config
	// match: (Xor64 (Const64 [c]) (Const64 [d]))
	// result: (Const64 [c^d])
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpConst64 {
				continue
			}
			c := auxIntToInt64(v_0.AuxInt)
			if v_1.Op != OpConst64 {
				continue
			}
			d := auxIntToInt64(v_1.AuxInt)
			v.reset(OpConst64)
			v.AuxInt = int64ToAuxInt(c ^ d)
			return true
		}
		break
	}
	// match: (Xor64 x x)
	// result: (Const64 [0])
	for {
		x := v_0
		if x != v_1 {
			break
		}
		v.reset(OpConst64)
		v.AuxInt = int64ToAuxInt(0)
		return true
	}
	// match: (Xor64 (Const64 [0]) x)
	// result: x
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpConst64 || auxIntToInt64(v_0.AuxInt) != 0 {
				continue
			}
			x := v_1
			v.copyOf(x)
			return true
		}
		break
	}
	// match: (Xor64 (Com64 x) x)
	// result: (Const64 [-1])
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpCom64 {
				continue
			}
			x := v_0.Args[0]
			if x != v_1 {
				continue
			}
			v.reset(OpConst64)
			v.AuxInt = int64ToAuxInt(-1)
			return true
		}
		break
	}
	// match: (Xor64 (Const64 [-1]) x)
	// result: (Com64 x)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpConst64 || auxIntToInt64(v_0.AuxInt) != -1 {
				continue
			}
			x := v_1
			v.reset(OpCom64)
			v.AddArg(x)
			return true
		}
		break
	}
	// match: (Xor64 x (Xor64 x y))
	// result: y
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			if v_1.Op != OpXor64 {
				continue
			}
			_ = v_1.Args[1]
			v_1_0 := v_1.Args[0]
			v_1_1 := v_1.Args[1]
			for _i1 := 0; _i1 <= 1; _i1, v_1_0, v_1_1 = _i1+1, v_1_1, v_1_0 {
				if x != v_1_0 {
					continue
				}
				y := v_1_1
				v.copyOf(y)
				return true
			}
		}
		break
	}
	// match: (Xor64 (Xor64 i:(Const64 <t>) z) x)
	// cond: (z.Op != OpConst64 && x.Op != OpConst64)
	// result: (Xor64 i (Xor64 <t> z x))
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpXor64 {
				continue
			}
			_ = v_0.Args[1]
			v_0_0 := v_0.Args[0]
			v_0_1 := v_0.Args[1]
			for _i1 := 0; _i1 <= 1; _i1, v_0_0, v_0_1 = _i1+1, v_0_1, v_0_0 {
				i := v_0_0
				if i.Op != OpConst64 {
					continue
				}
				t := i.Type
				z := v_0_1
				x := v_1
				if !(z.Op != OpConst64 && x.Op != OpConst64) {
					continue
				}
				v.reset(OpXor64)
				v0 := b.NewValue0(v.Pos, OpXor64, t)
				v0.AddArg2(z, x)
				v.AddArg2(i, v0)
				return true
			}
		}
		break
	}
	// match: (Xor64 (Const64 <t> [c]) (Xor64 (Const64 <t> [d]) x))
	// result: (Xor64 (Const64 <t> [c^d]) x)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpConst64 {
				continue
			}
			t := v_0.Type
			c := auxIntToInt64(v_0.AuxInt)
			if v_1.Op != OpXor64 {
				continue
			}
			_ = v_1.Args[1]
			v_1_0 := v_1.Args[0]
			v_1_1 := v_1.Args[1]
			for _i1 := 0; _i1 <= 1; _i1, v_1_0, v_1_1 = _i1+1, v_1_1, v_1_0 {
				if v_1_0.Op != OpConst64 || v_1_0.Type != t {
					continue
				}
				d := auxIntToInt64(v_1_0.AuxInt)
				x := v_1_1
				v.reset(OpXor64)
				v0 := b.NewValue0(v.Pos, OpConst64, t)
				v0.AuxInt = int64ToAuxInt(c ^ d)
				v.AddArg2(v0, x)
				return true
			}
		}
		break
	}
	// match: (Xor64 (Lsh64x64 x z:(Const64 <t> [c])) (Rsh64Ux64 x (Const64 [d])))
	// cond: c < 64 && d == 64-c && canRotate(config, 64)
	// result: (RotateLeft64 x z)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpLsh64x64 {
				continue
			}
			_ = v_0.Args[1]
			x := v_0.Args[0]
			z := v_0.Args[1]
			if z.Op != OpConst64 {
				continue
			}
			c := auxIntToInt64(z.AuxInt)
			if v_1.Op != OpRsh64Ux64 {
				continue
			}
			_ = v_1.Args[1]
			if x != v_1.Args[0] {
				continue
			}
			v_1_1 := v_1.Args[1]
			if v_1_1.Op != OpConst64 {
				continue
			}
			d := auxIntToInt64(v_1_1.AuxInt)
			if !(c < 64 && d == 64-c && canRotate(config, 64)) {
				continue
			}
			v.reset(OpRotateLeft64)
			v.AddArg2(x, z)
			return true
		}
		break
	}
	// match: (Xor64 left:(Lsh64x64 x y) right:(Rsh64Ux64 x (Sub64 (Const64 [64]) y)))
	// cond: (shiftIsBounded(left) || shiftIsBounded(right)) && canRotate(config, 64)
	// result: (RotateLeft64 x y)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			left := v_0
			if left.Op != OpLsh64x64 {
				continue
			}
			y := left.Args[1]
			x := left.Args[0]
			right := v_1
			if right.Op != OpRsh64Ux64 {
				continue
			}
			_ = right.Args[1]
			if x != right.Args[0] {
				continue
			}
			right_1 := right.Args[1]
			if right_1.Op != OpSub64 {
				continue
			}
			_ = right_1.Args[1]
			right_1_0 := right_1.Args[0]
			if right_1_0.Op != OpConst64 || auxIntToInt64(right_1_0.AuxInt) != 64 || y != right_1.Args[1] || !((shiftIsBounded(left) || shiftIsBounded(right)) && canRotate(config, 64)) {
				continue
			}
			v.reset(OpRotateLeft64)
			v.AddArg2(x, y)
			return true
		}
		break
	}
	// match: (Xor64 left:(Lsh64x32 x y) right:(Rsh64Ux32 x (Sub32 (Const32 [64]) y)))
	// cond: (shiftIsBounded(left) || shiftIsBounded(right)) && canRotate(config, 64)
	// result: (RotateLeft64 x y)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			left := v_0
			if left.Op != OpLsh64x32 {
				continue
			}
			y := left.Args[1]
			x := left.Args[0]
			right := v_1
			if right.Op != OpRsh64Ux32 {
				continue
			}
			_ = right.Args[1]
			if x != right.Args[0] {
				continue
			}
			right_1 := right.Args[1]
			if right_1.Op != OpSub32 {
				continue
			}
			_ = right_1.Args[1]
			right_1_0 := right_1.Args[0]
			if right_1_0.Op != OpConst32 || auxIntToInt32(right_1_0.AuxInt) != 64 || y != right_1.Args[1] || !((shiftIsBounded(left) || shiftIsBounded(right)) && canRotate(config, 64)) {
				continue
			}
			v.reset(OpRotateLeft64)
			v.AddArg2(x, y)
			return true
		}
		break
	}
	// match: (Xor64 left:(Lsh64x16 x y) right:(Rsh64Ux16 x (Sub16 (Const16 [64]) y)))
	// cond: (shiftIsBounded(left) || shiftIsBounded(right)) && canRotate(config, 64)
	// result: (RotateLeft64 x y)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			left := v_0
			if left.Op != OpLsh64x16 {
				continue
			}
			y := left.Args[1]
			x := left.Args[0]
			right := v_1
			if right.Op != OpRsh64Ux16 {
				continue
			}
			_ = right.Args[1]
			if x != right.Args[0] {
				continue
			}
			right_1 := right.Args[1]
			if right_1.Op != OpSub16 {
				continue
			}
			_ = right_1.Args[1]
			right_1_0 := right_1.Args[0]
			if right_1_0.Op != OpConst16 || auxIntToInt16(right_1_0.AuxInt) != 64 || y != right_1.Args[1] || !((shiftIsBounded(left) || shiftIsBounded(right)) && canRotate(config, 64)) {
				continue
			}
			v.reset(OpRotateLeft64)
			v.AddArg2(x, y)
			return true
		}
		break
	}
	// match: (Xor64 left:(Lsh64x8 x y) right:(Rsh64Ux8 x (Sub8 (Const8 [64]) y)))
	// cond: (shiftIsBounded(left) || shiftIsBounded(right)) && canRotate(config, 64)
	// result: (RotateLeft64 x y)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			left := v_0
			if left.Op != OpLsh64x8 {
				continue
			}
			y := left.Args[1]
			x := left.Args[0]
			right := v_1
			if right.Op != OpRsh64Ux8 {
				continue
			}
			_ = right.Args[1]
			if x != right.Args[0] {
				continue
			}
			right_1 := right.Args[1]
			if right_1.Op != OpSub8 {
				continue
			}
			_ = right_1.Args[1]
			right_1_0 := right_1.Args[0]
			if right_1_0.Op != OpConst8 || auxIntToInt8(right_1_0.AuxInt) != 64 || y != right_1.Args[1] || !((shiftIsBounded(left) || shiftIsBounded(right)) && canRotate(config, 64)) {
				continue
			}
			v.reset(OpRotateLeft64)
			v.AddArg2(x, y)
			return true
		}
		break
	}
	// match: (Xor64 right:(Rsh64Ux64 x y) left:(Lsh64x64 x z:(Sub64 (Const64 [64]) y)))
	// cond: (shiftIsBounded(left) || shiftIsBounded(right)) && canRotate(config, 64)
	// result: (RotateLeft64 x z)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			right := v_0
			if right.Op != OpRsh64Ux64 {
				continue
			}
			y := right.Args[1]
			x := right.Args[0]
			left := v_1
			if left.Op != OpLsh64x64 {
				continue
			}
			_ = left.Args[1]
			if x != left.Args[0] {
				continue
			}
			z := left.Args[1]
			if z.Op != OpSub64 {
				continue
			}
			_ = z.Args[1]
			z_0 := z.Args[0]
			if z_0.Op != OpConst64 || auxIntToInt64(z_0.AuxInt) != 64 || y != z.Args[1] || !((shiftIsBounded(left) || shiftIsBounded(right)) && canRotate(config, 64)) {
				continue
			}
			v.reset(OpRotateLeft64)
			v.AddArg2(x, z)
			return true
		}
		break
	}
	// match: (Xor64 right:(Rsh64Ux32 x y) left:(Lsh64x32 x z:(Sub32 (Const32 [64]) y)))
	// cond: (shiftIsBounded(left) || shiftIsBounded(right)) && canRotate(config, 64)
	// result: (RotateLeft64 x z)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			right := v_0
			if right.Op != OpRsh64Ux32 {
				continue
			}
			y := right.Args[1]
			x := right.Args[0]
			left := v_1
			if left.Op != OpLsh64x32 {
				continue
			}
			_ = left.Args[1]
			if x != left.Args[0] {
				continue
			}
			z := left.Args[1]
			if z.Op != OpSub32 {
				continue
			}
			_ = z.Args[1]
			z_0 := z.Args[0]
			if z_0.Op != OpConst32 || auxIntToInt32(z_0.AuxInt) != 64 || y != z.Args[1] || !((shiftIsBounded(left) || shiftIsBounded(right)) && canRotate(config, 64)) {
				continue
			}
			v.reset(OpRotateLeft64)
			v.AddArg2(x, z)
			return true
		}
		break
	}
	// match: (Xor64 right:(Rsh64Ux16 x y) left:(Lsh64x16 x z:(Sub16 (Const16 [64]) y)))
	// cond: (shiftIsBounded(left) || shiftIsBounded(right)) && canRotate(config, 64)
	// result: (RotateLeft64 x z)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			right := v_0
			if right.Op != OpRsh64Ux16 {
				continue
			}
			y := right.Args[1]
			x := right.Args[0]
			left := v_1
			if left.Op != OpLsh64x16 {
				continue
			}
			_ = left.Args[1]
			if x != left.Args[0] {
				continue
			}
			z := left.Args[1]
			if z.Op != OpSub16 {
				continue
			}
			_ = z.Args[1]
			z_0 := z.Args[0]
			if z_0.Op != OpConst16 || auxIntToInt16(z_0.AuxInt) != 64 || y != z.Args[1] || !((shiftIsBounded(left) || shiftIsBounded(right)) && canRotate(config, 64)) {
				continue
			}
			v.reset(OpRotateLeft64)
			v.AddArg2(x, z)
			return true
		}
		break
	}
	// match: (Xor64 right:(Rsh64Ux8 x y) left:(Lsh64x8 x z:(Sub8 (Const8 [64]) y)))
	// cond: (shiftIsBounded(left) || shiftIsBounded(right)) && canRotate(config, 64)
	// result: (RotateLeft64 x z)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			right := v_0
			if right.Op != OpRsh64Ux8 {
				continue
			}
			y := right.Args[1]
			x := right.Args[0]
			left := v_1
			if left.Op != OpLsh64x8 {
				continue
			}
			_ = left.Args[1]
			if x != left.Args[0] {
				continue
			}
			z := left.Args[1]
			if z.Op != OpSub8 {
				continue
			}
			_ = z.Args[1]
			z_0 := z.Args[0]
			if z_0.Op != OpConst8 || auxIntToInt8(z_0.AuxInt) != 64 || y != z.Args[1] || !((shiftIsBounded(left) || shiftIsBounded(right)) && canRotate(config, 64)) {
				continue
			}
			v.reset(OpRotateLeft64)
			v.AddArg2(x, z)
			return true
		}
		break
	}
	return false
}
func rewriteValuegeneric_OpXor8(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	config := b.Func.Config
	// match: (Xor8 (Const8 [c]) (Const8 [d]))
	// result: (Const8 [c^d])
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpConst8 {
				continue
			}
			c := auxIntToInt8(v_0.AuxInt)
			if v_1.Op != OpConst8 {
				continue
			}
			d := auxIntToInt8(v_1.AuxInt)
			v.reset(OpConst8)
			v.AuxInt = int8ToAuxInt(c ^ d)
			return true
		}
		break
	}
	// match: (Xor8 x x)
	// result: (Const8 [0])
	for {
		x := v_0
		if x != v_1 {
			break
		}
		v.reset(OpConst8)
		v.AuxInt = int8ToAuxInt(0)
		return true
	}
	// match: (Xor8 (Const8 [0]) x)
	// result: x
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpConst8 || auxIntToInt8(v_0.AuxInt) != 0 {
				continue
			}
			x := v_1
			v.copyOf(x)
			return true
		}
		break
	}
	// match: (Xor8 (Com8 x) x)
	// result: (Const8 [-1])
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpCom8 {
				continue
			}
			x := v_0.Args[0]
			if x != v_1 {
				continue
			}
			v.reset(OpConst8)
			v.AuxInt = int8ToAuxInt(-1)
			return true
		}
		break
	}
	// match: (Xor8 (Const8 [-1]) x)
	// result: (Com8 x)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpConst8 || auxIntToInt8(v_0.AuxInt) != -1 {
				continue
			}
			x := v_1
			v.reset(OpCom8)
			v.AddArg(x)
			return true
		}
		break
	}
	// match: (Xor8 x (Xor8 x y))
	// result: y
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			if v_1.Op != OpXor8 {
				continue
			}
			_ = v_1.Args[1]
			v_1_0 := v_1.Args[0]
			v_1_1 := v_1.Args[1]
			for _i1 := 0; _i1 <= 1; _i1, v_1_0, v_1_1 = _i1+1, v_1_1, v_1_0 {
				if x != v_1_0 {
					continue
				}
				y := v_1_1
				v.copyOf(y)
				return true
			}
		}
		break
	}
	// match: (Xor8 (Xor8 i:(Const8 <t>) z) x)
	// cond: (z.Op != OpConst8 && x.Op != OpConst8)
	// result: (Xor8 i (Xor8 <t> z x))
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpXor8 {
				continue
			}
			_ = v_0.Args[1]
			v_0_0 := v_0.Args[0]
			v_0_1 := v_0.Args[1]
			for _i1 := 0; _i1 <= 1; _i1, v_0_0, v_0_1 = _i1+1, v_0_1, v_0_0 {
				i := v_0_0
				if i.Op != OpConst8 {
					continue
				}
				t := i.Type
				z := v_0_1
				x := v_1
				if !(z.Op != OpConst8 && x.Op != OpConst8) {
					continue
				}
				v.reset(OpXor8)
				v0 := b.NewValue0(v.Pos, OpXor8, t)
				v0.AddArg2(z, x)
				v.AddArg2(i, v0)
				return true
			}
		}
		break
	}
	// match: (Xor8 (Const8 <t> [c]) (Xor8 (Const8 <t> [d]) x))
	// result: (Xor8 (Const8 <t> [c^d]) x)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpConst8 {
				continue
			}
			t := v_0.Type
			c := auxIntToInt8(v_0.AuxInt)
			if v_1.Op != OpXor8 {
				continue
			}
			_ = v_1.Args[1]
			v_1_0 := v_1.Args[0]
			v_1_1 := v_1.Args[1]
			for _i1 := 0; _i1 <= 1; _i1, v_1_0, v_1_1 = _i1+1, v_1_1, v_1_0 {
				if v_1_0.Op != OpConst8 || v_1_0.Type != t {
					continue
				}
				d := auxIntToInt8(v_1_0.AuxInt)
				x := v_1_1
				v.reset(OpXor8)
				v0 := b.NewValue0(v.Pos, OpConst8, t)
				v0.AuxInt = int8ToAuxInt(c ^ d)
				v.AddArg2(v0, x)
				return true
			}
		}
		break
	}
	// match: (Xor8 (Lsh8x64 x z:(Const64 <t> [c])) (Rsh8Ux64 x (Const64 [d])))
	// cond: c < 8 && d == 8-c && canRotate(config, 8)
	// result: (RotateLeft8 x z)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpLsh8x64 {
				continue
			}
			_ = v_0.Args[1]
			x := v_0.Args[0]
			z := v_0.Args[1]
			if z.Op != OpConst64 {
				continue
			}
			c := auxIntToInt64(z.AuxInt)
			if v_1.Op != OpRsh8Ux64 {
				continue
			}
			_ = v_1.Args[1]
			if x != v_1.Args[0] {
				continue
			}
			v_1_1 := v_1.Args[1]
			if v_1_1.Op != OpConst64 {
				continue
			}
			d := auxIntToInt64(v_1_1.AuxInt)
			if !(c < 8 && d == 8-c && canRotate(config, 8)) {
				continue
			}
			v.reset(OpRotateLeft8)
			v.AddArg2(x, z)
			return true
		}
		break
	}
	// match: (Xor8 left:(Lsh8x64 x y) right:(Rsh8Ux64 x (Sub64 (Const64 [8]) y)))
	// cond: (shiftIsBounded(left) || shiftIsBounded(right)) && canRotate(config, 8)
	// result: (RotateLeft8 x y)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			left := v_0
			if left.Op != OpLsh8x64 {
				continue
			}
			y := left.Args[1]
			x := left.Args[0]
			right := v_1
			if right.Op != OpRsh8Ux64 {
				continue
			}
			_ = right.Args[1]
			if x != right.Args[0] {
				continue
			}
			right_1 := right.Args[1]
			if right_1.Op != OpSub64 {
				continue
			}
			_ = right_1.Args[1]
			right_1_0 := right_1.Args[0]
			if right_1_0.Op != OpConst64 || auxIntToInt64(right_1_0.AuxInt) != 8 || y != right_1.Args[1] || !((shiftIsBounded(left) || shiftIsBounded(right)) && canRotate(config, 8)) {
				continue
			}
			v.reset(OpRotateLeft8)
			v.AddArg2(x, y)
			return true
		}
		break
	}
	// match: (Xor8 left:(Lsh8x32 x y) right:(Rsh8Ux32 x (Sub32 (Const32 [8]) y)))
	// cond: (shiftIsBounded(left) || shiftIsBounded(right)) && canRotate(config, 8)
	// result: (RotateLeft8 x y)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			left := v_0
			if left.Op != OpLsh8x32 {
				continue
			}
			y := left.Args[1]
			x := left.Args[0]
			right := v_1
			if right.Op != OpRsh8Ux32 {
				continue
			}
			_ = right.Args[1]
			if x != right.Args[0] {
				continue
			}
			right_1 := right.Args[1]
			if right_1.Op != OpSub32 {
				continue
			}
			_ = right_1.Args[1]
			right_1_0 := right_1.Args[0]
			if right_1_0.Op != OpConst32 || auxIntToInt32(right_1_0.AuxInt) != 8 || y != right_1.Args[1] || !((shiftIsBounded(left) || shiftIsBounded(right)) && canRotate(config, 8)) {
				continue
			}
			v.reset(OpRotateLeft8)
			v.AddArg2(x, y)
			return true
		}
		break
	}
	// match: (Xor8 left:(Lsh8x16 x y) right:(Rsh8Ux16 x (Sub16 (Const16 [8]) y)))
	// cond: (shiftIsBounded(left) || shiftIsBounded(right)) && canRotate(config, 8)
	// result: (RotateLeft8 x y)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			left := v_0
			if left.Op != OpLsh8x16 {
				continue
			}
			y := left.Args[1]
			x := left.Args[0]
			right := v_1
			if right.Op != OpRsh8Ux16 {
				continue
			}
			_ = right.Args[1]
			if x != right.Args[0] {
				continue
			}
			right_1 := right.Args[1]
			if right_1.Op != OpSub16 {
				continue
			}
			_ = right_1.Args[1]
			right_1_0 := right_1.Args[0]
			if right_1_0.Op != OpConst16 || auxIntToInt16(right_1_0.AuxInt) != 8 || y != right_1.Args[1] || !((shiftIsBounded(left) || shiftIsBounded(right)) && canRotate(config, 8)) {
				continue
			}
			v.reset(OpRotateLeft8)
			v.AddArg2(x, y)
			return true
		}
		break
	}
	// match: (Xor8 left:(Lsh8x8 x y) right:(Rsh8Ux8 x (Sub8 (Const8 [8]) y)))
	// cond: (shiftIsBounded(left) || shiftIsBounded(right)) && canRotate(config, 8)
	// result: (RotateLeft8 x y)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			left := v_0
			if left.Op != OpLsh8x8 {
				continue
			}
			y := left.Args[1]
			x := left.Args[0]
			right := v_1
			if right.Op != OpRsh8Ux8 {
				continue
			}
			_ = right.Args[1]
			if x != right.Args[0] {
				continue
			}
			right_1 := right.Args[1]
			if right_1.Op != OpSub8 {
				continue
			}
			_ = right_1.Args[1]
			right_1_0 := right_1.Args[0]
			if right_1_0.Op != OpConst8 || auxIntToInt8(right_1_0.AuxInt) != 8 || y != right_1.Args[1] || !((shiftIsBounded(left) || shiftIsBounded(right)) && canRotate(config, 8)) {
				continue
			}
			v.reset(OpRotateLeft8)
			v.AddArg2(x, y)
			return true
		}
		break
	}
	// match: (Xor8 right:(Rsh8Ux64 x y) left:(Lsh8x64 x z:(Sub64 (Const64 [8]) y)))
	// cond: (shiftIsBounded(left) || shiftIsBounded(right)) && canRotate(config, 8)
	// result: (RotateLeft8 x z)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			right := v_0
			if right.Op != OpRsh8Ux64 {
				continue
			}
			y := right.Args[1]
			x := right.Args[0]
			left := v_1
			if left.Op != OpLsh8x64 {
				continue
			}
			_ = left.Args[1]
			if x != left.Args[0] {
				continue
			}
			z := left.Args[1]
			if z.Op != OpSub64 {
				continue
			}
			_ = z.Args[1]
			z_0 := z.Args[0]
			if z_0.Op != OpConst64 || auxIntToInt64(z_0.AuxInt) != 8 || y != z.Args[1] || !((shiftIsBounded(left) || shiftIsBounded(right)) && canRotate(config, 8)) {
				continue
			}
			v.reset(OpRotateLeft8)
			v.AddArg2(x, z)
			return true
		}
		break
	}
	// match: (Xor8 right:(Rsh8Ux32 x y) left:(Lsh8x32 x z:(Sub32 (Const32 [8]) y)))
	// cond: (shiftIsBounded(left) || shiftIsBounded(right)) && canRotate(config, 8)
	// result: (RotateLeft8 x z)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			right := v_0
			if right.Op != OpRsh8Ux32 {
				continue
			}
			y := right.Args[1]
			x := right.Args[0]
			left := v_1
			if left.Op != OpLsh8x32 {
				continue
			}
			_ = left.Args[1]
			if x != left.Args[0] {
				continue
			}
			z := left.Args[1]
			if z.Op != OpSub32 {
				continue
			}
			_ = z.Args[1]
			z_0 := z.Args[0]
			if z_0.Op != OpConst32 || auxIntToInt32(z_0.AuxInt) != 8 || y != z.Args[1] || !((shiftIsBounded(left) || shiftIsBounded(right)) && canRotate(config, 8)) {
				continue
			}
			v.reset(OpRotateLeft8)
			v.AddArg2(x, z)
			return true
		}
		break
	}
	// match: (Xor8 right:(Rsh8Ux16 x y) left:(Lsh8x16 x z:(Sub16 (Const16 [8]) y)))
	// cond: (shiftIsBounded(left) || shiftIsBounded(right)) && canRotate(config, 8)
	// result: (RotateLeft8 x z)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			right := v_0
			if right.Op != OpRsh8Ux16 {
				continue
			}
			y := right.Args[1]
			x := right.Args[0]
			left := v_1
			if left.Op != OpLsh8x16 {
				continue
			}
			_ = left.Args[1]
			if x != left.Args[0] {
				continue
			}
			z := left.Args[1]
			if z.Op != OpSub16 {
				continue
			}
			_ = z.Args[1]
			z_0 := z.Args[0]
			if z_0.Op != OpConst16 || auxIntToInt16(z_0.AuxInt) != 8 || y != z.Args[1] || !((shiftIsBounded(left) || shiftIsBounded(right)) && canRotate(config, 8)) {
				continue
			}
			v.reset(OpRotateLeft8)
			v.AddArg2(x, z)
			return true
		}
		break
	}
	// match: (Xor8 right:(Rsh8Ux8 x y) left:(Lsh8x8 x z:(Sub8 (Const8 [8]) y)))
	// cond: (shiftIsBounded(left) || shiftIsBounded(right)) && canRotate(config, 8)
	// result: (RotateLeft8 x z)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			right := v_0
			if right.Op != OpRsh8Ux8 {
				continue
			}
			y := right.Args[1]
			x := right.Args[0]
			left := v_1
			if left.Op != OpLsh8x8 {
				continue
			}
			_ = left.Args[1]
			if x != left.Args[0] {
				continue
			}
			z := left.Args[1]
			if z.Op != OpSub8 {
				continue
			}
			_ = z.Args[1]
			z_0 := z.Args[0]
			if z_0.Op != OpConst8 || auxIntToInt8(z_0.AuxInt) != 8 || y != z.Args[1] || !((shiftIsBounded(left) || shiftIsBounded(right)) && canRotate(config, 8)) {
				continue
			}
			v.reset(OpRotateLeft8)
			v.AddArg2(x, z)
			return true
		}
		break
	}
	return false
}
func rewriteValuegeneric_OpZero(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Zero (SelectN [0] call:(StaticLECall _ _)) mem:(SelectN [1] call))
	// cond: isSameCall(call.Aux, "runtime.newobject")
	// result: mem
	for {
		if v_0.Op != OpSelectN || auxIntToInt64(v_0.AuxInt) != 0 {
			break
		}
		call := v_0.Args[0]
		if call.Op != OpStaticLECall || len(call.Args) != 2 {
			break
		}
		mem := v_1
		if mem.Op != OpSelectN || auxIntToInt64(mem.AuxInt) != 1 || call != mem.Args[0] || !(isSameCall(call.Aux, "runtime.newobject")) {
			break
		}
		v.copyOf(mem)
		return true
	}
	// match: (Zero {t1} [n] p1 store:(Store {t2} (OffPtr [o2] p2) _ mem))
	// cond: isSamePtr(p1, p2) && store.Uses == 1 && n >= o2 + t2.Size() && clobber(store)
	// result: (Zero {t1} [n] p1 mem)
	for {
		n := auxIntToInt64(v.AuxInt)
		t1 := auxToType(v.Aux)
		p1 := v_0
		store := v_1
		if store.Op != OpStore {
			break
		}
		t2 := auxToType(store.Aux)
		mem := store.Args[2]
		store_0 := store.Args[0]
		if store_0.Op != OpOffPtr {
			break
		}
		o2 := auxIntToInt64(store_0.AuxInt)
		p2 := store_0.Args[0]
		if !(isSamePtr(p1, p2) && store.Uses == 1 && n >= o2+t2.Size() && clobber(store)) {
			break
		}
		v.reset(OpZero)
		v.AuxInt = int64ToAuxInt(n)
		v.Aux = typeToAux(t1)
		v.AddArg2(p1, mem)
		return true
	}
	// match: (Zero {t} [n] dst1 move:(Move {t} [n] dst2 _ mem))
	// cond: move.Uses == 1 && isSamePtr(dst1, dst2) && clobber(move)
	// result: (Zero {t} [n] dst1 mem)
	for {
		n := auxIntToInt64(v.AuxInt)
		t := auxToType(v.Aux)
		dst1 := v_0
		move := v_1
		if move.Op != OpMove || auxIntToInt64(move.AuxInt) != n || auxToType(move.Aux) != t {
			break
		}
		mem := move.Args[2]
		dst2 := move.Args[0]
		if !(move.Uses == 1 && isSamePtr(dst1, dst2) && clobber(move)) {
			break
		}
		v.reset(OpZero)
		v.AuxInt = int64ToAuxInt(n)
		v.Aux = typeToAux(t)
		v.AddArg2(dst1, mem)
		return true
	}
	// match: (Zero {t} [n] dst1 vardef:(VarDef {x} move:(Move {t} [n] dst2 _ mem)))
	// cond: move.Uses == 1 && vardef.Uses == 1 && isSamePtr(dst1, dst2) && clobber(move, vardef)
	// result: (Zero {t} [n] dst1 (VarDef {x} mem))
	for {
		n := auxIntToInt64(v.AuxInt)
		t := auxToType(v.Aux)
		dst1 := v_0
		vardef := v_1
		if vardef.Op != OpVarDef {
			break
		}
		x := auxToSym(vardef.Aux)
		move := vardef.Args[0]
		if move.Op != OpMove || auxIntToInt64(move.AuxInt) != n || auxToType(move.Aux) != t {
			break
		}
		mem := move.Args[2]
		dst2 := move.Args[0]
		if !(move.Uses == 1 && vardef.Uses == 1 && isSamePtr(dst1, dst2) && clobber(move, vardef)) {
			break
		}
		v.reset(OpZero)
		v.AuxInt = int64ToAuxInt(n)
		v.Aux = typeToAux(t)
		v0 := b.NewValue0(v.Pos, OpVarDef, types.TypeMem)
		v0.Aux = symToAux(x)
		v0.AddArg(mem)
		v.AddArg2(dst1, v0)
		return true
	}
	// match: (Zero {t} [s] dst1 zero:(Zero {t} [s] dst2 _))
	// cond: isSamePtr(dst1, dst2)
	// result: zero
	for {
		s := auxIntToInt64(v.AuxInt)
		t := auxToType(v.Aux)
		dst1 := v_0
		zero := v_1
		if zero.Op != OpZero || auxIntToInt64(zero.AuxInt) != s || auxToType(zero.Aux) != t {
			break
		}
		dst2 := zero.Args[0]
		if !(isSamePtr(dst1, dst2)) {
			break
		}
		v.copyOf(zero)
		return true
	}
	// match: (Zero {t} [s] dst1 vardef:(VarDef (Zero {t} [s] dst2 _)))
	// cond: isSamePtr(dst1, dst2)
	// result: vardef
	for {
		s := auxIntToInt64(v.AuxInt)
		t := auxToType(v.Aux)
		dst1 := v_0
		vardef := v_1
		if vardef.Op != OpVarDef {
			break
		}
		vardef_0 := vardef.Args[0]
		if vardef_0.Op != OpZero || auxIntToInt64(vardef_0.AuxInt) != s || auxToType(vardef_0.Aux) != t {
			break
		}
		dst2 := vardef_0.Args[0]
		if !(isSamePtr(dst1, dst2)) {
			break
		}
		v.copyOf(vardef)
		return true
	}
	return false
}
func rewriteValuegeneric_OpZeroExt16to32(v *Value) bool {
	v_0 := v.Args[0]
	// match: (ZeroExt16to32 (Const16 [c]))
	// result: (Const32 [int32(uint16(c))])
	for {
		if v_0.Op != OpConst16 {
			break
		}
		c := auxIntToInt16(v_0.AuxInt)
		v.reset(OpConst32)
		v.AuxInt = int32ToAuxInt(int32(uint16(c)))
		return true
	}
	// match: (ZeroExt16to32 (Trunc32to16 x:(Rsh32Ux64 _ (Const64 [s]))))
	// cond: s >= 16
	// result: x
	for {
		if v_0.Op != OpTrunc32to16 {
			break
		}
		x := v_0.Args[0]
		if x.Op != OpRsh32Ux64 {
			break
		}
		_ = x.Args[1]
		x_1 := x.Args[1]
		if x_1.Op != OpConst64 {
			break
		}
		s := auxIntToInt64(x_1.AuxInt)
		if !(s >= 16) {
			break
		}
		v.copyOf(x)
		return true
	}
	return false
}
func rewriteValuegeneric_OpZeroExt16to64(v *Value) bool {
	v_0 := v.Args[0]
	// match: (ZeroExt16to64 (Const16 [c]))
	// result: (Const64 [int64(uint16(c))])
	for {
		if v_0.Op != OpConst16 {
			break
		}
		c := auxIntToInt16(v_0.AuxInt)
		v.reset(OpConst64)
		v.AuxInt = int64ToAuxInt(int64(uint16(c)))
		return true
	}
	// match: (ZeroExt16to64 (Trunc64to16 x:(Rsh64Ux64 _ (Const64 [s]))))
	// cond: s >= 48
	// result: x
	for {
		if v_0.Op != OpTrunc64to16 {
			break
		}
		x := v_0.Args[0]
		if x.Op != OpRsh64Ux64 {
			break
		}
		_ = x.Args[1]
		x_1 := x.Args[1]
		if x_1.Op != OpConst64 {
			break
		}
		s := auxIntToInt64(x_1.AuxInt)
		if !(s >= 48) {
			break
		}
		v.copyOf(x)
		return true
	}
	return false
}
func rewriteValuegeneric_OpZeroExt32to64(v *Value) bool {
	v_0 := v.Args[0]
	// match: (ZeroExt32to64 (Const32 [c]))
	// result: (Const64 [int64(uint32(c))])
	for {
		if v_0.Op != OpConst32 {
			break
		}
		c := auxIntToInt32(v_0.AuxInt)
		v.reset(OpConst64)
		v.AuxInt = int64ToAuxInt(int64(uint32(c)))
		return true
	}
	// match: (ZeroExt32to64 (Trunc64to32 x:(Rsh64Ux64 _ (Const64 [s]))))
	// cond: s >= 32
	// result: x
	for {
		if v_0.Op != OpTrunc64to32 {
			break
		}
		x := v_0.Args[0]
		if x.Op != OpRsh64Ux64 {
			break
		}
		_ = x.Args[1]
		x_1 := x.Args[1]
		if x_1.Op != OpConst64 {
			break
		}
		s := auxIntToInt64(x_1.AuxInt)
		if !(s >= 32) {
			break
		}
		v.copyOf(x)
		return true
	}
	return false
}
func rewriteValuegeneric_OpZeroExt8to16(v *Value) bool {
	v_0 := v.Args[0]
	// match: (ZeroExt8to16 (Const8 [c]))
	// result: (Const16 [int16( uint8(c))])
	for {
		if v_0.Op != OpConst8 {
			break
		}
		c := auxIntToInt8(v_0.AuxInt)
		v.reset(OpConst16)
		v.AuxInt = int16ToAuxInt(int16(uint8(c)))
		return true
	}
	// match: (ZeroExt8to16 (Trunc16to8 x:(Rsh16Ux64 _ (Const64 [s]))))
	// cond: s >= 8
	// result: x
	for {
		if v_0.Op != OpTrunc16to8 {
			break
		}
		x := v_0.Args[0]
		if x.Op != OpRsh16Ux64 {
			break
		}
		_ = x.Args[1]
		x_1 := x.Args[1]
		if x_1.Op != OpConst64 {
			break
		}
		s := auxIntToInt64(x_1.AuxInt)
		if !(s >= 8) {
			break
		}
		v.copyOf(x)
		return true
	}
	return false
}
func rewriteValuegeneric_OpZeroExt8to32(v *Value) bool {
	v_0 := v.Args[0]
	// match: (ZeroExt8to32 (Const8 [c]))
	// result: (Const32 [int32( uint8(c))])
	for {
		if v_0.Op != OpConst8 {
			break
		}
		c := auxIntToInt8(v_0.AuxInt)
		v.reset(OpConst32)
		v.AuxInt = int32ToAuxInt(int32(uint8(c)))
		return true
	}
	// match: (ZeroExt8to32 (Trunc32to8 x:(Rsh32Ux64 _ (Const64 [s]))))
	// cond: s >= 24
	// result: x
	for {
		if v_0.Op != OpTrunc32to8 {
			break
		}
		x := v_0.Args[0]
		if x.Op != OpRsh32Ux64 {
			break
		}
		_ = x.Args[1]
		x_1 := x.Args[1]
		if x_1.Op != OpConst64 {
			break
		}
		s := auxIntToInt64(x_1.AuxInt)
		if !(s >= 24) {
			break
		}
		v.copyOf(x)
		return true
	}
	return false
}
func rewriteValuegeneric_OpZeroExt8to64(v *Value) bool {
	v_0 := v.Args[0]
	// match: (ZeroExt8to64 (Const8 [c]))
	// result: (Const64 [int64( uint8(c))])
	for {
		if v_0.Op != OpConst8 {
			break
		}
		c := auxIntToInt8(v_0.AuxInt)
		v.reset(OpConst64)
		v.AuxInt = int64ToAuxInt(int64(uint8(c)))
		return true
	}
	// match: (ZeroExt8to64 (Trunc64to8 x:(Rsh64Ux64 _ (Const64 [s]))))
	// cond: s >= 56
	// result: x
	for {
		if v_0.Op != OpTrunc64to8 {
			break
		}
		x := v_0.Args[0]
		if x.Op != OpRsh64Ux64 {
			break
		}
		_ = x.Args[1]
		x_1 := x.Args[1]
		if x_1.Op != OpConst64 {
			break
		}
		s := auxIntToInt64(x_1.AuxInt)
		if !(s >= 56) {
			break
		}
		v.copyOf(x)
		return true
	}
	return false
}
func rewriteBlockgeneric(b *Block) bool {
	switch b.Kind {
	case BlockIf:
		// match: (If (Not cond) yes no)
		// result: (If cond no yes)
		for b.Controls[0].Op == OpNot {
			v_0 := b.Controls[0]
			cond := v_0.Args[0]
			b.resetWithControl(BlockIf, cond)
			b.swapSuccessors()
			return true
		}
		// match: (If (ConstBool [c]) yes no)
		// cond: c
		// result: (First yes no)
		for b.Controls[0].Op == OpConstBool {
			v_0 := b.Controls[0]
			c := auxIntToBool(v_0.AuxInt)
			if !(c) {
				break
			}
			b.Reset(BlockFirst)
			return true
		}
		// match: (If (ConstBool [c]) yes no)
		// cond: !c
		// result: (First no yes)
		for b.Controls[0].Op == OpConstBool {
			v_0 := b.Controls[0]
			c := auxIntToBool(v_0.AuxInt)
			if !(!c) {
				break
			}
			b.Reset(BlockFirst)
			b.swapSuccessors()
			return true
		}
	}
	return false
}

"""




```