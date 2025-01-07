Response: My thinking process to analyze the provided Go code went something like this:

1. **Understand the Goal:** The core request is to understand the *functionality* of the code, which is clearly related to loop bound checking and proving array/slice access safety. The `// ERROR` comments are a huge clue, indicating the compiler's analysis of loop induction variables and bounds.

2. **Identify the Core Mechanism:** The file name `loopbce.go` and the `// ERROR` comments containing phrases like "Induction variable: limits" and "Proved IsInBounds" strongly suggest this is a test case for the Go compiler's **Bounds Check Elimination (BCE)** optimization. The `-d=ssa/prove/debug=1` compiler flag reinforces this, as it enables debugging output for the SSA (Static Single Assignment) form, which is crucial for compiler optimizations and proofs.

3. **Categorize the Functions:** I scanned through the functions and noticed patterns:
    * Many functions iterate over slices (`[]int`, `[]byte`) or arrays (`[10]int`, `[100]int`).
    * Some iterate over strings.
    * The loops use various forms: `for i := range ...`, `for i := 0; i < len(a); i++`, `for i := len(a) - 1; i >= 0; i--`, loops with increments other than 1, and nested loops.
    * Some functions perform slicing operations within the loop.
    * A few functions involve integer overflow/underflow scenarios.
    * The `//go:build amd64` line indicates this might be architecture-specific testing.

4. **Analyze Individual Functions (Iterative Process):**  I went through each function, paying close attention to the loop structure and the `// ERROR` comments:
    * **Induction Variable Limits:**  The "Induction variable: limits" comment tells us the compiler has successfully determined the range of the loop counter. This is key for BCE.
    * **Proved IsInBounds/IsSliceInBounds:**  These comments indicate the compiler has *proven* that the array/slice access within the loop is always within the valid bounds, meaning a runtime bounds check is unnecessary and can be eliminated.
    * **Deduce the Function's Test Case:**  For each function, I tried to understand *what specific scenario* it was testing. For example:
        * `f0a`: Basic iteration over a slice.
        * `f2`: Iteration starting from a non-zero index.
        * `f4`: Iteration with a step of 2 over a fixed-size array.
        * `f5`: Iteration with a negative starting index and offset access.
        * `g0a` - `g0f`: Various ways to iterate over strings.
        * `k0`, `k1`, `k2`, `k3`: More complex array iterations, including offsets and slicing.
        * `d1`, `d2`, `d3`: Nested loops.
        * `d4`, `d5`, `bce1`: Testing with large integer values and potential overflows.
        * `nobce2`: Cases where BCE might *not* be possible.
        * `stride1`, `stride2`: Loops with strides.

5. **Synthesize the Overall Functionality:** After analyzing several functions, the pattern became clear: this code tests the ability of the Go compiler's SSA-based prove pass to:
    * **Infer the bounds of loop induction variables.**
    * **Use these bounds to prove the safety of array and slice accesses within the loop.**
    * **Handle different loop structures, starting conditions, increments, and array/slice manipulations.**
    * **Identify cases where bounds checks *cannot* be eliminated.**

6. **Construct the Explanatory Sections:** Based on this understanding, I started writing the different sections of the answer:
    * **Functionality Summary:**  Describing the code's purpose as testing the compiler's ability to prove bounds safety.
    * **Go Language Feature:** Identifying Bounds Check Elimination as the core feature.
    * **Go Code Example:**  Creating a simple example demonstrating BCE in action. This involved a basic loop over a slice where the compiler *can* prove safety.
    * **Code Logic with Example:** Choosing a more complex function (like `f4` or `g1`) and explaining how the compiler infers the induction variable limits and proves bounds. I included a hypothetical input and output to make it concrete.
    * **Command-Line Arguments:**  Explaining the `-0` (optimization level) and `-d=ssa/prove/debug=1` flags and their significance.
    * **Common Mistakes:**  Identifying potential pitfalls that prevent BCE, like iterating beyond the bounds or using dynamically determined loop limits that the compiler can't statically analyze.

7. **Refine and Review:** I reviewed the generated explanation to ensure it was clear, accurate, and addressed all parts of the prompt. I made sure the code examples were correct and illustrative. I double-checked the explanation of the compiler flags and the common mistakes.

Essentially, I approached this by: recognizing the pattern of error comments related to loop bounds, deducing the connection to BCE, analyzing individual functions to confirm the pattern and understand specific test cases, and then synthesizing this knowledge into a comprehensive explanation. The provided error messages within the code were the most valuable pieces of information for understanding the code's purpose.
The provided Go code snippet, located at `go/test/loopbce.go`, is a **test file specifically designed to evaluate the Go compiler's ability to perform Bounds Check Elimination (BCE)** during optimization.

Here's a breakdown of its functionality and related aspects:

**Core Functionality:**

The primary purpose of this code is to present various loop structures and array/slice access patterns to the Go compiler. Each function within the file aims to test a specific scenario where the compiler might be able to prove that array or slice access within the loop is always within the valid bounds, thus eliminating the need for runtime bounds checks.

* **Testing Different Loop Structures:** The code includes `for` loops using various forms:
    * `for i := range a`: Iterating over the indices of an array or slice.
    * `for _, i := range a`: Iterating over the elements of an array or slice (though the index isn't used for access in these examples).
    * `for i := start; i < end; i++`:  Standard `for` loop with explicit start, end, and increment.
    * Loops with different increments (e.g., `i += 2`).
    * Loops iterating backwards.
    * Nested loops.

* **Testing Array and Slice Access:**  The core of the tests involves accessing elements of arrays and slices using the loop variable as an index. The `// ERROR "(\([0-9]+\) )?Proved IsInBounds$"` and `// ERROR "(\([0-9]+\) )?Proved IsSliceInBounds$"` comments are crucial. They indicate that the compiler, during its static analysis (specifically the `ssa/prove` pass), has successfully proven that the access is within bounds.

* **Testing with Different Data Types:** The code tests with both slices (`[]int`, `[]byte`) and fixed-size arrays (`[10]int`, `[100]int`). It also includes examples with strings.

* **Testing Edge Cases and Complex Scenarios:** Some functions delve into more complex scenarios, such as:
    * Slicing within the loop (`a[i:]`, `a[:i+1]`).
    * Accessing elements with offsets (`a[i+10]`, `a[i-11]`).
    * Loops with non-zero starting points.
    * Loops with large integer values (testing potential overflow).

* **Negative Testing (Implicit):** While not explicitly marked as "negative tests," some functions might intentionally present scenarios where the compiler *cannot* easily prove bounds safety (though the provided snippet mostly showcases successful BCE).

**What Go Language Feature is Being Tested?**

The primary Go language feature being tested is **Bounds Check Elimination (BCE)**. BCE is a compiler optimization that removes runtime checks for array and slice accesses when the compiler can statically prove that the access will always be within the valid bounds. This optimization improves the performance of Go programs by reducing the overhead of these checks.

**Go Code Example Demonstrating BCE:**

```go
package main

func processSlice(data []int) int {
	sum := 0
	for i := 0; i < len(data); i++ {
		sum += data[i] // The compiler can often prove this is safe
	}
	return sum
}

func main() {
	mySlice := []int{1, 2, 3, 4, 5}
	result := processSlice(mySlice)
	println(result) // Output: 15
}
```

In this example, the Go compiler can analyze the `for` loop and determine that the index `i` will always be within the bounds of the `data` slice (from 0 up to `len(data)-1`). Therefore, the runtime bounds check for `data[i]` can be safely eliminated.

**Code Logic Explanation (with Example):**

Let's take the `f4` function as an example:

```go
func f4(a [10]int) int {
	x := 0
	for i := 0; i < len(a); i += 2 { // ERROR "Induction variable: limits \[0,8\], increment 2$"
		x += a[i] // ERROR "(\([0-9]+\) )?Proved IsInBounds$"
	}
	return x
}
```

**Assumed Input:** `a` is an array of 10 integers, e.g., `[1, 2, 3, 4, 5, 6, 7, 8, 9, 10]`.

**Logic:**

1. **Initialization:** `x` is initialized to 0.
2. **Loop:** The `for` loop iterates with the following characteristics:
   - **Initialization:** `i` starts at 0.
   - **Condition:** The loop continues as long as `i` is less than `len(a)` (which is 10).
   - **Increment:** `i` is incremented by 2 in each iteration.
3. **Access:** Inside the loop, `a[i]` accesses the element of the array `a` at the index `i`.
4. **Accumulation:** The value of `a[i]` is added to `x`.
5. **Return:** The function returns the final value of `x`.

**Compiler's Reasoning (Leading to BCE):**

The `// ERROR "Induction variable: limits \[0,8\], increment 2$"` comment indicates that the compiler's `ssa/prove` pass has determined the range of the induction variable `i`. It knows:

- `i` starts at 0.
- `i` is incremented by 2.
- The loop continues as long as `i < 10`.

Therefore, the possible values of `i` are 0, 2, 4, 6, and 8.

The `// ERROR "(\([0-9]+\) )?Proved IsInBounds$"` comment for `x += a[i]` signifies that the compiler has concluded that for all possible values of `i` (0, 2, 4, 6, 8), the access `a[i]` is within the valid bounds of the array `a` (indices 0 to 9). Hence, the runtime bounds check is unnecessary.

**Hypothetical Output (for the assumed input):**

If `a` is `[1, 2, 3, 4, 5, 6, 7, 8, 9, 10]`, the function would calculate:

`x = a[0] + a[2] + a[4] + a[6] + a[8]`
`x = 1 + 3 + 5 + 7 + 9`
`x = 25`

**Command-Line Arguments:**

The comment `// errorcheck -0 -d=ssa/prove/debug=1` provides information about the command-line arguments used when running this test file:

- **`-0`**: This flag sets the optimization level to 0, which typically disables most optimizations. However, in the context of testing specific optimization passes, it might be used to isolate the effect of the pass being tested. It's possible that for these specific tests, even with `-0`, certain core analyses like the `ssa/prove` pass are still active or configurable.
- **`-d=ssa/prove/debug=1`**: This flag enables debug output for the `ssa/prove` pass of the compiler. The `ssa` refers to the Static Single Assignment intermediate representation used by the Go compiler. The `prove` pass is responsible for performing static analysis to prove properties about the code, including bounds safety. `debug=1` likely enables a certain level of detail in the debug output, allowing developers to see how the compiler is reasoning about the code.

**Common Mistakes that Prevent BCE (Illustrative Examples):**

While not explicitly shown in this snippet, here are some common scenarios where the Go compiler might *not* be able to perform BCE:

1. **Accessing with an Index That is Not Statically Determinable:**

   ```go
   func processSliceDynamicIndex(data []int, index int) int {
       if index >= 0 && index < len(data) { // Even with this check
           return data[index] // BCE might still be difficult if 'index' is truly dynamic
       }
       return 0
   }
   ```

   If `index` is a variable whose value is determined at runtime (e.g., user input, result of another function), the compiler cannot guarantee that `index` will always be within the bounds of `data`.

2. **Modifying the Slice Length Within the Loop:**

   ```go
   func processSliceModifyingLength(data []int) int {
       sum := 0
       for i := 0; i < len(data); i++ {
           sum += data[i]
           if i == 0 {
               data = append(data, 100) // Modifying the slice
           }
       }
       return sum
   }
   ```

   If the length of the slice changes during the loop's execution, the compiler's initial assumptions about the bounds might become invalid.

3. **Using Complex or Unpredictable Loop Conditions:**

   ```go
   func processSliceComplexCondition(data []int) int {
       sum := 0
       i := 0
       for someCondition() { // 'someCondition' is complex
           if i < len(data) {
               sum += data[i]
           }
           i++
       }
       return sum
   }
   ```

   If the loop's termination condition is complex or depends on external factors, the compiler might struggle to determine the exact range of the loop variable.

4. **Indirect Accesses:**

   ```go
   func processSliceIndirect(data [][]int, outerIndex, innerIndex int) int {
       if outerIndex >= 0 && outerIndex < len(data) &&
          innerIndex >= 0 && innerIndex < len(data[outerIndex]) {
           return data[outerIndex][innerIndex] // Double indexing can be harder to prove
       }
       return 0
   }
   ```

   Proving bounds safety for multi-dimensional slices or when accessing through pointers can be more challenging for the compiler.

In summary, `go/test/loopbce.go` is a crucial test file for ensuring the effectiveness of the Go compiler's Bounds Check Elimination optimization. It presents a variety of loop and array/slice access patterns to verify that the compiler can correctly identify and eliminate unnecessary runtime bounds checks, leading to more efficient code.

Prompt: 
```
这是路径为go/test/loopbce.go的go语言实现的一部分， 请归纳一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果介绍代码逻辑，则建议带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，

"""
// errorcheck -0 -d=ssa/prove/debug=1

//go:build amd64

package main

import "math"

func f0a(a []int) int {
	x := 0
	for i := range a { // ERROR "Induction variable: limits \[0,\?\), increment 1$"
		x += a[i] // ERROR "(\([0-9]+\) )?Proved IsInBounds$"
	}
	return x
}

func f0b(a []int) int {
	x := 0
	for i := range a { // ERROR "Induction variable: limits \[0,\?\), increment 1$"
		b := a[i:] // ERROR "(\([0-9]+\) )?Proved IsSliceInBounds$"
		x += b[0]
	}
	return x
}

func f0c(a []int) int {
	x := 0
	for i := range a { // ERROR "Induction variable: limits \[0,\?\), increment 1$"
		b := a[:i+1] // ERROR "(\([0-9]+\) )?Proved IsSliceInBounds$"
		x += b[0]    // ERROR "(\([0-9]+\) )?Proved IsInBounds$"
	}
	return x
}

func f1(a []int) int {
	x := 0
	for _, i := range a { // ERROR "Induction variable: limits \[0,\?\), increment 1$"
		x += i
	}
	return x
}

func f2(a []int) int {
	x := 0
	for i := 1; i < len(a); i++ { // ERROR "Induction variable: limits \[1,\?\), increment 1$"
		x += a[i] // ERROR "(\([0-9]+\) )?Proved IsInBounds$"
	}
	return x
}

func f4(a [10]int) int {
	x := 0
	for i := 0; i < len(a); i += 2 { // ERROR "Induction variable: limits \[0,8\], increment 2$"
		x += a[i] // ERROR "(\([0-9]+\) )?Proved IsInBounds$"
	}
	return x
}

func f5(a [10]int) int {
	x := 0
	for i := -10; i < len(a); i += 2 { // ERROR "Induction variable: limits \[-10,8\], increment 2$"
		x += a[i+10]
	}
	return x
}

func f5_int32(a [10]int) int {
	x := 0
	for i := int32(-10); i < int32(len(a)); i += 2 { // ERROR "Induction variable: limits \[-10,8\], increment 2$"
		x += a[i+10]
	}
	return x
}

func f5_int16(a [10]int) int {
	x := 0
	for i := int16(-10); i < int16(len(a)); i += 2 { // ERROR "Induction variable: limits \[-10,8\], increment 2$"
		x += a[i+10]
	}
	return x
}

func f5_int8(a [10]int) int {
	x := 0
	for i := int8(-10); i < int8(len(a)); i += 2 { // ERROR "Induction variable: limits \[-10,8\], increment 2$"
		x += a[i+10]
	}
	return x
}

func f6(a []int) {
	for i := range a { // ERROR "Induction variable: limits \[0,\?\), increment 1$"
		b := a[0:i] // ERROR "(\([0-9]+\) )?Proved IsSliceInBounds$"
		f6(b)
	}
}

func g0a(a string) int {
	x := 0
	for i := 0; i < len(a); i++ { // ERROR "Induction variable: limits \[0,\?\), increment 1$"
		x += int(a[i]) // ERROR "(\([0-9]+\) )?Proved IsInBounds$"
	}
	return x
}

func g0b(a string) int {
	x := 0
	for i := 0; len(a) > i; i++ { // ERROR "Induction variable: limits \[0,\?\), increment 1$"
		x += int(a[i]) // ERROR "(\([0-9]+\) )?Proved IsInBounds$"
	}
	return x
}

func g0c(a string) int {
	x := 0
	for i := len(a); i > 0; i-- { // ERROR "Induction variable: limits \(0,\?\], increment 1$"
		x += int(a[i-1]) // ERROR "(\([0-9]+\) )?Proved IsInBounds$"
	}
	return x
}

func g0d(a string) int {
	x := 0
	for i := len(a); 0 < i; i-- { // ERROR "Induction variable: limits \(0,\?\], increment 1$"
		x += int(a[i-1]) // ERROR "(\([0-9]+\) )?Proved IsInBounds$"
	}
	return x
}

func g0e(a string) int {
	x := 0
	for i := len(a) - 1; i >= 0; i-- { // ERROR "Induction variable: limits \[0,\?\], increment 1$"
		x += int(a[i]) // ERROR "(\([0-9]+\) )?Proved IsInBounds$"
	}
	return x
}

func g0f(a string) int {
	x := 0
	for i := len(a) - 1; 0 <= i; i-- { // ERROR "Induction variable: limits \[0,\?\], increment 1$"
		x += int(a[i]) // ERROR "(\([0-9]+\) )?Proved IsInBounds$"
	}
	return x
}

func g1() int {
	a := "evenlength"
	x := 0
	for i := 0; i < len(a); i += 2 { // ERROR "Induction variable: limits \[0,8\], increment 2$"
		x += int(a[i]) // ERROR "(\([0-9]+\) )?Proved IsInBounds$"
	}
	return x
}

func g2() int {
	a := "evenlength"
	x := 0
	for i := 0; i < len(a); i += 2 { // ERROR "Induction variable: limits \[0,8\], increment 2$"
		j := i
		if a[i] == 'e' { // ERROR "(\([0-9]+\) )?Proved IsInBounds$"
			j = j + 1
		}
		x += int(a[j])
	}
	return x
}

func g3a() {
	a := "this string has length 25"
	for i := 0; i < len(a); i += 5 { // ERROR "Induction variable: limits \[0,20\], increment 5$"
		useString(a[i:])   // ERROR "(\([0-9]+\) )?Proved IsSliceInBounds$"
		useString(a[:i+3]) // ERROR "(\([0-9]+\) )?Proved IsSliceInBounds$"
		useString(a[:i+5]) // ERROR "(\([0-9]+\) )?Proved IsSliceInBounds$"
		useString(a[:i+6])
	}
}

func g3b(a string) {
	for i := 0; i < len(a); i++ { // ERROR "Induction variable: limits \[0,\?\), increment 1$"
		useString(a[i+1:]) // ERROR "(\([0-9]+\) )?Proved IsSliceInBounds$"
	}
}

func g3c(a string) {
	for i := 0; i < len(a); i++ { // ERROR "Induction variable: limits \[0,\?\), increment 1$"
		useString(a[:i+1]) // ERROR "(\([0-9]+\) )?Proved IsSliceInBounds$"
	}
}

func h1(a []byte) {
	c := a[:128]
	for i := range c { // ERROR "Induction variable: limits \[0,128\), increment 1$"
		c[i] = byte(i) // ERROR "(\([0-9]+\) )?Proved IsInBounds$"
	}
}

func h2(a []byte) {
	for i := range a[:128] { // ERROR "Induction variable: limits \[0,128\), increment 1$"
		a[i] = byte(i)
	}
}

func k0(a [100]int) [100]int {
	for i := 10; i < 90; i++ { // ERROR "Induction variable: limits \[10,90\), increment 1$"
		if a[0] == 0xdeadbeef {
			// This is a trick to prohibit sccp to optimize out the following out of bound check
			continue
		}
		a[i-11] = i
		a[i-10] = i // ERROR "(\([0-9]+\) )?Proved IsInBounds$"
		a[i-5] = i  // ERROR "(\([0-9]+\) )?Proved IsInBounds$"
		a[i] = i    // ERROR "(\([0-9]+\) )?Proved IsInBounds$"
		a[i+5] = i  // ERROR "(\([0-9]+\) )?Proved IsInBounds$"
		a[i+10] = i // ERROR "(\([0-9]+\) )?Proved IsInBounds$"
		a[i+11] = i
	}
	return a
}

func k1(a [100]int) [100]int {
	for i := 10; i < 90; i++ { // ERROR "Induction variable: limits \[10,90\), increment 1$"
		if a[0] == 0xdeadbeef {
			// This is a trick to prohibit sccp to optimize out the following out of bound check
			continue
		}
		useSlice(a[:i-11])
		useSlice(a[:i-10]) // ERROR "(\([0-9]+\) )?Proved IsSliceInBounds$"
		useSlice(a[:i-5])  // ERROR "(\([0-9]+\) )?Proved IsSliceInBounds$"
		useSlice(a[:i])    // ERROR "(\([0-9]+\) )?Proved IsSliceInBounds$"
		useSlice(a[:i+5])  // ERROR "(\([0-9]+\) )?Proved IsSliceInBounds$"
		useSlice(a[:i+10]) // ERROR "(\([0-9]+\) )?Proved IsSliceInBounds$"
		useSlice(a[:i+11]) // ERROR "(\([0-9]+\) )?Proved IsSliceInBounds$"
		useSlice(a[:i+12])

	}
	return a
}

func k2(a [100]int) [100]int {
	for i := 10; i < 90; i++ { // ERROR "Induction variable: limits \[10,90\), increment 1$"
		if a[0] == 0xdeadbeef {
			// This is a trick to prohibit sccp to optimize out the following out of bound check
			continue
		}
		useSlice(a[i-11:])
		useSlice(a[i-10:]) // ERROR "(\([0-9]+\) )?Proved IsSliceInBounds$"
		useSlice(a[i-5:])  // ERROR "(\([0-9]+\) )?Proved IsSliceInBounds$"
		useSlice(a[i:])    // ERROR "(\([0-9]+\) )?Proved IsSliceInBounds$"
		useSlice(a[i+5:])  // ERROR "(\([0-9]+\) )?Proved IsSliceInBounds$"
		useSlice(a[i+10:]) // ERROR "(\([0-9]+\) )?Proved IsSliceInBounds$"
		useSlice(a[i+11:]) // ERROR "(\([0-9]+\) )?Proved IsSliceInBounds$"
		useSlice(a[i+12:])
	}
	return a
}

func k3(a [100]int) [100]int {
	for i := -10; i < 90; i++ { // ERROR "Induction variable: limits \[-10,90\), increment 1$"
		if a[0] == 0xdeadbeef {
			// This is a trick to prohibit sccp to optimize out the following out of bound check
			continue
		}
		a[i+9] = i
		a[i+10] = i // ERROR "(\([0-9]+\) )?Proved IsInBounds$"
		a[i+11] = i
	}
	return a
}

func k3neg(a [100]int) [100]int {
	for i := 89; i > -11; i-- { // ERROR "Induction variable: limits \(-11,89\], increment 1$"
		if a[0] == 0xdeadbeef {
			// This is a trick to prohibit sccp to optimize out the following out of bound check
			continue
		}
		a[i+9] = i
		a[i+10] = i // ERROR "(\([0-9]+\) )?Proved IsInBounds$"
		a[i+11] = i
	}
	return a
}

func k3neg2(a [100]int) [100]int {
	for i := 89; i >= -10; i-- { // ERROR "Induction variable: limits \[-10,89\], increment 1$"
		if a[0] == 0xdeadbeef {
			// This is a trick to prohibit sccp to optimize out the following out of bound check
			continue
		}
		a[i+9] = i
		a[i+10] = i // ERROR "(\([0-9]+\) )?Proved IsInBounds$"
		a[i+11] = i
	}
	return a
}

func k4(a [100]int) [100]int {
	// Note: can't use (-1)<<63 here, because i-min doesn't get rewritten to i+(-min),
	// and it isn't worth adding that special case to prove.
	min := (-1)<<63 + 1
	for i := min; i < min+50; i++ { // ERROR "Induction variable: limits \[-9223372036854775807,-9223372036854775757\), increment 1$"
		a[i-min] = i // ERROR "(\([0-9]+\) )?Proved IsInBounds$"
	}
	return a
}

func k5(a [100]int) [100]int {
	max := (1 << 63) - 1
	for i := max - 50; i < max; i++ { // ERROR "Induction variable: limits \[9223372036854775757,9223372036854775807\), increment 1$"
		a[i-max+50] = i   // ERROR "(\([0-9]+\) )?Proved IsInBounds$"
		a[i-(max-70)] = i // ERROR "(\([0-9]+\) )?Proved IsInBounds$"
	}
	return a
}

func d1(a [100]int) [100]int {
	for i := 0; i < 100; i++ { // ERROR "Induction variable: limits \[0,100\), increment 1$"
		for j := 0; j < i; j++ { // ERROR "Induction variable: limits \[0,\?\), increment 1$"
			a[j] = 0   // ERROR "Proved IsInBounds$"
			a[j+1] = 0 // ERROR "Proved IsInBounds$"
			a[j+2] = 0
		}
	}
	return a
}

func d2(a [100]int) [100]int {
	for i := 0; i < 100; i++ { // ERROR "Induction variable: limits \[0,100\), increment 1$"
		for j := 0; i > j; j++ { // ERROR "Induction variable: limits \[0,\?\), increment 1$"
			a[j] = 0   // ERROR "Proved IsInBounds$"
			a[j+1] = 0 // ERROR "Proved IsInBounds$"
			a[j+2] = 0
		}
	}
	return a
}

func d3(a [100]int) [100]int {
	for i := 0; i <= 99; i++ { // ERROR "Induction variable: limits \[0,99\], increment 1$"
		for j := 0; j <= i-1; j++ {
			a[j] = 0
			a[j+1] = 0 // ERROR "Proved IsInBounds$"
			a[j+2] = 0
		}
	}
	return a
}

func d4() {
	for i := int64(math.MaxInt64 - 9); i < math.MaxInt64-2; i += 4 { // ERROR "Induction variable: limits \[9223372036854775798,9223372036854775802\], increment 4$"
		useString("foo")
	}
	for i := int64(math.MaxInt64 - 8); i < math.MaxInt64-2; i += 4 { // ERROR "Induction variable: limits \[9223372036854775799,9223372036854775803\], increment 4$"
		useString("foo")
	}
	for i := int64(math.MaxInt64 - 7); i < math.MaxInt64-2; i += 4 {
		useString("foo")
	}
	for i := int64(math.MaxInt64 - 6); i < math.MaxInt64-2; i += 4 { // ERROR "Induction variable: limits \[9223372036854775801,9223372036854775801\], increment 4$"
		useString("foo")
	}
	for i := int64(math.MaxInt64 - 9); i <= math.MaxInt64-2; i += 4 { // ERROR "Induction variable: limits \[9223372036854775798,9223372036854775802\], increment 4$"
		useString("foo")
	}
	for i := int64(math.MaxInt64 - 8); i <= math.MaxInt64-2; i += 4 { // ERROR "Induction variable: limits \[9223372036854775799,9223372036854775803\], increment 4$"
		useString("foo")
	}
	for i := int64(math.MaxInt64 - 7); i <= math.MaxInt64-2; i += 4 {
		useString("foo")
	}
	for i := int64(math.MaxInt64 - 6); i <= math.MaxInt64-2; i += 4 {
		useString("foo")
	}
}

func d5() {
	for i := int64(math.MinInt64 + 9); i > math.MinInt64+2; i -= 4 { // ERROR "Induction variable: limits \[-9223372036854775803,-9223372036854775799\], increment 4"
		useString("foo")
	}
	for i := int64(math.MinInt64 + 8); i > math.MinInt64+2; i -= 4 { // ERROR "Induction variable: limits \[-9223372036854775804,-9223372036854775800\], increment 4"
		useString("foo")
	}
	for i := int64(math.MinInt64 + 7); i > math.MinInt64+2; i -= 4 {
		useString("foo")
	}
	for i := int64(math.MinInt64 + 6); i > math.MinInt64+2; i -= 4 { // ERROR "Induction variable: limits \[-9223372036854775802,-9223372036854775802\], increment 4"
		useString("foo")
	}
	for i := int64(math.MinInt64 + 9); i >= math.MinInt64+2; i -= 4 { // ERROR "Induction variable: limits \[-9223372036854775803,-9223372036854775799\], increment 4"
		useString("foo")
	}
	for i := int64(math.MinInt64 + 8); i >= math.MinInt64+2; i -= 4 { // ERROR "Induction variable: limits \[-9223372036854775804,-9223372036854775800\], increment 4"
		useString("foo")
	}
	for i := int64(math.MinInt64 + 7); i >= math.MinInt64+2; i -= 4 {
		useString("foo")
	}
	for i := int64(math.MinInt64 + 6); i >= math.MinInt64+2; i -= 4 {
		useString("foo")
	}
}

func bce1() {
	// tests overflow of max-min
	a := int64(9223372036854774057)
	b := int64(-1547)
	z := int64(1337)

	if a%z == b%z {
		panic("invalid test: modulos should differ")
	}

	for i := b; i < a; i += z { // ERROR "Induction variable: limits \[-1547,9223372036854772720\], increment 1337"
		useString("foobar")
	}
}

func nobce2(a string) {
	for i := int64(0); i < int64(len(a)); i++ { // ERROR "Induction variable: limits \[0,\?\), increment 1$"
		useString(a[i:]) // ERROR "(\([0-9]+\) )?Proved IsSliceInBounds$"
	}
	for i := int64(0); i < int64(len(a))-31337; i++ { // ERROR "Induction variable: limits \[0,\?\), increment 1$"
		useString(a[i:]) // ERROR "(\([0-9]+\) )?Proved IsSliceInBounds$"
	}
	for i := int64(0); i < int64(len(a))+int64(-1<<63); i++ { // ERROR "Induction variable: limits \[0,\?\), increment 1$" "Disproved Less64"
		useString(a[i:])
	}
	j := int64(len(a)) - 123
	for i := int64(0); i < j+123+int64(-1<<63); i++ { // ERROR "Induction variable: limits \[0,\?\), increment 1$" "Disproved Less64"
		useString(a[i:])
	}
	for i := int64(0); i < j+122+int64(-1<<63); i++ { // ERROR "Induction variable: limits \[0,\?\), increment 1$"
		// len(a)-123+122+MinInt overflows when len(a) == 0, so a bound check is needed here
		useString(a[i:])
	}
}

func nobce3(a [100]int64) [100]int64 {
	min := int64((-1) << 63)
	max := int64((1 << 63) - 1)
	for i := min; i < max; i++ { // ERROR "Induction variable: limits \[-9223372036854775808,9223372036854775807\), increment 1$"
	}
	return a
}

func issue26116a(a []int) {
	// There is no induction variable here. The comparison is in the wrong direction.
	for i := 3; i > 6; i++ {
		a[i] = 0
	}
	for i := 7; i < 3; i-- {
		a[i] = 1
	}
}

func stride1(x *[7]int) int {
	s := 0
	for i := 0; i <= 8; i += 3 { // ERROR "Induction variable: limits \[0,6\], increment 3"
		s += x[i] // ERROR "Proved IsInBounds"
	}
	return s
}

func stride2(x *[7]int) int {
	s := 0
	for i := 0; i < 9; i += 3 { // ERROR "Induction variable: limits \[0,6\], increment 3"
		s += x[i] // ERROR "Proved IsInBounds"
	}
	return s
}

//go:noinline
func useString(a string) {
}

//go:noinline
func useSlice(a []int) {
}

func main() {
}

"""



```