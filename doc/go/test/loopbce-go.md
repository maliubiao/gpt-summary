Response: My thinking process to analyze the Go code and answer the user's request goes like this:

1. **Understand the Core Request:** The user wants to understand the functionality of the provided Go code snippet. They specifically ask for:
    * A general description of its purpose.
    * Inferring the Go language feature being demonstrated.
    * Illustrative Go code examples.
    * Details on command-line arguments (if any).
    * Common pitfalls for users.

2. **Initial Code Scan and High-Level Observation:** I quickly scan the code. The most striking feature is the `// ERROR "..."` comments scattered throughout. This strongly suggests the code is designed for testing or demonstrating specific compiler behaviors, particularly related to loop bounds checking and the Static Single Assignment (SSA) form's proving capabilities. The `//go:build amd64` and `// errorcheck -0 -d=ssa/prove/debug=1` directives further confirm this.

3. **Focus on the `// ERROR` Annotations:**  These annotations are the key to understanding the code's purpose. They indicate expected compiler output, specifically from the SSA prove pass. The messages often contain phrases like "Induction variable: limits...", "Proved IsInBounds", and "Proved IsSliceInBounds". This points directly to the code's purpose: demonstrating how the Go compiler's SSA prove pass can deduce the bounds of loop induction variables and prove the safety of array/slice accesses within those loops.

4. **Group Functions by Behavior:** I start grouping the functions based on the patterns in their loops and the associated `// ERROR` messages. I notice different loop structures:
    * `for i := range a`: Iterating over the indices of a slice or array.
    * `for _, i := range a`: Iterating over the values of a slice or array.
    * `for i := start; i < end; i++`:  Standard indexed loops.
    * Loops with different starting points, increments, and conditions.
    * Loops with slices of strings.
    * Nested loops.
    * Loops with potential integer overflow scenarios.

5. **Infer the Go Language Feature:** Based on the `// ERROR` messages and the loop structures, it becomes clear that this code demonstrates the **Go compiler's loop bounds check elimination (BCE)** feature, facilitated by the SSA prove pass. The compiler analyzes the loop conditions and induction variable behavior to determine if array/slice accesses are always within bounds. If it can prove this, it can eliminate redundant bounds checks, improving performance.

6. **Construct Illustrative Examples:** To solidify my understanding and provide clear examples for the user, I select a few representative functions:
    * `f0a`: Demonstrates basic slice iteration and bounds checking.
    * `f2`: Shows a loop with a non-zero starting index.
    * `f4`:  Illustrates a loop with a step increment.
    * `g0a`:  Shows string iteration.
    * `k0`:  A more complex example with multiple array accesses within the loop.

    For each example, I provide:
    * The function's Go code.
    * **Assumptions:** I explicitly state the assumed input (e.g., the content and length of the slice/array). This is crucial for demonstrating how the compiler would reason about the bounds.
    * **Expected Output:** I detail what the compiler's SSA prove pass would likely output (the `// ERROR` messages). This directly connects the code to its intended behavior.

7. **Address Command-Line Arguments:** I look for any usage of `os.Args` or flags in the code. Since there aren't any, I conclude that the code doesn't directly process command-line arguments. However, the `// errorcheck` and `-d=ssa/prove/debug=1` directives are *compiler directives*, used when running the `go test` command with specific flags. So, I explain how these directives influence the test execution and output.

8. **Identify Common Pitfalls:** I consider common mistakes developers make related to loops and array/slice access that this code might highlight:
    * **Off-by-one errors:** Loops starting or ending at incorrect indices. Examples like `f2` (starting at 1) are relevant here.
    * **Incorrect loop conditions:**  Leading to out-of-bounds access. While the current code *proves* correctness, variations with faulty conditions would cause runtime errors.
    * **Assuming fixed-size arrays when dealing with slices:**  Slices have dynamic lengths, and assumptions based on initial size can be wrong.
    * **Integer overflow/underflow in loop counters:**  While not explicitly shown to cause errors *here*, the `d4`, `d5`, `bce1`, `nobce3` functions touch on scenarios where overflow is considered by the prove pass.

9. **Structure the Answer:** I organize my findings into the requested categories: functionality, Go feature, code examples, command-line arguments, and common pitfalls. This makes the answer clear and easy to follow.

10. **Refine and Review:** I reread my answer and compare it to the code to ensure accuracy and completeness. I check if the examples are clear and if the explanations are easy to understand. I make sure to emphasize the role of the `// ERROR` annotations and the purpose of the `-d=ssa/prove/debug=1` flag.

By following these steps, I can effectively analyze the Go code snippet and provide a comprehensive answer that addresses the user's request. The key is to recognize the testing nature of the code and focus on the compiler directives and expected output.
这段Go代码文件 `loopbce.go` 的主要功能是 **测试 Go 编译器在循环语句中进行边界检查消除 (Bounds Check Elimination, BCE) 的能力**。

更具体地说，它包含了一系列精心设计的 Go 函数，这些函数涵盖了各种常见的循环模式，用于验证 Go 编译器能否静态地推断出循环索引的范围，从而消除运行时的边界检查，提高程序性能。

**以下是其功能的详细列举：**

1. **测试不同类型的 `for` 循环结构：**
   - `for i := range a`: 遍历切片或数组的索引。
   - `for _, i := range a`: 遍历切片或数组的值。
   - `for i := start; i < end; i++`:  标准的索引循环。
   - 倒序循环 (`for i := len(a) - 1; i >= 0; i--`)。
   - 步长不为 1 的循环 (`for i := 0; i < len(a); i += 2`)。

2. **测试对切片和数组的访问：**
   - 访问切片的单个元素 (`a[i]`)。
   - 创建子切片 (`a[i:]`, `a[:i+1]`, `a[0:i]`)。
   - 访问字符串的单个字符 (`a[i]`)。

3. **测试编译器对循环变量范围的推断：**
   - 观察编译器能否正确推断出循环变量的上下界。
   - 通过 `// ERROR "Induction variable: limits ..."` 注释来验证编译器的推断结果。

4. **测试边界检查消除 (BCE)：**
   - 验证在编译器能够推断出索引始终在有效范围内的情况下，是否会消除运行时的边界检查。
   - 通过 `// ERROR "(\([0-9]+\) )?Proved IsInBounds$"` 和 `// ERROR "(\([0-9]+\) )?Proved IsSliceInBounds$"` 注释来验证 BCE 是否成功。

5. **测试不同数据类型和场景：**
   - 使用 `int`, `int32`, `int16`, `int8` 等不同大小的整数作为循环变量。
   - 循环遍历字符串 (`string`)。
   - 包含嵌套循环 (`d1`, `d2`, `d3`)。
   - 循环变量涉及到 `math.MaxInt64` 和 `math.MinInt64` 等边界值 (`d4`, `d5`)。
   - 测试可能导致整数溢出的循环 (`bce1`)。
   - 测试在某些情况下边界检查无法消除的场景 (`nobce2`, `nobce3`)。

6. **使用 `//go:build amd64` 限制运行平台：**
   - 表明这些测试可能特定于 `amd64` 架构，可能因为 BCE 的实现细节与架构有关。

7. **使用 `// errorcheck -0 -d=ssa/prove/debug=1` 指定编译和测试选项：**
   - `errorcheck`:  指示这是一个错误检查测试文件。
   - `-0`:  禁用优化，以便更清晰地观察 SSA 证明过程。
   - `-d=ssa/prove/debug=1`: 启用 SSA 证明过程的调试输出，这会产生 `// ERROR` 注释中预期的消息。

**推理其是什么 Go 语言功能的实现：**

这段代码实际上不是一个 Go 语言功能的实现，**它是一个 Go 编译器的测试用例**，用于验证编译器对循环边界检查消除功能的实现是否正确。

**Go 代码举例说明：**

以下以 `f0a` 函数为例进行说明：

```go
func f0a(a []int) int {
	x := 0
	for i := range a { // ERROR "Induction variable: limits \[0,\?\), increment 1$"
		x += a[i] // ERROR "(\([0-9]+\) )?Proved IsInBounds$"
	}
	return x
}
```

**假设的输入与输出：**

**假设输入：** `a` 是一个包含整数的切片，例如 `[]int{1, 2, 3}`。

**代码推理：**

- 循环 `for i := range a` 会遍历切片 `a` 的索引，`i` 的取值范围是 `0` 到 `len(a)-1`。
- 在循环体内部，`a[i]` 用于访问切片的元素。
- 由于编译器可以静态地推断出 `i` 的范围不会超出 `a` 的有效索引范围，因此它可以消除运行时的边界检查。

**预期的 `// ERROR` 输出：**

- `// ERROR "Induction variable: limits \[0,\?\), increment 1$"`:  编译器推断出 `i` 是一个从 0 开始，步长为 1 的递增变量，上限未知（因为切片的长度在编译时可能未知）。
- `// ERROR "(\([0-9]+\) )?Proved IsInBounds$"`:  编译器证明了 `a[i]` 的访问是安全的，索引 `i` 始终在 `a` 的有效范围内。

**命令行参数的具体处理：**

这个 Go 文件本身并没有直接处理命令行参数。但是，它被设计为用 Go 的测试工具链来执行。当你使用 `go test` 命令运行包含此文件的包时，可以通过传递特定的标志来影响测试的行为：

- **`-gcflags`**:  可以将编译选项传递给 Go 编译器。例如，`-gcflags="-d=ssa/prove/debug=1"`  会启用 SSA 证明过程的调试输出，使得 `// ERROR` 注释中的消息能够被匹配。
- **`-run`**:  可以指定要运行的测试函数或测试用例。

例如，要运行包含 `loopbce.go` 的包并启用 SSA 证明调试输出，你可能需要执行类似以下的命令（假设该文件位于 `go/test/` 目录下）：

```bash
cd go/test
go test -gcflags="-d=ssa/prove/debug=1" loopbce.go
```

在这种情况下，`go test` 命令会编译 `loopbce.go` 文件，并根据文件中的 `// ERROR` 注释来检查编译器的输出。如果编译器的输出与 `// ERROR` 注释不符，测试将会失败。

**使用者易犯错的点：**

由于这个文件主要是用于测试编译器，所以对于一般的 Go 开发者来说，直接使用这个文件的情况不多。然而，理解其背后的原理对于编写高性能的 Go 代码非常重要。

在编写循环时，开发者容易犯的错误包括：

1. **Off-by-one 错误：** 循环的起始或结束条件设置不正确，导致数组或切片访问越界。

   ```go
   func example(a []int) {
       for i := 0; i <= len(a); i++ { // 错误：当 i 等于 len(a) 时会越界
           println(a[i])
       }
   }
   ```

2. **错误的循环增量或条件：**  导致循环次数不正确或永远无法终止。

   ```go
   func example(a []int) {
       for i := 0; i < len(a); i -= 1 { // 错误：i 永远不会大于等于 len(a)
           println(a[i])
       }
   }
   ```

3. **在循环内部修改循环变量导致意外行为：** 这可能会干扰编译器的 BCE 分析。

   ```go
   func example(a []int) {
       for i := 0; i < len(a); i++ {
           if a[i] == 0 {
               i++ // 错误：手动修改 i 可能导致跳过元素或越界
           }
           println(a[i])
       }
   }
   ```

4. **在不理解切片长度和容量的情况下操作切片：** 这可能导致对底层数组的访问超出预期。

理解编译器如何进行 BCE 可以帮助开发者编写出更容易被优化的代码。例如，使用 `for i := range a` 这样的标准循环结构通常更容易被编译器分析和优化。

### 提示词
```
这是路径为go/test/loopbce.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
```

### 源代码
```go
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
```