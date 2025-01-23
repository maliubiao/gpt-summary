Response: Let's break down the thought process for analyzing the Go code snippet.

1. **Initial Scan and High-Level Understanding:**

   - The file path `go/test/ken/convert.go` immediately suggests this is a *test* file. "ken" might be a specific test suite or author. The name "convert" strongly hints at type conversion.
   - The copyright notice and license are standard Go boilerplate and don't provide functional information.
   - The comment "// Test, near-exhaustive, of converting numbers between types." confirms the core purpose.
   - The comment "// No complex numbers though." clarifies a limitation.
   - The `package main` declaration indicates this is an executable program, likely run as a test.

2. **Identify Key Data Structures:**

   - Global variables `i8`, `u8`, etc., are declared for each basic numeric type in Go. This strongly suggests these are used to hold and convert values.
   - The `big` type is a type alias for `float64`. This might be used for representation before or after conversion, possibly to handle potential precision issues.
   - The `t` struct has `from`, `to` (both integers), and `val` (of type `big`). This looks like a test case structure, where `from` and `to` likely represent the source and destination types, and `val` is the value to convert.
   - The `const` block with `ti8`, `tu8`, etc., uses `iota`. This is a standard Go pattern for creating enumerated constants, clearly representing the different numeric types.
   - The `x` variable is a slice of `t` structs, initialized with a large number of test cases. This confirms the hypothesis that `t` is a test case structure.

3. **Analyze the `main` Function:**

   - The `for` loop iterates through the `x` slice (the test cases).
   - Inside the loop, `v` gets the `val` from the current test case, `w` is initialized to 0 (likely the result), and `f` and `t` get the `from` and `to` type identifiers.
   - The lines `i8 = 0; u8 = 0; ...` reset the global variables before each test. This is crucial for isolating test cases.
   - The `switch f*100 + t` is a clever way to create a unique integer key for each pair of source and destination types. This avoids deeply nested `if/else` statements.
   - Within each `case`, a series of type conversions are performed. For example, `i8 = int8(v); i8 = int8(i8); w = big(i8)` converts `v` (which is `big`, an alias for `float64`) to `int8`, and then back to `big`. The double conversion to `int8` is likely just a way to explicitly perform and visualize the conversion. The result is stored in `w`.
   - The `default` case prints a message if a type combination isn't handled, indicating potential incompleteness in the test.
   - The `if v != w` checks if the original value and the converted value are equal. This is the core of the test logic – verifying that the conversion produces the expected result. The printing of `i`, `v`, `w`, `f`, `t` helps identify failing test cases.

4. **Infer the Functionality:**

   Based on the analysis, the code's primary function is to *thoroughly test the correctness of Go's built-in numeric type conversion mechanism*. It does this by:

   - Defining a comprehensive set of test cases covering conversions between various integer and floating-point types (signed and unsigned, different sizes).
   - For each test case, performing the explicit type conversion using Go's syntax (e.g., `int8(value)`).
   - Comparing the original value (represented as `big`) with the converted value (also represented as `big`) to detect any discrepancies.

5. **Address Specific Prompts:**

   - **归纳功能 (Summarize Functionality):**  As stated above, it's a near-exhaustive test of Go's numeric type conversion.
   - **推理 Go 语言功能 (Infer Go Language Feature):** The code directly tests Go's *type conversion* feature.
   - **Go 代码举例 (Go Code Example):**  Provide a simple example of type conversion.
   - **代码逻辑 (Code Logic):** Explain the loop, switch statement, and conversion process with a hypothetical input.
   - **命令行参数 (Command-line Arguments):**  The code doesn't use `os.Args` or the `flag` package, so it doesn't handle command-line arguments.
   - **使用者易犯错的点 (Common Mistakes):**  Focus on potential data loss, overflow, and precision issues during conversion. Provide examples to illustrate these.

6. **Refine and Structure the Output:**

   - Organize the findings into clear sections.
   - Use precise language.
   - Provide code examples that are easy to understand.
   - Ensure the explanation of the code logic is step-by-step.
   - Emphasize the testing nature of the code.

By following this systematic approach, we can effectively analyze the provided Go code snippet and answer the given questions comprehensively. The key is to start with a high-level understanding and progressively delve into the details of the code's structure and logic.
## 功能归纳

这段 Go 代码的主要功能是**对 Go 语言中各种基本数字类型之间的相互转换进行详尽的测试**。它通过预定义一系列包含不同数值和源/目标类型的测试用例，然后逐个执行这些转换，并比较转换后的值是否与预期一致。

**可以推理出它是对 Go 语言数值类型转换功能的实现进行的测试。**

## Go 代码举例说明

```go
package main

import "fmt"

func main() {
	var i int32 = 100
	var f float64

	// 将 int32 转换为 float64
	f = float64(i)
	fmt.Println("int32 to float64:", f) // 输出: int32 to float64: 100

	var u uint8 = 250
	var i8 int8

	// 将 uint8 转换为 int8，可能发生溢出
	i8 = int8(u)
	fmt.Println("uint8 to int8:", i8) // 输出: uint8 to int8: -6

	var f32 float32 = 3.14159
	var i32 int32

	// 将 float32 转换为 int32，小数部分会被截断
	i32 = int32(f32)
	fmt.Println("float32 to int32:", i32) // 输出: float32 to int32: 3
}
```

这段代码演示了 Go 语言中进行数值类型转换的基本语法，与 `convert.go` 测试的目标一致。

## 代码逻辑介绍

这段 `convert.go` 代码的核心逻辑如下：

1. **定义全局变量：** 声明了各种基本数字类型的全局变量 (`i8`, `u8`, `i16`, `u16`, `i32`, `u32`, `i64`, `u64`, `f32`, `f64`)，这些变量在 `main` 函数的 `switch` 语句中被用来接收转换后的值。
2. **定义自定义类型 `big`：** `type big float64` 定义了一个 `float64` 的别名，用于存储测试用例中的数值，可能是为了统一处理不同类型的数值。
3. **定义结构体 `t`：**  `type t struct { from, to int; val big }` 定义了一个结构体 `t`，用于表示一个测试用例。
   - `from`:  一个整数，代表源类型（使用常量 `ti8`，`tu8` 等表示）。
   - `to`:    一个整数，代表目标类型。
   - `val`:   `big` 类型，代表要转换的数值。
4. **定义常量：**  `const ( ti8 = iota+1 ... tf64 )` 定义了一系列常量，分别对应各种基本数字类型，用于在测试用例中标识源类型和目标类型。`iota` 使得常量的值递增，方便区分。
5. **定义测试用例切片 `x`：**  `var x = []t{ ... }` 定义了一个结构体 `t` 的切片 `x`，包含了大量的测试用例。每个测试用例指定了要转换的数值 (`val`)，以及源类型 (`from`) 和目标类型 (`to`)。
   - 测试用例覆盖了各种类型之间的转换，包括：
     - 值在所有类型范围内的情况 (例如 10)。
     - 值在部分类型范围内的情况 (例如 -4 只对有符号类型有效，175 对 `u8` 及以上有效)。
     - 边界值附近的情况 (虽然这里没有明显的边界值测试，但结构类似)。
6. **`main` 函数：**
   - 遍历测试用例切片 `x`。
   - 对于每个测试用例：
     - 从 `x[i]` 中获取源值 `v`，源类型 `f`，目标类型 `t`。
     - 将全局变量重置为 0，确保每次测试的初始状态一致。
     - 使用 `switch f*100 + t` 语句，根据源类型和目标类型的组合执行相应的类型转换。
       - `f*100 + t` 是一种将两个整数映射到唯一整数的方法，方便在 `switch` 中进行匹配。
       - 每个 `case` 分支对应一种类型转换。例如，`case ti8*100 + tu8:` 表示从 `int8` 转换为 `uint8`。
       - 在 `case` 分支中，先将 `v` (类型为 `big`) 转换为源类型，然后将源类型的值转换为目标类型，并将结果赋值给对应的全局变量，最后再将全局变量的值转换回 `big` 类型赋值给 `w`。例如：
         ```go
         case ti8*100 + tu8:
             i8 = int8(v); // 将 big 转换为 int8
             u8 = uint8(i8); // 将 int8 转换为 uint8
             w = big(u8)     // 将 uint8 转换为 big
         ```
     - 比较原始值 `v` 和转换后的值 `w`。如果两者不相等，则打印错误信息，包括测试用例的索引、原始值、转换后的值、源类型和目标类型。

**假设输入与输出：**

假设当前循环处理到 `x[0]`，其值为 `{ ti8, ti8, 10 }`。

- **输入：**
    - `v` (原始值): `10` (类型为 `big`)
    - `f` (源类型): `ti8` (值为 1)
    - `t` (目标类型): `ti8` (值为 1)
- **执行的 `case` 分支：** `case ti8*100 + ti8:`，即 `case 101:`
- **代码执行：**
    - `i8 = int8(v)`，将 `10` (float64) 转换为 `int8`，`i8` 的值为 `10`。
    - `i8 = int8(i8)`，再次将 `i8` 转换为 `int8`，值不变，仍然是 `10`。
    - `w = big(i8)`，将 `10` (int8) 转换为 `big` (float64)，`w` 的值为 `10.0`。
- **比较：** `v` (10.0) 和 `w` (10.0) 相等。
- **输出：** 没有输出，因为转换成功。

假设当前循环处理到 `x[100]`，其值为 `{ ti8, tu8, -4 }`。

- **输入：**
    - `v` (原始值): `-4` (类型为 `big`)
    - `f` (源类型): `ti8` (值为 1)
    - `t` (目标类型): `tu8` (值为 2)
- **执行的 `case` 分支：** `case ti8*100 + tu8:`，即 `case 102:`
- **代码执行：**
    - `i8 = int8(v)`，将 `-4` (float64) 转换为 `int8`，`i8` 的值为 `-4`。
    - `u8 = uint8(i8)`，将 `-4` (int8) 转换为 `uint8`，会发生溢出，`u8` 的值会是一个很大的正数 (通常是 252，取决于具体的实现)。
    - `w = big(u8)`，将 `u8` 的值转换为 `big` (float64)。
- **比较：** `v` (-4.0) 和 `w` (252.0 或类似的值) 不相等。
- **输出：** 可能会打印类似 `100 -4 252 1 2` 的错误信息。

## 命令行参数

这段代码本身并没有处理任何命令行参数。它是一个独立的 Go 程序，通过硬编码的测试用例来执行转换测试。

## 使用者易犯错的点

虽然这段代码是测试代码，但它也揭示了在 Go 语言中进行数值类型转换时容易犯错的点：

1. **溢出：** 当将一个超出目标类型范围的值进行转换时，会发生溢出。例如，将一个大的正数转换为较小的有符号整数，或者将负数转换为无符号整数。

   ```go
   var u uint8 = 255
   var i8 int8 = int8(u) // i8 的值是 -1，发生了溢出
   ```

2. **截断：** 当将一个浮点数转换为整数时，小数部分会被直接截断，不会进行四舍五入。

   ```go
   var f float32 = 3.9
   var i int32 = int32(f) // i 的值是 3，小数部分被截断
   ```

3. **精度丢失：** 当将一个高精度的浮点数转换为低精度的浮点数时，可能会发生精度丢失。

   ```go
   var f64 float64 = 1.0 / 3.0
   var f32 float32 = float32(f64) // f32 的精度可能不如 f64
   ```

这段测试代码通过大量的用例验证了这些转换行为，帮助 Go 语言的开发者确保类型转换的正确性。作为使用者，需要了解这些潜在的问题，并在进行类型转换时谨慎处理，避免数据丢失或产生意外的结果。

### 提示词
```
这是路径为go/test/ken/convert.go的go语言实现的一部分， 请归纳一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果介绍代码逻辑，则建议带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
```

### 源代码
```
// run

// Copyright 2010 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Test, near-exhaustive, of converting numbers between types.
// No complex numbers though.

package main

var i8 int8;
var u8 uint8;
var i16 int16;
var u16 uint16;
var i32 int32;
var u32 uint32;
var i64 int64;
var u64 uint64;
var f32 float32;
var f64 float64;

type	big	float64

type	t	struct {
	from, to	int
	val		big
}

const (
	ti8	= iota+1
	tu8
	ti16
	tu16
	ti32
	tu32
	ti64
	tu64
	tf32
	tf64
)

var	x = []t{

	/* value good in all types (10) */
	{ ti8,  ti8,  10 }, { ti8,  tu8,  10 }, { ti8,  ti16, 10 }, { ti8,  tu16, 10 },
	{ ti8,  ti32, 10 }, { ti8,  tu32, 10 }, { ti8,  ti64, 10 }, { ti8,  tu64, 10 },
	{ ti8,  tf32, 10 }, { ti8,  tf64, 10 },

	{ tu8,  ti8,  10 }, { tu8,  tu8,  10 }, { tu8,  ti16, 10 }, { tu8,  tu16, 10 },
	{ tu8,  ti32, 10 }, { tu8,  tu32, 10 }, { tu8,  ti64, 10 }, { tu8,  tu64, 10 },
	{ tu8,  tf32, 10 }, { tu8,  tf64, 10 },

	{ ti16, ti8,  10 }, { ti16, tu8,  10 }, { ti16, ti16, 10 }, { ti16, tu16, 10 },
	{ ti16, ti32, 10 }, { ti16, tu32, 10 }, { ti16, ti64, 10 }, { ti16, tu64, 10 },
	{ ti16, tf32, 10 }, { ti16, tf64, 10 },

	{ tu16, ti8,  10 }, { tu16, tu8,  10 }, { tu16, ti16, 10 }, { tu16, tu16, 10 },
	{ tu16, ti32, 10 }, { tu16, tu32, 10 }, { tu16, ti64, 10 }, { tu16, tu64, 10 },
	{ tu16, tf32, 10 }, { tu16, tf64, 10 },

	{ ti32, ti8,  10 }, { ti32, tu8,  10 }, { ti32, ti16, 10 }, { ti32, tu16, 10 },
	{ ti32, ti32, 10 }, { ti32, tu32, 10 }, { ti32, ti64, 10 }, { ti32, tu64, 10 },
	{ ti32, tf32, 10 }, { ti32, tf64, 10 },

	{ tu32, ti8,  10 }, { tu32, tu8,  10 }, { tu32, ti16, 10 }, { tu32, tu16, 10 },
	{ tu32, ti32, 10 }, { tu32, tu32, 10 }, { tu32, ti64, 10 }, { tu32, tu64, 10 },
	{ tu32, tf32, 10 }, { tu32, tf64, 10 },

	{ ti64, ti8,  10 }, { ti64, tu8,  10 }, { ti64, ti16, 10 }, { ti64, tu16, 10 },
	{ ti64, ti32, 10 }, { ti64, tu32, 10 }, { ti64, ti64, 10 }, { ti64, tu64, 10 },
	{ ti64, tf32, 10 }, { ti64, tf64, 10 },

	{ tu64, ti8,  10 }, { tu64, tu8,  10 }, { tu64, ti16, 10 }, { tu64, tu16, 10 },
	{ tu64, ti32, 10 }, { tu64, tu32, 10 }, { tu64, ti64, 10 }, { tu64, tu64, 10 },
	{ tu64, tf32, 10 }, { tu64, tf64, 10 },

	{ tf32, ti8,  10 }, { tf32, tu8,  10 }, { tf32, ti16, 10 }, { tf32, tu16, 10 },
	{ tf32, ti32, 10 }, { tf32, tu32, 10 }, { tf32, ti64, 10 }, { tf32, tu64, 10 },
	{ tf32, tf32, 10 }, { tf32, tf64, 10 },

	{ tf64, ti8,  10 }, { tf64, tu8,  10 }, { tf64, ti16, 10 }, { tf64, tu16, 10 },
	{ tf64, ti32, 10 }, { tf64, tu32, 10 }, { tf64, ti64, 10 }, { tf64, tu64, 10 },
	{ tf64, tf32, 10 }, { tf64, tf64, 10 },

	/* value good in all signed types (-4) */
	{ ti8,  ti8,  -4 }, { ti8,  ti16, -4 },
	{ ti8,  ti32, -4 }, { ti8,  ti64, -4 },
	{ ti8,  tf32, -4 }, { ti8,  tf64, -4 },

	{ ti16, ti8,  -4 }, { ti16, ti16, -4 },
	{ ti16, ti32, -4 }, { ti16, ti64, -4 },
	{ ti16, tf32, -4 },

	{ ti32, ti8,  -4 }, { ti32, ti16, -4 },
	{ ti32, ti32, -4 }, { ti32, ti64, -4 },
	{ ti32, tf32, -4 }, { ti32, tf64, -4 },

	{ ti64, ti8,  -4 }, { ti64, ti16, -4 },
	{ ti64, ti32, -4 }, { ti64, ti64, -4 },
	{ ti64, tf32, -4 },

	{ tf32, ti8,  -4 }, { tf32, ti16, -4 },
	{ tf32, ti32, -4 }, { tf32, ti64, -4 },
	{ tf32, tf32, -4 },

	{ tf64, ti8,  -4 }, { tf64, ti16, -4 },
	{ tf64, ti32, -4 }, { tf64, ti64, -4 },
	{ tf64, tf32, -4 }, { tf64, tf64, -4 },

	/* value good in u8 and up (175) */
	{ tu8,  tu8,  175 }, { tu8,  ti16, 175 }, { tu8,  tu16, 175 },
	{ tu8,  ti32, 175 }, { tu8,  tu32, 175 }, { tu8,  ti64, 175 }, { tu8,  tu64, 175 },
	{ tu8,  tf32, 175 }, { tu8,  tf64, 175 },

	{ ti16, tu8,  175 }, { ti16, ti16, 175 }, { ti16, tu16, 175 },
	{ ti16, ti32, 175 }, { ti16, tu32, 175 }, { ti16, ti64, 175 }, { ti16, tu64, 175 },
	{ ti16, tf32, 175 }, { ti16, tf64, 175 },

	{ tu16, tu8,  175 }, { tu16, ti16, 175 }, { tu16, tu16, 175 },
	{ tu16, ti32, 175 }, { tu16, tu32, 175 }, { tu16, ti64, 175 }, { tu16, tu64, 175 },
	{ tu16, tf32, 175 }, { tu16, tf64, 175 },

	{ ti32, tu8,  175 }, { ti32, ti16, 175 }, { ti32, tu16, 175 },
	{ ti32, ti32, 175 }, { ti32, tu32, 175 }, { ti32, ti64, 175 }, { ti32, tu64, 175 },
	{ ti32, tf32, 175 }, { ti32, tf64, 175 },

	{ tu32, tu8,  175 }, { tu32, ti16, 175 }, { tu32, tu16, 175 },
	{ tu32, ti32, 175 }, { tu32, tu32, 175 }, { tu32, ti64, 175 }, { tu32, tu64, 175 },
	{ tu32, tf32, 175 }, { tu32, tf64, 175 },

	{ ti64, tu8,  175 }, { ti64, ti16, 175 }, { ti64, tu16, 175 },
	{ ti64, ti32, 175 }, { ti64, tu32, 175 }, { ti64, ti64, 175 }, { ti64, tu64, 175 },
	{ ti64, tf32, 175 }, { ti64, tf64, 175 },

	{ tu64, tu8,  175 }, { tu64, ti16, 175 }, { tu64, tu16, 175 },
	{ tu64, ti32, 175 }, { tu64, tu32, 175 }, { tu64, ti64, 175 }, { tu64, tu64, 175 },
	{ tu64, tf32, 175 }, { tu64, tf64, 175 },

	{ tf32, tu8,  175 }, { tf32, ti16, 175 }, { tf32, tu16, 175 },
	{ tf32, ti32, 175 }, { tf32, tu32, 175 }, { tf32, ti64, 175 }, { tf32, tu64, 175 },
	{ tf32, tf32, 175 }, { tf32, tf64, 175 },

	{ tf64, tu8,  175 }, { tf64, ti16, 175 }, { tf64, tu16, 175 },
	{ tf64, ti32, 175 }, { tf64, tu32, 175 }, { tf64, ti64, 175 }, { tf64, tu64, 175 },
	{ tf64, tf32, 175 }, { tf64, tf64, 175 },

	/* value good in u16 and up (41259) */
	{ tu16, tu16, 41259 },
	{ tu16, ti32, 41259 }, { tu16, ti64, 41259 }, { tu16, tu64, 41259 },
	{ tu16, tf32, 41259 }, { tu16, tf64, 41259 },

	{ ti32, tu16, 41259 },
	{ ti32, ti32, 41259 }, { ti32, tu32, 41259 }, { ti32, ti64, 41259 }, { ti32, tu64, 41259 },
	{ ti32, tf32, 41259 }, { ti32, tf64, 41259 },

	{ tu32, tu16, 41259 },
	{ tu32, ti32, 41259 }, { tu32, tu32, 41259 }, { tu32, ti64, 41259 }, { tu32, tu64, 41259 },
	{ tu32, tf32, 41259 }, { tu32, tf64, 41259 },

	{ ti64, tu16, 41259 },
	{ ti64, ti32, 41259 }, { ti64, tu32, 41259 }, { ti64, ti64, 41259 }, { ti64, tu64, 41259 },
	{ ti64, tf32, 41259 }, { ti64, tf64, 41259 },

	{ tu64, tu16, 41259 },
	{ tu64, ti32, 41259 }, { tu64, tu32, 41259 }, { tu64, ti64, 41259 }, { tu64, tu64, 41259 },
	{ tu64, tf32, 41259 }, { tu64, tf64, 41259 },

	{ tf32, tu16, 41259 },
	{ tf32, ti32, 41259 }, { tf32, tu32, 41259 }, { tf32, ti64, 41259 }, { tf32, tu64, 41259 },
	{ tf32, tf32, 41259 }, { tf32, tf64, 41259 },

	{ tf64, tu16, 41259 },
	{ tf64, ti32, 41259 }, { tf64, tu32, 41259 }, { tf64, ti64, 41259 }, { tf64, tu64, 41259 },
	{ tf64, tf32, 41259 }, { tf64, tf64, 41259 },

	/* value good in u32 and up (3758096384) */
	{ tu32, tu32, 3758096384 }, { tu32, ti64, 3758096384 }, { tu32, tu64, 3758096384 },
	{ tu32, tf32, 3758096384 }, { tu32, tf64, 3758096384 },

	{ ti64, tu32, 3758096384 }, { ti64, ti64, 3758096384 }, { ti64, tu64, 3758096384 },
	{ ti64, tf32, 3758096384 }, { ti64, tf64, 3758096384 },

	{ tu64, tu32, 3758096384 }, { tu64, ti64, 3758096384 }, { tu64, tu64, 3758096384 },
	{ tu64, tf32, 3758096384 }, { tu64, tf64, 3758096384 },

	{ tf32, tu32, 3758096384 }, { tf32, ti64, 3758096384 }, { tf32, tu64, 3758096384 },
	{ tf32, tf32, 3758096384 }, { tf32, tf64, 3758096384 },

	{ tf64, tu32, 3758096384 }, { tf64, ti64, 3758096384 }, { tf64, tu64, 3758096384 },
	{ tf64, tf32, 3758096384 }, { tf64, tf64, 3758096384 },

	/* value good in u64 and up (16717361816799281152) */
	{ tu64, tu64, 16717361816799281152 },
	{ tu64, tf32, 16717361816799281152 }, { tu64, tf64, 16717361816799281152 },

	{ tf32, tu64, 16717361816799281152 },
	{ tf32, tf32, 16717361816799281152 }, { tf32, tf64, 16717361816799281152 },

	{ tf64, tu64, 16717361816799281152 },
	{ tf64, tf32, 16717361816799281152 }, { tf64, tf64, 16717361816799281152 },
}

func main() {
	for i:=0; i<len(x); i++ {
		v := x[i].val		// input value
		w := big(0)		// output value
		f := x[i].from		// input type
		t := x[i].to		// output type

		i8  = 0; u8  = 0; i16 = 0; u16 = 0
		i32 = 0; u32 = 0; i64 = 0; u64 = 0
		f32 = 0; f64 = 0

		switch f*100 + t {
		default:
			println("missing case", i, v, f, t)
			w = v

		case ti8*100 + ti8:
			i8 = int8(v); i8 = int8(i8); w = big(i8)
		case ti8*100 + tu8:
			i8 = int8(v); u8 = uint8(i8); w = big(u8)
		case ti8*100 + ti16:
			i8 = int8(v); i16 = int16(i8); w = big(i16)
		case ti8*100 + tu16:
			i8 = int8(v); u16 = uint16(i8); w = big(u16)
		case ti8*100 + ti32:
			i8 = int8(v); i32 = int32(i8); w = big(i32)
		case ti8*100 + tu32:
			i8 = int8(v); u32 = uint32(i8); w = big(u32)
		case ti8*100 + ti64:
			i8 = int8(v); i64 = int64(i8); w = big(i64)
		case ti8*100 + tu64:
			i8 = int8(v); u64 = uint64(i8); w = big(u64)
		case ti8*100 + tf32:
			i8 = int8(v); f32 = float32(i8); w = big(f32)
		case ti8*100 + tf64:
			i8 = int8(v); f64 = float64(i8); w = big(f64)

		case tu8*100 + ti8:
			u8 = uint8(v); i8 = int8(u8); w = big(i8)
		case tu8*100 + tu8:
			u8 = uint8(v); u8 = uint8(u8); w = big(u8)
		case tu8*100 + ti16:
			u8 = uint8(v); i16 = int16(u8); w = big(i16)
		case tu8*100 + tu16:
			u8 = uint8(v); u16 = uint16(u8); w = big(u16)
		case tu8*100 + ti32:
			u8 = uint8(v); i32 = int32(u8); w = big(i32)
		case tu8*100 + tu32:
			u8 = uint8(v); u32 = uint32(u8); w = big(u32)
		case tu8*100 + ti64:
			u8 = uint8(v); i64 = int64(u8); w = big(i64)
		case tu8*100 + tu64:
			u8 = uint8(v); u64 = uint64(u8); w = big(u64)
		case tu8*100 + tf32:
			u8 = uint8(v); f32 = float32(u8); w = big(f32)
		case tu8*100 + tf64:
			u8 = uint8(v); f64 = float64(u8); w = big(f64)

		case ti16*100 + ti8:
			i16 = int16(v); i8 = int8(i16); w = big(i8)
		case ti16*100 + tu8:
			i16 = int16(v); u8 = uint8(i16); w = big(u8)
		case ti16*100 + ti16:
			i16 = int16(v); i16 = int16(i16); w = big(i16)
		case ti16*100 + tu16:
			i16 = int16(v); u16 = uint16(i16); w = big(u16)
		case ti16*100 + ti32:
			i16 = int16(v); i32 = int32(i16); w = big(i32)
		case ti16*100 + tu32:
			i16 = int16(v); u32 = uint32(i16); w = big(u32)
		case ti16*100 + ti64:
			i16 = int16(v); i64 = int64(i16); w = big(i64)
		case ti16*100 + tu64:
			i16 = int16(v); u64 = uint64(i16); w = big(u64)
		case ti16*100 + tf32:
			i16 = int16(v); f32 = float32(i16); w = big(f32)
		case ti16*100 + tf64:
			i16 = int16(v); f64 = float64(i16); w = big(f64)

		case tu16*100 + ti8:
			u16 = uint16(v); i8 = int8(u16); w = big(i8)
		case tu16*100 + tu8:
			u16 = uint16(v); u8 = uint8(u16); w = big(u8)
		case tu16*100 + ti16:
			u16 = uint16(v); i16 = int16(u16); w = big(i16)
		case tu16*100 + tu16:
			u16 = uint16(v); u16 = uint16(u16); w = big(u16)
		case tu16*100 + ti32:
			u16 = uint16(v); i32 = int32(u16); w = big(i32)
		case tu16*100 + tu32:
			u16 = uint16(v); u32 = uint32(u16); w = big(u32)
		case tu16*100 + ti64:
			u16 = uint16(v); i64 = int64(u16); w = big(i64)
		case tu16*100 + tu64:
			u16 = uint16(v); u64 = uint64(u16); w = big(u64)
		case tu16*100 + tf32:
			u16 = uint16(v); f32 = float32(u16); w = big(f32)
		case tu16*100 + tf64:
			u16 = uint16(v); f64 = float64(u16); w = big(f64)

		case ti32*100 + ti8:
			i32 = int32(v); i8 = int8(i32); w = big(i8)
		case ti32*100 + tu8:
			i32 = int32(v); u8 = uint8(i32); w = big(u8)
		case ti32*100 + ti16:
			i32 = int32(v); i16 = int16(i32); w = big(i16)
		case ti32*100 + tu16:
			i32 = int32(v); u16 = uint16(i32); w = big(u16)
		case ti32*100 + ti32:
			i32 = int32(v); i32 = int32(i32); w = big(i32)
		case ti32*100 + tu32:
			i32 = int32(v); u32 = uint32(i32); w = big(u32)
		case ti32*100 + ti64:
			i32 = int32(v); i64 = int64(i32); w = big(i64)
		case ti32*100 + tu64:
			i32 = int32(v); u64 = uint64(i32); w = big(u64)
		case ti32*100 + tf32:
			i32 = int32(v); f32 = float32(i32); w = big(f32)
		case ti32*100 + tf64:
			i32 = int32(v); f64 = float64(i32); w = big(f64)

		case tu32*100 + ti8:
			u32 = uint32(v); i8 = int8(u32); w = big(i8)
		case tu32*100 + tu8:
			u32 = uint32(v); u8 = uint8(u32); w = big(u8)
		case tu32*100 + ti16:
			u32 = uint32(v); i16 = int16(u32); w = big(i16)
		case tu32*100 + tu16:
			u32 = uint32(v); u16 = uint16(u32); w = big(u16)
		case tu32*100 + ti32:
			u32 = uint32(v); i32 = int32(u32); w = big(i32)
		case tu32*100 + tu32:
			u32 = uint32(v); u32 = uint32(u32); w = big(u32)
		case tu32*100 + ti64:
			u32 = uint32(v); i64 = int64(u32); w = big(i64)
		case tu32*100 + tu64:
			u32 = uint32(v); u64 = uint64(u32); w = big(u64)
		case tu32*100 + tf32:
			u32 = uint32(v); f32 = float32(u32); w = big(f32)
		case tu32*100 + tf64:
			u32 = uint32(v); f64 = float64(u32); w = big(f64)

		case ti64*100 + ti8:
			i64 = int64(v); i8 = int8(i64); w = big(i8)
		case ti64*100 + tu8:
			i64 = int64(v); u8 = uint8(i64); w = big(u8)
		case ti64*100 + ti16:
			i64 = int64(v); i16 = int16(i64); w = big(i16)
		case ti64*100 + tu16:
			i64 = int64(v); u16 = uint16(i64); w = big(u16)
		case ti64*100 + ti32:
			i64 = int64(v); i32 = int32(i64); w = big(i32)
		case ti64*100 + tu32:
			i64 = int64(v); u32 = uint32(i64); w = big(u32)
		case ti64*100 + ti64:
			i64 = int64(v); i64 = int64(i64); w = big(i64)
		case ti64*100 + tu64:
			i64 = int64(v); u64 = uint64(i64); w = big(u64)
		case ti64*100 + tf32:
			i64 = int64(v); f32 = float32(i64); w = big(f32)
		case ti64*100 + tf64:
			i64 = int64(v); f64 = float64(i64); w = big(f64)

		case tu64*100 + ti8:
			u64 = uint64(v); i8 = int8(u64); w = big(i8)
		case tu64*100 + tu8:
			u64 = uint64(v); u8 = uint8(u64); w = big(u8)
		case tu64*100 + ti16:
			u64 = uint64(v); i16 = int16(u64); w = big(i16)
		case tu64*100 + tu16:
			u64 = uint64(v); u16 = uint16(u64); w = big(u16)
		case tu64*100 + ti32:
			u64 = uint64(v); i32 = int32(u64); w = big(i32)
		case tu64*100 + tu32:
			u64 = uint64(v); u32 = uint32(u64); w = big(u32)
		case tu64*100 + ti64:
			u64 = uint64(v); i64 = int64(u64); w = big(i64)
		case tu64*100 + tu64:
			u64 = uint64(v); u64 = uint64(u64); w = big(u64)
		case tu64*100 + tf32:
			u64 = uint64(v); f32 = float32(u64); w = big(f32)
		case tu64*100 + tf64:
			u64 = uint64(v); f64 = float64(u64); w = big(f64)

		case tf32*100 + ti8:
			f32 = float32(v); i8 = int8(f32); w = big(i8)
		case tf32*100 + tu8:
			f32 = float32(v); u8 = uint8(f32); w = big(u8)
		case tf32*100 + ti16:
			f32 = float32(v); i16 = int16(f32); w = big(i16)
		case tf32*100 + tu16:
			f32 = float32(v); u16 = uint16(f32); w = big(u16)
		case tf32*100 + ti32:
			f32 = float32(v); i32 = int32(f32); w = big(i32)
		case tf32*100 + tu32:
			f32 = float32(v); u32 = uint32(f32); w = big(u32)
		case tf32*100 + ti64:
			f32 = float32(v); i64 = int64(f32); w = big(i64)
		case tf32*100 + tu64:
			f32 = float32(v); u64 = uint64(f32); w = big(u64)
		case tf32*100 + tf32:
			f32 = float32(v); f32 = float32(f32); w = big(f32)
		case tf32*100 + tf64:
			f32 = float32(v); f64 = float64(f32); w = big(f64)

		case tf64*100 + ti8:
			f64 = float64(v); i8 = int8(f64); w = big(i8)
		case tf64*100 + tu8:
			f64 = float64(v); u8 = uint8(f64); w = big(u8)
		case tf64*100 + ti16:
			f64 = float64(v); i16 = int16(f64); w = big(i16)
		case tf64*100 + tu16:
			f64 = float64(v); u16 = uint16(f64); w = big(u16)
		case tf64*100 + ti32:
			f64 = float64(v); i32 = int32(f64); w = big(i32)
		case tf64*100 + tu32:
			f64 = float64(v); u32 = uint32(f64); w = big(u32)
		case tf64*100 + ti64:
			f64 = float64(v); i64 = int64(f64); w = big(i64)
		case tf64*100 + tu64:
			f64 = float64(v); u64 = uint64(f64); w = big(u64)
		case tf64*100 + tf32:
			f64 = float64(v); f32 = float32(f64); w = big(f32)
		case tf64*100 + tf64:
			f64 = float64(v); f64 = float64(f64); w = big(f64)
		}
		if v != w { println(i, v, w, f, t) }
	}
}
```