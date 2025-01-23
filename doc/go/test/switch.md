Response: The user wants me to analyze a Go code snippet that focuses on `switch` statements. I need to:

1. **Summarize the functionality:**  The code tests various forms and features of the `switch` statement in Go.
2. **Explain the Go `switch` feature:**  Provide a general explanation of how `switch` works in Go, potentially with a simple example.
3. **Explain the code logic with examples:**  Go through the different `switch` constructs used in the code, explaining how each one behaves with specific example inputs (though the provided code doesn't take external input, I can discuss the behavior based on the initialized variables).
4. **Address command-line arguments:**  Check if the code uses any command-line arguments. If so, describe how they are processed. If not, explicitly state that.
5. **Identify common mistakes:** Point out potential pitfalls that developers might encounter while using `switch` statements in Go, supported by examples.

Let's break down the code section by section:

* **Initial Setup:**  Defines an `assert` function and initializes variables `i5`, `i7`, and `hello`.
* **`switch true`:** Tests boolean expression evaluation in `case` clauses.
* **`switch` (no tag):** Tests the implicit boolean true condition.
* **`switch x := 5; true`:**  Tests short variable declaration within the `switch` statement.
* **`switch i5`:** Tests switching on an integer value.
* **`case 0, 1, 2, 3, 4`:** Tests multiple values in a single `case`.
* **Empty `case` clauses:** Tests cases with no associated code.
* **`fallthrough`:** Tests the `fallthrough` keyword.
* **Scoping of `case` variables:**  Tests variable scope within `case` blocks.
* **Counting with `fallthrough`:**  Demonstrates the cumulative effect of `fallthrough`.
* **`switch hello`:** Tests switching on a string.
* **Variable declaration in `switch` tag:** Tests declaring and using a variable in the `switch` condition.
* **`switch` on nil-only comparable types (func, map, slice):** Verifies that these are not nil in this context.
* **`switch` on interface:** Tests switching on an interface value.
* **`switch` on implicit bool converted to interface:** Addresses a specific historical issue.
* **`switch` on interface with constant cases differing by type:** Addresses another historical issue.
* **`switch` on array:** Tests switching on array values.
* **`switch` on channel:** Tests switching on channel equality.
* **Empty `switch`:** Tests a `switch` statement with no `case` clauses.
* **Empty `switch` with `default`:** Tests a `default` case in an empty `switch`.
* **`default` and `fallthrough`:** Tests `fallthrough` from `default`.
* **`fallthrough` to `default` not at the end:** Tests `fallthrough` to a `default` case in the middle of the `switch`.
* **`os.Exit(0)` within a `case`:** Demonstrates exiting the program from within a `case`.
* **`switch (*int)(nil)`:** Tests comparing against the nil value of a specific type.

Based on this analysis, I can now generate the response.
```go
// run

// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Test switch statements.

package main

import "os"

func assert(cond bool, msg string) {
	if !cond {
		print("assertion fail: ", msg, "\n")
		panic(1)
	}
}

func main() {
	i5 := 5
	i7 := 7
	hello := "hello"

	switch true {
	case i5 < 5:
		assert(false, "<")
	case i5 == 5:
		assert(true, "!")
	case i5 > 5:
		assert(false, ">")
	}

	switch {
	case i5 < 5:
		assert(false, "<")
	case i5 == 5:
		assert(true, "!")
	case i5 > 5:
		assert(false, ">")
	}

	switch x := 5; true {
	case i5 < x:
		assert(false, "<")
	case i5 == x:
		assert(true, "!")
	case i5 > x:
		assert(false, ">")
	}

	switch x := 5; true {
	case i5 < x:
		assert(false, "<")
	case i5 == x:
		assert(true, "!")
	case i5 > x:
		assert(false, ">")
	}

	switch i5 {
	case 0:
		assert(false, "0")
	case 1:
		assert(false, "1")
	case 2:
		assert(false, "2")
	case 3:
		assert(false, "3")
	case 4:
		assert(false, "4")
	case 5:
		assert(true, "5")
	case 6:
		assert(false, "6")
	case 7:
		assert(false, "7")
	case 8:
		assert(false, "8")
	case 9:
		assert(false, "9")
	default:
		assert(false, "default")
	}

	switch i5 {
	case 0, 1, 2, 3, 4:
		assert(false, "4")
	case 5:
		assert(true, "5")
	case 6, 7, 8, 9:
		assert(false, "9")
	default:
		assert(false, "default")
	}

	switch i5 {
	case 0:
	case 1:
	case 2:
	case 3:
	case 4:
		assert(false, "4")
	case 5:
		assert(true, "5")
	case 6:
	case 7:
	case 8:
	case 9:
	default:
		assert(i5 == 5, "good")
	}

	switch i5 {
	case 0:
		dummy := 0
		_ = dummy
		fallthrough
	case 1:
		dummy := 0
		_ = dummy
		fallthrough
	case 2:
		dummy := 0
		_ = dummy
		fallthrough
	case 3:
		dummy := 0
		_ = dummy
		fallthrough
	case 4:
		dummy := 0
		assert(false, "4")
	case 5:
		dummy := 0
		_ = dummy
		fallthrough
	case 6:
		dummy := 0
		_ = dummy
		fallthrough
	case 7:
		dummy := 0
		_ = dummy
		fallthrough
	case 8:
		dummy := 0
		_ = dummy
		fallthrough
	case 9:
		dummy := 0
		_ = dummy
		fallthrough
	default:
		dummy := 0
		_ = dummy
		assert(i5 == 5, "good")
	}

	fired := false
	switch i5 {
	case 0:
		dummy := 0
		_ = dummy
		fallthrough // tests scoping of cases
	case 1:
		dummy := 0
		_ = dummy
		fallthrough
	case 2:
		dummy := 0
		_ = dummy
		fallthrough
	case 3:
		dummy := 0
		_ = dummy
		fallthrough
	case 4:
		dummy := 0
		assert(false, "4")
	case 5:
		dummy := 0
		_ = dummy
		fallthrough
	case 6:
		dummy := 0
		_ = dummy
		fallthrough
	case 7:
		dummy := 0
		_ = dummy
		fallthrough
	case 8:
		dummy := 0
		_ = dummy
		fallthrough
	case 9:
		dummy := 0
		_ = dummy
		fallthrough
	default:
		dummy := 0
		_ = dummy
		fired = !fired
		assert(i5 == 5, "good")
	}
	assert(fired, "fired")

	count := 0
	switch i5 {
	case 0:
		count = count + 1
		fallthrough
	case 1:
		count = count + 1
		fallthrough
	case 2:
		count = count + 1
		fallthrough
	case 3:
		count = count + 1
		fallthrough
	case 4:
		count = count + 1
		assert(false, "4")
	case 5:
		count = count + 1
		fallthrough
	case 6:
		count = count + 1
		fallthrough
	case 7:
		count = count + 1
		fallthrough
	case 8:
		count = count + 1
		fallthrough
	case 9:
		count = count + 1
		fallthrough
	default:
		assert(i5 == count, "good")
	}
	assert(fired, "fired")

	switch hello {
	case "wowie":
		assert(false, "wowie")
	case "hello":
		assert(true, "hello")
	case "jumpn":
		assert(false, "jumpn")
	default:
		assert(false, "default")
	}

	fired = false
	switch i := i5 + 2; i {
	case i7:
		fired = true
	default:
		assert(false, "fail")
	}
	assert(fired, "var")

	// switch on nil-only comparison types
	switch f := func() {}; f {
	case nil:
		assert(false, "f should not be nil")
	default:
	}

	switch m := make(map[int]int); m {
	case nil:
		assert(false, "m should not be nil")
	default:
	}

	switch a := make([]int, 1); a {
	case nil:
		assert(false, "m should not be nil")
	default:
	}

	// switch on interface.
	switch i := interface{}("hello"); i {
	case 42:
		assert(false, `i should be "hello"`)
	case "hello":
		assert(true, "hello")
	default:
		assert(false, `i should be "hello"`)
	}

	// switch on implicit bool converted to interface
	// was broken: see issue 3980
	switch i := interface{}(true); {
	case i:
		assert(true, "true")
	case false:
		assert(false, "i should be true")
	default:
		assert(false, "i should be true")
	}

	// switch on interface with constant cases differing by type.
	// was rejected by compiler: see issue 4781
	type T int
	type B bool
	type F float64
	type S string
	switch i := interface{}(float64(1.0)); i {
	case nil:
		assert(false, "i should be float64(1.0)")
	case (*int)(nil):
		assert(false, "i should be float64(1.0)")
	case 1:
		assert(false, "i should be float64(1.0)")
	case T(1):
		assert(false, "i should be float64(1.0)")
	case F(1.0):
		assert(false, "i should be float64(1.0)")
	case 1.0:
		assert(true, "true")
	case "hello":
		assert(false, "i should be float64(1.0)")
	case S("hello"):
		assert(false, "i should be float64(1.0)")
	case true, B(false):
		assert(false, "i should be float64(1.0)")
	case false, B(true):
		assert(false, "i should be float64(1.0)")
	}

	// switch on array.
	switch ar := [3]int{1, 2, 3}; ar {
	case [3]int{1, 2, 3}:
		assert(true, "[1 2 3]")
	case [3]int{4, 5, 6}:
		assert(false, "ar should be [1 2 3]")
	default:
		assert(false, "ar should be [1 2 3]")
	}

	// switch on channel
	switch c1, c2 := make(chan int), make(chan int); c1 {
	case nil:
		assert(false, "c1 did not match itself")
	case c2:
		assert(false, "c1 did not match itself")
	case c1:
		assert(true, "chan")
	default:
		assert(false, "c1 did not match itself")
	}

	// empty switch
	switch {
	}

	// empty switch with default case.
	fired = false
	switch {
	default:
		fired = true
	}
	assert(fired, "fail")

	// Default and fallthrough.
	count = 0
	switch {
	default:
		count++
		fallthrough
	case false:
		count++
	}
	assert(count == 2, "fail")

	// fallthrough to default, which is not at end.
	count = 0
	switch i5 {
	case 5:
		count++
		fallthrough
	default:
		count++
	case 6:
		count++
	}
	assert(count == 2, "fail")

	i := 0
	switch x := 5; {
	case i < x:
		os.Exit(0)
	case i == x:
	case i > x:
		os.Exit(1)
	}

	// Unified IR converts the tag and all case values to empty
	// interface, when any of the case values aren't assignable to the
	// tag value's type. Make sure that `case nil:` compares against the
	// tag type's nil value (i.e., `(*int)(nil)`), not nil interface
	// (i.e., `any(nil)`).
	switch (*int)(nil) {
	case nil:
		// ok
	case any(nil):
		assert(false, "case any(nil) matched")
	default:
		assert(false, "default matched")
	}
}
```

这个 Go 语言代码片段的主要功能是**测试 `switch` 语句的各种语法和行为**。它通过一系列的 `switch` 语句，结合 `assert` 函数来验证不同情况下 `switch` 语句的执行逻辑是否符合预期。

这段代码覆盖了 `switch` 语句的多种用法，包括：

* **带有条件表达式的 `switch`：**  例如 `switch true { ... }`，基于 `case` 后的布尔表达式进行匹配。
* **不带表达式的 `switch`：** 例如 `switch { ... }`，相当于 `switch true { ... }`，每个 `case` 都是一个布尔表达式。
* **带有初始化语句的 `switch`：** 例如 `switch x := 5; true { ... }`，可以在 `switch` 语句中声明和初始化变量。
* **基于变量值的 `switch`：** 例如 `switch i5 { ... }`，根据变量 `i5` 的值匹配 `case`。
* **`case` 中包含多个值：** 例如 `case 0, 1, 2, 3, 4:`，只要匹配到其中任何一个值就会执行对应的代码块。
* **空的 `case`：** 例如 `case 0:` 后没有任何语句，表示匹配到该 `case` 时不执行任何操作，会继续向下匹配。
* **`fallthrough` 关键字：**  允许在执行完当前 `case` 的代码后，继续执行下一个 `case` 的代码，即使下一个 `case` 的条件不满足。
* **不同数据类型的 `switch`：** 包括整数、字符串、接口、数组、通道等。
* **空 `switch` 和带有 `default` 的空 `switch`。**
* **在 `switch` 语句中进行类型断言 (虽然代码中没有显式类型断言，但 `switch` 对接口的处理可以看作一种隐式的类型判断)。**

这段代码实际上是 Go 语言标准库 `testing` 包的早期形式的体现，它通过断言来验证代码的正确性。

**Go 语言 `switch` 功能实现举例：**

`switch` 语句在 Go 中用于执行多个代码块中的一个，具体执行哪个代码块取决于 `switch` 表达式的值或条件是否与某个 `case` 匹配。

```go
package main

import "fmt"

func main() {
	score := 85

	switch {
	case score >= 90:
		fmt.Println("优秀")
	case score >= 80:
		fmt.Println("良好")
	case score >= 70:
		fmt.Println("中等")
	case score >= 60:
		fmt.Println("及格")
	default:
		fmt.Println("不及格")
	}

	day := "Monday"
	switch day {
	case "Monday":
		fmt.Println("星期一")
	case "Tuesday":
		fmt.Println("星期二")
	case "Wednesday", "Thursday":
		fmt.Println("星期三或星期四")
	default:
		fmt.Println("其他")
	}
}
```

**代码逻辑介绍 (带假设的输入与输出)：**

由于这段代码没有接受外部输入，它的行为是固定的。我们以其中一个 `switch` 语句为例：

```go
	i5 := 5
	switch i5 {
	case 0:
		assert(false, "0")
	case 1:
		assert(false, "1")
	case 2:
		assert(false, "2")
	case 3:
		assert(false, "3")
	case 4:
		assert(false, "4")
	case 5:
		assert(true, "5")
	case 6:
		assert(false, "6")
	case 7:
		assert(false, "7")
	case 8:
		assert(false, "8")
	case 9:
		assert(false, "9")
	default:
		assert(false, "default")
	}
```

**假设输入：** 变量 `i5` 的值为 `5`。

**执行流程：**

1. `switch i5`：开始执行 `switch` 语句，判断 `i5` 的值。
2. 逐个匹配 `case`：
   - `case 0:`：`i5` (5) 不等于 0，跳过。
   - `case 1:`：`i5` (5) 不等于 1，跳过。
   - ...
   - `case 5:`：`i5` (5) 等于 5，执行该 `case` 下的代码 `assert(true, "5")`。
3. `assert(true, "5")`：`assert` 函数接收到 `true`，条件满足，不会触发 `panic`。

**预期输出：** 由于所有的 `assert` 都会在条件为 `false` 时触发 `panic` 并打印错误信息，而这段代码中的断言都是期望成功的，所以如果程序正常执行完毕，不会有任何输出到标准输出或标准错误。

**命令行参数处理：**

这段代码本身不涉及任何命令行参数的处理。它是一个独立的 Go 程序，主要用于内部测试。

**使用者易犯错的点：**

1. **忘记 `break` (在其他语言中常见，但在 Go 中不需要)：**  Go 的 `switch` 语句在匹配到一个 `case` 后，默认不会继续执行后续的 `case`，除非使用了 `fallthrough` 关键字。对于从其他语言转过来的开发者，可能会习惯性地在每个 `case` 结尾添加 `break`，虽然在 Go 中不会报错，但显得冗余。

   ```go
   package main

   import "fmt"

   func main() {
       num := 1
       switch num {
       case 1:
           fmt.Println("One")
           // break // 不需要
       case 2:
           fmt.Println("Two")
       }
   }
   ```

2. **错误地使用 `fallthrough`：** `fallthrough` 会无条件地执行下一个 `case` 的代码，即使下一个 `case` 的条件不满足。如果不理解其行为，可能会导致意想不到的结果。

   ```go
   package main

   import "fmt"

   func main() {
       num := 1
       switch num {
       case 1:
           fmt.Println("Case 1")
           fallthrough
       case 2:
           fmt.Println("Case 2") // 即使 num 不是 2，也会被执行
       }
   }
   ```
   **输出：**
   ```
   Case 1
   Case 2
   ```

3. **`case` 表达式的类型不匹配：** `switch` 表达式和 `case` 表达式的类型需要兼容。

   ```go
   package main

   import "fmt"

   func main() {
       var val interface{} = 10
       switch val {
       case "10": // 类型不匹配，不会匹配到
           fmt.Println("String ten")
       case 10:
           fmt.Println("Integer ten") // 正确匹配
       }
   }
   ```

4. **在 `case` 中声明变量的作用域：** 在一个 `case` 中声明的变量，其作用域仅限于该 `case` 代码块。如果需要在多个 `case` 中使用变量，需要在 `switch` 外部声明。

   ```go
   package main

   import "fmt"

   func main() {
       num := 1
       switch num {
       case 1:
           message := "Hello from case 1"
           fmt.Println(message)
       case 2:
           // fmt.Println(message) // 错误：message 在这里未定义
       }
   }
   ```

这段测试代码非常全面地覆盖了 `switch` 语句的各种特性，可以作为学习和理解 Go 语言 `switch` 语句行为的良好参考。

### 提示词
```
这是路径为go/test/switch.go的go语言实现的一部分， 请归纳一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果介绍代码逻辑，则建议带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
```

### 源代码
```
// run

// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Test switch statements.

package main

import "os"

func assert(cond bool, msg string) {
	if !cond {
		print("assertion fail: ", msg, "\n")
		panic(1)
	}
}

func main() {
	i5 := 5
	i7 := 7
	hello := "hello"

	switch true {
	case i5 < 5:
		assert(false, "<")
	case i5 == 5:
		assert(true, "!")
	case i5 > 5:
		assert(false, ">")
	}

	switch {
	case i5 < 5:
		assert(false, "<")
	case i5 == 5:
		assert(true, "!")
	case i5 > 5:
		assert(false, ">")
	}

	switch x := 5; true {
	case i5 < x:
		assert(false, "<")
	case i5 == x:
		assert(true, "!")
	case i5 > x:
		assert(false, ">")
	}

	switch x := 5; true {
	case i5 < x:
		assert(false, "<")
	case i5 == x:
		assert(true, "!")
	case i5 > x:
		assert(false, ">")
	}

	switch i5 {
	case 0:
		assert(false, "0")
	case 1:
		assert(false, "1")
	case 2:
		assert(false, "2")
	case 3:
		assert(false, "3")
	case 4:
		assert(false, "4")
	case 5:
		assert(true, "5")
	case 6:
		assert(false, "6")
	case 7:
		assert(false, "7")
	case 8:
		assert(false, "8")
	case 9:
		assert(false, "9")
	default:
		assert(false, "default")
	}

	switch i5 {
	case 0, 1, 2, 3, 4:
		assert(false, "4")
	case 5:
		assert(true, "5")
	case 6, 7, 8, 9:
		assert(false, "9")
	default:
		assert(false, "default")
	}

	switch i5 {
	case 0:
	case 1:
	case 2:
	case 3:
	case 4:
		assert(false, "4")
	case 5:
		assert(true, "5")
	case 6:
	case 7:
	case 8:
	case 9:
	default:
		assert(i5 == 5, "good")
	}

	switch i5 {
	case 0:
		dummy := 0
		_ = dummy
		fallthrough
	case 1:
		dummy := 0
		_ = dummy
		fallthrough
	case 2:
		dummy := 0
		_ = dummy
		fallthrough
	case 3:
		dummy := 0
		_ = dummy
		fallthrough
	case 4:
		dummy := 0
		_ = dummy
		assert(false, "4")
	case 5:
		dummy := 0
		_ = dummy
		fallthrough
	case 6:
		dummy := 0
		_ = dummy
		fallthrough
	case 7:
		dummy := 0
		_ = dummy
		fallthrough
	case 8:
		dummy := 0
		_ = dummy
		fallthrough
	case 9:
		dummy := 0
		_ = dummy
		fallthrough
	default:
		dummy := 0
		_ = dummy
		assert(i5 == 5, "good")
	}

	fired := false
	switch i5 {
	case 0:
		dummy := 0
		_ = dummy
		fallthrough // tests scoping of cases
	case 1:
		dummy := 0
		_ = dummy
		fallthrough
	case 2:
		dummy := 0
		_ = dummy
		fallthrough
	case 3:
		dummy := 0
		_ = dummy
		fallthrough
	case 4:
		dummy := 0
		_ = dummy
		assert(false, "4")
	case 5:
		dummy := 0
		_ = dummy
		fallthrough
	case 6:
		dummy := 0
		_ = dummy
		fallthrough
	case 7:
		dummy := 0
		_ = dummy
		fallthrough
	case 8:
		dummy := 0
		_ = dummy
		fallthrough
	case 9:
		dummy := 0
		_ = dummy
		fallthrough
	default:
		dummy := 0
		_ = dummy
		fired = !fired
		assert(i5 == 5, "good")
	}
	assert(fired, "fired")

	count := 0
	switch i5 {
	case 0:
		count = count + 1
		fallthrough
	case 1:
		count = count + 1
		fallthrough
	case 2:
		count = count + 1
		fallthrough
	case 3:
		count = count + 1
		fallthrough
	case 4:
		count = count + 1
		assert(false, "4")
	case 5:
		count = count + 1
		fallthrough
	case 6:
		count = count + 1
		fallthrough
	case 7:
		count = count + 1
		fallthrough
	case 8:
		count = count + 1
		fallthrough
	case 9:
		count = count + 1
		fallthrough
	default:
		assert(i5 == count, "good")
	}
	assert(fired, "fired")

	switch hello {
	case "wowie":
		assert(false, "wowie")
	case "hello":
		assert(true, "hello")
	case "jumpn":
		assert(false, "jumpn")
	default:
		assert(false, "default")
	}

	fired = false
	switch i := i5 + 2; i {
	case i7:
		fired = true
	default:
		assert(false, "fail")
	}
	assert(fired, "var")

	// switch on nil-only comparison types
	switch f := func() {}; f {
	case nil:
		assert(false, "f should not be nil")
	default:
	}

	switch m := make(map[int]int); m {
	case nil:
		assert(false, "m should not be nil")
	default:
	}

	switch a := make([]int, 1); a {
	case nil:
		assert(false, "m should not be nil")
	default:
	}

	// switch on interface.
	switch i := interface{}("hello"); i {
	case 42:
		assert(false, `i should be "hello"`)
	case "hello":
		assert(true, "hello")
	default:
		assert(false, `i should be "hello"`)
	}

	// switch on implicit bool converted to interface
	// was broken: see issue 3980
	switch i := interface{}(true); {
	case i:
		assert(true, "true")
	case false:
		assert(false, "i should be true")
	default:
		assert(false, "i should be true")
	}

	// switch on interface with constant cases differing by type.
	// was rejected by compiler: see issue 4781
	type T int
	type B bool
	type F float64
	type S string
	switch i := interface{}(float64(1.0)); i {
	case nil:
		assert(false, "i should be float64(1.0)")
	case (*int)(nil):
		assert(false, "i should be float64(1.0)")
	case 1:
		assert(false, "i should be float64(1.0)")
	case T(1):
		assert(false, "i should be float64(1.0)")
	case F(1.0):
		assert(false, "i should be float64(1.0)")
	case 1.0:
		assert(true, "true")
	case "hello":
		assert(false, "i should be float64(1.0)")
	case S("hello"):
		assert(false, "i should be float64(1.0)")
	case true, B(false):
		assert(false, "i should be float64(1.0)")
	case false, B(true):
		assert(false, "i should be float64(1.0)")
	}

	// switch on array.
	switch ar := [3]int{1, 2, 3}; ar {
	case [3]int{1, 2, 3}:
		assert(true, "[1 2 3]")
	case [3]int{4, 5, 6}:
		assert(false, "ar should be [1 2 3]")
	default:
		assert(false, "ar should be [1 2 3]")
	}

	// switch on channel
	switch c1, c2 := make(chan int), make(chan int); c1 {
	case nil:
		assert(false, "c1 did not match itself")
	case c2:
		assert(false, "c1 did not match itself")
	case c1:
		assert(true, "chan")
	default:
		assert(false, "c1 did not match itself")
	}

	// empty switch
	switch {
	}

	// empty switch with default case.
	fired = false
	switch {
	default:
		fired = true
	}
	assert(fired, "fail")

	// Default and fallthrough.
	count = 0
	switch {
	default:
		count++
		fallthrough
	case false:
		count++
	}
	assert(count == 2, "fail")

	// fallthrough to default, which is not at end.
	count = 0
	switch i5 {
	case 5:
		count++
		fallthrough
	default:
		count++
	case 6:
		count++
	}
	assert(count == 2, "fail")

	i := 0
	switch x := 5; {
	case i < x:
		os.Exit(0)
	case i == x:
	case i > x:
		os.Exit(1)
	}

	// Unified IR converts the tag and all case values to empty
	// interface, when any of the case values aren't assignable to the
	// tag value's type. Make sure that `case nil:` compares against the
	// tag type's nil value (i.e., `(*int)(nil)`), not nil interface
	// (i.e., `any(nil)`).
	switch (*int)(nil) {
	case nil:
		// ok
	case any(nil):
		assert(false, "case any(nil) matched")
	default:
		assert(false, "default matched")
	}
}
```