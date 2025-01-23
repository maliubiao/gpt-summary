Response: Let's break down the thought process for analyzing this Go code.

**1. Initial Scan and Identification of Purpose:**

The first thing I noticed was the `// errorcheck` comment at the top. This immediately suggests that the code's primary function is to test the Go compiler's error detection capabilities. The subsequent comment, "Test compiler diagnosis of function missing return statements," confirms this. The "See issue 65 and golang.org/s/go11return" points to the specific Go feature being tested.

**2. Deconstructing the Code Structure:**

The code consists of multiple function definitions within the `package p`. The naming convention of the functions (`_() int`) is a strong clue that these are test cases. The `// ERROR "missing return"` comments scattered throughout the code are the key to understanding what each test is checking.

**3. Analyzing Individual Test Cases:**

I started going through the functions, looking for patterns:

* **Basic Cases:**  Functions with explicit `return` statements are marked as "okay". Functions without `return` are marked with the "missing return" error. This establishes the fundamental rule.
* **Control Flow:** The code then explores different control flow structures:
    * **`goto` and `panic`:**  These are also considered terminating statements, so functions ending with them are "okay". The distinction with `panic` only being the built-in function is important.
    * **Blocks:** Blocks ending in a terminating statement are okay. This means the compiler looks at the *last* statement of a block.
    * **Dead Code:**  Code after a terminating statement (even if it's never reached) triggers the "missing return" error. This is a crucial point about Go's static analysis.
    * **`if-else`:**  The tests demonstrate that an `if-else` chain must have a final `else` block that terminates to avoid the error. Even if the conditions logically cover all possibilities, the *syntax* must have the final `else`.
    * **`for` loops:** `for {}` (infinite loops) are okay. Loops with `break` or conditions are not. This highlights the difference between syntactically guaranteed termination and runtime behavior.
    * **`select` statements:**  `select` blocks are okay if all `case`s terminate (with `panic`, `goto`, or another terminating `select`) and there are no `break` statements that exit the `select`.
    * **`switch` statements:**  `switch` statements require a `default` case that terminates or all cases must terminate to be considered okay. `fallthrough` in a case also contributes to the termination analysis. `break` statements targeting the `switch` make it non-terminating.
    * **Type Switches:** The rules for type switches are similar to regular switches.
* **Function Literals:** The code repeats many of the same tests using anonymous functions (function literals) assigned to the blank identifier `_`. This confirms that the "missing return" check applies to function literals as well.

**4. Identifying the Core Functionality:**

Based on the analysis of the test cases, the core functionality of `go/test/return.go` is to verify that the Go compiler correctly identifies functions that are declared to return a value but do not have a guaranteed path to a `return` statement (or other terminating statements like `panic` or `goto`).

**5. Inferring the Go Feature:**

The code is clearly testing Go's **"Functions with Return Values"** and the compiler's **"Static Analysis for Missing Return Statements."**  This is a fundamental part of Go's type safety and ensures that functions that promise to return a value actually do so in all possible execution paths.

**6. Crafting the Example:**

To illustrate the feature, I needed a simple Go example that would trigger the "missing return" error and one that would be valid. This led to the `needsReturn()` and `hasReturn()` functions.

**7. Explaining the Logic (with Input/Output):**

For the logic explanation, I chose the `if-else` example because it demonstrates a common point of confusion. I created a scenario where a programmer might *think* all cases are covered, but the compiler still requires the explicit `else`. Providing input values and expected outcomes makes the explanation clearer.

**8. Command-Line Parameters and Common Mistakes:**

Since this is a *test* file for the compiler, it doesn't directly involve command-line arguments used by end-users. The "common mistakes" section focuses on the `if-else` and `switch` scenarios, as these are the most likely places where programmers might unintentionally create non-returning functions.

**Self-Correction/Refinement During the Process:**

* **Initial thought:**  Maybe this is about runtime error handling.
* **Correction:** The `// errorcheck` comment and the specific error messages point towards *compile-time* checking, not runtime errors.
* **Initial thought:** Perhaps the focus is just on the `return` keyword.
* **Correction:** The inclusion of `panic` and `goto` shows that the analysis includes other terminating statements.
* **Initial thought:**  The `break` statement might be considered a terminating statement in `for` loops.
* **Correction:** The tests demonstrate that `break` within a conditional `for` loop makes the loop *non-terminating* from the compiler's perspective. Only unconditional `for {}` loops are considered terminating.

By systematically analyzing the code, focusing on the error messages, and understanding the different control flow structures, I could accurately deduce the functionality and provide a comprehensive explanation.
### 功能归纳

这段Go代码的主要功能是**测试 Go 编译器对于函数缺少 return 语句的诊断能力**。  它通过定义一系列不同的函数（或匿名函数），并使用 `// ERROR "missing return"` 注释来标记那些预期编译器会报错 "missing return" 的情况。没有被标记 `// ERROR` 的函数则表示编译器应该能够正常通过编译，即认为这些函数都保证会返回一个值。

### Go 语言功能实现推理及代码示例

这段代码实际上是在测试 Go 语言的**函数返回值和静态类型检查**机制。Go 是一种静态类型语言，如果一个函数声明了返回值类型，编译器会确保所有可能的执行路径最终都会返回一个该类型的值，或者会执行一个像 `panic` 或 `goto` 这样的终止语句。

以下 Go 代码示例说明了 "missing return" 的错误：

```go
package main

import "fmt"

func needsReturn(x int) int {
	if x > 0 {
		fmt.Println("x is positive")
	} // 缺少 else 分支的 return，或者在 if 块后没有 return
}

func hasReturn(x int) int {
	if x > 0 {
		return x
	} else {
		return 0
	}
}

func main() {
	fmt.Println(hasReturn(5))
	// fmt.Println(needsReturn(5)) // 这行代码会导致编译错误
}
```

在上面的 `needsReturn` 函数中，如果 `x` 不大于 0，则函数没有明确的 `return` 语句，这会导致编译错误。  `hasReturn` 函数则在所有可能的执行路径上都有 `return` 语句，所以是合法的。

### 代码逻辑介绍 (带假设输入与输出)

这段测试代码的核心思想是通过各种控制流结构（如 `if-else`、`for`、`switch`、`select`）来模拟函数执行的不同路径，并判断编译器是否正确地识别出缺少 `return` 语句的情况。

**假设输入与输出（针对一个具体的测试用例）：**

考虑以下测试用例：

```go
func _() int {
	print(1)
	if x == nil {
		panic(2)
	}
} // ERROR "missing return"
```

* **假设输入:**  `x` 是一个 `interface{}` 类型的变量，其值可以是 `nil` 或非 `nil`。
* **代码逻辑:**
    1. 执行 `print(1)`，这会向标准输出打印 "1"。
    2. 判断 `x == nil`。
    3. 如果 `x` 为 `nil`，则执行 `panic(2)`，程序会终止并打印错误信息。
    4. 如果 `x` 不为 `nil`，则 `if` 块不执行，函数执行到末尾。
* **预期输出:**  由于当 `x` 不为 `nil` 时，函数没有明确的 `return` 语句，因此编译器会报错 "missing return"。 这与 `// ERROR "missing return"` 的标记一致。

**再例如：**

```go
func _() int {
	print(1)
	for {}
}
```

* **代码逻辑:**
    1. 执行 `print(1)`。
    2. 进入一个无限循环 `for {}`。
* **预期输出:**  由于程序会永远停留在 `for` 循环中，永远不会执行到函数末尾，这隐含地保证了函数不会因为缺少 `return` 而出错，因此编译器不会报错。

### 命令行参数的具体处理

这段代码本身是一个 Go 源代码文件，用于测试编译器的功能。它**不涉及**任何可以直接由用户在命令行中传递的参数。 它的运行方式是通过 Go 的测试工具链，例如使用 `go test` 命令来编译和运行包含此类测试代码的包。Go 的测试工具会解析带有 `// errorcheck` 标记的文件，并验证编译器产生的错误信息是否与代码中的 `// ERROR` 标记一致。

### 使用者易犯错的点

使用者在编写有返回值的 Go 函数时，容易犯以下错误，这些错误正是这段测试代码所覆盖的：

1. **在 `if-else` 结构中缺少最终的 `else` 分支的 `return` 语句。**

   ```go
   func example(x int) int {
       if x > 0 {
           return 1
       } // 如果 x <= 0，则缺少 return
   }
   ```

2. **在 `switch` 语句中，如果缺少 `default` 分支，并且不是所有 `case` 分支都以 `return`、`panic` 或 `goto` 结尾。**

   ```go
   func example(x int) int {
       switch x {
       case 1:
           return 1
       case 2:
           println("two") // 缺少 return
       }
   }
   ```

3. **在带有条件的 `for` 循环中，即使逻辑上循环可能永远执行，但只要语法上没有保证终止，就不能代替 `return`。**

   ```go
   func example(x int) int {
       for x > 0 {
           x--
       } // 循环结束，但缺少 return
   }
   ```

4. **在 `select` 语句中，如果不是所有的 `case` 分支都以终止语句结束，且没有 `default` 分支包含终止语句。**

   ```go
   func example(c chan int) int {
       select {
       case <-c:
           println("received") // 缺少 return
       }
   }
   ```

5. **在函数字面量（匿名函数）中忘记添加 `return` 语句，规则与普通函数相同。**

   ```go
   var myFunc = func(x int) int {
       if x > 0 {
           return 1
       }
   } // 缺少 return
   ```

这段测试代码通过大量的用例覆盖了这些易错点，确保 Go 编译器能够有效地检测出这些 "missing return" 的错误，从而帮助开发者编写更健壮的代码。

### 提示词
```
这是路径为go/test/return.go的go语言实现的一部分， 请归纳一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果介绍代码逻辑，则建议带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
```

### 源代码
```
// errorcheck

// Copyright 2013 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Test compiler diagnosis of function missing return statements.
// See issue 65 and golang.org/s/go11return.

package p

type T int

var x interface{}
var c chan int

func external() int // ok

func _() int {
} // ERROR "missing return"

func _() int {
	print(1)
} // ERROR "missing return"

// return is okay
func _() int {
	print(1)
	return 2
}

// goto is okay
func _() int {
L:
	print(1)
	goto L
}

// panic is okay
func _() int {
	print(1)
	panic(2)
}

// but only builtin panic
func _() int {
	var panic = func(int) {}
	print(1)
	panic(2)
} // ERROR "missing return"

// block ending in terminating statement is okay
func _() int {
	{
		print(1)
		return 2
	}
}

// block ending in terminating statement is okay
func _() int {
L:
	{
		print(1)
		goto L
	}
}

// block ending in terminating statement is okay
func _() int {
	print(1)
	{
		panic(2)
	}
}

// adding more code - even though it is dead - now requires a return

func _() int {
	print(1)
	return 2
	print(3)
} // ERROR "missing return"

func _() int {
L:
	print(1)
	goto L
	print(3)
} // ERROR "missing return"

func _() int {
	print(1)
	panic(2)
	print(3)
} // ERROR "missing return"

func _() int {
	{
		print(1)
		return 2
		print(3)
	}
} // ERROR "missing return"

func _() int {
L:
	{
		print(1)
		goto L
		print(3)
	}
} // ERROR "missing return"

func _() int {
	print(1)
	{
		panic(2)
		print(3)
	}
} // ERROR "missing return"

func _() int {
	{
		print(1)
		return 2
	}
	print(3)
} // ERROR "missing return"

func _() int {
L:
	{
		print(1)
		goto L
	}
	print(3)
} // ERROR "missing return"

func _() int {
	print(1)
	{
		panic(2)
	}
	print(3)
} // ERROR "missing return"

// even an empty dead block triggers the message, because it
// becomes the final statement.

func _() int {
	print(1)
	return 2
	{}
} // ERROR "missing return"

func _() int {
L:
	print(1)
	goto L
	{}
} // ERROR "missing return"

func _() int {
	print(1)
	panic(2)
	{}
} // ERROR "missing return"

func _() int {
	{
		print(1)
		return 2
		{}
	}
} // ERROR "missing return"

func _() int {
L:
	{
		print(1)
		goto L
		{}
	}
} // ERROR "missing return"

func _() int {
	print(1)
	{
		panic(2)
		{}
	}
} // ERROR "missing return"

func _() int {
	{
		print(1)
		return 2
	}
	{}
} // ERROR "missing return"

func _() int {
L:
	{
		print(1)
		goto L
	}
	{}
} // ERROR "missing return"

func _() int {
	print(1)
	{
		panic(2)
	}
	{}
} // ERROR "missing return"

// if-else chain with final else and all terminating is okay

func _() int {
	print(1)
	if x == nil {
		panic(2)
	} else {
		panic(3)
	}
}

func _() int {
L:
	print(1)
	if x == nil {
		panic(2)
	} else {
		goto L
	}
}

func _() int {
L:
	print(1)
	if x == nil {
		panic(2)
	} else if x == 1 {
		return 0
	} else if x != 2 {
		panic(3)
	} else {
		goto L
	}
}

// if-else chain missing final else is not okay, even if the
// conditions cover every possible case.

func _() int {
	print(1)
	if x == nil {
		panic(2)
	} else if x != nil {
		panic(3)
	}
} // ERROR "missing return"

func _() int {
	print(1)
	if x == nil {
		panic(2)
	}
} // ERROR "missing return"

func _() int {
	print(1)
	if x == nil {
		panic(2)
	} else if x == 1 {
		return 0
	} else if x != 1 {
		panic(3)
	}
} // ERROR "missing return"


// for { loops that never break are okay.

func _() int {
	print(1)
	for {}
}

func _() int {
	for {
		for {
			break
		}
	}
}

func _() int {
	for {
		L:
		for {
			break L
		}
	}
}

// for { loops that break are not okay.

func _() int {
	print(1)
	for { break }
} // ERROR "missing return"

func _() int {
	for {
		for {
		}
		break
	}
} // ERROR "missing return"

func _() int {
L:
	for {
		for {
			break L
		}
	}
} // ERROR "missing return"

// if there's a condition - even "true" - the loops are no longer syntactically terminating

func _() int {
	print(1)
	for x == nil {}
} // ERROR "missing return"

func _() int {
	for x == nil {
		for {
			break
		}
	}
} // ERROR "missing return"

func _() int {
	for x == nil {
		L:
		for {
			break L
		}
	}	
} // ERROR "missing return"

func _() int {
	print(1)
	for true {}
} // ERROR "missing return"

func _() int {
	for true {
		for {
			break
		}
	}
} // ERROR "missing return"

func _() int {
	for true {
		L:
		for {
			break L
		}
	}
} // ERROR "missing return"

// select in which all cases terminate and none break are okay.

func _() int {
	print(1)
	select{}
}

func _() int {
	print(1)
	select {
	case <-c:
		print(2)
		panic("abc")
	}
}

func _() int {
	print(1)
	select {
	case <-c:
		print(2)
		for{}
	}
}

func _() int {
L:
	print(1)
	select {
	case <-c:
		print(2)
		panic("abc")
	case c <- 1:
		print(2)
		goto L
	}
}

func _() int {
	print(1)
	select {
	case <-c:
		print(2)
		panic("abc")
	default:
		select{}
	}
}

// if any cases don't terminate, the select isn't okay anymore

func _() int {
	print(1)
	select {
	case <-c:
		print(2)
	}
} // ERROR "missing return"

func _() int {
L:
	print(1)
	select {
	case <-c:
		print(2)
		panic("abc")
		goto L
	case c <- 1:
		print(2)
	}
} // ERROR "missing return"


func _() int {
	print(1)
	select {
	case <-c:
		print(2)
		panic("abc")
	default:
		print(2)
	}
} // ERROR "missing return"


// if any breaks refer to the select, the select isn't okay anymore, even if they're dead

func _() int {
	print(1)
	select{ default: break }
} // ERROR "missing return"

func _() int {
	print(1)
	select {
	case <-c:
		print(2)
		panic("abc")
		break
	}
} // ERROR "missing return"

func _() int {
	print(1)
L:
	select {
	case <-c:
		print(2)
		for{ break L }
	}
} // ERROR "missing return"

func _() int {
	print(1)
L:
	select {
	case <-c:
		print(2)
		panic("abc")
	case c <- 1:
		print(2)
		break L
	}
} // ERROR "missing return"

func _() int {
	print(1)
	select {
	case <-c:
		print(1)
		panic("abc")
	default:
		select{}
		break
	}
} // ERROR "missing return"

// switch with default in which all cases terminate is okay

func _() int {
	print(1)
	switch x {
	case 1:
		print(2)
		panic(3)
	default:
		return 4
	}
}

func _() int {
	print(1)
	switch x {
	default:
		return 4
	case 1:
		print(2)
		panic(3)
	}
}

func _() int {
	print(1)
	switch x {
	case 1:
		print(2)
		fallthrough
	default:
		return 4
	}
}

// if no default or some case doesn't terminate, switch is no longer okay

func _() int {
	print(1)
	switch {
	}
} // ERROR "missing return"


func _() int {
	print(1)
	switch x {
	case 1:
		print(2)
		panic(3)
	case 2:
		return 4
	}
} // ERROR "missing return"

func _() int {
	print(1)
	switch x {
	case 2:
		return 4
	case 1:
		print(2)
		panic(3)
	}
} // ERROR "missing return"

func _() int {
	print(1)
	switch x {
	case 1:
		print(2)
		fallthrough
	case 2:
		return 4
	}
} // ERROR "missing return"

func _() int {
	print(1)
	switch x {
	case 1:
		print(2)
		panic(3)
	}
} // ERROR "missing return"

// if any breaks refer to the switch, switch is no longer okay

func _() int {
	print(1)
L:
	switch x {
	case 1:
		print(2)
		panic(3)
		break L
	default:
		return 4
	}
} // ERROR "missing return"

func _() int {
	print(1)
	switch x {
	default:
		return 4
		break
	case 1:
		print(2)
		panic(3)
	}
} // ERROR "missing return"

func _() int {
	print(1)
L:
	switch x {
	case 1:
		print(2)
		for {
			break L
		}
	default:
		return 4
	}
} // ERROR "missing return"

// type switch with default in which all cases terminate is okay

func _() int {
	print(1)
	switch x.(type) {
	case int:
		print(2)
		panic(3)
	default:
		return 4
	}
}

func _() int {
	print(1)
	switch x.(type) {
	default:
		return 4
	case int:
		print(2)
		panic(3)
	}
}

// if no default or some case doesn't terminate, switch is no longer okay

func _() int {
	print(1)
	switch {
	}
} // ERROR "missing return"


func _() int {
	print(1)
	switch x.(type) {
	case int:
		print(2)
		panic(3)
	case float64:
		return 4
	}
} // ERROR "missing return"

func _() int {
	print(1)
	switch x.(type) {
	case float64:
		return 4
	case int:
		print(2)
		panic(3)
	}
} // ERROR "missing return"

func _() int {
	print(1)
	switch x.(type) {
	case int:
		print(2)
		panic(3)
	}
} // ERROR "missing return"

// if any breaks refer to the switch, switch is no longer okay

func _() int {
	print(1)
L:
	switch x.(type) {
	case int:
		print(2)
		panic(3)
		break L
	default:
		return 4
	}
} // ERROR "missing return"

func _() int {
	print(1)
	switch x.(type) {
	default:
		return 4
		break
	case int:
		print(2)
		panic(3)
	}
} // ERROR "missing return"

func _() int {
	print(1)
L:
	switch x.(type) {
	case int:
		print(2)
		for {
			break L
		}
	default:
		return 4
	}
} // ERROR "missing return"

// again, but without the leading print(1).
// testing that everything works when the terminating statement is first.

func _() int {
} // ERROR "missing return"

// return is okay
func _() int {
	return 2
}

// goto is okay
func _() int {
L:
	goto L
}

// panic is okay
func _() int {
	panic(2)
}

// but only builtin panic
func _() int {
	var panic = func(int) {}
	panic(2)
} // ERROR "missing return"

// block ending in terminating statement is okay
func _() int {
	{
		return 2
	}
}

// block ending in terminating statement is okay
func _() int {
L:
	{
		goto L
	}
}

// block ending in terminating statement is okay
func _() int {
	{
		panic(2)
	}
}

// adding more code - even though it is dead - now requires a return

func _() int {
	return 2
	print(3)
} // ERROR "missing return"

func _() int {
L:
	goto L
	print(3)
} // ERROR "missing return"

func _() int {
	panic(2)
	print(3)
} // ERROR "missing return"

func _() int {
	{
		return 2
		print(3)
	}
} // ERROR "missing return"

func _() int {
L:
	{
		goto L
		print(3)
	}
} // ERROR "missing return"

func _() int {
	{
		panic(2)
		print(3)
	}
} // ERROR "missing return"

func _() int {
	{
		return 2
	}
	print(3)
} // ERROR "missing return"

func _() int {
L:
	{
		goto L
	}
	print(3)
} // ERROR "missing return"

func _() int {
	{
		panic(2)
	}
	print(3)
} // ERROR "missing return"

// even an empty dead block triggers the message, because it
// becomes the final statement.

func _() int {
	return 2
	{}
} // ERROR "missing return"

func _() int {
L:
	goto L
	{}
} // ERROR "missing return"

func _() int {
	panic(2)
	{}
} // ERROR "missing return"

func _() int {
	{
		return 2
		{}
	}
} // ERROR "missing return"

func _() int {
L:
	{
		goto L
		{}
	}
} // ERROR "missing return"

func _() int {
	{
		panic(2)
		{}
	}
} // ERROR "missing return"

func _() int {
	{
		return 2
	}
	{}
} // ERROR "missing return"

func _() int {
L:
	{
		goto L
	}
	{}
} // ERROR "missing return"

func _() int {
	{
		panic(2)
	}
	{}
} // ERROR "missing return"

// if-else chain with final else and all terminating is okay

func _() int {
	if x == nil {
		panic(2)
	} else {
		panic(3)
	}
}

func _() int {
L:
	if x == nil {
		panic(2)
	} else {
		goto L
	}
}

func _() int {
L:
	if x == nil {
		panic(2)
	} else if x == 1 {
		return 0
	} else if x != 2 {
		panic(3)
	} else {
		goto L
	}
}

// if-else chain missing final else is not okay, even if the
// conditions cover every possible case.

func _() int {
	if x == nil {
		panic(2)
	} else if x != nil {
		panic(3)
	}
} // ERROR "missing return"

func _() int {
	if x == nil {
		panic(2)
	}
} // ERROR "missing return"

func _() int {
	if x == nil {
		panic(2)
	} else if x == 1 {
		return 0
	} else if x != 1 {
		panic(3)
	}
} // ERROR "missing return"


// for { loops that never break are okay.

func _() int {
	for {}
}

func _() int {
	for {
		for {
			break
		}
	}
}

func _() int {
	for {
		L:
		for {
			break L
		}
	}
}

// for { loops that break are not okay.

func _() int {
	for { break }
} // ERROR "missing return"

func _() int {
	for {
		for {
		}
		break
	}
} // ERROR "missing return"

func _() int {
L:
	for {
		for {
			break L
		}
	}
} // ERROR "missing return"

// if there's a condition - even "true" - the loops are no longer syntactically terminating

func _() int {
	for x == nil {}
} // ERROR "missing return"

func _() int {
	for x == nil {
		for {
			break
		}
	}
} // ERROR "missing return"

func _() int {
	for x == nil {
		L:
		for {
			break L
		}
	}	
} // ERROR "missing return"

func _() int {
	for true {}
} // ERROR "missing return"

func _() int {
	for true {
		for {
			break
		}
	}
} // ERROR "missing return"

func _() int {
	for true {
		L:
		for {
			break L
		}
	}
} // ERROR "missing return"

// select in which all cases terminate and none break are okay.

func _() int {
	select{}
}

func _() int {
	select {
	case <-c:
		print(2)
		panic("abc")
	}
}

func _() int {
	select {
	case <-c:
		print(2)
		for{}
	}
}

func _() int {
L:
	select {
	case <-c:
		print(2)
		panic("abc")
	case c <- 1:
		print(2)
		goto L
	}
}

func _() int {
	select {
	case <-c:
		print(2)
		panic("abc")
	default:
		select{}
	}
}

// if any cases don't terminate, the select isn't okay anymore

func _() int {
	select {
	case <-c:
		print(2)
	}
} // ERROR "missing return"

func _() int {
L:
	select {
	case <-c:
		print(2)
		panic("abc")
		goto L
	case c <- 1:
		print(2)
	}
} // ERROR "missing return"


func _() int {
	select {
	case <-c:
		print(2)
		panic("abc")
	default:
		print(2)
	}
} // ERROR "missing return"


// if any breaks refer to the select, the select isn't okay anymore, even if they're dead

func _() int {
	select{ default: break }
} // ERROR "missing return"

func _() int {
	select {
	case <-c:
		print(2)
		panic("abc")
		break
	}
} // ERROR "missing return"

func _() int {
L:
	select {
	case <-c:
		print(2)
		for{ break L }
	}
} // ERROR "missing return"

func _() int {
L:
	select {
	case <-c:
		print(2)
		panic("abc")
	case c <- 1:
		print(2)
		break L
	}
} // ERROR "missing return"

func _() int {
	select {
	case <-c:
		panic("abc")
	default:
		select{}
		break
	}
} // ERROR "missing return"

// switch with default in which all cases terminate is okay

func _() int {
	switch x {
	case 1:
		print(2)
		panic(3)
	default:
		return 4
	}
}

func _() int {
	switch x {
	default:
		return 4
	case 1:
		print(2)
		panic(3)
	}
}

func _() int {
	switch x {
	case 1:
		print(2)
		fallthrough
	default:
		return 4
	}
}

// if no default or some case doesn't terminate, switch is no longer okay

func _() int {
	switch {
	}
} // ERROR "missing return"


func _() int {
	switch x {
	case 1:
		print(2)
		panic(3)
	case 2:
		return 4
	}
} // ERROR "missing return"

func _() int {
	switch x {
	case 2:
		return 4
	case 1:
		print(2)
		panic(3)
	}
} // ERROR "missing return"

func _() int {
	switch x {
	case 1:
		print(2)
		fallthrough
	case 2:
		return 4
	}
} // ERROR "missing return"

func _() int {
	switch x {
	case 1:
		print(2)
		panic(3)
	}
} // ERROR "missing return"

// if any breaks refer to the switch, switch is no longer okay

func _() int {
L:
	switch x {
	case 1:
		print(2)
		panic(3)
		break L
	default:
		return 4
	}
} // ERROR "missing return"

func _() int {
	switch x {
	default:
		return 4
		break
	case 1:
		print(2)
		panic(3)
	}
} // ERROR "missing return"

func _() int {
L:
	switch x {
	case 1:
		print(2)
		for {
			break L
		}
	default:
		return 4
	}
} // ERROR "missing return"

// type switch with default in which all cases terminate is okay

func _() int {
	switch x.(type) {
	case int:
		print(2)
		panic(3)
	default:
		return 4
	}
}

func _() int {
	switch x.(type) {
	default:
		return 4
	case int:
		print(2)
		panic(3)
	}
}

// if no default or some case doesn't terminate, switch is no longer okay

func _() int {
	switch {
	}
} // ERROR "missing return"


func _() int {
	switch x.(type) {
	case int:
		print(2)
		panic(3)
	case float64:
		return 4
	}
} // ERROR "missing return"

func _() int {
	switch x.(type) {
	case float64:
		return 4
	case int:
		print(2)
		panic(3)
	}
} // ERROR "missing return"

func _() int {
	switch x.(type) {
	case int:
		print(2)
		panic(3)
	}
} // ERROR "missing return"

// if any breaks refer to the switch, switch is no longer okay

func _() int {
L:
	switch x.(type) {
	case int:
		print(2)
		panic(3)
		break L
	default:
		return 4
	}
} // ERROR "missing return"

func _() int {
	switch x.(type) {
	default:
		return 4
		break
	case int:
		print(2)
		panic(3)
	}
} // ERROR "missing return"

func _() int {
L:
	switch x.(type) {
	case int:
		print(2)
		for {
			break L
		}
	default:
		return 4
	}
} // ERROR "missing return"

func _() int {
	switch x.(type) {
	default:
		return 4
	case int, float64:
		print(2)
		panic(3)
	}
}

// again, with func literals

var _ = func() int {
} // ERROR "missing return"

var _ = func() int {
	print(1)
} // ERROR "missing return"

// return is okay
var _ = func() int {
	print(1)
	return 2
}

// goto is okay
var _ = func() int {
L:
	print(1)
	goto L
}

// panic is okay
var _ = func() int {
	print(1)
	panic(2)
}

// but only builtin panic
var _ = func() int {
	var panic = func(int) {}
	print(1)
	panic(2)
} // ERROR "missing return"

// block ending in terminating statement is okay
var _ = func() int {
	{
		print(1)
		return 2
	}
}

// block ending in terminating statement is okay
var _ = func() int {
L:
	{
		print(1)
		goto L
	}
}

// block ending in terminating statement is okay
var _ = func() int {
	print(1)
	{
		panic(2)
	}
}

// adding more code - even though it is dead - now requires a return

var _ = func() int {
	print(1)
	return 2
	print(3)
} // ERROR "missing return"

var _ = func() int {
L:
	print(1)
	goto L
	print(3)
} // ERROR "missing return"

var _ = func() int {
	print(1)
	panic(2)
	print(3)
} // ERROR "missing return"

var _ = func() int {
	{
		print(1)
		return 2
		print(3)
	}
} // ERROR "missing return"

var _ = func() int {
L:
	{
		print(1)
		goto L
		print(3)
	}
} // ERROR "missing return"

var _ = func() int {
	print(1)
	{
		panic(2)
		print(3)
	}
} // ERROR "missing return"

var _ = func() int {
	{
		print(1)
		return 2
	}
	print(3)
} // ERROR "missing return"

var _ = func() int {
L:
	{
		print(1)
		goto L
	}
	print(3)
} // ERROR "missing return"

var _ = func() int {
	print(1)
	{
		panic(2)
	}
	print(3)
} // ERROR "missing return"

// even an empty dead block triggers the message, because it
// becomes the final statement.

var _ = func() int {
	print(1)
	return 2
	{}
} // ERROR "missing return"

var _ = func() int {
L:
	print(1)
	goto L
	{}
} // ERROR "missing return"

var _ = func() int {
	print(1)
	panic(2)
	{}
} // ERROR "missing return"

var _ = func() int {
	{
		print(1)
		return 2
		{}
	}
} // ERROR "missing return"

var _ = func() int {
L:
	{
		print(1)
		goto L
		{}
	}
} // ERROR "missing return"

var _ = func() int {
	print(1)
	{
		panic(2)
		{}
	}
} // ERROR "missing return"

var _ = func() int {
	{
		print(1)
		return 2
	}
	{}
} // ERROR "missing return"

var _ = func() int {
L:
	{
		print(1)
		goto L
	}
	{}
} // ERROR "missing return"

var _ = func() int {
	print(1)
	{
		panic(2)
	}
	{}
} // ERROR "missing return"

// if-else chain with final else and all terminating is okay

var _ = func() int {
	print(1)
	if x == nil {
		panic(2)
	} else {
		panic(3)
	}
}

var _ = func() int {
L:
	print(1)
	if x == nil {
		panic(2)
	} else {
		goto L
	}
}

var _ = func() int {
L:
	print(1)
	if x == nil {
		panic(2)
	} else if x == 1 {
		return 0
	} else if x != 2 {
		panic(3)
	} else {
		goto L
	}
}

// if-else chain missing final else is not okay, even if the
// conditions cover every possible case.

var _ = func() int {
	print(1)
	if x == nil {
		panic(2)
	} else if x != nil {
		panic(3)
	}
} // ERROR "missing return"

var _ = func() int {
	print(1)
	if x == nil {
		panic(2)
	}
} // ERROR "missing return"

var _ = func() int {
	print(1)
	if x == nil {
		panic(2)
	} else if x == 1 {
		return 0
	} else if x != 1 {
		panic(3)
	}
} // ERROR "missing return"


// for { loops that never break are okay.

var _ = func() int {
	print(1)
	for {}
}

var _ = func() int {
	for {
		for {
			break
		}
	}
}

var _ = func() int {
	for {
		L:
		for {
			break L
		}
	}
}

// for { loops that break are not okay.

var _ = func() int {
	print(1)
	for { break }
} // ERROR "missing return"

var _ = func() int {
	for {
		for {
		}
		break
	}
} // ERROR "missing return"

var _ = func() int {
L:
	for {
		for {
			break L
		}
	}
} // ERROR "missing return"

// if there's a condition - even "true" - the loops are no longer syntactically terminating

var _ = func() int {
	print(1)
	for x == nil {}
} // ERROR "missing return"

var _ = func() int {
	for x == nil {
		for {
			break
		}
	}
} // ERROR "missing return"

var _ = func() int {
	for x == nil {
		L:
		for {
			break L
		}
	}	
} // ERROR "missing return"

var _ = func() int {
	print(1)
	for true {}
} // ERROR "missing return"

var _ = func() int {
	for true {
		for {
			break
		}
	}
} // ERROR "missing return"

var _ = func() int {
	for true {
		L:
		for {
			break L
		}
	}
} // ERROR "missing return"

// select in which all cases terminate and none break are okay.

var _ = func() int {
	print(1)
	select{}
}

var _ = func() int {
	print(1)
	select {
	case <-c:
		print(2)
		panic("abc")
	}
}

var _ = func() int {
	print(1)
	select {
	case <-c:
		print(2)
		for{}
	}
}

var _ = func() int {
L:
	print(1)
	select {
	case <-c:
		print(2)
		panic("abc")
	case c <- 1:
		print(2)
		goto L
	}
}

var _ = func() int {
	print(1)
	select {
	case <-c:
		print(2)
		panic("abc")
	default:
		select{}
	}
}

// if any cases don't terminate, the select isn't okay anymore

var _ = func() int {
	print(1)
	select {
	case <-c:
		print(2)
	}
} // ERROR "missing return"

var _ = func() int {
L:
	print(1)
	select {
	case <-c:
		print(2)
		panic("abc")
		goto L
	case c <- 1:
		print(2)
	}
} // ERROR "missing return"


var _ = func() int {
	print(1)
	select {
	case <-c:
		print(2)
		panic("abc")
	default:
		print(2)
	}
} // ERROR "missing return"


// if any breaks refer to the select, the select isn't okay anymore, even if they're dead

var _ = func() int {
	print(1)
	select{ default: break }
} // ERROR "missing return"

var _ = func() int {
	print(1)
	select {
	case <-c:
		print(2)
		panic("abc")
		break
	}
} // ERROR "missing return"

var _ = func() int {
	print(1)
L:
	select {
	case <-c:
		print(2)
		for{ break L }
	}
} // ERROR "missing return"

var _ = func() int {
	print(1)
L:
	select {
	case <-c:
		print(2)
		panic("abc")
	case c <- 1:
		print(2)
		break L
	}
} // ERROR "missing return"

var _ = func() int {
	print(1)
	select {
	case <-c:
		print(1)
		panic("abc")
	default:
		select{}
		break
	}
} // ERROR "missing return"

// switch with default in which all cases terminate is okay

var _ = func() int {
	print(1)
	switch x {
	case 1:
		print(2)
		panic(3)
	default:
		return 4
	}
}

var _ = func() int {
	print(1)
	switch x {
	default:
		return 4
	case 1:
		print(2)
		panic(3)
	}
}

var _ = func() int {
	print(1)
	switch x {
	case 1:
		print(2)
		fallthrough
	default:
		return 4
	}
}

// if no default or some case doesn't terminate, switch is no longer okay

var _ = func() int {
	print(1)
	switch {
	}
} // ERROR "missing return"


var _ = func() int {
	print(1)
	switch x {
	case 1:
		print(2)
		panic(3)
	case 2:
		return 4
	}
} // ERROR "missing return"

var _ = func() int {
	print(1)
	switch x {
	case 2:
		return 4
	case 1:
		print(2)
		panic(3)
	}
} // ERROR "missing return"

var _ = func() int {
	print(1)
	switch x {
	case 1:
		print(2)
		fallthrough
	case 2:
		return 4
	}
} // ERROR "missing return"

var _ = func() int {
	print(1)
	switch x {
	case 1:
		print(2)
		panic(3)
	}
} // ERROR "missing return"

// if any breaks refer to the switch, switch is no longer okay

var _ = func() int {
	print(1)
L:
	switch x {
	case 1:
		print(2)
		panic(3)
		break L
	default:
		return 4
	}
} // ERROR "missing return"

var _ = func() int {
	print(1)
	switch x {
	default:
		return 4
		break
	case 1:
		print(2)
		panic(3)
	}
} // ERROR "missing return"

var _ = func() int {
	print(1)
L:
	switch x {
	case 1:
		print(2)
		for {
			break L
		}
	default:
		return 4
	}
} // ERROR "missing return"

// type switch with default in which all cases terminate is okay

var _ = func() int {
	print(1)
	switch x.(type) {
	case int:
		print(2)
		panic(3)
	default:
		return 4
	}
}

var _ = func() int {
	print(1)
	switch x.(type) {
	default:
		return 4
	case int:
		print(2)
		panic(3)
	}
}

// if no default or some case doesn't terminate, switch is no longer okay

var _ = func() int {
	print(1)
	switch {
	}
} // ERROR "missing return"


var _ = func() int {
	print(1)
	switch x.(type) {
	case int:
		print(2)
		panic(3)
	case float64:
		return 4
	}
} // ERROR "missing return"

var _ = func() int {
	print(1)
	switch x.(type) {
	case float64:
		return 4
	case int:
		print(2)
		panic(3)
	}
} // ERROR "missing return"

var _ = func() int {
	print(1)
	switch x.(type) {
	case int:
		print(2)
		panic(3)
	}
} // ERROR "missing return"

// if any breaks refer to the switch, switch is no longer okay

var _ = func() int {
	print(1)
L:
	switch x.(type) {
	case int:
		print(2)
		panic(3)
		break L
	default:
		return 4
	}
} // ERROR "missing return"

var _ = func() int {
	print(1)
	switch x.(type) {
	default:
		return 4
		break
	case int:
		print(2)
		panic(3)
	}
} // ERROR "missing return"

var _ = func() int {
	print(1)
L:
	switch x.(type) {
	case int:
		print(2)
		for {
			break L
		}
	default:
		return 4
	}
} // ERROR "missing return"

// again, but without the leading print(1).
// testing that everything works when the terminating statement is first.

var _ = func() int {
} // ERROR "missing return"

// return is okay
var _ = func() int {
	return 2
}

// goto is okay
var _ = func() int {
L:
	goto L
}

// panic is okay
var _ = func() int {
	panic(2)
}

// but only builtin panic
var _ = func() int {
	var panic = func(int) {}
	panic(2)
} // ERROR "missing return"

// block ending in terminating statement is okay
var _ = func() int {
	{
		return 2
	}
}

// block ending in terminating statement is okay
var _ = func() int {
L:
	{
		goto L
	}
}

// block ending in terminating statement is okay
var _ = func() int {
	{
		panic(2)
	}
}

// adding more code - even though it is dead - now requires a return

var _ = func() int {
	return 2
	print(3)
} // ERROR "missing return"

var _ = func() int {
L:
	goto L
	print(3)
} // ERROR "missing return"

var _ = func() int {
	panic(2)
	print(3)
} // ERROR "missing return"

var _ = func() int {
	{
		return 2
		print(3)
	}
} // ERROR "missing return"

var _ = func() int {
L:
	{
		goto L
		print(3)
	}
} // ERROR "missing return"

var _ = func() int {
	{
		panic(2)
		print(3)
	}
} // ERROR "missing return"

var _ = func() int {
	{
		return 2
	}
	print(3)
} // ERROR "missing return"

var _ = func() int {
L:
	{
		goto L
	}
	print(3)
} // ERROR "missing return"

var _ = func() int {
	{
		panic(2)
	}
	print(3)
} // ERROR "missing return"

// even an empty dead block triggers the message, because it
// becomes the final statement.

var _ = func() int {
	return 2
	{}
} // ERROR "missing return"

var _ = func() int {
L:
	goto L
	{}
} // ERROR "missing return"

var _ = func() int {
	panic(2)
	{}
} // ERROR "missing return"

var _ = func() int {
	{
		return 2
		{}
	}
} // ERROR "missing return"

var _ = func() int {
L:
	{
		goto L
		{}
	}
} // ERROR "missing return"

var _ = func() int {
	{
		panic(2)
		{}
	}
} // ERROR "missing return"

var _ = func() int {
	{
		return 2
	}
	{}
} // ERROR "missing return"

var _ = func() int {
L:
	{
		goto L
	}
	{}
} // ERROR "missing return"

var _ = func() int {
	{
		panic(2)
	}
	{}
} // ERROR "missing return"

// if-else chain with final else and all terminating is okay

var _ = func() int {
	if x == nil {
		panic(2)
	} else {
		panic(3)
	}
}

var _ = func() int {
L:
	if x == nil {
		panic(2)
	} else {
		goto L
	}
}

var _ = func() int {
L:
	if x == nil {
		panic(2)
	} else if x == 1 {
		return 0
	} else if x != 2 {
		panic(3)
	} else {
		goto L
	}
}

// if-else chain missing final else is not okay, even if the
// conditions cover every possible case.

var _ = func() int {
	if x == nil {
		panic(2)
	} else if x != nil {
		panic(3)
	}
} // ERROR "missing return"

var _ = func() int {
	if x == nil {
		panic(2)
	}
} // ERROR "missing return"

var _ = func() int {
	if x == nil {
		panic(2)
	} else if x == 1 {
		return 0
	} else if x != 1 {
		panic(3)
	}
} // ERROR "missing return"


// for { loops that never break are okay.

var _ = func() int {
	for {}
}

var _ = func() int {
	for {
		for {
			break
		}
	}
}

var _ = func() int {
	for {
		L:
		for {
			break L
		}
	}
}

// for { loops that break are not okay.

var _ = func() int {
	for { break }
} // ERROR "missing return"

var _ = func() int {
	for {
		for {
		}
		break
	}
} // ERROR "missing return"

var _ = func() int {
L:
	for {
		for {
			break L
		}
	}
} // ERROR "missing return"

// if there's a condition - even "true" - the loops are no longer syntactically terminating

var _ = func() int {
	for x == nil {}
} // ERROR "missing return"

var _ = func() int {
	for x == nil {
		for {
			break
		}
	}
} // ERROR "missing return"

var _ = func() int {
	for x == nil {
		L:
		for {
			break L
		}
	}	
} // ERROR "missing return"

var _ = func() int {
	for true {}
} // ERROR "missing return"

var _ = func() int {
	for true {
		for {
			break
		}
	}
} // ERROR "missing return"

var _ = func() int {
	for true {
		L:
		for {
			break L
		}
	}
} // ERROR "missing return"

// select in which all cases terminate and none break are okay.

var _ = func() int {
	select{}
}

var _ = func() int {
	select {
	case <-c:
		print(2)
		panic("abc")
	}
}

var _ = func() int {
	select {
	case <-c:
		print(2)
		for{}
	}
}

var _ = func() int {
L:
	select {
	case <-c:
		print(2)
		panic("abc")
	case c <- 1:
		print(2)
		goto L
	}
}

var _ = func() int {
	select {
	case <-c:
		print(2)
		panic("abc")
	default:
		select{}
	}
}

// if any cases don't terminate, the select isn't okay anymore

var _ = func() int {
	select {
	case <-c:
		print(2)
	}
} // ERROR "missing return"

var _ = func() int {
L:
	select {
	case <-c:
		print(2)
		panic("abc")
		goto L
	case c <- 1:
		print(2)
	}
} // ERROR "missing return"


var _ = func() int {
	select {
	case <-c:
		print(2)
		panic("abc")
	default:
		print(2)
	}
} // ERROR "missing return"


// if any breaks refer to the select, the select isn't okay anymore, even if they're dead

var _ = func() int {
	select{ default: break }
} // ERROR "missing return"

var _ = func() int {
	select {
	case <-c:
		print(2)
		panic("abc")
		break
	}
} // ERROR "missing return"

var _ = func() int {
L:
	select {
	case <-c:
		print(2)
		for{ break L }
	}
} // ERROR "missing return"

var _ = func() int {
L:
	select {
	case <-c:
		print(2)
		panic("abc")
	case c <- 1:
		print(2)
		break L
	}
} // ERROR "missing return"

var _ = func() int {
	select {
	case <-c:
		panic("abc")
	default:
		select{}
		break
	}
} // ERROR "missing return"

// switch with default in which all cases terminate is okay

var _ = func() int {
	switch x {
	case 1:
		print(2)
		panic(3)
	default:
		return 4
	}
}

var _ = func() int {
	switch x {
	default:
		return 4
	case 1:
		print(2)
		panic(3)
	}
}

var _ = func() int {
	switch x {
	case 1:
		print(2)
		fallthrough
	default:
		return 4
	}
}

// if no default or some case doesn't terminate, switch is no longer okay

var _ = func() int {
	switch {
	}
} // ERROR "missing return"


var _ = func() int {
	switch x {
	case 1:
		print(2)
		panic(3)
	case 2:
		return 4
	}
} // ERROR "missing return"

var _ = func() int {
	switch x {
	case 2:
		return 4
	case 1:
		print(2)
		panic(3)
	}
} // ERROR "missing return"

var _ = func() int {
	switch x {
	case 1:
		print(2)
		fallthrough
	case 2:
		return 4
	}
} // ERROR "missing return"

var _ = func() int {
	switch x {
	case 1:
		print(2)
		panic(3)
	}
} // ERROR "missing return"

// if any breaks refer to the switch, switch is no longer okay

var _ = func() int {
L:
	switch x {
	case 1:
		print(2)
		panic(3)
		break L
	default:
		return 4
	}
} // ERROR "missing return"

var _ = func() int {
	switch x {
	default:
		return 4
		break
	case 1:
		print(2)
		panic(3)
	}
} // ERROR "missing return"

var _ = func() int {
L:
	switch x {
	case 1:
		print(2)
		for {
			break L
		}
	default:
		return 4
	}
} // ERROR "missing return"

// type switch with default in which all cases terminate is okay

var _ = func() int {
	switch x.(type) {
	case int:
		print(2)
		panic(3)
	default:
		return 4
	}
}

var _ = func() int {
	switch x.(type) {
	default:
		return 4
	case int:
		print(2)
		panic(3)
	}
}

// if no default or some case doesn't terminate, switch is no longer okay

var _ = func() int {
	switch {
	}
} // ERROR "missing return"


var _ = func() int {
	switch x.(type) {
	case int:
		print(2)
		panic(3)
	case float64:
		return 4
	}
} // ERROR "missing return"

var _ = func() int {
	switch x.(type) {
	case float64:
		return 4
	case int:
		print(2)
		panic(3)
	}
} // ERROR "missing return"

var _ = func() int {
	switch x.(type) {
	case int:
		print(2)
		panic(3)
	}
} // ERROR "missing return"

// if any breaks refer to the switch, switch is no longer okay

var _ = func() int {
L:
	switch x.(type) {
	case int:
		print(2)
		panic(3)
		break L
	default:
		return 4
	}
} // ERROR "missing return"

var _ = func() int {
	switch x.(type) {
	default:
		return 4
		break
	case int:
		print(2)
		panic(3)
	}
} // ERROR "missing return"

var _ = func() int {
L:
	switch x.(type) {
	case int:
		print(2)
		for {
			break L
		}
	default:
		return 4
	}
} // ERROR "missing return"

var _ = func() int {
	switch x.(type) {
	default:
		return 4
	case int, float64:
		print(2)
		panic(3)
	}
}

/**/
```