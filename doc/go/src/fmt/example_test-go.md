Response:
Let's break down the thought process to answer the user's request about the `example_test.go` file.

**1. Understanding the Goal:**

The user wants to understand the functionality demonstrated in the provided Go code. They've specified several aspects to focus on:

* **Overall functionality:** What does this code *do*?
* **Underlying Go feature:**  What part of Go is being exemplified?
* **Code examples:** Demonstrate the functionality with simple Go code snippets.
* **Input/Output:** For code examples, provide expected inputs and outputs.
* **Command-line arguments:** Are there any related to command-line interaction?
* **Common mistakes:**  Are there pitfalls users should avoid?
* **Language:**  The answer should be in Chinese.

**2. Initial Scan and Categorization:**

The first step is to quickly read through the code and identify the distinct `Example` functions. The naming convention `Example<FunctionName>` strongly suggests that each function demonstrates the usage of a corresponding function from the `fmt` package.

I can mentally group these examples:

* **Error Formatting:** `ExampleErrorf`
* **Formatted Input (Scanning):** `ExampleFscanf`, `ExampleFscanln`, `ExampleSscanf`
* **Basic Printing:** `ExamplePrint`, `ExamplePrintln`, `ExamplePrintf`
* **String Formatting (Returning Strings):** `ExampleSprint`, `ExampleSprintln`, `ExampleSprintf`
* **Formatted Output to Writers:** `ExampleFprint`, `ExampleFprintln`, `ExampleFprintf`
* **Comparison of Printing Functions:** `Example_printers`
* **Detailed Formatting Options:** `Example_formats`

**3. Analyzing Each Example Function:**

For each `Example` function, I need to:

* **Identify the `fmt` function being demonstrated.** This is usually evident from the function name (e.g., `ExampleErrorf` uses `fmt.Errorf`).
* **Understand the core purpose of that `fmt` function.** (e.g., `fmt.Errorf` creates formatted error strings).
* **Analyze the code within the `Example` function.** How is the `fmt` function being called? What are the inputs? What is the expected output based on the `// Output:` comment?
* **Consider if there are any special behaviors or nuances.** (e.g., `Println` adds spaces, `Print` doesn't always, `Printf` is format-string controlled).

**4. Synthesizing the Functionality and Go Feature:**

After analyzing the individual examples, I can summarize the overall purpose of the file. It's clearly showcasing the functionalities of the `fmt` package in Go, focusing on formatted input and output.

**5. Creating Go Code Examples (if needed):**

While the provided code *are* examples, the prompt asks for *additional* examples to illustrate the underlying feature. For instance, to demonstrate the format specifiers in `Printf`,  I can create a small, self-contained program.

**6. Determining Inputs and Outputs:**

The `// Output:` comments in the original code serve as the "expected output."  For any additional code examples I create, I need to determine and include the corresponding output. This often involves running the code mentally or actually executing it.

**7. Addressing Command-Line Arguments:**

By examining the `fmt` package documentation or from my knowledge of Go, I know that the functions demonstrated in this file generally don't directly handle command-line arguments. They deal with input from `io.Reader` or strings and output to `io.Writer` or strings. Therefore, I can conclude that no specific command-line argument processing is being demonstrated.

**8. Identifying Common Mistakes:**

This requires understanding common user errors when working with formatted I/O in Go:

* **Mismatched format specifiers and arguments in `Printf`:**  This is a classic error leading to unexpected output or even panics.
* **Misunderstanding the differences between `Print`, `Println`, and `Printf`:** New users often don't grasp the nuances of spacing and newlines.
* **Forgetting to handle errors from input functions like `Fscanf`:** This can lead to unexpected program behavior.

**9. Structuring the Answer in Chinese:**

Finally, I need to organize the information logically and present it clearly in Chinese. This involves:

* **Starting with a general overview.**
* **Detailing the functionality of each example group.**
* **Providing specific Go code examples (as requested).**
* **Explaining input and output for those examples.**
* **Addressing command-line arguments (or the lack thereof).**
* **Highlighting common mistakes.**
* **Using clear and concise language.**

**Self-Correction/Refinement during the Process:**

* **Initial thought:**  Maybe I should explain the `io` package as well. **Correction:** The focus is on `fmt`, so I'll only mention `io.Reader` and `io.Writer` briefly in context.
* **Initial thought:** Should I provide *extensive* examples for every format specifier? **Correction:** The existing `Example_formats` is quite comprehensive, so I'll just provide a small illustrative example.
* **Initial thought:**  Should I translate the variable names from the original code? **Correction:** It's better to keep the original variable names for clarity when referencing the provided code.

By following these steps, including analysis, synthesis, and refinement, I can arrive at a comprehensive and accurate answer in Chinese that addresses all aspects of the user's request.
这段 Go 语言代码文件 `example_test.go` 是 `fmt` 标准库的一部分，专门用于展示 `fmt` 包中各种格式化输入输出函数的使用方法。它通过一系列以 `Example` 开头的函数，提供了清晰的示例代码和预期的输出结果，方便用户理解和学习 `fmt` 包的功能。

以下是它所展示的 `fmt` 包的主要功能：

**1. 格式化错误信息 (Errorf):**

* **功能:**  `fmt.Errorf` 函数允许使用格式化字符串来创建包含变量信息的错误消息。这使得错误信息更加清晰和具有描述性。
* **Go 代码示例:**
```go
package main

import "fmt"

func main() {
	name := "Alice"
	age := 30
	err := fmt.Errorf("用户信息：姓名 %q，年龄 %d", name, age)
	fmt.Println(err)
}
```
* **假设输入:** `name = "Alice"`, `age = 30`
* **预期输出:** `用户信息：姓名 "Alice"，年龄 30`

**2. 格式化输入 (Fscanf, Fscanln, Sscanf):**

* **功能:** 这些函数用于从不同的来源（`io.Reader` 或字符串）按照指定的格式读取数据，并将解析后的值存储到提供的变量中。
    * `Fscanf`: 从 `io.Reader` 中根据格式字符串读取数据。
    * `Fscanln`: 从 `io.Reader` 中读取一行，然后根据格式字符串解析数据。
    * `Sscanf`: 从字符串中根据格式字符串解析数据。
* **Go 代码示例 (Sscanf):**
```go
package main

import "fmt"

func main() {
	var city string
	var population int
	n, err := fmt.Sscanf("北京人口 2154万", "%s人口 %d万", &city, &population)
	if err != nil {
		fmt.Println("解析错误:", err)
		return
	}
	fmt.Printf("解析到 %d 个值: 城市=%s, 人口=%d\n", n, city, population)
}
```
* **假设输入:** 字符串 "北京人口 2154万"
* **预期输出:** `解析到 2 个值: 城市=北京, 人口=2154`

**3. 基本输出 (Print, Println, Printf):**

* **功能:** 这些是最基本的输出函数，用于将数据输出到标准输出 (通常是终端)。
    * `Print`:  按原样打印参数，如果参数之间不是字符串，会添加空格。不会自动添加换行符。
    * `Println`: 打印参数，并在参数之间添加空格，最后添加换行符。
    * `Printf`: 根据格式字符串格式化参数并输出。
* **Go 代码示例 (Printf):**
```go
package main

import "fmt"

func main() {
	product := "电脑"
	price := 5999.99
	fmt.Printf("产品：%s，价格：%.2f 元\n", product, price)
}
```
* **假设输入:** `product = "电脑"`, `price = 5999.99`
* **预期输出:** `产品：电脑，价格：5999.99 元`

**4. 格式化字符串 (Sprint, Sprintln, Sprintf):**

* **功能:** 这些函数的功能与 `Print`, `Println`, `Printf` 类似，但它们不是将结果输出到标准输出，而是将格式化后的字符串作为返回值返回。
* **Go 代码示例 (Sprintf):**
```go
package main

import "fmt"

func main() {
	name := "Bob"
	score := 95
	message := fmt.Sprintf("学生 %s 的成绩是 %d 分。", name, score)
	fmt.Println(message)
}
```
* **假设输入:** `name = "Bob"`, `score = 95`
* **预期输出:** `学生 Bob 的成绩是 95 分。`

**5. 格式化输出到 `io.Writer` (Fprint, Fprintln, Fprintf):**

* **功能:** 这些函数允许将格式化后的数据输出到任何实现了 `io.Writer` 接口的对象，例如文件、网络连接等。
    * `Fprint`: 将参数按原样写入 `io.Writer`。
    * `Fprintln`: 将参数写入 `io.Writer`，并在参数之间添加空格，最后添加换行符。
    * `Fprintf`: 根据格式字符串格式化参数并写入 `io.Writer`。
* **Go 代码示例 (Fprintf):**
```go
package main

import (
	"fmt"
	"os"
)

func main() {
	file, err := os.Create("output.txt")
	if err != nil {
		fmt.Println("创建文件失败:", err)
		return
	}
	defer file.Close()

	count := 10
	FprintfCount, err := fmt.Fprintf(file, "总共有 %d 个项目。\n", count)
	if err != nil {
		fmt.Println("写入文件失败:", err)
		return
	}
	fmt.Printf("写入了 %d 个字节到文件。\n", FprintfCount)
}
```
* **假设执行该代码:** 会创建一个名为 `output.txt` 的文件。
* **`output.txt` 的内容:** `总共有 10 个项目。\n`
* **标准输出:** `写入了 17 个字节到文件。\n` (字节数可能因环境而异)

**6. 格式化动词 (Verbs) 的详细演示:**

* `Example_formats` 函数详细展示了 `Printf`, `Sprintf`, `Fprintf` 中各种格式化动词（例如 `%d`, `%s`, `%v`, `%T`, `%f` 等）的用法，以及如何使用标志 (flags) 和宽度/精度来控制输出格式。

**关于命令行参数的处理：**

这段代码本身并不直接处理命令行参数。它专注于演示 `fmt` 包的格式化输入输出功能。命令行参数的处理通常由 `os` 包的 `Args` 变量来完成，或者使用 `flag` 标准库进行更复杂的解析。

**使用者易犯错的点：**

1. **`Printf` 的格式字符串与参数不匹配:** 这是最常见的错误。如果格式字符串中的动词数量或类型与提供的参数不一致，会导致意想不到的输出，甚至程序崩溃。
   * **示例:**
     ```go
     package main

     import "fmt"

     func main() {
         name := "Charlie"
         age := 25
         // 错误：格式字符串期望一个整数，但传递的是字符串
         fmt.Printf("年龄：%d\n", name)
         // 错误：格式字符串期望两个参数，但只传递了一个
         fmt.Printf("姓名：%s，年龄：%d\n", name)
     }
     ```
     * **可能输出或错误:**  程序可能会输出不正确的值，或者在运行时因为类型不匹配而发生 panic。

2. **混淆 `Print`, `Println`, `Printf` 的行为:**  新手容易忘记 `Println` 会自动添加空格和换行符，而 `Print` 不会。`Printf` 则完全由格式字符串控制。

3. **忽略输入函数的错误:** `Fscanf`, `Fscanln`, `Sscanf` 在解析失败时会返回错误。忽略这些错误可能导致程序逻辑错误。

4. **对浮点数的精度控制不当:**  在使用 `%f` 格式化浮点数时，如果不指定精度，可能会输出很多位小数。需要使用类似 `%.2f` 的格式来控制小数位数。

总而言之，`go/src/fmt/example_test.go` 是学习和理解 Go 语言 `fmt` 包功能的绝佳资源。它通过清晰的示例代码展示了各种格式化输入输出函数的使用方法，是掌握 Go 语言格式化技巧的重要参考。

### 提示词
```
这是路径为go/src/fmt/example_test.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
```

### 源代码
```go
// Copyright 2017 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package fmt_test

import (
	"fmt"
	"io"
	"math"
	"os"
	"strings"
	"time"
)

// The Errorf function lets us use formatting features
// to create descriptive error messages.
func ExampleErrorf() {
	const name, id = "bueller", 17
	err := fmt.Errorf("user %q (id %d) not found", name, id)
	fmt.Println(err.Error())

	// Output: user "bueller" (id 17) not found
}

func ExampleFscanf() {
	var (
		i int
		b bool
		s string
	)
	r := strings.NewReader("5 true gophers")
	n, err := fmt.Fscanf(r, "%d %t %s", &i, &b, &s)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Fscanf: %v\n", err)
	}
	fmt.Println(i, b, s)
	fmt.Println(n)
	// Output:
	// 5 true gophers
	// 3
}

func ExampleFscanln() {
	s := `dmr 1771 1.61803398875
	ken 271828 3.14159`
	r := strings.NewReader(s)
	var a string
	var b int
	var c float64
	for {
		n, err := fmt.Fscanln(r, &a, &b, &c)
		if err == io.EOF {
			break
		}
		if err != nil {
			panic(err)
		}
		fmt.Printf("%d: %s, %d, %f\n", n, a, b, c)
	}
	// Output:
	// 3: dmr, 1771, 1.618034
	// 3: ken, 271828, 3.141590
}

func ExampleSscanf() {
	var name string
	var age int
	n, err := fmt.Sscanf("Kim is 22 years old", "%s is %d years old", &name, &age)
	if err != nil {
		panic(err)
	}
	fmt.Printf("%d: %s, %d\n", n, name, age)

	// Output:
	// 2: Kim, 22
}

func ExamplePrint() {
	const name, age = "Kim", 22
	fmt.Print(name, " is ", age, " years old.\n")

	// It is conventional not to worry about any
	// error returned by Print.

	// Output:
	// Kim is 22 years old.
}

func ExamplePrintln() {
	const name, age = "Kim", 22
	fmt.Println(name, "is", age, "years old.")

	// It is conventional not to worry about any
	// error returned by Println.

	// Output:
	// Kim is 22 years old.
}

func ExamplePrintf() {
	const name, age = "Kim", 22
	fmt.Printf("%s is %d years old.\n", name, age)

	// It is conventional not to worry about any
	// error returned by Printf.

	// Output:
	// Kim is 22 years old.
}

func ExampleSprint() {
	const name, age = "Kim", 22
	s := fmt.Sprint(name, " is ", age, " years old.\n")

	io.WriteString(os.Stdout, s) // Ignoring error for simplicity.

	// Output:
	// Kim is 22 years old.
}

func ExampleSprintln() {
	const name, age = "Kim", 22
	s := fmt.Sprintln(name, "is", age, "years old.")

	io.WriteString(os.Stdout, s) // Ignoring error for simplicity.

	// Output:
	// Kim is 22 years old.
}

func ExampleSprintf() {
	const name, age = "Kim", 22
	s := fmt.Sprintf("%s is %d years old.\n", name, age)

	io.WriteString(os.Stdout, s) // Ignoring error for simplicity.

	// Output:
	// Kim is 22 years old.
}

func ExampleFprint() {
	const name, age = "Kim", 22
	n, err := fmt.Fprint(os.Stdout, name, " is ", age, " years old.\n")

	// The n and err return values from Fprint are
	// those returned by the underlying io.Writer.
	if err != nil {
		fmt.Fprintf(os.Stderr, "Fprint: %v\n", err)
	}
	fmt.Print(n, " bytes written.\n")

	// Output:
	// Kim is 22 years old.
	// 21 bytes written.
}

func ExampleFprintln() {
	const name, age = "Kim", 22
	n, err := fmt.Fprintln(os.Stdout, name, "is", age, "years old.")

	// The n and err return values from Fprintln are
	// those returned by the underlying io.Writer.
	if err != nil {
		fmt.Fprintf(os.Stderr, "Fprintln: %v\n", err)
	}
	fmt.Println(n, "bytes written.")

	// Output:
	// Kim is 22 years old.
	// 21 bytes written.
}

func ExampleFprintf() {
	const name, age = "Kim", 22
	n, err := fmt.Fprintf(os.Stdout, "%s is %d years old.\n", name, age)

	// The n and err return values from Fprintf are
	// those returned by the underlying io.Writer.
	if err != nil {
		fmt.Fprintf(os.Stderr, "Fprintf: %v\n", err)
	}
	fmt.Printf("%d bytes written.\n", n)

	// Output:
	// Kim is 22 years old.
	// 21 bytes written.
}

// Print, Println, and Printf lay out their arguments differently. In this example
// we can compare their behaviors. Println always adds blanks between the items it
// prints, while Print adds blanks only between non-string arguments and Printf
// does exactly what it is told.
// Sprint, Sprintln, Sprintf, Fprint, Fprintln, and Fprintf behave the same as
// their corresponding Print, Println, and Printf functions shown here.
func Example_printers() {
	a, b := 3.0, 4.0
	h := math.Hypot(a, b)

	// Print inserts blanks between arguments when neither is a string.
	// It does not add a newline to the output, so we add one explicitly.
	fmt.Print("The vector (", a, b, ") has length ", h, ".\n")

	// Println always inserts spaces between its arguments,
	// so it cannot be used to produce the same output as Print in this case;
	// its output has extra spaces.
	// Also, Println always adds a newline to the output.
	fmt.Println("The vector (", a, b, ") has length", h, ".")

	// Printf provides complete control but is more complex to use.
	// It does not add a newline to the output, so we add one explicitly
	// at the end of the format specifier string.
	fmt.Printf("The vector (%g %g) has length %g.\n", a, b, h)

	// Output:
	// The vector (3 4) has length 5.
	// The vector ( 3 4 ) has length 5 .
	// The vector (3 4) has length 5.
}

// These examples demonstrate the basics of printing using a format string. Printf,
// Sprintf, and Fprintf all take a format string that specifies how to format the
// subsequent arguments. For example, %d (we call that a 'verb') says to print the
// corresponding argument, which must be an integer (or something containing an
// integer, such as a slice of ints) in decimal. The verb %v ('v' for 'value')
// always formats the argument in its default form, just how Print or Println would
// show it. The special verb %T ('T' for 'Type') prints the type of the argument
// rather than its value. The examples are not exhaustive; see the package comment
// for all the details.
func Example_formats() {
	// A basic set of examples showing that %v is the default format, in this
	// case decimal for integers, which can be explicitly requested with %d;
	// the output is just what Println generates.
	integer := 23
	// Each of these prints "23" (without the quotes).
	fmt.Println(integer)
	fmt.Printf("%v\n", integer)
	fmt.Printf("%d\n", integer)

	// The special verb %T shows the type of an item rather than its value.
	fmt.Printf("%T %T\n", integer, &integer)
	// Result: int *int

	// Println(x) is the same as Printf("%v\n", x) so we will use only Printf
	// in the following examples. Each one demonstrates how to format values of
	// a particular type, such as integers or strings. We start each format
	// string with %v to show the default output and follow that with one or
	// more custom formats.

	// Booleans print as "true" or "false" with %v or %t.
	truth := true
	fmt.Printf("%v %t\n", truth, truth)
	// Result: true true

	// Integers print as decimals with %v and %d,
	// or in hex with %x, octal with %o, or binary with %b.
	answer := 42
	fmt.Printf("%v %d %x %o %b\n", answer, answer, answer, answer, answer)
	// Result: 42 42 2a 52 101010

	// Floats have multiple formats: %v and %g print a compact representation,
	// while %f prints a decimal point and %e uses exponential notation. The
	// format %6.2f used here shows how to set the width and precision to
	// control the appearance of a floating-point value. In this instance, 6 is
	// the total width of the printed text for the value (note the extra spaces
	// in the output) and 2 is the number of decimal places to show.
	pi := math.Pi
	fmt.Printf("%v %g %.2f (%6.2f) %e\n", pi, pi, pi, pi, pi)
	// Result: 3.141592653589793 3.141592653589793 3.14 (  3.14) 3.141593e+00

	// Complex numbers format as parenthesized pairs of floats, with an 'i'
	// after the imaginary part.
	point := 110.7 + 22.5i
	fmt.Printf("%v %g %.2f %.2e\n", point, point, point, point)
	// Result: (110.7+22.5i) (110.7+22.5i) (110.70+22.50i) (1.11e+02+2.25e+01i)

	// Runes are integers but when printed with %c show the character with that
	// Unicode value. The %q verb shows them as quoted characters, %U as a
	// hex Unicode code point, and %#U as both a code point and a quoted
	// printable form if the rune is printable.
	smile := '😀'
	fmt.Printf("%v %d %c %q %U %#U\n", smile, smile, smile, smile, smile, smile)
	// Result: 128512 128512 😀 '😀' U+1F600 U+1F600 '😀'

	// Strings are formatted with %v and %s as-is, with %q as quoted strings,
	// and %#q as backquoted strings.
	placeholders := `foo "bar"`
	fmt.Printf("%v %s %q %#q\n", placeholders, placeholders, placeholders, placeholders)
	// Result: foo "bar" foo "bar" "foo \"bar\"" `foo "bar"`

	// Maps formatted with %v show keys and values in their default formats.
	// The %#v form (the # is called a "flag" in this context) shows the map in
	// the Go source format. Maps are printed in a consistent order, sorted
	// by the values of the keys.
	isLegume := map[string]bool{
		"peanut":    true,
		"dachshund": false,
	}
	fmt.Printf("%v %#v\n", isLegume, isLegume)
	// Result: map[dachshund:false peanut:true] map[string]bool{"dachshund":false, "peanut":true}

	// Structs formatted with %v show field values in their default formats.
	// The %+v form shows the fields by name, while %#v formats the struct in
	// Go source format.
	person := struct {
		Name string
		Age  int
	}{"Kim", 22}
	fmt.Printf("%v %+v %#v\n", person, person, person)
	// Result: {Kim 22} {Name:Kim Age:22} struct { Name string; Age int }{Name:"Kim", Age:22}

	// The default format for a pointer shows the underlying value preceded by
	// an ampersand. The %p verb prints the pointer value in hex. We use a
	// typed nil for the argument to %p here because the value of any non-nil
	// pointer would change from run to run; run the commented-out Printf
	// call yourself to see.
	pointer := &person
	fmt.Printf("%v %p\n", pointer, (*int)(nil))
	// Result: &{Kim 22} 0x0
	// fmt.Printf("%v %p\n", pointer, pointer)
	// Result: &{Kim 22} 0x010203 // See comment above.

	// Arrays and slices are formatted by applying the format to each element.
	greats := [5]string{"Kitano", "Kobayashi", "Kurosawa", "Miyazaki", "Ozu"}
	fmt.Printf("%v %q\n", greats, greats)
	// Result: [Kitano Kobayashi Kurosawa Miyazaki Ozu] ["Kitano" "Kobayashi" "Kurosawa" "Miyazaki" "Ozu"]

	kGreats := greats[:3]
	fmt.Printf("%v %q %#v\n", kGreats, kGreats, kGreats)
	// Result: [Kitano Kobayashi Kurosawa] ["Kitano" "Kobayashi" "Kurosawa"] []string{"Kitano", "Kobayashi", "Kurosawa"}

	// Byte slices are special. Integer verbs like %d print the elements in
	// that format. The %s and %q forms treat the slice like a string. The %x
	// verb has a special form with the space flag that puts a space between
	// the bytes.
	cmd := []byte("a⌘")
	fmt.Printf("%v %d %s %q %x % x\n", cmd, cmd, cmd, cmd, cmd, cmd)
	// Result: [97 226 140 152] [97 226 140 152] a⌘ "a⌘" 61e28c98 61 e2 8c 98

	// Types that implement Stringer are printed the same as strings. Because
	// Stringers return a string, we can print them using a string-specific
	// verb such as %q.
	now := time.Unix(123456789, 0).UTC() // time.Time implements fmt.Stringer.
	fmt.Printf("%v %q\n", now, now)
	// Result: 1973-11-29 21:33:09 +0000 UTC "1973-11-29 21:33:09 +0000 UTC"

	// Output:
	// 23
	// 23
	// 23
	// int *int
	// true true
	// 42 42 2a 52 101010
	// 3.141592653589793 3.141592653589793 3.14 (  3.14) 3.141593e+00
	// (110.7+22.5i) (110.7+22.5i) (110.70+22.50i) (1.11e+02+2.25e+01i)
	// 128512 128512 😀 '😀' U+1F600 U+1F600 '😀'
	// foo "bar" foo "bar" "foo \"bar\"" `foo "bar"`
	// map[dachshund:false peanut:true] map[string]bool{"dachshund":false, "peanut":true}
	// {Kim 22} {Name:Kim Age:22} struct { Name string; Age int }{Name:"Kim", Age:22}
	// &{Kim 22} 0x0
	// [Kitano Kobayashi Kurosawa Miyazaki Ozu] ["Kitano" "Kobayashi" "Kurosawa" "Miyazaki" "Ozu"]
	// [Kitano Kobayashi Kurosawa] ["Kitano" "Kobayashi" "Kurosawa"] []string{"Kitano", "Kobayashi", "Kurosawa"}
	// [97 226 140 152] [97 226 140 152] a⌘ "a⌘" 61e28c98 61 e2 8c 98
	// 1973-11-29 21:33:09 +0000 UTC "1973-11-29 21:33:09 +0000 UTC"
}
```