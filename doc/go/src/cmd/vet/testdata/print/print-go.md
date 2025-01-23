Response:
My goal is to analyze the provided Go code snippet and explain its functionality, focusing on how it tests the `printf` checker in the `go vet` tool. Here's my thought process:

1. **Identify the core purpose:** The comments at the beginning clearly state, "This file contains tests for the printf checker." This immediately tells me the primary function of this code.

2. **Examine the structure:** The code defines several functions. The name `PrintfTests` strongly suggests this is the main testing function. Other functions have names like `UnsafePointerPrintfTest`, and types like `errorTest1`, `ptrStringer`, which hint at specific testing scenarios.

3. **Analyze `PrintfTests`:** This function contains a large number of `fmt.Printf` calls. Crucially, many of these calls are followed by `// ERROR "..."` comments. This pattern is the standard way Go's testing framework expects to find errors: the tool being tested (in this case, the `printf` checker within `go vet`) should report those errors.

4. **Categorize the tests in `PrintfTests`:** Looking at the `fmt.Printf` calls and their associated error messages, I can see different categories of tests:
    * **Correct usage:**  Examples like `fmt.Printf("")` and `fmt.Printf("%d %d %d", 3, i, imap)` without error comments demonstrate valid `Printf` usage.
    * **Incorrect format strings:** Tests like `fmt.Printf("%b", "hi") // ERROR ...` check if the checker correctly identifies type mismatches between the format specifier (`%b`) and the argument type (`string`).
    * **Incorrect number of arguments:** Calls like `fmt.Printf("%s", "hi", 3) // ERROR ...` test if the checker validates the number of arguments against the format string.
    * **Invalid format specifiers:**  Examples like `f.Warnf(0, "%r", "hello") // ERROR ...` check for unknown or invalid format verbs.
    * **Argument indexing:**  Tests using `%[n]` verify the correct handling of explicit argument indexing in format strings.
    * **Error interface:** The code checks how the checker interacts with types that implement the `error` interface. It also checks for cases that *look* like error methods but aren't (e.g., `testing.T.Error`).
    * **Stringer interface:** The code explores how the checker handles types implementing the `String()` method (the `fmt.Stringer` interface). It tests both correct and incorrect usage.
    * **Recursive calls in `String()`:**  The `recursiveStringer` and `recursivePtrStringer` types are designed to test the checker's ability to detect infinite recursion during string formatting.
    * **Println variations:**  Tests using `fmt.Println` and custom `Println`-like functions ensure the checker identifies potential formatting directives in these contexts.
    * **External packages:**  While commented out in the provided snippet, there's evidence of testing `Printf`-like functions from external packages.
    * **Unexported types:** The code checks if the checker correctly identifies issues when trying to format unexported struct fields.

5. **Analyze other functions and types:** The other functions and types support the tests in `PrintfTests`:
    * **`UnsafePointerPrintfTest`:** Specifically tests formatting of `unsafe.Pointer`.
    * **`errorTestN` types:** Used to test scenarios where methods are named `Error` but don't conform to the `error` interface.
    * **`ptrStringer`, `embeddedStringer`, `notstringer`, etc.:** These custom types are designed to test various aspects of the `fmt.Stringer` interface and its interactions with `Printf`.
    * **`Printf`, `Println`, `printf`, `Errorf`, `errorf`:** These are helper functions declared within the test file to mimic standard library functions or introduce slight variations for testing purposes.

6. **Infer the `printf` checker's function:** Based on the tests, I can infer that the `printf` checker within `go vet` aims to:
    * Validate format strings for correctness.
    * Ensure type compatibility between format specifiers and arguments.
    * Verify the correct number of arguments is provided.
    * Identify potential formatting directives in `Println` calls.
    * Handle argument indexing correctly.
    * Recognize and handle types implementing the `error` and `fmt.Stringer` interfaces.
    * Detect potential infinite recursion in `String()` methods called during formatting.

7. **Construct examples:** To illustrate the functionality, I would choose representative test cases from `PrintfTests` and show the expected behavior of `go vet`. I would also demonstrate how the checker flags common mistakes.

8. **Address command-line arguments:** The `go vet` tool itself might have flags, but this specific test file doesn't demonstrate any direct handling of command-line arguments *within* the tested code. Therefore, I would focus on how `go vet` is invoked in general.

9. **Identify common mistakes:** Based on the error scenarios in the test code, I would highlight typical errors developers make when using `Printf` and similar functions.

By following these steps, I can systematically analyze the code and provide a comprehensive explanation of its functionality and the `printf` checker it's designed to test. The key is to recognize the testing framework's conventions (the `// ERROR` comments) and categorize the various test cases to understand the checker's capabilities.
这段代码是 Go 语言 `go vet` 工具中 `printf` 检查器的一部分测试数据。它的主要功能是**测试 `go vet` 的 `printf` 检查器是否能够正确地检测出各种 `fmt.Printf`、`fmt.Sprintf`、`fmt.Println` 以及用户自定义的类似函数的调用中可能存在的格式化字符串错误和参数类型不匹配的问题。**

更具体地说，这个文件包含了一系列的 Go 代码示例，这些示例涵盖了 `fmt` 包中 `Printf` 系列函数以及一些用户自定义的具有类似功能的函数（例如 `Warnf`, `Logf` 等）。每个示例都旨在测试 `printf` 检查器在特定场景下的行为。

**功能列举：**

1. **测试 `fmt.Printf` 的正确用法:**  包含了一些格式化字符串和参数类型都正确的 `fmt.Printf` 调用，用于确保检查器不会误报。
2. **测试 `fmt.Printf` 的错误用法:** 大量示例展示了各种错误的 `fmt.Printf` 调用，并使用 `// ERROR "..."` 注释标明了 `go vet` 应该报告的错误信息。这些错误包括：
    * **格式化动词与参数类型不匹配:** 例如，使用 `%d` 格式化字符串，但传入的是字符串类型的参数。
    * **格式化字符串中的动词数量与参数数量不匹配:** 例如，格式化字符串中有两个 `%s`，但只传入了一个字符串参数。
    * **使用了无效的格式化动词或标志:** 例如，使用 `%r` 这种不存在的动词，或者使用 `%#s` 这种对于字符串来说没有意义的标志。
    * **`Println` 函数中使用了格式化动词:** `Println` 系列函数不应该包含格式化动词。
    * **使用了不正确的参数类型进行宽度或精度的指定 (`*`)：** 例如，`%.*s` 中，`*` 对应的参数应该是一个整数。
    * **使用了无效的参数索引 (`%[n]`)。**
    * **尝试格式化 `nil` 值时使用了不恰当的动词。**
    * **尝试格式化未导出的结构体或接口时使用了 `%s` 等需要实现 `String()` 方法的动词。**
    * **在 `String()` 方法内部使用 `%v` 等可能导致无限递归的格式化动词。**
3. **测试用户自定义的类似 `Printf` 的函数:** 代码中定义了一些类似 `Printf` 的函数（例如 `Warnf`, `Wrapf`），并测试了 `go vet` 是否能够正确地分析这些函数的格式化字符串和参数。
4. **测试实现了 `fmt.Stringer` 或 `error` 接口的类型:**  代码中定义了一些实现了 `String()` 和 `Error()` 方法的类型，并测试了 `go vet` 在格式化这些类型时的行为。
5. **测试命名相似但不符合 `error` 接口的方法:** 定义了一些名为 `Error` 但签名与 `error` 接口不符的方法，用于验证 `go vet` 不会将这些方法误判为实现了 `error` 接口。
6. **测试 `Println` 的变体和易错点:**  测试了 `Println` 及其变体，例如 `logpkg.Println`，并着重测试了在这些函数中误用格式化动词的情况。
7. **测试参数重排序功能 (`%[n]`) 的正确性和错误用法。**
8. **测试调用变参函数时 `...` 的使用是否正确。**

**代码推理及示例：**

这段代码的核心功能是验证 `go vet` 的 `printf` 检查器。假设 `go vet` 正在分析这段代码。

**假设输入：**  `go vet` 工具正在分析 `go/src/cmd/vet/testdata/print/print.go` 文件。

**示例 1：类型不匹配**

```go
fmt.Printf("%d", "hello") // ERROR "Printf format %d has arg \x22hello\x22 of wrong type string"
```

**推理：** `go vet` 的 `printf` 检查器会分析 `%d` 格式化动词，它期望一个整数类型的参数。然而，实际传入的参数是字符串 `"hello"`。因此，检查器会报告一个错误，指出参数类型不匹配。

**示例 2：参数数量不匹配**

```go
fmt.Printf("%s %d", "world") // ERROR "Printf format %s reads arg #2, but call has 1 arg$"
```

**推理：** 格式化字符串 `%s %d` 中有两个格式化动词，因此 `Printf` 期望接收两个参数。但是，调用时只提供了一个参数 `"world"`。`go vet` 的检查器会检测到参数数量不足。

**示例 3：`Println` 中误用格式化动词**

```go
fmt.Println("%s", "hello") // ERROR "Println call has possible Printf formatting directive %s"
```

**推理：** `fmt.Println` 系列函数会将所有参数原样输出，不进行格式化。因此，在 `Println` 中使用 `%s` 这样的格式化动词是错误的。`go vet` 的检查器会识别出这种潜在的错误用法。

**命令行参数的具体处理：**

这段代码本身并不直接处理命令行参数。 它是 `go vet` 工具的测试数据。`go vet` 工具通过命令行调用，通常的形式如下：

```bash
go vet [options] [packages]
```

常见的 `go vet` 选项包括：

* `-n`:  仅报告错误，不实际执行修复（如果启用了修复）。
* `-x`:  打印执行的命令。
* `-all`:  运行所有分析器，包括 `printf` 检查器。

当运行 `go vet` 并指定包含这段代码的包时，`printf` 检查器会被激活，并分析代码中的 `Printf` 系列函数调用，对照预期的错误信息（`// ERROR "..."` 注释）来验证其自身的正确性。

**使用者易犯错的点：**

1. **`Println` 中使用格式化动词：** 很多 Go 初学者会习惯性地在 `fmt.Println` 中使用 `%s`, `%d` 等格式化动词，认为它和 `fmt.Printf` 的用法类似，但这是错误的。`Println` 只是简单地将参数转换为字符串并输出，不会进行格式化。

   ```go
   name := "Alice"
   fmt.Println("Hello, %s!", name) // 输出：Hello, %s! Alice，而不是 Hello, Alice!
   ```

2. **`Printf` 的格式化动词与参数类型不匹配：**  这是最常见的错误。需要仔细核对格式化字符串中的动词和对应参数的类型。

   ```go
   age := 30
   fmt.Printf("Age: %s\n", age) // 错误：期望字符串，但传入的是整数
   fmt.Printf("Age: %d\n", age) // 正确
   ```

3. **`Printf` 的参数数量与格式化动词数量不匹配：**  需要确保提供的参数数量与格式化字符串中需要被格式化的值的数量一致。

   ```go
   name := "Bob"
   age := 25
   fmt.Printf("Name: %s\n")        // 错误：缺少 age 参数对应的格式化动词
   fmt.Printf("Name: %s, Age: %d\n", name) // 错误：缺少 age 参数
   fmt.Printf("Name: %s, Age: %d\n", name, age) // 正确
   ```

4. **在实现了 `String()` 方法的类型上使用 `%s` 以外的动词时可能产生意外结果：**  当使用 `%v` 或其他动词格式化实现了 `String()` 方法的类型时，`fmt` 包会调用该类型的 `String()` 方法获取字符串表示。如果忘记实现 `String()` 方法，或者实现不符合预期，可能会导致输出不正确。

5. **在 `String()` 方法内部使用 `%v` 格式化自身可能导致无限递归：**  如果一个类型的 `String()` 方法内部使用 `fmt.Sprintf("%v", self)` 来格式化自身，会导致 `String()` 方法被无限次调用，最终导致栈溢出。`go vet` 的 `printf` 检查器能够检测出这种潜在的递归调用。

这段测试代码通过大量的正反示例，系统地测试了 `go vet` 的 `printf` 检查器在各种情况下的准确性，帮助开发者避免在使用 `fmt` 包时常犯的错误。

### 提示词
```
这是路径为go/src/cmd/vet/testdata/print/print.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
```

### 源代码
```go
// Copyright 2010 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// This file contains tests for the printf checker.

package print

import (
	"fmt"
	logpkg "log" // renamed to make it harder to see
	"math"
	"os"
	"testing"
	"unsafe" // just for test case printing unsafe.Pointer
	// For testing printf-like functions from external package.
	// "github.com/foobar/externalprintf"
)

func UnsafePointerPrintfTest() {
	var up unsafe.Pointer
	fmt.Printf("%p, %x %X", up, up, up)
}

// Error methods that do not satisfy the Error interface and should be checked.
type errorTest1 int

func (errorTest1) Error(...interface{}) string {
	return "hi"
}

type errorTest2 int // Analogous to testing's *T type.
func (errorTest2) Error(...interface{}) {
}

type errorTest3 int

func (errorTest3) Error() { // No return value.
}

type errorTest4 int

func (errorTest4) Error() int { // Different return type.
	return 3
}

type errorTest5 int

func (errorTest5) error() { // niladic; don't complain if no args (was bug)
}

// This function never executes, but it serves as a simple test for the program.
// Test with make test.
func PrintfTests() {
	var b bool
	var i int
	var r rune
	var s string
	var x float64
	var p *int
	var imap map[int]int
	var fslice []float64
	var c complex64
	// Some good format/argtypes
	fmt.Printf("")
	fmt.Printf("%b %b %b", 3, i, x)
	fmt.Printf("%c %c %c %c", 3, i, 'x', r)
	fmt.Printf("%d %d %d", 3, i, imap)
	fmt.Printf("%e %e %e %e", 3e9, x, fslice, c)
	fmt.Printf("%E %E %E %E", 3e9, x, fslice, c)
	fmt.Printf("%f %f %f %f", 3e9, x, fslice, c)
	fmt.Printf("%F %F %F %F", 3e9, x, fslice, c)
	fmt.Printf("%g %g %g %g", 3e9, x, fslice, c)
	fmt.Printf("%G %G %G %G", 3e9, x, fslice, c)
	fmt.Printf("%b %b %b %b", 3e9, x, fslice, c)
	fmt.Printf("%o %o", 3, i)
	fmt.Printf("%p", p)
	fmt.Printf("%q %q %q %q", 3, i, 'x', r)
	fmt.Printf("%s %s %s", "hi", s, []byte{65})
	fmt.Printf("%t %t", true, b)
	fmt.Printf("%T %T", 3, i)
	fmt.Printf("%U %U", 3, i)
	fmt.Printf("%v %v", 3, i)
	fmt.Printf("%x %x %x %x %x %x %x", 3, i, "hi", s, x, c, fslice)
	fmt.Printf("%X %X %X %X %X %X %X", 3, i, "hi", s, x, c, fslice)
	fmt.Printf("%.*s %d %g", 3, "hi", 23, 2.3)
	fmt.Printf("%s", &stringerv)
	fmt.Printf("%v", &stringerv)
	fmt.Printf("%T", &stringerv)
	fmt.Printf("%s", &embeddedStringerv)
	fmt.Printf("%v", &embeddedStringerv)
	fmt.Printf("%T", &embeddedStringerv)
	fmt.Printf("%v", notstringerv)
	fmt.Printf("%T", notstringerv)
	fmt.Printf("%q", stringerarrayv)
	fmt.Printf("%v", stringerarrayv)
	fmt.Printf("%s", stringerarrayv)
	fmt.Printf("%v", notstringerarrayv)
	fmt.Printf("%T", notstringerarrayv)
	fmt.Printf("%d", new(fmt.Formatter))
	fmt.Printf("%*%", 2)               // Ridiculous but allowed.
	fmt.Printf("%s", interface{}(nil)) // Nothing useful we can say.

	fmt.Printf("%g", 1+2i)
	fmt.Printf("%#e %#E %#f %#F %#g %#G", 1.2, 1.2, 1.2, 1.2, 1.2, 1.2) // OK since Go 1.9
	// Some bad format/argTypes
	fmt.Printf("%b", "hi")                      // ERROR "Printf format %b has arg \x22hi\x22 of wrong type string"
	fmt.Printf("%t", c)                         // ERROR "Printf format %t has arg c of wrong type complex64"
	fmt.Printf("%t", 1+2i)                      // ERROR "Printf format %t has arg 1 \+ 2i of wrong type complex128"
	fmt.Printf("%c", 2.3)                       // ERROR "Printf format %c has arg 2.3 of wrong type float64"
	fmt.Printf("%d", 2.3)                       // ERROR "Printf format %d has arg 2.3 of wrong type float64"
	fmt.Printf("%e", "hi")                      // ERROR "Printf format %e has arg \x22hi\x22 of wrong type string"
	fmt.Printf("%E", true)                      // ERROR "Printf format %E has arg true of wrong type bool"
	fmt.Printf("%f", "hi")                      // ERROR "Printf format %f has arg \x22hi\x22 of wrong type string"
	fmt.Printf("%F", 'x')                       // ERROR "Printf format %F has arg 'x' of wrong type rune"
	fmt.Printf("%g", "hi")                      // ERROR "Printf format %g has arg \x22hi\x22 of wrong type string"
	fmt.Printf("%g", imap)                      // ERROR "Printf format %g has arg imap of wrong type map\[int\]int"
	fmt.Printf("%G", i)                         // ERROR "Printf format %G has arg i of wrong type int"
	fmt.Printf("%o", x)                         // ERROR "Printf format %o has arg x of wrong type float64"
	fmt.Printf("%p", nil)                       // ERROR "Printf format %p has arg nil of wrong type untyped nil"
	fmt.Printf("%p", 23)                        // ERROR "Printf format %p has arg 23 of wrong type int"
	fmt.Printf("%q", x)                         // ERROR "Printf format %q has arg x of wrong type float64"
	fmt.Printf("%s", b)                         // ERROR "Printf format %s has arg b of wrong type bool"
	fmt.Printf("%s", byte(65))                  // ERROR "Printf format %s has arg byte\(65\) of wrong type byte"
	fmt.Printf("%t", 23)                        // ERROR "Printf format %t has arg 23 of wrong type int"
	fmt.Printf("%U", x)                         // ERROR "Printf format %U has arg x of wrong type float64"
	fmt.Printf("%x", nil)                       // ERROR "Printf format %x has arg nil of wrong type untyped nil"
	fmt.Printf("%s", stringerv)                 // ERROR "Printf format %s has arg stringerv of wrong type .*print.ptrStringer"
	fmt.Printf("%t", stringerv)                 // ERROR "Printf format %t has arg stringerv of wrong type .*print.ptrStringer"
	fmt.Printf("%s", embeddedStringerv)         // ERROR "Printf format %s has arg embeddedStringerv of wrong type .*print.embeddedStringer"
	fmt.Printf("%t", embeddedStringerv)         // ERROR "Printf format %t has arg embeddedStringerv of wrong type .*print.embeddedStringer"
	fmt.Printf("%q", notstringerv)              // ERROR "Printf format %q has arg notstringerv of wrong type .*print.notstringer"
	fmt.Printf("%t", notstringerv)              // ERROR "Printf format %t has arg notstringerv of wrong type .*print.notstringer"
	fmt.Printf("%t", stringerarrayv)            // ERROR "Printf format %t has arg stringerarrayv of wrong type .*print.stringerarray"
	fmt.Printf("%t", notstringerarrayv)         // ERROR "Printf format %t has arg notstringerarrayv of wrong type .*print.notstringerarray"
	fmt.Printf("%q", notstringerarrayv)         // ERROR "Printf format %q has arg notstringerarrayv of wrong type .*print.notstringerarray"
	fmt.Printf("%d", BoolFormatter(true))       // ERROR "Printf format %d has arg BoolFormatter\(true\) of wrong type .*print.BoolFormatter"
	fmt.Printf("%z", FormatterVal(true))        // correct (the type is responsible for formatting)
	fmt.Printf("%d", FormatterVal(true))        // correct (the type is responsible for formatting)
	fmt.Printf("%s", nonemptyinterface)         // correct (the type is responsible for formatting)
	fmt.Printf("%.*s %d %6g", 3, "hi", 23, 'x') // ERROR "Printf format %6g has arg 'x' of wrong type rune"
	fmt.Println()                               // not an error
	fmt.Println("%s", "hi")                     // ERROR "Println call has possible Printf formatting directive %s"
	fmt.Println("%v", "hi")                     // ERROR "Println call has possible Printf formatting directive %v"
	fmt.Println("%T", "hi")                     // ERROR "Println call has possible Printf formatting directive %T"
	fmt.Println("0.0%")                         // correct (trailing % couldn't be a formatting directive)
	fmt.Printf("%s", "hi", 3)                   // ERROR "Printf call needs 1 arg but has 2 args"
	_ = fmt.Sprintf("%"+("s"), "hi", 3)         // ERROR "Sprintf call needs 1 arg but has 2 args"
	fmt.Printf("%s%%%d", "hi", 3)               // correct
	fmt.Printf("%08s", "woo")                   // correct
	fmt.Printf("% 8s", "woo")                   // correct
	fmt.Printf("%.*d", 3, 3)                    // correct
	fmt.Printf("%.*d x", 3, 3, 3, 3)            // ERROR "Printf call needs 2 args but has 4 args"
	fmt.Printf("%.*d x", "hi", 3)               // ERROR "Printf format %.*d uses non-int \x22hi\x22 as argument of \*"
	fmt.Printf("%.*d x", i, 3)                  // correct
	fmt.Printf("%.*d x", s, 3)                  // ERROR "Printf format %.\*d uses non-int s as argument of \*"
	fmt.Printf("%*% x", 0.22)                   // ERROR "Printf format %\*% uses non-int 0.22 as argument of \*"
	fmt.Printf("%q %q", multi()...)             // ok
	fmt.Printf("%#q", `blah`)                   // ok
	// printf("now is the time", "buddy")          // no error "printf call has arguments but no formatting directives"
	Printf("now is the time", "buddy") // ERROR "Printf call has arguments but no formatting directives"
	Printf("hi")                       // ok
	const format = "%s %s\n"
	Printf(format, "hi", "there")
	Printf(format, "hi")              // ERROR "Printf format %s reads arg #2, but call has 1 arg$"
	Printf("%s %d %.3v %q", "str", 4) // ERROR "Printf format %.3v reads arg #3, but call has 2 args"
	f := new(ptrStringer)
	f.Warn(0, "%s", "hello", 3)           // ERROR "Warn call has possible Printf formatting directive %s"
	f.Warnf(0, "%s", "hello", 3)          // ERROR "Warnf call needs 1 arg but has 2 args"
	f.Warnf(0, "%r", "hello")             // ERROR "Warnf format %r has unknown verb r"
	f.Warnf(0, "%#s", "hello")            // ERROR "Warnf format %#s has unrecognized flag #"
	f.Warn2(0, "%s", "hello", 3)          // ERROR "Warn2 call has possible Printf formatting directive %s"
	f.Warnf2(0, "%s", "hello", 3)         // ERROR "Warnf2 call needs 1 arg but has 2 args"
	f.Warnf2(0, "%r", "hello")            // ERROR "Warnf2 format %r has unknown verb r"
	f.Warnf2(0, "%#s", "hello")           // ERROR "Warnf2 format %#s has unrecognized flag #"
	f.Wrap(0, "%s", "hello", 3)           // ERROR "Wrap call has possible Printf formatting directive %s"
	f.Wrapf(0, "%s", "hello", 3)          // ERROR "Wrapf call needs 1 arg but has 2 args"
	f.Wrapf(0, "%r", "hello")             // ERROR "Wrapf format %r has unknown verb r"
	f.Wrapf(0, "%#s", "hello")            // ERROR "Wrapf format %#s has unrecognized flag #"
	f.Wrap2(0, "%s", "hello", 3)          // ERROR "Wrap2 call has possible Printf formatting directive %s"
	f.Wrapf2(0, "%s", "hello", 3)         // ERROR "Wrapf2 call needs 1 arg but has 2 args"
	f.Wrapf2(0, "%r", "hello")            // ERROR "Wrapf2 format %r has unknown verb r"
	f.Wrapf2(0, "%#s", "hello")           // ERROR "Wrapf2 format %#s has unrecognized flag #"
	fmt.Printf("%#s", FormatterVal(true)) // correct (the type is responsible for formatting)
	Printf("d%", 2)                       // ERROR "Printf format % is missing verb at end of string"
	Printf("%d", percentDV)
	Printf("%d", &percentDV)
	Printf("%d", notPercentDV)  // ERROR "Printf format %d has arg notPercentDV of wrong type .*print.notPercentDStruct"
	Printf("%d", &notPercentDV) // ERROR "Printf format %d has arg &notPercentDV of wrong type \*.*print.notPercentDStruct"
	Printf("%p", &notPercentDV) // Works regardless: we print it as a pointer.
	Printf("%q", &percentDV)    // ERROR "Printf format %q has arg &percentDV of wrong type \*.*print.percentDStruct"
	Printf("%s", percentSV)
	Printf("%s", &percentSV)
	// Good argument reorderings.
	Printf("%[1]d", 3)
	Printf("%[1]*d", 3, 1)
	Printf("%[2]*[1]d", 1, 3)
	Printf("%[2]*.[1]*[3]d", 2, 3, 4)
	fmt.Fprintf(os.Stderr, "%[2]*.[1]*[3]d", 2, 3, 4) // Use Fprintf to make sure we count arguments correctly.
	// Bad argument reorderings.
	Printf("%[xd", 3)                      // ERROR "Printf format %\[xd is missing closing \]"
	Printf("%[x]d x", 3)                   // ERROR "Printf format has invalid argument index \[x\]"
	Printf("%[3]*s x", "hi", 2)            // ERROR "Printf format has invalid argument index \[3\]"
	_ = fmt.Sprintf("%[3]d x", 2)          // ERROR "Sprintf format has invalid argument index \[3\]"
	Printf("%[2]*.[1]*[3]d x", 2, "hi", 4) // ERROR "Printf format %\[2]\*\.\[1\]\*\[3\]d uses non-int \x22hi\x22 as argument of \*"
	Printf("%[0]s x", "arg1")              // ERROR "Printf format has invalid argument index \[0\]"
	Printf("%[0]d x", 1)                   // ERROR "Printf format has invalid argument index \[0\]"
	// Something that satisfies the error interface.
	var e error
	fmt.Println(e.Error()) // ok
	// Something that looks like an error interface but isn't, such as the (*T).Error method
	// in the testing package.
	var et1 *testing.T
	et1.Error()        // ok
	et1.Error("hi")    // ok
	et1.Error("%d", 3) // ERROR "Error call has possible Printf formatting directive %d"
	var et3 errorTest3
	et3.Error() // ok, not an error method.
	var et4 errorTest4
	et4.Error() // ok, not an error method.
	var et5 errorTest5
	et5.error() // ok, not an error method.
	// Interfaces can be used with any verb.
	var iface interface {
		ToTheMadness() bool // Method ToTheMadness usually returns false
	}
	fmt.Printf("%f", iface) // ok: fmt treats interfaces as transparent and iface may well have a float concrete type
	// Can't print a function.
	Printf("%d", someFunction) // ERROR "Printf format %d arg someFunction is a func value, not called"
	Printf("%v", someFunction) // ERROR "Printf format %v arg someFunction is a func value, not called"
	Println(someFunction)      // ERROR "Println arg someFunction is a func value, not called"
	Printf("%p", someFunction) // ok: maybe someone wants to see the pointer
	Printf("%T", someFunction) // ok: maybe someone wants to see the type
	// Bug: used to recur forever.
	Printf("%p %x", recursiveStructV, recursiveStructV.next)
	Printf("%p %x", recursiveStruct1V, recursiveStruct1V.next) // ERROR "Printf format %x has arg recursiveStruct1V\.next of wrong type \*.*print\.RecursiveStruct2"
	Printf("%p %x", recursiveSliceV, recursiveSliceV)
	Printf("%p %x", recursiveMapV, recursiveMapV)
	// Special handling for Log.
	math.Log(3) // OK
	var t *testing.T
	t.Log("%d", 3) // ERROR "Log call has possible Printf formatting directive %d"
	t.Logf("%d", 3)
	t.Logf("%d", "hi") // ERROR "Logf format %d has arg \x22hi\x22 of wrong type string"

	Errorf(1, "%d", 3)    // OK
	Errorf(1, "%d", "hi") // ERROR "Errorf format %d has arg \x22hi\x22 of wrong type string"

	// Multiple string arguments before variadic args
	errorf("WARNING", "foobar")            // OK
	errorf("INFO", "s=%s, n=%d", "foo", 1) // OK
	errorf("ERROR", "%d")                  // ERROR "errorf format %d reads arg #1, but call has 0 args"

	// Printf from external package
	// externalprintf.Printf("%d", 42) // OK
	// externalprintf.Printf("foobar") // OK
	// level := 123
	// externalprintf.Logf(level, "%d", 42)                        // OK
	// externalprintf.Errorf(level, level, "foo %q bar", "foobar") // OK
	// externalprintf.Logf(level, "%d")                            // no error "Logf format %d reads arg #1, but call has 0 args"
	// var formatStr = "%s %s"
	// externalprintf.Sprintf(formatStr, "a", "b")     // OK
	// externalprintf.Logf(level, formatStr, "a", "b") // OK

	// user-defined Println-like functions
	ss := &someStruct{}
	ss.Log(someFunction, "foo")          // OK
	ss.Error(someFunction, someFunction) // OK
	ss.Println()                         // OK
	ss.Println(1.234, "foo")             // OK
	ss.Println(1, someFunction)          // no error "Println arg someFunction is a func value, not called"
	ss.log(someFunction)                 // OK
	ss.log(someFunction, "bar", 1.33)    // OK
	ss.log(someFunction, someFunction)   // no error "log arg someFunction is a func value, not called"

	// indexed arguments
	Printf("%d %[3]d %d %[2]d x", 1, 2, 3, 4)             // OK
	Printf("%d %[0]d %d %[2]d x", 1, 2, 3, 4)             // ERROR "Printf format has invalid argument index \[0\]"
	Printf("%d %[3]d %d %[-2]d x", 1, 2, 3, 4)            // ERROR "Printf format has invalid argument index \[-2\]"
	Printf("%d %[3]d %d %[2234234234234]d x", 1, 2, 3, 4) // ERROR "Printf format has invalid argument index \[2234234234234\]"
	Printf("%d %[3]d %-10d %[2]d x", 1, 2, 3)             // ERROR "Printf format %-10d reads arg #4, but call has 3 args"
	Printf("%[1][3]d x", 1, 2)                            // ERROR "Printf format %\[1\]\[ has unknown verb \["
	Printf("%[1]d x", 1, 2)                               // OK
	Printf("%d %[3]d %d %[2]d x", 1, 2, 3, 4, 5)          // OK

	// wrote Println but meant Fprintln
	Printf("%p\n", os.Stdout)   // OK
	Println(os.Stdout, "hello") // ERROR "Println does not take io.Writer but has first arg os.Stdout"

	Printf(someString(), "hello") // OK

	// Printf wrappers in package log should be detected automatically
	logpkg.Fatal("%d", 1)    // ERROR "Fatal call has possible Printf formatting directive %d"
	logpkg.Fatalf("%d", "x") // ERROR "Fatalf format %d has arg \x22x\x22 of wrong type string"
	logpkg.Fatalln("%d", 1)  // ERROR "Fatalln call has possible Printf formatting directive %d"
	logpkg.Panic("%d", 1)    // ERROR "Panic call has possible Printf formatting directive %d"
	logpkg.Panicf("%d", "x") // ERROR "Panicf format %d has arg \x22x\x22 of wrong type string"
	logpkg.Panicln("%d", 1)  // ERROR "Panicln call has possible Printf formatting directive %d"
	logpkg.Print("%d", 1)    // ERROR "Print call has possible Printf formatting directive %d"
	logpkg.Printf("%d", "x") // ERROR "Printf format %d has arg \x22x\x22 of wrong type string"
	logpkg.Println("%d", 1)  // ERROR "Println call has possible Printf formatting directive %d"

	// Methods too.
	var l *logpkg.Logger
	l.Fatal("%d", 1)    // ERROR "Fatal call has possible Printf formatting directive %d"
	l.Fatalf("%d", "x") // ERROR "Fatalf format %d has arg \x22x\x22 of wrong type string"
	l.Fatalln("%d", 1)  // ERROR "Fatalln call has possible Printf formatting directive %d"
	l.Panic("%d", 1)    // ERROR "Panic call has possible Printf formatting directive %d"
	l.Panicf("%d", "x") // ERROR "Panicf format %d has arg \x22x\x22 of wrong type string"
	l.Panicln("%d", 1)  // ERROR "Panicln call has possible Printf formatting directive %d"
	l.Print("%d", 1)    // ERROR "Print call has possible Printf formatting directive %d"
	l.Printf("%d", "x") // ERROR "Printf format %d has arg \x22x\x22 of wrong type string"
	l.Println("%d", 1)  // ERROR "Println call has possible Printf formatting directive %d"

	// Issue 26486
	dbg("", 1) // no error "call has arguments but no formatting directive"
}

func someString() string { return "X" }

type someStruct struct{}

// Log is non-variadic user-define Println-like function.
// Calls to this func must be skipped when checking
// for Println-like arguments.
func (ss *someStruct) Log(f func(), s string) {}

// Error is variadic user-define Println-like function.
// Calls to this func mustn't be checked for Println-like arguments,
// since variadic arguments type isn't interface{}.
func (ss *someStruct) Error(args ...func()) {}

// Println is variadic user-defined Println-like function.
// Calls to this func must be checked for Println-like arguments.
func (ss *someStruct) Println(args ...interface{}) {}

// log is variadic user-defined Println-like function.
// Calls to this func must be checked for Println-like arguments.
func (ss *someStruct) log(f func(), args ...interface{}) {}

// A function we use as a function value; it has no other purpose.
func someFunction() {}

// Printf is used by the test so we must declare it.
func Printf(format string, args ...interface{}) {
	fmt.Printf(format, args...)
}

// Println is used by the test so we must declare it.
func Println(args ...interface{}) {
	fmt.Println(args...)
}

// printf is used by the test so we must declare it.
func printf(format string, args ...interface{}) {
	fmt.Printf(format, args...)
}

// Errorf is used by the test for a case in which the first parameter
// is not a format string.
func Errorf(i int, format string, args ...interface{}) {
	_ = fmt.Errorf(format, args...)
}

// errorf is used by the test for a case in which the function accepts multiple
// string parameters before variadic arguments
func errorf(level, format string, args ...interface{}) {
	_ = fmt.Errorf(format, args...)
}

// multi is used by the test.
func multi() []interface{} {
	panic("don't call - testing only")
}

type stringer int

func (stringer) String() string { return "string" }

type ptrStringer float64

var stringerv ptrStringer

func (*ptrStringer) String() string {
	return "string"
}

func (p *ptrStringer) Warn2(x int, args ...interface{}) string {
	return p.Warn(x, args...)
}

func (p *ptrStringer) Warnf2(x int, format string, args ...interface{}) string {
	return p.Warnf(x, format, args...)
}

func (*ptrStringer) Warn(x int, args ...interface{}) string {
	return "warn"
}

func (*ptrStringer) Warnf(x int, format string, args ...interface{}) string {
	return "warnf"
}

func (p *ptrStringer) Wrap2(x int, args ...interface{}) string {
	return p.Wrap(x, args...)
}

func (p *ptrStringer) Wrapf2(x int, format string, args ...interface{}) string {
	return p.Wrapf(x, format, args...)
}

func (*ptrStringer) Wrap(x int, args ...interface{}) string {
	return fmt.Sprint(args...)
}

func (*ptrStringer) Wrapf(x int, format string, args ...interface{}) string {
	return fmt.Sprintf(format, args...)
}

func (*ptrStringer) BadWrap(x int, args ...interface{}) string {
	return fmt.Sprint(args) // ERROR "missing ... in args forwarded to print-like function"
}

func (*ptrStringer) BadWrapf(x int, format string, args ...interface{}) string {
	return fmt.Sprintf(format, args) // ERROR "missing ... in args forwarded to printf-like function"
}

func (*ptrStringer) WrapfFalsePositive(x int, arg1 string, arg2 ...interface{}) string {
	return fmt.Sprintf("%s %v", arg1, arg2)
}

type embeddedStringer struct {
	foo string
	ptrStringer
	bar int
}

var embeddedStringerv embeddedStringer

type notstringer struct {
	f float64
}

var notstringerv notstringer

type stringerarray [4]float64

func (stringerarray) String() string {
	return "string"
}

var stringerarrayv stringerarray

type notstringerarray [4]float64

var notstringerarrayv notstringerarray

var nonemptyinterface = interface {
	f()
}(nil)

// A data type we can print with "%d".
type percentDStruct struct {
	a int
	b []byte
	c *float64
}

var percentDV percentDStruct

// A data type we cannot print correctly with "%d".
type notPercentDStruct struct {
	a int
	b []byte
	c bool
}

var notPercentDV notPercentDStruct

// A data type we can print with "%s".
type percentSStruct struct {
	a string
	b []byte
	C stringerarray
}

var percentSV percentSStruct

type recursiveStringer int

func (s recursiveStringer) String() string {
	_ = fmt.Sprintf("%d", s)
	_ = fmt.Sprintf("%#v", s)
	_ = fmt.Sprintf("%v", s)  // ERROR "Sprintf format %v with arg s causes recursive .*String method call"
	_ = fmt.Sprintf("%v", &s) // ERROR "Sprintf format %v with arg &s causes recursive .*String method call"
	_ = fmt.Sprintf("%T", s)  // ok; does not recursively call String
	return fmt.Sprintln(s)    // ERROR "Sprintln arg s causes recursive call to .*String method"
}

type recursivePtrStringer int

func (p *recursivePtrStringer) String() string {
	_ = fmt.Sprintf("%v", *p)
	_ = fmt.Sprint(&p)     // ok; prints address
	return fmt.Sprintln(p) // ERROR "Sprintln arg p causes recursive call to .*String method"
}

type BoolFormatter bool

func (*BoolFormatter) Format(fmt.State, rune) {
}

// Formatter with value receiver
type FormatterVal bool

func (FormatterVal) Format(fmt.State, rune) {
}

type RecursiveSlice []RecursiveSlice

var recursiveSliceV = &RecursiveSlice{}

type RecursiveMap map[int]RecursiveMap

var recursiveMapV = make(RecursiveMap)

type RecursiveStruct struct {
	next *RecursiveStruct
}

var recursiveStructV = &RecursiveStruct{}

type RecursiveStruct1 struct {
	next *RecursiveStruct2
}

type RecursiveStruct2 struct {
	next *RecursiveStruct1
}

var recursiveStruct1V = &RecursiveStruct1{}

type unexportedInterface struct {
	f interface{}
}

// Issue 17798: unexported ptrStringer cannot be formatted.
type unexportedStringer struct {
	t ptrStringer
}
type unexportedStringerOtherFields struct {
	s string
	t ptrStringer
	S string
}

// Issue 17798: unexported error cannot be formatted.
type unexportedError struct {
	e error
}
type unexportedErrorOtherFields struct {
	s string
	e error
	S string
}

type errorer struct{}

func (e errorer) Error() string { return "errorer" }

type unexportedCustomError struct {
	e errorer
}

type errorInterface interface {
	error
	ExtraMethod()
}

type unexportedErrorInterface struct {
	e errorInterface
}

func UnexportedStringerOrError() {
	fmt.Printf("%s", unexportedInterface{"foo"}) // ok; prints {foo}
	fmt.Printf("%s", unexportedInterface{3})     // ok; we can't see the problem

	us := unexportedStringer{}
	fmt.Printf("%s", us)  // ERROR "Printf format %s has arg us of wrong type .*print.unexportedStringer"
	fmt.Printf("%s", &us) // ERROR "Printf format %s has arg &us of wrong type [*].*print.unexportedStringer"

	usf := unexportedStringerOtherFields{
		s: "foo",
		S: "bar",
	}
	fmt.Printf("%s", usf)  // ERROR "Printf format %s has arg usf of wrong type .*print.unexportedStringerOtherFields"
	fmt.Printf("%s", &usf) // ERROR "Printf format %s has arg &usf of wrong type [*].*print.unexportedStringerOtherFields"

	ue := unexportedError{
		e: &errorer{},
	}
	fmt.Printf("%s", ue)  // ERROR "Printf format %s has arg ue of wrong type .*print.unexportedError"
	fmt.Printf("%s", &ue) // ERROR "Printf format %s has arg &ue of wrong type [*].*print.unexportedError"

	uef := unexportedErrorOtherFields{
		s: "foo",
		e: &errorer{},
		S: "bar",
	}
	fmt.Printf("%s", uef)  // ERROR "Printf format %s has arg uef of wrong type .*print.unexportedErrorOtherFields"
	fmt.Printf("%s", &uef) // ERROR "Printf format %s has arg &uef of wrong type [*].*print.unexportedErrorOtherFields"

	uce := unexportedCustomError{
		e: errorer{},
	}
	fmt.Printf("%s", uce) // ERROR "Printf format %s has arg uce of wrong type .*print.unexportedCustomError"

	uei := unexportedErrorInterface{}
	fmt.Printf("%s", uei)       // ERROR "Printf format %s has arg uei of wrong type .*print.unexportedErrorInterface"
	fmt.Println("foo\n", "bar") // not an error

	fmt.Println("foo\n")  // ERROR "Println arg list ends with redundant newline"
	fmt.Println("foo\\n") // not an error
	fmt.Println(`foo\n`)  // not an error

	intSlice := []int{3, 4}
	fmt.Printf("%s", intSlice) // ERROR "Printf format %s has arg intSlice of wrong type \[\]int"
	nonStringerArray := [1]unexportedStringer{{}}
	fmt.Printf("%s", nonStringerArray)  // ERROR "Printf format %s has arg nonStringerArray of wrong type \[1\].*print.unexportedStringer"
	fmt.Printf("%s", []stringer{3, 4})  // not an error
	fmt.Printf("%s", [2]stringer{3, 4}) // not an error
}

// TODO: Disable complaint about '0' for Go 1.10. To be fixed properly in 1.11.
// See issues 23598 and 23605.
func DisableErrorForFlag0() {
	fmt.Printf("%0t", true)
}

// Issue 26486.
func dbg(format string, args ...interface{}) {
	if format == "" {
		format = "%v"
	}
	fmt.Printf(format, args...)
}

func PointersToCompoundTypes() {
	stringSlice := []string{"a", "b"}
	fmt.Printf("%s", &stringSlice) // not an error

	intSlice := []int{3, 4}
	fmt.Printf("%s", &intSlice) // ERROR "Printf format %s has arg &intSlice of wrong type \*\[\]int"

	stringArray := [2]string{"a", "b"}
	fmt.Printf("%s", &stringArray) // not an error

	intArray := [2]int{3, 4}
	fmt.Printf("%s", &intArray) // ERROR "Printf format %s has arg &intArray of wrong type \*\[2\]int"

	stringStruct := struct{ F string }{"foo"}
	fmt.Printf("%s", &stringStruct) // not an error

	intStruct := struct{ F int }{3}
	fmt.Printf("%s", &intStruct) // ERROR "Printf format %s has arg &intStruct of wrong type \*struct{F int}"

	stringMap := map[string]string{"foo": "bar"}
	fmt.Printf("%s", &stringMap) // not an error

	intMap := map[int]int{3: 4}
	fmt.Printf("%s", &intMap) // ERROR "Printf format %s has arg &intMap of wrong type \*map\[int\]int"

	type T2 struct {
		X string
	}
	type T1 struct {
		X *T2
	}
	fmt.Printf("%s\n", T1{&T2{"x"}}) // ERROR "Printf format %s has arg T1{&T2{.x.}} of wrong type .*print\.T1"
}
```