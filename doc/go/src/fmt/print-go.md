Response:
Let's break down the thought process for analyzing the `go/src/fmt/print.go` code snippet.

**1. Initial Scan and Identifying Key Structures:**

The first step is a quick read-through to get a high-level understanding. I look for:

* **Package and Imports:**  The `package fmt` and the imports (`internal/fmtsort`, `io`, `os`, `reflect`, `strconv`, `sync`, `unicode/utf8`). This immediately tells me it's the core formatting package, dealing with input/output, reflection, string conversion, concurrency, and Unicode.
* **Constants:** The `const` block defines various string constants used for formatting errors and special cases (like `<nil>`). This suggests error handling and specific string representations.
* **Interfaces:**  The `State`, `Formatter`, `Stringer`, and `GoStringer` interfaces are crucial. They define how custom types can interact with the formatting logic. I note their purpose based on the comments.
* **Structs:** The `buffer` and `pp` structs are important. `buffer` seems to be a simple byte buffer. `pp` looks like the core printer state, holding arguments, reflection values, and formatting flags. The `sync.Pool` for `ppFree` suggests optimization through object reuse.
* **Key Functions:** The `Fprintf`, `Printf`, `Sprintf`, `Fprint`, `Print`, `Sprint`, `Fprintln`, `Println`, `Sprintln`, and `Append` family of functions stand out. Their names clearly indicate their purpose: formatted and unformatted printing to different destinations (writer, stdout, string, byte slice).

**2. Deeper Dive into Core Functionality:**

Now, I start to understand *how* the formatting works.

* **`State` Interface:** This interface allows custom formatters to access the output writer, width, precision, and flags. It's the bridge between the `fmt` package and custom formatting logic.
* **`Formatter`, `Stringer`, `GoStringer`:** These interfaces represent different ways a type can customize its string representation. `Formatter` has the most control, `Stringer` provides a "native" string, and `GoStringer` provides Go syntax. The order of checking these interfaces in `handleMethods` is important.
* **`pp` Struct:** I realize this struct is the heart of the formatting process. It stores the state, including the output buffer, current argument, formatting parameters, and error flags. The use of a `sync.Pool` is an optimization to reduce garbage collection.
* **`doPrintf`:** This function is the core logic for handling formatted printing. It iterates through the format string, parses verbs and flags, and then calls `printArg` to format individual arguments. The handling of argument indexing (`[n]`) is also done here.
* **`doPrint`, `doPrintln`:** These handle unformatted printing, adding spaces or spaces and newlines as needed.
* **`printArg`, `printValue`:** These functions determine how to format a single argument, handling different types and invoking methods like `String`, `GoString`, and `Format`. Reflection is heavily used here.
* **Helper Functions:** Functions like `parsenum`, `intFromArg`, `parseArgNumber`, `getField`, `tooLarge` are utility functions that support the main formatting logic.

**3. Inferring Go Language Features and Examples:**

Based on the function names and the way they are used, I can infer the Go language features being implemented:

* **Formatted Output (Printf, Sprintf, Fprintf):**  This is the core functionality. I need to demonstrate formatting verbs (`%d`, `%s`, `%v`, etc.), flags (`#`, `0`, `-`, `+`, ` `), width, and precision.
* **Unformatted Output (Print, Sprint, Fprint):** I need to show how these functions print values with default formatting and add spaces.
* **Output with Newline (Println, Sprintln, Fprintln):**  Demonstrate the automatic newline addition.
* **Custom Formatting (Formatter Interface):** This is a key feature. I need an example of a type that implements the `Formatter` interface and how it's used with `Printf`.
* **String Conversion (Stringer Interface):**  Show a type implementing `String()` and how `Print` and `%s` use it.
* **Go Syntax Representation (GoStringer Interface):** Demonstrate `GoString()` and its use with `%#v`.

For each example, I consider:

* **Input:** What are the values being passed to the printing function?
* **Format String (if applicable):** What formatting directives are used?
* **Expected Output:** What should the printed string be?

**4. Identifying Potential Pitfalls:**

By examining the code and understanding how formatting works, I can identify common mistakes:

* **Incorrect Formatting Verbs:**  Using the wrong verb for a given type (e.g., `%d` for a string). The `badVerb` function confirms this is handled.
* **Missing Arguments:** Providing fewer arguments than specified in the format string. The `missingArg` function and the logic in `doPrintf` handle this.
* **Incorrect Argument Indexing:**  Using `[n]` incorrectly or with out-of-bounds indices. The `badArgNum` function and the `argNumber` logic deal with this.
* **Panic in Stringer/GoStringer/Formatter:**  The `catchPanic` function suggests this is a possibility. I need to demonstrate a case where a custom `String()` method panics.
* **Ignoring Return Values:**  Not checking the `n` (bytes written) and `err` values from the `Fprint` family of functions. While not directly demonstrated in the *provided* code, it's a general good practice for I/O operations.
* **Mixing Formatted and Unformatted Printing Incorrectly:**  Not understanding when spaces are added automatically.

**5. Structuring the Answer:**

Finally, I organize the information in a clear and structured way, using headings and bullet points, as requested by the prompt. I provide code examples with input and expected output for each feature and pitfall. I use Chinese for the explanations as specified.

**Self-Correction/Refinement during the Process:**

* **Initially, I might focus too much on the low-level buffer manipulation.** I need to shift my focus to the higher-level functionality exposed by the `fmt` package.
* **I might overlook the `GoStringer` interface.**  A careful review of the interfaces and their usage will correct this.
* **I might not immediately grasp the significance of the `State` interface.** Understanding that it's for *custom* formatters is key.
* **For pitfalls, I might initially think of obscure edge cases.** I should focus on the most common and easily reproducible errors.

By following this structured approach, I can systematically analyze the code snippet and provide a comprehensive and accurate answer to the prompt.
这段代码是 Go 语言标准库 `fmt` 包中 `print.go` 文件的一部分，它实现了 Go 语言中基本的格式化输出功能。 让我们逐一列举它的功能并进行推理和代码示例。

**功能列表:**

1. **定义了用于格式化输出的常量字符串:**  例如 `commaSpaceString` (", ")， `nilAngleString` ("<nil>") 等，用于在格式化过程中插入特定的文本。
2. **定义了格式化状态接口 `State`:**  该接口定义了传递给自定义格式化器的打印状态，包括写入输出、获取宽度和精度、检查标志等方法。
3. **定义了自定义格式化接口 `Formatter`:**  任何实现了 `Format(f State, verb rune)` 方法的类型都可以自定义其格式化输出的方式。
4. **定义了字符串化接口 `Stringer`:**  任何实现了 `String() string` 方法的类型，其 `String()` 方法的返回值会被用于默认的字符串格式化。
5. **定义了 Go 语法字符串化接口 `GoStringer`:** 任何实现了 `GoString() string` 方法的类型，其 `GoString()` 方法的返回值会被用于 `%#v` 格式的格式化。
6. **提供了 `FormatString` 函数:**  该函数根据 `State` 和 verb 构造出完整的格式化指令字符串（例如 "%+10.2f"）。
7. **实现了基于 `[]byte` 的缓冲区 `buffer`:** 用于高效地构建格式化后的字符串。
8. **定义了 `pp` 结构体:**  该结构体是打印器的核心状态，包含缓冲区、当前参数、反射值、格式化选项等信息，并使用 `sync.Pool` 进行复用以减少内存分配。
9. **提供了创建和释放 `pp` 结构体的函数 `newPrinter` 和 `free`:**  用于管理打印器的生命周期。
10. **实现了 `State` 接口的方法:**  `Width`, `Precision`, `Flag` 等方法允许访问 `pp` 结构体中存储的格式化选项。
11. **实现了 `io.Writer` 和 `io.StringWriter` 接口:**  使得 `pp` 结构体可以作为 `Fprintf` 等函数的写入目标。
12. **实现了各种格式化输出函数:**
    * `Fprintf(w io.Writer, format string, a ...any)`:  将根据格式字符串格式化后的输出写入 `io.Writer`。
    * `Printf(format string, a ...any)`: 将根据格式字符串格式化后的输出写入标准输出。
    * `Sprintf(format string, a ...any)`:  将根据格式字符串格式化后的输出返回字符串。
    * `Appendf(b []byte, format string, a ...any)`:  将根据格式字符串格式化后的输出追加到字节切片。
    * `Fprint(w io.Writer, a ...any)`: 将使用默认格式的输出写入 `io.Writer`，并在操作数之间添加空格（如果两者都不是字符串）。
    * `Print(a ...any)`: 将使用默认格式的输出写入标准输出，并在操作数之间添加空格（如果两者都不是字符串）。
    * `Sprint(a ...any)`: 将使用默认格式的输出返回字符串，并在操作数之间添加空格（如果两者都不是字符串）。
    * `Append(b []byte, a ...any)`: 将使用默认格式的输出追加到字节切片，并在操作数之间添加空格（如果两者都不是字符串）。
    * `Fprintln(w io.Writer, a ...any)`: 将使用默认格式的输出写入 `io.Writer`，总是在操作数之间添加空格，并在最后添加换行符。
    * `Println(a ...any)`: 将使用默认格式的输出写入标准输出，总是在操作数之间添加空格，并在最后添加换行符。
    * `Sprintln(a ...any)`: 将使用默认格式的输出返回字符串，总是在操作数之间添加空格，并在最后添加换行符。
    * `Appendln(b []byte, a ...any)`: 将使用默认格式的输出追加到字节切片，总是在操作数之间添加空格，并在最后添加换行符。
13. **实现了 `getField` 函数:**  用于获取结构体中指定字段的值，并处理接口类型的字段。
14. **实现了 `tooLarge` 函数:**  判断整数是否过大，用于限制宽度和精度的值。
15. **实现了 `parsenum` 函数:**  将字符串的一部分解析为整数。
16. **实现了处理未知类型的 `unknownType` 函数。**
17. **实现了处理非法动词的 `badVerb` 函数。**
18. **实现了针对不同数据类型的格式化函数:** `fmtBool`, `fmt0x64`, `fmtInteger`, `fmtFloat`, `fmtComplex`, `fmtString`, `fmtBytes`, `fmtPointer` 等，用于根据不同的格式动词 (`%d`, `%s`, `%f` 等) 对不同类型的值进行格式化。
19. **实现了 `catchPanic` 函数:**  用于捕获在调用 `String`, `GoString`, `Format` 方法时可能发生的 panic，并输出包含 panic 信息的字符串，避免程序崩溃。
20. **实现了 `handleMethods` 函数:**  用于检查参数是否实现了 `Formatter`, `GoStringer`, `Stringer` 接口，并调用相应的方法进行格式化。这是实现自定义格式化的关键。
21. **实现了核心的参数打印函数 `printArg`:**  根据参数的类型和格式动词调用相应的格式化函数或接口方法。
22. **实现了处理反射值的打印函数 `printValue`:**  用于格式化通过反射获取的值。
23. **实现了从参数列表中获取整数的 `intFromArg` 函数:** 用于处理宽度和精度等参数。
24. **实现了 `parseArgNumber` 函数:** 用于解析格式字符串中的显式参数索引（例如 `[1]`）。
25. **实现了 `argNumber` 函数:** 用于获取下一个要处理的参数的索引。
26. **实现了处理错误的参数索引和缺失参数的函数:** `badArgNum`, `missingArg`。
27. **实现了核心的格式化处理函数 `doPrintf`:**  该函数是格式化输出的核心逻辑，负责解析格式字符串，提取格式化选项，并调用相应的打印函数。它处理了各种格式化动词、标志、宽度、精度以及参数索引。
28. **实现了非格式化打印函数 `doPrint`:**  用于处理 `Print`, `Fprint`, `Sprint` 等函数，简单地将参数转换为字符串并输出，并在非字符串参数之间添加空格。
29. **实现了带换行符的非格式化打印函数 `doPrintln`:**  与 `doPrint` 类似，但总是在参数之间添加空格，并在最后添加换行符。

**推理出的 Go 语言功能实现及代码示例:**

这段代码的核心功能是实现 Go 语言的格式化输出，这主要体现在 `fmt.Printf`、`fmt.Sprintf`、`fmt.Println` 等一系列函数中。

**示例 1: 使用 `Printf` 进行格式化输出**

```go
package main

import "fmt"

func main() {
	name := "Alice"
	age := 30
	fmt.Printf("My name is %s and I am %d years old.\n", name, age)
	// 假设的输出: My name is Alice and I am 30 years old.

	price := 99.99
	fmt.Printf("The price is %.2f dollars.\n", price)
	// 假设的输出: The price is 99.99 dollars.

	fmt.Printf("Value: %v, Type: %T\n", age, age)
	// 假设的输出: Value: 30, Type: int
}
```

**假设的输入与输出:**

在上面的代码中，输入是变量 `name` 和 `age` 以及格式字符串。`Printf` 函数会根据格式字符串中的 `%s` 和 `%d` 将这些变量的值格式化并输出到标准输出。

**示例 2: 使用 `Sprintf` 格式化字符串**

```go
package main

import "fmt"

func main() {
	message := fmt.Sprintf("The answer is %d.", 42)
	fmt.Println(message)
	// 假设的输出: The answer is 42.
}
```

**假设的输入与输出:**

`Sprintf` 函数接收格式字符串和参数，并返回格式化后的字符串。在这个例子中，输入是格式字符串 `"The answer is %d."` 和整数 `42`，输出是字符串 `"The answer is 42."`。

**示例 3: 实现 `Stringer` 接口进行自定义格式化**

```go
package main

import "fmt"

type Point struct {
	X, Y int
}

func (p Point) String() string {
	return fmt.Sprintf("(%d, %d)", p.X, p.Y)
}

func main() {
	point := Point{X: 1, Y: 2}
	fmt.Println(point) // 默认使用 String() 方法
	// 假设的输出: (1, 2)
	fmt.Printf("Point: %s\n", point) // 显式使用 %s 格式化动词
	// 假设的输出: Point: (1, 2)
}
```

**假设的输入与输出:**

`Point` 结构体实现了 `String()` 方法。当 `fmt.Println` 或 `%s` 遇到 `Point` 类型的值时，会调用 `String()` 方法来获取其字符串表示。

**示例 4: 实现 `Formatter` 接口进行更精细的格式化控制**

```go
package main

import (
	"fmt"
	"io"
)

type Color struct {
	R, G, B uint8
}

func (c Color) Format(f fmt.State, verb rune) {
	switch verb {
	case 'v':
		if f.Flag('#') {
			fmt.Fprintf(f, "Color{R:%d, G:%d, B:%d}", c.R, c.G, c.B)
			return
		}
		fallthrough
	case 's':
		fmt.Fprintf(f, "#%02x%02x%02x", c.R, c.G, c.B)
	default:
		fmt.Fprintf(f, "%%!%c(Color=%#v)", verb, c)
	}
}

func main() {
	color := Color{R: 255, G: 0, B: 0}
	fmt.Printf("Color: %v\n", color)
	// 假设的输出: Color: #ff0000
	fmt.Printf("Color: %#v\n", color)
	// 假设的输出: Color: Color{R:255, G:0, B:0}
	fmt.Printf("Color: %s\n", color)
	// 假设的输出: Color: #ff0000
	fmt.Printf("Color: %x\n", color) // 未知 verb
	// 假设的输出: Color: %!x(Color=main.Color{R:0xff, G:0x0, B:0x0})
}
```

**假设的输入与输出:**

`Color` 结构体实现了 `Format` 方法。该方法根据不同的格式动词和标志 (`#`) 提供不同的格式化输出。

**命令行参数的具体处理:**

这段代码本身并不直接处理命令行参数。命令行参数的处理通常发生在 `main` 函数中，并可以使用 `os.Args` 获取。 `fmt` 包的格式化功能可以用于输出与命令行参数相关的信息。

**使用者易犯错的点:**

1. **格式化动词与参数类型不匹配:**  例如，使用 `%d` 格式化字符串，或者使用 `%s` 格式化整数。这会导致输出不符合预期，甚至可能引发 panic。

   ```go
   package main

   import "fmt"

   func main() {
       name := 123
       fmt.Printf("Name: %s\n", name) // 错误: %s 期望字符串类型
       // 假设的输出: Name: %!s(int=123)
   }
   ```

2. **忘记提供足够的参数:** 格式字符串中使用了占位符，但没有提供相应的参数。

   ```go
   package main

   import "fmt"

   func main() {
       fmt.Printf("Hello, %s and %s!\n", "World") // 缺少一个参数
       // 假设的输出: Hello, World and %!s(MISSING)!
   }
   ```

3. **错误理解格式化标志:**  例如，不清楚 `#`, `0`, `-`, `+`, ` ` 等标志的作用。

   ```go
   package main

   import "fmt"

   func main() {
       num := 10
       fmt.Printf("%#x\n", num)  // 输出带有 "0x" 前缀的十六进制
       // 假设的输出: 0xa
       fmt.Printf("%04d\n", num) // 输出前导零填充的四位十进制数
       // 假设的输出: 0010
   }
   ```

4. **精度和宽度的使用不当:**  例如，对不支持精度的类型使用精度，或者宽度和精度的值不合理。

   ```go
   package main

   import "fmt"

   func main() {
       str := "hello"
       fmt.Printf("%.2s\n", str) // 对字符串使用精度，只输出前两个字符
       // 假设的输出: he
       num := 123.456
       fmt.Printf("%6.1f\n", num) // 总宽度为 6，小数点后一位
       // 假设的输出:  123.5
   }
   ```

5. **在自定义 `Stringer` 或 `GoStringer` 方法中发生 panic:**  如果 `String()` 或 `GoString()` 方法内部发生 panic，`fmt` 包会捕获并输出错误信息，但开发者应该避免这种情况。

   ```go
   package main

   import "fmt"

   type BadStringer struct{}

   func (b BadStringer) String() string {
       panic("oops!")
   }

   func main() {
       bs := BadStringer{}
       fmt.Println(bs)
       // 假设的输出: (PANIC=String method: oops!)
   }
   ```

理解 `fmt` 包的实现原理有助于更好地使用 Go 语言的格式化输出功能，并避免常见的错误。

Prompt: 
```
这是路径为go/src/fmt/print.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。

"""
// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package fmt

import (
	"internal/fmtsort"
	"io"
	"os"
	"reflect"
	"strconv"
	"sync"
	"unicode/utf8"
)

// Strings for use with buffer.WriteString.
// This is less overhead than using buffer.Write with byte arrays.
const (
	commaSpaceString  = ", "
	nilAngleString    = "<nil>"
	nilParenString    = "(nil)"
	nilString         = "nil"
	mapString         = "map["
	percentBangString = "%!"
	missingString     = "(MISSING)"
	badIndexString    = "(BADINDEX)"
	panicString       = "(PANIC="
	extraString       = "%!(EXTRA "
	badWidthString    = "%!(BADWIDTH)"
	badPrecString     = "%!(BADPREC)"
	noVerbString      = "%!(NOVERB)"
	invReflectString  = "<invalid reflect.Value>"
)

// State represents the printer state passed to custom formatters.
// It provides access to the [io.Writer] interface plus information about
// the flags and options for the operand's format specifier.
type State interface {
	// Write is the function to call to emit formatted output to be printed.
	Write(b []byte) (n int, err error)
	// Width returns the value of the width option and whether it has been set.
	Width() (wid int, ok bool)
	// Precision returns the value of the precision option and whether it has been set.
	Precision() (prec int, ok bool)

	// Flag reports whether the flag c, a character, has been set.
	Flag(c int) bool
}

// Formatter is implemented by any value that has a Format method.
// The implementation controls how [State] and rune are interpreted,
// and may call [Sprint] or [Fprint](f) etc. to generate its output.
type Formatter interface {
	Format(f State, verb rune)
}

// Stringer is implemented by any value that has a String method,
// which defines the “native” format for that value.
// The String method is used to print values passed as an operand
// to any format that accepts a string or to an unformatted printer
// such as [Print].
type Stringer interface {
	String() string
}

// GoStringer is implemented by any value that has a GoString method,
// which defines the Go syntax for that value.
// The GoString method is used to print values passed as an operand
// to a %#v format.
type GoStringer interface {
	GoString() string
}

// FormatString returns a string representing the fully qualified formatting
// directive captured by the [State], followed by the argument verb. ([State] does not
// itself contain the verb.) The result has a leading percent sign followed by any
// flags, the width, and the precision. Missing flags, width, and precision are
// omitted. This function allows a [Formatter] to reconstruct the original
// directive triggering the call to Format.
func FormatString(state State, verb rune) string {
	var tmp [16]byte // Use a local buffer.
	b := append(tmp[:0], '%')
	for _, c := range " +-#0" { // All known flags
		if state.Flag(int(c)) { // The argument is an int for historical reasons.
			b = append(b, byte(c))
		}
	}
	if w, ok := state.Width(); ok {
		b = strconv.AppendInt(b, int64(w), 10)
	}
	if p, ok := state.Precision(); ok {
		b = append(b, '.')
		b = strconv.AppendInt(b, int64(p), 10)
	}
	b = utf8.AppendRune(b, verb)
	return string(b)
}

// Use simple []byte instead of bytes.Buffer to avoid large dependency.
type buffer []byte

func (b *buffer) write(p []byte) {
	*b = append(*b, p...)
}

func (b *buffer) writeString(s string) {
	*b = append(*b, s...)
}

func (b *buffer) writeByte(c byte) {
	*b = append(*b, c)
}

func (b *buffer) writeRune(r rune) {
	*b = utf8.AppendRune(*b, r)
}

// pp is used to store a printer's state and is reused with sync.Pool to avoid allocations.
type pp struct {
	buf buffer

	// arg holds the current item, as an interface{}.
	arg any

	// value is used instead of arg for reflect values.
	value reflect.Value

	// fmt is used to format basic items such as integers or strings.
	fmt fmt

	// reordered records whether the format string used argument reordering.
	reordered bool
	// goodArgNum records whether the most recent reordering directive was valid.
	goodArgNum bool
	// panicking is set by catchPanic to avoid infinite panic, recover, panic, ... recursion.
	panicking bool
	// erroring is set when printing an error string to guard against calling handleMethods.
	erroring bool
	// wrapErrs is set when the format string may contain a %w verb.
	wrapErrs bool
	// wrappedErrs records the targets of the %w verb.
	wrappedErrs []int
}

var ppFree = sync.Pool{
	New: func() any { return new(pp) },
}

// newPrinter allocates a new pp struct or grabs a cached one.
func newPrinter() *pp {
	p := ppFree.Get().(*pp)
	p.panicking = false
	p.erroring = false
	p.wrapErrs = false
	p.fmt.init(&p.buf)
	return p
}

// free saves used pp structs in ppFree; avoids an allocation per invocation.
func (p *pp) free() {
	// Proper usage of a sync.Pool requires each entry to have approximately
	// the same memory cost. To obtain this property when the stored type
	// contains a variably-sized buffer, we add a hard limit on the maximum
	// buffer to place back in the pool. If the buffer is larger than the
	// limit, we drop the buffer and recycle just the printer.
	//
	// See https://golang.org/issue/23199.
	if cap(p.buf) > 64*1024 {
		p.buf = nil
	} else {
		p.buf = p.buf[:0]
	}
	if cap(p.wrappedErrs) > 8 {
		p.wrappedErrs = nil
	}

	p.arg = nil
	p.value = reflect.Value{}
	p.wrappedErrs = p.wrappedErrs[:0]
	ppFree.Put(p)
}

func (p *pp) Width() (wid int, ok bool) { return p.fmt.wid, p.fmt.widPresent }

func (p *pp) Precision() (prec int, ok bool) { return p.fmt.prec, p.fmt.precPresent }

func (p *pp) Flag(b int) bool {
	switch b {
	case '-':
		return p.fmt.minus
	case '+':
		return p.fmt.plus || p.fmt.plusV
	case '#':
		return p.fmt.sharp || p.fmt.sharpV
	case ' ':
		return p.fmt.space
	case '0':
		return p.fmt.zero
	}
	return false
}

// Write implements [io.Writer] so we can call [Fprintf] on a pp (through [State]), for
// recursive use in custom verbs.
func (p *pp) Write(b []byte) (ret int, err error) {
	p.buf.write(b)
	return len(b), nil
}

// WriteString implements [io.StringWriter] so that we can call [io.WriteString]
// on a pp (through state), for efficiency.
func (p *pp) WriteString(s string) (ret int, err error) {
	p.buf.writeString(s)
	return len(s), nil
}

// These routines end in 'f' and take a format string.

// Fprintf formats according to a format specifier and writes to w.
// It returns the number of bytes written and any write error encountered.
func Fprintf(w io.Writer, format string, a ...any) (n int, err error) {
	p := newPrinter()
	p.doPrintf(format, a)
	n, err = w.Write(p.buf)
	p.free()
	return
}

// Printf formats according to a format specifier and writes to standard output.
// It returns the number of bytes written and any write error encountered.
func Printf(format string, a ...any) (n int, err error) {
	return Fprintf(os.Stdout, format, a...)
}

// Sprintf formats according to a format specifier and returns the resulting string.
func Sprintf(format string, a ...any) string {
	p := newPrinter()
	p.doPrintf(format, a)
	s := string(p.buf)
	p.free()
	return s
}

// Appendf formats according to a format specifier, appends the result to the byte
// slice, and returns the updated slice.
func Appendf(b []byte, format string, a ...any) []byte {
	p := newPrinter()
	p.doPrintf(format, a)
	b = append(b, p.buf...)
	p.free()
	return b
}

// These routines do not take a format string

// Fprint formats using the default formats for its operands and writes to w.
// Spaces are added between operands when neither is a string.
// It returns the number of bytes written and any write error encountered.
func Fprint(w io.Writer, a ...any) (n int, err error) {
	p := newPrinter()
	p.doPrint(a)
	n, err = w.Write(p.buf)
	p.free()
	return
}

// Print formats using the default formats for its operands and writes to standard output.
// Spaces are added between operands when neither is a string.
// It returns the number of bytes written and any write error encountered.
func Print(a ...any) (n int, err error) {
	return Fprint(os.Stdout, a...)
}

// Sprint formats using the default formats for its operands and returns the resulting string.
// Spaces are added between operands when neither is a string.
func Sprint(a ...any) string {
	p := newPrinter()
	p.doPrint(a)
	s := string(p.buf)
	p.free()
	return s
}

// Append formats using the default formats for its operands, appends the result to
// the byte slice, and returns the updated slice.
func Append(b []byte, a ...any) []byte {
	p := newPrinter()
	p.doPrint(a)
	b = append(b, p.buf...)
	p.free()
	return b
}

// These routines end in 'ln', do not take a format string,
// always add spaces between operands, and add a newline
// after the last operand.

// Fprintln formats using the default formats for its operands and writes to w.
// Spaces are always added between operands and a newline is appended.
// It returns the number of bytes written and any write error encountered.
func Fprintln(w io.Writer, a ...any) (n int, err error) {
	p := newPrinter()
	p.doPrintln(a)
	n, err = w.Write(p.buf)
	p.free()
	return
}

// Println formats using the default formats for its operands and writes to standard output.
// Spaces are always added between operands and a newline is appended.
// It returns the number of bytes written and any write error encountered.
func Println(a ...any) (n int, err error) {
	return Fprintln(os.Stdout, a...)
}

// Sprintln formats using the default formats for its operands and returns the resulting string.
// Spaces are always added between operands and a newline is appended.
func Sprintln(a ...any) string {
	p := newPrinter()
	p.doPrintln(a)
	s := string(p.buf)
	p.free()
	return s
}

// Appendln formats using the default formats for its operands, appends the result
// to the byte slice, and returns the updated slice. Spaces are always added
// between operands and a newline is appended.
func Appendln(b []byte, a ...any) []byte {
	p := newPrinter()
	p.doPrintln(a)
	b = append(b, p.buf...)
	p.free()
	return b
}

// getField gets the i'th field of the struct value.
// If the field itself is a non-nil interface, return a value for
// the thing inside the interface, not the interface itself.
func getField(v reflect.Value, i int) reflect.Value {
	val := v.Field(i)
	if val.Kind() == reflect.Interface && !val.IsNil() {
		val = val.Elem()
	}
	return val
}

// tooLarge reports whether the magnitude of the integer is
// too large to be used as a formatting width or precision.
func tooLarge(x int) bool {
	const max int = 1e6
	return x > max || x < -max
}

// parsenum converts ASCII to integer.  num is 0 (and isnum is false) if no number present.
func parsenum(s string, start, end int) (num int, isnum bool, newi int) {
	if start >= end {
		return 0, false, end
	}
	for newi = start; newi < end && '0' <= s[newi] && s[newi] <= '9'; newi++ {
		if tooLarge(num) {
			return 0, false, end // Overflow; crazy long number most likely.
		}
		num = num*10 + int(s[newi]-'0')
		isnum = true
	}
	return
}

func (p *pp) unknownType(v reflect.Value) {
	if !v.IsValid() {
		p.buf.writeString(nilAngleString)
		return
	}
	p.buf.writeByte('?')
	p.buf.writeString(v.Type().String())
	p.buf.writeByte('?')
}

func (p *pp) badVerb(verb rune) {
	p.erroring = true
	p.buf.writeString(percentBangString)
	p.buf.writeRune(verb)
	p.buf.writeByte('(')
	switch {
	case p.arg != nil:
		p.buf.writeString(reflect.TypeOf(p.arg).String())
		p.buf.writeByte('=')
		p.printArg(p.arg, 'v')
	case p.value.IsValid():
		p.buf.writeString(p.value.Type().String())
		p.buf.writeByte('=')
		p.printValue(p.value, 'v', 0)
	default:
		p.buf.writeString(nilAngleString)
	}
	p.buf.writeByte(')')
	p.erroring = false
}

func (p *pp) fmtBool(v bool, verb rune) {
	switch verb {
	case 't', 'v':
		p.fmt.fmtBoolean(v)
	default:
		p.badVerb(verb)
	}
}

// fmt0x64 formats a uint64 in hexadecimal and prefixes it with 0x or
// not, as requested, by temporarily setting the sharp flag.
func (p *pp) fmt0x64(v uint64, leading0x bool) {
	sharp := p.fmt.sharp
	p.fmt.sharp = leading0x
	p.fmt.fmtInteger(v, 16, unsigned, 'v', ldigits)
	p.fmt.sharp = sharp
}

// fmtInteger formats a signed or unsigned integer.
func (p *pp) fmtInteger(v uint64, isSigned bool, verb rune) {
	switch verb {
	case 'v':
		if p.fmt.sharpV && !isSigned {
			p.fmt0x64(v, true)
		} else {
			p.fmt.fmtInteger(v, 10, isSigned, verb, ldigits)
		}
	case 'd':
		p.fmt.fmtInteger(v, 10, isSigned, verb, ldigits)
	case 'b':
		p.fmt.fmtInteger(v, 2, isSigned, verb, ldigits)
	case 'o', 'O':
		p.fmt.fmtInteger(v, 8, isSigned, verb, ldigits)
	case 'x':
		p.fmt.fmtInteger(v, 16, isSigned, verb, ldigits)
	case 'X':
		p.fmt.fmtInteger(v, 16, isSigned, verb, udigits)
	case 'c':
		p.fmt.fmtC(v)
	case 'q':
		p.fmt.fmtQc(v)
	case 'U':
		p.fmt.fmtUnicode(v)
	default:
		p.badVerb(verb)
	}
}

// fmtFloat formats a float. The default precision for each verb
// is specified as last argument in the call to fmt_float.
func (p *pp) fmtFloat(v float64, size int, verb rune) {
	switch verb {
	case 'v':
		p.fmt.fmtFloat(v, size, 'g', -1)
	case 'b', 'g', 'G', 'x', 'X':
		p.fmt.fmtFloat(v, size, verb, -1)
	case 'f', 'e', 'E':
		p.fmt.fmtFloat(v, size, verb, 6)
	case 'F':
		p.fmt.fmtFloat(v, size, 'f', 6)
	default:
		p.badVerb(verb)
	}
}

// fmtComplex formats a complex number v with
// r = real(v) and j = imag(v) as (r+ji) using
// fmtFloat for r and j formatting.
func (p *pp) fmtComplex(v complex128, size int, verb rune) {
	// Make sure any unsupported verbs are found before the
	// calls to fmtFloat to not generate an incorrect error string.
	switch verb {
	case 'v', 'b', 'g', 'G', 'x', 'X', 'f', 'F', 'e', 'E':
		oldPlus := p.fmt.plus
		p.buf.writeByte('(')
		p.fmtFloat(real(v), size/2, verb)
		// Imaginary part always has a sign.
		p.fmt.plus = true
		p.fmtFloat(imag(v), size/2, verb)
		p.buf.writeString("i)")
		p.fmt.plus = oldPlus
	default:
		p.badVerb(verb)
	}
}

func (p *pp) fmtString(v string, verb rune) {
	switch verb {
	case 'v':
		if p.fmt.sharpV {
			p.fmt.fmtQ(v)
		} else {
			p.fmt.fmtS(v)
		}
	case 's':
		p.fmt.fmtS(v)
	case 'x':
		p.fmt.fmtSx(v, ldigits)
	case 'X':
		p.fmt.fmtSx(v, udigits)
	case 'q':
		p.fmt.fmtQ(v)
	default:
		p.badVerb(verb)
	}
}

func (p *pp) fmtBytes(v []byte, verb rune, typeString string) {
	switch verb {
	case 'v', 'd':
		if p.fmt.sharpV {
			p.buf.writeString(typeString)
			if v == nil {
				p.buf.writeString(nilParenString)
				return
			}
			p.buf.writeByte('{')
			for i, c := range v {
				if i > 0 {
					p.buf.writeString(commaSpaceString)
				}
				p.fmt0x64(uint64(c), true)
			}
			p.buf.writeByte('}')
		} else {
			p.buf.writeByte('[')
			for i, c := range v {
				if i > 0 {
					p.buf.writeByte(' ')
				}
				p.fmt.fmtInteger(uint64(c), 10, unsigned, verb, ldigits)
			}
			p.buf.writeByte(']')
		}
	case 's':
		p.fmt.fmtBs(v)
	case 'x':
		p.fmt.fmtBx(v, ldigits)
	case 'X':
		p.fmt.fmtBx(v, udigits)
	case 'q':
		p.fmt.fmtQ(string(v))
	default:
		p.printValue(reflect.ValueOf(v), verb, 0)
	}
}

func (p *pp) fmtPointer(value reflect.Value, verb rune) {
	var u uintptr
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Map, reflect.Pointer, reflect.Slice, reflect.UnsafePointer:
		u = uintptr(value.UnsafePointer())
	default:
		p.badVerb(verb)
		return
	}

	switch verb {
	case 'v':
		if p.fmt.sharpV {
			p.buf.writeByte('(')
			p.buf.writeString(value.Type().String())
			p.buf.writeString(")(")
			if u == 0 {
				p.buf.writeString(nilString)
			} else {
				p.fmt0x64(uint64(u), true)
			}
			p.buf.writeByte(')')
		} else {
			if u == 0 {
				p.fmt.padString(nilAngleString)
			} else {
				p.fmt0x64(uint64(u), !p.fmt.sharp)
			}
		}
	case 'p':
		p.fmt0x64(uint64(u), !p.fmt.sharp)
	case 'b', 'o', 'd', 'x', 'X':
		p.fmtInteger(uint64(u), unsigned, verb)
	default:
		p.badVerb(verb)
	}
}

func (p *pp) catchPanic(arg any, verb rune, method string) {
	if err := recover(); err != nil {
		// If it's a nil pointer, just say "<nil>". The likeliest causes are a
		// Stringer that fails to guard against nil or a nil pointer for a
		// value receiver, and in either case, "<nil>" is a nice result.
		if v := reflect.ValueOf(arg); v.Kind() == reflect.Pointer && v.IsNil() {
			p.buf.writeString(nilAngleString)
			return
		}
		// Otherwise print a concise panic message. Most of the time the panic
		// value will print itself nicely.
		if p.panicking {
			// Nested panics; the recursion in printArg cannot succeed.
			panic(err)
		}

		oldFlags := p.fmt.fmtFlags
		// For this output we want default behavior.
		p.fmt.clearflags()

		p.buf.writeString(percentBangString)
		p.buf.writeRune(verb)
		p.buf.writeString(panicString)
		p.buf.writeString(method)
		p.buf.writeString(" method: ")
		p.panicking = true
		p.printArg(err, 'v')
		p.panicking = false
		p.buf.writeByte(')')

		p.fmt.fmtFlags = oldFlags
	}
}

func (p *pp) handleMethods(verb rune) (handled bool) {
	if p.erroring {
		return
	}
	if verb == 'w' {
		// It is invalid to use %w other than with Errorf or with a non-error arg.
		_, ok := p.arg.(error)
		if !ok || !p.wrapErrs {
			p.badVerb(verb)
			return true
		}
		// If the arg is a Formatter, pass 'v' as the verb to it.
		verb = 'v'
	}

	// Is it a Formatter?
	if formatter, ok := p.arg.(Formatter); ok {
		handled = true
		defer p.catchPanic(p.arg, verb, "Format")
		formatter.Format(p, verb)
		return
	}

	// If we're doing Go syntax and the argument knows how to supply it, take care of it now.
	if p.fmt.sharpV {
		if stringer, ok := p.arg.(GoStringer); ok {
			handled = true
			defer p.catchPanic(p.arg, verb, "GoString")
			// Print the result of GoString unadorned.
			p.fmt.fmtS(stringer.GoString())
			return
		}
	} else {
		// If a string is acceptable according to the format, see if
		// the value satisfies one of the string-valued interfaces.
		// Println etc. set verb to %v, which is "stringable".
		switch verb {
		case 'v', 's', 'x', 'X', 'q':
			// Is it an error or Stringer?
			// The duplication in the bodies is necessary:
			// setting handled and deferring catchPanic
			// must happen before calling the method.
			switch v := p.arg.(type) {
			case error:
				handled = true
				defer p.catchPanic(p.arg, verb, "Error")
				p.fmtString(v.Error(), verb)
				return

			case Stringer:
				handled = true
				defer p.catchPanic(p.arg, verb, "String")
				p.fmtString(v.String(), verb)
				return
			}
		}
	}
	return false
}

func (p *pp) printArg(arg any, verb rune) {
	p.arg = arg
	p.value = reflect.Value{}

	if arg == nil {
		switch verb {
		case 'T', 'v':
			p.fmt.padString(nilAngleString)
		default:
			p.badVerb(verb)
		}
		return
	}

	// Special processing considerations.
	// %T (the value's type) and %p (its address) are special; we always do them first.
	switch verb {
	case 'T':
		p.fmt.fmtS(reflect.TypeOf(arg).String())
		return
	case 'p':
		p.fmtPointer(reflect.ValueOf(arg), 'p')
		return
	}

	// Some types can be done without reflection.
	switch f := arg.(type) {
	case bool:
		p.fmtBool(f, verb)
	case float32:
		p.fmtFloat(float64(f), 32, verb)
	case float64:
		p.fmtFloat(f, 64, verb)
	case complex64:
		p.fmtComplex(complex128(f), 64, verb)
	case complex128:
		p.fmtComplex(f, 128, verb)
	case int:
		p.fmtInteger(uint64(f), signed, verb)
	case int8:
		p.fmtInteger(uint64(f), signed, verb)
	case int16:
		p.fmtInteger(uint64(f), signed, verb)
	case int32:
		p.fmtInteger(uint64(f), signed, verb)
	case int64:
		p.fmtInteger(uint64(f), signed, verb)
	case uint:
		p.fmtInteger(uint64(f), unsigned, verb)
	case uint8:
		p.fmtInteger(uint64(f), unsigned, verb)
	case uint16:
		p.fmtInteger(uint64(f), unsigned, verb)
	case uint32:
		p.fmtInteger(uint64(f), unsigned, verb)
	case uint64:
		p.fmtInteger(f, unsigned, verb)
	case uintptr:
		p.fmtInteger(uint64(f), unsigned, verb)
	case string:
		p.fmtString(f, verb)
	case []byte:
		p.fmtBytes(f, verb, "[]byte")
	case reflect.Value:
		// Handle extractable values with special methods
		// since printValue does not handle them at depth 0.
		if f.IsValid() && f.CanInterface() {
			p.arg = f.Interface()
			if p.handleMethods(verb) {
				return
			}
		}
		p.printValue(f, verb, 0)
	default:
		// If the type is not simple, it might have methods.
		if !p.handleMethods(verb) {
			// Need to use reflection, since the type had no
			// interface methods that could be used for formatting.
			p.printValue(reflect.ValueOf(f), verb, 0)
		}
	}
}

// printValue is similar to printArg but starts with a reflect value, not an interface{} value.
// It does not handle 'p' and 'T' verbs because these should have been already handled by printArg.
func (p *pp) printValue(value reflect.Value, verb rune, depth int) {
	// Handle values with special methods if not already handled by printArg (depth == 0).
	if depth > 0 && value.IsValid() && value.CanInterface() {
		p.arg = value.Interface()
		if p.handleMethods(verb) {
			return
		}
	}
	p.arg = nil
	p.value = value

	switch f := value; value.Kind() {
	case reflect.Invalid:
		if depth == 0 {
			p.buf.writeString(invReflectString)
		} else {
			switch verb {
			case 'v':
				p.buf.writeString(nilAngleString)
			default:
				p.badVerb(verb)
			}
		}
	case reflect.Bool:
		p.fmtBool(f.Bool(), verb)
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		p.fmtInteger(uint64(f.Int()), signed, verb)
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		p.fmtInteger(f.Uint(), unsigned, verb)
	case reflect.Float32:
		p.fmtFloat(f.Float(), 32, verb)
	case reflect.Float64:
		p.fmtFloat(f.Float(), 64, verb)
	case reflect.Complex64:
		p.fmtComplex(f.Complex(), 64, verb)
	case reflect.Complex128:
		p.fmtComplex(f.Complex(), 128, verb)
	case reflect.String:
		p.fmtString(f.String(), verb)
	case reflect.Map:
		if p.fmt.sharpV {
			p.buf.writeString(f.Type().String())
			if f.IsNil() {
				p.buf.writeString(nilParenString)
				return
			}
			p.buf.writeByte('{')
		} else {
			p.buf.writeString(mapString)
		}
		sorted := fmtsort.Sort(f)
		for i, m := range sorted {
			if i > 0 {
				if p.fmt.sharpV {
					p.buf.writeString(commaSpaceString)
				} else {
					p.buf.writeByte(' ')
				}
			}
			p.printValue(m.Key, verb, depth+1)
			p.buf.writeByte(':')
			p.printValue(m.Value, verb, depth+1)
		}
		if p.fmt.sharpV {
			p.buf.writeByte('}')
		} else {
			p.buf.writeByte(']')
		}
	case reflect.Struct:
		if p.fmt.sharpV {
			p.buf.writeString(f.Type().String())
		}
		p.buf.writeByte('{')
		for i := 0; i < f.NumField(); i++ {
			if i > 0 {
				if p.fmt.sharpV {
					p.buf.writeString(commaSpaceString)
				} else {
					p.buf.writeByte(' ')
				}
			}
			if p.fmt.plusV || p.fmt.sharpV {
				if name := f.Type().Field(i).Name; name != "" {
					p.buf.writeString(name)
					p.buf.writeByte(':')
				}
			}
			p.printValue(getField(f, i), verb, depth+1)
		}
		p.buf.writeByte('}')
	case reflect.Interface:
		value := f.Elem()
		if !value.IsValid() {
			if p.fmt.sharpV {
				p.buf.writeString(f.Type().String())
				p.buf.writeString(nilParenString)
			} else {
				p.buf.writeString(nilAngleString)
			}
		} else {
			p.printValue(value, verb, depth+1)
		}
	case reflect.Array, reflect.Slice:
		switch verb {
		case 's', 'q', 'x', 'X':
			// Handle byte and uint8 slices and arrays special for the above verbs.
			t := f.Type()
			if t.Elem().Kind() == reflect.Uint8 {
				var bytes []byte
				if f.Kind() == reflect.Slice || f.CanAddr() {
					bytes = f.Bytes()
				} else {
					// We have an array, but we cannot Bytes() a non-addressable array,
					// so we build a slice by hand. This is a rare case but it would be nice
					// if reflection could help a little more.
					bytes = make([]byte, f.Len())
					for i := range bytes {
						bytes[i] = byte(f.Index(i).Uint())
					}
				}
				p.fmtBytes(bytes, verb, t.String())
				return
			}
		}
		if p.fmt.sharpV {
			p.buf.writeString(f.Type().String())
			if f.Kind() == reflect.Slice && f.IsNil() {
				p.buf.writeString(nilParenString)
				return
			}
			p.buf.writeByte('{')
			for i := 0; i < f.Len(); i++ {
				if i > 0 {
					p.buf.writeString(commaSpaceString)
				}
				p.printValue(f.Index(i), verb, depth+1)
			}
			p.buf.writeByte('}')
		} else {
			p.buf.writeByte('[')
			for i := 0; i < f.Len(); i++ {
				if i > 0 {
					p.buf.writeByte(' ')
				}
				p.printValue(f.Index(i), verb, depth+1)
			}
			p.buf.writeByte(']')
		}
	case reflect.Pointer:
		// pointer to array or slice or struct? ok at top level
		// but not embedded (avoid loops)
		if depth == 0 && f.UnsafePointer() != nil {
			switch a := f.Elem(); a.Kind() {
			case reflect.Array, reflect.Slice, reflect.Struct, reflect.Map:
				p.buf.writeByte('&')
				p.printValue(a, verb, depth+1)
				return
			}
		}
		fallthrough
	case reflect.Chan, reflect.Func, reflect.UnsafePointer:
		p.fmtPointer(f, verb)
	default:
		p.unknownType(f)
	}
}

// intFromArg gets the argNumth element of a. On return, isInt reports whether the argument has integer type.
func intFromArg(a []any, argNum int) (num int, isInt bool, newArgNum int) {
	newArgNum = argNum
	if argNum < len(a) {
		num, isInt = a[argNum].(int) // Almost always OK.
		if !isInt {
			// Work harder.
			switch v := reflect.ValueOf(a[argNum]); v.Kind() {
			case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
				n := v.Int()
				if int64(int(n)) == n {
					num = int(n)
					isInt = true
				}
			case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
				n := v.Uint()
				if int64(n) >= 0 && uint64(int(n)) == n {
					num = int(n)
					isInt = true
				}
			default:
				// Already 0, false.
			}
		}
		newArgNum = argNum + 1
		if tooLarge(num) {
			num = 0
			isInt = false
		}
	}
	return
}

// parseArgNumber returns the value of the bracketed number, minus 1
// (explicit argument numbers are one-indexed but we want zero-indexed).
// The opening bracket is known to be present at format[0].
// The returned values are the index, the number of bytes to consume
// up to the closing paren, if present, and whether the number parsed
// ok. The bytes to consume will be 1 if no closing paren is present.
func parseArgNumber(format string) (index int, wid int, ok bool) {
	// There must be at least 3 bytes: [n].
	if len(format) < 3 {
		return 0, 1, false
	}

	// Find closing bracket.
	for i := 1; i < len(format); i++ {
		if format[i] == ']' {
			width, ok, newi := parsenum(format, 1, i)
			if !ok || newi != i {
				return 0, i + 1, false
			}
			return width - 1, i + 1, true // arg numbers are one-indexed and skip paren.
		}
	}
	return 0, 1, false
}

// argNumber returns the next argument to evaluate, which is either the value of the passed-in
// argNum or the value of the bracketed integer that begins format[i:]. It also returns
// the new value of i, that is, the index of the next byte of the format to process.
func (p *pp) argNumber(argNum int, format string, i int, numArgs int) (newArgNum, newi int, found bool) {
	if len(format) <= i || format[i] != '[' {
		return argNum, i, false
	}
	p.reordered = true
	index, wid, ok := parseArgNumber(format[i:])
	if ok && 0 <= index && index < numArgs {
		return index, i + wid, true
	}
	p.goodArgNum = false
	return argNum, i + wid, ok
}

func (p *pp) badArgNum(verb rune) {
	p.buf.writeString(percentBangString)
	p.buf.writeRune(verb)
	p.buf.writeString(badIndexString)
}

func (p *pp) missingArg(verb rune) {
	p.buf.writeString(percentBangString)
	p.buf.writeRune(verb)
	p.buf.writeString(missingString)
}

func (p *pp) doPrintf(format string, a []any) {
	end := len(format)
	argNum := 0         // we process one argument per non-trivial format
	afterIndex := false // previous item in format was an index like [3].
	p.reordered = false
formatLoop:
	for i := 0; i < end; {
		p.goodArgNum = true
		lasti := i
		for i < end && format[i] != '%' {
			i++
		}
		if i > lasti {
			p.buf.writeString(format[lasti:i])
		}
		if i >= end {
			// done processing format string
			break
		}

		// Process one verb
		i++

		// Do we have flags?
		p.fmt.clearflags()
	simpleFormat:
		for ; i < end; i++ {
			c := format[i]
			switch c {
			case '#':
				p.fmt.sharp = true
			case '0':
				p.fmt.zero = true
			case '+':
				p.fmt.plus = true
			case '-':
				p.fmt.minus = true
			case ' ':
				p.fmt.space = true
			default:
				// Fast path for common case of ascii lower case simple verbs
				// without precision or width or argument indices.
				if 'a' <= c && c <= 'z' && argNum < len(a) {
					switch c {
					case 'w':
						p.wrappedErrs = append(p.wrappedErrs, argNum)
						fallthrough
					case 'v':
						// Go syntax
						p.fmt.sharpV = p.fmt.sharp
						p.fmt.sharp = false
						// Struct-field syntax
						p.fmt.plusV = p.fmt.plus
						p.fmt.plus = false
					}
					p.printArg(a[argNum], rune(c))
					argNum++
					i++
					continue formatLoop
				}
				// Format is more complex than simple flags and a verb or is malformed.
				break simpleFormat
			}
		}

		// Do we have an explicit argument index?
		argNum, i, afterIndex = p.argNumber(argNum, format, i, len(a))

		// Do we have width?
		if i < end && format[i] == '*' {
			i++
			p.fmt.wid, p.fmt.widPresent, argNum = intFromArg(a, argNum)

			if !p.fmt.widPresent {
				p.buf.writeString(badWidthString)
			}

			// We have a negative width, so take its value and ensure
			// that the minus flag is set
			if p.fmt.wid < 0 {
				p.fmt.wid = -p.fmt.wid
				p.fmt.minus = true
				p.fmt.zero = false // Do not pad with zeros to the right.
			}
			afterIndex = false
		} else {
			p.fmt.wid, p.fmt.widPresent, i = parsenum(format, i, end)
			if afterIndex && p.fmt.widPresent { // "%[3]2d"
				p.goodArgNum = false
			}
		}

		// Do we have precision?
		if i+1 < end && format[i] == '.' {
			i++
			if afterIndex { // "%[3].2d"
				p.goodArgNum = false
			}
			argNum, i, afterIndex = p.argNumber(argNum, format, i, len(a))
			if i < end && format[i] == '*' {
				i++
				p.fmt.prec, p.fmt.precPresent, argNum = intFromArg(a, argNum)
				// Negative precision arguments don't make sense
				if p.fmt.prec < 0 {
					p.fmt.prec = 0
					p.fmt.precPresent = false
				}
				if !p.fmt.precPresent {
					p.buf.writeString(badPrecString)
				}
				afterIndex = false
			} else {
				p.fmt.prec, p.fmt.precPresent, i = parsenum(format, i, end)
				if !p.fmt.precPresent {
					p.fmt.prec = 0
					p.fmt.precPresent = true
				}
			}
		}

		if !afterIndex {
			argNum, i, afterIndex = p.argNumber(argNum, format, i, len(a))
		}

		if i >= end {
			p.buf.writeString(noVerbString)
			break
		}

		verb, size := rune(format[i]), 1
		if verb >= utf8.RuneSelf {
			verb, size = utf8.DecodeRuneInString(format[i:])
		}
		i += size

		switch {
		case verb == '%': // Percent does not absorb operands and ignores f.wid and f.prec.
			p.buf.writeByte('%')
		case !p.goodArgNum:
			p.badArgNum(verb)
		case argNum >= len(a): // No argument left over to print for the current verb.
			p.missingArg(verb)
		case verb == 'w':
			p.wrappedErrs = append(p.wrappedErrs, argNum)
			fallthrough
		case verb == 'v':
			// Go syntax
			p.fmt.sharpV = p.fmt.sharp
			p.fmt.sharp = false
			// Struct-field syntax
			p.fmt.plusV = p.fmt.plus
			p.fmt.plus = false
			fallthrough
		default:
			p.printArg(a[argNum], verb)
			argNum++
		}
	}

	// Check for extra arguments unless the call accessed the arguments
	// out of order, in which case it's too expensive to detect if they've all
	// been used and arguably OK if they're not.
	if !p.reordered && argNum < len(a) {
		p.fmt.clearflags()
		p.buf.writeString(extraString)
		for i, arg := range a[argNum:] {
			if i > 0 {
				p.buf.writeString(commaSpaceString)
			}
			if arg == nil {
				p.buf.writeString(nilAngleString)
			} else {
				p.buf.writeString(reflect.TypeOf(arg).String())
				p.buf.writeByte('=')
				p.printArg(arg, 'v')
			}
		}
		p.buf.writeByte(')')
	}
}

func (p *pp) doPrint(a []any) {
	prevString := false
	for argNum, arg := range a {
		isString := arg != nil && reflect.TypeOf(arg).Kind() == reflect.String
		// Add a space between two non-string arguments.
		if argNum > 0 && !isString && !prevString {
			p.buf.writeByte(' ')
		}
		p.printArg(arg, 'v')
		prevString = isString
	}
}

// doPrintln is like doPrint but always adds a space between arguments
// and a newline after the last argument.
func (p *pp) doPrintln(a []any) {
	for argNum, arg := range a {
		if argNum > 0 {
			p.buf.writeByte(' ')
		}
		p.printArg(arg, 'v')
	}
	p.buf.writeByte('\n')
}

"""



```