Response:
Let's break down the thought process for analyzing the provided Go code snippet.

**1. Initial Understanding: The File Path and Purpose**

The first crucial piece of information is the file path: `go/src/runtime/error.go`. This immediately tells us a few things:

* **`runtime` package:** This is part of Go's core runtime, dealing with fundamental aspects of program execution. Errors handled here are likely low-level and critical.
* **`error.go`:**  The name strongly suggests this file defines error-related structures and functions.

Therefore, the primary goal will be to identify the different types of errors defined and how they are represented.

**2. Scanning for Key Structures and Interfaces**

The next step is to scan the code for important keywords and patterns:

* **`interface`:** The `Error` interface stands out immediately. It defines the contract for runtime errors. The `RuntimeError()` method is particularly interesting – it's a marker interface to distinguish runtime errors from regular errors.
* **`struct`:**  Look for defined structs. `TypeAssertionError`, `errorString`, `errorAddressString`, `plainError`, and `boundsError` are the main data structures representing specific error conditions.
* **Method implementations:** Pay attention to methods associated with these structs, particularly `Error()` (which fulfills the standard `error` interface) and `RuntimeError()` (fulfilling the `Error` interface).
* **Constants:**  `boundsErrorCode` and its constants (`boundsIndex`, `boundsSliceAlen`, etc.) indicate different subtypes of bounds errors.
* **Global variables:** `boundsErrorFmts` and `boundsNegErrorFmts` are used for formatting error messages.
* **Functions:**  `itoa`, `appendIntStr`, `printpanicval`, `printanycustomtype`, `printindented`, and `panicwrap` are the standalone functions. Their names provide hints about their roles.

**3. Analyzing Each Struct and its Methods**

* **`Error` interface:**  As mentioned, this is the core definition. The key takeaway is the `RuntimeError()` method.
* **`TypeAssertionError`:** This clearly relates to failed type assertions. The fields (`_interface`, `concrete`, `asserted`, `missingMethod`) provide details about the types involved. The `Error()` method formats a human-readable error message explaining the failure.
* **`errorString`:**  A simple wrapper around a string to represent a basic runtime error.
* **`errorAddressString`:**  Similar to `errorString`, but includes a memory address. The comment about `runtime/debug.SetPanicOnFault` provides important context – this error type is used in specific debugging scenarios. The `Addr()` method exposes the address.
* **`plainError`:**  A subtle variation of `errorString` that omits the "runtime error: " prefix. The comment mentioning issue #14965 suggests a specific reason for its existence.
* **`boundsError`:** This is the most complex struct, dealing with out-of-bounds errors during indexing and slicing. The `x` and `y` fields represent the involved indices/lengths, `signed` indicates signedness, and `code` specifies the type of bounds error. The `Error()` method uses the `boundsErrorFmts` and `boundsNegErrorFmts` to construct the error message.

**4. Analyzing the Functions**

* **`itoa`:**  A simple integer-to-ASCII conversion function. The `//go:nosplit` comment is a hint about its low-level nature and potential performance sensitivity.
* **`appendIntStr`:**  Appends an integer (handling signedness) to a byte slice. Used by `boundsError.Error()`.
* **`printpanicval`:**  Handles printing the value passed to `panic()`. It has special handling for different data types and calls `printindented` for strings.
* **`printanycustomtype`:**  A helper function for `printpanicval` to print custom types, including their type information.
* **`printindented`:**  Replaces newlines with newline and a tab, likely for better readability in stack traces or logs.
* **`panicwrap`:**  This function is quite interesting. It's called when a method on a nil pointer receiver is invoked. The code dissects the function name to create a specific error message. The comment "It is called from the generated wrapper code" is a key insight into its purpose.

**5. Inferring Go Language Features**

Based on the analysis, we can infer the following Go language features being implemented:

* **Interfaces:** The `Error` interface and its use are fundamental to Go's error handling.
* **Type Assertions:** `TypeAssertionError` directly implements the mechanism for handling failed type assertions.
* **Panic and Recover:** The `printpanicval` function strongly suggests the code is involved in the panic mechanism. The different error types defined here are the kinds of errors that can lead to a panic.
* **Slices and Arrays:** The `boundsError` struct is directly tied to how Go handles slice and array access, including bounds checking.
* **Method Calls on Nil Receivers:** `panicwrap` shows how Go handles the specific case of calling a method on a nil pointer.

**6. Developing Examples (Mental or Coded)**

At this stage, it's helpful to think of concrete Go code examples that would trigger these errors:

* **Type Assertion Error:**  An example of trying to assert an interface to a concrete type it doesn't implement.
* **Bounds Error:** Examples of out-of-range slice or array access.
* **Panic with different types:** Examples of calling `panic()` with various data types.
* **Method Call on Nil Receiver:** Creating a nil pointer to a struct and then calling a method on it.

**7. Identifying Potential User Errors**

Think about common mistakes Go developers make related to these error types:

* Incorrect type assertions.
* Off-by-one errors when accessing slices or arrays.
* Not checking for nil pointers before calling methods.

**8. Structuring the Answer**

Finally, organize the findings into a clear and structured answer, addressing each part of the prompt:

* **List of Features:** Summarize the functionality of each struct and function.
* **Go Language Feature Implementation:**  Explain which Go language features are being implemented, providing code examples.
* **Code Reasoning with Input/Output:** If a function's logic isn't immediately obvious (like `panicwrap`), include an explanation of its purpose and how it manipulates strings.
* **Command-line Arguments:**  If any part of the code hinted at command-line arguments (though this snippet doesn't), that would be addressed.
* **Common Mistakes:** Provide examples of common errors related to the implemented features.

By following this systematic approach, we can effectively analyze and understand the provided Go code snippet and generate a comprehensive answer. The key is to break down the code into smaller pieces, understand the purpose of each piece, and then connect it back to the broader context of the Go runtime and language features.
这段代码是 Go 语言运行时环境 `runtime` 包中 `error.go` 文件的一部分，它定义了 Go 语言中运行时错误相关的结构体和接口。其主要功能如下：

1. **定义了 `Error` 接口:**  这是所有运行时错误的根接口，它继承了标准的 `error` 接口，并添加了一个空方法 `RuntimeError()`。这个方法的主要作用是**标识一个类型为运行时错误**，与普通的 `error` 类型区分开来。任何实现了 `RuntimeError()` 方法的类型都被认为是运行时错误。

2. **定义了 `TypeAssertionError` 结构体:**  用于表示类型断言失败的错误。它包含了断言失败时涉及的接口类型 (`_interface`)、具体类型 (`concrete`)、被断言的类型 (`asserted`) 以及如果是因为缺少方法导致的失败，则会记录缺失的方法名 (`missingMethod`)。 `Error()` 方法会根据这些信息生成详细的错误消息。

3. **定义了 `errorString` 结构体:**  用于表示一个简单的运行时错误，它只包含一个错误字符串。 `Error()` 方法返回带有 "runtime error: " 前缀的错误消息。

4. **定义了 `errorAddressString` 结构体:**  类似于 `errorString`，但额外存储了错误发生的内存地址 (`addr`)。`Error()` 方法返回带有 "runtime error: " 前缀的错误消息。它还实现了 `Addr()` 方法，用于返回错误发生的内存地址。这个通常用于调试，可以通过 `runtime/debug.SetPanicOnFault` 启用。

5. **定义了 `plainError` 结构体:**  类似于 `errorString`，但其 `Error()` 方法返回的错误消息**不包含** "runtime error: " 前缀。这可能用于某些特定的错误输出场景，需要更简洁的错误信息。

6. **定义了 `boundsError` 结构体:**  用于表示索引或切片操作越界的错误。它包含了越界的索引值 (`x`)、长度/容量值 (`y`)、一个表示 `x` 是否为有符号数的布尔值 (`signed`) 以及一个表示具体越界错误类型的枚举值 (`code`)。 `Error()` 方法会根据这些信息生成详细的越界错误消息。

7. **定义了辅助函数 `itoa`:**  用于将无符号整数转换为十进制字符串表示。这是一个底层的、无栈分裂优化的函数，用于构建错误消息。

8. **定义了辅助函数 `appendIntStr`:** 用于将整数（有符号或无符号）添加到字节切片中，用于构建 `boundsError` 的错误消息。

9. **定义了与 `panic` 相关的打印函数 `printpanicval`, `printanycustomtype`, `printindented`:** 这些函数用于打印传递给 `panic` 的值。它们会根据值的类型进行格式化输出，并对字符串进行特殊处理以避免与堆栈跟踪信息混淆。

10. **定义了 `panicwrap` 函数:**  这个函数用于处理当调用一个值方法时，接收者是一个 nil 指针的情况。它会提取包名、类型名和方法名，并生成一个清晰的 panic 错误消息。

**推理它是什么 go 语言功能的实现：**

这段代码主要实现了 Go 语言的 **运行时错误处理机制** 和 **panic 机制** 的一部分。

**Go 代码举例说明：**

**1. 类型断言错误 (`TypeAssertionError`)**

```go
package main

import "fmt"

type MyInterface interface {
	DoSomething()
}

type MyConcreteType struct{}

func (m MyConcreteType) DoSomething() {}

type AnotherType struct{}

func main() {
	var i MyInterface
	i = MyConcreteType{}

	// 假设我们错误地尝试将 i 断言为 AnotherType
	_, ok := i.(AnotherType)
	if !ok {
		// 实际运行时会 panic 并抛出 TypeAssertionError
		fmt.Println("类型断言失败")
	}
}
```

**假设输入与输出：**

如果上述代码运行，因为 `MyConcreteType` 没有实现 `AnotherType` 的任何方法（实际上 `AnotherType` 是一个空结构体），类型断言会失败。虽然代码中我们检查了 `ok`，但在 panic 的场景下，如果没有 recover，将会抛出一个 `runtime.TypeAssertionError`。

**输出 (panic 信息，如果没有 recover):**

```
panic: interface conversion: main.MyInterface is main.MyConcreteType, not main.AnotherType
```

**2. 索引越界错误 (`boundsError`)**

```go
package main

import "fmt"

func main() {
	arr := [3]int{1, 2, 3}
	// 尝试访问超出数组边界的索引
	_ = arr[5]
}
```

**假设输入与输出：**

上述代码尝试访问 `arr` 的索引 5，而 `arr` 的有效索引是 0, 1, 2。

**输出 (panic 信息):**

```
panic: runtime error: index out of range [5] with length 3
```

**3. 切片越界错误 (`boundsError`)**

```go
package main

import "fmt"

func main() {
	s := []int{1, 2, 3}
	// 尝试创建超出切片容量的切片
	_ = s[:5]
}
```

**假设输入与输出：**

上述代码尝试创建一个从头开始到索引 5 的切片，但 `s` 的长度和容量都只有 3。

**输出 (panic 信息):**

```
panic: runtime error: slice bounds out of range [:5] with length 3
```

**4. 调用 nil 指针的方法 (`plainError` 由 `panicwrap` 生成)**

```go
package main

import "fmt"

type MyStruct struct {
	Value int
}

func (m *MyStruct) PrintValue() {
	fmt.Println(m.Value)
}

func main() {
	var s *MyStruct
	// 尝试调用 nil 指针的方法
	s.PrintValue()
}
```

**假设输入与输出：**

上述代码中 `s` 是一个 `*MyStruct` 类型的 nil 指针，尝试调用 `PrintValue` 方法会触发 panic。

**输出 (panic 信息):**

```
panic: value method main.(*MyStruct).PrintValue called using nil *main.MyStruct pointer
```

**命令行参数的具体处理：**

这段代码本身并不直接处理命令行参数。命令行参数的处理通常在 `main` 包的 `main` 函数中，使用 `os.Args` 获取，或者使用 `flag` 包进行解析。  `runtime` 包主要关注程序运行时的底层行为。

**使用者易犯错的点：**

1. **类型断言错误：**  在进行类型断言时，没有使用“comma ok idiom”（`,` ok`) 来检查断言是否成功，直接使用断言后的值，当断言失败时会导致 panic。

   ```go
   package main

   import "fmt"

   type MyInterface interface {
   	DoSomething()
   }

   type MyConcreteType struct{}

   func (m MyConcreteType) DoSomething() {}

   type AnotherType struct{}

   func main() {
   	var i MyInterface = MyConcreteType{}
   	// 易错：没有检查断言是否成功
   	concrete := i.(AnotherType) // 如果 i 的实际类型不是 AnotherType，会 panic
   	fmt.Println(concrete)
   }
   ```

2. **索引/切片越界：**  在访问数组、切片或字符串的元素时，索引超出了有效范围。尤其是在循环或动态计算索引时容易出现。

   ```go
   package main

   import "fmt"

   func main() {
   	s := []int{1, 2, 3}
   	for i := 0; i <= len(s); i++ { // 错误：循环条件应该是 i < len(s)
   		fmt.Println(s[i]) // 当 i == 3 时，会发生越界
   	}
   }
   ```

3. **调用 nil 指针的方法：**  在没有进行 nil 检查的情况下，调用指针类型的方法，如果指针是 nil，会导致 panic。

   ```go
   package main

   import "fmt"

   type MyStruct struct {
   	Value int
   }

   func (m *MyStruct) PrintValue() {
   	fmt.Println(m.Value)
   }

   func main() {
   	var s *MyStruct
   	// 易错：没有进行 nil 检查
   	s.PrintValue() // 如果 s 为 nil，会 panic
   }
   ```

总而言之，`go/src/runtime/error.go` 文件定义了 Go 语言运行时错误的关键类型和机制，为 Go 程序的稳定运行提供了基础保障。了解这些错误类型可以帮助开发者更好地理解和处理程序中可能出现的运行时错误。

### 提示词
```
这是路径为go/src/runtime/error.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
```

### 源代码
```go
// Copyright 2010 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package runtime

import (
	"internal/abi"
	"internal/bytealg"
	"internal/runtime/sys"
)

// The Error interface identifies a run time error.
type Error interface {
	error

	// RuntimeError is a no-op function but
	// serves to distinguish types that are run time
	// errors from ordinary errors: a type is a
	// run time error if it has a RuntimeError method.
	RuntimeError()
}

// A TypeAssertionError explains a failed type assertion.
type TypeAssertionError struct {
	_interface    *_type
	concrete      *_type
	asserted      *_type
	missingMethod string // one method needed by Interface, missing from Concrete
}

func (*TypeAssertionError) RuntimeError() {}

func (e *TypeAssertionError) Error() string {
	inter := "interface"
	if e._interface != nil {
		inter = toRType(e._interface).string()
	}
	as := toRType(e.asserted).string()
	if e.concrete == nil {
		return "interface conversion: " + inter + " is nil, not " + as
	}
	cs := toRType(e.concrete).string()
	if e.missingMethod == "" {
		msg := "interface conversion: " + inter + " is " + cs + ", not " + as
		if cs == as {
			// provide slightly clearer error message
			if toRType(e.concrete).pkgpath() != toRType(e.asserted).pkgpath() {
				msg += " (types from different packages)"
			} else {
				msg += " (types from different scopes)"
			}
		}
		return msg
	}
	return "interface conversion: " + cs + " is not " + as +
		": missing method " + e.missingMethod
}

// itoa converts val to a decimal representation. The result is
// written somewhere within buf and the location of the result is returned.
// buf must be at least 20 bytes.
//
//go:nosplit
func itoa(buf []byte, val uint64) []byte {
	i := len(buf) - 1
	for val >= 10 {
		buf[i] = byte(val%10 + '0')
		i--
		val /= 10
	}
	buf[i] = byte(val + '0')
	return buf[i:]
}

// An errorString represents a runtime error described by a single string.
type errorString string

func (e errorString) RuntimeError() {}

func (e errorString) Error() string {
	return "runtime error: " + string(e)
}

type errorAddressString struct {
	msg  string  // error message
	addr uintptr // memory address where the error occurred
}

func (e errorAddressString) RuntimeError() {}

func (e errorAddressString) Error() string {
	return "runtime error: " + e.msg
}

// Addr returns the memory address where a fault occurred.
// The address provided is best-effort.
// The veracity of the result may depend on the platform.
// Errors providing this method will only be returned as
// a result of using [runtime/debug.SetPanicOnFault].
func (e errorAddressString) Addr() uintptr {
	return e.addr
}

// plainError represents a runtime error described a string without
// the prefix "runtime error: " after invoking errorString.Error().
// See Issue #14965.
type plainError string

func (e plainError) RuntimeError() {}

func (e plainError) Error() string {
	return string(e)
}

// A boundsError represents an indexing or slicing operation gone wrong.
type boundsError struct {
	x int64
	y int
	// Values in an index or slice expression can be signed or unsigned.
	// That means we'd need 65 bits to encode all possible indexes, from -2^63 to 2^64-1.
	// Instead, we keep track of whether x should be interpreted as signed or unsigned.
	// y is known to be nonnegative and to fit in an int.
	signed bool
	code   boundsErrorCode
}

type boundsErrorCode uint8

const (
	boundsIndex boundsErrorCode = iota // s[x], 0 <= x < len(s) failed

	boundsSliceAlen // s[?:x], 0 <= x <= len(s) failed
	boundsSliceAcap // s[?:x], 0 <= x <= cap(s) failed
	boundsSliceB    // s[x:y], 0 <= x <= y failed (but boundsSliceA didn't happen)

	boundsSlice3Alen // s[?:?:x], 0 <= x <= len(s) failed
	boundsSlice3Acap // s[?:?:x], 0 <= x <= cap(s) failed
	boundsSlice3B    // s[?:x:y], 0 <= x <= y failed (but boundsSlice3A didn't happen)
	boundsSlice3C    // s[x:y:?], 0 <= x <= y failed (but boundsSlice3A/B didn't happen)

	boundsConvert // (*[x]T)(s), 0 <= x <= len(s) failed
	// Note: in the above, len(s) and cap(s) are stored in y
)

// boundsErrorFmts provide error text for various out-of-bounds panics.
// Note: if you change these strings, you should adjust the size of the buffer
// in boundsError.Error below as well.
var boundsErrorFmts = [...]string{
	boundsIndex:      "index out of range [%x] with length %y",
	boundsSliceAlen:  "slice bounds out of range [:%x] with length %y",
	boundsSliceAcap:  "slice bounds out of range [:%x] with capacity %y",
	boundsSliceB:     "slice bounds out of range [%x:%y]",
	boundsSlice3Alen: "slice bounds out of range [::%x] with length %y",
	boundsSlice3Acap: "slice bounds out of range [::%x] with capacity %y",
	boundsSlice3B:    "slice bounds out of range [:%x:%y]",
	boundsSlice3C:    "slice bounds out of range [%x:%y:]",
	boundsConvert:    "cannot convert slice with length %y to array or pointer to array with length %x",
}

// boundsNegErrorFmts are overriding formats if x is negative. In this case there's no need to report y.
var boundsNegErrorFmts = [...]string{
	boundsIndex:      "index out of range [%x]",
	boundsSliceAlen:  "slice bounds out of range [:%x]",
	boundsSliceAcap:  "slice bounds out of range [:%x]",
	boundsSliceB:     "slice bounds out of range [%x:]",
	boundsSlice3Alen: "slice bounds out of range [::%x]",
	boundsSlice3Acap: "slice bounds out of range [::%x]",
	boundsSlice3B:    "slice bounds out of range [:%x:]",
	boundsSlice3C:    "slice bounds out of range [%x::]",
}

func (e boundsError) RuntimeError() {}

func appendIntStr(b []byte, v int64, signed bool) []byte {
	if signed && v < 0 {
		b = append(b, '-')
		v = -v
	}
	var buf [20]byte
	b = append(b, itoa(buf[:], uint64(v))...)
	return b
}

func (e boundsError) Error() string {
	fmt := boundsErrorFmts[e.code]
	if e.signed && e.x < 0 {
		fmt = boundsNegErrorFmts[e.code]
	}
	// max message length is 99: "runtime error: slice bounds out of range [::%x] with capacity %y"
	// x can be at most 20 characters. y can be at most 19.
	b := make([]byte, 0, 100)
	b = append(b, "runtime error: "...)
	for i := 0; i < len(fmt); i++ {
		c := fmt[i]
		if c != '%' {
			b = append(b, c)
			continue
		}
		i++
		switch fmt[i] {
		case 'x':
			b = appendIntStr(b, e.x, e.signed)
		case 'y':
			b = appendIntStr(b, int64(e.y), true)
		}
	}
	return string(b)
}

type stringer interface {
	String() string
}

// printpanicval prints an argument passed to panic.
// If panic is called with a value that has a String or Error method,
// it has already been converted into a string by preprintpanics.
//
// To ensure that the traceback can be unambiguously parsed even when
// the panic value contains "\ngoroutine" and other stack-like
// strings, newlines in the string representation of v are replaced by
// "\n\t".
func printpanicval(v any) {
	switch v := v.(type) {
	case nil:
		print("nil")
	case bool:
		print(v)
	case int:
		print(v)
	case int8:
		print(v)
	case int16:
		print(v)
	case int32:
		print(v)
	case int64:
		print(v)
	case uint:
		print(v)
	case uint8:
		print(v)
	case uint16:
		print(v)
	case uint32:
		print(v)
	case uint64:
		print(v)
	case uintptr:
		print(v)
	case float32:
		print(v)
	case float64:
		print(v)
	case complex64:
		print(v)
	case complex128:
		print(v)
	case string:
		printindented(v)
	default:
		printanycustomtype(v)
	}
}

// Invariant: each newline in the string representation is followed by a tab.
func printanycustomtype(i any) {
	eface := efaceOf(&i)
	typestring := toRType(eface._type).string()

	switch eface._type.Kind_ {
	case abi.String:
		print(typestring, `("`)
		printindented(*(*string)(eface.data))
		print(`")`)
	case abi.Bool:
		print(typestring, "(", *(*bool)(eface.data), ")")
	case abi.Int:
		print(typestring, "(", *(*int)(eface.data), ")")
	case abi.Int8:
		print(typestring, "(", *(*int8)(eface.data), ")")
	case abi.Int16:
		print(typestring, "(", *(*int16)(eface.data), ")")
	case abi.Int32:
		print(typestring, "(", *(*int32)(eface.data), ")")
	case abi.Int64:
		print(typestring, "(", *(*int64)(eface.data), ")")
	case abi.Uint:
		print(typestring, "(", *(*uint)(eface.data), ")")
	case abi.Uint8:
		print(typestring, "(", *(*uint8)(eface.data), ")")
	case abi.Uint16:
		print(typestring, "(", *(*uint16)(eface.data), ")")
	case abi.Uint32:
		print(typestring, "(", *(*uint32)(eface.data), ")")
	case abi.Uint64:
		print(typestring, "(", *(*uint64)(eface.data), ")")
	case abi.Uintptr:
		print(typestring, "(", *(*uintptr)(eface.data), ")")
	case abi.Float32:
		print(typestring, "(", *(*float32)(eface.data), ")")
	case abi.Float64:
		print(typestring, "(", *(*float64)(eface.data), ")")
	case abi.Complex64:
		print(typestring, *(*complex64)(eface.data))
	case abi.Complex128:
		print(typestring, *(*complex128)(eface.data))
	default:
		print("(", typestring, ") ", eface.data)
	}
}

// printindented prints s, replacing "\n" with "\n\t".
func printindented(s string) {
	for {
		i := bytealg.IndexByteString(s, '\n')
		if i < 0 {
			break
		}
		i += len("\n")
		print(s[:i])
		print("\t")
		s = s[i:]
	}
	print(s)
}

// panicwrap generates a panic for a call to a wrapped value method
// with a nil pointer receiver.
//
// It is called from the generated wrapper code.
func panicwrap() {
	pc := sys.GetCallerPC()
	name := funcNameForPrint(funcname(findfunc(pc)))
	// name is something like "main.(*T).F".
	// We want to extract pkg ("main"), typ ("T"), and meth ("F").
	// Do it by finding the parens.
	i := bytealg.IndexByteString(name, '(')
	if i < 0 {
		throw("panicwrap: no ( in " + name)
	}
	pkg := name[:i-1]
	if i+2 >= len(name) || name[i-1:i+2] != ".(*" {
		throw("panicwrap: unexpected string after package name: " + name)
	}
	name = name[i+2:]
	i = bytealg.IndexByteString(name, ')')
	if i < 0 {
		throw("panicwrap: no ) in " + name)
	}
	if i+2 >= len(name) || name[i:i+2] != ")." {
		throw("panicwrap: unexpected string after type name: " + name)
	}
	typ := name[:i]
	meth := name[i+2:]
	panic(plainError("value method " + pkg + "." + typ + "." + meth + " called using nil *" + typ + " pointer"))
}
```