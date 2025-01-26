Response:
Let's break down the thought process for answering the request about `go/src/builtin/builtin.go`.

**1. Understanding the Core Request:**

The central task is to analyze the provided Go code and describe its functionality. Key constraints include providing Go code examples, specifying input/output for code reasoning, explaining command-line arguments (if applicable), and highlighting potential user errors. The answer needs to be in Chinese.

**2. Initial Analysis of the Code:**

The first thing to notice is the package comment: `"Package builtin provides documentation for Go's predeclared identifiers."` This is a crucial clue. It tells us this file isn't defining the *implementation* of these identifiers but rather providing documentation *about* them for tools like `godoc`. This immediately clarifies the core function.

**3. Categorizing the Content:**

Scanning the code reveals several distinct categories of content:

* **Basic Types:** `bool`, `uint8`, `int`, `string`, etc. These are fundamental Go types.
* **Type Aliases:** `byte = uint8`, `rune = int32`, `any = interface{}`. These provide alternative names for existing types.
* **Special Identifiers:** `true`, `false`, `iota`, `nil`. These are language-level constants and a zero value.
* **Interface:** `comparable`, `error`. These define interfaces.
* **Placeholder Types:** `Type`, `Type1`, `IntegerType`, etc. The comments clearly state these are for documentation purposes.
* **Built-in Functions:** `append`, `copy`, `len`, `make`, `panic`, etc. These are core Go functions.

**4. Deconstructing Each Category:**

* **Basic Types:**  The description for each type clearly states its range or definition. No complex logic here, just definitions.
* **Type Aliases:**  These are straightforward substitutions. Their purpose is often for clarity or convention.
* **Special Identifiers:**
    * `true`/`false`:  Defined using comparisons, highlighting their boolean nature.
    * `iota`: Explained as an ordinal number within `const` blocks. An example is needed to demonstrate its use.
    * `nil`: Described as the zero value for specific types.
* **Interfaces:**  `comparable` has a special constraint (only usable as a type parameter constraint). `error` is the standard error interface.
* **Placeholder Types:**  Important to note their purpose is *only* for documentation. Don't try to use them directly in actual Go code.
* **Built-in Functions:** For each function:
    * Describe its purpose.
    * Provide a simple Go code example illustrating its usage. Crucially, show input and expected output.
    * If a function has specific behavior or edge cases (like `append` with strings or `delete` on `nil` maps), mention them.
    * Consider potential mistakes users might make (e.g., not assigning the result of `append`).

**5. Addressing Specific Request Points:**

* **Functionality Listing:**  Summarize the roles of the file (documenting predeclared identifiers).
* **Go Code Examples:** For each built-in function and `iota`, create short, illustrative code snippets. Include `main` function for executability.
* **Input/Output for Code Reasoning:**  Explicitly state the input values and the expected output for each code example. This clarifies the function's effect.
* **Command-Line Arguments:**  This file itself doesn't handle command-line arguments. Explicitly state this.
* **User Errors:**  Focus on common pitfalls, particularly with `append` (not assigning the result) and `delete` (no-op on nil maps).
* **Chinese Language:** Ensure the entire response is in clear and accurate Chinese.

**6. Structuring the Answer:**

Organize the answer logically. A good structure would be:

* **Introduction:** Briefly explain the purpose of `builtin.go`.
* **Categories:**  Group the content into logical categories (basic types, special identifiers, built-in functions, etc.).
* **Detailed Explanation for Each Category/Item:**  Provide descriptions, examples, and address the specific points of the request.
* **Common Mistakes:**  Dedicate a section to user errors.
* **Conclusion:**  Summarize the key takeaways.

**7. Self-Correction/Refinement:**

* **Initial Thought:**  Might initially think the file *implements* these built-ins. The package comment quickly corrects this.
* **Clarity of Examples:** Ensure the code examples are simple and directly demonstrate the function's purpose. Avoid unnecessary complexity.
* **Accuracy of Descriptions:** Double-check the descriptions of each type and function against the Go language specification if needed.
* **Completeness:** Make sure all the listed items in `builtin.go` are addressed.

By following this structured thought process, the detailed and accurate answer provided in the initial prompt can be generated. The key is to understand the *documentation* purpose of the file and then systematically analyze its contents, addressing each aspect of the request.
这段代码是 Go 语言标准库中 `go/src/builtin/builtin.go` 文件的一部分。它**不是**这些功能的实际实现，而是**为 Go 语言的预声明标识符提供文档**。

这意味着 `godoc` 工具会读取这个文件，并根据其中的注释生成 Go 语言内置类型、常量、变量和函数的文档。实际上，这些内置的功能是由编译器直接支持的，而不是在 `builtin` 包中实现的。

以下是该文件中列举的功能及其说明：

**1. 基本数据类型:**

* **布尔类型:** `bool`，以及预声明的布尔值 `true` 和 `false`。
* **整数类型:** `uint8`, `uint16`, `uint32`, `uint64`, `int8`, `int16`, `int32`, `int64`, `int`, `uint`, `uintptr`。文件中定义了它们的名称和取值范围。
* **浮点数类型:** `float32`, `float64`。
* **复数类型:** `complex64`, `complex128`。
* **字符串类型:** `string`。说明了字符串是不可变的字节序列。

**2. 类型别名:**

* `byte` 是 `uint8` 的别名。
* `rune` 是 `int32` 的别名。
* `any` 是 `interface{}` 的别名。

**3. 特殊标识符:**

* **`iota`:**  表示 `const` 声明中常量的枚举值，从 0 开始。
    ```go
    package main

    import "fmt"

    func main() {
        const (
            a = iota // a == 0
            b        // b == 1
            c        // c == 2
        )
        fmt.Println(a, b, c) // 输出: 0 1 2
    }
    ```
    **推理:** `iota` 在 `const` 声明中每次出现都会递增。
    **假设输入:** 无
    **输出:** `0 1 2`

* **`nil`:** 表示指针、通道、函数、接口、map 或 slice 类型的零值。
    ```go
    package main

    import "fmt"

    func main() {
        var p *int
        var ch chan int
        var f func()
        var i interface{}
        var m map[string]int
        var s []int

        fmt.Println(p == nil)   // 输出: true
        fmt.Println(ch == nil)  // 输出: true
        fmt.Println(f == nil)   // 输出: true
        fmt.Println(i == nil)   // 输出: true
        fmt.Println(m == nil)   // 输出: true
        fmt.Println(s == nil)   // 输出: true
    }
    ```
    **推理:** `nil` 可以用来判断这些类型的变量是否已被初始化。
    **假设输入:** 无
    **输出:** 多行 `true`

**4. 用于文档的占位符类型:**

* `Type`, `Type1`, `IntegerType`, `FloatType`, `ComplexType`。  这些类型仅用于 `builtin.go` 的文档目的，表示任意 Go 类型。你不能在实际代码中直接使用它们作为类型。

**5. 内置函数:**

* **`append(slice []Type, elems ...Type) []Type`:** 向切片末尾追加元素。
    ```go
    package main

    import "fmt"

    func main() {
        s := []int{1, 2, 3}
        s = append(s, 4, 5)
        fmt.Println(s) // 输出: [1 2 3 4 5]

        // 特殊情况：追加字符串到 byte slice
        b := []byte("hello ")
        b = append(b, "world"...)
        fmt.Println(string(b)) // 输出: hello world
    }
    ```
    **推理:** `append` 会返回一个新的切片，即使原切片有足够的容量。
    **假设输入:** `s := []int{1, 2, 3}`, 追加元素 `4`, `5`
    **输出:** `[1 2 3 4 5]`

* **`copy(dst, src []Type) int`:** 将元素从源切片复制到目标切片。
    ```go
    package main

    import "fmt"

    func main() {
        src := []int{1, 2, 3, 4, 5}
        dst := make([]int, 3)
        n := copy(dst, src)
        fmt.Println(dst, n) // 输出: [1 2 3] 3
    }
    ```
    **推理:** `copy` 返回实际复制的元素数量，是 `len(dst)` 和 `len(src)` 中的较小值。
    **假设输入:** `src := []int{1, 2, 3, 4, 5}`, `dst := make([]int, 3)`
    **输出:** `[1 2 3] 3`

* **`delete(m map[Type]Type1, key Type)`:** 从 map 中删除指定的键值对。
    ```go
    package main

    import "fmt"

    func main() {
        m := map[string]int{"a": 1, "b": 2}
        delete(m, "a")
        fmt.Println(m) // 输出: map[b:2]
        delete(m, "c") // 删除不存在的键，无操作
    }
    ```
    **推理:** 如果 map 为 `nil` 或者键不存在，`delete` 不会报错，而是无操作。
    **假设输入:** `m := map[string]int{"a": 1, "b": 2}`, 删除键 `"a"`
    **输出:** `map[b:2]`

* **`len(v Type) int`:** 返回字符串、数组、数组指针、切片、map 或通道的长度。
    ```go
    package main

    import "fmt"

    func main() {
        s := "hello"
        arr := [3]int{1, 2, 3}
        slice := []int{1, 2}
        m := map[string]int{"a": 1}
        ch := make(chan int, 5)

        fmt.Println(len(s))     // 输出: 5
        fmt.Println(len(arr))   // 输出: 3
        fmt.Println(len(slice)) // 输出: 2
        fmt.Println(len(m))     // 输出: 1
        fmt.Println(len(ch))    // 输出: 0 (通道中当前元素数量)
    }
    ```
    **推理:** `len` 根据参数类型返回不同的长度信息。
    **假设输入:** `s := "hello"`, `arr := [3]int{1, 2, 3}`, `slice := []int{1, 2}`, `m := map[string]int{"a": 1}`, `ch := make(chan int, 5)`
    **输出:** `5`, `3`, `2`, `1`, `0`

* **`cap(v Type) int`:** 返回数组、数组指针、切片或通道的容量。
    ```go
    package main

    import "fmt"

    func main() {
        arr := [3]int{1, 2, 3}
        slice := make([]int, 2, 5)
        ch := make(chan int, 5)

        fmt.Println(cap(arr))   // 输出: 3
        fmt.Println(cap(slice)) // 输出: 5
        fmt.Println(cap(ch))    // 输出: 5
    }
    ```
    **推理:** `cap` 表示底层数组可容纳的元素数量，对于切片而言，是其可以增长到的最大长度。
    **假设输入:** `arr := [3]int{1, 2, 3}`, `slice := make([]int, 2, 5)`, `ch := make(chan int, 5)`
    **输出:** `3`, `5`, `5`

* **`make(t Type, size ...IntegerType) Type`:** 创建切片、map 或通道。
    ```go
    package main

    func main() {
        s := make([]int, 5)       // 创建长度和容量都为 5 的切片
        m := make(map[string]int) // 创建空 map
        ch := make(chan int)      // 创建无缓冲通道
        ch2 := make(chan int, 10) // 创建容量为 10 的缓冲通道
    }
    ```
    **推理:** `make` 的第一个参数是类型，而不是值。对于切片，可以指定长度和可选的容量。
    **假设输入:** 无，`make` 用于创建这些类型的值。
    **输出:** 创建相应类型的实例。

* **`max[T cmp.Ordered](x T, y ...T) T`:** 返回一组可排序参数中的最大值（Go 1.21 新增）。
    ```go
    package main

    import (
        "fmt"
        "cmp"
    )

    func main() {
        fmt.Println(max(1, 2, 3))   // 输出: 3
        fmt.Println(max(3.14, 2.71)) // 输出: 3.14
    }
    ```
    **推理:**  需要参数类型实现了 `cmp.Ordered` 接口。
    **假设输入:** `1, 2, 3`
    **输出:** `3`

* **`min[T cmp.Ordered](x T, y ...T) T`:** 返回一组可排序参数中的最小值（Go 1.21 新增）。
    ```go
    package main

    import (
        "fmt"
        "cmp"
    )

    func main() {
        fmt.Println(min(1, 2, 3))   // 输出: 1
        fmt.Println(min(3.14, 2.71)) // 输出: 2.71
    }
    ```
    **推理:** 需要参数类型实现了 `cmp.Ordered` 接口。
    **假设输入:** `1, 2, 3`
    **输出:** `1`

* **`new(Type) *Type`:** 分配内存并返回指向该类型零值的指针。
    ```go
    package main

    import "fmt"

    func main() {
        p := new(int)
        fmt.Println(*p) // 输出: 0 (int 的零值)

        s := new(string)
        fmt.Println(*s == "") // 输出: true (string 的零值是空字符串)
    }
    ```
    **推理:** `new` 返回的是指针。
    **假设输入:** 无
    **输出:** 打印对应类型的零值。

* **`complex(r, i FloatType) ComplexType`:** 使用实部和虚部构造复数。
    ```go
    package main

    import "fmt"

    func main() {
        c := complex(2.0, 3.0)
        fmt.Println(c) // 输出: (2+3i)
    }
    ```
    **推理:** 实部和虚部必须是浮点数类型。
    **假设输入:** 实部 `2.0`, 虚部 `3.0`
    **输出:** `(2+3i)`

* **`real(c ComplexType) FloatType`:** 返回复数的实部。
    ```go
    package main

    import "fmt"

    func main() {
        c := complex(2.0, 3.0)
        r := real(c)
        fmt.Println(r) // 输出: 2
    }
    ```
    **假设输入:** `c := complex(2.0, 3.0)`
    **输出:** `2`

* **`imag(c ComplexType) FloatType`:** 返回复数的虚部。
    ```go
    package main

    import "fmt"

    func main() {
        c := complex(2.0, 3.0)
        i := imag(c)
        fmt.Println(i) // 输出: 3
    }
    ```
    **假设输入:** `c := complex(2.0, 3.0)`
    **输出:** `3`

* **`clear[T ~[]Type | ~map[Type]Type1](t T)`:** 清空 map 或 slice（Go 1.21 新增）。
    ```go
    package main

    import "fmt"

    func main() {
        m := map[string]int{"a": 1, "b": 2}
        clear(m)
        fmt.Println(m) // 输出: map[]

        s := []int{1, 2, 3}
        clear(s)
        fmt.Println(s) // 输出: [0 0 0]
    }
    ```
    **推理:** 对于 map，`clear` 删除所有条目。对于 slice，将所有元素设置为零值。
    **假设输入:** `m := map[string]int{"a": 1, "b": 2}`, `s := []int{1, 2, 3}`
    **输出:** `map[]`, `[0 0 0]`

* **`close(c chan<- Type)`:** 关闭通道。
    ```go
    package main

    import "fmt"

    func main() {
        ch := make(chan int, 2)
        ch <- 1
        ch <- 2
        close(ch)

        for v := range ch {
            fmt.Println(v) // 输出: 1, 2
        }

        val, ok := <-ch
        fmt.Println(val, ok) // 输出: 0 false (通道已关闭且为空)
    }
    ```
    **推理:** 只能由发送者关闭通道。关闭后，接收者可以继续接收已发送的值，直到通道为空。接收空通道会得到零值和 `ok` 为 `false`。
    **假设输入:** 向通道发送 `1` 和 `2` 后关闭
    **输出:** `1`, `2`, `0 false`

* **`panic(v any)`:** 抛出 panic 异常，中断当前的 goroutine 的正常执行。
    ```go
    package main

    import "fmt"

    func main() {
        fmt.Println("Before panic")
        panic("Something went wrong!")
        fmt.Println("After panic") // 这行不会被执行
    }
    ```
    **推理:** `panic` 会导致程序终止，除非有 `recover` 捕获它。
    **假设输入:** 字符串 `"Something went wrong!"`
    **输出:**  程序会打印 "Before panic"，然后抛出 panic 并终止。

* **`recover() any`:**  在 `defer` 函数中捕获 `panic` 异常，使程序可以继续执行。
    ```go
    package main

    import "fmt"

    func main() {
        defer func() {
            if r := recover(); r != nil {
                fmt.Println("Recovered from panic:", r)
            }
        }()

        fmt.Println("Before panic")
        panic("Something went wrong!")
        fmt.Println("After panic") // 这行不会被执行
    }
    ```
    **推理:** `recover` 只能在 `defer` 函数中有效。如果发生 panic，`recover` 会返回传递给 `panic` 的值，否则返回 `nil`。
    **假设输入:** 字符串 `"Something went wrong!"`
    **输出:** `Before panic`, `Recovered from panic: Something went wrong!`

* **`print(args ...Type)`:** 以实现定义的方式格式化参数并写入标准错误。不保证其稳定性。
* **`println(args ...Type)`:**  以实现定义的方式格式化参数并在参数之间添加空格，最后添加换行符，写入标准错误。不保证其稳定性。
    ```go
    package main

    func main() {
        print("Hello, ")
        println("World!")
    }
    ```
    **推理:** 这两个函数主要用于引导和调试，不建议在生产环境中使用。
    **假设输入:** 字符串 `"Hello, "` 和 `"World!"`
    **输出:** 输出到标准错误，内容类似 "Hello, World!\n"。

**6. 接口类型:**

* **`error`:** 标准的错误接口，表示错误条件。

**关于命令行参数的具体处理:**

`builtin.go` 文件本身不涉及任何命令行参数的处理。它只是定义和文档化 Go 语言的内置元素。命令行参数的处理通常发生在 `main` 函数所在的包中，并使用 `os` 包来实现。

**使用者易犯错的点:**

* **不接收 `append` 的返回值:** `append` 操作可能会创建一个新的底层数组，因此必须将返回值赋值给原切片变量。
    ```go
    package main

    import "fmt"

    func main() {
        s := []int{1, 2, 3}
        append(s, 4) // 错误：s 没有被更新
        fmt.Println(s) // 输出: [1 2 3]

        s = append(s, 4) // 正确
        fmt.Println(s) // 输出: [1 2 3 4]
    }
    ```

* **在 `nil` 的 map 上使用 `delete` 不会报错，但也不会有任何效果。** 需要确保 map 已经被初始化后才能进行删除操作。
    ```go
    package main

    import "fmt"

    func main() {
        var m map[string]int
        delete(m, "key") // 不会报错，但也没有效果
        fmt.Println(m)    // 输出: map[] (或 nil，取决于具体情况)

        m = make(map[string]int)
        delete(m, "key") // 仍然没效果，因为键不存在
        fmt.Println(m)    // 输出: map[]
    }
    ```

总而言之，`go/src/builtin/builtin.go` 扮演着 Go 语言内置功能的“说明书”的角色，帮助开发者和工具理解和使用这些核心特性。实际的实现是在 Go 编译器的内部。

Prompt: 
```
这是路径为go/src/builtin/builtin.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。

"""
// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

/*
Package builtin provides documentation for Go's predeclared identifiers.
The items documented here are not actually in package builtin
but their descriptions here allow godoc to present documentation
for the language's special identifiers.
*/
package builtin

import "cmp"

// bool is the set of boolean values, true and false.
type bool bool

// true and false are the two untyped boolean values.
const (
	true  = 0 == 0 // Untyped bool.
	false = 0 != 0 // Untyped bool.
)

// uint8 is the set of all unsigned 8-bit integers.
// Range: 0 through 255.
type uint8 uint8

// uint16 is the set of all unsigned 16-bit integers.
// Range: 0 through 65535.
type uint16 uint16

// uint32 is the set of all unsigned 32-bit integers.
// Range: 0 through 4294967295.
type uint32 uint32

// uint64 is the set of all unsigned 64-bit integers.
// Range: 0 through 18446744073709551615.
type uint64 uint64

// int8 is the set of all signed 8-bit integers.
// Range: -128 through 127.
type int8 int8

// int16 is the set of all signed 16-bit integers.
// Range: -32768 through 32767.
type int16 int16

// int32 is the set of all signed 32-bit integers.
// Range: -2147483648 through 2147483647.
type int32 int32

// int64 is the set of all signed 64-bit integers.
// Range: -9223372036854775808 through 9223372036854775807.
type int64 int64

// float32 is the set of all IEEE 754 32-bit floating-point numbers.
type float32 float32

// float64 is the set of all IEEE 754 64-bit floating-point numbers.
type float64 float64

// complex64 is the set of all complex numbers with float32 real and
// imaginary parts.
type complex64 complex64

// complex128 is the set of all complex numbers with float64 real and
// imaginary parts.
type complex128 complex128

// string is the set of all strings of 8-bit bytes, conventionally but not
// necessarily representing UTF-8-encoded text. A string may be empty, but
// not nil. Values of string type are immutable.
type string string

// int is a signed integer type that is at least 32 bits in size. It is a
// distinct type, however, and not an alias for, say, int32.
type int int

// uint is an unsigned integer type that is at least 32 bits in size. It is a
// distinct type, however, and not an alias for, say, uint32.
type uint uint

// uintptr is an integer type that is large enough to hold the bit pattern of
// any pointer.
type uintptr uintptr

// byte is an alias for uint8 and is equivalent to uint8 in all ways. It is
// used, by convention, to distinguish byte values from 8-bit unsigned
// integer values.
type byte = uint8

// rune is an alias for int32 and is equivalent to int32 in all ways. It is
// used, by convention, to distinguish character values from integer values.
type rune = int32

// any is an alias for interface{} and is equivalent to interface{} in all ways.
type any = interface{}

// comparable is an interface that is implemented by all comparable types
// (booleans, numbers, strings, pointers, channels, arrays of comparable types,
// structs whose fields are all comparable types).
// The comparable interface may only be used as a type parameter constraint,
// not as the type of a variable.
type comparable interface{ comparable }

// iota is a predeclared identifier representing the untyped integer ordinal
// number of the current const specification in a (usually parenthesized)
// const declaration. It is zero-indexed.
const iota = 0 // Untyped int.

// nil is a predeclared identifier representing the zero value for a
// pointer, channel, func, interface, map, or slice type.
var nil Type // Type must be a pointer, channel, func, interface, map, or slice type

// Type is here for the purposes of documentation only. It is a stand-in
// for any Go type, but represents the same type for any given function
// invocation.
type Type int

// Type1 is here for the purposes of documentation only. It is a stand-in
// for any Go type, but represents the same type for any given function
// invocation.
type Type1 int

// IntegerType is here for the purposes of documentation only. It is a stand-in
// for any integer type: int, uint, int8 etc.
type IntegerType int

// FloatType is here for the purposes of documentation only. It is a stand-in
// for either float type: float32 or float64.
type FloatType float32

// ComplexType is here for the purposes of documentation only. It is a
// stand-in for either complex type: complex64 or complex128.
type ComplexType complex64

// The append built-in function appends elements to the end of a slice. If
// it has sufficient capacity, the destination is resliced to accommodate the
// new elements. If it does not, a new underlying array will be allocated.
// Append returns the updated slice. It is therefore necessary to store the
// result of append, often in the variable holding the slice itself:
//
//	slice = append(slice, elem1, elem2)
//	slice = append(slice, anotherSlice...)
//
// As a special case, it is legal to append a string to a byte slice, like this:
//
//	slice = append([]byte("hello "), "world"...)
func append(slice []Type, elems ...Type) []Type

// The copy built-in function copies elements from a source slice into a
// destination slice. (As a special case, it also will copy bytes from a
// string to a slice of bytes.) The source and destination may overlap. Copy
// returns the number of elements copied, which will be the minimum of
// len(src) and len(dst).
func copy(dst, src []Type) int

// The delete built-in function deletes the element with the specified key
// (m[key]) from the map. If m is nil or there is no such element, delete
// is a no-op.
func delete(m map[Type]Type1, key Type)

// The len built-in function returns the length of v, according to its type:
//
//	Array: the number of elements in v.
//	Pointer to array: the number of elements in *v (even if v is nil).
//	Slice, or map: the number of elements in v; if v is nil, len(v) is zero.
//	String: the number of bytes in v.
//	Channel: the number of elements queued (unread) in the channel buffer;
//	         if v is nil, len(v) is zero.
//
// For some arguments, such as a string literal or a simple array expression, the
// result can be a constant. See the Go language specification's "Length and
// capacity" section for details.
func len(v Type) int

// The cap built-in function returns the capacity of v, according to its type:
//
//	Array: the number of elements in v (same as len(v)).
//	Pointer to array: the number of elements in *v (same as len(v)).
//	Slice: the maximum length the slice can reach when resliced;
//	if v is nil, cap(v) is zero.
//	Channel: the channel buffer capacity, in units of elements;
//	if v is nil, cap(v) is zero.
//
// For some arguments, such as a simple array expression, the result can be a
// constant. See the Go language specification's "Length and capacity" section for
// details.
func cap(v Type) int

// The make built-in function allocates and initializes an object of type
// slice, map, or chan (only). Like new, the first argument is a type, not a
// value. Unlike new, make's return type is the same as the type of its
// argument, not a pointer to it. The specification of the result depends on
// the type:
//
//	Slice: The size specifies the length. The capacity of the slice is
//	equal to its length. A second integer argument may be provided to
//	specify a different capacity; it must be no smaller than the
//	length. For example, make([]int, 0, 10) allocates an underlying array
//	of size 10 and returns a slice of length 0 and capacity 10 that is
//	backed by this underlying array.
//	Map: An empty map is allocated with enough space to hold the
//	specified number of elements. The size may be omitted, in which case
//	a small starting size is allocated.
//	Channel: The channel's buffer is initialized with the specified
//	buffer capacity. If zero, or the size is omitted, the channel is
//	unbuffered.
func make(t Type, size ...IntegerType) Type

// The max built-in function returns the largest value of a fixed number of
// arguments of [cmp.Ordered] types. There must be at least one argument.
// If T is a floating-point type and any of the arguments are NaNs,
// max will return NaN.
func max[T cmp.Ordered](x T, y ...T) T

// The min built-in function returns the smallest value of a fixed number of
// arguments of [cmp.Ordered] types. There must be at least one argument.
// If T is a floating-point type and any of the arguments are NaNs,
// min will return NaN.
func min[T cmp.Ordered](x T, y ...T) T

// The new built-in function allocates memory. The first argument is a type,
// not a value, and the value returned is a pointer to a newly
// allocated zero value of that type.
func new(Type) *Type

// The complex built-in function constructs a complex value from two
// floating-point values. The real and imaginary parts must be of the same
// size, either float32 or float64 (or assignable to them), and the return
// value will be the corresponding complex type (complex64 for float32,
// complex128 for float64).
func complex(r, i FloatType) ComplexType

// The real built-in function returns the real part of the complex number c.
// The return value will be floating point type corresponding to the type of c.
func real(c ComplexType) FloatType

// The imag built-in function returns the imaginary part of the complex
// number c. The return value will be floating point type corresponding to
// the type of c.
func imag(c ComplexType) FloatType

// The clear built-in function clears maps and slices.
// For maps, clear deletes all entries, resulting in an empty map.
// For slices, clear sets all elements up to the length of the slice
// to the zero value of the respective element type. If the argument
// type is a type parameter, the type parameter's type set must
// contain only map or slice types, and clear performs the operation
// implied by the type argument. If t is nil, clear is a no-op.
func clear[T ~[]Type | ~map[Type]Type1](t T)

// The close built-in function closes a channel, which must be either
// bidirectional or send-only. It should be executed only by the sender,
// never the receiver, and has the effect of shutting down the channel after
// the last sent value is received. After the last value has been received
// from a closed channel c, any receive from c will succeed without
// blocking, returning the zero value for the channel element. The form
//
//	x, ok := <-c
//
// will also set ok to false for a closed and empty channel.
func close(c chan<- Type)

// The panic built-in function stops normal execution of the current
// goroutine. When a function F calls panic, normal execution of F stops
// immediately. Any functions whose execution was deferred by F are run in
// the usual way, and then F returns to its caller. To the caller G, the
// invocation of F then behaves like a call to panic, terminating G's
// execution and running any deferred functions. This continues until all
// functions in the executing goroutine have stopped, in reverse order. At
// that point, the program is terminated with a non-zero exit code. This
// termination sequence is called panicking and can be controlled by the
// built-in function recover.
//
// Starting in Go 1.21, calling panic with a nil interface value or an
// untyped nil causes a run-time error (a different panic).
// The GODEBUG setting panicnil=1 disables the run-time error.
func panic(v any)

// The recover built-in function allows a program to manage behavior of a
// panicking goroutine. Executing a call to recover inside a deferred
// function (but not any function called by it) stops the panicking sequence
// by restoring normal execution and retrieves the error value passed to the
// call of panic. If recover is called outside the deferred function it will
// not stop a panicking sequence. In this case, or when the goroutine is not
// panicking, recover returns nil.
//
// Prior to Go 1.21, recover would also return nil if panic is called with
// a nil argument. See [panic] for details.
func recover() any

// The print built-in function formats its arguments in an
// implementation-specific way and writes the result to standard error.
// Print is useful for bootstrapping and debugging; it is not guaranteed
// to stay in the language.
func print(args ...Type)

// The println built-in function formats its arguments in an
// implementation-specific way and writes the result to standard error.
// Spaces are always added between arguments and a newline is appended.
// Println is useful for bootstrapping and debugging; it is not guaranteed
// to stay in the language.
func println(args ...Type)

// The error built-in interface type is the conventional interface for
// representing an error condition, with the nil value representing no error.
type error interface {
	Error() string
}

"""



```