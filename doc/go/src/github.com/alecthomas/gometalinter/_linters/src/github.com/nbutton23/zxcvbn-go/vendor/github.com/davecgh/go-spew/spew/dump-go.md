Response:
Let's break down the thought process for analyzing the provided Go code snippet and generating the comprehensive answer.

**1. Initial Understanding & Core Purpose:**

The first step is to quickly scan the code and its comments. The copyright notice indicates the author and a permissive license. The package name `spew` and the function names like `dump`, `Fdump`, `Sdump`, and `Dump` immediately suggest a debugging or introspection tool for displaying Go data structures. The comment block before the `Dump` function explicitly confirms this, highlighting features like pointer dereferencing, circular reference detection, and hexdumping of byte arrays.

**2. Identifying Key Components:**

After getting the gist, we can dive deeper, looking for key data structures and functions.

* **`dumpState` struct:** This seems to hold the state of the dumping process, including the output writer, depth, pointer tracking for circular references, and configuration. This is central to the dumping logic.
* **`ConfigState` struct (implied):**  The code mentions `cs *ConfigState` in `dumpState`, indicating there's a separate structure for configuration. While not in the provided snippet, its existence is crucial.
* **`dump()` function:** This is the core recursive function that handles different Go types. The `switch v.Kind()` statement is a strong indicator of this.
* **`dumpPtr()`, `dumpSlice()` functions:**  These are helper functions for specific types (pointers and slices/arrays), simplifying the main `dump()` function.
* **`fdump()`, `Fdump()`, `Sdump()`, `Dump()` functions:** These are the public entry points, offering different ways to use the dumping functionality (to a writer, as a string, to standard output).
* **Regular expressions (`cCharRE`, `cUnsignedCharRE`, `cUint8tCharRE`):** These are for detecting C-style character arrays for special handling (hexdumping).
* **Global `Config` variable:** The `fdump` and `Dump` functions use a global `Config`, suggesting default settings.

**3. Analyzing Functionality by Function:**

Now, let's analyze each significant function's purpose:

* **`dumpState` methods:**
    * `indent()`: Handles indentation based on depth and configuration.
    * `unpackValue()`:  Unwraps values from interfaces.

* **`dumpPtr()`:**  Crucial for handling pointers. Focus on:
    * Circular reference detection using `d.pointers`.
    * Dereferencing logic (the `for ve.Kind() == reflect.Ptr` loop).
    * Displaying type and pointer addresses.
    * Handling `nil` and circular pointers.

* **`dumpSlice()`:** Focus on:
    * The logic for deciding whether to hexdump. Pay attention to the regular expressions for C-style arrays and the handling of `uint8` slices.
    * The hexdumping using `hex.Dump()`.
    * The recursive call to `d.dump()` for non-byte slices.

* **`dump()`:**  The heart of the logic. Focus on:
    * Handling `reflect.Invalid`.
    * The special handling of pointers (calling `dumpPtr`).
    * Displaying type information.
    * Displaying length and capacity.
    * The `switch v.Kind()` statement and how different types are handled (basic types, slices, arrays, strings, interfaces, maps, structs).
    * The handling of `MaxDepth` for recursion control.

* **`fdump()`:** The central worker function that takes a `ConfigState` and a writer.

* **`Fdump()`, `Sdump()`, `Dump()`:** These are wrappers around `fdump` with different defaults for the writer.

**4. Inferring Go Features:**

Based on the code, we can infer the following Go features being used:

* **Reflection (`reflect` package):** This is the core of the `spew` package. The code heavily uses `reflect.TypeOf`, `reflect.ValueOf`, `v.Kind()`, `v.Elem()`, `v.Field()`, etc., to introspect data structures.
* **Interfaces (`io.Writer`):** Used for output flexibility.
* **Regular Expressions (`regexp` package):** For pattern matching C-style character arrays.
* **String Conversion (`strconv` package):** For quoting strings.
* **Hex Encoding (`encoding/hex` package):** For hexdumping byte slices.
* **Error Handling (implicitly):**  Although not explicitly shown in this snippet, error interfaces are mentioned in the comments, implying their handling elsewhere.
* **Unsafe Pointer (`unsafe` package):** Used to bypass visibility restrictions when accessing underlying data of slices (conditionally, based on `UnsafeDisabled`).

**5. Crafting Examples and Explanations:**

With a good understanding of the code's functionality and the Go features used, we can now create illustrative examples. For each Go feature identified, create a simple example showcasing how `spew` might interact with it.

* **Reflection:** Show how `spew` displays the type and value of a variable.
* **Interfaces:** Demonstrate dumping a value held by an interface.
* **Pointers:** Show how `spew` dereferences pointers and displays addresses.
* **Circular References:** Create a simple circular data structure and show how `spew` detects it.
* **Slices and Arrays:** Demonstrate the hexdumping of byte slices and the recursive dumping of other types of slices.
* **Maps and Structs:** Show how `spew` displays the key-value pairs of maps and the fields of structs.

**6. Identifying Potential Pitfalls:**

Think about how users might misuse or misunderstand the `spew` library.

* **Large Data Structures:** Emphasize the impact of dumping very large structures on performance and output size.
* **Circular References:**  Explain that while detected, deeply nested circular structures can still produce a lot of output.
* **Configuration Options:** Briefly mention that the global `Config` can be modified, but it affects all subsequent calls to `Dump`.

**7. Structuring the Answer:**

Finally, organize the information into a clear and logical structure, using headings and bullet points for readability. Start with a concise summary of the functionality, then elaborate on each aspect with examples and explanations. Ensure the language is clear and accurate.

**Self-Correction/Refinement During the Process:**

* **Initial thought:**  Might initially focus too much on low-level details of the `dump` function.
* **Correction:**  Realize the need to provide a higher-level overview of the package's purpose and the public functions first.
* **Initial thought:**  Might forget to explicitly mention the `ConfigState` struct even if it's not fully present in the snippet.
* **Correction:**  Recognize the importance of configuration and mention it, even if details are missing.
* **Initial thought:**  Examples might be too complex initially.
* **Correction:**  Simplify the examples to focus on illustrating specific features.

By following this structured approach, combining code analysis with an understanding of Go's features, and refining the explanation along the way, we arrive at a comprehensive and helpful answer like the example provided in the prompt.
这段代码是Go语言中一个名为 `spew` 的库的一部分，其主要功能是**以一种更易读和更详细的方式打印Go语言的数据结构，用于调试和日志记录。** 它可以展示变量的类型、值，以及指针的地址，并且能处理循环引用的情况。

以下是其主要功能点的详细说明：

1. **详细的类型信息:**  `spew` 会打印出变量的完整类型信息，包括包路径。这比使用 `fmt.Printf("%v", obj)` 更具信息量，后者可能只显示基本类型。

2. **指针的解引用和地址显示:**  `spew` 会自动解引用指针，并显示指针指向的值。同时，它还可以显示指针的内存地址，方便追踪对象的生命周期和引用关系。

3. **循环引用检测:**  `spew` 能够检测并处理数据结构中的循环引用，避免无限递归导致程序崩溃。对于已经访问过的指针，它会标记为 `(circular)`。

4. **自定义 Stringer 和 error 接口调用:**  `spew` 可以调用用户自定义的 `String()` 和 `Error()` 方法（如果存在），即使这些方法是在未导出的类型上定义的。这允许用户自定义对象的打印输出格式。

5. **Byte 数组和切片的十六进制转储:**  对于 `[]byte` 类型的数组和切片，`spew` 会以类似于 `hexdump -C` 命令的格式进行打印，显示偏移量、十六进制值和 ASCII 表示，方便查看二进制数据。

6. **可配置的输出格式:**  `spew` 提供了配置选项（通过全局变量 `spew.Config`），可以自定义缩进、是否显示指针地址、是否调用方法等。

**它是 Go 语言反射功能的实现。**

`spew` 库的核心是利用 Go 语言的 `reflect` 包来实现对任意数据结构的运行时检查和分析。`reflect` 包允许程序在运行时检查变量的类型和值，即使在编译时不知道其具体类型。

**Go 代码示例：**

```go
package main

import (
	"fmt"
	"github.com/davecgh/go-spew/spew"
)

type MyStruct struct {
	Name string
	Age  int
	Data []byte
	Ref  *MyStruct
}

func main() {
	data := []byte{0x01, 0x02, 0x03, 0x41, 0x42, 0x43}
	obj1 := MyStruct{
		Name: "Alice",
		Age:  30,
		Data: data,
	}
	obj2 := MyStruct{
		Name: "Bob",
		Age:  25,
		Data: []byte{0x0A, 0x0B, 0x0C},
		Ref:  &obj1, // 指向 obj1
	}
	obj1.Ref = &obj2 // 造成循环引用

	fmt.Println("Using fmt.Printf:")
	fmt.Printf("%+v\n", obj1)
	fmt.Printf("%+v\n", obj2)

	fmt.Println("\nUsing spew.Dump:")
	spew.Dump(obj1)
	spew.Dump(obj2)
}
```

**假设的输入与输出：**

运行上面的代码，`fmt.Printf` 的输出可能如下：

```
Using fmt.Printf:
{Name:Alice Age:30 Data:[1 2 3 65 66 67] Ref:0xc00004a180}
{Name:Bob Age:25 Data:[10 11 12] Ref:0xc00004a120}
```

`spew.Dump` 的输出可能如下（具体的内存地址会不同）：

```
Using spew.Dump:
(main.MyStruct) {
 Name: (string) Alice
 Age: (int) 30
 Data: ([]uint8) {
  00000000  01 02 03 41 42 43                                |...ABC|
 }
 Ref: (*main.MyStruct)(0xc00004a180) {
  Name: (string) Bob
  Age: (int) 25
  Data: ([]uint8) {
   00000000  0a 0b 0c                                        |...|
  }
  Ref: (*main.MyStruct)(0xc00004a120) {
   Name: (string) Alice
   Age: (int) 30
   Data: ([]uint8) {
    00000000  01 02 03 41 42 43                                |...ABC|
   }
   Ref: (*main.MyStruct)(0xc00004a180) (circular)
  }
 }
}
(main.MyStruct) {
 Name: (string) Bob
 Age: (int) 25
 Data: ([]uint8) {
  00000000  0a 0b 0c                                        |...|
 }
 Ref: (*main.MyStruct)(0xc00004a120) {
  Name: (string) Alice
  Age: (int) 30
  Data: ([]uint8) {
   00000000  01 02 03 41 42 43                                |...ABC|
  }
  Ref: (*main.MyStruct)(0xc00004a180) (circular)
 }
}
```

可以看到 `spew.Dump` 的输出更详细，包含了类型信息、指针地址，并且正确地检测到了循环引用。对于 `Data` 字段的 `[]byte`，它进行了十六进制转储。

**命令行参数处理：**

这段代码本身没有直接处理命令行参数。`spew` 库的配置通常是通过 Go 代码中的全局变量 `spew.Config` 进行设置的。

例如，你可以在代码中修改 `spew.Config` 来改变输出的缩进：

```go
package main

import (
	"github.com/davecgh/go-spew/spew"
	"os"
)

func main() {
	spew.Config.Indent = "\t" // 使用制表符进行缩进
	spew.Dump("hello")

	spew.Config.DisablePointerAddresses = true // 禁用指针地址显示
	spew.Dump("world")
}
```

`spew.Config` 结构体包含以下一些重要的字段，用于配置输出行为：

* **`Indent`**:  用于缩进的字符串，默认为两个空格。
* **`MaxDepth`**:  指定递归打印的最大深度，防止无限递归。默认为 0 (不限制深度)。
* **`DisablePointerAddresses`**:  布尔值，控制是否显示指针的内存地址，默认为 `false`。
* **`DisableMethods`**: 布尔值，控制是否调用类型的 `String()` 和 `Error()` 方法，默认为 `false`。
* **`DisableCapacities`**: 布尔值，控制是否显示切片和通道的容量，默认为 `false`。
* **`SortKeys`**: 布尔值，控制是否对 map 的键进行排序后输出，默认为 `false`。

**使用者易犯错的点：**

1. **过度依赖 `spew.Dump` 进行生产环境日志记录：** 虽然 `spew.Dump` 的输出很详细，但在生产环境中，过多的信息可能会降低性能并使日志难以阅读。应该根据实际需求选择合适的日志级别和格式。

2. **忽略 `MaxDepth` 导致无限递归：**  如果打印的数据结构非常深或者存在循环引用，并且 `MaxDepth` 没有设置，可能会导致 `spew.Dump` 陷入无限递归，最终导致栈溢出。

   **示例：** 如果你打印一个深度嵌套且有循环引用的复杂数据结构，而没有设置 `spew.Config.MaxDepth`，可能会看到程序挂起或者崩溃。

3. **误解 `DisableMethods` 的作用：** 如果设置了 `DisableMethods = true`，`spew` 将不会调用类型的 `String()` 和 `Error()` 方法，可能会导致输出的信息不符合预期，因为某些类型可能依赖这些方法来提供有意义的字符串表示。

   **示例：** 假设你有一个自定义类型 `MyError` 实现了 `error` 接口，当你使用 `spew.Dump` 打印 `MyError` 实例时，如果 `DisableMethods` 为 `true`，你看到的可能只是结构体的字段值，而不是 `Error()` 方法返回的错误信息。

总而言之，这段 `dump.go` 文件是 `spew` 库的核心部分，它利用 Go 的反射机制，提供了强大的数据结构打印和调试功能。使用者应该理解其配置选项和潜在的陷阱，以便在开发过程中更有效地利用它。

Prompt: 
```
这是路径为go/src/github.com/alecthomas/gometalinter/_linters/src/github.com/nbutton23/zxcvbn-go/vendor/github.com/davecgh/go-spew/spew/dump.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。

"""
/*
 * Copyright (c) 2013-2016 Dave Collins <dave@davec.name>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

package spew

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"reflect"
	"regexp"
	"strconv"
	"strings"
)

var (
	// uint8Type is a reflect.Type representing a uint8.  It is used to
	// convert cgo types to uint8 slices for hexdumping.
	uint8Type = reflect.TypeOf(uint8(0))

	// cCharRE is a regular expression that matches a cgo char.
	// It is used to detect character arrays to hexdump them.
	cCharRE = regexp.MustCompile("^.*\\._Ctype_char$")

	// cUnsignedCharRE is a regular expression that matches a cgo unsigned
	// char.  It is used to detect unsigned character arrays to hexdump
	// them.
	cUnsignedCharRE = regexp.MustCompile("^.*\\._Ctype_unsignedchar$")

	// cUint8tCharRE is a regular expression that matches a cgo uint8_t.
	// It is used to detect uint8_t arrays to hexdump them.
	cUint8tCharRE = regexp.MustCompile("^.*\\._Ctype_uint8_t$")
)

// dumpState contains information about the state of a dump operation.
type dumpState struct {
	w                io.Writer
	depth            int
	pointers         map[uintptr]int
	ignoreNextType   bool
	ignoreNextIndent bool
	cs               *ConfigState
}

// indent performs indentation according to the depth level and cs.Indent
// option.
func (d *dumpState) indent() {
	if d.ignoreNextIndent {
		d.ignoreNextIndent = false
		return
	}
	d.w.Write(bytes.Repeat([]byte(d.cs.Indent), d.depth))
}

// unpackValue returns values inside of non-nil interfaces when possible.
// This is useful for data types like structs, arrays, slices, and maps which
// can contain varying types packed inside an interface.
func (d *dumpState) unpackValue(v reflect.Value) reflect.Value {
	if v.Kind() == reflect.Interface && !v.IsNil() {
		v = v.Elem()
	}
	return v
}

// dumpPtr handles formatting of pointers by indirecting them as necessary.
func (d *dumpState) dumpPtr(v reflect.Value) {
	// Remove pointers at or below the current depth from map used to detect
	// circular refs.
	for k, depth := range d.pointers {
		if depth >= d.depth {
			delete(d.pointers, k)
		}
	}

	// Keep list of all dereferenced pointers to show later.
	pointerChain := make([]uintptr, 0)

	// Figure out how many levels of indirection there are by dereferencing
	// pointers and unpacking interfaces down the chain while detecting circular
	// references.
	nilFound := false
	cycleFound := false
	indirects := 0
	ve := v
	for ve.Kind() == reflect.Ptr {
		if ve.IsNil() {
			nilFound = true
			break
		}
		indirects++
		addr := ve.Pointer()
		pointerChain = append(pointerChain, addr)
		if pd, ok := d.pointers[addr]; ok && pd < d.depth {
			cycleFound = true
			indirects--
			break
		}
		d.pointers[addr] = d.depth

		ve = ve.Elem()
		if ve.Kind() == reflect.Interface {
			if ve.IsNil() {
				nilFound = true
				break
			}
			ve = ve.Elem()
		}
	}

	// Display type information.
	d.w.Write(openParenBytes)
	d.w.Write(bytes.Repeat(asteriskBytes, indirects))
	d.w.Write([]byte(ve.Type().String()))
	d.w.Write(closeParenBytes)

	// Display pointer information.
	if !d.cs.DisablePointerAddresses && len(pointerChain) > 0 {
		d.w.Write(openParenBytes)
		for i, addr := range pointerChain {
			if i > 0 {
				d.w.Write(pointerChainBytes)
			}
			printHexPtr(d.w, addr)
		}
		d.w.Write(closeParenBytes)
	}

	// Display dereferenced value.
	d.w.Write(openParenBytes)
	switch {
	case nilFound == true:
		d.w.Write(nilAngleBytes)

	case cycleFound == true:
		d.w.Write(circularBytes)

	default:
		d.ignoreNextType = true
		d.dump(ve)
	}
	d.w.Write(closeParenBytes)
}

// dumpSlice handles formatting of arrays and slices.  Byte (uint8 under
// reflection) arrays and slices are dumped in hexdump -C fashion.
func (d *dumpState) dumpSlice(v reflect.Value) {
	// Determine whether this type should be hex dumped or not.  Also,
	// for types which should be hexdumped, try to use the underlying data
	// first, then fall back to trying to convert them to a uint8 slice.
	var buf []uint8
	doConvert := false
	doHexDump := false
	numEntries := v.Len()
	if numEntries > 0 {
		vt := v.Index(0).Type()
		vts := vt.String()
		switch {
		// C types that need to be converted.
		case cCharRE.MatchString(vts):
			fallthrough
		case cUnsignedCharRE.MatchString(vts):
			fallthrough
		case cUint8tCharRE.MatchString(vts):
			doConvert = true

		// Try to use existing uint8 slices and fall back to converting
		// and copying if that fails.
		case vt.Kind() == reflect.Uint8:
			// We need an addressable interface to convert the type
			// to a byte slice.  However, the reflect package won't
			// give us an interface on certain things like
			// unexported struct fields in order to enforce
			// visibility rules.  We use unsafe, when available, to
			// bypass these restrictions since this package does not
			// mutate the values.
			vs := v
			if !vs.CanInterface() || !vs.CanAddr() {
				vs = unsafeReflectValue(vs)
			}
			if !UnsafeDisabled {
				vs = vs.Slice(0, numEntries)

				// Use the existing uint8 slice if it can be
				// type asserted.
				iface := vs.Interface()
				if slice, ok := iface.([]uint8); ok {
					buf = slice
					doHexDump = true
					break
				}
			}

			// The underlying data needs to be converted if it can't
			// be type asserted to a uint8 slice.
			doConvert = true
		}

		// Copy and convert the underlying type if needed.
		if doConvert && vt.ConvertibleTo(uint8Type) {
			// Convert and copy each element into a uint8 byte
			// slice.
			buf = make([]uint8, numEntries)
			for i := 0; i < numEntries; i++ {
				vv := v.Index(i)
				buf[i] = uint8(vv.Convert(uint8Type).Uint())
			}
			doHexDump = true
		}
	}

	// Hexdump the entire slice as needed.
	if doHexDump {
		indent := strings.Repeat(d.cs.Indent, d.depth)
		str := indent + hex.Dump(buf)
		str = strings.Replace(str, "\n", "\n"+indent, -1)
		str = strings.TrimRight(str, d.cs.Indent)
		d.w.Write([]byte(str))
		return
	}

	// Recursively call dump for each item.
	for i := 0; i < numEntries; i++ {
		d.dump(d.unpackValue(v.Index(i)))
		if i < (numEntries - 1) {
			d.w.Write(commaNewlineBytes)
		} else {
			d.w.Write(newlineBytes)
		}
	}
}

// dump is the main workhorse for dumping a value.  It uses the passed reflect
// value to figure out what kind of object we are dealing with and formats it
// appropriately.  It is a recursive function, however circular data structures
// are detected and handled properly.
func (d *dumpState) dump(v reflect.Value) {
	// Handle invalid reflect values immediately.
	kind := v.Kind()
	if kind == reflect.Invalid {
		d.w.Write(invalidAngleBytes)
		return
	}

	// Handle pointers specially.
	if kind == reflect.Ptr {
		d.indent()
		d.dumpPtr(v)
		return
	}

	// Print type information unless already handled elsewhere.
	if !d.ignoreNextType {
		d.indent()
		d.w.Write(openParenBytes)
		d.w.Write([]byte(v.Type().String()))
		d.w.Write(closeParenBytes)
		d.w.Write(spaceBytes)
	}
	d.ignoreNextType = false

	// Display length and capacity if the built-in len and cap functions
	// work with the value's kind and the len/cap itself is non-zero.
	valueLen, valueCap := 0, 0
	switch v.Kind() {
	case reflect.Array, reflect.Slice, reflect.Chan:
		valueLen, valueCap = v.Len(), v.Cap()
	case reflect.Map, reflect.String:
		valueLen = v.Len()
	}
	if valueLen != 0 || !d.cs.DisableCapacities && valueCap != 0 {
		d.w.Write(openParenBytes)
		if valueLen != 0 {
			d.w.Write(lenEqualsBytes)
			printInt(d.w, int64(valueLen), 10)
		}
		if !d.cs.DisableCapacities && valueCap != 0 {
			if valueLen != 0 {
				d.w.Write(spaceBytes)
			}
			d.w.Write(capEqualsBytes)
			printInt(d.w, int64(valueCap), 10)
		}
		d.w.Write(closeParenBytes)
		d.w.Write(spaceBytes)
	}

	// Call Stringer/error interfaces if they exist and the handle methods flag
	// is enabled
	if !d.cs.DisableMethods {
		if (kind != reflect.Invalid) && (kind != reflect.Interface) {
			if handled := handleMethods(d.cs, d.w, v); handled {
				return
			}
		}
	}

	switch kind {
	case reflect.Invalid:
		// Do nothing.  We should never get here since invalid has already
		// been handled above.

	case reflect.Bool:
		printBool(d.w, v.Bool())

	case reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64, reflect.Int:
		printInt(d.w, v.Int(), 10)

	case reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uint:
		printUint(d.w, v.Uint(), 10)

	case reflect.Float32:
		printFloat(d.w, v.Float(), 32)

	case reflect.Float64:
		printFloat(d.w, v.Float(), 64)

	case reflect.Complex64:
		printComplex(d.w, v.Complex(), 32)

	case reflect.Complex128:
		printComplex(d.w, v.Complex(), 64)

	case reflect.Slice:
		if v.IsNil() {
			d.w.Write(nilAngleBytes)
			break
		}
		fallthrough

	case reflect.Array:
		d.w.Write(openBraceNewlineBytes)
		d.depth++
		if (d.cs.MaxDepth != 0) && (d.depth > d.cs.MaxDepth) {
			d.indent()
			d.w.Write(maxNewlineBytes)
		} else {
			d.dumpSlice(v)
		}
		d.depth--
		d.indent()
		d.w.Write(closeBraceBytes)

	case reflect.String:
		d.w.Write([]byte(strconv.Quote(v.String())))

	case reflect.Interface:
		// The only time we should get here is for nil interfaces due to
		// unpackValue calls.
		if v.IsNil() {
			d.w.Write(nilAngleBytes)
		}

	case reflect.Ptr:
		// Do nothing.  We should never get here since pointers have already
		// been handled above.

	case reflect.Map:
		// nil maps should be indicated as different than empty maps
		if v.IsNil() {
			d.w.Write(nilAngleBytes)
			break
		}

		d.w.Write(openBraceNewlineBytes)
		d.depth++
		if (d.cs.MaxDepth != 0) && (d.depth > d.cs.MaxDepth) {
			d.indent()
			d.w.Write(maxNewlineBytes)
		} else {
			numEntries := v.Len()
			keys := v.MapKeys()
			if d.cs.SortKeys {
				sortValues(keys, d.cs)
			}
			for i, key := range keys {
				d.dump(d.unpackValue(key))
				d.w.Write(colonSpaceBytes)
				d.ignoreNextIndent = true
				d.dump(d.unpackValue(v.MapIndex(key)))
				if i < (numEntries - 1) {
					d.w.Write(commaNewlineBytes)
				} else {
					d.w.Write(newlineBytes)
				}
			}
		}
		d.depth--
		d.indent()
		d.w.Write(closeBraceBytes)

	case reflect.Struct:
		d.w.Write(openBraceNewlineBytes)
		d.depth++
		if (d.cs.MaxDepth != 0) && (d.depth > d.cs.MaxDepth) {
			d.indent()
			d.w.Write(maxNewlineBytes)
		} else {
			vt := v.Type()
			numFields := v.NumField()
			for i := 0; i < numFields; i++ {
				d.indent()
				vtf := vt.Field(i)
				d.w.Write([]byte(vtf.Name))
				d.w.Write(colonSpaceBytes)
				d.ignoreNextIndent = true
				d.dump(d.unpackValue(v.Field(i)))
				if i < (numFields - 1) {
					d.w.Write(commaNewlineBytes)
				} else {
					d.w.Write(newlineBytes)
				}
			}
		}
		d.depth--
		d.indent()
		d.w.Write(closeBraceBytes)

	case reflect.Uintptr:
		printHexPtr(d.w, uintptr(v.Uint()))

	case reflect.UnsafePointer, reflect.Chan, reflect.Func:
		printHexPtr(d.w, v.Pointer())

	// There were not any other types at the time this code was written, but
	// fall back to letting the default fmt package handle it in case any new
	// types are added.
	default:
		if v.CanInterface() {
			fmt.Fprintf(d.w, "%v", v.Interface())
		} else {
			fmt.Fprintf(d.w, "%v", v.String())
		}
	}
}

// fdump is a helper function to consolidate the logic from the various public
// methods which take varying writers and config states.
func fdump(cs *ConfigState, w io.Writer, a ...interface{}) {
	for _, arg := range a {
		if arg == nil {
			w.Write(interfaceBytes)
			w.Write(spaceBytes)
			w.Write(nilAngleBytes)
			w.Write(newlineBytes)
			continue
		}

		d := dumpState{w: w, cs: cs}
		d.pointers = make(map[uintptr]int)
		d.dump(reflect.ValueOf(arg))
		d.w.Write(newlineBytes)
	}
}

// Fdump formats and displays the passed arguments to io.Writer w.  It formats
// exactly the same as Dump.
func Fdump(w io.Writer, a ...interface{}) {
	fdump(&Config, w, a...)
}

// Sdump returns a string with the passed arguments formatted exactly the same
// as Dump.
func Sdump(a ...interface{}) string {
	var buf bytes.Buffer
	fdump(&Config, &buf, a...)
	return buf.String()
}

/*
Dump displays the passed parameters to standard out with newlines, customizable
indentation, and additional debug information such as complete types and all
pointer addresses used to indirect to the final value.  It provides the
following features over the built-in printing facilities provided by the fmt
package:

	* Pointers are dereferenced and followed
	* Circular data structures are detected and handled properly
	* Custom Stringer/error interfaces are optionally invoked, including
	  on unexported types
	* Custom types which only implement the Stringer/error interfaces via
	  a pointer receiver are optionally invoked when passing non-pointer
	  variables
	* Byte arrays and slices are dumped like the hexdump -C command which
	  includes offsets, byte values in hex, and ASCII output

The configuration options are controlled by an exported package global,
spew.Config.  See ConfigState for options documentation.

See Fdump if you would prefer dumping to an arbitrary io.Writer or Sdump to
get the formatted result as a string.
*/
func Dump(a ...interface{}) {
	fdump(&Config, os.Stdout, a...)
}

"""



```