Response:
Let's break down the thought process for analyzing the Go code snippet and answering the user's request.

1. **Understand the Goal:** The user wants to know the functionality of the provided Go code, which is a part of the `spew` package for debugging output. They're asking for a description of its capabilities, illustrative code examples, explanations of involved Go features, handling of command-line arguments (if any), and common mistakes.

2. **Initial Code Scan and Keyword Identification:**  Quickly skim the code for prominent features and keywords. I see:
    * `package spew` -  Confirms this is part of the `spew` library.
    * Copyright notice and license - Standard boilerplate, skip for functionality.
    * `import` statements - Indicate dependencies, like `bytes`, `encoding/hex`, `fmt`, `io`, `os`, `reflect`, `regexp`, `strconv`, `strings`. These hint at functionalities like string manipulation, hex dumping, reflection, and output.
    * Global variables like `uint8Type`, `cCharRE`, `cUnsignedCharRE`, `cUint8tCharRE` - Suggest handling of different data types, especially related to C compatibility (cgo). The `regexp` usage indicates pattern matching for type names.
    * `dumpState` struct - This looks like the central context for the dumping process, holding state information.
    * Functions like `indent`, `unpackValue`, `dumpPtr`, `dumpSlice`, `dump`, `fdump`, `Fdump`, `Sdump`, `Dump` -  These are the core functions. The names strongly suggest different dumping behaviors and destinations.

3. **Focus on Core Functionality (the `dump` function and its helpers):** The name `dump` and its related functions (`dumpPtr`, `dumpSlice`) are the most suggestive of the core logic.

    * **`dumpState`:**  Analyze its members: `w` (writer, indicating output), `depth` (indentation level), `pointers` (for cycle detection), `ignoreNextType`/`ignoreNextIndent` (flags for formatting), `cs` (configuration). This structure manages the state of the dumping process.

    * **`dumpPtr`:** Deals with pointers. Key aspects:
        * Circular reference detection using the `pointers` map.
        * Displaying the type and memory address of the pointer.
        * Recursively calling `dump` on the dereferenced value.

    * **`dumpSlice`:** Handles arrays and slices. Notice the special handling for byte arrays (`uint8`) and C-style character arrays, which are hexdumped. This is a significant feature. The regular `dump` function is called recursively for other slice elements.

    * **`dump`:** The central dispatch function. It uses `reflect` to determine the type of the input value and then handles each type differently (bool, int, string, slice, map, struct, etc.). This is where the bulk of the formatting logic resides. Pay attention to the handling of nil values, interfaces, and the recursive nature of the function. The `handleMethods` call suggests invoking `Stringer` and `error` interfaces.

4. **Analyze Public Functions:**  Understand how the public functions expose the functionality:

    * **`Fdump`:** Takes an `io.Writer`, allowing output to any destination (files, buffers, etc.).
    * **`Sdump`:** Returns the formatted output as a string.
    * **`Dump`:** Prints to `os.Stdout`.

5. **Identify Key Go Features:** While analyzing the code, note the Go features being used:
    * **Reflection (`reflect` package):**  Crucial for inspecting the type and value of variables at runtime.
    * **Interfaces (`io.Writer`, `Stringer`, `error`):**  Used for polymorphism and custom formatting.
    * **Regular Expressions (`regexp`):** For matching C-style type names.
    * **String Manipulation (`strings`, `strconv`):**  For formatting the output.
    * **Hex Encoding (`encoding/hex`):** For the hexdump feature.
    * **Pointers:** Understanding how pointers and indirections are handled is essential.
    * **Maps:** Used for cycle detection (`pointers`).

6. **Infer Functionality and Provide Examples:** Based on the code analysis, describe the main functionalities: detailed variable dumping, handling pointers and circular references, hexdumping byte slices, invoking `Stringer`/`error` interfaces. Create simple Go examples to illustrate these features. Include expected input and output to make the examples clear.

7. **Command-Line Arguments:**  Carefully review the code for any command-line argument processing. In this snippet, there is *no* explicit command-line argument handling within the provided code. The configuration is done through the `spew.Config` global variable. It's important to state this clearly.

8. **Common Mistakes:** Think about how users might misuse this library. The most likely mistake is being unaware of the configuration options and getting unexpected output (e.g., not wanting pointer addresses, maximum depth being too shallow, not sorting map keys). Illustrate this with an example of modifying the `spew.Config`.

9. **Structure the Answer:** Organize the findings logically:
    * Start with a summary of the main functions.
    * Elaborate on each function with details.
    * Provide code examples with input and output.
    * Explain the relevant Go language features.
    * Address the command-line argument question.
    * Discuss potential user errors.
    * Use clear and concise language.

10. **Review and Refine:**  Read through the answer to ensure accuracy, clarity, and completeness. Check if the examples are correct and easy to understand. Make sure all aspects of the user's request are addressed. For example, initially, I might have overlooked the subtle detail of how C-style char arrays are handled. A careful re-read of the code would catch this.
这段Go语言代码是 `go-spew` 库中用于实现深度打印（dump）功能的关键部分。`go-spew` 用于以更易读和更详细的方式打印Go语言的变量，特别是在调试和日志记录时非常有用。

以下是这段代码的主要功能：

1. **深度遍历和打印任意Go变量:**  `dump` 函数是核心，它接收一个 `reflect.Value`，可以表示任何Go变量的值。它通过反射机制来检查变量的类型和内容，并进行格式化输出。这使得 `spew` 能够打印出嵌套结构，如结构体、切片、映射等。

2. **处理指针和循环引用:**  `dumpPtr` 函数专门处理指针类型。它会解引用指针，并跟踪已经访问过的指针地址，以检测和处理循环引用，避免无限递归。  当检测到循环引用时，会打印 `(circular)`。

3. **格式化输出:** 代码包含多种格式化输出的逻辑，例如：
    * **缩进:**  根据嵌套深度进行缩进，使输出更易读。
    * **类型信息:**  打印变量的类型信息，包括指针的层级。
    * **长度和容量:**  对于切片、数组和映射，会打印其长度和容量。
    * **十六进制转储:** 对于 `uint8` 类型的切片或数组，以及某些C语言风格的字符数组 (`_Ctype_char`, `_Ctype_unsignedchar`, `_Ctype_uint8_t`)，会以 `hexdump -C` 风格进行十六进制转储，显示偏移量、十六进制值和ASCII表示。

4. **调用 `Stringer` 和 `error` 接口:**  如果变量实现了 `fmt.Stringer` 或 `error` 接口，且配置允许 (`!d.cs.DisableMethods`)，则会调用这些方法来获取自定义的字符串表示。

5. **配置选项:** 通过 `dumpState` 结构体中的 `cs` 字段 (`ConfigState`)，可以控制打印的各种行为，例如缩进字符串、最大深度、是否显示指针地址、是否禁用调用 `Stringer`/`error` 方法等。这些配置通常在 `spew` 包的全局变量 `Config` 中设置。

6. **提供多种输出方式:** 提供了 `Fdump`（输出到 `io.Writer`）、`Sdump`（返回格式化后的字符串）和 `Dump`（输出到标准输出）等多个公共函数，方便用户在不同场景下使用。

**它是什么Go语言功能的实现？**

这段代码主要实现了 **Go语言的反射 (Reflection)** 功能。  `reflect` 包允许程序在运行时检查和操作变量的类型和值，这是 `spew` 能够实现通用深度打印的核心。

**Go代码举例说明:**

```go
package main

import (
	"fmt"
	"github.com/davecgh/go-spew/spew"
)

type Person struct {
	Name string
	Age  int
	City *City
	Friends []*Person
}

type City struct {
	Name    string
	Country string
}

func main() {
	city1 := &City{Name: "Beijing", Country: "China"}
	person1 := &Person{Name: "Alice", Age: 30, City: city1, Friends: []*Person{}}
	person2 := &Person{Name: "Bob", Age: 25, City: city1, Friends: []*Person{person1}}
	person1.Friends = append(person1.Friends, person2) // 创建循环引用

	fmt.Println("使用 fmt.Printf 的输出:")
	fmt.Printf("%+v\n", person1)

	fmt.Println("\n使用 spew.Dump 的输出:")
	spew.Dump(person1)
}
```

**假设的输入与输出:**

**输入 (运行上述代码):**

```go
// 代码本身定义了输入的数据结构和值
```

**输出:**

```
使用 fmt.Printf 的输出:
&{Name:Alice Age:30 City:0xc00004c390 Friends:[]unsafe.Pointer{0xc00004c480}}

使用 spew.Dump 的输出:
(*main.Person)(0xc00004c330)(
 Name: (string) "Alice",
 Age: (int) 30,
 City: (*main.City)(0xc00004c390)(
  Name: (string) "Beijing",
  Country: (string) "China",
 ),
 Friends: ([]*main.Person)(len=1 cap=1)(
  (*main.Person)(0xc00004c480)(
   Name: (string) "Bob",
   Age: (int) 25,
   City: (*main.City)(0xc00004c390)(
    Name: (string) "Beijing",
    Country: (string) "China",
   ),
   Friends: ([]*main.Person)(len=1 cap=1)(
    (*main.Person)(0xc00004c330)(circular),
   ),
  ),
 ),
)
```

**代码推理:**

* `fmt.Printf` 使用 `%+v` 只能提供基本的结构体字段名和值，对于嵌套结构和指针的显示相对简单。
* `spew.Dump` 提供了更详细的输出：
    * 包含了变量的类型信息 (`*main.Person`, `string`, `*main.City`)。
    * 明确显示了指针地址 `(0xc00004c330)`。
    * 能够深入打印嵌套的结构体 `City`。
    * **关键是它检测到了循环引用**，并将 `person1` 在 `person2.Friends` 中的引用标记为 `(circular)`，避免了无限递归。

**命令行参数的具体处理:**

这段代码本身并没有直接处理命令行参数。`go-spew` 的配置通常是通过修改其全局 `Config` 变量来实现的。例如，你可以在代码中设置缩进字符串、最大深度等：

```go
package main

import (
	"github.com/davecgh/go-spew/spew"
	"os"
)

func main() {
	spew.Config.Indent = "\t\t" // 设置缩进为两个制表符
	spew.Config.MaxDepth = 2    // 设置最大打印深度为 2

	data := map[string]interface{}{
		"name": "Example",
		"details": map[string]int{
			"value1": 10,
			"value2": 20,
		},
		"more": map[string]int{
			"nested1": 100,
		},
	}

	spew.Fdump(os.Stdout, data)
}
```

在这个例子中，我们通过修改 `spew.Config.Indent` 和 `spew.Config.MaxDepth` 来影响 `spew.Fdump` 的输出格式。  `go-spew` 本身没有内置的命令行参数解析逻辑。

**使用者易犯错的点:**

1. **不了解配置选项:**  `go-spew` 提供了很多配置选项，例如 `Indent`, `MaxDepth`, `DisablePointerAddresses`, `DisableMethods` 等。 如果不了解这些选项，可能会得到不符合预期的输出。

   **示例:**  如果用户想要查看所有指针的地址，但 `DisablePointerAddresses` 设置为 `true`，那么指针地址就不会显示出来。

2. **对循环引用的处理不熟悉:**  虽然 `go-spew` 可以处理循环引用，但用户可能不清楚它是如何检测和表示循环引用的 (`(circular)`)。

   **示例:**  用户可能会惊讶于一个结构体包含了自身，但 `spew` 只是打印 `(circular)` 而不是崩溃。

3. **误以为可以完全替代 `fmt.Printf`:**  虽然 `spew` 提供了更详细的输出，但在某些性能敏感的场景下，`fmt.Printf` 可能更轻量级。  `spew` 的反射操作会有一定的性能开销。

4. **忘记导入 `spew` 包:**  这是一个基础错误，但初学者可能会忘记导入 `github.com/davecgh/go-spew/spew` 包就直接使用 `spew.Dump`。

总而言之，这段代码是 `go-spew` 库的核心，利用 Go 语言的反射机制实现了深度、格式化的变量打印功能，并能处理指针和循环引用，是 Go 语言调试和日志记录的有力工具。

Prompt: 
```
这是路径为go/src/github.com/alecthomas/gometalinter/_linters/src/github.com/stretchr/objx/vendor/github.com/davecgh/go-spew/spew/dump.go的go语言实现的一部分， 请列举一下它的功能, 　
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