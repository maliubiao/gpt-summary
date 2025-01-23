Response:
Let's break down the thought process for analyzing this Go code snippet.

**1. Initial Understanding: What is the file about?**

The file path `go/src/runtime/string.go` immediately tells us this code is part of the Go runtime and deals with string manipulation. The package declaration `package runtime` confirms this. The copyright notice reinforces that this is official Go code.

**2. Scanning for Key Functionalities:**

I'll read through the code, focusing on function names and comments. This gives a high-level overview:

* **`concatstrings`, `concatstring2`...`concatstring5`:** These clearly handle string concatenation. The different suffixes suggest optimizations for different numbers of strings being concatenated.
* **`concatbytes`, `concatbyte2`...`concatbyte5`:**  Similar to the `concatstring` functions, but they return a `[]byte` instead of a `string`. This hints at a potential performance optimization or a different use case.
* **`slicebytetostring`:**  This function converts a byte slice to a string. The comment mentions compiler insertion, which is an important detail.
* **`stringDataOnStack`:** This seems to check if a string's underlying data resides on the stack. This is relevant for optimization, as stack allocation is generally faster.
* **`rawstringtmp`, `rawstring`:**  These appear to be low-level functions for allocating memory for strings. The `tmp` suffix might indicate a temporary allocation strategy.
* **`slicebytetostringtmp`:**  Another byte slice to string conversion, with a comment emphasizing potential modification issues if not used carefully. This suggests it's a potentially unsafe but optimized version.
* **`stringtoslicebyte`, `stringtoslicerune`:** These convert strings to byte slices and rune slices, respectively.
* **`slicerunetostring`:** Converts a rune slice back to a string.
* **`intstring`:**  Converts an integer to a string.
* **`gobytes`, `gostring`, `gostringn`:** These look like functions for converting C-style strings (`*byte`) to Go strings. The `go:linkname` directive is a strong indicator of interaction with external code.
* **`atoi64`, `atoi`, `atoi32`:**  Functions for converting strings to integers.
* **`parseByteCount`:**  Parses strings representing byte counts with optional suffixes (KB, MB, etc.).
* **`findnull`, `findnullw`:**  Functions to find the null terminator in byte and `uint16` arrays, often used with C-style strings.
* **`gostringnocopy`, `gostringw`:**  More functions for converting C-style strings to Go strings, with `nocopy` suggesting an optimization to avoid copying.

**3. Grouping and Categorizing Functionalities:**

Based on the names and comments, I can group the functions by their primary purpose:

* **String Concatenation:** `concatstrings`, `concatstringN`, `concatbytes`, `concatbyteN`
* **Byte/Rune Slice to String Conversion:** `slicebytetostring`, `slicebytetostringtmp`, `slicerunetostring`
* **String to Byte/Rune Slice Conversion:** `stringtoslicebyte`, `stringtoslicerune`
* **C-style String Conversion:** `gobytes`, `gostring`, `gostringn`, `gostringnocopy`, `gostringw`
* **Integer/Byte Count Parsing:** `atoi64`, `atoi`, `atoi32`, `parseByteCount`, `intstring`
* **Internal Helpers:** `rawstring`, `rawstringtmp`, `rawbyteslice`, `rawruneslice`, `stringDataOnStack`, `findnull`, `findnullw`

**4. Identifying Key Go Features:**

By understanding the functionalities, I can connect them to specific Go language features:

* **String Concatenation (`+` operator):** The `concatstring` functions are the underlying implementation of the `+` operator for strings.
* **Type Conversions (`string([]byte)`, `[]byte(string)`, `string([]rune)`):**  Functions like `slicebytetostring`, `stringtoslicebyte`, and `slicerunetostring` are used during these conversions.
* **Interaction with C code (cgo):** The `gobytes`, `gostring`, and related functions are crucial for interoperability with C libraries.
* **String Immutability:**  The code hints at optimizations based on whether string data is on the stack, and the need for copying in certain scenarios aligns with the immutability of Go strings.

**5. Developing Examples and Reasoning:**

For key functions, I can create simple Go examples to illustrate their use. For example, for `concatstrings`, I would demonstrate the `+` operator. For `slicebytetostring`, I'd show converting a `[]byte` to a `string`.

When reasoning about the code, I'll pay attention to:

* **Memory Allocation:** How are strings and slices allocated (`mallocgc`, `rawstring`, `rawbyteslice`)?
* **Optimization Techniques:**  The use of `tmpBuf`, checking if data is on the stack, and the specialized `concatstringN` functions suggest optimization efforts.
* **Potential Pitfalls:** The comment in `slicebytetostringtmp` is a clear warning about misuse.

**6. Considering Command-Line Arguments and Error Handling:**

While this specific code snippet doesn't directly handle command-line arguments, the `parseByteCount` function *could* be used to parse size arguments provided via the command line. Error handling is evident in functions like `atoi64` and `parseByteCount`, which return a boolean indicating success.

**7. Structuring the Answer:**

Finally, I'll organize the findings into a clear and structured answer, using headings, bullet points, and code examples to enhance readability. I'll address each part of the prompt systematically: functionalities, feature implementation, code reasoning, command-line arguments, and common mistakes.

This iterative process of reading, analyzing, categorizing, connecting to language features, and creating examples allows for a comprehensive understanding of the provided Go code. The focus is on understanding the *purpose* of the code within the larger context of the Go runtime.
这段代码是 Go 语言运行时环境 (`runtime`) 中 `string.go` 文件的一部分，它主要负责实现 Go 语言中字符串和字节切片之间的转换和连接操作。以下是其功能的详细列表：

**主要功能：**

1. **字符串连接 (`+` 运算符的底层实现):**
   - `concatstrings(buf *tmpBuf, a []string) string`:  实现多个字符串的连接。它可以接收一个预分配的临时缓冲区 `buf`，如果最终字符串足够小且不逃逸到调用函数之外，则可以将结果存储在该缓冲区中，以提高性能。
   - `concatstring2` 到 `concatstring5`: 针对 2 到 5 个字符串连接的优化版本，它们实际上是调用 `concatstrings` 并将参数包装成切片。

2. **字节切片连接:**
   - `concatbytes(a []string) []byte`:  将多个字符串连接成一个新的字节切片。
   - `concatbyte2` 到 `concatbyte5`: 针对 2 到 5 个字符串连接的优化版本，它们实际上是调用 `concatbytes` 并将参数包装成切片。

3. **字节切片到字符串的转换:**
   - `slicebytetostring(buf *tmpBuf, ptr *byte, n int) string`: 将一个字节切片转换为字符串。同样，它可以利用提供的临时缓冲区 `buf`。
   - `slicebytetostringtmp(ptr *byte, n int) string`:  一个更底层的版本，直接基于字节切片的指针和长度创建一个字符串。**注意：这个函数返回的字符串直接指向底层的字节数组，调用者需要确保在字符串使用期间，底层的字节数组不会被修改。** 这通常用于编译器优化场景。

4. **字符串到字节切片的转换:**
   - `stringtoslicebyte(buf *tmpBuf, s string) []byte`: 将字符串转换为字节切片。可以使用提供的临时缓冲区 `buf`。

5. **字符串到 Rune 切片的转换:**
   - `stringtoslicerune(buf *[tmpStringBufSize]rune, s string) []rune`: 将字符串转换为 Rune（Unicode 码点）切片。

6. **Rune 切片到字符串的转换:**
   - `slicerunetostring(buf *tmpBuf, a []rune) string`: 将 Rune 切片转换为字符串。可以使用提供的临时缓冲区 `buf`。

7. **与 C 风格字符串的交互:**
   - `gobytes(p *byte, n int) []byte`: 将指向 C 风格字符数组的指针和长度转换为 Go 的字节切片。
   - `gostring(p *byte) string`: 将指向 C 风格以 null 结尾的字符串的指针转换为 Go 字符串。
   - `internal_syscall_gostring(p *byte) string`: `gostring` 的内部版本，用于 `internal/syscall/unix` 包。
   - `gostringn(p *byte, l int) string`: 将指向 C 风格字符数组的指针和指定长度转换为 Go 字符串。
   - `gostringnocopy(str *byte) string`:  将指向 C 风格以 null 结尾的字符串的指针转换为 Go 字符串，**可能不会进行内存拷贝，直接使用底层内存**。这需要特别小心使用，因为底层内存可能由其他代码管理。
   - `gostringw(strw *uint16) string`: 将指向 C 风格以 null 结尾的宽字符 (uint16) 数组的指针转换为 Go 字符串。

8. **字符串和切片的底层操作:**
   - `rawstring(size int) (s string, b []byte)`: 分配指定大小的字符串存储空间，返回字符串和指向相同内存的字节切片。
   - `rawstringtmp(buf *tmpBuf, l int) (s string, b []byte)`: 尝试在提供的缓冲区中分配字符串，如果空间不足则调用 `rawstring`。
   - `rawbyteslice(size int) []byte`: 分配指定大小的字节切片。
   - `rawruneslice(size int) []rune`: 分配指定大小的 Rune 切片。

9. **辅助功能:**
   - `stringDataOnStack(s string) bool`:  检查字符串的底层数据是否存储在当前 Goroutine 的栈上。这主要用于优化，栈上分配通常更快。
   - `intstring(buf *[4]byte, v int64) string`: 将一个 `int64` 转换为包含其 Unicode 码点表示的字符串。
   - `atoi64(s string) (int64, bool)`: 将字符串转换为 `int64`。返回一个布尔值表示转换是否成功。
   - `atoi(s string) (int, bool)`: 将字符串转换为 `int`。
   - `atoi32(s string) (int32, bool)`: 将字符串转换为 `int32`。
   - `parseByteCount(s string) (int64, bool)`: 解析表示字节数的字符串，支持单位后缀 (如 "1024B", "1KB", "2MiB" 等)。
   - `findnull(s *byte) int`: 在以 null 结尾的字节数组中查找 null 字符的位置。
   - `findnullw(s *uint16) int`: 在以 null 结尾的宽字符数组中查找 null 字符的位置。
   - `stringStructOf(sp *string) *stringStruct`:  返回字符串的底层结构 `stringStruct` 的指针。
   - `tmpBuf`:  定义了一个固定大小的字节数组类型，用作临时缓冲区。

**它是什么 Go 语言功能的实现？**

这段代码是 Go 语言中以下核心功能的底层实现：

* **字符串连接 (`+` 运算符):**  `concatstrings` 系列函数是 `+` 运算符用于连接字符串时的实际执行代码。
* **字符串和字节切片之间的类型转换:**  例如，当你使用 `string(byteSlice)` 或 `[]byte(str)` 进行类型转换时，`slicebytetostring` 和 `stringtoslicebyte` 等函数会被调用。
* **与 C 代码的互操作 (cgo):** `gobytes`, `gostring`, `gostringn` 等函数使得 Go 语言能够方便地与 C 语言编写的库进行交互，将 C 风格的字符串转换为 Go 字符串，并将数据传递给 C 函数。
* **字符串的内部表示和操作:**  `rawstring` 等函数负责字符串的内存分配，而 `stringDataOnStack` 则涉及到 Go 运行时对字符串存储位置的管理。
* **字符串到数字的转换:** `atoi` 系列函数实现了将字符串表示的数字转换为 Go 的数字类型的功能。
* **解析字节大小字符串:** `parseByteCount`  在很多需要解析大小配置的场景中使用，例如资源限制、内存分配等。

**Go 代码举例说明:**

```go
package main

import "fmt"

func main() {
	// 字符串连接
	s1 := "Hello"
	s2 := " "
	s3 := "World"
	result := s1 + s2 + s3
	fmt.Println(result) // 输出: Hello World

	// 字节切片到字符串的转换
	byteSlice := []byte{'G', 'o'}
	strFromBytes := string(byteSlice)
	fmt.Println(strFromBytes) // 输出: Go

	// 字符串到字节切片的转换
	str := "Example"
	bytesFromString := []byte(str)
	fmt.Println(bytesFromString) // 输出: [69 120 97 109 112 108 101]

	// 与 C 风格字符串交互 (假设有 cgo 代码)
	// /*
	// #include <stdlib.h>
	// #include <string.h>
	// */
	// import "C"
	//
	// cStr := C.CString("C String")
	// defer C.free(unsafe.Pointer(cStr))
	// goStr := C.GoString(cStr)
	// fmt.Println(goStr)

	// 字符串到数字的转换
	numStr := "12345"
	num, ok := atoi(numStr)
	if ok {
		fmt.Println(num) // 输出: 12345
	}

	// 解析字节大小字符串
	sizeStr := "10MiB"
	size, ok := parseByteCount(sizeStr)
	if ok {
		fmt.Println(size) // 输出: 10485760
	}
}

func atoi(s string) (int, bool) {
	// 这里只是一个简化的例子，实际的 atoi 实现更复杂
	n := 0
	for _, r := range s {
		if r < '0' || r > '9' {
			return 0, false
		}
		n = n*10 + int(r-'0')
	}
	return n, true
}

func parseByteCount(s string) (int64, bool) {
	// 这里只是一个简化的例子，实际的 parseByteCount 实现更复杂
	multipliers := map[string]int64{"B": 1, "KB": 1024, "MB": 1024 * 1024}
	for suffix, multiplier := range multipliers {
		if len(s) > len(suffix) && s[len(s)-len(suffix):] == suffix {
			numStr := s[:len(s)-len(suffix)]
			n := 0
			for _, r := range numStr {
				if r < '0' || r > '9' {
					return 0, false
				}
				n = n*10 + int(r-'0')
			}
			return int64(n) * multiplier, true
		}
	}
	return 0, false
}
```

**代码推理 (假设的输入与输出):**

假设我们调用 `concatstrings` 函数：

```go
package main

import "fmt"
import "unsafe"

// 假设这是 runtime 包中的定义
type tmpBuf [32]byte

// 假设这是 runtime 包中的函数
func concatstrings(buf *tmpBuf, a []string) string {
	idx := 0
	l := 0
	count := 0
	for i, x := range a {
		n := len(x)
		if n == 0 {
			continue
		}
		if l+n < l {
			panic("string concatenation too long")
		}
		l += n
		count++
		idx = i
	}
	if count == 0 {
		return ""
	}

	if count == 1 && (buf != nil || !stringDataOnStack(a[idx])) {
		return a[idx]
	}
	s, b := rawstringtmp(buf, l)
	for _, x := range a {
		n := copy(b, x)
		b = b[n:]
	}
	return s
}

func rawstringtmp(buf *tmpBuf, l int) (s string, b []byte) {
	if buf != nil && l <= len(buf) {
		b = buf[:l]
		s = slicebytetostringtmp(&b[0], len(b))
	} else {
		s, b = rawstring(l)
	}
	return
}

func slicebytetostringtmp(ptr *byte, n int) string {
	return unsafe.String(unsafe.Pointer(ptr), n)
}

func rawstring(size int) (s string, b []byte) {
	p := make([]byte, size)
	return *(*string)(unsafe.Pointer(&p)), p
}

func stringDataOnStack(s string) bool {
	// 简化实现，实际的检查更复杂
	return false
}

func main() {
	var buf tmpBuf
	stringsToConcat := []string{"Hello", ", ", "World!"}
	result := concatstrings(&buf, stringsToConcat)
	fmt.Println(result) // 输出: Hello, World!
}
```

**假设的输入:** `stringsToConcat` 为 `[]string{"Hello", ", ", "World!"}`， `buf` 是一个足够大的 `tmpBuf`。

**推理:**

1. `concatstrings` 计算连接后字符串的总长度 `l`。
2. 由于 `buf` 不为 `nil` 且总长度 `l` (13) 小于 `tmpBuf` 的大小 (32)，`rawstringtmp` 会尝试使用 `buf`。
3. `rawstringtmp` 将 `buf` 的一部分切片出来作为 `b`，长度为 `l`。
4. `slicebytetostringtmp`  使用 `unsafe.String` 将 `b` 转换为字符串 `s`，**注意：这里 `s` 的底层数据就是 `buf` 的一部分。**
5. 循环遍历 `stringsToConcat`，将每个字符串的内容拷贝到 `b` 中。
6. 最终返回字符串 `s`，其内容为 "Hello, World!"。

**涉及命令行参数的具体处理:**

这段代码本身不直接处理命令行参数。但是，像 `parseByteCount` 这样的函数可能会在处理命令行参数时被使用。例如，在某个需要接收内存大小作为参数的程序中，可以使用 `parseByteCount` 来解析用户输入的字符串，例如：

```go
package main

import (
	"fmt"
	"os"
	"strconv"
)

// 假设这是 runtime 包中的函数
func parseByteCount(s string) (int64, bool) {
	multipliers := map[string]int64{"B": 1, "KB": 1024, "MB": 1024 * 1024}
	for suffix, multiplier := range multipliers {
		if len(s) > len(suffix) && s[len(s)-len(suffix):] == suffix {
			numStr := s[:len(s)-len(suffix)]
			n, err := strconv.Atoi(numStr)
			if err != nil {
				return 0, false
			}
			return int64(n) * multiplier, true
		}
	}
	n, err := strconv.Atoi(s)
	if err == nil {
		return int64(n), true
	}
	return 0, false
}

func main() {
	if len(os.Args) != 2 {
		fmt.Println("Usage: program <byte_count>")
		return
	}

	sizeStr := os.Args[1]
	size, ok := parseByteCount(sizeStr)
	if !ok {
		fmt.Printf("Invalid byte count: %s\n", sizeStr)
		return
	}

	fmt.Printf("Parsed size: %d bytes\n", size)
}
```

在这个例子中，如果用户在命令行输入 `program 1GB`，`parseByteCount` 函数会被用来解析 "1GB" 并返回对应的字节数。

**使用者易犯错的点:**

1. **滥用 `slicebytetostringtmp`:**  这个函数返回的字符串直接指向底层的字节数组。如果字节数组在字符串使用期间被修改，会导致未定义的行为。例如：

   ```go
   package main

   import "fmt"
   import "unsafe"

   func slicebytetostringtmp(ptr *byte, n int) string {
       return unsafe.String(unsafe.Pointer(ptr), n)
   }

   func main() {
       data := []byte{'h', 'e', 'l', 'l', 'o'}
       str := slicebytetostringtmp(&data[0], len(data))
       fmt.Println(str) // 输出: hello

       data[0] = 'J' // 修改了底层的字节数组
       fmt.Println(str) // 输出: Jello (字符串的内容也被修改了！)
   }
   ```

2. **错误地假设 `concatstrings` 的 `buf` 参数一定会生效:**  即使提供了 `buf`，如果最终的字符串长度超过 `tmpStringBufSize`，或者编译器判断结果可能会逃逸，`concatstrings` 仍然会分配新的内存。使用者不应依赖 `buf` 来控制内存分配的行为。

3. **在 C/Go 字符串转换中不注意内存管理:**  在使用 `C.CString` 等函数从 Go 传递字符串给 C 代码时，需要在 C 代码中使用 `free` 释放内存。同样，从 C 代码通过 `C.GoString` 获得的 Go 字符串，其底层的 C 内存是由 Go 运行时管理的，不应手动释放。忘记释放内存会导致内存泄漏。

总而言之，这段代码是 Go 语言中处理字符串和字节切片的核心部分，它提供了高效的连接和转换功能，并支持与 C 代码的互操作。理解其功能和潜在的陷阱对于编写健壮的 Go 程序至关重要。

### 提示词
```
这是路径为go/src/runtime/string.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
```

### 源代码
```go
// Copyright 2014 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package runtime

import (
	"internal/abi"
	"internal/bytealg"
	"internal/goarch"
	"internal/runtime/sys"
	"unsafe"
)

// The constant is known to the compiler.
// There is no fundamental theory behind this number.
const tmpStringBufSize = 32

type tmpBuf [tmpStringBufSize]byte

// concatstrings implements a Go string concatenation x+y+z+...
// The operands are passed in the slice a.
// If buf != nil, the compiler has determined that the result does not
// escape the calling function, so the string data can be stored in buf
// if small enough.
func concatstrings(buf *tmpBuf, a []string) string {
	idx := 0
	l := 0
	count := 0
	for i, x := range a {
		n := len(x)
		if n == 0 {
			continue
		}
		if l+n < l {
			throw("string concatenation too long")
		}
		l += n
		count++
		idx = i
	}
	if count == 0 {
		return ""
	}

	// If there is just one string and either it is not on the stack
	// or our result does not escape the calling frame (buf != nil),
	// then we can return that string directly.
	if count == 1 && (buf != nil || !stringDataOnStack(a[idx])) {
		return a[idx]
	}
	s, b := rawstringtmp(buf, l)
	for _, x := range a {
		n := copy(b, x)
		b = b[n:]
	}
	return s
}

func concatstring2(buf *tmpBuf, a0, a1 string) string {
	return concatstrings(buf, []string{a0, a1})
}

func concatstring3(buf *tmpBuf, a0, a1, a2 string) string {
	return concatstrings(buf, []string{a0, a1, a2})
}

func concatstring4(buf *tmpBuf, a0, a1, a2, a3 string) string {
	return concatstrings(buf, []string{a0, a1, a2, a3})
}

func concatstring5(buf *tmpBuf, a0, a1, a2, a3, a4 string) string {
	return concatstrings(buf, []string{a0, a1, a2, a3, a4})
}

// concatbytes implements a Go string concatenation x+y+z+... returning a slice
// of bytes.
// The operands are passed in the slice a.
func concatbytes(a []string) []byte {
	l := 0
	for _, x := range a {
		n := len(x)
		if l+n < l {
			throw("string concatenation too long")
		}
		l += n
	}
	if l == 0 {
		// This is to match the return type of the non-optimized concatenation.
		return []byte{}
	}

	b := rawbyteslice(l)
	offset := 0
	for _, x := range a {
		copy(b[offset:], x)
		offset += len(x)
	}

	return b
}

func concatbyte2(a0, a1 string) []byte {
	return concatbytes([]string{a0, a1})
}

func concatbyte3(a0, a1, a2 string) []byte {
	return concatbytes([]string{a0, a1, a2})
}

func concatbyte4(a0, a1, a2, a3 string) []byte {
	return concatbytes([]string{a0, a1, a2, a3})
}

func concatbyte5(a0, a1, a2, a3, a4 string) []byte {
	return concatbytes([]string{a0, a1, a2, a3, a4})
}

// slicebytetostring converts a byte slice to a string.
// It is inserted by the compiler into generated code.
// ptr is a pointer to the first element of the slice;
// n is the length of the slice.
// Buf is a fixed-size buffer for the result,
// it is not nil if the result does not escape.
func slicebytetostring(buf *tmpBuf, ptr *byte, n int) string {
	if n == 0 {
		// Turns out to be a relatively common case.
		// Consider that you want to parse out data between parens in "foo()bar",
		// you find the indices and convert the subslice to string.
		return ""
	}
	if raceenabled {
		racereadrangepc(unsafe.Pointer(ptr),
			uintptr(n),
			sys.GetCallerPC(),
			abi.FuncPCABIInternal(slicebytetostring))
	}
	if msanenabled {
		msanread(unsafe.Pointer(ptr), uintptr(n))
	}
	if asanenabled {
		asanread(unsafe.Pointer(ptr), uintptr(n))
	}
	if n == 1 {
		p := unsafe.Pointer(&staticuint64s[*ptr])
		if goarch.BigEndian {
			p = add(p, 7)
		}
		return unsafe.String((*byte)(p), 1)
	}

	var p unsafe.Pointer
	if buf != nil && n <= len(buf) {
		p = unsafe.Pointer(buf)
	} else {
		p = mallocgc(uintptr(n), nil, false)
	}
	memmove(p, unsafe.Pointer(ptr), uintptr(n))
	return unsafe.String((*byte)(p), n)
}

// stringDataOnStack reports whether the string's data is
// stored on the current goroutine's stack.
func stringDataOnStack(s string) bool {
	ptr := uintptr(unsafe.Pointer(unsafe.StringData(s)))
	stk := getg().stack
	return stk.lo <= ptr && ptr < stk.hi
}

func rawstringtmp(buf *tmpBuf, l int) (s string, b []byte) {
	if buf != nil && l <= len(buf) {
		b = buf[:l]
		s = slicebytetostringtmp(&b[0], len(b))
	} else {
		s, b = rawstring(l)
	}
	return
}

// slicebytetostringtmp returns a "string" referring to the actual []byte bytes.
//
// Callers need to ensure that the returned string will not be used after
// the calling goroutine modifies the original slice or synchronizes with
// another goroutine.
//
// The function is only called when instrumenting
// and otherwise intrinsified by the compiler.
//
// Some internal compiler optimizations use this function.
//   - Used for m[T1{... Tn{..., string(k), ...} ...}] and m[string(k)]
//     where k is []byte, T1 to Tn is a nesting of struct and array literals.
//   - Used for "<"+string(b)+">" concatenation where b is []byte.
//   - Used for string(b)=="foo" comparison where b is []byte.
func slicebytetostringtmp(ptr *byte, n int) string {
	if raceenabled && n > 0 {
		racereadrangepc(unsafe.Pointer(ptr),
			uintptr(n),
			sys.GetCallerPC(),
			abi.FuncPCABIInternal(slicebytetostringtmp))
	}
	if msanenabled && n > 0 {
		msanread(unsafe.Pointer(ptr), uintptr(n))
	}
	if asanenabled && n > 0 {
		asanread(unsafe.Pointer(ptr), uintptr(n))
	}
	return unsafe.String(ptr, n)
}

func stringtoslicebyte(buf *tmpBuf, s string) []byte {
	var b []byte
	if buf != nil && len(s) <= len(buf) {
		*buf = tmpBuf{}
		b = buf[:len(s)]
	} else {
		b = rawbyteslice(len(s))
	}
	copy(b, s)
	return b
}

func stringtoslicerune(buf *[tmpStringBufSize]rune, s string) []rune {
	// two passes.
	// unlike slicerunetostring, no race because strings are immutable.
	n := 0
	for range s {
		n++
	}

	var a []rune
	if buf != nil && n <= len(buf) {
		*buf = [tmpStringBufSize]rune{}
		a = buf[:n]
	} else {
		a = rawruneslice(n)
	}

	n = 0
	for _, r := range s {
		a[n] = r
		n++
	}
	return a
}

func slicerunetostring(buf *tmpBuf, a []rune) string {
	if raceenabled && len(a) > 0 {
		racereadrangepc(unsafe.Pointer(&a[0]),
			uintptr(len(a))*unsafe.Sizeof(a[0]),
			sys.GetCallerPC(),
			abi.FuncPCABIInternal(slicerunetostring))
	}
	if msanenabled && len(a) > 0 {
		msanread(unsafe.Pointer(&a[0]), uintptr(len(a))*unsafe.Sizeof(a[0]))
	}
	if asanenabled && len(a) > 0 {
		asanread(unsafe.Pointer(&a[0]), uintptr(len(a))*unsafe.Sizeof(a[0]))
	}
	var dum [4]byte
	size1 := 0
	for _, r := range a {
		size1 += encoderune(dum[:], r)
	}
	s, b := rawstringtmp(buf, size1+3)
	size2 := 0
	for _, r := range a {
		// check for race
		if size2 >= size1 {
			break
		}
		size2 += encoderune(b[size2:], r)
	}
	return s[:size2]
}

type stringStruct struct {
	str unsafe.Pointer
	len int
}

// Variant with *byte pointer type for DWARF debugging.
type stringStructDWARF struct {
	str *byte
	len int
}

func stringStructOf(sp *string) *stringStruct {
	return (*stringStruct)(unsafe.Pointer(sp))
}

func intstring(buf *[4]byte, v int64) (s string) {
	var b []byte
	if buf != nil {
		b = buf[:]
		s = slicebytetostringtmp(&b[0], len(b))
	} else {
		s, b = rawstring(4)
	}
	if int64(rune(v)) != v {
		v = runeError
	}
	n := encoderune(b, rune(v))
	return s[:n]
}

// rawstring allocates storage for a new string. The returned
// string and byte slice both refer to the same storage.
// The storage is not zeroed. Callers should use
// b to set the string contents and then drop b.
func rawstring(size int) (s string, b []byte) {
	p := mallocgc(uintptr(size), nil, false)
	return unsafe.String((*byte)(p), size), unsafe.Slice((*byte)(p), size)
}

// rawbyteslice allocates a new byte slice. The byte slice is not zeroed.
func rawbyteslice(size int) (b []byte) {
	cap := roundupsize(uintptr(size), true)
	p := mallocgc(cap, nil, false)
	if cap != uintptr(size) {
		memclrNoHeapPointers(add(p, uintptr(size)), cap-uintptr(size))
	}

	*(*slice)(unsafe.Pointer(&b)) = slice{p, size, int(cap)}
	return
}

// rawruneslice allocates a new rune slice. The rune slice is not zeroed.
func rawruneslice(size int) (b []rune) {
	if uintptr(size) > maxAlloc/4 {
		throw("out of memory")
	}
	mem := roundupsize(uintptr(size)*4, true)
	p := mallocgc(mem, nil, false)
	if mem != uintptr(size)*4 {
		memclrNoHeapPointers(add(p, uintptr(size)*4), mem-uintptr(size)*4)
	}

	*(*slice)(unsafe.Pointer(&b)) = slice{p, size, int(mem / 4)}
	return
}

// used by cmd/cgo
func gobytes(p *byte, n int) (b []byte) {
	if n == 0 {
		return make([]byte, 0)
	}

	if n < 0 || uintptr(n) > maxAlloc {
		panic(errorString("gobytes: length out of range"))
	}

	bp := mallocgc(uintptr(n), nil, false)
	memmove(bp, unsafe.Pointer(p), uintptr(n))

	*(*slice)(unsafe.Pointer(&b)) = slice{bp, n, n}
	return
}

// This is exported via linkname to assembly in syscall (for Plan9) and cgo.
//
//go:linkname gostring
func gostring(p *byte) string {
	l := findnull(p)
	if l == 0 {
		return ""
	}
	s, b := rawstring(l)
	memmove(unsafe.Pointer(&b[0]), unsafe.Pointer(p), uintptr(l))
	return s
}

// internal_syscall_gostring is a version of gostring for internal/syscall/unix.
//
//go:linkname internal_syscall_gostring internal/syscall/unix.gostring
func internal_syscall_gostring(p *byte) string {
	return gostring(p)
}

func gostringn(p *byte, l int) string {
	if l == 0 {
		return ""
	}
	s, b := rawstring(l)
	memmove(unsafe.Pointer(&b[0]), unsafe.Pointer(p), uintptr(l))
	return s
}

const (
	maxUint64 = ^uint64(0)
	maxInt64  = int64(maxUint64 >> 1)
)

// atoi64 parses an int64 from a string s.
// The bool result reports whether s is a number
// representable by a value of type int64.
func atoi64(s string) (int64, bool) {
	if s == "" {
		return 0, false
	}

	neg := false
	if s[0] == '-' {
		neg = true
		s = s[1:]
	}

	un := uint64(0)
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c < '0' || c > '9' {
			return 0, false
		}
		if un > maxUint64/10 {
			// overflow
			return 0, false
		}
		un *= 10
		un1 := un + uint64(c) - '0'
		if un1 < un {
			// overflow
			return 0, false
		}
		un = un1
	}

	if !neg && un > uint64(maxInt64) {
		return 0, false
	}
	if neg && un > uint64(maxInt64)+1 {
		return 0, false
	}

	n := int64(un)
	if neg {
		n = -n
	}

	return n, true
}

// atoi is like atoi64 but for integers
// that fit into an int.
func atoi(s string) (int, bool) {
	if n, ok := atoi64(s); n == int64(int(n)) {
		return int(n), ok
	}
	return 0, false
}

// atoi32 is like atoi but for integers
// that fit into an int32.
func atoi32(s string) (int32, bool) {
	if n, ok := atoi64(s); n == int64(int32(n)) {
		return int32(n), ok
	}
	return 0, false
}

// parseByteCount parses a string that represents a count of bytes.
//
// s must match the following regular expression:
//
//	^[0-9]+(([KMGT]i)?B)?$
//
// In other words, an integer byte count with an optional unit
// suffix. Acceptable suffixes include one of
// - KiB, MiB, GiB, TiB which represent binary IEC/ISO 80000 units, or
// - B, which just represents bytes.
//
// Returns an int64 because that's what its callers want and receive,
// but the result is always non-negative.
func parseByteCount(s string) (int64, bool) {
	// The empty string is not valid.
	if s == "" {
		return 0, false
	}
	// Handle the easy non-suffix case.
	last := s[len(s)-1]
	if last >= '0' && last <= '9' {
		n, ok := atoi64(s)
		if !ok || n < 0 {
			return 0, false
		}
		return n, ok
	}
	// Failing a trailing digit, this must always end in 'B'.
	// Also at this point there must be at least one digit before
	// that B.
	if last != 'B' || len(s) < 2 {
		return 0, false
	}
	// The one before that must always be a digit or 'i'.
	if c := s[len(s)-2]; c >= '0' && c <= '9' {
		// Trivial 'B' suffix.
		n, ok := atoi64(s[:len(s)-1])
		if !ok || n < 0 {
			return 0, false
		}
		return n, ok
	} else if c != 'i' {
		return 0, false
	}
	// Finally, we need at least 4 characters now, for the unit
	// prefix and at least one digit.
	if len(s) < 4 {
		return 0, false
	}
	power := 0
	switch s[len(s)-3] {
	case 'K':
		power = 1
	case 'M':
		power = 2
	case 'G':
		power = 3
	case 'T':
		power = 4
	default:
		// Invalid suffix.
		return 0, false
	}
	m := uint64(1)
	for i := 0; i < power; i++ {
		m *= 1024
	}
	n, ok := atoi64(s[:len(s)-3])
	if !ok || n < 0 {
		return 0, false
	}
	un := uint64(n)
	if un > maxUint64/m {
		// Overflow.
		return 0, false
	}
	un *= m
	if un > uint64(maxInt64) {
		// Overflow.
		return 0, false
	}
	return int64(un), true
}

//go:nosplit
func findnull(s *byte) int {
	if s == nil {
		return 0
	}

	// Avoid IndexByteString on Plan 9 because it uses SSE instructions
	// on x86 machines, and those are classified as floating point instructions,
	// which are illegal in a note handler.
	if GOOS == "plan9" {
		p := (*[maxAlloc/2 - 1]byte)(unsafe.Pointer(s))
		l := 0
		for p[l] != 0 {
			l++
		}
		return l
	}

	// pageSize is the unit we scan at a time looking for NULL.
	// It must be the minimum page size for any architecture Go
	// runs on. It's okay (just a minor performance loss) if the
	// actual system page size is larger than this value.
	const pageSize = 4096

	offset := 0
	ptr := unsafe.Pointer(s)
	// IndexByteString uses wide reads, so we need to be careful
	// with page boundaries. Call IndexByteString on
	// [ptr, endOfPage) interval.
	safeLen := int(pageSize - uintptr(ptr)%pageSize)

	for {
		t := *(*string)(unsafe.Pointer(&stringStruct{ptr, safeLen}))
		// Check one page at a time.
		if i := bytealg.IndexByteString(t, 0); i != -1 {
			return offset + i
		}
		// Move to next page
		ptr = unsafe.Pointer(uintptr(ptr) + uintptr(safeLen))
		offset += safeLen
		safeLen = pageSize
	}
}

func findnullw(s *uint16) int {
	if s == nil {
		return 0
	}
	p := (*[maxAlloc/2/2 - 1]uint16)(unsafe.Pointer(s))
	l := 0
	for p[l] != 0 {
		l++
	}
	return l
}

//go:nosplit
func gostringnocopy(str *byte) string {
	ss := stringStruct{str: unsafe.Pointer(str), len: findnull(str)}
	s := *(*string)(unsafe.Pointer(&ss))
	return s
}

func gostringw(strw *uint16) string {
	var buf [8]byte
	str := (*[maxAlloc/2/2 - 1]uint16)(unsafe.Pointer(strw))
	n1 := 0
	for i := 0; str[i] != 0; i++ {
		n1 += encoderune(buf[:], rune(str[i]))
	}
	s, b := rawstring(n1 + 4)
	n2 := 0
	for i := 0; str[i] != 0; i++ {
		// check for race
		if n2 >= n1 {
			break
		}
		n2 += encoderune(b[n2:], rune(str[i]))
	}
	b[n2] = 0 // for luck
	return s[:n2]
}
```