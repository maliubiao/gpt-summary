Response:
Let's break down the thought process for analyzing this Go code.

1. **Understand the Goal:** The initial prompt clearly states the code is for testing cgo's ability to detect invalid pointer passing at runtime. This immediately tells us the core functionality revolves around interactions between Go and C code, specifically when pointers are involved.

2. **Identify Key Components:**  Scan the code for major structures and functions. I see:
    * `package errorstest`: This tells us it's a testing package.
    * `import` statements: These reveal dependencies like `bytes`, `flag`, `fmt`, `os`, `exec`, `testing`, etc., hinting at testing infrastructure and interaction with the operating system. The presence of `internal/testenv` is a strong indicator of internal Go testing.
    * `var tmp = flag.String(...)`: This indicates a command-line flag for specifying a temporary directory.
    * `type ptrTest struct`: This is the core data structure for defining individual test cases. Its fields (`name`, `c`, `body`, `fail`, `expensive`, etc.) are crucial for understanding what each test aims to verify.
    * `var ptrTests = []ptrTest{ ... }`:  This is the collection of all the defined test cases. This is where the specific scenarios being tested are detailed.
    * `func TestPointerChecks(t *testing.T)`: This is the main testing function that orchestrates the execution of the individual tests.
    * `func buildPtrTests(t *testing.T, gopath string, cgocheck2 bool)`: This function builds the test executables. The `cgocheck2` parameter is a strong clue about different levels of checking.
    * `func testOne(t *testing.T, pt ptrTest, exe, exe2 string)`: This function executes a single test case. The presence of two executables (`exe` and `exe2`) built with different `cgocheck` levels is significant.

3. **Analyze `ptrTest`:**  This struct is central. Its fields tell a story:
    * `name`:  Self-explanatory.
    * `c`:  The C code snippet to include via `/* ... */`. This is where the C functions being called are defined.
    * `c1`:  Another C code snippet, likely for cases with separate cgo files (like those using `//export`).
    * `imports`: Go imports needed for the test.
    * `support`:  Go code to define helper types and functions.
    * `body`:  The main Go code that calls the C functions and triggers the pointer passing.
    * `extra`:  Allows for additional files needed for complex tests.
    * `fail`:  Whether the test is expected to trigger a cgo pointer error.
    * `expensive`:  Indicates tests that might be slower and are run with more thorough checks.

4. **Examine the Test Cases:**  Skim through the `ptrTests` array. Notice patterns:
    * Tests named "ptr..." or containing "ptr" in the description likely involve direct pointer passing violations.
    * Tests named "ok..." suggest scenarios where pointer passing is expected to be valid.
    * Tests involving "slice", "var", "barrier", "export", "string", "defer", "union", etc., highlight specific cgo features or edge cases related to pointer management.
    * The `fail: true` and `fail: false` fields are essential for understanding the expected outcome of each test.
    * The `expensive: true` field suggests a tiered testing approach with different levels of scrutiny.

5. **Understand the Test Execution Flow:**  Trace how `TestPointerChecks` works:
    * It builds two executables: one with standard cgo checks and one potentially with more expensive checks (indicated by `cgocheck2`).
    * It iterates through the `ptrTests`.
    * For each test, it runs `testOne` in parallel.
    * `testOne` executes the generated executables with different `GODEBUG=cgocheck` values (0, 1, and potentially 2) to verify the expected behavior (failure or success). The `expensive` flag influences which `cgocheck` levels are used.

6. **Focus on `buildPtrTests`:**  This function is responsible for generating the Go code that interacts with the C code. Notice:
    * It creates a temporary directory and `go.mod`.
    * It combines the C code snippets from the `ptrTests` into `cgo1.go` and `cgo2.go`.
    * It gathers the necessary Go imports.
    * It generates the `main` function that dispatches to the individual test functions.
    * It uses `go build` to compile the executables, potentially setting the `GOEXPERIMENT` environment variable for `cgocheck2`.

7. **Infer Functionality and Provide Examples:**  Based on the test cases and the code structure, start listing the functionalities being tested. For each functionality, select a relevant test case and create a simplified Go example demonstrating the concept. For example, the "ptr1" test case clearly demonstrates the invalidity of passing a pointer to a struct containing a Go pointer.

8. **Address Command-Line Arguments:** The code uses `flag.String("-tmp", ...)`. Explain how this flag can be used to control the temporary directory and its implications (cleanup or no cleanup).

9. **Identify Common Mistakes:**  Think about the scenarios that cause the tests to fail. This leads to understanding common pitfalls for users of cgo, such as:
    * Passing pointers to Go memory to C functions.
    * Returning Go pointers from exported C functions.
    * Storing Go pointers in C memory.

10. **Review and Refine:**  Go back through the analysis, ensuring the explanations are clear, concise, and accurate. Double-check the provided Go examples and the description of command-line arguments. Make sure the explanation of common mistakes is well-illustrated. For example, make sure to explicitly state *why* passing a pointer to a struct containing a Go pointer is problematic (because the Go garbage collector might move the pointed-to memory).

This systematic approach, starting with the overall goal and drilling down into the details of the code, helps to thoroughly understand the functionality and provide a comprehensive answer to the prompt.
这段代码是 Go 语言 `cmd/cgo` 工具内部 `testerrors` 包的一部分，专门用于测试 `cgo` 在运行时检测无效指针传递的功能。

**主要功能:**

1. **测试 `cgo` 对不同场景下非法 Go 指针传递到 C 代码的检测能力:**  代码定义了一系列测试用例 (`ptrTests`)，每个用例模拟了一种将 Go 指针（或包含 Go 指针的数据结构的指针）传递给 C 函数的场景。
2. **区分预期成功和失败的场景:** 每个测试用例都通过 `fail` 字段标记了该场景是否应该被 `cgo` 检测为错误。
3. **支持 "expensive" 检测:**  一些测试用例标记为 `expensive`，这意味着它们依赖于更严格、可能更耗时的指针检查。这通常对应于 `GODEBUG=cgocheck=2` 的设置。
4. **自动化测试执行:** `TestPointerChecks` 函数负责构建测试程序，并针对每个测试用例，使用不同的 `GODEBUG` 设置来运行测试，验证 `cgo` 是否按照预期检测到错误。
5. **使用命令行参数控制临时目录:** 可以通过 `-tmp` 命令行参数指定临时文件目录，并控制是否清理这些文件。

**它是什么 Go 语言功能的实现 (运行时指针检查):**

这段代码的核心是测试 `cgo` 的**运行时指针检查**机制。当 Go 代码调用 C 代码时，`cgo` 会在运行时进行检查，以防止将指向 Go 管理的内存的指针传递给 C 代码。这是为了防止 C 代码错误地访问或修改 Go 的内存，导致程序崩溃或数据损坏。

**Go 代码举例说明:**

假设我们有一个 C 函数 `void process_int(int *p)`，我们想从 Go 代码中传递一个指向 Go `int` 变量的指针给它。

```go
package main

/*
#include <stdio.h>
void process_int(int *p) {
    if (p != NULL) {
        printf("Value in C: %d\n", *p);
    } else {
        printf("Pointer is NULL in C\n");
    }
}
*/
import "C"
import "fmt"

func main() {
	goInt := 10
	// 尝试将 Go 变量的地址直接传递给 C 函数 (这通常是错误的)
	// C.process_int(&goInt) // 这行代码在开启 cgo 检查时会报错

	// 正确的做法是将数据复制到 C 分配的内存中
	cIntPtr := C.malloc(C.sizeof_int)
	if cIntPtr == nil {
		fmt.Println("Failed to allocate memory in C")
		return
	}
	defer C.free(cIntPtr) // 确保释放 C 分配的内存

	*(*C.int)(cIntPtr) = C.int(goInt)
	C.process_int((*C.int)(cIntPtr)) // 传递指向 C 分配内存的指针
}
```

**假设的输入与输出:**

如果 `cgo` 的运行时指针检查被启用（默认情况），并且我们尝试直接传递 `&goInt` 给 `C.process_int`，那么程序在运行时会因为 `cgo` 检测到无效指针传递而崩溃，并打印类似以下的错误信息：

```
panic: cgo argument has Go pointer to Go pointer
```

如果使用正确的做法，将 `goInt` 的值复制到 C 分配的内存中，那么程序将正常运行，并在控制台输出：

```
Value in C: 10
```

**命令行参数的具体处理:**

代码中使用了 `flag` 包来处理命令行参数。具体来说，它定义了一个名为 `tmp` 的字符串类型的 flag：

```go
var tmp = flag.String("tmp", "", "use `dir` for temporary files and do not clean up")
```

* **`-tmp`:**  这是命令行参数的名称。
* **`""`:** 这是 `tmp` 的默认值，如果命令行中没有提供 `-tmp` 参数，则使用空字符串。
* **`"use \`dir\` for temporary files and do not clean up"`:** 这是该参数的描述信息。

**使用方式:**

在运行测试时，可以使用 `-tmp` 参数来指定临时文件存放的目录。例如：

```bash
go test -cgotest.run=TestPointerChecks -- -tmp=/path/to/my/tempdir
```

如果指定了 `-tmp` 参数，测试框架会将该目录设置为临时目录 (`gopath`)，并且在测试结束后**不会**清理该目录。如果没有指定 `-tmp` 参数，测试框架会创建一个临时的目录，并在测试结束后将其清理。

**使用者易犯错的点:**

使用者在使用 `cgo` 时，最容易犯的错误就是**将 Go 管理的内存的指针直接传递给 C 代码**，或者**在 C 代码中存储指向 Go 管理内存的指针**。`cgo` 的运行时指针检查旨在捕获这些错误。

**示例 (使用者易犯错的情况):**

```go
package main

/*
#include <stdlib.h>
#include <stdio.h>

char** allocate_c_string_array() {
  return (char**)malloc(sizeof(char*) * 10);
}

void store_string(char** arr, int index, char* str) {
  arr[index] = str;
}

void print_string(char* str) {
  if (str != NULL) {
    printf("String in C: %s\n", str);
  } else {
    printf("String is NULL in C\n");
  }
}
*/
import "C"
import "fmt"

func main() {
	goStrings := []string{"hello", "world"}
	cStringArray := C.allocate_c_string_array()
	defer C.free(unsafe.Pointer(cStringArray)) // 注意释放 C 分配的内存

	// 错误的做法：直接将 Go 字符串的指针传递给 C 并存储
	// for i, s := range goStrings {
	// 	cStr := C.CString(s)
	// 	C.store_string(cStringArray, C.int(i), cStr) // 即使使用 C.CString，如果存储在 C 分配的结构中仍然可能触发问题
	// 	defer C.free(unsafe.Pointer(cStr))        // 需要手动释放 C.CString 分配的内存
	// }

	// 正确的做法：将 Go 字符串复制到 C 分配的内存中
	for i, s := range goStrings {
		cStr := C.CString(s)
		defer C.free(unsafe.Pointer(cStr)) // 及时释放

		// 分配 C 字符串的内存并复制
		dest := C.CString(s)
		C.store_string(cStringArray, C.int(i), dest)
		// 这里不需要 defer C.free(unsafe.Pointer(dest)), 因为 cStringArray 持有的是 dest 的指针，后续需要统一释放
	}

	// 打印 C 数组中的字符串
	cStr0 := C.GoString(C. дереference_char_pointer(cStringArray, C.int(0)))
	fmt.Println("String from C array:", cStr0)

	cStr1 := C.GoString(C. дереference_char_pointer(cStringArray, C.int(1)))
	fmt.Println("String from C array:", cStr1)
}

// Helper function to dereference char**
//export дереference_char_pointer
func дереference_char_pointer(p **C.char, i C.int) *C.char {
	return *(**C.char)(unsafe.Pointer(uintptr(unsafe.Pointer(p)) + uintptr(i)*unsafe.Sizeof(*p)))
}

```

在上面的错误示例中，虽然使用了 `C.CString` 将 Go 字符串转换为 C 字符串，但如果直接将 `cStr` 存储到 C 分配的数组中，仍然可能因为 Go 的垃圾回收机制导致问题。更好的做法是将 Go 数据复制到 C 分配的内存中，并确保在 Go 代码中正确管理 C 分配的内存的生命周期。

这段 `ptr_test.go` 的作用就是通过各种测试用例，确保 `cgo` 的运行时指针检查能够有效地检测到这些潜在的错误，从而提高使用 `cgo` 编写的程序的稳定性和安全性。

Prompt: 
```
这是路径为go/src/cmd/cgo/internal/testerrors/ptr_test.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，

"""
// Copyright 2015 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Tests that cgo detects invalid pointer passing at runtime.

package errorstest

import (
	"bytes"
	"flag"
	"fmt"
	"internal/testenv"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
)

var tmp = flag.String("tmp", "", "use `dir` for temporary files and do not clean up")

// ptrTest is the tests without the boilerplate.
type ptrTest struct {
	name      string   // for reporting
	c         string   // the cgo comment
	c1        string   // cgo comment forced into non-export cgo file
	imports   []string // a list of imports
	support   string   // supporting functions
	body      string   // the body of the main function
	extra     []extra  // extra files
	fail      bool     // whether the test should fail
	expensive bool     // whether the test requires the expensive check
}

type extra struct {
	name     string
	contents string
}

var ptrTests = []ptrTest{
	{
		// Passing a pointer to a struct that contains a Go pointer.
		name: "ptr1",
		c:    `typedef struct s1 { int *p; } s1; void f1(s1 *ps) {}`,
		body: `C.f1(&C.s1{new(C.int)})`,
		fail: true,
	},
	{
		// Passing a pointer to a struct that contains a Go pointer.
		name: "ptr2",
		c:    `typedef struct s2 { int *p; } s2; void f2(s2 *ps) {}`,
		body: `p := &C.s2{new(C.int)}; C.f2(p)`,
		fail: true,
	},
	{
		// Passing a pointer to an int field of a Go struct
		// that (irrelevantly) contains a Go pointer.
		name: "ok1",
		c:    `struct s3 { int i; int *p; }; void f3(int *p) {}`,
		body: `p := &C.struct_s3{i: 0, p: new(C.int)}; C.f3(&p.i)`,
		fail: false,
	},
	{
		// Passing a pointer to a pointer field of a Go struct.
		name: "ptrfield",
		c:    `struct s4 { int i; int *p; }; void f4(int **p) {}`,
		body: `p := &C.struct_s4{i: 0, p: new(C.int)}; C.f4(&p.p)`,
		fail: true,
	},
	{
		// Passing a pointer to a pointer field of a Go
		// struct, where the field does not contain a Go
		// pointer, but another field (irrelevantly) does.
		name: "ptrfieldok",
		c:    `struct s5 { int *p1; int *p2; }; void f5(int **p) {}`,
		body: `p := &C.struct_s5{p1: nil, p2: new(C.int)}; C.f5(&p.p1)`,
		fail: false,
	},
	{
		// Passing the address of a slice with no Go pointers.
		name:    "sliceok1",
		c:       `void f6(void **p) {}`,
		imports: []string{"unsafe"},
		body:    `s := []unsafe.Pointer{nil}; C.f6(&s[0])`,
		fail:    false,
	},
	{
		// Passing the address of a slice with a Go pointer.
		name:    "sliceptr1",
		c:       `void f7(void **p) {}`,
		imports: []string{"unsafe"},
		body:    `i := 0; s := []unsafe.Pointer{unsafe.Pointer(&i)}; C.f7(&s[0])`,
		fail:    true,
	},
	{
		// Passing the address of a slice with a Go pointer,
		// where we are passing the address of an element that
		// is not a Go pointer.
		name:    "sliceptr2",
		c:       `void f8(void **p) {}`,
		imports: []string{"unsafe"},
		body:    `i := 0; s := []unsafe.Pointer{nil, unsafe.Pointer(&i)}; C.f8(&s[0])`,
		fail:    true,
	},
	{
		// Passing the address of a slice that is an element
		// in a struct only looks at the slice.
		name:    "sliceok2",
		c:       `void f9(void **p) {}`,
		imports: []string{"unsafe"},
		support: `type S9 struct { p *int; s []unsafe.Pointer }`,
		body:    `i := 0; p := &S9{p:&i, s:[]unsafe.Pointer{nil}}; C.f9(&p.s[0])`,
		fail:    false,
	},
	{
		// Passing the address of a slice of an array that is
		// an element in a struct, with a type conversion.
		name:    "sliceok3",
		c:       `void f10(void* p) {}`,
		imports: []string{"unsafe"},
		support: `type S10 struct { p *int; a [4]byte }`,
		body:    `i := 0; p := &S10{p:&i}; s := p.a[:]; C.f10(unsafe.Pointer(&s[0]))`,
		fail:    false,
	},
	{
		// Passing the address of a slice of an array that is
		// an element in a struct, with a type conversion.
		name:    "sliceok4",
		c:       `typedef void* PV11; void f11(PV11 p) {}`,
		imports: []string{"unsafe"},
		support: `type S11 struct { p *int; a [4]byte }`,
		body:    `i := 0; p := &S11{p:&i}; C.f11(C.PV11(unsafe.Pointer(&p.a[0])))`,
		fail:    false,
	},
	{
		// Passing the address of a static variable with no
		// pointers doesn't matter.
		name:    "varok",
		c:       `void f12(char** parg) {}`,
		support: `var hello12 = [...]C.char{'h', 'e', 'l', 'l', 'o'}`,
		body:    `parg := [1]*C.char{&hello12[0]}; C.f12(&parg[0])`,
		fail:    false,
	},
	{
		// Passing the address of a static variable with
		// pointers does matter.
		name:    "var1",
		c:       `void f13(char*** parg) {}`,
		support: `var hello13 = [...]*C.char{new(C.char)}`,
		body:    `parg := [1]**C.char{&hello13[0]}; C.f13(&parg[0])`,
		fail:    true,
	},
	{
		// Storing a Go pointer into C memory should fail.
		name: "barrier",
		c: `#include <stdlib.h>
		    char **f14a() { return malloc(sizeof(char*)); }
		    void f14b(char **p) {}`,
		body:      `p := C.f14a(); *p = new(C.char); C.f14b(p)`,
		fail:      true,
		expensive: true,
	},
	{
		// Storing a pinned Go pointer into C memory should succeed.
		name: "barrierpinnedok",
		c: `#include <stdlib.h>
		    char **f14a2() { return malloc(sizeof(char*)); }
		    void f14b2(char **p) {}`,
		imports:   []string{"runtime"},
		body:      `var pinr runtime.Pinner; p := C.f14a2(); x := new(C.char); pinr.Pin(x); *p = x; C.f14b2(p); pinr.Unpin()`,
		fail:      false,
		expensive: true,
	},
	{
		// Storing a Go pointer into C memory by assigning a
		// large value should fail.
		name: "barrierstruct",
		c: `#include <stdlib.h>
		    struct s15 { char *a[10]; };
		    struct s15 *f15() { return malloc(sizeof(struct s15)); }
		    void f15b(struct s15 *p) {}`,
		body:      `p := C.f15(); p.a = [10]*C.char{new(C.char)}; C.f15b(p)`,
		fail:      true,
		expensive: true,
	},
	{
		// Storing a Go pointer into C memory using a slice
		// copy should fail.
		name: "barrierslice",
		c: `#include <stdlib.h>
		    struct s16 { char *a[10]; };
		    struct s16 *f16() { return malloc(sizeof(struct s16)); }
		    void f16b(struct s16 *p) {}`,
		body:      `p := C.f16(); copy(p.a[:], []*C.char{new(C.char)}); C.f16b(p)`,
		fail:      true,
		expensive: true,
	},
	{
		// A very large value uses a GC program, which is a
		// different code path.
		name: "barriergcprogarray",
		c: `#include <stdlib.h>
		    struct s17 { char *a[32769]; };
		    struct s17 *f17() { return malloc(sizeof(struct s17)); }
		    void f17b(struct s17 *p) {}`,
		body:      `p := C.f17(); p.a = [32769]*C.char{new(C.char)}; C.f17b(p)`,
		fail:      true,
		expensive: true,
	},
	{
		// Similar case, with a source on the heap.
		name: "barriergcprogarrayheap",
		c: `#include <stdlib.h>
		    struct s18 { char *a[32769]; };
		    struct s18 *f18() { return malloc(sizeof(struct s18)); }
		    void f18b(struct s18 *p) {}
		    void f18c(void *p) {}`,
		imports:   []string{"unsafe"},
		body:      `p := C.f18(); n := &[32769]*C.char{new(C.char)}; p.a = *n; C.f18b(p); n[0] = nil; C.f18c(unsafe.Pointer(n))`,
		fail:      true,
		expensive: true,
	},
	{
		// A GC program with a struct.
		name: "barriergcprogstruct",
		c: `#include <stdlib.h>
		    struct s19a { char *a[32769]; };
		    struct s19b { struct s19a f; };
		    struct s19b *f19() { return malloc(sizeof(struct s19b)); }
		    void f19b(struct s19b *p) {}`,
		body:      `p := C.f19(); p.f = C.struct_s19a{[32769]*C.char{new(C.char)}}; C.f19b(p)`,
		fail:      true,
		expensive: true,
	},
	{
		// Similar case, with a source on the heap.
		name: "barriergcprogstructheap",
		c: `#include <stdlib.h>
		    struct s20a { char *a[32769]; };
		    struct s20b { struct s20a f; };
		    struct s20b *f20() { return malloc(sizeof(struct s20b)); }
		    void f20b(struct s20b *p) {}
		    void f20c(void *p) {}`,
		imports:   []string{"unsafe"},
		body:      `p := C.f20(); n := &C.struct_s20a{[32769]*C.char{new(C.char)}}; p.f = *n; C.f20b(p); n.a[0] = nil; C.f20c(unsafe.Pointer(n))`,
		fail:      true,
		expensive: true,
	},
	{
		// Exported functions may not return Go pointers.
		name: "export1",
		c: `#ifdef _WIN32
		    __declspec(dllexport)
			#endif
		    extern unsigned char *GoFn21();`,
		support: `//export GoFn21
		          func GoFn21() *byte { return new(byte) }`,
		body: `C.GoFn21()`,
		fail: true,
	},
	{
		// Returning a C pointer is fine.
		name: "exportok",
		c: `#include <stdlib.h>
		    #ifdef _WIN32
		    __declspec(dllexport)
			#endif
		    extern unsigned char *GoFn22();`,
		support: `//export GoFn22
		          func GoFn22() *byte { return (*byte)(C.malloc(1)) }`,
		body: `C.GoFn22()`,
	},
	{
		// Passing a Go string is fine.
		name: "passstring",
		c: `#include <stddef.h>
		    typedef struct { const char *p; ptrdiff_t n; } gostring23;
		    gostring23 f23(gostring23 s) { return s; }`,
		imports: []string{"unsafe"},
		body:    `s := "a"; r := C.f23(*(*C.gostring23)(unsafe.Pointer(&s))); if *(*string)(unsafe.Pointer(&r)) != s { panic(r) }`,
	},
	{
		// Passing a slice of Go strings fails.
		name:    "passstringslice",
		c:       `void f24(void *p) {}`,
		imports: []string{"strings", "unsafe"},
		support: `type S24 struct { a [1]string }`,
		body:    `s := S24{a:[1]string{strings.Repeat("a", 2)}}; C.f24(unsafe.Pointer(&s.a[0]))`,
		fail:    true,
	},
	{
		// Exported functions may not return strings.
		name:    "retstring",
		c:       `extern void f25();`,
		imports: []string{"strings"},
		support: `//export GoStr25
		          func GoStr25() string { return strings.Repeat("a", 2) }`,
		body: `C.f25()`,
		c1: `#include <stddef.h>
		     typedef struct { const char *p; ptrdiff_t n; } gostring25;
		     extern gostring25 GoStr25();
		     void f25() { GoStr25(); }`,
		fail: true,
	},
	{
		// Don't check non-pointer data.
		// Uses unsafe code to get a pointer we shouldn't check.
		// Although we use unsafe, the uintptr represents an integer
		// that happens to have the same representation as a pointer;
		// that is, we are testing something that is not unsafe.
		name: "ptrdata1",
		c: `#include <stdlib.h>
		    void f26(void* p) {}`,
		imports: []string{"unsafe"},
		support: `type S26 struct { p *int; a [8*8]byte; u uintptr }`,
		body:    `i := 0; p := &S26{u:uintptr(unsafe.Pointer(&i))}; q := (*S26)(C.malloc(C.size_t(unsafe.Sizeof(*p)))); *q = *p; C.f26(unsafe.Pointer(q))`,
		fail:    false,
	},
	{
		// Like ptrdata1, but with a type that uses a GC program.
		name: "ptrdata2",
		c: `#include <stdlib.h>
		    void f27(void* p) {}`,
		imports: []string{"unsafe"},
		support: `type S27 struct { p *int; a [32769*8]byte; q *int; u uintptr }`,
		body:    `i := 0; p := S27{u:uintptr(unsafe.Pointer(&i))}; q := (*S27)(C.malloc(C.size_t(unsafe.Sizeof(p)))); *q = p; C.f27(unsafe.Pointer(q))`,
		fail:    false,
	},
	{
		// Check deferred pointers when they are used, not
		// when the defer statement is run.
		name: "defer1",
		c:    `typedef struct s28 { int *p; } s28; void f28(s28 *ps) {}`,
		body: `p := &C.s28{}; defer C.f28(p); p.p = new(C.int)`,
		fail: true,
	},
	{
		// Check a pointer to a union if the union has any
		// pointer fields.
		name:    "union1",
		c:       `typedef union { char **p; unsigned long i; } u29; void f29(u29 *pu) {}`,
		imports: []string{"unsafe"},
		body:    `var b C.char; p := &b; C.f29((*C.u29)(unsafe.Pointer(&p)))`,
		fail:    true,
	},
	{
		// Don't check a pointer to a union if the union does
		// not have any pointer fields.
		// Like ptrdata1 above, the uintptr represents an
		// integer that happens to have the same
		// representation as a pointer.
		name:    "union2",
		c:       `typedef union { unsigned long i; } u39; void f39(u39 *pu) {}`,
		imports: []string{"unsafe"},
		body:    `var b C.char; p := &b; C.f39((*C.u39)(unsafe.Pointer(&p)))`,
		fail:    false,
	},
	{
		// Test preemption while entering a cgo call. Issue #21306.
		name:    "preemptduringcall",
		c:       `void f30() {}`,
		imports: []string{"runtime", "sync"},
		body:    `var wg sync.WaitGroup; wg.Add(100); for i := 0; i < 100; i++ { go func(i int) { for j := 0; j < 100; j++ { C.f30(); runtime.GOMAXPROCS(i) }; wg.Done() }(i) }; wg.Wait()`,
		fail:    false,
	},
	{
		// Test poller deadline with cgocheck=2.  Issue #23435.
		name:    "deadline",
		c:       `#define US31 10`,
		imports: []string{"os", "time"},
		body:    `r, _, _ := os.Pipe(); r.SetDeadline(time.Now().Add(C.US31 * time.Microsecond))`,
		fail:    false,
	},
	{
		// Test for double evaluation of channel receive.
		name:    "chanrecv",
		c:       `void f32(char** p) {}`,
		imports: []string{"time"},
		body:    `c := make(chan []*C.char, 2); c <- make([]*C.char, 1); go func() { time.Sleep(10 * time.Second); panic("received twice from chan") }(); C.f32(&(<-c)[0]);`,
		fail:    false,
	},
	{
		// Test that converting the address of a struct field
		// to unsafe.Pointer still just checks that field.
		// Issue #25941.
		name:    "structfield",
		c:       `void f33(void* p) {}`,
		imports: []string{"unsafe"},
		support: `type S33 struct { p *int; a [8]byte; u uintptr }`,
		body:    `s := &S33{p: new(int)}; C.f33(unsafe.Pointer(&s.a))`,
		fail:    false,
	},
	{
		// Test that converting multiple struct field
		// addresses to unsafe.Pointer still just checks those
		// fields. Issue #25941.
		name:    "structfield2",
		c:       `void f34(void* p, int r, void* s) {}`,
		imports: []string{"unsafe"},
		support: `type S34 struct { a [8]byte; p *int; b int64; }`,
		body:    `s := &S34{p: new(int)}; C.f34(unsafe.Pointer(&s.a), 32, unsafe.Pointer(&s.b))`,
		fail:    false,
	},
	{
		// Test that second argument to cgoCheckPointer is
		// evaluated when a deferred function is deferred, not
		// when it is run.
		name:    "defer2",
		c:       `void f35(char **pc) {}`,
		support: `type S35a struct { s []*C.char }; type S35b struct { ps *S35a }`,
		body:    `p := &S35b{&S35a{[]*C.char{nil}}}; defer C.f35(&p.ps.s[0]); p.ps = nil`,
		fail:    false,
	},
	{
		// Test that indexing into a function call still
		// examines only the slice being indexed.
		name:    "buffer",
		c:       `void f36(void *p) {}`,
		imports: []string{"bytes", "unsafe"},
		body:    `var b bytes.Buffer; b.WriteString("a"); C.f36(unsafe.Pointer(&b.Bytes()[0]))`,
		fail:    false,
	},
	{
		// Test that bgsweep releasing a finalizer is OK.
		name:    "finalizer",
		c:       `// Nothing to declare.`,
		imports: []string{"os"},
		support: `func open37() { os.Open(os.Args[0]) }; var G37 [][]byte`,
		body:    `for i := 0; i < 10000; i++ { G37 = append(G37, make([]byte, 4096)); if i % 100 == 0 { G37 = nil; open37() } }`,
		fail:    false,
	},
	{
		// Test that converting generated struct to interface is OK.
		name:    "structof",
		c:       `// Nothing to declare.`,
		imports: []string{"reflect"},
		support: `type MyInt38 int; func (i MyInt38) Get() int { return int(i) }; type Getter38 interface { Get() int }`,
		body:    `t := reflect.StructOf([]reflect.StructField{{Name: "MyInt38", Type: reflect.TypeOf(MyInt38(0)), Anonymous: true}}); v := reflect.New(t).Elem(); v.Interface().(Getter38).Get()`,
		fail:    false,
	},
	{
		// Test that a converted address of a struct field results
		// in a check for just that field and not the whole struct.
		name:    "structfieldcast",
		c:       `struct S40i { int i; int* p; }; void f40(struct S40i* p) {}`,
		support: `type S40 struct { p *int; a C.struct_S40i }`,
		body:    `s := &S40{p: new(int)}; C.f40((*C.struct_S40i)(&s.a))`,
		fail:    false,
	},
	{
		// Test that we handle unsafe.StringData.
		name:    "stringdata",
		c:       `void f41(void* p) {}`,
		imports: []string{"unsafe"},
		body:    `s := struct { a [4]byte; p *int }{p: new(int)}; str := unsafe.String(&s.a[0], 4); C.f41(unsafe.Pointer(unsafe.StringData(str)))`,
		fail:    false,
	},
	{
		name:    "slicedata",
		c:       `void f42(void* p) {}`,
		imports: []string{"unsafe"},
		body:    `s := []*byte{nil, new(byte)}; C.f42(unsafe.Pointer(unsafe.SliceData(s)))`,
		fail:    true,
	},
	{
		name:    "slicedata2",
		c:       `void f43(void* p) {}`,
		imports: []string{"unsafe"},
		body:    `s := struct { a [4]byte; p *int }{p: new(int)}; C.f43(unsafe.Pointer(unsafe.SliceData(s.a[:])))`,
		fail:    false,
	},
	{
		// Passing the address of an element of a pointer-to-array.
		name:    "arraypointer",
		c:       `void f44(void* p) {}`,
		imports: []string{"unsafe"},
		body:    `a := new([10]byte); C.f44(unsafe.Pointer(&a[0]))`,
		fail:    false,
	},
	{
		// Passing the address of an element of a pointer-to-array
		// that contains a Go pointer.
		name:    "arraypointer2",
		c:       `void f45(void** p) {}`,
		imports: []string{"unsafe"},
		body:    `i := 0; a := &[2]unsafe.Pointer{nil, unsafe.Pointer(&i)}; C.f45(&a[0])`,
		fail:    true,
	},
}

func TestPointerChecks(t *testing.T) {
	testenv.MustHaveGoBuild(t)
	testenv.MustHaveCGO(t)

	var gopath string
	var dir string
	if *tmp != "" {
		gopath = *tmp
		dir = ""
	} else {
		d, err := os.MkdirTemp("", filepath.Base(t.Name()))
		if err != nil {
			t.Fatal(err)
		}
		dir = d
		gopath = d
	}

	exe := buildPtrTests(t, gopath, false)
	exe2 := buildPtrTests(t, gopath, true)

	// We (TestPointerChecks) return before the parallel subtest functions do,
	// so we can't just defer os.RemoveAll(dir). Instead we have to wait for
	// the parallel subtests to finish. This code looks racy but is not:
	// the add +1 run in serial before testOne blocks. The -1 run in parallel
	// after testOne finishes.
	var pending int32
	for _, pt := range ptrTests {
		pt := pt
		t.Run(pt.name, func(t *testing.T) {
			atomic.AddInt32(&pending, +1)
			defer func() {
				if atomic.AddInt32(&pending, -1) == 0 {
					os.RemoveAll(dir)
				}
			}()
			testOne(t, pt, exe, exe2)
		})
	}
}

func buildPtrTests(t *testing.T, gopath string, cgocheck2 bool) (exe string) {

	src := filepath.Join(gopath, "src", "ptrtest")
	if err := os.MkdirAll(src, 0777); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(src, "go.mod"), []byte("module ptrtest\ngo 1.20"), 0666); err != nil {
		t.Fatal(err)
	}

	// Prepare two cgo inputs: one for standard cgo and one for //export cgo.
	// (The latter cannot have C definitions, only declarations.)
	var cgo1, cgo2 bytes.Buffer
	fmt.Fprintf(&cgo1, "package main\n\n/*\n")
	fmt.Fprintf(&cgo2, "package main\n\n/*\n")

	// C code
	for _, pt := range ptrTests {
		cgo := &cgo1
		if strings.Contains(pt.support, "//export") {
			cgo = &cgo2
		}
		fmt.Fprintf(cgo, "%s\n", pt.c)
		fmt.Fprintf(&cgo1, "%s\n", pt.c1)
	}
	fmt.Fprintf(&cgo1, "*/\nimport \"C\"\n\n")
	fmt.Fprintf(&cgo2, "*/\nimport \"C\"\n\n")

	// Imports
	did1 := make(map[string]bool)
	did2 := make(map[string]bool)
	did1["os"] = true // for ptrTestMain
	fmt.Fprintf(&cgo1, "import \"os\"\n")

	for _, pt := range ptrTests {
		did := did1
		cgo := &cgo1
		if strings.Contains(pt.support, "//export") {
			did = did2
			cgo = &cgo2
		}
		for _, imp := range pt.imports {
			if !did[imp] {
				did[imp] = true
				fmt.Fprintf(cgo, "import %q\n", imp)
			}
		}
	}

	// Func support and bodies.
	for _, pt := range ptrTests {
		cgo := &cgo1
		if strings.Contains(pt.support, "//export") {
			cgo = &cgo2
		}
		fmt.Fprintf(cgo, "%s\nfunc %s() {\n%s\n}\n", pt.support, pt.name, pt.body)
	}

	// Func list and main dispatch.
	fmt.Fprintf(&cgo1, "var funcs = map[string]func() {\n")
	for _, pt := range ptrTests {
		fmt.Fprintf(&cgo1, "\t%q: %s,\n", pt.name, pt.name)
	}
	fmt.Fprintf(&cgo1, "}\n\n")
	fmt.Fprintf(&cgo1, "%s\n", ptrTestMain)

	if err := os.WriteFile(filepath.Join(src, "cgo1.go"), cgo1.Bytes(), 0666); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(src, "cgo2.go"), cgo2.Bytes(), 0666); err != nil {
		t.Fatal(err)
	}

	exeName := "ptrtest.exe"
	if cgocheck2 {
		exeName = "ptrtest2.exe"
	}
	cmd := exec.Command("go", "build", "-o", exeName)
	cmd.Dir = src
	cmd.Env = append(os.Environ(), "GOPATH="+gopath)

	// Set or remove cgocheck2 from the environment.
	goexperiment := strings.Split(os.Getenv("GOEXPERIMENT"), ",")
	if len(goexperiment) == 1 && goexperiment[0] == "" {
		goexperiment = nil
	}
	i := slices.Index(goexperiment, "cgocheck2")
	changed := false
	if cgocheck2 && i < 0 {
		goexperiment = append(goexperiment, "cgocheck2")
		changed = true
	} else if !cgocheck2 && i >= 0 {
		goexperiment = slices.Delete(goexperiment, i, i+1)
		changed = true
	}
	if changed {
		cmd.Env = append(cmd.Env, "GOEXPERIMENT="+strings.Join(goexperiment, ","))
	}

	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("go build: %v\n%s", err, out)
	}

	return filepath.Join(src, exeName)
}

const ptrTestMain = `
func main() {
	for _, arg := range os.Args[1:] {
		f := funcs[arg]
		if f == nil {
			panic("missing func "+arg)
		}
		f()
	}
}
`

var csem = make(chan bool, 16)

func testOne(t *testing.T, pt ptrTest, exe, exe2 string) {
	t.Parallel()

	// Run the tests in parallel, but don't run too many
	// executions in parallel, to avoid overloading the system.
	runcmd := func(cgocheck string) ([]byte, error) {
		csem <- true
		defer func() { <-csem }()
		x := exe
		if cgocheck == "2" {
			x = exe2
			cgocheck = "1"
		}
		cmd := exec.Command(x, pt.name)
		cmd.Env = append(os.Environ(), "GODEBUG=cgocheck="+cgocheck)
		return cmd.CombinedOutput()
	}

	if pt.expensive {
		buf, err := runcmd("1")
		if err != nil {
			t.Logf("%s", buf)
			if pt.fail {
				t.Fatalf("test marked expensive, but failed when not expensive: %v", err)
			} else {
				t.Errorf("failed unexpectedly with GODEBUG=cgocheck=1: %v", err)
			}
		}

	}

	cgocheck := ""
	if pt.expensive {
		cgocheck = "2"
	}

	buf, err := runcmd(cgocheck)
	if pt.fail {
		if err == nil {
			t.Logf("%s", buf)
			t.Fatalf("did not fail as expected")
		} else if !bytes.Contains(buf, []byte("Go pointer")) {
			t.Logf("%s", buf)
			t.Fatalf("did not print expected error (failed with %v)", err)
		}
	} else {
		if err != nil {
			t.Logf("%s", buf)
			t.Fatalf("failed unexpectedly: %v", err)
		}

		if !pt.expensive {
			// Make sure it passes with the expensive checks.
			buf, err := runcmd("2")
			if err != nil {
				t.Logf("%s", buf)
				t.Fatalf("failed unexpectedly with expensive checks: %v", err)
			}
		}
	}

	if pt.fail {
		buf, err := runcmd("0")
		if err != nil {
			t.Logf("%s", buf)
			t.Fatalf("failed unexpectedly with GODEBUG=cgocheck=0: %v", err)
		}
	}
}

"""



```