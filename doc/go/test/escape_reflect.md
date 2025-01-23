Response: Let's break down the thought process for analyzing this Go code snippet about `reflect` and escape analysis.

**1. Understanding the Goal:**

The core purpose of this code is to test how the Go compiler's escape analysis handles various operations using the `reflect` package. Escape analysis determines whether a variable needs to be allocated on the heap or if it can stay on the stack. The comments like `// ERROR "x does not escape"` are the key – they indicate the expected behavior according to the escape analysis.

**2. Initial Scan for Patterns:**

I would quickly scan the code looking for recurring patterns. The most obvious pattern is the consistent use of `reflect.ValueOf(x)`. This immediately tells me the focus is on how `reflect.ValueOf` and subsequent operations affect the escape of `x`.

**3. Categorizing the Functions:**

To make sense of the many functions, I would mentally group them based on the `reflect.Value` methods they use. This leads to categories like:

* **Type and Kind:** `typ`, `kind`
* **Basic Value Accessors:** `int1`, `ptr`, `bytes1`, `string1`, `string2`
* **Interface Conversion:** `interface1`, `interface2`, `interface3`, `interface4`
* **Address and Pointer Operations:** `addr`, `uintptr1`, `unsafeaddr`, `ifacedata`
* **Boolean Checks:** `can`, `is`, `is2`, `is3`, `overflow`
* **Length and Capacity:** `len1` through `len5`, `cap1` through `cap3`
* **Setting Length and Capacity:** `setlen`, `setcap`
* **Slicing:** `slice1`, `slice2`, `slice3`
* **Element Access:** `elem1`, `elem2`
* **Struct Field Access:** `field1`, `field2`, `numfield`
* **Array/Slice Indexing:** `index1` through `index5`
* **Function/Method Calls:** `call1`, `call2`, `method`, `nummethod`
* **Map Operations:** `mapindex`, `mapkeys`, `mapiter1` through `mapiter3`, `setmapindex`, `mapdelete`
* **Channel Operations:** `recv1`, `recv2`, `send1`, `send2`, `close1`, `select1`, `select2`
* **Type Conversion:** `convert1`, `convert2`
* **Setting Values:** `set1` through `set7`, `setiterkey1`, `setiterkey2`, `setitervalue1`, `setitervalue2`
* **Appending:** `append1`, `append2`

**4. Analyzing Each Category (and Individual Functions):**

For each category (and sometimes each function), I would try to understand *why* the escape analysis produces the given result.

* **"Does not escape"**: This usually means the `reflect.Value` and the underlying data are used in a way that doesn't require them to live beyond the function's scope. The results are often scalar values or copies.

* **"Escapes to heap"**: This means the data needs to be allocated on the heap because its lifetime extends beyond the function call. This often happens when the `reflect.Value` or a pointer to the underlying data is returned or stored in a place that outlives the function.

* **"Leaking param..."**:  This indicates that a parameter's data is escaping, often because a pointer or a reference to it is being returned or stored. The level indicates how many indirections away the escape occurs.

* **"moved to heap"**:  This means a local variable is being promoted to the heap, usually because it's being captured by a closure or its address is being taken and used in a way that requires heap allocation.

**5. Looking for "Unfortunate" Cases:**

The comments often highlight cases marked as "Unfortunate."  These are the key points where the current escape analysis might be overly conservative (allocating on the heap when it might not strictly be necessary). Understanding *why* these are "unfortunate" is important. Often, it's because the *interface* itself is escaping, even if the underlying *data* conceptually shouldn't need to.

**6. Connecting to Go Concepts:**

Throughout the analysis, I'd connect the observed behavior to core Go concepts:

* **Value vs. Pointer Semantics:** How `reflect.ValueOf` handles different kinds of values (values vs. pointers).
* **Interfaces:** The overhead and implications of using `interface{}` and type assertions.
* **Slices and Maps:**  How the internal structure of slices and maps affects escape analysis.
* **Channels:**  The nature of channel operations (sending, receiving) and how they can cause data to escape.

**7. Generating Examples:**

Once I have a good understanding of the function's behavior, generating example code becomes easier. The examples should demonstrate the function's basic usage and potentially highlight the escape behavior (although the escape behavior is more about compiler optimization and harder to directly observe in simple code).

**8. Identifying Common Mistakes:**

Based on the escape analysis results and the nature of `reflect`, I can infer common mistakes users might make:

* **Unnecessary Heap Allocations:**  Using `reflect` can sometimes lead to unexpected heap allocations if not used carefully, especially when converting to `interface{}` or working with pointers.
* **Performance Overhead:**  `reflect` is generally slower than direct type operations, and understanding its escape behavior can help optimize performance by avoiding unnecessary allocations.

**Self-Correction/Refinement during the process:**

* If I see a pattern that doesn't quite fit my current understanding, I'd revisit the Go documentation or experiment with small code snippets to clarify the behavior.
* If the "unfortunate" cases are not clear, I'd think about the underlying implementation of `reflect` and why certain operations might force an allocation.

By following this systematic process of scanning, categorizing, analyzing, connecting to Go concepts, and looking for "unfortunate" cases, I can effectively understand and summarize the functionality of the provided Go code. The key is to move beyond just reading the code and delve into *why* the escape analysis behaves the way it does.
这个 Go 语言文件 `escape_reflect.go` 的主要功能是 **测试 Go 语言编译器在涉及 `reflect` 包操作时的逃逸分析能力**。

简单来说，它定义了一系列函数，这些函数都使用了 `reflect` 包的 `reflect.ValueOf()` 方法，以及基于此 `reflect.Value` 的各种操作。  代码中的 `// ERROR "..."` 注释是编译器在执行逃逸分析时预期产生的错误信息。这些错误信息指出了哪些变量逃逸到了堆上（heap），哪些没有逃逸，以及哪些参数泄漏了。

**核心目的:**

通过这些测试用例，Go 团队可以验证编译器的逃逸分析是否准确和高效地工作，特别是在与反射相关的场景中。目标是尽可能地将变量分配在栈上以提高性能，只有在必要时才分配到堆上。

**可以推理出它是什么 Go 语言功能的实现：**

这个文件是 **Go 语言编译器逃逸分析** 功能的一部分测试用例。逃逸分析是编译器优化中的一个重要环节，它决定了一个变量应该分配在栈上还是堆上。

**Go 代码举例说明:**

假设我们想理解 `func int1(x int) int` 的逃逸行为。代码中注释 `// ERROR "x does not escape"` 表明 `x` 变量在 `reflect.ValueOf(x)` 操作后没有逃逸到堆上。这是因为 `v.Int()` 返回的是 `x` 的值的拷贝，而不是 `x` 本身的引用。

```go
package main

import (
	"fmt"
	"reflect"
)

func int1Example(x int) int {
	v := reflect.ValueOf(x)
	return int(v.Int())
}

func main() {
	num := 10
	result := int1Example(num)
	fmt.Println(result) // Output: 10
}
```

在这个例子中，`num` 变量在 `int1Example` 函数中通过 `reflect.ValueOf` 被转换为 `reflect.Value`，然后又通过 `v.Int()` 取回其整数值。由于没有返回 `v` 或 `x` 的指针或引用，`num` 变量不需要逃逸到堆上。

**代码逻辑介绍（带假设输入与输出）：**

以 `func bytes1(x []byte) byte` 为例：

* **假设输入:** `x` 为 `[]byte{1, 2, 3}`
* **代码逻辑:**
    1. `v := reflect.ValueOf(x)`: 将字节切片 `x` 转换为 `reflect.Value`。
    2. `return v.Bytes()[0]`: 调用 `v.Bytes()` 获取 `x` 的字节切片的副本，然后返回该副本的第一个字节。
* **预期输出:** `1`
* **逃逸分析结果:** `// ERROR "x does not escape"`，表明 `x` 本身并没有逃逸，因为 `v.Bytes()` 返回的是数据的副本。

再以 `func bytes2(x []byte) []byte` 为例：

* **假设输入:** `x` 为 `[]byte{1, 2, 3}`
* **代码逻辑:**
    1. `v := reflect.ValueOf(x)`: 将字节切片 `x` 转换为 `reflect.Value`。
    2. `return v.Bytes()`: 调用 `v.Bytes()` 获取 `x` 的字节切片的副本。
* **预期输出:** `[]byte{1, 2, 3}`
* **逃逸分析结果:** `// ERROR "leaking param: x$"` 和 `// ERROR "x escapes to heap"`，表明 `x` 逃逸到了堆上。 尽管 `v.Bytes()` 返回的是副本，但是由于函数返回了这个切片，编译器认为其生命周期可能超出函数范围，因此将 `x`（更准确地说，是 `x` 的底层数组）分配到堆上。

**命令行参数的具体处理：**

这个代码文件本身是一个测试文件，并不直接涉及命令行参数的处理。它是通过 `go test` 命令来执行的，而 `go test` 可能会有一些参数用于控制测试的执行方式（例如 `-v` 显示详细输出，`-run` 指定运行哪些测试用例），但这与 `escape_reflect.go` 文件的代码逻辑无关。

`// errorcheck -0 -m -l` 这样的注释是用于 `go test` 的特殊指令：

* `-0`:  表示不做优化。
* `-m`:  启用编译器优化和内联的打印信息。
* `-l`:  禁用内联。

这些参数是控制编译器行为的，用于验证逃逸分析的结果是否符合预期。

**使用者易犯错的点（示例）：**

在使用 `reflect` 包时，一个常见的错误是认为 `reflect.ValueOf()` 操作不会导致变量逃逸。实际上，正如代码中的例子所示，很多情况下，即使是对基本类型进行 `reflect.ValueOf()` 操作，如果后续的操作或函数的返回值涉及到了原始数据的引用或指针，都可能导致变量逃逸到堆上。

例如，在 `func interface1(x any) any` 中，尽管输入的是一个接口类型，但是将 `reflect.Value` 通过 `Interface()` 方法转换回接口类型并返回，会导致参数 `x` 逃逸。这是因为返回的接口值可能包含了指向原始数据的指针。

```go
package main

import (
	"fmt"
	"reflect"
)

func interface1Example(x interface{}) interface{} {
	v := reflect.ValueOf(x)
	return v.Interface()
}

func main() {
	num := 10
	result := interface1Example(num)
	fmt.Println(result) // Output: 10
	fmt.Printf("%T\n", result) // Output: int
}
```

在这个 `interface1Example` 函数中，即使传入的是一个基本类型 `int`，由于返回的是 `interface{}` 类型，编译器可能会将 `num` 变量分配到堆上，以便返回的接口值能够持有该值。  `escape_reflect.go` 中的 `// ERROR "leaking param: x$"` 注释就指出了这一点。

**总结:**

`escape_reflect.go` 是 Go 语言编译器测试套件的一部分，专门用于测试 `reflect` 包操作的逃逸分析。通过分析各种使用 `reflect.ValueOf` 和相关方法的场景，它可以验证编译器是否正确地判断了变量的逃逸行为，这对于保证 Go 程序的性能至关重要。使用者需要理解，即使是使用 `reflect` 对值进行操作，也可能因为后续的操作导致变量逃逸到堆上。

### 提示词
```
这是路径为go/test/escape_reflect.go的go语言实现的一部分， 请归纳一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果介绍代码逻辑，则建议带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
```

### 源代码
```
// errorcheck -0 -m -l

// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Test escape analysis for reflect Value operations.

package escape

import (
	"reflect"
	"unsafe"
)

var sink interface{}

func typ(x int) any {
	v := reflect.ValueOf(x) // ERROR "x does not escape"
	return v.Type()
}

func kind(x int) reflect.Kind {
	v := reflect.ValueOf(x) // ERROR "x does not escape"
	return v.Kind()
}

func int1(x int) int {
	v := reflect.ValueOf(x) // ERROR "x does not escape"
	return int(v.Int())
}

func ptr(x *int) *int { // ERROR "leaking param: x to result ~r0 level=0"
	v := reflect.ValueOf(x)
	return (*int)(v.UnsafePointer())
}

func bytes1(x []byte) byte { // ERROR "x does not escape"
	v := reflect.ValueOf(x) // ERROR "x does not escape"
	return v.Bytes()[0]
}

// Unfortunate: should only escape content. x (the interface storage) should not escape.
func bytes2(x []byte) []byte { // ERROR "leaking param: x$"
	v := reflect.ValueOf(x) // ERROR "x escapes to heap"
	return v.Bytes()
}

func string1(x string) string { // ERROR "leaking param: x to result ~r0 level=0"
	v := reflect.ValueOf(x) // ERROR "x does not escape"
	return v.String()
}

func string2(x int) string {
	v := reflect.ValueOf(x) // ERROR "x does not escape"
	return v.String()
}

// Unfortunate: should only escape to result.
func interface1(x any) any { // ERROR "leaking param: x$"
	v := reflect.ValueOf(x)
	return v.Interface()
}

func interface2(x int) any {
	v := reflect.ValueOf(x) // ERROR "x escapes to heap"
	return v.Interface()
}

// Unfortunate: should not escape.
func interface3(x int) int {
	v := reflect.ValueOf(x) // ERROR "x escapes to heap"
	return v.Interface().(int)
}

// Unfortunate: should only escape to result.
func interface4(x *int) any { // ERROR "leaking param: x$"
	v := reflect.ValueOf(x)
	return v.Interface()
}

func addr(x *int) reflect.Value { // ERROR "leaking param: x to result ~r0 level=0"
	v := reflect.ValueOf(x).Elem()
	return v.Addr()
}

// functions returning pointer as uintptr have to escape.
func uintptr1(x *int) uintptr { // ERROR "leaking param: x$"
	v := reflect.ValueOf(x)
	return v.Pointer()
}

func unsafeaddr(x *int) uintptr { // ERROR "leaking param: x$"
	v := reflect.ValueOf(x).Elem()
	return v.UnsafeAddr()
}

func ifacedata(x any) [2]uintptr { // ERROR "moved to heap: x"
	v := reflect.ValueOf(&x).Elem()
	return v.InterfaceData()
}

func can(x int) bool {
	v := reflect.ValueOf(x) // ERROR "x does not escape"
	return v.CanAddr() || v.CanInt() || v.CanSet() || v.CanInterface()
}

func is(x int) bool {
	v := reflect.ValueOf(x) // ERROR "x does not escape"
	return v.IsValid() || v.IsNil() || v.IsZero()
}

func is2(x [2]int) bool {
	v := reflect.ValueOf(x) // ERROR "x does not escape"
	return v.IsValid() || v.IsNil() || v.IsZero()
}

func is3(x struct{ a, b int }) bool {
	v := reflect.ValueOf(x) // ERROR "x does not escape"
	return v.IsValid() || v.IsNil() || v.IsZero()
}

func overflow(x int) bool {
	v := reflect.ValueOf(x) // ERROR "x does not escape"
	return v.OverflowInt(1 << 62)
}

func len1(x []int) int { // ERROR "x does not escape"
	v := reflect.ValueOf(x) // ERROR "x does not escape"
	return v.Len()
}

func len2(x [3]int) int {
	v := reflect.ValueOf(x) // ERROR "x does not escape"
	return v.Len()
}

func len3(x string) int { // ERROR "x does not escape"
	v := reflect.ValueOf(x) // ERROR "x does not escape"
	return v.Len()
}

func len4(x map[int]int) int { // ERROR "x does not escape"
	v := reflect.ValueOf(x)
	return v.Len()
}

func len5(x chan int) int { // ERROR "x does not escape"
	v := reflect.ValueOf(x)
	return v.Len()
}

func cap1(x []int) int { // ERROR "x does not escape"
	v := reflect.ValueOf(x) // ERROR "x does not escape"
	return v.Cap()
}

func cap2(x [3]int) int {
	v := reflect.ValueOf(x) // ERROR "x does not escape"
	return v.Cap()
}

func cap3(x chan int) int { // ERROR "x does not escape"
	v := reflect.ValueOf(x)
	return v.Cap()
}

func setlen(x *[]int, n int) { // ERROR "x does not escape"
	v := reflect.ValueOf(x).Elem()
	v.SetLen(n)
}

func setcap(x *[]int, n int) { // ERROR "x does not escape"
	v := reflect.ValueOf(x).Elem()
	v.SetCap(n)
}

// Unfortunate: x doesn't need to escape to heap, just to result.
func slice1(x []byte) []byte { // ERROR "leaking param: x$"
	v := reflect.ValueOf(x) // ERROR "x escapes to heap"
	return v.Slice(1, 2).Bytes()
}

// Unfortunate: x doesn't need to escape to heap, just to result.
func slice2(x string) string { // ERROR "leaking param: x$"
	v := reflect.ValueOf(x) // ERROR "x escapes to heap"
	return v.Slice(1, 2).String()
}

func slice3(x [10]byte) []byte {
	v := reflect.ValueOf(x) // ERROR "x escapes to heap"
	return v.Slice(1, 2).Bytes()
}

func elem1(x *int) int { // ERROR "x does not escape"
	v := reflect.ValueOf(x)
	return int(v.Elem().Int())
}

func elem2(x *string) string { // ERROR "leaking param: x to result ~r0 level=1"
	v := reflect.ValueOf(x)
	return string(v.Elem().String())
}

type S struct {
	A int
	B *int
	C string
}

func (S) M() {}

func field1(x S) int { // ERROR "x does not escape"
	v := reflect.ValueOf(x) // ERROR "x does not escape"
	return int(v.Field(0).Int())
}

func field2(x S) string { // ERROR "leaking param: x to result ~r0 level=0"
	v := reflect.ValueOf(x) // ERROR "x does not escape"
	return v.Field(2).String()
}

func numfield(x S) int { // ERROR "x does not escape"
	v := reflect.ValueOf(x) // ERROR "x does not escape"
	return v.NumField()
}

func index1(x []int) int { // ERROR "x does not escape"
	v := reflect.ValueOf(x) // ERROR "x does not escape"
	return int(v.Index(0).Int())
}

// Unfortunate: should only leak content (level=1)
func index2(x []string) string { // ERROR "leaking param: x to result ~r0 level=0"
	v := reflect.ValueOf(x) // ERROR "x does not escape"
	return v.Index(0).String()
}

func index3(x [3]int) int {
	v := reflect.ValueOf(x) // ERROR "x does not escape"
	return int(v.Index(0).Int())
}

func index4(x [3]string) string { // ERROR "leaking param: x to result ~r0 level=0"
	v := reflect.ValueOf(x) // ERROR "x does not escape"
	return v.Index(0).String()
}

func index5(x string) byte { // ERROR "x does not escape"
	v := reflect.ValueOf(x) // ERROR "x does not escape"
	return byte(v.Index(0).Uint())
}

// Unfortunate: x (the interface storage) doesn't need to escape as the function takes a scalar arg.
func call1(f func(int), x int) { // ERROR "leaking param: f$"
	fv := reflect.ValueOf(f)
	v := reflect.ValueOf(x)     // ERROR "x escapes to heap"
	fv.Call([]reflect.Value{v}) // ERROR "\[\]reflect\.Value{\.\.\.} does not escape"
}

func call2(f func(*int), x *int) { // ERROR "leaking param: f$" "leaking param: x$"
	fv := reflect.ValueOf(f)
	v := reflect.ValueOf(x)
	fv.Call([]reflect.Value{v}) // ERROR "\[\]reflect.Value{\.\.\.} does not escape"
}

func method(x S) reflect.Value { // ERROR "leaking param: x$"
	v := reflect.ValueOf(x) // ERROR "x escapes to heap"
	return v.Method(0)
}

func nummethod(x S) int { // ERROR "x does not escape"
	v := reflect.ValueOf(x) // ERROR "x does not escape"
	return v.NumMethod()
}

// Unfortunate: k doesn't need to escape.
func mapindex(m map[string]string, k string) string { // ERROR "m does not escape" "leaking param: k$"
	mv := reflect.ValueOf(m)
	kv := reflect.ValueOf(k) // ERROR "k escapes to heap"
	return mv.MapIndex(kv).String()
}

func mapkeys(m map[string]string) []reflect.Value { // ERROR "m does not escape"
	mv := reflect.ValueOf(m)
	return mv.MapKeys()
}

func mapiter1(m map[string]string) *reflect.MapIter { // ERROR "leaking param: m$"
	mv := reflect.ValueOf(m)
	return mv.MapRange()
}

func mapiter2(m map[string]string) string { // ERROR "leaking param: m$"
	mv := reflect.ValueOf(m)
	it := mv.MapRange()
	if it.Next() {
		return it.Key().String()
	}
	return ""
}

func mapiter3(m map[string]string, it *reflect.MapIter) { // ERROR "leaking param: m$" "it does not escape"
	mv := reflect.ValueOf(m)
	it.Reset(mv)
}

func recv1(ch chan string) string { // ERROR "ch does not escape"
	v := reflect.ValueOf(ch)
	r, _ := v.Recv()
	return r.String()
}

func recv2(ch chan string) string { // ERROR "ch does not escape"
	v := reflect.ValueOf(ch)
	r, _ := v.TryRecv()
	return r.String()
}

// Unfortunate: x (the interface storage) doesn't need to escape.
func send1(ch chan string, x string) { // ERROR "ch does not escape" "leaking param: x$"
	vc := reflect.ValueOf(ch)
	vx := reflect.ValueOf(x) // ERROR "x escapes to heap"
	vc.Send(vx)
}

// Unfortunate: x (the interface storage) doesn't need to escape.
func send2(ch chan string, x string) bool { // ERROR "ch does not escape" "leaking param: x$"
	vc := reflect.ValueOf(ch)
	vx := reflect.ValueOf(x) // ERROR "x escapes to heap"
	return vc.TrySend(vx)
}

func close1(ch chan string) { // ERROR "ch does not escape"
	v := reflect.ValueOf(ch)
	v.Close()
}

func select1(ch chan string) string { // ERROR "leaking param: ch$"
	v := reflect.ValueOf(ch)
	cas := reflect.SelectCase{Dir: reflect.SelectRecv, Chan: v}
	_, r, _ := reflect.Select([]reflect.SelectCase{cas}) // ERROR "\[\]reflect.SelectCase{...} does not escape"
	return r.String()
}

// Unfortunate: x (the interface storage) doesn't need to escape.
func select2(ch chan string, x string) { // ERROR "leaking param: ch$" "leaking param: x$"
	vc := reflect.ValueOf(ch)
	vx := reflect.ValueOf(x) // ERROR "x escapes to heap"
	cas := reflect.SelectCase{Dir: reflect.SelectSend, Chan: vc, Send: vx}
	reflect.Select([]reflect.SelectCase{cas}) // ERROR "\[\]reflect.SelectCase{...} does not escape"
}

var (
	intTyp    = reflect.TypeOf(int(0))     // ERROR "0 does not escape"
	uintTyp   = reflect.TypeOf(uint(0))    // ERROR "uint\(0\) does not escape"
	stringTyp = reflect.TypeOf(string("")) // ERROR ".. does not escape"
	bytesTyp  = reflect.TypeOf([]byte{})   // ERROR "\[\]byte{} does not escape"
)

// Unfortunate: should not escape.
func convert1(x int) uint {
	v := reflect.ValueOf(x) // ERROR "x escapes to heap"
	return uint(v.Convert(uintTyp).Uint())
}

// Unfortunate: should only escape content to result.
func convert2(x []byte) string { // ERROR "leaking param: x$"
	v := reflect.ValueOf(x) // ERROR "x escapes to heap"
	return v.Convert(stringTyp).String()
}

// Unfortunate: v doesn't need to leak, x (the interface storage) doesn't need to escape.
func set1(v reflect.Value, x int) { // ERROR "leaking param: v$"
	vx := reflect.ValueOf(x) // ERROR "x escapes to heap"
	v.Set(vx)
}

// Unfortunate: a can be stack allocated, x (the interface storage) doesn't need to escape.
func set2(x int) int64 {
	var a int // ERROR "moved to heap: a"
	v := reflect.ValueOf(&a).Elem()
	vx := reflect.ValueOf(x) // ERROR "x escapes to heap"
	v.Set(vx)
	return v.Int()
}

func set3(v reflect.Value, x int) { // ERROR "v does not escape"
	v.SetInt(int64(x))
}

func set4(x int) int {
	var a int
	v := reflect.ValueOf(&a).Elem() // a should not escape, no error printed
	v.SetInt(int64(x))
	return int(v.Int())
}

func set5(v reflect.Value, x string) { // ERROR "v does not escape" "leaking param: x$"
	v.SetString(x)
}

func set6(v reflect.Value, x []byte) { // ERROR "v does not escape" "leaking param: x$"
	v.SetBytes(x)
}

func set7(v reflect.Value, x unsafe.Pointer) { // ERROR "v does not escape" "leaking param: x$"
	v.SetPointer(x)
}

func setmapindex(m map[string]string, k, e string) { // ERROR "m does not escape" "leaking param: k$" "leaking param: e$"
	mv := reflect.ValueOf(m)
	kv := reflect.ValueOf(k) // ERROR "k escapes to heap"
	ev := reflect.ValueOf(e) // ERROR "e escapes to heap"
	mv.SetMapIndex(kv, ev)
}

// Unfortunate: k doesn't need to escape.
func mapdelete(m map[string]string, k string) { // ERROR "m does not escape" "leaking param: k$"
	mv := reflect.ValueOf(m)
	kv := reflect.ValueOf(k) // ERROR "k escapes to heap"
	mv.SetMapIndex(kv, reflect.Value{})
}

// Unfortunate: v doesn't need to leak.
func setiterkey1(v reflect.Value, it *reflect.MapIter) { // ERROR "leaking param: v$" "leaking param content: it$"
	v.SetIterKey(it)
}

// Unfortunate: v doesn't need to leak.
func setiterkey2(v reflect.Value, m map[string]string) { // ERROR "leaking param: v$" "leaking param: m$"
	it := reflect.ValueOf(m).MapRange()
	v.SetIterKey(it)
}

// Unfortunate: v doesn't need to leak.
func setitervalue1(v reflect.Value, it *reflect.MapIter) { // ERROR "leaking param: v$" "leaking param content: it$"
	v.SetIterValue(it)
}

// Unfortunate: v doesn't need to leak.
func setitervalue2(v reflect.Value, m map[string]string) { // ERROR "leaking param: v$" "leaking param: m$"
	it := reflect.ValueOf(m).MapRange()
	v.SetIterValue(it)
}

// Unfortunate: s doesn't need escape, only leak to result.
// And x (interface storage) doesn't need to escape.
func append1(s []int, x int) []int { // ERROR "leaking param: s$"
	sv := reflect.ValueOf(s)     // ERROR "s escapes to heap"
	xv := reflect.ValueOf(x)     // ERROR "x escapes to heap"
	rv := reflect.Append(sv, xv) // ERROR "... argument does not escape"
	return rv.Interface().([]int)
}

// Unfortunate: s doesn't need escape, only leak to result.
func append2(s, x []int) []int { // ERROR "leaking param: s$" "x does not escape"
	sv := reflect.ValueOf(s) // ERROR "s escapes to heap"
	xv := reflect.ValueOf(x) // ERROR "x does not escape"
	rv := reflect.AppendSlice(sv, xv)
	return rv.Interface().([]int)
}
```