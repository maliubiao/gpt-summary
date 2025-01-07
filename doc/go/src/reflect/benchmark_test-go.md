Response:
Let's break down the thought process for analyzing the provided Go benchmark code.

**1. Initial Understanding - The Goal:**

The first thing I notice is the file path: `go/src/reflect/benchmark_test.go`. This immediately tells me the code is part of the Go standard library's `reflect` package and is specifically for benchmarking. Benchmarks are used to measure the performance of different code implementations.

**2. High-Level Structure Scan:**

I quickly scan the code to identify key elements:

* **`package reflect_test`:** This confirms it's a test file within the `reflect` package's testing suite. The `_test` suffix is crucial.
* **`import (...)`:**  The imports show dependencies on `fmt`, the `reflect` package itself (aliased as `.`), `strconv`, and `testing`. This hints at operations involving reflection, string conversions, and benchmarking functionalities.
* **Global Variables `sourceAll` and `sinkAll`:** These are clearly set up as test data sources and sinks. `sourceAll` holds `reflect.Value` instances of various types, and `sinkAll` holds raw Go values. This pattern suggests the benchmarks will involve converting `reflect.Value` back to concrete types.
* **Numerous `Benchmark...` functions:** This is the core of the file. Each function with the `Benchmark` prefix is a Go benchmark function. The names of these functions (e.g., `BenchmarkBool`, `BenchmarkStringLen`, `BenchmarkDeepEqual`) strongly suggest what aspects of the `reflect` package are being measured.

**3. Analyzing Individual Benchmarks (Pattern Recognition):**

I start examining the benchmark functions individually, looking for common patterns:

* **Basic Value Extraction (e.g., `BenchmarkBool`, `BenchmarkString`, `BenchmarkBytes`):** These follow a simple pattern: iterate `b.N` times and extract a value from `sourceAll` using a `reflect.Value` method (`Bool()`, `String()`, `Bytes()`) and assign it to a raw variable in `sinkAll`. This directly benchmarks the cost of these reflection operations.
* **Length and Capacity (e.g., `BenchmarkSliceLen`, `BenchmarkMapLen`, `BenchmarkStringLen`, `BenchmarkArrayLen`, `BenchmarkSliceCap`):** These benchmarks call `Len()` or `Cap()` on `reflect.Value` instances. This measures the performance of getting the length or capacity of reflected types.
* **`DeepEqual` (e.g., `BenchmarkDeepEqual`, `BenchmarkMapsDeepEqual`):**  These benchmarks use `reflect.DeepEqual` to compare values. This highlights the cost of deep comparison using reflection. The `BenchmarkDeepEqual` uses a test suite (`deepEqualPerfTests`), suggesting more complex scenarios are being tested.
* **`IsZero` (e.g., `BenchmarkIsZero`):** This benchmark uses `value.IsZero()` to check if a reflected value is the zero value for its type. It tests various struct compositions.
* **`SetZero` (e.g., `BenchmarkSetZero`):** This benchmark focuses on setting reflected values to their zero value using `value.SetZero()` and comparing it to using `value.Set(Zero(value.Type()))`. This investigates the performance difference between direct `SetZero` and setting with a zero value.
* **`Select` (e.g., `BenchmarkSelect`):** This benchmarks the `reflect.Select` function, simulating channel operations within a `select` statement.
* **`Call` (e.g., `BenchmarkCall`, `BenchmarkCallMethod`, `BenchmarkCallArgCopy`):** These benchmarks focus on calling functions and methods through reflection, considering argument copying costs. `BenchmarkCallArgCopy` specifically tests the performance impact of different argument sizes.
* **Type Operations (e.g., `BenchmarkPtrTo`, `BenchmarkFieldByName1`, `BenchmarkFieldByName2`, `BenchmarkFieldByName3`):** These benchmarks measure the performance of operations on `reflect.Type`, such as getting a pointer type (`PointerTo`) or finding fields by name (`FieldByName`).
* **Interface Conversion (e.g., `BenchmarkInterfaceBig`, `BenchmarkInterfaceSmall`):** These benchmarks measure the cost of converting reflected values to their interface representation (`v.Interface()`).
* **`New` (e.g., `BenchmarkNew`):** This benchmarks creating new values of a reflected type using `reflect.New`.
* **Map Operations (e.g., `BenchmarkMap`, `BenchmarkMapIterNext`):** These benchmarks focus on map operations like indexing (`MapIndex`), setting values (`SetMapIndex`), and iterating (`MapRange`).

**4. Inferring Go Features:**

Based on the benchmarks, I can confidently infer that this code is testing the performance of the following `reflect` package functionalities:

* **Accessing values of different types:**  `Bool()`, `String()`, `Bytes()`, etc.
* **Getting length and capacity:** `Len()`, `Cap()`.
* **Deep equality comparison:** `DeepEqual()`.
* **Checking for zero values:** `IsZero()`.
* **Setting values to zero:** `SetZero()`.
* **Performing select operations on channels:** `Select()`.
* **Calling functions and methods:** `Call()`.
* **Converting between types and their pointer types:** `PointerTo()`.
* **Accessing struct fields by name:** `FieldByName()`.
* **Converting reflected values to interfaces:** `Interface()`.
* **Creating new values of a specific type:** `New()`.
* **Operating on maps:** `MapIndex()`, `SetMapIndex()`, `MapRange()`.

**5. Code Examples and Reasoning:**

For each inferred feature, I construct simple Go code examples to illustrate how these `reflect` functions are used. The key is to show the interaction between concrete Go values and their `reflect.Value` or `reflect.Type` representations.

**6. Input and Output (Where Applicable):**

For benchmarks like `BenchmarkCallArgCopy`, where the size of the argument influences performance, I explicitly mention the input (the byte array size) and implicitly the "output" (the execution time, which is what the benchmark measures).

**7. Command-Line Arguments:**

I recall that Go benchmarks are run using the `go test` command with the `-bench` flag. I explain how to use this flag and the regular expression syntax to target specific benchmarks.

**8. Common Mistakes:**

I consider common pitfalls when using reflection, such as:

* **Performance Overhead:**  Emphasize that reflection is generally slower than direct type operations.
* **Panic Potential:**  Highlight the possibility of panics if types don't match expectations (e.g., calling `Int()` on a `reflect.Value` that doesn't hold an integer). The `IsValid()` method is mentioned as a way to mitigate this.

**9. Language and Structure:**

Finally, I organize the information logically, using clear headings and bullet points for readability. I ensure the language is precise and avoids jargon where possible, explaining concepts in a way that is accessible to someone learning about reflection. The use of Chinese was maintained as requested.

This systematic approach, starting with a broad understanding and gradually drilling down into specifics, combined with knowledge of Go's testing and reflection mechanisms, enables a comprehensive analysis of the provided benchmark code.
这段代码是 Go 语言 `reflect` 包的一部分，用于进行性能基准测试。它主要测试了 `reflect` 包中各种功能的性能，以便了解这些功能在不同场景下的效率。

以下是代码中各个基准测试的功能列表：

**核心功能测试：**

* **`BenchmarkBool`**: 测试从 `reflect.Value` 中获取 `bool` 类型值的性能。
* **`BenchmarkString`**: 测试从 `reflect.Value` 中获取 `string` 类型值的性能。
* **`BenchmarkBytes`**: 测试从 `reflect.Value` 中获取 `[]byte` 类型值的性能。
* **`BenchmarkNamedBytes`**: 测试从 `reflect.Value` 中获取自定义 `[]byte` 类型（`namedBytes`）值的性能。
* **`BenchmarkBytesArray`**: 测试从 `reflect.Value` 中获取字节数组 (`[32]byte`) 类型值的性能。

**长度和容量测试：**

* **`BenchmarkSliceLen`**: 测试获取切片 (`[]any`) 的长度的性能。
* **`BenchmarkMapLen`**: 测试获取 map (`map[string]any`) 的长度的性能。
* **`BenchmarkStringLen`**: 测试获取字符串的长度的性能。
* **`BenchmarkArrayLen`**: 测试获取数组 (`[32]byte`) 的长度的性能。
* **`BenchmarkSliceCap`**: 测试获取切片 (`[]any`) 的容量的性能。

**深度相等测试：**

* **`BenchmarkDeepEqual`**: 测试 `reflect.DeepEqual` 函数在不同类型上的性能。它使用了 `deepEqualPerfTests` 这个变量，虽然代码中没有提供它的定义，但可以推断它是一个包含了多种测试用例的切片，每个用例包含两个待比较的值 `x` 和 `y`。
* **`BenchmarkMapsDeepEqual`**: 测试 `reflect.DeepEqual` 函数比较两个 map 的性能。

**零值测试：**

* **`BenchmarkIsZero`**: 测试 `reflect.Value.IsZero()` 方法判断不同类型的零值的性能。它创建了一个包含多种类型字段的结构体 `s`，并遍历其字段进行测试。

**设置零值测试：**

* **`BenchmarkSetZero`**: 测试 `reflect.Value.SetZero()` 方法将 `reflect.Value` 设置为其零值的性能，并与使用 `reflect.Zero()` 方法创建零值再进行设置的性能进行比较。

**Select 操作测试：**

* **`BenchmarkSelect`**: 测试 `reflect.Select` 函数在不同数量的 `SelectCase` 上的性能。它模拟了 `select` 语句在多个 channel 上的操作。

**函数调用测试：**

* **`BenchmarkCall`**: 测试通过 `reflect.Value.Call()` 方法调用函数的性能。
* **`BenchmarkCallMethod`**: 测试通过 `reflect.Value.Call()` 方法调用结构体方法的性能。
* **`BenchmarkCallArgCopy`**: 测试通过 `reflect.Value.Call()` 方法调用函数时，不同大小的数组参数拷贝的性能。

**类型操作测试：**

* **`BenchmarkPtrTo`**: 测试 `reflect.PointerTo()` 函数获取类型指针的性能。它特别测试了当类型 `rtype` 的 `ptrToThis` 字段为零时的性能，这种情况会触发 `reflect` 包内部的指针映射缓存。
* **`BenchmarkFieldByName1`**, **`BenchmarkFieldByName2`**, **`BenchmarkFieldByName3`**: 测试 `reflect.Type.FieldByName()` 方法查找结构体字段的性能，针对不同的结构体类型进行测试。

**接口操作测试：**

* **`BenchmarkInterfaceBig`**: 测试将包含较大数据的结构体转换为 `interface{}` 的性能。
* **`BenchmarkInterfaceSmall`**: 测试将较小的数据类型 (int64) 转换为 `interface{}` 的性能。

**New 操作测试：**

* **`BenchmarkNew`**: 测试 `reflect.New()` 函数创建指定类型指针的性能。

**Map 操作测试：**

* **`BenchmarkMap`**: 测试 `reflect.Value` 上 Map 相关的操作，包括 `MapIndex` (获取指定键的值) 和 `SetMapIndex` (设置指定键的值)。测试了使用 `string`、`uint64` 和自定义类型 `S` 作为键的 map。
* **`BenchmarkMapIterNext`**: 测试 `reflect.MapRange()` 方法进行 map 迭代的性能。

**代码功能推断与示例：**

这段代码主要测试了 Go 语言的 **反射 (reflection)** 功能的性能。反射允许程序在运行时检查和操作类型信息。

**示例 1: 获取值**

```go
package main

import (
	"fmt"
	"reflect"
)

func main() {
	var num int = 10
	value := reflect.ValueOf(num)

	// 获取 int 值
	intValue := value.Int()
	fmt.Println("Int Value:", intValue) // 输出: Int Value: 10

	var str string = "hello"
	stringValue := reflect.ValueOf(str)

	// 获取 string 值
	strValue := stringValue.String()
	fmt.Println("String Value:", strValue) // 输出: String Value: hello
}
```

**示例 2: 获取长度**

```go
package main

import (
	"fmt"
	"reflect"
)

func main() {
	slice := []int{1, 2, 3, 4, 5}
	sliceValue := reflect.ValueOf(slice)

	// 获取切片长度
	length := sliceValue.Len()
	fmt.Println("Slice Length:", length) // 输出: Slice Length: 5

	m := map[string]int{"a": 1, "b": 2}
	mapValue := reflect.ValueOf(m)

	// 获取 map 长度
	mapLength := mapValue.Len()
	fmt.Println("Map Length:", mapLength) // 输出: Map Length: 2
}
```

**示例 3: 深度相等**

```go
package main

import (
	"fmt"
	"reflect"
)

func main() {
	a := []int{1, 2, 3}
	b := []int{1, 2, 3}
	c := []int{1, 2, 4}

	fmt.Println("a == b:", reflect.DeepEqual(a, b)) // 输出: a == b: true
	fmt.Println("a == c:", reflect.DeepEqual(a, c)) // 输出: a == c: false
}
```

**示例 4: 调用函数**

```go
package main

import (
	"fmt"
	"reflect"
)

func add(x, y int) int {
	return x + y
}

func main() {
	funcValue := reflect.ValueOf(add)
	args := []reflect.Value{reflect.ValueOf(5), reflect.ValueOf(3)}
	result := funcValue.Call(args)
	fmt.Println("Result of add(5, 3):", result[0].Int()) // 输出: Result of add(5, 3): 8
}
```

**假设的输入与输出 (BenchmarkDeepEqual)：**

假设 `deepEqualPerfTests` 定义如下：

```go
var deepEqualPerfTests = []struct {
	x, y interface{}
}{
	{1, 1},
	{"hello", "hello"},
	{[]int{1, 2}, []int{1, 2}},
	{map[string]int{"a": 1}, map[string]int{"a": 1}},
}
```

对于 `BenchmarkDeepEqual` 函数，其内部循环会遍历 `deepEqualPerfTests`，并对每个测试用例运行一个子基准测试。例如，对于第一个测试用例 `{1, 1}`，它会运行类似于以下的基准测试：

```
BenchmarkDeepEqual/int
```

输出结果会显示 `reflect.DeepEqual(1, 1)` 的性能数据，例如：

```
BenchmarkDeepEqual/int-8   1000000000               0.250 ns/op           0 B/op          0 allocs/op
```

这表示在 8 个 CPU 核心下运行，执行了 10 亿次操作，每次操作耗时 0.250 纳秒，没有内存分配。

**命令行参数的具体处理：**

这个文件本身是一个基准测试文件，它会被 `go test` 命令调用，并使用 `-bench` 标志来运行基准测试。

运行所有基准测试：

```bash
go test -bench=. ./reflect
```

运行名称包含 "Bool" 的基准测试：

```bash
go test -bench=BenchmarkBool ./reflect
```

运行名称以 "BenchmarkDeepEqual" 开头的基准测试：

```bash
go test -bench=BenchmarkDeepEqual.* ./reflect
```

常用的 `-bench` 相关参数：

* **`-bench=<regexp>`**:  指定要运行的基准测试的正则表达式。`.` 表示运行所有基准测试。
* **`-benchtime=<d>`**: 指定每个基准测试的运行时间，例如 `1s` 表示 1 秒。默认为足够稳定地测量结果的时间。
* **`-benchmem`**:  输出基准测试的内存分配统计信息。
* **`-cpu=<n>`**: 指定运行基准测试的 CPU 数量。

**使用者易犯错的点：**

在编写和理解 `reflect` 包的基准测试时，使用者容易犯的错误可能包括：

1. **误解基准测试的目标**:  不清楚每个基准测试具体衡量的是哪个 `reflect` 功能的性能。仔细阅读基准测试的函数名和内部逻辑可以避免这个问题。

2. **对 `reflect.Value` 的理解不足**:  例如，错误地假设对不同类型的 `reflect.Value` 执行相同的方法会有相同的性能开销。实际上，由于底层类型的差异，性能可能会有很大不同。

3. **忽略内存分配**:  只关注执行时间，而忽略了内存分配对性能的影响。使用 `-benchmem` 标志可以帮助分析内存分配情况。

4. **不理解并行基准测试 (`b.RunParallel`)**:  对于使用了 `b.RunParallel` 的基准测试，例如 `BenchmarkCall`，其性能结果是并行执行的综合体现，需要理解并行执行可能带来的开销和优势。

5. **假设基准测试环境**:  基准测试结果可能受到硬件、操作系统和 Go 版本的影响。在不同的环境下运行可能会得到不同的结果。

总而言之，这段代码是 Go 语言 `reflect` 包的性能测试套件，它通过一系列细致的基准测试，帮助开发者和 Go 语言维护者了解 `reflect` 包中各种功能的性能特征，并可以用于持续优化 `reflect` 包的性能。

Prompt: 
```
这是路径为go/src/reflect/benchmark_test.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。

"""
// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package reflect_test

import (
	"fmt"
	. "reflect"
	"strconv"
	"testing"
)

var sourceAll = struct {
	Bool         Value
	String       Value
	Bytes        Value
	NamedBytes   Value
	BytesArray   Value
	SliceAny     Value
	MapStringAny Value
}{
	Bool:         ValueOf(new(bool)).Elem(),
	String:       ValueOf(new(string)).Elem(),
	Bytes:        ValueOf(new([]byte)).Elem(),
	NamedBytes:   ValueOf(new(namedBytes)).Elem(),
	BytesArray:   ValueOf(new([32]byte)).Elem(),
	SliceAny:     ValueOf(new([]any)).Elem(),
	MapStringAny: ValueOf(new(map[string]any)).Elem(),
}

var sinkAll struct {
	RawBool   bool
	RawString string
	RawBytes  []byte
	RawInt    int
}

func BenchmarkBool(b *testing.B) {
	for i := 0; i < b.N; i++ {
		sinkAll.RawBool = sourceAll.Bool.Bool()
	}
}

func BenchmarkString(b *testing.B) {
	for i := 0; i < b.N; i++ {
		sinkAll.RawString = sourceAll.String.String()
	}
}

func BenchmarkBytes(b *testing.B) {
	for i := 0; i < b.N; i++ {
		sinkAll.RawBytes = sourceAll.Bytes.Bytes()
	}
}

func BenchmarkNamedBytes(b *testing.B) {
	for i := 0; i < b.N; i++ {
		sinkAll.RawBytes = sourceAll.NamedBytes.Bytes()
	}
}

func BenchmarkBytesArray(b *testing.B) {
	for i := 0; i < b.N; i++ {
		sinkAll.RawBytes = sourceAll.BytesArray.Bytes()
	}
}

func BenchmarkSliceLen(b *testing.B) {
	for i := 0; i < b.N; i++ {
		sinkAll.RawInt = sourceAll.SliceAny.Len()
	}
}

func BenchmarkMapLen(b *testing.B) {
	for i := 0; i < b.N; i++ {
		sinkAll.RawInt = sourceAll.MapStringAny.Len()
	}
}

func BenchmarkStringLen(b *testing.B) {
	for i := 0; i < b.N; i++ {
		sinkAll.RawInt = sourceAll.String.Len()
	}
}

func BenchmarkArrayLen(b *testing.B) {
	for i := 0; i < b.N; i++ {
		sinkAll.RawInt = sourceAll.BytesArray.Len()
	}
}

func BenchmarkSliceCap(b *testing.B) {
	for i := 0; i < b.N; i++ {
		sinkAll.RawInt = sourceAll.SliceAny.Cap()
	}
}

func BenchmarkDeepEqual(b *testing.B) {
	for _, bb := range deepEqualPerfTests {
		b.Run(ValueOf(bb.x).Type().String(), func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				sink = DeepEqual(bb.x, bb.y)
			}
		})
	}
}

func BenchmarkMapsDeepEqual(b *testing.B) {
	m1 := map[int]int{
		1: 1, 2: 2,
	}
	m2 := map[int]int{
		1: 1, 2: 2,
	}
	for i := 0; i < b.N; i++ {
		DeepEqual(m1, m2)
	}
}

func BenchmarkIsZero(b *testing.B) {
	type Int4 struct {
		a, b, c, d int
	}
	type Int1024 struct {
		a [1024]int
	}
	type Int512 struct {
		a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11, a12, a13, a14, a15, a16 [16]S
	}
	s := struct {
		ArrayComparable      [4]T
		ArrayIncomparable    [4]_Complex
		StructComparable     T
		StructIncomparable   _Complex
		ArrayInt_4           [4]int
		ArrayInt_1024        [1024]int
		ArrayInt_1024_NoZero [1024]int
		Struct4Int           Int4
		ArrayStruct4Int_1024 [256]Int4
		ArrayChanInt_1024    [1024]chan int
		StructInt_512        Int512
	}{}
	s.ArrayInt_1024_NoZero[512] = 1
	source := ValueOf(s)

	for i := 0; i < source.NumField(); i++ {
		name := source.Type().Field(i).Name
		value := source.Field(i)
		b.Run(name, func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				sink = value.IsZero()
			}
		})
	}
}

func BenchmarkSetZero(b *testing.B) {
	source := ValueOf(new(struct {
		Bool      bool
		Int       int64
		Uint      uint64
		Float     float64
		Complex   complex128
		Array     [4]Value
		Chan      chan Value
		Func      func() Value
		Interface interface{ String() string }
		Map       map[string]Value
		Pointer   *Value
		Slice     []Value
		String    string
		Struct    Value
	})).Elem()

	for i := 0; i < source.NumField(); i++ {
		name := source.Type().Field(i).Name
		value := source.Field(i)
		zero := Zero(value.Type())
		b.Run(name+"/Direct", func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				value.SetZero()
			}
		})
		b.Run(name+"/CachedZero", func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				value.Set(zero)
			}
		})
		b.Run(name+"/NewZero", func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				value.Set(Zero(value.Type()))
			}
		})
	}
}

func BenchmarkSelect(b *testing.B) {
	channel := make(chan int)
	close(channel)
	var cases []SelectCase
	for i := 0; i < 8; i++ {
		cases = append(cases, SelectCase{
			Dir:  SelectRecv,
			Chan: ValueOf(channel),
		})
	}
	for _, numCases := range []int{1, 4, 8} {
		b.Run(strconv.Itoa(numCases), func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				_, _, _ = Select(cases[:numCases])
			}
		})
	}
}

func BenchmarkCall(b *testing.B) {
	fv := ValueOf(func(a, b string) {})
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		args := []Value{ValueOf("a"), ValueOf("b")}
		for pb.Next() {
			fv.Call(args)
		}
	})
}

type myint int64

func (i *myint) inc() {
	*i = *i + 1
}

func BenchmarkCallMethod(b *testing.B) {
	b.ReportAllocs()
	z := new(myint)

	v := ValueOf(z.inc)
	for i := 0; i < b.N; i++ {
		v.Call(nil)
	}
}

func BenchmarkCallArgCopy(b *testing.B) {
	byteArray := func(n int) Value {
		return Zero(ArrayOf(n, TypeOf(byte(0))))
	}
	sizes := [...]struct {
		fv  Value
		arg Value
	}{
		{ValueOf(func(a [128]byte) {}), byteArray(128)},
		{ValueOf(func(a [256]byte) {}), byteArray(256)},
		{ValueOf(func(a [1024]byte) {}), byteArray(1024)},
		{ValueOf(func(a [4096]byte) {}), byteArray(4096)},
		{ValueOf(func(a [65536]byte) {}), byteArray(65536)},
	}
	for _, size := range sizes {
		bench := func(b *testing.B) {
			args := []Value{size.arg}
			b.SetBytes(int64(size.arg.Len()))
			b.ResetTimer()
			b.RunParallel(func(pb *testing.PB) {
				for pb.Next() {
					size.fv.Call(args)
				}
			})
		}
		name := fmt.Sprintf("size=%v", size.arg.Len())
		b.Run(name, bench)
	}
}

func BenchmarkPtrTo(b *testing.B) {
	// Construct a type with a zero ptrToThis.
	type T struct{ int }
	t := SliceOf(TypeOf(T{}))
	ptrToThis := ValueOf(t).Elem().FieldByName("PtrToThis")
	if !ptrToThis.IsValid() {
		b.Skipf("%v has no ptrToThis field; was it removed from rtype?", t) // TODO fix this at top of refactoring
		// b.Fatalf("%v has no ptrToThis field; was it removed from rtype?", t)
	}
	if ptrToThis.Int() != 0 {
		b.Fatalf("%v.ptrToThis unexpectedly nonzero", t)
	}
	b.ResetTimer()

	// Now benchmark calling PointerTo on it: we'll have to hit the ptrMap cache on
	// every call.
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			PointerTo(t)
		}
	})
}

type B1 struct {
	X int
	Y int
	Z int
}

func BenchmarkFieldByName1(b *testing.B) {
	t := TypeOf(B1{})
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			t.FieldByName("Z")
		}
	})
}

func BenchmarkFieldByName2(b *testing.B) {
	t := TypeOf(S3{})
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			t.FieldByName("B")
		}
	})
}

func BenchmarkFieldByName3(b *testing.B) {
	t := TypeOf(R0{})
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			t.FieldByName("X")
		}
	})
}

type S struct {
	i1 int64
	i2 int64
}

func BenchmarkInterfaceBig(b *testing.B) {
	v := ValueOf(S{})
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			v.Interface()
		}
	})
	b.StopTimer()
}

func BenchmarkInterfaceSmall(b *testing.B) {
	v := ValueOf(int64(0))
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			v.Interface()
		}
	})
}

func BenchmarkNew(b *testing.B) {
	v := TypeOf(XM{})
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			New(v)
		}
	})
}

func BenchmarkMap(b *testing.B) {
	type V *int
	type S string
	value := ValueOf((V)(nil))
	stringKeys := []string{}
	mapOfStrings := map[string]V{}
	uint64Keys := []uint64{}
	mapOfUint64s := map[uint64]V{}
	userStringKeys := []S{}
	mapOfUserStrings := map[S]V{}
	for i := 0; i < 100; i++ {
		stringKey := fmt.Sprintf("key%d", i)
		stringKeys = append(stringKeys, stringKey)
		mapOfStrings[stringKey] = nil

		uint64Key := uint64(i)
		uint64Keys = append(uint64Keys, uint64Key)
		mapOfUint64s[uint64Key] = nil

		userStringKey := S(fmt.Sprintf("key%d", i))
		userStringKeys = append(userStringKeys, userStringKey)
		mapOfUserStrings[userStringKey] = nil
	}

	tests := []struct {
		label          string
		m, keys, value Value
	}{
		{"StringKeys", ValueOf(mapOfStrings), ValueOf(stringKeys), value},
		{"Uint64Keys", ValueOf(mapOfUint64s), ValueOf(uint64Keys), value},
		{"UserStringKeys", ValueOf(mapOfUserStrings), ValueOf(userStringKeys), value},
	}

	for _, tt := range tests {
		b.Run(tt.label, func(b *testing.B) {
			b.Run("MapIndex", func(b *testing.B) {
				b.ReportAllocs()
				for i := 0; i < b.N; i++ {
					for j := tt.keys.Len() - 1; j >= 0; j-- {
						tt.m.MapIndex(tt.keys.Index(j))
					}
				}
			})
			b.Run("SetMapIndex", func(b *testing.B) {
				b.ReportAllocs()
				for i := 0; i < b.N; i++ {
					for j := tt.keys.Len() - 1; j >= 0; j-- {
						tt.m.SetMapIndex(tt.keys.Index(j), tt.value)
					}
				}
			})
		})
	}
}

func BenchmarkMapIterNext(b *testing.B) {
	m := ValueOf(map[string]int{"a": 0, "b": 1, "c": 2, "d": 3})
	it := m.MapRange()
	for i := 0; i < b.N; i++ {
		for it.Next() {
		}
		it.Reset(m)
	}
}

"""



```