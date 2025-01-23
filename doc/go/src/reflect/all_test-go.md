Response:
The user wants to understand the functionality of the provided Go code snippet, which is part of the `reflect` package's test suite.

Here's a breakdown of the thought process to achieve the desired summary:

1. **Identify the Core Package:** The code starts with `package reflect_test` and imports the `reflect` package. This immediately signals that the primary focus is testing the functionalities of the `reflect` package.

2. **Recognize Test Functions:** The code defines several functions starting with `Test...`, such as `TestBool`, `TestTypes`, `TestSet`, etc. This is a common pattern in Go for writing unit tests. Each of these functions likely tests a specific aspect of the `reflect` package.

3. **Analyze Test Cases:** Within the test functions, there are variables like `typeTests` and `valueTests` which are slices of `pair` structs. These structs contain an instance of a type and its expected string representation. This suggests these tests are verifying the correct string representation of different Go types and values as reported by the `reflect` package.

4. **Look for Core `reflect` Operations:**  The code uses key functions from the `reflect` package like `ValueOf`, `TypeOf`, `Kind`, `Set`, `SetInt`, `SetString`, `Field`, `Elem`, `String`, `Interface`, `CanInt`, `CanUint`, `CanFloat`, `CanComplex`, `CanSet`, `Grow`, `Append`, `AppendSlice`, `Copy`, and `DeepEqual`. These functions represent the core capabilities of the `reflect` package – inspecting and manipulating Go types and values at runtime.

5. **Infer Functionality from Test Names:**  The names of the test functions provide strong hints about what's being tested:
    * `TestBool`: Likely tests reflection on boolean values.
    * `TestTypes`: Probably tests the `Type` information of various Go types.
    * `TestSet`:  Likely tests setting the values of reflected variables.
    * `TestSetValue`: Similar to `TestSet`, possibly focusing on setting using `ValueOf`.
    * `TestMapIterSet`:  Tests iterating and setting values in maps using reflection.
    * `TestCanIntUintFloatComplex`: Checks if reflected values can be interpreted as specific numeric types.
    * `TestCanSetField`: Tests if fields of a struct can be set via reflection.
    * `TestValueToString`:  Verifies the string representation of reflected values.
    * `TestArrayElemSet`: Tests setting elements in arrays and slices.
    * `TestPtrPointTo`, `TestPtrSetNil`, `TestMapSetNil`: Test reflection on pointers and maps, specifically setting them to nil.
    * `TestAll`: Seems like a more comprehensive test covering various type reflections.
    * `TestInterfaceGet`, `TestInterfaceValue`: Tests reflection on interface types.
    * `TestFunctionValue`: Tests reflection on function types.
    * `TestGrow`, `TestAppend`, `TestAppendSlice`, `TestCopy`, `TestCopyString`, `TestCopyArray`:  Test reflection operations related to slices and arrays (growing, appending, copying).
    * `TestDeepEqual`: Tests the `DeepEqual` function, which is part of the `reflect` package's utility for comparing values.
    * `TestTypeOf`: Verifies the `TypeOf` function.
    * `TestAlignment`: Checks the reported alignment of struct fields.

6. **Identify Supporting Structures:** The `pair` struct and the helper function `assert` and `valueToString` are used to structure the tests and compare results.

7. **Synthesize a Summary:** Based on the above observations, the primary function of this code snippet is to test various aspects of the Go `reflect` package. It focuses on verifying the correctness of type and value introspection, manipulation, and comparison for different Go data types.

8. **Structure the Answer:** Organize the findings into a clear and concise summary, mentioning the key areas of functionality being tested.
这是 `go/src/reflect/all_test.go` 文件的一部分，主要功能是 **对 Go 语言的 `reflect` 包进行全面的单元测试**。

具体来说，从提供的代码片段来看，它主要测试了以下 `reflect` 包的功能：

1. **基本类型反射:** 测试了对基本数据类型（如 `bool`、`int`、`uint`、`float`、`string`）的反射能力，包括获取类型信息和值信息。
2. **结构体反射:**  测试了对结构体的反射，包括获取字段信息（类型、名称、Tag）、访问和修改字段值。
3. **指针反射:** 测试了对指针的反射，包括获取指向的类型、设置指针指向的值（包括 `nil`）。
4. **数组和切片反射:** 测试了对数组和切片的反射，包括获取元素类型、访问和修改元素值、以及切片的增长、追加和复制操作。
5. **Map 反射:** 测试了对 Map 的反射，包括获取 Key 和 Value 的类型、遍历 Map、设置 Map 的值（包括 `nil`）。
6. **Channel 反射:** 测试了对 Channel 的反射，主要是获取 Channel 的类型信息。
7. **函数反射:** 测试了对函数的反射，主要是获取函数的类型信息和比较函数的值。
8. **Interface 反射:** 测试了对 Interface 的反射，包括获取 Interface 中存储的具体类型和值。
9. **类型字符串表示:**  测试了 `reflect.Type` 的 `String()` 方法，确保能正确返回各种类型的字符串表示。
10. **值的字符串表示:** 测试了一个自定义的 `valueToString` 函数（虽然代码中没有完整展示，但可以推断出其功能），用于将 `reflect.Value` 转换为字符串以便进行比较。
11. **`CanInt`, `CanUint`, `CanFloat`, `CanComplex` 方法:** 测试了 `reflect.Value` 的这些方法，用于判断 Value 是否能转换为特定的数值类型。
12. **`CanSet` 方法:** 测试了 `reflect.Value` 的 `CanSet` 方法，用于判断 Value 是否可以被设置。
13. **`DeepEqual` 函数:** 测试了 `reflect.DeepEqual` 函数，用于深度比较两个值是否相等，包括对循环引用的处理。
14. **`TypeOf` 函数:** 测试了 `reflect.TypeOf` 函数，用于获取值的类型信息。
15. **结构体内存对齐:** 测试了 `reflect` 包获取结构体字段偏移量的准确性，以验证结构体内存对齐是否与预期一致。

**可以推理出它是什么 go 语言功能的实现：**

这段代码主要测试的是 Go 语言的 **反射 (Reflection)** 功能的实现。反射是指在程序运行时检查和修改程序自身结构的能力，包括类型信息、值信息等。

**go 代码举例说明：**

假设我们要测试 `reflect.ValueOf` 和 `reflect.TypeOf` 函数对于结构体的处理：

```go
package main

import (
	"fmt"
	"reflect"
)

type MyStruct struct {
	Name string
	Age  int
}

func main() {
	s := MyStruct{"Alice", 30}

	// 使用 reflect.ValueOf 获取 s 的 Value
	v := reflect.ValueOf(s)
	fmt.Println("Value:", v) // Output: Value: {Alice 30}

	// 使用 reflect.TypeOf 获取 s 的 Type
	t := reflect.TypeOf(s)
	fmt.Println("Type:", t) // Output: Type: main.MyStruct

	// 访问结构体字段
	nameField := v.FieldByName("Name")
	fmt.Println("Name Field Value:", nameField) // Output: Name Field Value: Alice
	fmt.Println("Name Field Type:", nameField.Type()) // Output: Name Field Type: string

	ageField := v.FieldByName("Age")
	fmt.Println("Age Field Value:", ageField) // Output: Age Field Value: 30
	fmt.Println("Age Field Type:", ageField.Type())   // Output: Age Field Type: int
}
```

**假设的输入与输出（针对 `TestTypes` 函数）：**

**假设输入 `typeTests` 的其中一个元素：**

```go
{struct{ x int }{}, "int"},
```

**输出：**

测试代码会获取 `struct{ x int }` 类型中字段 `x` 的类型，并将其字符串表示与 `"int"` 进行比较。如果相等，则该测试用例通过。

**命令行参数的具体处理：**

这段代码片段中没有直接处理命令行参数的逻辑。但是，它引入了 `flag` 包，这表明在整个 `all_test.go` 文件中可能存在通过命令行参数控制测试行为的情况。例如，可能存在控制运行哪些测试用例、设置测试超时时间等参数。  如果存在命令行参数处理，通常会在 `init()` 函数或者 `TestMain` 函数中进行解析。 由于只提供了部分代码，无法确定具体的命令行参数处理方式。

**使用者易犯错的点：**

从提供的代码来看，没有直接体现使用者易犯错的点。 但是，基于 `reflect` 包的使用经验，一些常见的错误包括：

* **对不可导出的字段进行操作:** 尝试获取或设置结构体中未导出的字段的值会导致 panic。
* **对不可设置的 Value 进行 Set 操作:** 例如，对一个非指针的结构体 Value 调用 `Set` 方法会 panic。需要先通过 `Addr()` 获取指针，再通过 `Elem()` 获取可设置的 Value。
* **类型断言错误:** 在使用 `Interface()` 方法后，需要进行正确的类型断言才能将 `interface{}` 转换为具体类型。如果断言的类型不匹配，会导致 panic。
* **性能问题:** 过度使用反射会带来性能损耗，因为反射操作涉及到运行时的类型检查和查找。

**功能归纳：**

这段 `go/src/reflect/all_test.go` 的代码片段的主要功能是 **测试 Go 语言 `reflect` 包中关于类型信息获取、值信息获取与修改、以及类型比较等核心功能的正确性。** 它通过定义一系列的测试用例，覆盖了各种 Go 语言类型的反射场景，确保 `reflect` 包的各项功能能够按照预期工作。

### 提示词
```
这是路径为go/src/reflect/all_test.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第1部分，共7部分，请归纳一下它的功能
```

### 源代码
```go
// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package reflect_test

import (
	"bytes"
	"encoding/base64"
	"flag"
	"fmt"
	"go/token"
	"internal/asan"
	"internal/goarch"
	"internal/goexperiment"
	"internal/testenv"
	"io"
	"math"
	"math/rand"
	"net"
	"os"
	. "reflect"
	"reflect/internal/example1"
	"reflect/internal/example2"
	"runtime"
	"runtime/debug"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
	"unsafe"
)

var sink any

func TestBool(t *testing.T) {
	v := ValueOf(true)
	if v.Bool() != true {
		t.Fatal("ValueOf(true).Bool() = false")
	}
}

type integer int
type T struct {
	a int
	b float64
	c string
	d *int
}

var _ = T{} == T{} // tests depend on T being comparable

type pair struct {
	i any
	s string
}

func assert(t *testing.T, s, want string) {
	if s != want {
		t.Errorf("have %#q want %#q", s, want)
	}
}

var typeTests = []pair{
	{struct{ x int }{}, "int"},
	{struct{ x int8 }{}, "int8"},
	{struct{ x int16 }{}, "int16"},
	{struct{ x int32 }{}, "int32"},
	{struct{ x int64 }{}, "int64"},
	{struct{ x uint }{}, "uint"},
	{struct{ x uint8 }{}, "uint8"},
	{struct{ x uint16 }{}, "uint16"},
	{struct{ x uint32 }{}, "uint32"},
	{struct{ x uint64 }{}, "uint64"},
	{struct{ x float32 }{}, "float32"},
	{struct{ x float64 }{}, "float64"},
	{struct{ x int8 }{}, "int8"},
	{struct{ x (**int8) }{}, "**int8"},
	{struct{ x (**integer) }{}, "**reflect_test.integer"},
	{struct{ x ([32]int32) }{}, "[32]int32"},
	{struct{ x ([]int8) }{}, "[]int8"},
	{struct{ x (map[string]int32) }{}, "map[string]int32"},
	{struct{ x (chan<- string) }{}, "chan<- string"},
	{struct{ x (chan<- chan string) }{}, "chan<- chan string"},
	{struct{ x (chan<- <-chan string) }{}, "chan<- <-chan string"},
	{struct{ x (<-chan <-chan string) }{}, "<-chan <-chan string"},
	{struct{ x (chan (<-chan string)) }{}, "chan (<-chan string)"},
	{struct {
		x struct {
			c chan *int32
			d float32
		}
	}{},
		"struct { c chan *int32; d float32 }",
	},
	{struct{ x (func(a int8, b int32)) }{}, "func(int8, int32)"},
	{struct {
		x struct {
			c func(chan *integer, *int8)
		}
	}{},
		"struct { c func(chan *reflect_test.integer, *int8) }",
	},
	{struct {
		x struct {
			a int8
			b int32
		}
	}{},
		"struct { a int8; b int32 }",
	},
	{struct {
		x struct {
			a int8
			b int8
			c int32
		}
	}{},
		"struct { a int8; b int8; c int32 }",
	},
	{struct {
		x struct {
			a int8
			b int8
			c int8
			d int32
		}
	}{},
		"struct { a int8; b int8; c int8; d int32 }",
	},
	{struct {
		x struct {
			a int8
			b int8
			c int8
			d int8
			e int32
		}
	}{},
		"struct { a int8; b int8; c int8; d int8; e int32 }",
	},
	{struct {
		x struct {
			a int8
			b int8
			c int8
			d int8
			e int8
			f int32
		}
	}{},
		"struct { a int8; b int8; c int8; d int8; e int8; f int32 }",
	},
	{struct {
		x struct {
			a int8 `reflect:"hi there"`
		}
	}{},
		`struct { a int8 "reflect:\"hi there\"" }`,
	},
	{struct {
		x struct {
			a int8 `reflect:"hi \x00there\t\n\"\\"`
		}
	}{},
		`struct { a int8 "reflect:\"hi \\x00there\\t\\n\\\"\\\\\"" }`,
	},
	{struct {
		x struct {
			f func(args ...int)
		}
	}{},
		"struct { f func(...int) }",
	},
	{struct {
		x (interface {
			a(func(func(int) int) func(func(int)) int)
			b()
		})
	}{},
		"interface { reflect_test.a(func(func(int) int) func(func(int)) int); reflect_test.b() }",
	},
	{struct {
		x struct {
			int32
			int64
		}
	}{},
		"struct { int32; int64 }",
	},
}

var valueTests = []pair{
	{new(int), "132"},
	{new(int8), "8"},
	{new(int16), "16"},
	{new(int32), "32"},
	{new(int64), "64"},
	{new(uint), "132"},
	{new(uint8), "8"},
	{new(uint16), "16"},
	{new(uint32), "32"},
	{new(uint64), "64"},
	{new(float32), "256.25"},
	{new(float64), "512.125"},
	{new(complex64), "532.125+10i"},
	{new(complex128), "564.25+1i"},
	{new(string), "stringy cheese"},
	{new(bool), "true"},
	{new(*int8), "*int8(0)"},
	{new(**int8), "**int8(0)"},
	{new([5]int32), "[5]int32{0, 0, 0, 0, 0}"},
	{new(**integer), "**reflect_test.integer(0)"},
	{new(map[string]int32), "map[string]int32{<can't iterate on maps>}"},
	{new(chan<- string), "chan<- string"},
	{new(func(a int8, b int32)), "func(int8, int32)(0)"},
	{new(struct {
		c chan *int32
		d float32
	}),
		"struct { c chan *int32; d float32 }{chan *int32, 0}",
	},
	{new(struct{ c func(chan *integer, *int8) }),
		"struct { c func(chan *reflect_test.integer, *int8) }{func(chan *reflect_test.integer, *int8)(0)}",
	},
	{new(struct {
		a int8
		b int32
	}),
		"struct { a int8; b int32 }{0, 0}",
	},
	{new(struct {
		a int8
		b int8
		c int32
	}),
		"struct { a int8; b int8; c int32 }{0, 0, 0}",
	},
}

func testType(t *testing.T, i int, typ Type, want string) {
	s := typ.String()
	if s != want {
		t.Errorf("#%d: have %#q, want %#q", i, s, want)
	}
}

func TestTypes(t *testing.T) {
	for i, tt := range typeTests {
		testType(t, i, ValueOf(tt.i).Field(0).Type(), tt.s)
	}
}

func TestSet(t *testing.T) {
	for i, tt := range valueTests {
		v := ValueOf(tt.i)
		v = v.Elem()
		switch v.Kind() {
		case Int:
			v.SetInt(132)
		case Int8:
			v.SetInt(8)
		case Int16:
			v.SetInt(16)
		case Int32:
			v.SetInt(32)
		case Int64:
			v.SetInt(64)
		case Uint:
			v.SetUint(132)
		case Uint8:
			v.SetUint(8)
		case Uint16:
			v.SetUint(16)
		case Uint32:
			v.SetUint(32)
		case Uint64:
			v.SetUint(64)
		case Float32:
			v.SetFloat(256.25)
		case Float64:
			v.SetFloat(512.125)
		case Complex64:
			v.SetComplex(532.125 + 10i)
		case Complex128:
			v.SetComplex(564.25 + 1i)
		case String:
			v.SetString("stringy cheese")
		case Bool:
			v.SetBool(true)
		}
		s := valueToString(v)
		if s != tt.s {
			t.Errorf("#%d: have %#q, want %#q", i, s, tt.s)
		}
	}
}

func TestSetValue(t *testing.T) {
	for i, tt := range valueTests {
		v := ValueOf(tt.i).Elem()
		switch v.Kind() {
		case Int:
			v.Set(ValueOf(int(132)))
		case Int8:
			v.Set(ValueOf(int8(8)))
		case Int16:
			v.Set(ValueOf(int16(16)))
		case Int32:
			v.Set(ValueOf(int32(32)))
		case Int64:
			v.Set(ValueOf(int64(64)))
		case Uint:
			v.Set(ValueOf(uint(132)))
		case Uint8:
			v.Set(ValueOf(uint8(8)))
		case Uint16:
			v.Set(ValueOf(uint16(16)))
		case Uint32:
			v.Set(ValueOf(uint32(32)))
		case Uint64:
			v.Set(ValueOf(uint64(64)))
		case Float32:
			v.Set(ValueOf(float32(256.25)))
		case Float64:
			v.Set(ValueOf(512.125))
		case Complex64:
			v.Set(ValueOf(complex64(532.125 + 10i)))
		case Complex128:
			v.Set(ValueOf(complex128(564.25 + 1i)))
		case String:
			v.Set(ValueOf("stringy cheese"))
		case Bool:
			v.Set(ValueOf(true))
		}
		s := valueToString(v)
		if s != tt.s {
			t.Errorf("#%d: have %#q, want %#q", i, s, tt.s)
		}
	}
}

func TestMapIterSet(t *testing.T) {
	m := make(map[string]any, len(valueTests))
	for _, tt := range valueTests {
		m[tt.s] = tt.i
	}
	v := ValueOf(m)

	k := New(v.Type().Key()).Elem()
	e := New(v.Type().Elem()).Elem()

	iter := v.MapRange()
	for iter.Next() {
		k.SetIterKey(iter)
		e.SetIterValue(iter)
		want := m[k.String()]
		got := e.Interface()
		if got != want {
			t.Errorf("%q: want (%T) %v, got (%T) %v", k.String(), want, want, got, got)
		}
		if setkey, key := valueToString(k), valueToString(iter.Key()); setkey != key {
			t.Errorf("MapIter.Key() = %q, MapIter.SetKey() = %q", key, setkey)
		}
		if setval, val := valueToString(e), valueToString(iter.Value()); setval != val {
			t.Errorf("MapIter.Value() = %q, MapIter.SetValue() = %q", val, setval)
		}
	}

	if testenv.OptimizationOff() {
		return // no inlining with the noopt builder
	}

	got := int(testing.AllocsPerRun(10, func() {
		iter := v.MapRange()
		for iter.Next() {
			k.SetIterKey(iter)
			e.SetIterValue(iter)
		}
	}))
	// Calling MapRange should not allocate even though it returns a *MapIter.
	// The function is inlineable, so if the local usage does not escape
	// the *MapIter, it can remain stack allocated.
	want := 0
	if got != want {
		t.Errorf("wanted %d alloc, got %d", want, got)
	}
}

func TestCanIntUintFloatComplex(t *testing.T) {
	type integer int
	type uinteger uint
	type float float64
	type complex complex128

	var ops = [...]string{"CanInt", "CanUint", "CanFloat", "CanComplex"}

	var testCases = []struct {
		i    any
		want [4]bool
	}{
		// signed integer
		{132, [...]bool{true, false, false, false}},
		{int8(8), [...]bool{true, false, false, false}},
		{int16(16), [...]bool{true, false, false, false}},
		{int32(32), [...]bool{true, false, false, false}},
		{int64(64), [...]bool{true, false, false, false}},
		// unsigned integer
		{uint(132), [...]bool{false, true, false, false}},
		{uint8(8), [...]bool{false, true, false, false}},
		{uint16(16), [...]bool{false, true, false, false}},
		{uint32(32), [...]bool{false, true, false, false}},
		{uint64(64), [...]bool{false, true, false, false}},
		{uintptr(0xABCD), [...]bool{false, true, false, false}},
		// floating-point
		{float32(256.25), [...]bool{false, false, true, false}},
		{float64(512.125), [...]bool{false, false, true, false}},
		// complex
		{complex64(532.125 + 10i), [...]bool{false, false, false, true}},
		{complex128(564.25 + 1i), [...]bool{false, false, false, true}},
		// underlying
		{integer(-132), [...]bool{true, false, false, false}},
		{uinteger(132), [...]bool{false, true, false, false}},
		{float(256.25), [...]bool{false, false, true, false}},
		{complex(532.125 + 10i), [...]bool{false, false, false, true}},
		// not-acceptable
		{"hello world", [...]bool{false, false, false, false}},
		{new(int), [...]bool{false, false, false, false}},
		{new(uint), [...]bool{false, false, false, false}},
		{new(float64), [...]bool{false, false, false, false}},
		{new(complex64), [...]bool{false, false, false, false}},
		{new([5]int), [...]bool{false, false, false, false}},
		{new(integer), [...]bool{false, false, false, false}},
		{new(map[int]int), [...]bool{false, false, false, false}},
		{new(chan<- int), [...]bool{false, false, false, false}},
		{new(func(a int8)), [...]bool{false, false, false, false}},
		{new(struct{ i int }), [...]bool{false, false, false, false}},
	}

	for i, tc := range testCases {
		v := ValueOf(tc.i)
		got := [...]bool{v.CanInt(), v.CanUint(), v.CanFloat(), v.CanComplex()}

		for j := range tc.want {
			if got[j] != tc.want[j] {
				t.Errorf(
					"#%d: v.%s() returned %t for type %T, want %t",
					i,
					ops[j],
					got[j],
					tc.i,
					tc.want[j],
				)
			}
		}
	}
}

func TestCanSetField(t *testing.T) {
	type embed struct{ x, X int }
	type Embed struct{ x, X int }
	type S1 struct {
		embed
		x, X int
	}
	type S2 struct {
		*embed
		x, X int
	}
	type S3 struct {
		Embed
		x, X int
	}
	type S4 struct {
		*Embed
		x, X int
	}

	type testCase struct {
		// -1 means Addr().Elem() of current value
		index  []int
		canSet bool
	}
	tests := []struct {
		val   Value
		cases []testCase
	}{{
		val: ValueOf(&S1{}),
		cases: []testCase{
			{[]int{0}, false},
			{[]int{0, -1}, false},
			{[]int{0, 0}, false},
			{[]int{0, 0, -1}, false},
			{[]int{0, -1, 0}, false},
			{[]int{0, -1, 0, -1}, false},
			{[]int{0, 1}, true},
			{[]int{0, 1, -1}, true},
			{[]int{0, -1, 1}, true},
			{[]int{0, -1, 1, -1}, true},
			{[]int{1}, false},
			{[]int{1, -1}, false},
			{[]int{2}, true},
			{[]int{2, -1}, true},
		},
	}, {
		val: ValueOf(&S2{embed: &embed{}}),
		cases: []testCase{
			{[]int{0}, false},
			{[]int{0, -1}, false},
			{[]int{0, 0}, false},
			{[]int{0, 0, -1}, false},
			{[]int{0, -1, 0}, false},
			{[]int{0, -1, 0, -1}, false},
			{[]int{0, 1}, true},
			{[]int{0, 1, -1}, true},
			{[]int{0, -1, 1}, true},
			{[]int{0, -1, 1, -1}, true},
			{[]int{1}, false},
			{[]int{2}, true},
		},
	}, {
		val: ValueOf(&S3{}),
		cases: []testCase{
			{[]int{0}, true},
			{[]int{0, -1}, true},
			{[]int{0, 0}, false},
			{[]int{0, 0, -1}, false},
			{[]int{0, -1, 0}, false},
			{[]int{0, -1, 0, -1}, false},
			{[]int{0, 1}, true},
			{[]int{0, 1, -1}, true},
			{[]int{0, -1, 1}, true},
			{[]int{0, -1, 1, -1}, true},
			{[]int{1}, false},
			{[]int{2}, true},
		},
	}, {
		val: ValueOf(&S4{Embed: &Embed{}}),
		cases: []testCase{
			{[]int{0}, true},
			{[]int{0, -1}, true},
			{[]int{0, 0}, false},
			{[]int{0, 0, -1}, false},
			{[]int{0, -1, 0}, false},
			{[]int{0, -1, 0, -1}, false},
			{[]int{0, 1}, true},
			{[]int{0, 1, -1}, true},
			{[]int{0, -1, 1}, true},
			{[]int{0, -1, 1, -1}, true},
			{[]int{1}, false},
			{[]int{2}, true},
		},
	}}

	for _, tt := range tests {
		t.Run(tt.val.Type().Name(), func(t *testing.T) {
			for _, tc := range tt.cases {
				f := tt.val
				for _, i := range tc.index {
					if f.Kind() == Pointer {
						f = f.Elem()
					}
					if i == -1 {
						f = f.Addr().Elem()
					} else {
						f = f.Field(i)
					}
				}
				if got := f.CanSet(); got != tc.canSet {
					t.Errorf("CanSet() = %v, want %v", got, tc.canSet)
				}
			}
		})
	}
}

var _i = 7

var valueToStringTests = []pair{
	{123, "123"},
	{123.5, "123.5"},
	{byte(123), "123"},
	{"abc", "abc"},
	{T{123, 456.75, "hello", &_i}, "reflect_test.T{123, 456.75, hello, *int(&7)}"},
	{new(chan *T), "*chan *reflect_test.T(&chan *reflect_test.T)"},
	{[10]int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}, "[10]int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}"},
	{&[10]int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}, "*[10]int(&[10]int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10})"},
	{[]int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}, "[]int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}"},
	{&[]int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}, "*[]int(&[]int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10})"},
}

func TestValueToString(t *testing.T) {
	for i, test := range valueToStringTests {
		s := valueToString(ValueOf(test.i))
		if s != test.s {
			t.Errorf("#%d: have %#q, want %#q", i, s, test.s)
		}
	}
}

func TestArrayElemSet(t *testing.T) {
	v := ValueOf(&[10]int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}).Elem()
	v.Index(4).SetInt(123)
	s := valueToString(v)
	const want = "[10]int{1, 2, 3, 4, 123, 6, 7, 8, 9, 10}"
	if s != want {
		t.Errorf("[10]int: have %#q want %#q", s, want)
	}

	v = ValueOf([]int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10})
	v.Index(4).SetInt(123)
	s = valueToString(v)
	const want1 = "[]int{1, 2, 3, 4, 123, 6, 7, 8, 9, 10}"
	if s != want1 {
		t.Errorf("[]int: have %#q want %#q", s, want1)
	}
}

func TestPtrPointTo(t *testing.T) {
	var ip *int32
	var i int32 = 1234
	vip := ValueOf(&ip)
	vi := ValueOf(&i).Elem()
	vip.Elem().Set(vi.Addr())
	if *ip != 1234 {
		t.Errorf("got %d, want 1234", *ip)
	}

	ip = nil
	vp := ValueOf(&ip).Elem()
	vp.Set(Zero(vp.Type()))
	if ip != nil {
		t.Errorf("got non-nil (%p), want nil", ip)
	}
}

func TestPtrSetNil(t *testing.T) {
	var i int32 = 1234
	ip := &i
	vip := ValueOf(&ip)
	vip.Elem().Set(Zero(vip.Elem().Type()))
	if ip != nil {
		t.Errorf("got non-nil (%d), want nil", *ip)
	}
}

func TestMapSetNil(t *testing.T) {
	m := make(map[string]int)
	vm := ValueOf(&m)
	vm.Elem().Set(Zero(vm.Elem().Type()))
	if m != nil {
		t.Errorf("got non-nil (%p), want nil", m)
	}
}

func TestAll(t *testing.T) {
	testType(t, 1, TypeOf((int8)(0)), "int8")
	testType(t, 2, TypeOf((*int8)(nil)).Elem(), "int8")

	typ := TypeOf((*struct {
		c chan *int32
		d float32
	})(nil))
	testType(t, 3, typ, "*struct { c chan *int32; d float32 }")
	etyp := typ.Elem()
	testType(t, 4, etyp, "struct { c chan *int32; d float32 }")
	styp := etyp
	f := styp.Field(0)
	testType(t, 5, f.Type, "chan *int32")

	f, present := styp.FieldByName("d")
	if !present {
		t.Errorf("FieldByName says present field is absent")
	}
	testType(t, 6, f.Type, "float32")

	f, present = styp.FieldByName("absent")
	if present {
		t.Errorf("FieldByName says absent field is present")
	}

	typ = TypeOf([32]int32{})
	testType(t, 7, typ, "[32]int32")
	testType(t, 8, typ.Elem(), "int32")

	typ = TypeOf((map[string]*int32)(nil))
	testType(t, 9, typ, "map[string]*int32")
	mtyp := typ
	testType(t, 10, mtyp.Key(), "string")
	testType(t, 11, mtyp.Elem(), "*int32")

	typ = TypeOf((chan<- string)(nil))
	testType(t, 12, typ, "chan<- string")
	testType(t, 13, typ.Elem(), "string")

	// make sure tag strings are not part of element type
	typ = TypeOf(struct {
		d []uint32 `reflect:"TAG"`
	}{}).Field(0).Type
	testType(t, 14, typ, "[]uint32")
}

func TestInterfaceGet(t *testing.T) {
	var inter struct {
		E any
	}
	inter.E = 123.456
	v1 := ValueOf(&inter)
	v2 := v1.Elem().Field(0)
	assert(t, v2.Type().String(), "interface {}")
	i2 := v2.Interface()
	v3 := ValueOf(i2)
	assert(t, v3.Type().String(), "float64")
}

func TestInterfaceValue(t *testing.T) {
	var inter struct {
		E any
	}
	inter.E = 123.456
	v1 := ValueOf(&inter)
	v2 := v1.Elem().Field(0)
	assert(t, v2.Type().String(), "interface {}")
	v3 := v2.Elem()
	assert(t, v3.Type().String(), "float64")

	i3 := v2.Interface()
	if _, ok := i3.(float64); !ok {
		t.Error("v2.Interface() did not return float64, got ", TypeOf(i3))
	}
}

func TestFunctionValue(t *testing.T) {
	var x any = func() {}
	v := ValueOf(x)
	if fmt.Sprint(v.Interface()) != fmt.Sprint(x) {
		t.Fatalf("TestFunction returned wrong pointer")
	}
	assert(t, v.Type().String(), "func()")
}

func TestGrow(t *testing.T) {
	v := ValueOf([]int(nil))
	shouldPanic("reflect.Value.Grow using unaddressable value", func() { v.Grow(0) })
	v = ValueOf(new([]int)).Elem()
	v.Grow(0)
	if !v.IsNil() {
		t.Errorf("v.Grow(0) should still be nil")
	}
	v.Grow(1)
	if v.Cap() == 0 {
		t.Errorf("v.Cap = %v, want non-zero", v.Cap())
	}
	want := v.UnsafePointer()
	v.Grow(1)
	got := v.UnsafePointer()
	if got != want {
		t.Errorf("noop v.Grow should not change pointers")
	}

	t.Run("Append", func(t *testing.T) {
		var got, want []T
		v := ValueOf(&got).Elem()
		appendValue := func(vt T) {
			v.Grow(1)
			v.SetLen(v.Len() + 1)
			v.Index(v.Len() - 1).Set(ValueOf(vt))
		}
		for i := 0; i < 10; i++ {
			vt := T{i, float64(i), strconv.Itoa(i), &i}
			appendValue(vt)
			want = append(want, vt)
		}
		if !DeepEqual(got, want) {
			t.Errorf("value mismatch:\ngot  %v\nwant %v", got, want)
		}
	})

	t.Run("Rate", func(t *testing.T) {
		var b []byte
		v := ValueOf(new([]byte)).Elem()
		for i := 0; i < 10; i++ {
			b = append(b[:cap(b)], make([]byte, 1)...)
			v.SetLen(v.Cap())
			v.Grow(1)
			if v.Cap() != cap(b) {
				t.Errorf("v.Cap = %v, want %v", v.Cap(), cap(b))
			}
		}
	})

	t.Run("ZeroCapacity", func(t *testing.T) {
		for i := 0; i < 10; i++ {
			v := ValueOf(new([]byte)).Elem()
			v.Grow(61)
			b := v.Bytes()
			b = b[:cap(b)]
			for i, c := range b {
				if c != 0 {
					t.Fatalf("Value.Bytes[%d] = 0x%02x, want 0x00", i, c)
				}
				b[i] = 0xff
			}
			runtime.GC()
		}
	})
}

var appendTests = []struct {
	orig, extra []int
}{
	{nil, nil},
	{[]int{}, nil},
	{nil, []int{}},
	{[]int{}, []int{}},
	{nil, []int{22}},
	{[]int{}, []int{22}},
	{make([]int, 2, 4), nil},
	{make([]int, 2, 4), []int{}},
	{make([]int, 2, 4), []int{22}},
	{make([]int, 2, 4), []int{22, 33, 44}},
}

func TestAppend(t *testing.T) {
	for i, test := range appendTests {
		origLen, extraLen := len(test.orig), len(test.extra)
		want := append(test.orig, test.extra...)
		// Convert extra from []int to []Value.
		e0 := make([]Value, len(test.extra))
		for j, e := range test.extra {
			e0[j] = ValueOf(e)
		}
		// Convert extra from []int to *SliceValue.
		e1 := ValueOf(test.extra)

		// Test Append.
		a0 := ValueOf(&test.orig).Elem()
		have0 := Append(a0, e0...)
		if have0.CanAddr() {
			t.Errorf("Append #%d: have slice should not be addressable", i)
		}
		if !DeepEqual(have0.Interface(), want) {
			t.Errorf("Append #%d: have %v, want %v (%p %p)", i, have0, want, test.orig, have0.Interface())
		}
		// Check that the orig and extra slices were not modified.
		if a0.Len() != len(test.orig) {
			t.Errorf("Append #%d: a0.Len: have %d, want %d", i, a0.Len(), origLen)
		}
		if len(test.orig) != origLen {
			t.Errorf("Append #%d origLen: have %v, want %v", i, len(test.orig), origLen)
		}
		if len(test.extra) != extraLen {
			t.Errorf("Append #%d extraLen: have %v, want %v", i, len(test.extra), extraLen)
		}

		// Test AppendSlice.
		a1 := ValueOf(&test.orig).Elem()
		have1 := AppendSlice(a1, e1)
		if have1.CanAddr() {
			t.Errorf("AppendSlice #%d: have slice should not be addressable", i)
		}
		if !DeepEqual(have1.Interface(), want) {
			t.Errorf("AppendSlice #%d: have %v, want %v", i, have1, want)
		}
		// Check that the orig and extra slices were not modified.
		if a1.Len() != len(test.orig) {
			t.Errorf("AppendSlice #%d: a1.Len: have %d, want %d", i, a0.Len(), origLen)
		}
		if len(test.orig) != origLen {
			t.Errorf("AppendSlice #%d origLen: have %v, want %v", i, len(test.orig), origLen)
		}
		if len(test.extra) != extraLen {
			t.Errorf("AppendSlice #%d extraLen: have %v, want %v", i, len(test.extra), extraLen)
		}

		// Test Append and AppendSlice with unexported value.
		ax := ValueOf(struct{ x []int }{test.orig}).Field(0)
		shouldPanic("using unexported field", func() { Append(ax, e0...) })
		shouldPanic("using unexported field", func() { AppendSlice(ax, e1) })
	}
}

func TestCopy(t *testing.T) {
	a := []int{1, 2, 3, 4, 10, 9, 8, 7}
	b := []int{11, 22, 33, 44, 1010, 99, 88, 77, 66, 55, 44}
	c := []int{11, 22, 33, 44, 1010, 99, 88, 77, 66, 55, 44}
	for i := 0; i < len(b); i++ {
		if b[i] != c[i] {
			t.Fatalf("b != c before test")
		}
	}
	a1 := a
	b1 := b
	aa := ValueOf(&a1).Elem()
	ab := ValueOf(&b1).Elem()
	for tocopy := 1; tocopy <= 7; tocopy++ {
		aa.SetLen(tocopy)
		Copy(ab, aa)
		aa.SetLen(8)
		for i := 0; i < tocopy; i++ {
			if a[i] != b[i] {
				t.Errorf("(i) tocopy=%d a[%d]=%d, b[%d]=%d",
					tocopy, i, a[i], i, b[i])
			}
		}
		for i := tocopy; i < len(b); i++ {
			if b[i] != c[i] {
				if i < len(a) {
					t.Errorf("(ii) tocopy=%d a[%d]=%d, b[%d]=%d, c[%d]=%d",
						tocopy, i, a[i], i, b[i], i, c[i])
				} else {
					t.Errorf("(iii) tocopy=%d b[%d]=%d, c[%d]=%d",
						tocopy, i, b[i], i, c[i])
				}
			} else {
				t.Logf("tocopy=%d elem %d is okay\n", tocopy, i)
			}
		}
	}
}

func TestCopyString(t *testing.T) {
	t.Run("Slice", func(t *testing.T) {
		s := bytes.Repeat([]byte{'_'}, 8)
		val := ValueOf(s)

		n := Copy(val, ValueOf(""))
		if expecting := []byte("________"); n != 0 || !bytes.Equal(s, expecting) {
			t.Errorf("got n = %d, s = %s, expecting n = 0, s = %s", n, s, expecting)
		}

		n = Copy(val, ValueOf("hello"))
		if expecting := []byte("hello___"); n != 5 || !bytes.Equal(s, expecting) {
			t.Errorf("got n = %d, s = %s, expecting n = 5, s = %s", n, s, expecting)
		}

		n = Copy(val, ValueOf("helloworld"))
		if expecting := []byte("hellowor"); n != 8 || !bytes.Equal(s, expecting) {
			t.Errorf("got n = %d, s = %s, expecting n = 8, s = %s", n, s, expecting)
		}
	})
	t.Run("Array", func(t *testing.T) {
		s := [...]byte{'_', '_', '_', '_', '_', '_', '_', '_'}
		val := ValueOf(&s).Elem()

		n := Copy(val, ValueOf(""))
		if expecting := []byte("________"); n != 0 || !bytes.Equal(s[:], expecting) {
			t.Errorf("got n = %d, s = %s, expecting n = 0, s = %s", n, s[:], expecting)
		}

		n = Copy(val, ValueOf("hello"))
		if expecting := []byte("hello___"); n != 5 || !bytes.Equal(s[:], expecting) {
			t.Errorf("got n = %d, s = %s, expecting n = 5, s = %s", n, s[:], expecting)
		}

		n = Copy(val, ValueOf("helloworld"))
		if expecting := []byte("hellowor"); n != 8 || !bytes.Equal(s[:], expecting) {
			t.Errorf("got n = %d, s = %s, expecting n = 8, s = %s", n, s[:], expecting)
		}
	})
}

func TestCopyArray(t *testing.T) {
	a := [8]int{1, 2, 3, 4, 10, 9, 8, 7}
	b := [11]int{11, 22, 33, 44, 1010, 99, 88, 77, 66, 55, 44}
	c := b
	aa := ValueOf(&a).Elem()
	ab := ValueOf(&b).Elem()
	Copy(ab, aa)
	for i := 0; i < len(a); i++ {
		if a[i] != b[i] {
			t.Errorf("(i) a[%d]=%d, b[%d]=%d", i, a[i], i, b[i])
		}
	}
	for i := len(a); i < len(b); i++ {
		if b[i] != c[i] {
			t.Errorf("(ii) b[%d]=%d, c[%d]=%d", i, b[i], i, c[i])
		} else {
			t.Logf("elem %d is okay\n", i)
		}
	}
}

func TestBigUnnamedStruct(t *testing.T) {
	b := struct{ a, b, c, d int64 }{1, 2, 3, 4}
	v := ValueOf(b)
	b1 := v.Interface().(struct {
		a, b, c, d int64
	})
	if b1.a != b.a || b1.b != b.b || b1.c != b.c || b1.d != b.d {
		t.Errorf("ValueOf(%v).Interface().(*Big) = %v", b, b1)
	}
}

type big struct {
	a, b, c, d, e int64
}

func TestBigStruct(t *testing.T) {
	b := big{1, 2, 3, 4, 5}
	v := ValueOf(b)
	b1 := v.Interface().(big)
	if b1.a != b.a || b1.b != b.b || b1.c != b.c || b1.d != b.d || b1.e != b.e {
		t.Errorf("ValueOf(%v).Interface().(big) = %v", b, b1)
	}
}

type Basic struct {
	x int
	y float32
}

type NotBasic Basic

type DeepEqualTest struct {
	a, b any
	eq   bool
}

// Simple functions for DeepEqual tests.
var (
	fn1 func()             // nil.
	fn2 func()             // nil.
	fn3 = func() { fn1() } // Not nil.
)

type self struct{}

type Loop *Loop
type Loopy any

var loop1, loop2 Loop
var loopy1, loopy2 Loopy
var cycleMap1, cycleMap2, cycleMap3 map[string]any

type structWithSelfPtr struct {
	p *structWithSelfPtr
	s string
}

func init() {
	loop1 = &loop2
	loop2 = &loop1

	loopy1 = &loopy2
	loopy2 = &loopy1

	cycleMap1 = map[string]any{}
	cycleMap1["cycle"] = cycleMap1
	cycleMap2 = map[string]any{}
	cycleMap2["cycle"] = cycleMap2
	cycleMap3 = map[string]any{}
	cycleMap3["different"] = cycleMap3
}

var deepEqualTests = []DeepEqualTest{
	// Equalities
	{nil, nil, true},
	{1, 1, true},
	{int32(1), int32(1), true},
	{0.5, 0.5, true},
	{float32(0.5), float32(0.5), true},
	{"hello", "hello", true},
	{make([]int, 10), make([]int, 10), true},
	{&[3]int{1, 2, 3}, &[3]int{1, 2, 3}, true},
	{Basic{1, 0.5}, Basic{1, 0.5}, true},
	{error(nil), error(nil), true},
	{map[int]string{1: "one", 2: "two"}, map[int]string{2: "two", 1: "one"}, true},
	{fn1, fn2, true},
	{[]byte{1, 2, 3}, []byte{1, 2, 3}, true},
	{[]MyByte{1, 2, 3}, []MyByte{1, 2, 3}, true},
	{MyBytes{1, 2, 3}, MyBytes{1, 2, 3}, true},

	// Inequalities
	{1, 2, false},
	{int32(1), int32(2), false},
	{0.5, 0.6, false},
	{float32(0.5), float32(0.6), false},
	{"hello", "hey", false},
	{make([]int, 10), make([]int, 11), false},
	{&[3]int{1, 2, 3}, &[3]int{1, 2, 4}, false},
	{Basic{1, 0.5}, Basic{1, 0.6}, false},
	{Basic{1, 0}, Basic{2, 0}, false},
	{map[int]string{1: "one", 3: "two"}, map[int]string{2: "two", 1: "one"}, false},
	{map[int]string{1: "one", 2: "txo"}, map[int]string{2: "two", 1: "one"}, false},
	{map[int]string{1: "one"}, map[int]string{2: "two", 1: "one"}, false},
	{map[int]string{2: "two", 1: "one"}, map[int]string{1: "one"}, false},
	{nil, 1, false},
	{1, nil, false},
	{fn1, fn3, false},
	{fn3, fn3, false},
	{[][]int{{1}}, [][]int{{2}}, false},
	{&structWithSelfPtr{p: &structWithSelfPtr{s: "a"}}, &structWithSelfPtr{p: &structWithSelfPtr{s: "b"}}, false},

	// Fun with floating point.
	{math.NaN(), math.NaN(), false},
	{&[1]float64{math.NaN()}, &[1]float64{math.NaN()}, false},
	{&[1]float64{math.NaN()}, self{}, true},
	{[]float64{math.NaN()}, []float64{math.NaN()}, false},
	{[]float64{math.NaN()}, self{}, true},
	{map[float64]float64{math.NaN(): 1}, map[float64]float64{1: 2}, false},
	{map[float64]float64{math.NaN(): 1}, self{}, true},

	// Nil vs empty: not the same.
	{[]int{}, []int(nil), false},
	{[]int{}, []int{}, true},
	{[]int(nil), []int(nil), true},
	{map[int]int{}, map[int]int(nil), false},
	{map[int]int{}, map[int]int{}, true},
	{map[int]int(nil), map[int]int(nil), true},

	// Mismatched types
	{1, 1.0, false},
	{int32(1), int64(1), false},
	{0.5, "hello", false},
	{[]int{1, 2, 3}, [3]int{1, 2, 3}, false},
	{&[3]any{1, 2, 4}, &[3]any{1, 2, "s"}, false},
	{Basic{1, 0.5}, NotBasic{1, 0.5}, false},
	{map[uint]string{1: "one", 2: "two"}, map[int]string{2: "two", 1: "one"}, false},
	{[]byte{1, 2, 3}, []MyByte{1, 2, 3}, false},
	{[]MyByte{1, 2, 3}, MyBytes{1, 2, 3}, false},
	{[]byte{1, 2, 3}, MyBytes{1, 2, 3}, false},

	// Possible loops.
	{&loop1, &loop1, true},
	{&loop1, &loop2, true},
	{&loopy1, &loopy1, true},
	{&loopy1, &loopy2, true},
	{&cycleMap1, &cycleMap2, true},
	{&cycleMap1, &cycleMap3, false},
}

func TestDeepEqual(t *testing.T) {
	for i, test := range deepEqualTests {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			if test.b == (self{}) {
				test.b = test.a
			}
			if r := DeepEqual(test.a, test.b); r != test.eq {
				t.Errorf("DeepEqual(%#v, %#v) = %v, want %v", test.a, test.b, r, test.eq)
			}
		})
	}
}

func TestTypeOf(t *testing.T) {
	// Special case for nil
	if typ := TypeOf(nil); typ != nil {
		t.Errorf("expected nil type for nil value; got %v", typ)
	}
	for _, test := range deepEqualTests {
		v := ValueOf(test.a)
		if !v.IsValid() {
			continue
		}
		typ := TypeOf(test.a)
		if typ != v.Type() {
			t.Errorf("TypeOf(%v) = %v, but ValueOf(%v).Type() = %v", test.a, typ, test.a, v.Type())
		}
	}
}

type Recursive struct {
	x int
	r *Recursive
}

func TestDeepEqualRecursiveStruct(t *testing.T) {
	a, b := new(Recursive), new(Recursive)
	*a = Recursive{12, a}
	*b = Recursive{12, b}
	if !DeepEqual(a, b) {
		t.Error("DeepEqual(recursive same) = false, want true")
	}
}

type _Complex struct {
	a int
	b [3]*_Complex
	c *string
	d map[float64]float64
}

func TestDeepEqualComplexStruct(t *testing.T) {
	m := make(map[float64]float64)
	stra, strb := "hello", "hello"
	a, b := new(_Complex), new(_Complex)
	*a = _Complex{5, [3]*_Complex{a, b, a}, &stra, m}
	*b = _Complex{5, [3]*_Complex{b, a, a}, &strb, m}
	if !DeepEqual(a, b) {
		t.Error("DeepEqual(complex same) = false, want true")
	}
}

func TestDeepEqualComplexStructInequality(t *testing.T) {
	m := make(map[float64]float64)
	stra, strb := "hello", "helloo" // Difference is here
	a, b := new(_Complex), new(_Complex)
	*a = _Complex{5, [3]*_Complex{a, b, a}, &stra, m}
	*b = _Complex{5, [3]*_Complex{b, a, a}, &strb, m}
	if DeepEqual(a, b) {
		t.Error("DeepEqual(complex different) = true, want false")
	}
}

type UnexpT struct {
	m map[int]int
}

func TestDeepEqualUnexportedMap(t *testing.T) {
	// Check that DeepEqual can look at unexported fields.
	x1 := UnexpT{map[int]int{1: 2}}
	x2 := UnexpT{map[int]int{1: 2}}
	if !DeepEqual(&x1, &x2) {
		t.Error("DeepEqual(x1, x2) = false, want true")
	}

	y1 := UnexpT{map[int]int{2: 3}}
	if DeepEqual(&x1, &y1) {
		t.Error("DeepEqual(x1, y1) = true, want false")
	}
}

var deepEqualPerfTests = []struct {
	x, y any
}{
	{x: int8(99), y: int8(99)},
	{x: []int8{99}, y: []int8{99}},
	{x: int16(99), y: int16(99)},
	{x: []int16{99}, y: []int16{99}},
	{x: int32(99), y: int32(99)},
	{x: []int32{99}, y: []int32{99}},
	{x: int64(99), y: int64(99)},
	{x: []int64{99}, y: []int64{99}},
	{x: int(999999), y: int(999999)},
	{x: []int{999999}, y: []int{999999}},

	{x: uint8(99), y: uint8(99)},
	{x: []uint8{99}, y: []uint8{99}},
	{x: uint16(99), y: uint16(99)},
	{x: []uint16{99}, y: []uint16{99}},
	{x: uint32(99), y: uint32(99)},
	{x: []uint32{99}, y: []uint32{99}},
	{x: uint64(99), y: uint64(99)},
	{x: []uint64{99}, y: []uint64{99}},
	{x: uint(999999), y: uint(999999)},
	{x: []uint{999999}, y: []uint{999999}},
	{x: uintptr(999999), y: uintptr(999999)},
	{x: []uintptr{999999}, y: []uintptr{999999}},

	{x: float32(1.414), y: float32(1.414)},
	{x: []float32{1.414}, y: []float32{1.414}},
	{x: float64(1.414), y: float64(1.414)},
	{x: []float64{1.414}, y: []float64{1.414}},

	{x: complex64(1.414), y: complex64(1.414)},
	{x: []complex64{1.414}, y: []complex64{1.414}},
	{x: complex128(1.414), y: complex128(1.414)},
	{x: []complex128{1.414}, y: []complex128{1.414}},

	{x: true, y: true},
	{x: []bool{true}, y: []bool{true}},

	{x: "abcdef", y: "abcdef"},
	{x: []string{"abcdef"}, y: []string{"abcdef"}},

	{x: []byte("abcdef"), y: []byte("abcdef")},
	{x: [][]byte{[]byte("abcdef")}, y: [][]byte{[]byte("abcdef")}},

	{x: [6]byte{'a', 'b', 'c', 'a', 'b', 'c'}, y: [6]byte{'a', 'b', 'c', 'a', 'b', 'c'}},
	{x: [][6]byte{[6]byte{'a', 'b', 'c', 'a', 'b', 'c'}}, y: [][6]byte{[6]byte{'a', 'b', 'c', 'a', 'b', 'c'}}},
}

func TestDeepEqualAllocs(t *testing.T) {
	// TODO(prattmic): maps on stack
	if goexperiment.SwissMap {
		t.Skipf("Maps on stack not yet implemented")
	}
	if asan.Enabled {
		t.Skip("test allocates more with -asan; see #70079")
	}

	for _, tt := range deepEqualPerfTests {
		t.Run(ValueOf(tt.x).Type().String(), func(t *testing.T) {
			got := testing.AllocsPerRun(100, func() {
				if !DeepEqual(tt.x, tt.y) {
					t.Errorf("DeepEqual(%v, %v)=false", tt.x, tt.y)
				}
			})
			if int(got) != 0 {
				t.Errorf("DeepEqual(%v, %v) allocated %d times", tt.x, tt.y, int(got))
			}
		})
	}
}

func check2ndField(x any, offs uintptr, t *testing.T) {
	s := ValueOf(x)
	f := s.Type().Field(1)
	if f.Offset != offs {
		t.Error("mismatched offsets in structure alignment:", f.Offset, offs)
	}
}

// Check that structure alignment & offsets viewed through reflect agree with those
// from the compiler itself.
func TestAlignment(t *testing.T) {
	type T1inner struct {
		a int
	}
	type T1 struct {
		T1inner
		f int
	}
	type T2inner struct {
		a, b int
	}
	type T2 struct {
		T2inner
		f int
	}

	x := T1{T1inner{2}, 17}
	check2ndField(x, uintptr(unsafe.Pointer(&x.f))-uintptr(uns
```