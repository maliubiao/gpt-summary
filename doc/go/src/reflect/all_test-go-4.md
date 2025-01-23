Response:
Let's break down the thought process for analyzing this Go code snippet.

1. **Understand the Goal:** The request asks for an explanation of the Go code's functionality, to infer what Go feature it tests, provide illustrative examples, discuss command-line argument handling (if any), highlight potential pitfalls, and finally, summarize the functionality of this specific part.

2. **Initial Scan for Keywords and Patterns:** Quickly read through the code looking for common Go testing patterns and `reflect` package usage. Key observations:
    *  `func Test...`:  Indicates this is a test file.
    *  `t *testing.T`: Standard Go testing argument.
    *  `reflect.V`, `reflect.TypeFor`, `reflect.TypeOf`, `reflect.ArrayOf`, `reflect.SliceOf`, `reflect.StructOf`, `reflect.ChanOf`, etc.:  Strongly suggests the code is testing functionality within the `reflect` package itself.
    *  `OverflowUint`, `OverflowFloat`, `OverflowInt`:  These method names strongly hint at testing overflow behavior for different numeric types.
    *  `DeepEqual`: Indicates testing for value equality.
    *  `shouldPanic`: A helper function (likely defined elsewhere in the full file) to verify expected panics.
    *  `runtime.GC()`:  Suggests testing scenarios involving garbage collection and memory management.
    *  Loops, array/slice manipulation, struct creation: Common patterns for testing data structures.

3. **Focus on Individual Test Functions:**  The code is structured as a series of test functions. Analyze each function's purpose:

    * **`TestUintOverflow` and `TestTypeOverflow`:** These seem to be the most straightforward. They directly call methods like `OverflowUint` and `OverflowFloat` on `reflect.V` or types obtained via `reflect.TypeFor`. The tests check if known overflow and non-overflow values are correctly identified. *This is a good starting point for providing a code example.*

    * **`checkSameType`:**  A helper function to verify that when creating a `reflect.Type` (like with `reflect.ArrayOf`), the returned type is the same as the `reflect.Type` obtained directly from a concrete value of that type. This checks for caching/reuse of existing types.

    * **`TestArrayOf`:** This function tests the `reflect.ArrayOf` function. It creates arrays of various types, populates them, compares them using `DeepEqual`, and checks the `Comparable()` property. The test cases cover different element types (primitive, structs, arrays, slices). *This is another good candidate for a detailed explanation and example.*

    * **`TestArrayOfGC`:**  Specifically tests the interaction of `reflect.ArrayOf` with garbage collection. It creates arrays of pointers and ensures the pointers remain valid after a GC cycle.

    * **`TestArrayOfAlg` and `TestArrayOfGenericAlg`:** These appear to test the algorithmic equality and hashing of arrays created with `reflect.ArrayOf`. The `shouldPanic` call in `TestArrayOfAlg` suggests testing cases where comparison is not allowed (e.g., arrays containing slices).

    * **`TestArrayOfDirectIface`:**  This test deals with the internal representation of arrays when converted to interfaces, specifically looking at the `InterfaceData()` method and how pointers are handled in empty and non-empty arrays.

    * **`TestArrayOfPanicOnNegativeLength`:** Verifies that `reflect.ArrayOf` panics when given a negative length, as expected.

    * **`TestSliceOf`:** Similar to `TestArrayOf`, but for `reflect.SliceOf`.

    * **`TestSliceOverflow`:** Checks for panic conditions when creating slices that would exceed memory limits.

    * **`TestSliceOfGC`:** Tests `reflect.SliceOf` with garbage collection.

    * **`TestStructOfFieldName`:** Focuses on the validation of field names when using `reflect.StructOf`.

    * **`TestStructOf`:** A more comprehensive test of `reflect.StructOf`, covering field tags, size, alignment, duplicate fields, and interactions with types already in the binary.

    * **`TestStructOfExportRules`:** Specifically tests the rules around exporting fields in dynamically created structs using `reflect.StructOf`.

    * **`TestStructOfGC`:** Tests `reflect.StructOf` with garbage collection.

    * **`TestStructOfAlg` and `TestStructOfGenericAlg`:** Similar to the array tests, these verify the algorithmic equality and hashing of structs.

    * **`TestStructOfDirectIface`:** Similar to the array version, this checks interface representation for structs.

    * **`TestStructOfWithInterface`:** Tests the interaction of `reflect.StructOf` with interfaces, especially when embedding types that implement interfaces. It also highlights limitations in current Go implementations related to methods on embedded fields.

    * **`TestStructOfTooManyFields`:**  Ensures `reflect.StructOf` handles structs with many fields correctly.

    * **`TestStructOfDifferentPkgPath`:**  Verifies that `reflect.StructOf` enforces consistency in package paths for fields.

    * **`TestStructOfTooLarge`:**  Checks for panic conditions when creating structs that are too large.

    * **`TestStructOfAnonymous`:** Tests the creation of structs with anonymous fields.

    * **`TestChanOf`:** Tests the creation and usage of channels via `reflect.ChanOf`.

    * **`TestChanOfDir`:** Specifically tests the creation of send-only and receive-only channels.

    * **`TestChanOfGC`:** Tests channel creation with garbage collection.

4. **Infer the Go Feature:** Based on the consistent use of `reflect` functions, the manipulation of types and values at runtime, and the specific tests for array, slice, struct, and channel creation, the core Go feature being tested is **reflection**.

5. **Provide Code Examples:** Choose representative test functions like `TestUintOverflow`, `TestTypeOverflow`, and `TestArrayOf` to illustrate how the `reflect` package is used to inspect and manipulate types and values. Construct clear examples with inputs and expected outputs.

6. **Address Command-Line Arguments:**  Review the code for any direct usage of `os.Args` or flags. In this case, there are none, so state that explicitly.

7. **Identify Potential Pitfalls:** Think about common mistakes developers might make when using the `reflect` package. Examples include:
    * Incorrectly assuming comparability of dynamically created types.
    * Forgetting to handle potential panics.
    * Misunderstanding the nuances of interface values and embedded fields.

8. **Summarize the Functionality:** Condense the analysis into a concise summary of the code's purpose – testing various aspects of the Go `reflect` package.

9. **Review and Refine:** Read through the entire explanation to ensure clarity, accuracy, and completeness. Check that the code examples are correct and easy to understand. Ensure the language is natural and avoids overly technical jargon where possible. Make sure the section numbering (part 5 of 7) is noted as requested.
这是路径为 `go/src/reflect/all_test.go` 的 Go 语言实现的一部分，它主要负责测试 Go 语言的 **反射 (reflection)** 功能。

**功能列举:**

* **测试基本类型的溢出行为:**  测试 `reflect.Value` 和 `reflect.Type` 是否能正确检测各种整型和浮点类型的溢出情况。
* **测试动态创建数组 (`reflect.ArrayOf`)**:
    * 测试创建各种类型的数组，包括自定义类型、结构体、数组的数组等。
    * 测试创建的数组是否可比较 (`Comparable`)。
    * 测试创建的数组在赋值和使用后的值是否正确。
    * 测试数组类型在二进制中是否能被正确找到和重用。
    * 测试数组在垃圾回收 (`GC`) 后的数据是否保持完整。
    * 测试数组的算法相等性 (`DeepEqual`) 和哈希值的计算。
    * 测试创建负长度数组时是否会 panic。
* **测试动态创建切片 (`reflect.SliceOf`)**:
    * 测试创建切片后赋值和使用是否正确。
    * 测试切片在垃圾回收后的数据是否保持完整。
    * 测试创建过大切片时是否会 panic。
* **测试动态创建结构体 (`reflect.StructOf`)**:
    * 测试创建包含各种类型字段的结构体。
    * 测试结构体字段名的合法性。
    * 测试结构体的 `String()` 方法输出是否正确。
    * 测试结构体的大小 (`Size`)、对齐 (`Align`) 和字段偏移量 (`Offset`) 是否正确。
    * 测试包含零大小字段的结构体的大小和对齐。
    * 测试创建具有重复名字的字段是否会 panic。
    * 测试结构体的导出规则 (大小写)。
    * 测试结构体在垃圾回收后的数据是否保持完整。
    * 测试结构体的算法相等性 (`DeepEqual`) 和哈希值的计算。
    * 测试包含接口类型字段的结构体。
    * 测试创建字段过多的结构体。
    * 测试创建来自不同包路径的字段的结构体是否会 panic。
    * 测试创建过大结构体时是否会 panic。
    * 测试包含匿名结构体字段的情况。
* **测试动态创建通道 (`reflect.ChanOf`)**:
    * 测试创建双向通道、只读通道和只写通道。
    * 测试通道的发送和接收操作。
    * 测试通道在垃圾回收后的行为。

**推理的 Go 语言功能实现 (反射):**

这段代码主要测试了 Go 语言的反射机制。反射是指在程序运行时检查和修改程序结构和行为的能力。`reflect` 包提供了实现反射的各种类型和函数。

**Go 代码举例说明:**

```go
package main

import (
	"fmt"
	"reflect"
)

func main() {
	// 测试基本类型的溢出检测
	var i32 int32 = 2147483647
	v := reflect.ValueOf(i32)
	ovf := v.OverflowInt(int64(i32 + 1))
	fmt.Printf("int32 overflow: %v\n", ovf) // Output: int32 overflow: true

	// 测试动态创建数组
	arrayType := reflect.ArrayOf(5, reflect.TypeOf(int(0)))
	newArray := reflect.New(arrayType).Elem()
	for i := 0; i < newArray.Len(); i++ {
		newArray.Index(i).SetInt(int64(i * 2))
	}
	fmt.Printf("Created array: %v\n", newArray.Interface()) // Output: Created array: [0 2 4 6 8]

	// 测试动态创建结构体
	structFields := []reflect.StructField{
		{Name: "Name", Type: reflect.TypeOf(""), Tag: `json:"name"`},
		{Name: "Age", Type: reflect.TypeOf(0)},
	}
	structType := reflect.StructOf(structFields)
	newStruct := reflect.New(structType).Elem()
	newStruct.FieldByName("Name").SetString("Alice")
	newStruct.FieldByName("Age").SetInt(30)
	fmt.Printf("Created struct: %+v\n", newStruct.Interface()) // Output: Created struct: {Name:Alice Age:30}

	// 测试动态创建通道
	chanType := reflect.ChanOf(reflect.BothDir, reflect.TypeOf(string("")))
	newChan := reflect.MakeChan(chanType, 1)
	go func() {
		newChan.Send(reflect.ValueOf("message"))
	}()
	receivedValue, ok := newChan.Recv()
	fmt.Printf("Received from channel: %v, ok: %v\n", receivedValue, ok) // Output: Received from channel: message, ok: true
}
```

**假设的输入与输出 (代码推理):**

在 `TestTypeOverflow` 函数中，以测试 `int32` 溢出为例：

* **假设输入:** `maxInt32 = int64(0x7fffffff)`, `ovfInt32 = int64(1 << 31)`
* **预期输出:**
    * `TypeFor[int32]().OverflowInt(maxInt32)` 应该返回 `false` (不溢出)。
    * `TypeFor[int32]().OverflowInt(ovfInt32)` 应该返回 `true` (溢出)。

**命令行参数的具体处理:**

这段代码是测试代码，通常不会直接处理命令行参数。`go test` 命令会执行这些测试函数，但具体的参数由 `go test` 本身处理，而不是这些测试代码。

**使用者易犯错的点:**

* **动态创建的类型的可比较性:**  用户可能会错误地认为所有动态创建的类型都是可比较的。例如，包含切片的数组是不可比较的。`TestArrayOf` 函数就通过 `table.comparable` 字段来验证这一点。
    ```go
    // 易错点示例：包含切片的数组不可比较
    type MyType struct {
        Data []int
    }

    func main() {
        type1 := reflect.TypeOf(MyType{[]int{1, 2}})
        arrayType := reflect.ArrayOf(2, type1)
        fmt.Println(arrayType.Comparable()) // Output: false
    }
    ```
* **对 `panic` 的理解和处理:**  反射操作有时会触发 `panic`，例如尝试访问不存在的字段或创建非法类型的结构体。`shouldPanic` 函数用于测试预期的 `panic` 行为。用户在使用反射时需要注意捕获和处理这些潜在的 `panic`。

**功能归纳 (针对提供的代码片段 - 第5部分):**

这段代码片段 (第 5 部分) 主要集中在测试 Go 语言反射中 **动态创建数组 (`reflect.ArrayOf`)** 的功能。它涵盖了以下几个关键方面：

1. **创建各种类型的数组:** 包括基本类型、自定义类型、结构体以及嵌套数组。
2. **数组的可比较性:** 验证不同元素类型的数组是否可进行深度比较 (`DeepEqual`)。
3. **数组的赋值和取值:** 确保创建的数组可以正确赋值和读取元素。
4. **数组的垃圾回收:** 测试数组在垃圾回收后其内部数据是否仍然有效。
5. **数组的算法特性:**  验证数组的相等性判断和哈希值计算的正确性。
6. **边界条件测试:**  例如，测试创建负长度的数组是否会引发预期的 panic。
7. **与已存在类型的匹配:** 验证动态创建的数组类型是否能与程序中已有的相同类型的数组匹配。

总而言之，这部分代码是 `reflect` 包测试套件中关于数组动态创建功能的重要组成部分，旨在确保该功能的正确性和健壮性。

### 提示词
```
这是路径为go/src/reflect/all_test.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第5部分，共7部分，请归纳一下它的功能
```

### 源代码
```go
uint64(0xffffffff)
	if ovf := V(uint32(0)).OverflowUint(maxUint32); ovf {
		t.Errorf("%v wrongly overflows uint32", maxUint32)
	}
	ovfUint32 := uint64(1 << 32)
	if ovf := V(uint32(0)).OverflowUint(ovfUint32); !ovf {
		t.Errorf("%v should overflow uint32", ovfUint32)
	}
}

func TestTypeOverflow(t *testing.T) {
	if ovf := TypeFor[float64]().OverflowFloat(1e300); ovf {
		t.Errorf("%v wrongly overflows float64", 1e300)
	}

	maxFloat32 := float64((1<<24 - 1) << (127 - 23))
	if ovf := TypeFor[float32]().OverflowFloat(maxFloat32); ovf {
		t.Errorf("%v wrongly overflows float32", maxFloat32)
	}
	ovfFloat32 := float64((1<<24-1)<<(127-23) + 1<<(127-52))
	if ovf := TypeFor[float32]().OverflowFloat(ovfFloat32); !ovf {
		t.Errorf("%v should overflow float32", ovfFloat32)
	}
	if ovf := TypeFor[float32]().OverflowFloat(-ovfFloat32); !ovf {
		t.Errorf("%v should overflow float32", -ovfFloat32)
	}

	maxInt32 := int64(0x7fffffff)
	if ovf := TypeFor[int32]().OverflowInt(maxInt32); ovf {
		t.Errorf("%v wrongly overflows int32", maxInt32)
	}
	if ovf := TypeFor[int32]().OverflowInt(-1 << 31); ovf {
		t.Errorf("%v wrongly overflows int32", -int64(1)<<31)
	}
	ovfInt32 := int64(1 << 31)
	if ovf := TypeFor[int32]().OverflowInt(ovfInt32); !ovf {
		t.Errorf("%v should overflow int32", ovfInt32)
	}

	maxUint32 := uint64(0xffffffff)
	if ovf := TypeFor[uint32]().OverflowUint(maxUint32); ovf {
		t.Errorf("%v wrongly overflows uint32", maxUint32)
	}
	ovfUint32 := uint64(1 << 32)
	if ovf := TypeFor[uint32]().OverflowUint(ovfUint32); !ovf {
		t.Errorf("%v should overflow uint32", ovfUint32)
	}
}

func checkSameType(t *testing.T, x Type, y any) {
	if x != TypeOf(y) || TypeOf(Zero(x).Interface()) != TypeOf(y) {
		t.Errorf("did not find preexisting type for %s (vs %s)", TypeOf(x), TypeOf(y))
	}
}

func TestArrayOf(t *testing.T) {
	// check construction and use of type not in binary
	tests := []struct {
		n          int
		value      func(i int) any
		comparable bool
		want       string
	}{
		{
			n:          0,
			value:      func(i int) any { type Tint int; return Tint(i) },
			comparable: true,
			want:       "[]",
		},
		{
			n:          10,
			value:      func(i int) any { type Tint int; return Tint(i) },
			comparable: true,
			want:       "[0 1 2 3 4 5 6 7 8 9]",
		},
		{
			n:          10,
			value:      func(i int) any { type Tfloat float64; return Tfloat(i) },
			comparable: true,
			want:       "[0 1 2 3 4 5 6 7 8 9]",
		},
		{
			n:          10,
			value:      func(i int) any { type Tstring string; return Tstring(strconv.Itoa(i)) },
			comparable: true,
			want:       "[0 1 2 3 4 5 6 7 8 9]",
		},
		{
			n:          10,
			value:      func(i int) any { type Tstruct struct{ V int }; return Tstruct{i} },
			comparable: true,
			want:       "[{0} {1} {2} {3} {4} {5} {6} {7} {8} {9}]",
		},
		{
			n:          10,
			value:      func(i int) any { type Tint int; return []Tint{Tint(i)} },
			comparable: false,
			want:       "[[0] [1] [2] [3] [4] [5] [6] [7] [8] [9]]",
		},
		{
			n:          10,
			value:      func(i int) any { type Tint int; return [1]Tint{Tint(i)} },
			comparable: true,
			want:       "[[0] [1] [2] [3] [4] [5] [6] [7] [8] [9]]",
		},
		{
			n:          10,
			value:      func(i int) any { type Tstruct struct{ V [1]int }; return Tstruct{[1]int{i}} },
			comparable: true,
			want:       "[{[0]} {[1]} {[2]} {[3]} {[4]} {[5]} {[6]} {[7]} {[8]} {[9]}]",
		},
		{
			n:          10,
			value:      func(i int) any { type Tstruct struct{ V []int }; return Tstruct{[]int{i}} },
			comparable: false,
			want:       "[{[0]} {[1]} {[2]} {[3]} {[4]} {[5]} {[6]} {[7]} {[8]} {[9]}]",
		},
		{
			n:          10,
			value:      func(i int) any { type TstructUV struct{ U, V int }; return TstructUV{i, i} },
			comparable: true,
			want:       "[{0 0} {1 1} {2 2} {3 3} {4 4} {5 5} {6 6} {7 7} {8 8} {9 9}]",
		},
		{
			n: 10,
			value: func(i int) any {
				type TstructUV struct {
					U int
					V float64
				}
				return TstructUV{i, float64(i)}
			},
			comparable: true,
			want:       "[{0 0} {1 1} {2 2} {3 3} {4 4} {5 5} {6 6} {7 7} {8 8} {9 9}]",
		},
	}

	for _, table := range tests {
		at := ArrayOf(table.n, TypeOf(table.value(0)))
		v := New(at).Elem()
		vok := New(at).Elem()
		vnot := New(at).Elem()
		for i := 0; i < v.Len(); i++ {
			v.Index(i).Set(ValueOf(table.value(i)))
			vok.Index(i).Set(ValueOf(table.value(i)))
			j := i
			if i+1 == v.Len() {
				j = i + 1
			}
			vnot.Index(i).Set(ValueOf(table.value(j))) // make it differ only by last element
		}
		s := fmt.Sprint(v.Interface())
		if s != table.want {
			t.Errorf("constructed array = %s, want %s", s, table.want)
		}

		if table.comparable != at.Comparable() {
			t.Errorf("constructed array (%#v) is comparable=%v, want=%v", v.Interface(), at.Comparable(), table.comparable)
		}
		if table.comparable {
			if table.n > 0 {
				if DeepEqual(vnot.Interface(), v.Interface()) {
					t.Errorf(
						"arrays (%#v) compare ok (but should not)",
						v.Interface(),
					)
				}
			}
			if !DeepEqual(vok.Interface(), v.Interface()) {
				t.Errorf(
					"arrays (%#v) compare NOT-ok (but should)",
					v.Interface(),
				)
			}
		}
	}

	// check that type already in binary is found
	type T int
	checkSameType(t, ArrayOf(5, TypeOf(T(1))), [5]T{})
}

func TestArrayOfGC(t *testing.T) {
	type T *uintptr
	tt := TypeOf(T(nil))
	const n = 100
	var x []any
	for i := 0; i < n; i++ {
		v := New(ArrayOf(n, tt)).Elem()
		for j := 0; j < v.Len(); j++ {
			p := new(uintptr)
			*p = uintptr(i*n + j)
			v.Index(j).Set(ValueOf(p).Convert(tt))
		}
		x = append(x, v.Interface())
	}
	runtime.GC()

	for i, xi := range x {
		v := ValueOf(xi)
		for j := 0; j < v.Len(); j++ {
			k := v.Index(j).Elem().Interface()
			if k != uintptr(i*n+j) {
				t.Errorf("lost x[%d][%d] = %d, want %d", i, j, k, i*n+j)
			}
		}
	}
}

func TestArrayOfAlg(t *testing.T) {
	at := ArrayOf(6, TypeOf(byte(0)))
	v1 := New(at).Elem()
	v2 := New(at).Elem()
	if v1.Interface() != v1.Interface() {
		t.Errorf("constructed array %v not equal to itself", v1.Interface())
	}
	v1.Index(5).Set(ValueOf(byte(1)))
	if i1, i2 := v1.Interface(), v2.Interface(); i1 == i2 {
		t.Errorf("constructed arrays %v and %v should not be equal", i1, i2)
	}

	at = ArrayOf(6, TypeOf([]int(nil)))
	v1 = New(at).Elem()
	shouldPanic("", func() { _ = v1.Interface() == v1.Interface() })
}

func TestArrayOfGenericAlg(t *testing.T) {
	at1 := ArrayOf(5, TypeOf(string("")))
	at := ArrayOf(6, at1)
	v1 := New(at).Elem()
	v2 := New(at).Elem()
	if v1.Interface() != v1.Interface() {
		t.Errorf("constructed array %v not equal to itself", v1.Interface())
	}

	v1.Index(0).Index(0).Set(ValueOf("abc"))
	v2.Index(0).Index(0).Set(ValueOf("efg"))
	if i1, i2 := v1.Interface(), v2.Interface(); i1 == i2 {
		t.Errorf("constructed arrays %v and %v should not be equal", i1, i2)
	}

	v1.Index(0).Index(0).Set(ValueOf("abc"))
	v2.Index(0).Index(0).Set(ValueOf((v1.Index(0).Index(0).String() + " ")[:3]))
	if i1, i2 := v1.Interface(), v2.Interface(); i1 != i2 {
		t.Errorf("constructed arrays %v and %v should be equal", i1, i2)
	}

	// Test hash
	m := MakeMap(MapOf(at, TypeOf(int(0))))
	m.SetMapIndex(v1, ValueOf(1))
	if i1, i2 := v1.Interface(), v2.Interface(); !m.MapIndex(v2).IsValid() {
		t.Errorf("constructed arrays %v and %v have different hashes", i1, i2)
	}
}

func TestArrayOfDirectIface(t *testing.T) {
	{
		type T [1]*byte
		i1 := Zero(TypeOf(T{})).Interface()
		v1 := ValueOf(&i1).Elem()
		p1 := v1.InterfaceData()[1]

		i2 := Zero(ArrayOf(1, PointerTo(TypeOf(int8(0))))).Interface()
		v2 := ValueOf(&i2).Elem()
		p2 := v2.InterfaceData()[1]

		if p1 != 0 {
			t.Errorf("got p1=%v. want=%v", p1, nil)
		}

		if p2 != 0 {
			t.Errorf("got p2=%v. want=%v", p2, nil)
		}
	}
	{
		type T [0]*byte
		i1 := Zero(TypeOf(T{})).Interface()
		v1 := ValueOf(&i1).Elem()
		p1 := v1.InterfaceData()[1]

		i2 := Zero(ArrayOf(0, PointerTo(TypeOf(int8(0))))).Interface()
		v2 := ValueOf(&i2).Elem()
		p2 := v2.InterfaceData()[1]

		if p1 == 0 {
			t.Errorf("got p1=%v. want=not-%v", p1, nil)
		}

		if p2 == 0 {
			t.Errorf("got p2=%v. want=not-%v", p2, nil)
		}
	}
}

// Ensure passing in negative lengths panics.
// See https://golang.org/issue/43603
func TestArrayOfPanicOnNegativeLength(t *testing.T) {
	shouldPanic("reflect: negative length passed to ArrayOf", func() {
		ArrayOf(-1, TypeOf(byte(0)))
	})
}

func TestSliceOf(t *testing.T) {
	// check construction and use of type not in binary
	type T int
	st := SliceOf(TypeOf(T(1)))
	if got, want := st.String(), "[]reflect_test.T"; got != want {
		t.Errorf("SliceOf(T(1)).String()=%q, want %q", got, want)
	}
	v := MakeSlice(st, 10, 10)
	runtime.GC()
	for i := 0; i < v.Len(); i++ {
		v.Index(i).Set(ValueOf(T(i)))
		runtime.GC()
	}
	s := fmt.Sprint(v.Interface())
	want := "[0 1 2 3 4 5 6 7 8 9]"
	if s != want {
		t.Errorf("constructed slice = %s, want %s", s, want)
	}

	// check that type already in binary is found
	type T1 int
	checkSameType(t, SliceOf(TypeOf(T1(1))), []T1{})
}

func TestSliceOverflow(t *testing.T) {
	// check that MakeSlice panics when size of slice overflows uint
	const S = 1e6
	s := uint(S)
	l := (1<<(unsafe.Sizeof((*byte)(nil))*8)-1)/s + 1
	if l*s >= s {
		t.Fatal("slice size does not overflow")
	}
	var x [S]byte
	st := SliceOf(TypeOf(x))
	defer func() {
		err := recover()
		if err == nil {
			t.Fatal("slice overflow does not panic")
		}
	}()
	MakeSlice(st, int(l), int(l))
}

func TestSliceOfGC(t *testing.T) {
	type T *uintptr
	tt := TypeOf(T(nil))
	st := SliceOf(tt)
	const n = 100
	var x []any
	for i := 0; i < n; i++ {
		v := MakeSlice(st, n, n)
		for j := 0; j < v.Len(); j++ {
			p := new(uintptr)
			*p = uintptr(i*n + j)
			v.Index(j).Set(ValueOf(p).Convert(tt))
		}
		x = append(x, v.Interface())
	}
	runtime.GC()

	for i, xi := range x {
		v := ValueOf(xi)
		for j := 0; j < v.Len(); j++ {
			k := v.Index(j).Elem().Interface()
			if k != uintptr(i*n+j) {
				t.Errorf("lost x[%d][%d] = %d, want %d", i, j, k, i*n+j)
			}
		}
	}
}

func TestStructOfFieldName(t *testing.T) {
	// invalid field name "1nvalid"
	shouldPanic("has invalid name", func() {
		StructOf([]StructField{
			{Name: "Valid", Type: TypeOf("")},
			{Name: "1nvalid", Type: TypeOf("")},
		})
	})

	// invalid field name "+"
	shouldPanic("has invalid name", func() {
		StructOf([]StructField{
			{Name: "Val1d", Type: TypeOf("")},
			{Name: "+", Type: TypeOf("")},
		})
	})

	// no field name
	shouldPanic("has no name", func() {
		StructOf([]StructField{
			{Name: "", Type: TypeOf("")},
		})
	})

	// verify creation of a struct with valid struct fields
	validFields := []StructField{
		{
			Name: "φ",
			Type: TypeOf(""),
		},
		{
			Name: "ValidName",
			Type: TypeOf(""),
		},
		{
			Name: "Val1dNam5",
			Type: TypeOf(""),
		},
	}

	validStruct := StructOf(validFields)

	const structStr = `struct { φ string; ValidName string; Val1dNam5 string }`
	if got, want := validStruct.String(), structStr; got != want {
		t.Errorf("StructOf(validFields).String()=%q, want %q", got, want)
	}
}

func TestStructOf(t *testing.T) {
	// check construction and use of type not in binary
	fields := []StructField{
		{
			Name: "S",
			Tag:  "s",
			Type: TypeOf(""),
		},
		{
			Name: "X",
			Tag:  "x",
			Type: TypeOf(byte(0)),
		},
		{
			Name: "Y",
			Type: TypeOf(uint64(0)),
		},
		{
			Name: "Z",
			Type: TypeOf([3]uint16{}),
		},
	}

	st := StructOf(fields)
	v := New(st).Elem()
	runtime.GC()
	v.FieldByName("X").Set(ValueOf(byte(2)))
	v.FieldByIndex([]int{1}).Set(ValueOf(byte(1)))
	runtime.GC()

	s := fmt.Sprint(v.Interface())
	want := `{ 1 0 [0 0 0]}`
	if s != want {
		t.Errorf("constructed struct = %s, want %s", s, want)
	}
	const stStr = `struct { S string "s"; X uint8 "x"; Y uint64; Z [3]uint16 }`
	if got, want := st.String(), stStr; got != want {
		t.Errorf("StructOf(fields).String()=%q, want %q", got, want)
	}

	// check the size, alignment and field offsets
	stt := TypeOf(struct {
		String string
		X      byte
		Y      uint64
		Z      [3]uint16
	}{})
	if st.Size() != stt.Size() {
		t.Errorf("constructed struct size = %v, want %v", st.Size(), stt.Size())
	}
	if st.Align() != stt.Align() {
		t.Errorf("constructed struct align = %v, want %v", st.Align(), stt.Align())
	}
	if st.FieldAlign() != stt.FieldAlign() {
		t.Errorf("constructed struct field align = %v, want %v", st.FieldAlign(), stt.FieldAlign())
	}
	for i := 0; i < st.NumField(); i++ {
		o1 := st.Field(i).Offset
		o2 := stt.Field(i).Offset
		if o1 != o2 {
			t.Errorf("constructed struct field %v offset = %v, want %v", i, o1, o2)
		}
	}

	// Check size and alignment with a trailing zero-sized field.
	st = StructOf([]StructField{
		{
			Name: "F1",
			Type: TypeOf(byte(0)),
		},
		{
			Name: "F2",
			Type: TypeOf([0]*byte{}),
		},
	})
	stt = TypeOf(struct {
		G1 byte
		G2 [0]*byte
	}{})
	if st.Size() != stt.Size() {
		t.Errorf("constructed zero-padded struct size = %v, want %v", st.Size(), stt.Size())
	}
	if st.Align() != stt.Align() {
		t.Errorf("constructed zero-padded struct align = %v, want %v", st.Align(), stt.Align())
	}
	if st.FieldAlign() != stt.FieldAlign() {
		t.Errorf("constructed zero-padded struct field align = %v, want %v", st.FieldAlign(), stt.FieldAlign())
	}
	for i := 0; i < st.NumField(); i++ {
		o1 := st.Field(i).Offset
		o2 := stt.Field(i).Offset
		if o1 != o2 {
			t.Errorf("constructed zero-padded struct field %v offset = %v, want %v", i, o1, o2)
		}
	}

	// check duplicate names
	shouldPanic("duplicate field", func() {
		StructOf([]StructField{
			{Name: "string", PkgPath: "p", Type: TypeOf("")},
			{Name: "string", PkgPath: "p", Type: TypeOf("")},
		})
	})
	shouldPanic("has no name", func() {
		StructOf([]StructField{
			{Type: TypeOf("")},
			{Name: "string", PkgPath: "p", Type: TypeOf("")},
		})
	})
	shouldPanic("has no name", func() {
		StructOf([]StructField{
			{Type: TypeOf("")},
			{Type: TypeOf("")},
		})
	})
	// check that type already in binary is found
	checkSameType(t, StructOf(fields[2:3]), struct{ Y uint64 }{})

	// gccgo used to fail this test.
	type structFieldType any
	checkSameType(t,
		StructOf([]StructField{
			{
				Name: "F",
				Type: TypeOf((*structFieldType)(nil)).Elem(),
			},
		}),
		struct{ F structFieldType }{})
}

func TestStructOfExportRules(t *testing.T) {
	type S1 struct{}
	type s2 struct{}
	type ΦType struct{}
	type φType struct{}

	testPanic := func(i int, mustPanic bool, f func()) {
		defer func() {
			err := recover()
			if err == nil && mustPanic {
				t.Errorf("test-%d did not panic", i)
			}
			if err != nil && !mustPanic {
				t.Errorf("test-%d panicked: %v\n", i, err)
			}
		}()
		f()
	}

	tests := []struct {
		field     StructField
		mustPanic bool
		exported  bool
	}{
		{
			field:    StructField{Name: "S1", Anonymous: true, Type: TypeOf(S1{})},
			exported: true,
		},
		{
			field:    StructField{Name: "S1", Anonymous: true, Type: TypeOf((*S1)(nil))},
			exported: true,
		},
		{
			field:     StructField{Name: "s2", Anonymous: true, Type: TypeOf(s2{})},
			mustPanic: true,
		},
		{
			field:     StructField{Name: "s2", Anonymous: true, Type: TypeOf((*s2)(nil))},
			mustPanic: true,
		},
		{
			field:     StructField{Name: "Name", Type: nil, PkgPath: ""},
			mustPanic: true,
		},
		{
			field:     StructField{Name: "", Type: TypeOf(S1{}), PkgPath: ""},
			mustPanic: true,
		},
		{
			field:     StructField{Name: "S1", Anonymous: true, Type: TypeOf(S1{}), PkgPath: "other/pkg"},
			mustPanic: true,
		},
		{
			field:     StructField{Name: "S1", Anonymous: true, Type: TypeOf((*S1)(nil)), PkgPath: "other/pkg"},
			mustPanic: true,
		},
		{
			field:     StructField{Name: "s2", Anonymous: true, Type: TypeOf(s2{}), PkgPath: "other/pkg"},
			mustPanic: true,
		},
		{
			field:     StructField{Name: "s2", Anonymous: true, Type: TypeOf((*s2)(nil)), PkgPath: "other/pkg"},
			mustPanic: true,
		},
		{
			field: StructField{Name: "s2", Type: TypeOf(int(0)), PkgPath: "other/pkg"},
		},
		{
			field: StructField{Name: "s2", Type: TypeOf(int(0)), PkgPath: "other/pkg"},
		},
		{
			field:    StructField{Name: "S", Type: TypeOf(S1{})},
			exported: true,
		},
		{
			field:    StructField{Name: "S", Type: TypeOf((*S1)(nil))},
			exported: true,
		},
		{
			field:    StructField{Name: "S", Type: TypeOf(s2{})},
			exported: true,
		},
		{
			field:    StructField{Name: "S", Type: TypeOf((*s2)(nil))},
			exported: true,
		},
		{
			field:     StructField{Name: "s", Type: TypeOf(S1{})},
			mustPanic: true,
		},
		{
			field:     StructField{Name: "s", Type: TypeOf((*S1)(nil))},
			mustPanic: true,
		},
		{
			field:     StructField{Name: "s", Type: TypeOf(s2{})},
			mustPanic: true,
		},
		{
			field:     StructField{Name: "s", Type: TypeOf((*s2)(nil))},
			mustPanic: true,
		},
		{
			field: StructField{Name: "s", Type: TypeOf(S1{}), PkgPath: "other/pkg"},
		},
		{
			field: StructField{Name: "s", Type: TypeOf((*S1)(nil)), PkgPath: "other/pkg"},
		},
		{
			field: StructField{Name: "s", Type: TypeOf(s2{}), PkgPath: "other/pkg"},
		},
		{
			field: StructField{Name: "s", Type: TypeOf((*s2)(nil)), PkgPath: "other/pkg"},
		},
		{
			field:     StructField{Name: "", Type: TypeOf(ΦType{})},
			mustPanic: true,
		},
		{
			field:     StructField{Name: "", Type: TypeOf(φType{})},
			mustPanic: true,
		},
		{
			field:    StructField{Name: "Φ", Type: TypeOf(0)},
			exported: true,
		},
		{
			field:    StructField{Name: "φ", Type: TypeOf(0)},
			exported: false,
		},
	}

	for i, test := range tests {
		testPanic(i, test.mustPanic, func() {
			typ := StructOf([]StructField{test.field})
			if typ == nil {
				t.Errorf("test-%d: error creating struct type", i)
				return
			}
			field := typ.Field(0)
			n := field.Name
			if n == "" {
				panic("field.Name must not be empty")
			}
			exported := token.IsExported(n)
			if exported != test.exported {
				t.Errorf("test-%d: got exported=%v want exported=%v", i, exported, test.exported)
			}
			if field.PkgPath != test.field.PkgPath {
				t.Errorf("test-%d: got PkgPath=%q want pkgPath=%q", i, field.PkgPath, test.field.PkgPath)
			}
		})
	}
}

func TestStructOfGC(t *testing.T) {
	type T *uintptr
	tt := TypeOf(T(nil))
	fields := []StructField{
		{Name: "X", Type: tt},
		{Name: "Y", Type: tt},
	}
	st := StructOf(fields)

	const n = 10000
	var x []any
	for i := 0; i < n; i++ {
		v := New(st).Elem()
		for j := 0; j < v.NumField(); j++ {
			p := new(uintptr)
			*p = uintptr(i*n + j)
			v.Field(j).Set(ValueOf(p).Convert(tt))
		}
		x = append(x, v.Interface())
	}
	runtime.GC()

	for i, xi := range x {
		v := ValueOf(xi)
		for j := 0; j < v.NumField(); j++ {
			k := v.Field(j).Elem().Interface()
			if k != uintptr(i*n+j) {
				t.Errorf("lost x[%d].%c = %d, want %d", i, "XY"[j], k, i*n+j)
			}
		}
	}
}

func TestStructOfAlg(t *testing.T) {
	st := StructOf([]StructField{{Name: "X", Tag: "x", Type: TypeOf(int(0))}})
	v1 := New(st).Elem()
	v2 := New(st).Elem()
	if !DeepEqual(v1.Interface(), v1.Interface()) {
		t.Errorf("constructed struct %v not equal to itself", v1.Interface())
	}
	v1.FieldByName("X").Set(ValueOf(int(1)))
	if i1, i2 := v1.Interface(), v2.Interface(); DeepEqual(i1, i2) {
		t.Errorf("constructed structs %v and %v should not be equal", i1, i2)
	}

	st = StructOf([]StructField{{Name: "X", Tag: "x", Type: TypeOf([]int(nil))}})
	v1 = New(st).Elem()
	shouldPanic("", func() { _ = v1.Interface() == v1.Interface() })
}

func TestStructOfGenericAlg(t *testing.T) {
	st1 := StructOf([]StructField{
		{Name: "X", Tag: "x", Type: TypeOf(int64(0))},
		{Name: "Y", Type: TypeOf(string(""))},
	})
	st := StructOf([]StructField{
		{Name: "S0", Type: st1},
		{Name: "S1", Type: st1},
	})

	tests := []struct {
		rt  Type
		idx []int
	}{
		{
			rt:  st,
			idx: []int{0, 1},
		},
		{
			rt:  st1,
			idx: []int{1},
		},
		{
			rt: StructOf(
				[]StructField{
					{Name: "XX", Type: TypeOf([0]int{})},
					{Name: "YY", Type: TypeOf("")},
				},
			),
			idx: []int{1},
		},
		{
			rt: StructOf(
				[]StructField{
					{Name: "XX", Type: TypeOf([0]int{})},
					{Name: "YY", Type: TypeOf("")},
					{Name: "ZZ", Type: TypeOf([2]int{})},
				},
			),
			idx: []int{1},
		},
		{
			rt: StructOf(
				[]StructField{
					{Name: "XX", Type: TypeOf([1]int{})},
					{Name: "YY", Type: TypeOf("")},
				},
			),
			idx: []int{1},
		},
		{
			rt: StructOf(
				[]StructField{
					{Name: "XX", Type: TypeOf([1]int{})},
					{Name: "YY", Type: TypeOf("")},
					{Name: "ZZ", Type: TypeOf([1]int{})},
				},
			),
			idx: []int{1},
		},
		{
			rt: StructOf(
				[]StructField{
					{Name: "XX", Type: TypeOf([2]int{})},
					{Name: "YY", Type: TypeOf("")},
					{Name: "ZZ", Type: TypeOf([2]int{})},
				},
			),
			idx: []int{1},
		},
		{
			rt: StructOf(
				[]StructField{
					{Name: "XX", Type: TypeOf(int64(0))},
					{Name: "YY", Type: TypeOf(byte(0))},
					{Name: "ZZ", Type: TypeOf("")},
				},
			),
			idx: []int{2},
		},
		{
			rt: StructOf(
				[]StructField{
					{Name: "XX", Type: TypeOf(int64(0))},
					{Name: "YY", Type: TypeOf(int64(0))},
					{Name: "ZZ", Type: TypeOf("")},
					{Name: "AA", Type: TypeOf([1]int64{})},
				},
			),
			idx: []int{2},
		},
	}

	for _, table := range tests {
		v1 := New(table.rt).Elem()
		v2 := New(table.rt).Elem()

		if !DeepEqual(v1.Interface(), v1.Interface()) {
			t.Errorf("constructed struct %v not equal to itself", v1.Interface())
		}

		v1.FieldByIndex(table.idx).Set(ValueOf("abc"))
		v2.FieldByIndex(table.idx).Set(ValueOf("def"))
		if i1, i2 := v1.Interface(), v2.Interface(); DeepEqual(i1, i2) {
			t.Errorf("constructed structs %v and %v should not be equal", i1, i2)
		}

		abc := "abc"
		v1.FieldByIndex(table.idx).Set(ValueOf(abc))
		val := "+" + abc + "-"
		v2.FieldByIndex(table.idx).Set(ValueOf(val[1:4]))
		if i1, i2 := v1.Interface(), v2.Interface(); !DeepEqual(i1, i2) {
			t.Errorf("constructed structs %v and %v should be equal", i1, i2)
		}

		// Test hash
		m := MakeMap(MapOf(table.rt, TypeOf(int(0))))
		m.SetMapIndex(v1, ValueOf(1))
		if i1, i2 := v1.Interface(), v2.Interface(); !m.MapIndex(v2).IsValid() {
			t.Errorf("constructed structs %#v and %#v have different hashes", i1, i2)
		}

		v2.FieldByIndex(table.idx).Set(ValueOf("abc"))
		if i1, i2 := v1.Interface(), v2.Interface(); !DeepEqual(i1, i2) {
			t.Errorf("constructed structs %v and %v should be equal", i1, i2)
		}

		if i1, i2 := v1.Interface(), v2.Interface(); !m.MapIndex(v2).IsValid() {
			t.Errorf("constructed structs %v and %v have different hashes", i1, i2)
		}
	}
}

func TestStructOfDirectIface(t *testing.T) {
	{
		type T struct{ X [1]*byte }
		i1 := Zero(TypeOf(T{})).Interface()
		v1 := ValueOf(&i1).Elem()
		p1 := v1.InterfaceData()[1]

		i2 := Zero(StructOf([]StructField{
			{
				Name: "X",
				Type: ArrayOf(1, TypeOf((*int8)(nil))),
			},
		})).Interface()
		v2 := ValueOf(&i2).Elem()
		p2 := v2.InterfaceData()[1]

		if p1 != 0 {
			t.Errorf("got p1=%v. want=%v", p1, nil)
		}

		if p2 != 0 {
			t.Errorf("got p2=%v. want=%v", p2, nil)
		}
	}
	{
		type T struct{ X [0]*byte }
		i1 := Zero(TypeOf(T{})).Interface()
		v1 := ValueOf(&i1).Elem()
		p1 := v1.InterfaceData()[1]

		i2 := Zero(StructOf([]StructField{
			{
				Name: "X",
				Type: ArrayOf(0, TypeOf((*int8)(nil))),
			},
		})).Interface()
		v2 := ValueOf(&i2).Elem()
		p2 := v2.InterfaceData()[1]

		if p1 == 0 {
			t.Errorf("got p1=%v. want=not-%v", p1, nil)
		}

		if p2 == 0 {
			t.Errorf("got p2=%v. want=not-%v", p2, nil)
		}
	}
}

type StructI int

func (i StructI) Get() int { return int(i) }

type StructIPtr int

func (i *StructIPtr) Get() int  { return int(*i) }
func (i *StructIPtr) Set(v int) { *(*int)(i) = v }

type SettableStruct struct {
	SettableField int
}

func (p *SettableStruct) Set(v int) { p.SettableField = v }

type SettablePointer struct {
	SettableField *int
}

func (p *SettablePointer) Set(v int) { *p.SettableField = v }

func TestStructOfWithInterface(t *testing.T) {
	const want = 42
	type Iface interface {
		Get() int
	}
	type IfaceSet interface {
		Set(int)
	}
	tests := []struct {
		name string
		typ  Type
		val  Value
		impl bool
	}{
		{
			name: "StructI",
			typ:  TypeOf(StructI(want)),
			val:  ValueOf(StructI(want)),
			impl: true,
		},
		{
			name: "StructI",
			typ:  PointerTo(TypeOf(StructI(want))),
			val: ValueOf(func() any {
				v := StructI(want)
				return &v
			}()),
			impl: true,
		},
		{
			name: "StructIPtr",
			typ:  PointerTo(TypeOf(StructIPtr(want))),
			val: ValueOf(func() any {
				v := StructIPtr(want)
				return &v
			}()),
			impl: true,
		},
		{
			name: "StructIPtr",
			typ:  TypeOf(StructIPtr(want)),
			val:  ValueOf(StructIPtr(want)),
			impl: false,
		},
		// {
		//	typ:  TypeOf((*Iface)(nil)).Elem(), // FIXME(sbinet): fix method.ifn/tfn
		//	val:  ValueOf(StructI(want)),
		//	impl: true,
		// },
	}

	for i, table := range tests {
		for j := 0; j < 2; j++ {
			var fields []StructField
			if j == 1 {
				fields = append(fields, StructField{
					Name:    "Dummy",
					PkgPath: "",
					Type:    TypeOf(int(0)),
				})
			}
			fields = append(fields, StructField{
				Name:      table.name,
				Anonymous: true,
				PkgPath:   "",
				Type:      table.typ,
			})

			// We currently do not correctly implement methods
			// for embedded fields other than the first.
			// Therefore, for now, we expect those methods
			// to not exist.  See issues 15924 and 20824.
			// When those issues are fixed, this test of panic
			// should be removed.
			if j == 1 && table.impl {
				func() {
					defer func() {
						if err := recover(); err == nil {
							t.Errorf("test-%d-%d did not panic", i, j)
						}
					}()
					_ = StructOf(fields)
				}()
				continue
			}

			rt := StructOf(fields)
			rv := New(rt).Elem()
			rv.Field(j).Set(table.val)

			if _, ok := rv.Interface().(Iface); ok != table.impl {
				if table.impl {
					t.Errorf("test-%d-%d: type=%v fails to implement Iface.\n", i, j, table.typ)
				} else {
					t.Errorf("test-%d-%d: type=%v should NOT implement Iface\n", i, j, table.typ)
				}
				continue
			}

			if !table.impl {
				continue
			}

			v := rv.Interface().(Iface).Get()
			if v != want {
				t.Errorf("test-%d-%d: x.Get()=%v. want=%v\n", i, j, v, want)
			}

			fct := rv.MethodByName("Get")
			out := fct.Call(nil)
			if !DeepEqual(out[0].Interface(), want) {
				t.Errorf("test-%d-%d: x.Get()=%v. want=%v\n", i, j, out[0].Interface(), want)
			}
		}
	}

	// Test an embedded nil pointer with pointer methods.
	fields := []StructField{{
		Name:      "StructIPtr",
		Anonymous: true,
		Type:      PointerTo(TypeOf(StructIPtr(want))),
	}}
	rt := StructOf(fields)
	rv := New(rt).Elem()
	// This should panic since the pointer is nil.
	shouldPanic("", func() {
		rv.Interface().(IfaceSet).Set(want)
	})

	// Test an embedded nil pointer to a struct with pointer methods.

	fields = []StructField{{
		Name:      "SettableStruct",
		Anonymous: true,
		Type:      PointerTo(TypeOf(SettableStruct{})),
	}}
	rt = StructOf(fields)
	rv = New(rt).Elem()
	// This should panic since the pointer is nil.
	shouldPanic("", func() {
		rv.Interface().(IfaceSet).Set(want)
	})

	// The behavior is different if there is a second field,
	// since now an interface value holds a pointer to the struct
	// rather than just holding a copy of the struct.
	fields = []StructField{
		{
			Name:      "SettableStruct",
			Anonymous: true,
			Type:      PointerTo(TypeOf(SettableStruct{})),
		},
		{
			Name:      "EmptyStruct",
			Anonymous: true,
			Type:      StructOf(nil),
		},
	}
	// With the current implementation this is expected to panic.
	// Ideally it should work and we should be able to see a panic
	// if we call the Set method.
	shouldPanic("", func() {
		StructOf(fields)
	})

	// Embed a field that can be stored directly in an interface,
	// with a second field.
	fields = []StructField{
		{
			Name:      "SettablePointer",
			Anonymous: true,
			Type:      TypeOf(SettablePointer{}),
		},
		{
			Name:      "EmptyStruct",
			Anonymous: true,
			Type:      StructOf(nil),
		},
	}
	// With the current implementation this is expected to panic.
	// Ideally it should work and we should be able to call the
	// Set and Get methods.
	shouldPanic("", func() {
		StructOf(fields)
	})
}

func TestStructOfTooManyFields(t *testing.T) {
	// Bug Fix: #25402 - this should not panic
	tt := StructOf([]StructField{
		{Name: "Time", Type: TypeOf(time.Time{}), Anonymous: true},
	})

	if _, present := tt.MethodByName("After"); !present {
		t.Errorf("Expected method `After` to be found")
	}
}

func TestStructOfDifferentPkgPath(t *testing.T) {
	fields := []StructField{
		{
			Name:    "f1",
			PkgPath: "p1",
			Type:    TypeOf(int(0)),
		},
		{
			Name:    "f2",
			PkgPath: "p2",
			Type:    TypeOf(int(0)),
		},
	}
	shouldPanic("different PkgPath", func() {
		StructOf(fields)
	})
}

func TestStructOfTooLarge(t *testing.T) {
	t1 := TypeOf(byte(0))
	t2 := TypeOf(int16(0))
	t4 := TypeOf(int32(0))
	t0 := ArrayOf(0, t1)

	// 2^64-3 sized type (or 2^32-3 on 32-bit archs)
	bigType := StructOf([]StructField{
		{Name: "F1", Type: ArrayOf(int(^uintptr(0)>>1), t1)},
		{Name: "F2", Type: ArrayOf(int(^uintptr(0)>>1-1), t1)},
	})

	type test struct {
		shouldPanic bool
		fields      []StructField
	}

	tests := [...]test{
		{
			shouldPanic: false, // 2^64-1, ok
			fields: []StructField{
				{Name: "F1", Type: bigType},
				{Name: "F2", Type: ArrayOf(2, t1)},
			},
		},
		{
			shouldPanic: true, // overflow in total size
			fields: []StructField{
				{Name: "F1", Type: bigType},
				{Name: "F2", Type: ArrayOf(3, t1)},
			},
		},
		{
			shouldPanic: true, // overflow while aligning F2
			fields: []StructField{
				{Name: "F1", Type: bigType},
				{Name: "F2", Type: t4},
			},
		},
		{
			shouldPanic: true, // overflow while adding trailing byte for zero-sized fields
			fields: []StructField{
				{Name: "F1", Type: bigType},
				{Name: "F2", Type: ArrayOf(2, t1)},
				{Name: "F3", Type: t0},
			},
		},
		{
			shouldPanic: true, // overflow while aligning total size
			fields: []StructField{
				{Name: "F1", Type: t2},
				{Name: "F2", Type: bigType},
			},
		},
	}

	for i, tt := range tests {
		func() {
			defer func() {
				err := recover()
				if !tt.shouldPanic {
					if err != nil {
						t.Errorf("test %d should not panic, got %s", i, err)
					}
					return
				}
				if err == nil {
					t.Errorf("test %d expected to panic", i)
					return
				}
				s := fmt.Sprintf("%s", err)
				if s != "reflect.StructOf: struct size would exceed virtual address space" {
					t.Errorf("test %d wrong panic message: %s", i, s)
					return
				}
			}()
			_ = StructOf(tt.fields)
		}()
	}
}

func TestStructOfAnonymous(t *testing.T) {
	var s any = struct{ D1 }{}
	f := TypeOf(s).Field(0)
	ds := StructOf([]StructField{f})
	st := TypeOf(s)
	dt := New(ds).Elem()
	if st != dt.Type() {
		t.Errorf("StructOf returned %s, want %s", dt.Type(), st)
	}

	// This should not panic.
	_ = dt.Interface().(struct{ D1 })
}

func TestChanOf(t *testing.T) {
	// check construction and use of type not in binary
	type T string
	ct := ChanOf(BothDir, TypeOf(T("")))
	v := MakeChan(ct, 2)
	runtime.GC()
	v.Send(ValueOf(T("hello")))
	runtime.GC()
	v.Send(ValueOf(T("world")))
	runtime.GC()

	sv1, _ := v.Recv()
	sv2, _ := v.Recv()
	s1 := sv1.String()
	s2 := sv2.String()
	if s1 != "hello" || s2 != "world" {
		t.Errorf("constructed chan: have %q, %q, want %q, %q", s1, s2, "hello", "world")
	}

	// check that type already in binary is found
	type T1 int
	checkSameType(t, ChanOf(BothDir, TypeOf(T1(1))), (chan T1)(nil))

	// Check arrow token association in undefined chan types.
	var left chan<- chan T
	var right chan (<-chan T)
	tLeft := ChanOf(SendDir, ChanOf(BothDir, TypeOf(T(""))))
	tRight := ChanOf(BothDir, ChanOf(RecvDir, TypeOf(T(""))))
	if tLeft != TypeOf(left) {
		t.Errorf("chan<-chan: have %s, want %T", tLeft, left)
	}
	if tRight != TypeOf(right) {
		t.Errorf("chan<-chan: have %s, want %T", tRight, right)
	}
}

func TestChanOfDir(t *testing.T) {
	// check construction and use of type not in binary
	type T string
	crt := ChanOf(RecvDir, TypeOf(T("")))
	cst := ChanOf(SendDir, TypeOf(T("")))

	// check that type already in binary is found
	type T1 int
	checkSameType(t, ChanOf(RecvDir, TypeOf(T1(1))), (<-chan T1)(nil))
	checkSameType(t, ChanOf(SendDir, TypeOf(T1(1))), (chan<- T1)(nil))

	// check String form of ChanDir
	if crt.ChanDir().String() != "<-chan" {
		t.Errorf("chan dir: have %q, want %q", crt.ChanDir().String(), "<-chan")
	}
	if cst.ChanDir().String() != "chan<-" {
		t.Errorf("chan dir: have %q, want %q", cst.ChanDir().String(), "chan<-")
	}
}

func TestChanOfGC(t *testing.T) {
	done := make(chan bool, 1)
	go func() {
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			panic("deadlock in TestChanOfGC")
		}
	}()

	defer func() {
		done <- true
	}()

	type T *uintptr
	tt := TypeOf(T(nil))
	ct := ChanOf(BothDir,
```