Response:
Let's break down the thought process for analyzing this Go code snippet and generating the answer.

**1. Understanding the Goal:**

The request asks for an analysis of a specific part of `go/src/reflect/all_test.go`. The key requirements are to identify the functionality, provide Go code examples (with input/output), explain command-line argument handling (if any), point out common mistakes, and finally, summarize the overall purpose of the provided section. Since this is part 6 of 7, there's an implied need for a high-level summary, building on the previous parts.

**2. Initial Code Scan and Keyword Identification:**

The first step is to quickly scan the code for recurring patterns, function names, and keywords. This helps establish the general theme. Immediately noticeable are:

* `Test...` functions:  This clearly indicates unit tests.
* `reflect`:  The package name confirms we're dealing with Go's reflection capabilities.
* `MakeChan`, `MakeMap`, `FuncOf`, `MapOf`: These are core reflection functions for creating new types and values dynamically.
* `ValueOf`, `TypeOf`:  Essential reflection functions for examining existing values and types.
* `Send`, `Recv`, `SetMapIndex`, `MapKeys`, `MapIndex`, `Call`:  Methods for interacting with dynamically created channels, maps, and functions.
* `runtime.GC()`:  Explicit calls to the garbage collector suggest testing interactions with GC.
* `t.Errorf`, `t.Fatalf`:  Standard Go testing functions.
* Type definitions like `type K string`, `type V float64`, and various struct definitions.

**3. Grouping Functionality by Test Function:**

The code is organized into test functions. This is the most logical way to break down the analysis:

* **`TestChanOfGC`:** Deals with creating channels of pointer types and how the garbage collector interacts with them. The use of `uintptr` and saving pointers to channels in a slice `x` are key indicators.
* **`TestMapOf`:** Focuses on creating maps with various key/value types, including those not statically defined in the binary. It also checks for error conditions (invalid key types).
* **`TestMapOfGCKeys`:** Similar to `TestChanOfGC`, but for maps with pointer keys. It verifies that map keys are correctly retrieved after garbage collection.
* **`TestMapOfGCBigKey`:** Tests maps with keys larger than the word size, again with a focus on GC interaction.
* **`TestMapOfGCValues`:**  Tests maps where the *values* are pointers and how they survive GC.
* **`TestTypelinksSorted`:** Checks if the output of `reflect.TypeLinks()` is sorted. This relates to the internal organization of type information.
* **`TestFuncOf`:** Explores the dynamic creation of functions using `reflect.FuncOf` and `reflect.MakeFunc`. It covers different function signatures (including variadic) and calling these dynamically created functions.
* **`TestEmbed`:** Tests the behavior of embedded structs and accessing fields. Specifically, it checks that you can't directly access fields of an uninitialized embedded pointer.
* **`TestAllocsInterfaceBig` & `TestAllocsInterfaceSmall`:** These are micro-benchmarks that measure the number of allocations when converting values to `interface{}` using `ValueOf(...).Interface()`. They distinguish between small and large types.
* **`exhaustive` struct and its methods:** This defines a custom testing mechanism for exploring different combinations of choices, effectively a form of randomized/exhaustive testing.
* **`TestReflectFuncTraceback` & `TestReflectMethodTraceback`:** These tests seem related to debugging or error handling, likely verifying that stack traces are correctly generated when calling reflected functions or methods.
* **`TestSmallZero` & `TestBigZero`:** Tests the `reflect.Zero()` function, which creates zero values for a given type. It differentiates between small and large types.
* **`TestZeroSet`:** Checks if you can correctly set a struct field to its zero value using `reflect.Zero()`.
* **`TestFieldByIndexNil`:**  Specifically tests the behavior of `FieldByName` when dealing with nil embedded pointers.
* **`TestCallMethodJump` & `TestCallArgLive`:** These are complex tests dealing with potential issues related to garbage collection and the interaction of reflection calls with method dispatch and argument passing. They highlight potential pitfalls when using reflection with pointers and GC.
* **`TestMakeFuncStackCopy`:** Investigates how `MakeFunc` handles stack allocation and potential issues when the target function uses a significant amount of stack.
* **`TestValueString`:**  Tests the `String()` method of `reflect.Value` for different kinds of values (concrete types and methods).
* **`TestInvalid`:** Focuses on the `IsValid()` and `Kind()` methods for `reflect.Value`, particularly when dealing with uninitialized interface values.
* **`TestLarge`:**  Likely tests calling functions with large arguments.
* **`TestTypeFieldOutOfRangePanic`:**  Verifies that `Type.Field(index)` panics correctly for out-of-bounds indices.
* **`TestTypeFieldReadOnly`:** Checks that the `Index` field of `reflect.StructField` is read-only.
* **`TestCallGC`:**  Another test related to GC interaction during reflected function calls, likely focusing on how arguments are handled.
* **`TestKeepFuncLive` & `TestKeepMethodLive`:** These are crucial tests for ensuring that internal reflection structures (like `makeFuncImpl` and `methodValue`) are kept alive by the garbage collector as long as they are in use.
* **`TestMethodByNameUnExportedFirst`:** Tests that `MethodByName` can find exported methods even if unexported methods appear earlier in the method list.
* **`TestFuncLayout`:** A detailed test that examines the memory layout of function arguments and return values as determined by `reflect.FuncLayout`.
* **`TestGCBits`:**  A very extensive set of tests verifying the correctness of GC pointer bitmaps generated by the `reflect` package for various types and combinations of types (arrays, slices, channels, maps, pointers, functions).
* **`TestTypeOfTypeOf`:** Confirms that type constructors in `reflect` return concrete `*reflect.rtype` values.
* **`TestPtrToMethods`:** Checks that pointers to structs with embedded types correctly implement interfaces of the embedded type.
* **`TestMapAlloc`:**  A performance test to measure the number of allocations during map assignments.

**4. Code Example Construction (with Input/Output):**

For each test function group, think of a concise Go code example that demonstrates the core functionality being tested. The examples should be simple and illustrative. Focus on the key reflection functions and their behavior. Where applicable, provide a plausible input and the expected output.

**5. Identifying Command-Line Argument Handling:**

Carefully examine the code for any usage of `os.Args`, `flag` package, or other mechanisms for parsing command-line arguments. In this specific snippet, there's no explicit handling of command-line arguments.

**6. Spotting Potential Pitfalls (Common Mistakes):**

Think about how a developer might misuse the reflection features being tested. Common mistakes often involve:

* Incorrectly handling `nil` values with reflection.
* Forgetting that dynamically created types and functions exist only at runtime.
* Not understanding the interaction between reflection and the garbage collector (e.g., objects being prematurely collected).
* Trying to modify read-only parts of reflection objects.
* Making assumptions about the memory layout of types.

**7. Synthesizing the Overall Functionality:**

After analyzing each test function, step back and identify the overarching goal of this section of `all_test.go`. It's clearly focused on testing the core reflection functionalities related to dynamic type and value creation, manipulation, and inspection. The heavy emphasis on garbage collection interactions is also a crucial aspect.

**8. Structuring the Answer:**

Organize the findings in a clear and structured manner, following the prompts in the original request. Use headings, bullet points, and code blocks to improve readability. Provide clear explanations and link the code examples back to the functionalities being described.

**Self-Correction/Refinement during the Process:**

* **Initial thought:** "This is just testing basic reflection."  **Correction:** Realize the significant focus on GC interactions and more advanced reflection features like `FuncLayout`.
* **Initial thought:** "Need to explain every single line of code." **Correction:** Focus on the *purpose* of each test function and provide illustrative examples, not exhaustive line-by-line analysis.
* **Initial thought:** "Are there any command-line flags?" **Correction:**  A careful scan reveals no explicit command-line argument handling within this specific snippet.
* **Initial thought:** "Just list the test function names." **Correction:** Group related test functions by the functionality they are testing for better clarity.

By following these steps, combining close code examination with a higher-level understanding of Go's reflection capabilities and testing practices, we can generate a comprehensive and accurate analysis of the provided code snippet.
```chinese
这是第6部分，让我们来归纳一下 `go/src/reflect/all_test.go` 的这个代码片段的功能。

**功能归纳：**

这个代码片段主要集中在测试 `reflect` 包中用于动态创建和操作各种 Go 类型的核心功能，并特别关注这些功能与 Go 运行时（尤其是垃圾回收器 GC）的交互。  具体来说，它测试了以下几个方面：

1. **动态创建复合类型：**
   - **通道 (Channel):**  测试使用 `reflect.MakeChan` 创建通道，并通过 `Send` 和 `Recv` 方法发送和接收数据。 特别关注了当通道元素是指针类型时，GC 的行为。
   - **映射 (Map):** 测试使用 `reflect.MakeMap` 和 `reflect.MapOf` 创建映射，包括键和值类型不在编译时确定的情况。测试了 `SetMapIndex` 设置键值对， `MapKeys` 获取所有键，以及 `MapIndex` 获取特定键的值。同样，也重点测试了键和值为指针类型时 GC 的影响，以及键类型大小超过机器字长的情况。
   - **函数 (Function):** 测试使用 `reflect.FuncOf` 创建函数类型，并使用 `reflect.MakeFunc` 创建函数实例。测试了不同函数签名（包括变参函数）的创建和调用。

2. **类型信息的获取和比较：**
   - 测试 `reflect.TypeOf` 的使用，以及 `reflect.MapOf` 和 `reflect.FuncOf` 是否能够正确地找到已存在于二进制文件中的类型。
   - 测试 `reflect.TypeLinks()` 返回的类型链接是否已排序。

3. **反射与垃圾回收 (GC) 的交互：**
   - 多个测试用例 (`TestChanOfGC`, `TestMapOfGCKeys`, `TestMapOfGCValues`, `TestMapOfGCBigKey`) 专门用于验证当动态创建的类型（如通道和映射）的元素或键是指针类型时，GC 是否能正确处理这些类型的数据，防止数据丢失。这些测试会显式调用 `runtime.GC()` 来触发垃圾回收。

4. **反射操作的边界情况和错误处理：**
   - 测试创建映射时使用无效的键类型是否会触发 panic。
   - 测试访问结构体字段时的边界情况，例如使用 `FieldByName` 访问 nil 指针指向的嵌入结构体的字段。
   - 测试 `Type.Field(index)` 在索引超出范围时是否会 panic。

5. **反射的性能和内存分配：**
   - `TestAllocsInterfaceBig` 和 `TestAllocsInterfaceSmall` 测试了将 `reflect.Value` 转换为 `interface{}` 时的内存分配情况。
   - `TestMapAlloc` 测试了映射赋值操作的内存分配情况。
   - `TestSmallZero` 和 `TestBigZero` 测试了 `reflect.Zero()` 函数创建零值时的内存分配情况。

6. **反射与其他运行时功能的交互：**
   - 测试了反射调用函数和方法时，是否能够正确生成调用堆栈信息 (`TestReflectFuncTraceback`, `TestReflectMethodTraceback`)。
   - `TestCallMethodJump` 和 `TestCallArgLive` 涉及到反射调用方法时，参数传递和 GC 的复杂交互，旨在发现潜在的内存安全问题。
   - `TestMakeFuncStackCopy` 测试了使用 `MakeFunc` 创建的函数在栈上的行为。

7. **其他反射功能测试：**
   - 测试了 `reflect.Value` 的 `String()` 方法的输出。
   - 测试了 `reflect.IsValid()` 和 `reflect.Kind()` 对于无效 `reflect.Value` 的行为。
   - 测试了 `reflect.Zero()` 函数的 `Set` 方法。
   - 测试了 `reflect.FuncLayout` 函数，用于获取函数布局信息。
   - 测试了 `reflect.GCBits` 函数，用于获取类型的 GC 位图信息。

**基于代码的推理和 Go 代码示例：**

由于代码片段主要是测试用例，我们很难直接推理出一个正在实现的特定的“Go语言功能”。相反，它测试的是 `reflect` 包中已有的多个功能。

**示例 1：动态创建和使用通道**

```go
package main

import (
	"fmt"
	"reflect"
)

func main() {
	// 假设输入：想创建一个 string 类型的通道
	chanType := reflect.ChanOf(reflect.BothDir, reflect.TypeOf(""))

	// 动态创建通道
	ch := reflect.MakeChan(chanType, 10)

	// 发送数据
	sendValue := reflect.ValueOf("Hello, Reflection!")
	ch.Send(sendValue)

	// 接收数据
	receivedValue, ok := ch.Recv()
	if ok {
		fmt.Println("Received:", receivedValue.String()) // 输出: Received: Hello, Reflection!
	}
}
```

**示例 2：动态创建和使用映射**

```go
package main

import (
	"fmt"
	"reflect"
)

func main() {
	// 假设输入：想创建一个 map[string]int 类型的映射
	mapType := reflect.MapOf(reflect.TypeOf(""), reflect.TypeOf(0))

	// 动态创建映射
	m := reflect.MakeMap(mapType)

	// 设置键值对
	key := reflect.ValueOf("the answer")
	value := reflect.ValueOf(42)
	m.SetMapIndex(key, value)

	// 获取值
	retrievedValue := m.MapIndex(key)
	if retrievedValue.IsValid() {
		fmt.Println("Value:", retrievedValue.Int()) // 输出: Value: 42
	}
}
```

**示例 3：动态创建和调用函数**

```go
package main

import (
	"fmt"
	"reflect"
)

func add(a, b int) int {
	return a + b
}

func main() {
	// 假设输入：想动态创建一个与 add 函数签名相同的函数
	funcType := reflect.TypeOf(add)

	// 创建一个包装函数，它将接收到的 reflect.Value 转换为实际参数并调用 add
	makeAdd := reflect.MakeFunc(funcType, func(in []reflect.Value) []reflect.Value {
		a := int(in[0].Int())
		b := int(in[1].Int())
		result := add(a, b)
		return []reflect.Value{reflect.ValueOf(result)}
	})

	// 调用动态创建的函数
	args := []reflect.Value{reflect.ValueOf(5), reflect.ValueOf(3)}
	results := makeAdd.Call(args)

	fmt.Println("Result:", results[0].Int()) // 输出: Result: 8
}
```

**命令行参数的具体处理：**

在这个代码片段中，没有看到任何显式处理命令行参数的代码。`go test` 工具通常会处理测试相关的命令行参数，但这些参数不会直接在这个测试文件内部被解析和使用。

**使用者易犯错的点：**

这个代码片段中的测试用例也暗示了一些使用 `reflect` 时容易犯错的地方：

1. **对 nil 值的反射操作：** 尝试对 nil 指针或 nil 接口值进行某些反射操作可能会导致 panic。例如，在 `TestFieldByIndexNil` 中，尝试访问 nil 指针指向的嵌入结构体的字段就会 panic。
2. **不理解反射的运行时特性：** 动态创建的类型和函数只存在于运行时，编译时无法进行类型检查。这增加了出错的可能性。
3. **错误地假设内存布局：** 在涉及到 `unsafe` 包或者进行底层操作时，错误地假设类型的内存布局可能导致程序崩溃或数据损坏。虽然这个片段没有直接使用 `unsafe`，但对指针的理解在反射中至关重要。
4. **忘记处理 `reflect.Value` 的 `IsValid()` 方法：** 在从 `reflect.Value` 中提取数据之前，应该检查 `IsValid()` 的返回值，以确保 `reflect.Value` 包含有效的值。
5. **与垃圾回收的交互：** 如测试用例所示，当反射操作涉及到指针类型时，需要特别注意垃圾回收的行为，避免对象被意外回收。

**总结：**

总的来说，这个 `go/src/reflect/all_test.go` 的代码片段是 `reflect` 包功能测试的一个重要组成部分，它全面地测试了动态类型创建、值操作以及与 Go 运行时的交互，特别是强调了在处理指针类型时与垃圾回收的协同工作。这些测试用例帮助确保 `reflect` 包的正确性和稳定性，并为开发者提供了如何安全有效地使用反射功能的示例。
```
Prompt: 
```
这是路径为go/src/reflect/all_test.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第6部分，共7部分，请归纳一下它的功能

"""
 tt)

	// NOTE: The garbage collector handles allocated channels specially,
	// so we have to save pointers to channels in x; the pointer code will
	// use the gc info in the newly constructed chan type.
	const n = 100
	var x []any
	for i := 0; i < n; i++ {
		v := MakeChan(ct, n)
		for j := 0; j < n; j++ {
			p := new(uintptr)
			*p = uintptr(i*n + j)
			v.Send(ValueOf(p).Convert(tt))
		}
		pv := New(ct)
		pv.Elem().Set(v)
		x = append(x, pv.Interface())
	}
	runtime.GC()

	for i, xi := range x {
		v := ValueOf(xi).Elem()
		for j := 0; j < n; j++ {
			pv, _ := v.Recv()
			k := pv.Elem().Interface()
			if k != uintptr(i*n+j) {
				t.Errorf("lost x[%d][%d] = %d, want %d", i, j, k, i*n+j)
			}
		}
	}
}

func TestMapOf(t *testing.T) {
	// check construction and use of type not in binary
	type K string
	type V float64

	v := MakeMap(MapOf(TypeOf(K("")), TypeOf(V(0))))
	runtime.GC()
	v.SetMapIndex(ValueOf(K("a")), ValueOf(V(1)))
	runtime.GC()

	s := fmt.Sprint(v.Interface())
	want := "map[a:1]"
	if s != want {
		t.Errorf("constructed map = %s, want %s", s, want)
	}

	// check that type already in binary is found
	checkSameType(t, MapOf(TypeOf(V(0)), TypeOf(K(""))), map[V]K(nil))

	// check that invalid key type panics
	shouldPanic("invalid key type", func() { MapOf(TypeOf((func())(nil)), TypeOf(false)) })
}

func TestMapOfGCKeys(t *testing.T) {
	type T *uintptr
	tt := TypeOf(T(nil))
	mt := MapOf(tt, TypeOf(false))

	// NOTE: The garbage collector handles allocated maps specially,
	// so we have to save pointers to maps in x; the pointer code will
	// use the gc info in the newly constructed map type.
	const n = 100
	var x []any
	for i := 0; i < n; i++ {
		v := MakeMap(mt)
		for j := 0; j < n; j++ {
			p := new(uintptr)
			*p = uintptr(i*n + j)
			v.SetMapIndex(ValueOf(p).Convert(tt), ValueOf(true))
		}
		pv := New(mt)
		pv.Elem().Set(v)
		x = append(x, pv.Interface())
	}
	runtime.GC()

	for i, xi := range x {
		v := ValueOf(xi).Elem()
		var out []int
		for _, kv := range v.MapKeys() {
			out = append(out, int(kv.Elem().Interface().(uintptr)))
		}
		slices.Sort(out)
		for j, k := range out {
			if k != i*n+j {
				t.Errorf("lost x[%d][%d] = %d, want %d", i, j, k, i*n+j)
			}
		}
	}
}

// Test assignment and access to a map with keys larger than word size.
func TestMapOfGCBigKey(t *testing.T) {
	type KV struct {
		i int64
		j int64
	}

	kvTyp := TypeFor[KV]()
	mt := MapOf(kvTyp, kvTyp)

	const n = 100
	m := MakeMap(mt)
	for i := 0; i < n; i++ {
		kv := KV{int64(i), int64(i+1)}
		m.SetMapIndex(ValueOf(kv), ValueOf(kv))
	}

	for i := 0; i < n; i++ {
		kv := KV{int64(i), int64(i+1)}
		elem := m.MapIndex(ValueOf(kv)).Interface().(KV)
		if elem != kv {
			t.Errorf("lost m[%v] = %v, want %v", kv, elem, kv)
		}
	}
}

func TestMapOfGCValues(t *testing.T) {
	type T *uintptr
	tt := TypeOf(T(nil))
	mt := MapOf(TypeOf(1), tt)

	// NOTE: The garbage collector handles allocated maps specially,
	// so we have to save pointers to maps in x; the pointer code will
	// use the gc info in the newly constructed map type.
	const n = 100
	var x []any
	for i := 0; i < n; i++ {
		v := MakeMap(mt)
		for j := 0; j < n; j++ {
			p := new(uintptr)
			*p = uintptr(i*n + j)
			v.SetMapIndex(ValueOf(j), ValueOf(p).Convert(tt))
		}
		pv := New(mt)
		pv.Elem().Set(v)
		x = append(x, pv.Interface())
	}
	runtime.GC()

	for i, xi := range x {
		v := ValueOf(xi).Elem()
		for j := 0; j < n; j++ {
			k := v.MapIndex(ValueOf(j)).Elem().Interface().(uintptr)
			if k != uintptr(i*n+j) {
				t.Errorf("lost x[%d][%d] = %d, want %d", i, j, k, i*n+j)
			}
		}
	}
}

func TestTypelinksSorted(t *testing.T) {
	var last string
	for i, n := range TypeLinks() {
		if n < last {
			t.Errorf("typelinks not sorted: %q [%d] > %q [%d]", last, i-1, n, i)
		}
		last = n
	}
}

func TestFuncOf(t *testing.T) {
	// check construction and use of type not in binary
	type K string
	type V float64

	fn := func(args []Value) []Value {
		if len(args) != 1 {
			t.Errorf("args == %v, want exactly one arg", args)
		} else if args[0].Type() != TypeOf(K("")) {
			t.Errorf("args[0] is type %v, want %v", args[0].Type(), TypeOf(K("")))
		} else if args[0].String() != "gopher" {
			t.Errorf("args[0] = %q, want %q", args[0].String(), "gopher")
		}
		return []Value{ValueOf(V(3.14))}
	}
	v := MakeFunc(FuncOf([]Type{TypeOf(K(""))}, []Type{TypeOf(V(0))}, false), fn)

	outs := v.Call([]Value{ValueOf(K("gopher"))})
	if len(outs) != 1 {
		t.Fatalf("v.Call returned %v, want exactly one result", outs)
	} else if outs[0].Type() != TypeOf(V(0)) {
		t.Fatalf("c.Call[0] is type %v, want %v", outs[0].Type(), TypeOf(V(0)))
	}
	f := outs[0].Float()
	if f != 3.14 {
		t.Errorf("constructed func returned %f, want %f", f, 3.14)
	}

	// check that types already in binary are found
	type T1 int
	testCases := []struct {
		in, out  []Type
		variadic bool
		want     any
	}{
		{in: []Type{TypeOf(T1(0))}, want: (func(T1))(nil)},
		{in: []Type{TypeOf(int(0))}, want: (func(int))(nil)},
		{in: []Type{SliceOf(TypeOf(int(0)))}, variadic: true, want: (func(...int))(nil)},
		{in: []Type{TypeOf(int(0))}, out: []Type{TypeOf(false)}, want: (func(int) bool)(nil)},
		{in: []Type{TypeOf(int(0))}, out: []Type{TypeOf(false), TypeOf("")}, want: (func(int) (bool, string))(nil)},
	}
	for _, tt := range testCases {
		checkSameType(t, FuncOf(tt.in, tt.out, tt.variadic), tt.want)
	}

	// check that variadic requires last element be a slice.
	FuncOf([]Type{TypeOf(1), TypeOf(""), SliceOf(TypeOf(false))}, nil, true)
	shouldPanic("must be slice", func() { FuncOf([]Type{TypeOf(0), TypeOf(""), TypeOf(false)}, nil, true) })
	shouldPanic("must be slice", func() { FuncOf(nil, nil, true) })

	//testcase for  #54669
	var in []Type
	for i := 0; i < 51; i++ {
		in = append(in, TypeOf(1))
	}
	FuncOf(in, nil, false)
}

type R0 struct {
	*R1
	*R2
	*R3
	*R4
}

type R1 struct {
	*R5
	*R6
	*R7
	*R8
}

type R2 R1
type R3 R1
type R4 R1

type R5 struct {
	*R9
	*R10
	*R11
	*R12
}

type R6 R5
type R7 R5
type R8 R5

type R9 struct {
	*R13
	*R14
	*R15
	*R16
}

type R10 R9
type R11 R9
type R12 R9

type R13 struct {
	*R17
	*R18
	*R19
	*R20
}

type R14 R13
type R15 R13
type R16 R13

type R17 struct {
	*R21
	*R22
	*R23
	*R24
}

type R18 R17
type R19 R17
type R20 R17

type R21 struct {
	X int
}

type R22 R21
type R23 R21
type R24 R21

func TestEmbed(t *testing.T) {
	typ := TypeOf(R0{})
	f, ok := typ.FieldByName("X")
	if ok {
		t.Fatalf(`FieldByName("X") should fail, returned %v`, f.Index)
	}
}

func TestAllocsInterfaceBig(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping malloc count in short mode")
	}
	v := ValueOf(S{})
	if allocs := testing.AllocsPerRun(100, func() { v.Interface() }); allocs > 0 {
		t.Error("allocs:", allocs)
	}
}

func TestAllocsInterfaceSmall(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping malloc count in short mode")
	}
	v := ValueOf(int64(0))
	if allocs := testing.AllocsPerRun(100, func() { v.Interface() }); allocs > 0 {
		t.Error("allocs:", allocs)
	}
}

// An exhaustive is a mechanism for writing exhaustive or stochastic tests.
// The basic usage is:
//
//	for x.Next() {
//		... code using x.Maybe() or x.Choice(n) to create test cases ...
//	}
//
// Each iteration of the loop returns a different set of results, until all
// possible result sets have been explored. It is okay for different code paths
// to make different method call sequences on x, but there must be no
// other source of non-determinism in the call sequences.
//
// When faced with a new decision, x chooses randomly. Future explorations
// of that path will choose successive values for the result. Thus, stopping
// the loop after a fixed number of iterations gives somewhat stochastic
// testing.
//
// Example:
//
//	for x.Next() {
//		v := make([]bool, x.Choose(4))
//		for i := range v {
//			v[i] = x.Maybe()
//		}
//		fmt.Println(v)
//	}
//
// prints (in some order):
//
//	[]
//	[false]
//	[true]
//	[false false]
//	[false true]
//	...
//	[true true]
//	[false false false]
//	...
//	[true true true]
//	[false false false false]
//	...
//	[true true true true]
type exhaustive struct {
	r    *rand.Rand
	pos  int
	last []choice
}

type choice struct {
	off int
	n   int
	max int
}

func (x *exhaustive) Next() bool {
	if x.r == nil {
		x.r = rand.New(rand.NewSource(time.Now().UnixNano()))
	}
	x.pos = 0
	if x.last == nil {
		x.last = []choice{}
		return true
	}
	for i := len(x.last) - 1; i >= 0; i-- {
		c := &x.last[i]
		if c.n+1 < c.max {
			c.n++
			x.last = x.last[:i+1]
			return true
		}
	}
	return false
}

func (x *exhaustive) Choose(max int) int {
	if x.pos >= len(x.last) {
		x.last = append(x.last, choice{x.r.Intn(max), 0, max})
	}
	c := &x.last[x.pos]
	x.pos++
	if c.max != max {
		panic("inconsistent use of exhaustive tester")
	}
	return (c.n + c.off) % max
}

func (x *exhaustive) Maybe() bool {
	return x.Choose(2) == 1
}

func GCFunc(args []Value) []Value {
	runtime.GC()
	return []Value{}
}

func TestReflectFuncTraceback(t *testing.T) {
	f := MakeFunc(TypeOf(func() {}), GCFunc)
	f.Call([]Value{})
}

func TestReflectMethodTraceback(t *testing.T) {
	p := Point{3, 4}
	m := ValueOf(p).MethodByName("GCMethod")
	i := ValueOf(m.Interface()).Call([]Value{ValueOf(5)})[0].Int()
	if i != 8 {
		t.Errorf("Call returned %d; want 8", i)
	}
}

func TestSmallZero(t *testing.T) {
	type T [10]byte
	typ := TypeOf(T{})
	if allocs := testing.AllocsPerRun(100, func() { Zero(typ) }); allocs > 0 {
		t.Errorf("Creating small zero values caused %f allocs, want 0", allocs)
	}
}

func TestBigZero(t *testing.T) {
	const size = 1 << 10
	var v [size]byte
	z := Zero(ValueOf(v).Type()).Interface().([size]byte)
	for i := 0; i < size; i++ {
		if z[i] != 0 {
			t.Fatalf("Zero object not all zero, index %d", i)
		}
	}
}

func TestZeroSet(t *testing.T) {
	type T [16]byte
	type S struct {
		a uint64
		T T
		b uint64
	}
	v := S{
		a: 0xaaaaaaaaaaaaaaaa,
		T: T{9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9},
		b: 0xbbbbbbbbbbbbbbbb,
	}
	ValueOf(&v).Elem().Field(1).Set(Zero(TypeOf(T{})))
	if v != (S{
		a: 0xaaaaaaaaaaaaaaaa,
		b: 0xbbbbbbbbbbbbbbbb,
	}) {
		t.Fatalf("Setting a field to a Zero value didn't work")
	}
}

func TestFieldByIndexNil(t *testing.T) {
	type P struct {
		F int
	}
	type T struct {
		*P
	}
	v := ValueOf(T{})

	v.FieldByName("P") // should be fine

	defer func() {
		if err := recover(); err == nil {
			t.Fatalf("no error")
		} else if !strings.Contains(fmt.Sprint(err), "nil pointer to embedded struct") {
			t.Fatalf(`err=%q, wanted error containing "nil pointer to embedded struct"`, err)
		}
	}()
	v.FieldByName("F") // should panic

	t.Fatalf("did not panic")
}

// Given
//	type Outer struct {
//		*Inner
//		...
//	}
// the compiler generates the implementation of (*Outer).M dispatching to the embedded Inner.
// The implementation is logically:
//	func (p *Outer) M() {
//		(p.Inner).M()
//	}
// but since the only change here is the replacement of one pointer receiver with another,
// the actual generated code overwrites the original receiver with the p.Inner pointer and
// then jumps to the M method expecting the *Inner receiver.
//
// During reflect.Value.Call, we create an argument frame and the associated data structures
// to describe it to the garbage collector, populate the frame, call reflect.call to
// run a function call using that frame, and then copy the results back out of the frame.
// The reflect.call function does a memmove of the frame structure onto the
// stack (to set up the inputs), runs the call, and the memmoves the stack back to
// the frame structure (to preserve the outputs).
//
// Originally reflect.call did not distinguish inputs from outputs: both memmoves
// were for the full stack frame. However, in the case where the called function was
// one of these wrappers, the rewritten receiver is almost certainly a different type
// than the original receiver. This is not a problem on the stack, where we use the
// program counter to determine the type information and understand that
// during (*Outer).M the receiver is an *Outer while during (*Inner).M the receiver in the same
// memory word is now an *Inner. But in the statically typed argument frame created
// by reflect, the receiver is always an *Outer. Copying the modified receiver pointer
// off the stack into the frame will store an *Inner there, and then if a garbage collection
// happens to scan that argument frame before it is discarded, it will scan the *Inner
// memory as if it were an *Outer. If the two have different memory layouts, the
// collection will interpret the memory incorrectly.
//
// One such possible incorrect interpretation is to treat two arbitrary memory words
// (Inner.P1 and Inner.P2 below) as an interface (Outer.R below). Because interpreting
// an interface requires dereferencing the itab word, the misinterpretation will try to
// deference Inner.P1, causing a crash during garbage collection.
//
// This came up in a real program in issue 7725.

type Outer struct {
	*Inner
	R io.Reader
}

type Inner struct {
	X  *Outer
	P1 uintptr
	P2 uintptr
}

func (pi *Inner) M() {
	// Clear references to pi so that the only way the
	// garbage collection will find the pointer is in the
	// argument frame, typed as a *Outer.
	pi.X.Inner = nil

	// Set up an interface value that will cause a crash.
	// P1 = 1 is a non-zero, so the interface looks non-nil.
	// P2 = pi ensures that the data word points into the
	// allocated heap; if not the collection skips the interface
	// value as irrelevant, without dereferencing P1.
	pi.P1 = 1
	pi.P2 = uintptr(unsafe.Pointer(pi))
}

func TestCallMethodJump(t *testing.T) {
	// In reflect.Value.Call, trigger a garbage collection after reflect.call
	// returns but before the args frame has been discarded.
	// This is a little clumsy but makes the failure repeatable.
	*CallGC = true

	p := &Outer{Inner: new(Inner)}
	p.Inner.X = p
	ValueOf(p).Method(0).Call(nil)

	// Stop garbage collecting during reflect.call.
	*CallGC = false
}

func TestCallArgLive(t *testing.T) {
	type T struct{ X, Y *string } // pointerful aggregate

	F := func(t T) { *t.X = "ok" }

	// In reflect.Value.Call, trigger a garbage collection in reflect.call
	// between marshaling argument and the actual call.
	*CallGC = true

	x := new(string)
	runtime.SetFinalizer(x, func(p *string) {
		if *p != "ok" {
			t.Errorf("x dead prematurely")
		}
	})
	v := T{x, nil}

	ValueOf(F).Call([]Value{ValueOf(v)})

	// Stop garbage collecting during reflect.call.
	*CallGC = false
}

func TestMakeFuncStackCopy(t *testing.T) {
	target := func(in []Value) []Value {
		runtime.GC()
		useStack(16)
		return []Value{ValueOf(9)}
	}

	var concrete func(*int, int) int
	fn := MakeFunc(ValueOf(concrete).Type(), target)
	ValueOf(&concrete).Elem().Set(fn)
	x := concrete(nil, 7)
	if x != 9 {
		t.Errorf("have %#q want 9", x)
	}
}

// use about n KB of stack
func useStack(n int) {
	if n == 0 {
		return
	}
	var b [1024]byte // makes frame about 1KB
	useStack(n - 1 + int(b[99]))
}

type Impl struct{}

func (Impl) F() {}

func TestValueString(t *testing.T) {
	rv := ValueOf(Impl{})
	if rv.String() != "<reflect_test.Impl Value>" {
		t.Errorf("ValueOf(Impl{}).String() = %q, want %q", rv.String(), "<reflect_test.Impl Value>")
	}

	method := rv.Method(0)
	if method.String() != "<func() Value>" {
		t.Errorf("ValueOf(Impl{}).Method(0).String() = %q, want %q", method.String(), "<func() Value>")
	}
}

func TestInvalid(t *testing.T) {
	// Used to have inconsistency between IsValid() and Kind() != Invalid.
	type T struct{ v any }

	v := ValueOf(T{}).Field(0)
	if v.IsValid() != true || v.Kind() != Interface {
		t.Errorf("field: IsValid=%v, Kind=%v, want true, Interface", v.IsValid(), v.Kind())
	}
	v = v.Elem()
	if v.IsValid() != false || v.Kind() != Invalid {
		t.Errorf("field elem: IsValid=%v, Kind=%v, want false, Invalid", v.IsValid(), v.Kind())
	}
}

// Issue 8917.
func TestLarge(t *testing.T) {
	fv := ValueOf(func([256]*byte) {})
	fv.Call([]Value{ValueOf([256]*byte{})})
}

func fieldIndexRecover(t Type, i int) (recovered any) {
	defer func() {
		recovered = recover()
	}()

	t.Field(i)
	return
}

// Issue 15046.
func TestTypeFieldOutOfRangePanic(t *testing.T) {
	typ := TypeOf(struct{ X int }{10})
	testIndices := [...]struct {
		i         int
		mustPanic bool
	}{
		0: {-2, true},
		1: {0, false},
		2: {1, true},
		3: {1 << 10, true},
	}
	for i, tt := range testIndices {
		recoveredErr := fieldIndexRecover(typ, tt.i)
		if tt.mustPanic {
			if recoveredErr == nil {
				t.Errorf("#%d: fieldIndex %d expected to panic", i, tt.i)
			}
		} else {
			if recoveredErr != nil {
				t.Errorf("#%d: got err=%v, expected no panic", i, recoveredErr)
			}
		}
	}
}

func TestTypeFieldReadOnly(t *testing.T) {
	if runtime.GOOS == "js" || runtime.GOOS == "wasip1" {
		// This is OK because we don't use the optimization
		// for js or wasip1.
		t.Skip("test does not fault on GOOS=js")
	}

	// It's important that changing one StructField.Index
	// value not affect other StructField.Index values.
	// Right now StructField.Index is read-only;
	// that saves allocations but is otherwise not important.
	typ := TypeFor[struct{ f int }]()
	f := typ.Field(0)
	defer debug.SetPanicOnFault(debug.SetPanicOnFault(true))
	shouldPanic("", func() {
		f.Index[0] = 1
	})
}

// Issue 9179.
func TestCallGC(t *testing.T) {
	f := func(a, b, c, d, e string) {
	}
	g := func(in []Value) []Value {
		runtime.GC()
		return nil
	}
	typ := ValueOf(f).Type()
	f2 := MakeFunc(typ, g).Interface().(func(string, string, string, string, string))
	f2("four", "five5", "six666", "seven77", "eight888")
}

// Issue 18635 (function version).
func TestKeepFuncLive(t *testing.T) {
	// Test that we keep makeFuncImpl live as long as it is
	// referenced on the stack.
	typ := TypeOf(func(i int) {})
	var f, g func(in []Value) []Value
	f = func(in []Value) []Value {
		clobber()
		i := int(in[0].Int())
		if i > 0 {
			// We can't use Value.Call here because
			// runtime.call* will keep the makeFuncImpl
			// alive. However, by converting it to an
			// interface value and calling that,
			// reflect.callReflect is the only thing that
			// can keep the makeFuncImpl live.
			//
			// Alternate between f and g so that if we do
			// reuse the memory prematurely it's more
			// likely to get obviously corrupted.
			MakeFunc(typ, g).Interface().(func(i int))(i - 1)
		}
		return nil
	}
	g = func(in []Value) []Value {
		clobber()
		i := int(in[0].Int())
		MakeFunc(typ, f).Interface().(func(i int))(i)
		return nil
	}
	MakeFunc(typ, f).Call([]Value{ValueOf(10)})
}

type UnExportedFirst int

func (i UnExportedFirst) ΦExported()  {}
func (i UnExportedFirst) unexported() {}

// Issue 21177
func TestMethodByNameUnExportedFirst(t *testing.T) {
	defer func() {
		if recover() != nil {
			t.Errorf("should not panic")
		}
	}()
	typ := TypeOf(UnExportedFirst(0))
	m, _ := typ.MethodByName("ΦExported")
	if m.Name != "ΦExported" {
		t.Errorf("got %s, expected ΦExported", m.Name)
	}
}

// Issue 18635 (method version).
type KeepMethodLive struct{}

func (k KeepMethodLive) Method1(i int) {
	clobber()
	if i > 0 {
		ValueOf(k).MethodByName("Method2").Interface().(func(i int))(i - 1)
	}
}

func (k KeepMethodLive) Method2(i int) {
	clobber()
	ValueOf(k).MethodByName("Method1").Interface().(func(i int))(i)
}

func TestKeepMethodLive(t *testing.T) {
	// Test that we keep methodValue live as long as it is
	// referenced on the stack.
	KeepMethodLive{}.Method1(10)
}

// clobber tries to clobber unreachable memory.
func clobber() {
	runtime.GC()
	for i := 1; i < 32; i++ {
		for j := 0; j < 10; j++ {
			obj := make([]*byte, i)
			sink = obj
		}
	}
	runtime.GC()
}

func TestFuncLayout(t *testing.T) {
	align := func(x uintptr) uintptr {
		return (x + goarch.PtrSize - 1) &^ (goarch.PtrSize - 1)
	}
	var r []byte
	if goarch.PtrSize == 4 {
		r = []byte{0, 0, 0, 1}
	} else {
		r = []byte{0, 0, 1}
	}

	type S struct {
		a, b uintptr
		c, d *byte
	}

	type test struct {
		rcvr, typ                  Type
		size, argsize, retOffset   uintptr
		stack, gc, inRegs, outRegs []byte // pointer bitmap: 1 is pointer, 0 is scalar
		intRegs, floatRegs         int
		floatRegSize               uintptr
	}
	tests := []test{
		{
			typ:       ValueOf(func(a, b string) string { return "" }).Type(),
			size:      6 * goarch.PtrSize,
			argsize:   4 * goarch.PtrSize,
			retOffset: 4 * goarch.PtrSize,
			stack:     []byte{1, 0, 1, 0, 1},
			gc:        []byte{1, 0, 1, 0, 1},
		},
		{
			typ:       ValueOf(func(a, b, c uint32, p *byte, d uint16) {}).Type(),
			size:      align(align(3*4) + goarch.PtrSize + 2),
			argsize:   align(3*4) + goarch.PtrSize + 2,
			retOffset: align(align(3*4) + goarch.PtrSize + 2),
			stack:     r,
			gc:        r,
		},
		{
			typ:       ValueOf(func(a map[int]int, b uintptr, c any) {}).Type(),
			size:      4 * goarch.PtrSize,
			argsize:   4 * goarch.PtrSize,
			retOffset: 4 * goarch.PtrSize,
			stack:     []byte{1, 0, 1, 1},
			gc:        []byte{1, 0, 1, 1},
		},
		{
			typ:       ValueOf(func(a S) {}).Type(),
			size:      4 * goarch.PtrSize,
			argsize:   4 * goarch.PtrSize,
			retOffset: 4 * goarch.PtrSize,
			stack:     []byte{0, 0, 1, 1},
			gc:        []byte{0, 0, 1, 1},
		},
		{
			rcvr:      ValueOf((*byte)(nil)).Type(),
			typ:       ValueOf(func(a uintptr, b *int) {}).Type(),
			size:      3 * goarch.PtrSize,
			argsize:   3 * goarch.PtrSize,
			retOffset: 3 * goarch.PtrSize,
			stack:     []byte{1, 0, 1},
			gc:        []byte{1, 0, 1},
		},
		{
			typ:       ValueOf(func(a uintptr) {}).Type(),
			size:      goarch.PtrSize,
			argsize:   goarch.PtrSize,
			retOffset: goarch.PtrSize,
			stack:     []byte{},
			gc:        []byte{},
		},
		{
			typ:       ValueOf(func() uintptr { return 0 }).Type(),
			size:      goarch.PtrSize,
			argsize:   0,
			retOffset: 0,
			stack:     []byte{},
			gc:        []byte{},
		},
		{
			rcvr:      ValueOf(uintptr(0)).Type(),
			typ:       ValueOf(func(a uintptr) {}).Type(),
			size:      2 * goarch.PtrSize,
			argsize:   2 * goarch.PtrSize,
			retOffset: 2 * goarch.PtrSize,
			stack:     []byte{1},
			gc:        []byte{1},
			// Note: this one is tricky, as the receiver is not a pointer. But we
			// pass the receiver by reference to the autogenerated pointer-receiver
			// version of the function.
		},
		// TODO(mknyszek): Add tests for non-zero register count.
	}
	for _, lt := range tests {
		name := lt.typ.String()
		if lt.rcvr != nil {
			name = lt.rcvr.String() + "." + name
		}
		t.Run(name, func(t *testing.T) {
			defer SetArgRegs(SetArgRegs(lt.intRegs, lt.floatRegs, lt.floatRegSize))

			typ, argsize, retOffset, stack, gc, inRegs, outRegs, ptrs := FuncLayout(lt.typ, lt.rcvr)
			if typ.Size() != lt.size {
				t.Errorf("funcLayout(%v, %v).size=%d, want %d", lt.typ, lt.rcvr, typ.Size(), lt.size)
			}
			if argsize != lt.argsize {
				t.Errorf("funcLayout(%v, %v).argsize=%d, want %d", lt.typ, lt.rcvr, argsize, lt.argsize)
			}
			if retOffset != lt.retOffset {
				t.Errorf("funcLayout(%v, %v).retOffset=%d, want %d", lt.typ, lt.rcvr, retOffset, lt.retOffset)
			}
			if !bytes.Equal(stack, lt.stack) {
				t.Errorf("funcLayout(%v, %v).stack=%v, want %v", lt.typ, lt.rcvr, stack, lt.stack)
			}
			if !bytes.Equal(gc, lt.gc) {
				t.Errorf("funcLayout(%v, %v).gc=%v, want %v", lt.typ, lt.rcvr, gc, lt.gc)
			}
			if !bytes.Equal(inRegs, lt.inRegs) {
				t.Errorf("funcLayout(%v, %v).inRegs=%v, want %v", lt.typ, lt.rcvr, inRegs, lt.inRegs)
			}
			if !bytes.Equal(outRegs, lt.outRegs) {
				t.Errorf("funcLayout(%v, %v).outRegs=%v, want %v", lt.typ, lt.rcvr, outRegs, lt.outRegs)
			}
			if ptrs && len(stack) == 0 || !ptrs && len(stack) > 0 {
				t.Errorf("funcLayout(%v, %v) pointers flag=%v, want %v", lt.typ, lt.rcvr, ptrs, !ptrs)
			}
		})
	}
}

// trimBitmap removes trailing 0 elements from b and returns the result.
func trimBitmap(b []byte) []byte {
	for len(b) > 0 && b[len(b)-1] == 0 {
		b = b[:len(b)-1]
	}
	return b
}

func verifyGCBits(t *testing.T, typ Type, bits []byte) {
	heapBits := GCBits(New(typ).Interface())

	// Trim scalars at the end, as bits might end in zero,
	// e.g. with rep(2, lit(1, 0)).
	bits = trimBitmap(bits)

	if bytes.HasPrefix(heapBits, bits) {
		// Just the prefix matching is OK.
		//
		// The Go runtime's pointer/scalar iterator generates pointers beyond
		// the size of the type, up to the size of the size class. This space
		// is safe for the GC to scan since it's zero, and GCBits checks to
		// make sure that's true. But we need to handle the fact that the bitmap
		// may be larger than we expect.
		return
	}
	_, _, line, _ := runtime.Caller(1)
	t.Errorf("line %d: heapBits incorrect for %v\nhave %v\nwant %v", line, typ, heapBits, bits)
}

func verifyGCBitsSlice(t *testing.T, typ Type, cap int, bits []byte) {
	// Creating a slice causes the runtime to repeat a bitmap,
	// which exercises a different path from making the compiler
	// repeat a bitmap for a small array or executing a repeat in
	// a GC program.
	val := MakeSlice(typ, 0, cap)
	data := NewAt(typ.Elem(), val.UnsafePointer())
	heapBits := GCBits(data.Interface())
	// Repeat the bitmap for the slice size, trimming scalars in
	// the last element.
	bits = trimBitmap(rep(cap, bits))
	if bytes.Equal(heapBits, bits) {
		return
	}
	if len(heapBits) > len(bits) && bytes.Equal(heapBits[:len(bits)], bits) {
		// Just the prefix matching is OK.
		return
	}
	_, _, line, _ := runtime.Caller(1)
	t.Errorf("line %d: heapBits incorrect for make(%v, 0, %v)\nhave %v\nwant %v", line, typ, cap, heapBits, bits)
}

// Building blocks for types seen by the compiler (like [2]Xscalar).
// The compiler will create the type structures for the derived types,
// including their GC metadata.
type Xscalar struct{ x uintptr }
type Xptr struct{ x *byte }
type Xptrscalar struct {
	*byte
	uintptr
}
type Xscalarptr struct {
	uintptr
	*byte
}
type Xbigptrscalar struct {
	_ [100]*byte
	_ [100]uintptr
}

var Tscalar, Tint64, Tptr, Tscalarptr, Tptrscalar, Tbigptrscalar Type

func init() {
	// Building blocks for types constructed by reflect.
	// This code is in a separate block so that code below
	// cannot accidentally refer to these.
	// The compiler must NOT see types derived from these
	// (for example, [2]Scalar must NOT appear in the program),
	// or else reflect will use it instead of having to construct one.
	// The goal is to test the construction.
	type Scalar struct{ x uintptr }
	type Ptr struct{ x *byte }
	type Ptrscalar struct {
		*byte
		uintptr
	}
	type Scalarptr struct {
		uintptr
		*byte
	}
	type Bigptrscalar struct {
		_ [100]*byte
		_ [100]uintptr
	}
	type Int64 int64
	Tscalar = TypeOf(Scalar{})
	Tint64 = TypeOf(Int64(0))
	Tptr = TypeOf(Ptr{})
	Tscalarptr = TypeOf(Scalarptr{})
	Tptrscalar = TypeOf(Ptrscalar{})
	Tbigptrscalar = TypeOf(Bigptrscalar{})
}

var empty = []byte{}

func TestGCBits(t *testing.T) {
	verifyGCBits(t, TypeOf((*byte)(nil)), []byte{1})

	verifyGCBits(t, TypeOf(Xscalar{}), empty)
	verifyGCBits(t, Tscalar, empty)
	verifyGCBits(t, TypeOf(Xptr{}), lit(1))
	verifyGCBits(t, Tptr, lit(1))
	verifyGCBits(t, TypeOf(Xscalarptr{}), lit(0, 1))
	verifyGCBits(t, Tscalarptr, lit(0, 1))
	verifyGCBits(t, TypeOf(Xptrscalar{}), lit(1))
	verifyGCBits(t, Tptrscalar, lit(1))

	verifyGCBits(t, TypeOf([0]Xptr{}), empty)
	verifyGCBits(t, ArrayOf(0, Tptr), empty)
	verifyGCBits(t, TypeOf([1]Xptrscalar{}), lit(1))
	verifyGCBits(t, ArrayOf(1, Tptrscalar), lit(1))
	verifyGCBits(t, TypeOf([2]Xscalar{}), empty)
	verifyGCBits(t, ArrayOf(2, Tscalar), empty)
	verifyGCBits(t, TypeOf([10000]Xscalar{}), empty)
	verifyGCBits(t, ArrayOf(10000, Tscalar), empty)
	verifyGCBits(t, TypeOf([2]Xptr{}), lit(1, 1))
	verifyGCBits(t, ArrayOf(2, Tptr), lit(1, 1))
	verifyGCBits(t, TypeOf([10000]Xptr{}), rep(10000, lit(1)))
	verifyGCBits(t, ArrayOf(10000, Tptr), rep(10000, lit(1)))
	verifyGCBits(t, TypeOf([2]Xscalarptr{}), lit(0, 1, 0, 1))
	verifyGCBits(t, ArrayOf(2, Tscalarptr), lit(0, 1, 0, 1))
	verifyGCBits(t, TypeOf([10000]Xscalarptr{}), rep(10000, lit(0, 1)))
	verifyGCBits(t, ArrayOf(10000, Tscalarptr), rep(10000, lit(0, 1)))
	verifyGCBits(t, TypeOf([2]Xptrscalar{}), lit(1, 0, 1))
	verifyGCBits(t, ArrayOf(2, Tptrscalar), lit(1, 0, 1))
	verifyGCBits(t, TypeOf([10000]Xptrscalar{}), rep(10000, lit(1, 0)))
	verifyGCBits(t, ArrayOf(10000, Tptrscalar), rep(10000, lit(1, 0)))
	verifyGCBits(t, TypeOf([1][10000]Xptrscalar{}), rep(10000, lit(1, 0)))
	verifyGCBits(t, ArrayOf(1, ArrayOf(10000, Tptrscalar)), rep(10000, lit(1, 0)))
	verifyGCBits(t, TypeOf([2][10000]Xptrscalar{}), rep(2*10000, lit(1, 0)))
	verifyGCBits(t, ArrayOf(2, ArrayOf(10000, Tptrscalar)), rep(2*10000, lit(1, 0)))
	verifyGCBits(t, TypeOf([4]Xbigptrscalar{}), join(rep(3, join(rep(100, lit(1)), rep(100, lit(0)))), rep(100, lit(1))))
	verifyGCBits(t, ArrayOf(4, Tbigptrscalar), join(rep(3, join(rep(100, lit(1)), rep(100, lit(0)))), rep(100, lit(1))))

	verifyGCBitsSlice(t, TypeOf([]Xptr{}), 0, empty)
	verifyGCBitsSlice(t, SliceOf(Tptr), 0, empty)
	verifyGCBitsSlice(t, TypeOf([]Xptrscalar{}), 1, lit(1))
	verifyGCBitsSlice(t, SliceOf(Tptrscalar), 1, lit(1))
	verifyGCBitsSlice(t, TypeOf([]Xscalar{}), 2, lit(0))
	verifyGCBitsSlice(t, SliceOf(Tscalar), 2, lit(0))
	verifyGCBitsSlice(t, TypeOf([]Xscalar{}), 10000, lit(0))
	verifyGCBitsSlice(t, SliceOf(Tscalar), 10000, lit(0))
	verifyGCBitsSlice(t, TypeOf([]Xptr{}), 2, lit(1))
	verifyGCBitsSlice(t, SliceOf(Tptr), 2, lit(1))
	verifyGCBitsSlice(t, TypeOf([]Xptr{}), 10000, lit(1))
	verifyGCBitsSlice(t, SliceOf(Tptr), 10000, lit(1))
	verifyGCBitsSlice(t, TypeOf([]Xscalarptr{}), 2, lit(0, 1))
	verifyGCBitsSlice(t, SliceOf(Tscalarptr), 2, lit(0, 1))
	verifyGCBitsSlice(t, TypeOf([]Xscalarptr{}), 10000, lit(0, 1))
	verifyGCBitsSlice(t, SliceOf(Tscalarptr), 10000, lit(0, 1))
	verifyGCBitsSlice(t, TypeOf([]Xptrscalar{}), 2, lit(1, 0))
	verifyGCBitsSlice(t, SliceOf(Tptrscalar), 2, lit(1, 0))
	verifyGCBitsSlice(t, TypeOf([]Xptrscalar{}), 10000, lit(1, 0))
	verifyGCBitsSlice(t, SliceOf(Tptrscalar), 10000, lit(1, 0))
	verifyGCBitsSlice(t, TypeOf([][10000]Xptrscalar{}), 1, rep(10000, lit(1, 0)))
	verifyGCBitsSlice(t, SliceOf(ArrayOf(10000, Tptrscalar)), 1, rep(10000, lit(1, 0)))
	verifyGCBitsSlice(t, TypeOf([][10000]Xptrscalar{}), 2, rep(10000, lit(1, 0)))
	verifyGCBitsSlice(t, SliceOf(ArrayOf(10000, Tptrscalar)), 2, rep(10000, lit(1, 0)))
	verifyGCBitsSlice(t, TypeOf([]Xbigptrscalar{}), 4, join(rep(100, lit(1)), rep(100, lit(0))))
	verifyGCBitsSlice(t, SliceOf(Tbigptrscalar), 4, join(rep(100, lit(1)), rep(100, lit(0))))

	verifyGCBits(t, TypeOf((chan [100]Xscalar)(nil)), lit(1))
	verifyGCBits(t, ChanOf(BothDir, ArrayOf(100, Tscalar)), lit(1))

	verifyGCBits(t, TypeOf((func([10000]Xscalarptr))(nil)), lit(1))
	verifyGCBits(t, FuncOf([]Type{ArrayOf(10000, Tscalarptr)}, nil, false), lit(1))

	verifyGCBits(t, TypeOf((map[[10000]Xscalarptr]Xscalar)(nil)), lit(1))
	verifyGCBits(t, MapOf(ArrayOf(10000, Tscalarptr), Tscalar), lit(1))

	verifyGCBits(t, TypeOf((*[10000]Xscalar)(nil)), lit(1))
	verifyGCBits(t, PointerTo(ArrayOf(10000, Tscalar)), lit(1))

	verifyGCBits(t, TypeOf(([][10000]Xscalar)(nil)), lit(1))
	verifyGCBits(t, SliceOf(ArrayOf(10000, Tscalar)), lit(1))

	testGCBitsMap(t)
}

func rep(n int, b []byte) []byte { return bytes.Repeat(b, n) }
func join(b ...[]byte) []byte    { return bytes.Join(b, nil) }
func lit(x ...byte) []byte       { return x }

func TestTypeOfTypeOf(t *testing.T) {
	// Check that all the type constructors return concrete *rtype implementations.
	// It's difficult to test directly because the reflect package is only at arm's length.
	// The easiest thing to do is just call a function that crashes if it doesn't get an *rtype.
	check := func(name string, typ Type) {
		if underlying := TypeOf(typ).String(); underlying != "*reflect.rtype" {
			t.Errorf("%v returned %v, not *reflect.rtype", name, underlying)
		}
	}

	type T struct{ int }
	check("TypeOf", TypeOf(T{}))

	check("ArrayOf", ArrayOf(10, TypeOf(T{})))
	check("ChanOf", ChanOf(BothDir, TypeOf(T{})))
	check("FuncOf", FuncOf([]Type{TypeOf(T{})}, nil, false))
	check("MapOf", MapOf(TypeOf(T{}), TypeOf(T{})))
	check("PtrTo", PointerTo(TypeOf(T{})))
	check("SliceOf", SliceOf(TypeOf(T{})))
}

type XM struct{ _ bool }

func (*XM) String() string { return "" }

func TestPtrToMethods(t *testing.T) {
	var y struct{ XM }
	yp := New(TypeOf(y)).Interface()
	_, ok := yp.(fmt.Stringer)
	if !ok {
		t.Fatal("does not implement Stringer, but should")
	}
}

func TestMapAlloc(t *testing.T) {
	if asan.Enabled {
		t.Skip("test allocates more with -asan; see #70079")
	}
	m := ValueOf(make(map[int]int, 10))
	k := ValueOf(5)
	v := ValueOf(7)
	allocs := testing.AllocsPerRun(100, func() {
		m.SetMapIndex(k, v)
	})
	if allocs > 0.5 {
		t.Errorf("allocs per map assignment: want 0 got %f", allocs)
	}

	const size = 1000
	tmp := 0
	val := ValueOf(&tmp).Elem()
	allocs = testing
"""




```