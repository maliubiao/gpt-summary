Response:
Let's break down the thought process for analyzing this Go code snippet.

**1. Understanding the Goal:**

The prompt asks for the functionality of the provided Go code snippet, which is part of `go/src/reflect/all_test.go`. It also requests examples, code reasoning, command-line argument handling (though absent here), and potential pitfalls. Crucially, it's labeled as part 2 of 7, and specifically asks for a summary of this part's functionality.

**2. Initial Scan and Keyword Spotting:**

The first step is a quick scan for recognizable Go keywords and function names that hint at the code's purpose. Keywords like `func`, `struct`, `for`, `if`, `switch`, and function names like `Test...`, `Nil`, `NotNil`, `IsNil`, `IsZero`, `Select`, `Chan`, `Map`, `Func`, `Method`, `Call`, `MakeFunc` stand out. These immediately suggest testing functionalities related to reflection.

**3. Grouping by Functionality:**

Based on the initial scan, I can start grouping related test functions:

* **Nil Checks:** `Nil`, `NotNil`, `TestIsNil` clearly deal with checking for nil values of various types.
* **Zero Checks:** `TestIsZero`, `TestInternalIsZero` are about determining if a value is its zero value.
* **Interface Handling:** `TestInterfaceExtraction`, `TestNilPtrValueSub` touch upon how interfaces and nil pointers are handled in reflection.
* **Map Operations:** `TestMap`, `TestNilMap` test reflection operations on maps (length, key iteration, value lookup, setting values).
* **Channel Operations:** `TestChan` focuses on sending, receiving, closing, and other channel operations via reflection.
* **Select Statement:** `TestSelect`, `TestSelectMaxCases`, `TestSelectNop` are dedicated to testing the `reflect.Select` functionality.
* **Function Calls:** `TestFunc`, `TestCallConvert`, `TestCallWithStruct`, `TestCallReturnsEmpty`, `TestMakeFunc`, `TestMakeFuncInterface`, `TestMakeFuncVariadic`, `TestMakeFuncValidReturnAssignments`, `TestMakeFuncInvalidReturnAssignments` all revolve around testing the `reflect.Call` and `reflect.MakeFunc` functionalities.
* **Method Calls:** `TestMethod` tests calling methods on structs and pointers using reflection.

**4. Deeper Dive into Each Group:**

Now, I'll examine the code within each group more carefully:

* **Nil Checks:** Notice the use of `ValueOf`, `Field(0)`, `IsNil()`. The tests iterate through various types that can be nil (pointers, interfaces, maps, funcs, chans, slices, unsafe.Pointers). The `Nil` and `NotNil` helper functions provide concise assertions.
* **Zero Checks:** `IsZero()` is the central function being tested. The test cases cover a wide range of primitive types, arrays, chans, funcs, interfaces, maps, pointers, slices, strings, and structs. The use of `Zero(TypeOf(tt.x))` confirms the concept of zero values. `TestInternalIsZero` appears to be an internal test, possibly for optimization.
* **Interface Handling:** `TestInterfaceExtraction` checks if `Interface()` on an interface returns the correct value. `TestNilPtrValueSub` verifies that accessing the `Elem()` of a nil pointer is invalid.
* **Map Operations:** The `TestMap` function demonstrates `Len()`, `MapKeys()`, `MapIndex()`, `SetMapIndex()`, and setting a map to nil using reflection. `TestNilMap` specifically tests operations on nil maps.
* **Channel Operations:**  `TestChan` covers sending and receiving values using `Send()` and `Recv()`, non-blocking operations `TrySend()` and `TryRecv()`, and closing channels with `Close()`. It tests both making channels directly and via `MakeChan()`.
* **Select Statement:** `TestSelect` is quite complex. It uses an exhaustive iterator (`exhaustive`) to generate various combinations of `SelectCase`s. It tests sending, receiving, blocking, default cases, nil channels, closed channels, and includes a watchdog to detect deadlocks. `TestSelectMaxCases` and `TestSelectNop` are simpler tests for edge cases.
* **Function Calls:**  `TestFunc` demonstrates basic `Call()` with different argument types. The other `TestCall...` functions explore calling functions with interfaces, structs (empty and non-empty), and scenarios related to garbage collection. `TestMakeFunc` shows how to dynamically create functions using `MakeFunc` and various aspects like interfaces and variadic arguments.
* **Method Calls:** `TestMethod` covers calling methods via `Method()` and `MethodByName()` on both values and pointers, including curried method calls.

**5. Identifying Key Concepts and Go Features:**

From this analysis, the core Go features being tested are clearly related to reflection:

* **`reflect.TypeOf()`:** Getting the type of a variable.
* **`reflect.ValueOf()`:** Getting the `reflect.Value` of a variable.
* **`reflect.Zero()`:** Getting the zero value of a type.
* **`reflect.Value.Kind()`:** Determining the kind of value.
* **`reflect.Value.IsNil()`:** Checking if a value is nil.
* **`reflect.Value.IsZero()`:** Checking if a value is the zero value.
* **`reflect.Value.Field()`:** Accessing struct fields.
* **`reflect.Value.Interface()`:** Getting the underlying interface value.
* **`reflect.MakeMap()`:** Creating a new map.
* **`reflect.Value.Len()`:** Getting the length of an array, slice, or map.
* **`reflect.Value.MapKeys()`:** Getting the keys of a map.
* **`reflect.Value.MapIndex()`:** Accessing a value in a map.
* **`reflect.Value.SetMapIndex()`:** Setting a value in a map.
* **`reflect.MakeChan()`:** Creating a new channel.
* **`reflect.Value.Send()`:** Sending a value to a channel.
* **`reflect.Value.Recv()`:** Receiving a value from a channel.
* **`reflect.Value.TrySend()`:** Attempting to send a value to a channel without blocking.
* **`reflect.Value.TryRecv()`:** Attempting to receive a value from a channel without blocking.
* **`reflect.Value.Close()`:** Closing a channel.
* **`reflect.Select()`:** Implementing a select statement using reflection.
* **`reflect.Value.Call()`:** Calling a function or method.
* **`reflect.MakeFunc()`:** Creating a new function.
* **`reflect.Value.Method()`:** Getting a method by index.
* **`reflect.Value.MethodByName()`:** Getting a method by name.

**6. Synthesizing the Functionality Summary:**

Based on the detailed analysis, I can now formulate a concise summary of the code's functionality. The key is to focus on the *purpose* of these tests, which is to verify the correctness of the reflection package.

**7. Considering Examples, Reasoning, and Pitfalls:**

While analyzing, I keep an eye out for scenarios that would make good examples or highlight potential pitfalls. For instance, the `TestIsNil` function provides excellent examples of how `IsNil` works for different types. The `TestSelect` function, though complex, showcases the nuances of the `reflect.Select` functionality. Potential pitfalls, like trying to access `Elem()` on a nil pointer, become apparent during analysis.

**8. Addressing the "Part 2 of 7" Aspect:**

Finally, the prompt explicitly mentions this is part 2 of 7. This reinforces the idea that this section focuses on specific reflection capabilities. The summary should reflect this, indicating that it covers a subset of the overall reflection package's testing.

This detailed breakdown and iterative refinement process allows me to generate a comprehensive and accurate answer to the prompt.
这是 `go/src/reflect/all_test.go` 文件的一部分，主要集中在 **测试 Go 语言反射包 `reflect` 的核心功能**。 从提供的代码片段来看，它测试了以下 `reflect` 包的功能：

**1. 结构体字段偏移量计算:**

*   `TestFieldOffset`:  这个函数测试了 `reflect` 包计算结构体字段偏移量的能力。它创建了嵌套的结构体，并使用 `unsafe.Pointer` 来计算实际的偏移量，然后使用 `reflect` 包的 `Type.Field(i).Offset` 来验证计算结果是否正确。
    *   **代码推理解释:**  `reflect` 包需要准确知道结构体内部字段的内存布局，这样才能通过反射来访问和操作这些字段。这个测试确保了 `reflect` 包能正确计算出每个字段相对于结构体起始地址的偏移量。

**2. `IsNil()` 方法的测试:**

*   `TestIsNil`:  这个函数测试了 `reflect.Value` 的 `IsNil()` 方法，用于判断一个 `reflect.Value` 是否为 nil。它涵盖了多种可以为 nil 的类型，例如指针、接口、map、func、channel、slice 和 unsafe.Pointer。
    *   **代码举例说明:**
        ```go
        package main

        import (
            "fmt"
            "reflect"
        )

        func main() {
            var p *int
            vp := reflect.ValueOf(p)
            fmt.Println("Is pointer nil:", vp.IsNil()) // 输出: Is pointer nil: true

            var m map[string]int
            vm := reflect.ValueOf(m)
            fmt.Println("Is map nil:", vm.IsNil())   // 输出: Is map nil: true

            s := []int{}
            vs := reflect.ValueOf(s)
            fmt.Println("Is slice nil:", vs.IsNil()) // 输出: Is slice nil: false (空切片不是 nil)
        }
        ```
        *   **假设输入与输出:** 上面的代码创建了一个 nil 指针 `p`，一个 nil map `m` 和一个空切片 `s`。通过 `reflect.ValueOf` 获取它们的 `reflect.Value`，然后使用 `IsNil()` 方法判断是否为 nil。输出结果如注释所示。

**3. `IsZero()` 方法的测试:**

*   `TestIsZero`: 这个函数测试了 `reflect.Value` 的 `IsZero()` 方法，用于判断一个 `reflect.Value` 是否是其类型的零值。它测试了各种基本类型、数组、channel、func、interface、map、指针、slice、string 和 struct。
    *   **代码举例说明:**
        ```go
        package main

        import (
            "fmt"
            "reflect"
        )

        func main() {
            var i int
            vi := reflect.ValueOf(i)
            fmt.Println("Is int zero:", vi.IsZero()) // 输出: Is int zero: true

            var s string
            vs := reflect.ValueOf(s)
            fmt.Println("Is string zero:", vs.IsZero()) // 输出: Is string zero: true

            m := make(map[string]int)
            vm := reflect.ValueOf(m)
            fmt.Println("Is map zero:", vm.IsZero())   // 输出: Is map zero: false (即使是空 map 也是分配了内存的)
        }
        ```
        *   **假设输入与输出:** 上面的代码创建了一个零值 int `i`，一个零值 string `s` 和一个空的 map `m`。通过 `reflect.ValueOf` 获取它们的 `reflect.Value`，然后使用 `IsZero()` 方法判断是否为零值。输出结果如注释所示。

**4. 内部 `InternalIsZero()` 函数的测试:**

*   `TestInternalIsZero`:  这个函数测试了一个内部函数 `InternalIsZero`，它可能用于更高效地检查字节切片是否全部为零。这通常用于优化目的。

**5. 接口类型的提取:**

*   `TestInterfaceExtraction`:  这个函数测试了从包含接口类型字段的结构体中提取接口值的能力。它确保通过 `reflect` 获取到的接口值与原始接口值相同。

**6. 对 nil 指针 `Value` 调用 `Elem()` 的行为:**

*   `TestNilPtrValueSub`:  这个函数测试了当对表示 nil 指针的 `reflect.Value` 调用 `Elem()` 方法时，返回的 `Value` 是无效的 (`IsValid()` 返回 false)。

**总结第 2 部分的功能:**

总的来说，这部分代码专注于 **测试 `reflect` 包中关于值状态判断的核心功能**，包括：

*   **判断值的 nil 状态 (`IsNil()`)**，适用于多种可以为 nil 的类型。
*   **判断值是否为其类型的零值 (`IsZero()`)**，覆盖了各种基本和复合类型。
*   **测试结构体字段偏移量的计算**，这是反射访问结构体字段的基础。
*   **测试从结构体中提取接口值的能力。**
*   **验证对 nil 指针 `Value` 进行 `Elem()` 操作的行为。**

这些功能是 `reflect` 包的基础，对于运行时检查和操作 Go 程序的类型信息至关重要。 这部分测试确保了这些核心功能的正确性和可靠性。

### 提示词
```
这是路径为go/src/reflect/all_test.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第2部分，共7部分，请归纳一下它的功能
```

### 源代码
```go
afe.Pointer(&x)), t)

	x1 := T2{T2inner{2, 3}, 17}
	check2ndField(x1, uintptr(unsafe.Pointer(&x1.f))-uintptr(unsafe.Pointer(&x1)), t)
}

func Nil(a any, t *testing.T) {
	n := ValueOf(a).Field(0)
	if !n.IsNil() {
		t.Errorf("%v should be nil", a)
	}
}

func NotNil(a any, t *testing.T) {
	n := ValueOf(a).Field(0)
	if n.IsNil() {
		t.Errorf("value of type %v should not be nil", ValueOf(a).Type().String())
	}
}

func TestIsNil(t *testing.T) {
	// These implement IsNil.
	// Wrap in extra struct to hide interface type.
	doNil := []any{
		struct{ x *int }{},
		struct{ x any }{},
		struct{ x map[string]int }{},
		struct{ x func() bool }{},
		struct{ x chan int }{},
		struct{ x []string }{},
		struct{ x unsafe.Pointer }{},
	}
	for _, ts := range doNil {
		ty := TypeOf(ts).Field(0).Type
		v := Zero(ty)
		v.IsNil() // panics if not okay to call
	}

	// Check the implementations
	var pi struct {
		x *int
	}
	Nil(pi, t)
	pi.x = new(int)
	NotNil(pi, t)

	var si struct {
		x []int
	}
	Nil(si, t)
	si.x = make([]int, 10)
	NotNil(si, t)

	var ci struct {
		x chan int
	}
	Nil(ci, t)
	ci.x = make(chan int)
	NotNil(ci, t)

	var mi struct {
		x map[int]int
	}
	Nil(mi, t)
	mi.x = make(map[int]int)
	NotNil(mi, t)

	var ii struct {
		x any
	}
	Nil(ii, t)
	ii.x = 2
	NotNil(ii, t)

	var fi struct {
		x func(t *testing.T)
	}
	Nil(fi, t)
	fi.x = TestIsNil
	NotNil(fi, t)
}

func setField[S, V any](in S, offset uintptr, value V) (out S) {
	*(*V)(unsafe.Add(unsafe.Pointer(&in), offset)) = value
	return in
}

func TestIsZero(t *testing.T) {
	for i, tt := range []struct {
		x    any
		want bool
	}{
		// Booleans
		{true, false},
		{false, true},
		// Numeric types
		{int(0), true},
		{int(1), false},
		{int8(0), true},
		{int8(1), false},
		{int16(0), true},
		{int16(1), false},
		{int32(0), true},
		{int32(1), false},
		{int64(0), true},
		{int64(1), false},
		{uint(0), true},
		{uint(1), false},
		{uint8(0), true},
		{uint8(1), false},
		{uint16(0), true},
		{uint16(1), false},
		{uint32(0), true},
		{uint32(1), false},
		{uint64(0), true},
		{uint64(1), false},
		{float32(0), true},
		{float32(1.2), false},
		{float64(0), true},
		{float64(1.2), false},
		{math.Copysign(0, -1), true},
		{complex64(0), true},
		{complex64(1.2), false},
		{complex128(0), true},
		{complex128(1.2), false},
		{complex(math.Copysign(0, -1), 0), true},
		{complex(0, math.Copysign(0, -1)), true},
		{complex(math.Copysign(0, -1), math.Copysign(0, -1)), true},
		{uintptr(0), true},
		{uintptr(128), false},
		// Array
		{Zero(TypeOf([5]string{})).Interface(), true},
		{[5]string{}, true},                     // comparable array
		{[5]string{"", "", "", "a", ""}, false}, // comparable array
		{[1]*int{}, true},                       // direct pointer array
		{[1]*int{new(int)}, false},              // direct pointer array
		{[3][]int{}, true},                      // incomparable array
		{[3][]int{{1}}, false},                  // incomparable array
		{[1 << 12]byte{}, true},
		{[1 << 12]byte{1}, false},
		{[1]struct{ p *int }{}, true},
		{[1]struct{ p *int }{{new(int)}}, false},
		{[3]Value{}, true},
		{[3]Value{{}, ValueOf(0), {}}, false},
		// Chan
		{(chan string)(nil), true},
		{make(chan string), false},
		{time.After(1), false},
		// Func
		{(func())(nil), true},
		{New, false},
		// Interface
		{New(TypeOf(new(error)).Elem()).Elem(), true},
		{(io.Reader)(strings.NewReader("")), false},
		// Map
		{(map[string]string)(nil), true},
		{map[string]string{}, false},
		{make(map[string]string), false},
		// Pointer
		{(*func())(nil), true},
		{(*int)(nil), true},
		{new(int), false},
		// Slice
		{[]string{}, false},
		{([]string)(nil), true},
		{make([]string, 0), false},
		// Strings
		{"", true},
		{"not-zero", false},
		// Structs
		{T{}, true},                           // comparable struct
		{T{123, 456.75, "hello", &_i}, false}, // comparable struct
		{struct{ p *int }{}, true},            // direct pointer struct
		{struct{ p *int }{new(int)}, false},   // direct pointer struct
		{struct{ s []int }{}, true},           // incomparable struct
		{struct{ s []int }{[]int{1}}, false},  // incomparable struct
		{struct{ Value }{}, true},
		{struct{ Value }{ValueOf(0)}, false},
		{struct{ _, a, _ uintptr }{}, true}, // comparable struct with blank fields
		{setField(struct{ _, a, _ uintptr }{}, 0*unsafe.Sizeof(uintptr(0)), 1), true},
		{setField(struct{ _, a, _ uintptr }{}, 1*unsafe.Sizeof(uintptr(0)), 1), false},
		{setField(struct{ _, a, _ uintptr }{}, 2*unsafe.Sizeof(uintptr(0)), 1), true},
		{struct{ _, a, _ func() }{}, true}, // incomparable struct with blank fields
		{setField(struct{ _, a, _ func() }{}, 0*unsafe.Sizeof((func())(nil)), func() {}), true},
		{setField(struct{ _, a, _ func() }{}, 1*unsafe.Sizeof((func())(nil)), func() {}), false},
		{setField(struct{ _, a, _ func() }{}, 2*unsafe.Sizeof((func())(nil)), func() {}), true},
		{struct{ a [256]S }{}, true},
		{struct{ a [256]S }{a: [256]S{2: {i1: 1}}}, false},
		{struct{ a [256]float32 }{}, true},
		{struct{ a [256]float32 }{a: [256]float32{2: 1.0}}, false},
		{struct{ _, a [256]S }{}, true},
		{setField(struct{ _, a [256]S }{}, 0*unsafe.Sizeof(int64(0)), int64(1)), true},
		// UnsafePointer
		{(unsafe.Pointer)(nil), true},
		{(unsafe.Pointer)(new(int)), false},
	} {
		var x Value
		if v, ok := tt.x.(Value); ok {
			x = v
		} else {
			x = ValueOf(tt.x)
		}

		b := x.IsZero()
		if b != tt.want {
			t.Errorf("%d: IsZero((%s)(%+v)) = %t, want %t", i, x.Kind(), tt.x, b, tt.want)
		}

		if !Zero(TypeOf(tt.x)).IsZero() {
			t.Errorf("%d: IsZero(Zero(TypeOf((%s)(%+v)))) is false", i, x.Kind(), tt.x)
		}

		p := New(x.Type()).Elem()
		p.Set(x)
		p.SetZero()
		if !p.IsZero() {
			t.Errorf("%d: IsZero((%s)(%+v)) is true after SetZero", i, p.Kind(), tt.x)
		}
	}

	func() {
		defer func() {
			if r := recover(); r == nil {
				t.Error("should panic for invalid value")
			}
		}()
		(Value{}).IsZero()
	}()
}

func TestInternalIsZero(t *testing.T) {
	b := make([]byte, 512)
	for a := 0; a < 8; a++ {
		for i := 1; i <= 512-a; i++ {
			InternalIsZero(b[a : a+i])
		}
	}
}

func TestInterfaceExtraction(t *testing.T) {
	var s struct {
		W io.Writer
	}

	s.W = os.Stdout
	v := Indirect(ValueOf(&s)).Field(0).Interface()
	if v != s.W.(any) {
		t.Error("Interface() on interface: ", v, s.W)
	}
}

func TestNilPtrValueSub(t *testing.T) {
	var pi *int
	if pv := ValueOf(pi); pv.Elem().IsValid() {
		t.Error("ValueOf((*int)(nil)).Elem().IsValid()")
	}
}

func TestMap(t *testing.T) {
	m := map[string]int{"a": 1, "b": 2}
	mv := ValueOf(m)
	if n := mv.Len(); n != len(m) {
		t.Errorf("Len = %d, want %d", n, len(m))
	}
	keys := mv.MapKeys()
	newmap := MakeMap(mv.Type())
	for k, v := range m {
		// Check that returned Keys match keys in range.
		// These aren't required to be in the same order.
		seen := false
		for _, kv := range keys {
			if kv.String() == k {
				seen = true
				break
			}
		}
		if !seen {
			t.Errorf("Missing key %q", k)
		}

		// Check that value lookup is correct.
		vv := mv.MapIndex(ValueOf(k))
		if vi := vv.Int(); vi != int64(v) {
			t.Errorf("Key %q: have value %d, want %d", k, vi, v)
		}

		// Copy into new map.
		newmap.SetMapIndex(ValueOf(k), ValueOf(v))
	}
	vv := mv.MapIndex(ValueOf("not-present"))
	if vv.IsValid() {
		t.Errorf("Invalid key: got non-nil value %s", valueToString(vv))
	}

	newm := newmap.Interface().(map[string]int)
	if len(newm) != len(m) {
		t.Errorf("length after copy: newm=%d, m=%d", len(newm), len(m))
	}

	for k, v := range newm {
		mv, ok := m[k]
		if mv != v {
			t.Errorf("newm[%q] = %d, but m[%q] = %d, %v", k, v, k, mv, ok)
		}
	}

	newmap.SetMapIndex(ValueOf("a"), Value{})
	v, ok := newm["a"]
	if ok {
		t.Errorf("newm[\"a\"] = %d after delete", v)
	}

	mv = ValueOf(&m).Elem()
	mv.Set(Zero(mv.Type()))
	if m != nil {
		t.Errorf("mv.Set(nil) failed")
	}

	type S string
	shouldPanic("not assignable", func() { mv.MapIndex(ValueOf(S("key"))) })
	shouldPanic("not assignable", func() { mv.SetMapIndex(ValueOf(S("key")), ValueOf(0)) })
}

func TestNilMap(t *testing.T) {
	var m map[string]int
	mv := ValueOf(m)
	keys := mv.MapKeys()
	if len(keys) != 0 {
		t.Errorf(">0 keys for nil map: %v", keys)
	}

	// Check that value for missing key is zero.
	x := mv.MapIndex(ValueOf("hello"))
	if x.Kind() != Invalid {
		t.Errorf("m.MapIndex(\"hello\") for nil map = %v, want Invalid Value", x)
	}

	// Check big value too.
	var mbig map[string][10 << 20]byte
	x = ValueOf(mbig).MapIndex(ValueOf("hello"))
	if x.Kind() != Invalid {
		t.Errorf("mbig.MapIndex(\"hello\") for nil map = %v, want Invalid Value", x)
	}

	// Test that deletes from a nil map succeed.
	mv.SetMapIndex(ValueOf("hi"), Value{})
}

func TestChan(t *testing.T) {
	for loop := 0; loop < 2; loop++ {
		var c chan int
		var cv Value

		// check both ways to allocate channels
		switch loop {
		case 1:
			c = make(chan int, 1)
			cv = ValueOf(c)
		case 0:
			cv = MakeChan(TypeOf(c), 1)
			c = cv.Interface().(chan int)
		}

		// Send
		cv.Send(ValueOf(2))
		if i := <-c; i != 2 {
			t.Errorf("reflect Send 2, native recv %d", i)
		}

		// Recv
		c <- 3
		if i, ok := cv.Recv(); i.Int() != 3 || !ok {
			t.Errorf("native send 3, reflect Recv %d, %t", i.Int(), ok)
		}

		// TryRecv fail
		val, ok := cv.TryRecv()
		if val.IsValid() || ok {
			t.Errorf("TryRecv on empty chan: %s, %t", valueToString(val), ok)
		}

		// TryRecv success
		c <- 4
		val, ok = cv.TryRecv()
		if !val.IsValid() {
			t.Errorf("TryRecv on ready chan got nil")
		} else if i := val.Int(); i != 4 || !ok {
			t.Errorf("native send 4, TryRecv %d, %t", i, ok)
		}

		// TrySend fail
		c <- 100
		ok = cv.TrySend(ValueOf(5))
		i := <-c
		if ok {
			t.Errorf("TrySend on full chan succeeded: value %d", i)
		}

		// TrySend success
		ok = cv.TrySend(ValueOf(6))
		if !ok {
			t.Errorf("TrySend on empty chan failed")
			select {
			case x := <-c:
				t.Errorf("TrySend failed but it did send %d", x)
			default:
			}
		} else {
			if i = <-c; i != 6 {
				t.Errorf("TrySend 6, recv %d", i)
			}
		}

		// Close
		c <- 123
		cv.Close()
		if i, ok := cv.Recv(); i.Int() != 123 || !ok {
			t.Errorf("send 123 then close; Recv %d, %t", i.Int(), ok)
		}
		if i, ok := cv.Recv(); i.Int() != 0 || ok {
			t.Errorf("after close Recv %d, %t", i.Int(), ok)
		}
		// Closing a read-only channel
		shouldPanic("", func() {
			c := make(<-chan int, 1)
			cv := ValueOf(c)
			cv.Close()
		})
	}

	// check creation of unbuffered channel
	var c chan int
	cv := MakeChan(TypeOf(c), 0)
	c = cv.Interface().(chan int)
	if cv.TrySend(ValueOf(7)) {
		t.Errorf("TrySend on sync chan succeeded")
	}
	if v, ok := cv.TryRecv(); v.IsValid() || ok {
		t.Errorf("TryRecv on sync chan succeeded: isvalid=%v ok=%v", v.IsValid(), ok)
	}

	// len/cap
	cv = MakeChan(TypeOf(c), 10)
	c = cv.Interface().(chan int)
	for i := 0; i < 3; i++ {
		c <- i
	}
	if l, m := cv.Len(), cv.Cap(); l != len(c) || m != cap(c) {
		t.Errorf("Len/Cap = %d/%d want %d/%d", l, m, len(c), cap(c))
	}
}

// caseInfo describes a single case in a select test.
type caseInfo struct {
	desc      string
	canSelect bool
	recv      Value
	closed    bool
	helper    func()
	panic     bool
}

var allselect = flag.Bool("allselect", false, "exhaustive select test")

func TestSelect(t *testing.T) {
	selectWatch.once.Do(func() { go selectWatcher() })

	var x exhaustive
	nch := 0
	newop := func(n int, cap int) (ch, val Value) {
		nch++
		if nch%101%2 == 1 {
			c := make(chan int, cap)
			ch = ValueOf(c)
			val = ValueOf(n)
		} else {
			c := make(chan string, cap)
			ch = ValueOf(c)
			val = ValueOf(fmt.Sprint(n))
		}
		return
	}

	for n := 0; x.Next(); n++ {
		if testing.Short() && n >= 1000 {
			break
		}
		if n >= 100000 && !*allselect {
			break
		}
		if n%100000 == 0 && testing.Verbose() {
			println("TestSelect", n)
		}
		var cases []SelectCase
		var info []caseInfo

		// Ready send.
		if x.Maybe() {
			ch, val := newop(len(cases), 1)
			cases = append(cases, SelectCase{
				Dir:  SelectSend,
				Chan: ch,
				Send: val,
			})
			info = append(info, caseInfo{desc: "ready send", canSelect: true})
		}

		// Ready recv.
		if x.Maybe() {
			ch, val := newop(len(cases), 1)
			ch.Send(val)
			cases = append(cases, SelectCase{
				Dir:  SelectRecv,
				Chan: ch,
			})
			info = append(info, caseInfo{desc: "ready recv", canSelect: true, recv: val})
		}

		// Blocking send.
		if x.Maybe() {
			ch, val := newop(len(cases), 0)
			cases = append(cases, SelectCase{
				Dir:  SelectSend,
				Chan: ch,
				Send: val,
			})
			// Let it execute?
			if x.Maybe() {
				f := func() { ch.Recv() }
				info = append(info, caseInfo{desc: "blocking send", helper: f})
			} else {
				info = append(info, caseInfo{desc: "blocking send"})
			}
		}

		// Blocking recv.
		if x.Maybe() {
			ch, val := newop(len(cases), 0)
			cases = append(cases, SelectCase{
				Dir:  SelectRecv,
				Chan: ch,
			})
			// Let it execute?
			if x.Maybe() {
				f := func() { ch.Send(val) }
				info = append(info, caseInfo{desc: "blocking recv", recv: val, helper: f})
			} else {
				info = append(info, caseInfo{desc: "blocking recv"})
			}
		}

		// Zero Chan send.
		if x.Maybe() {
			// Maybe include value to send.
			var val Value
			if x.Maybe() {
				val = ValueOf(100)
			}
			cases = append(cases, SelectCase{
				Dir:  SelectSend,
				Send: val,
			})
			info = append(info, caseInfo{desc: "zero Chan send"})
		}

		// Zero Chan receive.
		if x.Maybe() {
			cases = append(cases, SelectCase{
				Dir: SelectRecv,
			})
			info = append(info, caseInfo{desc: "zero Chan recv"})
		}

		// nil Chan send.
		if x.Maybe() {
			cases = append(cases, SelectCase{
				Dir:  SelectSend,
				Chan: ValueOf((chan int)(nil)),
				Send: ValueOf(101),
			})
			info = append(info, caseInfo{desc: "nil Chan send"})
		}

		// nil Chan recv.
		if x.Maybe() {
			cases = append(cases, SelectCase{
				Dir:  SelectRecv,
				Chan: ValueOf((chan int)(nil)),
			})
			info = append(info, caseInfo{desc: "nil Chan recv"})
		}

		// closed Chan send.
		if x.Maybe() {
			ch := make(chan int)
			close(ch)
			cases = append(cases, SelectCase{
				Dir:  SelectSend,
				Chan: ValueOf(ch),
				Send: ValueOf(101),
			})
			info = append(info, caseInfo{desc: "closed Chan send", canSelect: true, panic: true})
		}

		// closed Chan recv.
		if x.Maybe() {
			ch, val := newop(len(cases), 0)
			ch.Close()
			val = Zero(val.Type())
			cases = append(cases, SelectCase{
				Dir:  SelectRecv,
				Chan: ch,
			})
			info = append(info, caseInfo{desc: "closed Chan recv", canSelect: true, closed: true, recv: val})
		}

		var helper func() // goroutine to help the select complete

		// Add default? Must be last case here, but will permute.
		// Add the default if the select would otherwise
		// block forever, and maybe add it anyway.
		numCanSelect := 0
		canProceed := false
		canBlock := true
		canPanic := false
		helpers := []int{}
		for i, c := range info {
			if c.canSelect {
				canProceed = true
				canBlock = false
				numCanSelect++
				if c.panic {
					canPanic = true
				}
			} else if c.helper != nil {
				canProceed = true
				helpers = append(helpers, i)
			}
		}
		if !canProceed || x.Maybe() {
			cases = append(cases, SelectCase{
				Dir: SelectDefault,
			})
			info = append(info, caseInfo{desc: "default", canSelect: canBlock})
			numCanSelect++
		} else if canBlock {
			// Select needs to communicate with another goroutine.
			cas := &info[helpers[x.Choose(len(helpers))]]
			helper = cas.helper
			cas.canSelect = true
			numCanSelect++
		}

		// Permute cases and case info.
		// Doing too much here makes the exhaustive loop
		// too exhausting, so just do two swaps.
		for loop := 0; loop < 2; loop++ {
			i := x.Choose(len(cases))
			j := x.Choose(len(cases))
			cases[i], cases[j] = cases[j], cases[i]
			info[i], info[j] = info[j], info[i]
		}

		if helper != nil {
			// We wait before kicking off a goroutine to satisfy a blocked select.
			// The pause needs to be big enough to let the select block before
			// we run the helper, but if we lose that race once in a while it's okay: the
			// select will just proceed immediately. Not a big deal.
			// For short tests we can grow [sic] the timeout a bit without fear of taking too long
			pause := 10 * time.Microsecond
			if testing.Short() {
				pause = 100 * time.Microsecond
			}
			time.AfterFunc(pause, helper)
		}

		// Run select.
		i, recv, recvOK, panicErr := runSelect(cases, info)
		if panicErr != nil && !canPanic {
			t.Fatalf("%s\npanicked unexpectedly: %v", fmtSelect(info), panicErr)
		}
		if panicErr == nil && canPanic && numCanSelect == 1 {
			t.Fatalf("%s\nselected #%d incorrectly (should panic)", fmtSelect(info), i)
		}
		if panicErr != nil {
			continue
		}

		cas := info[i]
		if !cas.canSelect {
			recvStr := ""
			if recv.IsValid() {
				recvStr = fmt.Sprintf(", received %v, %v", recv.Interface(), recvOK)
			}
			t.Fatalf("%s\nselected #%d incorrectly%s", fmtSelect(info), i, recvStr)
		}
		if cas.panic {
			t.Fatalf("%s\nselected #%d incorrectly (case should panic)", fmtSelect(info), i)
		}

		if cases[i].Dir == SelectRecv {
			if !recv.IsValid() {
				t.Fatalf("%s\nselected #%d but got %v, %v, want %v, %v", fmtSelect(info), i, recv, recvOK, cas.recv.Interface(), !cas.closed)
			}
			if !cas.recv.IsValid() {
				t.Fatalf("%s\nselected #%d but internal error: missing recv value", fmtSelect(info), i)
			}
			if recv.Interface() != cas.recv.Interface() || recvOK != !cas.closed {
				if recv.Interface() == cas.recv.Interface() && recvOK == !cas.closed {
					t.Fatalf("%s\nselected #%d, got %#v, %v, and DeepEqual is broken on %T", fmtSelect(info), i, recv.Interface(), recvOK, recv.Interface())
				}
				t.Fatalf("%s\nselected #%d but got %#v, %v, want %#v, %v", fmtSelect(info), i, recv.Interface(), recvOK, cas.recv.Interface(), !cas.closed)
			}
		} else {
			if recv.IsValid() || recvOK {
				t.Fatalf("%s\nselected #%d but got %v, %v, want %v, %v", fmtSelect(info), i, recv, recvOK, Value{}, false)
			}
		}
	}
}

func TestSelectMaxCases(t *testing.T) {
	var sCases []SelectCase
	channel := make(chan int)
	close(channel)
	for i := 0; i < 65536; i++ {
		sCases = append(sCases, SelectCase{
			Dir:  SelectRecv,
			Chan: ValueOf(channel),
		})
	}
	// Should not panic
	_, _, _ = Select(sCases)
	sCases = append(sCases, SelectCase{
		Dir:  SelectRecv,
		Chan: ValueOf(channel),
	})
	defer func() {
		if err := recover(); err != nil {
			if err.(string) != "reflect.Select: too many cases (max 65536)" {
				t.Fatalf("unexpected error from select call with greater than max supported cases")
			}
		} else {
			t.Fatalf("expected select call to panic with greater than max supported cases")
		}
	}()
	// Should panic
	_, _, _ = Select(sCases)
}

func TestSelectNop(t *testing.T) {
	// "select { default: }" should always return the default case.
	chosen, _, _ := Select([]SelectCase{{Dir: SelectDefault}})
	if chosen != 0 {
		t.Fatalf("expected Select to return 0, but got %#v", chosen)
	}
}

// selectWatch and the selectWatcher are a watchdog mechanism for running Select.
// If the selectWatcher notices that the select has been blocked for >1 second, it prints
// an error describing the select and panics the entire test binary.
var selectWatch struct {
	sync.Mutex
	once sync.Once
	now  time.Time
	info []caseInfo
}

func selectWatcher() {
	for {
		time.Sleep(1 * time.Second)
		selectWatch.Lock()
		if selectWatch.info != nil && time.Since(selectWatch.now) > 10*time.Second {
			fmt.Fprintf(os.Stderr, "TestSelect:\n%s blocked indefinitely\n", fmtSelect(selectWatch.info))
			panic("select stuck")
		}
		selectWatch.Unlock()
	}
}

// runSelect runs a single select test.
// It returns the values returned by Select but also returns
// a panic value if the Select panics.
func runSelect(cases []SelectCase, info []caseInfo) (chosen int, recv Value, recvOK bool, panicErr any) {
	defer func() {
		panicErr = recover()

		selectWatch.Lock()
		selectWatch.info = nil
		selectWatch.Unlock()
	}()

	selectWatch.Lock()
	selectWatch.now = time.Now()
	selectWatch.info = info
	selectWatch.Unlock()

	chosen, recv, recvOK = Select(cases)
	return
}

// fmtSelect formats the information about a single select test.
func fmtSelect(info []caseInfo) string {
	var buf strings.Builder
	fmt.Fprintf(&buf, "\nselect {\n")
	for i, cas := range info {
		fmt.Fprintf(&buf, "%d: %s", i, cas.desc)
		if cas.recv.IsValid() {
			fmt.Fprintf(&buf, " val=%#v", cas.recv.Interface())
		}
		if cas.canSelect {
			fmt.Fprintf(&buf, " canselect")
		}
		if cas.panic {
			fmt.Fprintf(&buf, " panic")
		}
		fmt.Fprintf(&buf, "\n")
	}
	fmt.Fprintf(&buf, "}")
	return buf.String()
}

type two [2]uintptr

// Difficult test for function call because of
// implicit padding between arguments.
func dummy(b byte, c int, d byte, e two, f byte, g float32, h byte) (i byte, j int, k byte, l two, m byte, n float32, o byte) {
	return b, c, d, e, f, g, h
}

func TestFunc(t *testing.T) {
	ret := ValueOf(dummy).Call([]Value{
		ValueOf(byte(10)),
		ValueOf(20),
		ValueOf(byte(30)),
		ValueOf(two{40, 50}),
		ValueOf(byte(60)),
		ValueOf(float32(70)),
		ValueOf(byte(80)),
	})
	if len(ret) != 7 {
		t.Fatalf("Call returned %d values, want 7", len(ret))
	}

	i := byte(ret[0].Uint())
	j := int(ret[1].Int())
	k := byte(ret[2].Uint())
	l := ret[3].Interface().(two)
	m := byte(ret[4].Uint())
	n := float32(ret[5].Float())
	o := byte(ret[6].Uint())

	if i != 10 || j != 20 || k != 30 || l != (two{40, 50}) || m != 60 || n != 70 || o != 80 {
		t.Errorf("Call returned %d, %d, %d, %v, %d, %g, %d; want 10, 20, 30, [40, 50], 60, 70, 80", i, j, k, l, m, n, o)
	}

	for i, v := range ret {
		if v.CanAddr() {
			t.Errorf("result %d is addressable", i)
		}
	}
}

func TestCallConvert(t *testing.T) {
	v := ValueOf(new(io.ReadWriter)).Elem()
	f := ValueOf(func(r io.Reader) io.Reader { return r })
	out := f.Call([]Value{v})
	if len(out) != 1 || out[0].Type() != TypeOf(new(io.Reader)).Elem() || !out[0].IsNil() {
		t.Errorf("expected [nil], got %v", out)
	}
}

type emptyStruct struct{}

type nonEmptyStruct struct {
	member int
}

func returnEmpty() emptyStruct {
	return emptyStruct{}
}

func takesEmpty(e emptyStruct) {
}

func returnNonEmpty(i int) nonEmptyStruct {
	return nonEmptyStruct{member: i}
}

func takesNonEmpty(n nonEmptyStruct) int {
	return n.member
}

func TestCallWithStruct(t *testing.T) {
	r := ValueOf(returnEmpty).Call(nil)
	if len(r) != 1 || r[0].Type() != TypeOf(emptyStruct{}) {
		t.Errorf("returning empty struct returned %#v instead", r)
	}
	r = ValueOf(takesEmpty).Call([]Value{ValueOf(emptyStruct{})})
	if len(r) != 0 {
		t.Errorf("takesEmpty returned values: %#v", r)
	}
	r = ValueOf(returnNonEmpty).Call([]Value{ValueOf(42)})
	if len(r) != 1 || r[0].Type() != TypeOf(nonEmptyStruct{}) || r[0].Field(0).Int() != 42 {
		t.Errorf("returnNonEmpty returned %#v", r)
	}
	r = ValueOf(takesNonEmpty).Call([]Value{ValueOf(nonEmptyStruct{member: 42})})
	if len(r) != 1 || r[0].Type() != TypeOf(1) || r[0].Int() != 42 {
		t.Errorf("takesNonEmpty returned %#v", r)
	}
}

func TestCallReturnsEmpty(t *testing.T) {
	// Issue 21717: past-the-end pointer write in Call with
	// nonzero-sized frame and zero-sized return value.
	runtime.GC()
	var finalized uint32
	f := func() (emptyStruct, *[2]int64) {
		i := new([2]int64) // big enough to not be tinyalloc'd, so finalizer always runs when i dies
		runtime.SetFinalizer(i, func(*[2]int64) { atomic.StoreUint32(&finalized, 1) })
		return emptyStruct{}, i
	}
	v := ValueOf(f).Call(nil)[0] // out[0] should not alias out[1]'s memory, so the finalizer should run.
	timeout := time.After(5 * time.Second)
	for atomic.LoadUint32(&finalized) == 0 {
		select {
		case <-timeout:
			t.Fatal("finalizer did not run")
		default:
		}
		runtime.Gosched()
		runtime.GC()
	}
	runtime.KeepAlive(v)
}

func TestMakeFunc(t *testing.T) {
	f := dummy
	fv := MakeFunc(TypeOf(f), func(in []Value) []Value { return in })
	ValueOf(&f).Elem().Set(fv)

	// Call g with small arguments so that there is
	// something predictable (and different from the
	// correct results) in those positions on the stack.
	g := dummy
	g(1, 2, 3, two{4, 5}, 6, 7, 8)

	// Call constructed function f.
	i, j, k, l, m, n, o := f(10, 20, 30, two{40, 50}, 60, 70, 80)
	if i != 10 || j != 20 || k != 30 || l != (two{40, 50}) || m != 60 || n != 70 || o != 80 {
		t.Errorf("Call returned %d, %d, %d, %v, %d, %g, %d; want 10, 20, 30, [40, 50], 60, 70, 80", i, j, k, l, m, n, o)
	}
}

func TestMakeFuncInterface(t *testing.T) {
	fn := func(i int) int { return i }
	incr := func(in []Value) []Value {
		return []Value{ValueOf(int(in[0].Int() + 1))}
	}
	fv := MakeFunc(TypeOf(fn), incr)
	ValueOf(&fn).Elem().Set(fv)
	if r := fn(2); r != 3 {
		t.Errorf("Call returned %d, want 3", r)
	}
	if r := fv.Call([]Value{ValueOf(14)})[0].Int(); r != 15 {
		t.Errorf("Call returned %d, want 15", r)
	}
	if r := fv.Interface().(func(int) int)(26); r != 27 {
		t.Errorf("Call returned %d, want 27", r)
	}
}

func TestMakeFuncVariadic(t *testing.T) {
	// Test that variadic arguments are packed into a slice and passed as last arg
	fn := func(_ int, is ...int) []int { return nil }
	fv := MakeFunc(TypeOf(fn), func(in []Value) []Value { return in[1:2] })
	ValueOf(&fn).Elem().Set(fv)

	r := fn(1, 2, 3)
	if r[0] != 2 || r[1] != 3 {
		t.Errorf("Call returned [%v, %v]; want 2, 3", r[0], r[1])
	}

	r = fn(1, []int{2, 3}...)
	if r[0] != 2 || r[1] != 3 {
		t.Errorf("Call returned [%v, %v]; want 2, 3", r[0], r[1])
	}

	r = fv.Call([]Value{ValueOf(1), ValueOf(2), ValueOf(3)})[0].Interface().([]int)
	if r[0] != 2 || r[1] != 3 {
		t.Errorf("Call returned [%v, %v]; want 2, 3", r[0], r[1])
	}

	r = fv.CallSlice([]Value{ValueOf(1), ValueOf([]int{2, 3})})[0].Interface().([]int)
	if r[0] != 2 || r[1] != 3 {
		t.Errorf("Call returned [%v, %v]; want 2, 3", r[0], r[1])
	}

	f := fv.Interface().(func(int, ...int) []int)

	r = f(1, 2, 3)
	if r[0] != 2 || r[1] != 3 {
		t.Errorf("Call returned [%v, %v]; want 2, 3", r[0], r[1])
	}
	r = f(1, []int{2, 3}...)
	if r[0] != 2 || r[1] != 3 {
		t.Errorf("Call returned [%v, %v]; want 2, 3", r[0], r[1])
	}
}

// Dummy type that implements io.WriteCloser
type WC struct {
}

func (w *WC) Write(p []byte) (n int, err error) {
	return 0, nil
}
func (w *WC) Close() error {
	return nil
}

func TestMakeFuncValidReturnAssignments(t *testing.T) {
	// reflect.Values returned from the wrapped function should be assignment-converted
	// to the types returned by the result of MakeFunc.

	// Concrete types should be promotable to interfaces they implement.
	var f func() error
	f = MakeFunc(TypeOf(f), func([]Value) []Value {
		return []Value{ValueOf(io.EOF)}
	}).Interface().(func() error)
	f()

	// Super-interfaces should be promotable to simpler interfaces.
	var g func() io.Writer
	g = MakeFunc(TypeOf(g), func([]Value) []Value {
		var w io.WriteCloser = &WC{}
		return []Value{ValueOf(&w).Elem()}
	}).Interface().(func() io.Writer)
	g()

	// Channels should be promotable to directional channels.
	var h func() <-chan int
	h = MakeFunc(TypeOf(h), func([]Value) []Value {
		return []Value{ValueOf(make(chan int))}
	}).Interface().(func() <-chan int)
	h()

	// Unnamed types should be promotable to named types.
	type T struct{ a, b, c int }
	var i func() T
	i = MakeFunc(TypeOf(i), func([]Value) []Value {
		return []Value{ValueOf(struct{ a, b, c int }{a: 1, b: 2, c: 3})}
	}).Interface().(func() T)
	i()
}

func TestMakeFuncInvalidReturnAssignments(t *testing.T) {
	// Type doesn't implement the required interface.
	shouldPanic("", func() {
		var f func() error
		f = MakeFunc(TypeOf(f), func([]Value) []Value {
			return []Value{ValueOf(int(7))}
		}).Interface().(func() error)
		f()
	})
	// Assigning to an interface with additional methods.
	shouldPanic("", func() {
		var f func() io.ReadWriteCloser
		f = MakeFunc(TypeOf(f), func([]Value) []Value {
			var w io.WriteCloser = &WC{}
			return []Value{ValueOf(&w).Elem()}
		}).Interface().(func() io.ReadWriteCloser)
		f()
	})
	// Directional channels can't be assigned to bidirectional ones.
	shouldPanic("", func() {
		var f func() chan int
		f = MakeFunc(TypeOf(f), func([]Value) []Value {
			var c <-chan int = make(chan int)
			return []Value{ValueOf(c)}
		}).Interface().(func() chan int)
		f()
	})
	// Two named types which are otherwise identical.
	shouldPanic("", func() {
		type T struct{ a, b, c int }
		type U struct{ a, b, c int }
		var f func() T
		f = MakeFunc(TypeOf(f), func([]Value) []Value {
			return []Value{ValueOf(U{a: 1, b: 2, c: 3})}
		}).Interface().(func() T)
		f()
	})
}

type Point struct {
	x, y int
}

// This will be index 0.
func (p Point) AnotherMethod(scale int) int {
	return -1
}

// This will be index 1.
func (p Point) Dist(scale int) int {
	//println("Point.Dist", p.x, p.y, scale)
	return p.x*p.x*scale + p.y*p.y*scale
}

// This will be index 2.
func (p Point) GCMethod(k int) int {
	runtime.GC()
	return k + p.x
}

// This will be index 3.
func (p Point) NoArgs() {
	// Exercise no-argument/no-result paths.
}

// This will be index 4.
func (p Point) TotalDist(points ...Point) int {
	tot := 0
	for _, q := range points {
		dx := q.x - p.x
		dy := q.y - p.y
		tot += dx*dx + dy*dy // Should call Sqrt, but it's just a test.

	}
	return tot
}

// This will be index 5.
func (p *Point) Int64Method(x int64) int64 {
	return x
}

// This will be index 6.
func (p *Point) Int32Method(x int32) int32 {
	return x
}

func TestMethod(t *testing.T) {
	// Non-curried method of type.
	p := Point{3, 4}
	i := TypeOf(p).Method(1).Func.Call([]Value{ValueOf(p), ValueOf(10)})[0].Int()
	if i != 250 {
		t.Errorf("Type Method returned %d; want 250", i)
	}

	m, ok := TypeOf(p).MethodByName("Dist")
	if !ok {
		t.Fatalf("method by name failed")
	}
	i = m.Func.Call([]Value{ValueOf(p), ValueOf(11)})[0].Int()
	if i != 275 {
		t.Errorf("Type MethodByName returned %d; want 275", i)
	}

	m, ok = TypeOf(p).MethodByName("NoArgs")
	if !ok {
		t.Fatalf("method by name failed")
	}
	n := len(m.Func.Call([]Value{ValueOf(p)}))
	if n != 0 {
		t.Errorf("NoArgs returned %d values; want 0", n)
	}

	i = TypeOf(&p).Method(1).Func.Call([]Value{ValueOf(&p), ValueOf(12)})[0].Int()
	if i != 300 {
		t.Errorf("Pointer Type Method returned %d; want 300", i)
	}

	m, ok = TypeOf(&p).MethodByName("Dist")
	if !ok {
		t.Fatalf("ptr method by name failed")
	}
	i = m.Func.Call([]Value{ValueOf(&p), ValueOf(13)})[0].Int()
	if i != 325 {
		t.Errorf("Pointer Type MethodByName returned %d; want 325", i)
	}

	m, ok = TypeOf(&p).MethodByName("NoArgs")
	if !ok {
		t.Fatalf("method by name failed")
	}
	n = len(m.Func.Call([]Value{ValueOf(&p)}))
	if n != 0 {
		t.Errorf("NoArgs returned %d values; want 0", n)
	}

	_, ok = TypeOf(&p).MethodByName("AA")
	if ok {
		t.Errorf(`MethodByName("AA") should have failed`)
	}

	_, ok = TypeOf(&p).MethodByName("ZZ")
	if ok {
		t.Errorf(`MethodByName("ZZ") should have failed`)
	}

	// Curried method of value.
	tfunc := TypeOf((func(int) int)(nil))
	v := ValueOf(p).Method(1)
	if tt := v.Type(); tt != tfunc {
		t.Errorf("Value Method Type is %s; want %s", tt, tfunc)
	}
	i = v.Call([]Value{ValueOf(14)})[0].Int()
	if i != 350 {
		t.Errorf("Value Method returned %d; want 350", i)
	}
	v = ValueOf(p).MethodByName("Dist")
	if tt := v.Type(); tt != tfunc {
		t.Errorf("Value MethodByName Type is %s; want %s", tt, tfunc)
	}
	i = v.Call([]Value{ValueOf(15)})[0].Int()
	if i != 375 {
		t.Errorf("Value MethodByName returned %d; want 375", i)
	}
	v = ValueOf(p).MethodByName("NoArgs")
	v.Call(nil)

	// Curried method of pointer.
	v = ValueOf(&p).Method(1)
	if tt := v.Type(); tt != tfunc {
		t.Errorf("Pointer Value Method Type is %s; want %s", tt, tfunc)
	}
	i = v.Call([]Value{ValueOf(16)})[0].Int()
	if i != 400 {
		t.Errorf("Pointer Value Method returned %d; want 400", i)
	}
	v = ValueOf(&p).MethodByName("Dist")
	if tt := v.Type(); tt != tfunc {
		t.Errorf("Pointer Value MethodByName Type is %s; want %s", tt, tfunc)
	}
	i = v.Call([]Value{ValueOf(17)})[0].Int()
	if i != 425 {
		t.Errorf("Pointer Value MethodByName returned %d; want 425", i)
	}
	v = ValueOf(&p).MethodByName("NoArgs")
	v.Call(nil)

	// Curried method of interface value.
	// Have to wrap interface value in a struct to get at it.
	// Passing it to ValueOf directly would
	// access the underlying Point, not the interface.
	var x interface {
		Dist(int) int
	} = p
	pv := ValueOf(&x).Elem()
	v = pv.Method(0)
	if tt := v.Type(); tt != tfunc {
		t.Errorf("Interface Method Type is %s; want %s", tt, tfunc)
	}
	i = v.Call([]Value{ValueOf(18)})[0].Int()
	if i != 450 {
		t.Errorf("Interface Method returned %d; want 450", i)
	}
	v = pv.MethodByName("Dist")
	if tt := v.Type(); tt != tfunc {
		t.Errorf("Interface MethodByName Type is %s; want %s", tt, tfunc)
	}
	i = v.Call([]Value{ValueOf(19)})[0].Int()
	if i != 475 {
		t.Errorf("Interface MethodByName returned %d; want 475", i)
```