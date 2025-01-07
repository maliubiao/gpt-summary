Response:
Let's break down the thought process for analyzing the provided Go code snippet.

1. **Understanding the Goal:** The request asks for the functionality of the provided Go code, which is a section of `go/src/reflect/all_test.go`. The core aim is to understand what aspect of the `reflect` package this specific chunk is testing.

2. **Initial Scan for Keywords and Structure:** Quickly scanning the code reveals several key elements:
    * `Test...` functions (e.g., `TestNamedT0`, `TestCallPanic`, `TestValuePanic`, `TestAlias`, `TestConvert`, `TestConvertPanic`, `TestConvertSlice2Array`, `TestConvertNaNs`, `TestComparable`, `TestValueOverflow`). This strongly suggests the code is testing various functionalities within the `reflect` package.
    * `reflect.ValueOf`, `reflect.TypeOf`, `v.Field`, `v.Method`, `v.Call`, `v.Convert`, `v.SetString`, `v.Interface`, etc. These are all core functions and methods of the `reflect` package.
    * `shouldPanic` function: This indicates testing scenarios where specific `reflect` operations should cause a panic.
    * `ok` and `bad` helper functions within `TestNamedT0` and `TestCallPanic`: These seem to simplify assertions about whether operations should succeed or fail.
    * Type definitions (e.g., `timp`, `t0`, `T1`, `T2`, `T`, `Empty`, `MyStruct`, etc.): These are used as test cases to explore how `reflect` interacts with different types.
    * `convertTests` variable: This looks like a structured way to define test cases for type conversion.

3. **Analyzing Individual Test Functions:**

    * **`TestNamedT0`:**  The structure involves nested structs and accessing fields using `v.Field()`. The `ok` and `bad` functions combined with comments like `// .X`, `// .t1`, etc., point to testing the accessibility (addressability) of struct fields, especially nested ones, and the impact of naming (lowercase vs. uppercase). The `clear` function (not provided, assumed to be a no-op or related to clearing/zeroing) reinforces this idea.

    * **`TestCallPanic`:** This test uses interfaces and methods (`v.Method()`, `v.Call()`). The `badCall` and `badMethod` helpers, along with the panics being tested, indicate this is verifying that attempting to call methods in invalid ways (e.g., on unexported methods or through incorrect Value types) results in the expected panics.

    * **`TestValuePanic`:** This is a straightforward test of `reflect.Value` method calls on inappropriate `Value` types (e.g., calling `Bool()` on a `float64` `Value`). The expected panic messages are explicitly provided.

    * **`TestAlias`:** This tests the ability to modify the underlying value of a variable through a `reflect.Value`. It demonstrates that reflection can indeed create an "alias" to the original data.

    * **`TestConvert`:** The presence of `convertTests` and the use of `ConvertibleTo`, `CanConvert`, and `Convert` clearly signal that this test focuses on type conversion using reflection. The extensive `convertTests` array provides many specific scenarios for conversion between different numeric types, strings, byte slices, runes, named types, slices to arrays, and interfaces.

    * **`TestConvertPanic`:**  This specifically checks for panics during type conversion, focusing on cases where slice to array/array pointer conversions fail due to length mismatches.

    * **`TestConvertSlice2Array`:**  This examines the behavior of converting a slice to an array. It highlights that the conversion creates a *copy* of the slice data, not a direct reference.

    * **`TestConvertNaNs`:** This deals with a specific edge case: how reflection handles and converts "Not a Number" (NaN) values for floating-point types. It's likely addressing potential issues related to how NaN's bit representation is preserved during reflection operations.

    * **`TestComparable`:** This test verifies the `Comparable()` method of `reflect.Type`, which determines if a type can be used in comparison operations (e.g., with `==`).

    * **`TestValueOverflow`:** This set of tests checks the `OverflowFloat` and `OverflowInt` methods of `reflect.Value`, ensuring they correctly identify when a value would overflow the target type during a conversion.

4. **Identifying the Core Functionality:** Based on the analysis of the individual test functions, the overarching functionality being tested is the `reflect` package's ability to:
    * **Inspect and manipulate struct fields:** Accessing, checking addressability, and understanding the impact of naming conventions.
    * **Call methods dynamically:**  Testing the `Method` and `Call` methods and the conditions under which these operations should panic.
    * **Handle errors and panics:** Ensuring that invalid operations on `reflect.Value` result in the expected panic messages.
    * **Perform type conversions:** Validating the `ConvertibleTo`, `CanConvert`, and `Convert` methods for various type combinations, including numeric types, strings, slices, arrays, and interfaces.
    * **Determine type comparability:**  Testing the `Comparable()` method.
    * **Detect potential overflows during conversions:**  Validating the `OverflowFloat` and `OverflowInt` methods.
    * **Work with specific floating-point edge cases:** Handling NaN values during conversions.

5. **Inferring the Go Language Feature:**  The code is testing the **`reflect` package** in Go. This package enables runtime inspection and manipulation of types and values.

6. **Constructing Example Code (for `TestNamedT0`):** To illustrate the addressability concept from `TestNamedT0`, an example showing how you can modify addressable fields but not unaddressable ones is helpful.

7. **Handling Missing Code (like `clear`):**  Since `clear` isn't defined, make a reasonable assumption about its purpose (likely related to zeroing or resetting values) to explain the intent of the tests in `TestNamedT0`.

8. **Addressing Potential Errors:**  Think about common mistakes users might make when using reflection, such as trying to modify unaddressable values or calling methods incorrectly.

9. **Summarizing Functionality:**  Combine the findings from the individual test analysis into a concise summary of the code's purpose.

10. **Review and Refine:**  Read through the entire explanation to ensure clarity, accuracy, and completeness. Check for any inconsistencies or areas that could be explained better. For example, explicitly mentioning the role of uppercase/lowercase field names in export visibility is crucial for understanding `TestNamedT0`.
这是 `go/src/reflect/all_test.go` 文件的一部分，主要关注 `reflect` 包中关于结构体字段访问、方法调用以及类型转换相关的测试。

**功能归纳 (第4部分):**

这部分代码主要测试了 `reflect` 包中以下几个方面的功能：

1. **结构体字段的可寻址性 (Addressability) 和访问:**
   - 测试了通过 `reflect.Value` 获取结构体字段(`Field()`)，并判断这些字段是否可寻址 (`CanSet()`)，以及在可寻址的情况下进行修改 (虽然这里用 `clear` 函数代替，但意图是测试修改)。
   - 特别关注了命名类型和未命名类型，以及嵌套结构体字段的可寻址性差异。

2. **方法调用的恐慌 (Panic) 测试:**
   - 测试了通过 `reflect.Value` 获取方法 (`Method()`) 并进行调用 (`Call()`) 时，在不同情况下是否会产生预期的恐慌。
   - 涵盖了调用未导出方法、通过非导出字段访问到的方法等情况。

3. **`reflect.Value` 操作的恐慌测试:**
   -  测试了在 `reflect.Value` 上调用某些方法时，如果 `Value` 的类型不匹配，是否会产生预期的恐慌。
   -  例如，在 `string` 类型的 `Value` 上调用 `Bool()` 方法，或者在不可寻址的 `Value` 上调用 `Addr()` 方法。

4. **别名 (Aliasing) 测试:**
   -  验证了通过 `reflect.Value` 修改结构体字段的值，会直接影响到原始变量。

5. **类型转换 (Conversion) 测试:**
   -  测试了 `reflect.Value` 的 `Convert()` 方法，验证了各种类型之间进行合法转换的能力，包括基本类型之间的转换、命名类型与未命名类型之间的转换、切片与数组之间的转换等。
   -  也测试了 `ConvertibleTo()` 和 `CanConvert()` 方法的正确性。

6. **类型是否可比较 (Comparable) 的测试:**
   - 测试了 `reflect.Type` 的 `Comparable()` 方法，判断不同类型是否可以进行比较操作。

7. **数值溢出 (Overflow) 的测试:**
   - 测试了 `reflect.Value` 的 `OverflowFloat()` 和 `OverflowInt()` 方法，判断将一个数值转换为更小的类型时是否会发生溢出。

**更详细的功能解释和代码示例:**

**1. 结构体字段的可寻址性和访问:**

```go
package main

import (
	"fmt"
	"reflect"
)

type Inner struct {
	W int
}

type T struct {
	X int
	t1 struct {
		Y int
		t0 Inner
	}
	T2 struct {
		Z int
		namedT0 Inner
	}
	NamedT1 struct {
		Y int
		t0 Inner
	}
	NamedT2 struct {
		Z int
		namedT0 Inner
	}
	namedT1 struct {
		Y int
		t0 Inner
	}
	namedT2 struct {
		Z int
		namedT0 Inner
	}
}

func main() {
	v := reflect.ValueOf(&T{}).Elem()

	// 可寻址的字段
	fmt.Println("可寻址字段:")
	fmt.Println("v.Field(0).CanSet():", v.Field(0).CanSet())         // .X
	fmt.Println("v.Field(1).Field(0).CanSet():", v.Field(1).Field(0).CanSet()) // .t1.Y
	fmt.Println("v.Field(1).Field(1).Field(0).CanSet():", v.Field(1).Field(1).Field(0).CanSet()) // .t1.t0.W

	// 不可寻址的字段（因为是通过未导出的字段访问）
	fmt.Println("\n不可寻址字段:")
	fmt.Println("v.Field(1).CanSet():", v.Field(1).CanSet())         // .t1
	fmt.Println("v.Field(1).Field(1).CanSet():", v.Field(1).Field(1).CanSet())    // .t1.t0

	// 修改可寻址字段
	if v.Field(0).CanSet() {
		v.Field(0).SetInt(100)
	}
	fmt.Println("\n修改后的值: v.Field(0).Int():", v.Field(0).Int()) // 输出 100
}
```

**假设输入与输出:**

对于上面的代码示例，假设我们创建了一个 `T` 类型的零值结构体。输出将会显示哪些字段是可寻址的，哪些不是，以及修改可寻址字段后的结果。

**2. 方法调用的恐慌测试:**

```go
package main

import (
	"fmt"
	"reflect"
)

type timp int

func (t timp) W() {}
func (t timp) w() {}

type T struct {
	t0 timp
}

func main() {
	i := timp(0)
	v := reflect.ValueOf(T{i})

	// 调用导出方法不会 panic
	m := v.Field(0).MethodByName("W")
	if m.IsValid() {
		m.Call(nil)
		fmt.Println("成功调用导出方法 W")
	}

	// 调用未导出方法会 panic
	m = v.Field(0).MethodByName("w")
	if m.IsValid() {
		defer func() {
			if r := recover(); r != nil {
				fmt.Println("调用未导出方法 w 发生 panic:", r)
			}
		}()
		m.Call(nil) // 这里会 panic
	}
}
```

**假设输入与输出:**

代码会尝试调用 `timp` 类型的导出方法 `W`（成功）和未导出方法 `w`（导致 panic 并被 recover）。

**3. `reflect.Value` 操作的恐慌测试:**

```go
package main

import (
	"fmt"
	"reflect"
)

func main() {
	v := reflect.ValueOf(10)

	defer func() {
		if r := recover(); r != nil {
			fmt.Println("发生 panic:", r)
		}
	}()

	// 在 int 类型的 Value 上调用 Bool() 会 panic
	fmt.Println("尝试调用 Bool():")
	v.Bool()
}
```

**假设输入与输出:**

代码会尝试在 `int` 类型的 `Value` 上调用 `Bool()` 方法，这将导致 panic 并输出相应的错误信息。

**4. 类型转换测试:**

```go
package main

import (
	"fmt"
	"reflect"
)

type MyInt int

func main() {
	var i int = 10
	v := reflect.ValueOf(i)

	// 转换为 int64
	vInt64 := v.Convert(reflect.TypeOf(int64(0)))
	fmt.Printf("int 转换为 int64: 类型=%s, 值=%v\n", vInt64.Type(), vInt64.Int())

	// 转换为 MyInt
	vMyInt := v.Convert(reflect.TypeOf(MyInt(0)))
	fmt.Printf("int 转换为 MyInt: 类型=%s, 值=%v\n", vMyInt.Type(), vMyInt.Interface())

	// 尝试将 int 转换为 string (会 panic 如果没有类型断言)
	defer func() {
		if r := recover(); r != nil {
			fmt.Println("类型转换 panic:", r)
		}
	}()
	vString := v.Convert(reflect.TypeOf(""))
	fmt.Printf("int 转换为 string: 类型=%s, 值=%v\n", vString.Type(), vString.String()) // 实际不会执行到这里
}
```

**假设输入与输出:**

代码会演示 `int` 类型的值转换为 `int64` 和自定义类型 `MyInt` 的过程。尝试转换为 `string` 会触发 panic，因为这是不安全的类型转换。

**易犯错的点 (结合之前的代码):**

- **尝试修改不可寻址的 `reflect.Value`:**  例如，获取结构体未导出字段的 `Value` 后尝试 `SetInt()` 会导致 panic。
- **在类型不匹配的 `reflect.Value` 上调用方法:**  例如，在 `string` 类型的 `Value` 上调用 `Int()`。
- **不理解类型转换的限制:** 某些类型之间的转换是不允许的，或者需要显式的类型断言。

总而言之，这部分 `all_test.go` 代码是 `reflect` 包功能测试的重要组成部分，它细致地检验了结构体字段的访问和修改规则，方法调用的各种场景，以及类型转换的正确性和安全性。

Prompt: 
```
这是路径为go/src/reflect/all_test.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第4部分，共7部分，请归纳一下它的功能

"""
2.namedT0
	bad(func() { clear(v.Field(6).Field(1).Field(0)) }) // .namedT2.namedT0.W

	// addressable
	v = ValueOf(&T{}).Elem()
	ok(func() { clear(v.Field(0)) })                    // .X
	bad(func() { clear(v.Field(1)) })                   // .t1
	ok(func() { clear(v.Field(1).Field(0)) })           // .t1.Y
	bad(func() { clear(v.Field(1).Field(1)) })          // .t1.t0
	ok(func() { clear(v.Field(1).Field(1).Field(0)) })  // .t1.t0.W
	ok(func() { clear(v.Field(2)) })                    // .T2
	ok(func() { clear(v.Field(2).Field(0)) })           // .T2.Z
	bad(func() { clear(v.Field(2).Field(1)) })          // .T2.namedT0
	bad(func() { clear(v.Field(2).Field(1).Field(0)) }) // .T2.namedT0.W
	ok(func() { clear(v.Field(3)) })                    // .NamedT1
	ok(func() { clear(v.Field(3).Field(0)) })           // .NamedT1.Y
	bad(func() { clear(v.Field(3).Field(1)) })          // .NamedT1.t0
	ok(func() { clear(v.Field(3).Field(1).Field(0)) })  // .NamedT1.t0.W
	ok(func() { clear(v.Field(4)) })                    // .NamedT2
	ok(func() { clear(v.Field(4).Field(0)) })           // .NamedT2.Z
	bad(func() { clear(v.Field(4).Field(1)) })          // .NamedT2.namedT0
	bad(func() { clear(v.Field(4).Field(1).Field(0)) }) // .NamedT2.namedT0.W
	bad(func() { clear(v.Field(5)) })                   // .namedT1
	bad(func() { clear(v.Field(5).Field(0)) })          // .namedT1.Y
	bad(func() { clear(v.Field(5).Field(1)) })          // .namedT1.t0
	bad(func() { clear(v.Field(5).Field(1).Field(0)) }) // .namedT1.t0.W
	bad(func() { clear(v.Field(6)) })                   // .namedT2
	bad(func() { clear(v.Field(6).Field(0)) })          // .namedT2.Z
	bad(func() { clear(v.Field(6).Field(1)) })          // .namedT2.namedT0
	bad(func() { clear(v.Field(6).Field(1).Field(0)) }) // .namedT2.namedT0.W
}

type timp int

func (t timp) W() {}
func (t timp) Y() {}
func (t timp) w() {}
func (t timp) y() {}

func TestCallPanic(t *testing.T) {
	type t0 interface {
		W()
		w()
	}
	type T1 interface {
		Y()
		y()
	}
	type T2 struct {
		T1
		t0
	}
	type T struct {
		t0 // 0
		T1 // 1

		NamedT0 t0 // 2
		NamedT1 T1 // 3
		NamedT2 T2 // 4

		namedT0 t0 // 5
		namedT1 T1 // 6
		namedT2 T2 // 7
	}
	ok := func(f func()) { f() }
	badCall := func(f func()) { shouldPanic("Call", f) }
	badMethod := func(f func()) { shouldPanic("Method", f) }
	call := func(v Value) { v.Call(nil) }

	i := timp(0)
	v := ValueOf(T{i, i, i, i, T2{i, i}, i, i, T2{i, i}})
	badCall(func() { call(v.Field(0).Method(0)) })          // .t0.W
	badCall(func() { call(v.Field(0).Elem().Method(0)) })   // .t0.W
	badCall(func() { call(v.Field(0).Method(1)) })          // .t0.w
	badMethod(func() { call(v.Field(0).Elem().Method(2)) }) // .t0.w
	ok(func() { call(v.Field(1).Method(0)) })               // .T1.Y
	ok(func() { call(v.Field(1).Elem().Method(0)) })        // .T1.Y
	badCall(func() { call(v.Field(1).Method(1)) })          // .T1.y
	badMethod(func() { call(v.Field(1).Elem().Method(2)) }) // .T1.y

	ok(func() { call(v.Field(2).Method(0)) })               // .NamedT0.W
	ok(func() { call(v.Field(2).Elem().Method(0)) })        // .NamedT0.W
	badCall(func() { call(v.Field(2).Method(1)) })          // .NamedT0.w
	badMethod(func() { call(v.Field(2).Elem().Method(2)) }) // .NamedT0.w

	ok(func() { call(v.Field(3).Method(0)) })               // .NamedT1.Y
	ok(func() { call(v.Field(3).Elem().Method(0)) })        // .NamedT1.Y
	badCall(func() { call(v.Field(3).Method(1)) })          // .NamedT1.y
	badMethod(func() { call(v.Field(3).Elem().Method(3)) }) // .NamedT1.y

	ok(func() { call(v.Field(4).Field(0).Method(0)) })             // .NamedT2.T1.Y
	ok(func() { call(v.Field(4).Field(0).Elem().Method(0)) })      // .NamedT2.T1.W
	badCall(func() { call(v.Field(4).Field(1).Method(0)) })        // .NamedT2.t0.W
	badCall(func() { call(v.Field(4).Field(1).Elem().Method(0)) }) // .NamedT2.t0.W

	badCall(func() { call(v.Field(5).Method(0)) })          // .namedT0.W
	badCall(func() { call(v.Field(5).Elem().Method(0)) })   // .namedT0.W
	badCall(func() { call(v.Field(5).Method(1)) })          // .namedT0.w
	badMethod(func() { call(v.Field(5).Elem().Method(2)) }) // .namedT0.w

	badCall(func() { call(v.Field(6).Method(0)) })        // .namedT1.Y
	badCall(func() { call(v.Field(6).Elem().Method(0)) }) // .namedT1.Y
	badCall(func() { call(v.Field(6).Method(0)) })        // .namedT1.y
	badCall(func() { call(v.Field(6).Elem().Method(0)) }) // .namedT1.y

	badCall(func() { call(v.Field(7).Field(0).Method(0)) })        // .namedT2.T1.Y
	badCall(func() { call(v.Field(7).Field(0).Elem().Method(0)) }) // .namedT2.T1.W
	badCall(func() { call(v.Field(7).Field(1).Method(0)) })        // .namedT2.t0.W
	badCall(func() { call(v.Field(7).Field(1).Elem().Method(0)) }) // .namedT2.t0.W
}

func TestValuePanic(t *testing.T) {
	vo := ValueOf
	shouldPanic("reflect.Value.Addr of unaddressable value", func() { vo(0).Addr() })
	shouldPanic("call of reflect.Value.Bool on float64 Value", func() { vo(0.0).Bool() })
	shouldPanic("call of reflect.Value.Bytes on string Value", func() { vo("").Bytes() })
	shouldPanic("call of reflect.Value.Call on bool Value", func() { vo(true).Call(nil) })
	shouldPanic("call of reflect.Value.CallSlice on int Value", func() { vo(0).CallSlice(nil) })
	shouldPanic("call of reflect.Value.Close on string Value", func() { vo("").Close() })
	shouldPanic("call of reflect.Value.Complex on float64 Value", func() { vo(0.0).Complex() })
	shouldPanic("call of reflect.Value.Elem on bool Value", func() { vo(false).Elem() })
	shouldPanic("call of reflect.Value.Field on int Value", func() { vo(0).Field(0) })
	shouldPanic("call of reflect.Value.Float on string Value", func() { vo("").Float() })
	shouldPanic("call of reflect.Value.Index on float64 Value", func() { vo(0.0).Index(0) })
	shouldPanic("call of reflect.Value.Int on bool Value", func() { vo(false).Int() })
	shouldPanic("call of reflect.Value.IsNil on int Value", func() { vo(0).IsNil() })
	shouldPanic("call of reflect.Value.Len on bool Value", func() { vo(false).Len() })
	shouldPanic("call of reflect.Value.MapIndex on float64 Value", func() { vo(0.0).MapIndex(vo(0.0)) })
	shouldPanic("call of reflect.Value.MapKeys on string Value", func() { vo("").MapKeys() })
	shouldPanic("call of reflect.Value.MapRange on int Value", func() { vo(0).MapRange() })
	shouldPanic("call of reflect.Value.Method on zero Value", func() { vo(nil).Method(0) })
	shouldPanic("call of reflect.Value.NumField on string Value", func() { vo("").NumField() })
	shouldPanic("call of reflect.Value.NumMethod on zero Value", func() { vo(nil).NumMethod() })
	shouldPanic("call of reflect.Value.OverflowComplex on float64 Value", func() { vo(float64(0)).OverflowComplex(0) })
	shouldPanic("call of reflect.Value.OverflowFloat on int64 Value", func() { vo(int64(0)).OverflowFloat(0) })
	shouldPanic("call of reflect.Value.OverflowInt on uint64 Value", func() { vo(uint64(0)).OverflowInt(0) })
	shouldPanic("call of reflect.Value.OverflowUint on complex64 Value", func() { vo(complex64(0)).OverflowUint(0) })
	shouldPanic("call of reflect.Value.Recv on string Value", func() { vo("").Recv() })
	shouldPanic("call of reflect.Value.Send on bool Value", func() { vo(true).Send(vo(true)) })
	shouldPanic("value of type string is not assignable to type bool", func() { vo(new(bool)).Elem().Set(vo("")) })
	shouldPanic("call of reflect.Value.SetBool on string Value", func() { vo(new(string)).Elem().SetBool(false) })
	shouldPanic("reflect.Value.SetBytes using unaddressable value", func() { vo("").SetBytes(nil) })
	shouldPanic("call of reflect.Value.SetCap on string Value", func() { vo(new(string)).Elem().SetCap(0) })
	shouldPanic("call of reflect.Value.SetComplex on string Value", func() { vo(new(string)).Elem().SetComplex(0) })
	shouldPanic("call of reflect.Value.SetFloat on string Value", func() { vo(new(string)).Elem().SetFloat(0) })
	shouldPanic("call of reflect.Value.SetInt on string Value", func() { vo(new(string)).Elem().SetInt(0) })
	shouldPanic("call of reflect.Value.SetLen on string Value", func() { vo(new(string)).Elem().SetLen(0) })
	shouldPanic("call of reflect.Value.SetString on int Value", func() { vo(new(int)).Elem().SetString("") })
	shouldPanic("reflect.Value.SetUint using unaddressable value", func() { vo(0.0).SetUint(0) })
	shouldPanic("call of reflect.Value.Slice on bool Value", func() { vo(true).Slice(1, 2) })
	shouldPanic("call of reflect.Value.Slice3 on int Value", func() { vo(0).Slice3(1, 2, 3) })
	shouldPanic("call of reflect.Value.TryRecv on bool Value", func() { vo(true).TryRecv() })
	shouldPanic("call of reflect.Value.TrySend on string Value", func() { vo("").TrySend(vo("")) })
	shouldPanic("call of reflect.Value.Uint on float64 Value", func() { vo(0.0).Uint() })
}

func shouldPanic(expect string, f func()) {
	defer func() {
		r := recover()
		if r == nil {
			panic("did not panic")
		}
		if expect != "" {
			var s string
			switch r := r.(type) {
			case string:
				s = r
			case *ValueError:
				s = r.Error()
			default:
				panic(fmt.Sprintf("panicked with unexpected type %T", r))
			}
			if !strings.HasPrefix(s, "reflect") {
				panic(`panic string does not start with "reflect": ` + s)
			}
			if !strings.Contains(s, expect) {
				panic(`panic string does not contain "` + expect + `": ` + s)
			}
		}
	}()
	f()
}

func isNonNil(x any) {
	if x == nil {
		panic("nil interface")
	}
}

func isValid(v Value) {
	if !v.IsValid() {
		panic("zero Value")
	}
}

func TestAlias(t *testing.T) {
	x := string("hello")
	v := ValueOf(&x).Elem()
	oldvalue := v.Interface()
	v.SetString("world")
	newvalue := v.Interface()

	if oldvalue != "hello" || newvalue != "world" {
		t.Errorf("aliasing: old=%q new=%q, want hello, world", oldvalue, newvalue)
	}
}

var V = ValueOf

func EmptyInterfaceV(x any) Value {
	return ValueOf(&x).Elem()
}

func ReaderV(x io.Reader) Value {
	return ValueOf(&x).Elem()
}

func ReadWriterV(x io.ReadWriter) Value {
	return ValueOf(&x).Elem()
}

type Empty struct{}
type MyStruct struct {
	x int `some:"tag"`
}
type MyStruct1 struct {
	x struct {
		int `some:"bar"`
	}
}
type MyStruct2 struct {
	x struct {
		int `some:"foo"`
	}
}
type MyString string
type MyBytes []byte
type MyBytesArrayPtr0 *[0]byte
type MyBytesArrayPtr *[4]byte
type MyBytesArray0 [0]byte
type MyBytesArray [4]byte
type MyRunes []int32
type MyFunc func()
type MyByte byte

type IntChan chan int
type IntChanRecv <-chan int
type IntChanSend chan<- int
type BytesChan chan []byte
type BytesChanRecv <-chan []byte
type BytesChanSend chan<- []byte

var convertTests = []struct {
	in  Value
	out Value
}{
	// numbers
	/*
		Edit .+1,/\*\//-1>cat >/tmp/x.go && go run /tmp/x.go

		package main

		import "fmt"

		var numbers = []string{
			"int8", "uint8", "int16", "uint16",
			"int32", "uint32", "int64", "uint64",
			"int", "uint", "uintptr",
			"float32", "float64",
		}

		func main() {
			// all pairs but in an unusual order,
			// to emit all the int8, uint8 cases
			// before n grows too big.
			n := 1
			for i, f := range numbers {
				for _, g := range numbers[i:] {
					fmt.Printf("\t{V(%s(%d)), V(%s(%d))},\n", f, n, g, n)
					n++
					if f != g {
						fmt.Printf("\t{V(%s(%d)), V(%s(%d))},\n", g, n, f, n)
						n++
					}
				}
			}
		}
	*/
	{V(int8(1)), V(int8(1))},
	{V(int8(2)), V(uint8(2))},
	{V(uint8(3)), V(int8(3))},
	{V(int8(4)), V(int16(4))},
	{V(int16(5)), V(int8(5))},
	{V(int8(6)), V(uint16(6))},
	{V(uint16(7)), V(int8(7))},
	{V(int8(8)), V(int32(8))},
	{V(int32(9)), V(int8(9))},
	{V(int8(10)), V(uint32(10))},
	{V(uint32(11)), V(int8(11))},
	{V(int8(12)), V(int64(12))},
	{V(int64(13)), V(int8(13))},
	{V(int8(14)), V(uint64(14))},
	{V(uint64(15)), V(int8(15))},
	{V(int8(16)), V(int(16))},
	{V(int(17)), V(int8(17))},
	{V(int8(18)), V(uint(18))},
	{V(uint(19)), V(int8(19))},
	{V(int8(20)), V(uintptr(20))},
	{V(uintptr(21)), V(int8(21))},
	{V(int8(22)), V(float32(22))},
	{V(float32(23)), V(int8(23))},
	{V(int8(24)), V(float64(24))},
	{V(float64(25)), V(int8(25))},
	{V(uint8(26)), V(uint8(26))},
	{V(uint8(27)), V(int16(27))},
	{V(int16(28)), V(uint8(28))},
	{V(uint8(29)), V(uint16(29))},
	{V(uint16(30)), V(uint8(30))},
	{V(uint8(31)), V(int32(31))},
	{V(int32(32)), V(uint8(32))},
	{V(uint8(33)), V(uint32(33))},
	{V(uint32(34)), V(uint8(34))},
	{V(uint8(35)), V(int64(35))},
	{V(int64(36)), V(uint8(36))},
	{V(uint8(37)), V(uint64(37))},
	{V(uint64(38)), V(uint8(38))},
	{V(uint8(39)), V(int(39))},
	{V(int(40)), V(uint8(40))},
	{V(uint8(41)), V(uint(41))},
	{V(uint(42)), V(uint8(42))},
	{V(uint8(43)), V(uintptr(43))},
	{V(uintptr(44)), V(uint8(44))},
	{V(uint8(45)), V(float32(45))},
	{V(float32(46)), V(uint8(46))},
	{V(uint8(47)), V(float64(47))},
	{V(float64(48)), V(uint8(48))},
	{V(int16(49)), V(int16(49))},
	{V(int16(50)), V(uint16(50))},
	{V(uint16(51)), V(int16(51))},
	{V(int16(52)), V(int32(52))},
	{V(int32(53)), V(int16(53))},
	{V(int16(54)), V(uint32(54))},
	{V(uint32(55)), V(int16(55))},
	{V(int16(56)), V(int64(56))},
	{V(int64(57)), V(int16(57))},
	{V(int16(58)), V(uint64(58))},
	{V(uint64(59)), V(int16(59))},
	{V(int16(60)), V(int(60))},
	{V(int(61)), V(int16(61))},
	{V(int16(62)), V(uint(62))},
	{V(uint(63)), V(int16(63))},
	{V(int16(64)), V(uintptr(64))},
	{V(uintptr(65)), V(int16(65))},
	{V(int16(66)), V(float32(66))},
	{V(float32(67)), V(int16(67))},
	{V(int16(68)), V(float64(68))},
	{V(float64(69)), V(int16(69))},
	{V(uint16(70)), V(uint16(70))},
	{V(uint16(71)), V(int32(71))},
	{V(int32(72)), V(uint16(72))},
	{V(uint16(73)), V(uint32(73))},
	{V(uint32(74)), V(uint16(74))},
	{V(uint16(75)), V(int64(75))},
	{V(int64(76)), V(uint16(76))},
	{V(uint16(77)), V(uint64(77))},
	{V(uint64(78)), V(uint16(78))},
	{V(uint16(79)), V(int(79))},
	{V(int(80)), V(uint16(80))},
	{V(uint16(81)), V(uint(81))},
	{V(uint(82)), V(uint16(82))},
	{V(uint16(83)), V(uintptr(83))},
	{V(uintptr(84)), V(uint16(84))},
	{V(uint16(85)), V(float32(85))},
	{V(float32(86)), V(uint16(86))},
	{V(uint16(87)), V(float64(87))},
	{V(float64(88)), V(uint16(88))},
	{V(int32(89)), V(int32(89))},
	{V(int32(90)), V(uint32(90))},
	{V(uint32(91)), V(int32(91))},
	{V(int32(92)), V(int64(92))},
	{V(int64(93)), V(int32(93))},
	{V(int32(94)), V(uint64(94))},
	{V(uint64(95)), V(int32(95))},
	{V(int32(96)), V(int(96))},
	{V(int(97)), V(int32(97))},
	{V(int32(98)), V(uint(98))},
	{V(uint(99)), V(int32(99))},
	{V(int32(100)), V(uintptr(100))},
	{V(uintptr(101)), V(int32(101))},
	{V(int32(102)), V(float32(102))},
	{V(float32(103)), V(int32(103))},
	{V(int32(104)), V(float64(104))},
	{V(float64(105)), V(int32(105))},
	{V(uint32(106)), V(uint32(106))},
	{V(uint32(107)), V(int64(107))},
	{V(int64(108)), V(uint32(108))},
	{V(uint32(109)), V(uint64(109))},
	{V(uint64(110)), V(uint32(110))},
	{V(uint32(111)), V(int(111))},
	{V(int(112)), V(uint32(112))},
	{V(uint32(113)), V(uint(113))},
	{V(uint(114)), V(uint32(114))},
	{V(uint32(115)), V(uintptr(115))},
	{V(uintptr(116)), V(uint32(116))},
	{V(uint32(117)), V(float32(117))},
	{V(float32(118)), V(uint32(118))},
	{V(uint32(119)), V(float64(119))},
	{V(float64(120)), V(uint32(120))},
	{V(int64(121)), V(int64(121))},
	{V(int64(122)), V(uint64(122))},
	{V(uint64(123)), V(int64(123))},
	{V(int64(124)), V(int(124))},
	{V(int(125)), V(int64(125))},
	{V(int64(126)), V(uint(126))},
	{V(uint(127)), V(int64(127))},
	{V(int64(128)), V(uintptr(128))},
	{V(uintptr(129)), V(int64(129))},
	{V(int64(130)), V(float32(130))},
	{V(float32(131)), V(int64(131))},
	{V(int64(132)), V(float64(132))},
	{V(float64(133)), V(int64(133))},
	{V(uint64(134)), V(uint64(134))},
	{V(uint64(135)), V(int(135))},
	{V(int(136)), V(uint64(136))},
	{V(uint64(137)), V(uint(137))},
	{V(uint(138)), V(uint64(138))},
	{V(uint64(139)), V(uintptr(139))},
	{V(uintptr(140)), V(uint64(140))},
	{V(uint64(141)), V(float32(141))},
	{V(float32(142)), V(uint64(142))},
	{V(uint64(143)), V(float64(143))},
	{V(float64(144)), V(uint64(144))},
	{V(int(145)), V(int(145))},
	{V(int(146)), V(uint(146))},
	{V(uint(147)), V(int(147))},
	{V(int(148)), V(uintptr(148))},
	{V(uintptr(149)), V(int(149))},
	{V(int(150)), V(float32(150))},
	{V(float32(151)), V(int(151))},
	{V(int(152)), V(float64(152))},
	{V(float64(153)), V(int(153))},
	{V(uint(154)), V(uint(154))},
	{V(uint(155)), V(uintptr(155))},
	{V(uintptr(156)), V(uint(156))},
	{V(uint(157)), V(float32(157))},
	{V(float32(158)), V(uint(158))},
	{V(uint(159)), V(float64(159))},
	{V(float64(160)), V(uint(160))},
	{V(uintptr(161)), V(uintptr(161))},
	{V(uintptr(162)), V(float32(162))},
	{V(float32(163)), V(uintptr(163))},
	{V(uintptr(164)), V(float64(164))},
	{V(float64(165)), V(uintptr(165))},
	{V(float32(166)), V(float32(166))},
	{V(float32(167)), V(float64(167))},
	{V(float64(168)), V(float32(168))},
	{V(float64(169)), V(float64(169))},

	// truncation
	{V(float64(1.5)), V(int(1))},

	// complex
	{V(complex64(1i)), V(complex64(1i))},
	{V(complex64(2i)), V(complex128(2i))},
	{V(complex128(3i)), V(complex64(3i))},
	{V(complex128(4i)), V(complex128(4i))},

	// string
	{V(string("hello")), V(string("hello"))},
	{V(string("bytes1")), V([]byte("bytes1"))},
	{V([]byte("bytes2")), V(string("bytes2"))},
	{V([]byte("bytes3")), V([]byte("bytes3"))},
	{V(string("runes♝")), V([]rune("runes♝"))},
	{V([]rune("runes♕")), V(string("runes♕"))},
	{V([]rune("runes🙈🙉🙊")), V([]rune("runes🙈🙉🙊"))},
	{V(int('a')), V(string("a"))},
	{V(int8('a')), V(string("a"))},
	{V(int16('a')), V(string("a"))},
	{V(int32('a')), V(string("a"))},
	{V(int64('a')), V(string("a"))},
	{V(uint('a')), V(string("a"))},
	{V(uint8('a')), V(string("a"))},
	{V(uint16('a')), V(string("a"))},
	{V(uint32('a')), V(string("a"))},
	{V(uint64('a')), V(string("a"))},
	{V(uintptr('a')), V(string("a"))},
	{V(int(-1)), V(string("\uFFFD"))},
	{V(int8(-2)), V(string("\uFFFD"))},
	{V(int16(-3)), V(string("\uFFFD"))},
	{V(int32(-4)), V(string("\uFFFD"))},
	{V(int64(-5)), V(string("\uFFFD"))},
	{V(int64(-1 << 32)), V(string("\uFFFD"))},
	{V(int64(1 << 32)), V(string("\uFFFD"))},
	{V(uint(0x110001)), V(string("\uFFFD"))},
	{V(uint32(0x110002)), V(string("\uFFFD"))},
	{V(uint64(0x110003)), V(string("\uFFFD"))},
	{V(uint64(1 << 32)), V(string("\uFFFD"))},
	{V(uintptr(0x110004)), V(string("\uFFFD"))},

	// named string
	{V(MyString("hello")), V(string("hello"))},
	{V(string("hello")), V(MyString("hello"))},
	{V(string("hello")), V(string("hello"))},
	{V(MyString("hello")), V(MyString("hello"))},
	{V(MyString("bytes1")), V([]byte("bytes1"))},
	{V([]byte("bytes2")), V(MyString("bytes2"))},
	{V([]byte("bytes3")), V([]byte("bytes3"))},
	{V(MyString("runes♝")), V([]rune("runes♝"))},
	{V([]rune("runes♕")), V(MyString("runes♕"))},
	{V([]rune("runes🙈🙉🙊")), V([]rune("runes🙈🙉🙊"))},
	{V([]rune("runes🙈🙉🙊")), V(MyRunes("runes🙈🙉🙊"))},
	{V(MyRunes("runes🙈🙉🙊")), V([]rune("runes🙈🙉🙊"))},
	{V(int('a')), V(MyString("a"))},
	{V(int8('a')), V(MyString("a"))},
	{V(int16('a')), V(MyString("a"))},
	{V(int32('a')), V(MyString("a"))},
	{V(int64('a')), V(MyString("a"))},
	{V(uint('a')), V(MyString("a"))},
	{V(uint8('a')), V(MyString("a"))},
	{V(uint16('a')), V(MyString("a"))},
	{V(uint32('a')), V(MyString("a"))},
	{V(uint64('a')), V(MyString("a"))},
	{V(uintptr('a')), V(MyString("a"))},
	{V(int(-1)), V(MyString("\uFFFD"))},
	{V(int8(-2)), V(MyString("\uFFFD"))},
	{V(int16(-3)), V(MyString("\uFFFD"))},
	{V(int32(-4)), V(MyString("\uFFFD"))},
	{V(int64(-5)), V(MyString("\uFFFD"))},
	{V(uint(0x110001)), V(MyString("\uFFFD"))},
	{V(uint32(0x110002)), V(MyString("\uFFFD"))},
	{V(uint64(0x110003)), V(MyString("\uFFFD"))},
	{V(uintptr(0x110004)), V(MyString("\uFFFD"))},

	// named []byte
	{V(string("bytes1")), V(MyBytes("bytes1"))},
	{V(MyBytes("bytes2")), V(string("bytes2"))},
	{V(MyBytes("bytes3")), V(MyBytes("bytes3"))},
	{V(MyString("bytes1")), V(MyBytes("bytes1"))},
	{V(MyBytes("bytes2")), V(MyString("bytes2"))},

	// named []rune
	{V(string("runes♝")), V(MyRunes("runes♝"))},
	{V(MyRunes("runes♕")), V(string("runes♕"))},
	{V(MyRunes("runes🙈🙉🙊")), V(MyRunes("runes🙈🙉🙊"))},
	{V(MyString("runes♝")), V(MyRunes("runes♝"))},
	{V(MyRunes("runes♕")), V(MyString("runes♕"))},

	// slice to array
	{V([]byte(nil)), V([0]byte{})},
	{V([]byte{}), V([0]byte{})},
	{V([]byte{1}), V([1]byte{1})},
	{V([]byte{1, 2}), V([2]byte{1, 2})},
	{V([]byte{1, 2, 3}), V([3]byte{1, 2, 3})},
	{V(MyBytes([]byte(nil))), V([0]byte{})},
	{V(MyBytes{}), V([0]byte{})},
	{V(MyBytes{1}), V([1]byte{1})},
	{V(MyBytes{1, 2}), V([2]byte{1, 2})},
	{V(MyBytes{1, 2, 3}), V([3]byte{1, 2, 3})},
	{V([]byte(nil)), V(MyBytesArray0{})},
	{V([]byte{}), V(MyBytesArray0([0]byte{}))},
	{V([]byte{1, 2, 3, 4}), V(MyBytesArray([4]byte{1, 2, 3, 4}))},
	{V(MyBytes{}), V(MyBytesArray0([0]byte{}))},
	{V(MyBytes{5, 6, 7, 8}), V(MyBytesArray([4]byte{5, 6, 7, 8}))},
	{V([]MyByte{}), V([0]MyByte{})},
	{V([]MyByte{1, 2}), V([2]MyByte{1, 2})},

	// slice to array pointer
	{V([]byte(nil)), V((*[0]byte)(nil))},
	{V([]byte{}), V(new([0]byte))},
	{V([]byte{7}), V(&[1]byte{7})},
	{V(MyBytes([]byte(nil))), V((*[0]byte)(nil))},
	{V(MyBytes([]byte{})), V(new([0]byte))},
	{V(MyBytes([]byte{9})), V(&[1]byte{9})},
	{V([]byte(nil)), V(MyBytesArrayPtr0(nil))},
	{V([]byte{}), V(MyBytesArrayPtr0(new([0]byte)))},
	{V([]byte{1, 2, 3, 4}), V(MyBytesArrayPtr(&[4]byte{1, 2, 3, 4}))},
	{V(MyBytes([]byte{})), V(MyBytesArrayPtr0(new([0]byte)))},
	{V(MyBytes([]byte{5, 6, 7, 8})), V(MyBytesArrayPtr(&[4]byte{5, 6, 7, 8}))},

	{V([]byte(nil)), V((*MyBytesArray0)(nil))},
	{V([]byte{}), V((*MyBytesArray0)(new([0]byte)))},
	{V([]byte{1, 2, 3, 4}), V(&MyBytesArray{1, 2, 3, 4})},
	{V(MyBytes([]byte(nil))), V((*MyBytesArray0)(nil))},
	{V(MyBytes([]byte{})), V((*MyBytesArray0)(new([0]byte)))},
	{V(MyBytes([]byte{5, 6, 7, 8})), V(&MyBytesArray{5, 6, 7, 8})},
	{V(new([0]byte)), V(new(MyBytesArray0))},
	{V(new(MyBytesArray0)), V(new([0]byte))},
	{V(MyBytesArrayPtr0(nil)), V((*[0]byte)(nil))},
	{V((*[0]byte)(nil)), V(MyBytesArrayPtr0(nil))},

	// named types and equal underlying types
	{V(new(int)), V(new(integer))},
	{V(new(integer)), V(new(int))},
	{V(Empty{}), V(struct{}{})},
	{V(new(Empty)), V(new(struct{}))},
	{V(struct{}{}), V(Empty{})},
	{V(new(struct{})), V(new(Empty))},
	{V(Empty{}), V(Empty{})},
	{V(MyBytes{}), V([]byte{})},
	{V([]byte{}), V(MyBytes{})},
	{V((func())(nil)), V(MyFunc(nil))},
	{V((MyFunc)(nil)), V((func())(nil))},

	// structs with different tags
	{V(struct {
		x int `some:"foo"`
	}{}), V(struct {
		x int `some:"bar"`
	}{})},

	{V(struct {
		x int `some:"bar"`
	}{}), V(struct {
		x int `some:"foo"`
	}{})},

	{V(MyStruct{}), V(struct {
		x int `some:"foo"`
	}{})},

	{V(struct {
		x int `some:"foo"`
	}{}), V(MyStruct{})},

	{V(MyStruct{}), V(struct {
		x int `some:"bar"`
	}{})},

	{V(struct {
		x int `some:"bar"`
	}{}), V(MyStruct{})},

	{V(MyStruct1{}), V(MyStruct2{})},
	{V(MyStruct2{}), V(MyStruct1{})},

	// can convert *byte and *MyByte
	{V((*byte)(nil)), V((*MyByte)(nil))},
	{V((*MyByte)(nil)), V((*byte)(nil))},

	// cannot convert mismatched array sizes
	{V([2]byte{}), V([2]byte{})},
	{V([3]byte{}), V([3]byte{})},
	{V(MyBytesArray0{}), V([0]byte{})},
	{V([0]byte{}), V(MyBytesArray0{})},

	// cannot convert other instances
	{V((**byte)(nil)), V((**byte)(nil))},
	{V((**MyByte)(nil)), V((**MyByte)(nil))},
	{V((chan byte)(nil)), V((chan byte)(nil))},
	{V((chan MyByte)(nil)), V((chan MyByte)(nil))},
	{V(([]byte)(nil)), V(([]byte)(nil))},
	{V(([]MyByte)(nil)), V(([]MyByte)(nil))},
	{V((map[int]byte)(nil)), V((map[int]byte)(nil))},
	{V((map[int]MyByte)(nil)), V((map[int]MyByte)(nil))},
	{V((map[byte]int)(nil)), V((map[byte]int)(nil))},
	{V((map[MyByte]int)(nil)), V((map[MyByte]int)(nil))},
	{V([2]byte{}), V([2]byte{})},
	{V([2]MyByte{}), V([2]MyByte{})},

	// other
	{V((***int)(nil)), V((***int)(nil))},
	{V((***byte)(nil)), V((***byte)(nil))},
	{V((***int32)(nil)), V((***int32)(nil))},
	{V((***int64)(nil)), V((***int64)(nil))},
	{V((chan byte)(nil)), V((chan byte)(nil))},
	{V((chan MyByte)(nil)), V((chan MyByte)(nil))},
	{V((map[int]bool)(nil)), V((map[int]bool)(nil))},
	{V((map[int]byte)(nil)), V((map[int]byte)(nil))},
	{V((map[uint]bool)(nil)), V((map[uint]bool)(nil))},
	{V([]uint(nil)), V([]uint(nil))},
	{V([]int(nil)), V([]int(nil))},
	{V(new(any)), V(new(any))},
	{V(new(io.Reader)), V(new(io.Reader))},
	{V(new(io.Writer)), V(new(io.Writer))},

	// channels
	{V(IntChan(nil)), V((chan<- int)(nil))},
	{V(IntChan(nil)), V((<-chan int)(nil))},
	{V((chan int)(nil)), V(IntChanRecv(nil))},
	{V((chan int)(nil)), V(IntChanSend(nil))},
	{V(IntChanRecv(nil)), V((<-chan int)(nil))},
	{V((<-chan int)(nil)), V(IntChanRecv(nil))},
	{V(IntChanSend(nil)), V((chan<- int)(nil))},
	{V((chan<- int)(nil)), V(IntChanSend(nil))},
	{V(IntChan(nil)), V((chan int)(nil))},
	{V((chan int)(nil)), V(IntChan(nil))},
	{V((chan int)(nil)), V((<-chan int)(nil))},
	{V((chan int)(nil)), V((chan<- int)(nil))},
	{V(BytesChan(nil)), V((chan<- []byte)(nil))},
	{V(BytesChan(nil)), V((<-chan []byte)(nil))},
	{V((chan []byte)(nil)), V(BytesChanRecv(nil))},
	{V((chan []byte)(nil)), V(BytesChanSend(nil))},
	{V(BytesChanRecv(nil)), V((<-chan []byte)(nil))},
	{V((<-chan []byte)(nil)), V(BytesChanRecv(nil))},
	{V(BytesChanSend(nil)), V((chan<- []byte)(nil))},
	{V((chan<- []byte)(nil)), V(BytesChanSend(nil))},
	{V(BytesChan(nil)), V((chan []byte)(nil))},
	{V((chan []byte)(nil)), V(BytesChan(nil))},
	{V((chan []byte)(nil)), V((<-chan []byte)(nil))},
	{V((chan []byte)(nil)), V((chan<- []byte)(nil))},

	// cannot convert other instances (channels)
	{V(IntChan(nil)), V(IntChan(nil))},
	{V(IntChanRecv(nil)), V(IntChanRecv(nil))},
	{V(IntChanSend(nil)), V(IntChanSend(nil))},
	{V(BytesChan(nil)), V(BytesChan(nil))},
	{V(BytesChanRecv(nil)), V(BytesChanRecv(nil))},
	{V(BytesChanSend(nil)), V(BytesChanSend(nil))},

	// interfaces
	{V(int(1)), EmptyInterfaceV(int(1))},
	{V(string("hello")), EmptyInterfaceV(string("hello"))},
	{V(new(bytes.Buffer)), ReaderV(new(bytes.Buffer))},
	{ReadWriterV(new(bytes.Buffer)), ReaderV(new(bytes.Buffer))},
	{V(new(bytes.Buffer)), ReadWriterV(new(bytes.Buffer))},
}

func TestConvert(t *testing.T) {
	canConvert := map[[2]Type]bool{}
	all := map[Type]bool{}

	for _, tt := range convertTests {
		t1 := tt.in.Type()
		if !t1.ConvertibleTo(t1) {
			t.Errorf("(%s).ConvertibleTo(%s) = false, want true", t1, t1)
			continue
		}

		t2 := tt.out.Type()
		if !t1.ConvertibleTo(t2) {
			t.Errorf("(%s).ConvertibleTo(%s) = false, want true", t1, t2)
			continue
		}

		all[t1] = true
		all[t2] = true
		canConvert[[2]Type{t1, t2}] = true

		// vout1 represents the in value converted to the in type.
		v1 := tt.in
		if !v1.CanConvert(t1) {
			t.Errorf("ValueOf(%T(%[1]v)).CanConvert(%s) = false, want true", tt.in.Interface(), t1)
		}
		vout1 := v1.Convert(t1)
		out1 := vout1.Interface()
		if vout1.Type() != tt.in.Type() || !DeepEqual(out1, tt.in.Interface()) {
			t.Errorf("ValueOf(%T(%[1]v)).Convert(%s) = %T(%[3]v), want %T(%[4]v)", tt.in.Interface(), t1, out1, tt.in.Interface())
		}

		// vout2 represents the in value converted to the out type.
		if !v1.CanConvert(t2) {
			t.Errorf("ValueOf(%T(%[1]v)).CanConvert(%s) = false, want true", tt.in.Interface(), t2)
		}
		vout2 := v1.Convert(t2)
		out2 := vout2.Interface()
		if vout2.Type() != tt.out.Type() || !DeepEqual(out2, tt.out.Interface()) {
			t.Errorf("ValueOf(%T(%[1]v)).Convert(%s) = %T(%[3]v), want %T(%[4]v)", tt.in.Interface(), t2, out2, tt.out.Interface())
		}
		if got, want := vout2.Kind(), vout2.Type().Kind(); got != want {
			t.Errorf("ValueOf(%T(%[1]v)).Convert(%s) has internal kind %v want %v", tt.in.Interface(), t1, got, want)
		}

		// vout3 represents a new value of the out type, set to vout2.  This makes
		// sure the converted value vout2 is really usable as a regular value.
		vout3 := New(t2).Elem()
		vout3.Set(vout2)
		out3 := vout3.Interface()
		if vout3.Type() != tt.out.Type() || !DeepEqual(out3, tt.out.Interface()) {
			t.Errorf("Set(ValueOf(%T(%[1]v)).Convert(%s)) = %T(%[3]v), want %T(%[4]v)", tt.in.Interface(), t2, out3, tt.out.Interface())
		}

		if IsRO(v1) {
			t.Errorf("table entry %v is RO, should not be", v1)
		}
		if IsRO(vout1) {
			t.Errorf("self-conversion output %v is RO, should not be", vout1)
		}
		if IsRO(vout2) {
			t.Errorf("conversion output %v is RO, should not be", vout2)
		}
		if IsRO(vout3) {
			t.Errorf("set(conversion output) %v is RO, should not be", vout3)
		}
		if !IsRO(MakeRO(v1).Convert(t1)) {
			t.Errorf("RO self-conversion output %v is not RO, should be", v1)
		}
		if !IsRO(MakeRO(v1).Convert(t2)) {
			t.Errorf("RO conversion output %v is not RO, should be", v1)
		}
	}

	// Assume that of all the types we saw during the tests,
	// if there wasn't an explicit entry for a conversion between
	// a pair of types, then it's not to be allowed. This checks for
	// things like 'int64' converting to '*int'.
	for t1 := range all {
		for t2 := range all {
			expectOK := t1 == t2 || canConvert[[2]Type{t1, t2}] || t2.Kind() == Interface && t2.NumMethod() == 0
			if ok := t1.ConvertibleTo(t2); ok != expectOK {
				t.Errorf("(%s).ConvertibleTo(%s) = %v, want %v", t1, t2, ok, expectOK)
			}
		}
	}
}

func TestConvertPanic(t *testing.T) {
	s := make([]byte, 4)
	p := new([8]byte)
	v := ValueOf(s)
	pt := TypeOf(p)
	if !v.Type().ConvertibleTo(pt) {
		t.Errorf("[]byte should be convertible to *[8]byte")
	}
	if v.CanConvert(pt) {
		t.Errorf("slice with length 4 should not be convertible to *[8]byte")
	}
	shouldPanic("reflect: cannot convert slice with length 4 to pointer to array with length 8", func() {
		_ = v.Convert(pt)
	})

	if v.CanConvert(pt.Elem()) {
		t.Errorf("slice with length 4 should not be convertible to [8]byte")
	}
	shouldPanic("reflect: cannot convert slice with length 4 to array with length 8", func() {
		_ = v.Convert(pt.Elem())
	})
}

func TestConvertSlice2Array(t *testing.T) {
	s := make([]int, 4)
	p := [4]int{}
	pt := TypeOf(p)
	ov := ValueOf(s)
	v := ov.Convert(pt)
	// Converting a slice to non-empty array needs to return
	// a non-addressable copy of the original memory.
	if v.CanAddr() {
		t.Fatalf("convert slice to non-empty array returns an addressable copy array")
	}
	for i := range s {
		ov.Index(i).Set(ValueOf(i + 1))
	}
	for i := range s {
		if v.Index(i).Int() != 0 {
			t.Fatalf("slice (%v) mutation visible in converted result (%v)", ov, v)
		}
	}
}

var gFloat32 float32

const snan uint32 = 0x7f800001

func TestConvertNaNs(t *testing.T) {
	// Test to see if a store followed by a load of a signaling NaN
	// maintains the signaling bit. (This used to fail on the 387 port.)
	gFloat32 = math.Float32frombits(snan)
	runtime.Gosched() // make sure we don't optimize the store/load away
	if got := math.Float32bits(gFloat32); got != snan {
		t.Errorf("store/load of sNaN not faithful, got %x want %x", got, snan)
	}
	// Test reflect's conversion between float32s. See issue 36400.
	type myFloat32 float32
	x := V(myFloat32(math.Float32frombits(snan)))
	y := x.Convert(TypeOf(float32(0)))
	z := y.Interface().(float32)
	if got := math.Float32bits(z); got != snan {
		t.Errorf("signaling nan conversion got %x, want %x", got, snan)
	}
}

type ComparableStruct struct {
	X int
}

type NonComparableStruct struct {
	X int
	Y map[string]int
}

var comparableTests = []struct {
	typ Type
	ok  bool
}{
	{TypeOf(1), true},
	{TypeOf("hello"), true},
	{TypeOf(new(byte)), true},
	{TypeOf((func())(nil)), false},
	{TypeOf([]byte{}), false},
	{TypeOf(map[string]int{}), false},
	{TypeOf(make(chan int)), true},
	{TypeOf(1.5), true},
	{TypeOf(false), true},
	{TypeOf(1i), true},
	{TypeOf(ComparableStruct{}), true},
	{TypeOf(NonComparableStruct{}), false},
	{TypeOf([10]map[string]int{}), false},
	{TypeOf([10]string{}), true},
	{TypeOf(new(any)).Elem(), true},
}

func TestComparable(t *testing.T) {
	for _, tt := range comparableTests {
		if ok := tt.typ.Comparable(); ok != tt.ok {
			t.Errorf("TypeOf(%v).Comparable() = %v, want %v", tt.typ, ok, tt.ok)
		}
	}
}

func TestValueOverflow(t *testing.T) {
	if ovf := V(float64(0)).OverflowFloat(1e300); ovf {
		t.Errorf("%v wrongly overflows float64", 1e300)
	}

	maxFloat32 := float64((1<<24 - 1) << (127 - 23))
	if ovf := V(float32(0)).OverflowFloat(maxFloat32); ovf {
		t.Errorf("%v wrongly overflows float32", maxFloat32)
	}
	ovfFloat32 := float64((1<<24-1)<<(127-23) + 1<<(127-52))
	if ovf := V(float32(0)).OverflowFloat(ovfFloat32); !ovf {
		t.Errorf("%v should overflow float32", ovfFloat32)
	}
	if ovf := V(float32(0)).OverflowFloat(-ovfFloat32); !ovf {
		t.Errorf("%v should overflow float32", -ovfFloat32)
	}

	maxInt32 := int64(0x7fffffff)
	if ovf := V(int32(0)).OverflowInt(maxInt32); ovf {
		t.Errorf("%v wrongly overflows int32", maxInt32)
	}
	if ovf := V(int32(0)).OverflowInt(-1 << 31); ovf {
		t.Errorf("%v wrongly overflows int32", -int64(1)<<31)
	}
	ovfInt32 := int64(1 << 31)
	if ovf := V(int32(0)).OverflowInt(ovfInt32); !ovf {
		t.Errorf("%v should overflow int32", ovfInt32)
	}

	maxUint32 :=
"""




```