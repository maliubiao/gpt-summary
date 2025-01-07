Response:
The user wants a summary of the Go code provided, which is part of `go/src/reflect/all_test.go`. This file seems to contain various test cases for the `reflect` package.

Here's a plan:
1. **Identify the main areas of functionality being tested.**  This involves looking at the names of the test functions and the operations performed within them.
2. **For each area, describe what it tests.**  This will involve explaining the purpose of the test and what aspects of the `reflect` package it verifies.
3. **If a test demonstrates a specific `reflect` feature, provide a code example.** This will make the explanation more concrete.
4. **If a test involves command-line arguments, explain their usage.** This section might not be relevant as it's a test file.
5. **Highlight common mistakes users might make related to the tested functionality.**
6. **Finally, provide a general summary of the file's overall purpose.**

Let's go through the code and identify the different test areas.

- `TestMapAlloc`: Tests the number of allocations when creating and assigning to maps, especially with size hints.
- `TestChanAlloc`: Tests the number of allocations during channel send and receive operations.
- `TestNames`: Tests the `Name()` method of `reflect.Type` for different types, including those with long names.
- `TestExported`: Tests the `IsExported()` function to check if a type is exported.
- `TestTypeStrings`: Tests the `String()` method of `reflect.Type` for various type representations.
- `TestOffsetLock`:  Seems to test concurrent access to some internal mechanism related to resolving reflect names (less clear without more context).
- `TestSwapper`: Tests the `Swapper` function which swaps elements in a slice.
- `TestUnaddressableField`: Tests that the `reflect` package prevents setting unexported fields of types from other packages.
- `TestAliasNames`: Tests how aliased types are represented when using `%#v` formatting.
- `TestIssue22031`: Tests the `CanSet()` method for fields in nested structs with slice fields.
- `TestIssue22073`: Tests calling methods with non-exported receivers.
- `TestMapIterNonEmptyMap`, `TestMapIterNilMap`, `TestMapIterReset`, `TestMapIterSafety`, `TestMapIterNext`, `TestMapIterDelete0`, `TestMapIterDelete1`: These tests extensively cover the functionality and safety of the `MapIter` type for iterating over maps.
- `TestConvertibleTo`: Tests the `ConvertibleTo()` method for types defined in different packages.
- `TestSetIter`: Tests the `SetIterKey` and `SetIterValue` methods of `reflect.Value` for map iterators.
- `TestMethodCallValueCodePtr`: Tests obtaining the code pointer of a method using `UnsafePointer()` and `Pointer()`.
- `TestIssue50208`: Tests the naming of generic types.
- `TestNegativeKindString`: Tests the `String()` method for negative `reflect.Kind` values.
- `TestValue_Cap`: Tests the `Cap()` method of `reflect.Value`.
- `TestValue_Len`: Tests the `Len()` method of `reflect.Value`.
- `TestValue_Comparable`: Tests the `Comparable()` method of `reflect.Value`.
- `TestValue_Equal`, `TestValue_EqualNonComparable`: Tests the `Equal()` method of `reflect.Value`.
- `TestInitFuncTypes`: Seems to test concurrent initialization of method information for function types.
- `TestClear`: Tests the `Clear()` method for maps and slices.
- `TestValuePointerAndUnsafePointer`: Tests the `Pointer()` and `UnsafePointer()` methods of `reflect.Value`.
- `TestSliceAt`: Tests the `SliceAt` function for creating slices from unsafe pointers.
- `TestMapOfKeyUpdate`: Tests that `MakeMap` with `MapOf` correctly handles key updates for floating-point zero values.
- `TestMapOfKeyPanic`: Tests that `MakeMap` with `MapOf` correctly panics on unhashable keys.

Now, let's start drafting the answer.
这是 `go/src/reflect/all_test.go` 文件的一部分，它专注于测试 Go 语言中 `reflect` 包的各种功能。`reflect` 包允许程序在运行时检查和操作类型信息。

以下是这段代码片段中各个测试用例的功能：

1. **`TestMapAlloc`**:  测试创建和操作 map 时内存的分配情况。它使用 `testing.AllocsPerRun` 来测量在向 map 中添加元素时发生的内存分配次数。这个测试用例特别关注使用 `MakeMapWithSize` 创建带有容量提示的 map，并验证其是否能减少不必要的重新分配。

    **Go 代码示例:**
    ```go
    package main

    import (
        "fmt"
        "reflect"
    )

    func main() {
        // 创建一个容量为 10 的 map
        mapType := reflect.TypeOf(map[int]int{})
        mapSize := 10
        mv := reflect.MakeMapWithSize(mapType, mapSize)

        // 向 map 中添加元素
        val := reflect.ValueOf(1)
        mv.SetMapIndex(val, val)

        fmt.Println(mv.Len()) // 输出: 1
    }
    ```
    **假设输入与输出:**  无特定的输入，此测试关注的是 `reflect.MakeMapWithSize` 的行为。预期的输出是当使用容量提示时，内存分配次数应该相对较少。

2. **`TestChanAlloc`**: 测试 channel 的发送和接收操作引起的内存分配次数。

    **Go 代码示例:**
    ```go
    package main

    import (
        "fmt"
        "reflect"
    )

    func main() {
        // 创建一个带缓冲的 channel
        chanType := reflect.TypeOf(make(chan *int, 1))
        cv := reflect.MakeChan(chanType, 1)

        // 创建一个 int 类型的指针
        intValue := reflect.ValueOf(new(int))

        // 发送和接收
        cv.Send(intValue)
        receivedValue, _ := cv.Recv()

        fmt.Println(receivedValue.IsNil()) // 输出: false
    }
    ```
    **假设输入与输出:** 无特定的输入，此测试关注 channel 发送和接收的内存分配。预期的输出是每次发送/接收操作分配的内存次数接近 1。

3. **`TestNames`**: 测试 `reflect.Type` 的 `Name()` 方法，用于获取类型的名称。这个测试用例覆盖了各种类型的命名，包括自定义类型和具有非常长名称的类型。

    **Go 代码示例:**
    ```go
    package main

    import (
        "fmt"
        "reflect"
    )

    type MyInt int

    func main() {
        var i MyInt
        typ := reflect.TypeOf(i)
        fmt.Println(typ.Name()) // 输出: MyInt
    }
    ```
    **假设输入与输出:**  不同的类型变量作为输入，输出是对应类型的名称字符串。例如，输入 `(*int32)(nil)`，输出 `"int32"`。

4. **`TestExported`**: 测试 `reflect.IsExported()` 函数，用于判断类型是否是导出的（首字母大写）。

    **Go 代码示例:**
    ```go
    package main

    import (
        "fmt"
        "reflect"
    )

    type ExportedType struct{}
    type unexportedType struct{}

    func main() {
        exportedTyp := reflect.TypeOf(ExportedType{})
        unexportedTyp := reflect.TypeOf(unexportedType{})

        fmt.Println(reflect.IsExported(exportedTyp))   // 输出: true
        fmt.Println(reflect.IsExported(unexportedTyp)) // 输出: false
    }
    ```
    **假设输入与输出:**  不同的类型变量作为输入，输出是布尔值，表示类型是否导出。例如，输入 `D1{}`，输出 `true`；输入 `big{}` (假设 `big` 是未导出的类型)，输出 `false`。

5. **`TestTypeStrings`**: 测试 `reflect.Type` 的 `String()` 方法，用于获取类型的字符串表示形式。

    **Go 代码示例:**
    ```go
    package main

    import (
        "fmt"
        "reflect"
    )

    type MyStruct struct {
        Field int
    }

    func (m MyStruct) Method() string {
        return ""
    }

    func main() {
        typ := reflect.TypeOf(MyStruct{})
        fmt.Println(typ.String())                 // 输出: main.MyStruct
        fmt.Println(reflect.TypeOf(new(MyStruct)).String()) // 输出: *main.MyStruct
        fmt.Println(reflect.TypeOf(new(MyStruct).Method).String()) // 输出: func() string
    }
    ```
    **假设输入与输出:** 不同的类型作为输入，输出是类型的字符串表示。例如，输入 `func(int) {}` 的类型，输出 `"func(int)"`。

6. **`TestOffsetLock`**:  这个测试似乎是为了验证在并发环境下，处理类型偏移量（offset）的相关操作是线程安全的。它创建了多个 goroutine 并发地调用 `ResolveReflectName` 函数。

    **命令行参数处理:**  这段代码本身没有直接处理命令行参数。它是一个内部测试，可能依赖于 Go 测试框架的并发执行能力。

    **使用者易犯错的点:**  如果不正确地处理并发访问共享的反射信息，可能会导致数据竞争或其他并发问题。这个测试用例旨在确保 `reflect` 包内部的机制能够安全地处理这种情况。

7. **`TestSwapper`**: 测试 `reflect.Swapper` 函数，该函数返回一个用于交换切片中两个元素的函数。

    **Go 代码示例:**
    ```go
    package main

    import (
        "fmt"
        "reflect"
        "slices"
    )

    func main() {
        s := []int{1, 2, 3}
        swapper := reflect.Swapper(s)
        swapper(0, 2)
        fmt.Println(s) // 输出: [3 2 1]
    }
    ```
    **假设输入与输出:**  输入一个切片和两个索引，输出是交换了指定索引元素的切片。例如，输入切片 `[]int{1, 20, 300}`，索引 `0` 和 `2`，输出 `[]int{300, 20, 1}`。

8. **`TestUnaddressableField`**:  测试 `reflect` 包是否禁止修改来自其他包的未导出字段。这确保了封装性。

    **使用者易犯错的点:**  试图使用 `reflect` 修改其他包中未导出的字段会引发 panic。

    **Go 代码示例 (演示错误用法):**
    ```go
    package main

    import (
        "reflect"
        "your_other_package" // 假设有这样一个包
    )

    func main() {
        b := your_other_package.Buffer{} // 假设 Buffer 在 your_other_package 中定义，且有未导出字段
        rv := reflect.ValueOf(&b).Elem()
        field := rv.FieldByName("unexportedField") // 假设有这样一个未导出字段
        // field.Set(...) // 这会 panic
        _ = field
    }
    ```

9. **`TestAliasNames`**: 测试别名类型的格式化输出 (`%#v`)。

    **Go 代码示例:**
    ```go
    package main

    import "fmt"

    type MyInt = int

    func main() {
        var i MyInt = 10
        fmt.Printf("%#v\n", i) // 输出: main.MyInt(10)
    }
    ```
    **假设输入与输出:**  别名类型的变量作为输入，输出是带有包名和类型名的格式化字符串。

10. **`TestIssue22031`**:  测试嵌套结构体中切片字段的 `CanSet()` 方法的行为。

11. **`TestIssue22073`**:  测试调用带有未导出接收者的方法。

12. **`TestMapIterNonEmptyMap`, `TestMapIterNilMap`, `TestMapIterReset`, `TestMapIterSafety`, `TestMapIterNext`, `TestMapIterDelete0`, `TestMapIterDelete1`**: 这些测试用例全面测试了 `reflect.MapIter` 类型，用于安全且高效地迭代 map。它们涵盖了非空 map、nil map 的迭代，以及在迭代过程中增删元素的情况。

    **Go 代码示例:**
    ```go
    package main

    import (
        "fmt"
        "reflect"
    )

    func main() {
        m := map[string]int{"one": 1, "two": 2}
        mapValue := reflect.ValueOf(m)
        iter := mapValue.MapRange()
        for iter.Next() {
            key := iter.Key()
            value := iter.Value()
            fmt.Printf("%v: %v\n", key, value)
        }
    }
    ```
    **假设输入与输出:**  一个 map 作为输入，输出是 map 中键值对的迭代结果，顺序不固定。

    **使用者易犯错的点:**
    *   在调用 `Next()` 之前或迭代结束后调用 `Key()` 或 `Value()` 会导致 panic。
    *   使用零值的 `MapIter` 会导致 panic。

13. **`TestConvertibleTo`**: 测试 `reflect.Type` 的 `ConvertibleTo()` 方法，用于检查一个类型的值是否可以转换为另一个类型。

14. **`TestSetIter`**: 测试 `reflect.Value` 的 `SetIterKey()` 和 `SetIterValue()` 方法，用于在迭代 map 时设置键和值。

    **使用者易犯错的点:**
    *   在调用 `Next()` 之前或迭代结束后调用 `SetIterKey()` 或 `SetIterValue()` 会导致 panic。
    *   尝试使用不可寻址的值或类型不匹配的值设置键或值会导致 panic。
    *   尝试设置从未导出字段获得的值也会导致 panic。

15. **`TestMethodCallValueCodePtr`**: 测试获取方法调用值的代码指针。

16. **`TestIssue50208`**: 测试泛型类型的名称表示。

17. **`TestNegativeKindString`**: 测试负数 `reflect.Kind` 的字符串表示。

18. **`TestValue_Cap`**: 测试 `reflect.Value` 的 `Cap()` 方法，用于获取数组、通道或切片的容量。

    **使用者易犯错的点:**  在非数组、切片或通道类型的 `reflect.Value` 上调用 `Cap()` 会导致 panic。

19. **`TestValue_Len`**: 测试 `reflect.Value` 的 `Len()` 方法，用于获取字符串、数组、通道或切片的长度。

    **使用者易犯错的点:** 在非字符串、数组、切片或通道类型的 `reflect.Value` 上调用 `Len()` 会导致 panic。

20. **`TestValue_Comparable`**: 测试 `reflect.Value` 的 `Comparable()` 方法，判断该值是否可比较。

21. **`TestValue_Equal`, `TestValue_EqualNonComparable`**: 测试 `reflect.Value` 的 `Equal()` 方法，用于比较两个 `reflect.Value` 是否相等。特别测试了不可比较类型的情况。

    **使用者易犯错的点:**  尝试使用 `Equal()` 比较两个不可比较的 `reflect.Value` 会导致 panic。

22. **`TestInitFuncTypes`**: 测试并发初始化函数类型信息。

23. **`TestClear`**: 测试 `reflect.Value` 的 `Clear()` 方法，用于清除 map 或 slice 中的元素。

    **使用者易犯错的点:**  在非 map 或 slice 类型的 `reflect.Value` 上调用 `Clear()` 会导致 panic。

24. **`TestValuePointerAndUnsafePointer`**: 测试 `reflect.Value` 的 `Pointer()` 和 `UnsafePointer()` 方法，用于获取底层数据的指针。

25. **`TestSliceAt`**: 测试 `reflect.SliceAt` 函数，用于从给定的指针和长度创建切片。

    **使用者易犯错的点:**
    *   使用 `nil` 指针和非零长度会导致 panic。
    *   使用负数长度会导致 panic。
    *   计算出的切片大小超出可寻址范围会导致 panic。

26. **`TestMapOfKeyUpdate`**: 测试使用 `reflect.MakeMap` 和 `reflect.MapOf` 创建的 map 是否正确处理键的更新，特别是对于浮点零值。

27. **`TestMapOfKeyPanic`**: 测试使用 `reflect.MakeMap` 和 `reflect.MapOf` 创建的 map 是否在尝试使用不可哈希的键时正确 panic。

**总结一下它的功能:**

这段代码是 `reflect` 包测试套件的一部分，其主要功能是 **验证 `reflect` 包提供的各种类型反射和操作功能是否按预期工作**。它涵盖了 map 的创建和操作、channel 的发送和接收、类型信息的获取（名称、导出状态、字符串表示）、切片元素交换、访问控制、别名类型、map 迭代、类型转换、方法调用、泛型类型、值的比较和属性获取等多个方面。这些测试用例旨在确保 `reflect` 包的稳定性和正确性，并且可以作为理解和使用 `reflect` 包的参考示例。

Prompt: 
```
这是路径为go/src/reflect/all_test.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第7部分，共7部分，请归纳一下它的功能

"""
.AllocsPerRun(100, func() {
		mv := MakeMapWithSize(TypeOf(map[int]int{}), size)
		// Only adding half of the capacity to not trigger re-allocations due too many overloaded buckets.
		for i := 0; i < size/2; i++ {
			val.SetInt(int64(i))
			mv.SetMapIndex(val, val)
		}
	})
	if allocs > 10 {
		t.Errorf("allocs per map assignment: want at most 10 got %f", allocs)
	}
	// Empirical testing shows that with capacity hint single run will trigger 3 allocations and without 91. I set
	// the threshold to 10, to not make it overly brittle if something changes in the initial allocation of the
	// map, but to still catch a regression where we keep re-allocating in the hashmap as new entries are added.
}

func TestChanAlloc(t *testing.T) {
	if asan.Enabled {
		t.Skip("test allocates more with -asan; see #70079")
	}
	// Note: for a chan int, the return Value must be allocated, so we
	// use a chan *int instead.
	c := ValueOf(make(chan *int, 1))
	v := ValueOf(new(int))
	allocs := testing.AllocsPerRun(100, func() {
		c.Send(v)
		_, _ = c.Recv()
	})
	if allocs < 0.5 || allocs > 1.5 {
		t.Errorf("allocs per chan send/recv: want 1 got %f", allocs)
	}
	// Note: there is one allocation in reflect.recv which seems to be
	// a limitation of escape analysis. If that is ever fixed the
	// allocs < 0.5 condition will trigger and this test should be fixed.
}

type TheNameOfThisTypeIsExactly255BytesLongSoWhenTheCompilerPrependsTheReflectTestPackageNameAndExtraStarTheLinkerRuntimeAndReflectPackagesWillHaveToCorrectlyDecodeTheSecondLengthByte0123456789_0123456789_0123456789_0123456789_0123456789_012345678 int

type nameTest struct {
	v    any
	want string
}

var nameTests = []nameTest{
	{(*int32)(nil), "int32"},
	{(*D1)(nil), "D1"},
	{(*[]D1)(nil), ""},
	{(*chan D1)(nil), ""},
	{(*func() D1)(nil), ""},
	{(*<-chan D1)(nil), ""},
	{(*chan<- D1)(nil), ""},
	{(*any)(nil), ""},
	{(*interface {
		F()
	})(nil), ""},
	{(*TheNameOfThisTypeIsExactly255BytesLongSoWhenTheCompilerPrependsTheReflectTestPackageNameAndExtraStarTheLinkerRuntimeAndReflectPackagesWillHaveToCorrectlyDecodeTheSecondLengthByte0123456789_0123456789_0123456789_0123456789_0123456789_012345678)(nil), "TheNameOfThisTypeIsExactly255BytesLongSoWhenTheCompilerPrependsTheReflectTestPackageNameAndExtraStarTheLinkerRuntimeAndReflectPackagesWillHaveToCorrectlyDecodeTheSecondLengthByte0123456789_0123456789_0123456789_0123456789_0123456789_012345678"},
}

func TestNames(t *testing.T) {
	for _, test := range nameTests {
		typ := TypeOf(test.v).Elem()
		if got := typ.Name(); got != test.want {
			t.Errorf("%v Name()=%q, want %q", typ, got, test.want)
		}
	}
}

func TestExported(t *testing.T) {
	type ΦExported struct{}
	type φUnexported struct{}
	type BigP *big
	type P int
	type p *P
	type P2 p
	type p3 p

	type exportTest struct {
		v    any
		want bool
	}
	exportTests := []exportTest{
		{D1{}, true},
		{(*D1)(nil), true},
		{big{}, false},
		{(*big)(nil), false},
		{(BigP)(nil), true},
		{(*BigP)(nil), true},
		{ΦExported{}, true},
		{φUnexported{}, false},
		{P(0), true},
		{(p)(nil), false},
		{(P2)(nil), true},
		{(p3)(nil), false},
	}

	for i, test := range exportTests {
		typ := TypeOf(test.v)
		if got := IsExported(typ); got != test.want {
			t.Errorf("%d: %s exported=%v, want %v", i, typ.Name(), got, test.want)
		}
	}
}

func TestTypeStrings(t *testing.T) {
	type stringTest struct {
		typ  Type
		want string
	}
	stringTests := []stringTest{
		{TypeOf(func(int) {}), "func(int)"},
		{FuncOf([]Type{TypeOf(int(0))}, nil, false), "func(int)"},
		{TypeOf(XM{}), "reflect_test.XM"},
		{TypeOf(new(XM)), "*reflect_test.XM"},
		{TypeOf(new(XM).String), "func() string"},
		{TypeOf(new(XM)).Method(0).Type, "func(*reflect_test.XM) string"},
		{ChanOf(3, TypeOf(XM{})), "chan reflect_test.XM"},
		{MapOf(TypeOf(int(0)), TypeOf(XM{})), "map[int]reflect_test.XM"},
		{ArrayOf(3, TypeOf(XM{})), "[3]reflect_test.XM"},
		{ArrayOf(3, TypeOf(struct{}{})), "[3]struct {}"},
	}

	for i, test := range stringTests {
		if got, want := test.typ.String(), test.want; got != want {
			t.Errorf("type %d String()=%q, want %q", i, got, want)
		}
	}
}

func TestOffsetLock(t *testing.T) {
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		i := i
		wg.Add(1)
		go func() {
			for j := 0; j < 50; j++ {
				ResolveReflectName(fmt.Sprintf("OffsetLockName:%d:%d", i, j))
			}
			wg.Done()
		}()
	}
	wg.Wait()
}

func TestSwapper(t *testing.T) {
	type I int
	var a, b, c I
	type pair struct {
		x, y int
	}
	type pairPtr struct {
		x, y int
		p    *I
	}
	type S string

	tests := []struct {
		in   any
		i, j int
		want any
	}{
		{
			in:   []int{1, 20, 300},
			i:    0,
			j:    2,
			want: []int{300, 20, 1},
		},
		{
			in:   []uintptr{1, 20, 300},
			i:    0,
			j:    2,
			want: []uintptr{300, 20, 1},
		},
		{
			in:   []int16{1, 20, 300},
			i:    0,
			j:    2,
			want: []int16{300, 20, 1},
		},
		{
			in:   []int8{1, 20, 100},
			i:    0,
			j:    2,
			want: []int8{100, 20, 1},
		},
		{
			in:   []*I{&a, &b, &c},
			i:    0,
			j:    2,
			want: []*I{&c, &b, &a},
		},
		{
			in:   []string{"eric", "sergey", "larry"},
			i:    0,
			j:    2,
			want: []string{"larry", "sergey", "eric"},
		},
		{
			in:   []S{"eric", "sergey", "larry"},
			i:    0,
			j:    2,
			want: []S{"larry", "sergey", "eric"},
		},
		{
			in:   []pair{{1, 2}, {3, 4}, {5, 6}},
			i:    0,
			j:    2,
			want: []pair{{5, 6}, {3, 4}, {1, 2}},
		},
		{
			in:   []pairPtr{{1, 2, &a}, {3, 4, &b}, {5, 6, &c}},
			i:    0,
			j:    2,
			want: []pairPtr{{5, 6, &c}, {3, 4, &b}, {1, 2, &a}},
		},
	}

	for i, tt := range tests {
		inStr := fmt.Sprint(tt.in)
		Swapper(tt.in)(tt.i, tt.j)
		if !DeepEqual(tt.in, tt.want) {
			t.Errorf("%d. swapping %v and %v of %v = %v; want %v", i, tt.i, tt.j, inStr, tt.in, tt.want)
		}
	}
}

// TestUnaddressableField tests that the reflect package will not allow
// a type from another package to be used as a named type with an
// unexported field.
//
// This ensures that unexported fields cannot be modified by other packages.
func TestUnaddressableField(t *testing.T) {
	var b Buffer // type defined in reflect, a different package
	var localBuffer struct {
		buf []byte
	}
	lv := ValueOf(&localBuffer).Elem()
	rv := ValueOf(b)
	shouldPanic("Set", func() {
		lv.Set(rv)
	})
}

type Tint int

type Tint2 = Tint

type Talias1 struct {
	byte
	uint8
	int
	int32
	rune
}

type Talias2 struct {
	Tint
	Tint2
}

func TestAliasNames(t *testing.T) {
	t1 := Talias1{byte: 1, uint8: 2, int: 3, int32: 4, rune: 5}
	out := fmt.Sprintf("%#v", t1)
	want := "reflect_test.Talias1{byte:0x1, uint8:0x2, int:3, int32:4, rune:5}"
	if out != want {
		t.Errorf("Talias1 print:\nhave: %s\nwant: %s", out, want)
	}

	t2 := Talias2{Tint: 1, Tint2: 2}
	out = fmt.Sprintf("%#v", t2)
	want = "reflect_test.Talias2{Tint:1, Tint2:2}"
	if out != want {
		t.Errorf("Talias2 print:\nhave: %s\nwant: %s", out, want)
	}
}

func TestIssue22031(t *testing.T) {
	type s []struct{ C int }

	type t1 struct{ s }
	type t2 struct{ f s }

	tests := []Value{
		ValueOf(t1{s{{}}}).Field(0).Index(0).Field(0),
		ValueOf(t2{s{{}}}).Field(0).Index(0).Field(0),
	}

	for i, test := range tests {
		if test.CanSet() {
			t.Errorf("%d: CanSet: got true, want false", i)
		}
	}
}

type NonExportedFirst int

func (i NonExportedFirst) ΦExported()       {}
func (i NonExportedFirst) nonexported() int { panic("wrong") }

func TestIssue22073(t *testing.T) {
	m := ValueOf(NonExportedFirst(0)).Method(0)

	if got := m.Type().NumOut(); got != 0 {
		t.Errorf("NumOut: got %v, want 0", got)
	}

	// Shouldn't panic.
	m.Call(nil)
}

func TestMapIterNonEmptyMap(t *testing.T) {
	m := map[string]int{"one": 1, "two": 2, "three": 3}
	iter := ValueOf(m).MapRange()
	if got, want := iterateToString(iter), `[one: 1, three: 3, two: 2]`; got != want {
		t.Errorf("iterator returned %s (after sorting), want %s", got, want)
	}
}

func TestMapIterNilMap(t *testing.T) {
	var m map[string]int
	iter := ValueOf(m).MapRange()
	if got, want := iterateToString(iter), `[]`; got != want {
		t.Errorf("non-empty result iteratoring nil map: %s", got)
	}
}

func TestMapIterReset(t *testing.T) {
	iter := new(MapIter)

	// Use of zero iterator should panic.
	func() {
		defer func() { recover() }()
		iter.Next()
		t.Error("Next did not panic")
	}()

	// Reset to new Map should work.
	m := map[string]int{"one": 1, "two": 2, "three": 3}
	iter.Reset(ValueOf(m))
	if got, want := iterateToString(iter), `[one: 1, three: 3, two: 2]`; got != want {
		t.Errorf("iterator returned %s (after sorting), want %s", got, want)
	}

	// Reset to Zero value should work, but iterating over it should panic.
	iter.Reset(Value{})
	func() {
		defer func() { recover() }()
		iter.Next()
		t.Error("Next did not panic")
	}()

	// Reset to a different Map with different types should work.
	m2 := map[int]string{1: "one", 2: "two", 3: "three"}
	iter.Reset(ValueOf(m2))
	if got, want := iterateToString(iter), `[1: one, 2: two, 3: three]`; got != want {
		t.Errorf("iterator returned %s (after sorting), want %s", got, want)
	}

	// Check that Reset, Next, and SetKey/SetValue play nicely together.
	m3 := map[uint64]uint64{
		1 << 0: 1 << 1,
		1 << 1: 1 << 2,
		1 << 2: 1 << 3,
	}
	kv := New(TypeOf(uint64(0))).Elem()
	for i := 0; i < 5; i++ {
		var seenk, seenv uint64
		iter.Reset(ValueOf(m3))
		for iter.Next() {
			kv.SetIterKey(iter)
			seenk ^= kv.Uint()
			kv.SetIterValue(iter)
			seenv ^= kv.Uint()
		}
		if seenk != 0b111 {
			t.Errorf("iteration yielded keys %b, want %b", seenk, 0b111)
		}
		if seenv != 0b1110 {
			t.Errorf("iteration yielded values %b, want %b", seenv, 0b1110)
		}
	}

	// Reset should not allocate.
	//
	// Except with -asan, where there are additional allocations.
	// See #70079.
	n := int(testing.AllocsPerRun(10, func() {
		iter.Reset(ValueOf(m2))
		iter.Reset(Value{})
	}))
	if !asan.Enabled && n > 0 {
		t.Errorf("MapIter.Reset allocated %d times", n)
	}
}

func TestMapIterSafety(t *testing.T) {
	// Using a zero MapIter causes a panic, but not a crash.
	func() {
		defer func() { recover() }()
		new(MapIter).Key()
		t.Fatal("Key did not panic")
	}()
	func() {
		defer func() { recover() }()
		new(MapIter).Value()
		t.Fatal("Value did not panic")
	}()
	func() {
		defer func() { recover() }()
		new(MapIter).Next()
		t.Fatal("Next did not panic")
	}()

	// Calling Key/Value on a MapIter before Next
	// causes a panic, but not a crash.
	var m map[string]int
	iter := ValueOf(m).MapRange()

	func() {
		defer func() { recover() }()
		iter.Key()
		t.Fatal("Key did not panic")
	}()
	func() {
		defer func() { recover() }()
		iter.Value()
		t.Fatal("Value did not panic")
	}()

	// Calling Next, Key, or Value on an exhausted iterator
	// causes a panic, but not a crash.
	iter.Next() // -> false
	func() {
		defer func() { recover() }()
		iter.Key()
		t.Fatal("Key did not panic")
	}()
	func() {
		defer func() { recover() }()
		iter.Value()
		t.Fatal("Value did not panic")
	}()
	func() {
		defer func() { recover() }()
		iter.Next()
		t.Fatal("Next did not panic")
	}()
}

func TestMapIterNext(t *testing.T) {
	// The first call to Next should reflect any
	// insertions to the map since the iterator was created.
	m := map[string]int{}
	iter := ValueOf(m).MapRange()
	m["one"] = 1
	if got, want := iterateToString(iter), `[one: 1]`; got != want {
		t.Errorf("iterator returned deleted elements: got %s, want %s", got, want)
	}
}

func TestMapIterDelete0(t *testing.T) {
	// Delete all elements before first iteration.
	m := map[string]int{"one": 1, "two": 2, "three": 3}
	iter := ValueOf(m).MapRange()
	delete(m, "one")
	delete(m, "two")
	delete(m, "three")
	if got, want := iterateToString(iter), `[]`; got != want {
		t.Errorf("iterator returned deleted elements: got %s, want %s", got, want)
	}
}

func TestMapIterDelete1(t *testing.T) {
	// Delete all elements after first iteration.
	m := map[string]int{"one": 1, "two": 2, "three": 3}
	iter := ValueOf(m).MapRange()
	var got []string
	for iter.Next() {
		got = append(got, fmt.Sprint(iter.Key(), iter.Value()))
		delete(m, "one")
		delete(m, "two")
		delete(m, "three")
	}
	if len(got) != 1 {
		t.Errorf("iterator returned wrong number of elements: got %d, want 1", len(got))
	}
}

// iterateToString returns the set of elements
// returned by an iterator in readable form.
func iterateToString(it *MapIter) string {
	var got []string
	for it.Next() {
		line := fmt.Sprintf("%v: %v", it.Key(), it.Value())
		got = append(got, line)
	}
	slices.Sort(got)
	return "[" + strings.Join(got, ", ") + "]"
}

func TestConvertibleTo(t *testing.T) {
	t1 := ValueOf(example1.MyStruct{}).Type()
	t2 := ValueOf(example2.MyStruct{}).Type()

	// Shouldn't raise stack overflow
	if t1.ConvertibleTo(t2) {
		t.Fatalf("(%s).ConvertibleTo(%s) = true, want false", t1, t2)
	}

	t3 := ValueOf([]example1.MyStruct{}).Type()
	t4 := ValueOf([]example2.MyStruct{}).Type()

	if t3.ConvertibleTo(t4) {
		t.Fatalf("(%s).ConvertibleTo(%s) = true, want false", t3, t4)
	}
}

func TestSetIter(t *testing.T) {
	data := map[string]int{
		"foo": 1,
		"bar": 2,
		"baz": 3,
	}

	m := ValueOf(data)
	i := m.MapRange()
	k := New(TypeOf("")).Elem()
	v := New(TypeOf(0)).Elem()
	shouldPanic("Value.SetIterKey called before Next", func() {
		k.SetIterKey(i)
	})
	shouldPanic("Value.SetIterValue called before Next", func() {
		v.SetIterValue(i)
	})
	data2 := map[string]int{}
	for i.Next() {
		k.SetIterKey(i)
		v.SetIterValue(i)
		data2[k.Interface().(string)] = v.Interface().(int)
	}
	if !DeepEqual(data, data2) {
		t.Errorf("maps not equal, got %v want %v", data2, data)
	}
	shouldPanic("Value.SetIterKey called on exhausted iterator", func() {
		k.SetIterKey(i)
	})
	shouldPanic("Value.SetIterValue called on exhausted iterator", func() {
		v.SetIterValue(i)
	})

	i.Reset(m)
	i.Next()
	shouldPanic("Value.SetIterKey using unaddressable value", func() {
		ValueOf("").SetIterKey(i)
	})
	shouldPanic("Value.SetIterValue using unaddressable value", func() {
		ValueOf(0).SetIterValue(i)
	})
	shouldPanic("value of type string is not assignable to type int", func() {
		New(TypeOf(0)).Elem().SetIterKey(i)
	})
	shouldPanic("value of type int is not assignable to type string", func() {
		New(TypeOf("")).Elem().SetIterValue(i)
	})

	// Make sure assignment conversion works.
	var x any
	y := ValueOf(&x).Elem()
	y.SetIterKey(i)
	if _, ok := data[x.(string)]; !ok {
		t.Errorf("got key %s which is not in map", x)
	}
	y.SetIterValue(i)
	if x.(int) < 1 || x.(int) > 3 {
		t.Errorf("got value %d which is not in map", x)
	}

	// Try some key/value types which are direct interfaces.
	a := 88
	b := 99
	pp := map[*int]*int{
		&a: &b,
	}
	i = ValueOf(pp).MapRange()
	i.Next()
	y.SetIterKey(i)
	if got := *y.Interface().(*int); got != a {
		t.Errorf("pointer incorrect: got %d want %d", got, a)
	}
	y.SetIterValue(i)
	if got := *y.Interface().(*int); got != b {
		t.Errorf("pointer incorrect: got %d want %d", got, b)
	}

	// Make sure we panic assigning from an unexported field.
	m = ValueOf(struct{ m map[string]int }{data}).Field(0)
	for iter := m.MapRange(); iter.Next(); {
		shouldPanic("using value obtained using unexported field", func() {
			k.SetIterKey(iter)
		})
		shouldPanic("using value obtained using unexported field", func() {
			v.SetIterValue(iter)
		})
	}
}

func TestMethodCallValueCodePtr(t *testing.T) {
	m := ValueOf(Point{}).Method(1)
	want := MethodValueCallCodePtr()
	if got := uintptr(m.UnsafePointer()); got != want {
		t.Errorf("methodValueCall code pointer mismatched, want: %v, got: %v", want, got)
	}
	if got := m.Pointer(); got != want {
		t.Errorf("methodValueCall code pointer mismatched, want: %v, got: %v", want, got)
	}
}

type A struct{}
type B[T any] struct{}

func TestIssue50208(t *testing.T) {
	want1 := "B[reflect_test.A]"
	if got := TypeOf(new(B[A])).Elem().Name(); got != want1 {
		t.Errorf("name of type parameter mismatched, want:%s, got:%s", want1, got)
	}
	want2 := "B[reflect_test.B[reflect_test.A]]"
	if got := TypeOf(new(B[B[A]])).Elem().Name(); got != want2 {
		t.Errorf("name of type parameter mismatched, want:%s, got:%s", want2, got)
	}
}

func TestNegativeKindString(t *testing.T) {
	x := -1
	s := Kind(x).String()
	want := "kind-1"
	if s != want {
		t.Fatalf("Kind(-1).String() = %q, want %q", s, want)
	}
}

type (
	namedBool  bool
	namedBytes []byte
)

func TestValue_Cap(t *testing.T) {
	a := &[3]int{1, 2, 3}
	v := ValueOf(a)
	if v.Cap() != cap(a) {
		t.Errorf("Cap = %d want %d", v.Cap(), cap(a))
	}

	a = nil
	v = ValueOf(a)
	if v.Cap() != cap(a) {
		t.Errorf("Cap = %d want %d", v.Cap(), cap(a))
	}

	getError := func(f func()) (errorStr string) {
		defer func() {
			e := recover()
			if str, ok := e.(string); ok {
				errorStr = str
			}
		}()
		f()
		return
	}
	e := getError(func() {
		var ptr *int
		ValueOf(ptr).Cap()
	})
	wantStr := "reflect: call of reflect.Value.Cap on ptr to non-array Value"
	if e != wantStr {
		t.Errorf("error is %q, want %q", e, wantStr)
	}
}

func TestValue_Len(t *testing.T) {
	a := &[3]int{1, 2, 3}
	v := ValueOf(a)
	if v.Len() != len(a) {
		t.Errorf("Len = %d want %d", v.Len(), len(a))
	}

	a = nil
	v = ValueOf(a)
	if v.Len() != len(a) {
		t.Errorf("Len = %d want %d", v.Len(), len(a))
	}

	getError := func(f func()) (errorStr string) {
		defer func() {
			e := recover()
			if str, ok := e.(string); ok {
				errorStr = str
			}
		}()
		f()
		return
	}
	e := getError(func() {
		var ptr *int
		ValueOf(ptr).Len()
	})
	wantStr := "reflect: call of reflect.Value.Len on ptr to non-array Value"
	if e != wantStr {
		t.Errorf("error is %q, want %q", e, wantStr)
	}
}

func TestValue_Comparable(t *testing.T) {
	var a int
	var s []int
	var i interface{} = a
	var iNil interface{}
	var iSlice interface{} = s
	var iArrayFalse interface{} = [2]interface{}{1, map[int]int{}}
	var iArrayTrue interface{} = [2]interface{}{1, struct{ I interface{} }{1}}
	var testcases = []struct {
		value      Value
		comparable bool
		deref      bool
	}{
		{
			ValueOf(&iNil),
			true,
			true,
		},
		{
			ValueOf(32),
			true,
			false,
		},
		{
			ValueOf(int8(1)),
			true,
			false,
		},
		{
			ValueOf(int16(1)),
			true,
			false,
		},
		{
			ValueOf(int32(1)),
			true,
			false,
		},
		{
			ValueOf(int64(1)),
			true,
			false,
		},
		{
			ValueOf(uint8(1)),
			true,
			false,
		},
		{
			ValueOf(uint16(1)),
			true,
			false,
		},
		{
			ValueOf(uint32(1)),
			true,
			false,
		},
		{
			ValueOf(uint64(1)),
			true,
			false,
		},
		{
			ValueOf(float32(1)),
			true,
			false,
		},
		{
			ValueOf(float64(1)),
			true,
			false,
		},
		{
			ValueOf(complex(float32(1), float32(1))),
			true,
			false,
		},
		{
			ValueOf(complex(float64(1), float64(1))),
			true,
			false,
		},
		{
			ValueOf("abc"),
			true,
			false,
		},
		{
			ValueOf(true),
			true,
			false,
		},
		{
			ValueOf(map[int]int{}),
			false,
			false,
		},
		{
			ValueOf([]int{}),
			false,
			false,
		},
		{
			Value{},
			false,
			false,
		},
		{
			ValueOf(&a),
			true,
			false,
		},
		{
			ValueOf(&s),
			true,
			false,
		},
		{
			ValueOf(&i),
			true,
			true,
		},
		{
			ValueOf(&iSlice),
			false,
			true,
		},
		{
			ValueOf([2]int{}),
			true,
			false,
		},
		{
			ValueOf([2]map[int]int{}),
			false,
			false,
		},
		{
			ValueOf([0]func(){}),
			false,
			false,
		},
		{
			ValueOf([2]struct{ I interface{} }{{1}, {1}}),
			true,
			false,
		},
		{
			ValueOf([2]struct{ I interface{} }{{[]int{}}, {1}}),
			false,
			false,
		},
		{
			ValueOf([2]interface{}{1, struct{ I int }{1}}),
			true,
			false,
		},
		{
			ValueOf([2]interface{}{[1]interface{}{map[int]int{}}, struct{ I int }{1}}),
			false,
			false,
		},
		{
			ValueOf(&iArrayFalse),
			false,
			true,
		},
		{
			ValueOf(&iArrayTrue),
			true,
			true,
		},
	}

	for _, cas := range testcases {
		v := cas.value
		if cas.deref {
			v = v.Elem()
		}
		got := v.Comparable()
		if got != cas.comparable {
			t.Errorf("%T.Comparable = %t, want %t", v, got, cas.comparable)
		}
	}
}

type ValueEqualTest struct {
	v, u           any
	eq             bool
	vDeref, uDeref bool
}

var equalI interface{} = 1
var equalSlice interface{} = []int{1}
var nilInterface interface{}
var mapInterface interface{} = map[int]int{}

var valueEqualTests = []ValueEqualTest{
	{
		Value{}, Value{},
		true,
		false, false,
	},
	{
		true, true,
		true,
		false, false,
	},
	{
		1, 1,
		true,
		false, false,
	},
	{
		int8(1), int8(1),
		true,
		false, false,
	},
	{
		int16(1), int16(1),
		true,
		false, false,
	},
	{
		int32(1), int32(1),
		true,
		false, false,
	},
	{
		int64(1), int64(1),
		true,
		false, false,
	},
	{
		uint(1), uint(1),
		true,
		false, false,
	},
	{
		uint8(1), uint8(1),
		true,
		false, false,
	},
	{
		uint16(1), uint16(1),
		true,
		false, false,
	},
	{
		uint32(1), uint32(1),
		true,
		false, false,
	},
	{
		uint64(1), uint64(1),
		true,
		false, false,
	},
	{
		float32(1), float32(1),
		true,
		false, false,
	},
	{
		float64(1), float64(1),
		true,
		false, false,
	},
	{
		complex(1, 1), complex(1, 1),
		true,
		false, false,
	},
	{
		complex128(1 + 1i), complex128(1 + 1i),
		true,
		false, false,
	},
	{
		func() {}, nil,
		false,
		false, false,
	},
	{
		&equalI, 1,
		true,
		true, false,
	},
	{
		(chan int)(nil), nil,
		false,
		false, false,
	},
	{
		(chan int)(nil), (chan int)(nil),
		true,
		false, false,
	},
	{
		&equalI, &equalI,
		true,
		false, false,
	},
	{
		struct{ i int }{1}, struct{ i int }{1},
		true,
		false, false,
	},
	{
		struct{ i int }{1}, struct{ i int }{2},
		false,
		false, false,
	},
	{
		&nilInterface, &nilInterface,
		true,
		true, true,
	},
	{
		1, ValueOf(struct{ i int }{1}).Field(0),
		true,
		false, false,
	},
}

func TestValue_Equal(t *testing.T) {
	for _, test := range valueEqualTests {
		var v, u Value
		if vv, ok := test.v.(Value); ok {
			v = vv
		} else {
			v = ValueOf(test.v)
		}

		if uu, ok := test.u.(Value); ok {
			u = uu
		} else {
			u = ValueOf(test.u)
		}
		if test.vDeref {
			v = v.Elem()
		}

		if test.uDeref {
			u = u.Elem()
		}

		if r := v.Equal(u); r != test.eq {
			t.Errorf("%s == %s got %t, want %t", v.Type(), u.Type(), r, test.eq)
		}
	}
}

func TestValue_EqualNonComparable(t *testing.T) {
	var invalid = Value{} // ValueOf(nil)
	var values = []Value{
		// Value of slice is non-comparable.
		ValueOf([]int(nil)),
		ValueOf(([]int{})),

		// Value of map is non-comparable.
		ValueOf(map[int]int(nil)),
		ValueOf((map[int]int{})),

		// Value of func is non-comparable.
		ValueOf(((func())(nil))),
		ValueOf(func() {}),

		// Value of struct is non-comparable because of non-comparable elements.
		ValueOf((NonComparableStruct{})),

		// Value of array is non-comparable because of non-comparable elements.
		ValueOf([0]map[int]int{}),
		ValueOf([0]func(){}),
		ValueOf(([1]struct{ I interface{} }{{[]int{}}})),
		ValueOf(([1]interface{}{[1]interface{}{map[int]int{}}})),
	}
	for _, value := range values {
		// Panic when reflect.Value.Equal using two valid non-comparable values.
		shouldPanic("are not comparable", func() { value.Equal(value) })

		// If one is non-comparable and the other is invalid, the expected result is always false.
		if r := value.Equal(invalid); r != false {
			t.Errorf("%s == invalid got %t, want false", value.Type(), r)
		}
	}
}

func TestInitFuncTypes(t *testing.T) {
	n := 100
	var wg sync.WaitGroup

	wg.Add(n)
	for i := 0; i < n; i++ {
		go func() {
			defer wg.Done()
			ipT := TypeOf(net.IP{})
			for i := 0; i < ipT.NumMethod(); i++ {
				_ = ipT.Method(i)
			}
		}()
	}
	wg.Wait()
}

func TestClear(t *testing.T) {
	m := make(map[string]any, len(valueTests))
	for _, tt := range valueTests {
		m[tt.s] = tt.i
	}
	mapTestFn := func(v Value) bool { v.Clear(); return v.Len() == 0 }

	s := make([]*pair, len(valueTests))
	for i := range s {
		s[i] = &valueTests[i]
	}
	sliceTestFn := func(v Value) bool {
		v.Clear()
		for i := 0; i < v.Len(); i++ {
			if !v.Index(i).IsZero() {
				return false
			}
		}
		return true
	}

	panicTestFn := func(v Value) bool { shouldPanic("reflect.Value.Clear", func() { v.Clear() }); return true }

	tests := []struct {
		name     string
		value    Value
		testFunc func(v Value) bool
	}{
		{"map", ValueOf(m), mapTestFn},
		{"slice no pointer", ValueOf([]int{1, 2, 3, 4, 5}), sliceTestFn},
		{"slice has pointer", ValueOf(s), sliceTestFn},
		{"non-map/slice", ValueOf(1), panicTestFn},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if !tc.testFunc(tc.value) {
				t.Errorf("unexpected result for value.Clear(): %v", tc.value)
			}
		})
	}
}

func TestValuePointerAndUnsafePointer(t *testing.T) {
	ptr := new(int)
	ch := make(chan int)
	m := make(map[int]int)
	unsafePtr := unsafe.Pointer(ptr)
	slice := make([]int, 1)
	fn := func() {}
	s := "foo"

	tests := []struct {
		name              string
		val               Value
		wantUnsafePointer unsafe.Pointer
	}{
		{"pointer", ValueOf(ptr), unsafe.Pointer(ptr)},
		{"channel", ValueOf(ch), *(*unsafe.Pointer)(unsafe.Pointer(&ch))},
		{"map", ValueOf(m), *(*unsafe.Pointer)(unsafe.Pointer(&m))},
		{"unsafe.Pointer", ValueOf(unsafePtr), unsafePtr},
		{"function", ValueOf(fn), **(**unsafe.Pointer)(unsafe.Pointer(&fn))},
		{"slice", ValueOf(slice), unsafe.Pointer(unsafe.SliceData(slice))},
		{"string", ValueOf(s), unsafe.Pointer(unsafe.StringData(s))},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.val.Pointer(); got != uintptr(tc.wantUnsafePointer) {
				t.Errorf("unexpected uintptr result, got %#x, want %#x", got, uintptr(tc.wantUnsafePointer))
			}
			if got := tc.val.UnsafePointer(); got != tc.wantUnsafePointer {
				t.Errorf("unexpected unsafe.Pointer result, got %#x, want %#x", got, tc.wantUnsafePointer)
			}
		})
	}
}

// Test cases copied from ../../test/unsafebuiltins.go
func TestSliceAt(t *testing.T) {
	const maxUintptr = 1 << (8 * unsafe.Sizeof(uintptr(0)))
	var p [10]byte

	typ := TypeOf(p[0])

	s := SliceAt(typ, unsafe.Pointer(&p[0]), len(p))
	if s.Pointer() != uintptr(unsafe.Pointer(&p[0])) {
		t.Fatalf("unexpected underlying array: %d, want: %d", s.Pointer(), uintptr(unsafe.Pointer(&p[0])))
	}
	if s.Len() != len(p) || s.Cap() != len(p) {
		t.Fatalf("unexpected len or cap, len: %d, cap: %d, want: %d", s.Len(), s.Cap(), len(p))
	}

	typ = TypeOf(0)
	if !SliceAt(typ, unsafe.Pointer((*int)(nil)), 0).IsNil() {
		t.Fatal("nil pointer with zero length must return nil")
	}

	// nil pointer with positive length panics
	shouldPanic("", func() { _ = SliceAt(typ, unsafe.Pointer((*int)(nil)), 1) })

	// negative length
	var neg int = -1
	shouldPanic("", func() { _ = SliceAt(TypeOf(byte(0)), unsafe.Pointer(&p[0]), neg) })

	// size overflows address space
	n := uint64(0)
	shouldPanic("", func() { _ = SliceAt(TypeOf(n), unsafe.Pointer(&n), maxUintptr/8) })
	shouldPanic("", func() { _ = SliceAt(TypeOf(n), unsafe.Pointer(&n), maxUintptr/8+1) })

	// sliced memory overflows address space
	last := (*byte)(unsafe.Pointer(^uintptr(0)))
	// This panics here, but won't panic in ../../test/unsafebuiltins.go,
	// because unsafe.Slice(last, 1) does not escape.
	//
	// _ = SliceAt(typ, unsafe.Pointer(last), 1)
	shouldPanic("", func() { _ = SliceAt(typ, unsafe.Pointer(last), 2) })
}

// Test that maps created with MapOf properly updates keys on overwrite as
// expected (i.e., it sets the key update flag in the map).
//
// This test is based on runtime.TestNegativeZero.
func TestMapOfKeyUpdate(t *testing.T) {
	m := MakeMap(MapOf(TypeFor[float64](), TypeFor[bool]()))

	zero := float64(0.0)
	negZero := math.Copysign(zero, -1.0)

	m.SetMapIndex(ValueOf(zero), ValueOf(true))
	m.SetMapIndex(ValueOf(negZero), ValueOf(true))

	if m.Len() != 1 {
		t.Errorf("map length got %d want 1", m.Len())
	}

	iter := m.MapRange()
	for iter.Next() {
		k := iter.Key().Float()
		if math.Copysign(1.0, k) > 0 {
			t.Errorf("map key %f has positive sign", k)
		}
	}
}

// Test that maps created with MapOf properly panic on unhashable keys, even if
// the map is empty. (i.e., it sets the hash might panic flag in the map).
//
// This test is a simplified version of runtime.TestEmptyMapWithInterfaceKey
// for reflect.
func TestMapOfKeyPanic(t *testing.T) {
	defer func() {
		r := recover()
		if r == nil {
			t.Errorf("didn't panic")
		}
	}()

	m := MakeMap(MapOf(TypeFor[any](), TypeFor[bool]()))

	var slice []int
	m.MapIndex(ValueOf(slice))
}

"""




```