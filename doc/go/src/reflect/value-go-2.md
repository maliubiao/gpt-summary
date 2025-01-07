Response:
The user wants a summary of the functionality of the provided Go code snippet. This snippet is part of the `reflect` package in Go, specifically the `value.go` file.

The code mainly deals with the `Value` type and its methods for manipulating and inspecting Go values at runtime.

I need to analyze the methods defined in the snippet and group them by their purpose.

Here's a breakdown of the methods and their functionalities:

*   **Setters:** Methods starting with `Set` are responsible for changing the underlying value of a `Value`.
    *   `SetBool`: Sets a boolean value.
    *   `SetBytes`: Sets a byte slice.
    *   `setRunes`: Sets a rune slice.
    *   `SetComplex`: Sets a complex number.
    *   `SetFloat`: Sets a floating-point number.
    *   `SetInt`: Sets an integer.
    *   `SetLen`: Sets the length of a slice.
    *   `SetCap`: Sets the capacity of a slice.
    *   `SetUint`: Sets an unsigned integer.
    *   `SetPointer`: Sets an `unsafe.Pointer`.
    *   `SetString`: Sets a string.

*   **Slicing:** Methods related to creating slices from existing values.
    *   `Slice`: Creates a new slice from an array, slice, or string.
    *   `Slice3`: Creates a new 3-index slice from an array or slice.

*   **String Representation:**  Methods for getting string representations of `Value`.
    *   `String`: Returns the string representation of the underlying value.
    *   `stringNonString`: Helper for `String` when the kind is not a string.

*   **Channel Operations:** Methods for interacting with channels.
    *   `TryRecv`: Attempts to receive a value from a channel without blocking.
    *   `TrySend`: Attempts to send a value on a channel without blocking.

*   **Type Information:** Methods for retrieving the type of a `Value`.
    *   `Type`: Returns the `Type` of the `Value`.
    *   `typeSlow`: Helper for `Type` for method values.
    *   `CanUint`: Checks if the `Value` can be represented as a `uint64`.
    *   `Uint`: Returns the underlying value as a `uint64`.

*   **Unsafe Operations:** Methods that provide access to the underlying memory, requiring careful usage.
    *   `UnsafeAddr`: Returns the address of the underlying data.
    *   `UnsafePointer`: Returns the underlying data as an `unsafe.Pointer`.

*   **Slice Manipulation:** Methods for modifying slices.
    *   `Grow`: Increases the capacity of a slice.
    *   `grow`: Internal version of `Grow` without assignability checks.
    *   `extendSlice`: Creates a new slice with increased length.
    *   `Clear`: Clears the contents of a map or slice.
    *   `Append`: Appends values to a slice.
    *   `AppendSlice`: Appends one slice to another.
    *   `Copy`: Copies elements between slices or arrays.

*   **Select Operation:** Methods for implementing the `select` statement.
    *   `Select`: Executes a `select` operation.
    *   `runtimeSelect`, `SelectDir`, `SelectCase`: Supporting types for `Select`.

*   **Constructors:** Functions for creating new `Value` instances.
    *   `MakeSlice`: Creates a new slice.
    *   `SliceAt`: Creates a slice at a specific memory location.
    *   `MakeChan`: Creates a new channel.
    *   `MakeMap`: Creates a new map.
    *   `MakeMapWithSize`: Creates a new map with an initial size hint.
    *   `Indirect`: Returns the value pointed to by a pointer `Value`.
    *   `ValueOf`: Creates a `Value` from an `interface{}`.
    *   `Zero`: Creates a `Value` representing the zero value of a type.
    *   `New`: Creates a `Value` representing a pointer to a new zero value.
    *   `NewAt`: Creates a `Value` representing a pointer to a value at a specific memory location.

*   **Type Conversion and Assignment:** Methods related to type compatibility.
    *   `assignTo`: Returns a `Value` that can be assigned to a destination type.
    *   `Convert`: Converts a `Value` to a different type.
    *   `CanConvert`: Checks if a `Value` can be converted to a different type.

*   **Comparison:** Methods for comparing `Value` instances.
    *   `Comparable`: Checks if a `Value` is comparable.
    *   `Equal`: Checks if two `Value` instances are equal.

Based on this analysis, the core function of this code snippet is to provide mechanisms for inspecting and manipulating Go values at runtime using reflection. This includes setting values, creating slices, performing channel operations, getting type information, and performing type conversions and comparisons.
这个go语言代码片段是 `go/src/reflect/value.go` 文件的一部分，它主要提供了 `reflect.Value` 类型的一系列方法，用于**设置（修改）**各种类型的 Go 语言变量的值。

这是第3部分，所以我们可以归纳一下这部分代码提供的设置 `reflect.Value` 的功能：

**核心功能：**

这部分代码主要提供了 `reflect.Value` 类型的一系列 `Set...` 方法，允许用户通过反射来修改 `reflect.Value` 对象所代表的底层 Go 语言变量的值。这些方法涵盖了 Go 语言的各种基本数据类型以及切片。

**具体功能点：**

1. **设置基本类型的值:**
    *   `SetBool(x bool)`:  设置 `bool` 类型的值。
    *   `SetComplex(x complex128)`: 设置 `complex64` 或 `complex128` 类型的值。
    *   `SetFloat(x float64)`: 设置 `float32` 或 `float64` 类型的值。
    *   `SetInt(x int64)`: 设置各种 `int` 类型（`int`, `int8`, `int16`, `int32`, `int64`）的值。
    *   `SetUint(x uint64)`: 设置各种 `uint` 类型（`uint`, `uint8`, `uint16`, `uint32`, `uint64`, `uintptr`）的值。
    *   `SetPointer(x unsafe.Pointer)`: 设置 `unsafe.Pointer` 类型的值。
    *   `SetString(x string)`: 设置 `string` 类型的值。

2. **设置切片类型的值:**
    *   `SetBytes(x []byte)`: 设置 `[]byte` 类型的值。
    *   `setRunes(x []rune)`: 设置 `[]rune` 类型的值。
    *   `SetLen(n int)`: 设置切片的长度。
    *   `SetCap(n int)`: 设置切片的容量。

3. **切片操作:**
    *   `Slice(i, j int)`:  创建一个新的 `reflect.Value`，表示原切片、数组或字符串的子切片 `v[i:j]`。
    *   `Slice3(i, j, k int)`: 创建一个新的 `reflect.Value`，表示原切片的子切片 `v[i:j:k]`。

4. **尝试非阻塞的通道操作:**
    *   `TryRecv() (x Value, ok bool)`: 尝试从通道接收值，不会阻塞。
    *   `TrySend(x Value) bool`: 尝试向通道发送值，不会阻塞。

5. **获取类型信息:**
    *   `Type() Type`: 获取 `reflect.Value` 代表的值的类型。
    *   `CanUint() bool`: 判断 `reflect.Value` 的值是否可以安全地转换为 `uint64`。
    *   `Uint() uint64`: 获取 `reflect.Value` 代表的 `uint` 类型的值。

6. **获取底层内存地址:**
    *   `UnsafeAddr() uintptr`: 获取 `reflect.Value` 底层数据的地址（`uintptr`）。
    *   `UnsafePointer() unsafe.Pointer`: 获取 `reflect.Value` 底层数据的 `unsafe.Pointer`。

7. **切片的扩容和扩展:**
    *   `Grow(n int)`: 增加切片的容量。
    *   `extendSlice(n int) Value`: 创建一个长度增加的新切片。

8. **清除切片或映射:**
    *   `Clear()`: 清空切片的内容（置零）或清空映射。

9. **切片的追加和复制:**
    *   `Append(s Value, x ...Value) Value`: 向切片追加元素。
    *   `AppendSlice(s, t Value) Value`: 将一个切片追加到另一个切片。
    *   `Copy(dst, src Value) int`: 将一个切片或数组的内容复制到另一个切片或数组。

10. **`select` 语句的反射实现:**
    *   `Select(cases []SelectCase) (chosen int, recv Value, recvOK bool)`:  实现了 `select` 语句的反射版本。
    *   `SelectCase`:  描述 `select` 语句中的一个 case。
    *   `SelectDir`:  描述 `select` case 的方向（发送、接收、默认）。

11. **构造 `reflect.Value`:**
    *   `MakeSlice(typ Type, len, cap int) Value`: 创建一个新的切片 `reflect.Value`。
    *   `SliceAt(typ Type, p unsafe.Pointer, n int) Value`: 在指定的内存地址创建一个切片 `reflect.Value`。
    *   `MakeChan(typ Type, buffer int) Value`: 创建一个新的通道 `reflect.Value`。
    *   `MakeMap(typ Type) Value`: 创建一个新的映射 `reflect.Value`。
    *   `MakeMapWithSize(typ Type, n int) Value`: 创建一个新的映射 `reflect.Value`，并指定初始容量。
    *   `Indirect(v Value) Value`: 如果 `v` 是指针，返回指针指向的值的 `reflect.Value`。
    *   `ValueOf(i any) Value`: 从一个 `interface{}` 创建 `reflect.Value`。
    *   `Zero(typ Type) Value`: 创建一个表示指定类型零值的 `reflect.Value`。
    *   `New(typ Type) Value`: 创建一个指向指定类型零值的新指针的 `reflect.Value`。
    *   `NewAt(typ Type, p unsafe.Pointer) Value`: 在指定的内存地址创建一个指向指定类型值的指针的 `reflect.Value`。

12. **类型转换和赋值:**
    *   `assignTo(context string, dst *abi.Type, target unsafe.Pointer) Value`: 尝试将当前 `reflect.Value` 的值赋值给指定类型的变量。
    *   `Convert(t Type) Value`: 将 `reflect.Value` 的值转换为指定的类型。
    *   `CanConvert(t Type) bool`: 判断 `reflect.Value` 的值是否可以转换为指定的类型。

13. **比较:**
    *   `Comparable() bool`: 判断 `reflect.Value` 的值是否可比较。
    *   `Equal(u Value) bool`: 判断两个 `reflect.Value` 的值是否相等。

**总结来说，这部分代码是 Go 语言反射机制中用于修改和操作变量值的核心组成部分。** 它提供了丰富的方法来动态地设置各种类型变量的值，进行切片操作，执行通道通信，并进行类型转换和比较。

由于这是第 3 部分，我们可以推测，前面的部分可能涉及 `reflect.Value` 的创建、获取值等只读操作，而后面的部分可能会涉及更高级的反射用法，例如调用方法、访问结构体字段等。

Prompt: 
```
这是路径为go/src/reflect/value.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第3部分，共4部分，请归纳一下它的功能

"""
 is not [Bool] or if [Value.CanSet] returns false.
func (v Value) SetBool(x bool) {
	v.mustBeAssignable()
	v.mustBe(Bool)
	*(*bool)(v.ptr) = x
}

// SetBytes sets v's underlying value.
// It panics if v's underlying value is not a slice of bytes
// or if [Value.CanSet] returns false.
func (v Value) SetBytes(x []byte) {
	v.mustBeAssignable()
	v.mustBe(Slice)
	if toRType(v.typ()).Elem().Kind() != Uint8 { // TODO add Elem method, fix mustBe(Slice) to return slice.
		panic("reflect.Value.SetBytes of non-byte slice")
	}
	*(*[]byte)(v.ptr) = x
}

// setRunes sets v's underlying value.
// It panics if v's underlying value is not a slice of runes (int32s)
// or if [Value.CanSet] returns false.
func (v Value) setRunes(x []rune) {
	v.mustBeAssignable()
	v.mustBe(Slice)
	if v.typ().Elem().Kind() != abi.Int32 {
		panic("reflect.Value.setRunes of non-rune slice")
	}
	*(*[]rune)(v.ptr) = x
}

// SetComplex sets v's underlying value to x.
// It panics if v's Kind is not [Complex64] or [Complex128],
// or if [Value.CanSet] returns false.
func (v Value) SetComplex(x complex128) {
	v.mustBeAssignable()
	switch k := v.kind(); k {
	default:
		panic(&ValueError{"reflect.Value.SetComplex", v.kind()})
	case Complex64:
		*(*complex64)(v.ptr) = complex64(x)
	case Complex128:
		*(*complex128)(v.ptr) = x
	}
}

// SetFloat sets v's underlying value to x.
// It panics if v's Kind is not [Float32] or [Float64],
// or if [Value.CanSet] returns false.
func (v Value) SetFloat(x float64) {
	v.mustBeAssignable()
	switch k := v.kind(); k {
	default:
		panic(&ValueError{"reflect.Value.SetFloat", v.kind()})
	case Float32:
		*(*float32)(v.ptr) = float32(x)
	case Float64:
		*(*float64)(v.ptr) = x
	}
}

// SetInt sets v's underlying value to x.
// It panics if v's Kind is not [Int], [Int8], [Int16], [Int32], or [Int64],
// or if [Value.CanSet] returns false.
func (v Value) SetInt(x int64) {
	v.mustBeAssignable()
	switch k := v.kind(); k {
	default:
		panic(&ValueError{"reflect.Value.SetInt", v.kind()})
	case Int:
		*(*int)(v.ptr) = int(x)
	case Int8:
		*(*int8)(v.ptr) = int8(x)
	case Int16:
		*(*int16)(v.ptr) = int16(x)
	case Int32:
		*(*int32)(v.ptr) = int32(x)
	case Int64:
		*(*int64)(v.ptr) = x
	}
}

// SetLen sets v's length to n.
// It panics if v's Kind is not [Slice], or if n is negative or
// greater than the capacity of the slice,
// or if [Value.CanSet] returns false.
func (v Value) SetLen(n int) {
	v.mustBeAssignable()
	v.mustBe(Slice)
	s := (*unsafeheader.Slice)(v.ptr)
	if uint(n) > uint(s.Cap) {
		panic("reflect: slice length out of range in SetLen")
	}
	s.Len = n
}

// SetCap sets v's capacity to n.
// It panics if v's Kind is not [Slice], or if n is smaller than the length or
// greater than the capacity of the slice,
// or if [Value.CanSet] returns false.
func (v Value) SetCap(n int) {
	v.mustBeAssignable()
	v.mustBe(Slice)
	s := (*unsafeheader.Slice)(v.ptr)
	if n < s.Len || n > s.Cap {
		panic("reflect: slice capacity out of range in SetCap")
	}
	s.Cap = n
}

// SetUint sets v's underlying value to x.
// It panics if v's Kind is not [Uint], [Uintptr], [Uint8], [Uint16], [Uint32], or [Uint64],
// or if [Value.CanSet] returns false.
func (v Value) SetUint(x uint64) {
	v.mustBeAssignable()
	switch k := v.kind(); k {
	default:
		panic(&ValueError{"reflect.Value.SetUint", v.kind()})
	case Uint:
		*(*uint)(v.ptr) = uint(x)
	case Uint8:
		*(*uint8)(v.ptr) = uint8(x)
	case Uint16:
		*(*uint16)(v.ptr) = uint16(x)
	case Uint32:
		*(*uint32)(v.ptr) = uint32(x)
	case Uint64:
		*(*uint64)(v.ptr) = x
	case Uintptr:
		*(*uintptr)(v.ptr) = uintptr(x)
	}
}

// SetPointer sets the [unsafe.Pointer] value v to x.
// It panics if v's Kind is not [UnsafePointer]
// or if [Value.CanSet] returns false.
func (v Value) SetPointer(x unsafe.Pointer) {
	v.mustBeAssignable()
	v.mustBe(UnsafePointer)
	*(*unsafe.Pointer)(v.ptr) = x
}

// SetString sets v's underlying value to x.
// It panics if v's Kind is not [String] or if [Value.CanSet] returns false.
func (v Value) SetString(x string) {
	v.mustBeAssignable()
	v.mustBe(String)
	*(*string)(v.ptr) = x
}

// Slice returns v[i:j].
// It panics if v's Kind is not [Array], [Slice] or [String], or if v is an unaddressable array,
// or if the indexes are out of bounds.
func (v Value) Slice(i, j int) Value {
	var (
		cap  int
		typ  *sliceType
		base unsafe.Pointer
	)
	switch kind := v.kind(); kind {
	default:
		panic(&ValueError{"reflect.Value.Slice", v.kind()})

	case Array:
		if v.flag&flagAddr == 0 {
			panic("reflect.Value.Slice: slice of unaddressable array")
		}
		tt := (*arrayType)(unsafe.Pointer(v.typ()))
		cap = int(tt.Len)
		typ = (*sliceType)(unsafe.Pointer(tt.Slice))
		base = v.ptr

	case Slice:
		typ = (*sliceType)(unsafe.Pointer(v.typ()))
		s := (*unsafeheader.Slice)(v.ptr)
		base = s.Data
		cap = s.Cap

	case String:
		s := (*unsafeheader.String)(v.ptr)
		if i < 0 || j < i || j > s.Len {
			panic("reflect.Value.Slice: string slice index out of bounds")
		}
		var t unsafeheader.String
		if i < s.Len {
			t = unsafeheader.String{Data: arrayAt(s.Data, i, 1, "i < s.Len"), Len: j - i}
		}
		return Value{v.typ(), unsafe.Pointer(&t), v.flag}
	}

	if i < 0 || j < i || j > cap {
		panic("reflect.Value.Slice: slice index out of bounds")
	}

	// Declare slice so that gc can see the base pointer in it.
	var x []unsafe.Pointer

	// Reinterpret as *unsafeheader.Slice to edit.
	s := (*unsafeheader.Slice)(unsafe.Pointer(&x))
	s.Len = j - i
	s.Cap = cap - i
	if cap-i > 0 {
		s.Data = arrayAt(base, i, typ.Elem.Size(), "i < cap")
	} else {
		// do not advance pointer, to avoid pointing beyond end of slice
		s.Data = base
	}

	fl := v.flag.ro() | flagIndir | flag(Slice)
	return Value{typ.Common(), unsafe.Pointer(&x), fl}
}

// Slice3 is the 3-index form of the slice operation: it returns v[i:j:k].
// It panics if v's Kind is not [Array] or [Slice], or if v is an unaddressable array,
// or if the indexes are out of bounds.
func (v Value) Slice3(i, j, k int) Value {
	var (
		cap  int
		typ  *sliceType
		base unsafe.Pointer
	)
	switch kind := v.kind(); kind {
	default:
		panic(&ValueError{"reflect.Value.Slice3", v.kind()})

	case Array:
		if v.flag&flagAddr == 0 {
			panic("reflect.Value.Slice3: slice of unaddressable array")
		}
		tt := (*arrayType)(unsafe.Pointer(v.typ()))
		cap = int(tt.Len)
		typ = (*sliceType)(unsafe.Pointer(tt.Slice))
		base = v.ptr

	case Slice:
		typ = (*sliceType)(unsafe.Pointer(v.typ()))
		s := (*unsafeheader.Slice)(v.ptr)
		base = s.Data
		cap = s.Cap
	}

	if i < 0 || j < i || k < j || k > cap {
		panic("reflect.Value.Slice3: slice index out of bounds")
	}

	// Declare slice so that the garbage collector
	// can see the base pointer in it.
	var x []unsafe.Pointer

	// Reinterpret as *unsafeheader.Slice to edit.
	s := (*unsafeheader.Slice)(unsafe.Pointer(&x))
	s.Len = j - i
	s.Cap = k - i
	if k-i > 0 {
		s.Data = arrayAt(base, i, typ.Elem.Size(), "i < k <= cap")
	} else {
		// do not advance pointer, to avoid pointing beyond end of slice
		s.Data = base
	}

	fl := v.flag.ro() | flagIndir | flag(Slice)
	return Value{typ.Common(), unsafe.Pointer(&x), fl}
}

// String returns the string v's underlying value, as a string.
// String is a special case because of Go's String method convention.
// Unlike the other getters, it does not panic if v's Kind is not [String].
// Instead, it returns a string of the form "<T value>" where T is v's type.
// The fmt package treats Values specially. It does not call their String
// method implicitly but instead prints the concrete values they hold.
func (v Value) String() string {
	// stringNonString is split out to keep String inlineable for string kinds.
	if v.kind() == String {
		return *(*string)(v.ptr)
	}
	return v.stringNonString()
}

func (v Value) stringNonString() string {
	if v.kind() == Invalid {
		return "<invalid Value>"
	}
	// If you call String on a reflect.Value of other type, it's better to
	// print something than to panic. Useful in debugging.
	return "<" + v.Type().String() + " Value>"
}

// TryRecv attempts to receive a value from the channel v but will not block.
// It panics if v's Kind is not [Chan].
// If the receive delivers a value, x is the transferred value and ok is true.
// If the receive cannot finish without blocking, x is the zero Value and ok is false.
// If the channel is closed, x is the zero value for the channel's element type and ok is false.
func (v Value) TryRecv() (x Value, ok bool) {
	v.mustBe(Chan)
	v.mustBeExported()
	return v.recv(true)
}

// TrySend attempts to send x on the channel v but will not block.
// It panics if v's Kind is not [Chan].
// It reports whether the value was sent.
// As in Go, x's value must be assignable to the channel's element type.
func (v Value) TrySend(x Value) bool {
	v.mustBe(Chan)
	v.mustBeExported()
	return v.send(x, true)
}

// Type returns v's type.
func (v Value) Type() Type {
	if v.flag != 0 && v.flag&flagMethod == 0 {
		return (*rtype)(abi.NoEscape(unsafe.Pointer(v.typ_))) // inline of toRType(v.typ()), for own inlining in inline test
	}
	return v.typeSlow()
}

func (v Value) typeSlow() Type {
	if v.flag == 0 {
		panic(&ValueError{"reflect.Value.Type", Invalid})
	}

	typ := v.typ()
	if v.flag&flagMethod == 0 {
		return toRType(v.typ())
	}

	// Method value.
	// v.typ describes the receiver, not the method type.
	i := int(v.flag) >> flagMethodShift
	if v.typ().Kind() == abi.Interface {
		// Method on interface.
		tt := (*interfaceType)(unsafe.Pointer(typ))
		if uint(i) >= uint(len(tt.Methods)) {
			panic("reflect: internal error: invalid method index")
		}
		m := &tt.Methods[i]
		return toRType(typeOffFor(typ, m.Typ))
	}
	// Method on concrete type.
	ms := typ.ExportedMethods()
	if uint(i) >= uint(len(ms)) {
		panic("reflect: internal error: invalid method index")
	}
	m := ms[i]
	return toRType(typeOffFor(typ, m.Mtyp))
}

// CanUint reports whether [Value.Uint] can be used without panicking.
func (v Value) CanUint() bool {
	switch v.kind() {
	case Uint, Uint8, Uint16, Uint32, Uint64, Uintptr:
		return true
	default:
		return false
	}
}

// Uint returns v's underlying value, as a uint64.
// It panics if v's Kind is not [Uint], [Uintptr], [Uint8], [Uint16], [Uint32], or [Uint64].
func (v Value) Uint() uint64 {
	k := v.kind()
	p := v.ptr
	switch k {
	case Uint:
		return uint64(*(*uint)(p))
	case Uint8:
		return uint64(*(*uint8)(p))
	case Uint16:
		return uint64(*(*uint16)(p))
	case Uint32:
		return uint64(*(*uint32)(p))
	case Uint64:
		return *(*uint64)(p)
	case Uintptr:
		return uint64(*(*uintptr)(p))
	}
	panic(&ValueError{"reflect.Value.Uint", v.kind()})
}

//go:nocheckptr
// This prevents inlining Value.UnsafeAddr when -d=checkptr is enabled,
// which ensures cmd/compile can recognize unsafe.Pointer(v.UnsafeAddr())
// and make an exception.

// UnsafeAddr returns a pointer to v's data, as a uintptr.
// It panics if v is not addressable.
//
// It's preferred to use uintptr(Value.Addr().UnsafePointer()) to get the equivalent result.
func (v Value) UnsafeAddr() uintptr {
	if v.typ() == nil {
		panic(&ValueError{"reflect.Value.UnsafeAddr", Invalid})
	}
	if v.flag&flagAddr == 0 {
		panic("reflect.Value.UnsafeAddr of unaddressable value")
	}
	// The compiler loses track as it converts to uintptr. Force escape.
	escapes(v.ptr)
	return uintptr(v.ptr)
}

// UnsafePointer returns v's value as a [unsafe.Pointer].
// It panics if v's Kind is not [Chan], [Func], [Map], [Pointer], [Slice], [String] or [UnsafePointer].
//
// If v's Kind is [Func], the returned pointer is an underlying
// code pointer, but not necessarily enough to identify a
// single function uniquely. The only guarantee is that the
// result is zero if and only if v is a nil func Value.
//
// If v's Kind is [Slice], the returned pointer is to the first
// element of the slice. If the slice is nil the returned value
// is nil.  If the slice is empty but non-nil the return value is non-nil.
//
// If v's Kind is [String], the returned pointer is to the first
// element of the underlying bytes of string.
func (v Value) UnsafePointer() unsafe.Pointer {
	k := v.kind()
	switch k {
	case Pointer:
		if !v.typ().Pointers() {
			// Since it is a not-in-heap pointer, all pointers to the heap are
			// forbidden! See comment in Value.Elem and issue #48399.
			if !verifyNotInHeapPtr(*(*uintptr)(v.ptr)) {
				panic("reflect: reflect.Value.UnsafePointer on an invalid notinheap pointer")
			}
			return *(*unsafe.Pointer)(v.ptr)
		}
		fallthrough
	case Chan, Map, UnsafePointer:
		return v.pointer()
	case Func:
		if v.flag&flagMethod != 0 {
			// As the doc comment says, the returned pointer is an
			// underlying code pointer but not necessarily enough to
			// identify a single function uniquely. All method expressions
			// created via reflect have the same underlying code pointer,
			// so their Pointers are equal. The function used here must
			// match the one used in makeMethodValue.
			code := methodValueCallCodePtr()
			return *(*unsafe.Pointer)(unsafe.Pointer(&code))
		}
		p := v.pointer()
		// Non-nil func value points at data block.
		// First word of data block is actual code.
		if p != nil {
			p = *(*unsafe.Pointer)(p)
		}
		return p
	case Slice:
		return (*unsafeheader.Slice)(v.ptr).Data
	case String:
		return (*unsafeheader.String)(v.ptr).Data
	}
	panic(&ValueError{"reflect.Value.UnsafePointer", v.kind()})
}

// StringHeader is the runtime representation of a string.
// It cannot be used safely or portably and its representation may
// change in a later release.
// Moreover, the Data field is not sufficient to guarantee the data
// it references will not be garbage collected, so programs must keep
// a separate, correctly typed pointer to the underlying data.
//
// Deprecated: Use unsafe.String or unsafe.StringData instead.
type StringHeader struct {
	Data uintptr
	Len  int
}

// SliceHeader is the runtime representation of a slice.
// It cannot be used safely or portably and its representation may
// change in a later release.
// Moreover, the Data field is not sufficient to guarantee the data
// it references will not be garbage collected, so programs must keep
// a separate, correctly typed pointer to the underlying data.
//
// Deprecated: Use unsafe.Slice or unsafe.SliceData instead.
type SliceHeader struct {
	Data uintptr
	Len  int
	Cap  int
}

func typesMustMatch(what string, t1, t2 Type) {
	if t1 != t2 {
		panic(what + ": " + t1.String() + " != " + t2.String())
	}
}

// arrayAt returns the i-th element of p,
// an array whose elements are eltSize bytes wide.
// The array pointed at by p must have at least i+1 elements:
// it is invalid (but impossible to check here) to pass i >= len,
// because then the result will point outside the array.
// whySafe must explain why i < len. (Passing "i < len" is fine;
// the benefit is to surface this assumption at the call site.)
func arrayAt(p unsafe.Pointer, i int, eltSize uintptr, whySafe string) unsafe.Pointer {
	return add(p, uintptr(i)*eltSize, "i < len")
}

// Grow increases the slice's capacity, if necessary, to guarantee space for
// another n elements. After Grow(n), at least n elements can be appended
// to the slice without another allocation.
//
// It panics if v's Kind is not a [Slice], or if n is negative or too large to
// allocate the memory, or if [Value.CanSet] returns false.
func (v Value) Grow(n int) {
	v.mustBeAssignable()
	v.mustBe(Slice)
	v.grow(n)
}

// grow is identical to Grow but does not check for assignability.
func (v Value) grow(n int) {
	p := (*unsafeheader.Slice)(v.ptr)
	switch {
	case n < 0:
		panic("reflect.Value.Grow: negative len")
	case p.Len+n < 0:
		panic("reflect.Value.Grow: slice overflow")
	case p.Len+n > p.Cap:
		t := v.typ().Elem()
		*p = growslice(t, *p, n)
	}
}

// extendSlice extends a slice by n elements.
//
// Unlike Value.grow, which modifies the slice in place and
// does not change the length of the slice in place,
// extendSlice returns a new slice value with the length
// incremented by the number of specified elements.
func (v Value) extendSlice(n int) Value {
	v.mustBeExported()
	v.mustBe(Slice)

	// Shallow copy the slice header to avoid mutating the source slice.
	sh := *(*unsafeheader.Slice)(v.ptr)
	s := &sh
	v.ptr = unsafe.Pointer(s)
	v.flag = flagIndir | flag(Slice) // equivalent flag to MakeSlice

	v.grow(n) // fine to treat as assignable since we allocate a new slice header
	s.Len += n
	return v
}

// Clear clears the contents of a map or zeros the contents of a slice.
//
// It panics if v's Kind is not [Map] or [Slice].
func (v Value) Clear() {
	switch v.Kind() {
	case Slice:
		sh := *(*unsafeheader.Slice)(v.ptr)
		st := (*sliceType)(unsafe.Pointer(v.typ()))
		typedarrayclear(st.Elem, sh.Data, sh.Len)
	case Map:
		mapclear(v.typ(), v.pointer())
	default:
		panic(&ValueError{"reflect.Value.Clear", v.Kind()})
	}
}

// Append appends the values x to a slice s and returns the resulting slice.
// As in Go, each x's value must be assignable to the slice's element type.
func Append(s Value, x ...Value) Value {
	s.mustBe(Slice)
	n := s.Len()
	s = s.extendSlice(len(x))
	for i, v := range x {
		s.Index(n + i).Set(v)
	}
	return s
}

// AppendSlice appends a slice t to a slice s and returns the resulting slice.
// The slices s and t must have the same element type.
func AppendSlice(s, t Value) Value {
	s.mustBe(Slice)
	t.mustBe(Slice)
	typesMustMatch("reflect.AppendSlice", s.Type().Elem(), t.Type().Elem())
	ns := s.Len()
	nt := t.Len()
	s = s.extendSlice(nt)
	Copy(s.Slice(ns, ns+nt), t)
	return s
}

// Copy copies the contents of src into dst until either
// dst has been filled or src has been exhausted.
// It returns the number of elements copied.
// Dst and src each must have kind [Slice] or [Array], and
// dst and src must have the same element type.
// It dst is an [Array], it panics if [Value.CanSet] returns false.
//
// As a special case, src can have kind [String] if the element type of dst is kind [Uint8].
func Copy(dst, src Value) int {
	dk := dst.kind()
	if dk != Array && dk != Slice {
		panic(&ValueError{"reflect.Copy", dk})
	}
	if dk == Array {
		dst.mustBeAssignable()
	}
	dst.mustBeExported()

	sk := src.kind()
	var stringCopy bool
	if sk != Array && sk != Slice {
		stringCopy = sk == String && dst.typ().Elem().Kind() == abi.Uint8
		if !stringCopy {
			panic(&ValueError{"reflect.Copy", sk})
		}
	}
	src.mustBeExported()

	de := dst.typ().Elem()
	if !stringCopy {
		se := src.typ().Elem()
		typesMustMatch("reflect.Copy", toType(de), toType(se))
	}

	var ds, ss unsafeheader.Slice
	if dk == Array {
		ds.Data = dst.ptr
		ds.Len = dst.Len()
		ds.Cap = ds.Len
	} else {
		ds = *(*unsafeheader.Slice)(dst.ptr)
	}
	if sk == Array {
		ss.Data = src.ptr
		ss.Len = src.Len()
		ss.Cap = ss.Len
	} else if sk == Slice {
		ss = *(*unsafeheader.Slice)(src.ptr)
	} else {
		sh := *(*unsafeheader.String)(src.ptr)
		ss.Data = sh.Data
		ss.Len = sh.Len
		ss.Cap = sh.Len
	}

	return typedslicecopy(de.Common(), ds, ss)
}

// A runtimeSelect is a single case passed to rselect.
// This must match ../runtime/select.go:/runtimeSelect
type runtimeSelect struct {
	dir SelectDir      // SelectSend, SelectRecv or SelectDefault
	typ *rtype         // channel type
	ch  unsafe.Pointer // channel
	val unsafe.Pointer // ptr to data (SendDir) or ptr to receive buffer (RecvDir)
}

// rselect runs a select. It returns the index of the chosen case.
// If the case was a receive, val is filled in with the received value.
// The conventional OK bool indicates whether the receive corresponds
// to a sent value.
//
// rselect generally doesn't escape the runtimeSelect slice, except
// that for the send case the value to send needs to escape. We don't
// have a way to represent that in the function signature. So we handle
// that with a forced escape in function Select.
//
//go:noescape
func rselect([]runtimeSelect) (chosen int, recvOK bool)

// A SelectDir describes the communication direction of a select case.
type SelectDir int

// NOTE: These values must match ../runtime/select.go:/selectDir.

const (
	_             SelectDir = iota
	SelectSend              // case Chan <- Send
	SelectRecv              // case <-Chan:
	SelectDefault           // default
)

// A SelectCase describes a single case in a select operation.
// The kind of case depends on Dir, the communication direction.
//
// If Dir is SelectDefault, the case represents a default case.
// Chan and Send must be zero Values.
//
// If Dir is SelectSend, the case represents a send operation.
// Normally Chan's underlying value must be a channel, and Send's underlying value must be
// assignable to the channel's element type. As a special case, if Chan is a zero Value,
// then the case is ignored, and the field Send will also be ignored and may be either zero
// or non-zero.
//
// If Dir is [SelectRecv], the case represents a receive operation.
// Normally Chan's underlying value must be a channel and Send must be a zero Value.
// If Chan is a zero Value, then the case is ignored, but Send must still be a zero Value.
// When a receive operation is selected, the received Value is returned by Select.
type SelectCase struct {
	Dir  SelectDir // direction of case
	Chan Value     // channel to use (for send or receive)
	Send Value     // value to send (for send)
}

// Select executes a select operation described by the list of cases.
// Like the Go select statement, it blocks until at least one of the cases
// can proceed, makes a uniform pseudo-random choice,
// and then executes that case. It returns the index of the chosen case
// and, if that case was a receive operation, the value received and a
// boolean indicating whether the value corresponds to a send on the channel
// (as opposed to a zero value received because the channel is closed).
// Select supports a maximum of 65536 cases.
func Select(cases []SelectCase) (chosen int, recv Value, recvOK bool) {
	if len(cases) > 65536 {
		panic("reflect.Select: too many cases (max 65536)")
	}
	// NOTE: Do not trust that caller is not modifying cases data underfoot.
	// The range is safe because the caller cannot modify our copy of the len
	// and each iteration makes its own copy of the value c.
	var runcases []runtimeSelect
	if len(cases) > 4 {
		// Slice is heap allocated due to runtime dependent capacity.
		runcases = make([]runtimeSelect, len(cases))
	} else {
		// Slice can be stack allocated due to constant capacity.
		runcases = make([]runtimeSelect, len(cases), 4)
	}

	haveDefault := false
	for i, c := range cases {
		rc := &runcases[i]
		rc.dir = c.Dir
		switch c.Dir {
		default:
			panic("reflect.Select: invalid Dir")

		case SelectDefault: // default
			if haveDefault {
				panic("reflect.Select: multiple default cases")
			}
			haveDefault = true
			if c.Chan.IsValid() {
				panic("reflect.Select: default case has Chan value")
			}
			if c.Send.IsValid() {
				panic("reflect.Select: default case has Send value")
			}

		case SelectSend:
			ch := c.Chan
			if !ch.IsValid() {
				break
			}
			ch.mustBe(Chan)
			ch.mustBeExported()
			tt := (*chanType)(unsafe.Pointer(ch.typ()))
			if ChanDir(tt.Dir)&SendDir == 0 {
				panic("reflect.Select: SendDir case using recv-only channel")
			}
			rc.ch = ch.pointer()
			rc.typ = toRType(&tt.Type)
			v := c.Send
			if !v.IsValid() {
				panic("reflect.Select: SendDir case missing Send value")
			}
			v.mustBeExported()
			v = v.assignTo("reflect.Select", tt.Elem, nil)
			if v.flag&flagIndir != 0 {
				rc.val = v.ptr
			} else {
				rc.val = unsafe.Pointer(&v.ptr)
			}
			// The value to send needs to escape. See the comment at rselect for
			// why we need forced escape.
			escapes(rc.val)

		case SelectRecv:
			if c.Send.IsValid() {
				panic("reflect.Select: RecvDir case has Send value")
			}
			ch := c.Chan
			if !ch.IsValid() {
				break
			}
			ch.mustBe(Chan)
			ch.mustBeExported()
			tt := (*chanType)(unsafe.Pointer(ch.typ()))
			if ChanDir(tt.Dir)&RecvDir == 0 {
				panic("reflect.Select: RecvDir case using send-only channel")
			}
			rc.ch = ch.pointer()
			rc.typ = toRType(&tt.Type)
			rc.val = unsafe_New(tt.Elem)
		}
	}

	chosen, recvOK = rselect(runcases)
	if runcases[chosen].dir == SelectRecv {
		tt := (*chanType)(unsafe.Pointer(runcases[chosen].typ))
		t := tt.Elem
		p := runcases[chosen].val
		fl := flag(t.Kind())
		if t.IfaceIndir() {
			recv = Value{t, p, fl | flagIndir}
		} else {
			recv = Value{t, *(*unsafe.Pointer)(p), fl}
		}
	}
	return chosen, recv, recvOK
}

/*
 * constructors
 */

// implemented in package runtime

//go:noescape
func unsafe_New(*abi.Type) unsafe.Pointer

//go:noescape
func unsafe_NewArray(*abi.Type, int) unsafe.Pointer

// MakeSlice creates a new zero-initialized slice value
// for the specified slice type, length, and capacity.
func MakeSlice(typ Type, len, cap int) Value {
	if typ.Kind() != Slice {
		panic("reflect.MakeSlice of non-slice type")
	}
	if len < 0 {
		panic("reflect.MakeSlice: negative len")
	}
	if cap < 0 {
		panic("reflect.MakeSlice: negative cap")
	}
	if len > cap {
		panic("reflect.MakeSlice: len > cap")
	}

	s := unsafeheader.Slice{Data: unsafe_NewArray(&(typ.Elem().(*rtype).t), cap), Len: len, Cap: cap}
	return Value{&typ.(*rtype).t, unsafe.Pointer(&s), flagIndir | flag(Slice)}
}

// SliceAt returns a [Value] representing a slice whose underlying
// data starts at p, with length and capacity equal to n.
//
// This is like [unsafe.Slice].
func SliceAt(typ Type, p unsafe.Pointer, n int) Value {
	unsafeslice(typ.common(), p, n)
	s := unsafeheader.Slice{Data: p, Len: n, Cap: n}
	return Value{SliceOf(typ).common(), unsafe.Pointer(&s), flagIndir | flag(Slice)}
}

// MakeChan creates a new channel with the specified type and buffer size.
func MakeChan(typ Type, buffer int) Value {
	if typ.Kind() != Chan {
		panic("reflect.MakeChan of non-chan type")
	}
	if buffer < 0 {
		panic("reflect.MakeChan: negative buffer size")
	}
	if typ.ChanDir() != BothDir {
		panic("reflect.MakeChan: unidirectional channel type")
	}
	t := typ.common()
	ch := makechan(t, buffer)
	return Value{t, ch, flag(Chan)}
}

// MakeMap creates a new map with the specified type.
func MakeMap(typ Type) Value {
	return MakeMapWithSize(typ, 0)
}

// MakeMapWithSize creates a new map with the specified type
// and initial space for approximately n elements.
func MakeMapWithSize(typ Type, n int) Value {
	if typ.Kind() != Map {
		panic("reflect.MakeMapWithSize of non-map type")
	}
	t := typ.common()
	m := makemap(t, n)
	return Value{t, m, flag(Map)}
}

// Indirect returns the value that v points to.
// If v is a nil pointer, Indirect returns a zero Value.
// If v is not a pointer, Indirect returns v.
func Indirect(v Value) Value {
	if v.Kind() != Pointer {
		return v
	}
	return v.Elem()
}

// ValueOf returns a new Value initialized to the concrete value
// stored in the interface i. ValueOf(nil) returns the zero Value.
func ValueOf(i any) Value {
	if i == nil {
		return Value{}
	}
	return unpackEface(i)
}

// Zero returns a Value representing the zero value for the specified type.
// The result is different from the zero value of the Value struct,
// which represents no value at all.
// For example, Zero(TypeOf(42)) returns a Value with Kind [Int] and value 0.
// The returned value is neither addressable nor settable.
func Zero(typ Type) Value {
	if typ == nil {
		panic("reflect: Zero(nil)")
	}
	t := &typ.(*rtype).t
	fl := flag(t.Kind())
	if t.IfaceIndir() {
		var p unsafe.Pointer
		if t.Size() <= abi.ZeroValSize {
			p = unsafe.Pointer(&zeroVal[0])
		} else {
			p = unsafe_New(t)
		}
		return Value{t, p, fl | flagIndir}
	}
	return Value{t, nil, fl}
}

//go:linkname zeroVal runtime.zeroVal
var zeroVal [abi.ZeroValSize]byte

// New returns a Value representing a pointer to a new zero value
// for the specified type. That is, the returned Value's Type is [PointerTo](typ).
func New(typ Type) Value {
	if typ == nil {
		panic("reflect: New(nil)")
	}
	t := &typ.(*rtype).t
	pt := ptrTo(t)
	if pt.IfaceIndir() {
		// This is a pointer to a not-in-heap type.
		panic("reflect: New of type that may not be allocated in heap (possibly undefined cgo C type)")
	}
	ptr := unsafe_New(t)
	fl := flag(Pointer)
	return Value{pt, ptr, fl}
}

// NewAt returns a Value representing a pointer to a value of the
// specified type, using p as that pointer.
func NewAt(typ Type, p unsafe.Pointer) Value {
	fl := flag(Pointer)
	t := typ.(*rtype)
	return Value{t.ptrTo(), p, fl}
}

// assignTo returns a value v that can be assigned directly to dst.
// It panics if v is not assignable to dst.
// For a conversion to an interface type, target, if not nil,
// is a suggested scratch space to use.
// target must be initialized memory (or nil).
func (v Value) assignTo(context string, dst *abi.Type, target unsafe.Pointer) Value {
	if v.flag&flagMethod != 0 {
		v = makeMethodValue(context, v)
	}

	switch {
	case directlyAssignable(dst, v.typ()):
		// Overwrite type so that they match.
		// Same memory layout, so no harm done.
		fl := v.flag&(flagAddr|flagIndir) | v.flag.ro()
		fl |= flag(dst.Kind())
		return Value{dst, v.ptr, fl}

	case implements(dst, v.typ()):
		if v.Kind() == Interface && v.IsNil() {
			// A nil ReadWriter passed to nil Reader is OK,
			// but using ifaceE2I below will panic.
			// Avoid the panic by returning a nil dst (e.g., Reader) explicitly.
			return Value{dst, nil, flag(Interface)}
		}
		x := valueInterface(v, false)
		if target == nil {
			target = unsafe_New(dst)
		}
		if dst.NumMethod() == 0 {
			*(*any)(target) = x
		} else {
			ifaceE2I(dst, x, target)
		}
		return Value{dst, target, flagIndir | flag(Interface)}
	}

	// Failed.
	panic(context + ": value of type " + stringFor(v.typ()) + " is not assignable to type " + stringFor(dst))
}

// Convert returns the value v converted to type t.
// If the usual Go conversion rules do not allow conversion
// of the value v to type t, or if converting v to type t panics, Convert panics.
func (v Value) Convert(t Type) Value {
	if v.flag&flagMethod != 0 {
		v = makeMethodValue("Convert", v)
	}
	op := convertOp(t.common(), v.typ())
	if op == nil {
		panic("reflect.Value.Convert: value of type " + stringFor(v.typ()) + " cannot be converted to type " + t.String())
	}
	return op(v, t)
}

// CanConvert reports whether the value v can be converted to type t.
// If v.CanConvert(t) returns true then v.Convert(t) will not panic.
func (v Value) CanConvert(t Type) bool {
	vt := v.Type()
	if !vt.ConvertibleTo(t) {
		return false
	}
	// Converting from slice to array or to pointer-to-array can panic
	// depending on the value.
	switch {
	case vt.Kind() == Slice && t.Kind() == Array:
		if t.Len() > v.Len() {
			return false
		}
	case vt.Kind() == Slice && t.Kind() == Pointer && t.Elem().Kind() == Array:
		n := t.Elem().Len()
		if n > v.Len() {
			return false
		}
	}
	return true
}

// Comparable reports whether the value v is comparable.
// If the type of v is an interface, this checks the dynamic type.
// If this reports true then v.Interface() == x will not panic for any x,
// nor will v.Equal(u) for any Value u.
func (v Value) Comparable() bool {
	k := v.Kind()
	switch k {
	case Invalid:
		return false

	case Array:
		switch v.Type().Elem().Kind() {
		case Interface, Array, Struct:
			for i := 0; i < v.Type().Len(); i++ {
				if !v.Index(i).Comparable() {
					return false
				}
			}
			return true
		}
		return v.Type().Comparable()

	case Interface:
		return v.IsNil() || v.Elem().Comparable()

	case Struct:
		for i := 0; i < v.NumField(); i++ {
			if !v.Field(i).Comparable() {
				return false
			}
		}
		return true

	default:
		return v.Type().Comparable()
	}
}

// Equal reports true if v is equal to u.
// For two invalid values, Equal will report true.
// For an interface value, Equal will compare the value within the interface.
// Otherwise, If the values have different types, Equal will report false.
// Otherwise, for arrays and structs Equal will compare each element in order,
// and report false if it finds non-equal elements.
// During all comparisons, if values of the same type are compared,
// and the type is not comparable, Equal will panic.
func (v Value) Equal(u Value) bool {
	if v.Kind() == Interface {
		v = v.Elem()
	}
	if u.Kind() == Interface {
		u = u.Elem()
	}

	if !v.IsValid() || !u.IsValid() {
		return v.IsValid() == u.IsValid()
	}

	if v.Kind() != u.Kind() || v.Type() != u.Type() {
		return false
	}

	// Handle each Kind directly rather than calling valueInterface
	// to avoid allocating.
	switch v.Kind() {
	default:
		panic("reflect.Value.Equal: invalid Kind")
	case Bool:
		return v.Bool() == u.Bool()
	case Int, Int8, Int16, Int32, Int64:
		return v.Int() == u.Int()
	case Uint, Uint8, Uint16, Uint32, Uint64, Uintptr:
		return v.Uint() == u.Uint()
	case Float32, Float64:
		return v.Float() == u.F
"""




```