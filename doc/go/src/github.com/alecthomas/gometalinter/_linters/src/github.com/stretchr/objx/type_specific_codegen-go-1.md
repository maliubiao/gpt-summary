Response:
Let's break down the thought process for analyzing this Go code snippet.

1. **Understand the Goal:** The request asks for a functional summary of the provided Go code, assuming it's part of a larger system. It also asks for specific examples, potential errors, and a high-level summary as part 2 of 2.

2. **Identify the Core Structure:**  The code defines methods on a type named `Value`. These methods are consistently named (e.g., `Uint8`, `MustUint8`, `Uint8Slice`, `MustUint8Slice`, `IsUint8`, `IsUint8Slice`, `EachUint8`, `WhereUint8`, `GroupUint8`, `ReplaceUint8`, `CollectUint8`). This naming convention strongly suggests a pattern for handling different Go primitive types.

3. **Recognize the Repetition:**  A quick scan reveals very similar blocks of code repeated for different unsigned integer types (`uint8`, `uint16`, `uint32`, `uint64`, `uintptr`), and then again for floating-point (`float32`, `float64`) and complex number (`complex64`, `complex128`) types. This repetition is a crucial observation.

4. **Deduce the Purpose of `Value`:** Given the methods, `Value` likely acts as a wrapper around a generic data type. The methods provide type-safe access and manipulation of the underlying data. The `Must...` methods suggest that the `Value` type might not always hold the expected type, and these methods enforce that expectation, potentially panicking if the type is wrong.

5. **Analyze Individual Method Categories:**  Group the methods by their function:
    * **Getter Methods:** `Uint8()`, `Uint8Slice()`, `Float32()`, `Float32Slice()`, etc. These methods attempt to retrieve the underlying data as a specific type. The presence of `optionalDefault` parameters indicates a way to handle type mismatches gracefully.
    * **Panic Getter Methods:** `MustUint8()`, `MustUint8Slice()`, etc. These are stricter versions that assume the data is of the expected type and will panic if it isn't.
    * **Type Checking Methods:** `IsUint8()`, `IsUint8Slice()`, etc. These allow checking the underlying data type without attempting to retrieve the value.
    * **Iteration/Manipulation Methods:**  `EachUint8()`, `WhereUint8()`, `GroupUint8()`, `ReplaceUint8()`, `CollectUint8()`. These methods operate on slices of the specific type. They often take a callback function as an argument, allowing for custom logic.

6. **Infer the Generic Implementation:** The file name `type_specific_codegen.go` strongly hints that this code is likely *generated* rather than written manually. A code generation process would explain the repetitive structure. The underlying `Value` type likely stores data as an `interface{}` and these type-specific methods provide a convenient and type-safe way to interact with it.

7. **Construct Example Usage:** For each category of methods, create simple, illustrative examples. Focus on demonstrating the core functionality and the difference between the standard getter and the `Must...` getter. Include examples of the iteration/manipulation methods with simple callback functions.

8. **Identify Potential Errors:** The `Must...` methods are obvious points of failure if the underlying data isn't of the expected type. Also, using the slice-based methods on a `Value` that doesn't hold a slice will cause a panic. Incorrect callback function logic could also lead to unexpected results.

9. **Address Command Line Arguments:**  The provided code doesn't contain any direct handling of command-line arguments. State this explicitly.

10. **Formulate the Summary (Part 2):**  Based on the analysis, summarize the core purpose of the code: providing type-safe access and manipulation for various primitive types stored within a `Value` struct. Emphasize the generated nature of the code and the benefits it provides in terms of convenience and type safety.

11. **Refine and Organize:** Review the entire analysis for clarity, accuracy, and completeness. Ensure the examples are easy to understand and the potential errors are clearly identified. Organize the information logically.

**Self-Correction/Refinement during the process:**

* **Initial thought:**  Perhaps `Value` is a simple struct holding different type fields.
* **Correction:** The extensive number of type-specific methods and the `Must...` methods strongly suggest `Value` uses `interface{}` internally.
* **Initial thought:**  The examples should be very complex to show all possibilities.
* **Correction:** Simple, focused examples are better for demonstrating the core functionality of each method.
* **Initial thought:**  Maybe there are hidden command-line argument interactions.
* **Correction:** A thorough scan confirms no direct command-line argument handling within the provided code. Stick to what's explicitly present.

By following this structured approach, combining code analysis with logical deduction and focusing on the observed patterns, a comprehensive and accurate understanding of the code's functionality can be achieved.
好的，这是第二部分，我们将归纳一下这个Go语言文件的功能。

**功能归纳**

这个 `type_specific_codegen.go` 文件的主要功能是为 `objx` 包的 `Value` 类型提供了一系列类型特定的方法，用于安全且方便地访问和操作存储在 `Value` 中的各种基本数据类型（如 `uint8`, `uint16`, `uint32`, `uint64`, `uintptr`, `float32`, `float64`, `complex64`, `complex128`）及其切片。

**具体来说，它做了以下几件事：**

1. **类型安全地获取值:**
   - 提供了 `Type()` 方法（例如 `Uint8()`, `Float32()`, `Complex128()`）来尝试将 `Value` 中存储的数据转换为指定的类型。如果类型匹配则返回该类型的值，否则返回一个默认值（通常是该类型的零值，也可以提供可选的默认值）。
   - 提供了 `MustType()` 方法（例如 `MustUint8()`, `MustFloat32()`, `MustComplex128()`），这些方法假定 `Value` 中的数据是指定的类型，并直接进行类型断言。如果类型不匹配，程序会发生 `panic`。

2. **类型安全地获取切片:**
   - 提供了 `TypeSlice()` 方法（例如 `Uint8Slice()`, `Float32Slice()`, `Complex128Slice()`）来尝试将 `Value` 中存储的数据转换为指定类型的切片。如果类型匹配则返回该切片，否则返回 `nil`（也可以提供可选的默认值）。
   - 提供了 `MustTypeSlice()` 方法（例如 `MustUint8Slice()`, `MustFloat32Slice()`, `MustComplex128Slice()`），这些方法假定 `Value` 中的数据是指定类型的切片，并直接进行类型断言。如果类型不匹配，程序会发生 `panic`。

3. **类型检查:**
   - 提供了 `IsType()` 方法（例如 `IsUint8()`, `IsFloat32()`, `IsComplex128()`）来检查 `Value` 中存储的数据是否为指定的类型。
   - 提供了 `IsTypeSlice()` 方法（例如 `IsUint8Slice()`, `IsFloat32Slice()`, `IsComplex128Slice()`）来检查 `Value` 中存储的数据是否为指定类型的切片。

4. **迭代和操作切片:**
   - 提供了 `EachType()` 方法（例如 `EachUint8()`, `EachFloat32()`, `EachComplex128()`），用于遍历指定类型的切片中的每个元素，并对每个元素执行回调函数。回调函数可以控制是否继续迭代。
   - 提供了 `WhereType()` 方法（例如 `WhereUint8()`, `WhereFloat32()`, `WhereComplex128()`），用于根据提供的 `decider` 函数筛选指定类型切片中的元素，返回一个新的 `Value` 对象，其中包含满足条件的元素组成的新切片。
   - 提供了 `GroupType()` 方法（例如 `GroupUint8()`, `GroupFloat32()`, `GroupComplex128()`），用于根据提供的 `grouper` 函数将指定类型切片中的元素分组，返回一个新的 `Value` 对象，其中包含一个 `map[string][]Type`，键是 `grouper` 函数的返回值，值是属于该组的元素切片。
   - 提供了 `ReplaceType()` 方法（例如 `ReplaceUint8()`, `ReplaceFloat32()`, `ReplaceComplex128()`），用于根据提供的 `replacer` 函数替换指定类型切片中的每个元素，返回一个新的 `Value` 对象，其中包含替换后的元素组成的新切片。
   - 提供了 `CollectType()` 方法（例如 `CollectUint8()`, `CollectFloat32()`, `CollectComplex128()`），用于根据提供的 `collector` 函数从指定类型切片中的每个元素收集一个值，返回一个新的 `Value` 对象，其中包含收集到的值组成的 `[]interface{}` 切片。

**总而言之，这个文件的核心目的是为了增强 `objx.Value` 的功能，使其能够更方便、更安全地处理各种基本数据类型及其切片，避免了在使用 `interface{}` 存储数据时频繁进行类型断言的麻烦和潜在的 `panic` 风险。**

可以推断出，`objx.Value` 的设计目标是提供一个灵活的容器来存储各种类型的数据，而这个 `type_specific_codegen.go` 文件是通过代码生成的方式，为每种基本类型都生成了相应的操作方法，以提高开发效率和代码可读性。这是一种常见的在需要处理多种类型但又希望保持类型安全性的 Go 语言编程模式。

Prompt: 
```
这是路径为go/src/github.com/alecthomas/gometalinter/_linters/src/github.com/stretchr/objx/type_specific_codegen.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第2部分，共2部分，请归纳一下它的功能

"""

func (v *Value) WhereUint8(decider func(int, uint8) bool) *Value {
	var selected []uint8
	v.EachUint8(func(index int, val uint8) bool {
		shouldSelect := decider(index, val)
		if !shouldSelect {
			selected = append(selected, val)
		}
		return true
	})
	return &Value{data: selected}
}

// GroupUint8 uses the specified grouper function to group the items
// keyed by the return of the grouper.  The object contained in the
// result will contain a map[string][]uint8.
func (v *Value) GroupUint8(grouper func(int, uint8) string) *Value {
	groups := make(map[string][]uint8)
	v.EachUint8(func(index int, val uint8) bool {
		group := grouper(index, val)
		if _, ok := groups[group]; !ok {
			groups[group] = make([]uint8, 0)
		}
		groups[group] = append(groups[group], val)
		return true
	})
	return &Value{data: groups}
}

// ReplaceUint8 uses the specified function to replace each uint8s
// by iterating each item.  The data in the returned result will be a
// []uint8 containing the replaced items.
func (v *Value) ReplaceUint8(replacer func(int, uint8) uint8) *Value {
	arr := v.MustUint8Slice()
	replaced := make([]uint8, len(arr))
	v.EachUint8(func(index int, val uint8) bool {
		replaced[index] = replacer(index, val)
		return true
	})
	return &Value{data: replaced}
}

// CollectUint8 uses the specified collector function to collect a value
// for each of the uint8s in the slice.  The data returned will be a
// []interface{}.
func (v *Value) CollectUint8(collector func(int, uint8) interface{}) *Value {
	arr := v.MustUint8Slice()
	collected := make([]interface{}, len(arr))
	v.EachUint8(func(index int, val uint8) bool {
		collected[index] = collector(index, val)
		return true
	})
	return &Value{data: collected}
}

/*
   Uint16 (uint16 and []uint16)
*/

// Uint16 gets the value as a uint16, returns the optionalDefault
// value or a system default object if the value is the wrong type.
func (v *Value) Uint16(optionalDefault ...uint16) uint16 {
	if s, ok := v.data.(uint16); ok {
		return s
	}
	if len(optionalDefault) == 1 {
		return optionalDefault[0]
	}
	return 0
}

// MustUint16 gets the value as a uint16.
//
// Panics if the object is not a uint16.
func (v *Value) MustUint16() uint16 {
	return v.data.(uint16)
}

// Uint16Slice gets the value as a []uint16, returns the optionalDefault
// value or nil if the value is not a []uint16.
func (v *Value) Uint16Slice(optionalDefault ...[]uint16) []uint16 {
	if s, ok := v.data.([]uint16); ok {
		return s
	}
	if len(optionalDefault) == 1 {
		return optionalDefault[0]
	}
	return nil
}

// MustUint16Slice gets the value as a []uint16.
//
// Panics if the object is not a []uint16.
func (v *Value) MustUint16Slice() []uint16 {
	return v.data.([]uint16)
}

// IsUint16 gets whether the object contained is a uint16 or not.
func (v *Value) IsUint16() bool {
	_, ok := v.data.(uint16)
	return ok
}

// IsUint16Slice gets whether the object contained is a []uint16 or not.
func (v *Value) IsUint16Slice() bool {
	_, ok := v.data.([]uint16)
	return ok
}

// EachUint16 calls the specified callback for each object
// in the []uint16.
//
// Panics if the object is the wrong type.
func (v *Value) EachUint16(callback func(int, uint16) bool) *Value {
	for index, val := range v.MustUint16Slice() {
		carryon := callback(index, val)
		if !carryon {
			break
		}
	}
	return v
}

// WhereUint16 uses the specified decider function to select items
// from the []uint16.  The object contained in the result will contain
// only the selected items.
func (v *Value) WhereUint16(decider func(int, uint16) bool) *Value {
	var selected []uint16
	v.EachUint16(func(index int, val uint16) bool {
		shouldSelect := decider(index, val)
		if !shouldSelect {
			selected = append(selected, val)
		}
		return true
	})
	return &Value{data: selected}
}

// GroupUint16 uses the specified grouper function to group the items
// keyed by the return of the grouper.  The object contained in the
// result will contain a map[string][]uint16.
func (v *Value) GroupUint16(grouper func(int, uint16) string) *Value {
	groups := make(map[string][]uint16)
	v.EachUint16(func(index int, val uint16) bool {
		group := grouper(index, val)
		if _, ok := groups[group]; !ok {
			groups[group] = make([]uint16, 0)
		}
		groups[group] = append(groups[group], val)
		return true
	})
	return &Value{data: groups}
}

// ReplaceUint16 uses the specified function to replace each uint16s
// by iterating each item.  The data in the returned result will be a
// []uint16 containing the replaced items.
func (v *Value) ReplaceUint16(replacer func(int, uint16) uint16) *Value {
	arr := v.MustUint16Slice()
	replaced := make([]uint16, len(arr))
	v.EachUint16(func(index int, val uint16) bool {
		replaced[index] = replacer(index, val)
		return true
	})
	return &Value{data: replaced}
}

// CollectUint16 uses the specified collector function to collect a value
// for each of the uint16s in the slice.  The data returned will be a
// []interface{}.
func (v *Value) CollectUint16(collector func(int, uint16) interface{}) *Value {
	arr := v.MustUint16Slice()
	collected := make([]interface{}, len(arr))
	v.EachUint16(func(index int, val uint16) bool {
		collected[index] = collector(index, val)
		return true
	})
	return &Value{data: collected}
}

/*
   Uint32 (uint32 and []uint32)
*/

// Uint32 gets the value as a uint32, returns the optionalDefault
// value or a system default object if the value is the wrong type.
func (v *Value) Uint32(optionalDefault ...uint32) uint32 {
	if s, ok := v.data.(uint32); ok {
		return s
	}
	if len(optionalDefault) == 1 {
		return optionalDefault[0]
	}
	return 0
}

// MustUint32 gets the value as a uint32.
//
// Panics if the object is not a uint32.
func (v *Value) MustUint32() uint32 {
	return v.data.(uint32)
}

// Uint32Slice gets the value as a []uint32, returns the optionalDefault
// value or nil if the value is not a []uint32.
func (v *Value) Uint32Slice(optionalDefault ...[]uint32) []uint32 {
	if s, ok := v.data.([]uint32); ok {
		return s
	}
	if len(optionalDefault) == 1 {
		return optionalDefault[0]
	}
	return nil
}

// MustUint32Slice gets the value as a []uint32.
//
// Panics if the object is not a []uint32.
func (v *Value) MustUint32Slice() []uint32 {
	return v.data.([]uint32)
}

// IsUint32 gets whether the object contained is a uint32 or not.
func (v *Value) IsUint32() bool {
	_, ok := v.data.(uint32)
	return ok
}

// IsUint32Slice gets whether the object contained is a []uint32 or not.
func (v *Value) IsUint32Slice() bool {
	_, ok := v.data.([]uint32)
	return ok
}

// EachUint32 calls the specified callback for each object
// in the []uint32.
//
// Panics if the object is the wrong type.
func (v *Value) EachUint32(callback func(int, uint32) bool) *Value {
	for index, val := range v.MustUint32Slice() {
		carryon := callback(index, val)
		if !carryon {
			break
		}
	}
	return v
}

// WhereUint32 uses the specified decider function to select items
// from the []uint32.  The object contained in the result will contain
// only the selected items.
func (v *Value) WhereUint32(decider func(int, uint32) bool) *Value {
	var selected []uint32
	v.EachUint32(func(index int, val uint32) bool {
		shouldSelect := decider(index, val)
		if !shouldSelect {
			selected = append(selected, val)
		}
		return true
	})
	return &Value{data: selected}
}

// GroupUint32 uses the specified grouper function to group the items
// keyed by the return of the grouper.  The object contained in the
// result will contain a map[string][]uint32.
func (v *Value) GroupUint32(grouper func(int, uint32) string) *Value {
	groups := make(map[string][]uint32)
	v.EachUint32(func(index int, val uint32) bool {
		group := grouper(index, val)
		if _, ok := groups[group]; !ok {
			groups[group] = make([]uint32, 0)
		}
		groups[group] = append(groups[group], val)
		return true
	})
	return &Value{data: groups}
}

// ReplaceUint32 uses the specified function to replace each uint32s
// by iterating each item.  The data in the returned result will be a
// []uint32 containing the replaced items.
func (v *Value) ReplaceUint32(replacer func(int, uint32) uint32) *Value {
	arr := v.MustUint32Slice()
	replaced := make([]uint32, len(arr))
	v.EachUint32(func(index int, val uint32) bool {
		replaced[index] = replacer(index, val)
		return true
	})
	return &Value{data: replaced}
}

// CollectUint32 uses the specified collector function to collect a value
// for each of the uint32s in the slice.  The data returned will be a
// []interface{}.
func (v *Value) CollectUint32(collector func(int, uint32) interface{}) *Value {
	arr := v.MustUint32Slice()
	collected := make([]interface{}, len(arr))
	v.EachUint32(func(index int, val uint32) bool {
		collected[index] = collector(index, val)
		return true
	})
	return &Value{data: collected}
}

/*
   Uint64 (uint64 and []uint64)
*/

// Uint64 gets the value as a uint64, returns the optionalDefault
// value or a system default object if the value is the wrong type.
func (v *Value) Uint64(optionalDefault ...uint64) uint64 {
	if s, ok := v.data.(uint64); ok {
		return s
	}
	if len(optionalDefault) == 1 {
		return optionalDefault[0]
	}
	return 0
}

// MustUint64 gets the value as a uint64.
//
// Panics if the object is not a uint64.
func (v *Value) MustUint64() uint64 {
	return v.data.(uint64)
}

// Uint64Slice gets the value as a []uint64, returns the optionalDefault
// value or nil if the value is not a []uint64.
func (v *Value) Uint64Slice(optionalDefault ...[]uint64) []uint64 {
	if s, ok := v.data.([]uint64); ok {
		return s
	}
	if len(optionalDefault) == 1 {
		return optionalDefault[0]
	}
	return nil
}

// MustUint64Slice gets the value as a []uint64.
//
// Panics if the object is not a []uint64.
func (v *Value) MustUint64Slice() []uint64 {
	return v.data.([]uint64)
}

// IsUint64 gets whether the object contained is a uint64 or not.
func (v *Value) IsUint64() bool {
	_, ok := v.data.(uint64)
	return ok
}

// IsUint64Slice gets whether the object contained is a []uint64 or not.
func (v *Value) IsUint64Slice() bool {
	_, ok := v.data.([]uint64)
	return ok
}

// EachUint64 calls the specified callback for each object
// in the []uint64.
//
// Panics if the object is the wrong type.
func (v *Value) EachUint64(callback func(int, uint64) bool) *Value {
	for index, val := range v.MustUint64Slice() {
		carryon := callback(index, val)
		if !carryon {
			break
		}
	}
	return v
}

// WhereUint64 uses the specified decider function to select items
// from the []uint64.  The object contained in the result will contain
// only the selected items.
func (v *Value) WhereUint64(decider func(int, uint64) bool) *Value {
	var selected []uint64
	v.EachUint64(func(index int, val uint64) bool {
		shouldSelect := decider(index, val)
		if !shouldSelect {
			selected = append(selected, val)
		}
		return true
	})
	return &Value{data: selected}
}

// GroupUint64 uses the specified grouper function to group the items
// keyed by the return of the grouper.  The object contained in the
// result will contain a map[string][]uint64.
func (v *Value) GroupUint64(grouper func(int, uint64) string) *Value {
	groups := make(map[string][]uint64)
	v.EachUint64(func(index int, val uint64) bool {
		group := grouper(index, val)
		if _, ok := groups[group]; !ok {
			groups[group] = make([]uint64, 0)
		}
		groups[group] = append(groups[group], val)
		return true
	})
	return &Value{data: groups}
}

// ReplaceUint64 uses the specified function to replace each uint64s
// by iterating each item.  The data in the returned result will be a
// []uint64 containing the replaced items.
func (v *Value) ReplaceUint64(replacer func(int, uint64) uint64) *Value {
	arr := v.MustUint64Slice()
	replaced := make([]uint64, len(arr))
	v.EachUint64(func(index int, val uint64) bool {
		replaced[index] = replacer(index, val)
		return true
	})
	return &Value{data: replaced}
}

// CollectUint64 uses the specified collector function to collect a value
// for each of the uint64s in the slice.  The data returned will be a
// []interface{}.
func (v *Value) CollectUint64(collector func(int, uint64) interface{}) *Value {
	arr := v.MustUint64Slice()
	collected := make([]interface{}, len(arr))
	v.EachUint64(func(index int, val uint64) bool {
		collected[index] = collector(index, val)
		return true
	})
	return &Value{data: collected}
}

/*
   Uintptr (uintptr and []uintptr)
*/

// Uintptr gets the value as a uintptr, returns the optionalDefault
// value or a system default object if the value is the wrong type.
func (v *Value) Uintptr(optionalDefault ...uintptr) uintptr {
	if s, ok := v.data.(uintptr); ok {
		return s
	}
	if len(optionalDefault) == 1 {
		return optionalDefault[0]
	}
	return 0
}

// MustUintptr gets the value as a uintptr.
//
// Panics if the object is not a uintptr.
func (v *Value) MustUintptr() uintptr {
	return v.data.(uintptr)
}

// UintptrSlice gets the value as a []uintptr, returns the optionalDefault
// value or nil if the value is not a []uintptr.
func (v *Value) UintptrSlice(optionalDefault ...[]uintptr) []uintptr {
	if s, ok := v.data.([]uintptr); ok {
		return s
	}
	if len(optionalDefault) == 1 {
		return optionalDefault[0]
	}
	return nil
}

// MustUintptrSlice gets the value as a []uintptr.
//
// Panics if the object is not a []uintptr.
func (v *Value) MustUintptrSlice() []uintptr {
	return v.data.([]uintptr)
}

// IsUintptr gets whether the object contained is a uintptr or not.
func (v *Value) IsUintptr() bool {
	_, ok := v.data.(uintptr)
	return ok
}

// IsUintptrSlice gets whether the object contained is a []uintptr or not.
func (v *Value) IsUintptrSlice() bool {
	_, ok := v.data.([]uintptr)
	return ok
}

// EachUintptr calls the specified callback for each object
// in the []uintptr.
//
// Panics if the object is the wrong type.
func (v *Value) EachUintptr(callback func(int, uintptr) bool) *Value {
	for index, val := range v.MustUintptrSlice() {
		carryon := callback(index, val)
		if !carryon {
			break
		}
	}
	return v
}

// WhereUintptr uses the specified decider function to select items
// from the []uintptr.  The object contained in the result will contain
// only the selected items.
func (v *Value) WhereUintptr(decider func(int, uintptr) bool) *Value {
	var selected []uintptr
	v.EachUintptr(func(index int, val uintptr) bool {
		shouldSelect := decider(index, val)
		if !shouldSelect {
			selected = append(selected, val)
		}
		return true
	})
	return &Value{data: selected}
}

// GroupUintptr uses the specified grouper function to group the items
// keyed by the return of the grouper.  The object contained in the
// result will contain a map[string][]uintptr.
func (v *Value) GroupUintptr(grouper func(int, uintptr) string) *Value {
	groups := make(map[string][]uintptr)
	v.EachUintptr(func(index int, val uintptr) bool {
		group := grouper(index, val)
		if _, ok := groups[group]; !ok {
			groups[group] = make([]uintptr, 0)
		}
		groups[group] = append(groups[group], val)
		return true
	})
	return &Value{data: groups}
}

// ReplaceUintptr uses the specified function to replace each uintptrs
// by iterating each item.  The data in the returned result will be a
// []uintptr containing the replaced items.
func (v *Value) ReplaceUintptr(replacer func(int, uintptr) uintptr) *Value {
	arr := v.MustUintptrSlice()
	replaced := make([]uintptr, len(arr))
	v.EachUintptr(func(index int, val uintptr) bool {
		replaced[index] = replacer(index, val)
		return true
	})
	return &Value{data: replaced}
}

// CollectUintptr uses the specified collector function to collect a value
// for each of the uintptrs in the slice.  The data returned will be a
// []interface{}.
func (v *Value) CollectUintptr(collector func(int, uintptr) interface{}) *Value {
	arr := v.MustUintptrSlice()
	collected := make([]interface{}, len(arr))
	v.EachUintptr(func(index int, val uintptr) bool {
		collected[index] = collector(index, val)
		return true
	})
	return &Value{data: collected}
}

/*
   Float32 (float32 and []float32)
*/

// Float32 gets the value as a float32, returns the optionalDefault
// value or a system default object if the value is the wrong type.
func (v *Value) Float32(optionalDefault ...float32) float32 {
	if s, ok := v.data.(float32); ok {
		return s
	}
	if len(optionalDefault) == 1 {
		return optionalDefault[0]
	}
	return 0
}

// MustFloat32 gets the value as a float32.
//
// Panics if the object is not a float32.
func (v *Value) MustFloat32() float32 {
	return v.data.(float32)
}

// Float32Slice gets the value as a []float32, returns the optionalDefault
// value or nil if the value is not a []float32.
func (v *Value) Float32Slice(optionalDefault ...[]float32) []float32 {
	if s, ok := v.data.([]float32); ok {
		return s
	}
	if len(optionalDefault) == 1 {
		return optionalDefault[0]
	}
	return nil
}

// MustFloat32Slice gets the value as a []float32.
//
// Panics if the object is not a []float32.
func (v *Value) MustFloat32Slice() []float32 {
	return v.data.([]float32)
}

// IsFloat32 gets whether the object contained is a float32 or not.
func (v *Value) IsFloat32() bool {
	_, ok := v.data.(float32)
	return ok
}

// IsFloat32Slice gets whether the object contained is a []float32 or not.
func (v *Value) IsFloat32Slice() bool {
	_, ok := v.data.([]float32)
	return ok
}

// EachFloat32 calls the specified callback for each object
// in the []float32.
//
// Panics if the object is the wrong type.
func (v *Value) EachFloat32(callback func(int, float32) bool) *Value {
	for index, val := range v.MustFloat32Slice() {
		carryon := callback(index, val)
		if !carryon {
			break
		}
	}
	return v
}

// WhereFloat32 uses the specified decider function to select items
// from the []float32.  The object contained in the result will contain
// only the selected items.
func (v *Value) WhereFloat32(decider func(int, float32) bool) *Value {
	var selected []float32
	v.EachFloat32(func(index int, val float32) bool {
		shouldSelect := decider(index, val)
		if !shouldSelect {
			selected = append(selected, val)
		}
		return true
	})
	return &Value{data: selected}
}

// GroupFloat32 uses the specified grouper function to group the items
// keyed by the return of the grouper.  The object contained in the
// result will contain a map[string][]float32.
func (v *Value) GroupFloat32(grouper func(int, float32) string) *Value {
	groups := make(map[string][]float32)
	v.EachFloat32(func(index int, val float32) bool {
		group := grouper(index, val)
		if _, ok := groups[group]; !ok {
			groups[group] = make([]float32, 0)
		}
		groups[group] = append(groups[group], val)
		return true
	})
	return &Value{data: groups}
}

// ReplaceFloat32 uses the specified function to replace each float32s
// by iterating each item.  The data in the returned result will be a
// []float32 containing the replaced items.
func (v *Value) ReplaceFloat32(replacer func(int, float32) float32) *Value {
	arr := v.MustFloat32Slice()
	replaced := make([]float32, len(arr))
	v.EachFloat32(func(index int, val float32) bool {
		replaced[index] = replacer(index, val)
		return true
	})
	return &Value{data: replaced}
}

// CollectFloat32 uses the specified collector function to collect a value
// for each of the float32s in the slice.  The data returned will be a
// []interface{}.
func (v *Value) CollectFloat32(collector func(int, float32) interface{}) *Value {
	arr := v.MustFloat32Slice()
	collected := make([]interface{}, len(arr))
	v.EachFloat32(func(index int, val float32) bool {
		collected[index] = collector(index, val)
		return true
	})
	return &Value{data: collected}
}

/*
   Float64 (float64 and []float64)
*/

// Float64 gets the value as a float64, returns the optionalDefault
// value or a system default object if the value is the wrong type.
func (v *Value) Float64(optionalDefault ...float64) float64 {
	if s, ok := v.data.(float64); ok {
		return s
	}
	if len(optionalDefault) == 1 {
		return optionalDefault[0]
	}
	return 0
}

// MustFloat64 gets the value as a float64.
//
// Panics if the object is not a float64.
func (v *Value) MustFloat64() float64 {
	return v.data.(float64)
}

// Float64Slice gets the value as a []float64, returns the optionalDefault
// value or nil if the value is not a []float64.
func (v *Value) Float64Slice(optionalDefault ...[]float64) []float64 {
	if s, ok := v.data.([]float64); ok {
		return s
	}
	if len(optionalDefault) == 1 {
		return optionalDefault[0]
	}
	return nil
}

// MustFloat64Slice gets the value as a []float64.
//
// Panics if the object is not a []float64.
func (v *Value) MustFloat64Slice() []float64 {
	return v.data.([]float64)
}

// IsFloat64 gets whether the object contained is a float64 or not.
func (v *Value) IsFloat64() bool {
	_, ok := v.data.(float64)
	return ok
}

// IsFloat64Slice gets whether the object contained is a []float64 or not.
func (v *Value) IsFloat64Slice() bool {
	_, ok := v.data.([]float64)
	return ok
}

// EachFloat64 calls the specified callback for each object
// in the []float64.
//
// Panics if the object is the wrong type.
func (v *Value) EachFloat64(callback func(int, float64) bool) *Value {
	for index, val := range v.MustFloat64Slice() {
		carryon := callback(index, val)
		if !carryon {
			break
		}
	}
	return v
}

// WhereFloat64 uses the specified decider function to select items
// from the []float64.  The object contained in the result will contain
// only the selected items.
func (v *Value) WhereFloat64(decider func(int, float64) bool) *Value {
	var selected []float64
	v.EachFloat64(func(index int, val float64) bool {
		shouldSelect := decider(index, val)
		if !shouldSelect {
			selected = append(selected, val)
		}
		return true
	})
	return &Value{data: selected}
}

// GroupFloat64 uses the specified grouper function to group the items
// keyed by the return of the grouper.  The object contained in the
// result will contain a map[string][]float64.
func (v *Value) GroupFloat64(grouper func(int, float64) string) *Value {
	groups := make(map[string][]float64)
	v.EachFloat64(func(index int, val float64) bool {
		group := grouper(index, val)
		if _, ok := groups[group]; !ok {
			groups[group] = make([]float64, 0)
		}
		groups[group] = append(groups[group], val)
		return true
	})
	return &Value{data: groups}
}

// ReplaceFloat64 uses the specified function to replace each float64s
// by iterating each item.  The data in the returned result will be a
// []float64 containing the replaced items.
func (v *Value) ReplaceFloat64(replacer func(int, float64) float64) *Value {
	arr := v.MustFloat64Slice()
	replaced := make([]float64, len(arr))
	v.EachFloat64(func(index int, val float64) bool {
		replaced[index] = replacer(index, val)
		return true
	})
	return &Value{data: replaced}
}

// CollectFloat64 uses the specified collector function to collect a value
// for each of the float64s in the slice.  The data returned will be a
// []interface{}.
func (v *Value) CollectFloat64(collector func(int, float64) interface{}) *Value {
	arr := v.MustFloat64Slice()
	collected := make([]interface{}, len(arr))
	v.EachFloat64(func(index int, val float64) bool {
		collected[index] = collector(index, val)
		return true
	})
	return &Value{data: collected}
}

/*
   Complex64 (complex64 and []complex64)
*/

// Complex64 gets the value as a complex64, returns the optionalDefault
// value or a system default object if the value is the wrong type.
func (v *Value) Complex64(optionalDefault ...complex64) complex64 {
	if s, ok := v.data.(complex64); ok {
		return s
	}
	if len(optionalDefault) == 1 {
		return optionalDefault[0]
	}
	return 0
}

// MustComplex64 gets the value as a complex64.
//
// Panics if the object is not a complex64.
func (v *Value) MustComplex64() complex64 {
	return v.data.(complex64)
}

// Complex64Slice gets the value as a []complex64, returns the optionalDefault
// value or nil if the value is not a []complex64.
func (v *Value) Complex64Slice(optionalDefault ...[]complex64) []complex64 {
	if s, ok := v.data.([]complex64); ok {
		return s
	}
	if len(optionalDefault) == 1 {
		return optionalDefault[0]
	}
	return nil
}

// MustComplex64Slice gets the value as a []complex64.
//
// Panics if the object is not a []complex64.
func (v *Value) MustComplex64Slice() []complex64 {
	return v.data.([]complex64)
}

// IsComplex64 gets whether the object contained is a complex64 or not.
func (v *Value) IsComplex64() bool {
	_, ok := v.data.(complex64)
	return ok
}

// IsComplex64Slice gets whether the object contained is a []complex64 or not.
func (v *Value) IsComplex64Slice() bool {
	_, ok := v.data.([]complex64)
	return ok
}

// EachComplex64 calls the specified callback for each object
// in the []complex64.
//
// Panics if the object is the wrong type.
func (v *Value) EachComplex64(callback func(int, complex64) bool) *Value {
	for index, val := range v.MustComplex64Slice() {
		carryon := callback(index, val)
		if !carryon {
			break
		}
	}
	return v
}

// WhereComplex64 uses the specified decider function to select items
// from the []complex64.  The object contained in the result will contain
// only the selected items.
func (v *Value) WhereComplex64(decider func(int, complex64) bool) *Value {
	var selected []complex64
	v.EachComplex64(func(index int, val complex64) bool {
		shouldSelect := decider(index, val)
		if !shouldSelect {
			selected = append(selected, val)
		}
		return true
	})
	return &Value{data: selected}
}

// GroupComplex64 uses the specified grouper function to group the items
// keyed by the return of the grouper.  The object contained in the
// result will contain a map[string][]complex64.
func (v *Value) GroupComplex64(grouper func(int, complex64) string) *Value {
	groups := make(map[string][]complex64)
	v.EachComplex64(func(index int, val complex64) bool {
		group := grouper(index, val)
		if _, ok := groups[group]; !ok {
			groups[group] = make([]complex64, 0)
		}
		groups[group] = append(groups[group], val)
		return true
	})
	return &Value{data: groups}
}

// ReplaceComplex64 uses the specified function to replace each complex64s
// by iterating each item.  The data in the returned result will be a
// []complex64 containing the replaced items.
func (v *Value) ReplaceComplex64(replacer func(int, complex64) complex64) *Value {
	arr := v.MustComplex64Slice()
	replaced := make([]complex64, len(arr))
	v.EachComplex64(func(index int, val complex64) bool {
		replaced[index] = replacer(index, val)
		return true
	})
	return &Value{data: replaced}
}

// CollectComplex64 uses the specified collector function to collect a value
// for each of the complex64s in the slice.  The data returned will be a
// []interface{}.
func (v *Value) CollectComplex64(collector func(int, complex64) interface{}) *Value {
	arr := v.MustComplex64Slice()
	collected := make([]interface{}, len(arr))
	v.EachComplex64(func(index int, val complex64) bool {
		collected[index] = collector(index, val)
		return true
	})
	return &Value{data: collected}
}

/*
   Complex128 (complex128 and []complex128)
*/

// Complex128 gets the value as a complex128, returns the optionalDefault
// value or a system default object if the value is the wrong type.
func (v *Value) Complex128(optionalDefault ...complex128) complex128 {
	if s, ok := v.data.(complex128); ok {
		return s
	}
	if len(optionalDefault) == 1 {
		return optionalDefault[0]
	}
	return 0
}

// MustComplex128 gets the value as a complex128.
//
// Panics if the object is not a complex128.
func (v *Value) MustComplex128() complex128 {
	return v.data.(complex128)
}

// Complex128Slice gets the value as a []complex128, returns the optionalDefault
// value or nil if the value is not a []complex128.
func (v *Value) Complex128Slice(optionalDefault ...[]complex128) []complex128 {
	if s, ok := v.data.([]complex128); ok {
		return s
	}
	if len(optionalDefault) == 1 {
		return optionalDefault[0]
	}
	return nil
}

// MustComplex128Slice gets the value as a []complex128.
//
// Panics if the object is not a []complex128.
func (v *Value) MustComplex128Slice() []complex128 {
	return v.data.([]complex128)
}

// IsComplex128 gets whether the object contained is a complex128 or not.
func (v *Value) IsComplex128() bool {
	_, ok := v.data.(complex128)
	return ok
}

// IsComplex128Slice gets whether the object contained is a []complex128 or not.
func (v *Value) IsComplex128Slice() bool {
	_, ok := v.data.([]complex128)
	return ok
}

// EachComplex128 calls the specified callback for each object
// in the []complex128.
//
// Panics if the object is the wrong type.
func (v *Value) EachComplex128(callback func(int, complex128) bool) *Value {
	for index, val := range v.MustComplex128Slice() {
		carryon := callback(index, val)
		if !carryon {
			break
		}
	}
	return v
}

// WhereComplex128 uses the specified decider function to select items
// from the []complex128.  The object contained in the result will contain
// only the selected items.
func (v *Value) WhereComplex128(decider func(int, complex128) bool) *Value {
	var selected []complex128
	v.EachComplex128(func(index int, val complex128) bool {
		shouldSelect := decider(index, val)
		if !shouldSelect {
			selected = append(selected, val)
		}
		return true
	})
	return &Value{data: selected}
}

// GroupComplex128 uses the specified grouper function to group the items
// keyed by the return of the grouper.  The object contained in the
// result will contain a map[string][]complex128.
func (v *Value) GroupComplex128(grouper func(int, complex128) string) *Value {
	groups := make(map[string][]complex128)
	v.EachComplex128(func(index int, val complex128) bool {
		group := grouper(index, val)
		if _, ok := groups[group]; !ok {
			groups[group] = make([]complex128, 0)
		}
		groups[group] = append(groups[group], val)
		return true
	})
	return &Value{data: groups}
}

// ReplaceComplex128 uses the specified function to replace each complex128s
// by iterating each item.  The data in the returned result will be a
// []complex128 containing the replaced items.
func (v *Value) ReplaceComplex128(replacer func(int, complex128) complex128) *Value {
	arr := v.MustComplex128Slice()
	replaced := make([]complex128, len(arr))
	v.EachComplex128(func(index int, val complex128) bool {
		replaced[index] = replacer(index, val)
		return true
	})
	return &Value{data: replaced}
}

// CollectComplex128 uses the specified collector function to collect a value
// for each of the complex128s in the slice.  The data returned will be a
// []interface{}.
func (v *Value) CollectComplex128(collector func(int, complex128) interface{}) *Value {
	arr := v.MustComplex128Slice()
	collected := make([]interface{}, len(arr))
	v.EachComplex128(func(index int, val complex128) bool {
		collected[index] = collector(index, val)
		return true
	})
	return &Value{data: collected}
}

"""




```