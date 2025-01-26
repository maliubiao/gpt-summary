Response:
Let's break down the thought process for analyzing the provided Go code.

**1. Understanding the Goal:**

The request asks for the functionality of the provided `value.go` code, its purpose within the larger context of Go logging (specifically `slog`), examples of its usage, potential pitfalls, and the Go feature it implements.

**2. Initial Scan and Keyword Spotting:**

A quick read reveals key terms like `Value`, `Kind`, `Attr`, `LogValuer`, and the various type conversions (e.g., `StringValue`, `IntValue`, `TimeValue`). The package name `slog` confirms it's related to structured logging. The comment block at the beginning is crucial for understanding the core concept of the `Value` struct – representing Go values efficiently.

**3. Deconstructing the `Value` Struct:**

This is central to understanding the code. The comments within the `Value` struct are incredibly helpful. We can immediately infer:

* **Efficiency:** The goal is to avoid allocations for small, common values.
* **`num` field:** Stores the actual value for basic types (int, uint, float, bool, duration) or the length for strings and nanoseconds for time.
* **`any` field:**  Acts as a discriminator and sometimes holds pointers for strings and groups, or the actual value for "any" type.
* **`Kind` enum:**  Defines the possible types a `Value` can hold.

**4. Analyzing `Kind`:**

The `Kind` type and its constants are straightforward. The `String()` method is a standard way to get a string representation of an enum. The unexported `kind` type is interesting – it seems like a way to internally represent the `Kind` within a `Value` without allowing direct user creation of `Value` with a `Kind`.

**5. Examining the Constructors:**

The functions like `StringValue`, `IntValue`, `TimeValue`, etc., are the ways to create `Value` instances. Observe how they populate the `num` and `any` fields based on the input type. The special handling for `time.Time` (dealing with zero time and monotonic clocks) is noteworthy. `GroupValue`'s logic for removing empty groups is a small but important detail.

**6. Investigating the Accessors:**

The `Any()`, `String()`, `Int64()`, etc., methods allow retrieval of the underlying Go value from a `Value`. Notice the type assertions and potential panics in the type-specific accessors. `String()` is designed to never panic. The `Group()` accessor reveals how groups of attributes are stored.

**7. Understanding `Equal()`:**

This method defines how to compare `Value` instances. It checks the `Kind` first and then compares the underlying data based on the `Kind`. The special handling for groups using `slices.EqualFunc` and `Attr.Equal` is important.

**8. Deciphering `isEmptyGroup()`:**

This is a utility function to quickly check if a `Value` representing a group is empty. The comment about immutability is key for understanding why a deep check isn't needed.

**9. Analyzing `append()`:**

This method is responsible for converting a `Value` into its string representation, similar to `fmt.Sprint`. It uses the standard `strconv` package for basic types.

**10. Exploring `LogValuer` and `Resolve()`:**

The `LogValuer` interface and the `Resolve()` method introduce a mechanism for deferred or dynamic value generation. The `Resolve()` method's loop and panic recovery are important for robustness. The `maxLogValues` constant suggests a safeguard against infinite recursion.

**11. Identifying the Core Go Feature:**

Based on the structure of `Value` and the goal of efficient representation of various types, the concept of **tagged unions** or **discriminated unions** comes to mind. While Go doesn't have explicit language support for tagged unions, this code implements a similar pattern using the `Kind` enum and the `any` interface.

**12. Constructing Examples and Reasoning:**

Now that we understand the individual components, we can construct examples to illustrate their usage. For instance, creating different types of `Value` and accessing their underlying values. The `LogValuer` example demonstrates deferred logging.

**13. Identifying Potential Pitfalls:**

Focus on the accessors that can panic if the `Kind` is incorrect. This is a common mistake users could make. Also, the immutability of groups is worth noting.

**14. Structuring the Answer:**

Organize the findings into logical sections: Functionality, Go Feature Implementation, Code Examples (with input/output), Command-line Arguments (none in this case), and Potential Mistakes. Use clear and concise language, especially for the explanation of the `Value` struct and the tagged union concept.

**Self-Correction/Refinement during the process:**

* **Initial thought:** Maybe `Value` is just a wrapper around `any`. **Correction:** The comments and structure reveal the optimization for small values, making it more than just a simple wrapper.
* **Initial thought:**  The `kind` type is confusing. **Correction:** It's an internal implementation detail to prevent direct user creation of `Value` with a `Kind`.
* **Initial thought:**  Focus only on the individual functions. **Correction:** Step back and understand the overall purpose and how the pieces fit together. The concept of efficient value representation and the `LogValuer` interface are crucial.

By following these steps, breaking down the code into manageable parts, and focusing on the core concepts, we can arrive at a comprehensive and accurate explanation of the `value.go` file.
这段Go语言代码是 `log/slog` 包中 `value.go` 文件的一部分，它定义了用于表示日志记录中值的 `Value` 类型及其相关功能。 它的核心目标是以一种高效的方式存储和操作各种Go类型的值，以便在结构化日志记录中使用。

以下是它的主要功能：

1. **高效地表示各种Go类型的值:**  `Value` 结构体旨在避免不必要的内存分配，特别是对于小的、常见的类型，如整数、浮点数、布尔值、短字符串和时间。它使用 `num` 字段存储这些值，并使用 `any` 字段来存储更复杂的类型或者作为类型标识符。

2. **区分不同的值类型:** `Kind` 类型是一个枚举，用于表示 `Value` 中存储的值的类型。这允许代码根据值的实际类型进行不同的处理。支持的 `Kind` 包括 `Any`, `Bool`, `Duration`, `Float64`, `Int64`, `String`, `Time`, `Uint64`, `Group` 和 `LogValuer`。

3. **提供创建不同类型 `Value` 的构造函数:**  代码提供了一系列以类型命名的构造函数，如 `StringValue`、`IntValue`、`BoolValue`、`TimeValue` 等，方便用户创建特定类型的 `Value`。

4. **提供访问 `Value` 中存储的值的方法:**  代码提供了一系列以类型命名的访问器方法，如 `Any()`、`String()`、`Int64()`、`Bool()`、`Time()` 等，用于获取 `Value` 中存储的实际Go值。需要注意的是，某些访问器（如 `Int64()`）在 `Value` 的 `Kind` 与请求的类型不匹配时会 panic。

5. **支持表示属性组 (Group):**  `GroupValue` 函数允许创建一个表示一组 `Attr` 的 `Value`。这使得可以在日志中记录嵌套的结构化数据。

6. **支持延迟求值的 `LogValuer` 接口:**  `LogValuer` 接口允许类型自定义其在日志中的表示。`Resolve()` 方法用于解析 `LogValuer`，获取其最终的 `Value`。这对于避免在日志级别不需要的情况下进行昂贵的操作非常有用。

7. **提供比较 `Value` 是否相等的方法:**  `Equal()` 方法用于比较两个 `Value` 是否表示相同的Go值。

8. **提供判断 `Value` 是否为空组的方法:** `isEmptyGroup()` 方法用于判断一个 `Value` 是否表示一个不包含任何属性的组。

9. **提供将 `Value` 转换为字符串表示的方法:** `String()` 和 `append()` 方法用于将 `Value` 转换为字符串表示，类似于 `fmt.Sprint` 的行为。

**它是什么Go语言功能的实现？**

从代码的结构和功能来看，`Value` 类型及其相关方法实现了一种**带类型标签的联合体 (Tagged Union) 或者变体类型 (Variant Type)** 的概念。

虽然 Go 语言本身没有内置的联合体类型，但 `slog.Value` 通过以下方式模拟了这种行为：

*   **`Kind` 枚举:**  作为类型标签，指示 `Value` 当前存储的数据类型。
*   **`num` 和 `any` 字段:**  共享存储空间，根据 `Kind` 的不同，`num` 或者 `any` 会被用来存储实际的值。

这种设计允许 `Value` 在不损失类型信息的情况下，以紧凑的方式存储多种类型的数据。

**Go 代码示例说明:**

```go
package main

import (
	"fmt"
	"log/slog"
	"time"
)

func main() {
	// 创建不同类型的 Value
	stringValue := slog.StringValue("hello")
	intValue := slog.IntValue(123)
	boolValue := slog.BoolValue(true)
	timeValue := slog.TimeValue(time.Now())
	durationValue := slog.DurationValue(time.Second * 5)

	// 创建一个属性组
	groupValue := slog.GroupValue(
		slog.String("name", "John"),
		slog.Int("age", 30),
	)

	// 访问 Value 中的值
	fmt.Println("String Value:", stringValue.String(), "Kind:", stringValue.Kind())
	fmt.Println("Int Value:", intValue.Int64(), "Kind:", intValue.Kind())
	fmt.Println("Bool Value:", boolValue.Bool(), "Kind:", boolValue.Kind())
	fmt.Println("Time Value:", timeValue.Time(), "Kind:", timeValue.Kind())
	fmt.Println("Duration Value:", durationValue.Duration(), "Kind:", durationValue.Kind())
	fmt.Println("Group Value:", groupValue.Group(), "Kind:", groupValue.Kind())

	// 使用 Any() 访问，需要进行类型断言
	anyValue := slog.AnyValue(3.14)
	if floatVal, ok := anyValue.Any().(float64); ok {
		fmt.Println("Any Value (float64):", floatVal, "Kind:", anyValue.Kind())
	}

	// 使用 LogValuer
	valuer := MyLogValuer{"custom value"}
	logValuerValue := slog.AnyValue(valuer)
	resolvedValue := logValuerValue.Resolve()
	fmt.Println("LogValuer Value (resolved):", resolvedValue.String(), "Kind:", resolvedValue.Kind())
}

// 自定义 LogValuer
type MyLogValuer struct {
	Value string
}

func (lv MyLogValuer) LogValue() slog.Value {
	return slog.StringValue(lv.Value)
}
```

**假设的输入与输出:**

由于代码示例中使用了 `time.Now()`，时间值会动态变化。但其他输出是可预测的。

**可能的输出:**

```
String Value: hello Kind: String
Int Value: 123 Kind: Int64
Bool Value: true Kind: Bool
Time Value: 2023-10-27 10:00:00 +0800 CST  Kind: Time  // 时间会根据实际运行时间变化
Duration Value: 5s Kind: Duration
Group Value: [{name John} {age 30}] Kind: Group
Any Value (float64): 3.14 Kind: Any
LogValuer Value (resolved): custom value Kind: String
```

**涉及命令行参数的具体处理:**

这段代码本身不涉及命令行参数的处理。命令行参数的处理通常在 `main` 函数或者专门的参数解析库中进行。`slog` 包的配置可能涉及到环境变量或程序配置，但 `value.go` 专注于值的表示。

**使用者易犯错的点:**

1. **类型断言错误:**  在使用 `Any()` 方法获取值时，如果不知道 `Value` 的实际 `Kind` 就进行类型断言，可能会导致 `panic`。应该先检查 `Kind` 或者使用类型开关 (type switch)。

    ```go
    value := slog.AnyValue(10)
    // 错误的做法，可能 panic
    intValue := value.Any().(int)

    // 正确的做法
    if value.Kind() == slog.KindInt64 {
        intValue := value.Int64()
        fmt.Println(intValue)
    } else {
        fmt.Println("Value is not an integer")
    }

    // 或者使用类型开关
    switch v := value.Any().(type) {
    case int64:
        fmt.Println("It's an int64:", v)
    default:
        fmt.Println("It's some other type")
    }
    ```

2. **在错误的 `Kind` 的 `Value` 上调用类型特定的访问器:** 例如，在一个 `Kind` 为 `String` 的 `Value` 上调用 `Int64()` 会导致 panic。

    ```go
    stringValue := slog.StringValue("abc")
    // 错误的用法，会 panic
    // intValue := stringValue.Int64()

    // 应该先检查 Kind
    if stringValue.Kind() == slog.KindInt64 {
        intValue := stringValue.Int64()
        fmt.Println(intValue)
    } else {
        fmt.Println("Value is not an integer")
    }
    ```

总而言之，`slog/value.go` 中的 `Value` 类型是 `slog` 包中表示日志记录值的核心抽象，它通过一种高效且类型安全的方式处理各种Go类型，并支持更高级的功能，如属性组和延迟求值。理解其 `Kind` 的概念和各种构造/访问方法是正确使用 `slog` 包的关键。

Prompt: 
```
这是路径为go/src/log/slog/value.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。

"""
// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package slog

import (
	"fmt"
	"math"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"time"
	"unsafe"
)

// A Value can represent any Go value, but unlike type any,
// it can represent most small values without an allocation.
// The zero Value corresponds to nil.
type Value struct {
	_ [0]func() // disallow ==
	// num holds the value for Kinds Int64, Uint64, Float64, Bool and Duration,
	// the string length for KindString, and nanoseconds since the epoch for KindTime.
	num uint64
	// If any is of type Kind, then the value is in num as described above.
	// If any is of type *time.Location, then the Kind is Time and time.Time value
	// can be constructed from the Unix nanos in num and the location (monotonic time
	// is not preserved).
	// If any is of type stringptr, then the Kind is String and the string value
	// consists of the length in num and the pointer in any.
	// Otherwise, the Kind is Any and any is the value.
	// (This implies that Attrs cannot store values of type Kind, *time.Location
	// or stringptr.)
	any any
}

type (
	stringptr *byte // used in Value.any when the Value is a string
	groupptr  *Attr // used in Value.any when the Value is a []Attr
)

// Kind is the kind of a [Value].
type Kind int

// The following list is sorted alphabetically, but it's also important that
// KindAny is 0 so that a zero Value represents nil.

const (
	KindAny Kind = iota
	KindBool
	KindDuration
	KindFloat64
	KindInt64
	KindString
	KindTime
	KindUint64
	KindGroup
	KindLogValuer
)

var kindStrings = []string{
	"Any",
	"Bool",
	"Duration",
	"Float64",
	"Int64",
	"String",
	"Time",
	"Uint64",
	"Group",
	"LogValuer",
}

func (k Kind) String() string {
	if k >= 0 && int(k) < len(kindStrings) {
		return kindStrings[k]
	}
	return "<unknown slog.Kind>"
}

// Unexported version of Kind, just so we can store Kinds in Values.
// (No user-provided value has this type.)
type kind Kind

// Kind returns v's Kind.
func (v Value) Kind() Kind {
	switch x := v.any.(type) {
	case Kind:
		return x
	case stringptr:
		return KindString
	case timeLocation, timeTime:
		return KindTime
	case groupptr:
		return KindGroup
	case LogValuer:
		return KindLogValuer
	case kind: // a kind is just a wrapper for a Kind
		return KindAny
	default:
		return KindAny
	}
}

//////////////// Constructors

// StringValue returns a new [Value] for a string.
func StringValue(value string) Value {
	return Value{num: uint64(len(value)), any: stringptr(unsafe.StringData(value))}
}

// IntValue returns a [Value] for an int.
func IntValue(v int) Value {
	return Int64Value(int64(v))
}

// Int64Value returns a [Value] for an int64.
func Int64Value(v int64) Value {
	return Value{num: uint64(v), any: KindInt64}
}

// Uint64Value returns a [Value] for a uint64.
func Uint64Value(v uint64) Value {
	return Value{num: v, any: KindUint64}
}

// Float64Value returns a [Value] for a floating-point number.
func Float64Value(v float64) Value {
	return Value{num: math.Float64bits(v), any: KindFloat64}
}

// BoolValue returns a [Value] for a bool.
func BoolValue(v bool) Value {
	u := uint64(0)
	if v {
		u = 1
	}
	return Value{num: u, any: KindBool}
}

type (
	// Unexported version of *time.Location, just so we can store *time.Locations in
	// Values. (No user-provided value has this type.)
	timeLocation *time.Location

	// timeTime is for times where UnixNano is undefined.
	timeTime time.Time
)

// TimeValue returns a [Value] for a [time.Time].
// It discards the monotonic portion.
func TimeValue(v time.Time) Value {
	if v.IsZero() {
		// UnixNano on the zero time is undefined, so represent the zero time
		// with a nil *time.Location instead. time.Time.Location method never
		// returns nil, so a Value with any == timeLocation(nil) cannot be
		// mistaken for any other Value, time.Time or otherwise.
		return Value{any: timeLocation(nil)}
	}
	nsec := v.UnixNano()
	t := time.Unix(0, nsec)
	if v.Equal(t) {
		// UnixNano correctly represents the time, so use a zero-alloc representation.
		return Value{num: uint64(nsec), any: timeLocation(v.Location())}
	}
	// Fall back to the general form.
	// Strip the monotonic portion to match the other representation.
	return Value{any: timeTime(v.Round(0))}
}

// DurationValue returns a [Value] for a [time.Duration].
func DurationValue(v time.Duration) Value {
	return Value{num: uint64(v.Nanoseconds()), any: KindDuration}
}

// GroupValue returns a new [Value] for a list of Attrs.
// The caller must not subsequently mutate the argument slice.
func GroupValue(as ...Attr) Value {
	// Remove empty groups.
	// It is simpler overall to do this at construction than
	// to check each Group recursively for emptiness.
	if n := countEmptyGroups(as); n > 0 {
		as2 := make([]Attr, 0, len(as)-n)
		for _, a := range as {
			if !a.Value.isEmptyGroup() {
				as2 = append(as2, a)
			}
		}
		as = as2
	}
	return Value{num: uint64(len(as)), any: groupptr(unsafe.SliceData(as))}
}

// countEmptyGroups returns the number of empty group values in its argument.
func countEmptyGroups(as []Attr) int {
	n := 0
	for _, a := range as {
		if a.Value.isEmptyGroup() {
			n++
		}
	}
	return n
}

// AnyValue returns a [Value] for the supplied value.
//
// If the supplied value is of type Value, it is returned
// unmodified.
//
// Given a value of one of Go's predeclared string, bool, or
// (non-complex) numeric types, AnyValue returns a Value of kind
// [KindString], [KindBool], [KindUint64], [KindInt64], or [KindFloat64].
// The width of the original numeric type is not preserved.
//
// Given a [time.Time] or [time.Duration] value, AnyValue returns a Value of kind
// [KindTime] or [KindDuration]. The monotonic time is not preserved.
//
// For nil, or values of all other types, including named types whose
// underlying type is numeric, AnyValue returns a value of kind [KindAny].
func AnyValue(v any) Value {
	switch v := v.(type) {
	case string:
		return StringValue(v)
	case int:
		return Int64Value(int64(v))
	case uint:
		return Uint64Value(uint64(v))
	case int64:
		return Int64Value(v)
	case uint64:
		return Uint64Value(v)
	case bool:
		return BoolValue(v)
	case time.Duration:
		return DurationValue(v)
	case time.Time:
		return TimeValue(v)
	case uint8:
		return Uint64Value(uint64(v))
	case uint16:
		return Uint64Value(uint64(v))
	case uint32:
		return Uint64Value(uint64(v))
	case uintptr:
		return Uint64Value(uint64(v))
	case int8:
		return Int64Value(int64(v))
	case int16:
		return Int64Value(int64(v))
	case int32:
		return Int64Value(int64(v))
	case float64:
		return Float64Value(v)
	case float32:
		return Float64Value(float64(v))
	case []Attr:
		return GroupValue(v...)
	case Kind:
		return Value{any: kind(v)}
	case Value:
		return v
	default:
		return Value{any: v}
	}
}

//////////////// Accessors

// Any returns v's value as an any.
func (v Value) Any() any {
	switch v.Kind() {
	case KindAny:
		if k, ok := v.any.(kind); ok {
			return Kind(k)
		}
		return v.any
	case KindLogValuer:
		return v.any
	case KindGroup:
		return v.group()
	case KindInt64:
		return int64(v.num)
	case KindUint64:
		return v.num
	case KindFloat64:
		return v.float()
	case KindString:
		return v.str()
	case KindBool:
		return v.bool()
	case KindDuration:
		return v.duration()
	case KindTime:
		return v.time()
	default:
		panic(fmt.Sprintf("bad kind: %s", v.Kind()))
	}
}

// String returns Value's value as a string, formatted like [fmt.Sprint]. Unlike
// the methods Int64, Float64, and so on, which panic if v is of the
// wrong kind, String never panics.
func (v Value) String() string {
	if sp, ok := v.any.(stringptr); ok {
		return unsafe.String(sp, v.num)
	}
	var buf []byte
	return string(v.append(buf))
}

func (v Value) str() string {
	return unsafe.String(v.any.(stringptr), v.num)
}

// Int64 returns v's value as an int64. It panics
// if v is not a signed integer.
func (v Value) Int64() int64 {
	if g, w := v.Kind(), KindInt64; g != w {
		panic(fmt.Sprintf("Value kind is %s, not %s", g, w))
	}
	return int64(v.num)
}

// Uint64 returns v's value as a uint64. It panics
// if v is not an unsigned integer.
func (v Value) Uint64() uint64 {
	if g, w := v.Kind(), KindUint64; g != w {
		panic(fmt.Sprintf("Value kind is %s, not %s", g, w))
	}
	return v.num
}

// Bool returns v's value as a bool. It panics
// if v is not a bool.
func (v Value) Bool() bool {
	if g, w := v.Kind(), KindBool; g != w {
		panic(fmt.Sprintf("Value kind is %s, not %s", g, w))
	}
	return v.bool()
}

func (v Value) bool() bool {
	return v.num == 1
}

// Duration returns v's value as a [time.Duration]. It panics
// if v is not a time.Duration.
func (v Value) Duration() time.Duration {
	if g, w := v.Kind(), KindDuration; g != w {
		panic(fmt.Sprintf("Value kind is %s, not %s", g, w))
	}

	return v.duration()
}

func (v Value) duration() time.Duration {
	return time.Duration(int64(v.num))
}

// Float64 returns v's value as a float64. It panics
// if v is not a float64.
func (v Value) Float64() float64 {
	if g, w := v.Kind(), KindFloat64; g != w {
		panic(fmt.Sprintf("Value kind is %s, not %s", g, w))
	}

	return v.float()
}

func (v Value) float() float64 {
	return math.Float64frombits(v.num)
}

// Time returns v's value as a [time.Time]. It panics
// if v is not a time.Time.
func (v Value) Time() time.Time {
	if g, w := v.Kind(), KindTime; g != w {
		panic(fmt.Sprintf("Value kind is %s, not %s", g, w))
	}
	return v.time()
}

// See TimeValue to understand how times are represented.
func (v Value) time() time.Time {
	switch a := v.any.(type) {
	case timeLocation:
		if a == nil {
			return time.Time{}
		}
		return time.Unix(0, int64(v.num)).In(a)
	case timeTime:
		return time.Time(a)
	default:
		panic(fmt.Sprintf("bad time type %T", v.any))
	}
}

// LogValuer returns v's value as a LogValuer. It panics
// if v is not a LogValuer.
func (v Value) LogValuer() LogValuer {
	return v.any.(LogValuer)
}

// Group returns v's value as a []Attr.
// It panics if v's [Kind] is not [KindGroup].
func (v Value) Group() []Attr {
	if sp, ok := v.any.(groupptr); ok {
		return unsafe.Slice((*Attr)(sp), v.num)
	}
	panic("Group: bad kind")
}

func (v Value) group() []Attr {
	return unsafe.Slice((*Attr)(v.any.(groupptr)), v.num)
}

//////////////// Other

// Equal reports whether v and w represent the same Go value.
func (v Value) Equal(w Value) bool {
	k1 := v.Kind()
	k2 := w.Kind()
	if k1 != k2 {
		return false
	}
	switch k1 {
	case KindInt64, KindUint64, KindBool, KindDuration:
		return v.num == w.num
	case KindString:
		return v.str() == w.str()
	case KindFloat64:
		return v.float() == w.float()
	case KindTime:
		return v.time().Equal(w.time())
	case KindAny, KindLogValuer:
		return v.any == w.any // may panic if non-comparable
	case KindGroup:
		return slices.EqualFunc(v.group(), w.group(), Attr.Equal)
	default:
		panic(fmt.Sprintf("bad kind: %s", k1))
	}
}

// isEmptyGroup reports whether v is a group that has no attributes.
func (v Value) isEmptyGroup() bool {
	if v.Kind() != KindGroup {
		return false
	}
	// We do not need to recursively examine the group's Attrs for emptiness,
	// because GroupValue removed them when the group was constructed, and
	// groups are immutable.
	return len(v.group()) == 0
}

// append appends a text representation of v to dst.
// v is formatted as with fmt.Sprint.
func (v Value) append(dst []byte) []byte {
	switch v.Kind() {
	case KindString:
		return append(dst, v.str()...)
	case KindInt64:
		return strconv.AppendInt(dst, int64(v.num), 10)
	case KindUint64:
		return strconv.AppendUint(dst, v.num, 10)
	case KindFloat64:
		return strconv.AppendFloat(dst, v.float(), 'g', -1, 64)
	case KindBool:
		return strconv.AppendBool(dst, v.bool())
	case KindDuration:
		return append(dst, v.duration().String()...)
	case KindTime:
		return append(dst, v.time().String()...)
	case KindGroup:
		return fmt.Append(dst, v.group())
	case KindAny, KindLogValuer:
		return fmt.Append(dst, v.any)
	default:
		panic(fmt.Sprintf("bad kind: %s", v.Kind()))
	}
}

// A LogValuer is any Go value that can convert itself into a Value for logging.
//
// This mechanism may be used to defer expensive operations until they are
// needed, or to expand a single value into a sequence of components.
type LogValuer interface {
	LogValue() Value
}

const maxLogValues = 100

// Resolve repeatedly calls LogValue on v while it implements [LogValuer],
// and returns the result.
// If v resolves to a group, the group's attributes' values are not recursively
// resolved.
// If the number of LogValue calls exceeds a threshold, a Value containing an
// error is returned.
// Resolve's return value is guaranteed not to be of Kind [KindLogValuer].
func (v Value) Resolve() (rv Value) {
	orig := v
	defer func() {
		if r := recover(); r != nil {
			rv = AnyValue(fmt.Errorf("LogValue panicked\n%s", stack(3, 5)))
		}
	}()

	for i := 0; i < maxLogValues; i++ {
		if v.Kind() != KindLogValuer {
			return v
		}
		v = v.LogValuer().LogValue()
	}
	err := fmt.Errorf("LogValue called too many times on Value of type %T", orig.Any())
	return AnyValue(err)
}

func stack(skip, nFrames int) string {
	pcs := make([]uintptr, nFrames+1)
	n := runtime.Callers(skip+1, pcs)
	if n == 0 {
		return "(no stack)"
	}
	frames := runtime.CallersFrames(pcs[:n])
	var b strings.Builder
	i := 0
	for {
		frame, more := frames.Next()
		fmt.Fprintf(&b, "called from %s (%s:%d)\n", frame.Function, frame.File, frame.Line)
		if !more {
			break
		}
		i++
		if i >= nFrames {
			fmt.Fprintf(&b, "(rest of stack elided)\n")
			break
		}
	}
	return b.String()
}

"""



```