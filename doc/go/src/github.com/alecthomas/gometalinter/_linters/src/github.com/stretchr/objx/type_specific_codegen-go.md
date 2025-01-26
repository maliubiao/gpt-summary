Response:
Let's break down the thought process for analyzing this Go code snippet.

1. **Understand the Context:** The path `go/src/github.com/alecthomas/gometalinter/_linters/src/github.com/stretchr/objx/type_specific_codegen.go` gives us some clues. It's within a linter (`gometalinter`), specifically related to code generation (`codegen`) for a type manipulation library (`objx` from `stretchr`). This suggests the code likely automates the creation of similar functions for different data types.

2. **Identify the Core Functionality:**  The code is organized into sections delimited by comments like `/* Inter (interface{} and []interface{}) */`, `/* Bool (bool and []bool) */`, etc. Each section contains a set of functions related to a specific Go type (e.g., `interface{}`, `bool`, `string`, `int`, etc.) and its slice counterpart.

3. **Analyze Individual Function Groups (Example: `Inter`)**:
    * **Getter Functions (`Inter`, `MustInter`):** These functions aim to retrieve the underlying data stored in a `Value` struct, casting it to the target type (`interface{}`). `Inter` provides an optional default value if the cast fails, while `MustInter` panics.
    * **Slice Getter Functions (`InterSlice`, `MustInterSlice`):** Similar to the getter functions, but specifically for slices of the target type (`[]interface{}`).
    * **Type Check Functions (`IsInter`, `IsInterSlice`):** These functions check if the stored data is of the expected type (`interface{}` or `[]interface{}`).
    * **Iteration Function (`EachInter`):** This function iterates over a slice of the target type and applies a user-provided callback function to each element. It panics if the underlying data isn't the correct slice type.
    * **Filtering Function (`WhereInter`):**  This function filters a slice of the target type based on a user-provided "decider" function, keeping only the elements for which the decider returns `true`.
    * **Grouping Function (`GroupInter`):** This function groups elements of a slice of the target type into a map, using the result of a user-provided "grouper" function as the key.
    * **Transformation Functions (`ReplaceInter`, `CollectInter`):** These functions transform the elements of a slice of the target type. `ReplaceInter` replaces each element with the result of a user-provided function, while `CollectInter` collects transformed values into a new slice.

4. **Recognize the Pattern:** Notice the striking similarity in the function signatures and logic across the different type sections (`Inter`, `Bool`, `Str`, `Int`, etc.). This strongly suggests a code generation pattern. The code is repetitive, which is a hallmark of code that could be generated.

5. **Infer the Purpose of `type_specific_codegen.go`:** Given the file name and the repetitive nature of the code, it's highly likely that this file *is the output* of a code generation process. Some other tool probably takes a list of types and generates this file, reducing manual effort and ensuring consistency.

6. **Consider Potential Issues (User Errors):**
    * **Incorrect Type Assertion with `Must...`:** Users might use `MustInter()` when they are unsure of the underlying type, leading to panics.
    * **Mismatched Callback Function Types:** When using `Each...`, `Where...`, `Group...`, `Replace...`, or `Collect...`, users need to ensure their callback functions accept the correct type for the slice elements.
    * **Nil Slices:**  Users might forget to handle cases where `...Slice` functions return `nil` if the type doesn't match.

7. **Structure the Answer:** Organize the findings into clear categories:
    * **Core Functionality:** Summarize the main purpose of the code.
    * **Go Language Feature (Inferred):** Explain the code generation aspect.
    * **Code Examples:** Provide concrete examples demonstrating the usage of key functions.
    * **Input/Output (for Code Examples):**  Clearly state the assumed input and the resulting output.
    * **Command-Line Arguments (Not Applicable):** Indicate if this aspect is relevant.
    * **Potential User Errors:** Highlight common mistakes users might make.
    * **Summary (Part 1):** Provide a concise overview of the file's functionality.

8. **Refine and Elaborate:**  Ensure the language is clear and precise. Explain the purpose of each group of functions and the implications of using `Must...` variants.

By following these steps, we can systematically analyze the provided Go code and arrive at a comprehensive understanding of its functionality and its place within the larger `objx` library. The key is to recognize patterns and infer the underlying design principles.
这段Go语言代码实现了一个名为 `Value` 的结构体的特定类型（type-specific）的操作方法。 从代码结构上看，它针对不同的Go语言内置类型（如 `interface{}`, `bool`, `string`, `int` 等及其对应的切片类型）分别实现了一组类似的功能，用于安全地获取、判断、遍历、过滤、分组、替换和收集 `Value` 结构体中存储的数据。

**功能归纳:**

这段代码的主要功能是为 `objx.Value` 结构体提供类型安全且便捷的方法来操作其内部存储的各种基本Go语言类型及其切片。具体来说，它提供了以下功能：

1. **类型安全地获取值:**  提供了 `Type()` 和 `MustType()` 两种方法来获取存储在 `Value` 中的特定类型的值。 `Type()` 方法在类型不匹配时返回默认值或系统默认值，而 `MustType()` 方法在类型不匹配时会触发 `panic`。
2. **类型判断:** 提供了 `IsType()` 方法来判断 `Value` 中存储的数据是否为指定的类型。
3. **切片遍历:** 提供了 `EachType()` 方法来遍历 `Value` 中存储的特定类型的切片，并对每个元素执行回调函数。
4. **切片过滤:** 提供了 `WhereType()` 方法来根据提供的判断函数过滤 `Value` 中存储的特定类型的切片，返回包含符合条件的元素的新 `Value`。
5. **切片分组:** 提供了 `GroupType()` 方法来根据提供的分组函数将 `Value` 中存储的特定类型的切片进行分组，返回一个包含分组结果的 `Value`，其内部数据是一个 `map[string][]Type`。
6. **切片替换:** 提供了 `ReplaceType()` 方法来遍历 `Value` 中存储的特定类型的切片，并使用提供的替换函数生成新的元素，返回包含替换后元素的新 `Value`。
7. **切片收集:** 提供了 `CollectType()` 方法来遍历 `Value` 中存储的特定类型的切片，并使用提供的收集函数将每个元素转换为另一种类型，返回包含收集到元素的新 `Value`，其内部数据是一个 `[]interface{}`。

其中 `Type` 可以是 `Inter` (对应 `interface{}`), `Bool`, `Str`, `Int`, `Int8`, `Int16`, `Int32`, `Int64`, `Uint`, `Uint8`, `Uint16`, `Uint32`, `Uint64` 等。

**Go语言功能实现推理:**

这段代码是围绕 Go 语言的 **类型断言 (Type Assertion)** 和 **反射 (Reflection)** （虽然代码中没有直接看到 `reflect` 包的使用，但其设计思想与反射有关）来实现类型安全的访问和操作。  `objx.Value` 结构体很可能内部存储的是一个 `interface{}` 类型的数据，以便能够容纳各种类型的值。  每个 `Type()` 或 `MustType()` 方法都使用了类型断言来尝试将 `interface{}` 转换为特定的类型。

**Go 代码举例说明:**

假设 `objx.Value` 结构体定义如下：

```go
package objx

type Value struct {
	data interface{}
}

func New(data interface{}) *Value {
	return &Value{data: data}
}
```

以下是一些使用示例：

```go
package main

import (
	"fmt"
	"github.com/stretchr/objx"
)

func main() {
	// 假设的输入
	data := objx.New([]interface{}{1, "hello", true, 3.14})

	// 获取 interface{} 类型的值
	interVal := data.Inter()
	fmt.Println("Inter value:", interVal) // 输出: Inter value: [1 hello true 3.14]  (因为data本身就是一个 []interface{})

	// 获取并断言为 []interface{}
	interSlice := data.InterSlice()
	fmt.Println("InterSlice value:", interSlice) // 输出: InterSlice value: [1 hello true 3.14]

	// 获取 string 类型的值，提供默认值
	strVal := data.Str("default") // 因为 data 的类型是 []interface{} 而不是 string，所以返回默认值
	fmt.Println("String value with default:", strVal) // 输出: String value with default: default

	// 尝试获取 string 切片，会返回 nil
	strSlice := data.StrSlice()
	fmt.Println("String slice value:", strSlice) // 输出: String slice value: []

	// 使用 MustStrSlice 获取 string 切片，会触发 panic
	// mustStrSlice := data.MustStrSlice() // 这行代码会 panic

	// 判断是否为 []interface{}
	isInterSlice := data.IsInterSlice()
	fmt.Println("Is inter slice:", isInterSlice) // 输出: Is inter slice: true

	// 遍历 []interface{}
	data.EachInter(func(index int, val interface{}) bool {
		fmt.Printf("Index: %d, Value: %v\n", index, val)
		return true
	})
	// 输出:
	// Index: 0, Value: 1
	// Index: 1, Value: hello
	// Index: 2, Value: true
	// Index: 3, Value: 3.14

	// 过滤 []interface{} 中为 string 的元素
	stringOnly := data.WhereInter(func(index int, val interface{}) bool {
		_, ok := val.(string)
		return ok
	})
	fmt.Println("Where Inter (string only):", stringOnly.Data()) // 输出: Where Inter (string only): [hello]  (假设 Data() 方法返回内部数据)

	// 分组 []interface{}，按类型分组
	grouped := data.GroupInter(func(index int, val interface{}) string {
		return fmt.Sprintf("%T", val)
	})
	fmt.Println("Group Inter:", grouped.Data())
	// 可能的输出: Group Inter: map[bool:[true] float64:[3.14] int:[1] string:[hello]]

	// 替换 []interface{} 中的元素，将所有元素转换为字符串
	replaced := data.ReplaceInter(func(index int, val interface{}) interface{} {
		return fmt.Sprintf("item-%d-%v", index, val)
	})
	fmt.Println("Replace Inter:", replaced.Data())
	// 输出: Replace Inter: [item-0-1 item-1-hello item-2-true item-3-3.14]

	// 收集 []interface{} 中的元素，提取字符串表示
	collected := data.CollectInter(func(index int, val interface{}) interface{} {
		return fmt.Sprintf("%v", val)
	})
	fmt.Println("Collect Inter:", collected.Data())
	// 输出: Collect Inter: [1 hello true 3.14]
}
```

**假设的输入与输出（与上述代码示例一致）**

**命令行参数的具体处理:**

这段代码本身不涉及命令行参数的处理。它是库代码，用于在 Go 程序内部操作数据。

**使用者易犯错的点:**

1. **使用 `MustType()` 方法时未确保类型匹配:** 如果使用者不确定 `Value` 中存储的数据类型，直接使用 `MustInter()`, `MustBool()`, `MustStr()` 等方法，当类型不匹配时会导致程序 `panic`。这会使程序崩溃，应该谨慎使用。

   ```go
   data := objx.New(123)
   // 错误的使用，因为 data 存储的是 int，尝试断言为 string 会 panic
   // str := data.MustStr()
   ```

2. **在 `EachType()`, `WhereType()`, `GroupType()`, `ReplaceType()`, `CollectType()` 中使用了错误的类型断言或操作:**  回调函数需要处理正确的元素类型。如果回调函数中假设了错误的类型，可能会导致类型断言失败或运行时错误。

   ```go
   data := objx.New([]int{1, 2, 3})
   // 错误的使用，EachInt 的回调函数应该接收 int 类型
   // data.EachInt(func(index int, val string) bool { // 编译错误：类型不匹配
   // 	fmt.Println(val)
   // 	return true
   // })

   data.EachInt(func(index int, val int) bool {
       fmt.Println(val)
       return true
   })
   ```

3. **忘记处理 `Type()` 方法返回的默认值:**  使用 `Inter()`, `Bool()`, `Str()` 等方法时，如果类型不匹配会返回默认值。使用者需要意识到这一点并进行相应的处理，避免使用未初始化的默认值导致逻辑错误。

   ```go
   data := objx.New(123)
   str := data.Str() // 如果 data 不是 string，str 将是空字符串 ""
   if str != "" {
       fmt.Println("String value:", str)
   } else {
       fmt.Println("Not a string")
   }
   ```

**总结 (第1部分):**

总而言之，这段代码是 `objx` 库中用于提供类型安全访问和操作 `Value` 结构体内部数据的核心组成部分。它通过为每种基本类型提供一套相似的方法，简化了从 `interface{}` 中提取和处理特定类型数据的过程，并提供了一些便捷的切片操作功能，如遍历、过滤、分组、替换和收集。 核心思想是利用 Go 的类型断言机制来实现这些功能，但使用者需要注意类型匹配，避免 `panic` 的发生。

Prompt: 
```
这是路径为go/src/github.com/alecthomas/gometalinter/_linters/src/github.com/stretchr/objx/type_specific_codegen.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第1部分，共2部分，请归纳一下它的功能

"""
package objx

/*
   Inter (interface{} and []interface{})
*/

// Inter gets the value as a interface{}, returns the optionalDefault
// value or a system default object if the value is the wrong type.
func (v *Value) Inter(optionalDefault ...interface{}) interface{} {
	if s, ok := v.data.(interface{}); ok {
		return s
	}
	if len(optionalDefault) == 1 {
		return optionalDefault[0]
	}
	return nil
}

// MustInter gets the value as a interface{}.
//
// Panics if the object is not a interface{}.
func (v *Value) MustInter() interface{} {
	return v.data.(interface{})
}

// InterSlice gets the value as a []interface{}, returns the optionalDefault
// value or nil if the value is not a []interface{}.
func (v *Value) InterSlice(optionalDefault ...[]interface{}) []interface{} {
	if s, ok := v.data.([]interface{}); ok {
		return s
	}
	if len(optionalDefault) == 1 {
		return optionalDefault[0]
	}
	return nil
}

// MustInterSlice gets the value as a []interface{}.
//
// Panics if the object is not a []interface{}.
func (v *Value) MustInterSlice() []interface{} {
	return v.data.([]interface{})
}

// IsInter gets whether the object contained is a interface{} or not.
func (v *Value) IsInter() bool {
	_, ok := v.data.(interface{})
	return ok
}

// IsInterSlice gets whether the object contained is a []interface{} or not.
func (v *Value) IsInterSlice() bool {
	_, ok := v.data.([]interface{})
	return ok
}

// EachInter calls the specified callback for each object
// in the []interface{}.
//
// Panics if the object is the wrong type.
func (v *Value) EachInter(callback func(int, interface{}) bool) *Value {
	for index, val := range v.MustInterSlice() {
		carryon := callback(index, val)
		if !carryon {
			break
		}
	}
	return v
}

// WhereInter uses the specified decider function to select items
// from the []interface{}.  The object contained in the result will contain
// only the selected items.
func (v *Value) WhereInter(decider func(int, interface{}) bool) *Value {
	var selected []interface{}
	v.EachInter(func(index int, val interface{}) bool {
		shouldSelect := decider(index, val)
		if !shouldSelect {
			selected = append(selected, val)
		}
		return true
	})
	return &Value{data: selected}
}

// GroupInter uses the specified grouper function to group the items
// keyed by the return of the grouper.  The object contained in the
// result will contain a map[string][]interface{}.
func (v *Value) GroupInter(grouper func(int, interface{}) string) *Value {
	groups := make(map[string][]interface{})
	v.EachInter(func(index int, val interface{}) bool {
		group := grouper(index, val)
		if _, ok := groups[group]; !ok {
			groups[group] = make([]interface{}, 0)
		}
		groups[group] = append(groups[group], val)
		return true
	})
	return &Value{data: groups}
}

// ReplaceInter uses the specified function to replace each interface{}s
// by iterating each item.  The data in the returned result will be a
// []interface{} containing the replaced items.
func (v *Value) ReplaceInter(replacer func(int, interface{}) interface{}) *Value {
	arr := v.MustInterSlice()
	replaced := make([]interface{}, len(arr))
	v.EachInter(func(index int, val interface{}) bool {
		replaced[index] = replacer(index, val)
		return true
	})
	return &Value{data: replaced}
}

// CollectInter uses the specified collector function to collect a value
// for each of the interface{}s in the slice.  The data returned will be a
// []interface{}.
func (v *Value) CollectInter(collector func(int, interface{}) interface{}) *Value {
	arr := v.MustInterSlice()
	collected := make([]interface{}, len(arr))
	v.EachInter(func(index int, val interface{}) bool {
		collected[index] = collector(index, val)
		return true
	})
	return &Value{data: collected}
}

/*
   Bool (bool and []bool)
*/

// Bool gets the value as a bool, returns the optionalDefault
// value or a system default object if the value is the wrong type.
func (v *Value) Bool(optionalDefault ...bool) bool {
	if s, ok := v.data.(bool); ok {
		return s
	}
	if len(optionalDefault) == 1 {
		return optionalDefault[0]
	}
	return false
}

// MustBool gets the value as a bool.
//
// Panics if the object is not a bool.
func (v *Value) MustBool() bool {
	return v.data.(bool)
}

// BoolSlice gets the value as a []bool, returns the optionalDefault
// value or nil if the value is not a []bool.
func (v *Value) BoolSlice(optionalDefault ...[]bool) []bool {
	if s, ok := v.data.([]bool); ok {
		return s
	}
	if len(optionalDefault) == 1 {
		return optionalDefault[0]
	}
	return nil
}

// MustBoolSlice gets the value as a []bool.
//
// Panics if the object is not a []bool.
func (v *Value) MustBoolSlice() []bool {
	return v.data.([]bool)
}

// IsBool gets whether the object contained is a bool or not.
func (v *Value) IsBool() bool {
	_, ok := v.data.(bool)
	return ok
}

// IsBoolSlice gets whether the object contained is a []bool or not.
func (v *Value) IsBoolSlice() bool {
	_, ok := v.data.([]bool)
	return ok
}

// EachBool calls the specified callback for each object
// in the []bool.
//
// Panics if the object is the wrong type.
func (v *Value) EachBool(callback func(int, bool) bool) *Value {
	for index, val := range v.MustBoolSlice() {
		carryon := callback(index, val)
		if !carryon {
			break
		}
	}
	return v
}

// WhereBool uses the specified decider function to select items
// from the []bool.  The object contained in the result will contain
// only the selected items.
func (v *Value) WhereBool(decider func(int, bool) bool) *Value {
	var selected []bool
	v.EachBool(func(index int, val bool) bool {
		shouldSelect := decider(index, val)
		if !shouldSelect {
			selected = append(selected, val)
		}
		return true
	})
	return &Value{data: selected}
}

// GroupBool uses the specified grouper function to group the items
// keyed by the return of the grouper.  The object contained in the
// result will contain a map[string][]bool.
func (v *Value) GroupBool(grouper func(int, bool) string) *Value {
	groups := make(map[string][]bool)
	v.EachBool(func(index int, val bool) bool {
		group := grouper(index, val)
		if _, ok := groups[group]; !ok {
			groups[group] = make([]bool, 0)
		}
		groups[group] = append(groups[group], val)
		return true
	})
	return &Value{data: groups}
}

// ReplaceBool uses the specified function to replace each bools
// by iterating each item.  The data in the returned result will be a
// []bool containing the replaced items.
func (v *Value) ReplaceBool(replacer func(int, bool) bool) *Value {
	arr := v.MustBoolSlice()
	replaced := make([]bool, len(arr))
	v.EachBool(func(index int, val bool) bool {
		replaced[index] = replacer(index, val)
		return true
	})
	return &Value{data: replaced}
}

// CollectBool uses the specified collector function to collect a value
// for each of the bools in the slice.  The data returned will be a
// []interface{}.
func (v *Value) CollectBool(collector func(int, bool) interface{}) *Value {
	arr := v.MustBoolSlice()
	collected := make([]interface{}, len(arr))
	v.EachBool(func(index int, val bool) bool {
		collected[index] = collector(index, val)
		return true
	})
	return &Value{data: collected}
}

/*
   Str (string and []string)
*/

// Str gets the value as a string, returns the optionalDefault
// value or a system default object if the value is the wrong type.
func (v *Value) Str(optionalDefault ...string) string {
	if s, ok := v.data.(string); ok {
		return s
	}
	if len(optionalDefault) == 1 {
		return optionalDefault[0]
	}
	return ""
}

// MustStr gets the value as a string.
//
// Panics if the object is not a string.
func (v *Value) MustStr() string {
	return v.data.(string)
}

// StrSlice gets the value as a []string, returns the optionalDefault
// value or nil if the value is not a []string.
func (v *Value) StrSlice(optionalDefault ...[]string) []string {
	if s, ok := v.data.([]string); ok {
		return s
	}
	if len(optionalDefault) == 1 {
		return optionalDefault[0]
	}
	return nil
}

// MustStrSlice gets the value as a []string.
//
// Panics if the object is not a []string.
func (v *Value) MustStrSlice() []string {
	return v.data.([]string)
}

// IsStr gets whether the object contained is a string or not.
func (v *Value) IsStr() bool {
	_, ok := v.data.(string)
	return ok
}

// IsStrSlice gets whether the object contained is a []string or not.
func (v *Value) IsStrSlice() bool {
	_, ok := v.data.([]string)
	return ok
}

// EachStr calls the specified callback for each object
// in the []string.
//
// Panics if the object is the wrong type.
func (v *Value) EachStr(callback func(int, string) bool) *Value {
	for index, val := range v.MustStrSlice() {
		carryon := callback(index, val)
		if !carryon {
			break
		}
	}
	return v
}

// WhereStr uses the specified decider function to select items
// from the []string.  The object contained in the result will contain
// only the selected items.
func (v *Value) WhereStr(decider func(int, string) bool) *Value {
	var selected []string
	v.EachStr(func(index int, val string) bool {
		shouldSelect := decider(index, val)
		if !shouldSelect {
			selected = append(selected, val)
		}
		return true
	})
	return &Value{data: selected}
}

// GroupStr uses the specified grouper function to group the items
// keyed by the return of the grouper.  The object contained in the
// result will contain a map[string][]string.
func (v *Value) GroupStr(grouper func(int, string) string) *Value {
	groups := make(map[string][]string)
	v.EachStr(func(index int, val string) bool {
		group := grouper(index, val)
		if _, ok := groups[group]; !ok {
			groups[group] = make([]string, 0)
		}
		groups[group] = append(groups[group], val)
		return true
	})
	return &Value{data: groups}
}

// ReplaceStr uses the specified function to replace each strings
// by iterating each item.  The data in the returned result will be a
// []string containing the replaced items.
func (v *Value) ReplaceStr(replacer func(int, string) string) *Value {
	arr := v.MustStrSlice()
	replaced := make([]string, len(arr))
	v.EachStr(func(index int, val string) bool {
		replaced[index] = replacer(index, val)
		return true
	})
	return &Value{data: replaced}
}

// CollectStr uses the specified collector function to collect a value
// for each of the strings in the slice.  The data returned will be a
// []interface{}.
func (v *Value) CollectStr(collector func(int, string) interface{}) *Value {
	arr := v.MustStrSlice()
	collected := make([]interface{}, len(arr))
	v.EachStr(func(index int, val string) bool {
		collected[index] = collector(index, val)
		return true
	})
	return &Value{data: collected}
}

/*
   Int (int and []int)
*/

// Int gets the value as a int, returns the optionalDefault
// value or a system default object if the value is the wrong type.
func (v *Value) Int(optionalDefault ...int) int {
	if s, ok := v.data.(int); ok {
		return s
	}
	if len(optionalDefault) == 1 {
		return optionalDefault[0]
	}
	return 0
}

// MustInt gets the value as a int.
//
// Panics if the object is not a int.
func (v *Value) MustInt() int {
	return v.data.(int)
}

// IntSlice gets the value as a []int, returns the optionalDefault
// value or nil if the value is not a []int.
func (v *Value) IntSlice(optionalDefault ...[]int) []int {
	if s, ok := v.data.([]int); ok {
		return s
	}
	if len(optionalDefault) == 1 {
		return optionalDefault[0]
	}
	return nil
}

// MustIntSlice gets the value as a []int.
//
// Panics if the object is not a []int.
func (v *Value) MustIntSlice() []int {
	return v.data.([]int)
}

// IsInt gets whether the object contained is a int or not.
func (v *Value) IsInt() bool {
	_, ok := v.data.(int)
	return ok
}

// IsIntSlice gets whether the object contained is a []int or not.
func (v *Value) IsIntSlice() bool {
	_, ok := v.data.([]int)
	return ok
}

// EachInt calls the specified callback for each object
// in the []int.
//
// Panics if the object is the wrong type.
func (v *Value) EachInt(callback func(int, int) bool) *Value {
	for index, val := range v.MustIntSlice() {
		carryon := callback(index, val)
		if !carryon {
			break
		}
	}
	return v
}

// WhereInt uses the specified decider function to select items
// from the []int.  The object contained in the result will contain
// only the selected items.
func (v *Value) WhereInt(decider func(int, int) bool) *Value {
	var selected []int
	v.EachInt(func(index int, val int) bool {
		shouldSelect := decider(index, val)
		if !shouldSelect {
			selected = append(selected, val)
		}
		return true
	})
	return &Value{data: selected}
}

// GroupInt uses the specified grouper function to group the items
// keyed by the return of the grouper.  The object contained in the
// result will contain a map[string][]int.
func (v *Value) GroupInt(grouper func(int, int) string) *Value {
	groups := make(map[string][]int)
	v.EachInt(func(index int, val int) bool {
		group := grouper(index, val)
		if _, ok := groups[group]; !ok {
			groups[group] = make([]int, 0)
		}
		groups[group] = append(groups[group], val)
		return true
	})
	return &Value{data: groups}
}

// ReplaceInt uses the specified function to replace each ints
// by iterating each item.  The data in the returned result will be a
// []int containing the replaced items.
func (v *Value) ReplaceInt(replacer func(int, int) int) *Value {
	arr := v.MustIntSlice()
	replaced := make([]int, len(arr))
	v.EachInt(func(index int, val int) bool {
		replaced[index] = replacer(index, val)
		return true
	})
	return &Value{data: replaced}
}

// CollectInt uses the specified collector function to collect a value
// for each of the ints in the slice.  The data returned will be a
// []interface{}.
func (v *Value) CollectInt(collector func(int, int) interface{}) *Value {
	arr := v.MustIntSlice()
	collected := make([]interface{}, len(arr))
	v.EachInt(func(index int, val int) bool {
		collected[index] = collector(index, val)
		return true
	})
	return &Value{data: collected}
}

/*
   Int8 (int8 and []int8)
*/

// Int8 gets the value as a int8, returns the optionalDefault
// value or a system default object if the value is the wrong type.
func (v *Value) Int8(optionalDefault ...int8) int8 {
	if s, ok := v.data.(int8); ok {
		return s
	}
	if len(optionalDefault) == 1 {
		return optionalDefault[0]
	}
	return 0
}

// MustInt8 gets the value as a int8.
//
// Panics if the object is not a int8.
func (v *Value) MustInt8() int8 {
	return v.data.(int8)
}

// Int8Slice gets the value as a []int8, returns the optionalDefault
// value or nil if the value is not a []int8.
func (v *Value) Int8Slice(optionalDefault ...[]int8) []int8 {
	if s, ok := v.data.([]int8); ok {
		return s
	}
	if len(optionalDefault) == 1 {
		return optionalDefault[0]
	}
	return nil
}

// MustInt8Slice gets the value as a []int8.
//
// Panics if the object is not a []int8.
func (v *Value) MustInt8Slice() []int8 {
	return v.data.([]int8)
}

// IsInt8 gets whether the object contained is a int8 or not.
func (v *Value) IsInt8() bool {
	_, ok := v.data.(int8)
	return ok
}

// IsInt8Slice gets whether the object contained is a []int8 or not.
func (v *Value) IsInt8Slice() bool {
	_, ok := v.data.([]int8)
	return ok
}

// EachInt8 calls the specified callback for each object
// in the []int8.
//
// Panics if the object is the wrong type.
func (v *Value) EachInt8(callback func(int, int8) bool) *Value {
	for index, val := range v.MustInt8Slice() {
		carryon := callback(index, val)
		if !carryon {
			break
		}
	}
	return v
}

// WhereInt8 uses the specified decider function to select items
// from the []int8.  The object contained in the result will contain
// only the selected items.
func (v *Value) WhereInt8(decider func(int, int8) bool) *Value {
	var selected []int8
	v.EachInt8(func(index int, val int8) bool {
		shouldSelect := decider(index, val)
		if !shouldSelect {
			selected = append(selected, val)
		}
		return true
	})
	return &Value{data: selected}
}

// GroupInt8 uses the specified grouper function to group the items
// keyed by the return of the grouper.  The object contained in the
// result will contain a map[string][]int8.
func (v *Value) GroupInt8(grouper func(int, int8) string) *Value {
	groups := make(map[string][]int8)
	v.EachInt8(func(index int, val int8) bool {
		group := grouper(index, val)
		if _, ok := groups[group]; !ok {
			groups[group] = make([]int8, 0)
		}
		groups[group] = append(groups[group], val)
		return true
	})
	return &Value{data: groups}
}

// ReplaceInt8 uses the specified function to replace each int8s
// by iterating each item.  The data in the returned result will be a
// []int8 containing the replaced items.
func (v *Value) ReplaceInt8(replacer func(int, int8) int8) *Value {
	arr := v.MustInt8Slice()
	replaced := make([]int8, len(arr))
	v.EachInt8(func(index int, val int8) bool {
		replaced[index] = replacer(index, val)
		return true
	})
	return &Value{data: replaced}
}

// CollectInt8 uses the specified collector function to collect a value
// for each of the int8s in the slice.  The data returned will be a
// []interface{}.
func (v *Value) CollectInt8(collector func(int, int8) interface{}) *Value {
	arr := v.MustInt8Slice()
	collected := make([]interface{}, len(arr))
	v.EachInt8(func(index int, val int8) bool {
		collected[index] = collector(index, val)
		return true
	})
	return &Value{data: collected}
}

/*
   Int16 (int16 and []int16)
*/

// Int16 gets the value as a int16, returns the optionalDefault
// value or a system default object if the value is the wrong type.
func (v *Value) Int16(optionalDefault ...int16) int16 {
	if s, ok := v.data.(int16); ok {
		return s
	}
	if len(optionalDefault) == 1 {
		return optionalDefault[0]
	}
	return 0
}

// MustInt16 gets the value as a int16.
//
// Panics if the object is not a int16.
func (v *Value) MustInt16() int16 {
	return v.data.(int16)
}

// Int16Slice gets the value as a []int16, returns the optionalDefault
// value or nil if the value is not a []int16.
func (v *Value) Int16Slice(optionalDefault ...[]int16) []int16 {
	if s, ok := v.data.([]int16); ok {
		return s
	}
	if len(optionalDefault) == 1 {
		return optionalDefault[0]
	}
	return nil
}

// MustInt16Slice gets the value as a []int16.
//
// Panics if the object is not a []int16.
func (v *Value) MustInt16Slice() []int16 {
	return v.data.([]int16)
}

// IsInt16 gets whether the object contained is a int16 or not.
func (v *Value) IsInt16() bool {
	_, ok := v.data.(int16)
	return ok
}

// IsInt16Slice gets whether the object contained is a []int16 or not.
func (v *Value) IsInt16Slice() bool {
	_, ok := v.data.([]int16)
	return ok
}

// EachInt16 calls the specified callback for each object
// in the []int16.
//
// Panics if the object is the wrong type.
func (v *Value) EachInt16(callback func(int, int16) bool) *Value {
	for index, val := range v.MustInt16Slice() {
		carryon := callback(index, val)
		if !carryon {
			break
		}
	}
	return v
}

// WhereInt16 uses the specified decider function to select items
// from the []int16.  The object contained in the result will contain
// only the selected items.
func (v *Value) WhereInt16(decider func(int, int16) bool) *Value {
	var selected []int16
	v.EachInt16(func(index int, val int16) bool {
		shouldSelect := decider(index, val)
		if !shouldSelect {
			selected = append(selected, val)
		}
		return true
	})
	return &Value{data: selected}
}

// GroupInt16 uses the specified grouper function to group the items
// keyed by the return of the grouper.  The object contained in the
// result will contain a map[string][]int16.
func (v *Value) GroupInt16(grouper func(int, int16) string) *Value {
	groups := make(map[string][]int16)
	v.EachInt16(func(index int, val int16) bool {
		group := grouper(index, val)
		if _, ok := groups[group]; !ok {
			groups[group] = make([]int16, 0)
		}
		groups[group] = append(groups[group], val)
		return true
	})
	return &Value{data: groups}
}

// ReplaceInt16 uses the specified function to replace each int16s
// by iterating each item.  The data in the returned result will be a
// []int16 containing the replaced items.
func (v *Value) ReplaceInt16(replacer func(int, int16) int16) *Value {
	arr := v.MustInt16Slice()
	replaced := make([]int16, len(arr))
	v.EachInt16(func(index int, val int16) bool {
		replaced[index] = replacer(index, val)
		return true
	})
	return &Value{data: replaced}
}

// CollectInt16 uses the specified collector function to collect a value
// for each of the int16s in the slice.  The data returned will be a
// []interface{}.
func (v *Value) CollectInt16(collector func(int, int16) interface{}) *Value {
	arr := v.MustInt16Slice()
	collected := make([]interface{}, len(arr))
	v.EachInt16(func(index int, val int16) bool {
		collected[index] = collector(index, val)
		return true
	})
	return &Value{data: collected}
}

/*
   Int32 (int32 and []int32)
*/

// Int32 gets the value as a int32, returns the optionalDefault
// value or a system default object if the value is the wrong type.
func (v *Value) Int32(optionalDefault ...int32) int32 {
	if s, ok := v.data.(int32); ok {
		return s
	}
	if len(optionalDefault) == 1 {
		return optionalDefault[0]
	}
	return 0
}

// MustInt32 gets the value as a int32.
//
// Panics if the object is not a int32.
func (v *Value) MustInt32() int32 {
	return v.data.(int32)
}

// Int32Slice gets the value as a []int32, returns the optionalDefault
// value or nil if the value is not a []int32.
func (v *Value) Int32Slice(optionalDefault ...[]int32) []int32 {
	if s, ok := v.data.([]int32); ok {
		return s
	}
	if len(optionalDefault) == 1 {
		return optionalDefault[0]
	}
	return nil
}

// MustInt32Slice gets the value as a []int32.
//
// Panics if the object is not a []int32.
func (v *Value) MustInt32Slice() []int32 {
	return v.data.([]int32)
}

// IsInt32 gets whether the object contained is a int32 or not.
func (v *Value) IsInt32() bool {
	_, ok := v.data.(int32)
	return ok
}

// IsInt32Slice gets whether the object contained is a []int32 or not.
func (v *Value) IsInt32Slice() bool {
	_, ok := v.data.([]int32)
	return ok
}

// EachInt32 calls the specified callback for each object
// in the []int32.
//
// Panics if the object is the wrong type.
func (v *Value) EachInt32(callback func(int, int32) bool) *Value {
	for index, val := range v.MustInt32Slice() {
		carryon := callback(index, val)
		if !carryon {
			break
		}
	}
	return v
}

// WhereInt32 uses the specified decider function to select items
// from the []int32.  The object contained in the result will contain
// only the selected items.
func (v *Value) WhereInt32(decider func(int, int32) bool) *Value {
	var selected []int32
	v.EachInt32(func(index int, val int32) bool {
		shouldSelect := decider(index, val)
		if !shouldSelect {
			selected = append(selected, val)
		}
		return true
	})
	return &Value{data: selected}
}

// GroupInt32 uses the specified grouper function to group the items
// keyed by the return of the grouper.  The object contained in the
// result will contain a map[string][]int32.
func (v *Value) GroupInt32(grouper func(int, int32) string) *Value {
	groups := make(map[string][]int32)
	v.EachInt32(func(index int, val int32) bool {
		group := grouper(index, val)
		if _, ok := groups[group]; !ok {
			groups[group] = make([]int32, 0)
		}
		groups[group] = append(groups[group], val)
		return true
	})
	return &Value{data: groups}
}

// ReplaceInt32 uses the specified function to replace each int32s
// by iterating each item.  The data in the returned result will be a
// []int32 containing the replaced items.
func (v *Value) ReplaceInt32(replacer func(int, int32) int32) *Value {
	arr := v.MustInt32Slice()
	replaced := make([]int32, len(arr))
	v.EachInt32(func(index int, val int32) bool {
		replaced[index] = replacer(index, val)
		return true
	})
	return &Value{data: replaced}
}

// CollectInt32 uses the specified collector function to collect a value
// for each of the int32s in the slice.  The data returned will be a
// []interface{}.
func (v *Value) CollectInt32(collector func(int, int32) interface{}) *Value {
	arr := v.MustInt32Slice()
	collected := make([]interface{}, len(arr))
	v.EachInt32(func(index int, val int32) bool {
		collected[index] = collector(index, val)
		return true
	})
	return &Value{data: collected}
}

/*
   Int64 (int64 and []int64)
*/

// Int64 gets the value as a int64, returns the optionalDefault
// value or a system default object if the value is the wrong type.
func (v *Value) Int64(optionalDefault ...int64) int64 {
	if s, ok := v.data.(int64); ok {
		return s
	}
	if len(optionalDefault) == 1 {
		return optionalDefault[0]
	}
	return 0
}

// MustInt64 gets the value as a int64.
//
// Panics if the object is not a int64.
func (v *Value) MustInt64() int64 {
	return v.data.(int64)
}

// Int64Slice gets the value as a []int64, returns the optionalDefault
// value or nil if the value is not a []int64.
func (v *Value) Int64Slice(optionalDefault ...[]int64) []int64 {
	if s, ok := v.data.([]int64); ok {
		return s
	}
	if len(optionalDefault) == 1 {
		return optionalDefault[0]
	}
	return nil
}

// MustInt64Slice gets the value as a []int64.
//
// Panics if the object is not a []int64.
func (v *Value) MustInt64Slice() []int64 {
	return v.data.([]int64)
}

// IsInt64 gets whether the object contained is a int64 or not.
func (v *Value) IsInt64() bool {
	_, ok := v.data.(int64)
	return ok
}

// IsInt64Slice gets whether the object contained is a []int64 or not.
func (v *Value) IsInt64Slice() bool {
	_, ok := v.data.([]int64)
	return ok
}

// EachInt64 calls the specified callback for each object
// in the []int64.
//
// Panics if the object is the wrong type.
func (v *Value) EachInt64(callback func(int, int64) bool) *Value {
	for index, val := range v.MustInt64Slice() {
		carryon := callback(index, val)
		if !carryon {
			break
		}
	}
	return v
}

// WhereInt64 uses the specified decider function to select items
// from the []int64.  The object contained in the result will contain
// only the selected items.
func (v *Value) WhereInt64(decider func(int, int64) bool) *Value {
	var selected []int64
	v.EachInt64(func(index int, val int64) bool {
		shouldSelect := decider(index, val)
		if !shouldSelect {
			selected = append(selected, val)
		}
		return true
	})
	return &Value{data: selected}
}

// GroupInt64 uses the specified grouper function to group the items
// keyed by the return of the grouper.  The object contained in the
// result will contain a map[string][]int64.
func (v *Value) GroupInt64(grouper func(int, int64) string) *Value {
	groups := make(map[string][]int64)
	v.EachInt64(func(index int, val int64) bool {
		group := grouper(index, val)
		if _, ok := groups[group]; !ok {
			groups[group] = make([]int64, 0)
		}
		groups[group] = append(groups[group], val)
		return true
	})
	return &Value{data: groups}
}

// ReplaceInt64 uses the specified function to replace each int64s
// by iterating each item.  The data in the returned result will be a
// []int64 containing the replaced items.
func (v *Value) ReplaceInt64(replacer func(int, int64) int64) *Value {
	arr := v.MustInt64Slice()
	replaced := make([]int64, len(arr))
	v.EachInt64(func(index int, val int64) bool {
		replaced[index] = replacer(index, val)
		return true
	})
	return &Value{data: replaced}
}

// CollectInt64 uses the specified collector function to collect a value
// for each of the int64s in the slice.  The data returned will be a
// []interface{}.
func (v *Value) CollectInt64(collector func(int, int64) interface{}) *Value {
	arr := v.MustInt64Slice()
	collected := make([]interface{}, len(arr))
	v.EachInt64(func(index int, val int64) bool {
		collected[index] = collector(index, val)
		return true
	})
	return &Value{data: collected}
}

/*
   Uint (uint and []uint)
*/

// Uint gets the value as a uint, returns the optionalDefault
// value or a system default object if the value is the wrong type.
func (v *Value) Uint(optionalDefault ...uint) uint {
	if s, ok := v.data.(uint); ok {
		return s
	}
	if len(optionalDefault) == 1 {
		return optionalDefault[0]
	}
	return 0
}

// MustUint gets the value as a uint.
//
// Panics if the object is not a uint.
func (v *Value) MustUint() uint {
	return v.data.(uint)
}

// UintSlice gets the value as a []uint, returns the optionalDefault
// value or nil if the value is not a []uint.
func (v *Value) UintSlice(optionalDefault ...[]uint) []uint {
	if s, ok := v.data.([]uint); ok {
		return s
	}
	if len(optionalDefault) == 1 {
		return optionalDefault[0]
	}
	return nil
}

// MustUintSlice gets the value as a []uint.
//
// Panics if the object is not a []uint.
func (v *Value) MustUintSlice() []uint {
	return v.data.([]uint)
}

// IsUint gets whether the object contained is a uint or not.
func (v *Value) IsUint() bool {
	_, ok := v.data.(uint)
	return ok
}

// IsUintSlice gets whether the object contained is a []uint or not.
func (v *Value) IsUintSlice() bool {
	_, ok := v.data.([]uint)
	return ok
}

// EachUint calls the specified callback for each object
// in the []uint.
//
// Panics if the object is the wrong type.
func (v *Value) EachUint(callback func(int, uint) bool) *Value {
	for index, val := range v.MustUintSlice() {
		carryon := callback(index, val)
		if !carryon {
			break
		}
	}
	return v
}

// WhereUint uses the specified decider function to select items
// from the []uint.  The object contained in the result will contain
// only the selected items.
func (v *Value) WhereUint(decider func(int, uint) bool) *Value {
	var selected []uint
	v.EachUint(func(index int, val uint) bool {
		shouldSelect := decider(index, val)
		if !shouldSelect {
			selected = append(selected, val)
		}
		return true
	})
	return &Value{data: selected}
}

// GroupUint uses the specified grouper function to group the items
// keyed by the return of the grouper.  The object contained in the
// result will contain a map[string][]uint.
func (v *Value) GroupUint(grouper func(int, uint) string) *Value {
	groups := make(map[string][]uint)
	v.EachUint(func(index int, val uint) bool {
		group := grouper(index, val)
		if _, ok := groups[group]; !ok {
			groups[group] = make([]uint, 0)
		}
		groups[group] = append(groups[group], val)
		return true
	})
	return &Value{data: groups}
}

// ReplaceUint uses the specified function to replace each uints
// by iterating each item.  The data in the returned result will be a
// []uint containing the replaced items.
func (v *Value) ReplaceUint(replacer func(int, uint) uint) *Value {
	arr := v.MustUintSlice()
	replaced := make([]uint, len(arr))
	v.EachUint(func(index int, val uint) bool {
		replaced[index] = replacer(index, val)
		return true
	})
	return &Value{data: replaced}
}

// CollectUint uses the specified collector function to collect a value
// for each of the uints in the slice.  The data returned will be a
// []interface{}.
func (v *Value) CollectUint(collector func(int, uint) interface{}) *Value {
	arr := v.MustUintSlice()
	collected := make([]interface{}, len(arr))
	v.EachUint(func(index int, val uint) bool {
		collected[index] = collector(index, val)
		return true
	})
	return &Value{data: collected}
}

/*
   Uint8 (uint8 and []uint8)
*/

// Uint8 gets the value as a uint8, returns the optionalDefault
// value or a system default object if the value is the wrong type.
func (v *Value) Uint8(optionalDefault ...uint8) uint8 {
	if s, ok := v.data.(uint8); ok {
		return s
	}
	if len(optionalDefault) == 1 {
		return optionalDefault[0]
	}
	return 0
}

// MustUint8 gets the value as a uint8.
//
// Panics if the object is not a uint8.
func (v *Value) MustUint8() uint8 {
	return v.data.(uint8)
}

// Uint8Slice gets the value as a []uint8, returns the optionalDefault
// value or nil if the value is not a []uint8.
func (v *Value) Uint8Slice(optionalDefault ...[]uint8) []uint8 {
	if s, ok := v.data.([]uint8); ok {
		return s
	}
	if len(optionalDefault) == 1 {
		return optionalDefault[0]
	}
	return nil
}

// MustUint8Slice gets the value as a []uint8.
//
// Panics if the object is not a []uint8.
func (v *Value) MustUint8Slice() []uint8 {
	return v.data.([]uint8)
}

// IsUint8 gets whether the object contained is a uint8 or not.
func (v *Value) IsUint8() bool {
	_, ok := v.data.(uint8)
	return ok
}

// IsUint8Slice gets whether the object contained is a []uint8 or not.
func (v *Value) IsUint8Slice() bool {
	_, ok := v.data.([]uint8)
	return ok
}

// EachUint8 calls the specified callback for each object
// in the []uint8.
//
// Panics if the object is the wrong type.
func (v *Value) EachUint8(callback func(int, uint8) bool) *Value {
	for index, val := range v.MustUint8Slice() {
		carryon := callback(index, val)
		if !carryon {
			break
		}
	}
	return v
}

// WhereUint8 uses the specified decider function to select items
// from the []uint8.  The object contained in the result will contain
// only the selected items.
"""




```