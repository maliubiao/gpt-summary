Response:
Let's break down the thought process for analyzing the `funcs.go` file.

1. **Identify the Core Purpose:** The filename `funcs.go` and the package declaration `package template` immediately suggest this file is about functions used within Go templates. The initial comments confirm this.

2. **Analyze the `FuncMap` Type:**  The definition of `FuncMap` as `map[string]any` is crucial. This tells us:
    * It's a map.
    * Keys are strings (function names).
    * Values are `any` (meaning they can be any type, but based on the comments, they *should* be functions).
    * The comments about return values (single or two with error) are important constraints.

3. **Examine `builtins()`:** This function is clearly defining a set of default functions available in templates. List them out and try to understand their purpose from the names:
    * `and`, `call`, `html`, `index`, `slice`, `js`, `len`, `not`, `or`, `print`, `printf`, `println`, `urlquery`, `eq`, `ge`, `gt`, `le`, `lt`, `ne`.

4. **Infer Functionality Based on Names:**  Even without detailed code, many function names are self-explanatory:
    * **Logical:** `and`, `or`, `not`
    * **Comparison:** `eq`, `ge`, `gt`, `le`, `lt`, `ne`
    * **String/Data Manipulation:** `len`, `index`, `slice`, `print`, `printf`, `println`, `urlquery`
    * **Escaping:** `html`, `js`
    * **Special:** `call` (suggests calling functions within the template).

5. **Connect `builtins()` to `builtinFuncs()`:** The `builtinFuncsOnce` and `builtinFuncs()` pattern is a standard Go idiom for lazy initialization and thread safety. It converts the `FuncMap` to a `map[string]reflect.Value`. This signals that the template engine uses reflection to invoke these functions.

6. **Understand `createValueFuncs()` and `addValueFuncs()`:** These functions clarify the conversion process from `FuncMap` to the reflection-based map. The error checking in `addValueFuncs()` (`goodName`, checking for `reflect.Func`, and `goodFunc`) is vital for ensuring valid function definitions.

7. **Analyze Helper Functions:**  Functions like `goodFunc`, `goodName`, `findFunction`, and `prepareArg` are utilities that support the core functionality. Focus on what checks they perform (valid names, correct function signatures, argument type compatibility).

8. **Deep Dive into Specific Functions (with example generation in mind):**
    * **`index`:**  Clearly for accessing elements in slices, arrays, maps, and strings. Think about different data types and indexing scenarios for examples.
    * **`slice`:** For taking slices of strings, arrays, and slices. Consider the different ways `slice` can be used (one, two, or three arguments).
    * **`len`:**  Straightforward – getting the length. Think of the supported types.
    * **`call`:**  The most complex. It involves reflection and handling function arguments. Focus on how arguments are prepared and the handling of errors. The `safeCall` function highlights error handling via `recover`.
    * **Boolean Logic (`and`, `or`, `not`):**  Standard logical operations.
    * **Comparison (`eq`, `ne`, `lt`, `le`, `gt`, `ge`):**  Think about the types that can be compared and potential edge cases (nil comparisons, mixed signed/unsigned integers).
    * **Escaping (`HTMLEscape`, `JSEscape`, `URLQueryEscaper`):**  Understand *what* characters are being escaped for each type and *why*.

9. **Consider Potential Errors (User Mistakes):**  Think about common mistakes when using templates:
    * Incorrect number of arguments to functions.
    * Passing arguments of the wrong type.
    * Trying to index or slice with out-of-bounds values.
    * Misunderstanding the behavior of logical operators.
    * Not escaping data properly when generating HTML or JavaScript.

10. **Structure the Answer:** Organize the findings logically:
    * **Overall Function:** Start with a high-level summary.
    * **Key Components:** Describe the main data structures (`FuncMap`) and functions (`builtins`, `builtinFuncs`).
    * **Detailed Functionality:**  Explain individual functions with examples (code and input/output).
    * **Command-Line Arguments (if applicable):**  In this case, the file doesn't directly handle command-line arguments, so mention this.
    * **Common Mistakes:**  List potential pitfalls for users.

11. **Refine and Review:**  Read through the answer to ensure clarity, accuracy, and completeness. Make sure the examples are correct and easy to understand. Check for any missing information or areas that could be explained better.

This methodical approach, moving from the general to the specific and constantly thinking about how the code is used, helps in thoroughly analyzing and understanding the functionality of a Go source file. The emphasis on generating examples as part of the analysis is crucial for illustrating the behavior of different functions.
这是一个Go语言模板引擎 (`text/template`) 的核心组成部分，专门负责**管理和提供可以在模板中调用的内置函数**。

**主要功能:**

1. **定义函数映射 (FuncMap):**
   - `FuncMap` 类型是一个 `map[string]any`，它定义了从函数名（字符串）到实际 Go 函数的映射。
   - 模板引擎在执行模板时，遇到函数调用（例如 `{{ .Name | html }}` 中的 `html`），会查找 `FuncMap` 中对应的 Go 函数并执行。
   - `FuncMap` 允许用户自定义函数，扩展模板引擎的功能。

2. **提供内置函数:**
   - `builtins()` 函数返回一个 `FuncMap`，包含了模板引擎预先定义好的一系列常用函数。
   - 这些内置函数涵盖了各种操作，例如：
     - **逻辑运算:** `and`, `or`, `not`
     - **比较运算:** `eq` (等于), `ne` (不等于), `lt` (小于), `le` (小于等于), `gt` (大于), `ge` (大于等于)
     - **字符串操作和输出:** `print`, `printf`, `println`
     - **长度计算:** `len`
     - **索引和切片操作:** `index`, `slice`
     - **类型转换和调用:** `call` (用于调用模板外部的函数)
     - **HTML 和 JavaScript 转义:** `html`, `js`
     - **URL 查询参数转义:** `urlquery`

3. **安全地注册和管理函数:**
   - `createValueFuncs` 和 `addValueFuncs` 函数用于将 `FuncMap` 转换为 `map[string]reflect.Value`。 `reflect.Value` 是 Go 反射包中的类型，允许动态调用函数。
   - `addValueFuncs` 会检查函数名的合法性 (`goodName`) 和函数签名的正确性 (`goodFunc`)，确保注册的函数符合模板引擎的要求（返回单个值或两个值，第二个是 `error`）。
   - `addFuncs` 用于向已有的 `FuncMap` 中添加新的函数。

4. **查找函数:**
   - `findFunction` 函数负责在模板自身的函数映射和全局内置函数映射中查找指定名称的函数。

5. **处理函数参数:**
   - `prepareArg` 函数用于检查传递给函数的参数是否与函数期望的参数类型兼容，并在必要时进行类型转换。

6. **安全调用函数:**
   - `call` 函数使用反射来调用模板中指定的函数。
   - `safeCall` 函数在 `call` 的基础上增加了 `recover` 机制，捕获函数执行过程中可能发生的 `panic`，并将其转换为 `error` 返回，保证模板引擎的稳定性。

7. **实现内置函数的具体逻辑:**
   - 文件中包含了各个内置函数的具体 Go 代码实现，例如 `index` 函数如何进行索引操作，`html` 函数如何进行 HTML 转义等等。

**它是什么Go语言功能的实现？**

这个文件是 Go 语言 `text/template` 包中实现**模板函数功能**的核心部分。模板函数允许在模板中执行 Go 代码，从而实现动态内容的生成和处理。

**Go代码示例:**

假设我们想在模板中使用一个自定义的函数 `ToUpper`，将字符串转换为大写。

```go
package main

import (
	"fmt"
	"strings"
	"text/template"
)

// 自定义函数
func ToUpper(s string) string {
	return strings.ToUpper(s)
}

func main() {
	tmplStr := `{{ .Name | ToUpper }}`

	// 创建包含自定义函数的 FuncMap
	funcMap := template.FuncMap{
		"ToUpper": ToUpper,
	}

	// 创建模板并解析
	tmpl, err := template.New("example").Funcs(funcMap).Parse(tmplStr)
	if err != nil {
		panic(err)
	}

	data := struct {
		Name string
	}{
		Name: "hello",
	}

	// 执行模板
	err = tmpl.Execute(nil, data)
	if err != nil {
		panic(err)
	}
}
```

**假设的输入与输出:**

- **模板字符串 (`tmplStr`):** `{{ .Name | ToUpper }}`
- **输入数据 (`data`):** `struct { Name string }{ Name: "hello" }`
- **输出:** `HELLO`

**代码推理:**

1. `template.New("example").Funcs(funcMap)` 创建一个新的模板，并将我们定义的 `funcMap` 注册到模板中。
2. `template.Parse(tmplStr)` 解析模板字符串。
3. 在执行模板时，遇到 `{{ .Name | ToUpper }}`：
   - `.Name` 获取数据中的 `Name` 字段，值为 `"hello"`。
   - `| ToUpper` 将 `"hello"` 作为参数传递给 `FuncMap` 中名为 `"ToUpper"` 的函数，即我们定义的 `ToUpper` 函数。
   - `ToUpper("hello")` 返回 `"HELLO"`。
4. 模板引擎将 `"HELLO"` 输出。

**命令行参数的具体处理:**

这个 `funcs.go` 文件本身并不直接处理命令行参数。命令行参数的处理通常发生在调用模板引擎的程序中，例如使用 `flag` 包解析命令行参数，并将解析后的数据传递给模板进行渲染。

**使用者易犯错的点:**

1. **函数签名不正确:**  定义自定义函数时，如果函数的返回值不是单个值，或者不是两个值且第二个值不是 `error` 类型，注册时会发生 `panic`。

   ```go
   // 错误示例：返回三个值
   func WrongFunc(s string) (string, int, error) {
       return "", 0, nil
   }

   func main() {
       funcMap := template.FuncMap{"WrongFunc": WrongFunc}
       // ... 创建模板并注册 funcMap 会导致 panic
   }
   ```

2. **传递给函数的参数类型不匹配:** 模板在执行函数时，如果传递的参数类型与函数定义的参数类型不兼容，会导致运行时错误。

   ```go
   // 假设有函数：
   func Add(a int, b int) int {
       return a + b
   }

   func main() {
       tmplStr := `{{ Add "1" 2 }}` // 错误：第一个参数是字符串
       funcMap := template.FuncMap{"Add": Add}
       // ... 执行模板会导致错误
   }
   ```

3. **在 `if` 等控制结构中使用返回值不是 `bool` 类型的函数:**  模板的 `if` 等控制结构要求条件表达式返回布尔值。如果调用返回非布尔值的函数作为条件，会导致错误。

   ```go
   // 假设有函数：
   func StringLength(s string) int {
       return len(s)
   }

   func main() {
       tmplStr := `{{ if StringLength .Name }}...{{ end }}` // 错误：StringLength 返回 int
       funcMap := template.FuncMap{"StringLength": StringLength}
       // ... 执行模板会导致错误
   }
   ```

总而言之，`go/src/text/template/funcs.go` 文件是 Go 语言模板引擎的核心，它定义了模板函数机制，提供了丰富的内置函数，并负责安全地管理和调用这些函数，使得用户能够在模板中进行复杂的逻辑处理和数据操作。

Prompt: 
```
这是路径为go/src/text/template/funcs.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。

"""
// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package template

import (
	"errors"
	"fmt"
	"io"
	"net/url"
	"reflect"
	"strings"
	"sync"
	"unicode"
	"unicode/utf8"
)

// FuncMap is the type of the map defining the mapping from names to functions.
// Each function must have either a single return value, or two return values of
// which the second has type error. In that case, if the second (error)
// return value evaluates to non-nil during execution, execution terminates and
// Execute returns that error.
//
// Errors returned by Execute wrap the underlying error; call [errors.As] to
// unwrap them.
//
// When template execution invokes a function with an argument list, that list
// must be assignable to the function's parameter types. Functions meant to
// apply to arguments of arbitrary type can use parameters of type interface{} or
// of type [reflect.Value]. Similarly, functions meant to return a result of arbitrary
// type can return interface{} or [reflect.Value].
type FuncMap map[string]any

// builtins returns the FuncMap.
// It is not a global variable so the linker can dead code eliminate
// more when this isn't called. See golang.org/issue/36021.
// TODO: revert this back to a global map once golang.org/issue/2559 is fixed.
func builtins() FuncMap {
	return FuncMap{
		"and":      and,
		"call":     emptyCall,
		"html":     HTMLEscaper,
		"index":    index,
		"slice":    slice,
		"js":       JSEscaper,
		"len":      length,
		"not":      not,
		"or":       or,
		"print":    fmt.Sprint,
		"printf":   fmt.Sprintf,
		"println":  fmt.Sprintln,
		"urlquery": URLQueryEscaper,

		// Comparisons
		"eq": eq, // ==
		"ge": ge, // >=
		"gt": gt, // >
		"le": le, // <=
		"lt": lt, // <
		"ne": ne, // !=
	}
}

var builtinFuncsOnce struct {
	sync.Once
	v map[string]reflect.Value
}

// builtinFuncsOnce lazily computes & caches the builtinFuncs map.
// TODO: revert this back to a global map once golang.org/issue/2559 is fixed.
func builtinFuncs() map[string]reflect.Value {
	builtinFuncsOnce.Do(func() {
		builtinFuncsOnce.v = createValueFuncs(builtins())
	})
	return builtinFuncsOnce.v
}

// createValueFuncs turns a FuncMap into a map[string]reflect.Value
func createValueFuncs(funcMap FuncMap) map[string]reflect.Value {
	m := make(map[string]reflect.Value)
	addValueFuncs(m, funcMap)
	return m
}

// addValueFuncs adds to values the functions in funcs, converting them to reflect.Values.
func addValueFuncs(out map[string]reflect.Value, in FuncMap) {
	for name, fn := range in {
		if !goodName(name) {
			panic(fmt.Errorf("function name %q is not a valid identifier", name))
		}
		v := reflect.ValueOf(fn)
		if v.Kind() != reflect.Func {
			panic("value for " + name + " not a function")
		}
		if err := goodFunc(name, v.Type()); err != nil {
			panic(err)
		}
		out[name] = v
	}
}

// addFuncs adds to values the functions in funcs. It does no checking of the input -
// call addValueFuncs first.
func addFuncs(out, in FuncMap) {
	for name, fn := range in {
		out[name] = fn
	}
}

// goodFunc reports whether the function or method has the right result signature.
func goodFunc(name string, typ reflect.Type) error {
	// We allow functions with 1 result or 2 results where the second is an error.
	switch numOut := typ.NumOut(); {
	case numOut == 1:
		return nil
	case numOut == 2 && typ.Out(1) == errorType:
		return nil
	case numOut == 2:
		return fmt.Errorf("invalid function signature for %s: second return value should be error; is %s", name, typ.Out(1))
	default:
		return fmt.Errorf("function %s has %d return values; should be 1 or 2", name, typ.NumOut())
	}
}

// goodName reports whether the function name is a valid identifier.
func goodName(name string) bool {
	if name == "" {
		return false
	}
	for i, r := range name {
		switch {
		case r == '_':
		case i == 0 && !unicode.IsLetter(r):
			return false
		case !unicode.IsLetter(r) && !unicode.IsDigit(r):
			return false
		}
	}
	return true
}

// findFunction looks for a function in the template, and global map.
func findFunction(name string, tmpl *Template) (v reflect.Value, isBuiltin, ok bool) {
	if tmpl != nil && tmpl.common != nil {
		tmpl.muFuncs.RLock()
		defer tmpl.muFuncs.RUnlock()
		if fn := tmpl.execFuncs[name]; fn.IsValid() {
			return fn, false, true
		}
	}
	if fn := builtinFuncs()[name]; fn.IsValid() {
		return fn, true, true
	}
	return reflect.Value{}, false, false
}

// prepareArg checks if value can be used as an argument of type argType, and
// converts an invalid value to appropriate zero if possible.
func prepareArg(value reflect.Value, argType reflect.Type) (reflect.Value, error) {
	if !value.IsValid() {
		if !canBeNil(argType) {
			return reflect.Value{}, fmt.Errorf("value is nil; should be of type %s", argType)
		}
		value = reflect.Zero(argType)
	}
	if value.Type().AssignableTo(argType) {
		return value, nil
	}
	if intLike(value.Kind()) && intLike(argType.Kind()) && value.Type().ConvertibleTo(argType) {
		value = value.Convert(argType)
		return value, nil
	}
	return reflect.Value{}, fmt.Errorf("value has type %s; should be %s", value.Type(), argType)
}

func intLike(typ reflect.Kind) bool {
	switch typ {
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return true
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		return true
	}
	return false
}

// indexArg checks if a reflect.Value can be used as an index, and converts it to int if possible.
func indexArg(index reflect.Value, cap int) (int, error) {
	var x int64
	switch index.Kind() {
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		x = index.Int()
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		x = int64(index.Uint())
	case reflect.Invalid:
		return 0, fmt.Errorf("cannot index slice/array with nil")
	default:
		return 0, fmt.Errorf("cannot index slice/array with type %s", index.Type())
	}
	if x < 0 || int(x) < 0 || int(x) > cap {
		return 0, fmt.Errorf("index out of range: %d", x)
	}
	return int(x), nil
}

// Indexing.

// index returns the result of indexing its first argument by the following
// arguments. Thus "index x 1 2 3" is, in Go syntax, x[1][2][3]. Each
// indexed item must be a map, slice, or array.
func index(item reflect.Value, indexes ...reflect.Value) (reflect.Value, error) {
	item = indirectInterface(item)
	if !item.IsValid() {
		return reflect.Value{}, fmt.Errorf("index of untyped nil")
	}
	for _, index := range indexes {
		index = indirectInterface(index)
		var isNil bool
		if item, isNil = indirect(item); isNil {
			return reflect.Value{}, fmt.Errorf("index of nil pointer")
		}
		switch item.Kind() {
		case reflect.Array, reflect.Slice, reflect.String:
			x, err := indexArg(index, item.Len())
			if err != nil {
				return reflect.Value{}, err
			}
			item = item.Index(x)
		case reflect.Map:
			index, err := prepareArg(index, item.Type().Key())
			if err != nil {
				return reflect.Value{}, err
			}
			if x := item.MapIndex(index); x.IsValid() {
				item = x
			} else {
				item = reflect.Zero(item.Type().Elem())
			}
		case reflect.Invalid:
			// the loop holds invariant: item.IsValid()
			panic("unreachable")
		default:
			return reflect.Value{}, fmt.Errorf("can't index item of type %s", item.Type())
		}
	}
	return item, nil
}

// Slicing.

// slice returns the result of slicing its first argument by the remaining
// arguments. Thus "slice x 1 2" is, in Go syntax, x[1:2], while "slice x"
// is x[:], "slice x 1" is x[1:], and "slice x 1 2 3" is x[1:2:3]. The first
// argument must be a string, slice, or array.
func slice(item reflect.Value, indexes ...reflect.Value) (reflect.Value, error) {
	item = indirectInterface(item)
	if !item.IsValid() {
		return reflect.Value{}, fmt.Errorf("slice of untyped nil")
	}
	if len(indexes) > 3 {
		return reflect.Value{}, fmt.Errorf("too many slice indexes: %d", len(indexes))
	}
	var cap int
	switch item.Kind() {
	case reflect.String:
		if len(indexes) == 3 {
			return reflect.Value{}, fmt.Errorf("cannot 3-index slice a string")
		}
		cap = item.Len()
	case reflect.Array, reflect.Slice:
		cap = item.Cap()
	default:
		return reflect.Value{}, fmt.Errorf("can't slice item of type %s", item.Type())
	}
	// set default values for cases item[:], item[i:].
	idx := [3]int{0, item.Len()}
	for i, index := range indexes {
		x, err := indexArg(index, cap)
		if err != nil {
			return reflect.Value{}, err
		}
		idx[i] = x
	}
	// given item[i:j], make sure i <= j.
	if idx[0] > idx[1] {
		return reflect.Value{}, fmt.Errorf("invalid slice index: %d > %d", idx[0], idx[1])
	}
	if len(indexes) < 3 {
		return item.Slice(idx[0], idx[1]), nil
	}
	// given item[i:j:k], make sure i <= j <= k.
	if idx[1] > idx[2] {
		return reflect.Value{}, fmt.Errorf("invalid slice index: %d > %d", idx[1], idx[2])
	}
	return item.Slice3(idx[0], idx[1], idx[2]), nil
}

// Length

// length returns the length of the item, with an error if it has no defined length.
func length(item reflect.Value) (int, error) {
	item, isNil := indirect(item)
	if isNil {
		return 0, fmt.Errorf("len of nil pointer")
	}
	switch item.Kind() {
	case reflect.Array, reflect.Chan, reflect.Map, reflect.Slice, reflect.String:
		return item.Len(), nil
	}
	return 0, fmt.Errorf("len of type %s", item.Type())
}

// Function invocation

func emptyCall(fn reflect.Value, args ...reflect.Value) reflect.Value {
	panic("unreachable") // implemented as a special case in evalCall
}

// call returns the result of evaluating the first argument as a function.
// The function must return 1 result, or 2 results, the second of which is an error.
func call(name string, fn reflect.Value, args ...reflect.Value) (reflect.Value, error) {
	fn = indirectInterface(fn)
	if !fn.IsValid() {
		return reflect.Value{}, fmt.Errorf("call of nil")
	}
	typ := fn.Type()
	if typ.Kind() != reflect.Func {
		return reflect.Value{}, fmt.Errorf("non-function %s of type %s", name, typ)
	}

	if err := goodFunc(name, typ); err != nil {
		return reflect.Value{}, err
	}
	numIn := typ.NumIn()
	var dddType reflect.Type
	if typ.IsVariadic() {
		if len(args) < numIn-1 {
			return reflect.Value{}, fmt.Errorf("wrong number of args for %s: got %d want at least %d", name, len(args), numIn-1)
		}
		dddType = typ.In(numIn - 1).Elem()
	} else {
		if len(args) != numIn {
			return reflect.Value{}, fmt.Errorf("wrong number of args for %s: got %d want %d", name, len(args), numIn)
		}
	}
	argv := make([]reflect.Value, len(args))
	for i, arg := range args {
		arg = indirectInterface(arg)
		// Compute the expected type. Clumsy because of variadics.
		argType := dddType
		if !typ.IsVariadic() || i < numIn-1 {
			argType = typ.In(i)
		}

		var err error
		if argv[i], err = prepareArg(arg, argType); err != nil {
			return reflect.Value{}, fmt.Errorf("arg %d: %w", i, err)
		}
	}
	return safeCall(fn, argv)
}

// safeCall runs fun.Call(args), and returns the resulting value and error, if
// any. If the call panics, the panic value is returned as an error.
func safeCall(fun reflect.Value, args []reflect.Value) (val reflect.Value, err error) {
	defer func() {
		if r := recover(); r != nil {
			if e, ok := r.(error); ok {
				err = e
			} else {
				err = fmt.Errorf("%v", r)
			}
		}
	}()
	ret := fun.Call(args)
	if len(ret) == 2 && !ret[1].IsNil() {
		return ret[0], ret[1].Interface().(error)
	}
	return ret[0], nil
}

// Boolean logic.

func truth(arg reflect.Value) bool {
	t, _ := isTrue(indirectInterface(arg))
	return t
}

// and computes the Boolean AND of its arguments, returning
// the first false argument it encounters, or the last argument.
func and(arg0 reflect.Value, args ...reflect.Value) reflect.Value {
	panic("unreachable") // implemented as a special case in evalCall
}

// or computes the Boolean OR of its arguments, returning
// the first true argument it encounters, or the last argument.
func or(arg0 reflect.Value, args ...reflect.Value) reflect.Value {
	panic("unreachable") // implemented as a special case in evalCall
}

// not returns the Boolean negation of its argument.
func not(arg reflect.Value) bool {
	return !truth(arg)
}

// Comparison.

// TODO: Perhaps allow comparison between signed and unsigned integers.

var (
	errBadComparisonType = errors.New("invalid type for comparison")
	errBadComparison     = errors.New("incompatible types for comparison")
	errNoComparison      = errors.New("missing argument for comparison")
)

type kind int

const (
	invalidKind kind = iota
	boolKind
	complexKind
	intKind
	floatKind
	stringKind
	uintKind
)

func basicKind(v reflect.Value) (kind, error) {
	switch v.Kind() {
	case reflect.Bool:
		return boolKind, nil
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return intKind, nil
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		return uintKind, nil
	case reflect.Float32, reflect.Float64:
		return floatKind, nil
	case reflect.Complex64, reflect.Complex128:
		return complexKind, nil
	case reflect.String:
		return stringKind, nil
	}
	return invalidKind, errBadComparisonType
}

// isNil returns true if v is the zero reflect.Value, or nil of its type.
func isNil(v reflect.Value) bool {
	if !v.IsValid() {
		return true
	}
	switch v.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return v.IsNil()
	}
	return false
}

// canCompare reports whether v1 and v2 are both the same kind, or one is nil.
// Called only when dealing with nillable types, or there's about to be an error.
func canCompare(v1, v2 reflect.Value) bool {
	k1 := v1.Kind()
	k2 := v2.Kind()
	if k1 == k2 {
		return true
	}
	// We know the type can be compared to nil.
	return k1 == reflect.Invalid || k2 == reflect.Invalid
}

// eq evaluates the comparison a == b || a == c || ...
func eq(arg1 reflect.Value, arg2 ...reflect.Value) (bool, error) {
	arg1 = indirectInterface(arg1)
	if len(arg2) == 0 {
		return false, errNoComparison
	}
	k1, _ := basicKind(arg1)
	for _, arg := range arg2 {
		arg = indirectInterface(arg)
		k2, _ := basicKind(arg)
		truth := false
		if k1 != k2 {
			// Special case: Can compare integer values regardless of type's sign.
			switch {
			case k1 == intKind && k2 == uintKind:
				truth = arg1.Int() >= 0 && uint64(arg1.Int()) == arg.Uint()
			case k1 == uintKind && k2 == intKind:
				truth = arg.Int() >= 0 && arg1.Uint() == uint64(arg.Int())
			default:
				if arg1.IsValid() && arg.IsValid() {
					return false, errBadComparison
				}
			}
		} else {
			switch k1 {
			case boolKind:
				truth = arg1.Bool() == arg.Bool()
			case complexKind:
				truth = arg1.Complex() == arg.Complex()
			case floatKind:
				truth = arg1.Float() == arg.Float()
			case intKind:
				truth = arg1.Int() == arg.Int()
			case stringKind:
				truth = arg1.String() == arg.String()
			case uintKind:
				truth = arg1.Uint() == arg.Uint()
			default:
				if !canCompare(arg1, arg) {
					return false, fmt.Errorf("non-comparable types %s: %v, %s: %v", arg1, arg1.Type(), arg.Type(), arg)
				}
				if isNil(arg1) || isNil(arg) {
					truth = isNil(arg) == isNil(arg1)
				} else {
					if !arg.Type().Comparable() {
						return false, fmt.Errorf("non-comparable type %s: %v", arg, arg.Type())
					}
					truth = arg1.Interface() == arg.Interface()
				}
			}
		}
		if truth {
			return true, nil
		}
	}
	return false, nil
}

// ne evaluates the comparison a != b.
func ne(arg1, arg2 reflect.Value) (bool, error) {
	// != is the inverse of ==.
	equal, err := eq(arg1, arg2)
	return !equal, err
}

// lt evaluates the comparison a < b.
func lt(arg1, arg2 reflect.Value) (bool, error) {
	arg1 = indirectInterface(arg1)
	k1, err := basicKind(arg1)
	if err != nil {
		return false, err
	}
	arg2 = indirectInterface(arg2)
	k2, err := basicKind(arg2)
	if err != nil {
		return false, err
	}
	truth := false
	if k1 != k2 {
		// Special case: Can compare integer values regardless of type's sign.
		switch {
		case k1 == intKind && k2 == uintKind:
			truth = arg1.Int() < 0 || uint64(arg1.Int()) < arg2.Uint()
		case k1 == uintKind && k2 == intKind:
			truth = arg2.Int() >= 0 && arg1.Uint() < uint64(arg2.Int())
		default:
			return false, errBadComparison
		}
	} else {
		switch k1 {
		case boolKind, complexKind:
			return false, errBadComparisonType
		case floatKind:
			truth = arg1.Float() < arg2.Float()
		case intKind:
			truth = arg1.Int() < arg2.Int()
		case stringKind:
			truth = arg1.String() < arg2.String()
		case uintKind:
			truth = arg1.Uint() < arg2.Uint()
		default:
			panic("invalid kind")
		}
	}
	return truth, nil
}

// le evaluates the comparison <= b.
func le(arg1, arg2 reflect.Value) (bool, error) {
	// <= is < or ==.
	lessThan, err := lt(arg1, arg2)
	if lessThan || err != nil {
		return lessThan, err
	}
	return eq(arg1, arg2)
}

// gt evaluates the comparison a > b.
func gt(arg1, arg2 reflect.Value) (bool, error) {
	// > is the inverse of <=.
	lessOrEqual, err := le(arg1, arg2)
	if err != nil {
		return false, err
	}
	return !lessOrEqual, nil
}

// ge evaluates the comparison a >= b.
func ge(arg1, arg2 reflect.Value) (bool, error) {
	// >= is the inverse of <.
	lessThan, err := lt(arg1, arg2)
	if err != nil {
		return false, err
	}
	return !lessThan, nil
}

// HTML escaping.

var (
	htmlQuot = []byte("&#34;") // shorter than "&quot;"
	htmlApos = []byte("&#39;") // shorter than "&apos;" and apos was not in HTML until HTML5
	htmlAmp  = []byte("&amp;")
	htmlLt   = []byte("&lt;")
	htmlGt   = []byte("&gt;")
	htmlNull = []byte("\uFFFD")
)

// HTMLEscape writes to w the escaped HTML equivalent of the plain text data b.
func HTMLEscape(w io.Writer, b []byte) {
	last := 0
	for i, c := range b {
		var html []byte
		switch c {
		case '\000':
			html = htmlNull
		case '"':
			html = htmlQuot
		case '\'':
			html = htmlApos
		case '&':
			html = htmlAmp
		case '<':
			html = htmlLt
		case '>':
			html = htmlGt
		default:
			continue
		}
		w.Write(b[last:i])
		w.Write(html)
		last = i + 1
	}
	w.Write(b[last:])
}

// HTMLEscapeString returns the escaped HTML equivalent of the plain text data s.
func HTMLEscapeString(s string) string {
	// Avoid allocation if we can.
	if !strings.ContainsAny(s, "'\"&<>\000") {
		return s
	}
	var b strings.Builder
	HTMLEscape(&b, []byte(s))
	return b.String()
}

// HTMLEscaper returns the escaped HTML equivalent of the textual
// representation of its arguments.
func HTMLEscaper(args ...any) string {
	return HTMLEscapeString(evalArgs(args))
}

// JavaScript escaping.

var (
	jsLowUni = []byte(`\u00`)
	hex      = []byte("0123456789ABCDEF")

	jsBackslash = []byte(`\\`)
	jsApos      = []byte(`\'`)
	jsQuot      = []byte(`\"`)
	jsLt        = []byte(`\u003C`)
	jsGt        = []byte(`\u003E`)
	jsAmp       = []byte(`\u0026`)
	jsEq        = []byte(`\u003D`)
)

// JSEscape writes to w the escaped JavaScript equivalent of the plain text data b.
func JSEscape(w io.Writer, b []byte) {
	last := 0
	for i := 0; i < len(b); i++ {
		c := b[i]

		if !jsIsSpecial(rune(c)) {
			// fast path: nothing to do
			continue
		}
		w.Write(b[last:i])

		if c < utf8.RuneSelf {
			// Quotes, slashes and angle brackets get quoted.
			// Control characters get written as \u00XX.
			switch c {
			case '\\':
				w.Write(jsBackslash)
			case '\'':
				w.Write(jsApos)
			case '"':
				w.Write(jsQuot)
			case '<':
				w.Write(jsLt)
			case '>':
				w.Write(jsGt)
			case '&':
				w.Write(jsAmp)
			case '=':
				w.Write(jsEq)
			default:
				w.Write(jsLowUni)
				t, b := c>>4, c&0x0f
				w.Write(hex[t : t+1])
				w.Write(hex[b : b+1])
			}
		} else {
			// Unicode rune.
			r, size := utf8.DecodeRune(b[i:])
			if unicode.IsPrint(r) {
				w.Write(b[i : i+size])
			} else {
				fmt.Fprintf(w, "\\u%04X", r)
			}
			i += size - 1
		}
		last = i + 1
	}
	w.Write(b[last:])
}

// JSEscapeString returns the escaped JavaScript equivalent of the plain text data s.
func JSEscapeString(s string) string {
	// Avoid allocation if we can.
	if strings.IndexFunc(s, jsIsSpecial) < 0 {
		return s
	}
	var b strings.Builder
	JSEscape(&b, []byte(s))
	return b.String()
}

func jsIsSpecial(r rune) bool {
	switch r {
	case '\\', '\'', '"', '<', '>', '&', '=':
		return true
	}
	return r < ' ' || utf8.RuneSelf <= r
}

// JSEscaper returns the escaped JavaScript equivalent of the textual
// representation of its arguments.
func JSEscaper(args ...any) string {
	return JSEscapeString(evalArgs(args))
}

// URLQueryEscaper returns the escaped value of the textual representation of
// its arguments in a form suitable for embedding in a URL query.
func URLQueryEscaper(args ...any) string {
	return url.QueryEscape(evalArgs(args))
}

// evalArgs formats the list of arguments into a string. It is therefore equivalent to
//
//	fmt.Sprint(args...)
//
// except that each argument is indirected (if a pointer), as required,
// using the same rules as the default string evaluation during template
// execution.
func evalArgs(args []any) string {
	ok := false
	var s string
	// Fast path for simple common case.
	if len(args) == 1 {
		s, ok = args[0].(string)
	}
	if !ok {
		for i, arg := range args {
			a, ok := printableValue(reflect.ValueOf(arg))
			if ok {
				args[i] = a
			} // else let fmt do its thing
		}
		s = fmt.Sprint(args...)
	}
	return s
}

"""



```