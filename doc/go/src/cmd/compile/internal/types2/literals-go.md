Response: Let's break down the thought process for analyzing the provided Go code snippet and answering the user's request.

**1. Understanding the Goal:**

The user wants to understand the functionality of the `literals.go` file within the `go/src/cmd/compile/internal/types2` package. They specifically asked for:

* A summary of the file's functions.
* An inference about the broader Go feature being implemented.
* Go code examples illustrating the feature.
* Details on any command-line arguments.
* Common mistakes users might make.

**2. Initial Code Scan and Keyword Identification:**

The first step is to quickly scan the code for keywords and patterns that provide clues about its purpose. Keywords like `literal`, `constant`, `typecheck`, `composite`, `array`, `slice`, `map`, `struct`, `func`, `langCompat`, `version`, `overflow`, and function names like `basicLit`, `funcLit`, `compositeLit`, and `indexedElts` immediately stand out.

**3. Inferring Core Functionality (Hypothesis Formation):**

Based on the keywords, the file's primary responsibility seems to be related to the type checking of various literal expressions in Go. "Literal" implies constant values directly represented in the code. The specific function names suggest handling different literal types: basic (numbers, strings), function, and composite (structs, arrays, slices, maps). The presence of `langCompat` and version checks suggests handling language evolution and ensuring compatibility.

**4. Analyzing Individual Functions:**

Now, let's examine each function in more detail:

* **`langCompat(lit *syntax.BasicLit)`:** This function checks for language version compatibility issues with numeric literals, specifically features introduced in Go 1.13 (underscores, binary/octal prefixes, hexadecimal floats). This reinforces the idea of the file dealing with language syntax and evolution.

* **`basicLit(x *operand, e *syntax.BasicLit)`:** This handles type checking for basic literals (integers, floats, imaginary numbers). It checks for language compatibility, limits the length of constants, sets the constant value, and checks for overflows. This confirms the role in handling simple constant values.

* **`funcLit(x *operand, e *syntax.FuncLit)`:** This deals with function literals (anonymous functions). It sets the scope, and if function bodies are not ignored, it schedules the function body for later type checking. This indicates handling the specific syntax and semantics of function literals.

* **`compositeLit(x *operand, e *syntax.CompositeLit, hint Type)`:** This is the most complex function, handling composite literals (structs, arrays, slices, maps). It determines the type, processes elements based on the type (field matching for structs, index handling for arrays/slices, key-value pairs for maps), and checks for various errors like missing/duplicate keys/fields, type mismatches, and invalid indices. This strongly supports the idea that this file manages the validation of structured literal data.

* **`indexedElts(elts []syntax.Expr, typ Type, length int64)`:** This helper function is used by `compositeLit` to specifically handle the elements of array and slice literals. It checks indices, detects duplicates, and ensures element type compatibility. This clarifies how array and slice literals are validated.

**5. Connecting Functions to Go Features:**

Based on the function analysis, the file is clearly implementing the type checking logic for various Go literal expressions. This directly relates to how Go ensures type safety and correctness when you define constant values and data structures in your code.

**6. Crafting Go Code Examples:**

To illustrate the functionality, create simple Go code examples that demonstrate each type of literal being handled:

* **Basic Literals:** Show integers, floats, and demonstrate the Go 1.13 features.
* **Function Literals:**  Illustrate an anonymous function being assigned to a variable.
* **Composite Literals:** Provide examples of struct, array, slice, and map literals, covering different initialization scenarios (named fields, ordered values, key-value pairs).

**7. Considering Command-Line Arguments:**

Review the code for any direct interaction with command-line flags. The `check.conf.IgnoreFuncBodies` flag suggests a compiler option to skip function body analysis, which could be exposed via a command-line flag (though not explicitly shown in this snippet). Mention this possibility and encourage the user to consult the `go build` documentation.

**8. Identifying Common Mistakes:**

Think about typical errors developers make when working with literals:

* **Struct Literals:**  Incorrect field names, missing required fields, providing values in the wrong order (without field names).
* **Array/Slice Literals:** Out-of-bounds indices, duplicate indices.
* **Map Literals:** Duplicate keys, incorrect key or value types.
* **General:** Type mismatches between the literal value and the expected type. The language version errors handled by `langCompat` are also good examples.

**9. Structuring the Answer:**

Organize the findings logically, starting with a concise summary of the file's purpose. Then, detail the functionality of each function. Provide the Go code examples. Discuss potential command-line arguments. Finally, list common mistakes.

**Self-Correction/Refinement During the Process:**

* **Initial thought:** Maybe this file is about parsing literals. **Correction:**  The presence of type checking logic (`check.typ`, `check.assignment`) indicates it's beyond just parsing; it's about semantic analysis.
* **Focus on errors:**  The numerous `check.errorf` calls highlight a key role of this code: detecting and reporting errors related to invalid literals. Emphasize this in the explanation.
* **Connecting to broader concepts:** Link the individual functionalities to the overarching Go features they support (type safety, language evolution, etc.).

By following this structured approach, combining code analysis with knowledge of Go's features and common developer errors, we can generate a comprehensive and helpful answer to the user's request.
这段 `literals.go` 文件是 Go 语言编译器 `cmd/compile/internal/types2` 包的一部分，它的主要功能是**对 Go 语言中的各种字面量（literals）进行类型检查**。

更具体地说，它负责处理以下类型的字面量：

1. **基本字面量 (Basic Literals):**  例如整数、浮点数、复数和字符串。
2. **函数字面量 (Function Literals):** 也称为匿名函数。
3. **复合字面量 (Composite Literals):** 用于创建结构体、数组、切片和映射类型的值。

下面详细列举其功能：

**1. 语言版本兼容性检查 (`langCompat`)**

   - **功能:** 检查数字字面量的表示是否与当前的 Go 语言版本兼容。
   - **涉及的 Go 语言功能:**  Go 语言在不同版本中引入了新的数字字面量表示方式，例如 Go 1.13 引入了数字字面量中的下划线分隔符、二进制字面量 (0b/0B)、八进制字面量 (0o/0O) 以及十六进制浮点数字面量。
   - **代码推理:**  函数检查字面量的长度和前缀，以确定是否使用了 Go 1.13 引入的特性。如果当前编译器不允许这些特性，则会报告错误。
   - **易犯错的点:**  在较旧的 Go 版本中使用新的字面量表示方法会导致编译错误。

   ```go
   // 假设当前 Go 版本低于 1.13

   package main

   import "fmt"

   func main() {
       // 编译时会报错：underscore in numeric literal
       num := 1_000_000
       fmt.Println(num)

       // 编译时会报错：binary literal
       bin := 0b1010
       fmt.Println(bin)
   }
   ```
   **假设输入:**  一个包含使用了 Go 1.13 特性的数字字面量的 Go 代码文件，并且使用低于 Go 1.13 的编译器版本进行编译。
   **预期输出:** 编译错误，提示使用了不支持的字面量格式。

**2. 基本字面量类型检查 (`basicLit`)**

   - **功能:** 对基本字面量（整数、浮点数、复数）进行类型检查和处理。
   - **涉及的 Go 语言功能:**  定义整型、浮点型和复数类型的常量值。
   - **代码推理:**
     - 调用 `langCompat` 进行语言版本兼容性检查。
     - 限制了 untyped 数字字面量的最大精度，防止过长的常量导致性能问题。
     - 调用 `x.setConst` 设置字面量的常量值和类型。
     - 检查整数值是否溢出。
   - **易犯错的点:**  定义过长的数字字面量可能会导致编译错误。

   ```go
   package main

   import "fmt"

   func main() {
       // 这个字面量太长，可能会导致编译错误 (取决于具体的实现限制)
       longNum := 12345678901234567890123456789012345678901234567890 // ... and so on
       fmt.Println(longNum)
   }
   ```
   **假设输入:** 一个包含非常长的数字字面量的 Go 代码文件。
   **预期输出:** 编译错误，提示常量过长。

**3. 函数字面量类型检查 (`funcLit`)**

   - **功能:** 处理函数字面量的类型检查。
   - **涉及的 Go 语言功能:**  匿名函数的定义和使用。
   - **代码推理:**
     - 获取函数字面量的签名 (参数和返回值类型)。
     - 设置函数字面量作用域的范围。
     - 如果配置允许并且存在函数体，则将函数体的类型检查安排到稍后进行，这允许处理函数体中引用自身定义类型的情况。
   - **易犯错的点:**  在函数字面量内部引用尚未完全定义的类型可能会导致类型检查错误。

   ```go
   package main

   import "fmt"

   type MyFunc func(int)

   func main() {
       // 定义一个函数字面量并赋值给 MyFunc 类型的变量
       var f MyFunc = func(x int) {
           fmt.Println(x)
       }
       f(10)
   }
   ```

**4. 复合字面量类型检查 (`compositeLit`)**

   - **功能:**  处理结构体、数组、切片和映射的复合字面量的类型检查。
   - **涉及的 Go 语言功能:**  创建结构体、数组、切片和映射类型的值。
   - **代码推理:**
     - **确定类型:** 首先尝试从字面量本身获取类型信息，如果没有，则尝试使用上下文提供的类型提示 (`hint`)。
     - **结构体字面量:**
       - 检查字段是否存在，是否重复。
       - 检查字段赋值的类型是否正确。
       - 区分使用键值对和按顺序赋值的方式。
     - **数组字面量:**
       - 检查索引是否越界，是否重复。
       - 检查元素类型是否正确。
       - 处理 `[...]` 语法自动推断数组长度的情况。
     - **切片字面量:**
       - 检查元素类型是否正确。
     - **映射字面量:**
       - 检查键的类型是否可以作为 map 的键（例如，不可比较的类型会报错）。
       - 检查键是否重复。
       - 检查值的类型是否正确。
   - **易犯错的点:**
     - **结构体:** 字段名拼写错误、未初始化所有必需字段、字段赋值类型不匹配。
     ```go
     package main

     type Person struct {
         Name string
         Age  int
     }

     func main() {
         // 错误：字段名拼写错误
         p1 := Person{Naem: "Alice", Age: 30} // 编译错误

         // 错误：字段类型不匹配
         p2 := Person{Name: "Bob", Age: "twenty"} // 编译错误

         // 错误：未初始化所有字段（如果某些字段没有默认值）
         // （在这个例子中，string和int有默认值，所以不会报错，但如果是其他类型可能报错）
         p3 := Person{Name: "Charlie"}
     }
     ```
     - **数组/切片:** 索引越界、提供了错误类型的元素。
     ```go
     package main

     import "fmt"

     func main() {
         // 错误：索引越界
         arr := [3]int{1, 2, 3, 4} // 编译错误

         // 错误：元素类型不匹配
         slice := []int{1, "two", 3} // 编译错误

         // 错误：重复的索引
         arr2 := [3]int{0: 10, 1: 20, 0: 30} // 编译错误
         fmt.Println(arr2)
     }
     ```
     - **映射:** 使用不可比较的类型作为键、重复的键。
     ```go
     package main

     import "fmt"

     type MyKey struct {
         Value []int
     }

     func main() {
         // 错误：使用切片作为 map 的键（切片不可比较）
         m1 := map[[]int]string{{1, 2}: "a"} // 编译错误

         // 错误：重复的键
         m2 := map[string]int{"hello": 1, "hello": 2} // 后面的 "hello": 2 会覆盖前面的值，但编译器不会报错
         fmt.Println(m2)
     }
     ```

**5. 索引元素类型检查 (`indexedElts`)**

   - **功能:**  一个辅助函数，用于检查数组或切片复合字面量中的元素。
   - **涉及的 Go 语言功能:**  数组和切片的初始化。
   - **代码推理:**
     - 遍历元素列表，确定每个元素的索引。
     - 检查索引是否是整数常量，是否在范围内，是否重复。
     - 递归调用 `check.exprWithHint` 检查元素表达式的类型，并使用 `check.assignment` 确保元素类型与数组/切片的元素类型兼容。

**关于命令行参数:**

这段代码本身并没有直接处理命令行参数。它位于编译器的内部类型检查阶段，在词法分析、语法分析之后。  命令行参数通常由编译器的更上层模块处理，例如 `go build` 命令。  与此文件功能相关的命令行参数可能包括影响语言版本选择的参数（例如 `-lang`），但这部分逻辑不会直接在这个文件中体现。

**总结:**

`literals.go` 文件的核心职责是确保 Go 语言代码中使用的字面量符合 Go 语言的类型规则和语法规范，从而保证程序的类型安全性和正确性。它针对不同类型的字面量实现了具体的检查逻辑，并在发现错误时报告给用户。

Prompt: 
```
这是路径为go/src/cmd/compile/internal/types2/literals.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，

"""
// Copyright 2024 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// This file implements typechecking of literals.

package types2

import (
	"cmd/compile/internal/syntax"
	. "internal/types/errors"
	"strings"
)

// langCompat reports an error if the representation of a numeric
// literal is not compatible with the current language version.
func (check *Checker) langCompat(lit *syntax.BasicLit) {
	s := lit.Value
	if len(s) <= 2 || check.allowVersion(go1_13) {
		return
	}
	// len(s) > 2
	if strings.Contains(s, "_") {
		check.versionErrorf(lit, go1_13, "underscore in numeric literal")
		return
	}
	if s[0] != '0' {
		return
	}
	radix := s[1]
	if radix == 'b' || radix == 'B' {
		check.versionErrorf(lit, go1_13, "binary literal")
		return
	}
	if radix == 'o' || radix == 'O' {
		check.versionErrorf(lit, go1_13, "0o/0O-style octal literal")
		return
	}
	if lit.Kind != syntax.IntLit && (radix == 'x' || radix == 'X') {
		check.versionErrorf(lit, go1_13, "hexadecimal floating-point literal")
	}
}

func (check *Checker) basicLit(x *operand, e *syntax.BasicLit) {
	switch e.Kind {
	case syntax.IntLit, syntax.FloatLit, syntax.ImagLit:
		check.langCompat(e)
		// The max. mantissa precision for untyped numeric values
		// is 512 bits, or 4048 bits for each of the two integer
		// parts of a fraction for floating-point numbers that are
		// represented accurately in the go/constant package.
		// Constant literals that are longer than this many bits
		// are not meaningful; and excessively long constants may
		// consume a lot of space and time for a useless conversion.
		// Cap constant length with a generous upper limit that also
		// allows for separators between all digits.
		const limit = 10000
		if len(e.Value) > limit {
			check.errorf(e, InvalidConstVal, "excessively long constant: %s... (%d chars)", e.Value[:10], len(e.Value))
			x.mode = invalid
			return
		}
	}
	x.setConst(e.Kind, e.Value)
	if x.mode == invalid {
		// The parser already establishes syntactic correctness.
		// If we reach here it's because of number under-/overflow.
		// TODO(gri) setConst (and in turn the go/constant package)
		// should return an error describing the issue.
		check.errorf(e, InvalidConstVal, "malformed constant: %s", e.Value)
		x.mode = invalid
		return
	}
	// Ensure that integer values don't overflow (go.dev/issue/54280).
	x.expr = e // make sure that check.overflow below has an error position
	check.overflow(x, opPos(x.expr))
}

func (check *Checker) funcLit(x *operand, e *syntax.FuncLit) {
	if sig, ok := check.typ(e.Type).(*Signature); ok {
		// Set the Scope's extent to the complete "func (...) {...}"
		// so that Scope.Innermost works correctly.
		sig.scope.pos = e.Pos()
		sig.scope.end = endPos(e)
		if !check.conf.IgnoreFuncBodies && e.Body != nil {
			// Anonymous functions are considered part of the
			// init expression/func declaration which contains
			// them: use existing package-level declaration info.
			decl := check.decl // capture for use in closure below
			iota := check.iota // capture for use in closure below (go.dev/issue/22345)
			// Don't type-check right away because the function may
			// be part of a type definition to which the function
			// body refers. Instead, type-check as soon as possible,
			// but before the enclosing scope contents changes (go.dev/issue/22992).
			check.later(func() {
				check.funcBody(decl, "<function literal>", sig, e.Body, iota)
			}).describef(e, "func literal")
		}
		x.mode = value
		x.typ = sig
	} else {
		check.errorf(e, InvalidSyntaxTree, "invalid function literal %v", e)
		x.mode = invalid
	}
}

func (check *Checker) compositeLit(x *operand, e *syntax.CompositeLit, hint Type) {
	var typ, base Type
	var isElem bool // true if composite literal is an element of an enclosing composite literal

	switch {
	case e.Type != nil:
		// composite literal type present - use it
		// [...]T array types may only appear with composite literals.
		// Check for them here so we don't have to handle ... in general.
		if atyp, _ := e.Type.(*syntax.ArrayType); atyp != nil && isdddArray(atyp) {
			// We have an "open" [...]T array type.
			// Create a new ArrayType with unknown length (-1)
			// and finish setting it up after analyzing the literal.
			typ = &Array{len: -1, elem: check.varType(atyp.Elem)}
			base = typ
			break
		}
		typ = check.typ(e.Type)
		base = typ

	case hint != nil:
		// no composite literal type present - use hint (element type of enclosing type)
		typ = hint
		base = typ
		// *T implies &T{}
		if b, ok := deref(coreType(base)); ok {
			base = b
		}
		isElem = true

	default:
		// TODO(gri) provide better error messages depending on context
		check.error(e, UntypedLit, "missing type in composite literal")
		// continue with invalid type so that elements are "used" (go.dev/issue/69092)
		typ = Typ[Invalid]
		base = typ
	}

	switch utyp := coreType(base).(type) {
	case *Struct:
		// Prevent crash if the struct referred to is not yet set up.
		// See analogous comment for *Array.
		if utyp.fields == nil {
			check.error(e, InvalidTypeCycle, "invalid recursive type")
			x.mode = invalid
			return
		}
		if len(e.ElemList) == 0 {
			break
		}
		// Convention for error messages on invalid struct literals:
		// we mention the struct type only if it clarifies the error
		// (e.g., a duplicate field error doesn't need the struct type).
		fields := utyp.fields
		if _, ok := e.ElemList[0].(*syntax.KeyValueExpr); ok {
			// all elements must have keys
			visited := make([]bool, len(fields))
			for _, e := range e.ElemList {
				kv, _ := e.(*syntax.KeyValueExpr)
				if kv == nil {
					check.error(e, MixedStructLit, "mixture of field:value and value elements in struct literal")
					continue
				}
				key, _ := kv.Key.(*syntax.Name)
				// do all possible checks early (before exiting due to errors)
				// so we don't drop information on the floor
				check.expr(nil, x, kv.Value)
				if key == nil {
					check.errorf(kv, InvalidLitField, "invalid field name %s in struct literal", kv.Key)
					continue
				}
				i := fieldIndex(fields, check.pkg, key.Value, false)
				if i < 0 {
					var alt Object
					if j := fieldIndex(fields, check.pkg, key.Value, true); j >= 0 {
						alt = fields[j]
					}
					msg := check.lookupError(base, key.Value, alt, true)
					check.error(kv.Key, MissingLitField, msg)
					continue
				}
				fld := fields[i]
				check.recordUse(key, fld)
				etyp := fld.typ
				check.assignment(x, etyp, "struct literal")
				// 0 <= i < len(fields)
				if visited[i] {
					check.errorf(kv, DuplicateLitField, "duplicate field name %s in struct literal", key.Value)
					continue
				}
				visited[i] = true
			}
		} else {
			// no element must have a key
			for i, e := range e.ElemList {
				if kv, _ := e.(*syntax.KeyValueExpr); kv != nil {
					check.error(kv, MixedStructLit, "mixture of field:value and value elements in struct literal")
					continue
				}
				check.expr(nil, x, e)
				if i >= len(fields) {
					check.errorf(x, InvalidStructLit, "too many values in struct literal of type %s", base)
					break // cannot continue
				}
				// i < len(fields)
				fld := fields[i]
				if !fld.Exported() && fld.pkg != check.pkg {
					check.errorf(x, UnexportedLitField, "implicit assignment to unexported field %s in struct literal of type %s", fld.name, base)
					continue
				}
				etyp := fld.typ
				check.assignment(x, etyp, "struct literal")
			}
			if len(e.ElemList) < len(fields) {
				check.errorf(inNode(e, e.Rbrace), InvalidStructLit, "too few values in struct literal of type %s", base)
				// ok to continue
			}
		}

	case *Array:
		// Prevent crash if the array referred to is not yet set up. Was go.dev/issue/18643.
		// This is a stop-gap solution. Should use Checker.objPath to report entire
		// path starting with earliest declaration in the source. TODO(gri) fix this.
		if utyp.elem == nil {
			check.error(e, InvalidTypeCycle, "invalid recursive type")
			x.mode = invalid
			return
		}
		n := check.indexedElts(e.ElemList, utyp.elem, utyp.len)
		// If we have an array of unknown length (usually [...]T arrays, but also
		// arrays [n]T where n is invalid) set the length now that we know it and
		// record the type for the array (usually done by check.typ which is not
		// called for [...]T). We handle [...]T arrays and arrays with invalid
		// length the same here because it makes sense to "guess" the length for
		// the latter if we have a composite literal; e.g. for [n]int{1, 2, 3}
		// where n is invalid for some reason, it seems fair to assume it should
		// be 3 (see also Checked.arrayLength and go.dev/issue/27346).
		if utyp.len < 0 {
			utyp.len = n
			// e.Type is missing if we have a composite literal element
			// that is itself a composite literal with omitted type. In
			// that case there is nothing to record (there is no type in
			// the source at that point).
			if e.Type != nil {
				check.recordTypeAndValue(e.Type, typexpr, utyp, nil)
			}
		}

	case *Slice:
		// Prevent crash if the slice referred to is not yet set up.
		// See analogous comment for *Array.
		if utyp.elem == nil {
			check.error(e, InvalidTypeCycle, "invalid recursive type")
			x.mode = invalid
			return
		}
		check.indexedElts(e.ElemList, utyp.elem, -1)

	case *Map:
		// Prevent crash if the map referred to is not yet set up.
		// See analogous comment for *Array.
		if utyp.key == nil || utyp.elem == nil {
			check.error(e, InvalidTypeCycle, "invalid recursive type")
			x.mode = invalid
			return
		}
		// If the map key type is an interface (but not a type parameter),
		// the type of a constant key must be considered when checking for
		// duplicates.
		keyIsInterface := isNonTypeParamInterface(utyp.key)
		visited := make(map[any][]Type, len(e.ElemList))
		for _, e := range e.ElemList {
			kv, _ := e.(*syntax.KeyValueExpr)
			if kv == nil {
				check.error(e, MissingLitKey, "missing key in map literal")
				continue
			}
			check.exprWithHint(x, kv.Key, utyp.key)
			check.assignment(x, utyp.key, "map literal")
			if x.mode == invalid {
				continue
			}
			if x.mode == constant_ {
				duplicate := false
				xkey := keyVal(x.val)
				if keyIsInterface {
					for _, vtyp := range visited[xkey] {
						if Identical(vtyp, x.typ) {
							duplicate = true
							break
						}
					}
					visited[xkey] = append(visited[xkey], x.typ)
				} else {
					_, duplicate = visited[xkey]
					visited[xkey] = nil
				}
				if duplicate {
					check.errorf(x, DuplicateLitKey, "duplicate key %s in map literal", x.val)
					continue
				}
			}
			check.exprWithHint(x, kv.Value, utyp.elem)
			check.assignment(x, utyp.elem, "map literal")
		}

	default:
		// when "using" all elements unpack KeyValueExpr
		// explicitly because check.use doesn't accept them
		for _, e := range e.ElemList {
			if kv, _ := e.(*syntax.KeyValueExpr); kv != nil {
				// Ideally, we should also "use" kv.Key but we can't know
				// if it's an externally defined struct key or not. Going
				// forward anyway can lead to other errors. Give up instead.
				e = kv.Value
			}
			check.use(e)
		}
		// if utyp is invalid, an error was reported before
		if isValid(utyp) {
			var qualifier string
			if isElem {
				qualifier = " element"
			}
			var cause string
			if utyp == nil {
				cause = " (no core type)"
			}
			check.errorf(e, InvalidLit, "invalid composite literal%s type %s%s", qualifier, typ, cause)
			x.mode = invalid
			return
		}
	}

	x.mode = value
	x.typ = typ
}

// indexedElts checks the elements (elts) of an array or slice composite literal
// against the literal's element type (typ), and the element indices against
// the literal length if known (length >= 0). It returns the length of the
// literal (maximum index value + 1).
func (check *Checker) indexedElts(elts []syntax.Expr, typ Type, length int64) int64 {
	visited := make(map[int64]bool, len(elts))
	var index, max int64
	for _, e := range elts {
		// determine and check index
		validIndex := false
		eval := e
		if kv, _ := e.(*syntax.KeyValueExpr); kv != nil {
			if typ, i := check.index(kv.Key, length); isValid(typ) {
				if i >= 0 {
					index = i
					validIndex = true
				} else {
					check.errorf(e, InvalidLitIndex, "index %s must be integer constant", kv.Key)
				}
			}
			eval = kv.Value
		} else if length >= 0 && index >= length {
			check.errorf(e, OversizeArrayLit, "index %d is out of bounds (>= %d)", index, length)
		} else {
			validIndex = true
		}

		// if we have a valid index, check for duplicate entries
		if validIndex {
			if visited[index] {
				check.errorf(e, DuplicateLitKey, "duplicate index %d in array or slice literal", index)
			}
			visited[index] = true
		}
		index++
		if index > max {
			max = index
		}

		// check element against composite literal element type
		var x operand
		check.exprWithHint(&x, eval, typ)
		check.assignment(&x, typ, "array or slice literal")
	}
	return max
}

"""



```