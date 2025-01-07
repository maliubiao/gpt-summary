Response:
Let's break down the thought process for analyzing this Go code snippet. The goal is to understand its function, demonstrate its usage, and point out potential pitfalls.

**1. Initial Understanding and Goal Identification:**

The comments at the beginning clearly state the purpose: "This file implements export filtering of an AST."  This immediately tells me the core function is to remove or modify elements of an Abstract Syntax Tree (AST) based on their export status. The `package doc` declaration indicates this code is part of the `go/doc` package, which is used for generating Go documentation. This gives further context – the filtering likely aims to produce documentation that only includes exported members.

**2. Function-by-Function Analysis:**

I'll go through each function and try to grasp its specific role:

* **`filterIdentList`:**  This looks simple. It iterates through a list of `*ast.Ident` (identifiers) and keeps only those that are exported. The `token.IsExported` function confirms this. It modifies the list in place.

* **`filterCompositeLit`:** This deals with `ast.CompositeLit` (composite literals like struct or slice literals). It filters the elements within the literal using `filterExprList`. The `Incomplete` flag suggests that if elements are removed, the literal might be considered incomplete for documentation purposes.

* **`filterExprList`:** This function handles a list of `ast.Expr` (expressions). It recursively calls `filterCompositeLit` for composite literals. It also handles `ast.KeyValueExpr` (key-value pairs), filtering based on the export status of the key.

* **`updateIdentList`:** This function replaces unexported identifiers with the underscore (`_`). It also returns a boolean indicating if any exported names were present. This suggests a strategy where unexported names are not entirely removed but replaced with a placeholder.

* **`hasExportedName`:** A straightforward function to check if a list of identifiers contains at least one exported identifier.

* **`removeAnonymousField`:** This specifically handles the removal of *unexported* anonymous fields (embedded types without explicit names) from interfaces. It checks the base type name of the anonymous field.

* **`filterFieldList`:** This is a more complex function that handles filtering fields (members of structs or interfaces). It distinguishes between named fields and anonymous fields. For anonymous fields, it uses `recordAnonymousField` (which is not in the snippet but hinted at) and considers predeclared types. It also recursively calls `filterType`. The `removedFields` return value is important.

* **`filterParamList`:**  This function applies `filterType` to the parameters of a function or method.

* **`filterType`:** This is the core recursive function. It handles various `ast.Expr` types, such as identifiers, pointers, arrays, structs, functions, interfaces, maps, and channels. It recursively calls `filterFieldList` for structs and interfaces. The `Incomplete` flag is set for structs and interfaces if fields/methods are removed.

* **`filterSpec`:** This function filters different kinds of `ast.Spec` (specifications like import, value, and type). It handles imports, value declarations (constants, variables), and type declarations, applying export filtering logic. The handling of `iota` and constants is interesting.

* **`copyConstType`:** This function seems to be a utility to create a copy of a constant's type, preserving position information. This is likely used when propagating type information for constants.

* **`filterSpecList`:** This filters a list of `ast.Spec` based on the token (e.g., `token.CONST`). It has special logic for propagating type information for constants.

* **`filterDecl`:** This function filters top-level declarations (`ast.Decl`) like `GenDecl` (general declarations like `import`, `const`, `type`, `var`) and `FuncDecl` (function and method declarations).

* **`fileExports`:** This is the entry point for filtering an entire `ast.File`. It iterates through the declarations and applies `filterDecl`.

**3. Identifying the Go Feature:**

Based on the function names and the manipulation of the AST, it's clear this code implements **export filtering for Go code**. This is a crucial part of the Go language's visibility rules. Only identifiers starting with an uppercase letter are exported and accessible from other packages. This code allows the `go/doc` package (and potentially other tools) to process Go code and generate documentation (or perform other analysis) that respects these visibility rules.

**4. Code Examples and Assumptions:**

Now, I'll create examples to illustrate the functions, making reasonable assumptions about input and output.

* **`filterIdentList`:** Straightforward, so the example is simple.
* **`filterCompositeLit` and `filterExprList`:** Need to show nested structures and how filtering propagates.
* **`updateIdentList`:**  Showcases the replacement of unexported names.
* **`filterFieldList`` and `filterType`:** These are more complex, so I'll focus on how they handle struct and interface fields.

**5. Command-Line Arguments (If Applicable):**

This particular code snippet doesn't directly handle command-line arguments. However, since it's part of the `go/doc` package, I know that `go doc` is the command-line tool that uses this functionality. I'll explain how `go doc` works.

**6. Common Mistakes:**

I'll think about scenarios where someone using or relying on this filtering might make mistakes. This often involves misunderstandings about Go's export rules or the behavior of the filtering.

**7. Refinement and Language:**

Finally, I'll review my analysis, ensuring the language is clear, concise, and accurate. I'll use Chinese as requested in the prompt. I'll also make sure to tie the individual functions back to the overall purpose of export filtering.

By following these steps, I can systematically analyze the code snippet, understand its purpose, provide illustrative examples, and address the specific requirements of the prompt. The key is to connect the low-level details of the code to the higher-level concept of Go's export mechanism.
这段代码是 Go 语言 `go/doc` 包中 `exports.go` 文件的一部分，它主要实现了 **对 Go 语言抽象语法树（AST）进行导出过滤的功能**。换句话说，它的作用是从 AST 中移除或修改那些未导出的（小写字母开头的）标识符、字段、方法等，以便后续的文档生成或其他代码分析工具只处理导出的部分。

以下是它各个部分的功能分解：

**核心功能：导出过滤**

该文件的核心目标是根据 Go 语言的导出规则（标识符首字母大写）过滤 AST 节点。这对于生成公开 API 的文档至关重要，因为文档通常只应该包含可以被其他包访问的部分。

**具体功能点：**

1. **`filterIdentList(list []*ast.Ident) []*ast.Ident`**:
   - **功能**:  接收一个 `ast.Ident`（标识符）切片，移除其中未导出的标识符，并返回过滤后的切片。
   - **原理**: 遍历标识符切片，使用 `token.IsExported(x.Name)` 判断标识符是否已导出。如果是，则保留；否则，移除。
   - **示例**:
     ```go
     package main

     import (
         "fmt"
         "go/ast"
         "go/token"
     )

     func main() {
         idents := []*ast.Ident{
             {Name: "ExportedFunc"},
             {Name: "unexportedFunc"},
             {Name: "ExportedVar"},
             {Name: "unexportedVar"},
         }

         filtered := filterIdentList(idents)
         for _, id := range filtered {
             fmt.Println(id.Name)
         }
         // 输出:
         // ExportedFunc
         // ExportedVar
     }

     func filterIdentList(list []*ast.Ident) []*ast.Ident {
         j := 0
         for _, x := range list {
             if token.IsExported(x.Name) {
                 list[j] = x
                 j++
             }
         }
         return list[:j]
     }
     ```

2. **`filterCompositeLit(lit *ast.CompositeLit, filter Filter, export bool)`**:
   - **功能**: 过滤复合字面量（如结构体、切片、Map 的字面量）中的元素。
   - **原理**: 调用 `filterExprList` 过滤字面量中的表达式列表。如果移除了元素，则将 `lit.Incomplete` 设置为 `true`，表示该字面量是不完整的。
   - **假设输入**: 一个包含未导出字段或元素的结构体字面量。
   - **假设输出**: 未导出字段或元素被移除后的结构体字面量，并且 `Incomplete` 字段可能被设置为 `true`。

3. **`filterExprList(list []ast.Expr, filter Filter, export bool) []ast.Expr`**:
   - **功能**: 过滤表达式列表。
   - **原理**: 遍历表达式列表，对于复合字面量调用 `filterCompositeLit` 进行过滤；对于键值对表达式，如果键是未导出的标识符，则跳过该键值对；如果值是复合字面量，则对其进行过滤。
   - **假设输入**: 一个包含未导出键或包含未导出元素的复合字面量的表达式列表。
   - **假设输出**: 未导出的键和包含未导出元素的复合字面量被移除后的表达式列表。

4. **`updateIdentList(list []*ast.Ident) (hasExported bool)`**:
   - **功能**: 将未导出的标识符替换为下划线 `_`，并返回是否至少存在一个导出的标识符。
   - **原理**: 遍历标识符列表，如果标识符未导出，则将其替换为 `underscore` 常量（`ast.NewIdent("_")`）。
   - **示例**:
     ```go
     package main

     import (
         "fmt"
         "go/ast"
         "go/token"
     )

     func main() {
         idents := []*ast.Ident{
             {Name: "ExportedFunc"},
             {Name: "unexportedFunc"},
         }

         hasExported := updateIdentList(idents)
         fmt.Println("Has Exported:", hasExported)
         for _, id := range idents {
             fmt.Println(id.Name)
         }
         // 输出:
         // Has Exported: true
         // ExportedFunc
         // _
     }

     var underscore = ast.NewIdent("_")

     func updateIdentList(list []*ast.Ident) (hasExported bool) {
         for i, x := range list {
             if token.IsExported(x.Name) {
                 hasExported = true
             } else {
                 list[i] = underscore
             }
         }
         return hasExported
     }
     ```

5. **`hasExportedName(list []*ast.Ident) bool`**:
   - **功能**: 判断标识符列表中是否包含任何导出的名称。
   - **原理**: 遍历标识符列表，如果找到一个导出的标识符，则返回 `true`。

6. **`removeAnonymousField(name string, ityp *ast.InterfaceType)`**:
   - **功能**: 从接口类型中移除指定名称的匿名字段（嵌入类型）。
   - **原理**: 遍历接口的方法列表，如果找到一个没有名称的字段（匿名字段），并且其类型名称与给定的 `name` 匹配，则移除该字段。
   - **假设输入**: 一个包含未导出匿名字段的接口类型。
   - **假设输出**: 未导出的匿名字段被移除后的接口类型，并且 `Incomplete` 字段可能被设置为 `true`。

7. **`(r *reader) filterFieldList(parent *namedType, fields *ast.FieldList, ityp *ast.InterfaceType) (removedFields bool)`**:
   - **功能**: 过滤结构体或接口的字段列表，移除未导出的字段名。对于匿名字段，会记录其类型信息。
   - **原理**: 遍历字段列表，对于命名字段，使用 `filterIdentList` 过滤字段名；对于匿名字段，会调用 `r.recordAnonymousField` 记录其类型，并根据其类型名称的导出状态决定是否保留。
   - **`r *reader`**:  表明该函数是 `reader` 类型的方法。`reader` 类型可能负责读取和处理 AST。
   - **假设输入**: 一个包含未导出字段的结构体或接口的字段列表。
   - **假设输出**: 未导出的字段被移除后的字段列表，`removedFields` 返回 `true`。

8. **`(r *reader) filterParamList(fields *ast.FieldList)`**:
   - **功能**: 对参数列表中的每个参数类型应用 `filterType`。
   - **原理**: 遍历参数列表，对每个参数的类型调用 `r.filterType` 进行过滤。

9. **`(r *reader) filterType(parent *namedType, typ ast.Expr)`**:
   - **功能**: 递归地过滤类型表达式 `typ` 中的未导出结构体字段或方法类型。
   - **原理**: 根据不同的类型表达式类型（如 `*ast.StructType`、`*ast.InterfaceType`、`*ast.FuncType` 等），调用相应的过滤函数（如 `r.filterFieldList`、`r.filterParamList`）进行递归过滤。如果移除了字段或方法，会将相应的结构体或接口类型的 `Incomplete` 字段设置为 `true`。
   - **这是一个核心的递归过滤函数**。

10. **`(r *reader) filterSpec(spec ast.Spec) bool`**:
    - **功能**: 过滤各种声明规范（`ast.Spec`），例如导入声明、值声明、类型声明。
    - **原理**:
        - **`*ast.ImportSpec`**: 总是保留导入声明。
        - **`*ast.ValueSpec`**: 过滤值声明中的表达式列表，如果存在导出的名称，则更新标识符列表（将未导出的替换为 `_`），并过滤类型。
        - **`*ast.TypeSpec`**: 如果类型名称已导出，则过滤其类型。
    - **返回值**:  指示该声明规范是否应该被保留。

11. **`copyConstType(typ ast.Expr, pos token.Pos) ast.Expr`**:
    - **功能**: 返回常量类型的副本，并设置其位置信息。
    - **原理**:  主要处理 `*ast.Ident` 和 `*ast.SelectorExpr` 类型的常量类型。

12. **`(r *reader) filterSpecList(list []ast.Spec, tok token.Token) []ast.Spec`**:
    - **功能**: 过滤声明规范列表。
    - **原理**: 对于常量声明 (`token.CONST`)，会传播类型信息，以便在未导出的常量被过滤掉时，类型信息不会丢失。然后遍历列表，调用 `r.filterSpec` 过滤每个声明规范。

13. **`(r *reader) filterDecl(decl ast.Decl) bool`**:
    - **功能**: 过滤顶层声明（`ast.Decl`），例如通用声明（`*ast.GenDecl`，包含 `import`、`const`、`type`、`var` 等）和函数声明（`*ast.FuncDecl`）。
    - **原理**:
        - **`*ast.GenDecl`**: 调用 `r.filterSpecList` 过滤其包含的声明规范。
        - **`*ast.FuncDecl`**: 只保留导出的函数或方法。
    - **返回值**: 指示该声明是否应该被保留。

14. **`(r *reader) fileExports(src *ast.File)`**:
    - **功能**:  作为入口函数，从 `ast.File` 中移除未导出的声明。
    - **原理**: 遍历文件的声明列表，调用 `r.filterDecl` 过滤每个声明。

**它是什么 Go 语言功能的实现？**

这段代码是 Go 语言中 **文档生成工具 (`go doc`)** 的一部分实现。更具体地说，它负责在生成文档之前，对代码的 AST 进行预处理，只保留导出的部分。这确保了生成的文档只包含可以被其他包使用的公共 API。

**代码推理示例：**

假设我们有以下 Go 代码：

```go
package mypackage

type ExportedStruct struct {
    ExportedField int
    unexportedField string
}

type unexportedStruct struct {
    ExportedField int
}

func ExportedFunc() {}

func unexportedFunc() {}

const ExportedConst = 10
const unexportedConst = 20

var ExportedVar int
var unexportedVar int
```

当 `fileExports` 函数处理这个文件的 AST 时，会发生以下（简化的）过程：

1. **`filterDecl` 处理函数声明：** `ExportedFunc` 会被保留，`unexportedFunc` 会被移除。
2. **`filterDecl` 处理通用声明（类型、常量、变量）：**
   - **`filterSpecList` 处理类型声明：** `ExportedStruct` 会被保留，并调用 `filterType` 过滤其字段。`unexportedStruct` 会被移除。
   - **`filterType` 处理 `ExportedStruct`：** `filterFieldList` 会移除 `unexportedField`。`ExportedStruct` 的 `Incomplete` 可能会被设置为 `true`。
   - **`filterSpecList` 处理常量声明：** `ExportedConst` 会被保留，`unexportedConst` 会被移除。可能会进行类型信息的传播。
   - **`filterSpecList` 处理变量声明：** `ExportedVar` 会被保留，`unexportedVar` 的名称会被替换为 `_`。
3. **最终的 AST 只会包含导出的部分。**

**命令行参数处理：**

这段代码本身并不直接处理命令行参数。它是 `go/doc` 包的内部实现。`go doc` 命令会解析命令行参数，然后使用 `go/parser` 解析 Go 代码，构建 AST，最后调用 `go/doc` 包中的函数（包括这里的代码）来处理 AST 并生成文档。

**使用者易犯错的点：**

虽然这段代码是内部实现，普通 Go 开发者不会直接调用它，但理解其背后的原理有助于避免一些关于 Go 导出规则的误解：

1. **误以为未导出的成员会被完全删除：**  像 `updateIdentList` 函数展示的那样，未导出的标识符有时会被替换为 `_` 而不是完全删除。这在某些需要保留结构的情况下（例如，匹配右侧表达式的数量）是有用的。
2. **忘记匿名嵌入字段的导出规则：**  如果一个匿名嵌入的结构体类型是未导出的，那么即使它的字段是导出的，这些字段也不会被视为外部类型的导出成员。`filterFieldList` 中的逻辑处理了这种情况。

总而言之，这段代码是 Go 语言文档生成工具的核心部分，它确保生成的文档只包含可以被外部包访问的公共 API，是理解 Go 语言导出机制的重要组成部分。

Prompt: 
```
这是路径为go/src/go/doc/exports.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。

"""
// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// This file implements export filtering of an AST.

package doc

import (
	"go/ast"
	"go/token"
)

// filterIdentList removes unexported names from list in place
// and returns the resulting list.
func filterIdentList(list []*ast.Ident) []*ast.Ident {
	j := 0
	for _, x := range list {
		if token.IsExported(x.Name) {
			list[j] = x
			j++
		}
	}
	return list[0:j]
}

var underscore = ast.NewIdent("_")

func filterCompositeLit(lit *ast.CompositeLit, filter Filter, export bool) {
	n := len(lit.Elts)
	lit.Elts = filterExprList(lit.Elts, filter, export)
	if len(lit.Elts) < n {
		lit.Incomplete = true
	}
}

func filterExprList(list []ast.Expr, filter Filter, export bool) []ast.Expr {
	j := 0
	for _, exp := range list {
		switch x := exp.(type) {
		case *ast.CompositeLit:
			filterCompositeLit(x, filter, export)
		case *ast.KeyValueExpr:
			if x, ok := x.Key.(*ast.Ident); ok && !filter(x.Name) {
				continue
			}
			if x, ok := x.Value.(*ast.CompositeLit); ok {
				filterCompositeLit(x, filter, export)
			}
		}
		list[j] = exp
		j++
	}
	return list[0:j]
}

// updateIdentList replaces all unexported identifiers with underscore
// and reports whether at least one exported name exists.
func updateIdentList(list []*ast.Ident) (hasExported bool) {
	for i, x := range list {
		if token.IsExported(x.Name) {
			hasExported = true
		} else {
			list[i] = underscore
		}
	}
	return hasExported
}

// hasExportedName reports whether list contains any exported names.
func hasExportedName(list []*ast.Ident) bool {
	for _, x := range list {
		if x.IsExported() {
			return true
		}
	}
	return false
}

// removeAnonymousField removes anonymous fields named name from an interface.
func removeAnonymousField(name string, ityp *ast.InterfaceType) {
	list := ityp.Methods.List // we know that ityp.Methods != nil
	j := 0
	for _, field := range list {
		keepField := true
		if n := len(field.Names); n == 0 {
			// anonymous field
			if fname, _ := baseTypeName(field.Type); fname == name {
				keepField = false
			}
		}
		if keepField {
			list[j] = field
			j++
		}
	}
	if j < len(list) {
		ityp.Incomplete = true
	}
	ityp.Methods.List = list[0:j]
}

// filterFieldList removes unexported fields (field names) from the field list
// in place and reports whether fields were removed. Anonymous fields are
// recorded with the parent type. filterType is called with the types of
// all remaining fields.
func (r *reader) filterFieldList(parent *namedType, fields *ast.FieldList, ityp *ast.InterfaceType) (removedFields bool) {
	if fields == nil {
		return
	}
	list := fields.List
	j := 0
	for _, field := range list {
		keepField := false
		if n := len(field.Names); n == 0 {
			// anonymous field or embedded type or union element
			fname := r.recordAnonymousField(parent, field.Type)
			if fname != "" {
				if token.IsExported(fname) {
					keepField = true
				} else if ityp != nil && predeclaredTypes[fname] {
					// possibly an embedded predeclared type; keep it for now but
					// remember this interface so that it can be fixed if name is also
					// defined locally
					keepField = true
					r.remember(fname, ityp)
				}
			} else {
				// If we're operating on an interface, assume that this is an embedded
				// type or union element.
				//
				// TODO(rfindley): consider traversing into approximation/unions
				// elements to see if they are entirely unexported.
				keepField = ityp != nil
			}
		} else {
			field.Names = filterIdentList(field.Names)
			if len(field.Names) < n {
				removedFields = true
			}
			if len(field.Names) > 0 {
				keepField = true
			}
		}
		if keepField {
			r.filterType(nil, field.Type)
			list[j] = field
			j++
		}
	}
	if j < len(list) {
		removedFields = true
	}
	fields.List = list[0:j]
	return
}

// filterParamList applies filterType to each parameter type in fields.
func (r *reader) filterParamList(fields *ast.FieldList) {
	if fields != nil {
		for _, f := range fields.List {
			r.filterType(nil, f.Type)
		}
	}
}

// filterType strips any unexported struct fields or method types from typ
// in place. If fields (or methods) have been removed, the corresponding
// struct or interface type has the Incomplete field set to true.
func (r *reader) filterType(parent *namedType, typ ast.Expr) {
	switch t := typ.(type) {
	case *ast.Ident:
		// nothing to do
	case *ast.ParenExpr:
		r.filterType(nil, t.X)
	case *ast.StarExpr: // possibly an embedded type literal
		r.filterType(nil, t.X)
	case *ast.UnaryExpr:
		if t.Op == token.TILDE { // approximation element
			r.filterType(nil, t.X)
		}
	case *ast.BinaryExpr:
		if t.Op == token.OR { // union
			r.filterType(nil, t.X)
			r.filterType(nil, t.Y)
		}
	case *ast.ArrayType:
		r.filterType(nil, t.Elt)
	case *ast.StructType:
		if r.filterFieldList(parent, t.Fields, nil) {
			t.Incomplete = true
		}
	case *ast.FuncType:
		r.filterParamList(t.TypeParams)
		r.filterParamList(t.Params)
		r.filterParamList(t.Results)
	case *ast.InterfaceType:
		if r.filterFieldList(parent, t.Methods, t) {
			t.Incomplete = true
		}
	case *ast.MapType:
		r.filterType(nil, t.Key)
		r.filterType(nil, t.Value)
	case *ast.ChanType:
		r.filterType(nil, t.Value)
	}
}

func (r *reader) filterSpec(spec ast.Spec) bool {
	switch s := spec.(type) {
	case *ast.ImportSpec:
		// always keep imports so we can collect them
		return true
	case *ast.ValueSpec:
		s.Values = filterExprList(s.Values, token.IsExported, true)
		if len(s.Values) > 0 || s.Type == nil && len(s.Values) == 0 {
			// If there are values declared on RHS, just replace the unexported
			// identifiers on the LHS with underscore, so that it matches
			// the sequence of expression on the RHS.
			//
			// Similarly, if there are no type and values, then this expression
			// must be following an iota expression, where order matters.
			if updateIdentList(s.Names) {
				r.filterType(nil, s.Type)
				return true
			}
		} else {
			s.Names = filterIdentList(s.Names)
			if len(s.Names) > 0 {
				r.filterType(nil, s.Type)
				return true
			}
		}
	case *ast.TypeSpec:
		// Don't filter type parameters here, by analogy with function parameters
		// which are not filtered for top-level function declarations.
		if name := s.Name.Name; token.IsExported(name) {
			r.filterType(r.lookupType(s.Name.Name), s.Type)
			return true
		} else if IsPredeclared(name) {
			if r.shadowedPredecl == nil {
				r.shadowedPredecl = make(map[string]bool)
			}
			r.shadowedPredecl[name] = true
		}
	}
	return false
}

// copyConstType returns a copy of typ with position pos.
// typ must be a valid constant type.
// In practice, only (possibly qualified) identifiers are possible.
func copyConstType(typ ast.Expr, pos token.Pos) ast.Expr {
	switch typ := typ.(type) {
	case *ast.Ident:
		return &ast.Ident{Name: typ.Name, NamePos: pos}
	case *ast.SelectorExpr:
		if id, ok := typ.X.(*ast.Ident); ok {
			// presumably a qualified identifier
			return &ast.SelectorExpr{
				Sel: ast.NewIdent(typ.Sel.Name),
				X:   &ast.Ident{Name: id.Name, NamePos: pos},
			}
		}
	}
	return nil // shouldn't happen, but be conservative and don't panic
}

func (r *reader) filterSpecList(list []ast.Spec, tok token.Token) []ast.Spec {
	if tok == token.CONST {
		// Propagate any type information that would get lost otherwise
		// when unexported constants are filtered.
		var prevType ast.Expr
		for _, spec := range list {
			spec := spec.(*ast.ValueSpec)
			if spec.Type == nil && len(spec.Values) == 0 && prevType != nil {
				// provide current spec with an explicit type
				spec.Type = copyConstType(prevType, spec.Pos())
			}
			if hasExportedName(spec.Names) {
				// exported names are preserved so there's no need to propagate the type
				prevType = nil
			} else {
				prevType = spec.Type
			}
		}
	}

	j := 0
	for _, s := range list {
		if r.filterSpec(s) {
			list[j] = s
			j++
		}
	}
	return list[0:j]
}

func (r *reader) filterDecl(decl ast.Decl) bool {
	switch d := decl.(type) {
	case *ast.GenDecl:
		d.Specs = r.filterSpecList(d.Specs, d.Tok)
		return len(d.Specs) > 0
	case *ast.FuncDecl:
		// ok to filter these methods early because any
		// conflicting method will be filtered here, too -
		// thus, removing these methods early will not lead
		// to the false removal of possible conflicts
		return token.IsExported(d.Name.Name)
	}
	return false
}

// fileExports removes unexported declarations from src in place.
func (r *reader) fileExports(src *ast.File) {
	j := 0
	for _, d := range src.Decls {
		if r.filterDecl(d) {
			src.Decls[j] = d
			j++
		}
	}
	src.Decls = src.Decls[0:j]
}

"""



```