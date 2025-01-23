Response: Let's break down the thought process for analyzing the provided Go code snippet.

1. **Understand the Goal:** The core request is to understand the functionality of the `typestring.go` file within the Go compiler's `types2` package. Specifically, the prompt asks for:
    * Listing its functions.
    * Inferring its purpose in a broader Go feature.
    * Providing Go code examples to illustrate.
    * Explaining any command-line argument handling (if applicable).
    * Identifying potential user errors.

2. **Initial Code Scan (Keywords and Structure):**  A quick scan reveals key terms and structural elements:
    * `package types2`: This immediately tells us we're within the `types2` package, which is a newer version of the `go/types` package for type checking.
    * `Qualifier func(*Package) string`:  This suggests a mechanism for controlling how package names are displayed.
    * `TypeString`, `WriteType`, `WriteSignature`:  These function names strongly imply string representations of Go types and signatures.
    * `typeWriter`: This looks like a central struct managing the type string generation process. It contains fields like `buf`, `seen`, `qf`, etc., suggesting it's managing the state of the stringification.
    * `typ`, `signature`, `tuple`, `typeList`, `tParamList`, `typeName`: These methods within `typeWriter` further reinforce the idea of recursively building type strings.
    * `switch t := typ.(type)`: This is the classic Go type switch, indicating that the code handles various Go type kinds.
    * Specific type cases: `*Basic`, `*Array`, `*Slice`, `*Struct`, `*Pointer`, `*Tuple`, `*Signature`, `*Union`, `*Interface`, `*Map`, `*Chan`, `*Named`, `*TypeParam`, `*Alias`. This confirms the code handles the majority of Go's type system.
    * Comments mentioning "type hashing": This hints at a deeper purpose beyond simple string representation.

3. **Deduce the Core Functionality:** Based on the keywords and structure, the primary function is clearly to generate string representations of Go types and function signatures. The `Qualifier` adds a layer of control over how package names are presented.

4. **Infer the Broader Go Feature:** The file's location (`go/src/cmd/compile/internal/types2`) and the explicit mention of "type hashing" provide strong clues. This code is likely used by the Go compiler itself. Type hashing is often used for:
    * **Compiler optimizations:**  Quickly comparing types.
    * **Interface satisfaction checks:**  Determining if a type implements an interface.
    * **Generic instantiation:**  Generating unique types for different generic instantiations.
    * **Reflection:**  Providing string representations of types at runtime (though this file is more for compile-time).

5. **Construct Go Code Examples:** To illustrate the functionality, simple examples showcasing different type representations are needed. The `TypeString` function is the easiest entry point. Examples should cover basic types, composite types (arrays, slices, structs, pointers, maps, channels), functions, interfaces, and generics. The `Qualifier` aspect also needs a demonstration.

6. **Address Command-Line Arguments:**  A review of the code reveals *no* direct handling of command-line arguments within this specific file. The `Qualifier` is programmatic, not based on command-line flags. Therefore, the conclusion should be that this file doesn't directly process command-line arguments.

7. **Identify Potential User Errors:**  Consider how developers might interact with the *outputs* of this code, even if they don't directly call these functions. Common points of confusion related to type representations include:
    * **Omitting package names:**  Understanding when and why package prefixes are needed.
    * **Distinguishing between type definitions and aliases:** The output should clearly differentiate them.
    * **Understanding generic type parameters:** How they are represented in the string.
    * **Channel direction syntax:** `chan`, `chan<-`, `<-chan`.

8. **Refine and Structure the Answer:** Organize the findings into clear sections as requested by the prompt. Use precise language and provide sufficient detail. Ensure the Go code examples are correct and easy to understand. Clearly state assumptions made during the inference process.

**Self-Correction/Refinement During the Process:**

* **Initial thought:**  Perhaps the `Qualifier` relates to import path shortening. **Correction:** The code clarifies it's more about controlling the presence or absence of the full path.
* **Initial thought:**  This is *only* for generating human-readable type strings. **Correction:** The "type hashing" aspect shows a deeper purpose for compiler internals. The different `typeWriter` creation functions (`newTypeWriter` vs. `newTypeHasher`) emphasize this.
* **Ensuring examples cover generics:**  Initially, I might have focused only on pre-generics Go. Recognizing the presence of `TypeParam` and related methods necessitates adding examples demonstrating generic types.
* **Clarity on error handling:**  The code uses `w.error()`. It's important to note that this likely signals a compiler error internally, rather than something a regular Go program would catch.

By following these steps, combining code analysis with domain knowledge about Go compilation, and refining the understanding along the way, a comprehensive answer addressing all aspects of the prompt can be constructed.
这段代码是 Go 语言编译器 `types2` 包中 `typestring.go` 文件的一部分，它的主要功能是 **将 Go 语言的类型以字符串的形式表示出来**。这个功能在编译器的很多地方都会用到，例如：

* **错误消息:** 当类型不匹配或者有类型相关的错误时，需要将类型信息包含在错误消息中，方便开发者理解。
* **调试信息:**  在调试过程中，查看变量的类型信息。
* **类型唯一性标识 (Type Hashing):**  虽然代码中没有直接体现，但相关的机制（`newTypeHasher`）暗示了它也可能被用于生成类型的唯一标识，用于编译器内部的优化和比较。
* **反射 (Reflection):**  虽然 `types2` 包是编译时的类型信息，但其设计思想与 `reflect` 包有相似之处，`reflect` 包在运行时也需要将类型转换为字符串。
* **泛型类型的表示:**  代码中处理了 `TypeParam`，说明它也负责表示泛型类型的字符串形式。

**更详细的功能点:**

1. **`Qualifier` 类型和相关函数 (`RelativeTo`):**
   - `Qualifier` 是一个函数类型，它接收一个 `*Package` 作为参数，返回一个字符串。它的作用是控制在类型字符串中如何表示来自其他包的类型。
   - 如果 `Qualifier` 返回一个非空字符串 `p`，则类型会以 `p.TypeName` 的形式表示（例如 `"encoding/json.Marshal"`）。
   - 如果返回空字符串，则只显示类型名（例如 `"Marshal"`）。
   - `RelativeTo(pkg *Package)` 函数返回一个 `Qualifier`，该 `Qualifier` 会将除了 `pkg` 包之外的所有包的类型都加上包路径前缀。

2. **`TypeString(typ Type, qf Qualifier) string`:**
   - 这是最主要的函数，它接收一个 `Type` 接口类型的变量和一个 `Qualifier`，返回该类型的字符串表示。
   - 它内部使用 `WriteType` 将类型写入一个 `bytes.Buffer`，然后将缓冲区的内容转换为字符串。

3. **`WriteType(buf *bytes.Buffer, typ Type, qf Qualifier)`:**
   - 该函数将 `Type` 接口类型的变量的字符串表示写入到提供的 `bytes.Buffer` 中。
   - 它创建了一个 `typeWriter` 实例来完成实际的写入工作。

4. **`WriteSignature(buf *bytes.Buffer, sig *Signature, qf Qualifier)`:**
   - 专门用于将函数签名（`Signature` 类型）的字符串表示写入到 `bytes.Buffer` 中，不包含前导的 `"func"` 关键字。

5. **`typeWriter` 结构体和相关方法:**
   - `typeWriter` 是一个核心结构体，负责维护类型字符串生成的状态。
   - `buf`:  用于存储生成的字符串的缓冲区。
   - `seen`:  用于检测类型循环引用的 map。
   - `qf`:  `Qualifier` 函数。
   - `ctxt`:  用于类型哈希的上下文信息。
   - `tparams`:  局部类型参数列表，用于处理泛型。
   - `paramNames`:  一个布尔值，指示是否需要写入函数参数的名称。
   - `tpSubscripts`: 一个布尔值，指示是否将类型参数索引写成下标。
   - `pkgInfo`: 一个布尔值，用于在某些情况下注解 unexported 字段的包路径。
   - `newTypeWriter` 和 `newTypeHasher`:  创建 `typeWriter` 实例的工厂函数，`newTypeHasher` 用于类型哈希的场景。
   - `byte`, `string`, `error`:  辅助方法，用于向缓冲区写入字符、字符串和错误信息。
   - `typ`:  核心方法，用于递归地处理各种 `Type`，并调用相应的方法进行字符串化。
   - `signature`, `tuple`, `typeList`, `tParamList`, `typeName`:  用于处理函数签名、元组（参数列表）、类型列表、类型参数列表和类型名称的具体方法。
   - `typeSet`: 用于写入接口类型集合的规范哈希。

6. **`subscript(x uint64) string`:**
   - 将一个无符号 64 位整数转换为下标形式的字符串（例如，将 `1` 转换为 `"₁"`）。这主要用于表示类型参数的索引。

**推理 Go 语言功能的实现和代码示例:**

这个文件是 Go 语言类型系统表示的核心部分，特别是对于编译时类型信息的处理至关重要。它可以被用于实现以下 Go 语言功能：

* **类型断言失败时的错误信息:**

```go
package main

import (
	"fmt"
	"go/src/cmd/compile/internal/types2"
)

func main() {
	var i interface{} = "hello"

	// 假设在类型断言失败时，编译器会使用 types2.TypeString 来生成类型信息
	_, ok := i.(int)
	if !ok {
		stringType := types2.TypeString(types2.NewNamed(nil, nil, "string", nil), nil)
		intType := types2.TypeString(types2.Typ[types2.Int], nil)
		fmt.Printf("类型断言失败: 接口的动态类型是 %s, 而尝试断言的类型是 %s\n", stringType, intType)
	}
}

// 假设的输出: 类型断言失败: 接口的动态类型是 string, 而尝试断言的类型是 int
```

* **泛型类型的表示:**

```go
package main

import (
	"fmt"
	"go/src/cmd/compile/internal/types2"
)

func main() {
	// 构造一个泛型类型 List[T] 的表示
	typeParamT := types2.NewTypeParam(types2.NewTypeName(nil, nil, "T", nil), nil)
	typeParamList := types2.NewTypeParamList(typeParamT)
	listType := types2.NewNamed(
		types2.NewPackage("main", "main"),
		types2.NewScope(nil, 0, 0, ""),
		"List",
		types2.NewStruct(nil, nil), // 假设 List 是一个空结构体
	)
	listType.SetTypeParams(typeParamList)

	// 实例化 List[int]
	intType := types2.Typ[types2.Int]
	instance := types2.NewInstantiation(listType, types2.NewTypeList(intType))

	// 使用 TypeString 获取字符串表示
	typeString := types2.TypeString(instance, nil)
	fmt.Println(typeString)
}

// 假设的输出: main.List[int]
```

**假设的输入与输出（基于代码推理）:**

* **输入 `TypeString(types2.Typ[types2.Int], nil)`:**
   * 输出: `"int"`
* **输入 `TypeString(types2.NewSlice(types2.Typ[types2.String]), nil)`:**
   * 输出: `"[]string"`
* **输入 `TypeString(types2.NewPointer(types2.Typ[types2.Bool]), nil)`:**
   * 输出: `"*bool"`
* **输入一个表示 `map[string]int` 的 `Type`:**
   * 输出: `"map[string]int"`
* **输入一个表示 `func(int, string) bool` 的 `Type`:**
   * 输出: `"func(int, string) bool"`
* **输入一个表示 `chan int` 的 `Type`:**
   * 输出: `"chan int"`
* **输入一个表示 `chan<- int` 的 `Type`:**
   * 输出: `"chan<- int"`
* **输入一个表示 `<-chan int` 的 `Type`:**
   * 输出: `"<-chan int"`
* **输入一个表示 `struct { Name string; Age int }` 的 `Type`:**
   * 输出: `"struct{ Name string; Age int }"`

**命令行参数的具体处理:**

这段代码本身 **不直接处理命令行参数**。它的功能是在 Go 编译器的内部被调用，用于生成类型字符串。命令行参数的处理通常发生在编译器的其他阶段，例如参数解析和配置阶段。 `Qualifier` 的使用允许在不修改核心类型字符串生成逻辑的情况下，根据上下文（例如是否需要显示完整的包路径）来调整输出。

**使用者易犯错的点:**

由于这段代码是编译器内部使用的，普通 Go 开发者不会直接调用这些函数。但是，理解其背后的原理可以帮助理解 Go 语言的类型表示，避免在以下方面产生误解：

1. **包路径的省略:** 当使用 `Qualifier` 时，可能会省略包路径，这在阅读类型信息时需要注意上下文，判断类型是否来自当前包。
2. **泛型类型的表示方式:**  理解泛型类型的表示，例如 `List[int]`，有助于理解泛型的实例化。
3. **通道类型的语法:**  `chan`, `chan<-`, `<-chan` 的区别需要明确。
4. **结构体标签:**  结构体标签会包含在类型字符串中，需要理解其含义。

总而言之，`go/src/cmd/compile/internal/types2/typestring.go` 文件是 Go 语言编译器中一个关键的组成部分，它负责将复杂的类型信息转换为人类可读的字符串形式，这对于编译器的错误报告、调试以及理解 Go 语言的类型系统至关重要。

### 提示词
```
这是路径为go/src/cmd/compile/internal/types2/typestring.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
```

### 源代码
```go
// Copyright 2013 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// This file implements printing of types.

package types2

import (
	"bytes"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"unicode/utf8"
)

// A Qualifier controls how named package-level objects are printed in
// calls to [TypeString], [ObjectString], and [SelectionString].
//
// These three formatting routines call the Qualifier for each
// package-level object O, and if the Qualifier returns a non-empty
// string p, the object is printed in the form p.O.
// If it returns an empty string, only the object name O is printed.
//
// Using a nil Qualifier is equivalent to using (*[Package]).Path: the
// object is qualified by the import path, e.g., "encoding/json.Marshal".
type Qualifier func(*Package) string

// RelativeTo returns a [Qualifier] that fully qualifies members of
// all packages other than pkg.
func RelativeTo(pkg *Package) Qualifier {
	if pkg == nil {
		return nil
	}
	return func(other *Package) string {
		if pkg == other {
			return "" // same package; unqualified
		}
		return other.Path()
	}
}

// TypeString returns the string representation of typ.
// The [Qualifier] controls the printing of
// package-level objects, and may be nil.
func TypeString(typ Type, qf Qualifier) string {
	var buf bytes.Buffer
	WriteType(&buf, typ, qf)
	return buf.String()
}

// WriteType writes the string representation of typ to buf.
// The [Qualifier] controls the printing of
// package-level objects, and may be nil.
func WriteType(buf *bytes.Buffer, typ Type, qf Qualifier) {
	newTypeWriter(buf, qf).typ(typ)
}

// WriteSignature writes the representation of the signature sig to buf,
// without a leading "func" keyword. The [Qualifier] controls the printing
// of package-level objects, and may be nil.
func WriteSignature(buf *bytes.Buffer, sig *Signature, qf Qualifier) {
	newTypeWriter(buf, qf).signature(sig)
}

type typeWriter struct {
	buf          *bytes.Buffer
	seen         map[Type]bool
	qf           Qualifier
	ctxt         *Context       // if non-nil, we are type hashing
	tparams      *TypeParamList // local type parameters
	paramNames   bool           // if set, write function parameter names, otherwise, write types only
	tpSubscripts bool           // if set, write type parameter indices as subscripts
	pkgInfo      bool           // package-annotate first unexported-type field to avoid confusing type description
}

func newTypeWriter(buf *bytes.Buffer, qf Qualifier) *typeWriter {
	return &typeWriter{buf, make(map[Type]bool), qf, nil, nil, true, false, false}
}

func newTypeHasher(buf *bytes.Buffer, ctxt *Context) *typeWriter {
	assert(ctxt != nil)
	return &typeWriter{buf, make(map[Type]bool), nil, ctxt, nil, false, false, false}
}

func (w *typeWriter) byte(b byte) {
	if w.ctxt != nil {
		if b == ' ' {
			b = '#'
		}
		w.buf.WriteByte(b)
		return
	}
	w.buf.WriteByte(b)
	if b == ',' || b == ';' {
		w.buf.WriteByte(' ')
	}
}

func (w *typeWriter) string(s string) {
	w.buf.WriteString(s)
}

func (w *typeWriter) error(msg string) {
	if w.ctxt != nil {
		panic(msg)
	}
	w.buf.WriteString("<" + msg + ">")
}

func (w *typeWriter) typ(typ Type) {
	if w.seen[typ] {
		w.error("cycle to " + goTypeName(typ))
		return
	}
	w.seen[typ] = true
	defer delete(w.seen, typ)

	switch t := typ.(type) {
	case nil:
		w.error("nil")

	case *Basic:
		// exported basic types go into package unsafe
		// (currently this is just unsafe.Pointer)
		if isExported(t.name) {
			if obj, _ := Unsafe.scope.Lookup(t.name).(*TypeName); obj != nil {
				w.typeName(obj)
				break
			}
		}
		w.string(t.name)

	case *Array:
		w.byte('[')
		w.string(strconv.FormatInt(t.len, 10))
		w.byte(']')
		w.typ(t.elem)

	case *Slice:
		w.string("[]")
		w.typ(t.elem)

	case *Struct:
		w.string("struct{")
		for i, f := range t.fields {
			if i > 0 {
				w.byte(';')
			}

			// If disambiguating one struct for another, look for the first unexported field.
			// Do this first in case of nested structs; tag the first-outermost field.
			pkgAnnotate := false
			if w.qf == nil && w.pkgInfo && !isExported(f.name) {
				// note for embedded types, type name is field name, and "string" etc are lower case hence unexported.
				pkgAnnotate = true
				w.pkgInfo = false // only tag once
			}

			// This doesn't do the right thing for embedded type
			// aliases where we should print the alias name, not
			// the aliased type (see go.dev/issue/44410).
			if !f.embedded {
				w.string(f.name)
				w.byte(' ')
			}
			w.typ(f.typ)
			if pkgAnnotate {
				w.string(" /* package ")
				w.string(f.pkg.Path())
				w.string(" */ ")
			}
			if tag := t.Tag(i); tag != "" {
				w.byte(' ')
				// TODO(gri) If tag contains blanks, replacing them with '#'
				//           in Context.TypeHash may produce another tag
				//           accidentally.
				w.string(strconv.Quote(tag))
			}
		}
		w.byte('}')

	case *Pointer:
		w.byte('*')
		w.typ(t.base)

	case *Tuple:
		w.tuple(t, false)

	case *Signature:
		w.string("func")
		w.signature(t)

	case *Union:
		// Unions only appear as (syntactic) embedded elements
		// in interfaces and syntactically cannot be empty.
		if t.Len() == 0 {
			w.error("empty union")
			break
		}
		for i, t := range t.terms {
			if i > 0 {
				w.string(termSep)
			}
			if t.tilde {
				w.byte('~')
			}
			w.typ(t.typ)
		}

	case *Interface:
		if w.ctxt == nil {
			if t == universeAnyAlias.Type().Underlying() {
				// When not hashing, we can try to improve type strings by writing "any"
				// for a type that is pointer-identical to universeAny.
				// TODO(rfindley): this logic should not be necessary with
				// gotypesalias=1. Remove once that is always the case.
				w.string("any")
				break
			}
			if t == asNamed(universeComparable.Type()).underlying {
				w.string("interface{comparable}")
				break
			}
		}
		if t.implicit {
			if len(t.methods) == 0 && len(t.embeddeds) == 1 {
				w.typ(t.embeddeds[0])
				break
			}
			// Something's wrong with the implicit interface.
			// Print it as such and continue.
			w.string("/* implicit */ ")
		}
		w.string("interface{")
		first := true
		if w.ctxt != nil {
			w.typeSet(t.typeSet())
		} else {
			for _, m := range t.methods {
				if !first {
					w.byte(';')
				}
				first = false
				w.string(m.name)
				w.signature(m.typ.(*Signature))
			}
			for _, typ := range t.embeddeds {
				if !first {
					w.byte(';')
				}
				first = false
				w.typ(typ)
			}
		}
		w.byte('}')

	case *Map:
		w.string("map[")
		w.typ(t.key)
		w.byte(']')
		w.typ(t.elem)

	case *Chan:
		var s string
		var parens bool
		switch t.dir {
		case SendRecv:
			s = "chan "
			// chan (<-chan T) requires parentheses
			if c, _ := t.elem.(*Chan); c != nil && c.dir == RecvOnly {
				parens = true
			}
		case SendOnly:
			s = "chan<- "
		case RecvOnly:
			s = "<-chan "
		default:
			w.error("unknown channel direction")
		}
		w.string(s)
		if parens {
			w.byte('(')
		}
		w.typ(t.elem)
		if parens {
			w.byte(')')
		}

	case *Named:
		// If hashing, write a unique prefix for t to represent its identity, since
		// named type identity is pointer identity.
		if w.ctxt != nil {
			w.string(strconv.Itoa(w.ctxt.getID(t)))
		}
		w.typeName(t.obj) // when hashing written for readability of the hash only
		if t.inst != nil {
			// instantiated type
			w.typeList(t.inst.targs.list())
		} else if w.ctxt == nil && t.TypeParams().Len() != 0 { // For type hashing, don't need to format the TypeParams
			// parameterized type
			w.tParamList(t.TypeParams().list())
		}

	case *TypeParam:
		if t.obj == nil {
			w.error("unnamed type parameter")
			break
		}
		if i := slices.Index(w.tparams.list(), t); i >= 0 {
			// The names of type parameters that are declared by the type being
			// hashed are not part of the type identity. Replace them with a
			// placeholder indicating their index.
			w.string(fmt.Sprintf("$%d", i))
		} else {
			w.string(t.obj.name)
			if w.tpSubscripts || w.ctxt != nil {
				w.string(subscript(t.id))
			}
			// If the type parameter name is the same as a predeclared object
			// (say int), point out where it is declared to avoid confusing
			// error messages. This doesn't need to be super-elegant; we just
			// need a clear indication that this is not a predeclared name.
			if w.ctxt == nil && Universe.Lookup(t.obj.name) != nil {
				if isTypes2 {
					w.string(fmt.Sprintf(" /* with %s declared at %v */", t.obj.name, t.obj.Pos()))
				} else {
					// Can't print position information because
					// we don't have a token.FileSet accessible.
					w.string("/* type parameter */")
				}
			}
		}

	case *Alias:
		w.typeName(t.obj)
		if list := t.targs.list(); len(list) != 0 {
			// instantiated type
			w.typeList(list)
		} else if w.ctxt == nil && t.TypeParams().Len() != 0 { // For type hashing, don't need to format the TypeParams
			// parameterized type
			w.tParamList(t.TypeParams().list())
		}
		if w.ctxt != nil {
			// TODO(gri) do we need to print the alias type name, too?
			w.typ(Unalias(t.obj.typ))
		}

	default:
		// For externally defined implementations of Type.
		// Note: In this case cycles won't be caught.
		w.string(t.String())
	}
}

// typeSet writes a canonical hash for an interface type set.
func (w *typeWriter) typeSet(s *_TypeSet) {
	assert(w.ctxt != nil)
	first := true
	for _, m := range s.methods {
		if !first {
			w.byte(';')
		}
		first = false
		w.string(m.name)
		w.signature(m.typ.(*Signature))
	}
	switch {
	case s.terms.isAll():
		// nothing to do
	case s.terms.isEmpty():
		w.string(s.terms.String())
	default:
		var termHashes []string
		for _, term := range s.terms {
			// terms are not canonically sorted, so we sort their hashes instead.
			var buf bytes.Buffer
			if term.tilde {
				buf.WriteByte('~')
			}
			newTypeHasher(&buf, w.ctxt).typ(term.typ)
			termHashes = append(termHashes, buf.String())
		}
		slices.Sort(termHashes)
		if !first {
			w.byte(';')
		}
		w.string(strings.Join(termHashes, "|"))
	}
}

func (w *typeWriter) typeList(list []Type) {
	w.byte('[')
	for i, typ := range list {
		if i > 0 {
			w.byte(',')
		}
		w.typ(typ)
	}
	w.byte(']')
}

func (w *typeWriter) tParamList(list []*TypeParam) {
	w.byte('[')
	var prev Type
	for i, tpar := range list {
		// Determine the type parameter and its constraint.
		// list is expected to hold type parameter names,
		// but don't crash if that's not the case.
		if tpar == nil {
			w.error("nil type parameter")
			continue
		}
		if i > 0 {
			if tpar.bound != prev {
				// bound changed - write previous one before advancing
				w.byte(' ')
				w.typ(prev)
			}
			w.byte(',')
		}
		prev = tpar.bound
		w.typ(tpar)
	}
	if prev != nil {
		w.byte(' ')
		w.typ(prev)
	}
	w.byte(']')
}

func (w *typeWriter) typeName(obj *TypeName) {
	w.string(packagePrefix(obj.pkg, w.qf))
	w.string(obj.name)
}

func (w *typeWriter) tuple(tup *Tuple, variadic bool) {
	w.byte('(')
	if tup != nil {
		for i, v := range tup.vars {
			if i > 0 {
				w.byte(',')
			}
			// parameter names are ignored for type identity and thus type hashes
			if w.ctxt == nil && v.name != "" && w.paramNames {
				w.string(v.name)
				w.byte(' ')
			}
			typ := v.typ
			if variadic && i == len(tup.vars)-1 {
				if s, ok := typ.(*Slice); ok {
					w.string("...")
					typ = s.elem
				} else {
					// special case:
					// append(s, "foo"...) leads to signature func([]byte, string...)
					if t, _ := under(typ).(*Basic); t == nil || t.kind != String {
						w.error("expected string type")
						continue
					}
					w.typ(typ)
					w.string("...")
					continue
				}
			}
			w.typ(typ)
		}
	}
	w.byte(')')
}

func (w *typeWriter) signature(sig *Signature) {
	if sig.TypeParams().Len() != 0 {
		if w.ctxt != nil {
			assert(w.tparams == nil)
			w.tparams = sig.TypeParams()
			defer func() {
				w.tparams = nil
			}()
		}
		w.tParamList(sig.TypeParams().list())
	}

	w.tuple(sig.params, sig.variadic)

	n := sig.results.Len()
	if n == 0 {
		// no result
		return
	}

	w.byte(' ')
	if n == 1 && (w.ctxt != nil || sig.results.vars[0].name == "") {
		// single unnamed result (if type hashing, name must be ignored)
		w.typ(sig.results.vars[0].typ)
		return
	}

	// multiple or named result(s)
	w.tuple(sig.results, false)
}

// subscript returns the decimal (utf8) representation of x using subscript digits.
func subscript(x uint64) string {
	const w = len("₀") // all digits 0...9 have the same utf8 width
	var buf [32 * w]byte
	i := len(buf)
	for {
		i -= w
		utf8.EncodeRune(buf[i:], '₀'+rune(x%10)) // '₀' == U+2080
		x /= 10
		if x == 0 {
			break
		}
	}
	return string(buf[i:])
}
```