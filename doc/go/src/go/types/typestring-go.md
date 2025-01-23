Response:
The user wants to understand the functionality of the provided Go code snippet from `go/src/go/types/typestring.go`. I need to:

1. **List the functions and their purposes.**  Focus on the core task of converting `types.Type` objects into string representations.
2. **Infer the overall Go feature being implemented.** This involves recognizing the pattern of converting internal type representations to human-readable strings.
3. **Provide Go code examples.** Illustrate how to use the key functions like `TypeString`.
4. **Address code reasoning, including input and output.**  Show examples of converting different types to strings.
5. **Explain command-line parameters (if applicable).**  The code mentions `go test -run=Generate -write=all`, so I should explain its role, even if it's related to code generation and not direct usage of these functions.
6. **Identify potential pitfalls for users.** Think about common mistakes when trying to represent types as strings.
7. **Answer in Chinese.** Ensure all explanations and examples are in Chinese.
这段代码是 Go 语言 `go/types` 包中 `typestring.go` 文件的一部分，它的主要功能是**将 Go 语言的类型（`types.Type`）转换为字符串表示形式**。 这在很多场景下都非常有用，比如调试、错误信息展示、代码生成等。

更具体地说，它实现了以下功能：

1. **`Qualifier` 类型和相关函数 `RelativeTo`**:
   - `Qualifier` 是一个函数类型，用于控制在类型字符串中如何打印包级别的对象。
   - 当 `TypeString`、`ObjectString` 和 `SelectionString` 这些格式化函数遇到包级别的对象时，会调用 `Qualifier`。
   - 如果 `Qualifier` 返回一个非空字符串 `p`，则对象会以 `p.O` 的形式打印（`O` 是对象名）。
   - 如果返回空字符串，则只打印对象名 `O`。
   - `RelativeTo(pkg *Package)` 函数返回一个 `Qualifier`，它会完全限定除 `pkg` 之外的所有包的成员。这意味着对于同一个包内的类型，不会包含包路径，而对于其他包的类型，会加上包路径。

2. **`TypeString(typ Type, qf Qualifier) string`**:
   - 这是将一个 `types.Type` 类型转换为字符串的主要函数。
   - 它接受一个 `types.Type` 类型的参数 `typ` 和一个可选的 `Qualifier` 函数 `qf`。
   - 它使用 `WriteType` 函数将类型写入一个 `bytes.Buffer`，然后返回缓冲区的内容。

3. **`WriteType(buf *bytes.Buffer, typ Type, qf Qualifier)`**:
   -  将 `types.Type` 类型 `typ` 的字符串表示形式写入提供的 `bytes.Buffer` `buf`。
   -  它也接受一个可选的 `Qualifier` 函数 `qf`。
   -  它内部使用 `typeWriter` 结构体来完成实际的类型写入工作。

4. **`WriteSignature(buf *bytes.Buffer, sig *Signature, qf Qualifier)`**:
   - 将函数签名 `sig` 的字符串表示形式写入提供的 `bytes.Buffer` `buf`，但不包含前导的 "func" 关键字。
   - 它也接受一个可选的 `Qualifier` 函数 `qf`。

5. **`typeWriter` 结构体和相关方法**:
   - `typeWriter` 是一个核心结构体，负责实际的类型字符串生成。
   - 它维护了已访问类型的 `seen` 映射，用于检测循环引用。
   - 它持有一个 `Qualifier` 函数 `qf`。
   - `typ(typ Type)` 方法是递归地将各种类型的 `types.Type` 转换为字符串的关键方法，它会根据类型的不同进行不同的处理，例如：
     - `*Basic`: 基本类型（如 `int`, `string`）。
     - `*Array`: 数组类型。
     - `*Slice`: 切片类型。
     - `*Struct`: 结构体类型。
     - `*Pointer`: 指针类型。
     - `*Tuple`: 元组类型（例如函数参数列表）。
     - `*Signature`: 函数签名。
     - `*Interface`: 接口类型。
     - `*Map`: 映射类型。
     - `*Chan`: 通道类型。
     - `*Named`: 命名类型（通过 `type` 关键字定义的类型）。
     - `*TypeParam`: 类型参数（用于泛型）。
     - `*Alias`: 类型别名。
   - 其他辅助方法如 `byte`, `string`, `error`, `tuple`, `signature`, `typeList`, `tParamList`, `typeName` 等用于构建字符串的不同部分。

**推理解释：**

这段代码的核心目的是实现 Go 语言类型系统的反射和字符串表示。它允许程序在运行时获取类型信息并将其转换为易于理解的字符串。这对于很多工具和框架至关重要，例如：

- **`fmt` 包的格式化输出**: 当你使用 `%T` 格式化动词打印一个变量的类型时，`fmt` 包内部会使用类似的功能来获取类型的字符串表示。
- **`reflect` 包**: 虽然 `reflect` 包提供了更底层的类型信息访问，但 `typestring` 提供的字符串表示是其输出的一种常见形式。
- **代码生成工具**: 许多代码生成工具需要将类型信息转换为字符串，以便生成相应的代码。
- **调试器和错误报告**: 在调试或查看错误信息时，清晰地展示类型信息对于理解问题非常有帮助。

**Go 代码示例：**

```go
package main

import (
	"bytes"
	"fmt"
	"go/types"
)

func main() {
	// 基本类型
	fmt.Println(types.TypeString(types.Typ[types.Int], nil)) // Output: int

	// 结构体类型
	fields := []*types.Var{
		types.NewField(0, nil, "Name", types.Typ[types.String], false),
		types.NewField(0, nil, "Age", types.Typ[types.Int], false),
	}
	st := types.NewStruct(fields, nil)
	fmt.Println(types.TypeString(st, nil)) // Output: struct{Name string; Age int}

	// 指针类型
	ptr := types.NewPointer(types.Typ[types.Int])
	fmt.Println(types.TypeString(ptr, nil)) // Output: *int

	// 切片类型
	slice := types.NewSlice(types.Typ[types.String])
	fmt.Println(types.TypeString(slice, nil)) // Output: []string

	// 函数类型
	params := types.NewTuple(types.NewVar(0, nil, "", types.Typ[types.Int]))
	results := types.NewTuple(types.NewVar(0, nil, "", types.Typ[types.String]))
	sig := types.NewSignature(nil, params, results, false)
	fmt.Println(types.TypeString(sig, nil)) // Output: func(int) string

	// 使用 Qualifier 控制输出
	pkg := types.NewPackage("example.com/mypackage", "mypackage")
	obj := types.NewTypeName(0, pkg, "MyType", types.Typ[types.Int])
	named := types.NewNamed(obj, types.Typ[types.Int], nil)

	// 使用 nil Qualifier (默认使用包路径)
	fmt.Println(types.TypeString(named, nil)) // Output: example.com/mypackage.MyType

	// 使用 RelativeTo Qualifier，对于当前包不加路径
	fmt.Println(types.TypeString(named, types.RelativeTo(pkg))) // Output: MyType
}
```

**代码推理（带假设的输入与输出）：**

假设我们有以下类型：

**输入类型 (Go 代码):**

```go
package main

import "go/types"

func getType() types.Type {
	fields := []*types.Var{
		types.NewField(0, nil, "Data", types.NewSlice(types.Typ[types.Int]), false),
	}
	return types.NewStruct(fields, nil)
}
```

**调用 `TypeString`:**

```go
package main

import (
	"fmt"
	"go/types"
)

func getType() types.Type {
	fields := []*types.Var{
		types.NewField(0, nil, "Data", types.NewSlice(types.Typ[types.Int]), false),
	}
	return types.NewStruct(fields, nil)
}

func main() {
	typ := getType()
	fmt.Println(types.TypeString(typ, nil))
}
```

**输出结果:**

```
struct{Data []int}
```

**推理过程:**

1. `getType()` 函数创建了一个结构体类型，该结构体有一个名为 `Data` 的字段，其类型为 `[]int` (int 类型的切片)。
2. `TypeString` 函数接收这个结构体类型作为输入。
3. `typeWriter` 内部会遍历结构体的字段。
4. 对于 `Data` 字段，它会先输出字段名 "Data"，然后输出字段类型 `[]int`。
5. 最终将整个结构体的字符串表示形式 "struct{Data []int}" 输出。

**命令行参数的具体处理:**

代码开头的注释 `// Code generated by "go test -run=Generate -write=all"; DO NOT EDIT.` 表明这个文件是通过一个 Go 测试命令生成的。

- **`go test`**:  这是 Go 语言的测试命令。
- **`-run=Generate`**:  指定要运行的测试函数或正则表达式。在这里，它表示运行名为 `Generate` 的测试函数。这个测试函数很可能负责生成 `typestring.go` 文件。
- **`-write=all`**:  这是一个测试标志，指示测试在运行时可以写入文件。在这种情况下，它允许 `Generate` 测试函数将生成的代码写入 `typestring.go` 文件。

这些命令行参数并不是 `typestring.go` 中函数直接处理的，而是用于生成这个文件的过程。`typestring.go` 自身的功能是将 `types.Type` 转换为字符串，而它的代码是由 `go test` 命令生成的。

**使用者易犯错的点：**

一个常见的易错点是**对 `Qualifier` 的理解和使用**。如果不理解 `Qualifier` 的作用，可能会在不同的场景下得到不一致的类型字符串表示。

**例子：**

假设你在一个包 `mypackage` 中定义了一个类型 `MyInt`，它实际上是 `int` 的别名。

```go
package mypackage

type MyInt int
```

现在，在另一个包中，你想要打印 `mypackage.MyInt` 的类型字符串：

```go
package main

import (
	"fmt"
	"go/types"
	"mypackage"
)

func main() {
	// 获取 mypackage.MyInt 的类型
	scope := types.NewScope(nil, 0, 0, "mypackage")
	myIntObj := types.NewTypeName(0, nil, "MyInt", types.Typ[types.Int])
	scope.Insert(myIntObj)
	named := types.NewNamed(myIntObj, types.Typ[types.Int], nil)

	// 使用 nil Qualifier
	fmt.Println(types.TypeString(named, nil)) // Output: mypackage.MyInt

	// 使用 RelativeTo(nil) Qualifier，效果和 nil 相同
	fmt.Println(types.TypeString(named, types.RelativeTo(nil))) // Output: mypackage.MyInt

	// 使用 RelativeTo(mypackage 的 Package 对象)
	pkg := types.NewPackage("yourmodule/mypackage", "mypackage") // 需要创建 Package 对象
	fmt.Println(types.TypeString(named, types.RelativeTo(pkg))) // Output: MyInt
}
```

在这个例子中，如果不理解 `RelativeTo` 的作用，可能会疑惑为什么在某些情况下会打印完整的包路径，而在另一些情况下只打印类型名。错误地使用 `Qualifier` 可能会导致生成的类型字符串不符合预期，从而在依赖这些字符串的工具中引发问题。例如，代码生成器可能会错误地生成重复的类型定义。

### 提示词
```
这是路径为go/src/go/types/typestring.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
```

### 源代码
```go
// Code generated by "go test -run=Generate -write=all"; DO NOT EDIT.
// Source: ../../cmd/compile/internal/types2/typestring.go

// Copyright 2013 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// This file implements printing of types.

package types

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