Response:
Let's break down the thought process for summarizing the provided Go code snippet.

1. **Understand the Goal:** The request asks for a summary of the functionality of the provided Go code, which is a part of `go/src/go/types/api_test.go`. This immediately tells us it's a testing file within the Go compiler's type checking system.

2. **Initial Scan and Keywords:** Quickly scan the code looking for keywords that indicate the purpose of the tests. Keywords like `Test`, `Info`, `Defs`, `Uses`, `Instances`, `Selections`, `Implicits`, `InitOrder`, `Scopes`, `PkgNameOf`, `PredicatesInfo`, `GenericMethodInfo`, `MultiFileInitOrder`, `Files`, `Selection` stand out. These are clearly the main areas being tested.

3. **Group Related Tests:**  Observe that many test functions relate to specific fields within the `Info` struct used during type checking. Group these together:
    * `TestInstances`:  Deals with instantiation of generic types.
    * `TestDefsInfo`: Focuses on definitions of objects.
    * `TestUsesInfo`: Focuses on the uses of objects.
    * `TestImplicitsInfo`:  Examines implicitly declared objects.
    * `TestScopesInfo`:  Verifies the creation and structure of scopes.
    * `TestInitOrderInfo` and `TestMultiFileInitOrder`:  Check the order of initialization of variables.
    * `TestSelection`:  Tests the selection of fields and methods.
    * `TestPkgNameOf`:  Verifies the retrieval of package names.
    * `TestPredicatesInfo`: Checks properties of expressions like "void," "type," etc.
    * `TestGenericMethodInfo`: Specifically tests information related to generic methods.
    * `TestFiles`: Tests the scenario of type-checking across multiple files.

4. **Identify Common Structures:** Notice the recurring pattern in most test functions:
    * Define a `tests` slice of structs.
    * Each struct contains a `src` field (Go source code).
    * Many also have `want` or similar fields representing the expected outcome.
    * Iterate through the `tests`.
    * Create an `Info` struct, often initializing specific fields like `Defs`, `Uses`, etc.
    * Call `typecheck` (or a similar function) to perform type checking on the `src`.
    * Assertions are made based on the content of the `Info` struct or other returned values.

5. **Infer High-Level Functionality:** Based on the grouped tests and common structures, infer the overall purpose: This file tests the `go/types` package's ability to correctly collect and expose information about Go code during the type-checking process. This includes:
    * Identifying where variables, functions, and types are *defined*.
    * Identifying where these elements are *used*.
    * Handling the complexities of *generic types* and their instantiation.
    * Understanding the *scope* in which identifiers are valid.
    * Determining the *order* in which variables are initialized.
    * Resolving *selections* (accessing fields and methods).
    * Identifying *implicit* declarations.
    * Determining the *properties* of expressions.

6. **Formulate the Summary:** Combine the inferences into a concise summary. Use clear and informative language. Emphasize the "information gathering" aspect of the tests. Mention the specific types of information being collected.

7. **Refine and Organize:**  Review the summary for clarity and accuracy. Ensure it flows logically. Group similar functionalities together in the summary. For instance, group tests related to the `Info` struct.

8. **Self-Correction/Double-Check:**  Read the original code snippet again to ensure no major functionalities were missed or misinterpreted. Verify that the summary accurately reflects the types of tests being performed. For example, ensure the summary mentions generics since several tests focus on them.

By following these steps, we can arrive at a comprehensive and accurate summary like the example provided in the prompt's answer. The process is iterative, starting with a broad understanding and gradually refining the details based on closer examination of the code.
这段代码是Go语言类型检查器(`go/types`)的一部分，专门用于测试类型检查器在处理**泛型实例化**和收集相关信息时的正确性。具体来说，它测试了类型检查器能否正确地**反向推断泛型函数的类型实参**。

**功能归纳：**

这段代码的主要功能是测试 `go/types` 包的类型检查器在处理泛型函数调用时，能否根据上下文（函数签名、赋值目标等）**反向推断出泛型函数的类型参数**。  它验证了类型检查器在不同的场景下，能否正确地确定泛型函数应该使用哪些具体的类型参数。

**更详细的解释：**

* **测试用例设计：** 代码中定义了一个名为 `TestInstances` 的测试函数，其中包含一个 `tests` 切片。每个 `test` 结构体代表一个独立的测试用例。
    * `src string`:  包含一段 Go 源代码，这段代码通常会调用一个或多个泛型函数。
    * `instances []testInst`:  期望在类型检查过程中生成的泛型实例化信息。 `testInst` 结构体包含了：
        * `name string`:  被实例化的泛型函数的名称。
        * `targs []string`:  期望推断出的类型实参列表（字符串形式）。
        * `typ string`:  期望的实例化后的函数类型（字符串形式）。

* **类型检查过程模拟：**  在每个测试用例中，代码会：
    1. 创建一个自定义的 `testImporter`，用于模拟导入其他包。
    2. 创建一个 `Config` 结构体，并设置 `Importer`。
    3. 创建 `instMap` 和 `useMap`，用于存储类型检查器收集到的实例化信息和使用信息。
    4. 定义 `makePkg` 函数，用于对给定的源代码进行类型检查，并将收集到的实例化信息和使用信息存储到 `instMap` 和 `useMap` 中。
    5. 首先对一个名为 `lib` 的基础库代码进行类型检查（尽管在这个特定的代码片段中 `lib` 的内容是固定的，但在更完整的测试文件中可能会有更复杂的 `lib` 代码）。
    6. 然后对当前测试用例的 `src` 代码进行类型检查。

* **断言和验证：**  测试的核心部分是对类型检查器产生的 `instMap` 中的泛型实例化信息进行验证：
    1. 对比实际生成的实例化数量和期望的数量。
    2. 遍历每个实际生成的实例化信息，并与期望的实例化信息进行逐项比较：
        * 比较泛型函数的名称。
        * 比较推断出的类型实参列表。
        * 比较实例化后的函数类型。
    3. 此外，代码还验证了一个重要的不变量：使用推断出的类型实参重新实例化泛型函数，应该得到与之前相同的实例化结果。 这通过调用 `Instantiate` 函数并比较结果来实现。

**Go 代码示例说明反向推断：**

假设我们有以下 Go 代码（对应于测试用例中的一个）：

```go
package reverse1a

func f(func(int, string)) {}

func g[P, Q any](P, Q) {}

func _() {
	f(g) // 在这里，类型检查器需要推断出 g 的类型实参
}
```

在这个例子中，`f` 函数接受一个类型为 `func(int, string)` 的函数作为参数。 `g` 是一个泛型函数，它接受两个任意类型的参数。  当我们将 `g` 作为参数传递给 `f` 时，类型检查器会分析 `f` 的参数类型，并尝试将 `g` 的类型参数 `P` 和 `Q` 与 `func(int, string)` 的参数类型进行匹配。

**假设的输入与输出：**

* **输入 (源代码):**  上面 `reverse1a` 包的源代码。
* **类型检查器的处理:**  类型检查器分析 `f(g)` 这行代码。 它知道 `f` 期望的参数类型是 `func(int, string)`。
* **推理:**  由于 `g` 是一个泛型函数 `func[P, Q any](P, Q)`，为了让 `g` 能够作为 `f` 的参数，`g` 必须被实例化为 `func(int, string)`。 这意味着 `P` 应该被推断为 `int`，`Q` 应该被推断为 `string`。
* **期望的输出 (测试断言):**  测试代码会断言 `instMap` 中包含对 `g` 的实例化信息，其中类型参数为 `["int", "string"]`，实例化后的类型为 `func(int, string)`。

**命令行参数：**

这段代码本身是 Go 源代码，不直接涉及命令行参数的处理。它是一个测试文件，通常会通过 `go test` 命令来运行。  `go test` 命令会编译并运行测试文件中的测试函数。

**易犯错的点：**

这段代码主要用于测试类型检查器的内部逻辑，用户一般不会直接与这段代码交互。  然而，从测试用例的角度来看，一些容易出错的点体现在：

* **泛型类型参数推断失败：**  在某些复杂的泛型函数调用场景中，类型检查器可能无法唯一确定类型参数，导致编译错误。 测试用例覆盖了各种推断场景，旨在确保类型检查器在这些情况下能够正确工作。
* **对泛型类型约束理解不透彻：**  Go 的泛型允许使用类型约束来限制类型参数的可能类型。 如果对类型约束的理解有偏差，可能会导致在编写或理解涉及泛型的代码时出现错误。

**这段代码 (第2部分) 的功能归纳：**

这段代码专门测试了 `go/types` 包在处理泛型函数实例化时**反向推断类型实参**的功能。 它通过一系列精心设计的测试用例，验证了类型检查器能否在不同的上下文中（例如，函数参数传递、变量赋值等）正确地推断出泛型函数的类型参数，并生成正确的实例化信息。  这是确保 Go 语言泛型功能正确实现的关键测试部分。

### 提示词
```
这是路径为go/src/go/types/api_test.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第2部分，共4部分，请归纳一下它的功能
```

### 源代码
```go
(int, string)`}},
		},
		{`package reverse2c; func f(func(int, string)) {}; func g[P, Q any](P, Q) {}; func _() { f(g[int]) }`,
			[]testInst{{`g`, []string{`int`, `string`}, `func(int, string)`}},
		},
		// reverse3a not possible (cannot assign to generic function outside of argument passing)
		{`package reverse3b; func f[R any](func(int) R) {}; func g[P any](P) string { return "" }; func _() { f(g) }`,
			[]testInst{
				{`f`, []string{`string`}, `func(func(int) string)`},
				{`g`, []string{`int`}, `func(int) string`},
			},
		},
		{`package reverse4a; var _, _ func([]int, *float32) = g, h; func g[P, Q any]([]P, *Q) {}; func h[R any]([]R, *float32) {}`,
			[]testInst{
				{`g`, []string{`int`, `float32`}, `func([]int, *float32)`},
				{`h`, []string{`int`}, `func([]int, *float32)`},
			},
		},
		{`package reverse4b; func f(_, _ func([]int, *float32)) {}; func g[P, Q any]([]P, *Q) {}; func h[R any]([]R, *float32) {}; func _() { f(g, h) }`,
			[]testInst{
				{`g`, []string{`int`, `float32`}, `func([]int, *float32)`},
				{`h`, []string{`int`}, `func([]int, *float32)`},
			},
		},
		{`package issue59956; func f(func(int), func(string), func(bool)) {}; func g[P any](P) {}; func _() { f(g, g, g) }`,
			[]testInst{
				{`g`, []string{`int`}, `func(int)`},
				{`g`, []string{`string`}, `func(string)`},
				{`g`, []string{`bool`}, `func(bool)`},
			},
		},
	}

	for _, test := range tests {
		imports := make(testImporter)
		conf := Config{Importer: imports}
		instMap := make(map[*ast.Ident]Instance)
		useMap := make(map[*ast.Ident]Object)
		makePkg := func(src string) *Package {
			pkg, err := typecheck(src, &conf, &Info{Instances: instMap, Uses: useMap})
			// allow error for issue51803
			if err != nil && (pkg == nil || pkg.Name() != "issue51803") {
				t.Fatal(err)
			}
			imports[pkg.Name()] = pkg
			return pkg
		}
		makePkg(lib)
		pkg := makePkg(test.src)

		t.Run(pkg.Name(), func(t *testing.T) {
			// Sort instances in source order for stability.
			instances := sortedInstances(instMap)
			if got, want := len(instances), len(test.instances); got != want {
				t.Fatalf("got %d instances, want %d", got, want)
			}

			// Pairwise compare with the expected instances.
			for ii, inst := range instances {
				var targs []Type
				for i := 0; i < inst.Inst.TypeArgs.Len(); i++ {
					targs = append(targs, inst.Inst.TypeArgs.At(i))
				}
				typ := inst.Inst.Type

				testInst := test.instances[ii]
				if got := inst.Ident.Name; got != testInst.name {
					t.Fatalf("got name %s, want %s", got, testInst.name)
				}
				if len(targs) != len(testInst.targs) {
					t.Fatalf("got %d type arguments; want %d", len(targs), len(testInst.targs))
				}
				for i, targ := range targs {
					if got := targ.String(); got != testInst.targs[i] {
						t.Errorf("type argument %d: got %s; want %s", i, got, testInst.targs[i])
					}
				}
				if got := typ.Underlying().String(); got != testInst.typ {
					t.Errorf("package %s: got %s; want %s", pkg.Name(), got, testInst.typ)
				}

				// Verify the invariant that re-instantiating the corresponding generic
				// type with TypeArgs results in an identical instance.
				ptype := useMap[inst.Ident].Type()
				lister, _ := ptype.(interface{ TypeParams() *TypeParamList })
				if lister == nil || lister.TypeParams().Len() == 0 {
					t.Fatalf("info.Types[%v] = %v, want parameterized type", inst.Ident, ptype)
				}
				inst2, err := Instantiate(nil, ptype, targs, true)
				if err != nil {
					t.Errorf("Instantiate(%v, %v) failed: %v", ptype, targs, err)
				}
				if !Identical(inst.Inst.Type, inst2) {
					t.Errorf("%v and %v are not identical", inst.Inst.Type, inst2)
				}
			}
		})
	}
}

type recordedInstance struct {
	Ident *ast.Ident
	Inst  Instance
}

func sortedInstances(m map[*ast.Ident]Instance) (instances []recordedInstance) {
	for id, inst := range m {
		instances = append(instances, recordedInstance{id, inst})
	}
	slices.SortFunc(instances, func(a, b recordedInstance) int {
		return CmpPos(a.Ident.Pos(), b.Ident.Pos())
	})
	return instances
}

func TestDefsInfo(t *testing.T) {
	var tests = []struct {
		src  string
		obj  string
		want string
	}{
		{`package p0; const x = 42`, `x`, `const p0.x untyped int`},
		{`package p1; const x int = 42`, `x`, `const p1.x int`},
		{`package p2; var x int`, `x`, `var p2.x int`},
		{`package p3; type x int`, `x`, `type p3.x int`},
		{`package p4; func f()`, `f`, `func p4.f()`},
		{`package p5; func f() int { x, _ := 1, 2; return x }`, `_`, `var _ int`},

		// Tests using generics.
		{`package g0; type x[T any] int`, `x`, `type g0.x[T any] int`},
		{`package g1; func f[T any]() {}`, `f`, `func g1.f[T any]()`},
		{`package g2; type x[T any] int; func (*x[_]) m() {}`, `m`, `func (*g2.x[_]).m()`},

		// Type parameters in receiver type expressions are definitions.
		{`package r0; type T[_ any] int; func (T[P]) _() {}`, `P`, `type parameter P any`},
		{`package r1; type T[_, _ any] int; func (T[P, Q]) _() {}`, `P`, `type parameter P any`},
		{`package r2; type T[_, _ any] int; func (T[P, Q]) _() {}`, `Q`, `type parameter Q any`},
	}

	for _, test := range tests {
		info := Info{
			Defs: make(map[*ast.Ident]Object),
		}
		name := mustTypecheck(test.src, nil, &info).Name()

		// find object
		var def Object
		for id, obj := range info.Defs {
			if id.Name == test.obj {
				def = obj
				break
			}
		}
		if def == nil {
			t.Errorf("package %s: %s not found", name, test.obj)
			continue
		}

		if got := def.String(); got != test.want {
			t.Errorf("package %s: got %s; want %s", name, got, test.want)
		}
	}
}

func TestUsesInfo(t *testing.T) {
	var tests = []struct {
		src  string
		obj  string
		want string
	}{
		{`package p0; func _() { _ = x }; const x = 42`, `x`, `const p0.x untyped int`},
		{`package p1; func _() { _ = x }; const x int = 42`, `x`, `const p1.x int`},
		{`package p2; func _() { _ = x }; var x int`, `x`, `var p2.x int`},
		{`package p3; func _() { type _ x }; type x int`, `x`, `type p3.x int`},
		{`package p4; func _() { _ = f }; func f()`, `f`, `func p4.f()`},

		// Tests using generics.
		{`package g0; func _[T any]() { _ = x }; const x = 42`, `x`, `const g0.x untyped int`},
		{`package g1; func _[T any](x T) { }`, `T`, `type parameter T any`},
		{`package g2; type N[A any] int; var _ N[int]`, `N`, `type g2.N[A any] int`},
		{`package g3; type N[A any] int; func (N[_]) m() {}`, `N`, `type g3.N[A any] int`},

		// Uses of fields are instantiated.
		{`package s1; type N[A any] struct{ a A }; var f = N[int]{}.a`, `a`, `field a int`},
		{`package s2; type N[A any] struct{ a A }; func (r N[B]) m(b B) { r.a = b }`, `a`, `field a B`},

		// Uses of methods are uses of the instantiated method.
		{`package m0; type N[A any] int; func (r N[B]) m() { r.n() }; func (N[C]) n() {}`, `n`, `func (m0.N[B]).n()`},
		{`package m1; type N[A any] int; func (r N[B]) m() { }; var f = N[int].m`, `m`, `func (m1.N[int]).m()`},
		{`package m2; func _[A any](v interface{ m() A }) { v.m() }`, `m`, `func (interface).m() A`},
		{`package m3; func f[A any]() interface{ m() A } { return nil }; var _ = f[int]().m()`, `m`, `func (interface).m() int`},
		{`package m4; type T[A any] func() interface{ m() A }; var x T[int]; var y = x().m`, `m`, `func (interface).m() int`},
		{`package m5; type T[A any] interface{ m() A }; func _[B any](t T[B]) { t.m() }`, `m`, `func (m5.T[B]).m() B`},
		{`package m6; type T[A any] interface{ m() }; func _[B any](t T[B]) { t.m() }`, `m`, `func (m6.T[B]).m()`},
		{`package m7; type T[A any] interface{ m() A }; func _(t T[int]) { t.m() }`, `m`, `func (m7.T[int]).m() int`},
		{`package m8; type T[A any] interface{ m() }; func _(t T[int]) { t.m() }`, `m`, `func (m8.T[int]).m()`},
		{`package m9; type T[A any] interface{ m() }; func _(t T[int]) { _ = t.m }`, `m`, `func (m9.T[int]).m()`},
		{
			`package m10; type E[A any] interface{ m() }; type T[B any] interface{ E[B]; n() }; func _(t T[int]) { t.m() }`,
			`m`,
			`func (m10.E[int]).m()`,
		},
		{`package m11; type T[A any] interface{ m(); n() }; func _(t1 T[int], t2 T[string]) { t1.m(); t2.n() }`, `m`, `func (m11.T[int]).m()`},
		{`package m12; type T[A any] interface{ m(); n() }; func _(t1 T[int], t2 T[string]) { t1.m(); t2.n() }`, `n`, `func (m12.T[string]).n()`},

		// For historic reasons, type parameters in receiver type expressions
		// are considered both definitions and uses (see go.dev/issue/68670).
		{`package r0; type T[_ any] int; func (T[P]) _() {}`, `P`, `type parameter P any`},
		{`package r1; type T[_, _ any] int; func (T[P, Q]) _() {}`, `P`, `type parameter P any`},
		{`package r2; type T[_, _ any] int; func (T[P, Q]) _() {}`, `Q`, `type parameter Q any`},
	}

	for _, test := range tests {
		info := Info{
			Uses: make(map[*ast.Ident]Object),
		}
		name := mustTypecheck(test.src, nil, &info).Name()

		// find object
		var use Object
		for id, obj := range info.Uses {
			if id.Name == test.obj {
				if use != nil {
					panic(fmt.Sprintf("multiple uses of %q", id.Name))
				}
				use = obj
			}
		}
		if use == nil {
			t.Errorf("package %s: %s not found", name, test.obj)
			continue
		}

		if got := use.String(); got != test.want {
			t.Errorf("package %s: got %s; want %s", name, got, test.want)
		}
	}
}

func TestGenericMethodInfo(t *testing.T) {
	src := `package p

type N[A any] int

func (r N[B]) m() { r.m(); r.n() }

func (r *N[C]) n() {  }
`
	fset := token.NewFileSet()
	f := mustParse(fset, src)
	info := Info{
		Defs:       make(map[*ast.Ident]Object),
		Uses:       make(map[*ast.Ident]Object),
		Selections: make(map[*ast.SelectorExpr]*Selection),
	}
	var conf Config
	pkg, err := conf.Check("p", fset, []*ast.File{f}, &info)
	if err != nil {
		t.Fatal(err)
	}

	N := pkg.Scope().Lookup("N").Type().(*Named)

	// Find the generic methods stored on N.
	gm, gn := N.Method(0), N.Method(1)
	if gm.Name() == "n" {
		gm, gn = gn, gm
	}

	// Collect objects from info.
	var dm, dn *Func   // the declared methods
	var dmm, dmn *Func // the methods used in the body of m
	for _, decl := range f.Decls {
		fdecl, ok := decl.(*ast.FuncDecl)
		if !ok {
			continue
		}
		def := info.Defs[fdecl.Name].(*Func)
		switch fdecl.Name.Name {
		case "m":
			dm = def
			ast.Inspect(fdecl.Body, func(n ast.Node) bool {
				if call, ok := n.(*ast.CallExpr); ok {
					sel := call.Fun.(*ast.SelectorExpr)
					use := info.Uses[sel.Sel].(*Func)
					selection := info.Selections[sel]
					if selection.Kind() != MethodVal {
						t.Errorf("Selection kind = %v, want %v", selection.Kind(), MethodVal)
					}
					if selection.Obj() != use {
						t.Errorf("info.Selections contains %v, want %v", selection.Obj(), use)
					}
					switch sel.Sel.Name {
					case "m":
						dmm = use
					case "n":
						dmn = use
					}
				}
				return true
			})
		case "n":
			dn = def
		}
	}

	if gm != dm {
		t.Errorf(`N.Method(...) returns %v for "m", but Info.Defs has %v`, gm, dm)
	}
	if gn != dn {
		t.Errorf(`N.Method(...) returns %v for "m", but Info.Defs has %v`, gm, dm)
	}
	if dmm != dm {
		t.Errorf(`Inside "m", r.m uses %v, want the defined func %v`, dmm, dm)
	}
	if dmn == dn {
		t.Errorf(`Inside "m", r.n uses %v, want a func distinct from %v`, dmm, dm)
	}
}

func TestImplicitsInfo(t *testing.T) {
	testenv.MustHaveGoBuild(t)

	var tests = []struct {
		src  string
		want string
	}{
		{`package p2; import . "fmt"; var _ = Println`, ""},           // no Implicits entry
		{`package p0; import local "fmt"; var _ = local.Println`, ""}, // no Implicits entry
		{`package p1; import "fmt"; var _ = fmt.Println`, "importSpec: package fmt"},

		{`package p3; func f(x interface{}) { switch x.(type) { case int: } }`, ""}, // no Implicits entry
		{`package p4; func f(x interface{}) { switch t := x.(type) { case int: _ = t } }`, "caseClause: var t int"},
		{`package p5; func f(x interface{}) { switch t := x.(type) { case int, uint: _ = t } }`, "caseClause: var t interface{}"},
		{`package p6; func f(x interface{}) { switch t := x.(type) { default: _ = t } }`, "caseClause: var t interface{}"},

		{`package p7; func f(x int) {}`, ""}, // no Implicits entry
		{`package p8; func f(int) {}`, "field: var  int"},
		{`package p9; func f() (complex64) { return 0 }`, "field: var  complex64"},
		{`package p10; type T struct{}; func (*T) f() {}`, "field: var  *p10.T"},

		// Tests using generics.
		{`package f0; func f[T any](x int) {}`, ""}, // no Implicits entry
		{`package f1; func f[T any](int) {}`, "field: var  int"},
		{`package f2; func f[T any](T) {}`, "field: var  T"},
		{`package f3; func f[T any]() (complex64) { return 0 }`, "field: var  complex64"},
		{`package f4; func f[T any](t T) (T) { return t }`, "field: var  T"},
		{`package t0; type T[A any] struct{}; func (*T[_]) f() {}`, "field: var  *t0.T[_]"},
		{`package t1; type T[A any] struct{}; func _(x interface{}) { switch t := x.(type) { case T[int]: _ = t } }`, "caseClause: var t t1.T[int]"},
		{`package t2; type T[A any] struct{}; func _[P any](x interface{}) { switch t := x.(type) { case T[P]: _ = t } }`, "caseClause: var t t2.T[P]"},
		{`package t3; func _[P any](x interface{}) { switch t := x.(type) { case P: _ = t } }`, "caseClause: var t P"},
	}

	for _, test := range tests {
		info := Info{
			Implicits: make(map[ast.Node]Object),
		}
		name := mustTypecheck(test.src, nil, &info).Name()

		// the test cases expect at most one Implicits entry
		if len(info.Implicits) > 1 {
			t.Errorf("package %s: %d Implicits entries found", name, len(info.Implicits))
			continue
		}

		// extract Implicits entry, if any
		var got string
		for n, obj := range info.Implicits {
			switch x := n.(type) {
			case *ast.ImportSpec:
				got = "importSpec"
			case *ast.CaseClause:
				got = "caseClause"
			case *ast.Field:
				got = "field"
			default:
				t.Fatalf("package %s: unexpected %T", name, x)
			}
			got += ": " + obj.String()
		}

		// verify entry
		if got != test.want {
			t.Errorf("package %s: got %q; want %q", name, got, test.want)
		}
	}
}

func TestPkgNameOf(t *testing.T) {
	testenv.MustHaveGoBuild(t)

	const src = `
package p

import (
	. "os"
	_ "io"
	"math"
	"path/filepath"
	snort "sort"
)

// avoid imported and not used errors
var (
	_ = Open // os.Open
	_ = math.Sin
	_ = filepath.Abs
	_ = snort.Ints
)
`

	var tests = []struct {
		path string // path string enclosed in "'s
		want string
	}{
		{`"os"`, "."},
		{`"io"`, "_"},
		{`"math"`, "math"},
		{`"path/filepath"`, "filepath"},
		{`"sort"`, "snort"},
	}

	fset := token.NewFileSet()
	f := mustParse(fset, src)
	info := Info{
		Defs:      make(map[*ast.Ident]Object),
		Implicits: make(map[ast.Node]Object),
	}
	var conf Config
	conf.Importer = importer.Default()
	_, err := conf.Check("p", fset, []*ast.File{f}, &info)
	if err != nil {
		t.Fatal(err)
	}

	// map import paths to importDecl
	imports := make(map[string]*ast.ImportSpec)
	for _, s := range f.Decls[0].(*ast.GenDecl).Specs {
		if imp, _ := s.(*ast.ImportSpec); imp != nil {
			imports[imp.Path.Value] = imp
		}
	}

	for _, test := range tests {
		imp := imports[test.path]
		if imp == nil {
			t.Fatalf("invalid test case: import path %s not found", test.path)
		}
		got := info.PkgNameOf(imp)
		if got == nil {
			t.Fatalf("import %s: package name not found", test.path)
		}
		if got.Name() != test.want {
			t.Errorf("import %s: got %s; want %s", test.path, got.Name(), test.want)
		}
	}

	// test non-existing importDecl
	if got := info.PkgNameOf(new(ast.ImportSpec)); got != nil {
		t.Errorf("got %s for non-existing import declaration", got.Name())
	}
}

func predString(tv TypeAndValue) string {
	var buf strings.Builder
	pred := func(b bool, s string) {
		if b {
			if buf.Len() > 0 {
				buf.WriteString(", ")
			}
			buf.WriteString(s)
		}
	}

	pred(tv.IsVoid(), "void")
	pred(tv.IsType(), "type")
	pred(tv.IsBuiltin(), "builtin")
	pred(tv.IsValue() && tv.Value != nil, "const")
	pred(tv.IsValue() && tv.Value == nil, "value")
	pred(tv.IsNil(), "nil")
	pred(tv.Addressable(), "addressable")
	pred(tv.Assignable(), "assignable")
	pred(tv.HasOk(), "hasOk")

	if buf.Len() == 0 {
		return "invalid"
	}
	return buf.String()
}

func TestPredicatesInfo(t *testing.T) {
	testenv.MustHaveGoBuild(t)

	var tests = []struct {
		src  string
		expr string
		pred string
	}{
		// void
		{`package n0; func f() { f() }`, `f()`, `void`},

		// types
		{`package t0; type _ int`, `int`, `type`},
		{`package t1; type _ []int`, `[]int`, `type`},
		{`package t2; type _ func()`, `func()`, `type`},
		{`package t3; type _ func(int)`, `int`, `type`},
		{`package t3; type _ func(...int)`, `...int`, `type`},

		// built-ins
		{`package b0; var _ = len("")`, `len`, `builtin`},
		{`package b1; var _ = (len)("")`, `(len)`, `builtin`},

		// constants
		{`package c0; var _ = 42`, `42`, `const`},
		{`package c1; var _ = "foo" + "bar"`, `"foo" + "bar"`, `const`},
		{`package c2; const (i = 1i; _ = i)`, `i`, `const`},

		// values
		{`package v0; var (a, b int; _ = a + b)`, `a + b`, `value`},
		{`package v1; var _ = &[]int{1}`, `[]int{…}`, `value`},
		{`package v2; var _ = func(){}`, `(func() literal)`, `value`},
		{`package v4; func f() { _ = f }`, `f`, `value`},
		{`package v3; var _ *int = nil`, `nil`, `value, nil`},
		{`package v3; var _ *int = (nil)`, `(nil)`, `value, nil`},

		// addressable (and thus assignable) operands
		{`package a0; var (x int; _ = x)`, `x`, `value, addressable, assignable`},
		{`package a1; var (p *int; _ = *p)`, `*p`, `value, addressable, assignable`},
		{`package a2; var (s []int; _ = s[0])`, `s[0]`, `value, addressable, assignable`},
		{`package a3; var (s struct{f int}; _ = s.f)`, `s.f`, `value, addressable, assignable`},
		{`package a4; var (a [10]int; _ = a[0])`, `a[0]`, `value, addressable, assignable`},
		{`package a5; func _(x int) { _ = x }`, `x`, `value, addressable, assignable`},
		{`package a6; func _()(x int) { _ = x; return }`, `x`, `value, addressable, assignable`},
		{`package a7; type T int; func (x T) _() { _ = x }`, `x`, `value, addressable, assignable`},
		// composite literals are not addressable

		// assignable but not addressable values
		{`package s0; var (m map[int]int; _ = m[0])`, `m[0]`, `value, assignable, hasOk`},
		{`package s1; var (m map[int]int; _, _ = m[0])`, `m[0]`, `value, assignable, hasOk`},

		// hasOk expressions
		{`package k0; var (ch chan int; _ = <-ch)`, `<-ch`, `value, hasOk`},
		{`package k1; var (ch chan int; _, _ = <-ch)`, `<-ch`, `value, hasOk`},

		// missing entries
		// - package names are collected in the Uses map
		// - identifiers being declared are collected in the Defs map
		{`package m0; import "os"; func _() { _ = os.Stdout }`, `os`, `<missing>`},
		{`package m1; import p "os"; func _() { _ = p.Stdout }`, `p`, `<missing>`},
		{`package m2; const c = 0`, `c`, `<missing>`},
		{`package m3; type T int`, `T`, `<missing>`},
		{`package m4; var v int`, `v`, `<missing>`},
		{`package m5; func f() {}`, `f`, `<missing>`},
		{`package m6; func _(x int) {}`, `x`, `<missing>`},
		{`package m6; func _()(x int) { return }`, `x`, `<missing>`},
		{`package m6; type T int; func (x T) _() {}`, `x`, `<missing>`},
	}

	for _, test := range tests {
		info := Info{Types: make(map[ast.Expr]TypeAndValue)}
		name := mustTypecheck(test.src, nil, &info).Name()

		// look for expression predicates
		got := "<missing>"
		for e, tv := range info.Types {
			//println(name, ExprString(e))
			if ExprString(e) == test.expr {
				got = predString(tv)
				break
			}
		}

		if got != test.pred {
			t.Errorf("package %s: got %s; want %s", name, got, test.pred)
		}
	}
}

func TestScopesInfo(t *testing.T) {
	testenv.MustHaveGoBuild(t)

	var tests = []struct {
		src    string
		scopes []string // list of scope descriptors of the form kind:varlist
	}{
		{`package p0`, []string{
			"file:",
		}},
		{`package p1; import ( "fmt"; m "math"; _ "os" ); var ( _ = fmt.Println; _ = m.Pi )`, []string{
			"file:fmt m",
		}},
		{`package p2; func _() {}`, []string{
			"file:", "func:",
		}},
		{`package p3; func _(x, y int) {}`, []string{
			"file:", "func:x y",
		}},
		{`package p4; func _(x, y int) { x, z := 1, 2; _ = z }`, []string{
			"file:", "func:x y z", // redeclaration of x
		}},
		{`package p5; func _(x, y int) (u, _ int) { return }`, []string{
			"file:", "func:u x y",
		}},
		{`package p6; func _() { { var x int; _ = x } }`, []string{
			"file:", "func:", "block:x",
		}},
		{`package p7; func _() { if true {} }`, []string{
			"file:", "func:", "if:", "block:",
		}},
		{`package p8; func _() { if x := 0; x < 0 { y := x; _ = y } }`, []string{
			"file:", "func:", "if:x", "block:y",
		}},
		{`package p9; func _() { switch x := 0; x {} }`, []string{
			"file:", "func:", "switch:x",
		}},
		{`package p10; func _() { switch x := 0; x { case 1: y := x; _ = y; default: }}`, []string{
			"file:", "func:", "switch:x", "case:y", "case:",
		}},
		{`package p11; func _(t interface{}) { switch t.(type) {} }`, []string{
			"file:", "func:t", "type switch:",
		}},
		{`package p12; func _(t interface{}) { switch t := t; t.(type) {} }`, []string{
			"file:", "func:t", "type switch:t",
		}},
		{`package p13; func _(t interface{}) { switch x := t.(type) { case int: _ = x } }`, []string{
			"file:", "func:t", "type switch:", "case:x", // x implicitly declared
		}},
		{`package p14; func _() { select{} }`, []string{
			"file:", "func:",
		}},
		{`package p15; func _(c chan int) { select{ case <-c: } }`, []string{
			"file:", "func:c", "comm:",
		}},
		{`package p16; func _(c chan int) { select{ case i := <-c: x := i; _ = x} }`, []string{
			"file:", "func:c", "comm:i x",
		}},
		{`package p17; func _() { for{} }`, []string{
			"file:", "func:", "for:", "block:",
		}},
		{`package p18; func _(n int) { for i := 0; i < n; i++ { _ = i } }`, []string{
			"file:", "func:n", "for:i", "block:",
		}},
		{`package p19; func _(a []int) { for i := range a { _ = i} }`, []string{
			"file:", "func:a", "range:i", "block:",
		}},
		{`package p20; var s int; func _(a []int) { for i, x := range a { s += x; _ = i } }`, []string{
			"file:", "func:a", "range:i x", "block:",
		}},
	}

	for _, test := range tests {
		info := Info{Scopes: make(map[ast.Node]*Scope)}
		name := mustTypecheck(test.src, nil, &info).Name()

		// number of scopes must match
		if len(info.Scopes) != len(test.scopes) {
			t.Errorf("package %s: got %d scopes; want %d", name, len(info.Scopes), len(test.scopes))
		}

		// scope descriptions must match
		for node, scope := range info.Scopes {
			kind := "<unknown node kind>"
			switch node.(type) {
			case *ast.File:
				kind = "file"
			case *ast.FuncType:
				kind = "func"
			case *ast.BlockStmt:
				kind = "block"
			case *ast.IfStmt:
				kind = "if"
			case *ast.SwitchStmt:
				kind = "switch"
			case *ast.TypeSwitchStmt:
				kind = "type switch"
			case *ast.CaseClause:
				kind = "case"
			case *ast.CommClause:
				kind = "comm"
			case *ast.ForStmt:
				kind = "for"
			case *ast.RangeStmt:
				kind = "range"
			}

			// look for matching scope description
			desc := kind + ":" + strings.Join(scope.Names(), " ")
			if !slices.Contains(test.scopes, desc) {
				t.Errorf("package %s: no matching scope found for %s", name, desc)
			}
		}
	}
}

func TestInitOrderInfo(t *testing.T) {
	var tests = []struct {
		src   string
		inits []string
	}{
		{`package p0; var (x = 1; y = x)`, []string{
			"x = 1", "y = x",
		}},
		{`package p1; var (a = 1; b = 2; c = 3)`, []string{
			"a = 1", "b = 2", "c = 3",
		}},
		{`package p2; var (a, b, c = 1, 2, 3)`, []string{
			"a = 1", "b = 2", "c = 3",
		}},
		{`package p3; var _ = f(); func f() int { return 1 }`, []string{
			"_ = f()", // blank var
		}},
		{`package p4; var (a = 0; x = y; y = z; z = 0)`, []string{
			"a = 0", "z = 0", "y = z", "x = y",
		}},
		{`package p5; var (a, _ = m[0]; m map[int]string)`, []string{
			"a, _ = m[0]", // blank var
		}},
		{`package p6; var a, b = f(); func f() (_, _ int) { return z, z }; var z = 0`, []string{
			"z = 0", "a, b = f()",
		}},
		{`package p7; var (a = func() int { return b }(); b = 1)`, []string{
			"b = 1", "a = (func() int literal)()",
		}},
		{`package p8; var (a, b = func() (_, _ int) { return c, c }(); c = 1)`, []string{
			"c = 1", "a, b = (func() (_, _ int) literal)()",
		}},
		{`package p9; type T struct{}; func (T) m() int { _ = y; return 0 }; var x, y = T.m, 1`, []string{
			"y = 1", "x = T.m",
		}},
		{`package p10; var (d = c + b; a = 0; b = 0; c = 0)`, []string{
			"a = 0", "b = 0", "c = 0", "d = c + b",
		}},
		{`package p11; var (a = e + c; b = d + c; c = 0; d = 0; e = 0)`, []string{
			"c = 0", "d = 0", "b = d + c", "e = 0", "a = e + c",
		}},
		// emit an initializer for n:1 initializations only once (not for each node
		// on the lhs which may appear in different order in the dependency graph)
		{`package p12; var (a = x; b = 0; x, y = m[0]; m map[int]int)`, []string{
			"b = 0", "x, y = m[0]", "a = x",
		}},
		// test case from spec section on package initialization
		{`package p12

		var (
			a = c + b
			b = f()
			c = f()
			d = 3
		)

		func f() int {
			d++
			return d
		}`, []string{
			"d = 3", "b = f()", "c = f()", "a = c + b",
		}},
		// test case for go.dev/issue/7131
		{`package main

		var counter int
		func next() int { counter++; return counter }

		var _ = makeOrder()
		func makeOrder() []int { return []int{f, b, d, e, c, a} }

		var a       = next()
		var b, c    = next(), next()
		var d, e, f = next(), next(), next()
		`, []string{
			"a = next()", "b = next()", "c = next()", "d = next()", "e = next()", "f = next()", "_ = makeOrder()",
		}},
		// test case for go.dev/issue/10709
		{`package p13

		var (
		    v = t.m()
		    t = makeT(0)
		)

		type T struct{}

		func (T) m() int { return 0 }

		func makeT(n int) T {
		    if n > 0 {
		        return makeT(n-1)
		    }
		    return T{}
		}`, []string{
			"t = makeT(0)", "v = t.m()",
		}},
		// test case for go.dev/issue/10709: same as test before, but variable decls swapped
		{`package p14

		var (
		    t = makeT(0)
		    v = t.m()
		)

		type T struct{}

		func (T) m() int { return 0 }

		func makeT(n int) T {
		    if n > 0 {
		        return makeT(n-1)
		    }
		    return T{}
		}`, []string{
			"t = makeT(0)", "v = t.m()",
		}},
		// another candidate possibly causing problems with go.dev/issue/10709
		{`package p15

		var y1 = f1()

		func f1() int { return g1() }
		func g1() int { f1(); return x1 }

		var x1 = 0

		var y2 = f2()

		func f2() int { return g2() }
		func g2() int { return x2 }

		var x2 = 0`, []string{
			"x1 = 0", "y1 = f1()", "x2 = 0", "y2 = f2()",
		}},
	}

	for _, test := range tests {
		info := Info{}
		name := mustTypecheck(test.src, nil, &info).Name()

		// number of initializers must match
		if len(info.InitOrder) != len(test.inits) {
			t.Errorf("package %s: got %d initializers; want %d", name, len(info.InitOrder), len(test.inits))
			continue
		}

		// initializers must match
		for i, want := range test.inits {
			got := info.InitOrder[i].String()
			if got != want {
				t.Errorf("package %s, init %d: got %s; want %s", name, i, got, want)
				continue
			}
		}
	}
}

func TestMultiFileInitOrder(t *testing.T) {
	fset := token.NewFileSet()
	fileA := mustParse(fset, `package main; var a = 1`)
	fileB := mustParse(fset, `package main; var b = 2`)

	// The initialization order must not depend on the parse
	// order of the files, only on the presentation order to
	// the type-checker.
	for _, test := range []struct {
		files []*ast.File
		want  string
	}{
		{[]*ast.File{fileA, fileB}, "[a = 1 b = 2]"},
		{[]*ast.File{fileB, fileA}, "[b = 2 a = 1]"},
	} {
		var info Info
		if _, err := new(Config).Check("main", fset, test.files, &info); err != nil {
			t.Fatal(err)
		}
		if got := fmt.Sprint(info.InitOrder); got != test.want {
			t.Fatalf("got %s; want %s", got, test.want)
		}
	}
}

func TestFiles(t *testing.T) {
	var sources = []string{
		"package p; type T struct{}; func (T) m1() {}",
		"package p; func (T) m2() {}; var x interface{ m1(); m2() } = T{}",
		"package p; func (T) m3() {}; var y interface{ m1(); m2(); m3() } = T{}",
		"package p",
	}

	var conf Config
	fset := token.NewFileSet()
	pkg := NewPackage("p", "p")
	var info Info
	check := NewChecker(&conf, fset, pkg, &info)

	for _, src := range sources {
		if err := check.Files([]*ast.File{mustParse(fset, src)}); err != nil {
			t.Error(err)
		}
	}

	// check InitOrder is [x y]
	var vars []string
	for _, init := range info.InitOrder {
		for _, v := range init.Lhs {
			vars = append(vars, v.Name())
		}
	}
	if got, want := fmt.Sprint(vars), "[x y]"; got != want {
		t.Errorf("InitOrder == %s, want %s", got, want)
	}
}

type testImporter map[string]*Package

func (m testImporter) Import(path string) (*Package, error) {
	if pkg := m[path]; pkg != nil {
		return pkg, nil
	}
	return nil, fmt.Errorf("package %q not found", path)
}

func TestSelection(t *testing.T) {
	selections := make(map[*ast.SelectorExpr]*Selection)

	// We need a specific fileset in this test below for positions.
	// Cannot use typecheck helper.
	fset := token.NewFileSet()
	imports := make(testImporter)
	conf := Config{Importer: imports}
	makePkg := func(path, src string) {
		pkg, err := conf.Check(path, fset, []*ast.File{mustParse(fset, src)}, &Info{Selections: selections})
		if err != nil {
			t.Fatal(err)
		}
		imports[path] = pkg
	}

	const libSrc = `
package lib
type T float64
const C T = 3
var V T
func F() {}
func (T) M() {}
`
	const mainSrc = `
package main
import "lib"

type A struct {
	*B
	C
}

type B struct {
	b int
}

func (B) f(int)

type C struct {
	c int
}

type G[P any] struct {
	p P
}

func (G[P]) m(P) {}

var Inst G[int]

func (C) g()
func (*C) h()

func main() {
	// qualified identifiers
	var _ lib.T
	_ = lib.C
	_ = lib.F
	_ = lib.V
	_ = lib.T.M

	// fields
	_ = A{}.B
	_ = new(A).B

	_ = A{}.C
	_ = new(A).C

	_ = A{}.b
	_ = new(A).b

	_ = A{}.c
	_ = new(A).c

	_ = Inst.p
	_ = G[string]{}.p

	// methods
	_ = A{}.f
	_ = new(A).f
	_ = A{}.g
	_ = new(A).g
	_ = new(A).h

	_ = B{}.f
	_ = new(B).f

	_ = C{}.g
	_ = new(C).g
	_ = new(C).h
	_ = Inst.m

	// method expressions
	_ = A.f
	_ = (*A).f
	_ = B.f
	_ = (*B).f
	_ = G[string].m
}`

	wantOut := map[string][2]string{
		"lib.T.M": {"method expr (lib.T) M(lib.T)", ".[0]"},

		"A{}.B":    {"field (main.A) B *main.B", ".[0]"},
		"new(A).B": {"field (*main.A) B *main.B", "->[0]"},
		"A{}.C":    {"field (main.A) C main.C", ".[1]"},
		"new(A).C": {"field (*main.A) C main.C", "->[1]"},
		"A{}.b":    {"field (main.A) b int", "->[0 0]"},
		"new(A).b": {"field (*main.A) b int", "->[0 0]"},
		"A{}.c":    {"field (main.A) c int", ".[1 0]"},
		"new(A).c": {"field (*main.A) c int", "->[1 0]"},
		"Inst.p":   {"field (main.G[int]) p int", ".[0]"},

		"A{}.f":    {"method (main.A) f(int)", "->[0 0]"},
		"new(A).f": {"method (*main.A) f(int)", "->[0 0]"},
		"A{}.g":    {"method (main.A) g()", ".[1 0]"},
		"new(A).g": {"method (*main.A) g()", "->[1 0]"},
		"new(A).h": {"method (*main.A) h()", "->[1 1]"}, // TODO(gri) should this report .[1 1] ?
		"B{}.f":    {"method (main.B) f(int)", ".[0]"},
		"new(B).f": {"method (*main.B) f(int)", "->[0]"},
		"C{}.g":    {"method (main.C) g()", ".[0]"},
		"new(C).g": {"method (*main.C) g()", "->[0]"},
		"new(C).h": {"method (*main.C) h()", "->[1]"}, // TODO(gri) should this report .[1] ?
		"Inst.m":   {"method (main.G[int]) m(int)", ".[0]"},

		"A.f":           {"method expr (main.A) f(main.A, int)", "->[0 0]"},
		"(*A).f":        {"method expr (*main.A) f(*main.A, int)", "->[0 0]"},
		"B.f":           {"method expr (main.B) f(main.B, int)", ".[0]"},
		"(*B).f":        {"method expr (*main.B) f(*main.B, int)", "->[0]"},
		"G[string].m":   {"method expr (main.G[string]) m(main.G[string], string)", ".[0]"},
		"G[string]{}.p": {"field (main.G[string]) p string", ".[0]"},
	}

	makePkg("lib", libSrc)
	makePkg("main", mainSrc)

	for e, sel := range selections {
		_ = sel.String() // assertion: must not panic

		start := fset.Position(e.Pos()).Offset
		end := fset.Position(e.End()).Offset
		syntax := mainSrc[start:end] // (all SelectorExprs are in main, not lib)

		direct := "."
		if sel.Indirect() {
			direct = "->"
		}
		got := [2]string{
			sel.String(),
			fmt.Sprintf("%s%v", direct, sel.Index()),
		}
		want := wantOut[syntax]
		if want != got {
			t.Errorf("%s: got %q; want %q", syntax, got, want)
		}
		delete(wantOut, syntax)

		// We must explicitly assert properties of the
		// Signature's receiver since it doesn't participate
		// in Identical() or String().
		sig, _ := sel.Type().(*Signature)
		if sel.Kind() == MethodVal {
			got := sig.Recv().Type()
			want := sel.Recv()
			if !Identical(got, want) {
				t.Errorf("%s: Recv() = %s, want %s", syntax, got, want)
			}
		} else if sig != nil && sig.Recv() != nil {
			t.Errorf("%s: signature has receiver %s", sig, sig.Recv().Type())
		}
	}
	// Assert that all wantOut entries were use
```