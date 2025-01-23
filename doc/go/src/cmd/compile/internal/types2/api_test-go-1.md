Response: The user wants a summary of the functionality of the provided Go code snippet. This code is part of the `api_test.go` file within the `types2` package of the Go compiler. It seems to contain various test cases for different features of the `types2` package.

Here's a plan to summarize the functionality:

1. **Identify the core purpose:** The code tests the `types2` package, which is responsible for type checking in the Go compiler.
2. **Group tests by functionality:**  Look for test function names and the logic within them to identify the features being tested. Common patterns include `TestX`, `TestIssueY`, and specific function calls being tested.
3. **List the functionalities:**  Create a bulleted list of the functionalities based on the identified groups.
4. **Provide examples where possible:** If the test name or logic clearly indicates a Go language feature, provide a concise Go code example illustrating it.
5. **Explain command-line parameters (if any):** Scan for any code dealing with command-line flags or arguments. This seems unlikely in a unit test file, but it's worth checking.
6. **Mention common mistakes (if any):**  Look for test cases that explicitly check for or prevent common errors.
7. **Summarize the overall functionality:**  Provide a brief concluding statement about the purpose of the code.
这段代码是 `go/src/cmd/compile/internal/types2/api_test.go` 文件的一部分，主要用于测试 `types2` 包的 API 功能。 `types2` 包是 Go 编译器中负责类型检查的核心组件。

以下是代码片段中涉及的一些主要功能测试：

* **选择器表达式 (Selector Expressions) 的类型和属性:** 测试了如何获取和验证选择器表达式（例如 `a.b`, `x.Method()`）的类型信息，包括其表示形式 (`String()`)、是否为间接选择 (`Indirect()`) 和索引 (`Index()`)。
* **常量求值和类型检查中的错误处理:**  测试了在类型检查过程中遇到未定义的常量或导入错误时的处理机制，确保程序不会崩溃，并且能够记录错误。例如，`TestIssue8518` 和 `TestIssue59603`。
* **`LookupFieldOrMethod` 函数:**  测试了 `LookupFieldOrMethod` 函数的功能，该函数用于在给定类型中查找字段或方法。测试涵盖了各种情况，包括结构体字段查找、方法查找（值方法和指针方法）、泛型类型的查找、以及在 `nil` 类型上调用该函数时的 panic 处理。
* **类型转换 (`ConvertibleTo`) 和类型赋值 (`AssignableTo`):** 测试了 `ConvertibleTo` 函数判断两种类型之间是否可以进行类型转换，以及 `AssignableTo` 函数判断一个值是否可以赋值给某个类型的变量。
* **类型恒等 (`Identical`):** 测试了 `Identical` 函数判断两个类型是否完全相同，包括基本类型、命名类型、别名类型、函数类型和泛型函数类型。它还测试了包含联合类型的接口的恒等性。
* **构造包含重复方法的无效接口:** 测试了 API 是否允许构造包含重复方法的无效接口，这在某些场景下（例如导入）可能是必要的。对应 `TestIssue61737`。
* **别名类型 (`Alias`) 的使用:** 测试了创建和使用别名类型，并确保能正确获取别名的底层类型。对应 `TestNewAlias_Issue65455` 和 `TestAlias_Rhs`。
* **函数调用表达式的类型推断:** 测试了函数调用表达式的类型推断，即使在存在未定义标识符的情况下也能正确推断。对应 `TestIssue15305`。
* **复合字面量的类型推断:** 测试了复合字面量（例如数组、切片、map 和结构体的字面量）的类型推断，以及复合字面量类型表达式的类型。对应 `TestCompositeLitTypes`。
* **对象及其父作用域:**  测试了 `Object` 接口的 `Parent()` 方法，验证了不同类型的对象是否具有父作用域。对应 `TestObjectParents`。
* **处理导入失败的情况:** 测试了在导入包失败时，类型检查器是否能正确处理，避免后续出现不必要的错误。对应 `TestFailedImport`。
* **泛型实例化 (`Instantiate`):** 测试了泛型类型的实例化功能，包括基本实例化和并发实例化，以及在实例化过程中遇到类型约束错误时的处理。对应 `TestInstantiate`, `TestInstantiateConcurrent` 和 `TestInstantiateErrors`。
* **实例化对象的属性:** 测试了实例化对象的各种属性，例如字段、方法、参数和返回值的类型信息，以及如何通过 `originObject` 获取原始对象。对应 `TestInstantiatedObjects`。
* **类型实现接口 (`Implements`):** 测试了 `Implements` 函数判断一个类型是否实现了某个接口，包括包含类型集合的接口。同时也测试了 `AssertableTo` 函数。
* **查找缺失的方法 (`MissingMethod`):** 测试了 `MissingMethod` 函数，用于查找一个类型是否缺少某个接口定义的方法，并判断是否是签名不匹配导致的。
* **错误信息中的 URL:** 测试了配置 `ErrorURL` 后，错误信息是否会包含相应的链接。
* **Go 版本控制:** 测试了类型检查器对不同 Go 版本的支持，包括模块版本和文件版本 (`//go:build`) 的处理。对应 `TestModuleVersion` 和 `TestFileVersions`。
* **处理过新的 Go 版本:** 测试了当代码使用了比当前 `go/types` 支持的更新的 Go 版本特性时，是否会产生相应的错误。对应 `TestTooNew`。
* **循环依赖中的别名处理:** 针对一个在循环依赖中过早取消别名的特定问题进行回归测试。对应 `TestUnaliasTooSoonInCycle`。
* **并发类型检查中 "any" 关键字的处理:** 测试了在并发类型检查中对 `any` 关键字（可能作为别名存在）的处理。对应 `TestAnyHijacking_Check`。
* **不依赖位置信息的版本判断:** 确保类型检查器在判断 Go 版本时不依赖于语法节点的位置信息，避免因位置信息错误导致判断错误。对应 `TestVersionWithoutPos`。

**如果你能推理出它是什么go语言功能的实现，请用go代码举例说明:**

* **选择器表达式:**  测试了如何获取结构体字段或调用方法的信息。
  ```go
  package main

  type MyStruct struct {
      Field int
  }

  func (m MyStruct) Method() {}

  func main() {
      s := MyStruct{Field: 10}
      _ = s.Field  // 这是一个选择器表达式
      s.Method()   // 这也是一个选择器表达式
  }
  ```

* **泛型实例化:** 测试了如何使用泛型类型并为其指定具体的类型参数。
  ```go
  package main

  type MyGeneric[T any] struct {
      Value T
  }

  func main() {
      var g MyGeneric[int] // 实例化 MyGeneric，指定类型参数为 int
      g.Value = 10
  }
  ```

* **类型别名:** 测试了如何使用类型别名来为现有类型创建新的名称。
  ```go
  package main

  type MyInt = int // MyInt 是 int 的别名

  func main() {
      var i MyInt = 5
      println(i)
  }
  ```

* **接口实现:** 测试了类型如何满足接口的要求。
  ```go
  package main

  type MyInterface interface {
      DoSomething()
  }

  type MyType struct{}

  func (MyType) DoSomething() {
      println("Doing something")
  }

  func main() {
      var i MyInterface = MyType{} // MyType 实现了 MyInterface
      i.DoSomething()
  }
  ```

**如果涉及代码推理，需要带上假设的输入与输出，**

例如 `TestLookupFieldOrMethod` 中的一个测试用例：

```go
{"var x T; type T struct{ f int }", true, []int{0}, false},
```

* **假设输入:**  一段 Go 源代码 `var x T; type T struct{ f int }`，我们正在查找变量 `x` 的类型 `T` 是否有名为 `f` 的字段。
* **预期输出:**
    * `found: true` (找到了字段)
    * `index: []int{0}` (字段 `f` 在结构体中的索引是 0)
    * `indirect: false` (不是通过指针间接访问)

**如果涉及命令行参数的具体处理，请详细介绍一下，**

这段代码本身是单元测试，主要通过 Go 的测试框架运行 (`go test`)，不直接涉及命令行参数的处理。 `types2` 包在实际的 `go build` 等编译过程中会被使用，那时可能会受到一些编译选项的影响，但这些选项不是由这段测试代码直接处理的。

**如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，**

在 `types2` 包的使用中，一些常见的错误点可能包括：

* **错误地假设类型是相同的:**  没有使用 `Identical` 函数进行精确的类型比较，而是直接使用 `==` 比较，这在处理命名类型或别名类型时可能会出错。例如：
  ```go
  package main

  type MyInt1 int
  type MyInt2 int

  func main() {
      var i1 MyInt1 = 5
      var i2 MyInt2 = 5
      // i1 和 i2 的底层类型都是 int，但它们是不同的命名类型
      // 直接比较类型会返回 false
      println(TypeOf(i1) == TypeOf(i2)) // 输出 false
  }
  ```
* **混淆类型转换和类型断言:**  不清楚何时应该使用类型转换，何时应该使用类型断言，特别是在处理接口类型时。
* **在 `nil` 类型上调用方法或访问字段:** 这会导致运行时 panic。`TestLookupFieldOrMethodOnNil` 就是为了测试这种情况的处理。

**这是第2部分，共2部分，请归纳一下它的功能**

总的来说，这段 `api_test.go` 代码片段是 `types2` 包功能测试的一部分，它系统地测试了类型检查器在处理各种 Go 语言结构和概念时的正确性，包括选择器、常量、方法查找、类型转换、类型恒等、泛型、接口、别名、复合字面量、作用域、导入、错误处理和 Go 版本控制等方面。这些测试用例确保了 `types2` 包的 API 能够按照预期工作，为 Go 编译器的类型检查功能提供了可靠的保障。

### 提示词
```
这是路径为go/src/cmd/compile/internal/types2/api_test.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
这是第2部分，共2部分，请归纳一下它的功能
```

### 源代码
```go
main.A, int)", "->[0 0]"},
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

		start := indexFor(mainSrc, syntax.StartPos(e))
		end := indexFor(mainSrc, syntax.EndPos(e))
		segment := mainSrc[start:end] // (all SelectorExprs are in main, not lib)

		direct := "."
		if sel.Indirect() {
			direct = "->"
		}
		got := [2]string{
			sel.String(),
			fmt.Sprintf("%s%v", direct, sel.Index()),
		}
		want := wantOut[segment]
		if want != got {
			t.Errorf("%s: got %q; want %q", segment, got, want)
		}
		delete(wantOut, segment)

		// We must explicitly assert properties of the
		// Signature's receiver since it doesn't participate
		// in Identical() or String().
		sig, _ := sel.Type().(*Signature)
		if sel.Kind() == MethodVal {
			got := sig.Recv().Type()
			want := sel.Recv()
			if !Identical(got, want) {
				t.Errorf("%s: Recv() = %s, want %s", segment, got, want)
			}
		} else if sig != nil && sig.Recv() != nil {
			t.Errorf("%s: signature has receiver %s", sig, sig.Recv().Type())
		}
	}
	// Assert that all wantOut entries were used exactly once.
	for segment := range wantOut {
		t.Errorf("no syntax.Selection found with syntax %q", segment)
	}
}

// indexFor returns the index into s corresponding to the position pos.
func indexFor(s string, pos syntax.Pos) int {
	i, line := 0, 1 // string index and corresponding line
	target := int(pos.Line())
	for line < target && i < len(s) {
		if s[i] == '\n' {
			line++
		}
		i++
	}
	return i + int(pos.Col()-1) // columns are 1-based
}

func TestIssue8518(t *testing.T) {
	imports := make(testImporter)
	conf := Config{
		Error:    func(err error) { t.Log(err) }, // don't exit after first error
		Importer: imports,
	}
	makePkg := func(path, src string) {
		imports[path], _ = conf.Check(path, []*syntax.File{mustParse(src)}, nil) // errors logged via conf.Error
	}

	const libSrc = `
package a
import "missing"
const C1 = foo
const C2 = missing.C
`

	const mainSrc = `
package main
import "a"
var _ = a.C1
var _ = a.C2
`

	makePkg("a", libSrc)
	makePkg("main", mainSrc) // don't crash when type-checking this package
}

func TestIssue59603(t *testing.T) {
	imports := make(testImporter)
	conf := Config{
		Error:    func(err error) { t.Log(err) }, // don't exit after first error
		Importer: imports,
	}
	makePkg := func(path, src string) {
		imports[path], _ = conf.Check(path, []*syntax.File{mustParse(src)}, nil) // errors logged via conf.Error
	}

	const libSrc = `
package a
const C = foo
`

	const mainSrc = `
package main
import "a"
const _ = a.C
`

	makePkg("a", libSrc)
	makePkg("main", mainSrc) // don't crash when type-checking this package
}

func TestLookupFieldOrMethodOnNil(t *testing.T) {
	// LookupFieldOrMethod on a nil type is expected to produce a run-time panic.
	defer func() {
		const want = "LookupFieldOrMethod on nil type"
		p := recover()
		if s, ok := p.(string); !ok || s != want {
			t.Fatalf("got %v, want %s", p, want)
		}
	}()
	LookupFieldOrMethod(nil, false, nil, "")
}

func TestLookupFieldOrMethod(t *testing.T) {
	// Test cases assume a lookup of the form a.f or x.f, where a stands for an
	// addressable value, and x for a non-addressable value (even though a variable
	// for ease of test case writing).
	var tests = []struct {
		src      string
		found    bool
		index    []int
		indirect bool
	}{
		// field lookups
		{"var x T; type T struct{}", false, nil, false},
		{"var x T; type T struct{ f int }", true, []int{0}, false},
		{"var x T; type T struct{ a, b, f, c int }", true, []int{2}, false},

		// field lookups on a generic type
		{"var x T[int]; type T[P any] struct{}", false, nil, false},
		{"var x T[int]; type T[P any] struct{ f P }", true, []int{0}, false},
		{"var x T[int]; type T[P any] struct{ a, b, f, c P }", true, []int{2}, false},

		// method lookups
		{"var a T; type T struct{}; func (T) f() {}", true, []int{0}, false},
		{"var a *T; type T struct{}; func (T) f() {}", true, []int{0}, true},
		{"var a T; type T struct{}; func (*T) f() {}", true, []int{0}, false},
		{"var a *T; type T struct{}; func (*T) f() {}", true, []int{0}, true}, // TODO(gri) should this report indirect = false?

		// method lookups on a generic type
		{"var a T[int]; type T[P any] struct{}; func (T[P]) f() {}", true, []int{0}, false},
		{"var a *T[int]; type T[P any] struct{}; func (T[P]) f() {}", true, []int{0}, true},
		{"var a T[int]; type T[P any] struct{}; func (*T[P]) f() {}", true, []int{0}, false},
		{"var a *T[int]; type T[P any] struct{}; func (*T[P]) f() {}", true, []int{0}, true}, // TODO(gri) should this report indirect = false?

		// collisions
		{"type ( E1 struct{ f int }; E2 struct{ f int }; x struct{ E1; *E2 })", false, []int{1, 0}, false},
		{"type ( E1 struct{ f int }; E2 struct{}; x struct{ E1; *E2 }); func (E2) f() {}", false, []int{1, 0}, false},

		// collisions on a generic type
		{"type ( E1[P any] struct{ f P }; E2[P any] struct{ f P }; x struct{ E1[int]; *E2[int] })", false, []int{1, 0}, false},
		{"type ( E1[P any] struct{ f P }; E2[P any] struct{}; x struct{ E1[int]; *E2[int] }); func (E2[P]) f() {}", false, []int{1, 0}, false},

		// outside methodset
		// (*T).f method exists, but value of type T is not addressable
		{"var x T; type T struct{}; func (*T) f() {}", false, nil, true},

		// outside method set of a generic type
		{"var x T[int]; type T[P any] struct{}; func (*T[P]) f() {}", false, nil, true},

		// recursive generic types; see go.dev/issue/52715
		{"var a T[int]; type ( T[P any] struct { *N[P] }; N[P any] struct { *T[P] } ); func (N[P]) f() {}", true, []int{0, 0}, true},
		{"var a T[int]; type ( T[P any] struct { *N[P] }; N[P any] struct { *T[P] } ); func (T[P]) f() {}", true, []int{0}, false},
	}

	for _, test := range tests {
		pkg := mustTypecheck("package p;"+test.src, nil, nil)

		obj := pkg.Scope().Lookup("a")
		if obj == nil {
			if obj = pkg.Scope().Lookup("x"); obj == nil {
				t.Errorf("%s: incorrect test case - no object a or x", test.src)
				continue
			}
		}

		f, index, indirect := LookupFieldOrMethod(obj.Type(), obj.Name() == "a", pkg, "f")
		if (f != nil) != test.found {
			if f == nil {
				t.Errorf("%s: got no object; want one", test.src)
			} else {
				t.Errorf("%s: got object = %v; want none", test.src, f)
			}
		}
		if !slices.Equal(index, test.index) {
			t.Errorf("%s: got index = %v; want %v", test.src, index, test.index)
		}
		if indirect != test.indirect {
			t.Errorf("%s: got indirect = %v; want %v", test.src, indirect, test.indirect)
		}
	}
}

// Test for go.dev/issue/52715
func TestLookupFieldOrMethod_RecursiveGeneric(t *testing.T) {
	const src = `
package pkg

type Tree[T any] struct {
	*Node[T]
}

func (*Tree[R]) N(r R) R { return r }

type Node[T any] struct {
	*Tree[T]
}

type Instance = *Tree[int]
`

	f := mustParse(src)
	pkg := NewPackage("pkg", f.PkgName.Value)
	if err := NewChecker(nil, pkg, nil).Files([]*syntax.File{f}); err != nil {
		panic(err)
	}

	T := pkg.Scope().Lookup("Instance").Type()
	_, _, _ = LookupFieldOrMethod(T, false, pkg, "M") // verify that LookupFieldOrMethod terminates
}

// newDefined creates a new defined type named T with the given underlying type.
func newDefined(underlying Type) *Named {
	tname := NewTypeName(nopos, nil, "T", nil)
	return NewNamed(tname, underlying, nil)
}

func TestConvertibleTo(t *testing.T) {
	for _, test := range []struct {
		v, t Type
		want bool
	}{
		{Typ[Int], Typ[Int], true},
		{Typ[Int], Typ[Float32], true},
		{Typ[Int], Typ[String], true},
		{newDefined(Typ[Int]), Typ[Int], true},
		{newDefined(new(Struct)), new(Struct), true},
		{newDefined(Typ[Int]), new(Struct), false},
		{Typ[UntypedInt], Typ[Int], true},
		{NewSlice(Typ[Int]), NewArray(Typ[Int], 10), true},
		{NewSlice(Typ[Int]), NewArray(Typ[Uint], 10), false},
		{NewSlice(Typ[Int]), NewPointer(NewArray(Typ[Int], 10)), true},
		{NewSlice(Typ[Int]), NewPointer(NewArray(Typ[Uint], 10)), false},
		// Untyped string values are not permitted by the spec, so the behavior below is undefined.
		{Typ[UntypedString], Typ[String], true},
	} {
		if got := ConvertibleTo(test.v, test.t); got != test.want {
			t.Errorf("ConvertibleTo(%v, %v) = %t, want %t", test.v, test.t, got, test.want)
		}
	}
}

func TestAssignableTo(t *testing.T) {
	for _, test := range []struct {
		v, t Type
		want bool
	}{
		{Typ[Int], Typ[Int], true},
		{Typ[Int], Typ[Float32], false},
		{newDefined(Typ[Int]), Typ[Int], false},
		{newDefined(new(Struct)), new(Struct), true},
		{Typ[UntypedBool], Typ[Bool], true},
		{Typ[UntypedString], Typ[Bool], false},
		// Neither untyped string nor untyped numeric assignments arise during
		// normal type checking, so the below behavior is technically undefined by
		// the spec.
		{Typ[UntypedString], Typ[String], true},
		{Typ[UntypedInt], Typ[Int], true},
	} {
		if got := AssignableTo(test.v, test.t); got != test.want {
			t.Errorf("AssignableTo(%v, %v) = %t, want %t", test.v, test.t, got, test.want)
		}
	}
}

func TestIdentical(t *testing.T) {
	// For each test, we compare the types of objects X and Y in the source.
	tests := []struct {
		src  string
		want bool
	}{
		// Basic types.
		{"var X int; var Y int", true},
		{"var X int; var Y string", false},

		// TODO: add more tests for complex types.

		// Named types.
		{"type X int; type Y int", false},

		// Aliases.
		{"type X = int; type Y = int", true},

		// Functions.
		{`func X(int) string { return "" }; func Y(int) string { return "" }`, true},
		{`func X() string { return "" }; func Y(int) string { return "" }`, false},
		{`func X(int) string { return "" }; func Y(int) {}`, false},

		// Generic functions. Type parameters should be considered identical modulo
		// renaming. See also go.dev/issue/49722.
		{`func X[P ~int](){}; func Y[Q ~int]() {}`, true},
		{`func X[P1 any, P2 ~*P1](){}; func Y[Q1 any, Q2 ~*Q1]() {}`, true},
		{`func X[P1 any, P2 ~[]P1](){}; func Y[Q1 any, Q2 ~*Q1]() {}`, false},
		{`func X[P ~int](P){}; func Y[Q ~int](Q) {}`, true},
		{`func X[P ~string](P){}; func Y[Q ~int](Q) {}`, false},
		{`func X[P ~int]([]P){}; func Y[Q ~int]([]Q) {}`, true},
	}

	for _, test := range tests {
		pkg := mustTypecheck("package p;"+test.src, nil, nil)
		X := pkg.Scope().Lookup("X")
		Y := pkg.Scope().Lookup("Y")
		if X == nil || Y == nil {
			t.Fatal("test must declare both X and Y")
		}
		if got := Identical(X.Type(), Y.Type()); got != test.want {
			t.Errorf("Identical(%s, %s) = %t, want %t", X.Type(), Y.Type(), got, test.want)
		}
	}
}

func TestIdentical_issue15173(t *testing.T) {
	// Identical should allow nil arguments and be symmetric.
	for _, test := range []struct {
		x, y Type
		want bool
	}{
		{Typ[Int], Typ[Int], true},
		{Typ[Int], nil, false},
		{nil, Typ[Int], false},
		{nil, nil, true},
	} {
		if got := Identical(test.x, test.y); got != test.want {
			t.Errorf("Identical(%v, %v) = %t", test.x, test.y, got)
		}
	}
}

func TestIdenticalUnions(t *testing.T) {
	tname := NewTypeName(nopos, nil, "myInt", nil)
	myInt := NewNamed(tname, Typ[Int], nil)
	tmap := map[string]*Term{
		"int":     NewTerm(false, Typ[Int]),
		"~int":    NewTerm(true, Typ[Int]),
		"string":  NewTerm(false, Typ[String]),
		"~string": NewTerm(true, Typ[String]),
		"myInt":   NewTerm(false, myInt),
	}
	makeUnion := func(s string) *Union {
		parts := strings.Split(s, "|")
		var terms []*Term
		for _, p := range parts {
			term := tmap[p]
			if term == nil {
				t.Fatalf("missing term %q", p)
			}
			terms = append(terms, term)
		}
		return NewUnion(terms)
	}
	for _, test := range []struct {
		x, y string
		want bool
	}{
		// These tests are just sanity checks. The tests for type sets and
		// interfaces provide much more test coverage.
		{"int|~int", "~int", true},
		{"myInt|~int", "~int", true},
		{"int|string", "string|int", true},
		{"int|int|string", "string|int", true},
		{"myInt|string", "int|string", false},
	} {
		x := makeUnion(test.x)
		y := makeUnion(test.y)
		if got := Identical(x, y); got != test.want {
			t.Errorf("Identical(%v, %v) = %t", test.x, test.y, got)
		}
	}
}

func TestIssue61737(t *testing.T) {
	// This test verifies that it is possible to construct invalid interfaces
	// containing duplicate methods using the go/types API.
	//
	// It must be possible for importers to construct such invalid interfaces.
	// Previously, this panicked.

	sig1 := NewSignatureType(nil, nil, nil, NewTuple(NewParam(nopos, nil, "", Typ[Int])), nil, false)
	sig2 := NewSignatureType(nil, nil, nil, NewTuple(NewParam(nopos, nil, "", Typ[String])), nil, false)

	methods := []*Func{
		NewFunc(nopos, nil, "M", sig1),
		NewFunc(nopos, nil, "M", sig2),
	}

	embeddedMethods := []*Func{
		NewFunc(nopos, nil, "M", sig2),
	}
	embedded := NewInterfaceType(embeddedMethods, nil)
	iface := NewInterfaceType(methods, []Type{embedded})
	iface.NumMethods() // unlike go/types, there is no Complete() method, so we complete implicitly
}

func TestNewAlias_Issue65455(t *testing.T) {
	obj := NewTypeName(nopos, nil, "A", nil)
	alias := NewAlias(obj, Typ[Int])
	alias.Underlying() // must not panic
}

func TestIssue15305(t *testing.T) {
	const src = "package p; func f() int16; var _ = f(undef)"
	f := mustParse(src)
	conf := Config{
		Error: func(err error) {}, // allow errors
	}
	info := &Info{
		Types: make(map[syntax.Expr]TypeAndValue),
	}
	conf.Check("p", []*syntax.File{f}, info) // ignore result
	for e, tv := range info.Types {
		if _, ok := e.(*syntax.CallExpr); ok {
			if tv.Type != Typ[Int16] {
				t.Errorf("CallExpr has type %v, want int16", tv.Type)
			}
			return
		}
	}
	t.Errorf("CallExpr has no type")
}

// TestCompositeLitTypes verifies that Info.Types registers the correct
// types for composite literal expressions and composite literal type
// expressions.
func TestCompositeLitTypes(t *testing.T) {
	for i, test := range []struct {
		lit, typ string
	}{
		{`[16]byte{}`, `[16]byte`},
		{`[...]byte{}`, `[0]byte`},                // test for go.dev/issue/14092
		{`[...]int{1, 2, 3}`, `[3]int`},           // test for go.dev/issue/14092
		{`[...]int{90: 0, 98: 1, 2}`, `[100]int`}, // test for go.dev/issue/14092
		{`[]int{}`, `[]int`},
		{`map[string]bool{"foo": true}`, `map[string]bool`},
		{`struct{}{}`, `struct{}`},
		{`struct{x, y int; z complex128}{}`, `struct{x int; y int; z complex128}`},
	} {
		f := mustParse(fmt.Sprintf("package p%d; var _ = %s", i, test.lit))
		types := make(map[syntax.Expr]TypeAndValue)
		if _, err := new(Config).Check("p", []*syntax.File{f}, &Info{Types: types}); err != nil {
			t.Fatalf("%s: %v", test.lit, err)
		}

		cmptype := func(x syntax.Expr, want string) {
			tv, ok := types[x]
			if !ok {
				t.Errorf("%s: no Types entry found", test.lit)
				return
			}
			if tv.Type == nil {
				t.Errorf("%s: type is nil", test.lit)
				return
			}
			if got := tv.Type.String(); got != want {
				t.Errorf("%s: got %v, want %s", test.lit, got, want)
			}
		}

		// test type of composite literal expression
		rhs := f.DeclList[0].(*syntax.VarDecl).Values
		cmptype(rhs, test.typ)

		// test type of composite literal type expression
		cmptype(rhs.(*syntax.CompositeLit).Type, test.typ)
	}
}

// TestObjectParents verifies that objects have parent scopes or not
// as specified by the Object interface.
func TestObjectParents(t *testing.T) {
	const src = `
package p

const C = 0

type T1 struct {
	a, b int
	T2
}

type T2 interface {
	im1()
	im2()
}

func (T1) m1() {}
func (*T1) m2() {}

func f(x int) { y := x; print(y) }
`

	f := mustParse(src)

	info := &Info{
		Defs: make(map[*syntax.Name]Object),
	}
	if _, err := new(Config).Check("p", []*syntax.File{f}, info); err != nil {
		t.Fatal(err)
	}

	for ident, obj := range info.Defs {
		if obj == nil {
			// only package names and implicit vars have a nil object
			// (in this test we only need to handle the package name)
			if ident.Value != "p" {
				t.Errorf("%v has nil object", ident)
			}
			continue
		}

		// struct fields, type-associated and interface methods
		// have no parent scope
		wantParent := true
		switch obj := obj.(type) {
		case *Var:
			if obj.IsField() {
				wantParent = false
			}
		case *Func:
			if obj.Type().(*Signature).Recv() != nil { // method
				wantParent = false
			}
		}

		gotParent := obj.Parent() != nil
		switch {
		case gotParent && !wantParent:
			t.Errorf("%v: want no parent, got %s", ident, obj.Parent())
		case !gotParent && wantParent:
			t.Errorf("%v: no parent found", ident)
		}
	}
}

// TestFailedImport tests that we don't get follow-on errors
// elsewhere in a package due to failing to import a package.
func TestFailedImport(t *testing.T) {
	testenv.MustHaveGoBuild(t)

	const src = `
package p

import foo "go/types/thisdirectorymustnotexistotherwisethistestmayfail/foo" // should only see an error here

const c = foo.C
type T = foo.T
var v T = c
func f(x T) T { return foo.F(x) }
`
	f := mustParse(src)
	files := []*syntax.File{f}

	// type-check using all possible importers
	for _, compiler := range []string{"gc", "gccgo", "source"} {
		errcount := 0
		conf := Config{
			Error: func(err error) {
				// we should only see the import error
				if errcount > 0 || !strings.Contains(err.Error(), "could not import") {
					t.Errorf("for %s importer, got unexpected error: %v", compiler, err)
				}
				errcount++
			},
			//Importer: importer.For(compiler, nil),
		}

		info := &Info{
			Uses: make(map[*syntax.Name]Object),
		}
		pkg, _ := conf.Check("p", files, info)
		if pkg == nil {
			t.Errorf("for %s importer, type-checking failed to return a package", compiler)
			continue
		}

		imports := pkg.Imports()
		if len(imports) != 1 {
			t.Errorf("for %s importer, got %d imports, want 1", compiler, len(imports))
			continue
		}
		imp := imports[0]
		if imp.Name() != "foo" {
			t.Errorf(`for %s importer, got %q, want "foo"`, compiler, imp.Name())
			continue
		}

		// verify that all uses of foo refer to the imported package foo (imp)
		for ident, obj := range info.Uses {
			if ident.Value == "foo" {
				if obj, ok := obj.(*PkgName); ok {
					if obj.Imported() != imp {
						t.Errorf("%s resolved to %v; want %v", ident.Value, obj.Imported(), imp)
					}
				} else {
					t.Errorf("%s resolved to %v; want package name", ident.Value, obj)
				}
			}
		}
	}
}

func TestInstantiate(t *testing.T) {
	// eventually we like more tests but this is a start
	const src = "package p; type T[P any] *T[P]"
	pkg := mustTypecheck(src, nil, nil)

	// type T should have one type parameter
	T := pkg.Scope().Lookup("T").Type().(*Named)
	if n := T.TypeParams().Len(); n != 1 {
		t.Fatalf("expected 1 type parameter; found %d", n)
	}

	// instantiation should succeed (no endless recursion)
	// even with a nil *Checker
	res, err := Instantiate(nil, T, []Type{Typ[Int]}, false)
	if err != nil {
		t.Fatal(err)
	}

	// instantiated type should point to itself
	if p := res.Underlying().(*Pointer).Elem(); p != res {
		t.Fatalf("unexpected result type: %s points to %s", res, p)
	}
}

func TestInstantiateConcurrent(t *testing.T) {
	const src = `package p

type I[P any] interface {
	m(P)
	n() P
}

type J = I[int]

type Nested[P any] *interface{b(P)}

type K = Nested[string]
`
	pkg := mustTypecheck(src, nil, nil)

	insts := []*Interface{
		pkg.Scope().Lookup("J").Type().Underlying().(*Interface),
		pkg.Scope().Lookup("K").Type().Underlying().(*Pointer).Elem().(*Interface),
	}

	// Use the interface instances concurrently.
	for _, inst := range insts {
		var (
			counts  [2]int      // method counts
			methods [2][]string // method strings
		)
		var wg sync.WaitGroup
		for i := 0; i < 2; i++ {
			i := i
			wg.Add(1)
			go func() {
				defer wg.Done()

				counts[i] = inst.NumMethods()
				for mi := 0; mi < counts[i]; mi++ {
					methods[i] = append(methods[i], inst.Method(mi).String())
				}
			}()
		}
		wg.Wait()

		if counts[0] != counts[1] {
			t.Errorf("mismatching method counts for %s: %d vs %d", inst, counts[0], counts[1])
			continue
		}
		for i := 0; i < counts[0]; i++ {
			if m0, m1 := methods[0][i], methods[1][i]; m0 != m1 {
				t.Errorf("mismatching methods for %s: %s vs %s", inst, m0, m1)
			}
		}
	}
}

func TestInstantiateErrors(t *testing.T) {
	tests := []struct {
		src    string // by convention, T must be the type being instantiated
		targs  []Type
		wantAt int // -1 indicates no error
	}{
		{"type T[P interface{~string}] int", []Type{Typ[Int]}, 0},
		{"type T[P1 interface{int}, P2 interface{~string}] int", []Type{Typ[Int], Typ[Int]}, 1},
		{"type T[P1 any, P2 interface{~[]P1}] int", []Type{Typ[Int], NewSlice(Typ[String])}, 1},
		{"type T[P1 interface{~[]P2}, P2 any] int", []Type{NewSlice(Typ[String]), Typ[Int]}, 0},
	}

	for _, test := range tests {
		src := "package p; " + test.src
		pkg := mustTypecheck(src, nil, nil)

		T := pkg.Scope().Lookup("T").Type().(*Named)

		_, err := Instantiate(nil, T, test.targs, true)
		if err == nil {
			t.Fatalf("Instantiate(%v, %v) returned nil error, want non-nil", T, test.targs)
		}

		var argErr *ArgumentError
		if !errors.As(err, &argErr) {
			t.Fatalf("Instantiate(%v, %v): error is not an *ArgumentError", T, test.targs)
		}

		if argErr.Index != test.wantAt {
			t.Errorf("Instantiate(%v, %v): error at index %d, want index %d", T, test.targs, argErr.Index, test.wantAt)
		}
	}
}

func TestArgumentErrorUnwrapping(t *testing.T) {
	var err error = &ArgumentError{
		Index: 1,
		Err:   Error{Msg: "test"},
	}
	var e Error
	if !errors.As(err, &e) {
		t.Fatalf("error %v does not wrap types.Error", err)
	}
	if e.Msg != "test" {
		t.Errorf("e.Msg = %q, want %q", e.Msg, "test")
	}
}

func TestInstanceIdentity(t *testing.T) {
	imports := make(testImporter)
	conf := Config{Importer: imports}
	makePkg := func(src string) {
		f := mustParse(src)
		name := f.PkgName.Value
		pkg, err := conf.Check(name, []*syntax.File{f}, nil)
		if err != nil {
			t.Fatal(err)
		}
		imports[name] = pkg
	}
	makePkg(`package lib; type T[P any] struct{}`)
	makePkg(`package a; import "lib"; var A lib.T[int]`)
	makePkg(`package b; import "lib"; var B lib.T[int]`)
	a := imports["a"].Scope().Lookup("A")
	b := imports["b"].Scope().Lookup("B")
	if !Identical(a.Type(), b.Type()) {
		t.Errorf("mismatching types: a.A: %s, b.B: %s", a.Type(), b.Type())
	}
}

// TestInstantiatedObjects verifies properties of instantiated objects.
func TestInstantiatedObjects(t *testing.T) {
	const src = `
package p

type T[P any] struct {
	field P
}

func (recv *T[Q]) concreteMethod(mParam Q) (mResult Q) { return }

type FT[P any] func(ftParam P) (ftResult P)

func F[P any](fParam P) (fResult P){ return }

type I[P any] interface {
	interfaceMethod(P)
}

type R[P any] T[P]

func (R[P]) m() {} // having a method triggers expansion of R

var (
	t T[int]
	ft FT[int]
	f = F[int]
	i I[int]
)

func fn() {
	var r R[int]
	_ = r
}
`
	info := &Info{
		Defs: make(map[*syntax.Name]Object),
	}
	f := mustParse(src)
	conf := Config{}
	pkg, err := conf.Check(f.PkgName.Value, []*syntax.File{f}, info)
	if err != nil {
		t.Fatal(err)
	}

	lookup := func(name string) Type { return pkg.Scope().Lookup(name).Type() }
	fnScope := pkg.Scope().Lookup("fn").(*Func).Scope()

	tests := []struct {
		name string
		obj  Object
	}{
		// Struct fields
		{"field", lookup("t").Underlying().(*Struct).Field(0)},
		{"field", fnScope.Lookup("r").Type().Underlying().(*Struct).Field(0)},

		// Methods and method fields
		{"concreteMethod", lookup("t").(*Named).Method(0)},
		{"recv", lookup("t").(*Named).Method(0).Type().(*Signature).Recv()},
		{"mParam", lookup("t").(*Named).Method(0).Type().(*Signature).Params().At(0)},
		{"mResult", lookup("t").(*Named).Method(0).Type().(*Signature).Results().At(0)},

		// Interface methods
		{"interfaceMethod", lookup("i").Underlying().(*Interface).Method(0)},

		// Function type fields
		{"ftParam", lookup("ft").Underlying().(*Signature).Params().At(0)},
		{"ftResult", lookup("ft").Underlying().(*Signature).Results().At(0)},

		// Function fields
		{"fParam", lookup("f").(*Signature).Params().At(0)},
		{"fResult", lookup("f").(*Signature).Results().At(0)},
	}

	// Collect all identifiers by name.
	idents := make(map[string][]*syntax.Name)
	syntax.Inspect(f, func(n syntax.Node) bool {
		if id, ok := n.(*syntax.Name); ok {
			idents[id.Value] = append(idents[id.Value], id)
		}
		return true
	})

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			if got := len(idents[test.name]); got != 1 {
				t.Fatalf("found %d identifiers named %s, want 1", got, test.name)
			}
			ident := idents[test.name][0]
			def := info.Defs[ident]
			if def == test.obj {
				t.Fatalf("info.Defs[%s] contains the test object", test.name)
			}
			if orig := originObject(test.obj); def != orig {
				t.Errorf("info.Defs[%s] does not match obj.Origin()", test.name)
			}
			if def.Pkg() != test.obj.Pkg() {
				t.Errorf("Pkg() = %v, want %v", def.Pkg(), test.obj.Pkg())
			}
			if def.Name() != test.obj.Name() {
				t.Errorf("Name() = %v, want %v", def.Name(), test.obj.Name())
			}
			if def.Pos() != test.obj.Pos() {
				t.Errorf("Pos() = %v, want %v", def.Pos(), test.obj.Pos())
			}
			if def.Parent() != test.obj.Parent() {
				t.Fatalf("Parent() = %v, want %v", def.Parent(), test.obj.Parent())
			}
			if def.Exported() != test.obj.Exported() {
				t.Fatalf("Exported() = %v, want %v", def.Exported(), test.obj.Exported())
			}
			if def.Id() != test.obj.Id() {
				t.Fatalf("Id() = %v, want %v", def.Id(), test.obj.Id())
			}
			// String and Type are expected to differ.
		})
	}
}

func originObject(obj Object) Object {
	switch obj := obj.(type) {
	case *Var:
		return obj.Origin()
	case *Func:
		return obj.Origin()
	}
	return obj
}

func TestImplements(t *testing.T) {
	const src = `
package p

type EmptyIface interface{}

type I interface {
	m()
}

type C interface {
	m()
	~int
}

type Integer interface{
	int8 | int16 | int32 | int64
}

type EmptyTypeSet interface{
	Integer
	~string
}

type N1 int
func (N1) m() {}

type N2 int
func (*N2) m() {}

type N3 int
func (N3) m(int) {}

type N4 string
func (N4) m()

type Bad Bad // invalid type
`

	f := mustParse(src)
	conf := Config{Error: func(error) {}}
	pkg, _ := conf.Check(f.PkgName.Value, []*syntax.File{f}, nil)

	lookup := func(tname string) Type { return pkg.Scope().Lookup(tname).Type() }
	var (
		EmptyIface   = lookup("EmptyIface").Underlying().(*Interface)
		I            = lookup("I").(*Named)
		II           = I.Underlying().(*Interface)
		C            = lookup("C").(*Named)
		CI           = C.Underlying().(*Interface)
		Integer      = lookup("Integer").Underlying().(*Interface)
		EmptyTypeSet = lookup("EmptyTypeSet").Underlying().(*Interface)
		N1           = lookup("N1")
		N1p          = NewPointer(N1)
		N2           = lookup("N2")
		N2p          = NewPointer(N2)
		N3           = lookup("N3")
		N4           = lookup("N4")
		Bad          = lookup("Bad")
	)

	tests := []struct {
		V    Type
		T    *Interface
		want bool
	}{
		{I, II, true},
		{I, CI, false},
		{C, II, true},
		{C, CI, true},
		{Typ[Int8], Integer, true},
		{Typ[Int64], Integer, true},
		{Typ[String], Integer, false},
		{EmptyTypeSet, II, true},
		{EmptyTypeSet, EmptyTypeSet, true},
		{Typ[Int], EmptyTypeSet, false},
		{N1, II, true},
		{N1, CI, true},
		{N1p, II, true},
		{N1p, CI, false},
		{N2, II, false},
		{N2, CI, false},
		{N2p, II, true},
		{N2p, CI, false},
		{N3, II, false},
		{N3, CI, false},
		{N4, II, true},
		{N4, CI, false},
		{Bad, II, false},
		{Bad, CI, false},
		{Bad, EmptyIface, true},
	}

	for _, test := range tests {
		if got := Implements(test.V, test.T); got != test.want {
			t.Errorf("Implements(%s, %s) = %t, want %t", test.V, test.T, got, test.want)
		}

		// The type assertion x.(T) is valid if T is an interface or if T implements the type of x.
		// The assertion is never valid if T is a bad type.
		V := test.T
		T := test.V
		want := false
		if _, ok := T.Underlying().(*Interface); (ok || Implements(T, V)) && T != Bad {
			want = true
		}
		if got := AssertableTo(V, T); got != want {
			t.Errorf("AssertableTo(%s, %s) = %t, want %t", V, T, got, want)
		}
	}
}

func TestMissingMethodAlternative(t *testing.T) {
	const src = `
package p
type T interface {
	m()
}

type V0 struct{}
func (V0) m() {}

type V1 struct{}

type V2 struct{}
func (V2) m() int

type V3 struct{}
func (*V3) m()

type V4 struct{}
func (V4) M()
`

	pkg := mustTypecheck(src, nil, nil)

	T := pkg.Scope().Lookup("T").Type().Underlying().(*Interface)
	lookup := func(name string) (*Func, bool) {
		return MissingMethod(pkg.Scope().Lookup(name).Type(), T, true)
	}

	// V0 has method m with correct signature. Should not report wrongType.
	method, wrongType := lookup("V0")
	if method != nil || wrongType {
		t.Fatalf("V0: got method = %v, wrongType = %v", method, wrongType)
	}

	checkMissingMethod := func(tname string, reportWrongType bool) {
		method, wrongType := lookup(tname)
		if method == nil || method.Name() != "m" || wrongType != reportWrongType {
			t.Fatalf("%s: got method = %v, wrongType = %v", tname, method, wrongType)
		}
	}

	// V1 has no method m. Should not report wrongType.
	checkMissingMethod("V1", false)

	// V2 has method m with wrong signature type (ignoring receiver). Should report wrongType.
	checkMissingMethod("V2", true)

	// V3 has no method m but it exists on *V3. Should report wrongType.
	checkMissingMethod("V3", true)

	// V4 has no method m but has M. Should not report wrongType.
	checkMissingMethod("V4", false)
}

func TestErrorURL(t *testing.T) {
	conf := Config{ErrorURL: " [go.dev/e/%s]"}

	// test case for a one-line error
	const src1 = `
package p
var _ T
`
	_, err := typecheck(src1, &conf, nil)
	if err == nil || !strings.HasSuffix(err.Error(), " [go.dev/e/UndeclaredName]") {
		t.Errorf("src1: unexpected error: got %v", err)
	}

	// test case for a multi-line error
	const src2 = `
package p
func f() int { return 0 }
var _ = f(1, 2)
`
	_, err = typecheck(src2, &conf, nil)
	if err == nil || !strings.Contains(err.Error(), " [go.dev/e/WrongArgCount]\n") {
		t.Errorf("src1: unexpected error: got %v", err)
	}
}

func TestModuleVersion(t *testing.T) {
	// version go1.dd must be able to typecheck go1.dd.0, go1.dd.1, etc.
	goversion := fmt.Sprintf("go1.%d", goversion.Version)
	for _, v := range []string{
		goversion,
		goversion + ".0",
		goversion + ".1",
		goversion + ".rc",
	} {
		conf := Config{GoVersion: v}
		pkg := mustTypecheck("package p", &conf, nil)
		if pkg.GoVersion() != conf.GoVersion {
			t.Errorf("got %s; want %s", pkg.GoVersion(), conf.GoVersion)
		}
	}
}

func TestFileVersions(t *testing.T) {
	for _, test := range []struct {
		goVersion   string
		fileVersion string
		wantVersion string
	}{
		{"", "", ""},                    // no versions specified
		{"go1.19", "", "go1.19"},        // module version specified
		{"", "go1.20", "go1.21"},        // file version specified below minimum of 1.21
		{"go1", "", "go1"},              // no file version specified
		{"go1", "goo1.22", "go1"},       // invalid file version specified
		{"go1", "go1.19", "go1.21"},     // file version specified below minimum of 1.21
		{"go1", "go1.20", "go1.21"},     // file version specified below minimum of 1.21
		{"go1", "go1.21", "go1.21"},     // file version specified at 1.21
		{"go1", "go1.22", "go1.22"},     // file version specified above 1.21
		{"go1.19", "", "go1.19"},        // no file version specified
		{"go1.19", "goo1.22", "go1.19"}, // invalid file version specified
		{"go1.19", "go1.20", "go1.21"},  // file version specified below minimum of 1.21
		{"go1.19", "go1.21", "go1.21"},  // file version specified at 1.21
		{"go1.19", "go1.22", "go1.22"},  // file version specified above 1.21
		{"go1.20", "", "go1.20"},        // no file version specified
		{"go1.20", "goo1.22", "go1.20"}, // invalid file version specified
		{"go1.20", "go1.19", "go1.21"},  // file version specified below minimum of 1.21
		{"go1.20", "go1.20", "go1.21"},  // file version specified below minimum of 1.21
		{"go1.20", "go1.21", "go1.21"},  // file version specified at 1.21
		{"go1.20", "go1.22", "go1.22"},  // file version specified above 1.21
		{"go1.21", "", "go1.21"},        // no file version specified
		{"go1.21", "goo1.22", "go1.21"}, // invalid file version specified
		{"go1.21", "go1.19", "go1.21"},  // file version specified below minimum of 1.21
		{"go1.21", "go1.20", "go1.21"},  // file version specified below minimum of 1.21
		{"go1.21", "go1.21", "go1.21"},  // file version specified at 1.21
		{"go1.21", "go1.22", "go1.22"},  // file version specified above 1.21
		{"go1.22", "", "go1.22"},        // no file version specified
		{"go1.22", "goo1.22", "go1.22"}, // invalid file version specified
		{"go1.22", "go1.19", "go1.21"},  // file version specified below minimum of 1.21
		{"go1.22", "go1.20", "go1.21"},  // file version specified below minimum of 1.21
		{"go1.22", "go1.21", "go1.21"},  // file version specified at 1.21
		{"go1.22", "go1.22", "go1.22"},  // file version specified above 1.21

		// versions containing release numbers
		// (file versions containing release numbers are considered invalid)
		{"go1.19.0", "", "go1.19.0"},         // no file version specified
		{"go1.20.1", "go1.19.1", "go1.20.1"}, // invalid file version
		{"go1.20.1", "go1.21.1", "go1.20.1"}, // invalid file version
		{"go1.21.1", "go1.19.1", "go1.21.1"}, // invalid file version
		{"go1.21.1", "go1.21.1", "go1.21.1"}, // invalid file version
		{"go1.22.1", "go1.19.1", "go1.22.1"}, // invalid file version
		{"go1.22.1", "go1.21.1", "go1.22.1"}, // invalid file version
	} {
		var src string
		if test.fileVersion != "" {
			src = "//go:build " + test.fileVersion + "\n"
		}
		src += "package p"

		conf := Config{GoVersion: test.goVersion}
		versions := make(map[*syntax.PosBase]string)
		var info Info
		info.FileVersions = versions
		mustTypecheck(src, &conf, &info)

		n := 0
		for _, v := range info.FileVersions {
			want := test.wantVersion
			if v != want {
				t.Errorf("%q: unexpected file version: got %v, want %v", src, v, want)
			}
			n++
		}
		if n != 1 {
			t.Errorf("%q: incorrect number of map entries: got %d", src, n)
		}
	}
}

// TestTooNew ensures that "too new" errors are emitted when the file
// or module is tagged with a newer version of Go than this go/types.
func TestTooNew(t *testing.T) {
	for _, test := range []struct {
		goVersion   string // package's Go version (as if derived from go.mod file)
		fileVersion string // file's Go version (becomes a build tag)
		wantErr     string // expected substring of concatenation of all errors
	}{
		{"go1.98", "", "package requires newer Go version go1.98"},
		{"", "go1.99", "p:2:9: file requires newer Go version go1.99"},
		{"go1.98", "go1.99", "package requires newer Go version go1.98"}, // (two
		{"go1.98", "go1.99", "file requires newer Go version go1.99"},    // errors)
	} {
		var src string
		if test.fileVersion != "" {
			src = "//go:build " + test.fileVersion + "\n"
		}
		src += "package p; func f()"

		var errs []error
		conf := Config{
			GoVersion: test.goVersion,
			Error:     func(err error) { errs = append(errs, err) },
		}
		info := &Info{Defs: make(map[*syntax.Name]Object)}
		typecheck(src, &conf, info)
		got := fmt.Sprint(errs)
		if !strings.Contains(got, test.wantErr) {
			t.Errorf("%q: unexpected error: got %q, want substring %q",
				src, got, test.wantErr)
		}

		// Assert that declarations were type checked nonetheless.
		var gotObjs []string
		for id, obj := range info.Defs {
			if obj != nil {
				objStr := strings.ReplaceAll(fmt.Sprintf("%s:%T", id.Value, obj), "types2", "types")
				gotObjs = append(gotObjs, objStr)
			}
		}
		wantObjs := "f:*types.Func"
		if !strings.Contains(fmt.Sprint(gotObjs), wantObjs) {
			t.Errorf("%q: got %s, want substring %q",
				src, gotObjs, wantObjs)
		}
	}
}

// This is a regression test for #66704.
func TestUnaliasTooSoonInCycle(t *testing.T) {
	t.Setenv("GODEBUG", "gotypesalias=1")
	const src = `package a

var x T[B] // this appears to cause Unalias to be called on B while still Invalid

type T[_ any] struct{}
type A T[B]
type B = T[A]
`
	pkg := mustTypecheck(src, nil, nil)
	B := pkg.Scope().Lookup("B")

	got, want := Unalias(B.Type()).String(), "a.T[a.A]"
	if got != want {
		t.Errorf("Unalias(type B = T[A]) = %q, want %q", got, want)
	}
}

func TestAlias_Rhs(t *testing.T) {
	const src = `package p

type A = B
type B = C
type C = int
`

	pkg := mustTypecheck(src, &Config{EnableAlias: true}, nil)
	A := pkg.Scope().Lookup("A")

	got, want := A.Type().(*Alias).Rhs().String(), "p.B"
	if got != want {
		t.Errorf("A.Rhs = %s, want %s", got, want)
	}
}

// Test the hijacking described of "any" described in golang/go#66921, for
// (concurrent) type checking.
func TestAnyHijacking_Check(t *testing.T) {
	for _, enableAlias := range []bool{false, true} {
		t.Run(fmt.Sprintf("EnableAlias=%t", enableAlias), func(t *testing.T) {
			var wg sync.WaitGroup
			for i := 0; i < 10; i++ {
				wg.Add(1)
				go func() {
					defer wg.Done()
					pkg := mustTypecheck("package p; var x any", &Config{EnableAlias: enableAlias}, nil)
					x := pkg.Scope().Lookup("x")
					if _, gotAlias := x.Type().(*Alias); gotAlias != enableAlias {
						t.Errorf(`Lookup("x").Type() is %T: got Alias: %t, want %t`, x.Type(), gotAlias, enableAlias)
					}
				}()
			}
			wg.Wait()
		})
	}
}

// This test function only exists for go/types.
// func TestVersionIssue69477(t *testing.T)

// TestVersionWithoutPos is a regression test for issue #69477,
// in which the type checker would use position information
// to compute which file it is "in" based on syntax position.
//
// As a rule the type checker should not depend on position
// information for correctness, only for error messages and
// Object.Pos. (Scope.LookupParent was a mistake.)
//
// The Checker now holds the effective version in a state variable.
func TestVersionWithoutPos(t *testing.T) {
	f := mustParse("//go:build go1.22\n\npackage p; var _ int")

	// Splice in a decl from another file. Its pos will be wrong.
	f.DeclList[0] = mustParse("package q; func _(s func(func() bool)) { for range s {} }").DeclList[0]

	// Type check. The checker will consult the effective
	// version (1.22) for the for-range stmt to know whether
	// range-over-func are permitted: they are not.
	// (Previously, no error was reported.)
	pkg := NewPackage("p", "p")
	check := NewChecker(&Config{}, pkg, nil)
	err := check.Files([]*syntax.File{f})
	got := fmt.Sprint(err)
	want := "range over s (variable of type func(func() bool)): requires go1.23"
	if !strings.Contains(got, want) {
		t.Errorf("check error was %q, want substring %q", got, want)
	}
}
```