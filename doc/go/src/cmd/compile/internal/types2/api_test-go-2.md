Response:
Let's break down the thought process for analyzing this Go code snippet.

1. **Understand the Goal:** The request asks for a summary of the code's functionality, explanations of specific Go features it tests, code examples, handling of command-line arguments (if any), common mistakes users might make (if any), and confirmation that this is part 3 of a 4-part series.

2. **Initial Scan for Clues:**  Quickly read through the code, paying attention to function names, variable names, imports, and any constants. Key observations:
    * **`api_test.go`:**  This immediately suggests the code is for testing the API of some Go functionality.
    * **`go/src/cmd/compile/internal/types2`:** This path is crucial. It indicates the code tests the `types2` package, which is a reimplementation of the Go type checker used by the `compile` command.
    * **`Test...` functions:**  These are standard Go testing functions.
    * **`Config` struct:** Used to configure the type checker.
    * **`Info` struct:** Used to store information gathered during type checking.
    * **`Check` method:** Likely the core function being tested, performing type checking.
    * **Various helper functions:** `makePkg`, `mustParse`, `mustTypecheck`, `indexFor`, `newDefined`. These likely set up test environments.
    * **Specific test names:**  `TestSelectionString`, `TestIssue8518`, `TestIssue59603`, `TestLookupFieldOrMethodOnNil`, `TestLookupFieldOrMethod`, `TestLookupFieldOrMethod_RecursiveGeneric`, `TestConvertibleTo`, `TestAssignableTo`, `TestIdentical`, `TestIdentical_issue15173`, `TestIdenticalUnions`, `TestIssue61737`, `TestNewAlias_Issue65455`, `TestIssue15305`, `TestCompositeLitTypes`, `TestObjectParents`, `TestFailedImport`, `TestInstantiate`, `TestInstantiateConcurrent`, `TestInstantiateErrors`, `TestArgumentErrorUnwrapping`, `TestInstanceIdentity`, `TestInstantiatedObjects`, `TestImplements`, `TestMissingMethodAlternative`, `TestErrorURL`, `TestModuleVersion`, `TestFileVersions`. These names give strong hints about what each test does.

3. **Categorize Functionality based on Test Names:**  Group the tests by the Go feature they seem to be testing:
    * **Selections:** `TestSelectionString`
    * **Error Handling/Resilience:** `TestIssue8518`, `TestIssue59603`, `TestFailedImport`
    * **Field/Method Lookup:** `TestLookupFieldOrMethodOnNil`, `TestLookupFieldOrMethod`, `TestLookupFieldOrMethod_RecursiveGeneric`
    * **Type Conversion/Assignment:** `TestConvertibleTo`, `TestAssignableTo`
    * **Type Identity:** `TestIdentical`, `TestIdentical_issue15173`, `TestIdenticalUnions`, `TestInstanceIdentity`
    * **Interface Construction:** `TestIssue61737`
    * **Alias Types:** `TestNewAlias_Issue65455`
    * **Type Inference/Context:** `TestIssue15305`
    * **Composite Literals:** `TestCompositeLitTypes`
    * **Object Properties (Parents):** `TestObjectParents`
    * **Generics/Instantiation:** `TestInstantiate`, `TestInstantiateConcurrent`, `TestInstantiateErrors`, `TestArgumentErrorUnwrapping`, `TestInstantiatedObjects`
    * **Interface Implementation:** `TestImplements`, `TestMissingMethodAlternative`
    * **Error Reporting:** `TestErrorURL`
    * **Go Versioning:** `TestModuleVersion`, `TestFileVersions`

4. **Deep Dive into Key Tests (and generate examples):** Choose a few representative tests to examine more closely and generate illustrative examples:
    * **`TestSelectionString`:** Focus on how the type checker resolves field and method selections. The `selections` map provides the input. Create a simple code snippet demonstrating field and method access on structs and pointers.
    * **`TestLookupFieldOrMethod`:** This test explicitly checks the `LookupFieldOrMethod` function. Explain its purpose and create a scenario where it would be used (e.g., in code completion or reflection).
    * **`TestConvertibleTo` and `TestAssignableTo`:** These are fundamental type system concepts. Illustrate the difference between convertible and assignable with simple examples.
    * **`TestIdentical`:** Show cases where types are identical and where they are not, including named types, aliases, and generic functions.
    * **`TestInstantiate` and related:** Explain how generics are instantiated and potential errors that can occur. Create a simple generic function or struct.

5. **Address Specific Request Points:**
    * **Functionality Summary:** Combine the categorized functionality into a concise summary.
    * **Go Feature Implementation:** Explain the purpose and mechanics of each feature being tested (e.g., method expressions, type conversions, generics).
    * **Code Examples:** Provide clear and concise Go code examples for the key features.
    * **Input/Output for Code Inference:** For tests like `TestSelectionString`, the `wantOut` map acts as the "expected output". The input is the `mainSrc`.
    * **Command-Line Arguments:** Scan the code for any usage of `os.Args` or similar. In this case, there are none directly within the snippet. However, mention that the type checker itself might be invoked with compiler flags, but these tests are internal.
    * **Common Mistakes:**  Think about typical errors related to the tested features. For instance, confusion between convertibility and assignability, incorrect generic type arguments, or misunderstanding method sets.
    * **Part 3 of 4:** Simply acknowledge this as stated in the request.

6. **Refine and Organize:**  Structure the answer logically with clear headings and bullet points. Ensure the language is clear and easy to understand for someone familiar with Go. Double-check that all aspects of the request have been addressed.

7. **Self-Correction/Improvements During the Process:**
    * Initially, I might focus too much on the individual tests without seeing the bigger picture. Stepping back to categorize by Go feature helps.
    * When generating examples, I need to ensure they are simple and directly illustrate the tested concept. Avoid overly complex examples.
    * I need to distinguish between the *internal* workings of the type checker and how a *user* might interact with the corresponding Go features. This is important for explaining potential user mistakes.
    *  Remember to explicitly state when a feature is *not* present in the code (like direct handling of command-line arguments).

By following this thought process, we can systematically analyze the code snippet and generate a comprehensive and accurate answer to the request.
这是 `go/src/cmd/compile/internal/types2/api_test.go` 文件的第 3 部分，该文件是 Go 语言编译器中 `types2` 包的 API 测试。 `types2` 包是 Go 语言类型系统的重新实现，旨在提供更精确和一致的类型检查。

根据提供的代码片段，我们可以归纳出这部分代码的功能是 **测试 `types2` 包中关于类型选择 (Selection)、类型转换 (ConvertibleTo)、类型赋值 (AssignableTo)、类型恒等 (Identical)、以及与泛型和接口相关的一些核心类型系统功能**。

以下是更详细的分解：

**1. 测试类型选择 (Selection)**

`TestSelectionString` 函数测试了 `types2` 包中 `Selection` 类型的 `String()` 方法以及对字段和方法的索引 (`Index()`) 和间接访问 (`Indirect()`) 的判断。它通过预定义的源文件 `libSrc` 和 `mainSrc`，以及一个包含表达式和预期输出的 `selections` map，来验证 `types2` 能否正确地解析和描述各种类型的选择器表达式（例如，访问结构体字段、调用方法等）。

**Go 代码示例 (类型选择)**

假设 `mainSrc` 中有如下代码：

```go
package main

import "lib"

var a lib.A
var b lib.B

func main() {
	_ = a.X
	_ = a.f(1)
	_ = b.f(1)
}
```

并且 `libSrc` 定义了 `A` 和 `B`：

```go
package lib

type A struct {
	X int
}

func (a A) f(i int) int {
	return i
}

type B int

func (b B) f(i int) int {
	return i
}
```

`TestSelectionString` 会解析 `mainSrc` 中的 `a.X` 和 `a.f` 和 `b.f` 这些选择器表达式，并验证 `types2` 能否正确地识别它们是字段访问还是方法调用，以及它们的类型签名和索引。

**假设输入与输出:**

对于表达式 `a.X`，假设 `types2` 分析后得到的 `Selection` 对象 `sel`：

* `sel.String()` 可能返回 `"field (lib.A) X int"`
* `sel.Indirect()` 可能返回 `false`
* `sel.Index()` 可能返回 `[0]` (假设 `X` 是 `A` 的第一个字段)

对于表达式 `a.f`，假设 `types2` 分析后得到的 `Selection` 对象 `sel`：

* `sel.String()` 可能返回 `"method expr (lib.A) f(lib.A, int) int"`
* `sel.Indirect()` 可能返回 `false`
* `sel.Index()` 可能返回 `[0]` (假设 `f` 是 `A` 的第一个方法)

**2. 测试错误处理和代码健壮性**

`TestIssue8518` 和 `TestIssue59603` 看起来是针对特定 bug 的回归测试。它们模拟了在类型检查过程中遇到错误（例如，导入不存在的包，使用未定义的常量）的情况，并确保 `types2` 不会因此崩溃。这体现了 `types2` 在处理错误和保证代码健壮性方面的能力。

**3. 测试 `LookupFieldOrMethod` 函数**

`TestLookupFieldOrMethodOnNil` 测试了在 `LookupFieldOrMethod` 函数中传入 `nil` 类型时是否会产生 panic。

`TestLookupFieldOrMethod` 则更全面地测试了 `LookupFieldOrMethod` 函数的功能，该函数用于在给定类型中查找字段或方法。它覆盖了各种情况，包括：

* 查找字段和方法
* 查找泛型类型的字段和方法
* 方法的接收者是指针类型的情况
* 命名冲突的情况
* 在方法集之外查找方法的情况
* 递归泛型类型的情况

**Go 代码示例 (`LookupFieldOrMethod`)**

```go
package main

type MyStruct struct {
	Field int
}

func (m MyStruct) Method() {}

func main() {
	var s MyStruct
	// 假设 pkg 是包含了 MyStruct 定义的 *types2.Package
	field, _, _ := types2.LookupFieldOrMethod(types2.TypeOf(s), false, pkg, "Field")
	if field != nil {
		println("找到了字段 Field")
	}

	method, _, _ := types2.LookupFieldOrMethod(types2.TypeOf(s), false, pkg, "Method")
	if method != nil {
		println("找到了方法 Method")
	}
}
```

**假设输入与输出:**

对于 `LookupFieldOrMethod(types2.TypeOf(s), false, pkg, "Field")`，假设 `MyStruct` 的定义如上，则：

* `found` (返回值，表示是否找到) 为 `true`
* `index` (返回值，字段的索引) 为 `[0]`
* `indirect` (返回值，是否为间接访问) 为 `false`

**4. 测试类型之间的关系：可转换和可赋值**

`TestConvertibleTo` 和 `TestAssignableTo` 测试了 `types2` 包中的 `ConvertibleTo` 和 `AssignableTo` 函数，这两个函数分别用于判断一个类型的值是否可以转换为另一个类型，以及是否可以赋值给另一个类型的变量。

**Go 代码示例 (类型转换和赋值)**

```go
package main

import "fmt"

func main() {
	var i int = 10
	var f float32

	// 可转换
	f = float32(i)
	fmt.Println("i 可以转换为 float32:", f)

	type MyInt int
	var mi MyInt = 20

	// 不可直接赋值，因为是不同的命名类型
	// mi = i // 编译错误

	// 可以通过类型转换赋值
	mi = MyInt(i)
	fmt.Println("i 可以转换为 MyInt:", mi)

	var s string = "hello"
	// 不可转换
	// _ = int(s) // 编译错误

	// 可赋值
	var i2 int
	i2 = i
	fmt.Println("i 可以赋值给 i2:", i2)
}
```

**假设输入与输出:**

对于 `ConvertibleTo(types2.Typ[types2.Int], types2.Typ[types2.Float32])`，期望输出为 `true`。
对于 `AssignableTo(types2.Typ[types2.Int], types2.Typ[types2.Float32])`，期望输出为 `false`。
对于 `AssignableTo(types2.NewNamed(types2.NewTypeName(0, nil, "MyInt", nil), types2.Typ[types2.Int], nil), types2.Typ[types2.Int])`，期望输出为 `false`。

**5. 测试类型恒等 (Identical)**

`TestIdentical` 和相关的 `TestIdentical_issue15173` 和 `TestIdenticalUnions` 测试了 `types2` 包中的 `Identical` 函数，该函数用于判断两个类型是否完全相同。这些测试覆盖了基本类型、命名类型、别名类型、函数类型以及包含联合类型的情况。

**Go 代码示例 (类型恒等)**

```go
package main

import "fmt"

type MyInt int
type MyIntAlias = int

func main() {
	var i1 int
	var i2 int
	fmt.Println("int 与 int 相同:", types2.Identical(types2.TypeOf(i1), types2.TypeOf(i2))) // true

	var mi1 MyInt
	var mi2 MyInt
	fmt.Println("MyInt 与 MyInt 相同:", types2.Identical(types2.TypeOf(mi1), types2.TypeOf(mi2))) // true

	var mia1 MyIntAlias
	var mia2 MyIntAlias
	fmt.Println("MyIntAlias 与 MyIntAlias 相同:", types2.Identical(types2.TypeOf(mia1), types2.TypeOf(mia2))) // true

	fmt.Println("int 与 MyInt 相同:", types2.Identical(types2.TypeOf(i1), types2.TypeOf(mi1))) // false
	fmt.Println("int 与 MyIntAlias 相同:", types2.Identical(types2.TypeOf(i1), types2.TypeOf(mia1))) // true
}
```

**假设输入与输出:**

对于 `Identical(types2.Typ[types2.Int], types2.Typ[types2.Int])`，期望输出为 `true`。
对于 `Identical(types2.NewNamed(types2.NewTypeName(0, nil, "MyInt", nil), types2.Typ[types2.Int], nil), types2.Typ[types2.Int])`，期望输出为 `false`。
对于 `Identical(types2.NewAlias(types2.NewTypeName(0, nil, "MyIntAlias", nil), types2.Typ[types2.Int]), types2.Typ[types2.Int])`，期望输出为 `true`。

**6. 测试接口相关功能**

`TestIssue61737` 测试了构建包含重复方法的无效接口的情况，这对于导入器处理这种情况非常重要。

`TestImplements` 测试了 `Implements` 函数，用于判断一个类型是否实现了某个接口。

`TestMissingMethodAlternative` 测试了 `MissingMethod` 函数，用于查找一个类型缺少接口方法的原因，并可能提供替代方法的建议。

**7. 测试泛型相关功能**

代码中包含多个测试用例涉及到泛型，例如 `TestSelectionString` 中对泛型类型的方法和字段的选择，`TestLookupFieldOrMethod` 中对泛型类型的查找，以及 `TestInstantiate`、`TestInstantiateConcurrent` 和 `TestInstantiateErrors` 等函数，这些函数专门测试了 `types2` 包中关于泛型实例化、并发实例化以及实例化过程中可能出现的错误处理。

**8. 其他测试**

* `TestNewAlias_Issue65455` 测试了创建别名类型的功能。
* `TestIssue15305` 看起来与类型推断有关。
* `TestCompositeLitTypes` 测试了复合字面量的类型检查。
* `TestObjectParents` 测试了对象的父作用域。
* `TestFailedImport` 测试了导入失败时的错误处理。
* `TestArgumentErrorUnwrapping` 测试了错误类型的解包。
* `TestInstanceIdentity` 测试了泛型实例的身份。
* `TestInstantiatedObjects` 测试了实例化对象的属性。
* `TestErrorURL` 测试了错误消息中 URL 的生成。
* `TestModuleVersion` 和 `TestFileVersions` 测试了 Go 版本相关的处理。

**命令行参数处理：**

从提供的代码片段来看，并没有直接处理命令行参数。这些测试是通过 Go 的 `testing` 包运行的，通常不需要显式的命令行参数处理。

**使用者易犯错的点：**

由于这是 `types2` 包的内部测试，直接的使用者是 Go 编译器本身。开发者在使用 `go/types` 包（`types2` 的上层抽象）时，可能会犯以下错误，而这些测试可能间接地覆盖了这些方面：

* **混淆可转换 (ConvertibleTo) 和可赋值 (AssignableTo):**  新手可能会认为只要类型之间可以相互转换，就可以直接赋值。
* **对命名类型 (Named Types) 的理解不足:**  即使底层类型相同，不同的命名类型之间也不能直接赋值。
* **对方法集 (Method Set) 的理解不足:**  哪些类型实现了哪些方法，以及指针接收者和值接收者的区别。
* **泛型类型参数约束的理解:**  在实例化泛型时，提供的类型参数必须满足类型约束。

**总结一下它的功能：**

这部分 `api_test.go` 的主要功能是 **全面测试 `types2` 包中核心的类型系统功能，包括类型选择、错误处理、字段和方法查找、类型转换、类型赋值、类型恒等、接口实现以及泛型实例化等关键方面。** 这些测试确保了 `types2` 包的正确性和健壮性，为 Go 语言编译器的准确类型检查提供了基础保障。

### 提示词
```
这是路径为go/src/cmd/compile/internal/types2/api_test.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第3部分，共4部分，请归纳一下它的功能
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
```