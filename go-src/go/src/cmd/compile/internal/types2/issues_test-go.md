Response: My goal is to analyze the provided Go code snippet and explain its functionality, inferring the Go language features it tests, providing illustrative examples, detailing command-line argument handling (if any), and highlighting potential pitfalls for users.

**1. Understanding the Code's Structure:**

The code is a Go test file (`issues_test.go`) within the `cmd/compile/internal/types2` package. This immediately tells me it's part of the Go compiler's type checking mechanism and is used to test specific bug fixes or edge cases ("issues"). The presence of `testing` package imports confirms this. Each `TestIssueXXXXX` function likely corresponds to a reported bug or issue in Go's type system.

**2. Analyzing Individual Test Functions:**

I will iterate through each `TestIssueXXXXX` function and try to understand its purpose.

* **`TestIssue5770`:** This test checks for an "undefined" error when a type is used before it's defined within a struct. This is a standard Go behavior.

* **`TestIssue5849`:** This test examines the type inference of various expressions involving bit shifts, untyped constants, and interface conversions. It specifically checks the `TypeAndValue` information associated with different syntax nodes.

* **`TestIssue6413`:**  This test verifies that `defer` and `go` calls are correctly identified as `CallExpr` and have the expected function type.

* **`TestIssue7245`:** This test focuses on the handling of named return values in method declarations, especially when the receiver type is declared after the method. It checks if the defined variable for the return value is the same object.

* **`TestIssue7827`:**  This test is about correctly identifying definitions (`Defs`) and uses (`Uses`) of variables in assignment statements, including cases where the left-hand side is not a variable (resulting in an error).

* **`TestIssue13898`:** This test checks that the `Pkg()` method of an `Object` returns the correct package, regardless of the order of imports. This relates to how packages are tracked during type checking. It utilizes `testenv.MustHaveGoBuild(t)`, indicating a dependency on the Go build tool.

* **`TestIssue22525`:** This test checks that the type checker correctly reports "declared and not used" errors for multiple variables declared on the same line.

* **`TestIssue25627`:** This test addresses how the type checker handles missing or invalid types within struct field declarations. It counts the expected number of fields even with errors.

* **`TestIssue28005`:**  This test verifies the correct handling of embedded interfaces, particularly when the embedding involves multiple files and different import orders. It ensures the receiver type name of embedded methods matches the method name.

* **`TestIssue28282`:** This test focuses on how interfaces are "completed" lazily and ensures that embedded methods are correctly linked and looked up.

* **`TestIssue29029`:** This test checks that the definition of methods within an interface is consistent whether the files are type-checked together or incrementally.

* **`TestIssue34151`:** This test involves type checking across packages and uses a custom `Importer` to provide a pre-compiled package. It likely tests the correct handling of interface embedding across package boundaries.

* **`TestIssue34921`:** This test aims to prevent race conditions during concurrent type checking, specifically when resolving the underlying type of an imported type.

* **`TestIssue43088`:** This test is designed to ensure that the `Comparable` function doesn't lead to infinite recursion when dealing with mutually recursive type definitions.

* **`TestIssue44515`:** This test verifies the `TypeString` function's behavior, especially when using a custom qualifier function, as is the case for the `unsafe` package.

* **`TestIssue43124`:** This complex test deals with disambiguating package names in error messages when multiple packages have the same name (e.g., "template"). It utilizes an `importHelper` and `testFiles` to manage multi-file testing and error checking with regular expressions.

* **`TestIssue50646`:** This test checks the properties of the `any` and `comparable` predeclared types, specifically their comparability, implementation relationships, and assignability.

* **`TestIssue55030`:** This test ensures that creating function signatures with variadic parameters involving different types and type parameters doesn't cause panics.

* **`TestIssue51093`:** This test focuses on type conversions using type parameters, ensuring that the resulting type is the type parameter itself and not a constant.

* **`TestIssue54258`:** This test thoroughly examines error messages when interface implementation fails due to differences in the package paths of struct fields within method signatures.

* **`TestIssue59944`:** This test, requiring CGO, verifies that methods cannot be defined on aliases of CGO types. It involves parsing both Go source and generated CGO code.

* **`TestIssue61931`:** This test checks that the type checker doesn't panic when encountering syntax errors (specifically a missing comma in a function call).

* **`TestIssue61938`:** This test verifies that type checking doesn't panic even when an error handler is not provided.

* **`TestIssue63260`:** This test focuses on ensuring that type parameters declared in function signatures are correctly linked to their usage within the function body.

* **`TestIssue44410`:** This test checks how type aliases are represented in the string representation of types, particularly within struct definitions.

* **`TestIssue59831`:** This test extensively checks the correctness and clarity of error messages when interface implementation fails due to missing or unexported methods with similar names (case sensitivity).

* **`TestIssue64759`:** This test verifies that build constraints (`//go:build`) are correctly respected, even when the configured Go version differs.

* **`TestIssue68334`:** This test checks the error message produced when attempting to range over a non-rangeable type (like `int`) in Go versions prior to 1.22. It also verifies that providing an error handler doesn't cause a crash.

* **`TestIssue68877`:** This test ensures that the `String()` method of a `TypeName` doesn't panic when dealing with chains of type aliases.

* **`TestIssue69092`:** This test verifies that the type checker correctly infers the `Invalid` type for incomplete or erroneous composite literals.

**3. Inferring Go Language Features:**

Based on the tests, the code covers a wide range of Go language features related to the type system:

* **Structs and Fields:** Definition, usage, embedding.
* **Interfaces:** Definition, implementation, embedding, method sets, handling of unexported methods.
* **Functions and Methods:** Declarations, calls (including `defer` and `go`), named return values, receiver types.
* **Type Aliases:** Definition and their impact on type representation.
* **Type Parameters (Generics):** Definition, usage in function signatures and bodies, type constraints, type conversions.
* **Constants and Variables:** Declaration, assignment, scope, "declared and not used" errors.
* **Basic Types:** `int`, `uint`, `string`, `bool`, `float`, `complex`, `rune`, `byte`.
* **Composite Types:** Slices, maps, pointers, structs, interfaces.
* **Untyped Constants:** Their interaction with type inference.
* **Type Conversions:** Explicit conversions, especially with type parameters.
* **Package Imports:** Handling import order, resolving package paths.
* **Error Handling:** Checking for specific error messages.
* **Build Constraints:**  `//go:build` directives.
* **CGO:** Interaction with C types and method declarations on aliases.
* **Range Loop:**  Behavior in different Go versions.
* **The `any` and `comparable` interfaces.**

**4. Illustrative Examples (Go Code):**

* **Issue 5770 (Undefined Type):**
```go
package main

type S struct {
	T // Error: undefined: T
}
```

* **Issue 5849 (Type Inference):**
```go
package main

var (
	s uint
	_ = uint16(16) << s // Type of this expression is uint
)
```

* **Issue 7827 (Defs and Uses):**
```go
package main

func main() {
	const w = 1 // defs w
	x := 2       // defs x
	w, x = 3, 4  // uses w, uses x (error on w)
	_ = x        // uses x
}
```

* **Issue 28005 (Embedded Interfaces):**
```go
package p

type A interface {
	MethodA()
}

type B interface {
	MethodB()
}

type C interface {
	A
	B
}
```

* **Issue 51093 (Type Parameter Conversion):**
```go
package main

func f[T int](x T) {
	_ = T(5) // The type of T(5) is T
}
```

* **Issue 54258 (Interface Implementation Errors):**
```go
// main package
package main

import "otherpkg"

type I interface {
	M(otherpkg.MyStruct)
}

type S struct{}

func (S) M(otherpkg.MyStruct) {}

var _ I = S{} // Error if MyStruct's definition differs in otherpkg
```

**5. Command-Line Arguments:**

The provided code doesn't directly process command-line arguments. However, the `testenv.MustHaveGoBuild(t)` and `testenv.MustHaveCGO(t)` functions indicate dependencies on the Go build environment and CGO being enabled, which can be influenced by command-line flags when running tests (e.g., `-tags cgo`). The `Config` struct used in type checking might also be indirectly affected by build flags in some scenarios.

**6. User Pitfalls:**

* **Order of Declarations (Issue 5770):** Using a type before it's declared.
* **Understanding `Defs` and `Uses` (Issue 7827):**  Incorrectly assuming assignments always define new variables.
* **Case Sensitivity of Method Names (Issue 59831):**  Assuming that method names differing only in case will satisfy interface requirements.
* **Package Path Differences in Interface Satisfaction (Issue 54258):**  Not realizing that seemingly identical struct types from different packages are distinct for interface matching.
* **Assumptions about Type Identity with Aliases:**  While aliases provide alternative names, the underlying type remains the same. Subtle differences can arise in error messages or type representations.
* **Go Version Specific Behavior (Issue 68334):**  Code that works in later Go versions might produce errors in older ones, especially with features like range over integers.

**7. Code Inference with Assumptions:**

Let's take `TestIssue5849` as an example for code inference:

**Assumption:** The goal is to verify the correct type inference for various expressions.

**Input:** The `src` string containing Go code.

**Processing:** The `mustTypecheck` function (not shown but assumed to be a helper) performs type checking on the provided source code and populates the `Info.Types` map with the inferred types of expressions. The test then iterates through this map.

**Expected Output:** The test asserts that the `tv.Type` (inferred type) for specific `syntax.Expr` nodes matches the `want` type. For instance, the literal `"foo"` should have the type `string`. The `nil` in the interface conversion should have the type `interface{}`. Bit shift operations with `uint` variables should result in `uint` types.

**Example with Bit Shift:**

* **Input Code Snippet (from `src`):** `_ = uint16(16) << s`
* **Assumed Input Value of `s`:** Let's say `s` is a `uint` with a value of `2`.
* **Expected Output (`tv.Type` for the `<<` expression):** `uint` (because the shift amount is a `uint`).

**Example with Interface Conversion:**

* **Input Code Snippet (from `src`):** `_ = (interface{})("foo")`
* **Expected Output (`tv.Type` for `("foo")`):** `string`
* **Expected Output (`tv.Type` for `(interface{})("foo")`):** `interface{}`

This detailed breakdown addresses all the requirements of the prompt, providing insights into the code's purpose, the Go features it tests, illustrative examples, potential pitfalls, and a demonstration of code inference.
Let's break down the functionality of the provided Go code snippet from `go/src/cmd/compile/internal/types2/issues_test.go`.

**Core Functionality:**

This file serves as a collection of **integration tests** for the `types2` package. The `types2` package is a reimplementation of the Go type checker. Each `TestIssueXXXX` function targets a specific bug or edge case that was encountered and fixed in the `types2` type checker.

**Key Features and Go Language Aspects Tested:**

Here's a breakdown of the functionalities demonstrated by the individual test functions, along with inferences about the Go language features being tested:

* **`TestIssue5770`:**
    * **Functionality:** Tests the error handling when an undefined type is used within a struct definition.
    * **Go Feature:**  Struct types, type definitions, error reporting during type checking.
    * **Inference:** The type checker should correctly identify and report an error when a type name is used before it's defined.

* **`TestIssue5849`:**
    * **Functionality:**  Verifies the type inference for various expressions, including bitwise left shifts with untyped constants and `uint` variables, and interface conversions.
    * **Go Feature:** Type inference, integer literals, bitwise operators, untyped constants, interface conversions.
    * **Inference:** The type checker should correctly deduce the resulting types of these expressions based on the operands' types and Go's type promotion rules.
    * **Example:**
        ```go
        package main

        func main() {
            var s uint
            _ = uint16(16) << s // The result type should be uint
            _ = (interface{})("hello") // The result type should be interface{}
        }
        ```
        **Assumption:** `s` is a `uint`.
        **Output:** The type checker should mark the first expression's type as `uint` and the second as `interface{}`.

* **`TestIssue6413`:**
    * **Functionality:** Checks that `defer` and `go` statements involving function calls are correctly identified as `CallExpr` and have the expected function type.
    * **Go Feature:** `defer` statement, `go` statement, function calls, type checking of function calls.
    * **Inference:** The type checker needs to correctly identify function calls within `defer` and `go` statements and assign them the appropriate function type.
    * **Example:**
        ```go
        package main

        func f() int { return 0 }

        func main() {
            defer f() // This is a CallExpr of type func() int
            go f()    // This is also a CallExpr of type func() int
        }
        ```

* **`TestIssue7245`:**
    * **Functionality:**  Ensures that the named return value in a method declaration is correctly linked to the corresponding `Var` object, even when the receiver type is declared after the method.
    * **Go Feature:** Methods, named return values, receiver types declared after the method.
    * **Inference:** The type checker should correctly associate the named return variable with its declaration.

* **`TestIssue7827`:**
    * **Functionality:** Tests the identification of definitions (`Defs`) and uses (`Uses`) of variables in assignment statements, including cases where the left-hand side is not a variable (resulting in an error).
    * **Go Feature:** Variable declaration, assignment statements, constant declarations, error reporting for invalid assignments.
    * **Inference:** The type checker needs to distinguish between defining a new variable and using an existing one in assignments. It should also detect and report errors when attempting to assign to non-variable expressions.

* **`TestIssue13898`:**
    * **Functionality:** Verifies that the `Pkg()` method of an `Object` returns the correct package, regardless of the order in which imports are listed.
    * **Go Feature:** Package imports, `go/types` package, `Object.Pkg()` method.
    * **Inference:** The internal representation of packages should be consistent and accessible through the `Pkg()` method, independent of import order.
    * **Command-line Parameters:** This test likely relies on the Go build environment being set up correctly so that the `go/types` package can be resolved. No specific command-line arguments are processed directly within the test code itself.

* **`TestIssue22525`:**
    * **Functionality:**  Checks that the type checker correctly reports "declared and not used" errors for multiple variables declared on the same line.
    * **Go Feature:** Multiple variable declarations on a single line, unused variable detection.
    * **Inference:** The type checker should iterate through all declared variables and flag those that are not subsequently used.

* **`TestIssue25627`:**
    * **Functionality:** Tests the resilience of the type checker when encountering missing or invalid types within struct field declarations. It verifies that the number of fields is still correctly counted.
    * **Go Feature:** Struct types, handling of undefined types in struct fields, error handling during type checking.
    * **Inference:** Even if a field's type is invalid, the type checker should be able to continue processing the struct definition and count the intended number of fields.

* **`TestIssue28005`:**
    * **Functionality:** Checks the correct handling of embedded interfaces, particularly when the embedding involves multiple files and different import orders. It ensures the receiver base type name of embedded methods matches the method's name.
    * **Go Feature:** Interface embedding, methods, receiver types, handling of multi-file packages.
    * **Inference:** The type checker needs to correctly resolve embedded interfaces and associate the methods with their originating types, regardless of file order.

* **`TestIssue28282`:**
    * **Functionality:** Tests the lazy completion of interfaces and ensures that embedded methods are correctly linked and looked up even after interface completion.
    * **Go Feature:** Interface completion, embedded interfaces, method lookup.
    * **Inference:** The type checker's lazy evaluation of interface properties should not lead to inconsistencies in method resolution.

* **`TestIssue29029`:**
    * **Functionality:**  Verifies that the definition of methods within an interface is consistent whether the files are type-checked together or incrementally.
    * **Go Feature:** Interface definitions, methods, incremental type checking.
    * **Inference:**  The type checking process should produce the same results whether all files are processed at once or in stages.

* **`TestIssue34151`:**
    * **Functionality:** Tests type checking across packages, specifically when an interface is defined in one package and used in another, and the importer provides a pre-compiled package.
    * **Go Feature:** Package imports, interfaces, custom importers.
    * **Inference:** The type checker should correctly handle interface satisfaction across package boundaries when using a custom importer.

* **`TestIssue34921`:**
    * **Functionality:**  Aims to prevent race conditions during concurrent type checking when resolving the underlying type of an imported type.
    * **Go Feature:** Type checking of imported types, concurrency safety.
    * **Inference:** The type checker should be designed to avoid data races when multiple goroutines are involved in type checking.

* **`TestIssue43088`:**
    * **Functionality:** Ensures that the `Comparable` function doesn't lead to infinite recursion when dealing with mutually recursive type definitions.
    * **Go Feature:** Type comparison, recursive types.
    * **Inference:** The `Comparable` function needs to handle potentially infinite type structures without crashing.

* **`TestIssue44515`:**
    * **Functionality:** Verifies the `TypeString` function's behavior, especially when using a custom qualifier function, as is the case for the `unsafe` package.
    * **Go Feature:**  Type string representation, custom type qualifiers.
    * **Inference:** The `TypeString` function should correctly use provided qualifier functions to generate appropriate string representations of types.

* **`TestIssue43124`:**
    * **Functionality:** Deals with disambiguating package names in error messages when multiple packages have the same name (e.g., "template").
    * **Go Feature:** Error reporting, package naming, import paths.
    * **Inference:** Error messages should be informative and clearly distinguish between packages with the same name using their full import paths.

* **`TestIssue50646`:**
    * **Functionality:** Checks the properties of the `any` and `comparable` predeclared types, specifically their comparability, implementation relationships, and assignability.
    * **Go Feature:** `any` type, `comparable` type, interface implementation, assignability.
    * **Inference:** The type checker should correctly understand the specific behaviors and relationships of these special types.

* **`TestIssue55030`:**
    * **Functionality:** Ensures that creating function signatures with variadic parameters involving different types and type parameters doesn't cause panics.
    * **Go Feature:** Variadic functions, type parameters, function signatures.
    * **Inference:** The type checker should handle complex function signature constructions without internal errors.

* **`TestIssue51093`:**
    * **Functionality:** Focuses on type conversions using type parameters, ensuring that the resulting type is the type parameter itself and not a constant.
    * **Go Feature:** Type parameters, type conversions.
    * **Inference:** When converting a value to a type parameter, the resulting type should be the type parameter itself.

* **`TestIssue54258`:**
    * **Functionality:** Thoroughly examines error messages when interface implementation fails due to differences in the package paths of struct fields within method signatures.
    * **Go Feature:** Interface implementation, struct types, package paths in type signatures.
    * **Inference:** Error messages for failed interface implementations should clearly highlight discrepancies in package paths of involved types.

* **`TestIssue59944`:**
    * **Functionality:** Verifies that methods cannot be defined on aliases of CGO types.
    * **Go Feature:** CGO, type aliases, method declarations on non-local types.
    * **Inference:** The type checker should enforce the restriction against defining methods on aliases of types originating from CGO.
    * **Command-line Parameters:** This test uses the `// -gotypesalias=1` directive, which influences how CGO types are handled. It also implicitly depends on CGO being enabled during the test execution.

* **`TestIssue61931`:**
    * **Functionality:** Checks that the type checker doesn't panic when encountering syntax errors (specifically a missing comma in a function call).
    * **Go Feature:** Error handling, syntax errors, robustness of the type checker.
    * **Inference:** The type checker should gracefully handle syntax errors without crashing.

* **`TestIssue61938`:**
    * **Functionality:** Verifies that type checking doesn't panic even when an error handler is not provided.
    * **Go Feature:** Error handling, robustness of the type checker.
    * **Inference:** The type checker should have default error handling behavior if no custom handler is supplied.

* **`TestIssue63260`:**
    * **Functionality:** Focuses on ensuring that type parameters declared in function signatures are correctly linked to their usage within the function body.
    * **Go Feature:** Type parameters, scope of type parameters.
    * **Inference:** The type checker should maintain the correct association between type parameters declared in the function signature and their usage within the function's scope.

* **`TestIssue44410`:**
    * **Functionality:** Checks how type aliases are represented in the string representation of types, particularly within struct definitions.
    * **Go Feature:** Type aliases, string representation of types.
    * **Inference:** The string representation of types should reflect the presence of type aliases when enabled.

* **`TestIssue59831`:**
    * **Functionality:** This test extensively checks the correctness and clarity of error messages when interface implementation fails due to missing or unexported methods with similar names (case sensitivity).
    * **Go Feature:** Interface implementation, method sets, case sensitivity of method names, error reporting.
    * **Inference:** Error messages should clearly indicate why an interface is not implemented, including details about missing or unexported methods and case mismatches.

* **`TestIssue64759`:**
    * **Functionality:** Verifies that build constraints (`//go:build`) are correctly respected, even when the configured Go version differs.
    * **Go Feature:** Build constraints, Go version directives.
    * **Inference:** The type checker should honor build constraints and only process code intended for the target Go version.

* **`TestIssue68334`:**
    * **Functionality:** Checks the error message produced when attempting to range over a non-rangeable type (like `int`) in Go versions prior to 1.22. It also verifies that providing an error handler doesn't cause a crash.
    * **Go Feature:** Range loops, Go versioning, error handling.
    * **Inference:** The type checker should correctly enforce the restrictions on range loops based on the specified Go version.

* **`TestIssue68877`:**
    * **Functionality:** Ensures that the `String()` method of a `TypeName` doesn't panic when dealing with chains of type aliases.
    * **Go Feature:** Type aliases, string representation of types, robustness.
    * **Inference:** The string representation logic for type names should handle complex alias chains without errors.

* **`TestIssue69092`:**
    * **Functionality:** Verifies that the type checker correctly infers the `Invalid` type for incomplete or erroneous composite literals.
    * **Go Feature:** Composite literals, error handling, `Invalid` type.
    * **Inference:** When encountering malformed composite literals, the type checker should assign the `Invalid` type.

**General Observations and Potential Pitfalls for Users:**

* **Understanding Type Inference:**  Users might be surprised by how Go infers types in certain situations (e.g., with untyped constants). `TestIssue5849` highlights this.
* **Interface Implementation Rules:** The tests around interface implementation (`TestIssue54258`, `TestIssue59831`) emphasize the strict rules, including case sensitivity of method names and the importance of matching package paths for struct fields in method signatures.
* **Go Version Dependencies:** Features like the behavior of range loops (`TestIssue68334`) can vary across Go versions. Users need to be aware of these differences.
* **CGO Interactions:**  Working with CGO introduces specific constraints, such as the inability to define methods on aliases of CGO types (`TestIssue59944`).
* **Error Handling:** The tests demonstrate how the type checker handles errors and the importance of providing error handlers when needed.

This comprehensive analysis should provide a clear understanding of the functionality of the provided Go code and the Go language features it tests.

Prompt: 
```
这是路径为go/src/cmd/compile/internal/types2/issues_test.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，

"""
// Copyright 2013 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// This file implements tests for various issues.

package types2_test

import (
	"cmd/compile/internal/syntax"
	"fmt"
	"internal/testenv"
	"regexp"
	"slices"
	"strings"
	"testing"

	. "cmd/compile/internal/types2"
)

func TestIssue5770(t *testing.T) {
	_, err := typecheck(`package p; type S struct{T}`, nil, nil)
	const want = "undefined: T"
	if err == nil || !strings.Contains(err.Error(), want) {
		t.Errorf("got: %v; want: %s", err, want)
	}
}

func TestIssue5849(t *testing.T) {
	src := `
package p
var (
	s uint
	_ = uint8(8)
	_ = uint16(16) << s
	_ = uint32(32 << s)
	_ = uint64(64 << s + s)
	_ = (interface{})("foo")
	_ = (interface{})(nil)
)`
	types := make(map[syntax.Expr]TypeAndValue)
	mustTypecheck(src, nil, &Info{Types: types})

	for x, tv := range types {
		var want Type
		switch x := x.(type) {
		case *syntax.BasicLit:
			switch x.Value {
			case `8`:
				want = Typ[Uint8]
			case `16`:
				want = Typ[Uint16]
			case `32`:
				want = Typ[Uint32]
			case `64`:
				want = Typ[Uint] // because of "+ s", s is of type uint
			case `"foo"`:
				want = Typ[String]
			}
		case *syntax.Name:
			if x.Value == "nil" {
				want = NewInterfaceType(nil, nil) // interface{} (for now, go/types types this as "untyped nil")
			}
		}
		if want != nil && !Identical(tv.Type, want) {
			t.Errorf("got %s; want %s", tv.Type, want)
		}
	}
}

func TestIssue6413(t *testing.T) {
	src := `
package p
func f() int {
	defer f()
	go f()
	return 0
}
`
	types := make(map[syntax.Expr]TypeAndValue)
	mustTypecheck(src, nil, &Info{Types: types})

	want := Typ[Int]
	n := 0
	for x, tv := range types {
		if _, ok := x.(*syntax.CallExpr); ok {
			if tv.Type != want {
				t.Errorf("%s: got %s; want %s", x.Pos(), tv.Type, want)
			}
			n++
		}
	}

	if n != 2 {
		t.Errorf("got %d CallExprs; want 2", n)
	}
}

func TestIssue7245(t *testing.T) {
	src := `
package p
func (T) m() (res bool) { return }
type T struct{} // receiver type after method declaration
`
	f := mustParse(src)

	var conf Config
	defs := make(map[*syntax.Name]Object)
	_, err := conf.Check(f.PkgName.Value, []*syntax.File{f}, &Info{Defs: defs})
	if err != nil {
		t.Fatal(err)
	}

	m := f.DeclList[0].(*syntax.FuncDecl)
	res1 := defs[m.Name].(*Func).Type().(*Signature).Results().At(0)
	res2 := defs[m.Type.ResultList[0].Name].(*Var)

	if res1 != res2 {
		t.Errorf("got %s (%p) != %s (%p)", res1, res2, res1, res2)
	}
}

// This tests that uses of existing vars on the LHS of an assignment
// are Uses, not Defs; and also that the (illegal) use of a non-var on
// the LHS of an assignment is a Use nonetheless.
func TestIssue7827(t *testing.T) {
	const src = `
package p
func _() {
	const w = 1        // defs w
        x, y := 2, 3       // defs x, y
        w, x, z := 4, 5, 6 // uses w, x, defs z; error: cannot assign to w
        _, _, _ = x, y, z  // uses x, y, z
}
`
	const want = `L3 defs func p._()
L4 defs const w untyped int
L5 defs var x int
L5 defs var y int
L6 defs var z int
L6 uses const w untyped int
L6 uses var x int
L7 uses var x int
L7 uses var y int
L7 uses var z int`

	// don't abort at the first error
	conf := Config{Error: func(err error) { t.Log(err) }}
	defs := make(map[*syntax.Name]Object)
	uses := make(map[*syntax.Name]Object)
	_, err := typecheck(src, &conf, &Info{Defs: defs, Uses: uses})
	if s := err.Error(); !strings.HasSuffix(s, "cannot assign to w") {
		t.Errorf("Check: unexpected error: %s", s)
	}

	var facts []string
	for id, obj := range defs {
		if obj != nil {
			fact := fmt.Sprintf("L%d defs %s", id.Pos().Line(), obj)
			facts = append(facts, fact)
		}
	}
	for id, obj := range uses {
		fact := fmt.Sprintf("L%d uses %s", id.Pos().Line(), obj)
		facts = append(facts, fact)
	}
	slices.Sort(facts)

	got := strings.Join(facts, "\n")
	if got != want {
		t.Errorf("Unexpected defs/uses\ngot:\n%s\nwant:\n%s", got, want)
	}
}

// This tests that the package associated with the types2.Object.Pkg method
// is the type's package independent of the order in which the imports are
// listed in the sources src1, src2 below.
// The actual issue is in go/internal/gcimporter which has a corresponding
// test; we leave this test here to verify correct behavior at the go/types
// level.
func TestIssue13898(t *testing.T) {
	testenv.MustHaveGoBuild(t)

	const src0 = `
package main

import "go/types"

func main() {
	var info types.Info
	for _, obj := range info.Uses {
		_ = obj.Pkg()
	}
}
`
	// like src0, but also imports go/importer
	const src1 = `
package main

import (
	"go/types"
	_ "go/importer"
)

func main() {
	var info types.Info
	for _, obj := range info.Uses {
		_ = obj.Pkg()
	}
}
`
	// like src1 but with different import order
	// (used to fail with this issue)
	const src2 = `
package main

import (
	_ "go/importer"
	"go/types"
)

func main() {
	var info types.Info
	for _, obj := range info.Uses {
		_ = obj.Pkg()
	}
}
`
	f := func(test, src string) {
		info := &Info{Uses: make(map[*syntax.Name]Object)}
		mustTypecheck(src, nil, info)

		var pkg *Package
		count := 0
		for id, obj := range info.Uses {
			if id.Value == "Pkg" {
				pkg = obj.Pkg()
				count++
			}
		}
		if count != 1 {
			t.Fatalf("%s: got %d entries named Pkg; want 1", test, count)
		}
		if pkg.Name() != "types" {
			t.Fatalf("%s: got %v; want package types2", test, pkg)
		}
	}

	f("src0", src0)
	f("src1", src1)
	f("src2", src2)
}

func TestIssue22525(t *testing.T) {
	const src = `package p; func f() { var a, b, c, d, e int }`

	got := "\n"
	conf := Config{Error: func(err error) { got += err.Error() + "\n" }}
	typecheck(src, &conf, nil) // do not crash
	want := "\n" +
		"p:1:27: declared and not used: a\n" +
		"p:1:30: declared and not used: b\n" +
		"p:1:33: declared and not used: c\n" +
		"p:1:36: declared and not used: d\n" +
		"p:1:39: declared and not used: e\n"
	if got != want {
		t.Errorf("got: %swant: %s", got, want)
	}
}

func TestIssue25627(t *testing.T) {
	const prefix = `package p; import "unsafe"; type P *struct{}; type I interface{}; type T `
	// The src strings (without prefix) are constructed such that the number of semicolons
	// plus one corresponds to the number of fields expected in the respective struct.
	for _, src := range []string{
		`struct { x Missing }`,
		`struct { Missing }`,
		`struct { *Missing }`,
		`struct { unsafe.Pointer }`,
		`struct { P }`,
		`struct { *I }`,
		`struct { a int; b Missing; *Missing }`,
	} {
		f := mustParse(prefix + src)

		conf := Config{Importer: defaultImporter(), Error: func(err error) {}}
		info := &Info{Types: make(map[syntax.Expr]TypeAndValue)}
		_, err := conf.Check(f.PkgName.Value, []*syntax.File{f}, info)
		if err != nil {
			if _, ok := err.(Error); !ok {
				t.Fatal(err)
			}
		}

		syntax.Inspect(f, func(n syntax.Node) bool {
			if decl, _ := n.(*syntax.TypeDecl); decl != nil {
				if tv, ok := info.Types[decl.Type]; ok && decl.Name.Value == "T" {
					want := strings.Count(src, ";") + 1
					if got := tv.Type.(*Struct).NumFields(); got != want {
						t.Errorf("%s: got %d fields; want %d", src, got, want)
					}
				}
			}
			return true
		})
	}
}

func TestIssue28005(t *testing.T) {
	// method names must match defining interface name for this test
	// (see last comment in this function)
	sources := [...]string{
		"package p; type A interface{ A() }",
		"package p; type B interface{ B() }",
		"package p; type X interface{ A; B }",
	}

	// compute original file ASTs
	var orig [len(sources)]*syntax.File
	for i, src := range sources {
		orig[i] = mustParse(src)
	}

	// run the test for all order permutations of the incoming files
	for _, perm := range [][len(sources)]int{
		{0, 1, 2},
		{0, 2, 1},
		{1, 0, 2},
		{1, 2, 0},
		{2, 0, 1},
		{2, 1, 0},
	} {
		// create file order permutation
		files := make([]*syntax.File, len(sources))
		for i := range perm {
			files[i] = orig[perm[i]]
		}

		// type-check package with given file order permutation
		var conf Config
		info := &Info{Defs: make(map[*syntax.Name]Object)}
		_, err := conf.Check("", files, info)
		if err != nil {
			t.Fatal(err)
		}

		// look for interface object X
		var obj Object
		for name, def := range info.Defs {
			if name.Value == "X" {
				obj = def
				break
			}
		}
		if obj == nil {
			t.Fatal("object X not found")
		}
		iface := obj.Type().Underlying().(*Interface) // object X must be an interface

		// Each iface method m is embedded; and m's receiver base type name
		// must match the method's name per the choice in the source file.
		for i := 0; i < iface.NumMethods(); i++ {
			m := iface.Method(i)
			recvName := m.Type().(*Signature).Recv().Type().(*Named).Obj().Name()
			if recvName != m.Name() {
				t.Errorf("perm %v: got recv %s; want %s", perm, recvName, m.Name())
			}
		}
	}
}

func TestIssue28282(t *testing.T) {
	// create type interface { error }
	et := Universe.Lookup("error").Type()
	it := NewInterfaceType(nil, []Type{et})
	// verify that after completing the interface, the embedded method remains unchanged
	// (interfaces are "completed" lazily now, so the completion happens implicitly when
	// accessing Method(0))
	want := et.Underlying().(*Interface).Method(0)
	got := it.Method(0)
	if got != want {
		t.Fatalf("%s.Method(0): got %q (%p); want %q (%p)", it, got, got, want, want)
	}
	// verify that lookup finds the same method in both interfaces (redundant check)
	obj, _, _ := LookupFieldOrMethod(et, false, nil, "Error")
	if obj != want {
		t.Fatalf("%s.Lookup: got %q (%p); want %q (%p)", et, obj, obj, want, want)
	}
	obj, _, _ = LookupFieldOrMethod(it, false, nil, "Error")
	if obj != want {
		t.Fatalf("%s.Lookup: got %q (%p); want %q (%p)", it, obj, obj, want, want)
	}
}

func TestIssue29029(t *testing.T) {
	f1 := mustParse(`package p; type A interface { M() }`)
	f2 := mustParse(`package p; var B interface { A }`)

	// printInfo prints the *Func definitions recorded in info, one *Func per line.
	printInfo := func(info *Info) string {
		var buf strings.Builder
		for _, obj := range info.Defs {
			if fn, ok := obj.(*Func); ok {
				fmt.Fprintln(&buf, fn)
			}
		}
		return buf.String()
	}

	// The *Func (method) definitions for package p must be the same
	// independent on whether f1 and f2 are type-checked together, or
	// incrementally.

	// type-check together
	var conf Config
	info := &Info{Defs: make(map[*syntax.Name]Object)}
	check := NewChecker(&conf, NewPackage("", "p"), info)
	if err := check.Files([]*syntax.File{f1, f2}); err != nil {
		t.Fatal(err)
	}
	want := printInfo(info)

	// type-check incrementally
	info = &Info{Defs: make(map[*syntax.Name]Object)}
	check = NewChecker(&conf, NewPackage("", "p"), info)
	if err := check.Files([]*syntax.File{f1}); err != nil {
		t.Fatal(err)
	}
	if err := check.Files([]*syntax.File{f2}); err != nil {
		t.Fatal(err)
	}
	got := printInfo(info)

	if got != want {
		t.Errorf("\ngot : %swant: %s", got, want)
	}
}

func TestIssue34151(t *testing.T) {
	const asrc = `package a; type I interface{ M() }; type T struct { F interface { I } }`
	const bsrc = `package b; import "a"; type T struct { F interface { a.I } }; var _ = a.T(T{})`

	a := mustTypecheck(asrc, nil, nil)

	conf := Config{Importer: importHelper{pkg: a}}
	mustTypecheck(bsrc, &conf, nil)
}

type importHelper struct {
	pkg      *Package
	fallback Importer
}

func (h importHelper) Import(path string) (*Package, error) {
	if path == h.pkg.Path() {
		return h.pkg, nil
	}
	if h.fallback == nil {
		return nil, fmt.Errorf("got package path %q; want %q", path, h.pkg.Path())
	}
	return h.fallback.Import(path)
}

// TestIssue34921 verifies that we don't update an imported type's underlying
// type when resolving an underlying type. Specifically, when determining the
// underlying type of b.T (which is the underlying type of a.T, which is int)
// we must not set the underlying type of a.T again since that would lead to
// a race condition if package b is imported elsewhere, in a package that is
// concurrently type-checked.
func TestIssue34921(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Error(r)
		}
	}()

	var sources = []string{
		`package a; type T int`,
		`package b; import "a"; type T a.T`,
	}

	var pkg *Package
	for _, src := range sources {
		conf := Config{Importer: importHelper{pkg: pkg}}
		pkg = mustTypecheck(src, &conf, nil) // pkg imported by the next package in this test
	}
}

func TestIssue43088(t *testing.T) {
	// type T1 struct {
	//         _ T2
	// }
	//
	// type T2 struct {
	//         _ struct {
	//                 _ T2
	//         }
	// }
	n1 := NewTypeName(nopos, nil, "T1", nil)
	T1 := NewNamed(n1, nil, nil)
	n2 := NewTypeName(nopos, nil, "T2", nil)
	T2 := NewNamed(n2, nil, nil)
	s1 := NewStruct([]*Var{NewField(nopos, nil, "_", T2, false)}, nil)
	T1.SetUnderlying(s1)
	s2 := NewStruct([]*Var{NewField(nopos, nil, "_", T2, false)}, nil)
	s3 := NewStruct([]*Var{NewField(nopos, nil, "_", s2, false)}, nil)
	T2.SetUnderlying(s3)

	// These calls must terminate (no endless recursion).
	Comparable(T1)
	Comparable(T2)
}

func TestIssue44515(t *testing.T) {
	typ := Unsafe.Scope().Lookup("Pointer").Type()

	got := TypeString(typ, nil)
	want := "unsafe.Pointer"
	if got != want {
		t.Errorf("got %q; want %q", got, want)
	}

	qf := func(pkg *Package) string {
		if pkg == Unsafe {
			return "foo"
		}
		return ""
	}
	got = TypeString(typ, qf)
	want = "foo.Pointer"
	if got != want {
		t.Errorf("got %q; want %q", got, want)
	}
}

func TestIssue43124(t *testing.T) {
	// TODO(rFindley) move this to testdata by enhancing support for importing.

	testenv.MustHaveGoBuild(t) // The go command is needed for the importer to determine the locations of stdlib .a files.

	// All involved packages have the same name (template). Error messages should
	// disambiguate between text/template and html/template by printing the full
	// path.
	const (
		asrc = `package a; import "text/template"; func F(template.Template) {}; func G(int) {}`
		bsrc = `
package b

import (
	"a"
	"html/template"
)

func _() {
	// Packages should be fully qualified when there is ambiguity within the
	// error string itself.
	a.F(template /* ERRORx "cannot use.*html/template.* as .*text/template" */ .Template{})
}
`
		csrc = `
package c

import (
	"a"
	"fmt"
	"html/template"
)

// go.dev/issue/46905: make sure template is not the first package qualified.
var _ fmt.Stringer = 1 // ERRORx "cannot use 1.*as fmt\\.Stringer"

// Packages should be fully qualified when there is ambiguity in reachable
// packages. In this case both a (and for that matter html/template) import
// text/template.
func _() { a.G(template /* ERRORx "cannot use .*html/template.*Template" */ .Template{}) }
`

		tsrc = `
package template

import "text/template"

type T int

// Verify that the current package name also causes disambiguation.
var _ T = template /* ERRORx "cannot use.*text/template.* as T value" */.Template{}
`
	)

	a := mustTypecheck(asrc, nil, nil)
	imp := importHelper{pkg: a, fallback: defaultImporter()}

	withImporter := func(cfg *Config) {
		cfg.Importer = imp
	}

	testFiles(t, []string{"b.go"}, [][]byte{[]byte(bsrc)}, 0, false, withImporter)
	testFiles(t, []string{"c.go"}, [][]byte{[]byte(csrc)}, 0, false, withImporter)
	testFiles(t, []string{"t.go"}, [][]byte{[]byte(tsrc)}, 0, false, withImporter)
}

func TestIssue50646(t *testing.T) {
	anyType := Universe.Lookup("any").Type().Underlying()
	comparableType := Universe.Lookup("comparable").Type()

	if !Comparable(anyType) {
		t.Error("any is not a comparable type")
	}
	if !Comparable(comparableType) {
		t.Error("comparable is not a comparable type")
	}

	if Implements(anyType, comparableType.Underlying().(*Interface)) {
		t.Error("any implements comparable")
	}
	if !Implements(comparableType, anyType.(*Interface)) {
		t.Error("comparable does not implement any")
	}

	if AssignableTo(anyType, comparableType) {
		t.Error("any assignable to comparable")
	}
	if !AssignableTo(comparableType, anyType) {
		t.Error("comparable not assignable to any")
	}
}

func TestIssue55030(t *testing.T) {
	// makeSig makes the signature func(typ...)
	makeSig := func(typ Type) {
		par := NewVar(nopos, nil, "", typ)
		params := NewTuple(par)
		NewSignatureType(nil, nil, nil, params, nil, true)
	}

	// makeSig must not panic for the following (example) types:
	// []int
	makeSig(NewSlice(Typ[Int]))

	// string
	makeSig(Typ[String])

	// P where P's core type is string
	{
		P := NewTypeName(nopos, nil, "P", nil) // [P string]
		makeSig(NewTypeParam(P, NewInterfaceType(nil, []Type{Typ[String]})))
	}

	// P where P's core type is an (unnamed) slice
	{
		P := NewTypeName(nopos, nil, "P", nil) // [P []int]
		makeSig(NewTypeParam(P, NewInterfaceType(nil, []Type{NewSlice(Typ[Int])})))
	}

	// P where P's core type is bytestring (i.e., string or []byte)
	{
		t1 := NewTerm(true, Typ[String])          // ~string
		t2 := NewTerm(false, NewSlice(Typ[Byte])) // []byte
		u := NewUnion([]*Term{t1, t2})            // ~string | []byte
		P := NewTypeName(nopos, nil, "P", nil)    // [P ~string | []byte]
		makeSig(NewTypeParam(P, NewInterfaceType(nil, []Type{u})))
	}
}

func TestIssue51093(t *testing.T) {
	// Each test stands for a conversion of the form P(val)
	// where P is a type parameter with typ as constraint.
	// The test ensures that P(val) has the correct type P
	// and is not a constant.
	var tests = []struct {
		typ string
		val string
	}{
		{"bool", "false"},
		{"int", "-1"},
		{"uint", "1.0"},
		{"rune", "'a'"},
		{"float64", "3.5"},
		{"complex64", "1.25"},
		{"string", "\"foo\""},

		// some more complex constraints
		{"~byte", "1"},
		{"~int | ~float64 | complex128", "1"},
		{"~uint64 | ~rune", "'X'"},
	}

	for _, test := range tests {
		src := fmt.Sprintf("package p; func _[P %s]() { _ = P(%s) }", test.typ, test.val)
		types := make(map[syntax.Expr]TypeAndValue)
		mustTypecheck(src, nil, &Info{Types: types})

		var n int
		for x, tv := range types {
			if x, _ := x.(*syntax.CallExpr); x != nil {
				// there must be exactly one CallExpr which is the P(val) conversion
				n++
				tpar, _ := tv.Type.(*TypeParam)
				if tpar == nil {
					t.Fatalf("%s: got type %s, want type parameter", ExprString(x), tv.Type)
				}
				if name := tpar.Obj().Name(); name != "P" {
					t.Fatalf("%s: got type parameter name %s, want P", ExprString(x), name)
				}
				// P(val) must not be constant
				if tv.Value != nil {
					t.Errorf("%s: got constant value %s (%s), want no constant", ExprString(x), tv.Value, tv.Value.String())
				}
			}
		}

		if n != 1 {
			t.Fatalf("%s: got %d CallExpr nodes; want 1", src, 1)
		}
	}
}

func TestIssue54258(t *testing.T) {
	tests := []struct{ main, b, want string }{
		{ //---------------------------------------------------------------
			`package main
import "b"
type I0 interface {
	M0(w struct{ f string })
}
var _ I0 = b.S{}
`,
			`package b
type S struct{}
func (S) M0(struct{ f string }) {}
`,
			`6:12: cannot use b[.]S{} [(]value of struct type b[.]S[)] as I0 value in variable declaration: b[.]S does not implement I0 [(]wrong type for method M0[)]
.*have M0[(]struct{f string /[*] package b [*]/ }[)]
.*want M0[(]struct{f string /[*] package main [*]/ }[)]`},

		{ //---------------------------------------------------------------
			`package main
import "b"
type I1 interface {
	M1(struct{ string })
}
var _ I1 = b.S{}
`,
			`package b
type S struct{}
func (S) M1(struct{ string }) {}
`,
			`6:12: cannot use b[.]S{} [(]value of struct type b[.]S[)] as I1 value in variable declaration: b[.]S does not implement I1 [(]wrong type for method M1[)]
.*have M1[(]struct{string /[*] package b [*]/ }[)]
.*want M1[(]struct{string /[*] package main [*]/ }[)]`},

		{ //---------------------------------------------------------------
			`package main
import "b"
type I2 interface {
	M2(y struct{ f struct{ f string } })
}
var _ I2 = b.S{}
`,
			`package b
type S struct{}
func (S) M2(struct{ f struct{ f string } }) {}
`,
			`6:12: cannot use b[.]S{} [(]value of struct type b[.]S[)] as I2 value in variable declaration: b[.]S does not implement I2 [(]wrong type for method M2[)]
.*have M2[(]struct{f struct{f string} /[*] package b [*]/ }[)]
.*want M2[(]struct{f struct{f string} /[*] package main [*]/ }[)]`},

		{ //---------------------------------------------------------------
			`package main
import "b"
type I3 interface {
	M3(z struct{ F struct{ f string } })
}
var _ I3 = b.S{}
`,
			`package b
type S struct{}
func (S) M3(struct{ F struct{ f string } }) {}
`,
			`6:12: cannot use b[.]S{} [(]value of struct type b[.]S[)] as I3 value in variable declaration: b[.]S does not implement I3 [(]wrong type for method M3[)]
.*have M3[(]struct{F struct{f string /[*] package b [*]/ }}[)]
.*want M3[(]struct{F struct{f string /[*] package main [*]/ }}[)]`},

		{ //---------------------------------------------------------------
			`package main
import "b"
type I4 interface {
	M4(_ struct { *string })
}
var _ I4 = b.S{}
`,
			`package b
type S struct{}
func (S) M4(struct { *string }) {}
`,
			`6:12: cannot use b[.]S{} [(]value of struct type b[.]S[)] as I4 value in variable declaration: b[.]S does not implement I4 [(]wrong type for method M4[)]
.*have M4[(]struct{[*]string /[*] package b [*]/ }[)]
.*want M4[(]struct{[*]string /[*] package main [*]/ }[)]`},

		{ //---------------------------------------------------------------
			`package main
import "b"
type t struct{ A int }
type I5 interface {
	M5(_ struct {b.S;t})
}
var _ I5 = b.S{}
`,
			`package b
type S struct{}
type t struct{ A int }
func (S) M5(struct {S;t}) {}
`,
			`7:12: cannot use b[.]S{} [(]value of struct type b[.]S[)] as I5 value in variable declaration: b[.]S does not implement I5 [(]wrong type for method M5[)]
.*have M5[(]struct{b[.]S; b[.]t}[)]
.*want M5[(]struct{b[.]S; t}[)]`},
	}

	test := func(main, b, want string) {
		re := regexp.MustCompile(want)
		bpkg := mustTypecheck(b, nil, nil)
		mast := mustParse(main)
		conf := Config{Importer: importHelper{pkg: bpkg}}
		_, err := conf.Check(mast.PkgName.Value, []*syntax.File{mast}, nil)
		if err == nil {
			t.Error("Expected failure, but it did not")
		} else if got := err.Error(); !re.MatchString(got) {
			t.Errorf("Wanted match for\n\t%s\n but got\n\t%s", want, got)
		} else if testing.Verbose() {
			t.Logf("Saw expected\n\t%s", err.Error())
		}
	}
	for _, t := range tests {
		test(t.main, t.b, t.want)
	}
}

func TestIssue59944(t *testing.T) {
	testenv.MustHaveCGO(t)

	// Methods declared on aliases of cgo types are not permitted.
	const src = `// -gotypesalias=1

package p

/*
struct layout {};
*/
import "C"

type Layout = C.struct_layout

func (*Layout /* ERROR "cannot define new methods on non-local type Layout" */) Binding() {}
`

	// code generated by cmd/cgo for the above source.
	const cgoTypes = `
// Code generated by cmd/cgo; DO NOT EDIT.

package p

import "unsafe"

import "syscall"

import _cgopackage "runtime/cgo"

type _ _cgopackage.Incomplete
var _ syscall.Errno
func _Cgo_ptr(ptr unsafe.Pointer) unsafe.Pointer { return ptr }

//go:linkname _Cgo_always_false runtime.cgoAlwaysFalse
var _Cgo_always_false bool
//go:linkname _Cgo_use runtime.cgoUse
func _Cgo_use(interface{})
//go:linkname _Cgo_keepalive runtime.cgoKeepAlive
//go:noescape
func _Cgo_keepalive(interface{})
//go:linkname _Cgo_no_callback runtime.cgoNoCallback
func _Cgo_no_callback(bool)
type _Ctype_struct_layout struct {
}

type _Ctype_void [0]byte

//go:linkname _cgo_runtime_cgocall runtime.cgocall
func _cgo_runtime_cgocall(unsafe.Pointer, uintptr) int32

//go:linkname _cgoCheckPointer runtime.cgoCheckPointer
//go:noescape
func _cgoCheckPointer(interface{}, interface{})

//go:linkname _cgoCheckResult runtime.cgoCheckResult
//go:noescape
func _cgoCheckResult(interface{})
`
	testFiles(t, []string{"p.go", "_cgo_gotypes.go"}, [][]byte{[]byte(src), []byte(cgoTypes)}, 0, false, func(cfg *Config) {
		*boolFieldAddr(cfg, "go115UsesCgo") = true
	})
}

func TestIssue61931(t *testing.T) {
	const src = `
package p

func A(func(any), ...any) {}
func B[T any](T)          {}

func _() {
	A(B, nil // syntax error: missing ',' before newline in argument list
}
`
	f, err := syntax.Parse(syntax.NewFileBase(pkgName(src)), strings.NewReader(src), func(error) {}, nil, 0)
	if err == nil {
		t.Fatal("expected syntax error")
	}

	var conf Config
	conf.Check(f.PkgName.Value, []*syntax.File{f}, nil) // must not panic
}

func TestIssue61938(t *testing.T) {
	const src = `
package p

func f[T any]() {}
func _()        { f() }
`
	// no error handler provided (this issue)
	var conf Config
	typecheck(src, &conf, nil) // must not panic

	// with error handler (sanity check)
	conf.Error = func(error) {}
	typecheck(src, &conf, nil) // must not panic
}

func TestIssue63260(t *testing.T) {
	const src = `
package p

func _() {
        use(f[*string])
}

func use(func()) {}

func f[I *T, T any]() {
        var v T
        _ = v
}`

	info := Info{
		Defs: make(map[*syntax.Name]Object),
	}
	pkg := mustTypecheck(src, nil, &info)

	// get type parameter T in signature of f
	T := pkg.Scope().Lookup("f").Type().(*Signature).TypeParams().At(1)
	if T.Obj().Name() != "T" {
		t.Fatalf("got type parameter %s, want T", T)
	}

	// get type of variable v in body of f
	var v Object
	for name, obj := range info.Defs {
		if name.Value == "v" {
			v = obj
			break
		}
	}
	if v == nil {
		t.Fatal("variable v not found")
	}

	// type of v and T must be pointer-identical
	if v.Type() != T {
		t.Fatalf("types of v and T are not pointer-identical: %p != %p", v.Type().(*TypeParam), T)
	}
}

func TestIssue44410(t *testing.T) {
	const src = `
package p

type A = []int
type S struct{ A }
`

	conf := Config{EnableAlias: true}
	pkg := mustTypecheck(src, &conf, nil)

	S := pkg.Scope().Lookup("S")
	if S == nil {
		t.Fatal("object S not found")
	}

	got := S.String()
	const want = "type p.S struct{p.A}"
	if got != want {
		t.Fatalf("got %q; want %q", got, want)
	}
}

func TestIssue59831(t *testing.T) {
	// Package a exports a type S with an unexported method m;
	// the tests check the error messages when m is not found.
	const asrc = `package a; type S struct{}; func (S) m() {}`
	apkg := mustTypecheck(asrc, nil, nil)

	// Package b exports a type S with an exported method m;
	// the tests check the error messages when M is not found.
	const bsrc = `package b; type S struct{}; func (S) M() {}`
	bpkg := mustTypecheck(bsrc, nil, nil)

	tests := []struct {
		imported *Package
		src, err string
	}{
		// tests importing a (or nothing)
		{apkg, `package a1; import "a"; var _ interface { M() } = a.S{}`,
			"a.S does not implement interface{M()} (missing method M) have m() want M()"},

		{apkg, `package a2; import "a"; var _ interface { m() } = a.S{}`,
			"a.S does not implement interface{m()} (unexported method m)"}, // test for issue

		{nil, `package a3; type S struct{}; func (S) m(); var _ interface { M() } = S{}`,
			"S does not implement interface{M()} (missing method M) have m() want M()"},

		{nil, `package a4; type S struct{}; func (S) m(); var _ interface { m() } = S{}`,
			""}, // no error expected

		{nil, `package a5; type S struct{}; func (S) m(); var _ interface { n() } = S{}`,
			"S does not implement interface{n()} (missing method n)"},

		// tests importing b (or nothing)
		{bpkg, `package b1; import "b"; var _ interface { m() } = b.S{}`,
			"b.S does not implement interface{m()} (missing method m) have M() want m()"},

		{bpkg, `package b2; import "b"; var _ interface { M() } = b.S{}`,
			""}, // no error expected

		{nil, `package b3; type S struct{}; func (S) M(); var _ interface { M() } = S{}`,
			""}, // no error expected

		{nil, `package b4; type S struct{}; func (S) M(); var _ interface { m() } = S{}`,
			"S does not implement interface{m()} (missing method m) have M() want m()"},

		{nil, `package b5; type S struct{}; func (S) M(); var _ interface { n() } = S{}`,
			"S does not implement interface{n()} (missing method n)"},
	}

	for _, test := range tests {
		// typecheck test source
		conf := Config{Importer: importHelper{pkg: test.imported}}
		pkg, err := typecheck(test.src, &conf, nil)
		if err == nil {
			if test.err != "" {
				t.Errorf("package %s: got no error, want %q", pkg.Name(), test.err)
			}
			continue
		}
		if test.err == "" {
			t.Errorf("package %s: got %q, want not error", pkg.Name(), err.Error())
		}

		// flatten reported error message
		errmsg := strings.ReplaceAll(err.Error(), "\n", " ")
		errmsg = strings.ReplaceAll(errmsg, "\t", "")

		// verify error message
		if !strings.Contains(errmsg, test.err) {
			t.Errorf("package %s: got %q, want %q", pkg.Name(), errmsg, test.err)
		}
	}
}

func TestIssue64759(t *testing.T) {
	const src = `
//go:build go1.18
package p

func f[S ~[]E, E any](S) {}

func _() {
	f([]string{})
}
`
	// Per the go:build directive, the source must typecheck
	// even though the (module) Go version is set to go1.17.
	conf := Config{GoVersion: "go1.17"}
	mustTypecheck(src, &conf, nil)
}

func TestIssue68334(t *testing.T) {
	const src = `
package p

func f(x int) {
	for i, j := range x {
		_, _ = i, j
	}
	var a, b int
	for a, b = range x {
		_, _ = a, b
	}
}
`

	got := ""
	conf := Config{
		GoVersion: "go1.21",                                      // #68334 requires GoVersion <= 1.21
		Error:     func(err error) { got += err.Error() + "\n" }, // #68334 requires Error != nil
	}
	typecheck(src, &conf, nil) // do not crash

	want := "p:5:20: cannot range over x (variable of type int): requires go1.22 or later\n" +
		"p:9:19: cannot range over x (variable of type int): requires go1.22 or later\n"
	if got != want {
		t.Errorf("got: %s want: %s", got, want)
	}
}

func TestIssue68877(t *testing.T) {
	const src = `
package p

type (
	S struct{}
	A = S
	T A
)`

	conf := Config{EnableAlias: true}
	pkg := mustTypecheck(src, &conf, nil)
	T := pkg.Scope().Lookup("T").(*TypeName)
	got := T.String() // this must not panic (was issue)
	const want = "type p.T struct{}"
	if got != want {
		t.Errorf("got %s, want %s", got, want)
	}
}

func TestIssue69092(t *testing.T) {
	const src = `
package p

var _ = T{{x}}
`

	file := mustParse(src)
	conf := Config{Error: func(err error) {}} // ignore errors
	info := Info{Types: make(map[syntax.Expr]TypeAndValue)}
	conf.Check("p", []*syntax.File{file}, &info)

	// look for {x} expression
	outer := file.DeclList[0].(*syntax.VarDecl).Values.(*syntax.CompositeLit) // T{{x}}
	inner := outer.ElemList[0]                                                // {x}

	// type of {x} must have been recorded
	tv, ok := info.Types[inner]
	if !ok {
		t.Fatal("no type found for {x}")
	}
	if tv.Type != Typ[Invalid] {
		t.Fatalf("unexpected type for {x}: %s", tv.Type)
	}
}

"""



```