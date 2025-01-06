Response: Let's break down the thought process for analyzing the provided Go code snippet.

**1. Initial Understanding: The Goal**

The first thing to do is read the code and comments to grasp the overall purpose. The package name `reflectdata` and the function names like `genhash`, `geneq`, `AlgType` immediately suggest this code deals with runtime reflection and how Go compares and hashes data. The comments confirm this.

**2. Deconstructing Function by Function**

The most effective way to understand the code is to analyze each function individually.

*   **`AlgType(t *types.Type) types.AlgKind`:**  The comment clearly states its purpose: to return more specific `AMEMxx` variants when possible. This hints at optimization based on the size and alignment of memory. The `switch` statement based on `t.Size()` reinforces this.

*   **`genhash(t *types.Type) *obj.LSym`:** The comment is crucial: "the generated function must match runtime.typehash exactly." This tells us this function generates code (or finds existing code) that calculates the hash of a value. The `switch` statement based on `AlgType(t)` is the core logic, handling different types and sizes. The `types.AMEM` case is interesting, as it seems to handle variable-length memory.

*   **`hashFunc(t *types.Type) *ir.Func`:** This function seems to generate the *actual* Go code for hashing arrays and structs. The logic within the `switch t.Kind()` block confirms this, iterating through array elements and struct fields.

*   **`runtimeHashFor(name string, t *types.Type) *ir.Name`:** A simple helper to look up runtime hash functions.

*   **`hashfor(t *types.Type) *ir.Name`:**  Similar to `genhash`, but returns an `ir.Name` (likely a reference to a function) instead of a symbol. It also handles fewer cases, suggesting it might be a higher-level abstraction.

*   **`sysClosure(name string) *obj.LSym`:** Creates a "closure" (in the Go compiler sense, not the anonymous function sense) that calls a runtime function. This is a common pattern for wrapping runtime functionality.

*   **`geneq(t *types.Type) *obj.LSym`:** Analogous to `genhash`, but for equality comparison. The structure and logic closely mirror `genhash`.

*   **`eqFunc(t *types.Type) *ir.Func`:** Analogous to `hashFunc`, generating Go code for equality comparisons of arrays and structs. The detailed logic within the `switch t.Kind()` block is more complex than `hashFunc`, handling various optimization strategies for arrays.

*   **`EqFor(t *types.Type) (ir.Node, bool)`:**  Similar to `hashfor`, but for equality, returning an `ir.Node` and a boolean indicating if a length parameter is needed.

*   **`anyCall(fn *ir.Func) bool`:** A simple helper to check if a function contains any function calls.

*   **`hashmem(t *types.Type) ir.Node`:**  A helper to look up the generic `memhash` runtime function.

**3. Identifying Core Functionality**

After understanding the individual functions, we can identify the key functionalities:

*   **Determining the Algorithm (`AlgType`):** This is the starting point for both hashing and equality.
*   **Generating Hash Functions (`genhash`, `hashFunc`):**  Creating or finding the code to compute hashes.
*   **Generating Equality Functions (`geneq`, `eqFunc`):** Creating or finding the code to compare for equality.
*   **Using Runtime Functions (`sysClosure`, `runtimeHashFor`, `hashfor`, `EqFor`, `hashmem`):** Leveraging existing, optimized functions in the Go runtime.

**4. Inferring Go Language Feature Implementation**

The code clearly implements the underlying mechanisms for:

*   **Hashing:** Used by maps and potentially other data structures that require efficient key lookup.
*   **Equality Comparison:** Used by the `==` operator, especially for composite types like arrays and structs.

**5. Providing Go Code Examples**

Based on the inferred functionality, it's relatively straightforward to provide examples of map usage (for hashing) and struct/array comparisons (for equality).

**6. Considering Command-Line Arguments**

The code references `base.Flag.LowerR`. This suggests the presence of compiler flags. Researching or recalling common Go compiler flags would lead to identifying `-N` and `-l` as relevant for inlining and optimization, which ties into the comments about `ir.Noinline`.

**7. Identifying Potential Pitfalls**

Focus on how the generated code or the underlying mechanisms could lead to errors. The main pitfall for users is assuming they can compare types that Go doesn't support for equality (like slices or functions directly with `==`). This aligns with the code's handling of `ANOEQ` and `ANOALG`. Another potential issue is relying on the specific hash values, as they are not guaranteed to be stable across Go versions.

**8. Iterative Refinement**

Throughout this process, there's an element of iteration. If something isn't clear, reread the code, the comments, or related documentation. For instance, the purpose of the closures might not be immediately obvious, requiring further thought or investigation. The connection between `AlgType` and the different hash/equality functions becomes clearer as you analyze more functions.

By following these steps, we can systematically analyze the given Go code snippet and arrive at a comprehensive understanding of its functionality and its role in the Go language.
这段 `alg.go` 文件是 Go 编译器 `cmd/compile` 的一部分，主要负责生成用于**反射**的**哈希**和**相等性比较**相关的代码和数据。

以下是它的主要功能：

**1. 确定类型的算法类型 (`AlgType` 函数):**

   - 该函数接收一个 `types.Type` 类型的参数，表示 Go 语言中的一个类型。
   - 它的主要目的是根据类型的大小和对齐方式，返回一个更具体的 `types.AlgKind` 值，特别是对于内存块 (`types.AMEM`) 类型。
   - 如果类型是 `types.AMEM` (表示一块原始内存)，它会尝试根据其大小返回更具体的 `AMEMxx` 变体 (如 `AMEM8`, `AMEM16`, `AMEM32` 等)。这样做可以为特定大小的内存块选择更优化的哈希和相等性比较函数。
   - 它会考虑类型的对齐要求，以避免将例如 `[2]int16` 视为 `int32`，如果 `int32` 需要更大的对齐。

**2. 生成哈希函数闭包 (`genhash` 函数):**

   - 该函数接收一个 `types.Type` 类型的参数。
   - 它的目标是生成一个符号 (`*obj.LSym`)，这个符号代表一个闭包，用于计算给定类型值的哈希值。
   - 它首先调用 `AlgType` 来获取类型的算法类型。
   - 对于基本类型（如 `int`, `string`, `float`, `complex` 等），它直接返回指向运行时相应哈希函数的闭包（例如，`strhash`，`f32hash`）。
   - 对于内存块类型 (`types.AMEM`)，它会创建一个新的闭包，该闭包调用运行时函数 `memhash_varlen`，并将内存块的大小编码到闭包的第一个槽位中。
   - 对于数组和结构体等复合类型，它会递归地为它们的元素类型或字段类型生成哈希函数。然后，它会生成一个新的哈希函数（通过调用 `hashFunc`），该函数会遍历数组元素或结构体字段，并调用相应的哈希函数。

**3. 生成实际的哈希函数代码 (`hashFunc` 函数):**

   - 该函数接收一个 `types.Type` 类型的参数。
   - 它负责生成实际的 Go 代码，用于计算数组和结构体的哈希值。
   - 对于数组，它会生成一个循环，遍历数组的每个元素，并调用元素类型的哈希函数，将结果累积起来。
   - 对于结构体，它会遍历结构体的每个字段。对于非内存类型的字段，它会调用字段类型的哈希函数。对于连续的内存块字段，它会调用 `memhash` 运行时函数来处理这些内存块。

**4. 获取运行时哈希函数 (`runtimeHashFor` 和 `hashfor` 函数):**

   - `runtimeHashFor` 是一个辅助函数，用于查找指定名称的运行时哈希函数。
   - `hashfor` 函数根据给定的类型，返回用于计算该类型哈希值的函数的 `ir.Name`（表示编译器内部的名称）。它会根据 `AlgType` 的结果选择合适的运行时哈希函数或调用 `hashFunc` 来生成自定义的哈希函数。

**5. 创建调用运行时函数的闭包 (`sysClosure` 函数):**

   - 该函数接收一个运行时函数的名字作为参数。
   - 它创建一个闭包，这个闭包会调用指定的运行时函数。这个闭包不捕获任何变量，只包含函数指针。

**6. 生成相等性比较函数闭包 (`geneq` 函数):**

   - 该函数接收一个 `types.Type` 类型的参数。
   - 它的目标是生成一个符号 (`*obj.LSym`)，这个符号代表一个闭包，用于比较给定类型的两个值是否相等。
   - 它的逻辑与 `genhash` 非常相似。
   - 对于基本类型，它直接返回指向运行时相应相等性比较函数的闭包（例如，`strequal`，`f32equal`）。
   - 对于内存块类型 (`types.AMEM`)，它会创建一个新的闭包，该闭包调用运行时函数 `memequal_varlen`，并将内存块的大小编码到闭包中。
   - 对于数组和结构体，它会生成一个新的相等性比较函数（通过调用 `eqFunc`），该函数会比较数组的每个元素或结构体的每个字段。

**7. 生成实际的相等性比较函数代码 (`eqFunc` 函数):**

   - 该函数接收一个 `types.Type` 类型的参数。
   - 它负责生成实际的 Go 代码，用于比较数组和结构体的相等性。
   - 对于数组，它会生成一个循环，遍历数组的每个元素，并比较对应的元素是否相等。它会进行一些优化，例如对于字符串类型的数组，会先比较长度，再比较内容；对于基本类型的数组，会进行循环展开以提高效率。
   - 对于结构体，它会比较结构体的每个字段。

**8. 获取相等性比较函数 (`EqFor` 函数):**

   - 该函数根据给定的类型，返回用于比较该类型值的相等性的函数 `ir.Node` 以及一个布尔值，指示调用该函数时是否需要传递长度参数（主要用于 `memequal`）。

**9. 检查函数是否包含函数调用 (`anyCall` 函数):**

   - 这是一个辅助函数，用于检查给定的函数体是否包含任何函数调用。

**10. 获取用于比较内存块的运行时函数 (`hashmem` 函数):**

    - 这是一个辅助函数，用于查找名为 "memhash" 的运行时函数。

**推理其实现的 Go 语言功能:**

这段代码是 Go 语言**反射 (reflection)** 机制的一部分实现。具体来说，它负责生成在运行时比较和哈希数据所需的底层函数。这些函数被 `reflect` 包以及其他需要进行类型判断和操作的 Go 语言特性使用，例如：

*   **`map` 数据结构:**  `map` 使用哈希函数来确定键的存储位置，并使用相等性比较函数来判断键是否已经存在。
*   **类型断言和类型 switch:** 这些操作需要在运行时比较类型是否一致。
*   **`reflect` 包的函数:**  例如 `reflect.DeepEqual` 就需要能够比较任意类型的值是否相等。

**Go 代码示例:**

```go
package main

import (
	"fmt"
	"reflect"
)

type MyStruct struct {
	A int
	B string
}

func main() {
	// 使用 map，内部会用到哈希和相等性比较
	m := make(map[MyStruct]int)
	s1 := MyStruct{A: 1, B: "hello"}
	s2 := MyStruct{A: 1, B: "hello"}
	m[s1] = 10
	fmt.Println(m[s2]) // 输出 10，因为 s1 和 s2 相等

	// 使用 reflect.DeepEqual 比较结构体
	fmt.Println(reflect.DeepEqual(s1, s2)) // 输出 true

	// 使用 reflect.DeepEqual 比较切片（注意：切片不能直接用 == 比较）
	slice1 := []int{1, 2, 3}
	slice2 := []int{1, 2, 3}
	fmt.Println(reflect.DeepEqual(slice1, slice2)) // 输出 true

	// 不同类型的比较
	var i int = 5
	var f float64 = 5.0
	fmt.Println(reflect.DeepEqual(i, int(f))) // 输出 true，DeepEqual 会尝试进行类型转换
}
```

**假设的输入与输出（针对 `genhash` 和 `geneq`）:**

**假设输入 (对于 `genhash`):**

```go
package main

type MyStruct struct {
	A int
	B string
}

func main() {
	var s MyStruct
	// 在编译时，编译器会调用 reflectdata.genhash 来为 MyStruct 生成哈希函数
}
```

**假设输出 (编译器生成的伪代码，展示 `genhash` 可能生成的内容):**

```go
// 为 MyStruct 生成的哈希函数闭包（伪代码）
var hashfunc_MyStruct struct {
	ptr uintptr // 指向实际的哈希函数
}

// 实际的哈希函数（伪代码）
func hash_MyStruct(p *MyStruct, h uintptr) uintptr {
	h = hash_int(&p.A, h)
	h = hash_string(&p.B, h)
	return h
}

// 在初始化时，将 hash_MyStruct 的地址赋值给 hashfunc_MyStruct.ptr
```

**假设输入 (对于 `geneq`):**

```go
package main

type MyStruct struct {
	A int
	B string
}

func main() {
	var s1, s2 MyStruct
	// 在编译时，编译器会调用 reflectdata.geneq 来为 MyStruct 生成相等性比较函数
	_ = s1 == s2 // 触发相等性比较
}
```

**假设输出 (编译器生成的伪代码，展示 `geneq` 可能生成的内容):**

```go
// 为 MyStruct 生成的相等性比较函数闭包（伪代码）
var eqfunc_MyStruct struct {
	ptr uintptr // 指向实际的相等性比较函数
}

// 实际的相等性比较函数（伪代码）
func eq_MyStruct(p *MyStruct, q *MyStruct) bool {
	if p.A != q.A {
		return false
	}
	if p.B != q.B {
		return false
	}
	return true
}

// 在初始化时，将 eq_MyStruct 的地址赋值给 eqfunc_MyStruct.ptr
```

**涉及的命令行参数:**

该代码片段本身不直接处理命令行参数。但是，它属于 Go 编译器的内部实现。Go 编译器的行为会受到一些命令行参数的影响，例如：

*   **`-N`:**  禁用优化。这可能会影响编译器是否内联某些生成的哈希或相等性比较函数。
*   **`-l`:**  禁用内联。这会阻止编译器内联生成的哈希和相等性比较函数，使得这些函数调用更加明确。
*   **`-gcflags`:**  允许传递更底层的 `gc` (garbage collector) 相关的标志，可能会间接影响代码生成。
*   **`- race`:** 启用竞态检测。这可能会影响某些内存操作的实现方式。

代码中出现的 `base.Flag.LowerR != 0` 似乎是一个内部的调试标志，可能用于在编译过程中打印生成哈希和相等性比较函数的相关信息。

**使用者易犯错的点:**

虽然使用者不直接与 `alg.go` 文件交互，但理解其背后的原理有助于避免一些常见的错误：

1. **假设自定义类型的相等性比较是按位比较:**  Go 的相等性比较规则由编译器根据类型结构生成。对于结构体，会逐字段比较；对于数组，会逐元素比较。直接比较包含指针、函数或其他不可直接比较类型的结构体可能会导致编译错误或运行时 panic。

    ```go
    package main

    type ContainsFunc struct {
        F func()
    }

    func main() {
        f1 := ContainsFunc{F: func() {}}
        f2 := ContainsFunc{F: func() {}}
        // 编译错误：invalid operation: f1 == f2 (func can only be compared to nil)
        // fmt.Println(f1 == f2)
        _ = f1.F == f2.F // 函数只能与 nil 比较
    }
    ```

2. **依赖哈希值的稳定性:**  Go 的哈希函数实现可能会在不同的 Go 版本或不同的架构上有所不同。因此，不应依赖哈希值的具体数值，而只应依赖于相等的值具有相同的哈希值这一性质。

3. **误解 `reflect.DeepEqual` 的行为:** `reflect.DeepEqual` 可以比较更复杂的类型（如切片、map），但其比较规则可能与简单的 `==` 操作符不同。例如，它会递归比较切片的元素。

    ```go
    package main

    import "reflect"
    import "fmt"

    func main() {
        s1 := []int{1, 2, 3}
        s2 := []int{1, 2, 3}
        fmt.Println(s1 == s2) // 编译错误：invalid operation: s1 == s2 (slice can only be compared to nil)
        fmt.Println(reflect.DeepEqual(s1, s2)) // 输出 true
    }
    ```

总而言之，`alg.go` 文件是 Go 编译器中一个关键的组成部分，它为反射机制提供了必要的哈希和相等性比较功能，使得 Go 语言能够在运行时对类型进行检查和操作。理解其功能有助于更深入地理解 Go 语言的内部机制。

Prompt: 
```
这是路径为go/src/cmd/compile/internal/reflectdata/alg.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，

"""
// Copyright 2016 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package reflectdata

import (
	"fmt"

	"cmd/compile/internal/base"
	"cmd/compile/internal/compare"
	"cmd/compile/internal/ir"
	"cmd/compile/internal/objw"
	"cmd/compile/internal/typecheck"
	"cmd/compile/internal/types"
	"cmd/internal/obj"
	"cmd/internal/src"
)

// AlgType returns the fixed-width AMEMxx variants instead of the general
// AMEM kind when possible.
func AlgType(t *types.Type) types.AlgKind {
	a := types.AlgType(t)
	if a == types.AMEM {
		if t.Alignment() < int64(base.Ctxt.Arch.Alignment) && t.Alignment() < t.Size() {
			// For example, we can't treat [2]int16 as an int32 if int32s require
			// 4-byte alignment. See issue 46283.
			return a
		}
		switch t.Size() {
		case 0:
			return types.AMEM0
		case 1:
			return types.AMEM8
		case 2:
			return types.AMEM16
		case 4:
			return types.AMEM32
		case 8:
			return types.AMEM64
		case 16:
			return types.AMEM128
		}
	}

	return a
}

// genhash returns a symbol which is the closure used to compute
// the hash of a value of type t.
// Note: the generated function must match runtime.typehash exactly.
func genhash(t *types.Type) *obj.LSym {
	switch AlgType(t) {
	default:
		// genhash is only called for types that have equality
		base.Fatalf("genhash %v", t)
	case types.AMEM0:
		return sysClosure("memhash0")
	case types.AMEM8:
		return sysClosure("memhash8")
	case types.AMEM16:
		return sysClosure("memhash16")
	case types.AMEM32:
		return sysClosure("memhash32")
	case types.AMEM64:
		return sysClosure("memhash64")
	case types.AMEM128:
		return sysClosure("memhash128")
	case types.ASTRING:
		return sysClosure("strhash")
	case types.AINTER:
		return sysClosure("interhash")
	case types.ANILINTER:
		return sysClosure("nilinterhash")
	case types.AFLOAT32:
		return sysClosure("f32hash")
	case types.AFLOAT64:
		return sysClosure("f64hash")
	case types.ACPLX64:
		return sysClosure("c64hash")
	case types.ACPLX128:
		return sysClosure("c128hash")
	case types.AMEM:
		// For other sizes of plain memory, we build a closure
		// that calls memhash_varlen. The size of the memory is
		// encoded in the first slot of the closure.
		closure := TypeLinksymLookup(fmt.Sprintf(".hashfunc%d", t.Size()))
		if len(closure.P) > 0 { // already generated
			return closure
		}
		if memhashvarlen == nil {
			memhashvarlen = typecheck.LookupRuntimeFunc("memhash_varlen")
		}
		ot := 0
		ot = objw.SymPtr(closure, ot, memhashvarlen, 0)
		ot = objw.Uintptr(closure, ot, uint64(t.Size())) // size encoded in closure
		objw.Global(closure, int32(ot), obj.DUPOK|obj.RODATA)
		return closure
	case types.ASPECIAL:
		break
	}

	closure := TypeLinksymPrefix(".hashfunc", t)
	if len(closure.P) > 0 { // already generated
		return closure
	}

	// Generate hash functions for subtypes.
	// There are cases where we might not use these hashes,
	// but in that case they will get dead-code eliminated.
	// (And the closure generated by genhash will also get
	// dead-code eliminated, as we call the subtype hashers
	// directly.)
	switch t.Kind() {
	case types.TARRAY:
		genhash(t.Elem())
	case types.TSTRUCT:
		for _, f := range t.Fields() {
			genhash(f.Type)
		}
	}

	if base.Flag.LowerR != 0 {
		fmt.Printf("genhash %v %v\n", closure, t)
	}

	fn := hashFunc(t)

	// Build closure. It doesn't close over any variables, so
	// it contains just the function pointer.
	objw.SymPtr(closure, 0, fn.Linksym(), 0)
	objw.Global(closure, int32(types.PtrSize), obj.DUPOK|obj.RODATA)

	return closure
}

func hashFunc(t *types.Type) *ir.Func {
	sym := TypeSymPrefix(".hash", t)
	if sym.Def != nil {
		return sym.Def.(*ir.Name).Func
	}

	pos := base.AutogeneratedPos // less confusing than end of input
	base.Pos = pos

	// func sym(p *T, h uintptr) uintptr
	fn := ir.NewFunc(pos, pos, sym, types.NewSignature(nil,
		[]*types.Field{
			types.NewField(pos, typecheck.Lookup("p"), types.NewPtr(t)),
			types.NewField(pos, typecheck.Lookup("h"), types.Types[types.TUINTPTR]),
		},
		[]*types.Field{
			types.NewField(pos, nil, types.Types[types.TUINTPTR]),
		},
	))
	sym.Def = fn.Nname
	fn.Pragma |= ir.Noinline // TODO(mdempsky): We need to emit this during the unified frontend instead, to allow inlining.

	typecheck.DeclFunc(fn)
	np := fn.Dcl[0]
	nh := fn.Dcl[1]

	switch t.Kind() {
	case types.TARRAY:
		// An array of pure memory would be handled by the
		// standard algorithm, so the element type must not be
		// pure memory.
		hashel := hashfor(t.Elem())

		// for i := 0; i < nelem; i++
		ni := typecheck.TempAt(base.Pos, ir.CurFunc, types.Types[types.TINT])
		init := ir.NewAssignStmt(base.Pos, ni, ir.NewInt(base.Pos, 0))
		cond := ir.NewBinaryExpr(base.Pos, ir.OLT, ni, ir.NewInt(base.Pos, t.NumElem()))
		post := ir.NewAssignStmt(base.Pos, ni, ir.NewBinaryExpr(base.Pos, ir.OADD, ni, ir.NewInt(base.Pos, 1)))
		loop := ir.NewForStmt(base.Pos, nil, cond, post, nil, false)
		loop.PtrInit().Append(init)

		// h = hashel(&p[i], h)
		call := ir.NewCallExpr(base.Pos, ir.OCALL, hashel, nil)

		nx := ir.NewIndexExpr(base.Pos, np, ni)
		nx.SetBounded(true)
		na := typecheck.NodAddr(nx)
		call.Args.Append(na)
		call.Args.Append(nh)
		loop.Body.Append(ir.NewAssignStmt(base.Pos, nh, call))

		fn.Body.Append(loop)

	case types.TSTRUCT:
		// Walk the struct using memhash for runs of AMEM
		// and calling specific hash functions for the others.
		for i, fields := 0, t.Fields(); i < len(fields); {
			f := fields[i]

			// Skip blank fields.
			if f.Sym.IsBlank() {
				i++
				continue
			}

			// Hash non-memory fields with appropriate hash function.
			if !compare.IsRegularMemory(f.Type) {
				hashel := hashfor(f.Type)
				call := ir.NewCallExpr(base.Pos, ir.OCALL, hashel, nil)
				na := typecheck.NodAddr(typecheck.DotField(base.Pos, np, i))
				call.Args.Append(na)
				call.Args.Append(nh)
				fn.Body.Append(ir.NewAssignStmt(base.Pos, nh, call))
				i++
				continue
			}

			// Otherwise, hash a maximal length run of raw memory.
			size, next := compare.Memrun(t, i)

			// h = hashel(&p.first, size, h)
			hashel := hashmem(f.Type)
			call := ir.NewCallExpr(base.Pos, ir.OCALL, hashel, nil)
			na := typecheck.NodAddr(typecheck.DotField(base.Pos, np, i))
			call.Args.Append(na)
			call.Args.Append(nh)
			call.Args.Append(ir.NewInt(base.Pos, size))
			fn.Body.Append(ir.NewAssignStmt(base.Pos, nh, call))

			i = next
		}
	}

	r := ir.NewReturnStmt(base.Pos, nil)
	r.Results.Append(nh)
	fn.Body.Append(r)

	if base.Flag.LowerR != 0 {
		ir.DumpList("genhash body", fn.Body)
	}

	typecheck.FinishFuncBody()

	fn.SetDupok(true)

	ir.WithFunc(fn, func() {
		typecheck.Stmts(fn.Body)
	})

	fn.SetNilCheckDisabled(true)

	return fn
}

func runtimeHashFor(name string, t *types.Type) *ir.Name {
	return typecheck.LookupRuntime(name, t)
}

// hashfor returns the function to compute the hash of a value of type t.
func hashfor(t *types.Type) *ir.Name {
	switch types.AlgType(t) {
	case types.AMEM:
		base.Fatalf("hashfor with AMEM type")
	case types.AINTER:
		return runtimeHashFor("interhash", t)
	case types.ANILINTER:
		return runtimeHashFor("nilinterhash", t)
	case types.ASTRING:
		return runtimeHashFor("strhash", t)
	case types.AFLOAT32:
		return runtimeHashFor("f32hash", t)
	case types.AFLOAT64:
		return runtimeHashFor("f64hash", t)
	case types.ACPLX64:
		return runtimeHashFor("c64hash", t)
	case types.ACPLX128:
		return runtimeHashFor("c128hash", t)
	}

	fn := hashFunc(t)
	return fn.Nname
}

// sysClosure returns a closure which will call the
// given runtime function (with no closed-over variables).
func sysClosure(name string) *obj.LSym {
	s := typecheck.LookupRuntimeVar(name + "·f")
	if len(s.P) == 0 {
		f := typecheck.LookupRuntimeFunc(name)
		objw.SymPtr(s, 0, f, 0)
		objw.Global(s, int32(types.PtrSize), obj.DUPOK|obj.RODATA)
	}
	return s
}

// geneq returns a symbol which is the closure used to compute
// equality for two objects of type t.
func geneq(t *types.Type) *obj.LSym {
	switch AlgType(t) {
	case types.ANOEQ, types.ANOALG:
		// The runtime will panic if it tries to compare
		// a type with a nil equality function.
		return nil
	case types.AMEM0:
		return sysClosure("memequal0")
	case types.AMEM8:
		return sysClosure("memequal8")
	case types.AMEM16:
		return sysClosure("memequal16")
	case types.AMEM32:
		return sysClosure("memequal32")
	case types.AMEM64:
		return sysClosure("memequal64")
	case types.AMEM128:
		return sysClosure("memequal128")
	case types.ASTRING:
		return sysClosure("strequal")
	case types.AINTER:
		return sysClosure("interequal")
	case types.ANILINTER:
		return sysClosure("nilinterequal")
	case types.AFLOAT32:
		return sysClosure("f32equal")
	case types.AFLOAT64:
		return sysClosure("f64equal")
	case types.ACPLX64:
		return sysClosure("c64equal")
	case types.ACPLX128:
		return sysClosure("c128equal")
	case types.AMEM:
		// make equality closure. The size of the type
		// is encoded in the closure.
		closure := TypeLinksymLookup(fmt.Sprintf(".eqfunc%d", t.Size()))
		if len(closure.P) != 0 {
			return closure
		}
		if memequalvarlen == nil {
			memequalvarlen = typecheck.LookupRuntimeFunc("memequal_varlen")
		}
		ot := 0
		ot = objw.SymPtr(closure, ot, memequalvarlen, 0)
		ot = objw.Uintptr(closure, ot, uint64(t.Size()))
		objw.Global(closure, int32(ot), obj.DUPOK|obj.RODATA)
		return closure
	case types.ASPECIAL:
		break
	}

	closure := TypeLinksymPrefix(".eqfunc", t)
	if len(closure.P) > 0 { // already generated
		return closure
	}

	if base.Flag.LowerR != 0 {
		fmt.Printf("geneq %v\n", t)
	}

	fn := eqFunc(t)

	// Generate a closure which points at the function we just generated.
	objw.SymPtr(closure, 0, fn.Linksym(), 0)
	objw.Global(closure, int32(types.PtrSize), obj.DUPOK|obj.RODATA)
	return closure
}

func eqFunc(t *types.Type) *ir.Func {
	// Autogenerate code for equality of structs and arrays.
	sym := TypeSymPrefix(".eq", t)
	if sym.Def != nil {
		return sym.Def.(*ir.Name).Func
	}

	pos := base.AutogeneratedPos // less confusing than end of input
	base.Pos = pos

	// func sym(p, q *T) bool
	fn := ir.NewFunc(pos, pos, sym, types.NewSignature(nil,
		[]*types.Field{
			types.NewField(pos, typecheck.Lookup("p"), types.NewPtr(t)),
			types.NewField(pos, typecheck.Lookup("q"), types.NewPtr(t)),
		},
		[]*types.Field{
			types.NewField(pos, typecheck.Lookup("r"), types.Types[types.TBOOL]),
		},
	))
	sym.Def = fn.Nname
	fn.Pragma |= ir.Noinline // TODO(mdempsky): We need to emit this during the unified frontend instead, to allow inlining.

	typecheck.DeclFunc(fn)
	np := fn.Dcl[0]
	nq := fn.Dcl[1]
	nr := fn.Dcl[2]

	// Label to jump to if an equality test fails.
	neq := typecheck.AutoLabel(".neq")

	// We reach here only for types that have equality but
	// cannot be handled by the standard algorithms,
	// so t must be either an array or a struct.
	switch t.Kind() {
	default:
		base.Fatalf("geneq %v", t)

	case types.TARRAY:
		nelem := t.NumElem()

		// checkAll generates code to check the equality of all array elements.
		// If unroll is greater than nelem, checkAll generates:
		//
		// if eq(p[0], q[0]) && eq(p[1], q[1]) && ... {
		// } else {
		//   goto neq
		// }
		//
		// And so on.
		//
		// Otherwise it generates:
		//
		// iterateTo := nelem/unroll*unroll
		// for i := 0; i < iterateTo; i += unroll {
		//   if eq(p[i+0], q[i+0]) && eq(p[i+1], q[i+1]) && ... && eq(p[i+unroll-1], q[i+unroll-1]) {
		//   } else {
		//     goto neq
		//   }
		// }
		// if eq(p[iterateTo+0], q[iterateTo+0]) && eq(p[iterateTo+1], q[iterateTo+1]) && ... {
		// } else {
		//    goto neq
		// }
		//
		checkAll := func(unroll int64, last bool, eq func(pi, qi ir.Node) ir.Node) {
			// checkIdx generates a node to check for equality at index i.
			checkIdx := func(i ir.Node) ir.Node {
				// pi := p[i]
				pi := ir.NewIndexExpr(base.Pos, np, i)
				pi.SetBounded(true)
				pi.SetType(t.Elem())
				// qi := q[i]
				qi := ir.NewIndexExpr(base.Pos, nq, i)
				qi.SetBounded(true)
				qi.SetType(t.Elem())
				return eq(pi, qi)
			}

			iterations := nelem / unroll
			iterateTo := iterations * unroll
			// If a loop is iterated only once, there shouldn't be any loop at all.
			if iterations == 1 {
				iterateTo = 0
			}

			if iterateTo > 0 {
				// Generate an unrolled for loop.
				// for i := 0; i < nelem/unroll*unroll; i += unroll
				i := typecheck.TempAt(base.Pos, ir.CurFunc, types.Types[types.TINT])
				init := ir.NewAssignStmt(base.Pos, i, ir.NewInt(base.Pos, 0))
				cond := ir.NewBinaryExpr(base.Pos, ir.OLT, i, ir.NewInt(base.Pos, iterateTo))
				loop := ir.NewForStmt(base.Pos, nil, cond, nil, nil, false)
				loop.PtrInit().Append(init)

				// if eq(p[i+0], q[i+0]) && eq(p[i+1], q[i+1]) && ... && eq(p[i+unroll-1], q[i+unroll-1]) {
				// } else {
				//   goto neq
				// }
				for j := int64(0); j < unroll; j++ {
					// if check {} else { goto neq }
					nif := ir.NewIfStmt(base.Pos, checkIdx(i), nil, nil)
					nif.Else.Append(ir.NewBranchStmt(base.Pos, ir.OGOTO, neq))
					loop.Body.Append(nif)
					post := ir.NewAssignStmt(base.Pos, i, ir.NewBinaryExpr(base.Pos, ir.OADD, i, ir.NewInt(base.Pos, 1)))
					loop.Body.Append(post)
				}

				fn.Body.Append(loop)

				if nelem == iterateTo {
					if last {
						fn.Body.Append(ir.NewAssignStmt(base.Pos, nr, ir.NewBool(base.Pos, true)))
					}
					return
				}
			}

			// Generate remaining checks, if nelem is not a multiple of unroll.
			if last {
				// Do last comparison in a different manner.
				nelem--
			}
			// if eq(p[iterateTo+0], q[iterateTo+0]) && eq(p[iterateTo+1], q[iterateTo+1]) && ... {
			// } else {
			//    goto neq
			// }
			for j := iterateTo; j < nelem; j++ {
				// if check {} else { goto neq }
				nif := ir.NewIfStmt(base.Pos, checkIdx(ir.NewInt(base.Pos, j)), nil, nil)
				nif.Else.Append(ir.NewBranchStmt(base.Pos, ir.OGOTO, neq))
				fn.Body.Append(nif)
			}
			if last {
				fn.Body.Append(ir.NewAssignStmt(base.Pos, nr, checkIdx(ir.NewInt(base.Pos, nelem))))
			}
		}

		switch t.Elem().Kind() {
		case types.TSTRING:
			// Do two loops. First, check that all the lengths match (cheap).
			// Second, check that all the contents match (expensive).
			checkAll(3, false, func(pi, qi ir.Node) ir.Node {
				// Compare lengths.
				eqlen, _ := compare.EqString(pi, qi)
				return eqlen
			})
			checkAll(1, true, func(pi, qi ir.Node) ir.Node {
				// Compare contents.
				_, eqmem := compare.EqString(pi, qi)
				return eqmem
			})
		case types.TFLOAT32, types.TFLOAT64:
			checkAll(2, true, func(pi, qi ir.Node) ir.Node {
				// p[i] == q[i]
				return ir.NewBinaryExpr(base.Pos, ir.OEQ, pi, qi)
			})
		case types.TSTRUCT:
			isCall := func(n ir.Node) bool {
				return n.Op() == ir.OCALL || n.Op() == ir.OCALLFUNC
			}
			var expr ir.Node
			var hasCallExprs bool
			allCallExprs := true
			and := func(cond ir.Node) {
				if expr == nil {
					expr = cond
				} else {
					expr = ir.NewLogicalExpr(base.Pos, ir.OANDAND, expr, cond)
				}
			}

			var tmpPos src.XPos
			pi := ir.NewIndexExpr(tmpPos, np, ir.NewInt(tmpPos, 0))
			pi.SetBounded(true)
			pi.SetType(t.Elem())
			qi := ir.NewIndexExpr(tmpPos, nq, ir.NewInt(tmpPos, 0))
			qi.SetBounded(true)
			qi.SetType(t.Elem())
			flatConds, canPanic := compare.EqStruct(t.Elem(), pi, qi)
			for _, c := range flatConds {
				if isCall(c) {
					hasCallExprs = true
				} else {
					allCallExprs = false
				}
			}
			if !hasCallExprs || allCallExprs || canPanic {
				checkAll(1, true, func(pi, qi ir.Node) ir.Node {
					// p[i] == q[i]
					return ir.NewBinaryExpr(base.Pos, ir.OEQ, pi, qi)
				})
			} else {
				checkAll(4, false, func(pi, qi ir.Node) ir.Node {
					expr = nil
					flatConds, _ := compare.EqStruct(t.Elem(), pi, qi)
					if len(flatConds) == 0 {
						return ir.NewBool(base.Pos, true)
					}
					for _, c := range flatConds {
						if !isCall(c) {
							and(c)
						}
					}
					return expr
				})
				checkAll(2, true, func(pi, qi ir.Node) ir.Node {
					expr = nil
					flatConds, _ := compare.EqStruct(t.Elem(), pi, qi)
					for _, c := range flatConds {
						if isCall(c) {
							and(c)
						}
					}
					return expr
				})
			}
		default:
			checkAll(1, true, func(pi, qi ir.Node) ir.Node {
				// p[i] == q[i]
				return ir.NewBinaryExpr(base.Pos, ir.OEQ, pi, qi)
			})
		}

	case types.TSTRUCT:
		flatConds, _ := compare.EqStruct(t, np, nq)
		if len(flatConds) == 0 {
			fn.Body.Append(ir.NewAssignStmt(base.Pos, nr, ir.NewBool(base.Pos, true)))
		} else {
			for _, c := range flatConds[:len(flatConds)-1] {
				// if cond {} else { goto neq }
				n := ir.NewIfStmt(base.Pos, c, nil, nil)
				n.Else.Append(ir.NewBranchStmt(base.Pos, ir.OGOTO, neq))
				fn.Body.Append(n)
			}
			fn.Body.Append(ir.NewAssignStmt(base.Pos, nr, flatConds[len(flatConds)-1]))
		}
	}

	// ret:
	//   return
	ret := typecheck.AutoLabel(".ret")
	fn.Body.Append(ir.NewLabelStmt(base.Pos, ret))
	fn.Body.Append(ir.NewReturnStmt(base.Pos, nil))

	// neq:
	//   r = false
	//   return (or goto ret)
	fn.Body.Append(ir.NewLabelStmt(base.Pos, neq))
	fn.Body.Append(ir.NewAssignStmt(base.Pos, nr, ir.NewBool(base.Pos, false)))
	if compare.EqCanPanic(t) || anyCall(fn) {
		// Epilogue is large, so share it with the equal case.
		fn.Body.Append(ir.NewBranchStmt(base.Pos, ir.OGOTO, ret))
	} else {
		// Epilogue is small, so don't bother sharing.
		fn.Body.Append(ir.NewReturnStmt(base.Pos, nil))
	}
	// TODO(khr): the epilogue size detection condition above isn't perfect.
	// We should really do a generic CL that shares epilogues across
	// the board. See #24936.

	if base.Flag.LowerR != 0 {
		ir.DumpList("geneq body", fn.Body)
	}

	typecheck.FinishFuncBody()

	fn.SetDupok(true)

	ir.WithFunc(fn, func() {
		typecheck.Stmts(fn.Body)
	})

	// Disable checknils while compiling this code.
	// We are comparing a struct or an array,
	// neither of which can be nil, and our comparisons
	// are shallow.
	fn.SetNilCheckDisabled(true)
	return fn
}

// EqFor returns ONAME node represents type t's equal function, and a boolean
// to indicates whether a length needs to be passed when calling the function.
func EqFor(t *types.Type) (ir.Node, bool) {
	switch types.AlgType(t) {
	case types.AMEM:
		return typecheck.LookupRuntime("memequal", t, t), true
	case types.ASPECIAL:
		fn := eqFunc(t)
		return fn.Nname, false
	}
	base.Fatalf("EqFor %v", t)
	return nil, false
}

func anyCall(fn *ir.Func) bool {
	return ir.Any(fn, func(n ir.Node) bool {
		// TODO(rsc): No methods?
		op := n.Op()
		return op == ir.OCALL || op == ir.OCALLFUNC
	})
}

func hashmem(t *types.Type) ir.Node {
	return typecheck.LookupRuntime("memhash", t)
}

"""



```