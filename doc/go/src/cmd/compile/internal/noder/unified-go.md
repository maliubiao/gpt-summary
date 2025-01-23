Response: Let's break down the thought process for analyzing this Go code snippet.

**1. Initial Understanding of the Request:**

The request asks for the functionality of the provided Go code, its purpose within the Go compilation process, examples of its use, command-line parameter handling (if any), and common mistakes. The code resides in `go/src/cmd/compile/internal/noder/unified.go`, which strongly suggests it's related to the "noder" phase of the compiler, specifically the "unified" approach.

**2. Core Function Identification - `unified()`:**

The most prominent function is `unified(m posMap, noders []*noder)`. This is likely the central entry point for the functionality described in the file. The comment block above it provides a high-level overview: constructing the local package's IR from its AST in two steps: generating an export data "stub" and then generating the IR from that stub. This immediately suggests a serialization/deserialization process is involved.

**3. Analyzing Key Functions Called by `unified()`:**

* **`inline.InlineCall = unifiedInlineCall` and `typecheck.HaveInlineBody = unifiedHaveInlineBody`:**  These assignments indicate that this code interacts with the inlining and typechecking stages. The prefixes "unified" suggest custom implementations for the unified noder.
* **`pgoir.LookupFunc = LookupFunc` and `pgoir.PostLookupCleanup = PostLookupCleanup`:** This points to interaction with Profile-Guided Optimization (PGO). The `LookupFunc` function name is self-explanatory.
* **`writePkgStub(m, noders)`:**  This aligns with the first step described in the `unified` function's comment: generating the export data "stub."
* **`newPkgReader(pkgbits.NewPkgDecoder(...))` and `readPackage(...)`:**  This corresponds to the second step: reading the export data stub.
* **`readBodies(target, false)`:** This function is responsible for expanding function bodies, likely after they've been initially loaded from the export data.
* **Loop checking `fn.Typecheck() == 0`:** This is a crucial verification step, ensuring all functions and at least their first statements have been typechecked.
* **Loop marking runtime functions with `ir.Norace`:** This is a specific optimization for runtime functions.

**4. Delving into Supporting Functions:**

* **`LookupFunc(fullName string)`:**  The comments and code clearly indicate its purpose: looking up functions (and methods) by their fully qualified names from the available export data. The `TODO` comments point out limitations with generics.
* **`PostLookupCleanup()`:** Its sole purpose is to call `readBodies`, indicating a post-processing step after using `LookupFunc`.
* **`lookupFunction(pkg *types.Pkg, symName string)` and `lookupMethod(pkg *types.Pkg, symName string)`:** These are helper functions for `LookupFunc`, separating the lookup logic for functions and methods. The comments highlight the ambiguity between methods and closures.
* **`readBodies(target *ir.Package, duringInlining bool)`:** This function manages the expansion of dictionaries and function bodies, with special handling for inlining.
* **`writePkgStub(...)`:** This function orchestrates the initial typechecking using `checkFiles`, creates a `pkgWriter`, collects declarations, and writes the public and private parts of the export data stub.
* **`freePackage(pkg *types2.Package)`:** This function attempts to trigger garbage collection of the `types2` package, likely to free up memory after its use in `writePkgStub`.
* **`readPackage(...)`:** This function reads the export data, populating the `importpkg` with information about the package's symbols and bodies.
* **`writeUnifiedExport(out io.Writer)`:** This function is responsible for writing the final, self-contained unified IR export data. It involves a `linker` to handle updates, re-exporting, and pruning.

**5. Inferring the Go Language Feature:**

Based on the function names (like `LookupFunc`, `readBodies`, `writePkgStub`, `writeUnifiedExport`), the presence of "export data," and the overall flow of generating an intermediate representation, the code is clearly involved in the **package compilation and linking process**. The "unified" naming suggests a modern approach to this process within the Go compiler. Specifically, it's about how the compiler handles the intermediate representation of code *between* compilation units.

**6. Crafting Examples and Explanations:**

Now that the core functionality is understood, the next step is to create illustrative examples.

* **`LookupFunc` Example:** A simple example demonstrating looking up a function by its fully qualified name makes the purpose clear. The input and output are straightforward.
* **`writeUnifiedExport` Explanation:**  Describing the command-line scenario where this function is used and highlighting the output file makes the context clearer.

**7. Identifying Potential Mistakes:**

The `LookupFunc` function's `TODO` comments about generics directly translate to a potential user mistake: trying to look up instantiated generic functions without the necessary type arguments. The ambiguity between methods and closures is another subtle point that could lead to confusion.

**8. Review and Refinement:**

Finally, review the entire analysis. Ensure the explanations are clear, the examples are accurate, and all aspects of the request are addressed. For instance, double-check if any command-line flags directly influence the behavior of this specific code (in this case, the provided code doesn't directly parse command-line flags itself, but the `writeUnifiedExport` function's behavior is influenced by the `aliastypeparam` experiment). Also, verify the inferred Go language feature aligns with the observed functionality.

This systematic approach, starting with the high-level entry point and progressively analyzing the called functions and their interactions, helps build a comprehensive understanding of the code's purpose and functionality. Paying attention to comments, variable names, and the overall flow of data is crucial in this process.
这段代码是 Go 编译器中 `noder` 包的一部分，专门负责实现**统一中间表示（Unified IR）的构建和处理**。

以下是它的主要功能：

**1. 统一 IR 的构建流程核心:**

   - `unified(m posMap, noders []*noder)` 是构建本地包统一 IR 的入口函数。
   - 它包含两个主要步骤：
      - **生成导出数据 "存根" (Stub):** 使用 `writePkgStub` 函数，基于语法树（AST）生成包含本地包所有信息的初步导出数据。这个存根不包含任何导入的包的信息。
      - **从导出数据生成 IR:** 使用 `readPackage` 函数读取上面生成的导出数据存根，并将其转换为编译器内部的中间表示 (`ir.Node`)。

**2. 按需查找函数 (Lazy Loading):**

   - `LookupFunc(fullName string) (*ir.Func, error)`: 允许根据完整的符号名称查找函数，即使该函数尚未被本地包引用。
   - 这对于某些场景（例如，PGO 期间需要查找 profile 中提到的函数）非常有用，避免了在编译初期加载所有函数。
   - 它会尝试查找函数和方法，因为符号命名可能存在歧义。
   - **推断的 Go 语言功能：**  这部分实现了 **按需加载函数定义** 的功能，尤其在处理大型项目或需要延迟加载的场景下。

   ```go
   // 假设我们有一个包 "mypkg" 包含一个函数 "MyFunc"
   // 在编译器的某个阶段，我们可以通过 LookupFunc 找到它

   import "cmd/compile/internal/noder"
   import "fmt"

   func main() {
       fullName := "mypkg.MyFunc"
       fn, err := noder.LookupFunc(fullName)
       if err != nil {
           fmt.Println("Error looking up function:", err)
           return
       }
       if fn != nil {
           fmt.Printf("Found function: %v\n", fn.Sym().Name)
           // 可以进一步操作找到的函数，例如查看其类型、声明等
       } else {
           fmt.Println("Function not found.")
       }
   }

   // 假设输入的 fullName 是 "mypkg.MyFunc"，且该函数存在于编译器的导出数据中
   // 预期输出：Found function: MyFunc
   ```

**3. 导出数据处理:**

   - `writePkgStub(m posMap, noders []*noder) string`:  负责生成本地包的导出数据存根。它使用 `types2` 包进行初步的类型检查，然后将必要的元数据写入到 `pkgbits` 格式的字符串中。
   - `readPackage(pr *pkgReader, importpkg *types.Pkg, localStub bool)`:  读取导出数据，用于加载本地包的存根或导入的包的信息。
   - `writeUnifiedExport(out io.Writer)`:  最终将完整的、自包含的统一 IR 导出数据写入到输出流。这包括处理依赖关系、内联信息等。

**4. 延迟加载函数体和字典:**

   - `readBodies(target *ir.Package, duringInlining bool)`: 迭代地展开所有待处理的函数体和泛型字典。这是一种延迟加载的策略，只有在需要时才加载函数体，可以提高编译效率。
   - `todoBodies` 和 `todoDicts` 变量（虽然在代码片段中未直接定义，但可以推断出其存在）用于存储待处理的函数体和字典。

**5. 与类型检查和内联的集成:**

   - 代码中可以看到与类型检查 (`typecheck`) 和内联 (`inline`) 相关的函数赋值，例如 `inline.InlineCall = unifiedInlineCall`。这表明 `unified.go` 模块负责提供统一 IR 构建阶段的内联和类型检查钩子。
   - 两次类型检查：一次在生成导出数据之前（使用 `types2`），一次在读取导出数据之后（使用 `gc/typecheck`）。这是为了兼容性和逐步迁移到 `types2` 的策略。

**6. 与 PGO 的集成:**

   - `pgoir.LookupFunc = LookupFunc` 和 `pgoir.PostLookupCleanup = PostLookupCleanup` 将 `LookupFunc` 和 `PostLookupCleanup` 函数暴露给 Profile-Guided Optimization (PGO) 模块使用。

**7. 内存管理:**

   - `freePackage(pkg *types2.Package)`:  尝试强制垃圾回收 `types2.Package`，以释放内存。

**涉及的 Go 语言功能实现:**

这段代码的核心是实现了 **Go 编译器的中间表示生成和处理流程**，特别是引入了 "统一 IR" 的概念。它涉及到以下 Go 语言功能的内部实现：

* **包的编译和链接:**  生成和读取包的导出数据是编译和链接过程的关键步骤。
* **函数和方法的查找:**  `LookupFunc` 的实现是符号解析和查找的一部分。
* **泛型 (Generics):**  `readBodies` 中处理 `todoDicts` 以及关于泛型实例化的注释表明它与泛型的编译有关。
* **内联 (Inlining):**  与 `inline` 包的交互表明它参与了内联优化。
* **Profile-Guided Optimization (PGO):**  通过 `pgoir` 包的集成，支持基于性能 profile 的优化。

**命令行参数的具体处理:**

这段代码本身**没有直接处理命令行参数**。它是在 Go 编译器的内部工作流程中被调用的模块。然而，编译器的命令行参数会间接地影响这段代码的行为，例如：

* **`-p <importpath>`:**  错误的 `-p` 参数会导致 `readPackage` 中出现 `mismatched import path` 错误。
* **`-l`:**  禁用内联可能会影响 `readBodies` 的 `duringInlining` 参数。
* **`-gcflags` 和 `-ldflags`:**  这些参数可以影响编译和链接的各个方面，间接影响统一 IR 的构建。
* **`-m`:**  内联决策的打印级别，会影响 `readBodies` 中对 `base.Flag.LowerM` 的处理。

**使用者易犯错的点 (开发者在扩展或修改编译器时):**

1. **假设 `LookupFunc` 能立即找到所有函数：**  `LookupFunc` 的设计是按需加载，如果依赖于它能立刻返回所有函数，可能会导致错误。需要理解其延迟加载的特性。
2. **不理解导出数据的格式 (`pkgbits`):** 修改导出数据的写入或读取逻辑需要深入理解 `pkgbits` 格式，否则容易引入兼容性问题。
3. **忽略类型检查的重要性：**  代码中强调了两次类型检查，如果跳过或不正确地执行类型检查，会导致生成的 IR 不正确。
4. **错误地处理泛型实例化：**  代码中的 `TODO` 注释表明泛型处理的复杂性，不正确地处理泛型实例化可能导致编译错误或运行时错误。
5. **在不应该调用 `readBodies` 的时候调用它：** `readBodies` 负责加载函数体，如果过早或过晚调用，可能会导致数据不一致。

总而言之，`unified.go` 是 Go 编译器中一个核心模块，负责将源代码转换为统一的中间表示，为后续的优化和代码生成阶段奠定基础。它涉及到包的导入导出、函数查找、泛型处理、内联优化等关键编译步骤。理解这段代码对于深入了解 Go 编译器的内部机制至关重要。

### 提示词
```
这是路径为go/src/cmd/compile/internal/noder/unified.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
```

### 源代码
```go
// Copyright 2021 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package noder

import (
	"cmp"
	"fmt"
	"internal/buildcfg"
	"internal/pkgbits"
	"internal/types/errors"
	"io"
	"runtime"
	"slices"
	"strings"

	"cmd/compile/internal/base"
	"cmd/compile/internal/inline"
	"cmd/compile/internal/ir"
	"cmd/compile/internal/pgoir"
	"cmd/compile/internal/typecheck"
	"cmd/compile/internal/types"
	"cmd/compile/internal/types2"
	"cmd/internal/src"
)

// localPkgReader holds the package reader used for reading the local
// package. It exists so the unified IR linker can refer back to it
// later.
var localPkgReader *pkgReader

// LookupFunc returns the ir.Func for an arbitrary full symbol name if
// that function exists in the set of available export data.
//
// This allows lookup of arbitrary functions and methods that aren't otherwise
// referenced by the local package and thus haven't been read yet.
//
// TODO(prattmic): Does not handle instantiation of generic types. Currently
// profiles don't contain the original type arguments, so we won't be able to
// create the runtime dictionaries.
//
// TODO(prattmic): Hit rate of this function is usually fairly low, and errors
// are only used when debug logging is enabled. Consider constructing cheaper
// errors by default.
func LookupFunc(fullName string) (*ir.Func, error) {
	pkgPath, symName, err := ir.ParseLinkFuncName(fullName)
	if err != nil {
		return nil, fmt.Errorf("error parsing symbol name %q: %v", fullName, err)
	}

	pkg, ok := types.PkgMap()[pkgPath]
	if !ok {
		return nil, fmt.Errorf("pkg %s doesn't exist in %v", pkgPath, types.PkgMap())
	}

	// Symbol naming is ambiguous. We can't necessarily distinguish between
	// a method and a closure. e.g., is foo.Bar.func1 a closure defined in
	// function Bar, or a method on type Bar? Thus we must simply attempt
	// to lookup both.

	fn, err := lookupFunction(pkg, symName)
	if err == nil {
		return fn, nil
	}

	fn, mErr := lookupMethod(pkg, symName)
	if mErr == nil {
		return fn, nil
	}

	return nil, fmt.Errorf("%s is not a function (%v) or method (%v)", fullName, err, mErr)
}

// PostLookupCleanup performs cleanup operations needed
// after a series of calls to LookupFunc, specifically invoking
// readBodies to post-process any funcs on the "todoBodies" list
// that were added as a result of the lookup operations.
func PostLookupCleanup() {
	readBodies(typecheck.Target, false)
}

func lookupFunction(pkg *types.Pkg, symName string) (*ir.Func, error) {
	sym := pkg.Lookup(symName)

	// TODO(prattmic): Enclosed functions (e.g., foo.Bar.func1) are not
	// present in objReader, only as OCLOSURE nodes in the enclosing
	// function.
	pri, ok := objReader[sym]
	if !ok {
		return nil, fmt.Errorf("func sym %v missing objReader", sym)
	}

	node, err := pri.pr.objIdxMayFail(pri.idx, nil, nil, false)
	if err != nil {
		return nil, fmt.Errorf("func sym %v lookup error: %w", sym, err)
	}
	name := node.(*ir.Name)
	if name.Op() != ir.ONAME || name.Class != ir.PFUNC {
		return nil, fmt.Errorf("func sym %v refers to non-function name: %v", sym, name)
	}
	return name.Func, nil
}

func lookupMethod(pkg *types.Pkg, symName string) (*ir.Func, error) {
	// N.B. readPackage creates a Sym for every object in the package to
	// initialize objReader and importBodyReader, even if the object isn't
	// read.
	//
	// However, objReader is only initialized for top-level objects, so we
	// must first lookup the type and use that to find the method rather
	// than looking for the method directly.
	typ, meth, err := ir.LookupMethodSelector(pkg, symName)
	if err != nil {
		return nil, fmt.Errorf("error looking up method symbol %q: %v", symName, err)
	}

	pri, ok := objReader[typ]
	if !ok {
		return nil, fmt.Errorf("type sym %v missing objReader", typ)
	}

	node, err := pri.pr.objIdxMayFail(pri.idx, nil, nil, false)
	if err != nil {
		return nil, fmt.Errorf("func sym %v lookup error: %w", typ, err)
	}
	name := node.(*ir.Name)
	if name.Op() != ir.OTYPE {
		return nil, fmt.Errorf("type sym %v refers to non-type name: %v", typ, name)
	}
	if name.Alias() {
		return nil, fmt.Errorf("type sym %v refers to alias", typ)
	}
	if name.Type().IsInterface() {
		return nil, fmt.Errorf("type sym %v refers to interface type", typ)
	}

	for _, m := range name.Type().Methods() {
		if m.Sym == meth {
			fn := m.Nname.(*ir.Name).Func
			return fn, nil
		}
	}

	return nil, fmt.Errorf("method %s missing from method set of %v", symName, typ)
}

// unified constructs the local package's Internal Representation (IR)
// from its syntax tree (AST).
//
// The pipeline contains 2 steps:
//
//  1. Generate the export data "stub".
//
//  2. Generate the IR from the export data above.
//
// The package data "stub" at step (1) contains everything from the local package,
// but nothing that has been imported. When we're actually writing out export data
// to the output files (see writeNewExport), we run the "linker", which:
//
//   - Updates compiler extensions data (e.g. inlining cost, escape analysis results).
//
//   - Handles re-exporting any transitive dependencies.
//
//   - Prunes out any unnecessary details (e.g. non-inlineable functions, because any
//     downstream importers only care about inlinable functions).
//
// The source files are typechecked twice: once before writing the export data
// using types2, and again after reading the export data using gc/typecheck.
// The duplication of work will go away once we only use the types2 type checker,
// removing the gc/typecheck step. For now, it is kept because:
//
//   - It reduces the engineering costs in maintaining a fork of typecheck
//     (e.g. no need to backport fixes like CL 327651).
//
//   - It makes it easier to pass toolstash -cmp.
//
//   - Historically, we would always re-run the typechecker after importing a package,
//     even though we know the imported data is valid. It's not ideal, but it's
//     not causing any problems either.
//
//   - gc/typecheck is still in charge of some transformations, such as rewriting
//     multi-valued function calls or transforming ir.OINDEX to ir.OINDEXMAP.
//
// Using the syntax tree with types2, which has a complete representation of generics,
// the unified IR has the full typed AST needed for introspection during step (1).
// In other words, we have all the necessary information to build the generic IR form
// (see writer.captureVars for an example).
func unified(m posMap, noders []*noder) {
	inline.InlineCall = unifiedInlineCall
	typecheck.HaveInlineBody = unifiedHaveInlineBody
	pgoir.LookupFunc = LookupFunc
	pgoir.PostLookupCleanup = PostLookupCleanup

	data := writePkgStub(m, noders)

	target := typecheck.Target

	localPkgReader = newPkgReader(pkgbits.NewPkgDecoder(types.LocalPkg.Path, data))
	readPackage(localPkgReader, types.LocalPkg, true)

	r := localPkgReader.newReader(pkgbits.RelocMeta, pkgbits.PrivateRootIdx, pkgbits.SyncPrivate)
	r.pkgInit(types.LocalPkg, target)

	readBodies(target, false)

	// Check that nothing snuck past typechecking.
	for _, fn := range target.Funcs {
		if fn.Typecheck() == 0 {
			base.FatalfAt(fn.Pos(), "missed typecheck: %v", fn)
		}

		// For functions, check that at least their first statement (if
		// any) was typechecked too.
		if len(fn.Body) != 0 {
			if stmt := fn.Body[0]; stmt.Typecheck() == 0 {
				base.FatalfAt(stmt.Pos(), "missed typecheck: %v", stmt)
			}
		}
	}

	// For functions originally came from package runtime,
	// mark as norace to prevent instrumenting, see issue #60439.
	for _, fn := range target.Funcs {
		if !base.Flag.CompilingRuntime && types.RuntimeSymName(fn.Sym()) != "" {
			fn.Pragma |= ir.Norace
		}
	}

	base.ExitIfErrors() // just in case
}

// readBodies iteratively expands all pending dictionaries and
// function bodies.
//
// If duringInlining is true, then the inline.InlineDecls is called as
// necessary on instantiations of imported generic functions, so their
// inlining costs can be computed.
func readBodies(target *ir.Package, duringInlining bool) {
	var inlDecls []*ir.Func

	// Don't use range--bodyIdx can add closures to todoBodies.
	for {
		// The order we expand dictionaries and bodies doesn't matter, so
		// pop from the end to reduce todoBodies reallocations if it grows
		// further.
		//
		// However, we do at least need to flush any pending dictionaries
		// before reading bodies, because bodies might reference the
		// dictionaries.

		if len(todoDicts) > 0 {
			fn := todoDicts[len(todoDicts)-1]
			todoDicts = todoDicts[:len(todoDicts)-1]
			fn()
			continue
		}

		if len(todoBodies) > 0 {
			fn := todoBodies[len(todoBodies)-1]
			todoBodies = todoBodies[:len(todoBodies)-1]

			pri, ok := bodyReader[fn]
			assert(ok)
			pri.funcBody(fn)

			// Instantiated generic function: add to Decls for typechecking
			// and compilation.
			if fn.OClosure == nil && len(pri.dict.targs) != 0 {
				// cmd/link does not support a type symbol referencing a method symbol
				// across DSO boundary, so force re-compiling methods on a generic type
				// even it was seen from imported package in linkshared mode, see #58966.
				canSkipNonGenericMethod := !(base.Ctxt.Flag_linkshared && ir.IsMethod(fn))
				if duringInlining && canSkipNonGenericMethod {
					inlDecls = append(inlDecls, fn)
				} else {
					target.Funcs = append(target.Funcs, fn)
				}
			}

			continue
		}

		break
	}

	todoDicts = nil
	todoBodies = nil

	if len(inlDecls) != 0 {
		// If we instantiated any generic functions during inlining, we need
		// to call CanInline on them so they'll be transitively inlined
		// correctly (#56280).
		//
		// We know these functions were already compiled in an imported
		// package though, so we don't need to actually apply InlineCalls or
		// save the function bodies any further than this.
		//
		// We can also lower the -m flag to 0, to suppress duplicate "can
		// inline" diagnostics reported against the imported package. Again,
		// we already reported those diagnostics in the original package, so
		// it's pointless repeating them here.

		oldLowerM := base.Flag.LowerM
		base.Flag.LowerM = 0
		inline.CanInlineFuncs(inlDecls, nil)
		base.Flag.LowerM = oldLowerM

		for _, fn := range inlDecls {
			fn.Body = nil // free memory
		}
	}
}

// writePkgStub type checks the given parsed source files,
// writes an export data package stub representing them,
// and returns the result.
func writePkgStub(m posMap, noders []*noder) string {
	pkg, info, otherInfo := checkFiles(m, noders)

	pw := newPkgWriter(m, pkg, info, otherInfo)

	pw.collectDecls(noders)

	publicRootWriter := pw.newWriter(pkgbits.RelocMeta, pkgbits.SyncPublic)
	privateRootWriter := pw.newWriter(pkgbits.RelocMeta, pkgbits.SyncPrivate)

	assert(publicRootWriter.Idx == pkgbits.PublicRootIdx)
	assert(privateRootWriter.Idx == pkgbits.PrivateRootIdx)

	{
		w := publicRootWriter
		w.pkg(pkg)

		if w.Version().Has(pkgbits.HasInit) {
			w.Bool(false)
		}

		scope := pkg.Scope()
		names := scope.Names()
		w.Len(len(names))
		for _, name := range names {
			w.obj(scope.Lookup(name), nil)
		}

		w.Sync(pkgbits.SyncEOF)
		w.Flush()
	}

	{
		w := privateRootWriter
		w.pkgInit(noders)
		w.Flush()
	}

	var sb strings.Builder
	pw.DumpTo(&sb)

	// At this point, we're done with types2. Make sure the package is
	// garbage collected.
	freePackage(pkg)

	return sb.String()
}

// freePackage ensures the given package is garbage collected.
func freePackage(pkg *types2.Package) {
	// The GC test below relies on a precise GC that runs finalizers as
	// soon as objects are unreachable. Our implementation provides
	// this, but other/older implementations may not (e.g., Go 1.4 does
	// not because of #22350). To avoid imposing unnecessary
	// restrictions on the GOROOT_BOOTSTRAP toolchain, we skip the test
	// during bootstrapping.
	if base.CompilerBootstrap || base.Debug.GCCheck == 0 {
		*pkg = types2.Package{}
		return
	}

	// Set a finalizer on pkg so we can detect if/when it's collected.
	done := make(chan struct{})
	runtime.SetFinalizer(pkg, func(*types2.Package) { close(done) })

	// Important: objects involved in cycles are not finalized, so zero
	// out pkg to break its cycles and allow the finalizer to run.
	*pkg = types2.Package{}

	// It typically takes just 1 or 2 cycles to release pkg, but it
	// doesn't hurt to try a few more times.
	for i := 0; i < 10; i++ {
		select {
		case <-done:
			return
		default:
			runtime.GC()
		}
	}

	base.Fatalf("package never finalized")
}

// readPackage reads package export data from pr to populate
// importpkg.
//
// localStub indicates whether pr is reading the stub export data for
// the local package, as opposed to relocated export data for an
// import.
func readPackage(pr *pkgReader, importpkg *types.Pkg, localStub bool) {
	{
		r := pr.newReader(pkgbits.RelocMeta, pkgbits.PublicRootIdx, pkgbits.SyncPublic)

		pkg := r.pkg()
		// This error can happen if "go tool compile" is called with wrong "-p" flag, see issue #54542.
		if pkg != importpkg {
			base.ErrorfAt(base.AutogeneratedPos, errors.BadImportPath, "mismatched import path, have %q (%p), want %q (%p)", pkg.Path, pkg, importpkg.Path, importpkg)
			base.ErrorExit()
		}

		if r.Version().Has(pkgbits.HasInit) {
			r.Bool()
		}

		for i, n := 0, r.Len(); i < n; i++ {
			r.Sync(pkgbits.SyncObject)
			if r.Version().Has(pkgbits.DerivedFuncInstance) {
				assert(!r.Bool())
			}
			idx := r.Reloc(pkgbits.RelocObj)
			assert(r.Len() == 0)

			path, name, code := r.p.PeekObj(idx)
			if code != pkgbits.ObjStub {
				objReader[types.NewPkg(path, "").Lookup(name)] = pkgReaderIndex{pr, idx, nil, nil, nil}
			}
		}

		r.Sync(pkgbits.SyncEOF)
	}

	if !localStub {
		r := pr.newReader(pkgbits.RelocMeta, pkgbits.PrivateRootIdx, pkgbits.SyncPrivate)

		if r.Bool() {
			sym := importpkg.Lookup(".inittask")
			task := ir.NewNameAt(src.NoXPos, sym, nil)
			task.Class = ir.PEXTERN
			sym.Def = task
		}

		for i, n := 0, r.Len(); i < n; i++ {
			path := r.String()
			name := r.String()
			idx := r.Reloc(pkgbits.RelocBody)

			sym := types.NewPkg(path, "").Lookup(name)
			if _, ok := importBodyReader[sym]; !ok {
				importBodyReader[sym] = pkgReaderIndex{pr, idx, nil, nil, nil}
			}
		}

		r.Sync(pkgbits.SyncEOF)
	}
}

// writeUnifiedExport writes to `out` the finalized, self-contained
// Unified IR export data file for the current compilation unit.
func writeUnifiedExport(out io.Writer) {
	// Use V2 as the encoded version aliastypeparams GOEXPERIMENT is enabled.
	version := pkgbits.V1
	if buildcfg.Experiment.AliasTypeParams {
		version = pkgbits.V2
	}
	l := linker{
		pw: pkgbits.NewPkgEncoder(version, base.Debug.SyncFrames),

		pkgs:   make(map[string]index),
		decls:  make(map[*types.Sym]index),
		bodies: make(map[*types.Sym]index),
	}

	publicRootWriter := l.pw.NewEncoder(pkgbits.RelocMeta, pkgbits.SyncPublic)
	privateRootWriter := l.pw.NewEncoder(pkgbits.RelocMeta, pkgbits.SyncPrivate)
	assert(publicRootWriter.Idx == pkgbits.PublicRootIdx)
	assert(privateRootWriter.Idx == pkgbits.PrivateRootIdx)

	var selfPkgIdx index

	{
		pr := localPkgReader
		r := pr.NewDecoder(pkgbits.RelocMeta, pkgbits.PublicRootIdx, pkgbits.SyncPublic)

		r.Sync(pkgbits.SyncPkg)
		selfPkgIdx = l.relocIdx(pr, pkgbits.RelocPkg, r.Reloc(pkgbits.RelocPkg))

		if r.Version().Has(pkgbits.HasInit) {
			r.Bool()
		}

		for i, n := 0, r.Len(); i < n; i++ {
			r.Sync(pkgbits.SyncObject)
			if r.Version().Has(pkgbits.DerivedFuncInstance) {
				assert(!r.Bool())
			}
			idx := r.Reloc(pkgbits.RelocObj)
			assert(r.Len() == 0)

			xpath, xname, xtag := pr.PeekObj(idx)
			assert(xpath == pr.PkgPath())
			assert(xtag != pkgbits.ObjStub)

			if types.IsExported(xname) {
				l.relocIdx(pr, pkgbits.RelocObj, idx)
			}
		}

		r.Sync(pkgbits.SyncEOF)
	}

	{
		var idxs []index
		for _, idx := range l.decls {
			idxs = append(idxs, idx)
		}
		slices.Sort(idxs)

		w := publicRootWriter

		w.Sync(pkgbits.SyncPkg)
		w.Reloc(pkgbits.RelocPkg, selfPkgIdx)

		if w.Version().Has(pkgbits.HasInit) {
			w.Bool(false)
		}

		w.Len(len(idxs))
		for _, idx := range idxs {
			w.Sync(pkgbits.SyncObject)
			if w.Version().Has(pkgbits.DerivedFuncInstance) {
				w.Bool(false)
			}
			w.Reloc(pkgbits.RelocObj, idx)
			w.Len(0)
		}

		w.Sync(pkgbits.SyncEOF)
		w.Flush()
	}

	{
		type symIdx struct {
			sym *types.Sym
			idx index
		}
		var bodies []symIdx
		for sym, idx := range l.bodies {
			bodies = append(bodies, symIdx{sym, idx})
		}
		slices.SortFunc(bodies, func(a, b symIdx) int { return cmp.Compare(a.idx, b.idx) })

		w := privateRootWriter

		w.Bool(typecheck.Lookup(".inittask").Def != nil)

		w.Len(len(bodies))
		for _, body := range bodies {
			w.String(body.sym.Pkg.Path)
			w.String(body.sym.Name)
			w.Reloc(pkgbits.RelocBody, body.idx)
		}

		w.Sync(pkgbits.SyncEOF)
		w.Flush()
	}

	base.Ctxt.Fingerprint = l.pw.DumpTo(out)
}
```