Response:
The user wants me to analyze a Go code snippet from `go/src/cmd/cgo/out.go`. This is the second part of a two-part snippet analysis. I need to:

1. **Summarize the functionality** of this code.
2. **Infer the broader Go feature** this code relates to and provide a Go code example.
3. **Explain code logic** with hypothetical inputs and outputs.
4. **Describe command-line argument handling**.
5. **Point out common mistakes for users**. (If any)

**Part 2 Focus:** This snippet primarily deals with generating C and Go code for exporting Go functions to C when using `cgo`. It handles two scenarios: the default `gc` compiler and the `gccgo` compiler.

**Breakdown of the Snippet:**

- **`writeGccExports` Function:** Generates C and Go wrapper functions to allow C code to call exported Go functions compiled with `gccgo`.
    - It writes to `.go`, `.m`, `.c`, and `.h` files.
    - It defines C function signatures and corresponding Go wrapper functions.
    - It handles argument and return value marshalling.
    - It includes `syscall.CgocallBack` and `syscall.CgocallBackDone` for `gccgo`.
- **`writeGcExports` Function:** Generates C and Go wrapper functions for the standard `gc` compiler.
    - It's similar to `writeGccExports` but uses a different approach for calling the Go function from C.
    - It handles argument and return value marshalling through a struct.
    - It includes directives for exporting and linking symbols.
- **`writeExportHeader` Function:** Writes the header of the `_cgo_export.h` file, including preamble and boilerplate code.
- **`gccgoToSymbol` Function:**  Mangles Go symbol names for `gccgo`.
- **`gccgoSymbolPrefix` Function:** Determines the prefix for `gccgo` symbols.
- **`forFieldList` Function:** A utility function to iterate over fields in an `ast.FieldList`.
- **`c` Function:** A helper function to create `TypeRepr` objects.
- **`goTypes` Map:** Defines mappings for basic Go types to their C equivalents.
- **`cgoType` and `doCgoType` Functions:**  Determine the C type representation of a Go type. Handles basic types, pointers, slices, and more complex types. It includes cycle detection for recursive types.
- **Constant Definitions:**  Various string constants define prologues and helper code snippets for C and Go files, handling things like thread safety (TSAN), memory safety (MSAN), and built-in functions like `GoString`, `CString`, etc.

**Overall Goal:** The code snippet facilitates the interoperability between Go and C by generating necessary glue code when Go functions are exported for use in C.
这段代码的主要功能是为使用 `cgo` 将 Go 函数导出到 C 代码时，生成必要的 C 和 Go 桥接代码。它区分了两种编译场景：使用标准的 `gc` 编译器和使用 `gccgo` 编译器。

**功能归纳:**

1. **为 `gc` 编译器生成 C 和 Go 桥接代码:**
   - 生成一个 C 函数包装器，该包装器接收 C 风格的参数，调用 Go 运行时环境，并调用实际的 Go 函数。
   - 生成一个 Go 函数包装器，该包装器负责解包 C 传递过来的参数结构体，并调用实际的 Go 函数。
   - 在内部链接模式下，导出 C 包装器。
   - 在外部链接模式下，导出 Go 包装器。
   - 使用 `//go:cgo_export_dynamic` 和 `//go:linkname` 指令来处理符号的导出和链接。
   - 对于有返回值的函数，处理返回值的传递和检查。

2. **为 `gccgo` 编译器生成 C 和 Go 桥接代码:**
   - 生成一个 C 函数包装器，该包装器接收 C 风格的参数，并直接调用对应的 Go 函数（通过特定的符号名称）。
   - 生成一个 Go 函数包装器，该包装器调用 `syscall.CgocallBack()` 和 `syscall.CgocallBackDone()`，然后调用实际的 Go 函数。
   - 定义了 `gccgo` 特有的符号前缀和符号 mangling 机制。

3. **生成 C 导出头文件 (`_cgo_export.h`):**
   - 包含必要的头文件和类型定义。
   - 生成导出函数的 C 声明。
   - 处理 "C" 导入注释中的前导代码。

4. **类型映射:**
   - 将 Go 类型映射到相应的 C 类型，以便在桥接代码中使用。
   - 处理基本类型、指针、切片等。
   - 对于不支持导出的 Go 类型会产生错误。

5. **提供内置函数的定义:**
   - 定义了 Go 和 C 中用于字符串和字节数组转换的内置函数，例如 `GoString`, `CString`, `GoBytes`, `CBytes`，以及内存分配函数 `_CMalloc`。
   - 针对 `gc` 和 `gccgo` 提供了不同的实现。

**推理出的 Go 语言功能：cgo (C语言互操作)**

这段代码是 `cgo` 工具链中生成桥接代码的关键部分，它使得 Go 语言能够调用 C 代码，反之亦然。导出的 Go 函数可以被 C 代码调用。

**Go 代码示例:**

假设我们有以下 Go 代码（在 `my_package.go` 中）：

```go
package my_package

import "C"

//export Add
func Add(a int, b int) int {
	return a + b
}

//export SayHello
func SayHello(name string) {
	C.puts(C.CString(name))
}
```

当使用 `go build` 或 `go install` 编译包含 `cgo` 指令的代码时，`cgo` 工具会生成类似上述代码片段中的桥接代码。

**代码推理与假设的输入与输出 (针对 `gc` 编译器):**

假设 `exp.ExpName` 是 "Add"，`fntype` 代表 `func(int, int) int`。

**输入 (传递给生成的 C 包装器):**

```c
struct {
    GoInt p0; // 对应参数 a
    GoInt p1; // 对应参数 b
} args;
args.p0 = 5;
args.p1 = 10;
```

**生成的 C 包装器代码片段 (简化):**

```c
GoInt _cgoexp_my_package_Add(void* _cgo_ctxt, struct { GoInt p0; GoInt p1; } _cgo_a) {
	_cgo_tsan_acquire();
	GoInt _cgo_r = _cgoexp_my_package_Add(_cgo_ctxt, _cgo_a); // 调用 Go 包装器
	_cgo_tsan_release();
	return _cgo_r;
}

void _cgoexp_my_package_Add(void* p){
	struct {
		GoInt p0;
		GoInt p1;
		GoInt r0;
	} *a = p;
	a->r0 = my_package.Add(a->p0, a->p1); // 调用实际的 Go 函数
	_cgoCheckResult(a->r0);
}
```

**输出 (由 C 包装器返回):**

`15` (GoInt 类型)

**代码推理与假设的输入与输出 (针对 `gccgo` 编译器):**

假设 `exp.ExpName` 是 "Add"，`fntype` 代表 `func(int, int) int`。

**输入 (传递给生成的 C 包装器):**

```c
GoInt p0 = 5;
GoInt p1 = 10;
```

**生成的 C 包装器代码片段 (简化):**

```c
GoInt Add(GoInt p0, GoInt p1) {
	GoInt r;
	if(_cgo_wait_runtime_init_done)
		_cgo_wait_runtime_init_done();
	_cgo_tsan_release();
	r = Cgoexp_Add(p0, p1); // 调用 Go 包装器
	_cgo_tsan_acquire();
	return r;
}

GoInt Cgoexp_Add(GoInt p0, GoInt p1) {
	syscall.CgocallBack();
	defer syscall.CgocallBackDone();
	return my_package.Add(p0, p1); // 调用实际的 Go 函数
}
```

**输出 (由 C 包装器返回):**

`15` (GoInt 类型)

**命令行参数的具体处理:**

这段代码中涉及的命令行参数主要影响了生成的代码：

- **`-gccgo`:**  如果设置，则会生成 `gccgo` 兼容的代码。
- **`-gccgopkgpath`:**  指定 `gccgo` 的包路径，用于符号 mangling。
- **`-gccgoprefix`:**  指定 `gccgo` 的符号前缀，用于符号 mangling。
- **`-objdir`:** 指定目标文件输出目录，用于查找 `gccgo` 命令进行符号 mangling。

`gccgoToSymbol` 函数会根据 `-gccgo`, `-gccgopkgpath`, 和 `-gccgoprefix` 的值来生成 `gccgo` 特定的符号名称。它会尝试查找 `gccgo` 命令，并使用 `pkgpath.ToSymbolFunc` 来进行符号 mangling。

**使用者易犯错的点 (示例):**

一个常见的错误是在导出的 Go 函数中使用 `cgo` 不支持的 Go 类型作为参数或返回值。例如，尝试导出带有 Go 结构体或切片的函数，而没有使用指针进行传递。

```go
package my_package

import "C"

// 错误示例：直接导出带有 Go 结构体的函数
//export ProcessData
//func ProcessData(data struct{ A int; B string }) {
//	C.puts(C.CString(data.B))
//}

// 正确示例：使用指针传递结构体
type Data struct {
	A int
	B string
}

//export ProcessData
func ProcessData(data *Data) {
	C.puts(C.CString(data.B))
}
```

在这个错误的示例中，`cgo` 无法直接将 Go 结构体转换为 C 中对应的结构体，会导致编译错误。正确的做法是使用指针传递结构体。

**总结这段代码的功能:**

总而言之，这段代码是 `cgo` 工具的核心组成部分，负责根据目标编译器 (`gc` 或 `gccgo`) 的不同，生成将 Go 函数暴露给 C 代码调用的桥梁代码。它处理了参数和返回值的传递，符号的导出和链接，以及内置函数的定义，从而实现了 Go 和 C 代码的无缝集成。

### 提示词
```
这是路径为go/src/cmd/cgo/out.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第2部分，共2部分，请归纳一下它的功能
```

### 源代码
```go
(fgcc, "\t_cgo_release_context(_cgo_ctxt);\n")
		if gccResult != "void" {
			if len(fntype.Results.List) == 1 && len(fntype.Results.List[0].Names) <= 1 {
				fmt.Fprintf(fgcc, "\treturn _cgo_a.r0;\n")
			} else {
				forFieldList(fntype.Results,
					func(i int, aname string, atype ast.Expr) {
						fmt.Fprintf(fgcc, "\tr.r%d = _cgo_a.r%d;\n", i, i)
					})
				fmt.Fprintf(fgcc, "\treturn r;\n")
			}
		}
		fmt.Fprintf(fgcc, "}\n")

		// In internal linking mode, the Go linker sees both
		// the C wrapper written above and the Go wrapper it
		// references. Hence, export the C wrapper (e.g., for
		// if we're building a shared object). The Go linker
		// will resolve the C wrapper's reference to the Go
		// wrapper without a separate export.
		fmt.Fprintf(fgo2, "//go:cgo_export_dynamic %s\n", exp.ExpName)
		// cgo_export_static refers to a symbol by its linker
		// name, so set the linker name of the Go wrapper.
		fmt.Fprintf(fgo2, "//go:linkname _cgoexp%s_%s _cgoexp%s_%s\n", cPrefix, exp.ExpName, cPrefix, exp.ExpName)
		// In external linking mode, the Go linker sees the Go
		// wrapper, but not the C wrapper. For this case,
		// export the Go wrapper so the host linker can
		// resolve the reference from the C wrapper to the Go
		// wrapper.
		fmt.Fprintf(fgo2, "//go:cgo_export_static _cgoexp%s_%s\n", cPrefix, exp.ExpName)

		// Build the wrapper function compiled by cmd/compile.
		// This unpacks the argument struct above and calls the Go function.
		fmt.Fprintf(fgo2, "func _cgoexp%s_%s(a *%s) {\n", cPrefix, exp.ExpName, gotype)

		fmt.Fprintf(fm, "void _cgoexp%s_%s(void* p){}\n", cPrefix, exp.ExpName)

		fmt.Fprintf(fgo2, "\t")

		if gccResult != "void" {
			// Write results back to frame.
			forFieldList(fntype.Results,
				func(i int, aname string, atype ast.Expr) {
					if i > 0 {
						fmt.Fprintf(fgo2, ", ")
					}
					fmt.Fprintf(fgo2, "a.r%d", i)
				})
			fmt.Fprintf(fgo2, " = ")
		}
		if fn.Recv != nil {
			fmt.Fprintf(fgo2, "a.recv.")
		}
		fmt.Fprintf(fgo2, "%s(", exp.Func.Name)
		forFieldList(fntype.Params,
			func(i int, aname string, atype ast.Expr) {
				if i > 0 {
					fmt.Fprint(fgo2, ", ")
				}
				fmt.Fprintf(fgo2, "a.p%d", i)
			})
		fmt.Fprint(fgo2, ")\n")
		if gccResult != "void" {
			// Verify that any results don't contain any
			// Go pointers.
			forFieldList(fntype.Results,
				func(i int, aname string, atype ast.Expr) {
					if !p.hasPointer(nil, atype, false) {
						return
					}
					fmt.Fprintf(fgo2, "\t_cgoCheckResult(a.r%d)\n", i)
				})
		}
		fmt.Fprint(fgo2, "}\n")
	}

	fmt.Fprintf(fgcch, "%s", gccExportHeaderEpilog)
}

// Write out the C header allowing C code to call exported gccgo functions.
func (p *Package) writeGccgoExports(fgo2, fm, fgcc, fgcch io.Writer) {
	gccgoSymbolPrefix := p.gccgoSymbolPrefix()

	p.writeExportHeader(fgcch)

	fmt.Fprintf(fgcc, "/* Code generated by cmd/cgo; DO NOT EDIT. */\n\n")
	fmt.Fprintf(fgcc, "#include \"_cgo_export.h\"\n")

	fmt.Fprintf(fgcc, "%s\n", gccgoExportFileProlog)
	fmt.Fprintf(fgcc, "%s\n", tsanProlog)
	fmt.Fprintf(fgcc, "%s\n", msanProlog)

	for _, exp := range p.ExpFunc {
		fn := exp.Func
		fntype := fn.Type

		cdeclBuf := new(strings.Builder)
		resultCount := 0
		forFieldList(fntype.Results,
			func(i int, aname string, atype ast.Expr) { resultCount++ })
		switch resultCount {
		case 0:
			fmt.Fprintf(cdeclBuf, "void")
		case 1:
			forFieldList(fntype.Results,
				func(i int, aname string, atype ast.Expr) {
					t := p.cgoType(atype)
					fmt.Fprintf(cdeclBuf, "%s", t.C)
				})
		default:
			// Declare a result struct.
			fmt.Fprintf(fgcch, "\n/* Return type for %s */\n", exp.ExpName)
			fmt.Fprintf(fgcch, "struct %s_return {\n", exp.ExpName)
			forFieldList(fntype.Results,
				func(i int, aname string, atype ast.Expr) {
					t := p.cgoType(atype)
					fmt.Fprintf(fgcch, "\t%s r%d;", t.C, i)
					if len(aname) > 0 {
						fmt.Fprintf(fgcch, " /* %s */", aname)
					}
					fmt.Fprint(fgcch, "\n")
				})
			fmt.Fprintf(fgcch, "};\n")
			fmt.Fprintf(cdeclBuf, "struct %s_return", exp.ExpName)
		}

		cRet := cdeclBuf.String()

		cdeclBuf = new(strings.Builder)
		fmt.Fprintf(cdeclBuf, "(")
		if fn.Recv != nil {
			fmt.Fprintf(cdeclBuf, "%s recv", p.cgoType(fn.Recv.List[0].Type).C.String())
		}
		// Function parameters.
		forFieldList(fntype.Params,
			func(i int, aname string, atype ast.Expr) {
				if i > 0 || fn.Recv != nil {
					fmt.Fprintf(cdeclBuf, ", ")
				}
				t := p.cgoType(atype)
				fmt.Fprintf(cdeclBuf, "%s p%d", t.C, i)
			})
		fmt.Fprintf(cdeclBuf, ")")
		cParams := cdeclBuf.String()

		if len(exp.Doc) > 0 {
			fmt.Fprintf(fgcch, "\n%s", exp.Doc)
		}

		fmt.Fprintf(fgcch, "extern %s %s%s;\n", cRet, exp.ExpName, cParams)

		// We need to use a name that will be exported by the
		// Go code; otherwise gccgo will make it static and we
		// will not be able to link against it from the C
		// code.
		goName := "Cgoexp_" + exp.ExpName
		fmt.Fprintf(fgcc, `extern %s %s %s __asm__("%s.%s");`, cRet, goName, cParams, gccgoSymbolPrefix, gccgoToSymbol(goName))
		fmt.Fprint(fgcc, "\n")

		fmt.Fprint(fgcc, "\nCGO_NO_SANITIZE_THREAD\n")
		fmt.Fprintf(fgcc, "%s %s %s {\n", cRet, exp.ExpName, cParams)
		if resultCount > 0 {
			fmt.Fprintf(fgcc, "\t%s r;\n", cRet)
		}
		fmt.Fprintf(fgcc, "\tif(_cgo_wait_runtime_init_done)\n")
		fmt.Fprintf(fgcc, "\t\t_cgo_wait_runtime_init_done();\n")
		fmt.Fprintf(fgcc, "\t_cgo_tsan_release();\n")
		fmt.Fprint(fgcc, "\t")
		if resultCount > 0 {
			fmt.Fprint(fgcc, "r = ")
		}
		fmt.Fprintf(fgcc, "%s(", goName)
		if fn.Recv != nil {
			fmt.Fprint(fgcc, "recv")
		}
		forFieldList(fntype.Params,
			func(i int, aname string, atype ast.Expr) {
				if i > 0 || fn.Recv != nil {
					fmt.Fprintf(fgcc, ", ")
				}
				fmt.Fprintf(fgcc, "p%d", i)
			})
		fmt.Fprint(fgcc, ");\n")
		fmt.Fprintf(fgcc, "\t_cgo_tsan_acquire();\n")
		if resultCount > 0 {
			fmt.Fprint(fgcc, "\treturn r;\n")
		}
		fmt.Fprint(fgcc, "}\n")

		// Dummy declaration for _cgo_main.c
		fmt.Fprintf(fm, `char %s[1] __asm__("%s.%s");`, goName, gccgoSymbolPrefix, gccgoToSymbol(goName))
		fmt.Fprint(fm, "\n")

		// For gccgo we use a wrapper function in Go, in order
		// to call CgocallBack and CgocallBackDone.

		// This code uses printer.Fprint, not conf.Fprint,
		// because we don't want //line comments in the middle
		// of the function types.
		fmt.Fprint(fgo2, "\n")
		fmt.Fprintf(fgo2, "func %s(", goName)
		if fn.Recv != nil {
			fmt.Fprint(fgo2, "recv ")
			printer.Fprint(fgo2, fset, fn.Recv.List[0].Type)
		}
		forFieldList(fntype.Params,
			func(i int, aname string, atype ast.Expr) {
				if i > 0 || fn.Recv != nil {
					fmt.Fprintf(fgo2, ", ")
				}
				fmt.Fprintf(fgo2, "p%d ", i)
				printer.Fprint(fgo2, fset, atype)
			})
		fmt.Fprintf(fgo2, ")")
		if resultCount > 0 {
			fmt.Fprintf(fgo2, " (")
			forFieldList(fntype.Results,
				func(i int, aname string, atype ast.Expr) {
					if i > 0 {
						fmt.Fprint(fgo2, ", ")
					}
					printer.Fprint(fgo2, fset, atype)
				})
			fmt.Fprint(fgo2, ")")
		}
		fmt.Fprint(fgo2, " {\n")
		fmt.Fprint(fgo2, "\tsyscall.CgocallBack()\n")
		fmt.Fprint(fgo2, "\tdefer syscall.CgocallBackDone()\n")
		fmt.Fprint(fgo2, "\t")
		if resultCount > 0 {
			fmt.Fprint(fgo2, "return ")
		}
		if fn.Recv != nil {
			fmt.Fprint(fgo2, "recv.")
		}
		fmt.Fprintf(fgo2, "%s(", exp.Func.Name)
		forFieldList(fntype.Params,
			func(i int, aname string, atype ast.Expr) {
				if i > 0 {
					fmt.Fprint(fgo2, ", ")
				}
				fmt.Fprintf(fgo2, "p%d", i)
			})
		fmt.Fprint(fgo2, ")\n")
		fmt.Fprint(fgo2, "}\n")
	}

	fmt.Fprintf(fgcch, "%s", gccExportHeaderEpilog)
}

// writeExportHeader writes out the start of the _cgo_export.h file.
func (p *Package) writeExportHeader(fgcch io.Writer) {
	fmt.Fprintf(fgcch, "/* Code generated by cmd/cgo; DO NOT EDIT. */\n\n")
	pkg := *importPath
	if pkg == "" {
		pkg = p.PackagePath
	}
	fmt.Fprintf(fgcch, "/* package %s */\n\n", pkg)
	fmt.Fprintf(fgcch, "%s\n", builtinExportProlog)

	// Remove absolute paths from #line comments in the preamble.
	// They aren't useful for people using the header file,
	// and they mean that the header files change based on the
	// exact location of GOPATH.
	re := regexp.MustCompile(`(?m)^(#line\s+\d+\s+")[^"]*[/\\]([^"]*")`)
	preamble := re.ReplaceAllString(p.Preamble, "$1$2")

	fmt.Fprintf(fgcch, "/* Start of preamble from import \"C\" comments.  */\n\n")
	fmt.Fprintf(fgcch, "%s\n", preamble)
	fmt.Fprintf(fgcch, "\n/* End of preamble from import \"C\" comments.  */\n\n")

	fmt.Fprintf(fgcch, "%s\n", p.gccExportHeaderProlog())
}

// gccgoToSymbol converts a name to a mangled symbol for gccgo.
func gccgoToSymbol(ppath string) string {
	if gccgoMangler == nil {
		var err error
		cmd := os.Getenv("GCCGO")
		if cmd == "" {
			cmd, err = exec.LookPath("gccgo")
			if err != nil {
				fatalf("unable to locate gccgo: %v", err)
			}
		}
		gccgoMangler, err = pkgpath.ToSymbolFunc(cmd, *objDir)
		if err != nil {
			fatalf("%v", err)
		}
	}
	return gccgoMangler(ppath)
}

// Return the package prefix when using gccgo.
func (p *Package) gccgoSymbolPrefix() string {
	if !*gccgo {
		return ""
	}

	if *gccgopkgpath != "" {
		return gccgoToSymbol(*gccgopkgpath)
	}
	if *gccgoprefix == "" && p.PackageName == "main" {
		return "main"
	}
	prefix := gccgoToSymbol(*gccgoprefix)
	if prefix == "" {
		prefix = "go"
	}
	return prefix + "." + p.PackageName
}

// Call a function for each entry in an ast.FieldList, passing the
// index into the list, the name if any, and the type.
func forFieldList(fl *ast.FieldList, fn func(int, string, ast.Expr)) {
	if fl == nil {
		return
	}
	i := 0
	for _, r := range fl.List {
		if r.Names == nil {
			fn(i, "", r.Type)
			i++
		} else {
			for _, n := range r.Names {
				fn(i, n.Name, r.Type)
				i++
			}
		}
	}
}

func c(repr string, args ...interface{}) *TypeRepr {
	return &TypeRepr{repr, args}
}

// Map predeclared Go types to Type.
var goTypes = map[string]*Type{
	"bool":       {Size: 1, Align: 1, C: c("GoUint8")},
	"byte":       {Size: 1, Align: 1, C: c("GoUint8")},
	"int":        {Size: 0, Align: 0, C: c("GoInt")},
	"uint":       {Size: 0, Align: 0, C: c("GoUint")},
	"rune":       {Size: 4, Align: 4, C: c("GoInt32")},
	"int8":       {Size: 1, Align: 1, C: c("GoInt8")},
	"uint8":      {Size: 1, Align: 1, C: c("GoUint8")},
	"int16":      {Size: 2, Align: 2, C: c("GoInt16")},
	"uint16":     {Size: 2, Align: 2, C: c("GoUint16")},
	"int32":      {Size: 4, Align: 4, C: c("GoInt32")},
	"uint32":     {Size: 4, Align: 4, C: c("GoUint32")},
	"int64":      {Size: 8, Align: 8, C: c("GoInt64")},
	"uint64":     {Size: 8, Align: 8, C: c("GoUint64")},
	"float32":    {Size: 4, Align: 4, C: c("GoFloat32")},
	"float64":    {Size: 8, Align: 8, C: c("GoFloat64")},
	"complex64":  {Size: 8, Align: 4, C: c("GoComplex64")},
	"complex128": {Size: 16, Align: 8, C: c("GoComplex128")},
}

// Map an ast type to a Type.
func (p *Package) cgoType(e ast.Expr) *Type {
	return p.doCgoType(e, make(map[ast.Expr]bool))
}

// Map an ast type to a Type, avoiding cycles.
func (p *Package) doCgoType(e ast.Expr, m map[ast.Expr]bool) *Type {
	if m[e] {
		fatalf("%s: invalid recursive type", fset.Position(e.Pos()))
	}
	m[e] = true
	switch t := e.(type) {
	case *ast.StarExpr:
		x := p.doCgoType(t.X, m)
		return &Type{Size: p.PtrSize, Align: p.PtrSize, C: c("%s*", x.C)}
	case *ast.ArrayType:
		if t.Len == nil {
			// Slice: pointer, len, cap.
			return &Type{Size: p.PtrSize * 3, Align: p.PtrSize, C: c("GoSlice")}
		}
		// Non-slice array types are not supported.
	case *ast.StructType:
		// Not supported.
	case *ast.FuncType:
		return &Type{Size: p.PtrSize, Align: p.PtrSize, C: c("void*")}
	case *ast.InterfaceType:
		return &Type{Size: 2 * p.PtrSize, Align: p.PtrSize, C: c("GoInterface")}
	case *ast.MapType:
		return &Type{Size: p.PtrSize, Align: p.PtrSize, C: c("GoMap")}
	case *ast.ChanType:
		return &Type{Size: p.PtrSize, Align: p.PtrSize, C: c("GoChan")}
	case *ast.Ident:
		goTypesFixup := func(r *Type) *Type {
			if r.Size == 0 { // int or uint
				rr := new(Type)
				*rr = *r
				rr.Size = p.IntSize
				rr.Align = p.IntSize
				r = rr
			}
			if r.Align > p.PtrSize {
				r.Align = p.PtrSize
			}
			return r
		}
		// Look up the type in the top level declarations.
		// TODO: Handle types defined within a function.
		for _, d := range p.Decl {
			gd, ok := d.(*ast.GenDecl)
			if !ok || gd.Tok != token.TYPE {
				continue
			}
			for _, spec := range gd.Specs {
				ts, ok := spec.(*ast.TypeSpec)
				if !ok {
					continue
				}
				if ts.Name.Name == t.Name {
					// Give a better error than the one
					// above if we detect a recursive type.
					if m[ts.Type] {
						fatalf("%s: invalid recursive type: %s refers to itself", fset.Position(e.Pos()), t.Name)
					}
					return p.doCgoType(ts.Type, m)
				}
			}
		}
		if def := typedef[t.Name]; def != nil {
			if defgo, ok := def.Go.(*ast.Ident); ok {
				switch defgo.Name {
				case "complex64", "complex128":
					// MSVC does not support the _Complex keyword
					// nor the complex macro.
					// Use GoComplex64 and GoComplex128 instead,
					// which are typedef-ed to a compatible type.
					// See go.dev/issues/36233.
					return goTypesFixup(goTypes[defgo.Name])
				}
			}
			return def
		}
		if t.Name == "uintptr" {
			return &Type{Size: p.PtrSize, Align: p.PtrSize, C: c("GoUintptr")}
		}
		if t.Name == "string" {
			// The string data is 1 pointer + 1 (pointer-sized) int.
			return &Type{Size: 2 * p.PtrSize, Align: p.PtrSize, C: c("GoString")}
		}
		if t.Name == "error" {
			return &Type{Size: 2 * p.PtrSize, Align: p.PtrSize, C: c("GoInterface")}
		}
		if r, ok := goTypes[t.Name]; ok {
			return goTypesFixup(r)
		}
		error_(e.Pos(), "unrecognized Go type %s", t.Name)
		return &Type{Size: 4, Align: 4, C: c("int")}
	case *ast.SelectorExpr:
		id, ok := t.X.(*ast.Ident)
		if ok && id.Name == "unsafe" && t.Sel.Name == "Pointer" {
			return &Type{Size: p.PtrSize, Align: p.PtrSize, C: c("void*")}
		}
	}
	error_(e.Pos(), "Go type not supported in export: %s", gofmt(e))
	return &Type{Size: 4, Align: 4, C: c("int")}
}

const gccProlog = `
#line 1 "cgo-gcc-prolog"
/*
  If x and y are not equal, the type will be invalid
  (have a negative array count) and an inscrutable error will come
  out of the compiler and hopefully mention "name".
*/
#define __cgo_compile_assert_eq(x, y, name) typedef char name[(x-y)*(x-y)*-2UL+1UL];

/* Check at compile time that the sizes we use match our expectations. */
#define __cgo_size_assert(t, n) __cgo_compile_assert_eq(sizeof(t), (size_t)n, _cgo_sizeof_##t##_is_not_##n)

__cgo_size_assert(char, 1)
__cgo_size_assert(short, 2)
__cgo_size_assert(int, 4)
typedef long long __cgo_long_long;
__cgo_size_assert(__cgo_long_long, 8)
__cgo_size_assert(float, 4)
__cgo_size_assert(double, 8)

extern char* _cgo_topofstack(void);

/*
  We use packed structs, but they are always aligned.
  The pragmas and address-of-packed-member are only recognized as warning
  groups in clang 4.0+, so ignore unknown pragmas first.
*/
#pragma GCC diagnostic ignored "-Wunknown-pragmas"
#pragma GCC diagnostic ignored "-Wpragmas"
#pragma GCC diagnostic ignored "-Waddress-of-packed-member"
#pragma GCC diagnostic ignored "-Wunknown-warning-option"
#pragma GCC diagnostic ignored "-Wunaligned-access"

#include <errno.h>
#include <string.h>
`

// Prologue defining TSAN functions in C.
const noTsanProlog = `
#define CGO_NO_SANITIZE_THREAD
#define _cgo_tsan_acquire()
#define _cgo_tsan_release()
`

// This must match the TSAN code in runtime/cgo/libcgo.h.
// This is used when the code is built with the C/C++ Thread SANitizer,
// which is not the same as the Go race detector.
// __tsan_acquire tells TSAN that we are acquiring a lock on a variable,
// in this case _cgo_sync. __tsan_release releases the lock.
// (There is no actual lock, we are just telling TSAN that there is.)
//
// When we call from Go to C we call _cgo_tsan_acquire.
// When the C function returns we call _cgo_tsan_release.
// Similarly, when C calls back into Go we call _cgo_tsan_release
// and then call _cgo_tsan_acquire when we return to C.
// These calls tell TSAN that there is a serialization point at the C call.
//
// This is necessary because TSAN, which is a C/C++ tool, can not see
// the synchronization in the Go code. Without these calls, when
// multiple goroutines call into C code, TSAN does not understand
// that the calls are properly synchronized on the Go side.
//
// To be clear, if the calls are not properly synchronized on the Go side,
// we will be hiding races. But when using TSAN on mixed Go C/C++ code
// it is more important to avoid false positives, which reduce confidence
// in the tool, than to avoid false negatives.
const yesTsanProlog = `
#line 1 "cgo-tsan-prolog"
#define CGO_NO_SANITIZE_THREAD __attribute__ ((no_sanitize_thread))

long long _cgo_sync __attribute__ ((common));

extern void __tsan_acquire(void*);
extern void __tsan_release(void*);

__attribute__ ((unused))
static void _cgo_tsan_acquire() {
	__tsan_acquire(&_cgo_sync);
}

__attribute__ ((unused))
static void _cgo_tsan_release() {
	__tsan_release(&_cgo_sync);
}
`

// Set to yesTsanProlog if we see -fsanitize=thread in the flags for gcc.
var tsanProlog = noTsanProlog

// noMsanProlog is a prologue defining an MSAN function in C.
// This is used when not compiling with -fsanitize=memory.
const noMsanProlog = `
#define _cgo_msan_write(addr, sz)
`

// yesMsanProlog is a prologue defining an MSAN function in C.
// This is used when compiling with -fsanitize=memory.
// See the comment above where _cgo_msan_write is called.
const yesMsanProlog = `
extern void __msan_unpoison(const volatile void *, size_t);

#define _cgo_msan_write(addr, sz) __msan_unpoison((addr), (sz))
`

// msanProlog is set to yesMsanProlog if we see -fsanitize=memory in the flags
// for the C compiler.
var msanProlog = noMsanProlog

const builtinProlog = `
#line 1 "cgo-builtin-prolog"
#include <stddef.h>

/* Define intgo when compiling with GCC.  */
typedef ptrdiff_t intgo;

#define GO_CGO_GOSTRING_TYPEDEF
typedef struct { const char *p; intgo n; } _GoString_;
typedef struct { char *p; intgo n; intgo c; } _GoBytes_;
_GoString_ GoString(char *p);
_GoString_ GoStringN(char *p, int l);
_GoBytes_ GoBytes(void *p, int n);
char *CString(_GoString_);
void *CBytes(_GoBytes_);
void *_CMalloc(size_t);

__attribute__ ((unused))
static size_t _GoStringLen(_GoString_ s) { return (size_t)s.n; }

__attribute__ ((unused))
static const char *_GoStringPtr(_GoString_ s) { return s.p; }
`

const goProlog = `
//go:linkname _cgo_runtime_cgocall runtime.cgocall
func _cgo_runtime_cgocall(unsafe.Pointer, uintptr) int32

//go:linkname _cgoCheckPointer runtime.cgoCheckPointer
//go:noescape
func _cgoCheckPointer(interface{}, interface{})

//go:linkname _cgoCheckResult runtime.cgoCheckResult
//go:noescape
func _cgoCheckResult(interface{})
`

const gccgoGoProlog = `
func _cgoCheckPointer(interface{}, interface{})

func _cgoCheckResult(interface{})
`

const goStringDef = `
//go:linkname _cgo_runtime_gostring runtime.gostring
func _cgo_runtime_gostring(*_Ctype_char) string

// GoString converts the C string p into a Go string.
func _Cfunc_GoString(p *_Ctype_char) string {
	return _cgo_runtime_gostring(p)
}
`

const goStringNDef = `
//go:linkname _cgo_runtime_gostringn runtime.gostringn
func _cgo_runtime_gostringn(*_Ctype_char, int) string

// GoStringN converts the C data p with explicit length l to a Go string.
func _Cfunc_GoStringN(p *_Ctype_char, l _Ctype_int) string {
	return _cgo_runtime_gostringn(p, int(l))
}
`

const goBytesDef = `
//go:linkname _cgo_runtime_gobytes runtime.gobytes
func _cgo_runtime_gobytes(unsafe.Pointer, int) []byte

// GoBytes converts the C data p with explicit length l to a Go []byte.
func _Cfunc_GoBytes(p unsafe.Pointer, l _Ctype_int) []byte {
	return _cgo_runtime_gobytes(p, int(l))
}
`

const cStringDef = `
// CString converts the Go string s to a C string.
//
// The C string is allocated in the C heap using malloc.
// It is the caller's responsibility to arrange for it to be
// freed, such as by calling C.free (be sure to include stdlib.h
// if C.free is needed).
func _Cfunc_CString(s string) *_Ctype_char {
	if len(s)+1 <= 0 {
		panic("string too large")
	}
	p := _cgo_cmalloc(uint64(len(s)+1))
	sliceHeader := struct {
		p   unsafe.Pointer
		len int
		cap int
	}{p, len(s)+1, len(s)+1}
	b := *(*[]byte)(unsafe.Pointer(&sliceHeader))
	copy(b, s)
	b[len(s)] = 0
	return (*_Ctype_char)(p)
}
`

const cBytesDef = `
// CBytes converts the Go []byte slice b to a C array.
//
// The C array is allocated in the C heap using malloc.
// It is the caller's responsibility to arrange for it to be
// freed, such as by calling C.free (be sure to include stdlib.h
// if C.free is needed).
func _Cfunc_CBytes(b []byte) unsafe.Pointer {
	p := _cgo_cmalloc(uint64(len(b)))
	sliceHeader := struct {
		p   unsafe.Pointer
		len int
		cap int
	}{p, len(b), len(b)}
	s := *(*[]byte)(unsafe.Pointer(&sliceHeader))
	copy(s, b)
	return p
}
`

const cMallocDef = `
func _Cfunc__CMalloc(n _Ctype_size_t) unsafe.Pointer {
	return _cgo_cmalloc(uint64(n))
}
`

var builtinDefs = map[string]string{
	"GoString":  goStringDef,
	"GoStringN": goStringNDef,
	"GoBytes":   goBytesDef,
	"CString":   cStringDef,
	"CBytes":    cBytesDef,
	"_CMalloc":  cMallocDef,
}

// Definitions for C.malloc in Go and in C. We define it ourselves
// since we call it from functions we define, such as C.CString.
// Also, we have historically ensured that C.malloc does not return
// nil even for an allocation of 0.

const cMallocDefGo = `
//go:cgo_import_static _cgoPREFIX_Cfunc__Cmalloc
//go:linkname __cgofn__cgoPREFIX_Cfunc__Cmalloc _cgoPREFIX_Cfunc__Cmalloc
var __cgofn__cgoPREFIX_Cfunc__Cmalloc byte
var _cgoPREFIX_Cfunc__Cmalloc = unsafe.Pointer(&__cgofn__cgoPREFIX_Cfunc__Cmalloc)

//go:linkname runtime_throw runtime.throw
func runtime_throw(string)

//go:cgo_unsafe_args
func _cgo_cmalloc(p0 uint64) (r1 unsafe.Pointer) {
	_cgo_runtime_cgocall(_cgoPREFIX_Cfunc__Cmalloc, uintptr(unsafe.Pointer(&p0)))
	if r1 == nil {
		runtime_throw("runtime: C malloc failed")
	}
	return
}
`

// cMallocDefC defines the C version of C.malloc for the gc compiler.
// It is defined here because C.CString and friends need a definition.
// We define it by hand, rather than simply inventing a reference to
// C.malloc, because <stdlib.h> may not have been included.
// This is approximately what writeOutputFunc would generate, but
// skips the cgo_topofstack code (which is only needed if the C code
// calls back into Go). This also avoids returning nil for an
// allocation of 0 bytes.
const cMallocDefC = `
CGO_NO_SANITIZE_THREAD
void _cgoPREFIX_Cfunc__Cmalloc(void *v) {
	struct {
		unsigned long long p0;
		void *r1;
	} PACKED *a = v;
	void *ret;
	_cgo_tsan_acquire();
	ret = malloc(a->p0);
	if (ret == 0 && a->p0 == 0) {
		ret = malloc(1);
	}
	a->r1 = ret;
	_cgo_tsan_release();
}
`

func (p *Package) cPrologGccgo() string {
	r := strings.NewReplacer(
		"PREFIX", cPrefix,
		"GCCGOSYMBOLPREF", p.gccgoSymbolPrefix(),
		"_cgoCheckPointer", gccgoToSymbol("_cgoCheckPointer"),
		"_cgoCheckResult", gccgoToSymbol("_cgoCheckResult"))
	return r.Replace(cPrologGccgo)
}

const cPrologGccgo = `
#line 1 "cgo-c-prolog-gccgo"
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

typedef unsigned char byte;
typedef intptr_t intgo;

struct __go_string {
	const unsigned char *__data;
	intgo __length;
};

typedef struct __go_open_array {
	void* __values;
	intgo __count;
	intgo __capacity;
} Slice;

struct __go_string __go_byte_array_to_string(const void* p, intgo len);
struct __go_open_array __go_string_to_byte_array (struct __go_string str);

extern void runtime_throw(const char *);

const char *_cgoPREFIX_Cfunc_CString(struct __go_string s) {
	char *p = malloc(s.__length+1);
	if(p == NULL)
		runtime_throw("runtime: C malloc failed");
	memmove(p, s.__data, s.__length);
	p[s.__length] = 0;
	return p;
}

void *_cgoPREFIX_Cfunc_CBytes(struct __go_open_array b) {
	char *p = malloc(b.__count);
	if(p == NULL)
		runtime_throw("runtime: C malloc failed");
	memmove(p, b.__values, b.__count);
	return p;
}

struct __go_string _cgoPREFIX_Cfunc_GoString(char *p) {
	intgo len = (p != NULL) ? strlen(p) : 0;
	return __go_byte_array_to_string(p, len);
}

struct __go_string _cgoPREFIX_Cfunc_GoStringN(char *p, int32_t n) {
	return __go_byte_array_to_string(p, n);
}

Slice _cgoPREFIX_Cfunc_GoBytes(char *p, int32_t n) {
	struct __go_string s = { (const unsigned char *)p, n };
	return __go_string_to_byte_array(s);
}

void *_cgoPREFIX_Cfunc__CMalloc(size_t n) {
	void *p = malloc(n);
	if(p == NULL && n == 0)
		p = malloc(1);
	if(p == NULL)
		runtime_throw("runtime: C malloc failed");
	return p;
}

struct __go_type_descriptor;
typedef struct __go_empty_interface {
	const struct __go_type_descriptor *__type_descriptor;
	void *__object;
} Eface;

extern void runtimeCgoCheckPointer(Eface, Eface)
	__asm__("runtime.cgoCheckPointer")
	__attribute__((weak));

extern void localCgoCheckPointer(Eface, Eface)
	__asm__("GCCGOSYMBOLPREF._cgoCheckPointer");

void localCgoCheckPointer(Eface ptr, Eface arg) {
	if(runtimeCgoCheckPointer) {
		runtimeCgoCheckPointer(ptr, arg);
	}
}

extern void runtimeCgoCheckResult(Eface)
	__asm__("runtime.cgoCheckResult")
	__attribute__((weak));

extern void localCgoCheckResult(Eface)
	__asm__("GCCGOSYMBOLPREF._cgoCheckResult");

void localCgoCheckResult(Eface val) {
	if(runtimeCgoCheckResult) {
		runtimeCgoCheckResult(val);
	}
}
`

// builtinExportProlog is a shorter version of builtinProlog,
// to be put into the _cgo_export.h file.
// For historical reasons we can't use builtinProlog in _cgo_export.h,
// because _cgo_export.h defines GoString as a struct while builtinProlog
// defines it as a function. We don't change this to avoid unnecessarily
// breaking existing code.
// The test of GO_CGO_GOSTRING_TYPEDEF avoids a duplicate definition
// error if a Go file with a cgo comment #include's the export header
// generated by a different package.
const builtinExportProlog = `
#line 1 "cgo-builtin-export-prolog"

#include <stddef.h>

#ifndef GO_CGO_EXPORT_PROLOGUE_H
#define GO_CGO_EXPORT_PROLOGUE_H

#ifndef GO_CGO_GOSTRING_TYPEDEF
typedef struct { const char *p; ptrdiff_t n; } _GoString_;
#endif

#endif
`

func (p *Package) gccExportHeaderProlog() string {
	return strings.Replace(gccExportHeaderProlog, "GOINTBITS", fmt.Sprint(8*p.IntSize), -1)
}

// gccExportHeaderProlog is written to the exported header, after the
// import "C" comment preamble but before the generated declarations
// of exported functions. This permits the generated declarations to
// use the type names that appear in goTypes, above.
//
// The test of GO_CGO_GOSTRING_TYPEDEF avoids a duplicate definition
// error if a Go file with a cgo comment #include's the export header
// generated by a different package. Unfortunately GoString means two
// different things: in this prolog it means a C name for the Go type,
// while in the prolog written into the start of the C code generated
// from a cgo-using Go file it means the C.GoString function. There is
// no way to resolve this conflict, but it also doesn't make much
// difference, as Go code never wants to refer to the latter meaning.
const gccExportHeaderProlog = `
/* Start of boilerplate cgo prologue.  */
#line 1 "cgo-gcc-export-header-prolog"

#ifndef GO_CGO_PROLOGUE_H
#define GO_CGO_PROLOGUE_H

typedef signed char GoInt8;
typedef unsigned char GoUint8;
typedef short GoInt16;
typedef unsigned short GoUint16;
typedef int GoInt32;
typedef unsigned int GoUint32;
typedef long long GoInt64;
typedef unsigned long long GoUint64;
typedef GoIntGOINTBITS GoInt;
typedef GoUintGOINTBITS GoUint;
typedef size_t GoUintptr;
typedef float GoFloat32;
typedef double GoFloat64;
#ifdef _MSC_VER
#include <complex.h>
typedef _Fcomplex GoComplex64;
typedef _Dcomplex GoComplex128;
#else
typedef float _Complex GoComplex64;
typedef double _Complex GoComplex128;
#endif

/*
  static assertion to make sure the file is being used on architecture
  at least with matching size of GoInt.
*/
typedef char _check_for_GOINTBITS_bit_pointer_matching_GoInt[sizeof(void*)==GOINTBITS/8 ? 1:-1];

#ifndef GO_CGO_GOSTRING_TYPEDEF
typedef _GoString_ GoString;
#endif
typedef void *GoMap;
typedef void *GoChan;
typedef struct { void *t; void *v; } GoInterface;
typedef struct { void *data; GoInt len; GoInt cap; } GoSlice;

#endif

/* End of boilerplate cgo prologue.  */

#ifdef __cplusplus
extern "C" {
#endif
`

// gccExportHeaderEpilog goes at the end of the generated header file.
const gccExportHeaderEpilog = `
#ifdef __cplusplus
}
#endif
`

// gccgoExportFileProlog is written to the _cgo_export.c file when
// using gccgo.
// We use weak declarations, and test the addresses, so that this code
// works with older versions of gccgo.
const gccgoExportFileProlog = `
#line 1 "cgo-gccgo-export-file-prolog"
extern _Bool runtime_iscgo __attribute__ ((weak));

static void GoInit(void) __attribute__ ((constructor));
static void GoInit(void) {
	if(&runtime_iscgo)
		runtime_iscgo = 1;
}

extern size_t _cgo_wait_runtime_init_done(void) __attribute__ ((weak));
`
```