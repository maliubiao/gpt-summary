Response:
Let's break down the thought process for analyzing the provided Go code.

**1. Initial Understanding - The Purpose of the File:**

The first line, `// This program is run via "go generate" (via a directive in sort.go)`, immediately tells us this isn't a typical application. It's a code generator. The `//go:build ignore` tag reinforces this, meaning it won't be compiled during a normal `go build`. The filename `gen_sort_variants.go` strongly suggests it generates different versions of sorting algorithms.

**2. Identifying Key Components:**

Scanning the `import` statements reveals standard library packages (`bytes`, `flag`, `fmt`, `go/format`, `log`, `os`, `text/template`). This indicates it reads input (likely a template), manipulates strings, formats code, and writes to files.

The `Variant` struct is crucial. Its fields (`Name`, `Path`, `Package`, `Imports`, `FuncSuffix`, etc.) suggest it defines the characteristics of each generated sorting variant.

The global variables `traditionalVariants`, `genericVariants`, and `expVariants` are arrays of `Variant` structs. This confirms the goal of generating multiple versions. The names themselves hint at the different types of variants being generated (interface-based, function-based, generic with constraints, etc.).

**3. Analyzing the `main` Function:**

The `main` function uses `flag` to parse command-line arguments `-generic` and `-exp`. This controls which set of variants will be generated. The logic is straightforward: check the flags and assign the appropriate `variants` slice. The loop `for i := range variants { generate(&variants[i]) }` indicates that the `generate` function is the core generation logic.

**4. Deconstructing the `generate` Function:**

The `generate` function takes a `Variant` pointer. It uses `text/template` to parse `templateCode` and execute it with the `Variant` data. The `Funcs` field of the `Variant` struct is registered with the template. This is a common pattern for code generation – using templates with dynamic data. The output is then formatted using `go/format` and written to the file specified in `v.Path`.

**5. Examining the `templateCode`:**

This is the heart of the code generation. It's a Go code template. Notice the `{{.Package}}`, `{{.Imports}}`, `{{.FuncSuffix}}`, `{{.DataType}}`, etc. These are template actions that will be replaced with the values from the `Variant` struct. Crucially, the `{{Less ...}}` and `{{Swap ...}}` template functions are used. These correspond to the functions defined in the `Variant.Funcs` map, allowing for different comparison and swapping logic in the generated code.

**6. Inferring Functionality - Connecting the Dots:**

Based on the above observations, the functionality becomes clear:

* **Purpose:** Generate different implementations of sorting algorithms based on a common template.
* **Mechanism:** Uses Go's `text/template` package to fill in a template with variant-specific information.
* **Customization:** The `Variant` struct defines the variations, including data types, function suffixes, comparison logic, and swap logic.
* **Control:** Command-line flags (`-generic`, `-exp`) select which set of variants to generate.
* **Output:** Generates Go source files (`.go`) for each variant.

**7. Reasoning about Go Language Features:**

* **Code Generation:**  This is the primary feature being demonstrated. Go's `go generate` mechanism is explicitly used.
* **Templates:** The `text/template` package is used for dynamic code creation.
* **Conditional Compilation (//go:build ignore):** This tells the compiler to skip this file during normal builds.
* **String Manipulation:**  Used extensively in building the template and formatting the output.
* **Command-line Arguments:**  The `flag` package handles parsing command-line options.

**8. Constructing Examples (Mental Walkthrough):**

Imagine the `traditionalVariants[0]` ("interface") is being processed. The template code will have `{{.Package}}` replaced with "sort", `{{.FuncSuffix}}` with "", `{{.DataType}}` with "Interface", and so on. The `{{Less "data" "j" "j-1"}}` in the `insertionSort` function will be replaced by `data.Less(j, j-1)` because that's what the `Funcs["Less"]` is defined as for this variant.

Similarly, for `genericVariants[0]` ("generic_ordered"), the `{{Less "data" "j" "j-1"}}` will become `cmp.Less(data[j], data[j-1])`. This highlights how the template and the `Variant` data work together.

**9. Identifying Potential Pitfalls:**

The most obvious pitfall is modifying the generated files directly. The "DO NOT EDIT" comment is a strong warning. Changes should be made to the template or the generator code itself. Another potential issue is incorrect configuration of the `Variant` structs, leading to compilation errors in the generated code.

**10. Structuring the Answer:**

Finally, the information is organized into clear sections: Functionality, Go Language Features, Code Example, Command-line Arguments, and Common Mistakes. This provides a comprehensive and easy-to-understand explanation.
这段Go语言代码文件 `gen_sort_variants.go` 的主要功能是**生成多种不同实现的排序算法变体**。它利用 Go 语言的 `go generate` 功能，通过读取一个模板文件 (`templateCode`)，并根据预定义的 `Variant` 结构体中的参数，生成不同的 `.go` 源文件，这些文件包含了特定类型的排序算法实现。

**以下是它的详细功能拆解：**

1. **定义排序算法变体 (`Variant` 结构体):**
   - `Variant` 结构体定义了每个需要生成的排序算法变体的属性，例如：
     - `Name`: 变体的名称（例如 "interface", "generic_ordered"）。
     - `Path`: 生成的代码文件的路径（例如 "zsortinterface.go"）。
     - `Package`: 生成的代码所属的包名（例如 "sort", "slices"）。
     - `Imports`: 生成的代码需要的 import 语句。
     - `FuncSuffix`: 添加到函数名后的后缀，用于区分不同的变体。
     - `DataType`: 排序函数接收的数据类型。
     - `TypeParam`: 排序函数的类型参数（用于泛型）。
     - `ExtraParam`: 额外添加到排序函数参数列表中的参数。
     - `ExtraArg`: 调用其他函数时需要传递的额外参数。
     - `Funcs`: 一个 `template.FuncMap`，定义了在模板中使用的自定义函数，例如 `Less` (比较) 和 `Swap` (交换)。

2. **预定义变体列表:**
   - `traditionalVariants`:  定义了传统的、非泛型的排序变体，例如针对 `sort.Interface` 和 `lessSwap` 函数类型的排序。
   - `genericVariants`: 定义了使用 Go 泛型的排序变体，例如针对实现了 `cmp.Ordered` 接口的类型以及接受比较函数的类型。
   - `expVariants`:  定义了使用 `golang.org/x/exp/constraints` 中定义的约束的排序变体。

3. **处理命令行参数 (`main` 函数):**
   - 使用 `flag` 包解析命令行参数：
     - `-generic`:  如果设置，则生成 `genericVariants` 中定义的泛型排序变体。
     - `-exp`: 如果设置，则生成 `expVariants` 中定义的实验性排序变体。
     - 如果两个参数都没有设置，则默认生成 `traditionalVariants` 中定义的传统排序变体。

4. **生成代码 (`generate` 函数):**
   - 接收一个 `Variant` 结构体的指针作为参数。
   - 使用 `template.New("gen").Funcs(v.Funcs).Parse(templateCode)` 解析 `templateCode` 字符串作为模板，并将 `Variant` 中定义的 `Funcs` 注册到模板中。
   - 使用 `tmpl.Execute(&out, v)` 将 `Variant` 中的数据填充到模板中，生成代码并写入到 `bytes.Buffer` 中。
   - 使用 `format.Source(out.Bytes())` 格式化生成的 Go 代码。
   - 使用 `os.WriteFile(v.Path, formatted, 0644)` 将格式化后的代码写入到 `Variant` 中指定的 `Path` 文件中。

5. **排序算法模板 (`templateCode` 字符串):**
   - 这是一个包含 Go 代码的字符串，其中使用了 `text/template` 的语法。
   - 它定义了一系列通用的排序算法函数，例如 `insertionSort`, `siftDown`, `heapSort`, `pdqsort`, `partition`, `symMerge` 等。
   - 模板中使用了 `{{.Package}}`, `{{.Imports}}`, `{{.FuncSuffix}}`, `{{.DataType}}`, `{{.TypeParam}}`, `{{.ExtraParam}}`, `{{.ExtraArg}}` 等占位符，这些占位符将在代码生成过程中被替换为 `Variant` 结构体中对应的值。
   - 关键的比较和交换操作使用了 `{{Less "data" "i" "j"}}` 和 `{{Swap "data" "i" "j"}}` 模板函数，它们会根据 `Variant` 中 `Funcs` 的定义生成不同的代码。

**推理其实现的 Go 语言功能:**

这个文件主要展示了 Go 语言的以下功能：

* **代码生成 (`go generate`):**  它利用 `go generate` 机制，在编译之前动态生成代码。
* **文本模板 (`text/template`):** 使用 `text/template` 包根据模板和数据生成文本输出（这里是 Go 代码）。
* **命令行参数解析 (`flag`):** 使用 `flag` 包处理命令行参数，允许用户控制生成哪些变体。
* **字符串操作 (`bytes`, `fmt`):**  使用 `bytes.Buffer` 构建字符串，并使用 `fmt.Sprintf` 格式化字符串。
* **代码格式化 (`go/format`):**  使用 `go/format` 包确保生成的代码符合 Go 的代码规范。
* **文件操作 (`os`):** 使用 `os.WriteFile` 将生成的代码写入文件。
* **结构体和切片:** 使用 `struct` 定义数据结构 (`Variant`)，并使用切片存储多个变体。
* **泛型 (在 `genericVariants` 和 `expVariants` 中):**  展示了如何生成使用 Go 泛型的代码。

**Go 代码举例说明 (基于模板和 `Variant`):**

假设我们运行 `go generate -generic`，那么会处理 `genericVariants` 中的第一个变体：

```go
Variant{
    Name:       "generic_ordered",
    Path:       "zsortordered.go",
    Package:    "slices",
    Imports:    "import \"cmp\"\n",
    FuncSuffix: "Ordered",
    TypeParam:  "[E cmp.Ordered]",
    ExtraParam: "",
    ExtraArg:   "",
    DataType:   "[]E",
    Funcs: template.FuncMap{
        "Less": func(name, i, j string) string {
            return fmt.Sprintf("cmp.Less(%s[%s], %s[%s])", name, i, name, j)
        },
        "Swap": func(name, i, j string) string {
            return fmt.Sprintf("%s[%s], %s[%s] = %s[%s], %s[%s]", name, i, name, j, name, j, name, i)
        },
    },
}
```

生成的 `zsortordered.go` 文件的一部分可能如下所示 (基于 `templateCode` 中的 `insertionSort` 函数):

```go
// Code generated by gen_sort_variants.go; DO NOT EDIT.

// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package slices

import "cmp"

// insertionSortOrdered sorts data[a:b] using insertion sort.
func insertionSortOrdered[E cmp.Ordered](data []E, a, b int) {
	for i := a + 1; i < b; i++ {
		for j := i; j > a && cmp.Less(data[j], data[j-1]); j-- {
			data[j], data[j-1] = data[j-1], data[j]
		}
	}
}
```

**假设的输入与输出:**

**输入:**  运行命令 `go generate -generic`

**输出:**  在当前目录下生成一个名为 `zsortordered.go` 的文件，其内容包含了使用泛型的 `insertionSortOrdered` 等排序函数实现。

**命令行参数的具体处理:**

- **`-generic`:**  这是一个布尔类型的标志。如果命令行中出现了 `-generic`，则 `genGeneric` 变量会被设置为 `true`，程序会生成 `genericVariants` 中定义的排序变体。
- **`-exp`:** 也是一个布尔类型的标志。如果命令行中出现了 `-exp`，则 `genExp` 变量会被设置为 `true`，程序会生成 `expVariants` 中定义的排序变体。
- **默认情况:** 如果没有提供任何标志，程序默认生成 `traditionalVariants` 中定义的排序变体。

**使用者易犯错的点:**

使用者最容易犯的错误是**直接修改生成的文件**。  由于这些文件是通过 `go generate` 自动生成的，任何手动修改都会在下一次运行 `go generate` 时被覆盖。

**例如：** 假设开发者手动修改了 `zsortinterface.go` 文件中的某个函数的实现。  然后，当其他开发者或构建系统运行 `go generate` 时，这个文件会被重新生成，之前的手动修改就会丢失。

因此，如果需要修改排序算法的实现，应该**修改 `gen_sort_variants.go` 文件中的 `templateCode` 或者相应的 `Variant` 结构体定义**，然后重新运行 `go generate`。

总结来说，`gen_sort_variants.go` 是一个代码生成工具，它通过模板和预定义的配置，自动化地生成多种不同类型的排序算法实现，这是 Go 语言中一种常见的提高代码复用性和灵活性的方式。

### 提示词
```
这是路径为go/src/sort/gen_sort_variants.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
```

### 源代码
```go
// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build ignore

// This program is run via "go generate" (via a directive in sort.go)
// to generate implementation variants of the underlying sorting algorithm.
// When passed the -generic flag it generates generic variants of sorting;
// otherwise it generates the non-generic variants used by the sort package.

package main

import (
	"bytes"
	"flag"
	"fmt"
	"go/format"
	"log"
	"os"
	"text/template"
)

type Variant struct {
	// Name is the variant name: should be unique among variants.
	Name string

	// Path is the file path into which the generator will emit the code for this
	// variant.
	Path string

	// Package is the package this code will be emitted into.
	Package string

	// Imports is the imports needed for this package.
	Imports string

	// FuncSuffix is appended to all function names in this variant's code. All
	// suffixes should be unique within a package.
	FuncSuffix string

	// DataType is the type of the data parameter of functions in this variant's
	// code.
	DataType string

	// TypeParam is the optional type parameter for the function.
	TypeParam string

	// ExtraParam is an extra parameter to pass to the function. Should begin with
	// ", " to separate from other params.
	ExtraParam string

	// ExtraArg is an extra argument to pass to calls between functions; typically
	// it invokes ExtraParam. Should begin with ", " to separate from other args.
	ExtraArg string

	// Funcs is a map of functions used from within the template. The following
	// functions are expected to exist:
	//
	//    Less (name, i, j):
	//      emits a comparison expression that checks if the value `name` at
	//      index `i` is smaller than at index `j`.
	//
	//    Swap (name, i, j):
	//      emits a statement that performs a data swap between elements `i` and
	//      `j` of the value `name`.
	Funcs template.FuncMap
}

var (
	traditionalVariants = []Variant{
		Variant{
			Name:       "interface",
			Path:       "zsortinterface.go",
			Package:    "sort",
			Imports:    "",
			FuncSuffix: "",
			TypeParam:  "",
			ExtraParam: "",
			ExtraArg:   "",
			DataType:   "Interface",
			Funcs: template.FuncMap{
				"Less": func(name, i, j string) string {
					return fmt.Sprintf("%s.Less(%s, %s)", name, i, j)
				},
				"Swap": func(name, i, j string) string {
					return fmt.Sprintf("%s.Swap(%s, %s)", name, i, j)
				},
			},
		},
		Variant{
			Name:       "func",
			Path:       "zsortfunc.go",
			Package:    "sort",
			Imports:    "",
			FuncSuffix: "_func",
			TypeParam:  "",
			ExtraParam: "",
			ExtraArg:   "",
			DataType:   "lessSwap",
			Funcs: template.FuncMap{
				"Less": func(name, i, j string) string {
					return fmt.Sprintf("%s.Less(%s, %s)", name, i, j)
				},
				"Swap": func(name, i, j string) string {
					return fmt.Sprintf("%s.Swap(%s, %s)", name, i, j)
				},
			},
		},
	}

	genericVariants = []Variant{
		Variant{
			Name:       "generic_ordered",
			Path:       "zsortordered.go",
			Package:    "slices",
			Imports:    "import \"cmp\"\n",
			FuncSuffix: "Ordered",
			TypeParam:  "[E cmp.Ordered]",
			ExtraParam: "",
			ExtraArg:   "",
			DataType:   "[]E",
			Funcs: template.FuncMap{
				"Less": func(name, i, j string) string {
					return fmt.Sprintf("cmp.Less(%s[%s], %s[%s])", name, i, name, j)
				},
				"Swap": func(name, i, j string) string {
					return fmt.Sprintf("%s[%s], %s[%s] = %s[%s], %s[%s]", name, i, name, j, name, j, name, i)
				},
			},
		},
		Variant{
			Name:       "generic_func",
			Path:       "zsortanyfunc.go",
			Package:    "slices",
			FuncSuffix: "CmpFunc",
			TypeParam:  "[E any]",
			ExtraParam: ", cmp func(a, b E) int",
			ExtraArg:   ", cmp",
			DataType:   "[]E",
			Funcs: template.FuncMap{
				"Less": func(name, i, j string) string {
					return fmt.Sprintf("(cmp(%s[%s], %s[%s]) < 0)", name, i, name, j)
				},
				"Swap": func(name, i, j string) string {
					return fmt.Sprintf("%s[%s], %s[%s] = %s[%s], %s[%s]", name, i, name, j, name, j, name, i)
				},
			},
		},
	}

	expVariants = []Variant{
		Variant{
			Name:       "exp_ordered",
			Path:       "zsortordered.go",
			Package:    "slices",
			Imports:    "import \"golang.org/x/exp/constraints\"\n",
			FuncSuffix: "Ordered",
			TypeParam:  "[E constraints.Ordered]",
			ExtraParam: "",
			ExtraArg:   "",
			DataType:   "[]E",
			Funcs: template.FuncMap{
				"Less": func(name, i, j string) string {
					return fmt.Sprintf("cmpLess(%s[%s], %s[%s])", name, i, name, j)
				},
				"Swap": func(name, i, j string) string {
					return fmt.Sprintf("%s[%s], %s[%s] = %s[%s], %s[%s]", name, i, name, j, name, j, name, i)
				},
			},
		},
		Variant{
			Name:       "exp_func",
			Path:       "zsortanyfunc.go",
			Package:    "slices",
			FuncSuffix: "CmpFunc",
			TypeParam:  "[E any]",
			ExtraParam: ", cmp func(a, b E) int",
			ExtraArg:   ", cmp",
			DataType:   "[]E",
			Funcs: template.FuncMap{
				"Less": func(name, i, j string) string {
					return fmt.Sprintf("(cmp(%s[%s], %s[%s]) < 0)", name, i, name, j)
				},
				"Swap": func(name, i, j string) string {
					return fmt.Sprintf("%s[%s], %s[%s] = %s[%s], %s[%s]", name, i, name, j, name, j, name, i)
				},
			},
		},
	}
)

func main() {
	genGeneric := flag.Bool("generic", false, "generate generic versions")
	genExp := flag.Bool("exp", false, "generate x/exp/slices versions")
	flag.Parse()

	var variants []Variant
	if *genExp {
		variants = expVariants
	} else if *genGeneric {
		variants = genericVariants
	} else {
		variants = traditionalVariants
	}
	for i := range variants {
		generate(&variants[i])
	}
}

// generate generates the code for variant `v` into a file named by `v.Path`.
func generate(v *Variant) {
	// Parse templateCode anew for each variant because Parse requires Funcs to be
	// registered, and it helps type-check the funcs.
	tmpl, err := template.New("gen").Funcs(v.Funcs).Parse(templateCode)
	if err != nil {
		log.Fatal("template Parse:", err)
	}

	var out bytes.Buffer
	err = tmpl.Execute(&out, v)
	if err != nil {
		log.Fatal("template Execute:", err)
	}

	formatted, err := format.Source(out.Bytes())
	if err != nil {
		log.Fatal("format:", err)
	}

	if err := os.WriteFile(v.Path, formatted, 0644); err != nil {
		log.Fatal("WriteFile:", err)
	}
}

var templateCode = `// Code generated by gen_sort_variants.go; DO NOT EDIT.

// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package {{.Package}}

{{.Imports}}

// insertionSort{{.FuncSuffix}} sorts data[a:b] using insertion sort.
func insertionSort{{.FuncSuffix}}{{.TypeParam}}(data {{.DataType}}, a, b int {{.ExtraParam}}) {
	for i := a + 1; i < b; i++ {
		for j := i; j > a && {{Less "data" "j" "j-1"}}; j-- {
			{{Swap "data" "j" "j-1"}}
		}
	}
}

// siftDown{{.FuncSuffix}} implements the heap property on data[lo:hi].
// first is an offset into the array where the root of the heap lies.
func siftDown{{.FuncSuffix}}{{.TypeParam}}(data {{.DataType}}, lo, hi, first int {{.ExtraParam}}) {
	root := lo
	for {
		child := 2*root + 1
		if child >= hi {
			break
		}
		if child+1 < hi && {{Less "data" "first+child" "first+child+1"}} {
			child++
		}
		if !{{Less "data" "first+root" "first+child"}} {
			return
		}
		{{Swap "data" "first+root" "first+child"}}
		root = child
	}
}

func heapSort{{.FuncSuffix}}{{.TypeParam}}(data {{.DataType}}, a, b int {{.ExtraParam}}) {
	first := a
	lo := 0
	hi := b - a

	// Build heap with greatest element at top.
	for i := (hi - 1) / 2; i >= 0; i-- {
		siftDown{{.FuncSuffix}}(data, i, hi, first {{.ExtraArg}})
	}

	// Pop elements, largest first, into end of data.
	for i := hi - 1; i >= 0; i-- {
		{{Swap "data" "first" "first+i"}}
		siftDown{{.FuncSuffix}}(data, lo, i, first {{.ExtraArg}})
	}
}

// pdqsort{{.FuncSuffix}} sorts data[a:b].
// The algorithm based on pattern-defeating quicksort(pdqsort), but without the optimizations from BlockQuicksort.
// pdqsort paper: https://arxiv.org/pdf/2106.05123.pdf
// C++ implementation: https://github.com/orlp/pdqsort
// Rust implementation: https://docs.rs/pdqsort/latest/pdqsort/
// limit is the number of allowed bad (very unbalanced) pivots before falling back to heapsort.
func pdqsort{{.FuncSuffix}}{{.TypeParam}}(data {{.DataType}}, a, b, limit int {{.ExtraParam}}) {
	const maxInsertion = 12

	var (
		wasBalanced    = true // whether the last partitioning was reasonably balanced
		wasPartitioned = true // whether the slice was already partitioned
	)

	for {
		length := b - a

		if length <= maxInsertion {
			insertionSort{{.FuncSuffix}}(data, a, b {{.ExtraArg}})
			return
		}

		// Fall back to heapsort if too many bad choices were made.
		if limit == 0 {
			heapSort{{.FuncSuffix}}(data, a, b {{.ExtraArg}})
			return
		}

		// If the last partitioning was imbalanced, we need to breaking patterns.
		if !wasBalanced {
			breakPatterns{{.FuncSuffix}}(data, a, b {{.ExtraArg}})
			limit--
		}

		pivot, hint := choosePivot{{.FuncSuffix}}(data, a, b {{.ExtraArg}})
		if hint == decreasingHint {
			reverseRange{{.FuncSuffix}}(data, a, b {{.ExtraArg}})
			// The chosen pivot was pivot-a elements after the start of the array.
			// After reversing it is pivot-a elements before the end of the array.
			// The idea came from Rust's implementation.
			pivot = (b - 1) - (pivot - a)
			hint = increasingHint
		}

		// The slice is likely already sorted.
		if wasBalanced && wasPartitioned && hint == increasingHint {
			if partialInsertionSort{{.FuncSuffix}}(data, a, b {{.ExtraArg}}) {
				return
			}
		}

		// Probably the slice contains many duplicate elements, partition the slice into
		// elements equal to and elements greater than the pivot.
		if a > 0 && !{{Less "data" "a-1" "pivot"}} {
			mid := partitionEqual{{.FuncSuffix}}(data, a, b, pivot {{.ExtraArg}})
			a = mid
			continue
		}

		mid, alreadyPartitioned := partition{{.FuncSuffix}}(data, a, b, pivot {{.ExtraArg}})
		wasPartitioned = alreadyPartitioned

		leftLen, rightLen := mid-a, b-mid
		balanceThreshold := length / 8
		if leftLen < rightLen {
			wasBalanced = leftLen >= balanceThreshold
			pdqsort{{.FuncSuffix}}(data, a, mid, limit {{.ExtraArg}})
			a = mid + 1
		} else {
			wasBalanced = rightLen >= balanceThreshold
			pdqsort{{.FuncSuffix}}(data, mid+1, b, limit {{.ExtraArg}})
			b = mid
		}
	}
}

// partition{{.FuncSuffix}} does one quicksort partition.
// Let p = data[pivot]
// Moves elements in data[a:b] around, so that data[i]<p and data[j]>=p for i<newpivot and j>newpivot.
// On return, data[newpivot] = p
func partition{{.FuncSuffix}}{{.TypeParam}}(data {{.DataType}}, a, b, pivot int {{.ExtraParam}}) (newpivot int, alreadyPartitioned bool) {
	{{Swap "data" "a" "pivot"}}
	i, j := a+1, b-1 // i and j are inclusive of the elements remaining to be partitioned

	for i <= j && {{Less "data" "i" "a"}} {
		i++
	}
	for i <= j && !{{Less "data" "j" "a"}} {
		j--
	}
	if i > j {
		{{Swap "data" "j" "a"}}
		return j, true
	}
	{{Swap "data" "i" "j"}}
	i++
	j--

	for {
		for i <= j && {{Less "data" "i" "a"}} {
			i++
		}
		for i <= j && !{{Less "data" "j" "a"}} {
			j--
		}
		if i > j {
			break
		}
		{{Swap "data" "i" "j"}}
		i++
		j--
	}
	{{Swap "data" "j" "a"}}
	return j, false
}

// partitionEqual{{.FuncSuffix}} partitions data[a:b] into elements equal to data[pivot] followed by elements greater than data[pivot].
// It assumed that data[a:b] does not contain elements smaller than the data[pivot].
func partitionEqual{{.FuncSuffix}}{{.TypeParam}}(data {{.DataType}}, a, b, pivot int {{.ExtraParam}}) (newpivot int) {
	{{Swap "data" "a" "pivot"}}
	i, j := a+1, b-1 // i and j are inclusive of the elements remaining to be partitioned

	for {
		for i <= j && !{{Less "data" "a" "i"}} {
			i++
		}
		for i <= j && {{Less "data" "a" "j"}} {
			j--
		}
		if i > j {
			break
		}
		{{Swap "data" "i" "j"}}
		i++
		j--
	}
	return i
}

// partialInsertionSort{{.FuncSuffix}} partially sorts a slice, returns true if the slice is sorted at the end.
func partialInsertionSort{{.FuncSuffix}}{{.TypeParam}}(data {{.DataType}}, a, b int {{.ExtraParam}}) bool {
	const (
		maxSteps         = 5  // maximum number of adjacent out-of-order pairs that will get shifted
		shortestShifting = 50 // don't shift any elements on short arrays
	)
	i := a + 1
	for j := 0; j < maxSteps; j++ {
		for i < b && !{{Less "data" "i" "i-1"}} {
			i++
		}

		if i == b {
			return true
		}

		if b-a < shortestShifting {
			return false
		}

		{{Swap "data" "i" "i-1"}}

		// Shift the smaller one to the left.
		if i-a >= 2 {
			for j := i - 1; j >= 1; j-- {
				if !{{Less "data" "j" "j-1"}} {
					break
				}
				{{Swap "data" "j" "j-1"}}
			}
		}
		// Shift the greater one to the right.
		if b-i >= 2 {
			for j := i + 1; j < b; j++ {
				if !{{Less "data" "j" "j-1"}} {
					break
				}
				{{Swap "data" "j" "j-1"}}
			}
		}
	}
	return false
}

// breakPatterns{{.FuncSuffix}} scatters some elements around in an attempt to break some patterns
// that might cause imbalanced partitions in quicksort.
func breakPatterns{{.FuncSuffix}}{{.TypeParam}}(data {{.DataType}}, a, b int {{.ExtraParam}}) {
	length := b - a
	if length >= 8 {
		random := xorshift(length)
		modulus := nextPowerOfTwo(length)

		for idx := a + (length/4)*2 - 1; idx <= a + (length/4)*2 + 1; idx++ {
			other := int(uint(random.Next()) & (modulus - 1))
			if other >= length {
				other -= length
			}
			{{Swap "data" "idx" "a+other"}}
		}
	}
}

// choosePivot{{.FuncSuffix}} chooses a pivot in data[a:b].
//
// [0,8): chooses a static pivot.
// [8,shortestNinther): uses the simple median-of-three method.
// [shortestNinther,∞): uses the Tukey ninther method.
func choosePivot{{.FuncSuffix}}{{.TypeParam}}(data {{.DataType}}, a, b int {{.ExtraParam}}) (pivot int, hint sortedHint) {
	const (
		shortestNinther = 50
		maxSwaps        = 4 * 3
	)

	l := b - a

	var (
		swaps int
		i     = a + l/4*1
		j     = a + l/4*2
		k     = a + l/4*3
	)

	if l >= 8 {
		if l >= shortestNinther {
			// Tukey ninther method, the idea came from Rust's implementation.
			i = medianAdjacent{{.FuncSuffix}}(data, i, &swaps {{.ExtraArg}})
			j = medianAdjacent{{.FuncSuffix}}(data, j, &swaps {{.ExtraArg}})
			k = medianAdjacent{{.FuncSuffix}}(data, k, &swaps {{.ExtraArg}})
		}
		// Find the median among i, j, k and stores it into j.
		j = median{{.FuncSuffix}}(data, i, j, k, &swaps {{.ExtraArg}})
	}

	switch swaps {
	case 0:
		return j, increasingHint
	case maxSwaps:
		return j, decreasingHint
	default:
		return j, unknownHint
	}
}

// order2{{.FuncSuffix}} returns x,y where data[x] <= data[y], where x,y=a,b or x,y=b,a.
func order2{{.FuncSuffix}}{{.TypeParam}}(data {{.DataType}}, a, b int, swaps *int {{.ExtraParam}}) (int, int) {
	if {{Less "data" "b" "a"}} {
		*swaps++
		return b, a
	}
	return a, b
}

// median{{.FuncSuffix}} returns x where data[x] is the median of data[a],data[b],data[c], where x is a, b, or c.
func median{{.FuncSuffix}}{{.TypeParam}}(data {{.DataType}}, a, b, c int, swaps *int {{.ExtraParam}}) int {
	a, b = order2{{.FuncSuffix}}(data, a, b, swaps {{.ExtraArg}})
	b, c = order2{{.FuncSuffix}}(data, b, c, swaps {{.ExtraArg}})
	a, b = order2{{.FuncSuffix}}(data, a, b, swaps {{.ExtraArg}})
	return b
}

// medianAdjacent{{.FuncSuffix}} finds the median of data[a - 1], data[a], data[a + 1] and stores the index into a.
func medianAdjacent{{.FuncSuffix}}{{.TypeParam}}(data {{.DataType}}, a int, swaps *int {{.ExtraParam}}) int {
	return median{{.FuncSuffix}}(data, a-1, a, a+1, swaps {{.ExtraArg}})
}

func reverseRange{{.FuncSuffix}}{{.TypeParam}}(data {{.DataType}}, a, b int {{.ExtraParam}}) {
	i := a
	j := b - 1
	for i < j {
		{{Swap "data" "i" "j"}}
		i++
		j--
	}
}

func swapRange{{.FuncSuffix}}{{.TypeParam}}(data {{.DataType}}, a, b, n int {{.ExtraParam}}) {
	for i := 0; i < n; i++ {
		{{Swap "data" "a+i" "b+i"}}
	}
}

func stable{{.FuncSuffix}}{{.TypeParam}}(data {{.DataType}}, n int {{.ExtraParam}}) {
	blockSize := 20 // must be > 0
	a, b := 0, blockSize
	for b <= n {
		insertionSort{{.FuncSuffix}}(data, a, b {{.ExtraArg}})
		a = b
		b += blockSize
	}
	insertionSort{{.FuncSuffix}}(data, a, n {{.ExtraArg}})

	for blockSize < n {
		a, b = 0, 2*blockSize
		for b <= n {
			symMerge{{.FuncSuffix}}(data, a, a+blockSize, b {{.ExtraArg}})
			a = b
			b += 2 * blockSize
		}
		if m := a + blockSize; m < n {
			symMerge{{.FuncSuffix}}(data, a, m, n {{.ExtraArg}})
		}
		blockSize *= 2
	}
}

// symMerge{{.FuncSuffix}} merges the two sorted subsequences data[a:m] and data[m:b] using
// the SymMerge algorithm from Pok-Son Kim and Arne Kutzner, "Stable Minimum
// Storage Merging by Symmetric Comparisons", in Susanne Albers and Tomasz
// Radzik, editors, Algorithms - ESA 2004, volume 3221 of Lecture Notes in
// Computer Science, pages 714-723. Springer, 2004.
//
// Let M = m-a and N = b-n. Wolog M < N.
// The recursion depth is bound by ceil(log(N+M)).
// The algorithm needs O(M*log(N/M + 1)) calls to data.Less.
// The algorithm needs O((M+N)*log(M)) calls to data.Swap.
//
// The paper gives O((M+N)*log(M)) as the number of assignments assuming a
// rotation algorithm which uses O(M+N+gcd(M+N)) assignments. The argumentation
// in the paper carries through for Swap operations, especially as the block
// swapping rotate uses only O(M+N) Swaps.
//
// symMerge assumes non-degenerate arguments: a < m && m < b.
// Having the caller check this condition eliminates many leaf recursion calls,
// which improves performance.
func symMerge{{.FuncSuffix}}{{.TypeParam}}(data {{.DataType}}, a, m, b int {{.ExtraParam}}) {
	// Avoid unnecessary recursions of symMerge
	// by direct insertion of data[a] into data[m:b]
	// if data[a:m] only contains one element.
	if m-a == 1 {
		// Use binary search to find the lowest index i
		// such that data[i] >= data[a] for m <= i < b.
		// Exit the search loop with i == b in case no such index exists.
		i := m
		j := b
		for i < j {
			h := int(uint(i+j) >> 1)
			if {{Less "data" "h" "a"}} {
				i = h + 1
			} else {
				j = h
			}
		}
		// Swap values until data[a] reaches the position before i.
		for k := a; k < i-1; k++ {
			{{Swap "data" "k" "k+1"}}
		}
		return
	}

	// Avoid unnecessary recursions of symMerge
	// by direct insertion of data[m] into data[a:m]
	// if data[m:b] only contains one element.
	if b-m == 1 {
		// Use binary search to find the lowest index i
		// such that data[i] > data[m] for a <= i < m.
		// Exit the search loop with i == m in case no such index exists.
		i := a
		j := m
		for i < j {
			h := int(uint(i+j) >> 1)
			if !{{Less "data" "m" "h"}} {
				i = h + 1
			} else {
				j = h
			}
		}
		// Swap values until data[m] reaches the position i.
		for k := m; k > i; k-- {
			{{Swap "data" "k" "k-1"}}
		}
		return
	}

	mid := int(uint(a+b) >> 1)
	n := mid + m
	var start, r int
	if m > mid {
		start = n - b
		r = mid
	} else {
		start = a
		r = m
	}
	p := n - 1

	for start < r {
		c := int(uint(start+r) >> 1)
		if !{{Less "data" "p-c" "c"}} {
			start = c + 1
		} else {
			r = c
		}
	}

	end := n - start
	if start < m && m < end {
		rotate{{.FuncSuffix}}(data, start, m, end {{.ExtraArg}})
	}
	if a < start && start < mid {
		symMerge{{.FuncSuffix}}(data, a, start, mid {{.ExtraArg}})
	}
	if mid < end && end < b {
		symMerge{{.FuncSuffix}}(data, mid, end, b {{.ExtraArg}})
	}
}

// rotate{{.FuncSuffix}} rotates two consecutive blocks u = data[a:m] and v = data[m:b] in data:
// Data of the form 'x u v y' is changed to 'x v u y'.
// rotate performs at most b-a many calls to data.Swap,
// and it assumes non-degenerate arguments: a < m && m < b.
func rotate{{.FuncSuffix}}{{.TypeParam}}(data {{.DataType}}, a, m, b int {{.ExtraParam}}) {
	i := m - a
	j := b - m

	for i != j {
		if i > j {
			swapRange{{.FuncSuffix}}(data, m-i, m, j {{.ExtraArg}})
			i -= j
		} else {
			swapRange{{.FuncSuffix}}(data, m-i, m+j-i, i {{.ExtraArg}})
			j -= i
		}
	}
	// i == j
	swapRange{{.FuncSuffix}}(data, m-i, m, i {{.ExtraArg}})
}
`
```