Response: Let's break down the thought process for analyzing this Go code snippet.

1. **Understand the Request:** The request asks for the functionality of the `size.go` file, aiming to identify the Go language features it supports. It also specifies a need for code examples, explanations of command-line arguments (if applicable), and common pitfalls.

2. **Initial Scan for Keywords and Concepts:**  A quick scan reveals terms like `PtrSize`, `RegSize`, `Slice`, `String`, `MaxWidth`, `CalcSize`, `RoundUp`, `interface`, `struct`, `array`, `chan`, `map`, and `func`. These immediately hint at memory layout, size calculations, and handling of fundamental Go data structures. The presence of `cmd/compile/internal` in the path strongly suggests this code is part of the Go compiler.

3. **Identify Key Variables:**  The global variables `PtrSize` and `RegSize` are fundamental. The comments explain their roles – pointer and register size, crucial for memory layout. The `Slice*Offset` and `SliceSize`/`StringSize` variables further reinforce the focus on the internal representation of these types.

4. **Analyze Key Functions:**
    * **`RoundUp`:** This is a straightforward utility function for alignment. The comment clearly explains its purpose.
    * **`expandiface`:** The name and comments clearly indicate its role in processing interfaces, specifically handling embedded interfaces and method sets.
    * **`calcStructOffset`:**  This function is clearly responsible for calculating the memory layout of struct fields, considering alignment and potential size limits. The comment about `not-in-heap` is a crucial detail.
    * **`CalcSize`:** This is the core function. Its purpose is to determine the size, alignment, equality/hashing algorithm, and pointer data size of a Go type. The switch statement based on `et := t.Kind()` is a strong indicator that it handles different Go type categories. The `CalcSizeDisabled` variable suggests a mechanism for controlling size calculations, potentially for optimization or debugging.
    * **`CalcStructSize`:**  This is a specialized version of `CalcSize` for struct types, considering field alignment and padding.
    * **`CheckSize`, `DeferCheckSize`, `ResumeCheckSize`:** This trio of functions deals with deferred size calculations, which is necessary for handling recursive types and import dependencies.
    * **`PtrDataSize`:** This function determines the portion of a type that contains pointer data.

5. **Connect Functions to Go Language Features:**
    * **Slices and Strings:** The `Slice*Offset`, `SliceSize`, and `StringSize` variables directly correspond to the internal structure of slices and strings in Go.
    * **Interfaces:** `expandiface` handles the dynamic dispatch mechanism of interfaces by building the method set.
    * **Structs:** `calcStructOffset` and `CalcStructSize` manage the memory layout of structs, considering field order and alignment. The `not-in-heap` comment is a specific optimization related to escape analysis.
    * **Arrays:** `CalcSize` handles array sizing, including checks for exceeding address space limits.
    * **Channels:** `CalcSize` considers the size of the element type when sizing channels.
    * **Maps:** `CalcSize` marks maps as having no direct equality comparison (`ANOEQ`).
    * **Pointers:** `CalcSize` correctly determines the size of pointers (`PtrSize`).
    * **Functions:** `CalcSize` calculates the size of function types (which is a pointer) and uses `TFUNCARGS` to determine the layout of function arguments and return values.
    * **Alignment:** The `RoundUp` function and the logic within `calcStructOffset` and `CalcStructSize` directly address memory alignment requirements.

6. **Infer Missing Information and Formulate Examples:** Based on the identified functions and their purposes, formulate Go code examples that demonstrate these concepts. For instance, the slice and string variables lead directly to examples of their memory layout. The struct functions suggest examples with different field types and their alignment. The interface functions imply examples with embedding.

7. **Address Specific Requirements:**
    * **Command-Line Arguments:**  A close reading reveals no direct handling of command-line arguments *within this specific file*. The global variables like `PtrSize` are likely set elsewhere (as mentioned in the comments regarding `gc.Main`). It's important to note the *absence* of something.
    * **Common Pitfalls:**  Think about common mistakes related to memory layout and type sizes. For example, assuming a struct's size is simply the sum of its field sizes without considering alignment is a common error. Another pitfall is misunderstanding the internal structure of slices or interfaces.

8. **Refine and Organize:** Structure the answer logically, starting with a high-level summary of the file's purpose, then diving into details for each function/concept. Provide clear explanations and link the code snippets back to the identified functionalities.

9. **Self-Correction/Review:**  Review the generated answer against the original code and the request. Are all the major functionalities covered? Are the examples accurate and relevant? Is the explanation clear and concise?  For example, initially, I might focus heavily on just size calculation. A review would remind me to also cover alignment, interface handling, and the deferred calculation mechanism. I would also double-check the examples to ensure they are syntactically correct and illustrate the intended point. Ensuring the "no command-line arguments" observation is explicitly stated is also important.

This iterative process of scanning, analyzing, connecting, inferring, and refining is crucial for understanding and explaining complex code like this.
这段Go语言代码文件 `size.go` 是 Go 编译器 `cmd/compile` 中 `internal/types` 包的一部分，主要负责计算和管理 Go 语言中各种类型的大小、对齐方式以及其他与内存布局相关的属性。它在编译过程中起着至关重要的作用，确保程序在运行时能够正确地访问和操作内存。

以下是它的主要功能：

1. **定义和管理全局的尺寸和偏移量信息：**
   - `PtrSize`: 指针的大小（通常是 4 字节或 8 字节，取决于目标架构）。
   - `RegSize`: 通用寄存器的大小。
   - `SlicePtrOffset`, `SliceLenOffset`, `SliceCapOffset`: 切片结构体中指针、长度和容量字段的偏移量。
   - `SliceSize`: 切片结构体的大小。
   - `StringSize`: 字符串结构体的大小。
   - `MaxWidth`: 目标架构上值的最大大小。

2. **提供计算类型大小和对齐方式的核心功能：**
   - `CalcSize(t *Type)`:  这是核心函数，用于计算给定类型 `t` 的大小（`width`）、对齐方式（`align`）、相等性/哈希算法（`alg`）以及包含指针数据的字节数（`ptrBytes`）。它会根据类型的不同进行不同的计算，例如：
     - **基本类型 (int, float, bool 等):** 直接返回其固定大小和对齐方式。
     - **指针类型 (`*T`):** 大小为 `PtrSize`，对齐方式为 `PtrSize`。
     - **切片类型 (`[]T`):** 大小为 `SliceSize`，对齐方式为 `PtrSize`。
     - **字符串类型 (`string`):** 大小为 `StringSize`，对齐方式为 `PtrSize`。
     - **数组类型 (`[n]T`):** 大小为 `n * sizeof(T)`，对齐方式与元素类型 `T` 相同。
     - **结构体类型 (`struct { ... }`):** 通过 `CalcStructSize` 计算，考虑字段的顺序和对齐要求。
     - **接口类型 (`interface { ... }`):** 大小为 `2 * PtrSize`（一个指向类型信息的指针，一个指向数据的指针），对齐方式为 `PtrSize`。
     - **通道类型 (`chan T`):** 大小为 `PtrSize`（通道本身是指针），需要计算元素类型的大小。
     - **Map 类型 (`map[K]V`):** 大小为 `PtrSize`（map 本身是指针），需要计算键和值类型的大小。
     - **函数类型 (`func(...)`)**: 大小为 `PtrSize` (函数也是指针)。
   - `CalcStructSize(t *Type)`: 专门用于计算结构体类型的大小和对齐方式。它会遍历结构体的字段，并根据每个字段的类型和对齐要求来计算整个结构体的大小，并考虑内存对齐。
   - `RoundUp(o int64, r int64)`: 一个辅助函数，用于将 `o` 向上舍入到 `r` 的倍数，其中 `r` 是 2 的幂。这用于实现内存对齐。

3. **处理接口类型的展开：**
   - `expandiface(t *Type)`:  用于展开接口类型 `t` 的方法集，包括嵌入的接口。它会收集接口的所有方法，并进行排序和去重，最终设置到接口类型的 `AllMethods` 字段中。

4. **处理递归类型的大小计算：**
   - `CheckSize(t *Type)`: 检查类型 `t` 的大小是否已计算，如果未计算则调用 `CalcSize`。为了处理递归类型（例如 `type T *struct{ next T }`），它使用了 `defercalc` 和 `deferredTypeStack` 来延迟计算，避免无限递归。
   - `DeferCheckSize()`: 递增 `defercalc` 计数器，表示需要延迟大小计算。
   - `ResumeCheckSize()`: 递减 `defercalc` 计数器。当计数器回到 0 时，会执行所有被延迟的 `CalcSize` 调用。

5. **计算包含指针数据的字节数：**
   - `PtrDataSize(t *Type)`: 返回类型 `t` 中包含指针数据的字节长度。这对于垃圾回收器了解哪些内存区域包含指针非常重要。

**Go 语言功能实现示例：**

**1. 计算结构体的大小和对齐：**

```go
package main

import (
	"fmt"
	"unsafe"
)

type MyStruct struct {
	A int32
	B string
	C bool
}

func main() {
	var s MyStruct
	fmt.Println("Size of MyStruct:", unsafe.Sizeof(s))        // 输出 MyStruct 的大小
	fmt.Println("Align of MyStruct.A:", unsafe.Alignof(s.A)) // 输出 A 字段的对齐方式
	fmt.Println("Align of MyStruct.B:", unsafe.Alignof(s.B)) // 输出 B 字段的对齐方式
	fmt.Println("Align of MyStruct.C:", unsafe.Alignof(s.C)) // 输出 C 字段的对齐方式
}
```

**假设的输入与输出：**

- **假设目标架构是 64 位：**
  - `unsafe.Sizeof(s)` 输出可能为 `24` (取决于字符串的内部结构，可能包含指针)。
  - `unsafe.Alignof(s.A)` 输出 `4`。
  - `unsafe.Alignof(s.B)` 输出 `8` (因为 string 包含指针).
  - `unsafe.Alignof(s.C)` 输出 `1`。

**`size.go` 的作用就是在编译时完成这些大小和对齐的计算，以便编译器生成正确的内存访问代码。**

**2. 计算切片的大小和偏移：**

```go
package main

import (
	"fmt"
	"reflect"
	"unsafe"
)

func main() {
	var s []int
	header := (*reflect.SliceHeader)(unsafe.Pointer(&s))

	fmt.Println("Size of slice:", unsafe.Sizeof(s)) // 输出切片本身的大小 (不包含底层数组)
	fmt.Println("Data pointer offset:", unsafe.Offsetof(header.Data))
	fmt.Println("Len offset:", unsafe.Offsetof(header.Len))
	fmt.Println("Cap offset:", unsafe.Offsetof(header.Cap))
}
```

**假设的输入与输出 (64 位架构)：**

- `unsafe.Sizeof(s)` 输出 `24` (对应 `SliceSize`，包含三个 `int64`)。
- `unsafe.Offsetof(header.Data)` 输出 `0`。
- `unsafe.Offsetof(header.Len)` 输出 `8`。
- `unsafe.Offsetof(header.Cap)` 输出 `16`。

**`size.go` 中 `SlicePtrOffset`, `SliceLenOffset`, `SliceCapOffset` 和 `SliceSize` 的值会被设置为类似这样的结果。**

**3. 计算接口的大小：**

```go
package main

import (
	"fmt"
	"unsafe"
)

type MyInterface interface {
	Method()
}

type MyType struct{}

func (MyType) Method() {}

func main() {
	var i MyInterface
	fmt.Println("Size of interface:", unsafe.Sizeof(i))
}
```

**假设的输入与输出 (64 位架构)：**

- `unsafe.Sizeof(i)` 输出 `16` (对应接口的 `2 * PtrSize`)。

**命令行参数处理：**

这个 `size.go` 文件本身不直接处理命令行参数。但是，它依赖于编译器在早期阶段设置的全局变量，例如 `PtrSize` 和 `RegSize`。这些全局变量的值通常是在编译器的入口点（例如 `cmd/compile/internal/gc/main.go`）根据目标架构的命令行参数（例如 `-arch=amd64`, `-arch=arm`) 进行设置的。

例如，编译器可能会有类似以下的逻辑（伪代码）：

```go
// cmd/compile/internal/gc/main.go

package main

import (
	"flag"
	"fmt"
	"os"

	"cmd/compile/internal/types"
)

var arch = flag.String("arch", "", "target architecture")

func main() {
	flag.Parse()

	switch *arch {
	case "amd64":
		types.PtrSize = 8
		types.RegSize = 8
		// ... 其他架构相关的设置
	case "386":
		types.PtrSize = 4
		types.RegSize = 4
		// ...
	default:
		fmt.Fprintf(os.Stderr, "unsupported architecture: %s\n", *arch)
		os.Exit(1)
	}

	// ... 编译器的其他初始化和编译流程
}
```

**使用者易犯错的点：**

使用者通常不会直接与 `size.go` 文件交互。但理解其背后的概念对于编写高效和正确的 Go 代码至关重要。

一个常见的误解是**忽略内存对齐**。例如，可能会认为一个结构体的大小只是其所有字段大小的总和。但实际上，编译器为了提高性能，会进行内存对齐，这可能导致结构体的大小比字段大小的总和大。

```go
package main

import "fmt"

type MisalignedStruct struct {
	A bool
	B int64
	C bool
}

func main() {
	fmt.Println("Size of MisalignedStruct:", unsafe.Sizeof(MisalignedStruct{})) // 可能输出 24 而不是 1 + 8 + 1 = 10
}
```

在这个例子中，由于 `int64` 需要 8 字节对齐，编译器会在 `bool` 字段后添加填充，使得 `int64` 的地址是 8 的倍数。

另一个误解是**切片的大小**。切片本身是一个小的结构体（包含指针、长度和容量），其大小是固定的。新手可能会误认为切片的大小会随着其包含的元素数量而变化。

理解 `size.go` 的功能有助于 Go 开发者更好地理解 Go 语言的内存模型，从而编写出更高效和避免潜在错误的程序。

### 提示词
```
这是路径为go/src/cmd/compile/internal/types/size.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
```

### 源代码
```go
// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package types

import (
	"math"
	"slices"

	"cmd/compile/internal/base"
	"cmd/internal/src"
	"internal/types/errors"
)

var PtrSize int

var RegSize int

// Slices in the runtime are represented by three components:
//
//	type slice struct {
//		ptr unsafe.Pointer
//		len int
//		cap int
//	}
//
// Strings in the runtime are represented by two components:
//
//	type string struct {
//		ptr unsafe.Pointer
//		len int
//	}
//
// These variables are the offsets of fields and sizes of these structs.
var (
	SlicePtrOffset int64
	SliceLenOffset int64
	SliceCapOffset int64

	SliceSize  int64
	StringSize int64
)

var SkipSizeForTracing bool

// typePos returns the position associated with t.
// This is where t was declared or where it appeared as a type expression.
func typePos(t *Type) src.XPos {
	if pos := t.Pos(); pos.IsKnown() {
		return pos
	}
	base.Fatalf("bad type: %v", t)
	panic("unreachable")
}

// MaxWidth is the maximum size of a value on the target architecture.
var MaxWidth int64

// CalcSizeDisabled indicates whether it is safe
// to calculate Types' widths and alignments. See CalcSize.
var CalcSizeDisabled bool

// machine size and rounding alignment is dictated around
// the size of a pointer, set in gc.Main (see ../gc/main.go).
var defercalc int

// RoundUp rounds o to a multiple of r, r is a power of 2.
func RoundUp(o int64, r int64) int64 {
	if r < 1 || r > 8 || r&(r-1) != 0 {
		base.Fatalf("Round %d", r)
	}
	return (o + r - 1) &^ (r - 1)
}

// expandiface computes the method set for interface type t by
// expanding embedded interfaces.
func expandiface(t *Type) {
	seen := make(map[*Sym]*Field)
	var methods []*Field

	addMethod := func(m *Field, explicit bool) {
		switch prev := seen[m.Sym]; {
		case prev == nil:
			seen[m.Sym] = m
		case !explicit && Identical(m.Type, prev.Type):
			return
		default:
			base.ErrorfAt(m.Pos, errors.DuplicateDecl, "duplicate method %s", m.Sym.Name)
		}
		methods = append(methods, m)
	}

	{
		methods := t.Methods()
		slices.SortStableFunc(methods, func(a, b *Field) int {
			// Sort embedded types by type name (if any).
			if a.Sym == nil && b.Sym == nil {
				return CompareSyms(a.Type.Sym(), b.Type.Sym())
			}

			// Sort methods before embedded types.
			if a.Sym == nil {
				return -1
			} else if b.Sym == nil {
				return +1
			}

			// Sort methods by symbol name.
			return CompareSyms(a.Sym, b.Sym)
		})
	}

	for _, m := range t.Methods() {
		if m.Sym == nil {
			continue
		}

		CheckSize(m.Type)
		addMethod(m, true)
	}

	for _, m := range t.Methods() {
		if m.Sym != nil || m.Type == nil {
			continue
		}

		// In 1.18, embedded types can be anything. In Go 1.17, we disallow
		// embedding anything other than interfaces. This requirement was caught
		// by types2 already, so allow non-interface here.
		if !m.Type.IsInterface() {
			continue
		}

		// Embedded interface: duplicate all methods
		// and add to t's method set.
		for _, t1 := range m.Type.AllMethods() {
			f := NewField(m.Pos, t1.Sym, t1.Type)
			addMethod(f, false)

			// Clear position after typechecking, for consistency with types2.
			f.Pos = src.NoXPos
		}

		// Clear position after typechecking, for consistency with types2.
		m.Pos = src.NoXPos
	}

	slices.SortFunc(methods, CompareFields)

	if int64(len(methods)) >= MaxWidth/int64(PtrSize) {
		base.ErrorfAt(typePos(t), 0, "interface too large")
	}
	for i, m := range methods {
		m.Offset = int64(i) * int64(PtrSize)
	}

	t.SetAllMethods(methods)
}

// calcStructOffset computes the offsets of a sequence of fields,
// starting at the given offset. It returns the resulting offset and
// maximum field alignment.
func calcStructOffset(t *Type, fields []*Field, offset int64) int64 {
	for _, f := range fields {
		CalcSize(f.Type)
		offset = RoundUp(offset, int64(f.Type.align))

		if t.IsStruct() { // param offsets depend on ABI
			f.Offset = offset

			// If type T contains a field F marked as not-in-heap,
			// then T must also be a not-in-heap type. Otherwise,
			// you could heap allocate T and then get a pointer F,
			// which would be a heap pointer to a not-in-heap type.
			if f.Type.NotInHeap() {
				t.SetNotInHeap(true)
			}
		}

		offset += f.Type.width

		maxwidth := MaxWidth
		// On 32-bit systems, reflect tables impose an additional constraint
		// that each field start offset must fit in 31 bits.
		if maxwidth < 1<<32 {
			maxwidth = 1<<31 - 1
		}
		if offset >= maxwidth {
			base.ErrorfAt(typePos(t), 0, "type %L too large", t)
			offset = 8 // small but nonzero
		}
	}

	return offset
}

func isAtomicStdPkg(p *Pkg) bool {
	if p.Prefix == `""` {
		panic("bad package prefix")
	}
	return p.Prefix == "sync/atomic" || p.Prefix == "internal/runtime/atomic"
}

// CalcSize calculates and stores the size, alignment, eq/hash algorithm,
// and ptrBytes for t.
// If CalcSizeDisabled is set, and the size/alignment
// have not already been calculated, it calls Fatal.
// This is used to prevent data races in the back end.
func CalcSize(t *Type) {
	// Calling CalcSize when typecheck tracing enabled is not safe.
	// See issue #33658.
	if base.EnableTrace && SkipSizeForTracing {
		return
	}
	if PtrSize == 0 {
		// Assume this is a test.
		return
	}

	if t == nil {
		return
	}

	if t.width == -2 {
		t.width = 0
		t.align = 1
		base.Fatalf("invalid recursive type %v", t)
		return
	}

	if t.widthCalculated() {
		return
	}

	if CalcSizeDisabled {
		base.Fatalf("width not calculated: %v", t)
	}

	// defer CheckSize calls until after we're done
	DeferCheckSize()

	lno := base.Pos
	if pos := t.Pos(); pos.IsKnown() {
		base.Pos = pos
	}

	t.width = -2
	t.align = 0  // 0 means use t.Width, below
	t.alg = AMEM // default
	// default t.ptrBytes is 0.
	if t.Noalg() {
		t.setAlg(ANOALG)
	}

	et := t.Kind()
	switch et {
	case TFUNC, TCHAN, TMAP, TSTRING:
		break

	// SimType == 0 during bootstrap
	default:
		if SimType[t.Kind()] != 0 {
			et = SimType[t.Kind()]
		}
	}

	var w int64
	switch et {
	default:
		base.Fatalf("CalcSize: unknown type: %v", t)

	// compiler-specific stuff
	case TINT8, TUINT8, TBOOL:
		// bool is int8
		w = 1
		t.intRegs = 1

	case TINT16, TUINT16:
		w = 2
		t.intRegs = 1

	case TINT32, TUINT32:
		w = 4
		t.intRegs = 1

	case TINT64, TUINT64:
		w = 8
		t.align = uint8(RegSize)
		t.intRegs = uint8(8 / RegSize)

	case TFLOAT32:
		w = 4
		t.floatRegs = 1
		t.setAlg(AFLOAT32)

	case TFLOAT64:
		w = 8
		t.align = uint8(RegSize)
		t.floatRegs = 1
		t.setAlg(AFLOAT64)

	case TCOMPLEX64:
		w = 8
		t.align = 4
		t.floatRegs = 2
		t.setAlg(ACPLX64)

	case TCOMPLEX128:
		w = 16
		t.align = uint8(RegSize)
		t.floatRegs = 2
		t.setAlg(ACPLX128)

	case TPTR:
		w = int64(PtrSize)
		t.intRegs = 1
		CheckSize(t.Elem())
		t.ptrBytes = int64(PtrSize) // See PtrDataSize

	case TUNSAFEPTR:
		w = int64(PtrSize)
		t.intRegs = 1
		t.ptrBytes = int64(PtrSize)

	case TINTER: // implemented as 2 pointers
		w = 2 * int64(PtrSize)
		t.align = uint8(PtrSize)
		t.intRegs = 2
		expandiface(t)
		if len(t.allMethods.Slice()) == 0 {
			t.setAlg(ANILINTER)
		} else {
			t.setAlg(AINTER)
		}
		t.ptrBytes = int64(2 * PtrSize)

	case TCHAN: // implemented as pointer
		w = int64(PtrSize)
		t.intRegs = 1
		t.ptrBytes = int64(PtrSize)

		CheckSize(t.Elem())

		// Make fake type to trigger channel element size check after
		// any top-level recursive type has been completed.
		t1 := NewChanArgs(t)
		CheckSize(t1)

	case TCHANARGS:
		t1 := t.ChanArgs()
		CalcSize(t1) // just in case
		// Make sure size of t1.Elem() is calculated at this point. We can
		// use CalcSize() here rather than CheckSize(), because the top-level
		// (possibly recursive) type will have been calculated before the fake
		// chanargs is handled.
		CalcSize(t1.Elem())
		if t1.Elem().width >= 1<<16 {
			base.Errorf("channel element type too large (>64kB)")
		}
		w = 1 // anything will do

	case TMAP: // implemented as pointer
		w = int64(PtrSize)
		t.intRegs = 1
		CheckSize(t.Elem())
		CheckSize(t.Key())
		t.setAlg(ANOEQ)
		t.ptrBytes = int64(PtrSize)

	case TFORW: // should have been filled in
		base.Fatalf("invalid recursive type %v", t)

	case TANY: // not a real type; should be replaced before use.
		base.Fatalf("CalcSize any")

	case TSTRING:
		if StringSize == 0 {
			base.Fatalf("early CalcSize string")
		}
		w = StringSize
		t.align = uint8(PtrSize)
		t.intRegs = 2
		t.setAlg(ASTRING)
		t.ptrBytes = int64(PtrSize)

	case TARRAY:
		if t.Elem() == nil {
			break
		}

		CalcSize(t.Elem())
		t.SetNotInHeap(t.Elem().NotInHeap())
		if t.Elem().width != 0 {
			cap := (uint64(MaxWidth) - 1) / uint64(t.Elem().width)
			if uint64(t.NumElem()) > cap {
				base.Errorf("type %L larger than address space", t)
			}
		}
		w = t.NumElem() * t.Elem().width
		t.align = t.Elem().align

		// ABIInternal only allows "trivial" arrays (i.e., length 0 or 1)
		// to be passed by register.
		switch t.NumElem() {
		case 0:
			t.intRegs = 0
			t.floatRegs = 0
		case 1:
			t.intRegs = t.Elem().intRegs
			t.floatRegs = t.Elem().floatRegs
		default:
			t.intRegs = math.MaxUint8
			t.floatRegs = math.MaxUint8
		}
		switch a := t.Elem().alg; a {
		case AMEM, ANOEQ, ANOALG:
			t.setAlg(a)
		default:
			switch t.NumElem() {
			case 0:
				// We checked above that the element type is comparable.
				t.setAlg(AMEM)
			case 1:
				// Single-element array is same as its lone element.
				t.setAlg(a)
			default:
				t.setAlg(ASPECIAL)
			}
		}
		if t.NumElem() > 0 {
			x := PtrDataSize(t.Elem())
			if x > 0 {
				t.ptrBytes = t.Elem().width*(t.NumElem()-1) + x
			}
		}

	case TSLICE:
		if t.Elem() == nil {
			break
		}
		w = SliceSize
		CheckSize(t.Elem())
		t.align = uint8(PtrSize)
		t.intRegs = 3
		t.setAlg(ANOEQ)
		if !t.Elem().NotInHeap() {
			t.ptrBytes = int64(PtrSize)
		}

	case TSTRUCT:
		if t.IsFuncArgStruct() {
			base.Fatalf("CalcSize fn struct %v", t)
		}
		CalcStructSize(t)
		w = t.width

	// make fake type to check later to
	// trigger function argument computation.
	case TFUNC:
		t1 := NewFuncArgs(t)
		CheckSize(t1)
		w = int64(PtrSize) // width of func type is pointer
		t.intRegs = 1
		t.setAlg(ANOEQ)
		t.ptrBytes = int64(PtrSize)

	// function is 3 cated structures;
	// compute their widths as side-effect.
	case TFUNCARGS:
		t1 := t.FuncArgs()
		// TODO(mdempsky): Should package abi be responsible for computing argwid?
		w = calcStructOffset(t1, t1.Recvs(), 0)
		w = calcStructOffset(t1, t1.Params(), w)
		w = RoundUp(w, int64(RegSize))
		w = calcStructOffset(t1, t1.Results(), w)
		w = RoundUp(w, int64(RegSize))
		t1.extra.(*Func).Argwid = w
		t.align = 1
	}

	if PtrSize == 4 && w != int64(int32(w)) {
		base.Errorf("type %v too large", t)
	}

	t.width = w
	if t.align == 0 {
		if w == 0 || w > 8 || w&(w-1) != 0 {
			base.Fatalf("invalid alignment for %v", t)
		}
		t.align = uint8(w)
	}

	base.Pos = lno

	ResumeCheckSize()
}

// CalcStructSize calculates the size of t,
// filling in t.width, t.align, t.intRegs, and t.floatRegs,
// even if size calculation is otherwise disabled.
func CalcStructSize(t *Type) {
	var maxAlign uint8 = 1

	// Recognize special types. This logic is duplicated in go/types and
	// cmd/compile/internal/types2.
	if sym := t.Sym(); sym != nil {
		switch {
		case sym.Name == "align64" && isAtomicStdPkg(sym.Pkg):
			maxAlign = 8
		}
	}

	fields := t.Fields()
	size := calcStructOffset(t, fields, 0)

	// For non-zero-sized structs which end in a zero-sized field, we
	// add an extra byte of padding to the type. This padding ensures
	// that taking the address of a zero-sized field can't manufacture a
	// pointer to the next object in the heap. See issue 9401.
	if size > 0 && fields[len(fields)-1].Type.width == 0 {
		size++
	}

	var intRegs, floatRegs uint64
	for _, field := range fields {
		typ := field.Type

		// The alignment of a struct type is the maximum alignment of its
		// field types.
		if align := typ.align; align > maxAlign {
			maxAlign = align
		}

		// Each field needs its own registers.
		// We sum in uint64 to avoid possible overflows.
		intRegs += uint64(typ.intRegs)
		floatRegs += uint64(typ.floatRegs)
	}

	// Final size includes trailing padding.
	size = RoundUp(size, int64(maxAlign))

	if intRegs > math.MaxUint8 || floatRegs > math.MaxUint8 {
		intRegs = math.MaxUint8
		floatRegs = math.MaxUint8
	}

	t.width = size
	t.align = maxAlign
	t.intRegs = uint8(intRegs)
	t.floatRegs = uint8(floatRegs)

	// Compute eq/hash algorithm type.
	t.alg = AMEM // default
	if t.Noalg() {
		t.setAlg(ANOALG)
	}
	if len(fields) == 1 && !fields[0].Sym.IsBlank() {
		// One-field struct is same as that one field alone.
		t.setAlg(fields[0].Type.alg)
	} else {
		for i, f := range fields {
			a := f.Type.alg
			switch a {
			case ANOEQ, ANOALG:
			case AMEM:
				// Blank fields and padded fields need a special compare.
				if f.Sym.IsBlank() || IsPaddedField(t, i) {
					a = ASPECIAL
				}
			default:
				// Fields with non-memory equality need a special compare.
				a = ASPECIAL
			}
			t.setAlg(a)
		}
	}
	// Compute ptrBytes.
	for i := len(fields) - 1; i >= 0; i-- {
		f := fields[i]
		if size := PtrDataSize(f.Type); size > 0 {
			t.ptrBytes = f.Offset + size
			break
		}
	}
}

func (t *Type) widthCalculated() bool {
	return t.align > 0
}

// when a type's width should be known, we call CheckSize
// to compute it.  during a declaration like
//
//	type T *struct { next T }
//
// it is necessary to defer the calculation of the struct width
// until after T has been initialized to be a pointer to that struct.
// similarly, during import processing structs may be used
// before their definition.  in those situations, calling
// DeferCheckSize() stops width calculations until
// ResumeCheckSize() is called, at which point all the
// CalcSizes that were deferred are executed.
// CalcSize should only be called when the type's size
// is needed immediately.  CheckSize makes sure the
// size is evaluated eventually.

var deferredTypeStack []*Type

func CheckSize(t *Type) {
	if t == nil {
		return
	}

	// function arg structs should not be checked
	// outside of the enclosing function.
	if t.IsFuncArgStruct() {
		base.Fatalf("CheckSize %v", t)
	}

	if defercalc == 0 {
		CalcSize(t)
		return
	}

	// if type has not yet been pushed on deferredTypeStack yet, do it now
	if !t.Deferwidth() {
		t.SetDeferwidth(true)
		deferredTypeStack = append(deferredTypeStack, t)
	}
}

func DeferCheckSize() {
	defercalc++
}

func ResumeCheckSize() {
	if defercalc == 1 {
		for len(deferredTypeStack) > 0 {
			t := deferredTypeStack[len(deferredTypeStack)-1]
			deferredTypeStack = deferredTypeStack[:len(deferredTypeStack)-1]
			t.SetDeferwidth(false)
			CalcSize(t)
		}
	}

	defercalc--
}

// PtrDataSize returns the length in bytes of the prefix of t
// containing pointer data. Anything after this offset is scalar data.
//
// PtrDataSize is only defined for actual Go types. It's an error to
// use it on compiler-internal types (e.g., TSSA, TRESULTS).
func PtrDataSize(t *Type) int64 {
	CalcSize(t)
	x := t.ptrBytes
	if t.Kind() == TPTR && t.Elem().NotInHeap() {
		// Note: this is done here instead of when we're setting
		// the ptrBytes field, because at that time (in NewPtr, usually)
		// the NotInHeap bit of the element type might not be set yet.
		x = 0
	}
	return x
}
```