Response: The user wants to understand the functionality of the Go code snippet provided, which is part of the `sym.go` file in the Go compiler's internal object linking package.

Here's a breakdown of the thought process to answer the user's request:

1. **Identify the Core Purpose:** The code is within the `obj` package, specifically `sym.go`. The file name strongly suggests it deals with symbols, a fundamental concept in linking and compilation.

2. **Analyze Key Structures:** Look for the central data structures and their methods.
    * `Link`: This struct likely represents the linking context.
    * `LSym`: This struct probably represents a symbol. The methods associated with `LSym` will provide clues about its purpose.
    * Maps (`hash`, `funchash`, `statichash`): These are clearly used for storing and looking up symbols by name, suggesting efficient symbol management.

3. **Examine Function Signatures and Logic:**  Go through each function and determine its role.
    * `Linknew`: This seems to initialize a new `Link` context. It sets up the hash maps and basic link settings.
    * `Lookup...`:  The various `Lookup` functions (`Lookup`, `LookupStatic`, `LookupABI`, `LookupABIInit`, `LookupDerived`) are central. They all aim to retrieve or create symbols, with variations based on staticness and ABI. The presence of locking (`ctxt.hashmu.Lock()`) indicates that symbol lookup and creation might be concurrent.
    * `Float...Sym`, `Int...Sym`: These functions create symbols representing floating-point and integer constants. They demonstrate how constant values are embedded into the object file.
    * `GCLocalsSym`: This function generates a symbol for garbage collector metadata, using a content hash to ensure uniqueness.
    * `NumberSyms`:  This function assigns indices to symbols. The logic involving different `PkgIdx` values (like `goobj.PkgIdxHashed`, `goobj.PkgIdxNone`, `goobj.PkgIdxSelf`, `goobj.PkgIdxBuiltin`) reveals how symbols are categorized for linking (e.g., local, external, built-in). The sorting of `ctxt.Data` suggests a concern for reproducible builds.
    * `isNonPkgSym`: This helper determines if a symbol should be referenced by name rather than index, highlighting different ways symbols can be resolved during linking.
    * `traverseSyms`, `traverseFuncAux`, `traverseAuxSyms`: These functions provide a way to iterate through various categories of symbols and their associated data (relocations, auxiliary symbols, etc.), which is crucial for tasks like code generation, debugging information, and optimization.

4. **Infer High-Level Functionality:** Based on the analysis of individual functions and data structures, deduce the overall purpose of the code:
    * **Symbol Management:** The primary function is to create, store, and retrieve symbols.
    * **Constant Representation:**  It provides mechanisms to represent constant values as symbols.
    * **Symbol Indexing:** It assigns indices to symbols for efficient referencing during linking.
    * **Symbol Classification:** It categorizes symbols based on scope (static), ABI, and whether they are part of the current package or external.
    * **Symbol Traversal:** It offers methods to iterate through collections of symbols and related data.

5. **Connect to Go Language Features:** Consider how these functionalities relate to the Go language:
    * **Linking Process:** The code is directly involved in the linking stage of the Go compilation process.
    * **Object Files:** It deals with the representation of symbols within object files.
    * **Garbage Collection:** The `GCLocalsSym` function connects to Go's garbage collection mechanism.
    * **Function Calls and ABIs:** The `LookupABI` functions relate to how function calls are resolved, especially when different calling conventions are involved.
    * **Constants:** The `Float...Sym` and `Int...Sym` functions are used to represent constant values defined in Go code.
    * **Reproducible Builds:** The sorting in `NumberSyms` indicates an effort to make builds more deterministic.
    * **Internal Representation:** The code reveals details about how the Go compiler and linker internally represent symbols.

6. **Construct Examples and Explanations:**  Provide concrete examples to illustrate the functionality. Focus on the most important aspects, such as symbol lookup and constant creation.

7. **Identify Potential Pitfalls:**  Think about how developers might misuse or misunderstand the functionality. In this case, the complexities of ABIs and static symbols are good candidates.

8. **Structure the Answer:** Organize the findings into clear sections, addressing each part of the user's request: functionality listing, code examples, input/output (where applicable), and potential pitfalls. Use clear and concise language.

**Self-Correction/Refinement during the thought process:**

* **Initial thought:**  Maybe this is just about storing symbols.
* **Correction:** The `LookupABI` and `NumberSyms` functions reveal a more sophisticated role in handling different ABIs and managing symbol indices for linking.
* **Initial thought:** The examples should focus on complex scenarios.
* **Correction:** Start with simpler examples of basic symbol lookup and constant creation to build understanding before introducing more advanced concepts like ABIs.
* **Initial thought:**  Just list the functions.
* **Correction:** Group related functions and describe their combined purpose for better clarity. For example, group all the `Lookup...` functions together.

By following these steps, the detailed and informative answer provided earlier can be constructed.
这是Go语言编译器 `cmd/compile` 中对象文件处理 (`obj`) 包中 `sym.go` 文件的一部分。它的主要功能是**管理和操作链接过程中的符号 (Symbols)**。

更具体地说，这段代码实现了以下功能：

1. **符号的创建和查找 (Symbol Creation and Lookup):**
   - 提供了多种方法来查找或创建符号 (`LSym`)，例如 `Lookup`, `LookupStatic`, `LookupABI`, `LookupDerived`, `LookupInit`, `LookupABIInit`。
   - `Lookup`: 查找或创建一个普通的符号。
   - `LookupStatic`: 查找或创建一个静态符号 (仅在当前编译单元可见)。
   - `LookupABI`:  查找或创建一个带有特定 ABI (Application Binary Interface) 的符号。
   - `LookupDerived`: 查找或创建一个从现有符号派生的符号，并继承其静态属性。
   - `LookupInit` 和 `LookupABIInit`:  在符号不存在时创建它，并允许在创建后执行一次初始化函数。
   - 使用 `hash`, `funchash`, `statichash` 这三个 `map` 来高效地存储和查找不同类型的符号。
   - 使用互斥锁 `ctxt.hashmu` 来保证并发安全性。

2. **常量符号的创建 (Constant Symbol Creation):**
   - 提供了创建特定类型常量符号的便捷方法：`Float32Sym`, `Float64Sym`, `Int32Sym`, `Int64Sym`, `Int128Sym`。
   - 这些函数会根据常量的值和类型创建一个唯一的只读数据符号 (通常位于 `.rodata` 段)。
   - 这些符号会被标记为本地 (`AttrLocal`) 和内容可寻址 (`AttrContentAddressable`)。

3. **GC 元数据符号的创建 (GC Metadata Symbol Creation):**
   - `GCLocalsSym`:  创建一个包含垃圾回收器局部变量信息的符号。
   - 使用内容的哈希值作为符号名的一部分，以实现内容寻址。

4. **符号的编号和索引 (Symbol Numbering and Indexing):**
   - `NumberSyms`:  在链接过程中为所有符号分配唯一的索引。
   - 根据符号的属性 (例如，是否为静态、是否为外部引用) 将符号分配到不同的列表中 (`defs`, `hasheddefs`, `hashed64defs`, `nonpkgdefs`, `nonpkgrefs`) 并赋予相应的 `PkgIdx` 和 `SymIdx`。
   - 这允许链接器通过索引而不是全名来引用符号，从而提高效率。
   - 处理链接到共享库的情况 (`ctxt.Flag_linkshared`)，以及运行时内置符号。

5. **判断是否为非包符号 (Determining Non-Package Symbols):**
   - `isNonPkgSym`:  判断一个符号是否应该通过名称而不是索引来引用。
   -  常见情况包括汇编代码中的符号 (非静态)，链接到共享库的符号，使用 `//go:linkname` 指令的符号，以及允许重复定义的符号 (`DupOK`)。

6. **符号的遍历 (Symbol Traversal):**
   - `traverseSyms`: 提供了一种通用的方法来遍历不同类型的符号 (定义、引用、辅助符号、PCData)。
   - `traverseFuncAux`:  遍历函数相关的辅助符号，例如 DWARF 信息和内联树。
   - `traverseAuxSyms`: 遍历所有辅助符号。
   - 这些遍历函数对于链接过程中的各种分析和处理非常重要。

**它是什么 Go 语言功能的实现？**

这段代码是 Go 语言 **链接器 (linker)** 的核心组成部分，负责将编译器生成的对象文件组合成最终的可执行文件或库。它实现了链接器中至关重要的 **符号管理** 功能。符号代表了代码和数据的名称和地址，链接器的主要任务就是解析这些符号引用，并将它们连接在一起。

**Go 代码举例说明:**

假设我们有以下 Go 代码：

```go
package main

import "fmt"

const message = "Hello, world!"

func main() {
	fmt.Println(message)
}
```

在编译和链接这个程序的过程中，`sym.go` 中的代码会被用来创建和管理以下一些符号：

- `main.main`:  `main` 函数的符号。
- `main.message`: 常量字符串 "Hello, world!" 的符号（可能通过 `ctxt.LookupInit` 或类似函数创建，并将字符串数据写入符号的数据区）。
- `fmt.Println`: 对 `fmt` 包中 `Println` 函数的引用符号。
- 内部运行时或标准库的符号 (例如用于字符串表示、类型信息的符号)。

**代码推理与假设输入输出:**

假设在编译 `main.go` 的过程中，编译器遇到了常量 `message`。

**假设输入:**
- `ctxt`: 当前的链接上下文 (`*Link`)。
- `name`: 字符串 "main.message"。

**代码推理 (可能发生在 `ctxt.LookupInit` 内部):**

```go
// 假设在某个编译阶段，编译器需要为常量 "Hello, world!" 创建符号
name := "main.message"
data := []byte("Hello, world!") // 常量的数据
ctxt := &Link{ /* ... */ } // 假设已经创建了链接上下文

// ... (在 sym.go 中的某个地方)

s := ctxt.LookupInit(name, func(s *LSym) {
    s.Type = objabi.SRODATA // 标记为只读数据
    s.Size = int64(len(data))
    s.P = data // 将常量数据写入符号
    s.Set(AttrLocal, false) // 假设不是本地符号
    s.Set(AttrContentAddressable, true) // 标记为内容可寻址
})

// 假设之后需要引用这个常量
s2 := ctxt.Lookup(name)
// s 和 s2 应该指向同一个 *LSym 对象
```

**假设输出:**

- `s`: 指向一个 `LSym` 结构体，其 `Name` 为 "main.message"，`Type` 为 `objabi.SRODATA`，`Size` 为 13，`P` 包含 "Hello, world!" 的字节。

**命令行参数的具体处理:**

这段代码本身不直接处理命令行参数。命令行参数的处理通常发生在 `cmd/link` 包中。 `sym.go` 中使用的 `ctxt.Flag_optimize` 和 `ctxt.Flag_linkshared` 等标志，其值可能是在 `cmd/link` 解析命令行参数后设置的。

例如，如果使用 `go build -ldflags="-linkmode external"` 构建程序，`ctxt.Flag_linkshared` 可能会被设置为 `true`。这将影响 `isNonPkgSym` 函数的判断逻辑，使得外部包的符号更可能被视为非包符号，需要通过名称引用。

**使用者易犯错的点:**

由于 `sym.go` 是 Go 编译器内部实现的一部分，普通 Go 开发者不会直接使用或修改它。然而，理解其背后的概念对于理解链接过程和解决链接错误非常重要。

一个潜在的混淆点可能是 **静态符号 (`AttrStatic`) 和本地符号 (`AttrLocal`) 的区别**：

- **静态符号** 指的是在编译时限定了作用域的符号，通常只在定义它的源文件中可见。在链接过程中，静态符号不会与其他编译单元中的同名符号冲突。可以通过 `ctxt.LookupStatic` 创建。
- **本地符号** 指的是链接器在最终输出文件中标记为本地的符号，它们不会被导出到其他链接单元。常量符号通常会被标记为本地。

错误地认为所有通过 `ctxt.LookupStatic` 创建的符号都会被标记为 `AttrLocal` 是一个常见的误解。实际上，`AttrStatic` 主要影响符号的查找和命名，而 `AttrLocal` 则控制符号在最终链接输出中的可见性。

例如，在编译器内部，可能会创建一个静态的全局变量，但它仍然需要在最终的可执行文件中可见，因此不会被标记为 `AttrLocal`。

总而言之，`sym.go` 是 Go 语言链接器中负责符号管理的关键组件，它提供了创建、查找、索引和操作符号的各种功能，是理解 Go 语言链接过程的基础。

### 提示词
```
这是路径为go/src/cmd/internal/obj/sym.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
```

### 源代码
```go
// Derived from Inferno utils/6l/obj.c and utils/6l/span.c
// https://bitbucket.org/inferno-os/inferno-os/src/master/utils/6l/obj.c
// https://bitbucket.org/inferno-os/inferno-os/src/master/utils/6l/span.c
//
//	Copyright © 1994-1999 Lucent Technologies Inc.  All rights reserved.
//	Portions Copyright © 1995-1997 C H Forsyth (forsyth@terzarima.net)
//	Portions Copyright © 1997-1999 Vita Nuova Limited
//	Portions Copyright © 2000-2007 Vita Nuova Holdings Limited (www.vitanuova.com)
//	Portions Copyright © 2004,2006 Bruce Ellis
//	Portions Copyright © 2005-2007 C H Forsyth (forsyth@terzarima.net)
//	Revisions Copyright © 2000-2007 Lucent Technologies Inc. and others
//	Portions Copyright © 2009 The Go Authors. All rights reserved.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.

package obj

import (
	"cmd/internal/goobj"
	"cmd/internal/hash"
	"cmd/internal/objabi"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"internal/buildcfg"
	"log"
	"math"
	"sort"
)

func Linknew(arch *LinkArch) *Link {
	ctxt := new(Link)
	ctxt.hash = make(map[string]*LSym)
	ctxt.funchash = make(map[string]*LSym)
	ctxt.statichash = make(map[string]*LSym)
	ctxt.Arch = arch
	ctxt.Pathname = objabi.WorkingDir()

	if err := ctxt.Headtype.Set(buildcfg.GOOS); err != nil {
		log.Fatalf("unknown goos %s", buildcfg.GOOS)
	}

	ctxt.Flag_optimize = true
	return ctxt
}

// LookupDerived looks up or creates the symbol with name derived from symbol s.
// The resulting symbol will be static iff s is.
func (ctxt *Link) LookupDerived(s *LSym, name string) *LSym {
	if s.Static() {
		return ctxt.LookupStatic(name)
	}
	return ctxt.Lookup(name)
}

// LookupStatic looks up the static symbol with name name.
// If it does not exist, it creates it.
func (ctxt *Link) LookupStatic(name string) *LSym {
	s := ctxt.statichash[name]
	if s == nil {
		s = &LSym{Name: name, Attribute: AttrStatic}
		ctxt.statichash[name] = s
	}
	return s
}

// LookupABI looks up a symbol with the given ABI.
// If it does not exist, it creates it.
func (ctxt *Link) LookupABI(name string, abi ABI) *LSym {
	return ctxt.LookupABIInit(name, abi, nil)
}

// LookupABIInit looks up a symbol with the given ABI.
// If it does not exist, it creates it and
// passes it to init for one-time initialization.
func (ctxt *Link) LookupABIInit(name string, abi ABI, init func(s *LSym)) *LSym {
	var hash map[string]*LSym
	switch abi {
	case ABI0:
		hash = ctxt.hash
	case ABIInternal:
		hash = ctxt.funchash
	default:
		panic("unknown ABI")
	}

	ctxt.hashmu.Lock()
	s := hash[name]
	if s == nil {
		s = &LSym{Name: name}
		s.SetABI(abi)
		hash[name] = s
		if init != nil {
			init(s)
		}
	}
	ctxt.hashmu.Unlock()
	return s
}

// Lookup looks up the symbol with name name.
// If it does not exist, it creates it.
func (ctxt *Link) Lookup(name string) *LSym {
	return ctxt.LookupInit(name, nil)
}

// LookupInit looks up the symbol with name name.
// If it does not exist, it creates it and
// passes it to init for one-time initialization.
func (ctxt *Link) LookupInit(name string, init func(s *LSym)) *LSym {
	ctxt.hashmu.Lock()
	s := ctxt.hash[name]
	if s == nil {
		s = &LSym{Name: name}
		ctxt.hash[name] = s
		if init != nil {
			init(s)
		}
	}
	ctxt.hashmu.Unlock()
	return s
}

func (ctxt *Link) rodataKind() (suffix string, typ objabi.SymKind) {
	return "", objabi.SRODATA
}

func (ctxt *Link) Float32Sym(f float32) *LSym {
	suffix, typ := ctxt.rodataKind()
	i := math.Float32bits(f)
	name := fmt.Sprintf("$f32.%08x%s", i, suffix)
	return ctxt.LookupInit(name, func(s *LSym) {
		s.Size = 4
		s.WriteFloat32(ctxt, 0, f)
		s.Type = typ
		s.Set(AttrLocal, true)
		s.Set(AttrContentAddressable, true)
		ctxt.constSyms = append(ctxt.constSyms, s)
	})
}

func (ctxt *Link) Float64Sym(f float64) *LSym {
	suffix, typ := ctxt.rodataKind()
	i := math.Float64bits(f)
	name := fmt.Sprintf("$f64.%016x%s", i, suffix)
	return ctxt.LookupInit(name, func(s *LSym) {
		s.Size = 8
		s.WriteFloat64(ctxt, 0, f)
		s.Type = typ
		s.Set(AttrLocal, true)
		s.Set(AttrContentAddressable, true)
		ctxt.constSyms = append(ctxt.constSyms, s)
	})
}

func (ctxt *Link) Int32Sym(i int64) *LSym {
	suffix, typ := ctxt.rodataKind()
	name := fmt.Sprintf("$i32.%08x%s", uint64(i), suffix)
	return ctxt.LookupInit(name, func(s *LSym) {
		s.Size = 4
		s.WriteInt(ctxt, 0, 4, i)
		s.Type = typ
		s.Set(AttrLocal, true)
		s.Set(AttrContentAddressable, true)
		ctxt.constSyms = append(ctxt.constSyms, s)
	})
}

func (ctxt *Link) Int64Sym(i int64) *LSym {
	suffix, typ := ctxt.rodataKind()
	name := fmt.Sprintf("$i64.%016x%s", uint64(i), suffix)
	return ctxt.LookupInit(name, func(s *LSym) {
		s.Size = 8
		s.WriteInt(ctxt, 0, 8, i)
		s.Type = typ
		s.Set(AttrLocal, true)
		s.Set(AttrContentAddressable, true)
		ctxt.constSyms = append(ctxt.constSyms, s)
	})
}

func (ctxt *Link) Int128Sym(hi, lo int64) *LSym {
	suffix, typ := ctxt.rodataKind()
	name := fmt.Sprintf("$i128.%016x%016x%s", uint64(hi), uint64(lo), suffix)
	return ctxt.LookupInit(name, func(s *LSym) {
		s.Size = 16
		if ctxt.Arch.ByteOrder == binary.LittleEndian {
			s.WriteInt(ctxt, 0, 8, lo)
			s.WriteInt(ctxt, 8, 8, hi)
		} else {
			s.WriteInt(ctxt, 0, 8, hi)
			s.WriteInt(ctxt, 8, 8, lo)
		}
		s.Type = typ
		s.Set(AttrLocal, true)
		s.Set(AttrContentAddressable, true)
		ctxt.constSyms = append(ctxt.constSyms, s)
	})
}

// GCLocalsSym generates a content-addressable sym containing data.
func (ctxt *Link) GCLocalsSym(data []byte) *LSym {
	sum := hash.Sum16(data)
	str := base64.StdEncoding.EncodeToString(sum[:16])
	return ctxt.LookupInit(fmt.Sprintf("gclocals·%s", str), func(lsym *LSym) {
		lsym.P = data
		lsym.Set(AttrContentAddressable, true)
	})
}

// Assign index to symbols.
// asm is set to true if this is called by the assembler (i.e. not the compiler),
// in which case all the symbols are non-package (for now).
func (ctxt *Link) NumberSyms() {
	if ctxt.Pkgpath == "" {
		panic("NumberSyms called without package path")
	}

	if ctxt.Headtype == objabi.Haix {
		// Data must be in a reliable order for reproducible builds.
		// The original entries are in a reliable order, but the TOC symbols
		// that are added in Progedit are added by different goroutines
		// that can be scheduled independently. We need to reorder those
		// symbols reliably. Sort by name but use a stable sort, so that
		// any original entries with the same name (all DWARFVAR symbols
		// have empty names but different relocation sets) are not shuffled.
		// TODO: Find a better place and optimize to only sort TOC symbols.
		sort.SliceStable(ctxt.Data, func(i, j int) bool {
			return ctxt.Data[i].Name < ctxt.Data[j].Name
		})
	}

	// Constant symbols are created late in the concurrent phase. Sort them
	// to ensure a deterministic order.
	sort.Slice(ctxt.constSyms, func(i, j int) bool {
		return ctxt.constSyms[i].Name < ctxt.constSyms[j].Name
	})
	ctxt.Data = append(ctxt.Data, ctxt.constSyms...)
	ctxt.constSyms = nil

	// So are SEH symbols.
	sort.Slice(ctxt.SEHSyms, func(i, j int) bool {
		return ctxt.SEHSyms[i].Name < ctxt.SEHSyms[j].Name
	})
	ctxt.Data = append(ctxt.Data, ctxt.SEHSyms...)
	ctxt.SEHSyms = nil

	ctxt.pkgIdx = make(map[string]int32)
	ctxt.defs = []*LSym{}
	ctxt.hashed64defs = []*LSym{}
	ctxt.hasheddefs = []*LSym{}
	ctxt.nonpkgdefs = []*LSym{}

	var idx, hashedidx, hashed64idx, nonpkgidx int32
	ctxt.traverseSyms(traverseDefs|traversePcdata, func(s *LSym) {
		if s.ContentAddressable() {
			if s.Size <= 8 && len(s.R) == 0 && contentHashSection(s) == 0 {
				// We can use short hash only for symbols without relocations.
				// Don't use short hash for symbols that belong in a particular section
				// or require special handling (such as type symbols).
				s.PkgIdx = goobj.PkgIdxHashed64
				s.SymIdx = hashed64idx
				if hashed64idx != int32(len(ctxt.hashed64defs)) {
					panic("bad index")
				}
				ctxt.hashed64defs = append(ctxt.hashed64defs, s)
				hashed64idx++
			} else {
				s.PkgIdx = goobj.PkgIdxHashed
				s.SymIdx = hashedidx
				if hashedidx != int32(len(ctxt.hasheddefs)) {
					panic("bad index")
				}
				ctxt.hasheddefs = append(ctxt.hasheddefs, s)
				hashedidx++
			}
		} else if isNonPkgSym(ctxt, s) {
			s.PkgIdx = goobj.PkgIdxNone
			s.SymIdx = nonpkgidx
			if nonpkgidx != int32(len(ctxt.nonpkgdefs)) {
				panic("bad index")
			}
			ctxt.nonpkgdefs = append(ctxt.nonpkgdefs, s)
			nonpkgidx++
		} else {
			s.PkgIdx = goobj.PkgIdxSelf
			s.SymIdx = idx
			if idx != int32(len(ctxt.defs)) {
				panic("bad index")
			}
			ctxt.defs = append(ctxt.defs, s)
			idx++
		}
		s.Set(AttrIndexed, true)
	})

	ipkg := int32(1) // 0 is invalid index
	nonpkgdef := nonpkgidx
	ctxt.traverseSyms(traverseRefs|traverseAux, func(rs *LSym) {
		if rs.PkgIdx != goobj.PkgIdxInvalid {
			return
		}
		if !ctxt.Flag_linkshared {
			// Assign special index for builtin symbols.
			// Don't do it when linking against shared libraries, as the runtime
			// may be in a different library.
			if i := goobj.BuiltinIdx(rs.Name, int(rs.ABI())); i != -1 && !rs.IsLinkname() {
				rs.PkgIdx = goobj.PkgIdxBuiltin
				rs.SymIdx = int32(i)
				rs.Set(AttrIndexed, true)
				return
			}
		}
		pkg := rs.Pkg
		if rs.ContentAddressable() {
			// for now, only support content-addressable symbols that are always locally defined.
			panic("hashed refs unsupported for now")
		}
		if pkg == "" || pkg == "\"\"" || pkg == "_" || !rs.Indexed() {
			rs.PkgIdx = goobj.PkgIdxNone
			rs.SymIdx = nonpkgidx
			rs.Set(AttrIndexed, true)
			if nonpkgidx != nonpkgdef+int32(len(ctxt.nonpkgrefs)) {
				panic("bad index")
			}
			ctxt.nonpkgrefs = append(ctxt.nonpkgrefs, rs)
			nonpkgidx++
			return
		}
		if k, ok := ctxt.pkgIdx[pkg]; ok {
			rs.PkgIdx = k
			return
		}
		rs.PkgIdx = ipkg
		ctxt.pkgIdx[pkg] = ipkg
		ipkg++
	})
}

// Returns whether s is a non-package symbol, which needs to be referenced
// by name instead of by index.
func isNonPkgSym(ctxt *Link, s *LSym) bool {
	if ctxt.IsAsm && !s.Static() {
		// asm symbols are referenced by name only, except static symbols
		// which are file-local and can be referenced by index.
		return true
	}
	if ctxt.Flag_linkshared {
		// The referenced symbol may be in a different shared library so
		// the linker cannot see its index.
		return true
	}
	if s.Pkg == "_" {
		// The frontend uses package "_" to mark symbols that should not
		// be referenced by index, e.g. linkname'd symbols.
		return true
	}
	if s.DuplicateOK() {
		// Dupok symbol needs to be dedup'd by name.
		return true
	}
	return false
}

// StaticNamePrefix is the prefix the front end applies to static temporary
// variables. When turned into LSyms, these can be tagged as static so
// as to avoid inserting them into the linker's name lookup tables.
const StaticNamePrefix = ".stmp_"

type traverseFlag uint32

const (
	traverseDefs traverseFlag = 1 << iota
	traverseRefs
	traverseAux
	traversePcdata

	traverseAll = traverseDefs | traverseRefs | traverseAux | traversePcdata
)

// Traverse symbols based on flag, call fn for each symbol.
func (ctxt *Link) traverseSyms(flag traverseFlag, fn func(*LSym)) {
	fnNoNil := func(s *LSym) {
		if s != nil {
			fn(s)
		}
	}
	lists := [][]*LSym{ctxt.Text, ctxt.Data}
	files := ctxt.PosTable.FileTable()
	for _, list := range lists {
		for _, s := range list {
			if flag&traverseDefs != 0 {
				fn(s)
			}
			if flag&traverseRefs != 0 {
				for _, r := range s.R {
					fnNoNil(r.Sym)
				}
			}
			if flag&traverseAux != 0 {
				fnNoNil(s.Gotype)
				if s.Type.IsText() {
					f := func(parent *LSym, aux *LSym) {
						fn(aux)
					}
					ctxt.traverseFuncAux(flag, s, f, files)
				} else if v := s.VarInfo(); v != nil {
					fnNoNil(v.dwarfInfoSym)
				}
			}
			if flag&traversePcdata != 0 && s.Type.IsText() {
				fi := s.Func().Pcln
				fnNoNil(fi.Pcsp)
				fnNoNil(fi.Pcfile)
				fnNoNil(fi.Pcline)
				fnNoNil(fi.Pcinline)
				for _, d := range fi.Pcdata {
					fnNoNil(d)
				}
			}
		}
	}
}

func (ctxt *Link) traverseFuncAux(flag traverseFlag, fsym *LSym, fn func(parent *LSym, aux *LSym), files []string) {
	fninfo := fsym.Func()
	pc := &fninfo.Pcln
	if flag&traverseAux == 0 {
		// NB: should it become necessary to walk aux sym reloc references
		// without walking the aux syms themselves, this can be changed.
		panic("should not be here")
	}
	for _, d := range pc.Funcdata {
		if d != nil {
			fn(fsym, d)
		}
	}
	usedFiles := make([]goobj.CUFileIndex, 0, len(pc.UsedFiles))
	for f := range pc.UsedFiles {
		usedFiles = append(usedFiles, f)
	}
	sort.Slice(usedFiles, func(i, j int) bool { return usedFiles[i] < usedFiles[j] })
	for _, f := range usedFiles {
		if filesym := ctxt.Lookup(files[f]); filesym != nil {
			fn(fsym, filesym)
		}
	}
	for _, call := range pc.InlTree.nodes {
		if call.Func != nil {
			fn(fsym, call.Func)
		}
	}

	auxsyms := []*LSym{fninfo.dwarfRangesSym, fninfo.dwarfLocSym, fninfo.dwarfDebugLinesSym, fninfo.dwarfInfoSym, fninfo.sehUnwindInfoSym}
	if wi := fninfo.WasmImport; wi != nil {
		auxsyms = append(auxsyms, wi.AuxSym)
	}
	if we := fninfo.WasmExport; we != nil {
		auxsyms = append(auxsyms, we.AuxSym)
	}
	for _, s := range auxsyms {
		if s == nil || s.Size == 0 {
			continue
		}
		fn(fsym, s)
		if flag&traverseRefs != 0 {
			for _, r := range s.R {
				if r.Sym != nil {
					fn(s, r.Sym)
				}
			}
		}
	}
}

// Traverse aux symbols, calling fn for each sym/aux pair.
func (ctxt *Link) traverseAuxSyms(flag traverseFlag, fn func(parent *LSym, aux *LSym)) {
	lists := [][]*LSym{ctxt.Text, ctxt.Data}
	files := ctxt.PosTable.FileTable()
	for _, list := range lists {
		for _, s := range list {
			if s.Gotype != nil {
				if flag&traverseDefs != 0 {
					fn(s, s.Gotype)
				}
			}
			if s.Type.IsText() {
				ctxt.traverseFuncAux(flag, s, fn, files)
			} else if v := s.VarInfo(); v != nil && v.dwarfInfoSym != nil {
				fn(s, v.dwarfInfoSym)
			}
		}
	}
}
```