Response:
My thought process to analyze the Go code snippet and answer the prompt goes like this:

1. **Understand the Goal:** The request asks for the functionality of the `SymbolBuilder` struct in the given Go code, potential use cases, code examples, handling of command-line arguments (if any), and common mistakes.

2. **Identify the Core Component:** The central element is the `SymbolBuilder` struct. My first step is to understand its purpose and how it interacts with the `Loader`. The comment "SymbolBuilder is a helper designed to help with the construction of new symbol contents" is a crucial starting point.

3. **Analyze Struct Members:** I examine the fields of `SymbolBuilder`:
    * `*extSymPayload`:  The comment indicates it points to the payload being updated. This suggests `SymbolBuilder` manipulates the underlying data of a symbol.
    * `symIdx`:  This is clearly the identifier (index) of the symbol being built or updated.
    * `l *Loader`: This signifies that `SymbolBuilder` is tightly coupled with the `Loader` and likely uses its methods to manage symbol data.

4. **Examine Key Methods:** I go through the methods of `SymbolBuilder`, grouping them by function:

    * **Creation/Initialization:** `MakeSymbolBuilder`, `MakeSymbolUpdater`, `CreateSymForUpdate`. These methods provide different ways to obtain a `SymbolBuilder` instance, either for a new symbol or an existing one. The cloning logic in `MakeSymbolUpdater` for non-external symbols is important to note.

    * **Getters:**  Methods like `Sym`, `Name`, `Type`, `Size`, `Data`, `Value`, etc. provide read access to the symbol's attributes. These are straightforward.

    * **Setters:** Methods like `SetType`, `SetSize`, `SetData`, `SetValue`, etc., allow modification of the symbol's attributes.

    * **Data Manipulation:** `AddBytes`, `AddUint8`, `AddUintXX`, `AddStringAt`, `AddCStringAt`, `Addstring`, `SetBytesAt`. These methods are responsible for adding data to the symbol's content. The handling of `sb.kind` (symbol type) is worth noting.

    * **Relocation Handling:** `Relocs`, `ResetRelocs`, `SetRelocType`, `SetRelocSym`, `SetRelocAdd`, `AddRelocs`, `AddRel`, `SortRelocs`, `AddSymRef`, `AddAddr`, `AddPCRelPlus`, etc. This is a significant part of the functionality, dealing with how symbols refer to each other.

    * **Attribute Management:** `Reachable`, `SetReachable`, `ReadOnly`, `SetReadOnly`, `DuplicateOK`, `SetDuplicateOK`, `VisibilityHidden`, `SetVisibilityHidden`, `SetNotInSymbolTable`, `SetSect`. These manage various properties of the symbol.

    * **Symbol Hierarchy:** `Outer`, `Sub`, `SortSub`, `AddInteriorSym`. This indicates support for hierarchical symbol structures.

    * **Specialized Operations:** `AddUleb`, `MakeWritable`, `GenAddAddrPlusFunc`. These provide more specific utilities. The `GenAddAddrPlusFunc` is interesting as it demonstrates conditional behavior based on the linking context.

5. **Infer Functionality:** Based on the methods, I can deduce that `SymbolBuilder` is a central tool for creating and modifying symbols during the linking process. It abstracts away the direct manipulation of the `Loader`'s internal data structures.

6. **Identify Go Features:** The code heavily uses structs, methods, and pointers, which are fundamental to Go. The relocation handling points towards the linker's role in resolving symbol references.

7. **Construct Code Examples:** I think about common scenarios where a linker would need to create or update symbols. Examples include:

    * Defining global variables (using `SetData` and `SetType`).
    * Creating string literals (using `Addstring`).
    * Defining functions (using `SetType` and adding instructions via `AddBytes` or other `Add...` methods).
    * Setting up relocations when a function calls another function or accesses a global variable.

8. **Address Specific Requirements:**

    * **Command-line Arguments:** I scan the code for any direct processing of command-line arguments. There isn't any in this snippet. The `Loader` might handle them, but `SymbolBuilder` itself doesn't seem to.

    * **Common Mistakes:** I consider potential errors users might make. For instance:
        * Forgetting to set the symbol type.
        * Incorrectly calculating symbol size.
        * Errors in setting up relocations (wrong type, target, or offset).
        * Modifying read-only symbols without calling `MakeWritable`.

9. **Structure the Answer:** I organize my findings into the requested sections: functionality, Go feature implementation, code examples, command-line arguments, and common mistakes. I aim for clear and concise explanations, using the identified methods and their behavior to illustrate the points. I provide specific examples with input and expected output where applicable.

10. **Review and Refine:** I reread my answer to ensure accuracy, completeness, and clarity. I check if I've addressed all parts of the prompt.

This systematic approach helps to break down the code into manageable parts, understand their interactions, and derive meaningful conclusions about the functionality and usage of `SymbolBuilder`.
`go/src/cmd/link/internal/loader/symbolbuilder.go` 文件中的 `SymbolBuilder` 结构体及其相关方法，主要用于在 Go 链接器 (linker) 中**创建和修改符号 (symbol)** 的内容和属性。

以下是其主要功能：

**1. 符号的创建和更新：**

* **`MakeSymbolBuilder(name string) *SymbolBuilder`:**  用于创建一个新的符号。它会创建一个静态符号（internal symbol），并返回一个 `SymbolBuilder` 实例，用于填充该符号的内容。
* **`MakeSymbolUpdater(symIdx Sym) *SymbolBuilder`:** 用于更新已存在的符号。如果该符号不是外部符号，它会先创建一个该符号的克隆，然后再对克隆进行修改。这样可以避免直接修改原始符号。
* **`CreateSymForUpdate(name string, version int) *SymbolBuilder`:**  查找或创建一个指定名称和版本的符号，并返回一个用于更新该符号的 `SymbolBuilder`。如果符号已存在，则直接返回用于更新它的 builder。

**2. 访问和修改符号的属性：**

`SymbolBuilder` 提供了大量的 getter 和 setter 方法来访问和修改符号的各种属性，例如：

* **基本属性:**
    * `Sym()`: 获取符号的索引 (Sym)。
    * `Name()`: 获取符号的名称。
    * `Version()`: 获取符号的版本。
    * `Type()`/`SetType(kind sym.SymKind)`: 获取/设置符号的类型 (例如：代码、数据、bss)。
    * `Size()`/`SetSize(size int64)`: 获取/设置符号的大小。
    * `Data()`/`SetData(data []byte)`: 获取/设置符号的数据内容。
    * `Value()`/`SetValue(v int64)`: 获取/设置符号的值（地址或偏移量）。
    * `Align()`/`SetAlign(align int32)`: 获取/设置符号的对齐方式。
* **链接器特定的属性:**
    * `Localentry()`/`SetLocalentry(value uint8)`:  获取/设置本地入口点。
    * `OnList()`/`SetOnList(v bool)`:  指示符号是否在列表中。
    * `External()`/`SetExternal(v bool)`:  指示符号是否是外部符号。
    * `Extname()`/`SetExtname(value string)`: 获取/设置外部名称。
    * `CgoExportDynamic()`/`SetCgoExportDynamic(value bool)`:  指示符号是否通过 cgo 导出为动态符号。
    * `Dynimplib()`/`SetDynimplib(value string)`: 获取/设置动态链接库的名称。
    * `Dynimpvers()`/`SetDynimpvers(value string)`: 获取/设置动态链接库的版本。
    * `VisibilityHidden()`/`SetVisibilityHidden(value bool)`:  指示符号是否隐藏（对外部不可见）。
    * `NotInSymbolTable()`/`SetNotInSymbolTable(value bool)`: 指示符号是否不在最终的符号表中。
* **与其他符号的关系:**
    * `SubSym()`: 获取子符号。
    * `GoType()`: 获取符号的 Go 类型信息。
    * `Sect()`/`SetSect(sect *sym.Section)`: 获取/设置符号所属的 section。
    * `Outer()`: 获取外部符号。
    * `Sub()`: 获取子符号（同 `SubSym()`）。

**3. 操作符号的数据内容：**

* **`AddBytes(data []byte)`:** 向符号的数据中追加字节。
* **`AddUint8(v uint8)` / `AddUintXX(...)`:** 向符号的数据中追加各种大小的无符号整数，会根据目标架构的字节序进行处理。
* **`SetUint8(...)` / `SetUintXX(...)`:**  在符号数据的指定偏移量处设置无符号整数。
* **`AddStringAt(off int64, str string)`:** 在符号数据的指定偏移量处添加字符串。
* **`AddCStringAt(off int64, str string)`:** 在符号数据的指定偏移量处添加 C 风格的字符串（以 null 结尾）。
* **`Addstring(str string)`:** 将字符串添加到符号的数据末尾，并添加 null 终止符。
* **`SetBytesAt(off int64, b []byte)`:** 将字节数组写入符号数据的指定偏移量。

**4. 处理重定位 (Relocation)：**

重定位是链接过程中的关键步骤，用于修正符号引用。 `SymbolBuilder` 提供了管理符号重定位的方法：

* **`Relocs() Relocs`:** 获取符号的所有重定位信息。
* **`ResetRelocs()`:** 移除符号的所有重定位信息。
* **`SetRelocType(i int, t objabi.RelocType)` / `SetRelocSym(i int, tgt Sym)` / `SetRelocAdd(i int, a int64)`:**  设置指定索引的重定位的类型、目标符号和加数。
* **`AddRelocs(n int) Relocs`:**  添加指定数量的重定位条目。
* **`AddRel(typ objabi.RelocType) (Reloc, int)`:** 添加一个新的指定类型的重定位，并返回其句柄和索引。
* **`SortRelocs()`:**  根据偏移量对重定位进行排序。
* **`AddSymRef(arch *sys.Arch, tgt Sym, add int64, typ objabi.RelocType, rsize int)`:** 添加一个通用的符号引用重定位。
* **`AddAddrPlus(...)` / `AddPCRelPlus(...)` / `AddSize(...)` 等:** 提供更便捷的方法添加特定类型的重定位，例如：绝对地址、PC 相对地址、符号大小等。
* **`GenAddAddrPlusFunc(internalExec bool) func(s *SymbolBuilder, arch *sys.Arch, tgt Sym, add int64) int64`:** 生成一个用于添加地址重定位的函数，可以根据是否是内部链接到可执行文件来选择直接写入地址还是生成重定位。

**5. 其他属性和操作：**

* **`Reachable()`/`SetReachable(v bool)`:** 获取/设置符号是否可达。
* **`ReadOnly()`/`SetReadOnly(v bool)`:** 获取/设置符号是否只读。
* **`DuplicateOK()`/`SetDuplicateOK(v bool)`:** 获取/设置符号是否允许重复。
* **`SortSub()`:** 对子符号进行排序。
* **`AddInteriorSym(sub Sym)`:** 添加一个内部符号。
* **`MakeWritable()`:** 如果符号是只读的，则创建一个可写的副本。
* **`AddUleb(v uint64)`:** 添加一个 LEB128 编码的无符号整数。

**推断 Go 语言功能的实现：**

`SymbolBuilder` 是 Go 链接器实现的核心部分，它用于构建和管理程序中的各种符号，包括：

* **全局变量和常量：** 使用 `SetType(sym.SDATA)` 或 `SetType(sym.SRODATA)`，并使用 `SetData()` 或 `AddBytes()` 等方法设置数据。
* **函数：** 使用 `SetType(sym.STEXT)`，并通过 `AddBytes()` 等方法添加机器码指令。
* **字符串字面量：**  使用 `Addstring()` 或 `AddCStringAt()`。
* **类型信息：**  可能使用 `SetType(sym.STYPE)`，并设置相应的结构体信息。
* **Go 的运行时数据结构：** 例如，用于实现 interface 或 reflection 的类型信息。

**Go 代码举例说明：**

假设我们要创建一个表示全局变量的符号 `myGlobalVar`，类型为 `int`，初始值为 `10`：

```go
package main

import (
	"cmd/internal/objabi"
	"cmd/link/internal/loader"
	"cmd/link/internal/sym"
	"cmd/internal/sys"
	"encoding/binary"
)

func createGlobalVarSymbol(l *loader.Loader, arch *sys.Arch) {
	sb := l.MakeSymbolBuilder("myGlobalVar")
	sb.SetType(sym.SDATA)
	data := make([]byte, arch.PtrSize) // 假设 int 大小与指针相同
	binary.LittleEndian.PutUintptr(data, uintptr(10)) // 设置初始值
	sb.SetData(data)
	sb.SetSize(int64(len(data)))
	sb.SetExternal(true) // 假设是外部可见的全局变量
}

// 假设我们有一个 Loader 实例 l 和目标架构信息 arch
// createGlobalVarSymbol(l, arch)
```

**假设输入与输出：**

* **输入：** `Loader` 实例 `l`，目标架构信息 `arch` (例如 `&sys.Arch{PtrSize: 8, ByteOrder: binary.LittleEndian}`)。
* **输出：**  在 `Loader` 中创建了一个名为 `myGlobalVar` 的符号，其类型为 `SDATA`，数据部分为表示整数 `10` 的字节序列 (例如，在小端 64 位架构上可能是 `[0a 00 00 00 00 00 00 00]`)，大小为 8 字节，并且标记为外部符号。

**再例如，创建一个字符串字面量符号：**

```go
func createStringLiteralSymbol(l *loader.Loader) {
	sb := l.MakeSymbolBuilder("go.string.\"hello\"")
	sb.SetType(sym.SRODATA) // 字符串字面量通常是只读数据
	sb.Addstring("hello")
	sb.SetExternal(true)
}

// createStringLiteralSymbol(l)
```

**假设输入与输出：**

* **输入：** `Loader` 实例 `l`。
* **输出：** 创建一个名为 `go.string."hello"` 的符号，类型为 `SRODATA`，数据部分包含字符串 "hello" 和一个 null 终止符 (即 `[h e l l o 0]`)，大小为 6 字节，并标记为外部符号。

**命令行参数的具体处理：**

`SymbolBuilder` 本身并不直接处理命令行参数。 命令行参数的处理通常发生在 `cmd/link/internal/link.go` 等更上层的模块中。 `Loader` 可能会根据命令行参数的影响，调用 `SymbolBuilder` 的方法来创建或修改符号。

例如，如果命令行参数指定了 `-X 'package.variable=value'` 来设置全局变量的值，链接器会在解析参数后，找到对应的符号并使用 `SymbolBuilder` 的 `SetData()` 方法来修改其内容。

**使用者易犯错的点：**

1. **忘记设置符号类型 (`SetType`)**: 如果没有设置符号类型，链接器可能无法正确处理该符号，导致链接错误或运行时错误。

   ```go
   // 错误示例：忘记设置符号类型
   sb := l.MakeSymbolBuilder("myFunc")
   // sb.SetType(sym.STEXT) // 忘记设置类型
   // sb.AddBytes(...)
   ```

2. **数据大小与符号大小不一致**:  如果通过 `AddBytes` 等方法添加数据后，没有正确设置符号的大小 (`SetSize`)，可能会导致链接器或运行时访问越界。

   ```go
   sb := l.MakeSymbolBuilder("myData")
   data := []byte{1, 2, 3, 4}
   sb.AddBytes(data)
   // sb.SetSize(int64(len(data))) // 忘记设置正确的大小
   ```

3. **重定位目标符号不存在**: 在添加重定位时，如果指定的目标符号 (`tgt`) 不存在，链接器会报错。

   ```go
   sb := l.MakeSymbolBuilder("callerFunc")
   // ... 添加 callerFunc 的代码 ...
   targetSym := l.LookupSym("nonExistentFunc", 0) // 查找不存在的符号
   sb.AddAddr(arch, targetSym) // 错误：尝试重定位到不存在的符号
   ```

4. **在只读符号上直接修改数据**: 某些符号（例如常量字符串）默认是只读的。直接修改其数据会导致 panic。应该先调用 `MakeWritable()` 创建可写副本。

   ```go
   sb := l.LookupSym("myStringConstant", 0) // 假设这是一个只读符号
   data := sb.Data()
   // data[0] = 'H' // 错误：尝试修改只读数据
   sb.MakeWritable()
   data = sb.Data()
   data[0] = 'H' // 正确：先创建可写副本
   ```

理解 `SymbolBuilder` 的功能对于深入理解 Go 链接器的实现至关重要。它提供了一组强大的工具，用于在链接过程中构建和操作程序中的各种符号。

Prompt: 
```
这是路径为go/src/cmd/link/internal/loader/symbolbuilder.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，

"""
// Copyright 2019 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package loader

import (
	"cmd/internal/goobj"
	"cmd/internal/objabi"
	"cmd/internal/sys"
	"cmd/link/internal/sym"
	"cmp"
	"slices"
)

// SymbolBuilder is a helper designed to help with the construction
// of new symbol contents.
type SymbolBuilder struct {
	*extSymPayload         // points to payload being updated
	symIdx         Sym     // index of symbol being updated/constructed
	l              *Loader // loader
}

// MakeSymbolBuilder creates a symbol builder for use in constructing
// an entirely new symbol.
func (l *Loader) MakeSymbolBuilder(name string) *SymbolBuilder {
	// for now assume that any new sym is intended to be static
	symIdx := l.CreateStaticSym(name)
	sb := &SymbolBuilder{l: l, symIdx: symIdx}
	sb.extSymPayload = l.getPayload(symIdx)
	return sb
}

// MakeSymbolUpdater creates a symbol builder helper for an existing
// symbol 'symIdx'. If 'symIdx' is not an external symbol, then create
// a clone of it (copy name, properties, etc) fix things up so that
// the lookup tables and caches point to the new version, not the old
// version.
func (l *Loader) MakeSymbolUpdater(symIdx Sym) *SymbolBuilder {
	if symIdx == 0 {
		panic("can't update the null symbol")
	}
	if !l.IsExternal(symIdx) {
		// Create a clone with the same name/version/kind etc.
		l.cloneToExternal(symIdx)
	}

	// Construct updater and return.
	sb := &SymbolBuilder{l: l, symIdx: symIdx}
	sb.extSymPayload = l.getPayload(symIdx)
	return sb
}

// CreateSymForUpdate creates a symbol with given name and version,
// returns a CreateSymForUpdate for update. If the symbol already
// exists, it will update in-place.
func (l *Loader) CreateSymForUpdate(name string, version int) *SymbolBuilder {
	s := l.LookupOrCreateSym(name, version)
	l.SetAttrReachable(s, true)
	return l.MakeSymbolUpdater(s)
}

// Getters for properties of the symbol we're working on.

func (sb *SymbolBuilder) Sym() Sym               { return sb.symIdx }
func (sb *SymbolBuilder) Name() string           { return sb.name }
func (sb *SymbolBuilder) Version() int           { return sb.ver }
func (sb *SymbolBuilder) Type() sym.SymKind      { return sb.kind }
func (sb *SymbolBuilder) Size() int64            { return sb.size }
func (sb *SymbolBuilder) Data() []byte           { return sb.data }
func (sb *SymbolBuilder) Value() int64           { return sb.l.SymValue(sb.symIdx) }
func (sb *SymbolBuilder) Align() int32           { return sb.l.SymAlign(sb.symIdx) }
func (sb *SymbolBuilder) Localentry() uint8      { return sb.l.SymLocalentry(sb.symIdx) }
func (sb *SymbolBuilder) OnList() bool           { return sb.l.AttrOnList(sb.symIdx) }
func (sb *SymbolBuilder) External() bool         { return sb.l.AttrExternal(sb.symIdx) }
func (sb *SymbolBuilder) Extname() string        { return sb.l.SymExtname(sb.symIdx) }
func (sb *SymbolBuilder) CgoExportDynamic() bool { return sb.l.AttrCgoExportDynamic(sb.symIdx) }
func (sb *SymbolBuilder) Dynimplib() string      { return sb.l.SymDynimplib(sb.symIdx) }
func (sb *SymbolBuilder) Dynimpvers() string     { return sb.l.SymDynimpvers(sb.symIdx) }
func (sb *SymbolBuilder) SubSym() Sym            { return sb.l.SubSym(sb.symIdx) }
func (sb *SymbolBuilder) GoType() Sym            { return sb.l.SymGoType(sb.symIdx) }
func (sb *SymbolBuilder) VisibilityHidden() bool { return sb.l.AttrVisibilityHidden(sb.symIdx) }
func (sb *SymbolBuilder) Sect() *sym.Section     { return sb.l.SymSect(sb.symIdx) }

// Setters for symbol properties.

func (sb *SymbolBuilder) SetType(kind sym.SymKind)   { sb.kind = kind }
func (sb *SymbolBuilder) SetSize(size int64)         { sb.size = size }
func (sb *SymbolBuilder) SetData(data []byte)        { sb.data = data }
func (sb *SymbolBuilder) SetOnList(v bool)           { sb.l.SetAttrOnList(sb.symIdx, v) }
func (sb *SymbolBuilder) SetExternal(v bool)         { sb.l.SetAttrExternal(sb.symIdx, v) }
func (sb *SymbolBuilder) SetValue(v int64)           { sb.l.SetSymValue(sb.symIdx, v) }
func (sb *SymbolBuilder) SetAlign(align int32)       { sb.l.SetSymAlign(sb.symIdx, align) }
func (sb *SymbolBuilder) SetLocalentry(value uint8)  { sb.l.SetSymLocalentry(sb.symIdx, value) }
func (sb *SymbolBuilder) SetExtname(value string)    { sb.l.SetSymExtname(sb.symIdx, value) }
func (sb *SymbolBuilder) SetDynimplib(value string)  { sb.l.SetSymDynimplib(sb.symIdx, value) }
func (sb *SymbolBuilder) SetDynimpvers(value string) { sb.l.SetSymDynimpvers(sb.symIdx, value) }
func (sb *SymbolBuilder) SetPlt(value int32)         { sb.l.SetPlt(sb.symIdx, value) }
func (sb *SymbolBuilder) SetGot(value int32)         { sb.l.SetGot(sb.symIdx, value) }
func (sb *SymbolBuilder) SetSpecial(value bool)      { sb.l.SetAttrSpecial(sb.symIdx, value) }
func (sb *SymbolBuilder) SetLocal(value bool)        { sb.l.SetAttrLocal(sb.symIdx, value) }
func (sb *SymbolBuilder) SetVisibilityHidden(value bool) {
	sb.l.SetAttrVisibilityHidden(sb.symIdx, value)
}
func (sb *SymbolBuilder) SetNotInSymbolTable(value bool) {
	sb.l.SetAttrNotInSymbolTable(sb.symIdx, value)
}
func (sb *SymbolBuilder) SetSect(sect *sym.Section) { sb.l.SetSymSect(sb.symIdx, sect) }

func (sb *SymbolBuilder) AddBytes(data []byte) {
	if sb.kind == 0 {
		sb.kind = sym.SDATA
	}
	sb.data = append(sb.data, data...)
	sb.size = int64(len(sb.data))
}

func (sb *SymbolBuilder) Relocs() Relocs {
	return sb.l.Relocs(sb.symIdx)
}

// ResetRelocs removes all relocations on this symbol.
func (sb *SymbolBuilder) ResetRelocs() {
	sb.relocs = sb.relocs[:0]
}

// SetRelocType sets the type of the 'i'-th relocation on this sym to 't'
func (sb *SymbolBuilder) SetRelocType(i int, t objabi.RelocType) {
	sb.relocs[i].SetType(uint16(t))
}

// SetRelocSym sets the target sym of the 'i'-th relocation on this sym to 's'
func (sb *SymbolBuilder) SetRelocSym(i int, tgt Sym) {
	sb.relocs[i].SetSym(goobj.SymRef{PkgIdx: 0, SymIdx: uint32(tgt)})
}

// SetRelocAdd sets the addend of the 'i'-th relocation on this sym to 'a'
func (sb *SymbolBuilder) SetRelocAdd(i int, a int64) {
	sb.relocs[i].SetAdd(a)
}

// Add n relocations, return a handle to the relocations.
func (sb *SymbolBuilder) AddRelocs(n int) Relocs {
	sb.relocs = append(sb.relocs, make([]goobj.Reloc, n)...)
	return sb.l.Relocs(sb.symIdx)
}

// Add a relocation with given type, return its handle and index
// (to set other fields).
func (sb *SymbolBuilder) AddRel(typ objabi.RelocType) (Reloc, int) {
	j := len(sb.relocs)
	sb.relocs = append(sb.relocs, goobj.Reloc{})
	sb.relocs[j].SetType(uint16(typ))
	relocs := sb.Relocs()
	return relocs.At(j), j
}

// SortRelocs Sort relocations by offset.
func (sb *SymbolBuilder) SortRelocs() {
	slices.SortFunc(sb.extSymPayload.relocs, func(a, b goobj.Reloc) int {
		return cmp.Compare(a.Off(), b.Off())
	})
}

func (sb *SymbolBuilder) Reachable() bool {
	return sb.l.AttrReachable(sb.symIdx)
}

func (sb *SymbolBuilder) SetReachable(v bool) {
	sb.l.SetAttrReachable(sb.symIdx, v)
}

func (sb *SymbolBuilder) ReadOnly() bool {
	return sb.l.AttrReadOnly(sb.symIdx)
}

func (sb *SymbolBuilder) SetReadOnly(v bool) {
	sb.l.SetAttrReadOnly(sb.symIdx, v)
}

func (sb *SymbolBuilder) DuplicateOK() bool {
	return sb.l.AttrDuplicateOK(sb.symIdx)
}

func (sb *SymbolBuilder) SetDuplicateOK(v bool) {
	sb.l.SetAttrDuplicateOK(sb.symIdx, v)
}

func (sb *SymbolBuilder) Outer() Sym {
	return sb.l.OuterSym(sb.symIdx)
}

func (sb *SymbolBuilder) Sub() Sym {
	return sb.l.SubSym(sb.symIdx)
}

func (sb *SymbolBuilder) SortSub() {
	sb.l.SortSub(sb.symIdx)
}

func (sb *SymbolBuilder) AddInteriorSym(sub Sym) {
	sb.l.AddInteriorSym(sb.symIdx, sub)
}

func (sb *SymbolBuilder) AddUint8(v uint8) int64 {
	off := sb.size
	if sb.kind == 0 {
		sb.kind = sym.SDATA
	}
	sb.size++
	sb.data = append(sb.data, v)
	return off
}

func (sb *SymbolBuilder) AddUintXX(arch *sys.Arch, v uint64, wid int) int64 {
	off := sb.size
	sb.setUintXX(arch, off, v, int64(wid))
	return off
}

func (sb *SymbolBuilder) setUintXX(arch *sys.Arch, off int64, v uint64, wid int64) int64 {
	if sb.kind == 0 {
		sb.kind = sym.SDATA
	}
	if sb.size < off+wid {
		sb.size = off + wid
		sb.Grow(sb.size)
	}

	switch wid {
	case 1:
		sb.data[off] = uint8(v)
	case 2:
		arch.ByteOrder.PutUint16(sb.data[off:], uint16(v))
	case 4:
		arch.ByteOrder.PutUint32(sb.data[off:], uint32(v))
	case 8:
		arch.ByteOrder.PutUint64(sb.data[off:], v)
	}

	return off + wid
}

func (sb *SymbolBuilder) AddUint16(arch *sys.Arch, v uint16) int64 {
	return sb.AddUintXX(arch, uint64(v), 2)
}

func (sb *SymbolBuilder) AddUint32(arch *sys.Arch, v uint32) int64 {
	return sb.AddUintXX(arch, uint64(v), 4)
}

func (sb *SymbolBuilder) AddUint64(arch *sys.Arch, v uint64) int64 {
	return sb.AddUintXX(arch, v, 8)
}

func (sb *SymbolBuilder) AddUint(arch *sys.Arch, v uint64) int64 {
	return sb.AddUintXX(arch, v, arch.PtrSize)
}

func (sb *SymbolBuilder) SetUint8(arch *sys.Arch, r int64, v uint8) int64 {
	return sb.setUintXX(arch, r, uint64(v), 1)
}

func (sb *SymbolBuilder) SetUint16(arch *sys.Arch, r int64, v uint16) int64 {
	return sb.setUintXX(arch, r, uint64(v), 2)
}

func (sb *SymbolBuilder) SetUint32(arch *sys.Arch, r int64, v uint32) int64 {
	return sb.setUintXX(arch, r, uint64(v), 4)
}

func (sb *SymbolBuilder) SetUint(arch *sys.Arch, r int64, v uint64) int64 {
	return sb.setUintXX(arch, r, v, int64(arch.PtrSize))
}

func (sb *SymbolBuilder) SetUintptr(arch *sys.Arch, r int64, v uintptr) int64 {
	return sb.setUintXX(arch, r, uint64(v), int64(arch.PtrSize))
}

func (sb *SymbolBuilder) SetAddrPlus(arch *sys.Arch, off int64, tgt Sym, add int64) int64 {
	if sb.Type() == 0 {
		sb.SetType(sym.SDATA)
	}
	if off+int64(arch.PtrSize) > sb.size {
		sb.size = off + int64(arch.PtrSize)
		sb.Grow(sb.size)
	}
	r, _ := sb.AddRel(objabi.R_ADDR)
	r.SetSym(tgt)
	r.SetOff(int32(off))
	r.SetSiz(uint8(arch.PtrSize))
	r.SetAdd(add)
	return off + int64(r.Siz())
}

func (sb *SymbolBuilder) SetAddr(arch *sys.Arch, off int64, tgt Sym) int64 {
	return sb.SetAddrPlus(arch, off, tgt, 0)
}

func (sb *SymbolBuilder) AddStringAt(off int64, str string) int64 {
	strLen := int64(len(str))
	if off+strLen > int64(len(sb.data)) {
		panic("attempt to write past end of buffer")
	}
	copy(sb.data[off:off+strLen], str)
	return off + strLen
}

// AddCStringAt adds str plus a null terminating byte.
func (sb *SymbolBuilder) AddCStringAt(off int64, str string) int64 {
	strLen := int64(len(str))
	if off+strLen+1 > int64(len(sb.data)) {
		panic("attempt to write past end of buffer")
	}
	copy(sb.data[off:off+strLen], str)
	sb.data[off+strLen] = 0
	return off + strLen + 1
}

func (sb *SymbolBuilder) Addstring(str string) int64 {
	if sb.kind == 0 {
		sb.kind = sym.SNOPTRDATA
	}
	r := sb.size
	sb.data = append(sb.data, str...)
	sb.data = append(sb.data, 0)
	sb.size = int64(len(sb.data))
	return r
}

func (sb *SymbolBuilder) SetBytesAt(off int64, b []byte) int64 {
	datLen := int64(len(b))
	if off+datLen > int64(len(sb.data)) {
		panic("attempt to write past end of buffer")
	}
	copy(sb.data[off:off+datLen], b)
	return off + datLen
}

func (sb *SymbolBuilder) addSymRef(tgt Sym, add int64, typ objabi.RelocType, rsize int) int64 {
	if sb.kind == 0 {
		sb.kind = sym.SDATA
	}
	i := sb.size

	sb.size += int64(rsize)
	sb.Grow(sb.size)

	r, _ := sb.AddRel(typ)
	r.SetSym(tgt)
	r.SetOff(int32(i))
	r.SetSiz(uint8(rsize))
	r.SetAdd(add)

	return i + int64(rsize)
}

// Add a symbol reference (relocation) with given type, addend, and size
// (the most generic form).
func (sb *SymbolBuilder) AddSymRef(arch *sys.Arch, tgt Sym, add int64, typ objabi.RelocType, rsize int) int64 {
	return sb.addSymRef(tgt, add, typ, rsize)
}

func (sb *SymbolBuilder) AddAddrPlus(arch *sys.Arch, tgt Sym, add int64) int64 {
	return sb.addSymRef(tgt, add, objabi.R_ADDR, arch.PtrSize)
}

func (sb *SymbolBuilder) AddAddrPlus4(arch *sys.Arch, tgt Sym, add int64) int64 {
	return sb.addSymRef(tgt, add, objabi.R_ADDR, 4)
}

func (sb *SymbolBuilder) AddAddr(arch *sys.Arch, tgt Sym) int64 {
	return sb.AddAddrPlus(arch, tgt, 0)
}

func (sb *SymbolBuilder) AddPEImageRelativeAddrPlus(arch *sys.Arch, tgt Sym, add int64) int64 {
	return sb.addSymRef(tgt, add, objabi.R_PEIMAGEOFF, 4)
}

func (sb *SymbolBuilder) AddPCRelPlus(arch *sys.Arch, tgt Sym, add int64) int64 {
	return sb.addSymRef(tgt, add, objabi.R_PCREL, 4)
}

func (sb *SymbolBuilder) AddCURelativeAddrPlus(arch *sys.Arch, tgt Sym, add int64) int64 {
	return sb.addSymRef(tgt, add, objabi.R_ADDRCUOFF, arch.PtrSize)
}

func (sb *SymbolBuilder) AddSize(arch *sys.Arch, tgt Sym) int64 {
	return sb.addSymRef(tgt, 0, objabi.R_SIZE, arch.PtrSize)
}

// GenAddAddrPlusFunc returns a function to be called when capturing
// a function symbol's address. In later stages of the link (when
// address assignment is done) when doing internal linking and
// targeting an executable, we can just emit the address of a function
// directly instead of generating a relocation. Clients can call
// this function (setting 'internalExec' based on build mode and target)
// and then invoke the returned function in roughly the same way that
// loader.*SymbolBuilder.AddAddrPlus would be used.
func GenAddAddrPlusFunc(internalExec bool) func(s *SymbolBuilder, arch *sys.Arch, tgt Sym, add int64) int64 {
	if internalExec {
		return func(s *SymbolBuilder, arch *sys.Arch, tgt Sym, add int64) int64 {
			if v := s.l.SymValue(tgt); v != 0 {
				return s.AddUint(arch, uint64(v+add))
			}
			return s.AddAddrPlus(arch, tgt, add)
		}
	} else {
		return (*SymbolBuilder).AddAddrPlus
	}
}

func (sb *SymbolBuilder) MakeWritable() {
	if sb.ReadOnly() {
		sb.data = append([]byte(nil), sb.data...)
		sb.l.SetAttrReadOnly(sb.symIdx, false)
	}
}

func (sb *SymbolBuilder) AddUleb(v uint64) {
	if v < 128 { // common case: 1 byte
		sb.AddUint8(uint8(v))
		return
	}
	for {
		c := uint8(v & 0x7f)
		v >>= 7
		if v != 0 {
			c |= 0x80
		}
		sb.AddUint8(c)
		if c&0x80 == 0 {
			break
		}
	}
}

"""



```