Response:
The user wants to understand the functionality of the Go code provided. I need to analyze the code and identify its main purposes and the functionalities of its components.

Here's a breakdown of the thought process to generate the answer:

1. **Identify the Core Package and Purpose:** The code is in `go/src/cmd/link/internal/loader/loader_test.go`. The `_test.go` suffix immediately indicates it's a testing file. The package `loader` within the `cmd/link/internal` path suggests this code is part of the Go linker and specifically deals with loading and managing symbols during the linking process.

2. **Analyze the Test Functions:** The file contains multiple test functions like `TestAddMaterializedSymbol`, `TestAddDataMethods`, and `TestOuterSub`. Each test function focuses on verifying specific aspects of the `Loader` type.

3. **Examine Key Types and Functions:**  The code introduces types like `Loader`, `Sym`, `Reloc`, and `SymbolBuilder`. Key functions like `NewLoader`, `LookupOrCreateSym`, `CreateStaticSym`, `MakeSymbolUpdater`, `AddRel`, `AddBytes`, `AddUint8`, `AddAddrPlus`, `AddInteriorSym`, and `SortSub` are defined and used in the tests.

4. **Infer Functionality from Tests:** By examining how these types and functions are used in the tests, I can infer their purpose.
    * `TestAddMaterializedSymbol` tests the creation and manipulation of symbols, including setting attributes like reachability, visibility, value, and alignment. It also tests adding relocations and data to symbols.
    * `TestAddDataMethods` specifically focuses on testing methods for adding different types of data (bytes, integers, strings, addresses) to symbols. It also verifies that the correct relocations are created for address-related data.
    * `TestOuterSub` deals with the concept of "outer" and "sub" symbols, likely representing a hierarchy or containment relationship between symbols. The tests verify the adding and sorting of sub-symbols within an outer symbol.

5. **Connect to Go Linking Concepts:** Based on the identified functionalities, I can connect them to concepts in the Go linking process. The `Loader` is likely responsible for managing the symbol table during linking. Adding data and relocations are essential steps in preparing the final executable. The outer/sub symbol relationship might represent the structure of code and data within a package or object file.

6. **Illustrate with Go Code Examples:** To provide a clearer understanding, I need to create simple Go code examples demonstrating the usage of the inferred functionalities. These examples should be basic and focus on the specific feature being illustrated. For example, showing how to create a symbol, add data, and a relocation.

7. **Address Command-Line Arguments (If Applicable):** I need to check if the test code or the inferred functionality involves handling command-line arguments. In this specific case, the `loader_test.go` focuses on internal logic and doesn't directly interact with command-line arguments. Therefore, I should state that it doesn't involve command-line argument processing.

8. **Identify Potential Pitfalls:**  Based on the code and understanding of linking, I can identify potential pitfalls for users of this functionality (even though it's internal). For example, incorrect relocation offsets or sizes, and the importance of using the `SymbolBuilder` for modifications.

9. **Structure the Answer:** Finally, I need to organize the information into a clear and structured answer, addressing each point in the user's request: main functionalities, inferred Go features, code examples, command-line arguments, and common mistakes.

**Self-Correction/Refinement:**

* **Initial thought:** Focus too much on the testing aspect. Realization: The tests reveal the *functionality* of the `Loader`.
* **Initial thought:**  Provide very complex examples. Realization: Simple, focused examples are better for understanding.
* **Consideration:**  Should I delve deeper into the internal workings of the linker? Decision: Stick to what can be inferred from the provided code and its tests, avoiding speculative details.
这段代码是 Go 语言链接器 (`cmd/link`) 中 `internal/loader` 包的一部分，名为 `loader_test.go`，它包含了对 `loader` 包中 `Loader` 类型及其相关功能的单元测试。

**主要功能列举:**

1. **符号管理:**
   - 创建和查找符号 (`LookupOrCreateSym`, `CreateStaticSym`)
   - 添加从目标文件读取的符号 (`addDummyObjSym`)
   - 获取和设置符号的各种属性 (类型, 可达性, 可见性, 值, 对齐方式, 是否在列表中, 是否允许重复)
   - 获取符号的名称 (`SymName`)
   - 判断是否为反射方法 (`IsReflectMethod`)

2. **符号数据管理:**
   - 向符号添加字节数据 (`AddBytes`)
   - 以特定字节大小添加无符号整数 (`AddUint8`, `AddUintXX`)
   - 设置指定偏移量的字节数据 (`SetUint8`)
   - 添加字符串数据 (`Addstring`)
   - 添加不同类型的地址 (绝对地址, 代码段相对地址, PE 镜像相对地址) (`AddAddrPlus`, `AddAddrPlus4`, `AddCURelativeAddrPlus`, `AddPEImageRelativeAddrPlus`)
   - 获取符号的数据 (`Data`)

3. **重定位管理:**
   - 向符号添加重定位信息 (`AddRel`)
   - 获取符号的重定位信息列表 (`Relocs`)

4. **内部符号管理 (Outer/Sub Symbols):**
   - 建立外部符号和内部符号的关系 (`AddInteriorSym`)
   - 获取符号的外部符号 (`OuterSym`)
   - 获取符号的第一个内部符号 (`SubSym`)
   - 对内部符号进行排序 (`SortSub`)
   - 设置和获取符号的值 (`SetSymValue`, `SymValue`) 用于排序

**它是什么Go语言功能的实现 (推断):**

这段代码实现的是 Go 语言链接器中用于加载和管理符号表的关键部分。链接器的主要任务之一是将多个编译后的目标文件（`.o` 文件）链接成一个可执行文件或共享库。在这个过程中，链接器需要读取这些目标文件中的符号信息，解决符号之间的引用关系，并最终确定每个符号在最终文件中的地址。

`Loader` 类型很可能就是负责在链接过程中维护这个符号表的结构。它提供了添加、查找、修改和查询符号信息的接口。

**Go 代码举例说明:**

以下代码示例展示了 `Loader` 的一些基本用法，灵感来源于测试代码：

```go
package main

import (
	"cmd/link/internal/loader"
	"cmd/link/internal/sym"
	"fmt"
	"testing"
)

func main() {
	// 模拟测试环境
	t := &testing.T{}
	ldr := loader.NewLoader(0, &loader.ErrorReporter{})

	// 创建一个外部符号
	extSym := ldr.LookupOrCreateSym("my_global_variable", 0)
	if extSym == 0 {
		fmt.Println("创建符号失败")
		return
	}

	// 获取符号的构建器
	sb := ldr.MakeSymbolUpdater(extSym)

	// 设置符号类型为数据
	sb.SetType(sym.SDATA)

	// 添加一些数据
	data := []byte{0x01, 0x02, 0x03, 0x04}
	sb.AddBytes(data)

	// 创建另一个符号用于重定位
	targetSym := ldr.LookupOrCreateSym("target_function", 0)
	if targetSym == 0 {
		fmt.Println("创建目标符号失败")
		return
	}

	// 添加一个重定位条目，指向 target_function
	rel, _ := sb.AddRel(0) // 假设 0 代表某种地址类型的重定位
	rel.SetOff(0)         // 重定位应用于数据的起始位置
	rel.SetSiz(4)         // 重定位的大小为 4 字节
	rel.SetSym(targetSym)

	// 获取符号的数据和重定位信息
	loadedData := ldr.Data(extSym)
	loadedRelocs := ldr.Relocs(extSym)

	fmt.Printf("符号数据: %v\n", loadedData)
	fmt.Printf("重定位信息: %+v\n", loadedRelocs)
}
```

**假设的输入与输出:**

虽然上面的例子是纯 Go 代码，但如果我们将 `Loader` 的使用场景放到链接器的上下文中，假设我们有两个编译后的目标文件 `a.o` 和 `b.o`：

**`a.o` 包含:**

- 符号 `my_global_variable` (未定义)
- 符号 `main.main` (已定义)

**`b.o` 包含:**

- 符号 `my_global_variable` (已定义，数据为 `[0x10, 0x20, 0x30, 0x40]`)

**使用 `Loader` 进行链接的 (简化) 过程:**

1. 链接器首先会创建 `Loader` 实例。
2. 它会读取 `a.o`，并调用类似 `addDummyObjSym` 的方法将 `my_global_variable` 和 `main.main` 添加到 `Loader` 的符号表中。此时 `my_global_variable` 可能是未定义的。
3. 接着，链接器读取 `b.o`，也会尝试添加 `my_global_variable`。 由于 `LookupOrCreateSym` 的存在，如果符号已经存在，则会返回已存在的符号。
4. 链接器会处理 `b.o` 中 `my_global_variable` 的定义，使用 `MakeSymbolUpdater` 和 `AddBytes` 将数据 `[0x10, 0x20, 0x30, 0x40]` 添加到 `Loader` 中 `my_global_variable` 对应的符号信息中。
5. 如果 `a.o` 中有对 `my_global_variable` 的引用 (例如，通过重定位)，链接器会利用 `Loader` 中存储的符号信息来解决这个引用，确定 `my_global_variable` 在最终可执行文件中的地址，并更新相应的重定位项。

**输出 (例如 `Loader.Data(ldr.LookupOrCreateSym("my_global_variable", 0))`):**

```
[]byte{0x10, 0x20, 0x30, 0x40}
```

**命令行参数的具体处理:**

这段代码本身 (`loader_test.go`) 并不直接处理命令行参数。 `Loader` 类型是在链接器的内部使用的，链接器的命令行参数处理逻辑在 `cmd/link/internal/link` 等其他包中。

链接器通常会接收以下类型的命令行参数：

- **输入文件:**  目标文件 (`.o`) 的路径。
- **输出文件:**  最终生成的可执行文件或共享库的路径。
- **库文件路径:**  指定需要链接的库文件的路径。
- **链接模式:**  例如，生成可执行文件还是共享库。
- **平台架构相关参数:**  目标平台的架构、操作系统等。
- **优化选项:**  控制链接过程中的优化行为。

**使用者易犯错的点 (虽然这是内部包，但可以推测使用此类功能的开发者可能遇到的问题):**

1. **不正确的重定位偏移量和大小:**  在添加重定位信息时，如果 `SetOff` 和 `SetSiz` 设置不正确，会导致链接后的程序运行时访问错误的地址。例如，如果重定位的 `Off` 指向了数据中间的位置，但实际需要重定位的是整个地址，就会出错。

   ```go
   // 错误示例：假设需要重定位一个 8 字节的地址，但只设置了大小为 4
   rel, _ := sb.AddRel(0)
   rel.SetOff(0)
   rel.SetSiz(4) // 应该设置为 8
   rel.SetSym(targetSym)
   ```

2. **符号类型不匹配:**  链接器需要根据符号的类型进行不同的处理。如果符号的类型设置错误（例如，将数据符号设置为代码符号），可能会导致链接错误或运行时错误。

   ```go
   // 错误示例：将一个应该存放数据的符号错误地设置为代码类型
   sb.SetType(sym.STEXT) // 假设 STEXT 代表代码类型
   sb.AddBytes([]byte{0x01, 0x02, 0x03, 0x04}) // 这应该是数据
   ```

3. **忘记使用 `MakeSymbolUpdater` 进行修改:**  `Loader` 提供了 `MakeSymbolUpdater` 来获取用于修改符号信息的对象。直接操作 `Loader` 内部状态可能会导致数据不一致。

   ```go
   // 错误示例：尝试直接修改 Loader 内部的符号数据 (这通常是不允许或不推荐的)
   // ldr.syms[extSym].data = ... // 假设 ldr.syms 存在，这是一种不安全的操作
   ```

4. **对内部符号 (Outer/Sub) 关系理解不足:**  在处理具有内部结构的符号时，例如结构体或函数内部的局部变量，需要正确建立和理解 `OuterSym` 和 `SubSym` 的关系，否则在进行符号查找或布局时可能会出现问题。

总而言之，`go/src/cmd/link/internal/loader/loader_test.go` 通过一系列单元测试，验证了 `internal/loader` 包中 `Loader` 类型在符号管理、数据管理和重定位管理等方面的核心功能，这些功能是 Go 语言链接器实现其链接任务的关键组成部分。

### 提示词
```
这是路径为go/src/cmd/link/internal/loader/loader_test.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
```

### 源代码
```go
// Copyright 2019 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package loader

import (
	"bytes"
	"cmd/internal/goobj"
	"cmd/internal/objabi"
	"cmd/internal/sys"
	"cmd/link/internal/sym"
	"fmt"
	"testing"
)

// dummyAddSym adds the named symbol to the loader as if it had been
// read from a Go object file. Note that it allocates a global
// index without creating an associated object reader, so one can't
// do anything interesting with this symbol (such as look at its
// data or relocations).
func addDummyObjSym(t *testing.T, ldr *Loader, or *oReader, name string) Sym {
	idx := uint32(len(ldr.objSyms))
	st := loadState{l: ldr}
	return st.addSym(name, 0, or, idx, nonPkgDef, &goobj.Sym{})
}

func mkLoader() *Loader {
	er := ErrorReporter{}
	ldr := NewLoader(0, &er)
	er.ldr = ldr
	return ldr
}

func TestAddMaterializedSymbol(t *testing.T) {
	ldr := mkLoader()
	dummyOreader := oReader{version: -1, syms: make([]Sym, 100)}
	or := &dummyOreader

	// Create some syms from a dummy object file symbol to get things going.
	ts1 := addDummyObjSym(t, ldr, or, "type:uint8")
	ts2 := addDummyObjSym(t, ldr, or, "mumble")
	ts3 := addDummyObjSym(t, ldr, or, "type:string")

	// Create some external symbols.
	es1 := ldr.LookupOrCreateSym("extnew1", 0)
	if es1 == 0 {
		t.Fatalf("LookupOrCreateSym failed for extnew1")
	}
	es1x := ldr.LookupOrCreateSym("extnew1", 0)
	if es1x != es1 {
		t.Fatalf("LookupOrCreateSym lookup: expected %d got %d for second lookup", es1, es1x)
	}
	es2 := ldr.LookupOrCreateSym("go:info.type.uint8", 0)
	if es2 == 0 {
		t.Fatalf("LookupOrCreateSym failed for go.info.type.uint8")
	}
	// Create a nameless symbol
	es3 := ldr.CreateStaticSym("")
	if es3 == 0 {
		t.Fatalf("CreateStaticSym failed for nameless sym")
	}

	// Grab symbol builder pointers
	sb1 := ldr.MakeSymbolUpdater(es1)
	sb2 := ldr.MakeSymbolUpdater(es2)
	sb3 := ldr.MakeSymbolUpdater(es3)

	// Suppose we create some more symbols, which triggers a grow.
	// Make sure the symbol builder's payload pointer is valid,
	// even across a grow.
	for i := 0; i < 9999; i++ {
		ldr.CreateStaticSym("dummy")
	}

	// Check get/set symbol type
	es3typ := sb3.Type()
	if es3typ != sym.Sxxx {
		t.Errorf("SymType(es3): expected %v, got %v", sym.Sxxx, es3typ)
	}
	sb3.SetType(sym.SRODATA)
	es3typ = sb3.Type()
	if es3typ != sym.SRODATA {
		t.Errorf("SymType(es3): expected %v, got %v", sym.SRODATA, es3typ)
	}
	es3typ = ldr.SymType(es3)
	if es3typ != sym.SRODATA {
		t.Errorf("SymType(es3): expected %v, got %v", sym.SRODATA, es3typ)
	}

	// New symbols should not initially be reachable.
	if ldr.AttrReachable(es1) || ldr.AttrReachable(es2) || ldr.AttrReachable(es3) {
		t.Errorf("newly materialized symbols should not be reachable")
	}

	// ... however it should be possible to set/unset their reachability.
	ldr.SetAttrReachable(es3, true)
	if !ldr.AttrReachable(es3) {
		t.Errorf("expected reachable symbol after update")
	}
	ldr.SetAttrReachable(es3, false)
	if ldr.AttrReachable(es3) {
		t.Errorf("expected unreachable symbol after update")
	}

	// Test expansion of attr bitmaps
	for idx := 0; idx < 36; idx++ {
		es := ldr.LookupOrCreateSym(fmt.Sprintf("zext%d", idx), 0)
		if ldr.AttrOnList(es) {
			t.Errorf("expected OnList after creation")
		}
		ldr.SetAttrOnList(es, true)
		if !ldr.AttrOnList(es) {
			t.Errorf("expected !OnList after update")
		}
		if ldr.AttrDuplicateOK(es) {
			t.Errorf("expected DupOK after creation")
		}
		ldr.SetAttrDuplicateOK(es, true)
		if !ldr.AttrDuplicateOK(es) {
			t.Errorf("expected !DupOK after update")
		}
	}

	sb1 = ldr.MakeSymbolUpdater(es1)
	sb2 = ldr.MakeSymbolUpdater(es2)

	// Get/set a few other attributes
	if ldr.AttrVisibilityHidden(es3) {
		t.Errorf("expected initially not hidden")
	}
	ldr.SetAttrVisibilityHidden(es3, true)
	if !ldr.AttrVisibilityHidden(es3) {
		t.Errorf("expected hidden after update")
	}

	// Test get/set symbol value.
	toTest := []Sym{ts2, es3}
	for i, s := range toTest {
		if v := ldr.SymValue(s); v != 0 {
			t.Errorf("ldr.Value(%d): expected 0 got %d\n", s, v)
		}
		nv := int64(i + 101)
		ldr.SetSymValue(s, nv)
		if v := ldr.SymValue(s); v != nv {
			t.Errorf("ldr.SetValue(%d,%d): expected %d got %d\n", s, nv, nv, v)
		}
	}

	// Check/set alignment
	es3al := ldr.SymAlign(es3)
	if es3al != 0 {
		t.Errorf("SymAlign(es3): expected 0, got %d", es3al)
	}
	ldr.SetSymAlign(es3, 128)
	es3al = ldr.SymAlign(es3)
	if es3al != 128 {
		t.Errorf("SymAlign(es3): expected 128, got %d", es3al)
	}

	// Add some relocations to the new symbols.
	r1, _ := sb1.AddRel(objabi.R_ADDR)
	r1.SetOff(0)
	r1.SetSiz(1)
	r1.SetSym(ts1)
	r2, _ := sb1.AddRel(objabi.R_CALL)
	r2.SetOff(3)
	r2.SetSiz(8)
	r2.SetSym(ts2)
	r3, _ := sb2.AddRel(objabi.R_USETYPE)
	r3.SetOff(7)
	r3.SetSiz(1)
	r3.SetSym(ts3)

	// Add some data to the symbols.
	d1 := []byte{1, 2, 3}
	d2 := []byte{4, 5, 6, 7}
	sb1.AddBytes(d1)
	sb2.AddBytes(d2)

	// Now invoke the usual loader interfaces to make sure
	// we're getting the right things back for these symbols.
	// First relocations...
	expRel := [][]Reloc{{r1, r2}, {r3}}
	for k, sb := range []*SymbolBuilder{sb1, sb2} {
		rsl := sb.Relocs()
		exp := expRel[k]
		if !sameRelocSlice(&rsl, exp) {
			t.Errorf("expected relocs %v, got %v", exp, rsl)
		}
	}

	// ... then data.
	dat := sb2.Data()
	if !bytes.Equal(dat, d2) {
		t.Errorf("expected es2 data %v, got %v", d2, dat)
	}

	// Nameless symbol should still be nameless.
	es3name := ldr.SymName(es3)
	if "" != es3name {
		t.Errorf("expected es3 name of '', got '%s'", es3name)
	}

	// Read value of materialized symbol.
	es1val := sb1.Value()
	if 0 != es1val {
		t.Errorf("expected es1 value of 0, got %v", es1val)
	}

	// Test other misc methods
	irm := ldr.IsReflectMethod(es1)
	if 0 != es1val {
		t.Errorf("expected IsReflectMethod(es1) value of 0, got %v", irm)
	}
}

func sameRelocSlice(s1 *Relocs, s2 []Reloc) bool {
	if s1.Count() != len(s2) {
		return false
	}
	for i := 0; i < s1.Count(); i++ {
		r1 := s1.At(i)
		r2 := &s2[i]
		if r1.Sym() != r2.Sym() ||
			r1.Type() != r2.Type() ||
			r1.Off() != r2.Off() ||
			r1.Add() != r2.Add() ||
			r1.Siz() != r2.Siz() {
			return false
		}
	}
	return true
}

type addFunc func(l *Loader, s Sym, s2 Sym) Sym

func mkReloc(l *Loader, typ objabi.RelocType, off int32, siz uint8, add int64, sym Sym) Reloc {
	r := Reloc{&goobj.Reloc{}, l.extReader, l}
	r.SetType(typ)
	r.SetOff(off)
	r.SetSiz(siz)
	r.SetAdd(add)
	r.SetSym(sym)
	return r
}

func TestAddDataMethods(t *testing.T) {
	ldr := mkLoader()
	dummyOreader := oReader{version: -1, syms: make([]Sym, 100)}
	or := &dummyOreader

	// Populate loader with some symbols.
	addDummyObjSym(t, ldr, or, "type:uint8")
	ldr.LookupOrCreateSym("hello", 0)

	arch := sys.ArchAMD64
	var testpoints = []struct {
		which       string
		addDataFunc addFunc
		expData     []byte
		expKind     sym.SymKind
		expRel      []Reloc
	}{
		{
			which: "AddUint8",
			addDataFunc: func(l *Loader, s Sym, _ Sym) Sym {
				sb := l.MakeSymbolUpdater(s)
				sb.AddUint8('a')
				return s
			},
			expData: []byte{'a'},
			expKind: sym.SDATA,
		},
		{
			which: "AddUintXX",
			addDataFunc: func(l *Loader, s Sym, _ Sym) Sym {
				sb := l.MakeSymbolUpdater(s)
				sb.AddUintXX(arch, 25185, 2)
				return s
			},
			expData: []byte{'a', 'b'},
			expKind: sym.SDATA,
		},
		{
			which: "SetUint8",
			addDataFunc: func(l *Loader, s Sym, _ Sym) Sym {
				sb := l.MakeSymbolUpdater(s)
				sb.AddUint8('a')
				sb.AddUint8('b')
				sb.SetUint8(arch, 1, 'c')
				return s
			},
			expData: []byte{'a', 'c'},
			expKind: sym.SDATA,
		},
		{
			which: "AddString",
			addDataFunc: func(l *Loader, s Sym, _ Sym) Sym {
				sb := l.MakeSymbolUpdater(s)
				sb.Addstring("hello")
				return s
			},
			expData: []byte{'h', 'e', 'l', 'l', 'o', 0},
			expKind: sym.SNOPTRDATA,
		},
		{
			which: "AddAddrPlus",
			addDataFunc: func(l *Loader, s Sym, s2 Sym) Sym {
				sb := l.MakeSymbolUpdater(s)
				sb.AddAddrPlus(arch, s2, 3)
				return s
			},
			expData: []byte{0, 0, 0, 0, 0, 0, 0, 0},
			expKind: sym.SDATA,
			expRel:  []Reloc{mkReloc(ldr, objabi.R_ADDR, 0, 8, 3, 6)},
		},
		{
			which: "AddAddrPlus4",
			addDataFunc: func(l *Loader, s Sym, s2 Sym) Sym {
				sb := l.MakeSymbolUpdater(s)
				sb.AddAddrPlus4(arch, s2, 3)
				return s
			},
			expData: []byte{0, 0, 0, 0},
			expKind: sym.SDATA,
			expRel:  []Reloc{mkReloc(ldr, objabi.R_ADDR, 0, 4, 3, 7)},
		},
		{
			which: "AddCURelativeAddrPlus",
			addDataFunc: func(l *Loader, s Sym, s2 Sym) Sym {
				sb := l.MakeSymbolUpdater(s)
				sb.AddCURelativeAddrPlus(arch, s2, 7)
				return s
			},
			expData: []byte{0, 0, 0, 0, 0, 0, 0, 0},
			expKind: sym.SDATA,
			expRel:  []Reloc{mkReloc(ldr, objabi.R_ADDRCUOFF, 0, 8, 7, 8)},
		},
		{
			which: "AddPEImageRelativeAddrPlus",
			addDataFunc: func(l *Loader, s Sym, s2 Sym) Sym {
				sb := l.MakeSymbolUpdater(s)
				sb.AddPEImageRelativeAddrPlus(arch, s2, 3)
				return s
			},
			expData: []byte{0, 0, 0, 0},
			expKind: sym.SDATA,
			expRel:  []Reloc{mkReloc(ldr, objabi.R_PEIMAGEOFF, 0, 4, 3, 9)},
		},
	}

	var pmi Sym
	for k, tp := range testpoints {
		name := fmt.Sprintf("new%d", k+1)
		mi := ldr.LookupOrCreateSym(name, 0)
		if mi == 0 {
			t.Fatalf("LookupOrCreateSym failed for %q", name)
		}
		mi = tp.addDataFunc(ldr, mi, pmi)
		if ldr.SymType(mi) != tp.expKind {
			t.Errorf("testing Loader.%s: expected kind %s got %s",
				tp.which, tp.expKind, ldr.SymType(mi))
		}
		if !bytes.Equal(ldr.Data(mi), tp.expData) {
			t.Errorf("testing Loader.%s: expected data %v got %v",
				tp.which, tp.expData, ldr.Data(mi))
		}
		relocs := ldr.Relocs(mi)
		if !sameRelocSlice(&relocs, tp.expRel) {
			t.Fatalf("testing Loader.%s: got relocslice %+v wanted %+v",
				tp.which, relocs, tp.expRel)
		}
		pmi = mi
	}
}

func TestOuterSub(t *testing.T) {
	ldr := mkLoader()
	dummyOreader := oReader{version: -1, syms: make([]Sym, 100)}
	or := &dummyOreader

	// Populate loader with some symbols.
	addDummyObjSym(t, ldr, or, "type:uint8")
	es1 := ldr.LookupOrCreateSym("outer", 0)
	ldr.MakeSymbolUpdater(es1).SetSize(101)
	es2 := ldr.LookupOrCreateSym("sub1", 0)
	es3 := ldr.LookupOrCreateSym("sub2", 0)
	es4 := ldr.LookupOrCreateSym("sub3", 0)
	es5 := ldr.LookupOrCreateSym("sub4", 0)
	es6 := ldr.LookupOrCreateSym("sub5", 0)

	// Should not have an outer sym initially
	if ldr.OuterSym(es1) != 0 {
		t.Errorf("es1 outer sym set ")
	}
	if ldr.SubSym(es2) != 0 {
		t.Errorf("es2 outer sym set ")
	}

	// Establish first outer/sub relationship
	ldr.AddInteriorSym(es1, es2)
	if ldr.OuterSym(es1) != 0 {
		t.Errorf("ldr.OuterSym(es1) got %d wanted %d", ldr.OuterSym(es1), 0)
	}
	if ldr.OuterSym(es2) != es1 {
		t.Errorf("ldr.OuterSym(es2) got %d wanted %d", ldr.OuterSym(es2), es1)
	}
	if ldr.SubSym(es1) != es2 {
		t.Errorf("ldr.SubSym(es1) got %d wanted %d", ldr.SubSym(es1), es2)
	}
	if ldr.SubSym(es2) != 0 {
		t.Errorf("ldr.SubSym(es2) got %d wanted %d", ldr.SubSym(es2), 0)
	}

	// Establish second outer/sub relationship
	ldr.AddInteriorSym(es1, es3)
	if ldr.OuterSym(es1) != 0 {
		t.Errorf("ldr.OuterSym(es1) got %d wanted %d", ldr.OuterSym(es1), 0)
	}
	if ldr.OuterSym(es2) != es1 {
		t.Errorf("ldr.OuterSym(es2) got %d wanted %d", ldr.OuterSym(es2), es1)
	}
	if ldr.OuterSym(es3) != es1 {
		t.Errorf("ldr.OuterSym(es3) got %d wanted %d", ldr.OuterSym(es3), es1)
	}
	if ldr.SubSym(es1) != es3 {
		t.Errorf("ldr.SubSym(es1) got %d wanted %d", ldr.SubSym(es1), es3)
	}
	if ldr.SubSym(es3) != es2 {
		t.Errorf("ldr.SubSym(es3) got %d wanted %d", ldr.SubSym(es3), es2)
	}

	// Some more
	ldr.AddInteriorSym(es1, es4)
	ldr.AddInteriorSym(es1, es5)
	ldr.AddInteriorSym(es1, es6)

	// Set values.
	ldr.SetSymValue(es2, 7)
	ldr.SetSymValue(es3, 1)
	ldr.SetSymValue(es4, 13)
	ldr.SetSymValue(es5, 101)
	ldr.SetSymValue(es6, 3)

	// Sort
	news := ldr.SortSub(es1)
	if news != es3 {
		t.Errorf("ldr.SortSub leader got %d wanted %d", news, es3)
	}
	pv := int64(-1)
	count := 0
	for ss := ldr.SubSym(es1); ss != 0; ss = ldr.SubSym(ss) {
		v := ldr.SymValue(ss)
		if v <= pv {
			t.Errorf("ldr.SortSub sortfail at %d: val %d >= prev val %d",
				ss, v, pv)
		}
		pv = v
		count++
	}
	if count != 5 {
		t.Errorf("expected %d in sub list got %d", 5, count)
	}
}
```