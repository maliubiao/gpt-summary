Response:
Let's break down the thought process for analyzing this Go code snippet.

1. **Understand the Goal:** The request asks for the functionality of the provided Go code, its purpose in the Go runtime, illustrative examples, potential issues, and to be in Chinese.

2. **Initial Scan and Keywords:**  Quickly scan the code for prominent keywords and data structures. Terms like `itab`, `interfacetype`, `_type`, `itabTable`, `getitab`, `convT`, `assertE2I`, and function names like `itabAdd`, `itabInit`, `interfaceSwitch` stand out. These immediately suggest this code is related to interface implementation and type assertions in Go.

3. **Identify Core Data Structures:**
    * **`itab`:** This structure likely represents the concrete implementation of an interface by a specific type. The `Inter` and `Type` fields confirm this. The `Fun` field probably holds the actual method implementations.
    * **`interfacetype`:** Represents an interface type definition. The `Methods` field is a key indicator.
    * **`_type`:** Represents the runtime type information for any Go type (struct, int, etc.).
    * **`itabTableType`:**  A hash table (or similar structure) for efficiently looking up `itab` instances. The `entries` field and the `find` method strongly suggest this.

4. **Trace Key Functions:** Focus on the most important functions and how they interact.
    * **`getitab`:**  This seems like the central function for retrieving or creating an `itab`. The logic involving looking in the `itabTable`, locking, and creating new `itab`s is crucial. The `canfail` parameter hints at its use in type assertions with the `, ok` syntax.
    * **`itabAdd`:** Responsible for adding new `itab`s to the `itabTable`. The resizing logic with `mallocgc` is noteworthy.
    * **`itabInit`:**  Populates the `Fun` array of an `itab` with the correct method pointers. The logic of matching interface methods with type methods is important.
    * **`convT` family:**  Functions like `convT`, `convTstring`, `convTslice` seem to handle conversions to interface values. The `mallocgc` calls and the handling of small values via `staticuint64s` are interesting details.
    * **`assertE2I` family:**  These functions clearly handle type assertions (e.g., `i.(T)`). The potential for panics is highlighted.
    * **`interfaceSwitch`:** This function is clearly related to type switches. The caching mechanism with `InterfaceSwitchCache` is a performance optimization.

5. **Infer Functionality:** Based on the data structures and key functions, start piecing together the overall functionality. This code manages the runtime representation of how concrete types implement interfaces. It handles looking up existing implementations, creating new ones, and efficiently accessing the correct methods. Type assertions and type switches are central to its purpose.

6. **Develop Illustrative Examples:**  Think about how these concepts manifest in Go code.
    * **Interface Implementation:** A simple interface and a struct that implements it. Demonstrate the implicit nature of interface satisfaction.
    * **Type Assertion:** Show both the single-result and two-result forms of type assertions, illustrating the potential for panics.
    * **Type Switch:**  Demonstrate how a `switch` statement on an interface variable works, highlighting the different cases.

7. **Address Potential Issues:**  Consider common mistakes or complexities. The use of `getitab` via `linkname` is a red flag. The potential for panics in type assertions is also a point to emphasize.

8. **Structure the Answer:** Organize the information logically. Start with a high-level overview of the functionality. Then delve into specific functions and their roles. Use clear headings and bullet points. Provide code examples to illustrate the concepts.

9. **Refine and Translate:** Review the answer for clarity and accuracy. Ensure the code examples are correct and easy to understand. Translate the entire response into Chinese, paying attention to technical terms. For example, `itab` can be explained as "接口类型表" or kept as `itab`. `interfacetype` is "接口类型". `_type` is "类型信息". `Type Assertion` is "类型断言". `Type Switch` is "类型选择".

10. **Self-Correction/Refinement during the process:**
    * **Initial thought:** Maybe `itabTable` is just a simple slice. **Correction:** The `find` method with its probing logic indicates it's a hash table.
    * **Initial thought:** `convT` is just about memory allocation. **Correction:**  It also involves copying data and potentially using optimized paths for small integers and empty strings/slices.
    * **Realization:** The comments about `linkname` and "hall of shame" highlight a pragmatic but potentially fragile aspect of the implementation, worth mentioning as a potential point of misuse.

By following these steps, combining code analysis, knowledge of Go's runtime, and a structured approach, it's possible to generate a comprehensive and accurate explanation of the provided code snippet. The iterative nature of thinking and refining is key to arriving at a good answer.
这段代码是 Go 语言运行时（runtime）中 `iface.go` 文件的一部分，主要负责**接口（interface）的动态类型和方法调度的实现**。

更具体地说，它实现了以下功能：

1. **`itab` 的管理和查找:**
   - **`itab` (interface table):**  `itab` 结构体是接口实现的核心。它存储了特定类型（concrete type）如何实现特定接口的信息。主要包含：
     - `Inter`: 指向接口类型 (`interfacetype`) 的指针。
     - `Type`: 指向具体类型 (`_type`) 的指针。
     - `Hash`: 用于类型 switch 的哈希值（注意：不是 `itabTable` 的哈希）。
     - `Fun`: 一个函数指针数组，存储了具体类型实现接口方法的地址。
   - **`itabTable`:** 一个全局的哈希表，用于缓存已经创建的 `itab` 实例。这样可以避免重复创建相同的接口实现信息，提高性能。
   - **`getitab(inter *interfacetype, typ *_type, canfail bool) *itab`:**  这是获取 `itab` 的核心函数。它首先尝试在 `itabTable` 中查找是否存在 `inter` 和 `typ` 对应的 `itab`。如果找到则直接返回，否则会创建一个新的 `itab` 并添加到 `itabTable` 中。`canfail` 参数用于指示在类型断言失败时是否应该 panic。
   - **`itabAdd(m *itab)`:** 将一个新的 `itab` 添加到 `itabTable` 中。如果 `itabTable` 快满了，它会进行扩容。
   - **`itabInit(m *itab, firstTime bool) string`:** 初始化 `itab` 的 `Fun` 数组。它会比较接口的方法列表和具体类型的方法列表，找到匹配的方法并将具体类型的方法地址填入 `m.Fun` 中。如果具体类型没有实现接口的所有方法，它会返回缺失的方法名。

2. **类型断言 (Type Assertion) 的实现:**
   - **`assertE2I(inter *interfacetype, t *_type) *itab`:**  用于将一个具体类型 `t` 的值转换为接口类型 `inter`。如果 `t` 为 `nil`，则会 panic。它内部调用 `getitab` 获取或创建 `itab`。
   - **`assertE2I2(inter *interfacetype, t *_type) *itab`:** 与 `assertE2I` 类似，但如果 `t` 为 `nil`，则返回 `nil`，不会 panic。这对应于类型断言的 `, ok` 形式。
   - **`typeAssert(s *abi.TypeAssert, t *_type) *itab`:**  更底层的类型断言实现，用于编译器生成的代码。它也使用 `getitab` 并可能更新类型断言的缓存 (`abi.TypeAssertCache`) 以提高后续相同类型断言的性能。
   - **`panicdottypeE(have, want, iface *_type)` 和 `panicdottypeI(have *itab, want, iface *_type)`:**  当类型断言失败时触发的 panic 函数。

3. **类型选择 (Type Switch) 的实现:**
   - **`interfaceSwitch(s *abi.InterfaceSwitch, t *_type) (int, *itab)`:**  用于实现 `switch` 语句中对接口类型的判断。它会遍历 `switch` 语句中的 `case`，尝试将接口的动态类型 `t` 转换为 `case` 中指定的接口类型。如果匹配成功，则返回 `case` 的索引和对应的 `itab`。它也使用了缓存 (`abi.InterfaceSwitchCache`) 来优化性能。

4. **值到接口的转换 (`convT` 系列函数):**
   - **`convT(t *_type, v unsafe.Pointer) unsafe.Pointer`:** 将指向类型 `t` 的值 `v` 转换为可以作为接口值第二部分的指针。它会分配内存并将值复制过去。
   - **`convTnoptr(t *_type, v unsafe.Pointer) unsafe.Pointer`:**  与 `convT` 类似，但它告诉内存分配器分配的内存不包含指针。
   - **`convT16(val uint16) unsafe.Pointer`, `convT32(val uint32) unsafe.Pointer`, `convT64(val uint64) unsafe.Pointer`, `convTstring(val string) unsafe.Pointer`, `convTslice(val []byte) unsafe.Pointer`:** 针对特定类型的优化转换函数，对于小整数和空字符串/切片使用了静态分配的内存。

**它是什么 Go 语言功能的实现？**

这段代码是 Go 语言**接口 (interface)** 功能的核心实现部分。接口是 Go 语言中实现多态的关键机制。它允许你定义一组方法签名，而不需要指定具体的实现。具体类型只要实现了接口定义的所有方法，就被认为是实现了该接口。

**Go 代码举例说明:**

```go
package main

import "fmt"

// 定义一个接口
type Animal interface {
	Speak() string
}

// 定义一个结构体类型
type Dog struct {
	Name string
}

func (d Dog) Speak() string {
	return "Woof!"
}

// 定义另一个结构体类型
type Cat struct {
	Name string
}

func (c Cat) Speak() string {
	return "Meow!"
}

func main() {
	// 创建 Dog 实例并赋值给 Animal 接口
	var animal1 Animal = Dog{Name: "Buddy"}
	fmt.Println(animal1.Speak()) // 输出: Woof!

	// 创建 Cat 实例并赋值给 Animal 接口
	var animal2 Animal = Cat{Name: "Whiskers"}
	fmt.Println(animal2.Speak()) // 输出: Meow!

	// 类型断言
	dog, ok := animal1.(Dog)
	if ok {
		fmt.Println("Animal 1 is a dog, name:", dog.Name) // 输出: Animal 1 is a dog, name: Buddy
	}

	// 类型选择
	describeAnimal(animal2) // 输出: Animal 2 is a Cat
}

func describeAnimal(animal Animal) {
	switch v := animal.(type) {
	case Dog:
		fmt.Println("Animal is a Dog")
	case Cat:
		fmt.Println("Animal is a Cat")
	default:
		fmt.Printf("Animal is of type %T\n", v)
	}
}
```

**代码推理 (假设的输入与输出):**

假设 `getitab` 函数被调用，传入一个 `Animal` 接口的 `interfacetype` 指针和一个 `Dog` 类型的 `_type` 指针，并且 `itabTable` 中还没有对应的 `itab`。

**假设输入:**

- `inter`: 指向 `Animal` 接口的 `interfacetype` 结构体。
- `typ`: 指向 `Dog` 类型的 `_type` 结构体。
- `canfail`: `false`

**推理过程:**

1. `getitab` 首先检查 `itabTable` 中是否已存在 `Animal` 和 `Dog` 的 `itab`。由于是假设 `itabTable` 中没有，所以查找失败。
2. 获取 `itabLock` 互斥锁。
3. 再次检查 `itabTable`，仍然没有找到。
4. 分配一个新的 `itab` 结构体的内存。
5. 初始化 `itab` 的 `Inter` 指向 `Animal` 的 `interfacetype`，`Type` 指向 `Dog` 的 `_type`。
6. 调用 `itabInit` 初始化 `itab` 的 `Fun` 数组。`itabInit` 会找到 `Dog` 类型中 `Speak()` 方法的地址，并将其存储到 `itab.Fun` 的相应位置。
7. 调用 `itabAdd` 将新创建的 `itab` 添加到 `itabTable` 中。
8. 释放 `itabLock` 互斥锁。
9. 返回新创建的 `itab` 指针。

**假设输出:**

- 返回一个指向新创建的 `itab` 结构体的指针，该 `itab` 结构体的 `Inter` 指向 `Animal`，`Type` 指向 `Dog`，并且 `Fun` 数组中包含了 `Dog.Speak` 方法的地址。

**命令行参数的具体处理:**

这段代码本身并不直接处理命令行参数。命令行参数的处理通常发生在 `os` 包和 `flag` 包中。这段代码是 Go 语言运行时的一部分，负责底层的接口实现机制，不会直接接触到命令行参数。

**使用者易犯错的点:**

1. **直接访问 `getitab` (通过 `//go:linkname`):** 代码注释中明确指出 `getitab` 应该是内部细节，但是一些第三方库（如 `github.com/bytedance/sonic`）通过 `//go:linkname` 这种非官方的方式直接访问它。这样做是不推荐的，因为它依赖于 Go 内部实现的细节，可能会在 Go 版本升级时失效，导致程序崩溃或其他不可预测的行为。

   ```go
   // 错误示例 (不应该这样做)
   //go:linkname internalGetitab runtime.getitab
   //func internalGetitab(inter *runtime.interfacetype, typ *_type, canfail bool) *runtime.itab {
   //  // ...
   //}
   ```

2. **对类型断言不进行错误处理:**  当进行类型断言时，如果不使用 `, ok` 的形式，而是直接进行断言，如果断言失败会引发 panic。使用者容易忘记进行错误处理，导致程序意外终止。

   ```go
   var animal Animal = Dog{}
   cat := animal.(Cat) // 如果 animal 的实际类型不是 Cat，这里会 panic
   fmt.Println(cat)

   // 正确的做法是使用 `, ok` 进行错误处理
   cat, ok := animal.(Cat)
   if ok {
       fmt.Println("It's a cat:", cat)
   } else {
       fmt.Println("It's not a cat")
   }
   ```

总而言之，这段 `iface.go` 代码是 Go 语言实现接口和类型断言等关键特性的基础，它通过管理 `itab` 结构和 `itabTable`，实现了接口的动态绑定和方法查找，是 Go 语言运行时中非常重要的组成部分。开发者通常不需要直接与这段代码交互，但理解其背后的原理有助于更好地理解 Go 语言的接口机制。

Prompt: 
```
这是路径为go/src/runtime/iface.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。

"""
// Copyright 2014 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package runtime

import (
	"internal/abi"
	"internal/goarch"
	"internal/runtime/atomic"
	"internal/runtime/sys"
	"unsafe"
)

const itabInitSize = 512

var (
	itabLock      mutex                               // lock for accessing itab table
	itabTable     = &itabTableInit                    // pointer to current table
	itabTableInit = itabTableType{size: itabInitSize} // starter table
)

// Note: change the formula in the mallocgc call in itabAdd if you change these fields.
type itabTableType struct {
	size    uintptr             // length of entries array. Always a power of 2.
	count   uintptr             // current number of filled entries.
	entries [itabInitSize]*itab // really [size] large
}

func itabHashFunc(inter *interfacetype, typ *_type) uintptr {
	// compiler has provided some good hash codes for us.
	return uintptr(inter.Type.Hash ^ typ.Hash)
}

// getitab should be an internal detail,
// but widely used packages access it using linkname.
// Notable members of the hall of shame include:
//   - github.com/bytedance/sonic
//
// Do not remove or change the type signature.
// See go.dev/issue/67401.
//
//go:linkname getitab
func getitab(inter *interfacetype, typ *_type, canfail bool) *itab {
	if len(inter.Methods) == 0 {
		throw("internal error - misuse of itab")
	}

	// easy case
	if typ.TFlag&abi.TFlagUncommon == 0 {
		if canfail {
			return nil
		}
		name := toRType(&inter.Type).nameOff(inter.Methods[0].Name)
		panic(&TypeAssertionError{nil, typ, &inter.Type, name.Name()})
	}

	var m *itab

	// First, look in the existing table to see if we can find the itab we need.
	// This is by far the most common case, so do it without locks.
	// Use atomic to ensure we see any previous writes done by the thread
	// that updates the itabTable field (with atomic.Storep in itabAdd).
	t := (*itabTableType)(atomic.Loadp(unsafe.Pointer(&itabTable)))
	if m = t.find(inter, typ); m != nil {
		goto finish
	}

	// Not found.  Grab the lock and try again.
	lock(&itabLock)
	if m = itabTable.find(inter, typ); m != nil {
		unlock(&itabLock)
		goto finish
	}

	// Entry doesn't exist yet. Make a new entry & add it.
	m = (*itab)(persistentalloc(unsafe.Sizeof(itab{})+uintptr(len(inter.Methods)-1)*goarch.PtrSize, 0, &memstats.other_sys))
	m.Inter = inter
	m.Type = typ
	// The hash is used in type switches. However, compiler statically generates itab's
	// for all interface/type pairs used in switches (which are added to itabTable
	// in itabsinit). The dynamically-generated itab's never participate in type switches,
	// and thus the hash is irrelevant.
	// Note: m.Hash is _not_ the hash used for the runtime itabTable hash table.
	m.Hash = 0
	itabInit(m, true)
	itabAdd(m)
	unlock(&itabLock)
finish:
	if m.Fun[0] != 0 {
		return m
	}
	if canfail {
		return nil
	}
	// this can only happen if the conversion
	// was already done once using the , ok form
	// and we have a cached negative result.
	// The cached result doesn't record which
	// interface function was missing, so initialize
	// the itab again to get the missing function name.
	panic(&TypeAssertionError{concrete: typ, asserted: &inter.Type, missingMethod: itabInit(m, false)})
}

// find finds the given interface/type pair in t.
// Returns nil if the given interface/type pair isn't present.
func (t *itabTableType) find(inter *interfacetype, typ *_type) *itab {
	// Implemented using quadratic probing.
	// Probe sequence is h(i) = h0 + i*(i+1)/2 mod 2^k.
	// We're guaranteed to hit all table entries using this probe sequence.
	mask := t.size - 1
	h := itabHashFunc(inter, typ) & mask
	for i := uintptr(1); ; i++ {
		p := (**itab)(add(unsafe.Pointer(&t.entries), h*goarch.PtrSize))
		// Use atomic read here so if we see m != nil, we also see
		// the initializations of the fields of m.
		// m := *p
		m := (*itab)(atomic.Loadp(unsafe.Pointer(p)))
		if m == nil {
			return nil
		}
		if m.Inter == inter && m.Type == typ {
			return m
		}
		h += i
		h &= mask
	}
}

// itabAdd adds the given itab to the itab hash table.
// itabLock must be held.
func itabAdd(m *itab) {
	// Bugs can lead to calling this while mallocing is set,
	// typically because this is called while panicking.
	// Crash reliably, rather than only when we need to grow
	// the hash table.
	if getg().m.mallocing != 0 {
		throw("malloc deadlock")
	}

	t := itabTable
	if t.count >= 3*(t.size/4) { // 75% load factor
		// Grow hash table.
		// t2 = new(itabTableType) + some additional entries
		// We lie and tell malloc we want pointer-free memory because
		// all the pointed-to values are not in the heap.
		t2 := (*itabTableType)(mallocgc((2+2*t.size)*goarch.PtrSize, nil, true))
		t2.size = t.size * 2

		// Copy over entries.
		// Note: while copying, other threads may look for an itab and
		// fail to find it. That's ok, they will then try to get the itab lock
		// and as a consequence wait until this copying is complete.
		iterate_itabs(t2.add)
		if t2.count != t.count {
			throw("mismatched count during itab table copy")
		}
		// Publish new hash table. Use an atomic write: see comment in getitab.
		atomicstorep(unsafe.Pointer(&itabTable), unsafe.Pointer(t2))
		// Adopt the new table as our own.
		t = itabTable
		// Note: the old table can be GC'ed here.
	}
	t.add(m)
}

// add adds the given itab to itab table t.
// itabLock must be held.
func (t *itabTableType) add(m *itab) {
	// See comment in find about the probe sequence.
	// Insert new itab in the first empty spot in the probe sequence.
	mask := t.size - 1
	h := itabHashFunc(m.Inter, m.Type) & mask
	for i := uintptr(1); ; i++ {
		p := (**itab)(add(unsafe.Pointer(&t.entries), h*goarch.PtrSize))
		m2 := *p
		if m2 == m {
			// A given itab may be used in more than one module
			// and thanks to the way global symbol resolution works, the
			// pointed-to itab may already have been inserted into the
			// global 'hash'.
			return
		}
		if m2 == nil {
			// Use atomic write here so if a reader sees m, it also
			// sees the correctly initialized fields of m.
			// NoWB is ok because m is not in heap memory.
			// *p = m
			atomic.StorepNoWB(unsafe.Pointer(p), unsafe.Pointer(m))
			t.count++
			return
		}
		h += i
		h &= mask
	}
}

// itabInit fills in the m.Fun array with all the code pointers for
// the m.Inter/m.Type pair. If the type does not implement the interface,
// it sets m.Fun[0] to 0 and returns the name of an interface function that is missing.
// If !firstTime, itabInit will not write anything to m.Fun (see issue 65962).
// It is ok to call this multiple times on the same m, even concurrently
// (although it will only be called once with firstTime==true).
func itabInit(m *itab, firstTime bool) string {
	inter := m.Inter
	typ := m.Type
	x := typ.Uncommon()

	// both inter and typ have method sorted by name,
	// and interface names are unique,
	// so can iterate over both in lock step;
	// the loop is O(ni+nt) not O(ni*nt).
	ni := len(inter.Methods)
	nt := int(x.Mcount)
	xmhdr := (*[1 << 16]abi.Method)(add(unsafe.Pointer(x), uintptr(x.Moff)))[:nt:nt]
	j := 0
	methods := (*[1 << 16]unsafe.Pointer)(unsafe.Pointer(&m.Fun[0]))[:ni:ni]
	var fun0 unsafe.Pointer
imethods:
	for k := 0; k < ni; k++ {
		i := &inter.Methods[k]
		itype := toRType(&inter.Type).typeOff(i.Typ)
		name := toRType(&inter.Type).nameOff(i.Name)
		iname := name.Name()
		ipkg := pkgPath(name)
		if ipkg == "" {
			ipkg = inter.PkgPath.Name()
		}
		for ; j < nt; j++ {
			t := &xmhdr[j]
			rtyp := toRType(typ)
			tname := rtyp.nameOff(t.Name)
			if rtyp.typeOff(t.Mtyp) == itype && tname.Name() == iname {
				pkgPath := pkgPath(tname)
				if pkgPath == "" {
					pkgPath = rtyp.nameOff(x.PkgPath).Name()
				}
				if tname.IsExported() || pkgPath == ipkg {
					ifn := rtyp.textOff(t.Ifn)
					if k == 0 {
						fun0 = ifn // we'll set m.Fun[0] at the end
					} else if firstTime {
						methods[k] = ifn
					}
					continue imethods
				}
			}
		}
		// didn't find method
		// Leaves m.Fun[0] set to 0.
		return iname
	}
	if firstTime {
		m.Fun[0] = uintptr(fun0)
	}
	return ""
}

func itabsinit() {
	lockInit(&itabLock, lockRankItab)
	lock(&itabLock)
	for _, md := range activeModules() {
		for _, i := range md.itablinks {
			itabAdd(i)
		}
	}
	unlock(&itabLock)
}

// panicdottypeE is called when doing an e.(T) conversion and the conversion fails.
// have = the dynamic type we have.
// want = the static type we're trying to convert to.
// iface = the static type we're converting from.
func panicdottypeE(have, want, iface *_type) {
	panic(&TypeAssertionError{iface, have, want, ""})
}

// panicdottypeI is called when doing an i.(T) conversion and the conversion fails.
// Same args as panicdottypeE, but "have" is the dynamic itab we have.
func panicdottypeI(have *itab, want, iface *_type) {
	var t *_type
	if have != nil {
		t = have.Type
	}
	panicdottypeE(t, want, iface)
}

// panicnildottype is called when doing an i.(T) conversion and the interface i is nil.
// want = the static type we're trying to convert to.
func panicnildottype(want *_type) {
	panic(&TypeAssertionError{nil, nil, want, ""})
	// TODO: Add the static type we're converting from as well.
	// It might generate a better error message.
	// Just to match other nil conversion errors, we don't for now.
}

// The specialized convTx routines need a type descriptor to use when calling mallocgc.
// We don't need the type to be exact, just to have the correct size, alignment, and pointer-ness.
// However, when debugging, it'd be nice to have some indication in mallocgc where the types came from,
// so we use named types here.
// We then construct interface values of these types,
// and then extract the type word to use as needed.
type (
	uint16InterfacePtr uint16
	uint32InterfacePtr uint32
	uint64InterfacePtr uint64
	stringInterfacePtr string
	sliceInterfacePtr  []byte
)

var (
	uint16Eface any = uint16InterfacePtr(0)
	uint32Eface any = uint32InterfacePtr(0)
	uint64Eface any = uint64InterfacePtr(0)
	stringEface any = stringInterfacePtr("")
	sliceEface  any = sliceInterfacePtr(nil)

	uint16Type *_type = efaceOf(&uint16Eface)._type
	uint32Type *_type = efaceOf(&uint32Eface)._type
	uint64Type *_type = efaceOf(&uint64Eface)._type
	stringType *_type = efaceOf(&stringEface)._type
	sliceType  *_type = efaceOf(&sliceEface)._type
)

// The conv and assert functions below do very similar things.
// The convXXX functions are guaranteed by the compiler to succeed.
// The assertXXX functions may fail (either panicking or returning false,
// depending on whether they are 1-result or 2-result).
// The convXXX functions succeed on a nil input, whereas the assertXXX
// functions fail on a nil input.

// convT converts a value of type t, which is pointed to by v, to a pointer that can
// be used as the second word of an interface value.
func convT(t *_type, v unsafe.Pointer) unsafe.Pointer {
	if raceenabled {
		raceReadObjectPC(t, v, sys.GetCallerPC(), abi.FuncPCABIInternal(convT))
	}
	if msanenabled {
		msanread(v, t.Size_)
	}
	if asanenabled {
		asanread(v, t.Size_)
	}
	x := mallocgc(t.Size_, t, true)
	typedmemmove(t, x, v)
	return x
}
func convTnoptr(t *_type, v unsafe.Pointer) unsafe.Pointer {
	// TODO: maybe take size instead of type?
	if raceenabled {
		raceReadObjectPC(t, v, sys.GetCallerPC(), abi.FuncPCABIInternal(convTnoptr))
	}
	if msanenabled {
		msanread(v, t.Size_)
	}
	if asanenabled {
		asanread(v, t.Size_)
	}

	x := mallocgc(t.Size_, t, false)
	memmove(x, v, t.Size_)
	return x
}

func convT16(val uint16) (x unsafe.Pointer) {
	if val < uint16(len(staticuint64s)) {
		x = unsafe.Pointer(&staticuint64s[val])
		if goarch.BigEndian {
			x = add(x, 6)
		}
	} else {
		x = mallocgc(2, uint16Type, false)
		*(*uint16)(x) = val
	}
	return
}

func convT32(val uint32) (x unsafe.Pointer) {
	if val < uint32(len(staticuint64s)) {
		x = unsafe.Pointer(&staticuint64s[val])
		if goarch.BigEndian {
			x = add(x, 4)
		}
	} else {
		x = mallocgc(4, uint32Type, false)
		*(*uint32)(x) = val
	}
	return
}

// convT64 should be an internal detail,
// but widely used packages access it using linkname.
// Notable members of the hall of shame include:
//   - github.com/bytedance/sonic
//
// Do not remove or change the type signature.
// See go.dev/issue/67401.
//
//go:linkname convT64
func convT64(val uint64) (x unsafe.Pointer) {
	if val < uint64(len(staticuint64s)) {
		x = unsafe.Pointer(&staticuint64s[val])
	} else {
		x = mallocgc(8, uint64Type, false)
		*(*uint64)(x) = val
	}
	return
}

// convTstring should be an internal detail,
// but widely used packages access it using linkname.
// Notable members of the hall of shame include:
//   - github.com/bytedance/sonic
//
// Do not remove or change the type signature.
// See go.dev/issue/67401.
//
//go:linkname convTstring
func convTstring(val string) (x unsafe.Pointer) {
	if val == "" {
		x = unsafe.Pointer(&zeroVal[0])
	} else {
		x = mallocgc(unsafe.Sizeof(val), stringType, true)
		*(*string)(x) = val
	}
	return
}

// convTslice should be an internal detail,
// but widely used packages access it using linkname.
// Notable members of the hall of shame include:
//   - github.com/bytedance/sonic
//
// Do not remove or change the type signature.
// See go.dev/issue/67401.
//
//go:linkname convTslice
func convTslice(val []byte) (x unsafe.Pointer) {
	// Note: this must work for any element type, not just byte.
	if (*slice)(unsafe.Pointer(&val)).array == nil {
		x = unsafe.Pointer(&zeroVal[0])
	} else {
		x = mallocgc(unsafe.Sizeof(val), sliceType, true)
		*(*[]byte)(x) = val
	}
	return
}

func assertE2I(inter *interfacetype, t *_type) *itab {
	if t == nil {
		// explicit conversions require non-nil interface value.
		panic(&TypeAssertionError{nil, nil, &inter.Type, ""})
	}
	return getitab(inter, t, false)
}

func assertE2I2(inter *interfacetype, t *_type) *itab {
	if t == nil {
		return nil
	}
	return getitab(inter, t, true)
}

// typeAssert builds an itab for the concrete type t and the
// interface type s.Inter. If the conversion is not possible it
// panics if s.CanFail is false and returns nil if s.CanFail is true.
func typeAssert(s *abi.TypeAssert, t *_type) *itab {
	var tab *itab
	if t == nil {
		if !s.CanFail {
			panic(&TypeAssertionError{nil, nil, &s.Inter.Type, ""})
		}
	} else {
		tab = getitab(s.Inter, t, s.CanFail)
	}

	if !abi.UseInterfaceSwitchCache(GOARCH) {
		return tab
	}

	// Maybe update the cache, so the next time the generated code
	// doesn't need to call into the runtime.
	if cheaprand()&1023 != 0 {
		// Only bother updating the cache ~1 in 1000 times.
		return tab
	}
	// Load the current cache.
	oldC := (*abi.TypeAssertCache)(atomic.Loadp(unsafe.Pointer(&s.Cache)))

	if cheaprand()&uint32(oldC.Mask) != 0 {
		// As cache gets larger, choose to update it less often
		// so we can amortize the cost of building a new cache.
		return tab
	}

	// Make a new cache.
	newC := buildTypeAssertCache(oldC, t, tab)

	// Update cache. Use compare-and-swap so if multiple threads
	// are fighting to update the cache, at least one of their
	// updates will stick.
	atomic_casPointer((*unsafe.Pointer)(unsafe.Pointer(&s.Cache)), unsafe.Pointer(oldC), unsafe.Pointer(newC))

	return tab
}

func buildTypeAssertCache(oldC *abi.TypeAssertCache, typ *_type, tab *itab) *abi.TypeAssertCache {
	oldEntries := unsafe.Slice(&oldC.Entries[0], oldC.Mask+1)

	// Count the number of entries we need.
	n := 1
	for _, e := range oldEntries {
		if e.Typ != 0 {
			n++
		}
	}

	// Figure out how big a table we need.
	// We need at least one more slot than the number of entries
	// so that we are guaranteed an empty slot (for termination).
	newN := n * 2                         // make it at most 50% full
	newN = 1 << sys.Len64(uint64(newN-1)) // round up to a power of 2

	// Allocate the new table.
	newSize := unsafe.Sizeof(abi.TypeAssertCache{}) + uintptr(newN-1)*unsafe.Sizeof(abi.TypeAssertCacheEntry{})
	newC := (*abi.TypeAssertCache)(mallocgc(newSize, nil, true))
	newC.Mask = uintptr(newN - 1)
	newEntries := unsafe.Slice(&newC.Entries[0], newN)

	// Fill the new table.
	addEntry := func(typ *_type, tab *itab) {
		h := int(typ.Hash) & (newN - 1)
		for {
			if newEntries[h].Typ == 0 {
				newEntries[h].Typ = uintptr(unsafe.Pointer(typ))
				newEntries[h].Itab = uintptr(unsafe.Pointer(tab))
				return
			}
			h = (h + 1) & (newN - 1)
		}
	}
	for _, e := range oldEntries {
		if e.Typ != 0 {
			addEntry((*_type)(unsafe.Pointer(e.Typ)), (*itab)(unsafe.Pointer(e.Itab)))
		}
	}
	addEntry(typ, tab)

	return newC
}

// Empty type assert cache. Contains one entry with a nil Typ (which
// causes a cache lookup to fail immediately.)
var emptyTypeAssertCache = abi.TypeAssertCache{Mask: 0}

// interfaceSwitch compares t against the list of cases in s.
// If t matches case i, interfaceSwitch returns the case index i and
// an itab for the pair <t, s.Cases[i]>.
// If there is no match, return N,nil, where N is the number
// of cases.
func interfaceSwitch(s *abi.InterfaceSwitch, t *_type) (int, *itab) {
	cases := unsafe.Slice(&s.Cases[0], s.NCases)

	// Results if we don't find a match.
	case_ := len(cases)
	var tab *itab

	// Look through each case in order.
	for i, c := range cases {
		tab = getitab(c, t, true)
		if tab != nil {
			case_ = i
			break
		}
	}

	if !abi.UseInterfaceSwitchCache(GOARCH) {
		return case_, tab
	}

	// Maybe update the cache, so the next time the generated code
	// doesn't need to call into the runtime.
	if cheaprand()&1023 != 0 {
		// Only bother updating the cache ~1 in 1000 times.
		// This ensures we don't waste memory on switches, or
		// switch arguments, that only happen a few times.
		return case_, tab
	}
	// Load the current cache.
	oldC := (*abi.InterfaceSwitchCache)(atomic.Loadp(unsafe.Pointer(&s.Cache)))

	if cheaprand()&uint32(oldC.Mask) != 0 {
		// As cache gets larger, choose to update it less often
		// so we can amortize the cost of building a new cache
		// (that cost is linear in oldc.Mask).
		return case_, tab
	}

	// Make a new cache.
	newC := buildInterfaceSwitchCache(oldC, t, case_, tab)

	// Update cache. Use compare-and-swap so if multiple threads
	// are fighting to update the cache, at least one of their
	// updates will stick.
	atomic_casPointer((*unsafe.Pointer)(unsafe.Pointer(&s.Cache)), unsafe.Pointer(oldC), unsafe.Pointer(newC))

	return case_, tab
}

// buildInterfaceSwitchCache constructs an interface switch cache
// containing all the entries from oldC plus the new entry
// (typ,case_,tab).
func buildInterfaceSwitchCache(oldC *abi.InterfaceSwitchCache, typ *_type, case_ int, tab *itab) *abi.InterfaceSwitchCache {
	oldEntries := unsafe.Slice(&oldC.Entries[0], oldC.Mask+1)

	// Count the number of entries we need.
	n := 1
	for _, e := range oldEntries {
		if e.Typ != 0 {
			n++
		}
	}

	// Figure out how big a table we need.
	// We need at least one more slot than the number of entries
	// so that we are guaranteed an empty slot (for termination).
	newN := n * 2                         // make it at most 50% full
	newN = 1 << sys.Len64(uint64(newN-1)) // round up to a power of 2

	// Allocate the new table.
	newSize := unsafe.Sizeof(abi.InterfaceSwitchCache{}) + uintptr(newN-1)*unsafe.Sizeof(abi.InterfaceSwitchCacheEntry{})
	newC := (*abi.InterfaceSwitchCache)(mallocgc(newSize, nil, true))
	newC.Mask = uintptr(newN - 1)
	newEntries := unsafe.Slice(&newC.Entries[0], newN)

	// Fill the new table.
	addEntry := func(typ *_type, case_ int, tab *itab) {
		h := int(typ.Hash) & (newN - 1)
		for {
			if newEntries[h].Typ == 0 {
				newEntries[h].Typ = uintptr(unsafe.Pointer(typ))
				newEntries[h].Case = case_
				newEntries[h].Itab = uintptr(unsafe.Pointer(tab))
				return
			}
			h = (h + 1) & (newN - 1)
		}
	}
	for _, e := range oldEntries {
		if e.Typ != 0 {
			addEntry((*_type)(unsafe.Pointer(e.Typ)), e.Case, (*itab)(unsafe.Pointer(e.Itab)))
		}
	}
	addEntry(typ, case_, tab)

	return newC
}

// Empty interface switch cache. Contains one entry with a nil Typ (which
// causes a cache lookup to fail immediately.)
var emptyInterfaceSwitchCache = abi.InterfaceSwitchCache{Mask: 0}

// reflect_ifaceE2I is for package reflect,
// but widely used packages access it using linkname.
// Notable members of the hall of shame include:
//   - gitee.com/quant1x/gox
//   - github.com/modern-go/reflect2
//   - github.com/v2pro/plz
//
// Do not remove or change the type signature.
//
//go:linkname reflect_ifaceE2I reflect.ifaceE2I
func reflect_ifaceE2I(inter *interfacetype, e eface, dst *iface) {
	*dst = iface{assertE2I(inter, e._type), e.data}
}

//go:linkname reflectlite_ifaceE2I internal/reflectlite.ifaceE2I
func reflectlite_ifaceE2I(inter *interfacetype, e eface, dst *iface) {
	*dst = iface{assertE2I(inter, e._type), e.data}
}

func iterate_itabs(fn func(*itab)) {
	// Note: only runs during stop the world or with itabLock held,
	// so no other locks/atomics needed.
	t := itabTable
	for i := uintptr(0); i < t.size; i++ {
		m := *(**itab)(add(unsafe.Pointer(&t.entries), i*goarch.PtrSize))
		if m != nil {
			fn(m)
		}
	}
}

// staticuint64s is used to avoid allocating in convTx for small integer values.
// staticuint64s[0] == 0, staticuint64s[1] == 1, and so forth.
// It is defined in assembler code so that it is read-only.
var staticuint64s [256]uint64

// getStaticuint64s is called by the reflect package to get a pointer
// to the read-only array.
//
//go:linkname getStaticuint64s
func getStaticuint64s() *[256]uint64 {
	return &staticuint64s
}

// The linker redirects a reference of a method that it determined
// unreachable to a reference to this function, so it will throw if
// ever called.
func unreachableMethod() {
	throw("unreachable method called. linker bug?")
}

"""



```