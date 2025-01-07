Response:
Let's break down the thought process for analyzing the provided Go code snippet from `runtime/type.go`.

**1. Understanding the Goal:**

The primary goal is to understand the *functionality* of this specific Go source code file. This involves identifying the core data structures, functions, and how they interact. The prompt also asks for concrete examples, potential pitfalls, and connections to Go language features.

**2. Initial Scan and Keyword Identification:**

The first step is a quick read-through to get a general sense of the code. Looking for keywords and structural elements is crucial:

* **`package runtime`:**  Indicates this is part of the Go runtime, dealing with low-level operations.
* **`import`:** Lists dependencies, giving hints about related areas (e.g., `internal/abi`, `internal/goarch`, `internal/runtime/atomic`). This suggests the code deals with type layout, architecture-specific details, and atomic operations.
* **`type` declarations:**  These define the fundamental data structures. `_type`, `rtype`, `uncommontype`, etc., all relate to representing Go types at runtime. The comment `// Runtime type representation.` at the beginning confirms this.
* **`func` declarations:** These are the operations performed on these types. Methods like `string()`, `uncommon()`, `name()`, `pkgpath()`, `getGCMask()`, `buildGCMask()`, and `typesEqual()` stand out.
* **Comments:**  Pay close attention to comments, especially those explaining the purpose of types and functions (e.g., the comment for `reflectOffs`).
* **`unsafe` package:**  Its presence signifies low-level memory manipulation and direct access to type representations.
* **`atomic` package:**  Indicates concurrency control and thread safety, particularly in functions like `getGCMaskOnDemand`.

**3. Deeper Dive into Core Structures:**

* **`_type` and `rtype`:** The fundamental building blocks. `_type` seems to be the underlying ABI representation, while `rtype` provides methods. The comment "embedding is okay here (unlike reflect)" is a key distinction.
* **`nameOff`, `typeOff`, `textOff`:**  These suggest offsets within some data structures (likely within modules). This points to how the compiler and linker arrange type information.
* **`uncommontype`:**  The name suggests it holds less frequently used type information.
* **`reflectOffs`:**  The extensive comment explains its purpose: handling types created at runtime (like with reflection) where compile-time offsets aren't possible. This is a crucial piece for understanding dynamic type information.
* **`bitCursor`:**  This is clearly used for manipulating bitmasks, which are related to garbage collection.

**4. Analyzing Key Functions:**

* **`string()`, `name()`, `pkgpath()`:** These functions are about extracting string representations of types and their package paths. They reveal how type names are structured and stored.
* **`getGCMask()` and `buildGCMask()`:** These are critical for understanding garbage collection. The "GC mask" tells the garbage collector which parts of a type contain pointers. The logic in `getGCMaskOnDemand` with the `inProgress` sentinel demonstrates concurrency control during mask construction.
* **`typesEqual()`:** This function is explicitly mentioned as being used in `typelinksinit` and is essential for de-duplicating type pointers in shared builds. The recursive nature of the comparison is important to note.
* **`typelinksinit()`:** This function seems to be invoked during initialization to handle type information from different modules in shared libraries, using `typesEqual` to ensure consistency.
* **`resolveNameOff()`, `resolveTypeOff()`, `textOff()`:** These functions are responsible for resolving offsets into actual memory addresses of names, types, and function code, respectively. They handle both compile-time and runtime created types using `reflectOffs`.

**5. Connecting to Go Language Features:**

As the analysis progresses, start connecting the code to higher-level Go concepts:

* **Reflection:**  The `reflectOffs` structure directly relates to how Go's reflection mechanism works at a low level.
* **Garbage Collection:**  The `getGCMask` and `buildGCMask` functions are fundamental to Go's automatic memory management.
* **Type System:**  The entire file revolves around representing and manipulating Go types, illustrating the runtime's understanding of the type system.
* **Packages and Modules:** The functions dealing with package paths and the `typelinksinit` function show how Go manages code organization and linking.
* **Concurrency:** The use of `atomic` operations in `getGCMaskOnDemand` highlights thread safety concerns when dealing with type metadata.

**6. Generating Examples and Identifying Pitfalls:**

Based on the understanding of the code, start formulating illustrative examples. For instance, showing how `rtype.string()` and `rtype.name()` differ for named and unnamed types. Think about potential misuse or misunderstandings:

* **Directly manipulating `_type` or `rtype`:**  Emphasize that these are internal structures and should not be accessed directly in user code.
* **Misunderstanding the difference between `string()` and `name()`:** Highlight the purpose of each method.
* **Complexity of `typesEqual`:** Point out the intricate logic for handling recursive types and types from different modules.

**7. Structuring the Answer:**

Finally, organize the findings into a coherent answer, addressing each part of the prompt:

* **Functionality:** List the key capabilities of the code.
* **Go Language Feature Implementation:**  Connect the code to specific Go features with code examples.
* **Code Reasoning (with assumptions and I/O):** Provide concrete examples with input and expected output to illustrate how certain functions work.
* **Command-line Arguments:** If applicable (not in this snippet), explain how command-line flags might influence this code.
* **User Mistakes:**  Point out common misunderstandings or incorrect usage.

**Self-Correction/Refinement:**

During the analysis, you might encounter areas that are unclear. For example, the purpose of `textOff` might not be immediately obvious. This would prompt further investigation (perhaps searching for its usage within the Go runtime source code) to understand its role in accessing function code. Similarly, the details of the `bitCursor` and the bit manipulation within `buildGCMask` might require careful examination to grasp the bitmask construction process.

By following this systematic approach, you can effectively analyze and understand complex code snippets like the one provided. The key is to break down the problem into smaller pieces, understand the purpose of each component, and then connect them back to the broader context of the Go runtime and language features.
这段代码是 Go 语言运行时环境（runtime）中 `type.go` 文件的一部分，主要负责**表示和操作 Go 语言的类型信息**。它定义了用于描述类型结构的关键数据结构和相关方法，是 Go 语言反射、类型判断、垃圾回收等核心功能的基础。

以下是它的主要功能点：

1. **定义了类型表示的核心结构体：**
    *   `_type`:  这是 ABI（Application Binary Interface）中定义的类型结构，包含了类型的大小、对齐方式、哈希值等基本信息。
    *   `rtype`:  是对 `_type` 的一个包装，添加了一些用于操作类型信息的方法，比如获取类型名称、包路径等。

2. **提供了获取类型名称的方法：**
    *   `rtype.string()`: 返回类型的完整字符串表示，例如 `pkg.TypeName` 或 `*pkg.TypeName`。
    *   `rtype.name()`: 返回类型名称，不包含包路径。
    *   `rtype.pkgpath()`: 返回定义类型的包的路径。

3. **提供了获取类型元信息的方法：**
    *   `rtype.uncommon()`: 返回类型的 `uncommontype` 结构，其中包含方法集等不常用但重要的类型信息。

4. **实现了获取类型 GC 标记（GCMask）的功能：**
    *   `getGCMask(t *_type)`:  返回一个字节指针，指向类型 `t` 的 GC 标记位图。GC 标记用于垃圾回收器判断对象中的哪些部分是指针，从而进行正确的内存管理。
    *   `getGCMaskOnDemand(t *_type)`:  按需构建 GC 标记位图。对于大型类型，Go 不会立即构建完整的 GC 标记，而是在第一次需要时构建。这里使用了原子操作和自旋等待来保证并发安全。
    *   `buildGCMask(t *_type, dst bitCursor)`:  实际构建 GC 标记位图的函数，它根据类型的结构递归地标记出指针字段。

5. **处理运行时创建的类型（例如通过反射创建）：**
    *   `reflectOffs`:  维护了一个全局映射表，用于存储运行时创建的 `rtype` 对象的偏移量。由于这些对象在堆上分配，地址可能不稳定，因此使用偏移量作为标识符。
    *   `resolveNameOff`, `resolveTypeOff`, `rtype.nameOff`, `rtype.typeOff`, `rtype.textOff`: 这些函数用于解析存储在类型信息中的偏移量，将其转换为实际的名称、类型或代码地址。这使得运行时可以访问到编译时和运行时创建的类型信息。

6. **实现了类型比较的功能 (用于共享构建模式)：**
    *   `typesEqual(t, v *_type, seen map[_typePair]struct{})`: 用于比较两个类型是否相等。这个函数主要用于 `buildmode=shared` 的情况下，因为在共享构建模式下，同一个类型可能在不同的模块中出现，导致 `*_type` 指针不同。此函数通过比较类型的结构、名称、包路径等来判断类型是否相同。
    *   `typelinksinit()`:  在程序初始化时被调用，用于扫描额外模块中的类型，并构建 `moduledata` 的 `typemap`，用于去重类型指针。

**可以推理出它是什么 Go 语言功能的实现：**

*   **反射 (Reflection):**  `reflectOffs` 的存在以及 `resolveNameOff` 和 `resolveTypeOff` 等函数表明这部分代码是 Go 反射机制的底层实现。反射允许程序在运行时检查和操作类型信息。

*   **垃圾回收 (Garbage Collection):** `getGCMask` 和 `buildGCMask` 明显与垃圾回收有关。Go 的垃圾回收器需要知道对象的内存布局，特别是哪些字段是指针，才能正确地追踪和回收内存。

*   **类型系统 (Type System):**  整个文件的核心就是对 Go 语言类型的表示和操作。这是 Go 强类型系统的基础。

*   **共享库 (Shared Libraries) 和模块 (Modules):**  `typelinksinit` 和 `typesEqual` 函数的存在表明这部分代码也处理了共享库或模块场景下的类型信息管理，确保不同模块中的相同类型可以被正确识别。

**Go 代码举例说明（反射）：**

```go
package main

import (
	"fmt"
	"reflect"
)

type MyInt int

func main() {
	var i MyInt = 10
	t := reflect.TypeOf(i)

	fmt.Println("Type String:", t.String())  // Output: main.MyInt
	fmt.Println("Type Name:", t.Name())    // Output: MyInt
	fmt.Println("Type Kind:", t.Kind())    // Output: int
	fmt.Println("Package Path:", t.PkgPath()) // Output: main
}
```

**假设的输入与输出（基于 `rtype` 的方法）：**

假设我们有一个 `rtype` 类型的变量 `rt` 代表 `main.MyInt` 类型。

*   **输入:** `rt.string()`
    *   **输出:** `"main.MyInt"`
*   **输入:** `rt.name()`
    *   **输出:** `"MyInt"`
*   **输入:** `rt.pkgpath()`
    *   **输出:** `"main"`

**命令行参数的具体处理：**

这段代码本身不直接处理命令行参数。但是，Go 编译器的构建模式（例如 `buildmode=shared`）会影响到 `typelinksinit` 和 `typesEqual` 的行为，这需要在编译时通过命令行参数指定。

例如，使用共享库构建：

```bash
go build -buildmode=shared -linkshared mypackage.go
```

在这种模式下，`typelinksinit` 会被调用，并且 `typesEqual` 函数在比较类型时会更加复杂，因为它需要考虑不同共享库中的相同类型。

**使用者易犯错的点（与反射相关）：**

*   **直接操作 `unsafe.Pointer` 转换得到的 `*_type` 或 `rtype`：**  Go 的类型系统是受到严格控制的，直接操作这些底层结构可能会破坏类型安全，导致程序崩溃或产生未定义的行为。开发者应该使用 `reflect` 包提供的安全接口进行类型操作。

    ```go
    package main

    import (
    	"fmt"
    	"unsafe"
    )

    type MyInt int

    func main() {
    	var i MyInt = 10
    	// 错误的做法：尝试直接访问 _type 结构（假设你知道它的布局）
    	typePtr := (*uintptr)(unsafe.Pointer(&i))
    	fmt.Println("Direct memory access:", *typePtr) // 这很危险，且类型布局可能变化
    }
    ```

*   **误解 `string()` 和 `name()` 的区别：**  开发者可能会混淆这两个方法，期望 `name()` 返回包含包路径的完整名称。

    ```go
    package mypackage

    type MyType struct {}

    // ... 在另一个包中 ...

    import (
    	"fmt"
    	"reflect"
    	"mypackage"
    )

    func main() {
    	var t mypackage.MyType
    	rt := reflect.TypeOf(t)
    	fmt.Println("String:", rt.String()) // 输出: mypackage.MyType
    	fmt.Println("Name:", rt.Name())   // 输出: MyType
    }
    ```

总而言之，这段代码是 Go 语言运行时环境中非常核心的部分，它负责类型信息的表示和管理，为反射、垃圾回收等关键功能提供了基础支持。开发者通常不需要直接与这段代码交互，而是通过 `reflect` 等更高级的包来操作类型信息。理解这段代码有助于深入理解 Go 语言的内部机制。

Prompt: 
```
这是路径为go/src/runtime/type.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。

"""
// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Runtime type representation.

package runtime

import (
	"internal/abi"
	"internal/goarch"
	"internal/goexperiment"
	"internal/runtime/atomic"
	"unsafe"
)

type nameOff = abi.NameOff
type typeOff = abi.TypeOff
type textOff = abi.TextOff

type _type = abi.Type

// rtype is a wrapper that allows us to define additional methods.
type rtype struct {
	*abi.Type // embedding is okay here (unlike reflect) because none of this is public
}

func (t rtype) string() string {
	s := t.nameOff(t.Str).Name()
	if t.TFlag&abi.TFlagExtraStar != 0 {
		return s[1:]
	}
	return s
}

func (t rtype) uncommon() *uncommontype {
	return t.Uncommon()
}

func (t rtype) name() string {
	if t.TFlag&abi.TFlagNamed == 0 {
		return ""
	}
	s := t.string()
	i := len(s) - 1
	sqBrackets := 0
	for i >= 0 && (s[i] != '.' || sqBrackets != 0) {
		switch s[i] {
		case ']':
			sqBrackets++
		case '[':
			sqBrackets--
		}
		i--
	}
	return s[i+1:]
}

// pkgpath returns the path of the package where t was defined, if
// available. This is not the same as the reflect package's PkgPath
// method, in that it returns the package path for struct and interface
// types, not just named types.
func (t rtype) pkgpath() string {
	if u := t.uncommon(); u != nil {
		return t.nameOff(u.PkgPath).Name()
	}
	switch t.Kind_ & abi.KindMask {
	case abi.Struct:
		st := (*structtype)(unsafe.Pointer(t.Type))
		return st.PkgPath.Name()
	case abi.Interface:
		it := (*interfacetype)(unsafe.Pointer(t.Type))
		return it.PkgPath.Name()
	}
	return ""
}

// getGCMask returns the pointer/nonpointer bitmask for type t.
//
// nosplit because it is used during write barriers and must not be preempted.
//
//go:nosplit
func getGCMask(t *_type) *byte {
	if t.TFlag&abi.TFlagGCMaskOnDemand != 0 {
		// Split the rest into getGCMaskOnDemand so getGCMask itself is inlineable.
		return getGCMaskOnDemand(t)
	}
	return t.GCData
}

// inProgress is a byte whose address is a sentinel indicating that
// some thread is currently building the GC bitmask for a type.
var inProgress byte

// nosplit because it is used during write barriers and must not be preempted.
//
//go:nosplit
func getGCMaskOnDemand(t *_type) *byte {
	// For large types, GCData doesn't point directly to a bitmask.
	// Instead it points to a pointer to a bitmask, and the runtime
	// is responsible for (on first use) creating the bitmask and
	// storing a pointer to it in that slot.
	// TODO: we could use &t.GCData as the slot, but types are
	// in read-only memory currently.
	addr := unsafe.Pointer(t.GCData)

	if GOOS == "aix" {
		addr = add(addr, firstmoduledata.data-aixStaticDataBase)
	}

	for {
		p := (*byte)(atomic.Loadp(addr))
		switch p {
		default: // Already built.
			return p
		case &inProgress: // Someone else is currently building it.
			// Just wait until the builder is done.
			// We can't block here, so spinning while having
			// the OS thread yield is about the best we can do.
			osyield()
			continue
		case nil: // Not built yet.
			// Attempt to get exclusive access to build it.
			if !atomic.Casp1((*unsafe.Pointer)(addr), nil, unsafe.Pointer(&inProgress)) {
				continue
			}

			// Build gcmask for this type.
			bytes := goarch.PtrSize * divRoundUp(t.PtrBytes/goarch.PtrSize, 8*goarch.PtrSize)
			p = (*byte)(persistentalloc(bytes, goarch.PtrSize, &memstats.other_sys))
			systemstack(func() {
				buildGCMask(t, bitCursor{ptr: p, n: 0})
			})

			// Store the newly-built gcmask for future callers.
			atomic.StorepNoWB(addr, unsafe.Pointer(p))
			return p
		}
	}
}

// A bitCursor is a simple cursor to memory to which we
// can write a set of bits.
type bitCursor struct {
	ptr *byte   // base of region
	n   uintptr // cursor points to bit n of region
}

// Write to b cnt bits starting at bit 0 of data.
// Requires cnt>0.
func (b bitCursor) write(data *byte, cnt uintptr) {
	// Starting byte for writing.
	p := addb(b.ptr, b.n/8)

	// Note: if we're starting halfway through a byte, we load the
	// existing lower bits so we don't clobber them.
	n := b.n % 8                    // # of valid bits in buf
	buf := uintptr(*p) & (1<<n - 1) // buffered bits to start

	// Work 8 bits at a time.
	for cnt > 8 {
		// Read 8 more bits, now buf has 8-15 valid bits in it.
		buf |= uintptr(*data) << n
		n += 8
		data = addb(data, 1)
		cnt -= 8
		// Write 8 of the buffered bits out.
		*p = byte(buf)
		buf >>= 8
		n -= 8
		p = addb(p, 1)
	}
	// Read remaining bits.
	buf |= (uintptr(*data) & (1<<cnt - 1)) << n
	n += cnt

	// Flush remaining bits.
	if n > 8 {
		*p = byte(buf)
		buf >>= 8
		n -= 8
		p = addb(p, 1)
	}
	*p &^= 1<<n - 1
	*p |= byte(buf)
}

func (b bitCursor) offset(cnt uintptr) bitCursor {
	return bitCursor{ptr: b.ptr, n: b.n + cnt}
}

// buildGCMask writes the ptr/nonptr bitmap for t to dst.
// t must have a pointer.
func buildGCMask(t *_type, dst bitCursor) {
	// Note: we want to avoid a situation where buildGCMask gets into a
	// very deep recursion, because M stacks are fixed size and pretty small
	// (16KB). We do that by ensuring that any recursive
	// call operates on a type at most half the size of its parent.
	// Thus, the recursive chain can be at most 64 calls deep (on a
	// 64-bit machine).
	// Recursion is avoided by using a "tail call" (jumping to the
	// "top" label) for any recursive call with a large subtype.
top:
	if t.PtrBytes == 0 {
		throw("pointerless type")
	}
	if t.TFlag&abi.TFlagGCMaskOnDemand == 0 {
		// copy t.GCData to dst
		dst.write(t.GCData, t.PtrBytes/goarch.PtrSize)
		return
	}
	// The above case should handle all kinds except
	// possibly arrays and structs.
	switch t.Kind() {
	case abi.Array:
		a := t.ArrayType()
		if a.Len == 1 {
			// Avoid recursive call for element type that
			// isn't smaller than the parent type.
			t = a.Elem
			goto top
		}
		e := a.Elem
		for i := uintptr(0); i < a.Len; i++ {
			buildGCMask(e, dst)
			dst = dst.offset(e.Size_ / goarch.PtrSize)
		}
	case abi.Struct:
		s := t.StructType()
		var bigField abi.StructField
		for _, f := range s.Fields {
			ft := f.Typ
			if !ft.Pointers() {
				continue
			}
			if ft.Size_ > t.Size_/2 {
				// Avoid recursive call for field type that
				// is larger than half of the parent type.
				// There can be only one.
				bigField = f
				continue
			}
			buildGCMask(ft, dst.offset(f.Offset/goarch.PtrSize))
		}
		if bigField.Typ != nil {
			// Note: this case causes bits to be written out of order.
			t = bigField.Typ
			dst = dst.offset(bigField.Offset / goarch.PtrSize)
			goto top
		}
	default:
		throw("unexpected kind")
	}
}

// reflectOffs holds type offsets defined at run time by the reflect package.
//
// When a type is defined at run time, its *rtype data lives on the heap.
// There are a wide range of possible addresses the heap may use, that
// may not be representable as a 32-bit offset. Moreover the GC may
// one day start moving heap memory, in which case there is no stable
// offset that can be defined.
//
// To provide stable offsets, we add pin *rtype objects in a global map
// and treat the offset as an identifier. We use negative offsets that
// do not overlap with any compile-time module offsets.
//
// Entries are created by reflect.addReflectOff.
var reflectOffs struct {
	lock mutex
	next int32
	m    map[int32]unsafe.Pointer
	minv map[unsafe.Pointer]int32
}

func reflectOffsLock() {
	lock(&reflectOffs.lock)
	if raceenabled {
		raceacquire(unsafe.Pointer(&reflectOffs.lock))
	}
}

func reflectOffsUnlock() {
	if raceenabled {
		racerelease(unsafe.Pointer(&reflectOffs.lock))
	}
	unlock(&reflectOffs.lock)
}

func resolveNameOff(ptrInModule unsafe.Pointer, off nameOff) name {
	if off == 0 {
		return name{}
	}
	base := uintptr(ptrInModule)
	for md := &firstmoduledata; md != nil; md = md.next {
		if base >= md.types && base < md.etypes {
			res := md.types + uintptr(off)
			if res > md.etypes {
				println("runtime: nameOff", hex(off), "out of range", hex(md.types), "-", hex(md.etypes))
				throw("runtime: name offset out of range")
			}
			return name{Bytes: (*byte)(unsafe.Pointer(res))}
		}
	}

	// No module found. see if it is a run time name.
	reflectOffsLock()
	res, found := reflectOffs.m[int32(off)]
	reflectOffsUnlock()
	if !found {
		println("runtime: nameOff", hex(off), "base", hex(base), "not in ranges:")
		for next := &firstmoduledata; next != nil; next = next.next {
			println("\ttypes", hex(next.types), "etypes", hex(next.etypes))
		}
		throw("runtime: name offset base pointer out of range")
	}
	return name{Bytes: (*byte)(res)}
}

func (t rtype) nameOff(off nameOff) name {
	return resolveNameOff(unsafe.Pointer(t.Type), off)
}

func resolveTypeOff(ptrInModule unsafe.Pointer, off typeOff) *_type {
	if off == 0 || off == -1 {
		// -1 is the sentinel value for unreachable code.
		// See cmd/link/internal/ld/data.go:relocsym.
		return nil
	}
	base := uintptr(ptrInModule)
	var md *moduledata
	for next := &firstmoduledata; next != nil; next = next.next {
		if base >= next.types && base < next.etypes {
			md = next
			break
		}
	}
	if md == nil {
		reflectOffsLock()
		res := reflectOffs.m[int32(off)]
		reflectOffsUnlock()
		if res == nil {
			println("runtime: typeOff", hex(off), "base", hex(base), "not in ranges:")
			for next := &firstmoduledata; next != nil; next = next.next {
				println("\ttypes", hex(next.types), "etypes", hex(next.etypes))
			}
			throw("runtime: type offset base pointer out of range")
		}
		return (*_type)(res)
	}
	if t := md.typemap[off]; t != nil {
		return t
	}
	res := md.types + uintptr(off)
	if res > md.etypes {
		println("runtime: typeOff", hex(off), "out of range", hex(md.types), "-", hex(md.etypes))
		throw("runtime: type offset out of range")
	}
	return (*_type)(unsafe.Pointer(res))
}

func (t rtype) typeOff(off typeOff) *_type {
	return resolveTypeOff(unsafe.Pointer(t.Type), off)
}

func (t rtype) textOff(off textOff) unsafe.Pointer {
	if off == -1 {
		// -1 is the sentinel value for unreachable code.
		// See cmd/link/internal/ld/data.go:relocsym.
		return unsafe.Pointer(abi.FuncPCABIInternal(unreachableMethod))
	}
	base := uintptr(unsafe.Pointer(t.Type))
	var md *moduledata
	for next := &firstmoduledata; next != nil; next = next.next {
		if base >= next.types && base < next.etypes {
			md = next
			break
		}
	}
	if md == nil {
		reflectOffsLock()
		res := reflectOffs.m[int32(off)]
		reflectOffsUnlock()
		if res == nil {
			println("runtime: textOff", hex(off), "base", hex(base), "not in ranges:")
			for next := &firstmoduledata; next != nil; next = next.next {
				println("\ttypes", hex(next.types), "etypes", hex(next.etypes))
			}
			throw("runtime: text offset base pointer out of range")
		}
		return res
	}
	res := md.textAddr(uint32(off))
	return unsafe.Pointer(res)
}

type uncommontype = abi.UncommonType

type interfacetype = abi.InterfaceType

type arraytype = abi.ArrayType

type chantype = abi.ChanType

type slicetype = abi.SliceType

type functype = abi.FuncType

type ptrtype = abi.PtrType

type name = abi.Name

type structtype = abi.StructType

func pkgPath(n name) string {
	if n.Bytes == nil || *n.Data(0)&(1<<2) == 0 {
		return ""
	}
	i, l := n.ReadVarint(1)
	off := 1 + i + l
	if *n.Data(0)&(1<<1) != 0 {
		i2, l2 := n.ReadVarint(off)
		off += i2 + l2
	}
	var nameOff nameOff
	copy((*[4]byte)(unsafe.Pointer(&nameOff))[:], (*[4]byte)(unsafe.Pointer(n.Data(off)))[:])
	pkgPathName := resolveNameOff(unsafe.Pointer(n.Bytes), nameOff)
	return pkgPathName.Name()
}

// typelinksinit scans the types from extra modules and builds the
// moduledata typemap used to de-duplicate type pointers.
func typelinksinit() {
	if firstmoduledata.next == nil {
		return
	}
	typehash := make(map[uint32][]*_type, len(firstmoduledata.typelinks))

	modules := activeModules()
	prev := modules[0]
	for _, md := range modules[1:] {
		// Collect types from the previous module into typehash.
	collect:
		for _, tl := range prev.typelinks {
			var t *_type
			if prev.typemap == nil {
				t = (*_type)(unsafe.Pointer(prev.types + uintptr(tl)))
			} else {
				t = prev.typemap[typeOff(tl)]
			}
			// Add to typehash if not seen before.
			tlist := typehash[t.Hash]
			for _, tcur := range tlist {
				if tcur == t {
					continue collect
				}
			}
			typehash[t.Hash] = append(tlist, t)
		}

		if md.typemap == nil {
			// If any of this module's typelinks match a type from a
			// prior module, prefer that prior type by adding the offset
			// to this module's typemap.
			tm := make(map[typeOff]*_type, len(md.typelinks))
			pinnedTypemaps = append(pinnedTypemaps, tm)
			md.typemap = tm
			for _, tl := range md.typelinks {
				t := (*_type)(unsafe.Pointer(md.types + uintptr(tl)))
				for _, candidate := range typehash[t.Hash] {
					seen := map[_typePair]struct{}{}
					if typesEqual(t, candidate, seen) {
						t = candidate
						break
					}
				}
				md.typemap[typeOff(tl)] = t
			}
		}

		prev = md
	}
}

type _typePair struct {
	t1 *_type
	t2 *_type
}

func toRType(t *abi.Type) rtype {
	return rtype{t}
}

// typesEqual reports whether two types are equal.
//
// Everywhere in the runtime and reflect packages, it is assumed that
// there is exactly one *_type per Go type, so that pointer equality
// can be used to test if types are equal. There is one place that
// breaks this assumption: buildmode=shared. In this case a type can
// appear as two different pieces of memory. This is hidden from the
// runtime and reflect package by the per-module typemap built in
// typelinksinit. It uses typesEqual to map types from later modules
// back into earlier ones.
//
// Only typelinksinit needs this function.
func typesEqual(t, v *_type, seen map[_typePair]struct{}) bool {
	tp := _typePair{t, v}
	if _, ok := seen[tp]; ok {
		return true
	}

	// mark these types as seen, and thus equivalent which prevents an infinite loop if
	// the two types are identical, but recursively defined and loaded from
	// different modules
	seen[tp] = struct{}{}

	if t == v {
		return true
	}
	kind := t.Kind_ & abi.KindMask
	if kind != v.Kind_&abi.KindMask {
		return false
	}
	rt, rv := toRType(t), toRType(v)
	if rt.string() != rv.string() {
		return false
	}
	ut := t.Uncommon()
	uv := v.Uncommon()
	if ut != nil || uv != nil {
		if ut == nil || uv == nil {
			return false
		}
		pkgpatht := rt.nameOff(ut.PkgPath).Name()
		pkgpathv := rv.nameOff(uv.PkgPath).Name()
		if pkgpatht != pkgpathv {
			return false
		}
	}
	if abi.Bool <= kind && kind <= abi.Complex128 {
		return true
	}
	switch kind {
	case abi.String, abi.UnsafePointer:
		return true
	case abi.Array:
		at := (*arraytype)(unsafe.Pointer(t))
		av := (*arraytype)(unsafe.Pointer(v))
		return typesEqual(at.Elem, av.Elem, seen) && at.Len == av.Len
	case abi.Chan:
		ct := (*chantype)(unsafe.Pointer(t))
		cv := (*chantype)(unsafe.Pointer(v))
		return ct.Dir == cv.Dir && typesEqual(ct.Elem, cv.Elem, seen)
	case abi.Func:
		ft := (*functype)(unsafe.Pointer(t))
		fv := (*functype)(unsafe.Pointer(v))
		if ft.OutCount != fv.OutCount || ft.InCount != fv.InCount {
			return false
		}
		tin, vin := ft.InSlice(), fv.InSlice()
		for i := 0; i < len(tin); i++ {
			if !typesEqual(tin[i], vin[i], seen) {
				return false
			}
		}
		tout, vout := ft.OutSlice(), fv.OutSlice()
		for i := 0; i < len(tout); i++ {
			if !typesEqual(tout[i], vout[i], seen) {
				return false
			}
		}
		return true
	case abi.Interface:
		it := (*interfacetype)(unsafe.Pointer(t))
		iv := (*interfacetype)(unsafe.Pointer(v))
		if it.PkgPath.Name() != iv.PkgPath.Name() {
			return false
		}
		if len(it.Methods) != len(iv.Methods) {
			return false
		}
		for i := range it.Methods {
			tm := &it.Methods[i]
			vm := &iv.Methods[i]
			// Note the mhdr array can be relocated from
			// another module. See #17724.
			tname := resolveNameOff(unsafe.Pointer(tm), tm.Name)
			vname := resolveNameOff(unsafe.Pointer(vm), vm.Name)
			if tname.Name() != vname.Name() {
				return false
			}
			if pkgPath(tname) != pkgPath(vname) {
				return false
			}
			tityp := resolveTypeOff(unsafe.Pointer(tm), tm.Typ)
			vityp := resolveTypeOff(unsafe.Pointer(vm), vm.Typ)
			if !typesEqual(tityp, vityp, seen) {
				return false
			}
		}
		return true
	case abi.Map:
		if goexperiment.SwissMap {
			mt := (*abi.SwissMapType)(unsafe.Pointer(t))
			mv := (*abi.SwissMapType)(unsafe.Pointer(v))
			return typesEqual(mt.Key, mv.Key, seen) && typesEqual(mt.Elem, mv.Elem, seen)
		}
		mt := (*abi.OldMapType)(unsafe.Pointer(t))
		mv := (*abi.OldMapType)(unsafe.Pointer(v))
		return typesEqual(mt.Key, mv.Key, seen) && typesEqual(mt.Elem, mv.Elem, seen)
	case abi.Pointer:
		pt := (*ptrtype)(unsafe.Pointer(t))
		pv := (*ptrtype)(unsafe.Pointer(v))
		return typesEqual(pt.Elem, pv.Elem, seen)
	case abi.Slice:
		st := (*slicetype)(unsafe.Pointer(t))
		sv := (*slicetype)(unsafe.Pointer(v))
		return typesEqual(st.Elem, sv.Elem, seen)
	case abi.Struct:
		st := (*structtype)(unsafe.Pointer(t))
		sv := (*structtype)(unsafe.Pointer(v))
		if len(st.Fields) != len(sv.Fields) {
			return false
		}
		if st.PkgPath.Name() != sv.PkgPath.Name() {
			return false
		}
		for i := range st.Fields {
			tf := &st.Fields[i]
			vf := &sv.Fields[i]
			if tf.Name.Name() != vf.Name.Name() {
				return false
			}
			if !typesEqual(tf.Typ, vf.Typ, seen) {
				return false
			}
			if tf.Name.Tag() != vf.Name.Tag() {
				return false
			}
			if tf.Offset != vf.Offset {
				return false
			}
			if tf.Name.IsEmbedded() != vf.Name.IsEmbedded() {
				return false
			}
		}
		return true
	default:
		println("runtime: impossible type kind", kind)
		throw("runtime: impossible type kind")
		return false
	}
}

"""



```