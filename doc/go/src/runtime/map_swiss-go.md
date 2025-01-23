Response:
Let's break down the thought process for analyzing the provided Go code snippet and generating the answer.

1. **Understanding the Context:** The first thing is to recognize that this code resides in `go/src/runtime/map_swiss.go`. The `runtime` package in Go is a core component responsible for managing the execution of Go programs. The filename `map_swiss.go` strongly suggests this file implements map functionality using a "Swiss table" approach (a specific kind of hash table implementation). The `//go:build goexperiment.swissmap` comment indicates this implementation might be experimental or a specific variant.

2. **Initial Scan for Core Functions:** I'd then quickly scan the code for function definitions. Keywords like `func` are important. I'd make a mental (or actual) list of the key functions and their names: `makemap64`, `makemap_small`, `makemap`, `mapaccess1`, `mapaccess2`, `mapaccess1_fat`, `mapaccess2_fat`, `mapassign`, `mapdelete`, `mapiterinit`, `mapiternext`, `mapclear`, and various `reflect_` prefixed functions like `reflect_makemap`, `reflect_mapaccess`, etc., as well as `mapclone`, `keys`, and `values`.

3. **Identifying Core Map Operations:**  Looking at the function names, I can immediately infer the basic map operations being implemented:
    * **Creation:** `makemap`, `makemap_small`, `makemap64` (all related to creating maps).
    * **Access/Lookup:** `mapaccess1`, `mapaccess2`, `mapaccess1_fat`, `mapaccess2_fat` (retrieving values from a map).
    * **Insertion/Update:** `mapassign` (adding or modifying key-value pairs).
    * **Deletion:** `mapdelete` (removing key-value pairs).
    * **Iteration:** `mapiterinit`, `mapiternext` (traversing the map's contents).
    * **Clearing:** `mapclear` (removing all entries).
    * **Length:** `reflect_maplen`, `reflectlite_maplen` (getting the number of elements).
    * **Cloning:** `mapclone` (creating a copy of the map).

4. **Recognizing `reflect` Package Integration:** The presence of functions prefixed with `reflect_` strongly indicates integration with the Go `reflect` package. Reflection allows examining and manipulating the structure and values of variables at runtime. These `reflect_` functions likely provide the underlying implementation for the `reflect` package's map operations.

5. **Paying Attention to Linkname Directives:**  The `//go:linkname` directives are crucial. They signify that functions in *other* packages (like `internal/runtime/maps` and `reflect`) are being *linked* to the functions defined in this file. The comments accompanying these directives are equally important, highlighting that external packages rely on these internal `runtime` functions and that their signatures should not be changed. This points to a potential point of fragility and the "hall of shame" concept.

6. **Understanding the Role of `abi.SwissMapType` and `maps.Map`:** The code uses `abi.SwissMapType` and `maps.Map`. These likely represent the type information and the underlying data structure for the Swiss table map implementation, respectively. The `unsafe.Pointer` type is also prominent, indicating low-level memory manipulation.

7. **Inferring Function Details:** Based on the names and parameters, I can infer what each function does:
    * `makemap` functions take type information and an optional hint for initial capacity.
    * `mapaccess` functions take the map, key, and return the value (and potentially a boolean indicating presence). The "fat" versions likely deal with the zero value of the element type.
    * `mapassign` takes the map and key and returns a pointer to the memory location where the value should be stored.
    * `mapdelete` takes the map and key to remove.
    * `mapiterinit` initializes an iterator, and `mapiternext` advances it.
    * `mapclear` removes all elements.
    * `mapclone` creates a copy.

8. **Considering Error Handling:** The `maps_errNilAssign` variable indicates a specific error condition (assignment to a nil map). The `maps_mapKeyError` function suggests handling of invalid map keys.

9. **Focusing on the "Why":** I'd then think about *why* this file exists. It's clearly implementing maps, but *why this specific implementation*? The `goexperiment.swissmap` build tag suggests this is a specific experimental version of map implementation.

10. **Constructing the Answer:**  Finally, I'd organize the information into a structured answer:
    * **High-level functionality:** Start with a general overview of the file's purpose – implementing map operations using a Swiss table.
    * **Detailed function list:** Go through the key functions and their roles (creation, access, etc.).
    * **Relationship to `reflect`:** Explain the integration with the `reflect` package.
    * **Example Code (Illustrative):** Provide simple Go code examples to demonstrate the usage of these functions conceptually, even though they are internal. *Crucially, emphasize that these are internal functions and should not be used directly in normal Go code.*
    * **Code Inference (Assumptions):** For the code inference part, I'd make reasonable assumptions about input and output, keeping the examples simple. Highlight that these are *assumptions* due to the internal nature of the code.
    * **Command-line arguments:** Note that this file doesn't directly handle command-line arguments, as it's a runtime component.
    * **Common Mistakes:** Focus on the main mistake: trying to directly use these internal functions due to the `//go:linkname` directives and the "hall of shame." Explain the risks involved.

**Self-Correction/Refinement During the Process:**

* **Initial thought:** "Maybe I should explain the Swiss table algorithm in detail."  **Correction:** The request is about the *functionality* of this specific *Go code*, not a general explanation of Swiss tables. Keep the focus on the provided code.
* **Initial thought:** "Should I provide very detailed code examples with all the `unsafe.Pointer` manipulations?" **Correction:**  The goal is to illustrate the *concept*, not provide a deep dive into unsafe operations. Simpler examples using standard Go syntax to represent the *effect* are better.
* **Initial thought:** "Should I list *all* the packages in the 'hall of shame'?" **Correction:**  The provided list in the comments is sufficient to illustrate the point. No need to exhaustively search for more.

By following these steps, combining code analysis with an understanding of Go's runtime and reflection mechanisms, and iteratively refining the approach, one can arrive at a comprehensive and accurate answer like the example provided in the initial prompt.
这是 `go/src/runtime/map_swiss.go` 文件的代码片段，它实现了 Go 语言中 **map (字典/哈希表)** 数据结构的一种特定实现，称为 **Swiss Map**。这个实现是 Go 语言实验性功能 `goexperiment.swissmap` 的一部分。

**主要功能：**

1. **Map 的创建 (`makemap`, `makemap_small`, `makemap64`, `reflect_makemap`):**  提供了创建 map 的函数。`makemap` 是核心的创建函数，可以指定初始容量 (hint)。`makemap_small` 针对已知较小容量的情况进行了优化。`makemap64` 接受 `int64` 类型的容量提示。`reflect_makemap` 是供 `reflect` 包使用的创建 map 的入口。

2. **Map 的元素访问 (`mapaccess1`, `mapaccess2`, `mapaccess1_fat`, `mapaccess2_fat`, `reflect_mapaccess`, `reflect_mapaccess_faststr`):** 提供了访问 map 中元素的函数。
   - `mapaccess1` 返回指向键对应值的指针。如果键不存在，则返回元素类型零值的指针（但永远不会返回 `nil`）。
   - `mapaccess2` 返回指向键对应值的指针以及一个布尔值，指示键是否存在。
   - `mapaccess1_fat` 和 `mapaccess2_fat` 是 `mapaccess1` 和 `mapaccess2` 的变体，用于在键不存在时返回用户提供的零值。
   - `reflect_mapaccess` 和 `reflect_mapaccess_faststr` 是供 `reflect` 包使用的访问 map 元素的入口，当键不存在时返回 `nil`。`reflect_mapaccess_faststr` 针对字符串类型的键进行了优化。

3. **Map 的元素赋值 (`mapassign`, `reflect_mapassign`, `reflect_mapassign_faststr`):** 提供了向 map 中添加或更新元素的函数。
   - `mapassign` 返回一个指向可以存储与给定键关联的值的内存位置的指针。
   - `reflect_mapassign` 和 `reflect_mapassign_faststr` 是供 `reflect` 包使用的赋值入口。`reflect_mapassign_faststr` 针对字符串类型的键进行了优化。

4. **Map 的元素删除 (`mapdelete`, `reflect_mapdelete`, `reflect_mapdelete_faststr`):** 提供了从 map 中删除元素的函数。
   - `mapdelete` 从 map 中删除指定的键值对。
   - `reflect_mapdelete` 和 `reflect_mapdelete_faststr` 是供 `reflect` 包使用的删除入口。`reflect_mapdelete_faststr` 针对字符串类型的键进行了优化。

5. **Map 的迭代 (`mapiterinit`, `mapiternext`, `reflect_mapiterinit`, `reflect_mapiternext`, `reflect_mapiterkey`, `reflect_mapiterelem`):** 提供了遍历 map 中元素的机制。
   - `mapiterinit` 初始化用于迭代 map 的迭代器结构 `maps.Iter`。
   - `mapiternext` 将迭代器移动到下一个元素。
   - `reflect_mapiterinit` 和 `reflect_mapiternext` 是供 `reflect` 包使用的迭代器初始化和移动入口。
   - `reflect_mapiterkey` 和 `reflect_mapiterelem` 返回当前迭代器指向的键和值。

6. **Map 的清空 (`mapclear`, `reflect_mapclear`):** 提供了清空 map 中所有元素的函数。

7. **Map 的长度 (`reflect_maplen`, `reflectlite_maplen`):**  提供了获取 map 中元素数量的函数。`reflectlite_maplen` 是 `internal/reflectlite` 包使用的版本。

8. **Map 的克隆 (`mapclone`, `mapclone2`):** 提供了创建 map 副本的功能。

**它是什么 Go 语言功能的实现：**

该文件是 Go 语言 `map` (字典/哈希表) 数据结构的底层实现之一， 特别是使用了名为 "Swiss Map" 的哈希表算法。

**Go 代码示例：**

虽然 `go/src/runtime/map_swiss.go` 中的函数通常不直接在用户代码中使用，但它们是 Go 语言 `map` 操作的基础。以下代码演示了 Go 语言中 `map` 的基本操作，这些操作在底层会调用 `map_swiss.go` 中定义的函数 (在启用了 `goexperiment.swissmap` 的情况下):

```go
package main

import "fmt"

func main() {
	// 创建一个 map
	myMap := make(map[string]int)

	// 添加元素
	myMap["apple"] = 1
	myMap["banana"] = 2
	myMap["orange"] = 3

	// 访问元素
	value, ok := myMap["banana"]
	fmt.Println("Value of banana:", value, "Exists:", ok) // Output: Value of banana: 2 Exists: true

	value, ok = myMap["grape"]
	fmt.Println("Value of grape:", value, "Exists:", ok)   // Output: Value of grape: 0 Exists: false

	// 赋值元素 (更新)
	myMap["apple"] = 10

	// 删除元素
	delete(myMap, "orange")

	// 迭代 map
	fmt.Println("Iterating over map:")
	for key, val := range myMap {
		fmt.Println(key, ":", val)
	}
	// Output (顺序可能不同):
	// Iterating over map:
	// apple : 10
	// banana : 2

	// 获取 map 长度
	fmt.Println("Length of map:", len(myMap)) // Output: Length of map: 2
}
```

**代码推理 (假设的输入与输出):**

假设我们调用 `mapaccess2` 函数，并提供以下输入：

* `t`: 一个描述 `map[string]int` 类型的 `abi.SwissMapType` 结构体。
* `m`: 一个已经创建的 `map[string]int` 类型的 `maps.Map` 结构体，包含键值对 `{"apple": 1, "banana": 2}`。
* `key`: 一个指向字符串 `"banana"` 的 `unsafe.Pointer`。

**预期输出：**

`mapaccess2` 函数应该返回：

* 一个指向 `int` 值 `2` 的 `unsafe.Pointer`。
* 一个布尔值 `true`，表示键存在。

如果 `key` 指向的字符串是 `"grape"` (map 中不存在的键)，则预期输出为：

* 一个指向 `int` 类型零值 `0` 的 `unsafe.Pointer`。
* 一个布尔值 `false`，表示键不存在。

**命令行参数的具体处理：**

此代码片段位于 Go 运行时库中，不直接处理用户提供的命令行参数。它作为 Go 程序执行的基础设施，被编译器生成的代码所调用。命令行参数的处理通常发生在 `main` 包的 `main` 函数中，并由 `os` 和 `flag` 等标准库包来完成。

**使用者易犯错的点：**

最容易犯的错误是尝试直接使用这些带有 `//go:linkname` 注释的函数。这些函数是 Go 运行时和反射机制的内部实现细节，不应该被用户代码直接调用。

**示例 (错误用法):**

```go
package main

import (
	_ "unsafe" // #nosec G103
)

//go:linkname myMapAccess runtime.mapaccess2

func myMapAccess(t *struct{}, m *struct{}, key unsafe.Pointer) (unsafe.Pointer, bool)

func main() {
	myMap := make(map[string]int)
	key := "apple"
	// 尝试直接调用 runtime 的内部函数 (这是错误的)
	// _, _ = myMapAccess(nil, unsafe.Pointer(&myMap), unsafe.Pointer(&key)) // 编译可能通过，但行为未定义且可能崩溃
}
```

**原因：**

1. **ABI 不稳定：** Go 运行时内部函数的签名和实现可能会在不同 Go 版本之间发生变化，直接依赖它们会导致代码在新版本下无法工作。
2. **内部状态：** 这些函数通常依赖于 Go 运行时维护的复杂内部状态，绕过正常的 Go `map` 操作可能导致状态不一致，引发难以调试的问题甚至程序崩溃。
3. **可维护性差：** 直接使用内部函数会使代码难以理解和维护，因为其行为和依赖关系不明确。

**总结：**

`go/src/runtime/map_swiss.go` 是 Go 语言 `map` 数据结构的一个底层实现，提供了创建、访问、赋值、删除、迭代和清空 map 的核心功能。它与 `reflect` 包紧密集成，为反射操作提供了基础。用户不应该直接调用此文件中定义的函数，而应该使用 Go 语言提供的标准 `map` 操作。

### 提示词
```
这是路径为go/src/runtime/map_swiss.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
```

### 源代码
```go
// Copyright 2014 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build goexperiment.swissmap

package runtime

import (
	"internal/abi"
	"internal/runtime/maps"
	"internal/runtime/sys"
	"unsafe"
)

const (
	// TODO: remove? These are used by tests but not the actual map
	loadFactorNum = 7
	loadFactorDen = 8
)

type maptype = abi.SwissMapType

//go:linkname maps_errNilAssign internal/runtime/maps.errNilAssign
var maps_errNilAssign error = plainError("assignment to entry in nil map")

//go:linkname maps_mapKeyError internal/runtime/maps.mapKeyError
func maps_mapKeyError(t *abi.SwissMapType, p unsafe.Pointer) error {
	return mapKeyError(t, p)
}

func makemap64(t *abi.SwissMapType, hint int64, m *maps.Map) *maps.Map {
	if int64(int(hint)) != hint {
		hint = 0
	}
	return makemap(t, int(hint), m)
}

// makemap_small implements Go map creation for make(map[k]v) and
// make(map[k]v, hint) when hint is known to be at most abi.SwissMapGroupSlots
// at compile time and the map needs to be allocated on the heap.
//
// makemap_small should be an internal detail,
// but widely used packages access it using linkname.
// Notable members of the hall of shame include:
//   - github.com/bytedance/sonic
//
// Do not remove or change the type signature.
// See go.dev/issue/67401.
//
//go:linkname makemap_small
func makemap_small() *maps.Map {
	return maps.NewEmptyMap()
}

// makemap implements Go map creation for make(map[k]v, hint).
// If the compiler has determined that the map or the first group
// can be created on the stack, m and optionally m.dirPtr may be non-nil.
// If m != nil, the map can be created directly in m.
// If m.dirPtr != nil, it points to a group usable for a small map.
//
// makemap should be an internal detail,
// but widely used packages access it using linkname.
// Notable members of the hall of shame include:
//   - github.com/ugorji/go/codec
//
// Do not remove or change the type signature.
// See go.dev/issue/67401.
//
//go:linkname makemap
func makemap(t *abi.SwissMapType, hint int, m *maps.Map) *maps.Map {
	if hint < 0 {
		hint = 0
	}

	return maps.NewMap(t, uintptr(hint), m, maxAlloc)
}

// mapaccess1 returns a pointer to h[key].  Never returns nil, instead
// it will return a reference to the zero object for the elem type if
// the key is not in the map.
// NOTE: The returned pointer may keep the whole map live, so don't
// hold onto it for very long.
//
// mapaccess1 is pushed from internal/runtime/maps. We could just call it, but
// we want to avoid one layer of call.
//
//go:linkname mapaccess1
func mapaccess1(t *abi.SwissMapType, m *maps.Map, key unsafe.Pointer) unsafe.Pointer

// mapaccess2 should be an internal detail,
// but widely used packages access it using linkname.
// Notable members of the hall of shame include:
//   - github.com/ugorji/go/codec
//
// Do not remove or change the type signature.
// See go.dev/issue/67401.
//
//go:linkname mapaccess2
func mapaccess2(t *abi.SwissMapType, m *maps.Map, key unsafe.Pointer) (unsafe.Pointer, bool)

func mapaccess1_fat(t *abi.SwissMapType, m *maps.Map, key, zero unsafe.Pointer) unsafe.Pointer {
	e := mapaccess1(t, m, key)
	if e == unsafe.Pointer(&zeroVal[0]) {
		return zero
	}
	return e
}

func mapaccess2_fat(t *abi.SwissMapType, m *maps.Map, key, zero unsafe.Pointer) (unsafe.Pointer, bool) {
	e := mapaccess1(t, m, key)
	if e == unsafe.Pointer(&zeroVal[0]) {
		return zero, false
	}
	return e, true
}

// mapassign is pushed from internal/runtime/maps. We could just call it, but
// we want to avoid one layer of call.
//
// mapassign should be an internal detail,
// but widely used packages access it using linkname.
// Notable members of the hall of shame include:
//   - github.com/bytedance/sonic
//   - github.com/RomiChan/protobuf
//   - github.com/segmentio/encoding
//   - github.com/ugorji/go/codec
//
// Do not remove or change the type signature.
// See go.dev/issue/67401.
//
//go:linkname mapassign
func mapassign(t *abi.SwissMapType, m *maps.Map, key unsafe.Pointer) unsafe.Pointer

// mapdelete should be an internal detail,
// but widely used packages access it using linkname.
// Notable members of the hall of shame include:
//   - github.com/ugorji/go/codec
//
// Do not remove or change the type signature.
// See go.dev/issue/67401.
//
//go:linkname mapdelete
func mapdelete(t *abi.SwissMapType, m *maps.Map, key unsafe.Pointer) {
	if raceenabled && m != nil {
		callerpc := sys.GetCallerPC()
		pc := abi.FuncPCABIInternal(mapdelete)
		racewritepc(unsafe.Pointer(m), callerpc, pc)
		raceReadObjectPC(t.Key, key, callerpc, pc)
	}
	if msanenabled && m != nil {
		msanread(key, t.Key.Size_)
	}
	if asanenabled && m != nil {
		asanread(key, t.Key.Size_)
	}

	m.Delete(t, key)
}

// mapiterinit initializes the Iter struct used for ranging over maps.
// The Iter struct pointed to by 'it' is allocated on the stack
// by the compilers order pass or on the heap by reflect_mapiterinit.
// Both need to have zeroed hiter since the struct contains pointers.
//
// mapiterinit should be an internal detail,
// but widely used packages access it using linkname.
// Notable members of the hall of shame include:
//   - github.com/bytedance/sonic
//   - github.com/goccy/go-json
//   - github.com/RomiChan/protobuf
//   - github.com/segmentio/encoding
//   - github.com/ugorji/go/codec
//   - github.com/wI2L/jettison
//
// Do not remove or change the type signature.
// See go.dev/issue/67401.
//
//go:linkname mapiterinit
func mapiterinit(t *abi.SwissMapType, m *maps.Map, it *maps.Iter) {
	if raceenabled && m != nil {
		callerpc := sys.GetCallerPC()
		racereadpc(unsafe.Pointer(m), callerpc, abi.FuncPCABIInternal(mapiterinit))
	}

	it.Init(t, m)
	it.Next()
}

// mapiternext should be an internal detail,
// but widely used packages access it using linkname.
// Notable members of the hall of shame include:
//   - github.com/bytedance/sonic
//   - github.com/RomiChan/protobuf
//   - github.com/segmentio/encoding
//   - github.com/ugorji/go/codec
//   - gonum.org/v1/gonum
//
// Do not remove or change the type signature.
// See go.dev/issue/67401.
//
//go:linkname mapiternext
func mapiternext(it *maps.Iter) {
	if raceenabled {
		callerpc := sys.GetCallerPC()
		racereadpc(unsafe.Pointer(it.Map()), callerpc, abi.FuncPCABIInternal(mapiternext))
	}

	it.Next()
}

// mapclear deletes all keys from a map.
func mapclear(t *abi.SwissMapType, m *maps.Map) {
	if raceenabled && m != nil {
		callerpc := sys.GetCallerPC()
		pc := abi.FuncPCABIInternal(mapclear)
		racewritepc(unsafe.Pointer(m), callerpc, pc)
	}

	m.Clear(t)
}

// Reflect stubs. Called from ../reflect/asm_*.s

// reflect_makemap is for package reflect,
// but widely used packages access it using linkname.
// Notable members of the hall of shame include:
//   - gitee.com/quant1x/gox
//   - github.com/modern-go/reflect2
//   - github.com/goccy/go-json
//   - github.com/RomiChan/protobuf
//   - github.com/segmentio/encoding
//   - github.com/v2pro/plz
//
// Do not remove or change the type signature.
// See go.dev/issue/67401.
//
//go:linkname reflect_makemap reflect.makemap
func reflect_makemap(t *abi.SwissMapType, cap int) *maps.Map {
	// Check invariants and reflects math.
	if t.Key.Equal == nil {
		throw("runtime.reflect_makemap: unsupported map key type")
	}
	// TODO: other checks

	return makemap(t, cap, nil)
}

// reflect_mapaccess is for package reflect,
// but widely used packages access it using linkname.
// Notable members of the hall of shame include:
//   - gitee.com/quant1x/gox
//   - github.com/modern-go/reflect2
//   - github.com/v2pro/plz
//
// Do not remove or change the type signature.
// See go.dev/issue/67401.
//
//go:linkname reflect_mapaccess reflect.mapaccess
func reflect_mapaccess(t *abi.SwissMapType, m *maps.Map, key unsafe.Pointer) unsafe.Pointer {
	elem, ok := mapaccess2(t, m, key)
	if !ok {
		// reflect wants nil for a missing element
		elem = nil
	}
	return elem
}

//go:linkname reflect_mapaccess_faststr reflect.mapaccess_faststr
func reflect_mapaccess_faststr(t *abi.SwissMapType, m *maps.Map, key string) unsafe.Pointer {
	elem, ok := mapaccess2_faststr(t, m, key)
	if !ok {
		// reflect wants nil for a missing element
		elem = nil
	}
	return elem
}

// reflect_mapassign is for package reflect,
// but widely used packages access it using linkname.
// Notable members of the hall of shame include:
//   - gitee.com/quant1x/gox
//   - github.com/v2pro/plz
//
// Do not remove or change the type signature.
//
//go:linkname reflect_mapassign reflect.mapassign0
func reflect_mapassign(t *abi.SwissMapType, m *maps.Map, key unsafe.Pointer, elem unsafe.Pointer) {
	p := mapassign(t, m, key)
	typedmemmove(t.Elem, p, elem)
}

//go:linkname reflect_mapassign_faststr reflect.mapassign_faststr0
func reflect_mapassign_faststr(t *abi.SwissMapType, m *maps.Map, key string, elem unsafe.Pointer) {
	p := mapassign_faststr(t, m, key)
	typedmemmove(t.Elem, p, elem)
}

//go:linkname reflect_mapdelete reflect.mapdelete
func reflect_mapdelete(t *abi.SwissMapType, m *maps.Map, key unsafe.Pointer) {
	mapdelete(t, m, key)
}

//go:linkname reflect_mapdelete_faststr reflect.mapdelete_faststr
func reflect_mapdelete_faststr(t *abi.SwissMapType, m *maps.Map, key string) {
	mapdelete_faststr(t, m, key)
}

// reflect_mapiterinit is for package reflect,
// but widely used packages access it using linkname.
// Notable members of the hall of shame include:
//   - github.com/modern-go/reflect2
//   - gitee.com/quant1x/gox
//   - github.com/v2pro/plz
//   - github.com/wI2L/jettison
//
// Do not remove or change the type signature.
// See go.dev/issue/67401.
//
//go:linkname reflect_mapiterinit reflect.mapiterinit
func reflect_mapiterinit(t *abi.SwissMapType, m *maps.Map, it *maps.Iter) {
	mapiterinit(t, m, it)
}

// reflect_mapiternext is for package reflect,
// but widely used packages access it using linkname.
// Notable members of the hall of shame include:
//   - gitee.com/quant1x/gox
//   - github.com/modern-go/reflect2
//   - github.com/goccy/go-json
//   - github.com/v2pro/plz
//   - github.com/wI2L/jettison
//
// Do not remove or change the type signature.
// See go.dev/issue/67401.
//
//go:linkname reflect_mapiternext reflect.mapiternext
func reflect_mapiternext(it *maps.Iter) {
	mapiternext(it)
}

// reflect_mapiterkey was for package reflect,
// but widely used packages access it using linkname.
// Notable members of the hall of shame include:
//   - github.com/goccy/go-json
//   - gonum.org/v1/gonum
//
// Do not remove or change the type signature.
// See go.dev/issue/67401.
//
//go:linkname reflect_mapiterkey reflect.mapiterkey
func reflect_mapiterkey(it *maps.Iter) unsafe.Pointer {
	return it.Key()
}

// reflect_mapiterelem was for package reflect,
// but widely used packages access it using linkname.
// Notable members of the hall of shame include:
//   - github.com/goccy/go-json
//   - gonum.org/v1/gonum
//
// Do not remove or change the type signature.
// See go.dev/issue/67401.
//
//go:linkname reflect_mapiterelem reflect.mapiterelem
func reflect_mapiterelem(it *maps.Iter) unsafe.Pointer {
	return it.Elem()
}

// reflect_maplen is for package reflect,
// but widely used packages access it using linkname.
// Notable members of the hall of shame include:
//   - github.com/goccy/go-json
//   - github.com/wI2L/jettison
//
// Do not remove or change the type signature.
// See go.dev/issue/67401.
//
//go:linkname reflect_maplen reflect.maplen
func reflect_maplen(m *maps.Map) int {
	if m == nil {
		return 0
	}
	if raceenabled {
		callerpc := sys.GetCallerPC()
		racereadpc(unsafe.Pointer(m), callerpc, abi.FuncPCABIInternal(reflect_maplen))
	}
	return int(m.Used())
}

//go:linkname reflect_mapclear reflect.mapclear
func reflect_mapclear(t *abi.SwissMapType, m *maps.Map) {
	mapclear(t, m)
}

//go:linkname reflectlite_maplen internal/reflectlite.maplen
func reflectlite_maplen(m *maps.Map) int {
	if m == nil {
		return 0
	}
	if raceenabled {
		callerpc := sys.GetCallerPC()
		racereadpc(unsafe.Pointer(m), callerpc, abi.FuncPCABIInternal(reflect_maplen))
	}
	return int(m.Used())
}

// mapinitnoop is a no-op function known the Go linker; if a given global
// map (of the right size) is determined to be dead, the linker will
// rewrite the relocation (from the package init func) from the outlined
// map init function to this symbol. Defined in assembly so as to avoid
// complications with instrumentation (coverage, etc).
func mapinitnoop()

// mapclone for implementing maps.Clone
//
//go:linkname mapclone maps.clone
func mapclone(m any) any {
	e := efaceOf(&m)
	e.data = unsafe.Pointer(mapclone2((*abi.SwissMapType)(unsafe.Pointer(e._type)), (*maps.Map)(e.data)))
	return m
}

func mapclone2(t *abi.SwissMapType, src *maps.Map) *maps.Map {
	dst := makemap(t, int(src.Used()), nil)

	var iter maps.Iter
	iter.Init(t, src)
	for iter.Next(); iter.Key() != nil; iter.Next() {
		dst.Put(t, iter.Key(), iter.Elem())
	}

	return dst
}

// keys for implementing maps.keys
//
//go:linkname keys maps.keys
func keys(m any, p unsafe.Pointer) {
	// Currently unused in the maps package.
	panic("unimplemented")
}

// values for implementing maps.values
//
//go:linkname values maps.values
func values(m any, p unsafe.Pointer) {
	// Currently unused in the maps package.
	panic("unimplemented")
}
```