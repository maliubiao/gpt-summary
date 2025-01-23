Response:
Let's break down the thought process for analyzing the provided Go code snippet.

1. **Identify the Core Purpose:** The filename `runtime_fast64_swiss.go` and the package `maps` immediately suggest this code is related to the implementation of Go's `map` data structure, specifically optimized for keys of type `uint64`. The `swiss` part likely refers to the Swiss table technique, a common optimization for hash tables.

2. **Examine Function Signatures and `go:linkname` Directives:** The `go:linkname` directives like `runtime_mapaccess1_fast64 runtime.mapaccess1_fast64` are crucial. They tell us that functions in this internal package are being linked to corresponding functions in the `runtime` package that are visible to regular Go code. This means the functions here are *the implementation* of map operations for `uint64` keys. The signatures of these functions (`runtime_mapaccess1_fast64`, `runtime_mapaccess2_fast64`, `runtime_mapassign_fast64`, `runtime_mapassign_fast64ptr`, `runtime_mapdelete_fast64`) directly correspond to the standard map operations: accessing (with one return value, accessing with a boolean "ok" value), assigning (inserting/updating), and deleting.

3. **Analyze Individual Functions:**

   * **`runtime_mapaccess1_fast64` and `runtime_mapaccess2_fast64`:** These are for reading map values. Key features include:
      * **Race detection:** The `race.Enabled` checks indicate support for Go's race detector.
      * **Nil/Empty map handling:** Returning the `zeroVal` for nil or empty maps is standard behavior.
      * **Concurrent read/write detection:** The `m.writing != 0` check prevents data corruption.
      * **Small map optimization:** The `m.dirLen == 0` block suggests a special handling for smaller maps, likely to avoid the overhead of the full directory structure. It iterates through the single group.
      * **Hashing and Probing:** The code calculates a hash, uses a directory to find a table, and then probes within the table's groups to locate the key. The `makeProbeSeq`, `matchH2`, and `matchEmpty` logic are central to the Swiss table implementation.

   * **`runtime_mapassign_fast64` and `runtime_mapassign_fast64ptr`:** These are for inserting or updating map values. Key features:
      * **Nil map panic:** Assigning to a nil map panics.
      * **Concurrent write detection:** Same as the access functions.
      * **Small map handling:** `m.growToSmall` and the conditional logic handle the initial creation and growth of small maps. The `putSlotSmallFast64` (and `putSlotSmallFastPtr`) function handles insertion into these small maps.
      * **Growth and Rehashing:** The `m.growToTable` and `t.rehash` calls indicate how the map expands when it gets full. The code also deals with deleted slots (`ctrlDeleted`) as part of the growth process.

   * **`runtime_mapdelete_fast64`:**  This function removes an entry. It delegates the actual deletion to `m.Delete`. It also includes a race condition check.

4. **Infer the Go Feature:** Based on the function names and their behavior, it's clear this code implements the core functionality of Go maps where the key is a `uint64` or a pointer (in the case of `runtime_mapassign_fast64ptr`). The presence of `fast64` in the names strongly suggests it's an optimization for this specific key type. The "swiss" part points to the specific Swiss table algorithm.

5. **Construct Example Code:** To demonstrate the functionality, create a simple Go program that uses a map with `uint64` keys and performs the operations implemented by the analyzed code: reading, writing, and deleting. This helps solidify the understanding of how the internal functions are used.

6. **Infer Input/Output for Code Reasoning:** For the access functions, the input is a map and a key. The output is the value (and a boolean for `runtime_mapaccess2_fast64`). For assign, the output is a pointer to the memory location where the value is stored. For delete, there's no explicit output, but the map's state changes.

7. **Consider Command-Line Parameters:** The code itself doesn't directly process command-line arguments. The `go:build goexperiment.swissmap` line is a build tag, not a runtime flag. It indicates this code is only included when the `swissmap` experiment is enabled during compilation. This is a key detail about how this specific implementation is activated.

8. **Identify Potential Pitfalls:**  The most obvious pitfall is concurrent access without proper synchronization. The code explicitly checks for this and calls `fatal`. Highlighting this is important for developers using maps. Another subtle point is that the specific "swissmap" optimization might not always be active if the build tag isn't set.

9. **Structure the Answer:** Organize the findings into logical sections: Functionality, Implemented Go Feature, Code Examples, Input/Output, Command-Line Arguments, and Potential Pitfalls. Use clear and concise language, and provide code examples that are easy to understand. Use Chinese as requested.

**Self-Correction/Refinement During the Process:**

* Initially, I might have just focused on the individual functions. But recognizing the `go:linkname` and connecting them to the `runtime` package is crucial for understanding the broader context.
* I might have initially missed the significance of the `go:build` tag. Realizing it controls whether this specific code is used is an important detail.
* When creating the example, ensuring it accurately reflects the function signatures and behaviors (e.g., the two return values of accessing) is essential.

By following these steps and iteratively refining the analysis, we can arrive at a comprehensive and accurate understanding of the provided Go code snippet.
这段代码是 Go 语言运行时（runtime）中 `map` 数据结构针对 `uint64` 类型键的优化实现，使用了名为 "Swiss table" 的哈希表技术。

以下是它的功能列表：

1. **`runtime_mapaccess1_fast64(typ *abi.SwissMapType, m *Map, key uint64) unsafe.Pointer`**:  这个函数实现了在 `key` 为 `uint64` 类型的 `map` `m` 中查找键为 `key` 的元素，并返回其值的指针。如果找不到，则返回指向 `zeroVal` 的指针（表示零值）。它用于 `value := map[key]` 这种只获取值的场景。

2. **`runtime_mapaccess2_fast64(typ *abi.SwissMapType, m *Map, key uint64) (unsafe.Pointer, bool)`**:  这个函数与 `runtime_mapaccess1_fast64` 类似，也是在 `key` 为 `uint64` 类型的 `map` `m` 中查找键为 `key` 的元素。但它返回两个值：值的指针和一个布尔值，指示键是否存在于 `map` 中。它用于 `value, ok := map[key]` 这种需要判断键是否存在的场景。

3. **`runtime_mapassign_fast64(typ *abi.SwissMapType, m *Map, key uint64) unsafe.Pointer`**:  这个函数实现了向 `key` 为 `uint64` 类型的 `map` `m` 中插入或更新键值对。如果键 `key` 不存在，则插入新的键值对；如果键 `key` 已经存在，则更新其对应的值。它返回指向新插入或已存在的值的指针。

4. **`runtime_mapassign_fast64ptr(typ *abi.SwissMapType, m *Map, key unsafe.Pointer) unsafe.Pointer`**: 这个函数的功能与 `runtime_mapassign_fast64` 类似，但是它处理键是指针类型(`unsafe.Pointer`)的情况。这通常用于键是 `uintptr` (在 64 位架构上与 `unsafe.Pointer` 大小相同) 的 map。

5. **`runtime_mapdelete_fast64(typ *abi.SwissMapType, m *Map, key uint64)`**: 这个函数实现了从 `key` 为 `uint64` 类型的 `map` `m` 中删除键为 `key` 的键值对。

**它是什么 Go 语言功能的实现？**

这段代码是 Go 语言 `map` 数据结构针对键类型为 `uint64` 的 **访问 (读取)**、**赋值 (写入/更新)** 和 **删除** 操作的底层实现。由于文件名中包含 `fast64`，可以推断这是对 `uint64` 键的特殊优化版本。 `swiss` 表明使用了 Swiss table 这种高效的哈希表实现。

**Go 代码举例说明:**

```go
package main

import "fmt"

func main() {
	m := make(map[uint64]string)

	// 赋值 (对应 runtime_mapassign_fast64)
	m[100] = "hello"
	m[200] = "world"

	// 访问 (对应 runtime_mapaccess2_fast64)
	value1, ok1 := m[100]
	fmt.Println(value1, ok1) // 输出: hello true

	value2, ok2 := m[300]
	fmt.Println(value2, ok2) // 输出:  false

	// 访问 (对应 runtime_mapaccess1_fast64，在不需要知道键是否存在时使用)
	value3 := m[200]
	fmt.Println(value3)      // 输出: world

	// 删除 (对应 runtime_mapdelete_fast64)
	delete(m, 100)

	value4, ok4 := m[100]
	fmt.Println(value4, ok4) // 输出:  false
}
```

**代码推理和假设的输入与输出:**

以 `runtime_mapaccess1_fast64` 为例：

**假设输入:**

* `typ`: 指向 `abi.SwissMapType` 的指针，描述了 map 的类型信息（例如键和值的大小，哈希函数等）。
* `m`: 指向 `Map` 结构体的指针，表示要操作的 map 实例。
* `key`: 要查找的 `uint64` 类型的键，假设其值为 `12345`.

**内部推理:**

1. **空指针检查和空 Map 检查:** 首先检查 `m` 是否为 `nil` 或 `m` 是否为空 (`m.Used() == 0`)。如果是，则直接返回 `zeroVal` 的指针。

2. **并发读写检查:** 检查 `m.writing` 标志，如果为非零，说明有其他 goroutine 正在进行写操作，此时会调用 `fatal` 报错，防止并发安全问题。

3. **小型 Map 的特殊处理 (`m.dirLen == 0`):** 如果 `dirLen` 为 0，表示这是一个小型 map，其数据直接存储在 `dirPtr` 指向的 group 中。代码会遍历这个 group，查找匹配的键。
   * 假设 `m.dirPtr` 指向的 group 中包含一个键为 `12345` 的键值对。
   * `g.ctrls().matchFull()` 会找到所有已使用的 slot。
   * 代码会逐个比较 slot 中的键，直到找到匹配的 `key` (12345)。
   * 找到匹配后，计算对应值的指针 (`unsafe.Pointer(uintptr(slotKey) + 8)`) 并返回。 这里的 `+ 8` 假设值的大小是 8 字节（需要根据 `typ.SlotSize` 和键的大小来确定）。

4. **大型 Map 的处理 (`m.dirLen > 0`):**
   * **计算哈希:**  使用 `typ.Hasher` 函数计算键 `key` 的哈希值。
   * **选择桶 (table):**  使用哈希值的一部分 (`m.directoryIndex(hash)`) 来选择一个目录项，该目录项指向一个二级 table (`t`).
   * **探测 (probing):** 使用哈希值的另一部分 (`h1(hash)`, `h2(hash)`) 和 `makeProbeSeq` 创建一个探测序列。遍历 table 中的 group (`g`)。
   * **匹配:** 对于每个 group，使用 `g.ctrls().matchH2(h2(hash))` 查找哈希值第二部分匹配的 slot。
   * **键比较:** 如果找到匹配的哈希值，则进一步比较 slot 中的实际键值 (`key == *(*uint64)(slotKey)`)。
   * **找到:** 如果找到匹配的键，则计算对应值的指针并返回。
   * **未找到:** 如果遍历完探测序列，遇到空槽 (`g.ctrls().matchEmpty() != 0`)，则说明键不存在，返回 `zeroVal` 的指针。

**假设输出 (对于上述输入):**

假设在 `m` 中找到了键为 `12345` 的键值对，并且其对应的值存储在内存地址 `0xABCDEF00`，则 `runtime_mapaccess1_fast64` 将返回 `unsafe.Pointer(0xABCDEF00)`.

**命令行参数的具体处理:**

这段代码本身不直接处理命令行参数。它属于 Go 运行时的内部实现，在程序运行时被调用。命令行参数的处理通常发生在 `main` 函数的 `os` 包中，或者使用 `flag` 包进行解析。

不过，需要注意的是代码开头的 `//go:build goexperiment.swissmap`。这是一个 **构建标签 (build tag)**，它指示这段代码只有在编译时启用了 `swissmap` 实验性特性时才会被包含到最终的可执行文件中。这意味着，如果你想使用基于 Swiss table 的 `map` 实现，你可能需要在编译时设置相应的构建约束，例如：

```bash
go build -tags=goexperiment.swissmap your_program.go
```

但这通常是 Go 语言开发团队用于测试新特性的一种方式，普通用户无需手动指定。Go 编译器会根据当前 Go 版本的配置和实验性特性开关来决定是否使用这段代码。

**使用者易犯错的点:**

这段代码是 Go 运行时的内部实现，普通 Go 开发者通常不会直接调用这些函数。然而，理解其背后的原理有助于避免在使用 `map` 时犯一些常见的错误，例如：

1. **并发读写不安全:** 代码中可以看到 `m.writing` 标志用于检测并发写操作。Go 的 `map` **不是并发安全的**。如果在多个 goroutine 中同时读写同一个 `map`，可能会导致程序崩溃或数据不一致。需要使用互斥锁 (sync.Mutex) 或其他并发控制机制来保护 `map` 的并发访问。

   ```go
   package main

   import (
       "fmt"
       "sync"
   )

   func main() {
       m := make(map[uint64]int)
       var wg sync.WaitGroup
       var mutex sync.Mutex

       for i := 0; i < 100; i++ {
           wg.Add(2)
           go func() {
               defer wg.Done()
               mutex.Lock()
               m[1]++
               mutex.Unlock()
           }()
           go func() {
               defer wg.Done()
               mutex.Lock()
               _ = m[1]
               mutex.Unlock()
           }()
       }
       wg.Wait()
       fmt.Println(m)
   }
   ```

   在这个例子中，使用 `sync.Mutex` 来保护对 `map` `m` 的并发读写操作。

2. **对 `nil` Map 进行赋值:**  在 `runtime_mapassign_fast64` 的开头可以看到，如果 `m` 为 `nil`，则会调用 `panic(errNilAssign)`。这意味着不能直接对一个未初始化的 `map` 进行赋值操作。

   ```go
   package main

   func main() {
       var m map[uint64]string
       // m[100] = "hello" // 运行时会 panic: assignment to entry in nil map
       m = make(map[uint64]string)
       m[100] = "hello" // 正确的做法是先使用 make 初始化 map
   }
   ```

总而言之，这段代码是 Go 语言 `map` 数据结构针对 `uint64` 键的一种高效底层实现，使用了 Swiss table 技术来优化查找、插入和删除操作的性能。理解其原理有助于更好地理解 `map` 的行为和避免常见的并发安全问题。

### 提示词
```
这是路径为go/src/internal/runtime/maps/runtime_fast64_swiss.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
```

### 源代码
```go
// Copyright 2024 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build goexperiment.swissmap

package maps

import (
	"internal/abi"
	"internal/race"
	"internal/runtime/sys"
	"unsafe"
)

//go:linkname runtime_mapaccess1_fast64 runtime.mapaccess1_fast64
func runtime_mapaccess1_fast64(typ *abi.SwissMapType, m *Map, key uint64) unsafe.Pointer {
	if race.Enabled && m != nil {
		callerpc := sys.GetCallerPC()
		pc := abi.FuncPCABIInternal(runtime_mapaccess1)
		race.ReadPC(unsafe.Pointer(m), callerpc, pc)
	}

	if m == nil || m.Used() == 0 {
		return unsafe.Pointer(&zeroVal[0])
	}

	if m.writing != 0 {
		fatal("concurrent map read and map write")
		return nil
	}

	if m.dirLen == 0 {
		g := groupReference{
			data: m.dirPtr,
		}
		full := g.ctrls().matchFull()
		slotKey := g.key(typ, 0)
		slotSize := typ.SlotSize
		for full != 0 {
			if key == *(*uint64)(slotKey) && full.lowestSet() {
				slotElem := unsafe.Pointer(uintptr(slotKey) + 8)
				return slotElem
			}
			slotKey = unsafe.Pointer(uintptr(slotKey) + slotSize)
			full = full.shiftOutLowest()
		}
		return unsafe.Pointer(&zeroVal[0])
	}

	k := key
	hash := typ.Hasher(abi.NoEscape(unsafe.Pointer(&k)), m.seed)

	// Select table.
	idx := m.directoryIndex(hash)
	t := m.directoryAt(idx)

	// Probe table.
	seq := makeProbeSeq(h1(hash), t.groups.lengthMask)
	for ; ; seq = seq.next() {
		g := t.groups.group(typ, seq.offset)

		match := g.ctrls().matchH2(h2(hash))

		for match != 0 {
			i := match.first()

			slotKey := g.key(typ, i)
			if key == *(*uint64)(slotKey) {
				slotElem := unsafe.Pointer(uintptr(slotKey) + 8)
				return slotElem
			}
			match = match.removeFirst()
		}

		match = g.ctrls().matchEmpty()
		if match != 0 {
			// Finding an empty slot means we've reached the end of
			// the probe sequence.
			return unsafe.Pointer(&zeroVal[0])
		}
	}
}

//go:linkname runtime_mapaccess2_fast64 runtime.mapaccess2_fast64
func runtime_mapaccess2_fast64(typ *abi.SwissMapType, m *Map, key uint64) (unsafe.Pointer, bool) {
	if race.Enabled && m != nil {
		callerpc := sys.GetCallerPC()
		pc := abi.FuncPCABIInternal(runtime_mapaccess1)
		race.ReadPC(unsafe.Pointer(m), callerpc, pc)
	}

	if m == nil || m.Used() == 0 {
		return unsafe.Pointer(&zeroVal[0]), false
	}

	if m.writing != 0 {
		fatal("concurrent map read and map write")
		return nil, false
	}

	if m.dirLen == 0 {
		g := groupReference{
			data: m.dirPtr,
		}
		full := g.ctrls().matchFull()
		slotKey := g.key(typ, 0)
		slotSize := typ.SlotSize
		for full != 0 {
			if key == *(*uint64)(slotKey) && full.lowestSet() {
				slotElem := unsafe.Pointer(uintptr(slotKey) + 8)
				return slotElem, true
			}
			slotKey = unsafe.Pointer(uintptr(slotKey) + slotSize)
			full = full.shiftOutLowest()
		}
		return unsafe.Pointer(&zeroVal[0]), false
	}

	k := key
	hash := typ.Hasher(abi.NoEscape(unsafe.Pointer(&k)), m.seed)

	// Select table.
	idx := m.directoryIndex(hash)
	t := m.directoryAt(idx)

	// Probe table.
	seq := makeProbeSeq(h1(hash), t.groups.lengthMask)
	for ; ; seq = seq.next() {
		g := t.groups.group(typ, seq.offset)

		match := g.ctrls().matchH2(h2(hash))

		for match != 0 {
			i := match.first()

			slotKey := g.key(typ, i)
			if key == *(*uint64)(slotKey) {
				slotElem := unsafe.Pointer(uintptr(slotKey) + 8)
				return slotElem, true
			}
			match = match.removeFirst()
		}

		match = g.ctrls().matchEmpty()
		if match != 0 {
			// Finding an empty slot means we've reached the end of
			// the probe sequence.
			return unsafe.Pointer(&zeroVal[0]), false
		}
	}
}

func (m *Map) putSlotSmallFast64(typ *abi.SwissMapType, hash uintptr, key uint64) unsafe.Pointer {
	g := groupReference{
		data: m.dirPtr,
	}

	match := g.ctrls().matchH2(h2(hash))

	// Look for an existing slot containing this key.
	for match != 0 {
		i := match.first()

		slotKey := g.key(typ, i)
		if key == *(*uint64)(slotKey) {
			slotElem := g.elem(typ, i)
			return slotElem
		}
		match = match.removeFirst()
	}

	// There can't be deleted slots, small maps can't have them
	// (see deleteSmall). Use matchEmptyOrDeleted as it is a bit
	// more efficient than matchEmpty.
	match = g.ctrls().matchEmptyOrDeleted()
	if match == 0 {
		fatal("small map with no empty slot (concurrent map writes?)")
	}

	i := match.first()

	slotKey := g.key(typ, i)
	*(*uint64)(slotKey) = key

	slotElem := g.elem(typ, i)

	g.ctrls().set(i, ctrl(h2(hash)))
	m.used++

	return slotElem
}

//go:linkname runtime_mapassign_fast64 runtime.mapassign_fast64
func runtime_mapassign_fast64(typ *abi.SwissMapType, m *Map, key uint64) unsafe.Pointer {
	if m == nil {
		panic(errNilAssign)
	}
	if race.Enabled {
		callerpc := sys.GetCallerPC()
		pc := abi.FuncPCABIInternal(runtime_mapassign)
		race.WritePC(unsafe.Pointer(m), callerpc, pc)
	}
	if m.writing != 0 {
		fatal("concurrent map writes")
	}

	k := key
	hash := typ.Hasher(abi.NoEscape(unsafe.Pointer(&k)), m.seed)

	// Set writing after calling Hasher, since Hasher may panic, in which
	// case we have not actually done a write.
	m.writing ^= 1 // toggle, see comment on writing

	if m.dirPtr == nil {
		m.growToSmall(typ)
	}

	if m.dirLen == 0 {
		if m.used < abi.SwissMapGroupSlots {
			elem := m.putSlotSmallFast64(typ, hash, key)

			if m.writing == 0 {
				fatal("concurrent map writes")
			}
			m.writing ^= 1

			return elem
		}

		// Can't fit another entry, grow to full size map.
		m.growToTable(typ)
	}

	var slotElem unsafe.Pointer
outer:
	for {
		// Select table.
		idx := m.directoryIndex(hash)
		t := m.directoryAt(idx)

		seq := makeProbeSeq(h1(hash), t.groups.lengthMask)

		// As we look for a match, keep track of the first deleted slot
		// we find, which we'll use to insert the new entry if
		// necessary.
		var firstDeletedGroup groupReference
		var firstDeletedSlot uintptr

		for ; ; seq = seq.next() {
			g := t.groups.group(typ, seq.offset)
			match := g.ctrls().matchH2(h2(hash))

			// Look for an existing slot containing this key.
			for match != 0 {
				i := match.first()

				slotKey := g.key(typ, i)
				if key == *(*uint64)(slotKey) {
					slotElem = g.elem(typ, i)

					t.checkInvariants(typ, m)
					break outer
				}
				match = match.removeFirst()
			}

			// No existing slot for this key in this group. Is this the end
			// of the probe sequence?
			match = g.ctrls().matchEmptyOrDeleted()
			if match == 0 {
				continue // nothing but filled slots. Keep probing.
			}
			i := match.first()
			if g.ctrls().get(i) == ctrlDeleted {
				// There are some deleted slots. Remember
				// the first one, and keep probing.
				if firstDeletedGroup.data == nil {
					firstDeletedGroup = g
					firstDeletedSlot = i
				}
				continue
			}
			// We've found an empty slot, which means we've reached the end of
			// the probe sequence.

			// If we found a deleted slot along the way, we can
			// replace it without consuming growthLeft.
			if firstDeletedGroup.data != nil {
				g = firstDeletedGroup
				i = firstDeletedSlot
				t.growthLeft++ // will be decremented below to become a no-op.
			}

			// If there is room left to grow, just insert the new entry.
			if t.growthLeft > 0 {
				slotKey := g.key(typ, i)
				*(*uint64)(slotKey) = key

				slotElem = g.elem(typ, i)

				g.ctrls().set(i, ctrl(h2(hash)))
				t.growthLeft--
				t.used++
				m.used++

				t.checkInvariants(typ, m)
				break outer
			}

			t.rehash(typ, m)
			continue outer
		}
	}

	if m.writing == 0 {
		fatal("concurrent map writes")
	}
	m.writing ^= 1

	return slotElem
}

func (m *Map) putSlotSmallFastPtr(typ *abi.SwissMapType, hash uintptr, key unsafe.Pointer) unsafe.Pointer {
	g := groupReference{
		data: m.dirPtr,
	}

	match := g.ctrls().matchH2(h2(hash))

	// Look for an existing slot containing this key.
	for match != 0 {
		i := match.first()

		slotKey := g.key(typ, i)
		if key == *(*unsafe.Pointer)(slotKey) {
			slotElem := g.elem(typ, i)
			return slotElem
		}
		match = match.removeFirst()
	}

	// There can't be deleted slots, small maps can't have them
	// (see deleteSmall). Use matchEmptyOrDeleted as it is a bit
	// more efficient than matchEmpty.
	match = g.ctrls().matchEmptyOrDeleted()
	if match == 0 {
		fatal("small map with no empty slot (concurrent map writes?)")
	}

	i := match.first()

	slotKey := g.key(typ, i)
	*(*unsafe.Pointer)(slotKey) = key

	slotElem := g.elem(typ, i)

	g.ctrls().set(i, ctrl(h2(hash)))
	m.used++

	return slotElem
}

// Key is a 64-bit pointer (only called on 64-bit GOARCH).
//
//go:linkname runtime_mapassign_fast64ptr runtime.mapassign_fast64ptr
func runtime_mapassign_fast64ptr(typ *abi.SwissMapType, m *Map, key unsafe.Pointer) unsafe.Pointer {
	if m == nil {
		panic(errNilAssign)
	}
	if race.Enabled {
		callerpc := sys.GetCallerPC()
		pc := abi.FuncPCABIInternal(runtime_mapassign)
		race.WritePC(unsafe.Pointer(m), callerpc, pc)
	}
	if m.writing != 0 {
		fatal("concurrent map writes")
	}

	k := key
	hash := typ.Hasher(abi.NoEscape(unsafe.Pointer(&k)), m.seed)

	// Set writing after calling Hasher, since Hasher may panic, in which
	// case we have not actually done a write.
	m.writing ^= 1 // toggle, see comment on writing

	if m.dirPtr == nil {
		m.growToSmall(typ)
	}

	if m.dirLen == 0 {
		if m.used < abi.SwissMapGroupSlots {
			elem := m.putSlotSmallFastPtr(typ, hash, key)

			if m.writing == 0 {
				fatal("concurrent map writes")
			}
			m.writing ^= 1

			return elem
		}

		// Can't fit another entry, grow to full size map.
		m.growToTable(typ)
	}

	var slotElem unsafe.Pointer
outer:
	for {
		// Select table.
		idx := m.directoryIndex(hash)
		t := m.directoryAt(idx)

		seq := makeProbeSeq(h1(hash), t.groups.lengthMask)

		// As we look for a match, keep track of the first deleted slot
		// we find, which we'll use to insert the new entry if
		// necessary.
		var firstDeletedGroup groupReference
		var firstDeletedSlot uintptr

		for ; ; seq = seq.next() {
			g := t.groups.group(typ, seq.offset)
			match := g.ctrls().matchH2(h2(hash))

			// Look for an existing slot containing this key.
			for match != 0 {
				i := match.first()

				slotKey := g.key(typ, i)
				if key == *(*unsafe.Pointer)(slotKey) {
					slotElem = g.elem(typ, i)

					t.checkInvariants(typ, m)
					break outer
				}
				match = match.removeFirst()
			}

			// No existing slot for this key in this group. Is this the end
			// of the probe sequence?
			match = g.ctrls().matchEmptyOrDeleted()
			if match == 0 {
				continue // nothing but filled slots. Keep probing.
			}
			i := match.first()
			if g.ctrls().get(i) == ctrlDeleted {
				// There are some deleted slots. Remember
				// the first one, and keep probing.
				if firstDeletedGroup.data == nil {
					firstDeletedGroup = g
					firstDeletedSlot = i
				}
				continue
			}
			// We've found an empty slot, which means we've reached the end of
			// the probe sequence.

			// If we found a deleted slot along the way, we can
			// replace it without consuming growthLeft.
			if firstDeletedGroup.data != nil {
				g = firstDeletedGroup
				i = firstDeletedSlot
				t.growthLeft++ // will be decremented below to become a no-op.
			}

			// If there is room left to grow, just insert the new entry.
			if t.growthLeft > 0 {
				slotKey := g.key(typ, i)
				*(*unsafe.Pointer)(slotKey) = key

				slotElem = g.elem(typ, i)

				g.ctrls().set(i, ctrl(h2(hash)))
				t.growthLeft--
				t.used++
				m.used++

				t.checkInvariants(typ, m)
				break outer
			}

			t.rehash(typ, m)
			continue outer
		}
	}

	if m.writing == 0 {
		fatal("concurrent map writes")
	}
	m.writing ^= 1

	return slotElem
}

//go:linkname runtime_mapdelete_fast64 runtime.mapdelete_fast64
func runtime_mapdelete_fast64(typ *abi.SwissMapType, m *Map, key uint64) {
	if race.Enabled {
		callerpc := sys.GetCallerPC()
		pc := abi.FuncPCABIInternal(runtime_mapassign)
		race.WritePC(unsafe.Pointer(m), callerpc, pc)
	}

	if m == nil || m.Used() == 0 {
		return
	}

	m.Delete(typ, abi.NoEscape(unsafe.Pointer(&key)))
}
```