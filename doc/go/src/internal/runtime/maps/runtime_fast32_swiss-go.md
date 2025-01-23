Response:
Let's break down the thought process for analyzing this Go code snippet.

**1. Initial Scan and Keywords:**

First, I'd quickly scan the code for recognizable keywords and function names. I see:

* `package maps`:  Indicates this is about map implementations.
* `//go:build goexperiment.swissmap`: This is crucial. It tells me this code is part of an *experimental* feature. This immediately sets a context: it's likely a newer, potentially faster, but not yet standard map implementation.
* `//go:linkname runtime_mapaccess1_fast32 runtime.mapaccess1_fast32`:  These `linkname` directives are strong hints. They suggest this code is *replacing* existing runtime functions related to map access and manipulation. The `fast32` suffix suggests it's optimized for maps where the key is a `uint32`.
* `runtime_mapaccess1_fast32`, `runtime_mapaccess2_fast32`, `runtime_mapassign_fast32`, `runtime_mapdelete_fast32`:  These are the core operations on a map: read (access), read with existence check (access2), write (assign), and delete.
* `unsafe.Pointer`:  Frequent use of `unsafe.Pointer` signals low-level manipulation of memory, further reinforcing the idea of a runtime optimization.
* `race.Enabled`, `race.ReadPC`, `race.WritePC`: This indicates the code is aware of and interacts with Go's race detection mechanism, ensuring proper handling of concurrent access.
* `m *Map`: This likely represents the internal structure of the map.
* `typ *abi.SwissMapType`: The `SwissMapType` name strongly suggests a particular data structure or algorithm is being implemented. A quick search reveals "Swiss tables" as a known efficient hash table implementation.
* `hash`, `h1`, `h2`:  These relate to hashing functions, essential for hash tables.
* `groupReference`, `ctrls`:  These likely point to internal structures related to the "Swiss table" organization.
* `growToSmall`, `growToTable`, `rehash`:  These functions relate to how the map resizes itself as it fills up.
* `fatal("concurrent ...")`:  Error handling for concurrent access.

**2. Inferring Functionality:**

Based on the function names and the `linkname` directives, it's clear this code implements the core map operations (`access`, `assign`, `delete`) specifically optimized for `uint32` keys within an experimental "Swiss table" map implementation.

* **`runtime_mapaccess1_fast32`**:  Looks up a value by key and returns a pointer to it.
* **`runtime_mapaccess2_fast32`**:  Looks up a value by key and returns a pointer to it *and* a boolean indicating whether the key was found.
* **`runtime_mapassign_fast32`**:  Sets or updates the value associated with a key. Handles map growth and rehashing.
* **`runtime_mapdelete_fast32`**: Removes the entry associated with a key.

**3. Connecting to Go Language Features:**

The most obvious Go language feature this relates to is the **`map` data structure**. This code is a low-level implementation detail of how `map[uint32]T` (where `T` is some type) might work when the `goexperiment.swissmap` build tag is enabled.

**4. Crafting the Example:**

To illustrate, I need a simple Go program that uses a `map[uint32]string`. This directly aligns with the `fast32` suffix. The example should demonstrate both reading and writing to the map.

```go
package main

import "fmt"

func main() {
	m := make(map[uint32]string)
	m[10] = "hello"
	value, ok := m[10]
	fmt.Println(value, ok) // Output: hello true
	value, ok = m[20]
	fmt.Println(value, ok) // Output:  false
}
```

**5. Reasoning about Input and Output:**

For `runtime_mapaccess1_fast32` and `runtime_mapaccess2_fast32`, the input is the map (`m`) and the key (`key uint32`). The output is a pointer to the value (and a boolean for `access2`). If the key isn't found, it returns a pointer to `zeroVal`.

For `runtime_mapassign_fast32`, the input is the map (`m`) and the key-value pair (`key uint32`, implicitly the value being assigned). The output is a pointer to the memory location where the value is stored.

For `runtime_mapdelete_fast32`, the input is the map (`m`) and the key (`key uint32`). There's no explicit return value, but the *effect* is the removal of the key-value pair from the map.

**6. Considering Command-Line Arguments:**

The `//go:build goexperiment.swissmap` directive is a build tag. This isn't a command-line argument *to* the compiled program, but rather an instruction *to the Go compiler* during the build process. To use this code, you'd need to build your Go program with this tag:

```bash
go build -tags=goexperiment.swissmap your_program.go
```

**7. Identifying Potential Pitfalls:**

The most obvious pitfall is forgetting the `-tags=goexperiment.swissmap` flag. If you don't include this, the standard Go map implementation will be used, and this specific code will be ignored. This could lead to confusion if you're trying to benchmark or understand the behavior of this experimental feature.

**8. Structuring the Answer:**

Finally, organize the findings into a clear and structured answer using the requested format (functionality, Go feature, code example, input/output, command-line arguments, potential pitfalls). Use clear, concise language and provide enough detail for someone unfamiliar with the code to understand its purpose. Emphasize the experimental nature of the code.
这段代码是 Go 语言运行时（runtime）中关于 map 实现的一部分，特别是针对键类型为 `uint32` 的 map 的优化实现，被称为 "fast32"。 它使用了名为 "Swiss table" 的哈希表算法。

**功能列举:**

1. **`runtime_mapaccess1_fast32(typ *abi.SwissMapType, m *Map, key uint32) unsafe.Pointer`**:  实现 map 的读取操作，给定 map `m` 和键 `key`，返回对应值的指针。如果键不存在，则返回指向零值的指针。这是一个不返回布尔值指示键是否存在的访问函数。

2. **`runtime_mapaccess2_fast32(typ *abi.SwissMapType, m *Map, key uint32) (unsafe.Pointer, bool)`**: 实现 map 的读取操作，给定 map `m` 和键 `key`，返回对应值的指针以及一个布尔值，指示键是否存在于 map 中。

3. **`runtime_mapassign_fast32(typ *abi.SwissMapType, m *Map, key uint32) unsafe.Pointer`**: 实现 map 的赋值或更新操作，给定 map `m` 和键 `key`，返回指向该键对应值的指针。如果键不存在，则会插入新的键值对。

4. **`runtime_mapdelete_fast32(typ *abi.SwissMapType, m *Map, key uint32)`**: 实现 map 的删除操作，给定 map `m` 和键 `key`，从 map 中移除该键值对。

5. **`putSlotSmallFast32(typ *abi.SwissMapType, hash uintptr, key uint32) unsafe.Pointer`**:  这是 `runtime_mapassign_fast32` 的一个辅助函数，用于在小 map 中插入新的键值对。小 map 的实现方式与大 map 不同，它没有目录层级。

**实现的 Go 语言功能:**

这段代码是 Go 语言中 `map` 数据结构针对键类型为 `uint32` 的一种优化实现。当 Go 程序的 map 的键类型为 `uint32` 并且启用了 `goexperiment.swissmap` 构建标签时，Go 编译器可能会选择使用这部分代码来实现 map 的操作。

**Go 代码举例说明:**

```go
//go:build goexperiment.swissmap

package main

import "fmt"

func main() {
	m := make(map[uint32]string)

	// 赋值
	m[10] = "hello"
	m[20] = "world"

	// 读取 (使用类似 runtime_mapaccess2_fast32 的效果)
	value1, ok1 := m[10]
	fmt.Println(value1, ok1) // 输出: hello true

	value2, ok2 := m[30]
	fmt.Println(value2, ok2) // 输出:  false

	// 更新
	m[10] = "你好"

	// 读取
	value3, ok3 := m[10]
	fmt.Println(value3, ok3) // 输出: 你好 true

	// 删除
	delete(m, 20)

	// 读取
	value4, ok4 := m[20]
	fmt.Println(value4, ok4) // 输出:  false
}
```

**假设的输入与输出 (针对 `runtime_mapaccess2_fast32`)：**

假设我们有以下输入：

* `typ`:  一个描述 `map[uint32]string` 类型的 `abi.SwissMapType` 结构体。
* `m`:  一个指向 `map[uint32]string` 的内部表示 `Map` 结构体的指针，其中包含键值对 `{10: "hello", 20: "world"}`。
* `key`:  `uint32` 类型的键，例如 `uint32(10)` 或 `uint32(30)`。

**输出示例 1 (key 存在):**

* 输入 `key`: `uint32(10)`
* 输出 `unsafe.Pointer`: 指向字符串 "hello" 的内存地址。
* 输出 `bool`: `true`

**输出示例 2 (key 不存在):**

* 输入 `key`: `uint32(30)`
* 输出 `unsafe.Pointer`: 指向零值（对于字符串来说是空字符串 "" 的内部表示）的内存地址。
* 输出 `bool`: `false`

**代码推理:**

这段代码的核心是实现了 "Swiss table" 这种哈希表。  它使用了 control bytes (`ctrls`) 来高效地存储每个 bucket 的元数据，例如是否为空、是否包含特定的哈希值等。

* **查找 (access):**  `runtime_mapaccess1_fast32` 和 `runtime_mapaccess2_fast32` 首先计算键的哈希值，然后根据哈希值找到对应的 bucket 组（group）。  在 bucket 组内，它会比较 control bytes 来快速定位可能包含目标键的 slot。如果找到匹配的键，则返回对应的值。

* **赋值 (assign):** `runtime_mapassign_fast32` 类似地找到目标 bucket 组。如果键已存在，则更新值。如果键不存在，它会找到一个空槽位插入新的键值对。如果 map 已满，则会触发扩容 (`growToTable`) 或进行小的本地增长 (`growToSmall`)。代码中还处理了已删除的槽位，以便重用这些空间。

* **删除 (delete):** `runtime_mapdelete_fast32` 找到包含目标键的 bucket，并将对应的 control byte 标记为已删除。

**命令行参数的具体处理:**

这段代码本身不直接处理命令行参数。它的启用依赖于 Go 编译器的构建标签。要使用这段代码实现的 map，需要在编译 Go 程序时指定 `-tags` 参数：

```bash
go build -tags=goexperiment.swissmap your_program.go
```

这里的 `-tags=goexperiment.swissmap` 告诉 Go 编译器在构建时包含带有 `//go:build goexperiment.swissmap` 标签的代码。如果不指定这个标签，Go 编译器将使用默认的 map 实现。

**使用者易犯错的点:**

* **忘记使用构建标签:**  最大的错误是开发者期望使用这段代码优化的 map 实现，但忘记在编译时添加 `-tags=goexperiment.swissmap`。  在这种情况下，程序会正常运行，但使用的是 Go 默认的 map 实现，而不是 `runtime_fast32_swiss.go` 中的实现。这可能导致性能测试结果与预期不符。

* **假设所有 `uint32` 键的 map 都使用此实现:**  开发者可能会错误地认为只要 map 的键类型是 `uint32`，就会自动使用 `runtime_fast32_swiss.go` 的实现。  实际上，这取决于构建标签的设置。

* **在非实验环境中使用:**  由于 `goexperiment.swissmap` 是一个实验性的特性，依赖于此可能会导致在未来的 Go 版本中行为发生变化，甚至被移除。  不应在生产环境的关键路径上过度依赖实验性特性。

**总结:**

`runtime_fast32_swiss.go` 是 Go 语言运行时中针对 `map[uint32]T` 的一种优化实现，使用了 Swiss table 算法。它的启用需要通过构建标签来控制。理解这一点对于想要利用或测试这种优化的开发者至关重要。

### 提示词
```
这是路径为go/src/internal/runtime/maps/runtime_fast32_swiss.go的go语言实现的一部分， 请列举一下它的功能, 　
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

//go:linkname runtime_mapaccess1_fast32 runtime.mapaccess1_fast32
func runtime_mapaccess1_fast32(typ *abi.SwissMapType, m *Map, key uint32) unsafe.Pointer {
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
			if key == *(*uint32)(slotKey) && full.lowestSet() {
				slotElem := unsafe.Pointer(uintptr(slotKey) + typ.ElemOff)
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
			if key == *(*uint32)(slotKey) {
				slotElem := unsafe.Pointer(uintptr(slotKey) + typ.ElemOff)
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

//go:linkname runtime_mapaccess2_fast32 runtime.mapaccess2_fast32
func runtime_mapaccess2_fast32(typ *abi.SwissMapType, m *Map, key uint32) (unsafe.Pointer, bool) {
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
			if key == *(*uint32)(slotKey) && full.lowestSet() {
				slotElem := unsafe.Pointer(uintptr(slotKey) + typ.ElemOff)
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
			if key == *(*uint32)(slotKey) {
				slotElem := unsafe.Pointer(uintptr(slotKey) + typ.ElemOff)
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

func (m *Map) putSlotSmallFast32(typ *abi.SwissMapType, hash uintptr, key uint32) unsafe.Pointer {
	g := groupReference{
		data: m.dirPtr,
	}

	match := g.ctrls().matchH2(h2(hash))

	// Look for an existing slot containing this key.
	for match != 0 {
		i := match.first()

		slotKey := g.key(typ, i)
		if key == *(*uint32)(slotKey) {
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
	*(*uint32)(slotKey) = key

	slotElem := g.elem(typ, i)

	g.ctrls().set(i, ctrl(h2(hash)))
	m.used++

	return slotElem
}

//go:linkname runtime_mapassign_fast32 runtime.mapassign_fast32
func runtime_mapassign_fast32(typ *abi.SwissMapType, m *Map, key uint32) unsafe.Pointer {
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
			elem := m.putSlotSmallFast32(typ, hash, key)

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
				if key == *(*uint32)(slotKey) {
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
				*(*uint32)(slotKey) = key

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

// Key is a 32-bit pointer (only called on 32-bit GOARCH). This source is identical to fast64ptr.
//
// TODO(prattmic): With some compiler refactoring we could avoid duplication of this function.
//
//go:linkname runtime_mapassign_fast32ptr runtime.mapassign_fast32ptr
func runtime_mapassign_fast32ptr(typ *abi.SwissMapType, m *Map, key unsafe.Pointer) unsafe.Pointer {
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

		// As we look for a match, keep track of the first deleted slot we
		// find, which we'll use to insert the new entry if necessary.
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

//go:linkname runtime_mapdelete_fast32 runtime.mapdelete_fast32
func runtime_mapdelete_fast32(typ *abi.SwissMapType, m *Map, key uint32) {
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