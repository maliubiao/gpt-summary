Response:
My thought process for analyzing the `table.go` code snippet and generating the answer follows these steps:

1. **Understand the Goal:** The request asks for a functional summary of the provided Go code, identification of the Go feature it implements, a code example demonstrating its use (with assumptions), and a summary of its functionality (for part 1).

2. **High-Level Code Scan:** I first scanned the code to identify key data structures, functions, and constants. Keywords like `table`, `groups`, `hash`, `Get`, `PutSlot`, `Delete`, `Iter`, `rehash`, `grow`, and `split` stood out. The package name `maps` and the copyright header immediately suggested this was related to Go's built-in `map` type.

3. **Identify Core Data Structure:** The `table` struct is clearly the central data structure. I paid attention to its fields:
    * `used`: Number of elements.
    * `capacity`: Total slots.
    * `growthLeft`: Slots available before rehashing.
    * `localDepth`:  Related to directory structure (for larger maps).
    * `index`: Index in the map's directory.
    * `groups`:  The actual storage for key-value pairs and control bytes.

4. **Analyze Key Functions:**  I then focused on the core functions:
    * `newTable`: Table creation.
    * `reset`:  Initialization/resetting of a table.
    * `Get`, `getWithKey`, `getWithoutKey`: Key lookup. The `probeSeq` concept and control bytes (`ctrls`) were notable for understanding the hashing strategy.
    * `PutSlot`, `uncheckedPutSlot`: Key insertion. The handling of deleted slots (tombstones) was interesting.
    * `Delete`: Key removal.
    * `Clear`: Removing all entries.
    * `Iter`, `Init`, `Next`:  Implementation of map iteration.
    * `rehash`, `grow`, `split`: Mechanisms for resizing the underlying storage. The distinction between `grow` and `split` was important.

5. **Infer the Go Feature:** Based on the function names (`Get`, `PutSlot`, `Delete`, `Iter`), the data structures (key-value storage), and the overall purpose, it became clear that this code implements a hash table, which is the underlying mechanism for Go's `map`. The presence of `rehash`, `grow`, and `split` further confirmed this, as these are common operations for dynamically sized hash tables.

6. **Construct a Code Example:** To illustrate the use, I created a simple Go program demonstrating common map operations: creation, insertion, retrieval, and deletion. I kept it straightforward and focused on the core functionalities implemented in the provided snippet. Since the provided code is internal, I used the standard `map[string]int` syntax, as the internal implementation details are generally hidden from the user.

7. **Address Input/Output and Command-Line Arguments:**  The provided snippet is a data structure implementation; it doesn't directly handle command-line arguments. Map creation and manipulation happen within the Go program's logic. Therefore, I stated that command-line argument processing isn't directly involved.

8. **Identify Potential Pitfalls:**  I considered common mistakes users make with maps. Concurrent access without proper synchronization is a classic issue. I provided an example of a data race to highlight this.

9. **Summarize Functionality (Part 1):** Finally, I concisely summarized the main responsibilities of the `table.go` code in the provided snippet, focusing on its role as a hash table implementation for Go maps.

10. **Review and Refine:** I reviewed my answer for clarity, accuracy, and completeness, ensuring it directly addressed all parts of the prompt. I double-checked the code example to make sure it was valid Go code and illustrated the intended functionality. I also made sure the explanation of potential errors was clear and concise.

Essentially, I followed a process of dissecting the code, identifying its purpose and key components, connecting it to the broader context of Go's `map` functionality, and then illustrating its use and potential pitfalls with practical examples. The structure of the request itself guided my analysis, prompting me to consider different aspects of the code's behavior.
```
这是路径为go/src/internal/runtime/maps/table.go的go语言实现的一部分， 请列举一下它的功能,
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明,
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第1部分，共2部分，请归纳一下它的功能
"""
// Copyright 2024 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package maps implements Go's builtin map type.
package maps

import (
	"internal/abi"
	"internal/goarch"
	"unsafe"
)

// Maximum size of a table before it is split at the directory level.
//
// TODO: Completely made up value. This should be tuned for performance vs grow
// latency.
// TODO: This should likely be based on byte size, as copying costs will
// dominate grow latency for large objects.
const maxTableCapacity = 1024

// Ensure the max capacity fits in uint16, used for capacity and growthLeft
// below.
var _ = uint16(maxTableCapacity)

// table is a Swiss table hash table structure.
//
// Each table is a complete hash table implementation.
//
// Map uses one or more tables to store entries. Extendible hashing (hash
// prefix) is used to select the table to use for a specific key. Using
// multiple tables enables incremental growth by growing only one table at a
// time.
type table struct {
	// The number of filled slots (i.e. the number of elements in the table).
	used uint16

	// The total number of slots (always 2^N). Equal to
	// `(groups.lengthMask+1)*abi.SwissMapGroupSlots`.
	capacity uint16

	// The number of slots we can still fill without needing to rehash.
	//
	// We rehash when used + tombstones > loadFactor*capacity, including
	// tombstones so the table doesn't overfill with tombstones. This field
	// counts down remaining empty slots before the next rehash.
	growthLeft uint16

	// The number of bits used by directory lookups above this table. Note
	// that this may be less then globalDepth, if the directory has grown
	// but this table has not yet been split.
	localDepth uint8

	// Index of this table in the Map directory. This is the index of the
	// _first_ location in the directory. The table may occur in multiple
	// sequential indicies.
	//
	// index is -1 if the table is stale (no longer installed in the
	// directory).
	index int

	// groups is an array of slot groups. Each group holds abi.SwissMapGroupSlots
	// key/elem slots and their control bytes. A table has a fixed size
	// groups array. The table is replaced (in rehash) when more space is
	// required.
	//
	// TODO(prattmic): keys and elements are interleaved to maximize
	// locality, but it comes at the expense of wasted space for some types
	// (consider uint8 key, uint64 element). Consider placing all keys
	// together in these cases to save space.
	groups groupsReference
}

func newTable(typ *abi.SwissMapType, capacity uint64, index int, localDepth uint8) *table {
	if capacity < abi.SwissMapGroupSlots {
		capacity = abi.SwissMapGroupSlots
	}

	t := &table{
		index:      index,
		localDepth: localDepth,
	}

	if capacity > maxTableCapacity {
		panic("initial table capacity too large")
	}

	// N.B. group count must be a power of two for probeSeq to visit every
	// group.
	capacity, overflow := alignUpPow2(capacity)
	if overflow {
		panic("rounded-up capacity overflows uint64")
	}

	t.reset(typ, uint16(capacity))

	return t
}

// reset resets the table with new, empty groups with the specified new total
// capacity.
func (t *table) reset(typ *abi.SwissMapType, capacity uint16) {
	groupCount := uint64(capacity) / abi.SwissMapGroupSlots
	t.groups = newGroups(typ, groupCount)
	t.capacity = capacity
	t.resetGrowthLeft()

	for i := uint64(0); i <= t.groups.lengthMask; i++ {
		g := t.groups.group(typ, i)
		g.ctrls().setEmpty()
	}
}

// Preconditions: table must be empty.
func (t *table) resetGrowthLeft() {
	var growthLeft uint16
	if t.capacity == 0 {
		// No real reason to support zero capacity table, since an
		// empty Map simply won't have a table.
		panic("table must have positive capacity")
	} else if t.capacity <= abi.SwissMapGroupSlots {
		// If the map fits in a single group then we're able to fill all of
		// the slots except 1 (an empty slot is needed to terminate find
		// operations).
		//
		// TODO(go.dev/issue/54766): With a special case in probing for
		// single-group tables, we could fill all slots.
		growthLeft = t.capacity - 1
	} else {
		if t.capacity*maxAvgGroupLoad < t.capacity {
			// TODO(prattmic): Do something cleaner.
			panic("overflow")
		}
		growthLeft = (t.capacity * maxAvgGroupLoad) / abi.SwissMapGroupSlots
	}
	t.growthLeft = growthLeft
}

func (t *table) Used() uint64 {
	return uint64(t.used)
}

// Get performs a lookup of the key that key points to. It returns a pointer to
// the element, or false if the key doesn't exist.
func (t *table) Get(typ *abi.SwissMapType, m *Map, key unsafe.Pointer) (unsafe.Pointer, bool) {
	// TODO(prattmic): We could avoid hashing in a variety of special
	// cases.
	//
	// - One entry maps could just directly compare the single entry
	//   without hashing.
	// - String keys could do quick checks of a few bytes before hashing.
	hash := typ.Hasher(key, m.seed)
	_, elem, ok := t.getWithKey(typ, hash, key)
	return elem, ok
}

// getWithKey performs a lookup of key, returning a pointer to the version of
// the key in the map in addition to the element.
//
// This is relevant when multiple different key values compare equal (e.g.,
// +0.0 and -0.0). When a grow occurs during iteration, iteration perform a
// lookup of keys from the old group in the new group in order to correctly
// expose updated elements. For NeedsKeyUpdate keys, iteration also must return
// the new key value, not the old key value.
// hash must be the hash of the key.
func (t *table) getWithKey(typ *abi.SwissMapType, hash uintptr, key unsafe.Pointer) (unsafe.Pointer, unsafe.Pointer, bool) {
	// To find the location of a key in the table, we compute hash(key). From
	// h1(hash(key)) and the capacity, we construct a probeSeq that visits
	// every group of slots in some interesting order. See [probeSeq].
	//
	// We walk through these indices. At each index, we select the entire
	// group starting with that index and extract potential candidates:
	// occupied slots with a control byte equal to h2(hash(key)). The key
	// at candidate slot i is compared with key; if key == g.slot(i).key
	// we are done and return the slot; if there is an empty slot in the
	// group, we stop and return an error; otherwise we continue to the
	// next probe index. Tombstones (ctrlDeleted) effectively behave like
	// full slots that never match the value we're looking for.
	//
	// The h2 bits ensure when we compare a key we are likely to have
	// actually found the object. That is, the chance is low that keys
	// compare false. Thus, when we search for an object, we are unlikely
	// to call Equal many times. This likelihood can be analyzed as follows
	// (assuming that h2 is a random enough hash function).
	//
	// Let's assume that there are k "wrong" objects that must be examined
	// in a probe sequence. For example, when doing a find on an object
	// that is in the table, k is the number of objects between the start
	// of the probe sequence and the final found object (not including the
	// final found object). The expected number of objects with an h2 match
	// is then k/128. Measurements and analysis indicate that even at high
	// load factors, k is less than 32, meaning that the number of false
	// positive comparisons we must perform is less than 1/8 per find.
	seq := makeProbeSeq(h1(hash), t.groups.lengthMask)
	for ; ; seq = seq.next() {
		g := t.groups.group(typ, seq.offset)

		match := g.ctrls().matchH2(h2(hash))

		for match != 0 {
			i := match.first()

			slotKey := g.key(typ, i)
			if typ.IndirectKey() {
				slotKey = *((*unsafe.Pointer)(slotKey))
			}
			if typ.Key.Equal(key, slotKey) {
				slotElem := g.elem(typ, i)
				if typ.IndirectElem() {
					slotElem = *((*unsafe.Pointer)(slotElem))
				}
				return slotKey, slotElem, true
			}
			match = match.removeFirst()
		}

		match = g.ctrls().matchEmpty()
		if match != 0 {
			// Finding an empty slot means we've reached the end of
			// the probe sequence.
			return nil, nil, false
		}
	}
}

func (t *table) getWithoutKey(typ *abi.SwissMapType, hash uintptr, key unsafe.Pointer) (unsafe.Pointer, bool) {
	seq := makeProbeSeq(h1(hash), t.groups.lengthMask)
	for ; ; seq = seq.next() {
		g := t.groups.group(typ, seq.offset)

		match := g.ctrls().matchH2(h2(hash))

		for match != 0 {
			i := match.first()

			slotKey := g.key(typ, i)
			if typ.IndirectKey() {
				slotKey = *((*unsafe.Pointer)(slotKey))
			}
			if typ.Key.Equal(key, slotKey) {
				slotElem := g.elem(typ, i)
				if typ.IndirectElem() {
					slotElem = *((*unsafe.Pointer)(slotElem))
				}
				return slotElem, true
			}
			match = match.removeFirst()
		}

		match = g.ctrls().matchEmpty()
		if match != 0 {
			// Finding an empty slot means we've reached the end of
			// the probe sequence.
			return nil, false
		}
	}
}

// PutSlot returns a pointer to the element slot where an inserted element
// should be written, and ok if it returned a valid slot.
//
// PutSlot returns ok false if the table was split and the Map needs to find
// the new table.
//
// hash must be the hash of key.
func (t *table) PutSlot(typ *abi.SwissMapType, m *Map, hash uintptr, key unsafe.Pointer) (unsafe.Pointer, bool) {
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
			if typ.IndirectKey() {
				slotKey = *((*unsafe.Pointer)(slotKey))
			}
			if typ.Key.Equal(key, slotKey) {
				if typ.NeedKeyUpdate() {
					typedmemmove(typ.Key, slotKey, key)
				}

				slotElem := g.elem(typ, i)
				if typ.IndirectElem() {
					slotElem = *((*unsafe.Pointer)(slotElem))
				}

				t.checkInvariants(typ, m)
				return slotElem, true
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
			if typ.IndirectKey() {
				kmem := newobject(typ.Key)
				*(*unsafe.Pointer)(slotKey) = kmem
				slotKey = kmem
			}
			typedmemmove(typ.Key, slotKey, key)

			slotElem := g.elem(typ, i)
			if typ.IndirectElem() {
				emem := newobject(typ.Elem)
				*(*unsafe.Pointer)(slotElem) = emem
				slotElem = emem
			}

			g.ctrls().set(i, ctrl(h2(hash)))
			t.growthLeft--
			t.used++
			m.used++

			t.checkInvariants(typ, m)
			return slotElem, true
		}

		t.rehash(typ, m)
		return nil, false
	}
}
"""
```
### 功能列举：

1. **定义了 `table` 结构体**:  这个结构体是哈希表的具体实现，包含用于存储键值对、控制信息和管理哈希表状态的字段。
2. **`newTable` 函数**: 用于创建一个新的 `table` 实例，初始化其容量、索引和深度等属性。
3. **`reset` 函数**:  用于重置 `table`，清空所有条目，并根据给定的容量重新初始化内部的组（groups）。
4. **`resetGrowthLeft` 函数**:  用于计算并设置 `growthLeft` 字段，该字段指示在需要扩容之前还能插入多少元素。
5. **`Used` 函数**:  返回当前哈希表中已使用的槽位数量，即元素的数量。
6. **`Get` 函数**:  根据给定的键查找哈希表中的元素。它使用哈希函数来定位可能的槽位，并比较键以找到匹配的条目。
7. **`getWithKey` 函数**:  类似于 `Get`，但除了返回元素之外，还返回键的指针。这在键可以有多种表示形式但比较相等的情况下很有用。
8. **`getWithoutKey` 函数**:  类似于 `Get`，但不返回键的指针，只返回元素和是否存在的布尔值。
9. **`PutSlot` 函数**:  负责向哈希表中插入新的键值对。它首先查找键是否已存在，如果存在则更新其值。如果不存在，则在合适的槽位插入新条目。如果哈希表已满，则会触发扩容（rehash）。

### 推理出的 Go 语言功能实现：

这段代码是 Go 语言 `map` 类型的底层哈希表实现的一部分。Go 的 `map` 是一种内置的关联数据结构，用于存储键值对。

**Go 代码示例：**

```go
package main

import "fmt"

func main() {
	m := make(map[string]int) // 创建一个 string 到 int 的 map

	m["hello"] = 1 // 插入键值对
	m["world"] = 2

	value, ok := m["hello"] // 获取键为 "hello" 的值
	if ok {
		fmt.Println("Value:", value) // 输出: Value: 1
	}

	value, ok = m["nonexistent"] // 获取不存在的键
	if !ok {
		fmt.Println("Key not found") // 输出: Key not found
	}

	delete(m, "hello") // 删除键值对
	fmt.Println("Map after deletion:", m) // 输出: Map after deletion: map[world:2]
}
```

**代码推理 (以 `PutSlot` 为例)：**

假设我们要向一个 `map[string]int` 中插入键值对 `"test": 100`。

**假设输入：**

* `typ`:  指向 `abi.SwissMapType` 的指针，描述了键类型（string）和值类型（int）。
* `m`: 指向 `Map` 结构体的指针，代表整个 map 实例。
* `hash`:  通过对键 `"test"` 和 map 的种子 (seed) 进行哈希运算得到的值。
* `key`: 指向字符串 `"test"` 的 `unsafe.Pointer`。

**处理过程（基于 `PutSlot` 函数）：**

1. **计算探测序列 (`probeSeq`)**:  使用键的哈希值的一部分 (`h1(hash)`) 和表的容量 (`t.groups.lengthMask`) 来生成一个探测序列，用于在哈希表中查找空闲或匹配的槽位。
2. **遍历组 (`groups`)**:  根据探测序列，依次访问哈希表中的槽位组。
3. **匹配哈希值 (`matchH2`)**:  对于每个组，检查控制字节 (`ctrls`) 是否与键哈希值的另一部分 (`h2(hash)`) 匹配。这可以快速排除不匹配的槽位。
4. **比较键 (`typ.Key.Equal`)**: 如果控制字节匹配，则比较槽位中的键与要插入的键是否相等。
   * **如果键已存在**:  并且 `typ.NeedKeyUpdate()` 返回 true (对于某些需要更新键的情况)，则更新槽位中的键。然后返回指向现有元素的指针。
   * **如果键不存在**:  继续查找空闲或已删除的槽位。
5. **处理已删除槽位 (tombstones)**: 如果找到已删除的槽位，则记录下来，以便在没有空闲槽位的情况下可以重用。
6. **找到空闲槽位**:  如果找到空闲槽位，并且 `t.growthLeft > 0`（表示还有空间），则将键值对插入到该槽位，更新控制字节，并减少 `growthLeft` 和增加 `used` 计数。
7. **扩容 (`rehash`)**: 如果没有空闲槽位且 `t.growthLeft` 为 0，则调用 `t.rehash` 函数来扩展哈希表的容量。
8. **返回结果**:  返回指向新插入元素槽位的指针和 `true`，表示插入成功。如果触发了扩容，则返回 `nil` 和 `false`，表示需要在新的哈希表中重新查找位置。

**假设输出（如果插入成功）：**

* 返回值是指向存储值 `100` 的内存地址的 `unsafe.Pointer`。
* 返回值为 `true`。

**假设输出（如果触发了扩容）：**

* 返回值为 `nil`。
* 返回值为 `false`。

### 命令行参数处理：

这段代码是 Go 运行时库的一部分，负责 `map` 的底层实现。它不直接处理命令行参数。命令行参数的处理通常发生在 `main` 函数中，并传递给程序的其他部分。

### 功能归纳 (第1部分)：

这段代码实现了 Go 语言 `map` 类型的核心数据结构 `table` 及其基本操作，包括：

* **创建和初始化哈希表 (`newTable`, `reset`)**:  负责分配内存和设置哈希表的初始状态。
* **查找元素 (`Get`, `getWithKey`, `getWithoutKey`)**:  实现了高效的键查找机制，使用了哈希和探测序列。
* **插入元素 (`PutSlot`)**:  实现了向哈希表中添加新键值对的逻辑，包括处理已存在的键和在需要时触发扩容。
* **管理哈希表状态**:  维护了哈希表的已用容量 (`used`)、总容量 (`capacity`) 和剩余可增长空间 (`growthLeft`) 等信息。

总而言之，这段代码是 Go `map` 实现的基础，提供了键值对存储和检索的核心功能。它使用了 Swiss Table 这种高效的哈希表结构，并包含了扩容的机制来适应动态增长的数据量。

### 提示词
```
这是路径为go/src/internal/runtime/maps/table.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```go
// Copyright 2024 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package maps implements Go's builtin map type.
package maps

import (
	"internal/abi"
	"internal/goarch"
	"unsafe"
)

// Maximum size of a table before it is split at the directory level.
//
// TODO: Completely made up value. This should be tuned for performance vs grow
// latency.
// TODO: This should likely be based on byte size, as copying costs will
// dominate grow latency for large objects.
const maxTableCapacity = 1024

// Ensure the max capacity fits in uint16, used for capacity and growthLeft
// below.
var _ = uint16(maxTableCapacity)

// table is a Swiss table hash table structure.
//
// Each table is a complete hash table implementation.
//
// Map uses one or more tables to store entries. Extendible hashing (hash
// prefix) is used to select the table to use for a specific key. Using
// multiple tables enables incremental growth by growing only one table at a
// time.
type table struct {
	// The number of filled slots (i.e. the number of elements in the table).
	used uint16

	// The total number of slots (always 2^N). Equal to
	// `(groups.lengthMask+1)*abi.SwissMapGroupSlots`.
	capacity uint16

	// The number of slots we can still fill without needing to rehash.
	//
	// We rehash when used + tombstones > loadFactor*capacity, including
	// tombstones so the table doesn't overfill with tombstones. This field
	// counts down remaining empty slots before the next rehash.
	growthLeft uint16

	// The number of bits used by directory lookups above this table. Note
	// that this may be less then globalDepth, if the directory has grown
	// but this table has not yet been split.
	localDepth uint8

	// Index of this table in the Map directory. This is the index of the
	// _first_ location in the directory. The table may occur in multiple
	// sequential indicies.
	//
	// index is -1 if the table is stale (no longer installed in the
	// directory).
	index int

	// groups is an array of slot groups. Each group holds abi.SwissMapGroupSlots
	// key/elem slots and their control bytes. A table has a fixed size
	// groups array. The table is replaced (in rehash) when more space is
	// required.
	//
	// TODO(prattmic): keys and elements are interleaved to maximize
	// locality, but it comes at the expense of wasted space for some types
	// (consider uint8 key, uint64 element). Consider placing all keys
	// together in these cases to save space.
	groups groupsReference
}

func newTable(typ *abi.SwissMapType, capacity uint64, index int, localDepth uint8) *table {
	if capacity < abi.SwissMapGroupSlots {
		capacity = abi.SwissMapGroupSlots
	}

	t := &table{
		index:      index,
		localDepth: localDepth,
	}

	if capacity > maxTableCapacity {
		panic("initial table capacity too large")
	}

	// N.B. group count must be a power of two for probeSeq to visit every
	// group.
	capacity, overflow := alignUpPow2(capacity)
	if overflow {
		panic("rounded-up capacity overflows uint64")
	}

	t.reset(typ, uint16(capacity))

	return t
}

// reset resets the table with new, empty groups with the specified new total
// capacity.
func (t *table) reset(typ *abi.SwissMapType, capacity uint16) {
	groupCount := uint64(capacity) / abi.SwissMapGroupSlots
	t.groups = newGroups(typ, groupCount)
	t.capacity = capacity
	t.resetGrowthLeft()

	for i := uint64(0); i <= t.groups.lengthMask; i++ {
		g := t.groups.group(typ, i)
		g.ctrls().setEmpty()
	}
}

// Preconditions: table must be empty.
func (t *table) resetGrowthLeft() {
	var growthLeft uint16
	if t.capacity == 0 {
		// No real reason to support zero capacity table, since an
		// empty Map simply won't have a table.
		panic("table must have positive capacity")
	} else if t.capacity <= abi.SwissMapGroupSlots {
		// If the map fits in a single group then we're able to fill all of
		// the slots except 1 (an empty slot is needed to terminate find
		// operations).
		//
		// TODO(go.dev/issue/54766): With a special case in probing for
		// single-group tables, we could fill all slots.
		growthLeft = t.capacity - 1
	} else {
		if t.capacity*maxAvgGroupLoad < t.capacity {
			// TODO(prattmic): Do something cleaner.
			panic("overflow")
		}
		growthLeft = (t.capacity * maxAvgGroupLoad) / abi.SwissMapGroupSlots
	}
	t.growthLeft = growthLeft
}

func (t *table) Used() uint64 {
	return uint64(t.used)
}

// Get performs a lookup of the key that key points to. It returns a pointer to
// the element, or false if the key doesn't exist.
func (t *table) Get(typ *abi.SwissMapType, m *Map, key unsafe.Pointer) (unsafe.Pointer, bool) {
	// TODO(prattmic): We could avoid hashing in a variety of special
	// cases.
	//
	// - One entry maps could just directly compare the single entry
	//   without hashing.
	// - String keys could do quick checks of a few bytes before hashing.
	hash := typ.Hasher(key, m.seed)
	_, elem, ok := t.getWithKey(typ, hash, key)
	return elem, ok
}

// getWithKey performs a lookup of key, returning a pointer to the version of
// the key in the map in addition to the element.
//
// This is relevant when multiple different key values compare equal (e.g.,
// +0.0 and -0.0). When a grow occurs during iteration, iteration perform a
// lookup of keys from the old group in the new group in order to correctly
// expose updated elements. For NeedsKeyUpdate keys, iteration also must return
// the new key value, not the old key value.
// hash must be the hash of the key.
func (t *table) getWithKey(typ *abi.SwissMapType, hash uintptr, key unsafe.Pointer) (unsafe.Pointer, unsafe.Pointer, bool) {
	// To find the location of a key in the table, we compute hash(key). From
	// h1(hash(key)) and the capacity, we construct a probeSeq that visits
	// every group of slots in some interesting order. See [probeSeq].
	//
	// We walk through these indices. At each index, we select the entire
	// group starting with that index and extract potential candidates:
	// occupied slots with a control byte equal to h2(hash(key)). The key
	// at candidate slot i is compared with key; if key == g.slot(i).key
	// we are done and return the slot; if there is an empty slot in the
	// group, we stop and return an error; otherwise we continue to the
	// next probe index. Tombstones (ctrlDeleted) effectively behave like
	// full slots that never match the value we're looking for.
	//
	// The h2 bits ensure when we compare a key we are likely to have
	// actually found the object. That is, the chance is low that keys
	// compare false. Thus, when we search for an object, we are unlikely
	// to call Equal many times. This likelihood can be analyzed as follows
	// (assuming that h2 is a random enough hash function).
	//
	// Let's assume that there are k "wrong" objects that must be examined
	// in a probe sequence. For example, when doing a find on an object
	// that is in the table, k is the number of objects between the start
	// of the probe sequence and the final found object (not including the
	// final found object). The expected number of objects with an h2 match
	// is then k/128. Measurements and analysis indicate that even at high
	// load factors, k is less than 32, meaning that the number of false
	// positive comparisons we must perform is less than 1/8 per find.
	seq := makeProbeSeq(h1(hash), t.groups.lengthMask)
	for ; ; seq = seq.next() {
		g := t.groups.group(typ, seq.offset)

		match := g.ctrls().matchH2(h2(hash))

		for match != 0 {
			i := match.first()

			slotKey := g.key(typ, i)
			if typ.IndirectKey() {
				slotKey = *((*unsafe.Pointer)(slotKey))
			}
			if typ.Key.Equal(key, slotKey) {
				slotElem := g.elem(typ, i)
				if typ.IndirectElem() {
					slotElem = *((*unsafe.Pointer)(slotElem))
				}
				return slotKey, slotElem, true
			}
			match = match.removeFirst()
		}

		match = g.ctrls().matchEmpty()
		if match != 0 {
			// Finding an empty slot means we've reached the end of
			// the probe sequence.
			return nil, nil, false
		}
	}
}

func (t *table) getWithoutKey(typ *abi.SwissMapType, hash uintptr, key unsafe.Pointer) (unsafe.Pointer, bool) {
	seq := makeProbeSeq(h1(hash), t.groups.lengthMask)
	for ; ; seq = seq.next() {
		g := t.groups.group(typ, seq.offset)

		match := g.ctrls().matchH2(h2(hash))

		for match != 0 {
			i := match.first()

			slotKey := g.key(typ, i)
			if typ.IndirectKey() {
				slotKey = *((*unsafe.Pointer)(slotKey))
			}
			if typ.Key.Equal(key, slotKey) {
				slotElem := g.elem(typ, i)
				if typ.IndirectElem() {
					slotElem = *((*unsafe.Pointer)(slotElem))
				}
				return slotElem, true
			}
			match = match.removeFirst()
		}

		match = g.ctrls().matchEmpty()
		if match != 0 {
			// Finding an empty slot means we've reached the end of
			// the probe sequence.
			return nil, false
		}
	}
}

// PutSlot returns a pointer to the element slot where an inserted element
// should be written, and ok if it returned a valid slot.
//
// PutSlot returns ok false if the table was split and the Map needs to find
// the new table.
//
// hash must be the hash of key.
func (t *table) PutSlot(typ *abi.SwissMapType, m *Map, hash uintptr, key unsafe.Pointer) (unsafe.Pointer, bool) {
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
			if typ.IndirectKey() {
				slotKey = *((*unsafe.Pointer)(slotKey))
			}
			if typ.Key.Equal(key, slotKey) {
				if typ.NeedKeyUpdate() {
					typedmemmove(typ.Key, slotKey, key)
				}

				slotElem := g.elem(typ, i)
				if typ.IndirectElem() {
					slotElem = *((*unsafe.Pointer)(slotElem))
				}

				t.checkInvariants(typ, m)
				return slotElem, true
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
			if typ.IndirectKey() {
				kmem := newobject(typ.Key)
				*(*unsafe.Pointer)(slotKey) = kmem
				slotKey = kmem
			}
			typedmemmove(typ.Key, slotKey, key)

			slotElem := g.elem(typ, i)
			if typ.IndirectElem() {
				emem := newobject(typ.Elem)
				*(*unsafe.Pointer)(slotElem) = emem
				slotElem = emem
			}

			g.ctrls().set(i, ctrl(h2(hash)))
			t.growthLeft--
			t.used++
			m.used++

			t.checkInvariants(typ, m)
			return slotElem, true
		}

		t.rehash(typ, m)
		return nil, false
	}
}

// uncheckedPutSlot inserts an entry known not to be in the table.
// This is used for grow/split where we are making a new table from
// entries in an existing table.
//
// Decrements growthLeft and increments used.
//
// Requires that the entry does not exist in the table, and that the table has
// room for another element without rehashing.
//
// Requires that there are no deleted entries in the table.
//
// For indirect keys and/or elements, the key and elem pointers can be
// put directly into the map, they do not need to be copied. This
// requires the caller to ensure that the referenced memory never
// changes (by sourcing those pointers from another indirect key/elem
// map).
func (t *table) uncheckedPutSlot(typ *abi.SwissMapType, hash uintptr, key, elem unsafe.Pointer) {
	if t.growthLeft == 0 {
		panic("invariant failed: growthLeft is unexpectedly 0")
	}

	// Given key and its hash hash(key), to insert it, we construct a
	// probeSeq, and use it to find the first group with an unoccupied (empty
	// or deleted) slot. We place the key/value into the first such slot in
	// the group and mark it as full with key's H2.
	seq := makeProbeSeq(h1(hash), t.groups.lengthMask)
	for ; ; seq = seq.next() {
		g := t.groups.group(typ, seq.offset)

		match := g.ctrls().matchEmptyOrDeleted()
		if match != 0 {
			i := match.first()

			slotKey := g.key(typ, i)
			if typ.IndirectKey() {
				*(*unsafe.Pointer)(slotKey) = key
			} else {
				typedmemmove(typ.Key, slotKey, key)
			}

			slotElem := g.elem(typ, i)
			if typ.IndirectElem() {
				*(*unsafe.Pointer)(slotElem) = elem
			} else {
				typedmemmove(typ.Elem, slotElem, elem)
			}

			t.growthLeft--
			t.used++
			g.ctrls().set(i, ctrl(h2(hash)))
			return
		}
	}
}

func (t *table) Delete(typ *abi.SwissMapType, m *Map, hash uintptr, key unsafe.Pointer) {
	seq := makeProbeSeq(h1(hash), t.groups.lengthMask)
	for ; ; seq = seq.next() {
		g := t.groups.group(typ, seq.offset)
		match := g.ctrls().matchH2(h2(hash))

		for match != 0 {
			i := match.first()

			slotKey := g.key(typ, i)
			origSlotKey := slotKey
			if typ.IndirectKey() {
				slotKey = *((*unsafe.Pointer)(slotKey))
			}

			if typ.Key.Equal(key, slotKey) {
				t.used--
				m.used--

				if typ.IndirectKey() {
					// Clearing the pointer is sufficient.
					*(*unsafe.Pointer)(origSlotKey) = nil
				} else if typ.Key.Pointers() {
					// Only bothing clear the key if there
					// are pointers in it.
					typedmemclr(typ.Key, slotKey)
				}

				slotElem := g.elem(typ, i)
				if typ.IndirectElem() {
					// Clearing the pointer is sufficient.
					*(*unsafe.Pointer)(slotElem) = nil
				} else {
					// Unlike keys, always clear the elem (even if
					// it contains no pointers), as compound
					// assignment operations depend on cleared
					// deleted values. See
					// https://go.dev/issue/25936.
					typedmemclr(typ.Elem, slotElem)
				}

				// Only a full group can appear in the middle
				// of a probe sequence (a group with at least
				// one empty slot terminates probing). Once a
				// group becomes full, it stays full until
				// rehashing/resizing. So if the group isn't
				// full now, we can simply remove the element.
				// Otherwise, we create a tombstone to mark the
				// slot as deleted.
				if g.ctrls().matchEmpty() != 0 {
					g.ctrls().set(i, ctrlEmpty)
					t.growthLeft++
				} else {
					g.ctrls().set(i, ctrlDeleted)
				}

				t.checkInvariants(typ, m)
				return
			}
			match = match.removeFirst()
		}

		match = g.ctrls().matchEmpty()
		if match != 0 {
			// Finding an empty slot means we've reached the end of
			// the probe sequence.
			return
		}
	}
}

// tombstones returns the number of deleted (tombstone) entries in the table. A
// tombstone is a slot that has been deleted but is still considered occupied
// so as not to violate the probing invariant.
func (t *table) tombstones() uint16 {
	return (t.capacity*maxAvgGroupLoad)/abi.SwissMapGroupSlots - t.used - t.growthLeft
}

// Clear deletes all entries from the map resulting in an empty map.
func (t *table) Clear(typ *abi.SwissMapType) {
	for i := uint64(0); i <= t.groups.lengthMask; i++ {
		g := t.groups.group(typ, i)
		typedmemclr(typ.Group, g.data)
		g.ctrls().setEmpty()
	}

	t.used = 0
	t.resetGrowthLeft()
}

type Iter struct {
	key  unsafe.Pointer // Must be in first position.  Write nil to indicate iteration end (see cmd/compile/internal/walk/range.go).
	elem unsafe.Pointer // Must be in second position (see cmd/compile/internal/walk/range.go).
	typ  *abi.SwissMapType
	m    *Map

	// Randomize iteration order by starting iteration at a random slot
	// offset. The offset into the directory uses a separate offset, as it
	// must adjust when the directory grows.
	entryOffset uint64
	dirOffset   uint64

	// Snapshot of Map.clearSeq at iteration initialization time. Used to
	// detect clear during iteration.
	clearSeq uint64

	// Value of Map.globalDepth during the last call to Next. Used to
	// detect directory grow during iteration.
	globalDepth uint8

	// dirIdx is the current directory index, prior to adjustment by
	// dirOffset.
	dirIdx int

	// tab is the table at dirIdx during the previous call to Next.
	tab *table

	// group is the group at entryIdx during the previous call to Next.
	group groupReference

	// entryIdx is the current entry index, prior to adjustment by entryOffset.
	// The lower 3 bits of the index are the slot index, and the upper bits
	// are the group index.
	entryIdx uint64
}

// Init initializes Iter for iteration.
func (it *Iter) Init(typ *abi.SwissMapType, m *Map) {
	it.typ = typ

	if m == nil || m.used == 0 {
		return
	}

	dirIdx := 0
	var groupSmall groupReference
	if m.dirLen <= 0 {
		// Use dirIdx == -1 as sentinel for small maps.
		dirIdx = -1
		groupSmall.data = m.dirPtr
	}

	it.m = m
	it.entryOffset = rand()
	it.dirOffset = rand()
	it.globalDepth = m.globalDepth
	it.dirIdx = dirIdx
	it.group = groupSmall
	it.clearSeq = m.clearSeq
}

func (it *Iter) Initialized() bool {
	return it.typ != nil
}

// Map returns the map this iterator is iterating over.
func (it *Iter) Map() *Map {
	return it.m
}

// Key returns a pointer to the current key. nil indicates end of iteration.
//
// Must not be called prior to Next.
func (it *Iter) Key() unsafe.Pointer {
	return it.key
}

// Key returns a pointer to the current element. nil indicates end of
// iteration.
//
// Must not be called prior to Next.
func (it *Iter) Elem() unsafe.Pointer {
	return it.elem
}

func (it *Iter) nextDirIdx() {
	// Skip other entries in the directory that refer to the same
	// logical table. There are two cases of this:
	//
	// Consider this directory:
	//
	// - 0: *t1
	// - 1: *t1
	// - 2: *t2a
	// - 3: *t2b
	//
	// At some point, the directory grew to accommodate a split of
	// t2. t1 did not split, so entries 0 and 1 both point to t1.
	// t2 did split, so the two halves were installed in entries 2
	// and 3.
	//
	// If dirIdx is 0 and it.tab is t1, then we should skip past
	// entry 1 to avoid repeating t1.
	//
	// If dirIdx is 2 and it.tab is t2 (pre-split), then we should
	// skip past entry 3 because our pre-split t2 already covers
	// all keys from t2a and t2b (except for new insertions, which
	// iteration need not return).
	//
	// We can achieve both of these by using to difference between
	// the directory and table depth to compute how many entries
	// the table covers.
	entries := 1 << (it.m.globalDepth - it.tab.localDepth)
	it.dirIdx += entries
	it.tab = nil
	it.group = groupReference{}
	it.entryIdx = 0
}

// Return the appropriate key/elem for key at slotIdx index within it.group, if
// any.
func (it *Iter) grownKeyElem(key unsafe.Pointer, slotIdx uintptr) (unsafe.Pointer, unsafe.Pointer, bool) {
	newKey, newElem, ok := it.m.getWithKey(it.typ, key)
	if !ok {
		// Key has likely been deleted, and
		// should be skipped.
		//
		// One exception is keys that don't
		// compare equal to themselves (e.g.,
		// NaN). These keys cannot be looked
		// up, so getWithKey will fail even if
		// the key exists.
		//
		// However, we are in luck because such
		// keys cannot be updated and they
		// cannot be deleted except with clear.
		// Thus if no clear has occurred, the
		// key/elem must still exist exactly as
		// in the old groups, so we can return
		// them from there.
		//
		// TODO(prattmic): Consider checking
		// clearSeq early. If a clear occurred,
		// Next could always return
		// immediately, as iteration doesn't
		// need to return anything added after
		// clear.
		if it.clearSeq == it.m.clearSeq && !it.typ.Key.Equal(key, key) {
			elem := it.group.elem(it.typ, slotIdx)
			if it.typ.IndirectElem() {
				elem = *((*unsafe.Pointer)(elem))
			}
			return key, elem, true
		}

		// This entry doesn't exist anymore.
		return nil, nil, false
	}

	return newKey, newElem, true
}

// Next proceeds to the next element in iteration, which can be accessed via
// the Key and Elem methods.
//
// The table can be mutated during iteration, though there is no guarantee that
// the mutations will be visible to the iteration.
//
// Init must be called prior to Next.
func (it *Iter) Next() {
	if it.m == nil {
		// Map was empty at Iter.Init.
		it.key = nil
		it.elem = nil
		return
	}

	if it.m.writing != 0 {
		fatal("concurrent map iteration and map write")
		return
	}

	if it.dirIdx < 0 {
		// Map was small at Init.
		for ; it.entryIdx < abi.SwissMapGroupSlots; it.entryIdx++ {
			k := uintptr(it.entryIdx+it.entryOffset) % abi.SwissMapGroupSlots

			if (it.group.ctrls().get(k) & ctrlEmpty) == ctrlEmpty {
				// Empty or deleted.
				continue
			}

			key := it.group.key(it.typ, k)
			if it.typ.IndirectKey() {
				key = *((*unsafe.Pointer)(key))
			}

			// As below, if we have grown to a full map since Init,
			// we continue to use the old group to decide the keys
			// to return, but must look them up again in the new
			// tables.
			grown := it.m.dirLen > 0
			var elem unsafe.Pointer
			if grown {
				var ok bool
				newKey, newElem, ok := it.m.getWithKey(it.typ, key)
				if !ok {
					// See comment below.
					if it.clearSeq == it.m.clearSeq && !it.typ.Key.Equal(key, key) {
						elem = it.group.elem(it.typ, k)
						if it.typ.IndirectElem() {
							elem = *((*unsafe.Pointer)(elem))
						}
					} else {
						continue
					}
				} else {
					key = newKey
					elem = newElem
				}
			} else {
				elem = it.group.elem(it.typ, k)
				if it.typ.IndirectElem() {
					elem = *((*unsafe.Pointer)(elem))
				}
			}

			it.entryIdx++
			it.key = key
			it.elem = elem
			return
		}
		it.key = nil
		it.elem = nil
		return
	}

	if it.globalDepth != it.m.globalDepth {
		// Directory has grown since the last call to Next. Adjust our
		// directory index.
		//
		// Consider:
		//
		// Before:
		// - 0: *t1
		// - 1: *t2  <- dirIdx
		//
		// After:
		// - 0: *t1a (split)
		// - 1: *t1b (split)
		// - 2: *t2  <- dirIdx
		// - 3: *t2
		//
		// That is, we want to double the current index when the
		// directory size doubles (or quadruple when the directory size
		// quadruples, etc).
		//
		// The actual (randomized) dirIdx is computed below as:
		//
		// dirIdx := (it.dirIdx + it.dirOffset) % it.m.dirLen
		//
		// Multiplication is associative across modulo operations,
		// A * (B % C) = (A * B) % (A * C),
		// provided that A is positive.
		//
		// Thus we can achieve this by adjusting it.dirIdx,
		// it.dirOffset, and it.m.dirLen individually.
		orders := it.m.globalDepth - it.globalDepth
		it.dirIdx <<= orders
		it.dirOffset <<= orders
		// it.m.dirLen was already adjusted when the directory grew.

		it.globalDepth = it.m.globalDepth
	}

	// Continue iteration until we find a full slot.
	for ; it.dirIdx < it.m.dirLen; it.nextDirIdx() {
		// Resolve the table.
		if it.tab == nil {
			dirIdx := int((uint64(it.dirIdx) + it.dirOffset) & uint64(it.m.dirLen-1))
			newTab := it.m.directoryAt(uintptr(dirIdx))
			if newTab.index != dirIdx {
				// Normally we skip past all duplicates of the
				// same entry in the table (see updates to
				// it.dirIdx at the end of the loop below), so
				// this case wouldn't occur.
				//
				// But on the very first call, we have a
				// completely randomized dirIdx that may refer
				// to a middle of a run of tables in the
				// directory. Do a one-time adjustment of the
				// offset to ensure we start at first index for
				// newTable.
				diff := dirIdx - newTab.index
				it.dirOffset -= uint64(diff)
				dirIdx = newTab.index
			}
			it.tab = newTab
		}

		// N.B. Use it.tab, not newTab. It is important to use the old
		// table for key selection if the table has grown. See comment
		// on grown below.

		entryMask := uint64(it.tab.capacity) - 1
		if it.entryIdx > entryMask {
			// Continue to next table.
			continue
		}

		// Fast path: skip matching and directly check if entryIdx is a
		// full slot.
		//
		// In the slow path below, we perform an 8-slot match check to
		// look for full slots within the group.
		//
		// However, with a max load factor of 7/8, each slot in a
		// mostly full map has a high probability of being full. Thus
		// it is cheaper to check a single slot than do a full control
		// match.

		entryIdx := (it.entryIdx + it.entryOffset) & entryMask
		slotIdx := uintptr(entryIdx & (abi.SwissMapGroupSlots - 1))
		if slotIdx == 0 || it.group.data == nil {
			// Only compute the group (a) when we switch
			// groups (slotIdx rolls over) and (b) on the
			// first iteration in this table (slotIdx may
			// not be zero due to entryOffset).
			groupIdx := entryIdx >> abi.SwissMapGroupSlotsBits
			it.group = it.tab.groups.group(it.typ, groupIdx)
		}

		if (it.group.ctrls().get(slotIdx) & ctrlEmpty) == 0 {
			// Slot full.

			key := it.group.key(it.typ, slotIdx)
			if it.typ.IndirectKey() {
				key = *((*unsafe.Pointer)(key))
			}

			grown := it.tab.index == -1
			var elem unsafe.Pointer
			if grown {
				newKey, newElem, ok := it.grownKeyElem(key, slotIdx)
				if !ok {
					// This entry doesn't exist
					// anymore. Continue to the
					// next one.
					goto next
				} else {
					key = newKey
					elem = newElem
				}
			} else {
				elem = it.group.elem(it.typ, slotIdx)
				if it.typ.IndirectElem() {
					elem = *((*unsafe.Pointer)(elem))
				}
			}

			it.entryIdx++
			it.key = key
			it.elem = elem
			return
		}

	next:
		it.entryIdx++

		// Slow path: use a match on the control word to jump ahead to
		// the next full slot.
		//
		// This is highly effective for maps with particularly low load
		// (e.g., map allocated with large hint but few insertions).
		//
		// For maps with medium load (e.g., 3-4 empty slots per group)
		// it also tends to work pretty well. Since slots within a
		// group are filled in order, then if there have been no
		// deletions, a match will allow skipping past all empty slots
		// at once.
		//
		// Note: it is tempting to cache the group match result in the
		// iterator to use across Next calls. However because entries
		// may be deleted between calls later calls would still need to
		// double-check the control value.

		var groupMatch bitset
		for it.entryIdx <= entryMask {
			entryIdx := (it.entryIdx + it.entryOffset) & entryMask
			slotIdx := uintptr(entryIdx & (abi.SwissMapGroupSlots - 1))

			if slotIdx == 0 || it.group.data == nil {
				// Only compute the group (a) when we switch
				// groups (slotIdx rolls over) and (b) on the
				// first iteration in this table (slotIdx may
				// not be zero due to entryOffset).
				groupIdx := entryIdx >> abi.SwissMapGroupSlotsBits
				it.group = it.tab.groups.group(it.typ, groupIdx)
			}

			if groupMatch == 0 {
				groupMatch = it.group.ctrls().matchFull()

				if slotIdx != 0 {
					// Starting in the middle of the group.
					// Ignore earlier groups.
					groupMatch = groupMatch.removeBelow(slotIdx)
				}

				// Skip over groups that are composed of only empty or
				// deleted slots.
				if groupMatch == 0 {
					// Jump past remaining slots in this
					// group.
					it.entryIdx += abi.SwissMapGroupSlots - uint64(slotIdx)
					continue
				}

				i := groupMatch.first()
				it.entryIdx += uint64(i - slotIdx)
				if it.entryIdx > entryMask {
					// Past the end of this table's iteration.
					continue
				}
				entryIdx += uint64(i - slotIdx)
				slotIdx = i
			}

			key := it.group.key(it.typ, slotIdx)
			if it.typ.IndirectKey() {
				key = *((*unsafe.Pointer)(key))
			}

			// If the table has changed since the last
			// call, then it has grown or split. In this
			// case, further mutations (changes to
			// key->elem or deletions) will not be visible
			// in our snapshot table. Instead we must
			// consult the new table by doing a full
			// lookup.
			//
			// We still use our old table to decide which
			// keys to lookup in order to avoid returning
			// the same key twice.
			grown := it.tab.index == -1
			var elem unsafe.Pointer
			if grown {
				newKey, newElem, ok := it.grownKeyElem(key, slotIdx)
				if !ok {
					// This entry doesn't exist anymore.
					// Continue to the next one.
					groupMatch = groupMatch.removeFirst()
					if groupMatch == 0 {
						// No more entries in this
						// group. Continue to next
						// group.
						it.entryIdx += abi.SwissMapGroupSlots - uint64(slotIdx)
						continue
					}

					// Next full slot.
					i := groupMatch.first()
					it.entryIdx += uint64(i - slotIdx)
					continue
				} else {
					key = newKey
					elem = newElem
				}
			} else {
				elem = it.group.elem(it.typ, slotIdx)
				if it.typ.IndirectElem() {
					elem = *((*unsafe.Pointer)(elem))
				}
			}

			// Jump ahead to the next full slot or next group.
			groupMatch = groupMatch.removeFirst()
			if groupMatch == 0 {
				// No more entries in
				// this group. Continue
				// to next group.
				it.entryIdx += abi.SwissMapGroupSlots - uint64(slotIdx)
			} else {
				// Next full slot.
				i := groupMatch.first()
				it.entryIdx += uint64(i - slotIdx)
			}

			it.key = key
			it.elem = elem
			return
		}

		// Continue to next table.
	}

	it.key = nil
	it.elem = nil
	return
}

// Replaces the table with one larger table or two split tables to fit more
// entries. Since the table is replaced, t is now stale and should not be
// modified.
func (t *table) rehash(typ *abi.SwissMapType, m *Map) {
	// TODO(prattmic): SwissTables typically perform a "rehash in place"
	// operation which recovers capacity consumed by tombstones without growing
	// the table by reordering slots as necessary to maintain the probe
	// invariant while eliminating all tombstones.
	//
	// However, it is unclear how to make rehash in place work with
	// iteration. Since iteration simply walks through all slots in order
	// (with random start offset), reordering the slots would break
	// iteration.
	//
	// As an alternative, we could do a "resize" to new groups allocation
	// of the same size. This would eliminate the tombstones, but using a
	// new allocation, so the existing grow support in iteration would
	// continue to work.

	newCapacity := 2 * t.capacity
	if newCapacity <= maxTableCapacity {
		t.grow(typ, m, newCapacity)
		return
	}

	t.split(typ, m)
}

// Bitmask for the last selection bit at this depth.
func localDepthMask(localDepth uint8) uintptr {
	if goarch.PtrSize == 4 {
		return uintptr(1) << (32 - localDepth)
	}
	return uintptr(1) << (64 - localDepth)
}

// split the table into two, installing the new tables in the map directory.
func (t *table) split(typ *abi.SwissMapType, m *Map) {
	localDepth := t.localDepth
	localDepth++

	// TODO: is this the best capacity?
	left := newTable(typ, maxTableCapacity, -1, localDepth)
	right := newTable(typ, maxTableCapacity, -1, localDepth)

	// Split in half at the localDepth bit from the top.
	mask := localDepthMask(localDepth)

	for i := uint64(0); i <= t.groups.lengthMask; i++ {
		g := t.groups.group(typ, i)
		for j := uintptr(0); j < abi.SwissMapGroupSlots; j++ {
			if (g.ctrls().get(j) & ctrlEmpty) == ctrlEmpty {
				// Empty or deleted
				continue
			}

			key := g.key(typ, j)
			if typ.IndirectKey() {
				key = *((*unsafe.Pointer)(key))
			}

			elem := g.elem(typ, j)
			if typ.IndirectElem() {
				elem = *((*unsafe.Pointer)(elem))
			}

			hash := typ.Hasher(key, m.seed)
			var newTable *table
			if hash&mask == 0 {
				newTable = left
			} else {
				newTable = right
			}
			newTable.uncheckedPutSlot(typ, hash, key, elem)
		}
	}

	m.installTableSplit(t, left, right)
	t.index = -1
}

// grow the capacity of the table by allocating a new table with a bigger array
// and uncheckedPutting each element of the table into the new table (we know
// that no insertion here will Put an already-present value), and discard the
// old table.
func (t *table) grow(typ *abi.SwissMapType, m *Map, newCapacity uint16) {
	newTable := newTable(typ, uint64(newCapacity), t.index, t.localDepth)

	if t.capacity > 0 {
		for i := uint64(0); i <= t.groups.lengthMask; i++ {
			g := t.groups.group(typ, i)
			for j := uintptr(0); j < abi.SwissMapGroupSlots; j++ {
				if (g.ctrls().get(j) & ctrlEmpty) == ctrlEmpty {
					// Empty or deleted
					continue
				}

				key := g.key(typ, j)
				if typ.IndirectKey() {
					key = *((*unsafe.Pointer)(key))
				}

				elem := g.e
```