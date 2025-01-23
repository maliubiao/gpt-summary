Response:
Let's break down the thought process for analyzing this Go `map.go` code snippet.

**1. Initial Skim and Keyword Identification:**

The first step is a quick read-through to get a general sense of the code. I'm looking for recurring keywords and patterns. Terms like "Swiss Table," "hash," "group," "slot," "table," "directory," "probe," "growth," "deletion," and "iteration" immediately jump out. These are strong indicators of the core functionality.

**2. Understanding the High-Level Structure:**

The initial comments in the `Package maps` section provide a valuable overview of the design, comparing it to Abseil's "Swiss Table." This gives me a crucial piece of context. The comments also outline the core terminology, which is essential for understanding the subsequent code. I note the hierarchical structure: Slots within Groups, Groups within Tables, and Tables within the Map's Directory.

**3. Function-by-Function Analysis (with an emphasis on public methods and key internal functions):**

I start analyzing the functions, focusing on what they *do* rather than getting bogged down in implementation details initially.

*   **`h1(h uintptr)` and `h2(h uintptr)`:** These clearly extract parts of a hash. The comments explain the significance of H1 (upper bits) and H2 (lower bits).
*   **`NewMap(mt *abi.SwissMapType, hint uintptr, m *Map, maxAlloc uintptr)`:** This is a constructor. The parameters (`hint`, `maxAlloc`) suggest it handles initialization with a suggested size and considers memory limits. The "small map optimization" is a key detail.
*   **`NewEmptyMap()`:**  A simple constructor for an empty map.
*   **`directoryIndex(hash uintptr)`:** This function is clearly responsible for selecting the appropriate table based on the hash. The logic for small maps (returning 0) is important.
*   **`directoryAt(i uintptr)` and `directorySet(i uintptr, nt *table)`:** These functions manipulate the directory, accessing and modifying table pointers.
*   **`replaceTable(nt *table)`:**  This function seems related to updating the directory when a table changes (likely during growth).
*   **`installTableSplit(old, left, right *table)`:** This looks like the core logic for handling table splitting and directory growth.
*   **`Used() uint64`:** A simple accessor for the number of elements.
*   **`Get(typ *abi.SwissMapType, key unsafe.Pointer)` and `getWithKey(...)`, `getWithoutKey(...)`, `getWithKeySmall(...)`:** These are the lookup functions. The `Small` variant is for the optimized case. The presence of both `WithKey` and `WithoutKey` hints at potential internal differences or optimizations.
*   **`Put(typ *abi.SwissMapType, key, elem unsafe.Pointer)` and `PutSlot(...)`, `putSlotSmall(...)`:**  These are the insertion functions. `PutSlot` likely manages finding the right place, while `Put` handles the actual data copying.
*   **`growToSmall(typ *abi.SwissMapType)` and `growToTable(typ *abi.SwissMapType)`:**  These are the growth mechanisms, transitioning from the small map optimization to a full table and growing the table itself.
*   **`Delete(typ *abi.SwissMapType, key unsafe.Pointer)` and `deleteSmall(...)`:** The deletion functions, with a small map optimization.
*   **`Clear(typ *abi.SwissMapType)` and `clearSmall(...)`:**  Functions for removing all elements.

**4. Identifying the Core Go Feature:**

Based on the function names (`Get`, `Put`, `Delete`, `Clear`), the `Used()` method (analogous to `len()`), and the overall structure involving keys and elements, it's highly probable that this code implements Go's built-in `map` type.

**5. Code Example Construction:**

To demonstrate the functionality, a simple `map` usage example is sufficient. I focus on the basic operations: creating, inserting, retrieving, deleting, and checking the length.

**6. Reasoning and Input/Output (for more complex functions):**

For functions like `installTableSplit`, understanding the exact input and output requires a deeper dive. The comments provide hints (old, left, right tables). I infer that `old` is the table being split, and `left` and `right` are the new tables. The output is the modification of the map's directory. While a full trace of the directory manipulation is complex, I can conceptually describe how the directory grows and how table pointers are updated. I might consider drawing a simple diagram in my internal "scratchpad" to visualize the directory structure before and after the split.

**7. Command-Line Arguments:**

A quick scan reveals no direct interaction with command-line arguments within this code snippet. This is expected for the core implementation of a built-in type.

**8. Common Pitfalls:**

The comments about concurrent read/write panics are a clear indicator of a common error. I highlight this with a simple example showing the error. The "iteration invalidation" aspect mentioned in the comments is another potential pitfall, which I try to explain conceptually.

**9. Language and Formatting:**

Throughout the process, I'm mindful of the request for a Chinese answer. I ensure the terminology and explanations are clear and accurate in Chinese. I also strive for a structured and well-formatted response, using headings and bullet points for readability.

**Self-Correction/Refinement During the Process:**

*   Initially, I might just list the function names. Then, I go back and add a brief description of each function's purpose.
*   I might initially focus too much on the low-level details of the "Swiss Table."  I realize it's more important to explain the overall *functionality* and how it relates to Go maps. The "Swiss Table" details are supporting information.
*   I might forget to include an example. I then add a simple, illustrative Go code snippet.
*   I might miss the "small map optimization" initially. A closer reading of the `NewMap` function reveals this important detail.

By following these steps, combining code analysis with understanding the underlying concepts, and focusing on the user's request, I can generate a comprehensive and informative answer.
这段代码是 Go 语言运行时环境（runtime）中 `maps` 包的一部分，它实现了 Go 语言内置的 `map` 类型。下面详细列举其功能，并进行推理和举例说明。

**功能列举:**

1. **哈希表的实现:** 实现了基于 "Swiss Table" 设计的哈希表，用于存储键值对。
2. **键值对存储:** 提供了存储和检索键值对的功能。
3. **动态扩容:**  实现了 map 的动态扩容机制，当元素数量超过一定阈值时，可以自动增加底层存储空间。
4. **键值对删除:** 允许从 map 中删除指定的键值对。
5. **迭代支持:**  支持对 map 进行迭代，遍历所有键值对。
6. **并发安全 (一定程度):**  通过 `writing` 字段检测并发写操作，虽然不是完全的并发安全，但可以防止一些基本的并发问题。
7. **小 map 优化:**  对于少量元素的 map，使用优化的存储结构，避免过早分配大的哈希表。
8. **哈希计算:**  使用与 map 类型关联的哈希函数 (`typ.Hasher`) 计算键的哈希值。
9. **碰撞处理:** 使用开放寻址法和二次探测来处理哈希碰撞。
10. **惰性删除:**  使用墓碑标记（"deleted"）来处理删除操作，提高性能，并在扩容时清理。
11. **目录结构:**  使用目录（directory）来管理多个哈希表，支持增量扩容。
12. **随机化迭代顺序:**  迭代顺序是随机的，防止程序依赖特定的迭代顺序。
13. **`Clear` 操作:**  提供清除 map 中所有元素的功能。

**Go 语言功能实现推理和代码示例:**

根据代码中的函数名、结构体定义以及注释，可以推断出这是 Go 语言 `map` 类型的核心实现。

**示例代码:**

```go
package main

import "fmt"

func main() {
	// 创建一个 string 到 int 的 map
	m := make(map[string]int)

	// 插入键值对
	m["apple"] = 1
	m["banana"] = 2
	m["cherry"] = 3

	// 获取值
	fmt.Println("Value for apple:", m["apple"]) // 输出: Value for apple: 1

	// 检查键是否存在
	value, ok := m["banana"]
	if ok {
		fmt.Println("Value for banana:", value) // 输出: Value for banana: 2
	}

	// 删除键值对
	delete(m, "banana")

	// 迭代 map
	fmt.Println("Iterating over map:")
	for key, val := range m {
		fmt.Printf("Key: %s, Value: %d\n", key, val)
		// 输出可能是:
		// Key: apple, Value: 1
		// Key: cherry, Value: 3
		// 或者
		// Key: cherry, Value: 3
		// Key: apple, Value: 1
		// (迭代顺序不确定)
	}

	// 获取 map 的长度
	fmt.Println("Length of map:", len(m)) // 输出: Length of map: 2

	// 清空 map
	m = make(map[string]int) // 或者使用 Clear (如果 maps 包导出了 Clear 函数，但通常用户不会直接调用内部的 Clear)
	fmt.Println("Length of map after clearing:", len(m)) // 输出: Length of map after clearing: 0
}
```

**代码推理 (以 `PutSlot` 函数为例):**

假设我们有以下输入：

*   `typ`: 一个 `abi.SwissMapType` 类型的指针，描述了 `map` 的键和值类型。
*   `key`: 一个 `unsafe.Pointer`，指向要插入的键 "grape"。
*   `m`: 当前的 `Map` 结构体实例。

**`PutSlot` 函数的执行流程（简化）：**

1. **检查并发写:** `if m.writing != 0 { fatal("concurrent map writes") }` - 检查是否有并发写操作。
2. **计算哈希:** `hash := typ.Hasher(key, m.seed)` - 使用与键类型关联的哈希函数和 map 的种子计算键的哈希值。
    *   **假设输入:** `key` 指向字符串 "grape"，`m.seed` 是一个随机数。
    *   **假设输出:** `hash` 的值为 `0x123456789abcdef0` (示例值)。
3. **标记写入:** `m.writing ^= 1` - 标记 map 正在被写入。
4. **小 map 处理:** `if m.dirPtr == nil { m.growToSmall(typ) }` - 如果是空 map，则初始化为小 map。
5. **小 map 插入:** `if m.dirLen == 0 { ... m.putSlotSmall(typ, hash, key) ... }` - 如果是小 map 且有空闲空间，则调用 `putSlotSmall` 插入。
6. **大 map 插入:** `for { idx := m.directoryIndex(hash); elem, ok := m.directoryAt(idx).PutSlot(typ, m, hash, key); if !ok { continue } ... }` - 如果是大的 map，则根据哈希值计算目录索引，然后在对应的 table 中插入。
    *   **假设输入:** `m.globalShift` 的值为 57。
    *   **`m.directoryIndex(hash)` 的计算:** `idx = hash >> (m.globalShift & 63)`，假设 `idx` 计算结果为 `0`。
    *   **`m.directoryAt(idx)`:** 获取目录中索引为 `0` 的 `table` 指针。
    *   **调用 `table.PutSlot`:** 在对应的 `table` 中寻找或分配一个空闲的 slot 来存储键值对。
7. **取消写入标记:** `m.writing ^= 1` - 完成写入后取消标记。
8. **返回元素槽指针:** `return elem` - 返回新插入元素的存储位置的指针。

**命令行参数处理:**

这段代码本身是 Go 语言运行时库的一部分，不直接处理命令行参数。命令行参数的处理通常发生在 `main` 函数中，与 `flag` 包或者直接解析 `os.Args` 相关。

**使用者易犯错的点:**

1. **并发读写未保护:**  Go 的 `map` 在并发读写时是不安全的，会导致程序崩溃或数据竞争。使用者需要使用互斥锁（`sync.Mutex`）或读写锁（`sync.RWMutex`）来保护并发访问。

    ```go
    package main

    import (
    	"fmt"
    	"sync"
    )

    func main() {
    	m := make(map[int]int)
    	var wg sync.WaitGroup
    	var mu sync.Mutex

    	// 多个 goroutine 并发写入 map (未保护)
    	for i := 0; i < 100; i++ {
    		wg.Add(1)
    		go func(n int) {
    			defer wg.Done()
    			m[n] = n * 2 // 潜在的数据竞争
    		}(i)
    	}
    	wg.Wait()
    	fmt.Println(m) // 输出结果可能不一致或程序崩溃

    	// 多个 goroutine 并发写入 map (使用互斥锁保护)
    	m2 := make(map[int]int)
    	for i := 0; i < 100; i++ {
    		wg.Add(1)
    		go func(n int) {
    			defer wg.Done()
    			mu.Lock()
    			m2[n] = n * 2
    			mu.Unlock()
    		}(i)
    	}
    	wg.Wait()
    	fmt.Println(m2) // 输出结果一致
    }
    ```

2. **依赖迭代顺序:**  Go 的 `map` 的迭代顺序是随机的，使用者不应该依赖特定的迭代顺序。如果需要有序的键值对，可以使用切片排序或者其他有序的数据结构。

    ```go
    package main

    import "fmt"

    func main() {
    	m := map[string]int{"c": 3, "a": 1, "b": 2}
    	fmt.Println("Iterating map:")
    	for key, val := range m {
    		fmt.Printf("Key: %s, Value: %d\n", key, val)
    		// 输出顺序是不确定的，可能是 a, b, c 或者 c, a, b 等
    	}
    }
    ```

3. **在迭代过程中修改 map:**  在迭代 `map` 的过程中添加或删除元素可能会导致一些未定义的行为，例如跳过某些元素或者重复访问某些元素。虽然 Go 保证不会在迭代过程中返回同一个 entry 多次，但添加的元素可能在迭代中被访问到，删除的元素则不会。

    ```go
    package main

    import "fmt"

    func main() {
    	m := map[int]int{1: 1, 2: 2, 3: 3}
    	for key := range m {
    		if key == 1 {
    			m[4] = 4 // 在迭代过程中添加元素
    		}
    		fmt.Println(key, m[key])
    	}
    	fmt.Println(m) // 输出结果中可能包含也可能不包含键 4
    }
    ```

这段代码揭示了 Go 语言 `map` 底层实现的复杂性和精妙之处，它通过优化的哈希表结构和动态扩容机制，提供了高效的键值对存储和检索功能。理解这些内部机制有助于我们更好地使用和理解 Go 语言的 `map` 类型。

### 提示词
```
这是路径为go/src/internal/runtime/maps/map.go的go语言实现的一部分， 请列举一下它的功能, 　
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

// Package maps implements Go's builtin map type.
package maps

import (
	"internal/abi"
	"internal/goarch"
	"internal/runtime/math"
	"internal/runtime/sys"
	"unsafe"
)

// This package contains the implementation of Go's builtin map type.
//
// The map design is based on Abseil's "Swiss Table" map design
// (https://abseil.io/about/design/swisstables), with additional modifications
// to cover Go's additional requirements, discussed below.
//
// Terminology:
// - Slot: A storage location of a single key/element pair.
// - Group: A group of abi.SwissMapGroupSlots (8) slots, plus a control word.
// - Control word: An 8-byte word which denotes whether each slot is empty,
//   deleted, or used. If a slot is used, its control byte also contains the
//   lower 7 bits of the hash (H2).
// - H1: Upper 57 bits of a hash.
// - H2: Lower 7 bits of a hash.
// - Table: A complete "Swiss Table" hash table. A table consists of one or
//   more groups for storage plus metadata to handle operation and determining
//   when to grow.
// - Map: The top-level Map type consists of zero or more tables for storage.
//   The upper bits of the hash select which table a key belongs to.
// - Directory: Array of the tables used by the map.
//
// At its core, the table design is similar to a traditional open-addressed
// hash table. Storage consists of an array of groups, which effectively means
// an array of key/elem slots with some control words interspersed. Lookup uses
// the hash to determine an initial group to check. If, due to collisions, this
// group contains no match, the probe sequence selects the next group to check
// (see below for more detail about the probe sequence).
//
// The key difference occurs within a group. In a standard open-addressed
// linear probed hash table, we would check each slot one at a time to find a
// match. A swiss table utilizes the extra control word to check all 8 slots in
// parallel.
//
// Each byte in the control word corresponds to one of the slots in the group.
// In each byte, 1 bit is used to indicate whether the slot is in use, or if it
// is empty/deleted. The other 7 bits contain the lower 7 bits of the hash for
// the key in that slot. See [ctrl] for the exact encoding.
//
// During lookup, we can use some clever bitwise manipulation to compare all 8
// 7-bit hashes against the input hash in parallel (see [ctrlGroup.matchH2]).
// That is, we effectively perform 8 steps of probing in a single operation.
// With SIMD instructions, this could be extended to 16 slots with a 16-byte
// control word.
//
// Since we only use 7 bits of the 64 bit hash, there is a 1 in 128 (~0.7%)
// probability of false positive on each slot, but that's fine: we always need
// double check each match with a standard key comparison regardless.
//
// Probing
//
// Probing is done using the upper 57 bits (H1) of the hash as an index into
// the groups array. Probing walks through the groups using quadratic probing
// until it finds a group with a match or a group with an empty slot. See
// [probeSeq] for specifics about the probe sequence. Note the probe
// invariants: the number of groups must be a power of two, and the end of a
// probe sequence must be a group with an empty slot (the table can never be
// 100% full).
//
// Deletion
//
// Probing stops when it finds a group with an empty slot. This affects
// deletion: when deleting from a completely full group, we must not mark the
// slot as empty, as there could be more slots used later in a probe sequence
// and this deletion would cause probing to stop too early. Instead, we mark
// such slots as "deleted" with a tombstone. If the group still has an empty
// slot, we don't need a tombstone and directly mark the slot empty. Insert
// prioritizes reuse of tombstones over filling an empty slots. Otherwise,
// tombstones are only completely cleared during grow, as an in-place cleanup
// complicates iteration.
//
// Growth
//
// The probe sequence depends on the number of groups. Thus, when growing the
// group count all slots must be reordered to match the new probe sequence. In
// other words, an entire table must be grown at once.
//
// In order to support incremental growth, the map splits its contents across
// multiple tables. Each table is still a full hash table, but an individual
// table may only service a subset of the hash space. Growth occurs on
// individual tables, so while an entire table must grow at once, each of these
// grows is only a small portion of a map. The maximum size of a single grow is
// limited by limiting the maximum size of a table before it is split into
// multiple tables.
//
// A map starts with a single table. Up to [maxTableCapacity], growth simply
// replaces this table with a replacement with double capacity. Beyond this
// limit, growth splits the table into two.
//
// The map uses "extendible hashing" to select which table to use. In
// extendible hashing, we use the upper bits of the hash as an index into an
// array of tables (called the "directory"). The number of bits uses increases
// as the number of tables increases. For example, when there is only 1 table,
// we use 0 bits (no selection necessary). When there are 2 tables, we use 1
// bit to select either the 0th or 1st table. [Map.globalDepth] is the number
// of bits currently used for table selection, and by extension (1 <<
// globalDepth), the size of the directory.
//
// Note that each table has its own load factor and grows independently. If the
// 1st bucket grows, it will split. We'll need 2 bits to select tables, though
// we'll have 3 tables total rather than 4. We support this by allowing
// multiple indicies to point to the same table. This example:
//
//	directory (globalDepth=2)
//	+----+
//	| 00 | --\
//	+----+    +--> table (localDepth=1)
//	| 01 | --/
//	+----+
//	| 10 | ------> table (localDepth=2)
//	+----+
//	| 11 | ------> table (localDepth=2)
//	+----+
//
// Tables track the depth they were created at (localDepth). It is necessary to
// grow the directory when splitting a table where globalDepth == localDepth.
//
// Iteration
//
// Iteration is the most complex part of the map due to Go's generous iteration
// semantics. A summary of semantics from the spec:
// 1. Adding and/or deleting entries during iteration MUST NOT cause iteration
//    to return the same entry more than once.
// 2. Entries added during iteration MAY be returned by iteration.
// 3. Entries modified during iteration MUST return their latest value.
// 4. Entries deleted during iteration MUST NOT be returned by iteration.
// 5. Iteration order is unspecified. In the implementation, it is explicitly
//    randomized.
//
// If the map never grows, these semantics are straightforward: just iterate
// over every table in the directory and every group and slot in each table.
// These semantics all land as expected.
//
// If the map grows during iteration, things complicate significantly. First
// and foremost, we need to track which entries we already returned to satisfy
// (1). There are three types of grow:
// a. A table replaced by a single larger table.
// b. A table split into two replacement tables.
// c. Growing the directory (occurs as part of (b) if necessary).
//
// For all of these cases, the replacement table(s) will have a different probe
// sequence, so simply tracking the current group and slot indices is not
// sufficient.
//
// For (a) and (b), note that grows of tables other than the one we are
// currently iterating over are irrelevant.
//
// We handle (a) and (b) by having the iterator keep a reference to the table
// it is currently iterating over, even after the table is replaced. We keep
// iterating over the original table to maintain the iteration order and avoid
// violating (1). Any new entries added only to the replacement table(s) will
// be skipped (allowed by (2)). To avoid violating (3) or (4), while we use the
// original table to select the keys, we must look them up again in the new
// table(s) to determine if they have been modified or deleted. There is yet
// another layer of complexity if the key does not compare equal itself. See
// [Iter.Next] for the gory details.
//
// Note that for (b) once we finish iterating over the old table we'll need to
// skip the next entry in the directory, as that contains the second split of
// the old table. We can use the old table's localDepth to determine the next
// logical index to use.
//
// For (b), we must adjust the current directory index when the directory
// grows. This is more straightforward, as the directory orders remains the
// same after grow, so we just double the index if the directory size doubles.

// Extracts the H1 portion of a hash: the 57 upper bits.
// TODO(prattmic): what about 32-bit systems?
func h1(h uintptr) uintptr {
	return h >> 7
}

// Extracts the H2 portion of a hash: the 7 bits not used for h1.
//
// These are used as an occupied control byte.
func h2(h uintptr) uintptr {
	return h & 0x7f
}

type Map struct {
	// The number of filled slots (i.e. the number of elements in all
	// tables). Excludes deleted slots.
	// Must be first (known by the compiler, for len() builtin).
	used uint64

	// seed is the hash seed, computed as a unique random number per map.
	seed uintptr

	// The directory of tables.
	//
	// Normally dirPtr points to an array of table pointers
	//
	// dirPtr *[dirLen]*table
	//
	// The length (dirLen) of this array is `1 << globalDepth`. Multiple
	// entries may point to the same table. See top-level comment for more
	// details.
	//
	// Small map optimization: if the map always contained
	// abi.SwissMapGroupSlots or fewer entries, it fits entirely in a
	// single group. In that case dirPtr points directly to a single group.
	//
	// dirPtr *group
	//
	// In this case, dirLen is 0. used counts the number of used slots in
	// the group. Note that small maps never have deleted slots (as there
	// is no probe sequence to maintain).
	dirPtr unsafe.Pointer
	dirLen int

	// The number of bits to use in table directory lookups.
	globalDepth uint8

	// The number of bits to shift out of the hash for directory lookups.
	// On 64-bit systems, this is 64 - globalDepth.
	globalShift uint8

	// writing is a flag that is toggled (XOR 1) while the map is being
	// written. Normally it is set to 1 when writing, but if there are
	// multiple concurrent writers, then toggling increases the probability
	// that both sides will detect the race.
	writing uint8

	// clearSeq is a sequence counter of calls to Clear. It is used to
	// detect map clears during iteration.
	clearSeq uint64
}

func depthToShift(depth uint8) uint8 {
	if goarch.PtrSize == 4 {
		return 32 - depth
	}
	return 64 - depth
}

// If m is non-nil, it should be used rather than allocating.
//
// maxAlloc should be runtime.maxAlloc.
//
// TODO(prattmic): Put maxAlloc somewhere accessible.
func NewMap(mt *abi.SwissMapType, hint uintptr, m *Map, maxAlloc uintptr) *Map {
	if m == nil {
		m = new(Map)
	}

	m.seed = uintptr(rand())

	if hint <= abi.SwissMapGroupSlots {
		// A small map can fill all 8 slots, so no need to increase
		// target capacity.
		//
		// In fact, since an 8 slot group is what the first assignment
		// to an empty map would allocate anyway, it doesn't matter if
		// we allocate here or on the first assignment.
		//
		// Thus we just return without allocating. (We'll save the
		// allocation completely if no assignment comes.)

		// Note that the compiler may have initialized m.dirPtr with a
		// pointer to a stack-allocated group, in which case we already
		// have a group. The control word is already initialized.

		return m
	}

	// Full size map.

	// Set initial capacity to hold hint entries without growing in the
	// average case.
	targetCapacity := (hint * abi.SwissMapGroupSlots) / maxAvgGroupLoad
	if targetCapacity < hint { // overflow
		return m // return an empty map.
	}

	dirSize := (uint64(targetCapacity) + maxTableCapacity - 1) / maxTableCapacity
	dirSize, overflow := alignUpPow2(dirSize)
	if overflow || dirSize > uint64(math.MaxUintptr) {
		return m // return an empty map.
	}

	// Reject hints that are obviously too large.
	groups, overflow := math.MulUintptr(uintptr(dirSize), maxTableCapacity)
	if overflow {
		return m // return an empty map.
	} else {
		mem, overflow := math.MulUintptr(groups, mt.GroupSize)
		if overflow || mem > maxAlloc {
			return m // return an empty map.
		}
	}

	m.globalDepth = uint8(sys.TrailingZeros64(dirSize))
	m.globalShift = depthToShift(m.globalDepth)

	directory := make([]*table, dirSize)

	for i := range directory {
		// TODO: Think more about initial table capacity.
		directory[i] = newTable(mt, uint64(targetCapacity)/dirSize, i, m.globalDepth)
	}

	m.dirPtr = unsafe.Pointer(&directory[0])
	m.dirLen = len(directory)

	return m
}

func NewEmptyMap() *Map {
	m := new(Map)
	m.seed = uintptr(rand())
	// See comment in NewMap. No need to eager allocate a group.
	return m
}

func (m *Map) directoryIndex(hash uintptr) uintptr {
	if m.dirLen == 1 {
		return 0
	}
	return hash >> (m.globalShift & 63)
}

func (m *Map) directoryAt(i uintptr) *table {
	return *(**table)(unsafe.Pointer(uintptr(m.dirPtr) + goarch.PtrSize*i))
}

func (m *Map) directorySet(i uintptr, nt *table) {
	*(**table)(unsafe.Pointer(uintptr(m.dirPtr) + goarch.PtrSize*i)) = nt
}

func (m *Map) replaceTable(nt *table) {
	// The number of entries that reference the same table doubles for each
	// time the globalDepth grows without the table splitting.
	entries := 1 << (m.globalDepth - nt.localDepth)
	for i := 0; i < entries; i++ {
		//m.directory[nt.index+i] = nt
		m.directorySet(uintptr(nt.index+i), nt)
	}
}

func (m *Map) installTableSplit(old, left, right *table) {
	if old.localDepth == m.globalDepth {
		// No room for another level in the directory. Grow the
		// directory.
		newDir := make([]*table, m.dirLen*2)
		for i := range m.dirLen {
			t := m.directoryAt(uintptr(i))
			newDir[2*i] = t
			newDir[2*i+1] = t
			// t may already exist in multiple indicies. We should
			// only update t.index once. Since the index must
			// increase, seeing the original index means this must
			// be the first time we've encountered this table.
			if t.index == i {
				t.index = 2 * i
			}
		}
		m.globalDepth++
		m.globalShift--
		//m.directory = newDir
		m.dirPtr = unsafe.Pointer(&newDir[0])
		m.dirLen = len(newDir)
	}

	// N.B. left and right may still consume multiple indicies if the
	// directory has grown multiple times since old was last split.
	left.index = old.index
	m.replaceTable(left)

	entries := 1 << (m.globalDepth - left.localDepth)
	right.index = left.index + entries
	m.replaceTable(right)
}

func (m *Map) Used() uint64 {
	return m.used
}

// Get performs a lookup of the key that key points to. It returns a pointer to
// the element, or false if the key doesn't exist.
func (m *Map) Get(typ *abi.SwissMapType, key unsafe.Pointer) (unsafe.Pointer, bool) {
	return m.getWithoutKey(typ, key)
}

func (m *Map) getWithKey(typ *abi.SwissMapType, key unsafe.Pointer) (unsafe.Pointer, unsafe.Pointer, bool) {
	if m.Used() == 0 {
		return nil, nil, false
	}

	if m.writing != 0 {
		fatal("concurrent map read and map write")
	}

	hash := typ.Hasher(key, m.seed)

	if m.dirLen == 0 {
		return m.getWithKeySmall(typ, hash, key)
	}

	idx := m.directoryIndex(hash)
	return m.directoryAt(idx).getWithKey(typ, hash, key)
}

func (m *Map) getWithoutKey(typ *abi.SwissMapType, key unsafe.Pointer) (unsafe.Pointer, bool) {
	if m.Used() == 0 {
		return nil, false
	}

	if m.writing != 0 {
		fatal("concurrent map read and map write")
	}

	hash := typ.Hasher(key, m.seed)

	if m.dirLen == 0 {
		_, elem, ok := m.getWithKeySmall(typ, hash, key)
		return elem, ok
	}

	idx := m.directoryIndex(hash)
	return m.directoryAt(idx).getWithoutKey(typ, hash, key)
}

func (m *Map) getWithKeySmall(typ *abi.SwissMapType, hash uintptr, key unsafe.Pointer) (unsafe.Pointer, unsafe.Pointer, bool) {
	g := groupReference{
		data: m.dirPtr,
	}

	h2 := uint8(h2(hash))
	ctrls := *g.ctrls()

	for i := uintptr(0); i < abi.SwissMapGroupSlots; i++ {
		c := uint8(ctrls)
		ctrls >>= 8
		if c != h2 {
			continue
		}

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
	}

	return nil, nil, false
}

func (m *Map) Put(typ *abi.SwissMapType, key, elem unsafe.Pointer) {
	slotElem := m.PutSlot(typ, key)
	typedmemmove(typ.Elem, slotElem, elem)
}

// PutSlot returns a pointer to the element slot where an inserted element
// should be written.
//
// PutSlot never returns nil.
func (m *Map) PutSlot(typ *abi.SwissMapType, key unsafe.Pointer) unsafe.Pointer {
	if m.writing != 0 {
		fatal("concurrent map writes")
	}

	hash := typ.Hasher(key, m.seed)

	// Set writing after calling Hasher, since Hasher may panic, in which
	// case we have not actually done a write.
	m.writing ^= 1 // toggle, see comment on writing

	if m.dirPtr == nil {
		m.growToSmall(typ)
	}

	if m.dirLen == 0 {
		if m.used < abi.SwissMapGroupSlots {
			elem := m.putSlotSmall(typ, hash, key)

			if m.writing == 0 {
				fatal("concurrent map writes")
			}
			m.writing ^= 1

			return elem
		}

		// Can't fit another entry, grow to full size map.
		//
		// TODO(prattmic): If this is an update to an existing key then
		// we actually don't need to grow.
		m.growToTable(typ)
	}

	for {
		idx := m.directoryIndex(hash)
		elem, ok := m.directoryAt(idx).PutSlot(typ, m, hash, key)
		if !ok {
			continue
		}

		if m.writing == 0 {
			fatal("concurrent map writes")
		}
		m.writing ^= 1

		return elem
	}
}

func (m *Map) putSlotSmall(typ *abi.SwissMapType, hash uintptr, key unsafe.Pointer) unsafe.Pointer {
	g := groupReference{
		data: m.dirPtr,
	}

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
		return nil
	}

	i := match.first()

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
	m.used++

	return slotElem
}

func (m *Map) growToSmall(typ *abi.SwissMapType) {
	grp := newGroups(typ, 1)
	m.dirPtr = grp.data

	g := groupReference{
		data: m.dirPtr,
	}
	g.ctrls().setEmpty()
}

func (m *Map) growToTable(typ *abi.SwissMapType) {
	tab := newTable(typ, 2*abi.SwissMapGroupSlots, 0, 0)

	g := groupReference{
		data: m.dirPtr,
	}

	for i := uintptr(0); i < abi.SwissMapGroupSlots; i++ {
		if (g.ctrls().get(i) & ctrlEmpty) == ctrlEmpty {
			// Empty
			continue
		}

		key := g.key(typ, i)
		if typ.IndirectKey() {
			key = *((*unsafe.Pointer)(key))
		}

		elem := g.elem(typ, i)
		if typ.IndirectElem() {
			elem = *((*unsafe.Pointer)(elem))
		}

		hash := typ.Hasher(key, m.seed)

		tab.uncheckedPutSlot(typ, hash, key, elem)
	}

	directory := make([]*table, 1)

	directory[0] = tab

	m.dirPtr = unsafe.Pointer(&directory[0])
	m.dirLen = len(directory)

	m.globalDepth = 0
	m.globalShift = depthToShift(m.globalDepth)
}

func (m *Map) Delete(typ *abi.SwissMapType, key unsafe.Pointer) {
	if m == nil || m.Used() == 0 {
		if err := mapKeyError(typ, key); err != nil {
			panic(err) // see issue 23734
		}
		return
	}

	if m.writing != 0 {
		fatal("concurrent map writes")
	}

	hash := typ.Hasher(key, m.seed)

	// Set writing after calling Hasher, since Hasher may panic, in which
	// case we have not actually done a write.
	m.writing ^= 1 // toggle, see comment on writing

	if m.dirLen == 0 {
		m.deleteSmall(typ, hash, key)
	} else {
		idx := m.directoryIndex(hash)
		m.directoryAt(idx).Delete(typ, m, hash, key)
	}

	if m.used == 0 {
		// Reset the hash seed to make it more difficult for attackers
		// to repeatedly trigger hash collisions. See
		// https://go.dev/issue/25237.
		m.seed = uintptr(rand())
	}

	if m.writing == 0 {
		fatal("concurrent map writes")
	}
	m.writing ^= 1
}

func (m *Map) deleteSmall(typ *abi.SwissMapType, hash uintptr, key unsafe.Pointer) {
	g := groupReference{
		data: m.dirPtr,
	}

	match := g.ctrls().matchH2(h2(hash))

	for match != 0 {
		i := match.first()
		slotKey := g.key(typ, i)
		origSlotKey := slotKey
		if typ.IndirectKey() {
			slotKey = *((*unsafe.Pointer)(slotKey))
		}
		if typ.Key.Equal(key, slotKey) {
			m.used--

			if typ.IndirectKey() {
				// Clearing the pointer is sufficient.
				*(*unsafe.Pointer)(origSlotKey) = nil
			} else if typ.Key.Pointers() {
				// Only bother clearing if there are pointers.
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

			// We only have 1 group, so it is OK to immediately
			// reuse deleted slots.
			g.ctrls().set(i, ctrlEmpty)
			return
		}
		match = match.removeFirst()
	}
}

// Clear deletes all entries from the map resulting in an empty map.
func (m *Map) Clear(typ *abi.SwissMapType) {
	if m == nil || m.Used() == 0 {
		return
	}

	if m.writing != 0 {
		fatal("concurrent map writes")
	}
	m.writing ^= 1 // toggle, see comment on writing

	if m.dirLen == 0 {
		m.clearSmall(typ)
	} else {
		var lastTab *table
		for i := range m.dirLen {
			t := m.directoryAt(uintptr(i))
			if t == lastTab {
				continue
			}
			t.Clear(typ)
			lastTab = t
		}
		m.used = 0
		m.clearSeq++
		// TODO: shrink directory?
	}

	// Reset the hash seed to make it more difficult for attackers to
	// repeatedly trigger hash collisions. See https://go.dev/issue/25237.
	m.seed = uintptr(rand())

	if m.writing == 0 {
		fatal("concurrent map writes")
	}
	m.writing ^= 1
}

func (m *Map) clearSmall(typ *abi.SwissMapType) {
	g := groupReference{
		data: m.dirPtr,
	}

	typedmemclr(typ.Group, g.data)
	g.ctrls().setEmpty()

	m.used = 0
	m.clearSeq++
}
```