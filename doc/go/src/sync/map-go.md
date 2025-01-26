Response:
Let's break down the thought process for analyzing the `sync.Map` code.

**1. Understanding the Goal:**

The request asks for the functionality of the provided Go code snippet, which is part of `sync/map.go`. The core task is to explain what this code does, how it works, provide usage examples, and highlight potential pitfalls.

**2. Initial Code Scan and High-Level Understanding:**

The first step is to quickly scan the code for keywords and structural elements:

* **Package `sync`:**  This immediately tells us it's about synchronization primitives in Go.
* **`type Map struct`:**  This defines a custom type named `Map`, suggesting a data structure.
* **Comments:** The comments are crucial. They explicitly state: "Map is like a Go map[any]any but is safe for concurrent use..." This is the most important piece of information. It's a concurrent map.
* **Fields of `Map`:**  `mu Mutex`, `read atomic.Pointer[readOnly]`, `dirty map[any]*entry`, `misses int`. These fields hint at the internal implementation: a mutex for locking, an atomic pointer for a read-only portion, a regular map for a dirty portion, and a counter for misses. This suggests a read-optimized approach.
* **Methods:**  `Load`, `Store`, `Delete`, `LoadOrStore`, `Range`, etc. These are the standard map operations, further solidifying its role as a map-like data structure.
* **`readOnly` struct:**  Contains `m map[any]*entry` and `amended bool`. This supports the idea of a separate read-optimized view.
* **`entry` struct:** Contains `p atomic.Pointer[any]`. This suggests atomic operations on individual entries.
* **`expunged`:** A special marker for deleted entries.

**3. Deeper Dive into Functionality (Method by Method):**

Now, go through each public method of the `Map` type and understand its purpose:

* **`Load(key any)`:**  Retrieves a value. The comments mention the "read" and "dirty" maps, suggesting a two-stage lookup for optimization.
* **`Store(key, value any)`:**  Sets a value. Likely involves updating either the "read" or "dirty" map, depending on the state.
* **`Delete(key any)`:**  Removes a value. Similar to `Store`, it needs to handle both "read" and "dirty" states.
* **`LoadOrStore(key, value any)`:**  Atomic get-or-set. More complex logic likely needed to handle concurrent access.
* **`Range(f func(key, value any) bool)`:** Iterates through the map. The comments highlight that it's not a snapshot and concurrent modifications are possible.
* **`Clear()`:** Empties the map. Needs to reset both "read" and "dirty" maps.
* **`Swap(key, value any)`:**  Atomic swap of values.
* **`CompareAndSwap(key, old, new any)`:** Atomic compare-and-swap.
* **`CompareAndDelete(key, old any)`:** Atomic compare-and-delete.

**4. Identifying Core Concepts and Implementation Details:**

As you analyze the methods, key concepts emerge:

* **Read Optimization:** The separation of `read` and `dirty` maps is the core optimization. Reads can often happen without acquiring the mutex if the data is in the `read` map.
* **Atomic Operations:** The use of `atomic.Pointer` is crucial for thread safety without constant locking.
* **Mutex for Writes and Promotions:** The `mu` mutex protects the `dirty` map and the process of promoting the `dirty` map to the `read` map.
* **Expunged Entries:**  The `expunged` marker is a clever way to handle deletions and avoid unnecessary data copying.
* **Miss Counter:** The `misses` counter triggers the promotion of the `dirty` map to the `read` map, balancing read performance with the cost of copying.

**5. Inferring Go Feature Implementation:**

Based on the functionality and the `sync` package, it's clear that `sync.Map` implements a **concurrently safe map**. This addresses the common need for shared mutable data structures in concurrent Go programs.

**6. Crafting Usage Examples:**

Now, create simple Go code examples demonstrating the key methods: `Load`, `Store`, `LoadOrStore`, `Delete`, and `Range`. These examples should be easy to understand and highlight the concurrent safety aspect. Think about scenarios where multiple goroutines access the map.

**7. Reasoning Through Input and Output (for Code Examples):**

For each code example, define clear input values and predict the expected output. This reinforces understanding and demonstrates how the methods work.

**8. Command-Line Arguments:**

This particular code snippet for `sync.Map` doesn't involve command-line arguments. Recognize this and state it explicitly.

**9. Identifying Common Mistakes:**

Think about how developers might misuse this data structure:

* **Overuse:**  Emphasize the specialization of `sync.Map` and recommend plain Go maps for simpler cases.
* **Incorrect Assumptions about `Range`:** Highlight that `Range` is not a snapshot and concurrent modifications can occur.
* **Type Safety:**  Since it's `map[any]any`, type assertions are necessary, which can lead to runtime errors if not handled carefully.

**10. Structuring the Answer (in Chinese):**

Organize the information logically:

* **功能列举 (List of Features):**  Start with a concise list of what the `Map` can do.
* **Go语言功能实现 (Go Feature Implementation):** Explain that it implements a concurrent map.
* **代码举例说明 (Code Examples):** Provide clear and illustrative Go code examples with input and output.
* **命令行参数的具体处理 (Command-Line Arguments):** State that there are none for this code.
* **使用者易犯错的点 (Common Mistakes):**  Explain the pitfalls with concrete examples.

**Self-Correction/Refinement during the Process:**

* **Initial thought:** Maybe it's just a thread-safe wrapper around a regular map.
* **Correction:** The internal structure with `read` and `dirty` maps suggests a more sophisticated optimization strategy than simple locking.
* **Initial thought:**  The `Range` function provides a snapshot.
* **Correction:** The comments explicitly state that it's not a snapshot, and concurrent modifications are possible. Adjust the explanation accordingly.
* **Ensuring clarity in Chinese:** Use precise terminology and clear sentence structures to convey the technical concepts accurately in Chinese.

By following these steps, systematically analyzing the code, and focusing on the key aspects of its functionality and implementation, we can arrive at a comprehensive and accurate explanation of `sync.Map`.
这段代码是 Go 语言标准库 `sync` 包中 `map.go` 文件的一部分，它定义并实现了一个名为 `Map` 的数据结构。 `Map` 类似于 Go 语言内置的 `map[any]any`，但关键的区别在于 **`sync.Map` 是并发安全的**，允许多个 goroutine 在没有额外锁或协调的情况下安全地访问和修改其中的数据。

**`sync.Map` 的功能列举:**

1. **存储键值对:**  `Map` 允许存储任意类型的键值对，因为其内部使用了 `any` 类型。
2. **并发安全:** 这是 `sync.Map` 最核心的功能。它通过内部的机制（例如原子操作、读写分离等）保证了在多个 goroutine 并发读写时的数据一致性，避免了数据竞争。
3. **加载 (Load):**  根据给定的键，安全地获取存储在 `Map` 中的值。如果键不存在，则返回 `nil` 和 `false`。
4. **存储 (Store):**  安全地设置给定键的值。
5. **加载或存储 (LoadOrStore):**  安全地获取给定键的值。如果键不存在，则存储给定的值并返回。返回已存在的值或新存储的值，以及一个布尔值指示是否是加载的已有值。
6. **加载并删除 (LoadAndDelete):** 安全地获取给定键的值并从 `Map` 中删除该键值对。返回被删除的值和一个布尔值指示键是否存在。
7. **删除 (Delete):** 安全地删除给定键的值。
8. **交换 (Swap):** 安全地用给定的新值替换给定键的现有值，并返回原始值。如果键不存在，则添加新值并返回 nil 和 false。
9. **比较并交换 (CompareAndSwap):** 安全地比较给定键的当前值是否与旧值相等，如果相等则将其替换为新值。返回一个布尔值指示是否成功交换。
10. **比较并删除 (CompareAndDelete):** 安全地比较给定键的当前值是否与给定的旧值相等，如果相等则删除该键值对。返回一个布尔值指示是否成功删除。
11. **范围迭代 (Range):**  遍历 `Map` 中的所有键值对，并对每个键值对调用提供的回调函数。如果回调函数返回 `false`，则停止迭代。**需要注意的是，`Range` 并不保证在迭代期间看到 `Map` 内容的快照，并发的修改可能反映在迭代过程中。**
12. **清空 (Clear):** 删除 `Map` 中的所有条目，使其成为空 `Map`。

**`sync.Map` 是什么 Go 语言功能的实现？**

`sync.Map` 是 Go 语言中用于实现 **并发安全的字典（map）** 的一种方式。它旨在解决在多 goroutine 环境下使用普通 `map` 需要额外加锁带来的性能瓶颈问题。

**Go 代码举例说明:**

```go
package main

import (
	"fmt"
	"sync"
	"time"
)

func main() {
	var m sync.Map

	// 存储数据
	m.Store("key1", "value1")
	m.Store("key2", 123)

	// 加载数据
	val1, ok1 := m.Load("key1")
	fmt.Printf("Load 'key1': value=%v, present=%v\n", val1, ok1) // 输出: Load 'key1': value=value1, present=true

	val3, ok3 := m.Load("key3")
	fmt.Printf("Load 'key3': value=%v, present=%v\n", val3, ok3) // 输出: Load 'key3': value=<nil>, present=false

	// 加载或存储
	actual, loaded := m.LoadOrStore("key2", 456)
	fmt.Printf("LoadOrStore 'key2': actual=%v, loaded=%v\n", actual, loaded) // 输出: LoadOrStore 'key2': actual=123, loaded=true

	actual, loaded = m.LoadOrStore("key4", "value4")
	fmt.Printf("LoadOrStore 'key4': actual=%v, loaded=%v\n", actual, loaded) // 输出: LoadOrStore 'key4': actual=value4, loaded=false

	// 删除数据
	m.Delete("key1")
	val1, ok1 = m.Load("key1")
	fmt.Printf("Load 'key1' after delete: value=%v, present=%v\n", val1, ok1) // 输出: Load 'key1' after delete: value=<nil>, present=false

	// 范围迭代
	fmt.Println("Iterating over the map:")
	m.Range(func(key, value any) bool {
		fmt.Printf("Key: %v, Value: %v\n", key, value)
		return true
	})
	// 可能输出 (顺序不保证):
	// Iterating over the map:
	// Key: key2, Value: 123
	// Key: key4, Value: value4

	// 并发操作示例
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(index int) {
			defer wg.Done()
			key := fmt.Sprintf("concurrent_key_%d", index)
			m.Store(key, index)
			val, ok := m.Load(key)
			fmt.Printf("Goroutine %d: Loaded key '%s', value=%v, present=%v\n", index, key, val, ok)
		}(i)
	}
	wg.Wait()
}
```

**假设的输入与输出 (基于上面的代码):**

* **输入:**  无特定的外部输入，主要是在代码内部进行操作。
* **输出:**  如代码注释中所示。  并发操作部分的输出顺序是不确定的，因为 goroutine 的执行顺序是无法预测的。

**命令行参数的具体处理:**

这段 `sync.Map` 的实现本身 **不涉及任何命令行参数的处理**。它是 Go 语言标准库的一部分，主要提供数据结构和并发控制功能。它的使用方式是在 Go 代码中导入 `sync` 包并使用 `sync.Map` 类型。

**使用者易犯错的点:**

1. **过度使用 `sync.Map`:** `sync.Map` 针对特定的用例进行了优化，即：
   * 给定键的条目只写入一次但读取多次（例如，只增长的缓存）。
   * 多个 goroutine 读取、写入和覆盖不相交的键集合的条目。
   如果你的用例不符合这些情况，使用普通的 `map` 搭配 `sync.Mutex` 或 `sync.RWMutex` 可能更简单且效率更高（尤其是写入操作频繁的场景）。`sync.Map` 的内部实现为了并发安全付出了一定的复杂性代价。

   **错误示例:** 在一个需要频繁写入且写入操作之间存在竞争的场景下无脑使用 `sync.Map`，可能导致性能不如加锁的普通 `map`。

2. **对 `Range` 的行为理解不准确:**  `sync.Map` 的 `Range` 方法并不保证在迭代期间看到 `Map` 内容的静态快照。并发的 `Store` 或 `Delete` 操作可能会影响正在进行的 `Range` 迭代。这意味着你在 `Range` 的回调函数中看到的数据可能来自 `Map` 在迭代过程中的不同状态。

   **错误示例:**  假设在 `Range` 迭代开始时 `Map` 中有 3 个元素，但在迭代过程中，另一个 goroutine 删除了一个元素。`Range` 的回调函数可能会只被调用两次，或者可能会尝试访问已被删除的元素（虽然 `sync.Map` 会尽力避免这种情况，但行为不是绝对确定的）。

3. **类型断言的必要性:** 由于 `sync.Map` 使用 `any` 类型存储键和值，从 `Map` 中加载数据后，通常需要进行类型断言才能使用具体的类型。如果类型断言失败，会导致 panic。

   **错误示例:**

   ```go
   var m sync.Map
   m.Store("count", 10)

   val, _ := m.Load("count")
   // 直接将 val 当作 int 使用会报错
   // result := val + 5 // 编译错误

   // 需要进行类型断言
   if count, ok := val.(int); ok {
       result := count + 5
       fmt.Println(result) // 正确
   } else {
       fmt.Println("类型断言失败")
   }
   ```

4. **`sync.Map` 不应该被复制:**  在第一次使用后复制 `sync.Map` 是不允许的。`sync.Map` 内部维护了一些状态，复制会导致这些状态不一致，从而引发不可预测的行为。

   **错误示例:**

   ```go
   var m1 sync.Map
   m1.Store("key", "value")

   m2 := m1 // 错误的复制
   m2.Store("another_key", "another_value") // 可能会导致问题

   val1, _ := m1.Load("another_key")
   fmt.Println(val1) // 结果不确定
   ```

总而言之，`sync.Map` 是 Go 语言中一个强大的并发安全的数据结构，但在使用时需要理解其特性和适用场景，避免常见的错误用法。

Prompt: 
```
这是路径为go/src/sync/map.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。

"""
// Copyright 2016 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build !goexperiment.synchashtriemap

package sync

import (
	"sync/atomic"
)

// Map is like a Go map[any]any but is safe for concurrent use
// by multiple goroutines without additional locking or coordination.
// Loads, stores, and deletes run in amortized constant time.
//
// The Map type is specialized. Most code should use a plain Go map instead,
// with separate locking or coordination, for better type safety and to make it
// easier to maintain other invariants along with the map content.
//
// The Map type is optimized for two common use cases: (1) when the entry for a given
// key is only ever written once but read many times, as in caches that only grow,
// or (2) when multiple goroutines read, write, and overwrite entries for disjoint
// sets of keys. In these two cases, use of a Map may significantly reduce lock
// contention compared to a Go map paired with a separate [Mutex] or [RWMutex].
//
// The zero Map is empty and ready for use. A Map must not be copied after first use.
//
// In the terminology of [the Go memory model], Map arranges that a write operation
// “synchronizes before” any read operation that observes the effect of the write, where
// read and write operations are defined as follows.
// [Map.Load], [Map.LoadAndDelete], [Map.LoadOrStore], [Map.Swap], [Map.CompareAndSwap],
// and [Map.CompareAndDelete] are read operations;
// [Map.Delete], [Map.LoadAndDelete], [Map.Store], and [Map.Swap] are write operations;
// [Map.LoadOrStore] is a write operation when it returns loaded set to false;
// [Map.CompareAndSwap] is a write operation when it returns swapped set to true;
// and [Map.CompareAndDelete] is a write operation when it returns deleted set to true.
//
// [the Go memory model]: https://go.dev/ref/mem
type Map struct {
	_ noCopy

	mu Mutex

	// read contains the portion of the map's contents that are safe for
	// concurrent access (with or without mu held).
	//
	// The read field itself is always safe to load, but must only be stored with
	// mu held.
	//
	// Entries stored in read may be updated concurrently without mu, but updating
	// a previously-expunged entry requires that the entry be copied to the dirty
	// map and unexpunged with mu held.
	read atomic.Pointer[readOnly]

	// dirty contains the portion of the map's contents that require mu to be
	// held. To ensure that the dirty map can be promoted to the read map quickly,
	// it also includes all of the non-expunged entries in the read map.
	//
	// Expunged entries are not stored in the dirty map. An expunged entry in the
	// clean map must be unexpunged and added to the dirty map before a new value
	// can be stored to it.
	//
	// If the dirty map is nil, the next write to the map will initialize it by
	// making a shallow copy of the clean map, omitting stale entries.
	dirty map[any]*entry

	// misses counts the number of loads since the read map was last updated that
	// needed to lock mu to determine whether the key was present.
	//
	// Once enough misses have occurred to cover the cost of copying the dirty
	// map, the dirty map will be promoted to the read map (in the unamended
	// state) and the next store to the map will make a new dirty copy.
	misses int
}

// readOnly is an immutable struct stored atomically in the Map.read field.
type readOnly struct {
	m       map[any]*entry
	amended bool // true if the dirty map contains some key not in m.
}

// expunged is an arbitrary pointer that marks entries which have been deleted
// from the dirty map.
var expunged = new(any)

// An entry is a slot in the map corresponding to a particular key.
type entry struct {
	// p points to the interface{} value stored for the entry.
	//
	// If p == nil, the entry has been deleted, and either m.dirty == nil or
	// m.dirty[key] is e.
	//
	// If p == expunged, the entry has been deleted, m.dirty != nil, and the entry
	// is missing from m.dirty.
	//
	// Otherwise, the entry is valid and recorded in m.read.m[key] and, if m.dirty
	// != nil, in m.dirty[key].
	//
	// An entry can be deleted by atomic replacement with nil: when m.dirty is
	// next created, it will atomically replace nil with expunged and leave
	// m.dirty[key] unset.
	//
	// An entry's associated value can be updated by atomic replacement, provided
	// p != expunged. If p == expunged, an entry's associated value can be updated
	// only after first setting m.dirty[key] = e so that lookups using the dirty
	// map find the entry.
	p atomic.Pointer[any]
}

func newEntry(i any) *entry {
	e := &entry{}
	e.p.Store(&i)
	return e
}

func (m *Map) loadReadOnly() readOnly {
	if p := m.read.Load(); p != nil {
		return *p
	}
	return readOnly{}
}

// Load returns the value stored in the map for a key, or nil if no
// value is present.
// The ok result indicates whether value was found in the map.
func (m *Map) Load(key any) (value any, ok bool) {
	read := m.loadReadOnly()
	e, ok := read.m[key]
	if !ok && read.amended {
		m.mu.Lock()
		// Avoid reporting a spurious miss if m.dirty got promoted while we were
		// blocked on m.mu. (If further loads of the same key will not miss, it's
		// not worth copying the dirty map for this key.)
		read = m.loadReadOnly()
		e, ok = read.m[key]
		if !ok && read.amended {
			e, ok = m.dirty[key]
			// Regardless of whether the entry was present, record a miss: this key
			// will take the slow path until the dirty map is promoted to the read
			// map.
			m.missLocked()
		}
		m.mu.Unlock()
	}
	if !ok {
		return nil, false
	}
	return e.load()
}

func (e *entry) load() (value any, ok bool) {
	p := e.p.Load()
	if p == nil || p == expunged {
		return nil, false
	}
	return *p, true
}

// Store sets the value for a key.
func (m *Map) Store(key, value any) {
	_, _ = m.Swap(key, value)
}

// Clear deletes all the entries, resulting in an empty Map.
func (m *Map) Clear() {
	read := m.loadReadOnly()
	if len(read.m) == 0 && !read.amended {
		// Avoid allocating a new readOnly when the map is already clear.
		return
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	read = m.loadReadOnly()
	if len(read.m) > 0 || read.amended {
		m.read.Store(&readOnly{})
	}

	clear(m.dirty)
	// Don't immediately promote the newly-cleared dirty map on the next operation.
	m.misses = 0
}

// tryCompareAndSwap compare the entry with the given old value and swaps
// it with a new value if the entry is equal to the old value, and the entry
// has not been expunged.
//
// If the entry is expunged, tryCompareAndSwap returns false and leaves
// the entry unchanged.
func (e *entry) tryCompareAndSwap(old, new any) bool {
	p := e.p.Load()
	if p == nil || p == expunged || *p != old {
		return false
	}

	// Copy the interface after the first load to make this method more amenable
	// to escape analysis: if the comparison fails from the start, we shouldn't
	// bother heap-allocating an interface value to store.
	nc := new
	for {
		if e.p.CompareAndSwap(p, &nc) {
			return true
		}
		p = e.p.Load()
		if p == nil || p == expunged || *p != old {
			return false
		}
	}
}

// unexpungeLocked ensures that the entry is not marked as expunged.
//
// If the entry was previously expunged, it must be added to the dirty map
// before m.mu is unlocked.
func (e *entry) unexpungeLocked() (wasExpunged bool) {
	return e.p.CompareAndSwap(expunged, nil)
}

// swapLocked unconditionally swaps a value into the entry.
//
// The entry must be known not to be expunged.
func (e *entry) swapLocked(i *any) *any {
	return e.p.Swap(i)
}

// LoadOrStore returns the existing value for the key if present.
// Otherwise, it stores and returns the given value.
// The loaded result is true if the value was loaded, false if stored.
func (m *Map) LoadOrStore(key, value any) (actual any, loaded bool) {
	// Avoid locking if it's a clean hit.
	read := m.loadReadOnly()
	if e, ok := read.m[key]; ok {
		actual, loaded, ok := e.tryLoadOrStore(value)
		if ok {
			return actual, loaded
		}
	}

	m.mu.Lock()
	read = m.loadReadOnly()
	if e, ok := read.m[key]; ok {
		if e.unexpungeLocked() {
			m.dirty[key] = e
		}
		actual, loaded, _ = e.tryLoadOrStore(value)
	} else if e, ok := m.dirty[key]; ok {
		actual, loaded, _ = e.tryLoadOrStore(value)
		m.missLocked()
	} else {
		if !read.amended {
			// We're adding the first new key to the dirty map.
			// Make sure it is allocated and mark the read-only map as incomplete.
			m.dirtyLocked()
			m.read.Store(&readOnly{m: read.m, amended: true})
		}
		m.dirty[key] = newEntry(value)
		actual, loaded = value, false
	}
	m.mu.Unlock()

	return actual, loaded
}

// tryLoadOrStore atomically loads or stores a value if the entry is not
// expunged.
//
// If the entry is expunged, tryLoadOrStore leaves the entry unchanged and
// returns with ok==false.
func (e *entry) tryLoadOrStore(i any) (actual any, loaded, ok bool) {
	p := e.p.Load()
	if p == expunged {
		return nil, false, false
	}
	if p != nil {
		return *p, true, true
	}

	// Copy the interface after the first load to make this method more amenable
	// to escape analysis: if we hit the "load" path or the entry is expunged, we
	// shouldn't bother heap-allocating.
	ic := i
	for {
		if e.p.CompareAndSwap(nil, &ic) {
			return i, false, true
		}
		p = e.p.Load()
		if p == expunged {
			return nil, false, false
		}
		if p != nil {
			return *p, true, true
		}
	}
}

// LoadAndDelete deletes the value for a key, returning the previous value if any.
// The loaded result reports whether the key was present.
func (m *Map) LoadAndDelete(key any) (value any, loaded bool) {
	read := m.loadReadOnly()
	e, ok := read.m[key]
	if !ok && read.amended {
		m.mu.Lock()
		read = m.loadReadOnly()
		e, ok = read.m[key]
		if !ok && read.amended {
			e, ok = m.dirty[key]
			delete(m.dirty, key)
			// Regardless of whether the entry was present, record a miss: this key
			// will take the slow path until the dirty map is promoted to the read
			// map.
			m.missLocked()
		}
		m.mu.Unlock()
	}
	if ok {
		return e.delete()
	}
	return nil, false
}

// Delete deletes the value for a key.
func (m *Map) Delete(key any) {
	m.LoadAndDelete(key)
}

func (e *entry) delete() (value any, ok bool) {
	for {
		p := e.p.Load()
		if p == nil || p == expunged {
			return nil, false
		}
		if e.p.CompareAndSwap(p, nil) {
			return *p, true
		}
	}
}

// trySwap swaps a value if the entry has not been expunged.
//
// If the entry is expunged, trySwap returns false and leaves the entry
// unchanged.
func (e *entry) trySwap(i *any) (*any, bool) {
	for {
		p := e.p.Load()
		if p == expunged {
			return nil, false
		}
		if e.p.CompareAndSwap(p, i) {
			return p, true
		}
	}
}

// Swap swaps the value for a key and returns the previous value if any.
// The loaded result reports whether the key was present.
func (m *Map) Swap(key, value any) (previous any, loaded bool) {
	read := m.loadReadOnly()
	if e, ok := read.m[key]; ok {
		if v, ok := e.trySwap(&value); ok {
			if v == nil {
				return nil, false
			}
			return *v, true
		}
	}

	m.mu.Lock()
	read = m.loadReadOnly()
	if e, ok := read.m[key]; ok {
		if e.unexpungeLocked() {
			// The entry was previously expunged, which implies that there is a
			// non-nil dirty map and this entry is not in it.
			m.dirty[key] = e
		}
		if v := e.swapLocked(&value); v != nil {
			loaded = true
			previous = *v
		}
	} else if e, ok := m.dirty[key]; ok {
		if v := e.swapLocked(&value); v != nil {
			loaded = true
			previous = *v
		}
	} else {
		if !read.amended {
			// We're adding the first new key to the dirty map.
			// Make sure it is allocated and mark the read-only map as incomplete.
			m.dirtyLocked()
			m.read.Store(&readOnly{m: read.m, amended: true})
		}
		m.dirty[key] = newEntry(value)
	}
	m.mu.Unlock()
	return previous, loaded
}

// CompareAndSwap swaps the old and new values for key
// if the value stored in the map is equal to old.
// The old value must be of a comparable type.
func (m *Map) CompareAndSwap(key, old, new any) (swapped bool) {
	read := m.loadReadOnly()
	if e, ok := read.m[key]; ok {
		return e.tryCompareAndSwap(old, new)
	} else if !read.amended {
		return false // No existing value for key.
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	read = m.loadReadOnly()
	swapped = false
	if e, ok := read.m[key]; ok {
		swapped = e.tryCompareAndSwap(old, new)
	} else if e, ok := m.dirty[key]; ok {
		swapped = e.tryCompareAndSwap(old, new)
		// We needed to lock mu in order to load the entry for key,
		// and the operation didn't change the set of keys in the map
		// (so it would be made more efficient by promoting the dirty
		// map to read-only).
		// Count it as a miss so that we will eventually switch to the
		// more efficient steady state.
		m.missLocked()
	}
	return swapped
}

// CompareAndDelete deletes the entry for key if its value is equal to old.
// The old value must be of a comparable type.
//
// If there is no current value for key in the map, CompareAndDelete
// returns false (even if the old value is the nil interface value).
func (m *Map) CompareAndDelete(key, old any) (deleted bool) {
	read := m.loadReadOnly()
	e, ok := read.m[key]
	if !ok && read.amended {
		m.mu.Lock()
		read = m.loadReadOnly()
		e, ok = read.m[key]
		if !ok && read.amended {
			e, ok = m.dirty[key]
			// Don't delete key from m.dirty: we still need to do the “compare” part
			// of the operation. The entry will eventually be expunged when the
			// dirty map is promoted to the read map.
			//
			// Regardless of whether the entry was present, record a miss: this key
			// will take the slow path until the dirty map is promoted to the read
			// map.
			m.missLocked()
		}
		m.mu.Unlock()
	}
	for ok {
		p := e.p.Load()
		if p == nil || p == expunged || *p != old {
			return false
		}
		if e.p.CompareAndSwap(p, nil) {
			return true
		}
	}
	return false
}

// Range calls f sequentially for each key and value present in the map.
// If f returns false, range stops the iteration.
//
// Range does not necessarily correspond to any consistent snapshot of the Map's
// contents: no key will be visited more than once, but if the value for any key
// is stored or deleted concurrently (including by f), Range may reflect any
// mapping for that key from any point during the Range call. Range does not
// block other methods on the receiver; even f itself may call any method on m.
//
// Range may be O(N) with the number of elements in the map even if f returns
// false after a constant number of calls.
func (m *Map) Range(f func(key, value any) bool) {
	// We need to be able to iterate over all of the keys that were already
	// present at the start of the call to Range.
	// If read.amended is false, then read.m satisfies that property without
	// requiring us to hold m.mu for a long time.
	read := m.loadReadOnly()
	if read.amended {
		// m.dirty contains keys not in read.m. Fortunately, Range is already O(N)
		// (assuming the caller does not break out early), so a call to Range
		// amortizes an entire copy of the map: we can promote the dirty copy
		// immediately!
		m.mu.Lock()
		read = m.loadReadOnly()
		if read.amended {
			read = readOnly{m: m.dirty}
			copyRead := read
			m.read.Store(&copyRead)
			m.dirty = nil
			m.misses = 0
		}
		m.mu.Unlock()
	}

	for k, e := range read.m {
		v, ok := e.load()
		if !ok {
			continue
		}
		if !f(k, v) {
			break
		}
	}
}

func (m *Map) missLocked() {
	m.misses++
	if m.misses < len(m.dirty) {
		return
	}
	m.read.Store(&readOnly{m: m.dirty})
	m.dirty = nil
	m.misses = 0
}

func (m *Map) dirtyLocked() {
	if m.dirty != nil {
		return
	}

	read := m.loadReadOnly()
	m.dirty = make(map[any]*entry, len(read.m))
	for k, e := range read.m {
		if !e.tryExpungeLocked() {
			m.dirty[k] = e
		}
	}
}

func (e *entry) tryExpungeLocked() (isExpunged bool) {
	p := e.p.Load()
	for p == nil {
		if e.p.CompareAndSwap(nil, expunged) {
			return true
		}
		p = e.p.Load()
	}
	return p == expunged
}

"""



```