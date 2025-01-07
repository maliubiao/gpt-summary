Response:
Let's break down the thought process for answering the user's request about the `hashtriemap.go` code.

**1. Understanding the Core Request:**

The user wants to understand the functionality of the provided Go code snippet. Specifically, they're asking for:

* **Functionality List:** A straightforward enumeration of what the code does.
* **Underlying Go Feature:**  An educated guess (and ideally confirmation) of what higher-level Go concept this code implements.
* **Code Examples:** Demonstrations of how to use the inferred Go feature.
* **Input/Output for Code Examples:** Clear illustration of the example's behavior.
* **Command-line Arguments:**  Information about relevant command-line options (unlikely here, but good to check).
* **Common Pitfalls:**  Potential mistakes users might make when using this type of data structure.
* **Language:** The response needs to be in Chinese.

**2. Initial Code Analysis (Skimming and Identifying Key Structures):**

The first step is to quickly read through the code, focusing on:

* **Package and Imports:** `package sync`, `internal/abi`, `internal/goarch`, `sync/atomic`, `unsafe`. This immediately suggests a low-level, concurrent data structure implementation. The `sync/atomic` package is a strong indicator of concurrency control.
* **Main Structure:** `HashTrieMap`. This is the central type and likely the core of the implementation. The type parameters `[K comparable, V any]` indicate it's a generic map.
* **Key Methods:** `Load`, `LoadOrStore`, `Store`, `Swap`, `CompareAndSwap`, `LoadAndDelete`, `Delete`, `CompareAndDelete`, `All`, `Range`, `Clear`. These method names strongly resemble the interface of standard Go maps and the `sync.Map`.
* **Internal Structures:** `indirect`, `entry`, `node`. These appear to be the building blocks of the hash trie data structure itself. The names suggest a hierarchical or tree-like organization.
* **`atomic.Pointer`:** Used extensively, confirming the concurrent nature of the implementation.
* **`Mutex`:** Present in the `indirect` structure, used for locking at certain levels.
* **`hashFunc`, `equalFunc`:** Indicate that custom hashing and equality functions are used.
* **Constants:** `nChildrenLog2`, `nChildren`, `nChildrenMask`. These likely define the branching factor of the trie.

**3. Forming Hypotheses and Connecting the Dots:**

Based on the initial analysis, the strongest hypothesis is that `HashTrieMap` is a **concurrent map implementation**. The method names are almost direct parallels to `sync.Map`. The use of a hash trie as the underlying data structure suggests an optimization for concurrent access and potentially large datasets.

**4. Elaborating on Functionality:**

Now, go through each of the public methods of `HashTrieMap` and describe what they do. This involves understanding the intent behind the method names and how they relate to map operations. For example:

* `Load`:  Clearly retrieves a value based on a key.
* `Store`: Sets a value for a key.
* `LoadOrStore`: A common concurrent map pattern.
* `Delete`: Removes a key-value pair.
* `CompareAndSwap`, `CompareAndDelete`: Atomic operations, essential for safe concurrency.
* `All`, `Range`:  Iteration methods.
* `Clear`: Empties the map.

**5. Crafting Code Examples:**

To illustrate the usage, provide simple, self-contained Go code snippets demonstrating the key operations. Crucially:

* **Focus on the essential methods:**  `Load`, `Store`, `LoadOrStore`, `Delete`.
* **Keep the examples short and easy to understand.**
* **Include sample input and expected output** (as comments or separate sections) to clearly show the effect of the code.
* **Make the examples realistic:**  Use concrete types for keys and values (e.g., `string`, `int`).

**6. Addressing Potential Pitfalls:**

Think about common mistakes developers make when working with concurrent data structures:

* **Forgetting to initialize:** The code has an `init()` method. Emphasize that the zero value is usable but might trigger initialization on first use.
* **Incorrect usage of `CompareAndSwap` and `CompareAndDelete`:** Highlight the requirement for comparable value types and the potential for failure if the value has changed concurrently.
* **Iteration behavior:** Explain that iterators don't provide a snapshot and concurrent modifications can affect the iteration.

**7. Considering Command-Line Arguments (and Recognizing Absence):**

Review the code for any handling of `os.Args` or similar mechanisms. In this case, the `HashTrieMap` is a library component and doesn't directly interact with command-line arguments. State this explicitly.

**8. Structuring and Formatting the Answer (in Chinese):**

Organize the information logically using headings and bullet points for readability. Translate the technical terms accurately into Chinese. Ensure the code examples are properly formatted.

**Self-Correction/Refinement During the Process:**

* **Initial thought:**  Is this just a reimplementation of `sync.Map`?  **Correction:** While similar in purpose, the underlying hash trie structure suggests a focus on different performance characteristics. Mention this distinction.
* **Code Example Simplicity:**  Am I making the examples too complex? **Correction:**  Simplify the examples to focus on the core functionality being demonstrated.
* **Clarity of Pitfalls:** Are the common mistakes clearly explained? **Correction:**  Provide specific examples or scenarios to illustrate the potential problems.

By following this structured approach, combining code analysis with knowledge of concurrent data structures and Go best practices, it's possible to generate a comprehensive and helpful answer to the user's request.
这段代码是 Go 语言中 `sync` 包内部 `hashtriemap.go` 文件的一部分，它实现了一个 **并发安全的哈希树形映射（Concurrent Hash Trie Map）**。

**功能列表:**

1. **并发安全的键值存储:** 允许在多个 Goroutine 中安全地进行键值对的存储和访问。
2. **高效的读取操作:**  `Load` 方法被设计为快速读取，这是该数据结构的主要优化目标。
3. **支持多种原子操作:** 提供了 `LoadOrStore` (加载或存储), `Swap` (交换), `CompareAndSwap` (比较并交换), `LoadAndDelete` (加载并删除), `Delete` (删除), `CompareAndDelete` (比较并删除) 等原子操作，确保并发修改的安全性。
4. **支持迭代:** 提供了 `All` 和 `Range` 方法来遍历 Map 中的所有键值对。
5. **支持清空:** `Clear` 方法可以删除 Map 中的所有条目。
6. **延迟初始化:**  通过 `inited` 原子变量和 `initMu` 互斥锁实现延迟初始化，只有在第一次使用时才会进行初始化。
7. **使用哈希树结构:**  内部使用哈希树（Hash Trie）作为底层数据结构，通过哈希值分层查找，提高了并发性能。
8. **处理哈希冲突:** 使用链表（overflow）来处理哈希冲突。
9. **可配置的子节点数量:**  通过 `nChildrenLog2` 等常量定义了哈希树每个节点的子节点数量（默认为 16）。

**推断 Go 语言功能实现：并发安全的 Map**

`HashTrieMap` 的功能和 `sync.Map` 非常相似，都是为了提供一个并发安全的键值存储。但是，它们的底层实现有所不同。`sync.Map` 使用了读写互斥锁和原子操作的组合，而 `HashTrieMap` 则使用了哈希树结构和更细粒度的锁（在 `indirect` 节点中）。

**Go 代码示例 (模拟 `sync.Map` 的用法):**

```go
package main

import (
	"fmt"
	"internal/sync"
	"sync/atomic"
)

func main() {
	var ht sync.HashTrieMap[string, int]

	// 存储键值对
	ht.Store("apple", 1)
	ht.Store("banana", 2)

	// 加载值
	value, ok := ht.Load("apple")
	fmt.Printf("Load(\"apple\"): value=%d, ok=%t\n", value, ok) // 输出: Load("apple"): value=1, ok=true

	value, ok = ht.Load("orange")
	fmt.Printf("Load(\"orange\"): value=%d, ok=%t\n", value, ok) // 输出: Load("orange"): value=0, ok=false

	// 加载或存储
	actual, loaded := ht.LoadOrStore("grape", 3)
	fmt.Printf("LoadOrStore(\"grape\", 3): actual=%d, loaded=%t\n", actual, loaded) // 输出: LoadOrStore("grape", 3): actual=3, loaded=false

	actual, loaded = ht.LoadOrStore("apple", 4)
	fmt.Printf("LoadOrStore(\"apple\", 4): actual=%d, loaded=%t\n", actual, loaded) // 输出: LoadOrStore("apple", 4): actual=1, loaded=true

	// 删除键值对
	ht.Delete("banana")
	_, ok = ht.Load("banana")
	fmt.Printf("Load(\"banana\") after Delete: ok=%t\n", ok) // 输出: Load("banana") after Delete: ok=false

	// 遍历所有键值对
	ht.Range(func(key string, value int) bool {
		fmt.Printf("Range: key=%s, value=%d\n", key, value)
		return true
	})
	// 可能输出:
	// Range: key=apple, value=1
	// Range: key=grape, value=3

	// 清空 Map
	ht.Clear()
	ht.Range(func(key string, value int) bool {
		fmt.Printf("Range after Clear: key=%s, value=%d\n", key, value)
		return true
	}) // 无输出

	// CompareAndSwap 示例
	var ht2 sync.HashTrieMap[string, *int]
	initialValue := 10
	ht2.Store("number", &initialValue)

	newValue := 20
	swapped := ht2.CompareAndSwap("number", &initialValue, &newValue)
	fmt.Printf("CompareAndSwap(\"number\", %d, %d): swapped=%t\n", initialValue, newValue, swapped) // 输出: CompareAndSwap("number", 10, 20): swapped=true

	loadedValue, _ := ht2.Load("number")
	fmt.Printf("Value after CompareAndSwap: %d\n", *loadedValue) // 输出: Value after CompareAndSwap: 20

	wrongOldValue := 30
	swapped = ht2.CompareAndSwap("number", &wrongOldValue, &newValue)
	fmt.Printf("CompareAndSwap(\"number\", %d, %d): swapped=%t\n", wrongOldValue, newValue, swapped) // 输出: CompareAndSwap("number", 30, 20): swapped=false

}
```

**假设的输入与输出:**

上面的代码示例中已经包含了假设的输出，这些输出是基于代码逻辑的推断。

**命令行参数的具体处理:**

这段代码本身是一个库的实现，并不直接处理命令行参数。它是在其他 Go 程序中被引用的。

**使用者易犯错的点:**

1. **未初始化直接使用:**  虽然 `HashTrieMap` 的零值是可用的，但内部需要在第一次使用时进行初始化。在并发场景下，过早地并发访问未初始化的 Map 可能会导致竞争条件。尽管代码中通过 `init()` 方法和互斥锁进行了保护，但理解其初始化机制仍然重要。

2. **`CompareAndSwap` 和 `CompareAndDelete` 的值类型要求:**  `CompareAndSwap` 和 `CompareAndDelete` 方法依赖于值的可比较性。如果值类型不可比较，调用这些方法将会导致 panic。

   ```go
   package main

   import (
   	"fmt"
   	"internal/sync"
   )

   type NotComparable struct {
   	data []int
   }

   func main() {
   	var ht sync.HashTrieMap[string, NotComparable]
   	nc1 := NotComparable{data: []int{1, 2}}
   	nc2 := NotComparable{data: []int{1, 2}}

   	ht.Store("test", nc1)
   	// ht.CompareAndSwap("test", nc1, nc2) // 会 panic: called CompareAndSwap when value is not of comparable type
   	fmt.Println("程序继续运行")
   }
   ```

3. **迭代器的快照隔离:** `All` 和 `Range` 方法返回的迭代器**不提供快照隔离**。这意味着在迭代过程中，如果其他 Goroutine 修改了 Map，迭代器可能会观察到这些修改。例如，可能在一次迭代中访问到同一个键的不同值，或者跳过某些新插入的键。使用者需要意识到这一点，尤其是在迭代过程中进行修改时。

4. **对指针类型值的 `CompareAndSwap` 的理解:** 当使用 `CompareAndSwap` 比较指针类型的值时，比较的是指针的地址，而不是指针指向的实际值是否相等。如果需要比较指针指向的值，需要确保传入 `CompareAndSwap` 的 `old` 参数是当前 Map 中存储的**同一个指针**。在上面的代码示例中，我们展示了如何正确地使用 `CompareAndSwap` 和指针。

了解这些细节可以帮助使用者更安全、更有效地使用 `HashTrieMap`。

Prompt: 
```
这是路径为go/src/internal/sync/hashtriemap.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。

"""
// Copyright 2024 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package sync

import (
	"internal/abi"
	"internal/goarch"
	"sync/atomic"
	"unsafe"
)

// HashTrieMap is an implementation of a concurrent hash-trie. The implementation
// is designed around frequent loads, but offers decent performance for stores
// and deletes as well, especially if the map is larger. Its primary use-case is
// the unique package, but can be used elsewhere as well.
//
// The zero HashTrieMap is empty and ready to use.
// It must not be copied after first use.
type HashTrieMap[K comparable, V any] struct {
	inited   atomic.Uint32
	initMu   Mutex
	root     atomic.Pointer[indirect[K, V]]
	keyHash  hashFunc
	valEqual equalFunc
	seed     uintptr
}

func (ht *HashTrieMap[K, V]) init() {
	if ht.inited.Load() == 0 {
		ht.initSlow()
	}
}

//go:noinline
func (ht *HashTrieMap[K, V]) initSlow() {
	ht.initMu.Lock()
	defer ht.initMu.Unlock()

	if ht.inited.Load() != 0 {
		// Someone got to it while we were waiting.
		return
	}

	// Set up root node, derive the hash function for the key, and the
	// equal function for the value, if any.
	var m map[K]V
	mapType := abi.TypeOf(m).MapType()
	ht.root.Store(newIndirectNode[K, V](nil))
	ht.keyHash = mapType.Hasher
	ht.valEqual = mapType.Elem.Equal
	ht.seed = uintptr(runtime_rand())

	ht.inited.Store(1)
}

type hashFunc func(unsafe.Pointer, uintptr) uintptr
type equalFunc func(unsafe.Pointer, unsafe.Pointer) bool

// Load returns the value stored in the map for a key, or nil if no
// value is present.
// The ok result indicates whether value was found in the map.
func (ht *HashTrieMap[K, V]) Load(key K) (value V, ok bool) {
	ht.init()
	hash := ht.keyHash(abi.NoEscape(unsafe.Pointer(&key)), ht.seed)

	i := ht.root.Load()
	hashShift := 8 * goarch.PtrSize
	for hashShift != 0 {
		hashShift -= nChildrenLog2

		n := i.children[(hash>>hashShift)&nChildrenMask].Load()
		if n == nil {
			return *new(V), false
		}
		if n.isEntry {
			return n.entry().lookup(key)
		}
		i = n.indirect()
	}
	panic("internal/concurrent.HashMapTrie: ran out of hash bits while iterating")
}

// LoadOrStore returns the existing value for the key if present.
// Otherwise, it stores and returns the given value.
// The loaded result is true if the value was loaded, false if stored.
func (ht *HashTrieMap[K, V]) LoadOrStore(key K, value V) (result V, loaded bool) {
	ht.init()
	hash := ht.keyHash(abi.NoEscape(unsafe.Pointer(&key)), ht.seed)
	var i *indirect[K, V]
	var hashShift uint
	var slot *atomic.Pointer[node[K, V]]
	var n *node[K, V]
	for {
		// Find the key or a candidate location for insertion.
		i = ht.root.Load()
		hashShift = 8 * goarch.PtrSize
		haveInsertPoint := false
		for hashShift != 0 {
			hashShift -= nChildrenLog2

			slot = &i.children[(hash>>hashShift)&nChildrenMask]
			n = slot.Load()
			if n == nil {
				// We found a nil slot which is a candidate for insertion.
				haveInsertPoint = true
				break
			}
			if n.isEntry {
				// We found an existing entry, which is as far as we can go.
				// If it stays this way, we'll have to replace it with an
				// indirect node.
				if v, ok := n.entry().lookup(key); ok {
					return v, true
				}
				haveInsertPoint = true
				break
			}
			i = n.indirect()
		}
		if !haveInsertPoint {
			panic("internal/concurrent.HashMapTrie: ran out of hash bits while iterating")
		}

		// Grab the lock and double-check what we saw.
		i.mu.Lock()
		n = slot.Load()
		if (n == nil || n.isEntry) && !i.dead.Load() {
			// What we saw is still true, so we can continue with the insert.
			break
		}
		// We have to start over.
		i.mu.Unlock()
	}
	// N.B. This lock is held from when we broke out of the outer loop above.
	// We specifically break this out so that we can use defer here safely.
	// One option is to break this out into a new function instead, but
	// there's so much local iteration state used below that this turns out
	// to be cleaner.
	defer i.mu.Unlock()

	var oldEntry *entry[K, V]
	if n != nil {
		oldEntry = n.entry()
		if v, ok := oldEntry.lookup(key); ok {
			// Easy case: by loading again, it turns out exactly what we wanted is here!
			return v, true
		}
	}
	newEntry := newEntryNode(key, value)
	if oldEntry == nil {
		// Easy case: create a new entry and store it.
		slot.Store(&newEntry.node)
	} else {
		// We possibly need to expand the entry already there into one or more new nodes.
		//
		// Publish the node last, which will make both oldEntry and newEntry visible. We
		// don't want readers to be able to observe that oldEntry isn't in the tree.
		slot.Store(ht.expand(oldEntry, newEntry, hash, hashShift, i))
	}
	return value, false
}

// expand takes oldEntry and newEntry whose hashes conflict from bit 64 down to hashShift and
// produces a subtree of indirect nodes to hold the two new entries.
func (ht *HashTrieMap[K, V]) expand(oldEntry, newEntry *entry[K, V], newHash uintptr, hashShift uint, parent *indirect[K, V]) *node[K, V] {
	// Check for a hash collision.
	oldHash := ht.keyHash(unsafe.Pointer(&oldEntry.key), ht.seed)
	if oldHash == newHash {
		// Store the old entry in the new entry's overflow list, then store
		// the new entry.
		newEntry.overflow.Store(oldEntry)
		return &newEntry.node
	}
	// We have to add an indirect node. Worse still, we may need to add more than one.
	newIndirect := newIndirectNode(parent)
	top := newIndirect
	for {
		if hashShift == 0 {
			panic("internal/concurrent.HashMapTrie: ran out of hash bits while inserting")
		}
		hashShift -= nChildrenLog2 // hashShift is for the level parent is at. We need to go deeper.
		oi := (oldHash >> hashShift) & nChildrenMask
		ni := (newHash >> hashShift) & nChildrenMask
		if oi != ni {
			newIndirect.children[oi].Store(&oldEntry.node)
			newIndirect.children[ni].Store(&newEntry.node)
			break
		}
		nextIndirect := newIndirectNode(newIndirect)
		newIndirect.children[oi].Store(&nextIndirect.node)
		newIndirect = nextIndirect
	}
	return &top.node
}

// Store sets the value for a key.
func (ht *HashTrieMap[K, V]) Store(key K, old V) {
	_, _ = ht.Swap(key, old)
}

// Swap swaps the value for a key and returns the previous value if any.
// The loaded result reports whether the key was present.
func (ht *HashTrieMap[K, V]) Swap(key K, new V) (previous V, loaded bool) {
	ht.init()
	hash := ht.keyHash(abi.NoEscape(unsafe.Pointer(&key)), ht.seed)
	var i *indirect[K, V]
	var hashShift uint
	var slot *atomic.Pointer[node[K, V]]
	var n *node[K, V]
	for {
		// Find the key or a candidate location for insertion.
		i = ht.root.Load()
		hashShift = 8 * goarch.PtrSize
		haveInsertPoint := false
		for hashShift != 0 {
			hashShift -= nChildrenLog2

			slot = &i.children[(hash>>hashShift)&nChildrenMask]
			n = slot.Load()
			if n == nil {
				// We found a nil slot which is a candidate for insertion,
				// or an existing entry that we'll replace.
				haveInsertPoint = true
				break
			}
			if n.isEntry {
				// Swap if the keys compare.
				old, swapped := n.entry().swap(key, new)
				if swapped {
					return old, true
				}
				// If we fail, that means we should try to insert.
				haveInsertPoint = true
				break
			}
			i = n.indirect()
		}
		if !haveInsertPoint {
			panic("internal/concurrent.HashMapTrie: ran out of hash bits while iterating")
		}

		// Grab the lock and double-check what we saw.
		i.mu.Lock()
		n = slot.Load()
		if (n == nil || n.isEntry) && !i.dead.Load() {
			// What we saw is still true, so we can continue with the insert.
			break
		}
		// We have to start over.
		i.mu.Unlock()
	}
	// N.B. This lock is held from when we broke out of the outer loop above.
	// We specifically break this out so that we can use defer here safely.
	// One option is to break this out into a new function instead, but
	// there's so much local iteration state used below that this turns out
	// to be cleaner.
	defer i.mu.Unlock()

	var zero V
	var oldEntry *entry[K, V]
	if n != nil {
		// Between before and now, something got inserted. Swap if the keys compare.
		oldEntry = n.entry()
		old, swapped := oldEntry.swap(key, new)
		if swapped {
			return old, true
		}
	}
	// The keys didn't compare, so we're doing an insertion.
	newEntry := newEntryNode(key, new)
	if oldEntry == nil {
		// Easy case: create a new entry and store it.
		slot.Store(&newEntry.node)
	} else {
		// We possibly need to expand the entry already there into one or more new nodes.
		//
		// Publish the node last, which will make both oldEntry and newEntry visible. We
		// don't want readers to be able to observe that oldEntry isn't in the tree.
		slot.Store(ht.expand(oldEntry, newEntry, hash, hashShift, i))
	}
	return zero, false
}

// CompareAndSwap swaps the old and new values for key
// if the value stored in the map is equal to old.
// The value type must be of a comparable type, otherwise CompareAndSwap will panic.
func (ht *HashTrieMap[K, V]) CompareAndSwap(key K, old, new V) (swapped bool) {
	ht.init()
	if ht.valEqual == nil {
		panic("called CompareAndSwap when value is not of comparable type")
	}
	hash := ht.keyHash(abi.NoEscape(unsafe.Pointer(&key)), ht.seed)
	for {
		// Find the key or return if it's not there.
		i := ht.root.Load()
		hashShift := 8 * goarch.PtrSize
		found := false
		for hashShift != 0 {
			hashShift -= nChildrenLog2

			slot := &i.children[(hash>>hashShift)&nChildrenMask]
			n := slot.Load()
			if n == nil {
				// Nothing to compare with. Give up.
				return false
			}
			if n.isEntry {
				// We found an entry. Try to compare and swap directly.
				return n.entry().compareAndSwap(key, old, new, ht.valEqual)
			}
			i = n.indirect()
		}
		if !found {
			panic("internal/concurrent.HashMapTrie: ran out of hash bits while iterating")
		}
	}
}

// LoadAndDelete deletes the value for a key, returning the previous value if any.
// The loaded result reports whether the key was present.
func (ht *HashTrieMap[K, V]) LoadAndDelete(key K) (value V, loaded bool) {
	ht.init()
	hash := ht.keyHash(abi.NoEscape(unsafe.Pointer(&key)), ht.seed)

	// Find a node with the key and compare with it. n != nil if we found the node.
	i, hashShift, slot, n := ht.find(key, hash, nil, *new(V))
	if n == nil {
		if i != nil {
			i.mu.Unlock()
		}
		return *new(V), false
	}

	// Try to delete the entry.
	v, e, loaded := n.entry().loadAndDelete(key)
	if !loaded {
		// Nothing was actually deleted, which means the node is no longer there.
		i.mu.Unlock()
		return *new(V), false
	}
	if e != nil {
		// We didn't actually delete the whole entry, just one entry in the chain.
		// Nothing else to do, since the parent is definitely not empty.
		slot.Store(&e.node)
		i.mu.Unlock()
		return v, true
	}
	// Delete the entry.
	slot.Store(nil)

	// Check if the node is now empty (and isn't the root), and delete it if able.
	for i.parent != nil && i.empty() {
		if hashShift == 8*goarch.PtrSize {
			panic("internal/concurrent.HashMapTrie: ran out of hash bits while iterating")
		}
		hashShift += nChildrenLog2

		// Delete the current node in the parent.
		parent := i.parent
		parent.mu.Lock()
		i.dead.Store(true)
		parent.children[(hash>>hashShift)&nChildrenMask].Store(nil)
		i.mu.Unlock()
		i = parent
	}
	i.mu.Unlock()
	return v, true
}

// Delete deletes the value for a key.
func (ht *HashTrieMap[K, V]) Delete(key K) {
	_, _ = ht.LoadAndDelete(key)
}

// CompareAndDelete deletes the entry for key if its value is equal to old.
// The value type must be comparable, otherwise this CompareAndDelete will panic.
//
// If there is no current value for key in the map, CompareAndDelete returns false
// (even if the old value is the nil interface value).
func (ht *HashTrieMap[K, V]) CompareAndDelete(key K, old V) (deleted bool) {
	ht.init()
	if ht.valEqual == nil {
		panic("called CompareAndDelete when value is not of comparable type")
	}
	hash := ht.keyHash(abi.NoEscape(unsafe.Pointer(&key)), ht.seed)

	// Find a node with the key. n != nil if we found the node.
	i, hashShift, slot, n := ht.find(key, hash, nil, *new(V))
	if n == nil {
		if i != nil {
			i.mu.Unlock()
		}
		return false
	}

	// Try to delete the entry.
	e, deleted := n.entry().compareAndDelete(key, old, ht.valEqual)
	if !deleted {
		// Nothing was actually deleted, which means the node is no longer there.
		i.mu.Unlock()
		return false
	}
	if e != nil {
		// We didn't actually delete the whole entry, just one entry in the chain.
		// Nothing else to do, since the parent is definitely not empty.
		slot.Store(&e.node)
		i.mu.Unlock()
		return true
	}
	// Delete the entry.
	slot.Store(nil)

	// Check if the node is now empty (and isn't the root), and delete it if able.
	for i.parent != nil && i.empty() {
		if hashShift == 8*goarch.PtrSize {
			panic("internal/concurrent.HashMapTrie: ran out of hash bits while iterating")
		}
		hashShift += nChildrenLog2

		// Delete the current node in the parent.
		parent := i.parent
		parent.mu.Lock()
		i.dead.Store(true)
		parent.children[(hash>>hashShift)&nChildrenMask].Store(nil)
		i.mu.Unlock()
		i = parent
	}
	i.mu.Unlock()
	return true
}

// find searches the tree for a node that contains key (hash must be the hash of key).
// If valEqual != nil, then it will also enforce that the values are equal as well.
//
// Returns a non-nil node, which will always be an entry, if found.
//
// If i != nil then i.mu is locked, and it is the caller's responsibility to unlock it.
func (ht *HashTrieMap[K, V]) find(key K, hash uintptr, valEqual equalFunc, value V) (i *indirect[K, V], hashShift uint, slot *atomic.Pointer[node[K, V]], n *node[K, V]) {
	for {
		// Find the key or return if it's not there.
		i = ht.root.Load()
		hashShift = 8 * goarch.PtrSize
		found := false
		for hashShift != 0 {
			hashShift -= nChildrenLog2

			slot = &i.children[(hash>>hashShift)&nChildrenMask]
			n = slot.Load()
			if n == nil {
				// Nothing to compare with. Give up.
				i = nil
				return
			}
			if n.isEntry {
				// We found an entry. Check if it matches.
				if _, ok := n.entry().lookupWithValue(key, value, valEqual); !ok {
					// No match, comparison failed.
					i = nil
					n = nil
					return
				}
				// We've got a match. Prepare to perform an operation on the key.
				found = true
				break
			}
			i = n.indirect()
		}
		if !found {
			panic("internal/concurrent.HashMapTrie: ran out of hash bits while iterating")
		}

		// Grab the lock and double-check what we saw.
		i.mu.Lock()
		n = slot.Load()
		if !i.dead.Load() && (n == nil || n.isEntry) {
			// Either we've got a valid node or the node is now nil under the lock.
			// In either case, we're done here.
			return
		}
		// We have to start over.
		i.mu.Unlock()
	}
}

// All returns an iterator over each key and value present in the map.
//
// The iterator does not necessarily correspond to any consistent snapshot of the
// HashTrieMap's contents: no key will be visited more than once, but if the value
// for any key is stored or deleted concurrently (including by yield), the iterator
// may reflect any mapping for that key from any point during iteration. The iterator
// does not block other methods on the receiver; even yield itself may call any
// method on the HashTrieMap.
func (ht *HashTrieMap[K, V]) All() func(yield func(K, V) bool) {
	ht.init()
	return func(yield func(key K, value V) bool) {
		ht.iter(ht.root.Load(), yield)
	}
}

// Range calls f sequentially for each key and value present in the map.
// If f returns false, range stops the iteration.
//
// This exists for compatibility with sync.Map; All should be preferred.
// It provides the same guarantees as sync.Map, and All.
func (ht *HashTrieMap[K, V]) Range(yield func(K, V) bool) {
	ht.init()
	ht.iter(ht.root.Load(), yield)
}

func (ht *HashTrieMap[K, V]) iter(i *indirect[K, V], yield func(key K, value V) bool) bool {
	for j := range i.children {
		n := i.children[j].Load()
		if n == nil {
			continue
		}
		if !n.isEntry {
			if !ht.iter(n.indirect(), yield) {
				return false
			}
			continue
		}
		e := n.entry()
		for e != nil {
			if !yield(e.key, *e.value.Load()) {
				return false
			}
			e = e.overflow.Load()
		}
	}
	return true
}

// Clear deletes all the entries, resulting in an empty HashTrieMap.
func (ht *HashTrieMap[K, V]) Clear() {
	ht.init()

	// It's sufficient to just drop the root on the floor, but the root
	// must always be non-nil.
	ht.root.Store(newIndirectNode[K, V](nil))
}

const (
	// 16 children. This seems to be the sweet spot for
	// load performance: any smaller and we lose out on
	// 50% or more in CPU performance. Any larger and the
	// returns are minuscule (~1% improvement for 32 children).
	nChildrenLog2 = 4
	nChildren     = 1 << nChildrenLog2
	nChildrenMask = nChildren - 1
)

// indirect is an internal node in the hash-trie.
type indirect[K comparable, V any] struct {
	node[K, V]
	dead     atomic.Bool
	mu       Mutex // Protects mutation to children and any children that are entry nodes.
	parent   *indirect[K, V]
	children [nChildren]atomic.Pointer[node[K, V]]
}

func newIndirectNode[K comparable, V any](parent *indirect[K, V]) *indirect[K, V] {
	return &indirect[K, V]{node: node[K, V]{isEntry: false}, parent: parent}
}

func (i *indirect[K, V]) empty() bool {
	nc := 0
	for j := range i.children {
		if i.children[j].Load() != nil {
			nc++
		}
	}
	return nc == 0
}

// entry is a leaf node in the hash-trie.
type entry[K comparable, V any] struct {
	node[K, V]
	overflow atomic.Pointer[entry[K, V]] // Overflow for hash collisions.
	key      K
	value    atomic.Pointer[V]
}

func newEntryNode[K comparable, V any](key K, value V) *entry[K, V] {
	e := &entry[K, V]{
		node: node[K, V]{isEntry: true},
		key:  key,
	}
	e.value.Store(&value)
	return e
}

func (e *entry[K, V]) lookup(key K) (V, bool) {
	for e != nil {
		if e.key == key {
			return *e.value.Load(), true
		}
		e = e.overflow.Load()
	}
	return *new(V), false
}

func (e *entry[K, V]) lookupWithValue(key K, value V, valEqual equalFunc) (V, bool) {
	for e != nil {
		oldp := e.value.Load()
		if e.key == key && (valEqual == nil || valEqual(unsafe.Pointer(oldp), abi.NoEscape(unsafe.Pointer(&value)))) {
			return *oldp, true
		}
		e = e.overflow.Load()
	}
	return *new(V), false
}

// swap replaces a value in the overflow chain if keys compare equal.
// Returns the old value, and whether or not anything was swapped.
//
// swap must be called under the mutex of the indirect node which e is a child of.
func (head *entry[K, V]) swap(key K, newv V) (V, bool) {
	if head.key == key {
		vp := new(V)
		*vp = newv
		oldp := head.value.Swap(vp)
		return *oldp, true
	}
	i := &head.overflow
	e := i.Load()
	for e != nil {
		if e.key == key {
			vp := new(V)
			*vp = newv
			oldp := e.value.Swap(vp)
			return *oldp, true
		}
		i = &e.overflow
		e = e.overflow.Load()
	}
	var zero V
	return zero, false
}

// compareAndSwap replaces a value for a matching key and existing value in the overflow chain.
// Returns whether or not anything was swapped.
//
// compareAndSwap must be called under the mutex of the indirect node which e is a child of.
func (head *entry[K, V]) compareAndSwap(key K, oldv, newv V, valEqual equalFunc) bool {
	var vbox *V
outerLoop:
	for {
		oldvp := head.value.Load()
		if head.key == key && valEqual(unsafe.Pointer(oldvp), abi.NoEscape(unsafe.Pointer(&oldv))) {
			// Return the new head of the list.
			if vbox == nil {
				// Delay explicit creation of a new value to hold newv. If we just pass &newv
				// to CompareAndSwap, then newv will unconditionally escape, even if the CAS fails.
				vbox = new(V)
				*vbox = newv
			}
			if head.value.CompareAndSwap(oldvp, vbox) {
				return true
			}
			// We need to restart from the head of the overflow list in case, due to a removal, a node
			// is moved up the list and we miss it.
			continue outerLoop
		}
		i := &head.overflow
		e := i.Load()
		for e != nil {
			oldvp := e.value.Load()
			if e.key == key && valEqual(unsafe.Pointer(oldvp), abi.NoEscape(unsafe.Pointer(&oldv))) {
				if vbox == nil {
					// Delay explicit creation of a new value to hold newv. If we just pass &newv
					// to CompareAndSwap, then newv will unconditionally escape, even if the CAS fails.
					vbox = new(V)
					*vbox = newv
				}
				if e.value.CompareAndSwap(oldvp, vbox) {
					return true
				}
				continue outerLoop
			}
			i = &e.overflow
			e = e.overflow.Load()
		}
		return false
	}
}

// loadAndDelete deletes an entry in the overflow chain by key. Returns the value for the key, the new
// entry chain and whether or not anything was loaded (and deleted).
//
// loadAndDelete must be called under the mutex of the indirect node which e is a child of.
func (head *entry[K, V]) loadAndDelete(key K) (V, *entry[K, V], bool) {
	if head.key == key {
		// Drop the head of the list.
		return *head.value.Load(), head.overflow.Load(), true
	}
	i := &head.overflow
	e := i.Load()
	for e != nil {
		if e.key == key {
			i.Store(e.overflow.Load())
			return *e.value.Load(), head, true
		}
		i = &e.overflow
		e = e.overflow.Load()
	}
	return *new(V), head, false
}

// compareAndDelete deletes an entry in the overflow chain if both the key and value compare
// equal. Returns the new entry chain and whether or not anything was deleted.
//
// compareAndDelete must be called under the mutex of the indirect node which e is a child of.
func (head *entry[K, V]) compareAndDelete(key K, value V, valEqual equalFunc) (*entry[K, V], bool) {
	if head.key == key && valEqual(unsafe.Pointer(head.value.Load()), abi.NoEscape(unsafe.Pointer(&value))) {
		// Drop the head of the list.
		return head.overflow.Load(), true
	}
	i := &head.overflow
	e := i.Load()
	for e != nil {
		if e.key == key && valEqual(unsafe.Pointer(e.value.Load()), abi.NoEscape(unsafe.Pointer(&value))) {
			i.Store(e.overflow.Load())
			return head, true
		}
		i = &e.overflow
		e = e.overflow.Load()
	}
	return head, false
}

// node is the header for a node. It's polymorphic and
// is actually either an entry or an indirect.
type node[K comparable, V any] struct {
	isEntry bool
}

func (n *node[K, V]) entry() *entry[K, V] {
	if !n.isEntry {
		panic("called entry on non-entry node")
	}
	return (*entry[K, V])(unsafe.Pointer(n))
}

func (n *node[K, V]) indirect() *indirect[K, V] {
	if n.isEntry {
		panic("called indirect on entry node")
	}
	return (*indirect[K, V])(unsafe.Pointer(n))
}

// Pull in runtime.rand so that we don't need to take a dependency
// on math/rand/v2.
//
//go:linkname runtime_rand runtime.rand
func runtime_rand() uint64

"""



```