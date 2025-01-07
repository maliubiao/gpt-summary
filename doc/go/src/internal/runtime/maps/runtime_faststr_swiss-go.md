Response:
Let's break down the thought process to analyze the provided Go code snippet.

1. **Understand the Goal:** The request is to analyze a Go file related to maps, specifically focusing on its functionality, potential use cases, example code, command-line arguments (if any), and common mistakes.

2. **Initial Scan for Keywords and Context:**  The first step is to quickly scan the code for relevant keywords. I see:
    * `//go:build goexperiment.swissmap`:  This immediately tells me this is an experimental feature, hinting that the underlying map implementation is different from the standard Go map. The "swissmap" name is a strong clue.
    * `package maps`: This confirms it's part of the internal `maps` package, likely for map implementation details.
    * `import`: The imported packages (`internal/abi`, `internal/goarch`, `internal/race`, `internal/runtime/sys`, `unsafe`) are all internal runtime or low-level packages. This reinforces the idea that this code deals with the core map implementation.
    * Function names like `getWithoutKeySmallFastStr`, `runtime_mapaccess1_faststr`, `runtime_mapaccess2_faststr`, `runtime_mapassign_faststr`, `runtime_mapdelete_faststr`: These clearly relate to map operations (access, assignment, deletion). The `faststr` suffix suggests optimizations for string keys.
    * `string`:  The frequent use of `string` as a key type stands out.
    * `hash`, `Hasher`, `h1`, `h2`:  Hashing is central to map implementations.
    * `ctrls`, `groupReference`: These likely represent internal structures for managing map buckets or groups.
    * `growToSmall`, `growToTable`, `rehash`:  These indicate mechanisms for resizing the map as it grows.
    * `race.Enabled`, `m.writing`:  These point to concurrency control and race detection.

3. **Identify Core Functionality:** Based on the function names, I can deduce the primary functionalities:
    * **`getWithoutKeySmallFastStr`**:  Looks up a string key in a "small" map (likely an optimization for small maps where separate directory structures might not be needed). It includes a "quick equality test" for long strings.
    * **`runtime_mapaccess1_faststr` and `runtime_mapaccess2_faststr`**:  Implement map access (reading values). The `1` and `2` likely correspond to the single-return (value) and two-return (value, ok) forms of map access in Go.
    * **`runtime_mapassign_faststr`**:  Implements map assignment (writing/inserting values).
    * **`runtime_mapdelete_faststr`**: Implements map deletion.

4. **Infer the "Swiss Map" Concept:**  The "swissmap" experiment name, combined with the code's structure (groups, control bytes), suggests this is likely an implementation of the Swiss Table data structure, known for its efficiency. The control bytes (`ctrls`) are a key characteristic of Swiss Tables, used for metadata about the slots in a group.

5. **Illustrative Go Code Example:**  To demonstrate the functionality, I need to show how a Go map with string keys would be used. This is straightforward:

   ```go
   package main

   func main() {
       m := make(map[string]int) // Or map[string]string, etc.
       m["hello"] = 1
       val, ok := m["hello"]
       println(val, ok)
       delete(m, "hello")
   }
   ```

   The key here is to connect the *internal* functions in the snippet to the *user-level* map operations in standard Go. The provided code snippet is *how* these user-level operations are implemented when the `goexperiment.swissmap` build tag is used.

6. **Code Reasoning (with Assumptions and I/O):** The `getWithoutKeySmallFastStr` function is interesting. Let's reason about it:

   * **Assumption:** A small map is being accessed, and the key is a string.
   * **Input:** A `Map` structure (`m`), a `SwissMapType` (`typ`), and a string `key`.
   * **Logic:** It iterates through the slots in a group, checking control bytes and then comparing keys. The `longStringQuickEqualityTest` is a pre-filter.
   * **Output:** A `unsafe.Pointer` to the value associated with the key, or `nil` if the key is not found.

   I can create a simple mental model of how this function works with a short example, even without knowing the exact bit layout of the `Map` structure.

7. **Command-Line Arguments:** The provided code doesn't directly handle command-line arguments. The `//go:build goexperiment.swissmap` line indicates a build tag, not a runtime flag. The way to enable this is through the `go build` command: `go build -tags=goexperiment.swissmap main.go`. It's important to explain how build tags work.

8. **Common Mistakes:**  Thinking about how users interact with maps, the most common mistakes are related to concurrency:

   * **Concurrent access without proper synchronization:**  Go's built-in maps are not safe for concurrent writes. The code itself has checks for `m.writing`. I can demonstrate this with a simple example involving goroutines.
   * **Nil map access:** Trying to access an element of a `nil` map will panic. This is a basic Go concept, but worth mentioning.

9. **Structuring the Answer:**  Finally, I organize the findings into a clear and structured answer using the headings provided in the prompt. I start with the basic functionality, then move to the more complex aspects like code reasoning and potential pitfalls. Using code blocks and clear explanations is crucial. I also ensure to use Chinese as requested.

**Self-Correction/Refinement during the process:**

* Initially, I might have focused too much on the low-level details of the `Map` structure. I need to shift focus to the *user-observable behavior* and how these internal functions support that.
* I need to clearly distinguish between the experimental nature of this code and the standard Go map behavior.
* The explanation of build tags is important because it's the mechanism to enable this specific implementation.
* When providing examples, keep them simple and directly relevant to the points being made.

By following these steps, I can effectively analyze the provided Go code snippet and generate a comprehensive and informative answer.
这段代码是 Go 语言运行时（runtime）中 `maps` 包的一部分，专门针对 **键类型为字符串的快速查找** 进行了优化的实现，并且是基于一个实验性的特性 `goexperiment.swissmap`（瑞士表）。

下面我将分点列举其功能，并尝试推理其实现，用 Go 代码举例说明，并解释相关概念。

**功能列举：**

1. **快速字符串键查找 (`getWithoutKeySmallFastStr`, `runtime_mapaccess1_faststr`, `runtime_mapaccess2_faststr`)**: 提供了高效的方式来查找 map 中是否存在指定的字符串键，并返回对应的值（或值和布尔表示是否存在）。  `faststr` 后缀表明这是针对字符串键的优化版本。
2. **快速字符串键赋值 (`runtime_mapassign_faststr`)**:  实现了向 map 中添加或更新字符串键值对的功能。
3. **快速字符串键删除 (`runtime_mapdelete_faststr`)**: 实现了从 map 中删除指定字符串键值对的功能。
4. **小 map 优化 (`getWithoutKeySmallFastStr`, `putSlotSmallFastStr`)**:  针对小 map（可能指元素数量较少的 map）进行了特殊优化，避免了使用完整的目录结构，从而提升性能。
5. **长字符串快速相等性测试 (`longStringQuickEqualityTest`)**:  在比较长字符串时，先进行一个快速的初步检查，如果前 8 个字节和后 8 个字节不相同，则认为字符串肯定不相等，从而避免昂贵的完整字符串比较。这是一种常见的优化策略。
6. **哈希计算和使用**:  使用了哈希函数 (`typ.Hasher`) 来确定键值对在 map 中的位置。
7. **控制位 (`ctrls`) 的使用**:  代码中出现了 `ctrls`，这很可能是瑞士表的核心概念，用于存储每个槽位的元数据，例如是否为空、是否已删除、以及部分哈希值等，以便快速过滤不匹配的槽位。
8. **探测序列 (`makeProbeSeq`)**:  当哈希冲突发生时，需要一种机制来查找下一个可能的槽位，`makeProbeSeq` 看起来就是用于生成这种探测序列。
9. **map 的增长和 rehash (`growToSmall`, `growToTable`, `rehash`)**:  当 map 的容量不足时，需要进行扩容，`growToSmall` 和 `growToTable` 可能分别对应扩容到小 map 和大 map 的情况，`rehash` 则是在扩容时重新组织 map 的数据。
10. **并发安全 (`m.writing`)**:  虽然代码中没有看到显式的锁，但 `m.writing` 字段的存在以及对它的检查，表明这段代码考虑了并发安全问题，至少在读操作和写操作之间进行了区分。
11. **实验性特性 (`//go:build goexperiment.swissmap`)**:  明确指出这段代码是基于一个实验性特性，意味着它的行为和性能可能会在未来的 Go 版本中发生变化。

**推断的 Go 语言功能实现：**

根据函数名和代码结构，可以推断这段代码实现了 Go 语言中 `map[string]T` 这种类型的 map 的部分核心操作，并且使用了名为 "瑞士表" 的哈希表实现。  当 Go 程序的构建时指定了 `goexperiment.swissmap` 标签，运行时会使用这段代码中实现的逻辑。

**Go 代码示例：**

```go
package main

import "fmt"

func main() {
	// 注意：这段代码需要使用 `-tags=goexperiment.swissmap` 编译
	m := make(map[string]int)

	// 赋值
	m["hello"] = 1
	m["world"] = 2

	// 访问
	val1 := m["hello"]
	val2, ok := m["world"]
	val3, ok2 := m["nonexistent"]

	fmt.Println(val1)      // Output: 1
	fmt.Println(val2, ok)   // Output: 2 true
	fmt.Println(val3, ok2)  // Output: 0 false

	// 删除
	delete(m, "hello")

	val4, ok3 := m["hello"]
	fmt.Println(val4, ok3)  // Output: 0 false
}
```

**假设的输入与输出（针对 `getWithoutKeySmallFastStr`）：**

假设我们有一个小的 map，其内部结构可能如下（这只是一个简化的概念模型）：

```
// 假设的 map 内部结构
type SmallMap struct {
	data [8]struct { // 假设最多 8 个槽位
		key   string
		value int
		ctrl  uint8 // 控制位
	}
	used int
}

// 假设的输入
m := &Map{dirPtr: unsafe.Pointer(&smallMapData)} // smallMapData 是一个 SmallMap 类型的变量
typ := &abi.SwissMapType{SlotSize: unsafe.Sizeof(smallMapData.data[0])}
key := "apple"

// 假设 smallMapData 中存储了以下数据：
// data[0]: key="banana", value=10, ctrl=...
// data[1]: key="apple", value=20, ctrl=...
// data[2]: 空槽位

// 预期的输出
// 如果找到 "apple"，则返回指向 value (20) 的 unsafe.Pointer
// 如果找不到 "apple"，则返回 nil
```

在 `getWithoutKeySmallFastStr` 函数中，它会遍历 `m.dirPtr` 指向的小 map 的槽位，比较控制位和键，如果找到匹配的键，则返回对应值的指针。

**命令行参数的具体处理：**

这段代码本身并没有直接处理命令行参数。  `//go:build goexperiment.swissmap` 是一个 **构建标签 (build tag)**。这意味着只有在 **编译 Go 程序时** 显式指定了这个标签，这段代码才会被包含到最终的可执行文件中。

使用 `go build` 命令时，可以通过 `-tags` 参数来指定构建标签：

```bash
go build -tags=goexperiment.swissmap main.go
```

如果不指定 `-tags=goexperiment.swissmap`，则这段代码很可能不会被使用，Go 运行时会使用其他的 map 实现。

**使用者易犯错的点：**

1. **并发访问不安全：**  虽然代码中似乎有 `m.writing` 这样的字段来尝试控制并发，但从标准 Go map 的角度来看，**同时对同一个 map 进行写入操作是不安全的，会导致数据竞争**。这段代码很可能只处理了部分并发场景，或者依赖于更上层调用者的同步机制。  使用者容易误以为使用了 `goexperiment.swissmap` 的 map 就天然是并发安全的，这是错误的。

   **示例：**

   ```go
   package main

   import (
       "fmt"
       "sync"
   )

   func main() {
       // 假设使用了 -tags=goexperiment.swissmap 编译
       m := make(map[string]int)
       var wg sync.WaitGroup

       // 多个 goroutine 同时写入
       for i := 0; i < 100; i++ {
           wg.Add(1)
           go func(n int) {
               defer wg.Done()
               m[fmt.Sprintf("key-%d", n)] = n
           }(i)
       }

       wg.Wait()
       fmt.Println(len(m)) // 结果可能不确定，可能小于 100
   }
   ```

   在上面的例子中，即使使用了 `goexperiment.swissmap` 的实现，如果没有额外的同步措施（例如 `sync.Mutex`），多个 goroutine 同时写入 `m` 仍然可能导致数据竞争。

2. **依赖实验性特性：**  使用者需要意识到 `goexperiment.swissmap` 是一个实验性特性。这意味着：
   - 它的行为、性能甚至存在性都可能在未来的 Go 版本中发生变化，没有任何兼容性保证。
   - 不应该在生产环境的代码中过度依赖这种实验性特性，除非你明确知道潜在的风险并愿意承担。

总而言之，这段代码是 Go 语言运行时为了优化字符串键的 map 查找、赋值和删除操作而实现的一部分，它基于一种名为 "瑞士表" 的哈希表结构，并且是一个实验性的特性。使用者需要通过构建标签来启用它，并需要注意其并发安全性以及作为实验性特性的潜在风险。

Prompt: 
```
这是路径为go/src/internal/runtime/maps/runtime_faststr_swiss.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。

"""
// Copyright 2024 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build goexperiment.swissmap

package maps

import (
	"internal/abi"
	"internal/goarch"
	"internal/race"
	"internal/runtime/sys"
	"unsafe"
)

func (m *Map) getWithoutKeySmallFastStr(typ *abi.SwissMapType, key string) unsafe.Pointer {
	g := groupReference{
		data: m.dirPtr,
	}

	ctrls := *g.ctrls()
	slotKey := g.key(typ, 0)
	slotSize := typ.SlotSize

	// The 64 threshold was chosen based on performance of BenchmarkMapStringKeysEight,
	// where there are 8 keys to check, all of which don't quick-match the lookup key.
	// In that case, we can save hashing the lookup key. That savings is worth this extra code
	// for strings that are long enough that hashing is expensive.
	if len(key) > 64 {
		// String hashing and equality might be expensive. Do a quick check first.
		j := abi.SwissMapGroupSlots
		for i := range abi.SwissMapGroupSlots {
			if ctrls&(1<<7) == 0 && longStringQuickEqualityTest(key, *(*string)(slotKey)) {
				if j < abi.SwissMapGroupSlots {
					// 2 strings both passed the quick equality test.
					// Break out of this loop and do it the slow way.
					goto dohash
				}
				j = i
			}
			slotKey = unsafe.Pointer(uintptr(slotKey) + slotSize)
			ctrls >>= 8
		}
		if j == abi.SwissMapGroupSlots {
			// No slot passed the quick test.
			return nil
		}
		// There's exactly one slot that passed the quick test. Do the single expensive comparison.
		slotKey = g.key(typ, uintptr(j))
		if key == *(*string)(slotKey) {
			return unsafe.Pointer(uintptr(slotKey) + 2*goarch.PtrSize)
		}
		return nil
	}

dohash:
	// This path will cost 1 hash and 1+ε comparisons.
	hash := typ.Hasher(abi.NoEscape(unsafe.Pointer(&key)), m.seed)
	h2 := uint8(h2(hash))
	ctrls = *g.ctrls()
	slotKey = g.key(typ, 0)

	for range abi.SwissMapGroupSlots {
		if uint8(ctrls) == h2 && key == *(*string)(slotKey) {
			return unsafe.Pointer(uintptr(slotKey) + 2*goarch.PtrSize)
		}
		slotKey = unsafe.Pointer(uintptr(slotKey) + slotSize)
		ctrls >>= 8
	}
	return nil
}

// Returns true if a and b might be equal.
// Returns false if a and b are definitely not equal.
// Requires len(a)>=8.
func longStringQuickEqualityTest(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	x, y := stringPtr(a), stringPtr(b)
	// Check first 8 bytes.
	if *(*[8]byte)(x) != *(*[8]byte)(y) {
		return false
	}
	// Check last 8 bytes.
	x = unsafe.Pointer(uintptr(x) + uintptr(len(a)) - 8)
	y = unsafe.Pointer(uintptr(y) + uintptr(len(a)) - 8)
	if *(*[8]byte)(x) != *(*[8]byte)(y) {
		return false
	}
	return true
}
func stringPtr(s string) unsafe.Pointer {
	type stringStruct struct {
		ptr unsafe.Pointer
		len int
	}
	return (*stringStruct)(unsafe.Pointer(&s)).ptr
}

//go:linkname runtime_mapaccess1_faststr runtime.mapaccess1_faststr
func runtime_mapaccess1_faststr(typ *abi.SwissMapType, m *Map, key string) unsafe.Pointer {
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

	if m.dirLen <= 0 {
		elem := m.getWithoutKeySmallFastStr(typ, key)
		if elem == nil {
			return unsafe.Pointer(&zeroVal[0])
		}
		return elem
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
			if key == *(*string)(slotKey) {
				slotElem := unsafe.Pointer(uintptr(slotKey) + 2*goarch.PtrSize)
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

//go:linkname runtime_mapaccess2_faststr runtime.mapaccess2_faststr
func runtime_mapaccess2_faststr(typ *abi.SwissMapType, m *Map, key string) (unsafe.Pointer, bool) {
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

	if m.dirLen <= 0 {
		elem := m.getWithoutKeySmallFastStr(typ, key)
		if elem == nil {
			return unsafe.Pointer(&zeroVal[0]), false
		}
		return elem, true
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
			if key == *(*string)(slotKey) {
				slotElem := unsafe.Pointer(uintptr(slotKey) + 2*goarch.PtrSize)
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

func (m *Map) putSlotSmallFastStr(typ *abi.SwissMapType, hash uintptr, key string) unsafe.Pointer {
	g := groupReference{
		data: m.dirPtr,
	}

	match := g.ctrls().matchH2(h2(hash))

	// Look for an existing slot containing this key.
	for match != 0 {
		i := match.first()

		slotKey := g.key(typ, i)
		if key == *(*string)(slotKey) {
			// Key needs update, as the backing storage may differ.
			*(*string)(slotKey) = key
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
	*(*string)(slotKey) = key

	slotElem := g.elem(typ, i)

	g.ctrls().set(i, ctrl(h2(hash)))
	m.used++

	return slotElem
}

//go:linkname runtime_mapassign_faststr runtime.mapassign_faststr
func runtime_mapassign_faststr(typ *abi.SwissMapType, m *Map, key string) unsafe.Pointer {
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
			elem := m.putSlotSmallFastStr(typ, hash, key)

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
				if key == *(*string)(slotKey) {
					// Key needs update, as the backing
					// storage may differ.
					*(*string)(slotKey) = key
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
				*(*string)(slotKey) = key

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

//go:linkname runtime_mapdelete_faststr runtime.mapdelete_faststr
func runtime_mapdelete_faststr(typ *abi.SwissMapType, m *Map, key string) {
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

"""



```