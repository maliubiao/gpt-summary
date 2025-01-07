Response:
Let's break down the thought process for analyzing this Go code snippet and fulfilling the request.

1. **Understanding the Request:** The core request is to analyze the provided Go code snippet, identify its functionality, explain how it relates to Go's map implementation, provide examples, and summarize its purpose. The "map_noswiss.go" file name is a strong hint that this code deals with Go's map implementation, specifically in a context where certain optimizations (like "swiSS hashing") might be disabled or alternative approaches are used. The "part 2 of 2" suggests we need to synthesize information from both parts.

2. **Initial Code Scan and Keyword Identification:**  The first step is to quickly scan the code for important keywords and function names. This helps in getting a high-level understanding of the code's purpose. Keywords that stand out are:

    * `map`:  This is the most obvious clue, indicating the code deals with Go maps.
    * `hmap`:  This is the internal struct representing a Go map.
    * `bmap`: This is the struct representing a map bucket.
    * `hiter`:  This struct is used for map iteration.
    * `hashGrow`, `mapclear`, `evacuate`: These names suggest operations related to resizing, clearing, and migrating data in the map.
    * `mapaccess`, `mapassign`, `mapdelete`: These names clearly relate to accessing, assigning, and deleting map elements.
    * `reflect_`:  Functions prefixed with `reflect_` are likely related to the `reflect` package's interaction with maps.
    * `mapclone`, `keys`, `values`: These indicate functions for cloning maps and extracting keys/values.
    * `unsafe.Pointer`: Frequent use of `unsafe.Pointer` indicates low-level memory manipulation, which is common in runtime code.
    * `raceenabled`:  Suggests code related to race detection during concurrent map access.

3. **Focusing on Key Functions and Logic:** After the initial scan, the next step is to analyze the purpose and logic of the most important functions.

    * **`mapiternext`:**  This function is clearly responsible for advancing the map iterator. The code logic iterates through buckets and entries, handling cases where the map has grown. The `checkBucket` logic is interesting and hints at how iterators handle concurrent modifications.

    * **`mapclear`:**  This function's purpose is evident: clear all entries from the map. It resets various `hmap` fields and re-initializes the bucket array.

    * **`hashGrow`:** This function handles map resizing. It determines whether to double the bucket count or just grow laterally (same size). It manages the `oldbuckets` and `newbuckets` during the growth process.

    * **`evacuate`:** This is a crucial function in the resizing process. It moves key-value pairs from the old buckets to the new buckets. It handles the logic for deciding which new bucket an entry should go to.

    * **`mapclone2`:** This function implements map cloning. It creates a new map and copies the contents from the original map. It has special handling for different map states (growing, small maps).

    * **`keys` and `values`:** These functions extract the keys and values from the map and store them in a slice. They need to iterate through all buckets, including the old buckets if the map is growing.

4. **Inferring Overall Functionality:** Based on the analyzed functions, the overall functionality of this code snippet is the core implementation of Go's `map` data structure, specifically focusing on operations like iteration, clearing, resizing, cloning, and extracting keys/values. The `map_noswiss.go` filename suggests this might be a version of the map implementation where "swiSS hashing" (a specific optimization) is not used.

5. **Providing Examples and Reasoning:**  Now, it's time to provide concrete examples.

    * **Iteration:** Show a simple `for...range` loop over a map and how the `mapiternext` function would be involved internally. Include a scenario with concurrent modification to illustrate the iterator's behavior.

    * **Clearing:** Demonstrate the `delete` keyword's effect on a map, which ultimately calls `mapclear`.

    * **Resizing:**  Show how adding elements to a map can trigger `hashGrow` and `evacuate`. Emphasize the incremental nature of evacuation.

    * **Cloning:**  Illustrate the `maps.Clone` function and how it uses `mapclone2` internally.

    * **Keys/Values:**  Demonstrate the `maps.Keys` and `maps.Values` functions.

6. **Addressing Specific Parts of the Request:**

    * **Go Language Feature:** Clearly state that this code implements the `map` feature in Go.
    * **Code Examples:** Provide clear and concise Go code snippets.
    * **Assumptions and I/O:** For code reasoning, mention the assumptions (e.g., initial map state) and describe the expected output.
    * **Command-line Arguments:**  Since this is runtime code, it doesn't directly handle command-line arguments. State this explicitly.
    * **Common Mistakes:** Think about common errors users might make when working with maps (e.g., iterating and modifying concurrently).
    * **Summarization:**  Concise summary of the code's purpose.

7. **Review and Refinement:** After drafting the initial response, review it for accuracy, clarity, and completeness. Ensure that all parts of the request have been addressed. For example, double-check that the examples are correct and that the explanations are easy to understand. Ensure the language is clear and avoids jargon where possible.

This structured approach allows for a systematic analysis of the code and ensures that all aspects of the request are addressed comprehensively. The initial scan and keyword identification provide a starting point, while the deeper analysis of key functions reveals the core logic. Finally, concrete examples and addressing the specific requirements of the prompt result in a thorough and helpful answer.
这是对 Go 语言 `runtime` 包中 `map_noswiss.go` 文件的一部分代码的分析。这个文件包含了 Go 语言 map 数据结构的核心实现，但从文件名 `map_noswiss.go` 可以推断，它可能是不包含某些特定优化（例如 "swiSS hashing"）的版本。

**功能归纳 (第2部分):**

这部分代码主要负责以下 Go 语言 map 的关键功能：

1. **迭代器推进 (`mapiternext`):**  实现了 map 迭代器的核心逻辑，用于在 `for...range` 循环中遍历 map 的键值对。它负责找到下一个有效的键值对，并处理 map 在迭代过程中可能发生的扩容。

2. **清空 Map (`mapclear`):**  提供了清空 map 所有键值对的功能。它会将 map 的内部状态重置，包括 buckets、oldbuckets 等。

3. **Map 扩容 (`hashGrow`):**  实现了 map 的扩容机制。当 map 的元素数量达到一定阈值时，会触发扩容，分配更大的 bucket 数组。扩容可以是翻倍大小，也可以是同等大小的“侧向增长”以减少 overflow buckets。

4. **扩容工作 (`growWork`):**  在访问 map 元素时，如果 map 正在扩容，`growWork` 会被调用，负责将旧 bucket 中的数据迁移到新的 bucket 中，逐步完成扩容过程。

5. **Bucket 迁移 (`evacuate`):**  扩容的核心步骤。它将旧 bucket 中的键值对重新哈希并移动到新的 bucket 中。这个过程需要处理键值对应该迁移到新 bucket 的哪个位置（高位或低位）。

6. **推进迁移标记 (`advanceEvacuationMark`):**  在扩容过程中，记录已经完成迁移的 bucket，并推进迁移的进度。

7. **反射相关的辅助函数 (`reflect_makemap`, `reflect_mapaccess`, `reflect_mapassign`, `reflect_mapdelete`, `reflect_mapiterinit`, `reflect_mapiternext`, `reflect_maplen`, `reflect_mapclear` 等):**  这些函数是 `reflect` 包与 map 交互的桥梁。它们允许通过反射 API 来创建、访问、修改、删除 map 元素，以及进行迭代和获取长度等操作。很多第三方库通过 `linkname` 技术直接调用这些 runtime 函数以实现更高效的 map 操作。

8. **Map 克隆 (`mapclone`, `mapclone2`, `moveToBmap`):** 实现了 map 的浅拷贝功能。`mapclone` 是用户可调用的函数，而 `mapclone2` 和 `moveToBmap` 是其内部实现，负责分配新的 `hmap` 和 `bmap`，并将原 map 的键值对复制到新的 map 中。

9. **获取 Map 的键 (`keys`, `copyKeys`):**  实现了获取 map 所有键的功能，并将这些键存储到一个 slice 中。

10. **获取 Map 的值 (`values`, `copyValues`):** 实现了获取 map 所有值的功能，并将这些值存储到一个 slice 中。

**它可以被认为是 Go 语言 map 数据结构在没有特定优化（如 "swiSS hashing"）情况下的核心操作实现。**

**Go 代码示例说明:**

以下是一些基于代码推理的 Go 代码示例，展示了这部分代码实现的功能。

**1. Map 迭代器推进 (`mapiternext`)**

```go
package main

import "fmt"

func main() {
	m := map[string]int{"a": 1, "b": 2, "c": 3}
	for key, value := range m {
		fmt.Printf("Key: %s, Value: %d\n", key, value)
	}
}
```

**推理:** 当使用 `for...range` 循环遍历 map 时，Go 编译器会使用 `mapiterinit` 初始化迭代器，然后循环调用 `mapiternext` 来获取下一个键值对。`mapiternext` 内部会根据当前的 bucket 和偏移量找到下一个有效的键值对。如果 map 在迭代过程中发生了扩容，`mapiternext` 也会处理这种情况，确保迭代能够继续进行。

**假设输入:**  一个包含若干键值对的 map `m`。

**预期输出:** 顺序可能不固定，但会打印出 map 中所有键值对。

**2. 清空 Map (`mapclear`)**

```go
package main

import "fmt"

func main() {
	m := map[string]int{"a": 1, "b": 2, "c": 3}
	fmt.Println("Before clear:", m)
	clear(m)
	fmt.Println("After clear:", m)
}
```

**推理:**  Go 1.21 引入了内置的 `clear` 函数，对于 map 类型，它会调用 `mapclear` 函数。`mapclear` 会重置 map 的内部状态，使其看起来像一个空的 map。

**假设输入:** 一个包含键值对的 map `m`。

**预期输出:**
```
Before clear: map[a:1 b:2 c:3]
After clear: map[]
```

**3. Map 扩容 (`hashGrow`)**

虽然我们不能直接调用 `hashGrow`，但可以通过向 map 中添加元素来观察扩容行为。

```go
package main

import "fmt"

func main() {
	m := make(map[int]int)
	capacity := 8 // 假设初始容量，实际可能不同
	for i := 0; i < capacity*2; i++ { // 添加超过初始容量的元素
		m[i] = i
		fmt.Printf("Count: %d, Len: %d\n", i+1, len(m))
	}
}
```

**推理:** 当 map 的元素数量接近其容量时，runtime 会自动调用 `hashGrow` 来分配更大的 bucket 数组。这可以避免过多的 hash 冲突，提高性能。

**假设输入:**  一个初始为空的 map `m`，并逐步添加元素。

**预期输出:**  在添加元素的过程中，当元素数量超过一定阈值时，map 的内部结构会发生变化（扩容），但这个过程对用户是透明的。输出会显示添加元素的数量。

**4. Map 克隆 (`mapclone`)**

```go
package main

import (
	"fmt"
	"maps"
)

func main() {
	m1 := map[string]int{"a": 1, "b": 2}
	m2 := maps.Clone(m1)
	fmt.Println("Original map:", m1)
	fmt.Println("Cloned map:", m2)

	// 修改克隆的 map 不影响原 map
	m2["a"] = 100
	fmt.Println("Original map after modifying clone:", m1)
	fmt.Println("Cloned map after modification:", m2)
}
```

**推理:** `maps.Clone` 函数会调用 runtime 中的 `mapclone`，进而调用 `mapclone2` 来创建一个新的 map，并将原 map 的键值对复制到新的 map 中。这是一个浅拷贝，意味着如果值是指针类型，则两个 map 会指向相同的底层数据。

**假设输入:** 一个包含键值对的 map `m1`。

**预期输出:**
```
Original map: map[a:1 b:2]
Cloned map: map[a:1 b:2]
Original map after modifying clone: map[a:1 b:2]
Cloned map after modification: map[a:100 b:2]
```

**5. 获取 Map 的键和值 (`keys`, `values`)**

```go
package main

import (
	"fmt"
	"maps"
	"sort"
)

func main() {
	m := map[string]int{"c": 3, "a": 1, "b": 2}
	keysSlice := maps.Keys(m)
	sort.Strings(keysSlice) // 对键进行排序以便输出一致
	fmt.Println("Keys:", keysSlice)

	valuesSlice := maps.Values(m)
	sort.Ints(valuesSlice) // 对值进行排序以便输出一致
	fmt.Println("Values:", valuesSlice)
}
```

**推理:** `maps.Keys` 和 `maps.Values` 分别调用 runtime 中的 `keys` 和 `values` 函数，遍历 map 的 buckets，并将键或值复制到一个新的 slice 中。

**假设输入:** 一个包含键值对的 map `m`。

**预期输出:**
```
Keys: [a b c]
Values: [1 2 3]
```

**命令行参数处理:**

这部分代码是 Go runtime 的一部分，主要负责 map 数据结构的内部实现。它不直接处理命令行参数。命令行参数的处理通常发生在 `main` 函数所在的包中，并使用 `os` 包或者第三方库来解析。

**使用者易犯错的点:**

1. **并发读写冲突:**  在多个 goroutine 中并发地读写 map，而不进行适当的同步控制（例如使用 `sync.Mutex` 或 `sync.RWMutex`），会导致程序崩溃或数据竞争。Go 的 map **不是并发安全的**。

   ```go
   package main

   import (
   	"fmt"
   	"sync"
   )

   func main() {
   	m := make(map[int]int)
   	var wg sync.WaitGroup
   	wg.Add(2)

   	go func() {
   		defer wg.Done()
   		for i := 0; i < 1000; i++ {
   			m[i] = i // 并发写
   		}
   	}()

   	go func() {
   		defer wg.Done()
   		for i := 0; i < 1000; i++ {
   			fmt.Println(m[i]) // 并发读
   		}
   	}()

   	wg.Wait() // 运行时可能会报错：fatal error: concurrent map read and map write
   }
   ```

2. **在迭代过程中修改 Map:**  在 `for...range` 循环迭代 map 的过程中，如果尝试添加或删除元素，可能会导致未定义的行为，甚至程序崩溃。

   ```go
   package main

   import "fmt"

   func main() {
   	m := map[string]int{"a": 1, "b": 2, "c": 3}
   	for key := range m {
   		if key == "a" {
   			delete(m, "b") // 在迭代过程中删除元素
   		}
   		fmt.Println(key) // 输出顺序或结果可能不确定
   	}
   	fmt.Println(m)
   }
   ```

**总结:**

这部分 `map_noswiss.go` 的代码是 Go 语言 map 数据结构的核心实现，涵盖了 map 的迭代、清空、扩容、元素迁移、克隆以及反射支持等关键功能。它提供了在没有某些特定优化情况下的 map 基础操作逻辑。理解这部分代码有助于深入了解 Go 语言 map 的内部机制，并避免在使用 map 时可能遇到的并发问题。

Prompt: 
```
这是路径为go/src/runtime/map_noswiss.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第2部分，共2部分，请归纳一下它的功能

"""
their low bit.
				if checkBucket>>(it.B-1) != uintptr(b.tophash[offi]&1) {
					continue
				}
			}
		}
		if it.clearSeq == h.clearSeq &&
			((b.tophash[offi] != evacuatedX && b.tophash[offi] != evacuatedY) ||
				!(t.ReflexiveKey() || t.Key.Equal(k, k))) {
			// This is the golden data, we can return it.
			// OR
			// key!=key, so the entry can't be deleted or updated, so we can just return it.
			// That's lucky for us because when key!=key we can't look it up successfully.
			it.key = k
			if t.IndirectElem() {
				e = *((*unsafe.Pointer)(e))
			}
			it.elem = e
		} else {
			// The hash table has grown since the iterator was started.
			// The golden data for this key is now somewhere else.
			// Check the current hash table for the data.
			// This code handles the case where the key
			// has been deleted, updated, or deleted and reinserted.
			// NOTE: we need to regrab the key as it has potentially been
			// updated to an equal() but not identical key (e.g. +0.0 vs -0.0).
			rk, re := mapaccessK(t, h, k)
			if rk == nil {
				continue // key has been deleted
			}
			it.key = rk
			it.elem = re
		}
		it.bucket = bucket
		if it.bptr != b { // avoid unnecessary write barrier; see issue 14921
			it.bptr = b
		}
		it.i = i + 1
		it.checkBucket = checkBucket
		return
	}
	b = b.overflow(t)
	i = 0
	goto next
}

// mapclear deletes all keys from a map.
// It is called by the compiler.
func mapclear(t *maptype, h *hmap) {
	if raceenabled && h != nil {
		callerpc := sys.GetCallerPC()
		pc := abi.FuncPCABIInternal(mapclear)
		racewritepc(unsafe.Pointer(h), callerpc, pc)
	}

	if h == nil || h.count == 0 {
		return
	}

	if h.flags&hashWriting != 0 {
		fatal("concurrent map writes")
	}

	h.flags ^= hashWriting
	h.flags &^= sameSizeGrow
	h.oldbuckets = nil
	h.nevacuate = 0
	h.noverflow = 0
	h.count = 0
	h.clearSeq++

	// Reset the hash seed to make it more difficult for attackers to
	// repeatedly trigger hash collisions. See issue 25237.
	h.hash0 = uint32(rand())

	// Keep the mapextra allocation but clear any extra information.
	if h.extra != nil {
		*h.extra = mapextra{}
	}

	// makeBucketArray clears the memory pointed to by h.buckets
	// and recovers any overflow buckets by generating them
	// as if h.buckets was newly alloced.
	_, nextOverflow := makeBucketArray(t, h.B, h.buckets)
	if nextOverflow != nil {
		// If overflow buckets are created then h.extra
		// will have been allocated during initial bucket creation.
		h.extra.nextOverflow = nextOverflow
	}

	if h.flags&hashWriting == 0 {
		fatal("concurrent map writes")
	}
	h.flags &^= hashWriting
}

func hashGrow(t *maptype, h *hmap) {
	// If we've hit the load factor, get bigger.
	// Otherwise, there are too many overflow buckets,
	// so keep the same number of buckets and "grow" laterally.
	bigger := uint8(1)
	if !overLoadFactor(h.count+1, h.B) {
		bigger = 0
		h.flags |= sameSizeGrow
	}
	oldbuckets := h.buckets
	newbuckets, nextOverflow := makeBucketArray(t, h.B+bigger, nil)

	flags := h.flags &^ (iterator | oldIterator)
	if h.flags&iterator != 0 {
		flags |= oldIterator
	}
	// commit the grow (atomic wrt gc)
	h.B += bigger
	h.flags = flags
	h.oldbuckets = oldbuckets
	h.buckets = newbuckets
	h.nevacuate = 0
	h.noverflow = 0

	if h.extra != nil && h.extra.overflow != nil {
		// Promote current overflow buckets to the old generation.
		if h.extra.oldoverflow != nil {
			throw("oldoverflow is not nil")
		}
		h.extra.oldoverflow = h.extra.overflow
		h.extra.overflow = nil
	}
	if nextOverflow != nil {
		if h.extra == nil {
			h.extra = new(mapextra)
		}
		h.extra.nextOverflow = nextOverflow
	}

	// the actual copying of the hash table data is done incrementally
	// by growWork() and evacuate().
}

// overLoadFactor reports whether count items placed in 1<<B buckets is over loadFactor.
func overLoadFactor(count int, B uint8) bool {
	return count > abi.OldMapBucketCount && uintptr(count) > loadFactorNum*(bucketShift(B)/loadFactorDen)
}

// tooManyOverflowBuckets reports whether noverflow buckets is too many for a map with 1<<B buckets.
// Note that most of these overflow buckets must be in sparse use;
// if use was dense, then we'd have already triggered regular map growth.
func tooManyOverflowBuckets(noverflow uint16, B uint8) bool {
	// If the threshold is too low, we do extraneous work.
	// If the threshold is too high, maps that grow and shrink can hold on to lots of unused memory.
	// "too many" means (approximately) as many overflow buckets as regular buckets.
	// See incrnoverflow for more details.
	if B > 15 {
		B = 15
	}
	// The compiler doesn't see here that B < 16; mask B to generate shorter shift code.
	return noverflow >= uint16(1)<<(B&15)
}

// growing reports whether h is growing. The growth may be to the same size or bigger.
func (h *hmap) growing() bool {
	return h.oldbuckets != nil
}

// sameSizeGrow reports whether the current growth is to a map of the same size.
func (h *hmap) sameSizeGrow() bool {
	return h.flags&sameSizeGrow != 0
}

//go:linkname sameSizeGrowForIssue69110Test
func sameSizeGrowForIssue69110Test(h *hmap) bool {
	return h.sameSizeGrow()
}

// noldbuckets calculates the number of buckets prior to the current map growth.
func (h *hmap) noldbuckets() uintptr {
	oldB := h.B
	if !h.sameSizeGrow() {
		oldB--
	}
	return bucketShift(oldB)
}

// oldbucketmask provides a mask that can be applied to calculate n % noldbuckets().
func (h *hmap) oldbucketmask() uintptr {
	return h.noldbuckets() - 1
}

func growWork(t *maptype, h *hmap, bucket uintptr) {
	// make sure we evacuate the oldbucket corresponding
	// to the bucket we're about to use
	evacuate(t, h, bucket&h.oldbucketmask())

	// evacuate one more oldbucket to make progress on growing
	if h.growing() {
		evacuate(t, h, h.nevacuate)
	}
}

func bucketEvacuated(t *maptype, h *hmap, bucket uintptr) bool {
	b := (*bmap)(add(h.oldbuckets, bucket*uintptr(t.BucketSize)))
	return evacuated(b)
}

// evacDst is an evacuation destination.
type evacDst struct {
	b *bmap          // current destination bucket
	i int            // key/elem index into b
	k unsafe.Pointer // pointer to current key storage
	e unsafe.Pointer // pointer to current elem storage
}

func evacuate(t *maptype, h *hmap, oldbucket uintptr) {
	b := (*bmap)(add(h.oldbuckets, oldbucket*uintptr(t.BucketSize)))
	newbit := h.noldbuckets()
	if !evacuated(b) {
		// TODO: reuse overflow buckets instead of using new ones, if there
		// is no iterator using the old buckets.  (If !oldIterator.)

		// xy contains the x and y (low and high) evacuation destinations.
		var xy [2]evacDst
		x := &xy[0]
		x.b = (*bmap)(add(h.buckets, oldbucket*uintptr(t.BucketSize)))
		x.k = add(unsafe.Pointer(x.b), dataOffset)
		x.e = add(x.k, abi.OldMapBucketCount*uintptr(t.KeySize))

		if !h.sameSizeGrow() {
			// Only calculate y pointers if we're growing bigger.
			// Otherwise GC can see bad pointers.
			y := &xy[1]
			y.b = (*bmap)(add(h.buckets, (oldbucket+newbit)*uintptr(t.BucketSize)))
			y.k = add(unsafe.Pointer(y.b), dataOffset)
			y.e = add(y.k, abi.OldMapBucketCount*uintptr(t.KeySize))
		}

		for ; b != nil; b = b.overflow(t) {
			k := add(unsafe.Pointer(b), dataOffset)
			e := add(k, abi.OldMapBucketCount*uintptr(t.KeySize))
			for i := 0; i < abi.OldMapBucketCount; i, k, e = i+1, add(k, uintptr(t.KeySize)), add(e, uintptr(t.ValueSize)) {
				top := b.tophash[i]
				if isEmpty(top) {
					b.tophash[i] = evacuatedEmpty
					continue
				}
				if top < minTopHash {
					throw("bad map state")
				}
				k2 := k
				if t.IndirectKey() {
					k2 = *((*unsafe.Pointer)(k2))
				}
				var useY uint8
				if !h.sameSizeGrow() {
					// Compute hash to make our evacuation decision (whether we need
					// to send this key/elem to bucket x or bucket y).
					hash := t.Hasher(k2, uintptr(h.hash0))
					if h.flags&iterator != 0 && !t.ReflexiveKey() && !t.Key.Equal(k2, k2) {
						// If key != key (NaNs), then the hash could be (and probably
						// will be) entirely different from the old hash. Moreover,
						// it isn't reproducible. Reproducibility is required in the
						// presence of iterators, as our evacuation decision must
						// match whatever decision the iterator made.
						// Fortunately, we have the freedom to send these keys either
						// way. Also, tophash is meaningless for these kinds of keys.
						// We let the low bit of tophash drive the evacuation decision.
						// We recompute a new random tophash for the next level so
						// these keys will get evenly distributed across all buckets
						// after multiple grows.
						useY = top & 1
						top = tophash(hash)
					} else {
						if hash&newbit != 0 {
							useY = 1
						}
					}
				}

				if evacuatedX+1 != evacuatedY || evacuatedX^1 != evacuatedY {
					throw("bad evacuatedN")
				}

				b.tophash[i] = evacuatedX + useY // evacuatedX + 1 == evacuatedY
				dst := &xy[useY]                 // evacuation destination

				if dst.i == abi.OldMapBucketCount {
					dst.b = h.newoverflow(t, dst.b)
					dst.i = 0
					dst.k = add(unsafe.Pointer(dst.b), dataOffset)
					dst.e = add(dst.k, abi.OldMapBucketCount*uintptr(t.KeySize))
				}
				dst.b.tophash[dst.i&(abi.OldMapBucketCount-1)] = top // mask dst.i as an optimization, to avoid a bounds check
				if t.IndirectKey() {
					*(*unsafe.Pointer)(dst.k) = k2 // copy pointer
				} else {
					typedmemmove(t.Key, dst.k, k) // copy elem
				}
				if t.IndirectElem() {
					*(*unsafe.Pointer)(dst.e) = *(*unsafe.Pointer)(e)
				} else {
					typedmemmove(t.Elem, dst.e, e)
				}
				dst.i++
				// These updates might push these pointers past the end of the
				// key or elem arrays.  That's ok, as we have the overflow pointer
				// at the end of the bucket to protect against pointing past the
				// end of the bucket.
				dst.k = add(dst.k, uintptr(t.KeySize))
				dst.e = add(dst.e, uintptr(t.ValueSize))
			}
		}
		// Unlink the overflow buckets & clear key/elem to help GC.
		if h.flags&oldIterator == 0 && t.Bucket.Pointers() {
			b := add(h.oldbuckets, oldbucket*uintptr(t.BucketSize))
			// Preserve b.tophash because the evacuation
			// state is maintained there.
			ptr := add(b, dataOffset)
			n := uintptr(t.BucketSize) - dataOffset
			memclrHasPointers(ptr, n)
		}
	}

	if oldbucket == h.nevacuate {
		advanceEvacuationMark(h, t, newbit)
	}
}

func advanceEvacuationMark(h *hmap, t *maptype, newbit uintptr) {
	h.nevacuate++
	// Experiments suggest that 1024 is overkill by at least an order of magnitude.
	// Put it in there as a safeguard anyway, to ensure O(1) behavior.
	stop := h.nevacuate + 1024
	if stop > newbit {
		stop = newbit
	}
	for h.nevacuate != stop && bucketEvacuated(t, h, h.nevacuate) {
		h.nevacuate++
	}
	if h.nevacuate == newbit { // newbit == # of oldbuckets
		// Growing is all done. Free old main bucket array.
		h.oldbuckets = nil
		// Can discard old overflow buckets as well.
		// If they are still referenced by an iterator,
		// then the iterator holds a pointers to the slice.
		if h.extra != nil {
			h.extra.oldoverflow = nil
		}
		h.flags &^= sameSizeGrow
	}
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
func reflect_makemap(t *maptype, cap int) *hmap {
	// Check invariants and reflects math.
	if t.Key.Equal == nil {
		throw("runtime.reflect_makemap: unsupported map key type")
	}
	if t.Key.Size_ > abi.OldMapMaxKeyBytes && (!t.IndirectKey() || t.KeySize != uint8(goarch.PtrSize)) ||
		t.Key.Size_ <= abi.OldMapMaxKeyBytes && (t.IndirectKey() || t.KeySize != uint8(t.Key.Size_)) {
		throw("key size wrong")
	}
	if t.Elem.Size_ > abi.OldMapMaxElemBytes && (!t.IndirectElem() || t.ValueSize != uint8(goarch.PtrSize)) ||
		t.Elem.Size_ <= abi.OldMapMaxElemBytes && (t.IndirectElem() || t.ValueSize != uint8(t.Elem.Size_)) {
		throw("elem size wrong")
	}
	if t.Key.Align_ > abi.OldMapBucketCount {
		throw("key align too big")
	}
	if t.Elem.Align_ > abi.OldMapBucketCount {
		throw("elem align too big")
	}
	if t.Key.Size_%uintptr(t.Key.Align_) != 0 {
		throw("key size not a multiple of key align")
	}
	if t.Elem.Size_%uintptr(t.Elem.Align_) != 0 {
		throw("elem size not a multiple of elem align")
	}
	if abi.OldMapBucketCount < 8 {
		throw("bucketsize too small for proper alignment")
	}
	if dataOffset%uintptr(t.Key.Align_) != 0 {
		throw("need padding in bucket (key)")
	}
	if dataOffset%uintptr(t.Elem.Align_) != 0 {
		throw("need padding in bucket (elem)")
	}

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
func reflect_mapaccess(t *maptype, h *hmap, key unsafe.Pointer) unsafe.Pointer {
	elem, ok := mapaccess2(t, h, key)
	if !ok {
		// reflect wants nil for a missing element
		elem = nil
	}
	return elem
}

//go:linkname reflect_mapaccess_faststr reflect.mapaccess_faststr
func reflect_mapaccess_faststr(t *maptype, h *hmap, key string) unsafe.Pointer {
	elem, ok := mapaccess2_faststr(t, h, key)
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
func reflect_mapassign(t *maptype, h *hmap, key unsafe.Pointer, elem unsafe.Pointer) {
	p := mapassign(t, h, key)
	typedmemmove(t.Elem, p, elem)
}

//go:linkname reflect_mapassign_faststr reflect.mapassign_faststr0
func reflect_mapassign_faststr(t *maptype, h *hmap, key string, elem unsafe.Pointer) {
	p := mapassign_faststr(t, h, key)
	typedmemmove(t.Elem, p, elem)
}

//go:linkname reflect_mapdelete reflect.mapdelete
func reflect_mapdelete(t *maptype, h *hmap, key unsafe.Pointer) {
	mapdelete(t, h, key)
}

//go:linkname reflect_mapdelete_faststr reflect.mapdelete_faststr
func reflect_mapdelete_faststr(t *maptype, h *hmap, key string) {
	mapdelete_faststr(t, h, key)
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
func reflect_mapiterinit(t *maptype, h *hmap, it *hiter) {
	mapiterinit(t, h, it)
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
func reflect_mapiternext(it *hiter) {
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
func reflect_mapiterkey(it *hiter) unsafe.Pointer {
	return it.key
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
func reflect_mapiterelem(it *hiter) unsafe.Pointer {
	return it.elem
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
func reflect_maplen(h *hmap) int {
	if h == nil {
		return 0
	}
	if raceenabled {
		callerpc := sys.GetCallerPC()
		racereadpc(unsafe.Pointer(h), callerpc, abi.FuncPCABIInternal(reflect_maplen))
	}
	return h.count
}

//go:linkname reflect_mapclear reflect.mapclear
func reflect_mapclear(t *maptype, h *hmap) {
	mapclear(t, h)
}

//go:linkname reflectlite_maplen internal/reflectlite.maplen
func reflectlite_maplen(h *hmap) int {
	if h == nil {
		return 0
	}
	if raceenabled {
		callerpc := sys.GetCallerPC()
		racereadpc(unsafe.Pointer(h), callerpc, abi.FuncPCABIInternal(reflect_maplen))
	}
	return h.count
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
	e.data = unsafe.Pointer(mapclone2((*maptype)(unsafe.Pointer(e._type)), (*hmap)(e.data)))
	return m
}

// moveToBmap moves a bucket from src to dst. It returns the destination bucket or new destination bucket if it overflows
// and the pos that the next key/value will be written, if pos == bucketCnt means needs to written in overflow bucket.
func moveToBmap(t *maptype, h *hmap, dst *bmap, pos int, src *bmap) (*bmap, int) {
	for i := 0; i < abi.OldMapBucketCount; i++ {
		if isEmpty(src.tophash[i]) {
			continue
		}

		for ; pos < abi.OldMapBucketCount; pos++ {
			if isEmpty(dst.tophash[pos]) {
				break
			}
		}

		if pos == abi.OldMapBucketCount {
			dst = h.newoverflow(t, dst)
			pos = 0
		}

		srcK := add(unsafe.Pointer(src), dataOffset+uintptr(i)*uintptr(t.KeySize))
		srcEle := add(unsafe.Pointer(src), dataOffset+abi.OldMapBucketCount*uintptr(t.KeySize)+uintptr(i)*uintptr(t.ValueSize))
		dstK := add(unsafe.Pointer(dst), dataOffset+uintptr(pos)*uintptr(t.KeySize))
		dstEle := add(unsafe.Pointer(dst), dataOffset+abi.OldMapBucketCount*uintptr(t.KeySize)+uintptr(pos)*uintptr(t.ValueSize))

		dst.tophash[pos] = src.tophash[i]
		if t.IndirectKey() {
			srcK = *(*unsafe.Pointer)(srcK)
			if t.NeedKeyUpdate() {
				kStore := newobject(t.Key)
				typedmemmove(t.Key, kStore, srcK)
				srcK = kStore
			}
			// Note: if NeedKeyUpdate is false, then the memory
			// used to store the key is immutable, so we can share
			// it between the original map and its clone.
			*(*unsafe.Pointer)(dstK) = srcK
		} else {
			typedmemmove(t.Key, dstK, srcK)
		}
		if t.IndirectElem() {
			srcEle = *(*unsafe.Pointer)(srcEle)
			eStore := newobject(t.Elem)
			typedmemmove(t.Elem, eStore, srcEle)
			*(*unsafe.Pointer)(dstEle) = eStore
		} else {
			typedmemmove(t.Elem, dstEle, srcEle)
		}
		pos++
		h.count++
	}
	return dst, pos
}

func mapclone2(t *maptype, src *hmap) *hmap {
	hint := src.count
	if overLoadFactor(hint, src.B) {
		// Note: in rare cases (e.g. during a same-sized grow) the map
		// can be overloaded. Make sure we don't allocate a destination
		// bucket array larger than the source bucket array.
		// This will cause the cloned map to be overloaded also,
		// but that's better than crashing. See issue 69110.
		hint = int(loadFactorNum * (bucketShift(src.B) / loadFactorDen))
	}
	dst := makemap(t, hint, nil)
	dst.hash0 = src.hash0
	dst.nevacuate = 0
	// flags do not need to be copied here, just like a new map has no flags.

	if src.count == 0 {
		return dst
	}

	if src.flags&hashWriting != 0 {
		fatal("concurrent map clone and map write")
	}

	if src.B == 0 && !(t.IndirectKey() && t.NeedKeyUpdate()) && !t.IndirectElem() {
		// Quick copy for small maps.
		dst.buckets = newobject(t.Bucket)
		dst.count = src.count
		typedmemmove(t.Bucket, dst.buckets, src.buckets)
		return dst
	}

	if dst.B == 0 {
		dst.buckets = newobject(t.Bucket)
	}
	dstArraySize := int(bucketShift(dst.B))
	srcArraySize := int(bucketShift(src.B))
	for i := 0; i < dstArraySize; i++ {
		dstBmap := (*bmap)(add(dst.buckets, uintptr(i*int(t.BucketSize))))
		pos := 0
		for j := 0; j < srcArraySize; j += dstArraySize {
			srcBmap := (*bmap)(add(src.buckets, uintptr((i+j)*int(t.BucketSize))))
			for srcBmap != nil {
				dstBmap, pos = moveToBmap(t, dst, dstBmap, pos, srcBmap)
				srcBmap = srcBmap.overflow(t)
			}
		}
	}

	if src.oldbuckets == nil {
		return dst
	}

	oldB := src.B
	srcOldbuckets := src.oldbuckets
	if !src.sameSizeGrow() {
		oldB--
	}
	oldSrcArraySize := int(bucketShift(oldB))

	for i := 0; i < oldSrcArraySize; i++ {
		srcBmap := (*bmap)(add(srcOldbuckets, uintptr(i*int(t.BucketSize))))
		if evacuated(srcBmap) {
			continue
		}

		if oldB >= dst.B { // main bucket bits in dst is less than oldB bits in src
			dstBmap := (*bmap)(add(dst.buckets, (uintptr(i)&bucketMask(dst.B))*uintptr(t.BucketSize)))
			for dstBmap.overflow(t) != nil {
				dstBmap = dstBmap.overflow(t)
			}
			pos := 0
			for srcBmap != nil {
				dstBmap, pos = moveToBmap(t, dst, dstBmap, pos, srcBmap)
				srcBmap = srcBmap.overflow(t)
			}
			continue
		}

		// oldB < dst.B, so a single source bucket may go to multiple destination buckets.
		// Process entries one at a time.
		for srcBmap != nil {
			// move from oldBlucket to new bucket
			for i := uintptr(0); i < abi.OldMapBucketCount; i++ {
				if isEmpty(srcBmap.tophash[i]) {
					continue
				}

				if src.flags&hashWriting != 0 {
					fatal("concurrent map clone and map write")
				}

				srcK := add(unsafe.Pointer(srcBmap), dataOffset+i*uintptr(t.KeySize))
				if t.IndirectKey() {
					srcK = *((*unsafe.Pointer)(srcK))
				}

				srcEle := add(unsafe.Pointer(srcBmap), dataOffset+abi.OldMapBucketCount*uintptr(t.KeySize)+i*uintptr(t.ValueSize))
				if t.IndirectElem() {
					srcEle = *((*unsafe.Pointer)(srcEle))
				}
				dstEle := mapassign(t, dst, srcK)
				typedmemmove(t.Elem, dstEle, srcEle)
			}
			srcBmap = srcBmap.overflow(t)
		}
	}
	return dst
}

// keys for implementing maps.keys
//
//go:linkname keys maps.keys
func keys(m any, p unsafe.Pointer) {
	e := efaceOf(&m)
	t := (*maptype)(unsafe.Pointer(e._type))
	h := (*hmap)(e.data)

	if h == nil || h.count == 0 {
		return
	}
	s := (*slice)(p)
	r := int(rand())
	offset := uint8(r >> h.B & (abi.OldMapBucketCount - 1))
	if h.B == 0 {
		copyKeys(t, h, (*bmap)(h.buckets), s, offset)
		return
	}
	arraySize := int(bucketShift(h.B))
	buckets := h.buckets
	for i := 0; i < arraySize; i++ {
		bucket := (i + r) & (arraySize - 1)
		b := (*bmap)(add(buckets, uintptr(bucket)*uintptr(t.BucketSize)))
		copyKeys(t, h, b, s, offset)
	}

	if h.growing() {
		oldArraySize := int(h.noldbuckets())
		for i := 0; i < oldArraySize; i++ {
			bucket := (i + r) & (oldArraySize - 1)
			b := (*bmap)(add(h.oldbuckets, uintptr(bucket)*uintptr(t.BucketSize)))
			if evacuated(b) {
				continue
			}
			copyKeys(t, h, b, s, offset)
		}
	}
	return
}

func copyKeys(t *maptype, h *hmap, b *bmap, s *slice, offset uint8) {
	for b != nil {
		for i := uintptr(0); i < abi.OldMapBucketCount; i++ {
			offi := (i + uintptr(offset)) & (abi.OldMapBucketCount - 1)
			if isEmpty(b.tophash[offi]) {
				continue
			}
			if h.flags&hashWriting != 0 {
				fatal("concurrent map read and map write")
			}
			k := add(unsafe.Pointer(b), dataOffset+offi*uintptr(t.KeySize))
			if t.IndirectKey() {
				k = *((*unsafe.Pointer)(k))
			}
			if s.len >= s.cap {
				fatal("concurrent map read and map write")
			}
			typedmemmove(t.Key, add(s.array, uintptr(s.len)*uintptr(t.Key.Size())), k)
			s.len++
		}
		b = b.overflow(t)
	}
}

// values for implementing maps.values
//
//go:linkname values maps.values
func values(m any, p unsafe.Pointer) {
	e := efaceOf(&m)
	t := (*maptype)(unsafe.Pointer(e._type))
	h := (*hmap)(e.data)
	if h == nil || h.count == 0 {
		return
	}
	s := (*slice)(p)
	r := int(rand())
	offset := uint8(r >> h.B & (abi.OldMapBucketCount - 1))
	if h.B == 0 {
		copyValues(t, h, (*bmap)(h.buckets), s, offset)
		return
	}
	arraySize := int(bucketShift(h.B))
	buckets := h.buckets
	for i := 0; i < arraySize; i++ {
		bucket := (i + r) & (arraySize - 1)
		b := (*bmap)(add(buckets, uintptr(bucket)*uintptr(t.BucketSize)))
		copyValues(t, h, b, s, offset)
	}

	if h.growing() {
		oldArraySize := int(h.noldbuckets())
		for i := 0; i < oldArraySize; i++ {
			bucket := (i + r) & (oldArraySize - 1)
			b := (*bmap)(add(h.oldbuckets, uintptr(bucket)*uintptr(t.BucketSize)))
			if evacuated(b) {
				continue
			}
			copyValues(t, h, b, s, offset)
		}
	}
	return
}

func copyValues(t *maptype, h *hmap, b *bmap, s *slice, offset uint8) {
	for b != nil {
		for i := uintptr(0); i < abi.OldMapBucketCount; i++ {
			offi := (i + uintptr(offset)) & (abi.OldMapBucketCount - 1)
			if isEmpty(b.tophash[offi]) {
				continue
			}

			if h.flags&hashWriting != 0 {
				fatal("concurrent map read and map write")
			}

			ele := add(unsafe.Pointer(b), dataOffset+abi.OldMapBucketCount*uintptr(t.KeySize)+offi*uintptr(t.ValueSize))
			if t.IndirectElem() {
				ele = *((*unsafe.Pointer)(ele))
			}
			if s.len >= s.cap {
				fatal("concurrent map read and map write")
			}
			typedmemmove(t.Elem, add(s.array, uintptr(s.len)*uintptr(t.Elem.Size())), ele)
			s.len++
		}
		b = b.overflow(t)
	}
}

"""




```