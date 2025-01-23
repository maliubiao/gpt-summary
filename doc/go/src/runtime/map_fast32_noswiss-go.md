Response:
Let's break down the thought process for analyzing this Go code snippet and generating the desired output.

**1. Understanding the Goal:**

The request asks for the functionality of the provided Go code, which is explicitly stated to be part of the `go/src/runtime/map_fast32_noswiss.go` file. This immediately signals that it's dealing with the low-level implementation of Go's `map` data structure, specifically optimized for `uint32` keys and when the `goexperiment.swissmap` build tag is *not* set.

**2. Initial Code Scan and Keyword Recognition:**

The first step is to quickly scan the code for keywords and function names that provide clues about its purpose. We see functions like:

* `mapaccess1_fast32`:  Likely related to accessing a map element and returning a pointer to the value.
* `mapaccess2_fast32`:  Similar to `mapaccess1_fast32`, but probably also returns a boolean indicating if the key was found.
* `mapassign_fast32`:  Clearly for assigning (inserting or updating) a key-value pair in the map.
* `mapassign_fast32ptr`:  Another assignment function, possibly handling pointer keys (though the comment indicates it's for `uint32`). This is a potential point of confusion to investigate.
* `mapdelete_fast32`:  For deleting a key-value pair.
* `growWork_fast32`:  Suggests a mechanism for resizing the map.
* `evacuate_fast32`:  Likely a part of the map resizing process, dealing with moving data between old and new buckets.

The presence of `hmap` and `bmap` suggests internal map data structures (hash map and bucket map). The `unsafe.Pointer` type signals low-level memory manipulation.

**3. Function-by-Function Analysis:**

Now, analyze each function individually:

* **`mapaccess1_fast32`:**  Checks for `nil` map, empty map, concurrent writes. It calculates the bucket based on the hash of the key. It handles map growth by potentially looking in the old buckets. It iterates through the bucket and its overflows to find the key. If found, it returns a pointer to the value. If not, it returns a pointer to `zeroVal`. *Key takeaway: Read access, returning value pointer.*

* **`mapaccess2_fast32`:** Very similar to `mapaccess1_fast32`, but also returns a `bool` to indicate if the key was found. *Key takeaway: Read access, returning value pointer and a boolean.*

* **`mapassign_fast32`:** Checks for `nil` map. Handles concurrent writes. Calculates the bucket. Manages map growth. Iterates through the bucket to find the key. If found, updates the value. If not found, finds an empty slot or allocates a new bucket. Handles map growth if the load factor is too high. *Key takeaway: Write access (insert/update), returns value pointer.*

* **`mapassign_fast32ptr`:**  The code is almost identical to `mapassign_fast32`. The comment and the use of `unsafe.Pointer` for the key in the signature are the key differentiators. However, the *internal* logic still treats the key as a 32-bit value (`dataOffset+i*4`). This suggests it's still optimized for 32-bit keys, even if the function signature accepts an `unsafe.Pointer`. This discrepancy is important to note. *Key takeaway:  Write access, returns value pointer, but with a potentially misleading name/signature – likely an artifact of `linkname` usage.*

* **`mapdelete_fast32`:** Checks for `nil` map, empty map, concurrent writes. Calculates the bucket. Handles map growth. Iterates through the bucket to find the key. If found, clears the key and value, updates the `tophash`, and decrements the map count. Handles the case where removing an element leads to contiguous empty slots. *Key takeaway: Delete access.*

* **`growWork_fast32`:**  This function is called during assignment and deletion when the map is growing. It triggers the evacuation of the old bucket corresponding to the current bucket being accessed and potentially another old bucket to make progress on the resizing. *Key takeaway:  Part of the map resizing mechanism.*

* **`evacuate_fast32`:** This is the core of the resizing logic. It moves key-value pairs from the old buckets to the new buckets. It determines the new bucket based on the hash and the growth factor. It marks old buckets as evacuated. *Key takeaway:  Core logic for moving data during map resizing.*

**4. Identifying the Overall Functionality:**

By analyzing the individual functions, it becomes clear that this code implements the core operations for a specific type of Go map:

* **Optimized for `uint32` keys:** The `_fast32` suffix is a strong indicator.
* **Without `swissmap` optimization:** The `//go:build !goexperiment.swissmap` confirms this.
* **Basic map operations:**  Get (with and without "ok" boolean), set, and delete.
* **Dynamic resizing:**  The `growWork` and `evacuate` functions handle increasing the map's capacity.
* **Concurrency control:** Checks for concurrent reads and writes using the `hashWriting` flag.

**5. Generating Examples and Explanations:**

Now, create concrete examples to illustrate the functionality. Choose simple scenarios for each function to demonstrate the core behavior. For the concurrency checks, briefly explain the concept and the error message.

**6. Addressing Specific Instructions:**

* **Go Code Examples:** Provide clear and concise examples for accessing, assigning, and deleting map entries.
* **Assumptions and Inputs/Outputs:**  For code that involves internal data structures, the examples are more about demonstrating the *effects* rather than inspecting internal state directly. The assumptions are about the map's initial state and the operations performed.
* **Command-line Arguments:** Since this code is part of the `runtime`, it doesn't directly process command-line arguments. State this explicitly.
* **Common Mistakes:** Focus on the most obvious pitfalls, like accessing a `nil` map or the implications of concurrent access without proper synchronization (although the code itself detects this and panics).

**7. Refining the Output:**

Organize the information logically. Start with a high-level summary, then detail each function's purpose. Use clear and concise language. Ensure the Go code examples are runnable and easy to understand. Pay attention to formatting and use code blocks for better readability.

**Self-Correction/Refinement during the Process:**

* **`mapassign_fast32ptr`:**  Initially, I might have assumed this was for pointer keys. However, noticing the internal use of `dataOffset + i*4` quickly reveals that it's still treating the key as a 32-bit value. The comment about `linkname` provides the context for why the signature might be misleading. It's crucial to highlight this potential point of confusion.
* **Concurrency:**  While the code has built-in checks for concurrent reads/writes, it's important to emphasize that these are *runtime* checks and not a replacement for proper synchronization mechanisms when multiple goroutines access the same map.

By following this structured approach, combining code analysis with an understanding of the request's requirements, it's possible to generate a comprehensive and accurate explanation of the provided Go code snippet.
这段代码是Go语言运行时（runtime）中关于 `map` 数据结构实现的一部分，专门针对 **键类型为 `uint32` 的 `map`** 进行了优化的版本，并且排除了 `swissmap` 优化实验特性。

下面分别列举其功能，并尝试推理其实现的 Go 语言功能，并提供代码示例。

**功能列举:**

1. **`mapaccess1_fast32(t *maptype, h *hmap, key uint32) unsafe.Pointer`**:  实现对 `map` 的读取操作，根据给定的键 `key` 查找对应的值，并返回指向该值的 `unsafe.Pointer`。如果键不存在，则返回指向 `zeroVal` 的指针。
2. **`mapaccess2_fast32(t *maptype, h *hmap, key uint32) (unsafe.Pointer, bool)`**: 类似 `mapaccess1_fast32`，实现对 `map` 的读取操作，但除了返回指向值的 `unsafe.Pointer` 外，还会返回一个 `bool` 值，表示键是否存在于 `map` 中。
3. **`mapassign_fast32(t *maptype, h *hmap, key uint32) unsafe.Pointer`**: 实现对 `map` 的写入或更新操作。根据给定的键 `key`，如果键已存在，则返回指向现有值的 `unsafe.Pointer`，以便修改；如果键不存在，则插入新的键值对，并返回指向新分配的值的 `unsafe.Pointer`。
4. **`mapassign_fast32ptr(t *maptype, h *hmap, key unsafe.Pointer) unsafe.Pointer`**:  这个函数的功能看起来与 `mapassign_fast32` 相似，但是它的键类型是 `unsafe.Pointer`。  根据注释，这可能是为了兼容一些广泛使用的包通过 `linkname` 访问内部函数而存在的。虽然参数是 `unsafe.Pointer`，但其内部逻辑仍然按照 `uint32` 的大小（4字节）来处理键。
5. **`mapdelete_fast32(t *maptype, h *hmap, key uint32)`**: 实现对 `map` 的删除操作，根据给定的键 `key` 从 `map` 中移除对应的键值对。
6. **`growWork_fast32(t *maptype, h *hmap, bucket uintptr)`**:  在 `map` 扩容时执行部分工作。当访问某个 `bucket` 时，会尝试迁移（evacuate）旧的 `bucket` 到新的存储位置。
7. **`evacuate_fast32(t *maptype, h *hmap, oldbucket uintptr)`**:  实现 `map` 扩容时的核心迁移逻辑，将旧的 `bucket` 中的键值对移动到新的 `bucket` 中。

**Go 语言功能推理和代码示例:**

这段代码是 Go 语言 `map` 数据结构底层实现的一部分，用于处理键类型为 `uint32` 的 `map` 的基本操作：读取、写入、删除，以及扩容。

```go
package main

import "fmt"

func main() {
	// 假设这是 runtime 内部使用的 map 类型和结构
	type maptype struct {
		// ... 其他字段
		BucketSize uintptr
		ValueSize  uintptr
		Hasher     func(unsafe.Pointer, uintptr) uintptr
		Key        struct{ Size_ uintptr }
		Elem       struct{ Size_ uintptr; Pointers func() bool }
		Bucket     unsafe.Pointer
	}

	type hmap struct {
		count     int
		flags     uint8
		B         uint8
		noverflow uint16
		hash0     uint32
		buckets   unsafe.Pointer
		oldbuckets unsafe.Pointer
		nevacuate uintptr
		// ... 其他字段
	}

	// 假设的 zeroVal
	var zeroVal [0]byte

	// 假设的常量
	const (
		bucketCnt         = 8
		dataOffset        = unsafe.Sizeof(struct{ tophash [bucketCnt]uint8 }{})
		hashWriting       = 1 << 0
		emptyRest         = 0
		emptyOne          = 1
		evacuatedX        = 2
		evacuatedY        = 3
		minTopHash        = 5
		oldIterator       = 1 << 1
	)

	// 假设的辅助函数
	bucketMask := func(b uint8) uintptr {
		return (1 << b) - 1
	}
	add := func(p unsafe.Pointer, x uintptr) unsafe.Pointer {
		return unsafe.Pointer(uintptr(p) + x)
	}
	isEmpty := func(x uint8) bool {
		return x <= emptyOne
	}
	tophash := func(hash uintptr) uint8 {
		top := hash >> (goarch.PtrSize * 8 - 8)
		if top < minTopHash {
			top += minTopHash
		}
		return uint8(top)
	}
	evacuated := func(b unsafe.Pointer) bool {
		return b == nil || (*[bucketCnt]uint8)(add(b, 0))[0] > emptyOne
	}
	overLoadFactor := func(count int, B uint8) bool {
		return count > bucketCnt && uintptr(count) > loadFactorNum*(bucketMask(B)+1)/loadFactorDen
	}
	tooManyOverflowBuckets := func(noverflow uint16, B uint8) bool {
		if B > 15 {
			return noverflow > 32768
		}
		return noverflow >= 1<<(B-4)
	}
	newobject := func(typ unsafe.Pointer) unsafe.Pointer {
		// 假设的分配内存函数
		return nil
	}
	memclrHasPointers := func(p unsafe.Pointer, n uintptr) {}
	memclrNoHeapPointers := func(p unsafe.Pointer, n uintptr) {}
	typedmemmove := func(t unsafe.Pointer, dst unsafe.Pointer, src unsafe.Pointer) {}
	plainError := func(s string) error { return fmt.Errorf(s) }
	fatal := func(s string) { panic(s) }
	noescape := func(p unsafe.Pointer) unsafe.Pointer { return p }
	growWork_fast32 := func(t *maptype, h *hmap, bucket uintptr) {}
	hashGrow := func(t *maptype, h *hmap) {}
	advanceEvacuationMark := func(h *hmap, t *maptype, newbit uintptr) {}
	bucketOf := func(t *maptype, h *hmap, key unsafe.Pointer) uintptr {
		hash := t.Hasher(key, uintptr(h.hash0))
		return uintptr(hash) & bucketMask(h.B)
	}
	newoverflow := func(t *maptype, b *bmap) *bmap {
		// 假设的分配 overflow bucket 的函数
		return nil
	}

	// 假设的 goarch 包提供的常量
	var goarch struct {
		PtrSize int
	}

	// 假设的内部结构体 bmap
	type bmap struct {
		tophash  [bucketCnt]uint8
		// 后面是 keys 和 values，根据类型大小动态排列
		overflow uintptr // 指向溢出桶
	}

	overflow := func(b *bmap, t *maptype) *bmap {
		return (*bmap)(unsafe.Pointer(b.overflow))
	}
	keys := func(b *bmap) unsafe.Pointer {
		return add(unsafe.Pointer(b), dataOffset)
	}

	// 示例用法
	var t maptype
	t.BucketSize = unsafe.Sizeof(bmap{})
	t.ValueSize = unsafe.Sizeof(int(0)) // 假设 value 是 int
	t.Key.Size_ = unsafe.Sizeof(uint32(0))
	t.Elem.Size_ = t.ValueSize
	t.Elem.Pointers = func() bool { return false }
	t.Hasher = func(p unsafe.Pointer, seed uintptr) uintptr {
		// 简单的 hash 函数示例，实际 runtime 中更复杂
		key := *(*uint32)(p)
		return uintptr(key*131 + uint32(seed))
	}
	goarch.PtrSize = 8 // 假设是 64 位架构

	h := &hmap{
		B:     4, // 初始 2^4 = 16 个 bucket
		hash0: 12345,
		buckets: newobject(unsafe.Pointer(t.Bucket)),
	}

	key1 := uint32(10)
	val1 := 100
	key2 := uint32(20)
	val2 := 200

	// 写入 map
	ptr1 := mapassign_fast32(&t, h, key1)
	*(*int)(ptr1) = val1

	ptr2 := mapassign_fast32(&t, h, key2)
	*(*int)(ptr2) = val2

	// 读取 map
	readPtr1 := mapaccess1_fast32(&t, h, key1)
	if readPtr1 != unsafe.Pointer(&zeroVal[0]) {
		fmt.Println("Key:", key1, "Value:", *(*int)(readPtr1)) // Output: Key: 10 Value: 100
	}

	readPtr2, ok := mapaccess2_fast32(&t, h, key2)
	if ok {
		fmt.Println("Key:", key2, "Value:", *(*int)(readPtr2)) // Output: Key: 20 Value: 200
	}

	// 删除 map 中的元素
	mapdelete_fast32(&t, h, key1)

	readPtr1AfterDelete, okAfterDelete := mapaccess2_fast32(&t, h, key1)
	fmt.Println("Key:", key1, "Exists after delete:", okAfterDelete) // Output: Key: 10 Exists after delete: false
	_ = readPtr1AfterDelete // 避免 unused variable 报错
}
```

**代码解释:**

上面的代码示例中，我们模拟了 `maptype` 和 `hmap` 的结构，以及一些相关的辅助函数。虽然这只是一个简化的模拟，但它展示了 `mapaccess1_fast32`、`mapaccess2_fast32`、`mapassign_fast32` 和 `mapdelete_fast32` 这些函数的基本使用方式。

*   **写入 (mapassign\_fast32):**  通过 `mapassign_fast32` 找到或分配存储 `key` 对应值的内存地址，并将值写入该地址。
*   **读取 (mapaccess1\_fast32, mapaccess2\_fast32):** 通过 `mapaccess` 函数根据 `key` 计算哈希，找到对应的 bucket，然后在 bucket 中查找 `key`，如果找到则返回值的地址（`mapaccess2_fast32` 还会返回 `true` 表示找到）。
*   **删除 (mapdelete\_fast32):**  通过 `mapdelete_fast32` 根据 `key` 找到对应的 bucket 和 entry，然后清除该 entry 的键值信息。

**`mapassign_fast32ptr` 的特殊性:**

`mapassign_fast32ptr` 的存在主要是为了兼容性和优化。由于 Go 语言的一些包可能通过 `//go:linkname` 直接链接到 runtime 的内部函数，因此需要提供这个函数。尽管它的参数是 `unsafe.Pointer`，但由于其内部逻辑是针对 `uint32` 优化的，它实际上会将传入的指针转换为 `uint32` 来处理。这是一种为了在特定场景下复用代码和保持性能的技巧。

**命令行参数处理:**

这段代码是 Go 语言的运行时实现，它本身并不直接处理命令行参数。命令行参数的处理通常发生在 `main` 包的 `main` 函数中，或者通过 `flag` 等标准库进行解析。`runtime` 模块主要负责底层的内存管理、 Goroutine 调度、以及数据结构的实现。

**使用者易犯错的点:**

1. **并发读写 `map` 但没有进行适当的同步:**  Go 的 `map` 在没有外部同步机制的情况下，进行并发的读写操作是 **不安全** 的。这段代码内部虽然有 `h.flags&hashWriting != 0` 的检查来避免 *runtime* 内部的并发写冲突，但这并不能阻止用户代码在多个 Goroutine 中同时读写同一个 `map` 导致的数据竞争。

    ```go
    package main

    import (
    	"fmt"
    	"sync"
    )

    func main() {
    	m := make(map[uint32]int)
    	var wg sync.WaitGroup

    	// 多个 Goroutine 并发写入 map
    	for i := 0; i < 100; i++ {
    		wg.Add(1)
    		go func(key uint32) {
    			defer wg.Done()
    			m[key] = int(key * 2) // 并发写，可能导致数据竞争
    		}(uint32(i))
    	}

    	wg.Wait()
    	fmt.Println(m) // 输出结果可能不确定
    }
    ```

    **正确做法是使用 `sync.Mutex` 或 `sync.RWMutex` 进行同步，或者使用并发安全的 `sync.Map`。**

2. **假设 `map` 的迭代顺序是固定的:** Go 的 `map` 在迭代时，元素的顺序是 **无序的** 且可能每次运行都不同。依赖 `map` 的迭代顺序会导致程序出现不可预测的行为。

    ```go
    package main

    import "fmt"

    func main() {
    	m := map[uint32]string{
    		1: "one",
    		2: "two",
    		3: "three",
    	}

    	// 错误的假设：迭代顺序总是 1, 2, 3
    	for k, v := range m {
    		fmt.Println(k, v)
    	}
    }
    ```

    **应该避免依赖 `map` 的迭代顺序，如果需要有序的键值对，可以使用 `slice` 或其他有序的数据结构。**

总而言之，这段代码是 Go 语言 `map` 底层实现的关键部分，它提供了针对 `uint32` 键类型的优化操作。理解其功能有助于深入了解 Go 语言 `map` 的工作原理。

### 提示词
```
这是路径为go/src/runtime/map_fast32_noswiss.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
```

### 源代码
```go
// Copyright 2018 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build !goexperiment.swissmap

package runtime

import (
	"internal/abi"
	"internal/goarch"
	"internal/runtime/sys"
	"unsafe"
)

func mapaccess1_fast32(t *maptype, h *hmap, key uint32) unsafe.Pointer {
	if raceenabled && h != nil {
		callerpc := sys.GetCallerPC()
		racereadpc(unsafe.Pointer(h), callerpc, abi.FuncPCABIInternal(mapaccess1_fast32))
	}
	if h == nil || h.count == 0 {
		return unsafe.Pointer(&zeroVal[0])
	}
	if h.flags&hashWriting != 0 {
		fatal("concurrent map read and map write")
	}
	var b *bmap
	if h.B == 0 {
		// One-bucket table. No need to hash.
		b = (*bmap)(h.buckets)
	} else {
		hash := t.Hasher(noescape(unsafe.Pointer(&key)), uintptr(h.hash0))
		m := bucketMask(h.B)
		b = (*bmap)(add(h.buckets, (hash&m)*uintptr(t.BucketSize)))
		if c := h.oldbuckets; c != nil {
			if !h.sameSizeGrow() {
				// There used to be half as many buckets; mask down one more power of two.
				m >>= 1
			}
			oldb := (*bmap)(add(c, (hash&m)*uintptr(t.BucketSize)))
			if !evacuated(oldb) {
				b = oldb
			}
		}
	}
	for ; b != nil; b = b.overflow(t) {
		for i, k := uintptr(0), b.keys(); i < abi.OldMapBucketCount; i, k = i+1, add(k, 4) {
			if *(*uint32)(k) == key && !isEmpty(b.tophash[i]) {
				return add(unsafe.Pointer(b), dataOffset+abi.OldMapBucketCount*4+i*uintptr(t.ValueSize))
			}
		}
	}
	return unsafe.Pointer(&zeroVal[0])
}

// mapaccess2_fast32 should be an internal detail,
// but widely used packages access it using linkname.
// Notable members of the hall of shame include:
//   - github.com/ugorji/go/codec
//
// Do not remove or change the type signature.
// See go.dev/issue/67401.
//
//go:linkname mapaccess2_fast32
func mapaccess2_fast32(t *maptype, h *hmap, key uint32) (unsafe.Pointer, bool) {
	if raceenabled && h != nil {
		callerpc := sys.GetCallerPC()
		racereadpc(unsafe.Pointer(h), callerpc, abi.FuncPCABIInternal(mapaccess2_fast32))
	}
	if h == nil || h.count == 0 {
		return unsafe.Pointer(&zeroVal[0]), false
	}
	if h.flags&hashWriting != 0 {
		fatal("concurrent map read and map write")
	}
	var b *bmap
	if h.B == 0 {
		// One-bucket table. No need to hash.
		b = (*bmap)(h.buckets)
	} else {
		hash := t.Hasher(noescape(unsafe.Pointer(&key)), uintptr(h.hash0))
		m := bucketMask(h.B)
		b = (*bmap)(add(h.buckets, (hash&m)*uintptr(t.BucketSize)))
		if c := h.oldbuckets; c != nil {
			if !h.sameSizeGrow() {
				// There used to be half as many buckets; mask down one more power of two.
				m >>= 1
			}
			oldb := (*bmap)(add(c, (hash&m)*uintptr(t.BucketSize)))
			if !evacuated(oldb) {
				b = oldb
			}
		}
	}
	for ; b != nil; b = b.overflow(t) {
		for i, k := uintptr(0), b.keys(); i < abi.OldMapBucketCount; i, k = i+1, add(k, 4) {
			if *(*uint32)(k) == key && !isEmpty(b.tophash[i]) {
				return add(unsafe.Pointer(b), dataOffset+abi.OldMapBucketCount*4+i*uintptr(t.ValueSize)), true
			}
		}
	}
	return unsafe.Pointer(&zeroVal[0]), false
}

// mapassign_fast32 should be an internal detail,
// but widely used packages access it using linkname.
// Notable members of the hall of shame include:
//   - github.com/bytedance/sonic
//   - github.com/ugorji/go/codec
//
// Do not remove or change the type signature.
// See go.dev/issue/67401.
//
//go:linkname mapassign_fast32
func mapassign_fast32(t *maptype, h *hmap, key uint32) unsafe.Pointer {
	if h == nil {
		panic(plainError("assignment to entry in nil map"))
	}
	if raceenabled {
		callerpc := sys.GetCallerPC()
		racewritepc(unsafe.Pointer(h), callerpc, abi.FuncPCABIInternal(mapassign_fast32))
	}
	if h.flags&hashWriting != 0 {
		fatal("concurrent map writes")
	}
	hash := t.Hasher(noescape(unsafe.Pointer(&key)), uintptr(h.hash0))

	// Set hashWriting after calling t.hasher for consistency with mapassign.
	h.flags ^= hashWriting

	if h.buckets == nil {
		h.buckets = newobject(t.Bucket) // newarray(t.bucket, 1)
	}

again:
	bucket := hash & bucketMask(h.B)
	if h.growing() {
		growWork_fast32(t, h, bucket)
	}
	b := (*bmap)(add(h.buckets, bucket*uintptr(t.BucketSize)))

	var insertb *bmap
	var inserti uintptr
	var insertk unsafe.Pointer

bucketloop:
	for {
		for i := uintptr(0); i < abi.OldMapBucketCount; i++ {
			if isEmpty(b.tophash[i]) {
				if insertb == nil {
					inserti = i
					insertb = b
				}
				if b.tophash[i] == emptyRest {
					break bucketloop
				}
				continue
			}
			k := *((*uint32)(add(unsafe.Pointer(b), dataOffset+i*4)))
			if k != key {
				continue
			}
			inserti = i
			insertb = b
			goto done
		}
		ovf := b.overflow(t)
		if ovf == nil {
			break
		}
		b = ovf
	}

	// Did not find mapping for key. Allocate new cell & add entry.

	// If we hit the max load factor or we have too many overflow buckets,
	// and we're not already in the middle of growing, start growing.
	if !h.growing() && (overLoadFactor(h.count+1, h.B) || tooManyOverflowBuckets(h.noverflow, h.B)) {
		hashGrow(t, h)
		goto again // Growing the table invalidates everything, so try again
	}

	if insertb == nil {
		// The current bucket and all the overflow buckets connected to it are full, allocate a new one.
		insertb = h.newoverflow(t, b)
		inserti = 0 // not necessary, but avoids needlessly spilling inserti
	}
	insertb.tophash[inserti&(abi.OldMapBucketCount-1)] = tophash(hash) // mask inserti to avoid bounds checks

	insertk = add(unsafe.Pointer(insertb), dataOffset+inserti*4)
	// store new key at insert position
	*(*uint32)(insertk) = key

	h.count++

done:
	elem := add(unsafe.Pointer(insertb), dataOffset+abi.OldMapBucketCount*4+inserti*uintptr(t.ValueSize))
	if h.flags&hashWriting == 0 {
		fatal("concurrent map writes")
	}
	h.flags &^= hashWriting
	return elem
}

// mapassign_fast32ptr should be an internal detail,
// but widely used packages access it using linkname.
// Notable members of the hall of shame include:
//   - github.com/ugorji/go/codec
//
// Do not remove or change the type signature.
// See go.dev/issue/67401.
//
//go:linkname mapassign_fast32ptr
func mapassign_fast32ptr(t *maptype, h *hmap, key unsafe.Pointer) unsafe.Pointer {
	if h == nil {
		panic(plainError("assignment to entry in nil map"))
	}
	if raceenabled {
		callerpc := sys.GetCallerPC()
		racewritepc(unsafe.Pointer(h), callerpc, abi.FuncPCABIInternal(mapassign_fast32))
	}
	if h.flags&hashWriting != 0 {
		fatal("concurrent map writes")
	}
	hash := t.Hasher(noescape(unsafe.Pointer(&key)), uintptr(h.hash0))

	// Set hashWriting after calling t.hasher for consistency with mapassign.
	h.flags ^= hashWriting

	if h.buckets == nil {
		h.buckets = newobject(t.Bucket) // newarray(t.bucket, 1)
	}

again:
	bucket := hash & bucketMask(h.B)
	if h.growing() {
		growWork_fast32(t, h, bucket)
	}
	b := (*bmap)(add(h.buckets, bucket*uintptr(t.BucketSize)))

	var insertb *bmap
	var inserti uintptr
	var insertk unsafe.Pointer

bucketloop:
	for {
		for i := uintptr(0); i < abi.OldMapBucketCount; i++ {
			if isEmpty(b.tophash[i]) {
				if insertb == nil {
					inserti = i
					insertb = b
				}
				if b.tophash[i] == emptyRest {
					break bucketloop
				}
				continue
			}
			k := *((*unsafe.Pointer)(add(unsafe.Pointer(b), dataOffset+i*4)))
			if k != key {
				continue
			}
			inserti = i
			insertb = b
			goto done
		}
		ovf := b.overflow(t)
		if ovf == nil {
			break
		}
		b = ovf
	}

	// Did not find mapping for key. Allocate new cell & add entry.

	// If we hit the max load factor or we have too many overflow buckets,
	// and we're not already in the middle of growing, start growing.
	if !h.growing() && (overLoadFactor(h.count+1, h.B) || tooManyOverflowBuckets(h.noverflow, h.B)) {
		hashGrow(t, h)
		goto again // Growing the table invalidates everything, so try again
	}

	if insertb == nil {
		// The current bucket and all the overflow buckets connected to it are full, allocate a new one.
		insertb = h.newoverflow(t, b)
		inserti = 0 // not necessary, but avoids needlessly spilling inserti
	}
	insertb.tophash[inserti&(abi.OldMapBucketCount-1)] = tophash(hash) // mask inserti to avoid bounds checks

	insertk = add(unsafe.Pointer(insertb), dataOffset+inserti*4)
	// store new key at insert position
	*(*unsafe.Pointer)(insertk) = key

	h.count++

done:
	elem := add(unsafe.Pointer(insertb), dataOffset+abi.OldMapBucketCount*4+inserti*uintptr(t.ValueSize))
	if h.flags&hashWriting == 0 {
		fatal("concurrent map writes")
	}
	h.flags &^= hashWriting
	return elem
}

func mapdelete_fast32(t *maptype, h *hmap, key uint32) {
	if raceenabled && h != nil {
		callerpc := sys.GetCallerPC()
		racewritepc(unsafe.Pointer(h), callerpc, abi.FuncPCABIInternal(mapdelete_fast32))
	}
	if h == nil || h.count == 0 {
		return
	}
	if h.flags&hashWriting != 0 {
		fatal("concurrent map writes")
	}

	hash := t.Hasher(noescape(unsafe.Pointer(&key)), uintptr(h.hash0))

	// Set hashWriting after calling t.hasher for consistency with mapdelete
	h.flags ^= hashWriting

	bucket := hash & bucketMask(h.B)
	if h.growing() {
		growWork_fast32(t, h, bucket)
	}
	b := (*bmap)(add(h.buckets, bucket*uintptr(t.BucketSize)))
	bOrig := b
search:
	for ; b != nil; b = b.overflow(t) {
		for i, k := uintptr(0), b.keys(); i < abi.OldMapBucketCount; i, k = i+1, add(k, 4) {
			if key != *(*uint32)(k) || isEmpty(b.tophash[i]) {
				continue
			}
			// Only clear key if there are pointers in it.
			// This can only happen if pointers are 32 bit
			// wide as 64 bit pointers do not fit into a 32 bit key.
			if goarch.PtrSize == 4 && t.Key.Pointers() {
				// The key must be a pointer as we checked pointers are
				// 32 bits wide and the key is 32 bits wide also.
				*(*unsafe.Pointer)(k) = nil
			}
			e := add(unsafe.Pointer(b), dataOffset+abi.OldMapBucketCount*4+i*uintptr(t.ValueSize))
			if t.Elem.Pointers() {
				memclrHasPointers(e, t.Elem.Size_)
			} else {
				memclrNoHeapPointers(e, t.Elem.Size_)
			}
			b.tophash[i] = emptyOne
			// If the bucket now ends in a bunch of emptyOne states,
			// change those to emptyRest states.
			if i == abi.OldMapBucketCount-1 {
				if b.overflow(t) != nil && b.overflow(t).tophash[0] != emptyRest {
					goto notLast
				}
			} else {
				if b.tophash[i+1] != emptyRest {
					goto notLast
				}
			}
			for {
				b.tophash[i] = emptyRest
				if i == 0 {
					if b == bOrig {
						break // beginning of initial bucket, we're done.
					}
					// Find previous bucket, continue at its last entry.
					c := b
					for b = bOrig; b.overflow(t) != c; b = b.overflow(t) {
					}
					i = abi.OldMapBucketCount - 1
				} else {
					i--
				}
				if b.tophash[i] != emptyOne {
					break
				}
			}
		notLast:
			h.count--
			// Reset the hash seed to make it more difficult for attackers to
			// repeatedly trigger hash collisions. See issue 25237.
			if h.count == 0 {
				h.hash0 = uint32(rand())
			}
			break search
		}
	}

	if h.flags&hashWriting == 0 {
		fatal("concurrent map writes")
	}
	h.flags &^= hashWriting
}

func growWork_fast32(t *maptype, h *hmap, bucket uintptr) {
	// make sure we evacuate the oldbucket corresponding
	// to the bucket we're about to use
	evacuate_fast32(t, h, bucket&h.oldbucketmask())

	// evacuate one more oldbucket to make progress on growing
	if h.growing() {
		evacuate_fast32(t, h, h.nevacuate)
	}
}

func evacuate_fast32(t *maptype, h *hmap, oldbucket uintptr) {
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
		x.e = add(x.k, abi.OldMapBucketCount*4)

		if !h.sameSizeGrow() {
			// Only calculate y pointers if we're growing bigger.
			// Otherwise GC can see bad pointers.
			y := &xy[1]
			y.b = (*bmap)(add(h.buckets, (oldbucket+newbit)*uintptr(t.BucketSize)))
			y.k = add(unsafe.Pointer(y.b), dataOffset)
			y.e = add(y.k, abi.OldMapBucketCount*4)
		}

		for ; b != nil; b = b.overflow(t) {
			k := add(unsafe.Pointer(b), dataOffset)
			e := add(k, abi.OldMapBucketCount*4)
			for i := 0; i < abi.OldMapBucketCount; i, k, e = i+1, add(k, 4), add(e, uintptr(t.ValueSize)) {
				top := b.tophash[i]
				if isEmpty(top) {
					b.tophash[i] = evacuatedEmpty
					continue
				}
				if top < minTopHash {
					throw("bad map state")
				}
				var useY uint8
				if !h.sameSizeGrow() {
					// Compute hash to make our evacuation decision (whether we need
					// to send this key/elem to bucket x or bucket y).
					hash := t.Hasher(k, uintptr(h.hash0))
					if hash&newbit != 0 {
						useY = 1
					}
				}

				b.tophash[i] = evacuatedX + useY // evacuatedX + 1 == evacuatedY, enforced in makemap
				dst := &xy[useY]                 // evacuation destination

				if dst.i == abi.OldMapBucketCount {
					dst.b = h.newoverflow(t, dst.b)
					dst.i = 0
					dst.k = add(unsafe.Pointer(dst.b), dataOffset)
					dst.e = add(dst.k, abi.OldMapBucketCount*4)
				}
				dst.b.tophash[dst.i&(abi.OldMapBucketCount-1)] = top // mask dst.i as an optimization, to avoid a bounds check

				// Copy key.
				if goarch.PtrSize == 4 && t.Key.Pointers() && writeBarrier.enabled {
					// Write with a write barrier.
					*(*unsafe.Pointer)(dst.k) = *(*unsafe.Pointer)(k)
				} else {
					*(*uint32)(dst.k) = *(*uint32)(k)
				}

				typedmemmove(t.Elem, dst.e, e)
				dst.i++
				// These updates might push these pointers past the end of the
				// key or elem arrays.  That's ok, as we have the overflow pointer
				// at the end of the bucket to protect against pointing past the
				// end of the bucket.
				dst.k = add(dst.k, 4)
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
```