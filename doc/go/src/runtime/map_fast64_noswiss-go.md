Response:
The user wants to understand the functionality of the provided Go code snippet, which is part of the `runtime` package and specifically deals with map operations for `uint64` keys.

Here's a breakdown of the thought process to answer the request:

1. **Identify the Core Functions:** The code defines several functions related to map access, assignment, and deletion: `mapaccess1_fast64`, `mapaccess2_fast64`, `mapassign_fast64`, `mapassign_fast64ptr`, `mapdelete_fast64`, `growWork_fast64`, and `evacuate_fast64`. The naming suggests these are optimized versions for maps with `uint64` keys.

2. **Analyze Each Function's Purpose:**
    * `mapaccess1_fast64`: Likely returns the value associated with a given key in the map, or a zero value if the key is not found.
    * `mapaccess2_fast64`: Similar to `mapaccess1_fast64`, but also returns a boolean indicating if the key was found. This is the standard way to check for key existence in Go maps.
    * `mapassign_fast64`: Assigns (or updates) a value for a given `uint64` key in the map.
    * `mapassign_fast64ptr`: Similar to `mapassign_fast64`, but takes a `unsafe.Pointer` as the key. This might be used when the key is not directly a `uint64` but resides in memory pointed to by the `unsafe.Pointer`.
    * `mapdelete_fast64`: Deletes an entry from the map based on its `uint64` key.
    * `growWork_fast64`: Seems to be involved in the map's growth mechanism, likely handling the movement of data during resizing.
    * `evacuate_fast64`:  Also related to map growth, likely responsible for moving data from old buckets to new buckets during resizing.

3. **Infer the Overall Functionality:** Based on the individual function purposes, the code snippet implements the core read, write, and delete operations for Go maps where the key type is `uint64`. The `_fast64` suffix strongly suggests it's an optimized path for this specific key type.

4. **Connect to Go Map Concepts:** Relate the code to general Go map concepts:
    * **`hmap`:** The central map data structure.
    * **`bmap` (bucket):** The unit of storage within the map.
    * **Hashing:** The `Hasher` function is used to determine the bucket for a given key.
    * **Load Factor and Growth:** The code includes logic for checking the load factor and triggering map growth when necessary.
    * **Overflow Buckets:** The linked list of buckets to handle hash collisions.
    * **Evacuation:** The process of moving data during map resizing.
    * **Concurrency Control:** The checks for `hashWriting` flag indicate a mechanism to prevent concurrent writes.

5. **Provide Go Code Examples:** Illustrate the usage of the inferred functions. Since these functions are internal and accessed via `//go:linkname`, direct usage is not idiomatic Go. Therefore, demonstrate the equivalent standard Go map operations that these functions underpin. This involves creating a map with `uint64` keys and showing how to access, assign, and delete elements.

6. **Address Code Reasoning (Input/Output):**  For the code reasoning part, focus on the core logic of `mapaccess1_fast64` as an example. Trace the steps involved in finding a key, including the initial bucket calculation, handling map growth, and iterating through buckets and overflow buckets. Define example inputs (a map and a key) and the expected output (the value or a zero value).

7. **Consider Command-Line Parameters:** Since this is core runtime code, it's unlikely to directly involve command-line parameters in the typical sense. However, mention the `go:build` directive at the top, which controls conditional compilation based on build tags (like `!goexperiment.swissmap`). This indirectly relates to build-time configuration.

8. **Identify Potential Pitfalls:**  Highlight common mistakes users might make when working with maps, even though they aren't directly calling these `_fast64` functions. These include:
    * Reading/writing nil maps (handled by panics in the code).
    * Concurrent map access without proper synchronization (the code has checks, but users need to understand the limitations of Go's built-in map concurrency).

9. **Structure the Answer:** Organize the information logically, addressing each part of the user's request clearly. Use headings and bullet points for better readability. Explain technical terms where necessary.

10. **Review and Refine:**  Read through the generated answer to ensure accuracy, clarity, and completeness. Make any necessary corrections or additions. For instance, initially, I might have focused too much on the low-level details of bucket manipulation. Refining the answer would involve stepping back and explaining the high-level purpose and then connecting the low-level details to it. Also, ensure the Go code examples are correct and relevant.
这段代码是 Go 语言运行时（runtime）包中关于 `map` 类型操作的优化实现，专门针对键类型为 `uint64` 且没有使用 `swissmap` 特性的情况。

**功能列举：**

这段代码实现了以下几个核心功能，用于操作键类型为 `uint64` 的 Go map：

1. **`mapaccess1_fast64(t *maptype, h *hmap, key uint64) unsafe.Pointer`:**
   - **查找 map 中的元素并返回其值地址。** 如果找到键 `key`，则返回对应值的内存地址。
   - **处理并发读写检测。**  如果开启了 `raceenabled`，会检查是否存在并发读取。如果检测到并发写入，会触发 `fatal` 错误。
   - **处理 nil map 或空 map。** 如果 map 为 `nil` 或 `count` 为 0，则返回零值的地址。
   - **处理 map 扩容时的查找。** 如果 map 正在扩容，会同时在旧的 buckets 和新的 buckets 中查找。
   - **遍历 bucket 和 overflow bucket。**  根据哈希值找到对应的 bucket，然后遍历该 bucket 和其 overflow 链表来查找键。

2. **`mapaccess2_fast64(t *maptype, h *hmap, key uint64) (unsafe.Pointer, bool)`:**
   - **查找 map 中的元素并返回其值地址和一个布尔值指示是否找到。**  这是 Go 中常用的 map 查找方式，通过返回的布尔值来判断键是否存在。
   - **其他功能与 `mapaccess1_fast64` 类似。**

3. **`mapassign_fast64(t *maptype, h *hmap, key uint64) unsafe.Pointer`:**
   - **向 map 中插入或更新键值对。**  如果键 `key` 存在，则更新其值；如果不存在，则插入新的键值对。
   - **处理并发写检测。** 如果开启了 `raceenabled`，会检查是否存在并发写入，如果检测到并发写入，会触发 `fatal` 错误。
   - **处理 nil map 赋值。** 如果 map 为 `nil`，会触发 `panic`。
   - **计算哈希值并找到对应的 bucket。**
   - **处理 map 扩容时的插入。** 如果 map 正在扩容，会先进行 `growWork_fast64` 操作。
   - **在 bucket 或 overflow bucket 中查找空位或已存在的键。**
   - **处理 map 达到负载因子时的扩容。** 如果达到负载因子或 overflow bucket 过多，会触发 `hashGrow` 进行扩容。
   - **返回插入或更新的元素的地址。**

4. **`mapassign_fast64ptr(t *maptype, h *hmap, key unsafe.Pointer) unsafe.Pointer`:**
   - **与 `mapassign_fast64` 功能类似，但接收的键是指向 `uint64` 的指针。**  这可能用于某些特殊场景，例如键不是直接存储在栈上，而是通过指针传递。

5. **`mapdelete_fast64(t *maptype, h *hmap, key uint64)`:**
   - **从 map 中删除指定的键值对。**
   - **处理并发写检测。**
   - **处理 nil map 或空 map 删除。**  如果 map 为 `nil` 或 `count` 为 0，则直接返回。
   - **计算哈希值并找到对应的 bucket。**
   - **处理 map 扩容时的删除。**
   - **在 bucket 或 overflow bucket 中查找并删除键值对。**
   - **清除键和值所占用的内存（如果类型包含指针）。**
   - **调整 bucket 的 `tophash` 状态。**

6. **`growWork_fast64(t *maptype, h *hmap, bucket uintptr)`:**
   - **在 map 扩容期间执行部分工作。**  当访问或修改 map 时，如果 map 正在扩容，会调用此函数来帮助完成扩容过程。
   - **负责将旧的 bucket 中的数据迁移到新的 bucket 中。**  会调用 `evacuate_fast64` 来完成迁移。

7. **`evacuate_fast64(t *maptype, h *hmap, oldbucket uintptr)`:**
   - **将旧的 bucket 中的键值对迁移到新的 bucket 中。** 这是 map 扩容的核心步骤。
   - **区分等大小扩容和双倍大小扩容，并根据新的哈希值将数据迁移到对应的新的 bucket。**
   - **处理 overflow bucket 的迁移。**
   - **在迁移完成后，清理旧 bucket 的数据，以便 GC 回收。**

**它是什么 Go 语言功能的实现：**

这段代码是 Go 语言中 `map` 数据结构在特定条件下的底层实现。更具体地说，它是当 map 的键类型是 `uint64` 且编译时没有启用 `swissmap` 特性时的优化实现。

**Go 代码举例说明：**

```go
package main

import "fmt"

func main() {
	m := make(map[uint64]string)

	// 插入元素
	m[10] = "value10"
	m[20] = "value20"

	// 查找元素
	val1, ok1 := m[10]
	fmt.Println("查找键 10:", val1, ok1) // 输出: 查找键 10: value10 true

	val2, ok2 := m[30]
	fmt.Println("查找键 30:", val2, ok2) // 输出: 查找键 30:  false

	// 更新元素
	m[10] = "newValue10"
	fmt.Println("更新后查找键 10:", m[10]) // 输出: 更新后查找键 10: newValue10

	// 删除元素
	delete(m, 20)
	val3, ok3 := m[20]
	fmt.Println("删除后查找键 20:", val3, ok3) // 输出: 删除后查找键 20:  false
}
```

**假设的输入与输出（针对 `mapaccess1_fast64`）：**

假设我们有以下 map 和查找键：

**输入：**

- `t`: 指向 `map[uint64]string` 类型的 `maptype` 结构体的指针。
- `h`: 指向上面创建的 map 的 `hmap` 结构体的指针，其中包含键值对 `10: "value10"` 和 `20: "value20"`。
- `key`: `uint64` 类型的键，例如 `uint64(10)`。

**输出：**

- 如果 `key` 为 `10`，则输出是指向字符串 `"value10"` 的 `unsafe.Pointer`。
- 如果 `key` 为 `30`，则输出是指向 `zeroVal` 的 `unsafe.Pointer` (表示零值，对于字符串来说是空字符串)。

**代码推理：**

当 `mapaccess1_fast64` 被调用时，它会执行以下步骤（简化）：

1. **检查并发读写：** 如果启用了 race 检测，会进行检查。
2. **检查 nil 或空 map：** 如果 map 为 `nil` 或为空，直接返回零值地址。
3. **计算哈希值：** 使用 `t.Hasher` 计算 `key` 的哈希值。
4. **定位 bucket：** 根据哈希值和 map 的 bucket 数量 `h.B` 计算出 key 应该在哪个 bucket 中。
5. **处理扩容：** 如果 map 正在扩容，会先检查旧的 buckets。
6. **遍历 bucket 和 overflow：** 遍历目标 bucket 及其 overflow 链表。
7. **比较键：** 在每个 bucket 中，比较存储的键是否与要查找的 `key` 相等。同时检查 `tophash` 以确保该槽位已被占用。
8. **返回结果：** 如果找到匹配的键，则返回对应值的地址；否则，继续查找，直到遍历完所有相关的 buckets。如果最终没有找到，则返回零值的地址。

**命令行参数的具体处理：**

这段代码本身不直接处理命令行参数。但是，`//go:build !goexperiment.swissmap` 是一个构建约束（build constraint），它告诉 Go 编译器，只有在 `goexperiment.swissmap` 构建标签 **没有** 设置时，才编译这段代码。这是一种在编译时根据不同条件选择不同实现的机制。

你可以在使用 `go build` 或 `go run` 命令时通过 `-tags` 参数来设置构建标签。例如，如果要启用 `swissmap`，你可能会使用：

```bash
go build -tags=goexperiment.swissmap your_program.go
```

或者，在没有设置 `-tags` 时，这段 `map_fast64_noswiss.go` 中的代码会被编译。

**使用者易犯错的点：**

由于这段代码是 Go 运行时的内部实现，普通 Go 开发者通常不会直接与这些函数交互。他们通过标准的 Go map 操作（例如 `m[key]`, `m[key] = value`, `delete(m, key)`) 来间接使用这些底层实现。

但是，理解这些底层机制可以帮助开发者避免一些常见的 map 使用错误：

1. **并发读写未同步：**  虽然代码中有并发读写检测（通过 `raceenabled`），但 Go 的内置 map **不是** 并发安全的。如果在多个 goroutine 中并发地读写同一个 map，而没有使用互斥锁或其他同步机制进行保护，可能会导致程序崩溃或数据竞争。

   ```go
   package main

   import (
       "fmt"
       "sync"
   )

   func main() {
       m := make(map[uint64]int)
       var wg sync.WaitGroup

       // 错误示例：并发写入，可能导致 panic
       for i := 0; i < 100; i++ {
           wg.Add(1)
           go func(i int) {
               defer wg.Done()
               m[uint64(i)] = i
           }(i)
       }
       wg.Wait()
       fmt.Println(m)
   }
   ```

   **正确做法是使用 `sync.Mutex` 或 `sync.RWMutex` 来保护 map 的并发访问。**

2. **在迭代 map 的同时修改 map：**  在 Go 中，当你在使用 `for range` 迭代 map 的过程中修改 map（添加或删除元素）时，行为是未定义的，可能会导致程序崩溃或跳过某些元素。

   ```go
   package main

   import "fmt"

   func main() {
       m := map[int]string{1: "a", 2: "b", 3: "c"}
       for k := range m {
           if k == 2 {
               delete(m, k) // 在迭代时删除元素，行为未定义
           }
       }
       fmt.Println(m)
   }
   ```

   **如果需要在迭代时修改 map，一种常见的做法是将需要删除的键收集起来，然后在迭代完成后再进行删除。**

总而言之，这段代码是 Go 语言 map 底层实现的关键部分，它优化了 `uint64` 键类型的 map 操作，但开发者通常不需要直接调用这些函数，而是通过标准的 Go map 语法来使用。理解其内部机制有助于更好地理解 map 的性能特性和避免一些常见的并发问题。

Prompt: 
```
这是路径为go/src/runtime/map_fast64_noswiss.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。

"""
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

func mapaccess1_fast64(t *maptype, h *hmap, key uint64) unsafe.Pointer {
	if raceenabled && h != nil {
		callerpc := sys.GetCallerPC()
		racereadpc(unsafe.Pointer(h), callerpc, abi.FuncPCABIInternal(mapaccess1_fast64))
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
		for i, k := uintptr(0), b.keys(); i < abi.OldMapBucketCount; i, k = i+1, add(k, 8) {
			if *(*uint64)(k) == key && !isEmpty(b.tophash[i]) {
				return add(unsafe.Pointer(b), dataOffset+abi.OldMapBucketCount*8+i*uintptr(t.ValueSize))
			}
		}
	}
	return unsafe.Pointer(&zeroVal[0])
}

// mapaccess2_fast64 should be an internal detail,
// but widely used packages access it using linkname.
// Notable members of the hall of shame include:
//   - github.com/ugorji/go/codec
//
// Do not remove or change the type signature.
// See go.dev/issue/67401.
//
//go:linkname mapaccess2_fast64
func mapaccess2_fast64(t *maptype, h *hmap, key uint64) (unsafe.Pointer, bool) {
	if raceenabled && h != nil {
		callerpc := sys.GetCallerPC()
		racereadpc(unsafe.Pointer(h), callerpc, abi.FuncPCABIInternal(mapaccess2_fast64))
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
		for i, k := uintptr(0), b.keys(); i < abi.OldMapBucketCount; i, k = i+1, add(k, 8) {
			if *(*uint64)(k) == key && !isEmpty(b.tophash[i]) {
				return add(unsafe.Pointer(b), dataOffset+abi.OldMapBucketCount*8+i*uintptr(t.ValueSize)), true
			}
		}
	}
	return unsafe.Pointer(&zeroVal[0]), false
}

// mapassign_fast64 should be an internal detail,
// but widely used packages access it using linkname.
// Notable members of the hall of shame include:
//   - github.com/bytedance/sonic
//   - github.com/ugorji/go/codec
//
// Do not remove or change the type signature.
// See go.dev/issue/67401.
//
//go:linkname mapassign_fast64
func mapassign_fast64(t *maptype, h *hmap, key uint64) unsafe.Pointer {
	if h == nil {
		panic(plainError("assignment to entry in nil map"))
	}
	if raceenabled {
		callerpc := sys.GetCallerPC()
		racewritepc(unsafe.Pointer(h), callerpc, abi.FuncPCABIInternal(mapassign_fast64))
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
		growWork_fast64(t, h, bucket)
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
					insertb = b
					inserti = i
				}
				if b.tophash[i] == emptyRest {
					break bucketloop
				}
				continue
			}
			k := *((*uint64)(add(unsafe.Pointer(b), dataOffset+i*8)))
			if k != key {
				continue
			}
			insertb = b
			inserti = i
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

	insertk = add(unsafe.Pointer(insertb), dataOffset+inserti*8)
	// store new key at insert position
	*(*uint64)(insertk) = key

	h.count++

done:
	elem := add(unsafe.Pointer(insertb), dataOffset+abi.OldMapBucketCount*8+inserti*uintptr(t.ValueSize))
	if h.flags&hashWriting == 0 {
		fatal("concurrent map writes")
	}
	h.flags &^= hashWriting
	return elem
}

// mapassign_fast64ptr should be an internal detail,
// but widely used packages access it using linkname.
// Notable members of the hall of shame include:
//   - github.com/bytedance/sonic
//   - github.com/ugorji/go/codec
//
// Do not remove or change the type signature.
// See go.dev/issue/67401.
//
//go:linkname mapassign_fast64ptr
func mapassign_fast64ptr(t *maptype, h *hmap, key unsafe.Pointer) unsafe.Pointer {
	if h == nil {
		panic(plainError("assignment to entry in nil map"))
	}
	if raceenabled {
		callerpc := sys.GetCallerPC()
		racewritepc(unsafe.Pointer(h), callerpc, abi.FuncPCABIInternal(mapassign_fast64))
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
		growWork_fast64(t, h, bucket)
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
					insertb = b
					inserti = i
				}
				if b.tophash[i] == emptyRest {
					break bucketloop
				}
				continue
			}
			k := *((*unsafe.Pointer)(add(unsafe.Pointer(b), dataOffset+i*8)))
			if k != key {
				continue
			}
			insertb = b
			inserti = i
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

	insertk = add(unsafe.Pointer(insertb), dataOffset+inserti*8)
	// store new key at insert position
	*(*unsafe.Pointer)(insertk) = key

	h.count++

done:
	elem := add(unsafe.Pointer(insertb), dataOffset+abi.OldMapBucketCount*8+inserti*uintptr(t.ValueSize))
	if h.flags&hashWriting == 0 {
		fatal("concurrent map writes")
	}
	h.flags &^= hashWriting
	return elem
}

func mapdelete_fast64(t *maptype, h *hmap, key uint64) {
	if raceenabled && h != nil {
		callerpc := sys.GetCallerPC()
		racewritepc(unsafe.Pointer(h), callerpc, abi.FuncPCABIInternal(mapdelete_fast64))
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
		growWork_fast64(t, h, bucket)
	}
	b := (*bmap)(add(h.buckets, bucket*uintptr(t.BucketSize)))
	bOrig := b
search:
	for ; b != nil; b = b.overflow(t) {
		for i, k := uintptr(0), b.keys(); i < abi.OldMapBucketCount; i, k = i+1, add(k, 8) {
			if key != *(*uint64)(k) || isEmpty(b.tophash[i]) {
				continue
			}
			// Only clear key if there are pointers in it.
			if t.Key.Pointers() {
				if goarch.PtrSize == 8 {
					*(*unsafe.Pointer)(k) = nil
				} else {
					// There are three ways to squeeze at one or more 32 bit pointers into 64 bits.
					// Just call memclrHasPointers instead of trying to handle all cases here.
					memclrHasPointers(k, 8)
				}
			}
			e := add(unsafe.Pointer(b), dataOffset+abi.OldMapBucketCount*8+i*uintptr(t.ValueSize))
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

func growWork_fast64(t *maptype, h *hmap, bucket uintptr) {
	// make sure we evacuate the oldbucket corresponding
	// to the bucket we're about to use
	evacuate_fast64(t, h, bucket&h.oldbucketmask())

	// evacuate one more oldbucket to make progress on growing
	if h.growing() {
		evacuate_fast64(t, h, h.nevacuate)
	}
}

func evacuate_fast64(t *maptype, h *hmap, oldbucket uintptr) {
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
		x.e = add(x.k, abi.OldMapBucketCount*8)

		if !h.sameSizeGrow() {
			// Only calculate y pointers if we're growing bigger.
			// Otherwise GC can see bad pointers.
			y := &xy[1]
			y.b = (*bmap)(add(h.buckets, (oldbucket+newbit)*uintptr(t.BucketSize)))
			y.k = add(unsafe.Pointer(y.b), dataOffset)
			y.e = add(y.k, abi.OldMapBucketCount*8)
		}

		for ; b != nil; b = b.overflow(t) {
			k := add(unsafe.Pointer(b), dataOffset)
			e := add(k, abi.OldMapBucketCount*8)
			for i := 0; i < abi.OldMapBucketCount; i, k, e = i+1, add(k, 8), add(e, uintptr(t.ValueSize)) {
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
					dst.e = add(dst.k, abi.OldMapBucketCount*8)
				}
				dst.b.tophash[dst.i&(abi.OldMapBucketCount-1)] = top // mask dst.i as an optimization, to avoid a bounds check

				// Copy key.
				if t.Key.Pointers() && writeBarrier.enabled {
					if goarch.PtrSize == 8 {
						// Write with a write barrier.
						*(*unsafe.Pointer)(dst.k) = *(*unsafe.Pointer)(k)
					} else {
						// There are three ways to squeeze at least one 32 bit pointer into 64 bits.
						// Give up and call typedmemmove.
						typedmemmove(t.Key, dst.k, k)
					}
				} else {
					*(*uint64)(dst.k) = *(*uint64)(k)
				}

				typedmemmove(t.Elem, dst.e, e)
				dst.i++
				// These updates might push these pointers past the end of the
				// key or elem arrays.  That's ok, as we have the overflow pointer
				// at the end of the bucket to protect against pointing past the
				// end of the bucket.
				dst.k = add(dst.k, 8)
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

"""



```