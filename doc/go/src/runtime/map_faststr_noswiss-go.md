Response:
Let's break down the thought process for analyzing the provided Go code snippet for `map_faststr_noswiss.go`.

**1. Initial Understanding & Context:**

* **File Path:** `go/src/runtime/map_faststr_noswiss.go` immediately tells us this is part of the Go runtime, specifically dealing with map implementations. The `_faststr` suggests it's an optimized version for string keys. The `_noswiss` suffix hints at a specific map implementation choice (likely contrasting with a "swissmap" version). The `//go:build !goexperiment.swissmap` confirms this.
* **Copyright and License:** Standard Go copyright and BSD license information, not directly relevant to functionality but good to note.
* **Package:** `package runtime` reinforces that this is core runtime code.
* **Imports:**  The imports provide clues about the code's dependencies:
    * `internal/abi`:  Likely for low-level ABI details, how functions are called, etc.
    * `internal/goarch`: Architecture-specific information (pointer sizes).
    * `internal/runtime/sys`:  System-level calls and information (like getting the caller's PC).
    * `unsafe`:  Indicates this code manipulates memory directly, suggesting performance-critical operations.

**2. Identifying Key Functions:**

A quick scan of the code reveals the core functions:

* `mapaccess1_faststr`: Looks like accessing a map element (returning only the value). The `1` likely signifies returning a single value.
* `mapaccess2_faststr`: Similar to `mapaccess1_faststr`, but the `2` suggests it might return a second value (likely a boolean indicating presence).
* `mapassign_faststr`:  Assigning a value to a map key.
* `mapdelete_faststr`: Deleting an entry from the map.
* `growWork_faststr`:  Related to growing the map's internal storage.
* `evacuate_faststr`: Also related to map growth, likely moving data during resizing.

**3. Analyzing Function Signatures and Logic (Iterative Process):**

For each function, we examine its signature and the core logic:

* **`mapaccess1_faststr(t *maptype, h *hmap, ky string) unsafe.Pointer`:**
    * Takes a `maptype`, `hmap` (likely the map's header/metadata), and a string key `ky`.
    * Returns an `unsafe.Pointer`, suggesting it returns the memory location of the value.
    * Includes checks for `raceenabled` (for data race detection), `h == nil` or empty map, and concurrent write flags.
    * Handles the case where `h.B == 0` (a single-bucket map) separately, with different logic for short and long keys. This is an optimization.
    * The `dohash:` label indicates a path where hashing is used to find the bucket.
    * The logic involving `h.oldbuckets` suggests it handles map growth/resizing.
    * The loops iterate through buckets and key slots, comparing keys.
    * The return value `unsafe.Pointer(&zeroVal[0])` likely means the key wasn't found.

* **`mapaccess2_faststr(t *maptype, h *hmap, ky string) (unsafe.Pointer, bool)`:**
    * Very similar structure to `mapaccess1_faststr`.
    * Returns a `bool` in addition to the `unsafe.Pointer`, strongly suggesting it indicates whether the key was found.

* **`mapassign_faststr(t *maptype, h *hmap, s string) unsafe.Pointer`:**
    * Takes a string `s` as the key.
    * Includes a panic for assignment to a nil map.
    * Sets the `hashWriting` flag to prevent concurrent writes.
    * Handles initial bucket allocation if `h.buckets` is nil.
    * The `again:` label indicates a potential retry after map growth.
    * The code searches for an existing key or an empty slot in the bucket.
    * If the map is full or has too many overflow buckets, it triggers `hashGrow`.
    * If no existing key is found, it inserts the new key and value.

* **`mapdelete_faststr(t *maptype, h *hmap, ky string)`:**
    * Similar checks for nil map and concurrent writes.
    * Calculates the hash and finds the bucket.
    * Iterates through the bucket to find the key.
    * Clears the key and value.
    * Handles the `emptyOne` and `emptyRest` states in the `tophash` array, which are important for efficient iteration and deletion.

* **`growWork_faststr(t *maptype, h *hmap, bucket uintptr)`:**
    * Seems to manage the evacuation process during map growth. It evacuates the bucket being accessed and potentially another one to make progress.

* **`evacuate_faststr(t *maptype, h *hmap, oldbucket uintptr)`:**
    *  Core logic for moving key-value pairs from old buckets to new buckets during map resizing.
    *  It determines whether a key belongs in the "x" or "y" half of the new buckets based on its hash.
    *  Uses `evacuatedX` and `evacuatedY` markers in `tophash`.

**4. Inferring Functionality:**

Based on the function names, signatures, and internal logic, we can confidently infer:

* This code implements the core logic for accessing, assigning, and deleting elements in a Go map where the keys are strings.
* The `_faststr` suffix indicates this is an optimized implementation for string keys, likely taking advantage of string-specific properties for faster comparisons or hashing.
* The `_noswiss` likely means it's the traditional hash table implementation in Go, as opposed to a more recent "swiss map" optimization.
* The code handles concurrent access (read and write) using flags and potentially mutexes (though not explicitly visible in this snippet).
* Map growth (resizing) is handled to maintain performance as the number of elements increases.

**5. Developing Examples (Mental or Actual Code Writing):**

To illustrate the functionality, we think about how these functions are used in typical Go map operations. This leads to the example code for access, assignment, and deletion.

**6. Identifying Potential Pitfalls:**

By understanding the underlying mechanics, we can identify potential issues:

* **Concurrent Access (without proper synchronization):**  The code has checks for concurrent read/write, but users need to use proper locking mechanisms (like `sync.Mutex` or `sync.RWMutex`) if they access maps concurrently from multiple goroutines.
* **Iteration during Growth:**  Map iteration behavior during growth can be tricky. The order might change, and elements might be visited multiple times or skipped. This isn't directly visible in *this* code snippet, but it's a general map concept.

**7. Structuring the Answer:**

Finally, we organize the findings into a clear and comprehensive answer, addressing each point in the prompt: functionality, inferred Go feature, code examples, assumptions, and potential pitfalls. We use clear and concise language, translating the technical details into understandable explanations.
这段代码是 Go 语言运行时（runtime）中用于实现 **非 swiss 版本的字符串键 map** 的一部分。它提供了针对字符串键的 map 的快速访问、赋值和删除操作。

**功能列举:**

1. **`mapaccess1_faststr(t *maptype, h *hmap, ky string) unsafe.Pointer`:**  根据给定的字符串键 `ky`，在 map `h` 中查找对应的值。如果找到，返回值的指针；如果未找到，返回零值的指针。这个函数用于获取 map 中键对应的值，并且不关心键是否存在。

2. **`mapaccess2_faststr(t *maptype, h *hmap, ky string) (unsafe.Pointer, bool)`:**  与 `mapaccess1_faststr` 类似，根据字符串键 `ky` 在 map `h` 中查找对应的值。但是，它返回两个值：值的指针和一个布尔值，该布尔值指示键是否存在于 map 中。这个函数用于安全地获取 map 中的值，需要知道键是否存在。

3. **`mapassign_faststr(t *maptype, h *hmap, s string) unsafe.Pointer`:**  将一个字符串键 `s` 插入或更新到 map `h` 中。如果键已存在，则更新其对应的值。该函数返回键对应值的指针，用于进行后续的值设置。

4. **`mapdelete_faststr(t *maptype, h *hmap, ky string)`:**  从 map `h` 中删除字符串键为 `ky` 的键值对。

5. **`growWork_faststr(t *maptype, h *hmap, bucket uintptr)`:**  在 map 扩容时执行一部分工作。当访问或修改 map 中的某个桶时，这个函数会确保与该桶对应的旧桶（如果存在）已经被迁移（evacuated）。它还会迁移额外的旧桶，以推进扩容过程。

6. **`evacuate_faststr(t *maptype, h *hmap, oldbucket uintptr)`:**  负责将旧的桶（在 map 扩容之前的桶）中的键值对迁移到新的桶中。这是 map 扩容的核心步骤。

**推理：这是 Go 语言 map 功能的实现**

这段代码的核心功能是提供 map 的基本操作：查找、插入/更新、删除。结合文件名和函数名中的 `map` 前缀，以及参数中的 `hmap` 和 `maptype`，可以断定这是 Go 语言 `map` 数据结构的底层实现。特别地，`_faststr` 表明这是针对字符串键的优化版本，而 `_noswiss` 则说明它不是使用了 "swiss map" 优化技术的实现。

**Go 代码示例：**

```go
package main

import "fmt"

func main() {
	m := make(map[string]int)

	// 赋值
	m["hello"] = 1
	m["world"] = 2

	// 访问 (使用类似 mapaccess2_faststr 的方式)
	if val, ok := m["hello"]; ok {
		fmt.Println("Value for 'hello':", val) // 输出: Value for 'hello': 1
	} else {
		fmt.Println("'hello' not found")
	}

	if val, ok := m["golang"]; ok {
		fmt.Println("Value for 'golang':", val)
	} else {
		fmt.Println("'golang' not found") // 输出: 'golang' not found
	}

	// 删除 (使用类似 mapdelete_faststr 的方式)
	delete(m, "world")

	// 再次访问
	if val, ok := m["world"]; ok {
		fmt.Println("Value for 'world':", val)
	} else {
		fmt.Println("'world' not found") // 输出: 'world' not found
	}

	fmt.Println("Map:", m) // 输出: Map: map[hello:1]
}
```

**代码推理示例：**

**假设输入：**

有一个 `map[string]int` 类型的 map `m`，其内部结构由 `hmap` 指针 `h` 表示，其中包含键值对 `{"apple": 10, "banana": 20}`。我们调用 `mapaccess2_faststr` 尝试访问键 "banana"。

**函数调用：**

`mapaccess2_faststr(mapTypeForStringInt, h, "banana")`

**推理过程：**

1. **检查 nil 和空 map：**  `h` 不为 `nil` 且 `h.count` (元素数量) 大于 0。
2. **检查并发写：** `h.flags&hashWriting` 为 0，表示没有并发写入。
3. **计算哈希：**  对键 "banana" 进行哈希计算（`t.Hasher(noescape(unsafe.Pointer(&ky)), uintptr(h.hash0))`）。
4. **查找桶：** 根据哈希值和桶的数量 (`h.B`) 计算出对应的桶。
5. **遍历桶：** 遍历该桶及其溢出桶中的所有槽位。
6. **比较键：**  对于每个槽位，比较槽位中的键的长度和内容是否与 "banana" 匹配。
   - 假设找到了一个槽位，其键的长度与 "banana" 相同。
   - 进一步比较键的内容 (`k.str == key.str` 或 `memequal(k.str, key.str, uintptr(key.len))`)。
   - 如果匹配成功。
7. **返回结果：** 返回该槽位对应的值的指针 (`unsafe.Pointer`) 和 `true` (表示找到了键)。

**假设输出：**

返回 `(unsafe.Pointer to int value 20, true)`。

**命令行参数的具体处理：**

这段代码本身不直接处理命令行参数。Go 语言的命令行参数处理通常在 `main` 包中使用 `os` 包的 `Args` 变量或者 `flag` 包来实现。  `map_faststr_noswiss.go` 作为运行时库的一部分，其功能是被 Go 编译器和运行时系统在执行程序时自动调用的。

**使用者易犯错的点：**

1. **并发读写不安全：**  Go 的 `map` 在没有外部同步机制的情况下，**并发读写是未定义的行为**，可能导致程序崩溃或数据损坏。这段代码内部虽然有 `hashWriting` 标志来检测并发写入，但这是为了在运行时检测到这种情况并抛出 `fatal` 错误，而不是提供并发安全的保证。使用者需要使用 `sync.Mutex` 或 `sync.RWMutex` 等同步机制来保护并发访问的 map。

   **错误示例：**

   ```go
   package main

   import (
       "fmt"
       "time"
   )

   func main() {
       m := make(map[string]int)

       go func() {
           for i := 0; i < 1000; i++ {
               m["key"] = i // 并发写入
           }
       }()

       go func() {
           for i := 0; i < 1000; i++ {
               fmt.Println(m["key"]) // 并发读取
               time.Sleep(time.Millisecond)
           }
       }()

       time.Sleep(time.Second)
   }
   ```

   运行上面的代码很可能会出现 panic，因为发生了并发的 map 读写。

2. **在迭代过程中删除或添加元素：** 在使用 `for...range` 迭代 map 的过程中，如果尝试删除或添加元素，可能会导致迭代行为不稳定，例如跳过某些元素或重复访问某些元素。虽然 Go 运行时会尝试处理这种情况，但不建议这样做。

   **错误示例：**

   ```go
   package main

   import "fmt"

   func main() {
       m := map[int]string{1: "a", 2: "b", 3: "c"}

       for k := range m {
           if k == 2 {
               delete(m, k) // 在迭代过程中删除元素
           }
       }

       fmt.Println(m) // 输出结果可能不确定
   }
   ```

总而言之，`go/src/runtime/map_faststr_noswiss.go` 是 Go 语言 map 数据结构针对字符串键的非 swiss 版本实现的核心代码，负责高效地进行 map 的基本操作。使用者需要注意并发安全问题，并在并发访问 map 时采取适当的同步措施。

Prompt: 
```
这是路径为go/src/runtime/map_faststr_noswiss.go的go语言实现的一部分， 请列举一下它的功能, 　
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

func mapaccess1_faststr(t *maptype, h *hmap, ky string) unsafe.Pointer {
	if raceenabled && h != nil {
		callerpc := sys.GetCallerPC()
		racereadpc(unsafe.Pointer(h), callerpc, abi.FuncPCABIInternal(mapaccess1_faststr))
	}
	if h == nil || h.count == 0 {
		return unsafe.Pointer(&zeroVal[0])
	}
	if h.flags&hashWriting != 0 {
		fatal("concurrent map read and map write")
	}
	key := stringStructOf(&ky)
	if h.B == 0 {
		// One-bucket table.
		b := (*bmap)(h.buckets)
		if key.len < 32 {
			// short key, doing lots of comparisons is ok
			for i, kptr := uintptr(0), b.keys(); i < abi.OldMapBucketCount; i, kptr = i+1, add(kptr, 2*goarch.PtrSize) {
				k := (*stringStruct)(kptr)
				if k.len != key.len || isEmpty(b.tophash[i]) {
					if b.tophash[i] == emptyRest {
						break
					}
					continue
				}
				if k.str == key.str || memequal(k.str, key.str, uintptr(key.len)) {
					return add(unsafe.Pointer(b), dataOffset+abi.OldMapBucketCount*2*goarch.PtrSize+i*uintptr(t.ValueSize))
				}
			}
			return unsafe.Pointer(&zeroVal[0])
		}
		// long key, try not to do more comparisons than necessary
		keymaybe := uintptr(abi.OldMapBucketCount)
		for i, kptr := uintptr(0), b.keys(); i < abi.OldMapBucketCount; i, kptr = i+1, add(kptr, 2*goarch.PtrSize) {
			k := (*stringStruct)(kptr)
			if k.len != key.len || isEmpty(b.tophash[i]) {
				if b.tophash[i] == emptyRest {
					break
				}
				continue
			}
			if k.str == key.str {
				return add(unsafe.Pointer(b), dataOffset+abi.OldMapBucketCount*2*goarch.PtrSize+i*uintptr(t.ValueSize))
			}
			// check first 4 bytes
			if *((*[4]byte)(key.str)) != *((*[4]byte)(k.str)) {
				continue
			}
			// check last 4 bytes
			if *((*[4]byte)(add(key.str, uintptr(key.len)-4))) != *((*[4]byte)(add(k.str, uintptr(key.len)-4))) {
				continue
			}
			if keymaybe != abi.OldMapBucketCount {
				// Two keys are potential matches. Use hash to distinguish them.
				goto dohash
			}
			keymaybe = i
		}
		if keymaybe != abi.OldMapBucketCount {
			k := (*stringStruct)(add(unsafe.Pointer(b), dataOffset+keymaybe*2*goarch.PtrSize))
			if memequal(k.str, key.str, uintptr(key.len)) {
				return add(unsafe.Pointer(b), dataOffset+abi.OldMapBucketCount*2*goarch.PtrSize+keymaybe*uintptr(t.ValueSize))
			}
		}
		return unsafe.Pointer(&zeroVal[0])
	}
dohash:
	hash := t.Hasher(noescape(unsafe.Pointer(&ky)), uintptr(h.hash0))
	m := bucketMask(h.B)
	b := (*bmap)(add(h.buckets, (hash&m)*uintptr(t.BucketSize)))
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
	top := tophash(hash)
	for ; b != nil; b = b.overflow(t) {
		for i, kptr := uintptr(0), b.keys(); i < abi.OldMapBucketCount; i, kptr = i+1, add(kptr, 2*goarch.PtrSize) {
			k := (*stringStruct)(kptr)
			if k.len != key.len || b.tophash[i] != top {
				continue
			}
			if k.str == key.str || memequal(k.str, key.str, uintptr(key.len)) {
				return add(unsafe.Pointer(b), dataOffset+abi.OldMapBucketCount*2*goarch.PtrSize+i*uintptr(t.ValueSize))
			}
		}
	}
	return unsafe.Pointer(&zeroVal[0])
}

// mapaccess2_faststr should be an internal detail,
// but widely used packages access it using linkname.
// Notable members of the hall of shame include:
//   - github.com/ugorji/go/codec
//
// Do not remove or change the type signature.
// See go.dev/issue/67401.
//
//go:linkname mapaccess2_faststr
func mapaccess2_faststr(t *maptype, h *hmap, ky string) (unsafe.Pointer, bool) {
	if raceenabled && h != nil {
		callerpc := sys.GetCallerPC()
		racereadpc(unsafe.Pointer(h), callerpc, abi.FuncPCABIInternal(mapaccess2_faststr))
	}
	if h == nil || h.count == 0 {
		return unsafe.Pointer(&zeroVal[0]), false
	}
	if h.flags&hashWriting != 0 {
		fatal("concurrent map read and map write")
	}
	key := stringStructOf(&ky)
	if h.B == 0 {
		// One-bucket table.
		b := (*bmap)(h.buckets)
		if key.len < 32 {
			// short key, doing lots of comparisons is ok
			for i, kptr := uintptr(0), b.keys(); i < abi.OldMapBucketCount; i, kptr = i+1, add(kptr, 2*goarch.PtrSize) {
				k := (*stringStruct)(kptr)
				if k.len != key.len || isEmpty(b.tophash[i]) {
					if b.tophash[i] == emptyRest {
						break
					}
					continue
				}
				if k.str == key.str || memequal(k.str, key.str, uintptr(key.len)) {
					return add(unsafe.Pointer(b), dataOffset+abi.OldMapBucketCount*2*goarch.PtrSize+i*uintptr(t.ValueSize)), true
				}
			}
			return unsafe.Pointer(&zeroVal[0]), false
		}
		// long key, try not to do more comparisons than necessary
		keymaybe := uintptr(abi.OldMapBucketCount)
		for i, kptr := uintptr(0), b.keys(); i < abi.OldMapBucketCount; i, kptr = i+1, add(kptr, 2*goarch.PtrSize) {
			k := (*stringStruct)(kptr)
			if k.len != key.len || isEmpty(b.tophash[i]) {
				if b.tophash[i] == emptyRest {
					break
				}
				continue
			}
			if k.str == key.str {
				return add(unsafe.Pointer(b), dataOffset+abi.OldMapBucketCount*2*goarch.PtrSize+i*uintptr(t.ValueSize)), true
			}
			// check first 4 bytes
			if *((*[4]byte)(key.str)) != *((*[4]byte)(k.str)) {
				continue
			}
			// check last 4 bytes
			if *((*[4]byte)(add(key.str, uintptr(key.len)-4))) != *((*[4]byte)(add(k.str, uintptr(key.len)-4))) {
				continue
			}
			if keymaybe != abi.OldMapBucketCount {
				// Two keys are potential matches. Use hash to distinguish them.
				goto dohash
			}
			keymaybe = i
		}
		if keymaybe != abi.OldMapBucketCount {
			k := (*stringStruct)(add(unsafe.Pointer(b), dataOffset+keymaybe*2*goarch.PtrSize))
			if memequal(k.str, key.str, uintptr(key.len)) {
				return add(unsafe.Pointer(b), dataOffset+abi.OldMapBucketCount*2*goarch.PtrSize+keymaybe*uintptr(t.ValueSize)), true
			}
		}
		return unsafe.Pointer(&zeroVal[0]), false
	}
dohash:
	hash := t.Hasher(noescape(unsafe.Pointer(&ky)), uintptr(h.hash0))
	m := bucketMask(h.B)
	b := (*bmap)(add(h.buckets, (hash&m)*uintptr(t.BucketSize)))
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
	top := tophash(hash)
	for ; b != nil; b = b.overflow(t) {
		for i, kptr := uintptr(0), b.keys(); i < abi.OldMapBucketCount; i, kptr = i+1, add(kptr, 2*goarch.PtrSize) {
			k := (*stringStruct)(kptr)
			if k.len != key.len || b.tophash[i] != top {
				continue
			}
			if k.str == key.str || memequal(k.str, key.str, uintptr(key.len)) {
				return add(unsafe.Pointer(b), dataOffset+abi.OldMapBucketCount*2*goarch.PtrSize+i*uintptr(t.ValueSize)), true
			}
		}
	}
	return unsafe.Pointer(&zeroVal[0]), false
}

// mapassign_faststr should be an internal detail,
// but widely used packages access it using linkname.
// Notable members of the hall of shame include:
//   - github.com/bytedance/sonic
//   - github.com/ugorji/go/codec
//
// Do not remove or change the type signature.
// See go.dev/issue/67401.
//
//go:linkname mapassign_faststr
func mapassign_faststr(t *maptype, h *hmap, s string) unsafe.Pointer {
	if h == nil {
		panic(plainError("assignment to entry in nil map"))
	}
	if raceenabled {
		callerpc := sys.GetCallerPC()
		racewritepc(unsafe.Pointer(h), callerpc, abi.FuncPCABIInternal(mapassign_faststr))
	}
	if h.flags&hashWriting != 0 {
		fatal("concurrent map writes")
	}
	key := stringStructOf(&s)
	hash := t.Hasher(noescape(unsafe.Pointer(&s)), uintptr(h.hash0))

	// Set hashWriting after calling t.hasher for consistency with mapassign.
	h.flags ^= hashWriting

	if h.buckets == nil {
		h.buckets = newobject(t.Bucket) // newarray(t.bucket, 1)
	}

again:
	bucket := hash & bucketMask(h.B)
	if h.growing() {
		growWork_faststr(t, h, bucket)
	}
	b := (*bmap)(add(h.buckets, bucket*uintptr(t.BucketSize)))
	top := tophash(hash)

	var insertb *bmap
	var inserti uintptr
	var insertk unsafe.Pointer

bucketloop:
	for {
		for i := uintptr(0); i < abi.OldMapBucketCount; i++ {
			if b.tophash[i] != top {
				if isEmpty(b.tophash[i]) && insertb == nil {
					insertb = b
					inserti = i
				}
				if b.tophash[i] == emptyRest {
					break bucketloop
				}
				continue
			}
			k := (*stringStruct)(add(unsafe.Pointer(b), dataOffset+i*2*goarch.PtrSize))
			if k.len != key.len {
				continue
			}
			if k.str != key.str && !memequal(k.str, key.str, uintptr(key.len)) {
				continue
			}
			// already have a mapping for key. Update it.
			inserti = i
			insertb = b
			// Overwrite existing key, so it can be garbage collected.
			// The size is already guaranteed to be set correctly.
			k.str = key.str
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
	insertb.tophash[inserti&(abi.OldMapBucketCount-1)] = top // mask inserti to avoid bounds checks

	insertk = add(unsafe.Pointer(insertb), dataOffset+inserti*2*goarch.PtrSize)
	// store new key at insert position
	*((*stringStruct)(insertk)) = *key
	h.count++

done:
	elem := add(unsafe.Pointer(insertb), dataOffset+abi.OldMapBucketCount*2*goarch.PtrSize+inserti*uintptr(t.ValueSize))
	if h.flags&hashWriting == 0 {
		fatal("concurrent map writes")
	}
	h.flags &^= hashWriting
	return elem
}

func mapdelete_faststr(t *maptype, h *hmap, ky string) {
	if raceenabled && h != nil {
		callerpc := sys.GetCallerPC()
		racewritepc(unsafe.Pointer(h), callerpc, abi.FuncPCABIInternal(mapdelete_faststr))
	}
	if h == nil || h.count == 0 {
		return
	}
	if h.flags&hashWriting != 0 {
		fatal("concurrent map writes")
	}

	key := stringStructOf(&ky)
	hash := t.Hasher(noescape(unsafe.Pointer(&ky)), uintptr(h.hash0))

	// Set hashWriting after calling t.hasher for consistency with mapdelete
	h.flags ^= hashWriting

	bucket := hash & bucketMask(h.B)
	if h.growing() {
		growWork_faststr(t, h, bucket)
	}
	b := (*bmap)(add(h.buckets, bucket*uintptr(t.BucketSize)))
	bOrig := b
	top := tophash(hash)
search:
	for ; b != nil; b = b.overflow(t) {
		for i, kptr := uintptr(0), b.keys(); i < abi.OldMapBucketCount; i, kptr = i+1, add(kptr, 2*goarch.PtrSize) {
			k := (*stringStruct)(kptr)
			if k.len != key.len || b.tophash[i] != top {
				continue
			}
			if k.str != key.str && !memequal(k.str, key.str, uintptr(key.len)) {
				continue
			}
			// Clear key's pointer.
			k.str = nil
			e := add(unsafe.Pointer(b), dataOffset+abi.OldMapBucketCount*2*goarch.PtrSize+i*uintptr(t.ValueSize))
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

func growWork_faststr(t *maptype, h *hmap, bucket uintptr) {
	// make sure we evacuate the oldbucket corresponding
	// to the bucket we're about to use
	evacuate_faststr(t, h, bucket&h.oldbucketmask())

	// evacuate one more oldbucket to make progress on growing
	if h.growing() {
		evacuate_faststr(t, h, h.nevacuate)
	}
}

func evacuate_faststr(t *maptype, h *hmap, oldbucket uintptr) {
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
		x.e = add(x.k, abi.OldMapBucketCount*2*goarch.PtrSize)

		if !h.sameSizeGrow() {
			// Only calculate y pointers if we're growing bigger.
			// Otherwise GC can see bad pointers.
			y := &xy[1]
			y.b = (*bmap)(add(h.buckets, (oldbucket+newbit)*uintptr(t.BucketSize)))
			y.k = add(unsafe.Pointer(y.b), dataOffset)
			y.e = add(y.k, abi.OldMapBucketCount*2*goarch.PtrSize)
		}

		for ; b != nil; b = b.overflow(t) {
			k := add(unsafe.Pointer(b), dataOffset)
			e := add(k, abi.OldMapBucketCount*2*goarch.PtrSize)
			for i := 0; i < abi.OldMapBucketCount; i, k, e = i+1, add(k, 2*goarch.PtrSize), add(e, uintptr(t.ValueSize)) {
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
					dst.e = add(dst.k, abi.OldMapBucketCount*2*goarch.PtrSize)
				}
				dst.b.tophash[dst.i&(abi.OldMapBucketCount-1)] = top // mask dst.i as an optimization, to avoid a bounds check

				// Copy key.
				*(*string)(dst.k) = *(*string)(k)

				typedmemmove(t.Elem, dst.e, e)
				dst.i++
				// These updates might push these pointers past the end of the
				// key or elem arrays.  That's ok, as we have the overflow pointer
				// at the end of the bucket to protect against pointing past the
				// end of the bucket.
				dst.k = add(dst.k, 2*goarch.PtrSize)
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