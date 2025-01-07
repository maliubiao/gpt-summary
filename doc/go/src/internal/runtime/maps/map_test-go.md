Response:
Let's break down the thought process for analyzing the provided Go code snippet.

**1. Initial Understanding - What is this?**

The first line `// Copyright 2024 The Go Authors. All rights reserved.` immediately signals this is part of the official Go project. The `package maps_test` indicates this is a test file for a `maps` package (likely internal, given the `internal/runtime/maps` import). The filename `map_test.go` reinforces this. Therefore, the code is about testing the implementation of Go's map data structure.

**2. High-Level Functionality - What are the tests doing?**

Scanning the function names gives a good overview: `TestCtrlSize`, `TestMapPut`, `TestMapSplit`, `TestMapDelete`, `TestTableClear`, `TestTableKeyUpdate`, `TestTablePutDelete`, `TestTableIteration`, `TestTableIterationDelete`, `TestTableIterationGrowDelete`, `TestTableIterationGrowDuplicate`, `TestAlignUpPow2`, `TestMapZeroSizeSlot`, `TestMapIndirect`, `TestMapDeleteClear`.

These names strongly suggest the tests cover core map operations:
* **Structure/Layout:** `CtrlSize` likely checks the size of internal control structures.
* **Basic Operations:** `Put`, `Get`, `Delete`, `Clear`.
* **Dynamic Behavior:** `Split` (resizing), `Grow` (related to resizing), `Iteration`.
* **Edge Cases/Specific Scenarios:** `KeyUpdate` (handling equivalent but distinct keys like +0.0 and -0.0), `PutDelete` (reusing deleted slots), `ZeroSizeSlot` (maps with empty key/value types), `Indirect` (handling large key/value types), `DeleteClear` (ensuring deletion clears memory).
* **Utility Functions:** `AlignUpPow2`.

**3. Deeper Dive - Examining Individual Tests**

Now, we go through each test function to understand its specific purpose and how it achieves it. We look for:

* **Setup:** How is the map being initialized?  (`maps.NewTestMap`) What are the key and value types?
* **Actions:** What operations are being performed on the map? (`Put`, `Get`, `Delete`, `Clear`, iteration).
* **Assertions:** What conditions are being checked to verify correctness?  (e.g., `m.Used()`, comparisons of retrieved values, checks for `ok` in `Get`, iteration results).
* **Specific Scenarios:** Does the test target a particular edge case or behavior?  (e.g., filling a group before deleting in `TestTablePutDelete`, growing the map during iteration).

**4. Identifying the Implemented Feature**

Based on the comprehensive set of tests, it's clear this code is testing the core implementation of Go's `map` data structure. The tests cover the fundamental operations and the dynamic resizing and rehashing mechanisms. The usage of `unsafe.Pointer` hints at a low-level implementation, likely dealing with memory management and layout.

**5. Code Example of the Feature (Go Map)**

Since the tests are for the standard Go map, a simple example of using a Go map is the most direct way to illustrate the feature. This would involve declaring and manipulating a map using the standard Go syntax.

**6. Code Reasoning (Hypothetical Inputs and Outputs)**

For each test, we can reason about the expected input and output. For example, in `TestMapPut`:

* **Input:** Inserting key-value pairs (uint32, uint64) into the map.
* **Output:** The `Used()` method should reflect the number of inserted elements. `Get()` with the same keys should retrieve the corresponding values.

Similarly, for `TestMapDelete`:

* **Input:** Inserting elements and then deleting them.
* **Output:** `Used()` should be 0 after deleting all elements. `Get()` on deleted keys should return `false`.

**7. Command-Line Arguments**

The provided code doesn't directly interact with command-line arguments. However, we can infer that the `testing` package is used, and standard Go testing flags (like `-v` for verbose output) would apply when running these tests using `go test`.

**8. Common Mistakes**

Thinking about common pitfalls when using Go maps leads to points like:

* **Iteration Order:**  Maps have no guaranteed iteration order.
* **Concurrent Access:** Maps are not safe for concurrent access without explicit locking.
* **Nil Maps:**  Accessing or modifying a `nil` map will cause a panic.
* **Key Types:**  Map keys must be comparable.

**9. Structuring the Answer**

Finally, the information gathered needs to be organized into a clear and comprehensive answer, addressing each point in the prompt. Using clear headings and code examples makes the explanation easier to understand. The use of bullet points helps in listing functionalities and potential mistakes.

This systematic approach of understanding the context, identifying the high-level purpose, analyzing individual components, and then synthesizing the information allows for a thorough and accurate explanation of the given code. The inclusion of concrete examples and potential pitfalls adds practical value to the answer.
这段Go语言代码是 `go/src/internal/runtime/maps/map_test.go` 文件的一部分，它主要用于**测试 Go 语言 map 的内部实现**。  由于路径中包含 `internal`, 这表明 `maps` 包是 Go 运行时环境的内部包，不建议直接在外部代码中使用。

让我们详细列举一下它的功能，并尝试推理其实现的 Go 语言功能：

**功能列表:**

* **`TestCtrlSize`:**  测试内部控制组 (`CtrlGroup`) 的大小是否与预定义的槽位数 (`abi.SwissMapGroupSlots`) 相符。这可能是为了确保内部数据结构的布局正确。
* **`TestMapPut`:** 测试向 map 中插入键值对的功能。
* **`TestMapSplit`:** 测试当 map 的容量达到一定程度时，触发内部 table 分裂（split）机制的功能。这涉及到 map 的动态扩容。
* **`TestMapDelete`:** 测试从 map 中删除键值对的功能。
* **`TestTableClear`:** 测试清空 map 中所有键值对的功能。
* **`TestTableKeyUpdate`:** 测试当使用已存在的键插入新值时，map 如何更新键值对。 特别地，它测试了浮点数 `+0.0` 和 `-0.0` 作为键的更新行为，因为它们在比较时被认为是相等的。
* **`TestTablePutDelete`:** 测试在删除一个键后，再次插入相同的键时，map 是否会复用之前删除的槽位，而不是分配新的空槽位。
* **`TestTableIteration`:** 测试 map 的迭代功能，确保能够遍历所有已存在的键值对。
* **`TestTableIterationDelete`:** 测试在迭代 map 的过程中删除元素，迭代器是否能够正确地跳过已删除的元素。
* **`TestTableIterationGrowDelete`:** 测试在迭代 map 的过程中，如果 map 发生了扩容（grow），并且期间有元素被删除，迭代器是否能够正确处理。
* **`TestTableIterationGrowDuplicate`:** 测试在 map 迭代过程中进行扩容操作，是否会导致重复的键出现。 这测试了扩容过程中的数据一致性。
* **`TestAlignUpPow2`:** 测试一个辅助函数 `AlignUpPow2`，该函数将一个给定的无符号 64 位整数向上对齐到最接近的 2 的幂。这在内存分配等场景中很常见。
* **`TestMapZeroSizeSlot`:** 测试当 map 的键或值类型的大小为零时（例如 `struct{}`），map 是否能够正常工作。
* **`TestMapIndirect`:** 测试当 map 的键或值类型很大时，map 的处理机制。这可能涉及到间接寻址或堆分配。
* **`TestMapDeleteClear`:** 测试删除 map 中的元素后，对应的值的内存是否被清理（设置为零值）。

**推理实现的 Go 语言功能：**

基于以上测试用例，可以推断出这段代码正在测试 **Go 语言 map 的核心实现，特别是使用了名为 "Swiss Map" 的哈希表算法**。  Swiss Map 是一种优化的哈希表实现，旨在提高性能和内存效率。

**Go 代码举例说明 (Go Map 的使用):**

```go
package main

import "fmt"

func main() {
	// 创建一个 string 类型的键，int 类型的值的 map
	myMap := make(map[string]int)

	// 插入键值对
	myMap["apple"] = 1
	myMap["banana"] = 2
	myMap["cherry"] = 3

	// 获取值
	appleValue, ok := myMap["apple"]
	if ok {
		fmt.Println("The value of apple is:", appleValue) // Output: The value of apple is: 1
	}

	// 删除键值对
	delete(myMap, "banana")

	// 遍历 map
	for key, value := range myMap {
		fmt.Printf("Key: %s, Value: %d\n", key, value)
		// Output (顺序不保证):
		// Key: apple, Value: 1
		// Key: cherry, Value: 3
	}

	// 检查 map 的长度
	fmt.Println("Length of the map:", len(myMap)) // Output: Length of the map: 2

	// 检查键是否存在
	_, ok = myMap["banana"]
	if !ok {
		fmt.Println("Banana is not in the map") // Output: Banana is not in the map
	}
}
```

**代码推理 (以 `TestMapPut` 为例):**

**假设输入:**

在 `TestMapPut` 中，代码循环插入键值对，键是 `uint32` 类型，值是 `uint64` 类型。 循环从 `i = 0` 到 `i < 31`，因此插入了 31 个键值对。

**假设输出:**

* 在插入 31 个元素后，`m.Used()` 应该返回 `31`。
* 随后通过 `Get` 方法获取之前插入的每个键对应的值，应该能够成功获取，并且获取到的值与插入的值相等。例如，当 `key` 为 `1` 时，`Get` 方法应该返回 `elem` 为 `257` (256 + 1)，并且 `ok` 为 `true`。

**命令行参数的具体处理:**

这段代码本身是测试代码，它使用了 `testing` 包。 要运行这些测试，你需要在包含此文件的目录下使用 `go test` 命令。

* **`go test`**: 运行当前目录下的所有测试文件中的测试函数。
* **`go test -v`**: 以更详细的输出模式运行测试，会打印每个测试函数的名称和结果。
* **`go test -run <正则表达式>`**:  运行名称匹配指定正则表达式的测试函数。 例如，`go test -run TestMapPut` 只会运行 `TestMapPut` 这个测试函数。
* **`go test -bench <正则表达式>`**: 运行性能测试（benchmark）。虽然这段代码没有性能测试，但 `go test` 也支持。
* **`go test -cpuprofile profile.out`**: 将 CPU 性能分析信息写入 `profile.out` 文件。
* **`go test -memprofile mem.out`**: 将内存性能分析信息写入 `mem.out` 文件。

**使用者易犯错的点 (基于 Go Map 的使用):**

* **并发读写不安全:** Go 的原生 `map` 类型不是并发安全的。如果在多个 Goroutine 中同时读写同一个 `map`，可能会导致程序崩溃或数据不一致。
    ```go
    package main

    import (
        "fmt"
        "sync"
    )

    func main() {
        m := make(map[int]int)
        var wg sync.WaitGroup

        // 两个 Goroutine 同时写入 map (这是一个潜在的 race condition)
        for i := 0; i < 2; i++ {
            wg.Add(1)
            go func() {
                defer wg.Done()
                for j := 0; j < 1000; j++ {
                    m[j] = j
                }
            }()
        }

        wg.Wait()
        fmt.Println("Map size:", len(m)) // 输出结果可能不确定
    }
    ```
    **解决方法:** 使用 `sync.Mutex` 或 `sync.RWMutex` 进行加锁保护，或者使用并发安全的 `sync.Map`。

* **迭代时删除元素:** 在使用 `range` 迭代 `map` 的过程中删除元素是安全的，但是需要注意迭代器可能已经跳过了被删除的元素，所以不会出现对同一个元素删除两次的情况。
    ```go
    package main

    import "fmt"

    func main() {
        m := map[int]string{1: "a", 2: "b", 3: "c"}
        for key := range m {
            if key == 2 {
                delete(m, key) // 安全地删除元素
            }
        }
        fmt.Println(m) // Output: map[1:a 3:c] (顺序不保证)
    }
    ```

* **nil map 的使用:**  声明但未初始化的 `map` 是 `nil`。 对 `nil map` 进行赋值操作会引发 `panic`。
    ```go
    package main

    func main() {
        var m map[string]int
        // m["key"] = 1 // 这行代码会 panic: assignment to entry in nil map
        _ = m
    }
    ```
    **解决方法:** 在使用 `map` 之前，始终使用 `make` 进行初始化。

* **键的类型必须是可比较的:**  `map` 的键类型必须是可比较的，例如基本数据类型（int, string, bool 等），指针，数组（元素类型可比较），结构体（所有字段类型可比较）。 Slice, map 或 function 不能作为 `map` 的键。
    ```go
    package main

    func main() {
        // invalid map key type: slice
        // m := make(map[[]int]string)

        // valid map key type: array
        m := make(map[[2]int]string)
        m[[2]int{1, 2}] = "value"
        _ = m
    }
    ```

总而言之，这段测试代码是 Go 语言运行时环境中 `map` 实现的关键组成部分，它通过各种测试用例确保了 `map` 功能的正确性和健壮性。理解这些测试用例有助于更深入地理解 Go `map` 的内部工作原理。

Prompt: 
```
这是路径为go/src/internal/runtime/maps/map_test.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。

"""
// Copyright 2024 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package maps_test

import (
	"fmt"
	"internal/abi"
	"internal/runtime/maps"
	"math"
	"testing"
	"unsafe"
)

func TestCtrlSize(t *testing.T) {
	cs := unsafe.Sizeof(maps.CtrlGroup(0))
	if cs != abi.SwissMapGroupSlots {
		t.Errorf("ctrlGroup size got %d want abi.SwissMapGroupSlots %d", cs, abi.SwissMapGroupSlots)
	}
}

func TestMapPut(t *testing.T) {
	m, typ := maps.NewTestMap[uint32, uint64](8)

	key := uint32(0)
	elem := uint64(256 + 0)

	for i := 0; i < 31; i++ {
		key += 1
		elem += 1
		m.Put(typ, unsafe.Pointer(&key), unsafe.Pointer(&elem))

		if maps.DebugLog {
			fmt.Printf("After put %d: %v\n", key, m)
		}
	}

	if m.Used() != 31 {
		t.Errorf("Used() used got %d want 31", m.Used())
	}

	key = uint32(0)
	elem = uint64(256 + 0)

	for i := 0; i < 31; i++ {
		key += 1
		elem += 1
		got, ok := m.Get(typ, unsafe.Pointer(&key))
		if !ok {
			t.Errorf("Get(%d) got ok false want true", key)
		}
		gotElem := *(*uint64)(got)
		if gotElem != elem {
			t.Errorf("Get(%d) got elem %d want %d", key, gotElem, elem)
		}
	}
}

// Grow enough to cause a table split.
func TestMapSplit(t *testing.T) {
	m, typ := maps.NewTestMap[uint32, uint64](0)

	key := uint32(0)
	elem := uint64(256 + 0)

	for i := 0; i < 2*maps.MaxTableCapacity; i++ {
		key += 1
		elem += 1
		m.Put(typ, unsafe.Pointer(&key), unsafe.Pointer(&elem))

		if maps.DebugLog {
			fmt.Printf("After put %d: %v\n", key, m)
		}
	}

	if m.Used() != 2*maps.MaxTableCapacity {
		t.Errorf("Used() used got %d want 31", m.Used())
	}

	key = uint32(0)
	elem = uint64(256 + 0)

	for i := 0; i < 2*maps.MaxTableCapacity; i++ {
		key += 1
		elem += 1
		got, ok := m.Get(typ, unsafe.Pointer(&key))
		if !ok {
			t.Errorf("Get(%d) got ok false want true", key)
		}
		gotElem := *(*uint64)(got)
		if gotElem != elem {
			t.Errorf("Get(%d) got elem %d want %d", key, gotElem, elem)
		}
	}
}

func TestMapDelete(t *testing.T) {
	m, typ := maps.NewTestMap[uint32, uint64](32)

	key := uint32(0)
	elem := uint64(256 + 0)

	for i := 0; i < 31; i++ {
		key += 1
		elem += 1
		m.Put(typ, unsafe.Pointer(&key), unsafe.Pointer(&elem))

		if maps.DebugLog {
			fmt.Printf("After put %d: %v\n", key, m)
		}
	}

	key = uint32(0)
	elem = uint64(256 + 0)

	for i := 0; i < 31; i++ {
		key += 1
		m.Delete(typ, unsafe.Pointer(&key))
	}

	if m.Used() != 0 {
		t.Errorf("Used() used got %d want 0", m.Used())
	}

	key = uint32(0)
	elem = uint64(256 + 0)

	for i := 0; i < 31; i++ {
		key += 1
		elem += 1
		_, ok := m.Get(typ, unsafe.Pointer(&key))
		if ok {
			t.Errorf("Get(%d) got ok true want false", key)
		}
	}
}

func TestTableClear(t *testing.T) {
	m, typ := maps.NewTestMap[uint32, uint64](32)

	key := uint32(0)
	elem := uint64(256 + 0)

	for i := 0; i < 31; i++ {
		key += 1
		elem += 1
		m.Put(typ, unsafe.Pointer(&key), unsafe.Pointer(&elem))

		if maps.DebugLog {
			fmt.Printf("After put %d: %v\n", key, m)
		}
	}

	m.Clear(typ)

	if m.Used() != 0 {
		t.Errorf("Clear() used got %d want 0", m.Used())
	}

	key = uint32(0)
	elem = uint64(256 + 0)

	for i := 0; i < 31; i++ {
		key += 1
		elem += 1
		_, ok := m.Get(typ, unsafe.Pointer(&key))
		if ok {
			t.Errorf("Get(%d) got ok true want false", key)
		}
	}
}

// +0.0 and -0.0 compare equal, but we must still must update the key slot when
// overwriting.
func TestTableKeyUpdate(t *testing.T) {
	m, typ := maps.NewTestMap[float64, uint64](8)

	zero := float64(0.0)
	negZero := math.Copysign(zero, -1.0)
	elem := uint64(0)

	m.Put(typ, unsafe.Pointer(&zero), unsafe.Pointer(&elem))
	if maps.DebugLog {
		fmt.Printf("After put %f: %v\n", zero, m)
	}

	elem = 1
	m.Put(typ, unsafe.Pointer(&negZero), unsafe.Pointer(&elem))
	if maps.DebugLog {
		fmt.Printf("After put %f: %v\n", negZero, m)
	}

	if m.Used() != 1 {
		t.Errorf("Used() used got %d want 1", m.Used())
	}

	it := new(maps.Iter)
	it.Init(typ, m)
	it.Next()
	keyPtr, elemPtr := it.Key(), it.Elem()
	if keyPtr == nil {
		t.Fatal("it.Key() got nil want key")
	}

	key := *(*float64)(keyPtr)
	elem = *(*uint64)(elemPtr)
	if math.Copysign(1.0, key) > 0 {
		t.Errorf("map key %f has positive sign", key)
	}
	if elem != 1 {
		t.Errorf("map elem got %d want 1", elem)
	}
}

// Put should reuse a deleted slot rather than consuming an empty slot.
func TestTablePutDelete(t *testing.T) {
	// Put will reuse the first deleted slot it encounters.
	//
	// This is awkward to test because Delete will only install ctrlDeleted
	// if the group is full, otherwise it goes straight to empty.
	//
	// So first we must add to the table continuously until we happen to
	// fill a group.

	// Avoid small maps, they have no tables.
	m, typ := maps.NewTestMap[uint32, uint32](16)

	key := uint32(0)
	elem := uint32(256 + 0)

	for {
		key += 1
		elem += 1

		m.Put(typ, unsafe.Pointer(&key), unsafe.Pointer(&elem))

		// Normally a Put that fills a group would fill it with the
		// inserted key, so why search the whole map for a potentially
		// different key in a full group?
		//
		// Put may grow/split a table. Initial construction of the new
		// table(s) could result in a full group consisting of
		// arbitrary keys.
		fullKeyPtr := m.KeyFromFullGroup(typ)
		if fullKeyPtr != nil {
			// Found a full group.
			key = *(*uint32)(fullKeyPtr)
			elem = 256 + key
			break
		}
	}

	// Key is in a full group. Deleting it will result in a ctrlDeleted
	// slot.
	m.Delete(typ, unsafe.Pointer(&key))

	// Re-insert key. This should reuse the deleted slot rather than
	// consuming space.
	tabWant := m.TableFor(typ, unsafe.Pointer(&key))
	growthLeftWant := tabWant.GrowthLeft()

	m.Put(typ, unsafe.Pointer(&key), unsafe.Pointer(&elem))

	tabGot := m.TableFor(typ, unsafe.Pointer(&key))
	growthLeftGot := tabGot.GrowthLeft()

	if tabGot != tabWant {
		// There shouldn't be a grow, as replacing a deleted slot
		// doesn't require more space.
		t.Errorf("Put(%d) grew table got %v want %v map %v", key, tabGot, tabWant, m)
	}

	if growthLeftGot != growthLeftWant {
		t.Errorf("GrowthLeft got %d want %d: map %v tab %v", growthLeftGot, growthLeftWant, m, tabGot)
	}
}

func TestTableIteration(t *testing.T) {
	m, typ := maps.NewTestMap[uint32, uint64](8)

	key := uint32(0)
	elem := uint64(256 + 0)

	for i := 0; i < 31; i++ {
		key += 1
		elem += 1
		m.Put(typ, unsafe.Pointer(&key), unsafe.Pointer(&elem))

		if maps.DebugLog {
			fmt.Printf("After put %d: %v\n", key, m)
		}
	}

	got := make(map[uint32]uint64)

	it := new(maps.Iter)
	it.Init(typ, m)
	for {
		it.Next()
		keyPtr, elemPtr := it.Key(), it.Elem()
		if keyPtr == nil {
			break
		}

		key := *(*uint32)(keyPtr)
		elem := *(*uint64)(elemPtr)
		got[key] = elem
	}

	if len(got) != 31 {
		t.Errorf("Iteration got %d entries, want 31: %+v", len(got), got)
	}

	key = uint32(0)
	elem = uint64(256 + 0)

	for i := 0; i < 31; i++ {
		key += 1
		elem += 1
		gotElem, ok := got[key]
		if !ok {
			t.Errorf("Iteration missing key %d", key)
			continue
		}
		if gotElem != elem {
			t.Errorf("Iteration key %d got elem %d want %d", key, gotElem, elem)
		}
	}
}

// Deleted keys shouldn't be visible in iteration.
func TestTableIterationDelete(t *testing.T) {
	m, typ := maps.NewTestMap[uint32, uint64](8)

	key := uint32(0)
	elem := uint64(256 + 0)

	for i := 0; i < 31; i++ {
		key += 1
		elem += 1
		m.Put(typ, unsafe.Pointer(&key), unsafe.Pointer(&elem))

		if maps.DebugLog {
			fmt.Printf("After put %d: %v\n", key, m)
		}
	}

	got := make(map[uint32]uint64)
	first := true
	deletedKey := uint32(1)
	it := new(maps.Iter)
	it.Init(typ, m)
	for {
		it.Next()
		keyPtr, elemPtr := it.Key(), it.Elem()
		if keyPtr == nil {
			break
		}

		key := *(*uint32)(keyPtr)
		elem := *(*uint64)(elemPtr)
		got[key] = elem

		if first {
			first = false

			// If the key we intended to delete was the one we just
			// saw, pick another to delete.
			if key == deletedKey {
				deletedKey++
			}
			m.Delete(typ, unsafe.Pointer(&deletedKey))
		}
	}

	if len(got) != 30 {
		t.Errorf("Iteration got %d entries, want 30: %+v", len(got), got)
	}

	key = uint32(0)
	elem = uint64(256 + 0)

	for i := 0; i < 31; i++ {
		key += 1
		elem += 1

		wantOK := true
		if key == deletedKey {
			wantOK = false
		}

		gotElem, gotOK := got[key]
		if gotOK != wantOK {
			t.Errorf("Iteration key %d got ok %v want ok %v", key, gotOK, wantOK)
			continue
		}
		if wantOK && gotElem != elem {
			t.Errorf("Iteration key %d got elem %d want %d", key, gotElem, elem)
		}
	}
}

// Deleted keys shouldn't be visible in iteration even after a grow.
func TestTableIterationGrowDelete(t *testing.T) {
	m, typ := maps.NewTestMap[uint32, uint64](8)

	key := uint32(0)
	elem := uint64(256 + 0)

	for i := 0; i < 31; i++ {
		key += 1
		elem += 1
		m.Put(typ, unsafe.Pointer(&key), unsafe.Pointer(&elem))

		if maps.DebugLog {
			fmt.Printf("After put %d: %v\n", key, m)
		}
	}

	got := make(map[uint32]uint64)
	first := true
	deletedKey := uint32(1)
	it := new(maps.Iter)
	it.Init(typ, m)
	for {
		it.Next()
		keyPtr, elemPtr := it.Key(), it.Elem()
		if keyPtr == nil {
			break
		}

		key := *(*uint32)(keyPtr)
		elem := *(*uint64)(elemPtr)
		got[key] = elem

		if first {
			first = false

			// If the key we intended to delete was the one we just
			// saw, pick another to delete.
			if key == deletedKey {
				deletedKey++
			}

			// Double the number of elements to force a grow.
			key := uint32(32)
			elem := uint64(256 + 32)

			for i := 0; i < 31; i++ {
				key += 1
				elem += 1
				m.Put(typ, unsafe.Pointer(&key), unsafe.Pointer(&elem))

				if maps.DebugLog {
					fmt.Printf("After put %d: %v\n", key, m)
				}
			}

			// Then delete from the grown map.
			m.Delete(typ, unsafe.Pointer(&deletedKey))
		}
	}

	// Don't check length: the number of new elements we'll see is
	// unspecified.

	// Check values only of the original pre-iteration entries.
	key = uint32(0)
	elem = uint64(256 + 0)

	for i := 0; i < 31; i++ {
		key += 1
		elem += 1

		wantOK := true
		if key == deletedKey {
			wantOK = false
		}

		gotElem, gotOK := got[key]
		if gotOK != wantOK {
			t.Errorf("Iteration key %d got ok %v want ok %v", key, gotOK, wantOK)
			continue
		}
		if wantOK && gotElem != elem {
			t.Errorf("Iteration key %d got elem %d want %d", key, gotElem, elem)
		}
	}
}

func testTableIterationGrowDuplicate(t *testing.T, grow int) {
	m, typ := maps.NewTestMap[uint32, uint64](8)

	key := uint32(0)
	elem := uint64(256 + 0)

	for i := 0; i < 31; i++ {
		key += 1
		elem += 1
		m.Put(typ, unsafe.Pointer(&key), unsafe.Pointer(&elem))

		if maps.DebugLog {
			fmt.Printf("After put %d: %v\n", key, m)
		}
	}

	got := make(map[uint32]uint64)
	it := new(maps.Iter)
	it.Init(typ, m)
	for i := 0; ; i++ {
		it.Next()
		keyPtr, elemPtr := it.Key(), it.Elem()
		if keyPtr == nil {
			break
		}

		key := *(*uint32)(keyPtr)
		elem := *(*uint64)(elemPtr)
		if elem != 256+uint64(key) {
			t.Errorf("iteration got key %d elem %d want elem %d", key, elem, 256+uint64(key))
		}
		if _, ok := got[key]; ok {
			t.Errorf("iteration got key %d more than once", key)
		}
		got[key] = elem

		// Grow halfway through iteration.
		if i == 16 {
			key := uint32(32)
			elem := uint64(256 + 32)

			for i := 0; i < grow; i++ {
				key += 1
				elem += 1
				m.Put(typ, unsafe.Pointer(&key), unsafe.Pointer(&elem))

				if maps.DebugLog {
					fmt.Printf("After put %d: %v\n", key, m)
				}
			}
		}
	}

	// Don't check length: the number of new elements we'll see is
	// unspecified.
}

// Grow should not allow duplicate keys to appear.
func TestTableIterationGrowDuplicate(t *testing.T) {
	// Small grow, only enough to cause table grow.
	t.Run("grow", func(t *testing.T) { testTableIterationGrowDuplicate(t, 32) })

	// Large grow, to cause table split.
	t.Run("split", func(t *testing.T) { testTableIterationGrowDuplicate(t, 2*maps.MaxTableCapacity) })
}

func TestAlignUpPow2(t *testing.T) {
	tests := []struct {
		in       uint64
		want     uint64
		overflow bool
	}{
		{
			in:   0,
			want: 0,
		},
		{
			in:   3,
			want: 4,
		},
		{
			in:   4,
			want: 4,
		},
		{
			in:   1 << 63,
			want: 1 << 63,
		},
		{
			in:   (1 << 63) - 1,
			want: 1 << 63,
		},
		{
			in:       (1 << 63) + 1,
			overflow: true,
		},
	}

	for _, tc := range tests {
		got, overflow := maps.AlignUpPow2(tc.in)
		if got != tc.want {
			t.Errorf("alignUpPow2(%d) got %d, want %d", tc.in, got, tc.want)
		}
		if overflow != tc.overflow {
			t.Errorf("alignUpPow2(%d) got overflow %v, want %v", tc.in, overflow, tc.overflow)
		}
	}
}

// Verify that a map with zero-size slot is safe to use.
func TestMapZeroSizeSlot(t *testing.T) {
	m, typ := maps.NewTestMap[struct{}, struct{}](16)

	key := struct{}{}
	elem := struct{}{}

	m.Put(typ, unsafe.Pointer(&key), unsafe.Pointer(&elem))

	if maps.DebugLog {
		fmt.Printf("After put %d: %v\n", key, m)
	}

	got, ok := m.Get(typ, unsafe.Pointer(&key))
	if !ok {
		t.Errorf("Get(%d) got ok false want true", key)
	}
	gotElem := *(*struct{})(got)
	if gotElem != elem {
		t.Errorf("Get(%d) got elem %d want %d", key, gotElem, elem)
	}

	tab := m.TableFor(typ, unsafe.Pointer(&key))
	start := tab.GroupsStart()
	length := tab.GroupsLength()
	end := unsafe.Pointer(uintptr(start) + length*typ.GroupSize - 1) // inclusive to ensure we have a valid pointer
	if uintptr(got) < uintptr(start) || uintptr(got) > uintptr(end) {
		t.Errorf("elem address outside groups allocation; got %p want [%p, %p]", got, start, end)
	}
}

func TestMapIndirect(t *testing.T) {
	type big [abi.SwissMapMaxKeyBytes + abi.SwissMapMaxElemBytes]byte

	m, typ := maps.NewTestMap[big, big](8)

	key := big{}
	elem := big{}
	elem[0] = 128

	for i := 0; i < 31; i++ {
		key[0] += 1
		elem[0] += 1
		m.Put(typ, unsafe.Pointer(&key), unsafe.Pointer(&elem))

		if maps.DebugLog {
			fmt.Printf("After put %v: %v\n", key, m)
		}
	}

	if m.Used() != 31 {
		t.Errorf("Used() used got %d want 31", m.Used())
	}

	key = big{}
	elem = big{}
	elem[0] = 128

	for i := 0; i < 31; i++ {
		key[0] += 1
		elem[0] += 1
		got, ok := m.Get(typ, unsafe.Pointer(&key))
		if !ok {
			t.Errorf("Get(%v) got ok false want true", key)
		}
		gotElem := *(*big)(got)
		if gotElem != elem {
			t.Errorf("Get(%v) got elem %v want %v", key, gotElem, elem)
		}
	}
}

// Delete should clear element. See https://go.dev/issue/25936.
func TestMapDeleteClear(t *testing.T) {
	m, typ := maps.NewTestMap[int64, int64](8)

	key := int64(0)
	elem := int64(128)

	m.Put(typ, unsafe.Pointer(&key), unsafe.Pointer(&elem))

	if maps.DebugLog {
		fmt.Printf("After put %d: %v\n", key, m)
	}

	got, ok := m.Get(typ, unsafe.Pointer(&key))
	if !ok {
		t.Errorf("Get(%d) got ok false want true", key)
	}
	gotElem := *(*int64)(got)
	if gotElem != elem {
		t.Errorf("Get(%d) got elem %d want %d", key, gotElem, elem)
	}

	m.Delete(typ, unsafe.Pointer(&key))

	gotElem = *(*int64)(got)
	if gotElem != 0 {
		t.Errorf("Delete(%d) failed to clear element. got %d want 0", key, gotElem)
	}
}

"""



```