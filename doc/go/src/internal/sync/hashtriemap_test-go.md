Response:
Let's break down the thought process for analyzing this Go code.

1. **Identify the Core Purpose:** The file name `hashtriemap_test.go` and the package name `sync_test` immediately suggest this is a test file for a data structure related to synchronization, specifically a hash trie map. The import of `internal/sync` confirms this.

2. **Examine the Top-Level Functions:** The first few functions are `TestHashTrieMap`, `TestHashTrieMapBadHash`, and `TestHashTrieMapTruncHash`. The `Test` prefix clearly indicates these are test functions. They all call `testHashTrieMap`, suggesting a common testing framework. The names "BadHash" and "TruncHash" hint at testing the map's behavior with intentionally poor hash functions.

3. **Analyze the Central Testing Function:** The `testHashTrieMap` function is the core of the testing logic. It takes a `newMap` function as an argument. This is a common pattern for testing interfaces or abstract data types – you can test different implementations using the same test suite. The various `t.Run` calls within this function indicate individual test cases.

4. **Understand Individual Test Cases:** Look at the names of the `t.Run` blocks: "LoadEmpty", "LoadOrStore", "All", "Clear", "CompareAndDelete", "CompareAndSwap", "Swap", "LoadAndDelete". These names directly correspond to common map operations. This strongly suggests the `HashTrieMap` is implementing a map-like interface.

5. **Infer the Data Structure's Functionality:** Based on the test cases, we can deduce the following functionalities of `HashTrieMap`:
    * **`Load(key)`:**  Retrieves a value associated with a key.
    * **`LoadOrStore(key, value)`:**  Retrieves the existing value for a key or stores a new value if the key is absent.
    * **`Clear()`:** Removes all entries from the map.
    * **`CompareAndDelete(key, oldValue)`:** Atomically deletes a key-value pair if the current value matches the provided `oldValue`.
    * **`CompareAndSwap(key, oldValue, newValue)`:** Atomically updates the value associated with a key if the current value matches `oldValue`.
    * **`Swap(key, newValue)`:** Atomically replaces the value associated with a key and returns the old value.
    * **`LoadAndDelete(key)`:** Atomically retrieves and removes the value associated with a key.
    * **`All()`:** Provides a way to iterate over all key-value pairs in the map.

6. **Look for Helper Functions and Assertions:** Functions like `expectPresent`, `expectMissing`, `expectLoaded`, etc., are helper functions for making assertions within the tests. They simplify the test code and make it more readable. The names clearly indicate the expected outcome of the operations being tested.

7. **Infer the Purpose of the "BadHash" and "TruncHash" Tests:** These tests indicate the `HashTrieMap` is designed to handle situations where the hash function might not be ideal (leading to more collisions). This suggests a robust implementation that doesn't rely on perfect hashing.

8. **Consider Concurrency:** The presence of `t.Run` blocks with "Concurrent" in their names, along with the use of `sync.WaitGroup` and `runtime.GOMAXPROCS`, strongly implies that the `HashTrieMap` is designed to be used concurrently and the tests are verifying its thread-safety.

9. **Code Examples (Mental Exercise):**  Imagine how you would use a standard `map` in Go and how these test cases are exercising similar behavior but with atomicity and concurrency considerations. For example, `LoadOrStore` is similar to checking if a key exists and then either retrieving or setting the value.

10. **Identify Potential Pitfalls (Based on Testing):** The tests for `CompareAndDelete` and `CompareAndSwap` reveal a common pitfall:  failing to check the return value (a boolean indicating success) can lead to incorrect assumptions about whether the operation succeeded. The concurrent tests highlight potential race conditions if the map wasn't designed for concurrency.

11. **Structure the Answer:** Organize the findings into the requested categories: functionality, inferred Go feature, code examples (illustrating usage and concurrency), command-line arguments (note their absence), and potential pitfalls.

12. **Refine and Elaborate:**  Fill in the details for each section, providing clear explanations and code examples where needed. Use precise language and refer back to specific parts of the code when explaining a feature. For instance, when discussing concurrency, mention the use of goroutines and `sync.WaitGroup`.

This systematic approach of examining the code structure, function names, test cases, and helper functions allows for a comprehensive understanding of the provided Go code snippet and the functionality it tests.
这段Go语言代码是 `internal/sync` 包中 `HashTrieMap` 类型的测试代码。它的主要功能是**测试 `HashTrieMap` 这个并发安全哈希树映射的各种操作的正确性**。

从代码的结构和测试用例来看，`HashTrieMap` 实现了类似 Go 语言标准库 `sync.Map` 的功能，但底层数据结构可能使用了哈希树（Hash Trie）来提高并发性能。

**`HashTrieMap` 的功能 (从测试代码推断):**

1. **存储和加载键值对:**
   - `Load(key)`:  根据键加载对应的值。
   - `LoadOrStore(key, value)`:  如果键存在则返回已有的值，否则存储新的键值对。

2. **清除所有键值对:**
   - `Clear()`:  清空哈希树映射中的所有元素。

3. **条件删除键值对:**
   - `CompareAndDelete(key, oldValue)`:  如果键存在且对应的值与 `oldValue` 相等，则删除该键值对。

4. **条件替换键值对:**
   - `CompareAndSwap(key, oldValue, newValue)`: 如果键存在且对应的值与 `oldValue` 相等，则将值替换为 `newValue`。

5. **替换键值对并返回旧值:**
   - `Swap(key, newValue)`:  替换键对应的值，并返回旧的值。如果键不存在，则存储新值并返回零值。

6. **加载并删除键值对:**
   - `LoadAndDelete(key)`:  加载键对应的值并删除该键值对。

7. **遍历所有键值对:**
   - `All()`: 提供一种遍历所有键值对的方式。

**`HashTrieMap` 的 Go 语言功能实现推断:**

从测试代码的方法名和行为来看，`HashTrieMap` 很有可能是在实现一个**并发安全的 Map**，其目的是在并发环境下提供高效的键值对存储和访问能力。它与 `sync.Map` 的功能类似，但可能在实现细节上有所不同，例如使用了哈希树这种数据结构。

**Go 代码举例说明:**

假设 `HashTrieMap` 的基本用法与 `sync.Map` 类似，我们可以这样使用：

```go
package main

import (
	"fmt"
	isync "internal/sync"
	"sync"
)

func main() {
	var m isync.HashTrieMap[string, int]

	// 存储键值对
	m.LoadOrStore("apple", 1)
	m.LoadOrStore("banana", 2)

	// 加载值
	val, ok := m.Load("apple")
	fmt.Println("apple:", val, ok) // 输出: apple: 1 true

	val, ok = m.Load("orange")
	fmt.Println("orange:", val, ok) // 输出: orange: 0 false

	// 加载或存储
	val, loaded := m.LoadOrStore("grape", 3)
	fmt.Println("grape (store):", val, loaded) // 输出: grape (store): 3 false

	val, loaded = m.LoadOrStore("apple", 4)
	fmt.Println("apple (load):", val, loaded)  // 输出: apple (load): 1 true

	// 条件删除
	deleted := m.CompareAndDelete("banana", 2)
	fmt.Println("delete banana:", deleted) // 输出: delete banana: true
	_, ok = m.Load("banana")
	fmt.Println("banana after delete:", ok) // 输出: banana after delete: false

	// 条件替换
	swapped := m.CompareAndSwap("apple", 1, 5)
	fmt.Println("swap apple:", swapped) // 输出: swap apple: false (因为当前值是 1)
	swapped = m.CompareAndSwap("apple", 4, 5)
	fmt.Println("swap apple:", swapped) // 输出: swap apple: true
	val, _ = m.Load("apple")
	fmt.Println("apple after swap:", val) // 输出: apple after swap: 5

	// 替换并返回旧值
	oldVal, loaded := m.Swap("grape", 6)
	fmt.Println("swap grape:", oldVal, loaded) // 输出: swap grape: 3 true
	val, _ = m.Load("grape")
	fmt.Println("grape after swap:", val)       // 输出: grape after swap: 6

	oldVal, loaded = m.Swap("kiwi", 7)
	fmt.Println("swap kiwi:", oldVal, loaded)  // 输出: swap kiwi: 0 false
	val, _ = m.Load("kiwi")
	fmt.Println("kiwi after swap:", val)        // 输出: kiwi after swap: 7

	// 加载并删除
	deletedVal, loaded := m.LoadAndDelete("apple")
	fmt.Println("load and delete apple:", deletedVal, loaded) // 输出: load and delete apple: 5 true
	_, ok = m.Load("apple")
	fmt.Println("apple after load and delete:", ok)        // 输出: apple after load and delete: false

	// 遍历所有
	fmt.Println("All items:")
	m.All()(func(key string, value int) bool {
		fmt.Printf("%s: %d\n", key, value)
		return true
	})
	// 可能输出:
	// All items:
	// grape: 6
	// kiwi: 7
}

func concurrentAccess(m *isync.HashTrieMap[string, int], key string, value int, wg *sync.WaitGroup) {
	defer wg.Done()
	m.LoadOrStore(key, value)
	loadedValue, _ := m.Load(key)
	fmt.Printf("Goroutine loaded %s: %d\n", key, loadedValue)
}

func main_concurrent() {
	var m isync.HashTrieMap[string, int]
	var wg sync.WaitGroup

	keys := []string{"a", "b", "c", "d", "e"}
	for i, key := range keys {
		wg.Add(1)
		go concurrentAccess(&m, key, i+1, &wg)
	}

	wg.Wait()

	fmt.Println("Final map:")
	m.All()(func(key string, value int) bool {
		fmt.Printf("%s: %d\n", key, value)
		return true
	})
}
```

**假设的输入与输出 (基于 `TestHashTrieMap` 中的测试用例):**

`TestHashTrieMap` 函数包含了多个子测试用例，每个用例针对 `HashTrieMap` 的不同功能进行测试。以下举例说明 `LoadOrStore` 测试用例：

**假设输入 (`testData` 和 `testHashTrieMap` 函数):**

```go
var testData = [128]string{"0", "1", "10", "11", ..., "1111111"} // 一系列字符串

func TestHashTrieMap(t *testing.T) {
	testHashTrieMap(t, func() *isync.HashTrieMap[string, int] {
		var m isync.HashTrieMap[string, int]
		return &m
	})
}

func testHashTrieMap(t *testing.T, newMap func() *isync.HashTrieMap[string, int]) {
	t.Run("LoadOrStore", func(t *testing.T) {
		m := newMap()
		// ... (测试逻辑) ...
	})
	// ...
}
```

**`LoadOrStore` 测试用例的推理和假设输出:**

在 `LoadOrStore` 测试用例中，代码会遍历 `testData`，并对每个字符串 `s` 执行 `Load` 和 `LoadOrStore` 操作。

1. **首次 `Load(s)`:** 由于映射初始为空，所以 `m.Load(s)` 应该返回零值 (对于 `int` 是 0) 和 `false` (表示键不存在)。测试代码中的 `expectMissing(t, s, 0)(m.Load(s))` 就是在断言这种情况。

   **假设输出:** 对于 `testData` 中的任意字符串 "0"，"1" 等， `m.Load("0")` 的返回结果是 `(0, false)`。

2. **首次 `LoadOrStore(s, i)`:**  由于键不存在，`m.LoadOrStore(s, i)` 会将键 `s` 和对应索引 `i` 存储到映射中，并返回存储的值 `i` 和 `false` (表示是新存储的)。 测试代码中的 `expectStored(t, s, i)(m.LoadOrStore(s, i))` 就是在断言这种情况。

   **假设输出:**  `m.LoadOrStore("0", 0)` 的返回结果是 `(0, false)`。 `m.LoadOrStore("1", 1)` 的返回结果是 `(1, false)`，以此类推。

3. **第二次 `Load(s)`:** 此时键 `s` 已经存在于映射中，`m.Load(s)` 应该返回之前存储的值 `i` 和 `true`。测试代码中的 `expectPresent(t, s, i)(m.Load(s))` 就是在断言这种情况。

   **假设输出:** 在执行 `m.LoadOrStore("0", 0)` 后， `m.Load("0")` 的返回结果是 `(0, true)`。

4. **第二次 `LoadOrStore(s, 0)`:** 此时键 `s` 已经存在，`m.LoadOrStore(s, 0)` 不会修改已有的值，而是返回已有的值 `i` 和 `true` (表示是已加载的)。测试代码中的 `expectLoaded(t, s, i)(m.LoadOrStore(s, 0))` 就是在断言这种情况。

   **假设输出:** 在执行 `m.LoadOrStore("0", 0)` 后， `m.LoadOrStore("0", 0)` 的返回结果是 `(0, true)`。

**命令行参数的具体处理:**

这段代码是测试代码，主要用于单元测试。它**不涉及任何命令行参数的处理**。Go 语言的测试是通过 `go test` 命令来执行的，不需要传递额外的命令行参数来控制这些测试用例的行为。

**使用者易犯错的点:**

由于 `HashTrieMap` 是并发安全的，使用者在从其他非并发安全的 `map` 迁移过来时，可能会忽略其提供的原子操作，导致一些潜在的并发问题。

**例如：**

```go
// 错误的做法 (非原子操作，可能存在竞态条件)
func increment(m *isync.HashTrieMap[string, int], key string) {
	val, ok := m.Load(key)
	if ok {
		m.Store(key, val+1) // HashTrieMap 没有 Store 方法，假设有
	} else {
		m.Store(key, 1)      // HashTrieMap 没有 Store 方法，假设有
	}
}

// 正确的做法 (使用原子操作)
func incrementCorrect(m *isync.HashTrieMap[string, int], key string) {
	for {
		current, ok := m.Load(key)
		newValue := 1
		if ok {
			newValue = current + 1
		}
		if m.CompareAndSwap(key, current, newValue) {
			return
		}
	}
}

// 更简洁的正确做法
func incrementCorrectSimplified(m *isync.HashTrieMap[string, int], key string) {
    m.LoadOrStore(key, 0) // 确保键存在
    for {
        oldValue, _ := m.Load(key)
        if m.CompareAndSwap(key, oldValue, oldValue+1) {
            return
        }
    }
}

// 使用 Swap 的做法
func incrementWithSwap(m *isync.HashTrieMap[string, int], key string) {
    for {
        oldValue, _ := m.LoadOrStore(key, 0) // 如果不存在则初始化为 0
        newValue := oldValue + 1
        if _, loaded := m.Swap(key, newValue); loaded {
            return
        }
    }
}
```

在错误的例子中，`Load` 和 `Store` (假设存在) 操作不是原子的。在并发环境下，多个 goroutine 可能同时读取到相同的值，然后进行加一操作，最终导致数据不一致。

正确的做法是使用 `HashTrieMap` 提供的原子操作，如 `CompareAndSwap` 或 `LoadOrStore` 结合循环重试，来确保操作的原子性。

总结来说，这段代码是 `internal/sync` 包中 `HashTrieMap` 的测试代码，用于验证其作为并发安全哈希树映射的各种操作的正确性。使用者需要理解其提供的原子操作，以避免在并发环境下出现数据竞争等问题。

### 提示词
```
这是路径为go/src/internal/sync/hashtriemap_test.go的go语言实现的一部分， 请列举一下它的功能, 　
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

package sync_test

import (
	"fmt"
	isync "internal/sync"
	"math"
	"runtime"
	"strconv"
	"sync"
	"testing"
)

func TestHashTrieMap(t *testing.T) {
	testHashTrieMap(t, func() *isync.HashTrieMap[string, int] {
		var m isync.HashTrieMap[string, int]
		return &m
	})
}

func TestHashTrieMapBadHash(t *testing.T) {
	testHashTrieMap(t, func() *isync.HashTrieMap[string, int] {
		return isync.NewBadHashTrieMap[string, int]()
	})
}

func TestHashTrieMapTruncHash(t *testing.T) {
	testHashTrieMap(t, func() *isync.HashTrieMap[string, int] {
		// Stub out the good hash function with a different terrible one
		// (truncated hash). Everything should still work as expected.
		// This is useful to test independently to catch issues with
		// near collisions, where only the last few bits of the hash differ.
		return isync.NewTruncHashTrieMap[string, int]()
	})
}

func testHashTrieMap(t *testing.T, newMap func() *isync.HashTrieMap[string, int]) {
	t.Run("LoadEmpty", func(t *testing.T) {
		m := newMap()

		for _, s := range testData {
			expectMissing(t, s, 0)(m.Load(s))
		}
	})
	t.Run("LoadOrStore", func(t *testing.T) {
		m := newMap()

		for i, s := range testData {
			expectMissing(t, s, 0)(m.Load(s))
			expectStored(t, s, i)(m.LoadOrStore(s, i))
			expectPresent(t, s, i)(m.Load(s))
			expectLoaded(t, s, i)(m.LoadOrStore(s, 0))
		}
		for i, s := range testData {
			expectPresent(t, s, i)(m.Load(s))
			expectLoaded(t, s, i)(m.LoadOrStore(s, 0))
		}
	})
	t.Run("All", func(t *testing.T) {
		m := newMap()

		testAll(t, m, testDataMap(testData[:]), func(_ string, _ int) bool {
			return true
		})
	})
	t.Run("Clear", func(t *testing.T) {
		t.Run("Simple", func(t *testing.T) {
			m := newMap()

			for i, s := range testData {
				expectMissing(t, s, 0)(m.Load(s))
				expectStored(t, s, i)(m.LoadOrStore(s, i))
				expectPresent(t, s, i)(m.Load(s))
				expectLoaded(t, s, i)(m.LoadOrStore(s, 0))
			}
			m.Clear()
			for _, s := range testData {
				expectMissing(t, s, 0)(m.Load(s))
			}
		})
		t.Run("Concurrent", func(t *testing.T) {
			m := newMap()

			// Load up the map.
			for i, s := range testData {
				expectMissing(t, s, 0)(m.Load(s))
				expectStored(t, s, i)(m.LoadOrStore(s, i))
			}
			gmp := runtime.GOMAXPROCS(-1)
			var wg sync.WaitGroup
			for i := range gmp {
				wg.Add(1)
				go func(id int) {
					defer wg.Done()

					for _, s := range testData {
						// Try a couple things to interfere with the clear.
						expectNotDeleted(t, s, math.MaxInt)(m.CompareAndDelete(s, math.MaxInt))
						m.CompareAndSwap(s, i, i+1) // May succeed or fail; we don't care.
					}
				}(i)
			}

			// Concurrently clear the map.
			runtime.Gosched()
			m.Clear()

			// Wait for workers to finish.
			wg.Wait()

			// It should all be empty now.
			for _, s := range testData {
				expectMissing(t, s, 0)(m.Load(s))
			}
		})
	})
	t.Run("CompareAndDelete", func(t *testing.T) {
		t.Run("All", func(t *testing.T) {
			m := newMap()

			for range 3 {
				for i, s := range testData {
					expectMissing(t, s, 0)(m.Load(s))
					expectStored(t, s, i)(m.LoadOrStore(s, i))
					expectPresent(t, s, i)(m.Load(s))
					expectLoaded(t, s, i)(m.LoadOrStore(s, 0))
				}
				for i, s := range testData {
					expectPresent(t, s, i)(m.Load(s))
					expectNotDeleted(t, s, math.MaxInt)(m.CompareAndDelete(s, math.MaxInt))
					expectDeleted(t, s, i)(m.CompareAndDelete(s, i))
					expectNotDeleted(t, s, i)(m.CompareAndDelete(s, i))
					expectMissing(t, s, 0)(m.Load(s))
				}
				for _, s := range testData {
					expectMissing(t, s, 0)(m.Load(s))
				}
			}
		})
		t.Run("One", func(t *testing.T) {
			m := newMap()

			for i, s := range testData {
				expectMissing(t, s, 0)(m.Load(s))
				expectStored(t, s, i)(m.LoadOrStore(s, i))
				expectPresent(t, s, i)(m.Load(s))
				expectLoaded(t, s, i)(m.LoadOrStore(s, 0))
			}
			expectNotDeleted(t, testData[15], math.MaxInt)(m.CompareAndDelete(testData[15], math.MaxInt))
			expectDeleted(t, testData[15], 15)(m.CompareAndDelete(testData[15], 15))
			expectNotDeleted(t, testData[15], 15)(m.CompareAndDelete(testData[15], 15))
			for i, s := range testData {
				if i == 15 {
					expectMissing(t, s, 0)(m.Load(s))
				} else {
					expectPresent(t, s, i)(m.Load(s))
				}
			}
		})
		t.Run("Multiple", func(t *testing.T) {
			m := newMap()

			for i, s := range testData {
				expectMissing(t, s, 0)(m.Load(s))
				expectStored(t, s, i)(m.LoadOrStore(s, i))
				expectPresent(t, s, i)(m.Load(s))
				expectLoaded(t, s, i)(m.LoadOrStore(s, 0))
			}
			for _, i := range []int{1, 105, 6, 85} {
				expectNotDeleted(t, testData[i], math.MaxInt)(m.CompareAndDelete(testData[i], math.MaxInt))
				expectDeleted(t, testData[i], i)(m.CompareAndDelete(testData[i], i))
				expectNotDeleted(t, testData[i], i)(m.CompareAndDelete(testData[i], i))
			}
			for i, s := range testData {
				if i == 1 || i == 105 || i == 6 || i == 85 {
					expectMissing(t, s, 0)(m.Load(s))
				} else {
					expectPresent(t, s, i)(m.Load(s))
				}
			}
		})
		t.Run("Iterate", func(t *testing.T) {
			m := newMap()

			testAll(t, m, testDataMap(testData[:]), func(s string, i int) bool {
				expectDeleted(t, s, i)(m.CompareAndDelete(s, i))
				return true
			})
			for _, s := range testData {
				expectMissing(t, s, 0)(m.Load(s))
			}
		})
		t.Run("ConcurrentUnsharedKeys", func(t *testing.T) {
			m := newMap()

			gmp := runtime.GOMAXPROCS(-1)
			var wg sync.WaitGroup
			for i := range gmp {
				wg.Add(1)
				go func(id int) {
					defer wg.Done()

					makeKey := func(s string) string {
						return s + "-" + strconv.Itoa(id)
					}
					for _, s := range testData {
						key := makeKey(s)
						expectMissing(t, key, 0)(m.Load(key))
						expectStored(t, key, id)(m.LoadOrStore(key, id))
						expectPresent(t, key, id)(m.Load(key))
						expectLoaded(t, key, id)(m.LoadOrStore(key, 0))
					}
					for _, s := range testData {
						key := makeKey(s)
						expectPresent(t, key, id)(m.Load(key))
						expectDeleted(t, key, id)(m.CompareAndDelete(key, id))
						expectMissing(t, key, 0)(m.Load(key))
					}
					for _, s := range testData {
						key := makeKey(s)
						expectMissing(t, key, 0)(m.Load(key))
					}
				}(i)
			}
			wg.Wait()
		})
		t.Run("ConcurrentSharedKeys", func(t *testing.T) {
			m := newMap()

			// Load up the map.
			for i, s := range testData {
				expectMissing(t, s, 0)(m.Load(s))
				expectStored(t, s, i)(m.LoadOrStore(s, i))
			}
			gmp := runtime.GOMAXPROCS(-1)
			var wg sync.WaitGroup
			for i := range gmp {
				wg.Add(1)
				go func(id int) {
					defer wg.Done()

					for i, s := range testData {
						expectNotDeleted(t, s, math.MaxInt)(m.CompareAndDelete(s, math.MaxInt))
						m.CompareAndDelete(s, i)
						expectMissing(t, s, 0)(m.Load(s))
					}
					for _, s := range testData {
						expectMissing(t, s, 0)(m.Load(s))
					}
				}(i)
			}
			wg.Wait()
		})
	})
	t.Run("CompareAndSwap", func(t *testing.T) {
		t.Run("All", func(t *testing.T) {
			m := newMap()

			for i, s := range testData {
				expectMissing(t, s, 0)(m.Load(s))
				expectStored(t, s, i)(m.LoadOrStore(s, i))
				expectPresent(t, s, i)(m.Load(s))
				expectLoaded(t, s, i)(m.LoadOrStore(s, 0))
			}
			for j := range 3 {
				for i, s := range testData {
					expectPresent(t, s, i+j)(m.Load(s))
					expectNotSwapped(t, s, math.MaxInt, i+j+1)(m.CompareAndSwap(s, math.MaxInt, i+j+1))
					expectSwapped(t, s, i, i+j+1)(m.CompareAndSwap(s, i+j, i+j+1))
					expectNotSwapped(t, s, i+j, i+j+1)(m.CompareAndSwap(s, i+j, i+j+1))
					expectPresent(t, s, i+j+1)(m.Load(s))
				}
			}
			for i, s := range testData {
				expectPresent(t, s, i+3)(m.Load(s))
			}
		})
		t.Run("One", func(t *testing.T) {
			m := newMap()

			for i, s := range testData {
				expectMissing(t, s, 0)(m.Load(s))
				expectStored(t, s, i)(m.LoadOrStore(s, i))
				expectPresent(t, s, i)(m.Load(s))
				expectLoaded(t, s, i)(m.LoadOrStore(s, 0))
			}
			expectNotSwapped(t, testData[15], math.MaxInt, 16)(m.CompareAndSwap(testData[15], math.MaxInt, 16))
			expectSwapped(t, testData[15], 15, 16)(m.CompareAndSwap(testData[15], 15, 16))
			expectNotSwapped(t, testData[15], 15, 16)(m.CompareAndSwap(testData[15], 15, 16))
			for i, s := range testData {
				if i == 15 {
					expectPresent(t, s, 16)(m.Load(s))
				} else {
					expectPresent(t, s, i)(m.Load(s))
				}
			}
		})
		t.Run("Multiple", func(t *testing.T) {
			m := newMap()

			for i, s := range testData {
				expectMissing(t, s, 0)(m.Load(s))
				expectStored(t, s, i)(m.LoadOrStore(s, i))
				expectPresent(t, s, i)(m.Load(s))
				expectLoaded(t, s, i)(m.LoadOrStore(s, 0))
			}
			for _, i := range []int{1, 105, 6, 85} {
				expectNotSwapped(t, testData[i], math.MaxInt, i+1)(m.CompareAndSwap(testData[i], math.MaxInt, i+1))
				expectSwapped(t, testData[i], i, i+1)(m.CompareAndSwap(testData[i], i, i+1))
				expectNotSwapped(t, testData[i], i, i+1)(m.CompareAndSwap(testData[i], i, i+1))
			}
			for i, s := range testData {
				if i == 1 || i == 105 || i == 6 || i == 85 {
					expectPresent(t, s, i+1)(m.Load(s))
				} else {
					expectPresent(t, s, i)(m.Load(s))
				}
			}
		})

		t.Run("ConcurrentUnsharedKeys", func(t *testing.T) {
			m := newMap()

			gmp := runtime.GOMAXPROCS(-1)
			var wg sync.WaitGroup
			for i := range gmp {
				wg.Add(1)
				go func(id int) {
					defer wg.Done()

					makeKey := func(s string) string {
						return s + "-" + strconv.Itoa(id)
					}
					for _, s := range testData {
						key := makeKey(s)
						expectMissing(t, key, 0)(m.Load(key))
						expectStored(t, key, id)(m.LoadOrStore(key, id))
						expectPresent(t, key, id)(m.Load(key))
						expectLoaded(t, key, id)(m.LoadOrStore(key, 0))
					}
					for _, s := range testData {
						key := makeKey(s)
						expectPresent(t, key, id)(m.Load(key))
						expectSwapped(t, key, id, id+1)(m.CompareAndSwap(key, id, id+1))
						expectPresent(t, key, id+1)(m.Load(key))
					}
					for _, s := range testData {
						key := makeKey(s)
						expectPresent(t, key, id+1)(m.Load(key))
					}
				}(i)
			}
			wg.Wait()
		})
		t.Run("ConcurrentUnsharedKeysWithDelete", func(t *testing.T) {
			m := newMap()

			gmp := runtime.GOMAXPROCS(-1)
			var wg sync.WaitGroup
			for i := range gmp {
				wg.Add(1)
				go func(id int) {
					defer wg.Done()

					makeKey := func(s string) string {
						return s + "-" + strconv.Itoa(id)
					}
					for _, s := range testData {
						key := makeKey(s)
						expectMissing(t, key, 0)(m.Load(key))
						expectStored(t, key, id)(m.LoadOrStore(key, id))
						expectPresent(t, key, id)(m.Load(key))
						expectLoaded(t, key, id)(m.LoadOrStore(key, 0))
					}
					for _, s := range testData {
						key := makeKey(s)
						expectPresent(t, key, id)(m.Load(key))
						expectSwapped(t, key, id, id+1)(m.CompareAndSwap(key, id, id+1))
						expectPresent(t, key, id+1)(m.Load(key))
						expectDeleted(t, key, id+1)(m.CompareAndDelete(key, id+1))
						expectNotSwapped(t, key, id+1, id+2)(m.CompareAndSwap(key, id+1, id+2))
						expectNotDeleted(t, key, id+1)(m.CompareAndDelete(key, id+1))
						expectMissing(t, key, 0)(m.Load(key))
					}
					for _, s := range testData {
						key := makeKey(s)
						expectMissing(t, key, 0)(m.Load(key))
					}
				}(i)
			}
			wg.Wait()
		})
		t.Run("ConcurrentSharedKeys", func(t *testing.T) {
			m := newMap()

			// Load up the map.
			for i, s := range testData {
				expectMissing(t, s, 0)(m.Load(s))
				expectStored(t, s, i)(m.LoadOrStore(s, i))
			}
			gmp := runtime.GOMAXPROCS(-1)
			var wg sync.WaitGroup
			for i := range gmp {
				wg.Add(1)
				go func(id int) {
					defer wg.Done()

					for i, s := range testData {
						expectNotSwapped(t, s, math.MaxInt, i+1)(m.CompareAndSwap(s, math.MaxInt, i+1))
						m.CompareAndSwap(s, i, i+1)
						expectPresent(t, s, i+1)(m.Load(s))
					}
					for i, s := range testData {
						expectPresent(t, s, i+1)(m.Load(s))
					}
				}(i)
			}
			wg.Wait()
		})
	})
	t.Run("Swap", func(t *testing.T) {
		t.Run("All", func(t *testing.T) {
			m := newMap()

			for i, s := range testData {
				expectMissing(t, s, 0)(m.Load(s))
				expectNotLoadedFromSwap(t, s, i)(m.Swap(s, i))
				expectPresent(t, s, i)(m.Load(s))
				expectLoadedFromSwap(t, s, i, i)(m.Swap(s, i))
			}
			for j := range 3 {
				for i, s := range testData {
					expectPresent(t, s, i+j)(m.Load(s))
					expectLoadedFromSwap(t, s, i+j, i+j+1)(m.Swap(s, i+j+1))
					expectPresent(t, s, i+j+1)(m.Load(s))
				}
			}
			for i, s := range testData {
				expectLoadedFromSwap(t, s, i+3, i+3)(m.Swap(s, i+3))
			}
		})
		t.Run("One", func(t *testing.T) {
			m := newMap()

			for i, s := range testData {
				expectMissing(t, s, 0)(m.Load(s))
				expectNotLoadedFromSwap(t, s, i)(m.Swap(s, i))
				expectPresent(t, s, i)(m.Load(s))
				expectLoadedFromSwap(t, s, i, i)(m.Swap(s, i))
			}
			expectLoadedFromSwap(t, testData[15], 15, 16)(m.Swap(testData[15], 16))
			for i, s := range testData {
				if i == 15 {
					expectPresent(t, s, 16)(m.Load(s))
				} else {
					expectPresent(t, s, i)(m.Load(s))
				}
			}
		})
		t.Run("Multiple", func(t *testing.T) {
			m := newMap()

			for i, s := range testData {
				expectMissing(t, s, 0)(m.Load(s))
				expectNotLoadedFromSwap(t, s, i)(m.Swap(s, i))
				expectPresent(t, s, i)(m.Load(s))
				expectLoadedFromSwap(t, s, i, i)(m.Swap(s, i))
			}
			for _, i := range []int{1, 105, 6, 85} {
				expectLoadedFromSwap(t, testData[i], i, i+1)(m.Swap(testData[i], i+1))
			}
			for i, s := range testData {
				if i == 1 || i == 105 || i == 6 || i == 85 {
					expectPresent(t, s, i+1)(m.Load(s))
				} else {
					expectPresent(t, s, i)(m.Load(s))
				}
			}
		})
		t.Run("ConcurrentUnsharedKeys", func(t *testing.T) {
			m := newMap()

			gmp := runtime.GOMAXPROCS(-1)
			var wg sync.WaitGroup
			for i := range gmp {
				wg.Add(1)
				go func(id int) {
					defer wg.Done()

					makeKey := func(s string) string {
						return s + "-" + strconv.Itoa(id)
					}
					for _, s := range testData {
						key := makeKey(s)
						expectMissing(t, key, 0)(m.Load(key))
						expectNotLoadedFromSwap(t, key, id)(m.Swap(key, id))
						expectPresent(t, key, id)(m.Load(key))
						expectLoadedFromSwap(t, key, id, id)(m.Swap(key, id))
					}
					for _, s := range testData {
						key := makeKey(s)
						expectPresent(t, key, id)(m.Load(key))
						expectLoadedFromSwap(t, key, id, id+1)(m.Swap(key, id+1))
						expectPresent(t, key, id+1)(m.Load(key))
					}
					for _, s := range testData {
						key := makeKey(s)
						expectPresent(t, key, id+1)(m.Load(key))
					}
				}(i)
			}
			wg.Wait()
		})
		t.Run("ConcurrentUnsharedKeysWithDelete", func(t *testing.T) {
			m := newMap()

			gmp := runtime.GOMAXPROCS(-1)
			var wg sync.WaitGroup
			for i := range gmp {
				wg.Add(1)
				go func(id int) {
					defer wg.Done()

					makeKey := func(s string) string {
						return s + "-" + strconv.Itoa(id)
					}
					for _, s := range testData {
						key := makeKey(s)
						expectMissing(t, key, 0)(m.Load(key))
						expectNotLoadedFromSwap(t, key, id)(m.Swap(key, id))
						expectPresent(t, key, id)(m.Load(key))
						expectLoadedFromSwap(t, key, id, id)(m.Swap(key, id))
					}
					for _, s := range testData {
						key := makeKey(s)
						expectPresent(t, key, id)(m.Load(key))
						expectLoadedFromSwap(t, key, id, id+1)(m.Swap(key, id+1))
						expectPresent(t, key, id+1)(m.Load(key))
						expectDeleted(t, key, id+1)(m.CompareAndDelete(key, id+1))
						expectNotLoadedFromSwap(t, key, id+2)(m.Swap(key, id+2))
						expectPresent(t, key, id+2)(m.Load(key))
					}
					for _, s := range testData {
						key := makeKey(s)
						expectPresent(t, key, id+2)(m.Load(key))
					}
				}(i)
			}
			wg.Wait()
		})
		t.Run("ConcurrentSharedKeys", func(t *testing.T) {
			m := newMap()

			// Load up the map.
			for i, s := range testData {
				expectMissing(t, s, 0)(m.Load(s))
				expectStored(t, s, i)(m.LoadOrStore(s, i))
			}
			gmp := runtime.GOMAXPROCS(-1)
			var wg sync.WaitGroup
			for i := range gmp {
				wg.Add(1)
				go func(id int) {
					defer wg.Done()

					for i, s := range testData {
						m.Swap(s, i+1)
						expectPresent(t, s, i+1)(m.Load(s))
					}
					for i, s := range testData {
						expectPresent(t, s, i+1)(m.Load(s))
					}
				}(i)
			}
			wg.Wait()
		})
	})
	t.Run("LoadAndDelete", func(t *testing.T) {
		t.Run("All", func(t *testing.T) {
			m := newMap()

			for range 3 {
				for i, s := range testData {
					expectMissing(t, s, 0)(m.Load(s))
					expectStored(t, s, i)(m.LoadOrStore(s, i))
					expectPresent(t, s, i)(m.Load(s))
					expectLoaded(t, s, i)(m.LoadOrStore(s, 0))
				}
				for i, s := range testData {
					expectPresent(t, s, i)(m.Load(s))
					expectLoadedFromDelete(t, s, i)(m.LoadAndDelete(s))
					expectMissing(t, s, 0)(m.Load(s))
					expectNotLoadedFromDelete(t, s, 0)(m.LoadAndDelete(s))
				}
				for _, s := range testData {
					expectMissing(t, s, 0)(m.Load(s))
				}
			}
		})
		t.Run("One", func(t *testing.T) {
			m := newMap()

			for i, s := range testData {
				expectMissing(t, s, 0)(m.Load(s))
				expectStored(t, s, i)(m.LoadOrStore(s, i))
				expectPresent(t, s, i)(m.Load(s))
				expectLoaded(t, s, i)(m.LoadOrStore(s, 0))
			}
			expectPresent(t, testData[15], 15)(m.Load(testData[15]))
			expectLoadedFromDelete(t, testData[15], 15)(m.LoadAndDelete(testData[15]))
			expectMissing(t, testData[15], 0)(m.Load(testData[15]))
			expectNotLoadedFromDelete(t, testData[15], 0)(m.LoadAndDelete(testData[15]))
			for i, s := range testData {
				if i == 15 {
					expectMissing(t, s, 0)(m.Load(s))
				} else {
					expectPresent(t, s, i)(m.Load(s))
				}
			}
		})
		t.Run("Multiple", func(t *testing.T) {
			m := newMap()

			for i, s := range testData {
				expectMissing(t, s, 0)(m.Load(s))
				expectStored(t, s, i)(m.LoadOrStore(s, i))
				expectPresent(t, s, i)(m.Load(s))
				expectLoaded(t, s, i)(m.LoadOrStore(s, 0))
			}
			for _, i := range []int{1, 105, 6, 85} {
				expectPresent(t, testData[i], i)(m.Load(testData[i]))
				expectLoadedFromDelete(t, testData[i], i)(m.LoadAndDelete(testData[i]))
				expectMissing(t, testData[i], 0)(m.Load(testData[i]))
				expectNotLoadedFromDelete(t, testData[i], 0)(m.LoadAndDelete(testData[i]))
			}
			for i, s := range testData {
				if i == 1 || i == 105 || i == 6 || i == 85 {
					expectMissing(t, s, 0)(m.Load(s))
				} else {
					expectPresent(t, s, i)(m.Load(s))
				}
			}
		})
		t.Run("Iterate", func(t *testing.T) {
			m := newMap()

			testAll(t, m, testDataMap(testData[:]), func(s string, i int) bool {
				expectLoadedFromDelete(t, s, i)(m.LoadAndDelete(s))
				return true
			})
			for _, s := range testData {
				expectMissing(t, s, 0)(m.Load(s))
			}
		})
		t.Run("ConcurrentUnsharedKeys", func(t *testing.T) {
			m := newMap()

			gmp := runtime.GOMAXPROCS(-1)
			var wg sync.WaitGroup
			for i := range gmp {
				wg.Add(1)
				go func(id int) {
					defer wg.Done()

					makeKey := func(s string) string {
						return s + "-" + strconv.Itoa(id)
					}
					for _, s := range testData {
						key := makeKey(s)
						expectMissing(t, key, 0)(m.Load(key))
						expectStored(t, key, id)(m.LoadOrStore(key, id))
						expectPresent(t, key, id)(m.Load(key))
						expectLoaded(t, key, id)(m.LoadOrStore(key, 0))
					}
					for _, s := range testData {
						key := makeKey(s)
						expectPresent(t, key, id)(m.Load(key))
						expectLoadedFromDelete(t, key, id)(m.LoadAndDelete(key))
						expectMissing(t, key, 0)(m.Load(key))
					}
					for _, s := range testData {
						key := makeKey(s)
						expectMissing(t, key, 0)(m.Load(key))
					}
				}(i)
			}
			wg.Wait()
		})
		t.Run("ConcurrentSharedKeys", func(t *testing.T) {
			m := newMap()

			// Load up the map.
			for i, s := range testData {
				expectMissing(t, s, 0)(m.Load(s))
				expectStored(t, s, i)(m.LoadOrStore(s, i))
			}
			gmp := runtime.GOMAXPROCS(-1)
			var wg sync.WaitGroup
			for i := range gmp {
				wg.Add(1)
				go func(id int) {
					defer wg.Done()

					for _, s := range testData {
						m.LoadAndDelete(s)
						expectMissing(t, s, 0)(m.Load(s))
					}
					for _, s := range testData {
						expectMissing(t, s, 0)(m.Load(s))
					}
				}(i)
			}
			wg.Wait()
		})
	})
}

func testAll[K, V comparable](t *testing.T, m *isync.HashTrieMap[K, V], testData map[K]V, yield func(K, V) bool) {
	for k, v := range testData {
		expectStored(t, k, v)(m.LoadOrStore(k, v))
	}
	visited := make(map[K]int)
	m.All()(func(key K, got V) bool {
		want, ok := testData[key]
		if !ok {
			t.Errorf("unexpected key %v in map", key)
			return false
		}
		if got != want {
			t.Errorf("expected key %v to have value %v, got %v", key, want, got)
			return false
		}
		visited[key]++
		return yield(key, got)
	})
	for key, n := range visited {
		if n > 1 {
			t.Errorf("visited key %v more than once", key)
		}
	}
}

func expectPresent[K, V comparable](t *testing.T, key K, want V) func(got V, ok bool) {
	t.Helper()
	return func(got V, ok bool) {
		t.Helper()

		if !ok {
			t.Errorf("expected key %v to be present in map", key)
		}
		if ok && got != want {
			t.Errorf("expected key %v to have value %v, got %v", key, want, got)
		}
	}
}

func expectMissing[K, V comparable](t *testing.T, key K, want V) func(got V, ok bool) {
	t.Helper()
	if want != *new(V) {
		// This is awkward, but the want argument is necessary to smooth over type inference.
		// Just make sure the want argument always looks the same.
		panic("expectMissing must always have a zero value variable")
	}
	return func(got V, ok bool) {
		t.Helper()

		if ok {
			t.Errorf("expected key %v to be missing from map, got value %v", key, got)
		}
		if !ok && got != want {
			t.Errorf("expected missing key %v to be paired with the zero value; got %v", key, got)
		}
	}
}

func expectLoaded[K, V comparable](t *testing.T, key K, want V) func(got V, loaded bool) {
	t.Helper()
	return func(got V, loaded bool) {
		t.Helper()

		if !loaded {
			t.Errorf("expected key %v to have been loaded, not stored", key)
		}
		if got != want {
			t.Errorf("expected key %v to have value %v, got %v", key, want, got)
		}
	}
}

func expectStored[K, V comparable](t *testing.T, key K, want V) func(got V, loaded bool) {
	t.Helper()
	return func(got V, loaded bool) {
		t.Helper()

		if loaded {
			t.Errorf("expected inserted key %v to have been stored, not loaded", key)
		}
		if got != want {
			t.Errorf("expected inserted key %v to have value %v, got %v", key, want, got)
		}
	}
}

func expectDeleted[K, V comparable](t *testing.T, key K, old V) func(deleted bool) {
	t.Helper()
	return func(deleted bool) {
		t.Helper()

		if !deleted {
			t.Errorf("expected key %v with value %v to be in map and deleted", key, old)
		}
	}
}

func expectNotDeleted[K, V comparable](t *testing.T, key K, old V) func(deleted bool) {
	t.Helper()
	return func(deleted bool) {
		t.Helper()

		if deleted {
			t.Errorf("expected key %v with value %v to not be in map and thus not deleted", key, old)
		}
	}
}

func expectSwapped[K, V comparable](t *testing.T, key K, old, new V) func(swapped bool) {
	t.Helper()
	return func(swapped bool) {
		t.Helper()

		if !swapped {
			t.Errorf("expected key %v with value %v to be in map and swapped for %v", key, old, new)
		}
	}
}

func expectNotSwapped[K, V comparable](t *testing.T, key K, old, new V) func(swapped bool) {
	t.Helper()
	return func(swapped bool) {
		t.Helper()

		if swapped {
			t.Errorf("expected key %v with value %v to not be in map or not swapped for %v", key, old, new)
		}
	}
}

func expectLoadedFromSwap[K, V comparable](t *testing.T, key K, want, new V) func(got V, loaded bool) {
	t.Helper()
	return func(got V, loaded bool) {
		t.Helper()

		if !loaded {
			t.Errorf("expected key %v to be in map and for %v to have been swapped for %v", key, want, new)
		} else if want != got {
			t.Errorf("key %v had its value %v swapped for %v, but expected it to have value %v", key, got, new, want)
		}
	}
}

func expectNotLoadedFromSwap[K, V comparable](t *testing.T, key K, new V) func(old V, loaded bool) {
	t.Helper()
	return func(old V, loaded bool) {
		t.Helper()

		if loaded {
			t.Errorf("expected key %v to not be in map, but found value %v for it", key, old)
		}
	}
}

func expectLoadedFromDelete[K, V comparable](t *testing.T, key K, want V) func(got V, loaded bool) {
	t.Helper()
	return func(got V, loaded bool) {
		t.Helper()

		if !loaded {
			t.Errorf("expected key %v to be in map to be deleted", key)
		} else if want != got {
			t.Errorf("key %v was deleted with value %v, but expected it to have value %v", key, got, want)
		}
	}
}

func expectNotLoadedFromDelete[K, V comparable](t *testing.T, key K, _ V) func(old V, loaded bool) {
	t.Helper()
	return func(old V, loaded bool) {
		t.Helper()

		if loaded {
			t.Errorf("expected key %v to not be in map, but found value %v for it", key, old)
		}
	}
}

func testDataMap(data []string) map[string]int {
	m := make(map[string]int)
	for i, s := range data {
		m[s] = i
	}
	return m
}

var (
	testDataSmall [8]string
	testData      [128]string
	testDataLarge [128 << 10]string
)

func init() {
	for i := range testDataSmall {
		testDataSmall[i] = fmt.Sprintf("%b", i)
	}
	for i := range testData {
		testData[i] = fmt.Sprintf("%b", i)
	}
	for i := range testDataLarge {
		testDataLarge[i] = fmt.Sprintf("%b", i)
	}
}
```