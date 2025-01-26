Response:
The user wants to understand the functionality of the provided Go code snippet from `go/src/sync/map_bench_test.go`.

Here's a breakdown of the thought process:

1. **Identify the core purpose:** The filename `map_bench_test.go` strongly suggests this code is for benchmarking different map implementations in Go.

2. **Analyze the `benchMap` function:** This function seems to be the central driver for the benchmarks. It iterates through different `mapInterface` implementations (`DeepCopyMap`, `RWMutexMap`, `isync.HashTrieMap`, `sync.Map`). It uses `testing.B` for benchmarking and `b.RunParallel` to execute tests concurrently. The `bench` struct likely defines the setup and per-goroutine logic for each specific benchmark.

3. **Understand the `bench` struct:** It has `setup` and `perG` functions. `setup` is for initializing the map before the benchmark starts, and `perG` contains the actual operations being benchmarked within each goroutine.

4. **Examine individual benchmark functions:** Functions like `BenchmarkMapLoadMostlyHits`, `BenchmarkMapLoadMostlyMisses`, etc., clearly represent different benchmark scenarios for map operations like `Load`, `LoadOrStore`, `LoadAndDelete`, `Range`, `Delete`, `Swap`, `CompareAndSwap`, and `CompareAndDelete`. The names themselves are quite descriptive.

5. **Infer the functionality being tested:** Based on the benchmark function names and the map operations used within their `perG` functions, it's clear that this code benchmarks the performance of various map operations under different conditions (e.g., mostly hits, mostly misses, balanced, collisions).

6. **Identify the Go feature being implemented/benchmarked:** The presence of `sync.Map` strongly suggests that this code is related to the `sync.Map` type in Go's standard library, which is a concurrent-safe map. The other map implementations (`DeepCopyMap`, `RWMutexMap`, `isync.HashTrieMap`) are likely used for comparison purposes.

7. **Provide a code example:** To illustrate the functionality, a simple example using `sync.Map` to demonstrate `Load`, `Store`, and `LoadOrStore` would be appropriate.

8. **Address input/output and command-line arguments:** Benchmarks in Go are typically run using the `go test` command. The `-bench` flag is used to specify which benchmarks to run. Explain how to use this flag and interpret the output.

9. **Identify potential pitfalls:**  Concurrency-related issues are common with maps. Emphasize the importance of using concurrent-safe maps like `sync.Map` when multiple goroutines access the map. Show an example of a race condition when using a regular `map` without proper synchronization.

10. **Structure the answer:** Organize the information logically with clear headings and code examples. Explain the purpose of each part of the code and the overall functionality. Use clear and concise language in Chinese as requested.
这段代码是 Go 语言标准库中 `sync` 包的一部分，位于 `go/src/sync/map_bench_test.go` 文件。它的主要功能是**对不同的并发安全 Map 实现进行性能基准测试 (benchmarking)**。

更具体地说，它测试了以下几种 Map 实现在不同操作场景下的性能：

* **`sync.Map`**: Go 语言标准库提供的并发安全的 Map。
* **`DeepCopyMap`**:  一个自定义的 Map 实现，可能通过深拷贝来实现并发安全（代码中未给出其具体实现，但从名称可以推断）。
* **`RWMutexMap`**:  一个使用读写锁 (`sync.RWMutex`) 保护的普通 `map` 实现。
* **`isync.HashTrieMap[any, any]`**: 一个内部的基于 HashTrie 的并发 Map 实现（`internal/sync` 包通常包含一些内部使用的同步原语）。

**代码功能列表:**

1. **定义 benchmark 结构体 (`bench`)**:  用于组织和配置基准测试，包含 `setup` 函数（在测试开始前执行的初始化操作）和 `perG` 函数（每个 Goroutine 执行的测试逻辑）。
2. **定义 `benchMap` 函数**:  这是基准测试的核心驱动函数。它接收一个 `bench` 结构体作为参数，并针对不同的 `mapInterface` 实现运行该基准测试。
3. **定义多个以 `BenchmarkMap` 开头的函数**: 这些函数分别针对不同的 Map 操作场景进行基准测试，例如：
    * **`BenchmarkMapLoadMostlyHits`**:  大部分情况下都能命中 key 的 `Load` 操作性能。
    * **`BenchmarkMapLoadMostlyMisses`**: 大部分情况下都无法命中 key 的 `Load` 操作性能。
    * **`BenchmarkMapLoadOrStoreBalanced`**:  `LoadOrStore` 操作中，命中和未命中的情况比较均衡。
    * **`BenchmarkMapLoadOrStoreUnique`**:  不断插入新的 key-value 对的 `LoadOrStore` 操作性能。
    * **`BenchmarkMapLoadOrStoreCollision`**:  对同一个 key 进行多次 `LoadOrStore` 操作的性能。
    * **`BenchmarkMapLoadAndDeleteBalanced`**: `LoadAndDelete` 操作中，命中和未命中的情况比较均衡。
    * **`BenchmarkMapLoadAndDeleteUnique`**:  不断删除新的 key-value 对的 `LoadAndDelete` 操作性能。
    * **`BenchmarkMapLoadAndDeleteCollision`**: 对同一个 key 进行多次 `LoadAndDelete` 操作的性能。
    * **`BenchmarkMapRange`**:  遍历整个 Map 的 `Range` 操作性能。
    * **`BenchmarkMapAdversarialAlloc`**:  在 Map 被提升为干净状态后立即存储新值的性能，模拟高并发写入的场景。
    * **`BenchmarkMapAdversarialDelete`**:  周期性删除一个 key 并添加一个新 key 的性能，模拟高并发删除和写入的场景。
    * **`BenchmarkMapDeleteCollision`**: 对同一个 key 进行多次 `Delete` 操作的性能。
    * **`BenchmarkMapSwapCollision`**: 对同一个 key 进行多次 `Swap` 操作的性能。
    * **`BenchmarkMapSwapMostlyHits`**:  大部分情况下都能命中 key 的 `Swap` 操作性能。
    * **`BenchmarkMapSwapMostlyMisses`**: 大部分情况下都无法命中 key 的 `Swap` 操作性能。
    * **`BenchmarkMapCompareAndSwapCollision`**: 对同一个 key 进行多次 `CompareAndSwap` 操作的性能。
    * **`BenchmarkMapCompareAndSwapNoExistingKey`**:  尝试对不存在的 key 进行 `CompareAndSwap` 操作的性能。
    * **`BenchmarkMapCompareAndSwapValueNotEqual`**:  `CompareAndSwap` 操作中，旧值与当前值不相等的情况。
    * **`BenchmarkMapCompareAndSwapMostlyHits`**:  大部分情况下都能命中 key 的 `CompareAndSwap` 操作性能。
    * **`BenchmarkMapCompareAndSwapMostlyMisses`**: 大部分情况下都无法命中 key 的 `CompareAndSwap` 操作性能。
    * **`BenchmarkMapCompareAndDeleteCollision`**: 对同一个 key 进行多次 `CompareAndDelete` 操作的性能。
    * **`BenchmarkMapCompareAndDeleteMostlyHits`**:  大部分情况下都能命中 key 的 `CompareAndDelete` 操作性能。
    * **`BenchmarkMapCompareAndDeleteMostlyMisses`**: 大部分情况下都无法命中 key 的 `CompareAndDelete` 操作性能。
    * **`BenchmarkMapClear`**:  清空 Map 的 `Clear` 操作性能。

**功能推理：并发安全 Map 的实现和性能对比**

这段代码的核心目的是为了测试和比较不同并发安全 Map 实现的性能。Go 语言标准库提供的 `sync.Map` 旨在提供一种高效的并发安全的 Map 实现，尤其是在读多写少的场景下。  通过与其他可能的实现方式（如基于读写锁的 `RWMutexMap` 和基于 HashTrie 的 `isync.HashTrieMap`）进行对比，可以更好地理解 `sync.Map` 的性能特点。 `DeepCopyMap` 作为一个对比项，可能代表了另一种简单的并发安全策略，但预期性能可能较低。

**Go 代码举例说明 `sync.Map` 的功能:**

```go
package main

import (
	"fmt"
	"sync"
)

func main() {
	var m sync.Map

	// 存储键值对
	m.Store("apple", 1)
	m.Store("banana", 2)

	// 加载键对应的值
	value, ok := m.Load("apple")
	if ok {
		fmt.Println("Value of apple:", value) // 输出: Value of apple: 1
	}

	// 尝试加载或存储，如果键不存在则存储
	actual, loaded := m.LoadOrStore("orange", 3)
	fmt.Println("LoadOrStore orange:", actual, loaded) // 输出: LoadOrStore orange: 3 false

	actual, loaded = m.LoadOrStore("apple", 4)
	fmt.Println("LoadOrStore apple:", actual, loaded)  // 输出: LoadOrStore apple: 1 true

	// 删除键值对
	m.Delete("banana")

	// 遍历 Map
	m.Range(func(key, value interface{}) bool {
		fmt.Printf("Key: %v, Value: %v\n", key, value)
		return true // 返回 false 可以停止遍历
	})
	// 可能输出:
	// Key: apple, Value: 1
	// Key: orange, Value: 3

	//  原子操作：如果键存在且值为 1，则替换为 5
	m.CompareAndSwap("apple", 1, 5)
	val, _ := m.Load("apple")
	fmt.Println("After CompareAndSwap apple:", val) // 输出: After CompareAndSwap apple: 5

	// 原子操作：如果键存在且值为 5，则删除
	m.CompareAndDelete("apple", 5)
	_, present := m.Load("apple")
	fmt.Println("Is apple present after CompareAndDelete:", present) // 输出: Is apple present after CompareAndDelete: false

	// 原子操作：交换键的值
	m.Store("grape", 6)
	m.Swap("grape", 7)
	val, _ = m.Load("grape")
	fmt.Println("After Swap grape:", val) // 输出: After Swap grape: 7

	// 清空 Map
	m.Clear()
	count := 0
	m.Range(func(_ ,_ interface{}) bool {
		count++
		return true
	})
	fmt.Println("Map size after Clear:", count) // 输出: Map size after Clear: 0
}
```

**假设的输入与输出（以 `BenchmarkMapLoadMostlyHits` 为例）:**

假设我们运行以下命令来执行 `BenchmarkMapLoadMostlyHits` 这个基准测试：

```bash
go test -bench=BenchmarkMapLoadMostlyHits ./sync
```

输出可能类似于：

```
goos: linux
goarch: amd64
pkg: sync
BenchmarkMapLoadMostlyHits/sync.DeepCopyMap-8         58715             20469 ns/op            0 B/op          0 allocs/op
BenchmarkMapLoadMostlyHits/sync.RWMutexMap-8          73804             15773 ns/op            0 B/op          0 allocs/op
BenchmarkMapLoadMostlyHits/sync.isync.HashTrieMap[any,any]-8         134743              8891 ns/op            0 B/op          0 allocs/op
BenchmarkMapLoadMostlyHits/sync.Map-8                169644              7080 ns/op            0 B/op          0 allocs/op
PASS
ok      sync    4.996s
```

**解释输出:**

* `BenchmarkMapLoadMostlyHits/sync.DeepCopyMap-8`: 表示针对 `DeepCopyMap` 运行的 `BenchmarkMapLoadMostlyHits` 基准测试，`-8` 表示 `GOMAXPROCS` 的值。
* `58715`: 表示在基准测试期间执行的操作次数。
* `20469 ns/op`: 表示每次操作的平均耗时为 20469 纳秒。
* `0 B/op`: 表示每次操作的内存分配量为 0 字节。
* `0 allocs/op`: 表示每次操作的内存分配次数为 0 次。

这个输出展示了在大部分情况下命中 key 的 `Load` 操作场景下，`sync.Map` 的性能通常优于 `DeepCopyMap` 和 `RWMutexMap`。 `isync.HashTrieMap` 在这个场景下表现也很好。

**命令行参数的具体处理:**

这段代码本身并没有直接处理命令行参数。它的运行依赖于 Go 的 `testing` 包提供的基准测试框架。要运行这些基准测试，你需要使用 `go test` 命令，并使用 `-bench` 标志来指定要运行的基准测试函数。

* **`-bench <regexp>`**:  指定要运行的基准测试函数，可以使用正则表达式匹配。例如：
    * `go test -bench=. ./sync`  会运行当前目录 `sync` 包下的所有基准测试函数。
    * `go test -bench=BenchmarkMapLoad ./sync` 会运行函数名包含 "BenchmarkMapLoad" 的基准测试。
    * `go test -bench=BenchmarkMapLoadMostlyHits ./sync` 只运行 `BenchmarkMapLoadMostlyHits` 这个基准测试。
* **`-benchtime <duration>`**: 指定每个基准测试运行的持续时间，默认为 1 秒。例如：`go test -bench=BenchmarkMapLoadMostlyHits -benchtime=5s ./sync` 会让每个基准测试运行 5 秒。
* **`-benchmem`**:  输出内存分配的统计信息（如 `B/op` 和 `allocs/op`）。
* **`-cpuprofile <file>`**: 将 CPU 分析信息写入指定文件。
* **`-memprofile <file>`**: 将内存分析信息写入指定文件。

**使用者易犯错的点:**

在使用 `sync.Map` 时，一个常见的错误是在不需要并发安全性的情况下仍然使用它。`sync.Map` 为了保证并发安全，引入了一些额外的开销，在单线程或者已经有其他同步机制保护的情况下，使用普通的 `map` 性能会更好。

**举例说明：**

假设你在一个单线程程序中频繁地使用 Map：

```go
package main

import "fmt"

func main() {
	// 不需要并发安全，使用普通的 map 即可
	m := make(map[string]int)
	for i := 0; i < 1000000; i++ {
		m[fmt.Sprintf("key-%d", i)] = i
		_ = m[fmt.Sprintf("key-%d", i/2)]
	}
	fmt.Println("Done")
}
```

如果错误地使用了 `sync.Map`：

```go
package main

import (
	"fmt"
	"sync"
)

func main() {
	var m sync.Map // 即使是单线程，仍然使用了 sync.Map
	for i := 0; i < 1000000; i++ {
		m.Store(fmt.Sprintf("key-%d", i), i)
		m.Load(fmt.Sprintf("key-%d", i/2))
	}
	fmt.Println("Done")
}
```

在单线程环境下，使用 `sync.Map` 会因为其内部的同步机制而产生不必要的性能损耗。  你应该根据实际的并发需求选择合适的 Map 类型。只有当多个 Goroutine 同时访问和修改 Map 时，才应该考虑使用 `sync.Map` 或其他并发安全的 Map 实现。

Prompt: 
```
这是路径为go/src/sync/map_bench_test.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。

"""
// Copyright 2016 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package sync_test

import (
	"fmt"
	isync "internal/sync"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
)

type bench struct {
	setup func(*testing.B, mapInterface)
	perG  func(b *testing.B, pb *testing.PB, i int, m mapInterface)
}

func benchMap(b *testing.B, bench bench) {
	for _, m := range [...]mapInterface{&DeepCopyMap{}, &RWMutexMap{}, &isync.HashTrieMap[any, any]{}, &sync.Map{}} {
		b.Run(fmt.Sprintf("%T", m), func(b *testing.B) {
			m = reflect.New(reflect.TypeOf(m).Elem()).Interface().(mapInterface)
			if bench.setup != nil {
				bench.setup(b, m)
			}

			b.ReportAllocs()
			b.ResetTimer()

			var i int64
			b.RunParallel(func(pb *testing.PB) {
				id := int(atomic.AddInt64(&i, 1) - 1)
				bench.perG(b, pb, id*b.N, m)
			})
		})
	}
}

func BenchmarkMapLoadMostlyHits(b *testing.B) {
	const hits, misses = 1023, 1

	benchMap(b, bench{
		setup: func(_ *testing.B, m mapInterface) {
			for i := 0; i < hits; i++ {
				m.LoadOrStore(i, i)
			}
			// Prime the map to get it into a steady state.
			for i := 0; i < hits*2; i++ {
				m.Load(i % hits)
			}
		},

		perG: func(b *testing.B, pb *testing.PB, i int, m mapInterface) {
			for ; pb.Next(); i++ {
				m.Load(i % (hits + misses))
			}
		},
	})
}

func BenchmarkMapLoadMostlyMisses(b *testing.B) {
	const hits, misses = 1, 1023

	benchMap(b, bench{
		setup: func(_ *testing.B, m mapInterface) {
			for i := 0; i < hits; i++ {
				m.LoadOrStore(i, i)
			}
			// Prime the map to get it into a steady state.
			for i := 0; i < hits*2; i++ {
				m.Load(i % hits)
			}
		},

		perG: func(b *testing.B, pb *testing.PB, i int, m mapInterface) {
			for ; pb.Next(); i++ {
				m.Load(i % (hits + misses))
			}
		},
	})
}

func BenchmarkMapLoadOrStoreBalanced(b *testing.B) {
	const hits, misses = 128, 128

	benchMap(b, bench{
		setup: func(b *testing.B, m mapInterface) {
			if _, ok := m.(*DeepCopyMap); ok {
				b.Skip("DeepCopyMap has quadratic running time.")
			}
			for i := 0; i < hits; i++ {
				m.LoadOrStore(i, i)
			}
			// Prime the map to get it into a steady state.
			for i := 0; i < hits*2; i++ {
				m.Load(i % hits)
			}
		},

		perG: func(b *testing.B, pb *testing.PB, i int, m mapInterface) {
			for ; pb.Next(); i++ {
				j := i % (hits + misses)
				if j < hits {
					if _, ok := m.LoadOrStore(j, i); !ok {
						b.Fatalf("unexpected miss for %v", j)
					}
				} else {
					if v, loaded := m.LoadOrStore(i, i); loaded {
						b.Fatalf("failed to store %v: existing value %v", i, v)
					}
				}
			}
		},
	})
}

func BenchmarkMapLoadOrStoreUnique(b *testing.B) {
	benchMap(b, bench{
		setup: func(b *testing.B, m mapInterface) {
			if _, ok := m.(*DeepCopyMap); ok {
				b.Skip("DeepCopyMap has quadratic running time.")
			}
		},

		perG: func(b *testing.B, pb *testing.PB, i int, m mapInterface) {
			for ; pb.Next(); i++ {
				m.LoadOrStore(i, i)
			}
		},
	})
}

func BenchmarkMapLoadOrStoreCollision(b *testing.B) {
	benchMap(b, bench{
		setup: func(_ *testing.B, m mapInterface) {
			m.LoadOrStore(0, 0)
		},

		perG: func(b *testing.B, pb *testing.PB, i int, m mapInterface) {
			for ; pb.Next(); i++ {
				m.LoadOrStore(0, 0)
			}
		},
	})
}

func BenchmarkMapLoadAndDeleteBalanced(b *testing.B) {
	const hits, misses = 128, 128

	benchMap(b, bench{
		setup: func(b *testing.B, m mapInterface) {
			if _, ok := m.(*DeepCopyMap); ok {
				b.Skip("DeepCopyMap has quadratic running time.")
			}
			for i := 0; i < hits; i++ {
				m.LoadOrStore(i, i)
			}
			// Prime the map to get it into a steady state.
			for i := 0; i < hits*2; i++ {
				m.Load(i % hits)
			}
		},

		perG: func(b *testing.B, pb *testing.PB, i int, m mapInterface) {
			for ; pb.Next(); i++ {
				j := i % (hits + misses)
				if j < hits {
					m.LoadAndDelete(j)
				} else {
					m.LoadAndDelete(i)
				}
			}
		},
	})
}

func BenchmarkMapLoadAndDeleteUnique(b *testing.B) {
	benchMap(b, bench{
		setup: func(b *testing.B, m mapInterface) {
			if _, ok := m.(*DeepCopyMap); ok {
				b.Skip("DeepCopyMap has quadratic running time.")
			}
		},

		perG: func(b *testing.B, pb *testing.PB, i int, m mapInterface) {
			for ; pb.Next(); i++ {
				m.LoadAndDelete(i)
			}
		},
	})
}

func BenchmarkMapLoadAndDeleteCollision(b *testing.B) {
	benchMap(b, bench{
		setup: func(_ *testing.B, m mapInterface) {
			m.LoadOrStore(0, 0)
		},

		perG: func(b *testing.B, pb *testing.PB, i int, m mapInterface) {
			for ; pb.Next(); i++ {
				if _, loaded := m.LoadAndDelete(0); loaded {
					m.Store(0, 0)
				}
			}
		},
	})
}

func BenchmarkMapRange(b *testing.B) {
	const mapSize = 1 << 10

	benchMap(b, bench{
		setup: func(_ *testing.B, m mapInterface) {
			for i := 0; i < mapSize; i++ {
				m.Store(i, i)
			}
		},

		perG: func(b *testing.B, pb *testing.PB, i int, m mapInterface) {
			for ; pb.Next(); i++ {
				m.Range(func(_, _ any) bool { return true })
			}
		},
	})
}

// BenchmarkMapAdversarialAlloc tests performance when we store a new value
// immediately whenever the map is promoted to clean and otherwise load a
// unique, missing key.
//
// This forces the Load calls to always acquire the map's mutex.
func BenchmarkMapAdversarialAlloc(b *testing.B) {
	benchMap(b, bench{
		perG: func(b *testing.B, pb *testing.PB, i int, m mapInterface) {
			var stores, loadsSinceStore int64
			for ; pb.Next(); i++ {
				m.Load(i)
				if loadsSinceStore++; loadsSinceStore > stores {
					m.LoadOrStore(i, stores)
					loadsSinceStore = 0
					stores++
				}
			}
		},
	})
}

// BenchmarkMapAdversarialDelete tests performance when we periodically delete
// one key and add a different one in a large map.
//
// This forces the Load calls to always acquire the map's mutex and periodically
// makes a full copy of the map despite changing only one entry.
func BenchmarkMapAdversarialDelete(b *testing.B) {
	const mapSize = 1 << 10

	benchMap(b, bench{
		setup: func(_ *testing.B, m mapInterface) {
			for i := 0; i < mapSize; i++ {
				m.Store(i, i)
			}
		},

		perG: func(b *testing.B, pb *testing.PB, i int, m mapInterface) {
			for ; pb.Next(); i++ {
				m.Load(i)

				if i%mapSize == 0 {
					m.Range(func(k, _ any) bool {
						m.Delete(k)
						return false
					})
					m.Store(i, i)
				}
			}
		},
	})
}

func BenchmarkMapDeleteCollision(b *testing.B) {
	benchMap(b, bench{
		setup: func(_ *testing.B, m mapInterface) {
			m.LoadOrStore(0, 0)
		},

		perG: func(b *testing.B, pb *testing.PB, i int, m mapInterface) {
			for ; pb.Next(); i++ {
				m.Delete(0)
			}
		},
	})
}

func BenchmarkMapSwapCollision(b *testing.B) {
	benchMap(b, bench{
		setup: func(_ *testing.B, m mapInterface) {
			m.LoadOrStore(0, 0)
		},

		perG: func(b *testing.B, pb *testing.PB, i int, m mapInterface) {
			for ; pb.Next(); i++ {
				m.Swap(0, 0)
			}
		},
	})
}

func BenchmarkMapSwapMostlyHits(b *testing.B) {
	const hits, misses = 1023, 1

	benchMap(b, bench{
		setup: func(_ *testing.B, m mapInterface) {
			for i := 0; i < hits; i++ {
				m.LoadOrStore(i, i)
			}
			// Prime the map to get it into a steady state.
			for i := 0; i < hits*2; i++ {
				m.Load(i % hits)
			}
		},

		perG: func(b *testing.B, pb *testing.PB, i int, m mapInterface) {
			for ; pb.Next(); i++ {
				if i%(hits+misses) < hits {
					v := i % (hits + misses)
					m.Swap(v, v)
				} else {
					m.Swap(i, i)
					m.Delete(i)
				}
			}
		},
	})
}

func BenchmarkMapSwapMostlyMisses(b *testing.B) {
	const hits, misses = 1, 1023

	benchMap(b, bench{
		setup: func(_ *testing.B, m mapInterface) {
			for i := 0; i < hits; i++ {
				m.LoadOrStore(i, i)
			}
			// Prime the map to get it into a steady state.
			for i := 0; i < hits*2; i++ {
				m.Load(i % hits)
			}
		},

		perG: func(b *testing.B, pb *testing.PB, i int, m mapInterface) {
			for ; pb.Next(); i++ {
				if i%(hits+misses) < hits {
					v := i % (hits + misses)
					m.Swap(v, v)
				} else {
					m.Swap(i, i)
					m.Delete(i)
				}
			}
		},
	})
}

func BenchmarkMapCompareAndSwapCollision(b *testing.B) {
	benchMap(b, bench{
		setup: func(_ *testing.B, m mapInterface) {
			m.LoadOrStore(0, 0)
		},

		perG: func(b *testing.B, pb *testing.PB, i int, m mapInterface) {
			for pb.Next() {
				if m.CompareAndSwap(0, 0, 42) {
					m.CompareAndSwap(0, 42, 0)
				}
			}
		},
	})
}

func BenchmarkMapCompareAndSwapNoExistingKey(b *testing.B) {
	benchMap(b, bench{
		perG: func(b *testing.B, pb *testing.PB, i int, m mapInterface) {
			for ; pb.Next(); i++ {
				if m.CompareAndSwap(i, 0, 0) {
					m.Delete(i)
				}
			}
		},
	})
}

func BenchmarkMapCompareAndSwapValueNotEqual(b *testing.B) {
	benchMap(b, bench{
		setup: func(_ *testing.B, m mapInterface) {
			m.Store(0, 0)
		},

		perG: func(b *testing.B, pb *testing.PB, i int, m mapInterface) {
			for ; pb.Next(); i++ {
				m.CompareAndSwap(0, 1, 2)
			}
		},
	})
}

func BenchmarkMapCompareAndSwapMostlyHits(b *testing.B) {
	const hits, misses = 1023, 1

	benchMap(b, bench{
		setup: func(b *testing.B, m mapInterface) {
			if _, ok := m.(*DeepCopyMap); ok {
				b.Skip("DeepCopyMap has quadratic running time.")
			}

			for i := 0; i < hits; i++ {
				m.LoadOrStore(i, i)
			}
			// Prime the map to get it into a steady state.
			for i := 0; i < hits*2; i++ {
				m.Load(i % hits)
			}
		},

		perG: func(b *testing.B, pb *testing.PB, i int, m mapInterface) {
			for ; pb.Next(); i++ {
				v := i
				if i%(hits+misses) < hits {
					v = i % (hits + misses)
				}
				m.CompareAndSwap(v, v, v)
			}
		},
	})
}

func BenchmarkMapCompareAndSwapMostlyMisses(b *testing.B) {
	const hits, misses = 1, 1023

	benchMap(b, bench{
		setup: func(_ *testing.B, m mapInterface) {
			for i := 0; i < hits; i++ {
				m.LoadOrStore(i, i)
			}
			// Prime the map to get it into a steady state.
			for i := 0; i < hits*2; i++ {
				m.Load(i % hits)
			}
		},

		perG: func(b *testing.B, pb *testing.PB, i int, m mapInterface) {
			for ; pb.Next(); i++ {
				v := i
				if i%(hits+misses) < hits {
					v = i % (hits + misses)
				}
				m.CompareAndSwap(v, v, v)
			}
		},
	})
}

func BenchmarkMapCompareAndDeleteCollision(b *testing.B) {
	benchMap(b, bench{
		setup: func(_ *testing.B, m mapInterface) {
			m.LoadOrStore(0, 0)
		},

		perG: func(b *testing.B, pb *testing.PB, i int, m mapInterface) {
			for ; pb.Next(); i++ {
				if m.CompareAndDelete(0, 0) {
					m.Store(0, 0)
				}
			}
		},
	})
}

func BenchmarkMapCompareAndDeleteMostlyHits(b *testing.B) {
	const hits, misses = 1023, 1

	benchMap(b, bench{
		setup: func(b *testing.B, m mapInterface) {
			if _, ok := m.(*DeepCopyMap); ok {
				b.Skip("DeepCopyMap has quadratic running time.")
			}

			for i := 0; i < hits; i++ {
				m.LoadOrStore(i, i)
			}
			// Prime the map to get it into a steady state.
			for i := 0; i < hits*2; i++ {
				m.Load(i % hits)
			}
		},

		perG: func(b *testing.B, pb *testing.PB, i int, m mapInterface) {
			for ; pb.Next(); i++ {
				v := i
				if i%(hits+misses) < hits {
					v = i % (hits + misses)
				}
				if m.CompareAndDelete(v, v) {
					m.Store(v, v)
				}
			}
		},
	})
}

func BenchmarkMapCompareAndDeleteMostlyMisses(b *testing.B) {
	const hits, misses = 1, 1023

	benchMap(b, bench{
		setup: func(_ *testing.B, m mapInterface) {
			for i := 0; i < hits; i++ {
				m.LoadOrStore(i, i)
			}
			// Prime the map to get it into a steady state.
			for i := 0; i < hits*2; i++ {
				m.Load(i % hits)
			}
		},

		perG: func(b *testing.B, pb *testing.PB, i int, m mapInterface) {
			for ; pb.Next(); i++ {
				v := i
				if i%(hits+misses) < hits {
					v = i % (hits + misses)
				}
				if m.CompareAndDelete(v, v) {
					m.Store(v, v)
				}
			}
		},
	})
}

func BenchmarkMapClear(b *testing.B) {
	benchMap(b, bench{
		perG: func(b *testing.B, pb *testing.PB, i int, m mapInterface) {
			for ; pb.Next(); i++ {
				k, v := i%256, i%256
				m.Clear()
				m.Store(k, v)
			}
		},
	})
}

"""



```