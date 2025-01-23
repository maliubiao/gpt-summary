Response:
Let's break down the thought process for analyzing this Go benchmark code.

**1. Understanding the Goal:**

The primary goal of this code is to benchmark the performance of Go maps under various conditions. This means it's testing different aspects of map operations like creation, access, iteration, assignment, deletion, and clearing. The file name `map_benchmark_test.go` strongly suggests this.

**2. Initial Code Scan - Identifying Key Components:**

I'd start by quickly scanning the code to identify major sections and patterns:

* **Imports:**  Standard testing packages (`testing`), plus some utility and low-level ones (`flag`, `fmt`, `math/rand`, `runtime`, `slices`, `strconv`, `strings`, `unsafe`, `encoding/binary`). The `unsafe` package hints at memory-level manipulation or size considerations, which is common in benchmarking.
* **Global Variables:** `mapbench` is a flag, indicating the possibility of running a more extensive benchmark suite. `size` is a constant likely used for default map sizes in some benchmarks.
* **Benchmark Functions:**  The code is full of functions starting with `Benchmark...`. This is the standard naming convention for Go benchmark tests. I'd notice different patterns in these names (e.g., `BenchmarkHashStringSpeed`, `BenchmarkMegMap`, `BenchmarkMapIter`, `BenchmarkMapAssignExists`). This suggests different categories of map operations are being tested.
* **Helper Functions:** There are functions like `cyclicPermutation`, `benchmarkMapStringKeysEight`, `benchmarkRepeatedLookup`, `benchSizes`, `smallBenchSizes`, `genIntValues`, `fillMap`, `iterCount`, `checkAllocSize`, etc. These are clearly designed to set up specific test scenarios and reduce code duplication.
* **Type Definitions:** `chunk`, `ComplexAlgKey`, `smallType`, `mediumType`, `bigType`, `mapBenchmarkKeyType`, `mapBenchmarkElemType`. These are used to create maps with different key and value types, allowing for performance comparisons based on data structure.
* **`sink` and `hugeSink`:** Global variables used to store results within benchmarks, preventing the compiler from optimizing away the operations being timed.

**3. Analyzing Individual Benchmark Functions (Examples):**

I'd pick a few benchmark functions as examples to understand their purpose:

* **`BenchmarkHashStringSpeed`:**  This clearly tests the speed of looking up string keys in a map. The setup creates a map of strings and then repeatedly accesses them.
* **`BenchmarkMegMap`:** The name "Meg" suggests testing with large strings. This benchmark checks the lookup speed for very long string keys.
* **`BenchmarkMapIter`:**  The name "Iter" strongly suggests benchmarking map iteration. The helper function `benchmarkMapIter` with generics reinforces this.
* **`BenchmarkMapAssignExists`:** This benchmark tests the performance of assigning values to existing keys in a map.

**4. Identifying Common Patterns and Themes:**

As I analyze more benchmark functions, I'd notice recurring patterns:

* **Varying Key and Value Types:** Many benchmarks use different key types (string, int, byte arrays, structs, pointers) and value types to see how they affect performance.
* **Varying Map Sizes:** Benchmarks like `BenchmarkMapFirst`, `BenchmarkMapMid`, `BenchmarkMapLast`, and the functions using `benchSizes` systematically test performance with different map sizes.
* **Testing Different Operations:**  Dedicated benchmarks exist for hash speed, lookup speed (hit and miss), iteration, assignment (new and existing keys), deletion, and clearing.
* **Use of Helper Functions for Setup:**  Functions like `fillMap` and the `gen...Values` functions are used to efficiently create and populate maps with specific data.

**5. Inferring the Overall Functionality:**

Based on the analysis of individual benchmarks and recurring patterns, I'd conclude that this code is designed to:

* **Measure the performance of various Go map operations.**
* **Compare the performance of maps with different key and value types.**
* **Evaluate the impact of map size on performance.**
* **Benchmark different scenarios, including hash calculation, lookups (hits and misses), iteration, assignment, deletion, and clearing.**
* **Provide insights into the efficiency of Go's map implementation under different workloads.**

**6. Inferring the Purpose in the Go Runtime:**

Knowing this is part of the Go runtime's test suite, it's clear that the purpose is to:

* **Ensure the map implementation is performant.**
* **Identify potential performance bottlenecks.**
* **Track performance changes over time (regression testing).**
* **Guide optimization efforts in the Go runtime.**

**7. Command-Line Arguments and Potential Mistakes:**

* The `mapbench` flag stands out. This controls whether the full, more extensive set of benchmarks is run. Without it, some benchmarks are skipped.
* A common mistake could be running the benchmarks without the `-mapbench` flag and missing some important performance tests.

**8. Structuring the Answer:**

Finally, I'd organize my findings into a clear and structured answer, covering the key aspects:

* **Overall Function:** Briefly state the main purpose (benchmarking Go maps).
* **Specific Functions:** List and describe the categories of benchmarks (hashing, lookups, iteration, assignment, etc.) with examples.
* **Go Language Feature:** Explain that it benchmarks the `map` data structure.
* **Code Example:**  Provide a simple Go map example to illustrate the feature being tested.
* **Assumptions and I/O (if applicable):** In this case, not much direct input/output beyond the benchmarking framework itself.
* **Command-Line Arguments:** Explain the `mapbench` flag.
* **Common Mistakes:** Point out the potential issue of not using the `-mapbench` flag.
* **Summary:** Briefly reiterate the purpose of the code.

This detailed thought process, starting with a high-level understanding and progressively diving into the details, allows for a comprehensive analysis of the provided Go benchmark code.
这个Go语言实现的文件 `go/src/runtime/map_benchmark_test.go` 的一部分，主要功能是**对 Go 语言中 `map` 这种数据结构在不同操作下的性能进行基准测试 (benchmark)**。

具体来说，它通过编写一系列的基准测试函数，来衡量 `map` 在以下方面的性能表现：

1. **不同键类型的哈希速度:**  测试使用不同类型的键（例如字符串、字节数组、整数等）进行哈希运算的速度。
2. **不同大小的 `map` 的性能:** 测试 `map` 在不同容量下的查找、插入等操作的性能。
3. **查找操作的性能:**  测试在 `map` 中查找已存在和不存在的键的性能。
4. **插入操作的性能:** 测试向 `map` 中插入新键值对的性能。
5. **迭代操作的性能:** 测试遍历 `map` 中所有键值对的性能。
6. **删除操作的性能:** 测试从 `map` 中删除键值对的性能。
7. **清空操作的性能:** 测试清空 `map` 中所有键值对的性能。
8. **使用不同大小的键的性能:**  测试使用不同长度的字符串作为键时的性能。
9. **预分配容量的影响:** 测试在创建 `map` 时指定初始容量对性能的影响。

**它是什么go语言功能的实现？**

这段代码主要用于测试和评估 Go 语言内置的 `map` 数据结构的性能。 `map` 是 Go 语言中一种非常重要且常用的关联数据结构，它提供了键值对的存储和快速查找功能。

**Go 代码举例说明 (假设的输入与输出):**

虽然这段代码本身是基准测试代码，但我们可以用一个简单的 Go 代码示例来展示 `map` 的基本用法，这是这些基准测试所针对的功能：

```go
package main

import "fmt"

func main() {
	// 创建一个 string 到 int 的 map
	ages := make(map[string]int)

	// 插入键值对
	ages["Alice"] = 30
	ages["Bob"] = 25
	ages["Charlie"] = 35

	// 查找键对应的值
	ageAlice, ok := ages["Alice"]
	if ok {
		fmt.Println("Alice's age:", ageAlice) // 输出: Alice's age: 30
	}

	// 查找不存在的键
	ageDavid, ok := ages["David"]
	if !ok {
		fmt.Println("David's age not found") // 输出: David's age not found
	}

	// 遍历 map
	for name, age := range ages {
		fmt.Printf("%s is %d years old\n", name, age)
	}

	// 删除键值对
	delete(ages, "Bob")
	fmt.Println("Ages after deleting Bob:", ages) // 输出: Ages after deleting Bob: map[Alice:30 Charlie:35]
}
```

**代码推理 (带上假设的输入与输出):**

以 `BenchmarkHashStringSpeed` 函数为例：

**假设输入:**

* `b *testing.B`:  Go 语言基准测试框架提供的参数，用于控制测试的运行。
* 在测试开始前，`size` 常量被定义为 `10`。

**代码:**

```go
func BenchmarkHashStringSpeed(b *testing.B) {
	strings := make([]string, size)
	for i := 0; i < size; i++ {
		strings[i] = fmt.Sprintf("string#%d", i)
	}
	sum := 0
	m := make(map[string]int, size)
	for i := 0; i < size; i++ {
		m[strings[i]] = 0
	}
	idx := 0
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		sum += m[strings[idx]]
		idx++
		if idx == size {
			idx = 0
		}
	}
}
```

**推理:**

1. **初始化:**  代码首先创建了一个包含 10 个字符串的切片 `strings`，每个字符串形如 "string#0", "string#1" ... "string#9"。然后创建了一个容量为 10 的 `map[string]int`，并将这些字符串作为键插入到 `map` 中，值都设置为 0。
2. **重置计时器:** `b.ResetTimer()` 表明从这里开始计算基准测试的时间。
3. **循环查找:**  在 `for i := 0; i < b.N; i++` 循环中，代码重复地根据 `idx` 从 `strings` 切片中取出一个字符串，并在 `map` 中查找该字符串对应的值，并将其加到 `sum` 变量上。`idx` 循环地从 0 递增到 9，确保每次都访问 `map` 中的不同键。
4. **基准测试目标:** 这个基准测试的目标是衡量在已经填充好数据的 `map` 中，使用字符串作为键进行查找操作的平均速度。

**假设输出 (不是实际的程序输出，而是基准测试的结果):**

当你运行 `go test -bench=. ./runtime` 命令时，这个基准测试可能会输出类似这样的结果：

```
BenchmarkHashStringSpeed-8   	 100000000	        10.5 ns/op	       0 B/op	       0 allocs/op
```

这表示在 8 个 CPU 核心下，`BenchmarkHashStringSpeed` 函数执行了 1 亿次迭代，每次操作平均耗时 10.5 纳秒，没有发生内存分配。

**命令行参数的具体处理:**

这段代码中使用了 `flag` 包来处理一个命令行参数：

```go
var mapbench = flag.Bool("mapbench", false, "enable the full set of map benchmark variants")
```

* **`flag.Bool("mapbench", false, "enable the full set of map benchmark variants")`**:  这行代码定义了一个名为 `mapbench` 的布尔类型的命令行标志。
    * `"mapbench"`:  这是标志的名称，在命令行中通过 `-mapbench` 来使用。
    * `false`:  这是标志的默认值，即如果不指定该标志，其值为 `false`。
    * `"enable the full set of map benchmark variants"`: 这是对该标志的描述，当使用 `-h` 或 `--help` 查看帮助信息时会显示。

**使用方式:**

在运行 `go test` 命令时，可以通过 `-mapbench` 标志来启用更全面的 `map` 基准测试变体。

* **不带 `-mapbench`:**  `go test -bench=. ./runtime`  在这种情况下，`mapbench` 的值为 `false`，某些被 `if !*mapbench` 条件排除的基准测试将被跳过。
* **带 `-mapbench`:** `go test -bench=. -mapbench ./runtime`  在这种情况下，`mapbench` 的值为 `true`，所有定义的 `map` 基准测试都会被执行。

**使用者易犯错的点:**

一个可能易犯的错误是**在运行基准测试时没有注意到 `-mapbench` 标志的影响**。  如果没有显式地设置 `-mapbench=true`，那么某些更全面的或更耗时的基准测试可能不会运行，导致对 `map` 性能的评估不够完整。  例如，在 `benchSizes` 函数中，可以看到一些特定的 `map` 大小的基准测试默认是启用的，而其他的则需要 `-mapbench` 标志才能运行。

**第1部分功能归纳:**

总而言之，这部分代码的主要功能是：

* **定义了一系列针对 Go 语言 `map` 数据结构的性能基准测试函数。**
* **测试了 `map` 在不同键类型下的哈希速度。**
* **测试了 `map` 在不同容量下的基本操作（查找）的性能。**
* **使用 `flag` 包定义了一个命令行参数 `-mapbench`，用于控制是否运行更全面的基准测试。**
* **为 Go 语言 `map` 的性能分析和优化提供了基础。**

### 提示词
```
这是路径为go/src/runtime/map_benchmark_test.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```go
// Copyright 2013 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package runtime_test

import (
	"encoding/binary"
	"flag"
	"fmt"
	"math/rand"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"testing"
	"unsafe"
)

var mapbench = flag.Bool("mapbench", false, "enable the full set of map benchmark variants")

const size = 10

func BenchmarkHashStringSpeed(b *testing.B) {
	strings := make([]string, size)
	for i := 0; i < size; i++ {
		strings[i] = fmt.Sprintf("string#%d", i)
	}
	sum := 0
	m := make(map[string]int, size)
	for i := 0; i < size; i++ {
		m[strings[i]] = 0
	}
	idx := 0
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		sum += m[strings[idx]]
		idx++
		if idx == size {
			idx = 0
		}
	}
}

type chunk [17]byte

func BenchmarkHashBytesSpeed(b *testing.B) {
	// a bunch of chunks, each with a different alignment mod 16
	var chunks [size]chunk
	// initialize each to a different value
	for i := 0; i < size; i++ {
		chunks[i][0] = byte(i)
	}
	// put into a map
	m := make(map[chunk]int, size)
	for i, c := range chunks {
		m[c] = i
	}
	idx := 0
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if m[chunks[idx]] != idx {
			b.Error("bad map entry for chunk")
		}
		idx++
		if idx == size {
			idx = 0
		}
	}
}

func BenchmarkHashInt32Speed(b *testing.B) {
	ints := make([]int32, size)
	for i := 0; i < size; i++ {
		ints[i] = int32(i)
	}
	sum := 0
	m := make(map[int32]int, size)
	for i := 0; i < size; i++ {
		m[ints[i]] = 0
	}
	idx := 0
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		sum += m[ints[idx]]
		idx++
		if idx == size {
			idx = 0
		}
	}
}

func BenchmarkHashInt64Speed(b *testing.B) {
	ints := make([]int64, size)
	for i := 0; i < size; i++ {
		ints[i] = int64(i)
	}
	sum := 0
	m := make(map[int64]int, size)
	for i := 0; i < size; i++ {
		m[ints[i]] = 0
	}
	idx := 0
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		sum += m[ints[idx]]
		idx++
		if idx == size {
			idx = 0
		}
	}
}
func BenchmarkHashStringArraySpeed(b *testing.B) {
	stringpairs := make([][2]string, size)
	for i := 0; i < size; i++ {
		for j := 0; j < 2; j++ {
			stringpairs[i][j] = fmt.Sprintf("string#%d/%d", i, j)
		}
	}
	sum := 0
	m := make(map[[2]string]int, size)
	for i := 0; i < size; i++ {
		m[stringpairs[i]] = 0
	}
	idx := 0
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		sum += m[stringpairs[idx]]
		idx++
		if idx == size {
			idx = 0
		}
	}
}

func BenchmarkMegMap(b *testing.B) {
	m := make(map[string]bool)
	for suffix := 'A'; suffix <= 'G'; suffix++ {
		m[strings.Repeat("X", 1<<20-1)+fmt.Sprint(suffix)] = true
	}
	key := strings.Repeat("X", 1<<20-1) + "k"
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = m[key]
	}
}

func BenchmarkMegOneMap(b *testing.B) {
	m := make(map[string]bool)
	m[strings.Repeat("X", 1<<20)] = true
	key := strings.Repeat("Y", 1<<20)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = m[key]
	}
}

func BenchmarkMegEqMap(b *testing.B) {
	m := make(map[string]bool)
	key1 := strings.Repeat("X", 1<<20)
	key2 := strings.Repeat("X", 1<<20) // equal but different instance
	m[key1] = true
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = m[key2]
	}
}

func BenchmarkMegEmptyMap(b *testing.B) {
	m := make(map[string]bool)
	key := strings.Repeat("X", 1<<20)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = m[key]
	}
}

func BenchmarkMegEmptyMapWithInterfaceKey(b *testing.B) {
	m := make(map[any]bool)
	key := strings.Repeat("X", 1<<20)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = m[key]
	}
}

func BenchmarkSmallStrMap(b *testing.B) {
	m := make(map[string]bool)
	for suffix := 'A'; suffix <= 'G'; suffix++ {
		m[fmt.Sprint(suffix)] = true
	}
	key := "k"
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = m[key]
	}
}

func BenchmarkMapStringKeysEight_16(b *testing.B)  { benchmarkMapStringKeysEight(b, 16) }
func BenchmarkMapStringKeysEight_32(b *testing.B)  { benchmarkMapStringKeysEight(b, 32) }
func BenchmarkMapStringKeysEight_64(b *testing.B)  { benchmarkMapStringKeysEight(b, 64) }
func BenchmarkMapStringKeysEight_128(b *testing.B) { benchmarkMapStringKeysEight(b, 128) }
func BenchmarkMapStringKeysEight_256(b *testing.B) { benchmarkMapStringKeysEight(b, 256) }
func BenchmarkMapStringKeysEight_1M(b *testing.B)  { benchmarkMapStringKeysEight(b, 1<<20) }

func benchmarkMapStringKeysEight(b *testing.B, keySize int) {
	m := make(map[string]bool)
	for i := 0; i < 8; i++ {
		m[strings.Repeat("K", i+1)] = true
	}
	key := strings.Repeat("K", keySize)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = m[key]
	}
}

func BenchmarkMapFirst(b *testing.B) {
	for n := 1; n <= 16; n++ {
		b.Run(fmt.Sprintf("%d", n), func(b *testing.B) {
			m := make(map[int]bool)
			for i := 0; i < n; i++ {
				m[i] = true
			}
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_ = m[0]
			}
		})
	}
}
func BenchmarkMapMid(b *testing.B) {
	for n := 1; n <= 16; n++ {
		b.Run(fmt.Sprintf("%d", n), func(b *testing.B) {
			m := make(map[int]bool)
			for i := 0; i < n; i++ {
				m[i] = true
			}
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_ = m[n>>1]
			}
		})
	}
}
func BenchmarkMapLast(b *testing.B) {
	for n := 1; n <= 16; n++ {
		b.Run(fmt.Sprintf("%d", n), func(b *testing.B) {
			m := make(map[int]bool)
			for i := 0; i < n; i++ {
				m[i] = true
			}
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_ = m[n-1]
			}
		})
	}
}

func cyclicPermutation(n int) []int {
	// From https://crypto.stackexchange.com/questions/51787/creating-single-cycle-permutations
	p := rand.New(rand.NewSource(1)).Perm(n)
	inc := make([]int, n)
	pInv := make([]int, n)
	for i := 0; i < n; i++ {
		inc[i] = (i + 1) % n
		pInv[p[i]] = i
	}
	res := make([]int, n)
	for i := 0; i < n; i++ {
		res[i] = pInv[inc[p[i]]]
	}

	// Test result.
	j := 0
	for i := 0; i < n-1; i++ {
		j = res[j]
		if j == 0 {
			panic("got back to 0 too early")
		}
	}
	j = res[j]
	if j != 0 {
		panic("didn't get back to 0")
	}
	return res
}

func BenchmarkMapCycle(b *testing.B) {
	// Arrange map entries to be a permutation, so that
	// we hit all entries, and one lookup is data dependent
	// on the previous lookup.
	const N = 3127
	p := cyclicPermutation(N)
	m := map[int]int{}
	for i := 0; i < N; i++ {
		m[i] = p[i]
	}
	b.ResetTimer()
	j := 0
	for i := 0; i < b.N; i++ {
		j = m[j]
	}
	sink = uint64(j)
}

// Accessing the same keys in a row.
func benchmarkRepeatedLookup(b *testing.B, lookupKeySize int) {
	m := make(map[string]bool)
	// At least bigger than a single bucket:
	for i := 0; i < 64; i++ {
		m[fmt.Sprintf("some key %d", i)] = true
	}
	base := strings.Repeat("x", lookupKeySize-1)
	key1 := base + "1"
	key2 := base + "2"
	b.ResetTimer()
	for i := 0; i < b.N/4; i++ {
		_ = m[key1]
		_ = m[key1]
		_ = m[key2]
		_ = m[key2]
	}
}

func BenchmarkRepeatedLookupStrMapKey32(b *testing.B) { benchmarkRepeatedLookup(b, 32) }
func BenchmarkRepeatedLookupStrMapKey1M(b *testing.B) { benchmarkRepeatedLookup(b, 1<<20) }

func BenchmarkMakeMap(b *testing.B) {
	b.Run("[Byte]Byte", func(b *testing.B) {
		var m map[byte]byte
		for i := 0; i < b.N; i++ {
			m = make(map[byte]byte, 10)
		}
		hugeSink = m
	})
	b.Run("[Int]Int", func(b *testing.B) {
		var m map[int]int
		for i := 0; i < b.N; i++ {
			m = make(map[int]int, 10)
		}
		hugeSink = m
	})
}

func BenchmarkNewEmptyMap(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = make(map[int]int)
	}
}

func BenchmarkNewSmallMap(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		m := make(map[int]int)
		m[0] = 0
		m[1] = 1
	}
}

func BenchmarkSameLengthMap(b *testing.B) {
	// long strings, same length, differ in first few
	// and last few bytes.
	m := make(map[string]bool)
	s1 := "foo" + strings.Repeat("-", 100) + "bar"
	s2 := "goo" + strings.Repeat("-", 100) + "ber"
	m[s1] = true
	m[s2] = true
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = m[s1]
	}
}

func BenchmarkSmallKeyMap(b *testing.B) {
	m := make(map[int16]bool)
	m[5] = true
	for i := 0; i < b.N; i++ {
		_ = m[5]
	}
}

func BenchmarkMapPopulate(b *testing.B) {
	for size := 1; size < 1000000; size *= 10 {
		b.Run(strconv.Itoa(size), func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				m := make(map[int]bool)
				for j := 0; j < size; j++ {
					m[j] = true
				}
			}
		})
	}
}

type ComplexAlgKey struct {
	a, b, c int64
	_       int
	d       int32
	_       int
	e       string
	_       int
	f, g, h int64
}

func BenchmarkComplexAlgMap(b *testing.B) {
	m := make(map[ComplexAlgKey]bool)
	var k ComplexAlgKey
	m[k] = true
	for i := 0; i < b.N; i++ {
		_ = m[k]
	}
}

func BenchmarkGoMapClear(b *testing.B) {
	b.Run("Reflexive", func(b *testing.B) {
		for size := 1; size < 100000; size *= 10 {
			b.Run(strconv.Itoa(size), func(b *testing.B) {
				m := make(map[int]int, size)
				for i := 0; i < b.N; i++ {
					m[0] = size // Add one element so len(m) != 0 avoiding fast paths.
					clear(m)
				}
			})
		}
	})
	b.Run("NonReflexive", func(b *testing.B) {
		for size := 1; size < 100000; size *= 10 {
			b.Run(strconv.Itoa(size), func(b *testing.B) {
				m := make(map[float64]int, size)
				for i := 0; i < b.N; i++ {
					m[1.0] = size // Add one element so len(m) != 0 avoiding fast paths.
					clear(m)
				}
			})
		}
	})
}

func BenchmarkMapStringConversion(b *testing.B) {
	for _, length := range []int{32, 64} {
		b.Run(strconv.Itoa(length), func(b *testing.B) {
			bytes := make([]byte, length)
			b.Run("simple", func(b *testing.B) {
				b.ReportAllocs()
				m := make(map[string]int)
				m[string(bytes)] = 0
				for i := 0; i < b.N; i++ {
					_ = m[string(bytes)]
				}
			})
			b.Run("struct", func(b *testing.B) {
				b.ReportAllocs()
				type stringstruct struct{ s string }
				m := make(map[stringstruct]int)
				m[stringstruct{string(bytes)}] = 0
				for i := 0; i < b.N; i++ {
					_ = m[stringstruct{string(bytes)}]
				}
			})
			b.Run("array", func(b *testing.B) {
				b.ReportAllocs()
				type stringarray [1]string
				m := make(map[stringarray]int)
				m[stringarray{string(bytes)}] = 0
				for i := 0; i < b.N; i++ {
					_ = m[stringarray{string(bytes)}]
				}
			})
		})
	}
}

var BoolSink bool

func BenchmarkMapInterfaceString(b *testing.B) {
	m := map[any]bool{}

	for i := 0; i < 100; i++ {
		m[fmt.Sprintf("%d", i)] = true
	}

	key := (any)("A")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		BoolSink = m[key]
	}
}
func BenchmarkMapInterfacePtr(b *testing.B) {
	m := map[any]bool{}

	for i := 0; i < 100; i++ {
		i := i
		m[&i] = true
	}

	key := new(int)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		BoolSink = m[key]
	}
}

var (
	hintLessThan8    = 7
	hintGreaterThan8 = 32
)

func BenchmarkNewEmptyMapHintLessThan8(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = make(map[int]int, hintLessThan8)
	}
}

func BenchmarkNewEmptyMapHintGreaterThan8(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = make(map[int]int, hintGreaterThan8)
	}
}

func benchSizes(f func(b *testing.B, n int)) func(*testing.B) {
	var cases = []int{
		0,
		6,
		12,
		18,
		24,
		30,
		64,
		128,
		256,
		512,
		1024,
		2048,
		4096,
		8192,
		1 << 16,
		1 << 18,
		1 << 20,
		1 << 22,
	}

	// Cases enabled by default. Set -mapbench for the remainder.
	//
	// With the other type combinations, there are literally thousands of
	// variations. It take too long to run all of these as part of
	// builders.
	byDefault := map[int]bool{
		6:       true,
		64:      true,
		1 << 16: true,
	}

	return func(b *testing.B) {
		for _, n := range cases {
			b.Run("len="+strconv.Itoa(n), func(b *testing.B) {
				if !*mapbench && !byDefault[n] {
					b.Skip("Skipped because -mapbench=false")
				}

				f(b, n)
			})
		}
	}
}
func smallBenchSizes(f func(b *testing.B, n int)) func(*testing.B) {
	return func(b *testing.B) {
		for n := 1; n <= 8; n++ {
			b.Run("len="+strconv.Itoa(n), func(b *testing.B) {
				f(b, n)
			})
		}
	}
}

// A 16 byte type.
type smallType [16]byte

// A 512 byte type.
type mediumType [1 << 9]byte

// A 4KiB type.
type bigType [1 << 12]byte

type mapBenchmarkKeyType interface {
	int32 | int64 | string | smallType | mediumType | bigType | *int32
}

type mapBenchmarkElemType interface {
	mapBenchmarkKeyType | []int32
}

func genIntValues[T int | int32 | int64](start, end int) []T {
	vals := make([]T, 0, end-start)
	for i := start; i < end; i++ {
		vals = append(vals, T(i))
	}
	return vals
}

func genStringValues(start, end int) []string {
	vals := make([]string, 0, end-start)
	for i := start; i < end; i++ {
		vals = append(vals, strconv.Itoa(i))
	}
	return vals
}

func genSmallValues(start, end int) []smallType {
	vals := make([]smallType, 0, end-start)
	for i := start; i < end; i++ {
		var v smallType
		binary.NativeEndian.PutUint64(v[:], uint64(i))
		vals = append(vals, v)
	}
	return vals
}

func genMediumValues(start, end int) []mediumType {
	vals := make([]mediumType, 0, end-start)
	for i := start; i < end; i++ {
		var v mediumType
		binary.NativeEndian.PutUint64(v[:], uint64(i))
		vals = append(vals, v)
	}
	return vals
}

func genBigValues(start, end int) []bigType {
	vals := make([]bigType, 0, end-start)
	for i := start; i < end; i++ {
		var v bigType
		binary.NativeEndian.PutUint64(v[:], uint64(i))
		vals = append(vals, v)
	}
	return vals
}

func genPtrValues[T any](start, end int) []*T {
	// Start and end don't mean much. Each pointer by definition has a
	// unique identity.
	vals := make([]*T, 0, end-start)
	for i := start; i < end; i++ {
		v := new(T)
		vals = append(vals, v)
	}
	return vals
}

func genIntSliceValues[T int | int32 | int64](start, end int) [][]T {
	vals := make([][]T, 0, end-start)
	for i := start; i < end; i++ {
		vals = append(vals, []T{T(i)})
	}
	return vals
}

func genValues[T mapBenchmarkElemType](start, end int) []T {
	var t T
	switch any(t).(type) {
	case int32:
		return any(genIntValues[int32](start, end)).([]T)
	case int64:
		return any(genIntValues[int64](start, end)).([]T)
	case string:
		return any(genStringValues(start, end)).([]T)
	case smallType:
		return any(genSmallValues(start, end)).([]T)
	case mediumType:
		return any(genMediumValues(start, end)).([]T)
	case bigType:
		return any(genBigValues(start, end)).([]T)
	case *int32:
		return any(genPtrValues[int32](start, end)).([]T)
	case []int32:
		return any(genIntSliceValues[int32](start, end)).([]T)
	default:
		panic("unreachable")
	}
}

// Avoid inlining to force a heap allocation.
//
//go:noinline
func newSink[T mapBenchmarkElemType]() *T {
	return new(T)
}

// Return a new maps filled with keys and elems. Both slices must be the same length.
func fillMap[K mapBenchmarkKeyType, E mapBenchmarkElemType](keys []K, elems []E) map[K]E {
	m := make(map[K]E, len(keys))
	for i := range keys {
		m[keys[i]] = elems[i]
	}
	return m
}

func iterCount(b *testing.B, n int) int {
	// Divide b.N by n so that the ns/op reports time per element,
	// not time per full map iteration. This makes benchmarks of
	// different map sizes more comparable.
	//
	// If size is zero we still need to do iterations.
	if n == 0 {
		return b.N
	}
	return b.N / n
}

func checkAllocSize[K, E any](b *testing.B, n int) {
	var k K
	size := uint64(n) * uint64(unsafe.Sizeof(k))
	var e E
	size += uint64(n) * uint64(unsafe.Sizeof(e))

	if size >= 1<<30 {
		b.Skipf("Total key+elem size %d exceeds 1GiB", size)
	}
}

func benchmarkMapIter[K mapBenchmarkKeyType, E mapBenchmarkElemType](b *testing.B, n int) {
	checkAllocSize[K, E](b, n)
	k := genValues[K](0, n)
	e := genValues[E](0, n)
	m := fillMap(k, e)
	iterations := iterCount(b, n)
	sinkK := newSink[K]()
	sinkE := newSink[E]()
	b.ResetTimer()

	for i := 0; i < iterations; i++ {
		for k, e := range m {
			*sinkK = k
			*sinkE = e
		}
	}
}

func BenchmarkMapIter(b *testing.B) {
	b.Run("Key=int32/Elem=int32", benchSizes(benchmarkMapIter[int32, int32]))
	b.Run("Key=int64/Elem=int64", benchSizes(benchmarkMapIter[int64, int64]))
	b.Run("Key=string/Elem=string", benchSizes(benchmarkMapIter[string, string]))
	b.Run("Key=smallType/Elem=int32", benchSizes(benchmarkMapIter[smallType, int32]))
	b.Run("Key=mediumType/Elem=int32", benchSizes(benchmarkMapIter[mediumType, int32]))
	b.Run("Key=bigType/Elem=int32", benchSizes(benchmarkMapIter[bigType, int32]))
	b.Run("Key=bigType/Elem=bigType", benchSizes(benchmarkMapIter[bigType, bigType]))
	b.Run("Key=int32/Elem=bigType", benchSizes(benchmarkMapIter[int32, bigType]))
	b.Run("Key=*int32/Elem=int32", benchSizes(benchmarkMapIter[*int32, int32]))
	b.Run("Key=int32/Elem=*int32", benchSizes(benchmarkMapIter[int32, *int32]))
}

func benchmarkMapIterLowLoad[K mapBenchmarkKeyType, E mapBenchmarkElemType](b *testing.B, n int) {
	// Only insert one entry regardless of map size.
	k := genValues[K](0, 1)
	e := genValues[E](0, 1)

	m := make(map[K]E, n)
	for i := range k {
		m[k[i]] = e[i]
	}

	iterations := iterCount(b, n)
	sinkK := newSink[K]()
	sinkE := newSink[E]()
	b.ResetTimer()

	for i := 0; i < iterations; i++ {
		for k, e := range m {
			*sinkK = k
			*sinkE = e
		}
	}
}

func BenchmarkMapIterLowLoad(b *testing.B) {
	b.Run("Key=int32/Elem=int32", benchSizes(benchmarkMapIterLowLoad[int32, int32]))
	b.Run("Key=int64/Elem=int64", benchSizes(benchmarkMapIterLowLoad[int64, int64]))
	b.Run("Key=string/Elem=string", benchSizes(benchmarkMapIterLowLoad[string, string]))
	b.Run("Key=smallType/Elem=int32", benchSizes(benchmarkMapIterLowLoad[smallType, int32]))
	b.Run("Key=mediumType/Elem=int32", benchSizes(benchmarkMapIterLowLoad[mediumType, int32]))
	b.Run("Key=bigType/Elem=int32", benchSizes(benchmarkMapIterLowLoad[bigType, int32]))
	b.Run("Key=bigType/Elem=bigType", benchSizes(benchmarkMapIterLowLoad[bigType, bigType]))
	b.Run("Key=int32/Elem=bigType", benchSizes(benchmarkMapIterLowLoad[int32, bigType]))
	b.Run("Key=*int32/Elem=int32", benchSizes(benchmarkMapIterLowLoad[*int32, int32]))
	b.Run("Key=int32/Elem=*int32", benchSizes(benchmarkMapIterLowLoad[int32, *int32]))
}

func benchmarkMapAccessHit[K mapBenchmarkKeyType, E mapBenchmarkElemType](b *testing.B, n int) {
	if n == 0 {
		b.Skip("can't access empty map")
	}
	checkAllocSize[K, E](b, n)
	k := genValues[K](0, n)
	e := genValues[E](0, n)
	m := fillMap(k, e)
	sink := newSink[E]()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		*sink = m[k[i%n]]
	}
}

func BenchmarkMapAccessHit(b *testing.B) {
	b.Run("Key=int32/Elem=int32", benchSizes(benchmarkMapAccessHit[int32, int32]))
	b.Run("Key=int64/Elem=int64", benchSizes(benchmarkMapAccessHit[int64, int64]))
	b.Run("Key=string/Elem=string", benchSizes(benchmarkMapAccessHit[string, string]))
	b.Run("Key=smallType/Elem=int32", benchSizes(benchmarkMapAccessHit[smallType, int32]))
	b.Run("Key=mediumType/Elem=int32", benchSizes(benchmarkMapAccessHit[mediumType, int32]))
	b.Run("Key=bigType/Elem=int32", benchSizes(benchmarkMapAccessHit[bigType, int32]))
	b.Run("Key=bigType/Elem=bigType", benchSizes(benchmarkMapAccessHit[bigType, bigType]))
	b.Run("Key=int32/Elem=bigType", benchSizes(benchmarkMapAccessHit[int32, bigType]))
	b.Run("Key=*int32/Elem=int32", benchSizes(benchmarkMapAccessHit[*int32, int32]))
	b.Run("Key=int32/Elem=*int32", benchSizes(benchmarkMapAccessHit[int32, *int32]))
}

var sinkOK bool

func benchmarkMapAccessMiss[K mapBenchmarkKeyType, E mapBenchmarkElemType](b *testing.B, n int) {
	checkAllocSize[K, E](b, n)
	k := genValues[K](0, n)
	e := genValues[E](0, n)
	m := fillMap(k, e)
	if n == 0 { // Create a lookup values for empty maps.
		n = 1
	}
	w := genValues[K](n, 2*n)
	b.ResetTimer()

	var ok bool
	for i := 0; i < b.N; i++ {
		_, ok = m[w[i%n]]
	}

	sinkOK = ok
}

func BenchmarkMapAccessMiss(b *testing.B) {
	b.Run("Key=int32/Elem=int32", benchSizes(benchmarkMapAccessMiss[int32, int32]))
	b.Run("Key=int64/Elem=int64", benchSizes(benchmarkMapAccessMiss[int64, int64]))
	b.Run("Key=string/Elem=string", benchSizes(benchmarkMapAccessMiss[string, string]))
	b.Run("Key=smallType/Elem=int32", benchSizes(benchmarkMapAccessMiss[smallType, int32]))
	b.Run("Key=mediumType/Elem=int32", benchSizes(benchmarkMapAccessMiss[mediumType, int32]))
	b.Run("Key=bigType/Elem=int32", benchSizes(benchmarkMapAccessMiss[bigType, int32]))
	b.Run("Key=bigType/Elem=bigType", benchSizes(benchmarkMapAccessMiss[bigType, bigType]))
	b.Run("Key=int32/Elem=bigType", benchSizes(benchmarkMapAccessMiss[int32, bigType]))
	b.Run("Key=*int32/Elem=int32", benchSizes(benchmarkMapAccessMiss[*int32, int32]))
	b.Run("Key=int32/Elem=*int32", benchSizes(benchmarkMapAccessMiss[int32, *int32]))
}

// Assign to a key that already exists.
func benchmarkMapAssignExists[K mapBenchmarkKeyType, E mapBenchmarkElemType](b *testing.B, n int) {
	if n == 0 {
		b.Skip("can't assign to existing keys in empty map")
	}
	checkAllocSize[K, E](b, n)
	k := genValues[K](0, n)
	e := genValues[E](0, n)
	m := fillMap(k, e)
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		m[k[i%n]] = e[i%n]
	}
}

func BenchmarkMapAssignExists(b *testing.B) {
	b.Run("Key=int32/Elem=int32", benchSizes(benchmarkMapAssignExists[int32, int32]))
	b.Run("Key=int64/Elem=int64", benchSizes(benchmarkMapAssignExists[int64, int64]))
	b.Run("Key=string/Elem=string", benchSizes(benchmarkMapAssignExists[string, string]))
	b.Run("Key=smallType/Elem=int32", benchSizes(benchmarkMapAssignExists[smallType, int32]))
	b.Run("Key=mediumType/Elem=int32", benchSizes(benchmarkMapAssignExists[mediumType, int32]))
	b.Run("Key=bigType/Elem=int32", benchSizes(benchmarkMapAssignExists[bigType, int32]))
	b.Run("Key=bigType/Elem=bigType", benchSizes(benchmarkMapAssignExists[bigType, bigType]))
	b.Run("Key=int32/Elem=bigType", benchSizes(benchmarkMapAssignExists[int32, bigType]))
	b.Run("Key=*int32/Elem=int32", benchSizes(benchmarkMapAssignExists[*int32, int32]))
	b.Run("Key=int32/Elem=*int32", benchSizes(benchmarkMapAssignExists[int32, *int32]))
}

// Fill a map of size n with no hint. Time is per-key. A new map is created
// every n assignments.
//
// TODO(prattmic): Results don't make much sense if b.N < n.
// TODO(prattmic): Measure distribution of assign time to reveal the grow
// latency.
func benchmarkMapAssignFillNoHint[K mapBenchmarkKeyType, E mapBenchmarkElemType](b *testing.B, n int) {
	if n == 0 {
		b.Skip("can't create empty map via assignment")
	}
	checkAllocSize[K, E](b, n)
	k := genValues[K](0, n)
	e := genValues[E](0, n)
	b.ResetTimer()

	var m map[K]E
	for i := 0; i < b.N; i++ {
		if i%n == 0 {
			m = make(map[K]E)
		}
		m[k[i%n]] = e[i%n]
	}
}

func BenchmarkMapAssignFillNoHint(b *testing.B) {
	b.Run("Key=int32/Elem=int32", benchSizes(benchmarkMapAssignFillNoHint[int32, int32]))
	b.Run("Key=int64/Elem=int64", benchSizes(benchmarkMapAssignFillNoHint[int64, int64]))
	b.Run("Key=string/Elem=string", benchSizes(benchmarkMapAssignFillNoHint[string, string]))
	b.Run("Key=smallType/Elem=int32", benchSizes(benchmarkMapAssignFillNoHint[smallType, int32]))
	b.Run("Key=mediumType/Elem=int32", benchSizes(benchmarkMapAssignFillNoHint[mediumType, int32]))
	b.Run("Key=bigType/Elem=int32", benchSizes(benchmarkMapAssignFillNoHint[bigType, int32]))
	b.Run("Key=bigType/Elem=bigType", benchSizes(benchmarkMapAssignFillNoHint[bigType, bigType]))
	b.Run("Key=int32/Elem=bigType", benchSizes(benchmarkMapAssignFillNoHint[int32, bigType]))
	b.Run("Key=*int32/Elem=int32", benchSizes(benchmarkMapAssignFillNoHint[*int32, int32]))
	b.Run("Key=int32/Elem=*int32", benchSizes(benchmarkMapAssignFillNoHint[int32, *int32]))
}

// Identical to benchmarkMapAssignFillNoHint, but additionally measures the
// latency of each mapassign to report tail latency due to map grow.
func benchmarkMapAssignGrowLatency[K mapBenchmarkKeyType, E mapBenchmarkElemType](b *testing.B, n int) {
	if n == 0 {
		b.Skip("can't create empty map via assignment")
	}
	checkAllocSize[K, E](b, n)
	k := genValues[K](0, n)
	e := genValues[E](0, n)

	// Store the run time of each mapassign. Keeping the full data rather
	// than a histogram provides higher precision. b.N tends to be <10M, so
	// the memory requirement isn't too bad.
	sample := make([]int64, b.N)

	b.ResetTimer()

	var m map[K]E
	for i := 0; i < b.N; i++ {
		if i%n == 0 {
			m = make(map[K]E)
		}
		start := runtime.Nanotime()
		m[k[i%n]] = e[i%n]
		end := runtime.Nanotime()
		sample[i] = end - start
	}

	b.StopTimer()

	slices.Sort(sample)
	// TODO(prattmic): Grow is so rare that even p99.99 often doesn't
	// display a grow case. Switch to a more direct measure of grow cases
	// only?
	b.ReportMetric(float64(sample[int(float64(len(sample))*0.5)]), "p50-ns/op")
	b.ReportMetric(float64(sample[int(float64(len(sample))*0.99)]), "p99-ns/op")
	b.ReportMetric(float64(sample[int(float64(len(sample))*0.999)]), "p99.9-ns/op")
	b.ReportMetric(float64(sample[int(float64(len(sample))*0.9999)]), "p99.99-ns/op")
	b.ReportMetric(float64(sample[len(sample)-1]), "p100-ns/op")
}

func BenchmarkMapAssignGrowLatency(b *testing.B) {
	b.Run("Key=int32/Elem=int32", benchSizes(benchmarkMapAssignGrowLatency[int32, int32]))
	b.Run("Key=int64/Elem=int64", benchSizes(benchmarkMapAssignGrowLatency[int64, int64]))
	b.Run("Key=string/Elem=string", benchSizes(benchmarkMapAssignGrowLatency[string, string]))
	b.Run("Key=smallType/Elem=int32", benchSizes(benchmarkMapAssignGrowLatency[smallType, int32]))
	b.Run("Key=mediumType/Elem=int32", benchSizes(benchmarkMapAssignGrowLatency[mediumType, int32]))
	b.Run("Key=bigType/Elem=int32", benchSizes(benchmarkMapAssignGrowLatency[bigType, int32]))
	b.Run("Key=bigType/Elem=bigType", benchSizes(benchmarkMapAssignGrowLatency[bigType, bigType]))
	b.Run("Key=int32/Elem=bigType", benchSizes(benchmarkMapAssignGrowLatency[int32, bigType]))
	b.Run("Key=*int32/Elem=int32", benchSizes(benchmarkMapAssignGrowLatency[*int32, int32]))
	b.Run("Key=int32/Elem=*int32", benchSizes(benchmarkMapAssignGrowLatency[int32, *int32]))
}

// Fill a map of size n with size hint. Time is per-key. A new map is created
// every n assignments.
//
// TODO(prattmic): Results don't make much sense if b.N < n.
func benchmarkMapAssignFillHint[K mapBenchmarkKeyType, E mapBenchmarkElemType](b *testing.B, n int) {
	if n == 0 {
		b.Skip("can't create empty map via assignment")
	}
	checkAllocSize[K, E](b, n)
	k := genValues[K](0, n)
	e := genValues[E](0, n)
	b.ResetTimer()

	var m map[K]E
	for i := 0; i < b.N; i++ {
		if i%n == 0 {
			m = make(map[K]E, n)
		}
		m[k[i%n]] = e[i%n]
	}
}

func BenchmarkMapAssignFillHint(b *testing.B) {
	b.Run("Key=int32/Elem=int32", benchSizes(benchmarkMapAssignFillHint[int32, int32]))
	b.Run("Key=int64/Elem=int64", benchSizes(benchmarkMapAssignFillHint[int64, int64]))
	b.Run("Key=string/Elem=string", benchSizes(benchmarkMapAssignFillHint[string, string]))
	b.Run("Key=smallType/Elem=int32", benchSizes(benchmarkMapAssignFillHint[smallType, int32]))
	b.Run("Key=mediumType/Elem=int32", benchSizes(benchmarkMapAssignFillHint[mediumType, int32]))
	b.Run("Key=bigType/Elem=int32", benchSizes(benchmarkMapAssignFillHint[bigType, int32]))
	b.Run("Key=bigType/Elem=bigType", benchSizes(benchmarkMapAssignFillHint[bigType, bigType]))
	b.Run("Key=int32/Elem=bigType", benchSizes(benchmarkMapAssignFillHint[int32, bigType]))
	b.Run("Key=*int32/Elem=int32", benchSizes(benchmarkMapAssignFillHint[*int32, int32]))
	b.Run("Key=int32/Elem=*int32", benchSizes(benchmarkMapAssignFillHint[int32, *int32]))
}

// Fill a map of size n, reusing the same map. Time is per-key. The map is
// cleared every n assignments.
//
// TODO(prattmic): Results don't make much sense if b.N < n.
func benchmarkMapAssignFillClear[K mapBenchmarkKeyType, E mapBenchmarkElemType](b *testing.B, n int) {
	if n == 0 {
		b.Skip("can't create empty map via assignment")
	}
	checkAllocSize[K, E](b, n)
	k := genValues[K](0, n)
	e := genValues[E](0, n)
	m := fillMap(k, e)
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		if i%n == 0 {
			clear(m)
		}
		m[k[i%n]] = e[i%n]
	}
}

func BenchmarkMapAssignFillClear(b *testing.B) {
	b.Run("Key=int32/Elem=int32", benchSizes(benchmarkMapAssignFillClear[int32, int32]))
	b.Run("Key=int64/Elem=int64", benchSizes(benchmarkMapAssignFillClear[int64, int64]))
	b.Run("Key=string/Elem=string", benchSizes(benchmarkMapAssignFillClear[string, string]))
	b.Run("Key=smallType/Elem=int32", benchSizes(benchmarkMapAssignFillClear[smallType, int32]))
	b.Run("Key=mediumType/Elem=int32", benchSizes(benchmarkMapAssignFillClear[mediumType, int32]))
	b.Run("Key=bigType/Elem=int32", benchSizes(benchmarkMapAssignFillClear[bigType, int32]))
	b.Run("Key=bigType/Elem=bigType", benchSizes(benchmarkMapAssignFillClear[bigType, bigType]))
	b.Run("Key=int32/Elem=bigType", benchSizes(benchmarkMapAssignFillClear[int32, bigType]))
	b.Run("Key=*int32/Elem=int32", benchSizes(benchmarkMapAssignFillClear[*int32, int32]))
	b.Run("Key=int32/Elem=*int32", benchSizes(benchmarkMapAssignFillClear[int32, *int32]))
}

// Modify values using +=.
func benchmarkMapAssignAddition[K mapBenchmarkKeyType, E int32 | int64 | string](b *testing.B, n int) {
	if n == 0 {
		b.Skip("can't modify empty map via assignment")
	}
	checkAllocSize[K, E](b, n)
	k := genValues[K](0, n)
	e := genValues[E](0, n)
	m := fillMap(k, e)
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		m[k[i%n]] += e[i%n]
	}
}

func BenchmarkMapAssignAddition(b *testing.B) {
	b.Run("Key=int32/Elem=int32", benchSizes(benchmarkMapAssignAddition[int32, int32]))
	b.Run("Key=int64/Elem=int64", benchSizes(benchmarkMapAssignAddition[int64, int64]))
	b.Run("Key=string/Elem=string", benchSizes(benchmarkMapAssignAddition[string, string]))
	b.Run("Key=smallType/Elem=int32", benchSizes(benchmarkMapAssignAddition[smallType, int32]))
	b.Run("Key=mediumType/Elem=int32", benchSizes(benchmarkMapAssignAddition[mediumType, int32]))
	b.Run("Key=bigType/Elem=int32", benchSizes(benchmarkMapAssignAddition[bigType, int32]))
}

// Modify values append.
func benchmarkMapAssignAppend[K mapBenchmarkKeyType](b *testing.B, n int) {
	if n == 0 {
		b.Skip("can't modify empty map via append")
	}
	checkAllocSize[K, []int32](b, n)
	k := genValues[K](0, n)
	e := genValues[[]int32](0, n)
	m := fillMap(k, e)
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		m[k[i%n]] = append(m[k[i%n]], e[i%n][0])
	}
}

func BenchmarkMapAssignAppend(b *testing.B) {
	b.Run("Key=int32/Elem=[]int32", benchSizes(benchmarkMapAssignAppend[int32]))
	b.Run("Key=int64/Elem=[]int32", benchSizes(benchmarkMapAssignAppend[int64]))
	b.Run("Key=string/Elem=[]int32", benchSizes(benchmarkMapAssignAppend[string]))
}

func benchmarkMapDelete[K mapBenchmarkKeyType, E mapBenchmarkElemType](b *testing.B, n int) {
	if n == 0 {
		b.Skip("can't delete from empty map")
	}
	checkAllocSize[K, E](b, n)
	k := genValues[K](0, n)
	e := genValues[E](0, n)
	m := fillMap(k, e)
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		if len(m) == 0 {
			// We'd like to StopTimer while refilling the map, but
			// it is way too expensive and thus makes the benchmark
			// take a long time. See https://go.dev/issue/20875.
			for j := range k {
				m[k[j]] = e[j]
			}
		}
		delete(m, k[i%n])
	}
}

func BenchmarkMapDelete(b *testing.B) {
	b.Run("Key=int32/Elem=int32", benchSizes(benchmarkMapDelete[int32, int32]))
	b.Run("Key=int64/Elem=int64", benchSizes(benchmarkMapDelete[int64, int64]))
	b.Run("Key=string/Elem=string", benchSizes(benchmarkMapDelete[string, string]))
	b.Run("Key=smallType/Elem=int32", benchSizes(benchmarkMapDelete[smallType, int32]))
	b.Run("Key=mediumType/Elem=int32", benchSizes(benchmarkMapDelete[mediumType, int32]))
	b.Run("Key=bigType/Elem=int32", benchSizes(benchmarkMapDelete[bigType, int32]))
	b.Run("Key=bigType/Elem=bigType", benchSizes(benchmarkMapDelete[bigType, bigType]))
	b.Run("Key=int32/Elem=bigType", benchSizes(benchmarkMapDelete[int32, bigType]))
	b.Run("Key=*int32/Elem=int32", benchSizes(benchmarkMapDelete[*int32, int32]))
	b.Run("Key=int32/Elem=*int32", benchSizes(benchmarkMapDelete[int32, *int32]))
}

// Use iterator to pop an element. We want this to be fast, see
// https://go.dev/issue/8412.
func benchmarkMapPop[K mapBenchmarkKeyType, E mapBenchmarkElemType](b *testing.B, n int) {
	if n == 0 {
		b.Skip("can't delete from empty map")
	}
	checkAllocSize[K, E](b, n)
	k := genValues[K](0, n)
	e := genValues[E](0, n)
	m := fillMap(k, e)
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		if len(m) == 0 {
			// We'd like to StopTimer while refilling the map, but
			// it is way too expensive and thus makes the benchmark
			// take a long time. See https://go.dev/issue/20875.
			for j := range k {
				m[k[j]] = e[j]
			}
		}
		for key := range m {
			delete(m, key)
			break
		}
	}
}

func BenchmarkMapPop(b *testing.B) {
	b.Run("Key=int32/Elem=int32", benchSizes(benchmarkMapPop[int32, int32]))
	b.Run("Key=int64/Elem=int64", benchSizes(benchmarkMapPop[int64, int64]))
	b.Run("Key=string/Elem=string", benchSizes(benchmarkMapPop[string, string]))
	b.Run("Key=smallType/Elem=int32", benchSizes(benchmarkMapPop[smallType, int32]))
	b.Run("Key=mediumType/Elem=int32", benchSizes(benchmarkMapPop[mediumType, i
```