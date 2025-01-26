Response:
Let's break down the thought process for answering this request.

1. **Understanding the Core Request:** The request is to analyze the provided Go code snippet from `go/src/math/rand/v2/rand.go`. The key tasks are: listing functionalities, inferring and demonstrating Go feature usage, explaining code logic with examples, detailing command-line argument handling (if any), and pointing out common mistakes.

2. **Initial Code Scan - Identifying Key Structures:**  A quick skim of the code reveals the central components:
    * `Source` interface:  Represents the underlying random number generator.
    * `Rand` struct: Holds a `Source` and provides methods for generating various random number types.
    * Top-level functions:  Convenience functions that use a global `Rand` instance.

3. **Functionality Listing - Method by Method:**  Go through each function (method and top-level function) and describe its purpose. Focus on the input and output types and the general nature of the random number generated (e.g., `Int64` returns a 63-bit integer, `Float64` returns a float between 0 and 1). Pay attention to the constraints or panics, like in `IntN` where `n` must be positive.

4. **Inferring Go Feature Usage - `Source` and `Rand`:** The presence of the `Source` interface and the `Rand` struct that takes a `Source` in its `New` function immediately suggests the use of interfaces and dependency injection. This allows for different random number generation algorithms (implementations of `Source`) to be used with the same `Rand` methods. The top-level functions using `globalRand` hint at a default implementation.

5. **Go Feature Example - Demonstrating Interface Usage:**  To illustrate the interface, creating a custom `Source` is the most direct approach. Define a simple struct that implements the `Uint64()` method. Then, show how to create a `Rand` using this custom source. Provide example input (seeding) and expected output to make it concrete.

6. **Code Reasoning - `uint64n` (Crucial Part):** This function is the most complex and interesting. The comments within the code provide valuable clues. The explanation should focus on:
    * The problem: Generating uniform random numbers within a given range [0, n).
    * The challenge:  Simple modulo operation can introduce bias if `n` doesn't divide the range of the random number generator.
    * The solution:  Rejection sampling. The code attempts to generate a random number and rejects it if it falls within a specific range that would lead to bias.
    * Power of two optimization: A special case for when `n` is a power of two, allowing for a simple bitmask.
    * 32-bit optimization:  Explaining why there's a separate `uint32n` and how it mirrors the logic of `uint64n` while being optimized for 32-bit systems.

7. **Code Reasoning Example - `uint64n`:**
    * Provide an example where `n` is a power of two to show the simple masking.
    * Provide an example where `n` is *not* a power of two to illustrate the rejection sampling process. Explain the intuition behind the `thresh` value. Initially, I might just describe the rejection sampling, but the code comments specifically mention the double-width multiplication, so incorporating that adds detail.

8. **Command-Line Arguments:**  A careful reading of the code reveals no explicit command-line argument processing. Therefore, the answer should state this clearly.

9. **Common Mistakes:** The package documentation itself highlights a major point: **not for security-sensitive work**. This is the primary mistake users might make. The single-goroutine safety for `Source` and `Rand` is another important point to mention. Initially, I considered focusing on incorrect usage of `IntN` with negative numbers (since it panics), but the security aspect is a more fundamental concern.

10. **Structuring the Answer:** Organize the information logically with clear headings and subheadings. Use formatting (like code blocks) to improve readability.

11. **Language and Tone:** Use clear and concise Chinese. Explain technical concepts in a way that is understandable without being overly simplistic.

12. **Review and Refinement:**  After drafting the answer, review it for accuracy, completeness, and clarity. Ensure that the code examples are correct and that the explanations are easy to follow. For example, initially, my explanation of `uint64n` might have been too high-level, but by referencing the code comments and Lemire's blog posts, I could add more technical depth. Similarly, double-checking for explicit command-line argument handling is essential.
好的，让我们来分析一下 `go/src/math/rand/v2/rand.go` 这部分代码的功能。

**主要功能：**

这段 Go 代码实现了一个伪随机数生成器（PRNG）。它提供了生成各种类型的随机数的方法，适用于模拟等任务，但不适合用于安全敏感的场景。

**核心概念：**

* **`Source` 接口:** 定义了一个生成均匀分布的 `uint64` 伪随机数的接口。任何实现了 `Uint64()` 方法的类型都可以作为随机数的来源。`Source` 不是并发安全的。
* **`Rand` 结构体:**  包含一个 `Source` 实例，并提供了一系列方法，基于其 `Source` 生成不同类型的随机数（`int64`, `uint32`, `float64` 等）。`Rand` 实例也不是并发安全的。
* **顶层便利函数:**  例如 `rand.Int()`, `rand.Float64()` 等，这些函数使用一个全局的 `Rand` 实例（`globalRand`），是并发安全的。

**具体功能列表：**

1. **`Source` 接口:**
   - `Uint64() uint64`:  生成一个 `uint64` 类型的伪随机数。

2. **`Rand` 结构体及其方法:**
   - `New(src Source) *Rand`: 创建一个新的 `Rand` 实例，使用传入的 `Source` 作为随机数来源。
   - `Int64() int64`: 返回一个非负的 63 位伪随机 `int64`。
   - `Uint32() uint32`: 返回一个 32 位伪随机 `uint32`。
   - `Uint64() uint64`: 返回一个 64 位伪随机 `uint64`。
   - `Int32() int32`: 返回一个非负的 31 位伪随机 `int32`。
   - `Int() int`: 返回一个非负的伪随机 `int`。
   - `Uint() uint`: 返回一个伪随机 `uint`。
   - `Int64N(n int64) int64`: 返回一个在半开区间 `[0, n)` 内的非负伪随机 `int64`。如果 `n <= 0` 则 panic。
   - `Uint64N(n uint64) uint64`: 返回一个在半开区间 `[0, n)` 内的非负伪随机 `uint64`。如果 `n == 0` 则 panic。
   - `Int32N(n int32) int32`: 返回一个在半开区间 `[0, n)` 内的非负伪随机 `int32`。如果 `n <= 0` 则 panic。
   - `Uint32N(n uint32) uint32`: 返回一个在半开区间 `[0, n)` 内的非负伪随机 `uint32`。如果 `n == 0` 则 panic。
   - `IntN(n int) int`: 返回一个在半开区间 `[0, n)` 内的非负伪随机 `int`。如果 `n <= 0` 则 panic。
   - `UintN(n uint) uint`: 返回一个在半开区间 `[0, n)` 内的非负伪随机 `uint`。如果 `n == 0` 则 panic。
   - `Float64() float64`: 返回一个在半开区间 `[0.0, 1.0)` 内的伪随机 `float64`。
   - `Float32() float32`: 返回一个在半开区间 `[0.0, 1.0)` 内的伪随机 `float32`。
   - `Perm(n int) []int`: 返回一个包含 `[0, n)` 范围内整数的伪随机排列的切片。
   - `Shuffle(n int, swap func(i, j int))`:  对 `n` 个元素进行伪随机洗牌，使用提供的 `swap` 函数交换元素。如果 `n < 0` 则 panic。

3. **顶层便利函数 (使用 `globalRand`):**
   - `Int64() int64`
   - `Uint32() uint32`
   - `Uint64N(n uint64) uint64`
   - `Uint32N(n uint32) uint32`
   - `Uint64() uint64`
   - `Int32() int32`
   - `Int() int`
   - `Uint() uint`
   - `Int64N(n int64) int64`
   - `Int32N(n int32) int32`
   - `IntN(n int) int`
   - `UintN(n uint) uint`
   - `N[Int intType](n Int) Int`:  返回一个在半开区间 `[0, n)` 内的伪随机数，类型由泛型参数 `Int` 指定。
   - `Float64() float64`
   - `Float32() float32`
   - `Perm(n int) []int`
   - `Shuffle(n int, swap func(i, j int))`
   - `NormFloat64() float64`: 返回一个符合标准正态分布的 `float64`。
   - `ExpFloat64() float64`: 返回一个符合指数分布的 `float64`。

4. **`runtimeSource` 结构体:**
   - 实现了 `Source` 接口，其 `Uint64()` 方法调用了 `runtime.rand()` 函数，这是一个由 Go 运行时提供的快速随机数生成器。

**推断 Go 语言功能的实现并举例：**

这段代码主要展示了以下 Go 语言功能的实现：

* **接口 (`interface`):** `Source` 接口定义了生成随机数的规范，允许使用不同的随机数生成算法。
* **结构体 (`struct`):** `Rand` 用于封装随机数生成的状态和方法。
* **方法 (`method`):** `Rand` 结构体上定义了各种生成特定类型随机数的方法。
* **函数 (`func`):**  顶层的便利函数提供了更简洁的调用方式。
* **Panic:**  在参数不合法的情况下（例如 `IntN` 的 `n <= 0`），代码会调用 `panic` 来终止程序。
* **泛型 (`[Int intType]`):**  `N` 函数使用了泛型，使其可以生成多种整数类型的随机数，提高了代码的通用性。
* **位运算:**  在 `Int64`, `Uint32`, `Int` 等方法中，使用了位运算来从 `Source` 生成的 `uint64` 中提取或调整特定范围的随机数。
* **类型断言和类型转换:** 在 `N` 函数中，将 `uint64` 转换为泛型指定的整数类型 `Int`。

**Go 代码示例：**

```go
package main

import (
	"fmt"
	"math/rand/v2"
)

func main() {
	// 使用默认的随机数生成器
	fmt.Println("默认 Int:", rand.Int())
	fmt.Println("默认 Float64:", rand.Float64())
	fmt.Println("默认 IntN(10):", rand.IntN(10))

	// 创建自定义的 Source
	type MySource struct {
		seed uint64
	}

	func (s *MySource) Uint64() uint64 {
		s.seed = s.seed*1103515245 + 12345
		return s.seed
	}

	// 创建使用自定义 Source 的 Rand
	myRand := rand.New(&MySource{seed: 1})
	fmt.Println("自定义 Rand Int64:", myRand.Int64())
	fmt.Println("自定义 Rand Float32:", myRand.Float32())
	fmt.Println("自定义 Rand IntN(5):", myRand.IntN(5))

	// 使用泛型 N 函数
	var n16 int16 = 100
	randomInt16 := rand.N(n16)
	fmt.Printf("泛型 N 生成 int16: %T, %v\n", randomInt16, randomInt16)
}
```

**假设的输入与输出：**

由于是伪随机数生成器，输出是可预测的，但取决于初始状态（种子）。默认情况下，`globalRand` 的种子是变化的。自定义的 `MySource` 使用固定的初始种子，所以每次运行的输出是相同的。

**默认的随机数生成器：**

```
默认 Int: 8130396348002971820  // 输出会变化
默认 Float64: 0.3878101473038266  // 输出会变化
默认 IntN(10): 7             // 输出会变化
```

**自定义的随机数生成器：**

```
自定义 Rand Int64: 12346
自定义 Rand Float32: 0.5772617
自定义 Rand IntN(5): 1
```

**泛型 N 函数：**

```
泛型 N 生成 int16: int16, 38
```

**命令行参数的具体处理：**

这段代码本身**没有直接处理命令行参数**。 `math/rand/v2` 包主要提供生成随机数的功能，并不涉及命令行交互。如果你需要在命令行程序中使用随机数，你需要自己在你的程序中获取命令行参数（例如使用 `os.Args` 或 `flag` 包），然后利用 `math/rand/v2` 生成随机数。

**使用者易犯错的点：**

1. **不安全地用于安全敏感的场景：**  文档明确指出，这个包的随机数生成器是伪随机的，不适合用于加密、生成安全令牌等需要高安全性随机数的场景。应该使用 `crypto/rand` 包。

2. **在并发环境中使用 `Source` 或 `Rand` 而不进行同步：** `Source` 和 `Rand` 的文档说明它们不是并发安全的。如果在多个 Goroutine 中共享同一个 `Source` 或 `Rand` 实例，可能会导致数据竞争和不可预测的结果。应该使用顶层的便利函数，或者在共享时使用互斥锁等同步机制。

   ```go
   package main

   import (
       "fmt"
       "math/rand/v2"
       "sync"
   )

   func main() {
       var wg sync.WaitGroup
       r := rand.New(rand.NewSource(1)) // 注意：这里使用相同的 seed 以便观察问题

       for i := 0; i < 5; i++ {
           wg.Add(1)
           go func() {
               defer wg.Done()
               // 错误示例：并发访问同一个 Rand 实例
               fmt.Println(r.Intn(100))
           }()
       }
       wg.Wait()

       fmt.Println("--- 使用顶层函数 (安全) ---")
       for i := 0; i < 5; i++ {
           wg.Add(1)
           go func() {
               defer wg.Done()
               // 正确示例：使用顶层函数
               fmt.Println(rand.Intn(100))
           }()
       }
       wg.Wait()
   }
   ```

   在上面的错误示例中，多个 Goroutine 并发调用 `r.Intn(100)`，可能会导致 `r` 内部状态的竞争。使用顶层函数 `rand.Intn(100)` 是线程安全的，因为它内部使用了互斥锁来保护全局的 `globalRand` 实例。

3. **误解 `IntN` 等函数的行为：**  需要注意 `IntN(n)` 返回的是 `[0, n)` 半开区间内的随机数，不包括 `n`。如果需要生成 `[0, n]` 范围内的随机数，应该使用 `IntN(n+1)`。

4. **忘记设置种子 (`seed`):**  对于可重复的随机数序列，可以使用 `rand.NewSource(seed)` 创建 `Source`，并使用相同的种子初始化不同的 `Rand` 实例。如果不设置种子，或者使用默认的 `globalRand`，每次运行程序生成的随机数序列可能会不同。

希望这个详细的解释能够帮助你理解 `go/src/math/rand/v2/rand.go` 的功能和使用方法。

Prompt: 
```
这是路径为go/src/math/rand/v2/rand.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。

"""
// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package rand implements pseudo-random number generators suitable for tasks
// such as simulation, but it should not be used for security-sensitive work.
//
// Random numbers are generated by a [Source], usually wrapped in a [Rand].
// Both types should be used by a single goroutine at a time: sharing among
// multiple goroutines requires some kind of synchronization.
//
// Top-level functions, such as [Float64] and [Int],
// are safe for concurrent use by multiple goroutines.
//
// This package's outputs might be easily predictable regardless of how it's
// seeded. For random numbers suitable for security-sensitive work, see the
// [crypto/rand] package.
package rand

import (
	"math/bits"
	_ "unsafe" // for go:linkname
)

// A Source is a source of uniformly-distributed
// pseudo-random uint64 values in the range [0, 1<<64).
//
// A Source is not safe for concurrent use by multiple goroutines.
type Source interface {
	Uint64() uint64
}

// A Rand is a source of random numbers.
type Rand struct {
	src Source
}

// New returns a new Rand that uses random values from src
// to generate other random values.
func New(src Source) *Rand {
	return &Rand{src: src}
}

// Int64 returns a non-negative pseudo-random 63-bit integer as an int64.
func (r *Rand) Int64() int64 { return int64(r.src.Uint64() &^ (1 << 63)) }

// Uint32 returns a pseudo-random 32-bit value as a uint32.
func (r *Rand) Uint32() uint32 { return uint32(r.src.Uint64() >> 32) }

// Uint64 returns a pseudo-random 64-bit value as a uint64.
func (r *Rand) Uint64() uint64 { return r.src.Uint64() }

// Int32 returns a non-negative pseudo-random 31-bit integer as an int32.
func (r *Rand) Int32() int32 { return int32(r.src.Uint64() >> 33) }

// Int returns a non-negative pseudo-random int.
func (r *Rand) Int() int { return int(uint(r.src.Uint64()) << 1 >> 1) }

// Uint returns a pseudo-random uint.
func (r *Rand) Uint() uint { return uint(r.src.Uint64()) }

// Int64N returns, as an int64, a non-negative pseudo-random number in the half-open interval [0,n).
// It panics if n <= 0.
func (r *Rand) Int64N(n int64) int64 {
	if n <= 0 {
		panic("invalid argument to Int64N")
	}
	return int64(r.uint64n(uint64(n)))
}

// Uint64N returns, as a uint64, a non-negative pseudo-random number in the half-open interval [0,n).
// It panics if n == 0.
func (r *Rand) Uint64N(n uint64) uint64 {
	if n == 0 {
		panic("invalid argument to Uint64N")
	}
	return r.uint64n(n)
}

// uint64n is the no-bounds-checks version of Uint64N.
func (r *Rand) uint64n(n uint64) uint64 {
	if is32bit && uint64(uint32(n)) == n {
		return uint64(r.uint32n(uint32(n)))
	}
	if n&(n-1) == 0 { // n is power of two, can mask
		return r.Uint64() & (n - 1)
	}

	// Suppose we have a uint64 x uniform in the range [0,2⁶⁴)
	// and want to reduce it to the range [0,n) preserving exact uniformity.
	// We can simulate a scaling arbitrary precision x * (n/2⁶⁴) by
	// the high bits of a double-width multiply of x*n, meaning (x*n)/2⁶⁴.
	// Since there are 2⁶⁴ possible inputs x and only n possible outputs,
	// the output is necessarily biased if n does not divide 2⁶⁴.
	// In general (x*n)/2⁶⁴ = k for x*n in [k*2⁶⁴,(k+1)*2⁶⁴).
	// There are either floor(2⁶⁴/n) or ceil(2⁶⁴/n) possible products
	// in that range, depending on k.
	// But suppose we reject the sample and try again when
	// x*n is in [k*2⁶⁴, k*2⁶⁴+(2⁶⁴%n)), meaning rejecting fewer than n possible
	// outcomes out of the 2⁶⁴.
	// Now there are exactly floor(2⁶⁴/n) possible ways to produce
	// each output value k, so we've restored uniformity.
	// To get valid uint64 math, 2⁶⁴ % n = (2⁶⁴ - n) % n = -n % n,
	// so the direct implementation of this algorithm would be:
	//
	//	hi, lo := bits.Mul64(r.Uint64(), n)
	//	thresh := -n % n
	//	for lo < thresh {
	//		hi, lo = bits.Mul64(r.Uint64(), n)
	//	}
	//
	// That still leaves an expensive 64-bit division that we would rather avoid.
	// We know that thresh < n, and n is usually much less than 2⁶⁴, so we can
	// avoid the last four lines unless lo < n.
	//
	// See also:
	// https://lemire.me/blog/2016/06/27/a-fast-alternative-to-the-modulo-reduction
	// https://lemire.me/blog/2016/06/30/fast-random-shuffling
	hi, lo := bits.Mul64(r.Uint64(), n)
	if lo < n {
		thresh := -n % n
		for lo < thresh {
			hi, lo = bits.Mul64(r.Uint64(), n)
		}
	}
	return hi
}

// uint32n is an identical computation to uint64n
// but optimized for 32-bit systems.
func (r *Rand) uint32n(n uint32) uint32 {
	if n&(n-1) == 0 { // n is power of two, can mask
		return uint32(r.Uint64()) & (n - 1)
	}
	// On 64-bit systems we still use the uint64 code below because
	// the probability of a random uint64 lo being < a uint32 n is near zero,
	// meaning the unbiasing loop almost never runs.
	// On 32-bit systems, here we need to implement that same logic in 32-bit math,
	// both to preserve the exact output sequence observed on 64-bit machines
	// and to preserve the optimization that the unbiasing loop almost never runs.
	//
	// We want to compute
	// 	hi, lo := bits.Mul64(r.Uint64(), n)
	// In terms of 32-bit halves, this is:
	// 	x1:x0 := r.Uint64()
	// 	0:hi, lo1:lo0 := bits.Mul64(x1:x0, 0:n)
	// Writing out the multiplication in terms of bits.Mul32 allows
	// using direct hardware instructions and avoiding
	// the computations involving these zeros.
	x := r.Uint64()
	lo1a, lo0 := bits.Mul32(uint32(x), n)
	hi, lo1b := bits.Mul32(uint32(x>>32), n)
	lo1, c := bits.Add32(lo1a, lo1b, 0)
	hi += c
	if lo1 == 0 && lo0 < uint32(n) {
		n64 := uint64(n)
		thresh := uint32(-n64 % n64)
		for lo1 == 0 && lo0 < thresh {
			x := r.Uint64()
			lo1a, lo0 = bits.Mul32(uint32(x), n)
			hi, lo1b = bits.Mul32(uint32(x>>32), n)
			lo1, c = bits.Add32(lo1a, lo1b, 0)
			hi += c
		}
	}
	return hi
}

// Int32N returns, as an int32, a non-negative pseudo-random number in the half-open interval [0,n).
// It panics if n <= 0.
func (r *Rand) Int32N(n int32) int32 {
	if n <= 0 {
		panic("invalid argument to Int32N")
	}
	return int32(r.uint64n(uint64(n)))
}

// Uint32N returns, as a uint32, a non-negative pseudo-random number in the half-open interval [0,n).
// It panics if n == 0.
func (r *Rand) Uint32N(n uint32) uint32 {
	if n == 0 {
		panic("invalid argument to Uint32N")
	}
	return uint32(r.uint64n(uint64(n)))
}

const is32bit = ^uint(0)>>32 == 0

// IntN returns, as an int, a non-negative pseudo-random number in the half-open interval [0,n).
// It panics if n <= 0.
func (r *Rand) IntN(n int) int {
	if n <= 0 {
		panic("invalid argument to IntN")
	}
	return int(r.uint64n(uint64(n)))
}

// UintN returns, as a uint, a non-negative pseudo-random number in the half-open interval [0,n).
// It panics if n == 0.
func (r *Rand) UintN(n uint) uint {
	if n == 0 {
		panic("invalid argument to UintN")
	}
	return uint(r.uint64n(uint64(n)))
}

// Float64 returns, as a float64, a pseudo-random number in the half-open interval [0.0,1.0).
func (r *Rand) Float64() float64 {
	// There are exactly 1<<53 float64s in [0,1). Use Intn(1<<53) / (1<<53).
	return float64(r.Uint64()<<11>>11) / (1 << 53)
}

// Float32 returns, as a float32, a pseudo-random number in the half-open interval [0.0,1.0).
func (r *Rand) Float32() float32 {
	// There are exactly 1<<24 float32s in [0,1). Use Intn(1<<24) / (1<<24).
	return float32(r.Uint32()<<8>>8) / (1 << 24)
}

// Perm returns, as a slice of n ints, a pseudo-random permutation of the integers
// in the half-open interval [0,n).
func (r *Rand) Perm(n int) []int {
	p := make([]int, n)
	for i := range p {
		p[i] = i
	}
	r.Shuffle(len(p), func(i, j int) { p[i], p[j] = p[j], p[i] })
	return p
}

// Shuffle pseudo-randomizes the order of elements.
// n is the number of elements. Shuffle panics if n < 0.
// swap swaps the elements with indexes i and j.
func (r *Rand) Shuffle(n int, swap func(i, j int)) {
	if n < 0 {
		panic("invalid argument to Shuffle")
	}

	// Fisher-Yates shuffle: https://en.wikipedia.org/wiki/Fisher%E2%80%93Yates_shuffle
	// Shuffle really ought not be called with n that doesn't fit in 32 bits.
	// Not only will it take a very long time, but with 2³¹! possible permutations,
	// there's no way that any PRNG can have a big enough internal state to
	// generate even a minuscule percentage of the possible permutations.
	// Nevertheless, the right API signature accepts an int n, so handle it as best we can.
	for i := n - 1; i > 0; i-- {
		j := int(r.uint64n(uint64(i + 1)))
		swap(i, j)
	}
}

/*
 * Top-level convenience functions
 */

// globalRand is the source of random numbers for the top-level
// convenience functions.
var globalRand = &Rand{src: runtimeSource{}}

//go:linkname runtime_rand runtime.rand
func runtime_rand() uint64

// runtimeSource is a Source that uses the runtime fastrand functions.
type runtimeSource struct{}

func (runtimeSource) Uint64() uint64 {
	return runtime_rand()
}

// Int64 returns a non-negative pseudo-random 63-bit integer as an int64
// from the default Source.
func Int64() int64 { return globalRand.Int64() }

// Uint32 returns a pseudo-random 32-bit value as a uint32
// from the default Source.
func Uint32() uint32 { return globalRand.Uint32() }

// Uint64N returns, as a uint64, a pseudo-random number in the half-open interval [0,n)
// from the default Source.
// It panics if n == 0.
func Uint64N(n uint64) uint64 { return globalRand.Uint64N(n) }

// Uint32N returns, as a uint32, a pseudo-random number in the half-open interval [0,n)
// from the default Source.
// It panics if n == 0.
func Uint32N(n uint32) uint32 { return globalRand.Uint32N(n) }

// Uint64 returns a pseudo-random 64-bit value as a uint64
// from the default Source.
func Uint64() uint64 { return globalRand.Uint64() }

// Int32 returns a non-negative pseudo-random 31-bit integer as an int32
// from the default Source.
func Int32() int32 { return globalRand.Int32() }

// Int returns a non-negative pseudo-random int from the default Source.
func Int() int { return globalRand.Int() }

// Uint returns a pseudo-random uint from the default Source.
func Uint() uint { return globalRand.Uint() }

// Int64N returns, as an int64, a pseudo-random number in the half-open interval [0,n)
// from the default Source.
// It panics if n <= 0.
func Int64N(n int64) int64 { return globalRand.Int64N(n) }

// Int32N returns, as an int32, a pseudo-random number in the half-open interval [0,n)
// from the default Source.
// It panics if n <= 0.
func Int32N(n int32) int32 { return globalRand.Int32N(n) }

// IntN returns, as an int, a pseudo-random number in the half-open interval [0,n)
// from the default Source.
// It panics if n <= 0.
func IntN(n int) int { return globalRand.IntN(n) }

// UintN returns, as a uint, a pseudo-random number in the half-open interval [0,n)
// from the default Source.
// It panics if n == 0.
func UintN(n uint) uint { return globalRand.UintN(n) }

// N returns a pseudo-random number in the half-open interval [0,n) from the default Source.
// The type parameter Int can be any integer type.
// It panics if n <= 0.
func N[Int intType](n Int) Int {
	if n <= 0 {
		panic("invalid argument to N")
	}
	return Int(globalRand.uint64n(uint64(n)))
}

type intType interface {
	~int | ~int8 | ~int16 | ~int32 | ~int64 |
		~uint | ~uint8 | ~uint16 | ~uint32 | ~uint64 | ~uintptr
}

// Float64 returns, as a float64, a pseudo-random number in the half-open interval [0.0,1.0)
// from the default Source.
func Float64() float64 { return globalRand.Float64() }

// Float32 returns, as a float32, a pseudo-random number in the half-open interval [0.0,1.0)
// from the default Source.
func Float32() float32 { return globalRand.Float32() }

// Perm returns, as a slice of n ints, a pseudo-random permutation of the integers
// in the half-open interval [0,n) from the default Source.
func Perm(n int) []int { return globalRand.Perm(n) }

// Shuffle pseudo-randomizes the order of elements using the default Source.
// n is the number of elements. Shuffle panics if n < 0.
// swap swaps the elements with indexes i and j.
func Shuffle(n int, swap func(i, j int)) { globalRand.Shuffle(n, swap) }

// NormFloat64 returns a normally distributed float64 in the range
// [-math.MaxFloat64, +math.MaxFloat64] with
// standard normal distribution (mean = 0, stddev = 1)
// from the default Source.
// To produce a different normal distribution, callers can
// adjust the output using:
//
//	sample = NormFloat64() * desiredStdDev + desiredMean
func NormFloat64() float64 { return globalRand.NormFloat64() }

// ExpFloat64 returns an exponentially distributed float64 in the range
// (0, +math.MaxFloat64] with an exponential distribution whose rate parameter
// (lambda) is 1 and whose mean is 1/lambda (1) from the default Source.
// To produce a distribution with a different rate parameter,
// callers can adjust the output using:
//
//	sample = ExpFloat64() / desiredRateParameter
func ExpFloat64() float64 { return globalRand.ExpFloat64() }

"""



```