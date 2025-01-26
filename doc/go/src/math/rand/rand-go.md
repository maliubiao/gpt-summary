Response:
Let's break down the thought process for analyzing the provided Go code snippet for `math/rand/rand.go`.

**1. Understanding the Goal:**

The core request is to understand the *functionality* of this code. This means identifying what it does, how it's used, and any important considerations for developers.

**2. Initial Scan and Keyword Recognition:**

A quick skim reveals important keywords and concepts:

* `package rand`:  Indicates this is the standard library's pseudo-random number generation package.
* `pseudo-random`:  Highlights that these numbers are not truly random, but generated algorithmically. This immediately suggests limitations for security-sensitive applications.
* `Source`, `Rand`: These appear to be core interfaces/structs related to random number generation. Understanding their relationship is key.
* `Seed`:  This is related to initializing the random number generator.
* `Int`, `Float`, `Perm`, `Shuffle`, `Read`: These are methods for generating different types of random values.
* `concurrent`, `goroutine`, `sync`:  These terms indicate considerations for multi-threaded usage.
* `top-level functions`:  These seem to be convenience functions that are safe for concurrent use.
* `crypto/rand`:  This is a crucial comparison point, emphasizing the non-cryptographically secure nature of `math/rand`.
* `GODEBUG`:  Indicates runtime configuration options.

**3. Deconstructing Key Components:**

Now, let's focus on the main building blocks:

* **`Source` Interface:**  This defines the basic contract for a random number generator: producing 63-bit integers and being seedable. The `Source64` extension adds the ability to generate 64-bit unsigned integers directly. This is a good starting point for understanding the underlying mechanisms.

* **`Rand` Struct:**  This appears to be a higher-level object that uses a `Source` to generate various types of random numbers. The `readVal` and `readPos` fields likely relate to efficiently generating random bytes.

* **`NewSource` and `New` Functions:**  These are constructors for creating `Source` and `Rand` instances, respectively.

* **Random Number Generation Methods (`Int63`, `Uint32`, `Float64`, etc.):**  Analyze how these methods are implemented. Notice the common pattern of calling `Int63` as the base for other integer types and how floating-point numbers are derived. The comments about maintaining Go 1 compatibility are important.

* **Concurrency Aspects:**  Pay attention to the comments about thread safety. `Source` and `Rand` instances are *not* safe for concurrent use by default. The top-level functions are an exception. The `lockedSource` struct and the mutex in `runtimeSource` are related to managing concurrency.

* **Top-Level Functions:**  Understand that these functions use a global `Rand` instance, and how that instance is initialized (lazy initialization, `GODEBUG` options).

* **`Seed` Function:**  Examine the logic for seeding, especially the distinctions between the top-level `Seed` and the `Rand.Seed` method, and the impact of `GODEBUG`. The deprecation notice is also important.

**4. Identifying Functionality Categories:**

Based on the deconstruction, we can categorize the functionality:

* **Core Random Number Generation:**  Providing basic integer and floating-point random numbers.
* **Seeding:**  Controlling the initial state of the generator.
* **Concurrency Management:**  Handling multi-threaded access.
* **Higher-Level Utilities:**  Functions like `Perm` and `Shuffle`.
* **Byte Generation:**  The `Read` method.
* **Global Convenience Functions:**  Easier access to random numbers.

**5. Code Examples and Reasoning:**

For each category, think of simple use cases and write illustrative Go code. Crucially, explain *why* the code works as it does, referencing the underlying mechanisms (e.g., how `Intn` uses `Int31n` or `Int63n`). For code involving choices (like `NewSource` vs. top-level functions), explain the trade-offs (e.g., concurrency safety).

**6. Input/Output and Assumptions:**

When providing code examples, be explicit about the expected input and output. For instance, when demonstrating `Intn(10)`, state that the output will be between 0 and 9. Make any necessary assumptions clear (e.g., "assuming the default seed").

**7. Command-Line Parameters (GODEBUG):**

Focus on the `GODEBUG` variables mentioned in the code (`randautoseed`, `randseednop`). Explain what they control and how they affect the package's behavior.

**8. Common Mistakes:**

Think about how developers might misuse this package:

* Using `Rand` or `Source` concurrently without synchronization.
* Assuming `math/rand` is suitable for cryptographic purposes.
* Not understanding the impact of seeding (or not seeding).
* Being unaware of the differences between top-level functions and `Rand` instances.

**9. Structuring the Answer:**

Organize the information logically with clear headings and bullet points. Start with a high-level overview and then delve into specifics. Use code blocks for examples and provide explanations for each point. Use clear and concise language.

**Self-Correction/Refinement during the process:**

* **Initial thought:**  Focusing too much on the low-level details of the random number generation algorithms.
* **Correction:** Realize the request is about the *functionality* and usage, so focus on the API and how developers interact with it.
* **Initial thought:**  Not clearly distinguishing between `Source`, `Rand`, and the top-level functions.
* **Correction:** Explicitly explain the relationships and differences between these components.
* **Initial thought:**  Forgetting to mention the `GODEBUG` variables.
* **Correction:**  Add a section specifically addressing command-line parameters.
* **Initial thought:**  Not providing enough concrete code examples.
* **Correction:**  Develop more examples to illustrate key functionalities.

By following this structured thought process, we can effectively analyze the provided Go code and provide a comprehensive and informative answer.
这段代码是 Go 语言标准库 `math/rand` 包的一部分，它实现了伪随机数生成器的功能。这个包提供了生成各种随机数的方法，适用于模拟等非安全敏感的任务。

**主要功能列举：**

1. **提供伪随机数生成的基础接口 `Source` 和 `Source64`:**
   - `Source` 定义了生成 `int64` 类型伪随机数的标准。
   - `Source64` 扩展了 `Source` 接口，增加了直接生成 `uint64` 类型伪随机数的能力。

2. **提供 `Rand` 类型用于生成各种类型的随机数:**
   - `Rand` 结构体包含一个 `Source`，并基于它提供生成 `int64`, `uint32`, `uint64`, `int32`, `int`, `float64`, `float32` 等类型随机数的方法。
   - `Rand` 也提供了生成指定范围内的随机数（如 `Intn`, `Int63n`, `Int31n`），随机排列 (`Perm`) 和随机打乱 (`Shuffle`) 的功能。
   - `Rand` 可以通过 `Seed` 方法设置种子，从而控制生成的随机数序列。

3. **提供便捷的顶层函数 (Top-level functions) 用于生成随机数:**
   - 这些函数（如 `Float64`, `Int`, `Read` 等）使用一个全局的 `Rand` 实例，方便在不创建 `Rand` 对象的情况下直接生成随机数。
   - **顶层函数是并发安全的。**

4. **提供设置随机数生成器种子的方法 `Seed`:**
   - 顶层的 `Seed` 函数用于设置全局随机数生成器的种子。
   - `Rand` 类型的 `Seed` 方法用于设置特定 `Rand` 实例的种子。

5. **提供生成随机字节的方法 `Read`:**
   - `Rand` 类型的 `Read` 方法填充给定的字节切片为随机字节。
   - 顶层的 `Read` 函数也提供了类似的功能。

6. **提供创建新的 `Source` 和 `Rand` 的方法 `NewSource` 和 `New`:**
   - `NewSource` 使用给定的种子创建一个新的、独立的 `Source`。
   - `New` 使用一个已有的 `Source` 创建一个新的 `Rand` 实例。

7. **内部使用 `runtimeSource` 利用 Go 运行时的快速随机数生成功能:**
   - 在没有显式调用 `Seed` 的情况下，顶层函数会使用 `runtimeSource`，它利用运行时的 `runtime_rand` 函数来提高性能。

8. **通过 `lockedSource` 实现并发安全的 `Source`:**
   - 当需要并发安全地使用 `Source` 时，可以使用 `lockedSource` 对底层的 `Source` 进行加锁保护。

**它是什么 Go 语言功能的实现？**

这段代码是 Go 语言标准库中**伪随机数生成**功能的实现。它不是加密安全的随机数生成器（应该使用 `crypto/rand` 包）。`math/rand` 适用于模拟、游戏、测试等场景，在这些场景中，可重复的随机数序列（通过设置相同的种子）有时是期望的。

**Go 代码示例说明：**

```go
package main

import (
	"fmt"
	"math/rand"
	"time"
)

func main() {
	// 使用顶层函数生成随机数
	fmt.Println("顶层函数生成的随机整数:", rand.Intn(100)) // 生成 0 到 99 的随机整数
	fmt.Println("顶层函数生成的随机浮点数:", rand.Float64()) // 生成 0.0 到 1.0 的随机浮点数

	// 使用 NewSource 创建一个新的 Source 并设置种子
	source := rand.NewSource(time.Now().UnixNano())
	// 使用 New 基于 Source 创建 Rand
	r := rand.New(source)
	fmt.Println("使用 New 创建的 Rand 生成的随机整数:", r.Intn(100))

	// 设置 Rand 的种子
	r.Seed(42)
	fmt.Println("设置种子后的 Rand 生成的第一个随机整数:", r.Intn(100))

	// 再次使用相同的种子，会生成相同的序列
	r2 := rand.New(rand.NewSource(42))
	fmt.Println("使用相同种子生成的 Rand 的第一个随机整数:", r2.Intn(100))

	// 生成随机字节
	b := make([]byte, 10)
	n, err := rand.Read(b)
	if err != nil {
		fmt.Println("生成随机字节失败:", err)
	} else {
		fmt.Printf("生成的 %d 个随机字节: %v\n", n, b)
	}

	// 并发使用顶层函数是安全的
	go func() {
		fmt.Println("goroutine 中顶层函数生成的随机数:", rand.Intn(100))
	}()

	// 并发使用同一个 Rand 实例是不安全的，需要同步
	r3 := rand.New(rand.NewSource(time.Now().UnixNano()))
	var ch = make(chan int)
	go func() {
		// 这里只是演示，实际使用需要更严谨的同步机制，例如互斥锁
		ch <- r3.Intn(100)
	}()
	fmt.Println("并发中使用 Rand 生成的随机数 (非线程安全，仅作演示):", <-ch)
}
```

**假设的输入与输出：**

由于是随机数生成，每次运行的输出都会不同，但以下是一些可能的输出示例：

```
顶层函数生成的随机整数: 56
顶层函数生成的随机浮点数: 0.8765432109876543
使用 New 创建的 Rand 生成的随机整数: 23
设置种子后的 Rand 生成的第一个随机整数: 92
使用相同种子生成的 Rand 的第一个随机整数: 92
生成的 10 个随机字节: [17 203 14 87 231 119 169 134 182 156]
goroutine 中顶层函数生成的随机数: 78
并发中使用 Rand 生成的随机数 (非线程安全，仅作演示): 45
```

**使用者易犯错的点：**

1. **将 `math/rand` 用于安全敏感的场景：**  `math/rand` 生成的是伪随机数，其序列是可预测的，不应用于加密、生成安全令牌等需要高度随机性的场景。应该使用 `crypto/rand` 包。

   ```go
   // 错误示例：不应该用于生成密钥
   // import "math/rand"
   // key := make([]byte, 32)
   // rand.Read(key)
   ```

2. **在并发环境下不正确地使用 `Rand` 实例：**  `Rand` 结构体的设计不是并发安全的。多个 goroutine 同时调用同一个 `Rand` 实例的方法可能导致数据竞争和不可预测的结果。

   ```go
   // 错误示例：并发访问同一个 Rand 实例
   // r := rand.New(rand.NewSource(time.Now().UnixNano()))
   // var wg sync.WaitGroup
   // for i := 0; i < 10; i++ {
   // 	wg.Add(1)
   // 	go func() {
   // 		defer wg.Done()
   // 		fmt.Println(r.Intn(100)) // 可能存在数据竞争
   // 	}()
   // }
   // wg.Wait()
   ```

   **解决方法：**
   - 使用顶层函数，它们是并发安全的。
   - 为每个 goroutine 创建独立的 `Rand` 实例。
   - 使用互斥锁 (`sync.Mutex`) 或其他同步机制保护对共享 `Rand` 实例的访问。

3. **误解 `Seed` 的作用：**  `Seed` 函数用于初始化随机数生成器的状态。使用相同的种子会生成相同的随机数序列。在开发和测试中，这可能很有用，但在生产环境中，通常希望生成不同的随机数序列，因此需要使用不同的种子，例如基于当前时间。

   ```go
   // 错误示例：始终使用相同的固定种子，导致每次运行生成相同的随机数序列
   // rand.Seed(42)
   // fmt.Println(rand.Intn(10)) // 每次运行结果都一样
   ```

4. **忘记初始化种子：** 如果不调用 `Seed`，Go 1.20 之前的版本会默认使用种子 `1`，导致每次程序启动时生成相同的随机数序列。Go 1.20 及以后版本会随机初始化种子。为了确保每次运行都生成不同的随机数序列，通常会使用当前时间作为种子。

   ```go
   // 推荐做法：使用当前时间作为种子
   rand.Seed(time.Now().UnixNano())
   ```

这段代码是 `math/rand` 包的核心，它定义了生成伪随机数的基础结构和方法，为 Go 语言程序提供了方便的随机数生成能力。理解其功能和使用注意事项对于编写可靠的 Go 程序至关重要。

Prompt: 
```
这是路径为go/src/math/rand/rand.go的go语言实现的一部分， 请列举一下它的功能, 　
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
// crypto/rand package.
package rand

import (
	"internal/godebug"
	"sync"
	"sync/atomic"
	_ "unsafe" // for go:linkname
)

// A Source represents a source of uniformly-distributed
// pseudo-random int64 values in the range [0, 1<<63).
//
// A Source is not safe for concurrent use by multiple goroutines.
type Source interface {
	Int63() int64
	Seed(seed int64)
}

// A Source64 is a [Source] that can also generate
// uniformly-distributed pseudo-random uint64 values in
// the range [0, 1<<64) directly.
// If a [Rand] r's underlying [Source] s implements Source64,
// then r.Uint64 returns the result of one call to s.Uint64
// instead of making two calls to s.Int63.
type Source64 interface {
	Source
	Uint64() uint64
}

// NewSource returns a new pseudo-random [Source] seeded with the given value.
// Unlike the default [Source] used by top-level functions, this source is not
// safe for concurrent use by multiple goroutines.
// The returned [Source] implements [Source64].
func NewSource(seed int64) Source {
	return newSource(seed)
}

func newSource(seed int64) *rngSource {
	var rng rngSource
	rng.Seed(seed)
	return &rng
}

// A Rand is a source of random numbers.
type Rand struct {
	src Source
	s64 Source64 // non-nil if src is source64

	// readVal contains remainder of 63-bit integer used for bytes
	// generation during most recent Read call.
	// It is saved so next Read call can start where the previous
	// one finished.
	readVal int64
	// readPos indicates the number of low-order bytes of readVal
	// that are still valid.
	readPos int8
}

// New returns a new [Rand] that uses random values from src
// to generate other random values.
func New(src Source) *Rand {
	s64, _ := src.(Source64)
	return &Rand{src: src, s64: s64}
}

// Seed uses the provided seed value to initialize the generator to a deterministic state.
// Seed should not be called concurrently with any other [Rand] method.
func (r *Rand) Seed(seed int64) {
	if lk, ok := r.src.(*lockedSource); ok {
		lk.seedPos(seed, &r.readPos)
		return
	}

	r.src.Seed(seed)
	r.readPos = 0
}

// Int63 returns a non-negative pseudo-random 63-bit integer as an int64.
func (r *Rand) Int63() int64 { return r.src.Int63() }

// Uint32 returns a pseudo-random 32-bit value as a uint32.
func (r *Rand) Uint32() uint32 { return uint32(r.Int63() >> 31) }

// Uint64 returns a pseudo-random 64-bit value as a uint64.
func (r *Rand) Uint64() uint64 {
	if r.s64 != nil {
		return r.s64.Uint64()
	}
	return uint64(r.Int63())>>31 | uint64(r.Int63())<<32
}

// Int31 returns a non-negative pseudo-random 31-bit integer as an int32.
func (r *Rand) Int31() int32 { return int32(r.Int63() >> 32) }

// Int returns a non-negative pseudo-random int.
func (r *Rand) Int() int {
	u := uint(r.Int63())
	return int(u << 1 >> 1) // clear sign bit if int == int32
}

// Int63n returns, as an int64, a non-negative pseudo-random number in the half-open interval [0,n).
// It panics if n <= 0.
func (r *Rand) Int63n(n int64) int64 {
	if n <= 0 {
		panic("invalid argument to Int63n")
	}
	if n&(n-1) == 0 { // n is power of two, can mask
		return r.Int63() & (n - 1)
	}
	max := int64((1 << 63) - 1 - (1<<63)%uint64(n))
	v := r.Int63()
	for v > max {
		v = r.Int63()
	}
	return v % n
}

// Int31n returns, as an int32, a non-negative pseudo-random number in the half-open interval [0,n).
// It panics if n <= 0.
func (r *Rand) Int31n(n int32) int32 {
	if n <= 0 {
		panic("invalid argument to Int31n")
	}
	if n&(n-1) == 0 { // n is power of two, can mask
		return r.Int31() & (n - 1)
	}
	max := int32((1 << 31) - 1 - (1<<31)%uint32(n))
	v := r.Int31()
	for v > max {
		v = r.Int31()
	}
	return v % n
}

// int31n returns, as an int32, a non-negative pseudo-random number in the half-open interval [0,n).
// n must be > 0, but int31n does not check this; the caller must ensure it.
// int31n exists because Int31n is inefficient, but Go 1 compatibility
// requires that the stream of values produced by math/rand remain unchanged.
// int31n can thus only be used internally, by newly introduced APIs.
//
// For implementation details, see:
// https://lemire.me/blog/2016/06/27/a-fast-alternative-to-the-modulo-reduction
// https://lemire.me/blog/2016/06/30/fast-random-shuffling
func (r *Rand) int31n(n int32) int32 {
	v := r.Uint32()
	prod := uint64(v) * uint64(n)
	low := uint32(prod)
	if low < uint32(n) {
		thresh := uint32(-n) % uint32(n)
		for low < thresh {
			v = r.Uint32()
			prod = uint64(v) * uint64(n)
			low = uint32(prod)
		}
	}
	return int32(prod >> 32)
}

// Intn returns, as an int, a non-negative pseudo-random number in the half-open interval [0,n).
// It panics if n <= 0.
func (r *Rand) Intn(n int) int {
	if n <= 0 {
		panic("invalid argument to Intn")
	}
	if n <= 1<<31-1 {
		return int(r.Int31n(int32(n)))
	}
	return int(r.Int63n(int64(n)))
}

// Float64 returns, as a float64, a pseudo-random number in the half-open interval [0.0,1.0).
func (r *Rand) Float64() float64 {
	// A clearer, simpler implementation would be:
	//	return float64(r.Int63n(1<<53)) / (1<<53)
	// However, Go 1 shipped with
	//	return float64(r.Int63()) / (1 << 63)
	// and we want to preserve that value stream.
	//
	// There is one bug in the value stream: r.Int63() may be so close
	// to 1<<63 that the division rounds up to 1.0, and we've guaranteed
	// that the result is always less than 1.0.
	//
	// We tried to fix this by mapping 1.0 back to 0.0, but since float64
	// values near 0 are much denser than near 1, mapping 1 to 0 caused
	// a theoretically significant overshoot in the probability of returning 0.
	// Instead of that, if we round up to 1, just try again.
	// Getting 1 only happens 1/2⁵³ of the time, so most clients
	// will not observe it anyway.
again:
	f := float64(r.Int63()) / (1 << 63)
	if f == 1 {
		goto again // resample; this branch is taken O(never)
	}
	return f
}

// Float32 returns, as a float32, a pseudo-random number in the half-open interval [0.0,1.0).
func (r *Rand) Float32() float32 {
	// Same rationale as in Float64: we want to preserve the Go 1 value
	// stream except we want to fix it not to return 1.0
	// This only happens 1/2²⁴ of the time (plus the 1/2⁵³ of the time in Float64).
again:
	f := float32(r.Float64())
	if f == 1 {
		goto again // resample; this branch is taken O(very rarely)
	}
	return f
}

// Perm returns, as a slice of n ints, a pseudo-random permutation of the integers
// in the half-open interval [0,n).
func (r *Rand) Perm(n int) []int {
	m := make([]int, n)
	// In the following loop, the iteration when i=0 always swaps m[0] with m[0].
	// A change to remove this useless iteration is to assign 1 to i in the init
	// statement. But Perm also effects r. Making this change will affect
	// the final state of r. So this change can't be made for compatibility
	// reasons for Go 1.
	for i := 0; i < n; i++ {
		j := r.Intn(i + 1)
		m[i] = m[j]
		m[j] = i
	}
	return m
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
	i := n - 1
	for ; i > 1<<31-1-1; i-- {
		j := int(r.Int63n(int64(i + 1)))
		swap(i, j)
	}
	for ; i > 0; i-- {
		j := int(r.int31n(int32(i + 1)))
		swap(i, j)
	}
}

// Read generates len(p) random bytes and writes them into p. It
// always returns len(p) and a nil error.
// Read should not be called concurrently with any other Rand method.
func (r *Rand) Read(p []byte) (n int, err error) {
	switch src := r.src.(type) {
	case *lockedSource:
		return src.read(p, &r.readVal, &r.readPos)
	case *runtimeSource:
		return src.read(p, &r.readVal, &r.readPos)
	}
	return read(p, r.src, &r.readVal, &r.readPos)
}

func read(p []byte, src Source, readVal *int64, readPos *int8) (n int, err error) {
	pos := *readPos
	val := *readVal
	rng, _ := src.(*rngSource)
	for n = 0; n < len(p); n++ {
		if pos == 0 {
			if rng != nil {
				val = rng.Int63()
			} else {
				val = src.Int63()
			}
			pos = 7
		}
		p[n] = byte(val)
		val >>= 8
		pos--
	}
	*readPos = pos
	*readVal = val
	return
}

/*
 * Top-level convenience functions
 */

// globalRandGenerator is the source of random numbers for the top-level
// convenience functions. When possible it uses the runtime fastrand64
// function to avoid locking. This is not possible if the user called Seed,
// either explicitly or implicitly via GODEBUG=randautoseed=0.
var globalRandGenerator atomic.Pointer[Rand]

var randautoseed = godebug.New("randautoseed")

// randseednop controls whether the global Seed is a no-op.
var randseednop = godebug.New("randseednop")

// globalRand returns the generator to use for the top-level convenience
// functions.
func globalRand() *Rand {
	if r := globalRandGenerator.Load(); r != nil {
		return r
	}

	// This is the first call. Initialize based on GODEBUG.
	var r *Rand
	if randautoseed.Value() == "0" {
		randautoseed.IncNonDefault()
		r = New(new(lockedSource))
		r.Seed(1)
	} else {
		r = &Rand{
			src: &runtimeSource{},
			s64: &runtimeSource{},
		}
	}

	if !globalRandGenerator.CompareAndSwap(nil, r) {
		// Two different goroutines called some top-level
		// function at the same time. While the results in
		// that case are unpredictable, if we just use r here,
		// and we are using a seed, we will most likely return
		// the same value for both calls. That doesn't seem ideal.
		// Just use the first one to get in.
		return globalRandGenerator.Load()
	}

	return r
}

//go:linkname runtime_rand runtime.rand
func runtime_rand() uint64

// runtimeSource is an implementation of Source64 that uses the runtime
// fastrand functions.
type runtimeSource struct {
	// The mutex is used to avoid race conditions in Read.
	mu sync.Mutex
}

func (*runtimeSource) Int63() int64 {
	return int64(runtime_rand() & rngMask)
}

func (*runtimeSource) Seed(int64) {
	panic("internal error: call to runtimeSource.Seed")
}

func (*runtimeSource) Uint64() uint64 {
	return runtime_rand()
}

func (fs *runtimeSource) read(p []byte, readVal *int64, readPos *int8) (n int, err error) {
	fs.mu.Lock()
	n, err = read(p, fs, readVal, readPos)
	fs.mu.Unlock()
	return
}

// Seed uses the provided seed value to initialize the default Source to a
// deterministic state. Seed values that have the same remainder when
// divided by 2³¹-1 generate the same pseudo-random sequence.
// Seed, unlike the [Rand.Seed] method, is safe for concurrent use.
//
// If Seed is not called, the generator is seeded randomly at program startup.
//
// Prior to Go 1.20, the generator was seeded like Seed(1) at program startup.
// To force the old behavior, call Seed(1) at program startup.
// Alternately, set GODEBUG=randautoseed=0 in the environment
// before making any calls to functions in this package.
//
// Deprecated: As of Go 1.20 there is no reason to call Seed with
// a random value. Programs that call Seed with a known value to get
// a specific sequence of results should use New(NewSource(seed)) to
// obtain a local random generator.
//
// As of Go 1.24 [Seed] is a no-op. To restore the previous behavior set
// GODEBUG=randseednop=0.
func Seed(seed int64) {
	if randseednop.Value() != "0" {
		return
	}
	randseednop.IncNonDefault()

	orig := globalRandGenerator.Load()

	// If we are already using a lockedSource, we can just re-seed it.
	if orig != nil {
		if _, ok := orig.src.(*lockedSource); ok {
			orig.Seed(seed)
			return
		}
	}

	// Otherwise either
	// 1) orig == nil, which is the normal case when Seed is the first
	// top-level function to be called, or
	// 2) orig is already a runtimeSource, in which case we need to change
	// to a lockedSource.
	// Either way we do the same thing.

	r := New(new(lockedSource))
	r.Seed(seed)

	if !globalRandGenerator.CompareAndSwap(orig, r) {
		// Something changed underfoot. Retry to be safe.
		Seed(seed)
	}
}

// Int63 returns a non-negative pseudo-random 63-bit integer as an int64
// from the default [Source].
func Int63() int64 { return globalRand().Int63() }

// Uint32 returns a pseudo-random 32-bit value as a uint32
// from the default [Source].
func Uint32() uint32 { return globalRand().Uint32() }

// Uint64 returns a pseudo-random 64-bit value as a uint64
// from the default [Source].
func Uint64() uint64 { return globalRand().Uint64() }

// Int31 returns a non-negative pseudo-random 31-bit integer as an int32
// from the default [Source].
func Int31() int32 { return globalRand().Int31() }

// Int returns a non-negative pseudo-random int from the default [Source].
func Int() int { return globalRand().Int() }

// Int63n returns, as an int64, a non-negative pseudo-random number in the half-open interval [0,n)
// from the default [Source].
// It panics if n <= 0.
func Int63n(n int64) int64 { return globalRand().Int63n(n) }

// Int31n returns, as an int32, a non-negative pseudo-random number in the half-open interval [0,n)
// from the default [Source].
// It panics if n <= 0.
func Int31n(n int32) int32 { return globalRand().Int31n(n) }

// Intn returns, as an int, a non-negative pseudo-random number in the half-open interval [0,n)
// from the default [Source].
// It panics if n <= 0.
func Intn(n int) int { return globalRand().Intn(n) }

// Float64 returns, as a float64, a pseudo-random number in the half-open interval [0.0,1.0)
// from the default [Source].
func Float64() float64 { return globalRand().Float64() }

// Float32 returns, as a float32, a pseudo-random number in the half-open interval [0.0,1.0)
// from the default [Source].
func Float32() float32 { return globalRand().Float32() }

// Perm returns, as a slice of n ints, a pseudo-random permutation of the integers
// in the half-open interval [0,n) from the default [Source].
func Perm(n int) []int { return globalRand().Perm(n) }

// Shuffle pseudo-randomizes the order of elements using the default [Source].
// n is the number of elements. Shuffle panics if n < 0.
// swap swaps the elements with indexes i and j.
func Shuffle(n int, swap func(i, j int)) { globalRand().Shuffle(n, swap) }

// Read generates len(p) random bytes from the default [Source] and
// writes them into p. It always returns len(p) and a nil error.
// Read, unlike the [Rand.Read] method, is safe for concurrent use.
//
// Deprecated: For almost all use cases, [crypto/rand.Read] is more appropriate.
// If a deterministic source is required, use [math/rand/v2.ChaCha8.Read].
func Read(p []byte) (n int, err error) { return globalRand().Read(p) }

// NormFloat64 returns a normally distributed float64 in the range
// [-[math.MaxFloat64], +[math.MaxFloat64]] with
// standard normal distribution (mean = 0, stddev = 1)
// from the default [Source].
// To produce a different normal distribution, callers can
// adjust the output using:
//
//	sample = NormFloat64() * desiredStdDev + desiredMean
func NormFloat64() float64 { return globalRand().NormFloat64() }

// ExpFloat64 returns an exponentially distributed float64 in the range
// (0, +[math.MaxFloat64]] with an exponential distribution whose rate parameter
// (lambda) is 1 and whose mean is 1/lambda (1) from the default [Source].
// To produce a distribution with a different rate parameter,
// callers can adjust the output using:
//
//	sample = ExpFloat64() / desiredRateParameter
func ExpFloat64() float64 { return globalRand().ExpFloat64() }

type lockedSource struct {
	lk sync.Mutex
	s  *rngSource
}

func (r *lockedSource) Int63() (n int64) {
	r.lk.Lock()
	n = r.s.Int63()
	r.lk.Unlock()
	return
}

func (r *lockedSource) Uint64() (n uint64) {
	r.lk.Lock()
	n = r.s.Uint64()
	r.lk.Unlock()
	return
}

func (r *lockedSource) Seed(seed int64) {
	r.lk.Lock()
	r.seed(seed)
	r.lk.Unlock()
}

// seedPos implements Seed for a lockedSource without a race condition.
func (r *lockedSource) seedPos(seed int64, readPos *int8) {
	r.lk.Lock()
	r.seed(seed)
	*readPos = 0
	r.lk.Unlock()
}

// seed seeds the underlying source.
// The caller must have locked r.lk.
func (r *lockedSource) seed(seed int64) {
	if r.s == nil {
		r.s = newSource(seed)
	} else {
		r.s.Seed(seed)
	}
}

// read implements Read for a lockedSource without a race condition.
func (r *lockedSource) read(p []byte, readVal *int64, readPos *int8) (n int, err error) {
	r.lk.Lock()
	n, err = read(p, r.s, readVal, readPos)
	r.lk.Unlock()
	return
}

"""



```