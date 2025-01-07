Response:
Let's break down the thought process for analyzing the provided Go code.

**1. Understanding the Goal:**

The primary goal is to analyze the given Go code snippet from `go/src/internal/runtime/atomic/types.go` and explain its functionality, relate it to Go features, provide examples, and highlight potential pitfalls.

**2. Initial Skim and Identification of Key Components:**

The first step is to quickly skim through the code to identify the major building blocks. I noticed the following recurring patterns:

* **Structs with `noCopy`:**  This immediately signals that these structs are designed to be used as singletons or shared memory locations and should not be copied. This is a crucial piece of information.
* **Methods like `Load`, `Store`, `CompareAndSwap`, `Swap`, `Add`, `And`, `Or`:** These method names are strong indicators of atomic operations.
* **Type variations (Int32, Int64, Uint8, etc.):** This shows that the code provides atomic operations for different integer and boolean types.
* **`unsafe.Pointer` and methods with "NoWB":** This points towards advanced, potentially unsafe operations related to memory management and the garbage collector.
* **`Pointer[T any]`:**  This signifies a generic atomic pointer type.
* **`go:nosplit` directives:**  These hints at performance optimizations and low-level runtime considerations.

**3. Categorizing Functionality:**

Based on the identified components, I started categorizing the functionality:

* **Atomic Integer Operations:** `Int32`, `Int64`, `Uint32`, `Uint64`, `Uintptr` all have similar sets of methods for atomic loading, storing, compare-and-swap, swapping, and addition.
* **Atomic Boolean Operations:** `Bool` provides atomic loading and storing of boolean values.
* **Atomic Bitwise Operations:** `Uint8` and `Uint32` have `And` and `Or` methods for atomic bitwise operations.
* **Atomic Floating-Point Operations:** `Float64` provides atomic loading and storing of floating-point values.
* **Atomic Pointer Operations:** `UnsafePointer` and `Pointer[T]` allow atomic manipulation of pointers, with variations for write barrier handling.

**4. Connecting to Go Features:**

The core functionality directly relates to **concurrency and synchronization** in Go. The `atomic` package provides low-level primitives for managing shared data safely between goroutines without explicit locking mechanisms in many cases.

Specifically:

* **Atomicity:** The central theme. Operations are guaranteed to be indivisible.
* **Data Races:** The primary problem these types solve.
* **`sync/atomic` Package:**  The natural connection. This internal package likely forms the foundation for the public `sync/atomic` package.
* **Generics (`Pointer[T]`)**: A more recent Go feature that allows for type-safe atomic pointers.
* **`unsafe` package:** Used for direct memory manipulation, essential for low-level atomic operations.

**5. Providing Code Examples:**

For each category of functionality, I aimed to provide a simple, illustrative Go code example. The key was to demonstrate how to create and use these atomic types, showcasing the basic operations like `Load`, `Store`, and `CompareAndSwap`. I focused on the most common use cases.

**6. Reasoning about Implementation (Less Deep Dive Here):**

While the code uses internal functions (`Loadint32`, `Casint64`, etc.), the prompt didn't require a deep dive into the underlying implementation details. I noted that these likely rely on CPU-level atomic instructions.

**7. Identifying Potential Pitfalls:**

This is where understanding the "why" behind the code becomes important.

* **No Copying:** The `noCopy` struct is a major red flag. Accidentally copying these structs can lead to subtle and hard-to-debug concurrency issues.
* **`UnsafePointer` and "NoWB":** The warnings in the comments are crucial. Misusing these can break Go's garbage collection and lead to memory corruption.
* **Relaxed Ordering (`LoadAcquire`, `StoreRelease`, `CompareAndSwapRelease`):** These are advanced features requiring a deep understanding of memory ordering. Incorrect usage can lead to subtle concurrency bugs.

**8. Structuring the Answer:**

I organized the answer logically, starting with a general overview of the file's purpose, then detailing each type and its functions, providing code examples, and finally highlighting potential pitfalls. Using clear headings and bullet points improves readability.

**Self-Correction/Refinement During the Process:**

* **Initial thought:** "This looks like the `sync/atomic` package."  **Correction:** "It's the *internal* `atomic` package, likely the foundation for the public one."
* **Initial thought:** "Just list the functions." **Refinement:** "Explain *what* each function does and *why* it's important for atomicity."
* **Initial thought:** "Simple examples are enough." **Refinement:** "Make the examples clear and focused on demonstrating the core functionality."
* **Initial thought:** "Mention all possible edge cases." **Refinement:** "Focus on the most common and easily made mistakes."

By following these steps, I could systematically analyze the code, extract the relevant information, and present it in a comprehensive and understandable way. The process involved understanding the code's structure, its purpose in the context of concurrency, and the potential for misuse.
这个`types.go`文件定义了一系列用于原子操作的类型。原子操作是指一个操作是不可中断的。在多线程并发编程中，原子操作可以保证数据的一致性，避免出现数据竞争的问题。

**功能列举:**

这个文件主要定义了以下几种原子类型，并为每种类型提供了相应的原子操作方法：

1. **`Int32`**: 原子访问的 `int32` 类型。提供以下方法：
   - `Load()`: 原子地读取并返回值。
   - `Store(value int32)`: 原子地更新值。
   - `CompareAndSwap(old, new int32) bool`: 原子地比较当前值与 `old`，如果相等则将当前值替换为 `new`，并返回是否成功。
   - `Swap(new int32) int32`: 原子地将当前值替换为 `new`，并返回替换前的值。
   - `Add(delta int32) int32`: 原子地将 `delta` 加到当前值上，并返回新的值。

2. **`Int64`**: 原子访问的 `int64` 类型。提供与 `Int32` 类似的方法。需要注意的是，`Int64` 在所有平台上都是 8 字节对齐的，这与普通的 `int64` 可能不同。

3. **`Uint8`**: 原子访问的 `uint8` 类型。提供以下方法：
   - `Load()`: 原子地读取并返回值。
   - `Store(value uint8)`: 原子地更新值。
   - `And(value uint8)`: 原子地将当前值与 `value` 进行按位与操作，并将结果存回当前值。
   - `Or(value uint8)`: 原子地将当前值与 `value` 进行按位或操作，并将结果存回当前值。

4. **`Bool`**: 原子访问的 `bool` 类型。实际上是基于 `Uint8` 实现的。提供以下方法：
   - `Load()`: 原子地读取并返回值。
   - `Store(value bool)`: 原子地更新值。

5. **`Uint32`**: 原子访问的 `uint32` 类型。提供以下方法：
   - `Load()`: 原子地读取并返回值。
   - `LoadAcquire()`: 原子地读取并返回值，但放宽了排序约束。
   - `Store(value uint32)`: 原子地更新值。
   - `StoreRelease(value uint32)`: 原子地更新值，但放宽了排序约束。
   - `CompareAndSwap(old, new uint32) bool`: 原子地比较并交换。
   - `CompareAndSwapRelease(old, new uint32) bool`: 原子地比较并交换，但放宽了排序约束。
   - `Swap(value uint32) uint32`: 原子地交换并返回值。
   - `And(value uint32)`: 原子地进行按位与操作。
   - `Or(value uint32)`: 原子地进行按位或操作。
   - `Add(delta int32) uint32`: 原子地加法。

6. **`Uint64`**: 原子访问的 `uint64` 类型。提供与 `Uint32` 类似的方法，同样保证 8 字节对齐。

7. **`Uintptr`**: 原子访问的 `uintptr` 类型。提供与 `Uint32` 类似的原子操作方法，包括 `LoadAcquire` 和 `StoreRelease`。

8. **`Float64`**: 原子访问的 `float64` 类型。提供以下方法：
   - `Load()`: 原子地读取并返回值。
   - `Store(value float64)`: 原子地更新值。
   **注意：** Go 的原子操作主要针对整数类型。`Float64` 的实现方式是通过 `Uint64` 的原子操作来间接实现的，需要使用 `unsafe.Pointer` 进行类型转换。

9. **`UnsafePointer`**: 原子访问的 `unsafe.Pointer` 类型。提供以下方法：
   - `Load()`: 原子地读取并返回值。
   - `StoreNoWB(value unsafe.Pointer)`: 原子地更新值，但不包含写屏障（Write Barrier）。
   - `Store(value unsafe.Pointer)`: 原子地更新值，包含写屏障。
   - `CompareAndSwapNoWB(old, new unsafe.Pointer) bool`: 原子地比较并交换，不包含写屏障。
   - `CompareAndSwap(old, new unsafe.Pointer) bool`: 原子地比较并交换，包含写屏障。
   **重要提示：** 使用 `UnsafePointer` 时需要格外小心，尤其是 `StoreNoWB` 和 `CompareAndSwapNoWB`，因为它们跳过了写屏障，可能导致垃圾回收器无法正确追踪指针，从而引发内存安全问题。

10. **`Pointer[T any]`**: 原子访问的 `*T` 类型的指针。这是一个泛型类型，可以用于任何类型的指针。提供以下方法：
    - `Load()`: 原子地读取并返回值。
    - `StoreNoWB(value *T)`: 原子地更新值，不包含写屏障。
    - `Store(value *T)`: 原子地更新值，包含写屏障。
    - `CompareAndSwapNoWB(old, new *T) bool`: 原子地比较并交换，不包含写屏障。
    - `CompareAndSwap(old, new *T) bool`: 原子地比较并交换，包含写屏障。

**Go 语言功能的实现：原子操作**

这个文件实现的是 Go 语言中的**原子操作**功能。原子操作是并发编程中非常重要的概念，它保证了对共享变量的操作是不可分割的，不会被其他线程中断。这对于避免数据竞争和保证数据一致性至关重要。

**Go 代码举例说明:**

假设我们要在多个 goroutine 中安全地递增一个计数器。使用 `atomic.Int32` 可以实现：

```go
package main

import (
	"fmt"
	"internal/runtime/atomic"
	"sync"
)

func main() {
	var counter atomic.Int32
	var wg sync.WaitGroup

	numGoroutines := 100

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 1000; j++ {
				counter.Add(1)
			}
		}()
	}

	wg.Wait()
	fmt.Println("Counter:", counter.Load()) // 输出结果接近 100000
}
```

**假设的输入与输出：**

在上面的例子中，没有显式的输入，goroutine 内部循环执行递增操作。最终的输出是计数器的值。由于多个 goroutine 并发执行，每次运行的结果可能会略有不同，但会非常接近 `numGoroutines * 1000 = 100000`。

**代码推理：**

`counter.Add(1)`  这行代码使用了 `atomic.Int32` 类型的 `Add` 方法。即使多个 goroutine 同时执行这行代码，由于 `Add` 是原子操作，所以不会出现多个 goroutine 同时读取到相同的值然后都加 1 的情况，从而保证了最终计数器的正确性。

**使用者易犯错的点：**

1. **误解原子操作的范围：** 原子操作只能保证**单个**操作的原子性。如果需要多个操作组合在一起的原子性，仍然需要使用互斥锁或其他同步机制。例如，先读取一个值，然后根据这个值进行更新，这两个操作组合起来不一定是原子的。

   ```go
   package main

   import (
       "fmt"
       "internal/runtime/atomic"
       "sync"
   )

   func main() {
       var value atomic.Int32
       var wg sync.WaitGroup

       numGoroutines := 100

       for i := 0; i < numGoroutines; i++ {
           wg.Add(1)
           go func() {
               defer wg.Done()
               // 非原子操作的组合
               current := value.Load()
               newValue := current + 1
               value.Store(newValue) // 即使 Load 和 Store 是原子的，但组合起来不是
           }()
       }

       wg.Wait()
       fmt.Println("Value:", value.Load()) // 输出结果可能小于 100，因为存在数据竞争
   }
   ```

   在这个错误的例子中，即使 `Load` 和 `Store` 操作是原子的，但 `Load` 和 `Store` 之间的操作不是原子的，仍然可能发生数据竞争。应该使用 `CompareAndSwap` 来实现这种复合的原子操作：

   ```go
   package main

   import (
       "fmt"
       "internal/runtime/atomic"
       "sync"
   )

   func main() {
       var value atomic.Int32
       var wg sync.WaitGroup

       numGoroutines := 100

       for i := 0; i < numGoroutines; i++ {
           wg.Add(1)
           go func() {
               defer wg.Done()
               for {
                   current := value.Load()
                   newValue := current + 1
                   if value.CompareAndSwap(current, newValue) {
                       break
                   }
               }
           }()
       }

       wg.Wait()
       fmt.Println("Value:", value.Load()) // 输出结果接近 100
   }
   ```

2. **不恰当地复制原子类型：**  代码中每个原子类型的定义都包含了 `noCopy` 字段。这意味着这些类型**不应该被复制**。复制原子类型会导致每个副本都有自己的独立值，而无法实现预期的原子共享效果。Go 的 `go vet` 工具可以检测到这种错误。

   ```go
   package main

   import (
       "fmt"
       "internal/runtime/atomic"
       "sync"
   )

   func modifyCounter(c atomic.Int32) { // 错误：原子类型被值传递复制
       c.Add(1)
   }

   func main() {
       var counter atomic.Int32
       var wg sync.WaitGroup

       numGoroutines := 10

       for i := 0; i < numGoroutines; i++ {
           wg.Add(1)
           go func() {
               defer wg.Done()
               modifyCounter(counter) // 错误：修改的是副本
           }()
       }

       wg.Wait()
       fmt.Println("Counter:", counter.Load()) // 输出结果很可能是 0
   }
   ```

   正确的做法是通过指针传递原子类型：

   ```go
   package main

   import (
       "fmt"
       "internal/runtime/atomic"
       "sync"
   )

   func modifyCounter(c *atomic.Int32) {
       c.Add(1)
   }

   func main() {
       var counter atomic.Int32
       var wg sync.WaitGroup

       numGoroutines := 10

       for i := 0; i < numGoroutines; i++ {
           wg.Add(1)
           go func() {
               defer wg.Done()
               modifyCounter(&counter)
           }()
       }

       wg.Wait()
       fmt.Println("Counter:", counter.Load()) // 输出结果接近 10
   }
   ```

3. **对 `UnsafePointer` 的误用：** 如前所述，`UnsafePointer` 的 `StoreNoWB` 和 `CompareAndSwapNoWB` 方法跳过了写屏障，这在大多数情况下是不应该使用的。除非非常清楚自己在做什么，并且确信操作的指针不会被垃圾回收器管理，否则应该使用带有写屏障的版本 (`Store` 和 `CompareAndSwap`)。

总而言之，`go/src/internal/runtime/atomic/types.go` 文件定义了 Go 语言底层用于实现原子操作的各种数据类型和方法，为并发编程提供了重要的基础工具。正确理解和使用这些类型可以有效地避免数据竞争，保证程序的正确性。

Prompt: 
```
这是路径为go/src/internal/runtime/atomic/types.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。

"""
// Copyright 2021 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package atomic

import "unsafe"

// Int32 is an atomically accessed int32 value.
//
// An Int32 must not be copied.
type Int32 struct {
	noCopy noCopy
	value  int32
}

// Load accesses and returns the value atomically.
//
//go:nosplit
func (i *Int32) Load() int32 {
	return Loadint32(&i.value)
}

// Store updates the value atomically.
//
//go:nosplit
func (i *Int32) Store(value int32) {
	Storeint32(&i.value, value)
}

// CompareAndSwap atomically compares i's value with old,
// and if they're equal, swaps i's value with new.
// It reports whether the swap ran.
//
//go:nosplit
func (i *Int32) CompareAndSwap(old, new int32) bool {
	return Casint32(&i.value, old, new)
}

// Swap replaces i's value with new, returning
// i's value before the replacement.
//
//go:nosplit
func (i *Int32) Swap(new int32) int32 {
	return Xchgint32(&i.value, new)
}

// Add adds delta to i atomically, returning
// the new updated value.
//
// This operation wraps around in the usual
// two's-complement way.
//
//go:nosplit
func (i *Int32) Add(delta int32) int32 {
	return Xaddint32(&i.value, delta)
}

// Int64 is an atomically accessed int64 value.
//
// 8-byte aligned on all platforms, unlike a regular int64.
//
// An Int64 must not be copied.
type Int64 struct {
	noCopy noCopy
	_      align64
	value  int64
}

// Load accesses and returns the value atomically.
//
//go:nosplit
func (i *Int64) Load() int64 {
	return Loadint64(&i.value)
}

// Store updates the value atomically.
//
//go:nosplit
func (i *Int64) Store(value int64) {
	Storeint64(&i.value, value)
}

// CompareAndSwap atomically compares i's value with old,
// and if they're equal, swaps i's value with new.
// It reports whether the swap ran.
//
//go:nosplit
func (i *Int64) CompareAndSwap(old, new int64) bool {
	return Casint64(&i.value, old, new)
}

// Swap replaces i's value with new, returning
// i's value before the replacement.
//
//go:nosplit
func (i *Int64) Swap(new int64) int64 {
	return Xchgint64(&i.value, new)
}

// Add adds delta to i atomically, returning
// the new updated value.
//
// This operation wraps around in the usual
// two's-complement way.
//
//go:nosplit
func (i *Int64) Add(delta int64) int64 {
	return Xaddint64(&i.value, delta)
}

// Uint8 is an atomically accessed uint8 value.
//
// A Uint8 must not be copied.
type Uint8 struct {
	noCopy noCopy
	value  uint8
}

// Load accesses and returns the value atomically.
//
//go:nosplit
func (u *Uint8) Load() uint8 {
	return Load8(&u.value)
}

// Store updates the value atomically.
//
//go:nosplit
func (u *Uint8) Store(value uint8) {
	Store8(&u.value, value)
}

// And takes value and performs a bit-wise
// "and" operation with the value of u, storing
// the result into u.
//
// The full process is performed atomically.
//
//go:nosplit
func (u *Uint8) And(value uint8) {
	And8(&u.value, value)
}

// Or takes value and performs a bit-wise
// "or" operation with the value of u, storing
// the result into u.
//
// The full process is performed atomically.
//
//go:nosplit
func (u *Uint8) Or(value uint8) {
	Or8(&u.value, value)
}

// Bool is an atomically accessed bool value.
//
// A Bool must not be copied.
type Bool struct {
	// Inherits noCopy from Uint8.
	u Uint8
}

// Load accesses and returns the value atomically.
//
//go:nosplit
func (b *Bool) Load() bool {
	return b.u.Load() != 0
}

// Store updates the value atomically.
//
//go:nosplit
func (b *Bool) Store(value bool) {
	s := uint8(0)
	if value {
		s = 1
	}
	b.u.Store(s)
}

// Uint32 is an atomically accessed uint32 value.
//
// A Uint32 must not be copied.
type Uint32 struct {
	noCopy noCopy
	value  uint32
}

// Load accesses and returns the value atomically.
//
//go:nosplit
func (u *Uint32) Load() uint32 {
	return Load(&u.value)
}

// LoadAcquire is a partially unsynchronized version
// of Load that relaxes ordering constraints. Other threads
// may observe operations that precede this operation to
// occur after it, but no operation that occurs after it
// on this thread can be observed to occur before it.
//
// WARNING: Use sparingly and with great care.
//
//go:nosplit
func (u *Uint32) LoadAcquire() uint32 {
	return LoadAcq(&u.value)
}

// Store updates the value atomically.
//
//go:nosplit
func (u *Uint32) Store(value uint32) {
	Store(&u.value, value)
}

// StoreRelease is a partially unsynchronized version
// of Store that relaxes ordering constraints. Other threads
// may observe operations that occur after this operation to
// precede it, but no operation that precedes it
// on this thread can be observed to occur after it.
//
// WARNING: Use sparingly and with great care.
//
//go:nosplit
func (u *Uint32) StoreRelease(value uint32) {
	StoreRel(&u.value, value)
}

// CompareAndSwap atomically compares u's value with old,
// and if they're equal, swaps u's value with new.
// It reports whether the swap ran.
//
//go:nosplit
func (u *Uint32) CompareAndSwap(old, new uint32) bool {
	return Cas(&u.value, old, new)
}

// CompareAndSwapRelease is a partially unsynchronized version
// of Cas that relaxes ordering constraints. Other threads
// may observe operations that occur after this operation to
// precede it, but no operation that precedes it
// on this thread can be observed to occur after it.
// It reports whether the swap ran.
//
// WARNING: Use sparingly and with great care.
//
//go:nosplit
func (u *Uint32) CompareAndSwapRelease(old, new uint32) bool {
	return CasRel(&u.value, old, new)
}

// Swap replaces u's value with new, returning
// u's value before the replacement.
//
//go:nosplit
func (u *Uint32) Swap(value uint32) uint32 {
	return Xchg(&u.value, value)
}

// And takes value and performs a bit-wise
// "and" operation with the value of u, storing
// the result into u.
//
// The full process is performed atomically.
//
//go:nosplit
func (u *Uint32) And(value uint32) {
	And(&u.value, value)
}

// Or takes value and performs a bit-wise
// "or" operation with the value of u, storing
// the result into u.
//
// The full process is performed atomically.
//
//go:nosplit
func (u *Uint32) Or(value uint32) {
	Or(&u.value, value)
}

// Add adds delta to u atomically, returning
// the new updated value.
//
// This operation wraps around in the usual
// two's-complement way.
//
//go:nosplit
func (u *Uint32) Add(delta int32) uint32 {
	return Xadd(&u.value, delta)
}

// Uint64 is an atomically accessed uint64 value.
//
// 8-byte aligned on all platforms, unlike a regular uint64.
//
// A Uint64 must not be copied.
type Uint64 struct {
	noCopy noCopy
	_      align64
	value  uint64
}

// Load accesses and returns the value atomically.
//
//go:nosplit
func (u *Uint64) Load() uint64 {
	return Load64(&u.value)
}

// Store updates the value atomically.
//
//go:nosplit
func (u *Uint64) Store(value uint64) {
	Store64(&u.value, value)
}

// CompareAndSwap atomically compares u's value with old,
// and if they're equal, swaps u's value with new.
// It reports whether the swap ran.
//
//go:nosplit
func (u *Uint64) CompareAndSwap(old, new uint64) bool {
	return Cas64(&u.value, old, new)
}

// Swap replaces u's value with new, returning
// u's value before the replacement.
//
//go:nosplit
func (u *Uint64) Swap(value uint64) uint64 {
	return Xchg64(&u.value, value)
}

// Add adds delta to u atomically, returning
// the new updated value.
//
// This operation wraps around in the usual
// two's-complement way.
//
//go:nosplit
func (u *Uint64) Add(delta int64) uint64 {
	return Xadd64(&u.value, delta)
}

// Uintptr is an atomically accessed uintptr value.
//
// A Uintptr must not be copied.
type Uintptr struct {
	noCopy noCopy
	value  uintptr
}

// Load accesses and returns the value atomically.
//
//go:nosplit
func (u *Uintptr) Load() uintptr {
	return Loaduintptr(&u.value)
}

// LoadAcquire is a partially unsynchronized version
// of Load that relaxes ordering constraints. Other threads
// may observe operations that precede this operation to
// occur after it, but no operation that occurs after it
// on this thread can be observed to occur before it.
//
// WARNING: Use sparingly and with great care.
//
//go:nosplit
func (u *Uintptr) LoadAcquire() uintptr {
	return LoadAcquintptr(&u.value)
}

// Store updates the value atomically.
//
//go:nosplit
func (u *Uintptr) Store(value uintptr) {
	Storeuintptr(&u.value, value)
}

// StoreRelease is a partially unsynchronized version
// of Store that relaxes ordering constraints. Other threads
// may observe operations that occur after this operation to
// precede it, but no operation that precedes it
// on this thread can be observed to occur after it.
//
// WARNING: Use sparingly and with great care.
//
//go:nosplit
func (u *Uintptr) StoreRelease(value uintptr) {
	StoreReluintptr(&u.value, value)
}

// CompareAndSwap atomically compares u's value with old,
// and if they're equal, swaps u's value with new.
// It reports whether the swap ran.
//
//go:nosplit
func (u *Uintptr) CompareAndSwap(old, new uintptr) bool {
	return Casuintptr(&u.value, old, new)
}

// Swap replaces u's value with new, returning
// u's value before the replacement.
//
//go:nosplit
func (u *Uintptr) Swap(value uintptr) uintptr {
	return Xchguintptr(&u.value, value)
}

// Add adds delta to u atomically, returning
// the new updated value.
//
// This operation wraps around in the usual
// two's-complement way.
//
//go:nosplit
func (u *Uintptr) Add(delta uintptr) uintptr {
	return Xadduintptr(&u.value, delta)
}

// Float64 is an atomically accessed float64 value.
//
// 8-byte aligned on all platforms, unlike a regular float64.
//
// A Float64 must not be copied.
type Float64 struct {
	// Inherits noCopy and align64 from Uint64.
	u Uint64
}

// Load accesses and returns the value atomically.
//
//go:nosplit
func (f *Float64) Load() float64 {
	r := f.u.Load()
	return *(*float64)(unsafe.Pointer(&r))
}

// Store updates the value atomically.
//
//go:nosplit
func (f *Float64) Store(value float64) {
	f.u.Store(*(*uint64)(unsafe.Pointer(&value)))
}

// UnsafePointer is an atomically accessed unsafe.Pointer value.
//
// Note that because of the atomicity guarantees, stores to values
// of this type never trigger a write barrier, and the relevant
// methods are suffixed with "NoWB" to indicate that explicitly.
// As a result, this type should be used carefully, and sparingly,
// mostly with values that do not live in the Go heap anyway.
//
// An UnsafePointer must not be copied.
type UnsafePointer struct {
	noCopy noCopy
	value  unsafe.Pointer
}

// Load accesses and returns the value atomically.
//
//go:nosplit
func (u *UnsafePointer) Load() unsafe.Pointer {
	return Loadp(unsafe.Pointer(&u.value))
}

// StoreNoWB updates the value atomically.
//
// WARNING: As the name implies this operation does *not*
// perform a write barrier on value, and so this operation may
// hide pointers from the GC. Use with care and sparingly.
// It is safe to use with values not found in the Go heap.
// Prefer Store instead.
//
//go:nosplit
func (u *UnsafePointer) StoreNoWB(value unsafe.Pointer) {
	StorepNoWB(unsafe.Pointer(&u.value), value)
}

// Store updates the value atomically.
func (u *UnsafePointer) Store(value unsafe.Pointer) {
	storePointer(&u.value, value)
}

// provided by runtime
//
//go:linkname storePointer
func storePointer(ptr *unsafe.Pointer, new unsafe.Pointer)

// CompareAndSwapNoWB atomically (with respect to other methods)
// compares u's value with old, and if they're equal,
// swaps u's value with new.
// It reports whether the swap ran.
//
// WARNING: As the name implies this operation does *not*
// perform a write barrier on value, and so this operation may
// hide pointers from the GC. Use with care and sparingly.
// It is safe to use with values not found in the Go heap.
// Prefer CompareAndSwap instead.
//
//go:nosplit
func (u *UnsafePointer) CompareAndSwapNoWB(old, new unsafe.Pointer) bool {
	return Casp1(&u.value, old, new)
}

// CompareAndSwap atomically compares u's value with old,
// and if they're equal, swaps u's value with new.
// It reports whether the swap ran.
func (u *UnsafePointer) CompareAndSwap(old, new unsafe.Pointer) bool {
	return casPointer(&u.value, old, new)
}

func casPointer(ptr *unsafe.Pointer, old, new unsafe.Pointer) bool

// Pointer is an atomic pointer of type *T.
type Pointer[T any] struct {
	u UnsafePointer
}

// Load accesses and returns the value atomically.
//
//go:nosplit
func (p *Pointer[T]) Load() *T {
	return (*T)(p.u.Load())
}

// StoreNoWB updates the value atomically.
//
// WARNING: As the name implies this operation does *not*
// perform a write barrier on value, and so this operation may
// hide pointers from the GC. Use with care and sparingly.
// It is safe to use with values not found in the Go heap.
// Prefer Store instead.
//
//go:nosplit
func (p *Pointer[T]) StoreNoWB(value *T) {
	p.u.StoreNoWB(unsafe.Pointer(value))
}

// Store updates the value atomically.
//
//go:nosplit
func (p *Pointer[T]) Store(value *T) {
	p.u.Store(unsafe.Pointer(value))
}

// CompareAndSwapNoWB atomically (with respect to other methods)
// compares u's value with old, and if they're equal,
// swaps u's value with new.
// It reports whether the swap ran.
//
// WARNING: As the name implies this operation does *not*
// perform a write barrier on value, and so this operation may
// hide pointers from the GC. Use with care and sparingly.
// It is safe to use with values not found in the Go heap.
// Prefer CompareAndSwap instead.
//
//go:nosplit
func (p *Pointer[T]) CompareAndSwapNoWB(old, new *T) bool {
	return p.u.CompareAndSwapNoWB(unsafe.Pointer(old), unsafe.Pointer(new))
}

// CompareAndSwap atomically (with respect to other methods)
// compares u's value with old, and if they're equal,
// swaps u's value with new.
// It reports whether the swap ran.
func (p *Pointer[T]) CompareAndSwap(old, new *T) bool {
	return p.u.CompareAndSwap(unsafe.Pointer(old), unsafe.Pointer(new))
}

// noCopy may be embedded into structs which must not be copied
// after the first use.
//
// See https://golang.org/issues/8005#issuecomment-190753527
// for details.
type noCopy struct{}

// Lock is a no-op used by -copylocks checker from `go vet`.
func (*noCopy) Lock()   {}
func (*noCopy) Unlock() {}

// align64 may be added to structs that must be 64-bit aligned.
// This struct is recognized by a special case in the compiler
// and will not work if copied to any other package.
type align64 struct{}

"""



```