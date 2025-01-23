Response:
Let's break down the thought process to answer the request about the `iter.go` file.

**1. Understanding the Core Request:**

The request asks for a breakdown of the `iter.go` file's functionality, potential Go feature implementation, code examples, considerations for command-line arguments (though this turns out to be irrelevant for this specific file), and common user errors. The language should be Chinese.

**2. Initial Skim and Keyword Identification:**

I first scanned the code and the accompanying documentation comments for keywords and structural elements. I noticed:

* `package iter`: This immediately tells me it's a library providing iteration-related functionality.
* `Seq[V any]`, `Seq2[K, V any]`: These type definitions are central and seem to represent different forms of iterators. The comments mentioning "yield" are crucial.
* The explanations of "Iterators," "Naming Conventions," "Single-Use Iterators," "Pulling Values," and "Mutation" are high-level descriptions of concepts the package implements.
* The presence of `Pull[V any]` and `Pull2[K, V any]` functions suggests a mechanism to convert between "push" and "pull" style iteration.
*  The mention of `runtime.newcoro` and `runtime.coroswitch` hints at a potentially advanced implementation detail, likely related to lightweight concurrency or state management within the iterators.
*  The "Standard Library Usage" section gives context about how this package might interact with other Go standard library parts.
* The "Mutation" section discusses how to handle modifications during iteration, which is important for understanding the limitations of the basic iterators.

**3. Deconstructing the Functionality:**

Based on the skim, I started to categorize the functionalities:

* **Defining Iterator Types:** The core function is to provide standard `Seq` and `Seq2` types. The documentation clearly explains what these types represent: functions that accept a `yield` callback.
* **Push Iteration:** The default behavior described aligns with "push" iteration, where the iterator "pushes" values to the `yield` function. The `range` loop example reinforces this.
* **Pull Iteration:** The `Pull` and `Pull2` functions introduce the concept of "pull" iteration, providing `next()` and `stop()` functions. This is a way to consume iterator values on demand.
* **Handling Concurrency (Implicit):** The use of `runtime.newcoro` and `runtime.coroswitch` suggests an underlying mechanism for managing the state of the iterator, possibly involving lightweight "coroutines" or similar techniques. The `race` package usage is a strong indicator of managing concurrent access and preventing data races.
* **Standard Library Integration:** The documentation explicitly mentions integration with `maps` and `slices`, which is a key feature.
* **Guidance and Conventions:** The documentation provides naming conventions and best practices for using iterators.

**4. Identifying the Go Feature:**

The core Go feature being implemented is **custom iterators**. While Go has the built-in `range` keyword, this package provides a *generalized* way to define and consume iterators beyond the standard collection types. The `Pull` functions, in particular, demonstrate how to build a different style of iteration on top of the basic `Seq` and `Seq2` types. The use of `runtime.newcoro` and `runtime.coroswitch` suggests the implementation leverages **goroutines and potentially a form of cooperative multitasking** to manage the iterator's state and the `yield` mechanism efficiently. This is a more advanced technique than a simple function call.

**5. Crafting Code Examples:**

I needed examples that showcased both the "push" and "pull" styles of iteration.

* **Push Iteration:** The `PrintAll` example from the documentation was perfect. I created a simple `GenerateNumbers` function to provide a concrete `Seq` implementation.
* **Pull Iteration:**  I adapted the `Pairs` example from the documentation, as it clearly demonstrates the usage of `Pull`. I created a simple `GenerateNumbers` function again for demonstration.

**6. Addressing Command-Line Arguments:**

After reviewing the code and documentation, it became clear that this specific file doesn't handle command-line arguments. Therefore, I explicitly stated that it's not relevant.

**7. Identifying Potential User Errors:**

I considered common pitfalls when working with iterators:

* **Forgetting `defer stop()` with `Pull`:**  This is crucial for resource management and preventing goroutine leaks.
* **Calling `next()` after the iterator is done:** While safe, it's a common misunderstanding.
* **Concurrent access to `next()` or `stop()`:** The documentation explicitly mentions this as an error, and the `race` package confirms it.

**8. Structuring the Answer in Chinese:**

Finally, I organized the information logically, using clear and concise Chinese, mirroring the sections in the original request. I ensured the code examples were properly formatted and included explanations of the input and output. I also made sure to translate the technical terms accurately.

**Self-Correction/Refinement during the process:**

* Initially, I might have focused too much on the `runtime` package details. However, it's important to focus on the *user-facing functionality* first. The `runtime` details are implementation details that support the core functionality.
* I made sure to explicitly connect the `Seq` and `Seq2` types to the concept of a `yield` function, as this is the central mechanism.
* I double-checked that my code examples were correct and demonstrated the intended functionality.
* I ensured the Chinese translation was accurate and natural-sounding.

By following these steps, I could produce a comprehensive and accurate answer to the user's request.
好的，让我们来分析一下 `go/src/iter/iter.go` 文件的功能。

**文件功能概述:**

这个 `iter` 包提供了一种在 Go 语言中处理序列迭代的通用机制。它定义了两种核心的迭代器类型 `Seq` 和 `Seq2`，并提供了一种将“推模式”迭代器转换为“拉模式”迭代器的方法。 它的主要目标是提供一种更灵活、可组合的迭代方式，可以与 Go 的 `range` 循环良好地集成。

**核心功能点:**

1. **定义了迭代器类型 `Seq` 和 `Seq2`:**
   - `Seq[V any]` 代表一个返回单个值的序列的迭代器。它是一个函数类型，接受一个 `yield` 回调函数，并将序列中的每个元素传递给该回调。
   - `Seq2[K, V any]` 代表一个返回键值对序列的迭代器。它也接受一个 `yield` 回调函数，并将序列中的每个键值对传递给该回调。
   - `yield` 函数返回一个布尔值，`true` 表示继续迭代，`false` 表示提前停止。

2. **提供了将“推模式”迭代器转换为“拉模式”迭代器的功能 (`Pull` 和 `Pull2` 函数):**
   - 传统的 `Seq` 和 `Seq2` 可以看作是“推模式”迭代器，它们主动将值“推送”给 `yield` 函数。
   - `Pull[V any](seq Seq[V])` 将 `Seq` 类型的迭代器转换为一个“拉模式”迭代器，返回 `next` 和 `stop` 两个函数。
     - `next()` 函数返回序列中的下一个值以及一个布尔值，指示是否还有更多元素。
     - `stop()` 函数用于提前终止迭代。
   - `Pull2[K, V any](seq Seq2[K, V])`  对 `Seq2` 类型的迭代器执行类似的操作。

3. **命名约定和最佳实践:**
   - 文档中详细介绍了命名约定，例如集合类型的迭代器方法通常命名为 `All()`，针对不同序列或配置的迭代器使用更具体的名称（例如 `Cities()`, `Scan()`, `Backward()`）。
   - 强调了“单次使用迭代器”的概念，用于处理不可重放的数据流。

4. **与标准库的集成:**
   - 文档提到了 `maps` 和 `slices` 包中基于迭代器的 API，例如 `maps.Keys()` 和 `slices.Sorted()`。

5. **关于修改的说明:**
   - 强调了迭代器本身不提供修改序列的直接方式。如果需要修改，通常会定义一个包含额外操作的位置类型，并迭代该位置。

**推理其实现的 Go 语言功能：**

这个包的核心功能可以理解为对 Go 语言中迭代模式的一种更高级的抽象和封装。它利用了以下 Go 语言特性：

* **函数类型作为一等公民:**  `Seq` 和 `Seq2` 被定义为函数类型，使得可以将迭代逻辑作为参数传递和返回。
* **闭包:**  迭代器函数通常会捕获外部变量的状态，例如在 `Pull` 函数中创建的 `yield` 函数。
* **`defer` 语句:**  在 `Pull` 函数中，`defer stop()` 用于确保在不再需要迭代器时总是调用 `stop` 函数，即使发生错误。
* **`panic` 和 `recover`:**  `Pull` 函数中使用了 `recover` 来捕获迭代过程中可能发生的 `panic`，并将其传递给调用者。
* **`runtime.Goexit()`:**  代码中出现了 `runtime.Goexit()`，这表明该包可能需要处理 `go` 协程退出的情况。
* **内部的 `runtime.newcoro` 和 `runtime.coroswitch`:** 这两个未导出的函数表明 `Pull` 函数的实现可能使用了轻量级的协程或者类似的机制来实现“拉模式”迭代。这是一种比较底层的技术，用于在函数调用之间保存和恢复状态。
* **`internal/race` 包:**  `race.Acquire` 和 `race.Release` 的使用表明该包考虑了并发安全，并使用了 Go 的竞争检测器来帮助发现潜在的并发问题。

**Go 代码举例说明:**

**示例 1: 使用 `Seq` 迭代并打印数字**

```go
package main

import (
	"fmt"
	"iter"
)

// GenerateNumbers 返回一个生成指定数量数字的迭代器
func GenerateNumbers(n int) iter.Seq[int] {
	return func(yield func(int) bool) {
		for i := 0; i < n; i++ {
			if !yield(i) {
				return // 提前停止
			}
		}
	}
}

func main() {
	numbers := GenerateNumbers(5)
	for num := range numbers {
		fmt.Println(num)
	}
	// 输出:
	// 0
	// 1
	// 2
	// 3
	// 4
}
```

**假设输入与输出:**

在上面的例子中，`GenerateNumbers(5)` 创建了一个 `Seq[int]` 类型的迭代器。
- **假设输入:**  调用 `GenerateNumbers(5)`。
- **输出:**  `range numbers` 循环会依次调用迭代器，`yield` 函数会将 0, 1, 2, 3, 4 传递给 `fmt.Println`，从而打印这些数字。

**示例 2: 使用 `Pull` 将 `Seq` 转换为“拉模式”迭代器**

```go
package main

import (
	"fmt"
	"iter"
)

// GenerateNumbers 返回一个生成指定数量数字的迭代器 (同上)
func GenerateNumbers(n int) iter.Seq[int] {
	return func(yield func(int) bool) {
		for i := 0; i < n; i++ {
			if !yield(i) {
				return
			}
		}
	}
}

func main() {
	numbers := GenerateNumbers(3)
	next, stop := iter.Pull(numbers)
	defer stop()

	val1, ok1 := next()
	fmt.Printf("Value: %d, OK: %t\n", val1, ok1) // 输出: Value: 0, OK: true

	val2, ok2 := next()
	fmt.Printf("Value: %d, OK: %t\n", val2, ok2) // 输出: Value: 1, OK: true

	// 提前停止迭代
	stop()

	val3, ok3 := next()
	fmt.Printf("Value: %d, OK: %t\n", val3, ok3) // 输出: Value: 0, OK: false (因为已经停止)
}
```

**假设输入与输出:**

- **假设输入:** 调用 `GenerateNumbers(3)` 和 `iter.Pull(numbers)`。
- **输出:**
  - 第一次调用 `next()` 会返回 0 和 `true`。
  - 第二次调用 `next()` 会返回 1 和 `true`。
  - 调用 `stop()` 后，后续的 `next()` 调用会返回零值（对于 `int` 是 0）和 `false`。

**命令行参数的具体处理:**

在这个 `iter.go` 文件中，并没有看到任何直接处理命令行参数的代码。这个包主要关注的是迭代逻辑的定义和转换，而不是应用程序的入口和参数解析。 命令行参数的处理通常会在 `main` 函数所在的包中进行，并传递给需要这些参数的函数。

**使用者易犯错的点:**

1. **忘记在 `Pull` 返回的 `next` 和 `stop` 中调用 `stop`:** 如果使用 `Pull` 获取了“拉模式”迭代器，并且没有将序列完全消费完，**必须**调用 `stop()` 来释放迭代器可能持有的资源，并允许底层的迭代器函数完成执行。通常使用 `defer stop()` 来确保 `stop` 被调用。

   ```go
   package main

   import (
       "fmt"
       "iter"
   )

   func GenerateNumbers(n int) iter.Seq[int] {
       return func(yield func(int) bool) {
           fmt.Println("GenerateNumbers started")
           defer fmt.Println("GenerateNumbers finished") // 演示 stop 的重要性
           for i := 0; i < n; i++ {
               if !yield(i) {
                   return
               }
           }
       }
   }

   func main() {
       numbers := GenerateNumbers(5)
       next, stop := iter.Pull(numbers)
       // 错误示例：忘记调用 stop()
       val, ok := next()
       fmt.Println(val, ok)
       // GenerateNumbers started 会打印
       // 输出可能只打印第一个值，并且 "GenerateNumbers finished" 可能不会立即打印，直到垃圾回收发生
   }
   ```

   **正确做法:**

   ```go
   package main

   import (
       "fmt"
       "iter"
   )

   // ... GenerateNumbers 定义同上 ...

   func main() {
       numbers := GenerateNumbers(5)
       next, stop := iter.Pull(numbers)
       defer stop() // 确保 stop 被调用

       val, ok := next()
       fmt.Println(val, ok)
       // GenerateNumbers started 会打印
       // 输出第一个值
       // GenerateNumbers finished 会在 main 函数结束前打印
   }
   ```

2. **在 `yield` 返回 `false` 后继续调用 `yield`:**  `yield` 函数返回 `false` 的目的是告知迭代器提前停止。如果在 `yield` 返回 `false` 后，迭代器逻辑仍然继续调用 `yield`，这会导致程序出现意外行为，甚至可能 `panic` (如代码中 `Pull` 的实现所示，会检查 `yieldNext` 状态)。

3. **并发不安全地使用 `Pull` 返回的 `next` 和 `stop`:** 文档明确指出，不能从多个 Goroutine 同时调用 `next` 或 `stop`。 这会导致数据竞争。

总而言之，`go/src/iter/iter.go` 提供了一套用于定义和操作迭代器的基础框架，它借鉴了函数式编程的一些思想，并通过 `Pull` 函数提供了更灵活的迭代控制方式。理解其核心概念和最佳实践对于有效地使用这个包至关重要。

### 提示词
```
这是路径为go/src/iter/iter.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
```

### 源代码
```go
// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

/*
Package iter provides basic definitions and operations related to
iterators over sequences.

# Iterators

An iterator is a function that passes successive elements of a
sequence to a callback function, conventionally named yield.
The function stops either when the sequence is finished or
when yield returns false, indicating to stop the iteration early.
This package defines [Seq] and [Seq2]
(pronounced like seek—the first syllable of sequence)
as shorthands for iterators that pass 1 or 2 values per sequence element
to yield:

	type (
		Seq[V any]     func(yield func(V) bool)
		Seq2[K, V any] func(yield func(K, V) bool)
	)

Seq2 represents a sequence of paired values, conventionally key-value
or index-value pairs.

Yield returns true if the iterator should continue with the next
element in the sequence, false if it should stop.

Iterator functions are most often called by a range loop, as in:

	func PrintAll[V any](seq iter.Seq[V]) {
		for v := range seq {
			fmt.Println(v)
		}
	}

# Naming Conventions

Iterator functions and methods are named for the sequence being walked:

	// All returns an iterator over all elements in s.
	func (s *Set[V]) All() iter.Seq[V]

The iterator method on a collection type is conventionally named All,
because it iterates a sequence of all the values in the collection.

For a type containing multiple possible sequences, the iterator's name
can indicate which sequence is being provided:

	// Cities returns an iterator over the major cities in the country.
	func (c *Country) Cities() iter.Seq[*City]

	// Languages returns an iterator over the official spoken languages of the country.
	func (c *Country) Languages() iter.Seq[string]

If an iterator requires additional configuration, the constructor function
can take additional configuration arguments:

	// Scan returns an iterator over key-value pairs with min ≤ key ≤ max.
	func (m *Map[K, V]) Scan(min, max K) iter.Seq2[K, V]

	// Split returns an iterator over the (possibly-empty) substrings of s
	// separated by sep.
	func Split(s, sep string) iter.Seq[string]

When there are multiple possible iteration orders, the method name may
indicate that order:

	// All returns an iterator over the list from head to tail.
	func (l *List[V]) All() iter.Seq[V]

	// Backward returns an iterator over the list from tail to head.
	func (l *List[V]) Backward() iter.Seq[V]

	// Preorder returns an iterator over all nodes of the syntax tree
	// beneath (and including) the specified root, in depth-first preorder,
	// visiting a parent node before its children.
	func Preorder(root Node) iter.Seq[Node]

# Single-Use Iterators

Most iterators provide the ability to walk an entire sequence:
when called, the iterator does any setup necessary to start the
sequence, then calls yield on successive elements of the sequence,
and then cleans up before returning. Calling the iterator again
walks the sequence again.

Some iterators break that convention, providing the ability to walk a
sequence only once. These “single-use iterators” typically report values
from a data stream that cannot be rewound to start over.
Calling the iterator again after stopping early may continue the
stream, but calling it again after the sequence is finished will yield
no values at all. Doc comments for functions or methods that return
single-use iterators should document this fact:

	// Lines returns an iterator over lines read from r.
	// It returns a single-use iterator.
	func (r *Reader) Lines() iter.Seq[string]

# Pulling Values

Functions and methods that accept or return iterators
should use the standard [Seq] or [Seq2] types, to ensure
compatibility with range loops and other iterator adapters.
The standard iterators can be thought of as “push iterators”, which
push values to the yield function.

Sometimes a range loop is not the most natural way to consume values
of the sequence. In this case, [Pull] converts a standard push iterator
to a “pull iterator”, which can be called to pull one value at a time
from the sequence. [Pull] starts an iterator and returns a pair
of functions—next and stop—which return the next value from the iterator
and stop it, respectively.

For example:

	// Pairs returns an iterator over successive pairs of values from seq.
	func Pairs[V any](seq iter.Seq[V]) iter.Seq2[V, V] {
		return func(yield func(V, V) bool) {
			next, stop := iter.Pull(seq)
			defer stop()
			for {
				v1, ok1 := next()
				if !ok1 {
					return
				}
				v2, ok2 := next()
				// If ok2 is false, v2 should be the
				// zero value; yield one last pair.
				if !yield(v1, v2) {
					return
				}
				if !ok2 {
					return
				}
			}
		}
	}

If clients do not consume the sequence to completion, they must call stop,
which allows the iterator function to finish and return. As shown in
the example, the conventional way to ensure this is to use defer.

# Standard Library Usage

A few packages in the standard library provide iterator-based APIs,
most notably the [maps] and [slices] packages.
For example, [maps.Keys] returns an iterator over the keys of a map,
while [slices.Sorted] collects the values of an iterator into a slice,
sorts them, and returns the slice, so to iterate over the sorted keys of a map:

	for _, key := range slices.Sorted(maps.Keys(m)) {
		...
	}

# Mutation

Iterators provide only the values of the sequence, not any direct way
to modify it. If an iterator wishes to provide a mechanism for modifying
a sequence during iteration, the usual approach is to define a position type
with the extra operations and then provide an iterator over positions.

For example, a tree implementation might provide:

	// Positions returns an iterator over positions in the sequence.
	func (t *Tree[V]) Positions() iter.Seq[*Pos]

	// A Pos represents a position in the sequence.
	// It is only valid during the yield call it is passed to.
	type Pos[V any] struct { ... }

	// Pos returns the value at the cursor.
	func (p *Pos[V]) Value() V

	// Delete deletes the value at this point in the iteration.
	func (p *Pos[V]) Delete()

	// Set changes the value v at the cursor.
	func (p *Pos[V]) Set(v V)

And then a client could delete boring values from the tree using:

	for p := range t.Positions() {
		if boring(p.Value()) {
			p.Delete()
		}
	}
*/
package iter

import (
	"internal/race"
	"runtime"
	"unsafe"
)

// Seq is an iterator over sequences of individual values.
// When called as seq(yield), seq calls yield(v) for each value v in the sequence,
// stopping early if yield returns false.
// See the [iter] package documentation for more details.
type Seq[V any] func(yield func(V) bool)

// Seq2 is an iterator over sequences of pairs of values, most commonly key-value pairs.
// When called as seq(yield), seq calls yield(k, v) for each pair (k, v) in the sequence,
// stopping early if yield returns false.
// See the [iter] package documentation for more details.
type Seq2[K, V any] func(yield func(K, V) bool)

type coro struct{}

//go:linkname newcoro runtime.newcoro
func newcoro(func(*coro)) *coro

//go:linkname coroswitch runtime.coroswitch
func coroswitch(*coro)

// Pull converts the “push-style” iterator sequence seq
// into a “pull-style” iterator accessed by the two functions
// next and stop.
//
// Next returns the next value in the sequence
// and a boolean indicating whether the value is valid.
// When the sequence is over, next returns the zero V and false.
// It is valid to call next after reaching the end of the sequence
// or after calling stop. These calls will continue
// to return the zero V and false.
//
// Stop ends the iteration. It must be called when the caller is
// no longer interested in next values and next has not yet
// signaled that the sequence is over (with a false boolean return).
// It is valid to call stop multiple times and when next has
// already returned false. Typically, callers should “defer stop()”.
//
// It is an error to call next or stop from multiple goroutines
// simultaneously.
//
// If the iterator panics during a call to next (or stop),
// then next (or stop) itself panics with the same value.
func Pull[V any](seq Seq[V]) (next func() (V, bool), stop func()) {
	var (
		v          V
		ok         bool
		done       bool
		yieldNext  bool
		racer      int
		panicValue any
		seqDone    bool // to detect Goexit
	)
	c := newcoro(func(c *coro) {
		race.Acquire(unsafe.Pointer(&racer))
		if done {
			race.Release(unsafe.Pointer(&racer))
			return
		}
		yield := func(v1 V) bool {
			if done {
				return false
			}
			if !yieldNext {
				panic("iter.Pull: yield called again before next")
			}
			yieldNext = false
			v, ok = v1, true
			race.Release(unsafe.Pointer(&racer))
			coroswitch(c)
			race.Acquire(unsafe.Pointer(&racer))
			return !done
		}
		// Recover and propagate panics from seq.
		defer func() {
			if p := recover(); p != nil {
				panicValue = p
			} else if !seqDone {
				panicValue = goexitPanicValue
			}
			done = true // Invalidate iterator
			race.Release(unsafe.Pointer(&racer))
		}()
		seq(yield)
		var v0 V
		v, ok = v0, false
		seqDone = true
	})
	next = func() (v1 V, ok1 bool) {
		race.Write(unsafe.Pointer(&racer)) // detect races

		if done {
			return
		}
		if yieldNext {
			panic("iter.Pull: next called again before yield")
		}
		yieldNext = true
		race.Release(unsafe.Pointer(&racer))
		coroswitch(c)
		race.Acquire(unsafe.Pointer(&racer))

		// Propagate panics and goexits from seq.
		if panicValue != nil {
			if panicValue == goexitPanicValue {
				// Propagate runtime.Goexit from seq.
				runtime.Goexit()
			} else {
				panic(panicValue)
			}
		}
		return v, ok
	}
	stop = func() {
		race.Write(unsafe.Pointer(&racer)) // detect races

		if !done {
			done = true
			race.Release(unsafe.Pointer(&racer))
			coroswitch(c)
			race.Acquire(unsafe.Pointer(&racer))

			// Propagate panics and goexits from seq.
			if panicValue != nil {
				if panicValue == goexitPanicValue {
					// Propagate runtime.Goexit from seq.
					runtime.Goexit()
				} else {
					panic(panicValue)
				}
			}
		}
	}
	return next, stop
}

// Pull2 converts the “push-style” iterator sequence seq
// into a “pull-style” iterator accessed by the two functions
// next and stop.
//
// Next returns the next pair in the sequence
// and a boolean indicating whether the pair is valid.
// When the sequence is over, next returns a pair of zero values and false.
// It is valid to call next after reaching the end of the sequence
// or after calling stop. These calls will continue
// to return a pair of zero values and false.
//
// Stop ends the iteration. It must be called when the caller is
// no longer interested in next values and next has not yet
// signaled that the sequence is over (with a false boolean return).
// It is valid to call stop multiple times and when next has
// already returned false. Typically, callers should “defer stop()”.
//
// It is an error to call next or stop from multiple goroutines
// simultaneously.
//
// If the iterator panics during a call to next (or stop),
// then next (or stop) itself panics with the same value.
func Pull2[K, V any](seq Seq2[K, V]) (next func() (K, V, bool), stop func()) {
	var (
		k          K
		v          V
		ok         bool
		done       bool
		yieldNext  bool
		racer      int
		panicValue any
		seqDone    bool
	)
	c := newcoro(func(c *coro) {
		race.Acquire(unsafe.Pointer(&racer))
		if done {
			race.Release(unsafe.Pointer(&racer))
			return
		}
		yield := func(k1 K, v1 V) bool {
			if done {
				return false
			}
			if !yieldNext {
				panic("iter.Pull2: yield called again before next")
			}
			yieldNext = false
			k, v, ok = k1, v1, true
			race.Release(unsafe.Pointer(&racer))
			coroswitch(c)
			race.Acquire(unsafe.Pointer(&racer))
			return !done
		}
		// Recover and propagate panics from seq.
		defer func() {
			if p := recover(); p != nil {
				panicValue = p
			} else if !seqDone {
				panicValue = goexitPanicValue
			}
			done = true // Invalidate iterator.
			race.Release(unsafe.Pointer(&racer))
		}()
		seq(yield)
		var k0 K
		var v0 V
		k, v, ok = k0, v0, false
		seqDone = true
	})
	next = func() (k1 K, v1 V, ok1 bool) {
		race.Write(unsafe.Pointer(&racer)) // detect races

		if done {
			return
		}
		if yieldNext {
			panic("iter.Pull2: next called again before yield")
		}
		yieldNext = true
		race.Release(unsafe.Pointer(&racer))
		coroswitch(c)
		race.Acquire(unsafe.Pointer(&racer))

		// Propagate panics and goexits from seq.
		if panicValue != nil {
			if panicValue == goexitPanicValue {
				// Propagate runtime.Goexit from seq.
				runtime.Goexit()
			} else {
				panic(panicValue)
			}
		}
		return k, v, ok
	}
	stop = func() {
		race.Write(unsafe.Pointer(&racer)) // detect races

		if !done {
			done = true
			race.Release(unsafe.Pointer(&racer))
			coroswitch(c)
			race.Acquire(unsafe.Pointer(&racer))

			// Propagate panics and goexits from seq.
			if panicValue != nil {
				if panicValue == goexitPanicValue {
					// Propagate runtime.Goexit from seq.
					runtime.Goexit()
				} else {
					panic(panicValue)
				}
			}
		}
	}
	return next, stop
}

// goexitPanicValue is a sentinel value indicating that an iterator
// exited via runtime.Goexit.
var goexitPanicValue any = new(int)
```