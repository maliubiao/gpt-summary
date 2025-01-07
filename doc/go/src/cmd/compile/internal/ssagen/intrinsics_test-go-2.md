Response:
Let's break down the thought process for answering this multi-part question about the provided Go code snippet.

**1. Understanding the Core Task:**

The central goal is to analyze a piece of Go code responsible for defining "intrinsics" for different architectures. The code is part of the Go compiler.

**2. Deconstructing the Request:**

The prompt has several specific requests:

* **List the function:**  What does this code do?
* **Infer the Go feature:** What higher-level Go concept does this relate to?
* **Provide a Go example:**  Illustrate the inferred feature with code.
* **Handle code inference:** If inferring, include input/output assumptions.
* **Handle command-line parameters:**  Explain if any are relevant.
* **Highlight common mistakes:** Point out potential pitfalls for users.
* **Provide a summary:** Concisely state the code's purpose.
* **Indicate part number:** This is part 3 of 4.

**3. Analyzing the Code Snippet:**

The code is a large Go map. The keys of the map are tuples (strings) and the values are empty structs (`struct{}{}`). Each tuple has three elements:

* **Architecture (e.g., "amd64", "arm64", "ppc64")**: This clearly indicates architecture-specific handling.
* **Package Path (e.g., "internal/runtime/atomic", "math/bits")**: This points to standard Go libraries.
* **Function Name (e.g., "AddInt32", "Mul64", "Bswap32")**: These are recognizable function names.

The structure strongly suggests that this code is defining a set of functions that the Go compiler will treat specially, depending on the target architecture.

**4. Inferring the Go Feature: Intrinsics**

The file path `go/src/cmd/compile/internal/ssagen/intrinsics_test.go` and the variable name `intrinsics` strongly suggest that this code defines compiler intrinsics. Intrinsics are special functions that the compiler can replace with highly optimized, architecture-specific machine code.

**5. Explaining Intrinsics:**

Now that the concept of intrinsics is identified, the explanation needs to cover:

* **What they are:** Compiler optimizations for specific functions.
* **Why they are used:** Performance gains by leveraging hardware features.
* **How they work (conceptually):** The compiler recognizes these functions and substitutes optimized code.

**6. Providing a Go Example:**

To illustrate intrinsics, a good example involves a function that has a known intrinsic and shows how it's used like a regular Go function. Atomic operations are a classic example because they often have highly optimized hardware instructions.

* **Choose an intrinsic:** `sync/atomic.AddInt32` is a good choice.
* **Show the usage:** A simple function that increments an integer using `atomic.AddInt32`.
* **Explain the benefit:**  The compiler *might* replace this with a single atomic instruction, which is more efficient than a general addition with locking.

**7. Addressing Other Requests:**

* **Code Inference (Input/Output):** For the given code snippet (the map definition), there's no direct input/output in the traditional sense. It's a data structure. The *input* to the compiler would be Go code that calls these functions, and the *output* would be the compiled machine code with the intrinsics applied.
* **Command-Line Parameters:**  This specific code doesn't directly process command-line arguments. However, the Go compiler itself has flags that influence code generation and optimization, so mentioning this broader context is useful. Specifically, architecture-related flags like `GOARCH` are relevant.
* **Common Mistakes:** A key mistake users could make is relying too heavily on the *expectation* of an intrinsic being applied. Intrinsics are an optimization, and the compiler might not always use them. Also, thinking intrinsics change the *semantics* of the function is wrong; they only change the implementation.
* **Summary:**  A concise restatement of the main function: defining intrinsics for the Go compiler.
* **Part Number:**  Simply acknowledge the "Part 3 of 4" indication.

**8. Structuring the Answer:**

Organize the answer logically, following the order of the requests in the prompt. Use clear headings and formatting to make it easy to read and understand.

**Self-Correction/Refinement during the thought process:**

* **Initial thought:** Maybe this is about some kind of function registration.
* **Correction:** The `intrinsics` variable name and the context within the compiler source code strongly point to compiler intrinsics.
* **Initial thought:**  Should I provide assembly code examples?
* **Refinement:**  While assembly would be the ultimate manifestation of intrinsics, a Go code example demonstrating the *usage* is more accessible and directly answers the "what Go language feature" question. The explanation should *mention* the assembly optimization.
* **Initial thought:**  Focus only on the `ppc64` entries since that's the majority of the snippet.
* **Refinement:** While the snippet heavily features `ppc64`, the presence of other architectures (`ppc64le`, `riscv64`, `s390x`) is crucial to understanding the architecture-specific nature of intrinsics. The explanation should highlight this multi-architecture aspect.

By following this structured thought process, addressing each part of the prompt, and making necessary refinements, we arrive at a comprehensive and accurate answer.
这是 `go/src/cmd/compile/internal/ssagen/intrinsics_test.go` 文件的一部分，它定义了一个名为 `intrinsics` 的 map。这个 map 的键是由架构（例如 "amd64"）、包路径（例如 "internal/runtime/atomic"）和函数名（例如 "AddInt32"）组成的字符串三元组。值是一个空的结构体 `struct{}{}`。

**功能归纳:**

这段代码定义了一组在特定架构下需要被编译器特殊处理的 "intrinsic" 函数。 这些 intrinsic 函数通常是标准库中的某些函数，编译器会针对不同的架构，使用优化的、更底层的指令或代码序列来替换对这些函数的调用，以提高性能。

**Go 语言功能的实现 (推断):**

这段代码是 Go 编译器中实现 **内联函数优化** (intrinsic function optimization) 的一部分。 编译器会识别这些特定的函数调用，并用更高效的机器码指令来替换它们，而不是像普通函数那样进行调用。 这通常用于一些非常底层的、性能敏感的操作，例如原子操作、位操作和一些数学运算。

**Go 代码举例说明:**

假设 `intrinsics` map 中定义了 `"amd64", "sync/atomic", "AddInt32"`。 这意味着在 `amd64` 架构下，对 `sync/atomic.AddInt32` 函数的调用可能会被编译器替换为更高效的原子加法指令。

```go
package main

import (
	"fmt"
	"sync/atomic"
)

func main() {
	var counter int32 = 0
	atomic.AddInt32(&counter, 1)
	fmt.Println(counter) // 输出: 1
}
```

**代码推理:**

* **假设输入:** 上面的 Go 代码在 `amd64` 架构下编译。
* **编译器行为:**  当编译器遇到 `atomic.AddInt32(&counter, 1)` 时，它会查找 `intrinsics` map。因为存在 `"amd64", "sync/atomic", "AddInt32"` 的条目，编译器会用 `amd64` 架构下高效的原子加法指令来替换这个函数调用，而不是生成一个普通的函数调用。
* **输出:** 程序会正确地将 `counter` 的值原子地增加 1，并输出 `1`。

**命令行参数的具体处理:**

这段代码本身并不直接处理命令行参数。 但是，Go 编译器 `go build` 或 `go run` 命令会使用 `-gcflags` 参数来传递编译器的 flag。 其中一些 flag 可能会影响 intrinsic 函数的处理，例如：

* `-N`: 禁用优化，这可能会导致 intrinsic 函数不被替换。
* `-l`: 禁用内联，也可能影响 intrinsic 函数的处理，因为很多 intrinsic 函数依赖于内联。
* `-a`: 强制重新编译所有包，确保 intrinsic 函数的定义是最新的。
* `-tags`:  可以用于构建特定平台的版本，这会影响哪些 intrinsic 函数会被激活。

例如，使用 `go build -gcflags="-N"` 编译上面的代码可能会阻止编译器将 `atomic.AddInt32` 替换为原子指令。

**使用者易犯错的点:**

使用者通常不需要直接与 `intrinsics` map 打交道。  但是，理解 intrinsic 函数的存在可以帮助理解一些性能表现。 一个可能的误解是认为所有标准库中的函数都会被替换为 intrinsic 函数。 实际上，只有一小部分性能关键的函数会被作为 intrinsic 函数处理。

例如，使用者可能会认为所有的数学运算都会被替换为最底层的硬件指令，但这并不总是成立。只有在 `intrinsics` map 中列出的函数，且编译器认为有利可图时，才会进行替换。

**功能归纳 (针对第3部分):**

这部分 `intrinsics` map 定义了 `ppc64`, `ppc64le`, `riscv64` 和 `s390x` 这几种架构下的一系列可以被编译器优化处理的 intrinsic 函数。 这些函数主要集中在原子操作 (`internal/runtime/atomic`, `sync/atomic`)、一些基础数学运算 (`math`, `math/bits`) 以及运行时系统调用 (`internal/runtime/sys`, `runtime`) 相关的函数。 这意味着 Go 编译器在为这些架构编译代码时，能够利用更底层的、硬件相关的指令来提高这些特定操作的执行效率。

Prompt: 
```
这是路径为go/src/cmd/compile/internal/ssagen/intrinsics_test.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第3部分，共4部分，请归纳一下它的功能

"""
internal/runtime/atomic", "LoadAcquintptr"}:             struct{}{},
	{"ppc64", "internal/runtime/atomic", "Loadint32"}:                  struct{}{},
	{"ppc64", "internal/runtime/atomic", "Loadint64"}:                  struct{}{},
	{"ppc64", "internal/runtime/atomic", "Loadp"}:                      struct{}{},
	{"ppc64", "internal/runtime/atomic", "Loaduint"}:                   struct{}{},
	{"ppc64", "internal/runtime/atomic", "Loaduintptr"}:                struct{}{},
	{"ppc64", "internal/runtime/atomic", "Or"}:                         struct{}{},
	{"ppc64", "internal/runtime/atomic", "Or8"}:                        struct{}{},
	{"ppc64", "internal/runtime/atomic", "Store"}:                      struct{}{},
	{"ppc64", "internal/runtime/atomic", "Store64"}:                    struct{}{},
	{"ppc64", "internal/runtime/atomic", "Store8"}:                     struct{}{},
	{"ppc64", "internal/runtime/atomic", "StoreRel"}:                   struct{}{},
	{"ppc64", "internal/runtime/atomic", "StoreRel64"}:                 struct{}{},
	{"ppc64", "internal/runtime/atomic", "StoreReluintptr"}:            struct{}{},
	{"ppc64", "internal/runtime/atomic", "Storeint32"}:                 struct{}{},
	{"ppc64", "internal/runtime/atomic", "Storeint64"}:                 struct{}{},
	{"ppc64", "internal/runtime/atomic", "Storeuintptr"}:               struct{}{},
	{"ppc64", "internal/runtime/atomic", "Xadd"}:                       struct{}{},
	{"ppc64", "internal/runtime/atomic", "Xadd64"}:                     struct{}{},
	{"ppc64", "internal/runtime/atomic", "Xaddint32"}:                  struct{}{},
	{"ppc64", "internal/runtime/atomic", "Xaddint64"}:                  struct{}{},
	{"ppc64", "internal/runtime/atomic", "Xadduintptr"}:                struct{}{},
	{"ppc64", "internal/runtime/atomic", "Xchg8"}:                      struct{}{},
	{"ppc64", "internal/runtime/atomic", "Xchg"}:                       struct{}{},
	{"ppc64", "internal/runtime/atomic", "Xchg64"}:                     struct{}{},
	{"ppc64", "internal/runtime/atomic", "Xchgint32"}:                  struct{}{},
	{"ppc64", "internal/runtime/atomic", "Xchgint64"}:                  struct{}{},
	{"ppc64", "internal/runtime/atomic", "Xchguintptr"}:                struct{}{},
	{"ppc64", "internal/runtime/math", "Add64"}:                        struct{}{},
	{"ppc64", "internal/runtime/math", "Mul64"}:                        struct{}{},
	{"ppc64", "internal/runtime/math", "MulUintptr"}:                   struct{}{},
	{"ppc64", "internal/runtime/sys", "Bswap32"}:                       struct{}{},
	{"ppc64", "internal/runtime/sys", "Bswap64"}:                       struct{}{},
	{"ppc64", "internal/runtime/sys", "GetCallerPC"}:                   struct{}{},
	{"ppc64", "internal/runtime/sys", "GetCallerSP"}:                   struct{}{},
	{"ppc64", "internal/runtime/sys", "GetClosurePtr"}:                 struct{}{},
	{"ppc64", "internal/runtime/sys", "Len64"}:                         struct{}{},
	{"ppc64", "internal/runtime/sys", "Len8"}:                          struct{}{},
	{"ppc64", "internal/runtime/sys", "OnesCount64"}:                   struct{}{},
	{"ppc64", "internal/runtime/sys", "Prefetch"}:                      struct{}{},
	{"ppc64", "internal/runtime/sys", "PrefetchStreamed"}:              struct{}{},
	{"ppc64", "internal/runtime/sys", "TrailingZeros32"}:               struct{}{},
	{"ppc64", "internal/runtime/sys", "TrailingZeros64"}:               struct{}{},
	{"ppc64", "math", "Abs"}:                                           struct{}{},
	{"ppc64", "math", "Ceil"}:                                          struct{}{},
	{"ppc64", "math", "Copysign"}:                                      struct{}{},
	{"ppc64", "math", "FMA"}:                                           struct{}{},
	{"ppc64", "math", "Floor"}:                                         struct{}{},
	{"ppc64", "math", "Round"}:                                         struct{}{},
	{"ppc64", "math", "Trunc"}:                                         struct{}{},
	{"ppc64", "math", "sqrt"}:                                          struct{}{},
	{"ppc64", "math/big", "mulWW"}:                                     struct{}{},
	{"ppc64", "math/bits", "Add"}:                                      struct{}{},
	{"ppc64", "math/bits", "Add64"}:                                    struct{}{},
	{"ppc64", "math/bits", "Len"}:                                      struct{}{},
	{"ppc64", "math/bits", "Len16"}:                                    struct{}{},
	{"ppc64", "math/bits", "Len32"}:                                    struct{}{},
	{"ppc64", "math/bits", "Len64"}:                                    struct{}{},
	{"ppc64", "math/bits", "Len8"}:                                     struct{}{},
	{"ppc64", "math/bits", "Mul"}:                                      struct{}{},
	{"ppc64", "math/bits", "Mul64"}:                                    struct{}{},
	{"ppc64", "math/bits", "OnesCount16"}:                              struct{}{},
	{"ppc64", "math/bits", "OnesCount32"}:                              struct{}{},
	{"ppc64", "math/bits", "OnesCount64"}:                              struct{}{},
	{"ppc64", "math/bits", "OnesCount8"}:                               struct{}{},
	{"ppc64", "math/bits", "ReverseBytes16"}:                           struct{}{},
	{"ppc64", "math/bits", "ReverseBytes32"}:                           struct{}{},
	{"ppc64", "math/bits", "ReverseBytes64"}:                           struct{}{},
	{"ppc64", "math/bits", "RotateLeft"}:                               struct{}{},
	{"ppc64", "math/bits", "RotateLeft32"}:                             struct{}{},
	{"ppc64", "math/bits", "RotateLeft64"}:                             struct{}{},
	{"ppc64", "math/bits", "Sub"}:                                      struct{}{},
	{"ppc64", "math/bits", "Sub64"}:                                    struct{}{},
	{"ppc64", "math/bits", "TrailingZeros16"}:                          struct{}{},
	{"ppc64", "math/bits", "TrailingZeros32"}:                          struct{}{},
	{"ppc64", "math/bits", "TrailingZeros64"}:                          struct{}{},
	{"ppc64", "runtime", "KeepAlive"}:                                  struct{}{},
	{"ppc64", "runtime", "publicationBarrier"}:                         struct{}{},
	{"ppc64", "runtime", "slicebytetostringtmp"}:                       struct{}{},
	{"ppc64", "sync", "runtime_LoadAcquintptr"}:                        struct{}{},
	{"ppc64", "sync", "runtime_StoreReluintptr"}:                       struct{}{},
	{"ppc64", "sync/atomic", "AddInt32"}:                               struct{}{},
	{"ppc64", "sync/atomic", "AddInt64"}:                               struct{}{},
	{"ppc64", "sync/atomic", "AddUint32"}:                              struct{}{},
	{"ppc64", "sync/atomic", "AddUint64"}:                              struct{}{},
	{"ppc64", "sync/atomic", "AddUintptr"}:                             struct{}{},
	{"ppc64", "sync/atomic", "CompareAndSwapInt32"}:                    struct{}{},
	{"ppc64", "sync/atomic", "CompareAndSwapInt64"}:                    struct{}{},
	{"ppc64", "sync/atomic", "CompareAndSwapUint32"}:                   struct{}{},
	{"ppc64", "sync/atomic", "CompareAndSwapUint64"}:                   struct{}{},
	{"ppc64", "sync/atomic", "CompareAndSwapUintptr"}:                  struct{}{},
	{"ppc64", "sync/atomic", "LoadInt32"}:                              struct{}{},
	{"ppc64", "sync/atomic", "LoadInt64"}:                              struct{}{},
	{"ppc64", "sync/atomic", "LoadPointer"}:                            struct{}{},
	{"ppc64", "sync/atomic", "LoadUint32"}:                             struct{}{},
	{"ppc64", "sync/atomic", "LoadUint64"}:                             struct{}{},
	{"ppc64", "sync/atomic", "LoadUintptr"}:                            struct{}{},
	{"ppc64", "sync/atomic", "StoreInt32"}:                             struct{}{},
	{"ppc64", "sync/atomic", "StoreInt64"}:                             struct{}{},
	{"ppc64", "sync/atomic", "StoreUint32"}:                            struct{}{},
	{"ppc64", "sync/atomic", "StoreUint64"}:                            struct{}{},
	{"ppc64", "sync/atomic", "StoreUintptr"}:                           struct{}{},
	{"ppc64", "sync/atomic", "SwapInt32"}:                              struct{}{},
	{"ppc64", "sync/atomic", "SwapInt64"}:                              struct{}{},
	{"ppc64", "sync/atomic", "SwapUint32"}:                             struct{}{},
	{"ppc64", "sync/atomic", "SwapUint64"}:                             struct{}{},
	{"ppc64", "sync/atomic", "SwapUintptr"}:                            struct{}{},
	{"ppc64le", "internal/runtime/atomic", "And"}:                      struct{}{},
	{"ppc64le", "internal/runtime/atomic", "And8"}:                     struct{}{},
	{"ppc64le", "internal/runtime/atomic", "Cas"}:                      struct{}{},
	{"ppc64le", "internal/runtime/atomic", "Cas64"}:                    struct{}{},
	{"ppc64le", "internal/runtime/atomic", "CasRel"}:                   struct{}{},
	{"ppc64le", "internal/runtime/atomic", "Casint32"}:                 struct{}{},
	{"ppc64le", "internal/runtime/atomic", "Casint64"}:                 struct{}{},
	{"ppc64le", "internal/runtime/atomic", "Casp1"}:                    struct{}{},
	{"ppc64le", "internal/runtime/atomic", "Casuintptr"}:               struct{}{},
	{"ppc64le", "internal/runtime/atomic", "Load"}:                     struct{}{},
	{"ppc64le", "internal/runtime/atomic", "Load64"}:                   struct{}{},
	{"ppc64le", "internal/runtime/atomic", "Load8"}:                    struct{}{},
	{"ppc64le", "internal/runtime/atomic", "LoadAcq"}:                  struct{}{},
	{"ppc64le", "internal/runtime/atomic", "LoadAcq64"}:                struct{}{},
	{"ppc64le", "internal/runtime/atomic", "LoadAcquintptr"}:           struct{}{},
	{"ppc64le", "internal/runtime/atomic", "Loadint32"}:                struct{}{},
	{"ppc64le", "internal/runtime/atomic", "Loadint64"}:                struct{}{},
	{"ppc64le", "internal/runtime/atomic", "Loadp"}:                    struct{}{},
	{"ppc64le", "internal/runtime/atomic", "Loaduint"}:                 struct{}{},
	{"ppc64le", "internal/runtime/atomic", "Loaduintptr"}:              struct{}{},
	{"ppc64le", "internal/runtime/atomic", "Or"}:                       struct{}{},
	{"ppc64le", "internal/runtime/atomic", "Or8"}:                      struct{}{},
	{"ppc64le", "internal/runtime/atomic", "Store"}:                    struct{}{},
	{"ppc64le", "internal/runtime/atomic", "Store64"}:                  struct{}{},
	{"ppc64le", "internal/runtime/atomic", "Store8"}:                   struct{}{},
	{"ppc64le", "internal/runtime/atomic", "StoreRel"}:                 struct{}{},
	{"ppc64le", "internal/runtime/atomic", "StoreRel64"}:               struct{}{},
	{"ppc64le", "internal/runtime/atomic", "StoreReluintptr"}:          struct{}{},
	{"ppc64le", "internal/runtime/atomic", "Storeint32"}:               struct{}{},
	{"ppc64le", "internal/runtime/atomic", "Storeint64"}:               struct{}{},
	{"ppc64le", "internal/runtime/atomic", "Storeuintptr"}:             struct{}{},
	{"ppc64le", "internal/runtime/atomic", "Xadd"}:                     struct{}{},
	{"ppc64le", "internal/runtime/atomic", "Xadd64"}:                   struct{}{},
	{"ppc64le", "internal/runtime/atomic", "Xaddint32"}:                struct{}{},
	{"ppc64le", "internal/runtime/atomic", "Xaddint64"}:                struct{}{},
	{"ppc64le", "internal/runtime/atomic", "Xadduintptr"}:              struct{}{},
	{"ppc64le", "internal/runtime/atomic", "Xchg8"}:                    struct{}{},
	{"ppc64le", "internal/runtime/atomic", "Xchg"}:                     struct{}{},
	{"ppc64le", "internal/runtime/atomic", "Xchg64"}:                   struct{}{},
	{"ppc64le", "internal/runtime/atomic", "Xchgint32"}:                struct{}{},
	{"ppc64le", "internal/runtime/atomic", "Xchgint64"}:                struct{}{},
	{"ppc64le", "internal/runtime/atomic", "Xchguintptr"}:              struct{}{},
	{"ppc64le", "internal/runtime/math", "Add64"}:                      struct{}{},
	{"ppc64le", "internal/runtime/math", "Mul64"}:                      struct{}{},
	{"ppc64le", "internal/runtime/math", "MulUintptr"}:                 struct{}{},
	{"ppc64le", "internal/runtime/sys", "Bswap32"}:                     struct{}{},
	{"ppc64le", "internal/runtime/sys", "Bswap64"}:                     struct{}{},
	{"ppc64le", "internal/runtime/sys", "GetCallerPC"}:                 struct{}{},
	{"ppc64le", "internal/runtime/sys", "GetCallerSP"}:                 struct{}{},
	{"ppc64le", "internal/runtime/sys", "GetClosurePtr"}:               struct{}{},
	{"ppc64le", "internal/runtime/sys", "Len64"}:                       struct{}{},
	{"ppc64le", "internal/runtime/sys", "Len8"}:                        struct{}{},
	{"ppc64le", "internal/runtime/sys", "OnesCount64"}:                 struct{}{},
	{"ppc64le", "internal/runtime/sys", "Prefetch"}:                    struct{}{},
	{"ppc64le", "internal/runtime/sys", "PrefetchStreamed"}:            struct{}{},
	{"ppc64le", "internal/runtime/sys", "TrailingZeros32"}:             struct{}{},
	{"ppc64le", "internal/runtime/sys", "TrailingZeros64"}:             struct{}{},
	{"ppc64le", "math", "Abs"}:                                         struct{}{},
	{"ppc64le", "math", "Ceil"}:                                        struct{}{},
	{"ppc64le", "math", "Copysign"}:                                    struct{}{},
	{"ppc64le", "math", "FMA"}:                                         struct{}{},
	{"ppc64le", "math", "Floor"}:                                       struct{}{},
	{"ppc64le", "math", "Round"}:                                       struct{}{},
	{"ppc64le", "math", "Trunc"}:                                       struct{}{},
	{"ppc64le", "math", "sqrt"}:                                        struct{}{},
	{"ppc64le", "math/big", "mulWW"}:                                   struct{}{},
	{"ppc64le", "math/bits", "Add"}:                                    struct{}{},
	{"ppc64le", "math/bits", "Add64"}:                                  struct{}{},
	{"ppc64le", "math/bits", "Len"}:                                    struct{}{},
	{"ppc64le", "math/bits", "Len16"}:                                  struct{}{},
	{"ppc64le", "math/bits", "Len32"}:                                  struct{}{},
	{"ppc64le", "math/bits", "Len64"}:                                  struct{}{},
	{"ppc64le", "math/bits", "Len8"}:                                   struct{}{},
	{"ppc64le", "math/bits", "Mul"}:                                    struct{}{},
	{"ppc64le", "math/bits", "Mul64"}:                                  struct{}{},
	{"ppc64le", "math/bits", "OnesCount16"}:                            struct{}{},
	{"ppc64le", "math/bits", "OnesCount32"}:                            struct{}{},
	{"ppc64le", "math/bits", "OnesCount64"}:                            struct{}{},
	{"ppc64le", "math/bits", "OnesCount8"}:                             struct{}{},
	{"ppc64le", "math/bits", "ReverseBytes16"}:                         struct{}{},
	{"ppc64le", "math/bits", "ReverseBytes32"}:                         struct{}{},
	{"ppc64le", "math/bits", "ReverseBytes64"}:                         struct{}{},
	{"ppc64le", "math/bits", "RotateLeft"}:                             struct{}{},
	{"ppc64le", "math/bits", "RotateLeft32"}:                           struct{}{},
	{"ppc64le", "math/bits", "RotateLeft64"}:                           struct{}{},
	{"ppc64le", "math/bits", "Sub"}:                                    struct{}{},
	{"ppc64le", "math/bits", "Sub64"}:                                  struct{}{},
	{"ppc64le", "math/bits", "TrailingZeros16"}:                        struct{}{},
	{"ppc64le", "math/bits", "TrailingZeros32"}:                        struct{}{},
	{"ppc64le", "math/bits", "TrailingZeros64"}:                        struct{}{},
	{"ppc64le", "runtime", "KeepAlive"}:                                struct{}{},
	{"ppc64le", "runtime", "publicationBarrier"}:                       struct{}{},
	{"ppc64le", "runtime", "slicebytetostringtmp"}:                     struct{}{},
	{"ppc64le", "sync", "runtime_LoadAcquintptr"}:                      struct{}{},
	{"ppc64le", "sync", "runtime_StoreReluintptr"}:                     struct{}{},
	{"ppc64le", "sync/atomic", "AddInt32"}:                             struct{}{},
	{"ppc64le", "sync/atomic", "AddInt64"}:                             struct{}{},
	{"ppc64le", "sync/atomic", "AddUint32"}:                            struct{}{},
	{"ppc64le", "sync/atomic", "AddUint64"}:                            struct{}{},
	{"ppc64le", "sync/atomic", "AddUintptr"}:                           struct{}{},
	{"ppc64le", "sync/atomic", "CompareAndSwapInt32"}:                  struct{}{},
	{"ppc64le", "sync/atomic", "CompareAndSwapInt64"}:                  struct{}{},
	{"ppc64le", "sync/atomic", "CompareAndSwapUint32"}:                 struct{}{},
	{"ppc64le", "sync/atomic", "CompareAndSwapUint64"}:                 struct{}{},
	{"ppc64le", "sync/atomic", "CompareAndSwapUintptr"}:                struct{}{},
	{"ppc64le", "sync/atomic", "LoadInt32"}:                            struct{}{},
	{"ppc64le", "sync/atomic", "LoadInt64"}:                            struct{}{},
	{"ppc64le", "sync/atomic", "LoadPointer"}:                          struct{}{},
	{"ppc64le", "sync/atomic", "LoadUint32"}:                           struct{}{},
	{"ppc64le", "sync/atomic", "LoadUint64"}:                           struct{}{},
	{"ppc64le", "sync/atomic", "LoadUintptr"}:                          struct{}{},
	{"ppc64le", "sync/atomic", "StoreInt32"}:                           struct{}{},
	{"ppc64le", "sync/atomic", "StoreInt64"}:                           struct{}{},
	{"ppc64le", "sync/atomic", "StoreUint32"}:                          struct{}{},
	{"ppc64le", "sync/atomic", "StoreUint64"}:                          struct{}{},
	{"ppc64le", "sync/atomic", "StoreUintptr"}:                         struct{}{},
	{"ppc64le", "sync/atomic", "SwapInt32"}:                            struct{}{},
	{"ppc64le", "sync/atomic", "SwapInt64"}:                            struct{}{},
	{"ppc64le", "sync/atomic", "SwapUint32"}:                           struct{}{},
	{"ppc64le", "sync/atomic", "SwapUint64"}:                           struct{}{},
	{"ppc64le", "sync/atomic", "SwapUintptr"}:                          struct{}{},
	{"riscv64", "internal/runtime/atomic", "And"}:                      struct{}{},
	{"riscv64", "internal/runtime/atomic", "And8"}:                     struct{}{},
	{"riscv64", "internal/runtime/atomic", "Cas"}:                      struct{}{},
	{"riscv64", "internal/runtime/atomic", "Cas64"}:                    struct{}{},
	{"riscv64", "internal/runtime/atomic", "CasRel"}:                   struct{}{},
	{"riscv64", "internal/runtime/atomic", "Casint32"}:                 struct{}{},
	{"riscv64", "internal/runtime/atomic", "Casint64"}:                 struct{}{},
	{"riscv64", "internal/runtime/atomic", "Casp1"}:                    struct{}{},
	{"riscv64", "internal/runtime/atomic", "Casuintptr"}:               struct{}{},
	{"riscv64", "internal/runtime/atomic", "Load"}:                     struct{}{},
	{"riscv64", "internal/runtime/atomic", "Load64"}:                   struct{}{},
	{"riscv64", "internal/runtime/atomic", "Load8"}:                    struct{}{},
	{"riscv64", "internal/runtime/atomic", "LoadAcq"}:                  struct{}{},
	{"riscv64", "internal/runtime/atomic", "LoadAcq64"}:                struct{}{},
	{"riscv64", "internal/runtime/atomic", "LoadAcquintptr"}:           struct{}{},
	{"riscv64", "internal/runtime/atomic", "Loadint32"}:                struct{}{},
	{"riscv64", "internal/runtime/atomic", "Loadint64"}:                struct{}{},
	{"riscv64", "internal/runtime/atomic", "Loadp"}:                    struct{}{},
	{"riscv64", "internal/runtime/atomic", "Loaduint"}:                 struct{}{},
	{"riscv64", "internal/runtime/atomic", "Loaduintptr"}:              struct{}{},
	{"riscv64", "internal/runtime/atomic", "Or"}:                       struct{}{},
	{"riscv64", "internal/runtime/atomic", "Or8"}:                      struct{}{},
	{"riscv64", "internal/runtime/atomic", "Store"}:                    struct{}{},
	{"riscv64", "internal/runtime/atomic", "Store64"}:                  struct{}{},
	{"riscv64", "internal/runtime/atomic", "Store8"}:                   struct{}{},
	{"riscv64", "internal/runtime/atomic", "StoreRel"}:                 struct{}{},
	{"riscv64", "internal/runtime/atomic", "StoreRel64"}:               struct{}{},
	{"riscv64", "internal/runtime/atomic", "StoreReluintptr"}:          struct{}{},
	{"riscv64", "internal/runtime/atomic", "Storeint32"}:               struct{}{},
	{"riscv64", "internal/runtime/atomic", "Storeint64"}:               struct{}{},
	{"riscv64", "internal/runtime/atomic", "StorepNoWB"}:               struct{}{},
	{"riscv64", "internal/runtime/atomic", "Storeuintptr"}:             struct{}{},
	{"riscv64", "internal/runtime/atomic", "Xadd"}:                     struct{}{},
	{"riscv64", "internal/runtime/atomic", "Xadd64"}:                   struct{}{},
	{"riscv64", "internal/runtime/atomic", "Xaddint32"}:                struct{}{},
	{"riscv64", "internal/runtime/atomic", "Xaddint64"}:                struct{}{},
	{"riscv64", "internal/runtime/atomic", "Xadduintptr"}:              struct{}{},
	{"riscv64", "internal/runtime/atomic", "Xchg"}:                     struct{}{},
	{"riscv64", "internal/runtime/atomic", "Xchg64"}:                   struct{}{},
	{"riscv64", "internal/runtime/atomic", "Xchgint32"}:                struct{}{},
	{"riscv64", "internal/runtime/atomic", "Xchgint64"}:                struct{}{},
	{"riscv64", "internal/runtime/atomic", "Xchguintptr"}:              struct{}{},
	{"riscv64", "internal/runtime/math", "Add64"}:                      struct{}{},
	{"riscv64", "internal/runtime/math", "Mul64"}:                      struct{}{},
	{"riscv64", "internal/runtime/math", "MulUintptr"}:                 struct{}{},
	{"riscv64", "internal/runtime/sys", "GetCallerPC"}:                 struct{}{},
	{"riscv64", "internal/runtime/sys", "GetCallerSP"}:                 struct{}{},
	{"riscv64", "internal/runtime/sys", "GetClosurePtr"}:               struct{}{},
	{"riscv64", "math", "Abs"}:                                         struct{}{},
	{"riscv64", "math", "Copysign"}:                                    struct{}{},
	{"riscv64", "math", "FMA"}:                                         struct{}{},
	{"riscv64", "math", "sqrt"}:                                        struct{}{},
	{"riscv64", "math/big", "mulWW"}:                                   struct{}{},
	{"riscv64", "math/bits", "Add"}:                                    struct{}{},
	{"riscv64", "math/bits", "Add64"}:                                  struct{}{},
	{"riscv64", "math/bits", "Mul"}:                                    struct{}{},
	{"riscv64", "math/bits", "Mul64"}:                                  struct{}{},
	{"riscv64", "math/bits", "RotateLeft"}:                             struct{}{},
	{"riscv64", "math/bits", "RotateLeft16"}:                           struct{}{},
	{"riscv64", "math/bits", "RotateLeft32"}:                           struct{}{},
	{"riscv64", "math/bits", "RotateLeft64"}:                           struct{}{},
	{"riscv64", "math/bits", "RotateLeft8"}:                            struct{}{},
	{"riscv64", "math/bits", "Sub"}:                                    struct{}{},
	{"riscv64", "math/bits", "Sub64"}:                                  struct{}{},
	{"riscv64", "runtime", "KeepAlive"}:                                struct{}{},
	{"riscv64", "runtime", "publicationBarrier"}:                       struct{}{},
	{"riscv64", "runtime", "slicebytetostringtmp"}:                     struct{}{},
	{"riscv64", "sync", "runtime_LoadAcquintptr"}:                      struct{}{},
	{"riscv64", "sync", "runtime_StoreReluintptr"}:                     struct{}{},
	{"riscv64", "sync/atomic", "AddInt32"}:                             struct{}{},
	{"riscv64", "sync/atomic", "AddInt64"}:                             struct{}{},
	{"riscv64", "sync/atomic", "AddUint32"}:                            struct{}{},
	{"riscv64", "sync/atomic", "AddUint64"}:                            struct{}{},
	{"riscv64", "sync/atomic", "AddUintptr"}:                           struct{}{},
	{"riscv64", "sync/atomic", "CompareAndSwapInt32"}:                  struct{}{},
	{"riscv64", "sync/atomic", "CompareAndSwapInt64"}:                  struct{}{},
	{"riscv64", "sync/atomic", "CompareAndSwapUint32"}:                 struct{}{},
	{"riscv64", "sync/atomic", "CompareAndSwapUint64"}:                 struct{}{},
	{"riscv64", "sync/atomic", "CompareAndSwapUintptr"}:                struct{}{},
	{"riscv64", "sync/atomic", "LoadInt32"}:                            struct{}{},
	{"riscv64", "sync/atomic", "LoadInt64"}:                            struct{}{},
	{"riscv64", "sync/atomic", "LoadPointer"}:                          struct{}{},
	{"riscv64", "sync/atomic", "LoadUint32"}:                           struct{}{},
	{"riscv64", "sync/atomic", "LoadUint64"}:                           struct{}{},
	{"riscv64", "sync/atomic", "LoadUintptr"}:                          struct{}{},
	{"riscv64", "sync/atomic", "StoreInt32"}:                           struct{}{},
	{"riscv64", "sync/atomic", "StoreInt64"}:                           struct{}{},
	{"riscv64", "sync/atomic", "StoreUint32"}:                          struct{}{},
	{"riscv64", "sync/atomic", "StoreUint64"}:                          struct{}{},
	{"riscv64", "sync/atomic", "StoreUintptr"}:                         struct{}{},
	{"riscv64", "sync/atomic", "SwapInt32"}:                            struct{}{},
	{"riscv64", "sync/atomic", "SwapInt64"}:                            struct{}{},
	{"riscv64", "sync/atomic", "SwapUint32"}:                           struct{}{},
	{"riscv64", "sync/atomic", "SwapUint64"}:                           struct{}{},
	{"riscv64", "sync/atomic", "SwapUintptr"}:                          struct{}{},
	{"s390x", "internal/runtime/atomic", "And"}:                        struct{}{},
	{"s390x", "internal/runtime/atomic", "And8"}:                       struct{}{},
	{"s390x", "internal/runtime/atomic", "Cas"}:                        struct{}{},
	{"s390x", "internal/runtime/atomic", "Cas64"}:                      struct{}{},
	{"s390x", "internal/runtime/atomic", "CasRel"}:                     struct{}{},
	{"s390x", "internal/runtime/atomic", "Casint32"}:                   struct{}{},
	{"s390x", "internal/runtime/atomic", "Casint64"}:                   struct{}{},
	{"s390x", "internal/runtime/atomic", "Casp1"}:                      struct{}{},
	{"s390x", "internal/runtime/atomic", "Casuintptr"}:                 struct{}{},
	{"s390x", "internal/runtime/atomic", "Load"}:                       struct{}{},
	{"s390x", "internal/runtime/atomic", "Load64"}:                     struct{}{},
	{"s390x", "internal/runtime/atomic", "Load8"}:                      struct{}{},
	{"s390x", "internal/runtime/atomic", "LoadAcq"}:                    struct{}{},
	{"s390x", "internal/runtime/atomic", "LoadAcq64"}:                  struct{}{},
	{"s390x", "internal/runtime/atomic", "LoadAcquintptr"}:             struct{}{},
	{"s390x", "internal/runtime/atomic", "Loadint32"}:                  struct{}{},
	{"s390x", "internal/runtime/atomic", "Loadint64"}:                  struct{}{},
	{"s390x", "internal/runtime/atomic", "Loadp"}:                      struct{}{},
	{"s390x", "internal/runtime/atomic", "Loaduint"}:                   struct{}{},
	{"s390x", "internal/runtime/atomic", "Loaduintptr"}:                struct{}{},
	{"s390x", "internal/runtime/atomic", "Or"}:                         struct{}{},
	{"s390x", "internal/runtime/atomic", "Or8"}:                        struct{}{},
	{"s390x", "internal/runtime/atomic", "Store"}:                      struct{}{},
	{"s390x", "internal/runtime/atomic", "Store64"}:                    struct{}{},
	{"s390x", "internal/runtime/atomic", "Store8"}:                     struct{}{},
	{"s390x", "internal/runtime/atomic", "StoreRel"}:                   struct{}{},
	{"s390x", "internal/runtime/atomic", "StoreRel64"}:                 struct{}{},
	{"s390x", "internal/runtime/atomic", "StoreReluintptr"}:            struct{}{},
	{"s390x", "internal/runtime/atomic", "Storeint32"}:                 struct{}{},
	{"s390x", "internal/runtime/atomic", "Storeint64"}:                 struct{}{},
	{"s390x", "internal/runtime/atomic", "StorepNoWB"}:                 struct{}{},
	{"s390x", "internal/runtime/atomic", "Storeuintptr"}:               struct{}{},
	{"s390x", "internal/runtime/atomic", "Xadd"}:                       struct{}{},
	{"s390x", "internal/runtime/atomic", "Xadd64"}:                     struct{}{},
	{"s390x", "internal/runtime/atomic", "Xaddint32"}:                  struct{}{},
	{"s390x", "internal/runtime/atomic", "Xaddint64"}:                  struct{}{},
	{"s390x", "internal/runtime/atomic", "Xadduintptr"}:                struct{}{},
	{"s390x", "internal/runtime/atomic", "Xchg"}:                       struct{}{},
	{"s390x", "internal/runtime/atomic", "Xchg64"}:                     struct{}{},
	{"s390x", "internal/runtime/atomic", "Xchgint32"}:                  struct{}{},
	{"s390x", "internal/runtime/atomic", "Xchgint64"}:                  struct{}{},
	{"s390x", "internal/runtime/atomic", "Xchguintptr"}:                struct{}{},
	{"s390x", "internal/runtime/math", "Add64"}:                        struct{}{},
	{"s390x", "internal/runtime/math", "Mul64"}:                        struct{}{},
	{"s390x", "internal/runtime/sys", "Bswap32"}:                       struct{}{},
	{"s390x", "internal/runtime/sys", "Bswap64"}:                       struct{}{},
	{"s390x", "internal/runtime/sys", "GetCallerPC"}:                   struct{}{},
	{"s390x", "internal/runtime/sys", "GetCallerSP"}:                   struct{}{},
	{"s390x", "internal/runtime/sys", "GetClosurePtr"}:                 struct{}{},
	{"s390x", "internal/runtime/sys", "Len64"}:                         struct{}{},
	{"s390x", "internal/runtime/sys", "Len8"}:                          struct{}{},
	{"s390x", "internal/runtime/sys", "OnesCount64"}:                   struct{}{},
	{"s390x", "internal/runtime/sys", "TrailingZeros32"}:               struct{}{},
	{"s390x", "internal/runtime/sys", "TrailingZeros64"}:               struct{}{},
	{"s390x", "internal/runtime/sys", "TrailingZeros8"}:                struct{}{},
	{"s390x", "math", "Ceil"}:                                          struct{}{},
	{"s390x", "math", "FMA"}:                                           struct{}{},
	{"s390x", "math", "Floor"}:                                         struct{}{},
	{"s390x", "math", "Round"}:                                         struct{}{},
	{"s390x", "math", "RoundToEven"}:                                   struct{}{},
	{"s390x", "math", "Trunc"}:                                         struct{}{},
	{"s390x", "math", "sqrt"}:                                          struct{}{},
	{"s390x", "math/big", "mulWW"}:                                     struct{}{},
	{"s390x", "math/bits", "Add"}:                                      struct{}{},
	{"s390x", "math/bits", "Add64"}:                                    struct{}{},
	{"s390x", "math/bits", "Len"}:                                      struct{}{},
	{"s390x", "math/bits", "Len16"}:                                    struct{}{},
	{"s390x", "math/bits", "Len32"}:                                    struct{}{},
	{"s390x", "math/bits", "Len64"}:                                    struct{}{},
	{"s390x", "math/bits", "Len8"}:                                     struct{}{},
	{"s390x", "math/bits", "Mul"}:                                      struct{}{},
	{"s390x", "math/bits", "Mul64"}:                                    struct{}{},
	{"s390x", "math/bits", "OnesCount16"}:                              struct{}{},
	{"s390x", "math/bits", "OnesCount32"}:                              struct{}{},
	{"s390x", "math/bits", "OnesCount64"}:                              struct{}{},
	{"s390x", "math/bits", "OnesCount8"}:                               struct{}{},
	{"s390x", "math/bits", "ReverseBytes32"}:                           struct{}{},
	{"s390x", "math/bits", "ReverseBytes64"}:                           struct{}{},
	{"s390x", "math/bits", "RotateLeft"}:                               struct{}{},
	{"s390x", "math/bits", "RotateLeft32"}:                             struct{}{},
	{"s390x", "math/bits", "RotateLeft64"}:                             struct{}{},
	{"s390x", "math/bits", "Sub"}:                         
"""




```