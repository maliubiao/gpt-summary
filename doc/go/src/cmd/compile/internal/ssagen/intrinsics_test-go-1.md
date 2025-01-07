Response: My thinking process to answer the request goes like this:

1. **Understand the Goal:** The user wants to understand the functionality of the provided Go code snippet, which is a test file (`intrinsics_test.go`). The request asks for a breakdown of the code's purpose, potential Go feature implementation, code examples, command-line argument handling (if any), common mistakes, and a final summary of the functionality. The crucial context is that this is part 2 of 2.

2. **Initial Analysis of the Code:** I immediately recognize the code as a Go test file. The presence of `import "testing"` and functions like `TestIntrinsics` and `TestIntrinsicBuilders` confirms this. The core of the code revolves around two maps: `wantIntrinsics` and `intrinsics`.

3. **Deconstructing `wantIntrinsics`:** This map is a key-value store where the key is a tuple of (architecture, package path, function name) and the value is an empty struct. This pattern strongly suggests that `wantIntrinsics` defines a *set* of expected intrinsics for different architectures. The data itself is a long list of these tuples, covering various architectures (amd64, arm64, ppc64, etc.) and Go standard library packages (runtime, sync/atomic, math/bits, etc.).

4. **Deconstructing `TestIntrinsics`:** This test function aims to verify the contents of the `intrinsics` map against the `wantIntrinsics` map.
    * It initializes an `intrinsicBuildConfig`.
    * It calls `initIntrinsics(cfg)`, which is likely the function that populates the `intrinsics` map.
    * There's a conditional block based on `*updateIntrinsics`. This suggests a mechanism to *update* the `wantIntrinsics` data, probably when new intrinsics are added or existing ones change. This is a common pattern in Go's standard library tests.
    * The main part of the test iterates through both `intrinsics` and `wantIntrinsics` to check for missing or unwanted intrinsics. It ensures that the set of actually generated intrinsics matches the expected set.

5. **Deconstructing `TestIntrinsicBuilders`:** This test function checks if specific intrinsics are present for certain architectures *after* calling `initIntrinsics`. It's a more targeted check for the existence of particular intrinsics. It also demonstrates how configuration (like `cfg.goppc64` and `cfg.instrumenting`) might affect the set of available intrinsics.

6. **Inferring Functionality:** Based on the code structure and the names of the maps and functions, I can infer the following:
    * **Intrinsic Generation:** The code is part of the Go compiler's (specifically `cmd/compile/internal/ssagen`) process of generating machine code. "Intrinsics" are highly optimized, architecture-specific implementations of certain Go functions.
    * **Testing Framework:** This file is a test suite to ensure that the compiler correctly identifies and makes available the expected set of intrinsics for different architectures.
    * **Configuration:** The `intrinsicBuildConfig` structure likely holds configuration options that influence the selection of intrinsics.

7. **Providing a Code Example:** To illustrate the concept of intrinsics, I would provide a simple Go function that might have an intrinsic implementation and demonstrate how it's used. The `sync/atomic` package is a good example because it often uses intrinsics for performance.

8. **Addressing Command-line Arguments:** The `*updateIntrinsics` variable strongly suggests a command-line flag. I would explain its purpose and how it's used.

9. **Identifying Potential Mistakes:** A common mistake users could make is when *adding* new intrinsics. They might forget to update the `wantIntrinsics` map, causing the tests to fail.

10. **Formulating the Summary (for Part 2):** Since this is part 2, I need to synthesize the information from this specific snippet. The key takeaway is the testing aspect, ensuring the correct set of intrinsics is generated based on the target architecture.

11. **Review and Refine:** Finally, I review my answer to ensure it's clear, concise, and accurate, addressing all aspects of the user's request. I double-check the terminology and ensure I'm using Go-specific terms correctly. I also ensure the code examples are functional and illustrate the concept effectively.
这是 `go/src/cmd/compile/internal/ssagen/intrinsics_test.go` 文件的一部分，它专注于测试 Go 编译器中**内联函数（intrinsics）**的实现。

**它的功能可以归纳为:**

1. **定义期望的内联函数集合:**  `wantIntrinsics` 这个 `map` 定义了在各种 Go 支持的架构（如 amd64, arm64, ppc64, riscv64, s390x, wasm 等）上，对于特定的包和函数，我们期望编译器能够将其处理为内联函数。

2. **测试内联函数的初始化:** `TestIntrinsics` 函数用于测试 `initIntrinsics` 函数的正确性。`initIntrinsics` 负责根据构建配置（`intrinsicBuildConfig`）初始化全局的 `intrinsics` 映射，该映射存储了实际可用的内联函数。

3. **验证生成的内联函数是否符合预期:** `TestIntrinsics` 会比较 `intrinsics` 中实际生成的内联函数集合与 `wantIntrinsics` 中定义的期望集合。它会检查是否有不应该出现的内联函数，以及是否缺少了期望的内联函数。

4. **测试特定内联构建器是否存在:** `TestIntrinsicBuilders` 函数用于测试在特定架构上，某些关键的内联函数构建器是否被正确初始化。例如，它会检查 `internal/runtime/sys.GetCallerSP` 在所有架构上是否存在内联实现。

**它是什么 Go 语言功能的实现：**

这段代码是 Go 编译器中**内联函数 (intrinsics)** 功能的测试。内联函数是指编译器将函数调用替换为函数体本身，从而减少函数调用的开销，提升程序性能的一种优化手段。  `intrinsics` 在这里特指那些编译器针对特定架构进行了特殊优化的内联函数实现，通常直接映射到硬件指令或高度优化的汇编代码。

**Go 代码举例说明:**

假设 `wantIntrinsics` 中定义了 `amd64` 架构下 `sync/atomic.LoadInt32` 应该被内联。

```go
package main

import (
	"fmt"
	"sync/atomic"
)

func main() {
	var counter int32 = 10
	loadedValue := atomic.LoadInt32(&counter)
	fmt.Println(loadedValue) // Output: 10
}
```

在编译这个程序时，如果内联函数机制正常工作，编译器会将 `atomic.LoadInt32(&counter)` 的调用替换为针对 `amd64` 架构优化的加载指令，而不是进行实际的函数调用。

**代码推理与假设的输入与输出:**

* **假设输入：** 编译目标架构是 `amd64`，并且 `initIntrinsics` 函数被正确调用并填充了 `intrinsics` 映射。
* **`wantIntrinsics` 中包含:** `{"amd64", "sync/atomic", "LoadInt32"}: struct{}{}`
* **`intrinsics` 中包含:** 一个 `intrinsicKey` 对应 `amd64`, `"sync/atomic"`, `"LoadInt32"` 的条目。

* **`TestIntrinsics` 函数的输出：**  如果 `intrinsics` 中存在且仅存在 `wantIntrinsics` 中定义的内联函数，则 `TestIntrinsics` 函数会通过测试，不会有任何 `t.Errorf` 输出。 如果 `intrinsics` 中缺少了某个 `wantIntrinsics` 定义的内联函数，或者多了 `wantIntrinsics` 中没有定义的内联函数，则会输出相应的错误信息。

**命令行参数的具体处理:**

在 `TestIntrinsics` 函数中，有以下代码段：

```go
	if *updateIntrinsics {
		// ...
		return
	}
```

这表明该测试套件支持一个名为 `updateIntrinsics` 的布尔类型的命令行标志。  通常，这种标志会被定义在测试文件的开头，例如：

```go
var updateIntrinsics = flag.Bool("update", false, "update intrinsics")
```

当在运行测试时加上 `-update` 标志（例如 `go test -args -update`），`*updateIntrinsics` 的值会变为 `true`。

**`updateIntrinsics` 标志的作用：**

当设置了 `-update` 标志运行时，`TestIntrinsics` 函数会执行以下操作：

1. 遍历当前 `intrinsics` 映射中实际存在的内联函数。
2. 将这些内联函数的架构、包名和函数名格式化输出到标准输出。
3. **不会执行后续的比较逻辑**，直接返回。

这个机制通常用于更新 `wantIntrinsics` 的内容。 当添加了新的内联函数或者修改了现有的内联函数时，运行带有 `-update` 标志的测试，可以将当前编译器生成的内联函数列表输出出来，开发者可以将这个输出复制到 `wantIntrinsics` 的定义中，从而更新期望的内联函数列表。  之后，不带 `-update` 标志运行测试，就可以验证新的内联函数是否被正确处理。

**归纳一下它的功能 (第 2 部分):**

作为 `go/src/cmd/compile/internal/ssagen/intrinsics_test.go` 的第二部分，这段代码的核心功能是**测试 Go 编译器针对不同架构实现的内联函数机制的正确性**。 它通过维护一个期望的内联函数列表 (`wantIntrinsics`)，并与编译器实际生成的内联函数进行比对，确保编译器能够按预期为各种架构优化特定的函数调用。 此外，它还提供了一个更新期望列表的机制，方便在修改内联函数实现后同步测试用例。

Prompt: 
```
这是路径为go/src/cmd/compile/internal/ssagen/intrinsics_test.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
这是第2部分，共2部分，请归纳一下它的功能

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
	{"s390x", "math/bits", "Sub"}:                                      struct{}{},
	{"s390x", "math/bits", "Sub64"}:                                    struct{}{},
	{"s390x", "math/bits", "TrailingZeros16"}:                          struct{}{},
	{"s390x", "math/bits", "TrailingZeros32"}:                          struct{}{},
	{"s390x", "math/bits", "TrailingZeros64"}:                          struct{}{},
	{"s390x", "math/bits", "TrailingZeros8"}:                           struct{}{},
	{"s390x", "runtime", "KeepAlive"}:                                  struct{}{},
	{"s390x", "runtime", "slicebytetostringtmp"}:                       struct{}{},
	{"s390x", "sync", "runtime_LoadAcquintptr"}:                        struct{}{},
	{"s390x", "sync", "runtime_StoreReluintptr"}:                       struct{}{},
	{"s390x", "sync/atomic", "AddInt32"}:                               struct{}{},
	{"s390x", "sync/atomic", "AddInt64"}:                               struct{}{},
	{"s390x", "sync/atomic", "AddUint32"}:                              struct{}{},
	{"s390x", "sync/atomic", "AddUint64"}:                              struct{}{},
	{"s390x", "sync/atomic", "AddUintptr"}:                             struct{}{},
	{"s390x", "sync/atomic", "CompareAndSwapInt32"}:                    struct{}{},
	{"s390x", "sync/atomic", "CompareAndSwapInt64"}:                    struct{}{},
	{"s390x", "sync/atomic", "CompareAndSwapUint32"}:                   struct{}{},
	{"s390x", "sync/atomic", "CompareAndSwapUint64"}:                   struct{}{},
	{"s390x", "sync/atomic", "CompareAndSwapUintptr"}:                  struct{}{},
	{"s390x", "sync/atomic", "LoadInt32"}:                              struct{}{},
	{"s390x", "sync/atomic", "LoadInt64"}:                              struct{}{},
	{"s390x", "sync/atomic", "LoadPointer"}:                            struct{}{},
	{"s390x", "sync/atomic", "LoadUint32"}:                             struct{}{},
	{"s390x", "sync/atomic", "LoadUint64"}:                             struct{}{},
	{"s390x", "sync/atomic", "LoadUintptr"}:                            struct{}{},
	{"s390x", "sync/atomic", "StoreInt32"}:                             struct{}{},
	{"s390x", "sync/atomic", "StoreInt64"}:                             struct{}{},
	{"s390x", "sync/atomic", "StoreUint32"}:                            struct{}{},
	{"s390x", "sync/atomic", "StoreUint64"}:                            struct{}{},
	{"s390x", "sync/atomic", "StoreUintptr"}:                           struct{}{},
	{"s390x", "sync/atomic", "SwapInt32"}:                              struct{}{},
	{"s390x", "sync/atomic", "SwapInt64"}:                              struct{}{},
	{"s390x", "sync/atomic", "SwapUint32"}:                             struct{}{},
	{"s390x", "sync/atomic", "SwapUint64"}:                             struct{}{},
	{"s390x", "sync/atomic", "SwapUintptr"}:                            struct{}{},
	{"wasm", "internal/runtime/sys", "GetCallerPC"}:                    struct{}{},
	{"wasm", "internal/runtime/sys", "GetCallerSP"}:                    struct{}{},
	{"wasm", "internal/runtime/sys", "GetClosurePtr"}:                  struct{}{},
	{"wasm", "internal/runtime/sys", "Len64"}:                          struct{}{},
	{"wasm", "internal/runtime/sys", "Len8"}:                           struct{}{},
	{"wasm", "internal/runtime/sys", "OnesCount64"}:                    struct{}{},
	{"wasm", "internal/runtime/sys", "TrailingZeros32"}:                struct{}{},
	{"wasm", "internal/runtime/sys", "TrailingZeros64"}:                struct{}{},
	{"wasm", "internal/runtime/sys", "TrailingZeros8"}:                 struct{}{},
	{"wasm", "math", "Abs"}:                                            struct{}{},
	{"wasm", "math", "Ceil"}:                                           struct{}{},
	{"wasm", "math", "Copysign"}:                                       struct{}{},
	{"wasm", "math", "Floor"}:                                          struct{}{},
	{"wasm", "math", "RoundToEven"}:                                    struct{}{},
	{"wasm", "math", "Trunc"}:                                          struct{}{},
	{"wasm", "math", "sqrt"}:                                           struct{}{},
	{"wasm", "math/bits", "Len"}:                                       struct{}{},
	{"wasm", "math/bits", "Len16"}:                                     struct{}{},
	{"wasm", "math/bits", "Len32"}:                                     struct{}{},
	{"wasm", "math/bits", "Len64"}:                                     struct{}{},
	{"wasm", "math/bits", "Len8"}:                                      struct{}{},
	{"wasm", "math/bits", "OnesCount16"}:                               struct{}{},
	{"wasm", "math/bits", "OnesCount32"}:                               struct{}{},
	{"wasm", "math/bits", "OnesCount64"}:                               struct{}{},
	{"wasm", "math/bits", "OnesCount8"}:                                struct{}{},
	{"wasm", "math/bits", "RotateLeft"}:                                struct{}{},
	{"wasm", "math/bits", "RotateLeft32"}:                              struct{}{},
	{"wasm", "math/bits", "RotateLeft64"}:                              struct{}{},
	{"wasm", "math/bits", "TrailingZeros16"}:                           struct{}{},
	{"wasm", "math/bits", "TrailingZeros32"}:                           struct{}{},
	{"wasm", "math/bits", "TrailingZeros64"}:                           struct{}{},
	{"wasm", "math/bits", "TrailingZeros8"}:                            struct{}{},
	{"wasm", "runtime", "KeepAlive"}:                                   struct{}{},
	{"wasm", "runtime", "slicebytetostringtmp"}:                        struct{}{},
}

func TestIntrinsics(t *testing.T) {
	cfg := &intrinsicBuildConfig{
		goppc64: 10,
	}
	initIntrinsics(cfg)

	if *updateIntrinsics {
		var updatedIntrinsics []*testIntrinsicKey
		for ik, _ := range intrinsics {
			updatedIntrinsics = append(updatedIntrinsics, &testIntrinsicKey{ik.arch.Name, ik.pkg, ik.fn})
		}
		slices.SortFunc(updatedIntrinsics, func(a, b *testIntrinsicKey) int {
			if n := strings.Compare(a.archName, b.archName); n != 0 {
				return n
			}
			if n := strings.Compare(a.pkg, b.pkg); n != 0 {
				return n
			}
			return strings.Compare(a.fn, b.fn)
		})
		for _, tik := range updatedIntrinsics {
			fmt.Printf("\t{%q, %q, %q}: struct{}{},\n", tik.archName, tik.pkg, tik.fn)
		}
		return
	}

	gotIntrinsics := make(map[testIntrinsicKey]struct{})
	for ik, _ := range intrinsics {
		gotIntrinsics[testIntrinsicKey{ik.arch.Name, ik.pkg, ik.fn}] = struct{}{}
	}
	for ik, _ := range gotIntrinsics {
		if _, found := wantIntrinsics[ik]; !found {
			t.Errorf("Got unwanted intrinsic %v %v.%v", ik.archName, ik.pkg, ik.fn)
		}
	}

	for ik, _ := range wantIntrinsics {
		if _, found := gotIntrinsics[ik]; !found {
			t.Errorf("Want intrinsic %v %v.%v", ik.archName, ik.pkg, ik.fn)
		}
	}
}

func TestIntrinsicBuilders(t *testing.T) {
	cfg := &intrinsicBuildConfig{}
	initIntrinsics(cfg)

	for _, arch := range sys.Archs {
		if intrinsics.lookup(arch, "internal/runtime/sys", "GetCallerSP") == nil {
			t.Errorf("No intrinsic for internal/runtime/sys.GetCallerSP on arch %v", arch)
		}
	}

	if intrinsics.lookup(sys.ArchAMD64, "runtime", "slicebytetostringtmp") == nil {
		t.Error("No intrinsic for runtime.slicebytetostringtmp")
	}

	if intrinsics.lookup(sys.ArchRISCV64, "runtime", "publicationBarrier") == nil {
		t.Errorf("No intrinsic for runtime.publicationBarrier on arch %v", sys.ArchRISCV64)
	}

	if intrinsics.lookup(sys.ArchAMD64, "internal/runtime/sys", "Bswap32") == nil {
		t.Errorf("No intrinsic for internal/runtime/sys.Bswap32 on arch %v", sys.ArchAMD64)
	}
	if intrinsics.lookup(sys.ArchAMD64, "internal/runtime/sys", "Bswap64") == nil {
		t.Errorf("No intrinsic for internal/runtime/sys.Bswap64 on arch %v", sys.ArchAMD64)
	}

	if intrinsics.lookup(sys.ArchPPC64, "internal/runtime/sys", "Bswap64") != nil {
		t.Errorf("Found intrinsic for internal/runtime/sys.Bswap64 on arch %v", sys.ArchPPC64)
	}

	cfg.goppc64 = 10
	cfg.instrumenting = true

	initIntrinsics(cfg)

	if intrinsics.lookup(sys.ArchAMD64, "runtime", "slicebytetostringtmp") != nil {
		t.Error("Intrinsic incorrectly exists for runtime.slicebytetostringtmp")
	}

	if intrinsics.lookup(sys.ArchPPC64, "internal/runtime/sys", "Bswap64") == nil {
		t.Errorf("No intrinsic for internal/runtime/sys.Bswap64 on arch %v", sys.ArchPPC64)
	}
}

"""




```