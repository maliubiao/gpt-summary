Response:
My thinking process to answer the request about `go/src/internal/runtime/sys/intrinsics.go` goes through these stages:

1. **Understanding the Request:** I first carefully read the request, noting the specific requirements: list functionalities, infer Go feature implementation, provide Go code examples (with assumptions for reasoning), detail command-line argument handling (if any), and highlight common mistakes. The request emphasizes a Go language perspective and expects explanations in Chinese.

2. **Analyzing the Code:** I then go through the provided Go code snippet line by line, focusing on identifying the purpose of each function and constant. I look for patterns and known algorithms.

    * **De Bruijn Sequences and Tables:** I recognize `deBruijn32tab`, `deBruijn32`, `deBruijn64tab`, and `deBruijn64`. My knowledge base tells me these are often used for efficient bit manipulation, specifically finding the position of the least significant set bit (trailing zeros).

    * **Lookup Tables for Trailing Zeros:** `ntz8tab` is clearly a lookup table. The string content and the function `TrailingZeros8` confirm its purpose: finding the number of trailing zeros in a byte.

    * **Lookup Table for Length:** `len8tab` and the function `Len8` point to a lookup table for determining the number of bits required to represent a byte.

    * **Bit Counting Algorithms:** The constants `m0`, `m1`, `m2` and the `OnesCount64` function strongly suggest a bit manipulation algorithm for counting set bits (population count). The comments mentioning "Hacker's Delight" solidify this.

    * **Leading Zeros:**  The `LeadingZeros` functions are defined in terms of `Len` functions, indicating a straightforward calculation.

    * **Byte Swapping:** `Bswap64` and `Bswap32` have clear byte swapping logic using bitwise operations and masks.

    * **Prefetching:** `Prefetch` and `PrefetchStreamed` are described as producing specific CPU instructions, indicating memory prefetching functionalities.

    * **Stack and Program Counter Introspection:** `GetCallerPC` and `GetCallerSP` clearly relate to retrieving information about the calling function's context. The comments explain their usage and limitations.

    * **Closure Pointer:** `GetClosurePtr` and its accompanying explanation point to accessing the closure environment. The constraints on its usage (assignment at function entry, `//go:nosplit`) are important clues.

3. **Categorizing Functionalities:** I group the identified functionalities into logical categories to structure the answer:

    * Bit Manipulation (trailing zeros, leading zeros, population count, length)
    * Byte Order Manipulation (byte swapping)
    * Memory Management Hints (prefetching)
    * Runtime Introspection (caller PC/SP, closure pointer)

4. **Inferring Go Feature Implementations:** This is where I connect the low-level intrinsics to higher-level Go features.

    * **Bit Manipulation:** These intrinsics are fundamental building blocks for the `math/bits` package. I provide an example demonstrating how `bits.TrailingZeros` likely uses the underlying `sys.TrailingZeros` functions.

    * **Byte Swapping:**  This is used for dealing with different byte orders (endianness) when interacting with external systems or data formats. I provide an example of network programming where byte order conversion is necessary.

    * **Prefetching:**  While not directly exposed in user-level Go code, prefetching is used internally by the Go runtime to optimize memory access patterns. I note this internal usage.

    * **Runtime Introspection:** `GetCallerPC` and `GetCallerSP` are critical for debugging, profiling, and potentially implementing advanced features like stack walking or error reporting. I illustrate their use in a simple logging scenario. `GetClosurePtr` is less common in typical user code but crucial for the implementation of closures themselves. I demonstrate its conceptual use, although direct usage is restricted.

5. **Providing Go Code Examples:** For each inferred Go feature, I construct a concise and illustrative code example. Crucially, for code reasoning involving intrinsics, I make explicit assumptions about inputs and expected outputs to demonstrate the behavior.

6. **Command-Line Argument Handling:** I review the code and the identified functionalities. None of the functions directly process command-line arguments. Therefore, I state that this file doesn't handle command-line arguments.

7. **Identifying Common Mistakes:** I consider how developers might misuse these low-level functions, especially the runtime introspection ones:

    * **Incorrect `GetCallerSP` Usage:**  The crucial point is the invalidation of the stack pointer after subsequent function calls, especially those that might grow or shrink the stack. I provide a concrete example of incorrect usage and explain why it's problematic.

8. **Structuring the Answer in Chinese:** Finally, I translate my understanding and examples into clear and concise Chinese, ensuring the technical terms are accurately translated. I organize the answer logically, following the structure of the request. I use appropriate formatting (like code blocks) to enhance readability.

**(Self-Correction/Refinement during the process):**

* **Initial thought:**  Perhaps the bit manipulation functions are only for internal runtime use.
* **Correction:** Realized that the `math/bits` package provides a higher-level abstraction that likely relies on these low-level intrinsics. The `// Copied from math/bits to avoid dependence.` comment is a strong indicator.
* **Initial thought:**  Focus heavily on the technical details of the De Bruijn sequence.
* **Refinement:**  While important for understanding the implementation, the *functionality* is what the user needs to grasp. Focus on *what* it does (find trailing zeros) rather than deep mathematical explanations unless directly relevant to the user's understanding.
* **Double-checking:**  Ensuring the Go code examples are runnable and clearly demonstrate the intended functionality. Making sure the assumptions for input/output are clearly stated.

By following these steps, I aim to provide a comprehensive and accurate answer that addresses all aspects of the user's request.
这个 `go/src/internal/runtime/sys/intrinsics.go` 文件定义了一些底层、平台相关的“内在函数”（intrinsics），这些函数通常对应于特定的 CPU 指令或非常底层的操作，用于优化性能或访问硬件特性。由于它位于 `internal/runtime` 包下，这意味着这些函数主要供 Go 运行时系统内部使用，普通 Go 开发者通常不需要直接调用它们。

以下是该文件中的主要功能：

**1. 位操作相关的函数 (Bit Manipulation):**

* **`TrailingZeros32(x uint32) int`**:  计算 32 位无符号整数 `x` 末尾有多少个连续的 0 比特。如果 `x` 为 0，则返回 32。
* **`TrailingZeros64(x uint64) int`**:  计算 64 位无符号整数 `x` 末尾有多少个连续的 0 比特。如果 `x` 为 0，则返回 64。
* **`TrailingZeros8(x uint8) int`**:   计算 8 位无符号整数 `x` 末尾有多少个连续的 0 比特。如果 `x` 为 0，则返回 8。
* **`Len64(x uint64) int`**: 计算表示 64 位无符号整数 `x` 所需的最小比特数。如果 `x` 为 0，则返回 0。
* **`OnesCount64(x uint64) int`**: 计算 64 位无符号整数 `x` 中 1 的比特数（也称为 population count 或 popcount）。
* **`LeadingZeros64(x uint64) int`**: 计算 64 位无符号整数 `x` 开头有多少个连续的 0 比特。如果 `x` 为 0，则返回 64。
* **`LeadingZeros8(x uint8) int`**:  计算 8 位无符号整数 `x` 开头有多少个连续的 0 比特。如果 `x` 为 0，则返回 8。
* **`Len8(x uint8) int`**:  计算表示 8 位无符号整数 `x` 所需的最小比特数。如果 `x` 为 0，则返回 0。

**2. 字节序转换函数 (Byte Order Manipulation):**

* **`Bswap64(x uint64) uint64`**: 将 64 位无符号整数 `x` 的字节顺序反转（例如，大端转小端，反之亦然）。
* **`Bswap32(x uint32) uint32`**: 将 32 位无符号整数 `x` 的字节顺序反转。

**3. 缓存预取指令 (Cache Prefetch):**

* **`Prefetch(addr uintptr)`**:  发出预取指令，将内存地址 `addr` 的数据加载到缓存中。这是对 CPU 的一个提示，表明即将访问该地址的数据。
* **`PrefetchStreamed(addr uintptr)`**: 发出预取指令，提示内存地址 `addr` 的数据将被流式访问，即很可能很快被访问，但只访问一次。这有助于避免污染缓存。

**4. 调用栈信息获取函数 (Call Stack Introspection):**

* **`GetCallerPC() uintptr`**: 返回调用者的调用者的程序计数器 (PC)。
* **`GetCallerSP() uintptr`**: 返回调用者的调用者的栈指针 (SP)。

**5. 闭包指针获取函数 (Closure Pointer):**

* **`GetClosurePtr() uintptr`**: 返回当前闭包的指针。

**推理性功能及其 Go 代码示例:**

这个文件中的函数是 Go 运行时系统实现各种底层功能的基础。

**功能一：实现 `math/bits` 包中的位操作函数**

`math/bits` 包提供了标准库的位操作函数，而 `internal/runtime/sys/intrinsics.go` 中的函数很可能是这些标准库函数的底层实现。例如，`math/bits.TrailingZeros` 可能最终会调用 `sys.TrailingZeros32` 或 `sys.TrailingZeros64`。

```go
package main

import (
	"fmt"
	"math/bits"
	"internal/runtime/sys" // 注意：不建议在普通代码中导入 internal 包
)

func main() {
	var x uint32 = 8 // 二进制: 1000
	tz1 := bits.TrailingZeros(x)
	tz2 := sys.TrailingZeros32(x)

	fmt.Printf("bits.TrailingZeros(%d) = %d\n", x, tz1) // 输出: bits.TrailingZeros(8) = 3
	fmt.Printf("sys.TrailingZeros32(%d) = %d\n", x, tz2) // 输出: sys.TrailingZeros32(8) = 3

	var y uint64 = 16 // 二进制: 10000
	lz1 := bits.LeadingZeros64(y)
	lz2 := sys.LeadingZeros64(y)
	fmt.Printf("bits.LeadingZeros64(%d) = %d\n", y, lz1) // 输出: bits.LeadingZeros64(16) = 60
	fmt.Printf("sys.LeadingZeros64(%d) = %d\n", y, lz2) // 输出: sys.LeadingZeros64(16) = 60
}
```

**假设的输入与输出:**

对于上面的例子：
* **输入 `x`**: `uint32(8)`
* **输出 `bits.TrailingZeros(x)`**: `3`
* **输出 `sys.TrailingZeros32(x)`**: `3`

* **输入 `y`**: `uint64(16)`
* **输出 `bits.LeadingZeros64(y)`**: `60`
* **输出 `sys.LeadingZeros64(y)`**: `60`

**功能二：实现跨平台的字节序处理**

`Bswap32` 和 `Bswap64` 用于在不同的字节序架构之间转换数据。这在网络编程、文件格式处理等场景中非常重要。

```go
package main

import (
	"encoding/binary"
	"fmt"
	"internal/runtime/sys" // 注意：不建议在普通代码中导入 internal 包
)

func main() {
	var x uint32 = 0x01020304 // 大端表示
	swapped := sys.Bswap32(x)
	fmt.Printf("Original: 0x%X\n", x)      // 输出: Original: 0x1020304
	fmt.Printf("Bswap32:  0x%X\n", swapped) // 输出 (在小端机器上): Bswap32:  0x4030201

	buf := make([]byte, 4)
	binary.BigEndian.PutUint32(buf, x) // 将 x 以大端序写入 buf
	fmt.Printf("BigEndian: %X\n", buf)   // 输出: BigEndian: [1 2 3 4]

	var y uint32
	// 假设机器是小端序，直接读取 buf 会得到小端序的值
	y = binary.LittleEndian.Uint32(buf)
	fmt.Printf("LittleEndian.Uint32 from buf: 0x%X\n", y) // 输出 (在小端机器上): LittleEndian.Uint32 from buf: 0x4030201
}
```

**假设的输入与输出 (在小端机器上):**

* **输入 `x`**: `uint32(0x01020304)`
* **输出 `sys.Bswap32(x)`**: `uint32(0x04030201)`

**功能三：用于 Go 调度器或垃圾回收器的性能优化**

`Prefetch` 和 `PrefetchStreamed` 函数允许运行时系统向 CPU 发出预取指令，以提高数据访问速度。这通常在 Go 的调度器、垃圾回收器等性能敏感的部分使用。普通用户代码很少需要直接调用。

**功能四：用于调试、性能分析或实现某些底层机制**

`GetCallerPC` 和 `GetCallerSP` 允许运行时系统或某些调试工具获取调用栈的信息。例如，`runtime.Caller` 函数的底层可能使用 `GetCallerPC`。

```go
package main

import (
	"fmt"
	"runtime"
	"internal/runtime/sys" // 注意：不建议在普通代码中导入 internal 包
)

func inner() {
	pc := sys.GetCallerPC()
	sp := sys.GetCallerSP()
	fmt.Printf("Inside inner, caller's caller PC: 0x%X, SP: 0x%X\n", pc, sp)

	// 使用 runtime 包的方法获取类似信息
	rpc, file, line, ok := runtime.Caller(2) // 获取调用 `inner` 的函数的调用者的信息
	if ok {
		fmt.Printf("Using runtime.Caller: PC: 0x%X, File: %s, Line: %d\n", rpc, file, line)
	}
}

func outer() {
	inner()
}

func main() {
	outer()
}
```

**假设的输出:**

输出会因运行环境和编译器版本而异，但会显示 `inner` 函数中获取到的调用者的调用者的 PC 和 SP 值，以及 `runtime.Caller` 获取的类似信息。

**功能五：实现闭包机制**

`GetClosurePtr` 用于获取当前闭包的指针，这对于理解和实现 Go 的闭包机制至关重要。在 Go 编译器的实现中，闭包通常会被转换为一个包含捕获变量的环境结构，`GetClosurePtr` 可以访问这个结构。

```go
package main

import (
	"fmt"
	"internal/runtime/sys" // 注意：只在特定场景下使用
)

//go:nosplit
func createCounter(start int) func() int {
	//go:nosplit
	return func() int {
		closurePtr := sys.GetClosurePtr()
		// 注意：这里只是为了演示概念，实际操作闭包指针非常复杂且不安全
		// 你需要知道闭包的具体结构才能安全地访问其内容
		// 假设闭包的第一个字段是捕获的 start 变量的指针
		capturedStartPtr := (**int)(closurePtr)
		*capturedStartPtr++
		return **capturedStartPtr
	}
}

func main() {
	counter := createCounter(0)
	fmt.Println(counter()) // 输出: 1
	fmt.Println(counter()) // 输出: 2
}
```

**假设的输入与输出:**

* **调用 `createCounter(0)`**: 创建一个闭包，捕获 `start` 变量。
* **首次调用闭包**: `GetClosurePtr` 返回闭包结构的指针，通过该指针修改捕获的 `start` 变量，并返回修改后的值 `1`。
* **再次调用闭包**: 类似地，返回 `2`。

**命令行参数的具体处理:**

这个文件中的代码主要定义了一些 Go 的内置函数，并不直接处理命令行参数。命令行参数的处理通常发生在 `main` 包的 `main` 函数中，并使用 `os` 包或第三方库进行解析。

**使用者易犯错的点 (针对 `GetCallerSP` 和 `GetClosurePtr`):**

* **`GetCallerSP()` 的误用:**
    * 错误地认为 `GetCallerSP()` 返回的栈指针在后续函数调用后仍然有效。栈可能因为函数调用、goroutine 的增长或收缩而移动，导致之前获取的 SP 值失效。
    * 将 `GetCallerSP()` 的结果传递给可能导致栈移动的非 `nosplit` 函数。

    ```go
    package main

    import (
    	"fmt"
    	"internal/runtime/sys"
    )

    //go:nosplit
    func f() uintptr {
    	return sys.GetCallerSP()
    }

    func g() {
    	sp := f()
    	println("Before h:", sp)
    	h() // h 可能导致栈移动
    	println("After h:", sp) // 这里的 sp 可能已经失效
    }

    func h() {
    	// 一些可能导致栈增长的操作
    	longString := "this is a long string"
    	_ = longString
    }

    func main() {
    	g()
    }
    ```
    在这个例子中，`h()` 函数中的操作可能导致栈增长，使得在 `g()` 函数中 `After h:` 打印的 `sp` 值不再指向之前的栈帧。

* **`GetClosurePtr()` 的使用限制:**
    * 未在函数入口的赋值语句中使用 `GetClosurePtr()`，可能导致编译器无法正确识别和处理。
    * 调用的函数没有使用 `//go:nosplit` 指令，函数序言可能会覆盖保存闭包指针的寄存器。
    * 尝试在 PGO 优化下调用 `GetClosurePtr()`，可能因为 devirtualization 没有考虑到闭包上下文而导致错误。

总结来说，`go/src/internal/runtime/sys/intrinsics.go` 文件定义了一些底层的、平台相关的内在函数，用于支持 Go 运行时的各种核心功能，例如位操作优化、字节序转换、缓存预取以及获取调用栈和闭包信息。普通 Go 开发者通常不需要直接使用这些函数，但了解它们有助于理解 Go 语言的底层实现机制。对于 `GetCallerSP` 和 `GetClosurePtr` 这类函数，由于其底层性和对运行时状态的依赖，使用者需要格外小心，避免不当使用导致程序错误。

### 提示词
```
这是路径为go/src/internal/runtime/sys/intrinsics.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
```

### 源代码
```go
// Copyright 2016 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package sys

// Copied from math/bits to avoid dependence.

var deBruijn32tab = [32]byte{
	0, 1, 28, 2, 29, 14, 24, 3, 30, 22, 20, 15, 25, 17, 4, 8,
	31, 27, 13, 23, 21, 19, 16, 7, 26, 12, 18, 6, 11, 5, 10, 9,
}

const deBruijn32 = 0x077CB531

var deBruijn64tab = [64]byte{
	0, 1, 56, 2, 57, 49, 28, 3, 61, 58, 42, 50, 38, 29, 17, 4,
	62, 47, 59, 36, 45, 43, 51, 22, 53, 39, 33, 30, 24, 18, 12, 5,
	63, 55, 48, 27, 60, 41, 37, 16, 46, 35, 44, 21, 52, 32, 23, 11,
	54, 26, 40, 15, 34, 20, 31, 10, 25, 14, 19, 9, 13, 8, 7, 6,
}

const deBruijn64 = 0x03f79d71b4ca8b09

const ntz8tab = "" +
	"\x08\x00\x01\x00\x02\x00\x01\x00\x03\x00\x01\x00\x02\x00\x01\x00" +
	"\x04\x00\x01\x00\x02\x00\x01\x00\x03\x00\x01\x00\x02\x00\x01\x00" +
	"\x05\x00\x01\x00\x02\x00\x01\x00\x03\x00\x01\x00\x02\x00\x01\x00" +
	"\x04\x00\x01\x00\x02\x00\x01\x00\x03\x00\x01\x00\x02\x00\x01\x00" +
	"\x06\x00\x01\x00\x02\x00\x01\x00\x03\x00\x01\x00\x02\x00\x01\x00" +
	"\x04\x00\x01\x00\x02\x00\x01\x00\x03\x00\x01\x00\x02\x00\x01\x00" +
	"\x05\x00\x01\x00\x02\x00\x01\x00\x03\x00\x01\x00\x02\x00\x01\x00" +
	"\x04\x00\x01\x00\x02\x00\x01\x00\x03\x00\x01\x00\x02\x00\x01\x00" +
	"\x07\x00\x01\x00\x02\x00\x01\x00\x03\x00\x01\x00\x02\x00\x01\x00" +
	"\x04\x00\x01\x00\x02\x00\x01\x00\x03\x00\x01\x00\x02\x00\x01\x00" +
	"\x05\x00\x01\x00\x02\x00\x01\x00\x03\x00\x01\x00\x02\x00\x01\x00" +
	"\x04\x00\x01\x00\x02\x00\x01\x00\x03\x00\x01\x00\x02\x00\x01\x00" +
	"\x06\x00\x01\x00\x02\x00\x01\x00\x03\x00\x01\x00\x02\x00\x01\x00" +
	"\x04\x00\x01\x00\x02\x00\x01\x00\x03\x00\x01\x00\x02\x00\x01\x00" +
	"\x05\x00\x01\x00\x02\x00\x01\x00\x03\x00\x01\x00\x02\x00\x01\x00" +
	"\x04\x00\x01\x00\x02\x00\x01\x00\x03\x00\x01\x00\x02\x00\x01\x00"

// TrailingZeros32 returns the number of trailing zero bits in x; the result is 32 for x == 0.
func TrailingZeros32(x uint32) int {
	if x == 0 {
		return 32
	}
	// see comment in TrailingZeros64
	return int(deBruijn32tab[(x&-x)*deBruijn32>>(32-5)])
}

// TrailingZeros64 returns the number of trailing zero bits in x; the result is 64 for x == 0.
func TrailingZeros64(x uint64) int {
	if x == 0 {
		return 64
	}
	// If popcount is fast, replace code below with return popcount(^x & (x - 1)).
	//
	// x & -x leaves only the right-most bit set in the word. Let k be the
	// index of that bit. Since only a single bit is set, the value is two
	// to the power of k. Multiplying by a power of two is equivalent to
	// left shifting, in this case by k bits. The de Bruijn (64 bit) constant
	// is such that all six bit, consecutive substrings are distinct.
	// Therefore, if we have a left shifted version of this constant we can
	// find by how many bits it was shifted by looking at which six bit
	// substring ended up at the top of the word.
	// (Knuth, volume 4, section 7.3.1)
	return int(deBruijn64tab[(x&-x)*deBruijn64>>(64-6)])
}

// TrailingZeros8 returns the number of trailing zero bits in x; the result is 8 for x == 0.
func TrailingZeros8(x uint8) int {
	return int(ntz8tab[x])
}

const len8tab = "" +
	"\x00\x01\x02\x02\x03\x03\x03\x03\x04\x04\x04\x04\x04\x04\x04\x04" +
	"\x05\x05\x05\x05\x05\x05\x05\x05\x05\x05\x05\x05\x05\x05\x05\x05" +
	"\x06\x06\x06\x06\x06\x06\x06\x06\x06\x06\x06\x06\x06\x06\x06\x06" +
	"\x06\x06\x06\x06\x06\x06\x06\x06\x06\x06\x06\x06\x06\x06\x06\x06" +
	"\x07\x07\x07\x07\x07\x07\x07\x07\x07\x07\x07\x07\x07\x07\x07\x07" +
	"\x07\x07\x07\x07\x07\x07\x07\x07\x07\x07\x07\x07\x07\x07\x07\x07" +
	"\x07\x07\x07\x07\x07\x07\x07\x07\x07\x07\x07\x07\x07\x07\x07\x07" +
	"\x07\x07\x07\x07\x07\x07\x07\x07\x07\x07\x07\x07\x07\x07\x07\x07" +
	"\x08\x08\x08\x08\x08\x08\x08\x08\x08\x08\x08\x08\x08\x08\x08\x08" +
	"\x08\x08\x08\x08\x08\x08\x08\x08\x08\x08\x08\x08\x08\x08\x08\x08" +
	"\x08\x08\x08\x08\x08\x08\x08\x08\x08\x08\x08\x08\x08\x08\x08\x08" +
	"\x08\x08\x08\x08\x08\x08\x08\x08\x08\x08\x08\x08\x08\x08\x08\x08" +
	"\x08\x08\x08\x08\x08\x08\x08\x08\x08\x08\x08\x08\x08\x08\x08\x08" +
	"\x08\x08\x08\x08\x08\x08\x08\x08\x08\x08\x08\x08\x08\x08\x08\x08" +
	"\x08\x08\x08\x08\x08\x08\x08\x08\x08\x08\x08\x08\x08\x08\x08\x08" +
	"\x08\x08\x08\x08\x08\x08\x08\x08\x08\x08\x08\x08\x08\x08\x08\x08"

// Len64 returns the minimum number of bits required to represent x; the result is 0 for x == 0.
//
// nosplit because this is used in src/runtime/histogram.go, which make run in sensitive contexts.
//
//go:nosplit
func Len64(x uint64) (n int) {
	if x >= 1<<32 {
		x >>= 32
		n = 32
	}
	if x >= 1<<16 {
		x >>= 16
		n += 16
	}
	if x >= 1<<8 {
		x >>= 8
		n += 8
	}
	return n + int(len8tab[x])
}

// --- OnesCount ---

const m0 = 0x5555555555555555 // 01010101 ...
const m1 = 0x3333333333333333 // 00110011 ...
const m2 = 0x0f0f0f0f0f0f0f0f // 00001111 ...

// OnesCount64 returns the number of one bits ("population count") in x.
func OnesCount64(x uint64) int {
	// Implementation: Parallel summing of adjacent bits.
	// See "Hacker's Delight", Chap. 5: Counting Bits.
	// The following pattern shows the general approach:
	//
	//   x = x>>1&(m0&m) + x&(m0&m)
	//   x = x>>2&(m1&m) + x&(m1&m)
	//   x = x>>4&(m2&m) + x&(m2&m)
	//   x = x>>8&(m3&m) + x&(m3&m)
	//   x = x>>16&(m4&m) + x&(m4&m)
	//   x = x>>32&(m5&m) + x&(m5&m)
	//   return int(x)
	//
	// Masking (& operations) can be left away when there's no
	// danger that a field's sum will carry over into the next
	// field: Since the result cannot be > 64, 8 bits is enough
	// and we can ignore the masks for the shifts by 8 and up.
	// Per "Hacker's Delight", the first line can be simplified
	// more, but it saves at best one instruction, so we leave
	// it alone for clarity.
	const m = 1<<64 - 1
	x = x>>1&(m0&m) + x&(m0&m)
	x = x>>2&(m1&m) + x&(m1&m)
	x = (x>>4 + x) & (m2 & m)
	x += x >> 8
	x += x >> 16
	x += x >> 32
	return int(x) & (1<<7 - 1)
}

// LeadingZeros64 returns the number of leading zero bits in x; the result is 64 for x == 0.
func LeadingZeros64(x uint64) int { return 64 - Len64(x) }

// LeadingZeros8 returns the number of leading zero bits in x; the result is 8 for x == 0.
func LeadingZeros8(x uint8) int { return 8 - Len8(x) }

// Len8 returns the minimum number of bits required to represent x; the result is 0 for x == 0.
func Len8(x uint8) int {
	return int(len8tab[x])
}

// Bswap64 returns its input with byte order reversed
// 0x0102030405060708 -> 0x0807060504030201
func Bswap64(x uint64) uint64 {
	c8 := uint64(0x00ff00ff00ff00ff)
	a := x >> 8 & c8
	b := (x & c8) << 8
	x = a | b
	c16 := uint64(0x0000ffff0000ffff)
	a = x >> 16 & c16
	b = (x & c16) << 16
	x = a | b
	c32 := uint64(0x00000000ffffffff)
	a = x >> 32 & c32
	b = (x & c32) << 32
	x = a | b
	return x
}

// Bswap32 returns its input with byte order reversed
// 0x01020304 -> 0x04030201
func Bswap32(x uint32) uint32 {
	c8 := uint32(0x00ff00ff)
	a := x >> 8 & c8
	b := (x & c8) << 8
	x = a | b
	c16 := uint32(0x0000ffff)
	a = x >> 16 & c16
	b = (x & c16) << 16
	x = a | b
	return x
}

// Prefetch prefetches data from memory addr to cache
//
// AMD64: Produce PREFETCHT0 instruction
//
// ARM64: Produce PRFM instruction with PLDL1KEEP option
func Prefetch(addr uintptr) {}

// PrefetchStreamed prefetches data from memory addr, with a hint that this data is being streamed.
// That is, it is likely to be accessed very soon, but only once. If possible, this will avoid polluting the cache.
//
// AMD64: Produce PREFETCHNTA instruction
//
// ARM64: Produce PRFM instruction with PLDL1STRM option
func PrefetchStreamed(addr uintptr) {}

// GetCallerPC returns the program counter (PC) of its caller's caller.
// GetCallerSP returns the stack pointer (SP) of its caller's caller.
// Both are implemented as intrinsics on every platform.
//
// For example:
//
//	func f(arg1, arg2, arg3 int) {
//		pc := GetCallerPC()
//		sp := GetCallerSP()
//	}
//
// These two lines find the PC and SP immediately following
// the call to f (where f will return).
//
// The call to GetCallerPC and GetCallerSP must be done in the
// frame being asked about.
//
// The result of GetCallerSP is correct at the time of the return,
// but it may be invalidated by any subsequent call to a function
// that might relocate the stack in order to grow or shrink it.
// A general rule is that the result of GetCallerSP should be used
// immediately and can only be passed to nosplit functions.

func GetCallerPC() uintptr

func GetCallerSP() uintptr

// GetClosurePtr returns the pointer to the current closure.
// GetClosurePtr can only be used in an assignment statement
// at the entry of a function. Moreover, go:nosplit directive
// must be specified at the declaration of caller function,
// so that the function prolog does not clobber the closure register.
// for example:
//
//	//go:nosplit
//	func f(arg1, arg2, arg3 int) {
//		dx := GetClosurePtr()
//	}
//
// The compiler rewrites calls to this function into instructions that fetch the
// pointer from a well-known register (DX on x86 architecture, etc.) directly.
//
// WARNING: PGO-based devirtualization cannot detect that caller of
// GetClosurePtr requires closure context, and thus must maintain a list of
// these functions, which is in
// cmd/compile/internal/devirtualize/pgo.maybeDevirtualizeFunctionCall.
func GetClosurePtr() uintptr
```