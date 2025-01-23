Response:
Let's break down the thought process for analyzing this Go assembly code.

1. **Understand the Context:** The first and most crucial step is to recognize where this code comes from: `go/src/crypto/internal/fips140/sha256/_asm/sha256block_amd64_avx2.go`. This tells us a lot:
    * **`crypto`:**  It's related to cryptographic operations.
    * **`internal`:** It's an internal package, likely not meant for direct external use.
    * **`fips140`:** This strongly suggests it's a FIPS 140-2 compliant implementation of something. FIPS 140-2 is a US government standard for cryptographic modules.
    * **`sha256`:**  This clearly indicates the code is implementing the SHA-256 hash algorithm.
    * **`_asm`:** This means the code is written in assembly language (using the `avo` library for Go-style assembly generation).
    * **`amd64_avx2`:**  This specifies the target architecture and instruction set: 64-bit AMD/Intel processors with AVX2 support.
    * **`.go`:** Despite being assembly, the code is embedded within a Go file using the `avo` library.

2. **Identify the Core Function:** The presence of a function named `blockAVX2()` and the comment mentioning "AVX2 version by Intel, same algorithm as code in Linux kernel" strongly points to this function being the main implementation of the SHA-256 block processing using AVX2 instructions.

3. **High-Level Functionality (Initial Guess):** Based on the context, the primary function is likely to take a block of data and the current hash state as input and update the hash state according to the SHA-256 algorithm, optimized with AVX2 instructions.

4. **Examine the `blockAVX2` Function:**
    * **`Implement("blockAVX2")`:**  This `avo` directive indicates the start of the assembly implementation for the Go function `blockAVX2`.
    * **`AllocLocal(536)`:** This allocates stack space, suggesting the function needs local variables.
    * **`Load(Param("dig"), CTX)` and `Load(Param("p").Base(), INP)`:**  These load function parameters into registers. "dig" likely refers to the digest (hash state), and "p" likely refers to the input data.
    * **`Load(Param("p").Len(), NUM_BYTES)`:** Loads the length of the input data.
    * **`LEAQ(Mem{Base: INP, Index: NUM_BYTES, Scale: 1, Disp: -64}, NUM_BYTES)`:** Calculates the pointer to the last block of data.
    * **`CMPQ(NUM_BYTES, INP)` and `JE(LabelRef("avx2_only_one_block"))`:** Checks if there's only one block of data.
    * **Loading Digest:** The lines `MOVL(CTX.Offset(0), a)`, `MOVL(CTX.Offset(4), b)`, etc., load the eight 32-bit words of the current hash digest into registers `a` through `h`.
    * **Loops and Labels:** The presence of labels like `avx2_loop0`, `avx2_loop1`, etc., suggests the core of the algorithm involves iterative processing of the input data. The comments within these loops ("at each iteration works with one block (512 bit)") confirm this.
    * **`done_hash()`:**  This label and the `RET()` instruction indicate the function's exit point.

5. **Analyze the Loops (Focusing on Key Operations):**
    * **`avx2_loop0`:**  Loads 64 bytes (4 x 16-byte AVX2 registers) of input data, performs byte swapping (`VPSHUFB`) to convert from little-endian to big-endian, and transposes data. This prepares the data for the SHA-256 rounds.
    * **`avx2_loop1`:** This loop seems to perform the main SHA-256 round operations and scheduling. The calls to `roundAndSchedN0`, `roundAndSchedN1`, etc., are strong indicators of the SHA-256 round functions. The "scheduling" part refers to the expansion of the 512-bit input block into 64 32-bit words.
    * **`avx2_loop2`:**  Processes the last 16 rounds of SHA-256 without further scheduling, using `doRoundN0`, `doRoundN1`, etc.
    * **`avx2_loop3`:** Handles the case where there are more than two blocks, reusing the scheduled results from the previous block.
    * **`avx2_do_last_block`:** Handles the final block of data, which might be padded.

6. **Identify Key AVX2 Instructions:** The use of instructions like `VMOVDQU`, `VPSHUFB`, `VPERM2I128`, `VPADDD`, `VPSRLD`, `VPSLLD`, `VPOR`, and `VPXOR` confirms the AVX2 optimization. These instructions allow for parallel processing of data, significantly speeding up the SHA-256 computation.

7. **Infer Go Functionality:** Based on the assembly code's operations, we can infer that the corresponding Go function `blockAVX2` is responsible for processing one or more 64-byte blocks of data using the SHA-256 algorithm, leveraging AVX2 instructions for performance.

8. **Construct a Go Example:**  To illustrate the functionality, we need a Go example that uses a hypothetical `blockAVX2` function. Since the provided code is assembly, we need to imagine how it would be called from Go. It would likely take the current hash state (an array of 8 `uint32`) and a data block (`[]byte`) as input.

9. **Identify Potential Pitfalls:**  Given that this is a low-level, optimized implementation, potential errors could arise from:
    * **Incorrect input size:** The AVX2 implementation likely expects input in multiples of the block size (64 bytes).
    * **Endianness issues:** The code explicitly handles byte swapping, but if the calling code doesn't provide data in the expected endianness, it could lead to incorrect results.
    * **State management:**  Incorrectly managing the hash state between calls to the block processing function could corrupt the hash.

10. **Refine the Explanation:**  Organize the findings into clear sections (functionality, Go implementation, command-line arguments (not applicable here), common mistakes). Use clear and concise language, explaining the assembly concepts in a way that is understandable to someone familiar with Go but perhaps less so with assembly.

**Self-Correction/Refinement During the Process:**

* **Initial thought:** Maybe the `main` package indicates this is an executable. **Correction:** The presence of `Implement("blockAVX2")` suggests this is meant to be part of a larger package, and `main` is likely just for testing/building the assembly.
* **Uncertainty about parameters:**  The `Param("dig")` and `Param("p")` are `avo` constructs. **Refinement:** Infer their meaning based on how they are used. "dig" is loaded into `CTX` and used to access the hash state, so it's likely the current digest. "p" is loaded into `INP` and used to access the input data.
* **Figuring out the loops:** Initially, the loop structure might seem complex. **Refinement:** By looking at the `CMPQ` instructions and the jump labels (`JB`, `JA`), the loop conditions and flow become clearer. The comments within the loops are also very helpful.
* **Understanding `SRND`:** Seeing `SRND = RSI // SRND is same register as CTX` was initially confusing. **Refinement:**  Realize that registers are being reused to save resources. `SRND` is used as a loop counter, and since the digest isn't needed during the inner loops, the same register can be used.

By following these steps of contextual understanding, code examination, inference, and refinement, we can arrive at a comprehensive explanation of the given assembly code.
这段代码是Go语言标准库中 `crypto/sha256` 包为了追求在支持 AVX2 指令集的 AMD64 架构上的性能而实现的一个优化的 SHA-256 块处理函数 `blockAVX2` 的汇编实现。 它使用了 `mmcloughlin/avo` 这个 Go 汇编代码生成库来生成实际的汇编指令。

**功能列表:**

1. **SHA-256 核心块处理:**  该函数实现了 SHA-256 算法的核心循环，用于处理 64 字节（512 比特）的数据块。
2. **AVX2 指令集优化:**  它利用了 AVX2 (Advanced Vector Extensions 2) 指令集提供的并行处理能力，可以同时处理多个 32 位的数据，从而显著提升 SHA-256 的计算速度。
3. **大端序转换:**  代码中包含了将小端序（Little-Endian）数据转换为大端序（Big-Endian）的操作，这是因为 SHA-256 算法规范要求使用大端序。
4. **消息调度:** 代码中实现了 SHA-256 的消息调度部分，即将 64 字节的输入数据扩展成 64 个 32 位的字，供后续的轮函数使用。
5. **轮函数执行:** 代码实现了 SHA-256 的 64 轮压缩函数，这些轮函数通过一系列的位运算和加法操作来更新哈希值。
6. **处理多数据块:** 函数能够处理多于一个数据块的情况，通过循环处理每个 64 字节的数据块。
7. **处理最后一个数据块:**  针对最后一个可能不足 64 字节的数据块，代码也有相应的处理逻辑。
8. **初始化和更新哈希状态:**  函数接收当前的哈希状态（8个 32 位字）作为输入，并在处理完数据块后更新这个状态。

**推断的 Go 语言功能实现和代码示例:**

基于汇编代码的逻辑，我们可以推断出在 Go 代码中会有一个名为 `blockAVX2` 的函数，它的作用是处理一个或多个 64 字节的数据块，并更新 SHA-256 的哈希状态。

```go
package sha256

//go:noescape
func blockAVX2(dig *[8]uint32, p []byte)

func processBlocksAVX2(dig *[8]uint32, data []byte) {
	const blockSize = 64
	for len(data) >= blockSize {
		blockAVX2(dig, data[:blockSize])
		data = data[blockSize:]
	}
	// 剩余的数据块需要用其他方式处理，例如通用的 Go 实现或者其他优化的汇编实现
	// ...
}

func main() {
	var digest [8]uint32 = [8]uint32{
		0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
		0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
	} // SHA-256 的初始哈希值

	data := []byte("hello world")
	processBlocksAVX2(&digest, data)

	println("SHA-256 Digest:", digest)
}
```

**假设的输入与输出:**

* **假设输入:**
    * `dig`: 一个指向 `[8]uint32` 数组的指针，包含了当前的 SHA-256 哈希状态（例如，初始值或之前处理块后的状态）。
    * `p`: 一个 `[]byte` 切片，包含了要处理的数据块。
* **假设输出:**
    * 函数会修改 `dig` 指向的数组，使其包含处理完输入数据块后的新的 SHA-256 哈希状态。

**代码推理说明:**

1. **参数加载:**  `Load(Param("dig"), CTX)` 和 `Load(Param("p").Base(), INP)` 说明函数接收两个参数，一个是指向哈希状态的指针，另一个是指向数据块起始地址的指针。
2. **循环处理:** `avx2_loop0`, `avx2_loop1`, `avx2_loop2`, `avx2_loop3` 这些标签暗示了代码中存在循环，用于处理多个数据块。
3. **AVX2 指令:** 代码中大量使用了 `VMOVDQU`, `VPSHUFB`, `VPERM2I128`, `VPADDD` 等 AVX2 指令，表明它正在利用 AVX2 的并行计算能力。
4. **字节序转换:** `flip_mask_DATA()` 和 `VPSHUFB` 指令用于执行字节序的翻转。
5. **轮函数和消息调度:** `roundAndSchedN0`, `roundAndSchedN1`, `roundAndSchedN2`, `roundAndSchedN3`, `doRoundN0`, `doRoundN1`, `doRoundN2`, `doRoundN3` 这些函数名和内部的位运算逻辑与 SHA-256 的轮函数和消息调度过程相符。

**命令行参数的具体处理:**

这段代码本身是汇编实现，不直接处理命令行参数。命令行参数的处理通常发生在调用这个汇编函数的 Go 代码中。 上面的 `main` 函数就是一个简单的例子，它直接定义了要哈希的数据。 如果要处理命令行参数，你需要在 Go 代码中使用 `os` 包的 `Args` 来获取，并进行相应的解析和处理，然后将需要哈希的数据传递给 `processBlocksAVX2` 函数。

**使用者易犯错的点:**

1. **输入数据长度不是 64 的倍数:** 虽然代码中考虑了最后一个数据块的处理，但在调用这个汇编优化的函数之前，Go 代码可能需要确保数据被正确地分块和填充。如果直接传递一个非 64 字节整数倍长度的数据给 `blockAVX2`，可能会导致错误或未预期的行为。  虽然 `processBlocksAVX2` 示例中做了简单的分块处理，但实际应用中可能需要更精细的填充逻辑。

   **例如，错误的调用方式:**

   ```go
   // 假设 blockAVX2 只处理完整的 64 字节块
   var digest [8]uint32 = [...]uint32{ /* ... */ }
   data := []byte("this is a string with length not a multiple of 64")
   sha256.blockAVX2(&digest, data) // 这可能会导致问题，因为 data 的长度不是 64 的倍数
   ```

   **正确的调用方式 (假设有外部的填充逻辑):**

   ```go
   var digest [8]uint32 = [...]uint32{ /* ... */ }
   data := []byte("this is a string with length not a multiple of 64")
   paddedData := padSHA256(data) // 假设有这样一个填充函数
   for i := 0; i < len(paddedData)/64; i++ {
       sha256.blockAVX2(&digest, paddedData[i*64:(i+1)*64])
   }
   ```

2. **错误的哈希状态管理:**  SHA-256 是一个迭代的哈希算法，需要在处理每个数据块后更新哈希状态。如果使用者没有正确地传递和更新哈希状态，最终的哈希值将会是错误的。

   **例如，错误的哈希状态管理:**

   ```go
   var digest [8]uint32 = [...]uint32{ /* 初始值 */ }
   data1 := []byte("part 1")
   sha256.blockAVX2(&digest, data1)

   var digest2 [8]uint32 = [...]uint32{ /* 再次使用初始值，而不是上一次计算后的值 */ }
   data2 := []byte("part 2")
   sha256.blockAVX2(&digest2, data2) // 错误：应该使用处理 data1 后的 digest

   // 正确的做法是复用 digest
   var digest_correct [8]uint32 = [...]uint32{ /* 初始值 */ }
   data1_correct := []byte("part 1")
   sha256.blockAVX2(&digest_correct, data1_correct)

   data2_correct := []byte("part 2")
   sha256.blockAVX2(&digest_correct, data2_correct) // 正确：复用之前的哈希状态
   ```

这段汇编代码是 `crypto/sha256` 包为了性能优化所做的底层实现，使用者通常不需要直接调用这个函数，而是使用 `crypto/sha256` 包提供的更高级别的 API，这些 API 会负责处理数据分块、填充和状态管理等细节。 理解这段代码的功能有助于深入了解 SHA-256 算法的实现和性能优化的方法。

### 提示词
```
这是路径为go/src/crypto/internal/fips140/sha256/_asm/sha256block_amd64_avx2.go的go语言实现的一部分， 请列举一下它的功能, 　
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

package main

import (
	. "github.com/mmcloughlin/avo/build"
	. "github.com/mmcloughlin/avo/operand"
	. "github.com/mmcloughlin/avo/reg"
)

// The avx2-version is described in an Intel White-Paper:
// "Fast SHA-256 Implementations on Intel Architecture Processors"
// To find it, surf to http://www.intel.com/p/en_US/embedded
// and search for that title.
// AVX2 version by Intel, same algorithm as code in Linux kernel:
// https://github.com/torvalds/linux/blob/master/arch/x86/crypto/sha256-avx2-asm.S
// by
//     James Guilford <james.guilford@intel.com>
//     Kirk Yap <kirk.s.yap@intel.com>
//     Tim Chen <tim.c.chen@linux.intel.com>

func blockAVX2() {
	Implement("blockAVX2")
	AllocLocal(536)

	Load(Param("dig"), CTX) // d.h[8]
	Load(Param("p").Base(), INP)
	Load(Param("p").Len(), NUM_BYTES)

	LEAQ(Mem{Base: INP, Index: NUM_BYTES, Scale: 1, Disp: -64}, NUM_BYTES) // Pointer to the last block
	MOVQ(NUM_BYTES, Mem{Base: SP}.Offset(_INP_END))

	CMPQ(NUM_BYTES, INP)
	JE(LabelRef("avx2_only_one_block"))

	Comment("Load initial digest")
	CTX := Mem{Base: CTX}
	MOVL(CTX.Offset(0), a)  //  a = H0
	MOVL(CTX.Offset(4), b)  //  b = H1
	MOVL(CTX.Offset(8), c)  //  c = H2
	MOVL(CTX.Offset(12), d) //  d = H3
	MOVL(CTX.Offset(16), e) //  e = H4
	MOVL(CTX.Offset(20), f) //  f = H5
	MOVL(CTX.Offset(24), g) //  g = H6
	MOVL(CTX.Offset(28), h) //  h = H7

	avx2_loop0()
	avx2_last_block_enter()
	avx2_loop1()
	avx2_loop2()
	avx2_loop3()
	avx2_do_last_block()
	avx2_only_one_block()
	done_hash()
}

func avx2_loop0() {
	Label("avx2_loop0")
	Comment("at each iteration works with one block (512 bit)")
	VMOVDQU(Mem{Base: INP}.Offset(0*32), XTMP0)
	VMOVDQU(Mem{Base: INP}.Offset(1*32), XTMP1)
	VMOVDQU(Mem{Base: INP}.Offset(2*32), XTMP2)
	VMOVDQU(Mem{Base: INP}.Offset(3*32), XTMP3)

	flip_mask := flip_mask_DATA()

	VMOVDQU(flip_mask, BYTE_FLIP_MASK)

	Comment("Apply Byte Flip Mask: LE -> BE")
	VPSHUFB(BYTE_FLIP_MASK, XTMP0, XTMP0)
	VPSHUFB(BYTE_FLIP_MASK, XTMP1, XTMP1)
	VPSHUFB(BYTE_FLIP_MASK, XTMP2, XTMP2)
	VPSHUFB(BYTE_FLIP_MASK, XTMP3, XTMP3)

	Comment("Transpose data into high/low parts")
	VPERM2I128(Imm(0x20), XTMP2, XTMP0, XDWORD0) //  w3,  w2,  w1,  w0
	VPERM2I128(Imm(0x31), XTMP2, XTMP0, XDWORD1) //  w7,  w6,  w5,  w4
	VPERM2I128(Imm(0x20), XTMP3, XTMP1, XDWORD2) // w11, w10,  w9,  w8
	VPERM2I128(Imm(0x31), XTMP3, XTMP1, XDWORD3) // w15, w14, w13, w12

	K256 := K256_DATA()
	LEAQ(K256, TBL) // Loading address of table with round-specific constants
}

func avx2_last_block_enter() {
	Label("avx2_last_block_enter")
	ADDQ(Imm(64), INP)
	MOVQ(INP, Mem{Base: SP}.Offset(_INP))
	XORQ(SRND, SRND)
}

// for w0 - w47
func avx2_loop1() {
	Label("avx2_loop1")

	Comment("Do 4 rounds and scheduling")
	VPADDD(Mem{Base: TBL, Scale: 1, Index: SRND}.Offset((0 * 32)), XDWORD0, XFER)
	VMOVDQU(XFER, Mem{Base: SP, Scale: 1, Index: SRND}.Offset(_XFER+0*32))
	roundAndSchedN0(_XFER+0*32, a, b, c, d, e, f, g, h, XDWORD0, XDWORD1, XDWORD2, XDWORD3)
	roundAndSchedN1(_XFER+0*32, h, a, b, c, d, e, f, g, XDWORD0, XDWORD1, XDWORD2, XDWORD3)
	roundAndSchedN2(_XFER+0*32, g, h, a, b, c, d, e, f, XDWORD0, XDWORD1, XDWORD2, XDWORD3)
	roundAndSchedN3(_XFER+0*32, f, g, h, a, b, c, d, e, XDWORD0, XDWORD1, XDWORD2, XDWORD3)

	Comment("Do 4 rounds and scheduling")
	VPADDD(Mem{Base: TBL, Scale: 1, Index: SRND}.Offset(1*32), XDWORD1, XFER)
	VMOVDQU(XFER, Mem{Base: SP, Scale: 1, Index: SRND}.Offset(_XFER+1*32))
	roundAndSchedN0(_XFER+1*32, e, f, g, h, a, b, c, d, XDWORD1, XDWORD2, XDWORD3, XDWORD0)
	roundAndSchedN1(_XFER+1*32, d, e, f, g, h, a, b, c, XDWORD1, XDWORD2, XDWORD3, XDWORD0)
	roundAndSchedN2(_XFER+1*32, c, d, e, f, g, h, a, b, XDWORD1, XDWORD2, XDWORD3, XDWORD0)
	roundAndSchedN3(_XFER+1*32, b, c, d, e, f, g, h, a, XDWORD1, XDWORD2, XDWORD3, XDWORD0)

	Comment("Do 4 rounds and scheduling")
	VPADDD(Mem{Base: TBL, Scale: 1, Index: SRND}.Offset((2 * 32)), XDWORD2, XFER)
	VMOVDQU(XFER, Mem{Base: SP, Scale: 1, Index: SRND}.Offset(_XFER+2*32))
	roundAndSchedN0(_XFER+2*32, a, b, c, d, e, f, g, h, XDWORD2, XDWORD3, XDWORD0, XDWORD1)
	roundAndSchedN1(_XFER+2*32, h, a, b, c, d, e, f, g, XDWORD2, XDWORD3, XDWORD0, XDWORD1)
	roundAndSchedN2(_XFER+2*32, g, h, a, b, c, d, e, f, XDWORD2, XDWORD3, XDWORD0, XDWORD1)
	roundAndSchedN3(_XFER+2*32, f, g, h, a, b, c, d, e, XDWORD2, XDWORD3, XDWORD0, XDWORD1)

	Comment("Do 4 rounds and scheduling")
	VPADDD(Mem{Base: TBL, Scale: 1, Index: SRND}.Offset((3 * 32)), XDWORD3, XFER)
	VMOVDQU(XFER, Mem{Base: SP, Scale: 1, Index: SRND}.Offset(_XFER+3*32))
	roundAndSchedN0(_XFER+3*32, e, f, g, h, a, b, c, d, XDWORD3, XDWORD0, XDWORD1, XDWORD2)
	roundAndSchedN1(_XFER+3*32, d, e, f, g, h, a, b, c, XDWORD3, XDWORD0, XDWORD1, XDWORD2)
	roundAndSchedN2(_XFER+3*32, c, d, e, f, g, h, a, b, XDWORD3, XDWORD0, XDWORD1, XDWORD2)
	roundAndSchedN3(_XFER+3*32, b, c, d, e, f, g, h, a, XDWORD3, XDWORD0, XDWORD1, XDWORD2)

	ADDQ(Imm(4*32), SRND)
	CMPQ(SRND, U32(3*4*32))
	JB(LabelRef("avx2_loop1"))
}

// w48 - w63 processed with no scheduling (last 16 rounds)
func avx2_loop2() {
	Label("avx2_loop2")
	VPADDD(Mem{Base: TBL, Scale: 1, Index: SRND}.Offset(0*32), XDWORD0, XFER)
	VMOVDQU(XFER, Mem{Base: SP, Scale: 1, Index: SRND}.Offset(_XFER+0*32))
	doRoundN0(_XFER+0*32, a, b, c, d, e, f, g, h, h)
	doRoundN1(_XFER+0*32, h, a, b, c, d, e, f, g, h)
	doRoundN2(_XFER+0*32, g, h, a, b, c, d, e, f, g)
	doRoundN3(_XFER+0*32, f, g, h, a, b, c, d, e, f)

	VPADDD(Mem{Base: TBL, Scale: 1, Index: SRND}.Offset(1*32), XDWORD1, XFER)
	VMOVDQU(XFER, Mem{Base: SP, Scale: 1, Index: SRND}.Offset(_XFER+1*32))
	doRoundN0(_XFER+1*32, e, f, g, h, a, b, c, d, e)
	doRoundN1(_XFER+1*32, d, e, f, g, h, a, b, c, d)
	doRoundN2(_XFER+1*32, c, d, e, f, g, h, a, b, c)
	doRoundN3(_XFER+1*32, b, c, d, e, f, g, h, a, b)

	ADDQ(Imm(2*32), SRND)

	VMOVDQU(XDWORD2, XDWORD0)
	VMOVDQU(XDWORD3, XDWORD1)

	CMPQ(SRND, U32(4*4*32))
	JB(LabelRef("avx2_loop2"))

	Load(Param("dig"), CTX) // d.h[8]
	MOVQ(Mem{Base: SP}.Offset(_INP), INP)

	registers := []GPPhysical{a, b, c, d, e, f, g, h}
	for i, reg := range registers {
		addm(Mem{Base: CTX}.Offset(i*4), reg)
	}

	CMPQ(Mem{Base: SP}.Offset(_INP_END), INP)
	JB(LabelRef("done_hash"))

	XORQ(SRND, SRND)
}

// Do second block using previously scheduled results
func avx2_loop3() {
	Label("avx2_loop3")
	doRoundN0(_XFER+0*32+16, a, b, c, d, e, f, g, h, a)
	doRoundN1(_XFER+0*32+16, h, a, b, c, d, e, f, g, h)
	doRoundN2(_XFER+0*32+16, g, h, a, b, c, d, e, f, g)
	doRoundN3(_XFER+0*32+16, f, g, h, a, b, c, d, e, f)

	doRoundN0(_XFER+1*32+16, e, f, g, h, a, b, c, d, e)
	doRoundN1(_XFER+1*32+16, d, e, f, g, h, a, b, c, d)
	doRoundN2(_XFER+1*32+16, c, d, e, f, g, h, a, b, c)
	doRoundN3(_XFER+1*32+16, b, c, d, e, f, g, h, a, b)

	ADDQ(Imm(2*32), SRND)
	CMPQ(SRND, U32(4*4*32))
	JB(LabelRef("avx2_loop3"))

	Load(Param("dig"), CTX) // d.h[8]
	MOVQ(Mem{Base: SP}.Offset(_INP), INP)
	ADDQ(Imm(64), INP)

	registers := []GPPhysical{a, b, c, d, e, f, g, h}
	for i, reg := range registers {
		addm(Mem{Base: CTX}.Offset(i*4), reg)
	}

	CMPQ(Mem{Base: SP}.Offset(_INP_END), INP)
	JA(LabelRef("avx2_loop0"))
	JB(LabelRef("done_hash"))
}

func avx2_do_last_block() {
	Label("avx2_do_last_block")
	VMOVDQU(Mem{Base: INP}.Offset(0), XWORD0)
	VMOVDQU(Mem{Base: INP}.Offset(16), XWORD1)
	VMOVDQU(Mem{Base: INP}.Offset(32), XWORD2)
	VMOVDQU(Mem{Base: INP}.Offset(48), XWORD3)

	flip_mask := flip_mask_DATA()
	VMOVDQU(flip_mask, BYTE_FLIP_MASK)

	VPSHUFB(X_BYTE_FLIP_MASK, XWORD0, XWORD0)
	VPSHUFB(X_BYTE_FLIP_MASK, XWORD1, XWORD1)
	VPSHUFB(X_BYTE_FLIP_MASK, XWORD2, XWORD2)
	VPSHUFB(X_BYTE_FLIP_MASK, XWORD3, XWORD3)

	K256 := K256_DATA()
	LEAQ(K256, TBL)

	JMP(LabelRef("avx2_last_block_enter"))
}

// Load initial digest
func avx2_only_one_block() {
	Label("avx2_only_one_block")
	registers := []GPPhysical{a, b, c, d, e, f, g, h}
	for i, reg := range registers {
		MOVL(Mem{Base: CTX}.Offset(i*4), reg)
	}
	JMP(LabelRef("avx2_do_last_block"))
}

func done_hash() {
	Label("done_hash")
	VZEROUPPER()
	RET()
}

// addm (mem), reg
//   - Add reg to mem using reg-mem add and store
func addm(P1 Mem, P2 GPPhysical) {
	ADDL(P2, P1)
	MOVL(P1, P2)
}

var (
	XDWORD0 VecPhysical = Y4
	XDWORD1             = Y5
	XDWORD2             = Y6
	XDWORD3             = Y7

	XWORD0 = X4
	XWORD1 = X5
	XWORD2 = X6
	XWORD3 = X7

	XTMP0 = Y0
	XTMP1 = Y1
	XTMP2 = Y2
	XTMP3 = Y3
	XTMP4 = Y8
	XTMP5 = Y11

	XFER = Y9

	BYTE_FLIP_MASK   = Y13 // mask to convert LE -> BE
	X_BYTE_FLIP_MASK = X13

	NUM_BYTES GPPhysical = RDX
	INP                  = RDI

	CTX = RSI // Beginning of digest in memory (a, b, c, ... , h)

	a = EAX
	b = EBX
	c = ECX
	d = R8L
	e = EDX
	f = R9L
	g = R10L
	h = R11L

	old_h = R11L

	TBL = RBP

	SRND = RSI // SRND is same register as CTX

	T1 = R12L

	y0 = R13L
	y1 = R14L
	y2 = R15L
	y3 = EDI

	// Offsets
	XFER_SIZE    = 2 * 64 * 4
	INP_END_SIZE = 8
	INP_SIZE     = 8

	_XFER      = 0
	_INP_END   = _XFER + XFER_SIZE
	_INP       = _INP_END + INP_END_SIZE
	STACK_SIZE = _INP + INP_SIZE
)

func roundAndSchedN0(disp int, a, b, c, d, e, f, g, h GPPhysical, XDWORD0, XDWORD1, XDWORD2, XDWORD3 VecPhysical) {
	//                                                                 #############################  RND N + 0 ############################//
	MOVL(a, y3)           //                                           y3 = a
	RORXL(Imm(25), e, y0) //                                           y0 = e >> 25
	RORXL(Imm(11), e, y1) //                                           y1 = e >> 11

	ADDL(Mem{Base: SP, Disp: disp + 0*4, Scale: 1, Index: SRND}, h) // h = k + w + h
	ORL(c, y3)                                                      // y3 = a|c
	VPALIGNR(Imm(4), XDWORD2, XDWORD3, XTMP0)                       // XTMP0 = W[-7]
	MOVL(f, y2)                                                     // y2 = f
	RORXL(Imm(13), a, T1)                                           // T1 = a >> 13

	XORL(y1, y0)                  //                                   y0 = (e>>25) ^ (e>>11)
	XORL(g, y2)                   //                                   y2 = f^g
	VPADDD(XDWORD0, XTMP0, XTMP0) //                                   XTMP0 = W[-7] + W[-16]
	RORXL(Imm(6), e, y1)          //                                   y1 = (e >> 6)

	ANDL(e, y2)           //                                           y2 = (f^g)&e
	XORL(y1, y0)          //                                           y0 = (e>>25) ^ (e>>11) ^ (e>>6)
	RORXL(Imm(22), a, y1) //                                           y1 = a >> 22
	ADDL(h, d)            //                                           d = k + w + h + d

	ANDL(b, y3)                               //                       y3 = (a|c)&b
	VPALIGNR(Imm(4), XDWORD0, XDWORD1, XTMP1) //                       XTMP1 = W[-15]
	XORL(T1, y1)                              //                       y1 = (a>>22) ^ (a>>13)
	RORXL(Imm(2), a, T1)                      //                       T1 = (a >> 2)

	XORL(g, y2)                  //                                    y2 = CH = ((f^g)&e)^g
	VPSRLD(Imm(7), XTMP1, XTMP2) //
	XORL(T1, y1)                 //                                    y1 = (a>>22) ^ (a>>13) ^ (a>>2)
	MOVL(a, T1)                  //                                    T1 = a
	ANDL(c, T1)                  //                                    T1 = a&c

	ADDL(y0, y2)                    //                                 y2 = S1 + CH
	VPSLLD(Imm(32-7), XTMP1, XTMP3) //
	ORL(T1, y3)                     //                                 y3 = MAJ = (a|c)&b)|(a&c)
	ADDL(y1, h)                     //                                 h = k + w + h + S0

	ADDL(y2, d)               //                                       d = k + w + h + d + S1 + CH = d + t1
	VPOR(XTMP2, XTMP3, XTMP3) //                                       XTMP3 = W[-15] ror 7

	VPSRLD(Imm(18), XTMP1, XTMP2)
	ADDL(y2, h) //                                                     h = k + w + h + S0 + S1 + CH = t1 + S0
	ADDL(y3, h) //                                                     h = t1 + S0 + MAJ
}

func roundAndSchedN1(disp int, a, b, c, d, e, f, g, h GPPhysical, XDWORD0, XDWORD1, XDWORD2, XDWORD3 VecPhysical) {
	//                                                                 ################################### RND N + 1 ############################
	MOVL(a, y3)                                                     // y3 = a
	RORXL(Imm(25), e, y0)                                           // y0 = e >> 25
	RORXL(Imm(11), e, y1)                                           // y1 = e >> 11
	ADDL(Mem{Base: SP, Disp: disp + 1*4, Scale: 1, Index: SRND}, h) // h = k + w + h
	ORL(c, y3)                                                      // y3 = a|c

	VPSRLD(Imm(3), XTMP1, XTMP4) //                                    XTMP4 = W[-15] >> 3
	MOVL(f, y2)                  //                                    y2 = f
	RORXL(Imm(13), a, T1)        //                                    T1 = a >> 13
	XORL(y1, y0)                 //                                    y0 = (e>>25) ^ (e>>11)
	XORL(g, y2)                  //                                    y2 = f^g

	RORXL(Imm(6), e, y1)  //                                           y1 = (e >> 6)
	XORL(y1, y0)          //                                           y0 = (e>>25) ^ (e>>11) ^ (e>>6)
	RORXL(Imm(22), a, y1) //                                           y1 = a >> 22
	ANDL(e, y2)           //                                           y2 = (f^g)&e
	ADDL(h, d)            //                                           d = k + w + h + d

	VPSLLD(Imm(32-18), XTMP1, XTMP1)
	ANDL(b, y3)  //                                                    y3 = (a|c)&b
	XORL(T1, y1) //                                                    y1 = (a>>22) ^ (a>>13)

	VPXOR(XTMP1, XTMP3, XTMP3)
	RORXL(Imm(2), a, T1) //                                            T1 = (a >> 2)
	XORL(g, y2)          //                                            y2 = CH = ((f^g)&e)^g

	VPXOR(XTMP2, XTMP3, XTMP3) //                                      XTMP3 = W[-15] ror 7 ^ W[-15] ror 18
	XORL(T1, y1)               //                                      y1 = (a>>22) ^ (a>>13) ^ (a>>2)
	MOVL(a, T1)                //                                      T1 = a
	ANDL(c, T1)                //                                      T1 = a&c
	ADDL(y0, y2)               //                                      y2 = S1 + CH

	VPXOR(XTMP4, XTMP3, XTMP1)         //                              XTMP1 = s0
	VPSHUFD(Imm(0xFA), XDWORD3, XTMP2) //                              XTMP2 = W[-2] {BBAA}
	ORL(T1, y3)                        //                              y3 = MAJ = (a|c)&b)|(a&c)
	ADDL(y1, h)                        //                              h = k + w + h + S0

	VPADDD(XTMP1, XTMP0, XTMP0) //                                     XTMP0 = W[-16] + W[-7] + s0
	ADDL(y2, d)                 //                                     d = k + w + h + d + S1 + CH = d + t1
	ADDL(y2, h)                 //                                     h = k + w + h + S0 + S1 + CH = t1 + S0
	ADDL(y3, h)                 //                                     h = t1 + S0 + MAJ

	VPSRLD(Imm(10), XTMP2, XTMP4) //                                   XTMP4 = W[-2] >> 10 {BBAA}
}

func roundAndSchedN2(disp int, a, b, c, d, e, f, g, h GPPhysical, XDWORD0, XDWORD1, XDWORD2, XDWORD3 VecPhysical) {
	//                                                                 ################################### RND N + 2 ############################
	var shuff_00BA Mem = shuff_00BA_DATA()

	MOVL(a, y3)                                                     // y3 = a
	RORXL(Imm(25), e, y0)                                           // y0 = e >> 25
	ADDL(Mem{Base: SP, Disp: disp + 2*4, Scale: 1, Index: SRND}, h) // h = k + w + h

	VPSRLQ(Imm(19), XTMP2, XTMP3) //                                   XTMP3 = W[-2] ror 19 {xBxA}
	RORXL(Imm(11), e, y1)         //                                   y1 = e >> 11
	ORL(c, y3)                    //                                   y3 = a|c
	MOVL(f, y2)                   //                                   y2 = f
	XORL(g, y2)                   //                                   y2 = f^g

	RORXL(Imm(13), a, T1)         //                                   T1 = a >> 13
	XORL(y1, y0)                  //                                   y0 = (e>>25) ^ (e>>11)
	VPSRLQ(Imm(17), XTMP2, XTMP2) //                                   XTMP2 = W[-2] ror 17 {xBxA}
	ANDL(e, y2)                   //                                   y2 = (f^g)&e

	RORXL(Imm(6), e, y1) //                                            y1 = (e >> 6)
	VPXOR(XTMP3, XTMP2, XTMP2)
	ADDL(h, d)  //                                                     d = k + w + h + d
	ANDL(b, y3) //                                                     y3 = (a|c)&b

	XORL(y1, y0)               //                                      y0 = (e>>25) ^ (e>>11) ^ (e>>6)
	RORXL(Imm(22), a, y1)      //                                      y1 = a >> 22
	VPXOR(XTMP2, XTMP4, XTMP4) //                                      XTMP4 = s1 {xBxA}
	XORL(g, y2)                //                                      y2 = CH = ((f^g)&e)^g

	VPSHUFB(shuff_00BA, XTMP4, XTMP4) //                               XTMP4 = s1 {00BA}

	XORL(T1, y1)                //                                     y1 = (a>>22) ^ (a>>13)
	RORXL(Imm(2), a, T1)        //                                     T1 = (a >> 2)
	VPADDD(XTMP4, XTMP0, XTMP0) //                                     XTMP0 = {..., ..., W[1], W[0]}

	XORL(T1, y1)                   //                                  y1 = (a>>22) ^ (a>>13) ^ (a>>2)
	MOVL(a, T1)                    //                                  T1 = a
	ANDL(c, T1)                    //                                  T1 = a&c
	ADDL(y0, y2)                   //                                  y2 = S1 + CH
	VPSHUFD(Imm(80), XTMP0, XTMP2) //                                  XTMP2 = W[-2] {DDCC}

	ORL(T1, y3) //                                                     y3 = MAJ = (a|c)&b)|(a&c)
	ADDL(y1, h) //                                                     h = k + w + h + S0
	ADDL(y2, d) //                                                     d = k + w + h + d + S1 + CH = d + t1
	ADDL(y2, h) //                                                     h = k + w + h + S0 + S1 + CH = t1 + S0

	ADDL(y3, h) //                                                     h = t1 + S0 + MAJ
}

func roundAndSchedN3(disp int, a, b, c, d, e, f, g, h GPPhysical, XDWORD0, XDWORD1, XDWORD2, XDWORD3 VecPhysical) {
	//                                                                 ################################### RND N + 3 ############################
	var shuff_DC00 Mem = shuff_DC00_DATA()

	MOVL(a, y3)                                                     // y3 = a
	RORXL(Imm(25), e, y0)                                           // y0 = e >> 25
	RORXL(Imm(11), e, y1)                                           // y1 = e >> 11
	ADDL(Mem{Base: SP, Disp: disp + 3*4, Scale: 1, Index: SRND}, h) // h = k + w + h
	ORL(c, y3)                                                      // y3 = a|c

	VPSRLD(Imm(10), XTMP2, XTMP5) //                                   XTMP5 = W[-2] >> 10 {DDCC}
	MOVL(f, y2)                   //                                   y2 = f
	RORXL(Imm(13), a, T1)         //                                   T1 = a >> 13
	XORL(y1, y0)                  //                                   y0 = (e>>25) ^ (e>>11)
	XORL(g, y2)                   //                                   y2 = f^g

	VPSRLQ(Imm(19), XTMP2, XTMP3) //                                   XTMP3 = W[-2] ror 19 {xDxC}
	RORXL(Imm(6), e, y1)          //                                   y1 = (e >> 6)
	ANDL(e, y2)                   //                                   y2 = (f^g)&e
	ADDL(h, d)                    //                                   d = k + w + h + d
	ANDL(b, y3)                   //                                   y3 = (a|c)&b

	VPSRLQ(Imm(17), XTMP2, XTMP2) //                                   XTMP2 = W[-2] ror 17 {xDxC}
	XORL(y1, y0)                  //                                   y0 = (e>>25) ^ (e>>11) ^ (e>>6)
	XORL(g, y2)                   //                                   y2 = CH = ((f^g)&e)^g

	VPXOR(XTMP3, XTMP2, XTMP2)
	RORXL(Imm(22), a, y1) //                                           y1 = a >> 22
	ADDL(y0, y2)          //                                           y2 = S1 + CH

	VPXOR(XTMP2, XTMP5, XTMP5) //                                      XTMP5 = s1 {xDxC}
	XORL(T1, y1)               //                                      y1 = (a>>22) ^ (a>>13)
	ADDL(y2, d)                //                                      d = k + w + h + d + S1 + CH = d + t1

	RORXL(Imm(2), a, T1) //                                            T1 = (a >> 2)

	VPSHUFB(shuff_DC00, XTMP5, XTMP5) //                               XTMP5 = s1 {DC00}

	VPADDD(XTMP0, XTMP5, XDWORD0) //                                   XDWORD0 = {W[3], W[2], W[1], W[0]}
	XORL(T1, y1)                  //                                   y1 = (a>>22) ^ (a>>13) ^ (a>>2)
	MOVL(a, T1)                   //                                   T1 = a
	ANDL(c, T1)                   //                                   T1 = a&c
	ORL(T1, y3)                   //                                   y3 = MAJ = (a|c)&b)|(a&c)

	ADDL(y1, h) //                                                     h = k + w + h + S0
	ADDL(y2, h) //                                                     h = k + w + h + S0 + S1 + CH = t1 + S0
	ADDL(y3, h) //                                                     h = t1 + S0 + MAJ
}

func doRoundN0(disp int, a, b, c, d, e, f, g, h, old_h GPPhysical) {
	//                                                                 ################################### RND N + 0 ###########################
	MOVL(f, y2)           //                                           y2 = f
	RORXL(Imm(25), e, y0) //                                           y0 = e >> 25
	RORXL(Imm(11), e, y1) //                                           y1 = e >> 11
	XORL(g, y2)           //                                           y2 = f^g

	XORL(y1, y0)         //                                            y0 = (e>>25) ^ (e>>11)
	RORXL(Imm(6), e, y1) //                                            y1 = (e >> 6)
	ANDL(e, y2)          //                                            y2 = (f^g)&e

	XORL(y1, y0)          //                                           y0 = (e>>25) ^ (e>>11) ^ (e>>6)
	RORXL(Imm(13), a, T1) //                                           T1 = a >> 13
	XORL(g, y2)           //                                           y2 = CH = ((f^g)&e)^g
	RORXL(Imm(22), a, y1) //                                           y1 = a >> 22
	MOVL(a, y3)           //                                           y3 = a

	XORL(T1, y1)                                                    // y1 = (a>>22) ^ (a>>13)
	RORXL(Imm(2), a, T1)                                            // T1 = (a >> 2)
	ADDL(Mem{Base: SP, Disp: disp + 0*4, Scale: 1, Index: SRND}, h) // h = k + w + h
	ORL(c, y3)                                                      // y3 = a|c

	XORL(T1, y1) //                                                    y1 = (a>>22) ^ (a>>13) ^ (a>>2)
	MOVL(a, T1)  //                                                    T1 = a
	ANDL(b, y3)  //                                                    y3 = (a|c)&b
	ANDL(c, T1)  //                                                    T1 = a&c
	ADDL(y0, y2) //                                                    y2 = S1 + CH

	ADDL(h, d)  //                                                     d = k + w + h + d
	ORL(T1, y3) //                                                     y3 = MAJ = (a|c)&b)|(a&c)
	ADDL(y1, h) //                                                     h = k + w + h + S0
	ADDL(y2, d) //                                                     d = k + w + h + d + S1 + CH = d + t1
}

func doRoundN1(disp int, a, b, c, d, e, f, g, h, old_h GPPhysical) {
	//                                                                 ################################### RND N + 1 ###########################
	ADDL(y2, old_h)       //                                           h = k + w + h + S0 + S1 + CH = t1 + S0
	MOVL(f, y2)           //                                           y2 = f
	RORXL(Imm(25), e, y0) //                                           y0 = e >> 25
	RORXL(Imm(11), e, y1) //                                           y1 = e >> 11
	XORL(g, y2)           //                                           y2 = f^g

	XORL(y1, y0)         //                                            y0 = (e>>25) ^ (e>>11)
	RORXL(Imm(6), e, y1) //                                            y1 = (e >> 6)
	ANDL(e, y2)          //                                            y2 = (f^g)&e
	ADDL(y3, old_h)      //                                            h = t1 + S0 + MAJ

	XORL(y1, y0)          //                                           y0 = (e>>25) ^ (e>>11) ^ (e>>6)
	RORXL(Imm(13), a, T1) //                                           T1 = a >> 13
	XORL(g, y2)           //                                           y2 = CH = ((f^g)&e)^g
	RORXL(Imm(22), a, y1) //                                           y1 = a >> 22
	MOVL(a, y3)           //                                           y3 = a

	XORL(T1, y1)                                                    // y1 = (a>>22) ^ (a>>13)
	RORXL(Imm(2), a, T1)                                            // T1 = (a >> 2)
	ADDL(Mem{Base: SP, Disp: disp + 1*4, Scale: 1, Index: SRND}, h) // h = k + w + h
	ORL(c, y3)                                                      // y3 = a|c

	XORL(T1, y1) //                                                    y1 = (a>>22) ^ (a>>13) ^ (a>>2)
	MOVL(a, T1)  //                                                    T1 = a
	ANDL(b, y3)  //                                                    y3 = (a|c)&b
	ANDL(c, T1)  //                                                    T1 = a&c
	ADDL(y0, y2) //                                                    y2 = S1 + CH

	ADDL(h, d)  //                                                     d = k + w + h + d
	ORL(T1, y3) //                                                     y3 = MAJ = (a|c)&b)|(a&c)
	ADDL(y1, h) //                                                     h = k + w + h + S0

	ADDL(y2, d) //                                                     d = k + w + h + d + S1 + CH = d + t1
}

func doRoundN2(disp int, a, b, c, d, e, f, g, h, old_h GPPhysical) {
	//                                                                 ################################### RND N + 2 ##############################
	ADDL(y2, old_h)       //                                           h = k + w + h + S0 + S1 + CH = t1 + S0
	MOVL(f, y2)           //                                           y2 = f
	RORXL(Imm(25), e, y0) //                                           y0 = e >> 25
	RORXL(Imm(11), e, y1) //                                           y1 = e >> 11
	XORL(g, y2)           //                                           y2 = f^g

	XORL(y1, y0)         //                                            y0 = (e>>25) ^ (e>>11)
	RORXL(Imm(6), e, y1) //                                            y1 = (e >> 6)
	ANDL(e, y2)          //                                            y2 = (f^g)&e
	ADDL(y3, old_h)      //                                            h = t1 + S0 + MAJ

	XORL(y1, y0)          //                                           y0 = (e>>25) ^ (e>>11) ^ (e>>6)
	RORXL(Imm(13), a, T1) //                                           T1 = a >> 13
	XORL(g, y2)           //                                           y2 = CH = ((f^g)&e)^g
	RORXL(Imm(22), a, y1) //                                           y1 = a >> 22
	MOVL(a, y3)           //                                           y3 = a

	XORL(T1, y1)                                                    // y1 = (a>>22) ^ (a>>13)
	RORXL(Imm(2), a, T1)                                            // T1 = (a >> 2)
	ADDL(Mem{Base: SP, Disp: disp + 2*4, Scale: 1, Index: SRND}, h) // h = k + w + h
	ORL(c, y3)                                                      // y3 = a|c

	XORL(T1, y1) //                                                    y1 = (a>>22) ^ (a>>13) ^ (a>>2)
	MOVL(a, T1)  //                                                    T1 = a
	ANDL(b, y3)  //                                                    y3 = (a|c)&b
	ANDL(c, T1)  //                                                    T1 = a&c
	ADDL(y0, y2) //                                                    y2 = S1 + CH

	ADDL(h, d)  //                                                     d = k + w + h + d
	ORL(T1, y3) //                                                     y3 = MAJ = (a|c)&b)|(a&c)
	ADDL(y1, h) //                                                     h = k + w + h + S0

	ADDL(y2, d) //                                                     d = k + w + h + d + S1 + CH = d + t1
}

func doRoundN3(disp int, a, b, c, d, e, f, g, h, old_h GPPhysical) {
	//                                                                 ################################### RND N + 3 ###########################
	ADDL(y2, old_h)       //                                           h = k + w + h + S0 + S1 + CH = t1 + S0
	MOVL(f, y2)           //                                           y2 = f
	RORXL(Imm(25), e, y0) //                                           y0 = e >> 25
	RORXL(Imm(11), e, y1) //                                           y1 = e >> 11
	XORL(g, y2)           //                                           y2 = f^g

	XORL(y1, y0)         //                                            y0 = (e>>25) ^ (e>>11)
	RORXL(Imm(6), e, y1) //                                            y1 = (e >> 6)
	ANDL(e, y2)          //                                            y2 = (f^g)&e
	ADDL(y3, old_h)      //                                            h = t1 + S0 + MAJ

	XORL(y1, y0)          //                                           y0 = (e>>25) ^ (e>>11) ^ (e>>6)
	RORXL(Imm(13), a, T1) //                                           T1 = a >> 13
	XORL(g, y2)           //                                           y2 = CH = ((f^g)&e)^g
	RORXL(Imm(22), a, y1) //                                           y1 = a >> 22
	MOVL(a, y3)           //                                           y3 = a

	XORL(T1, y1)                                                    // y1 = (a>>22) ^ (a>>13)
	RORXL(Imm(2), a, T1)                                            // T1 = (a >> 2)
	ADDL(Mem{Base: SP, Disp: disp + 3*4, Scale: 1, Index: SRND}, h) // h = k + w + h
	ORL(c, y3)                                                      // y3 = a|c

	XORL(T1, y1) //                                                    y1 = (a>>22) ^ (a>>13) ^ (a>>2)
	MOVL(a, T1)  //                                                    T1 = a
	ANDL(b, y3)  //                                                    y3 = (a|c)&b
	ANDL(c, T1)  //                                                    T1 = a&c
	ADDL(y0, y2) //                                                    y2 = S1 + CH

	ADDL(h, d)  //                                                     d = k + w + h + d
	ORL(T1, y3) //                                                     y3 = MAJ = (a|c)&b)|(a&c)
	ADDL(y1, h) //                                                     h = k + w + h + S0

	ADDL(y2, d) //                                                     d = k + w + h + d + S1 + CH = d + t1

	ADDL(y2, h) //                                                     h = k + w + h + S0 + S1 + CH = t1 + S0

	ADDL(y3, h) //                                                     h = t1 + S0 + MAJ
}

// Pointers for memoizing Data section symbols
var flip_maskPtr, shuff_00BAPtr, shuff_DC00Ptr, K256Ptr *Mem

// shuffle byte order from LE to BE
func flip_mask_DATA() Mem {
	if flip_maskPtr != nil {
		return *flip_maskPtr
	}

	flip_mask := GLOBL("flip_mask", RODATA)
	flip_maskPtr = &flip_mask

	DATA(0x00, U64(0x0405060700010203))
	DATA(0x08, U64(0x0c0d0e0f08090a0b))
	DATA(0x10, U64(0x0405060700010203))
	DATA(0x18, U64(0x0c0d0e0f08090a0b))
	return flip_mask
}

// shuffle xBxA -> 00BA
func shuff_00BA_DATA() Mem {
	if shuff_00BAPtr != nil {
		return *shuff_00BAPtr
	}

	shuff_00BA := GLOBL("shuff_00BA", RODATA)
	shuff_00BAPtr = &shuff_00BA

	DATA(0x00, U64(0x0b0a090803020100))
	DATA(0x08, U64(0xFFFFFFFFFFFFFFFF))
	DATA(0x10, U64(0x0b0a090803020100))
	DATA(0x18, U64(0xFFFFFFFFFFFFFFFF))
	return shuff_00BA
}

// shuffle xDxC -> DC00
func shuff_DC00_DATA() Mem {
	if shuff_DC00Ptr != nil {
		return *shuff_DC00Ptr
	}

	shuff_DC00 := GLOBL("shuff_DC00", RODATA)
	shuff_DC00Ptr = &shuff_DC00

	DATA(0x00, U64(0xFFFFFFFFFFFFFFFF))
	DATA(0x08, U64(0x0b0a090803020100))
	DATA(0x10, U64(0xFFFFFFFFFFFFFFFF))
	DATA(0x18, U64(0x0b0a090803020100))
	return shuff_DC00
}

// Round specific constants
func K256_DATA() Mem {
	if K256Ptr != nil {
		return *K256Ptr
	}

	K256 := GLOBL("K256", NOPTR+RODATA)
	K256Ptr = &K256

	offset_idx := 0

	for i := 0; i < len(_K); i += 4 {
		DATA((offset_idx+0)*4, U32(_K[i+0])) // k1
		DATA((offset_idx+1)*4, U32(_K[i+1])) // k2
		DATA((offset_idx+2)*4, U32(_K[i+2])) // k3
		DATA((offset_idx+3)*4, U32(_K[i+3])) // k4

		DATA((offset_idx+4)*4, U32(_K[i+0])) // k1
		DATA((offset_idx+5)*4, U32(_K[i+1])) // k2
		DATA((offset_idx+6)*4, U32(_K[i+2])) // k3
		DATA((offset_idx+7)*4, U32(_K[i+3])) // k4
		offset_idx += 8
	}
	return K256
}
```