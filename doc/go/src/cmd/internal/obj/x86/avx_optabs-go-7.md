Response:
My thought process for answering the request goes like this:

1. **Understand the Goal:** The user wants to know the functionality of the provided Go code snippet, which is part of `go/src/cmd/internal/obj/x86/avx_optabs.go`. They also want me to infer its purpose within the larger Go compilation process, provide code examples (with assumptions), discuss potential command-line interactions, highlight common errors, and finally summarize the functionality based on this partial view. Crucially, this is "part 8 of 9", implying I should also consider the context of the entire file if possible, even though I don't have the other parts.

2. **Initial Code Analysis:**  I immediately recognize the structure: a large slice of structs. Each struct appears to define properties for an instruction. The fields like `as`, `ytab`, `prefix`, and `op` are key. The `op` field is further broken down into byte sequences. The presence of `avxEscape`, `vex` and `evex` prefixes strongly suggests this is related to AVX (Advanced Vector Extensions) instructions for x86 processors.

3. **Inferring the Functionality:** Based on the structure and the field names, I deduce that this code is defining a table of AVX instructions and their corresponding encodings. Specifically:
    * `as`: Likely represents the assembly mnemonic for the instruction (e.g., `AVPSRAVQ`).
    * `ytab`:  Probably refers to a lookup table (`_yvblendmpd`, etc.) that provides additional information about the instruction's operands or behavior. Since the name often includes "v", it's likely related to vector operations.
    * `prefix`: Indicates the instruction prefix (e.g., `Pavx`).
    * `op`: Contains the byte sequence that encodes the instruction. The various flags (`avxEscape`, `vex128`, `evexW0`, etc.) specify different AVX encoding variations (VEX, EVEX prefixes, operand sizes, etc.).

4. **Connecting to Go Compilation:**  I know that the Go compiler needs to translate Go code into machine code. For x86 architectures, this involves selecting appropriate instructions. This `avx_optabs.go` file likely plays a crucial role in this instruction selection process, especially when the Go code involves vector operations that can be optimized using AVX instructions. It acts as a lookup table to find the correct byte encoding for a given AVX instruction.

5. **Developing a Code Example (with Assumptions):**  To illustrate how this might be used, I need to create a simple Go program that could potentially be compiled down to one of these AVX instructions. I pick `AVPSRAVQ` as an example because its name suggests a "vector packed shift right arithmetic variable by quantity".

    * **Assumption:** I assume there's a Go construct (likely using the `math/bits` package or compiler intrinsics) that maps to this instruction.
    * **Code:** I create a simple Go function that performs a bitwise right shift on two slices of `int64`. This is a plausible scenario where `AVPSRAVQ` could be used.
    * **Input/Output:** I provide example input slices and the expected output after the shift operation.

6. **Considering Command-Line Arguments:**  This file itself doesn't directly handle command-line arguments. However, the Go compiler (`go build`, `go run`) *does*. I explain how compiler flags like `-gcflags` could potentially influence the code generation process and indirectly the usage of these AVX instructions. Specifically, flags related to optimization levels or target CPU architecture could determine whether AVX instructions are even considered.

7. **Identifying Potential Pitfalls:**  I think about common mistakes developers might make related to SIMD (Single Instruction, Multiple Data) and AVX:
    * **Incorrect Data Alignment:** AVX instructions often require data to be aligned in memory for optimal performance (or even correctness). I provide an example of unaligned data and explain why it can lead to issues.
    * **Not Checking for CPU Support:**  AVX is not available on all CPUs. Code that relies on AVX instructions might crash or behave unexpectedly on older processors. I suggest using CPU feature detection before using AVX-specific code.

8. **Summarizing the Functionality (Part 8 of 9):** Given that this is part 8 of 9, I infer that the complete file likely contains similar tables for *other* instruction sets (e.g., SSE, potentially older x86 instructions, or even other AVX extensions). Therefore, I summarize the function of *this specific part* as defining the AVX instruction encodings used by the Go compiler for a subset of AVX instructions. The larger file likely provides a comprehensive mapping for the x86 architecture.

9. **Refining the Language:** I ensure the language is clear, concise, and uses appropriate technical terms. I double-check that I've addressed all parts of the user's request.

By following these steps, I can systematically analyze the provided code snippet, infer its purpose within the Go compilation process, and provide a comprehensive answer with relevant examples and explanations. The "part 8 of 9" context helps guide the summary and suggests the broader purpose of the file.
这是`go/src/cmd/internal/obj/x86/avx_optabs.go`文件的第8部分，主要功能是定义了一系列AVX (Advanced Vector Extensions) 指令的操作码表 (optabs)。这个表是Go编译器在将Go代码编译成x86汇编代码时，特别是涉及到使用AVX指令进行向量化优化时，用来查找和生成正确指令编码的关键数据结构。

**功能归纳:**

这部分代码定义了大量AVX指令及其对应的不同编码方式。 具体来说，它为每个AVX指令定义了一个结构体，包含了以下信息：

* **`as`**:  Go汇编语言中表示该AVX指令的助记符，例如 `AVPSRAVQ`， `AVPSRAW` 等。这些助记符与 `go tool asm` 中使用的指令名称相对应。
* **`ytab`**: 指向另一个表（例如 `_yvblendmpd`, `_yvpslld`）的引用。这些表可能定义了指令的有效操作数类型、组合或其他属性。
* **`prefix`**:  指令的前缀，例如 `Pavx`，指示这是一个AVX指令。
* **`op`**:  一个 `opBytes` 类型的切片，包含了该AVX指令在不同AVX扩展（例如 VEX, EVEX）、不同数据宽度（例如 128位, 256位, 512位）、以及广播/zeroing等特性下的具体操作码字节序列。

**推理解释:**

这段代码是Go编译器后端的一部分，负责将中间表示形式的Go代码转换为目标机器的机器码。当Go代码中存在可以利用AVX指令进行优化的操作（例如，对数组或切片的并行操作）时，编译器会查找这个 `optabs` 表，找到与所需操作对应的AVX指令，并根据目标架构和AVX特性选择正确的操作码。

**Go代码示例说明:**

虽然这段代码本身不是可以直接运行的Go代码，但它定义了Go编译器如何处理使用了AVX指令的Go代码。 假设我们有以下Go代码，它可能被编译器优化成使用 `AVPSRAVQ` 指令：

```go
package main

func shiftRight(a, b []int64, shift uint64) {
	for i := range a {
		// 假设编译器能识别出这里可以使用向量化的算术右移
		a[i] = a[i] >> (b[i] & (63)) // 假设 b[i] 提供了移位的位数
	}
}

func main() {
	a := []int64{8, 16, 32, 64}
	b := []int64{1, 2, 3, 4}
	shiftRight(a, b, 0)
	// ...
}
```

**假设的输入与输出:**

* **输入 `a`**: `[]int64{8, 16, 32, 64}`
* **输入 `b`**: `[]int64{1, 2, 3, 4}`
* **操作**: 编译器尝试将循环内的右移操作向量化，可能使用 `AVPSRAVQ` 指令。
* **输出 `a` (理论上，编译器优化后的效果)**: `[]int64{4, 4, 4, 4}` (因为 `8>>1=4`, `16>>2=4`, `32>>3=4`, `64>>4=4`)

**代码推理:**

编译器在遇到 `a[i] = a[i] >> (b[i] & (63))` 这样的代码时，可能会识别出这是一个可以并行执行的算术右移操作。如果目标CPU支持AVX，编译器会查找 `avx_optabs.go` 中关于算术右移的指令。  例如，它可能会找到 `AVPSRAVQ` 的定义，并根据操作数类型 (int64) 和目标AVX扩展版本，选择相应的 `opBytes` 中的字节序列来生成机器码。

**命令行参数的具体处理:**

这个文件本身不处理命令行参数。但是，Go编译器的命令行参数会影响是否以及如何使用这些AVX指令。

* **`-gcflags`**: 可以传递给底层的Go编译器。例如，使用 `-gcflags=-V -d=ssa/prove/debug=1` 可以查看编译器的优化过程，包括是否进行了向量化。
* **`-buildmode`**:  不同的构建模式可能会影响代码生成和优化。
* **GOARCH 环境变量**:  设置目标架构（例如 `GOARCH=amd64`）是使用这些x86 AVX指令的前提。
* **目标 CPU 特性**: 编译器通常会根据目标CPU的特性来选择最合适的指令集。可以通过一些构建标签或选项来指定目标CPU。

**使用者易犯错的点 (与直接使用此文件无关，而是指编写可能被AVX优化的Go代码时):**

1. **数据对齐问题**: AVX指令在处理对齐的数据时性能最佳。如果数组或切片没有正确对齐，可能会导致性能下降，甚至在某些情况下触发错误。 虽然Go的内存管理通常会处理对齐，但在与其他语言（如C）交互时需要注意。

   ```go
   package main

   import "fmt"
   import "unsafe"

   func main() {
       data := [5]int64{1, 2, 3, 4, 5}
       // 假设我们想对 data[1:] 进行向量化操作，但它的起始地址可能不是 16/32/64 字节对齐的
       subSlice := data[1:]
       fmt.Println("Sub-slice address:", unsafe.Pointer(&subSlice[0]))
       // ... 对 subSlice 的操作可能无法充分利用 AVX 的优势
   }
   ```

2. **不必要的复杂性**: 有时，为了让编译器更容易进行向量化，需要编写更简洁、更符合模式的代码。过于复杂的逻辑可能阻止编译器进行有效的AVX优化。

**总结 (第8部分的功能):**

作为 `go/src/cmd/internal/obj/x86/avx_optabs.go` 文件的第八部分，这段代码的核心功能是**为Go编译器提供AVX指令集的查找表，定义了大量AVX指令在不同扩展和特性下的具体操作码编码**。这使得编译器能够在编译Go代码时，识别潜在的向量化机会，并生成高效的AVX机器码，从而提升程序的执行性能，尤其是在处理大量数据时。  考虑到这是第8部分，整个 `avx_optabs.go` 文件很可能包含了针对x86架构更广泛的AVX指令定义。

Prompt: 
```
这是路径为go/src/cmd/internal/obj/x86/avx_optabs.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第8部分，共9部分，请归纳一下它的功能

"""
vex0F38 | evexW0, evexN16 | evexBcstN4 | evexZeroingEnabled, 0x46,
		avxEscape | evex256 | evex66 | evex0F38 | evexW0, evexN32 | evexBcstN4 | evexZeroingEnabled, 0x46,
		avxEscape | evex512 | evex66 | evex0F38 | evexW0, evexN64 | evexBcstN4 | evexZeroingEnabled, 0x46,
	}},
	{as: AVPSRAVQ, ytab: _yvblendmpd, prefix: Pavx, op: opBytes{
		avxEscape | evex128 | evex66 | evex0F38 | evexW1, evexN16 | evexBcstN8 | evexZeroingEnabled, 0x46,
		avxEscape | evex256 | evex66 | evex0F38 | evexW1, evexN32 | evexBcstN8 | evexZeroingEnabled, 0x46,
		avxEscape | evex512 | evex66 | evex0F38 | evexW1, evexN64 | evexBcstN8 | evexZeroingEnabled, 0x46,
	}},
	{as: AVPSRAVW, ytab: _yvblendmpd, prefix: Pavx, op: opBytes{
		avxEscape | evex128 | evex66 | evex0F38 | evexW1, evexN16 | evexZeroingEnabled, 0x11,
		avxEscape | evex256 | evex66 | evex0F38 | evexW1, evexN32 | evexZeroingEnabled, 0x11,
		avxEscape | evex512 | evex66 | evex0F38 | evexW1, evexN64 | evexZeroingEnabled, 0x11,
	}},
	{as: AVPSRAW, ytab: _yvpslld, prefix: Pavx, op: opBytes{
		avxEscape | vex128 | vex66 | vex0F | vexW0, 0x71, 04,
		avxEscape | vex256 | vex66 | vex0F | vexW0, 0x71, 04,
		avxEscape | vex128 | vex66 | vex0F | vexW0, 0xE1,
		avxEscape | vex256 | vex66 | vex0F | vexW0, 0xE1,
		avxEscape | evex128 | evex66 | evex0F | evexW0, evexN16 | evexZeroingEnabled, 0x71, 04,
		avxEscape | evex256 | evex66 | evex0F | evexW0, evexN32 | evexZeroingEnabled, 0x71, 04,
		avxEscape | evex512 | evex66 | evex0F | evexW0, evexN64 | evexZeroingEnabled, 0x71, 04,
		avxEscape | evex128 | evex66 | evex0F | evexW0, evexN16 | evexZeroingEnabled, 0xE1,
		avxEscape | evex256 | evex66 | evex0F | evexW0, evexN16 | evexZeroingEnabled, 0xE1,
		avxEscape | evex512 | evex66 | evex0F | evexW0, evexN16 | evexZeroingEnabled, 0xE1,
	}},
	{as: AVPSRLD, ytab: _yvpslld, prefix: Pavx, op: opBytes{
		avxEscape | vex128 | vex66 | vex0F | vexW0, 0x72, 02,
		avxEscape | vex256 | vex66 | vex0F | vexW0, 0x72, 02,
		avxEscape | vex128 | vex66 | vex0F | vexW0, 0xD2,
		avxEscape | vex256 | vex66 | vex0F | vexW0, 0xD2,
		avxEscape | evex128 | evex66 | evex0F | evexW0, evexN16 | evexBcstN4 | evexZeroingEnabled, 0x72, 02,
		avxEscape | evex256 | evex66 | evex0F | evexW0, evexN32 | evexBcstN4 | evexZeroingEnabled, 0x72, 02,
		avxEscape | evex512 | evex66 | evex0F | evexW0, evexN64 | evexBcstN4 | evexZeroingEnabled, 0x72, 02,
		avxEscape | evex128 | evex66 | evex0F | evexW0, evexN16 | evexZeroingEnabled, 0xD2,
		avxEscape | evex256 | evex66 | evex0F | evexW0, evexN16 | evexZeroingEnabled, 0xD2,
		avxEscape | evex512 | evex66 | evex0F | evexW0, evexN16 | evexZeroingEnabled, 0xD2,
	}},
	{as: AVPSRLDQ, ytab: _yvpslldq, prefix: Pavx, op: opBytes{
		avxEscape | vex128 | vex66 | vex0F | vexW0, 0x73, 03,
		avxEscape | vex256 | vex66 | vex0F | vexW0, 0x73, 03,
		avxEscape | evex128 | evex66 | evex0F | evexW0, evexN16, 0x73, 03,
		avxEscape | evex256 | evex66 | evex0F | evexW0, evexN32, 0x73, 03,
		avxEscape | evex512 | evex66 | evex0F | evexW0, evexN64, 0x73, 03,
	}},
	{as: AVPSRLQ, ytab: _yvpslld, prefix: Pavx, op: opBytes{
		avxEscape | vex128 | vex66 | vex0F | vexW0, 0x73, 02,
		avxEscape | vex256 | vex66 | vex0F | vexW0, 0x73, 02,
		avxEscape | vex128 | vex66 | vex0F | vexW0, 0xD3,
		avxEscape | vex256 | vex66 | vex0F | vexW0, 0xD3,
		avxEscape | evex128 | evex66 | evex0F | evexW1, evexN16 | evexBcstN8 | evexZeroingEnabled, 0x73, 02,
		avxEscape | evex256 | evex66 | evex0F | evexW1, evexN32 | evexBcstN8 | evexZeroingEnabled, 0x73, 02,
		avxEscape | evex512 | evex66 | evex0F | evexW1, evexN64 | evexBcstN8 | evexZeroingEnabled, 0x73, 02,
		avxEscape | evex128 | evex66 | evex0F | evexW1, evexN16 | evexZeroingEnabled, 0xD3,
		avxEscape | evex256 | evex66 | evex0F | evexW1, evexN16 | evexZeroingEnabled, 0xD3,
		avxEscape | evex512 | evex66 | evex0F | evexW1, evexN16 | evexZeroingEnabled, 0xD3,
	}},
	{as: AVPSRLVD, ytab: _yvandnpd, prefix: Pavx, op: opBytes{
		avxEscape | vex128 | vex66 | vex0F38 | vexW0, 0x45,
		avxEscape | vex256 | vex66 | vex0F38 | vexW0, 0x45,
		avxEscape | evex128 | evex66 | evex0F38 | evexW0, evexN16 | evexBcstN4 | evexZeroingEnabled, 0x45,
		avxEscape | evex256 | evex66 | evex0F38 | evexW0, evexN32 | evexBcstN4 | evexZeroingEnabled, 0x45,
		avxEscape | evex512 | evex66 | evex0F38 | evexW0, evexN64 | evexBcstN4 | evexZeroingEnabled, 0x45,
	}},
	{as: AVPSRLVQ, ytab: _yvandnpd, prefix: Pavx, op: opBytes{
		avxEscape | vex128 | vex66 | vex0F38 | vexW1, 0x45,
		avxEscape | vex256 | vex66 | vex0F38 | vexW1, 0x45,
		avxEscape | evex128 | evex66 | evex0F38 | evexW1, evexN16 | evexBcstN8 | evexZeroingEnabled, 0x45,
		avxEscape | evex256 | evex66 | evex0F38 | evexW1, evexN32 | evexBcstN8 | evexZeroingEnabled, 0x45,
		avxEscape | evex512 | evex66 | evex0F38 | evexW1, evexN64 | evexBcstN8 | evexZeroingEnabled, 0x45,
	}},
	{as: AVPSRLVW, ytab: _yvblendmpd, prefix: Pavx, op: opBytes{
		avxEscape | evex128 | evex66 | evex0F38 | evexW1, evexN16 | evexZeroingEnabled, 0x10,
		avxEscape | evex256 | evex66 | evex0F38 | evexW1, evexN32 | evexZeroingEnabled, 0x10,
		avxEscape | evex512 | evex66 | evex0F38 | evexW1, evexN64 | evexZeroingEnabled, 0x10,
	}},
	{as: AVPSRLW, ytab: _yvpslld, prefix: Pavx, op: opBytes{
		avxEscape | vex128 | vex66 | vex0F | vexW0, 0x71, 02,
		avxEscape | vex256 | vex66 | vex0F | vexW0, 0x71, 02,
		avxEscape | vex128 | vex66 | vex0F | vexW0, 0xD1,
		avxEscape | vex256 | vex66 | vex0F | vexW0, 0xD1,
		avxEscape | evex128 | evex66 | evex0F | evexW0, evexN16 | evexZeroingEnabled, 0x71, 02,
		avxEscape | evex256 | evex66 | evex0F | evexW0, evexN32 | evexZeroingEnabled, 0x71, 02,
		avxEscape | evex512 | evex66 | evex0F | evexW0, evexN64 | evexZeroingEnabled, 0x71, 02,
		avxEscape | evex128 | evex66 | evex0F | evexW0, evexN16 | evexZeroingEnabled, 0xD1,
		avxEscape | evex256 | evex66 | evex0F | evexW0, evexN16 | evexZeroingEnabled, 0xD1,
		avxEscape | evex512 | evex66 | evex0F | evexW0, evexN16 | evexZeroingEnabled, 0xD1,
	}},
	{as: AVPSUBB, ytab: _yvandnpd, prefix: Pavx, op: opBytes{
		avxEscape | vex128 | vex66 | vex0F | vexW0, 0xF8,
		avxEscape | vex256 | vex66 | vex0F | vexW0, 0xF8,
		avxEscape | evex128 | evex66 | evex0F | evexW0, evexN16 | evexZeroingEnabled, 0xF8,
		avxEscape | evex256 | evex66 | evex0F | evexW0, evexN32 | evexZeroingEnabled, 0xF8,
		avxEscape | evex512 | evex66 | evex0F | evexW0, evexN64 | evexZeroingEnabled, 0xF8,
	}},
	{as: AVPSUBD, ytab: _yvandnpd, prefix: Pavx, op: opBytes{
		avxEscape | vex128 | vex66 | vex0F | vexW0, 0xFA,
		avxEscape | vex256 | vex66 | vex0F | vexW0, 0xFA,
		avxEscape | evex128 | evex66 | evex0F | evexW0, evexN16 | evexBcstN4 | evexZeroingEnabled, 0xFA,
		avxEscape | evex256 | evex66 | evex0F | evexW0, evexN32 | evexBcstN4 | evexZeroingEnabled, 0xFA,
		avxEscape | evex512 | evex66 | evex0F | evexW0, evexN64 | evexBcstN4 | evexZeroingEnabled, 0xFA,
	}},
	{as: AVPSUBQ, ytab: _yvandnpd, prefix: Pavx, op: opBytes{
		avxEscape | vex128 | vex66 | vex0F | vexW0, 0xFB,
		avxEscape | vex256 | vex66 | vex0F | vexW0, 0xFB,
		avxEscape | evex128 | evex66 | evex0F | evexW1, evexN16 | evexBcstN8 | evexZeroingEnabled, 0xFB,
		avxEscape | evex256 | evex66 | evex0F | evexW1, evexN32 | evexBcstN8 | evexZeroingEnabled, 0xFB,
		avxEscape | evex512 | evex66 | evex0F | evexW1, evexN64 | evexBcstN8 | evexZeroingEnabled, 0xFB,
	}},
	{as: AVPSUBSB, ytab: _yvandnpd, prefix: Pavx, op: opBytes{
		avxEscape | vex128 | vex66 | vex0F | vexW0, 0xE8,
		avxEscape | vex256 | vex66 | vex0F | vexW0, 0xE8,
		avxEscape | evex128 | evex66 | evex0F | evexW0, evexN16 | evexZeroingEnabled, 0xE8,
		avxEscape | evex256 | evex66 | evex0F | evexW0, evexN32 | evexZeroingEnabled, 0xE8,
		avxEscape | evex512 | evex66 | evex0F | evexW0, evexN64 | evexZeroingEnabled, 0xE8,
	}},
	{as: AVPSUBSW, ytab: _yvandnpd, prefix: Pavx, op: opBytes{
		avxEscape | vex128 | vex66 | vex0F | vexW0, 0xE9,
		avxEscape | vex256 | vex66 | vex0F | vexW0, 0xE9,
		avxEscape | evex128 | evex66 | evex0F | evexW0, evexN16 | evexZeroingEnabled, 0xE9,
		avxEscape | evex256 | evex66 | evex0F | evexW0, evexN32 | evexZeroingEnabled, 0xE9,
		avxEscape | evex512 | evex66 | evex0F | evexW0, evexN64 | evexZeroingEnabled, 0xE9,
	}},
	{as: AVPSUBUSB, ytab: _yvandnpd, prefix: Pavx, op: opBytes{
		avxEscape | vex128 | vex66 | vex0F | vexW0, 0xD8,
		avxEscape | vex256 | vex66 | vex0F | vexW0, 0xD8,
		avxEscape | evex128 | evex66 | evex0F | evexW0, evexN16 | evexZeroingEnabled, 0xD8,
		avxEscape | evex256 | evex66 | evex0F | evexW0, evexN32 | evexZeroingEnabled, 0xD8,
		avxEscape | evex512 | evex66 | evex0F | evexW0, evexN64 | evexZeroingEnabled, 0xD8,
	}},
	{as: AVPSUBUSW, ytab: _yvandnpd, prefix: Pavx, op: opBytes{
		avxEscape | vex128 | vex66 | vex0F | vexW0, 0xD9,
		avxEscape | vex256 | vex66 | vex0F | vexW0, 0xD9,
		avxEscape | evex128 | evex66 | evex0F | evexW0, evexN16 | evexZeroingEnabled, 0xD9,
		avxEscape | evex256 | evex66 | evex0F | evexW0, evexN32 | evexZeroingEnabled, 0xD9,
		avxEscape | evex512 | evex66 | evex0F | evexW0, evexN64 | evexZeroingEnabled, 0xD9,
	}},
	{as: AVPSUBW, ytab: _yvandnpd, prefix: Pavx, op: opBytes{
		avxEscape | vex128 | vex66 | vex0F | vexW0, 0xF9,
		avxEscape | vex256 | vex66 | vex0F | vexW0, 0xF9,
		avxEscape | evex128 | evex66 | evex0F | evexW0, evexN16 | evexZeroingEnabled, 0xF9,
		avxEscape | evex256 | evex66 | evex0F | evexW0, evexN32 | evexZeroingEnabled, 0xF9,
		avxEscape | evex512 | evex66 | evex0F | evexW0, evexN64 | evexZeroingEnabled, 0xF9,
	}},
	{as: AVPTERNLOGD, ytab: _yvalignd, prefix: Pavx, op: opBytes{
		avxEscape | evex128 | evex66 | evex0F3A | evexW0, evexN16 | evexBcstN4 | evexZeroingEnabled, 0x25,
		avxEscape | evex256 | evex66 | evex0F3A | evexW0, evexN32 | evexBcstN4 | evexZeroingEnabled, 0x25,
		avxEscape | evex512 | evex66 | evex0F3A | evexW0, evexN64 | evexBcstN4 | evexZeroingEnabled, 0x25,
	}},
	{as: AVPTERNLOGQ, ytab: _yvalignd, prefix: Pavx, op: opBytes{
		avxEscape | evex128 | evex66 | evex0F3A | evexW1, evexN16 | evexBcstN8 | evexZeroingEnabled, 0x25,
		avxEscape | evex256 | evex66 | evex0F3A | evexW1, evexN32 | evexBcstN8 | evexZeroingEnabled, 0x25,
		avxEscape | evex512 | evex66 | evex0F3A | evexW1, evexN64 | evexBcstN8 | evexZeroingEnabled, 0x25,
	}},
	{as: AVPTEST, ytab: _yvptest, prefix: Pavx, op: opBytes{
		avxEscape | vex128 | vex66 | vex0F38 | vexW0, 0x17,
		avxEscape | vex256 | vex66 | vex0F38 | vexW0, 0x17,
	}},
	{as: AVPTESTMB, ytab: _yvpshufbitqmb, prefix: Pavx, op: opBytes{
		avxEscape | evex128 | evex66 | evex0F38 | evexW0, evexN16, 0x26,
		avxEscape | evex256 | evex66 | evex0F38 | evexW0, evexN32, 0x26,
		avxEscape | evex512 | evex66 | evex0F38 | evexW0, evexN64, 0x26,
	}},
	{as: AVPTESTMD, ytab: _yvpshufbitqmb, prefix: Pavx, op: opBytes{
		avxEscape | evex128 | evex66 | evex0F38 | evexW0, evexN16 | evexBcstN4, 0x27,
		avxEscape | evex256 | evex66 | evex0F38 | evexW0, evexN32 | evexBcstN4, 0x27,
		avxEscape | evex512 | evex66 | evex0F38 | evexW0, evexN64 | evexBcstN4, 0x27,
	}},
	{as: AVPTESTMQ, ytab: _yvpshufbitqmb, prefix: Pavx, op: opBytes{
		avxEscape | evex128 | evex66 | evex0F38 | evexW1, evexN16 | evexBcstN8, 0x27,
		avxEscape | evex256 | evex66 | evex0F38 | evexW1, evexN32 | evexBcstN8, 0x27,
		avxEscape | evex512 | evex66 | evex0F38 | evexW1, evexN64 | evexBcstN8, 0x27,
	}},
	{as: AVPTESTMW, ytab: _yvpshufbitqmb, prefix: Pavx, op: opBytes{
		avxEscape | evex128 | evex66 | evex0F38 | evexW1, evexN16, 0x26,
		avxEscape | evex256 | evex66 | evex0F38 | evexW1, evexN32, 0x26,
		avxEscape | evex512 | evex66 | evex0F38 | evexW1, evexN64, 0x26,
	}},
	{as: AVPTESTNMB, ytab: _yvpshufbitqmb, prefix: Pavx, op: opBytes{
		avxEscape | evex128 | evexF3 | evex0F38 | evexW0, evexN16, 0x26,
		avxEscape | evex256 | evexF3 | evex0F38 | evexW0, evexN32, 0x26,
		avxEscape | evex512 | evexF3 | evex0F38 | evexW0, evexN64, 0x26,
	}},
	{as: AVPTESTNMD, ytab: _yvpshufbitqmb, prefix: Pavx, op: opBytes{
		avxEscape | evex128 | evexF3 | evex0F38 | evexW0, evexN16 | evexBcstN4, 0x27,
		avxEscape | evex256 | evexF3 | evex0F38 | evexW0, evexN32 | evexBcstN4, 0x27,
		avxEscape | evex512 | evexF3 | evex0F38 | evexW0, evexN64 | evexBcstN4, 0x27,
	}},
	{as: AVPTESTNMQ, ytab: _yvpshufbitqmb, prefix: Pavx, op: opBytes{
		avxEscape | evex128 | evexF3 | evex0F38 | evexW1, evexN16 | evexBcstN8, 0x27,
		avxEscape | evex256 | evexF3 | evex0F38 | evexW1, evexN32 | evexBcstN8, 0x27,
		avxEscape | evex512 | evexF3 | evex0F38 | evexW1, evexN64 | evexBcstN8, 0x27,
	}},
	{as: AVPTESTNMW, ytab: _yvpshufbitqmb, prefix: Pavx, op: opBytes{
		avxEscape | evex128 | evexF3 | evex0F38 | evexW1, evexN16, 0x26,
		avxEscape | evex256 | evexF3 | evex0F38 | evexW1, evexN32, 0x26,
		avxEscape | evex512 | evexF3 | evex0F38 | evexW1, evexN64, 0x26,
	}},
	{as: AVPUNPCKHBW, ytab: _yvandnpd, prefix: Pavx, op: opBytes{
		avxEscape | vex128 | vex66 | vex0F | vexW0, 0x68,
		avxEscape | vex256 | vex66 | vex0F | vexW0, 0x68,
		avxEscape | evex128 | evex66 | evex0F | evexW0, evexN16 | evexZeroingEnabled, 0x68,
		avxEscape | evex256 | evex66 | evex0F | evexW0, evexN32 | evexZeroingEnabled, 0x68,
		avxEscape | evex512 | evex66 | evex0F | evexW0, evexN64 | evexZeroingEnabled, 0x68,
	}},
	{as: AVPUNPCKHDQ, ytab: _yvandnpd, prefix: Pavx, op: opBytes{
		avxEscape | vex128 | vex66 | vex0F | vexW0, 0x6A,
		avxEscape | vex256 | vex66 | vex0F | vexW0, 0x6A,
		avxEscape | evex128 | evex66 | evex0F | evexW0, evexN16 | evexBcstN4 | evexZeroingEnabled, 0x6A,
		avxEscape | evex256 | evex66 | evex0F | evexW0, evexN32 | evexBcstN4 | evexZeroingEnabled, 0x6A,
		avxEscape | evex512 | evex66 | evex0F | evexW0, evexN64 | evexBcstN4 | evexZeroingEnabled, 0x6A,
	}},
	{as: AVPUNPCKHQDQ, ytab: _yvandnpd, prefix: Pavx, op: opBytes{
		avxEscape | vex128 | vex66 | vex0F | vexW0, 0x6D,
		avxEscape | vex256 | vex66 | vex0F | vexW0, 0x6D,
		avxEscape | evex128 | evex66 | evex0F | evexW1, evexN16 | evexBcstN8 | evexZeroingEnabled, 0x6D,
		avxEscape | evex256 | evex66 | evex0F | evexW1, evexN32 | evexBcstN8 | evexZeroingEnabled, 0x6D,
		avxEscape | evex512 | evex66 | evex0F | evexW1, evexN64 | evexBcstN8 | evexZeroingEnabled, 0x6D,
	}},
	{as: AVPUNPCKHWD, ytab: _yvandnpd, prefix: Pavx, op: opBytes{
		avxEscape | vex128 | vex66 | vex0F | vexW0, 0x69,
		avxEscape | vex256 | vex66 | vex0F | vexW0, 0x69,
		avxEscape | evex128 | evex66 | evex0F | evexW0, evexN16 | evexZeroingEnabled, 0x69,
		avxEscape | evex256 | evex66 | evex0F | evexW0, evexN32 | evexZeroingEnabled, 0x69,
		avxEscape | evex512 | evex66 | evex0F | evexW0, evexN64 | evexZeroingEnabled, 0x69,
	}},
	{as: AVPUNPCKLBW, ytab: _yvandnpd, prefix: Pavx, op: opBytes{
		avxEscape | vex128 | vex66 | vex0F | vexW0, 0x60,
		avxEscape | vex256 | vex66 | vex0F | vexW0, 0x60,
		avxEscape | evex128 | evex66 | evex0F | evexW0, evexN16 | evexZeroingEnabled, 0x60,
		avxEscape | evex256 | evex66 | evex0F | evexW0, evexN32 | evexZeroingEnabled, 0x60,
		avxEscape | evex512 | evex66 | evex0F | evexW0, evexN64 | evexZeroingEnabled, 0x60,
	}},
	{as: AVPUNPCKLDQ, ytab: _yvandnpd, prefix: Pavx, op: opBytes{
		avxEscape | vex128 | vex66 | vex0F | vexW0, 0x62,
		avxEscape | vex256 | vex66 | vex0F | vexW0, 0x62,
		avxEscape | evex128 | evex66 | evex0F | evexW0, evexN16 | evexBcstN4 | evexZeroingEnabled, 0x62,
		avxEscape | evex256 | evex66 | evex0F | evexW0, evexN32 | evexBcstN4 | evexZeroingEnabled, 0x62,
		avxEscape | evex512 | evex66 | evex0F | evexW0, evexN64 | evexBcstN4 | evexZeroingEnabled, 0x62,
	}},
	{as: AVPUNPCKLQDQ, ytab: _yvandnpd, prefix: Pavx, op: opBytes{
		avxEscape | vex128 | vex66 | vex0F | vexW0, 0x6C,
		avxEscape | vex256 | vex66 | vex0F | vexW0, 0x6C,
		avxEscape | evex128 | evex66 | evex0F | evexW1, evexN16 | evexBcstN8 | evexZeroingEnabled, 0x6C,
		avxEscape | evex256 | evex66 | evex0F | evexW1, evexN32 | evexBcstN8 | evexZeroingEnabled, 0x6C,
		avxEscape | evex512 | evex66 | evex0F | evexW1, evexN64 | evexBcstN8 | evexZeroingEnabled, 0x6C,
	}},
	{as: AVPUNPCKLWD, ytab: _yvandnpd, prefix: Pavx, op: opBytes{
		avxEscape | vex128 | vex66 | vex0F | vexW0, 0x61,
		avxEscape | vex256 | vex66 | vex0F | vexW0, 0x61,
		avxEscape | evex128 | evex66 | evex0F | evexW0, evexN16 | evexZeroingEnabled, 0x61,
		avxEscape | evex256 | evex66 | evex0F | evexW0, evexN32 | evexZeroingEnabled, 0x61,
		avxEscape | evex512 | evex66 | evex0F | evexW0, evexN64 | evexZeroingEnabled, 0x61,
	}},
	{as: AVPXOR, ytab: _yvaddsubpd, prefix: Pavx, op: opBytes{
		avxEscape | vex128 | vex66 | vex0F | vexW0, 0xEF,
		avxEscape | vex256 | vex66 | vex0F | vexW0, 0xEF,
	}},
	{as: AVPXORD, ytab: _yvblendmpd, prefix: Pavx, op: opBytes{
		avxEscape | evex128 | evex66 | evex0F | evexW0, evexN16 | evexBcstN4 | evexZeroingEnabled, 0xEF,
		avxEscape | evex256 | evex66 | evex0F | evexW0, evexN32 | evexBcstN4 | evexZeroingEnabled, 0xEF,
		avxEscape | evex512 | evex66 | evex0F | evexW0, evexN64 | evexBcstN4 | evexZeroingEnabled, 0xEF,
	}},
	{as: AVPXORQ, ytab: _yvblendmpd, prefix: Pavx, op: opBytes{
		avxEscape | evex128 | evex66 | evex0F | evexW1, evexN16 | evexBcstN8 | evexZeroingEnabled, 0xEF,
		avxEscape | evex256 | evex66 | evex0F | evexW1, evexN32 | evexBcstN8 | evexZeroingEnabled, 0xEF,
		avxEscape | evex512 | evex66 | evex0F | evexW1, evexN64 | evexBcstN8 | evexZeroingEnabled, 0xEF,
	}},
	{as: AVRANGEPD, ytab: _yvfixupimmpd, prefix: Pavx, op: opBytes{
		avxEscape | evex512 | evex66 | evex0F3A | evexW1, evexN64 | evexBcstN8 | evexSaeEnabled | evexZeroingEnabled, 0x50,
		avxEscape | evex128 | evex66 | evex0F3A | evexW1, evexN16 | evexBcstN8 | evexZeroingEnabled, 0x50,
		avxEscape | evex256 | evex66 | evex0F3A | evexW1, evexN32 | evexBcstN8 | evexZeroingEnabled, 0x50,
	}},
	{as: AVRANGEPS, ytab: _yvfixupimmpd, prefix: Pavx, op: opBytes{
		avxEscape | evex512 | evex66 | evex0F3A | evexW0, evexN64 | evexBcstN4 | evexSaeEnabled | evexZeroingEnabled, 0x50,
		avxEscape | evex128 | evex66 | evex0F3A | evexW0, evexN16 | evexBcstN4 | evexZeroingEnabled, 0x50,
		avxEscape | evex256 | evex66 | evex0F3A | evexW0, evexN32 | evexBcstN4 | evexZeroingEnabled, 0x50,
	}},
	{as: AVRANGESD, ytab: _yvfixupimmsd, prefix: Pavx, op: opBytes{
		avxEscape | evex128 | evex66 | evex0F3A | evexW1, evexN8 | evexSaeEnabled | evexZeroingEnabled, 0x51,
	}},
	{as: AVRANGESS, ytab: _yvfixupimmsd, prefix: Pavx, op: opBytes{
		avxEscape | evex128 | evex66 | evex0F3A | evexW0, evexN4 | evexSaeEnabled | evexZeroingEnabled, 0x51,
	}},
	{as: AVRCP14PD, ytab: _yvexpandpd, prefix: Pavx, op: opBytes{
		avxEscape | evex128 | evex66 | evex0F38 | evexW1, evexN16 | evexBcstN8 | evexZeroingEnabled, 0x4C,
		avxEscape | evex256 | evex66 | evex0F38 | evexW1, evexN32 | evexBcstN8 | evexZeroingEnabled, 0x4C,
		avxEscape | evex512 | evex66 | evex0F38 | evexW1, evexN64 | evexBcstN8 | evexZeroingEnabled, 0x4C,
	}},
	{as: AVRCP14PS, ytab: _yvexpandpd, prefix: Pavx, op: opBytes{
		avxEscape | evex128 | evex66 | evex0F38 | evexW0, evexN16 | evexBcstN4 | evexZeroingEnabled, 0x4C,
		avxEscape | evex256 | evex66 | evex0F38 | evexW0, evexN32 | evexBcstN4 | evexZeroingEnabled, 0x4C,
		avxEscape | evex512 | evex66 | evex0F38 | evexW0, evexN64 | evexBcstN4 | evexZeroingEnabled, 0x4C,
	}},
	{as: AVRCP14SD, ytab: _yvgetexpsd, prefix: Pavx, op: opBytes{
		avxEscape | evex128 | evex66 | evex0F38 | evexW1, evexN8 | evexZeroingEnabled, 0x4D,
	}},
	{as: AVRCP14SS, ytab: _yvgetexpsd, prefix: Pavx, op: opBytes{
		avxEscape | evex128 | evex66 | evex0F38 | evexW0, evexN4 | evexZeroingEnabled, 0x4D,
	}},
	{as: AVRCP28PD, ytab: _yvexp2pd, prefix: Pavx, op: opBytes{
		avxEscape | evex512 | evex66 | evex0F38 | evexW1, evexN64 | evexBcstN8 | evexSaeEnabled | evexZeroingEnabled, 0xCA,
	}},
	{as: AVRCP28PS, ytab: _yvexp2pd, prefix: Pavx, op: opBytes{
		avxEscape | evex512 | evex66 | evex0F38 | evexW0, evexN64 | evexBcstN4 | evexSaeEnabled | evexZeroingEnabled, 0xCA,
	}},
	{as: AVRCP28SD, ytab: _yvgetexpsd, prefix: Pavx, op: opBytes{
		avxEscape | evex128 | evex66 | evex0F38 | evexW1, evexN8 | evexSaeEnabled | evexZeroingEnabled, 0xCB,
	}},
	{as: AVRCP28SS, ytab: _yvgetexpsd, prefix: Pavx, op: opBytes{
		avxEscape | evex128 | evex66 | evex0F38 | evexW0, evexN4 | evexSaeEnabled | evexZeroingEnabled, 0xCB,
	}},
	{as: AVRCPPS, ytab: _yvptest, prefix: Pavx, op: opBytes{
		avxEscape | vex128 | vex0F | vexW0, 0x53,
		avxEscape | vex256 | vex0F | vexW0, 0x53,
	}},
	{as: AVRCPSS, ytab: _yvrcpss, prefix: Pavx, op: opBytes{
		avxEscape | vex128 | vexF3 | vex0F | vexW0, 0x53,
	}},
	{as: AVREDUCEPD, ytab: _yvgetmantpd, prefix: Pavx, op: opBytes{
		avxEscape | evex512 | evex66 | evex0F3A | evexW1, evexN64 | evexBcstN8 | evexSaeEnabled | evexZeroingEnabled, 0x56,
		avxEscape | evex128 | evex66 | evex0F3A | evexW1, evexN16 | evexBcstN8 | evexZeroingEnabled, 0x56,
		avxEscape | evex256 | evex66 | evex0F3A | evexW1, evexN32 | evexBcstN8 | evexZeroingEnabled, 0x56,
	}},
	{as: AVREDUCEPS, ytab: _yvgetmantpd, prefix: Pavx, op: opBytes{
		avxEscape | evex512 | evex66 | evex0F3A | evexW0, evexN64 | evexBcstN4 | evexSaeEnabled | evexZeroingEnabled, 0x56,
		avxEscape | evex128 | evex66 | evex0F3A | evexW0, evexN16 | evexBcstN4 | evexZeroingEnabled, 0x56,
		avxEscape | evex256 | evex66 | evex0F3A | evexW0, evexN32 | evexBcstN4 | evexZeroingEnabled, 0x56,
	}},
	{as: AVREDUCESD, ytab: _yvfixupimmsd, prefix: Pavx, op: opBytes{
		avxEscape | evex128 | evex66 | evex0F3A | evexW1, evexN8 | evexSaeEnabled | evexZeroingEnabled, 0x57,
	}},
	{as: AVREDUCESS, ytab: _yvfixupimmsd, prefix: Pavx, op: opBytes{
		avxEscape | evex128 | evex66 | evex0F3A | evexW0, evexN4 | evexSaeEnabled | evexZeroingEnabled, 0x57,
	}},
	{as: AVRNDSCALEPD, ytab: _yvgetmantpd, prefix: Pavx, op: opBytes{
		avxEscape | evex512 | evex66 | evex0F3A | evexW1, evexN64 | evexBcstN8 | evexSaeEnabled | evexZeroingEnabled, 0x09,
		avxEscape | evex128 | evex66 | evex0F3A | evexW1, evexN16 | evexBcstN8 | evexZeroingEnabled, 0x09,
		avxEscape | evex256 | evex66 | evex0F3A | evexW1, evexN32 | evexBcstN8 | evexZeroingEnabled, 0x09,
	}},
	{as: AVRNDSCALEPS, ytab: _yvgetmantpd, prefix: Pavx, op: opBytes{
		avxEscape | evex512 | evex66 | evex0F3A | evexW0, evexN64 | evexBcstN4 | evexSaeEnabled | evexZeroingEnabled, 0x08,
		avxEscape | evex128 | evex66 | evex0F3A | evexW0, evexN16 | evexBcstN4 | evexZeroingEnabled, 0x08,
		avxEscape | evex256 | evex66 | evex0F3A | evexW0, evexN32 | evexBcstN4 | evexZeroingEnabled, 0x08,
	}},
	{as: AVRNDSCALESD, ytab: _yvfixupimmsd, prefix: Pavx, op: opBytes{
		avxEscape | evex128 | evex66 | evex0F3A | evexW1, evexN8 | evexSaeEnabled | evexZeroingEnabled, 0x0B,
	}},
	{as: AVRNDSCALESS, ytab: _yvfixupimmsd, prefix: Pavx, op: opBytes{
		avxEscape | evex128 | evex66 | evex0F3A | evexW0, evexN4 | evexSaeEnabled | evexZeroingEnabled, 0x0A,
	}},
	{as: AVROUNDPD, ytab: _yvroundpd, prefix: Pavx, op: opBytes{
		avxEscape | vex128 | vex66 | vex0F3A | vexW0, 0x09,
		avxEscape | vex256 | vex66 | vex0F3A | vexW0, 0x09,
	}},
	{as: AVROUNDPS, ytab: _yvroundpd, prefix: Pavx, op: opBytes{
		avxEscape | vex128 | vex66 | vex0F3A | vexW0, 0x08,
		avxEscape | vex256 | vex66 | vex0F3A | vexW0, 0x08,
	}},
	{as: AVROUNDSD, ytab: _yvdppd, prefix: Pavx, op: opBytes{
		avxEscape | vex128 | vex66 | vex0F3A | vexW0, 0x0B,
	}},
	{as: AVROUNDSS, ytab: _yvdppd, prefix: Pavx, op: opBytes{
		avxEscape | vex128 | vex66 | vex0F3A | vexW0, 0x0A,
	}},
	{as: AVRSQRT14PD, ytab: _yvexpandpd, prefix: Pavx, op: opBytes{
		avxEscape | evex128 | evex66 | evex0F38 | evexW1, evexN16 | evexBcstN8 | evexZeroingEnabled, 0x4E,
		avxEscape | evex256 | evex66 | evex0F38 | evexW1, evexN32 | evexBcstN8 | evexZeroingEnabled, 0x4E,
		avxEscape | evex512 | evex66 | evex0F38 | evexW1, evexN64 | evexBcstN8 | evexZeroingEnabled, 0x4E,
	}},
	{as: AVRSQRT14PS, ytab: _yvexpandpd, prefix: Pavx, op: opBytes{
		avxEscape | evex128 | evex66 | evex0F38 | evexW0, evexN16 | evexBcstN4 | evexZeroingEnabled, 0x4E,
		avxEscape | evex256 | evex66 | evex0F38 | evexW0, evexN32 | evexBcstN4 | evexZeroingEnabled, 0x4E,
		avxEscape | evex512 | evex66 | evex0F38 | evexW0, evexN64 | evexBcstN4 | evexZeroingEnabled, 0x4E,
	}},
	{as: AVRSQRT14SD, ytab: _yvgetexpsd, prefix: Pavx, op: opBytes{
		avxEscape | evex128 | evex66 | evex0F38 | evexW1, evexN8 | evexZeroingEnabled, 0x4F,
	}},
	{as: AVRSQRT14SS, ytab: _yvgetexpsd, prefix: Pavx, op: opBytes{
		avxEscape | evex128 | evex66 | evex0F38 | evexW0, evexN4 | evexZeroingEnabled, 0x4F,
	}},
	{as: AVRSQRT28PD, ytab: _yvexp2pd, prefix: Pavx, op: opBytes{
		avxEscape | evex512 | evex66 | evex0F38 | evexW1, evexN64 | evexBcstN8 | evexSaeEnabled | evexZeroingEnabled, 0xCC,
	}},
	{as: AVRSQRT28PS, ytab: _yvexp2pd, prefix: Pavx, op: opBytes{
		avxEscape | evex512 | evex66 | evex0F38 | evexW0, evexN64 | evexBcstN4 | evexSaeEnabled | evexZeroingEnabled, 0xCC,
	}},
	{as: AVRSQRT28SD, ytab: _yvgetexpsd, prefix: Pavx, op: opBytes{
		avxEscape | evex128 | evex66 | evex0F38 | evexW1, evexN8 | evexSaeEnabled | evexZeroingEnabled, 0xCD,
	}},
	{as: AVRSQRT28SS, ytab: _yvgetexpsd, prefix: Pavx, op: opBytes{
		avxEscape | evex128 | evex66 | evex0F38 | evexW0, evexN4 | evexSaeEnabled | evexZeroingEnabled, 0xCD,
	}},
	{as: AVRSQRTPS, ytab: _yvptest, prefix: Pavx, op: opBytes{
		avxEscape | vex128 | vex0F | vexW0, 0x52,
		avxEscape | vex256 | vex0F | vexW0, 0x52,
	}},
	{as: AVRSQRTSS, ytab: _yvrcpss, prefix: Pavx, op: opBytes{
		avxEscape | vex128 | vexF3 | vex0F | vexW0, 0x52,
	}},
	{as: AVSCALEFPD, ytab: _yvscalefpd, prefix: Pavx, op: opBytes{
		avxEscape | evex512 | evex66 | evex0F38 | evexW1, evexN64 | evexBcstN8 | evexRoundingEnabled | evexZeroingEnabled, 0x2C,
		avxEscape | evex128 | evex66 | evex0F38 | evexW1, evexN16 | evexBcstN8 | evexZeroingEnabled, 0x2C,
		avxEscape | evex256 | evex66 | evex0F38 | evexW1, evexN32 | evexBcstN8 | evexZeroingEnabled, 0x2C,
	}},
	{as: AVSCALEFPS, ytab: _yvscalefpd, prefix: Pavx, op: opBytes{
		avxEscape | evex512 | evex66 | evex0F38 | evexW0, evexN64 | evexBcstN4 | evexRoundingEnabled | evexZeroingEnabled, 0x2C,
		avxEscape | evex128 | evex66 | evex0F38 | evexW0, evexN16 | evexBcstN4 | evexZeroingEnabled, 0x2C,
		avxEscape | evex256 | evex66 | evex0F38 | evexW0, evexN32 | evexBcstN4 | evexZeroingEnabled, 0x2C,
	}},
	{as: AVSCALEFSD, ytab: _yvgetexpsd, prefix: Pavx, op: opBytes{
		avxEscape | evex128 | evex66 | evex0F38 | evexW1, evexN8 | evexRoundingEnabled | evexZeroingEnabled, 0x2D,
	}},
	{as: AVSCALEFSS, ytab: _yvgetexpsd, prefix: Pavx, op: opBytes{
		avxEscape | evex128 | evex66 | evex0F38 | evexW0, evexN4 | evexRoundingEnabled | evexZeroingEnabled, 0x2D,
	}},
	{as: AVSCATTERDPD, ytab: _yvpscatterdq, prefix: Pavx, op: opBytes{
		avxEscape | evex128 | evex66 | evex0F38 | evexW1, evexN8, 0xA2,
		avxEscape | evex256 | evex66 | evex0F38 | evexW1, evexN8, 0xA2,
		avxEscape | evex512 | evex66 | evex0F38 | evexW1, evexN8, 0xA2,
	}},
	{as: AVSCATTERDPS, ytab: _yvpscatterdd, prefix: Pavx, op: opBytes{
		avxEscape | evex128 | evex66 | evex0F38 | evexW0, evexN4, 0xA2,
		avxEscape | evex256 | evex66 | evex0F38 | evexW0, evexN4, 0xA2,
		avxEscape | evex512 | evex66 | evex0F38 | evexW0, evexN4, 0xA2,
	}},
	{as: AVSCATTERPF0DPD, ytab: _yvgatherpf0dpd, prefix: Pavx, op: opBytes{
		avxEscape | evex512 | evex66 | evex0F38 | evexW1, evexN8, 0xC6, 05,
	}},
	{as: AVSCATTERPF0DPS, ytab: _yvgatherpf0dps, prefix: Pavx, op: opBytes{
		avxEscape | evex512 | evex66 | evex0F38 | evexW0, evexN4, 0xC6, 05,
	}},
	{as: AVSCATTERPF0QPD, ytab: _yvgatherpf0dps, prefix: Pavx, op: opBytes{
		avxEscape | evex512 | evex66 | evex0F38 | evexW1, evexN8, 0xC7, 05,
	}},
	{as: AVSCATTERPF0QPS, ytab: _yvgatherpf0dps, prefix: Pavx, op: opBytes{
		avxEscape | evex512 | evex66 | evex0F38 | evexW0, evexN4, 0xC7, 05,
	}},
	{as: AVSCATTERPF1DPD, ytab: _yvgatherpf0dpd, prefix: Pavx, op: opBytes{
		avxEscape | evex512 | evex66 | evex0F38 | evexW1, evexN8, 0xC6, 06,
	}},
	{as: AVSCATTERPF1DPS, ytab: _yvgatherpf0dps, prefix: Pavx, op: opBytes{
		avxEscape | evex512 | evex66 | evex0F38 | evexW0, evexN4, 0xC6, 06,
	}},
	{as: AVSCATTERPF1QPD, ytab: _yvgatherpf0dps, prefix: Pavx, op: opBytes{
		avxEscape | evex512 | evex66 | evex0F38 | evexW1, evexN8, 0xC7, 06,
	}},
	{as: AVSCATTERPF1QPS, ytab: _yvgatherpf0dps, prefix: Pavx, op: opBytes{
		avxEscape | evex512 | evex66 | evex0F38 | evexW0, evexN4, 0xC7, 06,
	}},
	{as: AVSCATTERQPD, ytab: _yvpscatterdd, prefix: Pavx, op: opBytes{
		avxEscape | evex128 | evex66 | evex0F38 | evexW1, evexN8, 0xA3,
		avxEscape | evex256 | evex66 | evex0F38 | evexW1, evexN8, 0xA3,
		avxEscape | evex512 | evex66 | evex0F38 | evexW1, evexN8, 0xA3,
	}},
	{as: AVSCATTERQPS, ytab: _yvpscatterqd, prefix: Pavx, op: opBytes{
		avxEscape | evex128 | evex66 | evex0F38 | evexW0, evexN4, 0xA3,
		avxEscape | evex256 | evex66 | evex0F38 | evexW0, evexN4, 0xA3,
		avxEscape | evex512 | evex66 | evex0F38 | evexW0, evexN4, 0xA3,
	}},
	{as: AVSHUFF32X4, ytab: _yvshuff32x4, prefix: Pavx, op: opBytes{
		avxEscape | evex256 | evex66 | evex0F3A | evexW0, evexN32 | evexBcstN4 | evexZeroingEnabled, 0x23,
		avxEscape | evex512 | evex66 | evex0F3A | evexW0, evexN64 | evexBcstN4 | evexZeroingEnabled, 0x23,
	}},
	{as: AVSHUFF64X2, ytab: _yvshuff32x4, prefix: Pavx, op: opBytes{
		avxEscape | evex256 | evex66 | evex0F3A | evexW1, evexN32 | evexBcstN8 | evexZeroingEnabled, 0x23,
		avxEscape | evex512 | evex66 | evex0F3A | evexW1, evexN64 | evexBcstN8 | evexZeroingEnabled, 0x23,
	}},
	{as: AVSHUFI32X4, ytab: _yvshuff32x4, prefix: Pavx, op: opBytes{
		avxEscape | evex256 | evex66 | evex0F3A | evexW0, evexN32 | evexBcstN4 | evexZeroingEnabled, 0x43,
		avxEscape | evex512 | evex66 | evex0F3A | evexW0, evexN64 | evexBcstN4 | evexZeroingEnabled, 0x43,
	}},
	{as: AVSHUFI64X2, ytab: _yvshuff32x4, prefix: Pavx, op: opBytes{
		avxEscape | evex256 | evex66 | evex0F3A | evexW1, evexN32 | evexBcstN8 | evexZeroingEnabled, 0x43,
		avxEscape | evex512 | evex66 | evex0F3A | evexW1, evexN64 | evexBcstN8 | evexZeroingEnabled, 0x43,
	}},
	{as: AVSHUFPD, ytab: _yvgf2p8affineinvqb, prefix: Pavx, op: opBytes{
		avxEscape | vex128 | vex66 | vex0F | vexW0, 0xC6,
		avxEscape | vex256 | vex66 | vex0F | vexW0, 0xC6,
		avxEscape | evex128 | evex66 | evex0F | evexW1, evexN16 | evexBcstN8 | evexZeroingEnabled, 0xC6,
		avxEscape | evex256 | evex66 | evex0F | evexW1, evexN32 | evexBcstN8 | evexZeroingEnabled, 0xC6,
		avxEscape | evex512 | evex66 | evex0F | evexW1, evexN64 | evexBcstN8 | evexZeroingEnabled, 0xC6,
	}},
	{as: AVSHUFPS, ytab: _yvgf2p8affineinvqb, prefix: Pavx, op: opBytes{
		avxEscape | vex128 | vex0F | vexW0, 0xC6,
		avxEscape | vex256 | vex0F | vexW0, 0xC6,
		avxEscape | evex128 | evex0F | evexW0, evexN16 | evexBcstN4 | evexZeroingEnabled, 0xC6,
		avxEscape | evex256 | evex0F | evexW0, evexN32 | evexBcstN4 | evexZeroingEnabled, 0xC6,
		avxEscape | evex512 | evex0F | evexW0, evexN64 | evexBcstN4 | evexZeroingEnabled, 0xC6,
	}},
	{as: AVSQRTPD, ytab: _yvcvtdq2ps, prefix: Pavx, op: opBytes{
		avxEscape | vex128 | vex66 | vex0F | vexW0, 0x51,
		avxEscape | vex256 | vex66 | vex0F | vexW0, 0x51,
		avxEscape | evex512 | evex66 | evex0F | evexW1, evexN64 | evexBcstN8 | evexRoundingEnabled | evexZeroingEnabled, 0x51,
		avxEscape | evex128 | evex66 | evex0F | evexW1, evexN16 | evexBcstN8 | evexZeroingEnabled, 0x51,
		avxEscape | evex256 | evex66 | evex0F | evexW1, evexN32 | evexBcstN8 | evexZeroingEnabled, 0x51,
	}},
	{as: AVSQRTPS, ytab: _yvcvtdq2ps, prefix: Pavx, op: opBytes{
		avxEscape | vex128 | vex0F | vexW0, 0x51,
		avxEscape | vex256 | vex0F | vexW0, 0x51,
		avxEscape | evex512 | evex0F | evexW0, evexN64 | evexBcstN4 | evexRoundingEnabled | evexZeroingEnabled, 0x51,
		avxEscape | evex128 | evex0F | evexW0, evexN16 | evexBcstN4 | evexZeroingEnabled, 0x51,
		avxEscape | evex256 | evex0F | evexW0, evexN32 | evexBcstN4 | evexZeroingEnabled, 0x51,
	}},
	{as: AVSQRTSD, ytab: _yvaddsd, prefix: Pavx, op: opBytes{
		avxEscape | vex128 | vexF2 | vex0F | vexW0, 0x51,
		avxEscape | evex128 | evexF2 | evex0F | evexW1, evexN8 | evexRoundingEnabled | evexZeroingEnabled, 0x51,
	}},
	{as: AVSQRTSS, ytab: _yvaddsd, prefix: Pavx, op: opBytes{
		avxEscape | vex128 | vexF3 | vex0F | vexW0, 0x51,
		avxEscape | evex128 | evexF3 | evex0F | evexW0, evexN4 | evexRoundingEnabled | evexZeroingEnabled, 0x51,
	}},
	{as: AVSTMXCSR, ytab: _yvldmxcsr, prefix: Pavx, op: opBytes{
		avxEscape | vex128 | vex0F | vexW0, 0xAE, 03,
	}},
	{as: AVSUBPD, ytab: _yvaddpd, prefix: Pavx, op: opBytes{
		avxEscape | vex128 | vex66 | vex0F | vexW0, 0x5C,
		avxEscape | vex256 | vex66 | vex0F | vexW0, 0x5C,
		avxEscape | evex512 | evex66 | evex0F | evexW1, evexN64 | evexBcstN8 | evexRoundingEnabled | evexZeroingEnabled, 0x5C,
		avxEscape | evex128 | evex66 | evex0F | evexW1, evexN16 | evexBcstN8 | evexZeroingEnabled, 0x5C,
		avxEscape | evex256 | evex66 | evex0F | evexW1, evexN32 | evexBcstN8 | evexZeroingEnabled, 0x5C,
	}},
	{as: AVSUBPS, ytab: _yvaddpd, prefix: Pavx, op: opBytes{
		avxEscape | vex128 | vex0F | vexW0, 0x5C,
		avxEscape | vex256 | ve
"""




```