Response:
The user has provided a snippet of Go code from `go/src/cmd/internal/obj/x86/avx_optabs.go`. This file likely defines the instruction set and their encodings for the x86 architecture, specifically focusing on AVX instructions.

The user wants to understand the functionality of this code snippet, which is the 6th part of a 9-part series.

**Plan:**

1. **Identify the structure:** The code is a slice of structs. Each struct seems to define an AVX instruction with its assembly name (`as`), a table for different operand types (`ytab`), a prefix (`prefix`), and the opcode bytes (`op`).
2. **Explain the purpose of each field:**
    - `as`:  Assembly instruction mnemonic (e.g., AVPCMPUD).
    - `ytab`:  Likely a lookup table to determine valid operand combinations for the instruction.
    - `prefix`:  Instruction prefix (Pavx suggests AVX).
    - `op`:  Opcode bytes defining the instruction's binary representation. The `opBytes` struct likely contains different encodings based on AVX features (e.g., vector length, operand size).
3. **Infer the overall functionality:** This code defines the mapping between assembly instructions and their machine code representation for AVX instructions. This is crucial for the Go compiler to translate assembly code into executable machine code.
4. **Provide a Go code example:**  Demonstrate how these instructions might be used in Go assembly.
5. **Explain any command-line arguments:** This file is not directly used by command-line arguments. It's part of the compiler's internal data. So, this point is not applicable.
6. **Highlight potential errors:**  Directly using these internal data structures is not typical for Go developers. Potential errors would arise if someone tries to manually modify this file without understanding the implications for the Go compiler.
7. **Summarize the functionality of this part:** Focus on the specific instructions defined in this code block.
这段代码是Go编译器内部用于定义x86架构下AVX（高级向量扩展）指令集的机器码表示的一部分。它定义了一系列AVX指令及其对应的操作码（opcodes）和相关的属性。

**功能列举:**

1. **定义AVX指令的助记符 (as):**  例如 `AVPCMPUD`, `AVPCOMPRESSB` 等，这些是程序员在汇编代码中使用的指令名称。
2. **指定操作数类型表 (ytab):**  例如 `_yvpcmpb`, `_yvcompresspd`。这些表定义了指令可以接受的不同操作数类型组合。
3. **定义指令前缀 (prefix):**  例如 `Pavx`，表明这些是AVX指令。
4. **定义指令的操作码字节 (op):** `opBytes` 结构体中包含了一系列字节，用于表示该指令在不同AVX扩展下的机器码编码。这些编码会根据不同的特性（如向量长度 128/256/512 位，数据类型等）而有所不同。

**推理解释和Go代码示例:**

这段代码是Go编译器将AVX汇编指令翻译成机器码的关键数据。当Go编译器遇到使用AVX指令的汇编代码时，它会查找这个表来确定如何编码该指令。

假设我们想在Go汇编中使用 `AVPCOMPRESSD` 指令，将一个向量寄存器中的非零元素压缩到另一个向量寄存器中。

**假设的输入（Go汇编代码）：**

```assembly
#include "textflag.h"

// func compress(in []int32) []int32
TEXT ·compress(SB), NOSPLIT, $0-16
    MOVQ    (SP), AX     // in slice pointer
    MOVQ    8(SP), BX     // in slice length
    LEAQ    returndata<>(SB), CX // result slice data pointer
    MOVQ    $0, DX        // result slice length

    VPXOR   Y0, Y0, Y0    // 清零 Y0 寄存器
    MOVQ    BX, SI
loop:
    CMPQ    SI, $0
    JE      end

    MOVL    (AX)(SI*4 - 4), R8D // 加载输入切片元素到 R8D
    CMPL    R8D, $0
    JE      next_element

    MOVL    R8D, (CX)(DX*4)   // 将非零元素写入结果切片
    INCQ    DX

next_element:
    DECQ    SI
    JMP     loop

end:
    MOVQ    DX, returndata+8(SB) // 设置结果切片长度
    RET
```

**输出 (编译器根据 `avx_optabs.go` 中的信息生成的部分机器码)：**

当编译器处理 `AVPCOMPRESSD` 相关的汇编指令时，会根据 `avx_optabs.go` 中 `AVPCOMPRESSD` 的定义，选择合适的机器码编码。例如，对于256位的向量操作，它可能会选择 `avxEscape | evex256 | evex66 | evex0F38 | evexW0, evexN4 | evexZeroingEnabled, 0x8B` 对应的编码。

**涉及的代码推理:**

`avx_optabs.go` 文件本身不执行程序逻辑，它只是数据的定义。Go编译器（例如 `compile/internal/gc`）在编译过程中会读取并使用这些数据。编译器会根据汇编指令的操作数类型、向量长度等信息，匹配到 `avx_optabs.go` 中对应的条目，并生成相应的机器码。

**命令行参数的具体处理:**

这个文件本身不处理命令行参数。Go编译器的命令行参数由 `cmd/compile` 包处理。`avx_optabs.go` 中定义的数据会被编译器内部的逻辑使用，而不会直接受命令行参数的影响。但是，编译器的某些命令行参数（例如 `-gcflags -V=2`）可能会影响编译器输出的调试信息，从而间接地让你看到编译器如何使用这些数据。

**使用者易犯错的点:**

普通Go开发者通常不会直接与 `avx_optabs.go` 文件交互。这个文件是Go编译器内部实现的一部分。

**归纳一下它的功能 (第6部分):**

这部分代码主要定义了一系列以 "AVP" 开头的AVX指令的操作码映射，这些指令涵盖了诸如**打包比较 (PCMP)**、**压缩 (COMPRESS)**、**冲突检测 (CONFLICT)**、**点积 (PDP)**、**数据重排 (PERM)**、**扩展 (EXPAND)**、**提取 (EXTR)**、**分散/收集 (GATHER)**、**水平加减 (PHADD/PHSUB)**、**插入 (PINSR)**、**前导零计数 (PLZCNT)**、**带符号/无符号乘法 (PMADD)**、**掩码移动 (PMASKMOV)**、**最大/最小值 (PMAX/PMIN)** 以及 **向量寄存器到掩码寄存器/掩码寄存器到向量寄存器移动 (PMOV)** 等多种操作。这些指令是AVX指令集中用于处理向量数据的核心指令，提供了更高级和高效的数据并行处理能力。

### 提示词
```
这是路径为go/src/cmd/internal/obj/x86/avx_optabs.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第6部分，共9部分，请归纳一下它的功能
```

### 源代码
```go
3A | evexW0, evexN32, 0x3E,
		avxEscape | evex512 | evex66 | evex0F3A | evexW0, evexN64, 0x3E,
	}},
	{as: AVPCMPUD, ytab: _yvpcmpb, prefix: Pavx, op: opBytes{
		avxEscape | evex128 | evex66 | evex0F3A | evexW0, evexN16 | evexBcstN4, 0x1E,
		avxEscape | evex256 | evex66 | evex0F3A | evexW0, evexN32 | evexBcstN4, 0x1E,
		avxEscape | evex512 | evex66 | evex0F3A | evexW0, evexN64 | evexBcstN4, 0x1E,
	}},
	{as: AVPCMPUQ, ytab: _yvpcmpb, prefix: Pavx, op: opBytes{
		avxEscape | evex128 | evex66 | evex0F3A | evexW1, evexN16 | evexBcstN8, 0x1E,
		avxEscape | evex256 | evex66 | evex0F3A | evexW1, evexN32 | evexBcstN8, 0x1E,
		avxEscape | evex512 | evex66 | evex0F3A | evexW1, evexN64 | evexBcstN8, 0x1E,
	}},
	{as: AVPCMPUW, ytab: _yvpcmpb, prefix: Pavx, op: opBytes{
		avxEscape | evex128 | evex66 | evex0F3A | evexW1, evexN16, 0x3E,
		avxEscape | evex256 | evex66 | evex0F3A | evexW1, evexN32, 0x3E,
		avxEscape | evex512 | evex66 | evex0F3A | evexW1, evexN64, 0x3E,
	}},
	{as: AVPCMPW, ytab: _yvpcmpb, prefix: Pavx, op: opBytes{
		avxEscape | evex128 | evex66 | evex0F3A | evexW1, evexN16, 0x3F,
		avxEscape | evex256 | evex66 | evex0F3A | evexW1, evexN32, 0x3F,
		avxEscape | evex512 | evex66 | evex0F3A | evexW1, evexN64, 0x3F,
	}},
	{as: AVPCOMPRESSB, ytab: _yvcompresspd, prefix: Pavx, op: opBytes{
		avxEscape | evex128 | evex66 | evex0F38 | evexW0, evexN1 | evexZeroingEnabled, 0x63,
		avxEscape | evex256 | evex66 | evex0F38 | evexW0, evexN1 | evexZeroingEnabled, 0x63,
		avxEscape | evex512 | evex66 | evex0F38 | evexW0, evexN1 | evexZeroingEnabled, 0x63,
	}},
	{as: AVPCOMPRESSD, ytab: _yvcompresspd, prefix: Pavx, op: opBytes{
		avxEscape | evex128 | evex66 | evex0F38 | evexW0, evexN4 | evexZeroingEnabled, 0x8B,
		avxEscape | evex256 | evex66 | evex0F38 | evexW0, evexN4 | evexZeroingEnabled, 0x8B,
		avxEscape | evex512 | evex66 | evex0F38 | evexW0, evexN4 | evexZeroingEnabled, 0x8B,
	}},
	{as: AVPCOMPRESSQ, ytab: _yvcompresspd, prefix: Pavx, op: opBytes{
		avxEscape | evex128 | evex66 | evex0F38 | evexW1, evexN8 | evexZeroingEnabled, 0x8B,
		avxEscape | evex256 | evex66 | evex0F38 | evexW1, evexN8 | evexZeroingEnabled, 0x8B,
		avxEscape | evex512 | evex66 | evex0F38 | evexW1, evexN8 | evexZeroingEnabled, 0x8B,
	}},
	{as: AVPCOMPRESSW, ytab: _yvcompresspd, prefix: Pavx, op: opBytes{
		avxEscape | evex128 | evex66 | evex0F38 | evexW1, evexN2 | evexZeroingEnabled, 0x63,
		avxEscape | evex256 | evex66 | evex0F38 | evexW1, evexN2 | evexZeroingEnabled, 0x63,
		avxEscape | evex512 | evex66 | evex0F38 | evexW1, evexN2 | evexZeroingEnabled, 0x63,
	}},
	{as: AVPCONFLICTD, ytab: _yvexpandpd, prefix: Pavx, op: opBytes{
		avxEscape | evex128 | evex66 | evex0F38 | evexW0, evexN16 | evexBcstN4 | evexZeroingEnabled, 0xC4,
		avxEscape | evex256 | evex66 | evex0F38 | evexW0, evexN32 | evexBcstN4 | evexZeroingEnabled, 0xC4,
		avxEscape | evex512 | evex66 | evex0F38 | evexW0, evexN64 | evexBcstN4 | evexZeroingEnabled, 0xC4,
	}},
	{as: AVPCONFLICTQ, ytab: _yvexpandpd, prefix: Pavx, op: opBytes{
		avxEscape | evex128 | evex66 | evex0F38 | evexW1, evexN16 | evexBcstN8 | evexZeroingEnabled, 0xC4,
		avxEscape | evex256 | evex66 | evex0F38 | evexW1, evexN32 | evexBcstN8 | evexZeroingEnabled, 0xC4,
		avxEscape | evex512 | evex66 | evex0F38 | evexW1, evexN64 | evexBcstN8 | evexZeroingEnabled, 0xC4,
	}},
	{as: AVPDPBUSD, ytab: _yvblendmpd, prefix: Pavx, op: opBytes{
		avxEscape | evex128 | evex66 | evex0F38 | evexW0, evexN16 | evexBcstN4 | evexZeroingEnabled, 0x50,
		avxEscape | evex256 | evex66 | evex0F38 | evexW0, evexN32 | evexBcstN4 | evexZeroingEnabled, 0x50,
		avxEscape | evex512 | evex66 | evex0F38 | evexW0, evexN64 | evexBcstN4 | evexZeroingEnabled, 0x50,
	}},
	{as: AVPDPBUSDS, ytab: _yvblendmpd, prefix: Pavx, op: opBytes{
		avxEscape | evex128 | evex66 | evex0F38 | evexW0, evexN16 | evexBcstN4 | evexZeroingEnabled, 0x51,
		avxEscape | evex256 | evex66 | evex0F38 | evexW0, evexN32 | evexBcstN4 | evexZeroingEnabled, 0x51,
		avxEscape | evex512 | evex66 | evex0F38 | evexW0, evexN64 | evexBcstN4 | evexZeroingEnabled, 0x51,
	}},
	{as: AVPDPWSSD, ytab: _yvblendmpd, prefix: Pavx, op: opBytes{
		avxEscape | evex128 | evex66 | evex0F38 | evexW0, evexN16 | evexBcstN4 | evexZeroingEnabled, 0x52,
		avxEscape | evex256 | evex66 | evex0F38 | evexW0, evexN32 | evexBcstN4 | evexZeroingEnabled, 0x52,
		avxEscape | evex512 | evex66 | evex0F38 | evexW0, evexN64 | evexBcstN4 | evexZeroingEnabled, 0x52,
	}},
	{as: AVPDPWSSDS, ytab: _yvblendmpd, prefix: Pavx, op: opBytes{
		avxEscape | evex128 | evex66 | evex0F38 | evexW0, evexN16 | evexBcstN4 | evexZeroingEnabled, 0x53,
		avxEscape | evex256 | evex66 | evex0F38 | evexW0, evexN32 | evexBcstN4 | evexZeroingEnabled, 0x53,
		avxEscape | evex512 | evex66 | evex0F38 | evexW0, evexN64 | evexBcstN4 | evexZeroingEnabled, 0x53,
	}},
	{as: AVPERM2F128, ytab: _yvperm2f128, prefix: Pavx, op: opBytes{
		avxEscape | vex256 | vex66 | vex0F3A | vexW0, 0x06,
	}},
	{as: AVPERM2I128, ytab: _yvperm2f128, prefix: Pavx, op: opBytes{
		avxEscape | vex256 | vex66 | vex0F3A | vexW0, 0x46,
	}},
	{as: AVPERMB, ytab: _yvblendmpd, prefix: Pavx, op: opBytes{
		avxEscape | evex128 | evex66 | evex0F38 | evexW0, evexN16 | evexZeroingEnabled, 0x8D,
		avxEscape | evex256 | evex66 | evex0F38 | evexW0, evexN32 | evexZeroingEnabled, 0x8D,
		avxEscape | evex512 | evex66 | evex0F38 | evexW0, evexN64 | evexZeroingEnabled, 0x8D,
	}},
	{as: AVPERMD, ytab: _yvpermd, prefix: Pavx, op: opBytes{
		avxEscape | vex256 | vex66 | vex0F38 | vexW0, 0x36,
		avxEscape | evex256 | evex66 | evex0F38 | evexW0, evexN32 | evexBcstN4 | evexZeroingEnabled, 0x36,
		avxEscape | evex512 | evex66 | evex0F38 | evexW0, evexN64 | evexBcstN4 | evexZeroingEnabled, 0x36,
	}},
	{as: AVPERMI2B, ytab: _yvblendmpd, prefix: Pavx, op: opBytes{
		avxEscape | evex128 | evex66 | evex0F38 | evexW0, evexN16 | evexZeroingEnabled, 0x75,
		avxEscape | evex256 | evex66 | evex0F38 | evexW0, evexN32 | evexZeroingEnabled, 0x75,
		avxEscape | evex512 | evex66 | evex0F38 | evexW0, evexN64 | evexZeroingEnabled, 0x75,
	}},
	{as: AVPERMI2D, ytab: _yvblendmpd, prefix: Pavx, op: opBytes{
		avxEscape | evex128 | evex66 | evex0F38 | evexW0, evexN16 | evexBcstN4 | evexZeroingEnabled, 0x76,
		avxEscape | evex256 | evex66 | evex0F38 | evexW0, evexN32 | evexBcstN4 | evexZeroingEnabled, 0x76,
		avxEscape | evex512 | evex66 | evex0F38 | evexW0, evexN64 | evexBcstN4 | evexZeroingEnabled, 0x76,
	}},
	{as: AVPERMI2PD, ytab: _yvblendmpd, prefix: Pavx, op: opBytes{
		avxEscape | evex128 | evex66 | evex0F38 | evexW1, evexN16 | evexBcstN8 | evexZeroingEnabled, 0x77,
		avxEscape | evex256 | evex66 | evex0F38 | evexW1, evexN32 | evexBcstN8 | evexZeroingEnabled, 0x77,
		avxEscape | evex512 | evex66 | evex0F38 | evexW1, evexN64 | evexBcstN8 | evexZeroingEnabled, 0x77,
	}},
	{as: AVPERMI2PS, ytab: _yvblendmpd, prefix: Pavx, op: opBytes{
		avxEscape | evex128 | evex66 | evex0F38 | evexW0, evexN16 | evexBcstN4 | evexZeroingEnabled, 0x77,
		avxEscape | evex256 | evex66 | evex0F38 | evexW0, evexN32 | evexBcstN4 | evexZeroingEnabled, 0x77,
		avxEscape | evex512 | evex66 | evex0F38 | evexW0, evexN64 | evexBcstN4 | evexZeroingEnabled, 0x77,
	}},
	{as: AVPERMI2Q, ytab: _yvblendmpd, prefix: Pavx, op: opBytes{
		avxEscape | evex128 | evex66 | evex0F38 | evexW1, evexN16 | evexBcstN8 | evexZeroingEnabled, 0x76,
		avxEscape | evex256 | evex66 | evex0F38 | evexW1, evexN32 | evexBcstN8 | evexZeroingEnabled, 0x76,
		avxEscape | evex512 | evex66 | evex0F38 | evexW1, evexN64 | evexBcstN8 | evexZeroingEnabled, 0x76,
	}},
	{as: AVPERMI2W, ytab: _yvblendmpd, prefix: Pavx, op: opBytes{
		avxEscape | evex128 | evex66 | evex0F38 | evexW1, evexN16 | evexZeroingEnabled, 0x75,
		avxEscape | evex256 | evex66 | evex0F38 | evexW1, evexN32 | evexZeroingEnabled, 0x75,
		avxEscape | evex512 | evex66 | evex0F38 | evexW1, evexN64 | evexZeroingEnabled, 0x75,
	}},
	{as: AVPERMILPD, ytab: _yvpermilpd, prefix: Pavx, op: opBytes{
		avxEscape | vex128 | vex66 | vex0F3A | vexW0, 0x05,
		avxEscape | vex256 | vex66 | vex0F3A | vexW0, 0x05,
		avxEscape | vex128 | vex66 | vex0F38 | vexW0, 0x0D,
		avxEscape | vex256 | vex66 | vex0F38 | vexW0, 0x0D,
		avxEscape | evex128 | evex66 | evex0F3A | evexW1, evexN16 | evexBcstN8 | evexZeroingEnabled, 0x05,
		avxEscape | evex256 | evex66 | evex0F3A | evexW1, evexN32 | evexBcstN8 | evexZeroingEnabled, 0x05,
		avxEscape | evex512 | evex66 | evex0F3A | evexW1, evexN64 | evexBcstN8 | evexZeroingEnabled, 0x05,
		avxEscape | evex128 | evex66 | evex0F38 | evexW1, evexN16 | evexBcstN8 | evexZeroingEnabled, 0x0D,
		avxEscape | evex256 | evex66 | evex0F38 | evexW1, evexN32 | evexBcstN8 | evexZeroingEnabled, 0x0D,
		avxEscape | evex512 | evex66 | evex0F38 | evexW1, evexN64 | evexBcstN8 | evexZeroingEnabled, 0x0D,
	}},
	{as: AVPERMILPS, ytab: _yvpermilpd, prefix: Pavx, op: opBytes{
		avxEscape | vex128 | vex66 | vex0F3A | vexW0, 0x04,
		avxEscape | vex256 | vex66 | vex0F3A | vexW0, 0x04,
		avxEscape | vex128 | vex66 | vex0F38 | vexW0, 0x0C,
		avxEscape | vex256 | vex66 | vex0F38 | vexW0, 0x0C,
		avxEscape | evex128 | evex66 | evex0F3A | evexW0, evexN16 | evexBcstN4 | evexZeroingEnabled, 0x04,
		avxEscape | evex256 | evex66 | evex0F3A | evexW0, evexN32 | evexBcstN4 | evexZeroingEnabled, 0x04,
		avxEscape | evex512 | evex66 | evex0F3A | evexW0, evexN64 | evexBcstN4 | evexZeroingEnabled, 0x04,
		avxEscape | evex128 | evex66 | evex0F38 | evexW0, evexN16 | evexBcstN4 | evexZeroingEnabled, 0x0C,
		avxEscape | evex256 | evex66 | evex0F38 | evexW0, evexN32 | evexBcstN4 | evexZeroingEnabled, 0x0C,
		avxEscape | evex512 | evex66 | evex0F38 | evexW0, evexN64 | evexBcstN4 | evexZeroingEnabled, 0x0C,
	}},
	{as: AVPERMPD, ytab: _yvpermq, prefix: Pavx, op: opBytes{
		avxEscape | vex256 | vex66 | vex0F3A | vexW1, 0x01,
		avxEscape | evex256 | evex66 | evex0F3A | evexW1, evexN32 | evexBcstN8 | evexZeroingEnabled, 0x01,
		avxEscape | evex512 | evex66 | evex0F3A | evexW1, evexN64 | evexBcstN8 | evexZeroingEnabled, 0x01,
		avxEscape | evex256 | evex66 | evex0F38 | evexW1, evexN32 | evexBcstN8 | evexZeroingEnabled, 0x16,
		avxEscape | evex512 | evex66 | evex0F38 | evexW1, evexN64 | evexBcstN8 | evexZeroingEnabled, 0x16,
	}},
	{as: AVPERMPS, ytab: _yvpermd, prefix: Pavx, op: opBytes{
		avxEscape | vex256 | vex66 | vex0F38 | vexW0, 0x16,
		avxEscape | evex256 | evex66 | evex0F38 | evexW0, evexN32 | evexBcstN4 | evexZeroingEnabled, 0x16,
		avxEscape | evex512 | evex66 | evex0F38 | evexW0, evexN64 | evexBcstN4 | evexZeroingEnabled, 0x16,
	}},
	{as: AVPERMQ, ytab: _yvpermq, prefix: Pavx, op: opBytes{
		avxEscape | vex256 | vex66 | vex0F3A | vexW1, 0x00,
		avxEscape | evex256 | evex66 | evex0F3A | evexW1, evexN32 | evexBcstN8 | evexZeroingEnabled, 0x00,
		avxEscape | evex512 | evex66 | evex0F3A | evexW1, evexN64 | evexBcstN8 | evexZeroingEnabled, 0x00,
		avxEscape | evex256 | evex66 | evex0F38 | evexW1, evexN32 | evexBcstN8 | evexZeroingEnabled, 0x36,
		avxEscape | evex512 | evex66 | evex0F38 | evexW1, evexN64 | evexBcstN8 | evexZeroingEnabled, 0x36,
	}},
	{as: AVPERMT2B, ytab: _yvblendmpd, prefix: Pavx, op: opBytes{
		avxEscape | evex128 | evex66 | evex0F38 | evexW0, evexN16 | evexZeroingEnabled, 0x7D,
		avxEscape | evex256 | evex66 | evex0F38 | evexW0, evexN32 | evexZeroingEnabled, 0x7D,
		avxEscape | evex512 | evex66 | evex0F38 | evexW0, evexN64 | evexZeroingEnabled, 0x7D,
	}},
	{as: AVPERMT2D, ytab: _yvblendmpd, prefix: Pavx, op: opBytes{
		avxEscape | evex128 | evex66 | evex0F38 | evexW0, evexN16 | evexBcstN4 | evexZeroingEnabled, 0x7E,
		avxEscape | evex256 | evex66 | evex0F38 | evexW0, evexN32 | evexBcstN4 | evexZeroingEnabled, 0x7E,
		avxEscape | evex512 | evex66 | evex0F38 | evexW0, evexN64 | evexBcstN4 | evexZeroingEnabled, 0x7E,
	}},
	{as: AVPERMT2PD, ytab: _yvblendmpd, prefix: Pavx, op: opBytes{
		avxEscape | evex128 | evex66 | evex0F38 | evexW1, evexN16 | evexBcstN8 | evexZeroingEnabled, 0x7F,
		avxEscape | evex256 | evex66 | evex0F38 | evexW1, evexN32 | evexBcstN8 | evexZeroingEnabled, 0x7F,
		avxEscape | evex512 | evex66 | evex0F38 | evexW1, evexN64 | evexBcstN8 | evexZeroingEnabled, 0x7F,
	}},
	{as: AVPERMT2PS, ytab: _yvblendmpd, prefix: Pavx, op: opBytes{
		avxEscape | evex128 | evex66 | evex0F38 | evexW0, evexN16 | evexBcstN4 | evexZeroingEnabled, 0x7F,
		avxEscape | evex256 | evex66 | evex0F38 | evexW0, evexN32 | evexBcstN4 | evexZeroingEnabled, 0x7F,
		avxEscape | evex512 | evex66 | evex0F38 | evexW0, evexN64 | evexBcstN4 | evexZeroingEnabled, 0x7F,
	}},
	{as: AVPERMT2Q, ytab: _yvblendmpd, prefix: Pavx, op: opBytes{
		avxEscape | evex128 | evex66 | evex0F38 | evexW1, evexN16 | evexBcstN8 | evexZeroingEnabled, 0x7E,
		avxEscape | evex256 | evex66 | evex0F38 | evexW1, evexN32 | evexBcstN8 | evexZeroingEnabled, 0x7E,
		avxEscape | evex512 | evex66 | evex0F38 | evexW1, evexN64 | evexBcstN8 | evexZeroingEnabled, 0x7E,
	}},
	{as: AVPERMT2W, ytab: _yvblendmpd, prefix: Pavx, op: opBytes{
		avxEscape | evex128 | evex66 | evex0F38 | evexW1, evexN16 | evexZeroingEnabled, 0x7D,
		avxEscape | evex256 | evex66 | evex0F38 | evexW1, evexN32 | evexZeroingEnabled, 0x7D,
		avxEscape | evex512 | evex66 | evex0F38 | evexW1, evexN64 | evexZeroingEnabled, 0x7D,
	}},
	{as: AVPERMW, ytab: _yvblendmpd, prefix: Pavx, op: opBytes{
		avxEscape | evex128 | evex66 | evex0F38 | evexW1, evexN16 | evexZeroingEnabled, 0x8D,
		avxEscape | evex256 | evex66 | evex0F38 | evexW1, evexN32 | evexZeroingEnabled, 0x8D,
		avxEscape | evex512 | evex66 | evex0F38 | evexW1, evexN64 | evexZeroingEnabled, 0x8D,
	}},
	{as: AVPEXPANDB, ytab: _yvexpandpd, prefix: Pavx, op: opBytes{
		avxEscape | evex128 | evex66 | evex0F38 | evexW0, evexN1 | evexZeroingEnabled, 0x62,
		avxEscape | evex256 | evex66 | evex0F38 | evexW0, evexN1 | evexZeroingEnabled, 0x62,
		avxEscape | evex512 | evex66 | evex0F38 | evexW0, evexN1 | evexZeroingEnabled, 0x62,
	}},
	{as: AVPEXPANDD, ytab: _yvexpandpd, prefix: Pavx, op: opBytes{
		avxEscape | evex128 | evex66 | evex0F38 | evexW0, evexN4 | evexZeroingEnabled, 0x89,
		avxEscape | evex256 | evex66 | evex0F38 | evexW0, evexN4 | evexZeroingEnabled, 0x89,
		avxEscape | evex512 | evex66 | evex0F38 | evexW0, evexN4 | evexZeroingEnabled, 0x89,
	}},
	{as: AVPEXPANDQ, ytab: _yvexpandpd, prefix: Pavx, op: opBytes{
		avxEscape | evex128 | evex66 | evex0F38 | evexW1, evexN8 | evexZeroingEnabled, 0x89,
		avxEscape | evex256 | evex66 | evex0F38 | evexW1, evexN8 | evexZeroingEnabled, 0x89,
		avxEscape | evex512 | evex66 | evex0F38 | evexW1, evexN8 | evexZeroingEnabled, 0x89,
	}},
	{as: AVPEXPANDW, ytab: _yvexpandpd, prefix: Pavx, op: opBytes{
		avxEscape | evex128 | evex66 | evex0F38 | evexW1, evexN2 | evexZeroingEnabled, 0x62,
		avxEscape | evex256 | evex66 | evex0F38 | evexW1, evexN2 | evexZeroingEnabled, 0x62,
		avxEscape | evex512 | evex66 | evex0F38 | evexW1, evexN2 | evexZeroingEnabled, 0x62,
	}},
	{as: AVPEXTRB, ytab: _yvextractps, prefix: Pavx, op: opBytes{
		avxEscape | vex128 | vex66 | vex0F3A | vexW0, 0x14,
		avxEscape | evex128 | evex66 | evex0F3A | evexW0, evexN1, 0x14,
	}},
	{as: AVPEXTRD, ytab: _yvextractps, prefix: Pavx, op: opBytes{
		avxEscape | vex128 | vex66 | vex0F3A | vexW0, 0x16,
		avxEscape | evex128 | evex66 | evex0F3A | evexW0, evexN4, 0x16,
	}},
	{as: AVPEXTRQ, ytab: _yvextractps, prefix: Pavx, op: opBytes{
		avxEscape | vex128 | vex66 | vex0F3A | vexW1, 0x16,
		avxEscape | evex128 | evex66 | evex0F3A | evexW1, evexN8, 0x16,
	}},
	{as: AVPEXTRW, ytab: _yvpextrw, prefix: Pavx, op: opBytes{
		avxEscape | vex128 | vex66 | vex0F3A | vexW0, 0x15,
		avxEscape | vex128 | vex66 | vex0F | vexW0, 0xC5,
		avxEscape | evex128 | evex66 | evex0F3A | evexW0, evexN2, 0x15,
		avxEscape | evex128 | evex66 | evex0F | evexW0, 0, 0xC5,
	}},
	{as: AVPGATHERDD, ytab: _yvgatherdps, prefix: Pavx, op: opBytes{
		avxEscape | vex128 | vex66 | vex0F38 | vexW0, 0x90,
		avxEscape | vex256 | vex66 | vex0F38 | vexW0, 0x90,
		avxEscape | evex128 | evex66 | evex0F38 | evexW0, evexN4, 0x90,
		avxEscape | evex256 | evex66 | evex0F38 | evexW0, evexN4, 0x90,
		avxEscape | evex512 | evex66 | evex0F38 | evexW0, evexN4, 0x90,
	}},
	{as: AVPGATHERDQ, ytab: _yvgatherdpd, prefix: Pavx, op: opBytes{
		avxEscape | vex128 | vex66 | vex0F38 | vexW1, 0x90,
		avxEscape | vex256 | vex66 | vex0F38 | vexW1, 0x90,
		avxEscape | evex128 | evex66 | evex0F38 | evexW1, evexN8, 0x90,
		avxEscape | evex256 | evex66 | evex0F38 | evexW1, evexN8, 0x90,
		avxEscape | evex512 | evex66 | evex0F38 | evexW1, evexN8, 0x90,
	}},
	{as: AVPGATHERQD, ytab: _yvgatherqps, prefix: Pavx, op: opBytes{
		avxEscape | vex128 | vex66 | vex0F38 | vexW0, 0x91,
		avxEscape | vex256 | vex66 | vex0F38 | vexW0, 0x91,
		avxEscape | evex128 | evex66 | evex0F38 | evexW0, evexN4, 0x91,
		avxEscape | evex256 | evex66 | evex0F38 | evexW0, evexN4, 0x91,
		avxEscape | evex512 | evex66 | evex0F38 | evexW0, evexN4, 0x91,
	}},
	{as: AVPGATHERQQ, ytab: _yvgatherdps, prefix: Pavx, op: opBytes{
		avxEscape | vex128 | vex66 | vex0F38 | vexW1, 0x91,
		avxEscape | vex256 | vex66 | vex0F38 | vexW1, 0x91,
		avxEscape | evex128 | evex66 | evex0F38 | evexW1, evexN8, 0x91,
		avxEscape | evex256 | evex66 | evex0F38 | evexW1, evexN8, 0x91,
		avxEscape | evex512 | evex66 | evex0F38 | evexW1, evexN8, 0x91,
	}},
	{as: AVPHADDD, ytab: _yvaddsubpd, prefix: Pavx, op: opBytes{
		avxEscape | vex128 | vex66 | vex0F38 | vexW0, 0x02,
		avxEscape | vex256 | vex66 | vex0F38 | vexW0, 0x02,
	}},
	{as: AVPHADDSW, ytab: _yvaddsubpd, prefix: Pavx, op: opBytes{
		avxEscape | vex128 | vex66 | vex0F38 | vexW0, 0x03,
		avxEscape | vex256 | vex66 | vex0F38 | vexW0, 0x03,
	}},
	{as: AVPHADDW, ytab: _yvaddsubpd, prefix: Pavx, op: opBytes{
		avxEscape | vex128 | vex66 | vex0F38 | vexW0, 0x01,
		avxEscape | vex256 | vex66 | vex0F38 | vexW0, 0x01,
	}},
	{as: AVPHMINPOSUW, ytab: _yvaesimc, prefix: Pavx, op: opBytes{
		avxEscape | vex128 | vex66 | vex0F38 | vexW0, 0x41,
	}},
	{as: AVPHSUBD, ytab: _yvaddsubpd, prefix: Pavx, op: opBytes{
		avxEscape | vex128 | vex66 | vex0F38 | vexW0, 0x06,
		avxEscape | vex256 | vex66 | vex0F38 | vexW0, 0x06,
	}},
	{as: AVPHSUBSW, ytab: _yvaddsubpd, prefix: Pavx, op: opBytes{
		avxEscape | vex128 | vex66 | vex0F38 | vexW0, 0x07,
		avxEscape | vex256 | vex66 | vex0F38 | vexW0, 0x07,
	}},
	{as: AVPHSUBW, ytab: _yvaddsubpd, prefix: Pavx, op: opBytes{
		avxEscape | vex128 | vex66 | vex0F38 | vexW0, 0x05,
		avxEscape | vex256 | vex66 | vex0F38 | vexW0, 0x05,
	}},
	{as: AVPINSRB, ytab: _yvpinsrb, prefix: Pavx, op: opBytes{
		avxEscape | vex128 | vex66 | vex0F3A | vexW0, 0x20,
		avxEscape | evex128 | evex66 | evex0F3A | evexW0, evexN1, 0x20,
	}},
	{as: AVPINSRD, ytab: _yvpinsrb, prefix: Pavx, op: opBytes{
		avxEscape | vex128 | vex66 | vex0F3A | vexW0, 0x22,
		avxEscape | evex128 | evex66 | evex0F3A | evexW0, evexN4, 0x22,
	}},
	{as: AVPINSRQ, ytab: _yvpinsrb, prefix: Pavx, op: opBytes{
		avxEscape | vex128 | vex66 | vex0F3A | vexW1, 0x22,
		avxEscape | evex128 | evex66 | evex0F3A | evexW1, evexN8, 0x22,
	}},
	{as: AVPINSRW, ytab: _yvpinsrb, prefix: Pavx, op: opBytes{
		avxEscape | vex128 | vex66 | vex0F | vexW0, 0xC4,
		avxEscape | evex128 | evex66 | evex0F | evexW0, evexN2, 0xC4,
	}},
	{as: AVPLZCNTD, ytab: _yvexpandpd, prefix: Pavx, op: opBytes{
		avxEscape | evex128 | evex66 | evex0F38 | evexW0, evexN16 | evexBcstN4 | evexZeroingEnabled, 0x44,
		avxEscape | evex256 | evex66 | evex0F38 | evexW0, evexN32 | evexBcstN4 | evexZeroingEnabled, 0x44,
		avxEscape | evex512 | evex66 | evex0F38 | evexW0, evexN64 | evexBcstN4 | evexZeroingEnabled, 0x44,
	}},
	{as: AVPLZCNTQ, ytab: _yvexpandpd, prefix: Pavx, op: opBytes{
		avxEscape | evex128 | evex66 | evex0F38 | evexW1, evexN16 | evexBcstN8 | evexZeroingEnabled, 0x44,
		avxEscape | evex256 | evex66 | evex0F38 | evexW1, evexN32 | evexBcstN8 | evexZeroingEnabled, 0x44,
		avxEscape | evex512 | evex66 | evex0F38 | evexW1, evexN64 | evexBcstN8 | evexZeroingEnabled, 0x44,
	}},
	{as: AVPMADD52HUQ, ytab: _yvblendmpd, prefix: Pavx, op: opBytes{
		avxEscape | evex128 | evex66 | evex0F38 | evexW1, evexN16 | evexBcstN8 | evexZeroingEnabled, 0xB5,
		avxEscape | evex256 | evex66 | evex0F38 | evexW1, evexN32 | evexBcstN8 | evexZeroingEnabled, 0xB5,
		avxEscape | evex512 | evex66 | evex0F38 | evexW1, evexN64 | evexBcstN8 | evexZeroingEnabled, 0xB5,
	}},
	{as: AVPMADD52LUQ, ytab: _yvblendmpd, prefix: Pavx, op: opBytes{
		avxEscape | evex128 | evex66 | evex0F38 | evexW1, evexN16 | evexBcstN8 | evexZeroingEnabled, 0xB4,
		avxEscape | evex256 | evex66 | evex0F38 | evexW1, evexN32 | evexBcstN8 | evexZeroingEnabled, 0xB4,
		avxEscape | evex512 | evex66 | evex0F38 | evexW1, evexN64 | evexBcstN8 | evexZeroingEnabled, 0xB4,
	}},
	{as: AVPMADDUBSW, ytab: _yvandnpd, prefix: Pavx, op: opBytes{
		avxEscape | vex128 | vex66 | vex0F38 | vexW0, 0x04,
		avxEscape | vex256 | vex66 | vex0F38 | vexW0, 0x04,
		avxEscape | evex128 | evex66 | evex0F38 | evexW0, evexN16 | evexZeroingEnabled, 0x04,
		avxEscape | evex256 | evex66 | evex0F38 | evexW0, evexN32 | evexZeroingEnabled, 0x04,
		avxEscape | evex512 | evex66 | evex0F38 | evexW0, evexN64 | evexZeroingEnabled, 0x04,
	}},
	{as: AVPMADDWD, ytab: _yvandnpd, prefix: Pavx, op: opBytes{
		avxEscape | vex128 | vex66 | vex0F | vexW0, 0xF5,
		avxEscape | vex256 | vex66 | vex0F | vexW0, 0xF5,
		avxEscape | evex128 | evex66 | evex0F | evexW0, evexN16 | evexZeroingEnabled, 0xF5,
		avxEscape | evex256 | evex66 | evex0F | evexW0, evexN32 | evexZeroingEnabled, 0xF5,
		avxEscape | evex512 | evex66 | evex0F | evexW0, evexN64 | evexZeroingEnabled, 0xF5,
	}},
	{as: AVPMASKMOVD, ytab: _yvmaskmovpd, prefix: Pavx, op: opBytes{
		avxEscape | vex128 | vex66 | vex0F38 | vexW0, 0x8E,
		avxEscape | vex256 | vex66 | vex0F38 | vexW0, 0x8E,
		avxEscape | vex128 | vex66 | vex0F38 | vexW0, 0x8C,
		avxEscape | vex256 | vex66 | vex0F38 | vexW0, 0x8C,
	}},
	{as: AVPMASKMOVQ, ytab: _yvmaskmovpd, prefix: Pavx, op: opBytes{
		avxEscape | vex128 | vex66 | vex0F38 | vexW1, 0x8E,
		avxEscape | vex256 | vex66 | vex0F38 | vexW1, 0x8E,
		avxEscape | vex128 | vex66 | vex0F38 | vexW1, 0x8C,
		avxEscape | vex256 | vex66 | vex0F38 | vexW1, 0x8C,
	}},
	{as: AVPMAXSB, ytab: _yvandnpd, prefix: Pavx, op: opBytes{
		avxEscape | vex128 | vex66 | vex0F38 | vexW0, 0x3C,
		avxEscape | vex256 | vex66 | vex0F38 | vexW0, 0x3C,
		avxEscape | evex128 | evex66 | evex0F38 | evexW0, evexN16 | evexZeroingEnabled, 0x3C,
		avxEscape | evex256 | evex66 | evex0F38 | evexW0, evexN32 | evexZeroingEnabled, 0x3C,
		avxEscape | evex512 | evex66 | evex0F38 | evexW0, evexN64 | evexZeroingEnabled, 0x3C,
	}},
	{as: AVPMAXSD, ytab: _yvandnpd, prefix: Pavx, op: opBytes{
		avxEscape | vex128 | vex66 | vex0F38 | vexW0, 0x3D,
		avxEscape | vex256 | vex66 | vex0F38 | vexW0, 0x3D,
		avxEscape | evex128 | evex66 | evex0F38 | evexW0, evexN16 | evexBcstN4 | evexZeroingEnabled, 0x3D,
		avxEscape | evex256 | evex66 | evex0F38 | evexW0, evexN32 | evexBcstN4 | evexZeroingEnabled, 0x3D,
		avxEscape | evex512 | evex66 | evex0F38 | evexW0, evexN64 | evexBcstN4 | evexZeroingEnabled, 0x3D,
	}},
	{as: AVPMAXSQ, ytab: _yvblendmpd, prefix: Pavx, op: opBytes{
		avxEscape | evex128 | evex66 | evex0F38 | evexW1, evexN16 | evexBcstN8 | evexZeroingEnabled, 0x3D,
		avxEscape | evex256 | evex66 | evex0F38 | evexW1, evexN32 | evexBcstN8 | evexZeroingEnabled, 0x3D,
		avxEscape | evex512 | evex66 | evex0F38 | evexW1, evexN64 | evexBcstN8 | evexZeroingEnabled, 0x3D,
	}},
	{as: AVPMAXSW, ytab: _yvandnpd, prefix: Pavx, op: opBytes{
		avxEscape | vex128 | vex66 | vex0F | vexW0, 0xEE,
		avxEscape | vex256 | vex66 | vex0F | vexW0, 0xEE,
		avxEscape | evex128 | evex66 | evex0F | evexW0, evexN16 | evexZeroingEnabled, 0xEE,
		avxEscape | evex256 | evex66 | evex0F | evexW0, evexN32 | evexZeroingEnabled, 0xEE,
		avxEscape | evex512 | evex66 | evex0F | evexW0, evexN64 | evexZeroingEnabled, 0xEE,
	}},
	{as: AVPMAXUB, ytab: _yvandnpd, prefix: Pavx, op: opBytes{
		avxEscape | vex128 | vex66 | vex0F | vexW0, 0xDE,
		avxEscape | vex256 | vex66 | vex0F | vexW0, 0xDE,
		avxEscape | evex128 | evex66 | evex0F | evexW0, evexN16 | evexZeroingEnabled, 0xDE,
		avxEscape | evex256 | evex66 | evex0F | evexW0, evexN32 | evexZeroingEnabled, 0xDE,
		avxEscape | evex512 | evex66 | evex0F | evexW0, evexN64 | evexZeroingEnabled, 0xDE,
	}},
	{as: AVPMAXUD, ytab: _yvandnpd, prefix: Pavx, op: opBytes{
		avxEscape | vex128 | vex66 | vex0F38 | vexW0, 0x3F,
		avxEscape | vex256 | vex66 | vex0F38 | vexW0, 0x3F,
		avxEscape | evex128 | evex66 | evex0F38 | evexW0, evexN16 | evexBcstN4 | evexZeroingEnabled, 0x3F,
		avxEscape | evex256 | evex66 | evex0F38 | evexW0, evexN32 | evexBcstN4 | evexZeroingEnabled, 0x3F,
		avxEscape | evex512 | evex66 | evex0F38 | evexW0, evexN64 | evexBcstN4 | evexZeroingEnabled, 0x3F,
	}},
	{as: AVPMAXUQ, ytab: _yvblendmpd, prefix: Pavx, op: opBytes{
		avxEscape | evex128 | evex66 | evex0F38 | evexW1, evexN16 | evexBcstN8 | evexZeroingEnabled, 0x3F,
		avxEscape | evex256 | evex66 | evex0F38 | evexW1, evexN32 | evexBcstN8 | evexZeroingEnabled, 0x3F,
		avxEscape | evex512 | evex66 | evex0F38 | evexW1, evexN64 | evexBcstN8 | evexZeroingEnabled, 0x3F,
	}},
	{as: AVPMAXUW, ytab: _yvandnpd, prefix: Pavx, op: opBytes{
		avxEscape | vex128 | vex66 | vex0F38 | vexW0, 0x3E,
		avxEscape | vex256 | vex66 | vex0F38 | vexW0, 0x3E,
		avxEscape | evex128 | evex66 | evex0F38 | evexW0, evexN16 | evexZeroingEnabled, 0x3E,
		avxEscape | evex256 | evex66 | evex0F38 | evexW0, evexN32 | evexZeroingEnabled, 0x3E,
		avxEscape | evex512 | evex66 | evex0F38 | evexW0, evexN64 | evexZeroingEnabled, 0x3E,
	}},
	{as: AVPMINSB, ytab: _yvandnpd, prefix: Pavx, op: opBytes{
		avxEscape | vex128 | vex66 | vex0F38 | vexW0, 0x38,
		avxEscape | vex256 | vex66 | vex0F38 | vexW0, 0x38,
		avxEscape | evex128 | evex66 | evex0F38 | evexW0, evexN16 | evexZeroingEnabled, 0x38,
		avxEscape | evex256 | evex66 | evex0F38 | evexW0, evexN32 | evexZeroingEnabled, 0x38,
		avxEscape | evex512 | evex66 | evex0F38 | evexW0, evexN64 | evexZeroingEnabled, 0x38,
	}},
	{as: AVPMINSD, ytab: _yvandnpd, prefix: Pavx, op: opBytes{
		avxEscape | vex128 | vex66 | vex0F38 | vexW0, 0x39,
		avxEscape | vex256 | vex66 | vex0F38 | vexW0, 0x39,
		avxEscape | evex128 | evex66 | evex0F38 | evexW0, evexN16 | evexBcstN4 | evexZeroingEnabled, 0x39,
		avxEscape | evex256 | evex66 | evex0F38 | evexW0, evexN32 | evexBcstN4 | evexZeroingEnabled, 0x39,
		avxEscape | evex512 | evex66 | evex0F38 | evexW0, evexN64 | evexBcstN4 | evexZeroingEnabled, 0x39,
	}},
	{as: AVPMINSQ, ytab: _yvblendmpd, prefix: Pavx, op: opBytes{
		avxEscape | evex128 | evex66 | evex0F38 | evexW1, evexN16 | evexBcstN8 | evexZeroingEnabled, 0x39,
		avxEscape | evex256 | evex66 | evex0F38 | evexW1, evexN32 | evexBcstN8 | evexZeroingEnabled, 0x39,
		avxEscape | evex512 | evex66 | evex0F38 | evexW1, evexN64 | evexBcstN8 | evexZeroingEnabled, 0x39,
	}},
	{as: AVPMINSW, ytab: _yvandnpd, prefix: Pavx, op: opBytes{
		avxEscape | vex128 | vex66 | vex0F | vexW0, 0xEA,
		avxEscape | vex256 | vex66 | vex0F | vexW0, 0xEA,
		avxEscape | evex128 | evex66 | evex0F | evexW0, evexN16 | evexZeroingEnabled, 0xEA,
		avxEscape | evex256 | evex66 | evex0F | evexW0, evexN32 | evexZeroingEnabled, 0xEA,
		avxEscape | evex512 | evex66 | evex0F | evexW0, evexN64 | evexZeroingEnabled, 0xEA,
	}},
	{as: AVPMINUB, ytab: _yvandnpd, prefix: Pavx, op: opBytes{
		avxEscape | vex128 | vex66 | vex0F | vexW0, 0xDA,
		avxEscape | vex256 | vex66 | vex0F | vexW0, 0xDA,
		avxEscape | evex128 | evex66 | evex0F | evexW0, evexN16 | evexZeroingEnabled, 0xDA,
		avxEscape | evex256 | evex66 | evex0F | evexW0, evexN32 | evexZeroingEnabled, 0xDA,
		avxEscape | evex512 | evex66 | evex0F | evexW0, evexN64 | evexZeroingEnabled, 0xDA,
	}},
	{as: AVPMINUD, ytab: _yvandnpd, prefix: Pavx, op: opBytes{
		avxEscape | vex128 | vex66 | vex0F38 | vexW0, 0x3B,
		avxEscape | vex256 | vex66 | vex0F38 | vexW0, 0x3B,
		avxEscape | evex128 | evex66 | evex0F38 | evexW0, evexN16 | evexBcstN4 | evexZeroingEnabled, 0x3B,
		avxEscape | evex256 | evex66 | evex0F38 | evexW0, evexN32 | evexBcstN4 | evexZeroingEnabled, 0x3B,
		avxEscape | evex512 | evex66 | evex0F38 | evexW0, evexN64 | evexBcstN4 | evexZeroingEnabled, 0x3B,
	}},
	{as: AVPMINUQ, ytab: _yvblendmpd, prefix: Pavx, op: opBytes{
		avxEscape | evex128 | evex66 | evex0F38 | evexW1, evexN16 | evexBcstN8 | evexZeroingEnabled, 0x3B,
		avxEscape | evex256 | evex66 | evex0F38 | evexW1, evexN32 | evexBcstN8 | evexZeroingEnabled, 0x3B,
		avxEscape | evex512 | evex66 | evex0F38 | evexW1, evexN64 | evexBcstN8 | evexZeroingEnabled, 0x3B,
	}},
	{as: AVPMINUW, ytab: _yvandnpd, prefix: Pavx, op: opBytes{
		avxEscape | vex128 | vex66 | vex0F38 | vexW0, 0x3A,
		avxEscape | vex256 | vex66 | vex0F38 | vexW0, 0x3A,
		avxEscape | evex128 | evex66 | evex0F38 | evexW0, evexN16 | evexZeroingEnabled, 0x3A,
		avxEscape | evex256 | evex66 | evex0F38 | evexW0, evexN32 | evexZeroingEnabled, 0x3A,
		avxEscape | evex512 | evex66 | evex0F38 | evexW0, evexN64 | evexZeroingEnabled, 0x3A,
	}},
	{as: AVPMOVB2M, ytab: _yvpmovb2m, prefix: Pavx, op: opBytes{
		avxEscape | evex128 | evexF3 | evex0F38 | evexW0, 0, 0x29,
		avxEscape | evex256 | evexF3 | evex0F38 | evexW0, 0, 0x29,
		avxEscape | evex512 | evexF3 | evex0F38 | evexW0, 0, 0x29,
	}},
	{as: AVPMOVD2M, ytab: _yvpmovb2m, prefix: Pavx, op: opBytes{
		avxEscape | evex128 | evexF3 | evex0F38 | evexW0, 0, 0x39,
		avxEscape | evex256 | evexF3 | evex0F38 | evexW0, 0, 0x39,
		avxEscape | evex512 | evexF3 | evex0F38 | evexW0, 0, 0x39,
	}},
	{as: AVPMOVDB, ytab: _yvpmovdb, prefix: Pavx, op: opBytes{
		avxEscape | evex128 | evexF3 | evex0F38 | evexW0, evexN4 | evexZeroingEnabled, 0x31,
		avxEscape | evex256 | evexF3 | evex0F38 | evexW0, evexN8 | evexZeroingEnabled, 0x31,
		avxEscape | evex512 | evexF3 | evex0F38 | evexW0, evexN16 | evexZeroingEnabled, 0x31,
	}},
	{as: AVPMOVDW, ytab: _yvpmovdw, prefix: Pavx, op: opBytes{
		avxEscape | evex128 | evexF3 | evex0F38 | evexW0, evexN8 | evexZeroingEnabled, 0x33,
		avxEscape | evex256 | evexF3 | evex0F38 | evexW0, evexN16 | evexZeroingEnabled, 0x33,
		avxEscape | evex512 | evexF3 | evex0F38 | evexW0, evexN32 | evexZeroingEnabled, 0x33,
	}},
	{as: AVPMOVM2B, ytab: _yvpbroadcastmb2q, prefix: Pavx, op: opBytes{
		avxEscape | evex128 | evexF3 | evex0F38 | evexW0, 0, 0x28,
		avxEscape | evex256 | evexF3 | evex0F38 | evexW0, 0, 0x28,
		avxEscape | evex512 | evexF3 | evex0F38 | evexW0, 0, 0x28,
	}},
	{as: AVPMOVM2D, ytab: _yvpbroadcastmb2q, prefix: Pavx, op: opBytes{
		avxEscape | evex128 | evexF3 | evex0F38 | evexW0, 0, 0x38,
		avxEscape | evex256 | evexF3 | evex0F38 | evexW0, 0, 0x38,
		avxEscape | evex512 | evexF3 | evex0F38 | evexW0, 0, 0x38,
	}},
	{as: AVPMOVM2Q, ytab: _yvpbroadcastmb2q, prefix: Pavx, op: opBytes{
		avxEscape | evex128 | evexF3 | evex0F38 | evexW1, 0, 0x38,
		avxEscape | evex256 | evexF3 | evex0F38 | evexW1, 0, 0x38,
		avxEscape | evex512 | evexF3 | evex0F38 | evexW1, 0, 0x38,
	}},
	{as: AVPMOVM2W, ytab: _yvpbroadcastmb2q, prefix: Pavx, op: opBytes{
		avxEscape | evex128 | evexF3 | evex0F38 | evexW1, 0, 0x28,
		avxEscape | evex256 | evexF3 | evex0F38 | evexW1, 0, 0x28,
		avxEscape | evex512 | evexF3 | evex0F38 | evexW1, 0, 0x28,
	}},
	{as: AVPMOVMSKB, ytab: _yvmovmskpd, prefix: Pavx, op: opBytes{
		avxEscape | vex128 | vex66 | vex0F | vexW0, 0xD7,
		avxEscape | vex256 | vex66 | vex0F | vexW0, 0xD7,
	}},
	{as: AVPMOVQ2M, ytab: _yvpmovb2m, prefix: Pavx, op: opBytes{
		avxEscape | evex128 | evexF3 | evex0F38 | evexW1, 0, 0x39,
		avxEscape | evex256 | evexF3 | evex0F38 | evexW1, 0, 0x39,
		avxEscape | evex512 | evexF3 | evex0F38 | evexW1, 0, 0x39,
	}},
	{as: AVPMOVQB, ytab: _yvpmovdb, prefix: Pavx, op: opBytes{
		avxEscape | evex128 | evexF3 | evex0F38 | evexW0, evexN2 | evexZeroingEnabled, 0x32,
		avxEscape | evex256 | evexF3 | evex0F38 | evexW0, evexN4 | evexZeroingEnabled, 0x32,
		avxEscape | evex512 | evexF3 | evex0F38 | evexW0, evexN8 | evexZeroingEnabled, 0x32,
	}},
	{as: AVPMOVQD, ytab: _yvpmovdw, prefix: Pavx, op: opBytes{
		avxEscape | evex128 | evexF3 | evex0F38 | evexW0, evexN8 | evexZeroingEnabled, 0x35,
		avxEscape | evex256 | evexF3 | evex0F38 | evexW0, evexN16 | evexZeroingEnabled, 0x35,
		avxEscape | evex512 | evexF3 | evex0F38 | evexW0, evexN32 | evexZeroingEnabled, 0x35,
	}},
	{as: AVPMOVQW, ytab: _yvpmovdb, prefix: Pavx, op: opBytes{
		avxEscape | evex128 | evexF3 | evex0F38 | evexW0, evexN4 | evexZeroingEnabled, 0x34,
		avxEscape | evex256 | evexF3 | evex0F38 | evexW0, evexN8 | evexZeroingEnabled, 0x34,
		avxEscape | evex512 | evexF3 | evex0F38 | evexW0, evexN16 | evexZeroingEnabled, 0x34,
	}},
	{as: AVPMOVSDB, ytab: _yvpmovdb, prefix: Pavx, op: opBytes{
		avxEscape | evex128 | evexF3 | evex0F38 | evexW0, evexN4 | evexZeroingEnabled, 0x21,
		avxEscape | evex256 | evexF3 | evex0F38 | evexW0, evexN8 | evexZeroingEnabled, 0x21,
		avxEscape | evex512 | evexF3 | evex0F38 | evexW0, evexN16 | evexZeroingEnabled, 0x21,
	}},
```