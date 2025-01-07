Response:
The user wants to understand the functionality of the provided Go code snippet. This code defines a list of operations (`AMD64ops`) and block types (`AMD64blocks`) specific to the AMD64 architecture within the Go compiler's SSA (Static Single Assignment) framework.

**Plan:**

1. **Identify the core purpose:** The code defines the instruction set and control flow structures for the AMD64 architecture as understood by the Go compiler's SSA generation.
2. **Categorize operations:**  Group the listed operations into logical categories based on their functionality (e.g., data movement, arithmetic, control flow, atomic operations, etc.).
3. **Explain key concepts:** Briefly explain terms like "SSA," "opcode," "register," "aux," and "symEffect."
4. **Provide Go code examples:**  Illustrate how some common operations might translate to Go code. Focus on clarity and representative examples.
5. **Address potential misunderstandings:** Point out areas where users might make incorrect assumptions or misinterpret the information.
6. **Summarize the functionality:** Concisely reiterate the overall purpose of the code snippet.
这是Go语言编译器中用于定义AMD64架构的SSA（Static Single Assignment）中间表示的操作（operations）和基本块（blocks）的一部分。

**功能归纳:**

这段代码定义了在Go语言编译过程中，针对AMD64架构，能够执行的各种底层操作和控制流结构。它详细描述了每个操作的名称、参数数量、使用的寄存器、对应的汇编指令、类型信息、辅助信息（auxiliary information）以及可能的副作用。

**更具体的功能列表:**

1. **数据移动 (Move Operations):**
   - 在通用寄存器之间移动数据，包括不同大小的数据的零扩展和符号扩展 (如 `MOVBLZX`, `MOVBQZX`, `MOVWQSX` 等)。
   - 加载常量到寄存器 (如 `MOVLconst`, `MOVQconst`)。
   - 在整数和浮点寄存器之间移动数据，包括类型转换 (如 `CVTTSD2SL`, `CVTSL2SS`) 和直接移动不转换 (如 `MOVQi2f`, `MOVQf2i`)。
   - 从内存加载数据到寄存器 (如 `MOVBload`, `MOVWload`, `MOVLload`, `MOVQload`)。
   - 将寄存器中的数据存储到内存 (如 `MOVBstore`, `MOVWstore`, `MOVLstore`, `MOVQstore`)。
   - 加载和存储 16 字节的数据 (如 `MOVOload`, `MOVOstore`)。
   - 使用索引寻址进行加载和存储 (如 `MOVBloadidx1`, `MOVWstoreidx2`)。
   - 存储常量值到内存 (如 `MOVBstoreconst`, `MOVWstoreconst`)。
   - 使用索引寻址存储常量值到内存 (如 `MOVBstoreconstidx1`)。

2. **地址计算 (Address Computation):**
   - 计算有效地址 (Load Effective Address) (如 `LEAQ`, `LEAL`, `LEAW`, `LEAQ1` 等)。

3. **位运算 (Bitwise Operations):**
   - 异或 (XOR) 操作 (如 `PXOR`)。
   - 或 (OR) 操作 (如 `POR`)。
   - 与非 (AND NOT) 操作 (需要 CPUID feature: BMI1) (如 `ANDNQ`, `ANDNL`)。
   - 提取最低位的 set bit (需要 CPUID feature: BMI1) (如 `BLSIQ`, `BLSIL`)。
   - 提取最低位的 set bit 和其以下的位 (需要 CPUID feature: BMI1) (如 `BLSMSKQ`, `BLSMSKL`)。
   - 将最低位的 set bit 清零 (需要 CPUID feature: BMI1) (如 `BLSRQ`, `BLSRL`)。
   - 计算尾部零比特数 (需要 CPUID feature: BMI1) (如 `TZCNTQ`, `TZCNTL`)。
   - 计算头部零比特数 (需要 CPUID feature: LZCNT) (如 `LZCNTQ`, `LZCNTL`)。

4. **类型转换 (Type Conversion):**
   - 浮点数到整数的转换 (如 `CVTTSD2SL`, `CVTTSS2SQ`)。
   - 整数到浮点数的转换 (如 `CVTSL2SS`, `CVTSQ2SD`)。
   - 不同精度浮点数之间的转换 (如 `CVTSD2SS`, `CVTSS2SD`)。

5. **过程调用 (Procedure Calls):**
   - 静态函数调用 (`CALLstatic`, `CALLtail`)。
   - 通过闭包调用函数 (`CALLclosure`)。
   - 通过函数指针调用函数 (`CALLinter`)。

6. **内存操作 (Memory Operations):**
   - 使用 DUFF'S DEVICE 进行内存清零 (`DUFFZERO`) 和复制 (`DUFFCOPY`)。
   - 使用 REP STOSQ 指令进行快速内存清零 (`REPSTOSQ`).
   - 使用 REPMOVSQ 指令进行快速内存复制 (`REPMOVSQ`)。

7. **原子操作 (Atomic Operations):**
   - 原子加载 (如 `MOVBatomicload`, `MOVLatomicload`, `MOVQatomicload`)。
   - 原子交换 (如 `XCHGB`, `XCHGL`, `XCHGQ`)。
   - 原子加法 (如 `XADDLlock`, `XADDQlock`)。
   - 原子比较并交换 (如 `CMPXCHGLlock`, `CMPXCHGQlock`)。
   - 原子逻辑运算 (如 `ANDBlock`, `ANDLlock`, `ORBlock`, `ORLlock`, `LoweredAtomicAnd64`, `LoweredAtomicOr32`)。

8. **标志位操作 (Flag Operations):**
   - 反转标志位 (用于比较操作的优化) (`InvertFlags`).
   - 定义了比较操作可能产生的标志位结果 (如 `FlagEQ`, `FlagLT_ULT`)，这些通常用于条件跳转。

9. **运行时支持 (Runtime Support):**
   - 获取 G 协程本地存储指针 (`LoweredGetG`).
   - 获取闭包指针 (`LoweredGetClosurePtr`).
   - 获取调用者 PC (`LoweredGetCallerPC`).
   - 获取调用者 SP (`LoweredGetCallerSP`).
   - 执行空指针检查 (`LoweredNilCheck`).
   - 调用写屏障 (`LoweredWB`).
   - 检查 CPU 特性 (`LoweredHasCPUFeature`).
   - 触发边界检查失败的 panic (`LoweredPanicBoundsA`, `LoweredPanicBoundsB`, `LoweredPanicBoundsC`).

10. **预取指令 (Prefetch Instructions):**
    - 提示 CPU 预加载数据到缓存 (如 `PrefetchT0`, `PrefetchNTA`).

11. **字节序转换 (Byte Swapping):** (需要 CPUID feature: MOVBE)
    - 加载和存储时进行字节序转换 (如 `MOVBEWstore`, `MOVBELload`, `MOVBEQstore`)，以及对应的索引寻址版本。

12. **移位操作扩展 (Shift with Register Operand) (需要 CPUID feature: BMI2):**
    - 使用寄存器指定移位量的算术右移 (`SARXQ`, `SARXL`)，逻辑左移 (`SHLXQ`, `SHLXL`)，逻辑右移 (`SHRXQ`, `SHRXL`)，以及对应的内存加载版本和索引寻址加载版本。

13. **SIMD 操作 (Single Instruction, Multiple Data):**
    - 打包解包字节 (`PUNPCKLBW`).
    - Shuffle 字 (`PSHUFLW`).
    - 广播字节 (`PSHUFBbroadcast`, `VPBROADCASTB`).
    - 带符号的 negate/zero/preserve 字节 (`PSIGNB`).
    - 比较字节 (`PCMPEQB`).
    - 获取字节的符号位 (`PMOVMSKB`).

14. **基本块 (Blocks):**
    - 定义了各种控制流基本块，如相等 (`EQ`)、不等 (`NE`)、小于 (`LT`)、大于 (`GT`) 等条件分支，以及用于实现跳转表的 `JUMPTABLE`。

**Go 代码示例 (推理):**

虽然这段代码本身不是直接可执行的 Go 代码，但它描述了 Go 编译器在底层如何处理各种 Go 语言结构。以下是一些基于这段代码的 Go 代码示例及其背后的操作：

**示例 1: 整数加法**

```go
func add(a, b int64) int64 {
	return a + b
}
```

在 SSA 中，`a + b` 可能会被表示为一个 `ADDQ` 操作。

**示例 2: 类型转换**

```go
func floatToInt(f float64) int32 {
	return int32(f)
}
```

在 SSA 中，`int32(f)` 可能会被表示为一个 `CVTTSD2SL` 操作。

**示例 3: 内存赋值**

```go
func storeValue(ptr *int, value int) {
	*ptr = value
}
```

在 SSA 中，`*ptr = value` 可能会被表示为一个 `MOVLstore` 操作。

**示例 4: 原子操作**

```go
import "sync/atomic"

func atomicIncrement(ptr *int64) {
	atomic.AddInt64(ptr, 1)
}
```

在 SSA 中，`atomic.AddInt64(ptr, 1)` 可能会被表示为一个 `XADDQlock` 或 `LoweredAtomicAdd64` 操作。

**涉及代码推理的示例:**

假设有以下 Go 代码：

```go
package main

func main() {
	var x int8 = 10
	var y int64 = int64(x)
	println(y)
}
```

**假设输入:** `x` 的值为 `10` (int8)。

**涉及的操作:** `int64(x)` 会触发一个类型转换操作。根据提供的代码，可能会使用 `MOVBQZX` (如果需要零扩展) 或其他类似的符号/零扩展操作。

**SSA 表示 (简化):**

1. Load the value of `x` into a register.
2. Execute the `MOVBQZX` operation,将 `x` 的 8 位值零扩展到 64 位，并将结果存储到另一个寄存器。
3. Move the 64 位结果 to the variable `y`.

**输出:** `y` 的值为 `10` (int64)。

**命令行参数的具体处理:**

这段代码本身不直接处理命令行参数。它定义的是编译器内部的表示。命令行参数的处理发生在编译器的其他阶段，例如在解析命令行参数、确定目标架构等过程中。这些参数会影响最终生成的机器码，从而间接地影响这些 SSA 操作的使用。例如，`-gcflags=-V -r` 等参数会影响编译器的优化和代码生成过程，进而影响 SSA 的构建和转换。

**使用者易犯错的点:**

*   **误解 SSA 操作的直接执行:**  开发者通常不需要直接操作这些 SSA 操作。这是编译器内部的表示形式，用于代码优化和生成。理解这些操作有助于理解编译器的工作原理，但不是编写 Go 代码的日常所需。
*   **将 SSA 操作等同于汇编指令:** 虽然 `asm` 字段提供了对应的汇编指令，但 SSA 操作是更抽象的表示，可能在编译过程中被进一步优化和转换。
*   **忽略 `aux` 字段的重要性:**  `aux` 字段携带了操作的额外信息，例如常量值、符号信息等，对于理解操作的完整含义至关重要。
*   **不理解 `symEffect`:**  `symEffect` 描述了操作对符号的影响，例如是否读取、写入或获取地址。这对于理解内存访问操作的语义很重要。

**总结:**

这段 `AMD64Ops.go` 文件定义了 Go 编译器在处理 AMD64 架构代码时所使用的底层操作集合和控制流结构。它详细描述了各种数据移动、算术运算、内存访问、原子操作、函数调用等操作，以及用于构建控制流图的基本块类型。这些定义是 Go 编译器进行代码分析、优化和最终生成机器码的基础。开发者一般不需要直接接触这些定义，但理解它们可以帮助更好地理解 Go 编译器的内部工作原理。

Prompt: 
```
这是路径为go/src/cmd/compile/internal/ssa/_gen/AMD64Ops.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
这是第2部分，共2部分，请归纳一下它的功能

"""
gn extend arg0 from int8 to int64
		{name: "MOVBQZX", argLength: 1, reg: gp11, asm: "MOVBLZX"}, // zero extend arg0 from int8 to int64
		{name: "MOVWQSX", argLength: 1, reg: gp11, asm: "MOVWQSX"}, // sign extend arg0 from int16 to int64
		{name: "MOVWQZX", argLength: 1, reg: gp11, asm: "MOVWLZX"}, // zero extend arg0 from int16 to int64
		{name: "MOVLQSX", argLength: 1, reg: gp11, asm: "MOVLQSX"}, // sign extend arg0 from int32 to int64
		{name: "MOVLQZX", argLength: 1, reg: gp11, asm: "MOVL"},    // zero extend arg0 from int32 to int64

		{name: "MOVLconst", reg: gp01, asm: "MOVL", typ: "UInt32", aux: "Int32", rematerializeable: true}, // 32 low bits of auxint
		{name: "MOVQconst", reg: gp01, asm: "MOVQ", typ: "UInt64", aux: "Int64", rematerializeable: true}, // auxint

		{name: "CVTTSD2SL", argLength: 1, reg: fpgp, asm: "CVTTSD2SL"}, // convert float64 to int32
		{name: "CVTTSD2SQ", argLength: 1, reg: fpgp, asm: "CVTTSD2SQ"}, // convert float64 to int64
		{name: "CVTTSS2SL", argLength: 1, reg: fpgp, asm: "CVTTSS2SL"}, // convert float32 to int32
		{name: "CVTTSS2SQ", argLength: 1, reg: fpgp, asm: "CVTTSS2SQ"}, // convert float32 to int64
		{name: "CVTSL2SS", argLength: 1, reg: gpfp, asm: "CVTSL2SS"},   // convert int32 to float32
		{name: "CVTSL2SD", argLength: 1, reg: gpfp, asm: "CVTSL2SD"},   // convert int32 to float64
		{name: "CVTSQ2SS", argLength: 1, reg: gpfp, asm: "CVTSQ2SS"},   // convert int64 to float32
		{name: "CVTSQ2SD", argLength: 1, reg: gpfp, asm: "CVTSQ2SD"},   // convert int64 to float64
		{name: "CVTSD2SS", argLength: 1, reg: fp11, asm: "CVTSD2SS"},   // convert float64 to float32
		{name: "CVTSS2SD", argLength: 1, reg: fp11, asm: "CVTSS2SD"},   // convert float32 to float64

		// Move values between int and float registers, with no conversion.
		// TODO: should we have generic versions of these?
		{name: "MOVQi2f", argLength: 1, reg: gpfp, typ: "Float64"}, // move 64 bits from int to float reg
		{name: "MOVQf2i", argLength: 1, reg: fpgp, typ: "UInt64"},  // move 64 bits from float to int reg
		{name: "MOVLi2f", argLength: 1, reg: gpfp, typ: "Float32"}, // move 32 bits from int to float reg
		{name: "MOVLf2i", argLength: 1, reg: fpgp, typ: "UInt32"},  // move 32 bits from float to int reg, zero extend

		{name: "PXOR", argLength: 2, reg: fp21, asm: "PXOR", commutative: true, resultInArg0: true}, // exclusive or, applied to X regs (for float negation).
		{name: "POR", argLength: 2, reg: fp21, asm: "POR", commutative: true, resultInArg0: true},   // inclusive or, applied to X regs (for float min/max).

		{name: "LEAQ", argLength: 1, reg: gp11sb, asm: "LEAQ", aux: "SymOff", rematerializeable: true, symEffect: "Addr"}, // arg0 + auxint + offset encoded in aux
		{name: "LEAL", argLength: 1, reg: gp11sb, asm: "LEAL", aux: "SymOff", rematerializeable: true, symEffect: "Addr"}, // arg0 + auxint + offset encoded in aux
		{name: "LEAW", argLength: 1, reg: gp11sb, asm: "LEAW", aux: "SymOff", rematerializeable: true, symEffect: "Addr"}, // arg0 + auxint + offset encoded in aux

		// LEAxn computes arg0 + n*arg1 + auxint + aux
		// x==L zeroes the upper 4 bytes.
		{name: "LEAQ1", argLength: 2, reg: gp21sb, asm: "LEAQ", scale: 1, commutative: true, aux: "SymOff", symEffect: "Addr"}, // arg0 + arg1 + auxint + aux
		{name: "LEAL1", argLength: 2, reg: gp21sb, asm: "LEAL", scale: 1, commutative: true, aux: "SymOff", symEffect: "Addr"}, // arg0 + arg1 + auxint + aux
		{name: "LEAW1", argLength: 2, reg: gp21sb, asm: "LEAW", scale: 1, commutative: true, aux: "SymOff", symEffect: "Addr"}, // arg0 + arg1 + auxint + aux
		{name: "LEAQ2", argLength: 2, reg: gp21sb, asm: "LEAQ", scale: 2, aux: "SymOff", symEffect: "Addr"},                    // arg0 + 2*arg1 + auxint + aux
		{name: "LEAL2", argLength: 2, reg: gp21sb, asm: "LEAL", scale: 2, aux: "SymOff", symEffect: "Addr"},                    // arg0 + 2*arg1 + auxint + aux
		{name: "LEAW2", argLength: 2, reg: gp21sb, asm: "LEAW", scale: 2, aux: "SymOff", symEffect: "Addr"},                    // arg0 + 2*arg1 + auxint + aux
		{name: "LEAQ4", argLength: 2, reg: gp21sb, asm: "LEAQ", scale: 4, aux: "SymOff", symEffect: "Addr"},                    // arg0 + 4*arg1 + auxint + aux
		{name: "LEAL4", argLength: 2, reg: gp21sb, asm: "LEAL", scale: 4, aux: "SymOff", symEffect: "Addr"},                    // arg0 + 4*arg1 + auxint + aux
		{name: "LEAW4", argLength: 2, reg: gp21sb, asm: "LEAW", scale: 4, aux: "SymOff", symEffect: "Addr"},                    // arg0 + 4*arg1 + auxint + aux
		{name: "LEAQ8", argLength: 2, reg: gp21sb, asm: "LEAQ", scale: 8, aux: "SymOff", symEffect: "Addr"},                    // arg0 + 8*arg1 + auxint + aux
		{name: "LEAL8", argLength: 2, reg: gp21sb, asm: "LEAL", scale: 8, aux: "SymOff", symEffect: "Addr"},                    // arg0 + 8*arg1 + auxint + aux
		{name: "LEAW8", argLength: 2, reg: gp21sb, asm: "LEAW", scale: 8, aux: "SymOff", symEffect: "Addr"},                    // arg0 + 8*arg1 + auxint + aux
		// Note: LEAx{1,2,4,8} must not have OpSB as either argument.

		// MOVxload: loads
		// Load (Q=8,L=4,W=2,B=1) bytes from (arg0+auxint+aux), arg1=mem.
		// "+auxint+aux" == add auxint and the offset of the symbol in aux (if any) to the effective address
		// Standard versions zero extend the result. SX versions sign extend the result.
		{name: "MOVBload", argLength: 2, reg: gpload, asm: "MOVBLZX", aux: "SymOff", typ: "UInt8", faultOnNilArg0: true, symEffect: "Read"},
		{name: "MOVBQSXload", argLength: 2, reg: gpload, asm: "MOVBQSX", aux: "SymOff", faultOnNilArg0: true, symEffect: "Read"},
		{name: "MOVWload", argLength: 2, reg: gpload, asm: "MOVWLZX", aux: "SymOff", typ: "UInt16", faultOnNilArg0: true, symEffect: "Read"},
		{name: "MOVWQSXload", argLength: 2, reg: gpload, asm: "MOVWQSX", aux: "SymOff", faultOnNilArg0: true, symEffect: "Read"},
		{name: "MOVLload", argLength: 2, reg: gpload, asm: "MOVL", aux: "SymOff", typ: "UInt32", faultOnNilArg0: true, symEffect: "Read"},
		{name: "MOVLQSXload", argLength: 2, reg: gpload, asm: "MOVLQSX", aux: "SymOff", faultOnNilArg0: true, symEffect: "Read"},
		{name: "MOVQload", argLength: 2, reg: gpload, asm: "MOVQ", aux: "SymOff", typ: "UInt64", faultOnNilArg0: true, symEffect: "Read"},

		// MOVxstore: stores
		// Store (Q=8,L=4,W=2,B=1) low bytes of arg1.
		// Does *(arg0+auxint+aux) = arg1, arg2=mem.
		{name: "MOVBstore", argLength: 3, reg: gpstore, asm: "MOVB", aux: "SymOff", typ: "Mem", faultOnNilArg0: true, symEffect: "Write"},
		{name: "MOVWstore", argLength: 3, reg: gpstore, asm: "MOVW", aux: "SymOff", typ: "Mem", faultOnNilArg0: true, symEffect: "Write"},
		{name: "MOVLstore", argLength: 3, reg: gpstore, asm: "MOVL", aux: "SymOff", typ: "Mem", faultOnNilArg0: true, symEffect: "Write"},
		{name: "MOVQstore", argLength: 3, reg: gpstore, asm: "MOVQ", aux: "SymOff", typ: "Mem", faultOnNilArg0: true, symEffect: "Write"},

		// MOVOload/store: 16 byte load/store
		// These operations are only used to move data around: there is no *O arithmetic, for example.
		{name: "MOVOload", argLength: 2, reg: fpload, asm: "MOVUPS", aux: "SymOff", typ: "Int128", faultOnNilArg0: true, symEffect: "Read"}, // load 16 bytes from arg0+auxint+aux. arg1=mem
		{name: "MOVOstore", argLength: 3, reg: fpstore, asm: "MOVUPS", aux: "SymOff", typ: "Mem", faultOnNilArg0: true, symEffect: "Write"}, // store 16 bytes in arg1 to arg0+auxint+aux. arg2=mem

		// MOVxloadidx: indexed loads
		// load (Q=8,L=4,W=2,B=1) bytes from (arg0+scale*arg1+auxint+aux), arg2=mem.
		// Results are zero-extended. (TODO: sign-extending indexed loads)
		{name: "MOVBloadidx1", argLength: 3, reg: gploadidx, commutative: true, asm: "MOVBLZX", scale: 1, aux: "SymOff", typ: "UInt8", symEffect: "Read"},
		{name: "MOVWloadidx1", argLength: 3, reg: gploadidx, commutative: true, asm: "MOVWLZX", scale: 1, aux: "SymOff", typ: "UInt16", symEffect: "Read"},
		{name: "MOVWloadidx2", argLength: 3, reg: gploadidx, asm: "MOVWLZX", scale: 2, aux: "SymOff", typ: "UInt16", symEffect: "Read"},
		{name: "MOVLloadidx1", argLength: 3, reg: gploadidx, commutative: true, asm: "MOVL", scale: 1, aux: "SymOff", typ: "UInt32", symEffect: "Read"},
		{name: "MOVLloadidx4", argLength: 3, reg: gploadidx, asm: "MOVL", scale: 4, aux: "SymOff", typ: "UInt32", symEffect: "Read"},
		{name: "MOVLloadidx8", argLength: 3, reg: gploadidx, asm: "MOVL", scale: 8, aux: "SymOff", typ: "UInt32", symEffect: "Read"},
		{name: "MOVQloadidx1", argLength: 3, reg: gploadidx, commutative: true, asm: "MOVQ", scale: 1, aux: "SymOff", typ: "UInt64", symEffect: "Read"},
		{name: "MOVQloadidx8", argLength: 3, reg: gploadidx, asm: "MOVQ", scale: 8, aux: "SymOff", typ: "UInt64", symEffect: "Read"},

		// MOVxstoreidx: indexed stores
		// Store (Q=8,L=4,W=2,B=1) low bytes of arg2.
		// Does *(arg0+scale*arg1+auxint+aux) = arg2, arg3=mem.
		{name: "MOVBstoreidx1", argLength: 4, reg: gpstoreidx, commutative: true, asm: "MOVB", scale: 1, aux: "SymOff", symEffect: "Write"},
		{name: "MOVWstoreidx1", argLength: 4, reg: gpstoreidx, commutative: true, asm: "MOVW", scale: 1, aux: "SymOff", symEffect: "Write"},
		{name: "MOVWstoreidx2", argLength: 4, reg: gpstoreidx, asm: "MOVW", scale: 2, aux: "SymOff", symEffect: "Write"},
		{name: "MOVLstoreidx1", argLength: 4, reg: gpstoreidx, commutative: true, asm: "MOVL", scale: 1, aux: "SymOff", symEffect: "Write"},
		{name: "MOVLstoreidx4", argLength: 4, reg: gpstoreidx, asm: "MOVL", scale: 4, aux: "SymOff", symEffect: "Write"},
		{name: "MOVLstoreidx8", argLength: 4, reg: gpstoreidx, asm: "MOVL", scale: 8, aux: "SymOff", symEffect: "Write"},
		{name: "MOVQstoreidx1", argLength: 4, reg: gpstoreidx, commutative: true, asm: "MOVQ", scale: 1, aux: "SymOff", symEffect: "Write"},
		{name: "MOVQstoreidx8", argLength: 4, reg: gpstoreidx, asm: "MOVQ", scale: 8, aux: "SymOff", symEffect: "Write"},

		// TODO: add size-mismatched indexed loads/stores, like MOVBstoreidx4?

		// MOVxstoreconst: constant stores
		// Store (O=16,Q=8,L=4,W=2,B=1) constant bytes.
		// Does *(arg0+ValAndOff(AuxInt).Off()+aux) = ValAndOff(AuxInt).Val(), arg1=mem.
		// O version can only store the constant 0.
		{name: "MOVBstoreconst", argLength: 2, reg: gpstoreconst, asm: "MOVB", aux: "SymValAndOff", typ: "Mem", faultOnNilArg0: true, symEffect: "Write"},
		{name: "MOVWstoreconst", argLength: 2, reg: gpstoreconst, asm: "MOVW", aux: "SymValAndOff", typ: "Mem", faultOnNilArg0: true, symEffect: "Write"},
		{name: "MOVLstoreconst", argLength: 2, reg: gpstoreconst, asm: "MOVL", aux: "SymValAndOff", typ: "Mem", faultOnNilArg0: true, symEffect: "Write"},
		{name: "MOVQstoreconst", argLength: 2, reg: gpstoreconst, asm: "MOVQ", aux: "SymValAndOff", typ: "Mem", faultOnNilArg0: true, symEffect: "Write"},
		{name: "MOVOstoreconst", argLength: 2, reg: gpstoreconst, asm: "MOVUPS", aux: "SymValAndOff", typ: "Mem", faultOnNilArg0: true, symEffect: "Write"},

		// MOVxstoreconstidx: constant indexed stores
		// Store (Q=8,L=4,W=2,B=1) constant bytes.
		// Does *(arg0+scale*arg1+ValAndOff(AuxInt).Off()+aux) = ValAndOff(AuxInt).Val(), arg2=mem.
		{name: "MOVBstoreconstidx1", argLength: 3, reg: gpstoreconstidx, commutative: true, asm: "MOVB", scale: 1, aux: "SymValAndOff", typ: "Mem", symEffect: "Write"},
		{name: "MOVWstoreconstidx1", argLength: 3, reg: gpstoreconstidx, commutative: true, asm: "MOVW", scale: 1, aux: "SymValAndOff", typ: "Mem", symEffect: "Write"},
		{name: "MOVWstoreconstidx2", argLength: 3, reg: gpstoreconstidx, asm: "MOVW", scale: 2, aux: "SymValAndOff", typ: "Mem", symEffect: "Write"},
		{name: "MOVLstoreconstidx1", argLength: 3, reg: gpstoreconstidx, commutative: true, asm: "MOVL", scale: 1, aux: "SymValAndOff", typ: "Mem", symEffect: "Write"},
		{name: "MOVLstoreconstidx4", argLength: 3, reg: gpstoreconstidx, asm: "MOVL", scale: 4, aux: "SymValAndOff", typ: "Mem", symEffect: "Write"},
		{name: "MOVQstoreconstidx1", argLength: 3, reg: gpstoreconstidx, commutative: true, asm: "MOVQ", scale: 1, aux: "SymValAndOff", typ: "Mem", symEffect: "Write"},
		{name: "MOVQstoreconstidx8", argLength: 3, reg: gpstoreconstidx, asm: "MOVQ", scale: 8, aux: "SymValAndOff", typ: "Mem", symEffect: "Write"},

		// arg0 = pointer to start of memory to zero
		// arg1 = mem
		// auxint = # of bytes to zero
		// returns mem
		{
			name:      "DUFFZERO",
			aux:       "Int64",
			argLength: 2,
			reg: regInfo{
				inputs:   []regMask{buildReg("DI")},
				clobbers: buildReg("DI"),
			},
			faultOnNilArg0: true,
			unsafePoint:    true, // FP maintenance around DUFFCOPY can be clobbered by interrupts
		},

		// arg0 = address of memory to zero
		// arg1 = # of 8-byte words to zero
		// arg2 = value to store (will always be zero)
		// arg3 = mem
		// returns mem
		{
			name:      "REPSTOSQ",
			argLength: 4,
			reg: regInfo{
				inputs:   []regMask{buildReg("DI"), buildReg("CX"), buildReg("AX")},
				clobbers: buildReg("DI CX"),
			},
			faultOnNilArg0: true,
		},

		// With a register ABI, the actual register info for these instructions (i.e., what is used in regalloc) is augmented with per-call-site bindings of additional arguments to specific in and out registers.
		{name: "CALLstatic", argLength: -1, reg: regInfo{clobbers: callerSave}, aux: "CallOff", clobberFlags: true, call: true},                                              // call static function aux.(*obj.LSym).  last arg=mem, auxint=argsize, returns mem
		{name: "CALLtail", argLength: -1, reg: regInfo{clobbers: callerSave}, aux: "CallOff", clobberFlags: true, call: true, tailCall: true},                                // tail call static function aux.(*obj.LSym).  last arg=mem, auxint=argsize, returns mem
		{name: "CALLclosure", argLength: -1, reg: regInfo{inputs: []regMask{gpsp, buildReg("DX"), 0}, clobbers: callerSave}, aux: "CallOff", clobberFlags: true, call: true}, // call function via closure.  arg0=codeptr, arg1=closure, last arg=mem, auxint=argsize, returns mem
		{name: "CALLinter", argLength: -1, reg: regInfo{inputs: []regMask{gp}, clobbers: callerSave}, aux: "CallOff", clobberFlags: true, call: true},                        // call fn by pointer.  arg0=codeptr, last arg=mem, auxint=argsize, returns mem

		// arg0 = destination pointer
		// arg1 = source pointer
		// arg2 = mem
		// auxint = # of bytes to copy, must be multiple of 16
		// returns memory
		{
			name:      "DUFFCOPY",
			aux:       "Int64",
			argLength: 3,
			reg: regInfo{
				inputs:   []regMask{buildReg("DI"), buildReg("SI")},
				clobbers: buildReg("DI SI X0"), // uses X0 as a temporary
			},
			clobberFlags:   true,
			faultOnNilArg0: true,
			faultOnNilArg1: true,
			unsafePoint:    true, // FP maintenance around DUFFCOPY can be clobbered by interrupts
		},

		// arg0 = destination pointer
		// arg1 = source pointer
		// arg2 = # of 8-byte words to copy
		// arg3 = mem
		// returns memory
		{
			name:      "REPMOVSQ",
			argLength: 4,
			reg: regInfo{
				inputs:   []regMask{buildReg("DI"), buildReg("SI"), buildReg("CX")},
				clobbers: buildReg("DI SI CX"),
			},
			faultOnNilArg0: true,
			faultOnNilArg1: true,
		},

		// (InvertFlags (CMPQ a b)) == (CMPQ b a)
		// So if we want (SETL (CMPQ a b)) but we can't do that because a is a constant,
		// then we do (SETL (InvertFlags (CMPQ b a))) instead.
		// Rewrites will convert this to (SETG (CMPQ b a)).
		// InvertFlags is a pseudo-op which can't appear in assembly output.
		{name: "InvertFlags", argLength: 1}, // reverse direction of arg0

		// Pseudo-ops
		{name: "LoweredGetG", argLength: 1, reg: gp01}, // arg0=mem
		// Scheduler ensures LoweredGetClosurePtr occurs only in entry block,
		// and sorts it to the very beginning of the block to prevent other
		// use of DX (the closure pointer)
		{name: "LoweredGetClosurePtr", reg: regInfo{outputs: []regMask{buildReg("DX")}}, zeroWidth: true},
		// LoweredGetCallerPC evaluates to the PC to which its "caller" will return.
		// I.e., if f calls g "calls" sys.GetCallerPC,
		// the result should be the PC within f that g will return to.
		// See runtime/stubs.go for a more detailed discussion.
		{name: "LoweredGetCallerPC", reg: gp01, rematerializeable: true},
		// LoweredGetCallerSP returns the SP of the caller of the current function. arg0=mem
		{name: "LoweredGetCallerSP", argLength: 1, reg: gp01, rematerializeable: true},
		//arg0=ptr,arg1=mem, returns void.  Faults if ptr is nil.
		{name: "LoweredNilCheck", argLength: 2, reg: regInfo{inputs: []regMask{gpsp}}, clobberFlags: true, nilCheck: true, faultOnNilArg0: true},
		// LoweredWB invokes runtime.gcWriteBarrier{auxint}. arg0=mem, auxint=# of buffer entries needed.
		// It saves all GP registers if necessary, but may clobber others.
		// Returns a pointer to a write barrier buffer in R11.
		{name: "LoweredWB", argLength: 1, reg: regInfo{clobbers: callerSave &^ (gp | g), outputs: []regMask{buildReg("R11")}}, clobberFlags: true, aux: "Int64"},

		{name: "LoweredHasCPUFeature", argLength: 0, reg: gp01, rematerializeable: true, typ: "UInt64", aux: "Sym", symEffect: "None"},

		// There are three of these functions so that they can have three different register inputs.
		// When we check 0 <= c <= cap (A), then 0 <= b <= c (B), then 0 <= a <= b (C), we want the
		// default registers to match so we don't need to copy registers around unnecessarily.
		{name: "LoweredPanicBoundsA", argLength: 3, aux: "Int64", reg: regInfo{inputs: []regMask{dx, bx}}, typ: "Mem", call: true}, // arg0=idx, arg1=len, arg2=mem, returns memory. AuxInt contains report code (see PanicBounds in generic.go).
		{name: "LoweredPanicBoundsB", argLength: 3, aux: "Int64", reg: regInfo{inputs: []regMask{cx, dx}}, typ: "Mem", call: true}, // arg0=idx, arg1=len, arg2=mem, returns memory. AuxInt contains report code (see PanicBounds in generic.go).
		{name: "LoweredPanicBoundsC", argLength: 3, aux: "Int64", reg: regInfo{inputs: []regMask{ax, cx}}, typ: "Mem", call: true}, // arg0=idx, arg1=len, arg2=mem, returns memory. AuxInt contains report code (see PanicBounds in generic.go).

		// Constant flag values. For any comparison, there are 5 possible
		// outcomes: the three from the signed total order (<,==,>) and the
		// three from the unsigned total order. The == cases overlap.
		// Note: there's a sixth "unordered" outcome for floating-point
		// comparisons, but we don't use such a beast yet.
		// These ops are for temporary use by rewrite rules. They
		// cannot appear in the generated assembly.
		{name: "FlagEQ"},     // equal
		{name: "FlagLT_ULT"}, // signed < and unsigned <
		{name: "FlagLT_UGT"}, // signed < and unsigned >
		{name: "FlagGT_UGT"}, // signed > and unsigned >
		{name: "FlagGT_ULT"}, // signed > and unsigned <

		// Atomic loads.  These are just normal loads but return <value,memory> tuples
		// so they can be properly ordered with other loads.
		// load from arg0+auxint+aux.  arg1=mem.
		{name: "MOVBatomicload", argLength: 2, reg: gpload, asm: "MOVB", aux: "SymOff", faultOnNilArg0: true, symEffect: "Read"},
		{name: "MOVLatomicload", argLength: 2, reg: gpload, asm: "MOVL", aux: "SymOff", faultOnNilArg0: true, symEffect: "Read"},
		{name: "MOVQatomicload", argLength: 2, reg: gpload, asm: "MOVQ", aux: "SymOff", faultOnNilArg0: true, symEffect: "Read"},

		// Atomic stores and exchanges.  Stores use XCHG to get the right memory ordering semantics.
		// store arg0 to arg1+auxint+aux, arg2=mem.
		// These ops return a tuple of <old contents of *(arg1+auxint+aux), memory>.
		// Note: arg0 and arg1 are backwards compared to MOVLstore (to facilitate resultInArg0)!
		{name: "XCHGB", argLength: 3, reg: gpstorexchg, asm: "XCHGB", aux: "SymOff", resultInArg0: true, faultOnNilArg1: true, hasSideEffects: true, symEffect: "RdWr"},
		{name: "XCHGL", argLength: 3, reg: gpstorexchg, asm: "XCHGL", aux: "SymOff", resultInArg0: true, faultOnNilArg1: true, hasSideEffects: true, symEffect: "RdWr"},
		{name: "XCHGQ", argLength: 3, reg: gpstorexchg, asm: "XCHGQ", aux: "SymOff", resultInArg0: true, faultOnNilArg1: true, hasSideEffects: true, symEffect: "RdWr"},

		// Atomic adds.
		// *(arg1+auxint+aux) += arg0.  arg2=mem.
		// Returns a tuple of <old contents of *(arg1+auxint+aux), memory>.
		// Note: arg0 and arg1 are backwards compared to MOVLstore (to facilitate resultInArg0)!
		{name: "XADDLlock", argLength: 3, reg: gpstorexchg, asm: "XADDL", typ: "(UInt32,Mem)", aux: "SymOff", resultInArg0: true, clobberFlags: true, faultOnNilArg1: true, hasSideEffects: true, symEffect: "RdWr"},
		{name: "XADDQlock", argLength: 3, reg: gpstorexchg, asm: "XADDQ", typ: "(UInt64,Mem)", aux: "SymOff", resultInArg0: true, clobberFlags: true, faultOnNilArg1: true, hasSideEffects: true, symEffect: "RdWr"},
		{name: "AddTupleFirst32", argLength: 2}, // arg1=tuple <x,y>.  Returns <x+arg0,y>.
		{name: "AddTupleFirst64", argLength: 2}, // arg1=tuple <x,y>.  Returns <x+arg0,y>.

		// Compare and swap.
		// arg0 = pointer, arg1 = old value, arg2 = new value, arg3 = memory.
		// if *(arg0+auxint+aux) == arg1 {
		//   *(arg0+auxint+aux) = arg2
		//   return (true, memory)
		// } else {
		//   return (false, memory)
		// }
		// Note that these instructions also return the old value in AX, but we ignore it.
		// TODO: have these return flags instead of bool.  The current system generates:
		//    CMPXCHGQ ...
		//    SETEQ AX
		//    CMPB  AX, $0
		//    JNE ...
		// instead of just
		//    CMPXCHGQ ...
		//    JEQ ...
		// but we can't do that because memory-using ops can't generate flags yet
		// (flagalloc wants to move flag-generating instructions around).
		{name: "CMPXCHGLlock", argLength: 4, reg: cmpxchg, asm: "CMPXCHGL", aux: "SymOff", clobberFlags: true, faultOnNilArg0: true, hasSideEffects: true, symEffect: "RdWr"},
		{name: "CMPXCHGQlock", argLength: 4, reg: cmpxchg, asm: "CMPXCHGQ", aux: "SymOff", clobberFlags: true, faultOnNilArg0: true, hasSideEffects: true, symEffect: "RdWr"},

		// Atomic memory updates using logical operations.
		// Old style that just returns the memory state.
		{name: "ANDBlock", argLength: 3, reg: gpstore, asm: "ANDB", aux: "SymOff", clobberFlags: true, faultOnNilArg0: true, hasSideEffects: true, symEffect: "RdWr"}, // *(arg0+auxint+aux) &= arg1
		{name: "ANDLlock", argLength: 3, reg: gpstore, asm: "ANDL", aux: "SymOff", clobberFlags: true, faultOnNilArg0: true, hasSideEffects: true, symEffect: "RdWr"}, // *(arg0+auxint+aux) &= arg1
		{name: "ANDQlock", argLength: 3, reg: gpstore, asm: "ANDQ", aux: "SymOff", clobberFlags: true, faultOnNilArg0: true, hasSideEffects: true, symEffect: "RdWr"}, // *(arg0+auxint+aux) &= arg1
		{name: "ORBlock", argLength: 3, reg: gpstore, asm: "ORB", aux: "SymOff", clobberFlags: true, faultOnNilArg0: true, hasSideEffects: true, symEffect: "RdWr"},   // *(arg0+auxint+aux) |= arg1
		{name: "ORLlock", argLength: 3, reg: gpstore, asm: "ORL", aux: "SymOff", clobberFlags: true, faultOnNilArg0: true, hasSideEffects: true, symEffect: "RdWr"},   // *(arg0+auxint+aux) |= arg1
		{name: "ORQlock", argLength: 3, reg: gpstore, asm: "ORQ", aux: "SymOff", clobberFlags: true, faultOnNilArg0: true, hasSideEffects: true, symEffect: "RdWr"},   // *(arg0+auxint+aux) |= arg1

		// Atomic memory updates using logical operations.
		// *(arg0+auxint+aux) op= arg1. arg2=mem.
		// New style that returns a tuple of <old contents of *(arg0+auxint+aux), memory>.
		{name: "LoweredAtomicAnd64", argLength: 3, reg: atomicLogic, resultNotInArgs: true, asm: "ANDQ", aux: "SymOff", clobberFlags: true, faultOnNilArg0: true, hasSideEffects: true, symEffect: "RdWr", unsafePoint: true, needIntTemp: true},
		{name: "LoweredAtomicAnd32", argLength: 3, reg: atomicLogic, resultNotInArgs: true, asm: "ANDL", aux: "SymOff", clobberFlags: true, faultOnNilArg0: true, hasSideEffects: true, symEffect: "RdWr", unsafePoint: true, needIntTemp: true},
		{name: "LoweredAtomicOr64", argLength: 3, reg: atomicLogic, resultNotInArgs: true, asm: "ORQ", aux: "SymOff", clobberFlags: true, faultOnNilArg0: true, hasSideEffects: true, symEffect: "RdWr", unsafePoint: true, needIntTemp: true},
		{name: "LoweredAtomicOr32", argLength: 3, reg: atomicLogic, resultNotInArgs: true, asm: "ORL", aux: "SymOff", clobberFlags: true, faultOnNilArg0: true, hasSideEffects: true, symEffect: "RdWr", unsafePoint: true, needIntTemp: true},

		// Prefetch instructions
		// Do prefetch arg0 address. arg0=addr, arg1=memory. Instruction variant selects locality hint
		{name: "PrefetchT0", argLength: 2, reg: prefreg, asm: "PREFETCHT0", hasSideEffects: true},
		{name: "PrefetchNTA", argLength: 2, reg: prefreg, asm: "PREFETCHNTA", hasSideEffects: true},

		// CPUID feature: BMI1.
		{name: "ANDNQ", argLength: 2, reg: gp21, asm: "ANDNQ", clobberFlags: true},         // arg0 &^ arg1
		{name: "ANDNL", argLength: 2, reg: gp21, asm: "ANDNL", clobberFlags: true},         // arg0 &^ arg1
		{name: "BLSIQ", argLength: 1, reg: gp11, asm: "BLSIQ", clobberFlags: true},         // arg0 & -arg0
		{name: "BLSIL", argLength: 1, reg: gp11, asm: "BLSIL", clobberFlags: true},         // arg0 & -arg0
		{name: "BLSMSKQ", argLength: 1, reg: gp11, asm: "BLSMSKQ", clobberFlags: true},     // arg0 ^ (arg0 - 1)
		{name: "BLSMSKL", argLength: 1, reg: gp11, asm: "BLSMSKL", clobberFlags: true},     // arg0 ^ (arg0 - 1)
		{name: "BLSRQ", argLength: 1, reg: gp11flags, asm: "BLSRQ", typ: "(UInt64,Flags)"}, // arg0 & (arg0 - 1)
		{name: "BLSRL", argLength: 1, reg: gp11flags, asm: "BLSRL", typ: "(UInt32,Flags)"}, // arg0 & (arg0 - 1)
		// count the number of trailing zero bits, prefer TZCNTQ over BSFQ, as TZCNTQ(0)==64
		// and BSFQ(0) is undefined. Same for TZCNTL(0)==32
		{name: "TZCNTQ", argLength: 1, reg: gp11, asm: "TZCNTQ", clobberFlags: true},
		{name: "TZCNTL", argLength: 1, reg: gp11, asm: "TZCNTL", clobberFlags: true},

		// CPUID feature: LZCNT.
		// count the number of leading zero bits.
		{name: "LZCNTQ", argLength: 1, reg: gp11, asm: "LZCNTQ", typ: "UInt64", clobberFlags: true},
		{name: "LZCNTL", argLength: 1, reg: gp11, asm: "LZCNTL", typ: "UInt32", clobberFlags: true},

		// CPUID feature: MOVBE
		// MOVBEWload does not satisfy zero extended, so only use MOVBEWstore
		{name: "MOVBEWstore", argLength: 3, reg: gpstore, asm: "MOVBEW", aux: "SymOff", typ: "Mem", faultOnNilArg0: true, symEffect: "Write"}, // swap and store 2 bytes in arg1 to arg0+auxint+aux. arg2=mem
		{name: "MOVBELload", argLength: 2, reg: gpload, asm: "MOVBEL", aux: "SymOff", typ: "UInt32", faultOnNilArg0: true, symEffect: "Read"}, // load and swap 4 bytes from arg0+auxint+aux. arg1=mem.  Zero extend.
		{name: "MOVBELstore", argLength: 3, reg: gpstore, asm: "MOVBEL", aux: "SymOff", typ: "Mem", faultOnNilArg0: true, symEffect: "Write"}, // swap and store 4 bytes in arg1 to arg0+auxint+aux. arg2=mem
		{name: "MOVBEQload", argLength: 2, reg: gpload, asm: "MOVBEQ", aux: "SymOff", typ: "UInt64", faultOnNilArg0: true, symEffect: "Read"}, // load and swap 8 bytes from arg0+auxint+aux. arg1=mem
		{name: "MOVBEQstore", argLength: 3, reg: gpstore, asm: "MOVBEQ", aux: "SymOff", typ: "Mem", faultOnNilArg0: true, symEffect: "Write"}, // swap and store 8 bytes in arg1 to arg0+auxint+aux. arg2=mem
		// indexed MOVBE loads
		{name: "MOVBELloadidx1", argLength: 3, reg: gploadidx, commutative: true, asm: "MOVBEL", scale: 1, aux: "SymOff", typ: "UInt32", symEffect: "Read"}, // load and swap 4 bytes from arg0+arg1+auxint+aux. arg2=mem. Zero extend.
		{name: "MOVBELloadidx4", argLength: 3, reg: gploadidx, asm: "MOVBEL", scale: 4, aux: "SymOff", typ: "UInt32", symEffect: "Read"},                    // load and swap 4 bytes from arg0+4*arg1+auxint+aux. arg2=mem. Zero extend.
		{name: "MOVBELloadidx8", argLength: 3, reg: gploadidx, asm: "MOVBEL", scale: 8, aux: "SymOff", typ: "UInt32", symEffect: "Read"},                    // load and swap 4 bytes from arg0+8*arg1+auxint+aux. arg2=mem. Zero extend.
		{name: "MOVBEQloadidx1", argLength: 3, reg: gploadidx, commutative: true, asm: "MOVBEQ", scale: 1, aux: "SymOff", typ: "UInt64", symEffect: "Read"}, // load and swap 8 bytes from arg0+arg1+auxint+aux. arg2=mem
		{name: "MOVBEQloadidx8", argLength: 3, reg: gploadidx, asm: "MOVBEQ", scale: 8, aux: "SymOff", typ: "UInt64", symEffect: "Read"},                    // load and swap 8 bytes from arg0+8*arg1+auxint+aux. arg2=mem
		// indexed MOVBE stores
		{name: "MOVBEWstoreidx1", argLength: 4, reg: gpstoreidx, commutative: true, asm: "MOVBEW", scale: 1, aux: "SymOff", symEffect: "Write"}, // swap and store 2 bytes in arg2 to arg0+arg1+auxint+aux. arg3=mem
		{name: "MOVBEWstoreidx2", argLength: 4, reg: gpstoreidx, asm: "MOVBEW", scale: 2, aux: "SymOff", symEffect: "Write"},                    // swap and store 2 bytes in arg2 to arg0+2*arg1+auxint+aux. arg3=mem
		{name: "MOVBELstoreidx1", argLength: 4, reg: gpstoreidx, commutative: true, asm: "MOVBEL", scale: 1, aux: "SymOff", symEffect: "Write"}, // swap and store 4 bytes in arg2 to arg0+arg1+auxint+aux. arg3=mem
		{name: "MOVBELstoreidx4", argLength: 4, reg: gpstoreidx, asm: "MOVBEL", scale: 4, aux: "SymOff", symEffect: "Write"},                    // swap and store 4 bytes in arg2 to arg0+4*arg1+auxint+aux. arg3=mem
		{name: "MOVBELstoreidx8", argLength: 4, reg: gpstoreidx, asm: "MOVBEL", scale: 8, aux: "SymOff", symEffect: "Write"},                    // swap and store 4 bytes in arg2 to arg0+8*arg1+auxint+aux. arg3=mem
		{name: "MOVBEQstoreidx1", argLength: 4, reg: gpstoreidx, commutative: true, asm: "MOVBEQ", scale: 1, aux: "SymOff", symEffect: "Write"}, // swap and store 8 bytes in arg2 to arg0+arg1+auxint+aux. arg3=mem
		{name: "MOVBEQstoreidx8", argLength: 4, reg: gpstoreidx, asm: "MOVBEQ", scale: 8, aux: "SymOff", symEffect: "Write"},                    // swap and store 8 bytes in arg2 to arg0+8*arg1+auxint+aux. arg3=mem

		// CPUID feature: BMI2.
		{name: "SARXQ", argLength: 2, reg: gp21, asm: "SARXQ"}, // signed arg0 >> arg1, shift amount is mod 64
		{name: "SARXL", argLength: 2, reg: gp21, asm: "SARXL"}, // signed int32(arg0) >> arg1, shift amount is mod 32
		{name: "SHLXQ", argLength: 2, reg: gp21, asm: "SHLXQ"}, // arg0 << arg1, shift amount is mod 64
		{name: "SHLXL", argLength: 2, reg: gp21, asm: "SHLXL"}, // arg0 << arg1, shift amount is mod 32
		{name: "SHRXQ", argLength: 2, reg: gp21, asm: "SHRXQ"}, // unsigned arg0 >> arg1, shift amount is mod 64
		{name: "SHRXL", argLength: 2, reg: gp21, asm: "SHRXL"}, // unsigned uint32(arg0) >> arg1, shift amount is mod 32

		{name: "SARXLload", argLength: 3, reg: gp21shxload, asm: "SARXL", aux: "SymOff", typ: "Uint32", faultOnNilArg0: true, symEffect: "Read"}, // signed *(arg0+auxint+aux) >> arg1, arg2=mem, shift amount is mod 32
		{name: "SARXQload", argLength: 3, reg: gp21shxload, asm: "SARXQ", aux: "SymOff", typ: "Uint64", faultOnNilArg0: true, symEffect: "Read"}, // signed *(arg0+auxint+aux) >> arg1, arg2=mem, shift amount is mod 64
		{name: "SHLXLload", argLength: 3, reg: gp21shxload, asm: "SHLXL", aux: "SymOff", typ: "Uint32", faultOnNilArg0: true, symEffect: "Read"}, // *(arg0+auxint+aux) << arg1, arg2=mem, shift amount is mod 32
		{name: "SHLXQload", argLength: 3, reg: gp21shxload, asm: "SHLXQ", aux: "SymOff", typ: "Uint64", faultOnNilArg0: true, symEffect: "Read"}, // *(arg0+auxint+aux) << arg1, arg2=mem, shift amount is mod 64
		{name: "SHRXLload", argLength: 3, reg: gp21shxload, asm: "SHRXL", aux: "SymOff", typ: "Uint32", faultOnNilArg0: true, symEffect: "Read"}, // unsigned *(arg0+auxint+aux) >> arg1, arg2=mem, shift amount is mod 32
		{name: "SHRXQload", argLength: 3, reg: gp21shxload, asm: "SHRXQ", aux: "SymOff", typ: "Uint64", faultOnNilArg0: true, symEffect: "Read"}, // unsigned *(arg0+auxint+aux) >> arg1, arg2=mem, shift amount is mod 64

		{name: "SARXLloadidx1", argLength: 4, reg: gp21shxloadidx, asm: "SARXL", scale: 1, aux: "SymOff", typ: "Uint32", faultOnNilArg0: true, symEffect: "Read"}, // signed *(arg0+1*arg1+auxint+aux) >> arg2, arg3=mem, shift amount is mod 32
		{name: "SARXLloadidx4", argLength: 4, reg: gp21shxloadidx, asm: "SARXL", scale: 4, aux: "SymOff", typ: "Uint32", faultOnNilArg0: true, symEffect: "Read"}, // signed *(arg0+4*arg1+auxint+aux) >> arg2, arg3=mem, shift amount is mod 32
		{name: "SARXLloadidx8", argLength: 4, reg: gp21shxloadidx, asm: "SARXL", scale: 8, aux: "SymOff", typ: "Uint32", faultOnNilArg0: true, symEffect: "Read"}, // signed *(arg0+8*arg1+auxint+aux) >> arg2, arg3=mem, shift amount is mod 32
		{name: "SARXQloadidx1", argLength: 4, reg: gp21shxloadidx, asm: "SARXQ", scale: 1, aux: "SymOff", typ: "Uint64", faultOnNilArg0: true, symEffect: "Read"}, // signed *(arg0+1*arg1+auxint+aux) >> arg2, arg3=mem, shift amount is mod 64
		{name: "SARXQloadidx8", argLength: 4, reg: gp21shxloadidx, asm: "SARXQ", scale: 8, aux: "SymOff", typ: "Uint64", faultOnNilArg0: true, symEffect: "Read"}, // signed *(arg0+8*arg1+auxint+aux) >> arg2, arg3=mem, shift amount is mod 64
		{name: "SHLXLloadidx1", argLength: 4, reg: gp21shxloadidx, asm: "SHLXL", scale: 1, aux: "SymOff", typ: "Uint32", faultOnNilArg0: true, symEffect: "Read"}, // *(arg0+1*arg1+auxint+aux) << arg2, arg3=mem, shift amount is mod 32
		{name: "SHLXLloadidx4", argLength: 4, reg: gp21shxloadidx, asm: "SHLXL", scale: 4, aux: "SymOff", typ: "Uint32", faultOnNilArg0: true, symEffect: "Read"}, // *(arg0+4*arg1+auxint+aux) << arg2, arg3=mem, shift amount is mod 32
		{name: "SHLXLloadidx8", argLength: 4, reg: gp21shxloadidx, asm: "SHLXL", scale: 8, aux: "SymOff", typ: "Uint32", faultOnNilArg0: true, symEffect: "Read"}, // *(arg0+8*arg1+auxint+aux) << arg2, arg3=mem, shift amount is mod 32
		{name: "SHLXQloadidx1", argLength: 4, reg: gp21shxloadidx, asm: "SHLXQ", scale: 1, aux: "SymOff", typ: "Uint64", faultOnNilArg0: true, symEffect: "Read"}, // *(arg0+1*arg1+auxint+aux) << arg2, arg3=mem, shift amount is mod 64
		{name: "SHLXQloadidx8", argLength: 4, reg: gp21shxloadidx, asm: "SHLXQ", scale: 8, aux: "SymOff", typ: "Uint64", faultOnNilArg0: true, symEffect: "Read"}, // *(arg0+8*arg1+auxint+aux) << arg2, arg3=mem, shift amount is mod 64
		{name: "SHRXLloadidx1", argLength: 4, reg: gp21shxloadidx, asm: "SHRXL", scale: 1, aux: "SymOff", typ: "Uint32", faultOnNilArg0: true, symEffect: "Read"}, // unsigned *(arg0+1*arg1+auxint+aux) >> arg2, arg3=mem, shift amount is mod 32
		{name: "SHRXLloadidx4", argLength: 4, reg: gp21shxloadidx, asm: "SHRXL", scale: 4, aux: "SymOff", typ: "Uint32", faultOnNilArg0: true, symEffect: "Read"}, // unsigned *(arg0+4*arg1+auxint+aux) >> arg2, arg3=mem, shift amount is mod 32
		{name: "SHRXLloadidx8", argLength: 4, reg: gp21shxloadidx, asm: "SHRXL", scale: 8, aux: "SymOff", typ: "Uint32", faultOnNilArg0: true, symEffect: "Read"}, // unsigned *(arg0+8*arg1+auxint+aux) >> arg2, arg3=mem, shift amount is mod 32
		{name: "SHRXQloadidx1", argLength: 4, reg: gp21shxloadidx, asm: "SHRXQ", scale: 1, aux: "SymOff", typ: "Uint64", faultOnNilArg0: true, symEffect: "Read"}, // unsigned *(arg0+1*arg1+auxint+aux) >> arg2, arg3=mem, shift amount is mod 64
		{name: "SHRXQloadidx8", argLength: 4, reg: gp21shxloadidx, asm: "SHRXQ", scale: 8, aux: "SymOff", typ: "Uint64", faultOnNilArg0: true, symEffect: "Read"}, // unsigned *(arg0+8*arg1+auxint+aux) >> arg2, arg3=mem, shift amount is mod 64

		// Unpack bytes, low 64-bits.
		//
		// Input/output registers treated as [8]uint8.
		//
		// output = {in1[0], in2[0], in1[1], in2[1], in1[2], in2[2], in1[3], in2[3]}
		{name: "PUNPCKLBW", argLength: 2, reg: fp21, resultInArg0: true, asm: "PUNPCKLBW"},

		// Shuffle 16-bit words, low 64-bits.
		//
		// Input/output registers treated as [4]uint16.
		// aux=source word index for each destination word, 2 bits per index.
		//
		// output[i] = input[(aux>>2*i)&3].
		{name: "PSHUFLW", argLength: 1, reg: fp11, aux: "Int8", asm: "PSHUFLW"},

		// Broadcast input byte.
		//
		// Input treated as uint8, output treated as [16]uint8.
		//
		// output[i] = input.
		{name: "PSHUFBbroadcast", argLength: 1, reg: fp11, resultInArg0: true, asm: "PSHUFB"}, // PSHUFB with mask zero, (GOAMD64=v1)
		{name: "VPBROADCASTB", argLength: 1, reg: gpfp, asm: "VPBROADCASTB"}, // Broadcast input byte from gp (GOAMD64=v3)

		// Byte negate/zero/preserve (GOAMD64=v2).
		//
		// Input/output registers treated as [16]uint8.
		//
		// if in2[i] > 0 {
		//   output[i] = in1[i]
		// } else if in2[i] == 0 {
		//   output[i] = 0
		// } else {
		//   output[i] = -1 * in1[i]
		// }
		{name: "PSIGNB", argLength: 2, reg: fp21, resultInArg0: true, asm: "PSIGNB"},

		// Byte compare.
		//
		// Input/output registers treated as [16]uint8.
		//
		// if in1[i] == in2[i] {
		//   output[i] = 0xff
		// } else {
		//   output[i] = 0
		// }
		{name: "PCMPEQB", argLength: 2, reg: fp21, resultInArg0: true, asm: "PCMPEQB"},

		// Byte sign mask. Output is a bitmap of sign bits from each input byte.
		//
		// Input treated as [16]uint8. Output is [16]bit (uint16 bitmap).
		//
		// output[i] = (input[i] >> 7) & 1
		{name: "PMOVMSKB", argLength: 1, reg: fpgp, asm: "PMOVMSKB"},
	}

	var AMD64blocks = []blockData{
		{name: "EQ", controls: 1},
		{name: "NE", controls: 1},
		{name: "LT", controls: 1},
		{name: "LE", controls: 1},
		{name: "GT", controls: 1},
		{name: "GE", controls: 1},
		{name: "OS", controls: 1},
		{name: "OC", controls: 1},
		{name: "ULT", controls: 1},
		{name: "ULE", controls: 1},
		{name: "UGT", controls: 1},
		{name: "UGE", controls: 1},
		{name: "EQF", controls: 1},
		{name: "NEF", controls: 1},
		{name: "ORD", controls: 1}, // FP, ordered comparison (parity zero)
		{name: "NAN", controls: 1}, // FP, unordered comparison (parity one)

		// JUMPTABLE implements jump tables.
		// Aux is the symbol (an *obj.LSym) for the jump table.
		// control[0] is the index into the jump table.
		// control[1] is the address of the jump table (the address of the symbol stored in Aux).
		{name: "JUMPTABLE", controls: 2, aux: "Sym"},
	}

	archs = append(archs, arch{
		name:               "AMD64",
		pkg:                "cmd/internal/obj/x86",
		genfile:            "../../amd64/ssa.go",
		ops:                AMD64ops,
		blocks:             AMD64blocks,
		regnames:           regNamesAMD64,
		ParamIntRegNames:   "AX BX CX DI SI R8 R9 R10 R11",
		ParamFloatRegNames: "X0 X1 X2 X3 X4 X5 X6 X7 X8 X9 X10 X11 X12 X13 X14",
		gpregmask:          gp,
		fpregmask:          fp,
		specialregmask:     x15,
		framepointerreg:    int8(num["BP"]),
		linkreg:            -1, // not used
	})
}

"""




```