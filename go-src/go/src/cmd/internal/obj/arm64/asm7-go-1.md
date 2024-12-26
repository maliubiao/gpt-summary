Response: The user wants a summary of the functionality of the provided Go code snippet. This is the second part of a larger file.

I need to analyze the functions and their purposes to understand what this part of the code does.

Based on the function names and their logic, this part seems to be responsible for:

1. **Splitting immediate values:** `splitImm24uScaled` handles splitting a 24-bit unsigned immediate into scaled low and high parts.
2. **Checking instruction operand types:** Functions like `isSTLXRop`, `isSTXPop`, `isANDop`, etc., determine the type of operation based on the `obj.As` value. These are likely used during instruction encoding to select the correct instruction format.
3. **Validating constants:** `ispcdisp`, `isaddcon`, `isaddcon2`, `isbitcon` are used to check if a constant value can be encoded within a specific instruction format.
4. **Encoding bitwise constants:** `bitconEncode` takes a bitwise constant and encodes it according to the ARM64 specification.
5. **Calculating logarithms:** `log2` calculates the base-2 logarithm of a number.
6. **Classifying operands:** `autoclass`, `oregclass`, `con32class`, `con64class`, `loadStoreClass`, `loadStorePairClass`, `aclass` categorize different types of operands (immediate values, registers, memory addresses) based on their properties. This classification is likely used to determine which encoding scheme to apply.
7. **Shifting offsets:** `offsetshift` scales offsets based on the operand class.
8. **Checking for single 16-bit values:** `movcon` determines if a value can be represented by a single 16-bit value.
9. **Classifying registers:** `rclass` categorizes registers.
10. **Looking up instruction templates:** `oplook` finds the appropriate instruction template (`Optab`) based on the operands' classes.
11. **Comparing operand classes:** `cmp` checks if one operand class is compatible with another.
12. **Comparing instruction templates:** `ocmp` compares two `Optab` structures.
13. **Setting operand ranges:** `oprangeset` associates instruction types with their valid `Optab` entries.
14. **Building the instruction opcode table:** `buildop` initializes the `oprange` table, which maps instruction types to their possible encodings.
15. **Checking floating-point constant encoding:** `chipfloat7` determines if a floating-point number can be encoded as an immediate value in certain floating-point instructions.
16. **Encoding system register arguments:** `SYSARG5` and `SYSARG4` format arguments for system instructions.
17. **Checking for unpredictable behavior:** `checkUnpredictable` warns about situations in load/store pair instructions that might lead to undefined behavior.
18. **Validating array indices and offsets:** `checkindex`, `checkoffset`, `checkShiftAmount` ensure that array indices, memory offsets, and shift amounts are within valid ranges.
19. **Generating the machine code:** `asmout` takes a program instruction and outputs its machine code representation.

**Hypothesis:** This part of the code is responsible for taking an abstract representation of an ARM64 instruction (likely from a compiler's intermediate representation) and translating it into the actual binary encoding that the processor can execute. This involves classifying operands, looking up instruction templates, and then filling in the specific bit fields of the instruction based on the operands' values and types.
这是 `go/src/cmd/internal/obj/arm64/asm7.go` 文件的一部分，它主要负责 **ARM64 汇编指令的编码和操作数分类**。

具体来说，这部分代码定义了一些函数，用于：

1. **操作数类型的分类（Operand Classification）：**
   - `aclass(a *obj.Addr) int`:  根据 `obj.Addr` 结构体的信息（类型、寄存器、偏移等），将操作数分类到不同的类别 (例如：寄存器 `C_REG`，立即数 `C_ZCON`、`C_ADDCON`，内存地址 `C_LAUTO`、`C_LOREG` 等)。 这些类别在后续的指令编码过程中用于选择合适的指令格式。
   - `rclass(r int16) int`: 对寄存器进行分类。
   - `con32class(a *obj.Addr) int`: 对 32 位指令的常量操作数进行分类。
   - `con64class(a *obj.Addr) int`: 对 64 位指令的常量操作数进行分类。
   - `autoclass(l int64) int`: 对自动变量的偏移量进行分类。
   - `oregclass(l int64) int`: 对寄存器偏移量进行分类。
   - `loadStoreClass`, `loadStorePairClass`: 对加载/存储指令的偏移量进行更细致的分类。

2. **判断操作数的性质：**
   - `isSTLXRop`, `isSTXPop`, `isANDop`, `isANDWop`, `isADDop`, `isADDWop`, `isADDSop`, `isNEGop`, `isLoadStorePairOp`, `isMOVop`:  判断给定的操作码 `obj.As` 是否属于特定的指令类型。
   - `isRegShiftOrExt(a *obj.Addr) bool`: 判断操作数是否包含寄存器移位或扩展。
   - `ispcdisp(v int32) bool`: 判断值 `v` 是否是有效的 PC 相对位移。
   - `isaddcon(v int64) bool`, `isaddcon2(v int64) bool`: 判断常量 `v` 是否可以编码为加法/减法指令的立即数。
   - `isbitcon(x uint64) bool`: 判断常量 `x` 是否可以编码为逻辑指令的位掩码。
   - `sequenceOfOnes(x uint64) bool`:  判断一个常量是否是二进制全 1 序列。
   - `movcon(v int64) int`: 判断常量 `v` 是否可以编码为 `movk`/`movn` 指令的操作数。
   - `chipfloat7(e float64) int`:  检查浮点数是否可以作为 `FMOVS`/`FMOVD` 指令的立即数。

3. **操作数处理和转换：**
   - `splitImm24uScaled(v int32, shift int) (int32, int32, error)`: 将一个 24 位无符号立即数拆分为一个缩放后的低 12 位值和一个未缩放的高 12 位值。
   - `bitconEncode(x uint64, mode int) uint32`: 将位掩码常量编码为逻辑指令使用的格式。
   - `log2(x uint64) uint32`: 计算以 2 为底的对数。
   - `offsetshift(p *obj.Prog, v int64, cls int) int64`:  根据操作数类别，返回指令中使用的偏移量值，可能经过缩放。
   - `regoff(a *obj.Addr) int32`:  计算操作数的偏移量。
   - `SYSARG5`, `SYSARG4`:  用于构建 `SYS` 指令的参数。

4. **指令模板查找和匹配：**
   - `oplook(p *obj.Prog) *Optab`:  根据指令的操作码和操作数的类别，在指令模板表 `optab` 中查找匹配的条目。`Optab` 结构体包含了指令的各种信息，例如指令类型、操作数类别、编码方式等。
   - `cmp(a int, b int) bool`:  比较两个操作数类别是否兼容。
   - `ocmp(p1, p2 Optab) int`:  比较两个指令模板 `Optab` 是否相等。
   - `oprangeset(a obj.As, t []Optab)`:  设置特定操作码对应的指令模板范围。
   - `buildop(ctxt *obj.Link)`:  构建指令操作码表 `oprange`，将操作码映射到可能的 `Optab` 列表。

5. **错误检查和警告：**
   - `checkUnpredictable`: 检查加载/存储对指令是否存在可能导致不可预测行为的情况。
   - `checkindex`, `checkoffset`, `checkShiftAmount`: 检查数组索引、内存偏移和移位量是否在有效范围内。

6. **指令编码的核心逻辑：**
   - `asmout(p *obj.Prog, out []uint32) (count int)`:  这是将高级指令 `obj.Prog` 编码为实际机器码的核心函数。它首先调用 `oplook` 找到匹配的指令模板，然后根据模板的类型和操作数的信息，将指令编码到 `out` 数组中。

**推理出的 Go 语言功能实现：**

这部分代码是 **Go 语言汇编器（assembler）** 中 ARM64 架构后端的一部分。它的主要功能是将 Go 语言的汇编代码（或编译器生成的中间表示）转换为 ARM64 机器码。

**Go 代码举例说明:**

假设我们有如下的 Go 汇编代码：

```assembly
TEXT ·add(SB),NOSPLIT,$0-24
  MOVQ arg0+0(FP), R0  // 将第一个参数加载到 R0
  MOVQ arg1+8(FP), R1  // 将第二个参数加载到 R1
  ADDQ R1, R0         // R0 = R0 + R1
  MOVQ R0, ret+16(FP) // 将结果存储到返回值位置
  RET
```

当汇编器处理 `ADDQ R1, R0` 这条指令时，`asmout` 函数会被调用，并执行以下步骤（简化）：

1. **操作数分类:** `oplook` 函数会被调用，对 `R1` 和 `R0` 进行分类，它们会被分类为 `C_REG` (寄存器)。
2. **指令模板查找:**  `oplook` 函数会根据操作码 `ADDQ` 和操作数类别 `C_REG`, `C_REG`，在 `oprange` 表中查找匹配的 `Optab` 结构体，该结构体描述了 `ADDQ` 寄存器加寄存器指令的编码格式。
3. **指令编码:** `asmout` 函数会根据查找到的 `Optab` 结构体，并结合 `R1` 和 `R0` 的寄存器编号，生成对应的 ARM64 机器码。例如，`ADDQ R1, R0` 可能会被编码为 `0x8b000001`。

**假设的输入与输出 (针对 `splitImm24uScaled`):**

**输入:** `v = 0x100C`, `shift = 2`

**输出:** `hi = 0x1000`, `lo = 0x3`, `error = nil`

**推理:**
- `v >> shift` (0x100C >> 2) = 0x403
- `lo = (v >> shift) & 0xfff` (0x403 & 0xfff) = 0x403  (这里代码有误，应该是 `lo = (v >> shift) & 0xfff`，且后续计算有调整，实际 `lo` 应该为 3)
- `lo << shift` (0x403 << 2) = 0x100C (如果 `lo` 为 0x403)
- `hi = v - (lo << shift)` (0x100C - 0x100C) = 0  (如果 `lo` 为 0x403)
- 实际代码中，如果 `hi > 0xfff000` 会进行调整。 对于输入 `0x100C` 和 `shift = 2`，实际计算过程如下：
    - `lo = (0x100c >> 2) & 0xfff = 0x403`
    - `hi = 0x100c - (0x403 << 2) = 0x100c - 0x100c = 0`
    - 但由于 `v&((1<<shift)-1)` (0x100c & 3) 为 0，所以直接返回。

**假设的输入与输出 (针对 `isbitcon`):**

**输入:** `x = 0b0101010101010101010101010101010101010101010101010101010101010101` (重复的 `01`)

**输出:** `true`

**输入:** `x = 0b11111111111111111111111111111110`

**输出:** `false`

**命令行参数处理：**

这段代码本身是 Go 语言的实现，并不直接处理命令行参数。命令行参数的处理通常发生在 `cmd/asm/internal/asm.go` 等更上层的模块中。这些参数会影响汇编器的行为，例如指定目标架构、输入输出文件等。

**使用者易犯错的点：**

对于直接使用这段代码的开发者（通常是 Go 语言工具链的维护者），容易犯错的点可能包括：

- **操作数类别定义不准确：** 如果 `aclass` 等分类函数对操作数类型的判断有误，会导致 `oplook` 找不到正确的指令模板，从而生成错误的机器码。
- **指令模板 `optab` 定义错误：**  `optab` 中指令的编码信息如果与 ARM64 手册不符，会导致生成的机器码错误。
- **位运算错误：** 在进行立即数拆分、位掩码编码等操作时，如果位运算逻辑错误，会导致生成错误的指令字段。
- **忽略指令的限制条件：** 例如，某些指令对立即数的范围、寄存器的使用有特定的限制，如果没有在代码中进行正确的检查，会导致生成非法的指令。

**归纳一下它的功能 (第2部分):**

这部分 `asm7.go` 代码的核心功能是 **为 ARM64 架构的 Go 汇编器提供操作数分类和指令模板匹配的功能**。它定义了各种函数来识别和分类不同类型的操作数，并根据操作码和操作数类型，从预定义的指令模板表中找到合适的编码方案，为后续的机器码生成阶段提供必要的信息。它还包含了对常量进行特殊处理和编码的逻辑，以及一些基本的错误检查机制。

Prompt: 
```
这是路径为go/src/cmd/internal/obj/arm64/asm7.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
这是第2部分，共4部分，请归纳一下它的功能

"""
 immediate into a scaled 12 bit unsigned lo value
// and an unscaled shifted 12 bit unsigned hi value. These are typically used
// by adding or subtracting the hi value and using the lo value as the offset
// for a load or store.
func splitImm24uScaled(v int32, shift int) (int32, int32, error) {
	if v < 0 {
		return 0, 0, fmt.Errorf("%d is not a 24 bit unsigned immediate", v)
	}
	if v > 0xfff000+0xfff<<shift {
		return 0, 0, fmt.Errorf("%d is too large for a scaled 24 bit unsigned immediate", v)
	}
	if v&((1<<shift)-1) != 0 {
		return 0, 0, fmt.Errorf("%d is not a multiple of %d", v, 1<<shift)
	}
	lo := (v >> shift) & 0xfff
	hi := v - (lo << shift)
	if hi > 0xfff000 {
		hi = 0xfff000
		lo = (v - hi) >> shift
	}
	if hi & ^0xfff000 != 0 {
		panic(fmt.Sprintf("bad split for %x with shift %v (%x, %x)", v, shift, hi, lo))
	}
	return hi, lo, nil
}

func (c *ctxt7) regoff(a *obj.Addr) int32 {
	c.instoffset = 0
	c.aclass(a)
	return int32(c.instoffset)
}

func isSTLXRop(op obj.As) bool {
	switch op {
	case ASTLXR, ASTLXRW, ASTLXRB, ASTLXRH,
		ASTXR, ASTXRW, ASTXRB, ASTXRH:
		return true
	}
	return false
}

func isSTXPop(op obj.As) bool {
	switch op {
	case ASTXP, ASTLXP, ASTXPW, ASTLXPW:
		return true
	}
	return false
}

func isANDop(op obj.As) bool {
	switch op {
	case AAND, AORR, AEOR, AANDS, ATST,
		ABIC, AEON, AORN, ABICS:
		return true
	}
	return false
}

func isANDWop(op obj.As) bool {
	switch op {
	case AANDW, AORRW, AEORW, AANDSW, ATSTW,
		ABICW, AEONW, AORNW, ABICSW:
		return true
	}
	return false
}

func isADDop(op obj.As) bool {
	switch op {
	case AADD, AADDS, ASUB, ASUBS, ACMN, ACMP:
		return true
	}
	return false
}

func isADDWop(op obj.As) bool {
	switch op {
	case AADDW, AADDSW, ASUBW, ASUBSW, ACMNW, ACMPW:
		return true
	}
	return false
}

func isADDSop(op obj.As) bool {
	switch op {
	case AADDS, AADDSW, ASUBS, ASUBSW:
		return true
	}
	return false
}

func isNEGop(op obj.As) bool {
	switch op {
	case ANEG, ANEGW, ANEGS, ANEGSW:
		return true
	}
	return false
}

func isLoadStorePairOp(op obj.As) bool {
	switch op {
	case AFLDPQ, AFSTPQ, ALDP, ASTP, ALDPW, ASTPW:
		return true
	}
	return false
}

func isMOVop(op obj.As) bool {
	switch op {
	case AMOVB, AMOVBU, AMOVH, AMOVHU, AMOVW, AMOVWU, AMOVD, AFMOVS, AFMOVD, AFMOVQ:
		return true
	}
	return false
}

func isRegShiftOrExt(a *obj.Addr) bool {
	return (a.Index-obj.RBaseARM64)&REG_EXT != 0 || (a.Index-obj.RBaseARM64)&REG_LSL != 0
}

// Maximum PC-relative displacement.
// The actual limit is ±2²⁰, but we are conservative
// to avoid needing to recompute the literal pool flush points
// as span-dependent jumps are enlarged.
const maxPCDisp = 512 * 1024

// ispcdisp reports whether v is a valid PC-relative displacement.
func ispcdisp(v int32) bool {
	return -maxPCDisp < v && v < maxPCDisp && v&3 == 0
}

func isaddcon(v int64) bool {
	/* uimm12 or uimm24? */
	if v < 0 {
		return false
	}
	if (v & 0xFFF) == 0 {
		v >>= 12
	}
	return v <= 0xFFF
}

func isaddcon2(v int64) bool {
	return 0 <= v && v <= 0xFFFFFF
}

// isbitcon reports whether a constant can be encoded into a logical instruction.
// bitcon has a binary form of repetition of a bit sequence of length 2, 4, 8, 16, 32, or 64,
// which itself is a rotate (w.r.t. the length of the unit) of a sequence of ones.
// special cases: 0 and -1 are not bitcon.
// this function needs to run against virtually all the constants, so it needs to be fast.
// for this reason, bitcon testing and bitcon encoding are separate functions.
func isbitcon(x uint64) bool {
	if x == 1<<64-1 || x == 0 {
		return false
	}
	// determine the period and sign-extend a unit to 64 bits
	switch {
	case x != x>>32|x<<32:
		// period is 64
		// nothing to do
	case x != x>>16|x<<48:
		// period is 32
		x = uint64(int64(int32(x)))
	case x != x>>8|x<<56:
		// period is 16
		x = uint64(int64(int16(x)))
	case x != x>>4|x<<60:
		// period is 8
		x = uint64(int64(int8(x)))
	default:
		// period is 4 or 2, always true
		// 0001, 0010, 0100, 1000 -- 0001 rotate
		// 0011, 0110, 1100, 1001 -- 0011 rotate
		// 0111, 1011, 1101, 1110 -- 0111 rotate
		// 0101, 1010             -- 01   rotate, repeat
		return true
	}
	return sequenceOfOnes(x) || sequenceOfOnes(^x)
}

// sequenceOfOnes tests whether a constant is a sequence of ones in binary, with leading and trailing zeros.
func sequenceOfOnes(x uint64) bool {
	y := x & -x // lowest set bit of x. x is good iff x+y is a power of 2
	y += x
	return (y-1)&y == 0
}

// bitconEncode returns the encoding of a bitcon used in logical instructions
// x is known to be a bitcon
// a bitcon is a sequence of n ones at low bits (i.e. 1<<n-1), right rotated
// by R bits, and repeated with period of 64, 32, 16, 8, 4, or 2.
// it is encoded in logical instructions with 3 bitfields
// N (1 bit) : R (6 bits) : S (6 bits), where
// N=1           -- period=64
// N=0, S=0xxxxx -- period=32
// N=0, S=10xxxx -- period=16
// N=0, S=110xxx -- period=8
// N=0, S=1110xx -- period=4
// N=0, S=11110x -- period=2
// R is the shift amount, low bits of S = n-1
func bitconEncode(x uint64, mode int) uint32 {
	if mode == 32 {
		x &= 0xffffffff
		x = x<<32 | x
	}
	var period uint32
	// determine the period and sign-extend a unit to 64 bits
	switch {
	case x != x>>32|x<<32:
		period = 64
	case x != x>>16|x<<48:
		period = 32
		x = uint64(int64(int32(x)))
	case x != x>>8|x<<56:
		period = 16
		x = uint64(int64(int16(x)))
	case x != x>>4|x<<60:
		period = 8
		x = uint64(int64(int8(x)))
	case x != x>>2|x<<62:
		period = 4
		x = uint64(int64(x<<60) >> 60)
	default:
		period = 2
		x = uint64(int64(x<<62) >> 62)
	}
	neg := false
	if int64(x) < 0 {
		x = ^x
		neg = true
	}
	y := x & -x // lowest set bit of x.
	s := log2(y)
	n := log2(x+y) - s // x (or ^x) is a sequence of n ones left shifted by s bits
	if neg {
		// ^x is a sequence of n ones left shifted by s bits
		// adjust n, s for x
		s = n + s
		n = period - n
	}

	N := uint32(0)
	if mode == 64 && period == 64 {
		N = 1
	}
	R := (period - s) & (period - 1) & uint32(mode-1) // shift amount of right rotate
	S := (n - 1) | 63&^(period<<1-1)                  // low bits = #ones - 1, high bits encodes period
	return N<<22 | R<<16 | S<<10
}

func log2(x uint64) uint32 {
	if x == 0 {
		panic("log2 of 0")
	}
	n := uint32(0)
	if x >= 1<<32 {
		x >>= 32
		n += 32
	}
	if x >= 1<<16 {
		x >>= 16
		n += 16
	}
	if x >= 1<<8 {
		x >>= 8
		n += 8
	}
	if x >= 1<<4 {
		x >>= 4
		n += 4
	}
	if x >= 1<<2 {
		x >>= 2
		n += 2
	}
	if x >= 1<<1 {
		x >>= 1
		n += 1
	}
	return n
}

func autoclass(l int64) int {
	if l == 0 {
		return C_ZAUTO
	}

	if l < 0 {
		if l >= -256 && (l&15) == 0 {
			return C_NSAUTO_16
		}
		if l >= -256 && (l&7) == 0 {
			return C_NSAUTO_8
		}
		if l >= -256 && (l&3) == 0 {
			return C_NSAUTO_4
		}
		if l >= -256 {
			return C_NSAUTO
		}
		if l >= -512 && (l&15) == 0 {
			return C_NPAUTO_16
		}
		if l >= -512 && (l&7) == 0 {
			return C_NPAUTO
		}
		if l >= -1024 && (l&15) == 0 {
			return C_NQAUTO_16
		}
		if l >= -4095 {
			return C_NAUTO4K
		}
		return C_LAUTO
	}

	if l <= 255 {
		if (l & 15) == 0 {
			return C_PSAUTO_16
		}
		if (l & 7) == 0 {
			return C_PSAUTO_8
		}
		if (l & 3) == 0 {
			return C_PSAUTO_4
		}
		return C_PSAUTO
	}
	if l <= 504 {
		if l&15 == 0 {
			return C_PPAUTO_16
		}
		if l&7 == 0 {
			return C_PPAUTO
		}
	}
	if l <= 1008 {
		if l&15 == 0 {
			return C_PQAUTO_16
		}
	}
	if l <= 4095 {
		if l&15 == 0 {
			return C_UAUTO4K_16
		}
		if l&7 == 0 {
			return C_UAUTO4K_8
		}
		if l&3 == 0 {
			return C_UAUTO4K_4
		}
		if l&1 == 0 {
			return C_UAUTO4K_2
		}
		return C_UAUTO4K
	}
	if l <= 8190 {
		if l&15 == 0 {
			return C_UAUTO8K_16
		}
		if l&7 == 0 {
			return C_UAUTO8K_8
		}
		if l&3 == 0 {
			return C_UAUTO8K_4
		}
		if l&1 == 0 {
			return C_UAUTO8K
		}
	}
	if l <= 16380 {
		if l&15 == 0 {
			return C_UAUTO16K_16
		}
		if l&7 == 0 {
			return C_UAUTO16K_8
		}
		if l&3 == 0 {
			return C_UAUTO16K
		}
	}
	if l <= 32760 {
		if l&15 == 0 {
			return C_UAUTO32K_16
		}
		if l&7 == 0 {
			return C_UAUTO32K
		}
	}
	if l <= 65520 && (l&15) == 0 {
		return C_UAUTO64K
	}
	return C_LAUTO
}

func oregclass(l int64) int {
	return autoclass(l) - C_ZAUTO + C_ZOREG
}

/*
 * given an offset v and a class c (see above)
 * return the offset value to use in the instruction,
 * scaled if necessary
 */
func (c *ctxt7) offsetshift(p *obj.Prog, v int64, cls int) int64 {
	s := 0
	if cls >= C_SEXT1 && cls <= C_SEXT16 {
		s = cls - C_SEXT1
	} else {
		switch cls {
		case C_UAUTO4K, C_UOREG4K, C_ZOREG:
			s = 0
		case C_UAUTO8K, C_UOREG8K:
			s = 1
		case C_UAUTO16K, C_UOREG16K:
			s = 2
		case C_UAUTO32K, C_UOREG32K:
			s = 3
		case C_UAUTO64K, C_UOREG64K:
			s = 4
		default:
			c.ctxt.Diag("bad class: %v\n%v", DRconv(cls), p)
		}
	}
	vs := v >> uint(s)
	if vs<<uint(s) != v {
		c.ctxt.Diag("odd offset: %d\n%v", v, p)
	}
	return vs
}

/*
 * if v contains a single 16-bit value aligned
 * on a 16-bit field, and thus suitable for movk/movn,
 * return the field index 0 to 3; otherwise return -1.
 */
func movcon(v int64) int {
	for s := 0; s < 64; s += 16 {
		if (uint64(v) &^ (uint64(0xFFFF) << uint(s))) == 0 {
			return s / 16
		}
	}
	return -1
}

func rclass(r int16) int {
	switch {
	case REG_R0 <= r && r <= REG_R30: // not 31
		return C_REG
	case r == REGZERO:
		return C_ZREG
	case REG_F0 <= r && r <= REG_F31:
		return C_FREG
	case REG_V0 <= r && r <= REG_V31:
		return C_VREG
	case r == REGSP:
		return C_RSP
	case r >= REG_ARNG && r < REG_ELEM:
		return C_ARNG
	case r >= REG_ELEM && r < REG_ELEM_END:
		return C_ELEM
	case r >= REG_UXTB && r < REG_SPECIAL,
		r >= REG_LSL && r < REG_ARNG:
		return C_EXTREG
	case r >= REG_SPECIAL:
		return C_SPR
	}
	return C_GOK
}

// con32class reclassifies the constant of 32-bit instruction. Because the constant type is 32-bit,
// but saved in Offset which type is int64, con32class treats it as uint32 type and reclassifies it.
func (c *ctxt7) con32class(a *obj.Addr) int {
	v := uint32(a.Offset)
	// For 32-bit instruction with constant, rewrite
	// the high 32-bit to be a repetition of the low
	// 32-bit, so that the BITCON test can be shared
	// for both 32-bit and 64-bit. 32-bit ops will
	// zero the high 32-bit of the destination register
	// anyway.
	vbitcon := uint64(v)<<32 | uint64(v)
	if v == 0 {
		return C_ZCON
	}
	if isaddcon(int64(v)) {
		if v <= 0xFFF {
			if isbitcon(vbitcon) {
				return C_ABCON0
			}
			return C_ADDCON0
		}
		if isbitcon(vbitcon) {
			return C_ABCON
		}
		if movcon(int64(v)) >= 0 {
			return C_AMCON
		}
		if movcon(int64(^v)) >= 0 {
			return C_AMCON
		}
		return C_ADDCON
	}

	t := movcon(int64(v))
	if t >= 0 {
		if isbitcon(vbitcon) {
			return C_MBCON
		}
		return C_MOVCON
	}

	t = movcon(int64(^v))
	if t >= 0 {
		if isbitcon(vbitcon) {
			return C_MBCON
		}
		return C_MOVCON
	}

	if isbitcon(vbitcon) {
		return C_BITCON
	}

	if 0 <= v && v <= 0xffffff {
		return C_ADDCON2
	}
	return C_LCON
}

// con64class reclassifies the constant of C_VCON and C_LCON class.
func (c *ctxt7) con64class(a *obj.Addr) int {
	zeroCount := 0
	negCount := 0
	for i := uint(0); i < 4; i++ {
		immh := uint32(a.Offset >> (i * 16) & 0xffff)
		if immh == 0 {
			zeroCount++
		} else if immh == 0xffff {
			negCount++
		}
	}
	if zeroCount >= 3 || negCount >= 3 {
		return C_MOVCON
	} else if zeroCount == 2 || negCount == 2 {
		return C_MOVCON2
	} else if zeroCount == 1 || negCount == 1 {
		return C_MOVCON3
	} else {
		return C_VCON
	}
}

// loadStoreClass reclassifies a load or store operation based on its offset.
func (c *ctxt7) loadStoreClass(p *obj.Prog, lsc int, v int64) int {
	// Avoid reclassification of pre/post-indexed loads and stores.
	if p.Scond == C_XPRE || p.Scond == C_XPOST {
		return lsc
	}
	if cmp(C_NSAUTO, lsc) || cmp(C_NSOREG, lsc) {
		return lsc
	}

	needsPool := true
	if v >= -4095 && v <= 4095 {
		needsPool = false
	}

	switch p.As {
	case AMOVB, AMOVBU:
		if cmp(C_UAUTO4K, lsc) || cmp(C_UOREG4K, lsc) {
			return lsc
		}
		if v >= 0 && v <= 0xffffff {
			needsPool = false
		}
	case AMOVH, AMOVHU:
		if cmp(C_UAUTO8K, lsc) || cmp(C_UOREG8K, lsc) {
			return lsc
		}
		if v >= 0 && v <= 0xfff000+0xfff<<1 && v&1 == 0 {
			needsPool = false
		}
	case AMOVW, AMOVWU, AFMOVS:
		if cmp(C_UAUTO16K, lsc) || cmp(C_UOREG16K, lsc) {
			return lsc
		}
		if v >= 0 && v <= 0xfff000+0xfff<<2 && v&3 == 0 {
			needsPool = false
		}
	case AMOVD, AFMOVD:
		if cmp(C_UAUTO32K, lsc) || cmp(C_UOREG32K, lsc) {
			return lsc
		}
		if v >= 0 && v <= 0xfff000+0xfff<<3 && v&7 == 0 {
			needsPool = false
		}
	case AFMOVQ:
		if cmp(C_UAUTO64K, lsc) || cmp(C_UOREG64K, lsc) {
			return lsc
		}
		if v >= 0 && v <= 0xfff000+0xfff<<4 && v&15 == 0 {
			needsPool = false
		}
	}
	if needsPool && cmp(C_LAUTO, lsc) {
		return C_LAUTOPOOL
	}
	if needsPool && cmp(C_LOREG, lsc) {
		return C_LOREGPOOL
	}
	return lsc
}

// loadStorePairClass reclassifies a load or store pair operation based on its offset.
func (c *ctxt7) loadStorePairClass(p *obj.Prog, lsc int, v int64) int {
	// Avoid reclassification of pre/post-indexed loads and stores.
	if p.Scond == C_XPRE || p.Scond == C_XPOST {
		return lsc
	}

	if cmp(C_NAUTO4K, lsc) || cmp(C_NOREG4K, lsc) {
		return lsc
	}
	if cmp(C_UAUTO4K, lsc) || cmp(C_UOREG4K, lsc) {
		return lsc
	}

	needsPool := true
	if v >= 0 && v <= 0xffffff {
		needsPool = false
	}
	if needsPool && cmp(C_LAUTO, lsc) {
		return C_LAUTOPOOL
	}
	if needsPool && cmp(C_LOREG, lsc) {
		return C_LOREGPOOL
	}
	return lsc
}

func (c *ctxt7) aclass(a *obj.Addr) int {
	switch a.Type {
	case obj.TYPE_NONE:
		return C_NONE

	case obj.TYPE_REG:
		return rclass(a.Reg)

	case obj.TYPE_REGREG:
		return C_PAIR

	case obj.TYPE_SHIFT:
		return C_SHIFT

	case obj.TYPE_REGLIST:
		return C_LIST

	case obj.TYPE_MEM:
		// The base register should be an integer register.
		if int16(REG_F0) <= a.Reg && a.Reg <= int16(REG_V31) {
			break
		}
		switch a.Name {
		case obj.NAME_EXTERN, obj.NAME_STATIC:
			if a.Sym == nil {
				break
			}
			c.instoffset = a.Offset
			if a.Sym != nil { // use relocation
				if a.Sym.Type == objabi.STLSBSS {
					if c.ctxt.Flag_shared {
						return C_TLS_IE
					} else {
						return C_TLS_LE
					}
				}
				return C_ADDR
			}
			return C_LEXT

		case obj.NAME_GOTREF:
			return C_GOTADDR

		case obj.NAME_AUTO:
			if a.Reg == REGSP {
				// unset base register for better printing, since
				// a.Offset is still relative to pseudo-SP.
				a.Reg = obj.REG_NONE
			}
			// The frame top 8 or 16 bytes are for FP
			c.instoffset = int64(c.autosize) + a.Offset - int64(c.extrasize)
			return autoclass(c.instoffset)

		case obj.NAME_PARAM:
			if a.Reg == REGSP {
				// unset base register for better printing, since
				// a.Offset is still relative to pseudo-FP.
				a.Reg = obj.REG_NONE
			}
			c.instoffset = int64(c.autosize) + a.Offset + 8
			return autoclass(c.instoffset)

		case obj.NAME_NONE:
			if a.Index != 0 {
				if a.Offset != 0 {
					if isRegShiftOrExt(a) {
						// extended or shifted register offset, (Rn)(Rm.UXTW<<2) or (Rn)(Rm<<2).
						return C_ROFF
					}
					return C_GOK
				}
				// register offset, (Rn)(Rm)
				return C_ROFF
			}
			c.instoffset = a.Offset
			return oregclass(c.instoffset)
		}
		return C_GOK

	case obj.TYPE_FCONST:
		return C_FCON

	case obj.TYPE_TEXTSIZE:
		return C_TEXTSIZE

	case obj.TYPE_CONST, obj.TYPE_ADDR:
		switch a.Name {
		case obj.NAME_NONE:
			c.instoffset = a.Offset
			if a.Reg != 0 && a.Reg != REGZERO {
				break
			}
			v := c.instoffset
			if v == 0 {
				return C_ZCON
			}
			if isaddcon(v) {
				if v <= 0xFFF {
					if isbitcon(uint64(v)) {
						return C_ABCON0
					}
					return C_ADDCON0
				}
				if isbitcon(uint64(v)) {
					return C_ABCON
				}
				if movcon(v) >= 0 {
					return C_AMCON
				}
				if movcon(^v) >= 0 {
					return C_AMCON
				}
				return C_ADDCON
			}

			t := movcon(v)
			if t >= 0 {
				if isbitcon(uint64(v)) {
					return C_MBCON
				}
				return C_MOVCON
			}

			t = movcon(^v)
			if t >= 0 {
				if isbitcon(uint64(v)) {
					return C_MBCON
				}
				return C_MOVCON
			}

			if isbitcon(uint64(v)) {
				return C_BITCON
			}

			if 0 <= v && v <= 0xffffff {
				return C_ADDCON2
			}

			if uint64(v) == uint64(uint32(v)) || v == int64(int32(v)) {
				return C_LCON
			}
			return C_VCON

		case obj.NAME_EXTERN, obj.NAME_STATIC:
			if a.Sym == nil {
				return C_GOK
			}
			if a.Sym.Type == objabi.STLSBSS {
				c.ctxt.Diag("taking address of TLS variable is not supported")
			}
			c.instoffset = a.Offset
			return C_VCONADDR

		case obj.NAME_AUTO:
			if a.Reg == REGSP {
				// unset base register for better printing, since
				// a.Offset is still relative to pseudo-SP.
				a.Reg = obj.REG_NONE
			}
			// The frame top 8 or 16 bytes are for FP
			c.instoffset = int64(c.autosize) + a.Offset - int64(c.extrasize)

		case obj.NAME_PARAM:
			if a.Reg == REGSP {
				// unset base register for better printing, since
				// a.Offset is still relative to pseudo-FP.
				a.Reg = obj.REG_NONE
			}
			c.instoffset = int64(c.autosize) + a.Offset + 8
		default:
			return C_GOK
		}
		cf := c.instoffset
		if isaddcon(cf) || isaddcon(-cf) {
			return C_AACON
		}
		if isaddcon2(cf) {
			return C_AACON2
		}

		return C_LACON

	case obj.TYPE_BRANCH:
		return C_SBRA

	case obj.TYPE_SPECIAL:
		opd := SpecialOperand(a.Offset)
		if SPOP_EQ <= opd && opd <= SPOP_NV {
			return C_COND
		}
		return C_SPOP
	}
	return C_GOK
}

func (c *ctxt7) oplook(p *obj.Prog) *Optab {
	a1 := int(p.Optab)
	if a1 != 0 {
		return &optab[a1-1]
	}
	a1 = int(p.From.Class)
	if a1 == 0 {
		a1 = c.aclass(&p.From)
		// do not break C_ADDCON2 when S bit is set
		if (p.As == AADDS || p.As == AADDSW || p.As == ASUBS || p.As == ASUBSW) && a1 == C_ADDCON2 {
			a1 = C_LCON
		}
		if p.From.Type == obj.TYPE_CONST && p.From.Name == obj.NAME_NONE {
			if p.As == AMOVW || isADDWop(p.As) || isANDWop(p.As) {
				// For 32-bit instruction with constant, we need to
				// treat its offset value as 32 bits to classify it.
				a1 = c.con32class(&p.From)
				// do not break C_ADDCON2 when S bit is set
				if (p.As == AADDSW || p.As == ASUBSW) && a1 == C_ADDCON2 {
					a1 = C_LCON
				}
			}
			if ((p.As == AMOVD) || isANDop(p.As) || isADDop(p.As)) && (a1 == C_LCON || a1 == C_VCON) {
				// more specific classification of 64-bit integers
				a1 = c.con64class(&p.From)
			}
		}
		if p.From.Type == obj.TYPE_MEM {
			if isMOVop(p.As) && (cmp(C_LAUTO, a1) || cmp(C_LOREG, a1)) {
				// More specific classification of large offset loads and stores.
				a1 = c.loadStoreClass(p, a1, c.instoffset)
			}
			if isLoadStorePairOp(p.As) && (cmp(C_LAUTO, a1) || cmp(C_LOREG, a1)) {
				// More specific classification of large offset loads and stores.
				a1 = c.loadStorePairClass(p, a1, c.instoffset)
			}
		}
		p.From.Class = int8(a1)
	}

	a2 := C_NONE
	if p.Reg != 0 {
		a2 = rclass(p.Reg)
	}

	a3 := C_NONE
	if p.GetFrom3() != nil {
		a3 = int(p.GetFrom3().Class)
		if a3 == 0 {
			a3 = c.aclass(p.GetFrom3())
			p.GetFrom3().Class = int8(a3)
		}
	}

	a4 := int(p.To.Class)
	if a4 == 0 {
		a4 = c.aclass(&p.To)
		if p.To.Type == obj.TYPE_MEM {
			if isMOVop(p.As) && (cmp(C_LAUTO, a4) || cmp(C_LOREG, a4)) {
				// More specific classification of large offset loads and stores.
				a4 = c.loadStoreClass(p, a4, c.instoffset)
			}
			if isLoadStorePairOp(p.As) && (cmp(C_LAUTO, a4) || cmp(C_LOREG, a4)) {
				// More specific classification of large offset loads and stores.
				a4 = c.loadStorePairClass(p, a4, c.instoffset)
			}
		}
		p.To.Class = int8(a4)
	}

	a5 := C_NONE
	if p.RegTo2 != 0 {
		a5 = rclass(p.RegTo2)
	} else if p.GetTo2() != nil {
		a5 = int(p.GetTo2().Class)
		if a5 == 0 {
			a5 = c.aclass(p.GetTo2())
			p.GetTo2().Class = int8(a5)
		}
	}

	if false {
		fmt.Printf("oplook %v %d %d %d %d %d\n", p.As, a1, a2, a3, a4, a5)
		fmt.Printf("\t\t%d %d\n", p.From.Type, p.To.Type)
	}

	ops := oprange[p.As&obj.AMask]
	c1 := &xcmp[a1]
	c2 := &xcmp[a2]
	c3 := &xcmp[a3]
	c4 := &xcmp[a4]
	c5 := &xcmp[a5]
	for i := range ops {
		op := &ops[i]
		if c1[op.a1] && c2[op.a2] && c3[op.a3] && c4[op.a4] && c5[op.a5] && p.Scond == op.scond {
			p.Optab = uint16(cap(optab) - cap(ops) + i + 1)
			return op
		}
	}

	c.ctxt.Diag("illegal combination: %v %v %v %v %v %v, %d %d", p, DRconv(a1), DRconv(a2), DRconv(a3), DRconv(a4), DRconv(a5), p.From.Type, p.To.Type)
	// Turn illegal instruction into an UNDEF, avoid crashing in asmout
	return &Optab{obj.AUNDEF, C_NONE, C_NONE, C_NONE, C_NONE, C_NONE, 90, 4, 0, 0, 0}
}

func cmp(a int, b int) bool {
	if a == b {
		return true
	}
	switch a {
	case C_RSP:
		if b == C_REG {
			return true
		}

	case C_ZREG:
		if b == C_REG {
			return true
		}

	case C_ADDCON0:
		if b == C_ZCON || b == C_ABCON0 {
			return true
		}

	case C_ADDCON:
		if b == C_ZCON || b == C_ABCON0 || b == C_ADDCON0 || b == C_ABCON || b == C_AMCON {
			return true
		}

	case C_MBCON:
		if b == C_ABCON0 {
			return true
		}

	case C_BITCON:
		if b == C_ABCON0 || b == C_ABCON || b == C_MBCON {
			return true
		}

	case C_MOVCON:
		if b == C_MBCON || b == C_ZCON || b == C_ADDCON0 || b == C_ABCON0 || b == C_AMCON {
			return true
		}

	case C_ADDCON2:
		if b == C_ZCON || b == C_ADDCON || b == C_ADDCON0 {
			return true
		}

	case C_LCON:
		if b == C_ZCON || b == C_BITCON || b == C_ADDCON || b == C_ADDCON0 || b == C_ABCON || b == C_ABCON0 || b == C_MBCON || b == C_MOVCON || b == C_ADDCON2 || b == C_AMCON {
			return true
		}

	case C_MOVCON2:
		return cmp(C_LCON, b)

	case C_VCON:
		return cmp(C_LCON, b)

	case C_LACON:
		if b == C_AACON || b == C_AACON2 {
			return true
		}

	case C_SEXT2:
		if b == C_SEXT1 {
			return true
		}

	case C_SEXT4:
		if b == C_SEXT1 || b == C_SEXT2 {
			return true
		}

	case C_SEXT8:
		if b >= C_SEXT1 && b <= C_SEXT4 {
			return true
		}

	case C_SEXT16:
		if b >= C_SEXT1 && b <= C_SEXT8 {
			return true
		}

	case C_LEXT:
		if b >= C_SEXT1 && b <= C_SEXT16 {
			return true
		}

	case C_NSAUTO_8:
		if b == C_NSAUTO_16 {
			return true
		}

	case C_NSAUTO_4:
		if b == C_NSAUTO_16 || b == C_NSAUTO_8 {
			return true
		}

	case C_NSAUTO:
		switch b {
		case C_NSAUTO_4, C_NSAUTO_8, C_NSAUTO_16:
			return true
		}

	case C_NPAUTO_16:
		switch b {
		case C_NSAUTO_16:
			return true
		}

	case C_NPAUTO:
		switch b {
		case C_NSAUTO_16, C_NSAUTO_8, C_NPAUTO_16:
			return true
		}

	case C_NQAUTO_16:
		switch b {
		case C_NSAUTO_16, C_NPAUTO_16:
			return true
		}

	case C_NAUTO4K:
		switch b {
		case C_NSAUTO_16, C_NSAUTO_8, C_NSAUTO_4, C_NSAUTO, C_NPAUTO_16,
			C_NPAUTO, C_NQAUTO_16:
			return true
		}

	case C_PSAUTO_16:
		if b == C_ZAUTO {
			return true
		}

	case C_PSAUTO_8:
		if b == C_ZAUTO || b == C_PSAUTO_16 {
			return true
		}

	case C_PSAUTO_4:
		switch b {
		case C_ZAUTO, C_PSAUTO_16, C_PSAUTO_8:
			return true
		}

	case C_PSAUTO:
		switch b {
		case C_ZAUTO, C_PSAUTO_16, C_PSAUTO_8, C_PSAUTO_4:
			return true
		}

	case C_PPAUTO_16:
		switch b {
		case C_ZAUTO, C_PSAUTO_16:
			return true
		}

	case C_PPAUTO:
		switch b {
		case C_ZAUTO, C_PSAUTO_16, C_PSAUTO_8, C_PPAUTO_16:
			return true
		}

	case C_PQAUTO_16:
		switch b {
		case C_ZAUTO, C_PSAUTO_16, C_PPAUTO_16:
			return true
		}

	case C_UAUTO4K:
		switch b {
		case C_ZAUTO, C_PSAUTO, C_PSAUTO_4, C_PSAUTO_8, C_PSAUTO_16,
			C_PPAUTO, C_PPAUTO_16, C_PQAUTO_16,
			C_UAUTO4K_2, C_UAUTO4K_4, C_UAUTO4K_8, C_UAUTO4K_16:
			return true
		}

	case C_UAUTO8K:
		switch b {
		case C_ZAUTO, C_PSAUTO, C_PSAUTO_4, C_PSAUTO_8, C_PSAUTO_16,
			C_PPAUTO, C_PPAUTO_16, C_PQAUTO_16,
			C_UAUTO4K_2, C_UAUTO4K_4, C_UAUTO4K_8, C_UAUTO4K_16,
			C_UAUTO8K_4, C_UAUTO8K_8, C_UAUTO8K_16:
			return true
		}

	case C_UAUTO16K:
		switch b {
		case C_ZAUTO, C_PSAUTO, C_PSAUTO_4, C_PSAUTO_8, C_PSAUTO_16,
			C_PPAUTO, C_PPAUTO_16, C_PQAUTO_16,
			C_UAUTO4K_4, C_UAUTO4K_8, C_UAUTO4K_16,
			C_UAUTO8K_4, C_UAUTO8K_8, C_UAUTO8K_16,
			C_UAUTO16K_8, C_UAUTO16K_16:
			return true
		}

	case C_UAUTO32K:
		switch b {
		case C_ZAUTO, C_PSAUTO, C_PSAUTO_4, C_PSAUTO_8, C_PSAUTO_16,
			C_PPAUTO, C_PPAUTO_16, C_PQAUTO_16,
			C_UAUTO4K_8, C_UAUTO4K_16,
			C_UAUTO8K_8, C_UAUTO8K_16,
			C_UAUTO16K_8, C_UAUTO16K_16,
			C_UAUTO32K_16:
			return true
		}

	case C_UAUTO64K:
		switch b {
		case C_ZAUTO, C_PSAUTO, C_PSAUTO_4, C_PSAUTO_8, C_PSAUTO_16,
			C_PPAUTO_16, C_PQAUTO_16, C_UAUTO4K_16, C_UAUTO8K_16, C_UAUTO16K_16,
			C_UAUTO32K_16:
			return true
		}

	case C_LAUTO:
		switch b {
		case C_ZAUTO, C_NSAUTO, C_NSAUTO_4, C_NSAUTO_8, C_NSAUTO_16, C_NPAUTO_16, C_NPAUTO, C_NQAUTO_16, C_NAUTO4K,
			C_PSAUTO, C_PSAUTO_4, C_PSAUTO_8, C_PSAUTO_16,
			C_PPAUTO, C_PPAUTO_16, C_PQAUTO_16,
			C_UAUTO4K, C_UAUTO4K_2, C_UAUTO4K_4, C_UAUTO4K_8, C_UAUTO4K_16,
			C_UAUTO8K, C_UAUTO8K_4, C_UAUTO8K_8, C_UAUTO8K_16,
			C_UAUTO16K, C_UAUTO16K_8, C_UAUTO16K_16,
			C_UAUTO32K, C_UAUTO32K_16,
			C_UAUTO64K:
			return true
		}

	case C_NSOREG_8:
		if b == C_NSOREG_16 {
			return true
		}

	case C_NSOREG_4:
		if b == C_NSOREG_8 || b == C_NSOREG_16 {
			return true
		}

	case C_NSOREG:
		switch b {
		case C_NSOREG_4, C_NSOREG_8, C_NSOREG_16:
			return true
		}

	case C_NPOREG_16:
		switch b {
		case C_NSOREG_16:
			return true
		}

	case C_NPOREG:
		switch b {
		case C_NSOREG_16, C_NSOREG_8, C_NPOREG_16:
			return true
		}

	case C_NQOREG_16:
		switch b {
		case C_NSOREG_16, C_NPOREG_16:
			return true
		}

	case C_NOREG4K:
		switch b {
		case C_NSOREG_16, C_NSOREG_8, C_NSOREG_4, C_NSOREG, C_NPOREG_16, C_NPOREG, C_NQOREG_16:
			return true
		}

	case C_PSOREG_16:
		if b == C_ZOREG {
			return true
		}

	case C_PSOREG_8:
		if b == C_ZOREG || b == C_PSOREG_16 {
			return true
		}

	case C_PSOREG_4:
		switch b {
		case C_ZOREG, C_PSOREG_16, C_PSOREG_8:
			return true
		}

	case C_PSOREG:
		switch b {
		case C_ZOREG, C_PSOREG_16, C_PSOREG_8, C_PSOREG_4:
			return true
		}

	case C_PPOREG_16:
		switch b {
		case C_ZOREG, C_PSOREG_16:
			return true
		}

	case C_PPOREG:
		switch b {
		case C_ZOREG, C_PSOREG_16, C_PSOREG_8, C_PPOREG_16:
			return true
		}

	case C_PQOREG_16:
		switch b {
		case C_ZOREG, C_PSOREG_16, C_PPOREG_16:
			return true
		}

	case C_UOREG4K:
		switch b {
		case C_ZOREG, C_PSOREG, C_PSOREG_4, C_PSOREG_8, C_PSOREG_16,
			C_PPOREG, C_PPOREG_16, C_PQOREG_16,
			C_UOREG4K_2, C_UOREG4K_4, C_UOREG4K_8, C_UOREG4K_16:
			return true
		}

	case C_UOREG8K:
		switch b {
		case C_ZOREG, C_PSOREG, C_PSOREG_4, C_PSOREG_8, C_PSOREG_16,
			C_PPOREG, C_PPOREG_16, C_PQOREG_16,
			C_UOREG4K_2, C_UOREG4K_4, C_UOREG4K_8, C_UOREG4K_16,
			C_UOREG8K_4, C_UOREG8K_8, C_UOREG8K_16:
			return true
		}

	case C_UOREG16K:
		switch b {
		case C_ZOREG, C_PSOREG, C_PSOREG_4, C_PSOREG_8, C_PSOREG_16,
			C_PPOREG, C_PPOREG_16, C_PQOREG_16,
			C_UOREG4K_4, C_UOREG4K_8, C_UOREG4K_16,
			C_UOREG8K_4, C_UOREG8K_8, C_UOREG8K_16,
			C_UOREG16K_8, C_UOREG16K_16:
			return true
		}

	case C_UOREG32K:
		switch b {
		case C_ZOREG, C_PSOREG, C_PSOREG_4, C_PSOREG_8, C_PSOREG_16,
			C_PPOREG, C_PPOREG_16, C_PQOREG_16,
			C_UOREG4K_8, C_UOREG4K_16,
			C_UOREG8K_8, C_UOREG8K_16,
			C_UOREG16K_8, C_UOREG16K_16,
			C_UOREG32K_16:
			return true
		}

	case C_UOREG64K:
		switch b {
		case C_ZOREG, C_PSOREG, C_PSOREG_4, C_PSOREG_8, C_PSOREG_16,
			C_PPOREG_16, C_PQOREG_16, C_UOREG4K_16, C_UOREG8K_16, C_UOREG16K_16,
			C_UOREG32K_16:
			return true
		}

	case C_LOREG:
		switch b {
		case C_ZOREG, C_NSOREG, C_NSOREG_4, C_NSOREG_8, C_NSOREG_16, C_NPOREG, C_NPOREG_16, C_NQOREG_16, C_NOREG4K,
			C_PSOREG, C_PSOREG_4, C_PSOREG_8, C_PSOREG_16,
			C_PPOREG, C_PPOREG_16, C_PQOREG_16,
			C_UOREG4K, C_UOREG4K_2, C_UOREG4K_4, C_UOREG4K_8, C_UOREG4K_16,
			C_UOREG8K, C_UOREG8K_4, C_UOREG8K_8, C_UOREG8K_16,
			C_UOREG16K, C_UOREG16K_8, C_UOREG16K_16,
			C_UOREG32K, C_UOREG32K_16,
			C_UOREG64K:
			return true
		}

	case C_LBRA:
		if b == C_SBRA {
			return true
		}
	}

	return false
}

func ocmp(p1, p2 Optab) int {
	if p1.as != p2.as {
		return int(p1.as) - int(p2.as)
	}
	if p1.a1 != p2.a1 {
		return int(p1.a1) - int(p2.a1)
	}
	if p1.a2 != p2.a2 {
		return int(p1.a2) - int(p2.a2)
	}
	if p1.a3 != p2.a3 {
		return int(p1.a3) - int(p2.a3)
	}
	if p1.a4 != p2.a4 {
		return int(p1.a4) - int(p2.a4)
	}
	if p1.scond != p2.scond {
		return int(p1.scond) - int(p2.scond)
	}
	return 0
}

func oprangeset(a obj.As, t []Optab) {
	oprange[a&obj.AMask] = t
}

func buildop(ctxt *obj.Link) {
	if oprange[AAND&obj.AMask] != nil {
		// Already initialized; stop now.
		// This happens in the cmd/asm tests,
		// each of which re-initializes the arch.
		return
	}

	for i := 0; i < C_GOK; i++ {
		for j := 0; j < C_GOK; j++ {
			if cmp(j, i) {
				xcmp[i][j] = true
			}
		}
	}

	slices.SortFunc(optab, ocmp)
	for i := 0; i < len(optab); i++ {
		as, start := optab[i].as, i
		for ; i < len(optab)-1; i++ {
			if optab[i+1].as != as {
				break
			}
		}
		t := optab[start : i+1]
		oprangeset(as, t)
		switch as {
		default:
			ctxt.Diag("unknown op in build: %v", as)
			ctxt.DiagFlush()
			log.Fatalf("bad code")

		case AADD:
			oprangeset(AADDS, t)
			oprangeset(ASUB, t)
			oprangeset(ASUBS, t)
			oprangeset(AADDW, t)
			oprangeset(AADDSW, t)
			oprangeset(ASUBW, t)
			oprangeset(ASUBSW, t)

		case AAND: /* logical immediate, logical shifted register */
			oprangeset(AANDW, t)
			oprangeset(AEOR, t)
			oprangeset(AEORW, t)
			oprangeset(AORR, t)
			oprangeset(AORRW, t)
			oprangeset(ABIC, t)
			oprangeset(ABICW, t)
			oprangeset(AEON, t)
			oprangeset(AEONW, t)
			oprangeset(AORN, t)
			oprangeset(AORNW, t)

		case AANDS: /* logical immediate, logical shifted register, set flags, cannot target RSP */
			oprangeset(AANDSW, t)
			oprangeset(ABICS, t)
			oprangeset(ABICSW, t)

		case ANEG:
			oprangeset(ANEGS, t)
			oprangeset(ANEGSW, t)
			oprangeset(ANEGW, t)

		case AADC: /* rn=Rd */
			oprangeset(AADCW, t)

			oprangeset(AADCS, t)
			oprangeset(AADCSW, t)
			oprangeset(ASBC, t)
			oprangeset(ASBCW, t)
			oprangeset(ASBCS, t)
			oprangeset(ASBCSW, t)

		case ANGC: /* rn=REGZERO */
			oprangeset(ANGCW, t)

			oprangeset(ANGCS, t)
			oprangeset(ANGCSW, t)

		case ACMP:
			oprangeset(ACMPW, t)
			oprangeset(ACMN, t)
			oprangeset(ACMNW, t)

		case ATST:
			oprangeset(ATSTW, t)

			/* register/register, and shifted */
		case AMVN:
			oprangeset(AMVNW, t)

		case AMOVK:
			oprangeset(AMOVKW, t)
			oprangeset(AMOVN, t)
			oprangeset(AMOVNW, t)
			oprangeset(AMOVZ, t)
			oprangeset(AMOVZW, t)

		case ASWPD:
			for i := range atomicLDADD {
				oprangeset(i, t)
			}
			for i := range atomicSWP {
				if i == ASWPD {
					continue
				}
				oprangeset(i, t)
			}

		case ACASPD:
			oprangeset(ACASPW, t)
		case ABEQ:
			oprangeset(ABNE, t)
			oprangeset(ABCS, t)
			oprangeset(ABHS, t)
			oprangeset(ABCC, t)
			oprangeset(ABLO, t)
			oprangeset(ABMI, t)
			oprangeset(ABPL, t)
			oprangeset(ABVS, t)
			oprangeset(ABVC, t)
			oprangeset(ABHI, t)
			oprangeset(ABLS, t)
			oprangeset(ABGE, t)
			oprangeset(ABLT, t)
			oprangeset(ABGT, t)
			oprangeset(ABLE, t)

		case ALSL:
			oprangeset(ALSLW, t)
			oprangeset(ALSR, t)
			oprangeset(ALSRW, t)
			oprangeset(AASR, t)
			oprangeset(AASRW, t)
			oprangeset(AROR, t)
			oprangeset(ARORW, t)

		case ACLS:
			oprangeset(ACLSW, t)
			oprangeset(ACLZ, t)
			oprangeset(ACLZW, t)
			oprangeset(ARBIT, t)
			oprangeset(ARBITW, t)
			oprangeset(AREV, t)
			oprangeset(AREVW, t)
			oprangeset(AREV16, t)
			oprangeset(AREV16W, t)
			oprangeset(AREV32, t)

		case ASDIV:
			oprangeset(ASDIVW, t)
			oprangeset(AUDIV, t)
			oprangeset(AUDIVW, t)
			oprangeset(ACRC32B, t)
			oprangeset(ACRC32CB, t)
			oprangeset(ACRC32CH, t)
			oprangeset(ACRC32CW, t)
			oprangeset(ACRC32CX, t)
			oprangeset(ACRC32H, t)
			oprangeset(ACRC32W, t)
			oprangeset(ACRC32X, t)

		case AMADD:
			oprangeset(AMADDW, t)
			oprangeset(AMSUB, t)
			oprangeset(AMSUBW, t)
			oprangeset(ASMADDL, t)
			oprangeset(ASMSUBL, t)
			oprangeset(AUMADDL, t)
			oprangeset(AUMSUBL, t)

		case AREM:
			oprangeset(AREMW, t)
			oprangeset(AUREM, t)
			oprangeset(AUREMW, t)

		case AMUL:
			oprangeset(AMULW, t)
			oprangeset(AMNEG, t)
			oprangeset(AMNEGW, t)
			oprangeset(ASMNEGL, t)
			oprangeset(ASMULL, t)
			oprangeset(ASMULH, t)
			oprangeset(AUMNEGL, t)
			oprangeset(AUMULH, t)
			oprangeset(AUMULL, t)

		case AMOVB:
			oprangeset(AMOVBU, t)

		case AMOVH:
			oprangeset(AMOVHU, t)

		case AMOVW:
			oprangeset(AMOVWU, t)

		case ABFM:
			oprangeset(ABFMW, t)
			oprangeset(ASBFM, t)
			oprangeset(ASBFMW, t)
			oprangeset(AUBFM, t)
			oprangeset(AUBFMW, t)

		case ABFI:
			oprangeset(ABFIW, t)
			oprangeset(ABFXIL, t)
			oprangeset(ABFXILW, t)
			oprangeset(ASBFIZ, t)
			oprangeset(ASBFIZW, t)
			oprangeset(ASBFX, t)
			oprangeset(ASBFXW, t)
			oprangeset(AUBFIZ, t)
			oprangeset(AUBFIZW, t)
			oprangeset(AUBFX, t)
			oprangeset(AUBFXW, t)

		case AEXTR:
			oprangeset(AEXTRW, t)

		case ASXTB:
			oprangeset(ASXTBW, t)
			oprangeset(ASXTH, t)
			oprangeset(ASXTHW, t)
			oprangeset(ASXTW, t)
			oprangeset(AUXTB, t)
			oprangeset(AUXTH, t)
			oprangeset(AUXTW, t)
			oprangeset(AUXTBW, t)
			oprangeset(AUXTHW, t)

		case ACCMN:
			oprangeset(ACCMNW, t)
			oprangeset(ACCMP, t)
			oprangeset(ACCMPW, t)

		case ACSEL:
			oprangeset(ACSELW, t)
			oprangeset(ACSINC, t)
			oprangeset(ACSINCW, t)
			oprangeset(ACSINV, t)
			oprangeset(ACSINVW, t)
			oprangeset(ACSNEG, t)
			oprangeset(ACSNEGW, t)

		case ACINC:
			// aliases Rm=Rn, !cond
			oprangeset(ACINCW, t)
			oprangeset(ACINV, t)
			oprangeset(ACINVW, t)
			oprangeset(ACNEG, t)
			oprangeset(ACNEGW, t)

			// aliases, Rm=Rn=REGZERO, !cond
		case ACSET:
			oprangeset(ACSETW, t)

			oprangeset(ACSETM, t)
			oprangeset(ACSETMW, t)

		case AMOVD,
			AB,
			ABL,
			AWORD,
			ADWORD,
			obj.ARET,
			obj.ATEXT:
			break

		case AFLDPQ:
			break
		case AFSTPQ:
			break
		case ALDP:
			oprangeset(AFLDPD, t)

		case ASTP:
			oprangeset(AFSTPD, t)

		case ASTPW:
			oprangeset(AFSTPS, t)

		case ALDPW:
			oprangeset(ALDPSW, t)
			oprangeset(AFLDPS, t)

		case AERET:
			oprangeset(AWFE, t)
			oprangeset(AWFI, t)
			oprangeset(AYIELD, t)
			oprangeset(ASEV, t)
			oprangeset(ASEVL, t)
			oprangeset(ANOOP, t)
			oprangeset(ADRPS, t)

		case ACBZ:
			oprangeset(ACBZW, t)
			oprangeset(ACBNZ, t)
			oprangeset(ACBNZW, t)

		case ATBZ:
			oprangeset(ATBNZ, t)

		case AADR, AADRP:
			break

		case ACLREX:
			break

		case ASVC:
			oprangeset(AHVC, t)
			oprangeset(AHLT, t)
			oprangeset(ASMC, t)
			oprangeset(ABRK, t)
			oprangeset(ADCPS1, t)
			oprangeset(ADCPS2, t)
			oprangeset(ADCPS3, t)

		case AFADDS:
			oprangeset(AFADDD, t)
			oprangeset(AFSUBS, t)
			oprangeset(AFSUBD, t)
			oprangeset(AFMULS, t)
			oprangeset(AFMULD, t)
			oprangeset(AFNMULS, t)
			oprangeset(AFNMULD, t)
			oprangeset(AFDIVS, t)
			oprangeset(AFMAXD, t)
			oprangeset(AFMAXS, t)
			oprangeset(AFMIND, t)
			oprangeset(AFMINS, t)
			oprangeset(AFMAXNMD, t)
			oprangeset(AFMAXNMS, t)
			oprangeset(AFMINNMD, t)
			oprangeset(AFMINNMS, t)
			oprangeset(AFDIVD, t)

		case AFMSUBD:
			oprangeset(AFMSUBS, t)
			oprangeset(AFMADDS, t)
			oprangeset(AFMADDD, t)
			oprangeset(AFNMSUBS, t)
			oprangeset(AFNMSUBD, t)
			oprangeset(AFNMADDS, t)
			oprangeset(AFNMADDD, t)

		case AFCVTSD:
			oprangeset(AFCVTDS, t)
			oprangeset(AFABSD, t)
			oprangeset(AFABSS, t)
			oprangeset(AFNEGD, t)
			oprangeset(AFNEGS, t)
			oprangeset(AFSQRTD, t)
			oprangeset(AFSQRTS, t)
			oprangeset(AFRINTNS, t)
			oprangeset(AFRINTND, t)
			oprangeset(AFRINTPS, t)
			oprangeset(AFRINTPD, t)
			oprangeset(AFRINTMS, t)
			oprangeset(AFRINTMD, t)
			oprangeset(AFRINTZS, t)
			oprangeset(AFRINTZD, t)
			oprangeset(AFRINTAS, t)
			oprangeset(AFRINTAD, t)
			oprangeset(AFRINTXS, t)
			oprangeset(AFRINTXD, t)
			oprangeset(AFRINTIS, t)
			oprangeset(AFRINTID, t)
			oprangeset(AFCVTDH, t)
			oprangeset(AFCVTHS, t)
			oprangeset(AFCVTHD, t)
			oprangeset(AFCVTSH, t)

		case AFCMPS:
			oprangeset(AFCMPD, t)
			oprangeset(AFCMPES, t)
			oprangeset(AFCMPED, t)

		case AFCCMPS:
			oprangeset(AFCCMPD, t)
			oprangeset(AFCCMPES, t)
			oprangeset(AFCCMPED, t)

		case AFCSELD:
			oprangeset(AFCSELS, t)

		case AFMOVQ, AFMOVD, AFMOVS,
			AVMOVQ, AVMOVD, AVMOVS:
			break

		case AFCVTZSD:
			oprangeset(AFCVTZSDW, t)
			oprangeset(AFCVTZSS, t)
			oprangeset(AFCVTZSSW, t)
			oprangeset(AFCVTZUD, t)
			oprangeset(AFCVTZUDW, t)
			oprangeset(AFCVTZUS, t)
			oprangeset(AFCVTZUSW, t)

		case ASCVTFD:
			oprangeset(ASCVTFS, t)
			oprangeset(ASCVTFWD, t)
			oprangeset(ASCVTFWS, t)
			oprangeset(AUCVTFD, t)
			oprangeset(AUCVTFS, t)
			oprangeset(AUCVTFWD, t)
			oprangeset(AUCVTFWS, t)

		case ASYS:
			oprangeset(AAT, t)
			oprangeset(AIC, t)

		case ATLBI:
			oprangeset(ADC, t)

		case ASYSL, AHINT:
			break

		case ADMB:
			oprangeset(ADSB, t)
			oprangeset(AISB, t)

		case AMRS, AMSR:
			break

		case ALDAR:
			oprangeset(ALDARW, t)
			oprangeset(ALDARB, t)
			oprangeset(ALDARH, t)
			fallthrough

		case ALDXR:
			oprangeset(ALDXRB, t)
			oprangeset(ALDXRH, t)
			oprangeset(ALDXRW, t)

		case ALDAXR:
			oprangeset(ALDAXRB, t)
			oprangeset(ALDAXRH, t)
			oprangeset(ALDAXRW, t)

		case ALDXP:
			oprangeset(ALDXPW, t)
			oprangeset(ALDAXP, t)
			oprangeset(ALDAXPW, t)

		case ASTLR:
			oprangeset(ASTLRB, t)
			oprangeset(ASTLRH, t)
			oprangeset(ASTLRW, t)

		case ASTXR:
			oprangeset(ASTXRB, t)
			oprangeset(ASTXRH, t)
			oprangeset(ASTXRW, t)

		case ASTLXR:
			oprangeset(ASTLXRB, t)
			oprangeset(ASTLXRH, t)
			oprangeset(ASTLXRW, t)

		case ASTXP:
			oprangeset(ASTLXP, t)
			oprangeset(ASTLXPW, t)
			oprangeset(ASTXPW, t)

		case AVADDP:
			oprangeset(AVAND, t)
			oprangeset(AVCMEQ, t)
			oprangeset(AVORR, t)
			oprangeset(AVEOR, t)
			oprangeset(AVBSL, t)
			oprangeset(AVBIT, t)
			oprangeset(AVCMTST, t)
			oprangeset(AVUMAX, t)
			oprangeset(AVUMIN, t)
			oprangeset(AVUZP1, t)
			oprangeset(AVUZP2, t)
			oprangeset(AVBIF, t)

		case AVADD:
			oprangeset(AVSUB, t)
			oprangeset(AVRAX1, t)

		case AAESD:
			oprangeset(AAESE, t)
			oprangeset(AAESMC, t)
			oprangeset(AAESIMC, t)
			oprangeset(ASHA1SU1, t)
			oprangeset(ASHA256SU0, t)
			oprangeset(ASHA512SU0, t)
			oprangeset(ASHA1H, t)

		case ASHA1C:
			oprangeset(ASHA1P, t)
			oprangeset(ASHA1M, t)
			oprangeset(ASHA256H, t)
			oprangeset(ASHA256H2, t)
			oprangeset(ASHA512H, t)
			oprangeset(ASHA512H2, t)

		case ASHA1SU0:
			oprangeset(ASHA256SU1, t)
			oprangeset(ASHA512SU1, t)

		case AVADDV:
			oprangeset(AVUADDLV, t)

		case AVFMLA:
			oprangeset(AVFMLS, t)

		case AVPMULL:
			oprangeset(AVPMULL2, t)

		case AVUSHR:
			oprangeset(AVSHL, t)
			oprangeset(AVSRI, t)
			oprangeset(AVSLI, t)
			oprangeset(AVUSRA, t)

		case AVREV32:
			oprangeset(AVCNT, t)
			oprangeset(AVRBIT, t)
			oprangeset(AVREV64, t)
			oprangeset(AVREV16, t)

		case AVZIP1:
			oprangeset(AVZIP2, t)
			oprangeset(AVTRN1, t)
			oprangeset(AVTRN2, t)

		case AVUXTL:
			oprangeset(AVUXTL2, t)

		case AVUSHLL:
			oprangeset(AVUSHLL2, t)

		case AVLD1R:
			oprangeset(AVLD2, t)
			oprangeset(AVLD2R, t)
			oprangeset(AVLD3, t)
			oprangeset(AVLD3R, t)
			oprangeset(AVLD4, t)
			oprangeset(AVLD4R, t)

		case AVEOR3:
			oprangeset(AVBCAX, t)

		case AVUADDW:
			oprangeset(AVUADDW2, t)

		case AVTBL:
			oprangeset(AVTBX, t)

		case AVCNT,
			AVMOV,
			AVLD1,
			AVST1,
			AVST2,
			AVST3,
			AVST4,
			AVDUP,
			AVMOVI,
			APRFM,
			AVEXT,
			AVXAR:
			break

		case obj.ANOP,
			obj.AUNDEF,
			obj.AFUNCDATA,
			obj.APCALIGN,
			obj.APCALIGNMAX,
			obj.APCDATA,
			obj.ADUFFZERO,
			obj.ADUFFCOPY:
			break
		}
	}
}

// chipfloat7() checks if the immediate constants available in  FMOVS/FMOVD instructions.
// For details of the range of constants available, see
// http://infocenter.arm.com/help/topic/com.arm.doc.dui0473m/dom1359731199385.html.
func (c *ctxt7) chipfloat7(e float64) int {
	ei := math.Float64bits(e)
	l := uint32(int32(ei))
	h := uint32(int32(ei >> 32))

	if l != 0 || h&0xffff != 0 {
		return -1
	}
	h1 := h & 0x7fc00000
	if h1 != 0x40000000 && h1 != 0x3fc00000 {
		return -1
	}
	n := 0

	// sign bit (a)
	if h&0x80000000 != 0 {
		n |= 1 << 7
	}

	// exp sign bit (b)
	if h1 == 0x3fc00000 {
		n |= 1 << 6
	}

	// rest of exp and mantissa (cd-efgh)
	n |= int((h >> 16) & 0x3f)

	//print("match %.8lux %.8lux %d\n", l, h, n);
	return n
}

/* form offset parameter to SYS; special register number */
func SYSARG5(op0 int, op1 int, Cn int, Cm int, op2 int) int {
	return op0<<19 | op1<<16 | Cn<<12 | Cm<<8 | op2<<5
}

func SYSARG4(op1 int, Cn int, Cm int, op2 int) int {
	return SYSARG5(0, op1, Cn, Cm, op2)
}

// checkUnpredictable checks if the source and transfer registers are the same register.
// ARM64 manual says it is "constrained unpredictable" if the src and dst registers of STP/LDP are same.
func (c *ctxt7) checkUnpredictable(p *obj.Prog, isload bool, wback bool, rn int16, rt1 int16, rt2 int16) {
	if wback && rn != REGSP && (rn == rt1 || rn == rt2) {
		c.ctxt.Diag("constrained unpredictable behavior: %v", p)
	}
	if isload && rt1 == rt2 {
		c.ctxt.Diag("constrained unpredictable behavior: %v", p)
	}
}

/* checkindex checks if index >= 0 && index <= maxindex */
func (c *ctxt7) checkindex(p *obj.Prog, index, maxindex int) {
	if index < 0 || index > maxindex {
		c.ctxt.Diag("register element index out of range 0 to %d: %v", maxindex, p)
	}
}

/* checkoffset checks whether the immediate offset is valid for VLD[1-4].P and VST[1-4].P */
func (c *ctxt7) checkoffset(p *obj.Prog, as obj.As) {
	var offset, list, n, expect int64
	switch as {
	case AVLD1, AVLD2, AVLD3, AVLD4, AVLD1R, AVLD2R, AVLD3R, AVLD4R:
		offset = p.From.Offset
		list = p.To.Offset
	case AVST1, AVST2, AVST3, AVST4:
		offset = p.To.Offset
		list = p.From.Offset
	default:
		c.ctxt.Diag("invalid operation on op %v", p.As)
	}
	opcode := (list >> 12) & 15
	q := (list >> 30) & 1
	size := (list >> 10) & 3
	if offset == 0 {
		return
	}
	switch opcode {
	case 0x7:
		n = 1 // one register
	case 0xa:
		n = 2 // two registers
	case 0x6:
		n = 3 // three registers
	case 0x2:
		n = 4 // four registers
	default:
		c.ctxt.Diag("invalid register numbers in ARM64 register list: %v", p)
	}

	switch as {
	case AVLD1R, AVLD2R, AVLD3R, AVLD4R:
		if offset != n*(1<<uint(size)) {
			c.ctxt.Diag("invalid post-increment offset: %v", p)
		}
	default:
		if !(q == 0 && offset == n*8) && !(q == 1 && offset == n*16) {
			c.ctxt.Diag("invalid post-increment offset: %v", p)
		}
	}

	switch as {
	case AVLD1, AVST1:
		return
	case AVLD1R:
		expect = 1
	case AVLD2, AVST2, AVLD2R:
		expect = 2
	case AVLD3, AVST3, AVLD3R:
		expect = 3
	case AVLD4, AVST4, AVLD4R:
		expect = 4
	}

	if expect != n {
		c.ctxt.Diag("expected %d registers, got %d: %v.", expect, n, p)
	}
}

/* checkShiftAmount checks whether the index shift amount is valid */
/* for load with register offset instructions */
func (c *ctxt7) checkShiftAmount(p *obj.Prog, a *obj.Addr) {
	var amount int16
	amount = (a.Index >> 5) & 7
	switch p.As {
	case AMOVB, AMOVBU:
		if amount != 0 {
			c.ctxt.Diag("invalid index shift amount: %v", p)
		}
	case AMOVH, AMOVHU:
		if amount != 1 && amount != 0 {
			c.ctxt.Diag("invalid index shift amount: %v", p)
		}
	case AMOVW, AMOVWU, AFMOVS:
		if amount != 2 && amount != 0 {
			c.ctxt.Diag("invalid index shift amount: %v", p)
		}
	case AMOVD, AFMOVD:
		if amount != 3 && amount != 0 {
			c.ctxt.Diag("invalid index shift amount: %v", p)
		}
	default:
		panic("invalid operation")
	}
}

func (c *ctxt7) asmout(p *obj.Prog, out []uint32) (count int) {
	o := c.oplook(p)

	var os [5]uint32
	o1 := uint32(0)
	o2 := uint32(0)
	o3 := uint32(0)
	o4 := uint32(0)
	o5 := uint32(0)
	if false { /*debug['P']*/
		fmt.Printf("%x: %v\ttype %d\n", uint32(p.Pc), p, o.type_)
	}
	switch o.type_ {
	default:
		c.ctxt.Diag("%v: unknown asm %d", p, o.type_)

	case 0: /* pseudo ops */
		break

	case 1: /* op Rm,[Rn],Rd; default Rn=Rd -> op Rm<<0,[Rn,]Rd (shifted register) */
		o1 = c.oprrr(p, p.As)

		rf := int(p.From.Reg)
		rt := int(p.To.Reg)
		r := int(p.Reg)
		if p.To.Type == obj.TYPE_NONE {
			rt = REGZERO
		}
		if r == obj.REG_NONE {
			r = rt
		}
		o1 |= (uint32(rf&31) << 16) | (uint32(r&31) << 5) | uint32(rt&31)

	case 2: /* add/sub $(uimm12|uimm24)[,R],R; cmp $(uimm12|uimm24),R */
		if p.To.Reg == REG_RSP && isADDSop(p.As) {
			c.ctxt.Diag("illegal destination register: %v\n", p)
		}
		o1 = c.opirr(p, p.As)

		rt, r := p.To.Reg, p.Reg
		if p.To.Type == obj.TYPE_NONE {
			if (o1 & Sbit) == 0 {
				c.ctxt.Diag("ineffective ZR destination\n%v", p)
			}
			rt = REGZERO
		}
		if r == obj.REG_NONE {
			r = rt
		}
		v := c.regoff(&p.From)
		o1 = c.oaddi(p, p.As, v, rt, r)

	case 3: /* op R<<n[,R],R (shifted register) */
		o1 = c.oprrr(p, p.As)

		amount := (p.From.Offset >> 10) & 63
		is64bit := o1 & (1 << 31)
		if is64bit == 0 && amount >= 32 {
			c.ctxt.Diag("shift amount out of range 0 to 31: %v", p)
		}
		shift := (p.From.Offset >> 22) & 3
		if (shift > 2 || shift < 0) && (isADDop(p.As) || isADDWop(p.As) || isNEGop(p.As)) {
			c.ctxt.Diag("unsupported shift operator: %v", p)
		}
		o1 |= uint32(p.From.Offset) /* includes reg, op, etc */
		rt := int(p.To.Reg)
		if p.To.Type == obj.TYPE_NONE {
			rt = REGZERO
		}
		r := int(p.Reg)
		if p.As == AMVN || p.As == AMVNW || isNEGop(p.As) {
			r = REGZERO
		} else if r == obj.REG_NONE {
			r = rt
		}
		o1 |= (uint32(r&31) << 5) | uint32(rt&31)

	case 4: /* mov $addcon, R; mov $recon, R; mov $racon, R; mov $addcon2, R */
		rt, r := p.To.Reg, o.param
		if r == obj.REG_NONE {
			r = REGZERO
		} else if r == REGFROM {
			r = p.From.Reg
		}
		if r == obj.REG_NONE {
			r = REGSP
		}

		v := c.regoff(&p.From)
		a := AADD
		if v < 0 {
			a = ASUB
			v = -v
		}

		if o.size(c.ctxt, p) == 8 {
			// NOTE: this case does not use REGTMP. If it ever does,
			// remove the NOTUSETMP flag in optab.
			o1 = c.oaddi(p, a, v&0xfff000, rt, r)
			o2 = c.oaddi(p, a, v&0x000fff, rt, rt)
			break
		}

		o1 = c.oaddi(p, a, v, rt, r)

	case 5: /* b s; bl s */
		o1 = c.opbra(p, p.As)

		if p.To.Sym == nil {
			o1 |= uint32(c.brdist(p, 0, 26, 2))
			break
		}

		c.cursym.AddRel(c.ctxt, obj.Reloc{
			Type: objabi.R_CALLARM64,
			Off:  int32(c.pc),
			Siz:  4,
			Sym:  p.To.Sym,
			Add:  p.To.Offset,
		})

	case 6: /* b ,O(R); bl ,O(R) */
		o1 = c.opbrr(p, p.As)
		o1 |= uint32(p.To.Reg&31) << 5
		if p.As == obj.ACALL {
			c.cursym.AddRel(c.ctxt, obj.Reloc{
				Type: objabi.R_CALLIND,
				Off:  int32(c.pc),
			})
		}

	case 7: /* beq s */
		o1 = c.opbra(p, p.As)

		o1 |= uint32(c.brdist(p, 0, 19, 2) << 5)

	case 8: /* lsl $c,[R],R -> ubfm $(W-1)-c,$(-c MOD (W-1)),Rn,Rd */
		rt, rf := p.To.Reg, p.Reg
		if rf == obj.REG_NONE {
			rf = rt
		}
		v := p.From.Offset
		switch p.As {
		case AASR:
			o1 = c.opbfm(p, ASBFM, v, 63, rf, rt)

		case AASRW:
			o1 = c.opbfm(p, ASBFMW, v, 31, rf, rt)

		case ALSL:
			o1 = c.opbfm(p, AUBFM, (64-v)&63, 63-v, rf, rt)

		case ALSLW:
			o1 = c.opbfm(p, AUBFMW, (32-v)&31, 31-v, rf, rt)

		case ALSR:
			o1 = c.opbfm(p, AUBFM, v, 63, rf, rt)

		case ALSRW:
			o1 = c.opbfm(p, AUBFMW, v, 31, rf, rt)

		case AROR:
			o1 = c.opextr(p, AEXTR, v, rf, rf, rt)

		case ARORW:
			o1 = c.opextr(p, AEXTRW, v, rf, rf, rt)

		default:
			c.ctxt.Diag("bad shift $con\n%v", p)
			break
		}

	case 9: /* lsl Rm,[Rn],Rd -> lslv Rm, Rn, Rd */
		o1 = c.oprrr(p, p.As)

		r := int(p.Reg)
		if r == obj.REG_NONE {
			r = int(p.To.Reg)
		}
		o1 |= (uint32(p.From.Reg&31) << 16) | (uint32(r&31) << 5) | uint32(p.To.Reg&31)

	case 10: /* brk/hvc/.../svc [$con] */
		o1 = c.opimm(p, p.As)

		if p.From.Type != obj.TYPE_NONE {
			o1 |= uint32((p.From.Offset & 0xffff) << 5)
		}

	case 11: /* dword */
		c.aclass(&p.To)

		o1 = uint32(c.instoffset)
		o2 = uint32(c.instoffset >> 32)
		if p.To.Sym != nil {
			c.cursym.AddRel(c.ctxt, obj.Reloc{
				Type: objabi.R_ADDR,
				Off:  int32(c.pc),
				Siz:  8,
				Sym:  p.To.Sym,
				Add:  p.To.Offset,
			})
			o2 = 0
			o1 = o2
		}

	case 12: /* movT $vcon, reg */
		// NOTE: this case does not use REGTMP. If it ever does,
		// remove the NOTUSETMP flag in optab.
		num := c.omovlconst(p.As, p, &p.From, int(p.To.Reg), os[:])
		if num == 0 {
			c.ctxt.Diag("invalid constant: %v", p)
		}
		o1 = os[0]
		o2 = os[1]
		o3 = os[2]
		o4 = os[3]

	case 13: /* addop $vcon, [R], R (64 bit literal); cmp $lcon,R -> addop $lcon,R, ZR */
		if p.Reg == REGTMP {
			c.ctxt.Diag("cannot use REGTMP as source: %v\n", p)
		}
		if p.To.Reg == REG_RSP && isADDSop(p.As) {
			c.ctxt.Diag("illegal destination register: %v\n", p)
		}
		o := uint32(0)
		num := uint8(0)
		cls := int(p.From.Class)
		if isADDWop(p.As) {
			if !cmp(C_LCON, cls) {
				c.ctxt.Diag("illegal combination: %v", p)
			}
			num = c.omovlconst(AMOVW, p, &p.From, REGTMP, os[:])
		} else {
			num = c.omovlconst(AMOVD, p, &p.From, REGTMP, os[:])
		}
		if num == 0 {
			c.ctxt.Diag("invalid constant: %v", p)
		}

		rt, r, rf := p.To.Reg, p.Reg, int16(REGTMP)
		if p.To.Type == obj.TYPE_NONE {
			rt = REGZERO
		}
		if r == obj.REG_NONE {
			r = rt
		}
		if p.To.Type != obj.TYPE_NONE && (rt == REGSP || r == REGSP) {
			o = c.opxrrr(p, p.As, rt, r, rf, false)
			o |= LSL0_64
		} else {
			o = c.oprrr(p, p.As)
			o |= uint32(rf&31) << 16 /* shift is 0 */
			o |= uint32(r&31) << 5
			o |= uint32(rt & 31)
		}

		os[num] = o
		o1 = os[0]
		o2 = os[1]
		o3 = os[2]
		o4 = os[3]
		o5 = os[4]

	case 14: /* word */
		if c.aclass(&p.To) == C_ADDR {
			c.ctxt.Diag("address constant needs DWORD\n%v", p)
		}
		o1 = uint32(c.instoffset)
		if p.To.Sym != nil {
			// This case happens with words generated
			// in the PC stream as part of the literal pool.
			c.cursym.AddRel(c.ctxt, obj.Reloc{
				Type: objabi.R_ADDR,
				Off:  int32(c.pc),
				Siz:  4,
				Sym:  p.To.Sym,
				Add:  p.To.Offset,
			})
			o1 = 0
		}

	case 15: /* mul/mneg/umulh/umull r,[r,]r; madd/msub/fmadd/fmsub/fnmadd/fnmsub Rm,Ra,Rn,Rd */
		o1 = c.oprrr(p, p.As)

		rf := int(p.From.Reg)
		rt := int(p.To.Reg)
		var r int
		var ra int
		if p.From3Type() == obj.TYPE_REG {
			r = int(p.GetFrom3().Reg)
			ra = int(p.Reg)
			if ra == obj.REG_NONE {
				ra = REGZERO
			}
		} else {
			r = int(p.Reg)
			if r == obj.REG_NONE {
				r = rt
			}
			ra = REGZERO
		}

		o1 |= (uint32(rf&31) << 16) | (uint32(ra&31) << 10) | (uint32(r&31) << 5) | uint32(rt&31)

	case 16: /* XremY R[,R],R -> XdivY; XmsubY */
		o1 = c.oprrr(p, p.As)

		rf := int(p.From.Reg)
		rt := int(p.To.Reg)
		r := int(p.Reg)
		if r == obj.REG_NONE {
			r = rt
		}
		o1 |= (uint32(rf&31) << 16) | (uint32(r&31) << 5) | REGTMP&31
		o2 = c.oprrr(p, AMSUBW)
		o2 |= o1 & (1 << 31) /* same size */
		o2 |= (uint32(rf&31) << 16) | (uint32(r&31) << 10) | (REGTMP & 31 << 5) | uint32(rt&31)

	case 17: /* op Rm,[Rn],Rd; default Rn=ZR */
		o1 = c.oprrr(p, p.As)

		rf := int(p.From.Reg)
		rt := int(p.To.Reg)
		r := int(p.Reg)
		if p.To.Type == obj.TYPE_NONE {
			rt = REGZERO
		}
		if r == obj.REG_NONE {
			r = REGZERO
		}
		o1 |= (uint32(rf&31) << 16) | (uint32(r&31) << 5) | uint32(rt&31)

	case 18: /* csel cond,Rn,Rm,Rd; cinc/cinv/cneg cond,Rn,Rd; cset cond,Rd */
		o1 = c.oprrr(p, p.As)

		cond := SpecialOperand(p.From.Offset)
		if cond < SPOP_EQ || cond > SPOP_NV || (cond == SPOP_AL || cond == SPOP_NV) && p.From3Type() == obj.TYPE_NONE {
			c.ctxt.Diag("invalid condition: %v", p)
		} else {
			cond -= SPOP_EQ
		}

		r := int(p.Reg)
		var rf int = r
		if p.From3Type() == obj.TYPE_NONE {
			/* CINC/CINV/CNEG or CSET/CSETM*/
			if r == obj.REG_NONE {
				/* CSET/CSETM */
				rf = REGZERO
				r = rf
			}
			cond ^= 1
		} else {
			rf = int(p.GetFrom3().Reg) /* CSEL */
		}

		rt := int(p.To.Reg)
		o1 |= (uint32(rf&31) << 16) | (uint32(cond&15) << 12) | (uint32(r&31) << 5) | uint32(rt&31)

	case 19: /* CCMN cond, (Rm|uimm5),Rn, uimm4 -> ccmn Rn,Rm,uimm4,cond */
		nzcv := int(p.To.Offset)

		cond := SpecialOperand(p.From.Offset)
		if cond < SPOP_EQ || cond > SPOP_NV {
			c.ctxt.Diag("invalid condition\n%v", p)
		} else {
			cond -= SPOP_EQ
		}
		var rf int
		if p.GetFrom3().Type == obj.TYPE_REG {
			o1 = c.oprrr(p, p.As)
			rf = int(p.GetFrom3().Reg) /* Rm */
		} else {
			o1 = c.opirr(p, p.As)
			rf = int(p.GetFrom3().Offset & 0x1F)
		}

		o1 |= (uint32(rf&31) << 16) | (uint32(cond&15) << 12) | (uint32(p.Reg&31) << 5) | uint32(nzcv)

	case 20: /* movT R,O(R) -> strT */
		v := c.regoff(&p.To)
		sz := int32(1 << uint(movesize(p.As)))

		rt, rf := p.To.Reg, p.From.Reg
		if rt == obj.REG_NONE {
			rt = o.param
		}
		if v < 0 || v%sz != 0 { /* unscaled 9-bit signed */
			o1 = c.olsr9s(p, c.opstr(p, p.As), v, rt, rf)
		} else {
			v = int32(c.offsetshift(p, int64(v), int(o.a4)))
			o1 = c.olsr12u(p, c.opstr(p, p.As), v, rt, rf)
		}

	case 21: /* movT O(R),R -> ldrT */
		v := c.regoff(&p.From)
		sz := int32(1 << uint(movesize(p.As)))

		rt, rf := p.To.Reg, p.From.Reg
		if rf == obj.REG_NONE {
			rf = o.param
		}
		if v < 0 || v%sz != 0 { /* unscaled 9-bit signed */
			o1 = c.olsr9s(p, c.opldr(p, p.As), v, rf, rt)
		} else {
			v = int32(c.offsetshift(p, int64(v), int(o.a1)))
			o1 = c.olsr12u(p, c.opldr(p, p.As), v, rf, rt)
		}

	case 22: /* movT (R)O!,R; movT O(R)!, R -> ldrT */
		if p.From.Reg != REGSP && p.From.Reg == p.To.Reg {
			c.ctxt.Diag("constrained unpredictable behavior: %v", p)
		}

		v := int32(p.From.Offset)

		if v < -256 || v > 255 {
			c.ctxt.Diag("offset out of range [-256,255]: %v", p)
		}
		o1 = c.opldr(p, p.As)
		if o.scond == C_XPOST {
			o1 |= 1 << 10
		} else {
			o1 |= 3 << 10
		}
		o1 |= ((uint32(v) & 0x1FF) << 12) | (uint32(p.From.Reg&31) << 5) | uint32(p.To.Reg&31)

	case 23: /* movT R,(R)O!; movT O(R)!, R -> strT */
		if p.To.Reg != REGSP && p.From.Reg == p.To.Reg {
			c.ctxt.Diag("constrained unpredictable behavior: %v", p)
		}

		v := int32(p.To.Offset)

		if v < -256 || v > 255 {
			c.ctxt.Diag("offset out of range [-256,255]: %v", p)
		}
		o1 = c.opstr(p, p.As)
		if o.scond == C_XPOST {
			o1 |= 1 << 10
		} else {
			o1 |= 3 << 10
		}
		o1 |= ((uint32(v) & 0x1FF) << 12) | (uint32(p.To.Reg&31) << 5) | uint32(p.From.Reg&31)

	case 24: /* mov/mvn Rs,Rd -> add $0,Rs,Rd or orr Rs,ZR,Rd */
		rf := int(p.From.Reg)
		rt := int(p.To.Reg)
		if rf == REGSP || rt == REGSP {
			if p.As == AMVN || p.As == AMVNW {
				c.ctxt.Diag("illegal SP reference\n%v", p)
			}
			o1 = c.opirr(p, p.As)
			o1 |= (uint32(rf&31) << 5) | uint32(rt&31)
		} else {
			o1 = c.oprrr(p, p.As)
			o1 |= (uint32(rf&31) << 16) | (REGZERO & 31 << 5) | uint32(rt&31)
		}

	case 25: /* negX Rs, Rd -> subX Rs<<0, ZR, Rd */
		o1 = c.oprrr(p, p.As)

		rf := int(p.From.Reg)
		if rf == C_NONE {
			rf = int(p.To.Reg)
		}
		rt := int(p.To.Reg)
		o1 |= (uint32(rf&31) << 16) | (REGZERO & 31 << 5) | uint32(rt&31)

	case 26: /* op Vn, Vd; op Vn.<T>, Vd.<T> */
		o1 = c.oprrr(p, p.As)
		cf := c.aclass(&p.From)
		af := (p.From.Reg >> 5) & 15
		at := (p.To.Reg >> 5) & 15
		var sz int16
		switch p.As {
		case AAESD, AAESE, AAESIMC, AAESMC:
			sz = ARNG_16B
		case ASHA1SU1, ASHA256SU0:
			sz = ARNG_4S
		case ASHA512SU0:
			sz = ARNG_2D
		}

		if cf == C_ARNG {
			if p.As == ASHA1H {
				c.ctxt.Diag("invalid operands: %v", p)
			} else {
				if af != sz || af != at {
					c.ctxt.Diag("invalid arrangement: %v", p)
				}
			}
		}
		o1 |= uint32(p.From.Reg&31)<<5 | uint32(p.To.Reg&31)

	case 27: /* op Rm<<n[,Rn],Rd (extended register) */
		if p.To.Reg == REG_RSP && isADDSop(p.As) {
			c.ctxt.Diag("illegal destination register: %v\n", p)
		}
		rt, r, rf := p.To.Reg, p.Reg, p.From.Reg
		if p.To.Type == obj.TYPE_NONE {
			rt = REGZERO
		}
		if r == obj.REG_NONE {
			r = rt
		}
		if (p.From.Reg-obj.RBaseARM64)&REG_EXT != 0 ||
			(p.From.Reg >= REG_LSL && p.From.Reg < REG_ARNG) {
			amount := (p.From.Reg >> 5) & 7
			if amount > 4 {
				c.ctxt.Diag("shift amount out of range 0 to 4: %v", p)
			}
			o1 = c.opxrrr(p, p.As, rt, r, obj.REG_NONE, true)
			o1 |= c.encRegShiftOrExt(p, &p.From, p.From.Reg) /* includes reg, op, etc */
		} else {
			o1 = c.opxrrr(p, p.As, rt, r, rf, false)
		}

	case 28: /* logop $vcon, [R], R (64 bit literal) */
		if p.Reg == REGTMP {
			c.ctxt.Diag("cannot use REGTMP as source: %v\n", p)
		}
		o := uint32(0)
		num := uint8(0)
		cls := int(p.From.Class)
		if isANDWop(p.As) {
			if !cmp(C_LCON, cls) {
				c.ctxt.Diag("illegal combination: %v", p)
			}
			num = c.omovlconst(AMOVW, p, &p.From, REGTMP, os[:])
		} else {
			num = c.omovlconst(AMOVD, p, &p.From, REGTMP, os[:])
		}

		if num == 0 {
			c.ctxt.Diag("invalid constant: %v", p)
		}
		rt := int(p.To.Reg)
		if p.To.Type == obj.TYPE_NONE {
			rt = REGZERO
		}
		r := int(p.Reg)
		if r == obj.REG_NONE {
			r = rt
		}
		o = c.oprrr(p, p.As)
		o |= REGTMP & 31 << 16 /* shift is 0 */
		o |= uint32(r&31) << 5
		o |= uint32(rt & 31)

		os[num] = o
		o1 = os[0]
		o2 = os[1]
		o3 = os[2]
		o4 = os[3]
		o5 = os[4]

	case 29: /* op Rn, Rd */
		fc := c.aclass(&p.From)
		tc := c.aclass(&p.To)
		if (p.As == AFMOVD || p.As == AFMOVS) && (fc == C_REG || fc == C_ZREG || tc == C_REG || tc == C_ZREG) {
			// FMOV Rx, Fy or FMOV Fy, Rx
			o1 = FPCVTI(0, 0, 0, 0, 6)
			if p.As == AFMOVD {
				o1 |= 1<<31 | 1<<22 // 64-bit
			}
			if fc == C_REG || fc == C_ZREG {
				o1 |= 1 << 16 // FMOV Rx, Fy
			}
		} else {
			o1 = c.oprrr(p, p.As)
		}
		o1 |= uint32(p.From.Reg&31)<<5 | uint32(p.To.Reg&31)

	case 30: /* movT R,L(R) -> strT */
		// If offset L fits in a 12 bit unsigned immediate:
		//	add $L, R, Rtmp  or  sub $L, R, Rtmp
		//	str R, (Rtmp)
		// Otherwise, if offset L can be split into hi+lo, and both fit into instructions:
		//	add $hi, R, Rtmp
		//	str R, lo(Rtmp)
		// Otherwise, use constant pool:
		//	mov $L, Rtmp (from constant pool)
		//	str R, (R+Rtmp)
		s := movesize(o.as)
		if s < 0 {
			c.ctxt.Diag("unexpected long move, op %v tab %v\n%v", p.As, o.as, p)
		}

		r := p.To.Reg
		if r == obj.REG_NONE {
			r = o.param
		}

		v := c.regoff(&p.To)
		if v >= -256 && v <= 256 {
			c.ctxt.Diag("%v: bad type for offset %d (should be 9 bit signed immediate store)", p, v)
		}
		if v >= 0 && v <= 4095 && v&((1<<int32(s))-1) == 0 {
			c.ctxt.Diag("%v: bad type for offset %d (should be 12 bit unsigned immediate store)", p, v)
		}

		// Handle smaller unaligned and negative offsets via addition or subtraction.
		if v >= -4095 && v <= 4095 {
			o1 = c.oaddi12(p, v, REGTMP, int16(r))
			o2 = c.olsr12u(p, c.opstr(p, p.As), 0, REGTMP, p.From.Reg)
			break
		}

		hi, lo, err := splitImm24uScaled(v, s)
		if err != nil {
			goto storeusepool
		}
		if p.Pool != nil {
			c.ctxt.Diag("%v: unused constant in pool (%v)\n", p, v)
		}
		o1 = c.oaddi(p, AADD, hi, REGTMP, r)
		o2 = c.olsr12u(p, c.opstr(p, p.As), lo, REGTMP, p.From.Reg)
		break

	storeusepool:
		if p.Pool == nil {
			c.ctxt.Diag("%v: constant is not in pool", p)
		}
		if r == REGTMP || p.From.Reg == REGTMP {
			c.ctxt.Diag("REGTMP used in large offset store: %v", p)
		}
		o1 = c.omovlit(AMOVD, p, &p.To, REGTMP)
		o2 = c.olsxrr(p, int32(c.opstrr(p, p.As, false)), int(p.From.Reg), int(r), REGTMP)

	case 31: /* movT L(R), R -> ldrT */
		// If offset L fits in a 12 bit unsigned immediate:
		//	add $L, R, Rtmp  or  sub $L, R, Rtmp
		//	ldr R, (Rtmp)
		// Otherwise, if offset L can be split into hi+lo, and both fit into instructions:
		//	add $hi, R, Rtmp
		//	ldr lo(Rtmp), R
		// Otherwise, use constant pool:
		//	mov $L, Rtmp (from constant pool)
		//	ldr (R+Rtmp), R
		s := movesize(o.as)
		if s < 0 {
			c.ctxt.Diag("unexpected long move, op %v tab %v\n%v", p.As, o.as, p)
		}

		r := p.From.Reg
		if r == obj.REG_NONE {
			r = o.param
		}

		v := c.regoff(&p.From)
		if v >= -256 && v <= 256 {
			c.ctxt.Diag("%v: bad type for offset %d (should be 9 bit signed immediate load)", p, v)
		}
		if v >= 0 && v <= 4095 && v&((1<<int32(s))-1) == 0 {
			c.ctxt.Diag("%v: bad type for offset %d (should be 12 bit unsigned immediate load)", p, v)
		}

		// Handle smaller unaligned and negative offsets via addition or subtraction.
		if v >= -4095 && v <= 4095 {
			o1 = c.oaddi12(p, v, REGTMP, int16(r))
			o2 = c.olsr12u(p, c.opldr(p, p.As), 0, REGTMP, p.To.Reg)
			break
		}

		hi, lo, err := splitImm24uScaled(v, s)
		if err != nil {
			goto loadusepool
		}
		if p.Pool != nil {
			c.ctxt.Diag("%v: unused constant in pool (%v)\n", p, v)
		}
		o1 = c.oaddi(p, AADD, hi, REGTMP, r)
		o2 = c.olsr12u(p, c.opldr(p, p.As), lo, REGTMP, p.To.Reg)
		break

	loadusepool:
		if p.Pool == nil {
			c.ctxt.Diag("%v: constant is not in pool", p)
		}
		if r == REGTMP || p.From.Reg == REGTMP {
			c.ctxt.Diag("REGTMP used in large offset load: %v", p)
		}
		o1 = c.omovlit(AMOVD, p, &p.From, REGTMP)
		o2 = c.olsxrr(p, int32(c.opldrr(p, p.As, false)), int(p.To.Reg), int(r), REGTMP)

	case 32: /* mov $con, R -> movz/movn */
		o1 = c.omovconst(p.As, p, &p.From, int(p.To.Reg))

	case 33: /* movk $uimm16 << pos */
		o1 = c.opirr(p, p.As)

		d := p.From.Offset
		if d == 0 {
			c.ctxt.Diag("zero shifts cannot be handled correctly: %v", p)
		}
		s := movcon(d)
		if s < 0 || s >= 4 {
			c.ctxt.Diag("bad constant for MOVK: %#x\n%v", uint64(d), p)
		}
		if (o1&S64) == 0 && s >= 2 {
			c.ctxt.Diag("illegal bit position\n%v", p)
		}
		if ((uint64(d) >> uint(s*16)) >> 16) != 0 {
			c.ctxt.Diag("requires uimm16\n%v", p)
		}
		rt := int(p.To.Reg)

		o1 |= uint32((((d >> uint(s*16)) & 0xFFFF) << 5) | int64((uint32(s)&3)<<21) | int64(rt&31))

	case 34: /* mov $lacon,R */
		o1 = c.omovlit(AMOVD, p, &p.From, REGTMP)
		rt, r, rf := p.To.Reg, p.From.Reg, int16(REGTMP)
		if r == obj.REG_NONE {
			r = o.param
		}
		o2 = c.opxrrr(p, AADD, rt, r, rf, false)
		o2 |= LSL0_64

	case 35: /* mov SPR,R -> mrs */
		o1 = c.oprrr(p, AMRS)

		// SysRegEnc function returns the system register encoding and accessFlags.
		_, v, accessFlags := SysRegEnc(p.From.Reg)
		if v == 0 {
			c.ctxt.Diag("illegal system register:\n%v", p)
		}
		if (o1 & (v &^ (3 << 19))) != 0 {
			c.ctxt.Diag("MRS register value overlap\n%v", p)
		}
		if accessFlags&SR_READ == 0 {
			c.ctxt.Diag("system register is not readable: %v", p)
		}

		o1 |= v
		o1 |= uint32(p.To.Reg & 31)

	case 36: /* mov R,SPR */
		o1 = c.oprrr(p, AMSR)

		// SysRegEnc function returns the system register encoding and accessFlags.
		_, v, accessFlags := SysRegEnc(p.To.Reg)
		if v == 0 {
			c.ctxt.Diag("illegal system register:\n%v", p)
		}
		if (o1 & (v &^ (3 << 19))) != 0 {
			c.ctxt.Diag("MSR register value overlap\n%v", p)
		}
		if accessFlags&SR_WRITE == 0 {
			c.ctxt.Diag("system register is not writable: %v", p)
		}

		o1 |= v
		o1 |= uint32(p.From.Reg & 31)

	case 37: /* mov $con,PSTATEfield -> MSR [immediate] */
		if (uint64(p.From.Offset) &^ uint64(0xF)) != 0 {
			c.ctxt.Diag("illegal immediate for PSTATE field\n%v", p)
		}
		o1 = c.opirr(p, AMSR)
		o1 |= uint32((p.From.Offset & 0xF) << 8) /* Crm */
		v := uint32(0)
		// PSTATEfield can be special registers and special operands.
		if p.To.Type == obj.TYPE_REG && p.To.Reg == REG_SPSel {
			v = 0<<16 | 4<<12 | 5<<5
		} else if p.To.Type == obj.TYPE_REG && p.To.Reg == REG_DIT {
			// op1 = 011 (3) op2 = 010 (2)
			v = 3<<16 | 2<<5
		} else if p.To.Type == obj.TYPE_SPECIAL {
			opd := SpecialOperand(p.To.Offset)
			for _, pf := range pstatefield {
				if pf.opd == opd {
					v = pf.enc
					break
				}
			}
		}

		if v == 0 {
			c.ctxt.Diag("illegal PSTATE field for immediate move\n%v", p)
		}
		o1 |= v

	case 38: /* clrex [$imm] */
		o1 = c.opimm(p, p.As)

		if p.To.Type == obj.TYPE_NONE {
			o1 |= 0xF << 8
		} else {
			o1 |= uint32((p.To.Offset & 0xF) << 8)
		}

	case 39: /* cbz R, rel */
		o1 = c.opirr(p, p.As)

		o1 |= uint32(p.From.Reg & 31)
		o1 |= uint32(c.brdist(p, 0, 19, 2) << 5)

	case 40: /* tbz */
		o1 = c.opirr(p, p.As)

		v := int32(p.From.Offset)
		if v < 0 || v > 63 {
			c.ctxt.Diag("illegal bit number\n%v", p)
		}
		o1 |= ((uint32(v) & 0x20) << (31 - 5)) | ((uint32(v) & 0x1F) << 19)
		o1 |= uint32(c.brdist(p, 0, 14, 2) << 5)
		o1 |= uint32(p.Reg & 31)

	case 41: /* eret, nop, others with no operands */
		o1 = c.op0(p, p.As)

	case 42: /* bfm R,r,s,R */
		o1 = c.opbfm(p, p.As, p.From.Offset, p.GetFrom3().Offset, p.Reg, p.To.Reg)

	case 43: /* bfm aliases */
		rt, rf := p.To.Reg, p.Reg
		if rf == obj.REG_NONE {
			rf = rt
		}
		r, s := p.From.Offset, p.GetFrom3().Offset
		switch p.As {
		case ABFI:
			if r != 0 {
				r = 64 - r
			}
			o1 = c.opbfm(p, ABFM, r, s-1, rf, rt)

		case ABFIW:
			if r != 0 {
				r = 32 - r
			}
			o1 = c.opbfm(p, ABFMW, r, s-1, rf, rt)

		case ABFXIL:
			o1 = c.opbfm(p, ABFM, r, r+s-1, rf, rt)

		case ABFXILW:
			o1 = c.opbfm(p, ABFMW, r, r+s-1, rf, rt)

		case ASBFIZ:
			if r != 0 {
				r = 64 - r
			}
			o1 = c.opbfm(p, ASBFM, r, s-1, rf, rt)

		case ASBFIZW:
			if r != 0 {
				r = 32 - r
			}
			o1 = c.opbfm(p, ASBFMW, r, s-1, rf, rt)

		case ASBFX:
			o1 = c.opbfm(p, ASBFM, r, r+s-1, rf, rt)

		case ASBFXW:
			o1 = c.opbfm(p, ASBFMW, r, r+s-1, rf, rt)

		case AUBFIZ:
			if r != 0 {
				r = 64 - r
			}
			o1 = c.opbfm(p, AUBFM, r, s-1, rf, rt)

		case AUBFIZW:
			if r != 0 {
				r = 32 - r
			}
			o1 = c.opbfm(p, AUBFMW, r, s-1, rf, rt)

		case AUBFX:
			o1 = c.opbfm(p, AUBFM, r, r+s-1, rf, rt)

		case AUBFXW:
			o1 = c.opbfm(p, AUBFMW, r, r+s-1, rf, rt)

		default:
			c.ctxt.Diag("bad bfm alias\n%v", p)
			break
		}

	case 44: /* extr $b, Rn, Rm, Rd */
		o1 = c.opextr(p, p.As, p.From.Offset, p.GetFrom3().Reg, p.Reg, p.To.Reg)

	case 45: /* sxt/uxt[bhw] R,R; movT R,R -> sxtT R,R */
		as := p.As
		rt, rf := p.To.Reg, p.From.Reg
		if rf == REGZERO {
			as = AMOVWU /* clearer in disassembly */
		}
		switch as {
		case AMOVB, ASXTB:
			o1 = c.opbfm(p, ASBFM, 0, 7, rf, rt)

		case AMOVH, ASXTH:
			o1 = c.opbfm(p, ASBFM, 0, 15, rf, rt)

		case AMOVW, ASXTW:
			o1 = c.opbfm(p, ASBFM, 0, 31, rf, rt)

		case AMOVBU, AUXTB:
			o1 = c.opbfm(p, AUBFM, 0, 7, rf, rt)

		case AMOVHU, AUXTH:
			o1 = c.opbfm(p, AUBFM, 0, 15, rf, rt)

		case AMOVWU:
			o1 = c.oprrr(p, as) | (uint32(rf&31) << 16) | (REGZERO & 31 << 5) | uint32(rt&31)

		case AUXTW:
			o1 = c.opbfm(p, AUBFM, 0, 31, rf, rt)

		case ASXTBW:
			o1 = c.opbfm(p, ASBFMW, 0, 7, 
"""




```